#![forbid(unsafe_code)]
//! Audit framing cannot remove source/derivative bytes from a deletion closure.
//! These synthetic publications exercise ownership, canonical decoding and durable retries.

mod file_import_fault_support;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use file_import_fault_support::{TestResult, cx, fixture, fresh_dir, open, request, standard};
use fss_core::{
    CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest, SensorId, TimestampNs,
};
use fss_object::ObjectManifest;
use fss_publication::SlotName;
use fss_reference::deletion::retention::policy::{POLICY_DOMAIN, RetentionPolicyRecord};
use fss_reference::deletion::{
    CommitOutcome, DeletionCompletion, DeletionError, DeletionIndex, DeletionPlan,
    STAGE_DELETION_COMPLETION_STAGED, STAGE_DELETION_PLAN_STAGED, commit_deletion, plan_deletion,
};
use fss_reference::{FileIngestAdapter, ReferenceDeployment, ReplayCx};

type TestValue<T> = Result<T, Box<dyn std::error::Error>>;
const PRINCIPAL: &str = "operator:deletion-audit-role";

struct Harness {
    root: PathBuf,
    deployment: ReferenceDeployment,
    import: ContentDigest,
    context: ReplayCx,
}

impl Harness {
    fn new(label: &str) -> TestValue<Self> {
        let dir = fresh_dir(&format!("deletion-audit-{label}"))?;
        let frame = fs::read(fixture("jpeg/gray_16x16_flat.jpg")?)?;
        let input = dir.join("source.mjpeg");
        fs::write(&input, frame.repeat(2))?;
        let root = dir.join("deployment");
        let mut deployment = open(&root, standard())?;
        let context = cx("deletion-audit-role")?;
        let receipt = FileIngestAdapter::ingest(
            request(&input, frame.len() as u64, 8)?,
            &context,
            &mut deployment,
        )?;
        Ok(Self {
            root,
            deployment,
            import: receipt.import_identity,
            context,
        })
    }

    fn second_import(&mut self) -> TestValue<ContentDigest> {
        let frame = fs::read(fixture("jpeg/gray_16x16_flat.jpg")?)?;
        let path = self
            .root
            .parent()
            .ok_or("missing test directory")?
            .join("second.mjpeg");
        fs::write(&path, frame.repeat(3))?;
        let mut input = request(&path, frame.len() as u64, 8)?;
        input.sensor_id = SensorId::parse("sensor:audit-role-second")?;
        Ok(FileIngestAdapter::ingest(input, &self.context, &mut self.deployment)?.import_identity)
    }

    fn plan(&self) -> TestValue<DeletionPlan> {
        Ok(plan_deletion(&self.deployment, self.import, &self.context)?)
    }

    fn commit(&mut self, plan: &DeletionPlan) -> TestResult {
        let receipt = commit_deletion(
            &mut self.deployment,
            plan.digest()?,
            plan.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &self.context,
        )?;
        assert_eq!(receipt.outcome, CommitOutcome::Completed);
        Ok(())
    }

    fn reopen(self) -> TestValue<Self> {
        let Self {
            root,
            deployment,
            import,
            ..
        } = self;
        drop(deployment);
        let deployment = open(&root, standard())?;
        Ok(Self {
            root,
            deployment,
            import,
            context: cx("deletion-audit-reopen")?,
        })
    }

    /// Publish an import-attributable derivative with the payload beneath zero or more
    /// intermediate manifests. Only the outer root is published; inner manifests are children.
    fn attach(&mut self, bytes: &[u8], depth: usize, label: &str) -> TestValue<ContentDigest> {
        let payload = self.deployment.stage_payload(bytes)?;
        let mut child = payload;
        for level in 0..depth {
            let manifest =
                ObjectManifest::new(format!("audit-role-container-{level}"), [child], None)?;
            child = self
                .deployment
                .stage_payload(&manifest.try_canonical_bytes()?)?;
        }
        let edge = self.deployment.stage_payload(&self.import.bytes())?;
        let manifest = ObjectManifest::new("audit-role-content", [child], Some(edge))?;
        self.deployment.publish_and_commit(
            &SlotName::parse(format!("audit-role-{label}"))?,
            &manifest,
            CaptureInterval::new(TimestampNs(2000), TimestampNs(2000))?,
            &self.context,
        )?;
        Ok(payload)
    }
}

fn snapshot(root: &Path) -> TestValue<BTreeMap<PathBuf, Vec<u8>>> {
    let mut out = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                out.insert(path.strip_prefix(root)?.to_owned(), fs::read(path)?);
            } else {
                return Err("unexpected non-regular test entry".into());
            }
        }
    }
    Ok(out)
}

fn marker(domain: &str, import: ContentDigest) -> Vec<u8> {
    let mut e = CanonicalEncoder::new();
    if domain != POLICY_DOMAIN {
        e.text("fss.canonical.v1");
    }
    e.text(domain);
    e.digest(import);
    e.text("synthetic source bytes, not an audit record");
    e.finish()
}

/// A valid, uncommitted policy spelling supplied as ordinary content, independently encoded.
fn copied_policy(harness: &Harness) -> TestValue<Vec<u8>> {
    let mut e = CanonicalEncoder::new();
    e.text(POLICY_DOMAIN);
    SensorId::parse("sensor:audit-role")?.encode_canonical(&mut e);
    e.bool(true);
    e.u64(100);
    e.bool(false);
    e.bool(false);
    TimestampNs(1000).encode_canonical(&mut e);
    TimestampNs(1010).encode_canonical(&mut e);
    e.text("Synthetic source containing a copied policy");
    e.u64(1);
    e.text(PRINCIPAL);
    e.text(harness.deployment.site_lineage());
    harness.deployment.current_anchor().encode_canonical(&mut e);
    e.digest(harness.import);
    e.bool(false);
    let bytes = e.finish();
    let record = RetentionPolicyRecord::from_bytes(&bytes, ContentDigest::sha256(&bytes))?;
    assert_eq!(record.to_bytes(), bytes);
    Ok(bytes)
}

#[test]
fn every_audit_prefix_remains_deletable_as_direct_or_nested_content() -> TestResult {
    let mut harness = Harness::new("prefix-content")?;
    let domains = [
        "fss.deletion_plan.v1",
        "fss.deletion_plan.v2",
        "fss.deletion_plan.v3",
        "fss.deletion_plan.v4",
        "fss.deletion_completion.v1",
        "fss.deletion_completion.v2",
        "fss.deletion_completion.v3",
        "fss.deletion_completion.v4",
        POLICY_DOMAIN,
    ];
    let mut targets = Vec::new();
    for (number, domain) in domains.iter().enumerate() {
        let bytes = marker(domain, harness.import);
        for depth in [0, 2] {
            targets.push(harness.attach(&bytes, depth, &format!("prefix-{number}-{depth}"))?);
        }
    }
    let plan = harness.plan()?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    for digest in &targets {
        assert!(plan.deletable.iter().any(|object| object.digest == *digest));
        assert!(!plan.retained.iter().any(|object| object.digest == *digest));
    }
    harness.commit(&plan)?;
    for digest in targets {
        assert!(!harness.deployment.publisher().object_name_present(digest));
    }
    assert!(
        DeletionIndex::read(&harness.deployment)?
            .plan(plan.digest()?)
            .is_some()
    );
    Ok(())
}

#[test]
fn complete_canonical_audit_copies_do_not_change_nested_content_ownership() -> TestResult {
    let mut harness = Harness::new("canonical-content")?;
    let proposal = harness.plan()?;
    let plan_bytes = proposal.canonical_bytes()?;
    assert_eq!(
        DeletionPlan::decode(&plan_bytes, proposal.digest()?)?,
        proposal
    );
    let completion = DeletionCompletion::of(&proposal)?;
    let completion_bytes = completion.canonical_bytes()?;
    assert_eq!(
        DeletionCompletion::decode(&completion_bytes, completion.digest()?)?,
        completion
    );
    let policy_bytes = copied_policy(&harness)?;
    let mut targets = Vec::new();
    for (label, bytes) in [
        ("plan", plan_bytes),
        ("completion", completion_bytes),
        ("policy", policy_bytes),
    ] {
        targets.push(harness.attach(&bytes, 3, label)?);
    }
    let plan = harness.plan()?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    for digest in &targets {
        assert!(plan.deletable.iter().any(|object| object.digest == *digest));
    }
    harness.commit(&plan)?;
    for digest in targets {
        assert!(!harness.deployment.publisher().object_name_present(digest));
    }
    Ok(())
}

#[test]
fn unowned_malformed_foreign_or_unbound_audit_candidates_refuse_without_writes() -> TestResult {
    for case in 0..6 {
        let mut harness = Harness::new(&format!("unowned-{case}"))?;
        let baseline = harness.plan()?;
        let bytes = match case {
            0 => marker("fss.deletion_plan.v1", harness.import),
            1 => marker("fss.deletion_completion.v1", harness.import),
            2 => marker(POLICY_DOMAIN, harness.import),
            3 => {
                let mut foreign = baseline.clone();
                foreign.site_lineage = "site:foreign-audit".to_owned();
                foreign.basis_anchor.site_lineage = foreign.site_lineage.clone();
                foreign.canonical_bytes()?
            }
            4 => {
                let mut unbound = baseline.clone();
                unbound.basis_anchor.commit_sequence += 100;
                unbound.basis_anchor.state_root = ContentDigest::sha256(b"unknown authority");
                unbound.canonical_bytes()?
            }
            _ => DeletionCompletion::of(&baseline)?.canonical_bytes()?,
        };
        let digest = harness.deployment.stage_payload(&bytes)?;
        let before = snapshot(&harness.root)?;
        assert!(
            harness.plan().is_err(),
            "candidate {case} was silently exempted"
        );
        assert!(
            commit_deletion(
                &mut harness.deployment,
                baseline.digest()?,
                baseline.approval_digest(PRINCIPAL)?,
                PRINCIPAL,
                &harness.context,
            )
            .is_err(),
            "candidate {case} allowed a stale approval to commit"
        );
        assert_eq!(snapshot(&harness.root)?, before);
        assert_eq!(harness.deployment.publisher().spool().read(digest)?, bytes);
    }
    Ok(())
}

#[test]
fn committed_audit_bytes_shared_with_later_content_are_explicitly_retained() -> TestResult {
    let mut harness = Harness::new("committed-shared")?;
    let second = harness.second_import()?;
    let first = harness.plan()?;
    let first_digest = first.digest()?;
    let plan_bytes = first.canonical_bytes()?;
    let completion = DeletionCompletion::of(&first)?;
    let completion_digest = completion.digest()?;
    let completion_bytes = completion.canonical_bytes()?;
    harness.commit(&first)?;

    harness.import = second;
    assert_eq!(
        harness.attach(&plan_bytes, 2, "committed-plan")?,
        first_digest
    );
    assert_eq!(
        harness.attach(&completion_bytes, 2, "committed-completion")?,
        completion_digest
    );
    let plan = harness.plan()?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    for digest in [first_digest, completion_digest] {
        assert!(!plan.deletable.iter().any(|object| object.digest == digest));
        assert!(plan.retained.iter().any(|object| {
            object.digest == digest && object.reason == "deletion_audit_metadata"
        }));
    }
    harness.commit(&plan)?;
    let harness = harness.reopen()?;
    let index = DeletionIndex::read(&harness.deployment)?;
    assert_eq!(index.entries().len(), 2);
    assert!(index.entries().iter().all(|entry| entry.is_complete()));
    assert_eq!(
        harness.deployment.publisher().spool().read(first_digest)?,
        plan_bytes
    );
    assert_eq!(
        harness
            .deployment
            .publisher()
            .spool()
            .read(completion_digest)?,
        completion_bytes
    );
    Ok(())
}

#[test]
fn interrupted_plan_and_completion_staging_preserve_exact_retries() -> TestResult {
    for (number, stage) in [STAGE_DELETION_PLAN_STAGED, STAGE_DELETION_COMPLETION_STAGED]
        .into_iter()
        .enumerate()
    {
        let mut harness = Harness::new(&format!("retry-{number}"))?;
        let second = harness.second_import()?;
        let plan = harness.plan()?;
        let digest = plan.digest()?;
        let approval = plan.approval_digest(PRINCIPAL)?;
        let stop = cx("deletion-audit-stop")?;
        stop.set_cancel_at_checkpoint_occurrence(stage, 1);
        assert!(matches!(
            commit_deletion(&mut harness.deployment, digest, approval, PRINCIPAL, &stop),
            Err(DeletionError::Cancelled { stage: actual }) if actual == stage
        ));
        assert!(stop.is_drain_completed());
        let mut harness = harness.reopen()?;
        if stage == STAGE_DELETION_PLAN_STAGED {
            assert!(DeletionIndex::read(&harness.deployment)?.is_empty());
            assert_eq!(harness.plan()?, plan);
        } else {
            // The staged completion is valid metadata only because this exact plan is durable.
            // Planning another import still succeeds and reports the incomplete deletion.
            let other = plan_deletion(&harness.deployment, second, &harness.context)?;
            assert!(
                other
                    .blockers
                    .iter()
                    .any(|finding| finding.kind == "incomplete_deletion")
            );
        }
        let receipt = commit_deletion(
            &mut harness.deployment,
            digest,
            approval,
            PRINCIPAL,
            &harness.context,
        )?;
        assert_eq!(
            receipt.outcome,
            if stage == STAGE_DELETION_PLAN_STAGED {
                CommitOutcome::Completed
            } else {
                CommitOutcome::Resumed
            }
        );
        assert!(
            DeletionIndex::read(&harness.deployment)?
                .plan(digest)
                .ok_or("missing resumed deletion")?
                .is_complete()
        );
    }
    Ok(())
}
