#![forbid(unsafe_code)]
//! A deletion closure cannot be established by silently skipping unreadable retained bytes.
//! Faults alter only this test's synthetic spool envelopes; no real deployment is touched.

mod file_import_fault_support;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use file_import_fault_support::{TestResult, cx, fixture, fresh_dir, open, request, standard};
use fss_core::ContentDigest;
use fss_reference::deletion::{CommitOutcome, DeletionError, commit_deletion, plan_deletion};
use fss_reference::{FileIngestAdapter, ReferenceDeployment, ReplayCx};

type ResultOf<T> = Result<T, Box<dyn std::error::Error>>;
const PRINCIPAL: &str = "operator:deletion-custody-refusal";

struct Harness {
    root: PathBuf,
    deployment: ReferenceDeployment,
    import: ContentDigest,
    context: ReplayCx,
}

impl Harness {
    fn new(label: &str) -> ResultOf<Self> {
        let dir = fresh_dir(&format!("deletion-custody-{label}"))?;
        let frame = fs::read(fixture("jpeg/gray_16x16_flat.jpg")?)?;
        let input = dir.join("source.mjpeg");
        fs::write(&input, frame.repeat(2))?;
        let root = dir.join("deployment");
        let mut deployment = open(&root, standard())?;
        let context = cx("deletion-custody")?;
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

    fn reopen(self) -> ResultOf<Self> {
        let Self {
            root,
            deployment,
            import,
            context,
        } = self;
        drop(deployment);
        let deployment = open(&root, standard())?;
        Ok(Self {
            root,
            deployment,
            import,
            context,
        })
    }

    fn refusal(&self, digest: ContentDigest) -> ResultOf<String> {
        match self.deployment.publisher().spool().read(digest) {
            Err(error) => Ok(error.to_string()),
            Ok(_) => Err("fault did not make the target unreadable".into()),
        }
    }
}

fn same_storage_error<T>(result: Result<T, DeletionError>, expected: &str) -> TestResult {
    match result {
        Err(DeletionError::Spool(error)) => assert_eq!(error.to_string(), expected),
        Err(other) => return Err(format!("wrong refusal: {other}").into()),
        Ok(_) => {
            return Err("unreadable object was silently excluded from deletion planning".into());
        }
    }
    Ok(())
}

fn snapshot(root: &Path) -> ResultOf<BTreeMap<PathBuf, Vec<u8>>> {
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

fn corrupt(path: &Path) -> ResultOf<Vec<u8>> {
    let original = fs::read(path)?;
    let mut changed = original.clone();
    *changed.last_mut().ok_or("empty spool envelope")? ^= 0x80;
    fs::write(path, changed)?;
    Ok(original)
}

#[test]
fn every_corrupt_closure_object_refuses_planning_and_commit_without_writes() -> TestResult {
    let mut harness = Harness::new("closure")?;
    let baseline = plan_deletion(&harness.deployment, harness.import, &harness.context)?;
    assert!(baseline.blockers.is_empty());
    assert!(baseline.deletable.len() > 2);
    let digest = baseline.digest()?;
    let approval = baseline.approval_digest(PRINCIPAL)?;
    for target in &baseline.deletable {
        let path = harness
            .deployment
            .publisher()
            .spool()
            .object_path(target.digest);
        let original = corrupt(&path)?;
        let expected = harness.refusal(target.digest)?;
        let before = snapshot(&harness.root)?;
        same_storage_error(
            plan_deletion(&harness.deployment, harness.import, &harness.context),
            &expected,
        )?;
        same_storage_error(
            commit_deletion(
                &mut harness.deployment,
                digest,
                approval,
                PRINCIPAL,
                &harness.context,
            ),
            &expected,
        )?;
        assert_eq!(snapshot(&harness.root)?, before);
        // A read-only scan does not poison the index or mutate a verification hold.
        fs::write(&path, original)?;
        assert_eq!(
            plan_deletion(&harness.deployment, harness.import, &harness.context)?.digest()?,
            digest
        );
    }
    Ok(())
}

#[test]
fn a_missing_indexed_object_is_not_a_zero_byte_leaf() -> TestResult {
    let mut harness = Harness::new("missing")?;
    let baseline = plan_deletion(&harness.deployment, harness.import, &harness.context)?;
    let target = baseline.deletable.first().ok_or("empty closure")?.digest;
    let path = harness.deployment.publisher().spool().object_path(target);
    let original = fs::read(&path)?;
    fs::remove_file(&path)?;
    let expected = harness.refusal(target)?;
    let before = snapshot(&harness.root)?;
    same_storage_error(
        plan_deletion(&harness.deployment, harness.import, &harness.context),
        &expected,
    )?;
    same_storage_error(
        commit_deletion(
            &mut harness.deployment,
            baseline.digest()?,
            baseline.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &harness.context,
        ),
        &expected,
    )?;
    assert_eq!(snapshot(&harness.root)?, before);
    fs::write(path, original)?;
    assert_eq!(
        plan_deletion(&harness.deployment, harness.import, &harness.context)?,
        baseline
    );
    Ok(())
}

#[test]
fn corruption_cannot_hide_the_only_reference_from_an_unpublished_derivative() -> TestResult {
    let mut harness = Harness::new("hidden-edge")?;
    let mut payload = b"synthetic derivative referencing import: ".to_vec();
    payload.extend_from_slice(&harness.import.bytes());
    let target = harness.deployment.stage_payload(&payload)?;
    let baseline = plan_deletion(&harness.deployment, harness.import, &harness.context)?;
    assert!(
        baseline
            .deletable
            .iter()
            .any(|object| object.digest == target)
    );
    let path = harness.deployment.publisher().spool().object_path(target);
    let original = corrupt(&path)?;
    let expected = harness.refusal(target)?;
    let before = snapshot(&harness.root)?;
    same_storage_error(
        plan_deletion(&harness.deployment, harness.import, &harness.context),
        &expected,
    )?;
    assert_eq!(snapshot(&harness.root)?, before);
    fs::write(path, original)?;
    assert_eq!(
        plan_deletion(&harness.deployment, harness.import, &harness.context)?,
        baseline
    );
    Ok(())
}

#[test]
fn an_unreadable_apparent_nonmember_must_not_be_assumed_unrelated() -> TestResult {
    let mut harness = Harness::new("nonmember")?;
    let payload = b"unrelated retained bytes with no source references";
    let target = harness.deployment.stage_payload(payload)?;
    let baseline = plan_deletion(&harness.deployment, harness.import, &harness.context)?;
    assert!(
        !baseline
            .deletable
            .iter()
            .any(|object| object.digest == target)
    );
    let path = harness.deployment.publisher().spool().object_path(target);
    let original = corrupt(&path)?;
    let expected = harness.refusal(target)?;
    let before = snapshot(&harness.root)?;
    same_storage_error(
        plan_deletion(&harness.deployment, harness.import, &harness.context),
        &expected,
    )?;
    assert_eq!(snapshot(&harness.root)?, before);
    fs::write(path, original)?;
    let plan = plan_deletion(&harness.deployment, harness.import, &harness.context)?;
    assert_eq!(plan, baseline);
    commit_deletion(
        &mut harness.deployment,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &harness.context,
    )?;
    assert_eq!(
        harness
            .deployment
            .publisher()
            .spool()
            .read(target)?
            .as_slice(),
        payload
    );
    Ok(())
}

#[test]
fn corrupt_objects_recovered_on_open_require_custody_repair_before_cleanup() -> TestResult {
    let mut harness = Harness::new("reopen")?;
    let target = harness
        .deployment
        .stage_payload(b"unpublished retained object")?;
    let baseline = plan_deletion(&harness.deployment, harness.import, &harness.context)?;
    let path = harness.deployment.publisher().spool().object_path(target);
    let original = corrupt(&path)?;
    let harness = harness.reopen()?;
    let expected = harness.refusal(target)?;
    let before = snapshot(&harness.root)?;
    same_storage_error(
        plan_deletion(&harness.deployment, harness.import, &harness.context),
        &expected,
    )?;
    assert_eq!(snapshot(&harness.root)?, before);
    // Reopening classified this object as corrupt for the lifetime of that reader.
    fs::write(path, original)?;
    same_storage_error(
        plan_deletion(&harness.deployment, harness.import, &harness.context),
        &expected,
    )?;
    let harness = harness.reopen()?;
    assert_eq!(
        plan_deletion(&harness.deployment, harness.import, &harness.context)?,
        baseline
    );
    Ok(())
}

#[test]
fn readable_staged_objects_remain_admissible_without_promoting_their_state() -> TestResult {
    let mut harness = Harness::new("staged")?;
    let payload = format!("synthetic derivative {}", harness.import.to_text());
    let target = harness.deployment.stage_payload(payload.as_bytes())?;
    let state = harness.deployment.publisher().spool().state(target);
    let before = snapshot(&harness.root)?;
    let plan = plan_deletion(&harness.deployment, harness.import, &harness.context)?;
    assert!(plan.blockers.is_empty());
    assert!(plan.deletable.iter().any(|object| object.digest == target));
    assert_eq!(harness.deployment.publisher().spool().state(target), state);
    assert_eq!(snapshot(&harness.root)?, before);
    let receipt = commit_deletion(
        &mut harness.deployment,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &harness.context,
    )?;
    assert_eq!(receipt.outcome, CommitOutcome::Completed);
    assert!(!harness.deployment.publisher().object_name_present(target));
    Ok(())
}
