#![forbid(unsafe_code)]
//! Holds exercised against real retained imports, authority journals and deletion closure.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BatchId, BudgetVector, CaptureInterval, ContentDigest, EvidenceDelta, ObjectId, OperationId,
    Plane, SensorId, StreamId, TimestampNs,
};
use fss_reference::deletion::holds::{
    CAP_HOLD_COMMIT, CAP_HOLD_PREPARE, HOLD_OBJECT_PREFIX, HoldError, HoldOutcome, HoldRecord,
    HoldRequest, HoldState, STAGE_HOLD_COMMITTED, STAGE_HOLD_STAGED, commit_hold, list_holds,
    preview_hold,
};
use fss_reference::deletion::{
    CommitOutcome, DeletionError, STAGE_DELETION_RECORD_APPENDED, commit_deletion, plan_deletion,
};
use fss_reference::ingest::{FileFormatHint, FileIngestAdapter, FileIngestRequest};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::reference_deployment::FAMILY_EVIDENCE_HOLD;
use fss_reference::{ReferenceDeployment, ReferenceError, ReplayCx};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:evidence-hold";
const PRINCIPAL: &str = "principal:hold-owner";

struct Directory(PathBuf);
impl Directory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100 {
            let root = std::env::temp_dir().join(format!(
                "fss-evidence-hold-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Ok(Self(root)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn authority(caps: &[&str]) -> TestResult<ContextAuthority> {
    Ok(ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:evidence-hold".into(),
        operation_id: OperationId::parse("operation:evidence-hold")?,
        principal: PRINCIPAL.into(),
        capabilities: caps.iter().map(|c| (*c).to_owned()).collect(),
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(8192)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?)
}

struct Fixture {
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    authority: ContextAuthority,
    directory: Directory,
}
impl Fixture {
    fn new(name: &str) -> TestResult<Self> {
        let directory = Directory::new(name)?;
        let root = directory.0.join("deployment");
        let authority = authority(&["ADP-REPLAY-001", CAP_HOLD_PREPARE, CAP_HOLD_COMMIT])?;
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        Ok(Self {
            deployment,
            cx,
            authority,
            directory,
        })
    }

    fn ingest(&mut self, name: &str, gray: u8) -> TestResult<ContentDigest> {
        let path = self.directory.0.join(format!("{name}.mjpeg"));
        let bytes = encode_jpeg(
            16,
            16,
            &[gray; 256],
            &JpegConfig {
                quality: 90,
                subsampling: Subsampling::Grayscale,
                restart_interval: 0,
                custom_markers: Vec::new(),
            },
        )?;
        fs::write(&path, bytes)?;
        let request = FileIngestRequest::new(
            path,
            SensorId::parse(format!("sensor:{name}"))?,
            StreamId::parse(format!("stream:{name}"))?,
        )
        .with_receive_time(TimestampNs(1_000_000_000))
        .with_format_hint(FileFormatHint::JpegStream);
        Ok(FileIngestAdapter::ingest(request, &self.cx, &mut self.deployment)?.import_identity)
    }

    fn apply(&mut self, request: &HoldRequest) -> TestResult<HoldRecord> {
        let preview = preview_hold(&self.deployment, request, &self.authority, &self.cx)?;
        Ok(commit_hold(
            &mut self.deployment,
            request,
            preview.record.approval(),
            &self.authority,
            &self.cx,
        )?
        .record)
    }

    fn fresh_cx(&self) -> TestResult<ReplayCx> {
        Ok(ReplayCx::from_context_authority(
            &self.authority,
            self.deployment.root().to_path_buf(),
        )?)
    }
}

fn request(id: &str, import_identity: ContentDigest, state: HoldState) -> HoldRequest {
    HoldRequest {
        hold_id: id.into(),
        import_identity,
        state,
        reason: if state == HoldState::Held {
            "Preserve incident evidence"
        } else {
            "Owner review complete"
        }
        .into(),
    }
}

#[test]
fn hold_survives_reopen_blocks_deletion_and_release_keeps_audit_history() -> TestResult {
    let mut f = Fixture::new("lifecycle")?;
    let import = f.ingest("north", 40)?;
    let req = request("incident", import, HoldState::Held);
    let head = f.deployment.current_anchor().clone();
    let objects = f.deployment.publisher().spool().digests().count();
    let preview = preview_hold(&f.deployment, &req, &f.authority, &f.cx)?;
    assert_eq!(preview.outcome, HoldOutcome::Proposed);
    assert_eq!(*f.deployment.current_anchor(), head);
    assert_eq!(f.deployment.publisher().spool().digests().count(), objects);
    let placed = f.apply(&req)?;
    let head = f.deployment.current_anchor().clone();
    let again = commit_hold(
        &mut f.deployment,
        &req,
        placed.approval(),
        &f.authority,
        &f.cx,
    )?;
    assert_eq!(again.outcome, HoldOutcome::AlreadyCurrent);
    assert_eq!(*f.deployment.current_anchor(), head);

    let Fixture {
        deployment,
        cx,
        authority,
        directory,
    } = f;
    let root = deployment.root().to_path_buf();
    drop(deployment);
    let mut deployment = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    assert_eq!(
        list_holds(&deployment, &authority, &cx)?,
        vec![placed.clone()]
    );
    let blocked = plan_deletion(&deployment, import, &cx)?;
    assert!(
        blocked
            .blockers
            .iter()
            .any(|b| b.kind == "evidence_hold" && b.subject == "incident")
    );
    let result = commit_deletion(
        &mut deployment,
        blocked.digest()?,
        blocked.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &cx,
    );
    assert!(
        matches!(result, Err(DeletionError::Blocked(ref b)) if b.iter().any(|b| b.kind == "evidence_hold"))
    );
    assert_eq!(*deployment.current_anchor(), head);

    let release = request("incident", import, HoldState::Released);
    let preview = preview_hold(&deployment, &release, &authority, &cx)?;
    let released = commit_hold(
        &mut deployment,
        &release,
        preview.record.approval(),
        &authority,
        &cx,
    )?;
    assert_eq!(released.record.predecessor(), Some(placed.digest()));
    let plan = plan_deletion(&deployment, import, &cx)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    for digest in [placed.digest(), released.record.digest()] {
        assert!(
            plan.retained
                .iter()
                .any(|o| o.digest == digest && o.reason == "authority_history")
        );
        assert!(!plan.deletable.iter().any(|o| o.digest == digest));
    }
    assert!(
        plan.tombstones
            .iter()
            .all(|t| !t.object_id.starts_with(HOLD_OBJECT_PREFIX))
    );
    let receipt = commit_deletion(
        &mut deployment,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &cx,
    )?;
    assert_eq!(receipt.outcome, CommitOutcome::Completed);
    assert_eq!(
        list_holds(&deployment, &authority, &cx)?,
        vec![released.record.clone()]
    );
    assert_eq!(
        deployment.publisher().spool().read(placed.digest())?,
        placed.to_bytes()
    );
    assert!(matches!(
        preview_hold(&deployment, &req, &authority, &cx),
        Err(HoldError::ReleasedIdentifier)
    ));
    assert!(
        preview_hold(
            &deployment,
            &request("new-hold", import, HoldState::Held),
            &authority,
            &cx
        )
        .is_err()
    );
    drop(deployment);
    drop(directory);
    Ok(())
}

#[test]
fn stale_hold_and_deletion_approvals_never_write() -> TestResult {
    let mut f = Fixture::new("stale")?;
    let import = f.ingest("north", 40)?;
    let req = request("incident", import, HoldState::Held);
    let preview = preview_hold(&f.deployment, &req, &f.authority, &f.cx)?;
    let old_deletion = plan_deletion(&f.deployment, import, &f.cx)?;
    f.apply(&request("other-hold", import, HoldState::Held))?;
    let head = f.deployment.current_anchor().clone();
    let objects = f.deployment.publisher().spool().digests().count();
    assert!(matches!(
        commit_hold(
            &mut f.deployment,
            &req,
            preview.record.approval(),
            &f.authority,
            &f.cx
        ),
        Err(HoldError::StaleApproval)
    ));
    assert!(matches!(
        commit_deletion(
            &mut f.deployment,
            old_deletion.digest()?,
            old_deletion.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &f.cx
        ),
        Err(DeletionError::StalePlan(_))
    ));
    assert_eq!(*f.deployment.current_anchor(), head);
    assert_eq!(f.deployment.publisher().spool().digests().count(), objects);
    Ok(())
}

#[test]
fn hold_protects_later_shared_derivatives_but_not_unrelated_imports() -> TestResult {
    let mut f = Fixture::new("shared")?;
    let north = f.ingest("north", 40)?;
    let south = f.ingest("south", 190)?;
    let third = f.ingest("third", 80)?;
    f.apply(&request("incident", south, HoldState::Held))?;
    assert!(
        plan_deletion(&f.deployment, north, &f.cx)?
            .blockers
            .is_empty()
    );
    let mut bytes = north.bytes().to_vec();
    bytes.extend_from_slice(&south.bytes());
    let digest = f.deployment.stage_payload(&bytes)?;
    f.deployment.append_batch(
        BatchId::parse("batch:shared-hold-evidence")?,
        vec![EvidenceDelta {
            delta_id: "delta:shared-hold-evidence".into(),
            family: "test_shared_evidence".into(),
            object_id: ObjectId::parse("object:shared-hold-evidence")?,
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(0), TimestampNs(0))?,
            plane: Plane::Cognition,
            payload_digest: digest,
            witness_digest: None,
            operation_id: None,
        }],
        vec![digest],
        &f.cx,
    )?;
    let plan = plan_deletion(&f.deployment, north, &f.cx)?;
    assert!(plan.deletable.iter().any(|o| o.digest == digest));
    assert!(
        plan.blockers
            .iter()
            .any(|b| b.kind == "evidence_hold" && b.subject == "incident")
    );
    assert!(
        plan_deletion(&f.deployment, third, &f.cx)?
            .blockers
            .is_empty()
    );
    f.apply(&request("incident", south, HoldState::Released))?;
    assert!(
        plan_deletion(&f.deployment, north, &f.cx)?
            .blockers
            .is_empty()
    );
    Ok(())
}

#[test]
fn overlapping_holds_release_independently() -> TestResult {
    let mut f = Fixture::new("multiple")?;
    let import = f.ingest("north", 40)?;
    f.apply(&request("first", import, HoldState::Held))?;
    f.apply(&request("second", import, HoldState::Held))?;
    f.apply(&request("first", import, HoldState::Released))?;
    let plan = plan_deletion(&f.deployment, import, &f.cx)?;
    let blockers: Vec<_> = plan
        .blockers
        .iter()
        .filter(|b| b.kind == "evidence_hold")
        .map(|b| b.subject.as_str())
        .collect();
    assert_eq!(blockers, ["second"]);
    Ok(())
}

#[test]
fn capabilities_scope_and_raw_writer_cannot_bypass_hold_authority() -> TestResult {
    let mut f = Fixture::new("authority")?;
    let import = f.ingest("north", 40)?;
    let req = request("incident", import, HoldState::Held);
    let preview_only = authority(&[CAP_HOLD_PREPARE])?;
    let preview = preview_hold(&f.deployment, &req, &preview_only, &f.cx)?;
    assert!(matches!(
        commit_hold(
            &mut f.deployment,
            &req,
            preview.record.approval(),
            &preview_only,
            &f.cx
        ),
        Err(HoldError::Unauthorized)
    ));
    let mut foreign = f.authority.clone();
    foreign.anchor_universe = ContentDigest::sha256(b"site:foreign");
    assert!(matches!(
        preview_hold(&f.deployment, &req, &foreign, &f.cx),
        Err(HoldError::Unauthorized)
    ));
    let digest = ContentDigest::sha256(b"not staged");
    let head = f.deployment.current_anchor().clone();
    for (family, object) in [
        (FAMILY_EVIDENCE_HOLD, "object:any".to_owned()),
        ("other_family", format!("{HOLD_OBJECT_PREFIX}shadow")),
    ] {
        let result = f.deployment.append_batch(
            BatchId::parse("batch:forged-hold")?,
            vec![EvidenceDelta {
                delta_id: "delta:forged-hold".into(),
                family: family.into(),
                object_id: ObjectId::parse(object)?,
                prior_generation: None,
                new_generation: 1,
                validity: CaptureInterval::new(TimestampNs(0), TimestampNs(0))?,
                plane: Plane::Authority,
                payload_digest: digest,
                witness_digest: None,
                operation_id: None,
            }],
            vec![digest],
            &f.cx,
        );
        assert!(matches!(
            result,
            Err(ReferenceError::ReservedDeltaFamily { .. })
        ));
    }
    assert_eq!(*f.deployment.current_anchor(), head);
    Ok(())
}

#[test]
fn staged_cancellation_does_not_create_a_hold_and_exact_retry_commits_once() -> TestResult {
    let mut f = Fixture::new("cancel")?;
    let import = f.ingest("north", 40)?;
    let req = request("incident", import, HoldState::Held);
    let preview = preview_hold(&f.deployment, &req, &f.authority, &f.cx)?;
    let head = f.deployment.current_anchor().clone();
    f.cx.set_cancel_at_checkpoint(STAGE_HOLD_STAGED);
    assert!(matches!(
        commit_hold(
            &mut f.deployment,
            &req,
            preview.record.approval(),
            &f.authority,
            &f.cx
        ),
        Err(HoldError::Cancelled)
    ));
    assert_eq!(*f.deployment.current_anchor(), head);
    let fresh = f.fresh_cx()?;
    assert!(list_holds(&f.deployment, &f.authority, &fresh)?.is_empty());
    fresh.set_cancel_at_checkpoint(STAGE_HOLD_COMMITTED);
    let committed = commit_hold(
        &mut f.deployment,
        &req,
        preview.record.approval(),
        &f.authority,
        &fresh,
    )?;
    assert_eq!(committed.outcome, HoldOutcome::Committed);
    assert!(fresh.is_drain_completed());
    let head = f.deployment.current_anchor().clone();
    let fresh = f.fresh_cx()?;
    let again = commit_hold(
        &mut f.deployment,
        &req,
        preview.record.approval(),
        &f.authority,
        &fresh,
    )?;
    assert_eq!(again.outcome, HoldOutcome::AlreadyCurrent);
    assert_eq!(*f.deployment.current_anchor(), head);
    Ok(())
}

#[test]
fn incomplete_deletion_refuses_new_preservation_then_resumes_exactly_once() -> TestResult {
    let mut f = Fixture::new("deleting")?;
    let north = f.ingest("north", 40)?;
    let south = f.ingest("south", 190)?;
    let plan = plan_deletion(&f.deployment, north, &f.cx)?;
    let digest = plan.digest()?;
    let approval = plan.approval_digest(PRINCIPAL)?;
    f.cx.set_cancel_at_checkpoint(STAGE_DELETION_RECORD_APPENDED);
    assert!(matches!(
        commit_deletion(&mut f.deployment, digest, approval, PRINCIPAL, &f.cx),
        Err(DeletionError::Cancelled {
            stage: STAGE_DELETION_RECORD_APPENDED
        })
    ));
    let fresh = f.fresh_cx()?;
    let head = f.deployment.current_anchor().clone();
    assert!(matches!(
        preview_hold(
            &f.deployment,
            &request("new", south, HoldState::Held),
            &f.authority,
            &fresh
        ),
        Err(HoldError::DeletionInProgress)
    ));
    assert_eq!(*f.deployment.current_anchor(), head);
    assert_eq!(
        commit_deletion(&mut f.deployment, digest, approval, PRINCIPAL, &fresh)?.outcome,
        CommitOutcome::Resumed
    );
    assert_eq!(
        commit_deletion(&mut f.deployment, digest, approval, PRINCIPAL, &fresh)?.outcome,
        CommitOutcome::AlreadyComplete
    );
    Ok(())
}
