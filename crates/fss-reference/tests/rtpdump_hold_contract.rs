#![forbid(unsafe_code)]
//! One preservation owner for completed RTP and ordinary file imports.
mod rtpdump_support;

use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
    SensorId, StreamId, TimestampNs,
};
use fss_reference::deletion::holds::{
    CAP_HOLD_COMMIT, CAP_HOLD_PREPARE, HoldError, HoldOutcome, HoldRequest, HoldState, commit_hold,
    list_holds, preview_hold,
};
use fss_reference::deletion::{
    DeletionError, DeletionScope, STAGE_DELETION_RECORD_APPENDED, commit_deletion, plan_deletion,
    plan_scope_deletion,
};
use fss_reference::ingest::rtpdump::import::{
    RtpImportLimits, RtpImportScope, prepare_rtp_import, publish_rtp_import,
};
use fss_reference::ingest::rtpdump::recovery::{RtpRecoveryPolicy, inspect_rtp_import};
use fss_reference::{FileIngestAdapter, FileIngestRequest, ReferenceDeployment, ReplayCx};
use rtpdump_support::{Error, TestResult, config, real_dump};
use std::path::PathBuf;

const SITE: &str = "site:rtp-hold";
const PRINCIPAL: &str = "operator:rtp-hold";
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Fixture {
    dep: ReferenceDeployment,
    cx: ReplayCx,
    authority: ContextAuthority,
    dir: Directory,
}
impl Fixture {
    fn new(label: &str) -> Result<Self, Error> {
        let base = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
        std::fs::create_dir_all(base)?;
        let mut directory = None;
        for at in 0..1000 {
            let path = base.join(format!("rtp-hold-{label}-{}-{at}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    directory = Some(Directory(path));
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        let dir = directory.ok_or("temporary directory limit")?;
        let root = dir.0.join("deployment");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:rtp-hold".into(),
            operation_id: OperationId::parse("operation:rtp-hold")?,
            principal: PRINCIPAL.into(),
            capabilities: vec![
                "ADP-REPLAY-001".into(),
                "ADP-FILE-001".into(),
                CAP_HOLD_PREPARE.into(),
                CAP_HOLD_COMMIT.into(),
            ],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::default(),
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&authority, &root)?;
        let dep = ReferenceDeployment::open(&root, SITE, &cx)?;
        Ok(Self {
            dep,
            cx,
            authority,
            dir,
        })
    }
    fn rtp(&mut self, name: &str, fragmented: bool) -> Result<ContentDigest, Error> {
        let bytes = real_dump(fragmented);
        let scope = RtpImportScope {
            sensor: SensorId::parse(format!("sensor:{name}"))?,
            stream: StreamId::parse(format!("stream:{name}"))?,
            receive_time: TimestampNs(1_000_000_000),
        };
        Ok(publish_rtp_import(
            prepare_rtp_import(
                &bytes,
                scope,
                config(),
                RtpImportLimits::default(),
                &self.cx,
            )?,
            &self.cx,
            &mut self.dep,
        )?
        .root())
    }
    fn request(&self, root: ContentDigest, state: HoldState) -> HoldRequest {
        HoldRequest {
            hold_id: "incident".into(),
            import_identity: root,
            state,
            reason: "Owner incident review".into(),
        }
    }
    fn apply(&mut self, request: &HoldRequest) -> Result<ContentDigest, Error> {
        let preview = preview_hold(&self.dep, request, &self.authority, &self.cx)?;
        Ok(commit_hold(
            &mut self.dep,
            request,
            preview.record.approval(),
            &self.authority,
            &self.cx,
        )?
        .record
        .digest())
    }
}

#[test]
fn rtp_hold_survives_restart_blocks_deletion_and_releases_with_existing_approval() -> TestResult {
    let mut f = Fixture::new("lifecycle")?;
    let root = f.rtp("north", true)?;
    let request = f.request(root, HoldState::Held);
    let before = f.dep.current_anchor().clone();
    let preview = preview_hold(&f.dep, &request, &f.authority, &f.cx)?;
    assert_eq!(f.dep.current_anchor(), &before);
    let approval = preview.record.approval();
    let held = f.apply(&request)?;
    let head = f.dep.current_anchor().clone();
    assert_eq!(
        commit_hold(&mut f.dep, &request, approval, &f.authority, &f.cx)?.outcome,
        HoldOutcome::AlreadyCurrent
    );
    assert_eq!(f.dep.current_anchor(), &head);
    let Fixture {
        dep,
        cx,
        authority,
        dir,
    } = f;
    let path = dep.root().to_path_buf();
    drop(dep);
    let mut dep = ReferenceDeployment::reopen(&path, SITE, &cx)?;
    assert_eq!(list_holds(&dep, &authority, &cx)?.len(), 1);
    let plan = plan_deletion(&dep, root, &cx)?;
    assert!(plan.blockers.iter().any(|b| b.kind == "evidence_hold"));
    assert!(matches!(
        commit_deletion(
            &mut dep,
            plan.digest()?,
            plan.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &cx
        ),
        Err(DeletionError::Blocked(_))
    ));
    let release = HoldRequest {
        state: HoldState::Released,
        ..request
    };
    let preview = preview_hold(&dep, &release, &authority, &cx)?;
    let released = commit_hold(
        &mut dep,
        &release,
        preview.record.approval(),
        &authority,
        &cx,
    )?
    .record
    .digest();
    let plan = plan_deletion(&dep, root, &cx)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    commit_deletion(
        &mut dep,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &cx,
    )?;
    for digest in [held, released] {
        assert!(dep.publisher().spool().read(digest).is_ok());
    }
    assert!(inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &dep).is_err());
    drop(dep);
    drop(dir);
    Ok(())
}

#[test]
fn held_rtp_member_blocks_one_mixed_file_and_rtp_sensor_plan() -> TestResult {
    let mut f = Fixture::new("mixed")?;
    let rtp = f.rtp("north", false)?;
    let input = f.dir.0.join("north.mjpeg");
    let jpeg = include_bytes!("../../../tests/fixtures/media/jpeg/gray_16x16_flat.jpg");
    std::fs::write(&input, jpeg)?;
    let file = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            input,
            SensorId::parse("sensor:north")?,
            StreamId::parse("stream:north-jpeg")?,
        )
        .with_receive_time(TimestampNs(1_000_000_000)),
        &f.cx,
        &mut f.dep,
    )?
    .import_identity;
    let req = f.request(rtp, HoldState::Held);
    f.apply(&req)?;
    let scope = DeletionScope::Sensor(SensorId::parse("sensor:north")?);
    let plan = plan_scope_deletion(&f.dep, &scope, &f.cx)?;
    let mut expected = vec![rtp, file];
    expected.sort();
    assert_eq!(plan.imports, expected);
    assert!(plan.blockers.iter().any(|b| b.kind == "evidence_hold"));
    f.apply(&HoldRequest {
        state: HoldState::Released,
        ..req
    })?;
    let plan = plan_scope_deletion(&f.dep, &scope, &f.cx)?;
    assert_eq!(plan.imports, expected);
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    commit_deletion(
        &mut f.dep,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &f.cx,
    )?;
    Ok(())
}

#[test]
fn new_authority_invalidates_rtp_hold_approval_without_writing() -> TestResult {
    let mut f = Fixture::new("stale")?;
    let first = f.rtp("north", false)?;
    let req = f.request(first, HoldState::Held);
    let preview = preview_hold(&f.dep, &req, &f.authority, &f.cx)?;
    f.rtp("south", true)?;
    let before = f.dep.current_anchor().clone();
    assert!(matches!(
        commit_hold(
            &mut f.dep,
            &req,
            preview.record.approval(),
            &f.authority,
            &f.cx
        ),
        Err(HoldError::StaleApproval)
    ));
    assert_eq!(f.dep.current_anchor(), &before);
    assert!(list_holds(&f.dep, &f.authority, &f.cx)?.is_empty());
    Ok(())
}

#[test]
fn hold_cannot_be_placed_after_deletion_record_even_while_source_still_exists() -> TestResult {
    let mut f = Fixture::new("after-denial")?;
    let root = f.rtp("north", false)?;
    let plan = plan_deletion(&f.dep, root, &f.cx)?;
    let stop = ReplayCx::from_context_authority(&f.authority, f.dep.root())?;
    stop.set_cancel_at_checkpoint(STAGE_DELETION_RECORD_APPENDED);
    assert!(
        commit_deletion(
            &mut f.dep,
            plan.digest()?,
            plan.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &stop
        )
        .is_err()
    );
    let head = f.dep.current_anchor().clone();
    let req = f.request(root, HoldState::Held);
    assert!(matches!(
        preview_hold(&f.dep, &req, &f.authority, &f.cx),
        Err(HoldError::DeletionInProgress)
    ));
    assert_eq!(f.dep.current_anchor(), &head);
    assert!(plan.deletable.iter().all(|object| {
        f.dep
            .publisher()
            .spool()
            .object_path(object.digest)
            .exists()
    }));
    Ok(())
}

#[test]
fn cancelled_or_corrupt_rtp_hold_admission_creates_no_authority() -> TestResult {
    let mut f = Fixture::new("admission")?;
    let root = f.rtp("north", false)?;
    let req = f.request(root, HoldState::Held);
    let head = f.dep.current_anchor().clone();
    let stop = ReplayCx::from_context_authority(&f.authority, f.dep.root())?;
    stop.request_cancellation();
    assert!(preview_hold(&f.dep, &req, &f.authority, &stop).is_err());
    let retained = inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &f.cx, &f.dep)?;
    std::fs::remove_file(
        f.dep
            .publisher()
            .spool()
            .object_path(retained.report().chunk_digests()[0]),
    )?;
    assert!(preview_hold(&f.dep, &req, &f.authority, &f.cx).is_err());
    assert_eq!(f.dep.current_anchor(), &head);
    assert!(list_holds(&f.dep, &f.authority, &f.cx)?.is_empty());
    Ok(())
}

#[test]
fn deadline_hold_needs_explicit_approved_expiry_before_rtp_deletion() -> TestResult {
    let mut f = Fixture::new("deadline")?;
    let root = f.rtp("north", false)?;
    let state = HoldState::Until {
        not_before: TimestampNs(2_000_000_000),
    };
    let req = f.request(root, state);
    f.apply(&req)?;
    assert!(
        plan_deletion(&f.dep, root, &f.cx)?
            .blockers
            .iter()
            .any(|b| b.kind == "evidence_hold")
    );
    let expired = HoldState::Expired {
        not_before: TimestampNs(2_000_000_000),
        attested_now: CaptureInterval::new(TimestampNs(2_000_000_000), TimestampNs(2_100_000_000))?,
    };
    f.apply(&HoldRequest {
        state: expired,
        ..req
    })?;
    assert!(plan_deletion(&f.dep, root, &f.cx)?.blockers.is_empty());
    Ok(())
}
