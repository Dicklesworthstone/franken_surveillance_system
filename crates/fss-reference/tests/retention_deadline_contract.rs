#![forbid(unsafe_code)]
//! Deadline retention over real imports, durable hold authority and graph-complete deletion.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, OperationId, SensorId, StreamId, TimestampNs,
};
use fss_publication::SlotName;
use fss_reference::deletion::holds::{
    CAP_HOLD_COMMIT, CAP_HOLD_PREPARE, HoldError, HoldOutcome, HoldRecord, HoldRequest, HoldState,
    MAX_ACTIVE_HOLDS, RetentionReadiness, STAGE_HOLD_COMMITTED, STAGE_HOLD_STAGED, commit_hold,
    list_holds, preview_hold,
};
use fss_reference::deletion::{CommitOutcome, DeletionError, commit_deletion, plan_deletion};
use fss_reference::ingest::{
    FileFormatHint, FileIngestAdapter, FileIngestRequest, RetainedFileImport, RetainedReadLimits,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:retention-deadline";
const PRINCIPAL: &str = "principal:retention-owner";

struct Directory(PathBuf);
impl Directory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-retention-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
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
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:retention".into(),
            operation_id: OperationId::parse("operation:retention")?,
            principal: PRINCIPAL.into(),
            capabilities: ["ADP-REPLAY-001", CAP_HOLD_PREPARE, CAP_HOLD_COMMIT]
                .into_iter()
                .map(str::to_owned)
                .collect(),
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
        })?;
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
        fs::write(
            &path,
            encode_jpeg(
                16,
                16,
                &[gray; 256],
                &JpegConfig {
                    quality: 90,
                    subsampling: Subsampling::Grayscale,
                    restart_interval: 0,
                    custom_markers: Vec::new(),
                },
            )?,
        )?;
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
        reason: "Owner retention decision".into(),
    }
}
fn until(deadline: i128) -> HoldState {
    HoldState::Until {
        not_before: TimestampNs(deadline),
    }
}
fn time(first: i128, last: i128) -> TestResult<CaptureInterval> {
    Ok(CaptureInterval::new(TimestampNs(first), TimestampNs(last))?)
}
fn expired(deadline: i128, first: i128, last: i128) -> TestResult<HoldState> {
    Ok(HoldState::Expired {
        not_before: TimestampNs(deadline),
        attested_now: time(first, last)?,
    })
}
fn blocked_by(f: &Fixture, import: ContentDigest, id: &str) -> TestResult<bool> {
    Ok(plan_deletion(&f.deployment, import, &f.cx)?
        .blockers
        .iter()
        .any(|b| b.kind == "evidence_hold" && b.subject == id))
}

#[test]
fn minimum_retention_survives_reopen_and_requires_exact_expiry_before_deletion() -> TestResult {
    let mut f = Fixture::new("lifecycle")?;
    let import = f.ingest("north", 40)?;
    let retain = request("minimum", import, until(10));
    let placed = f.apply(&retain)?;
    let root = f.deployment.root().to_path_buf();
    let Fixture {
        deployment,
        cx,
        authority,
        directory,
    } = f;
    drop(deployment);
    let deployment = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    let mut f = Fixture {
        deployment,
        cx,
        authority,
        directory,
    };
    assert_eq!(
        list_holds(&f.deployment, &f.authority, &f.cx)?,
        vec![placed.clone()]
    );
    assert_eq!(
        placed.request().state.readiness(time(10, 12)?)?,
        RetentionReadiness::EligibleForExpiry
    );
    assert!(blocked_by(&f, import, "minimum")?); // Eligibility alone releases nothing.
    let head = f.deployment.current_anchor().clone();
    let objects = f.deployment.publisher().spool().digests().count();
    assert!(matches!(
        preview_hold(
            &f.deployment,
            &request("minimum", import, HoldState::Released),
            &f.authority,
            &f.cx
        ),
        Err(HoldError::Conflict)
    ));
    assert!(matches!(
        preview_hold(
            &f.deployment,
            &request("minimum", import, expired(10, 9, 12)?),
            &f.authority,
            &f.cx
        ),
        Err(HoldError::RetentionNotElapsed)
    ));
    assert!(matches!(
        preview_hold(
            &f.deployment,
            &request("minimum", import, expired(9, 10, 12)?),
            &f.authority,
            &f.cx
        ),
        Err(HoldError::Conflict)
    ));
    assert_eq!(*f.deployment.current_anchor(), head);
    assert_eq!(f.deployment.publisher().spool().digests().count(), objects);

    let blocked = plan_deletion(&f.deployment, import, &f.cx)?;
    let refused = commit_deletion(
        &mut f.deployment,
        blocked.digest()?,
        blocked.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &f.cx,
    );
    assert!(matches!(refused, Err(DeletionError::Blocked(_))));
    let expiry = request("minimum", import, expired(10, 10, 12)?);
    let preview = preview_hold(&f.deployment, &expiry, &f.authority, &f.cx)?;
    assert_eq!(preview.outcome, HoldOutcome::Proposed);
    assert_ne!(preview.record.approval(), placed.approval());
    assert!(matches!(
        commit_hold(
            &mut f.deployment,
            &expiry,
            placed.approval(),
            &f.authority,
            &f.cx
        ),
        Err(HoldError::StaleApproval)
    ));
    assert_eq!(*f.deployment.current_anchor(), head);
    let done = f.apply(&expiry)?;
    assert_eq!(done.predecessor(), Some(placed.digest()));
    RetainedFileImport::open(&f.deployment, import, RetainedReadLimits::default(), &f.cx)?; // Expiry is not deletion.
    let head = f.deployment.current_anchor().clone();
    assert_eq!(
        commit_hold(
            &mut f.deployment,
            &expiry,
            done.approval(),
            &f.authority,
            &f.cx
        )?
        .outcome,
        HoldOutcome::AlreadyCurrent
    );
    assert_eq!(*f.deployment.current_anchor(), head);
    assert!(matches!(
        commit_deletion(
            &mut f.deployment,
            blocked.digest()?,
            blocked.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &f.cx
        ),
        Err(DeletionError::StalePlan(_))
    ));
    let plan = plan_deletion(&f.deployment, import, &f.cx)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    for digest in [placed.digest(), done.digest()] {
        assert!(
            plan.retained
                .iter()
                .any(|o| o.digest == digest && o.reason == "authority_history")
        );
        assert!(!plan.deletable.iter().any(|o| o.digest == digest));
    }
    assert_eq!(
        commit_deletion(
            &mut f.deployment,
            plan.digest()?,
            plan.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &f.cx
        )?
        .outcome,
        CommitOutcome::Completed
    );
    assert_eq!(list_holds(&f.deployment, &f.authority, &f.cx)?, vec![done]);
    assert!(matches!(
        preview_hold(&f.deployment, &retain, &f.authority, &f.cx),
        Err(HoldError::ReleasedIdentifier)
    ));
    Ok(())
}

#[test]
fn later_shared_derivatives_remain_protected_by_each_independent_hold() -> TestResult {
    let mut f = Fixture::new("shared")?;
    let north = f.ingest("north", 40)?;
    let south = f.ingest("south", 80)?;
    f.apply(&request("short", north, until(10)))?;
    f.apply(&request("long", north, until(20)))?;
    f.apply(&request("investigation", north, HoldState::Held))?;
    let mut shared = b"shared derivation after retention placement".to_vec();
    shared.extend(north.bytes());
    shared.extend(south.bytes());
    let slot = SlotName::parse("retention-shared")?;
    let staged = f
        .deployment
        .stage_and_publish(&slot, &[shared.as_slice()], &f.cx)?;
    f.deployment
        .publish_and_commit(&slot, &staged.manifest, time(0, 0)?, &f.cx)?;
    for id in ["short", "long", "investigation"] {
        assert!(blocked_by(&f, south, id)?);
    }
    f.apply(&request("short", north, expired(10, 10, 12)?))?;
    assert!(!blocked_by(&f, south, "short")?);
    assert!(blocked_by(&f, south, "long")?);
    assert!(blocked_by(&f, south, "investigation")?);
    f.apply(&request("long", north, expired(20, 20, 22)?))?;
    assert!(blocked_by(&f, south, "investigation")?);
    f.apply(&request("investigation", north, HoldState::Released))?;
    assert!(
        plan_deletion(&f.deployment, south, &f.cx)?
            .blockers
            .is_empty()
    );
    Ok(())
}

#[test]
fn altered_time_bounds_and_intervening_authority_invalidate_expiry_approval() -> TestResult {
    let mut f = Fixture::new("approval")?;
    let import = f.ingest("north", 40)?;
    f.apply(&request("minimum", import, until(10)))?;
    let expiry = request("minimum", import, expired(10, 10, 12)?);
    let preview = preview_hold(&f.deployment, &expiry, &f.authority, &f.cx)?;
    let head = f.deployment.current_anchor().clone();
    let objects = f.deployment.publisher().spool().digests().count();
    for bounds in [(11, 12), (10, 13)] {
        let changed = request("minimum", import, expired(10, bounds.0, bounds.1)?);
        assert!(matches!(
            commit_hold(
                &mut f.deployment,
                &changed,
                preview.record.approval(),
                &f.authority,
                &f.cx
            ),
            Err(HoldError::StaleApproval)
        ));
    }
    assert_eq!(*f.deployment.current_anchor(), head);
    assert_eq!(f.deployment.publisher().spool().digests().count(), objects);
    f.apply(&request("independent", import, HoldState::Held))?;
    let head = f.deployment.current_anchor().clone();
    let objects = f.deployment.publisher().spool().digests().count();
    assert!(matches!(
        commit_hold(
            &mut f.deployment,
            &expiry,
            preview.record.approval(),
            &f.authority,
            &f.cx
        ),
        Err(HoldError::StaleApproval)
    ));
    assert_eq!(*f.deployment.current_anchor(), head);
    assert_eq!(f.deployment.publisher().spool().digests().count(), objects);
    assert!(blocked_by(&f, import, "minimum")?);
    Ok(())
}

#[test]
fn cancellation_before_expiry_append_keeps_protection_and_post_commit_is_success() -> TestResult {
    for stage in [STAGE_HOLD_STAGED, STAGE_HOLD_COMMITTED] {
        let mut f = Fixture::new("cancel")?;
        let import = f.ingest("north", 40)?;
        f.apply(&request("minimum", import, until(10)))?;
        let expiry = request("minimum", import, expired(10, 10, 12)?);
        let preview = preview_hold(&f.deployment, &expiry, &f.authority, &f.cx)?;
        let head = f.deployment.current_anchor().clone();
        f.cx.set_cancel_at_checkpoint(stage);
        let result = commit_hold(
            &mut f.deployment,
            &expiry,
            preview.record.approval(),
            &f.authority,
            &f.cx,
        );
        assert!(f.cx.is_drain_completed());
        f.cx = f.fresh_cx()?;
        if stage == STAGE_HOLD_STAGED {
            assert!(matches!(result, Err(HoldError::Cancelled)));
            assert_eq!(*f.deployment.current_anchor(), head);
            assert!(blocked_by(&f, import, "minimum")?);
            assert_eq!(
                commit_hold(
                    &mut f.deployment,
                    &expiry,
                    preview.record.approval(),
                    &f.authority,
                    &f.cx
                )?
                .outcome,
                HoldOutcome::Committed
            );
        } else {
            assert_eq!(result?.outcome, HoldOutcome::Committed);
            assert!(!blocked_by(&f, import, "minimum")?);
            assert_eq!(
                commit_hold(
                    &mut f.deployment,
                    &expiry,
                    preview.record.approval(),
                    &f.authority,
                    &f.cx
                )?
                .outcome,
                HoldOutcome::AlreadyCurrent
            );
        }
    }
    Ok(())
}

#[test]
fn deadline_holds_share_the_active_bound_and_only_committed_expiry_frees_capacity() -> TestResult {
    let mut f = Fixture::new("capacity")?;
    let import = f.ingest("north", 40)?;
    for index in 0..MAX_ACTIVE_HOLDS {
        f.apply(&request(&format!("minimum-{index}"), import, until(10)))?;
    }
    let extra = request("extra", import, until(10));
    assert!(matches!(
        preview_hold(&f.deployment, &extra, &f.authority, &f.cx),
        Err(HoldError::Limit)
    ));
    let expiry = request("minimum-0", import, expired(10, 10, 12)?);
    preview_hold(&f.deployment, &expiry, &f.authority, &f.cx)?;
    assert!(matches!(
        preview_hold(&f.deployment, &extra, &f.authority, &f.cx),
        Err(HoldError::Limit)
    ));
    f.apply(&expiry)?;
    f.apply(&extra)?;
    let records = list_holds(&f.deployment, &f.authority, &f.cx)?;
    assert_eq!(records.len(), MAX_ACTIVE_HOLDS + 1);
    assert_eq!(
        records
            .iter()
            .filter(|r| r.request().state.is_active())
            .count(),
        MAX_ACTIVE_HOLDS
    );
    Ok(())
}
