#![forbid(unsafe_code)]
//! Real retained JPEG/native screening, exact independent authority and cold custody behavior.

use super::*;
use crate::ingest::long_watch::LongWatchReport;
use crate::ingest::privacy_mask::{declare_mask, preview_mask};
use crate::ingest::recorded_decode::ComponentInterpretation;
use crate::ingest::recorded_watch::{WatchDetectorConfig, WatchTrackerConfig, WatchZone};
use crate::ingest::{CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest};
use crate::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId, TimestampNs};
use std::fs;
use std::path::{Path, PathBuf};

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:historical-health-contract";
const PRINCIPAL: &str = "principal:historical-health-contract";
const FRAMES: usize = 12;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-historical-health-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("temporary directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:historical-health".into(),
        operation_id: OperationId::parse("operation:historical-health")?,
        principal: PRINCIPAL.into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(128 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}
struct Fixture {
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    plan: WatchPlan,
    _directory: Directory,
}
impl Fixture {
    fn new(label: &str, all_refused: bool) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let source = directory.0.join("camera.mjpeg");
        let config = JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        };
        let mut frame = encode_jpeg(16, 16, &vec![80; 256], &config)?;
        if all_refused {
            let position = frame
                .windows(2)
                .position(|pair| pair == [0xff, 0xc0])
                .ok_or("JPEG SOF0")?;
            frame[position + 1] = 0xc2;
        }
        let bytes = frame.repeat(FRAMES);
        fs::write(&source, bytes)?;
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut import_limits = FileIngestLimits::standard();
        import_limits.chunk_bytes = 4096;
        let receipt = FileIngestAdapter::ingest(
            FileIngestRequest::new(
                &source,
                SensorId::parse("sensor:historical-health")?,
                StreamId::parse("stream:historical-health")?,
            )
            .with_limits(import_limits)
            .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?)
            .with_receive_time(TimestampNs(1_000_000_000_000)),
            &cx,
            &mut deployment,
        )?;
        fs::remove_file(source)?;
        let plan = WatchPlan {
            import_identity: receipt.import_identity,
            interpretation: ComponentInterpretation::Grayscale,
            first_segment: 0,
            segment_count: FRAMES,
            zones: vec![WatchZone {
                zone_id: "porch".into(),
                x: 0,
                y: 0,
                width: 16,
                height: 16,
            }],
            detector: WatchDetectorConfig::default(),
            tracker: WatchTrackerConfig::default(),
        };
        Ok(Self {
            deployment,
            cx,
            plan,
            _directory: directory,
        })
    }
    fn analyze(&self, tolerant: bool) -> Test<LongWatchReport> {
        Ok(LongWatchReport::analyze_screened(
            &self.deployment,
            &self.plan,
            WatchOptions {
                tolerate_decode_refusals: tolerant,
            },
            &LongDwellLimits::default(),
            &self.cx,
        )?)
    }
    fn snapshot(&self) -> (LedgerAnchor, ContentDigest, usize) {
        (
            self.deployment.current_anchor().clone(),
            self.deployment.effects().last_root(),
            self.deployment.publisher().spool().digests().count(),
        )
    }
}

#[test]
fn degraded_quiet_recording_retains_without_events_and_replays_after_restart() -> Test {
    let mut f = Fixture::new("cold", false)?;
    let before = f.snapshot();
    let mut report = f.analyze(false)?;
    assert_eq!(f.snapshot(), before, "screening preview is read-only");
    assert!(report.candidates().is_empty());
    assert!(report.publication_blocked());
    assert!(
        report
            .publish(&mut f.deployment, &BTreeSet::new(), &f.cx)
            .is_err()
    );
    let diagnostic = report.health_diagnostic().ok_or("diagnostic missing")?;
    assert_eq!(diagnostic.record().status(), "suspected_degradation");
    assert!(matches!(
        diagnostic.retain(
            &mut f.deployment,
            ContentDigest::sha256(b"event approval"),
            &f.cx
        ),
        Err(HistoricalHealthError::ApprovalMismatch)
    ));
    assert_eq!(f.snapshot(), before, "mismatched approval stages nothing");
    let retained = diagnostic.retain(&mut f.deployment, diagnostic.approval_digest(), &f.cx)?;
    assert!(!retained.already_retained);
    assert_eq!(
        f.deployment.current_anchor().commit_sequence,
        before.0.commit_sequence + 2
    );
    assert_eq!(f.deployment.effects().last_root(), before.1);
    for batch in &f.deployment.ledger().batches()[before.0.commit_sequence as usize..] {
        assert!(batch.deltas.iter().all(|delta| matches!(
            delta.family.as_str(),
            ROOT_REACHABILITY_FAMILY | FAMILY_HISTORICAL_HEALTH
        )));
    }
    let root = f.deployment.root().to_path_buf();
    drop(f.deployment);
    f.deployment = ReferenceDeployment::open(&root, SITE, &f.cx)?;
    let stable = f.snapshot();
    let limits = HistoricalHealthReadLimits::default();
    let inspected = read_retained(&f.deployment, retained.record_digest, &limits, &f.cx)?;
    assert!(!inspected.native_verified);
    assert_eq!(inspected.frames_replayed, 0);
    let verified = verify_retained(
        &f.deployment,
        retained.record_digest,
        retained.provenance_root,
        &limits,
        &f.cx,
    )?;
    assert!(verified.native_verified);
    assert_eq!(verified.frames_replayed, FRAMES);
    assert_eq!(verified.record.to_bytes(), diagnostic.record().to_bytes());
    assert_eq!(
        f.snapshot(),
        stable,
        "cold verification changes no authority/custody"
    );
    let rerun = f.analyze(false)?;
    let repeated = rerun
        .health_diagnostic()
        .ok_or("rerun diagnostic missing")?;
    assert!(repeated.already_retained());
    assert!(
        repeated
            .retain(&mut f.deployment, repeated.approval_digest(), &f.cx)?
            .already_retained
    );
    assert_eq!(f.snapshot(), stable, "idempotent retention does not append");
    Ok(())
}

#[test]
fn all_refused_scan_retains_incomplete_requested_hints_without_screened_time() -> Test {
    let mut f = Fixture::new("all-refused", true)?;
    let report = f.analyze(true)?;
    assert_eq!(report.frames_decoded(), 0);
    assert!(report.candidates().is_empty());
    assert!(report.publication_blocked());
    let diagnostic = report
        .health_diagnostic()
        .ok_or("incomplete diagnostic missing")?;
    let record = diagnostic.record();
    assert_eq!(record.status(), "incomplete");
    assert!(!record.summary().complete());
    assert_eq!(record.summary().frames_screened(), 0);
    assert!(!record.time_reliable());
    assert_eq!(
        record.capture_scope_semantics(),
        "requested_source_capsule_hints_when_no_frames_screened"
    );
    assert_eq!(record.capture_scope().earliest, TimestampNs(0));
    assert_eq!(record.capture_scope().latest, TimestampNs(1_100_000_000));
    let retained = diagnostic.retain(&mut f.deployment, diagnostic.approval_digest(), &f.cx)?;
    let verified = verify_retained(
        &f.deployment,
        retained.record_digest,
        retained.provenance_root,
        &HistoricalHealthReadLimits::default(),
        &f.cx,
    )?;
    assert!(verified.native_verified);
    assert_eq!(
        verified.frames_replayed, 0,
        "successful replay can reproduce explicit total refusal"
    );
    assert_eq!(verified.record.status(), "incomplete");
    Ok(())
}

#[test]
fn generic_append_cannot_forge_or_shadow_a_historical_diagnostic() -> Test {
    let mut f = Fixture::new("reserved", false)?;
    let report = f.analyze(false)?;
    let diagnostic = report.health_diagnostic().ok_or("diagnostic missing")?;
    let before = f.snapshot();
    let delta = diagnostic.record.delta(diagnostic.provenance_root())?;
    assert!(matches!(
        f.deployment.append_batch(
            batch_id(diagnostic.record_digest())?,
            vec![delta.clone()],
            vec![],
            &f.cx
        ),
        Err(ReferenceError::ReservedDeltaFamily { .. })
    ));
    let mut shadow = delta;
    shadow.family = "caller_invented_family".into();
    assert!(matches!(
        f.deployment.append_batch(
            BatchId::parse("batch:forged-health")?,
            vec![shadow],
            vec![],
            &f.cx
        ),
        Err(ReferenceError::ReservedDeltaFamily { .. })
    ));
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn current_privacy_change_preserves_historical_metadata_but_refuses_replay_and_retry() -> Test {
    let mut f = Fixture::new("privacy", false)?;
    let report = f.analyze(false)?;
    let diagnostic = report.health_diagnostic().ok_or("diagnostic missing")?;
    let retained = diagnostic.retain(&mut f.deployment, diagnostic.approval_digest(), &f.cx)?;
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:historical-health")?,
        [16, 16],
        &[[0, 0, 4, 4]],
    )?;
    let approval = preview_mask(&f.deployment, &policy)?.approval;
    declare_mask(&mut f.deployment, &policy, approval, &f.cx)?;
    let before = f.snapshot();
    assert_eq!(
        read_retained(
            &f.deployment,
            retained.record_digest,
            &HistoricalHealthReadLimits::default(),
            &f.cx
        )?
        .record
        .status(),
        "suspected_degradation"
    );
    assert!(matches!(
        verify_retained(
            &f.deployment,
            retained.record_digest,
            retained.provenance_root,
            &HistoricalHealthReadLimits::default(),
            &f.cx
        ),
        Err(HistoricalHealthError::PrivacyChanged)
    ));
    assert!(
        diagnostic
            .retain(&mut f.deployment, diagnostic.approval_digest(), &f.cx)
            .is_err()
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn retained_trace_damage_is_not_healed_from_a_cached_scan_or_metadata_inspection() -> Test {
    let mut f = Fixture::new("trace-damage", false)?;
    let report = f.analyze(false)?;
    let diagnostic = report.health_diagnostic().ok_or("diagnostic missing")?;
    let retained = diagnostic.retain(&mut f.deployment, diagnostic.approval_digest(), &f.cx)?;
    let path = f
        .deployment
        .publisher()
        .spool()
        .object_path(diagnostic.record.trace_digest());
    fs::remove_file(&path)?;
    let before = f.snapshot();
    let inspected = read_retained(
        &f.deployment,
        retained.record_digest,
        &HistoricalHealthReadLimits::default(),
        &f.cx,
    )?;
    assert!(
        !inspected.native_verified,
        "small metadata does not certify full trace custody"
    );
    assert!(
        verify_retained(
            &f.deployment,
            retained.record_digest,
            retained.provenance_root,
            &HistoricalHealthReadLimits::default(),
            &f.cx
        )
        .is_err()
    );
    assert!(
        diagnostic
            .retain(&mut f.deployment, diagnostic.approval_digest(), &f.cx)
            .is_err()
    );
    assert!(
        !path.exists(),
        "a retry never repairs custody from stale in-memory bytes"
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn import_deletion_covers_diagnostic_root_trace_receipt_and_blocks_cached_retention() -> Test {
    let mut f = Fixture::new("deletion", false)?;
    let report = f.analyze(false)?;
    let diagnostic = report.health_diagnostic().ok_or("diagnostic missing")?;
    let retained = diagnostic.retain(&mut f.deployment, diagnostic.approval_digest(), &f.cx)?;
    let plan = crate::deletion::plan_deletion(&f.deployment, f.plan.import_identity, &f.cx)?;
    assert!(plan.blockers.is_empty());
    let deleted = plan.deleted_set();
    for digest in [
        retained.record_digest,
        retained.provenance_root,
        diagnostic.record.trace_digest(),
    ] {
        assert!(
            deleted.contains(&digest),
            "source-closed deletion must cover {digest}"
        );
    }
    crate::deletion::commit_deletion(
        &mut f.deployment,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &f.cx,
    )?;
    let before = f.snapshot();
    assert!(
        read_retained(
            &f.deployment,
            retained.record_digest,
            &HistoricalHealthReadLimits::default(),
            &f.cx
        )
        .is_err()
    );
    assert!(
        diagnostic
            .retain(&mut f.deployment, diagnostic.approval_digest(), &f.cx)
            .is_err()
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn cold_prefix_cross_bindings_and_exact_reservation_admission_fail_closed() -> Test {
    let mut f = Fixture::new("bounds", false)?;
    let report = f.analyze(false)?;
    let diagnostic = report.health_diagnostic().ok_or("diagnostic missing")?;
    let original_batches = f.deployment.ledger().batches().len();
    let retained = diagnostic.retain(&mut f.deployment, diagnostic.approval_digest(), &f.cx)?;
    let read = |digest, bound| -> Result<Vec<u8>> {
        Ok(f.deployment
            .publisher()
            .spool()
            .read_bounded(digest, bound)?)
    };
    assert!(
        read_retained_at(
            &f.deployment.ledger().batches()[..original_batches + 1],
            retained.record_digest,
            read
        )
        .is_err(),
        "visible root alone is not diagnostic authority"
    );
    let mut altered = f.deployment.ledger().batches().to_vec();
    let _ = altered.last_mut().ok_or("batch missing")?.children.pop();
    assert!(read_retained_at(&altered, retained.record_digest, read).is_err());
    let mut bytes = diagnostic.record.to_bytes();
    bytes.push(0);
    assert!(HistoricalHealthRecord::from_bytes(&bytes).is_err());
    let mut limits = HistoricalHealthReadLimits::default();
    limits.maximum_metadata_bytes = 1;
    assert!(read_retained(&f.deployment, retained.record_digest, &limits, &f.cx).is_err());
    let mut limits = HistoricalHealthReadLimits::default();
    limits.execution.maximum_pixel_samples -= 1;
    assert!(matches!(
        verify_retained(
            &f.deployment,
            retained.record_digest,
            retained.provenance_root,
            &limits,
            &f.cx
        ),
        Err(HistoricalHealthError::Limit)
    ));
    assert!(
        verify_retained(
            &f.deployment,
            retained.record_digest,
            ContentDigest::sha256(b"different root"),
            &HistoricalHealthReadLimits::default(),
            &f.cx
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn cancellation_after_root_leaves_no_diagnostic_authority_and_retry_is_source_guarded() -> Test {
    let mut f = Fixture::new("root-prefix", false)?;
    let report = f.analyze(false)?;
    let diagnostic = report.health_diagnostic().ok_or("diagnostic missing")?;
    let before = f.deployment.current_anchor().commit_sequence;
    f.cx.set_cancel_at_checkpoint("historical_health:commit");
    assert!(
        diagnostic
            .retain(&mut f.deployment, diagnostic.approval_digest(), &f.cx)
            .is_err()
    );
    assert_eq!(f.deployment.current_anchor().commit_sequence, before + 1);
    assert!(retained_batch(f.deployment.ledger().batches(), diagnostic.record_digest()).is_none());
    f.cx = context(f.deployment.root())?;
    let retained = diagnostic.retain(&mut f.deployment, diagnostic.approval_digest(), &f.cx)?;
    assert!(!retained.already_retained);
    assert_eq!(f.deployment.current_anchor().commit_sequence, before + 2);
    assert!(
        diagnostic
            .retain(&mut f.deployment, diagnostic.approval_digest(), &f.cx)?
            .already_retained
    );
    assert_eq!(f.deployment.effects().operations().count(), 0);
    Ok(())
}
