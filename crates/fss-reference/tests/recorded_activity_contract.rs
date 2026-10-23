#![forbid(unsafe_code)]
//! Real retained imports through the native activity producer's failure and retry boundaries.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec, SensorId,
    StreamId, TimestampNs,
};
use fss_object::HostSpoolIo;
use fss_reference::activity_replay::ActivityReplayPlan;
use fss_reference::activity_replay::operator::{
    ActivityVerificationLimits, ActivityVerificationRequest, verify_retained_activity,
};
use fss_reference::executor_activity::ActivityThresholdPolicy;
use fss_reference::executor_activity_package::ACTIVITY_PACKAGE_V1_SHA256;
use fss_reference::ingest::recorded_activity::{
    RecordedActivityError, RecordedActivityLimits, RecordedActivityRequest,
    STAGE_ACTIVITY_BEFORE_PUBLISH, STAGE_ACTIVITY_RESULT, produce_recorded_activity,
};
use fss_reference::{
    ADP_FILE_ROW_ID, ADP_REPLAY_ROW_ID, ExecBudget, FileIngestAdapter, FileIngestLimits,
    FileIngestRequest, ReferenceDeployment, ReplayCx, ReplayIoAuthority, ScalarExecCx,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:recorded-activity";
const BACKGROUND: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/background.jpg");
const GRADIENT: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> TestResult<Self> {
        for _ in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fss-recorded-activity-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("scratch directory allowance exhausted".into())
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:recorded-activity".to_owned(),
        operation_id: OperationId::parse("operation:recorded-activity")?,
        principal: "operator:recorded-activity".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_owned(), ADP_FILE_ROW_ID.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: ContentDigest::sha256(b"recorded-activity-test"),
        generation: 1,
    })?;
    Ok(ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority,
        root.join("scratch"),
    )?))
}

struct Fixture {
    deployment: ReferenceDeployment,
    request: RecordedActivityRequest,
    cx: ReplayCx,
    root: PathBuf,
    _scratch: Scratch,
}
fn fixture() -> TestResult<Fixture> {
    recording(&[BACKGROUND, GRADIENT], 0, 1)
}

fn recording(sources: &[&[u8]], reference_segment: usize, segment: usize) -> TestResult<Fixture> {
    let scratch = Scratch::new()?;
    let root = scratch.0.join("deployment");
    let cx = context(&scratch.0)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let input = scratch.0.join("input.mjpeg");
    fs::write(&input, sources.concat())?;
    let sensor = SensorId::parse("sensor:recorded-activity")?;
    let stream = StreamId::parse("stream:recorded-activity")?;
    let imported = FileIngestAdapter::ingest(
        FileIngestRequest::new(&input, sensor.clone(), stream.clone())
            .with_receive_time(TimestampNs(5_000_000_000))
            .with_limits(FileIngestLimits {
                chunk_bytes: 67,
                max_batch_deltas: 8,
                ..FileIngestLimits::standard()
            }),
        &cx,
        &mut deployment,
    )?;
    assert_eq!(imported.capsule_count, sources.len());
    // Neither initial production nor a retry can fall back to the former input file.
    fs::remove_file(input)?;
    Ok(Fixture {
        deployment,
        cx,
        root,
        _scratch: scratch,
        request: RecordedActivityRequest {
            import_identity: imported.import_identity,
            reference_segment,
            segment,
            expected_package_sha256: ContentDigest::parse(ACTIVITY_PACKAGE_V1_SHA256)?,
            plan: ActivityReplayPlan {
                sensor_id: sensor,
                stream_id: stream,
                job_id: "job:recorded-activity".to_owned(),
                policy: ActivityThresholdPolicy::reference()?,
                interpretation: ComponentInterpretation::Grayscale,
                execution: ExecBudget::new(10_000_000, 16 * 1024 * 1024),
            },
        },
    })
}
fn tree(root: &Path) -> TestResult<BTreeMap<PathBuf, ContentDigest>> {
    let mut found = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else {
                found.insert(
                    entry.path().strip_prefix(root)?.to_path_buf(),
                    ContentDigest::sha256(&fs::read(entry.path())?),
                );
            }
        }
    }
    Ok(found)
}

#[test]
fn independent_package_and_shared_read_publication_history_budgets_refuse_before_writes()
-> TestResult {
    let mut f = fixture()?;
    let before = tree(&f.root)?;
    let mut wrong = f.request.clone();
    wrong.expected_package_sha256 = ContentDigest::sha256(b"another package");
    assert!(matches!(
        produce_recorded_activity(
            &mut f.deployment,
            wrong,
            RecordedActivityLimits::default(),
            &f.cx,
            &ScalarExecCx::new()
        ),
        Err(RecordedActivityError::PackagePin)
    ));
    for limits in [
        RecordedActivityLimits {
            max_source_read_bytes: 1,
            ..RecordedActivityLimits::default()
        },
        RecordedActivityLimits {
            max_staged_bytes: 1,
            ..RecordedActivityLimits::default()
        },
        RecordedActivityLimits {
            max_history_batches: 0,
            ..RecordedActivityLimits::default()
        },
        RecordedActivityLimits {
            max_history_entries: 1,
            ..RecordedActivityLimits::default()
        },
    ] {
        assert!(
            produce_recorded_activity(
                &mut f.deployment,
                f.request.clone(),
                limits,
                &f.cx,
                &ScalarExecCx::new()
            )
            .is_err()
        );
        assert_eq!(before, tree(&f.root)?);
    }
    Ok(())
}

#[test]
fn cancellation_after_computation_but_before_publication_leaves_import_unchanged() -> TestResult {
    let mut f = fixture()?;
    let before = tree(&f.root)?;
    f.cx.set_cancel_at_checkpoint(STAGE_ACTIVITY_BEFORE_PUBLISH);
    let scalar = ScalarExecCx::new();
    let result = produce_recorded_activity(
        &mut f.deployment,
        f.request.clone(),
        RecordedActivityLimits::default(),
        &f.cx,
        &scalar,
    );
    assert!(
        matches!(result, Err(RecordedActivityError::Cancelled)),
        "{result:?}"
    );
    assert!(scalar.is_drain_completed());
    assert_eq!(before, tree(&f.root)?);
    Ok(())
}

#[test]
fn source_commit_survives_cancellation_and_cold_exact_retry_finishes_once() -> TestResult {
    let mut f = fixture()?;
    f.cx.set_cancel_at_checkpoint(STAGE_ACTIVITY_RESULT);
    let result = produce_recorded_activity(
        &mut f.deployment,
        f.request.clone(),
        RecordedActivityLimits::default(),
        &f.cx,
        &ScalarExecCx::new(),
    );
    assert!(
        matches!(result, Err(RecordedActivityError::Cancelled)),
        "{result:?}"
    );
    let roots: Vec<_> = f
        .deployment
        .publisher()
        .visible_roots()
        .filter(|root| root.slot.as_str().starts_with("xi-"))
        .map(|root| (root.slot.clone(), root.root))
        .collect();
    assert_eq!(
        roots.len(),
        1,
        "complete source custody must survive cancellation"
    );
    assert!(!f.deployment.ledger().batches().iter().any(|batch| {
        batch
            .deltas
            .iter()
            .any(|delta| delta.family == "executor_model_result")
    }));
    drop(f.deployment);
    let fresh = context(&f._scratch.0)?;
    let mut deployment = ReferenceDeployment::reopen(&f.root, SITE, &fresh)?;
    let completed = produce_recorded_activity(
        &mut deployment,
        f.request.clone(),
        RecordedActivityLimits::default(),
        &fresh,
        &ScalarExecCx::new(),
    )?;
    assert_eq!(
        roots,
        vec![(completed.source_slot.clone(), completed.source_root)]
    );
    assert!(!completed.retained.result.supports_absence_claim());
    assert!(completed.source_read_bytes > 0 && completed.decode_work > 0);
    let before_retry = tree(&f.root)?;
    let retried = produce_recorded_activity(
        &mut deployment,
        f.request.clone(),
        RecordedActivityLimits::default(),
        &fresh,
        &ScalarExecCx::new(),
    )?;
    assert_eq!(
        completed.retained.result_digest,
        retried.retained.result_digest
    );
    assert_eq!(completed.final_anchor, retried.final_anchor);
    assert_eq!(completed.source_read_bytes, retried.source_read_bytes);
    assert_eq!(completed.decode_work, retried.decode_work);
    assert_eq!(before_retry, tree(&f.root)?);
    Ok(())
}

#[test]
fn exact_retry_refuses_damaged_published_jpeg_copy_without_repairing_it() -> TestResult {
    let mut f = fixture()?;
    let complete = produce_recorded_activity(
        &mut f.deployment,
        f.request.clone(),
        RecordedActivityLimits::default(),
        &f.cx,
        &ScalarExecCx::new(),
    )?;
    // The input was split into 67-byte chunks. This complete-JPEG role is a different object;
    // the original imported source still verifies, so this specifically exercises retry custody.
    let copied = f
        .deployment
        .publisher()
        .spool()
        .object_path(complete.retained.result.input_capture_root);
    fs::write(&copied, b"damaged published JPEG role")?;
    let before = tree(&f.root)?;
    let retry = produce_recorded_activity(
        &mut f.deployment,
        f.request.clone(),
        RecordedActivityLimits::default(),
        &f.cx,
        &ScalarExecCx::new(),
    );
    assert!(
        matches!(retry, Err(RecordedActivityError::Spool(_))),
        "{retry:?}"
    );
    assert_eq!(
        before,
        tree(&f.root)?,
        "retry repaired a damaged immutable publication"
    );
    Ok(())
}

#[test]
fn distinct_earlier_capsules_with_identical_jpegs_share_result_without_colliding_roles()
-> TestResult {
    let mut f = recording(&[BACKGROUND, BACKGROUND, GRADIENT], 0, 2)?;
    let first = produce_recorded_activity(
        &mut f.deployment,
        f.request.clone(),
        RecordedActivityLimits::default(),
        &f.cx,
        &ScalarExecCx::new(),
    )?;
    f.request.reference_segment = 1;
    let second = produce_recorded_activity(
        &mut f.deployment,
        f.request.clone(),
        RecordedActivityLimits::default(),
        &f.cx,
        &ScalarExecCx::new(),
    )?;
    assert_eq!(first.retained.result_digest, second.retained.result_digest);
    assert_eq!(first.retained.anchor, second.retained.anchor);
    assert_ne!(first.reference_capsule, second.reference_capsule);
    assert_ne!(first.source_slot, second.source_slot);
    assert_ne!(first.source_root, second.source_root);
    drop(f.deployment);
    for receipt in [first, second] {
        let slots = [receipt.source_slot.clone()];
        let verified = verify_retained_activity(
            ActivityVerificationRequest {
                root: &f.root,
                site: SITE,
                expected_ledger_root: None,
                result: receipt.retained.result_digest,
                reference_capsule: receipt.reference_capsule,
                source_slots: &slots,
                plan: receipt.plan.clone(),
            },
            &HostSpoolIo,
            ActivityVerificationLimits::default(),
            &ScalarExecCx::new(),
            &|| false,
        )?;
        assert_eq!(
            verified.result().object_digest(),
            receipt.retained.result_digest
        );
    }
    Ok(())
}
