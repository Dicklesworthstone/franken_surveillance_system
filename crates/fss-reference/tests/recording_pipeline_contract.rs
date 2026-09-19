#![forbid(unsafe_code)]
//! Retained recording -> canonical decode -> exact inference -> complete analysis contracts.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};
use fss_reference::ingest::{FileIngestAdapter, FileIngestRequest};
use fss_reference::ingest::analysis::{AnalysisBudget, AnalysisLimits, AnalysisReport};
use fss_reference::ingest::detections::{BoxEncoding, CoordinateSpace, DetectionSpec};
use fss_reference::ingest::inference::RecordedModel;
use fss_reference::ingest::recorded_decode::{
    ComponentInterpretation, DecodeBudget, RecordedDecodeRequest, RecordedFrame,
    STAGE_RECORDED_DECODE_COMMIT,
};
use fss_reference::ingest::recording_pipeline::{
    RecordingBudget, RecordingError, RecordingRequest, RecordingStage, run_recording,
};
use fss_reference::ingest::tracking::TrackingConfig;

const JPEG: &[u8] = include_bytes!("../../fss-cli/tests/fixtures/retained_file_8x8.jpg");
const MODEL: &[u8] = include_bytes!("../../fss-cli/tests/fixtures/detector_rows_8x8.fssmodel");
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> TestResult<Self> {
        for n in 0..100 {
            let path = std::env::temp_dir().join(format!("fss-pipeline-{label}-{}-{n}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(e) => return Err(e.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:pipeline".into(), operation_id: OperationId::parse("operation:pipeline")?,
        principal: "principal:pipeline".into(), capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None, priority: 10, budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:pipeline"), generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(&authority, root.to_path_buf())?)
}
struct Fixture {
    dir: Directory, cx: ReplayCx, deployment: ReferenceDeployment,
    request: RecordingRequest, model: RecordedModel,
}
fn fixture(label: &str) -> TestResult<Fixture> {
    let dir = Directory::new(label)?;
    let root = dir.0.join("deployment");
    let source = dir.0.join("source.mjpeg");
    fs::write(&source, [JPEG, JPEG, JPEG].concat())?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, "site:pipeline", &cx)?;
    let imported = FileIngestAdapter::ingest(FileIngestRequest::new(&source,
        SensorId::parse("sensor:pipeline")?, StreamId::parse("stream:pipeline")?)
        .with_receive_time(TimestampNs(1_000_000_000)), &cx, &mut deployment)?;
    let model = RecordedModel::decode(MODEL, ContentDigest::sha256(MODEL))?;
    let request = RecordingRequest {
        import_identity: imported.import_identity, interpretation: ComponentInterpretation::Grayscale,
        first_segment: 0, segment_count: 3, maximum_tensor_bytes: 64 * 1024 * 1024,
        limits: AnalysisLimits::default(),
        detector: DetectionSpec { model_digest: model.digest(), output_port: "detections".into(),
            labels: vec!["vehicle".into(), "animal".into()], encoding: BoxEncoding::Xyxy,
            coordinates: CoordinateSpace::Normalized, minimum_score_ppm: 500_000,
            nms_iou_ppm: 500_000, maximum_rows: 4096, maximum_detections: 128 },
        tracking: TrackingConfig { minimum_iou_ppm: 300_000, confirmation_hits: 2,
            maximum_missed_frames: 2, maximum_tracks: 128 },
    };
    Ok(Fixture { dir, cx, deployment, request, model })
}
fn budget() -> RecordingBudget<'static> {
    RecordingBudget::new(DecodeBudget::new(1_000_000_000), 1_000_000_000,
        AnalysisBudget::new(1_000_000, 1_000_000))
}
fn source(request: &RecordingRequest, segment_index: usize) -> RecordedDecodeRequest {
    RecordedDecodeRequest { import_identity: request.import_identity, segment_index,
        interpretation: request.interpretation, read_limits: request.limits.read_limits,
        decode_limits: request.limits.decode_limits }
}
fn model_receipts(deployment: &ReferenceDeployment) -> usize {
    deployment.ledger().batches().iter().flat_map(|batch| &batch.deltas)
        .filter(|delta| delta.family == "model_invocation_receipt").count()
}

#[test]
fn complete_recording_replays_after_restart_with_zero_numeric_allowance() -> TestResult {
    let mut f = fixture("restart")?;
    let mut work = budget();
    let result = run_recording(&mut f.deployment, &f.request, &f.model, &mut work, &ScalarExecCx::new(), &f.cx)?;
    assert_eq!(result.progress.stage, RecordingStage::Complete);
    assert_eq!(result.progress.new_decodes, 3);
    assert_eq!(result.progress.new_inferences, 3);
    assert_eq!(result.report.observations().len(), 3);
    assert!(result.report.observations()[2].tracking().tracks.iter().all(|t| t.confirmed));
    assert!(work.decode.used() > 0 && work.model_charged() > 0);
    assert_eq!(model_receipts(&f.deployment), 3);
    let anchor = f.deployment.current_anchor().clone();
    fs::remove_file(f.dir.0.join("source.mjpeg"))?;
    drop(f.deployment);
    let mut reopened = ReferenceDeployment::open(&f.dir.0.join("deployment"), "site:pipeline", &f.cx)?;
    let restored_model = RecordedModel::decode(&reopened.publisher().spool().read(f.model.digest())?, f.model.digest())?;
    let mut reused = RecordingBudget::new(DecodeBudget::new(0), 0, AnalysisBudget::new(1_000_000, 1_000_000));
    let again = run_recording(&mut reopened, &f.request, &restored_model, &mut reused, &ScalarExecCx::new(), &f.cx)?;
    assert_eq!(again.report.encoded(), result.report.encoded());
    assert_eq!(again.progress.completed, result.progress.completed);
    assert_eq!(again.progress.reused_decodes, 3);
    assert_eq!(again.progress.reused_inferences, 3);
    assert_eq!(again.progress.new_decodes + again.progress.new_inferences, 0);
    assert_eq!(*reopened.current_anchor(), anchor);
    assert_eq!(reused.decode.used(), 0);
    assert_eq!(reused.model_charged(), 0);
    assert!(reused.analysis.detection.used() > 0);
    AnalysisReport::verify(&reopened, again.report.encoded(), again.report.digest(), &f.request.limits,
        &mut AnalysisBudget::new(1_000_000, 1_000_000), &f.cx)?;
    assert_eq!(*reopened.current_anchor(), anchor);
    Ok(())
}

#[test]
fn cumulative_model_budget_stops_at_exact_prefix_and_retry_reuses_it() -> TestResult {
    let mut oracle = fixture("cost")?;
    oracle.request.segment_count = 1;
    let mut one = budget();
    run_recording(&mut oracle.deployment, &oracle.request, &oracle.model, &mut one, &ScalarExecCx::new(), &oracle.cx)?;
    let cost = one.model_charged();
    assert!(cost > 0);
    let mut f = fixture("partial")?;
    let mut limited = RecordingBudget::new(DecodeBudget::new(1_000_000_000), cost, AnalysisBudget::new(1_000_000, 1_000_000));
    let error = run_recording(&mut f.deployment, &f.request, &f.model, &mut limited, &ScalarExecCx::new(), &f.cx)
        .expect_err("second invocation cannot get a fresh work allowance");
    assert_eq!(error.progress.stage, RecordingStage::Inference);
    assert_eq!(error.progress.next_segment, Some(1));
    assert_eq!(error.progress.completed.len(), 1);
    assert_eq!(error.progress.new_decodes, 2);
    assert_eq!(error.progress.new_inferences, 1);
    assert_eq!(limited.model_charged(), cost);
    assert_eq!(limited.model_remaining(), 0);
    assert_eq!(model_receipts(&f.deployment), 1);
    let mut remaining = RecordingBudget::new(DecodeBudget::new(1_000_000_000), 2 * cost, AnalysisBudget::new(1_000_000, 1_000_000));
    let done = run_recording(&mut f.deployment, &f.request, &f.model, &mut remaining, &ScalarExecCx::new(), &f.cx)?;
    assert_eq!(done.progress.completed[0], error.progress.completed[0]);
    assert_eq!(done.progress.reused_decodes, 2);
    assert_eq!(done.progress.new_decodes, 1);
    assert_eq!(done.progress.reused_inferences, 1);
    assert_eq!(done.progress.new_inferences, 2);
    assert_eq!(remaining.model_charged(), 2 * cost);
    assert_eq!(model_receipts(&f.deployment), 3);
    Ok(())
}

#[test]
fn failed_execution_reservation_is_not_refunded_as_zero_work() -> TestResult {
    let mut f = fixture("reservation")?;
    let mut limited = RecordingBudget::new(DecodeBudget::new(1_000_000_000), 1, AnalysisBudget::new(1_000_000, 1_000_000));
    let error = run_recording(&mut f.deployment, &f.request, &f.model, &mut limited, &ScalarExecCx::new(), &f.cx)
        .expect_err("graph needs more than one work unit");
    assert_eq!(error.progress.completed.len(), 0);
    assert_eq!(error.progress.new_decodes, 1);
    assert_eq!(limited.model_charged(), 1);
    assert_eq!(limited.model_remaining(), 0);
    assert_eq!(model_receipts(&f.deployment), 0);
    Ok(())
}

#[test]
fn malformed_contracts_and_out_of_range_source_publish_nothing() -> TestResult {
    let mut f = fixture("preflight")?;
    let before = f.deployment.current_anchor().clone();
    for case in 0..8 {
        let mut request = f.request.clone();
        match case {
            0 => request.segment_count = 0,
            1 => request.segment_count = 257,
            2 => request.first_segment = usize::MAX,
            3 => request.detector.model_digest = ContentDigest::sha256(b"wrong model"),
            4 => request.detector.output_port = "missing".into(),
            5 => request.detector.maximum_rows = 2,
            6 => request.first_segment = 3,
            _ => request.maximum_tensor_bytes = 1,
        }
        let mut work = budget();
        let error = run_recording(&mut f.deployment, &request, &f.model, &mut work, &ScalarExecCx::new(), &f.cx)
            .expect_err("invalid request");
        assert_eq!(error.progress.stage, RecordingStage::Preflight);
        assert!(error.progress.completed.is_empty());
        assert_eq!(work.model_charged(), 0);
        assert_eq!(work.decode.used(), 0);
        assert_eq!(*f.deployment.current_anchor(), before);
    }
    Ok(())
}

#[test]
fn detector_budget_failure_keeps_all_runs_but_never_returns_a_partial_report() -> TestResult {
    let mut f = fixture("analysis-budget")?;
    let mut work = RecordingBudget::new(DecodeBudget::new(1_000_000_000), 1_000_000_000, AnalysisBudget::new(0, 0));
    let error = run_recording(&mut f.deployment, &f.request, &f.model, &mut work, &ScalarExecCx::new(), &f.cx)
        .expect_err("postprocessing needs explicit work");
    assert_eq!(error.progress.stage, RecordingStage::Analysis);
    assert_eq!(error.progress.next_segment, None);
    assert_eq!(error.progress.completed.len(), 3);
    assert_eq!(model_receipts(&f.deployment), 3);
    let before = f.deployment.current_anchor().clone();
    let mut retry = RecordingBudget::new(DecodeBudget::new(0), 0, AnalysisBudget::new(1_000_000, 1_000_000));
    let complete = run_recording(&mut f.deployment, &f.request, &f.model, &mut retry, &ScalarExecCx::new(), &f.cx)?;
    assert_eq!(complete.progress.completed, error.progress.completed);
    assert_eq!(*f.deployment.current_anchor(), before);
    Ok(())
}

#[test]
fn cancelled_owner_or_executor_cannot_start_or_reuse_work() -> TestResult {
    let mut f = fixture("cancel")?;
    let before = f.deployment.current_anchor().clone();
    let exec = ScalarExecCx::new(); exec.request_cancellation();
    assert!(run_recording(&mut f.deployment, &f.request, &f.model, &mut budget(), &exec, &f.cx).is_err());
    assert_eq!(*f.deployment.current_anchor(), before);
    f.cx.set_cancel_at_checkpoint("recording_pipeline:preflight");
    let error = run_recording(&mut f.deployment, &f.request, &f.model, &mut budget(), &ScalarExecCx::new(), &f.cx)
        .expect_err("cancelled owner");
    assert!(matches!(error.cause, RecordingError::Cancelled));
    assert_eq!(*f.deployment.current_anchor(), before);
    Ok(())
}

#[test]
fn cancellation_after_inference_recovers_without_repeating_numeric_work() -> TestResult {
    let mut f = fixture("cancel-analysis")?;
    f.cx.set_cancel_at_checkpoint("recording_pipeline:analysis");
    let error = run_recording(&mut f.deployment, &f.request, &f.model, &mut budget(), &ScalarExecCx::new(), &f.cx)
        .expect_err("analysis boundary cancelled");
    assert_eq!(error.progress.stage, RecordingStage::Analysis);
    assert_eq!(error.progress.completed.len(), 3);
    let fresh = context(&f.dir.0.join("deployment"))?;
    let mut retry = RecordingBudget::new(DecodeBudget::new(0), 0, AnalysisBudget::new(1_000_000, 1_000_000));
    let done = run_recording(&mut f.deployment, &f.request, &f.model, &mut retry, &ScalarExecCx::new(), &fresh)?;
    assert_eq!(done.progress.completed, error.progress.completed);
    assert_eq!(done.progress.reused_inferences, 3);
    Ok(())
}

#[test]
fn interrupted_decode_root_resumes_then_completes_the_same_pipeline() -> TestResult {
    let mut f = fixture("decode-cut")?;
    f.cx.set_cancel_at_checkpoint(STAGE_RECORDED_DECODE_COMMIT);
    let error = run_recording(&mut f.deployment, &f.request, &f.model, &mut budget(), &ScalarExecCx::new(), &f.cx)
        .expect_err("cut between root and final receipt");
    assert_eq!(error.progress.stage, RecordingStage::Decode);
    assert!(error.progress.completed.is_empty());
    drop(f.deployment);
    let fresh = context(&f.dir.0.join("deployment"))?;
    let mut reopened = ReferenceDeployment::open(&f.dir.0.join("deployment"), "site:pipeline", &fresh)?;
    let completed = run_recording(&mut reopened, &f.request, &f.model, &mut budget(), &ScalarExecCx::new(), &fresh)?;
    assert_eq!(completed.report.observations().len(), 3);
    assert_eq!(model_receipts(&reopened), 3);
    Ok(())
}

#[test]
fn missing_completed_pixels_are_not_silently_regenerated_by_retry() -> TestResult {
    let mut f = fixture("missing-pixels")?;
    let selected = source(&f.request, 0);
    let frame = RecordedFrame::decode_and_publish(&mut f.deployment, &selected, &mut DecodeBudget::new(1_000_000_000), &f.cx)?;
    let path = f.deployment.publisher().spool().object_path(ContentDigest::sha256(frame.pixels()));
    fs::remove_file(&path)?;
    let before = f.deployment.current_anchor().clone();
    let mut work = budget();
    let error = run_recording(&mut f.deployment, &f.request, &f.model, &mut work, &ScalarExecCx::new(), &f.cx)
        .expect_err("completion is not a cache miss when custody is missing");
    assert_eq!(error.progress.stage, RecordingStage::Decode);
    assert_eq!(work.decode.used(), 0);
    assert_eq!(work.model_charged(), 0);
    assert!(!path.exists());
    assert_eq!(*f.deployment.current_anchor(), before);
    Ok(())
}

#[test]
fn corrupted_completed_pixels_refuse_without_spending_decode_allowance() -> TestResult {
    let mut f = fixture("corrupt-pixels")?;
    let selected = source(&f.request, 0);
    let frame = RecordedFrame::decode_and_publish(&mut f.deployment, &selected, &mut DecodeBudget::new(1_000_000_000), &f.cx)?;
    let path = f.deployment.publisher().spool().object_path(ContentDigest::sha256(frame.pixels()));
    let mut corrupt = frame.pixels().to_vec(); corrupt[0] ^= 1; fs::write(&path, &corrupt)?;
    let before = f.deployment.current_anchor().clone();
    let mut work = DecodeBudget::new(1_000_000_000);
    assert!(RecordedFrame::decode_and_publish(&mut f.deployment, &selected, &mut work, &f.cx).is_err());
    assert_eq!(work.used(), 0);
    assert_eq!(fs::read(path)?, corrupt);
    assert_eq!(*f.deployment.current_anchor(), before);
    Ok(())
}

#[test]
fn cached_runs_still_enforce_tensor_and_decoded_frame_bounds() -> TestResult {
    let mut f = fixture("cached-limits")?;
    run_recording(&mut f.deployment, &f.request, &f.model, &mut budget(), &ScalarExecCx::new(), &f.cx)?;
    let before = f.deployment.current_anchor().clone();
    f.request.limits.decode_limits.maximum_pixels = 1;
    let mut work = budget();
    assert!(run_recording(&mut f.deployment, &f.request, &f.model, &mut work, &ScalarExecCx::new(), &f.cx).is_err());
    assert_eq!(work.decode.used(), 0);
    assert_eq!(*f.deployment.current_anchor(), before);
    f.request.limits = AnalysisLimits::default();
    f.request.maximum_tensor_bytes = f.model.graph().inputs().iter().try_fold(0_usize, |sum, port| {
        Ok::<usize, fss_tensor::TensorError>(sum + port.shape().size_bytes(port.dtype())?)
    })?;
    let refused = run_recording(&mut f.deployment, &f.request, &f.model, &mut budget(), &ScalarExecCx::new(), &f.cx)
        .expect_err("cached intermediate/output accounting exceeds the input-only ceiling");
    assert_eq!(refused.progress.stage, RecordingStage::Inference);
    assert_eq!(*f.deployment.current_anchor(), before);
    Ok(())
}

#[test]
fn empty_thresholded_results_are_complete_analysis_not_fabricated_tracks() -> TestResult {
    let mut f = fixture("empty")?;
    f.request.detector.minimum_score_ppm = 1_000_000;
    let done = run_recording(&mut f.deployment, &f.request, &f.model, &mut budget(), &ScalarExecCx::new(), &f.cx)?;
    assert_eq!(done.report.observations().len(), 3);
    for observation in done.report.observations() {
        assert!(observation.detection().detections().is_empty());
        assert!(observation.tracking().tracks.is_empty());
    }
    assert!(f.deployment.ledger().batches().iter().flat_map(|b| &b.deltas)
        .all(|d| d.family != "event_revision" && d.family != "effect_receipt"));
    Ok(())
}
