#![forbid(unsafe_code)]
//! Real retained JPEG/model fixtures exercise selection, inference, sparse tracks and replay.

use std::{error::Error, fs, path::{Path, PathBuf}};
use fss_core::{BudgetVector, CanonicalDecoder, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};
use fss_reference::ingest::{FileIngestAdapter, FileIngestRequest};
use fss_reference::ingest::activity::{ActivityError, ActivityPolicy, ActivitySampler, SamplingReason};
use fss_reference::ingest::analysis::{AnalysisBudget, AnalysisLimits};
use fss_reference::ingest::detections::{BoxEncoding, CoordinateSpace, DetectionSpec};
use fss_reference::ingest::inference::RecordedModel;
use fss_reference::ingest::pixel_change::PixelChangeConfig;
use fss_reference::ingest::recorded_decode::{ComponentInterpretation, DecodeBudget, RecordedDecodeRequest, RecordedFrame};
use fss_reference::ingest::recording_pipeline::{RecordingBudget, RecordingRequest, RecordingStage, run_recording};
use fss_reference::ingest::recording_pipeline::sampling::{
    RequiredFrame, SampledReport, SamplingPlan, run_sampled_recording,
};
use fss_reference::ingest::tracking::TrackingConfig;

const JPEG: &[u8] = include_bytes!("../../fss-cli/tests/fixtures/retained_file_8x8.jpg");
const MODEL: &[u8] = include_bytes!("../../fss-cli/tests/fixtures/detector_rows_8x8.fssmodel");
type TestResult<T = ()> = Result<T, Box<dyn Error>>;
struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> TestResult<Self> {
        for n in 0..100 {
            let path = std::env::temp_dir().join(format!("fss-sampling-{label}-{}-{n}", std::process::id()));
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
        trace_id: "trace:sampling".into(), operation_id: OperationId::parse("operation:sampling")?,
        principal: "principal:sampling".into(), capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None, priority: 10, budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:sampling"), generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(&authority, root.to_path_buf())?)
}
struct Fixture {
    dir: Directory, cx: ReplayCx, deployment: ReferenceDeployment, request: RecordingRequest, model: RecordedModel,
}
fn fixture(label: &str, count: usize) -> TestResult<Fixture> {
    let dir = Directory::new(label)?;
    let root = dir.0.join("deployment"); let source = dir.0.join("source.mjpeg");
    fs::write(&source, JPEG.repeat(count))?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, "site:sampling", &cx)?;
    let imported = FileIngestAdapter::ingest(FileIngestRequest::new(&source,
        SensorId::parse("sensor:sampling")?, StreamId::parse("stream:sampling")?)
        .with_receive_time(TimestampNs(1_000_000_000)), &cx, &mut deployment)?;
    let model = RecordedModel::decode(MODEL, ContentDigest::sha256(MODEL))?;
    let request = RecordingRequest {
        import_identity: imported.import_identity, interpretation: ComponentInterpretation::Grayscale,
        first_segment: 0, segment_count: count, maximum_tensor_bytes: 64 * 1024 * 1024,
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
fn policy(stride: u32) -> ActivityPolicy {
    ActivityPolicy { change: PixelChangeConfig { minimum_delta: 20, minimum_changed_pixels: 1,
        minimum_changed_fraction_ppm: 0 }, sentinel_stride: stride, post_activity_frames: 0 }
}
fn budget(model_units: u64, decode_units: u64) -> RecordingBudget<'static> {
    RecordingBudget::new(DecodeBudget::new(decode_units), model_units, AnalysisBudget::new(1_000_000, 1_000_000))
}
fn normal_budget() -> RecordingBudget<'static> { budget(1_000_000_000, 1_000_000_000) }
fn receipt_count(deployment: &ReferenceDeployment, family: &str) -> usize {
    deployment.ledger().batches().iter().flat_map(|b| &b.deltas).filter(|d| d.family == family).count()
}
fn selected(report: &SampledReport) -> Vec<u64> {
    report.decisions().iter().filter(|d| d.selected()).map(|d| d.segment_index()).collect()
}
fn source(request: &RecordingRequest, index: usize) -> RecordedDecodeRequest {
    RecordedDecodeRequest { import_identity: request.import_identity, interpretation: request.interpretation,
        segment_index: index, read_limits: request.limits.read_limits, decode_limits: request.limits.decode_limits }
}

#[test]
fn quiet_recording_executes_only_sentinels_and_keeps_all_source_decisions() -> TestResult {
    let mut f = fixture("quiet", 9)?;
    let plan = SamplingPlan::new(&f.request, policy(3), 10_000, vec![])?;
    let out = run_sampled_recording(&mut f.deployment, &f.request, &f.model, &plan,
        &mut normal_budget(), &ScalarExecCx::new(), &f.cx)?;
    assert_eq!(out.progress.stage, RecordingStage::Complete);
    assert_eq!(selected(&out.report), [0, 3, 6]);
    assert_eq!(out.report.decisions().len(), 9); assert_eq!(out.report.skipped_frames(), 6);
    assert_eq!(out.progress.new_decodes, 9); assert_eq!(out.progress.new_inferences, 3);
    assert_eq!(receipt_count(&f.deployment, "model_invocation_receipt"), 3);
    assert_eq!(receipt_count(&f.deployment, "decode_receipt"), 9);
    assert_eq!(out.report.comparisons_used(), 8 * 64);
    for d in out.report.decisions() { RecordedFrame::open(&f.deployment, &source(&f.request, d.segment_index() as usize), &f.cx)?; }
    // A gap cannot count as a sequence of empty frames or confirm a track across omissions.
    assert!(out.report.analysis().observations().iter().flat_map(|o| &o.tracking().tracks).all(|t| !t.confirmed));
    Ok(())
}

#[test]
fn required_quiet_frames_override_sampling_and_policy_is_canonical() -> TestResult {
    let mut f = fixture("required", 7)?;
    let basis = ContentDigest::sha256(b"obligation:inspect-exact-frame");
    let required = vec![RequiredFrame { segment_index: 5, basis }, RequiredFrame { segment_index: 2, basis }];
    let plan = SamplingPlan::new(&f.request, policy(3), 10_000, required.clone())?;
    let reverse = SamplingPlan::new(&f.request, policy(3), 10_000, required.into_iter().rev().collect())?;
    assert_eq!(plan.encoded(), reverse.encoded());
    let restored = SamplingPlan::decode(plan.encoded(), plan.digest())?;
    let out = run_sampled_recording(&mut f.deployment, &f.request, &f.model, &restored,
        &mut normal_budget(), &ScalarExecCx::new(), &f.cx)?;
    assert_eq!(selected(&out.report), [0, 2, 3, 5, 6]);
    assert!(out.report.decisions()[2].reasons().contains(&SamplingReason::Required));
    assert!(out.report.decisions()[5].reasons().contains(&SamplingReason::Required));
    Ok(())
}

#[test]
fn no_comparison_budget_forces_inference_instead_of_inventing_quiet() -> TestResult {
    let mut f = fixture("floor", 7)?;
    let plan = SamplingPlan::new(&f.request, policy(256), 0, vec![])?;
    let out = run_sampled_recording(&mut f.deployment, &f.request, &f.model, &plan,
        &mut normal_budget(), &ScalarExecCx::new(), &f.cx)?;
    assert_eq!(out.progress.new_inferences, 7); assert_eq!(out.report.skipped_frames(), 0);
    assert_eq!(out.report.comparisons_used(), 0);
    assert!(out.report.decisions().iter().any(|d| d.reasons().contains(&SamplingReason::ComparisonBudgetFloor)));
    assert!(out.report.decisions().iter().filter(|d| d.reasons().contains(&SamplingReason::ComparisonBudgetFloor))
        .all(|d| d.measurement().is_none()));
    Ok(())
}

#[test]
fn stride_one_preserves_the_existing_all_frame_analysis_exactly() -> TestResult {
    let mut f = fixture("all", 4)?;
    let old = run_recording(&mut f.deployment, &f.request, &f.model, &mut normal_budget(), &ScalarExecCx::new(), &f.cx)?;
    let plan = SamplingPlan::new(&f.request, policy(1), 10_000, vec![])?;
    let out = run_sampled_recording(&mut f.deployment, &f.request, &f.model, &plan,
        &mut budget(0, 0), &ScalarExecCx::new(), &f.cx)?;
    assert_eq!(out.report.analysis().encoded(), old.report.encoded());
    assert_eq!(out.progress.new_decodes + out.progress.new_inferences, 0);
    assert_eq!(out.progress.reused_inferences, 4);
    Ok(())
}

#[test]
fn restart_reuses_selected_numeric_work_and_verifies_skipped_evidence_read_only() -> TestResult {
    let mut f = fixture("restart", 7)?;
    let plan = SamplingPlan::new(&f.request, policy(3), 10_000, vec![])?;
    let out = run_sampled_recording(&mut f.deployment, &f.request, &f.model, &plan,
        &mut normal_budget(), &ScalarExecCx::new(), &f.cx)?;
    let anchor = f.deployment.current_anchor().clone();
    fs::remove_file(f.dir.0.join("source.mjpeg"))?;
    drop(f.deployment);
    let mut deployment = ReferenceDeployment::open(&f.dir.0.join("deployment"), "site:sampling", &f.cx)?;
    let plan = SamplingPlan::decode(plan.encoded(), plan.digest())?;
    let mut work = budget(0, 0);
    let again = run_sampled_recording(&mut deployment, &f.request, &f.model, &plan, &mut work, &ScalarExecCx::new(), &f.cx)?;
    assert_eq!(again.report.encoded(), out.report.encoded());
    assert_eq!(again.progress.reused_decodes, 7); assert_eq!(again.progress.reused_inferences, 3);
    assert_eq!(work.model_charged(), 0); assert_eq!(work.decode.used(), 0);
    let verified = SampledReport::verify(&deployment, out.report.encoded(), out.report.digest(),
        &f.request.limits, 10_000, &mut AnalysisBudget::new(1_000_000, 1_000_000), &f.cx)?;
    assert_eq!(verified.encoded(), out.report.encoded());
    assert_eq!(*deployment.current_anchor(), anchor);
    Ok(())
}

#[test]
fn model_budget_cannot_drop_a_due_sentinel_and_exact_retry_reuses_prefix() -> TestResult {
    let mut oracle = fixture("one-cost", 1)?; let mut one = normal_budget();
    run_recording(&mut oracle.deployment, &oracle.request, &oracle.model, &mut one, &ScalarExecCx::new(), &oracle.cx)?;
    let cost = one.model_charged(); assert!(cost > 0);
    let mut f = fixture("partial", 7)?;
    let plan = SamplingPlan::new(&f.request, policy(3), 10_000, vec![])?;
    let mut limited = budget(cost, 1_000_000_000);
    let failed = run_sampled_recording(&mut f.deployment, &f.request, &f.model, &plan,
        &mut limited, &ScalarExecCx::new(), &f.cx).err().ok_or("due sentinel was skipped")?;
    assert_eq!(failed.progress.stage, RecordingStage::Inference);
    assert_eq!(failed.progress.next_segment, Some(3)); assert_eq!(failed.progress.completed.len(), 1);
    assert_eq!(failed.decisions.len(), 4); assert!(failed.decisions[3].selected());
    assert_eq!(limited.model_charged(), cost);
    let mut remaining = budget(cost * 2, 1_000_000_000);
    let done = run_sampled_recording(&mut f.deployment, &f.request, &f.model, &plan,
        &mut remaining, &ScalarExecCx::new(), &f.cx)?;
    assert_eq!(&done.report.decisions()[..4], failed.decisions.as_slice());
    assert_eq!(done.progress.reused_inferences, 1); assert_eq!(done.progress.new_inferences, 2);
    assert_eq!(receipt_count(&f.deployment, "model_invocation_receipt"), 3);
    Ok(())
}

#[test]
fn cancelled_sampling_does_not_execute_a_model_and_retains_decoded_progress() -> TestResult {
    let mut f = fixture("cancel", 3)?;
    let plan = SamplingPlan::new(&f.request, policy(3), 10_000, vec![])?;
    f.cx.set_cancel_at_checkpoint("recording_pipeline:sampling");
    let failed = run_sampled_recording(&mut f.deployment, &f.request, &f.model, &plan,
        &mut normal_budget(), &ScalarExecCx::new(), &f.cx).err().ok_or("sampling cancellation ignored")?;
    assert_eq!(failed.progress.stage, RecordingStage::Sampling);
    assert_eq!(failed.progress.new_decodes, 1); assert_eq!(failed.progress.new_inferences, 0);
    assert!(failed.decisions.is_empty()); assert_eq!(failed.comparisons_used, 0);
    let fresh = context(&f.dir.0.join("deployment"))?;
    let out = run_sampled_recording(&mut f.deployment, &f.request, &f.model, &plan,
        &mut normal_budget(), &ScalarExecCx::new(), &fresh)?;
    assert_eq!(out.progress.reused_decodes, 1); assert_eq!(out.progress.new_inferences, 1);
    Ok(())
}

#[test]
fn invalid_requirements_and_changed_source_ranges_never_publish_work() -> TestResult {
    let mut f = fixture("invalid", 3)?;
    let basis = ContentDigest::sha256(b"required");
    for required in [vec![RequiredFrame { segment_index: 3, basis }],
        vec![RequiredFrame { segment_index: 1, basis }; 2]] {
        assert!(SamplingPlan::new(&f.request, policy(3), 10_000, required).is_err());
    }
    let plan = SamplingPlan::new(&f.request, policy(3), 10_000, vec![])?;
    let before = f.deployment.current_anchor().clone();
    for field in 0..4 {
        let mut request = f.request.clone();
        match field {
            0 => request.first_segment = 1, 1 => request.segment_count = 2,
            2 => request.import_identity = ContentDigest::sha256(b"other import"),
            _ => request.interpretation = ComponentInterpretation::YCbCr,
        }
        assert!(run_sampled_recording(&mut f.deployment, &request, &f.model, &plan,
            &mut normal_budget(), &ScalarExecCx::new(), &f.cx).is_err());
        assert_eq!(*f.deployment.current_anchor(), before);
    }
    for end in 0..plan.encoded().len() {
        let prefix = &plan.encoded()[..end];
        assert!(SamplingPlan::decode(prefix, ContentDigest::sha256(prefix)).is_err());
    }
    Ok(())
}

#[test]
fn rehashed_skip_tampering_truncation_and_unadmitted_verify_work_are_refused() -> TestResult {
    let mut f = fixture("tamper", 4)?;
    let plan = SamplingPlan::new(&f.request, policy(3), 10_000, vec![])?;
    let out = run_sampled_recording(&mut f.deployment, &f.request, &f.model, &plan,
        &mut normal_budget(), &ScalarExecCx::new(), &f.cx)?;
    let mut bytes = out.report.encoded().to_vec();
    let mut d = CanonicalDecoder::new(&bytes);
    d.bytes()?; d.u32()?; d.text()?; d.bytes()?; d.u64()?; d.u64()?;
    d.bytes()?; // first decision
    let start = d.offset(); let skipped = d.bytes()?;
    let last = start + 8 + skipped.len() - 1;
    bytes[last] ^= 1; // tamper a measured quiet-frame decision, then recompute the outer hash.
    let before = f.deployment.current_anchor().clone();
    assert!(SampledReport::verify(&f.deployment, &bytes, ContentDigest::sha256(&bytes), &f.request.limits,
        10_000, &mut AnalysisBudget::new(1_000_000, 1_000_000), &f.cx).is_err());
    let bytes = out.report.encoded();
    for end in [0, 1, 8, 16, bytes.len() - 1] {
        let prefix = &bytes[..end];
        assert!(SampledReport::verify(&f.deployment, prefix, ContentDigest::sha256(prefix), &f.request.limits,
            10_000, &mut AnalysisBudget::new(1_000_000, 1_000_000), &f.cx).is_err());
    }
    assert!(SampledReport::verify(&f.deployment, bytes, out.report.digest(), &f.request.limits,
        9_999, &mut AnalysisBudget::new(1_000_000, 1_000_000), &f.cx).is_err());
    assert_eq!(*f.deployment.current_anchor(), before);
    Ok(())
}

#[test]
fn sampler_retries_are_idempotent_and_changed_requirements_do_not_rebind_history() -> TestResult {
    let mut f = fixture("idempotent", 3)?;
    let frame = RecordedFrame::decode_and_publish(&mut f.deployment, &source(&f.request, 0),
        &mut DecodeBudget::new(1_000_000), &f.cx)?;
    let mut sampler = ActivitySampler::new(policy(3), 10_000)?;
    let first = sampler.push(&frame, None, &f.cx)?;
    assert_eq!(sampler.push(&frame, None, &f.cx)?, first);
    assert_eq!(sampler.comparisons_used(), 0);
    assert_eq!(sampler.push(&frame, Some(ContentDigest::sha256(b"new basis")), &f.cx), Err(ActivityError::ReplayConflict));
    let later = RecordedFrame::decode_and_publish(&mut f.deployment, &source(&f.request, 2),
        &mut DecodeBudget::new(1_000_000), &f.cx)?;
    let gap = sampler.push(&later, None, &f.cx)?;
    assert!(gap.reasons().contains(&SamplingReason::ComparisonReset));
    assert_eq!(sampler.push(&frame, None, &f.cx), Err(ActivityError::OutOfOrder));
    Ok(())
}
