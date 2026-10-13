#![forbid(unsafe_code)]
//! Re-execute retained native computations rather than accepting internally consistent records.
use std::sync::atomic::AtomicBool;

use fss_codec_mjpeg::color::{RgbDecodeLimits, decode_rgb};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeError};
use fss_core::{
    CanonicalDecode, CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, ContentDigest,
    SensorCapsule, SensorId, SensorSourceBytesSpec, StreamId, TimestampNs,
};
use fss_reference::activity_replay::{
    ActivityReplayError, ActivityReplayInputs, ActivityReplayLimits, ActivityReplayPlan,
    replay_activity_result,
};
use fss_reference::executor_activity::{
    ActivityExecutorModel, ActivityFrameBinding, ActivityThresholdPolicy, ExecutorModelOutcome,
    ExecutorModelResult, rgb_decode_receipt_bytes,
};
use fss_reference::{ExecBudget, ModelInvocationReceipt, ScalarExecCx};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const BACKGROUND: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/background.jpg");
const GRADIENT: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");

struct Inputs {
    result: Vec<u8>, invocation: Vec<u8>, frame_source: Vec<u8>, reference_source: Vec<u8>,
    frame_capsule: Vec<u8>, reference_capsule: Vec<u8>, frame_decode: Vec<u8>, reference_decode: Vec<u8>,
}
impl Inputs {
    fn borrow(&self) -> ActivityReplayInputs<'_> {
        ActivityReplayInputs { result: &self.result, invocation: &self.invocation,
            frame_source: &self.frame_source, reference_source: &self.reference_source,
            frame_capsule: &self.frame_capsule, reference_capsule: &self.reference_capsule,
            frame_decode: &self.frame_decode, reference_decode: &self.reference_decode }
    }
    fn length(&self) -> usize {
        [&self.result, &self.invocation, &self.frame_source, &self.reference_source,
            &self.frame_capsule, &self.reference_capsule, &self.frame_decode, &self.reference_decode]
            .iter().map(|bytes| bytes.len()).sum()
    }
}
struct Fixture { model: ActivityExecutorModel, plan: ActivityReplayPlan, inputs: Inputs, receipt: ModelInvocationReceipt }
fn capsule(bytes: &[u8], sequence: u64) -> Result<SensorCapsule, fss_core::ContractError> {
    let capture = CaptureInterval::new(TimestampNs(0), TimestampNs(5_000_000_000))?;
    SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
        capsule_id: CapsuleId::parse(format!("capsule:replay:{sequence}"))?,
        sensor_id: SensorId::parse("sensor:replay")?, stream_id: StreamId::parse("stream:replay")?,
        sequence, capture, receive_time: capture.latest, clock_basis: ClockBasis::Estimated,
        source: bytes, frame_count: 1, gap_before: false,
    })
}
fn fixture(quiet: bool) -> Result<Fixture, Box<dyn std::error::Error>> {
    let cx = ScalarExecCx::new();
    let model = ActivityExecutorModel::load_committed(&cx)?;
    let plan = ActivityReplayPlan {
        sensor_id: SensorId::parse("sensor:replay")?, stream_id: StreamId::parse("stream:replay")?,
        job_id: "job:replay".to_owned(), policy: ActivityThresholdPolicy::reference()?,
        interpretation: ComponentInterpretation::Grayscale,
        execution: ExecBudget::new(10_000_000, 16 * 1024 * 1024),
    };
    let frame_bytes = if quiet { BACKGROUND } else { GRADIENT };
    let decode = |bytes: &[u8]| decode_rgb(bytes, ContentDigest::sha256(bytes).bytes(),
        plan.interpretation, RgbDecodeLimits::default(), &mut DecodeBudget::new(10_000_000));
    let frame = decode(frame_bytes)?;
    let reference = decode(BACKGROUND)?;
    let fc = capsule(frame_bytes, 1)?;
    let rc = capsule(BACKGROUND, 0)?;
    let (result, receipt) = model.invoke(&plan.sensor_id,
        ActivityFrameBinding { pixels: frame.pixels(), receipt: frame.receipt(),
            source_digest: fc.source_digest, capsule: &fc },
        ActivityFrameBinding { pixels: reference.pixels(), receipt: reference.receipt(),
            source_digest: rc.source_digest, capsule: &rc },
        &plan.policy, plan.execution, &plan.job_id, &cx)?;
    let inputs = Inputs {
        result: result.try_canonical_bytes()?, invocation: receipt.to_json_canonical().into_bytes(),
        frame_source: frame_bytes.to_vec(), reference_source: BACKGROUND.to_vec(),
        frame_capsule: fc.try_canonical_bytes()?, reference_capsule: rc.try_canonical_bytes()?,
        frame_decode: rgb_decode_receipt_bytes(&frame.receipt()),
        reference_decode: rgb_decode_receipt_bytes(&reference.receipt()),
    };
    Ok(Fixture { model, plan, inputs, receipt })
}
fn run(f: &Fixture) -> Result<fss_reference::activity_replay::ReplayedActivityResult, ActivityReplayError> {
    replay_activity_result(&f.model, &f.plan, f.inputs.borrow(), ActivityReplayLimits::default(),
        &mut DecodeBudget::new(20_000_000), &ScalarExecCx::new())
}

#[test]
fn native_sources_reproduce_the_complete_result_and_operator_receipt() -> TestResult {
    let f = fixture(false)?;
    let replay = run(&f)?;
    assert_eq!(replay.result().try_canonical_bytes()?, f.inputs.result);
    assert_eq!(replay.invocation(), &f.receipt);
    assert!(matches!(replay.result().outcome, ExecutorModelOutcome::Activity { .. }));
    assert!(replay.decode_units() > 0);
    assert!(replay.decoded_bytes() > 0);
    assert!(replay.result().reference_only);
    assert!(!replay.result().supports_absence_claim());
    Ok(())
}

#[test]
fn distinct_capsules_with_identical_pixels_reproduce_quietness_not_absence() -> TestResult {
    let f = fixture(true)?;
    let replay = run(&f)?;
    assert_eq!(replay.result().outcome, ExecutorModelOutcome::NoActivity { score_bits: 0.0_f32.to_bits() });
    assert!(!replay.result().supports_absence_claim());
    assert_ne!(f.inputs.frame_capsule, f.inputs.reference_capsule);
    assert_eq!(f.inputs.frame_source, f.inputs.reference_source);
    Ok(())
}

#[test]
fn a_reencoded_result_with_a_different_finite_score_is_not_replayable() -> TestResult {
    let mut f = fixture(false)?;
    let mut result = ExecutorModelResult::decode_canonical(&f.inputs.result)?;
    result.outcome = ExecutorModelOutcome::NoActivity { score_bits: 0.0_f32.to_bits() };
    f.inputs.result = result.try_canonical_bytes()?;
    assert!(matches!(run(&f), Err(ActivityReplayError::ReplayMismatch("complete result"))));
    Ok(())
}

#[test]
fn resealing_receipt_and_result_digests_cannot_replace_the_native_operator_trace() -> TestResult {
    let mut f = fixture(false)?;
    let mut result = ExecutorModelResult::decode_canonical(&f.inputs.result)?;
    f.receipt.usage.work_units += 1;
    f.inputs.invocation = f.receipt.to_json_canonical().into_bytes();
    result.invocation_receipt_digest = f.receipt.compute_canonical_digest();
    result.invocation_receipt_object = ContentDigest::sha256(&f.inputs.invocation);
    f.inputs.result = result.try_canonical_bytes()?;
    assert!(matches!(run(&f), Err(ActivityReplayError::ReplayMismatch("complete invocation"))));
    Ok(())
}

#[test]
fn independent_policy_and_generation_are_checked_before_native_work() -> TestResult {
    for change_model in [false, true] {
        let mut f = fixture(false)?;
        if change_model {
            let mut result = ExecutorModelResult::decode_canonical(&f.inputs.result)?;
            result.model_generation = "model:fss-activity:v2".to_owned();
            f.inputs.result = result.try_canonical_bytes()?;
        } else { f.plan.policy = ActivityThresholdPolicy::new(2, 0.5)?; }
        let mut budget = DecodeBudget::new(20_000_000);
        assert!(matches!(replay_activity_result(&f.model, &f.plan, f.inputs.borrow(),
            ActivityReplayLimits::default(), &mut budget, &ScalarExecCx::new()),
            Err(ActivityReplayError::RegistrationMismatch)));
        assert_eq!(budget.used(), 0);
    }
    Ok(())
}

#[test]
fn reference_capsules_cannot_mix_streams_sensors_order_or_source_lengths() -> TestResult {
    for change in 0..5 {
        let mut f = fixture(false)?;
        let mut reference = SensorCapsule::from_canonical_bytes(&f.inputs.reference_capsule)?;
        match change {
            0 => reference.sensor_id = SensorId::parse("sensor:other")?,
            1 => reference.stream_id = StreamId::parse("stream:other")?,
            2 => reference.sequence = 1,
            3 => reference.source_bytes += 1,
            _ => reference.frame_count = 2,
        }
        f.inputs.reference_capsule = reference.try_canonical_bytes()?;
        let mut budget = DecodeBudget::new(20_000_000);
        assert!(matches!(replay_activity_result(&f.model, &f.plan, f.inputs.borrow(),
            ActivityReplayLimits::default(), &mut budget, &ScalarExecCx::new()),
            Err(ActivityReplayError::Binding(_))));
        assert_eq!(budget.used(), 0);
    }
    Ok(())
}

#[test]
fn stored_decode_records_are_checked_against_new_native_decodes() -> TestResult {
    let mut f = fixture(false)?;
    let mut result = ExecutorModelResult::decode_canonical(&f.inputs.result)?;
    let last = f.inputs.frame_decode.last_mut().ok_or("empty decode record")?;
    *last ^= 1;
    result.decode_receipt_digest = ContentDigest::sha256(&f.inputs.frame_decode);
    f.inputs.result = result.try_canonical_bytes()?;
    assert!(matches!(run(&f), Err(ActivityReplayError::Binding("native decode record"))));
    Ok(())
}

#[test]
fn exact_aggregate_input_rgb_and_shared_decode_budgets_work_without_refills() -> TestResult {
    let f = fixture(false)?;
    let measured = run(&f)?;
    let mut limits = ActivityReplayLimits { max_input_bytes: f.inputs.length(),
        max_decoded_bytes: measured.decoded_bytes(), ..Default::default() };
    let mut budget = DecodeBudget::new(measured.decode_units());
    assert!(replay_activity_result(&f.model, &f.plan, f.inputs.borrow(), limits,
        &mut budget, &ScalarExecCx::new()).is_ok());
    assert_eq!(budget.remaining(), 0);
    // Calling again must not refill the caller's already consumed native allowance.
    assert!(matches!(replay_activity_result(&f.model, &f.plan, f.inputs.borrow(), limits,
        &mut budget, &ScalarExecCx::new()), Err(ActivityReplayError::Decode(DecodeError::BudgetExhausted))));
    let mut short = DecodeBudget::new(measured.decode_units() - 1);
    assert!(matches!(replay_activity_result(&f.model, &f.plan, f.inputs.borrow(), limits,
        &mut short, &ScalarExecCx::new()), Err(ActivityReplayError::Decode(DecodeError::BudgetExhausted))));
    assert!(short.used() > 0);
    limits.max_decoded_bytes -= 1;
    assert!(matches!(replay_activity_result(&f.model, &f.plan, f.inputs.borrow(), limits,
        &mut DecodeBudget::new(20_000_000), &ScalarExecCx::new()),
        Err(ActivityReplayError::Decode(DecodeError::Limit))));
    limits.max_input_bytes -= 1;
    let mut untouched = DecodeBudget::new(20_000_000);
    assert!(matches!(replay_activity_result(&f.model, &f.plan, f.inputs.borrow(), limits,
        &mut untouched, &ScalarExecCx::new()), Err(ActivityReplayError::Limit("inputs"))));
    assert_eq!(untouched.used(), 0);
    Ok(())
}

#[test]
fn every_truncated_result_and_trailing_bytes_fail_before_decoding_sources() -> TestResult {
    let mut f = fixture(false)?;
    let original = f.inputs.result.clone();
    for end in 0..original.len() {
        f.inputs.result = original[..end].to_vec();
        let mut budget = DecodeBudget::new(20_000_000);
        assert!(replay_activity_result(&f.model, &f.plan, f.inputs.borrow(),
            ActivityReplayLimits::default(), &mut budget, &ScalarExecCx::new()).is_err());
        assert_eq!(budget.used(), 0);
    }
    f.inputs.result = original;
    f.inputs.result.push(0);
    assert!(run(&f).is_err());
    Ok(())
}

#[test]
fn scalar_and_native_cancellation_leave_no_replayed_result() -> TestResult {
    let f = fixture(false)?;
    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    assert!(matches!(replay_activity_result(&f.model, &f.plan, f.inputs.borrow(),
        ActivityReplayLimits::default(), &mut DecodeBudget::new(20_000_000), &cx),
        Err(ActivityReplayError::Cancelled)));
    assert!(cx.is_drain_completed());
    let cx = ScalarExecCx::new();
    let flag = AtomicBool::new(true);
    let mut budget = DecodeBudget::cancellable(20_000_000, &flag);
    assert!(matches!(replay_activity_result(&f.model, &f.plan, f.inputs.borrow(),
        ActivityReplayLimits::default(), &mut budget, &cx), Err(ActivityReplayError::Cancelled)));
    assert_eq!(budget.used(), 0);
    assert!(cx.is_drain_completed());
    Ok(())
}

#[test]
fn a_starved_reexecution_never_becomes_a_successful_quiet_result() -> TestResult {
    let mut f = fixture(false)?;
    f.plan.execution = ExecBudget::new(0, 0);
    assert!(matches!(run(&f), Err(ActivityReplayError::Unscored)));
    Ok(())
}

#[test]
fn job_identity_and_original_execution_allowance_are_part_of_exact_replay() -> TestResult {
    for change_job in [false, true] {
        let mut f = fixture(false)?;
        if change_job { f.plan.job_id = "job:different".to_owned(); }
        else { f.plan.execution.max_macs += 1; }
        assert!(matches!(run(&f), Err(ActivityReplayError::ReplayMismatch("complete invocation"))));
    }
    Ok(())
}
