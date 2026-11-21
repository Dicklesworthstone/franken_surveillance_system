#![forbid(unsafe_code)]
//! Executor-backed observation and policy routing contract tests (fss-2h5zq.51 / fss-2h5zq.52).
//!
//! Verifies:
//! - threshold boundary classification at, 1 ULP below, and 1 ULP above the policy threshold,
//!   plus non-finite abstention and invalid policy rejection;
//! - single-camera and shared-failure-domain corroboration guards (one camera or shared domain
//!   never reaches `Corroborated` / `PrepareAlert`; `NoActivity` never certifies absence);
//! - executor budget exhaustion and cancellation producing typed `Abstained` results that hold
//!   policy decisions `Indeterminate` (never negatives or benign);
//! - canonical round-trip of all three `ExecutorModelOutcome` variants, domain tag binding,
//!   non-mock typing (`ReferenceModelResult::ScalarExecutor`), `Continuity::NotObservable`,
//!   receipt digest binding, and tamper refusal.

use std::error::Error;

use fss_codec_mjpeg::color::{DecodedRgb, RgbDecodeLimits, decode_rgb};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget};
use fss_core::{
    CanonicalDecoder, CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, ContentDigest,
    EventId, EventState, EvidenceEdgeRelation, ProbabilityInterval, SensorCapsule, SensorId,
    SensorSourceBytesSpec, StreamId, TimestampNs,
};
use fss_reference::executor_activity::{
    ACTIVITY_MODEL_GENERATION, ActivityExecutorModel, ActivityFrameBinding,
    ActivityThresholdPolicy, ContinuityNotObservableReason, EXECUTOR_MODEL_RESULT_DOMAIN,
    ExecutorAbstentionReason, ExecutorContinuity, ExecutorModelOutcome, ExecutorModelResult,
    rgb_decode_receipt_bytes,
};
use fss_reference::model_receipt::ReceiptOutcome;
use fss_reference::{
    ExecBudget, ReferenceModelObservation, ReferenceModelResult, ReferencePolicyAction,
    ScalarExecCx, evaluate_unknown_presence,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const BACKGROUND: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/background.jpg");
const GRADIENT: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
const BROWN_Q100: &[u8] = include_bytes!("../../../tests/fixtures/media/jpeg/brown_luma_q100.jpg");
const BROWN_QFIX: &[u8] = include_bytes!("../../../tests/fixtures/media/jpeg/brown_luma_qfix.jpg");

fn decode_gray(bytes: &[u8]) -> TestResult<DecodedRgb> {
    Ok(decode_rgb(
        bytes,
        ContentDigest::sha256(bytes).bytes(),
        ComponentInterpretation::Grayscale,
        RgbDecodeLimits::default(),
        &mut DecodeBudget::new(10_000_000),
    )?)
}

fn capsule_for(source: &[u8], sensor: &str, sequence: u64) -> TestResult<SensorCapsule> {
    let capture = CaptureInterval::new(TimestampNs(1_000), TimestampNs(5_000_000_000))?;
    Ok(SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
        capsule_id: CapsuleId::parse(format!("capsule:exec-obs:{sensor}:{sequence}"))?,
        sensor_id: SensorId::parse(sensor)?,
        stream_id: StreamId::parse("stream:exec-obs")?,
        sequence,
        capture,
        receive_time: capture.latest,
        clock_basis: ClockBasis::Estimated,
        source,
        frame_count: 1,
        gap_before: false,
    })?)
}

fn bind<'a>(
    bytes: &'a [u8],
    decoded: &'a DecodedRgb,
    capsule: &'a SensorCapsule,
) -> ActivityFrameBinding<'a> {
    ActivityFrameBinding {
        pixels: decoded.pixels(),
        receipt: decoded.receipt(),
        source_digest: ContentDigest::sha256(bytes),
        capsule,
    }
}

#[test]
fn threshold_boundary_classifies_below_equal_above_and_nonfinite() -> TestResult {
    let policy = ActivityThresholdPolicy::reference()?;
    let threshold = policy.threshold();
    let just_below = f32::from_bits(threshold.to_bits() - 1);
    let just_above = f32::from_bits(threshold.to_bits() + 1);
    assert!(just_below < threshold && threshold < just_above);

    assert_eq!(
        policy.classify(0.0),
        ExecutorModelOutcome::NoActivity {
            score_bits: 0.0_f32.to_bits(),
        }
    );
    assert_eq!(
        policy.classify(just_below),
        ExecutorModelOutcome::NoActivity {
            score_bits: just_below.to_bits(),
        }
    );
    // Strict inequality: score == threshold is NoActivity (never absence).
    assert_eq!(
        policy.classify(threshold),
        ExecutorModelOutcome::NoActivity {
            score_bits: threshold.to_bits(),
        }
    );
    assert_eq!(
        policy.classify(just_above),
        ExecutorModelOutcome::Activity {
            score_bits: just_above.to_bits(),
        }
    );

    for nonfinite in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        assert_eq!(
            policy.classify(nonfinite),
            ExecutorModelOutcome::Abstained {
                reason: ExecutorAbstentionReason::NonFiniteScore,
                receipt_outcome: ReceiptOutcome::Ok,
            }
        );
    }

    // Invalid policy specs fail closed.
    assert!(ActivityThresholdPolicy::new(0, 0.01).is_err());
    assert!(ActivityThresholdPolicy::new(1, -0.001).is_err());
    assert!(ActivityThresholdPolicy::new(1, f32::NAN).is_err());
    assert!(ActivityThresholdPolicy::new(1, f32::INFINITY).is_err());

    // Digest binds both generation and threshold bits.
    let gen2 = ActivityThresholdPolicy::new(2, threshold)?;
    let higher = ActivityThresholdPolicy::new(1, just_above)?;
    assert_ne!(policy.digest(), gen2.digest());
    assert_ne!(policy.digest(), higher.digest());
    Ok(())
}

#[test]
fn single_camera_and_shared_domain_never_corroborate_and_no_activity_never_certifies_absence()
-> TestResult {
    let cx = ScalarExecCx::new();
    let model = ActivityExecutorModel::load_committed(&cx)?;
    let policy_ref = ActivityThresholdPolicy::reference()?;
    let policy_any_pos = ActivityThresholdPolicy::new(2, 0.0)?;
    let interval = CaptureInterval::new(TimestampNs(1_000), TimestampNs(5_000_000_000))?;

    let bg = decode_gray(BACKGROUND)?;
    let grad = decode_gray(GRADIENT)?;
    let q100 = decode_gray(BROWN_Q100)?;
    let qfix = decode_gray(BROWN_QFIX)?;

    let cam_a = SensorId::parse("sensor:exec-obs-a")?;
    let cam_b = SensorId::parse("sensor:exec-obs-b")?;

    let cap_a_ref = capsule_for(BACKGROUND, "sensor:exec-obs-a", 1)?;
    let cap_a_bg = capsule_for(BACKGROUND, "sensor:exec-obs-a", 2)?;
    let cap_a_grad = capsule_for(GRADIENT, "sensor:exec-obs-a", 3)?;
    let cap_b_ref = capsule_for(BROWN_Q100, "sensor:exec-obs-b", 1)?;
    let cap_b_qfix = capsule_for(BROWN_QFIX, "sensor:exec-obs-b", 2)?;

    let (a_quiet, a_quiet_receipt) = model.invoke(
        &cam_a,
        bind(BACKGROUND, &bg, &cap_a_bg),
        bind(BACKGROUND, &bg, &cap_a_ref),
        &policy_ref,
        ExecBudget::unlimited(),
        "job:exec-obs:a-quiet",
        &cx,
    )?;
    let (a_active, a_active_receipt) = model.invoke(
        &cam_a,
        bind(GRADIENT, &grad, &cap_a_grad),
        bind(BACKGROUND, &bg, &cap_a_ref),
        &policy_ref,
        ExecBudget::unlimited(),
        "job:exec-obs:a-active",
        &cx,
    )?;
    let (b_active, b_active_receipt) = model.invoke(
        &cam_b,
        bind(BROWN_QFIX, &qfix, &cap_b_qfix),
        bind(BROWN_Q100, &q100, &cap_b_ref),
        &policy_any_pos,
        ExecBudget::unlimited(),
        "job:exec-obs:b-active",
        &cx,
    )?;

    assert!(matches!(
        a_quiet.outcome,
        ExecutorModelOutcome::NoActivity { .. }
    ));
    assert_eq!(a_quiet.outcome.score(), Some(0.0));
    assert!(matches!(
        a_active.outcome,
        ExecutorModelOutcome::Activity { .. }
    ));
    assert!(matches!(
        b_active.outcome,
        ExecutorModelOutcome::Activity { .. }
    ));
    assert_eq!(a_quiet_receipt.outcome, ReceiptOutcome::Ok);
    assert_eq!(a_active_receipt.outcome, ReceiptOutcome::Ok);
    assert_eq!(b_active_receipt.outcome, ReceiptOutcome::Ok);
    assert!(!a_quiet.supports_absence_claim());
    assert!(!a_active.supports_absence_claim());

    // 1. Single-camera Activity: Witnessed + Hold, NEVER Corroborated / PrepareAlert.
    let single_active = evaluate_unknown_presence(
        EventId::parse("event:exec-obs:single-active")?,
        vec![ReferenceModelObservation::new(
            a_active.clone(),
            "power:circuit-a",
            interval,
        )?],
    )?;
    assert_eq!(single_active.event.state, EventState::Witnessed);
    assert_eq!(single_active.action, ReferencePolicyAction::Hold);
    assert_eq!(
        single_active.event.probability,
        ProbabilityInterval::new(0.0, 1.0)?
    );

    // 2. Single-camera NoActivity: Indeterminate + Hold, DerivedFrom (never Contradicts/Rejected).
    let single_quiet = evaluate_unknown_presence(
        EventId::parse("event:exec-obs:single-quiet")?,
        vec![ReferenceModelObservation::new(
            a_quiet.clone(),
            "power:circuit-a",
            interval,
        )?],
    )?;
    assert_eq!(single_quiet.event.state, EventState::Indeterminate);
    assert_eq!(single_quiet.action, ReferencePolicyAction::Hold);
    assert_eq!(single_quiet.event.evidence.len(), 1);
    assert_eq!(
        single_quiet.event.evidence[0].relation,
        EvidenceEdgeRelation::DerivedFrom
    );

    // 3. Two distinct sensors on the SAME failure domain still NEVER corroborate.
    let shared_domain = evaluate_unknown_presence(
        EventId::parse("event:exec-obs:shared-domain")?,
        vec![
            ReferenceModelObservation::new(a_active.clone(), "power:shared-bus", interval)?,
            ReferenceModelObservation::new(b_active.clone(), "power:shared-bus", interval)?,
        ],
    )?;
    assert_eq!(shared_domain.event.state, EventState::Witnessed);
    assert_eq!(shared_domain.action, ReferencePolicyAction::Hold);

    // 4. Two distinct sensors with distinct capture roots on INDEPENDENT failure domains corroborate.
    let independent = evaluate_unknown_presence(
        EventId::parse("event:exec-obs:independent")?,
        vec![
            ReferenceModelObservation::new(a_active.clone(), "power:circuit-a", interval)?,
            ReferenceModelObservation::new(b_active, "power:circuit-b", interval)?,
        ],
    )?;
    assert_eq!(independent.event.state, EventState::Corroborated);
    assert_eq!(independent.action, ReferencePolicyAction::PrepareAlert);

    // 5. One Activity + one NoActivity stays Witnessed + Hold (NoActivity is neutral, not contradicting).
    let mixed = evaluate_unknown_presence(
        EventId::parse("event:exec-obs:mixed")?,
        vec![
            ReferenceModelObservation::new(a_active, "power:circuit-a", interval)?,
            ReferenceModelObservation::new(a_quiet, "power:circuit-a", interval)?,
        ],
    )?;
    assert_eq!(mixed.event.state, EventState::Witnessed);
    assert_eq!(mixed.action, ReferencePolicyAction::Hold);
    Ok(())
}

#[test]
fn executor_budget_failure_and_cancellation_abstain_and_hold_policy_open() -> TestResult {
    let cx = ScalarExecCx::new();
    let model = ActivityExecutorModel::load_committed(&cx)?;
    let policy = ActivityThresholdPolicy::reference()?;
    let interval = CaptureInterval::new(TimestampNs(1_000), TimestampNs(5_000_000_000))?;

    let bg = decode_gray(BACKGROUND)?;
    let grad = decode_gray(GRADIENT)?;
    let cam_a = SensorId::parse("sensor:exec-obs-fault-a")?;
    let cap_ref = capsule_for(BACKGROUND, "sensor:exec-obs-fault-a", 1)?;
    let cap_grad = capsule_for(GRADIENT, "sensor:exec-obs-fault-a", 2)?;

    // Budget exhaustion -> Abstained(ExecutorFailed, BudgetExhausted).
    let (starved, starved_receipt) = model.invoke(
        &cam_a,
        bind(GRADIENT, &grad, &cap_grad),
        bind(BACKGROUND, &bg, &cap_ref),
        &policy,
        ExecBudget::new(1, 1),
        "job:exec-obs:budget-starved",
        &cx,
    )?;
    assert_eq!(
        starved.outcome,
        ExecutorModelOutcome::Abstained {
            reason: ExecutorAbstentionReason::ExecutorFailed,
            receipt_outcome: ReceiptOutcome::BudgetExhausted,
        }
    );
    assert_eq!(starved.outcome.score(), None);
    assert_eq!(starved_receipt.outcome, ReceiptOutcome::BudgetExhausted);
    starved_receipt.verify(
        starved_receipt.generation,
        &starved_receipt.compute_canonical_digest(),
    )?;

    // Cancellation -> Abstained(ExecutorFailed, Cancelled).
    let cancel_cx = ScalarExecCx::new();
    cancel_cx.request_cancellation();
    // Preprocessing runs under cx; cancel during executor by checking via a dedicated cancelled cx
    // only if preprocessing accepts or via model invocation returning Cancelled/Abstained.
    let cancel_outcome = model.invoke(
        &cam_a,
        bind(GRADIENT, &grad, &cap_grad),
        bind(BACKGROUND, &bg, &cap_ref),
        &policy,
        ExecBudget::unlimited(),
        "job:exec-obs:cancelled",
        &cancel_cx,
    );
    // Cancellation before preprocessing fails closed with Prepaid/Preprocess(Cancelled); never returns NoActivity.
    assert!(
        cancel_outcome.is_err()
            || matches!(
                cancel_outcome,
                Ok((
                    ExecutorModelResult {
                        outcome: ExecutorModelOutcome::Abstained { .. },
                        ..
                    },
                    _
                ))
            )
    );

    // Policy decision with starved abstention alone -> Indeterminate + Hold (never Rejected).
    let alone = evaluate_unknown_presence(
        EventId::parse("event:exec-obs:starved-alone")?,
        vec![ReferenceModelObservation::new(
            starved.clone(),
            "power:circuit-a",
            interval,
        )?],
    )?;
    assert_eq!(alone.event.state, EventState::Indeterminate);
    assert_eq!(alone.action, ReferencePolicyAction::Hold);

    // Even alongside two healthy supporting sensors, an unresolved abstention prevents Corroborated.
    let (a_ok, _) = model.invoke(
        &cam_a,
        bind(GRADIENT, &grad, &cap_grad),
        bind(BACKGROUND, &bg, &cap_ref),
        &policy,
        ExecBudget::unlimited(),
        "job:exec-obs:healthy-a",
        &cx,
    )?;
    let q100 = decode_gray(BROWN_Q100)?;
    let qfix = decode_gray(BROWN_QFIX)?;
    let cam_b = SensorId::parse("sensor:exec-obs-fault-b")?;
    let cap_b_ref = capsule_for(BROWN_Q100, "sensor:exec-obs-fault-b", 1)?;
    let cap_b_qfix = capsule_for(BROWN_QFIX, "sensor:exec-obs-fault-b", 2)?;
    let (b_ok, _) = model.invoke(
        &cam_b,
        bind(BROWN_QFIX, &qfix, &cap_b_qfix),
        bind(BROWN_Q100, &q100, &cap_b_ref),
        &ActivityThresholdPolicy::new(2, 0.0)?,
        ExecBudget::unlimited(),
        "job:exec-obs:healthy-b",
        &cx,
    )?;
    let blocked = evaluate_unknown_presence(
        EventId::parse("event:exec-obs:abstention-blocks-corroboration")?,
        vec![
            ReferenceModelObservation::new(a_ok, "power:circuit-a", interval)?,
            ReferenceModelObservation::new(b_ok, "power:circuit-b", interval)?,
            ReferenceModelObservation::new(starved, "power:circuit-c", interval)?,
        ],
    )?;
    assert_eq!(blocked.event.state, EventState::Indeterminate);
    assert_eq!(blocked.action, ReferencePolicyAction::Hold);
    Ok(())
}

#[test]
fn canonical_roundtrip_domain_binding_continuity_and_tamper_refusal() -> TestResult {
    let cx = ScalarExecCx::new();
    let model = ActivityExecutorModel::load_committed(&cx)?;
    let policy = ActivityThresholdPolicy::reference()?;
    let bg = decode_gray(BACKGROUND)?;
    let grad = decode_gray(GRADIENT)?;
    let cam = SensorId::parse("sensor:exec-obs-codec")?;
    let cap_ref = capsule_for(BACKGROUND, "sensor:exec-obs-codec", 1)?;
    let cap_bg = capsule_for(BACKGROUND, "sensor:exec-obs-codec", 2)?;
    let cap_grad = capsule_for(GRADIENT, "sensor:exec-obs-codec", 3)?;

    let (active, active_receipt) = model.invoke(
        &cam,
        bind(GRADIENT, &grad, &cap_grad),
        bind(BACKGROUND, &bg, &cap_ref),
        &policy,
        ExecBudget::unlimited(),
        "job:exec-obs:codec-active",
        &cx,
    )?;
    let (quiet, quiet_receipt) = model.invoke(
        &cam,
        bind(BACKGROUND, &bg, &cap_bg),
        bind(BACKGROUND, &bg, &cap_ref),
        &policy,
        ExecBudget::unlimited(),
        "job:exec-obs:codec-quiet",
        &cx,
    )?;
    let (abstained, abstained_receipt) = model.invoke(
        &cam,
        bind(GRADIENT, &grad, &cap_grad),
        bind(BACKGROUND, &bg, &cap_ref),
        &policy,
        ExecBudget::new(1, 1),
        "job:exec-obs:codec-abstained",
        &cx,
    )?;

    let expected_ref_decode = ContentDigest::sha256(&rgb_decode_receipt_bytes(&bg.receipt()));
    for (result, receipt, frame_decoded) in [
        (&active, &active_receipt, &grad),
        (&quiet, &quiet_receipt, &bg),
        (&abstained, &abstained_receipt, &grad),
    ] {
        // Explicit non-mock typing.
        let wrapped = ReferenceModelResult::from(result.clone());
        assert!(matches!(wrapped, ReferenceModelResult::ScalarExecutor(_)));
        assert_eq!(wrapped.object_digest(), result.object_digest());
        assert_eq!(wrapped.canonical_bytes(), result.canonical_bytes());

        // Registered domain tag, generation, continuity, reference-only, and receipt digests.
        let bytes = result.canonical_bytes();
        let mut dec = CanonicalDecoder::new(&bytes);
        assert_eq!(dec.text()?, EXECUTOR_MODEL_RESULT_DOMAIN);
        assert_eq!(result.model_generation, ACTIVITY_MODEL_GENERATION);
        assert_eq!(
            result.continuity,
            ExecutorContinuity::NotObservable {
                reason: ContinuityNotObservableReason::FileSource,
            }
        );
        assert!(result.reference_only);
        assert!(!result.supports_absence_claim());
        assert_eq!(
            result.decode_receipt_digest,
            ContentDigest::sha256(&rgb_decode_receipt_bytes(&frame_decoded.receipt()))
        );
        assert_eq!(result.reference_decode_receipt_digest, expected_ref_decode);
        assert_eq!(
            result.invocation_receipt_digest,
            receipt.compute_canonical_digest()
        );
        assert_eq!(
            result.invocation_receipt_object,
            ContentDigest::sha256(receipt.to_json_canonical().as_bytes())
        );

        // Exact round-trip decode.
        let decoded = ExecutorModelResult::decode_canonical(&bytes)?;
        assert_eq!(decoded, *result);

        // Trailing bytes are refused.
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(ExecutorModelResult::decode_canonical(&extended).is_err());

        // Truncated bytes are refused.
        assert!(ExecutorModelResult::decode_canonical(&bytes[..bytes.len() - 1]).is_err());
    }

    // Wrong domain tag is refused.
    let mut wrong_domain = active.canonical_bytes();
    if let Some(pos) = wrong_domain.windows(b"v1".len()).position(|w| w == b"v1") {
        wrong_domain[pos + 1] = b'2';
    }
    assert!(ExecutorModelResult::decode_canonical(&wrong_domain).is_err());
    Ok(())
}
