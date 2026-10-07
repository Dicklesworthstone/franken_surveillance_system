//! Executor-backed observations through the unknown-presence policy (fss-2h5zq.51).
//!
//! Every score here is computed by the scalar executor over pixels natively decoded from the
//! checked-in fss-codec-mjpeg fixtures. One fixture pair is not accuracy evidence, and the score
//! is not a calibrated probability.

use std::error::Error;

use fss_codec_mjpeg::color::{DecodedRgb, RgbDecodeLimits, decode_rgb};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget};
use fss_core::{
    CanonicalEncode, CaptureInterval, ContentDigest, EventId, EventState, EvidenceEdgeRelation,
    ProbabilityInterval, SensorId, TimestampNs,
};

use crate::executor_activity::{
    ACTIVITY_MODEL_GENERATION, ActivityExecutorModel, ActivityFrameBinding,
    ActivityThresholdPolicy, ContinuityNotObservableReason, EXECUTOR_MODEL_RESULT_DOMAIN,
    ExecutorAbstentionReason, ExecutorContinuity, ExecutorModelOutcome, ExecutorModelResult,
    rgb_decode_receipt_bytes,
};
use crate::model_receipt::ReceiptOutcome;
use crate::{
    ExecBudget, MockModelOutcome, MockModelResult, MockSemanticLabel, ReferenceError,
    ReferenceModelObservation, ReferenceModelResult, ReferencePolicyAction, ScalarExecCx,
    evaluate_unknown_presence,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const BACKGROUND: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/background.jpg");
const GRADIENT: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");

fn decode(bytes: &[u8]) -> TestResult<DecodedRgb> {
    Ok(decode_rgb(
        bytes,
        ContentDigest::sha256(bytes).bytes(),
        ComponentInterpretation::Grayscale,
        RgbDecodeLimits::default(),
        &mut DecodeBudget::new(10_000_000),
    )?)
}

fn binding<'a>(bytes: &[u8], decoded: &'a DecodedRgb) -> ActivityFrameBinding<'a> {
    ActivityFrameBinding {
        pixels: decoded.pixels(),
        receipt: decoded.receipt(),
        source_digest: ContentDigest::sha256(bytes),
        capsule_digest: ContentDigest::sha256(&[bytes, b"capsule"].concat()),
    }
}

fn budget() -> ExecBudget {
    ExecBudget::new(10_000_000, 16 * 1024 * 1024)
}

/// Runs the executor on `frame` against the background reference.
fn run(
    frame: &[u8],
    policy: &ActivityThresholdPolicy,
    budget: ExecBudget,
    job: &str,
) -> TestResult<ExecutorModelResult> {
    let reference = decode(BACKGROUND)?;
    let current = decode(frame)?;
    let model = ActivityExecutorModel::load_committed(&ScalarExecCx::new())?;
    let (result, receipt) = model.invoke(
        &SensorId::parse("sensor:file-cam")?,
        binding(frame, &current),
        binding(BACKGROUND, &reference),
        policy,
        budget,
        job,
        &ScalarExecCx::new(),
    )?;
    assert_eq!(
        result.invocation_receipt_digest,
        receipt.compute_canonical_digest()
    );
    assert_eq!(
        result.invocation_receipt_object,
        ContentDigest::sha256(receipt.to_json_canonical().as_bytes())
    );
    receipt.verify(receipt.generation, &result.invocation_receipt_digest)?;
    Ok(result)
}

fn interval() -> TestResult<CaptureInterval> {
    Ok(CaptureInterval::new(
        TimestampNs(0),
        TimestampNs(5_000_000_000),
    )?)
}

fn observation(result: ExecutorModelResult, domain: &str) -> TestResult<ReferenceModelObservation> {
    Ok(ReferenceModelObservation::new(result, domain, interval()?)?)
}

#[test]
fn real_executor_scores_decoded_pixels_both_sides_of_the_threshold() -> TestResult {
    let policy = ActivityThresholdPolicy::reference()?;
    let changed = run(GRADIENT, &policy, budget(), "job:activity:changed")?;
    let unchanged = run(BACKGROUND, &policy, budget(), "job:activity:unchanged")?;
    let changed_score = changed
        .outcome
        .score()
        .ok_or("changed frame has no score")?;
    let unchanged_score = unchanged
        .outcome
        .score()
        .ok_or("unchanged frame has no score")?;
    println!(
        "CAPLOG {{\"bead\":\"fss-2h5zq.51\",\"step\":\"executor_scores\",\"changed\":{changed_score},\"unchanged\":{unchanged_score},\"threshold\":{}}}",
        policy.threshold()
    );
    assert!(matches!(
        changed.outcome,
        ExecutorModelOutcome::Activity { .. }
    ));
    assert!(changed_score > policy.threshold());
    assert!(matches!(
        unchanged.outcome,
        ExecutorModelOutcome::NoActivity { .. }
    ));
    assert_eq!(unchanged_score, 0.0);

    // The same real score on the other side of a different policy generation.
    let strict = ActivityThresholdPolicy::new(2, changed_score)?;
    let held = run(GRADIENT, &strict, budget(), "job:activity:changed")?;
    assert!(matches!(
        held.outcome,
        ExecutorModelOutcome::NoActivity { .. }
    ));
    assert_eq!(held.outcome.score(), Some(changed_score));
    assert_ne!(
        held.threshold_policy_digest,
        changed.threshold_policy_digest
    );
    assert_eq!(held.threshold_policy_generation, 2);
    assert_ne!(held.object_digest(), changed.object_digest());

    // Receipts and source bindings are real digests, never placeholders.
    for result in [&changed, &unchanged] {
        assert_eq!(result.model_generation, ACTIVITY_MODEL_GENERATION);
        assert_eq!(
            result.continuity,
            ExecutorContinuity::NotObservable {
                reason: ContinuityNotObservableReason::FileSource
            }
        );
        assert!(
            result.reference_only,
            "unactivated receipts carry the activationGeneration sentinel"
        );
        assert!(!result.supports_absence_claim());
        assert_eq!(
            result.reference_decode_receipt_digest,
            ContentDigest::sha256(&rgb_decode_receipt_bytes(&decode(BACKGROUND)?.receipt()))
        );
    }
    assert_eq!(changed.input_capture_root, ContentDigest::sha256(GRADIENT));
    assert_eq!(
        changed.decode_receipt_digest,
        ContentDigest::sha256(&rgb_decode_receipt_bytes(&decode(GRADIENT)?.receipt()))
    );
    Ok(())
}

#[test]
fn executor_results_are_deterministic() -> TestResult {
    let policy = ActivityThresholdPolicy::reference()?;
    let first = run(GRADIENT, &policy, budget(), "job:activity:repeat")?;
    let second = run(GRADIENT, &policy, budget(), "job:activity:repeat")?;
    assert_eq!(first, second);
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    Ok(())
}

#[test]
fn executor_failure_abstains_and_never_reads_as_no_detection() -> TestResult {
    let policy = ActivityThresholdPolicy::reference()?;
    let failed = run(
        GRADIENT,
        &policy,
        ExecBudget::new(1, 1),
        "job:activity:starved",
    )?;
    match failed.outcome {
        ExecutorModelOutcome::Abstained {
            reason,
            receipt_outcome,
        } => {
            assert_eq!(reason, ExecutorAbstentionReason::ExecutorFailed);
            assert_ne!(receipt_outcome, ReceiptOutcome::Ok);
        }
        other => return Err(format!("starved executor produced {other:?}").into()),
    }
    assert_eq!(failed.outcome.score(), None);

    let decision = evaluate_unknown_presence(
        EventId::parse("event:executor:abstain")?,
        vec![observation(failed, "file:recording")?],
    )?;
    assert_eq!(decision.event.state, EventState::Indeterminate);
    assert_eq!(decision.action, ReferencePolicyAction::Hold);
    assert!(
        decision
            .event
            .evidence
            .iter()
            .all(|edge| edge.relation == EvidenceEdgeRelation::DerivedFrom && !edge.supports)
    );
    Ok(())
}

#[test]
fn below_threshold_is_not_absence_or_contradiction() -> TestResult {
    let policy = ActivityThresholdPolicy::reference()?;
    let quiet = run(BACKGROUND, &policy, budget(), "job:activity:quiet")?;
    let decision = evaluate_unknown_presence(
        EventId::parse("event:executor:quiet")?,
        vec![observation(quiet, "file:recording")?],
    )?;
    assert_ne!(decision.event.state, EventState::Rejected);
    assert_eq!(decision.event.state, EventState::Indeterminate);
    assert!(
        decision
            .event
            .evidence
            .iter()
            .all(|edge| edge.relation != EvidenceEdgeRelation::Contradicts)
    );
    Ok(())
}

#[test]
fn one_camera_is_never_corroborated() -> TestResult {
    let policy = ActivityThresholdPolicy::reference()?;
    let activity = run(GRADIENT, &policy, budget(), "job:activity:a")?;
    let single = evaluate_unknown_presence(
        EventId::parse("event:executor:single")?,
        vec![observation(activity.clone(), "file:recording")?],
    )?;
    assert_eq!(single.event.state, EventState::Witnessed);
    assert_eq!(single.action, ReferencePolicyAction::Hold);
    assert_eq!(single.event.model_receipts, vec![activity.object_digest()]);
    assert_eq!(
        single.event.probability,
        ProbabilityInterval::new(0.0, 1.0)?
    );

    // Two activity results of the same camera, even under two declared failure domains and two
    // invocations, stay one sensor and one capture root: never corroborated.
    let again = run(GRADIENT, &policy, budget(), "job:activity:b")?;
    assert_ne!(again.object_digest(), activity.object_digest());
    let doubled = evaluate_unknown_presence(
        EventId::parse("event:executor:double")?,
        vec![
            observation(activity, "file:recording:a")?,
            observation(again, "file:recording:b")?,
        ],
    )?;
    assert_ne!(doubled.event.state, EventState::Corroborated);
    assert_eq!(doubled.action, ReferencePolicyAction::Hold);
    Ok(())
}

#[test]
fn duplicate_executor_results_are_refused_and_mixing_variants_works() -> TestResult {
    let policy = ActivityThresholdPolicy::reference()?;
    let activity = run(GRADIENT, &policy, budget(), "job:activity:dup")?;
    let duplicate = evaluate_unknown_presence(
        EventId::parse("event:executor:dup")?,
        vec![
            observation(activity.clone(), "file:recording")?,
            observation(activity.clone(), "file:recording:other")?,
        ],
    );
    assert!(matches!(
        duplicate,
        Err(ReferenceError::InvalidSpec("duplicate_model_result"))
    ));

    // A second, independent mock camera's person finding plus the executor activity: two
    // sensors, two capture roots, two domains.
    let mock = MockModelResult {
        generation_id: "mock:model:cam-side:v1".to_owned(),
        sensor_id: SensorId::parse("sensor:cam-side")?,
        model_spec_digest: ContentDigest::sha256(b"spec"),
        input_capture_root: ContentDigest::sha256(b"side-capture"),
        continuity_digest: ContentDigest::sha256(b"side-continuity"),
        outcome: MockModelOutcome::Finding {
            label: MockSemanticLabel::PersonLike,
            probability: ProbabilityInterval::new(0.9, 1.0)?,
        },
    };
    let mixed = evaluate_unknown_presence(
        EventId::parse("event:executor:mixed")?,
        vec![
            observation(activity.clone(), "file:recording")?,
            ReferenceModelObservation::new(mock.clone(), "side-power", interval()?)?,
        ],
    )?;
    assert_eq!(mixed.event.state, EventState::Corroborated);
    assert_eq!(mixed.event.model_receipts.len(), 2);

    // Each variant keeps its own encoding; an executor result is never a mock result.
    let executor = ReferenceModelResult::from(activity.clone());
    assert_eq!(executor.object_digest(), activity.object_digest());
    assert_eq!(executor.canonical_bytes(), activity.canonical_bytes());
    assert_eq!(
        ContentDigest::sha256(&executor.canonical_bytes()),
        activity.object_digest()
    );
    let mut domain = fss_core::CanonicalEncoder::new();
    domain.text(EXECUTOR_MODEL_RESULT_DOMAIN);
    assert!(executor.canonical_bytes().starts_with(&domain.finish()));
    assert_eq!(
        ReferenceModelResult::from(mock.clone()).object_digest(),
        mock.object_digest()
    );
    Ok(())
}

#[test]
fn receipt_binds_package_root_resize_program_and_decode_receipts() -> TestResult {
    use crate::model_receipt::{
        ReceiptDigest, compute_preprocess_program_digest, compute_resized_preprocess_program_digest,
    };
    use crate::preprocess::{ResizeAspect, ResizeFilter};

    let model = ActivityExecutorModel::load_committed(&ScalarExecCx::new())?;
    let reference = decode(BACKGROUND)?;
    let current = decode(GRADIENT)?;
    let (result, receipt) = model.invoke(
        &SensorId::parse("sensor:file-cam")?,
        binding(GRADIENT, &current),
        binding(BACKGROUND, &reference),
        &ActivityThresholdPolicy::reference()?,
        budget(),
        "job:activity:receipt",
        &ScalarExecCx::new(),
    )?;
    let package = model.package();
    // The verified package manifest is the model package root: not the inline-graph sentinel.
    assert_eq!(
        receipt.model_package_root,
        ReceiptDigest::Content(package.manifest_digest())
    );
    // Three input tensors, then the two decode-receipt records they were derived from.
    assert_eq!(receipt.input_roots.len(), 5);
    assert_eq!(
        receipt.input_roots[3..],
        [
            ReceiptDigest::Content(result.decode_receipt_digest),
            ReceiptDigest::Content(result.reference_decode_receipt_digest),
        ]
    );
    assert!(
        receipt
            .backend
            .feature_set
            .contains(&"input_roots:tensors=3,sources=2".to_owned())
    );
    // The preprocessing descriptor binds the recorded resize, not only the target size.
    let spec = package.spec();
    let resized = compute_resized_preprocess_program_digest(
        &spec.program,
        ResizeFilter::Nearest,
        ResizeAspect::Stretch,
    );
    assert_eq!(receipt.preprocess_program, ReceiptDigest::Content(resized));
    assert_ne!(
        resized,
        compute_preprocess_program_digest(Some(&spec.program))
    );
    assert_ne!(
        resized,
        compute_resized_preprocess_program_digest(
            &spec.program,
            ResizeFilter::Bilinear,
            ResizeAspect::Stretch
        )
    );
    // Still reference-only: no activation system exists.
    assert!(receipt.activation_generation.is_not_applicable());
    assert!(!receipt.model_package_root.is_not_applicable());
    assert!(result.reference_only);
    assert!(
        receipt
            .backend
            .feature_set
            .iter()
            .all(|f| !f.starts_with("sentinel:modelPackageRoot"))
    );
    receipt.verify(receipt.generation, &result.invocation_receipt_digest)?;
    assert!(receipt.to_json_canonical().contains(&format!(
        "\"modelPackageRoot\":\"{}\"",
        package.manifest_digest()
    )));
    Ok(())
}

#[test]
fn retained_results_round_trip_and_noncanonical_bytes_are_refused() -> TestResult {
    use crate::executor_activity::ExecutorActivityError;

    let policy = ActivityThresholdPolicy::reference()?;
    let activity = run(GRADIENT, &policy, budget(), "job:activity:rt-a")?;
    let quiet = run(BACKGROUND, &policy, budget(), "job:activity:rt-q")?;
    let failed = run(
        GRADIENT,
        &policy,
        ExecBudget::new(1, 1),
        "job:activity:rt-f",
    )?;
    assert!(matches!(
        activity.outcome,
        ExecutorModelOutcome::Activity { .. }
    ));
    assert!(matches!(
        quiet.outcome,
        ExecutorModelOutcome::NoActivity { .. }
    ));
    assert!(matches!(
        failed.outcome,
        ExecutorModelOutcome::Abstained { .. }
    ));
    for result in [&activity, &quiet, &failed] {
        let bytes = result.canonical_bytes();
        let decoded = ExecutorModelResult::decode_canonical(&bytes)?;
        assert_eq!(&decoded, result);
        assert_eq!(decoded.object_digest(), result.object_digest());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            ExecutorModelResult::decode_canonical(&trailing),
            Err(ExecutorActivityError::Decode(_))
        ));
        assert!(ExecutorModelResult::decode_canonical(&bytes[..bytes.len() - 1]).is_err());
    }
    // An unknown outcome tag is refused.
    let mut bytes = activity.canonical_bytes();
    let tag_at = bytes.len() - 5;
    assert_eq!(
        bytes[tag_at], 1,
        "activity outcome tag precedes the score bits"
    );
    bytes[tag_at] = 9;
    assert!(ExecutorModelResult::decode_canonical(&bytes).is_err());
    Ok(())
}

#[test]
fn scores_are_never_compared_across_generations_or_model_identities() -> TestResult {
    use crate::executor_activity::ExecutorActivityError;
    use std::cmp::Ordering;

    let policy = ActivityThresholdPolicy::reference()?;
    let changed = run(GRADIENT, &policy, budget(), "job:activity:cmp-a")?;
    let quiet = run(BACKGROUND, &policy, budget(), "job:activity:cmp-b")?;
    assert_eq!(changed.compare_scores(&quiet)?, Ordering::Greater);
    assert_eq!(quiet.compare_scores(&changed)?, Ordering::Less);

    let mut other_generation = quiet.clone();
    other_generation.model_generation = "model:fss-activity:v2".to_owned();
    assert!(matches!(
        changed.compare_scores(&other_generation),
        Err(ExecutorActivityError::CrossGenerationScoreMixing { .. })
    ));
    let mut other_model = quiet.clone();
    other_model.model_digest = ContentDigest::sha256(b"another package");
    assert!(matches!(
        changed.compare_scores(&other_model),
        Err(ExecutorActivityError::CrossModelScoreMixing { .. })
    ));
    let failed = run(
        GRADIENT,
        &policy,
        ExecBudget::new(1, 1),
        "job:activity:cmp-f",
    )?;
    assert!(matches!(
        changed.compare_scores(&failed),
        Err(ExecutorActivityError::NoScore)
    ));
    Ok(())
}

#[test]
fn threshold_boundary_at_just_below_and_just_above() -> TestResult {
    let policy = ActivityThresholdPolicy::reference()?;
    let t = policy.threshold();
    let below = f32::from_bits(t.to_bits() - 1);
    let above = f32::from_bits(t.to_bits() + 1);
    assert!(below < t && t < above);
    assert!(matches!(
        policy.classify(t),
        ExecutorModelOutcome::NoActivity { score_bits } if score_bits == t.to_bits()
    ));
    assert!(matches!(
        policy.classify(below),
        ExecutorModelOutcome::NoActivity { .. }
    ));
    assert!(matches!(
        policy.classify(above),
        ExecutorModelOutcome::Activity { score_bits } if score_bits == above.to_bits()
    ));
    for nonfinite in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        assert!(matches!(
            policy.classify(nonfinite),
            ExecutorModelOutcome::Abstained {
                reason: ExecutorAbstentionReason::NonFiniteScore,
                ..
            }
        ));
    }
    Ok(())
}
