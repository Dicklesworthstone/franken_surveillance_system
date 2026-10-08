//! Executor-backed observations through the unknown-presence policy (fss-2h5zq.51).
//!
//! Every score here is computed by the scalar executor over pixels natively decoded from the
//! checked-in fss-codec-mjpeg fixtures. One fixture pair is not accuracy evidence, and the score
//! is not a calibrated probability.

use std::error::Error;

use fss_codec_mjpeg::color::{DecodedRgb, RgbDecodeLimits, decode_rgb};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget};
use fss_core::{
    CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, ContentDigest, EventId, EventState,
    EvidenceEdgeRelation, ProbabilityInterval, SensorCapsule, SensorId, SensorSourceBytesSpec,
    StreamId, TimestampNs,
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

fn binding<'a>(
    bytes: &[u8],
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

/// The sensor capsule of `source` as recorded by `sensor`.
fn capsule_for(source: &[u8], sensor: &str, sequence: u64) -> TestResult<SensorCapsule> {
    let capture = interval()?;
    Ok(SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
        capsule_id: CapsuleId::parse(format!("capsule:executor-test:{sequence}"))?,
        sensor_id: SensorId::parse(sensor)?,
        stream_id: StreamId::parse("stream:executor-test")?,
        sequence,
        capture,
        receive_time: capture.latest,
        clock_basis: ClockBasis::Estimated,
        source,
        frame_count: 1,
        gap_before: false,
    })?)
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
    let frame_capsule = capsule_for(frame, "sensor:file-cam", 1)?;
    let reference_capsule = capsule_for(BACKGROUND, "sensor:file-cam", 0)?;
    let (result, receipt) = model.invoke(
        &SensorId::parse("sensor:file-cam")?,
        binding(frame, &current, &frame_capsule),
        binding(BACKGROUND, &reference, &reference_capsule),
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
        "executor_scores changed={changed_score} unchanged={unchanged_score} threshold={}",
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
    let frame_capsule = capsule_for(GRADIENT, "sensor:file-cam", 1)?;
    let reference_capsule = capsule_for(BACKGROUND, "sensor:file-cam", 0)?;
    let (result, receipt) = model.invoke(
        &SensorId::parse("sensor:file-cam")?,
        binding(GRADIENT, &current, &frame_capsule),
        binding(BACKGROUND, &reference, &reference_capsule),
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

/// Review finding (2026-10-08, fss-2h5zq.51): `capsule_digest` was taken from the caller
/// unchecked, so a result could name a capsule it never saw. The binding now carries the actual
/// capsule; one that names other source bytes or another sensor (for the evaluated frame or the
/// reference frame) is refused, and the result names the digest of the capsule it was given.
#[test]
fn a_capsule_that_is_not_the_frames_own_is_refused() -> TestResult {
    let model = ActivityExecutorModel::load_committed(&ScalarExecCx::new())?;
    let sensor = SensorId::parse("sensor:file-cam")?;
    let current = decode(GRADIENT)?;
    let reference = decode(BACKGROUND)?;
    let own = capsule_for(GRADIENT, "sensor:file-cam", 1)?;
    let reference_own = capsule_for(BACKGROUND, "sensor:file-cam", 0)?;
    let other_bytes = capsule_for(BACKGROUND, "sensor:file-cam", 1)?;
    let other_sensor = capsule_for(GRADIENT, "sensor:cam-side", 1)?;
    let reference_other_sensor = capsule_for(BACKGROUND, "sensor:cam-side", 0)?;
    let invoke = |frame: &SensorCapsule, reference_capsule: &SensorCapsule| {
        model.invoke(
            &sensor,
            binding(GRADIENT, &current, frame),
            binding(BACKGROUND, &reference, reference_capsule),
            &ActivityThresholdPolicy::reference()?,
            budget(),
            "job:activity:capsule",
            &ScalarExecCx::new(),
        )
    };
    for (case, frame, reference_capsule, expected) in [
        (
            "frame_capsule_of_other_bytes",
            &other_bytes,
            &reference_own,
            "capsule names other source bytes",
        ),
        (
            "frame_capsule_of_other_sensor",
            &other_sensor,
            &reference_own,
            "capsule names another sensor",
        ),
        (
            "reference_capsule_of_other_bytes",
            &own,
            &own,
            "capsule names other source bytes",
        ),
        (
            "reference_capsule_of_other_sensor",
            &own,
            &reference_other_sensor,
            "capsule names another sensor",
        ),
    ] {
        match invoke(frame, reference_capsule) {
            Err(ExecutorActivityError::InvalidInput(what)) => assert_eq!(what, expected, "{case}"),
            other => return Err(format!("{case}: expected refusal, got {other:?}").into()),
        }
    }
    let (result, _) = invoke(&own, &reference_own)?;
    assert_eq!(
        result.capsule_digest,
        ContentDigest::sha256(&own.canonical_bytes())
    );
    assert_ne!(
        result.capsule_digest,
        ContentDigest::sha256(&other_bytes.canonical_bytes())
    );
    assert_eq!(result.input_capture_root, own.source_digest);
    Ok(())
}

struct RetentionDirectory(std::path::PathBuf);

impl RetentionDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-executor-retention-{name}-{}-{attempt}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }
}

impl Drop for RetentionDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn replay_cx(root: &std::path::Path) -> TestResult<crate::ReplayCx> {
    use fss_core::region::{ContextAuthority, RootAuthoritySpec};
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:executor-retention".to_owned(),
        operation_id: fss_core::OperationId::parse("operation:executor-retention")?,
        principal: "principal:executor-retention".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(b"site:executor-retention"),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(crate::ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

/// Review finding (2026-10-08, fss-2h5zq.51): executor results and invocation receipts were
/// staged but never reachable from a ledgered root. A retained result now has a published root
/// and a ledger batch with one `executor_model_result` and one `model_invocation_receipt` delta;
/// after the deployment is dropped and reopened, the result and the exact receipt bytes read
/// back from the ledger and spool. A rerun is idempotent, a receipt of another invocation is
/// refused, and a retained object damaged on disk is refused on read-back.
#[test]
fn executor_results_and_receipts_are_ledgered_and_read_back_after_restart() -> TestResult {
    use crate::executor_activity::{open_retained_executor_result, retain_executor_result};
    use crate::reference_deployment::{
        FAMILY_EXECUTOR_MODEL_RESULT, FAMILY_MODEL_INVOCATION_RECEIPT,
    };

    let dir = RetentionDirectory::new("roundtrip")?;
    let root = dir.0.join("deployment");
    let cx = replay_cx(&root)?;
    let model = ActivityExecutorModel::load_committed(&ScalarExecCx::new())?;
    let current = decode(GRADIENT)?;
    let reference = decode(BACKGROUND)?;
    let frame_capsule = capsule_for(GRADIENT, "sensor:file-cam", 1)?;
    let reference_capsule = capsule_for(BACKGROUND, "sensor:file-cam", 0)?;
    let invoke = |job: &str, budget: ExecBudget| {
        model.invoke(
            &SensorId::parse("sensor:file-cam")?,
            binding(GRADIENT, &current, &frame_capsule),
            binding(BACKGROUND, &reference, &reference_capsule),
            &ActivityThresholdPolicy::reference()?,
            budget,
            job,
            &ScalarExecCx::new(),
        )
    };
    let (result, receipt) = invoke("job:activity:retain", budget())?;
    let (_, other_receipt) = invoke("job:activity:retain-other", ExecBudget::new(1, 1))?;

    let (retained, sequence) = {
        let mut deployment =
            crate::ReferenceDeployment::open(&root, "site:executor-retention", &cx)?;
        // A receipt of another invocation is never ledgered beside this result.
        assert!(matches!(
            retain_executor_result(&mut deployment, &result, &other_receipt, interval()?, &cx),
            Err(ExecutorActivityError::RetentionMismatch(_))
        ));
        let retained =
            retain_executor_result(&mut deployment, &result, &receipt, interval()?, &cx)?;
        let sequence = deployment.current_anchor().commit_sequence;
        // Idempotent: the same retention again commits nothing new.
        let again = retain_executor_result(&mut deployment, &result, &receipt, interval()?, &cx)?;
        assert_eq!(again, retained);
        assert_eq!(deployment.current_anchor().commit_sequence, sequence);
        assert!(deployment.reconcile()?.is_clean());
        (retained, sequence)
    };
    assert_eq!(retained.result_digest, result.object_digest());
    assert_eq!(
        retained.receipt_json,
        receipt.to_json_canonical().into_bytes()
    );

    // Restart: everything reads back from the reopened deployment's ledger and spool.
    let reopened = crate::ReferenceDeployment::reopen(&root, "site:executor-retention", &cx)?;
    assert_eq!(reopened.current_anchor().commit_sequence, sequence);
    let batch = reopened
        .ledger()
        .batches()
        .iter()
        .find(|batch| batch.new_anchor == retained.anchor)
        .ok_or("retained batch missing after restart")?;
    let families: Vec<&str> = batch.deltas.iter().map(|d| d.family.as_str()).collect();
    assert_eq!(
        families,
        [
            FAMILY_EXECUTOR_MODEL_RESULT,
            FAMILY_MODEL_INVOCATION_RECEIPT
        ]
    );
    for delta in &batch.deltas {
        assert_eq!(delta.witness_digest, Some(retained.root));
    }
    assert!(
        batch
            .deltas
            .iter()
            .any(|d| d.payload_digest == retained.result_digest)
    );
    assert!(
        batch
            .deltas
            .iter()
            .any(|d| d.payload_digest == result.invocation_receipt_object)
    );
    let read_back = open_retained_executor_result(&reopened, retained.result_digest, &cx)?;
    assert_eq!(read_back, retained);
    assert_eq!(read_back.result, result);
    assert_eq!(
        ContentDigest::sha256(&read_back.receipt_json),
        result.invocation_receipt_object
    );

    // A retained object damaged on disk after the restart is refused on read-back.
    let object = reopened
        .publisher()
        .spool()
        .object_path(retained.result_digest);
    let mut bytes = std::fs::read(&object)?;
    let last = bytes.last_mut().ok_or("empty object")?;
    *last ^= 0x01;
    std::fs::write(&object, bytes)?;
    assert!(open_retained_executor_result(&reopened, retained.result_digest, &cx).is_err());
    Ok(())
}
