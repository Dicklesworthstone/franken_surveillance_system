//! Contract tests for FSS-082 belief interval and first-class contradiction types.

#![forbid(unsafe_code)]

use fss_core::belief::{
    BeliefError, BeliefInterval, Contradiction, ContradictionParams, MAX_CONFLICTING_EVIDENCE,
    MAX_CONTRADICTION_ID_LEN, MAX_FAILURE_DOMAINS, MAX_STATEMENT_LEN, MAX_UNRESOLVED_WORLDS,
    MICRO_DENOMINATOR, MIN_CONFLICTING_EVIDENCE, MIN_FAILURE_DOMAINS, MIN_UNRESOLVED_WORLDS,
};
use fss_core::{
    CalibrationGeneration, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    ContentDigest, HypothesisDisposition, KnowledgeState, ProvenanceClass, RuntimeOutcome,
    TimestampNs,
};
use std::collections::BTreeSet;
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

fn test_calibration() -> Result<CalibrationGeneration, Box<dyn Error>> {
    CalibrationGeneration::parse("gen:cal:camera_color_v1".to_string())
        .map_err(|e| Box::new(e) as Box<dyn Error>)
}

fn test_calibration_other() -> Result<CalibrationGeneration, Box<dyn Error>> {
    CalibrationGeneration::parse("gen:cal:thermal_v1".to_string())
        .map_err(|e| Box::new(e) as Box<dyn Error>)
}

#[test]
fn test_belief_interval_valid_creation_and_bounds() -> TestResult {
    // Total ignorance: [0, 1_000_000]
    let full = BeliefInterval::new(0, MICRO_DENOMINATOR)?;
    assert_eq!(full.lower_micro(), 0);
    assert_eq!(full.upper_micro(), MICRO_DENOMINATOR);
    assert_eq!(full.width_micro(), MICRO_DENOMINATOR);
    assert!(full.is_total_ignorance());
    assert!(!full.is_point());
    assert!((full.lower_f64() - 0.0).abs() < f64::EPSILON);
    assert!((full.upper_f64() - 1.0).abs() < f64::EPSILON);

    // Sharp point probabilities
    let zero_point = BeliefInterval::point(0)?;
    assert!(zero_point.is_point());
    assert_eq!(zero_point.width_micro(), 0);

    let one_point = BeliefInterval::point(MICRO_DENOMINATOR)?;
    assert!(one_point.is_point());
    assert_eq!(one_point.width_micro(), 0);

    // Calibrated interval
    let cal = test_calibration()?;
    let calibrated = BeliefInterval::with_calibration(200_000, 800_000, cal.clone())?;
    assert_eq!(calibrated.calibration_generation(), Some(&cal));
    assert_eq!(calibrated.width_micro(), 600_000);
    assert!(calibrated.contains_probability(500_000));
    assert!(!calibrated.contains_probability(100_000));
    assert!(!calibrated.contains_probability(900_000));

    Ok(())
}

#[test]
fn test_belief_interval_inverted_lower_upper_fails_closed_never_clamped() {
    // Lower == upper is valid (point probability)
    assert!(BeliefInterval::new(500_000, 500_000).is_ok());

    // Bound + 1: lower == upper + 1 must fail closed with typed error, NEVER clamped
    let err = BeliefInterval::new(500_001, 500_000);
    assert!(matches!(
        err,
        Err(BeliefError::InvertedInterval {
            lower_micro: 500_001,
            upper_micro: 500_000,
        })
    ));

    // Severe inversion: [900_000, 100_000]
    let err_severe = BeliefInterval::new(900_000, 100_000);
    assert!(matches!(
        err_severe,
        Err(BeliefError::InvertedInterval {
            lower_micro: 900_000,
            upper_micro: 100_000,
        })
    ));
}

#[test]
fn test_belief_interval_bounds_at_bound_and_bound_plus_one() {
    // Upper bound at MICRO_DENOMINATOR (1_000_000) is valid
    assert!(BeliefInterval::new(0, MICRO_DENOMINATOR).is_ok());
    assert!(BeliefInterval::new(MICRO_DENOMINATOR, MICRO_DENOMINATOR).is_ok());

    // Bound + 1: 1_000_001 must return typed OutOfRange error
    let err = BeliefInterval::new(0, MICRO_DENOMINATOR + 1);
    assert!(matches!(
        err,
        Err(BeliefError::OutOfRange {
            field: "upper_micro",
            actual: 1_000_001,
            limit: 1_000_000,
        })
    ));

    // Lower bound > MICRO_DENOMINATOR
    let err_lower = BeliefInterval::new(MICRO_DENOMINATOR + 1, MICRO_DENOMINATOR + 1);
    assert!(matches!(
        err_lower,
        Err(BeliefError::OutOfRange {
            field: "lower_micro",
            actual: 1_000_001,
            limit: 1_000_000,
        })
    ));
}

#[test]
fn test_belief_interval_from_f64_conversion() -> TestResult {
    let interval = BeliefInterval::from_f64(0.25, 0.75)?;
    assert_eq!(interval.lower_micro(), 250_000);
    assert_eq!(interval.upper_micro(), 750_000);

    // Rejects non-finite values
    assert!(matches!(
        BeliefInterval::from_f64(f64::NAN, 0.5),
        Err(BeliefError::InvalidProbability(_))
    ));
    assert!(matches!(
        BeliefInterval::from_f64(0.5, f64::INFINITY),
        Err(BeliefError::InvalidProbability(_))
    ));

    // Rejects negative or > 1.0 values
    assert!(matches!(
        BeliefInterval::from_f64(-0.01, 0.5),
        Err(BeliefError::InvalidProbability(_))
    ));
    assert!(matches!(
        BeliefInterval::from_f64(0.5, 1.0001),
        Err(BeliefError::InvalidProbability(_))
    ));

    // Rejects inverted f64
    assert!(matches!(
        BeliefInterval::from_f64(0.8, 0.2),
        Err(BeliefError::InvertedInterval { .. })
    ));

    Ok(())
}

#[test]
fn test_belief_interval_intersection_fusion_and_disjoint_contradiction() -> TestResult {
    let cal = test_calibration()?;
    let i1 = BeliefInterval::with_calibration(200_000, 700_000, cal.clone())?;
    let i2 = BeliefInterval::with_calibration(400_000, 900_000, cal.clone())?;

    // Overlapping intervals fuse into intersection [400_000, 700_000]
    assert!(i1.overlaps(&i2));
    assert!(!i1.is_contradiction_with(&i2));
    let fused = i1.intersect(&i2)?;
    assert_eq!(fused.lower_micro(), 400_000);
    assert_eq!(fused.upper_micro(), 700_000);
    assert_eq!(fused.calibration_generation(), Some(&cal));

    // Disjoint intervals: [100_000, 300_000] and [400_000, 800_000]
    let disjoint1 = BeliefInterval::new(100_000, 300_000)?;
    let disjoint2 = BeliefInterval::new(400_000, 800_000)?;
    assert!(!disjoint1.overlaps(&disjoint2));
    assert!(disjoint1.is_contradiction_with(&disjoint2));

    // Intersecting disjoint intervals must fail closed with DisjointIntervals contradiction, NEVER clamp
    let contra_err = disjoint1.intersect(&disjoint2);
    assert!(matches!(
        contra_err,
        Err(BeliefError::DisjointIntervals {
            lower_a: 100_000,
            upper_a: 300_000,
            lower_b: 400_000,
            upper_b: 800_000,
        })
    ));

    // Calibration mismatch returns typed error
    let other_cal = test_calibration_other()?;
    let diff_cal = BeliefInterval::with_calibration(400_000, 600_000, other_cal)?;
    let cal_err = i1.intersect(&diff_cal);
    assert!(matches!(
        cal_err,
        Err(BeliefError::CalibrationMismatch { .. })
    ));

    Ok(())
}

#[test]
fn test_belief_interval_span_and_complement() -> TestResult {
    let i1 = BeliefInterval::new(200_000, 500_000)?;
    let i2 = BeliefInterval::new(400_000, 800_000)?;

    // Span / convex hull: [200_000, 800_000]
    let spanned = i1.span(&i2)?;
    assert_eq!(spanned.lower_micro(), 200_000);
    assert_eq!(spanned.upper_micro(), 800_000);

    // Complement / negation: [200_000, 700_000] -> [300_000, 800_000]
    let target = BeliefInterval::new(200_000, 700_000)?;
    let comp = target.complement();
    assert_eq!(comp.lower_micro(), 300_000);
    assert_eq!(comp.upper_micro(), 800_000);

    Ok(())
}

#[test]
fn test_belief_interval_canonical_roundtrip() -> TestResult {
    let cal = test_calibration()?;
    let original = BeliefInterval::with_calibration(123_456, 789_012, cal)?;

    let mut encoder = CanonicalEncoder::new();
    original.encode_canonical(&mut encoder);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let decoded = BeliefInterval::decode_canonical(&mut decoder)?;
    decoder.ensure_finished()?;

    assert_eq!(original, decoded);
    assert_eq!(original.interval_digest(), decoded.interval_digest());

    Ok(())
}

fn sample_contradiction_params() -> Result<ContradictionParams, BeliefError> {
    let d1 = ContentDigest::sha256(b"cam1-detection-evidence");
    let d2 = ContentDigest::sha256(b"radar-negative-evidence");

    Ok(ContradictionParams {
        contradiction_id: "contra:test:001".to_string(),
        conflicting_evidence: BTreeSet::from([d1, d2]),
        failure_domains: BTreeSet::from(["domain:optical:cam1".to_string(), "domain:rf:radar".to_string()]),
        unresolved_worlds: BTreeSet::from(["world:person_present".to_string(), "world:empty_scene".to_string()]),
        claim_id: Some("claim:presence:zone_a".to_string()),
        statement: "Optical sensor reports presence while RF radar reports clear sector under identical geometry".to_string(),
        belief_interval: Some(BeliefInterval::new(100_000, 900_000)?),
        created_at: TimestampNs(1_000_000),
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::Derived,
        disposition: HypothesisDisposition::Live,
        outcome: RuntimeOutcome::Indeterminate,
    })
}

#[test]
fn test_contradiction_construction_valid() -> TestResult {
    let params = sample_contradiction_params()?;
    let contra = Contradiction::new(params.clone())?;

    assert_eq!(contra.contradiction_id(), &params.contradiction_id);
    assert_eq!(contra.conflicting_evidence().len(), 2);
    assert_eq!(contra.failure_domains().len(), 2);
    assert_eq!(contra.unresolved_worlds().len(), 2);
    assert_eq!(contra.claim_id(), params.claim_id.as_deref());
    assert_eq!(contra.statement(), &params.statement);
    assert_eq!(contra.knowledge_state(), KnowledgeState::Conflicted);
    assert_eq!(contra.provenance(), ProvenanceClass::Derived);
    assert_eq!(contra.disposition(), HypothesisDisposition::Live);
    assert_eq!(contra.outcome(), RuntimeOutcome::Indeterminate);
    assert_eq!(contra.created_at(), TimestampNs(1_000_000));

    Ok(())
}

#[test]
fn test_contradiction_requires_two_evidence_roots_at_bound_and_bound_plus_one() -> TestResult {
    let mut params = sample_contradiction_params()?;

    // Bound - 1: exactly 1 evidence root fails closed
    params.conflicting_evidence = BTreeSet::from([ContentDigest::sha256(b"only-one")]);
    let err_one = Contradiction::new(params.clone());
    assert!(matches!(
        err_one,
        Err(BeliefError::InsufficientEvidenceRoots {
            actual: 1,
            min_required: MIN_CONFLICTING_EVIDENCE,
        })
    ));

    // Bound: exactly MIN_CONFLICTING_EVIDENCE (2) passes
    params.conflicting_evidence =
        BTreeSet::from([ContentDigest::sha256(b"e1"), ContentDigest::sha256(b"e2")]);
    assert!(Contradiction::new(params.clone()).is_ok());

    // Max bound: MAX_CONFLICTING_EVIDENCE (64) passes
    let mut max_evidence = BTreeSet::new();
    for i in 0..MAX_CONFLICTING_EVIDENCE {
        max_evidence.insert(ContentDigest::sha256(format!("evidence:{i}").as_bytes()));
    }
    params.conflicting_evidence = max_evidence;
    assert!(Contradiction::new(params.clone()).is_ok());

    // Max bound + 1: MAX_CONFLICTING_EVIDENCE + 1 (65) fails closed
    params
        .conflicting_evidence
        .insert(ContentDigest::sha256(b"overflow"));
    let err_over = Contradiction::new(params);
    assert!(matches!(
        err_over,
        Err(BeliefError::OverLimitLength {
            field: "conflicting_evidence",
            actual: 65,
            limit: MAX_CONFLICTING_EVIDENCE,
        })
    ));

    Ok(())
}

#[test]
fn test_contradiction_requires_two_independent_failure_domains_at_bound_and_bound_plus_one()
-> TestResult {
    let mut params = sample_contradiction_params()?;

    // Bound - 1: exactly 1 failure domain fails closed (prohibited: calling single sensor contradicted/corroborated)
    params.failure_domains = BTreeSet::from(["domain:cam1".to_string()]);
    let err_one = Contradiction::new(params.clone());
    assert!(matches!(
        err_one,
        Err(BeliefError::InsufficientFailureDomains {
            actual: 1,
            min_required: MIN_FAILURE_DOMAINS,
        })
    ));

    // Bound: exactly MIN_FAILURE_DOMAINS (2) passes
    params.failure_domains = BTreeSet::from(["domain:cam1".to_string(), "domain:cam2".to_string()]);
    assert!(Contradiction::new(params.clone()).is_ok());

    // Max bound: MAX_FAILURE_DOMAINS (32) passes
    let mut max_domains = BTreeSet::new();
    for i in 0..MAX_FAILURE_DOMAINS {
        max_domains.insert(format!("domain:sensor:{i}"));
    }
    params.failure_domains = max_domains;
    assert!(Contradiction::new(params.clone()).is_ok());

    // Max bound + 1: MAX_FAILURE_DOMAINS + 1 (33) fails closed
    params
        .failure_domains
        .insert("domain:sensor:overflow".to_string());
    let err_over = Contradiction::new(params);
    assert!(matches!(
        err_over,
        Err(BeliefError::OverLimitLength {
            field: "failure_domains",
            actual: 33,
            limit: MAX_FAILURE_DOMAINS,
        })
    ));

    Ok(())
}

#[test]
fn test_contradiction_requires_unresolved_worlds_at_bound_and_bound_plus_one() -> TestResult {
    let mut params = sample_contradiction_params()?;

    // Bound - 1: empty unresolved worlds fails closed (contradiction must keep alternative worlds alive)
    params.unresolved_worlds = BTreeSet::new();
    let err_empty = Contradiction::new(params.clone());
    assert!(matches!(err_empty, Err(BeliefError::EmptyUnresolvedWorlds)));

    // Bound: exactly MIN_UNRESOLVED_WORLDS (1) passes
    params.unresolved_worlds = BTreeSet::from(["world:unresolved_branch".to_string()]);
    assert_eq!(params.unresolved_worlds.len(), MIN_UNRESOLVED_WORLDS);
    assert!(Contradiction::new(params.clone()).is_ok());

    // Max bound: MAX_UNRESOLVED_WORLDS (64) passes
    let mut max_worlds = BTreeSet::new();
    for i in 0..MAX_UNRESOLVED_WORLDS {
        max_worlds.insert(format!("world:candidate:{i}"));
    }
    params.unresolved_worlds = max_worlds;
    assert!(Contradiction::new(params.clone()).is_ok());

    // Max bound + 1: MAX_UNRESOLVED_WORLDS + 1 (65) fails closed
    params
        .unresolved_worlds
        .insert("world:candidate:overflow".to_string());
    let err_over = Contradiction::new(params);
    assert!(matches!(
        err_over,
        Err(BeliefError::OverLimitLength {
            field: "unresolved_worlds",
            actual: 65,
            limit: MAX_UNRESOLVED_WORLDS,
        })
    ));

    Ok(())
}

#[test]
fn test_contradiction_string_length_bounds_at_bound_and_bound_plus_one() -> TestResult {
    let mut params = sample_contradiction_params()?;

    // Contradiction ID: empty fails
    params.contradiction_id = String::new();
    assert!(matches!(
        Contradiction::new(params.clone()),
        Err(BeliefError::EmptyField {
            field: "contradiction_id"
        })
    ));

    // Contradiction ID: bound (128) passes
    params.contradiction_id = "a".repeat(MAX_CONTRADICTION_ID_LEN);
    assert!(Contradiction::new(params.clone()).is_ok());

    // Contradiction ID: bound + 1 (129) fails
    params.contradiction_id = "a".repeat(MAX_CONTRADICTION_ID_LEN + 1);
    assert!(matches!(
        Contradiction::new(params.clone()),
        Err(BeliefError::OverLimitLength {
            field: "contradiction_id",
            actual: 129,
            limit: MAX_CONTRADICTION_ID_LEN,
        })
    ));

    // Statement: empty fails
    params.contradiction_id = "contra:valid".to_string();
    params.statement = String::new();
    assert!(matches!(
        Contradiction::new(params.clone()),
        Err(BeliefError::EmptyField { field: "statement" })
    ));

    // Statement: bound (512) passes
    params.statement = "s".repeat(MAX_STATEMENT_LEN);
    assert!(Contradiction::new(params.clone()).is_ok());

    // Statement: bound + 1 (513) fails
    params.statement = "s".repeat(MAX_STATEMENT_LEN + 1);
    assert!(matches!(
        Contradiction::new(params),
        Err(BeliefError::OverLimitLength {
            field: "statement",
            actual: 513,
            limit: MAX_STATEMENT_LEN,
        })
    ));

    Ok(())
}

#[test]
fn test_contradiction_orthogonal_coordinates_preserved() -> TestResult {
    let params = sample_contradiction_params()?;
    let contra = Contradiction::new(params)?;

    // All 4 coordinates remain strictly orthogonal enum values, never collapsed into a scalar score
    assert_eq!(contra.knowledge_state(), KnowledgeState::Conflicted);
    assert_eq!(contra.provenance(), ProvenanceClass::Derived);
    assert_eq!(contra.disposition(), HypothesisDisposition::Live);
    assert_eq!(contra.outcome(), RuntimeOutcome::Indeterminate);

    // Contradiction explicitly preserves uncertainty rather than flattening into low confidence
    assert!(contra.is_active());
    assert!(!contra.unresolved_worlds().is_empty());
    assert!(contra.failure_domains().len() >= 2);

    Ok(())
}

#[test]
fn test_contradiction_canonical_roundtrip() -> TestResult {
    let params = sample_contradiction_params()?;
    let original = Contradiction::new(params)?;

    let mut encoder = CanonicalEncoder::new();
    original.encode_canonical(&mut encoder);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let decoded = Contradiction::decode_canonical(&mut decoder)?;
    decoder.ensure_finished()?;

    assert_eq!(original, decoded);
    assert_eq!(
        original.contradiction_digest(),
        decoded.contradiction_digest()
    );

    Ok(())
}
