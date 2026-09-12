//! Contract tests for FSS-082 belief interval and first-class contradiction types.

#![forbid(unsafe_code)]

use fss_core::belief::{
    BeliefError, BeliefInterval, CONTRADICTION_DOMAIN, Contradiction, ContradictionParams,
    MAX_CONFLICTING_EVIDENCE, MAX_CONTRADICTION_ID_LEN, MAX_FAILURE_DOMAINS, MAX_STATEMENT_LEN,
    MAX_UNRESOLVED_WORLDS, MICRO_DENOMINATOR, MIN_CONFLICTING_EVIDENCE, MIN_FAILURE_DOMAINS,
    MIN_UNRESOLVED_WORLDS,
};
use fss_core::{
    CalibrationGeneration, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    ContentDigest, ContractError, HypothesisDisposition, KnowledgeState, ProvenanceClass,
    RuntimeOutcome, TimestampNs,
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

#[test]
fn test_finding_1_inverted_float_near_micro_boundary_fails_closed() {
    let lower = 0.5000004;
    let upper = 0.5000001;
    assert!(lower > upper);
    let res = BeliefInterval::from_f64(lower, upper);
    assert!(
        matches!(res, Err(BeliefError::InvertedInterval { .. })),
        "Inverted float input must fail closed with InvertedInterval, got: {res:?}"
    );
}

#[test]
fn test_finding_2_canonical_decode_rejects_duplicate_and_unsorted_domains()
-> Result<(), Box<dyn Error>> {
    let valid = sample_contradiction_params()?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text(CONTRADICTION_DOMAIN);
    encoder.text(&valid.contradiction_id);
    // 2 evidence digests
    encoder.u64(2);
    for d in &valid.conflicting_evidence {
        encoder.digest(*d);
    }
    // Non-canonical duplicate domains: count=3, ["domain:a", "domain:a", "domain:b"]
    encoder.u64(3);
    encoder.text("domain:a");
    encoder.text("domain:a");
    encoder.text("domain:b");
    // Remainder of valid fields...
    encoder.u64(valid.unresolved_worlds.len() as u64);
    for w in &valid.unresolved_worlds {
        encoder.text(w);
    }
    encoder.bool(false);
    encoder.text(&valid.statement);
    encoder.bool(false);
    valid.created_at.encode_canonical(&mut encoder);
    encoder.text(valid.knowledge_state.as_str());
    encoder.u8(1);
    encoder.u8(1);
    encoder.u8(1);

    let bytes = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&bytes);
    let res = Contradiction::decode_canonical(&mut decoder);
    assert_eq!(
        res.err(),
        Some(ContractError::NonCanonicalOrdering),
        "Canonical decode must reject duplicate elements in set with NonCanonicalOrdering"
    );
    Ok(())
}

#[test]
fn test_finding_2_canonical_decode_rejects_unsorted_domains() -> Result<(), Box<dyn Error>> {
    let valid = sample_contradiction_params()?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text(CONTRADICTION_DOMAIN);
    encoder.text(&valid.contradiction_id);
    encoder.u64(2);
    for d in &valid.conflicting_evidence {
        encoder.digest(*d);
    }
    // Unsorted failure domains: ["domain:z", "domain:a"]
    encoder.u64(2);
    encoder.text("domain:z");
    encoder.text("domain:a");
    encoder.u64(valid.unresolved_worlds.len() as u64);
    for w in &valid.unresolved_worlds {
        encoder.text(w);
    }
    encoder.bool(false);
    encoder.text(&valid.statement);
    encoder.bool(false);
    valid.created_at.encode_canonical(&mut encoder);
    encoder.text(valid.knowledge_state.as_str());
    encoder.u8(1);
    encoder.u8(1);
    encoder.u8(1);

    let bytes = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&bytes);
    let res = Contradiction::decode_canonical(&mut decoder);
    assert_eq!(
        res.err(),
        Some(ContractError::NonCanonicalOrdering),
        "Canonical decode must reject unsorted elements in set with NonCanonicalOrdering"
    );
    Ok(())
}

#[test]
fn test_finding_2_canonical_decode_rejects_duplicate_evidence() -> Result<(), Box<dyn Error>> {
    let valid = sample_contradiction_params()?;
    let d = ContentDigest::sha256(b"same-evidence");
    let mut encoder = CanonicalEncoder::new();
    encoder.text(CONTRADICTION_DOMAIN);
    encoder.text(&valid.contradiction_id);
    // Duplicate evidence digests: [d, d]
    encoder.u64(2);
    encoder.digest(d);
    encoder.digest(d);
    encoder.u64(valid.failure_domains.len() as u64);
    for dom in &valid.failure_domains {
        encoder.text(dom);
    }
    encoder.u64(valid.unresolved_worlds.len() as u64);
    for w in &valid.unresolved_worlds {
        encoder.text(w);
    }
    encoder.bool(false);
    encoder.text(&valid.statement);
    encoder.bool(false);
    valid.created_at.encode_canonical(&mut encoder);
    encoder.text(valid.knowledge_state.as_str());
    encoder.u8(1);
    encoder.u8(1);
    encoder.u8(1);

    let bytes = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&bytes);
    let res = Contradiction::decode_canonical(&mut decoder);
    assert_eq!(
        res.err(),
        Some(ContractError::NonCanonicalOrdering),
        "Canonical decode must reject duplicate evidence with NonCanonicalOrdering"
    );
    Ok(())
}

#[test]
fn test_finding_5_evidence_under_min_fails_with_evidence_error_not_invalid_identifier()
-> Result<(), Box<dyn Error>> {
    let valid = sample_contradiction_params()?;
    let mut encoder = CanonicalEncoder::new();
    encoder.text(CONTRADICTION_DOMAIN);
    encoder.text(&valid.contradiction_id);
    // Under min: exactly 1 evidence digest (< MIN_CONFLICTING_EVIDENCE = 2)
    encoder.u64(1);
    encoder.digest(ContentDigest::sha256(b"only-one"));
    encoder.u64(valid.failure_domains.len() as u64);
    for d in &valid.failure_domains {
        encoder.text(d);
    }
    encoder.u64(valid.unresolved_worlds.len() as u64);
    for w in &valid.unresolved_worlds {
        encoder.text(w);
    }
    encoder.bool(false);
    encoder.text(&valid.statement);
    encoder.bool(false);
    valid.created_at.encode_canonical(&mut encoder);
    encoder.text(valid.knowledge_state.as_str());
    encoder.u8(1);
    encoder.u8(1);
    encoder.u8(1);

    let bytes = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&bytes);
    let res = Contradiction::decode_canonical(&mut decoder);
    assert_eq!(
        res.err(),
        Some(ContractError::EvidenceRequired),
        "Stream with evidence_count = 1 must reject with EvidenceRequired, not InvalidIdentifier"
    );
    Ok(())
}

#[test]
fn test_finding_3_known_supported_contradiction_is_active() -> Result<(), Box<dyn Error>> {
    let mut params = sample_contradiction_params()?;
    params.knowledge_state = KnowledgeState::Known;
    params.disposition = HypothesisDisposition::Supported;
    params.outcome = RuntimeOutcome::Ok;
    let contra = Contradiction::new(params)?;
    assert!(
        contra.is_active(),
        "A known, supported physical contradiction must be active!"
    );
    Ok(())
}

#[test]
fn test_finding_4_intersect_uncalibrated_does_not_launder_calibration() -> Result<(), Box<dyn Error>>
{
    let cal = test_calibration()?;
    let calibrated = BeliefInterval::with_calibration(200_000, 800_000, cal)?;
    let uncalibrated = BeliefInterval::new(600_000, 700_000)?;
    let fused = calibrated.intersect(&uncalibrated)?;
    assert_eq!(
        fused.calibration_generation(),
        None,
        "Fusing with uncalibrated evidence must not launder uncalibrated bounds into a calibration generation"
    );
    Ok(())
}

#[test]
fn test_finding_2_canonical_decode_rejects_unsorted_evidence() -> Result<(), Box<dyn Error>> {
    let valid = sample_contradiction_params()?;
    let d1 = ContentDigest::sha256(b"z-evidence");
    let d2 = ContentDigest::sha256(b"a-evidence");
    let (greater, lesser) = if d1 > d2 { (d1, d2) } else { (d2, d1) };

    let mut encoder = CanonicalEncoder::new();
    encoder.text(CONTRADICTION_DOMAIN);
    encoder.text(&valid.contradiction_id);
    // Unsorted evidence: greater, then lesser
    encoder.u64(2);
    encoder.digest(greater);
    encoder.digest(lesser);
    encoder.u64(valid.failure_domains.len() as u64);
    for dom in &valid.failure_domains {
        encoder.text(dom);
    }
    encoder.u64(valid.unresolved_worlds.len() as u64);
    for w in &valid.unresolved_worlds {
        encoder.text(w);
    }
    encoder.bool(false);
    encoder.text(&valid.statement);
    encoder.bool(false);
    valid.created_at.encode_canonical(&mut encoder);
    encoder.text(valid.knowledge_state.as_str());
    encoder.u8(1);
    encoder.u8(1);
    encoder.u8(1);

    let bytes = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&bytes);
    let res = Contradiction::decode_canonical(&mut decoder);
    assert_eq!(
        res.err(),
        Some(ContractError::NonCanonicalOrdering),
        "Canonical decode must reject unsorted evidence with NonCanonicalOrdering"
    );
    Ok(())
}

#[test]
fn test_finding_2_canonical_decode_rejects_duplicate_and_unsorted_worlds()
-> Result<(), Box<dyn Error>> {
    let valid = sample_contradiction_params()?;

    // Duplicate worlds
    let mut enc_dup = CanonicalEncoder::new();
    enc_dup.text(CONTRADICTION_DOMAIN);
    enc_dup.text(&valid.contradiction_id);
    enc_dup.u64(valid.conflicting_evidence.len() as u64);
    for d in &valid.conflicting_evidence {
        enc_dup.digest(*d);
    }
    enc_dup.u64(valid.failure_domains.len() as u64);
    for dom in &valid.failure_domains {
        enc_dup.text(dom);
    }
    enc_dup.u64(2);
    enc_dup.text("world:same");
    enc_dup.text("world:same");
    enc_dup.bool(false);
    enc_dup.text(&valid.statement);
    enc_dup.bool(false);
    valid.created_at.encode_canonical(&mut enc_dup);
    enc_dup.text(valid.knowledge_state.as_str());
    enc_dup.u8(1);
    enc_dup.u8(1);
    enc_dup.u8(1);

    let bytes_dup = enc_dup.finish();
    let mut dec_dup = CanonicalDecoder::new(&bytes_dup);
    assert_eq!(
        Contradiction::decode_canonical(&mut dec_dup).err(),
        Some(ContractError::NonCanonicalOrdering),
        "Canonical decode must reject duplicate worlds with NonCanonicalOrdering"
    );

    // Unsorted worlds
    let mut enc_unsorted = CanonicalEncoder::new();
    enc_unsorted.text(CONTRADICTION_DOMAIN);
    enc_unsorted.text(&valid.contradiction_id);
    enc_unsorted.u64(valid.conflicting_evidence.len() as u64);
    for d in &valid.conflicting_evidence {
        enc_unsorted.digest(*d);
    }
    enc_unsorted.u64(valid.failure_domains.len() as u64);
    for dom in &valid.failure_domains {
        enc_unsorted.text(dom);
    }
    enc_unsorted.u64(2);
    enc_unsorted.text("world:z");
    enc_unsorted.text("world:a");
    enc_unsorted.bool(false);
    enc_unsorted.text(&valid.statement);
    enc_unsorted.bool(false);
    valid.created_at.encode_canonical(&mut enc_unsorted);
    enc_unsorted.text(valid.knowledge_state.as_str());
    enc_unsorted.u8(1);
    enc_unsorted.u8(1);
    enc_unsorted.u8(1);

    let bytes_unsorted = enc_unsorted.finish();
    let mut dec_unsorted = CanonicalDecoder::new(&bytes_unsorted);
    assert_eq!(
        Contradiction::decode_canonical(&mut dec_unsorted).err(),
        Some(ContractError::NonCanonicalOrdering),
        "Canonical decode must reject unsorted worlds with NonCanonicalOrdering"
    );

    Ok(())
}

#[test]
fn test_finding_3_terminal_disposition_contradiction_is_inactive() -> Result<(), Box<dyn Error>> {
    let mut params = sample_contradiction_params()?;
    params.knowledge_state = KnowledgeState::Conflicted;

    // Refuted is inactive even with Conflicted knowledge state
    params.disposition = HypothesisDisposition::Refuted;
    let contra_refuted = Contradiction::new(params.clone())?;
    assert!(
        !contra_refuted.is_active(),
        "Refuted contradiction must be inactive"
    );

    // Resolved is inactive
    params.disposition = HypothesisDisposition::Resolved;
    let contra_resolved = Contradiction::new(params.clone())?;
    assert!(
        !contra_resolved.is_active(),
        "Resolved contradiction must be inactive"
    );

    // Superseded is inactive
    params.disposition = HypothesisDisposition::Superseded;
    let contra_superseded = Contradiction::new(params.clone())?;
    assert!(
        !contra_superseded.is_active(),
        "Superseded contradiction must be inactive"
    );

    // Indeterminate knowledge state with outcome Ok is active
    params.knowledge_state = KnowledgeState::Indeterminate;
    params.disposition = HypothesisDisposition::Live;
    params.outcome = RuntimeOutcome::Ok;
    let contra_indet = Contradiction::new(params)?;
    assert!(
        contra_indet.is_active(),
        "Indeterminate knowledge state contradiction must be active"
    );

    Ok(())
}

#[test]
fn test_finding_4_span_uncalibrated_does_not_launder_calibration() -> Result<(), Box<dyn Error>> {
    let cal = test_calibration()?;
    let calibrated = BeliefInterval::with_calibration(200_000, 800_000, cal)?;
    let uncalibrated = BeliefInterval::new(600_000, 700_000)?;
    let spanned = calibrated.span(&uncalibrated)?;
    assert_eq!(
        spanned.calibration_generation(),
        None,
        "Spanning with uncalibrated evidence must not launder uncalibrated bounds into a calibration generation"
    );
    Ok(())
}

#[test]
fn test_finding_5_decode_bounds_and_error_variants() -> Result<(), Box<dyn Error>> {
    let valid = sample_contradiction_params()?;

    // Domains under min (< 2) returns CorroborationRequired
    let mut enc_dom = CanonicalEncoder::new();
    enc_dom.text(CONTRADICTION_DOMAIN);
    enc_dom.text(&valid.contradiction_id);
    enc_dom.u64(valid.conflicting_evidence.len() as u64);
    for d in &valid.conflicting_evidence {
        enc_dom.digest(*d);
    }
    enc_dom.u64(1);
    enc_dom.text("domain:only_one");
    enc_dom.u64(valid.unresolved_worlds.len() as u64);
    for w in &valid.unresolved_worlds {
        enc_dom.text(w);
    }
    enc_dom.bool(false);
    enc_dom.text(&valid.statement);
    enc_dom.bool(false);
    valid.created_at.encode_canonical(&mut enc_dom);
    enc_dom.text(valid.knowledge_state.as_str());
    enc_dom.u8(1);
    enc_dom.u8(1);
    enc_dom.u8(1);

    let bytes_dom = enc_dom.finish();
    let mut dec_dom = CanonicalDecoder::new(&bytes_dom);
    assert_eq!(
        Contradiction::decode_canonical(&mut dec_dom).err(),
        Some(ContractError::CorroborationRequired),
        "Domains under min must reject with CorroborationRequired"
    );

    // Worlds under min (< 1) returns InvalidIdentifier
    let mut enc_world = CanonicalEncoder::new();
    enc_world.text(CONTRADICTION_DOMAIN);
    enc_world.text(&valid.contradiction_id);
    enc_world.u64(valid.conflicting_evidence.len() as u64);
    for d in &valid.conflicting_evidence {
        enc_world.digest(*d);
    }
    enc_world.u64(valid.failure_domains.len() as u64);
    for dom in &valid.failure_domains {
        enc_world.text(dom);
    }
    enc_world.u64(0);
    enc_world.bool(false);
    enc_world.text(&valid.statement);
    enc_world.bool(false);
    valid.created_at.encode_canonical(&mut enc_world);
    enc_world.text(valid.knowledge_state.as_str());
    enc_world.u8(1);
    enc_world.u8(1);
    enc_world.u8(1);

    let bytes_world = enc_world.finish();
    let mut dec_world = CanonicalDecoder::new(&bytes_world);
    assert_eq!(
        Contradiction::decode_canonical(&mut dec_world).err(),
        Some(ContractError::InvalidIdentifier),
        "Worlds under min must reject with InvalidIdentifier"
    );

    Ok(())
}

/// Hand-encodes a contradiction (no claim, no interval, Derived/Live/Indeterminate) with an
/// arbitrary knowledge-state spelling so the decoder's state parser can be probed directly.
fn contradiction_bytes_with_state_text(params: &ContradictionParams, state_text: &str) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(CONTRADICTION_DOMAIN);
    encoder.text(&params.contradiction_id);
    encoder.u64(params.conflicting_evidence.len() as u64);
    for digest in &params.conflicting_evidence {
        encoder.digest(*digest);
    }
    encoder.u64(params.failure_domains.len() as u64);
    for domain in &params.failure_domains {
        encoder.text(domain);
    }
    encoder.u64(params.unresolved_worlds.len() as u64);
    for world in &params.unresolved_worlds {
        encoder.text(world);
    }
    encoder.bool(false);
    encoder.text(&params.statement);
    encoder.bool(false);
    params.created_at.encode_canonical(&mut encoder);
    encoder.text(state_text);
    encoder.u8(2);
    encoder.u8(1);
    encoder.u8(6);
    encoder.finish()
}

#[test]
fn test_contradiction_knowledge_state_uses_canonical_parser_for_every_name() -> TestResult {
    let all_states = [
        (KnowledgeState::Known, "KSTATE-001", "known"),
        (KnowledgeState::Estimated, "KSTATE-002", "estimated"),
        (KnowledgeState::Unknown, "KSTATE-003", "unknown"),
        (KnowledgeState::Conflicted, "KSTATE-004", "conflicted"),
        (KnowledgeState::Stale, "KSTATE-005", "stale"),
        (
            KnowledgeState::NotObservable,
            "KSTATE-006",
            "not_observable",
        ),
        (KnowledgeState::Redacted, "KSTATE-007", "redacted"),
        (KnowledgeState::Indeterminate, "KSTATE-008", "indeterminate"),
        (
            KnowledgeState::NotApplicable,
            "KSTATE-009",
            "not_applicable",
        ),
    ];

    let mut base = sample_contradiction_params()?;
    base.claim_id = None;
    base.belief_interval = None;
    base.provenance = ProvenanceClass::Derived;
    base.disposition = HypothesisDisposition::Live;
    base.outcome = RuntimeOutcome::Indeterminate;

    for (state, id, name) in all_states {
        assert_eq!(state.as_str(), name);
        assert_eq!(state.id(), id);
        assert_eq!(KnowledgeState::from_name(name)?, state);
        assert_eq!(KnowledgeState::from_id(id)?, state);

        let mut params = base.clone();
        params.knowledge_state = state;
        let contra = Contradiction::new(params.clone())?;
        let bytes = contradiction_bytes_with_state_text(&params, name);
        assert_eq!(bytes, contra.to_canonical_bytes(), "{name} framing drifted");

        let decoded = Contradiction::from_canonical_bytes(&bytes)?;
        assert_eq!(decoded, contra, "{name} did not round-trip");
        assert_eq!(decoded.knowledge_state(), KnowledgeState::from_name(name)?);
        assert_eq!(decoded.knowledge_state(), KnowledgeState::from_id(id)?);
        assert_eq!(decoded.to_canonical_bytes(), bytes);
    }

    for bogus in [
        "",
        "KNOWN",
        "Known",
        "not-observable",
        "notobservable",
        "redacted ",
        " redacted",
        "KSTATE-007",
        "degraded",
        "null",
    ] {
        assert_eq!(
            KnowledgeState::from_name(bogus),
            Err(ContractError::InvalidIdentifier),
            "from_name must refuse {bogus:?}"
        );
        assert_eq!(
            Contradiction::from_canonical_bytes(&contradiction_bytes_with_state_text(&base, bogus)),
            Err(ContractError::InvalidIdentifier),
            "contradiction decoder must refuse {bogus:?}"
        );
    }

    for bogus_id in [
        "",
        "known",
        "KSTATE-000",
        "KSTATE-010",
        "kstate-001",
        "KSTATE-1",
    ] {
        assert_eq!(
            KnowledgeState::from_id(bogus_id),
            Err(ContractError::InvalidIdentifier),
            "from_id must refuse {bogus_id:?}"
        );
    }

    Ok(())
}

/// Every knowledge state, spelled out so a new variant forces this contract to be revisited.
const ALL_KNOWLEDGE_STATES: [KnowledgeState; 9] = [
    KnowledgeState::Known,
    KnowledgeState::Estimated,
    KnowledgeState::Unknown,
    KnowledgeState::Conflicted,
    KnowledgeState::Stale,
    KnowledgeState::NotObservable,
    KnowledgeState::Redacted,
    KnowledgeState::Indeterminate,
    KnowledgeState::NotApplicable,
];

/// Every runtime outcome.
const ALL_RUNTIME_OUTCOMES: [RuntimeOutcome; 7] = [
    RuntimeOutcome::Ok,
    RuntimeOutcome::Error,
    RuntimeOutcome::Cancelled,
    RuntimeOutcome::Panicked,
    RuntimeOutcome::Partial,
    RuntimeOutcome::Indeterminate,
    RuntimeOutcome::Refused,
];

#[test]
fn test_rkg27_unresolved_contradiction_stays_active_in_every_knowledge_state() -> TestResult {
    for disposition in [
        HypothesisDisposition::Live,
        HypothesisDisposition::Supported,
        HypothesisDisposition::Disfavored,
    ] {
        for knowledge_state in ALL_KNOWLEDGE_STATES {
            for outcome in ALL_RUNTIME_OUTCOMES {
                let mut params = sample_contradiction_params()?;
                params.disposition = disposition;
                params.knowledge_state = knowledge_state;
                params.outcome = outcome;
                let contra = Contradiction::new(params)?;
                assert!(
                    contra.is_active(),
                    "unresolved {disposition:?} contradiction in {} with outcome {outcome:?} must stay active",
                    knowledge_state.as_str()
                );
            }
        }
    }
    Ok(())
}

#[test]
fn test_rkg27_disfavored_redacted_is_as_active_as_disfavored_known() -> TestResult {
    let mut params = sample_contradiction_params()?;
    params.disposition = HypothesisDisposition::Disfavored;
    params.outcome = RuntimeOutcome::Ok;
    params.knowledge_state = KnowledgeState::Known;
    let known = Contradiction::new(params.clone())?;
    params.knowledge_state = KnowledgeState::Redacted;
    let redacted = Contradiction::new(params)?;
    assert!(known.is_active());
    assert_eq!(
        redacted.is_active(),
        known.is_active(),
        "redaction must not make a disfavored contradiction disappear"
    );
    Ok(())
}

#[test]
fn test_rkg27_terminal_disposition_retires_contradiction_in_every_knowledge_state() -> TestResult {
    for disposition in [
        HypothesisDisposition::Refuted,
        HypothesisDisposition::Resolved,
        HypothesisDisposition::Superseded,
    ] {
        for knowledge_state in ALL_KNOWLEDGE_STATES {
            for outcome in ALL_RUNTIME_OUTCOMES {
                let mut params = sample_contradiction_params()?;
                params.disposition = disposition;
                params.knowledge_state = knowledge_state;
                params.outcome = outcome;
                let contra = Contradiction::new(params)?;
                assert!(
                    !contra.is_active(),
                    "{disposition:?} contradiction in {} with outcome {outcome:?} must be retired",
                    knowledge_state.as_str()
                );
            }
        }
    }
    Ok(())
}
