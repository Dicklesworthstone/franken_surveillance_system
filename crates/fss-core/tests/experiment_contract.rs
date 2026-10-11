#![forbid(unsafe_code)]
//! Contract tests for the same-binary A/A and A/B experiment receipt
//! framework (FSS-196, bead fss-x4a.26.16): kind invariants enforced at
//! construction, honest comparison outcomes (never forced), determinism
//! alarms surfaced, canonical round-trip and digest stability.

use fss_core::experiment::{
    ComparisonOutcome, ExperimentError, ExperimentKind, ExperimentReceipt, ExperimentRun,
};
use fss_core::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest};

fn run(id: &str, variant: Option<&str>, binary: u8, outcome: Option<u8>) -> ExperimentRun {
    ExperimentRun {
        run_id: id.to_string(),
        variant_id: variant.map(str::to_string),
        binary_identity: ContentDigest::sha256(&[binary]),
        inputs_digest: ContentDigest::sha256(b"inputs"),
        schedule_seed: Some(7),
        outcome_digest: outcome.map(|o| ContentDigest::sha256(&[o])),
    }
}

#[test]
fn aa_identical_outcomes_prove_determinism() {
    let a = run("run-1", None, 1, Some(42));
    let b = run("run-2", None, 1, Some(42));
    let receipt = ExperimentReceipt::compare("exp:1", ExperimentKind::Aa, a, b).expect("compare");
    assert_eq!(receipt.comparison, ComparisonOutcome::Identical);
    assert!(!receipt.is_determinism_alarm());
}

#[test]
fn aa_divergent_outcomes_are_an_alarm_not_a_pass() {
    let a = run("run-1", None, 1, Some(42));
    let b = run("run-2", None, 1, Some(43));
    let receipt = ExperimentReceipt::compare("exp:1", ExperimentKind::Aa, a, b).expect("compare");
    assert_eq!(receipt.comparison, ComparisonOutcome::Divergent);
    assert!(
        receipt.is_determinism_alarm(),
        "same-binary divergence is a determinism alarm"
    );
}

#[test]
fn aa_with_different_binaries_is_refused_as_mislabeled() {
    let a = run("run-1", None, 1, Some(42));
    let b = run("run-2", None, 2, Some(42));
    let r = ExperimentReceipt::compare("exp:1", ExperimentKind::Aa, a, b);
    assert_eq!(r, Err(ExperimentError::AaRequiresSameBinary));
}

#[test]
fn ab_requires_distinct_labeled_variants() {
    let a = run("run-1", Some("control"), 1, Some(42));
    let b = run("run-2", Some("control"), 2, Some(42));
    let r = ExperimentReceipt::compare("exp:1", ExperimentKind::Ab, a, b);
    assert_eq!(r, Err(ExperimentError::AbRequiresDistinctVariants));
    let a = run("run-1", None, 1, Some(42));
    let b = run("run-2", Some("treatment"), 2, Some(42));
    let r = ExperimentReceipt::compare("exp:1", ExperimentKind::Ab, a, b);
    assert_eq!(r, Err(ExperimentError::AbRequiresVariantLabels));
}

#[test]
fn ab_comparison_records_divergence_without_judgment() {
    let a = run("run-1", Some("control"), 1, Some(42));
    let b = run("run-2", Some("treatment"), 1, Some(43));
    let receipt = ExperimentReceipt::compare("exp:1", ExperimentKind::Ab, a, b).expect("compare");
    assert_eq!(receipt.comparison, ComparisonOutcome::Divergent);
    assert!(!receipt.is_determinism_alarm());
}

#[test]
fn indeterminate_runs_never_force_a_verdict() {
    let a = run("run-1", None, 1, Some(42));
    let b = run("run-2", None, 1, None);
    let receipt = ExperimentReceipt::compare("exp:1", ExperimentKind::Aa, a, b).expect("compare");
    assert_eq!(receipt.comparison, ComparisonOutcome::Indeterminate);
    let a = run("run-1", None, 1, None);
    let b = run("run-2", None, 1, None);
    let receipt = ExperimentReceipt::compare("exp:2", ExperimentKind::Aa, a, b).expect("compare");
    assert_eq!(receipt.comparison, ComparisonOutcome::Indeterminate);
}

#[test]
fn receipt_digest_is_deterministic_and_canonical_roundtrip() {
    let a = run("run-1", None, 1, Some(42));
    let b = run("run-2", None, 1, Some(42));
    let r1 = ExperimentReceipt::compare("exp:1", ExperimentKind::Aa, a.clone(), b.clone()).expect("c1");
    let r2 = ExperimentReceipt::compare("exp:1", ExperimentKind::Aa, a, b).expect("c2");
    assert_eq!(r1.receipt_digest, r2.receipt_digest, "same inputs, same receipt digest");
    assert_eq!(r1.computed_digest(), r1.receipt_digest, "stored digest is the computed digest");

    // The kind codec round-trips in isolation (the full receipt leads with
    // the experiment id; field order is pinned by the module's encoder).
    let mut encoder = CanonicalEncoder::new();
    ExperimentKind::Ab.encode_canonical(&mut encoder);
    let bytes = encoder.finish();
    let kind = ExperimentKind::decode_canonical(&mut CanonicalDecoder::new(&bytes)).expect("kind decodes");
    assert_eq!(kind, ExperimentKind::Ab);
    assert!(ExperimentKind::decode_canonical(&mut CanonicalDecoder::new(&[9u8])).is_err());
}

#[test]
fn schema_identity_is_registered() {
    let receipt = ExperimentReceipt::compare(
        "exp:1",
        ExperimentKind::Aa,
        run("run-1", None, 1, Some(1)),
        run("run-2", None, 1, Some(1)),
    )
    .expect("compare");
    assert_eq!(ExperimentReceipt::SCHEMA, "fss.experiment_receipt.v1");
}
