#![forbid(unsafe_code)]
//! Canonical decode contract for `CoverageWitness` domain sets (fss-8yptk N1).
//!
//! The authorized, observed, and excluded domain sets are encoded in strictly increasing order.
//! A decoder that accepted duplicate or unsorted entries would map several byte strings onto the
//! same witness, so re-encoding would not reproduce the input and the witness digest would no
//! longer identify one canonical encoding. Out-of-order entries must fail with the typed
//! `ContractError::NonCanonicalOrdering`, matching the `Contradiction` decoder convention.

use std::error::Error;

use fss_core::{
    CanonicalDecode, CanonicalEncode, CanonicalEncoder, ContractError, CoverageWitness,
    EventStoreEntry, LedgerAnchor,
};

type TestResult = Result<(), Box<dyn Error>>;

/// Encodes a witness field by field so tests can place arbitrary set entries on the wire.
fn encode_witness_with_sets(authorized: &[&str], observed: &[&str], excluded: &[&str]) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new();
    encode_witness_body(&mut encoder, authorized, observed, excluded);
    encoder.finish()
}

fn encode_witness_body(
    encoder: &mut CanonicalEncoder,
    authorized: &[&str],
    observed: &[&str],
    excluded: &[&str],
) {
    LedgerAnchor::genesis("site-coverage-canonical").encode_canonical(encoder);
    for set in [authorized, observed, excluded] {
        encoder.u64(set.len() as u64);
        for value in set {
            encoder.text(value);
        }
    }
    encoder.u8(1); // continuity: Continuous
    encoder.u8(1); // completeness: Complete
    encoder.text("no_unauthorized_intrusion");
    encoder.u8(1); // stop reason: Complete
    encoder.u64(1); // authorized generation
    encoder.u64(1); // observed generation
}

fn assert_non_canonical(bytes: &[u8], case: &str) -> TestResult {
    match CoverageWitness::from_canonical_bytes(bytes) {
        Err(ContractError::NonCanonicalOrdering) => Ok(()),
        other => Err(format!("{case}: expected Err(NonCanonicalOrdering), got {other:?}").into()),
    }
}

#[test]
fn canonical_witness_sets_decode_and_reencode_byte_identically() -> TestResult {
    let bytes = encode_witness_with_sets(&["a", "d"], &["a", "d"], &["b"]);
    let witness = CoverageWitness::from_canonical_bytes(&bytes)
        .map_err(|e| format!("canonical witness must decode: {e:?}"))?;
    assert_eq!(witness.authorized_domain.len(), 2);
    assert_eq!(witness.observed_domain.len(), 2);
    assert_eq!(witness.excluded_domain.len(), 1);
    assert_eq!(witness.canonical_bytes(), bytes);
    Ok(())
}

#[test]
fn empty_sets_remain_canonical() -> TestResult {
    let bytes = encode_witness_with_sets(&[], &[], &[]);
    let witness = CoverageWitness::from_canonical_bytes(&bytes)
        .map_err(|e| format!("empty-set witness must decode: {e:?}"))?;
    assert!(witness.authorized_domain.is_empty());
    assert_eq!(witness.canonical_bytes(), bytes);
    Ok(())
}

#[test]
fn duplicate_authorized_entries_are_rejected() -> TestResult {
    let bytes = encode_witness_with_sets(&["d", "d"], &["d"], &[]);
    assert_non_canonical(&bytes, "authorized {d, d}")
}

#[test]
fn unsorted_authorized_entries_are_rejected() -> TestResult {
    let bytes = encode_witness_with_sets(&["z", "d"], &["d"], &[]);
    assert_non_canonical(&bytes, "authorized {z, d}")
}

#[test]
fn duplicate_and_unsorted_observed_entries_are_rejected() -> TestResult {
    assert_non_canonical(
        &encode_witness_with_sets(&["d"], &["d", "d"], &[]),
        "observed {d, d}",
    )?;
    assert_non_canonical(
        &encode_witness_with_sets(&["d", "z"], &["z", "d"], &[]),
        "observed {z, d}",
    )
}

#[test]
fn duplicate_and_unsorted_excluded_entries_are_rejected() -> TestResult {
    assert_non_canonical(
        &encode_witness_with_sets(&["d"], &["d"], &["x", "x"]),
        "excluded {x, x}",
    )?;
    assert_non_canonical(
        &encode_witness_with_sets(&["d"], &["d"], &["y", "x"]),
        "excluded {y, x}",
    )
}

#[test]
fn out_of_order_entry_after_a_valid_prefix_is_rejected() -> TestResult {
    // The first two entries are ordered; only the third breaks the order.
    let bytes = encode_witness_with_sets(&["a", "c", "b"], &["a"], &[]);
    assert_non_canonical(&bytes, "authorized {a, c, b}")
}

#[test]
fn event_store_entry_rejects_embedded_non_canonical_witness() -> TestResult {
    let mut encoder = CanonicalEncoder::new();
    encoder.u8(5); // RegisterCoverageWitness
    encode_witness_body(&mut encoder, &["d", "d"], &["d"], &[]);
    let bytes = encoder.finish();
    match EventStoreEntry::from_canonical_bytes(&bytes) {
        Err(ContractError::NonCanonicalOrdering) => Ok(()),
        other => Err(format!("expected Err(NonCanonicalOrdering), got {other:?}").into()),
    }
}
