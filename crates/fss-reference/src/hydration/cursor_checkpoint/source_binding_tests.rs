#![forbid(unsafe_code)]
//! Canonical, monotone source requirements in the ordinary disclosure checkpoint.

use super::*;
use crate::ReferenceHydrationLimits;

type Value = Result<(), Box<dyn std::error::Error>>;

fn pins() -> SourceBindingPins {
    BTreeMap::from([
        (ContentDigest::sha256(b"descriptor:a"), ContentDigest::sha256(b"custody:a")),
        (ContentDigest::sha256(b"descriptor:b"), ContentDigest::sha256(b"custody:b")),
    ])
}

fn catalog_with_pins() -> ReferenceHydrationCatalog {
    let mut catalog = ReferenceHydrationCatalog::new();
    catalog.source_requirements = pins();
    catalog
}

fn sealed(body: Vec<u8>) -> Result<Vec<u8>, HydrationError> {
    let mut encoded = CanonicalEncoder::new();
    encoded.bytes(&body);
    encoded.digest(ContentDigest::sha256(&body));
    Ok(encoded.finish_checked()?)
}

fn raw(domain: &str, count: u64, entries: &[(ContentDigest, ContentDigest)]) -> Result<Vec<u8>, HydrationError> {
    let mut body = CanonicalEncoder::new();
    body.text(domain);
    body.i128(20);
    body.u64(0); // No cursors; the source count has its own ceiling.
    if domain == BOUND_DOMAIN {
        body.u64(count);
        for (descriptor, pin) in entries {
            body.digest(*descriptor);
            body.digest(*pin);
        }
    }
    sealed(body.finish_checked()?)
}

#[test]
fn source_free_checkpoints_keep_exact_v1_bytes_and_do_not_claim_historical_authority() -> Value {
    let catalog = ReferenceHydrationCatalog::new();
    let bytes = catalog.checkpoint_cursors(TimestampNs(20), 4096)?;
    assert_eq!(bytes, raw(DOMAIN, 0, &[])?);
    let decoded = CursorCheckpoint::decode(&bytes, 4096, 0)?;
    assert!(decoded.source_requirements.is_empty());
    let mut restored = ReferenceHydrationCatalog::new();
    restored.restore_cursor_checkpoint(&bytes, 4096, TimestampNs(20))?;
    assert!(restored.source_requirements.is_empty());
    Ok(())
}

#[test]
fn v2_roundtrip_retains_exact_requirements_without_any_descriptor_binding_payload_or_grant() -> Value {
    let catalog = catalog_with_pins();
    let bytes = catalog.checkpoint_cursors(TimestampNs(20), 4096)?;
    let entries: Vec<_> = pins().into_iter().collect();
    assert_eq!(bytes, raw(BOUND_DOMAIN, 2, &entries)?);
    let mut restored = ReferenceHydrationCatalog::new();
    restored.restore_cursor_checkpoint(&bytes, 4096, TimestampNs(21))?;
    assert_eq!(restored.source_requirements, pins());
    for (descriptor, pin) in pins() {
        assert_eq!(restored.source_binding_requirement(descriptor), Some(pin));
    }
    assert!(restored.descriptors.is_empty());
    assert!(restored.source_bindings.is_empty());
    assert!(restored.artifacts.is_empty());
    assert_eq!(restored.stored_payload_bytes(), 0);
    assert_eq!(restored.checkpoint_cursors(TimestampNs(20), 4096)?, bytes);
    Ok(())
}

#[test]
fn every_v2_truncation_bit_corruption_and_trailing_byte_refuses_without_catalog_mutation() -> Value {
    let bytes = catalog_with_pins().checkpoint_cursors(TimestampNs(20), 4096)?;
    let mut restored = ReferenceHydrationCatalog::new();
    let original = restored.checkpoint_cursors(TimestampNs(20), 4096)?;
    for length in 0..bytes.len() {
        assert!(restored.restore_cursor_checkpoint(&bytes[..length], 4096, TimestampNs(20)).is_err());
        assert_eq!(restored.checkpoint_cursors(TimestampNs(20), 4096)?, original);
    }
    for index in 0..bytes.len() {
        let mut corrupt = bytes.clone();
        corrupt[index] ^= 1;
        assert!(restored.restore_cursor_checkpoint(&corrupt, 4096, TimestampNs(20)).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(restored.restore_cursor_checkpoint(&trailing, 4096, TimestampNs(20)).is_err());
    assert_eq!(restored.checkpoint_cursors(TimestampNs(20), 4096)?, original);
    Ok(())
}

#[test]
fn duplicate_unsorted_oversized_and_noncanonical_empty_source_sets_refuse() -> Value {
    let entries: Vec<_> = pins().into_iter().collect();
    for bytes in [
        raw(BOUND_DOMAIN, 2, &[entries[0], entries[0]])?,
        raw(BOUND_DOMAIN, 2, &[entries[1], entries[0]])?,
        raw(BOUND_DOMAIN, u64::MAX, &[])?,
    ] {
        // The explicit cases below avoid interpreting a checksum as authorization.
        assert!(CursorCheckpoint::decode(&bytes, 4096, 0).is_err());
    }
    assert!(CursorCheckpoint::decode(&raw(BOUND_DOMAIN, 0, &[])?, 4096, 0).is_err());
    assert!(CursorCheckpoint::decode(&raw(BOUND_DOMAIN, 3, &entries)?, 4096, 0).is_err());
    assert!(CursorCheckpoint::decode(&raw("fss.hydration_cursor_checkpoint.v999", 0, &[])?, 4096, 0).is_err());
    Ok(())
}

#[test]
fn source_requirements_never_expire_or_rebind_in_a_successor() -> Value {
    let bytes = catalog_with_pins().checkpoint_cursors(TimestampNs(20), 4096)?;
    let prior = CursorCheckpoint::decode(&bytes, 4096, 0)?;
    let mut next = prior.clone();
    next.captured_at = TimestampNs(i128::MAX);
    next.validate_successor(&prior)?;
    for descriptor in pins().keys() {
        let mut missing = next.clone();
        missing.source_requirements.remove(descriptor);
        assert!(missing.validate_successor(&prior).is_err());
        let mut changed = next.clone();
        changed.source_requirements.insert(*descriptor, ContentDigest::sha256(b"weaker custody"));
        assert!(changed.validate_successor(&prior).is_err());
    }
    let empty = CursorCheckpoint::decode(&raw(DOMAIN, 0, &[])?, 4096, 0)?;
    assert!(empty.validate_successor(&prior).is_err());
    next.source_requirements.insert(ContentDigest::sha256(b"new descriptor"), ContentDigest::sha256(b"new custody"));
    next.validate_successor(&prior)?;
    Ok(())
}

#[test]
fn exact_byte_and_descriptor_ceilings_apply_independently_of_cursor_capacity() -> Value {
    let bytes = catalog_with_pins().checkpoint_cursors(TimestampNs(20), 4096)?;
    assert_eq!(catalog_with_pins().checkpoint_cursors(TimestampNs(20), bytes.len())?, bytes);
    assert!(catalog_with_pins().checkpoint_cursors(TimestampNs(20), bytes.len() - 1).is_err());
    let mut too_small = ReferenceHydrationCatalog::with_limits(ReferenceHydrationLimits {
        max_descriptors: 1, max_issued_cursors: 0, ..Default::default()
    });
    assert!(too_small.restore_cursor_checkpoint(&bytes, bytes.len(), TimestampNs(20)).is_err());
    assert!(too_small.source_requirements.is_empty());
    let mut exact = ReferenceHydrationCatalog::with_limits(ReferenceHydrationLimits {
        max_descriptors: 2, max_issued_cursors: 0, ..Default::default()
    });
    exact.restore_cursor_checkpoint(&bytes, bytes.len(), TimestampNs(20))?;
    assert_eq!(exact.source_requirements, pins());
    Ok(())
}

#[test]
fn trusted_restore_cannot_reset_pins_with_legacy_bytes_or_change_them_atomically() -> Value {
    let mut restored = catalog_with_pins();
    let before = restored.checkpoint_cursors(TimestampNs(20), 4096)?;
    assert!(restored.restore_cursor_checkpoint(&raw(DOMAIN, 0, &[])?, 4096, TimestampNs(20)).is_err());
    let mut entries: Vec<_> = pins().into_iter().collect();
    entries[0].1 = ContentDigest::sha256(b"changed original owner");
    assert!(restored.restore_cursor_checkpoint(&raw(BOUND_DOMAIN, 2, &entries)?, 4096, TimestampNs(20)).is_err());
    assert_eq!(restored.checkpoint_cursors(TimestampNs(20), 4096)?, before);
    Ok(())
}

#[test]
fn journal_disclosure_transition_checks_binding_pins_as_well_as_cursor_mutations() -> Value {
    let prior = CursorCheckpoint::decode(&catalog_with_pins().checkpoint_cursors(TimestampNs(20), 4096)?, 4096, 0)?;
    let session = SessionId::parse("session:source-recovery")?;
    prior.validate_disclosure(None, &session, None, None)?;
    prior.validate_disclosure(Some(&prior), &session, None, None)?;
    let mut weakened = prior.clone();
    weakened.source_requirements.clear();
    assert!(weakened.validate_disclosure(Some(&prior), &session, None, None).is_err());
    Ok(())
}
