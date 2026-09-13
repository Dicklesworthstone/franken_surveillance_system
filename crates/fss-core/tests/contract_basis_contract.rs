#![forbid(unsafe_code)]
//! Normative contract and planted-bypass tests for ContractBasis (FSS-241).
//!
//! Verifies:
//! 1. Canonical encoding and bit-level stability against golden fixture `contract_basis_v1.bin`.
//! 2. Pinned freeze digests for reference contract basis and its canonical binary envelope.
//! 3. Registry-digest computation from raw byte slices.
//! 4. Fail-closed compatibility negotiation under semantic protocol `fss/1`.
//! 5. Stale-basis refusal semantics mapped to `ERR-AGENT-SESSION-STALE-001`.
//! 6. Exact-equality planted-bypass tests for corrupted magic, unknown version,
//!    truncated input, trailing bytes, checksum bit-flips, and mutated registry fields.

use std::error::Error;

use fss_core::contract_basis::{
    check_basis_freshness, check_compatibility, compute_registry_digests,
    decode_canonical_binary, encode_canonical_binary, negotiate_basis, reference_contract_basis,
    refuse_stale_anchor, validate_contract_basis, CompatibilityResult,
    ContractBasisError, ContractBasisRefusal, StaleBasisReason,
    CANONICAL_ONTOLOGY_GENERATION_ID, CANONICAL_PRODUCER_RELEASE_ID,
    CANONICAL_SEMANTIC_PROTOCOL, CONTRACT_BASIS_FORMAT_VERSION, CONTRACT_BASIS_MAGIC,
    MAX_CONTRACT_BASIS_BINARY_BYTES,
    REFERENCE_CAPABILITY_REGISTRY_DIGEST, REFERENCE_CONTRACT_BASIS_CANONICAL_DIGEST,
    REFERENCE_CONTRACT_BASIS_FREEZE_DIGEST, REFERENCE_CONTRACT_BASIS_GENERATION,
    REFERENCE_COST_REGISTRY_DIGEST, REFERENCE_ERROR_REGISTRY_DIGEST,
    REFERENCE_OPERATION_REGISTRY_DIGEST, REFERENCE_SCHEMA_CATALOG_DIGEST,
    REFERENCE_VIEW_REGISTRY_DIGEST, SCHEMA_CONTRACT_BASIS,
};
use fss_core::{
    CanonicalDecode, CanonicalEncode, ContentDigest, ContractBasis, ContractBasisRegistryBytes,
    LedgerAnchor, Sha256Hasher,
};

#[test]
fn test_reference_contract_basis_golden_fixture_and_pinned_digests() -> Result<(), Box<dyn Error>> {
    let basis = reference_contract_basis();

    // 1. Verify exact fields of the reference contract basis
    assert_eq!(basis.semantic_protocol, CANONICAL_SEMANTIC_PROTOCOL);
    assert_eq!(basis.ontology_generation_id, CANONICAL_ONTOLOGY_GENERATION_ID);
    assert_eq!(basis.producer_release_id, CANONICAL_PRODUCER_RELEASE_ID);
    assert_eq!(basis.accepted_nightly, None);

    // 2. Verify all six registry digests match pinned constants
    assert_eq!(
        basis.schema_catalog_digest.to_text(),
        REFERENCE_SCHEMA_CATALOG_DIGEST
    );
    assert_eq!(
        basis.operation_registry_digest.to_text(),
        REFERENCE_OPERATION_REGISTRY_DIGEST
    );
    assert_eq!(
        basis.view_registry_digest.to_text(),
        REFERENCE_VIEW_REGISTRY_DIGEST
    );
    assert_eq!(
        basis.capability_registry_digest.to_text(),
        REFERENCE_CAPABILITY_REGISTRY_DIGEST
    );
    assert_eq!(
        basis.error_registry_digest.to_text(),
        REFERENCE_ERROR_REGISTRY_DIGEST
    );
    assert_eq!(
        basis.cost_registry_digest.to_text(),
        REFERENCE_COST_REGISTRY_DIGEST
    );

    // 3. Verify inner canonical basis digest matches pinned constant
    let inner_digest = basis.basis_digest();
    assert_eq!(
        inner_digest.to_text(),
        REFERENCE_CONTRACT_BASIS_CANONICAL_DIGEST,
        "inner canonical basis digest must match pinned constant"
    );

    // 4. Encode to canonical binary envelope
    let binary = encode_canonical_binary(&basis)?;

    // 5. Compare against golden fixture file
    let fixture_bytes = include_bytes!("../../../tests/fixtures/contract_basis_v1.bin");
    assert_eq!(
        binary.as_slice(),
        fixture_bytes,
        "encoded canonical binary must exactly match golden fixture"
    );

    // 6. Verify binary freeze digest over envelope bytes
    let binary_digest = ContentDigest::sha256(&binary);
    assert_eq!(
        binary_digest.to_text(),
        REFERENCE_CONTRACT_BASIS_FREEZE_DIGEST,
        "binary freeze digest must match pinned constant"
    );

    // 7. Verify header format: magic + version
    assert_eq!(&binary[0..8], &CONTRACT_BASIS_MAGIC);
    let ver_bytes: [u8; 4] = binary[8..12].try_into()?;
    assert_eq!(u32::from_be_bytes(ver_bytes), CONTRACT_BASIS_FORMAT_VERSION);

    // 8. Decode back from golden fixture bytes and verify round-trip identity
    let decoded = decode_canonical_binary(fixture_bytes)?;
    assert_eq!(decoded, basis);

    Ok(())
}

#[test]
fn test_contract_basis_canonical_decode_trait_roundtrip() -> Result<(), Box<dyn Error>> {
    let basis = reference_contract_basis();
    let canonical_bytes = basis.try_canonical_bytes()?;
    let decoded = ContractBasis::from_canonical_bytes(&canonical_bytes)?;
    assert_eq!(decoded, basis);

    // Test with accepted nightly specified
    let mut basis_with_nightly = basis.clone();
    basis_with_nightly.accepted_nightly = Some("nightly-2026-08-31".to_owned());
    let bytes_nightly = basis_with_nightly.try_canonical_bytes()?;
    let decoded_nightly = ContractBasis::from_canonical_bytes(&bytes_nightly)?;
    assert_eq!(decoded_nightly, basis_with_nightly);
    assert_ne!(decoded_nightly.basis_digest(), basis.basis_digest());

    Ok(())
}

#[test]
fn test_registry_digest_computation_from_raw_bytes() -> Result<(), Box<dyn Error>> {
    let schema_catalog = b"test:schemas:v1";
    let operations = b"test:operations:v1";
    let views = b"test:views:v1";
    let capabilities = b"test:capabilities:v1";
    let errors = b"test:errors:v1";
    let costs = b"test:costs:v1";

    let spec = ContractBasisRegistryBytes::new(
        schema_catalog,
        operations,
        views,
        capabilities,
        errors,
        costs,
        "test:release:v1",
    );

    let digests = compute_registry_digests(spec);
    assert_eq!(
        digests.schema_catalog_digest,
        ContentDigest::sha256(schema_catalog)
    );
    assert_eq!(
        digests.operation_registry_digest,
        ContentDigest::sha256(operations)
    );
    assert_eq!(digests.view_registry_digest, ContentDigest::sha256(views));
    assert_eq!(
        digests.capability_registry_digest,
        ContentDigest::sha256(capabilities)
    );
    assert_eq!(digests.error_registry_digest, ContentDigest::sha256(errors));
    assert_eq!(digests.cost_registry_digest, ContentDigest::sha256(costs));

    let basis = digests.into_contract_basis("test:release:v1", None);
    assert_eq!(basis.semantic_protocol, CANONICAL_SEMANTIC_PROTOCOL);
    assert_eq!(basis.producer_release_id, "test:release:v1");
    assert_eq!(basis.schema_catalog_digest, digests.schema_catalog_digest);

    // Verify roundtrip encoding
    let encoded = encode_canonical_binary(&basis)?;
    let decoded = decode_canonical_binary(&encoded)?;
    assert_eq!(decoded, basis);

    Ok(())
}

#[test]
fn test_compatibility_negotiation_exact_match() -> Result<(), Box<dyn Error>> {
    let server_basis = reference_contract_basis();
    let client_basis = reference_contract_basis();

    let compat = check_compatibility(&server_basis, &client_basis);
    assert_eq!(compat, CompatibilityResult::Identical);

    let negotiated = negotiate_basis(&server_basis, &client_basis)?;
    assert_eq!(negotiated, server_basis);

    Ok(())
}

#[test]
fn test_compatibility_negotiation_with_notes() -> Result<(), Box<dyn Error>> {
    let server_basis = reference_contract_basis();
    let mut client_basis = reference_contract_basis();
    client_basis.producer_release_id = "fss:client-driver:v2".to_owned();

    let compat = check_compatibility(&server_basis, &client_basis);
    match compat {
        CompatibilityResult::CompatibleWithNotes { notes } => {
            assert!(!notes.is_empty());
            assert!(notes[0].contains("producer release divergence"));
        }
        other => return Err(format!("expected CompatibleWithNotes, got {other:?}").into()),
    }

    // Negotiation succeeds: server basis governs interpretation
    let negotiated = negotiate_basis(&server_basis, &client_basis)?;
    assert_eq!(negotiated, server_basis);

    Ok(())
}

#[test]
fn test_planted_bypass_incompatible_protocol() -> Result<(), Box<dyn Error>> {
    let server_basis = reference_contract_basis();
    let mut candidate = reference_contract_basis();
    candidate.semantic_protocol = "fss/2".to_owned();

    // Planted mutant check 1: basis digest changes
    assert_ne!(candidate.basis_digest(), server_basis.basis_digest());

    // Planted mutant check 2: validation rejects non-fss/1
    let val_err = validate_contract_basis(&candidate).err().ok_or("expected error")?;
    assert_eq!(val_err.error_id(), "ERR-AGENT-PROTOCOL-001");

    // Planted mutant check 3: binary encode fails closed
    let enc_err = encode_canonical_binary(&candidate).err().ok_or("expected error")?;
    assert_eq!(enc_err.error_id(), "ERR-AGENT-PROTOCOL-001");

    // Planted mutant check 4: check_compatibility refuses
    let compat = check_compatibility(&server_basis, &candidate);
    match compat {
        CompatibilityResult::Incompatible(refusal) => {
            assert_eq!(refusal.error_code(), "ERR-AGENT-PROTOCOL-001");
            match refusal {
                ContractBasisRefusal::IncompatibleProtocol { expected, actual } => {
                    assert_eq!(expected, "fss/1");
                    assert_eq!(actual, "fss/2");
                }
                other => return Err(format!("unexpected refusal variant: {other:?}").into()),
            }
        }
        other => return Err(format!("expected Incompatible, got {other:?}").into()),
    }

    // Planted mutant check 5: negotiate_basis fails closed
    let neg_err = negotiate_basis(&server_basis, &candidate).err().ok_or("expected error")?;
    assert_eq!(neg_err.error_id(), "ERR-AGENT-PROTOCOL-001");

    Ok(())
}

#[test]
fn test_planted_bypass_incompatible_registries() -> Result<(), Box<dyn Error>> {
    let server_basis = reference_contract_basis();
    let mutant_digest = ContentDigest::sha256(b"mutant:registry:drift");

    // 1. Incompatible schema catalog
    let mut b1 = server_basis.clone();
    b1.schema_catalog_digest = mutant_digest;
    assert_ne!(b1.basis_digest(), server_basis.basis_digest());
    let c1 = check_compatibility(&server_basis, &b1);
    match c1 {
        CompatibilityResult::Incompatible(refusal) => {
            assert_eq!(refusal.error_code(), "ERR-AGENT-PROTOCOL-001");
            assert!(matches!(refusal, ContractBasisRefusal::IncompatibleSchemaCatalog { .. }));
        }
        other => return Err(format!("expected Incompatible, got {other:?}").into()),
    }
    assert_eq!(
        negotiate_basis(&server_basis, &b1).err().ok_or("err")?.error_id(),
        "ERR-AGENT-PROTOCOL-001"
    );

    // 2. Incompatible operation registry
    let mut b2 = server_basis.clone();
    b2.operation_registry_digest = mutant_digest;
    assert_ne!(b2.basis_digest(), server_basis.basis_digest());
    let c2 = check_compatibility(&server_basis, &b2);
    match c2 {
        CompatibilityResult::Incompatible(refusal) => {
            assert_eq!(refusal.error_code(), "ERR-AGENT-PROTOCOL-001");
            assert!(matches!(refusal, ContractBasisRefusal::IncompatibleOperationRegistry { .. }));
        }
        other => return Err(format!("expected Incompatible, got {other:?}").into()),
    }

    // 3. Incompatible view registry
    let mut b3 = server_basis.clone();
    b3.view_registry_digest = mutant_digest;
    assert_ne!(b3.basis_digest(), server_basis.basis_digest());
    let c3 = check_compatibility(&server_basis, &b3);
    match c3 {
        CompatibilityResult::Incompatible(refusal) => {
            assert_eq!(refusal.error_code(), "ERR-AGENT-PROTOCOL-001");
            assert!(matches!(refusal, ContractBasisRefusal::IncompatibleViewRegistry { .. }));
        }
        other => return Err(format!("expected Incompatible, got {other:?}").into()),
    }

    // 4. Incompatible capability registry
    let mut b4 = server_basis.clone();
    b4.capability_registry_digest = mutant_digest;
    assert_ne!(b4.basis_digest(), server_basis.basis_digest());
    let c4 = check_compatibility(&server_basis, &b4);
    match c4 {
        CompatibilityResult::Incompatible(refusal) => {
            assert_eq!(refusal.error_code(), "ERR-AGENT-PROTOCOL-001");
            assert!(matches!(refusal, ContractBasisRefusal::IncompatibleCapabilityRegistry { .. }));
        }
        other => return Err(format!("expected Incompatible, got {other:?}").into()),
    }

    // 5. Incompatible error registry
    let mut b5 = server_basis.clone();
    b5.error_registry_digest = mutant_digest;
    assert_ne!(b5.basis_digest(), server_basis.basis_digest());
    let c5 = check_compatibility(&server_basis, &b5);
    match c5 {
        CompatibilityResult::Incompatible(refusal) => {
            assert_eq!(refusal.error_code(), "ERR-AGENT-PROTOCOL-001");
            assert!(matches!(refusal, ContractBasisRefusal::IncompatibleErrorRegistry { .. }));
        }
        other => return Err(format!("expected Incompatible, got {other:?}").into()),
    }

    // 6. Incompatible cost registry
    let mut b6 = server_basis.clone();
    b6.cost_registry_digest = mutant_digest;
    assert_ne!(b6.basis_digest(), server_basis.basis_digest());
    let c6 = check_compatibility(&server_basis, &b6);
    match c6 {
        CompatibilityResult::Incompatible(refusal) => {
            assert_eq!(refusal.error_code(), "ERR-AGENT-PROTOCOL-001");
            assert!(matches!(refusal, ContractBasisRefusal::IncompatibleCostRegistry { .. }));
        }
        other => return Err(format!("expected Incompatible, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_planted_bypass_incompatible_ontology() -> Result<(), Box<dyn Error>> {
    let server_basis = reference_contract_basis();
    let mut candidate = reference_contract_basis();
    candidate.ontology_generation_id = "ontology:custom:v9".to_owned();

    assert_ne!(candidate.basis_digest(), server_basis.basis_digest());
    let compat = check_compatibility(&server_basis, &candidate);
    match compat {
        CompatibilityResult::Incompatible(refusal) => {
            assert_eq!(refusal.error_code(), "ERR-AGENT-PROTOCOL-001");
            match refusal {
                ContractBasisRefusal::IncompatibleOntology { expected, actual } => {
                    assert_eq!(expected, CANONICAL_ONTOLOGY_GENERATION_ID);
                    assert_eq!(actual, "ontology:custom:v9");
                }
                other => return Err(format!("unexpected refusal: {other:?}").into()),
            }
        }
        other => return Err(format!("expected Incompatible, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_planted_bypass_stale_basis_tombstoned_registry() -> Result<(), Box<dyn Error>> {
    let current_basis = reference_contract_basis();
    let tombstoned_digest = ContentDigest::sha256(b"tombstoned:legacy:ops:v0");

    let mut candidate = reference_contract_basis();
    candidate.operation_registry_digest = tombstoned_digest;

    let res = check_basis_freshness(&candidate, &current_basis, &[tombstoned_digest]);
    let err = res.err().ok_or("expected stale basis error")?;
    assert_eq!(err.error_id(), "ERR-AGENT-SESSION-STALE-001");

    match err {
        ContractBasisError::StaleBasis { reason } => match reason {
            StaleBasisReason::TombstonedRegistryDigest { registry, tombstoned_digest: td } => {
                assert_eq!(registry, "operation");
                assert_eq!(td, tombstoned_digest);
            }
            other => return Err(format!("unexpected staleness reason: {other:?}").into()),
        },
        other => return Err(format!("unexpected error variant: {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_planted_bypass_stale_basis_superseded_ontology() -> Result<(), Box<dyn Error>> {
    let current_basis = reference_contract_basis();
    let mut candidate = reference_contract_basis();
    candidate.ontology_generation_id = "ontology:legacy:v0".to_owned();

    let res = check_basis_freshness(&candidate, &current_basis, &[]);
    let err = res.err().ok_or("expected stale basis error")?;
    assert_eq!(err.error_id(), "ERR-AGENT-SESSION-STALE-001");

    match err {
        ContractBasisError::StaleBasis { reason } => match reason {
            StaleBasisReason::SupersededGeneration { registry, current_generation, basis_generation } => {
                assert_eq!(registry, "ontology");
                assert_eq!(current_generation, CANONICAL_ONTOLOGY_GENERATION_ID);
                assert_eq!(basis_generation, "ontology:legacy:v0");
            }
            other => return Err(format!("unexpected staleness reason: {other:?}").into()),
        },
        other => return Err(format!("unexpected error variant: {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_planted_bypass_stale_anchor_refusal() -> Result<(), Box<dyn Error>> {
    // Case 1: valid_at is not strictly older than current (same epoch and sequence)
    let mut anchor_a = LedgerAnchor::genesis("site:delta");
    anchor_a.ledger_epoch = 1;
    anchor_a.commit_sequence = 100;
    let mut anchor_b = LedgerAnchor::genesis("site:delta");
    anchor_b.ledger_epoch = 1;
    anchor_b.commit_sequence = 100;
    let res1 = refuse_stale_anchor(&anchor_a, &anchor_b);
    let err1 = res1.err().ok_or("expected stale anchor error")?;
    assert_eq!(err1.error_id(), "ERR-AGENT-SESSION-STALE-001");

    // Case 2: valid_at is newer than current
    let mut anchor_future = LedgerAnchor::genesis("site:delta");
    anchor_future.ledger_epoch = 1;
    anchor_future.commit_sequence = 105;
    let res2 = refuse_stale_anchor(&anchor_future, &anchor_b);
    let err2 = res2.err().ok_or("expected stale anchor error")?;
    assert_eq!(err2.error_id(), "ERR-AGENT-SESSION-STALE-001");

    // Case 3: divergent site lineage
    let mut anchor_other_site = LedgerAnchor::genesis("site:divergent");
    anchor_other_site.ledger_epoch = 1;
    anchor_other_site.commit_sequence = 50;
    let res3 = refuse_stale_anchor(&anchor_other_site, &anchor_b);
    let err3 = res3.err().ok_or("expected lineage divergence error")?;
    assert_eq!(err3.error_id(), "ERR-AGENT-SESSION-STALE-001");

    // Case 4: strictly older anchor succeeds
    let mut anchor_older = LedgerAnchor::genesis("site:delta");
    anchor_older.ledger_epoch = 1;
    anchor_older.commit_sequence = 99;
    assert!(refuse_stale_anchor(&anchor_older, &anchor_b).is_ok());

    Ok(())
}

#[test]
fn test_planted_bypass_binary_bad_magic() -> Result<(), Box<dyn Error>> {
    let basis = reference_contract_basis();
    let mut bytes = encode_canonical_binary(&basis)?;

    // Tamper with magic header
    bytes[0..8].copy_from_slice(b"BADMAGIC");

    // Recompute trailer checksum so it bypasses checksum to reach magic check
    let payload_len = bytes.len() - 32;
    let (payload, _) = bytes.split_at(payload_len);
    let mut hasher = Sha256Hasher::new();
    hasher.update(SCHEMA_CONTRACT_BASIS.as_bytes());
    hasher.update(payload);
    let new_checksum = hasher.finalize()?;
    bytes[payload_len..].copy_from_slice(&new_checksum);

    let err = decode_canonical_binary(&bytes).err().ok_or("expected error")?;
    assert_eq!(err.error_id(), "ERR-SCHEMA-UNSUPPORTED-001");
    match err {
        ContractBasisError::BadMagic { expected, actual } => {
            assert_eq!(expected, CONTRACT_BASIS_MAGIC);
            assert_eq!(&actual, b"BADMAGIC");
        }
        other => return Err(format!("unexpected error variant: {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_planted_bypass_binary_unknown_version() -> Result<(), Box<dyn Error>> {
    let basis = reference_contract_basis();
    let mut bytes = encode_canonical_binary(&basis)?;

    // Tamper with format version (set to 99)
    bytes[8..12].copy_from_slice(&99u32.to_be_bytes());

    // Recompute trailer checksum
    let payload_len = bytes.len() - 32;
    let (payload, _) = bytes.split_at(payload_len);
    let mut hasher = Sha256Hasher::new();
    hasher.update(SCHEMA_CONTRACT_BASIS.as_bytes());
    hasher.update(payload);
    let new_checksum = hasher.finalize()?;
    bytes[payload_len..].copy_from_slice(&new_checksum);

    let err = decode_canonical_binary(&bytes).err().ok_or("expected error")?;
    assert_eq!(err.error_id(), "ERR-SCHEMA-UNSUPPORTED-001");
    match err {
        ContractBasisError::UnknownVersion { expected, actual } => {
            assert_eq!(expected, CONTRACT_BASIS_FORMAT_VERSION);
            assert_eq!(actual, 99);
        }
        other => return Err(format!("unexpected error variant: {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_planted_bypass_binary_corrupt_checksum() -> Result<(), Box<dyn Error>> {
    let fixture_bytes = include_bytes!("../../../tests/fixtures/contract_basis_v1.bin");
    let mut tampered = fixture_bytes.to_vec();

    // Flip 1 bit in trailing checksum byte
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;

    let err = decode_canonical_binary(&tampered).err().ok_or("expected checksum error")?;
    assert_eq!(err.error_id(), "ERR-NEG-CHECKSUM-MISMATCH-001");
    assert!(matches!(err, ContractBasisError::ChecksumMismatch { .. }));

    Ok(())
}

#[test]
fn test_planted_bypass_binary_truncated_input() -> Result<(), Box<dyn Error>> {
    let fixture_bytes = include_bytes!("../../../tests/fixtures/contract_basis_v1.bin");

    // Case 1: length below minimum envelope size (48 bytes)
    let too_short = &fixture_bytes[..40];
    let err1 = decode_canonical_binary(too_short).err().ok_or("expected error")?;
    assert_eq!(err1.error_id(), "ERR-SCHEMA-UNSUPPORTED-001");
    assert!(matches!(err1, ContractBasisError::Truncated { .. }));

    // Case 2: inner payload truncated relative to declared length
    let mut truncated_inner = fixture_bytes.to_vec();
    truncated_inner.drain(50..60); // remove 10 bytes from inner payload
    let payload_len = truncated_inner.len() - 32;
    let (payload, _) = truncated_inner.split_at(payload_len);
    let mut hasher = Sha256Hasher::new();
    hasher.update(SCHEMA_CONTRACT_BASIS.as_bytes());
    hasher.update(payload);
    let new_checksum = hasher.finalize()?;
    truncated_inner[payload_len..].copy_from_slice(&new_checksum);

    let err2 = decode_canonical_binary(&truncated_inner).err().ok_or("expected error")?;
    assert_eq!(err2.error_id(), "ERR-SCHEMA-UNSUPPORTED-001");
    assert!(matches!(err2, ContractBasisError::Truncated { .. }));

    Ok(())
}

#[test]
fn test_planted_bypass_binary_trailing_bytes() -> Result<(), Box<dyn Error>> {
    let basis = reference_contract_basis();
    let original = encode_canonical_binary(&basis)?;

    // Append extra byte inside the envelope before trailer
    let mut with_trailing = original.clone();
    // Insert an extra byte at end of inner payload (before trailer)
    let trailer_start = with_trailing.len() - 32;
    with_trailing.insert(trailer_start, 0xEE);
    // Recompute trailer
    let payload_len = with_trailing.len() - 32;
    let (payload, _) = with_trailing.split_at(payload_len);
    let mut hasher = Sha256Hasher::new();
    hasher.update(SCHEMA_CONTRACT_BASIS.as_bytes());
    hasher.update(payload);
    let new_checksum = hasher.finalize()?;
    with_trailing[payload_len..].copy_from_slice(&new_checksum);

    let err = decode_canonical_binary(&with_trailing).err().ok_or("expected error")?;
    assert_eq!(err.error_id(), "ERR-SCHEMA-UNSUPPORTED-001");
    assert!(matches!(err, ContractBasisError::TrailingBytes { .. }));

    Ok(())
}

#[test]
fn test_planted_bypass_binary_oversized() -> Result<(), Box<dyn Error>> {
    let oversized = vec![0u8; MAX_CONTRACT_BASIS_BINARY_BYTES + 1];
    let err = decode_canonical_binary(&oversized).err().ok_or("expected error")?;
    assert_eq!(err.error_id(), "ERR-SCHEMA-UNSUPPORTED-001");
    assert!(matches!(err, ContractBasisError::InputOversized { .. }));

    Ok(())
}

#[test]
fn test_planted_bypass_empty_producer_release_id() -> Result<(), Box<dyn Error>> {
    let mut basis = reference_contract_basis();
    basis.producer_release_id = "   ".to_owned();

    let err = validate_contract_basis(&basis).err().ok_or("expected error")?;
    assert_eq!(err.error_id(), "ERR-AGENT-PROTOCOL-001");

    let compat = check_compatibility(&reference_contract_basis(), &basis);
    match compat {
        CompatibilityResult::Incompatible(refusal) => {
            assert_eq!(refusal.error_code(), "ERR-AGENT-PROTOCOL-001");
            assert!(matches!(refusal, ContractBasisRefusal::InvalidProducerRelease { .. }));
        }
        other => return Err(format!("expected Incompatible, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_schema_identifier_constant() {
    assert_eq!(SCHEMA_CONTRACT_BASIS, "fss.agent_contract_basis.v1");
    assert_eq!(REFERENCE_CONTRACT_BASIS_GENERATION, "gen:fss1:reference-v1");
}
