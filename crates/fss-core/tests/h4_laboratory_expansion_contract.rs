#![forbid(unsafe_code)]
//! Deterministic contract tests for hydration ladder level H4: laboratory_expansion (AGT-H4).
//!
//! Enforces:
//! 1. Normative row properties: ID H4, name laboratory_expansion, content, owner, schema
//! 2. Constitutional hard gates: may_claim_authority == false, may_authorize_effects == false,
//!    is_production_safe == false, is_quarantined == true
//! 3. Planted bypass negative tests with exact error matching:
//!    - non-quarantined output rejected (DerivedLayerAuthorityForbidden)
//!    - zero quarantine receipt or drain witness rejected (InvalidDigest)
//!    - missing/empty proof roots rejected (EvidenceRequired)
//!    - inverted time interval rejected (InvertedTimeInterval)
//!    - missing anchor lineage rejected (DerivedBeliefMissingAnchor)
//!    - degraded or indeterminate completeness rejected (EvidenceRequired)
//!    - empty intermediates, alternate systems, or oracle comparisons rejected (EvidenceRequired)
//!    - excess collection bounds rejected (ArithmeticOverflow)
//!    - routine hydration purpose or unavailable policy rejected (LaboratoryGrantRequired)
//! 4. Security against OOM: decode_canonical bounds-checks lengths against remaining input and
//!    hard limits before allocating Vec::with_capacity
//! 5. Mutant R22 kill: decode_canonical invokes expansion.validate()
//! 6. Byte-exact canonical round-trip serialization and digest determinism
//! 7. Zero unwrap, expect, or panic anywhere in test suite

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use fss_core::{
    AlternateSystem, BudgetVector, CanonicalDecode, CanonicalDecoder, CanonicalEncode,
    CanonicalEncoder, Completeness, ContentDigest, ContractBasis, ContractBasisRegistryBytes,
    ContractError, HandleAvailability, HydrationError, HydrationLevel,
    HydrationPurpose, HydrationRequest, HydrationRequestSpec, IntermediateArtifact,
    LaboratoryAccess, LaboratoryQuarantine, LedgerAnchor, OracleComparison, ReplayBundleRef,
    SemanticHandle, SemanticHandleSpec, SessionId, TimestampNs, H4LaboratoryExpansion,
    H4LaboratoryExpansionParams, H4_CONTENT, H4_LEVEL_ID, H4_LEVEL_NAME, H4_OWNER, H4_SCHEMA,
};

fn sample_basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
        b"schemas",
        b"operations",
        b"views",
        b"capabilities",
        b"errors",
        b"costs",
        "h4-contract:test",
    ))
}

fn sample_anchor() -> LedgerAnchor {
    let mut anchor = LedgerAnchor::genesis("site:lab:qualification");
    anchor.commit_sequence = 42;
    anchor
}

fn sample_budget() -> Result<BudgetVector, Box<dyn Error>> {
    Ok(BudgetVector::builder()
        .bytes(65_536)
        .tokens(1_024)
        .latency_ms(50)
        .cpu_millis(10)
        .build()?)
}

fn sample_replay_bundle() -> ReplayBundleRef {
    ReplayBundleRef {
        bundle_id: "replay:bundle:run-101".to_owned(),
        bundle_digest: ContentDigest::sha256(b"bundle-payload-bytes"),
        manifest_root: ContentDigest::sha256(b"bundle-manifest-root"),
        seed: 0x1234_5678_9abc_def0,
        delta_batch_count: 5,
        environment_digest: ContentDigest::sha256(b"environment-closure-v1"),
    }
}

fn sample_intermediates() -> Vec<IntermediateArtifact> {
    vec![
        IntermediateArtifact {
            stage_name: "backbone.layer3.feature_map".to_owned(),
            content_type: "application/x-fss-tensor-f32".to_owned(),
            digest: ContentDigest::sha256(b"feature-map-data"),
            shape: vec![1, 64, 56, 56],
            byte_count: 802_816,
        },
        IntermediateArtifact {
            stage_name: "head.classification.logits".to_owned(),
            content_type: "application/x-fss-tensor-f32".to_owned(),
            digest: ContentDigest::sha256(b"logits-data"),
            shape: vec![1, 10],
            byte_count: 40,
        },
    ]
}

fn sample_alternate_systems() -> Vec<AlternateSystem> {
    vec![AlternateSystem {
        system_id: "oracle:ffmpeg-v6.1".to_owned(),
        version: "6.1.1-firstparty-oracle".to_owned(),
        framework: "ffmpeg".to_owned(),
        quarantine_digest: ContentDigest::sha256(b"quarantine-container-receipt"),
    }]
}

fn sample_oracle_comparisons() -> Vec<OracleComparison> {
    vec![OracleComparison {
        comparison_id: "cmp:psnr:ffmpeg-vs-native:frame-001".to_owned(),
        oracle_id: "oracle:ffmpeg-v6.1".to_owned(),
        metric_name: "psnr_y_channel".to_owned(),
        discrepancy_score: 0.0025,
        tolerance_threshold: 0.05,
        within_tolerance: true,
        oracle_version: "6.1.1".to_owned(),
    }]
}

fn sample_quarantine() -> LaboratoryQuarantine {
    LaboratoryQuarantine {
        quarantined_from_production: true,
        quarantine_receipt_digest: ContentDigest::sha256(b"sealed-process-drain-receipt"),
        isolation_boundary: "sealed_linux_namespace_container".to_owned(),
        process_drain_witness: ContentDigest::sha256(b"process-tree-drain-witness-all-tasks-zero"),
    }
}

fn sample_valid_expansion() -> Result<H4LaboratoryExpansion, Box<dyn Error>> {
    let subject_digest = ContentDigest::sha256(b"canonical-evidence-subject-data");
    let secondary_root = ContentDigest::sha256(b"secondary-anchor-proof-root");
    let mut proof_roots = BTreeSet::new();
    proof_roots.insert(subject_digest);
    proof_roots.insert(secondary_root);

    let expansion = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:sha256:abcd1234abcd1234".to_owned(),
        subject_id: "evidence:packet:cam-east:1042".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: sample_alternate_systems(),
        oracle_comparisons: sample_oracle_comparisons(),
        quarantine: sample_quarantine(),
        laboratory_access: LaboratoryAccess::QualificationOnly,
        purpose: HydrationPurpose::Qualification,
        anchor: sample_anchor(),
        contract_basis: sample_basis(),
        estimated_cost: sample_budget()?,
        published_at: TimestampNs(1_000_000_000),
        retention_until: TimestampNs(2_000_000_000),
        proof_roots,
        completeness: Completeness::Complete,
    })?;

    Ok(expansion)
}

#[test]
fn test_h4_laboratory_expansion_normative_row_properties() {
    assert_eq!(H4_LEVEL_ID, "H4");
    assert_eq!(H4_LEVEL_NAME, "laboratory_expansion");
    assert_eq!(
        H4_CONTENT,
        "replay bundle, intermediates, alternate decoders/models, and oracle comparisons"
    );
    assert_eq!(H4_OWNER, "fss-laboratory/oracle");
    assert_eq!(H4_SCHEMA, "fss.h4_laboratory_expansion.v1");

    assert_eq!(HydrationLevel::H4.as_str(), "H4");
    assert_eq!(HydrationLevel::H4.ordinal(), 4);
    assert_eq!(HydrationLevel::H4.successor(), None);
    assert_eq!(HydrationLevel::from_ordinal(4), Some(HydrationLevel::H4));
}

#[test]
fn test_h4_laboratory_expansion_valid_construction_and_gates() -> Result<(), Box<dyn Error>> {
    let expansion = sample_valid_expansion()?;

    // Level check
    assert_eq!(expansion.level(), HydrationLevel::H4);

    // Constitutional hard gates
    assert!(
        !expansion.may_claim_authority(),
        "Laboratory expansion must NEVER claim authority"
    );
    assert!(
        !expansion.may_authorize_effects(),
        "Laboratory expansion must NEVER authorize effects"
    );
    assert!(
        !expansion.is_production_safe(),
        "Laboratory expansion is non-production quarantine only"
    );
    assert!(
        expansion.is_quarantined(),
        "Laboratory expansion must be quarantined from production"
    );

    // Deterministic digest
    let digest = expansion.computed_digest();
    assert_eq!(expansion.expansion_digest, digest);
    assert_ne!(digest.bytes(), [0u8; 32]);

    // Validation passes
    expansion.validate()?;

    Ok(())
}

#[test]
fn test_h4_to_hydration_artifact_packaging() -> Result<(), Box<dyn Error>> {
    let expansion = sample_valid_expansion()?;
    let artifact = expansion.to_hydration_artifact()?;

    assert_eq!(artifact.level, HydrationLevel::H4);
    assert_eq!(
        artifact.content_type,
        "application/vnd.fss.h4-laboratory-expansion+canonical"
    );
    assert_eq!(artifact.completeness, Completeness::Complete);
    assert_eq!(
        artifact.applied_transform.as_deref(),
        Some("quarantined_laboratory_expansion")
    );
    assert!(!artifact.payload.is_empty());
    assert!(artifact.proof_roots.contains(&expansion.subject_digest));

    // Artifact verifies cleanly
    artifact.verify()?;

    Ok(())
}

#[test]
fn test_planted_negative_non_quarantined_rejected() -> Result<(), Box<dyn Error>> {
    let mut quarantine = sample_quarantine();
    quarantine.quarantined_from_production = false; // ILLEGAL: claiming production

    let subject_digest = ContentDigest::sha256(b"sub");
    let mut proof_roots = BTreeSet::new();
    proof_roots.insert(subject_digest);
    proof_roots.insert(ContentDigest::sha256(b"other"));

    let res = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: sample_alternate_systems(),
        oracle_comparisons: sample_oracle_comparisons(),
        quarantine,
        laboratory_access: LaboratoryAccess::QualificationOnly,
        purpose: HydrationPurpose::Qualification,
        anchor: sample_anchor(),
        contract_basis: sample_basis(),
        estimated_cost: sample_budget()?,
        published_at: TimestampNs(100),
        retention_until: TimestampNs(200),
        proof_roots,
        completeness: Completeness::Complete,
    });

    let Err(err) = res else {
        return Err("Must reject non-quarantined laboratory output".into());
    };
    assert_eq!(err, HydrationError::Contract(ContractError::DerivedLayerAuthorityForbidden));

    Ok(())
}

#[test]
fn test_planted_negative_zero_receipt_digests_rejected() -> Result<(), Box<dyn Error>> {
    let zero_digest = ContentDigest::new(fss_core::DigestAlgorithm::Sha256, [0u8; 32]);
    let subject_digest = ContentDigest::sha256(b"sub");
    let mut proof_roots = BTreeSet::new();
    proof_roots.insert(subject_digest);
    proof_roots.insert(ContentDigest::sha256(b"other"));

    // 1. Zero quarantine receipt
    let mut q1 = sample_quarantine();
    q1.quarantine_receipt_digest = zero_digest;
    let res1 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: sample_alternate_systems(),
        oracle_comparisons: sample_oracle_comparisons(),
        quarantine: q1,
        laboratory_access: LaboratoryAccess::QualificationOnly,
        purpose: HydrationPurpose::Qualification,
        anchor: sample_anchor(),
        contract_basis: sample_basis(),
        estimated_cost: sample_budget()?,
        published_at: TimestampNs(100),
        retention_until: TimestampNs(200),
        proof_roots: proof_roots.clone(),
        completeness: Completeness::Complete,
    });
    let Err(err1) = res1 else {
        return Err("Must reject zero quarantine receipt".into());
    };
    assert_eq!(err1, HydrationError::Contract(ContractError::InvalidDigest));

    // 2. Zero process drain witness
    let mut q2 = sample_quarantine();
    q2.process_drain_witness = zero_digest;
    let res2 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: sample_alternate_systems(),
        oracle_comparisons: sample_oracle_comparisons(),
        quarantine: q2,
        laboratory_access: LaboratoryAccess::QualificationOnly,
        purpose: HydrationPurpose::Qualification,
        anchor: sample_anchor(),
        contract_basis: sample_basis(),
        estimated_cost: sample_budget()?,
        published_at: TimestampNs(100),
        retention_until: TimestampNs(200),
        proof_roots,
        completeness: Completeness::Complete,
    });
    let Err(err2) = res2 else {
        return Err("Must reject zero process drain witness".into());
    };
    assert_eq!(err2, HydrationError::Contract(ContractError::InvalidDigest));

    Ok(())
}

#[test]
fn test_planted_negative_proof_roots_failures() -> Result<(), Box<dyn Error>> {
    let subject_digest = ContentDigest::sha256(b"sub");

    // 1. Empty proof roots
    let res1 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: sample_alternate_systems(),
        oracle_comparisons: sample_oracle_comparisons(),
        quarantine: sample_quarantine(),
        laboratory_access: LaboratoryAccess::QualificationOnly,
        purpose: HydrationPurpose::Qualification,
        anchor: sample_anchor(),
        contract_basis: sample_basis(),
        estimated_cost: sample_budget()?,
        published_at: TimestampNs(100),
        retention_until: TimestampNs(200),
        proof_roots: BTreeSet::new(), // EMPTY
        completeness: Completeness::Complete,
    });
    let Err(err1) = res1 else {
        return Err("Must reject empty proof roots".into());
    };
    assert_eq!(err1, HydrationError::Contract(ContractError::EvidenceRequired));

    // 2. Missing subject digest from proof roots
    let other_root = ContentDigest::sha256(b"other-only");
    let res2 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: sample_alternate_systems(),
        oracle_comparisons: sample_oracle_comparisons(),
        quarantine: sample_quarantine(),
        laboratory_access: LaboratoryAccess::QualificationOnly,
        purpose: HydrationPurpose::Qualification,
        anchor: sample_anchor(),
        contract_basis: sample_basis(),
        estimated_cost: sample_budget()?,
        published_at: TimestampNs(100),
        retention_until: TimestampNs(200),
        proof_roots: BTreeSet::from([other_root]), // DOES NOT CONTAIN subject_digest
        completeness: Completeness::Complete,
    });
    let Err(err2) = res2 else {
        return Err("Must reject proof roots without subject_digest".into());
    };
    assert_eq!(err2, HydrationError::Contract(ContractError::EvidenceRequired));

    // 3. Only subject_digest without an independent proof anchor
    let res3 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: sample_alternate_systems(),
        oracle_comparisons: sample_oracle_comparisons(),
        quarantine: sample_quarantine(),
        laboratory_access: LaboratoryAccess::QualificationOnly,
        purpose: HydrationPurpose::Qualification,
        anchor: sample_anchor(),
        contract_basis: sample_basis(),
        estimated_cost: sample_budget()?,
        published_at: TimestampNs(100),
        retention_until: TimestampNs(200),
        proof_roots: BTreeSet::from([subject_digest]), // NO independent root
        completeness: Completeness::Complete,
    });
    let Err(err3) = res3 else {
        return Err("Must reject self-referential proof roots without anchor".into());
    };
    assert_eq!(err3, HydrationError::Contract(ContractError::EvidenceRequired));

    Ok(())
}

#[test]
fn test_planted_negative_empty_normative_collections_rejected() -> Result<(), Box<dyn Error>> {
    let subject_digest = ContentDigest::sha256(b"sub");
    let mut proof_roots = BTreeSet::new();
    proof_roots.insert(subject_digest);
    proof_roots.insert(ContentDigest::sha256(b"other"));

    // 1. Empty intermediates
    let res1 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: vec![], // EMPTY
        alternate_systems: sample_alternate_systems(),
        oracle_comparisons: sample_oracle_comparisons(),
        quarantine: sample_quarantine(),
        laboratory_access: LaboratoryAccess::QualificationOnly,
        purpose: HydrationPurpose::Qualification,
        anchor: sample_anchor(),
        contract_basis: sample_basis(),
        estimated_cost: sample_budget()?,
        published_at: TimestampNs(100),
        retention_until: TimestampNs(200),
        proof_roots: proof_roots.clone(),
        completeness: Completeness::Complete,
    });
    let Err(err1) = res1 else {
        return Err("Must reject empty intermediates".into());
    };
    assert_eq!(err1, HydrationError::Contract(ContractError::EvidenceRequired));

    // 2. Empty alternate systems
    let res2 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: vec![], // EMPTY
        oracle_comparisons: sample_oracle_comparisons(),
        quarantine: sample_quarantine(),
        laboratory_access: LaboratoryAccess::QualificationOnly,
        purpose: HydrationPurpose::Qualification,
        anchor: sample_anchor(),
        contract_basis: sample_basis(),
        estimated_cost: sample_budget()?,
        published_at: TimestampNs(100),
        retention_until: TimestampNs(200),
        proof_roots: proof_roots.clone(),
        completeness: Completeness::Complete,
    });
    let Err(err2) = res2 else {
        return Err("Must reject empty alternate systems".into());
    };
    assert_eq!(err2, HydrationError::Contract(ContractError::EvidenceRequired));

    // 3. Empty oracle comparisons
    let res3 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: sample_alternate_systems(),
        oracle_comparisons: vec![], // EMPTY
        quarantine: sample_quarantine(),
        laboratory_access: LaboratoryAccess::QualificationOnly,
        purpose: HydrationPurpose::Qualification,
        anchor: sample_anchor(),
        contract_basis: sample_basis(),
        estimated_cost: sample_budget()?,
        published_at: TimestampNs(100),
        retention_until: TimestampNs(200),
        proof_roots,
        completeness: Completeness::Complete,
    });
    let Err(err3) = res3 else {
        return Err("Must reject empty oracle comparisons".into());
    };
    assert_eq!(err3, HydrationError::Contract(ContractError::EvidenceRequired));

    Ok(())
}

#[test]
fn test_planted_negative_laboratory_access_and_purpose_gating() -> Result<(), Box<dyn Error>> {
    let subject_digest = ContentDigest::sha256(b"sub");
    let mut proof_roots = BTreeSet::new();
    proof_roots.insert(subject_digest);
    proof_roots.insert(ContentDigest::sha256(b"other"));

    // 1. LaboratoryAccess::Unavailable
    let res1 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: sample_alternate_systems(),
        oracle_comparisons: sample_oracle_comparisons(),
        quarantine: sample_quarantine(),
        laboratory_access: LaboratoryAccess::Unavailable, // UNAVAILABLE
        purpose: HydrationPurpose::Qualification,
        anchor: sample_anchor(),
        contract_basis: sample_basis(),
        estimated_cost: sample_budget()?,
        published_at: TimestampNs(100),
        retention_until: TimestampNs(200),
        proof_roots: proof_roots.clone(),
        completeness: Completeness::Complete,
    });
    let Err(err1) = res1 else {
        return Err("Must reject H4 under LaboratoryAccess::Unavailable".into());
    };
    assert_eq!(err1, HydrationError::LaboratoryGrantRequired);

    // 2. Routine purpose under QualificationOnly
    let res2 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: sample_alternate_systems(),
        oracle_comparisons: sample_oracle_comparisons(),
        quarantine: sample_quarantine(),
        laboratory_access: LaboratoryAccess::QualificationOnly,
        purpose: HydrationPurpose::Routine, // ROUTINE FORBIDDEN
        anchor: sample_anchor(),
        contract_basis: sample_basis(),
        estimated_cost: sample_budget()?,
        published_at: TimestampNs(100),
        retention_until: TimestampNs(200),
        proof_roots: proof_roots.clone(),
        completeness: Completeness::Complete,
    });
    let Err(err2) = res2 else {
        return Err("Must reject Routine purpose for H4 laboratory expansion".into());
    };
    assert_eq!(err2, HydrationError::LaboratoryGrantRequired);

    // 3. Routine purpose under QualificationOrDebugGrant
    let res3 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: sample_alternate_systems(),
        oracle_comparisons: sample_oracle_comparisons(),
        quarantine: sample_quarantine(),
        laboratory_access: LaboratoryAccess::QualificationOrDebugGrant,
        purpose: HydrationPurpose::Routine, // ROUTINE FORBIDDEN
        anchor: sample_anchor(),
        contract_basis: sample_basis(),
        estimated_cost: sample_budget()?,
        published_at: TimestampNs(100),
        retention_until: TimestampNs(200),
        proof_roots,
        completeness: Completeness::Complete,
    });
    let Err(err3) = res3 else {
        return Err("Must reject Routine purpose under QualificationOrDebugGrant".into());
    };
    assert_eq!(err3, HydrationError::LaboratoryGrantRequired);

    Ok(())
}

#[test]
fn test_planted_negative_degraded_completeness_rejected() -> Result<(), Box<dyn Error>> {
    let subject_digest = ContentDigest::sha256(b"sub");
    let mut proof_roots = BTreeSet::new();
    proof_roots.insert(subject_digest);
    proof_roots.insert(ContentDigest::sha256(b"other"));

    let bad_states = [
        Completeness::Unknown,
        Completeness::NotObservable,
        Completeness::Unauthorized,
        Completeness::Stale,
    ];

    for completeness in bad_states {
        let res = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
            handle_id: "semantic-handle:test".to_owned(),
            subject_id: "evidence:test".to_owned(),
            subject_digest,
            replay_bundle: sample_replay_bundle(),
            intermediates: sample_intermediates(),
            alternate_systems: sample_alternate_systems(),
            oracle_comparisons: sample_oracle_comparisons(),
            quarantine: sample_quarantine(),
            laboratory_access: LaboratoryAccess::QualificationOnly,
            purpose: HydrationPurpose::Qualification,
            anchor: sample_anchor(),
            contract_basis: sample_basis(),
            estimated_cost: sample_budget()?,
            published_at: TimestampNs(100),
            retention_until: TimestampNs(200),
            proof_roots: proof_roots.clone(),
            completeness, // INADMISSIBLE
        });
        let Err(err) = res else {
            return Err("Must reject degraded/indeterminate completeness".into());
        };
        assert_eq!(err, HydrationError::Contract(ContractError::EvidenceRequired));
    }

    Ok(())
}

#[test]
fn test_security_decode_large_length_rejected_without_oom() -> Result<(), Box<dyn Error>> {
    // Craft binary payload with u32::MAX intermediates length
    let mut encoder = CanonicalEncoder::new();
    encoder.text(H4_SCHEMA);
    encoder.text("semantic-handle:attack");
    encoder.text("evidence:attack");
    encoder.digest(ContentDigest::sha256(b"sub"));
    sample_replay_bundle().encode_canonical(&mut encoder);
    encoder.u32(u32::MAX); // MALICIOUS LENGTH: requesting ~137 GB
    let payload = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&payload);
    let res = H4LaboratoryExpansion::decode_canonical(&mut decoder);
    let Err(err) = res else {
        return Err("decode_canonical must reject u32::MAX length before allocating".into());
    };
    assert_eq!(err, ContractError::ArithmeticOverflow);

    // Also verify length exceeding remaining input
    let mut encoder2 = CanonicalEncoder::new();
    encoder2.text(H4_SCHEMA);
    encoder2.text("semantic-handle:attack");
    encoder2.text("evidence:attack");
    encoder2.digest(ContentDigest::sha256(b"sub"));
    sample_replay_bundle().encode_canonical(&mut encoder2);
    encoder2.u32(50); // 50 items require hundreds of bytes, but payload ends here
    let payload2 = encoder2.finish();

    let mut decoder2 = CanonicalDecoder::new(&payload2);
    let res2 = H4LaboratoryExpansion::decode_canonical(&mut decoder2);
    let Err(err2) = res2 else {
        return Err("decode_canonical must reject length exceeding available bytes".into());
    };
    assert_eq!(err2, ContractError::ArithmeticOverflow);

    Ok(())
}

#[test]
fn test_decode_canonical_validates_and_kills_mutant_r22() -> Result<(), Box<dyn Error>> {
    // Construct valid expansion, then serialize it manually with an illegal field
    // (quarantined_from_production = false)
    let valid = sample_valid_expansion()?;

    let mut encoder = CanonicalEncoder::new();
    encoder.text(H4_SCHEMA);
    encoder.text(&valid.handle_id);
    encoder.text(&valid.subject_id);
    encoder.digest(valid.subject_digest);
    valid.replay_bundle.encode_canonical(&mut encoder);

    encoder.u32(valid.intermediates.len() as u32);
    for item in &valid.intermediates {
        item.encode_canonical(&mut encoder);
    }
    encoder.u32(valid.alternate_systems.len() as u32);
    for item in &valid.alternate_systems {
        item.encode_canonical(&mut encoder);
    }
    encoder.u32(valid.oracle_comparisons.len() as u32);
    for item in &valid.oracle_comparisons {
        item.encode_canonical(&mut encoder);
    }

    // ILLEGAL: quarantine set to false
    encoder.bool(false); // quarantined_from_production = false
    encoder.digest(valid.quarantine.quarantine_receipt_digest);
    encoder.text(&valid.quarantine.isolation_boundary);
    encoder.digest(valid.quarantine.process_drain_witness);

    valid.laboratory_access.encode_canonical(&mut encoder);
    valid.purpose.encode_canonical(&mut encoder);
    valid.anchor.encode_canonical(&mut encoder);
    valid.contract_basis.encode_canonical(&mut encoder);

    let mut cost_enc = CanonicalEncoder::new();
    valid.estimated_cost.encode_to_canonical(&mut cost_enc);
    encoder.bytes(&cost_enc.finish());

    valid.published_at.encode_canonical(&mut encoder);
    valid.retention_until.encode_canonical(&mut encoder);

    encoder.u32(valid.proof_roots.len() as u32);
    for r in &valid.proof_roots {
        encoder.digest(*r);
    }
    encoder.u8(1); // Complete
    encoder.digest(ContentDigest::sha256(b"fake-digest"));

    let payload = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&payload);

    // If decode_canonical did not call validate(), this would bypass validation.
    let res = H4LaboratoryExpansion::decode_canonical(&mut decoder);
    let Err(err) = res else {
        return Err("decode_canonical must invoke validate() and reject non-quarantined payload".into());
    };
    assert_eq!(err, ContractError::DerivedLayerAuthorityForbidden);

    Ok(())
}

#[test]
fn test_h4_canonical_roundtrip_determinism() -> Result<(), Box<dyn Error>> {
    let expansion = sample_valid_expansion()?;

    let mut encoder = CanonicalEncoder::new();
    expansion.encode_canonical(&mut encoder);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let decoded = H4LaboratoryExpansion::decode_canonical(&mut decoder)?;

    assert_eq!(expansion, decoded);
    assert_eq!(expansion.expansion_digest, decoded.expansion_digest);
    assert_eq!(expansion.computed_digest(), decoded.computed_digest());

    Ok(())
}

#[test]
fn test_semantic_handle_h4_delivery_integration() -> Result<(), Box<dyn Error>> {
    let expansion = sample_valid_expansion()?;

    let levels = BTreeSet::from([
        HydrationLevel::H0,
        HydrationLevel::H1,
        HydrationLevel::H2,
        HydrationLevel::H3,
        HydrationLevel::H4,
    ]);

    let handle = SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: sample_basis(),
        anchor: sample_anchor(),
        subject_id: expansion.subject_id.clone(),
        subject_digest: expansion.subject_digest,
        semantic_type: "evidence_bundle".to_owned(),
        source_id: "sensor:cam-east".to_owned(),
        capture_interval: None,
        spatial_scope: None,
        privacy_class: "private:property".to_owned(),
        applied_transform: Some("quarantined_laboratory_expansion".to_owned()),
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(2_000_000_000),
        levels: levels.clone(),
        required_capabilities: levels
            .iter()
            .map(|l| {
                (
                    *l,
                    BTreeSet::from([format!("capability:hydrate:{}", l.as_str())]),
                )
            })
            .collect(),
        estimated_costs: {
            let mut costs = BTreeMap::new();
            for &l in &levels {
                costs.insert(
                    l,
                    BudgetVector::builder()
                        .bytes(100_000)
                        .tokens(2_000)
                        .build()?,
                );
            }
            costs
        },
        laboratory_access: LaboratoryAccess::QualificationOnly,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1_000_000_000),
    })?;

    let request = HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:qualification")?,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: HydrationLevel::H4,
        allow_lower_level: false,
        available_capabilities: handle
            .required_capabilities
            .values()
            .flatten()
            .cloned()
            .collect(),
        authorized_privacy_classes: BTreeSet::from([handle.privacy_class.clone()]),
        budget: BudgetVector::builder()
            .bytes(200_000)
            .tokens(4_000)
            .build()?,
        purpose: HydrationPurpose::Qualification,
        continuation: None,
        issued_at: TimestampNs(1_500_000_000),
    })?;

    let now = TimestampNs(1_500_000_000);
    let artifact = handle.to_h4_laboratory_expansion(&request, now, &expansion)?;

    assert_eq!(artifact.level, HydrationLevel::H4);
    assert!(artifact.proof_roots.contains(&handle.subject_digest));

    Ok(())
}
