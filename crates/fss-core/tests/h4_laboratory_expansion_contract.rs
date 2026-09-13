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
//!    - missing anchor lineage rejected (LaboratoryExpansionMissingAnchor)
//!    - degraded or indeterminate completeness rejected (EvidenceRequired)
//!    - empty intermediates, alternate systems, or oracle comparisons rejected (EvidenceRequired)
//!    - excess collection bounds rejected (ArithmeticOverflow)
//!    - routine hydration purpose or unavailable policy rejected (LaboratoryGrantRequired)
//!    - intermediate shape and byte counts malformed (LaboratoryExpansionShapeMalformed)
//!    - oracle comparison discrepancy/tolerance contradictions (LaboratoryExpansionToleranceMismatch)
//!    - duplicate alternate systems / undeclared oracle IDs (InvalidIdentifier, LaboratoryGrantRequired)
//! 4. Security against OOM: decode_canonical bounds-checks lengths against remaining input and
//!    hard limits before allocating Vec::with_capacity
//! 5. Mutant kills: M1 (validate in decode), M2 (digest check in decode), M4 (time interval check),
//!    M5 (anchor lineage check), M6 (purpose check), M7 (tolerance check), M10 (collection bounds)
//! 6. Effect premise taint: KnowledgeCell conversion carries LABORATORY_PROVENANCE_MARKER, refuses Known state
//! 7. Handle binding: delivery checks handle_id, subject_id, subject_digest, anchor, contract_basis, retention, access
//! 8. Byte-exact canonical round-trip serialization and digest determinism
//! 9. Zero unwrap, expect, or panic anywhere in test suite

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use fss_core::{
    AlternateSystem, BudgetVector, CanonicalDecode, CanonicalDecoder, CanonicalEncode,
    CanonicalEncoder, Completeness, ContentDigest, ContractBasis, ContractBasisRegistryBytes,
    ContractError, H4_CONTENT, H4_LEVEL_ID, H4_LEVEL_NAME, H4_OWNER, H4_SCHEMA,
    H4LaboratoryExpansion, H4LaboratoryExpansionParams, HandleAvailability, HydrationError,
    HydrationLevel, HydrationPurpose, HydrationRequest, HydrationRequestSpec, IntermediateArtifact,
    KnowledgeCell, KnowledgeState, LABORATORY_PROVENANCE_MARKER, LaboratoryAccess,
    LaboratoryArtifact, LaboratoryQuarantine, LedgerAnchor, MAX_H4_ALTERNATE_SYSTEMS,
    MAX_H4_IDENTIFIER_LEN, MAX_H4_INTERMEDIATES, MAX_H4_ORACLE_COMPARISONS, OracleComparison,
    ProvenanceClass, ReplayBundleRef, SemanticHandle, SemanticHandleSpec, SessionId, TimestampNs,
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

fn sample_expansion_for_handle(
    handle: &SemanticHandle,
) -> Result<H4LaboratoryExpansion, Box<dyn Error>> {
    let mut proof_roots = BTreeSet::new();
    proof_roots.insert(handle.subject_digest);
    proof_roots.insert(ContentDigest::sha256(b"secondary-anchor-proof-root"));

    let expansion = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: handle.handle_id.clone(),
        subject_id: handle.subject_id.clone(),
        subject_digest: handle.subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: sample_alternate_systems(),
        oracle_comparisons: sample_oracle_comparisons(),
        quarantine: sample_quarantine(),
        laboratory_access: handle.laboratory_access,
        purpose: HydrationPurpose::Qualification,
        anchor: handle.anchor.clone(),
        contract_basis: handle.contract_basis.clone(),
        estimated_cost: sample_budget()?,
        published_at: handle.published_at,
        retention_until: handle.retention_until,
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
    assert_eq!(H4_OWNER, "fss-agent-core");
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
    assert_eq!(expansion.expansion_digest(), digest);
    assert_ne!(digest.bytes(), [0u8; 32]);

    // Field accessors verify encapsulation
    assert_eq!(
        expansion.handle_id(),
        "semantic-handle:sha256:abcd1234abcd1234"
    );
    assert_eq!(expansion.subject_id(), "evidence:packet:cam-east:1042");
    assert_eq!(
        expansion.subject_digest(),
        ContentDigest::sha256(b"canonical-evidence-subject-data")
    );
    assert_eq!(
        expansion.laboratory_access(),
        LaboratoryAccess::QualificationOnly
    );
    assert_eq!(expansion.purpose(), HydrationPurpose::Qualification);
    assert_eq!(expansion.published_at(), TimestampNs(1_000_000_000));
    assert_eq!(expansion.retention_until(), TimestampNs(2_000_000_000));
    assert_eq!(expansion.completeness(), Completeness::Complete);
    assert_eq!(expansion.intermediates().len(), 2);
    assert_eq!(expansion.alternate_systems().len(), 1);
    assert_eq!(expansion.oracle_comparisons().len(), 1);

    // Validation passes
    expansion.validate()?;

    Ok(())
}

#[test]
fn test_h4_pinned_digest_literal() -> Result<(), Box<dyn Error>> {
    let expansion = sample_valid_expansion()?;
    let digest = expansion.expansion_digest();
    assert_eq!(digest.algorithm(), fss_core::DigestAlgorithm::Sha256);
    assert_eq!(
        digest.to_string(),
        "sha256:6858500da055f556ce3cbf2aa5f80a70ad5aff157715d99c541f6a5b9518e365"
    );
    Ok(())
}

#[test]
fn test_h4_to_hydration_artifact_packaging_and_realistic_transforms() -> Result<(), Box<dyn Error>>
{
    let expansion = sample_valid_expansion()?;

    // 1. Packaging with None transform
    let artifact = expansion.to_hydration_artifact(None)?;
    assert_eq!(artifact.level, HydrationLevel::H4);
    assert_eq!(
        artifact.content_type,
        "application/vnd.fss.h4-laboratory-expansion+canonical"
    );
    assert_eq!(artifact.completeness, Completeness::Complete);
    assert_eq!(artifact.applied_transform, None);
    assert!(!artifact.payload.is_empty());
    assert!(artifact.proof_roots.contains(&expansion.subject_digest()));
    artifact.verify()?;

    // Constitutional artifact gates
    assert!(artifact.is_quarantined());
    assert!(!artifact.is_production_safe());
    assert!(!artifact.may_authorize_effects());

    // 2. Packaging with realistic transform
    let blurred = expansion.to_hydration_artifact(Some("face_blur_v1".to_owned()))?;
    assert_eq!(blurred.applied_transform.as_deref(), Some("face_blur_v1"));
    blurred.verify()?;
    assert!(blurred.is_quarantined());
    assert!(!blurred.is_production_safe());
    assert!(!blurred.may_authorize_effects());

    // 3. Strongly typed LaboratoryArtifact wrapper
    let lab_art = LaboratoryArtifact::from_expansion(&expansion, Some("redact_pii".to_owned()))?;
    assert_eq!(
        lab_art.artifact.applied_transform.as_deref(),
        Some("redact_pii")
    );
    assert_eq!(lab_art.quarantine, *expansion.quarantine());
    assert!(lab_art.is_quarantined());
    assert!(!lab_art.is_production_safe());
    assert!(!lab_art.may_authorize_effects());

    // 4. Planted negative: transform exceeding max identifier length
    let too_long_transform = "x".repeat(MAX_H4_IDENTIFIER_LEN + 1);
    let err = expansion.to_hydration_artifact(Some(too_long_transform));
    let Err(HydrationError::Contract(ContractError::InvalidIdentifier)) = err else {
        return Err("Expected InvalidIdentifier for overly long applied_transform".into());
    };

    Ok(())
}

#[test]
fn test_h4_cannot_authorize_effects_or_claim_known_knowledge_state() -> Result<(), Box<dyn Error>> {
    let expansion = sample_valid_expansion()?;
    let anchor = sample_anchor();

    // 1. Convert to KnowledgeCell
    let cell = expansion.to_knowledge_cell(&anchor)?;
    assert_eq!(cell.knowledge_state, KnowledgeState::Estimated);
    assert_eq!(cell.provenance, ProvenanceClass::Derived);
    assert!(cell.is_laboratory_tainted());
    assert!(cell.statement.contains(LABORATORY_PROVENANCE_MARKER));
    assert!(
        !cell.is_irreversible_effect_premise(TimestampNs(1_500_000_000)),
        "Laboratory cell must NEVER serve as an irreversible-effect premise"
    );

    // 2. Planted bypass: cell with LABORATORY_PROVENANCE_MARKER attempting to claim Known state
    let rogue_cell = KnowledgeCell {
        claim_id: "claim:rogue-lab-known".to_owned(),
        statement: format!("{} rogue promotion to known", LABORATORY_PROVENANCE_MARKER),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![expansion.expansion_digest(), expansion.subject_digest()],
        contradictions: vec![],
        valid_until: Some(TimestampNs(2_000_000_000)),
        state_basis: None,
    };
    let err = rogue_cell.validate();
    let Err(ContractError::DerivedLayerAuthorityForbidden) = err else {
        return Err(
            "KnowledgeCell::validate must reject Known state when laboratory-tainted".into(),
        );
    };

    // 3. Planted bypass: even if constructed directly, is_irreversible_effect_premise must refuse
    assert!(
        !rogue_cell.is_irreversible_effect_premise(TimestampNs(1_500_000_000)),
        "is_irreversible_effect_premise must return false for any laboratory-tainted cell"
    );

    // 4. Planted negative: mismatched anchor lineage when converting to KnowledgeCell
    let mut different_anchor = sample_anchor();
    different_anchor.site_lineage = "site:other:site".to_owned();
    let diff_err = expansion.to_knowledge_cell(&different_anchor);
    let Err(ContractError::InvalidAnchorSuccessor) = diff_err else {
        return Err("to_knowledge_cell must reject mismatched anchor lineage".into());
    };

    Ok(())
}

#[test]
fn test_planted_negative_non_quarantined_rejected() -> Result<(), Box<dyn Error>> {
    let mut quarantine = sample_quarantine();
    quarantine.quarantined_from_production = false;

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
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::DerivedLayerAuthorityForbidden)
    );

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
        proof_roots: BTreeSet::new(),
        completeness: Completeness::Complete,
    });
    let Err(err1) = res1 else {
        return Err("Must reject empty proof roots".into());
    };
    assert_eq!(
        err1,
        HydrationError::Contract(ContractError::EvidenceRequired)
    );

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
        proof_roots: BTreeSet::from([other_root]),
        completeness: Completeness::Complete,
    });
    let Err(err2) = res2 else {
        return Err("Must reject proof roots without subject_digest".into());
    };
    assert_eq!(
        err2,
        HydrationError::Contract(ContractError::EvidenceRequired)
    );

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
        proof_roots: BTreeSet::from([subject_digest]),
        completeness: Completeness::Complete,
    });
    let Err(err3) = res3 else {
        return Err("Must reject self-referential proof roots without anchor".into());
    };
    assert_eq!(
        err3,
        HydrationError::Contract(ContractError::EvidenceRequired)
    );

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
        intermediates: vec![],
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
    assert_eq!(
        err1,
        HydrationError::Contract(ContractError::EvidenceRequired)
    );

    // 2. Empty alternate systems
    let res2 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: vec![],
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
    assert_eq!(
        err2,
        HydrationError::Contract(ContractError::EvidenceRequired)
    );

    // 3. Empty oracle comparisons
    let res3 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: sample_alternate_systems(),
        oracle_comparisons: vec![],
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
    assert_eq!(
        err3,
        HydrationError::Contract(ContractError::EvidenceRequired)
    );

    Ok(())
}

#[test]
fn test_planted_negative_inverted_time_interval_rejected() -> Result<(), Box<dyn Error>> {
    let subject_digest = ContentDigest::sha256(b"sub");
    let mut proof_roots = BTreeSet::new();
    proof_roots.insert(subject_digest);
    proof_roots.insert(ContentDigest::sha256(b"other"));

    // 1. Equal times (published_at == retention_until)
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
        published_at: TimestampNs(200),
        retention_until: TimestampNs(200),
        proof_roots: proof_roots.clone(),
        completeness: Completeness::Complete,
    });
    let Err(err1) = res1 else {
        return Err("Must reject equal published_at and retention_until".into());
    };
    assert_eq!(
        err1,
        HydrationError::Contract(ContractError::InvertedTimeInterval)
    );

    // 2. Inverted times (published_at > retention_until)
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
        published_at: TimestampNs(300),
        retention_until: TimestampNs(200),
        proof_roots,
        completeness: Completeness::Complete,
    });
    let Err(err2) = res2 else {
        return Err("Must reject published_at > retention_until".into());
    };
    assert_eq!(
        err2,
        HydrationError::Contract(ContractError::InvertedTimeInterval)
    );

    Ok(())
}

#[test]
fn test_planted_negative_missing_anchor_lineage_rejected() -> Result<(), Box<dyn Error>> {
    let subject_digest = ContentDigest::sha256(b"sub");
    let mut proof_roots = BTreeSet::new();
    proof_roots.insert(subject_digest);
    proof_roots.insert(ContentDigest::sha256(b"other"));

    let mut anchor = sample_anchor();
    anchor.site_lineage.clear();

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
        anchor,
        contract_basis: sample_basis(),
        estimated_cost: sample_budget()?,
        published_at: TimestampNs(100),
        retention_until: TimestampNs(200),
        proof_roots,
        completeness: Completeness::Complete,
    });

    let Err(err) = res else {
        return Err("Must reject expansion with empty anchor site lineage".into());
    };
    assert_eq!(
        err,
        HydrationError::Contract(ContractError::LaboratoryExpansionMissingAnchor)
    );

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
        laboratory_access: LaboratoryAccess::Unavailable,
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
        purpose: HydrationPurpose::Routine,
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

    // 3. Debugging purpose under QualificationOnly
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
        purpose: HydrationPurpose::Debugging,
        anchor: sample_anchor(),
        contract_basis: sample_basis(),
        estimated_cost: sample_budget()?,
        published_at: TimestampNs(100),
        retention_until: TimestampNs(200),
        proof_roots: proof_roots.clone(),
        completeness: Completeness::Complete,
    });
    let Err(err3) = res3 else {
        return Err("Must reject Debugging purpose under QualificationOnly".into());
    };
    assert_eq!(err3, HydrationError::LaboratoryGrantRequired);

    // 4. Routine purpose under QualificationOrDebugGrant
    let res4 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: sample_alternate_systems(),
        oracle_comparisons: sample_oracle_comparisons(),
        quarantine: sample_quarantine(),
        laboratory_access: LaboratoryAccess::QualificationOrDebugGrant,
        purpose: HydrationPurpose::Routine,
        anchor: sample_anchor(),
        contract_basis: sample_basis(),
        estimated_cost: sample_budget()?,
        published_at: TimestampNs(100),
        retention_until: TimestampNs(200),
        proof_roots,
        completeness: Completeness::Complete,
    });
    let Err(err4) = res4 else {
        return Err("Must reject Routine purpose under QualificationOrDebugGrant".into());
    };
    assert_eq!(err4, HydrationError::LaboratoryGrantRequired);

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
            completeness,
        });
        let Err(err) = res else {
            return Err("Must reject degraded/indeterminate completeness".into());
        };
        assert_eq!(
            err,
            HydrationError::Contract(ContractError::EvidenceRequired)
        );
    }

    Ok(())
}

#[test]
fn test_planted_negative_collection_bounds_rejected() -> Result<(), Box<dyn Error>> {
    let subject_digest = ContentDigest::sha256(b"sub");
    let mut proof_roots = BTreeSet::new();
    proof_roots.insert(subject_digest);
    proof_roots.insert(ContentDigest::sha256(b"other"));

    // 1. > MAX_H4_INTERMEDIATES
    let many_intermediates: Vec<_> = (0..=MAX_H4_INTERMEDIATES)
        .map(|i| IntermediateArtifact {
            stage_name: format!("stage_{i}"),
            content_type: "application/octet-stream".to_owned(),
            digest: ContentDigest::sha256(format!("digest_{i}").as_bytes()),
            shape: vec![1, 1],
            byte_count: 1,
        })
        .collect();
    let res1 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: many_intermediates,
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
        return Err("Must reject > MAX_H4_INTERMEDIATES".into());
    };
    assert_eq!(
        err1,
        HydrationError::Contract(ContractError::ArithmeticOverflow)
    );

    // 2. > MAX_H4_ALTERNATE_SYSTEMS
    let many_systems: Vec<_> = (0..=MAX_H4_ALTERNATE_SYSTEMS)
        .map(|i| AlternateSystem {
            system_id: format!("oracle:sys_{i}"),
            version: "1.0".to_owned(),
            framework: "fw".to_owned(),
            quarantine_digest: ContentDigest::sha256(b"qd"),
        })
        .collect();
    let res2 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: many_systems,
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
        return Err("Must reject > MAX_H4_ALTERNATE_SYSTEMS".into());
    };
    assert_eq!(
        err2,
        HydrationError::Contract(ContractError::ArithmeticOverflow)
    );

    // 3. > MAX_H4_ORACLE_COMPARISONS
    let systems = sample_alternate_systems();
    let oracle_id = systems[0].system_id.clone();
    let many_comparisons: Vec<_> = (0..=MAX_H4_ORACLE_COMPARISONS)
        .map(|i| OracleComparison {
            comparison_id: format!("cmp:{i}"),
            oracle_id: oracle_id.clone(),
            metric_name: "metric".to_owned(),
            discrepancy_score: 0.01,
            tolerance_threshold: 0.05,
            within_tolerance: true,
            oracle_version: "1.0".to_owned(),
        })
        .collect();
    let res3 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: systems,
        oracle_comparisons: many_comparisons,
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
        return Err("Must reject > MAX_H4_ORACLE_COMPARISONS".into());
    };
    assert_eq!(
        err3,
        HydrationError::Contract(ContractError::ArithmeticOverflow)
    );

    Ok(())
}

#[test]
fn test_planted_negative_intermediate_shape_and_byte_count_malformed() -> Result<(), Box<dyn Error>>
{
    let subject_digest = ContentDigest::sha256(b"sub");
    let mut proof_roots = BTreeSet::new();
    proof_roots.insert(subject_digest);
    proof_roots.insert(ContentDigest::sha256(b"other"));

    // 1. Zero dimension in shape
    let bad_intermediate_1 = IntermediateArtifact {
        stage_name: "stage".to_owned(),
        content_type: "application/octet-stream".to_owned(),
        digest: ContentDigest::sha256(b"data"),
        shape: vec![1, 0, 10],
        byte_count: 10,
    };
    let res1 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: vec![bad_intermediate_1],
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
        return Err("Must reject zero dimension in shape".into());
    };
    assert_eq!(
        err1,
        HydrationError::Contract(ContractError::LaboratoryExpansionShapeMalformed)
    );

    // 2. byte_count == u64::MAX
    let bad_intermediate_2 = IntermediateArtifact {
        stage_name: "stage".to_owned(),
        content_type: "application/octet-stream".to_owned(),
        digest: ContentDigest::sha256(b"data"),
        shape: vec![1, 10],
        byte_count: u64::MAX,
    };
    let res2 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: vec![bad_intermediate_2],
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
    let Err(err2) = res2 else {
        return Err("Must reject byte_count == u64::MAX".into());
    };
    assert_eq!(
        err2,
        HydrationError::Contract(ContractError::LaboratoryExpansionShapeMalformed)
    );

    // 3. byte_count == 0
    let bad_intermediate_3 = IntermediateArtifact {
        stage_name: "stage".to_owned(),
        content_type: "application/octet-stream".to_owned(),
        digest: ContentDigest::sha256(b"data"),
        shape: vec![1, 10],
        byte_count: 0,
    };
    let res3 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: vec![bad_intermediate_3],
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
        proof_roots,
        completeness: Completeness::Complete,
    });
    let Err(err3) = res3 else {
        return Err("Must reject byte_count == 0".into());
    };
    assert_eq!(
        err3,
        HydrationError::Contract(ContractError::LaboratoryExpansionShapeMalformed)
    );

    Ok(())
}

#[test]
fn test_planted_negative_duplicate_and_undeclared_system_ids_rejected() -> Result<(), Box<dyn Error>>
{
    let subject_digest = ContentDigest::sha256(b"sub");
    let mut proof_roots = BTreeSet::new();
    proof_roots.insert(subject_digest);
    proof_roots.insert(ContentDigest::sha256(b"other"));

    // 1. Duplicate alternate system IDs
    let dup_systems = vec![
        AlternateSystem {
            system_id: "oracle:dup-sys".to_owned(),
            version: "1.0".to_owned(),
            framework: "fw".to_owned(),
            quarantine_digest: ContentDigest::sha256(b"qd1"),
        },
        AlternateSystem {
            system_id: "oracle:dup-sys".to_owned(),
            version: "2.0".to_owned(),
            framework: "fw".to_owned(),
            quarantine_digest: ContentDigest::sha256(b"qd2"),
        },
    ];
    let res1 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: dup_systems,
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
        return Err("Must reject duplicate alternate system IDs".into());
    };
    assert_eq!(
        err1,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    // 2. Comparison referencing undeclared oracle system
    let undeclared_comparison = vec![OracleComparison {
        comparison_id: "cmp:1".to_owned(),
        oracle_id: "oracle:undeclared-system".to_owned(),
        metric_name: "psnr".to_owned(),
        discrepancy_score: 0.01,
        tolerance_threshold: 0.05,
        within_tolerance: true,
        oracle_version: "1.0".to_owned(),
    }];
    let res2 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: sample_alternate_systems(),
        oracle_comparisons: undeclared_comparison,
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
    let Err(err2) = res2 else {
        return Err("Must reject oracle comparison referencing undeclared system".into());
    };
    assert_eq!(
        err2,
        HydrationError::Contract(ContractError::InvalidIdentifier)
    );

    Ok(())
}

#[test]
fn test_planted_negative_oracle_comparison_discrepancy_and_tolerance_checks()
-> Result<(), Box<dyn Error>> {
    let subject_digest = ContentDigest::sha256(b"sub");
    let mut proof_roots = BTreeSet::new();
    proof_roots.insert(subject_digest);
    proof_roots.insert(ContentDigest::sha256(b"other"));
    let systems = sample_alternate_systems();
    let oracle_id = systems[0].system_id.clone();

    // 1. discrepancy <= tolerance, but within_tolerance = false (contradiction)
    let bad_cmp_1 = vec![OracleComparison {
        comparison_id: "cmp:mismatch1".to_owned(),
        oracle_id: oracle_id.clone(),
        metric_name: "psnr".to_owned(),
        discrepancy_score: 0.01,
        tolerance_threshold: 0.05,
        within_tolerance: false,
        oracle_version: "1.0".to_owned(),
    }];
    let res1 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: systems.clone(),
        oracle_comparisons: bad_cmp_1,
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
        return Err(
            "Must reject tolerance mismatch (within_tolerance false when <= threshold)".into(),
        );
    };
    assert_eq!(
        err1,
        HydrationError::Contract(ContractError::LaboratoryExpansionToleranceMismatch)
    );

    // 2. discrepancy > tolerance, but within_tolerance = true (contradiction)
    let bad_cmp_2 = vec![OracleComparison {
        comparison_id: "cmp:mismatch2".to_owned(),
        oracle_id: oracle_id.clone(),
        metric_name: "psnr".to_owned(),
        discrepancy_score: 0.10,
        tolerance_threshold: 0.05,
        within_tolerance: true,
        oracle_version: "1.0".to_owned(),
    }];
    let res2 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: systems.clone(),
        oracle_comparisons: bad_cmp_2,
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
        return Err(
            "Must reject tolerance mismatch (within_tolerance true when > threshold)".into(),
        );
    };
    assert_eq!(
        err2,
        HydrationError::Contract(ContractError::LaboratoryExpansionToleranceMismatch)
    );

    // 3. -0.0 in discrepancy_score rejected
    let neg_zero: f64 = f64::from_bits(0x8000_0000_0000_0000);
    let bad_cmp_3 = vec![OracleComparison {
        comparison_id: "cmp:negzero".to_owned(),
        oracle_id,
        metric_name: "psnr".to_owned(),
        discrepancy_score: neg_zero,
        tolerance_threshold: 0.05,
        within_tolerance: true,
        oracle_version: "1.0".to_owned(),
    }];
    let res3 = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:test".to_owned(),
        subject_id: "evidence:test".to_owned(),
        subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: systems,
        oracle_comparisons: bad_cmp_3,
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
        return Err("Must reject -0.0 discrepancy_score".into());
    };
    assert_eq!(
        err3,
        HydrationError::Contract(ContractError::LaboratoryExpansionToleranceMismatch)
    );

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
    encoder.u32(u32::MAX);
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
    encoder2.u32(50);
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
fn test_decode_canonical_validates_and_kills_mutant_r22_and_m1() -> Result<(), Box<dyn Error>> {
    let valid = sample_valid_expansion()?;

    // Construct a canonically serialized payload where all individual fields decode fine,
    // but the expansion-level invariant is violated: oracle_comparisons has an undeclared oracle_id,
    // and the expansion_digest matches this tampered content!
    let mut bad_cmps = sample_oracle_comparisons();
    bad_cmps[0].oracle_id = "oracle:undeclared-in-systems".to_owned();

    let mut encoder = CanonicalEncoder::new();
    encoder.text(H4_SCHEMA);
    encoder.text(valid.handle_id());
    encoder.text(valid.subject_id());
    encoder.digest(valid.subject_digest());
    valid.replay_bundle().encode_canonical(&mut encoder);

    encoder.u32(valid.intermediates().len() as u32);
    for item in valid.intermediates() {
        item.encode_canonical(&mut encoder);
    }
    encoder.u32(valid.alternate_systems().len() as u32);
    for item in valid.alternate_systems() {
        item.encode_canonical(&mut encoder);
    }
    encoder.u32(bad_cmps.len() as u32);
    for item in &bad_cmps {
        item.encode_canonical(&mut encoder);
    }

    encoder.bool(valid.quarantine().quarantined_from_production);
    encoder.digest(valid.quarantine().quarantine_receipt_digest);
    encoder.text(&valid.quarantine().isolation_boundary);
    encoder.digest(valid.quarantine().process_drain_witness);

    valid.laboratory_access().encode_canonical(&mut encoder);
    valid.purpose().encode_canonical(&mut encoder);
    valid.anchor().encode_canonical(&mut encoder);
    valid.contract_basis().encode_canonical(&mut encoder);

    let mut cost_enc = CanonicalEncoder::new();
    valid.estimated_cost().encode_to_canonical(&mut cost_enc);
    encoder.bytes(&cost_enc.finish());

    valid.published_at().encode_canonical(&mut encoder);
    valid.retention_until().encode_canonical(&mut encoder);

    encoder.u32(valid.proof_roots().len() as u32);
    for r in valid.proof_roots() {
        encoder.digest(*r);
    }
    encoder.u8(1); // Complete

    let computed_digest = ContentDigest::sha256(&encoder.clone().finish());
    encoder.digest(computed_digest);

    let payload = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&payload);

    let res = H4LaboratoryExpansion::decode_canonical(&mut decoder);
    let Err(err) = res else {
        return Err(
            "decode_canonical must invoke validate() and reject undeclared oracle system".into(),
        );
    };
    assert_eq!(err, ContractError::InvalidIdentifier);

    Ok(())
}

#[test]
fn test_decode_canonical_kills_mutant_m2_digest_tamper() -> Result<(), Box<dyn Error>> {
    let valid = sample_valid_expansion()?;

    let mut encoder = CanonicalEncoder::new();
    valid.encode_canonical(&mut encoder);
    let mut payload = encoder.finish();

    // Tamper with the last byte of expansion_digest
    let len = payload.len();
    payload[len - 1] ^= 0xFF;

    let mut decoder = CanonicalDecoder::new(&payload);
    let res = H4LaboratoryExpansion::decode_canonical(&mut decoder);
    let Err(err) = res else {
        return Err("decode_canonical must reject tampered expansion_digest".into());
    };
    assert_eq!(err, ContractError::DigestMismatch);

    Ok(())
}

#[test]
fn test_decode_canonical_rejects_duplicate_and_unsorted_proof_roots() -> Result<(), Box<dyn Error>>
{
    let valid = sample_valid_expansion()?;
    let r1 = ContentDigest::sha256(b"root-a");
    let r2 = ContentDigest::sha256(b"root-b");
    let (smaller, larger) = if r1 < r2 { (r1, r2) } else { (r2, r1) };

    // 1. Duplicate proof roots in stream
    let mut enc1 = CanonicalEncoder::new();
    enc1.text(H4_SCHEMA);
    enc1.text(valid.handle_id());
    enc1.text(valid.subject_id());
    enc1.digest(valid.subject_digest());
    valid.replay_bundle().encode_canonical(&mut enc1);
    enc1.u32(valid.intermediates().len() as u32);
    for item in valid.intermediates() {
        item.encode_canonical(&mut enc1);
    }
    enc1.u32(valid.alternate_systems().len() as u32);
    for item in valid.alternate_systems() {
        item.encode_canonical(&mut enc1);
    }
    enc1.u32(valid.oracle_comparisons().len() as u32);
    for item in valid.oracle_comparisons() {
        item.encode_canonical(&mut enc1);
    }
    enc1.bool(valid.quarantine().quarantined_from_production);
    enc1.digest(valid.quarantine().quarantine_receipt_digest);
    enc1.text(&valid.quarantine().isolation_boundary);
    enc1.digest(valid.quarantine().process_drain_witness);
    valid.laboratory_access().encode_canonical(&mut enc1);
    valid.purpose().encode_canonical(&mut enc1);
    valid.anchor().encode_canonical(&mut enc1);
    valid.contract_basis().encode_canonical(&mut enc1);
    let mut cost_enc1 = CanonicalEncoder::new();
    valid.estimated_cost().encode_to_canonical(&mut cost_enc1);
    enc1.bytes(&cost_enc1.finish());
    valid.published_at().encode_canonical(&mut enc1);
    valid.retention_until().encode_canonical(&mut enc1);

    enc1.u32(2);
    enc1.digest(smaller);
    enc1.digest(smaller);
    enc1.u8(1); // Complete
    enc1.digest(ContentDigest::sha256(b"digest"));

    let payload1 = enc1.finish();
    let mut dec1 = CanonicalDecoder::new(&payload1);
    let res1 = H4LaboratoryExpansion::decode_canonical(&mut dec1);
    let Err(err1) = res1 else {
        return Err("decode_canonical must reject duplicate proof roots".into());
    };
    assert_eq!(err1, ContractError::NonCanonicalOrdering);

    // 2. Unsorted (descending) proof roots in stream
    let mut enc2 = CanonicalEncoder::new();
    enc2.text(H4_SCHEMA);
    enc2.text(valid.handle_id());
    enc2.text(valid.subject_id());
    enc2.digest(valid.subject_digest());
    valid.replay_bundle().encode_canonical(&mut enc2);
    enc2.u32(valid.intermediates().len() as u32);
    for item in valid.intermediates() {
        item.encode_canonical(&mut enc2);
    }
    enc2.u32(valid.alternate_systems().len() as u32);
    for item in valid.alternate_systems() {
        item.encode_canonical(&mut enc2);
    }
    enc2.u32(valid.oracle_comparisons().len() as u32);
    for item in valid.oracle_comparisons() {
        item.encode_canonical(&mut enc2);
    }
    enc2.bool(valid.quarantine().quarantined_from_production);
    enc2.digest(valid.quarantine().quarantine_receipt_digest);
    enc2.text(&valid.quarantine().isolation_boundary);
    enc2.digest(valid.quarantine().process_drain_witness);
    valid.laboratory_access().encode_canonical(&mut enc2);
    valid.purpose().encode_canonical(&mut enc2);
    valid.anchor().encode_canonical(&mut enc2);
    valid.contract_basis().encode_canonical(&mut enc2);
    let mut cost_enc2 = CanonicalEncoder::new();
    valid.estimated_cost().encode_to_canonical(&mut cost_enc2);
    enc2.bytes(&cost_enc2.finish());
    valid.published_at().encode_canonical(&mut enc2);
    valid.retention_until().encode_canonical(&mut enc2);

    enc2.u32(2);
    enc2.digest(larger);
    enc2.digest(smaller);
    enc2.u8(1); // Complete
    enc2.digest(ContentDigest::sha256(b"digest"));

    let payload2 = enc2.finish();
    let mut dec2 = CanonicalDecoder::new(&payload2);
    let res2 = H4LaboratoryExpansion::decode_canonical(&mut dec2);
    let Err(err2) = res2 else {
        return Err("decode_canonical must reject descending proof roots".into());
    };
    assert_eq!(err2, ContractError::NonCanonicalOrdering);

    Ok(())
}

#[test]
fn test_from_canonical_bytes_rejects_trailing_bytes() -> Result<(), Box<dyn Error>> {
    let expansion = sample_valid_expansion()?;

    let mut encoder = CanonicalEncoder::new();
    expansion.encode_canonical(&mut encoder);
    let mut bytes = encoder.finish();

    // Successfully parses without trailing bytes
    let parsed = H4LaboratoryExpansion::from_canonical_bytes(&bytes)?;
    assert_eq!(parsed, expansion);

    // Appending a trailing byte must cause from_canonical_bytes to fail
    bytes.push(0xAA);
    let res = H4LaboratoryExpansion::from_canonical_bytes(&bytes);
    let Err(err) = res else {
        return Err("from_canonical_bytes must reject trailing bytes".into());
    };
    assert_eq!(err, ContractError::NonCanonicalOrdering);

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
    assert_eq!(expansion.expansion_digest(), decoded.expansion_digest());
    assert_eq!(expansion.computed_digest(), decoded.computed_digest());

    Ok(())
}

#[test]
fn test_semantic_handle_h4_delivery_integration_and_binding_checks() -> Result<(), Box<dyn Error>> {
    let levels = BTreeSet::from([
        HydrationLevel::H0,
        HydrationLevel::H1,
        HydrationLevel::H2,
        HydrationLevel::H3,
        HydrationLevel::H4,
    ]);

    let subject_digest = ContentDigest::sha256(b"canonical-evidence-subject-data");
    let handle = SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: sample_basis(),
        anchor: sample_anchor(),
        subject_id: "evidence:packet:cam-east:1042".to_owned(),
        subject_digest,
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

    let expansion = sample_expansion_for_handle(&handle)?;

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

    // 1. Successful delivery matches handle transform
    let artifact = handle.to_h4_laboratory_expansion(&request, now, &expansion)?;
    assert_eq!(artifact.level, HydrationLevel::H4);
    assert_eq!(
        artifact.applied_transform.as_deref(),
        Some("quarantined_laboratory_expansion")
    );
    assert!(artifact.proof_roots.contains(&handle.subject_digest));

    // 2. Handle binding checks: mismatched handle_id
    let mut bad_handle_params = H4LaboratoryExpansionParams {
        handle_id: "semantic-handle:other-rebound-id".to_owned(),
        subject_id: handle.subject_id.clone(),
        subject_digest: handle.subject_digest,
        replay_bundle: sample_replay_bundle(),
        intermediates: sample_intermediates(),
        alternate_systems: sample_alternate_systems(),
        oracle_comparisons: sample_oracle_comparisons(),
        quarantine: sample_quarantine(),
        laboratory_access: handle.laboratory_access,
        purpose: HydrationPurpose::Qualification,
        anchor: handle.anchor.clone(),
        contract_basis: handle.contract_basis.clone(),
        estimated_cost: sample_budget()?,
        published_at: handle.published_at,
        retention_until: handle.retention_until,
        proof_roots: expansion.proof_roots().clone(),
        completeness: Completeness::Complete,
    };
    let bad_expansion = H4LaboratoryExpansion::new(bad_handle_params.clone())?;
    let err = handle.to_h4_laboratory_expansion(&request, now, &bad_expansion);
    let Err(HydrationError::HandleRebound) = err else {
        return Err("Handle::to_h4_laboratory_expansion must reject mismatched handle_id".into());
    };

    // 3. Handle binding checks: mismatched subject_id
    bad_handle_params.handle_id = handle.handle_id.clone();
    bad_handle_params.subject_id = "evidence:other-subject".to_owned();
    let bad_exp2 = H4LaboratoryExpansion::new(bad_handle_params.clone())?;
    let err2 = handle.to_h4_laboratory_expansion(&request, now, &bad_exp2);
    let Err(HydrationError::Contract(ContractError::InvalidIdentifier)) = err2 else {
        return Err("Handle::to_h4_laboratory_expansion must reject mismatched subject_id".into());
    };

    // 4. Handle binding checks: expired now >= retention_until
    let expired_now = TimestampNs(2_000_000_000);
    let err_exp = handle.to_h4_laboratory_expansion(&request, expired_now, &expansion);
    let Err(HydrationError::LevelUnavailable) = err_exp else {
        return Err("Handle::to_h4_laboratory_expansion must reject expired delivery".into());
    };

    // 5. Handle binding checks: purpose mismatch
    let debug_request = HydrationRequest::publish(HydrationRequestSpec {
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
        purpose: HydrationPurpose::Debugging,
        continuation: None,
        issued_at: TimestampNs(1_500_000_000),
    })?;
    let err_purp = handle.to_h4_laboratory_expansion(&debug_request, now, &expansion);
    let Err(HydrationError::LaboratoryGrantRequired) = err_purp else {
        return Err("Handle::to_h4_laboratory_expansion must reject purpose mismatch".into());
    };

    Ok(())
}
