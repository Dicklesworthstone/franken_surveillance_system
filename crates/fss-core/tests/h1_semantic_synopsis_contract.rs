#![forbid(unsafe_code)]
//! Deterministic contract tests for hydration ladder level H1: semantic_synopsis (AGT-H1, fss-x4a.30.82.13).
//!
//! Enforces:
//! 1. Normative row identity and properties from registries/AGENT_ABSTRACTIONS.md
//! 2. Content completeness: typed facts, knowledge states, provenance, contradictions, quality, and omissions
//! 3. Prohibition against raw payloads, decoded media, decision crops/artifacts, and laboratory bundles
//! 4. Invariant enforcement & planted bypasses (zero digest, expired retention, non-canonical facts,
//!    undeclared provenance, omission=None, prohibited classifications, trailing bytes)
//! 5. Deterministic canonical binary encoding & decoding with exact roundtrip and trailing bytes refusal
//! 6. Conversion to canonical KnowledgeCell representations with exact source evidence (no synthetic roots)
//! 7. Integration with SemanticHandle materialization

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use fss_core::{
    BeliefInterval, BudgetVector, CanonicalDecode, CanonicalDecoder, CanonicalEncode,
    CanonicalEncoder, Completeness, ContentDigest, ContractBasis, ContractBasisRegistryBytes,
    ContractError, Contradiction, ContradictionParams, DigestAlgorithm, Generation, H1_CONTENT,
    H1_LEVEL_ID, H1_LEVEL_NAME, H1_OWNER, H1_SCHEMA, H1ContentSpec, H1SemanticSynopsis,
    H1SynopsisParams, HandleAvailability, HydrationArtifact, HydrationError, HydrationLevel,
    HypothesisDisposition, KnowledgeState, KnowledgeStateBasis, LaboratoryAccess, LedgerAnchor,
    MAX_H1_CAPABILITIES, MAX_H1_CONTRADICTIONS, MAX_H1_FACTS, MAX_H1_KNOWLEDGE_STATES,
    MAX_H1_OMISSIONS, MAX_H1_PROVENANCE_CLASSES, OmissionReason, ProvenanceClass,
    REDACTED_STATEMENT_MARKER, RedactionMarker, RedactionReason, RuntimeOutcome, SemanticHandle,
    SemanticHandleSpec, StaleBasis, SynopsisClassification, SynopsisQuality, TimestampNs,
    WorldFact, WorldFactKind,
};

fn sample_basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
        b"schemas",
        b"operations",
        b"views",
        b"capabilities",
        b"errors",
        b"costs",
        "fss/1",
    ))
}

fn sample_anchor(seq: u64) -> LedgerAnchor {
    let mut a = LedgerAnchor::genesis("site:us-east:h1");
    a.commit_sequence = seq;
    a
}

fn sample_budget() -> Result<BudgetVector, Box<dyn Error>> {
    let b = BudgetVector::builder()
        .latency_ms(10)
        .tokens(128)
        .bytes(1024)
        .cpu_millis(2)
        .privacy_exposure(0.1)
        .build()?;
    Ok(b)
}

fn sample_contradiction() -> Result<Contradiction, Box<dyn Error>> {
    let d1 = ContentDigest::sha256(b"optical-observation");
    let d2 = ContentDigest::sha256(b"radar-negative-witness");
    let params = ContradictionParams {
        contradiction_id: "contra:test:001".to_string(),
        conflicting_evidence: BTreeSet::from([d1, d2]),
        failure_domains: BTreeSet::from([
            "domain:optical:cam1".to_string(),
            "domain:rf:radar".to_string(),
        ]),
        unresolved_worlds: BTreeSet::from([
            "world:person_present".to_string(),
            "world:empty_scene".to_string(),
        ]),
        claim_id: Some("claim:presence:zone_a".to_string()),
        statement: "Optical sensor reports presence while RF radar reports clear sector"
            .to_string(),
        belief_interval: Some(BeliefInterval::new(100_000, 900_000)?),
        created_at: TimestampNs(1_000_000),
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::Derived,
        disposition: HypothesisDisposition::Live,
        outcome: RuntimeOutcome::Indeterminate,
    };
    let c = Contradiction::new(params)?;
    Ok(c)
}

fn sample_facts() -> Result<Vec<WorldFact>, Box<dyn Error>> {
    let f1 = WorldFact::new(
        "fact:device:cam01",
        WorldFactKind::Device,
        sample_anchor(1),
        "Camera 01 active and calibrated",
        ProvenanceClass::Observed,
        ContentDigest::sha256(b"device:cam01:calib"),
        Generation(1),
    )?;
    let f2 = WorldFact::new(
        "fact:geometry:zone_a",
        WorldFactKind::Geometry,
        sample_anchor(1),
        "Zone A boundary verified",
        ProvenanceClass::Derived,
        ContentDigest::sha256(b"geom:zone_a"),
        Generation(1),
    )?;
    Ok(vec![f1, f2])
}

fn sample_h1_params() -> Result<H1SynopsisParams, Box<dyn Error>> {
    let facts = sample_facts()?;
    let contra = sample_contradiction()?;
    let quality = SynopsisQuality::new(
        Completeness::Complete,
        Some(BeliefInterval::new(800_000, 950_000)?),
        1_000_000,
        Some(ContentDigest::sha256(b"calibration-gen-1")),
    )?;

    Ok(H1SynopsisParams {
        handle_id: "semantic-handle:sha256:test-h1".to_string(),
        subject_id: "evidence:hydration-test-h1".to_string(),
        subject_digest: ContentDigest::sha256(b"immutable subject h1"),
        semantic_type: "semantic_synopsis".to_string(),
        classification: SynopsisClassification::SemanticSynopsis,
        anchor: sample_anchor(1),
        contract_basis: sample_basis(),
        estimated_cost: sample_budget()?,
        required_capabilities: BTreeSet::from(["capability:hydrate:h1".to_string()]),
        privacy_class: "private:property".to_string(),
        published_at: TimestampNs(100),
        retention_until: TimestampNs(10_000),
        facts,
        knowledge_states: BTreeSet::from([
            KnowledgeState::Known,
            KnowledgeState::Estimated,
            KnowledgeState::Conflicted,
        ]),
        provenance_classes: BTreeSet::from([ProvenanceClass::Observed, ProvenanceClass::Derived]),
        contradictions: vec![contra],
        quality,
        omissions: BTreeSet::from([OmissionReason::PrivacyRedaction]),
    })
}

fn sample_handle() -> Result<SemanticHandle, Box<dyn Error>> {
    let levels = BTreeSet::from([HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2]);
    let caps = BTreeMap::from([
        (
            HydrationLevel::H0,
            BTreeSet::from(["capability:hydrate:h0".to_string()]),
        ),
        (
            HydrationLevel::H1,
            BTreeSet::from(["capability:hydrate:h1".to_string()]),
        ),
        (
            HydrationLevel::H2,
            BTreeSet::from(["capability:hydrate:h2".to_string()]),
        ),
    ]);
    let costs = BTreeMap::from([
        (HydrationLevel::H0, sample_budget()?),
        (HydrationLevel::H1, sample_budget()?),
        (HydrationLevel::H2, sample_budget()?),
    ]);

    let handle = SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: sample_basis(),
        anchor: sample_anchor(1),
        subject_id: "evidence:hydration-test-h1".to_string(),
        subject_digest: ContentDigest::sha256(b"immutable subject h1"),
        semantic_type: "semantic_synopsis".to_string(),
        source_id: "sensor:cam01".to_string(),
        capture_interval: None,
        spatial_scope: Some("zone:perimeter".to_string()),
        privacy_class: "private:property".to_string(),
        applied_transform: None,
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(10_000),
        levels,
        required_capabilities: caps,
        estimated_costs: costs,
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(100),
    })?;
    Ok(handle)
}

#[test]
fn test_h1_normative_row_identity_and_properties() -> Result<(), Box<dyn Error>> {
    let params = sample_h1_params()?;
    let synopsis = H1SemanticSynopsis::new(params)?;

    // Verify exact normative constants and accessors
    assert_eq!(synopsis.level(), HydrationLevel::H1);
    assert_eq!(synopsis.level_id(), H1_LEVEL_ID);
    assert_eq!(synopsis.level_id(), "H1");
    assert_eq!(synopsis.level_name(), H1_LEVEL_NAME);
    assert_eq!(synopsis.level_name(), "semantic_synopsis");
    assert_eq!(synopsis.content_declaration(), H1_CONTENT);
    assert_eq!(
        synopsis.content_declaration(),
        "typed facts, knowledge states, provenance, contradictions, quality, and omissions"
    );
    assert_eq!(synopsis.owner(), H1_OWNER);
    assert_eq!(synopsis.owner(), "fss-agent-core");
    assert_eq!(HydrationLevel::H1.owner(), H1_OWNER);
    assert_eq!(
        synopsis.classification(),
        SynopsisClassification::SemanticSynopsis
    );
    assert_eq!(H1_SCHEMA, "fss.h1_semantic_synopsis.v1");

    // Verify content accessors
    assert_eq!(synopsis.facts().len(), 2);
    assert!(synopsis.fact("fact:device:cam01").is_some());
    assert!(synopsis.fact("fact:geometry:zone_a").is_some());
    assert!(synopsis.fact("fact:nonexistent").is_none());
    assert!(synopsis.has_knowledge_state(KnowledgeState::Known));
    assert!(synopsis.has_knowledge_state(KnowledgeState::Estimated));
    assert!(synopsis.has_knowledge_state(KnowledgeState::Conflicted));
    assert!(!synopsis.has_knowledge_state(KnowledgeState::Unknown));
    assert!(synopsis.has_provenance(ProvenanceClass::Observed));
    assert!(synopsis.has_provenance(ProvenanceClass::Derived));
    assert!(!synopsis.has_provenance(ProvenanceClass::Predicted));
    assert!(synopsis.has_contradictions());
    assert_eq!(synopsis.contradictions().len(), 1);
    assert!(synopsis.is_complete());
    assert!(synopsis.has_omissions());
    assert!(
        synopsis
            .omissions()
            .contains(&OmissionReason::PrivacyRedaction)
    );
    assert!(!synopsis.is_expired_at(TimestampNs(500)));
    assert!(synopsis.is_expired_at(TimestampNs(20_000)));
    assert!(synopsis.requires_capability("capability:hydrate:h1"));
    assert!(!synopsis.requires_capability("capability:unknown"));
    assert!(synopsis.satisfies_budget(&sample_budget()?));

    Ok(())
}

#[test]
fn test_h1_to_knowledge_cells_binds_evidence_digests_without_state_root()
-> Result<(), Box<dyn Error>> {
    let params = sample_h1_params()?;
    let synopsis = H1SemanticSynopsis::new(params)?;

    let cells = synopsis.to_knowledge_cells();
    assert_eq!(cells.len(), 2);

    let cam_fact = synopsis.fact("fact:device:cam01");
    assert!(cam_fact.is_some());
    if let Some(fact) = cam_fact {
        let cell = &cells[0];
        assert_eq!(cell.claim_id, fact.fact_id);
        assert_eq!(cell.statement, fact.statement);
        assert_eq!(cell.knowledge_state, KnowledgeState::Known);
        assert_eq!(cell.provenance, fact.provenance);
        assert_eq!(cell.hypothesis, None);
        // Must contain exact fact evidence digest and NOT state_root
        assert_eq!(cell.evidence, vec![fact.evidence_digest]);
        assert_eq!(cell.contradictions, Vec::<ContentDigest>::new());
        assert_eq!(cell.valid_until, None);
        assert_eq!(cell.state_basis, None);
        assert!(cell.validate().is_ok());
    }

    let geom_fact = synopsis.fact("fact:geometry:zone_a");
    assert!(geom_fact.is_some());
    if let Some(fact) = geom_fact {
        let cell = &cells[1];
        assert_eq!(cell.claim_id, fact.fact_id);
        assert_eq!(cell.statement, fact.statement);
        assert_eq!(cell.knowledge_state, KnowledgeState::Estimated);
        assert_eq!(cell.provenance, fact.provenance);
        assert_eq!(cell.hypothesis, None);
        assert_eq!(cell.evidence, vec![fact.evidence_digest]);
        assert_eq!(cell.contradictions, Vec::<ContentDigest>::new());
        assert_eq!(cell.valid_until, None);
        assert_eq!(cell.state_basis, None);
        assert!(cell.validate().is_ok());
    }

    Ok(())
}

#[test]
fn test_h1_canonical_binary_roundtrip_and_trailing_bytes_refusal() -> Result<(), Box<dyn Error>> {
    let params = sample_h1_params()?;
    let synopsis = H1SemanticSynopsis::new(params)?;

    let bytes = synopsis.to_canonical_bytes()?;
    assert!(!bytes.is_empty());

    let decoded = H1SemanticSynopsis::from_canonical_bytes(&bytes)?;
    assert_eq!(decoded, synopsis);
    assert_eq!(decoded.canonical_digest()?, synopsis.canonical_digest()?);

    // Planted trailing byte must be refused with NonCanonicalOrdering
    let mut trailing = bytes.clone();
    trailing.push(0xFF);
    let trailing_err = H1SemanticSynopsis::from_canonical_bytes(&trailing);
    assert_eq!(
        trailing_err,
        Err(ContractError::NonCanonicalOrdering),
        "Trailing bytes after canonical envelope must be refused"
    );

    Ok(())
}

#[test]
fn test_h1_extract_from_semantic_handle() -> Result<(), Box<dyn Error>> {
    let handle = sample_handle()?;
    let facts = sample_facts()?;
    let contra = sample_contradiction()?;
    let quality = SynopsisQuality::new(Completeness::Complete, None, 1_000, None)?;

    let spec = H1ContentSpec {
        facts,
        knowledge_states: BTreeSet::from([
            KnowledgeState::Known,
            KnowledgeState::Estimated,
            KnowledgeState::Conflicted,
        ]),
        provenance_classes: BTreeSet::from([ProvenanceClass::Observed, ProvenanceClass::Derived]),
        contradictions: vec![contra],
        quality,
        omissions: BTreeSet::new(),
        classification: Some(SynopsisClassification::EpistemicBeliefSynopsis),
    };

    let synopsis = handle.to_h1_synopsis(spec)?;
    assert_eq!(synopsis.handle_id(), handle.handle_id);
    assert_eq!(synopsis.subject_id(), handle.subject_id);
    assert_eq!(synopsis.subject_digest(), handle.subject_digest);
    assert_eq!(
        synopsis.classification(),
        SynopsisClassification::EpistemicBeliefSynopsis
    );
    assert!(!synopsis.has_omissions());
    Ok(())
}

#[test]
fn test_h1_handle_without_h1_level_refuses() -> Result<(), Box<dyn Error>> {
    // Publish a handle with only H0
    let handle = SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: sample_basis(),
        anchor: sample_anchor(1),
        subject_id: "evidence:h0-only".to_string(),
        subject_digest: ContentDigest::sha256(b"h0 only subject"),
        semantic_type: "semantic_synopsis".to_string(),
        source_id: "sensor:cam01".to_string(),
        capture_interval: None,
        spatial_scope: None,
        privacy_class: "private:property".to_string(),
        applied_transform: None,
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(10_000),
        levels: BTreeSet::from([HydrationLevel::H0]),
        required_capabilities: BTreeMap::from([(
            HydrationLevel::H0,
            BTreeSet::from(["capability:h0".to_string()]),
        )]),
        estimated_costs: BTreeMap::from([(HydrationLevel::H0, sample_budget()?)]),
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(100),
    })?;

    let spec = H1ContentSpec {
        facts: sample_facts()?,
        knowledge_states: BTreeSet::from([KnowledgeState::Known]),
        provenance_classes: BTreeSet::from([ProvenanceClass::Observed, ProvenanceClass::Derived]),
        contradictions: Vec::new(),
        quality: SynopsisQuality::new(Completeness::Complete, None, 1000, None)?,
        omissions: BTreeSet::new(),
        classification: None,
    };

    let res = handle.to_h1_synopsis(spec);
    assert!(
        matches!(res, Err(HydrationError::LevelUnavailable)),
        "Handle lacking H1 level must refuse H1 materialization"
    );
    Ok(())
}

#[test]
fn test_h1_planted_prohibited_classifications_fail() -> Result<(), Box<dyn Error>> {
    let mut params = sample_h1_params()?;

    let prohibited = [
        SynopsisClassification::ProhibitedRawPayload,
        SynopsisClassification::ProhibitedDecodedMedia,
        SynopsisClassification::ProhibitedDecisionArtifact,
        SynopsisClassification::ProhibitedLaboratoryReplay,
    ];

    for p in prohibited {
        assert!(p.is_prohibited());
        assert!(!p.is_permitted());
        params.classification = p;
        let res = H1SemanticSynopsis::new(params.clone());
        assert_eq!(
            res,
            Err(HydrationError::Contract(
                ContractError::ProhibitedEvidencePromotion
            )),
            "Prohibited classification {:?} must be refused",
            p
        );
    }
    Ok(())
}

#[test]
fn test_h1_planted_non_canonical_facts_fail() -> Result<(), Box<dyn Error>> {
    let mut params = sample_h1_params()?;
    // Reverse facts order so it violates canonical ascending fact_id sort
    params.facts.reverse();

    let res = H1SemanticSynopsis::new(params);
    assert_eq!(
        res,
        Err(HydrationError::Contract(
            ContractError::NonCanonicalOrdering
        )),
        "Non-canonically ordered facts must be refused"
    );
    Ok(())
}

#[test]
fn test_h1_planted_duplicate_facts_fail() -> Result<(), Box<dyn Error>> {
    let mut params = sample_h1_params()?;
    // Duplicate first fact
    params.facts.push(params.facts[0].clone());

    let res = H1SemanticSynopsis::new(params);
    assert_eq!(
        res,
        Err(HydrationError::Contract(
            ContractError::NonCanonicalOrdering
        )),
        "Duplicate facts must be refused"
    );
    Ok(())
}

#[test]
fn test_h1_planted_fact_provenance_not_declared_fails() -> Result<(), Box<dyn Error>> {
    let mut params = sample_h1_params()?;
    // Remove Derived from declared provenance_classes while fact:geometry:zone_a has ProvenanceClass::Derived
    params.provenance_classes.remove(&ProvenanceClass::Derived);

    let res = H1SemanticSynopsis::new(params);
    assert_eq!(
        res,
        Err(HydrationError::Contract(
            ContractError::ProhibitedEvidencePromotion
        )),
        "Undeclared fact provenance must be refused"
    );
    Ok(())
}

#[test]
fn test_h1_planted_omission_none_fails() -> Result<(), Box<dyn Error>> {
    let mut params = sample_h1_params()?;
    // OmissionReason::None is invalid as an explicit omission reason
    params.omissions.insert(OmissionReason::None);

    let res = H1SemanticSynopsis::new(params);
    assert_eq!(
        res,
        Err(HydrationError::Contract(ContractError::InvalidIdentifier)),
        "OmissionReason::None in omissions set must be refused"
    );
    Ok(())
}

#[test]
fn test_h1_planted_expired_retention_fails() -> Result<(), Box<dyn Error>> {
    let mut params = sample_h1_params()?;
    // retention_until before published_at
    params.retention_until = TimestampNs(50);
    params.published_at = TimestampNs(100);

    let res = H1SemanticSynopsis::new(params);
    assert_eq!(
        res,
        Err(HydrationError::ContinuationExpired),
        "Retention expiring before publication must be refused"
    );
    Ok(())
}

#[test]
fn test_h1_planted_zero_subject_digest_fails() -> Result<(), Box<dyn Error>> {
    let mut params = sample_h1_params()?;
    params.subject_digest = ContentDigest::new(DigestAlgorithm::Sha256, [0u8; 32]);

    let res = H1SemanticSynopsis::new(params);
    assert_eq!(
        res,
        Err(HydrationError::Contract(ContractError::InvalidDigest)),
        "Zero subject digest must be refused"
    );
    Ok(())
}

#[test]
fn test_h1_planted_empty_knowledge_states_fails() -> Result<(), Box<dyn Error>> {
    let mut params = sample_h1_params()?;
    params.knowledge_states.clear();

    let res = H1SemanticSynopsis::new(params);
    assert_eq!(
        res,
        Err(HydrationError::Contract(ContractError::InvalidIdentifier)),
        "Empty knowledge states must be refused"
    );
    Ok(())
}

#[test]
fn test_h1_planted_empty_provenance_classes_fails() -> Result<(), Box<dyn Error>> {
    let mut params = sample_h1_params()?;
    params.provenance_classes.clear();

    let res = H1SemanticSynopsis::new(params);
    assert_eq!(
        res,
        Err(HydrationError::Contract(ContractError::InvalidIdentifier)),
        "Empty provenance classes must be refused"
    );
    Ok(())
}

#[test]
fn test_h1_planted_zero_calibration_digest_fails() -> Result<(), Box<dyn Error>> {
    let zero_digest = ContentDigest::new(DigestAlgorithm::Sha256, [0u8; 32]);
    let quality_res = SynopsisQuality::new(Completeness::Complete, None, 1000, Some(zero_digest));
    assert_eq!(
        quality_res,
        Err(HydrationError::Contract(ContractError::InvalidDigest)),
        "Zero calibration digest in SynopsisQuality must be refused"
    );
    Ok(())
}

#[test]
fn test_h1_synopsis_classification_parsing_and_display() -> Result<(), Box<dyn Error>> {
    let all = [
        (
            SynopsisClassification::SemanticSynopsis,
            "semantic_synopsis",
        ),
        (
            SynopsisClassification::EpistemicBeliefSynopsis,
            "epistemic_belief_synopsis",
        ),
        (
            SynopsisClassification::CoverageQualitySynopsis,
            "coverage_quality_synopsis",
        ),
        (
            SynopsisClassification::CorroborationSynopsis,
            "corroboration_synopsis",
        ),
        (
            SynopsisClassification::ProhibitedRawPayload,
            "prohibited_raw_payload",
        ),
        (
            SynopsisClassification::ProhibitedDecodedMedia,
            "prohibited_decoded_media",
        ),
        (
            SynopsisClassification::ProhibitedDecisionArtifact,
            "prohibited_decision_artifact",
        ),
        (
            SynopsisClassification::ProhibitedLaboratoryReplay,
            "prohibited_laboratory_replay",
        ),
    ];

    for (c, name) in all {
        assert_eq!(c.as_str(), name);
        assert_eq!(c.to_string(), name);
        assert_eq!(SynopsisClassification::from_name(name)?, c);
        assert_eq!(name.parse::<SynopsisClassification>()?, c);

        let mut enc = CanonicalEncoder::new();
        c.encode_canonical(&mut enc);
        let bytes = enc.finish_checked()?;
        let mut dec = CanonicalDecoder::new(&bytes);
        assert_eq!(SynopsisClassification::decode_canonical(&mut dec)?, c);
        dec.ensure_finished()?;
    }

    assert!(
        "unknown_classification"
            .parse::<SynopsisClassification>()
            .is_err()
    );
    Ok(())
}

#[test]
fn test_h1_owner_pinned_to_registry() -> Result<(), Box<dyn Error>> {
    let registry = include_str!("../../../architecture/semantic_hydration.json");
    let key = "\"semantic_owner\": \"";
    let pos = registry
        .find(key)
        .ok_or("missing semantic_owner in registry")?;
    let start = pos + key.len();
    let end = registry[start..]
        .find('"')
        .ok_or("malformed semantic_owner string")?
        + start;
    let expected_owner = &registry[start..end];
    assert_eq!(expected_owner, "fss-agent-core");
    assert_eq!(H1_OWNER, expected_owner);
    assert_eq!(HydrationLevel::H1.owner(), expected_owner);

    let params = sample_h1_params()?;
    let synopsis = H1SemanticSynopsis::new(params)?;
    assert_eq!(synopsis.owner(), expected_owner);
    Ok(())
}

#[test]
fn test_h1_to_knowledge_cells_contradiction_mapping() -> Result<(), Box<dyn Error>> {
    let mut params = sample_h1_params()?;
    let d1 = params.facts[0].evidence_digest;
    let d2 = ContentDigest::sha256(b"cam01-contradicting-evidence");
    let contra_cam = Contradiction::new(ContradictionParams {
        contradiction_id: "contra:test:000".to_string(),
        conflicting_evidence: BTreeSet::from([d1, d2]),
        failure_domains: BTreeSet::from([
            "domain:optical:cam1".to_string(),
            "domain:telemetry:cam1".to_string(),
        ]),
        unresolved_worlds: BTreeSet::from([
            "world:cam_working".to_string(),
            "world:cam_failed".to_string(),
        ]),
        claim_id: Some("fact:device:cam01".to_string()),
        statement: "Camera reported active but telemetry shows offline".to_string(),
        belief_interval: Some(BeliefInterval::new(100_000, 900_000)?),
        created_at: TimestampNs(1_000_000),
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::Derived,
        disposition: HypothesisDisposition::Live,
        outcome: RuntimeOutcome::Indeterminate,
    })?;
    params.contradictions.insert(0, contra_cam);

    // With cam01 contradicted, Known is no longer grounded by any uncontradicted Observed fact
    let err_ungrounded = H1SemanticSynopsis::new(params.clone());
    assert_eq!(
        err_ungrounded.err(),
        Some(HydrationError::Contract(
            ContractError::KnowledgeStateBasisMismatch
        )),
        "Declared Known state must be rejected when its only observed grounding fact is contradicted"
    );

    // Removing Known allows synopsis creation with [Estimated, Conflicted]
    params.knowledge_states.remove(&KnowledgeState::Known);
    let synopsis = H1SemanticSynopsis::new(params)?;
    let cells = synopsis.to_knowledge_cells();
    assert_eq!(cells.len(), 2);
    // fact:device:cam01 is now contradicted -> knowledge_state must be Conflicted
    assert_eq!(cells[0].claim_id, "fact:device:cam01");
    assert_eq!(cells[0].knowledge_state, KnowledgeState::Conflicted);
    assert!(!cells[0].contradictions.is_empty());

    // fact:geometry:zone_a is Derived and uncontradicted -> Estimated
    assert_eq!(cells[1].claim_id, "fact:geometry:zone_a");
    assert_eq!(cells[1].knowledge_state, KnowledgeState::Estimated);
    assert!(cells[1].contradictions.is_empty());
    Ok(())
}

#[test]
fn test_h1_to_hydration_artifact_roundtrip_and_verify() -> Result<(), Box<dyn Error>> {
    let params = sample_h1_params()?;
    let synopsis = H1SemanticSynopsis::new(params)?;

    let artifact = synopsis.to_hydration_artifact()?;
    assert_eq!(artifact.level, HydrationLevel::H1);
    assert_eq!(
        artifact.content_type,
        "application/fss.h1_semantic_synopsis.v1"
    );
    artifact.verify()?;

    let artifact_from_try: HydrationArtifact = synopsis.clone().try_into()?;
    assert_eq!(artifact, artifact_from_try);
    artifact_from_try.verify()?;
    Ok(())
}

#[test]
fn test_h1_handle_missing_cost_or_capability_refuses() -> Result<(), Box<dyn Error>> {
    let handle = sample_handle()?;
    let spec = H1ContentSpec {
        facts: sample_facts()?,
        knowledge_states: BTreeSet::from([
            KnowledgeState::Known,
            KnowledgeState::Estimated,
            KnowledgeState::Conflicted,
        ]),
        provenance_classes: BTreeSet::from([ProvenanceClass::Observed, ProvenanceClass::Derived]),
        contradictions: vec![sample_contradiction()?],
        quality: SynopsisQuality::new(Completeness::Complete, None, 1_000, None)?,
        omissions: BTreeSet::from([OmissionReason::PrivacyRedaction]),
        classification: None,
    };

    // 1. Missing cost entry for H1
    let mut handle_missing_cost = handle.clone();
    handle_missing_cost
        .estimated_costs
        .remove(&HydrationLevel::H1);
    let res_cost = H1SemanticSynopsis::from_semantic_handle(&handle_missing_cost, spec.clone());
    assert_eq!(res_cost.err(), Some(HydrationError::LevelUnavailable));

    // 2. Missing capability entry for H1
    let mut handle_missing_cap = handle.clone();
    handle_missing_cap
        .required_capabilities
        .remove(&HydrationLevel::H1);
    let res_cap = H1SemanticSynopsis::from_semantic_handle(&handle_missing_cap, spec);
    assert_eq!(res_cap.err(), Some(HydrationError::LevelUnavailable));
    Ok(())
}

#[test]
fn test_h1_tampered_handle_refuses() -> Result<(), Box<dyn Error>> {
    let mut handle = sample_handle()?;
    handle.descriptor_digest = ContentDigest::sha256(b"tampered descriptor");
    let spec = H1ContentSpec {
        facts: sample_facts()?,
        knowledge_states: BTreeSet::from([
            KnowledgeState::Known,
            KnowledgeState::Estimated,
            KnowledgeState::Conflicted,
        ]),
        provenance_classes: BTreeSet::from([ProvenanceClass::Observed, ProvenanceClass::Derived]),
        contradictions: vec![sample_contradiction()?],
        quality: SynopsisQuality::new(Completeness::Complete, None, 1_000, None)?,
        omissions: BTreeSet::from([OmissionReason::PrivacyRedaction]),
        classification: None,
    };

    let res = H1SemanticSynopsis::from_semantic_handle(&handle, spec);
    assert_eq!(
        res.err(),
        Some(HydrationError::Contract(ContractError::DigestMismatch))
    );
    Ok(())
}

#[test]
fn test_h1_synopsis_classification_exact_match_no_aliases() -> Result<(), Box<dyn Error>> {
    assert!(
        " semantic_synopsis"
            .parse::<SynopsisClassification>()
            .is_err()
    );
    assert!(
        "semantic_synopsis "
            .parse::<SynopsisClassification>()
            .is_err()
    );
    assert!(
        "semantic_synopsis\n"
            .parse::<SynopsisClassification>()
            .is_err()
    );
    assert!(
        "SEMANTIC_SYNOPSIS"
            .parse::<SynopsisClassification>()
            .is_err()
    );
    assert!("synopsis".parse::<SynopsisClassification>().is_err());
    assert!(SynopsisClassification::from_name(" semantic_synopsis").is_err());
    assert!(SynopsisClassification::from_name("").is_err());
    Ok(())
}

#[test]
fn test_h1_hydration_level_and_availability_exact_match() -> Result<(), Box<dyn Error>> {
    assert!(" H1".parse::<HydrationLevel>().is_err());
    assert!("H1 ".parse::<HydrationLevel>().is_err());
    assert!("h1".parse::<HydrationLevel>().is_err());
    assert!("semantic_synopsis".parse::<HydrationLevel>().is_err());
    assert_eq!("H1".parse::<HydrationLevel>()?, HydrationLevel::H1);

    assert!(" available".parse::<HandleAvailability>().is_err());
    assert!("available ".parse::<HandleAvailability>().is_err());
    assert!("AVAILABLE".parse::<HandleAvailability>().is_err());
    assert_eq!(
        "available".parse::<HandleAvailability>()?,
        HandleAvailability::Available
    );
    Ok(())
}

#[test]
fn test_h1_dos_protection_collection_bounds() -> Result<(), Box<dyn Error>> {
    let params = sample_h1_params()?;
    let synopsis = H1SemanticSynopsis::new(params)?;

    let mut enc = CanonicalEncoder::new();
    enc.text(H1_SCHEMA);
    enc.text(synopsis.handle_id());
    enc.text(synopsis.subject_id());
    enc.digest(synopsis.subject_digest());
    enc.text(synopsis.semantic_type());
    synopsis.classification().encode_canonical(&mut enc);
    synopsis.anchor().encode_canonical(&mut enc);
    synopsis.contract_basis().encode_canonical(&mut enc);
    synopsis.estimated_cost().encode_canonical(&mut enc);
    enc.u64(synopsis.required_capabilities().len() as u64);
    for cap in synopsis.required_capabilities() {
        enc.text(cap);
    }
    enc.text(synopsis.privacy_class());
    synopsis.published_at().encode_canonical(&mut enc);
    synopsis.retention_until().encode_canonical(&mut enc);
    synopsis.quality().encode_canonical(&mut enc);

    // 1. Oversized facts count: MAX_H1_FACTS + 1
    let mut bad_facts = enc.clone();
    bad_facts.u64((MAX_H1_FACTS + 1) as u64);
    let bytes_bad_facts = bad_facts.finish_checked()?;
    let mut dec = CanonicalDecoder::new(&bytes_bad_facts);
    assert_eq!(
        H1SemanticSynopsis::decode_canonical(&mut dec).err(),
        Some(ContractError::CountBoundExceeded)
    );

    // 2. Oversized facts count: u64::MAX
    let mut bad_facts_max = enc.clone();
    bad_facts_max.u64(u64::MAX);
    let bytes_bad_facts_max = bad_facts_max.finish_checked()?;
    let mut dec_max = CanonicalDecoder::new(&bytes_bad_facts_max);
    assert_eq!(
        H1SemanticSynopsis::decode_canonical(&mut dec_max).err(),
        Some(ContractError::CountBoundExceeded)
    );

    // 3. Oversized knowledge states count: MAX_H1_KNOWLEDGE_STATES + 1
    let mut bad_ks = enc.clone();
    bad_ks.u64(0); // 0 facts
    bad_ks.u64((MAX_H1_KNOWLEDGE_STATES + 1) as u64);
    let bytes_bad_ks = bad_ks.finish_checked()?;
    let mut dec_ks = CanonicalDecoder::new(&bytes_bad_ks);
    assert_eq!(
        H1SemanticSynopsis::decode_canonical(&mut dec_ks).err(),
        Some(ContractError::CountBoundExceeded)
    );

    // 4. Oversized provenance classes count: MAX_H1_PROVENANCE_CLASSES + 1
    let mut bad_prov = enc.clone();
    bad_prov.u64(0); // 0 facts
    bad_prov.u64(1); // 1 ks
    KnowledgeState::Known.encode_canonical(&mut bad_prov);
    bad_prov.u64((MAX_H1_PROVENANCE_CLASSES + 1) as u64);
    let bytes_bad_prov = bad_prov.finish_checked()?;
    let mut dec_prov = CanonicalDecoder::new(&bytes_bad_prov);
    assert_eq!(
        H1SemanticSynopsis::decode_canonical(&mut dec_prov).err(),
        Some(ContractError::CountBoundExceeded)
    );

    // 5. Oversized contradictions count: MAX_H1_CONTRADICTIONS + 1
    let mut bad_contra = enc.clone();
    bad_contra.u64(0); // 0 facts
    bad_contra.u64(1); // 1 ks
    KnowledgeState::Known.encode_canonical(&mut bad_contra);
    bad_contra.u64(1); // 1 prov
    ProvenanceClass::Observed.encode_canonical(&mut bad_contra);
    bad_contra.u64((MAX_H1_CONTRADICTIONS + 1) as u64);
    let bytes_bad_contra = bad_contra.finish_checked()?;
    let mut dec_contra = CanonicalDecoder::new(&bytes_bad_contra);
    assert_eq!(
        H1SemanticSynopsis::decode_canonical(&mut dec_contra).err(),
        Some(ContractError::CountBoundExceeded)
    );

    // 6. Oversized omissions count: MAX_H1_OMISSIONS + 1
    let mut bad_omissions = enc.clone();
    bad_omissions.u64(0); // 0 facts
    bad_omissions.u64(1); // 1 ks
    KnowledgeState::Known.encode_canonical(&mut bad_omissions);
    bad_omissions.u64(1); // 1 prov
    ProvenanceClass::Observed.encode_canonical(&mut bad_omissions);
    bad_omissions.u64(0); // 0 contra
    bad_omissions.u64((MAX_H1_OMISSIONS + 1) as u64);
    let bytes_bad_omissions = bad_omissions.finish_checked()?;
    let mut dec_omissions = CanonicalDecoder::new(&bytes_bad_omissions);
    assert_eq!(
        H1SemanticSynopsis::decode_canonical(&mut dec_omissions).err(),
        Some(ContractError::CountBoundExceeded)
    );

    Ok(())
}

#[test]
fn test_h1_contract_mutants_killed() -> Result<(), Box<dyn Error>> {
    let params = sample_h1_params()?;
    let synopsis = H1SemanticSynopsis::new(params)?;

    // 1. M1d: Contradiction ordering in decode
    let contra1 = sample_contradiction()?;
    let d1 = ContentDigest::sha256(b"optical-2");
    let d2 = ContentDigest::sha256(b"radar-2");
    let contra2 = Contradiction::new(ContradictionParams {
        contradiction_id: "contra:test:002".to_string(),
        conflicting_evidence: BTreeSet::from([d1, d2]),
        failure_domains: BTreeSet::from([
            "domain:optical:cam2".to_string(),
            "domain:rf:radar2".to_string(),
        ]),
        unresolved_worlds: BTreeSet::from(["world:a".to_string(), "world:b".to_string()]),
        claim_id: Some("claim:test:002".to_string()),
        statement: "Second contradiction statement for ordering test".to_string(),
        belief_interval: Some(BeliefInterval::new(200_000, 800_000)?),
        created_at: TimestampNs(2_000_000),
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::Derived,
        disposition: HypothesisDisposition::Live,
        outcome: RuntimeOutcome::Indeterminate,
    })?;

    // Encode contradictions in decreasing order (contra2 before contra1)
    let bad_contradiction_order_bytes = {
        let mut enc = CanonicalEncoder::new();
        enc.text(H1_SCHEMA);
        enc.text(synopsis.handle_id());
        enc.text(synopsis.subject_id());
        enc.digest(synopsis.subject_digest());
        enc.text(synopsis.semantic_type());
        synopsis.classification().encode_canonical(&mut enc);
        synopsis.anchor().encode_canonical(&mut enc);
        synopsis.contract_basis().encode_canonical(&mut enc);
        synopsis.estimated_cost().encode_canonical(&mut enc);
        enc.u64(synopsis.required_capabilities().len() as u64);
        for cap in synopsis.required_capabilities() {
            enc.text(cap);
        }
        enc.text(synopsis.privacy_class());
        synopsis.published_at().encode_canonical(&mut enc);
        synopsis.retention_until().encode_canonical(&mut enc);
        synopsis.quality().encode_canonical(&mut enc);
        // Facts
        enc.u64(synopsis.facts().len() as u64);
        for fact in synopsis.facts() {
            fact.encode_canonical(&mut enc);
        }
        // Knowledge states
        enc.u64(synopsis.knowledge_states().len() as u64);
        for ks in synopsis.knowledge_states() {
            ks.encode_canonical(&mut enc);
        }
        // Provenance classes
        enc.u64(synopsis.provenance_classes().len() as u64);
        for prov in synopsis.provenance_classes() {
            prov.encode_canonical(&mut enc);
        }
        // Contradictions out of order: 2 then 1
        enc.u64(2);
        contra2.encode_canonical(&mut enc);
        contra1.encode_canonical(&mut enc);
        // Omissions
        enc.u64(synopsis.omissions().len() as u64);
        for om in synopsis.omissions() {
            om.encode_canonical(&mut enc);
        }
        enc.finish_checked()?
    };
    let mut dec_contra = CanonicalDecoder::new(&bad_contradiction_order_bytes);
    let res_contra = H1SemanticSynopsis::decode_canonical(&mut dec_contra);
    assert_eq!(
        res_contra.err(),
        Some(ContractError::NonCanonicalOrdering),
        "M1d: Decreasing contradiction order in decode must fail with NonCanonicalOrdering"
    );

    // 2. M1e: Validate in decode (zero subject digest)
    let bad_subject_digest_bytes = {
        let mut enc = CanonicalEncoder::new();
        enc.text(H1_SCHEMA);
        enc.text(synopsis.handle_id());
        enc.text(synopsis.subject_id());
        enc.digest(ContentDigest::new(
            fss_core::DigestAlgorithm::Sha256,
            [0u8; 32],
        ));
        enc.text(synopsis.semantic_type());
        synopsis.classification().encode_canonical(&mut enc);
        synopsis.anchor().encode_canonical(&mut enc);
        synopsis.contract_basis().encode_canonical(&mut enc);
        synopsis.estimated_cost().encode_canonical(&mut enc);
        enc.u64(synopsis.required_capabilities().len() as u64);
        for cap in synopsis.required_capabilities() {
            enc.text(cap);
        }
        enc.text(synopsis.privacy_class());
        synopsis.published_at().encode_canonical(&mut enc);
        synopsis.retention_until().encode_canonical(&mut enc);
        synopsis.quality().encode_canonical(&mut enc);
        enc.u64(synopsis.facts().len() as u64);
        for fact in synopsis.facts() {
            fact.encode_canonical(&mut enc);
        }
        enc.u64(synopsis.knowledge_states().len() as u64);
        for ks in synopsis.knowledge_states() {
            ks.encode_canonical(&mut enc);
        }
        enc.u64(synopsis.provenance_classes().len() as u64);
        for prov in synopsis.provenance_classes() {
            prov.encode_canonical(&mut enc);
        }
        enc.u64(synopsis.contradictions().len() as u64);
        for contra in synopsis.contradictions() {
            contra.encode_canonical(&mut enc);
        }
        enc.u64(synopsis.omissions().len() as u64);
        for om in synopsis.omissions() {
            om.encode_canonical(&mut enc);
        }
        enc.finish_checked()?
    };
    let mut dec_zero = CanonicalDecoder::new(&bad_subject_digest_bytes);
    let res_zero = H1SemanticSynopsis::decode_canonical(&mut dec_zero);
    assert_eq!(
        res_zero.err(),
        Some(ContractError::InvalidDigest),
        "M1e: Zero subject digest must be rejected in decode via validate()"
    );

    // 3. M1h: fact.validate() in decode (empty statement in fact)
    let bad_fact_bytes = {
        let mut enc = CanonicalEncoder::new();
        enc.text(H1_SCHEMA);
        enc.text(synopsis.handle_id());
        enc.text(synopsis.subject_id());
        enc.digest(synopsis.subject_digest());
        enc.text(synopsis.semantic_type());
        synopsis.classification().encode_canonical(&mut enc);
        synopsis.anchor().encode_canonical(&mut enc);
        synopsis.contract_basis().encode_canonical(&mut enc);
        synopsis.estimated_cost().encode_canonical(&mut enc);
        enc.u64(synopsis.required_capabilities().len() as u64);
        for cap in synopsis.required_capabilities() {
            enc.text(cap);
        }
        enc.text(synopsis.privacy_class());
        synopsis.published_at().encode_canonical(&mut enc);
        synopsis.retention_until().encode_canonical(&mut enc);
        synopsis.quality().encode_canonical(&mut enc);
        // 1 fact with empty statement (fails fact.validate())
        enc.u64(1);
        enc.text("fact:invalid:001");
        WorldFactKind::Device.encode_canonical(&mut enc);
        sample_anchor(1).encode_canonical(&mut enc);
        enc.text(""); // Empty statement!
        ProvenanceClass::Observed.encode_canonical(&mut enc);
        enc.digest(ContentDigest::sha256(b"evidence"));
        enc.u64(1); // Generation
        // Knowledge states
        enc.u64(synopsis.knowledge_states().len() as u64);
        for ks in synopsis.knowledge_states() {
            ks.encode_canonical(&mut enc);
        }
        // Provenance classes
        enc.u64(synopsis.provenance_classes().len() as u64);
        for prov in synopsis.provenance_classes() {
            prov.encode_canonical(&mut enc);
        }
        enc.u64(0); // Contradictions
        enc.u64(0); // Omissions
        enc.finish_checked()?
    };
    let mut dec_fact = CanonicalDecoder::new(&bad_fact_bytes);
    let res_fact = H1SemanticSynopsis::decode_canonical(&mut dec_fact);
    assert_eq!(
        res_fact.err(),
        Some(ContractError::InvalidIdentifier),
        "M1h: Empty fact statement must be rejected in decode via fact.validate()"
    );

    // 4. M1i: Capability valid_text in decode (empty capability string)
    let bad_cap_bytes = {
        let mut enc = CanonicalEncoder::new();
        enc.text(H1_SCHEMA);
        enc.text(synopsis.handle_id());
        enc.text(synopsis.subject_id());
        enc.digest(synopsis.subject_digest());
        enc.text(synopsis.semantic_type());
        synopsis.classification().encode_canonical(&mut enc);
        synopsis.anchor().encode_canonical(&mut enc);
        synopsis.contract_basis().encode_canonical(&mut enc);
        synopsis.estimated_cost().encode_canonical(&mut enc);
        // Required capabilities with an invalid empty string
        enc.u64(1);
        enc.text(""); // Empty capability string!
        enc.text(synopsis.privacy_class());
        synopsis.published_at().encode_canonical(&mut enc);
        synopsis.retention_until().encode_canonical(&mut enc);
        synopsis.quality().encode_canonical(&mut enc);
        enc.u64(0); // Facts
        enc.u64(0); // Knowledge states
        enc.u64(0); // Provenance classes
        enc.u64(0); // Contradictions
        enc.u64(0); // Omissions
        enc.finish_checked()?
    };
    let mut dec_cap = CanonicalDecoder::new(&bad_cap_bytes);
    let res_cap = H1SemanticSynopsis::decode_canonical(&mut dec_cap);
    assert_eq!(
        res_cap.err(),
        Some(ContractError::InvalidIdentifier),
        "M1i: Invalid capability text must be rejected in decode"
    );

    Ok(())
}

#[test]
fn test_h1_validate_via_new_mutants_killed() -> Result<(), Box<dyn Error>> {
    // 1. M1d: Unordered contradiction list via new() must fail with NonCanonicalOrdering
    let contra1 = sample_contradiction()?;
    let d1 = ContentDigest::sha256(b"optical-2");
    let d2 = ContentDigest::sha256(b"radar-2");
    let contra2 = Contradiction::new(ContradictionParams {
        contradiction_id: "contra:test:002".to_string(),
        conflicting_evidence: BTreeSet::from([d1, d2]),
        failure_domains: BTreeSet::from([
            "domain:optical:cam2".to_string(),
            "domain:rf:radar2".to_string(),
        ]),
        unresolved_worlds: BTreeSet::from(["world:a".to_string(), "world:b".to_string()]),
        claim_id: Some("claim:test:002".to_string()),
        statement: "Second contradiction statement for ordering test".to_string(),
        belief_interval: Some(BeliefInterval::new(200_000, 800_000)?),
        created_at: TimestampNs(2_000_000),
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::Derived,
        disposition: HypothesisDisposition::Live,
        outcome: RuntimeOutcome::Indeterminate,
    })?;
    assert!(contra1.contradiction_id() < contra2.contradiction_id());
    let mut params_unordered_contra = sample_h1_params()?;
    params_unordered_contra.contradictions = vec![contra2, contra1.clone()];
    assert_eq!(
        H1SemanticSynopsis::new(params_unordered_contra),
        Err(HydrationError::Contract(
            ContractError::NonCanonicalOrdering
        )),
        "M1d: Unordered contradiction list via new() must fail with NonCanonicalOrdering"
    );

    // 2. M1h: Invalid struct-literal fact (empty statement) via new() must fail with InvalidIdentifier
    let bad_fact = WorldFact {
        fact_id: "fact:test:bad_empty_stmt".to_string(),
        kind: WorldFactKind::Device,
        anchor: sample_anchor(1),
        statement: "".to_string(),
        provenance: ProvenanceClass::Observed,
        evidence_digest: ContentDigest::sha256(b"bad-fact-evidence"),
        generation: Generation(1),
    };
    let mut params_bad_fact = sample_h1_params()?;
    params_bad_fact.facts = vec![bad_fact];
    assert_eq!(
        H1SemanticSynopsis::new(params_bad_fact),
        Err(HydrationError::Contract(ContractError::InvalidIdentifier)),
        "M1h: Invalid struct-literal fact via new() must fail with InvalidIdentifier"
    );

    // 3. M1i: Invalid capability via new() must fail with InvalidIdentifier
    let mut params_bad_cap = sample_h1_params()?;
    params_bad_cap.required_capabilities.insert("".to_string());
    assert_eq!(
        H1SemanticSynopsis::new(params_bad_cap),
        Err(HydrationError::Contract(ContractError::InvalidIdentifier)),
        "M1i: Invalid capability text via new() must fail with InvalidIdentifier"
    );

    // 4. R3: Contradiction with state not in declared knowledge_states must fail with KnowledgeStateBasisMismatch
    let mut params_r3 = sample_h1_params()?;
    params_r3.contradictions = vec![contra1];
    params_r3
        .knowledge_states
        .remove(&KnowledgeState::Conflicted);
    assert_eq!(
        H1SemanticSynopsis::new(params_r3),
        Err(HydrationError::Contract(
            ContractError::KnowledgeStateBasisMismatch
        )),
        "R3: Contradiction state not in declared knowledge_states must fail with KnowledgeStateBasisMismatch"
    );

    Ok(())
}

#[test]
fn test_h1_fact_epistemic_grounding_and_irreversible_effect_premise() -> Result<(), Box<dyn Error>>
{
    let mut params = sample_h1_params()?;
    let op_fact = WorldFact::new(
        "fact:device:operator_asserted",
        WorldFactKind::Device,
        sample_anchor(1),
        "Operator asserted fact statement",
        ProvenanceClass::OperatorAsserted,
        ContentDigest::sha256(b"op-assertion"),
        Generation(1),
    )?;

    params.facts.push(op_fact);
    params.facts.sort_by(|a, b| a.fact_id.cmp(&b.fact_id));
    params
        .provenance_classes
        .insert(ProvenanceClass::OperatorAsserted);

    let synopsis = H1SemanticSynopsis::new(params)?;
    let cells = synopsis.to_knowledge_cells();

    let now = TimestampNs(1_000_000);

    let observed_cell = cells
        .iter()
        .find(|c| c.claim_id == "fact:device:cam01")
        .ok_or("missing observed cell")?;
    assert_eq!(observed_cell.knowledge_state, KnowledgeState::Known);
    assert_eq!(observed_cell.provenance, ProvenanceClass::Observed);
    assert!(observed_cell.is_irreversible_effect_premise(now));

    let op_cell = cells
        .iter()
        .find(|c| c.claim_id == "fact:device:operator_asserted")
        .ok_or("missing operator cell")?;
    assert_eq!(op_cell.knowledge_state, KnowledgeState::Estimated);
    assert_eq!(op_cell.provenance, ProvenanceClass::OperatorAsserted);
    assert!(!op_cell.is_irreversible_effect_premise(now));

    // Policy fact also must not become Known
    let mut params_policy = sample_h1_params()?;
    let policy_fact = WorldFact::new(
        "fact:policy:retention",
        WorldFactKind::Device,
        sample_anchor(1),
        "Policy statement",
        ProvenanceClass::Policy,
        ContentDigest::sha256(b"policy"),
        Generation(1),
    )?;
    params_policy.facts.push(policy_fact);
    params_policy
        .facts
        .sort_by(|a, b| a.fact_id.cmp(&b.fact_id));
    params_policy
        .provenance_classes
        .insert(ProvenanceClass::Policy);

    let synopsis_policy = H1SemanticSynopsis::new(params_policy)?;
    let policy_cells = synopsis_policy.to_knowledge_cells();
    let policy_cell = policy_cells
        .iter()
        .find(|c| c.claim_id == "fact:policy:retention")
        .ok_or("missing policy cell")?;
    assert_eq!(policy_cell.knowledge_state, KnowledgeState::Estimated);
    assert_eq!(policy_cell.provenance, ProvenanceClass::Policy);
    assert!(!policy_cell.is_irreversible_effect_premise(now));

    // Conflicted is NEVER emitted without an attached contradiction
    for cell in &policy_cells {
        if cell.knowledge_state == KnowledgeState::Conflicted {
            assert!(!cell.contradictions.is_empty());
        }
    }

    Ok(())
}

#[test]
fn test_h1_golden_digest_and_canonical_bytes() -> Result<(), Box<dyn Error>> {
    let params = sample_h1_params()?;
    let synopsis = H1SemanticSynopsis::new(params)?;

    let canonical_bytes = synopsis.to_canonical_bytes()?;

    // Pinned canonical byte vector length (Item 1)
    assert_eq!(canonical_bytes.len(), 1884);

    let bytes_digest = ContentDigest::sha256(&canonical_bytes);
    let canonical_digest = synopsis.canonical_digest()?;
    assert_eq!(bytes_digest, canonical_digest);

    // Independently derived golden digest literal (Item 1)
    let golden_canonical_digest = ContentDigest::parse(
        "sha256:fc0ce37b21b3a43c2ac6849802baf34272a082f820a21e3437edd5e904a90a39",
    )?;
    assert_eq!(canonical_digest, golden_canonical_digest);

    let artifact = synopsis.to_hydration_artifact()?;
    let golden_artifact_digest = ContentDigest::parse(
        "sha256:7bdae56122f2a4425da09ebc692ac6f59dfe1d3e933a136df6ce787d60878b6e",
    )?;
    assert_eq!(artifact.artifact_digest, golden_artifact_digest);
    artifact.verify()?;

    // Verify bit-exact roundtrip
    let decoded = H1SemanticSynopsis::from_canonical_bytes(&canonical_bytes)?;
    assert_eq!(decoded, synopsis);
    assert_eq!(decoded.canonical_digest()?, golden_canonical_digest);

    let decoded_artifact = decoded.to_hydration_artifact()?;
    assert_eq!(decoded_artifact.artifact_digest, golden_artifact_digest);
    decoded_artifact.verify()?;

    Ok(())
}

#[test]
fn test_h1_derived_knowledge_states_and_operator_asserted() -> Result<(), Box<dyn Error>> {
    let params = sample_h1_params()?;
    let synopsis = H1SemanticSynopsis::new(params)?;

    // derived_knowledge_states is the exact union of cell states
    let cells = synopsis.to_knowledge_cells();
    let expected_derived: BTreeSet<KnowledgeState> =
        cells.iter().map(|c| c.knowledge_state).collect();
    assert_eq!(synopsis.derived_knowledge_states(), expected_derived);
    assert_eq!(
        synopsis.derived_knowledge_states(),
        BTreeSet::from([KnowledgeState::Known, KnowledgeState::Estimated])
    );

    // Now test a synopsis with ONLY OperatorAsserted fact:
    // OperatorAsserted can NEVER be Known, always Estimated.
    let op_fact = WorldFact::new(
        "fact:device:operator_asserted",
        WorldFactKind::Device,
        sample_anchor(1),
        "Operator asserted fact statement",
        ProvenanceClass::OperatorAsserted,
        ContentDigest::sha256(b"op-assertion"),
        Generation(1),
    )?;

    let mut op_params = sample_h1_params()?;
    op_params.facts = vec![op_fact];
    op_params.contradictions = Vec::new();
    op_params.knowledge_states = BTreeSet::from([KnowledgeState::Estimated]);
    op_params.provenance_classes = BTreeSet::from([ProvenanceClass::OperatorAsserted]);
    let op_synopsis = H1SemanticSynopsis::new(op_params)?;

    let op_cells = op_synopsis.to_knowledge_cells();
    assert_eq!(op_cells.len(), 1);
    assert_eq!(op_cells[0].knowledge_state, KnowledgeState::Estimated);
    assert_eq!(
        op_synopsis.derived_knowledge_states(),
        BTreeSet::from([KnowledgeState::Estimated])
    );
    assert!(
        !op_synopsis
            .derived_knowledge_states()
            .contains(&KnowledgeState::Known)
    );

    Ok(())
}

#[test]
fn test_h1_redacted_only_for_fact_with_own_redaction() -> Result<(), Box<dyn Error>> {
    let mut params = sample_h1_params()?;
    // Add a redacted fact whose statement has REDACTED_STATEMENT_MARKER
    let redacted_fact = WorldFact::new(
        "fact:device:cam02:redacted",
        WorldFactKind::Device,
        sample_anchor(1),
        format!("Camera 02 {}", REDACTED_STATEMENT_MARKER),
        ProvenanceClass::Observed,
        ContentDigest::sha256(b"cam02:redacted:ev"),
        Generation(1),
    )?;
    params.facts.push(redacted_fact);
    params.facts.sort_by(|a, b| a.fact_id.cmp(&b.fact_id));
    params.knowledge_states.insert(KnowledgeState::Redacted);

    let synopsis = H1SemanticSynopsis::new(params)?;
    let cells = synopsis.to_knowledge_cells();

    // The redacted fact cell must have KnowledgeState::Redacted with RedactionMarker basis
    let red_cell = cells
        .iter()
        .find(|c| c.claim_id == "fact:device:cam02:redacted")
        .ok_or("missing redacted cell")?;
    assert_eq!(red_cell.knowledge_state, KnowledgeState::Redacted);
    assert!(matches!(
        &red_cell.state_basis,
        Some(KnowledgeStateBasis::Redaction(RedactionMarker {
            reason: RedactionReason::PrivacyProjection,
            ..
        }))
    ));
    assert!(red_cell.validate().is_ok());

    // Other un-redacted fact cells remain Known/Estimated
    let cam01_cell = cells
        .iter()
        .find(|c| c.claim_id == "fact:device:cam01")
        .ok_or("missing cam01 cell")?;
    assert_eq!(cam01_cell.knowledge_state, KnowledgeState::Known);
    assert_eq!(cam01_cell.state_basis, None);

    Ok(())
}

#[test]
fn test_h1_stale_only_for_fact_with_own_stale_basis() -> Result<(), Box<dyn Error>> {
    let mut params = sample_h1_params()?;
    params.anchor = sample_anchor(10); // current synopsis anchor has seq 10
    // Fact 1 has older anchor (seq 1)
    let stale_fact = WorldFact::new(
        "fact:device:cam_stale",
        WorldFactKind::Device,
        sample_anchor(1), // older than 10!
        "Stale camera calibration",
        ProvenanceClass::Observed,
        ContentDigest::sha256(b"cam:stale:ev"),
        Generation(1),
    )?;
    // Fact 2 has current anchor (seq 10)
    let fresh_fact = WorldFact::new(
        "fact:device:cam_fresh",
        WorldFactKind::Device,
        sample_anchor(10), // matches current!
        "Fresh camera calibration",
        ProvenanceClass::Observed,
        ContentDigest::sha256(b"cam:fresh:ev"),
        Generation(1),
    )?;
    params.facts = vec![fresh_fact, stale_fact];
    params.contradictions = Vec::new();
    params.knowledge_states = BTreeSet::from([KnowledgeState::Known, KnowledgeState::Stale]);
    params.provenance_classes = BTreeSet::from([ProvenanceClass::Observed]);

    let synopsis = H1SemanticSynopsis::new(params)?;
    let cells = synopsis.to_knowledge_cells();

    let stale_cell = cells
        .iter()
        .find(|c| c.claim_id == "fact:device:cam_stale")
        .ok_or("missing stale cell")?;
    assert_eq!(stale_cell.knowledge_state, KnowledgeState::Stale);
    assert!(matches!(
        &stale_cell.state_basis,
        Some(KnowledgeStateBasis::Stale(StaleBasis::OlderAnchor { .. }))
    ));
    assert!(stale_cell.validate().is_ok());

    let fresh_cell = cells
        .iter()
        .find(|c| c.claim_id == "fact:device:cam_fresh")
        .ok_or("missing fresh cell")?;
    assert_eq!(fresh_cell.knowledge_state, KnowledgeState::Known);
    assert_eq!(fresh_cell.state_basis, None);

    Ok(())
}

#[test]
fn test_h1_completeness_stale_caps_cells_at_stale() -> Result<(), Box<dyn Error>> {
    let mut params = sample_h1_params()?;
    params.quality = SynopsisQuality::new(
        Completeness::Stale,
        Some(BeliefInterval::new(800_000, 950_000)?),
        1_000_000,
        Some(ContentDigest::sha256(b"calibration-gen-1")),
    )?;
    params.contradictions = Vec::new();
    params.knowledge_states = BTreeSet::from([KnowledgeState::Stale]);

    let synopsis = H1SemanticSynopsis::new(params.clone())?;
    let cells = synopsis.to_knowledge_cells();
    // Every cell must be capped at Stale-with-basis
    for cell in &cells {
        assert_eq!(cell.knowledge_state, KnowledgeState::Stale);
        assert!(matches!(
            &cell.state_basis,
            Some(KnowledgeStateBasis::Stale(StaleBasis::OlderAnchor { .. }))
        ));
        assert!(cell.validate().is_ok());
    }
    assert_eq!(
        synopsis.derived_knowledge_states(),
        BTreeSet::from([KnowledgeState::Stale])
    );

    // In validate(), KnowledgeState::Known cannot be grounded when Completeness::Stale
    let mut invalid_params = params;
    invalid_params
        .knowledge_states
        .insert(KnowledgeState::Known);
    assert_eq!(
        H1SemanticSynopsis::new(invalid_params),
        Err(HydrationError::Contract(
            ContractError::KnowledgeStateBasisMismatch
        )),
        "KnowledgeState::Known must NOT be grounded when synopsis completeness is Stale"
    );

    Ok(())
}

#[test]
fn test_h1_indeterminate_only_from_own_effect_outcome() -> Result<(), Box<dyn Error>> {
    // 1. An Effect fact with own indeterminate statement gets Indeterminate with Reconciliation basis
    let effect_fact = WorldFact::new(
        "fact:effect:valve_actuation",
        WorldFactKind::Effect,
        sample_anchor(1),
        "Actuator command sent: indeterminate physical confirmation",
        ProvenanceClass::Observed,
        ContentDigest::sha256(b"actuator:valve:receipt"),
        Generation(1),
    )?;

    let mut params = sample_h1_params()?;
    params.facts.push(effect_fact);
    params.facts.sort_by(|a, b| a.fact_id.cmp(&b.fact_id));
    params
        .knowledge_states
        .insert(KnowledgeState::Indeterminate);

    let synopsis = H1SemanticSynopsis::new(params)?;
    let cells = synopsis.to_knowledge_cells();
    let effect_cell = cells
        .iter()
        .find(|c| c.claim_id == "fact:effect:valve_actuation")
        .ok_or("missing effect cell")?;
    assert_eq!(effect_cell.knowledge_state, KnowledgeState::Indeterminate);
    assert!(matches!(
        &effect_cell.state_basis,
        Some(KnowledgeStateBasis::Reconciliation(_))
    ));
    assert!(effect_cell.validate().is_ok());

    // 2. A bare Effect fact without indeterminate outcome cannot ground KnowledgeState::Indeterminate
    let bare_effect_fact = WorldFact::new(
        "fact:effect:camera_reboot",
        WorldFactKind::Effect,
        sample_anchor(1),
        "Camera reboot completed normally",
        ProvenanceClass::Observed,
        ContentDigest::sha256(b"camera:reboot:ok"),
        Generation(1),
    )?;
    let mut bare_params = sample_h1_params()?;
    bare_params.facts = vec![bare_effect_fact];
    bare_params.contradictions = Vec::new(); // No contradictions
    bare_params.knowledge_states = BTreeSet::from([KnowledgeState::Indeterminate]);
    bare_params.provenance_classes = BTreeSet::from([ProvenanceClass::Observed]);

    assert_eq!(
        H1SemanticSynopsis::new(bare_params),
        Err(HydrationError::Contract(
            ContractError::KnowledgeStateBasisMismatch
        )),
        "Bare Effect fact without indeterminate outcome must not ground KnowledgeState::Indeterminate"
    );

    Ok(())
}

#[test]
fn test_h1_count_bound_exceeded_via_new() -> Result<(), Box<dyn Error>> {
    // 1. Over-limit capabilities through new() returns CountBoundExceeded
    let mut params_cap = sample_h1_params()?;
    for i in 0..=(MAX_H1_CAPABILITIES + 1) {
        params_cap
            .required_capabilities
            .insert(format!("capability:test:overlimit:{i:04}"));
    }
    assert_eq!(
        H1SemanticSynopsis::new(params_cap),
        Err(HydrationError::CapacityExceeded),
        "Over-limit capabilities must return CountBoundExceeded via new()"
    );

    // 2. Over-limit facts through new() returns CountBoundExceeded
    let mut params_facts = sample_h1_params()?;
    let mut oversized_facts = Vec::new();
    for i in 0..=(MAX_H1_FACTS + 1) {
        oversized_facts.push(WorldFact::new(
            format!("fact:device:{i:06}"),
            WorldFactKind::Device,
            sample_anchor(1),
            "Fact statement",
            ProvenanceClass::Observed,
            ContentDigest::sha256(format!("ev:{i}").as_bytes()),
            Generation(1),
        )?);
    }
    params_facts.facts = oversized_facts;
    assert_eq!(
        H1SemanticSynopsis::new(params_facts),
        Err(HydrationError::CapacityExceeded),
        "Over-limit facts must return CountBoundExceeded via new()"
    );

    // 3. Over-limit contradictions through new() returns CountBoundExceeded
    let mut params_contra = sample_h1_params()?;
    let mut oversized_contra = Vec::new();
    for i in 0..=(MAX_H1_CONTRADICTIONS + 1) {
        oversized_contra.push(Contradiction::new(ContradictionParams {
            contradiction_id: format!("contra:test:{i:06}"),
            conflicting_evidence: BTreeSet::from([
                ContentDigest::sha256(b"e1"),
                ContentDigest::sha256(b"e2"),
            ]),
            failure_domains: BTreeSet::from(["domain:a".to_string(), "domain:b".to_string()]),
            unresolved_worlds: BTreeSet::from(["world:a".to_string()]),
            claim_id: None,
            statement: "Contradiction statement".to_string(),
            belief_interval: None,
            created_at: TimestampNs(100),
            knowledge_state: KnowledgeState::Conflicted,
            provenance: ProvenanceClass::Derived,
            disposition: HypothesisDisposition::Live,
            outcome: RuntimeOutcome::Indeterminate,
        })?);
    }
    params_contra.contradictions = oversized_contra;
    assert_eq!(
        H1SemanticSynopsis::new(params_contra),
        Err(HydrationError::CapacityExceeded),
        "Over-limit contradictions must return CountBoundExceeded via new()"
    );

    Ok(())
}

#[test]
fn test_h1_decode_byte_truncation_returns_invalid_digest() -> Result<(), Box<dyn Error>> {
    let params = sample_h1_params()?;
    let synopsis = H1SemanticSynopsis::new(params)?;

    // Encode a valid prefix up to the facts count
    let mut enc = CanonicalEncoder::new();
    enc.text(H1_SCHEMA);
    enc.text(synopsis.handle_id());
    enc.text(synopsis.subject_id());
    enc.digest(synopsis.subject_digest());
    enc.text(synopsis.semantic_type());
    synopsis.classification().encode_canonical(&mut enc);
    synopsis.anchor().encode_canonical(&mut enc);
    synopsis.contract_basis().encode_canonical(&mut enc);
    synopsis.estimated_cost().encode_canonical(&mut enc);
    enc.u64(synopsis.required_capabilities().len() as u64);
    for cap in synopsis.required_capabilities() {
        enc.text(cap);
    }
    enc.text(synopsis.privacy_class());
    synopsis.published_at().encode_canonical(&mut enc);
    synopsis.retention_until().encode_canonical(&mut enc);
    synopsis.quality().encode_canonical(&mut enc);

    // Case 1: facts count = 50 (within MAX_H1_FACTS=1024), but buffer has 0 remaining bytes
    let mut bad_facts_trunc = enc.clone();
    bad_facts_trunc.u64(50); // raw_count <= MAX_H1_FACTS, but remaining is 0
    let bytes_facts_trunc = bad_facts_trunc.finish_checked()?;
    let mut dec_facts = CanonicalDecoder::new(&bytes_facts_trunc);
    assert_eq!(
        H1SemanticSynopsis::decode_canonical(&mut dec_facts).err(),
        Some(ContractError::InvalidDigest),
        "Facts byte truncation must return InvalidDigest, NOT CountBoundExceeded"
    );

    // Case 2: knowledge states count = 10 (within MAX_H1_KNOWLEDGE_STATES=16), but buffer truncated
    let mut bad_ks_trunc = enc.clone();
    bad_ks_trunc.u64(0); // 0 facts
    bad_ks_trunc.u64(10); // raw_count <= MAX_H1_KNOWLEDGE_STATES, remaining is 0
    let bytes_ks_trunc = bad_ks_trunc.finish_checked()?;
    let mut dec_ks = CanonicalDecoder::new(&bytes_ks_trunc);
    assert_eq!(
        H1SemanticSynopsis::decode_canonical(&mut dec_ks).err(),
        Some(ContractError::InvalidDigest),
        "Knowledge states byte truncation must return InvalidDigest, NOT CountBoundExceeded"
    );

    // Case 3: provenance classes count = 10 (within MAX_H1_PROVENANCE_CLASSES=16), but buffer truncated
    let mut bad_prov_trunc = enc.clone();
    bad_prov_trunc.u64(0); // 0 facts
    bad_prov_trunc.u64(1); // 1 ks
    KnowledgeState::Known.encode_canonical(&mut bad_prov_trunc);
    bad_prov_trunc.u64(10); // raw_count <= MAX_H1_PROVENANCE_CLASSES, remaining is 0
    let bytes_prov_trunc = bad_prov_trunc.finish_checked()?;
    let mut dec_prov = CanonicalDecoder::new(&bytes_prov_trunc);
    assert_eq!(
        H1SemanticSynopsis::decode_canonical(&mut dec_prov).err(),
        Some(ContractError::InvalidDigest),
        "Provenance classes byte truncation must return InvalidDigest, NOT CountBoundExceeded"
    );

    // Case 4: contradictions count = 50 (within MAX_H1_CONTRADICTIONS=1024), but buffer truncated
    let mut bad_contra_trunc = enc.clone();
    bad_contra_trunc.u64(0); // 0 facts
    bad_contra_trunc.u64(1); // 1 ks
    KnowledgeState::Known.encode_canonical(&mut bad_contra_trunc);
    bad_contra_trunc.u64(1); // 1 prov
    ProvenanceClass::Observed.encode_canonical(&mut bad_contra_trunc);
    bad_contra_trunc.u64(50); // raw_count <= MAX_H1_CONTRADICTIONS, remaining is 0
    let bytes_contra_trunc = bad_contra_trunc.finish_checked()?;
    let mut dec_contra = CanonicalDecoder::new(&bytes_contra_trunc);
    assert_eq!(
        H1SemanticSynopsis::decode_canonical(&mut dec_contra).err(),
        Some(ContractError::InvalidDigest),
        "Contradictions byte truncation must return InvalidDigest, NOT CountBoundExceeded"
    );

    // Case 5: omissions count = 10 (within MAX_H1_OMISSIONS=64), but buffer truncated
    let mut bad_omiss_trunc = enc.clone();
    bad_omiss_trunc.u64(0); // 0 facts
    bad_omiss_trunc.u64(1); // 1 ks
    KnowledgeState::Known.encode_canonical(&mut bad_omiss_trunc);
    bad_omiss_trunc.u64(1); // 1 prov
    ProvenanceClass::Observed.encode_canonical(&mut bad_omiss_trunc);
    bad_omiss_trunc.u64(0); // 0 contra
    bad_omiss_trunc.u64(10); // raw_count <= MAX_H1_OMISSIONS, remaining is 0
    let bytes_omiss_trunc = bad_omiss_trunc.finish_checked()?;
    let mut dec_omiss = CanonicalDecoder::new(&bytes_omiss_trunc);
    assert_eq!(
        H1SemanticSynopsis::decode_canonical(&mut dec_omiss).err(),
        Some(ContractError::InvalidDigest),
        "Omissions byte truncation must return InvalidDigest, NOT CountBoundExceeded"
    );

    Ok(())
}

#[test]
fn test_h1_kill_mutants_x14c_and_x14d() -> Result<(), Box<dyn Error>> {
    // Mutant X14c: OperatorAsserted fact erroneously promoted to Known when Known is declared in knowledge_states
    let op_fact = WorldFact::new(
        "fact:device:op_only",
        WorldFactKind::Device,
        sample_anchor(1),
        "Operator assertion only",
        ProvenanceClass::OperatorAsserted,
        ContentDigest::sha256(b"op_evidence"),
        Generation(1),
    )?;
    let mut params_x14c = sample_h1_params()?;
    params_x14c.facts = vec![op_fact];
    params_x14c.contradictions = Vec::new();
    params_x14c.knowledge_states = BTreeSet::from([KnowledgeState::Estimated]);
    params_x14c.provenance_classes = BTreeSet::from([ProvenanceClass::OperatorAsserted]);
    let syn_x14c = H1SemanticSynopsis::new(params_x14c)?;

    let cells = syn_x14c.to_knowledge_cells();
    assert_eq!(cells.len(), 1);
    // MUST be Estimated, NEVER Known
    assert_eq!(cells[0].knowledge_state, KnowledgeState::Estimated);
    assert_ne!(cells[0].knowledge_state, KnowledgeState::Known);
    assert_eq!(
        syn_x14c.derived_knowledge_states(),
        BTreeSet::from([KnowledgeState::Estimated])
    );

    // Mutant X14d: Bare Effect fact without indeterminate outcome erroneously grounds KnowledgeState::Indeterminate
    let bare_effect = WorldFact::new(
        "fact:effect:normal_action",
        WorldFactKind::Effect,
        sample_anchor(1),
        "Normal effect completed without issue",
        ProvenanceClass::Observed,
        ContentDigest::sha256(b"effect_ok"),
        Generation(1),
    )?;
    let mut params_x14d = sample_h1_params()?;
    params_x14d.facts = vec![bare_effect];
    params_x14d.contradictions = Vec::new();
    params_x14d.knowledge_states = BTreeSet::from([KnowledgeState::Indeterminate]);
    params_x14d.provenance_classes = BTreeSet::from([ProvenanceClass::Observed]);

    // Must be rejected in validate() because bare effect cannot ground Indeterminate
    let res_x14d = H1SemanticSynopsis::new(params_x14d);
    assert_eq!(
        res_x14d,
        Err(HydrationError::Contract(
            ContractError::KnowledgeStateBasisMismatch
        )),
        "Mutant X14d killed: bare effect cannot ground Indeterminate"
    );

    Ok(())
}
