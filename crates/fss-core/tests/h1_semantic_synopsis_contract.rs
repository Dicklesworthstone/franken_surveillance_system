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
    H1SynopsisParams, HandleAvailability, HydrationError, HydrationLevel, HypothesisDisposition,
    KnowledgeState, LaboratoryAccess, LedgerAnchor, OmissionReason, ProvenanceClass,
    RuntimeOutcome, SemanticHandle, SemanticHandleSpec, SynopsisClassification, SynopsisQuality,
    TimestampNs, WorldFact, WorldFactKind,
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
        knowledge_states: BTreeSet::from([KnowledgeState::Known, KnowledgeState::Conflicted]),
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
    assert_eq!(synopsis.owner(), "fss-situation/fss-context-pack");
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
        assert_eq!(cell.knowledge_state, KnowledgeState::Known);
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

    let bytes = synopsis.to_canonical_bytes();
    assert!(!bytes.is_empty());

    let decoded = H1SemanticSynopsis::from_canonical_bytes(&bytes)?;
    assert_eq!(decoded, synopsis);
    assert_eq!(decoded.canonical_digest(), synopsis.canonical_digest());

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
        knowledge_states: BTreeSet::from([KnowledgeState::Known, KnowledgeState::Conflicted]),
        provenance_classes: BTreeSet::from([ProvenanceClass::Observed, ProvenanceClass::Derived]),
        contradictions: vec![contra],
        quality,
        omissions: BTreeSet::new(),
        classification: Some(SynopsisClassification::EpistemicBeliefSynopsis),
    };

    let synopsis = handle.to_h1_synopsis(spec)?;
    assert_eq!(synopsis.handle_id, handle.handle_id);
    assert_eq!(synopsis.subject_id, handle.subject_id);
    assert_eq!(synopsis.subject_digest, handle.subject_digest);
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
        let bytes = enc.finish();
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
