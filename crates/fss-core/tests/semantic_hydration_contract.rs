//! Contract tests for semantic hydration.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    BeliefInterval, BudgetVector, CanonicalEncode, CanonicalEncoder, Completeness, ContentDigest,
    ContinuationCursor, ContinuationCursorPublishParams, ContinuationScope, ContractBasis,
    ContractBasisRegistryBytes, ContractError, Contradiction, ContradictionParams, Generation,
    H0Identity, H0IdentityParams, H0_CONTENT, H0_LEVEL_ID, H0_LEVEL_NAME, H1ContentSpec,
    H1SemanticSynopsis, H1SynopsisParams, H1_CONTENT, H1_LEVEL_ID, H1_LEVEL_NAME, H1_OWNER,
    HYDRATION_VIEW_ID, HandleAvailability, HydrationArtifact, HydrationError, HydrationLevel,
    HydrationPurpose, HydrationReceipt, HydrationReceiptSpec, HydrationRequest,
    HydrationRequestSpec, HypothesisDisposition, LaboratoryAccess, LedgerAnchor, KnowledgeState,
    OmissionReason, ProvenanceClass, RuntimeOutcome, SemanticHandle, SemanticHandleSpec, SessionId,
    SynopsisClassification, SynopsisQuality, TimestampNs, WorldFact, WorldFactKind,
};

fn basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
        b"schemas",
        b"operations",
        b"views",
        b"capabilities",
        b"errors",
        b"costs",
        "fss-hydration-contract:test",
    ))
}

fn anchor() -> LedgerAnchor {
    let mut anchor = LedgerAnchor::genesis("site:hydration-contract");
    anchor.commit_sequence = 7;
    anchor
}

fn levels() -> BTreeSet<HydrationLevel> {
    BTreeSet::from([HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2])
}

fn capabilities() -> BTreeMap<HydrationLevel, BTreeSet<String>> {
    BTreeMap::from([
        (
            HydrationLevel::H0,
            BTreeSet::from(["capability:hydrate:h0".to_owned()]),
        ),
        (
            HydrationLevel::H1,
            BTreeSet::from(["capability:hydrate:h1".to_owned()]),
        ),
        (
            HydrationLevel::H2,
            BTreeSet::from(["capability:hydrate:h2".to_owned()]),
        ),
    ])
}

fn costs() -> Result<BTreeMap<HydrationLevel, BudgetVector>, ContractError> {
    Ok(BTreeMap::from([
        (
            HydrationLevel::H0,
            BudgetVector::builder()
                .latency_ms(5)
                .tokens(32)
                .bytes(256)
                .cpu_millis(1)
                .build()?,
        ),
        (
            HydrationLevel::H1,
            BudgetVector::builder()
                .latency_ms(10)
                .tokens(128)
                .bytes(1_024)
                .cpu_millis(2)
                .privacy_exposure(0.1)
                .build()?,
        ),
        (
            HydrationLevel::H2,
            BudgetVector::builder()
                .latency_ms(20)
                .tokens(256)
                .bytes(4_096)
                .cpu_millis(4)
                .privacy_exposure(0.2)
                .build()?,
        ),
    ]))
}

fn handle() -> Result<SemanticHandle, HydrationError> {
    SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: basis(),
        anchor: anchor(),
        subject_id: "evidence:hydration-contract".to_owned(),
        subject_digest: ContentDigest::sha256(b"immutable subject"),
        semantic_type: "evidence_bundle".to_owned(),
        source_id: "sensor:hydration-contract".to_owned(),
        capture_interval: None,
        spatial_scope: Some("zone:rear".to_owned()),
        privacy_class: "private:property".to_owned(),
        applied_transform: None,
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(10_000),
        levels: levels(),
        required_capabilities: capabilities(),
        estimated_costs: costs()?,
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })
}

fn make_request(
    handle: &SemanticHandle,
    level: HydrationLevel,
    continuation: Option<ContinuationCursor>,
) -> Result<HydrationRequest, HydrationError> {
    HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:hydration-contract")?,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: level,
        allow_lower_level: false,
        available_capabilities: capabilities().into_values().flatten().collect(),
        authorized_privacy_classes: BTreeSet::from(["private:property".to_owned()]),
        budget: costs()?
            .get(&level)
            .copied()
            .ok_or(HydrationError::LevelUnavailable)?,
        purpose: HydrationPurpose::IncidentAdjudication,
        continuation,
        issued_at: TimestampNs(20),
    })
}

#[test]
fn public_receipt_closes_over_request_handle_and_artifact() -> Result<(), HydrationError> {
    let handle = handle()?;
    let request = make_request(&handle, HydrationLevel::H1, None)?;
    let artifact = HydrationArtifact::publish(
        HydrationLevel::H1,
        "application/fss+json",
        b"bounded semantic synopsis".to_vec(),
        [handle.subject_digest],
        Completeness::Complete,
        None,
    )?;
    let cursor = ContinuationCursor::publish(ContinuationCursorPublishParams {
        scope: ContinuationScope::EvidenceHydration,
        stream_id: handle.handle_id.clone(),
        contract_basis: handle.contract_basis.clone(),
        session_id: request.session_id.clone(),
        view_id: HYDRATION_VIEW_ID.to_owned(),
        basis_anchor: handle.anchor.clone(),
        resume_anchor: handle.anchor.clone(),
        source_digest: handle.ladder_policy_digest(),
        position: 2,
        upper_bound: 3,
        selection_witness: artifact.artifact_digest,
        predecessor_digest: None,
        issued_at: TimestampNs(20),
        expires_at: TimestampNs(1_000),
    })?;
    let mut proof_roots = artifact.proof_roots.clone();
    proof_roots.insert(artifact.artifact_digest);
    proof_roots.insert(handle.descriptor_digest);
    proof_roots.insert(request.request_digest);
    let receipt = HydrationReceipt::publish(HydrationReceiptSpec {
        request_digest: request.request_digest,
        handle_id: handle.handle_id.clone(),
        descriptor_digest: handle.descriptor_digest,
        subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: HydrationLevel::H1,
        delivered_level: Some(HydrationLevel::H1),
        availability: HandleAvailability::Available,
        cost: handle
            .estimated_cost(HydrationLevel::H1)
            .ok_or(HydrationError::LevelUnavailable)?,
        completeness: Completeness::Complete,
        artifact_digest: Some(artifact.artifact_digest),
        proof_roots,
        continuation: Some(cursor.clone()),
        invalidators: BTreeSet::from([
            format!("descriptor:{}", handle.descriptor_digest),
            "retention-expiry".to_owned(),
        ]),
        issued_at: TimestampNs(20),
    })?;

    receipt.validate_for(&request, &handle, Some(&artifact))?;
    let next = make_request(&handle, HydrationLevel::H2, Some(cursor))?;
    next.verify()?;
    Ok(())
}

#[test]
fn receipt_rejects_subject_substitution() -> Result<(), HydrationError> {
    let handle = handle()?;
    let request = make_request(&handle, HydrationLevel::H0, None)?;
    let artifact = HydrationArtifact::publish(
        HydrationLevel::H0,
        "application/fss+json",
        b"identity metadata".to_vec(),
        [handle.subject_digest],
        Completeness::Complete,
        None,
    )?;
    let mut proof_roots = artifact.proof_roots.clone();
    proof_roots.insert(artifact.artifact_digest);
    proof_roots.insert(handle.descriptor_digest);
    proof_roots.insert(request.request_digest);
    let mut receipt = HydrationReceipt::publish(HydrationReceiptSpec {
        request_digest: request.request_digest,
        handle_id: handle.handle_id.clone(),
        descriptor_digest: handle.descriptor_digest,
        subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: HydrationLevel::H0,
        delivered_level: Some(HydrationLevel::H0),
        availability: HandleAvailability::Available,
        cost: handle
            .estimated_cost(HydrationLevel::H0)
            .ok_or(HydrationError::LevelUnavailable)?,
        completeness: Completeness::Complete,
        artifact_digest: Some(artifact.artifact_digest),
        proof_roots,
        continuation: None,
        invalidators: BTreeSet::from(["descriptor-revision".to_owned()]),
        issued_at: TimestampNs(20),
    })?;
    receipt.subject_digest = ContentDigest::sha256(b"substituted subject");

    assert!(matches!(
        receipt.validate_for(&request, &handle, Some(&artifact)),
        Err(HydrationError::Contract(ContractError::DigestMismatch))
    ));
    Ok(())
}

fn sample_contradiction() -> Result<Contradiction, HydrationError> {
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
        statement: "Optical sensor reports presence while RF radar reports clear sector".to_string(),
        belief_interval: Some(BeliefInterval::new(100_000, 900_000).map_err(ContractError::from)?),
        created_at: TimestampNs(1_000_000),
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::Derived,
        disposition: HypothesisDisposition::Live,
        outcome: RuntimeOutcome::Indeterminate,
    };
    Contradiction::new(params).map_err(|e| HydrationError::Contract(ContractError::from(e)))
}

fn sample_facts() -> Result<Vec<WorldFact>, ContractError> {
    let f1 = WorldFact::new(
        "fact:device:cam01",
        WorldFactKind::Device,
        anchor(),
        "Camera 01 active and calibrated",
        ProvenanceClass::Observed,
        ContentDigest::sha256(b"device:cam01:calib"),
        Generation(1),
    )?;
    let f2 = WorldFact::new(
        "fact:geometry:zone_a",
        WorldFactKind::Geometry,
        anchor(),
        "Zone A boundary verified",
        ProvenanceClass::Derived,
        ContentDigest::sha256(b"geom:zone_a"),
        Generation(1),
    )?;
    Ok(vec![f1, f2])
}

fn sample_h1_params() -> Result<H1SynopsisParams, HydrationError> {
    let facts = sample_facts().map_err(HydrationError::Contract)?;
    let contra = sample_contradiction()?;
    let quality = SynopsisQuality::new(
        Completeness::Complete,
        Some(BeliefInterval::new(800_000, 950_000).map_err(ContractError::from)?),
        1_000_000,
        Some(ContentDigest::sha256(b"calibration-gen-1")),
    )?;

    Ok(H1SynopsisParams {
        handle_id: "semantic-handle:sha256:test1".to_string(),
        subject_id: "evidence:hydration-test".to_string(),
        subject_digest: ContentDigest::sha256(b"immutable subject"),
        semantic_type: "semantic_synopsis".to_string(),
        classification: SynopsisClassification::SemanticSynopsis,
        anchor: anchor(),
        contract_basis: basis(),
        estimated_cost: BudgetVector::builder()
            .latency_ms(10)
            .tokens(128)
            .bytes(1024)
            .build()
            .map_err(HydrationError::Contract)?,
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

#[test]
fn test_h0_identity_contract() -> Result<(), HydrationError> {
    let h = handle()?;
    let h0 = h.to_h0_identity()?;

    assert_eq!(h0.level(), HydrationLevel::H0);
    assert_eq!(h0.level_id(), H0_LEVEL_ID);
    assert_eq!(h0.level_name(), H0_LEVEL_NAME);
    assert_eq!(h0.content_declaration(), H0_CONTENT);
    assert_eq!(h0.subject_id, "evidence:hydration-contract");
    assert_eq!(h0.subject_digest, h.subject_digest);
    assert!(!h0.is_expired_at(TimestampNs(5_000)));
    assert!(h0.is_expired_at(TimestampNs(15_000)));

    let mut encoder = CanonicalEncoder::new();
    h0.encode_canonical(&mut encoder);
    let bytes = encoder.finish();

    let decoded = H0Identity::from_canonical_bytes(&bytes).map_err(HydrationError::Contract)?;
    assert_eq!(decoded, h0);
    assert_eq!(decoded.canonical_digest(), h0.canonical_digest());
    Ok(())
}

#[test]
fn test_h1_semantic_synopsis_contract() -> Result<(), HydrationError> {
    let params = sample_h1_params()?;
    let synopsis = H1SemanticSynopsis::new(params.clone())?;

    // Verify accessors and normative bindings
    assert_eq!(synopsis.level(), HydrationLevel::H1);
    assert_eq!(synopsis.level_id(), H1_LEVEL_ID);
    assert_eq!(synopsis.level_name(), H1_LEVEL_NAME);
    assert_eq!(synopsis.content_declaration(), H1_CONTENT);
    assert_eq!(synopsis.owner(), H1_OWNER);
    assert_eq!(synopsis.classification(), SynopsisClassification::SemanticSynopsis);
    assert_eq!(synopsis.facts().len(), 2);
    assert!(synopsis.fact("fact:device:cam01").is_some());
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
    assert!(synopsis.omissions().contains(&OmissionReason::PrivacyRedaction));
    assert!(!synopsis.is_expired_at(TimestampNs(500)));
    assert!(synopsis.is_expired_at(TimestampNs(20_000)));
    assert!(synopsis.requires_capability("capability:hydrate:h1"));
    assert!(!synopsis.requires_capability("capability:unknown"));

    // Knowledge cell generation binds real evidence digests
    let cells = synopsis.to_knowledge_cells();
    assert_eq!(cells.len(), 2);
    for cell in &cells {
        assert_eq!(cell.state, KnowledgeState::Known);
        assert_eq!(cell.evidence.len(), 2);
        assert!(!cell.statement.is_empty());
    }

    // Binary canonical serialization round-trip
    let mut encoder = CanonicalEncoder::new();
    synopsis.encode_canonical(&mut encoder);
    let bytes = encoder.finish();

    let decoded = H1SemanticSynopsis::from_canonical_bytes(&bytes).map_err(HydrationError::Contract)?;
    assert_eq!(decoded, synopsis);
    assert_eq!(decoded.canonical_digest(), synopsis.canonical_digest());
    Ok(())
}

#[test]
fn test_h1_extract_from_semantic_handle() -> Result<(), HydrationError> {
    let h = handle()?;
    let facts = sample_facts().map_err(HydrationError::Contract)?;
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

    let synopsis = h.to_h1_synopsis(spec)?;
    assert_eq!(synopsis.handle_id, h.handle_id);
    assert_eq!(synopsis.subject_id, h.subject_id);
    assert_eq!(synopsis.subject_digest, h.subject_digest);
    assert_eq!(synopsis.classification(), SynopsisClassification::EpistemicBeliefSynopsis);
    assert!(!synopsis.has_omissions());
    Ok(())
}

#[test]
fn test_h1_planted_prohibited_classifications_fail() -> Result<(), HydrationError> {
    let mut params = sample_h1_params()?;

    let prohibited = [
        SynopsisClassification::ProhibitedRawPayload,
        SynopsisClassification::ProhibitedDecodedMedia,
        SynopsisClassification::ProhibitedDecisionArtifact,
        SynopsisClassification::ProhibitedLaboratoryReplay,
    ];

    for p in prohibited {
        params.classification = p;
        let res = H1SemanticSynopsis::new(params.clone());
        assert!(matches!(
            res,
            Err(HydrationError::Contract(ContractError::ProhibitedEvidencePromotion))
        ));
    }
    Ok(())
}

#[test]
fn test_h1_planted_non_canonical_facts_fail() -> Result<(), HydrationError> {
    let mut params = sample_h1_params()?;
    // Reverse facts order so it violates canonical ascending fact_id sort
    params.facts.reverse();

    let res = H1SemanticSynopsis::new(params);
    assert!(matches!(
        res,
        Err(HydrationError::Contract(ContractError::NonCanonicalOrdering))
    ));
    Ok(())
}

#[test]
fn test_h1_planted_fact_provenance_not_declared_fails() -> Result<(), HydrationError> {
    let mut params = sample_h1_params()?;
    // Remove Derived from declared provenance_classes while fact:geometry:zone_a has ProvenanceClass::Derived
    params.provenance_classes.remove(&ProvenanceClass::Derived);

    let res = H1SemanticSynopsis::new(params);
    assert!(matches!(
        res,
        Err(HydrationError::Contract(ContractError::ProhibitedEvidencePromotion))
    ));
    Ok(())
}

#[test]
fn test_h1_planted_omission_none_fails() -> Result<(), HydrationError> {
    let mut params = sample_h1_params()?;
    // OmissionReason::None is invalid as an explicit omission reason
    params.omissions.insert(OmissionReason::None);

    let res = H1SemanticSynopsis::new(params);
    assert!(matches!(
        res,
        Err(HydrationError::Contract(ContractError::InvalidIdentifier))
    ));
    Ok(())
}

#[test]
fn test_h1_planted_expired_retention_fails() -> Result<(), HydrationError> {
    let mut params = sample_h1_params()?;
    // retention_until before published_at
    params.retention_until = TimestampNs(50);
    params.published_at = TimestampNs(100);

    let res = H1SemanticSynopsis::new(params);
    assert!(matches!(
        res,
        Err(HydrationError::ContinuationExpired)
    ));
    Ok(())
}

#[test]
fn test_h1_planted_zero_subject_digest_fails() -> Result<(), HydrationError> {
    let mut params = sample_h1_params()?;
    params.subject_digest = ContentDigest::from([0u8; 32]);

    let res = H1SemanticSynopsis::new(params);
    assert!(matches!(
        res,
        Err(HydrationError::Contract(ContractError::InvalidDigest))
    ));
    Ok(())
}
