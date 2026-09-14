#![forbid(unsafe_code)]
//! Deterministic contract tests for agent abstraction layers:
//! - AGT-LAYER-003: world_facts_and_coverage (INV-063)
//! - AGT-LAYER-004: derived_beliefs (INV-069)

use std::collections::BTreeSet;
use std::error::Error;
use std::str::FromStr;

use fss_core::abstraction::{AuthorityAnchor, AuthorityContext, CurrentAnchorSource};
use fss_core::belief::BeliefInterval;
use fss_core::effect::{Obligation, ObligationState};
use fss_core::region::{
    ContextAuthority, QuiescenceProof, RegionId, RegionKind, RegionState, RootAuthoritySpec,
};
use fss_core::{
    AGENT_ABSTRACTION_FREEZE_DIGEST, AGENT_ABSTRACTION_GENERATION, AgentAbstractionLayer, BatchId,
    BudgetVector, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CapsuleId,
    CaptureInterval, ClockBasis, Completeness, ContentDigest, ContractError, CoverageContinuity,
    CoverageStopReason, CoverageWitness, DerivedBelief, DerivedBeliefParams, DigestAlgorithm,
    EvidenceDelta, Generation, KnowledgeState, KnowledgeStateBasis, LedgerAnchor,
    NegativeReadClaim, NegativeReadOutcome, ObjectId, ObligationId, OmissionReason, OperationId,
    Plane, PrivacyGeneration, ProvenanceClass, RUNTIME_AUTHORITY_DOMAIN, RedactionMarker,
    RedactionReason, ReferenceLedger, RuntimeAuthorityAndCustody, RuntimeAuthorityAndCustodyRecord,
    RuntimeAuthorityParams, RuntimeAuthorityRecord, RuntimeGrant,
    SOURCE_EVIDENCE_RECORD_FORMAT_VERSION, SensorCapsule, SensorId, SourceCustody,
    SourceEvidenceClassification, SourceEvidenceParams, SourceEvidenceRecord, StreamId,
    TimestampNs, UnknownReason, WorldFact, WorldFactKind, evaluate_negative_read,
};

#[test]
fn test_normative_agent_abstraction_layers_census() -> Result<(), Box<dyn Error>> {
    let all = AgentAbstractionLayer::ALL;
    assert_eq!(all.len(), 11);

    // Verify canonical tower ordering and stable IDs
    let expected_ids = [
        "AGT-LAYER-001",
        "AGT-LAYER-002",
        "AGT-LAYER-003",
        "AGT-LAYER-004",
        "AGT-LAYER-005",
        "AGT-LAYER-006",
        "AGT-LAYER-007",
        "AGT-LAYER-008",
        "AGT-LAYER-009",
        "AGT-LAYER-010",
        "AGT-LAYER-011",
    ];

    let expected_names = [
        "runtime_authority_and_custody",
        "source_evidence",
        "world_facts_and_coverage",
        "derived_beliefs",
        "situation_capsule",
        "investigation_and_hypotheses",
        "affordance_frontier",
        "plan_and_effect",
        "outcome_and_episode",
        "learning_and_memory",
        "workspace_and_handoff",
    ];

    for (i, layer) in all.iter().enumerate() {
        assert_eq!(layer.id(), expected_ids[i]);
        assert_eq!(layer.name(), expected_names[i]);
        assert_eq!(layer.tower_level(), i as u8);
        assert_eq!(layer.status(), "normative");
        assert!(!layer.owner().is_empty());
        assert!(!layer.agent_question().is_empty());
        assert!(!layer.output().is_empty());
        assert!(!layer.prohibition().is_empty());
        assert!(!layer.invariant().is_empty());
    }

    Ok(())
}

#[test]
fn test_pinned_generation_and_freeze_digest_constants() -> Result<(), Box<dyn Error>> {
    use fss_core::{
        AGENT_ABSTRACTIONS_FREEZE_DIGEST, AGENT_ABSTRACTIONS_GENERATION, CANONICAL_LAYERS,
    };

    assert_eq!(AGENT_ABSTRACTIONS_GENERATION, "gen:fss1:abstraction-v1");
    assert_eq!(
        AGENT_ABSTRACTIONS_FREEZE_DIGEST,
        "sha256:98dfe512d870a36079fe49435d1f53d669c63a0034d03a771248fbab0abf34a9"
    );
    assert_eq!(CANONICAL_LAYERS.len(), 11);
    assert_eq!(
        CANONICAL_LAYERS[0],
        AgentAbstractionLayer::RuntimeAuthorityAndCustody
    );
    assert_eq!(
        CANONICAL_LAYERS[10],
        AgentAbstractionLayer::WorkspaceAndHandoff
    );

    Ok(())
}

#[test]
fn test_derived_beliefs_row_properties() -> Result<(), Box<dyn Error>> {
    let layer = AgentAbstractionLayer::DerivedBeliefs;

    // 1. Exact normative stable ID
    assert_eq!(layer.id(), "AGT-LAYER-004");

    // 2. Exact normative schema name
    assert_eq!(layer.name(), "derived_beliefs");
    assert_eq!(format!("{layer}"), "derived_beliefs");

    // 3. Exact normative owner
    assert_eq!(layer.owner(), "fss-perception/fss-association/fss-graph");

    // 4. Exact normative question
    assert_eq!(
        layer.agent_question(),
        "What entities, tracks, events, relations, and uncertainties are supported?"
    );

    // 5. Exact normative output
    assert_eq!(
        layer.output(),
        "Generation-pinned derived beliefs and graph/search projections with receipts."
    );

    // 6. Exact normative prohibition
    assert_eq!(
        layer.prohibition(),
        "Cannot authorize effects or certify absence beyond coverage."
    );

    // 7. Exact normative invariant
    assert_eq!(layer.invariant(), "INV-069");

    // 8. Exact normative status
    assert_eq!(layer.status(), "normative");

    // 9. Semantic plane: Cognition (strictly non-authority)
    assert_eq!(layer.plane(), Plane::Cognition);

    // 10. Tower level: L3 (0-indexed: 3)
    assert_eq!(layer.tower_level(), 3);

    // 11. Constitutional non-authority gates:
    // A derived layer can NEVER claim authority (AGENTS.md)
    assert!(!layer.may_claim_authority());

    // A derived layer can NEVER authorize effects (INV-069)
    assert!(!layer.may_authorize_effects());

    // Derived state is anchor-pinned and rebuildable from canonical history (INV-069)
    assert!(layer.is_anchor_pinned_rebuildable());

    Ok(())
}

#[test]
fn test_derived_beliefs_parse_and_resolution() -> Result<(), Box<dyn Error>> {
    // Parse from stable ID
    let from_id = AgentAbstractionLayer::from_id("AGT-LAYER-004")?;
    assert_eq!(from_id, AgentAbstractionLayer::DerivedBeliefs);

    // Parse from schema name
    let from_name = AgentAbstractionLayer::from_name("derived_beliefs")?;
    assert_eq!(from_name, AgentAbstractionLayer::DerivedBeliefs);

    // Parse via FromStr with stable ID
    let from_str_id = AgentAbstractionLayer::from_str("AGT-LAYER-004")?;
    assert_eq!(from_str_id, AgentAbstractionLayer::DerivedBeliefs);

    // Parse via FromStr with schema name
    let from_str_name = AgentAbstractionLayer::from_str("derived_beliefs")?;
    assert_eq!(from_str_name, AgentAbstractionLayer::DerivedBeliefs);

    // Parse from tower level
    let from_level = AgentAbstractionLayer::from_tower_level(3)?;
    assert_eq!(from_level, AgentAbstractionLayer::DerivedBeliefs);

    // Unknown ID fails closed
    let unknown_id = AgentAbstractionLayer::from_id("AGT-LAYER-999");
    assert!(unknown_id.is_err());

    // Unknown name fails closed
    let unknown_name = AgentAbstractionLayer::from_name("arbitrary_cognition");
    assert!(unknown_name.is_err());

    // Out-of-bounds level fails closed
    let bad_level = AgentAbstractionLayer::from_tower_level(100);
    assert!(bad_level.is_err());

    Ok(())
}

#[test]
fn test_agent_abstraction_layer_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    for layer in AgentAbstractionLayer::ALL {
        let mut encoder = CanonicalEncoder::new();
        layer.encode_canonical(&mut encoder);
        let encoded = encoder.finish();

        let mut decoder = CanonicalDecoder::new(&encoded);
        let decoded = AgentAbstractionLayer::decode_canonical(&mut decoder)?;

        assert_eq!(decoded, layer);
        assert_eq!(decoded.id(), layer.id());
        assert_eq!(decoded.name(), layer.name());
        assert_eq!(decoded.tower_level(), layer.tower_level());
    }

    Ok(())
}

fn sample_anchor() -> LedgerAnchor {
    LedgerAnchor::genesis("site:us-east:primary")
}

fn sample_ledger() -> ReferenceLedger {
    ReferenceLedger::new("site:us-east:primary")
}

fn sample_authority(ledger: &ReferenceLedger) -> Result<AuthorityAnchor, ContractError> {
    AuthorityAnchor::from_committed_head(ledger)
}

fn make_test_delta(
    id: &str,
    object: &str,
    prior: Option<u64>,
    generation: u64,
) -> Result<EvidenceDelta, ContractError> {
    Ok(EvidenceDelta {
        delta_id: id.to_owned(),
        family: "sensor_capsule".to_owned(),
        object_id: ObjectId::parse(object)?,
        prior_generation: prior,
        new_generation: generation,
        validity: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
        plane: Plane::Authority,
        payload_digest: ContentDigest::sha256(id.as_bytes()),
        witness_digest: None,
        operation_id: None,
    })
}

fn advance_ledger(
    ledger: &mut ReferenceLedger,
    batch_id: &str,
    delta_id: &str,
    object_id: &str,
) -> Result<(), ContractError> {
    let parsed_object_id = ObjectId::parse(object_id)?;
    let (prior, next_gen) = match ledger.current().objects.get(&parsed_object_id) {
        Some(current) => (Some(current.generation), current.generation + 1),
        None => (None, 1),
    };
    let batch = ledger.prepare_batch(
        BatchId::parse(batch_id)?,
        vec![make_test_delta(delta_id, object_id, prior, next_gen)?],
        [],
    )?;
    ledger.append(batch)?;
    Ok(())
}

fn sample_uncertainty() -> Result<BeliefInterval, Box<dyn Error>> {
    Ok(BeliefInterval::new(750_000, 920_000)?)
}

#[test]
fn test_derived_belief_construction_and_validation() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let uncertainty = sample_uncertainty()?;
    let evidence_root = ContentDigest::sha256(b"evidence_packet_001");
    let receipt = ContentDigest::sha256(b"graph_projection_receipt_v1");

    let belief = DerivedBelief::new(
        DerivedBeliefParams {
            belief_id: "belief:track:person:001".into(),
            anchor: anchor.clone(),
            generation: Generation(1),
            statement: "Track 001 classified as person in restricted perimeter".into(),
            knowledge_state: KnowledgeState::Estimated,
            provenance: ProvenanceClass::Derived,
            uncertainty,
            supporting_evidence: vec![evidence_root],
            contradictions: vec![],
            derivation_receipt: receipt,
        }
        .with_computed_receipt()?,
    )?;

    // Properties
    assert_eq!(belief.belief_id(), "belief:track:person:001");
    assert_eq!(belief.anchor(), &anchor);
    assert_eq!(belief.generation(), Generation(1));
    assert_eq!(belief.knowledge_state(), KnowledgeState::Estimated);
    assert_eq!(belief.provenance(), ProvenanceClass::Derived);
    assert_eq!(belief.layer(), AgentAbstractionLayer::DerivedBeliefs);

    // Constitutional Hard Gates
    assert!(!belief.may_claim_authority());
    assert!(!belief.may_authorize_effects());
    assert!(belief.is_anchor_pinned());
    assert!(belief.is_rebuildable());

    // Validation passes
    belief.validate()?;

    Ok(())
}

#[test]
fn test_derived_belief_to_knowledge_cell_hard_gate() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let uncertainty = sample_uncertainty()?;
    let evidence_root = ContentDigest::sha256(b"evidence_packet_001");
    let receipt = ContentDigest::sha256(b"graph_projection_receipt_v1");
    let now = TimestampNs(1_000_000_000);

    let belief = DerivedBelief::new(
        DerivedBeliefParams {
            belief_id: "belief:track:vehicle:002".into(),
            anchor,
            generation: Generation(1),
            statement: "Vehicle track 002 speed estimated at 35km/h".into(),
            knowledge_state: KnowledgeState::Estimated,
            provenance: ProvenanceClass::Derived,
            uncertainty,
            supporting_evidence: vec![evidence_root],
            contradictions: vec![],
            derivation_receipt: receipt,
        }
        .with_computed_receipt()?,
    )?;

    let cell = belief.to_knowledge_cell(&sample_anchor())?;

    // The cell inherits the derived belief's attributes
    assert_eq!(cell.claim_id, "belief:track:vehicle:002");
    assert_eq!(cell.knowledge_state, KnowledgeState::Estimated);
    assert_eq!(cell.provenance, ProvenanceClass::Derived);
    assert_eq!(cell.evidence.len(), 1);

    // Constitutional Hard Gate: A derived proposition can NEVER be an irreversible-effect premise!
    assert!(
        !cell.is_irreversible_effect_premise(now),
        "Derived belief MUST NOT authorize an irreversible effect"
    );

    Ok(())
}

#[test]
fn test_planted_negative_derived_belief_known_forbidden() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let uncertainty = sample_uncertainty()?;
    let evidence_root = ContentDigest::sha256(b"evidence_packet_001");
    let receipt = ContentDigest::sha256(b"graph_projection_receipt_v1");

    // Derived belief attempting to claim Known state must fail closed (DerivedBeliefKnownForbidden)
    let res = DerivedBelief::new(DerivedBeliefParams {
        belief_id: "belief:illegal:known".into(),
        anchor,
        generation: Generation(1),
        statement: "Illegally upgrading derived belief to known state".into(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        uncertainty,
        supporting_evidence: vec![evidence_root],
        contradictions: vec![],
        derivation_receipt: receipt,
    });

    let Err(err) = res else {
        return Err("DerivedBelief must refuse KnowledgeState::Known".into());
    };
    assert_eq!(err, ContractError::DerivedBeliefKnownForbidden);

    Ok(())
}

#[test]
fn test_planted_negative_derived_belief_non_derived_provenance_forbidden()
-> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let uncertainty = sample_uncertainty()?;
    let evidence_root = ContentDigest::sha256(b"evidence_packet_001");
    let receipt = ContentDigest::sha256(b"graph_projection_receipt_v1");

    // Derived belief with non-Derived provenance must fail closed
    let res = DerivedBelief::new(DerivedBeliefParams {
        belief_id: "belief:illegal:provenance".into(),
        anchor,
        generation: Generation(1),
        statement: "Derived belief masquerading as policy provenance".into(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Policy,
        uncertainty,
        supporting_evidence: vec![evidence_root],
        contradictions: vec![],
        derivation_receipt: receipt,
    });

    let Err(err) = res else {
        return Err("DerivedBelief must refuse non-Derived provenance".into());
    };
    assert_eq!(err, ContractError::KnowledgeStateBasisMismatch);

    Ok(())
}

#[test]
fn test_planted_negative_derived_belief_empty_evidence_forbidden() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let uncertainty = sample_uncertainty()?;
    let receipt = ContentDigest::sha256(b"graph_projection_receipt_v1");

    // Derived belief without supporting evidence must fail closed (ungrounded cognition)
    let res = DerivedBelief::new(DerivedBeliefParams {
        belief_id: "belief:illegal:ungrounded".into(),
        anchor,
        generation: Generation(1),
        statement: "Derived belief with no canonical evidence roots".into(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        uncertainty,
        supporting_evidence: vec![],
        contradictions: vec![],
        derivation_receipt: receipt,
    });

    let Err(err) = res else {
        return Err("DerivedBelief must refuse empty supporting evidence".into());
    };
    assert_eq!(err, ContractError::EvidenceRequired);

    Ok(())
}

#[test]
fn test_planted_negative_derived_belief_missing_anchor_forbidden() -> Result<(), Box<dyn Error>> {
    let mut bad_anchor = sample_anchor();
    bad_anchor.site_lineage = String::new(); // Invalid empty lineage
    let uncertainty = sample_uncertainty()?;
    let evidence_root = ContentDigest::sha256(b"evidence_packet_001");
    let receipt = ContentDigest::sha256(b"graph_projection_receipt_v1");

    // Derived belief without anchor lineage must fail closed
    let res = DerivedBelief::new(DerivedBeliefParams {
        belief_id: "belief:illegal:no_anchor".into(),
        anchor: bad_anchor,
        generation: Generation(1),
        statement: "Derived belief with unpinned anchor lineage".into(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        uncertainty,
        supporting_evidence: vec![evidence_root],
        contradictions: vec![],
        derivation_receipt: receipt,
    });

    let Err(err) = res else {
        return Err("DerivedBelief must refuse missing anchor lineage".into());
    };
    assert_eq!(err, ContractError::DerivedBeliefMissingAnchor);

    Ok(())
}

#[test]
fn test_planted_negative_derived_belief_invalid_identifier() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let uncertainty = sample_uncertainty()?;
    let evidence_root = ContentDigest::sha256(b"evidence_packet_001");
    let receipt = ContentDigest::sha256(b"graph_projection_receipt_v1");

    // Empty belief_id must fail closed
    let res = DerivedBelief::new(DerivedBeliefParams {
        belief_id: "".into(),
        anchor,
        generation: Generation(1),
        statement: "Statement with empty ID".into(),
        knowledge_state: KnowledgeState::Estimated,
        provenance: ProvenanceClass::Derived,
        uncertainty,
        supporting_evidence: vec![evidence_root],
        contradictions: vec![],
        derivation_receipt: receipt,
    });

    let Err(err) = res else {
        return Err("DerivedBelief must refuse empty belief_id".into());
    };
    assert_eq!(err, ContractError::InvalidIdentifier);

    Ok(())
}

#[test]
fn test_derived_belief_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let uncertainty = sample_uncertainty()?;
    let evidence_root = ContentDigest::sha256(b"evidence_packet_001");
    let contradiction_root = ContentDigest::sha256(b"conflicting_track_evidence");
    let receipt = ContentDigest::sha256(b"graph_projection_receipt_v1");

    let belief = DerivedBelief::new(
        DerivedBeliefParams {
            belief_id: "belief:track:person:roundtrip_001".into(),
            anchor,
            generation: Generation(42),
            statement: "Person detected in Zone 4 with micro-probability [750000, 920000]".into(),
            knowledge_state: KnowledgeState::Estimated,
            provenance: ProvenanceClass::Derived,
            uncertainty,
            supporting_evidence: vec![evidence_root],
            contradictions: vec![contradiction_root],
            derivation_receipt: receipt,
        }
        .with_computed_receipt()?,
    )?;

    let mut encoder = CanonicalEncoder::new();
    belief.encode_canonical(&mut encoder);
    let encoded = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&encoded);
    let decoded = DerivedBelief::decode_canonical(&mut decoder)?;

    assert_eq!(decoded, belief);
    assert_eq!(decoded.belief_id(), belief.belief_id());
    assert_eq!(decoded.anchor(), belief.anchor());
    assert_eq!(decoded.generation(), belief.generation());
    assert_eq!(decoded.statement(), belief.statement());
    assert_eq!(decoded.knowledge_state(), belief.knowledge_state());
    assert_eq!(decoded.provenance(), belief.provenance());
    assert_eq!(decoded.uncertainty(), belief.uncertainty());
    assert_eq!(decoded.supporting_evidence(), belief.supporting_evidence());
    assert_eq!(decoded.contradictions(), belief.contradictions());
    assert_eq!(decoded.derivation_receipt(), belief.derivation_receipt());

    Ok(())
}

fn sample_witness(predicate: &str, authorized: &[&str], observed: &[&str]) -> CoverageWitness {
    let mut auth_set = BTreeSet::new();
    for a in authorized {
        auth_set.insert((*a).to_string());
    }
    let mut obs_set = BTreeSet::new();
    for o in observed {
        obs_set.insert((*o).to_string());
    }
    CoverageWitness {
        anchor: sample_anchor(),
        authorized_domain: auth_set,
        observed_domain: obs_set,
        excluded_domain: BTreeSet::new(),
        continuity: CoverageContinuity::Continuous,
        completeness: Completeness::Complete,
        negative_predicate: predicate.to_string(),
        stop_reason: CoverageStopReason::Complete,
        authorized_generation: 1,
        observed_generation: 1,
    }
}

#[test]
fn test_world_facts_and_coverage_row_properties() -> Result<(), Box<dyn Error>> {
    let layer = AgentAbstractionLayer::WorldFactsAndCoverage;

    // 1. Exact normative stable ID
    assert_eq!(layer.id(), "AGT-LAYER-003");

    // 2. Exact normative schema name
    assert_eq!(layer.name(), "world_facts_and_coverage");
    assert_eq!(format!("{layer}"), "world_facts_and_coverage");

    // 3. Exact normative owner
    assert_eq!(layer.owner(), "fss-chronicle/fss-coverage");

    // 4. Exact normative question
    assert_eq!(
        layer.agent_question(),
        "What did the system authoritatively observe or do at one anchor?"
    );

    // 5. Exact normative output
    assert_eq!(
        layer.output(),
        "Device, geometry, calibration, coverage, policy, archive, and effect facts."
    );

    // 6. Exact normative prohibition
    assert_eq!(
        layer.prohibition(),
        "Cannot include unqualified cognition as fact."
    );

    // 7. Exact normative invariant
    assert_eq!(layer.invariant(), "INV-063");

    // 8. Exact normative status
    assert_eq!(layer.status(), "normative");

    // 9. Semantic plane: Authority plane
    assert_eq!(layer.plane(), Plane::Authority);
    assert!(layer.may_claim_authority());

    // 10. Cannot authorize side effects (strictly PlanAndEffect)
    assert!(!layer.may_authorize_effects());

    // 11. Anchor-pinned and rebuildable from canonical history
    assert!(layer.is_anchor_pinned_rebuildable());

    // 12. Canonical tower level (L2)
    assert_eq!(layer.tower_level(), 2);

    Ok(())
}

#[test]
fn test_world_facts_parse_and_resolution() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        AgentAbstractionLayer::from_id("AGT-LAYER-003")?,
        AgentAbstractionLayer::WorldFactsAndCoverage
    );
    assert_eq!(
        AgentAbstractionLayer::from_name("world_facts_and_coverage")?,
        AgentAbstractionLayer::WorldFactsAndCoverage
    );
    assert_eq!(
        AgentAbstractionLayer::from_tower_level(2)?,
        AgentAbstractionLayer::WorldFactsAndCoverage
    );
    assert_eq!(
        AgentAbstractionLayer::from_str("AGT-LAYER-003")?,
        AgentAbstractionLayer::WorldFactsAndCoverage
    );
    assert_eq!(
        AgentAbstractionLayer::from_str("world_facts_and_coverage")?,
        AgentAbstractionLayer::WorldFactsAndCoverage
    );

    // Unknown identities must fail closed with UnknownAbstractionLayer
    let Err(err) = AgentAbstractionLayer::from_id("AGT-LAYER-999") else {
        return Err("expected unknown abstraction layer error".into());
    };
    assert_eq!(
        err,
        ContractError::UnknownAbstractionLayer("AGT-LAYER-999".into())
    );

    let Err(err_name) = AgentAbstractionLayer::from_name("nonexistent_layer") else {
        return Err("expected unknown abstraction layer name error".into());
    };
    assert_eq!(
        err_name,
        ContractError::UnknownAbstractionLayer("nonexistent_layer".into())
    );

    Ok(())
}

#[test]
fn test_world_fact_kind_census_and_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let kinds = [
        (WorldFactKind::Device, "device"),
        (WorldFactKind::Geometry, "geometry"),
        (WorldFactKind::Calibration, "calibration"),
        (WorldFactKind::Coverage, "coverage"),
        (WorldFactKind::Policy, "policy"),
        (WorldFactKind::Archive, "archive"),
        (WorldFactKind::Effect, "effect"),
    ];

    for (kind, expected_name) in kinds {
        assert_eq!(kind.as_str(), expected_name);
        assert_eq!(format!("{kind}"), expected_name);
        assert_eq!(WorldFactKind::from_name(expected_name)?, kind);
        assert_eq!(WorldFactKind::from_str(expected_name)?, kind);

        // Canonical roundtrip
        let mut encoder = CanonicalEncoder::new();
        kind.encode_canonical(&mut encoder);
        let bytes = encoder.finish();

        let mut decoder = CanonicalDecoder::new(&bytes);
        let decoded = WorldFactKind::decode_canonical(&mut decoder)?;
        assert_eq!(decoded, kind);
    }

    // Invalid kind name fails closed
    assert!(WorldFactKind::from_name("cognition").is_err());
    assert!(WorldFactKind::from_str("invalid_kind").is_err());

    Ok(())
}

#[test]
fn test_world_fact_construction_and_validation() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let evidence = ContentDigest::sha256(b"camera_calibration_receipt_v1");

    let fact = WorldFact::new(
        "fact:device:cam01:calib".to_string(),
        WorldFactKind::Calibration,
        anchor.clone(),
        "Camera cam01 calibration parameters verified at epoch 1".to_string(),
        ProvenanceClass::Observed,
        evidence,
        Generation(1),
    )?;

    assert_eq!(fact.fact_id, "fact:device:cam01:calib");
    assert_eq!(fact.kind, WorldFactKind::Calibration);
    assert_eq!(fact.anchor, anchor);
    assert_eq!(fact.provenance, ProvenanceClass::Observed);
    assert_eq!(fact.evidence_digest, evidence);
    assert_eq!(fact.generation, Generation(1));
    assert_eq!(fact.layer(), AgentAbstractionLayer::WorldFactsAndCoverage);
    assert_eq!(fact.plane(), Plane::Authority);

    // Canonical roundtrip
    let mut encoder = CanonicalEncoder::new();
    fact.encode_canonical(&mut encoder);
    let encoded = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&encoded);
    let decoded = WorldFact::decode_canonical(&mut decoder)?;
    assert_eq!(decoded, fact);

    Ok(())
}

#[test]
fn test_planted_negative_world_fact_validation_failures() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let evidence = ContentDigest::sha256(b"camera_calibration_receipt_v1");

    // 1. Empty fact_id fails closed
    let res = WorldFact::new(
        "",
        WorldFactKind::Device,
        anchor.clone(),
        "Valid statement".to_string(),
        ProvenanceClass::Observed,
        evidence,
        Generation(1),
    );
    let Err(err) = res else {
        return Err("expected error for empty fact_id".into());
    };
    assert_eq!(err, ContractError::InvalidIdentifier);

    // 2. Empty statement fails closed
    let res = WorldFact::new(
        "fact:device:001",
        WorldFactKind::Device,
        anchor.clone(),
        "",
        ProvenanceClass::Observed,
        evidence,
        Generation(1),
    );
    let Err(err) = res else {
        return Err("expected error for empty statement".into());
    };
    assert_eq!(err, ContractError::InvalidIdentifier);

    // 3. Empty anchor lineage fails closed
    let mut bad_anchor = anchor.clone();
    bad_anchor.site_lineage = String::new();
    let res = WorldFact::new(
        "fact:device:001",
        WorldFactKind::Device,
        bad_anchor,
        "Valid statement".to_string(),
        ProvenanceClass::Observed,
        evidence,
        Generation(1),
    );
    let Err(err) = res else {
        return Err("expected error for empty anchor lineage".into());
    };
    assert_eq!(err, ContractError::DerivedBeliefMissingAnchor);

    // 4. Zero generation fails closed
    let res = WorldFact::new(
        "fact:device:001",
        WorldFactKind::Device,
        anchor.clone(),
        "Valid statement".to_string(),
        ProvenanceClass::Observed,
        evidence,
        Generation(0),
    );
    let Err(err) = res else {
        return Err("expected error for zero generation".into());
    };
    assert_eq!(err, ContractError::GenerationConflict);

    // 5. Zero evidence digest fails closed
    let zero_digest = ContentDigest::new(DigestAlgorithm::Sha256, [0u8; 32]);
    let res = WorldFact::new(
        "fact:device:001",
        WorldFactKind::Device,
        anchor.clone(),
        "Valid statement".to_string(),
        ProvenanceClass::Observed,
        zero_digest,
        Generation(1),
    );
    let Err(err) = res else {
        return Err("expected error for zero evidence digest".into());
    };
    assert_eq!(err, ContractError::InvalidDigest);

    // 6. Malformed fact_id fails closed (validate_id rejects whitespace)
    let res = WorldFact::new(
        "fact device 001",
        WorldFactKind::Device,
        anchor.clone(),
        "Valid statement".to_string(),
        ProvenanceClass::Observed,
        evidence,
        Generation(1),
    );
    let Err(err) = res else {
        return Err("expected error for malformed fact_id".into());
    };
    assert_eq!(err, ContractError::InvalidIdentifier);

    // 7. Non-Observed provenance: ProvenanceClass::Derived fails closed
    let res = WorldFact::new(
        "fact:device:001",
        WorldFactKind::Device,
        anchor.clone(),
        "Valid statement".to_string(),
        ProvenanceClass::Derived,
        evidence,
        Generation(1),
    );
    let Err(err) = res else {
        return Err("expected error for derived provenance in WorldFact".into());
    };
    assert_eq!(err, ContractError::EvidenceRequired);

    // 8. Non-Observed provenance: ProvenanceClass::VendorClaimed fails closed
    let res = WorldFact::new(
        "fact:device:001",
        WorldFactKind::Device,
        anchor.clone(),
        "Valid statement".to_string(),
        ProvenanceClass::VendorClaimed,
        evidence,
        Generation(1),
    );
    let Err(err) = res else {
        return Err("expected error for vendor claimed provenance in WorldFact".into());
    };
    assert_eq!(err, ContractError::EvidenceRequired);

    // 9. Non-Observed provenance: ProvenanceClass::Predicted fails closed
    let res = WorldFact::new(
        "fact:device:001",
        WorldFactKind::Device,
        anchor.clone(),
        "Valid statement".to_string(),
        ProvenanceClass::Predicted,
        evidence,
        Generation(1),
    );
    let Err(err) = res else {
        return Err("expected error for predicted provenance in WorldFact".into());
    };
    assert_eq!(err, ContractError::EvidenceRequired);

    // 10. Non-Observed provenance: ProvenanceClass::Remembered fails closed
    let res = WorldFact::new(
        "fact:device:001",
        WorldFactKind::Device,
        anchor,
        "Valid statement".to_string(),
        ProvenanceClass::Remembered,
        evidence,
        Generation(1),
    );
    let Err(err) = res else {
        return Err("expected error for remembered provenance in WorldFact".into());
    };
    assert_eq!(err, ContractError::EvidenceRequired);

    Ok(())
}

#[test]
fn test_negative_read_claim_requires_coverage_witness() -> Result<(), Box<dyn Error>> {
    let ledger = sample_ledger();
    let anchor = ledger.current().anchor.clone();
    let authority = sample_authority(&ledger)?;
    let mut target_domain = BTreeSet::new();
    target_domain.insert("zone:north_perimeter".to_string());

    // Claim WITHOUT CoverageWitness must fail closed (AGENTS.md prime directive)
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:001".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: anchor.clone(),
        target_domain,
        target_generation: 1,
        coverage_witness: None,
    };

    let Err(err) = evaluate_negative_read(&claim, &authority) else {
        return Err("expected error for uncertified coverage".into());
    };
    assert_eq!(err, ContractError::CoverageUncertified);

    Ok(())
}

#[test]
fn test_planted_negative_uncertified_coverage_witness_fails() -> Result<(), Box<dyn Error>> {
    let ledger = sample_ledger();
    let anchor = ledger.current().anchor.clone();
    let authority = sample_authority(&ledger)?;
    let mut target_domain = BTreeSet::new();
    target_domain.insert("zone:north_perimeter".to_string());

    // 1. Coverage gap (continuity == Gapped)
    let mut witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:north_perimeter"],
        &["zone:north_perimeter"],
    );
    witness.continuity = CoverageContinuity::Gapped;
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:gap".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: anchor.clone(),
        target_domain: target_domain.clone(),
        target_generation: 1,
        coverage_witness: Some(witness),
    };
    let Err(err) = evaluate_negative_read(&claim, &authority) else {
        return Err("expected error for gapped coverage".into());
    };
    assert_eq!(err, ContractError::CoverageUncertified);

    // 2. Incomplete coverage (completeness == Partial)
    let mut witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:north_perimeter"],
        &["zone:north_perimeter"],
    );
    witness.completeness = Completeness::Partial;
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:partial".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: anchor.clone(),
        target_domain: target_domain.clone(),
        target_generation: 1,
        coverage_witness: Some(witness),
    };
    let Err(err) = evaluate_negative_read(&claim, &authority) else {
        return Err("expected error for partial coverage".into());
    };
    assert_eq!(err, ContractError::CoverageUncertified);

    // 3. Stop reason not complete
    let mut witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:north_perimeter"],
        &["zone:north_perimeter"],
    );
    witness.stop_reason = CoverageStopReason::BudgetExhausted;
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:budget".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: anchor.clone(),
        target_domain: target_domain.clone(),
        target_generation: 1,
        coverage_witness: Some(witness),
    };
    let Err(err) = evaluate_negative_read(&claim, &authority) else {
        return Err("expected error for budget exhausted stop reason".into());
    };
    assert_eq!(err, ContractError::CoverageUncertified);

    // 4. Non-empty excluded domain
    let mut witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:north_perimeter"],
        &["zone:north_perimeter"],
    );
    witness
        .excluded_domain
        .insert("zone:north_gate".to_string());
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:excluded".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: anchor.clone(),
        target_domain: target_domain.clone(),
        target_generation: 1,
        coverage_witness: Some(witness),
    };
    let Err(err) = evaluate_negative_read(&claim, &authority) else {
        return Err("expected error for non-empty excluded domain".into());
    };
    assert_eq!(err, ContractError::CoverageUncertified);

    // 5. Target domain not covered by observed domain
    let witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:south_perimeter"],
        &["zone:south_perimeter"],
    );
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:domain_mismatch".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: anchor.clone(),
        target_domain: target_domain.clone(),
        target_generation: 1,
        coverage_witness: Some(witness),
    };
    let Err(err) = evaluate_negative_read(&claim, &authority) else {
        return Err("expected error for domain mismatch".into());
    };
    assert_eq!(err, ContractError::CoverageUncertified);

    // 6. Predicate mismatch
    let witness = sample_witness(
        "no_fire_detected",
        &["zone:north_perimeter"],
        &["zone:north_perimeter"],
    );
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:pred_mismatch".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: anchor.clone(),
        target_domain: target_domain.clone(),
        target_generation: 1,
        coverage_witness: Some(witness),
    };
    let Err(err) = evaluate_negative_read(&claim, &authority) else {
        return Err("expected error for predicate mismatch".into());
    };
    assert_eq!(err, ContractError::CoverageUncertified);

    // 7. Generation mismatch
    let witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:north_perimeter"],
        &["zone:north_perimeter"],
    );
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:gen_mismatch".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: anchor.clone(),
        target_domain: target_domain.clone(),
        target_generation: 2, // Witness has gen 1
        coverage_witness: Some(witness),
    };
    let Err(err) = evaluate_negative_read(&claim, &authority) else {
        return Err("expected error for generation mismatch".into());
    };
    assert_eq!(err, ContractError::GenerationConflict);

    // 8. (Check 1, RM7) Witness anchor mismatch from claim anchor:
    // Witness is at authority anchor, but claim has different anchor.
    let witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:north_perimeter"],
        &["zone:north_perimeter"],
    );
    let mut different_claim_anchor = anchor.clone();
    different_claim_anchor.commit_sequence += 1;
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:witness_claim_anchor_mismatch".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: different_claim_anchor,
        target_domain: target_domain.clone(),
        target_generation: 1,
        coverage_witness: Some(witness),
    };
    let Err(err) = evaluate_negative_read(&claim, &authority) else {
        return Err("expected error for witness != claim anchor (RM7)".into());
    };
    assert_eq!(err, ContractError::StaleAnchor);

    // 9. (Check 2, RM3) Site lineage mismatch:
    // Witness and claim match each other, but have different site lineage from authority.
    let mut other_site_anchor = anchor.clone();
    other_site_anchor.site_lineage = "site:other_lineage".to_string();
    let mut other_witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:north_perimeter"],
        &["zone:north_perimeter"],
    );
    other_witness.anchor = other_site_anchor.clone();
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:site_lineage_mismatch".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: other_site_anchor,
        target_domain: target_domain.clone(),
        target_generation: 1,
        coverage_witness: Some(other_witness),
    };
    let Err(err) = evaluate_negative_read(&claim, &authority) else {
        return Err("expected error for site lineage mismatch (RM3)".into());
    };
    assert_eq!(err, ContractError::StaleAnchor);

    // 10. (Check 3, RM4) Strictly older commit sequence/epoch (stale anchor):
    // Witness and claim match, same lineage, but sequence is older than authority anchor.
    let witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:north_perimeter"],
        &["zone:north_perimeter"],
    );
    let mut advanced_ledger = sample_ledger();
    advance_ledger(&mut advanced_ledger, "batch:rm4_adv", "delta:rm4_adv", "object:rm4_adv")?;
    let newer_authority = sample_authority(&advanced_ledger)?;
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:stale_sequence".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: anchor.clone(),
        target_domain: target_domain.clone(),
        target_generation: 1,
        coverage_witness: Some(witness),
    };
    let Err(err) = evaluate_negative_read(&claim, &newer_authority) else {
        return Err("expected error for strictly older sequence (RM4)".into());
    };
    assert_eq!(err, ContractError::StaleAnchor);

    // 11. (Check 4, RM8) Divergent state root at same sequence:
    // Witness and claim match, same lineage and sequence, but different state root from authority.
    let mut ledger_a = sample_ledger();
    advance_ledger(&mut ledger_a, "batch:rm8_a", "delta:rm8_a", "object:rm8_a")?;
    let mut ledger_b = sample_ledger();
    advance_ledger(&mut ledger_b, "batch:rm8_b", "delta:rm8_b", "object:rm8_b")?;
    let anchor_a = ledger_a.current().anchor.clone();
    let forked_authority = sample_authority(&ledger_b)?;
    let witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:north_perimeter"],
        &["zone:north_perimeter"],
    );
    let mut witness_a = witness.clone();
    witness_a.anchor = anchor_a.clone();
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:divergent_state_root".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: anchor_a,
        target_domain: target_domain.clone(),
        target_generation: 1,
        coverage_witness: Some(witness_a),
    };
    let Err(err) = evaluate_negative_read(&claim, &forked_authority) else {
        return Err("expected error for divergent state root (RM8)".into());
    };
    assert_eq!(err, ContractError::StaleAnchor);

    // 12. (Check 4, RM8f) Future witness anchor (ledger_epoch ahead of current)
    let mut future_epoch_anchor = anchor.clone();
    future_epoch_anchor.ledger_epoch += 1;
    let mut future_witness = witness.clone();
    future_witness.anchor = future_epoch_anchor.clone();
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:future_ledger_epoch".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: future_epoch_anchor,
        target_domain: target_domain.clone(),
        target_generation: 1,
        coverage_witness: Some(future_witness),
    };
    let Err(err) = evaluate_negative_read(&claim, &authority) else {
        return Err("expected error for future ledger epoch (RM8f)".into());
    };
    assert_eq!(err, ContractError::StaleAnchor);

    // 13. (Check 4, RM8f) Future witness anchor (commit_sequence ahead of current)
    let mut future_seq_anchor = anchor.clone();
    future_seq_anchor.commit_sequence += 1;
    let mut future_witness = witness.clone();
    future_witness.anchor = future_seq_anchor.clone();
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:future_commit_sequence".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: future_seq_anchor,
        target_domain: target_domain.clone(),
        target_generation: 1,
        coverage_witness: Some(future_witness),
    };
    let Err(err) = evaluate_negative_read(&claim, &authority) else {
        return Err("expected error for future commit sequence (RM8f)".into());
    };
    assert_eq!(err, ContractError::StaleAnchor);

    // 14. (Check 4, RM8p) Divergent policy_epoch from authority
    let mut divergent_policy_anchor = anchor.clone();
    divergent_policy_anchor.policy_epoch += 1;
    let mut divergent_policy_witness = witness.clone();
    divergent_policy_witness.anchor = divergent_policy_anchor.clone();
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:divergent_policy_epoch".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: divergent_policy_anchor,
        target_domain: target_domain.clone(),
        target_generation: 1,
        coverage_witness: Some(divergent_policy_witness),
    };
    let Err(err) = evaluate_negative_read(&claim, &authority) else {
        return Err("expected error for divergent policy epoch (RM8p)".into());
    };
    assert_eq!(err, ContractError::StaleAnchor);

    // 15. (Check 4, RM8) Divergent privacy_epoch from authority
    let mut divergent_privacy_anchor = anchor.clone();
    divergent_privacy_anchor.privacy_epoch += 1;
    let mut divergent_privacy_witness = witness.clone();
    divergent_privacy_witness.anchor = divergent_privacy_anchor.clone();
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:divergent_privacy_epoch".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: divergent_privacy_anchor,
        target_domain: target_domain.clone(),
        target_generation: 1,
        coverage_witness: Some(divergent_privacy_witness),
    };
    let Err(err) = evaluate_negative_read(&claim, &authority) else {
        return Err("expected error for divergent privacy epoch (RM8)".into());
    };
    assert_eq!(err, ContractError::StaleAnchor);

    // 16. (Check 4, RM8) Divergent schema_epoch from authority
    let mut divergent_schema_anchor = anchor.clone();
    divergent_schema_anchor.schema_epoch += 1;
    let mut divergent_schema_witness = witness.clone();
    divergent_schema_witness.anchor = divergent_schema_anchor.clone();
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:divergent_schema_epoch".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: divergent_schema_anchor,
        target_domain: target_domain.clone(),
        target_generation: 1,
        coverage_witness: Some(divergent_schema_witness),
    };
    let Err(err) = evaluate_negative_read(&claim, &authority) else {
        return Err("expected error for divergent schema epoch (RM8)".into());
    };
    assert_eq!(err, ContractError::StaleAnchor);

    // 17. (Check 4, RM8) Divergent adapter_registry_epoch from authority
    let mut divergent_adapter_anchor = anchor.clone();
    divergent_adapter_anchor.adapter_registry_epoch += 1;
    let mut divergent_adapter_witness = witness;
    divergent_adapter_witness.anchor = divergent_adapter_anchor.clone();
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:divergent_adapter_epoch".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: divergent_adapter_anchor,
        target_domain,
        target_generation: 1,
        coverage_witness: Some(divergent_adapter_witness),
    };
    let Err(err) = evaluate_negative_read(&claim, &authority) else {
        return Err("expected error for divergent adapter registry epoch (RM8)".into());
    };
    assert_eq!(err, ContractError::StaleAnchor);

    Ok(())
}

#[test]
fn test_negative_read_outcome_from_witness_direct_contracts() -> Result<(), Box<dyn Error>> {
    let ledger = sample_ledger();
    let anchor = ledger.current().anchor.clone();
    let authority = sample_authority(&ledger)?;
    let mut target_domain = BTreeSet::new();
    target_domain.insert("zone:north_perimeter".to_string());

    // 1. Direct construction succeeds with valid parameters (generation taken from claim)
    let witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:north_perimeter"],
        &["zone:north_perimeter"],
    );
    let outcome = NegativeReadOutcome::from_witness(
        "neg_claim:direct_ok",
        "no_unauthorized_intrusion",
        anchor.clone(),
        target_domain.clone(),
        &witness,
        &authority,
        1,
    )?;
    assert_eq!(outcome.claim_id(), "neg_claim:direct_ok");
    assert_eq!(outcome.query_predicate(), "no_unauthorized_intrusion");
    assert_eq!(outcome.anchor(), &anchor);
    assert_eq!(outcome.certified_domain(), &target_domain);
    assert_eq!(outcome.witness_digest(), witness.witness_digest());
    assert_eq!(outcome.generation(), 1);

    // 2. RM9 killer: Dropping require_certified_absence in from_witness must fail
    let mut uncertified_witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:north_perimeter"],
        &["zone:north_perimeter"],
    );
    uncertified_witness.stop_reason = CoverageStopReason::BudgetExhausted;
    let res = NegativeReadOutcome::from_witness(
        "neg_claim:rm9_direct",
        "no_unauthorized_intrusion",
        anchor.clone(),
        target_domain.clone(),
        &uncertified_witness,
        &authority,
        1,
    );
    assert!(matches!(res, Err(ContractError::CoverageUncertified)));

    // 3. RM7 killer: Dropping witness.anchor != anchor in from_witness must fail
    let mut different_anchor = anchor.clone();
    different_anchor.commit_sequence += 1;
    let res = NegativeReadOutcome::from_witness(
        "neg_claim:rm7_direct",
        "no_unauthorized_intrusion",
        different_anchor,
        target_domain.clone(),
        &witness,
        &authority,
        1,
    );
    assert!(matches!(res, Err(ContractError::StaleAnchor)));

    // 4. RM3 in from_witness: site lineage mismatch
    let other_site_ledger = ReferenceLedger::new("site:other");
    let other_site_authority = sample_authority(&other_site_ledger)?;
    let res = NegativeReadOutcome::from_witness(
        "neg_claim:rm3_direct",
        "no_unauthorized_intrusion",
        anchor.clone(),
        target_domain.clone(),
        &witness,
        &other_site_authority,
        1,
    );
    assert!(matches!(res, Err(ContractError::StaleAnchor)));

    // 5. RM4 in from_witness: strictly older sequence
    let mut newer_ledger = sample_ledger();
    advance_ledger(&mut newer_ledger, "batch:rm4_dir", "delta:rm4_dir", "object:rm4_dir")?;
    let newer_authority = sample_authority(&newer_ledger)?;
    let res = NegativeReadOutcome::from_witness(
        "neg_claim:rm4_direct",
        "no_unauthorized_intrusion",
        anchor.clone(),
        target_domain.clone(),
        &witness,
        &newer_authority,
        1,
    );
    assert!(matches!(res, Err(ContractError::StaleAnchor)));

    // 6. RM8 in from_witness: divergent state root at same sequence
    let mut ledger_a = sample_ledger();
    advance_ledger(&mut ledger_a, "batch:rm8_da", "delta:rm8_da", "object:rm8_da")?;
    let mut ledger_b = sample_ledger();
    advance_ledger(&mut ledger_b, "batch:rm8_db", "delta:rm8_db", "object:rm8_db")?;
    let anchor_a = ledger_a.current().anchor.clone();
    let mut witness_a = witness.clone();
    witness_a.anchor = anchor_a.clone();
    let forked_authority = sample_authority(&ledger_b)?;
    let res = NegativeReadOutcome::from_witness(
        "neg_claim:rm8_direct",
        "no_unauthorized_intrusion",
        anchor_a,
        target_domain.clone(),
        &witness_a,
        &forked_authority,
        1,
    );
    assert!(matches!(res, Err(ContractError::StaleAnchor)));

    // 6b. RM8f in from_witness: future witness anchor (ledger_epoch ahead of current)
    let mut future_epoch_anchor = anchor.clone();
    future_epoch_anchor.ledger_epoch += 1;
    let mut future_witness = witness.clone();
    future_witness.anchor = future_epoch_anchor.clone();
    let res = NegativeReadOutcome::from_witness(
        "neg_claim:rm8f_future_epoch",
        "no_unauthorized_intrusion",
        future_epoch_anchor,
        target_domain.clone(),
        &future_witness,
        &authority,
        1,
    );
    assert!(matches!(res, Err(ContractError::StaleAnchor)));

    // 6c. RM8f in from_witness: future witness anchor (commit_sequence ahead of current)
    let mut future_seq_anchor = anchor.clone();
    future_seq_anchor.commit_sequence += 1;
    let mut future_witness = witness.clone();
    future_witness.anchor = future_seq_anchor.clone();
    let res = NegativeReadOutcome::from_witness(
        "neg_claim:rm8f_future_seq",
        "no_unauthorized_intrusion",
        future_seq_anchor,
        target_domain.clone(),
        &future_witness,
        &authority,
        1,
    );
    assert!(matches!(res, Err(ContractError::StaleAnchor)));

    // 6d. RM8p in from_witness: divergent policy_epoch from authority
    let mut divergent_policy_anchor = anchor.clone();
    divergent_policy_anchor.policy_epoch += 1;
    let mut divergent_policy_witness = witness.clone();
    divergent_policy_witness.anchor = divergent_policy_anchor.clone();
    let res = NegativeReadOutcome::from_witness(
        "neg_claim:rm8p_policy_epoch",
        "no_unauthorized_intrusion",
        divergent_policy_anchor,
        target_domain.clone(),
        &divergent_policy_witness,
        &authority,
        1,
    );
    assert!(matches!(res, Err(ContractError::StaleAnchor)));

    // 6e. RM8 in from_witness: divergent privacy_epoch from authority
    let mut divergent_privacy_anchor = anchor.clone();
    divergent_privacy_anchor.privacy_epoch += 1;
    let mut divergent_privacy_witness = witness.clone();
    divergent_privacy_witness.anchor = divergent_privacy_anchor.clone();
    let res = NegativeReadOutcome::from_witness(
        "neg_claim:rm8_privacy_epoch",
        "no_unauthorized_intrusion",
        divergent_privacy_anchor,
        target_domain.clone(),
        &divergent_privacy_witness,
        &authority,
        1,
    );
    assert!(matches!(res, Err(ContractError::StaleAnchor)));

    // 6f. RM8 in from_witness: divergent schema_epoch from authority
    let mut divergent_schema_anchor = anchor.clone();
    divergent_schema_anchor.schema_epoch += 1;
    let mut divergent_schema_witness = witness.clone();
    divergent_schema_witness.anchor = divergent_schema_anchor.clone();
    let res = NegativeReadOutcome::from_witness(
        "neg_claim:rm8_schema_epoch",
        "no_unauthorized_intrusion",
        divergent_schema_anchor,
        target_domain.clone(),
        &divergent_schema_witness,
        &authority,
        1,
    );
    assert!(matches!(res, Err(ContractError::StaleAnchor)));

    // 6g. RM8 in from_witness: divergent adapter_registry_epoch from authority
    let mut divergent_adapter_anchor = anchor.clone();
    divergent_adapter_anchor.adapter_registry_epoch += 1;
    let mut divergent_adapter_witness = witness.clone();
    divergent_adapter_witness.anchor = divergent_adapter_anchor.clone();
    let res = NegativeReadOutcome::from_witness(
        "neg_claim:rm8_adapter_epoch",
        "no_unauthorized_intrusion",
        divergent_adapter_anchor,
        target_domain.clone(),
        &divergent_adapter_witness,
        &authority,
        1,
    );
    assert!(matches!(res, Err(ContractError::StaleAnchor)));

    // 7. Generation mismatch or zero generation fails closed (N6)
    let res = NegativeReadOutcome::from_witness(
        "neg_claim:gen_zero",
        "no_unauthorized_intrusion",
        anchor.clone(),
        target_domain.clone(),
        &witness,
        &authority,
        0,
    );
    assert!(matches!(res, Err(ContractError::GenerationConflict)));

    let res = NegativeReadOutcome::from_witness(
        "neg_claim:gen_mismatch",
        "no_unauthorized_intrusion",
        anchor,
        target_domain,
        &witness,
        &authority,
        99,
    );
    assert!(matches!(res, Err(ContractError::GenerationConflict)));

    Ok(())
}

#[test]
fn test_authority_context_as_current_anchor_source() -> Result<(), Box<dyn Error>> {
    let ledger = sample_ledger();
    let anchor = ledger.current().anchor.clone();
    let basis = fss_core::contract_basis::reference_contract_basis();
    let authority = AuthorityAnchor::from_committed_head(&ledger)?;

    // 1. AuthorityContext constructed from AuthorityAnchor implements CurrentAnchorSource
    let auth_ctx = AuthorityContext::new(&basis, &authority);
    assert_eq!(auth_ctx.current_anchor(), &anchor);
    assert_eq!(auth_ctx.contract_basis(), &basis);

    // 2. AuthorityContext constructed from committed head implements CurrentAnchorSource
    let auth_ctx_head = AuthorityContext::from_committed_head(&basis, &ledger)?;
    assert_eq!(auth_ctx_head.current_anchor(), &anchor);
    assert_eq!(auth_ctx_head.contract_basis(), &basis);

    let witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:north_perimeter"],
        &["zone:north_perimeter"],
    );
    let mut target_domain = BTreeSet::new();
    target_domain.insert("zone:north_perimeter".to_string());
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:auth_ctx_ok".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: anchor.clone(),
        target_domain: target_domain.clone(),
        target_generation: 1,
        coverage_witness: Some(witness.clone()),
    };

    let outcome = evaluate_negative_read(&claim, &auth_ctx)?;
    assert_eq!(outcome.claim_id(), "neg_claim:auth_ctx_ok");

    let outcome_head = evaluate_negative_read(&claim, &auth_ctx_head)?;
    assert_eq!(outcome_head.claim_id(), "neg_claim:auth_ctx_ok");

    Ok(())
}

#[test]
fn test_negative_read_claim_with_certified_absence_succeeds() -> Result<(), Box<dyn Error>> {
    let ledger = sample_ledger();
    let anchor = ledger.current().anchor.clone();
    let authority = sample_authority(&ledger)?;
    let mut target_domain = BTreeSet::new();
    target_domain.insert("zone:north_perimeter".to_string());
    target_domain.insert("zone:east_perimeter".to_string());

    let witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:north_perimeter", "zone:east_perimeter"],
        &["zone:north_perimeter", "zone:east_perimeter"],
    );

    let claim = NegativeReadClaim {
        claim_id: "neg_claim:certified_ok".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: anchor.clone(),
        target_domain: target_domain.clone(),
        target_generation: 1,
        coverage_witness: Some(witness.clone()),
    };

    let outcome = evaluate_negative_read(&claim, &authority)?;
    assert_eq!(outcome.claim_id(), "neg_claim:certified_ok");
    assert_eq!(outcome.query_predicate(), "no_unauthorized_intrusion");
    assert_eq!(outcome.anchor(), &anchor);
    assert_eq!(outcome.certified_domain(), &target_domain);
    assert_eq!(outcome.witness_digest(), witness.witness_digest());
    assert_eq!(outcome.generation(), 1);

    // Direct construction via NegativeReadOutcome::from_witness
    let direct = NegativeReadOutcome::from_witness(
        "neg_claim:direct_ok",
        "no_unauthorized_intrusion",
        anchor.clone(),
        target_domain.clone(),
        &witness,
        &authority,
        1,
    )?;
    assert_eq!(direct.claim_id(), "neg_claim:direct_ok");
    assert_eq!(direct.query_predicate(), "no_unauthorized_intrusion");
    assert_eq!(direct.anchor(), &anchor);
    assert_eq!(direct.certified_domain(), &target_domain);
    assert_eq!(direct.witness_digest(), witness.witness_digest());
    assert_eq!(direct.generation(), 1);

    // Canonical roundtrip with verified decode
    let mut encoder = CanonicalEncoder::new();
    outcome.encode_canonical(&mut encoder);
    let encoded = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&encoded);
    let decoded = NegativeReadOutcome::decode_verified(&mut decoder, &witness, &authority)?;
    assert_eq!(decoded, outcome);

    Ok(())
}

#[test]
fn test_negative_read_outcome_decode_invariants() -> Result<(), Box<dyn Error>> {
    let ledger = sample_ledger();
    let anchor = ledger.current().anchor.clone();
    let authority = sample_authority(&ledger)?;
    let witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:a", "zone:b"],
        &["zone:a", "zone:b"],
    );
    let witness_digest = witness.witness_digest();

    // 1. Non-canonical ordering (duplicate or unsorted items in certified_domain)
    let mut encoder = CanonicalEncoder::new();
    encoder.text("neg_claim:001");
    encoder.text("no_unauthorized_intrusion");
    anchor.encode_canonical(&mut encoder);
    encoder.u64(2); // 2 items
    encoder.text("zone:b");
    encoder.text("zone:a"); // unsorted!
    encoder.digest(witness_digest);
    encoder.u64(1);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let Err(err) = NegativeReadOutcome::decode_verified(&mut decoder, &witness, &authority) else {
        return Err("expected error for non-canonical ordering".into());
    };
    assert_eq!(err, ContractError::NonCanonicalOrdering);

    // 2. Duplicate items in certified_domain
    let mut encoder = CanonicalEncoder::new();
    encoder.text("neg_claim:001");
    encoder.text("no_unauthorized_intrusion");
    anchor.encode_canonical(&mut encoder);
    encoder.u64(2);
    encoder.text("zone:a");
    encoder.text("zone:a"); // duplicate!
    encoder.digest(witness_digest);
    encoder.u64(1);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let Err(err) = NegativeReadOutcome::decode_verified(&mut decoder, &witness, &authority) else {
        return Err("expected error for duplicate domain items".into());
    };
    assert_eq!(err, ContractError::NonCanonicalOrdering);

    // 3. Zero generation rejected
    let mut encoder = CanonicalEncoder::new();
    encoder.text("neg_claim:001");
    encoder.text("no_unauthorized_intrusion");
    anchor.encode_canonical(&mut encoder);
    encoder.u64(1);
    encoder.text("zone:a");
    encoder.digest(witness_digest);
    encoder.u64(0); // zero generation!
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let Err(err) = NegativeReadOutcome::decode_verified(&mut decoder, &witness, &authority) else {
        return Err("expected error for zero generation".into());
    };
    assert_eq!(err, ContractError::GenerationConflict);

    // 4. Zero witness digest rejected
    let mut encoder = CanonicalEncoder::new();
    encoder.text("neg_claim:001");
    encoder.text("no_unauthorized_intrusion");
    anchor.encode_canonical(&mut encoder);
    encoder.u64(1);
    encoder.text("zone:a");
    encoder.digest(ContentDigest::new(
        fss_core::DigestAlgorithm::Sha256,
        [0u8; 32],
    )); // zero digest!
    encoder.u64(1);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let Err(err) = NegativeReadOutcome::decode_verified(&mut decoder, &witness, &authority) else {
        return Err("expected error for zero witness digest".into());
    };
    assert_eq!(err, ContractError::InvalidDigest);

    // 5. Empty claim_id rejected
    let mut encoder = CanonicalEncoder::new();
    encoder.text(""); // empty claim_id
    encoder.text("no_unauthorized_intrusion");
    anchor.encode_canonical(&mut encoder);
    encoder.u64(1);
    encoder.text("zone:a");
    encoder.digest(witness_digest);
    encoder.u64(1);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let Err(err) = NegativeReadOutcome::decode_verified(&mut decoder, &witness, &authority) else {
        return Err("expected error for empty claim_id".into());
    };
    assert_eq!(err, ContractError::InvalidIdentifier);

    // 6. Malformed claim_id (spaces) rejected by validate_id
    let mut encoder = CanonicalEncoder::new();
    encoder.text("claim with spaces");
    encoder.text("no_unauthorized_intrusion");
    anchor.encode_canonical(&mut encoder);
    encoder.u64(1);
    encoder.text("zone:a");
    encoder.digest(witness_digest);
    encoder.u64(1);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let Err(err) = NegativeReadOutcome::decode_verified(&mut decoder, &witness, &authority) else {
        return Err("expected error for malformed claim_id".into());
    };
    assert_eq!(err, ContractError::InvalidIdentifier);

    // 7. Witness digest mismatch rejected
    let other_witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:other"],
        &["zone:other"],
    );
    let mut encoder = CanonicalEncoder::new();
    encoder.text("neg_claim:001");
    encoder.text("no_unauthorized_intrusion");
    anchor.encode_canonical(&mut encoder);
    encoder.u64(1);
    encoder.text("zone:a");
    encoder.digest(other_witness.witness_digest()); // mismatched digest!
    encoder.u64(1);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let Err(err) = NegativeReadOutcome::decode_verified(&mut decoder, &witness, &authority) else {
        return Err("expected error for mismatched witness digest".into());
    };
    assert_eq!(err, ContractError::CoverageUncertified);

    // 8. Trailing unconsumed bytes rejected by ensure_finished()
    let mut encoder = CanonicalEncoder::new();
    encoder.text("neg_claim:001");
    encoder.text("no_unauthorized_intrusion");
    anchor.encode_canonical(&mut encoder);
    encoder.u64(1);
    encoder.text("zone:a");
    encoder.digest(witness_digest);
    encoder.u64(1);
    encoder.u8(0xFF); // trailing byte!
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let Err(err) = NegativeReadOutcome::decode_verified(&mut decoder, &witness, &authority) else {
        return Err("expected error for trailing bytes in decode_verified".into());
    };
    assert_eq!(err, ContractError::NonCanonicalOrdering);

    Ok(())
}

#[test]
fn test_older_snapshot_at_head_refused_as_stale_anchor() -> Result<(), Box<dyn Error>> {
    let mut ledger = sample_ledger();
    let old_snapshot = ledger.current().clone();
    let old_anchor = old_snapshot.anchor.clone();
    advance_ledger(
        &mut ledger,
        "batch:snap_advance",
        "delta:snap_advance",
        "object:snap_advance",
    )?;

    // An older snapshot retrieved via snapshot_at(0)
    let snapshot_0 = ledger.snapshot_at(0).ok_or("snapshot 0 missing")?;
    assert_eq!(snapshot_0.anchor, old_anchor);

    // Real committed authority from ledger head (now at commit_sequence 1)
    let authority = AuthorityAnchor::from_committed_head(&ledger)?;
    assert_eq!(authority.anchor().commit_sequence, 1);

    // Claim and witness at older snapshot anchor (commit_sequence 0)
    let witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:north_perimeter"],
        &["zone:north_perimeter"],
    );
    let mut target_domain = BTreeSet::new();
    target_domain.insert("zone:north_perimeter".to_string());
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:old_snapshot".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: old_anchor,
        target_domain,
        target_generation: 1,
        coverage_witness: Some(witness),
    };

    // Evaluating the older snapshot claim against head authority MUST be refused as StaleAnchor
    let res = evaluate_negative_read(&claim, &authority);
    assert_eq!(res.err(), Some(ContractError::StaleAnchor));

    Ok(())
}

#[test]
fn test_probe_n2d_refuses_stale_witness_and_requires_ledger_authority() -> Result<(), Box<dyn Error>> {
    let mut ledger = sample_ledger();
    let old_anchor = ledger.current().anchor.clone();

    // The real ledger head is 5 commits past the stale witness.
    for i in 1..=5 {
        advance_ledger(
            &mut ledger,
            &format!("batch:probe_n2d:{i}"),
            &format!("delta:probe_n2d:{i}"),
            &format!("object:probe_n2d:{i}"),
        )?;
    }

    let honest = AuthorityAnchor::from_committed_head(&ledger)?;
    assert_eq!(honest.anchor().commit_sequence, 5);

    let witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:north_perimeter"],
        &["zone:north_perimeter"],
    );
    let mut target_domain = BTreeSet::new();
    target_domain.insert("zone:north_perimeter".to_string());
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:probe_n2d".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: old_anchor,
        target_domain,
        target_generation: 1,
        coverage_witness: Some(witness),
    };

    let res = evaluate_negative_read(&claim, &honest);
    assert_eq!(res.err(), Some(ContractError::StaleAnchor));

    Ok(())
}

#[test]
fn test_probe_n2e_context_from_committed_head_refuses_stale_and_mismatched_claims(
) -> Result<(), Box<dyn Error>> {
    let basis = fss_core::contract_basis::reference_contract_basis();
    let mut ledger = sample_ledger();
    let old_anchor = ledger.current().anchor.clone();

    advance_ledger(
        &mut ledger,
        "batch:probe_n2e",
        "delta:probe_n2e",
        "object:probe_n2e",
    )?;

    let ctx = AuthorityContext::from_committed_head(&basis, &ledger)?;
    assert_eq!(ctx.current_anchor().commit_sequence, 1);

    // 1. Stale claim at sequence 0 against context at sequence 1
    let witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:north_perimeter"],
        &["zone:north_perimeter"],
    );
    let mut target_domain = BTreeSet::new();
    target_domain.insert("zone:north_perimeter".to_string());
    let stale_claim = NegativeReadClaim {
        claim_id: "neg_claim:probe_n2e_stale".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: old_anchor.clone(),
        target_domain: target_domain.clone(),
        target_generation: 1,
        coverage_witness: Some(witness.clone()),
    };
    let res = evaluate_negative_read(&stale_claim, &ctx);
    assert_eq!(res.err(), Some(ContractError::StaleAnchor));

    // 2. Mismatched lineage claim against context
    let mut forged_anchor = old_anchor;
    forged_anchor.site_lineage = "site:arbitrary".to_string();
    let mut forged_witness = witness;
    forged_witness.anchor = forged_anchor.clone();
    let mismatched_claim = NegativeReadClaim {
        claim_id: "neg_claim:probe_n2e_lineage".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: forged_anchor,
        target_domain,
        target_generation: 1,
        coverage_witness: Some(forged_witness),
    };
    let res = evaluate_negative_read(&mismatched_claim, &ctx);
    assert_eq!(res.err(), Some(ContractError::StaleAnchor));

    Ok(())
}

#[test]
fn test_agent_abstraction_pinned_freeze_digest_and_generation() -> Result<(), Box<dyn Error>> {
    assert_eq!(AGENT_ABSTRACTION_GENERATION, "gen:fss1:abstraction-v1");
    assert_eq!(
        AGENT_ABSTRACTION_FREEZE_DIGEST,
        "sha256:98dfe512d870a36079fe49435d1f53d669c63a0034d03a771248fbab0abf34a9"
    );
    let stack_json = include_str!("../../../architecture/agent_abstraction_stack.json");
    assert!(
        stack_json.contains(AGENT_ABSTRACTION_FREEZE_DIGEST),
        "registryDigest in architecture/agent_abstraction_stack.json must match AGENT_ABSTRACTION_FREEZE_DIGEST"
    );
    Ok(())
}

#[test]
fn test_source_evidence_row_properties() -> Result<(), Box<dyn Error>> {
    let layer = AgentAbstractionLayer::SourceEvidence;
    assert_eq!(layer.id(), "AGT-LAYER-002");
    assert_eq!(layer.name(), "source_evidence");
    assert_eq!(format!("{layer}"), "source_evidence");
    assert_eq!(layer.owner(), "fss-capture/fss-media/fss-chronicle");
    assert_eq!(
        layer.agent_question(),
        "What exact packets, files, measurements, continuity, and capture-time intervals exist?"
    );
    assert_eq!(
        layer.output(),
        "Immutable sensor capsules, source objects, continuity and time evidence."
    );
    assert_eq!(
        layer.prohibition(),
        "Cannot promote decode or model output into source evidence."
    );
    assert_eq!(layer.invariant(), "INV-003");
    assert_eq!(layer.status(), "normative");
    assert_eq!(layer.plane(), Plane::Authority);
    assert_eq!(layer.tower_level(), 1);
    assert!(layer.may_claim_authority());
    assert!(!layer.may_authorize_effects());
    Ok(())
}

fn make_test_sensor_capsule(
    source_digest: ContentDigest,
    source_bytes: u64,
) -> Result<SensorCapsule, ContractError> {
    Ok(SensorCapsule {
        capsule_id: CapsuleId::parse("cap:001")?,
        sensor_id: SensorId::parse("sensor:cam01")?,
        stream_id: StreamId::parse("stream:front_gate")?,
        sequence: 42,
        capture: CaptureInterval {
            earliest: TimestampNs(1_700_000_000_000_000_000),
            latest: TimestampNs(1_700_000_005_000_000_000),
        },
        receive_time: TimestampNs(1_700_000_006_000_000_000),
        clock_basis: ClockBasis::HostMonotonic,
        source_digest,
        source_bytes,
        frame_count: 30,
        gap_before: false,
    })
}

#[test]
fn test_source_evidence_record_valid_construction() -> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("camera.sensor.front_gate");
    let source_digest = ContentDigest::sha256(b"raw-h264-nalu-data");
    let continuity_digest = ContentDigest::sha256(b"rtcp-continuity-witness-sequence-42");
    let capsule = make_test_sensor_capsule(source_digest, 1024)?;

    let record = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:packet:front_gate:0042".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Raw H.264 capture packets from front gate optical sensor".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::SensorCapsule,
        custody: SourceCustody::Retained {
            source_digest,
            source_bytes: 1024,
            storage_handle: "cas/sha256/raw-h264".to_string(),
        },
        omission: None,
        capsule: Some(capsule.clone()),
        continuity_witness: Some(continuity_digest),
    })?;

    assert_eq!(record.evidence_id(), "source:packet:front_gate:0042");
    assert_eq!(record.anchor(), &anchor);
    assert_eq!(record.generation(), Generation(1));
    assert_eq!(record.provenance(), ProvenanceClass::Observed);
    assert_eq!(
        record.classification(),
        SourceEvidenceClassification::SensorCapsule
    );
    assert_eq!(
        record.custody(),
        &SourceCustody::Retained {
            source_digest,
            source_bytes: 1024,
            storage_handle: "cas/sha256/raw-h264".to_string(),
        }
    );
    assert_eq!(record.omission(), None);
    assert_eq!(record.capsule(), Some(&capsule));
    assert_eq!(record.continuity_witness(), Some(continuity_digest));
    assert_eq!(record.layer(), AgentAbstractionLayer::SourceEvidence);
    assert_eq!(record.plane(), Plane::Authority);
    assert!(record.may_claim_authority());
    assert!(!record.may_authorize_effects());

    let kcell = record.to_knowledge_cell();
    assert_eq!(kcell.claim_id, "source:packet:front_gate:0042");
    assert_eq!(kcell.knowledge_state, KnowledgeState::Known);
    assert_eq!(kcell.provenance, ProvenanceClass::Observed);
    assert_eq!(
        kcell.evidence,
        vec![source_digest, capsule.metadata_digest(), continuity_digest]
    );
    assert!(kcell.validate().is_ok());

    Ok(())
}

#[test]
fn test_source_evidence_record_retention_forbidden_exemption() -> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("camera.sensor.restricted_area");

    let record = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:packet:restricted:0099".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Physical sensor reading where raw video retention is legally forbidden"
            .to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::PhysicalSensorMeasurement,
        custody: SourceCustody::NotRetained,
        omission: Some(OmissionReason::PrivacyRedaction),
        capsule: None,
        continuity_witness: None,
    })?;

    assert_eq!(record.custody(), &SourceCustody::NotRetained);
    assert_eq!(record.omission(), Some(OmissionReason::PrivacyRedaction));

    let kcell = record.to_knowledge_cell();
    assert!(kcell.evidence.is_empty());
    assert_eq!(kcell.knowledge_state, KnowledgeState::Redacted);
    assert_eq!(
        kcell.state_basis,
        Some(KnowledgeStateBasis::Redaction(RedactionMarker {
            reason: RedactionReason::PrivacyProjection,
            privacy_generation: PrivacyGeneration::canonical_v1(),
        }))
    );
    assert!(kcell.validate().is_ok());

    // Capability filtered maps to Redacted with CapabilityProjection basis
    let record_cap = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:packet:restricted:0101".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Capability filtered sensor stream".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::PhysicalSensorMeasurement,
        custody: SourceCustody::NotRetained,
        omission: Some(OmissionReason::CapabilityFiltered),
        capsule: None,
        continuity_witness: None,
    })?;
    let kcell_cap = record_cap.to_knowledge_cell();
    assert_eq!(kcell_cap.knowledge_state, KnowledgeState::Redacted);
    assert_eq!(
        kcell_cap.state_basis,
        Some(KnowledgeStateBasis::Redaction(RedactionMarker {
            reason: RedactionReason::CapabilityProjection,
            privacy_generation: PrivacyGeneration::canonical_v1(),
        }))
    );
    assert!(kcell_cap.validate().is_ok());

    // Non-genesis privacy epoch in anchor is truthfully propagated into RedactionMarker
    let mut anchor_v7 = anchor.clone();
    anchor_v7.privacy_epoch = 7;
    let record_v7 = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:packet:restricted:0102".to_string(),
        anchor: anchor_v7,
        generation: Generation(1),
        statement: "Privacy redacted frame under epoch 7".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::PhysicalSensorMeasurement,
        custody: SourceCustody::NotRetained,
        omission: Some(OmissionReason::PrivacyRedaction),
        capsule: None,
        continuity_witness: None,
    })?;
    let kcell_v7 = record_v7.to_knowledge_cell();
    assert_eq!(
        kcell_v7.state_basis,
        Some(KnowledgeStateBasis::Redaction(RedactionMarker {
            reason: RedactionReason::PrivacyProjection,
            privacy_generation: PrivacyGeneration::parse("privacy:projection:v7")?,
        }))
    );
    assert!(kcell_v7.validate().is_ok());

    // Upstream missing maps to NotObservable
    let record_upstream = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:packet:restricted:0100".to_string(),
        anchor,
        generation: Generation(1),
        statement: "Upstream sensor dropout".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::SourcePayloadFile,
        custody: SourceCustody::NotRetained,
        omission: Some(OmissionReason::UpstreamMissing),
        capsule: None,
        continuity_witness: None,
    })?;
    let kcell_upstream = record_upstream.to_knowledge_cell();
    assert!(kcell_upstream.evidence.is_empty());
    assert_eq!(
        kcell_upstream.knowledge_state,
        KnowledgeState::NotObservable
    );
    assert!(kcell_upstream.validate().is_ok());

    Ok(())
}

#[test]
fn test_source_evidence_gap_before_maps_to_unknown_without_fabricated_basis()
-> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("camera.sensor.gap_sensor");
    let source_digest = ContentDigest::sha256(b"source-with-gap");
    let mut capsule = make_test_sensor_capsule(source_digest, 512)?;
    capsule.gap_before = true;

    let record = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:gap:001".to_string(),
        anchor,
        generation: Generation(2),
        statement: "Capsule preceded by gap".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::SensorCapsule,
        custody: SourceCustody::Retained {
            source_digest,
            source_bytes: 512,
            storage_handle: "cas/gap/bytes".to_string(),
        },
        omission: None,
        capsule: Some(capsule),
        continuity_witness: None,
    })?;

    let kcell = record.to_knowledge_cell();
    assert_eq!(kcell.knowledge_state, KnowledgeState::Unknown);
    // The gap reason is a typed basis derived from the capsule's own `gap_before` flag, not a
    // fabricated stale/redaction basis and not free text appended to the statement.
    assert_eq!(
        kcell.state_basis,
        Some(KnowledgeStateBasis::Unknown(
            UnknownReason::ContinuityGapBeforeCapsule
        ))
    );
    assert_eq!(kcell.statement, "Capsule preceded by gap");
    assert!(!kcell.statement.contains("continuity gap before capsule"));
    assert!(kcell.validate().is_ok());

    // The typed reason is only accepted on an `unknown` cell.
    let mut mismatched = kcell.clone();
    mismatched.knowledge_state = KnowledgeState::Known;
    assert_eq!(
        mismatched.validate(),
        Err(ContractError::KnowledgeStateBasisMismatch)
    );

    Ok(())
}

#[test]
fn test_planted_negative_source_evidence_bypasses() -> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("camera.sensor.cam01");
    let source_digest = ContentDigest::sha256(b"raw-packet-bytes");
    let valid_custody = SourceCustody::Retained {
        source_digest,
        source_bytes: 1024,
        storage_handle: "cas/sha256/raw-packet".to_string(),
    };

    // 1. Empty ID rejected with InvalidIdentifier
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Valid statement".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: valid_custody.clone(),
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::InvalidIdentifier));

    // Path traversal /../ in ID rejected with InvalidIdentifier
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:packet/../cam01".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Valid statement".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: valid_custody.clone(),
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::InvalidIdentifier));

    // Newline in ID rejected with InvalidIdentifier
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:packet\ncam01".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Valid statement".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: valid_custody.clone(),
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::InvalidIdentifier));

    // 2. Empty anchor site lineage rejected with SourceEvidenceMissingAnchor
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: LedgerAnchor::genesis(""),
        generation: Generation(1),
        statement: "Valid statement".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: valid_custody.clone(),
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::SourceEvidenceMissingAnchor));

    // 3. Zero generation rejected with GenerationConflict
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(0),
        statement: "Valid statement".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: valid_custody.clone(),
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::GenerationConflict));

    // 4. Empty statement rejected with SourceEvidenceStatementMalformed
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: valid_custody.clone(),
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::SourceEvidenceStatementMalformed));

    // 5. INV-003 violation: NotRetained without omission reason
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Missing both source and retention exemption".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: SourceCustody::NotRetained,
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::SourceEvidenceOmissionRequired));

    // NotRetained with omission Some(OmissionReason::None) rejected with SourceEvidenceOmissionRequired
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Missing valid retention exemption reason".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: SourceCustody::NotRetained,
        omission: Some(OmissionReason::None),
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::SourceEvidenceOmissionRequired));

    // NotRetained with omission reason but capsule with bytes > 0 rejected with SourceEvidenceNotRetainedWithCapsuleBytes
    let cap_with_bytes = make_test_sensor_capsule(source_digest, 1024)?;
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "NotRetained but capsule has bytes".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::SensorCapsule,
        custody: SourceCustody::NotRetained,
        omission: Some(OmissionReason::ResourcePressure),
        capsule: Some(cap_with_bytes),
        continuity_witness: None,
    });
    assert_eq!(
        res,
        Err(ContractError::SourceEvidenceNotRetainedWithCapsuleBytes)
    );

    // Retained with an omission reason rejected with SourceEvidenceRetainedWithOmission
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Retained with omission reason".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: valid_custody.clone(),
        omission: Some(OmissionReason::PrivacyRedaction),
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::SourceEvidenceRetainedWithOmission));

    // Retained with Some(OmissionReason::None) rejected with SourceEvidenceRetainedWithOmission
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Retained with Some(OmissionReason::None)".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: valid_custody.clone(),
        omission: Some(OmissionReason::None),
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::SourceEvidenceRetainedWithOmission));

    // Custody source_bytes != capsule source_bytes rejected with SourceEvidenceByteCountMismatch
    let cap_mismatch_bytes = make_test_sensor_capsule(source_digest, 99)?;
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Custody bytes mismatch capsule bytes".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::SensorCapsule,
        custody: SourceCustody::Retained {
            source_digest,
            source_bytes: 1024,
            storage_handle: "cas/sha256/raw-packet".to_string(),
        },
        omission: None,
        capsule: Some(cap_mismatch_bytes),
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::SourceEvidenceByteCountMismatch));

    // Digest mismatch: Custody source_digest != capsule source_digest rejected with DigestMismatch
    let different_digest = ContentDigest::sha256(b"different-source-digest");
    let cap_different_digest = make_test_sensor_capsule(different_digest, 1024)?;
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Custody digest mismatch capsule digest".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::SensorCapsule,
        custody: SourceCustody::Retained {
            source_digest,
            source_bytes: 1024,
            storage_handle: "cas/sha256/raw-packet".to_string(),
        },
        omission: None,
        capsule: Some(cap_different_digest),
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::DigestMismatch));

    // Classification parse refuses unknown tokens with UnknownSourceEvidenceClassification
    assert_eq!(
        SourceEvidenceClassification::parse("decoded_frame_pcap"),
        Err(ContractError::UnknownSourceEvidenceClassification(
            "decoded_frame_pcap".to_string()
        ))
    );
    assert_eq!(
        SourceEvidenceClassification::parse("model-output file"),
        Err(ContractError::UnknownSourceEvidenceClassification(
            "model-output file".to_string()
        ))
    );
    assert_eq!(
        SourceEvidenceClassification::parse("rgb-pixels from sensor"),
        Err(ContractError::UnknownSourceEvidenceClassification(
            "rgb-pixels from sensor".to_string()
        ))
    );
    assert_eq!(
        SourceEvidenceClassification::parse(" RAW_WIRE_PACKETS "),
        Err(ContractError::UnknownSourceEvidenceClassification(
            " RAW_WIRE_PACKETS ".to_string()
        ))
    );
    assert_eq!(
        SourceEvidenceClassification::parse(""),
        Err(ContractError::UnknownSourceEvidenceClassification(
            "".to_string()
        ))
    );

    // Canonical decoder refuses non-canonical classification tokens
    let mut encoder = CanonicalEncoder::new();
    encoder.text("decoded_frame_pcap");
    let bytes = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&bytes);
    assert_eq!(
        SourceEvidenceClassification::decode_canonical(&mut decoder),
        Err(ContractError::UnknownSourceEvidenceClassification(
            "decoded_frame_pcap".to_string()
        ))
    );

    // Prohibited classifications return ProhibitedEvidencePromotion
    let prohibited_kinds = [
        SourceEvidenceClassification::DecodedFrameBuffer,
        SourceEvidenceClassification::ModelInferenceOutput,
        SourceEvidenceClassification::DerivedCognition,
    ];
    for prohibited in prohibited_kinds {
        assert!(prohibited.is_prohibited());
        assert!(!prohibited.is_permitted());
        let res = SourceEvidenceRecord::new(SourceEvidenceParams {
            evidence_id: "source:001".to_string(),
            anchor: anchor.clone(),
            generation: Generation(1),
            statement: "Valid statement".to_string(),
            provenance: ProvenanceClass::Observed,
            classification: prohibited,
            custody: valid_custody.clone(),
            omission: None,
            capsule: None,
            continuity_witness: None,
        });
        assert_eq!(res, Err(ContractError::ProhibitedEvidencePromotion));
    }

    // Non-Observed provenance rejected with ProhibitedEvidencePromotion
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Valid statement".to_string(),
        provenance: ProvenanceClass::Derived,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: valid_custody.clone(),
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::ProhibitedEvidencePromotion));

    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor,
        generation: Generation(1),
        statement: "Valid statement".to_string(),
        provenance: ProvenanceClass::Predicted,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: valid_custody,
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::ProhibitedEvidencePromotion));

    Ok(())
}

#[test]
fn test_source_evidence_not_retained_mutant_m7_kill() -> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("camera.sensor.m7");
    let zero_digest = ContentDigest::new(DigestAlgorithm::Sha256, [0u8; 32]);
    let non_zero_digest = ContentDigest::sha256(b"some-bytes");

    // Condition A: source_bytes > 0, digest == 0, frame_count == 0
    let mut cap_a = make_test_sensor_capsule(zero_digest, 100)?;
    cap_a.frame_count = 0;
    let res_a = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:m7:a".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "M7 test condition A".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::SensorCapsule,
        custody: SourceCustody::NotRetained,
        omission: Some(OmissionReason::ResourcePressure),
        capsule: Some(cap_a),
        continuity_witness: None,
    });
    assert_eq!(
        res_a,
        Err(ContractError::SourceEvidenceNotRetainedWithCapsuleBytes)
    );

    // Condition B: source_bytes == 0, digest != 0, frame_count == 0
    let mut cap_b = make_test_sensor_capsule(non_zero_digest, 0)?;
    cap_b.frame_count = 0;
    let res_b = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:m7:b".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "M7 test condition B".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::SensorCapsule,
        custody: SourceCustody::NotRetained,
        omission: Some(OmissionReason::ResourcePressure),
        capsule: Some(cap_b),
        continuity_witness: None,
    });
    assert_eq!(
        res_b,
        Err(ContractError::SourceEvidenceNotRetainedWithCapsuleBytes)
    );

    // Condition C: source_bytes == 0, digest == 0, frame_count == 30
    let mut cap_c = make_test_sensor_capsule(zero_digest, 0)?;
    cap_c.frame_count = 30;
    let res_c = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:m7:c".to_string(),
        anchor,
        generation: Generation(1),
        statement: "M7 test condition C".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::SensorCapsule,
        custody: SourceCustody::NotRetained,
        omission: Some(OmissionReason::ResourcePressure),
        capsule: Some(cap_c),
        continuity_witness: None,
    });
    assert_eq!(
        res_c,
        Err(ContractError::SourceEvidenceNotRetainedWithCapsuleBytes)
    );

    Ok(())
}

#[test]
fn test_source_evidence_cross_checks_and_payload_binding() -> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("camera.sensor.cross_checks");
    let source_digest = ContentDigest::sha256(b"cross-check-source");
    let witness_digest = ContentDigest::sha256(b"cross-check-witness");
    let valid_custody = SourceCustody::Retained {
        source_digest,
        source_bytes: 1024,
        storage_handle: "cas/valid/handle".to_string(),
    };
    let valid_capsule = make_test_sensor_capsule(source_digest, 1024)?;

    // 1. Classification SensorCapsule requires capsule payload
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:cc:01".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Missing capsule".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::SensorCapsule,
        custody: valid_custody.clone(),
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::SourceEvidenceCapsuleRequired));

    // 2. Classification ContinuityWitness requires witness payload
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:cc:02".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Missing witness".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::ContinuityWitness,
        custody: valid_custody.clone(),
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::SourceEvidenceWitnessRequired));

    // 3. NotRetained with continuity_witness rejected
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:cc:03".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "NotRetained with witness".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::PhysicalSensorMeasurement,
        custody: SourceCustody::NotRetained,
        omission: Some(OmissionReason::RetentionPolicy),
        capsule: None,
        continuity_witness: Some(witness_digest),
    });
    assert_eq!(
        res,
        Err(ContractError::SourceEvidenceNotRetainedWithWitness)
    );

    // 4. Continuity witness equals source digest rejected
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:cc:04".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Circular witness".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: valid_custody.clone(),
        omission: None,
        capsule: None,
        continuity_witness: Some(source_digest),
    });
    assert_eq!(
        res,
        Err(ContractError::SourceEvidenceWitnessEqualsSourceDigest)
    );

    // 5. source_bytes == u64::MAX rejected with ArithmeticOverflow
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:cc:05".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Max source bytes".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: SourceCustody::Retained {
            source_digest,
            source_bytes: u64::MAX,
            storage_handle: "cas/overflow".to_string(),
        },
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::ArithmeticOverflow));

    // 6. Zero source bytes in Retained custody
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:cc:06".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Zero source bytes".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: SourceCustody::Retained {
            source_digest,
            source_bytes: 0,
            storage_handle: "cas/zero".to_string(),
        },
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::EvidenceRequired));

    // 7. Zero source digest in Retained custody
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:cc:07".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Zero source digest".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: SourceCustody::Retained {
            source_digest: ContentDigest::new(DigestAlgorithm::Sha256, [0u8; 32]),
            source_bytes: 1024,
            storage_handle: "cas/zero_dig".to_string(),
        },
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::InvalidDigest));

    // 8. Zero continuity witness
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:cc:08".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Zero continuity witness".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: valid_custody,
        omission: None,
        capsule: None,
        continuity_witness: Some(ContentDigest::new(DigestAlgorithm::Sha256, [0u8; 32])),
    });
    assert_eq!(res, Err(ContractError::InvalidDigest));

    // 9. Inverted capture interval on capsule
    let mut inv_cap = valid_capsule.clone();
    inv_cap.capture.earliest = TimestampNs(2_000_000_000);
    inv_cap.capture.latest = TimestampNs(1_000_000_000);
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:cc:09".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Inverted interval".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::SensorCapsule,
        custody: SourceCustody::Retained {
            source_digest,
            source_bytes: 1024,
            storage_handle: "cas/inv".to_string(),
        },
        omission: None,
        capsule: Some(inv_cap),
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::InvertedTimeInterval));

    // 10. receive_time before capture window
    let mut early_rx_cap = valid_capsule;
    early_rx_cap.capture.earliest = TimestampNs(2_000_000_000);
    early_rx_cap.capture.latest = TimestampNs(3_000_000_000);
    early_rx_cap.receive_time = TimestampNs(1_000_000_000);
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:cc:10".to_string(),
        anchor,
        generation: Generation(1),
        statement: "Early receive time".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::SensorCapsule,
        custody: SourceCustody::Retained {
            source_digest,
            source_bytes: 1024,
            storage_handle: "cas/early".to_string(),
        },
        omission: None,
        capsule: Some(early_rx_cap),
        continuity_witness: None,
    });
    assert_eq!(res, Err(ContractError::InvertedTimeInterval));

    Ok(())
}

#[test]
fn test_source_evidence_storage_handle_and_id_sanitization() -> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("camera.sensor.sanitize");
    let source_digest = ContentDigest::sha256(b"sanitize-source");

    let make_handle_record = |handle: &str| {
        SourceEvidenceRecord::new(SourceEvidenceParams {
            evidence_id: "source:san:01".to_string(),
            anchor: anchor.clone(),
            generation: Generation(1),
            statement: "Storage handle test".to_string(),
            provenance: ProvenanceClass::Observed,
            classification: SourceEvidenceClassification::RawWirePackets,
            custody: SourceCustody::Retained {
                source_digest,
                source_bytes: 1024,
                storage_handle: handle.to_string(),
            },
            omission: None,
            capsule: None,
            continuity_witness: None,
        })
    };

    // 1. Empty handle
    assert_eq!(
        make_handle_record(""),
        Err(ContractError::SourceEvidenceEmptyStorageHandle)
    );

    // 2. Traversal handles: a `.` or `..` segment anywhere.
    let traversal_handles = [
        "..",
        ".",
        "../../etc/shadow",
        "../parent",
        "dir/./file",
        "dir/../file",
        "./x",
        "a/./b",
        "../x",
        "a/../b",
        "a/..",
    ];
    for handle in traversal_handles {
        assert_eq!(
            make_handle_record(handle),
            Err(ContractError::SourceEvidenceStorageHandleTraversal),
            "handle: {handle}"
        );
    }

    // 2b. Any `%` is refused as percent-encoding, never decoded and never reported as
    // traversal: `foo%bar` names no traversal, and `%2e` / `%252e` are refused before decoding.
    let percent_handles = [
        "%2e%2e/etc/passwd",
        "safe/%2E%2E/secret",
        "%2e./escape",
        ".%2e/escape",
        "%2e/x",
        "%252e/escape",
        "%252e/x",
        "dir/%2e%2e",
        "foo%bar",
        "%",
    ];
    for handle in percent_handles {
        assert_eq!(
            make_handle_record(handle),
            Err(ContractError::SourceEvidenceStorageHandlePercentEncodingRefused),
            "handle: {handle}"
        );
    }

    // 3. Absolute path, URLs, schemes, drive letters
    let abs_path_handles = [
        "/etc/shadow",
        "/leading_slash",
        "\\windows\\system32",
        "\\\\server\\share",
        "file:///etc/shadow",
        "file:/tmp/payload",
        "ftp://archive/payload",
        "smb://server/share",
        "s3://bucket/key",
        "cas://safe/secret",
        "http://evil.com/leak",
        "https://evil.com/leak",
        "c:foo",
        "C:\\Windows\\system32",
        "c:/windows/system32",
        "d:drive_letter",
        "//empty_leading",
    ];
    for handle in abs_path_handles {
        assert_eq!(
            make_handle_record(handle),
            Err(ContractError::SourceEvidenceStorageHandleAbsolutePath),
            "handle: {handle}"
        );
    }

    // 4a. Empty segments: a doubled or trailing separator.
    let empty_segment_handles = ["foo//bar", "trailing/slash/", "middle///triple", "a/"];
    for handle in empty_segment_handles {
        assert_eq!(
            make_handle_record(handle),
            Err(ContractError::SourceEvidenceStorageHandleEmptySegment),
            "handle: {handle}"
        );
    }

    // 4b. Characters outside the allow-list (spaces, bidi, format, control, non-ASCII,
    // backslash), each refused with the dedicated disallowed-character code.
    let malformed_handles = [
        // Spaces
        " ",
        "   ",
        " leading_space",
        "trailing_space ",
        "embedded space",
        // Bidi, format, control, unicode fullwidth
        "\u{2066}isolate",
        "\u{202A}embed",
        "\u{061C}arabic_mark",
        "\u{2028}line_sep",
        "\u{3000}ideographic_space",
        "\u{00A0}nbsp",
        "fullwidth\u{FF0E}dot",
        "null\0byte",
        "newline\npath",
        "cr\rpath",
        "zero\u{200B}width",
        "bom\u{FEFF}mark",
        "rtl\u{202E}override",
        "soft\u{00AD}hyphen",
        "narrow\u{202F}nbsp",
        "joiner\u{2060}word",
        "a\u{2066}b",
        "a\u{202A}b",
        "a\u{061C}b",
        "a\u{2028}b",
        "a\u{3000}b",
        "a\u{00A0}b",
        "a/\u{FF0E}\u{FF0E}/b",
        "a/\u{3002}/b",
        "a b",
        "a\\b",
    ];
    for handle in malformed_handles {
        assert_eq!(
            make_handle_record(handle),
            Err(ContractError::SourceEvidenceStorageHandleDisallowedCharacter),
            "handle: {handle}"
        );
    }

    // 4c. Over-length is its own code, distinct from a disallowed character; the bound is
    // inclusive at 4096 bytes.
    let over_length_handle = "a".repeat(4097);
    assert_eq!(
        make_handle_record(&over_length_handle),
        Err(ContractError::SourceEvidenceStorageHandleOverLength)
    );
    assert!(make_handle_record(&"a".repeat(4096)).is_ok());

    // 4d. Empty segment, over-length, disallowed character, percent and traversal refusals
    // carry five distinct stable codes.
    let codes = BTreeSet::from([
        ContractError::SourceEvidenceStorageHandleEmptySegment.code(),
        ContractError::SourceEvidenceStorageHandleOverLength.code(),
        ContractError::SourceEvidenceStorageHandleDisallowedCharacter.code(),
        ContractError::SourceEvidenceStorageHandlePercentEncodingRefused.code(),
        ContractError::SourceEvidenceStorageHandleTraversal.code(),
    ]);
    assert_eq!(codes.len(), 5);
    assert_eq!(
        ContractError::SourceEvidenceStorageHandlePercentEncodingRefused.code(),
        "source_evidence_storage_handle_percent_encoding_refused"
    );

    // 5. Valid handles accepted
    let valid_handles = [
        "cas/safe/handle",
        "a",
        "payload-01.bin",
        "retained_evidence-01.dat",
        "dir/sub.dir/file_name-1.dat",
    ];
    for handle in valid_handles {
        assert!(make_handle_record(handle).is_ok(), "valid handle: {handle}");
    }

    // 6. Bad IDs (refuse . or .. as ANY segment)
    let bad_ids = [
        ".",
        "..",
        ":",
        "..:..:etc",
        "source:..:x",
        "a:.:b",
        ".:foo",
        "bar:.",
        "source:valid:01:..:tail",
    ];
    for bad_id in bad_ids {
        let res = SourceEvidenceRecord::new(SourceEvidenceParams {
            evidence_id: bad_id.to_string(),
            anchor: anchor.clone(),
            generation: Generation(1),
            statement: "Bad ID test".to_string(),
            provenance: ProvenanceClass::Observed,
            classification: SourceEvidenceClassification::RawWirePackets,
            custody: SourceCustody::Retained {
                source_digest,
                source_bytes: 1024,
                storage_handle: "cas/good/handle".to_string(),
            },
            omission: None,
            capsule: None,
            continuity_witness: None,
        });
        assert_eq!(res, Err(ContractError::InvalidIdentifier), "id: {bad_id}");
    }

    // 7. RawWirePackets carrying a capsule is strictly refused
    let capsule = make_test_sensor_capsule(source_digest, 1024)?;
    let raw_with_capsule = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:raw:with:capsule".to_string(),
        anchor,
        generation: Generation(1),
        statement: "Raw packets illegally carrying sensor capsule".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: SourceCustody::Retained {
            source_digest,
            source_bytes: 1024,
            storage_handle: "cas/good/handle".to_string(),
        },
        omission: None,
        capsule: Some(capsule),
        continuity_witness: None,
    });
    assert_eq!(
        raw_with_capsule,
        Err(ContractError::SourceEvidenceRawWirePacketsWithCapsule)
    );

    Ok(())
}

#[test]
fn test_source_evidence_statement_512_byte_boundary() -> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("camera.sensor.boundary");
    let source_digest = ContentDigest::sha256(b"boundary-payload");
    let custody = SourceCustody::Retained {
        source_digest,
        source_bytes: 1024,
        storage_handle: "cas/boundary".to_string(),
    };

    // 0 bytes: Err
    let res0 = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:stmt:0".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: custody.clone(),
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(res0, Err(ContractError::SourceEvidenceStatementMalformed));

    // 1 byte: Ok
    let res1 = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:stmt:1".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "x".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: custody.clone(),
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert!(res1.is_ok());

    // 512 bytes: Ok
    let stmt_512 = "a".repeat(512);
    let res512 = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:stmt:512".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: stmt_512,
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: custody.clone(),
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert!(res512.is_ok());

    // 513 bytes: Err
    let stmt_513 = "a".repeat(513);
    let res513 = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:stmt:513".to_string(),
        anchor,
        generation: Generation(1),
        statement: stmt_513,
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody,
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(res513, Err(ContractError::SourceEvidenceStatementMalformed));

    Ok(())
}

#[test]
fn test_source_evidence_decode_path_negatives_kill_m8_m9_m10() -> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("camera.sensor.dec_neg");
    let source_digest = ContentDigest::sha256(b"dec-neg-source");
    let continuity_digest = ContentDigest::sha256(b"dec-neg-witness");
    let capsule = make_test_sensor_capsule(source_digest, 1024)?;

    let valid_record = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:dec:001".to_string(),
        anchor,
        generation: Generation(1),
        statement: "Valid record for decode negation testing".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::SensorCapsule,
        custody: SourceCustody::Retained {
            source_digest,
            source_bytes: 1024,
            storage_handle: "cas/dec/neg".to_string(),
        },
        omission: None,
        capsule: Some(capsule),
        continuity_witness: Some(continuity_digest),
    })?;

    let valid_bytes = valid_record.to_canonical_bytes()?;

    // 1. Invalid version envelope (version 1 or 99)
    let mut bad_ver_bytes = valid_bytes.clone();
    bad_ver_bytes[0..4].copy_from_slice(&1u32.to_be_bytes());
    let mut decoder = CanonicalDecoder::new(&bad_ver_bytes);
    assert_eq!(
        SourceEvidenceRecord::decode_canonical(&mut decoder),
        Err(ContractError::UnsupportedSourceEvidenceVersion(1))
    );

    // 2. Trailing unparsed bytes: decode_canonical succeeds leaving trailing bytes for siblings;
    // from_canonical_bytes rejects trailing bytes with NonCanonicalOrdering
    let mut trailing_bytes = valid_bytes.clone();
    trailing_bytes.push(0xFF);
    let mut decoder = CanonicalDecoder::new(&trailing_bytes);
    let decoded_sibling = SourceEvidenceRecord::decode_canonical(&mut decoder)?;
    assert_eq!(decoded_sibling, valid_record);
    assert_eq!(decoder.remaining(), 1);
    assert_eq!(
        SourceEvidenceRecord::from_canonical_bytes(&trailing_bytes),
        Err(ContractError::NonCanonicalOrdering)
    );

    // 3. Unknown custody tag (tag = 5)
    let mut encoder = CanonicalEncoder::new();
    encoder.u32(SOURCE_EVIDENCE_RECORD_FORMAT_VERSION);
    encoder.text("source:dec:custody");
    valid_record.anchor().encode_canonical(&mut encoder);
    encoder.u64(1);
    encoder.text("statement");
    valid_record.provenance().encode_canonical(&mut encoder);
    valid_record.classification().encode_canonical(&mut encoder);
    encoder.u8(5); // Unknown custody tag
    let raw = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&raw);
    assert_eq!(
        SourceEvidenceRecord::decode_canonical(&mut decoder),
        Err(ContractError::UnknownSourceCustodyTag(5))
    );

    // 4. Provenance alias "PROV-001" refused on decode
    let mut encoder = CanonicalEncoder::new();
    encoder.u32(SOURCE_EVIDENCE_RECORD_FORMAT_VERSION);
    encoder.text("source:dec:prov");
    valid_record.anchor().encode_canonical(&mut encoder);
    encoder.u64(1);
    encoder.text("statement");
    encoder.text("PROV-001"); // Non-canonical alias
    let raw = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&raw);
    assert_eq!(
        SourceEvidenceRecord::decode_canonical(&mut decoder),
        Err(ContractError::InvalidIdentifier)
    );

    // 5. Empty statement refused on decode
    let mut encoder = CanonicalEncoder::new();
    encoder.u32(SOURCE_EVIDENCE_RECORD_FORMAT_VERSION);
    encoder.text("source:dec:stmt_empty");
    valid_record.anchor().encode_canonical(&mut encoder);
    encoder.u64(1);
    encoder.text(""); // Empty statement
    valid_record.provenance().encode_canonical(&mut encoder);
    valid_record.classification().encode_canonical(&mut encoder);
    valid_record.custody().encode_canonical(&mut encoder);
    encoder.bool(false);
    encoder.bool(false);
    encoder.bool(false);
    let raw = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&raw);
    assert_eq!(
        SourceEvidenceRecord::decode_canonical(&mut decoder),
        Err(ContractError::SourceEvidenceStatementMalformed)
    );

    // 6. Statement > 512 bytes refused on decode
    let mut encoder = CanonicalEncoder::new();
    encoder.u32(SOURCE_EVIDENCE_RECORD_FORMAT_VERSION);
    encoder.text("source:dec:stmt_long");
    valid_record.anchor().encode_canonical(&mut encoder);
    encoder.u64(1);
    encoder.text(&"x".repeat(513)); // 513 bytes
    valid_record.provenance().encode_canonical(&mut encoder);
    valid_record.classification().encode_canonical(&mut encoder);
    valid_record.custody().encode_canonical(&mut encoder);
    encoder.bool(false);
    encoder.bool(false);
    encoder.bool(false);
    let raw = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&raw);
    assert_eq!(
        SourceEvidenceRecord::decode_canonical(&mut decoder),
        Err(ContractError::SourceEvidenceStatementMalformed)
    );

    // 7. Generation 0 refused on decode
    let mut encoder = CanonicalEncoder::new();
    encoder.u32(SOURCE_EVIDENCE_RECORD_FORMAT_VERSION);
    encoder.text("source:dec:gen0");
    valid_record.anchor().encode_canonical(&mut encoder);
    encoder.u64(0); // Gen 0
    encoder.text("statement");
    valid_record.provenance().encode_canonical(&mut encoder);
    valid_record.classification().encode_canonical(&mut encoder);
    valid_record.custody().encode_canonical(&mut encoder);
    encoder.bool(false);
    encoder.bool(false);
    encoder.bool(false);
    let raw = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&raw);
    assert_eq!(
        SourceEvidenceRecord::decode_canonical(&mut decoder),
        Err(ContractError::GenerationConflict)
    );

    // 8. ID "." refused on decode
    let mut encoder = CanonicalEncoder::new();
    encoder.u32(SOURCE_EVIDENCE_RECORD_FORMAT_VERSION);
    encoder.text(".");
    valid_record.anchor().encode_canonical(&mut encoder);
    encoder.u64(1);
    encoder.text("statement");
    valid_record.provenance().encode_canonical(&mut encoder);
    valid_record.classification().encode_canonical(&mut encoder);
    valid_record.custody().encode_canonical(&mut encoder);
    encoder.bool(false);
    encoder.bool(false);
    encoder.bool(false);
    let raw = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&raw);
    assert_eq!(
        SourceEvidenceRecord::decode_canonical(&mut decoder),
        Err(ContractError::InvalidIdentifier)
    );

    // 9. SensorCapsule without capsule payload refused on decode
    let mut encoder = CanonicalEncoder::new();
    encoder.u32(SOURCE_EVIDENCE_RECORD_FORMAT_VERSION);
    encoder.text("source:dec:nocapsule");
    valid_record.anchor().encode_canonical(&mut encoder);
    encoder.u64(1);
    encoder.text("statement");
    valid_record.provenance().encode_canonical(&mut encoder);
    SourceEvidenceClassification::SensorCapsule.encode_canonical(&mut encoder);
    valid_record.custody().encode_canonical(&mut encoder);
    encoder.bool(false); // omission: none
    encoder.bool(false); // capsule: none (VIOLATION)
    encoder.bool(false); // witness: none
    let raw = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&raw);
    assert_eq!(
        SourceEvidenceRecord::decode_canonical(&mut decoder),
        Err(ContractError::SourceEvidenceCapsuleRequired)
    );

    // 10. ContinuityWitness without witness payload refused on decode
    let mut encoder = CanonicalEncoder::new();
    encoder.u32(SOURCE_EVIDENCE_RECORD_FORMAT_VERSION);
    encoder.text("source:dec:nowitness");
    valid_record.anchor().encode_canonical(&mut encoder);
    encoder.u64(1);
    encoder.text("statement");
    valid_record.provenance().encode_canonical(&mut encoder);
    SourceEvidenceClassification::ContinuityWitness.encode_canonical(&mut encoder);
    valid_record.custody().encode_canonical(&mut encoder);
    encoder.bool(false); // omission: none
    encoder.bool(false); // capsule: none
    encoder.bool(false); // witness: none (VIOLATION)
    let raw = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&raw);
    assert_eq!(
        SourceEvidenceRecord::decode_canonical(&mut decoder),
        Err(ContractError::SourceEvidenceWitnessRequired)
    );

    // 11. Circular continuity witness (equals source digest) refused on decode
    let mut encoder = CanonicalEncoder::new();
    encoder.u32(SOURCE_EVIDENCE_RECORD_FORMAT_VERSION);
    encoder.text("source:dec:circ_witness");
    valid_record.anchor().encode_canonical(&mut encoder);
    encoder.u64(1);
    encoder.text("statement");
    valid_record.provenance().encode_canonical(&mut encoder);
    valid_record.classification().encode_canonical(&mut encoder);
    valid_record.custody().encode_canonical(&mut encoder);
    encoder.bool(false); // omission: none
    encoder.bool(true);
    if let Some(cap) = valid_record.capsule() {
        cap.encode_canonical(&mut encoder);
    }
    encoder.bool(true);
    encoder.digest(source_digest); // EQUALS SOURCE DIGEST (VIOLATION)
    let raw = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&raw);
    assert_eq!(
        SourceEvidenceRecord::decode_canonical(&mut decoder),
        Err(ContractError::SourceEvidenceWitnessEqualsSourceDigest)
    );

    // 12. NotRetained with continuity witness refused on decode
    let mut encoder = CanonicalEncoder::new();
    encoder.u32(SOURCE_EVIDENCE_RECORD_FORMAT_VERSION);
    encoder.text("source:dec:not_ret_wit");
    valid_record.anchor().encode_canonical(&mut encoder);
    encoder.u64(1);
    encoder.text("statement");
    valid_record.provenance().encode_canonical(&mut encoder);
    SourceEvidenceClassification::PhysicalSensorMeasurement.encode_canonical(&mut encoder);
    SourceCustody::NotRetained.encode_canonical(&mut encoder);
    encoder.bool(true);
    OmissionReason::RetentionPolicy.encode_canonical(&mut encoder);
    encoder.bool(false); // capsule: none
    encoder.bool(true); // witness: present (VIOLATION)
    encoder.digest(continuity_digest);
    let raw = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&raw);
    assert_eq!(
        SourceEvidenceRecord::decode_canonical(&mut decoder),
        Err(ContractError::SourceEvidenceNotRetainedWithWitness)
    );

    Ok(())
}

#[test]
fn test_clock_basis_and_sensor_capsule_canonical_codecs() -> Result<(), Box<dyn Error>> {
    // ClockBasis::parse succeeds on canonical strings
    assert_eq!(
        ClockBasis::parse("utc_disciplined")?,
        ClockBasis::UtcDisciplined
    );
    assert_eq!(
        ClockBasis::parse("device_monotonic")?,
        ClockBasis::DeviceMonotonic
    );
    assert_eq!(
        ClockBasis::parse("host_monotonic")?,
        ClockBasis::HostMonotonic
    );
    assert_eq!(ClockBasis::parse("estimated")?, ClockBasis::Estimated);

    // ClockBasis::parse fails on unknown string with UnknownClockBasisName
    assert_eq!(
        ClockBasis::parse("invalid_clock_basis"),
        Err(ContractError::UnknownClockBasisName(
            "invalid_clock_basis".to_string()
        ))
    );

    // SensorCapsule canonical roundtrip
    let source_digest = ContentDigest::sha256(b"sensor-capsule-test-bytes");
    let capsule = make_test_sensor_capsule(source_digest, 2048)?;

    let mut encoder = CanonicalEncoder::new();
    capsule.encode_canonical(&mut encoder);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let decoded = SensorCapsule::decode_canonical(&mut decoder)?;
    assert_eq!(decoded, capsule);

    // SensorCapsule decode fails on inverted interval
    let mut bad_enc = CanonicalEncoder::new();
    let mut bad_cap = capsule.clone();
    bad_cap.capture.earliest = TimestampNs(2_000);
    bad_cap.capture.latest = TimestampNs(1_000);
    bad_cap.encode_canonical(&mut bad_enc);
    let bad_bytes = bad_enc.finish();
    let mut decoder = CanonicalDecoder::new(&bad_bytes);
    assert_eq!(
        SensorCapsule::decode_canonical(&mut decoder),
        Err(ContractError::InvertedTimeInterval)
    );

    // SensorCapsule decode fails on receive_time < earliest
    let mut bad_enc = CanonicalEncoder::new();
    let mut bad_cap = capsule;
    bad_cap.receive_time = TimestampNs(bad_cap.capture.earliest.0 - 1);
    bad_cap.encode_canonical(&mut bad_enc);
    let bad_bytes = bad_enc.finish();
    let mut decoder = CanonicalDecoder::new(&bad_bytes);
    assert_eq!(
        SensorCapsule::decode_canonical(&mut decoder),
        Err(ContractError::InvertedTimeInterval)
    );

    Ok(())
}

#[test]
fn test_source_evidence_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("camera.sensor.dock_bay");
    let source_digest = ContentDigest::sha256(b"dock-bay-payload-bytes");
    let continuity_digest = ContentDigest::sha256(b"dock-bay-continuity");
    let capsule = make_test_sensor_capsule(source_digest, 4096)?;

    let record = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:packet:dock_bay:0128".to_string(),
        anchor,
        generation: Generation(3),
        statement: "Dock bay source packets with continuity witness".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::SensorCapsule,
        custody: SourceCustody::Retained {
            source_digest,
            source_bytes: 4096,
            storage_handle: "cas/dock-bay/packets".to_string(),
        },
        omission: None,
        capsule: Some(capsule),
        continuity_witness: Some(continuity_digest),
    })?;

    let bytes = record.to_canonical_bytes()?;
    let decoded = SourceEvidenceRecord::from_canonical_bytes(&bytes)?;

    assert_eq!(decoded, record);
    assert_eq!(decoded.evidence_id(), record.evidence_id());
    assert_eq!(decoded.anchor(), record.anchor());
    assert_eq!(decoded.generation(), record.generation());
    assert_eq!(decoded.statement(), record.statement());
    assert_eq!(decoded.provenance(), record.provenance());
    assert_eq!(decoded.classification(), record.classification());
    assert_eq!(decoded.custody(), record.custody());
    assert_eq!(decoded.omission(), record.omission());
    assert_eq!(decoded.capsule(), record.capsule());
    assert_eq!(decoded.continuity_witness(), record.continuity_witness());

    // Roundtrip for NotRetained record
    let not_retained_record = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:omitted:dock_bay:0129".to_string(),
        anchor: LedgerAnchor::genesis("camera.sensor.dock_bay"),
        generation: Generation(3),
        statement: "Omitted dock bay frame".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::SourcePayloadFile,
        custody: SourceCustody::NotRetained,
        omission: Some(OmissionReason::TransientPreviewOnly),
        capsule: None,
        continuity_witness: None,
    })?;

    let bytes = not_retained_record.to_canonical_bytes()?;
    let decoded_not_retained = SourceEvidenceRecord::from_canonical_bytes(&bytes)?;
    assert_eq!(decoded_not_retained, not_retained_record);

    Ok(())
}

fn valid_runtime_authority_params() -> Result<RuntimeAuthorityParams, Box<dyn Error>> {
    let operation_id = OperationId::parse("op:runtime:test:001")?;
    let cx = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:runtime:test:001".to_string(),
        operation_id: operation_id.clone(),
        principal: "principal:operator:001".to_string(),
        capabilities: vec![
            "CAP-AGENT-CANCEL-001".to_string(),
            "CAP-LEDGER-APPEND-001".to_string(),
            "CAP-OBJECT-PUBLISH-001".to_string(),
            "CAP-OBJECT-STAGE-001".to_string(),
            "PROHIBITED-INFER-MISSION-MEANING".to_string(),
            "PROHIBITED-INFER-PHYSICAL-TRUTH".to_string(),
        ],
        deadline: Some(TimestampNs(1_700_000_000_000_000_000)),
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:scope:internal".to_string(),
        retention_scope: "retention:scope:standard".to_string(),
        anchor_universe: ContentDigest::sha256(b"test-anchor-universe"),
        generation: 1,
    })?;

    let source_digest = ContentDigest::sha256(b"test-source-bytes");
    let custody = SourceCustody::Retained {
        source_digest,
        source_bytes: 1024,
        storage_handle: "storage/handle/raw/001".to_string(),
    };

    let obligation = Obligation {
        obligation_id: ObligationId::parse("ob:test:001")?,
        operation_id: operation_id.clone(),
        terminal_predicate: "predicate:effect:committed".to_string(),
        state: ObligationState::Verified,
        proof_digest: Some(ContentDigest::sha256(b"proof-digest-001")),
    };

    Ok(RuntimeAuthorityParams {
        record_id: "auth:record:test:001".to_string(),
        generation: Generation(1),
        context: cx,
        grants: vec![
            RuntimeGrant::LedgerAppend,
            RuntimeGrant::ObjectPublish,
            RuntimeGrant::ObjectStage,
        ],
        region_id: RegionId::new("region:property:001")?,
        region_kind: RegionKind::Property,
        parent_region_id: Some(RegionId::new("region:process:root")?),
        region_state: RegionState::Active,
        quiescence_proof: None,
        custody,
        obligations: vec![obligation],
        object_roots: vec![source_digest],
        receipt_roots: vec![ContentDigest::sha256(b"receipt-root-001")],
        contract_basis: None,
    })
}

#[test]
fn test_runtime_authority_and_custody_row_properties() -> Result<(), Box<dyn Error>> {
    let layer = AgentAbstractionLayer::RuntimeAuthorityAndCustody;

    assert_eq!(layer.id(), "AGT-LAYER-001");
    assert_eq!(layer.name(), "runtime_authority_and_custody");
    assert_eq!(layer.tower_level(), 0);
    assert_eq!(layer.plane(), Plane::Authority);
    assert!(layer.may_claim_authority());
    assert!(!layer.may_authorize_effects());
    assert!(!layer.is_anchor_pinned());
    assert!(!layer.is_rebuildable());
    assert!(!layer.is_anchor_pinned_rebuildable());
    assert!(layer.is_runtime_authority_and_custody());
    assert_eq!(layer.status(), "normative");
    assert_eq!(layer.invariant(), "INV-006");
    assert_eq!(layer.owner(), "asupersync/authority/object owners");
    assert_eq!(
        layer.agent_question(),
        "What work, authority, budget, identity, time, and object custody exist?"
    );
    assert_eq!(
        layer.output(),
        "Context, grants, regions, obligations, object roots, and receipts."
    );
    assert_eq!(
        layer.prohibition(),
        "Cannot infer mission meaning or physical truth."
    );

    assert_eq!(
        RUNTIME_AUTHORITY_DOMAIN,
        "fss.runtime_authority_and_custody.v1"
    );
    Ok(())
}

#[test]
fn test_runtime_authority_and_custody_parse_and_resolution() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        AgentAbstractionLayer::from_id("AGT-LAYER-001")?,
        AgentAbstractionLayer::RuntimeAuthorityAndCustody
    );
    assert_eq!(
        AgentAbstractionLayer::from_name("runtime_authority_and_custody")?,
        AgentAbstractionLayer::RuntimeAuthorityAndCustody
    );
    assert_eq!(
        AgentAbstractionLayer::from_tower_level(0)?,
        AgentAbstractionLayer::RuntimeAuthorityAndCustody
    );
    assert_eq!(
        AgentAbstractionLayer::from_str("AGT-LAYER-001")?,
        AgentAbstractionLayer::RuntimeAuthorityAndCustody
    );
    assert_eq!(
        AgentAbstractionLayer::from_str("runtime_authority_and_custody")?,
        AgentAbstractionLayer::RuntimeAuthorityAndCustody
    );

    assert_eq!(
        RuntimeGrant::from_id("CAP-LEDGER-APPEND-001")?,
        RuntimeGrant::LedgerAppend
    );
    assert_eq!(
        RuntimeGrant::from_str("CAP-OBJECT-PUBLISH-001")?,
        RuntimeGrant::ObjectPublish
    );
    assert_eq!(
        RuntimeGrant::from_id("PROHIBITED-INFER-MISSION-MEANING")?,
        RuntimeGrant::InferMissionMeaning
    );
    assert_eq!(
        RuntimeGrant::from_id("PROHIBITED-INFER-PHYSICAL-TRUTH")?,
        RuntimeGrant::InferPhysicalTruth
    );

    Ok(())
}

#[test]
fn test_outcome_and_workspace_layers_belong_to_cognition_plane() -> Result<(), Box<dyn Error>> {
    let outcome = AgentAbstractionLayer::OutcomeAndEpisode;
    assert_eq!(outcome.plane(), Plane::Cognition);
    assert!(!outcome.may_claim_authority());
    assert!(!outcome.may_authorize_effects());

    let workspace = AgentAbstractionLayer::WorkspaceAndHandoff;
    assert_eq!(workspace.plane(), Plane::Cognition);
    assert!(!workspace.may_claim_authority());
    assert!(!workspace.may_authorize_effects());

    // Verify all 11 layer planes conform to the architecture specification
    assert_eq!(
        AgentAbstractionLayer::RuntimeAuthorityAndCustody.plane(),
        Plane::Authority
    );
    assert_eq!(
        AgentAbstractionLayer::SourceEvidence.plane(),
        Plane::Authority
    );
    assert_eq!(
        AgentAbstractionLayer::WorldFactsAndCoverage.plane(),
        Plane::Authority
    );
    assert_eq!(
        AgentAbstractionLayer::DerivedBeliefs.plane(),
        Plane::Cognition
    );
    assert_eq!(
        AgentAbstractionLayer::SituationCapsule.plane(),
        Plane::Cognition
    );
    assert_eq!(
        AgentAbstractionLayer::InvestigationAndHypotheses.plane(),
        Plane::Cognition
    );
    assert_eq!(
        AgentAbstractionLayer::AffordanceFrontier.plane(),
        Plane::Cognition
    );
    assert_eq!(AgentAbstractionLayer::PlanAndEffect.plane(), Plane::Effect);
    assert_eq!(
        AgentAbstractionLayer::OutcomeAndEpisode.plane(),
        Plane::Cognition
    );
    assert_eq!(
        AgentAbstractionLayer::LearningAndMemory.plane(),
        Plane::Cognition
    );
    assert_eq!(
        AgentAbstractionLayer::WorkspaceAndHandoff.plane(),
        Plane::Cognition
    );

    // Authority permissions
    assert!(AgentAbstractionLayer::RuntimeAuthorityAndCustody.may_claim_authority());
    assert!(AgentAbstractionLayer::SourceEvidence.may_claim_authority());
    assert!(AgentAbstractionLayer::WorldFactsAndCoverage.may_claim_authority());
    assert!(!AgentAbstractionLayer::DerivedBeliefs.may_claim_authority());
    assert!(!AgentAbstractionLayer::SituationCapsule.may_claim_authority());
    assert!(!AgentAbstractionLayer::InvestigationAndHypotheses.may_claim_authority());
    assert!(!AgentAbstractionLayer::AffordanceFrontier.may_claim_authority());
    assert!(!AgentAbstractionLayer::PlanAndEffect.may_claim_authority());
    assert!(!AgentAbstractionLayer::OutcomeAndEpisode.may_claim_authority());
    assert!(!AgentAbstractionLayer::LearningAndMemory.may_claim_authority());
    assert!(!AgentAbstractionLayer::WorkspaceAndHandoff.may_claim_authority());

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum MiniJson {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<MiniJson>),
    Obj(Vec<(String, MiniJson)>),
}

struct MiniJsonParser<'a> {
    src: &'a [u8],
    pos: usize,
}

impl MiniJsonParser<'_> {
    fn ws(&mut self) {
        while matches!(self.src.get(self.pos), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.pos += 1;
        }
    }

    fn eat(&mut self, byte: u8) -> Option<()> {
        self.ws();
        if self.src.get(self.pos) == Some(&byte) {
            self.pos += 1;
            Some(())
        } else {
            None
        }
    }

    fn lit(&mut self, word: &[u8]) -> Option<()> {
        if self.src.get(self.pos..)?.starts_with(word) {
            self.pos += word.len();
            Some(())
        } else {
            None
        }
    }

    fn value(&mut self) -> Option<MiniJson> {
        self.ws();
        match *self.src.get(self.pos)? {
            b'{' => {
                self.pos += 1;
                let mut fields = Vec::new();
                if self.eat(b'}').is_some() {
                    return Some(MiniJson::Obj(fields));
                }
                loop {
                    self.ws();
                    let key = self.string()?;
                    self.eat(b':')?;
                    fields.push((key, self.value()?));
                    if self.eat(b',').is_none() {
                        self.eat(b'}')?;
                        return Some(MiniJson::Obj(fields));
                    }
                }
            }
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                if self.eat(b']').is_some() {
                    return Some(MiniJson::Arr(items));
                }
                loop {
                    items.push(self.value()?);
                    if self.eat(b',').is_none() {
                        self.eat(b']')?;
                        return Some(MiniJson::Arr(items));
                    }
                }
            }
            b'"' => self.string().map(MiniJson::Str),
            b't' => self.lit(b"true").map(|()| MiniJson::Bool(true)),
            b'f' => self.lit(b"false").map(|()| MiniJson::Bool(false)),
            b'n' => self.lit(b"null").map(|()| MiniJson::Null),
            _ => {
                let start = self.pos;
                while matches!(
                    self.src.get(self.pos),
                    Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                ) {
                    self.pos += 1;
                }
                if start == self.pos {
                    return None;
                }
                String::from_utf8(self.src.get(start..self.pos)?.to_vec())
                    .ok()
                    .map(MiniJson::Num)
            }
        }
    }

    fn string(&mut self) -> Option<String> {
        if self.src.get(self.pos) != Some(&b'"') {
            return None;
        }
        self.pos += 1;
        let mut out = Vec::new();
        loop {
            let byte = *self.src.get(self.pos)?;
            self.pos += 1;
            match byte {
                b'"' => return String::from_utf8(out).ok(),
                b'\\' => {
                    let esc = *self.src.get(self.pos)?;
                    self.pos += 1;
                    match esc {
                        b'"' | b'\\' | b'/' => out.push(esc),
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'u' => {
                            let hex =
                                std::str::from_utf8(self.src.get(self.pos..self.pos + 4)?).ok()?;
                            self.pos += 4;
                            let ch = char::from_u32(u32::from_str_radix(hex, 16).ok()?)?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return None,
                    }
                }
                other => out.push(other),
            }
        }
    }
}

impl MiniJson {
    fn parse(text: &str) -> Option<Self> {
        let mut parser = MiniJsonParser {
            src: text.as_bytes(),
            pos: 0,
        };
        let value = parser.value()?;
        parser.ws();
        (parser.pos == parser.src.len()).then_some(value)
    }

    fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    fn write_canonical(&self, out: &mut String) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(true) => out.push_str("true"),
            Self::Bool(false) => out.push_str("false"),
            Self::Num(n) => out.push_str(n),
            Self::Str(s) => {
                out.push('"');
                for c in s.chars() {
                    match c {
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        '\t' => out.push_str("\\t"),
                        _ => out.push(c),
                    }
                }
                out.push('"');
            }
            Self::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_canonical(out);
                }
                out.push(']');
            }
            Self::Obj(fields) => {
                out.push('{');
                let mut sorted = fields.clone();
                sorted.sort_by(|a, b| a.0.cmp(&b.0));
                for (i, (k, v)) in sorted.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push('"');
                    for c in k.chars() {
                        match c {
                            '"' => out.push_str("\\\""),
                            '\\' => out.push_str("\\\\"),
                            _ => out.push(c),
                        }
                    }
                    out.push('"');
                    out.push(':');
                    v.write_canonical(out);
                }
                out.push('}');
            }
        }
    }
}

#[test]
fn test_all_rust_layer_strings_match_machine_registry_json() -> Result<(), Box<dyn Error>> {
    let stack_json = include_str!("../../../architecture/agent_abstraction_stack.json");
    let root = MiniJson::parse(stack_json).ok_or("failed to parse agent_abstraction_stack.json")?;
    let layers_arr = root.get("layers").ok_or("missing layers array")?;
    let MiniJson::Arr(layers) = layers_arr else {
        return Err("layers is not an array".into());
    };
    assert_eq!(layers.len(), 11, "expected 11 layers in machine registry");

    for (layer, json_layer) in AgentAbstractionLayer::ALL.iter().zip(layers.iter()) {
        let id = json_layer
            .get("id")
            .and_then(MiniJson::as_str)
            .ok_or("missing id")?;
        let name = json_layer
            .get("name")
            .and_then(MiniJson::as_str)
            .ok_or("missing name")?;
        let owner = json_layer
            .get("owner")
            .and_then(MiniJson::as_str)
            .ok_or("missing owner")?;
        let question = json_layer
            .get("question")
            .and_then(MiniJson::as_str)
            .ok_or("missing question")?;
        let output = json_layer
            .get("output")
            .and_then(MiniJson::as_str)
            .ok_or("missing output")?;
        let prohibition = json_layer
            .get("prohibition")
            .and_then(MiniJson::as_str)
            .ok_or("missing prohibition")?;
        let invariant = json_layer
            .get("invariant")
            .and_then(MiniJson::as_str)
            .ok_or("missing invariant")?;
        let status = json_layer
            .get("status")
            .and_then(MiniJson::as_str)
            .ok_or("missing status")?;

        assert_eq!(layer.id(), id, "ID mismatch for {}", layer.id());
        assert_eq!(layer.name(), name, "name mismatch for {}", layer.id());
        assert_eq!(layer.owner(), owner, "owner mismatch for {}", layer.id());
        assert_eq!(
            layer.agent_question(),
            question,
            "question mismatch for {}",
            layer.id()
        );
        assert_eq!(layer.output(), output, "output mismatch for {}", layer.id());
        assert_eq!(
            layer.prohibition(),
            prohibition,
            "prohibition mismatch for {}",
            layer.id()
        );
        assert_eq!(
            layer.invariant(),
            invariant,
            "invariant mismatch for {}",
            layer.id()
        );
        assert_eq!(layer.status(), status, "status mismatch for {}", layer.id());
    }

    Ok(())
}

#[test]
fn test_runtime_authority_record_valid_construction() -> Result<(), Box<dyn Error>> {
    let params = valid_runtime_authority_params()?;
    let record = RuntimeAuthorityAndCustodyRecord::new(params)?;

    assert_eq!(
        record.layer(),
        AgentAbstractionLayer::RuntimeAuthorityAndCustody
    );
    assert_eq!(record.plane(), Plane::Authority);
    assert_eq!(record.invariant(), "INV-006");
    assert!(record.may_claim_authority());
    assert!(!record.may_authorize_effects());
    assert!(!record.is_anchor_pinned());
    assert!(!record.is_rebuildable());
    assert!(record.prohibits_mission_meaning_inference());
    assert!(record.prohibits_physical_truth_inference());
    assert!(record.has_grant(RuntimeGrant::LedgerAppend));
    assert!(record.has_grant(RuntimeGrant::ObjectPublish));
    assert!(record.has_grant(RuntimeGrant::ObjectStage));
    assert!(!record.has_grant(RuntimeGrant::ModelInfer));
    assert!(record.is_retained_custody());
    assert!(!record.is_quiescent());

    record.validate()?;
    record.validate_invariants()?;
    let _: RuntimeAuthorityAndCustody = record.clone();
    let _: RuntimeAuthorityRecord = record.clone();

    let layer = AgentAbstractionLayer::RuntimeAuthorityAndCustody;
    layer.validate_runtime_authority(&record)?;

    assert_eq!(
        AgentAbstractionLayer::SourceEvidence.validate_runtime_authority(&record),
        Err(ContractError::UnknownAbstractionLayer(
            "source_evidence".to_string()
        ))
    );

    let digest = record.canonical_digest();
    assert_ne!(digest.bytes(), [0u8; 32]);

    Ok(())
}

#[test]
fn test_runtime_authority_and_custody_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let params = valid_runtime_authority_params()?;
    let record = RuntimeAuthorityAndCustodyRecord::new(params)?;

    let mut encoder = CanonicalEncoder::new();
    record.encode_canonical(&mut encoder);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let decoded = RuntimeAuthorityAndCustodyRecord::decode_canonical(&mut decoder)?;

    assert_eq!(decoded, record);
    assert_eq!(decoded.record_id, record.record_id);
    assert_eq!(decoded.generation, record.generation);
    assert_eq!(decoded.context, record.context);
    assert_eq!(decoded.grants, record.grants);
    assert_eq!(decoded.region_id, record.region_id);
    assert_eq!(decoded.region_kind, record.region_kind);
    assert_eq!(decoded.parent_region_id, record.parent_region_id);
    assert_eq!(decoded.region_state, record.region_state);
    assert_eq!(decoded.quiescence_proof, record.quiescence_proof);
    assert_eq!(decoded.custody, record.custody);
    assert_eq!(decoded.obligations, record.obligations);
    assert_eq!(decoded.object_roots, record.object_roots);
    assert_eq!(decoded.receipt_roots, record.receipt_roots);
    assert_eq!(decoded.canonical_digest(), record.canonical_digest());

    Ok(())
}

#[test]
fn test_planted_negative_runtime_authority_and_custody_bypasses() -> Result<(), Box<dyn Error>> {
    // Planted bypass 1: Prohibited mission meaning inference
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.grants.push(RuntimeGrant::InferMissionMeaning);
    let bad_record = RuntimeAuthorityAndCustodyRecord {
        record_id: bad_params.record_id.clone(),
        generation: bad_params.generation,
        context: bad_params.context.clone(),
        grants: bad_params.grants.clone(),
        region_id: bad_params.region_id.clone(),
        region_kind: bad_params.region_kind,
        parent_region_id: bad_params.parent_region_id.clone(),
        region_state: bad_params.region_state,
        quiescence_proof: bad_params.quiescence_proof.clone(),
        custody: bad_params.custody.clone(),
        obligations: bad_params.obligations.clone(),
        object_roots: bad_params.object_roots.clone(),
        receipt_roots: bad_params.receipt_roots.clone(),
        contract_basis: bad_params.contract_basis.clone(),
    };
    assert!(!bad_record.prohibits_mission_meaning_inference());
    assert_eq!(
        bad_record.validate(),
        Err(ContractError::ProhibitedMissionMeaningInference)
    );
    assert_eq!(
        bad_record.validate_invariants(),
        Err(ContractError::ProhibitedMissionMeaningInference)
    );
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::ProhibitedMissionMeaningInference)
    );

    // Planted bypass 2: Prohibited physical truth inference
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.grants.push(RuntimeGrant::InferPhysicalTruth);
    let bad_record = RuntimeAuthorityAndCustodyRecord {
        record_id: bad_params.record_id.clone(),
        generation: bad_params.generation,
        context: bad_params.context.clone(),
        grants: bad_params.grants.clone(),
        region_id: bad_params.region_id.clone(),
        region_kind: bad_params.region_kind,
        parent_region_id: bad_params.parent_region_id.clone(),
        region_state: bad_params.region_state,
        quiescence_proof: bad_params.quiescence_proof.clone(),
        custody: bad_params.custody.clone(),
        obligations: bad_params.obligations.clone(),
        object_roots: bad_params.object_roots.clone(),
        receipt_roots: bad_params.receipt_roots.clone(),
        contract_basis: bad_params.contract_basis.clone(),
    };
    assert!(!bad_record.prohibits_physical_truth_inference());
    assert_eq!(
        bad_record.validate(),
        Err(ContractError::ProhibitedPhysicalTruthInference)
    );
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::ProhibitedPhysicalTruthInference)
    );

    // Planted bypass 3: Unbound grant (not present in Cx context capabilities)
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.grants.push(RuntimeGrant::ModelInfer);
    bad_params.grants.sort();
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::UnboundCapabilityGrant(
            "CAP-MODEL-INFER-001".to_string()
        ))
    );

    // Planted bypass 4: Duplicate capability grant in record
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.grants.push(RuntimeGrant::LedgerAppend);
    bad_params.grants.sort();
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::DuplicateGrant(
            "CAP-LEDGER-APPEND-001".to_string()
        ))
    );

    // Planted bypass 5: Duplicate obligation ID in record
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params
        .obligations
        .push(bad_params.obligations[0].clone());
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::DuplicateObligation(
            "ob:test:001".to_string()
        ))
    );

    // Planted bypass 6: Region can be its own parent (cyclic hierarchy)
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.parent_region_id = Some(bad_params.region_id.clone());
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::SelfParentedRegion(
            "region:property:001".to_string()
        ))
    );

    // Planted bypass 7: Orphan non-root region (missing parent)
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.parent_region_id = None;
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::OrphanRegion(
            "region:property:001".to_string()
        ))
    );

    // Planted bypass 8: Root ProcessRegion with parent
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.region_kind = RegionKind::Process;
    bad_params.parent_region_id = Some(RegionId::new("region:external")?);
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::RootRegionWithParent(
            "region:property:001".to_string()
        ))
    );

    // Planted bypass 9: DrainRequested without cancellation reason
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.region_state = RegionState::DrainRequested;
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::MissingCancellationReason)
    );

    // Planted bypass 10: Finalizing without cancellation reason
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.region_state = RegionState::Finalizing;
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::MissingCancellationReason)
    );

    // Planted bypass 11: Closed region with no drain record (missing quiescence proof)
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.region_state = RegionState::Closed;
    bad_params.quiescence_proof = None;
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::MissingDrainRecord)
    );

    // Planted bypass 12: Closed region retains Pending obligation
    let mut bad_params = valid_runtime_authority_params()?;
    let proof = QuiescenceProof {
        region_id: bad_params.region_id.clone(),
        region_kind: bad_params.region_kind,
        parent_id: bad_params.parent_region_id.clone(),
        closed_at: TimestampNs(1_700_000_000_100_000_000),
        total_tasks: 5,
        total_obligations: 1,
        indeterminate_obligations: 0,
        proof_digest: QuiescenceProof::compute_digest(
            &bad_params.region_id,
            bad_params.region_kind,
            bad_params.parent_region_id.as_ref(),
            TimestampNs(1_700_000_000_100_000_000),
            5,
            1,
            0,
        ),
    };
    bad_params.region_state = RegionState::Closed;
    bad_params.quiescence_proof = Some(proof.clone());
    bad_params.obligations[0].state = ObligationState::Pending;
    bad_params.obligations[0].proof_digest = None;
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::UnresolvedObligationOnClosure(
            "ob:test:001".to_string()
        ))
    );

    // Planted bypass 13: Closed region retains Indeterminate obligation
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.region_state = RegionState::Closed;
    bad_params.quiescence_proof = Some(proof.clone());
    bad_params.obligations[0].state = ObligationState::Indeterminate;
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::IndeterminateObligationOnClosure(
            "ob:test:001".to_string()
        ))
    );

    // Planted bypass 14: Object root unrelated to custody digest
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.object_roots = vec![ContentDigest::sha256(b"unrelated-object-digest")];
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::CustodyRootMismatch)
    );

    // Planted bypass 15: NotRetained custody with non-empty object roots
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.custody = SourceCustody::NotRetained;
    bad_params.object_roots = vec![ContentDigest::sha256(b"unexpected-root")];
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::EvidenceRequired)
    );

    // Planted bypass 16: Generation 0 rejected
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.generation = Generation(0);
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::GenerationConflict)
    );

    // Planted bypass 17: Generation mismatch with context
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.generation = Generation(2);
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::GenerationConflict)
    );

    // Planted bypass 18: Retained custody zero source bytes
    let mut bad_params = valid_runtime_authority_params()?;
    let source_digest = ContentDigest::sha256(b"zero-bytes-custody");
    bad_params.custody = SourceCustody::Retained {
        source_digest,
        source_bytes: 0,
        storage_handle: "storage/handle/raw/001".to_string(),
    };
    bad_params.object_roots = vec![source_digest];
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::EvidenceRequired)
    );

    // Planted bypass 19: Premature quiescence proof on Active region
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.region_state = RegionState::Active;
    bad_params.quiescence_proof = Some(proof.clone());
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::PrematureQuiescenceProof)
    );

    // Planted bypass 20: Unregistered capability grant string
    assert_eq!(
        RuntimeGrant::from_id("cap:rogue-unregistered"),
        Err(ContractError::UnregisteredCapabilityGrant(
            "cap:rogue-unregistered".to_string()
        ))
    );

    // Planted bypass 21: Unknown, malformed, or out-of-range tower level must fail closed.
    let Err(err_level) = AgentAbstractionLayer::from_tower_level(99) else {
        return Err("expected out-of-bounds tower level to fail".into());
    };
    assert_eq!(err_level, ContractError::UnknownEntryTag(99));

    // Planted bypass 22: Malformed or mutated ID must fail closed.
    let Err(err_id) = AgentAbstractionLayer::from_id("AGT-LAYER-000") else {
        return Err("expected unknown ID to fail".into());
    };
    assert_eq!(
        err_id,
        ContractError::UnknownAbstractionLayer("AGT-LAYER-000".into())
    );

    // Planted bypass 23: Case-sensitive name mismatch must fail closed.
    let Err(err_name) = AgentAbstractionLayer::from_name("Runtime_Authority_And_Custody") else {
        return Err("expected uppercase name to fail".into());
    };
    assert_eq!(
        err_name,
        ContractError::UnknownAbstractionLayer("Runtime_Authority_And_Custody".into())
    );

    // Planted bypass 24 (Q8): ContextAuthority decode with cap_count=u64::MAX fails gracefully without panic
    let mut enc = CanonicalEncoder::new();
    enc.text("trace:dos:001");
    OperationId::parse("op:dos:001")?.encode_canonical(&mut enc);
    enc.text("principal:operator:001");
    enc.u64(u64::MAX); // hostile cap_count
    let bytes = enc.finish();
    let mut dec = CanonicalDecoder::new(&bytes);
    assert_eq!(
        ContextAuthority::decode_canonical(&mut dec),
        Err(ContractError::CountBoundExceeded)
    );

    // Planted bypass 25 (Q9): RuntimeAuthorityAndCustodyRecord decode with grant_count=u64::MAX fails gracefully without panic
    let mut enc = CanonicalEncoder::new();
    enc.text(RUNTIME_AUTHORITY_DOMAIN);
    enc.text("auth:record:dos:001");
    Generation(1).encode_canonical(&mut enc);
    valid_runtime_authority_params()?
        .context
        .encode_canonical(&mut enc);
    enc.u64(u64::MAX); // hostile grant_count
    let bytes = enc.finish();
    let mut dec = CanonicalDecoder::new(&bytes);
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::decode_canonical(&mut dec),
        Err(ContractError::CountBoundExceeded)
    );

    // Planted bypass 26 (Q1): Record with grants reversed or non-canonical ordering rejected
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.grants = vec![RuntimeGrant::ObjectStage, RuntimeGrant::ObjectPublish];
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::NonCanonicalOrdering)
    );

    // Planted bypass 27 (Q10): ContextAuthority with unsorted capabilities rejected on decode
    let mut enc = CanonicalEncoder::new();
    enc.text("trace:unsorted:001");
    OperationId::parse("op:unsorted:001")?.encode_canonical(&mut enc);
    enc.text("principal:operator:001");
    enc.u64(2);
    enc.text("CAP-OBJECT-STAGE-001");
    enc.text("CAP-OBJECT-PUBLISH-001");
    enc.bool(false); // deadline None
    enc.u8(10); // priority
    enc.bool(false); // cancellation None
    BudgetVector::default().encode_canonical(&mut enc);
    enc.text("privacy:scope:internal");
    enc.text("retention:scope:standard");
    enc.digest(ContentDigest::sha256(b"test-anchor-universe"));
    enc.u64(1); // generation
    enc.bool(false); // lease fence None
    enc.bool(false); // idempotency None
    enc.bool(false); // lab controls None
    let bytes = enc.finish();
    let mut dec = CanonicalDecoder::new(&bytes);
    assert_eq!(
        ContextAuthority::decode_canonical(&mut dec),
        Err(ContractError::NonCanonicalOrdering)
    );

    // Planted bypass 28 (Q4a): QuiescenceProof wrong region kind
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.region_state = RegionState::Closed;
    let mut bad_proof = proof.clone();
    bad_proof.region_kind = RegionKind::Process;
    bad_params.quiescence_proof = Some(bad_proof);
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::ProofRegionMismatch(
            RegionKind::Process.as_str().to_string()
        ))
    );

    // Planted bypass 29 (Q4b): QuiescenceProof wrong parent
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.region_state = RegionState::Closed;
    let mut bad_proof = proof.clone();
    bad_proof.parent_id = Some(RegionId::new("region:wrong:parent")?);
    bad_params.quiescence_proof = Some(bad_proof);
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::ProofRegionMismatch(
            "region:wrong:parent".to_string()
        ))
    );

    // Planted bypass 30 (Q4c): QuiescenceProof indeterminate_obligations > 0
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.region_state = RegionState::Closed;
    let mut bad_proof = proof.clone();
    bad_proof.indeterminate_obligations = 7;
    bad_params.quiescence_proof = Some(bad_proof);
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::IndeterminateObligationOnClosure(
            "quiescence_proof.indeterminate_obligations=7".to_string()
        ))
    );

    // Planted bypass 31 (Q4d): QuiescenceProof tampered / uncomputed digest
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.region_state = RegionState::Closed;
    let mut bad_proof = proof.clone();
    bad_proof.proof_digest = ContentDigest::sha256(b"tampered-digest");
    bad_params.quiescence_proof = Some(bad_proof);
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::DigestMismatch)
    );

    // Planted bypass (K6a): QuiescenceProof wrong region_id
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.region_state = RegionState::Closed;
    let mut bad_proof = proof.clone();
    bad_proof.region_id = RegionId::new("region:different:id")?;
    bad_proof.proof_digest = QuiescenceProof::compute_digest(
        &bad_proof.region_id,
        bad_proof.region_kind,
        bad_proof.parent_id.as_ref(),
        bad_proof.closed_at,
        bad_proof.total_tasks,
        bad_proof.total_obligations,
        bad_proof.indeterminate_obligations,
    );
    bad_params.quiescence_proof = Some(bad_proof);
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::ProofRegionMismatch(
            "region:different:id".to_string()
        ))
    );

    // Planted bypass (K6b): QuiescenceProof total_obligations < record.obligations.len()
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.region_state = RegionState::Closed;
    let mut bad_proof = proof.clone();
    bad_proof.total_obligations = 0; // record has 1 obligation!
    bad_proof.proof_digest = QuiescenceProof::compute_digest(
        &bad_proof.region_id,
        bad_proof.region_kind,
        bad_proof.parent_id.as_ref(),
        bad_proof.closed_at,
        bad_proof.total_tasks,
        bad_proof.total_obligations,
        bad_proof.indeterminate_obligations,
    );
    bad_params.quiescence_proof = Some(bad_proof);
    assert!(matches!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::ProofRegionMismatch(_))
    ));

    // Planted bypass (K6c): QuiescenceProof total_tasks == 0 when record has obligations
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.region_state = RegionState::Closed;
    let mut bad_proof = proof.clone();
    bad_proof.total_tasks = 0;
    bad_proof.proof_digest = QuiescenceProof::compute_digest(
        &bad_proof.region_id,
        bad_proof.region_kind,
        bad_proof.parent_id.as_ref(),
        bad_proof.closed_at,
        bad_proof.total_tasks,
        bad_proof.total_obligations,
        bad_proof.indeterminate_obligations,
    );
    bad_params.quiescence_proof = Some(bad_proof);
    assert!(matches!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::ProofRegionMismatch(_))
    ));

    // Planted bypass (K6d): QuiescenceProof total_obligations == 100 when record has empty obligations
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.region_state = RegionState::Closed;
    bad_params.obligations.clear();
    let mut bad_proof = proof.clone();
    bad_proof.total_obligations = 100;
    bad_proof.proof_digest = QuiescenceProof::compute_digest(
        &bad_proof.region_id,
        bad_proof.region_kind,
        bad_proof.parent_id.as_ref(),
        bad_proof.closed_at,
        bad_proof.total_tasks,
        bad_proof.total_obligations,
        bad_proof.indeterminate_obligations,
    );
    bad_params.quiescence_proof = Some(bad_proof);
    assert!(matches!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::ProofRegionMismatch(_))
    ));

    // Planted bypass: QuiescenceProof total_obligations == 99 against a record with 1 resolved obligation
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.region_state = RegionState::Closed;
    bad_params.obligations = vec![Obligation {
        obligation_id: ObligationId::parse("obligation:test:closure:1")?,
        operation_id: OperationId::parse("op:test:closure:1")?,
        terminal_predicate: "terminal_predicate_met".to_string(),
        state: ObligationState::Verified,
        proof_digest: Some(ContentDigest::sha256(b"obligation_proof")),
    }];
    let mut bad_proof = proof.clone();
    bad_proof.total_tasks = 1;
    bad_proof.total_obligations = 99;
    bad_proof.proof_digest = QuiescenceProof::compute_digest(
        &bad_proof.region_id,
        bad_proof.region_kind,
        bad_proof.parent_id.as_ref(),
        bad_proof.closed_at,
        bad_proof.total_tasks,
        bad_proof.total_obligations,
        bad_proof.indeterminate_obligations,
    );
    bad_params.quiescence_proof = Some(bad_proof);
    assert!(matches!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::ProofRegionMismatch(_))
    ));

    // Planted bypass 32 (Q2): Retained custody with extra unrelated object root
    let mut bad_params = valid_runtime_authority_params()?;
    let source_digest = ContentDigest::sha256(b"test-source-bytes");
    bad_params.object_roots = vec![
        source_digest,
        ContentDigest::sha256(b"extra-unrelated-root"),
    ];
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::CustodyRootMismatch)
    );

    // Planted bypass 33 (Q3a): Retained custody with duplicate object roots
    let mut bad_params = valid_runtime_authority_params()?;
    bad_params.object_roots = vec![source_digest, source_digest];
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::CustodyRootMismatch)
    );

    // Planted bypass 34 (Q3b): Duplicate receipt roots rejected
    let mut bad_params = valid_runtime_authority_params()?;
    let receipt = ContentDigest::sha256(b"receipt-root-001");
    bad_params.receipt_roots = vec![receipt, receipt];
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::NonCanonicalOrdering)
    );

    // Planted bypass 35 (K10): Decode skips validate test
    // Generation mismatch: record generation (2) != context generation (1).
    // Decoder fields decode cleanly; ONLY record.validate() catches and rejects it.
    let mut enc = CanonicalEncoder::new();
    enc.text(RUNTIME_AUTHORITY_DOMAIN);
    enc.text("auth:record:invalid:k10");
    Generation(2).encode_canonical(&mut enc); // Generation 2!
    valid_runtime_authority_params()?
        .context
        .encode_canonical(&mut enc); // context has Generation 1!
    enc.u64(0); // grants count
    RegionId::new("region:property:001")?.encode_canonical(&mut enc);
    RegionKind::Property.encode_canonical(&mut enc);
    enc.bool(true);
    RegionId::new("region:process:root")?.encode_canonical(&mut enc);
    RegionState::Active.encode_canonical(&mut enc);
    enc.bool(false); // quiescence proof None
    SourceCustody::NotRetained.encode_canonical(&mut enc);
    enc.u64(0); // obligations count
    enc.u64(0); // object roots count
    enc.u64(0); // receipt roots count
    enc.bool(false); // contract basis None
    let bytes = enc.finish();
    let mut dec = CanonicalDecoder::new(&bytes);
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::decode_canonical(&mut dec),
        Err(ContractError::GenerationConflict)
    );

    // Additional K10 check: Closed region without QuiescenceProof decoded cleanly
    // and caught ONLY by record.validate()
    let mut enc = CanonicalEncoder::new();
    enc.text(RUNTIME_AUTHORITY_DOMAIN);
    enc.text("auth:record:invalid:k10b");
    Generation(1).encode_canonical(&mut enc);
    valid_runtime_authority_params()?
        .context
        .encode_canonical(&mut enc);
    enc.u64(0); // grants count
    RegionId::new("region:property:001")?.encode_canonical(&mut enc);
    RegionKind::Property.encode_canonical(&mut enc);
    enc.bool(true);
    RegionId::new("region:process:root")?.encode_canonical(&mut enc);
    RegionState::Closed.encode_canonical(&mut enc); // Closed!
    enc.bool(false); // quiescence proof None!
    SourceCustody::NotRetained.encode_canonical(&mut enc);
    enc.u64(0); // obligations count
    enc.u64(0); // object roots count
    enc.u64(0); // receipt roots count
    enc.bool(false); // contract basis None
    let bytes = enc.finish();
    let mut dec = CanonicalDecoder::new(&bytes);
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::decode_canonical(&mut dec),
        Err(ContractError::MissingDrainRecord)
    );

    // Planted bypass: Record with obligations reversed in new() rejected
    let mut bad_params = valid_runtime_authority_params()?;
    let ob1 = Obligation {
        obligation_id: ObligationId::parse("ob:test:001")?,
        operation_id: bad_params.context.operation_id.clone(),
        terminal_predicate: "predicate:effect:committed".to_string(),
        state: ObligationState::Verified,
        proof_digest: Some(ContentDigest::sha256(b"proof-digest-001")),
    };
    let ob2 = Obligation {
        obligation_id: ObligationId::parse("ob:test:002")?,
        operation_id: bad_params.context.operation_id.clone(),
        terminal_predicate: "predicate:effect:committed".to_string(),
        state: ObligationState::Verified,
        proof_digest: Some(ContentDigest::sha256(b"proof-digest-002")),
    };
    bad_params.obligations = vec![ob2.clone(), ob1.clone()]; // reversed!
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::new(bad_params),
        Err(ContractError::NonCanonicalOrdering)
    );

    // Planted bypass: Record with duplicate obligations in decode_canonical rejected
    let mut enc = CanonicalEncoder::new();
    enc.text(RUNTIME_AUTHORITY_DOMAIN);
    enc.text("auth:record:dup-ob:001");
    Generation(1).encode_canonical(&mut enc);
    valid_runtime_authority_params()?
        .context
        .encode_canonical(&mut enc);
    enc.u64(0); // grants
    RegionId::new("region:property:001")?.encode_canonical(&mut enc);
    RegionKind::Property.encode_canonical(&mut enc);
    enc.bool(true);
    RegionId::new("region:process:root")?.encode_canonical(&mut enc);
    RegionState::Active.encode_canonical(&mut enc);
    enc.bool(false); // quiescence proof
    SourceCustody::NotRetained.encode_canonical(&mut enc);
    enc.u64(2); // obligations count
    ob1.encode_canonical(&mut enc);
    ob1.encode_canonical(&mut enc); // duplicate obligation!
    enc.u64(0); // object roots
    enc.u64(0); // receipt roots
    enc.bool(false); // contract basis
    let bytes = enc.finish();
    let mut dec = CanonicalDecoder::new(&bytes);
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::decode_canonical(&mut dec),
        Err(ContractError::DuplicateObligation(
            "ob:test:001".to_string()
        ))
    );

    // Planted bypass: Record with reversed obligations in decode_canonical rejected
    let mut enc = CanonicalEncoder::new();
    enc.text(RUNTIME_AUTHORITY_DOMAIN);
    enc.text("auth:record:rev-ob:001");
    Generation(1).encode_canonical(&mut enc);
    valid_runtime_authority_params()?
        .context
        .encode_canonical(&mut enc);
    enc.u64(0); // grants
    RegionId::new("region:property:001")?.encode_canonical(&mut enc);
    RegionKind::Property.encode_canonical(&mut enc);
    enc.bool(true);
    RegionId::new("region:process:root")?.encode_canonical(&mut enc);
    RegionState::Active.encode_canonical(&mut enc);
    enc.bool(false); // quiescence proof
    SourceCustody::NotRetained.encode_canonical(&mut enc);
    enc.u64(2); // obligations count
    ob2.encode_canonical(&mut enc);
    ob1.encode_canonical(&mut enc); // reversed obligation!
    enc.u64(0); // object roots
    enc.u64(0); // receipt roots
    enc.bool(false); // contract basis
    let bytes = enc.finish();
    let mut dec = CanonicalDecoder::new(&bytes);
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::decode_canonical(&mut dec),
        Err(ContractError::NonCanonicalOrdering)
    );

    // Planted bypass (W1): ContextAuthority with empty privacy_scope rejected
    let mut bad_cx = valid_runtime_authority_params()?.context;
    bad_cx.privacy_scope = String::new();
    assert_eq!(bad_cx.validate(), Err(ContractError::InvalidIdentifier));

    // Planted bypass (W1): ContextAuthority with empty retention_scope rejected
    let mut bad_cx = valid_runtime_authority_params()?.context;
    bad_cx.retention_scope = String::new();
    assert_eq!(bad_cx.validate(), Err(ContractError::InvalidIdentifier));

    // Planted test (Q11): contract_basis None is explicitly permitted for initial/L0 bootstrapping
    let mut params_none_basis = valid_runtime_authority_params()?;
    params_none_basis.contract_basis = None;
    let record_none_basis = RuntimeAuthorityAndCustodyRecord::new(params_none_basis)?;
    assert!(record_none_basis.contract_basis.is_none());
    let mut encoder = CanonicalEncoder::new();
    record_none_basis.encode_canonical(&mut encoder);
    let bytes = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&bytes);
    let decoded_none_basis = RuntimeAuthorityAndCustodyRecord::decode_canonical(&mut decoder)?;
    assert_eq!(decoded_none_basis, record_none_basis);

    // Planted bypass 36 (Q7): Unrecognized SourceCustody tag returns UnknownEntryTag
    let mut enc = CanonicalEncoder::new();
    enc.u8(99);
    let bytes = enc.finish();
    let mut dec = CanonicalDecoder::new(&bytes);
    assert_eq!(
        SourceCustody::decode_canonical(&mut dec),
        Err(ContractError::UnknownSourceCustodyTag(99))
    );

    // Planted bypass: Record with duplicate grants in decode_canonical rejected
    let mut enc = CanonicalEncoder::new();
    enc.text(RUNTIME_AUTHORITY_DOMAIN);
    enc.text("auth:record:dup-grant:001");
    Generation(1).encode_canonical(&mut enc);
    valid_runtime_authority_params()?
        .context
        .encode_canonical(&mut enc);
    enc.u64(2); // grants count
    RuntimeGrant::LedgerAppend.encode_canonical(&mut enc);
    RuntimeGrant::LedgerAppend.encode_canonical(&mut enc); // duplicate grant!
    RegionId::new("region:property:001")?.encode_canonical(&mut enc);
    RegionKind::Property.encode_canonical(&mut enc);
    enc.bool(true);
    RegionId::new("region:process:root")?.encode_canonical(&mut enc);
    RegionState::Active.encode_canonical(&mut enc);
    enc.bool(false); // quiescence proof
    SourceCustody::NotRetained.encode_canonical(&mut enc);
    enc.u64(0); // obligations count
    enc.u64(0); // object roots
    enc.u64(0); // receipt roots
    enc.bool(false); // contract basis
    let bytes = enc.finish();
    let mut dec = CanonicalDecoder::new(&bytes);
    assert_eq!(
        RuntimeAuthorityAndCustodyRecord::decode_canonical(&mut dec),
        Err(ContractError::DuplicateGrant(
            "CAP-LEDGER-APPEND-001".to_string()
        ))
    );

    Ok(())
}

#[test]
fn test_source_evidence_golden_vector() -> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor {
        site_lineage: "site:golden".to_string(),
        ledger_epoch: 1,
        commit_sequence: 1,
        adapter_registry_epoch: 1,
        schema_epoch: 1,
        policy_epoch: 1,
        privacy_epoch: 1,
        state_root: ContentDigest::sha256(b"golden-state-root"),
    };
    let source_digest = ContentDigest::sha256(b"golden-source-payload-bytes");
    let continuity_witness = ContentDigest::sha256(b"golden-continuity-witness-42");
    let capsule = SensorCapsule {
        capsule_id: CapsuleId::parse("cap:golden:001")?,
        sensor_id: SensorId::parse("sensor:golden:cam01")?,
        stream_id: StreamId::parse("stream:golden:rgb")?,
        sequence: 100,
        capture: CaptureInterval {
            earliest: TimestampNs(1_700_000_000_000_000_000),
            latest: TimestampNs(1_700_000_001_000_000_000),
        },
        receive_time: TimestampNs(1_700_000_001_100_000_000),
        clock_basis: ClockBasis::UtcDisciplined,
        source_digest,
        source_bytes: 2048,
        frame_count: 60,
        gap_before: false,
    };
    let record = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:golden:001".to_string(),
        anchor,
        generation: Generation(5),
        statement: "Golden source evidence record for canonical wire format verification"
            .to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::SensorCapsule,
        custody: SourceCustody::Retained {
            source_digest,
            source_bytes: 2048,
            storage_handle: "cas/sha256/golden-source-payload".to_string(),
        },
        omission: None,
        capsule: Some(capsule),
        continuity_witness: Some(continuity_witness),
    })?;

    assert_eq!(SOURCE_EVIDENCE_RECORD_FORMAT_VERSION, 2);

    let canonical_bytes = record.to_canonical_bytes()?;
    let expected_hex = "000000020000000000000011736f757263653a676f6c64656e3a303031000000000000000b736974653a676f6c64656e0000000000000001000000000000000100000000000000010000000000000001000000000000000100000000000000010116a86d9757449df9918f423fc0bf7fb115fccedaf6547fb294c34919d994f0aa00000000000000050000000000000044476f6c64656e20736f757263652065766964656e6365207265636f726420666f722063616e6f6e6963616c207769726520666f726d617420766572696669636174696f6e00000000000000086f62736572766564000000000000000e73656e736f725f63617073756c650101b9474e3237099ce42c7040178cb9a4601d56f29f3362e5ef114989ea5244f7d2000000000000080000000000000000206361732f7368613235362f676f6c64656e2d736f757263652d7061796c6f61640001000000000000000e6361703a676f6c64656e3a303031000000000000001373656e736f723a676f6c64656e3a63616d3031000000000000001173747265616d3a676f6c64656e3a7267620000000000000064000000000000000017979cfe362a0000000000000000000017979cfe71c4ca00000000000000000017979cfe77baab00000000000000000f7574635f6469736369706c696e656401b9474e3237099ce42c7040178cb9a4601d56f29f3362e5ef114989ea5244f7d200000000000008000000003c0001019a2af80ebb359fc05dccf283e344594d86d4556e4448eb19ec3ed084a6840f70";
    let actual_hex = canonical_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(
        actual_hex, expected_hex,
        "canonical byte vector must match pinned golden bytes"
    );

    let digest = record.canonical_digest()?;
    let expected_digest = ContentDigest::parse(
        "sha256:9394e4b5cc079e1a4c3b609a7680c5e9e61434b5570320698bea3f06c567c2fc",
    )?;
    assert_eq!(
        digest, expected_digest,
        "canonical digest must match pinned golden digest literal"
    );

    // Decode back and verify roundtrip identity
    let decoded = SourceEvidenceRecord::from_canonical_bytes(&canonical_bytes)?;
    assert_eq!(decoded, record);

    Ok(())
}

#[test]
fn test_agent_abstraction_freeze_digest_recomputed_in_rust() -> Result<(), Box<dyn Error>> {
    let stack_json = include_str!("../../../architecture/agent_abstraction_stack.json");
    let root = MiniJson::parse(stack_json).ok_or("failed to parse agent_abstraction_stack.json")?;
    let MiniJson::Obj(mut fields) = root else {
        return Err("expected root to be an object".into());
    };

    // Remove registryDigest before computing canonical freeze digest
    fields.retain(|(k, _)| k != "registryDigest");

    // Canonicalize layers: sort by id, retain only known keys
    const KNOWN_LAYER_KEYS: &[&str] = &[
        "id",
        "invariant",
        "name",
        "output",
        "owner",
        "prohibition",
        "question",
        "status",
    ];
    for (k, v) in &mut fields {
        match (k.as_str(), v) {
            ("layers", MiniJson::Arr(layers)) => {
                layers.sort_by(|a, b| {
                    let id_a = a.get("id").and_then(MiniJson::as_str).unwrap_or("");
                    let id_b = b.get("id").and_then(MiniJson::as_str).unwrap_or("");
                    id_a.cmp(id_b)
                });
                for layer in layers.iter_mut() {
                    if let MiniJson::Obj(layer_fields) = layer {
                        layer_fields.retain(|(lk, _)| KNOWN_LAYER_KEYS.contains(&lk.as_str()));
                    }
                }
            }
            ("hydrationLevels", MiniJson::Arr(hydration)) => {
                hydration.sort_by(|a, b| {
                    let id_a = a.get("id").and_then(MiniJson::as_str).unwrap_or("");
                    let id_b = b.get("id").and_then(MiniJson::as_str).unwrap_or("");
                    id_a.cmp(id_b)
                });
                const KNOWN_HYDRATION_KEYS: &[&str] = &["content", "id", "name"];
                for hyd in hydration.iter_mut() {
                    if let MiniJson::Obj(hyd_fields) = hyd {
                        hyd_fields.retain(|(hk, _)| KNOWN_HYDRATION_KEYS.contains(&hk.as_str()));
                    }
                }
            }
            _ => {}
        }
    }

    let canonical_root = MiniJson::Obj(fields);
    let mut canonical_json = String::new();
    canonical_root.write_canonical(&mut canonical_json);

    let digest = ContentDigest::sha256(canonical_json.as_bytes());
    assert_eq!(
        digest.to_string(),
        AGENT_ABSTRACTION_FREEZE_DIGEST,
        "Rust recomputed freeze digest must match AGENT_ABSTRACTION_FREEZE_DIGEST"
    );

    Ok(())
}
