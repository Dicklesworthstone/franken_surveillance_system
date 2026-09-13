#![forbid(unsafe_code)]
//! Deterministic contract tests for agent abstraction layers:
//! - AGT-LAYER-003: world_facts_and_coverage (INV-063)
//! - AGT-LAYER-004: derived_beliefs (INV-069)

use std::collections::BTreeSet;
use std::error::Error;
use std::str::FromStr;

use fss_core::belief::BeliefInterval;
use fss_core::{
    evaluate_negative_read, AgentAbstractionLayer, CanonicalDecode, CanonicalDecoder,
    CanonicalEncode, CanonicalEncoder, CapsuleId, CaptureInterval, ClockBasis, Completeness,
    ContentDigest, ContractError, CoverageContinuity, CoverageStopReason, CoverageWitness,
    DerivedBelief, DerivedBeliefParams, Generation, KnowledgeState, LedgerAnchor,
    NegativeReadClaim, NegativeReadOutcome, OmissionReason, Plane, ProvenanceClass, SensorCapsule,
    SensorId, SourceCustody, SourceEvidenceClassification, SourceEvidenceParams,
    SourceEvidenceRecord, StreamId, TimestampNs, WorldFact, WorldFactKind,
    AGENT_ABSTRACTION_FREEZE_DIGEST, AGENT_ABSTRACTION_GENERATION,
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
fn test_runtime_authority_and_custody_row_properties() -> Result<(), Box<dyn Error>> {
    let layer = AgentAbstractionLayer::RuntimeAuthorityAndCustody;

    // 1. Exact normative stable ID
    assert_eq!(layer.id(), "AGT-LAYER-001");

    // 2. Exact normative schema name
    assert_eq!(layer.name(), "runtime_authority_and_custody");
    assert_eq!(format!("{layer}"), "runtime_authority_and_custody");

    // 3. Exact normative owner
    assert_eq!(layer.owner(), "asupersync/authority/object owners");

    // 4. Exact normative question
    assert_eq!(
        layer.agent_question(),
        "What work, authority, budget, identity, time, and object custody exist?"
    );

    // 5. Exact normative output
    assert_eq!(
        layer.output(),
        "Context, grants, regions, obligations, object roots, and receipts."
    );

    // 6. Exact normative prohibition
    assert_eq!(
        layer.prohibition(),
        "Cannot infer mission meaning or physical truth."
    );

    // 7. Exact normative invariant
    assert_eq!(layer.invariant(), "INV-006");

    // 8. Exact normative status
    assert_eq!(layer.status(), "normative");

    // 9. Semantic plane: Authority
    assert_eq!(layer.plane(), Plane::Authority);

    // 10. Tower level: L0 (0-indexed: 0)
    assert_eq!(layer.tower_level(), 0);

    // 11. Authority plane permissions:
    assert!(layer.may_claim_authority());
    assert!(!layer.may_authorize_effects());

    // 12. Helper predicates:
    assert!(layer.is_runtime_authority_and_custody());
    assert!(layer.prohibits_mission_meaning_inference());
    assert!(layer.prohibits_physical_truth_inference());

    // 13. Invariant validation passes:
    layer.validate_invariants()?;

    Ok(())
}

#[test]
fn test_runtime_authority_and_custody_parse_and_resolution() -> Result<(), Box<dyn Error>> {
    // Parse from stable ID
    let from_id = AgentAbstractionLayer::from_id("AGT-LAYER-001")?;
    assert_eq!(from_id, AgentAbstractionLayer::RuntimeAuthorityAndCustody);

    // Parse from schema name
    let from_name = AgentAbstractionLayer::from_name("runtime_authority_and_custody")?;
    assert_eq!(from_name, AgentAbstractionLayer::RuntimeAuthorityAndCustody);

    // Parse via FromStr with stable ID
    let from_str_id = AgentAbstractionLayer::from_str("AGT-LAYER-001")?;
    assert_eq!(from_str_id, AgentAbstractionLayer::RuntimeAuthorityAndCustody);

    // Parse via FromStr with schema name
    let from_str_name = AgentAbstractionLayer::from_str("runtime_authority_and_custody")?;
    assert_eq!(from_str_name, AgentAbstractionLayer::RuntimeAuthorityAndCustody);

    // Parse from tower level
    let from_level = AgentAbstractionLayer::from_tower_level(0)?;
    assert_eq!(from_level, AgentAbstractionLayer::RuntimeAuthorityAndCustody);

    Ok(())
}

#[test]
fn test_planted_negative_runtime_authority_and_custody_bypasses() -> Result<(), Box<dyn Error>> {
    let layer = AgentAbstractionLayer::RuntimeAuthorityAndCustody;

    // Planted bypass 1: Runtime authority must NEVER be permitted to authorize effects directly.
    assert!(!layer.may_authorize_effects());

    // Planted bypass 2: Runtime authority plane must strictly be Authority, never Cognition or Effect.
    assert_ne!(layer.plane(), Plane::Cognition);
    assert_ne!(layer.plane(), Plane::Effect);
    assert_eq!(layer.plane(), Plane::Authority);

    // Planted bypass 3: Invariant must strictly be INV-006, not any other invariant.
    assert_eq!(layer.invariant(), "INV-006");

    // Planted bypass 4: Must strictly prohibit mission meaning inference.
    assert!(layer.prohibits_mission_meaning_inference());

    // Planted bypass 5: Must strictly prohibit physical truth inference.
    assert!(layer.prohibits_physical_truth_inference());

    // Planted bypass 6: Unknown, malformed, or out-of-range tower level must fail closed.
    let Err(err_level) = AgentAbstractionLayer::from_tower_level(99) else {
        return Err("expected out-of-bounds tower level to fail".into());
    };
    assert_eq!(err_level, ContractError::UnknownEntryTag(99));

    // Planted bypass 7: Malformed or mutated ID must fail closed.
    let Err(err_id) = AgentAbstractionLayer::from_id("AGT-LAYER-000") else {
        return Err("expected unknown ID to fail".into());
    };
    assert_eq!(
        err_id,
        ContractError::UnknownAbstractionLayer("AGT-LAYER-000".into())
    );

    // Planted bypass 8: Case-sensitive name mismatch must fail closed.
    let Err(err_name) = AgentAbstractionLayer::from_name("Runtime_Authority_And_Custody") else {
        return Err("expected uppercase name to fail".into());
    };
    assert_eq!(
        err_name,
        ContractError::UnknownAbstractionLayer("Runtime_Authority_And_Custody".into())
    );

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
    assert_eq!(err, ContractError::InvalidIdentifier);

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

    // 5. Prohibition: "Cannot include unqualified cognition as fact" (INV-063)
    let res = WorldFact::new(
        "fact:device:001",
        WorldFactKind::Device,
        anchor.clone(),
        "Statement with unqualified cognition treated as fact".to_string(),
        ProvenanceClass::Observed,
        evidence,
        Generation(1),
    );
    let Err(err) = res else {
        return Err("expected error for unqualified cognition".into());
    };
    assert_eq!(err, ContractError::EvidenceRequired);

    // 6. Planted bypass: ProvenanceClass::Predicted fails closed
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

    // 7. Planted bypass: ProvenanceClass::Remembered fails closed
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
    let anchor = sample_anchor();
    let mut target_domain = BTreeSet::new();
    target_domain.insert("zone:north_perimeter".to_string());

    // Claim WITHOUT CoverageWitness must fail closed (AGENTS.md prime directive)
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:001".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor,
        target_domain,
        target_generation: 1,
        coverage_witness: None,
    };

    let Err(err) = evaluate_negative_read(&claim) else {
        return Err("expected error for uncertified coverage".into());
    };
    assert_eq!(err, ContractError::CoverageUncertified);

    Ok(())
}

#[test]
fn test_planted_negative_uncertified_coverage_witness_fails() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
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
    let Err(err) = evaluate_negative_read(&claim) else {
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
    let Err(err) = evaluate_negative_read(&claim) else {
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
    let Err(err) = evaluate_negative_read(&claim) else {
        return Err("expected error for budget exhausted stop reason".into());
    };
    assert_eq!(err, ContractError::CoverageUncertified);

    // 4. Non-empty excluded domain
    let mut witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:north_perimeter"],
        &["zone:north_perimeter"],
    );
    witness.excluded_domain.insert("zone:north_gate".to_string());
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:excluded".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: anchor.clone(),
        target_domain: target_domain.clone(),
        target_generation: 1,
        coverage_witness: Some(witness),
    };
    let Err(err) = evaluate_negative_read(&claim) else {
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
    let Err(err) = evaluate_negative_read(&claim) else {
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
    let Err(err) = evaluate_negative_read(&claim) else {
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
        target_domain,
        target_generation: 2, // Witness has gen 1
        coverage_witness: Some(witness),
    };
    let Err(err) = evaluate_negative_read(&claim) else {
        return Err("expected error for generation mismatch".into());
    };
    assert_eq!(err, ContractError::GenerationConflict);

    // 8. Anchor lineage mismatch
    let witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:north_perimeter"],
        &["zone:north_perimeter"],
    );
    let mut rogue_anchor = anchor.clone();
    rogue_anchor.site_lineage = "site:rogue_lineage".to_string();
    let mut target_domain = BTreeSet::new();
    target_domain.insert("zone:north_perimeter".to_string());
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:stale_anchor".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: rogue_anchor,
        target_domain,
        target_generation: 1,
        coverage_witness: Some(witness),
    };
    let Err(err) = evaluate_negative_read(&claim) else {
        return Err("expected error for stale anchor".into());
    };
    assert_eq!(err, ContractError::StaleAnchor);

    // 9. Anchor epoch/seq_no mismatch (stale anchor)
    let witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:north_perimeter"],
        &["zone:north_perimeter"],
    );
    let mut stale_anchor = anchor;
    stale_anchor.ledger_epoch += 1;
    let mut target_domain = BTreeSet::new();
    target_domain.insert("zone:north_perimeter".to_string());
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:stale_epoch".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: stale_anchor,
        target_domain,
        target_generation: 1,
        coverage_witness: Some(witness),
    };
    let Err(err) = evaluate_negative_read(&claim) else {
        return Err("expected error for stale anchor epoch".into());
    };
    assert_eq!(err, ContractError::StaleAnchor);

    Ok(())
}

#[test]
fn test_negative_read_claim_with_certified_absence_succeeds() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
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

    let outcome = evaluate_negative_read(&claim)?;
    assert_eq!(outcome.claim_id, "neg_claim:certified_ok");
    assert_eq!(outcome.query_predicate, "no_unauthorized_intrusion");
    assert_eq!(outcome.anchor, anchor);
    assert_eq!(outcome.certified_domain, target_domain);
    assert_eq!(outcome.witness_digest, witness.witness_digest());
    assert_eq!(outcome.generation, 1);

    // Canonical roundtrip
    let mut encoder = CanonicalEncoder::new();
    outcome.encode_canonical(&mut encoder);
    let encoded = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&encoded);
    let decoded = NegativeReadOutcome::decode_canonical(&mut decoder)?;
    assert_eq!(decoded, outcome);

    Ok(())
}

#[test]
fn test_negative_read_outcome_decode_invariants() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let witness_digest = ContentDigest::sha256(b"sample_witness_digest");

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
    let Err(err) = NegativeReadOutcome::decode_canonical(&mut decoder) else {
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
    let Err(err) = NegativeReadOutcome::decode_canonical(&mut decoder) else {
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
    let Err(err) = NegativeReadOutcome::decode_canonical(&mut decoder) else {
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
    encoder.digest(ContentDigest::new(fss_core::DigestAlgorithm::Sha256, [0u8; 32])); // zero digest!
    encoder.u64(1);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let Err(err) = NegativeReadOutcome::decode_canonical(&mut decoder) else {
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
    let Err(err) = NegativeReadOutcome::decode_canonical(&mut decoder) else {
        return Err("expected error for empty claim_id".into());
    };
    assert_eq!(err, ContractError::InvalidIdentifier);

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

fn make_test_sensor_capsule(source_digest: ContentDigest, source_bytes: u64) -> SensorCapsule {
    SensorCapsule {
        capsule_id: CapsuleId::parse("cap:001").unwrap(),
        sensor_id: SensorId::parse("sensor:cam01").unwrap(),
        stream_id: StreamId::parse("stream:front_gate").unwrap(),
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
    }
}

#[test]
fn test_source_evidence_record_valid_construction() -> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("camera.sensor.front_gate");
    let source_digest = ContentDigest::sha256(b"raw-h264-nalu-data");
    let continuity_digest = ContentDigest::sha256(b"rtcp-continuity-witness-sequence-42");
    let capsule = make_test_sensor_capsule(source_digest, 1024);

    let record = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:packet:front_gate:0042".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Raw H.264 capture packets from front gate optical sensor".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: SourceCustody::Retained {
            source_digest,
            source_bytes: 1024,
            storage_handle: "cas://sha256/raw-h264".to_string(),
        },
        omission: None,
        capsule: Some(capsule.clone()),
        continuity_witness: Some(continuity_digest),
    })?;

    assert_eq!(record.evidence_id, "source:packet:front_gate:0042");
    assert_eq!(record.anchor, anchor);
    assert_eq!(record.generation, Generation(1));
    assert_eq!(record.provenance, ProvenanceClass::Observed);
    assert_eq!(
        record.classification,
        SourceEvidenceClassification::RawWirePackets
    );
    assert_eq!(
        record.custody,
        SourceCustody::Retained {
            source_digest,
            source_bytes: 1024,
            storage_handle: "cas://sha256/raw-h264".to_string(),
        }
    );
    assert_eq!(record.omission, None);
    assert_eq!(record.capsule, Some(capsule.clone()));
    assert_eq!(record.continuity_witness, Some(continuity_digest));
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
    let continuity_digest = ContentDigest::sha256(b"rtcp-continuity-witness-restricted");

    let record = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:packet:restricted:0099".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement:
            "Physical sensor reading where raw video retention is legally forbidden"
                .to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::PhysicalSensorMeasurement,
        custody: SourceCustody::NotRetained,
        omission: Some(OmissionReason::PrivacyRedaction),
        capsule: None,
        continuity_witness: Some(continuity_digest),
    })?;

    assert_eq!(record.custody, SourceCustody::NotRetained);
    assert_eq!(record.omission, Some(OmissionReason::PrivacyRedaction));

    let kcell = record.to_knowledge_cell();
    assert!(kcell.evidence.is_empty());
    assert_eq!(kcell.knowledge_state, KnowledgeState::Unknown);
    assert!(kcell.validate().is_ok());

    // Also test upstream missing maps to NotObservable
    let record_upstream = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:packet:restricted:0100".to_string(),
        anchor,
        generation: Generation(1),
        statement: "Upstream sensor dropout".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::SensorCapsule,
        custody: SourceCustody::NotRetained,
        omission: Some(OmissionReason::UpstreamMissing),
        capsule: None,
        continuity_witness: None,
    })?;
    let kcell_upstream = record_upstream.to_knowledge_cell();
    assert!(kcell_upstream.evidence.is_empty());
    assert_eq!(kcell_upstream.knowledge_state, KnowledgeState::NotObservable);
    assert!(kcell_upstream.validate().is_ok());

    Ok(())
}

#[test]
fn test_planted_negative_source_evidence_bypasses() -> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("camera.sensor.cam01");
    let source_digest = ContentDigest::sha256(b"raw-packet-bytes");
    let valid_custody = SourceCustody::Retained {
        source_digest,
        source_bytes: 1024,
        storage_handle: "cas://sha256/raw-packet".to_string(),
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
    assert_eq!(res.unwrap_err(), ContractError::InvalidIdentifier);

    // E8: Path traversal /../ in ID rejected with InvalidIdentifier
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
    assert_eq!(res.unwrap_err(), ContractError::InvalidIdentifier);

    // E8: Newline in ID rejected with InvalidIdentifier
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
    assert_eq!(res.unwrap_err(), ContractError::InvalidIdentifier);

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
    assert_eq!(res.unwrap_err(), ContractError::SourceEvidenceMissingAnchor);

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
    assert_eq!(res.unwrap_err(), ContractError::GenerationConflict);

    // 4. Empty statement rejected with InvalidIdentifier
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
    assert_eq!(res.unwrap_err(), ContractError::InvalidIdentifier);

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
    assert_eq!(res.unwrap_err(), ContractError::SourceEvidenceOmissionRequired);

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
    assert_eq!(res.unwrap_err(), ContractError::SourceEvidenceOmissionRequired);

    // E1: NotRetained with omission reason but capsule with bytes > 0 rejected with SourceEvidenceNotRetainedWithCapsuleBytes
    let cap_with_bytes = make_test_sensor_capsule(source_digest, 1024);
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
        res.unwrap_err(),
        ContractError::SourceEvidenceNotRetainedWithCapsuleBytes
    );

    // E2: Retained with an omission reason rejected with SourceEvidenceRetainedWithOmission
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
    assert_eq!(
        res.unwrap_err(),
        ContractError::SourceEvidenceRetainedWithOmission
    );

    // E10: Retained with Some(OmissionReason::None) rejected with SourceEvidenceRetainedWithOmission
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
    assert_eq!(
        res.unwrap_err(),
        ContractError::SourceEvidenceRetainedWithOmission
    );

    // E3: Custody source_bytes != capsule source_bytes (1024 vs 99) rejected with SourceEvidenceByteCountMismatch
    let cap_mismatch_bytes = make_test_sensor_capsule(source_digest, 99);
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
            storage_handle: "cas://sha256/raw-packet".to_string(),
        },
        omission: None,
        capsule: Some(cap_mismatch_bytes),
        continuity_witness: None,
    });
    assert_eq!(
        res.unwrap_err(),
        ContractError::SourceEvidenceByteCountMismatch
    );

    // Digest mismatch: Custody source_digest != capsule source_digest rejected with DigestMismatch
    let different_digest = ContentDigest::sha256(b"different-source-digest");
    let cap_different_digest = make_test_sensor_capsule(different_digest, 1024);
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
            storage_handle: "cas://sha256/raw-packet".to_string(),
        },
        omission: None,
        capsule: Some(cap_different_digest),
        continuity_witness: None,
    });
    assert_eq!(res.unwrap_err(), ContractError::DigestMismatch);

    // E7: Retained with empty storage handle rejected with SourceEvidenceEmptyStorageHandle
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Empty storage handle".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: SourceCustody::Retained {
            source_digest,
            source_bytes: 1024,
            storage_handle: "".to_string(),
        },
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(
        res.unwrap_err(),
        ContractError::SourceEvidenceEmptyStorageHandle
    );

    // E7: Retained with whitespace-only storage handle rejected with SourceEvidenceEmptyStorageHandle
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Whitespace storage handle".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: SourceCustody::Retained {
            source_digest,
            source_bytes: 1024,
            storage_handle: "   \t\n  ".to_string(),
        },
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(
        res.unwrap_err(),
        ContractError::SourceEvidenceEmptyStorageHandle
    );

    // E5: Classification parse refuses keyword heuristic bypasses
    assert_eq!(
        SourceEvidenceClassification::parse("decoded_frame_pcap"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        SourceEvidenceClassification::parse("model-output file"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        SourceEvidenceClassification::parse("rgb-pixels from sensor"),
        Err(ContractError::InvalidIdentifier)
    );

    // E6: Classification parse refuses non-canonical tokens including whitespace/casing
    assert_eq!(
        SourceEvidenceClassification::parse(" RAW_WIRE_PACKETS "),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        SourceEvidenceClassification::parse("raw_wire_packets_extra"),
        Err(ContractError::InvalidIdentifier)
    );
    assert_eq!(
        SourceEvidenceClassification::parse(""),
        Err(ContractError::InvalidIdentifier)
    );

    // E5/E6: Canonical decoder refuses non-canonical classification tokens
    let mut encoder = CanonicalEncoder::new();
    encoder.text("decoded_frame_pcap");
    let bytes = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&bytes);
    assert_eq!(
        SourceEvidenceClassification::decode_canonical(&mut decoder),
        Err(ContractError::InvalidIdentifier)
    );

    let mut encoder = CanonicalEncoder::new();
    encoder.text(" RAW_WIRE_PACKETS ");
    let bytes = encoder.finish();
    let mut decoder = CanonicalDecoder::new(&bytes);
    assert_eq!(
        SourceEvidenceClassification::decode_canonical(&mut decoder),
        Err(ContractError::InvalidIdentifier)
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
        assert_eq!(res.unwrap_err(), ContractError::ProhibitedEvidencePromotion);
    }

    // Statement field does NOT check keyword denylists; classification is typed.
    // "Decoded-frame RGB pixels from YOLO" succeeds when classification is permitted.
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement:
            "Decoded-frame RGB pixels from YOLO (legacy text with permitted typed classification)"
                .to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: valid_custody.clone(),
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert!(res.is_ok());

    // Non-Observed provenance (Derived, Predicted) rejected with ProhibitedEvidencePromotion
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
    assert_eq!(res.unwrap_err(), ContractError::ProhibitedEvidencePromotion);

    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Valid statement".to_string(),
        provenance: ProvenanceClass::Predicted,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: valid_custody,
        omission: None,
        capsule: None,
        continuity_witness: None,
    });
    assert_eq!(res.unwrap_err(), ContractError::ProhibitedEvidencePromotion);

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

    // ClockBasis::parse refuses unknown clock basis names with typed error
    match ClockBasis::parse("atomic_clock_v2") {
        Err(ContractError::UnknownClockBasisName(name)) => {
            assert_eq!(name, "atomic_clock_v2");
        }
        other => return Err(format!("expected UnknownClockBasisName, got {other:?}").into()),
    }

    // SensorCapsule CanonicalEncode and CanonicalDecode roundtrip
    let digest = ContentDigest::sha256(b"sensor-capsule-test-bytes");
    let capsule = make_test_sensor_capsule(digest, 2048);

    let mut encoder = CanonicalEncoder::new();
    capsule.encode_canonical(&mut encoder);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let decoded = SensorCapsule::decode_canonical(&mut decoder)?;
    assert_eq!(decoded, capsule);

    Ok(())
}

#[test]
fn test_source_evidence_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("camera.sensor.dock_bay");
    let source_digest = ContentDigest::sha256(b"dock-bay-payload-bytes");
    let continuity_digest = ContentDigest::sha256(b"dock-bay-continuity");
    let capsule = make_test_sensor_capsule(source_digest, 4096);

    let record = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:packet:dock_bay:0128".to_string(),
        anchor,
        generation: Generation(3),
        statement: "Dock bay source packets with continuity witness".to_string(),
        provenance: ProvenanceClass::Observed,
        classification: SourceEvidenceClassification::RawWirePackets,
        custody: SourceCustody::Retained {
            source_digest,
            source_bytes: 4096,
            storage_handle: "cas://dock-bay/packets".to_string(),
        },
        omission: None,
        capsule: Some(capsule),
        continuity_witness: Some(continuity_digest),
    })?;

    let mut encoder = CanonicalEncoder::new();
    record.encode_canonical(&mut encoder);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let decoded = SourceEvidenceRecord::decode_canonical(&mut decoder)?;

    assert_eq!(decoded, record);
    assert_eq!(decoded.evidence_id, record.evidence_id);
    assert_eq!(decoded.anchor, record.anchor);
    assert_eq!(decoded.generation, record.generation);
    assert_eq!(decoded.statement, record.statement);
    assert_eq!(decoded.provenance, record.provenance);
    assert_eq!(decoded.classification, record.classification);
    assert_eq!(decoded.custody, record.custody);
    assert_eq!(decoded.omission, record.omission);
    assert_eq!(decoded.capsule, record.capsule);
    assert_eq!(decoded.continuity_witness, record.continuity_witness);

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

    let mut encoder = CanonicalEncoder::new();
    not_retained_record.encode_canonical(&mut encoder);
    let bytes = encoder.finish();

    let mut decoder = CanonicalDecoder::new(&bytes);
    let decoded_not_retained = SourceEvidenceRecord::decode_canonical(&mut decoder)?;
    assert_eq!(decoded_not_retained, not_retained_record);

    Ok(())
}

