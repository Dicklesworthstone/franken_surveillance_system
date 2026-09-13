#![forbid(unsafe_code)]
//! Deterministic contract tests for agent abstraction layers:
//! - AGT-LAYER-003: world_facts_and_coverage (INV-063)
//! - AGT-LAYER-004: derived_beliefs (INV-069)

use std::collections::BTreeSet;
use std::error::Error;
use std::str::FromStr;

use fss_core::abstraction::{
    AuthorityAnchor, AuthorityContext, CurrentAnchorSource,
};
use fss_core::belief::BeliefInterval;
use fss_core::{
    AGENT_ABSTRACTION_FREEZE_DIGEST, AGENT_ABSTRACTION_GENERATION, AgentAbstractionLayer,
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, Completeness,
    ContentDigest, ContractError, CoverageContinuity, CoverageStopReason, CoverageWitness,
    DerivedBelief, DerivedBeliefParams, DigestAlgorithm, Generation, KnowledgeState, LedgerAnchor,
    NegativeReadClaim, NegativeReadOutcome, Plane, ProvenanceClass, SourceEvidenceParams,
    SourceEvidenceRecord, TimestampNs, WorldFact, WorldFactKind, evaluate_negative_read,
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
    assert_eq!(
        from_str_id,
        AgentAbstractionLayer::RuntimeAuthorityAndCustody
    );

    // Parse via FromStr with schema name
    let from_str_name = AgentAbstractionLayer::from_str("runtime_authority_and_custody")?;
    assert_eq!(
        from_str_name,
        AgentAbstractionLayer::RuntimeAuthorityAndCustody
    );

    // Parse from tower level
    let from_level = AgentAbstractionLayer::from_tower_level(0)?;
    assert_eq!(
        from_level,
        AgentAbstractionLayer::RuntimeAuthorityAndCustody
    );

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
    let anchor = sample_anchor();
    let authority = AuthorityAnchor::from_authority(anchor.clone())?;
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
    let anchor = sample_anchor();
    let authority = AuthorityAnchor::from_authority(anchor.clone())?;
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
    let mut newer_authority_anchor = anchor.clone();
    newer_authority_anchor.commit_sequence += 5;
    let newer_authority = AuthorityAnchor::from_authority(newer_authority_anchor)?;
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
    let mut forked_authority_anchor = anchor.clone();
    forked_authority_anchor.state_root = ContentDigest::sha256(b"forked_authority_state_root");
    let forked_authority = AuthorityAnchor::from_authority(forked_authority_anchor)?;
    let witness = sample_witness(
        "no_unauthorized_intrusion",
        &["zone:north_perimeter"],
        &["zone:north_perimeter"],
    );
    let claim = NegativeReadClaim {
        claim_id: "neg_claim:divergent_state_root".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: anchor.clone(),
        target_domain,
        target_generation: 1,
        coverage_witness: Some(witness),
    };
    let Err(err) = evaluate_negative_read(&claim, &forked_authority) else {
        return Err("expected error for divergent state root (RM8)".into());
    };
    assert_eq!(err, ContractError::StaleAnchor);

    Ok(())
}

#[test]
fn test_negative_read_outcome_from_witness_direct_contracts() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let authority = AuthorityAnchor::from_authority(anchor.clone())?;
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
    let mut other_site_anchor = anchor.clone();
    other_site_anchor.site_lineage = "site:other".to_string();
    let other_site_authority = AuthorityAnchor::from_authority(other_site_anchor)?;
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
    let mut newer_anchor = anchor.clone();
    newer_anchor.commit_sequence += 1;
    let newer_authority = AuthorityAnchor::from_authority(newer_anchor)?;
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
    let mut forked_anchor = anchor.clone();
    forked_anchor.state_root = ContentDigest::sha256(b"forked_anchor_state_root");
    let forked_authority = AuthorityAnchor::from_authority(forked_anchor)?;
    let res = NegativeReadOutcome::from_witness(
        "neg_claim:rm8_direct",
        "no_unauthorized_intrusion",
        anchor.clone(),
        target_domain.clone(),
        &witness,
        &forked_authority,
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
fn test_authority_context_and_contract_basis_as_current_anchor_source() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let basis = fss_core::contract_basis::reference_contract_basis();

    // 1. AuthorityContext implements CurrentAnchorSource
    let auth_ctx = AuthorityContext::new(&basis, anchor.clone())?;
    assert_eq!(auth_ctx.current_anchor(), &anchor);
    assert_eq!(auth_ctx.contract_basis(), &basis);

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

    // 2. (&ContractBasis, &LedgerAnchor) tuple implements CurrentAnchorSource
    let tuple_source = (&basis, &anchor);
    assert_eq!(tuple_source.current_anchor(), &anchor);
    let outcome_tuple = evaluate_negative_read(&claim, &tuple_source)?;
    assert_eq!(outcome_tuple.claim_id(), "neg_claim:auth_ctx_ok");

    Ok(())
}

#[test]
fn test_negative_read_claim_with_certified_absence_succeeds() -> Result<(), Box<dyn Error>> {
    let anchor = sample_anchor();
    let authority = AuthorityAnchor::from_authority(anchor.clone())?;
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
    let anchor = sample_anchor();
    let authority = AuthorityAnchor::from_authority(anchor.clone())?;
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

#[test]
fn test_source_evidence_record_valid_construction() -> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("camera.sensor.front_gate");
    let source_digest = ContentDigest::sha256(b"raw-h264-nalu-data");
    let continuity_digest = ContentDigest::sha256(b"rtcp-continuity-witness-sequence-42");

    let record = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:packet:front_gate:0042".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Raw H.264 capture packets from front gate optical sensor".to_string(),
        provenance: ProvenanceClass::Observed,
        source_bytes_digest: Some(source_digest),
        continuity_witness: Some(continuity_digest),
        retention_forbidden_reason: None,
    })?;

    assert_eq!(record.evidence_id, "source:packet:front_gate:0042");
    assert_eq!(record.anchor, anchor);
    assert_eq!(record.generation, Generation(1));
    assert_eq!(record.provenance, ProvenanceClass::Observed);
    assert_eq!(record.source_bytes_digest, Some(source_digest));
    assert_eq!(record.continuity_witness, Some(continuity_digest));
    assert_eq!(record.retention_forbidden_reason, None);
    assert_eq!(record.layer(), AgentAbstractionLayer::SourceEvidence);
    assert_eq!(record.plane(), Plane::Authority);
    assert!(record.may_claim_authority());
    assert!(!record.may_authorize_effects());

    let kcell = record.to_knowledge_cell();
    assert_eq!(kcell.claim_id, "source:packet:front_gate:0042");
    assert_eq!(kcell.knowledge_state, KnowledgeState::Known);
    assert_eq!(kcell.provenance, ProvenanceClass::Observed);
    assert_eq!(kcell.evidence, vec![source_digest]);

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
        statement: "Physical sensor reading where raw video retention is legally forbidden"
            .to_string(),
        provenance: ProvenanceClass::Observed,
        source_bytes_digest: None,
        continuity_witness: Some(continuity_digest),
        retention_forbidden_reason: Some(
            "Statutory privacy retention prohibition on private quarters (INV-003)".to_string(),
        ),
    })?;

    assert_eq!(record.source_bytes_digest, None);
    assert!(record.retention_forbidden_reason.is_some());

    let kcell = record.to_knowledge_cell();
    assert!(kcell.evidence.is_empty());
    assert_eq!(kcell.knowledge_state, KnowledgeState::Known);

    Ok(())
}

#[test]
fn test_planted_negative_source_evidence_bypasses() -> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("camera.sensor.cam01");
    let source_digest = ContentDigest::sha256(b"raw-packet-bytes");

    // 1. Empty ID rejected
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Valid statement".to_string(),
        provenance: ProvenanceClass::Observed,
        source_bytes_digest: Some(source_digest),
        continuity_witness: None,
        retention_forbidden_reason: None,
    });
    match res {
        Err(err) if err.code() == "invalid_identifier" => {}
        Err(err) => return Err(format!("expected invalid_identifier, got: {err}").into()),
        Ok(_) => return Err("expected error, got Ok".into()),
    }

    // 2. Empty anchor site lineage rejected
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: LedgerAnchor::genesis(""),
        generation: Generation(1),
        statement: "Valid statement".to_string(),
        provenance: ProvenanceClass::Observed,
        source_bytes_digest: Some(source_digest),
        continuity_witness: None,
        retention_forbidden_reason: None,
    });
    match res {
        Err(err) if err.code() == "invalid_identifier" => {}
        Err(err) => return Err(format!("expected invalid_identifier, got: {err}").into()),
        Ok(_) => return Err("expected error, got Ok".into()),
    }

    // 3. Zero generation rejected
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(0),
        statement: "Valid statement".to_string(),
        provenance: ProvenanceClass::Observed,
        source_bytes_digest: Some(source_digest),
        continuity_witness: None,
        retention_forbidden_reason: None,
    });
    match res {
        Err(err) if err.code() == "generation_conflict" => {}
        Err(err) => return Err(format!("expected generation_conflict, got: {err}").into()),
        Ok(_) => return Err("expected error, got Ok".into()),
    }

    // 4. Empty statement rejected
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "".to_string(),
        provenance: ProvenanceClass::Observed,
        source_bytes_digest: Some(source_digest),
        continuity_witness: None,
        retention_forbidden_reason: None,
    });
    match res {
        Err(err) if err.code() == "invalid_identifier" => {}
        Err(err) => return Err(format!("expected invalid_identifier, got: {err}").into()),
        Ok(_) => return Err("expected error, got Ok".into()),
    }

    // 5. INV-003 violation: neither source bytes nor retention reason
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Missing both source and retention exemption".to_string(),
        provenance: ProvenanceClass::Observed,
        source_bytes_digest: None,
        continuity_witness: None,
        retention_forbidden_reason: None,
    });
    match res {
        Err(err) if err.code() == "evidence_required" => {}
        Err(err) => return Err(format!("expected evidence_required, got: {err}").into()),
        Ok(_) => return Err("expected error, got Ok".into()),
    }

    // 6. Prohibited promotion: decoded frame in statement
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Decoded frame RGB pixels from camera".to_string(),
        provenance: ProvenanceClass::Observed,
        source_bytes_digest: Some(source_digest),
        continuity_witness: None,
        retention_forbidden_reason: None,
    });
    match res {
        Err(err) if err.code() == "prohibited_evidence_promotion" => {}
        Err(err) => {
            return Err(format!("expected prohibited_evidence_promotion, got: {err}").into());
        }
        Ok(_) => return Err("expected error, got Ok".into()),
    }

    // 7. Prohibited promotion: model output in statement
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Model output detections".to_string(),
        provenance: ProvenanceClass::Observed,
        source_bytes_digest: Some(source_digest),
        continuity_witness: None,
        retention_forbidden_reason: None,
    });
    match res {
        Err(err) if err.code() == "prohibited_evidence_promotion" => {}
        Err(err) => {
            return Err(format!("expected prohibited_evidence_promotion, got: {err}").into());
        }
        Ok(_) => return Err("expected error, got Ok".into()),
    }

    // 8. Prohibited promotion: VLM inference in statement
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "VLM inference summary of scene".to_string(),
        provenance: ProvenanceClass::Observed,
        source_bytes_digest: Some(source_digest),
        continuity_witness: None,
        retention_forbidden_reason: None,
    });
    match res {
        Err(err) if err.code() == "prohibited_evidence_promotion" => {}
        Err(err) => {
            return Err(format!("expected prohibited_evidence_promotion, got: {err}").into());
        }
        Ok(_) => return Err("expected error, got Ok".into()),
    }

    // 9. Prohibited promotion: non-Observed provenance (Derived)
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Valid statement".to_string(),
        provenance: ProvenanceClass::Derived,
        source_bytes_digest: Some(source_digest),
        continuity_witness: None,
        retention_forbidden_reason: None,
    });
    match res {
        Err(err) if err.code() == "prohibited_evidence_promotion" => {}
        Err(err) => {
            return Err(format!("expected prohibited_evidence_promotion, got: {err}").into());
        }
        Ok(_) => return Err("expected error, got Ok".into()),
    }

    // 10. Prohibited promotion: non-Observed provenance (Predicted)
    let res = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:001".to_string(),
        anchor: anchor.clone(),
        generation: Generation(1),
        statement: "Valid statement".to_string(),
        provenance: ProvenanceClass::Predicted,
        source_bytes_digest: Some(source_digest),
        continuity_witness: None,
        retention_forbidden_reason: None,
    });
    match res {
        Err(err) if err.code() == "prohibited_evidence_promotion" => {}
        Err(err) => {
            return Err(format!("expected prohibited_evidence_promotion, got: {err}").into());
        }
        Ok(_) => return Err("expected error, got Ok".into()),
    }

    Ok(())
}

#[test]
fn test_source_evidence_canonical_roundtrip() -> Result<(), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("camera.sensor.dock_bay");
    let source_digest = ContentDigest::sha256(b"dock-bay-payload-bytes");
    let continuity_digest = ContentDigest::sha256(b"dock-bay-continuity");

    let record = SourceEvidenceRecord::new(SourceEvidenceParams {
        evidence_id: "source:packet:dock_bay:0128".to_string(),
        anchor,
        generation: Generation(3),
        statement: "Dock bay source packets with continuity witness".to_string(),
        provenance: ProvenanceClass::Observed,
        source_bytes_digest: Some(source_digest),
        continuity_witness: Some(continuity_digest),
        retention_forbidden_reason: None,
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
    assert_eq!(decoded.source_bytes_digest, record.source_bytes_digest);
    assert_eq!(decoded.continuity_witness, record.continuity_witness);
    assert_eq!(
        decoded.retention_forbidden_reason,
        record.retention_forbidden_reason
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
