#![forbid(unsafe_code)]
//! Deterministic contract tests for agent abstraction layers:
//! - AGT-LAYER-003: world_facts_and_coverage (INV-063)
//! - AGT-LAYER-004: derived_beliefs (INV-069)

use std::collections::BTreeSet;
use std::error::Error;
use std::str::FromStr;

use fss_core::belief::BeliefInterval;
use fss_core::effect::{Obligation, ObligationState};
use fss_core::region::{
    ContextAuthority, QuiescenceProof, RegionId, RegionKind, RegionState, RootAuthoritySpec,
};
use fss_core::{
    AGENT_ABSTRACTION_FREEZE_DIGEST, AGENT_ABSTRACTION_GENERATION, AgentAbstractionLayer,
    BudgetVector, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    Completeness, ContentDigest, ContractError, CoverageContinuity, CoverageStopReason,
    CoverageWitness, DerivedBelief, DerivedBeliefParams, Generation, KnowledgeState, LedgerAnchor,
    NegativeReadClaim, NegativeReadOutcome, ObligationId, OperationId, Plane, ProvenanceClass,
    RUNTIME_AUTHORITY_DOMAIN, RuntimeAuthorityAndCustody, RuntimeAuthorityAndCustodyRecord,
    RuntimeAuthorityParams, RuntimeAuthorityRecord, RuntimeGrant, SourceCustody,
    SourceEvidenceParams, SourceEvidenceRecord, TimestampNs, WorldFact, WorldFactKind,
    evaluate_negative_read,
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
    encoder.digest(ContentDigest::new(
        fss_core::DigestAlgorithm::Sha256,
        [0u8; 32],
    )); // zero digest!
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
        storage_handle: "storage:handle:raw:001".to_string(),
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
        storage_handle: "storage:handle:raw:001".to_string(),
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
        Err(ContractError::UnknownEntryTag(99))
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
