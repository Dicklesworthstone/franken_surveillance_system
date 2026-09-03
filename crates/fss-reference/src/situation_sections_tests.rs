use std::collections::BTreeSet;
use std::error::Error;

use fss_core::{
    ActionAffordance, AffordanceClass, BudgetVector, Completeness, ContentDigest, ContractBasis,
    ContractError, HandoffId, KnowledgeCell, KnowledgeState, LedgerAnchor, MissionId, ObligationId,
    PrincipalId, ProvenanceClass, ResourcePressure, SessionId, SituationCapsule, SituationFrame,
    TimestampNs, WorldEnvelope,
};

use crate::{
    ReferenceError, ReferenceProjectionSpec, ReferenceSituation, project_reference_situation,
    seal_reference_publication_handoff,
};

fn basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(
        b"schemas",
        b"operations",
        b"views",
        b"capabilities",
        b"errors",
        b"costs",
        "fss-reference:test",
        Some("nightly-2026-08-31".to_owned()),
    )
}

fn situation(long_optional_why: bool) -> Result<ReferenceSituation, ContractError> {
    let anchor = LedgerAnchor::genesis("site:situation-sections");
    let evidence = ContentDigest::sha256(b"retained-evidence");
    let world = fss_core::PossibleWorld {
        world_id: "world:protected".to_owned(),
        description: "A protected high-loss world remains live.".to_owned(),
        claim_ids: BTreeSet::from(["claim:presence".to_owned()]),
        evidence: vec![evidence],
        consequence_severity: 5,
        protected: true,
    };
    let envelope = WorldEnvelope {
        envelope_id: "world-envelope:sections".to_owned(),
        objective_id: "objective:sections".to_owned(),
        anchor: anchor.clone(),
        nominal_claim_ids: BTreeSet::from(["claim:presence".to_owned()]),
        certified_core_claim_ids: BTreeSet::new(),
        alternatives: vec![world],
        adversarial_residuals: Vec::new(),
        common_invariants: BTreeSet::from(["invariant:no-blind-effect".to_owned()]),
        coverage_boundary_handles: BTreeSet::from(["fss://coverage/sections".to_owned()]),
    };
    let retained_worlds = envelope.world_ids();
    let affordance = ActionAffordance {
        affordance_id: "affordance:investigate".to_owned(),
        operation: "investigate".to_owned(),
        target: "fss://event/sections/evidence".to_owned(),
        rationale: "Acquire independent evidence.".to_owned(),
        class: AffordanceClass::Probe,
        supported_worlds: retained_worlds,
        unsafe_worlds: BTreeSet::new(),
        required_capabilities: BTreeSet::from(["capability:evidence.query".to_owned()]),
        cost: BudgetVector {
            latency_ms: 100,
            tokens: 10,
            bytes: 128,
            cpu_millis: 5,
            accelerator_millis: 2,
            energy_millijoules: 7,
            privacy_exposure: 0.1,
            ..BudgetVector::default()
        },
        reversible: true,
        branch_predicate: None,
    };
    let known = KnowledgeCell {
        claim_id: "claim:policy".to_owned(),
        statement: "Policy currently withholds an effect.".to_owned(),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![evidence],
        contradictions: Vec::new(),
        valid_until: None,
    };
    let conflicted = KnowledgeCell {
        claim_id: "claim:presence".to_owned(),
        statement: "Presence remains conflicted.".to_owned(),
        knowledge_state: KnowledgeState::Conflicted,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![evidence],
        contradictions: vec![ContentDigest::sha256(b"contradiction")],
        valid_until: None,
    };
    let why = if long_optional_why {
        vec!["optional explanatory detail ".repeat(400)]
    } else {
        vec!["Two retained interpretations remain decision-relevant.".to_owned()]
    };
    let frame = SituationFrame {
        frame_id: "frame:sections".to_owned(),
        objective_id: "objective:sections".to_owned(),
        anchor: anchor.clone(),
        world_envelope: envelope,
        knowledge_cells: vec![known, conflicted],
        now: vec!["A candidate event is under investigation.".to_owned()],
        changed: vec!["A contradictory observation arrived.".to_owned()],
        why,
        unknown: vec!["Independent corroboration is still absent.".to_owned()],
        at_risk: vec!["An irreversible alert must remain blocked.".to_owned()],
        next: vec!["affordance:investigate".to_owned()],
        evidence_handles: BTreeSet::from([format!("fss://proof/{evidence}")]),
    };
    let capsule = SituationCapsule {
        capsule_id: "situation:sections".to_owned(),
        revision: 1,
        contract_basis: basis(),
        mission_id: MissionId::parse("mission:sections")?,
        session_id: SessionId::parse("session:sections")?,
        principal_id: PrincipalId::parse("principal:sections")?,
        anchor,
        previous_anchor: None,
        frame,
        obligations: vec![ObligationId::parse("obligation:sections")?],
        affordances: vec![affordance],
        completeness: Completeness::Partial,
        created_at: TimestampNs(1_000),
    };
    capsule.validate()?;
    Ok(ReferenceSituation {
        capsule,
        proof_roots: BTreeSet::from([evidence]),
    })
}

fn spec(target_tokens: u64) -> ReferenceProjectionSpec {
    ReferenceProjectionSpec {
        view_id: "AVIEW-001".to_owned(),
        available_resources: BudgetVector {
            latency_ms: 10_000,
            tokens: 20_000,
            bytes: 1_000_000,
            model_calls: 10,
            cpu_millis: 10_000,
            accelerator_millis: 10_000,
            energy_millijoules: 1_000_000,
            network_bytes: 1_000_000,
            storage_operations: 10_000,
            privacy_exposure: 10.0,
            operator_attention_seconds: 1_000.0,
        },
        reserved_resources: BudgetVector {
            latency_ms: 100,
            tokens: 100,
            bytes: 1_000,
            storage_operations: 1,
            ..BudgetVector::default()
        },
        pressure: ResourcePressure::Elevated,
        degraded_dimensions: BTreeSet::from(["model_calls".to_owned()]),
        target_tokens,
    }
}

#[test]
fn complete_sections_are_deterministic_and_cross_verified() -> Result<(), Box<dyn Error>> {
    let first = project_reference_situation(situation(false)?, &spec(10_000))?;
    let second = project_reference_situation(situation(false)?, &spec(10_000))?;

    assert_eq!(first, second);
    assert_eq!(first.verify()?, first.publication_digest);
    assert_eq!(first.resource_state.pressure, ResourcePressure::Elevated);
    assert_eq!(
        first.control_envelope.information_gathering_affordance_ids,
        BTreeSet::from(["affordance:investigate".to_owned()])
    );
    assert_eq!(
        first.compression_receipt.stop_reason,
        fss_core::CompressionStopReason::Complete
    );
    assert!(
        first
            .context_pack
            .items
            .iter()
            .any(|item| item.item_id == "context:obligation:obligation:sections")
    );
    assert!(
        first
            .context_pack
            .items
            .iter()
            .any(|item| item.item_id == "context:world:world:protected")
    );
    Ok(())
}

#[test]
fn hard_budget_cannot_omit_critical_semantics() -> Result<(), Box<dyn Error>> {
    assert!(matches!(
        project_reference_situation(situation(false)?, &spec(1)),
        Err(ReferenceError::Contract(ContractError::BudgetExhausted))
    ));
    Ok(())
}

#[test]
fn optional_omission_is_receipted_and_hydratable() -> Result<(), Box<dyn Error>> {
    let publication = project_reference_situation(situation(true)?, &spec(2_000))?;

    assert!(publication.compression_receipt.omitted_classes.contains("why"));
    assert!(
        publication
            .compression_receipt
            .critical_preservation
            .is_lossless()
    );
    assert!(
        !publication
            .compression_receipt
            .expansion_handles
            .is_empty()
    );
    assert!(publication.context_pack.continuation.is_some());
    assert!(
        publication
            .context_pack
            .items
            .iter()
            .any(|item| item.kind == "contradiction")
    );
    assert!(
        publication
            .context_pack
            .items
            .iter()
            .any(|item| item.kind == "protected_world")
    );
    publication.verify()?;
    Ok(())
}

#[test]
fn handoff_root_covers_the_complete_publication() -> Result<(), Box<dyn Error>> {
    let publication = project_reference_situation(situation(false)?, &spec(10_000))?;
    let handoff = seal_reference_publication_handoff(
        &publication,
        HandoffId::parse("handoff:sections")?,
        TimestampNs(2_000),
        TimestampNs(3_000),
    )?;

    assert_eq!(
        handoff.situation_capsule_root,
        publication.publication_digest
    );
    assert!(handoff.child_roots.contains(&publication.context_pack.pack_digest));
    assert!(
        handoff
            .child_roots
            .contains(&publication.compression_receipt.receipt_digest())
    );
    handoff.verify()?;
    Ok(())
}
