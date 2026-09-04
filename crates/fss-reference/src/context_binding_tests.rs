use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use fss_core::hydration::{
    HandleAvailability, HydrationLevel, LaboratoryAccess, SemanticHandle, SemanticHandleSpec,
};
use fss_core::{
    ActionAffordance, AffordanceClass, BudgetVector, Completeness, ContentDigest,
    ContextBindingError, ContextExpansionBindingSet, ContractBasis, ContractError, HandoffId,
    KnowledgeCell, KnowledgeState, LedgerAnchor, MissionId, ObligationId, PrincipalId,
    ProvenanceClass, ResourcePressure, SessionId, SituationCapsule, SituationFrame, TimestampNs,
    WorldEnvelope,
};

use crate::{
    BoundReferenceSituationPublication, ReferenceContextBindingError, ReferenceExpansionBindingSpec,
    ReferenceProjectionSpec, ReferenceSituation, project_reference_situation,
    seal_bound_reference_publication_handoff,
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

fn situation() -> Result<ReferenceSituation, ContractError> {
    let anchor = LedgerAnchor::genesis("site:bound-context");
    let evidence = ContentDigest::sha256(b"bound-context-evidence");
    let envelope = WorldEnvelope {
        envelope_id: "world-envelope:bound-context".to_owned(),
        objective_id: "objective:bound-context".to_owned(),
        anchor: anchor.clone(),
        nominal_claim_ids: BTreeSet::from(["claim:presence".to_owned()]),
        certified_core_claim_ids: BTreeSet::new(),
        alternatives: vec![fss_core::PossibleWorld {
            world_id: "world:bound-context:protected".to_owned(),
            description: "A protected high-loss world remains live.".to_owned(),
            claim_ids: BTreeSet::from(["claim:presence".to_owned()]),
            evidence: vec![evidence],
            consequence_severity: 5,
            protected: true,
        }],
        adversarial_residuals: Vec::new(),
        common_invariants: BTreeSet::from(["invariant:no-blind-effect".to_owned()]),
        coverage_boundary_handles: BTreeSet::from(["fss://coverage/bound-context".to_owned()]),
    };
    let affordance = ActionAffordance {
        affordance_id: "affordance:bound-context:investigate".to_owned(),
        operation: "investigate".to_owned(),
        target: "fss://event/bound-context/evidence".to_owned(),
        rationale: "Acquire independent evidence.".to_owned(),
        class: AffordanceClass::Probe,
        supported_worlds: envelope.world_ids(),
        unsafe_worlds: BTreeSet::new(),
        required_capabilities: BTreeSet::from(["capability:evidence.query".to_owned()]),
        cost: BudgetVector {
            latency_ms: 100,
            tokens: 10,
            bytes: 128,
            cpu_millis: 5,
            privacy_exposure: 0.1,
            ..BudgetVector::default()
        },
        reversible: true,
        branch_predicate: None,
    };
    let frame = SituationFrame {
        frame_id: "frame:bound-context".to_owned(),
        objective_id: "objective:bound-context".to_owned(),
        anchor: anchor.clone(),
        world_envelope: envelope,
        knowledge_cells: vec![KnowledgeCell {
            claim_id: "claim:presence".to_owned(),
            statement: "Presence remains unresolved.".to_owned(),
            knowledge_state: KnowledgeState::Conflicted,
            provenance: ProvenanceClass::Derived,
            hypothesis: None,
            evidence: vec![evidence],
            contradictions: vec![ContentDigest::sha256(b"bound-context-contradiction")],
            valid_until: None,
        }],
        now: vec!["A candidate event remains under investigation.".to_owned()],
        changed: vec!["A contradictory observation arrived.".to_owned()],
        why: vec!["optional explanatory detail ".repeat(400)],
        unknown: vec!["Independent corroboration is absent.".to_owned()],
        at_risk: vec!["An irreversible alert remains blocked.".to_owned()],
        next: vec!["affordance:bound-context:investigate".to_owned()],
        evidence_handles: BTreeSet::from([format!("fss://proof/{evidence}")]),
    };
    let capsule = SituationCapsule {
        capsule_id: "situation:bound-context".to_owned(),
        revision: 1,
        contract_basis: basis(),
        mission_id: MissionId::parse("mission:bound-context")?,
        session_id: SessionId::parse("session:bound-context")?,
        principal_id: PrincipalId::parse("principal:bound-context")?,
        anchor,
        previous_anchor: None,
        frame,
        obligations: vec![ObligationId::parse("obligation:bound-context")?],
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

fn projection_spec() -> ReferenceProjectionSpec {
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
        target_tokens: 2_000,
    }
}

fn descriptor_for_slot(
    slot_id: &str,
    contract_basis: &ContractBasis,
    anchor: &LedgerAnchor,
) -> Result<SemanticHandle, fss_core::hydration::HydrationError> {
    let levels = BTreeSet::from([HydrationLevel::H0, HydrationLevel::H1]);
    let required_capabilities = BTreeMap::from([
        (
            HydrationLevel::H0,
            BTreeSet::from(["capability:hydrate:H0".to_owned()]),
        ),
        (
            HydrationLevel::H1,
            BTreeSet::from(["capability:hydrate:H1".to_owned()]),
        ),
    ]);
    let estimated_costs = BTreeMap::from([
        (
            HydrationLevel::H0,
            BudgetVector {
                latency_ms: 10,
                tokens: 32,
                bytes: 256,
                storage_operations: 1,
                ..BudgetVector::default()
            },
        ),
        (
            HydrationLevel::H1,
            BudgetVector {
                latency_ms: 100,
                tokens: 1_024,
                bytes: 16_384,
                cpu_millis: 10,
                storage_operations: 1,
                privacy_exposure: 0.1,
                ..BudgetVector::default()
            },
        ),
    ]);
    SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: contract_basis.clone(),
        anchor: anchor.clone(),
        subject_id: format!("context-expansion-subject:{slot_id}"),
        subject_digest: ContentDigest::sha256(slot_id.as_bytes()),
        semantic_type: "semantic_context_expansion".to_owned(),
        source_id: "context-pack:bound-context".to_owned(),
        capture_interval: None,
        spatial_scope: None,
        privacy_class: "private:property".to_owned(),
        applied_transform: Some("decision_preserving_summary".to_owned()),
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(10_000),
        levels,
        required_capabilities,
        estimated_costs,
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })
}

fn binding_specs(
    publication: &crate::ReferenceSituationPublication,
) -> Result<Vec<ReferenceExpansionBindingSpec>, fss_core::hydration::HydrationError> {
    ContextExpansionBindingSet::required_slots(
        &publication.context_pack,
        &publication.compression_receipt,
    )
    .into_iter()
    .map(|slot_id| {
        let descriptor = descriptor_for_slot(
            &slot_id,
            &publication.context_pack.contract_basis,
            &publication.context_pack.anchor,
        )?;
        Ok(ReferenceExpansionBindingSpec {
            purpose: format!("Hydrate exact optional context for {slot_id}."),
            slot_id,
            descriptor,
            hydration_level: HydrationLevel::H1,
        })
    })
    .collect()
}

#[test]
fn bound_reference_publication_is_self_contained_and_handoff_rooted()
-> Result<(), Box<dyn Error>> {
    let publication = project_reference_situation(situation()?, &projection_spec())?;
    assert!(!publication.compression_receipt.expansion_handles.is_empty());
    let bound = BoundReferenceSituationPublication::publish(
        publication,
        binding_specs(&project_reference_situation(situation()?, &projection_spec())?)?,
    )?;

    assert_eq!(bound.verify()?, bound.bound_publication_digest);
    assert_eq!(
        bound.descriptors.len(),
        bound.expansion_bindings.bindings.len()
    );
    let handoff = seal_bound_reference_publication_handoff(
        &bound,
        HandoffId::parse("handoff:bound-context")?,
        TimestampNs(2_000),
        TimestampNs(3_000),
    )?;
    assert_eq!(
        handoff.situation_capsule_root,
        bound.bound_publication_digest
    );
    assert!(
        handoff
            .child_roots
            .contains(&bound.expansion_bindings.binding_set_digest)
    );
    for descriptor in &bound.descriptors {
        assert!(handoff.child_roots.contains(&descriptor.descriptor_digest));
        assert!(handoff.child_roots.contains(&descriptor.subject_digest));
    }
    handoff.verify()?;
    Ok(())
}

#[test]
fn incomplete_binding_specs_fail_closed() -> Result<(), Box<dyn Error>> {
    let publication = project_reference_situation(situation()?, &projection_spec())?;
    let mut specs = binding_specs(&publication)?;
    let omitted = specs.pop().ok_or(ContractError::NotFound)?;
    assert!(matches!(
        BoundReferenceSituationPublication::publish(publication, specs),
        Err(ReferenceContextBindingError::Binding(
            ContextBindingError::MissingSlot(slot)
        )) if slot == omitted.slot_id
    ));
    Ok(())
}

#[test]
fn unused_ambient_descriptor_is_rejected() -> Result<(), Box<dyn Error>> {
    let publication = project_reference_situation(situation()?, &projection_spec())?;
    let specs = binding_specs(&publication)?;
    let mut bound = BoundReferenceSituationPublication::publish(publication, specs)?;
    bound.descriptors.push(descriptor_for_slot(
        "slot:unused",
        &bound.publication.context_pack.contract_basis,
        &bound.publication.context_pack.anchor,
    )?);
    bound.descriptors.sort_by(|left, right| {
        (&left.handle_id, left.descriptor_digest).cmp(&(&right.handle_id, right.descriptor_digest))
    });
    bound.bound_publication_digest = bound.computed_digest();
    assert!(matches!(
        bound.verify(),
        Err(ReferenceContextBindingError::Binding(
            ContextBindingError::Contract(ContractError::IncompletePublicationGraph)
        ))
    ));
    Ok(())
}
