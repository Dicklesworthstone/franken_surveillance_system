use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use fss_core::hydration::{
    HandleAvailability, HydrationLevel, LaboratoryAccess, SemanticHandle, SemanticHandleSpec,
};
use fss_core::{
    ActionAffordance, AffordanceClass, BudgetVector, Completeness, ContentDigest,
    ContextBindingError, ContextExpansionBindingSet, ContractBasis, ContractBasisRegistryBytes,
    ContractError, HandoffId, KnowledgeCell, KnowledgeCellParams, KnowledgeState, LedgerAnchor,
    MissionId, ObligationId, PrincipalId, ProvenanceClass, ResourcePressure, SessionId,
    SituationCapsule, SituationFrame, TimestampNs, WorldEnvelope,
};

use crate::{
    BoundReferenceSituationPublication, ReferenceContextBindingError,
    ReferenceExpansionBindingSpec, ReferenceProjectionSpec, ReferenceSituation,
    project_reference_situation, seal_bound_reference_publication_handoff,
};

fn basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(
        ContractBasisRegistryBytes::new(
            b"schemas",
            b"operations",
            b"views",
            b"capabilities",
            b"errors",
            b"costs",
            "fss-reference:test",
        )
        .with_accepted_nightly("nightly-2026-08-31"),
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
        cost: BudgetVector::builder()
            .latency_ms(100)
            .tokens(10)
            .bytes(128)
            .cpu_millis(5)
            .privacy_exposure(0.1)
            .build()?,
        reversible: true,
        branch_predicate: None,
    };
    let frame = SituationFrame {
        frame_id: "frame:bound-context".to_owned(),
        objective_id: "objective:bound-context".to_owned(),
        anchor: anchor.clone(),
        world_envelope: envelope,
        knowledge_cells: vec![KnowledgeCell::new(KnowledgeCellParams {
            claim_id: "claim:presence".to_owned(),
            statement: "Presence remains unresolved.".to_owned(),
            knowledge_state: KnowledgeState::Conflicted,
            provenance: ProvenanceClass::Derived,
            hypothesis: None,
            evidence: vec![evidence],
            contradictions: vec![ContentDigest::sha256(b"bound-context-contradiction")],
            valid_until: None,
            state_basis: None,
        })?],
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
        mission_state: None,
    };
    capsule.validate()?;
    Ok(ReferenceSituation::new(capsule, BTreeSet::from([evidence])))
}

/// The fixture sealed as a compile path would seal it: both bound routes need a sealed
/// publication (fss-6sph6).
fn sealed_situation() -> Result<ReferenceSituation, Box<dyn Error>> {
    let mut sealed = situation()?;
    sealed.seal_effect_bindings()?;
    Ok(sealed)
}

fn projection_spec() -> ReferenceProjectionSpec {
    ReferenceProjectionSpec {
        view_id: "AVIEW-001".to_owned(),
        available_resources: BudgetVector::builder()
            .latency_ms(10_000)
            .tokens(20_000)
            .bytes(1_000_000)
            .model_calls(10)
            .cpu_millis(10_000)
            .accelerator_millis(10_000)
            .energy_millijoules(1_000_000)
            .network_bytes(1_000_000)
            .storage_operations(10_000)
            .privacy_exposure(10.0)
            .operator_attention_seconds(1_000.0)
            .build()
            .unwrap_or(BudgetVector::ZERO),
        reserved_resources: BudgetVector::builder()
            .latency_ms(100)
            .tokens(100)
            .bytes(1_000)
            .storage_operations(1)
            .build()
            .unwrap_or(BudgetVector::ZERO),
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
            BudgetVector::builder()
                .latency_ms(10)
                .tokens(32)
                .bytes(256)
                .storage_operations(1)
                .build()
                .unwrap_or(BudgetVector::ZERO),
        ),
        (
            HydrationLevel::H1,
            BudgetVector::builder()
                .latency_ms(100)
                .tokens(1_024)
                .bytes(16_384)
                .cpu_millis(10)
                .storage_operations(1)
                .privacy_exposure(0.1)
                .build()
                .unwrap_or(BudgetVector::ZERO),
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

pub(crate) fn binding_specs(
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
fn bound_reference_publication_is_self_contained_and_handoff_rooted() -> Result<(), Box<dyn Error>>
{
    let publication = project_reference_situation(sealed_situation()?, &projection_spec())?;
    assert!(!publication.compression_receipt.expansion_handles.is_empty());
    let bound = BoundReferenceSituationPublication::publish(
        publication,
        binding_specs(&project_reference_situation(
            sealed_situation()?,
            &projection_spec(),
        )?)?,
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
    let publication = project_reference_situation(sealed_situation()?, &projection_spec())?;
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
    let publication = project_reference_situation(sealed_situation()?, &projection_spec())?;
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

/// A bound publication whose situation capsule still validates, but whose binding fields were
/// altered, yields no proof-root set: `proof_roots` verifies the complete bound publication
/// before rooting anything.
#[test]
fn tampered_bound_publication_yields_no_proof_roots() -> Result<(), Box<dyn Error>> {
    let publication = project_reference_situation(sealed_situation()?, &projection_spec())?;
    let specs = binding_specs(&publication)?;
    let bound = BoundReferenceSituationPublication::publish(publication, specs)?;
    assert!(
        bound
            .proof_roots()?
            .contains(&bound.expansion_bindings.binding_set_digest)
    );

    // Altered bound identity.
    let mut forged_root = bound.clone();
    forged_root.bound_publication_digest = ContentDigest::sha256(b"forged-bound-publication");
    forged_root
        .publication
        .situation
        .capsule
        .decision_fingerprint()?;
    assert!(matches!(
        forged_root.proof_roots(),
        Err(ReferenceContextBindingError::Binding(
            ContextBindingError::Contract(ContractError::DigestMismatch)
        ))
    ));

    // Altered binding-set identity, with the outer bound digest resealed over the forgery.
    let mut forged_binding_set = bound.clone();
    forged_binding_set.expansion_bindings.binding_set_digest =
        ContentDigest::sha256(b"forged-binding-set");
    forged_binding_set.bound_publication_digest = forged_binding_set.computed_digest();
    forged_binding_set
        .publication
        .situation
        .capsule
        .decision_fingerprint()?;
    assert!(matches!(
        forged_binding_set.proof_roots(),
        Err(ReferenceContextBindingError::Binding(
            ContextBindingError::Contract(ContractError::DigestMismatch)
        ))
    ));

    // An ambient descriptor smuggled into the catalog, resealed.
    let mut ambient = bound;
    ambient.descriptors.push(descriptor_for_slot(
        "slot:unused",
        &ambient.publication.context_pack.contract_basis,
        &ambient.publication.context_pack.anchor,
    )?);
    ambient.descriptors.sort_by(|left, right| {
        (&left.handle_id, left.descriptor_digest).cmp(&(&right.handle_id, right.descriptor_digest))
    });
    ambient.bound_publication_digest = ambient.computed_digest();
    ambient
        .publication
        .situation
        .capsule
        .decision_fingerprint()?;
    assert!(matches!(
        ambient.proof_roots(),
        Err(ReferenceContextBindingError::Binding(
            ContextBindingError::Contract(ContractError::IncompletePublicationGraph)
        ))
    ));
    Ok(())
}

mod hydration_delivery {
    use super::*;
    use crate::ReferenceHydrationCatalog;
    use fss_core::hydration::{
        HydrationArtifact, HydrationError, HydrationPurpose, HydrationRequest,
        HydrationRequestSpec, HydrationResponse,
    };

    struct Fixture {
        bound: BoundReferenceSituationPublication,
        slot_id: String,
        descriptor: SemanticHandle,
        catalog: ReferenceHydrationCatalog,
        spec: HydrationRequestSpec,
    }

    impl Fixture {
        fn new() -> Result<Self, Box<dyn Error>> {
            let publication = project_reference_situation(sealed_situation()?, &projection_spec())?;
            let specs = binding_specs(&publication)?;
            let bound = BoundReferenceSituationPublication::publish(publication, specs)?;
            let binding = bound
                .expansion_bindings
                .bindings
                .first()
                .ok_or(ContractError::NotFound)?;
            let slot_id = binding.slot_id.clone();
            let descriptor = bound
                .descriptors
                .iter()
                .find(|descriptor| {
                    descriptor.handle_id == binding.reference.handle_id
                        && descriptor.descriptor_digest == binding.reference.descriptor_digest
                })
                .cloned()
                .ok_or(HydrationError::DescriptorNotFound)?;
            let mut catalog = ReferenceHydrationCatalog::new();
            catalog.register_descriptor(descriptor.clone())?;
            for level in [HydrationLevel::H0, HydrationLevel::H1] {
                let artifact = HydrationArtifact::publish(
                    level,
                    "application/fss+json",
                    format!("exact context {level:?}").into_bytes(),
                    [descriptor.subject_digest],
                    Completeness::Complete,
                    descriptor.applied_transform.clone(),
                )?;
                catalog.register_artifact(
                    &descriptor.handle_id,
                    descriptor.descriptor_digest,
                    artifact,
                )?;
            }
            let spec = HydrationRequestSpec {
                contract_basis: descriptor.contract_basis.clone(),
                session_id: bound.publication.context_pack.session_id.clone(),
                handle_id: descriptor.handle_id.clone(),
                expected_descriptor_digest: descriptor.descriptor_digest,
                expected_subject_digest: descriptor.subject_digest,
                anchor: descriptor.anchor.clone(),
                requested_level: HydrationLevel::H1,
                allow_lower_level: false,
                available_capabilities: descriptor
                    .required_capabilities
                    .values()
                    .flatten()
                    .cloned()
                    .collect(),
                authorized_privacy_classes: BTreeSet::from([descriptor.privacy_class.clone()]),
                budget: descriptor
                    .estimated_cost(HydrationLevel::H1)
                    .ok_or(HydrationError::LevelUnavailable)?,
                purpose: HydrationPurpose::IncidentAdjudication,
                continuation: None,
                issued_at: TimestampNs(2_000),
            };
            Ok(Self {
                bound,
                slot_id,
                descriptor,
                catalog,
                spec,
            })
        }

        fn request(&self) -> Result<HydrationRequest, HydrationError> {
            HydrationRequest::publish(self.spec.clone())
        }

        fn hydrate(
            &mut self,
            now: TimestampNs,
        ) -> Result<HydrationResponse, ReferenceContextBindingError> {
            let request = self.request()?;
            self.catalog
                .hydrate_context_slot(&self.bound, &self.slot_id, &request, now)
        }

        fn h0_budget(&self) -> Result<BudgetVector, HydrationError> {
            self.descriptor
                .estimated_cost(HydrationLevel::H0)
                .ok_or(HydrationError::LevelUnavailable)
        }
    }

    #[test]
    fn context_slot_delivers_verified_artifact_deterministically() -> Result<(), Box<dyn Error>> {
        let mut fixture = Fixture::new()?;
        let request = fixture.request()?;
        let first = fixture.hydrate(TimestampNs(2_000))?;
        let second = fixture.hydrate(TimestampNs(2_000))?;
        assert_eq!(first.receipt, second.receipt);
        assert_eq!(first.artifact, second.artifact);
        assert_eq!(first.receipt.delivered_level, Some(HydrationLevel::H1));
        assert_eq!(first.receipt.completeness, Completeness::Complete);
        assert!(first.artifact.is_some());
        first.validate_for(&request, &fixture.descriptor)?;
        Ok(())
    }

    #[test]
    fn embedded_descriptor_does_not_register_itself_in_catalog() -> Result<(), Box<dyn Error>> {
        let mut fixture = Fixture::new()?;
        fixture.catalog = ReferenceHydrationCatalog::new();
        assert!(matches!(
            fixture.hydrate(TimestampNs(2_000)),
            Err(ReferenceContextBindingError::Binding(
                ContextBindingError::Hydration(HydrationError::DescriptorNotFound)
            ))
        ));
        assert_eq!(fixture.catalog.issued_cursor_count(), 0);
        assert_eq!(fixture.catalog.stored_payload_bytes(), 0);
        Ok(())
    }

    #[test]
    fn another_session_cannot_use_a_valid_bound_publication() -> Result<(), Box<dyn Error>> {
        let mut fixture = Fixture::new()?;
        fixture.spec.session_id = SessionId::parse("session:context-intruder")?;
        fixture.spec.allow_lower_level = true;
        fixture.spec.budget = fixture.h0_budget()?;
        let stored = fixture.catalog.stored_payload_bytes();
        assert!(matches!(
            fixture.hydrate(TimestampNs(2_000)),
            Err(ReferenceContextBindingError::Binding(
                ContextBindingError::Hydration(HydrationError::ContinuationCrossSession)
            ))
        ));
        assert_eq!(fixture.catalog.issued_cursor_count(), 0);
        assert_eq!(fixture.catalog.stored_payload_bytes(), stored);
        Ok(())
    }

    #[test]
    fn unknown_slot_and_resealed_price_forgery_never_deliver() -> Result<(), Box<dyn Error>> {
        let mut fixture = Fixture::new()?;
        let request = fixture.request()?;
        assert!(matches!(
            fixture.catalog.hydrate_context_slot(
                &fixture.bound,
                "slot:missing",
                &request,
                TimestampNs(2_000),
            ),
            Err(ReferenceContextBindingError::Binding(ContextBindingError::MissingSlot(_)))
        ));
        let binding = fixture
            .bound
            .expansion_bindings
            .bindings
            .first_mut()
            .ok_or(ContractError::NotFound)?;
        binding.estimated_cost = BudgetVector::ZERO;
        binding.binding_digest = binding.computed_digest();
        fixture.bound.expansion_bindings.binding_set_digest =
            fixture.bound.expansion_bindings.computed_digest();
        fixture.bound.bound_publication_digest = fixture.bound.computed_digest();
        assert!(fixture.hydrate(TimestampNs(2_000)).is_err());
        assert_eq!(fixture.catalog.issued_cursor_count(), 0);
        Ok(())
    }

    #[test]
    fn newer_catalog_revision_never_retargets_an_old_context() -> Result<(), Box<dyn Error>> {
        let mut fixture = Fixture::new()?;
        let mut anchor = fixture.descriptor.anchor.clone();
        anchor.commit_sequence += 1;
        let newer = descriptor_for_slot(
            &fixture.slot_id,
            &fixture.descriptor.contract_basis,
            &anchor,
        )?;
        fixture.catalog.register_descriptor(newer.clone())?;
        assert!(matches!(
            fixture.hydrate(TimestampNs(2_000)),
            Err(ReferenceContextBindingError::Binding(ContextBindingError::Hydration(
                HydrationError::Contract(ContractError::StaleAnchor)
            )))
        ));
        assert_eq!(
            fixture.catalog.current_descriptor(&fixture.descriptor.handle_id),
            Some(&newer),
        );
        assert_eq!(fixture.catalog.issued_cursor_count(), 0);
        Ok(())
    }

    #[test]
    fn retention_expiry_is_an_explicit_verified_non_delivery() -> Result<(), Box<dyn Error>> {
        let mut fixture = Fixture::new()?;
        let request = fixture.request()?;
        let response = fixture.hydrate(TimestampNs(10_000))?;
        assert!(response.artifact.is_none());
        assert_eq!(response.receipt.availability, HandleAvailability::Expired);
        assert_eq!(response.receipt.cost, BudgetVector::ZERO);
        response.validate_for(&request, &fixture.descriptor)?;
        assert_eq!(fixture.catalog.issued_cursor_count(), 0);
        Ok(())
    }

    #[test]
    fn authority_grants_and_non_token_resource_limits_are_enforced() -> Result<(), Box<dyn Error>> {
        let mut fixture = Fixture::new()?;
        let original = fixture.spec.clone();
        let stored = fixture.catalog.stored_payload_bytes();
        for expected in [
            HydrationError::CapabilityDenied,
            HydrationError::PrivacyDenied,
            HydrationError::BudgetExceeded,
        ] {
            fixture.spec = original.clone();
            match expected {
                HydrationError::CapabilityDenied => fixture.spec.available_capabilities.clear(),
                HydrationError::PrivacyDenied => fixture.spec.authorized_privacy_classes.clear(),
                _ => {
                    // Tokens and bytes are sufficient; latency, CPU, storage and privacy are not.
                    fixture.spec.budget = BudgetVector::builder()
                        .tokens(1_024)
                        .bytes(16_384)
                        .build()?;
                }
            }
            assert!(matches!(
                fixture.hydrate(TimestampNs(2_000)),
                Err(ReferenceContextBindingError::Binding(
                    ContextBindingError::Hydration(error)
                )) if error == expected
            ));
            assert_eq!(fixture.catalog.issued_cursor_count(), 0);
            assert_eq!(fixture.catalog.stored_payload_bytes(), stored);
        }
        Ok(())
    }

    #[test]
    fn lower_level_delivery_requires_explicit_consent() -> Result<(), Box<dyn Error>> {
        let mut fixture = Fixture::new()?;
        fixture.spec.budget = fixture.h0_budget()?;
        assert!(matches!(
            fixture.hydrate(TimestampNs(2_000)),
            Err(ReferenceContextBindingError::Binding(
                ContextBindingError::Hydration(HydrationError::BudgetExceeded)
            ))
        ));
        assert_eq!(fixture.catalog.issued_cursor_count(), 0);
        fixture.spec.allow_lower_level = true;
        let response = fixture.hydrate(TimestampNs(2_000))?;
        assert_eq!(response.receipt.delivered_level, Some(HydrationLevel::H0));
        assert_eq!(response.receipt.completeness, Completeness::Partial);
        assert!(response.receipt.continuation.is_some());
        response.validate_for(&fixture.request()?, &fixture.descriptor)?;
        Ok(())
    }

    #[test]
    fn context_expansion_reuses_exact_single_use_continuation() -> Result<(), Box<dyn Error>> {
        let mut fixture = Fixture::new()?;
        let full_spec = fixture.spec.clone();
        fixture.spec.allow_lower_level = true;
        fixture.spec.budget = fixture.h0_budget()?;
        let first = fixture.hydrate(TimestampNs(2_000))?;
        let cursor = first
            .receipt
            .continuation
            .ok_or(HydrationError::WrongContinuation)?;
        fixture.spec = full_spec;
        fixture.spec.continuation = Some(cursor.clone());
        fixture.spec.session_id = SessionId::parse("session:context-intruder")?;
        assert!(fixture.hydrate(TimestampNs(2_001)).is_err());
        assert!(!fixture
            .catalog
            .issued_cursor(&cursor.cursor_digest)
            .ok_or(HydrationError::ContinuationUnissued)?
            .consumed);
        fixture.spec.session_id = fixture.bound.publication.context_pack.session_id.clone();
        let response = fixture.hydrate(TimestampNs(2_001))?;
        assert_eq!(response.receipt.delivered_level, Some(HydrationLevel::H1));
        response.validate_for(&fixture.request()?, &fixture.descriptor)?;
        assert!(fixture
            .catalog
            .issued_cursor(&cursor.cursor_digest)
            .ok_or(HydrationError::ContinuationUnissued)?
            .consumed);
        assert!(matches!(
            fixture.hydrate(TimestampNs(2_001)),
            Err(ReferenceContextBindingError::Binding(ContextBindingError::Hydration(
                HydrationError::ContinuationAlreadyConsumed
            )))
        ));
        Ok(())
    }
}
