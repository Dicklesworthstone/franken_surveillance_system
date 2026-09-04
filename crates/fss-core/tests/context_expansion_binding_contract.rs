#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use fss_core::hydration::{
    HandleAvailability, HydrationError, HydrationLevel, LaboratoryAccess, SemanticHandle,
    SemanticHandleSpec,
};
use fss_core::{
    BudgetVector, Completeness, CompressionCompleteness, CompressionLossClass,
    CompressionStopReason, CompressionTransform, CompressionTransformKind, ContentDigest,
    ContextBindingError, ContextExpansionBinding, ContextExpansionBindingSet, ContextItem,
    ContractBasis, ContractError, CriticalPreservation, ExpansionHandle, KnowledgeState,
    LedgerAnchor, MissionId, SemanticCompressionReceipt, SemanticContextPack, SessionId,
    TimestampNs,
};

fn basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(
        b"schemas",
        b"operations",
        b"views",
        b"capabilities",
        b"errors",
        b"costs",
        "fss:test",
        None,
    )
}

fn anchor(sequence: u64) -> LedgerAnchor {
    let mut anchor = LedgerAnchor::genesis("site:context-binding");
    anchor.commit_sequence = sequence;
    anchor
}

fn handle(subject: &str, sequence: u64) -> Result<SemanticHandle, HydrationError> {
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
                latency_ms: 25,
                tokens: 128,
                bytes: 1_024,
                cpu_millis: 5,
                storage_operations: 1,
                privacy_exposure: 0.1,
                ..BudgetVector::default()
            },
        ),
    ]);
    SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: basis(),
        anchor: anchor(sequence),
        subject_id: format!("context-subject:{subject}"),
        subject_digest: ContentDigest::sha256(subject.as_bytes()),
        semantic_type: "semantic_context_expansion".to_owned(),
        source_id: "context-pack:test".to_owned(),
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

fn pack_and_receipt() -> Result<(SemanticContextPack, SemanticCompressionReceipt), ContractError> {
    let pack = SemanticContextPack::publish(
        "context-pack:test",
        basis(),
        MissionId::parse("mission:context-binding")?,
        SessionId::parse("session:context-binding")?,
        "AVIEW-001",
        anchor(0),
        ContentDigest::sha256(b"situation-frame"),
        vec![ContextItem {
            item_id: "context:knowledge:selected".to_owned(),
            kind: "knowledge".to_owned(),
            epistemic_state: KnowledgeState::Known,
            content: "A bounded selected context item.".to_owned(),
            basis: BTreeSet::from(["claim:selected".to_owned()]),
            expansion_handles: BTreeSet::from(["slot:item:evidence".to_owned()]),
        }],
        "compression:context-binding",
        Some("continuation:context-binding".to_owned()),
        TimestampNs(2),
    )?;
    let receipt = SemanticCompressionReceipt {
        receipt_id: "compression:context-binding".to_owned(),
        source_anchor: pack.anchor.clone(),
        view_id: pack.view_id.clone(),
        target_tokens: pack.token_count + 1_024,
        selected_classes: BTreeSet::from(["knowledge".to_owned()]),
        omitted_classes: BTreeSet::from(["knowledge".to_owned()]),
        transforms: vec![CompressionTransform {
            kind: CompressionTransformKind::Select,
            scope: "knowledge".to_owned(),
            loss_class: CompressionLossClass::BoundedLoss,
            details: Some("one optional knowledge item remains hydratable".to_owned()),
        }],
        completeness: vec![CompressionCompleteness {
            domain: "knowledge".to_owned(),
            state: Completeness::Bounded,
            omitted_count: 1,
        }],
        critical_preservation: CriticalPreservation {
            known_critical_items: 0,
            omitted_critical_items: 0,
            omitted_invalidations: 0,
            omitted_contradictions: 0,
        },
        actual_tokens: pack.token_count,
        actual_bytes: pack.encoded_bytes(),
        expansion_handles: vec![ExpansionHandle {
            handle: "slot:receipt:knowledge".to_owned(),
            purpose: "Hydrate omitted knowledge context.".to_owned(),
            estimated_cost: BudgetVector {
                tokens: 128,
                bytes: 1_024,
                ..BudgetVector::default()
            },
        }],
        selection_frontier_digest: Some(ContentDigest::sha256(b"selection-frontier")),
        stop_reason: CompressionStopReason::TargetBudget,
        output_digest: pack.pack_digest,
    };
    receipt.validate_for(&pack)?;
    Ok((pack, receipt))
}

#[test]
fn exact_slot_bindings_validate_against_descriptor_catalog() -> Result<(), Box<dyn Error>> {
    let (pack, receipt) = pack_and_receipt()?;
    let item_handle = handle("item-evidence", 0)?;
    let receipt_handle = handle("omitted-knowledge", 0)?;
    let bindings = vec![
        ContextExpansionBinding::publish(
            "slot:item:evidence",
            &item_handle,
            HydrationLevel::H1,
            "Hydrate the selected item's exact evidence synopsis.",
        )?,
        ContextExpansionBinding::publish(
            "slot:receipt:knowledge",
            &receipt_handle,
            HydrationLevel::H1,
            "Hydrate the omitted knowledge class.",
        )?,
    ];
    let binding_set = ContextExpansionBindingSet::publish(&pack, &receipt, bindings)?;
    binding_set.validate_catalog(
        &pack,
        &receipt,
        &[item_handle.clone(), receipt_handle.clone()],
    )?;
    assert_eq!(
        binding_set
            .binding_for_slot("slot:item:evidence")
            .ok_or(ContractError::NotFound)?
            .reference
            .descriptor_digest,
        item_handle.descriptor_digest
    );
    Ok(())
}

#[test]
fn missing_and_unexpected_slots_fail_closed() -> Result<(), Box<dyn Error>> {
    let (pack, receipt) = pack_and_receipt()?;
    let item_handle = handle("item-evidence", 0)?;
    let only_binding = ContextExpansionBinding::publish(
        "slot:item:evidence",
        &item_handle,
        HydrationLevel::H1,
        "Hydrate item evidence.",
    )?;
    assert!(matches!(
        ContextExpansionBindingSet::publish(&pack, &receipt, vec![only_binding]),
        Err(ContextBindingError::MissingSlot(slot)) if slot == "slot:receipt:knowledge"
    ));

    let receipt_handle = handle("omitted-knowledge", 0)?;
    let extra_handle = handle("unexpected", 0)?;
    let bindings = vec![
        ContextExpansionBinding::publish(
            "slot:item:evidence",
            &item_handle,
            HydrationLevel::H1,
            "Hydrate item evidence.",
        )?,
        ContextExpansionBinding::publish(
            "slot:receipt:knowledge",
            &receipt_handle,
            HydrationLevel::H1,
            "Hydrate omitted knowledge.",
        )?,
        ContextExpansionBinding::publish(
            "slot:unexpected",
            &extra_handle,
            HydrationLevel::H1,
            "This slot was never emitted.",
        )?,
    ];
    assert!(matches!(
        ContextExpansionBindingSet::publish(&pack, &receipt, bindings),
        Err(ContextBindingError::UnexpectedSlot(slot)) if slot == "slot:unexpected"
    ));
    Ok(())
}

#[test]
fn future_descriptor_and_descriptor_substitution_are_rejected() -> Result<(), Box<dyn Error>> {
    let (pack, receipt) = pack_and_receipt()?;
    let future = handle("item-evidence", 1)?;
    let current = handle("omitted-knowledge", 0)?;
    let future_bindings = vec![
        ContextExpansionBinding::publish(
            "slot:item:evidence",
            &future,
            HydrationLevel::H1,
            "Future descriptor.",
        )?,
        ContextExpansionBinding::publish(
            "slot:receipt:knowledge",
            &current,
            HydrationLevel::H1,
            "Current descriptor.",
        )?,
    ];
    assert!(matches!(
        ContextExpansionBindingSet::publish(&pack, &receipt, future_bindings),
        Err(ContextBindingError::Contract(ContractError::StaleAnchor))
    ));

    let exact = handle("item-evidence", 0)?;
    let exact_binding = ContextExpansionBinding::publish(
        "slot:item:evidence",
        &exact,
        HydrationLevel::H1,
        "Exact descriptor.",
    )?;
    let receipt_binding = ContextExpansionBinding::publish(
        "slot:receipt:knowledge",
        &current,
        HydrationLevel::H1,
        "Current descriptor.",
    )?;
    let binding_set =
        ContextExpansionBindingSet::publish(&pack, &receipt, vec![exact_binding, receipt_binding])?;
    let substituted = handle("item-evidence", 1)?;
    assert!(matches!(
        binding_set.validate_catalog(&pack, &receipt, &[substituted, current]),
        Err(ContextBindingError::Hydration(
            HydrationError::DescriptorNotFound
        ))
    ));
    Ok(())
}

#[test]
fn descriptor_price_cannot_be_rewritten_by_the_context_surface() -> Result<(), Box<dyn Error>> {
    let (pack, receipt) = pack_and_receipt()?;
    let item_handle = handle("item-evidence", 0)?;
    let receipt_handle = handle("omitted-knowledge", 0)?;
    let mut tampered = ContextExpansionBinding::publish(
        "slot:item:evidence",
        &item_handle,
        HydrationLevel::H1,
        "Hydrate item evidence.",
    )?;
    tampered.estimated_cost.tokens += 1;
    tampered.binding_digest = tampered.computed_digest();
    let binding_set = ContextExpansionBindingSet::publish(
        &pack,
        &receipt,
        vec![
            tampered,
            ContextExpansionBinding::publish(
                "slot:receipt:knowledge",
                &receipt_handle,
                HydrationLevel::H1,
                "Hydrate omitted knowledge.",
            )?,
        ],
    )?;
    assert!(matches!(
        binding_set.validate_catalog(&pack, &receipt, &[item_handle, receipt_handle]),
        Err(ContextBindingError::Contract(ContractError::DigestMismatch))
    ));
    Ok(())
}
