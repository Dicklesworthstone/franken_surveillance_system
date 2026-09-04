#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use fss_core::hydration::{
    HandleAvailability, HydrationLevel, LaboratoryAccess, SemanticHandle, SemanticHandleSpec,
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

fn exact_cost() -> BudgetVector {
    BudgetVector {
        latency_ms: 25,
        tokens: 128,
        bytes: 1_024,
        cpu_millis: 5,
        storage_operations: 1,
        privacy_exposure: 0.1,
        ..BudgetVector::default()
    }
}

fn descriptor(anchor: &LedgerAnchor) -> Result<SemanticHandle, Box<dyn Error>> {
    Ok(SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: basis(),
        anchor: anchor.clone(),
        subject_id: "context-subject:omitted-knowledge".to_owned(),
        subject_digest: ContentDigest::sha256(b"omitted-knowledge"),
        semantic_type: "semantic_context_expansion".to_owned(),
        source_id: "context-pack:metadata".to_owned(),
        capture_interval: None,
        spatial_scope: None,
        privacy_class: "private:property".to_owned(),
        applied_transform: Some("decision_preserving_summary".to_owned()),
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(10_000),
        levels: BTreeSet::from([HydrationLevel::H0, HydrationLevel::H1]),
        required_capabilities: BTreeMap::from([
            (HydrationLevel::H0, BTreeSet::new()),
            (
                HydrationLevel::H1,
                BTreeSet::from(["capability:hydrate:H1".to_owned()]),
            ),
        ]),
        estimated_costs: BTreeMap::from([
            (HydrationLevel::H0, BudgetVector::default()),
            (HydrationLevel::H1, exact_cost()),
        ]),
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })?)
}

fn pack_and_receipt(
) -> Result<(SemanticContextPack, SemanticCompressionReceipt), Box<dyn Error>> {
    let anchor = LedgerAnchor::genesis("site:context-metadata");
    let pack = SemanticContextPack::publish(
        "context-pack:metadata",
        basis(),
        MissionId::parse("mission:context-metadata")?,
        SessionId::parse("session:context-metadata")?,
        "AVIEW-001",
        anchor,
        ContentDigest::sha256(b"situation-frame"),
        vec![ContextItem {
            item_id: "context:knowledge:selected".to_owned(),
            kind: "knowledge".to_owned(),
            epistemic_state: KnowledgeState::Known,
            content: "Selected context.".to_owned(),
            basis: BTreeSet::from(["claim:selected".to_owned()]),
            expansion_handles: BTreeSet::new(),
        }],
        "compression:context-metadata",
        Some("continuation:context-metadata".to_owned()),
        TimestampNs(2),
    )?;
    let receipt = SemanticCompressionReceipt {
        receipt_id: "compression:context-metadata".to_owned(),
        source_anchor: pack.anchor.clone(),
        view_id: pack.view_id.clone(),
        target_tokens: pack.token_count + 128,
        selected_classes: BTreeSet::from(["knowledge".to_owned()]),
        omitted_classes: BTreeSet::from(["knowledge".to_owned()]),
        transforms: vec![CompressionTransform {
            kind: CompressionTransformKind::Select,
            scope: "knowledge".to_owned(),
            loss_class: CompressionLossClass::BoundedLoss,
            details: Some("one optional item omitted".to_owned()),
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
            estimated_cost: exact_cost(),
        }],
        selection_frontier_digest: Some(ContentDigest::sha256(b"selection-frontier")),
        stop_reason: CompressionStopReason::TargetBudget,
        output_digest: pack.pack_digest,
    };
    receipt.validate_for(&pack)?;
    Ok((pack, receipt))
}

#[test]
fn receipt_metadata_must_match_descriptor_bound_slot() -> Result<(), Box<dyn Error>> {
    let (pack, receipt) = pack_and_receipt()?;
    let descriptor = descriptor(&pack.anchor)?;
    let binding = ContextExpansionBinding::publish(
        "slot:receipt:knowledge",
        &descriptor,
        HydrationLevel::H1,
        "Hydrate omitted knowledge context.",
    )?;
    let binding_set = ContextExpansionBindingSet::publish(&pack, &receipt, vec![binding])?;
    binding_set.validate_catalog(&pack, &receipt, &[descriptor])?;
    binding_set.validate_receipt_metadata(&receipt)?;
    Ok(())
}

#[test]
fn cheaper_or_reworded_receipt_metadata_is_rejected() -> Result<(), Box<dyn Error>> {
    let (pack, receipt) = pack_and_receipt()?;
    let descriptor = descriptor(&pack.anchor)?;
    let binding = ContextExpansionBinding::publish(
        "slot:receipt:knowledge",
        &descriptor,
        HydrationLevel::H1,
        "Hydrate omitted knowledge context.",
    )?;
    let binding_set = ContextExpansionBindingSet::publish(&pack, &receipt, vec![binding])?;

    let mut cheaper = receipt.clone();
    cheaper.expansion_handles[0].estimated_cost.latency_ms = 0;
    assert!(matches!(
        binding_set.validate_receipt_metadata(&cheaper),
        Err(ContextBindingError::Contract(ContractError::DigestMismatch))
    ));

    let mut reworded = receipt;
    reworded.expansion_handles[0].purpose = "Different semantic expansion.".to_owned();
    assert!(matches!(
        binding_set.validate_receipt_metadata(&reworded),
        Err(ContextBindingError::Contract(ContractError::DigestMismatch))
    ));
    Ok(())
}
