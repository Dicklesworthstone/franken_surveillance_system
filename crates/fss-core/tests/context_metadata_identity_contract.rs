#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use fss_core::{
    BudgetVector, Completeness, CompressionCompleteness, CompressionStopReason, ContentDigest,
    ContextBindingError, ContextExpansionBinding, ContextExpansionBindingSet, ContractError,
    CriticalPreservation, ExpansionHandle, HydrationLevel, LedgerAnchor,
    SemanticCompressionReceipt, SemanticHandleReference,
};

fn fixture() -> (SemanticCompressionReceipt, ContextExpansionBindingSet) {
    let root = ContentDigest::sha256(b"metadata-identity-fixture");
    let mut reference = SemanticHandleReference {
        handle_id: "semantic-handle:metadata-identity".to_owned(),
        descriptor_digest: root,
        subject_digest: root,
        contract_basis_digest: root,
        descriptor_anchor: LedgerAnchor::genesis("site:metadata-identity"),
        hydration_level: HydrationLevel::H0,
        ladder_policy_digest: root,
        reference_digest: root,
    };
    reference.reference_digest = reference.computed_digest();
    let mut binding = ContextExpansionBinding {
        slot_id: "slot:metadata-identity".to_owned(),
        reference,
        purpose: "Expand the exact omitted context.".to_owned(),
        estimated_cost: BudgetVector::default(),
        binding_digest: root,
    };
    binding.binding_digest = binding.computed_digest();
    let receipt = SemanticCompressionReceipt {
        receipt_id: "compression:metadata-identity".to_owned(),
        source_anchor: LedgerAnchor::genesis("site:metadata-identity"),
        view_id: "AVIEW-001".to_owned(),
        target_tokens: 10,
        selected_classes: BTreeSet::from(["knowledge".to_owned()]),
        omitted_classes: BTreeSet::from(["knowledge".to_owned()]),
        transforms: Vec::new(),
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
        actual_tokens: 1,
        actual_bytes: 1,
        expansion_handles: vec![ExpansionHandle {
            handle: binding.slot_id.clone(),
            purpose: binding.purpose.clone(),
            estimated_cost: binding.estimated_cost,
        }],
        selection_frontier_digest: Some(root),
        stop_reason: CompressionStopReason::TargetBudget,
        output_digest: root,
    };
    let mut bindings = ContextExpansionBindingSet {
        contract_basis_digest: root,
        pack_digest: root,
        compression_receipt_digest: receipt.receipt_digest(),
        bindings: vec![binding],
        binding_set_digest: root,
    };
    bindings.binding_set_digest = bindings.computed_digest();
    (receipt, bindings)
}

#[test]
fn exact_receipt_metadata_is_accepted() -> Result<(), ContextBindingError> {
    let (receipt, bindings) = fixture();
    bindings.validate_receipt_metadata(&receipt)
}

#[test]
fn identical_expansions_do_not_authorize_another_receipt() {
    let (mut receipt, bindings) = fixture();
    receipt.output_digest = ContentDigest::sha256(b"another-context-pack");
    assert_eq!(
        bindings.validate_receipt_metadata(&receipt),
        Err(ContextBindingError::Contract(ContractError::DigestMismatch))
    );
}

#[test]
fn resealing_the_set_does_not_hide_a_damaged_nested_reference() {
    let (receipt, mut bindings) = fixture();
    bindings.bindings[0].reference.subject_digest = ContentDigest::sha256(b"another-subject");
    bindings.binding_set_digest = bindings.computed_digest();
    assert_eq!(
        bindings.validate_receipt_metadata(&receipt),
        Err(ContextBindingError::Contract(ContractError::DigestMismatch))
    );
}

#[test]
fn resealed_duplicate_slots_are_rejected_before_lookup() {
    let (receipt, mut bindings) = fixture();
    let duplicate = bindings.bindings[0].clone();
    bindings.bindings.push(duplicate);
    bindings.binding_set_digest = bindings.computed_digest();
    assert_eq!(
        bindings.validate_receipt_metadata(&receipt),
        Err(ContextBindingError::DuplicateSlot(
            "slot:metadata-identity".to_owned()
        ))
    );
}

#[test]
fn damaged_set_digest_is_rejected_even_with_unchanged_metadata() {
    let (receipt, mut bindings) = fixture();
    bindings.binding_set_digest = ContentDigest::sha256(b"another-binding-set");
    assert_eq!(
        bindings.validate_receipt_metadata(&receipt),
        Err(ContextBindingError::Contract(ContractError::DigestMismatch))
    );
}
