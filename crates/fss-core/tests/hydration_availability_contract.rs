use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    BudgetVector, Completeness, ContentDigest, ContractBasis, ContractError, HandleAvailability,
    HydrationError, HydrationLevel, HydrationPurpose, HydrationReceipt, HydrationReceiptSpec,
    HydrationRequest, HydrationRequestSpec, LaboratoryAccess, LedgerAnchor, SemanticHandle,
    SemanticHandleSpec, SessionId, TimestampNs,
};

fn basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(
        b"schemas",
        b"operations",
        b"views",
        b"capabilities",
        b"errors",
        b"costs",
        "fss-hydration-availability:test",
        None,
    )
}

fn handle() -> Result<SemanticHandle, HydrationError> {
    SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: basis(),
        anchor: LedgerAnchor::genesis("site:hydration-availability"),
        subject_id: "evidence:availability".to_owned(),
        subject_digest: ContentDigest::sha256(b"availability subject"),
        semantic_type: "evidence_bundle".to_owned(),
        source_id: "sensor:availability".to_owned(),
        capture_interval: None,
        spatial_scope: None,
        privacy_class: "private:property".to_owned(),
        applied_transform: None,
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(100),
        levels: BTreeSet::from([HydrationLevel::H0]),
        required_capabilities: BTreeMap::from([(HydrationLevel::H0, BTreeSet::new())]),
        estimated_costs: BTreeMap::from([(HydrationLevel::H0, BudgetVector::default())]),
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })
}

fn request(
    handle: &SemanticHandle,
    issued_at: TimestampNs,
) -> Result<HydrationRequest, HydrationError> {
    HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:hydration-availability")?,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: HydrationLevel::H0,
        allow_lower_level: false,
        available_capabilities: BTreeSet::new(),
        authorized_privacy_classes: BTreeSet::from(["private:property".to_owned()]),
        budget: BudgetVector::default(),
        purpose: HydrationPurpose::Routine,
        continuation: None,
        issued_at,
    })
}

fn unavailable_receipt(
    request: &HydrationRequest,
    handle: &SemanticHandle,
    availability: HandleAvailability,
) -> Result<HydrationReceipt, HydrationError> {
    HydrationReceipt::publish(HydrationReceiptSpec {
        request_digest: request.request_digest,
        handle_id: handle.handle_id.clone(),
        descriptor_digest: handle.descriptor_digest,
        subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: request.requested_level,
        delivered_level: None,
        availability,
        cost: BudgetVector::default(),
        completeness: availability.unavailable_completeness(),
        artifact_digest: None,
        proof_roots: BTreeSet::from([handle.descriptor_digest]),
        continuation: None,
        invalidators: BTreeSet::from(["descriptor-or-retention-change".to_owned()]),
        issued_at: request.issued_at,
    })
}

#[test]
fn retention_deadline_changes_effective_availability_to_expired() -> Result<(), HydrationError> {
    let handle = handle()?;
    let request = request(&handle, TimestampNs(100))?;
    let receipt = unavailable_receipt(&request, &handle, HandleAvailability::Expired)?;

    receipt.validate_for(&request, &handle, None)
}

#[test]
fn available_descriptor_cannot_be_reported_deleted() -> Result<(), HydrationError> {
    let handle = handle()?;
    let request = request(&handle, TimestampNs(20))?;
    let receipt = unavailable_receipt(&request, &handle, HandleAvailability::Deleted)?;

    assert!(matches!(
        receipt.validate_for(&request, &handle, None),
        Err(HydrationError::Contract(ContractError::DigestMismatch))
    ));
    Ok(())
}
