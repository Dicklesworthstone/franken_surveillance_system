#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use fss_core::{
    BudgetVector, Completeness, ContentDigest, ContractBasis, ContractError, HandleAvailability,
    HydrationArtifact, HydrationError, HydrationLevel, HydrationPurpose, HydrationRequest,
    HydrationRequestSpec, LaboratoryAccess, LedgerAnchor, SemanticHandle, SemanticHandleSpec,
    SessionId, TimestampNs,
};
use fss_reference::{ReferenceHydrationCatalog, ReferenceHydrationLimits};

fn descriptor(name: &str) -> Result<SemanticHandle, HydrationError> {
    let levels = BTreeSet::from([HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2]);
    let mut anchor = LedgerAnchor::genesis("site:catalog");
    anchor.commit_sequence = 1;
    SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: ContractBasis::from_registry_bytes(
            b"s", b"o", b"v", b"c", b"e", b"cost", "catalog:test", None,
        ),
        anchor,
        subject_id: format!("subject:{name}"),
        subject_digest: ContentDigest::sha256(name.as_bytes()),
        semantic_type: "evidence_bundle".to_owned(),
        source_id: "sensor:catalog".to_owned(),
        capture_interval: None,
        spatial_scope: None,
        privacy_class: "private:property".to_owned(),
        applied_transform: None,
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(100),
        required_capabilities: levels.iter().map(|level| (*level, BTreeSet::new())).collect(),
        estimated_costs: levels.iter().map(|level| {
            (*level, BudgetVector { bytes: 256, ..BudgetVector::default() })
        }).collect(),
        levels,
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })
}

fn artifact(handle: &SemanticHandle, level: HydrationLevel) -> Result<HydrationArtifact, HydrationError> {
    HydrationArtifact::publish(level, "text/plain", level.as_str().as_bytes().to_vec(),
        [handle.subject_digest], Completeness::Complete, None)
}

fn catalog() -> Result<(ReferenceHydrationCatalog, SemanticHandle), HydrationError> {
    let handle = descriptor("first")?;
    let mut catalog = ReferenceHydrationCatalog::new();
    catalog.register_descriptor(handle.clone())?;
    for level in &handle.levels {
        catalog.register_artifact(&handle.handle_id, handle.descriptor_digest, artifact(&handle, *level)?)?;
    }
    Ok((catalog, handle))
}

fn request(handle: &SemanticHandle) -> Result<HydrationRequest, HydrationError> {
    HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:catalog")?,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: HydrationLevel::H0,
        allow_lower_level: false,
        available_capabilities: BTreeSet::new(),
        authorized_privacy_classes: BTreeSet::from([handle.privacy_class.clone()]),
        budget: BudgetVector { bytes: 256, ..BudgetVector::default() },
        purpose: HydrationPurpose::Routine,
        continuation: None,
        issued_at: TimestampNs(10).max(handle.published_at),
    })
}

fn reseal_request(request: &mut HydrationRequest) {
    request.request_digest = request.computed_digest();
    request.request_id = format!("hydration-request:{}", request.request_digest);
}

fn revision(handle: &SemanticHandle, sequence: u64, state: HandleAvailability) -> SemanticHandle {
    let mut next = handle.clone();
    next.anchor.commit_sequence = sequence;
    next.published_at = TimestampNs(30);
    next.availability = state;
    next.descriptor_digest = next.computed_descriptor_digest();
    next
}

#[test]
fn delayed_reads_are_deterministic_but_expiry_is_rechecked() -> Result<(), HydrationError> {
    let (catalog, handle) = catalog()?;
    let request = request(&handle)?;
    let first = catalog.hydrate(&request, TimestampNs(20))?;
    assert_eq!(first, catalog.hydrate(&request, TimestampNs(20))?);
    assert_eq!(first.receipt.issued_at, TimestampNs(20));
    let expired = catalog.hydrate(&request, TimestampNs(100))?;
    assert!(expired.artifact.is_none());
    assert_eq!(expired.receipt.availability, HandleAvailability::Expired);
    expired.validate_for(&request, &handle)
}

#[test]
fn superseded_descriptors_cannot_serve_retained_payloads() -> Result<(), HydrationError> {
    let (mut catalog, old) = catalog()?;
    let old_request = request(&old)?;
    let deleted = revision(&old, 2, HandleAvailability::Deleted);
    catalog.register_descriptor(deleted.clone())?;
    catalog.register_descriptor(old.clone())?;
    assert_eq!(catalog.current_descriptor(&old.handle_id), Some(&deleted));
    assert_eq!(catalog.hydrate(&old_request, TimestampNs(40)),
        Err(HydrationError::Contract(ContractError::StaleAnchor)));
    let current = catalog.hydrate(&request(&deleted)?, TimestampNs(40))?;
    assert_eq!(current.receipt.availability, HandleAvailability::Deleted);
    assert!(current.artifact.is_none());
    assert!(catalog.descriptor(&old.handle_id, old.descriptor_digest).is_some());
    Ok(())
}

#[test]
fn equal_anchor_replacement_and_terminal_resurrection_are_refused() -> Result<(), HydrationError> {
    let (mut catalog, old) = catalog()?;
    let fork = revision(&old, 1, HandleAvailability::Deleted);
    assert_eq!(catalog.register_descriptor(fork),
        Err(HydrationError::Contract(ContractError::StaleAnchor)));
    assert_eq!(catalog.current_descriptor(&old.handle_id), Some(&old));
    let deleted = revision(&old, 2, HandleAvailability::Deleted);
    catalog.register_descriptor(deleted.clone())?;
    let resurrected = revision(&deleted, 3, HandleAvailability::Available);
    assert_eq!(catalog.register_descriptor(resurrected),
        Err(HydrationError::Contract(ContractError::GenerationConflict)));
    assert_eq!(catalog.current_descriptor(&old.handle_id), Some(&deleted));
    Ok(())
}

#[test]
fn expiry_cannot_be_reversed_by_a_late_retention_extension() -> Result<(), HydrationError> {
    let (mut catalog, old) = catalog()?;
    let mut late = revision(&old, 2, HandleAvailability::Available);
    late.published_at = TimestampNs(100);
    late.retention_until = TimestampNs(200);
    late.descriptor_digest = late.computed_descriptor_digest();
    assert_eq!(catalog.register_descriptor(late),
        Err(HydrationError::Contract(ContractError::GenerationConflict)));
    Ok(())
}

#[test]
fn unavailable_metadata_still_requires_privacy_scope() -> Result<(), HydrationError> {
    let (catalog, handle) = catalog()?;
    let mut request = request(&handle)?;
    request.authorized_privacy_classes.clear();
    reseal_request(&mut request);
    assert_eq!(catalog.hydrate(&request, TimestampNs(100)), Err(HydrationError::PrivacyDenied));
    Ok(())
}

#[test]
fn continuations_verify_prior_artifact_and_preserve_expiry_ceiling() -> Result<(), HydrationError> {
    let (catalog, handle) = catalog()?;
    let first_request = request(&handle)?;
    let first = catalog.hydrate(&first_request, TimestampNs(20))?;
    let mut cursor = first.receipt.continuation.ok_or(HydrationError::WrongContinuation)?;
    cursor.expires_at = TimestampNs(70);
    cursor.cursor_digest = cursor.computed_digest();
    cursor.cursor_id = format!("continuation:{}", cursor.cursor_digest);
    let mut next = request(&handle)?;
    next.requested_level = HydrationLevel::H1;
    next.issued_at = TimestampNs(30);
    next.continuation = Some(cursor.clone());
    reseal_request(&mut next);
    let response = catalog.hydrate(&next, TimestampNs(40))?;
    response.validate_for(&next, &handle)?;
    let next_cursor = response.receipt.continuation.ok_or(HydrationError::WrongContinuation)?;
    assert_eq!(next_cursor.predecessor_digest, Some(cursor.cursor_digest));
    assert_eq!(next_cursor.expires_at, TimestampNs(70));

    cursor.selection_witness = ContentDigest::sha256(b"invented prior artifact");
    cursor.cursor_digest = cursor.computed_digest();
    cursor.cursor_id = format!("continuation:{}", cursor.cursor_digest);
    next.continuation = Some(cursor);
    reseal_request(&mut next);
    assert_eq!(catalog.hydrate(&next, TimestampNs(40)), Err(HydrationError::WrongContinuation));
    Ok(())
}

#[test]
fn rejected_and_duplicate_writes_do_not_consume_capacity() -> Result<(), HydrationError> {
    let handle = descriptor("bounded")?;
    let mut catalog = ReferenceHydrationCatalog::with_limits(ReferenceHydrationLimits {
        max_descriptors: 1, max_payload_bytes: 3,
    });
    catalog.register_descriptor(handle.clone())?;
    let first = artifact(&handle, HydrationLevel::H0)?;
    catalog.register_artifact(&handle.handle_id, handle.descriptor_digest, first.clone())?;
    catalog.register_artifact(&handle.handle_id, handle.descriptor_digest, first)?;
    assert_eq!(catalog.stored_payload_bytes(), 2);
    assert_eq!(catalog.register_artifact(&handle.handle_id, handle.descriptor_digest,
        artifact(&handle, HydrationLevel::H1)?), Err(HydrationError::BudgetExceeded));
    assert_eq!(catalog.stored_payload_bytes(), 2);
    assert_eq!(catalog.register_descriptor(descriptor("excess")?), Err(HydrationError::BudgetExceeded));
    assert_eq!(catalog.current_descriptor(&handle.handle_id), Some(&handle));
    catalog.hydrate(&request(&handle)?, TimestampNs(20))?;
    Ok(())
}
