//! Contract tests for reference hydration catalog.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use fss_core::{
    BudgetVector, Completeness, ContentDigest, ContractBasis, ContractBasisRegistryBytes,
    ContractError, HandleAvailability, HydrationArtifact, HydrationError, HydrationLevel,
    HydrationPurpose, HydrationRequest, HydrationRequestSpec, LaboratoryAccess, LedgerAnchor,
    SemanticHandle, SemanticHandleSpec, SessionId, TimestampNs,
};
use fss_reference::{ReferenceHydrationCatalog, ReferenceHydrationLimits};

fn descriptor(name: &str) -> Result<SemanticHandle, HydrationError> {
    let levels = BTreeSet::from([HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2]);
    let mut anchor = LedgerAnchor::genesis("site:catalog");
    anchor.commit_sequence = 1;
    SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
            b"s",
            b"o",
            b"v",
            b"c",
            b"e",
            b"cost",
            "catalog:test",
        )),
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
        required_capabilities: levels
            .iter()
            .map(|level| (*level, BTreeSet::new()))
            .collect(),
        estimated_costs: levels
            .iter()
            .map(|level| {
                Ok((
                    *level,
                    BudgetVector::builder()
                        .bytes(256)
                        .build()
                        .map_err(ContractError::from)?,
                ))
            })
            .collect::<Result<_, HydrationError>>()?,
        levels,
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })
}

fn artifact(
    handle: &SemanticHandle,
    level: HydrationLevel,
) -> Result<HydrationArtifact, HydrationError> {
    HydrationArtifact::publish(
        level,
        "text/plain",
        level.as_str().as_bytes().to_vec(),
        [handle.subject_digest],
        Completeness::Complete,
        None,
    )
}

fn catalog() -> Result<(ReferenceHydrationCatalog, SemanticHandle), HydrationError> {
    let handle = descriptor("first")?;
    let mut catalog = ReferenceHydrationCatalog::new();
    catalog.register_descriptor(handle.clone())?;
    for level in &handle.levels {
        catalog.register_artifact(
            &handle.handle_id,
            handle.descriptor_digest,
            artifact(&handle, *level)?,
        )?;
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
        budget: BudgetVector::builder()
            .bytes(256)
            .build()
            .map_err(ContractError::from)?,
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
    let (mut catalog, handle) = catalog()?;
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
    assert_eq!(
        catalog.hydrate(&old_request, TimestampNs(40)),
        Err(HydrationError::Contract(ContractError::StaleAnchor))
    );
    let current = catalog.hydrate(&request(&deleted)?, TimestampNs(40))?;
    assert_eq!(current.receipt.availability, HandleAvailability::Deleted);
    assert!(current.artifact.is_none());
    assert!(
        catalog
            .descriptor(&old.handle_id, old.descriptor_digest)
            .is_some()
    );
    Ok(())
}

#[test]
fn equal_anchor_replacement_and_terminal_resurrection_are_refused() -> Result<(), HydrationError> {
    let (mut catalog, old) = catalog()?;
    let fork = revision(&old, 1, HandleAvailability::Deleted);
    assert_eq!(
        catalog.register_descriptor(fork),
        Err(HydrationError::Contract(ContractError::StaleAnchor))
    );
    assert_eq!(catalog.current_descriptor(&old.handle_id), Some(&old));
    let deleted = revision(&old, 2, HandleAvailability::Deleted);
    catalog.register_descriptor(deleted.clone())?;
    let resurrected = revision(&deleted, 3, HandleAvailability::Available);
    assert_eq!(
        catalog.register_descriptor(resurrected),
        Err(HydrationError::Contract(ContractError::GenerationConflict))
    );
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
    assert_eq!(
        catalog.register_descriptor(late),
        Err(HydrationError::Contract(ContractError::GenerationConflict))
    );
    Ok(())
}

#[test]
fn unavailable_metadata_still_requires_privacy_scope() -> Result<(), HydrationError> {
    let (mut catalog, handle) = catalog()?;
    let mut request = request(&handle)?;
    request.authorized_privacy_classes.clear();
    reseal_request(&mut request);
    assert_eq!(
        catalog.hydrate(&request, TimestampNs(100)),
        Err(HydrationError::PrivacyDenied)
    );
    Ok(())
}

#[test]
fn continuations_verify_prior_artifact_and_preserve_expiry_ceiling() -> Result<(), HydrationError> {
    let (mut catalog, handle) = catalog()?;
    let first_request = request(&handle)?;
    let first = catalog.hydrate(&first_request, TimestampNs(20))?;
    let cursor = first
        .receipt
        .continuation
        .ok_or(HydrationError::WrongContinuation)?;
    assert_eq!(cursor.expires_at, TimestampNs(100));
    assert_eq!(catalog.issued_cursor_count(), 1);

    // Legitimate continuation matches issued cursor and preserves expiry ceiling
    let mut next = request(&handle)?;
    next.requested_level = HydrationLevel::H1;
    next.issued_at = TimestampNs(30);
    next.continuation = Some(cursor.clone());
    reseal_request(&mut next);
    let response = catalog.hydrate(&next, TimestampNs(40))?;
    response.validate_for(&next, &handle)?;
    let next_cursor = response
        .receipt
        .continuation
        .ok_or(HydrationError::WrongContinuation)?;
    assert_eq!(next_cursor.predecessor_digest, Some(cursor.cursor_digest));
    assert_eq!(next_cursor.expires_at, TimestampNs(100));

    // Tampered expiry on cursor produces an unissued digest and is rejected
    let mut tampered = cursor.clone();
    tampered.expires_at = TimestampNs(70);
    tampered.cursor_digest = tampered.computed_digest();
    tampered.cursor_id = format!("continuation:{}", tampered.cursor_digest);
    let mut tampered_request = request(&handle)?;
    tampered_request.requested_level = HydrationLevel::H1;
    tampered_request.issued_at = TimestampNs(30);
    tampered_request.continuation = Some(tampered);
    reseal_request(&mut tampered_request);
    assert_eq!(
        catalog.hydrate(&tampered_request, TimestampNs(40)),
        Err(HydrationError::ContinuationUnissued)
    );

    // Tampered artifact witness is rejected
    let mut bad_witness = cursor.clone();
    bad_witness.selection_witness = ContentDigest::sha256(b"invented prior artifact");
    bad_witness.cursor_digest = bad_witness.computed_digest();
    bad_witness.cursor_id = format!("continuation:{}", bad_witness.cursor_digest);
    let mut bad_witness_request = request(&handle)?;
    bad_witness_request.requested_level = HydrationLevel::H1;
    bad_witness_request.issued_at = TimestampNs(30);
    bad_witness_request.continuation = Some(bad_witness);
    reseal_request(&mut bad_witness_request);
    assert_eq!(
        catalog.hydrate(&bad_witness_request, TimestampNs(40)),
        Err(HydrationError::ContinuationUnissued)
    );

    // Replay of already-consumed cursor is rejected
    assert_eq!(
        catalog.hydrate(&next, TimestampNs(40)),
        Err(HydrationError::ContinuationAlreadyConsumed)
    );

    // Cross-session presentation of active cursor is rejected
    let mut other_session_request = request(&handle)?;
    other_session_request.session_id = SessionId::parse("session:other")?;
    other_session_request.requested_level = HydrationLevel::H2;
    other_session_request.issued_at = TimestampNs(40);
    other_session_request.continuation = Some(next_cursor.clone());
    reseal_request(&mut other_session_request);
    assert_eq!(
        catalog.hydrate(&other_session_request, TimestampNs(40)),
        Err(HydrationError::ContinuationCrossSession)
    );

    // Continuation presented after expiry is rejected
    let mut expired_request = request(&handle)?;
    expired_request.requested_level = HydrationLevel::H2;
    expired_request.issued_at = TimestampNs(40);
    expired_request.continuation = Some(next_cursor);
    reseal_request(&mut expired_request);
    assert_eq!(
        catalog.hydrate(&expired_request, TimestampNs(100)),
        Err(HydrationError::ContinuationExpired)
    );
    Ok(())
}

#[test]
fn issued_cursor_cannot_be_reused_twice_for_ordinal_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut catalog, handle) = catalog()?;
    let first_request = request(&handle)?;
    let first_resp = catalog.hydrate(&first_request, TimestampNs(20))?;
    let cursor = first_resp
        .receipt
        .continuation
        .ok_or(HydrationError::WrongContinuation)?;

    // First use: advance from H0 to H1
    let mut next_request = request(&handle)?;
    next_request.requested_level = HydrationLevel::H1;
    next_request.issued_at = TimestampNs(30);
    next_request.continuation = Some(cursor.clone());
    reseal_request(&mut next_request);

    let second_resp = catalog.hydrate(&next_request, TimestampNs(35))?;
    assert_eq!(
        second_resp.receipt.delivered_level,
        Some(HydrationLevel::H1)
    );

    // Replay attempt: presenting the exact same cursor again must fail
    let replay_result = catalog.hydrate(&next_request, TimestampNs(40));
    assert_eq!(
        replay_result,
        Err(HydrationError::ContinuationAlreadyConsumed)
    );
    Ok(())
}

#[test]
fn cursor_capacity_is_bounded_and_evicts_consumed_or_expired() -> Result<(), HydrationError> {
    let handle = descriptor("cursor-capacity")?;
    let mut catalog = ReferenceHydrationCatalog::with_limits(ReferenceHydrationLimits {
        max_descriptors: 10,
        max_payload_bytes: 1024 * 1024,
        max_issued_cursors: 2,
    });
    catalog.register_descriptor(handle.clone())?;
    for level in &handle.levels {
        catalog.register_artifact(
            &handle.handle_id,
            handle.descriptor_digest,
            artifact(&handle, *level)?,
        )?;
    }

    // 1st request -> issues cursor 1 (1 / 2 slots used)
    let first_request = request(&handle)?;
    let first_resp = catalog.hydrate(&first_request, TimestampNs(10))?;
    let cursor1 = first_resp
        .receipt
        .continuation
        .ok_or(HydrationError::WrongContinuation)?;
    assert_eq!(catalog.issued_cursor_count(), 1);

    // 2nd request -> issues cursor 2 (2 / 2 slots used)
    let second_request = request(&handle)?;
    let second_resp = catalog.hydrate(&second_request, TimestampNs(12))?;
    let _cursor2 = second_resp
        .receipt
        .continuation
        .ok_or(HydrationError::WrongContinuation)?;
    assert_eq!(catalog.issued_cursor_count(), 2);

    // 3rd request without continuation -> capacity is full, neither cursor is expired or consumed
    let third_request = request(&handle)?;
    assert_eq!(
        catalog.hydrate(&third_request, TimestampNs(15)),
        Err(HydrationError::CapacityExceeded)
    );

    // Advance cursor1: cursor1 is consumed and evicted under capacity pressure
    let mut advance_request = request(&handle)?;
    advance_request.requested_level = HydrationLevel::H1;
    advance_request.issued_at = TimestampNs(20);
    advance_request.continuation = Some(cursor1.clone());
    reseal_request(&mut advance_request);
    let advance_resp = catalog.hydrate(&advance_request, TimestampNs(25))?;
    let _cursor3 = advance_resp
        .receipt
        .continuation
        .ok_or(HydrationError::WrongContinuation)?;
    assert_eq!(catalog.issued_cursor_count(), 2);
    assert!(catalog.issued_cursor(&cursor1.cursor_digest).is_none());

    // Prune expired cursors at timestamp 100
    catalog.prune_expired_cursors(TimestampNs(100));
    assert_eq!(catalog.issued_cursor_count(), 0);

    Ok(())
}

#[test]
fn unavailable_receipt_has_no_explicit_downgrade_invalidator() -> Result<(), HydrationError> {
    let (mut catalog, handle) = catalog()?;
    let mut request = request(&handle)?;
    request.requested_level = HydrationLevel::H1;
    reseal_request(&mut request);
    let response = catalog.hydrate(&request, TimestampNs(100))?;
    assert_eq!(response.receipt.delivered_level, None);
    assert_eq!(response.receipt.availability, HandleAvailability::Expired);
    assert!(
        !response
            .receipt
            .invalidators
            .iter()
            .any(|inv| inv.starts_with("explicit-downgrade")),
        "unavailable response must not include explicit-downgrade invalidator"
    );
    Ok(())
}

#[test]
fn rejected_and_duplicate_writes_do_not_consume_capacity() -> Result<(), HydrationError> {
    let handle = descriptor("bounded")?;
    let mut catalog = ReferenceHydrationCatalog::with_limits(ReferenceHydrationLimits {
        max_descriptors: 1,
        max_payload_bytes: 3,
        max_issued_cursors: 4_096,
    });
    catalog.register_descriptor(handle.clone())?;
    let first = artifact(&handle, HydrationLevel::H0)?;
    catalog.register_artifact(&handle.handle_id, handle.descriptor_digest, first.clone())?;
    catalog.register_artifact(&handle.handle_id, handle.descriptor_digest, first)?;
    assert_eq!(catalog.stored_payload_bytes(), 2);
    assert_eq!(
        catalog.register_artifact(
            &handle.handle_id,
            handle.descriptor_digest,
            artifact(&handle, HydrationLevel::H1)?
        ),
        Err(HydrationError::BudgetExceeded)
    );
    assert_eq!(catalog.stored_payload_bytes(), 2);
    assert_eq!(
        catalog.register_descriptor(descriptor("excess")?),
        Err(HydrationError::BudgetExceeded)
    );
    assert_eq!(catalog.current_descriptor(&handle.handle_id), Some(&handle));
    catalog.hydrate(&request(&handle)?, TimestampNs(20))?;
    Ok(())
}
