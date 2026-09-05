#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use fss_core::{
    BudgetVector, Completeness, ContentDigest, ContinuationCursor, ContinuationScope, ContractBasis,
    ContractError, HYDRATION_VIEW_ID, HandleAvailability, HydrationArtifact, HydrationError,
    HydrationLevel, HydrationPurpose, HydrationReceipt, HydrationReceiptSpec, HydrationRequest,
    HydrationRequestSpec, LaboratoryAccess, LedgerAnchor, SemanticHandle, SemanticHandleSpec,
    SessionId, TimestampNs,
};

fn handle() -> Result<SemanticHandle, HydrationError> {
    let levels = BTreeSet::from([
        HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2,
        HydrationLevel::H3, HydrationLevel::H4,
    ]);
    SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: ContractBasis::from_registry_bytes(
            b"schemas", b"operations", b"views", b"capabilities", b"errors", b"costs",
            "hydration-admission:test", None,
        ),
        anchor: LedgerAnchor::genesis("site:admission"),
        subject_id: "subject:admission".to_owned(),
        subject_digest: ContentDigest::sha256(b"exact redacted subject"),
        semantic_type: "evidence_bundle".to_owned(),
        source_id: "sensor:admission".to_owned(),
        capture_interval: None,
        spatial_scope: None,
        privacy_class: "private:property".to_owned(),
        applied_transform: Some("redaction:test".to_owned()),
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(100),
        required_capabilities: levels.iter().map(|level| {
            (*level, BTreeSet::from([format!("capability:hydrate:{}", level.as_str())]))
        }).collect(),
        estimated_costs: levels.iter().map(|level| {
            (*level, BudgetVector { bytes: 1_024, tokens: 256, ..BudgetVector::default() })
        }).collect(),
        levels,
        laboratory_access: LaboratoryAccess::QualificationOrDebugGrant,
        debug_capability: Some("capability:hydrate:debug".to_owned()),
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })
}

fn request(handle: &SemanticHandle, level: HydrationLevel) -> Result<HydrationRequest, HydrationError> {
    HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:admission")?,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: level,
        allow_lower_level: false,
        available_capabilities: handle.required_capabilities.values().flatten().cloned().collect(),
        authorized_privacy_classes: BTreeSet::from([handle.privacy_class.clone()]),
        budget: BudgetVector { bytes: 2_048, tokens: 512, ..BudgetVector::default() },
        purpose: HydrationPurpose::Qualification,
        continuation: None,
        issued_at: TimestampNs(10),
    })
}

fn artifact(handle: &SemanticHandle, level: HydrationLevel) -> Result<HydrationArtifact, HydrationError> {
    HydrationArtifact::publish(
        level, "application/fss+json", b"redacted synopsis".to_vec(),
        [handle.subject_digest], Completeness::Complete, handle.applied_transform.clone(),
    )
}

fn receipt(
    handle: &SemanticHandle,
    request: &HydrationRequest,
    artifact: &HydrationArtifact,
    now: TimestampNs,
) -> Result<HydrationReceipt, HydrationError> {
    let mut roots = artifact.proof_roots.clone();
    roots.extend([handle.descriptor_digest, request.request_digest, artifact.artifact_digest]);
    HydrationReceipt::publish(HydrationReceiptSpec {
        request_digest: request.request_digest,
        handle_id: handle.handle_id.clone(),
        descriptor_digest: handle.descriptor_digest,
        subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: request.requested_level,
        delivered_level: Some(artifact.level),
        availability: HandleAvailability::Available,
        cost: handle.estimated_cost(artifact.level).ok_or(HydrationError::LevelUnavailable)?,
        completeness: artifact.completeness_for(request.requested_level),
        artifact_digest: Some(artifact.artifact_digest),
        proof_roots: roots,
        continuation: None,
        invalidators: BTreeSet::from(["descriptor-and-disclosure-policy".to_owned()]),
        issued_at: now,
    })
}

fn reseal_request(request: &mut HydrationRequest) {
    request.request_digest = request.computed_digest();
    request.request_id = format!("hydration-request:{}", request.request_digest);
}

fn reseal_receipt(receipt: &mut HydrationReceipt) {
    receipt.receipt_digest = receipt.computed_digest();
    receipt.receipt_id = format!("hydration-receipt:{}", receipt.receipt_digest);
}

#[test]
fn delayed_service_uses_actual_receipt_time() -> Result<(), HydrationError> {
    let handle = handle()?;
    let request = request(&handle, HydrationLevel::H1)?;
    let artifact = artifact(&handle, HydrationLevel::H1)?;
    let receipt = receipt(&handle, &request, &artifact, TimestampNs(20))?;
    receipt.validate_for(&request, &handle, Some(&artifact))
}

#[test]
fn backdating_and_expiry_crossing_are_rejected() -> Result<(), HydrationError> {
    let handle = handle()?;
    let request = request(&handle, HydrationLevel::H1)?;
    let artifact = artifact(&handle, HydrationLevel::H1)?;
    let backdated = receipt(&handle, &request, &artifact, TimestampNs(9))?;
    assert_eq!(backdated.validate_for(&request, &handle, Some(&artifact)),
        Err(HydrationError::Contract(ContractError::InvertedTimeInterval)));
    let expired = receipt(&handle, &request, &artifact, TimestampNs(100))?;
    assert_eq!(expired.validate_for(&request, &handle, Some(&artifact)),
        Err(HydrationError::Contract(ContractError::DigestMismatch)));
    Ok(())
}

#[test]
fn rehashed_receipts_cannot_bypass_disclosure_clamps() -> Result<(), HydrationError> {
    let handle = handle()?;
    let artifact = artifact(&handle, HydrationLevel::H1)?;
    let mut denied = request(&handle, HydrationLevel::H1)?;
    denied.available_capabilities.clear();
    reseal_request(&mut denied);
    let forged = receipt(&handle, &denied, &artifact, TimestampNs(20))?;
    assert_eq!(forged.validate_for(&denied, &handle, Some(&artifact)),
        Err(HydrationError::CapabilityDenied));

    let mut denied = request(&handle, HydrationLevel::H1)?;
    denied.authorized_privacy_classes.clear();
    reseal_request(&mut denied);
    let forged = receipt(&handle, &denied, &artifact, TimestampNs(20))?;
    assert_eq!(forged.validate_for(&denied, &handle, Some(&artifact)),
        Err(HydrationError::PrivacyDenied));
    Ok(())
}

#[test]
fn independent_verifier_checks_h4_purpose() -> Result<(), HydrationError> {
    let handle = handle()?;
    let artifact = artifact(&handle, HydrationLevel::H4)?;
    let mut request = request(&handle, HydrationLevel::H4)?;
    let valid = receipt(&handle, &request, &artifact, TimestampNs(20))?;
    valid.validate_for(&request, &handle, Some(&artifact))?;
    request.purpose = HydrationPurpose::Routine;
    reseal_request(&mut request);
    let forged = receipt(&handle, &request, &artifact, TimestampNs(20))?;
    assert_eq!(forged.validate_for(&request, &handle, Some(&artifact)),
        Err(HydrationError::LaboratoryGrantRequired));
    Ok(())
}

#[test]
fn cost_rewriting_and_payload_underpricing_fail_closed() -> Result<(), HydrationError> {
    let mut handle = handle()?;
    let artifact = artifact(&handle, HydrationLevel::H1)?;
    let original_request = request(&handle, HydrationLevel::H1)?;
    let mut forged = receipt(&handle, &original_request, &artifact, TimestampNs(20))?;
    forged.cost = BudgetVector::default();
    reseal_receipt(&mut forged);
    assert_eq!(forged.validate_for(&original_request, &handle, Some(&artifact)),
        Err(HydrationError::Contract(ContractError::DigestMismatch)));

    handle.estimated_costs.insert(HydrationLevel::H1, BudgetVector::default());
    handle.descriptor_digest = handle.computed_descriptor_digest();
    let request = request(&handle, HydrationLevel::H1)?;
    let underpriced = receipt(&handle, &request, &artifact, TimestampNs(20))?;
    assert_eq!(underpriced.validate_for(&request, &handle, Some(&artifact)),
        Err(HydrationError::BudgetExceeded));
    Ok(())
}

#[test]
fn fallback_requires_consent_and_partial_completeness() -> Result<(), HydrationError> {
    let handle = handle()?;
    let artifact = artifact(&handle, HydrationLevel::H1)?;
    let mut request = request(&handle, HydrationLevel::H3)?;
    let forbidden = receipt(&handle, &request, &artifact, TimestampNs(20))?;
    assert_eq!(forbidden.validate_for(&request, &handle, Some(&artifact)),
        Err(HydrationError::LevelUnavailable));
    request.allow_lower_level = true;
    reseal_request(&mut request);
    let mut permitted = receipt(&handle, &request, &artifact, TimestampNs(20))?;
    permitted.validate_for(&request, &handle, Some(&artifact))?;
    assert_eq!(permitted.completeness, Completeness::Partial);
    permitted.completeness = Completeness::Complete;
    reseal_receipt(&mut permitted);
    assert_eq!(permitted.validate_for(&request, &handle, Some(&artifact)),
        Err(HydrationError::Contract(ContractError::DigestMismatch)));
    Ok(())
}

#[test]
fn receipt_must_retain_input_proof_roots() -> Result<(), HydrationError> {
    let handle = handle()?;
    let request = request(&handle, HydrationLevel::H1)?;
    let artifact = artifact(&handle, HydrationLevel::H1)?;
    let original = receipt(&handle, &request, &artifact, TimestampNs(20))?;
    for root in [handle.subject_digest, handle.descriptor_digest, request.request_digest] {
        let mut forged = original.clone();
        forged.proof_roots.remove(&root);
        reseal_receipt(&mut forged);
        assert_eq!(forged.validate_for(&request, &handle, Some(&artifact)),
            Err(HydrationError::Contract(ContractError::DigestMismatch)));
    }
    Ok(())
}

#[test]
fn explicit_disposition_survives_retention_expiry() -> Result<(), HydrationError> {
    let mut handle = handle()?;
    for availability in [
        HandleAvailability::Deleted, HandleAvailability::Corrupt, HandleAvailability::Superseded,
        HandleAvailability::PrivacyTransformed, HandleAvailability::NotObservable,
    ] {
        handle.availability = availability;
        handle.descriptor_digest = handle.computed_descriptor_digest();
        handle.verify()?;
        assert_eq!(handle.availability_at(TimestampNs(200)), availability);
    }
    Ok(())
}

#[test]
fn cursor_must_keep_the_exact_delivered_artifact_and_parent() -> Result<(), HydrationError> {
    let handle = handle()?;
    let request = request(&handle, HydrationLevel::H1)?;
    let artifact = artifact(&handle, HydrationLevel::H1)?;
    let mut original = receipt(&handle, &request, &artifact, TimestampNs(20))?;
    let cursor = ContinuationCursor::publish(
        ContinuationScope::EvidenceHydration, handle.handle_id.clone(), handle.contract_basis.clone(),
        request.session_id.clone(), HYDRATION_VIEW_ID, handle.anchor.clone(), handle.anchor.clone(),
        handle.ladder_policy_digest(), 2, 5, artifact.artifact_digest, None,
        TimestampNs(20), TimestampNs(70),
    )?;
    original.continuation = Some(cursor.clone());
    reseal_receipt(&mut original);
    original.validate_for(&request, &handle, Some(&artifact))?;
    for mutation in 0..6 {
        let mut changed = cursor.clone();
        match mutation {
            0 => changed.source_digest = ContentDigest::sha256(b"other ladder"),
            1 => changed.upper_bound = 6,
            2 => changed.selection_witness = ContentDigest::sha256(b"other artifact"),
            3 => changed.predecessor_digest = Some(ContentDigest::sha256(b"invented parent")),
            4 => changed.expires_at = TimestampNs(101),
            _ => changed.issued_at = TimestampNs(19),
        }
        changed.cursor_digest = changed.computed_digest();
        changed.cursor_id = format!("continuation:{}", changed.cursor_digest);
        let mut forged = original.clone();
        forged.continuation = Some(changed);
        reseal_receipt(&mut forged);
        assert_eq!(forged.validate_for(&request, &handle, Some(&artifact)),
            Err(HydrationError::WrongContinuation));
    }
    Ok(())
}
