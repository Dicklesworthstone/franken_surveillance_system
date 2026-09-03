use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    BudgetVector, CanonicalEncode, Completeness, ContentDigest, ContinuationCursor,
    ContinuationScope, ContractBasis, HandleAvailability, HydrationArtifact, HydrationError,
    HydrationLevel, HydrationPurpose, HydrationReceipt, HydrationReceiptSpec, HydrationRequest,
    HydrationRequestSpec, LaboratoryAccess, LedgerAnchor, SemanticHandle, SemanticHandleSpec,
    SessionId, TimestampNs, HYDRATION_VIEW_ID,
};

fn basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(
        b"schemas",
        b"operations",
        b"views",
        b"capabilities",
        b"errors",
        b"costs",
        "fss-hydration-cursor:test",
        None,
    )
}

fn handle() -> Result<SemanticHandle, HydrationError> {
    let levels = BTreeSet::from([
        HydrationLevel::H0,
        HydrationLevel::H1,
        HydrationLevel::H2,
    ]);
    SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: basis(),
        anchor: LedgerAnchor::genesis("site:hydration-cursor"),
        subject_id: "evidence:cursor".to_owned(),
        subject_digest: ContentDigest::sha256(b"cursor subject"),
        semantic_type: "evidence_bundle".to_owned(),
        source_id: "sensor:cursor".to_owned(),
        capture_interval: None,
        spatial_scope: None,
        privacy_class: "private:property".to_owned(),
        applied_transform: None,
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(1_000),
        levels: levels.clone(),
        required_capabilities: levels
            .iter()
            .copied()
            .map(|level| (level, BTreeSet::new()))
            .collect(),
        estimated_costs: levels
            .iter()
            .copied()
            .map(|level| (level, BudgetVector::default()))
            .collect(),
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })
}

fn request(handle: &SemanticHandle) -> Result<HydrationRequest, HydrationError> {
    HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:hydration-cursor")?,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: HydrationLevel::H1,
        allow_lower_level: false,
        available_capabilities: BTreeSet::new(),
        authorized_privacy_classes: BTreeSet::from(["private:property".to_owned()]),
        budget: BudgetVector::default(),
        purpose: HydrationPurpose::IncidentAdjudication,
        continuation: None,
        issued_at: TimestampNs(20),
    })
}

fn artifact(handle: &SemanticHandle) -> Result<HydrationArtifact, HydrationError> {
    HydrationArtifact::publish(
        HydrationLevel::H1,
        "application/fss+json",
        b"cursor artifact".to_vec(),
        [handle.subject_digest],
        Completeness::Complete,
        None,
    )
}

fn cursor(
    handle: &SemanticHandle,
    request: &HydrationRequest,
    artifact: &HydrationArtifact,
    stream_digest: ContentDigest,
    page_digest: ContentDigest,
    expires_at: TimestampNs,
) -> Result<ContinuationCursor, HydrationError> {
    Ok(ContinuationCursor::publish(
        ContinuationScope::EvidenceHydration,
        handle.handle_id.clone(),
        handle.contract_basis.clone(),
        request.session_id.clone(),
        HYDRATION_VIEW_ID,
        handle.anchor.clone(),
        handle.anchor.clone(),
        stream_digest,
        2,
        3,
        page_digest,
        None,
        request.issued_at,
        expires_at,
    )?)
}

fn receipt(
    handle: &SemanticHandle,
    request: &HydrationRequest,
    artifact: &HydrationArtifact,
    cursor: ContinuationCursor,
) -> Result<HydrationReceipt, HydrationError> {
    let mut proof_roots = artifact.proof_roots.clone();
    proof_roots.insert(artifact.artifact_digest);
    HydrationReceipt::publish(HydrationReceiptSpec {
        request_digest: request.request_digest,
        handle_id: handle.handle_id.clone(),
        descriptor_digest: handle.descriptor_digest,
        subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: HydrationLevel::H1,
        delivered_level: Some(HydrationLevel::H1),
        availability: HandleAvailability::Available,
        cost: BudgetVector::default(),
        completeness: Completeness::Complete,
        artifact_digest: Some(artifact.artifact_digest),
        proof_roots,
        continuation: Some(cursor),
        invalidators: BTreeSet::from(["descriptor-or-retention-change".to_owned()]),
        issued_at: request.issued_at,
    })
}

#[test]
fn cursor_cannot_rebind_ladder_policy() -> Result<(), HydrationError> {
    let handle = handle()?;
    let request = request(&handle)?;
    let artifact = artifact(&handle)?;
    let cursor = cursor(
        &handle,
        &request,
        &artifact,
        ContentDigest::sha256(b"other ladder"),
        artifact.artifact_digest,
        TimestampNs(500),
    )?;
    let receipt = receipt(&handle, &request, &artifact, cursor)?;

    assert_eq!(
        receipt.validate_for(&request, &handle, Some(&artifact)),
        Err(HydrationError::WrongContinuation)
    );
    Ok(())
}

#[test]
fn cursor_page_must_name_delivered_artifact() -> Result<(), HydrationError> {
    let handle = handle()?;
    let request = request(&handle)?;
    let artifact = artifact(&handle)?;
    let cursor = cursor(
        &handle,
        &request,
        &artifact,
        handle.ladder_policy_digest(),
        ContentDigest::sha256(b"other page"),
        TimestampNs(500),
    )?;
    let receipt = receipt(&handle, &request, &artifact, cursor)?;

    assert_eq!(
        receipt.validate_for(&request, &handle, Some(&artifact)),
        Err(HydrationError::WrongContinuation)
    );
    Ok(())
}

#[test]
fn cursor_cannot_outlive_exact_subject_retention() -> Result<(), HydrationError> {
    let handle = handle()?;
    let request = request(&handle)?;
    let artifact = artifact(&handle)?;
    let cursor = cursor(
        &handle,
        &request,
        &artifact,
        handle.ladder_policy_digest(),
        artifact.artifact_digest,
        TimestampNs(1_001),
    )?;
    let receipt = receipt(&handle, &request, &artifact, cursor)?;

    assert_eq!(
        receipt.validate_for(&request, &handle, Some(&artifact)),
        Err(HydrationError::WrongContinuation)
    );
    Ok(())
}

#[test]
fn cursor_digest_changes_with_semantic_binding() -> Result<(), HydrationError> {
    let handle = handle()?;
    let request = request(&handle)?;
    let artifact = artifact(&handle)?;
    let first = cursor(
        &handle,
        &request,
        &artifact,
        handle.ladder_policy_digest(),
        artifact.artifact_digest,
        TimestampNs(500),
    )?;
    let second = cursor(
        &handle,
        &request,
        &artifact,
        ContentDigest::sha256(b"other ladder"),
        artifact.artifact_digest,
        TimestampNs(500),
    )?;

    assert_ne!(
        first.canonical_digest("fss.hydration_cursor_test.v1"),
        second.canonical_digest("fss.hydration_cursor_test.v1")
    );
    Ok(())
}
