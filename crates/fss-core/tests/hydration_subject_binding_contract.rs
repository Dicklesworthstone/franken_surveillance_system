use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    BudgetVector, Completeness, ContentDigest, ContractBasis, ContractError, HandleAvailability,
    HydrationArtifact, HydrationError, HydrationLevel, HydrationPurpose, HydrationReceipt,
    HydrationReceiptSpec, HydrationRequest, HydrationRequestSpec, LaboratoryAccess, LedgerAnchor,
    SemanticHandle, SemanticHandleSpec, SessionId, TimestampNs,
};

fn basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(
        b"schemas",
        b"operations",
        b"views",
        b"capabilities",
        b"errors",
        b"costs",
        "fss-hydration-subject:test",
        None,
    )
}

fn handle() -> Result<SemanticHandle, HydrationError> {
    SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: basis(),
        anchor: LedgerAnchor::genesis("site:hydration-subject"),
        subject_id: "evidence:subject-binding".to_owned(),
        subject_digest: ContentDigest::sha256(b"redacted subject"),
        semantic_type: "evidence_bundle".to_owned(),
        source_id: "sensor:subject-binding".to_owned(),
        capture_interval: None,
        spatial_scope: None,
        privacy_class: "private:redacted".to_owned(),
        applied_transform: Some("redaction:faces:v1".to_owned()),
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(1_000),
        levels: BTreeSet::from([HydrationLevel::H0]),
        required_capabilities: BTreeMap::from([(HydrationLevel::H0, BTreeSet::new())]),
        estimated_costs: BTreeMap::from([(HydrationLevel::H0, BudgetVector::default())]),
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(10),
    })
}

fn request(
    handle: &SemanticHandle,
    issued_at: TimestampNs,
) -> Result<HydrationRequest, HydrationError> {
    HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:hydration-subject")?,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: HydrationLevel::H0,
        allow_lower_level: false,
        available_capabilities: BTreeSet::new(),
        authorized_privacy_classes: BTreeSet::from(["private:redacted".to_owned()]),
        budget: BudgetVector::default(),
        purpose: HydrationPurpose::IncidentAdjudication,
        continuation: None,
        issued_at,
    })
}

fn receipt(
    handle: &SemanticHandle,
    request: &HydrationRequest,
    artifact: &HydrationArtifact,
) -> Result<HydrationReceipt, HydrationError> {
    let mut proof_roots = artifact.proof_roots.clone();
    proof_roots.insert(artifact.artifact_digest);
    HydrationReceipt::publish(HydrationReceiptSpec {
        request_digest: request.request_digest,
        handle_id: handle.handle_id.clone(),
        descriptor_digest: handle.descriptor_digest,
        subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: HydrationLevel::H0,
        delivered_level: Some(HydrationLevel::H0),
        availability: HandleAvailability::Available,
        cost: BudgetVector::default(),
        completeness: Completeness::Complete,
        artifact_digest: Some(artifact.artifact_digest),
        proof_roots,
        continuation: None,
        invalidators: BTreeSet::from(["descriptor-or-transform-change".to_owned()]),
        issued_at: request.issued_at,
    })
}

#[test]
fn request_cannot_predate_descriptor_publication() -> Result<(), HydrationError> {
    let handle = handle()?;
    let request = request(&handle, TimestampNs(9))?;
    let artifact = HydrationArtifact::publish(
        HydrationLevel::H0,
        "application/fss+json",
        b"metadata".to_vec(),
        [handle.subject_digest],
        Completeness::Complete,
        handle.applied_transform.clone(),
    )?;
    let receipt = receipt(&handle, &request, &artifact)?;

    assert_eq!(
        receipt.validate_for(&request, &handle, Some(&artifact)),
        Err(HydrationError::Contract(ContractError::StaleAnchor))
    );
    Ok(())
}

#[test]
fn artifact_transform_must_match_exact_subject() -> Result<(), HydrationError> {
    let handle = handle()?;
    let request = request(&handle, TimestampNs(20))?;
    let artifact = HydrationArtifact::publish(
        HydrationLevel::H0,
        "application/fss+json",
        b"metadata".to_vec(),
        [handle.subject_digest],
        Completeness::Complete,
        None,
    )?;
    let receipt = receipt(&handle, &request, &artifact)?;

    assert!(matches!(
        receipt.validate_for(&request, &handle, Some(&artifact)),
        Err(HydrationError::Contract(ContractError::DigestMismatch))
    ));
    Ok(())
}

#[test]
fn artifact_must_retain_exact_subject_root() -> Result<(), HydrationError> {
    let handle = handle()?;
    let request = request(&handle, TimestampNs(20))?;
    let artifact = HydrationArtifact::publish(
        HydrationLevel::H0,
        "application/fss+json",
        b"metadata".to_vec(),
        [ContentDigest::sha256(b"unrelated provenance")],
        Completeness::Complete,
        handle.applied_transform.clone(),
    )?;
    let receipt = receipt(&handle, &request, &artifact)?;

    assert!(matches!(
        receipt.validate_for(&request, &handle, Some(&artifact)),
        Err(HydrationError::Contract(ContractError::DigestMismatch))
    ));
    Ok(())
}
