#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    BudgetVector, Completeness, ContentDigest, ContinuationCursor, ContinuationScope,
    ContractBasis, ContractError, HYDRATION_VIEW_ID, HandleAvailability, HydrationArtifact,
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
        "fss-hydration-contract:test",
        None,
    )
}

fn anchor() -> LedgerAnchor {
    let mut anchor = LedgerAnchor::genesis("site:hydration-contract");
    anchor.commit_sequence = 7;
    anchor
}

fn levels() -> BTreeSet<HydrationLevel> {
    BTreeSet::from([HydrationLevel::H0, HydrationLevel::H1, HydrationLevel::H2])
}

fn capabilities() -> BTreeMap<HydrationLevel, BTreeSet<String>> {
    BTreeMap::from([
        (
            HydrationLevel::H0,
            BTreeSet::from(["capability:hydrate:h0".to_owned()]),
        ),
        (
            HydrationLevel::H1,
            BTreeSet::from(["capability:hydrate:h1".to_owned()]),
        ),
        (
            HydrationLevel::H2,
            BTreeSet::from(["capability:hydrate:h2".to_owned()]),
        ),
    ])
}

fn costs() -> BTreeMap<HydrationLevel, BudgetVector> {
    BTreeMap::from([
        (
            HydrationLevel::H0,
            BudgetVector {
                latency_ms: 5,
                tokens: 32,
                bytes: 256,
                cpu_millis: 1,
                ..BudgetVector::default()
            },
        ),
        (
            HydrationLevel::H1,
            BudgetVector {
                latency_ms: 10,
                tokens: 128,
                bytes: 1_024,
                cpu_millis: 2,
                privacy_exposure: 0.1,
                ..BudgetVector::default()
            },
        ),
        (
            HydrationLevel::H2,
            BudgetVector {
                latency_ms: 20,
                tokens: 256,
                bytes: 4_096,
                cpu_millis: 4,
                privacy_exposure: 0.2,
                ..BudgetVector::default()
            },
        ),
    ])
}

fn handle() -> Result<SemanticHandle, HydrationError> {
    SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: basis(),
        anchor: anchor(),
        subject_id: "evidence:hydration-contract".to_owned(),
        subject_digest: ContentDigest::sha256(b"immutable subject"),
        semantic_type: "evidence_bundle".to_owned(),
        source_id: "sensor:hydration-contract".to_owned(),
        capture_interval: None,
        spatial_scope: Some("zone:rear".to_owned()),
        privacy_class: "private:property".to_owned(),
        applied_transform: None,
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(10_000),
        levels: levels(),
        required_capabilities: capabilities(),
        estimated_costs: costs(),
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })
}

fn make_request(
    handle: &SemanticHandle,
    level: HydrationLevel,
    continuation: Option<ContinuationCursor>,
) -> Result<HydrationRequest, HydrationError> {
    HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:hydration-contract")?,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: level,
        allow_lower_level: false,
        available_capabilities: capabilities().into_values().flatten().collect(),
        authorized_privacy_classes: BTreeSet::from(["private:property".to_owned()]),
        budget: costs()
            .get(&level)
            .copied()
            .ok_or(HydrationError::LevelUnavailable)?,
        purpose: HydrationPurpose::IncidentAdjudication,
        continuation,
        issued_at: TimestampNs(20),
    })
}

#[test]
fn public_receipt_closes_over_request_handle_and_artifact() -> Result<(), HydrationError> {
    let handle = handle()?;
    let request = make_request(&handle, HydrationLevel::H1, None)?;
    let artifact = HydrationArtifact::publish(
        HydrationLevel::H1,
        "application/fss+json",
        b"bounded semantic synopsis".to_vec(),
        [handle.subject_digest],
        Completeness::Complete,
        None,
    )?;
    let cursor = ContinuationCursor::publish(
        ContinuationScope::EvidenceHydration,
        handle.handle_id.clone(),
        handle.contract_basis.clone(),
        request.session_id.clone(),
        HYDRATION_VIEW_ID,
        handle.anchor.clone(),
        handle.anchor.clone(),
        handle.ladder_policy_digest(),
        2,
        3,
        artifact.artifact_digest,
        None,
        TimestampNs(20),
        TimestampNs(1_000),
    )?;
    let mut proof_roots = artifact.proof_roots.clone();
    proof_roots.insert(artifact.artifact_digest);
    proof_roots.insert(handle.descriptor_digest);
    proof_roots.insert(request.request_digest);
    let receipt = HydrationReceipt::publish(HydrationReceiptSpec {
        request_digest: request.request_digest,
        handle_id: handle.handle_id.clone(),
        descriptor_digest: handle.descriptor_digest,
        subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: HydrationLevel::H1,
        delivered_level: Some(HydrationLevel::H1),
        availability: HandleAvailability::Available,
        cost: handle
            .estimated_cost(HydrationLevel::H1)
            .ok_or(HydrationError::LevelUnavailable)?,
        completeness: Completeness::Complete,
        artifact_digest: Some(artifact.artifact_digest),
        proof_roots,
        continuation: Some(cursor.clone()),
        invalidators: BTreeSet::from([
            format!("descriptor:{}", handle.descriptor_digest),
            "retention-expiry".to_owned(),
        ]),
        issued_at: TimestampNs(20),
    })?;

    receipt.validate_for(&request, &handle, Some(&artifact))?;
    let next = make_request(&handle, HydrationLevel::H2, Some(cursor))?;
    next.verify()?;
    Ok(())
}

#[test]
fn receipt_rejects_subject_substitution() -> Result<(), HydrationError> {
    let handle = handle()?;
    let request = make_request(&handle, HydrationLevel::H0, None)?;
    let artifact = HydrationArtifact::publish(
        HydrationLevel::H0,
        "application/fss+json",
        b"identity metadata".to_vec(),
        [handle.subject_digest],
        Completeness::Complete,
        None,
    )?;
    let mut proof_roots = artifact.proof_roots.clone();
    proof_roots.insert(artifact.artifact_digest);
    proof_roots.insert(handle.descriptor_digest);
    proof_roots.insert(request.request_digest);
    let mut receipt = HydrationReceipt::publish(HydrationReceiptSpec {
        request_digest: request.request_digest,
        handle_id: handle.handle_id.clone(),
        descriptor_digest: handle.descriptor_digest,
        subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: HydrationLevel::H0,
        delivered_level: Some(HydrationLevel::H0),
        availability: HandleAvailability::Available,
        cost: handle
            .estimated_cost(HydrationLevel::H0)
            .ok_or(HydrationError::LevelUnavailable)?,
        completeness: Completeness::Complete,
        artifact_digest: Some(artifact.artifact_digest),
        proof_roots,
        continuation: None,
        invalidators: BTreeSet::from(["descriptor-revision".to_owned()]),
        issued_at: TimestampNs(20),
    })?;
    receipt.subject_digest = ContentDigest::sha256(b"substituted subject");

    assert!(matches!(
        receipt.validate_for(&request, &handle, Some(&artifact)),
        Err(HydrationError::Contract(ContractError::DigestMismatch))
    ));
    Ok(())
}
