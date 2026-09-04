use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use fss_core::hydration::{
    HandleAvailability, HydrationArtifact, HydrationError, HydrationLevel, HydrationPurpose,
    HydrationRequest, HydrationRequestSpec, LaboratoryAccess, SemanticHandle, SemanticHandleSpec,
};
use fss_core::{
    BudgetVector, Completeness, ContentDigest, ContractBasis, ContractError, LedgerAnchor,
    SessionId, TimestampNs,
};

use crate::ReferenceHydrationCatalog;

fn basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(
        b"schemas",
        b"operations",
        b"views",
        b"capabilities",
        b"errors",
        b"costs",
        "fss-reference:test",
        Some("nightly-2026-08-31".to_owned()),
    )
}

fn anchor() -> LedgerAnchor {
    let mut anchor = LedgerAnchor::genesis("site:reference-hydration");
    anchor.commit_sequence = 7;
    anchor
}

fn level_set() -> BTreeSet<HydrationLevel> {
    [
        HydrationLevel::H0,
        HydrationLevel::H1,
        HydrationLevel::H2,
        HydrationLevel::H3,
        HydrationLevel::H4,
    ]
    .into_iter()
    .collect()
}

fn capabilities() -> BTreeMap<HydrationLevel, BTreeSet<String>> {
    level_set()
        .into_iter()
        .map(|level| {
            (
                level,
                BTreeSet::from([format!("capability:hydrate:{}", level.as_str())]),
            )
        })
        .collect()
}

fn cost(level: HydrationLevel) -> BudgetVector {
    let scale = u64::from(level.ordinal()) + 1;
    BudgetVector {
        latency_ms: scale * 10,
        tokens: scale * 100,
        bytes: scale * 1_000,
        cpu_millis: scale * 5,
        accelerator_millis: scale * 2,
        energy_millijoules: scale * 20,
        network_bytes: scale * 500,
        storage_operations: scale,
        privacy_exposure: scale as f64 / 10.0,
        operator_attention_seconds: scale as f64,
        ..BudgetVector::default()
    }
}

fn costs() -> BTreeMap<HydrationLevel, BudgetVector> {
    level_set()
        .into_iter()
        .map(|level| (level, cost(level)))
        .collect()
}

fn descriptor(
    availability: HandleAvailability,
    retention_until: TimestampNs,
) -> Result<SemanticHandle, HydrationError> {
    SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: basis(),
        anchor: anchor(),
        subject_id: "evidence:reference-hydration".to_owned(),
        subject_digest: ContentDigest::sha256(b"reference-hydration-subject"),
        semantic_type: "evidence_bundle".to_owned(),
        source_id: "sensor:rear-yard".to_owned(),
        capture_interval: None,
        spatial_scope: Some("zone:rear-yard".to_owned()),
        privacy_class: "private:property".to_owned(),
        applied_transform: None,
        availability,
        retention_until,
        levels: level_set(),
        required_capabilities: capabilities(),
        estimated_costs: costs(),
        laboratory_access: LaboratoryAccess::QualificationOrDebugGrant,
        debug_capability: Some("capability:hydrate:debug".to_owned()),
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })
}

fn catalog(
    availability: HandleAvailability,
    retention_until: TimestampNs,
) -> Result<(ReferenceHydrationCatalog, SemanticHandle), HydrationError> {
    let descriptor = descriptor(availability, retention_until)?;
    let mut catalog = ReferenceHydrationCatalog::new();
    catalog.register_descriptor(descriptor.clone())?;
    for level in level_set() {
        let artifact = HydrationArtifact::publish(
            level,
            if level >= HydrationLevel::H2 {
                "application/octet-stream"
            } else {
                "application/fss+json"
            },
            format!("artifact:{}", level.as_str()).into_bytes(),
            [descriptor.subject_digest],
            Completeness::Complete,
            None,
        )?;
        catalog.register_artifact(
            &descriptor.handle_id,
            descriptor.descriptor_digest,
            artifact,
        )?;
    }
    Ok((catalog, descriptor))
}

fn request(
    descriptor: &SemanticHandle,
    level: HydrationLevel,
    allow_lower_level: bool,
    budget: BudgetVector,
    capabilities: &[&str],
    purpose: HydrationPurpose,
) -> Result<HydrationRequest, HydrationError> {
    HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: descriptor.contract_basis.clone(),
        session_id: SessionId::parse("session:reference-hydration")?,
        handle_id: descriptor.handle_id.clone(),
        expected_descriptor_digest: descriptor.descriptor_digest,
        expected_subject_digest: descriptor.subject_digest,
        anchor: descriptor.anchor.clone(),
        requested_level: level,
        allow_lower_level,
        available_capabilities: capabilities
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        authorized_privacy_classes: BTreeSet::from([descriptor.privacy_class.clone()]),
        budget,
        purpose,
        continuation: None,
        issued_at: TimestampNs(100),
    })
}

fn ample_budget() -> BudgetVector {
    BudgetVector {
        latency_ms: 10_000,
        tokens: 100_000,
        bytes: 100_000_000,
        model_calls: 100,
        cpu_millis: 100_000,
        accelerator_millis: 100_000,
        energy_millijoules: 100_000_000,
        network_bytes: 100_000_000,
        storage_operations: 100_000,
        privacy_exposure: 100.0,
        operator_attention_seconds: 100_000.0,
    }
}

#[test]
fn exact_level_hydration_is_proof_bearing() -> Result<(), Box<dyn Error>> {
    let (catalog, descriptor) = catalog(HandleAvailability::Available, TimestampNs(10_000))?;
    let request = request(
        &descriptor,
        HydrationLevel::H2,
        false,
        ample_budget(),
        &["capability:hydrate:H2"],
        HydrationPurpose::IncidentAdjudication,
    )?;
    let response = catalog.hydrate(&request, TimestampNs(101))?;

    assert_eq!(response.receipt.delivered_level, Some(HydrationLevel::H2));
    assert_eq!(response.receipt.completeness, Completeness::Complete);
    assert!(response.receipt.continuation.is_some());
    assert!(
        response
            .receipt
            .proof_roots
            .contains(&descriptor.subject_digest)
    );
    response.validate_for(&request, &descriptor)?;
    Ok(())
}

#[test]
fn lower_level_delivery_is_explicit_and_bounded() -> Result<(), Box<dyn Error>> {
    let (catalog, descriptor) = catalog(HandleAvailability::Available, TimestampNs(10_000))?;
    let request = request(
        &descriptor,
        HydrationLevel::H3,
        true,
        cost(HydrationLevel::H1),
        &["capability:hydrate:H1"],
        HydrationPurpose::IncidentAdjudication,
    )?;
    let response = catalog.hydrate(&request, TimestampNs(101))?;

    assert_eq!(response.receipt.delivered_level, Some(HydrationLevel::H1));
    assert_eq!(response.receipt.completeness, Completeness::Bounded);
    assert!(
        response
            .receipt
            .invalidators
            .contains("explicit-downgrade:H3-to-H1")
    );
    Ok(())
}

#[test]
fn budget_failure_does_not_silently_downgrade() -> Result<(), Box<dyn Error>> {
    let (catalog, descriptor) = catalog(HandleAvailability::Available, TimestampNs(10_000))?;
    let request = request(
        &descriptor,
        HydrationLevel::H3,
        false,
        cost(HydrationLevel::H1),
        &["capability:hydrate:H3"],
        HydrationPurpose::IncidentAdjudication,
    )?;
    assert_eq!(
        catalog.hydrate(&request, TimestampNs(101)),
        Err(HydrationError::BudgetExceeded)
    );
    Ok(())
}

#[test]
fn privacy_and_capability_denials_are_distinct() -> Result<(), Box<dyn Error>> {
    let (catalog, descriptor) = catalog(HandleAvailability::Available, TimestampNs(10_000))?;
    let mut privacy_request = request(
        &descriptor,
        HydrationLevel::H1,
        false,
        ample_budget(),
        &["capability:hydrate:H1"],
        HydrationPurpose::Routine,
    )?;
    privacy_request.authorized_privacy_classes.clear();
    privacy_request.request_digest = privacy_request.computed_digest();
    privacy_request.request_id = format!("hydration-request:{}", privacy_request.request_digest);
    assert_eq!(
        catalog.hydrate(&privacy_request, TimestampNs(101)),
        Err(HydrationError::PrivacyDenied)
    );

    let capability_request = request(
        &descriptor,
        HydrationLevel::H1,
        false,
        ample_budget(),
        &[],
        HydrationPurpose::Routine,
    )?;
    assert_eq!(
        catalog.hydrate(&capability_request, TimestampNs(101)),
        Err(HydrationError::CapabilityDenied)
    );
    Ok(())
}

#[test]
fn expired_subject_returns_typed_unavailability() -> Result<(), Box<dyn Error>> {
    let (catalog, descriptor) = catalog(HandleAvailability::Available, TimestampNs(100))?;
    let request = request(
        &descriptor,
        HydrationLevel::H2,
        false,
        ample_budget(),
        &["capability:hydrate:H2"],
        HydrationPurpose::IncidentAdjudication,
    )?;
    let response = catalog.hydrate(&request, TimestampNs(101))?;

    assert!(response.artifact.is_none());
    assert_eq!(response.receipt.availability, HandleAvailability::Expired);
    assert_eq!(response.receipt.completeness, Completeness::Stale);
    assert_eq!(response.receipt.cost, BudgetVector::default());
    Ok(())
}

#[test]
fn h4_requires_qualification_or_explicit_debug_grant() -> Result<(), Box<dyn Error>> {
    let (catalog, descriptor) = catalog(HandleAvailability::Available, TimestampNs(10_000))?;
    let routine = request(
        &descriptor,
        HydrationLevel::H4,
        false,
        ample_budget(),
        &["capability:hydrate:H4"],
        HydrationPurpose::Routine,
    )?;
    assert_eq!(
        catalog.hydrate(&routine, TimestampNs(101)),
        Err(HydrationError::LaboratoryGrantRequired)
    );

    let qualification = request(
        &descriptor,
        HydrationLevel::H4,
        false,
        ample_budget(),
        &["capability:hydrate:H4"],
        HydrationPurpose::Qualification,
    )?;
    assert_eq!(
        catalog
            .hydrate(&qualification, TimestampNs(101))?
            .receipt
            .delivered_level,
        Some(HydrationLevel::H4)
    );

    let debugging = request(
        &descriptor,
        HydrationLevel::H4,
        false,
        ample_budget(),
        &["capability:hydrate:H4", "capability:hydrate:debug"],
        HydrationPurpose::Debugging,
    )?;
    assert_eq!(
        catalog
            .hydrate(&debugging, TimestampNs(101))?
            .receipt
            .delivered_level,
        Some(HydrationLevel::H4)
    );
    Ok(())
}

#[test]
fn continuation_is_exactly_bound_to_the_next_level() -> Result<(), Box<dyn Error>> {
    let (catalog, descriptor) = catalog(HandleAvailability::Available, TimestampNs(10_000))?;
    let first = request(
        &descriptor,
        HydrationLevel::H1,
        false,
        ample_budget(),
        &["capability:hydrate:H1"],
        HydrationPurpose::IncidentAdjudication,
    )?;
    let first_response = catalog.hydrate(&first, TimestampNs(101))?;
    let cursor = first_response
        .receipt
        .continuation
        .clone()
        .ok_or(ContractError::NotFound)?;
    let second = HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: descriptor.contract_basis.clone(),
        session_id: first.session_id.clone(),
        handle_id: descriptor.handle_id.clone(),
        expected_descriptor_digest: descriptor.descriptor_digest,
        expected_subject_digest: descriptor.subject_digest,
        anchor: descriptor.anchor.clone(),
        requested_level: HydrationLevel::H2,
        allow_lower_level: false,
        available_capabilities: BTreeSet::from(["capability:hydrate:H2".to_owned()]),
        authorized_privacy_classes: BTreeSet::from([descriptor.privacy_class.clone()]),
        budget: ample_budget(),
        purpose: HydrationPurpose::IncidentAdjudication,
        continuation: Some(cursor),
        issued_at: TimestampNs(102),
    })?;
    assert_eq!(
        catalog
            .hydrate(&second, TimestampNs(103))?
            .receipt
            .delivered_level,
        Some(HydrationLevel::H2)
    );
    Ok(())
}

#[test]
fn stale_descriptor_revision_is_not_retargeted() -> Result<(), Box<dyn Error>> {
    let (catalog, descriptor) = catalog(HandleAvailability::Available, TimestampNs(10_000))?;
    let mut request = request(
        &descriptor,
        HydrationLevel::H1,
        false,
        ample_budget(),
        &["capability:hydrate:H1"],
        HydrationPurpose::Routine,
    )?;
    request.expected_descriptor_digest = ContentDigest::sha256(b"newer-descriptor");
    request.request_digest = request.computed_digest();
    request.request_id = format!("hydration-request:{}", request.request_digest);
    assert_eq!(
        catalog.hydrate(&request, TimestampNs(101)),
        Err(HydrationError::DescriptorNotFound)
    );
    Ok(())
}
