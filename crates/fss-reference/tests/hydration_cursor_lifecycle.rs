#![forbid(unsafe_code)]
//! Public-API regressions for bounded, single-use hydration continuations.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use fss_core::hydration::{
    HandleAvailability, HydrationArtifact, HydrationError, HydrationLevel, HydrationPurpose,
    HydrationRequest, HydrationRequestSpec, LaboratoryAccess, SemanticHandle, SemanticHandleSpec,
};
use fss_core::{
    BudgetVector, Completeness, ContentDigest, ContinuationCursor, ContractBasis,
    ContractBasisRegistryBytes, ContractError, LedgerAnchor, SessionId, TimestampNs,
};
use fss_reference::{ReferenceHydrationCatalog, ReferenceHydrationLimits};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn cost(level: HydrationLevel) -> Result<BudgetVector, HydrationError> {
    let scale = u64::from(level.ordinal()) + 1;
    BudgetVector::builder()
        .latency_ms(scale * 10)
        .tokens(scale * 100)
        .bytes(scale * 1_000)
        .cpu_millis(scale * 5)
        .accelerator_millis(scale * 2)
        .energy_millijoules(scale * 20)
        .network_bytes(scale * 500)
        .storage_operations(scale)
        .privacy_exposure(scale as f64 / 10.0)
        .operator_attention_seconds(scale as f64)
        .build()
        .map_err(|error| HydrationError::Contract(ContractError::from(error)))
}

fn add_subject(
    catalog: &mut ReferenceHydrationCatalog,
    name: &str,
    retention_until: TimestampNs,
    last_artifact: HydrationLevel,
) -> TestResult<SemanticHandle> {
    let basis = ContractBasis::from_registry_bytes(
        ContractBasisRegistryBytes::new(
            b"schemas",
            b"operations",
            b"views",
            b"capabilities",
            b"errors",
            b"costs",
            "fss-reference:cursor-lifecycle",
        )
        .with_accepted_nightly("nightly-2026-08-31"),
    );
    let mut anchor = LedgerAnchor::genesis("site:cursor-lifecycle");
    anchor.commit_sequence = 7;
    let levels = BTreeSet::from([
        HydrationLevel::H0,
        HydrationLevel::H1,
        HydrationLevel::H2,
        HydrationLevel::H3,
        HydrationLevel::H4,
    ]);
    let mut estimated_costs = BTreeMap::new();
    let mut required_capabilities = BTreeMap::new();
    for level in &levels {
        estimated_costs.insert(*level, cost(*level)?);
        required_capabilities.insert(
            *level,
            BTreeSet::from([format!("capability:hydrate:{}", level.as_str())]),
        );
    }
    let descriptor = SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: basis,
        anchor,
        subject_id: format!("evidence:{name}"),
        subject_digest: ContentDigest::sha256(name.as_bytes()),
        semantic_type: "evidence_bundle".to_owned(),
        source_id: "sensor:cursor-lifecycle".to_owned(),
        capture_interval: None,
        spatial_scope: Some("zone:rear-yard".to_owned()),
        privacy_class: "private:property".to_owned(),
        applied_transform: None,
        availability: HandleAvailability::Available,
        retention_until,
        levels: levels.clone(),
        required_capabilities,
        estimated_costs,
        laboratory_access: LaboratoryAccess::QualificationOrDebugGrant,
        debug_capability: Some("capability:hydrate:debug".to_owned()),
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })?;
    catalog.register_descriptor(descriptor.clone())?;
    for level in levels.into_iter().filter(|level| *level <= last_artifact) {
        // These tests stop at H2; no laboratory artifact or authority is fabricated.
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
    Ok(descriptor)
}

fn fixture(
    capacity: usize,
    last_artifact: HydrationLevel,
) -> TestResult<(ReferenceHydrationCatalog, SemanticHandle)> {
    let mut catalog = ReferenceHydrationCatalog::with_limits(ReferenceHydrationLimits {
        max_issued_cursors: capacity,
        ..ReferenceHydrationLimits::default()
    });
    let descriptor = add_subject(&mut catalog, "first", TimestampNs(200), last_artifact)?;
    Ok((catalog, descriptor))
}

fn request(
    descriptor: &SemanticHandle,
    level: HydrationLevel,
    continuation: Option<ContinuationCursor>,
    now: TimestampNs,
) -> TestResult<HydrationRequest> {
    Ok(HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: descriptor.contract_basis.clone(),
        session_id: SessionId::parse("session:cursor-lifecycle")?,
        handle_id: descriptor.handle_id.clone(),
        expected_descriptor_digest: descriptor.descriptor_digest,
        expected_subject_digest: descriptor.subject_digest,
        anchor: descriptor.anchor.clone(),
        requested_level: level,
        allow_lower_level: false,
        available_capabilities: BTreeSet::from([format!("capability:hydrate:{}", level.as_str())]),
        authorized_privacy_classes: BTreeSet::from([descriptor.privacy_class.clone()]),
        budget: cost(HydrationLevel::H4)?,
        purpose: HydrationPurpose::IncidentAdjudication,
        continuation,
        issued_at: now,
    })?)
}

#[test]
fn active_exact_retry_reuses_capacity_and_receipt() -> TestResult {
    let (mut catalog, descriptor) = fixture(1, HydrationLevel::H2)?;
    let read = request(&descriptor, HydrationLevel::H0, None, TimestampNs(100))?;
    let first = catalog.hydrate(&read, TimestampNs(100))?;
    assert_eq!(catalog.hydrate(&read, TimestampNs(100))?, first);
    assert_eq!(catalog.issued_cursor_count(), 1);
    Ok(())
}

#[test]
fn same_clock_tick_cannot_resurrect_a_consumed_cursor() -> TestResult {
    let (mut catalog, descriptor) = fixture(8, HydrationLevel::H2)?;
    let first = request(&descriptor, HydrationLevel::H0, None, TimestampNs(100))?;
    let cursor = catalog
        .hydrate(&first, TimestampNs(100))?
        .receipt
        .continuation
        .ok_or(ContractError::NotFound)?;
    let next = request(
        &descriptor,
        HydrationLevel::H1,
        Some(cursor.clone()),
        TimestampNs(100),
    )?;
    catalog.hydrate(&next, TimestampNs(100))?;
    assert_eq!(
        catalog.hydrate(&first, TimestampNs(100)),
        Err(HydrationError::ContinuationAlreadyConsumed),
    );
    assert!(
        catalog
            .issued_cursor(&cursor.cursor_digest)
            .ok_or(ContractError::NotFound)?
            .consumed
    );
    assert_eq!(
        catalog.hydrate(&next, TimestampNs(100)),
        Err(HydrationError::ContinuationAlreadyConsumed),
    );
    assert_eq!(catalog.issued_cursor_count(), 2);
    Ok(())
}

#[test]
fn consumed_cleanup_keeps_unexpired_replay_tombstones() -> TestResult {
    let (mut catalog, descriptor) = fixture(8, HydrationLevel::H2)?;
    let first = request(&descriptor, HydrationLevel::H0, None, TimestampNs(100))?;
    let cursor = catalog
        .hydrate(&first, TimestampNs(100))?
        .receipt
        .continuation
        .ok_or(ContractError::NotFound)?;
    let next = request(
        &descriptor,
        HydrationLevel::H1,
        Some(cursor.clone()),
        TimestampNs(100),
    )?;
    catalog.hydrate(&next, TimestampNs(100))?;
    catalog.prune_consumed_cursors();
    catalog.prune_expired_cursors(TimestampNs(100));
    assert!(
        catalog
            .issued_cursor(&cursor.cursor_digest)
            .ok_or(ContractError::NotFound)?
            .consumed
    );
    assert_eq!(catalog.issued_cursor_count(), 2);
    assert_eq!(
        catalog.hydrate(&first, TimestampNs(100)),
        Err(HydrationError::ContinuationAlreadyConsumed),
    );
    Ok(())
}

#[test]
fn capacity_refusal_does_not_consume_or_forget_the_predecessor() -> TestResult {
    let (mut catalog, descriptor) = fixture(1, HydrationLevel::H2)?;
    let first = request(&descriptor, HydrationLevel::H0, None, TimestampNs(100))?;
    let response = catalog.hydrate(&first, TimestampNs(100))?;
    let cursor = response
        .receipt
        .continuation
        .clone()
        .ok_or(ContractError::NotFound)?;
    let before = catalog.issued_cursor(&cursor.cursor_digest).cloned();
    let next = request(
        &descriptor,
        HydrationLevel::H1,
        Some(cursor.clone()),
        TimestampNs(100),
    )?;
    for _ in 0..3 {
        assert_eq!(
            catalog.hydrate(&next, TimestampNs(100)),
            Err(HydrationError::CapacityExceeded)
        );
        assert_eq!(
            catalog.issued_cursor(&cursor.cursor_digest).cloned(),
            before
        );
        assert_eq!(catalog.issued_cursor_count(), 1);
    }
    assert_eq!(catalog.hydrate(&first, TimestampNs(100))?, response);
    Ok(())
}

#[test]
fn terminal_delivery_can_consume_at_capacity_without_forgetting_history() -> TestResult {
    let (mut catalog, descriptor) = fixture(1, HydrationLevel::H1)?;
    let first = request(&descriptor, HydrationLevel::H0, None, TimestampNs(100))?;
    let cursor = catalog
        .hydrate(&first, TimestampNs(100))?
        .receipt
        .continuation
        .ok_or(ContractError::NotFound)?;
    let next = request(
        &descriptor,
        HydrationLevel::H1,
        Some(cursor.clone()),
        TimestampNs(100),
    )?;
    let response = catalog.hydrate(&next, TimestampNs(100))?;
    assert_eq!(response.receipt.delivered_level, Some(HydrationLevel::H1));
    assert!(response.receipt.continuation.is_none());
    assert!(
        catalog
            .issued_cursor(&cursor.cursor_digest)
            .ok_or(ContractError::NotFound)?
            .consumed
    );
    assert_eq!(catalog.issued_cursor_count(), 1);
    assert_eq!(
        catalog.hydrate(&next, TimestampNs(100)),
        Err(HydrationError::ContinuationAlreadyConsumed)
    );
    Ok(())
}

#[test]
fn expiry_reclaims_capacity_but_pressure_does_not() -> TestResult {
    let (mut catalog, first_descriptor) = fixture(1, HydrationLevel::H1)?;
    let second_descriptor =
        add_subject(&mut catalog, "second", TimestampNs(300), HydrationLevel::H1)?;
    let first = request(
        &first_descriptor,
        HydrationLevel::H0,
        None,
        TimestampNs(100),
    )?;
    let old = catalog
        .hydrate(&first, TimestampNs(100))?
        .receipt
        .continuation
        .ok_or(ContractError::NotFound)?;
    let blocked = request(
        &second_descriptor,
        HydrationLevel::H0,
        None,
        TimestampNs(199),
    )?;
    assert_eq!(
        catalog.hydrate(&blocked, TimestampNs(199)),
        Err(HydrationError::CapacityExceeded)
    );
    assert!(catalog.issued_cursor(&old.cursor_digest).is_some());
    let fresh = request(
        &second_descriptor,
        HydrationLevel::H0,
        None,
        TimestampNs(200),
    )?;
    let new = catalog
        .hydrate(&fresh, TimestampNs(200))?
        .receipt
        .continuation
        .ok_or(ContractError::NotFound)?;
    assert!(catalog.issued_cursor(&old.cursor_digest).is_none());
    assert!(catalog.issued_cursor(&new.cursor_digest).is_some());
    assert_eq!(catalog.issued_cursor_count(), 1);
    Ok(())
}

#[test]
fn zero_cursor_capacity_still_allows_terminal_artifacts() -> TestResult {
    let (mut catalog, descriptor) = fixture(0, HydrationLevel::H2)?;
    let first = request(&descriptor, HydrationLevel::H0, None, TimestampNs(100))?;
    assert_eq!(
        catalog.hydrate(&first, TimestampNs(100)),
        Err(HydrationError::CapacityExceeded)
    );
    let terminal = request(&descriptor, HydrationLevel::H2, None, TimestampNs(100))?;
    assert_eq!(
        catalog
            .hydrate(&terminal, TimestampNs(100))?
            .receipt
            .delivered_level,
        Some(HydrationLevel::H2)
    );
    assert_eq!(catalog.issued_cursor_count(), 0);
    Ok(())
}
