use super::*;

fn basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(
        b"schemas",
        b"operations",
        b"views",
        b"capabilities",
        b"errors",
        b"costs",
        "fss:test",
        None,
    )
}

fn anchor(sequence: u64) -> LedgerAnchor {
    let mut anchor = LedgerAnchor::genesis("site:hydration");
    anchor.commit_sequence = sequence;
    anchor
}

fn levels(maximum: HydrationLevel) -> BTreeSet<HydrationLevel> {
    (0..=maximum.ordinal())
        .filter_map(HydrationLevel::from_ordinal)
        .collect()
}

fn capabilities(maximum: HydrationLevel) -> BTreeMap<HydrationLevel, BTreeSet<String>> {
    levels(maximum)
        .into_iter()
        .map(|level| {
            (
                level,
                BTreeSet::from([format!("capability:hydrate:{}", level.as_str())]),
            )
        })
        .collect()
}

fn costs(maximum: HydrationLevel) -> BTreeMap<HydrationLevel, BudgetVector> {
    levels(maximum)
        .into_iter()
        .map(|level| {
            let scale = u64::from(level.ordinal()) + 1;
            (
                level,
                BudgetVector {
                    latency_ms: scale * 10,
                    tokens: scale * 100,
                    bytes: scale * 1_000,
                    cpu_millis: scale * 5,
                    privacy_exposure: scale as f64 / 10.0,
                    ..BudgetVector::default()
                },
            )
        })
        .collect()
}

fn handle(
    availability: HandleAvailability,
    sequence: u64,
) -> Result<SemanticHandle, HydrationError> {
    SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: basis(),
        anchor: anchor(sequence),
        subject_id: "evidence:hydration:test".to_owned(),
        subject_digest: ContentDigest::sha256(b"subject"),
        semantic_type: "evidence_bundle".to_owned(),
        source_id: "sensor:test".to_owned(),
        capture_interval: Some(CaptureInterval::new(TimestampNs(10), TimestampNs(20))?),
        spatial_scope: Some("zone:rear".to_owned()),
        privacy_class: "private:property".to_owned(),
        applied_transform: None,
        availability,
        retention_until: TimestampNs(10_000),
        levels: levels(HydrationLevel::H4),
        required_capabilities: capabilities(HydrationLevel::H4),
        estimated_costs: costs(HydrationLevel::H4),
        laboratory_access: LaboratoryAccess::QualificationOrDebugGrant,
        debug_capability: Some("capability:hydrate:debug".to_owned()),
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })
}

#[test]
fn descriptor_revisions_preserve_immutable_handle_identity() -> Result<(), HydrationError> {
    let available = handle(HandleAvailability::Available, 1)?;
    let expired = handle(HandleAvailability::Expired, 2)?;
    assert_eq!(available.handle_id, expired.handle_id);
    assert_ne!(available.descriptor_digest, expired.descriptor_digest);
    available.verify()?;
    expired.verify()
}

#[test]
fn ladders_must_be_contiguous() -> Result<(), HydrationError> {
    let mut spec = SemanticHandleSpec {
        contract_basis: basis(),
        anchor: anchor(1),
        subject_id: "evidence:gap".to_owned(),
        subject_digest: ContentDigest::sha256(b"gap"),
        semantic_type: "evidence_bundle".to_owned(),
        source_id: "sensor:test".to_owned(),
        capture_interval: None,
        spatial_scope: None,
        privacy_class: "private:property".to_owned(),
        applied_transform: None,
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(100),
        levels: BTreeSet::from([HydrationLevel::H0, HydrationLevel::H2]),
        required_capabilities: BTreeMap::new(),
        estimated_costs: BTreeMap::new(),
        laboratory_access: LaboratoryAccess::Unavailable,
        debug_capability: None,
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    };
    for level in spec.levels.iter().copied() {
        spec.required_capabilities.insert(level, BTreeSet::new());
        spec.estimated_costs.insert(level, BudgetVector::default());
    }
    assert_eq!(
        SemanticHandle::publish(spec),
        Err(HydrationError::LevelUnavailable)
    );
    Ok(())
}

#[test]
fn request_cursor_is_bound_to_handle_session_and_level() -> Result<(), HydrationError> {
    let handle = handle(HandleAvailability::Available, 1)?;
    let cursor = ContinuationCursor::publish(
        ContinuationScope::EvidenceHydration,
        handle.handle_id.clone(),
        handle.contract_basis.clone(),
        SessionId::parse("session:hydration")?,
        HYDRATION_VIEW_ID,
        handle.anchor.clone(),
        handle.anchor.clone(),
        handle.ladder_policy_digest(),
        2,
        5,
        handle.descriptor_digest,
        None,
        TimestampNs(10),
        TimestampNs(100),
    )?;
    let request = HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:hydration")?,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: HydrationLevel::H2,
        allow_lower_level: false,
        available_capabilities: BTreeSet::new(),
        authorized_privacy_classes: BTreeSet::new(),
        budget: BudgetVector::default(),
        purpose: HydrationPurpose::IncidentAdjudication,
        continuation: Some(cursor),
        issued_at: TimestampNs(20),
    })?;
    request.verify()
}

#[test]
fn artifact_tampering_is_detected() -> Result<(), HydrationError> {
    let mut artifact = HydrationArtifact::publish(
        HydrationLevel::H1,
        "application/fss+json",
        b"semantic synopsis".to_vec(),
        [ContentDigest::sha256(b"evidence proof")],
        Completeness::Complete,
        None,
    )?;
    artifact.payload.push(0);
    assert!(matches!(
        artifact.verify(),
        Err(HydrationError::Contract(ContractError::DigestMismatch))
    ));
    Ok(())
}

#[test]
fn payload_integrity_is_not_sufficient_provenance() {
    assert_eq!(
        HydrationArtifact::publish(
            HydrationLevel::H1,
            "application/fss+json",
            b"unproven synopsis".to_vec(),
            [],
            Completeness::Complete,
            None,
        ),
        Err(HydrationError::Contract(ContractError::EvidenceRequired))
    );
}
