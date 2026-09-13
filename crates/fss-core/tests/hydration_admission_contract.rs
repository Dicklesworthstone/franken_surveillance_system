//! Contract tests for hydration admission control and validation.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    AlternateSystem, BudgetVector, Completeness, ContentDigest, ContinuationCursor,
    ContinuationCursorPublishParams, ContinuationScope, ContractBasis, ContractBasisRegistryBytes,
    ContractError, H4LaboratoryExpansion, H4LaboratoryExpansionParams, HYDRATION_VIEW_ID,
    HandleAvailability, HydrationArtifact, HydrationError, HydrationLevel, HydrationPurpose,
    HydrationReceipt, HydrationReceiptSpec, HydrationRequest, HydrationRequestSpec,
    IntermediateArtifact, LaboratoryAccess, LaboratoryQuarantine, LedgerAnchor, OracleComparison,
    ReplayBundleRef, SemanticHandle, SemanticHandleSpec, SessionId, TimestampNs,
};

fn handle() -> Result<SemanticHandle, HydrationError> {
    let levels = BTreeSet::from([
        HydrationLevel::H0,
        HydrationLevel::H1,
        HydrationLevel::H2,
        HydrationLevel::H3,
        HydrationLevel::H4,
    ]);
    SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
            b"schemas",
            b"operations",
            b"views",
            b"capabilities",
            b"errors",
            b"costs",
            "hydration-admission:test",
        )),
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
        required_capabilities: levels
            .iter()
            .map(|level| {
                (
                    *level,
                    BTreeSet::from([format!("capability:hydrate:{}", level.as_str())]),
                )
            })
            .collect(),
        estimated_costs: {
            let mut costs = BTreeMap::new();
            for &level in &levels {
                costs.insert(
                    level,
                    BudgetVector::builder()
                        .bytes(if level == HydrationLevel::H4 {
                            4_096
                        } else {
                            1_024
                        })
                        .tokens(256)
                        .build()
                        .map_err(ContractError::from)?,
                );
            }
            costs
        },
        levels,
        laboratory_access: LaboratoryAccess::QualificationOrDebugGrant,
        debug_capability: Some("capability:hydrate:debug".to_owned()),
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(1),
    })
}

fn request(
    handle: &SemanticHandle,
    level: HydrationLevel,
) -> Result<HydrationRequest, HydrationError> {
    HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:admission")?,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: level,
        allow_lower_level: false,
        available_capabilities: handle
            .required_capabilities
            .values()
            .flatten()
            .cloned()
            .collect(),
        authorized_privacy_classes: BTreeSet::from([handle.privacy_class.clone()]),
        budget: BudgetVector::builder()
            .bytes(if level == HydrationLevel::H4 {
                4_096
            } else {
                2_048
            })
            .tokens(512)
            .build()
            .map_err(ContractError::from)?,
        purpose: HydrationPurpose::Qualification,
        continuation: None,
        issued_at: TimestampNs(10),
    })
}

fn artifact(
    handle: &SemanticHandle,
    level: HydrationLevel,
) -> Result<HydrationArtifact, HydrationError> {
    if level == HydrationLevel::H4 {
        let mut proof_roots = BTreeSet::new();
        proof_roots.insert(handle.subject_digest);
        proof_roots.insert(ContentDigest::sha256(b"secondary-anchor-proof-root"));
        let expansion = H4LaboratoryExpansion::new(H4LaboratoryExpansionParams {
            handle_id: handle.handle_id.clone(),
            subject_id: handle.subject_id.clone(),
            subject_digest: handle.subject_digest,
            replay_bundle: ReplayBundleRef {
                bundle_id: "replay:bundle:run-101".to_owned(),
                bundle_digest: ContentDigest::sha256(b"bundle-payload-bytes"),
                manifest_root: ContentDigest::sha256(b"bundle-manifest-root"),
                seed: 0x1234_5678_9abc_def0,
                delta_batch_count: 5,
                environment_digest: ContentDigest::sha256(b"environment-closure-v1"),
            },
            intermediates: vec![IntermediateArtifact {
                stage_name: "backbone.layer3".to_owned(),
                content_type: "application/x-fss-tensor-f32".to_owned(),
                digest: ContentDigest::sha256(b"feature-map-data"),
                shape: vec![1, 10],
                byte_count: 40,
            }],
            alternate_systems: vec![AlternateSystem {
                system_id: "oracle:ffmpeg-v6.1".to_owned(),
                version: "6.1.1".to_owned(),
                framework: "ffmpeg".to_owned(),
                quarantine_digest: ContentDigest::sha256(b"quarantine-container"),
            }],
            oracle_comparisons: vec![OracleComparison {
                comparison_id: "cmp:psnr".to_owned(),
                oracle_id: "oracle:ffmpeg-v6.1".to_owned(),
                metric_name: "psnr_y".to_owned(),
                discrepancy_score: 0.01,
                tolerance_threshold: 0.05,
                within_tolerance: true,
                oracle_version: "6.1.1".to_owned(),
            }],
            quarantine: LaboratoryQuarantine {
                quarantined_from_production: true,
                quarantine_receipt_digest: ContentDigest::sha256(b"quarantine-receipt"),
                isolation_boundary: "sealed_linux_namespace".to_owned(),
                process_drain_witness: ContentDigest::sha256(b"process-drain-witness"),
            },
            laboratory_access: handle.laboratory_access,
            purpose: HydrationPurpose::Qualification,
            anchor: handle.anchor.clone(),
            contract_basis: handle.contract_basis.clone(),
            estimated_cost: handle
                .estimated_cost(HydrationLevel::H4)
                .ok_or(HydrationError::LevelUnavailable)?,
            published_at: handle.published_at,
            retention_until: handle.retention_until,
            proof_roots,
            completeness: Completeness::Complete,
            applied_transform: handle.applied_transform.clone(),
        })?;
        expansion.to_hydration_artifact(handle.applied_transform.clone())
    } else {
        HydrationArtifact::publish(
            level,
            "application/fss+json",
            b"redacted synopsis".to_vec(),
            [handle.subject_digest],
            Completeness::Complete,
            handle.applied_transform.clone(),
        )
    }
}

fn receipt(
    handle: &SemanticHandle,
    request: &HydrationRequest,
    artifact: &HydrationArtifact,
    now: TimestampNs,
) -> Result<HydrationReceipt, HydrationError> {
    let mut roots = artifact.proof_roots.clone();
    roots.extend([
        handle.descriptor_digest,
        request.request_digest,
        artifact.artifact_digest,
    ]);
    HydrationReceipt::publish(HydrationReceiptSpec {
        request_digest: request.request_digest,
        handle_id: handle.handle_id.clone(),
        descriptor_digest: handle.descriptor_digest,
        subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: request.requested_level,
        delivered_level: Some(artifact.level),
        availability: HandleAvailability::Available,
        cost: handle
            .estimated_cost(artifact.level)
            .ok_or(HydrationError::LevelUnavailable)?,
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
    assert_eq!(
        backdated.validate_for(&request, &handle, Some(&artifact)),
        Err(HydrationError::Contract(
            ContractError::InvertedTimeInterval
        ))
    );
    let expired = receipt(&handle, &request, &artifact, TimestampNs(100))?;
    assert_eq!(
        expired.validate_for(&request, &handle, Some(&artifact)),
        Err(HydrationError::Contract(ContractError::DigestMismatch))
    );
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
    assert_eq!(
        forged.validate_for(&denied, &handle, Some(&artifact)),
        Err(HydrationError::CapabilityDenied)
    );

    let mut denied = request(&handle, HydrationLevel::H1)?;
    denied.authorized_privacy_classes.clear();
    reseal_request(&mut denied);
    let forged = receipt(&handle, &denied, &artifact, TimestampNs(20))?;
    assert_eq!(
        forged.validate_for(&denied, &handle, Some(&artifact)),
        Err(HydrationError::PrivacyDenied)
    );
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
    assert_eq!(
        forged.validate_for(&request, &handle, Some(&artifact)),
        Err(HydrationError::LaboratoryGrantRequired)
    );
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
    assert_eq!(
        forged.validate_for(&original_request, &handle, Some(&artifact)),
        Err(HydrationError::Contract(ContractError::DigestMismatch))
    );

    handle
        .estimated_costs
        .insert(HydrationLevel::H1, BudgetVector::default());
    handle.descriptor_digest = handle.computed_descriptor_digest();
    let request = request(&handle, HydrationLevel::H1)?;
    let underpriced = receipt(&handle, &request, &artifact, TimestampNs(20))?;
    assert_eq!(
        underpriced.validate_for(&request, &handle, Some(&artifact)),
        Err(HydrationError::BudgetExceeded)
    );
    Ok(())
}

#[test]
fn fallback_requires_consent_and_partial_completeness() -> Result<(), HydrationError> {
    let handle = handle()?;
    let artifact = artifact(&handle, HydrationLevel::H1)?;
    let mut request = request(&handle, HydrationLevel::H3)?;
    let forbidden = receipt(&handle, &request, &artifact, TimestampNs(20))?;
    assert_eq!(
        forbidden.validate_for(&request, &handle, Some(&artifact)),
        Err(HydrationError::LevelUnavailable)
    );
    request.allow_lower_level = true;
    reseal_request(&mut request);
    let mut permitted = receipt(&handle, &request, &artifact, TimestampNs(20))?;
    permitted.validate_for(&request, &handle, Some(&artifact))?;
    assert_eq!(permitted.completeness, Completeness::Partial);
    permitted.completeness = Completeness::Complete;
    reseal_receipt(&mut permitted);
    assert_eq!(
        permitted.validate_for(&request, &handle, Some(&artifact)),
        Err(HydrationError::Contract(ContractError::DigestMismatch))
    );
    Ok(())
}

#[test]
fn receipt_must_retain_input_proof_roots() -> Result<(), HydrationError> {
    let handle = handle()?;
    let request = request(&handle, HydrationLevel::H1)?;
    let artifact = artifact(&handle, HydrationLevel::H1)?;
    let original = receipt(&handle, &request, &artifact, TimestampNs(20))?;
    for root in [
        handle.subject_digest,
        handle.descriptor_digest,
        request.request_digest,
    ] {
        let mut forged = original.clone();
        forged.proof_roots.remove(&root);
        reseal_receipt(&mut forged);
        assert_eq!(
            forged.validate_for(&request, &handle, Some(&artifact)),
            Err(HydrationError::Contract(ContractError::DigestMismatch))
        );
    }
    Ok(())
}

#[test]
fn explicit_disposition_survives_retention_expiry() -> Result<(), HydrationError> {
    let mut handle = handle()?;
    for availability in [
        HandleAvailability::Deleted,
        HandleAvailability::Corrupt,
        HandleAvailability::Superseded,
        HandleAvailability::PrivacyTransformed,
        HandleAvailability::NotObservable,
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
    let cursor = ContinuationCursor::publish(ContinuationCursorPublishParams {
        scope: ContinuationScope::EvidenceHydration,
        stream_id: handle.handle_id.clone(),
        contract_basis: handle.contract_basis.clone(),
        session_id: request.session_id.clone(),
        view_id: HYDRATION_VIEW_ID.to_owned(),
        basis_anchor: handle.anchor.clone(),
        resume_anchor: handle.anchor.clone(),
        source_digest: handle.ladder_policy_digest(),
        position: 2,
        upper_bound: 5,
        selection_witness: artifact.artifact_digest,
        predecessor_digest: None,
        issued_at: TimestampNs(20),
        expires_at: TimestampNs(70),
    })?;
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
        assert_eq!(
            forged.validate_for(&request, &handle, Some(&artifact)),
            Err(HydrationError::WrongContinuation)
        );
    }
    Ok(())
}

#[test]
fn request_set_capacity_is_bounded() -> Result<(), HydrationError> {
    let handle = handle()?;
    let mut spec = HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:admission")?,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: HydrationLevel::H0,
        allow_lower_level: false,
        available_capabilities: (0..1_024).map(|i| format!("cap:{i}")).collect(),
        authorized_privacy_classes: BTreeSet::from([handle.privacy_class.clone()]),
        budget: BudgetVector::default(),
        purpose: HydrationPurpose::Routine,
        continuation: None,
        issued_at: TimestampNs(10),
    };
    // Exact bound (1_024) succeeds
    let request_bound = HydrationRequest::publish(spec.clone())?;
    assert_eq!(request_bound.available_capabilities.len(), 1_024);

    // Bound + 1 (1_025) fails
    spec.available_capabilities = (0..1_025).map(|i| format!("cap:{i}")).collect();
    assert_eq!(
        HydrationRequest::publish(spec.clone()),
        Err(HydrationError::CapacityExceeded)
    );

    // Exact bound (1_024) for privacy classes succeeds
    spec.available_capabilities.clear();
    spec.authorized_privacy_classes = (0..1_024).map(|i| format!("priv:{i}")).collect();
    let request_priv_bound = HydrationRequest::publish(spec.clone())?;
    assert_eq!(request_priv_bound.authorized_privacy_classes.len(), 1_024);

    // Bound + 1 (1_025) for privacy classes fails
    spec.authorized_privacy_classes = (0..1_025).map(|i| format!("priv:{i}")).collect();
    assert_eq!(
        HydrationRequest::publish(spec),
        Err(HydrationError::CapacityExceeded)
    );
    Ok(())
}
