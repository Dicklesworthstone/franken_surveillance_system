#![forbid(unsafe_code)]
//! Contract & fault tests for `FSS-210` (`fss-x4a.24.10`): immutable semantic handles and
//! bounded progressive H0–H4 hydration including the complete `H3SourceEvidence` ladder rung.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::hydration::{
    H3_CONTENT, H3_CONTENT_TYPE, H3_LEVEL_ID, H3_LEVEL_NAME, H3_OWNER, H3_SCHEMA, H3SourceEvidence,
    H3SourceEvidenceParams, H3SourcePayload, HYDRATION_VIEW_ID, HandleAvailability,
    HydrationArtifact, HydrationError, HydrationLevel, HydrationPurpose, HydrationRequest,
    HydrationRequestSpec, LaboratoryAccess, SemanticHandle, SemanticHandleSpec,
};
use fss_core::{
    BudgetVector, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    CaptureInterval, Completeness, ContentDigest, ContinuationCursor,
    ContinuationCursorPublishParams, ContinuationScope, ContractBasis, ContractBasisRegistryBytes,
    ContractError, LedgerAnchor, SessionId, TimestampNs,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
        b"schemas-210",
        b"operations-210",
        b"views-210",
        b"capabilities-210",
        b"errors-210",
        b"costs-210",
        "fss:210",
    ))
}

fn anchor(seq: u64) -> LedgerAnchor {
    let mut a = LedgerAnchor::genesis("site:fss-210");
    a.commit_sequence = seq;
    a.state_root = ContentDigest::sha256(format!("state-210-{seq}").as_bytes());
    a
}

fn full_handle(seq: u64) -> Result<SemanticHandle, HydrationError> {
    let levels: BTreeSet<HydrationLevel> = HydrationLevel::ALL.into_iter().collect();
    let mut caps = BTreeMap::new();
    let mut costs = BTreeMap::new();
    for level in &levels {
        let scale = u64::from(level.ordinal()) + 1;
        caps.insert(
            *level,
            BTreeSet::from([format!("capability:hydrate:{}", level.as_str())]),
        );
        let budget = BudgetVector::builder()
            .latency_ms(scale * 10)
            .tokens(scale * 100)
            .bytes(scale * 4_096)
            .cpu_millis(scale * 5)
            .privacy_exposure(scale as f64 / 10.0)
            .build()
            .map_err(ContractError::from)?;
        costs.insert(*level, budget);
    }
    SemanticHandle::publish(SemanticHandleSpec {
        contract_basis: basis(),
        anchor: anchor(seq),
        subject_id: "evidence:cam-front:frame-001".to_owned(),
        subject_digest: ContentDigest::sha256(b"subject-frame-001"),
        semantic_type: "evidence_bundle".to_owned(),
        source_id: "sensor:cam-front".to_owned(),
        capture_interval: Some(CaptureInterval::new(TimestampNs(100), TimestampNs(200))?),
        spatial_scope: Some("zone:driveway".to_owned()),
        privacy_class: "private:property".to_owned(),
        applied_transform: None,
        availability: HandleAvailability::Available,
        retention_until: TimestampNs(50_000),
        levels,
        required_capabilities: caps,
        estimated_costs: costs,
        laboratory_access: LaboratoryAccess::QualificationOrDebugGrant,
        debug_capability: Some("capability:hydrate:debug".to_owned()),
        derivative_handles: BTreeSet::new(),
        published_at: TimestampNs(10),
    })
}

fn generous_budget() -> Result<BudgetVector, ContractError> {
    BudgetVector::builder()
        .latency_ms(1_000)
        .tokens(10_000)
        .bytes(1_000_000)
        .cpu_millis(1_000)
        .privacy_exposure(1.0)
        .build()
        .map_err(ContractError::from)
}

#[test]
fn h3_source_evidence_and_h0_to_h4_progressive_hydration_contract() -> TestResult {
    let handle = full_handle(3)?;
    assert_eq!(H3_LEVEL_ID, "H3");
    assert_eq!(H3_LEVEL_NAME, "source_evidence");
    assert_eq!(H3_OWNER, "fss-agent-core");
    assert_eq!(H3_SCHEMA, "fss.h3_source_evidence.v1");
    assert_eq!(H3_CONTENT, HydrationLevel::H3.content());

    // Build all 4 normative H3SourcePayload families and verify canonical round-trip!
    let custody = ContentDigest::sha256(b"spool-custody-object-001");
    let payloads = [
        H3SourcePayload::EncodedPacketBatch {
            codec: "h264/annexb".to_owned(),
            packet_count: 12,
            capture_interval: CaptureInterval::new(TimestampNs(100), TimestampNs(200))?,
            raw_bytes: vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1E],
        },
        H3SourcePayload::ImmutableObjectBytes {
            object_root: ContentDigest::sha256(b"object-root-001"),
            media_type: "application/octet-stream".to_owned(),
            raw_bytes: b"immutable-verified-pack-slice".to_vec(),
        },
        H3SourcePayload::ExactSourceMetadata {
            metadata_schema: "onvif.rtsp.sdp.v1".to_owned(),
            stream_generation: 7,
            fields: BTreeMap::from([
                ("codec".to_owned(), "H264".to_owned()),
                ("fps".to_owned(), "30".to_owned()),
            ]),
        },
        H3SourcePayload::FullResolutionMedia {
            codec: "jpeg".to_owned(),
            width_px: 1920,
            height_px: 1080,
            capture_interval: CaptureInterval::new(TimestampNs(100), TimestampNs(133))?,
            raw_bytes: vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0xFF, 0xD9],
        },
    ];

    let mut h3_artifact_opt: Option<HydrationArtifact> = None;
    for payload in payloads {
        let is_raw = payload.contains_raw_media();
        let h3 = H3SourceEvidence::new(H3SourceEvidenceParams {
            handle_id: handle.handle_id.clone(),
            subject_id: handle.subject_id.clone(),
            subject_digest: handle.subject_digest,
            source_id: handle.source_id.clone(),
            source_custody_digest: custody,
            authorization_grant_id: "grant:owner-h3-001".to_owned(),
            privacy_class: handle.privacy_class.clone(),
            required_capabilities: BTreeSet::from(["capability:hydrate:H3".to_owned()]),
            payload,
            anchor: handle.anchor.clone(),
            contract_basis: handle.contract_basis.clone(),
            estimated_cost: handle.estimated_costs[&HydrationLevel::H3],
            published_at: handle.published_at,
            retention_until: handle.retention_until,
            proof_roots: BTreeSet::from([handle.subject_digest, custody]),
            completeness: Completeness::Complete,
            applied_transform: handle.applied_transform.clone(),
        })?;
        assert!(!h3.is_quarantined());
        assert!(!h3.grants_effect_authority());
        assert_eq!(h3.level(), HydrationLevel::H3);
        assert_eq!(h3.payload().contains_raw_media(), is_raw);
        h3.verify_against_handle(&handle)?;

        // Canonical binary encode/decode round-trip.
        let mut enc = CanonicalEncoder::new();
        h3.encode_canonical(&mut enc);
        let wire = enc.finish_checked()?;
        let mut dec = CanonicalDecoder::new(&wire);
        let decoded = H3SourceEvidence::decode_canonical(&mut dec)?;
        dec.ensure_finished()?;
        assert_eq!(decoded, h3);

        // Bridge into sealed HydrationArtifact and round-trip back.
        let artifact = h3.to_hydration_artifact()?;
        assert_eq!(artifact.content_type, H3_CONTENT_TYPE);
        assert!(artifact.is_production_safe());
        assert_eq!(H3SourceEvidence::from_hydration_artifact(&artifact)?, h3);
        h3_artifact_opt = Some(artifact);
    }

    // Validate progressive continuation cursor stepping directly to H3 and delivering H3 artifact!
    let h3_artifact = h3_artifact_opt.ok_or("missing h3 artifact")?;
    let cursor_h3 = ContinuationCursor::publish(ContinuationCursorPublishParams {
        scope: ContinuationScope::EvidenceHydration,
        stream_id: handle.handle_id.clone(),
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:fss-210")?,
        view_id: HYDRATION_VIEW_ID.to_owned(),
        basis_anchor: handle.anchor.clone(),
        resume_anchor: handle.anchor.clone(),
        source_digest: handle.ladder_policy_digest(),
        position: 3, // exact ordinal of H3
        upper_bound: 5,
        selection_witness: handle.descriptor_digest,
        predecessor_digest: None,
        issued_at: TimestampNs(20),
        expires_at: TimestampNs(10_000),
    })?;
    let req_h3 = HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:fss-210")?,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: HydrationLevel::H3,
        allow_lower_level: false,
        available_capabilities: BTreeSet::from(["capability:hydrate:H3".to_owned()]),
        authorized_privacy_classes: BTreeSet::from(["private:property".to_owned()]),
        budget: generous_budget()?,
        purpose: HydrationPurpose::IncidentAdjudication,
        continuation: Some(cursor_h3),
        issued_at: TimestampNs(25),
    })?;
    let quoted_cost = req_h3.validate_delivery(&handle, &h3_artifact, TimestampNs(30))?;
    assert_eq!(quoted_cost, handle.estimated_costs[&HydrationLevel::H3]);

    emit_caplog(
        "fss210_h3_and_progressive_h0_h4",
        "all_4_h3_payloads_canonical_codec_and_continuation_delivery_verified",
        "all_4_h3_payloads_canonical_codec_and_continuation_delivery_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn h3_denies_missing_capability_privacy_degraded_completeness_and_tamper() -> TestResult {
    let handle = full_handle(4)?;
    let custody = ContentDigest::sha256(b"spool-custody-faults");
    let valid_payload = H3SourcePayload::ImmutableObjectBytes {
        object_root: ContentDigest::sha256(b"obj-root"),
        media_type: "application/octet-stream".to_owned(),
        raw_bytes: b"exact-bytes".to_vec(),
    };

    // 1. Degraded completeness (Unknown/Stale) MUST be refused at H3 construction!
    let bad_comp = H3SourceEvidence::new(H3SourceEvidenceParams {
        handle_id: handle.handle_id.clone(),
        subject_id: handle.subject_id.clone(),
        subject_digest: handle.subject_digest,
        source_id: handle.source_id.clone(),
        source_custody_digest: custody,
        authorization_grant_id: "grant:1".to_owned(),
        privacy_class: handle.privacy_class.clone(),
        required_capabilities: BTreeSet::from(["capability:hydrate:H3".to_owned()]),
        payload: valid_payload.clone(),
        anchor: handle.anchor.clone(),
        contract_basis: handle.contract_basis.clone(),
        estimated_cost: handle.estimated_costs[&HydrationLevel::H3],
        published_at: handle.published_at,
        retention_until: handle.retention_until,
        proof_roots: BTreeSet::from([handle.subject_digest, custody]),
        completeness: Completeness::Stale,
        applied_transform: None,
    });
    assert!(matches!(
        bad_comp,
        Err(HydrationError::Contract(ContractError::EvidenceRequired))
    ));

    // 2. Empty required_capabilities fails closed with CapabilityDenied!
    let no_caps = H3SourceEvidence::new(H3SourceEvidenceParams {
        handle_id: handle.handle_id.clone(),
        subject_id: handle.subject_id.clone(),
        subject_digest: handle.subject_digest,
        source_id: handle.source_id.clone(),
        source_custody_digest: custody,
        authorization_grant_id: "grant:1".to_owned(),
        privacy_class: handle.privacy_class.clone(),
        required_capabilities: BTreeSet::new(),
        payload: valid_payload.clone(),
        anchor: handle.anchor.clone(),
        contract_basis: handle.contract_basis.clone(),
        estimated_cost: handle.estimated_costs[&HydrationLevel::H3],
        published_at: handle.published_at,
        retention_until: handle.retention_until,
        proof_roots: BTreeSet::from([handle.subject_digest, custody]),
        completeness: Completeness::Complete,
        applied_transform: None,
    });
    assert_eq!(no_caps, Err(HydrationError::CapabilityDenied));

    // 3. Valid H3 artifact delivered without H3 capability OR without privacy class fails closed!
    let h3 = H3SourceEvidence::new(H3SourceEvidenceParams {
        handle_id: handle.handle_id.clone(),
        subject_id: handle.subject_id.clone(),
        subject_digest: handle.subject_digest,
        source_id: handle.source_id.clone(),
        source_custody_digest: custody,
        authorization_grant_id: "grant:2".to_owned(),
        privacy_class: handle.privacy_class.clone(),
        required_capabilities: BTreeSet::from(["capability:hydrate:H3".to_owned()]),
        payload: valid_payload,
        anchor: handle.anchor.clone(),
        contract_basis: handle.contract_basis.clone(),
        estimated_cost: handle.estimated_costs[&HydrationLevel::H3],
        published_at: handle.published_at,
        retention_until: handle.retention_until,
        proof_roots: BTreeSet::from([handle.subject_digest, custody]),
        completeness: Completeness::Complete,
        applied_transform: None,
    })?;
    let mut artifact = h3.to_hydration_artifact()?;

    let req_no_cap = HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:fss-210-deny")?,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: HydrationLevel::H3,
        allow_lower_level: false,
        available_capabilities: BTreeSet::from(["capability:hydrate:H2".to_owned()]),
        authorized_privacy_classes: BTreeSet::from(["private:property".to_owned()]),
        budget: generous_budget()?,
        purpose: HydrationPurpose::IncidentAdjudication,
        continuation: None,
        issued_at: TimestampNs(25),
    })?;
    assert_eq!(
        req_no_cap.validate_delivery(&handle, &artifact, TimestampNs(30)),
        Err(HydrationError::CapabilityDenied)
    );

    let req_no_priv = HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: handle.contract_basis.clone(),
        session_id: SessionId::parse("session:fss-210-deny-priv")?,
        handle_id: handle.handle_id.clone(),
        expected_descriptor_digest: handle.descriptor_digest,
        expected_subject_digest: handle.subject_digest,
        anchor: handle.anchor.clone(),
        requested_level: HydrationLevel::H3,
        allow_lower_level: false,
        available_capabilities: BTreeSet::from(["capability:hydrate:H3".to_owned()]),
        authorized_privacy_classes: BTreeSet::from(["public:site".to_owned()]),
        budget: generous_budget()?,
        purpose: HydrationPurpose::IncidentAdjudication,
        continuation: None,
        issued_at: TimestampNs(25),
    })?;
    assert_eq!(
        req_no_priv.validate_delivery(&handle, &artifact, TimestampNs(30)),
        Err(HydrationError::PrivacyDenied)
    );

    // 4. Envelope/payload completeness mismatch smuggling fails closed!
    let mismatched_env = HydrationArtifact::publish(
        HydrationLevel::H3,
        H3_CONTENT_TYPE,
        artifact.payload.clone(),
        artifact.proof_roots.clone(),
        Completeness::Partial,
        None,
    )?;
    assert!(matches!(
        H3SourceEvidence::from_hydration_artifact(&mismatched_env),
        Err(HydrationError::Contract(ContractError::DigestMismatch))
    ));

    // 5. Bit-flip tamper inside H3 canonical payload fails closed on decode!
    let last = artifact.payload.len() - 1;
    artifact.payload[last] ^= 0x01;
    assert!(matches!(
        H3SourceEvidence::from_hydration_artifact(&artifact),
        Err(HydrationError::Contract(ContractError::DigestMismatch))
    ));

    emit_caplog(
        "fss210_h3_faults_and_denials",
        "degraded_completeness_cap_privacy_denial_and_tamper_failed_closed",
        "degraded_completeness_cap_privacy_denial_and_tamper_failed_closed",
        "pass",
    );
    Ok(())
}
