#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use fss_core::{
    CapsuleId, CaptureInterval, ClockBasis, Completeness, CompressionCompleteness,
    CompressionLossClass, CompressionStopReason, CompressionTransform, CompressionTransformKind,
    ContentDigest, ContractBasis, ContractBasisRegistryBytes, ContractError, CriticalPreservation,
    EffectIntent, EffectJournal, HandoffCapsule, HandoffId, HandoffPublishParams, LedgerAnchor,
    MissionId, OperationId, PrincipalId, SemanticCompressionReceipt, SemanticContextPack,
    SensorCapsule, SensorId, SensorSourceBytesSpec, SessionId, StreamId, TimestampNs,
};

fn sample_basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(
        ContractBasisRegistryBytes::new(
            b"test_schemas",
            b"test_operations",
            b"test_views",
            b"test_capabilities",
            b"test_errors",
            b"test_costs",
            "fss-core:0.0.1",
        )
        .with_accepted_nightly("nightly-2026-08-31"),
    )
}

#[test]
fn test_contract_basis_registry_bytes_parameter_struct() {
    let spec = ContractBasisRegistryBytes::new(
        b"catalog",
        b"ops",
        b"views",
        b"caps",
        b"errs",
        b"costs",
        "release-123",
    );
    assert_eq!(spec.producer_release_id, "release-123");
    assert_eq!(spec.accepted_nightly, None);

    let spec_with_nightly = spec.with_accepted_nightly("nightly-2026-08-31");
    assert_eq!(
        spec_with_nightly.accepted_nightly,
        Some("nightly-2026-08-31")
    );

    let basis = ContractBasis::from_registry_bytes(spec_with_nightly);
    assert_eq!(basis.semantic_protocol, "fss/1");
    assert_eq!(basis.producer_release_id, "release-123");
    assert_eq!(
        basis.accepted_nightly.as_deref(),
        Some("nightly-2026-08-31")
    );
    assert_eq!(
        basis.schema_catalog_digest,
        ContentDigest::sha256(b"catalog")
    );
    assert_eq!(
        basis.operation_registry_digest,
        ContentDigest::sha256(b"ops")
    );
    assert_eq!(basis.view_registry_digest, ContentDigest::sha256(b"views"));
    assert_eq!(
        basis.capability_registry_digest,
        ContentDigest::sha256(b"caps")
    );
    assert_eq!(basis.error_registry_digest, ContentDigest::sha256(b"errs"));
    assert_eq!(basis.cost_registry_digest, ContentDigest::sha256(b"costs"));

    let digest = basis.basis_digest();
    assert_eq!(digest, basis.basis_digest());
}

#[test]
fn test_handoff_capsule_publish_params() -> Result<(), ContractError> {
    let situation_root = ContentDigest::sha256(b"situation-root-bytes");
    let child_proof = ContentDigest::sha256(b"investigation-case-1");
    let basis = sample_basis();

    let params = HandoffPublishParams {
        handoff_id: HandoffId::parse("handoff:test-001")?,
        mission_id: MissionId::parse("mission:test-001")?,
        source_session_id: SessionId::parse("session:test-001")?,
        source_principal_id: PrincipalId::parse("principal:test-001")?,
        anchor: LedgerAnchor::genesis("site:test-anchor"),
        situation_capsule_root: situation_root,
        child_roots: vec![child_proof],
        contract_basis: basis.clone(),
        created_at: TimestampNs(100),
        expires_at: TimestampNs(200),
    };

    let handoff = HandoffCapsule::publish(params)?;
    assert_eq!(handoff.handoff_id.as_str(), "handoff:test-001");
    assert!(handoff.child_roots.contains(&situation_root));
    assert!(handoff.child_roots.contains(&child_proof));
    assert_eq!(handoff.verify()?, handoff.handoff_root);

    // Test inverted time interval rejection
    let inverted_params = HandoffPublishParams {
        handoff_id: HandoffId::parse("handoff:test-002")?,
        mission_id: MissionId::parse("mission:test-002")?,
        source_session_id: SessionId::parse("session:test-002")?,
        source_principal_id: PrincipalId::parse("principal:test-002")?,
        anchor: LedgerAnchor::genesis("site:test-anchor"),
        situation_capsule_root: situation_root,
        child_roots: vec![child_proof],
        contract_basis: basis,
        created_at: TimestampNs(200),
        expires_at: TimestampNs(100),
    };
    assert_eq!(
        HandoffCapsule::publish(inverted_params),
        Err(ContractError::InvertedTimeInterval)
    );

    Ok(())
}

#[test]
fn test_sensor_capsule_from_source_bytes_spec() -> Result<(), ContractError> {
    let payload = b"raw-h264-nalu-data-stream-bytes";
    let spec = SensorSourceBytesSpec {
        capsule_id: CapsuleId::parse("capsule:cam01-seq001")?,
        sensor_id: SensorId::parse("sensor:cam01")?,
        stream_id: StreamId::parse("stream:cam01-main")?,
        sequence: 42,
        capture: CaptureInterval {
            start: TimestampNs(1_000_000),
            end: TimestampNs(1_033_333),
        },
        receive_time: TimestampNs(1_040_000),
        clock_basis: ClockBasis::MonotonicOffsetCertified,
        source: payload,
        frame_count: 1,
        gap_before: false,
    };

    let capsule = SensorCapsule::from_source_bytes(spec);
    assert_eq!(capsule.capsule_id.as_str(), "capsule:cam01-seq001");
    assert_eq!(capsule.sensor_id.as_str(), "sensor:cam01");
    assert_eq!(capsule.sequence, 42);
    assert_eq!(capsule.source_bytes, payload.len() as u64);
    assert_eq!(capsule.source_digest, ContentDigest::sha256(payload));
    assert_eq!(capsule.frame_count, 1);
    assert!(!capsule.gap_before);

    let meta_digest = capsule.metadata_digest();
    assert_eq!(meta_digest, capsule.metadata_digest());

    Ok(())
}

#[test]
fn test_semantic_compression_receipt_validation() -> Result<(), ContractError> {
    let anchor = LedgerAnchor::genesis("site:test");
    let pack = SemanticContextPack::publish(
        "pack:test-001",
        sample_basis(),
        MissionId::parse("mission:test")?,
        SessionId::parse("session:test")?,
        "AVIEW-001",
        anchor.clone(),
        ContentDigest::sha256(b"frame-digest"),
        vec![],
        "receipt:test-001",
        None,
        TimestampNs(50),
    )?;

    let receipt = SemanticCompressionReceipt {
        receipt_id: "receipt:test-001".to_owned(),
        source_anchor: anchor,
        view_id: "AVIEW-001".to_owned(),
        target_tokens: pack.token_count,
        selected_classes: BTreeSet::new(),
        omitted_classes: BTreeSet::new(),
        transforms: vec![CompressionTransform {
            kind: CompressionTransformKind::Select,
            scope: "nominal".to_owned(),
            loss_class: CompressionLossClass::Lossless,
            details: None,
        }],
        completeness: vec![CompressionCompleteness {
            domain: "nominal".to_owned(),
            state: Completeness::Complete,
            omitted_count: 0,
        }],
        critical_preservation: CriticalPreservation {
            known_critical_items: 0,
            omitted_critical_items: 0,
            omitted_invalidations: 0,
            omitted_contradictions: 0,
        },
        actual_tokens: pack.token_count,
        actual_bytes: pack.encoded_bytes(),
        expansion_handles: Vec::new(),
        selection_frontier_digest: None,
        stop_reason: CompressionStopReason::Complete,
        output_digest: pack.pack_digest,
    };

    receipt.validate()?;
    receipt.validate_for(&pack)?;
    let digest = receipt.receipt_digest();
    assert_eq!(digest, receipt.receipt_digest());

    Ok(())
}

#[test]
fn test_effect_journal_obligations_iterator() -> Result<(), ContractError> {
    let mut journal = EffectJournal::new(sample_basis(), LedgerAnchor::genesis("site:journal"));
    let op_id = OperationId::parse("op:pan-tilt-01")?;
    let intent = EffectIntent::new(
        op_id.clone(),
        "ptz:pan".to_owned(),
        "camera:driveway".to_owned(),
        b"{\"pan\": 10}".to_vec(),
        false,
    );

    journal.record_intent(intent)?;
    journal.bind_obligation(&op_id, "ptz.settled", TimestampNs(500))?;

    let obligations: Vec<_> = journal.obligations().collect();
    assert_eq!(obligations.len(), 1);
    assert_eq!(obligations[0].operation_id, op_id);
    assert_eq!(obligations[0].terminal_predicate, "ptz.settled");

    Ok(())
}
