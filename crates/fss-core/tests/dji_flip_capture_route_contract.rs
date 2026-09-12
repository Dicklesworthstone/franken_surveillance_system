#![forbid(unsafe_code)]
//! Contract and negative-evidence verification tests for NEG-001 (DJI Flip SDK non-dependency constraint).

use fss_core::acquisition::{
    AcquisitionError, AcquisitionRequest, CONSTRAINT_NEG_001, CaptureDeviceTuple,
    CaptureReadinessState, CaptureRouteKind, LiveCaptureRouteResult, Neg001ScenarioLog,
    SCHEMA_NEG001_SCENARIO_LOG, UnavailableCaptureReason, UnsupportedCaptureReason,
    evaluate_capture_route,
};
use fss_core::{
    AdapterCapabilities, AdapterGeneration, AdapterId, AdapterIdentity, AdapterKind,
    CanonicalDecode, CanonicalEncode, ClockBasis, ContentDigest, ContractError, CredentialMethod,
    DeviceCapabilities, DeviceClass, DeviceGeneration, DeviceId, DeviceIdentity,
    FirmwareGeneration, IsolationMode, MediaKind, SourceId, SourceIdentity, SourceKind,
    StreamGeneration, TimestampNs,
};

fn make_dji_flip_tuple() -> Result<CaptureDeviceTuple, ContractError> {
    CaptureDeviceTuple::new(
        "DJI Flip",
        "v01.00.0100",
        "DJI RC-N3",
        "DJI Fly v1.14.0",
        "linux-x86_64",
        "owner-authorized-lab",
    )
}

#[test]
fn test_neg001_dji_flip_sdk_route_returns_unsupported() -> Result<(), Box<dyn std::error::Error>> {
    let tuple = make_dji_flip_tuple()?;
    assert!(tuple.is_dji_flip());

    let result = evaluate_capture_route(
        &tuple,
        CaptureRouteKind::ProprietarySdkLiveCapture,
        true,
        true,
    );

    match &result {
        LiveCaptureRouteResult::Unsupported(unsupported) => {
            assert_eq!(unsupported.constraint_id, Some(CONSTRAINT_NEG_001));
            assert_eq!(
                unsupported.route_kind,
                CaptureRouteKind::ProprietarySdkLiveCapture
            );
            match &unsupported.reason {
                UnsupportedCaptureReason::ProhibitedSdkDependency {
                    sdk_name,
                    constraint_id,
                } => {
                    assert_eq!(sdk_name, "DJI Mobile SDK");
                    assert_eq!(*constraint_id, CONSTRAINT_NEG_001);
                }
                other => return Err(format!("unexpected reason: {other:?}").into()),
            }
            assert!(unsupported.remediation.contains("NEG-001"));
        }
        other => return Err(format!("expected Unsupported result, got: {other:?}").into()),
    }

    // Invariants: unsupported route NEVER reports as adapter acceptance, streaming, or readiness
    assert!(!result.is_adapter_accepted());
    assert!(!result.is_streaming());
    assert!(!result.is_ready());
    assert_eq!(result.readiness_state(), CaptureReadinessState::Unsupported);

    Ok(())
}

#[test]
fn test_neg001_dji_flip_live_streaming_route_returns_unsupported()
-> Result<(), Box<dyn std::error::Error>> {
    let tuple = make_dji_flip_tuple()?;

    let result = evaluate_capture_route(&tuple, CaptureRouteKind::LiveStreaming, true, true);

    match &result {
        LiveCaptureRouteResult::Unsupported(unsupported) => {
            assert_eq!(unsupported.constraint_id, Some(CONSTRAINT_NEG_001));
            assert_eq!(unsupported.route_kind, CaptureRouteKind::LiveStreaming);
            match &unsupported.reason {
                UnsupportedCaptureReason::UnsupportedLiveRouteForDevice {
                    device_model,
                    route_kind,
                    constraint_id,
                } => {
                    assert_eq!(device_model, "DJI Flip");
                    assert_eq!(*route_kind, CaptureRouteKind::LiveStreaming);
                    assert_eq!(*constraint_id, CONSTRAINT_NEG_001);
                }
                other => return Err(format!("unexpected reason: {other:?}").into()),
            }
        }
        other => return Err(format!("expected Unsupported result, got: {other:?}").into()),
    }

    assert!(!result.is_adapter_accepted());
    assert!(!result.is_streaming());
    assert!(!result.is_ready());
    assert_eq!(result.readiness_state(), CaptureReadinessState::Unsupported);

    Ok(())
}

#[test]
fn test_neg001_gate100_recorded_import_and_lab_bridge_succeed()
-> Result<(), Box<dyn std::error::Error>> {
    let tuple = make_dji_flip_tuple()?;

    // 1. GATE-100 RecordedFileImport
    let import_result =
        evaluate_capture_route(&tuple, CaptureRouteKind::RecordedFileImport, true, true);

    match &import_result {
        LiveCaptureRouteResult::Established(est) => {
            assert_eq!(est.promotion_gate, "GATE-100");
            assert_eq!(est.route_kind, CaptureRouteKind::RecordedFileImport);
            assert!(est.authority_lease_id.contains("recorded-import"));
        }
        other => {
            return Err(format!("expected Established for recorded import, got: {other:?}").into());
        }
    }

    assert!(import_result.is_ready());
    assert_eq!(
        import_result.readiness_state(),
        CaptureReadinessState::QualifiedReady
    );
    // Route evaluation is NOT adapter acceptance and NEVER streaming
    assert!(!import_result.is_adapter_accepted());
    assert!(!import_result.is_streaming());

    // 2. GATE-100 OwnerAuthorizedLabBridge
    let lab_result = evaluate_capture_route(
        &tuple,
        CaptureRouteKind::OwnerAuthorizedLabBridge,
        true,
        true,
    );

    match &lab_result {
        LiveCaptureRouteResult::Established(est) => {
            assert_eq!(est.promotion_gate, "GATE-100");
            assert_eq!(est.route_kind, CaptureRouteKind::OwnerAuthorizedLabBridge);
            assert!(est.authority_lease_id.contains("lab-bridge"));
        }
        other => return Err(format!("expected Established for lab bridge, got: {other:?}").into()),
    }

    assert!(lab_result.is_ready());
    assert_eq!(
        lab_result.readiness_state(),
        CaptureReadinessState::QualifiedReady
    );
    assert!(!lab_result.is_adapter_accepted());
    assert!(!lab_result.is_streaming());

    Ok(())
}

#[test]
fn test_neg001_unestablished_device_tuple_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let unestablished_tuple = CaptureDeviceTuple::new(
        "Generic Camera",
        "unestablished-fw",
        "none",
        "unestablished-app",
        "linux-x86_64",
        "unauthorized-account",
    )?;

    assert!(!unestablished_tuple.is_dji_flip());

    let result = evaluate_capture_route(
        &unestablished_tuple,
        CaptureRouteKind::LiveStreaming,
        true,
        true,
    );

    match &result {
        LiveCaptureRouteResult::Unsupported(unsupported) => match &unsupported.reason {
            UnsupportedCaptureReason::UnestablishedDeviceTuple { missing_dimension } => {
                assert!(missing_dimension.contains("unestablished"));
            }
            other => return Err(format!("unexpected reason: {other:?}").into()),
        },
        other => return Err(format!("expected Unsupported result, got: {other:?}").into()),
    }

    assert!(!result.is_adapter_accepted());
    assert!(!result.is_streaming());
    assert!(!result.is_ready());
    assert_eq!(result.readiness_state(), CaptureReadinessState::Unsupported);

    Ok(())
}

#[test]
fn test_neg001_auth_revocation_returns_unavailable() -> Result<(), Box<dyn std::error::Error>> {
    let tuple = make_dji_flip_tuple()?;

    let result = evaluate_capture_route(
        &tuple,
        CaptureRouteKind::RecordedFileImport,
        false, // Authority revoked
        true,
    );

    match &result {
        LiveCaptureRouteResult::Unavailable(unavail) => match &unavail.reason {
            UnavailableCaptureReason::AuthRevoked { detail } => {
                assert!(detail.contains("revoked"));
            }
            other => return Err(format!("unexpected reason: {other:?}").into()),
        },
        other => return Err(format!("expected Unavailable result, got: {other:?}").into()),
    }

    assert!(!result.is_adapter_accepted());
    assert!(!result.is_streaming());
    assert!(!result.is_ready());
    assert_eq!(result.readiness_state(), CaptureReadinessState::Unavailable);

    Ok(())
}

#[test]
fn test_neg001_privacy_scope_mismatch_returns_unavailable() -> Result<(), Box<dyn std::error::Error>>
{
    let tuple = make_dji_flip_tuple()?;

    let result = evaluate_capture_route(
        &tuple,
        CaptureRouteKind::RecordedFileImport,
        true,
        false, // Privacy scope mismatch
    );

    match &result {
        LiveCaptureRouteResult::Unavailable(unavail) => match &unavail.reason {
            UnavailableCaptureReason::PrivacyScopeExceeded { scope, required } => {
                assert_eq!(scope, "owner-authorized-lab");
                assert_eq!(required, "owner-authorized-lab");
            }
            other => return Err(format!("unexpected reason: {other:?}").into()),
        },
        other => return Err(format!("expected Unavailable result, got: {other:?}").into()),
    }

    assert!(!result.is_adapter_accepted());
    assert!(!result.is_streaming());
    assert!(!result.is_ready());
    assert_eq!(result.readiness_state(), CaptureReadinessState::Unavailable);

    Ok(())
}

#[test]
fn test_neg001_acquisition_request_refuses_dji_flip_streaming()
-> Result<(), Box<dyn std::error::Error>> {
    let source_id = SourceId::parse("src:dji:flip01")?;
    let device_id = DeviceId::parse("device:dji:flip01")?;
    let adapter_id = AdapterId::parse("adapter:dji:flip01")?;
    let stream_generation = StreamGeneration::parse("gen:stream:1080p60-nv12")?;

    let source_identity = SourceIdentity {
        source_id,
        device_id: device_id.clone(),
        adapter_id: adapter_id.clone(),
        source_kind: SourceKind::PhysicalSensor,
        media_kind: MediaKind::Video,
        channel: "main".to_string(),
        nominal_clock_basis: ClockBasis::HostMonotonic,
        stream_generation,
        failure_domain: "power:lab-bench-1".to_string(),
        is_live: true,
    };

    let device_identity = DeviceIdentity {
        device_id: device_id.clone(),
        generation: DeviceGeneration::parse("gen:dev:2026-09-12:rev1")?,
        manufacturer: "DJI".to_string(),
        model: "Flip".to_string(),
        hardware_revision: "HW-1.0".to_string(),
        firmware_version: FirmwareGeneration::parse("gen:firmware:v1-0-100")?,
        application_version: None,
        model_generation: None,
        device_class: DeviceClass::Camera,
        capabilities: DeviceCapabilities::AUDIO_CAPTURE,
        failure_domain: "power:lab-bench-1".to_string(),
    };

    let adapter_identity = AdapterIdentity {
        adapter_id: adapter_id.clone(),
        generation: AdapterGeneration::parse("gen:adapter:dji-flip-lab-v1")?,
        adapter_kind: AdapterKind::FileArchive,
        protocol_profile: "lab:dji-flip:bridge".to_string(),
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::None,
        capabilities: AdapterCapabilities::STREAMING,
        max_bandwidth_bytes_per_sec: 50_000_000,
        max_buffer_frames: 16,
        request_timeout_ns: 5_000_000_000,
    };

    let request = AcquisitionRequest {
        source_identity,
        device_identity,
        adapter_identity,
        requested_capabilities: AdapterCapabilities::STREAMING,
        requested_at_ns: TimestampNs(1_000_000_000),
    };

    // AcquisitionRequest::verify must fail closed with UnsupportedLiveRoute for DJI Flip streaming
    match request.verify() {
        Err(AcquisitionError::UnsupportedLiveRoute {
            constraint_id,
            detail,
        }) => {
            assert_eq!(constraint_id, CONSTRAINT_NEG_001);
            assert!(detail.contains("DJI Flip live streaming"));
        }
        other => return Err(format!("expected UnsupportedLiveRoute error, got: {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_neg001_tuple_canonical_encoding_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let tuple = make_dji_flip_tuple()?;
    let bytes = tuple.try_canonical_bytes()?;
    let decoded = CaptureDeviceTuple::from_canonical_bytes(&bytes)?;
    assert_eq!(tuple, decoded);

    let route = CaptureRouteKind::ProprietarySdkLiveCapture;
    let bytes2 = route.try_canonical_bytes()?;
    let dec_route = CaptureRouteKind::from_canonical_bytes(&bytes2)?;
    assert_eq!(route, dec_route);

    let readiness = CaptureReadinessState::Unsupported;
    let bytes3 = readiness.try_canonical_bytes()?;
    let dec_readiness = CaptureReadinessState::from_canonical_bytes(&bytes3)?;
    assert_eq!(readiness, dec_readiness);

    Ok(())
}

#[test]
fn test_neg001_empty_tuple_fields_fail_closed() {
    assert!(matches!(
        CaptureDeviceTuple::new("", "v1", "rc", "app", "linux", "scope"),
        Err(ContractError::InvalidIdentifier)
    ));
    assert!(matches!(
        CaptureDeviceTuple::new("model", "  ", "rc", "app", "linux", "scope"),
        Err(ContractError::InvalidIdentifier)
    ));
    assert!(matches!(
        CaptureDeviceTuple::new("model", "v1", "rc", "app", "", "scope"),
        Err(ContractError::InvalidIdentifier)
    ));
    assert!(matches!(
        CaptureDeviceTuple::new("model", "v1", "rc", "app", "linux", "  "),
        Err(ContractError::InvalidIdentifier)
    ));
}

#[test]
fn test_neg001_scenario_jsonl_log_contains_no_secrets() -> Result<(), Box<dyn std::error::Error>> {
    let tuple = make_dji_flip_tuple()?;
    let source_digest = ContentDigest::sha256(b"dji_flip_source_evidence_v1");
    let registry_digest = ContentDigest::sha256(b"adapter_registry_neg001_sha");
    let proof_hash = ContentDigest::sha256(b"proof_bundle_neg001");

    let log_entry = Neg001ScenarioLog {
        schema_version: SCHEMA_NEG001_SCENARIO_LOG,
        run_id: "run-neg001-qual-001".to_string(),
        neg_id: CONSTRAINT_NEG_001,
        source_digest,
        registry_digest,
        tuple,
        route_kind: CaptureRouteKind::ProprietarySdkLiveCapture,
        authority_scope: "owner-authorized-lab".to_string(),
        privacy_scope: "lab-isolated".to_string(),
        hypothesis_state: "rejected",
        finding_state: "unestablished_mobile_sdk",
        decision_state: "non_dependency_preserved",
        expected_readiness: CaptureReadinessState::Unsupported,
        observed_readiness: CaptureReadinessState::Unsupported,
        is_adapter_accepted: false,
        is_streaming: false,
        revival_condition_met: false,
        proof_hash,
        reproduction_command: "cargo test -p fss-core --test dji_flip_capture_route_contract"
            .to_string(),
    };

    let line = log_entry.to_jsonl_line();
    assert!(line.contains("\"schema_version\":\"fss.negative_evidence.scenario_log.v1\""));
    assert!(line.contains("\"neg_id\":\"NEG-001\""));
    assert!(line.contains("\"is_adapter_accepted\":false"));
    assert!(line.contains("\"is_streaming\":false"));
    assert!(line.contains("\"expected_readiness\":\"unsupported\""));
    assert!(line.contains("\"observed_readiness\":\"unsupported\""));

    // Verify no private credentials or secrets in output
    let lower = line.to_lowercase();
    assert!(!lower.contains("password"));
    assert!(!lower.contains("private_key"));
    assert!(!lower.contains("bearer"));
    assert!(!lower.contains("secret"));

    Ok(())
}
