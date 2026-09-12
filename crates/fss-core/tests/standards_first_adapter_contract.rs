#![forbid(unsafe_code)]
//! Tests for standards-first camera access compliance under NEG-002 (fss-x4a.1.32.2).

use fss_core::identity::{
    AdapterCapabilities, AdapterIdentity, AdapterKind, CredentialMethod, IsolationMode,
    StandardsComplianceError,
};
use fss_core::{AdapterGeneration, AdapterId};

#[test]
fn test_valid_standards_first_adapters_pass() -> Result<(), Box<dyn std::error::Error>> {
    let uvc_adapter = AdapterIdentity {
        adapter_id: AdapterId::parse("adapter:generic-uvc-001")?,
        generation: AdapterGeneration::parse("gen:adapter:uvc-v1")?,
        adapter_kind: AdapterKind::Uvc,
        protocol_profile: "uvc:1.5:isochronous".to_string(),
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::None,
        capabilities: AdapterCapabilities::STREAMING,
        max_bandwidth_bytes_per_sec: 100_000_000,
        max_buffer_frames: 16,
        request_timeout_ns: 5_000_000_000,
    };
    assert!(uvc_adapter.verify_standards_compliance().is_ok());

    let rtsp_adapter = AdapterIdentity {
        adapter_id: AdapterId::parse("adapter:generic-rtsp-001")?,
        generation: AdapterGeneration::parse("gen:adapter:rtsp-v1")?,
        adapter_kind: AdapterKind::Rtsp,
        protocol_profile: "rtsp:rfc2326:interleaved".to_string(),
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::DigestAuth,
        capabilities: AdapterCapabilities::STREAMING,
        max_bandwidth_bytes_per_sec: 50_000_000,
        max_buffer_frames: 32,
        request_timeout_ns: 5_000_000_000,
    };
    assert!(rtsp_adapter.verify_standards_compliance().is_ok());

    let onvif_adapter = AdapterIdentity {
        adapter_id: AdapterId::parse("adapter:onvif-t-001")?,
        generation: AdapterGeneration::parse("gen:adapter:onvif-v1")?,
        adapter_kind: AdapterKind::OnvifProfileT,
        protocol_profile: "onvif:profile-t:h264".to_string(),
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::BasicAuth,
        capabilities: AdapterCapabilities::STREAMING.union(AdapterCapabilities::PTZ_CONTROL),
        max_bandwidth_bytes_per_sec: 50_000_000,
        max_buffer_frames: 32,
        request_timeout_ns: 5_000_000_000,
    };
    assert!(onvif_adapter.verify_standards_compliance().is_ok());
    Ok(())
}

#[test]
fn test_marketing_inferred_standards_claim_fails_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let bad_adapter = AdapterIdentity {
        adapter_id: AdapterId::parse("adapter:consumer-wifi-cam-001")?,
        generation: AdapterGeneration::parse("gen:adapter:cam-v1")?,
        adapter_kind: AdapterKind::Rtsp,
        protocol_profile: "rtsp:inferred-from-marketing-box-claim".to_string(),
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::None,
        capabilities: AdapterCapabilities::STREAMING,
        max_bandwidth_bytes_per_sec: 10_000_000,
        max_buffer_frames: 16,
        request_timeout_ns: 5_000_000_000,
    };

    let res = bad_adapter.verify_standards_compliance();
    assert!(matches!(
        res,
        Err(StandardsComplianceError::UnverifiedStandardsClaim { ref detail })
            if detail.contains("marketing") || detail.contains("box")
    ));
    Ok(())
}

#[test]
fn test_proprietary_native_promotion_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let proprietary_adapter = AdapterIdentity {
        adapter_id: AdapterId::parse("adapter:wyze-v4-lab-001")?,
        generation: AdapterGeneration::parse("gen:adapter:wyze-v1")?,
        adapter_kind: AdapterKind::VirtualSimulated,
        protocol_profile: "vendor:reverse-engineered-app-protocol".to_string(),
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::None,
        capabilities: AdapterCapabilities::STREAMING,
        max_bandwidth_bytes_per_sec: 10_000_000,
        max_buffer_frames: 16,
        request_timeout_ns: 5_000_000_000,
    };

    let res = proprietary_adapter.verify_standards_compliance();
    assert!(matches!(
        res,
        Err(StandardsComplianceError::ProprietaryNativePromotion { ref detail })
            if detail.contains("wyze") || detail.contains("NativePureRust")
    ));
    Ok(())
}

#[test]
fn test_proprietary_in_sealed_laboratory_passes() -> Result<(), Box<dyn std::error::Error>> {
    let lab_adapter = AdapterIdentity {
        adapter_id: AdapterId::parse("adapter:wyze-v4-lab-001")?,
        generation: AdapterGeneration::parse("gen:adapter:wyze-v1")?,
        adapter_kind: AdapterKind::VirtualSimulated,
        protocol_profile: "authorized-lab:wyze-v4-fw-1.2.3".to_string(),
        isolation_mode: IsolationMode::SealedLaboratoryProcess,
        credential_method: CredentialMethod::Token,
        capabilities: AdapterCapabilities::STREAMING,
        max_bandwidth_bytes_per_sec: 10_000_000,
        max_buffer_frames: 16,
        request_timeout_ns: 5_000_000_000,
    };

    assert!(lab_adapter.verify_standards_compliance().is_ok());
    Ok(())
}

#[test]
fn test_unscoped_vendor_token_in_native_driver_fails_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let bad_token_adapter = AdapterIdentity {
        adapter_id: AdapterId::parse("adapter:unscoped-token-cam-001")?,
        generation: AdapterGeneration::parse("gen:adapter:cam-v1")?,
        adapter_kind: AdapterKind::Rtsp,
        protocol_profile: "rtsp:rfc2326:interleaved".to_string(),
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::Token,
        capabilities: AdapterCapabilities::STREAMING,
        max_bandwidth_bytes_per_sec: 10_000_000,
        max_buffer_frames: 16,
        request_timeout_ns: 5_000_000_000,
    };

    let res = bad_token_adapter.verify_standards_compliance();
    assert!(matches!(
        res,
        Err(StandardsComplianceError::UnscopedVendorToken { ref detail })
            if detail.contains("token")
    ));
    Ok(())
}

#[test]
fn test_unverified_standards_claim_without_evidence_fails_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let unverified_adapter = AdapterIdentity {
        adapter_id: AdapterId::parse("adapter:unverified-onvif-001")?,
        generation: AdapterGeneration::parse("gen:adapter:cam-v1")?,
        adapter_kind: AdapterKind::OnvifProfileT,
        protocol_profile: "generic live onvif stream".to_string(), // lacks qualifying evidence/spec reference
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::BasicAuth,
        capabilities: AdapterCapabilities::STREAMING,
        max_bandwidth_bytes_per_sec: 50_000_000,
        max_buffer_frames: 32,
        request_timeout_ns: 5_000_000_000,
    };

    let res = unverified_adapter.verify_standards_compliance();
    assert!(matches!(
        res,
        Err(StandardsComplianceError::UnverifiedStandardsClaim { .. })
    ));
    Ok(())
}

#[test]
fn test_marketing_underscore_and_synonyms_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let bad_adapter = AdapterIdentity {
        adapter_id: AdapterId::parse("adapter:synonym-cam-001")?,
        generation: AdapterGeneration::parse("gen:adapter:cam-v1")?,
        adapter_kind: AdapterKind::Rtsp,
        protocol_profile: "rtsp:rfc2326:datasheet".to_string(),
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::None,
        capabilities: AdapterCapabilities::STREAMING,
        max_bandwidth_bytes_per_sec: 10_000_000,
        max_buffer_frames: 16,
        request_timeout_ns: 5_000_000_000,
    };

    let res = bad_adapter.verify_standards_compliance();
    assert!(matches!(
        res,
        Err(StandardsComplianceError::UnverifiedStandardsClaim { ref detail })
            if detail.contains("datasheet")
    ));
    Ok(())
}

#[test]
fn test_proprietary_vendor_ring_nest_in_native_fails_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let ring_adapter = AdapterIdentity {
        adapter_id: AdapterId::parse("adapter:ring-doorbell-001")?,
        generation: AdapterGeneration::parse("gen:adapter:ring-v1")?,
        adapter_kind: AdapterKind::VirtualSimulated,
        protocol_profile: "ring-cloud-stream".to_string(),
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::None,
        capabilities: AdapterCapabilities::STREAMING,
        max_bandwidth_bytes_per_sec: 10_000_000,
        max_buffer_frames: 16,
        request_timeout_ns: 5_000_000_000,
    };

    let res = ring_adapter.verify_standards_compliance();
    assert!(matches!(
        res,
        Err(StandardsComplianceError::ProprietaryNativePromotion { ref detail })
            if detail.contains("ring")
    ));

    let nest_adapter = AdapterIdentity {
        adapter_id: AdapterId::parse("adapter:nest-cam-001")?,
        generation: AdapterGeneration::parse("gen:adapter:nest-v1")?,
        adapter_kind: AdapterKind::VirtualSimulated,
        protocol_profile: "nest-webrtc-stream".to_string(),
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::None,
        capabilities: AdapterCapabilities::STREAMING,
        max_bandwidth_bytes_per_sec: 10_000_000,
        max_buffer_frames: 16,
        request_timeout_ns: 5_000_000_000,
    };

    let res = nest_adapter.verify_standards_compliance();
    assert!(matches!(
        res,
        Err(StandardsComplianceError::ProprietaryNativePromotion { ref detail })
            if detail.contains("nest")
    ));
    Ok(())
}

#[test]
fn test_screen_capture_with_spaces_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = AdapterIdentity {
        adapter_id: AdapterId::parse("adapter:screen-capture-bridge-001")?,
        generation: AdapterGeneration::parse("gen:adapter:v1")?,
        adapter_kind: AdapterKind::VirtualSimulated,
        protocol_profile: "screen capture stream".to_string(), // space instead of underscore
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::None,
        capabilities: AdapterCapabilities::STREAMING,
        max_bandwidth_bytes_per_sec: 10_000_000,
        max_buffer_frames: 16,
        request_timeout_ns: 5_000_000_000,
    };
    let res = adapter.verify_standards_compliance();
    assert!(matches!(
        res,
        Err(StandardsComplianceError::ProprietaryNativePromotion { .. })
    ));
    Ok(())
}

#[test]
fn test_app_automation_with_spaces_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = AdapterIdentity {
        adapter_id: AdapterId::parse("adapter:app-automation-bridge-001")?,
        generation: AdapterGeneration::parse("gen:adapter:v1")?,
        adapter_kind: AdapterKind::VirtualSimulated,
        protocol_profile: "app automation bridge".to_string(),
        isolation_mode: IsolationMode::NativePureRust,
        credential_method: CredentialMethod::None,
        capabilities: AdapterCapabilities::STREAMING,
        max_bandwidth_bytes_per_sec: 10_000_000,
        max_buffer_frames: 16,
        request_timeout_ns: 5_000_000_000,
    };
    let res = adapter.verify_standards_compliance();
    assert!(matches!(
        res,
        Err(StandardsComplianceError::ProprietaryNativePromotion { .. })
    ));
    Ok(())
}

#[test]
fn test_unscoped_vendor_token_in_sealed_lab_fails_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = AdapterIdentity {
        adapter_id: AdapterId::parse("adapter:wyze-ambient-001")?,
        generation: AdapterGeneration::parse("gen:adapter:wyze-v1")?,
        adapter_kind: AdapterKind::VirtualSimulated,
        protocol_profile: "authorized-lab:global-ambient-token:wyze-v4".to_string(),
        isolation_mode: IsolationMode::SealedLaboratoryProcess,
        credential_method: CredentialMethod::Token,
        capabilities: AdapterCapabilities::STREAMING,
        max_bandwidth_bytes_per_sec: 10_000_000,
        max_buffer_frames: 16,
        request_timeout_ns: 5_000_000_000,
    };
    let res = adapter.verify_standards_compliance();
    assert!(matches!(
        res,
        Err(StandardsComplianceError::UnscopedVendorToken { .. })
    ));
    Ok(())
}

#[test]
fn test_security_boundary_violation_in_rust_fails_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = AdapterIdentity {
        adapter_id: AdapterId::parse("adapter:scanner-cam-001")?,
        generation: AdapterGeneration::parse("gen:adapter:v1")?,
        adapter_kind: AdapterKind::VirtualSimulated,
        protocol_profile: "auth-bypass:broad-scanning".to_string(),
        isolation_mode: IsolationMode::SealedLaboratoryProcess,
        credential_method: CredentialMethod::None,
        capabilities: AdapterCapabilities::STREAMING,
        max_bandwidth_bytes_per_sec: 10_000_000,
        max_buffer_frames: 16,
        request_timeout_ns: 5_000_000_000,
    };
    let res = adapter.verify_standards_compliance();
    let err_str = format!("{res:?}");
    assert!(err_str.contains("SecurityBoundaryViolation"));
    Ok(())
}
