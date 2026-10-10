#![forbid(unsafe_code)]
//! Batch contract tests for the seven remaining device-adapter registry-row
//! realizations (fss-x4a.30.89.2/.3/.4/.5/.6/.7/.10/.11): construction,
//! verification, NEG-002 compliance, canonical round-trip, digest
//! distinctness, and per-row capability/credential honesty.

use fss_core::{
    AdapterCapabilities, AdapterKind, CanonicalDecode, CanonicalEncode, CanonicalEncoder,
    CredentialMethod, IsolationMode,
};
use fss_reference::{
    adp_dji_flip_adapter_identity, adp_insta_link_adapter_identity, adp_onvif_m_adapter_identity,
    adp_onvif_t_adapter_identity, adp_rtsp_adapter_identity, adp_s3_adapter_identity,
    adp_uvc_adapter_identity,
};

macro_rules! row_tests {
    ($name:ident, $ctor:expr, $runtime_id:literal, $kind:expr, $isolation:expr, $cred:expr) => {
        #[test]
        fn $name() {
            let id = $ctor.expect("identity must construct");
            assert_eq!(id.adapter_id.as_str(), $runtime_id);
            assert_eq!(id.adapter_kind, $kind);
            assert_eq!(id.isolation_mode, $isolation);
            assert_eq!(id.credential_method, $cred);
            id.verify().expect("structural verify");
            id.verify_standards_compliance().expect("NEG-002 compliance");
            // Canonical round-trip is identity.
            let mut encoder = CanonicalEncoder::new();
            id.encode_canonical(&mut encoder);
            let bytes = encoder.finish();
            let mut decoder = fss_core::CanonicalDecoder::new(&bytes);
            let back = fss_core::AdapterIdentity::decode_canonical(&mut decoder).expect("decode");
            assert_eq!(id, back);
        }
    };
}

row_tests!(
    rtsp_row,
    adp_rtsp_adapter_identity(),
    "adapter:adp-rtsp-001",
    AdapterKind::Rtsp,
    IsolationMode::NativePureRust,
    CredentialMethod::DigestAuth
);
row_tests!(
    uvc_row,
    adp_uvc_adapter_identity(),
    "adapter:adp-uvc-001",
    AdapterKind::Uvc,
    IsolationMode::NativePureRust,
    CredentialMethod::None
);
row_tests!(
    insta_link_row,
    adp_insta_link_adapter_identity(),
    "adapter:adp-insta-link-001",
    AdapterKind::Uvc,
    IsolationMode::NativePureRust,
    CredentialMethod::None
);
row_tests!(
    onvif_t_row,
    adp_onvif_t_adapter_identity(),
    "adapter:adp-onvif-t-001",
    AdapterKind::OnvifProfileT,
    IsolationMode::NativePureRust,
    CredentialMethod::DigestAuth
);
row_tests!(
    onvif_m_row,
    adp_onvif_m_adapter_identity(),
    "adapter:adp-onvif-m-001",
    AdapterKind::OnvifProfileM,
    IsolationMode::NativePureRust,
    CredentialMethod::DigestAuth
);
row_tests!(
    dji_flip_row,
    adp_dji_flip_adapter_identity(),
    "adapter:adp-dji-flip-lab-001",
    AdapterKind::FileArchive,
    IsolationMode::SealedLaboratoryProcess,
    CredentialMethod::None
);
row_tests!(
    s3_import_row,
    adp_s3_adapter_identity(),
    "adapter:adp-s3-import-001",
    AdapterKind::FileArchive,
    IsolationMode::SealedLaboratoryProcess,
    CredentialMethod::Token
);

#[test]
fn all_row_digests_are_distinct() {
    let digests = [
        adp_rtsp_adapter_identity().expect("rtsp").canonical_digest(),
        adp_uvc_adapter_identity().expect("uvc").canonical_digest(),
        adp_insta_link_adapter_identity().expect("insta").canonical_digest(),
        adp_onvif_t_adapter_identity().expect("onvif-t").canonical_digest(),
        adp_onvif_m_adapter_identity().expect("onvif-m").canonical_digest(),
        adp_dji_flip_adapter_identity().expect("dji").canonical_digest(),
        adp_s3_adapter_identity().expect("s3").canonical_digest(),
    ];
    for i in 0..digests.len() {
        for j in (i + 1)..digests.len() {
            assert_ne!(digests[i], digests[j], "rows {i} and {j} share a digest");
        }
    }
}

#[test]
fn capability_honesty_by_row() {
    // DJI Flip: manual import only — zero capabilities claimed (NEG-001).
    let dji = adp_dji_flip_adapter_identity().expect("dji");
    assert_eq!(dji.capabilities, AdapterCapabilities::NONE);
    // ONVIF-M: metadata only — telemetry, no streaming.
    let onvif_m = adp_onvif_m_adapter_identity().expect("onvif-m");
    assert!(onvif_m.capabilities.contains(AdapterCapabilities::TELEMETRY));
    assert!(!onvif_m.capabilities.contains(AdapterCapabilities::STREAMING));
    // RTSP/ONVIF-T: streaming + discovery.
    let rtsp = adp_rtsp_adapter_identity().expect("rtsp");
    assert!(rtsp.capabilities.contains(AdapterCapabilities::STREAMING));
    assert!(rtsp.capabilities.contains(AdapterCapabilities::DEVICE_DISCOVERY));
    // UVC rows: streaming + snapshot.
    let uvc = adp_uvc_adapter_identity().expect("uvc");
    assert!(uvc.capabilities.contains(AdapterCapabilities::STREAMING));
    assert!(uvc.capabilities.contains(AdapterCapabilities::SNAPSHOT));
}

#[test]
fn standards_claims_cite_specifications() {
    // NEG-002 rule 2: standards rows must carry spec/gate citations in the
    // profile (enforced at construction for Rtsp/Uvc/OnvifProfileT kinds).
    let rtsp = adp_rtsp_adapter_identity().expect("rtsp");
    assert!(rtsp.protocol_profile.contains("rfc2326"));
    let uvc = adp_uvc_adapter_identity().expect("uvc");
    assert!(uvc.protocol_profile.contains("uvc"));
    let onvif_t = adp_onvif_t_adapter_identity().expect("onvif-t");
    assert!(onvif_t.protocol_profile.to_ascii_lowercase().contains("profile-t"));
}

#[test]
fn file_row_uses_the_canonical_registry_id() {
    // The runtime id stays the lane's identity of record (`adp:file-001`
    // normalizes to `adapter:file-001`); the registry row ADP-FILE-001 maps
    // to it via the ADP_FILE_ROW_ID/ADP_FILE_RUNTIME_ID constants.
    let id = fss_reference::ingest::file_adapter::default_adapter_identity()
        .expect("file identity");
    assert_eq!(id.adapter_id.as_str(), "adapter:file-001");
    assert_eq!(id.adapter_kind, AdapterKind::FileArchive);
    id.verify().expect("verify");
    id.verify_standards_compliance().expect("compliance");
}
