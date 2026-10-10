#![forbid(unsafe_code)]
//! Contract tests for the ADP-AOSU-P1MAX-LAB-001 typed registry-row
//! realization (bead fss-x4a.30.89.9): identity construction, canonical
//! round-trip and ordering, NEG-002 compliance both directions, generation
//! monotonicity, capability honesty, and kind parsing fail-closed.

use fss_core::{
    AdapterCapabilities, AdapterKind, CanonicalDecode, CanonicalEncode, CanonicalEncoder,
    ContractError, CredentialMethod, IsolationMode,
};
use fss_reference::{
    ADP_AOSU_CAPABILITIES, ADP_AOSU_CURRENT_STATE, ADP_AOSU_GENERATION, ADP_AOSU_PROMOTION_GATE,
    ADP_AOSU_PROTOCOL_PROFILE, ADP_AOSU_ROW_ID, ADP_AOSU_SURFACE, ADP_AOSU_TIER,
    adp_aosu_adapter_identity,
};

#[test]
fn row_constants_match_the_normative_registry_row() {
    assert_eq!(ADP_AOSU_ROW_ID, "ADP-AOSU-P1MAX-LAB-001");
    assert_eq!(ADP_AOSU_SURFACE, "AOSU P1 Max owner-auth lab");
    assert_eq!(ADP_AOSU_TIER, "T3");
    assert_eq!(ADP_AOSU_CURRENT_STATE, "research target");
    assert_eq!(ADP_AOSU_PROMOTION_GATE, "GATE-090");
    assert_eq!(ADP_AOSU_GENERATION, "gen:fss1:adapters-v1");
}

#[test]
fn identity_constructs_verified_and_compliant() {
    let id = adp_aosu_adapter_identity().expect("identity must construct");
    assert_eq!(id.adapter_id.as_str(), "adapter:adp-aosu-p1max-lab-001");
    assert_eq!(id.adapter_kind, AdapterKind::TuyaLan);
    assert_eq!(id.protocol_profile, ADP_AOSU_PROTOCOL_PROFILE);
    // NEG-002: proprietary lab path is sealed, credential is a device-local
    // secret (the Tuya local_key), never an ambient token.
    assert_eq!(id.isolation_mode, IsolationMode::SealedLaboratoryProcess);
    assert_eq!(id.credential_method, CredentialMethod::LocalSecret);
    id.verify().expect("structural verify");
    id.verify_standards_compliance().expect("NEG-002 compliance");
}

#[test]
fn capability_honesty_no_streaming_for_event_driven_battery_cams() {
    // The adapter must never imply continuous coverage.
    assert!(!ADP_AOSU_CAPABILITIES.contains(AdapterCapabilities::STREAMING));
    assert!(ADP_AOSU_CAPABILITIES.contains(AdapterCapabilities::DEVICE_DISCOVERY));
    assert!(ADP_AOSU_CAPABILITIES.contains(AdapterCapabilities::TELEMETRY));
    assert!(ADP_AOSU_CAPABILITIES.is_valid());
}

#[test]
fn canonical_roundtrip_and_digest_stability() {
    let id = adp_aosu_adapter_identity().expect("identity");
    let mut encoder = CanonicalEncoder::new();
    id.encode_canonical(&mut encoder);
    let bytes = encoder.finish();
    let mut decoder = fss_core::CanonicalDecoder::new(&bytes);
    let back = fss_core::AdapterIdentity::decode_canonical(&mut decoder).expect("decode");
    assert_eq!(id, back, "canonical encode/decode is identity");
    // Digest is deterministic across constructions.
    let again = adp_aosu_adapter_identity().expect("identity again");
    assert_eq!(id.canonical_digest(), again.canonical_digest());
}

#[test]
fn kind_parse_roundtrip_and_fail_closed() {
    assert_eq!(AdapterKind::TuyaLan.as_str(), "tuya_lan");
    assert_eq!(AdapterKind::TutkIotc.as_str(), "tutk_iotc");
    assert_eq!(AdapterKind::parse("tuya_lan"), Ok(AdapterKind::TuyaLan));
    assert_eq!(AdapterKind::parse("tutk_iotc"), Ok(AdapterKind::TutkIotc));
    assert_eq!(
        AdapterKind::parse("aosu_cloud"),
        Err(ContractError::InvalidIdentifier),
        "unknown kinds fail closed"
    );
    // Canonical decode rejects undefined discriminants.
    let raw = [9u8];
    let mut decoder = fss_core::CanonicalDecoder::new(&raw);
    assert!(AdapterKind::decode_canonical(&mut decoder).is_err());
}

#[test]
fn proprietary_lab_path_cannot_claim_native_isolation() {
    let mut id = adp_aosu_adapter_identity().expect("identity");
    id.isolation_mode = IsolationMode::NativePureRust;
    assert!(
        id.verify_standards_compliance().is_err(),
        "NEG-002 must reject native isolation for a proprietary lab row"
    );
}

#[test]
fn generation_transitions_are_monotonic() {
    let id = adp_aosu_adapter_identity().expect("identity");
    // Same-generation transition fails closed.
    let same = fss_core::AdapterGeneration::parse(ADP_AOSU_GENERATION).expect("generation");
    assert_eq!(
        id.transition_generation(same),
        Err(ContractError::GenerationConflict)
    );
    // A strictly newer generation succeeds and re-verifies.
    let newer = fss_core::AdapterGeneration::parse("gen:fss1:adapters-v2").expect("newer gen");
    let next = id.transition_generation(newer).expect("transition");
    assert!(next.generation > id.generation);
    next.verify().expect("re-verify");
}

#[test]
fn identity_field_bounds_enforced() {
    let mut id = adp_aosu_adapter_identity().expect("identity");
    id.protocol_profile = String::new();
    assert_eq!(id.verify(), Err(ContractError::InvalidIdentifier));
    let mut id = adp_aosu_adapter_identity().expect("identity");
    id.max_buffer_frames = 0;
    assert_eq!(id.verify(), Err(ContractError::InvalidIdentifier));
    let mut id = adp_aosu_adapter_identity().expect("identity");
    id.request_timeout_ns = 0;
    assert_eq!(id.verify(), Err(ContractError::InvalidIdentifier));
}
