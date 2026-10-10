//! Contract tests for the ADP-WYZE-V4-LAB-001 typed registry-row
//! realization (bead fss-x4a.30.89.8): identity construction, canonical
//! round-trip, NEG-002 compliance both directions, generation monotonicity,
//! and capability honesty (streaming IS live-proven on this tuple, unlike
//! the battery AOSU lane — the two rows must differ exactly there).

use fss_core::{
    AdapterCapabilities, AdapterKind, CanonicalDecode, CanonicalEncode, CanonicalEncoder,
    ContractError, CredentialMethod, IsolationMode,
};
use fss_reference::{
    ADP_WYZE_CAPABILITIES, ADP_WYZE_CURRENT_STATE, ADP_WYZE_GENERATION, ADP_WYZE_PROMOTION_GATE,
    ADP_WYZE_PROTOCOL_PROFILE, ADP_WYZE_ROW_ID, ADP_WYZE_SURFACE, ADP_WYZE_TIER,
    adp_aosu_adapter_identity, adp_wyze_adapter_identity,
};

#[test]
fn row_constants_match_the_normative_registry_row() {
    assert_eq!(ADP_WYZE_ROW_ID, "ADP-WYZE-V4-LAB-001");
    assert_eq!(ADP_WYZE_SURFACE, "Wyze Cam v4 owner-auth lab");
    assert_eq!(ADP_WYZE_TIER, "T3");
    assert_eq!(ADP_WYZE_CURRENT_STATE, "research target");
    assert_eq!(ADP_WYZE_PROMOTION_GATE, "GATE-090");
    assert_eq!(ADP_WYZE_GENERATION, "gen:fss1:adapters-v1");
}

#[test]
fn identity_constructs_verified_and_compliant() {
    let id = adp_wyze_adapter_identity().expect("identity must construct");
    assert_eq!(id.adapter_id.as_str(), "adapter:adp-wyze-v4-lab-001");
    assert_eq!(id.adapter_kind, AdapterKind::TutkIotc);
    assert_eq!(id.protocol_profile, ADP_WYZE_PROTOCOL_PROFILE);
    assert_eq!(id.isolation_mode, IsolationMode::SealedLaboratoryProcess);
    assert_eq!(id.credential_method, CredentialMethod::LocalSecret);
    id.verify().expect("structural verify");
    id.verify_standards_compliance().expect("NEG-002 compliance");
}

#[test]
fn capability_honesty_streaming_is_live_proven_here_but_not_ptz_or_audio() {
    assert!(ADP_WYZE_CAPABILITIES.contains(AdapterCapabilities::STREAMING));
    assert!(ADP_WYZE_CAPABILITIES.contains(AdapterCapabilities::DEVICE_DISCOVERY));
    assert!(ADP_WYZE_CAPABILITIES.contains(AdapterCapabilities::TELEMETRY));
    assert!(!ADP_WYZE_CAPABILITIES.contains(AdapterCapabilities::PTZ_CONTROL));
    assert!(!ADP_WYZE_CAPABILITIES.contains(AdapterCapabilities::TWO_WAY_AUDIO));
    assert!(ADP_WYZE_CAPABILITIES.is_valid());
    // Cross-row honesty: the AOSU row must NOT declare streaming (battery).
    let aosu = adp_aosu_adapter_identity().expect("aosu identity");
    assert!(!aosu.capabilities.contains(AdapterCapabilities::STREAMING));
}

#[test]
fn canonical_roundtrip_and_digest_stability() {
    let id = adp_wyze_adapter_identity().expect("identity");
    let mut encoder = CanonicalEncoder::new();
    id.encode_canonical(&mut encoder);
    let bytes = encoder.finish();
    let mut decoder = fss_core::CanonicalDecoder::new(&bytes);
    let back = fss_core::AdapterIdentity::decode_canonical(&mut decoder).expect("decode");
    assert_eq!(id, back);
    let again = adp_wyze_adapter_identity().expect("identity again");
    assert_eq!(id.canonical_digest(), again.canonical_digest());
    // And the two lab rows have distinct digests (distinct identities).
    let aosu = adp_aosu_adapter_identity().expect("aosu identity");
    assert_ne!(id.canonical_digest(), aosu.canonical_digest());
}

#[test]
fn proprietary_lab_path_cannot_claim_native_isolation() {
    let mut id = adp_wyze_adapter_identity().expect("identity");
    id.isolation_mode = IsolationMode::NativePureRust;
    assert!(id.verify_standards_compliance().is_err());
}

#[test]
fn generation_transitions_are_monotonic() {
    let id = adp_wyze_adapter_identity().expect("identity");
    let same = fss_core::AdapterGeneration::parse(ADP_WYZE_GENERATION).expect("generation");
    assert_eq!(
        id.transition_generation(same),
        Err(ContractError::GenerationConflict)
    );
    let newer = fss_core::AdapterGeneration::parse("gen:fss1:adapters-v2").expect("newer gen");
    let next = id.transition_generation(newer).expect("transition");
    assert!(next.generation > id.generation);
    next.verify().expect("re-verify");
}

#[test]
fn identity_field_bounds_enforced() {
    let mut id = adp_wyze_adapter_identity().expect("identity");
    id.max_bandwidth_bytes_per_sec = 0;
    assert_eq!(id.verify(), Err(ContractError::InvalidIdentifier));
}
