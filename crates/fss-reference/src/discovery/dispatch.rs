#![forbid(unsafe_code)]
//! DeviceCandidate → adapter dispatch + owner-auth requirements (DISC-6,
//! fss-yodhk.6).
//!
//! Maps a fingerprinted host ([`BrandConfidence`]) to the typed adapter path
//! that can onboard it, naming the EXACT missing owner-auth ingredient. A
//! recommendation never grants effect authority (AGENTS.md); unsupported and
//! blocked paths carry typed reasons, never null.
//!
//! Registry rows referenced: native `unifi_direct::protect_live` (UniFi
//! Protect), native Tapo local ONVIF/RTSP/DS-JSON, ADP-WYZE-V4-LAB-001 (TUTK
//! NEW), ADP-AOSU-P1MAX-LAB-001 (Tuya/AOSU), ADP-RTSP-001 / ADP-ONVIF-T-001
//! (standards), ADP-UVC-001 (local USB), plus the import-only fallback.

use crate::discovery::fingerprint::{Brand, BrandConfidence, Confidence, Signal};

/// One onboarding path recommendation with its requirements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterDispatch {
    /// Adapter row id (registry).
    pub adapter: AdapterPath,
    /// Whether onboarding can proceed right now.
    pub readiness: Readiness,
    /// The exact owner-auth ingredient still missing (typed, per brand).
    pub missing: Option<AuthIngredient>,
    /// Why the path is unusable, when it is (typed reason).
    pub blocked_reason: Option<&'static str>,
}

/// Adapter paths reachable from a fingerprinted brand.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdapterPath {
    /// Native pure-Rust UniFi Protect adapter (`unifi_direct::protect_live` + RTSP/RTSPS).
    UniFiProtect,
    /// Native pure-Rust TP-Link Tapo local camera adapter (ONVIF+RTSP / local DS-JSON).
    Tapo,
    /// ADP-WYZE-V4-LAB-001: TUTK NEW protocol (Wyze-class).
    TutkNew,
    /// ADP-AOSU-P1MAX-LAB-001: Tuya/AOSU homebase path.
    TuyaAosu,
    /// ADP-RTSP-001 / ADP-ONVIF-T-001: standards path.
    Standards,
    /// ADP-UVC-001: local USB capture.
    Uvc,
    /// Import-only (no live path).
    ImportOnly,
}

/// The owner-auth ingredient each brand needs (exact, never vague).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthIngredient {
    /// UniFi Protect: owner-authorized direct camera or Protect RTSP/RTSPS credentials.
    UniFiProtectCredentials,
    /// TP-Link Tapo: owner-authorized Tapo camera account credentials (ONVIF/RTSP or local HTTPS).
    TapoLocalCredentials,
    /// Wyze: UID + ENR from the owner account inventory.
    WyzeUidEnr,
    /// AOSU: device local_key (via fresh app login capture or IPA toolchain).
    AosuLocalKey,
    /// Resideo: web credentials for the embedded Digest-auth surface.
    ResideoWebCredentials,
    /// Owner-approved ONVIF/RTSP endpoint and its scoped device credentials.
    StandardsEndpointCredentials,
}

/// Onboarding readiness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Readiness {
    /// The exact ingredient is available; onboarding can proceed.
    Ready,
    /// The named ingredient must be provisioned first.
    NeedsIngredient,
    /// The path is not available for this host (typed reason attached).
    Unavailable,
}

fn has_rtsp_surface(signals: &[Signal]) -> bool {
    signals.iter().any(|s| match s {
        Signal::RtspBanner { .. } => true,
        Signal::PortSignature(ports) => ports.contains(&554) || ports.contains(&8554),
        _ => false,
    })
}

fn has_tutk_listener(signals: &[Signal]) -> bool {
    signals.iter().any(|s| matches!(s, Signal::TutkListener(_)))
}

/// Dispatches one fingerprinted candidate to its adapter path.
///
/// Confidence gates the mapping: `Possible` (no supporting signal) never
/// dispatches to a live path — it falls to `ImportOnly` with a typed reason,
/// because onboarding a guessed brand would violate the no-bare-guess rule.
#[must_use]
pub fn dispatch(brand: &BrandConfidence) -> AdapterDispatch {
    let strong = brand.confidence >= Confidence::Likely;
    match (&brand.brand, strong) {
        (Brand::UniFiProtect, true) => AdapterDispatch {
            adapter: AdapterPath::UniFiProtect,
            readiness: Readiness::NeedsIngredient,
            missing: Some(AuthIngredient::UniFiProtectCredentials),
            blocked_reason: None,
        },
        (Brand::Tapo, true) => AdapterDispatch {
            adapter: AdapterPath::Tapo,
            readiness: Readiness::NeedsIngredient,
            missing: Some(AuthIngredient::TapoLocalCredentials),
            blocked_reason: None,
        },
        (Brand::Tutk, true) => {
            if has_rtsp_surface(&brand.signals) && !has_tutk_listener(&brand.signals) {
                AdapterDispatch {
                    adapter: AdapterPath::Standards,
                    readiness: Readiness::NeedsIngredient,
                    missing: Some(AuthIngredient::StandardsEndpointCredentials),
                    blocked_reason: None,
                }
            } else {
                AdapterDispatch {
                    adapter: AdapterPath::TutkNew,
                    readiness: Readiness::NeedsIngredient,
                    missing: Some(AuthIngredient::WyzeUidEnr),
                    blocked_reason: None,
                }
            }
        }
        (Brand::Tuya, true) => AdapterDispatch {
            adapter: AdapterPath::TuyaAosu,
            readiness: Readiness::NeedsIngredient,
            missing: Some(AuthIngredient::AosuLocalKey),
            blocked_reason: None,
        },
        (Brand::EmbeddedWeb, true) => AdapterDispatch {
            adapter: AdapterPath::Standards,
            readiness: Readiness::NeedsIngredient,
            missing: Some(AuthIngredient::ResideoWebCredentials),
            blocked_reason: None,
        },
        (Brand::Standards, true) => AdapterDispatch {
            adapter: AdapterPath::Standards,
            readiness: Readiness::NeedsIngredient,
            missing: Some(AuthIngredient::StandardsEndpointCredentials),
            blocked_reason: None,
        },
        (Brand::Infrastructure, _) => AdapterDispatch {
            adapter: AdapterPath::ImportOnly,
            readiness: Readiness::Unavailable,
            missing: None,
            blocked_reason: Some("infrastructure device, not a camera candidate"),
        },
        (Brand::CloudOnly, _) => AdapterDispatch {
            adapter: AdapterPath::ImportOnly,
            readiness: Readiness::Unavailable,
            missing: None,
            blocked_reason: Some("cloud-only accessory: no local service surface observed"),
        },
        (Brand::Unknown, _) => AdapterDispatch {
            adapter: AdapterPath::ImportOnly,
            readiness: Readiness::Unavailable,
            missing: None,
            blocked_reason: Some("no supporting fingerprint signal; a guess never dispatches"),
        },
        (Brand::UniFiProtect, false) => AdapterDispatch {
            adapter: AdapterPath::ImportOnly,
            readiness: Readiness::Unavailable,
            missing: Some(AuthIngredient::UniFiProtectCredentials),
            blocked_reason: Some(
                "OUI-only Ubiquiti host (Possible): verify UDP-10001 TLV / Protect ports before onboarding",
            ),
        },
        (Brand::Tapo, false) => AdapterDispatch {
            adapter: AdapterPath::ImportOnly,
            readiness: Readiness::Unavailable,
            missing: Some(AuthIngredient::TapoLocalCredentials),
            blocked_reason: Some(
                "OUI-only TP-Link host (Possible): verify Tapo camera ports (443+8800 / 2020 / 554) before onboarding",
            ),
        },
        // Possible-confidence TUTK: the OUI suggests the family, but Wyze also
        // makes non-camera devices and credential-less corroboration is
        // impossible (discovery HMAC is keyed by the camera identity — NEG-005).
        // The owner's UID+ENR both corroborate and onboard, so name them.
        (Brand::Tutk, false) => AdapterDispatch {
            adapter: AdapterPath::ImportOnly,
            readiness: Readiness::Unavailable,
            missing: Some(AuthIngredient::WyzeUidEnr),
            blocked_reason: Some(
                "OUI-only (Possible): provision Wyze UID+ENR to corroborate and onboard",
            ),
        },
        // Other weak-confidence brands: collect more signals first.
        (_, false) => AdapterDispatch {
            adapter: AdapterPath::ImportOnly,
            readiness: Readiness::Unavailable,
            missing: None,
            blocked_reason: Some("confidence below Likely; collect more signals first"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::fingerprint::Signal;

    fn confidence(brand: Brand, conf: Confidence, signals: Vec<Signal>) -> BrandConfidence {
        BrandConfidence {
            brand,
            confidence: conf,
            signals,
        }
    }

    #[test]
    fn unifi_protect_dispatches_to_native_adapter_never_import_only() {
        let c = confidence(
            Brand::UniFiProtect,
            Confidence::Confirmed,
            vec![
                Signal::OuiVendor("Ubiquiti Inc".into()),
                Signal::UniFiDiscovery {
                    model: Some("UVC G4 Instant".into()),
                    firmware: Some("UVC.SAV530q.v4.72.38.67".into()),
                },
            ],
        );
        let d = dispatch(&c);
        assert_eq!(d.adapter, AdapterPath::UniFiProtect);
        assert_eq!(d.readiness, Readiness::NeedsIngredient);
        assert_eq!(d.missing, Some(AuthIngredient::UniFiProtectCredentials));
        assert_eq!(d.blocked_reason, None);
    }

    #[test]
    fn tapo_dispatches_to_tapo_credentials_never_resideo() {
        let c = confidence(
            Brand::Tapo,
            Confidence::Likely,
            vec![
                Signal::OuiVendor("TP-Link Systems Inc.".into()),
                Signal::PortSignature(vec![443, 8800]),
            ],
        );
        let d = dispatch(&c);
        assert_eq!(d.adapter, AdapterPath::Tapo);
        assert_eq!(d.readiness, Readiness::NeedsIngredient);
        assert_eq!(d.missing, Some(AuthIngredient::TapoLocalCredentials));
        assert_ne!(d.missing, Some(AuthIngredient::ResideoWebCredentials));
        assert_eq!(d.blocked_reason, None);
    }

    #[test]
    fn wyze_dispatches_to_tutk_with_exact_ingredient() {
        let c = confidence(
            Brand::Tutk,
            Confidence::Likely,
            vec![Signal::OuiVendor("Wyze Labs Inc".into())],
        );
        let d = dispatch(&c);
        assert_eq!(d.adapter, AdapterPath::TutkNew);
        assert_eq!(d.readiness, Readiness::NeedsIngredient);
        assert_eq!(d.missing, Some(AuthIngredient::WyzeUidEnr));
        assert_eq!(d.blocked_reason, None);
    }

    #[test]
    fn wyze_with_open_rtsp_port_554_dispatches_to_standards_rtsp() {
        let c = confidence(
            Brand::Tutk,
            Confidence::Likely,
            vec![
                Signal::OuiVendor("Wyze Labs Inc".into()),
                Signal::PortSignature(vec![554]),
            ],
        );
        let d = dispatch(&c);
        assert_eq!(d.adapter, AdapterPath::Standards);
        assert_eq!(d.readiness, Readiness::NeedsIngredient);
        assert_eq!(
            d.missing,
            Some(AuthIngredient::StandardsEndpointCredentials)
        );
    }

    #[test]
    fn aosu_confirmed_needs_local_key() {
        let c = confidence(
            Brand::Tuya,
            Confidence::Confirmed,
            vec![
                Signal::OuiVendor("Shenzhen Glazero Technology Co., Ltd.".into()),
                Signal::PortSignature(vec![6668, 8888]),
            ],
        );
        let d = dispatch(&c);
        assert_eq!(d.adapter, AdapterPath::TuyaAosu);
        assert_eq!(d.missing, Some(AuthIngredient::AosuLocalKey));
    }

    #[test]
    fn unknown_never_dispatches_live() {
        let c = confidence(Brand::Unknown, Confidence::Possible, vec![]);
        let d = dispatch(&c);
        assert_eq!(d.adapter, AdapterPath::ImportOnly);
        assert_eq!(d.readiness, Readiness::Unavailable);
        assert!(d.blocked_reason.is_some());
    }

    #[test]
    fn weak_tutk_names_the_corroborating_credential() {
        let c = confidence(Brand::Tutk, Confidence::Possible, vec![]);
        let d = dispatch(&c);
        assert_eq!(d.adapter, AdapterPath::ImportOnly);
        assert_eq!(d.readiness, Readiness::Unavailable);
        assert_eq!(d.missing, Some(AuthIngredient::WyzeUidEnr));
        assert!(d.blocked_reason.is_some_and(|r| r.contains("corroborate")));
    }

    #[test]
    fn weak_other_brands_held_back() {
        let c = confidence(Brand::Tuya, Confidence::Possible, vec![]);
        let d = dispatch(&c);
        assert_eq!(
            d.blocked_reason,
            Some("confidence below Likely; collect more signals first")
        );
    }

    #[test]
    fn infrastructure_unavailable_with_reason() {
        let c = confidence(
            Brand::Infrastructure,
            Confidence::Confirmed,
            vec![Signal::OuiVendor("eero inc.".into())],
        );
        let d = dispatch(&c);
        assert_eq!(d.readiness, Readiness::Unavailable);
        assert!(d.blocked_reason.is_some());
    }
}
