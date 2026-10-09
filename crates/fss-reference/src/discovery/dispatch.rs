//! DeviceCandidate → adapter dispatch + owner-auth requirements (DISC-6,
//! fss-yodhk.6).
//!
//! Maps a fingerprinted host ([`BrandConfidence`]) to the typed adapter path
//! that can onboard it, naming the EXACT missing owner-auth ingredient. A
//! recommendation never grants effect authority (AGENTS.md); unsupported and
//! blocked paths carry typed reasons, never null.
//!
//! Registry rows referenced: ADP-WYZE-V4-LAB-001 (TUTK NEW), ADP-AOSU-
//! P1MAX-LAB-001 (Tuya/AOSU), ADP-RTSP-001 / ADP-ONVIF-T-001 (standards),
//! ADP-UVC-001 (local USB), plus the import-only fallback.

use crate::discovery::fingerprint::{Brand, BrandConfidence, Confidence};

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
    /// Wyze: UID + ENR from the owner account inventory.
    WyzeUidEnr,
    /// AOSU: device local_key (via fresh app login capture or IPA toolchain).
    AosuLocalKey,
    /// Resideo: web credentials for the embedded Digest-auth surface.
    ResideoWebCredentials,
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

/// Dispatches one fingerprinted candidate to its adapter path.
///
/// Confidence gates the mapping: `Possible` (no supporting signal) never
/// dispatches to a live path — it falls to `ImportOnly` with a typed reason,
/// because onboarding a guessed brand would violate the no-bare-guess rule.
#[must_use]
pub fn dispatch(brand: &BrandConfidence) -> AdapterDispatch {
    let strong = brand.confidence >= Confidence::Likely;
    match (&brand.brand, strong) {
        (Brand::Tutk, true) => AdapterDispatch {
            adapter: AdapterPath::TutkNew,
            readiness: Readiness::NeedsIngredient,
            missing: Some(AuthIngredient::WyzeUidEnr),
            blocked_reason: None,
        },
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
            missing: None,
            blocked_reason: None,
        },
        (Brand::Infrastructure, _) => AdapterDispatch {
            adapter: AdapterPath::ImportOnly,
            readiness: Readiness::Unavailable,
            missing: None,
            blocked_reason: Some("infrastructure device, not a camera candidate"),
        },
        (Brand::Unknown, _) => AdapterDispatch {
            adapter: AdapterPath::ImportOnly,
            readiness: Readiness::Unavailable,
            missing: None,
            blocked_reason: Some("no supporting fingerprint signal; a guess never dispatches"),
        },
        // weak confidence on a real brand: same honesty rule
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
    fn weak_confidence_held_back() {
        let c = confidence(Brand::Tutk, Confidence::Possible, vec![]);
        let d = dispatch(&c);
        assert_eq!(d.adapter, AdapterPath::ImportOnly);
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
