//! Stable camera families and onboarding friction classes (LAB-PROVISION-001).
//!
//! This is the machine-readable truth behind `DEVICE_ADAPTER_MATRIX.md`
//! sections 3a (custom-firmware / on-device-software) and 3b (onboarding
//! friction classes). Every value here is a distinct, stable identity; a
//! decode of an unknown discriminant fails closed to [`ContractError`]
//! instead of guessing.
//!
//! The friction model is deliberately split in two because the two goals the
//! owner cares about are different per device:
//!
//! * **software** — getting FSS's own userspace (Rust agent + tailscaled)
//!   running *on* the camera. This is "the universal thing."
//! * **data** — FSS ingesting the camera's video over an existing lane
//!   (standards or a proven protocol). This may work with or without
//!   flashing and is modeled by [`crate::recipe::DataLane`].
//!
//! [`FrictionClass`] therefore describes the **software** path only. A
//! camera that is `FLocked` for software can still be fully usable for data
//! (Wyze/AOSU are exactly this: locked firmware, live-proven ingest lane).

use core::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContractError,
};

/// A stable camera family with a documented, honest onboarding path.
///
/// Adding a family is a registry change (new discriminant + a
/// [`crate::recipe::OnboardingRecipe`]); it is never renumbered or reused.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CameraFamily {
    /// Yi IPC — Shenzhen Zowee ODM `YiHC_Y_2_0`, generic-IPC ONVIF stack
    /// (ADP-YI-IPC-LAB-001, bead fss-u3e43).
    Yi = 1,
    /// Wyze Cam v4 — TUTK/IOTC NEW (0xCC51) (ADP-WYZE-V4-LAB-001).
    WyzeV4 = 2,
    /// AOSU 4K P1 Max — Glazero/Tuya homebase + battery cams
    /// (ADP-AOSU-P1MAX-LAB-001).
    AosUP1Max = 3,
    /// An OpenIPC-supported camera whose stock firmware has a web-UI update
    /// (the "open-by-design" procurement class).
    OpenIPCClassA = 4,
    /// A camera that already speaks RTSP/ONVIF; no firmware change needed.
    GenericStandards = 5,
}

impl CameraFamily {
    /// Every family known to the registry, in stable discriminant order.
    pub const ALL: [Self; 5] = [
        Self::Yi,
        Self::WyzeV4,
        Self::AosUP1Max,
        Self::OpenIPCClassA,
        Self::GenericStandards,
    ];

    /// The stable machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Yi => "yi",
            Self::WyzeV4 => "wyze_v4",
            Self::AosUP1Max => "aosu_p1_max",
            Self::OpenIPCClassA => "openipc_class_a",
            Self::GenericStandards => "generic_standards",
        }
    }

    /// Parses a family from its identifier, failing closed on unknown values.
    pub fn parse(value: &str) -> Result<Self, ContractError> {
        match value {
            "yi" => Ok(Self::Yi),
            "wyze_v4" => Ok(Self::WyzeV4),
            "aosu_p1_max" => Ok(Self::AosUP1Max),
            "openipc_class_a" => Ok(Self::OpenIPCClassA),
            "generic_standards" => Ok(Self::GenericStandards),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl fmt::Display for CameraFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for CameraFamily {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self as u8);
    }
}

impl CanonicalDecode for CameraFamily {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Yi),
            2 => Ok(Self::WyzeV4),
            3 => Ok(Self::AosUP1Max),
            4 => Ok(Self::OpenIPCClassA),
            5 => Ok(Self::GenericStandards),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// The honest friction for getting **FSS software** running on a
/// factory-state unit. Values map 1:1 to `DEVICE_ADAPTER_MATRIX.md` section 3b.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum FrictionClass {
    /// A — open-by-design: flash over the network via the vendor's own
    /// update endpoint. No physical touch.
    AOpenByDesign = 1,
    /// B — one-time owner pairing (QR-to-lens), then standards forever.
    BOneTimePairing = 2,
    /// C — owner cloud account yields the key via official API (no MITM).
    COwnerCloudKey = 3,
    /// D — one SD card, once, via the vendor's own update mechanism.
    DSdCardOnce = 4,
    /// E — network-native, zero touch: standards or a proven lane, no
    /// firmware change required.
    ENetworkNative = 5,
    /// F — locked: no legitimate path today (would require exploit
    /// development, which the owner charter excludes).
    FLocked = 6,
}

impl FrictionClass {
    /// Every friction class in stable discriminant order.
    pub const ALL: [Self; 6] = [
        Self::AOpenByDesign,
        Self::BOneTimePairing,
        Self::COwnerCloudKey,
        Self::DSdCardOnce,
        Self::ENetworkNative,
        Self::FLocked,
    ];

    /// The stable machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AOpenByDesign => "a_open_by_design",
            Self::BOneTimePairing => "b_one_time_pairing",
            Self::COwnerCloudKey => "c_owner_cloud_key",
            Self::DSdCardOnce => "d_sd_card_once",
            Self::ENetworkNative => "e_network_native",
            Self::FLocked => "f_locked",
        }
    }

    /// Parses a friction class from its identifier, failing closed.
    pub fn parse(value: &str) -> Result<Self, ContractError> {
        match value {
            "a_open_by_design" => Ok(Self::AOpenByDesign),
            "b_one_time_pairing" => Ok(Self::BOneTimePairing),
            "c_owner_cloud_key" => Ok(Self::COwnerCloudKey),
            "d_sd_card_once" => Ok(Self::DSdCardOnce),
            "e_network_native" => Ok(Self::ENetworkNative),
            "f_locked" => Ok(Self::FLocked),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }

    /// Whether this friction class is achievable with zero physical touch.
    ///
    /// Only `AOpenByDesign` (network flash) and `ENetworkNative` (already
    /// reachable) are fully wireless. `BOneTimePairing` is an owner action in
    /// the same room (no tools, no card) and is not "physical touch" in the
    /// sense of opening the device, but it is not network-only either, so it
    /// reports `false` here.
    #[must_use]
    pub const fn wireless_capable(self) -> bool {
        matches!(self, Self::AOpenByDesign | Self::ENetworkNative)
    }
}

impl fmt::Display for FrictionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for FrictionClass {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self as u8);
    }
}

impl CanonicalDecode for FrictionClass {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::AOpenByDesign),
            2 => Ok(Self::BOneTimePairing),
            3 => Ok(Self::COwnerCloudKey),
            4 => Ok(Self::DSdCardOnce),
            5 => Ok(Self::ENetworkNative),
            6 => Ok(Self::FLocked),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_round_trips_canonical() {
        for family in CameraFamily::ALL {
            let bytes = family.canonical_bytes();
            assert_eq!(Ok(family), CameraFamily::from_canonical_bytes(&bytes));
        }
    }

    #[test]
    fn family_parse_fails_closed_on_unknown() {
        assert_eq!(Err(ContractError::InvalidIdentifier), CameraFamily::parse("sonos"));
        assert_eq!(Err(ContractError::InvalidIdentifier), CameraFamily::parse(""));
        assert_eq!(Ok(CameraFamily::Yi), CameraFamily::parse("yi"));
    }

    #[test]
    fn friction_wireless_only_for_network_paths() {
        assert!(FrictionClass::AOpenByDesign.wireless_capable());
        assert!(FrictionClass::ENetworkNative.wireless_capable());
        assert!(!FrictionClass::DSdCardOnce.wireless_capable());
        assert!(!FrictionClass::BOneTimePairing.wireless_capable());
        assert!(!FrictionClass::FLocked.wireless_capable());
    }

    #[test]
    fn friction_decodes_fail_closed() {
        // 0 and 7 are not valid discriminants.
        assert!(FrictionClass::from_canonical_bytes(&[0u8]).is_err());
        assert!(FrictionClass::from_canonical_bytes(&[7u8]).is_err());
        assert_eq!(
            Ok(FrictionClass::DSdCardOnce),
            FrictionClass::from_canonical_bytes(&[4u8])
        );
    }
}
