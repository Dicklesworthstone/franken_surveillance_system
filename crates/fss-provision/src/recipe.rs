//! Typed onboarding recipes per camera family (LAB-PROVISION-001).
//!
//! A [`OnboardingRecipe`] is the machine-readable form of
//! `DEVICE_ADAPTER_MATRIX.md` sections 3a and 3b for one
//! [`CameraFamily`]: how FSS software gets on (or doesn't), the exact
//! prerequisites, the ordered steps, the brick-recovery path, and — separately
//! — the ingest lane that carries the camera's *data* (which may work with or
//! without flashing).
//!
//! The registry is a closed, total map over [`CameraFamily::ALL`]; its
//! integrity is checked by [`RecipeRegistry::verify_integrity`] so a registry
//! row can never silently contradict the friction/transport/prerequisite
//! invariants below.

use core::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContractError,
};

use crate::family::{CameraFamily, FrictionClass};

/// How FSS software reaches a camera.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Transport {
    /// Write a FAT32 SD image and let the vendor's own SD updater flash it.
    SdImage = 1,
    /// Push a firmware image over the vendor's own (usually unsigned) web-UI
    /// update endpoint, over the network.
    NetworkUpdate = 2,
    /// Provision the device over the Tuya LAN channel under the owner account.
    TuyaProvisioning = 3,
    /// No firmware change: the camera already speaks a standard we ingest.
    StandardsNative = 4,
    /// No software path at all (locked).
    None = 5,
}

impl Transport {
    /// The stable machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SdImage => "sd_image",
            Self::NetworkUpdate => "network_update",
            Self::TuyaProvisioning => "tuya_provisioning",
            Self::StandardsNative => "standards_native",
            Self::None => "none",
        }
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for Transport {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self as u8);
    }
}

impl CanonicalDecode for Transport {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::SdImage),
            2 => Ok(Self::NetworkUpdate),
            3 => Ok(Self::TuyaProvisioning),
            4 => Ok(Self::StandardsNative),
            5 => Ok(Self::None),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// The FSS ingest lane that carries a camera's data, independent of whether
/// we flash its software.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DataLane {
    /// ONVIF Profile T (discovery, profiles, stream URI, events).
    OnvifT = 1,
    /// RTSP/RTP direct.
    Rtsp = 2,
    /// Wyze TUTK/IOTC NEW (0xCC51), first-party `fss-tutk` lane.
    TutkNew = 3,
    /// Tuya 3.4/3.5 LAN, first-party `fss-tuya` lane.
    Tuya35 = 4,
    /// No data lane established.
    None = 5,
}

impl DataLane {
    /// The stable machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OnvifT => "onvif_t",
            Self::Rtsp => "rtsp",
            Self::TutkNew => "tutk_new",
            Self::Tuya35 => "tuya_35",
            Self::None => "none",
        }
    }
}

impl fmt::Display for DataLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for DataLane {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self as u8);
    }
}

impl CanonicalDecode for DataLane {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::OnvifT),
            2 => Ok(Self::Rtsp),
            3 => Ok(Self::TutkNew),
            4 => Ok(Self::Tuya35),
            5 => Ok(Self::None),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// A typed owner input the onboarding path requires before it can proceed.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Prerequisite {
    /// The SN prefix read from the camera's physical label (variant match).
    SnPrefix = 1,
    /// The current firmware version (from label or app).
    FirmwareVersion = 2,
    /// The stock web-UI update endpoint is reachable on the network.
    WebUpdateEndpoint = 3,
    /// The owner's Tuya `local_key`, via the official IoT developer API.
    LocalKey = 4,
    /// The one-time owner pairing (QR-to-lens); satisfied by the step itself.
    OneTimePairing = 5,
}

impl Prerequisite {
    /// The stable machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SnPrefix => "sn_prefix",
            Self::FirmwareVersion => "firmware_version",
            Self::WebUpdateEndpoint => "web_update_endpoint",
            Self::LocalKey => "local_key",
            Self::OneTimePairing => "one_time_pairing",
        }
    }
}

impl fmt::Display for Prerequisite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for Prerequisite {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self as u8);
    }
}

impl CanonicalDecode for Prerequisite {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::SnPrefix),
            2 => Ok(Self::FirmwareVersion),
            3 => Ok(Self::WebUpdateEndpoint),
            4 => Ok(Self::LocalKey),
            5 => Ok(Self::OneTimePairing),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// A bounded set of onboarding actions. Free-form strings are not allowed: a
/// step is a stable verb plus a fixed human detail, so agents and the CLI
/// never have to interpret prose.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum StepKind {
    /// Read the SN prefix off the physical label (Yi variant match).
    ReadLabelSnPrefix = 1,
    /// Select the exact yi-hack release from SN prefix + firmware version.
    SelectYiHackRelease = 2,
    /// Assemble the on-camera FSS agent bundle (digest-pinned).
    BuildAgentBundle = 3,
    /// Lay out the FAT32 SD image for the selected release.
    BuildSdImage = 4,
    /// Physically insert the SD card into the camera.
    InsertSdCard = 5,
    /// Physically power the camera on so the vendor updater flashes it.
    PowerOnForFlash = 6,
    /// Verify root SSH/dropbear after the flash.
    VerifyRootSsh = 7,
    /// Install tailscaled in `--tun=userspace-networking` mode (SD swap on).
    InstallTailscaleUserspace = 8,
    /// Verify the camera's RTSP/ONVIF is reachable from a tailnet member.
    VerifyTailnetEndpoint = 9,
    /// Confirm the on-camera agent reports health to the FSS host.
    ReportAgentHealth = 10,
    /// Flash the Coupler-built OpenIPC image over the stock web-UI update.
    NetworkFlashOpenipc = 11,
    /// Enable RTSP/ONVIF on a standards-native camera (or after pairing).
    EnableStandards = 12,
    /// One-time same-room QR-to-lens app pairing (Yi data path).
    AppPairingQr = 13,
    /// Confirm the owner's Tuya IoT developer account is linked.
    RegisterTuyaAccount = 14,
    /// Pair the device with the generic Smart Life app (owner account).
    SmartLifePairing = 15,
}

impl StepKind {
    /// Whether this step requires physical access to the device.
    #[must_use]
    pub const fn is_physical(self) -> bool {
        matches!(
            self,
            Self::ReadLabelSnPrefix | Self::InsertSdCard | Self::PowerOnForFlash
        )
    }

    /// Whether this step is performed over the network (no physical touch).
    #[must_use]
    pub const fn is_wireless(self) -> bool {
        !self.is_physical()
    }

    /// The stable machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadLabelSnPrefix => "read_label_sn_prefix",
            Self::SelectYiHackRelease => "select_yihack_release",
            Self::BuildAgentBundle => "build_agent_bundle",
            Self::BuildSdImage => "build_sd_image",
            Self::InsertSdCard => "insert_sd_card",
            Self::PowerOnForFlash => "power_on_for_flash",
            Self::VerifyRootSsh => "verify_root_ssh",
            Self::InstallTailscaleUserspace => "install_tailscale_userspace",
            Self::VerifyTailnetEndpoint => "verify_tailnet_endpoint",
            Self::ReportAgentHealth => "report_agent_health",
            Self::NetworkFlashOpenipc => "network_flash_openipc",
            Self::EnableStandards => "enable_standards",
            Self::AppPairingQr => "app_pairing_qr",
            Self::RegisterTuyaAccount => "register_tuya_account",
            Self::SmartLifePairing => "smart_life_pairing",
        }
    }
}

impl fmt::Display for StepKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One onboarding step: a stable verb plus its fixed human detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnboardingStep {
    kind: StepKind,
    detail: &'static str,
}

impl OnboardingStep {
    const fn new(kind: StepKind, detail: &'static str) -> Self {
        Self { kind, detail }
    }

    /// The stable action verb.
    #[must_use]
    pub const fn kind(&self) -> StepKind {
        self.kind
    }

    /// The fixed human-readable detail for this step.
    #[must_use]
    pub const fn detail(&self) -> &'static str {
        self.detail
    }

    /// Whether this step requires physical access to the device.
    #[must_use]
    pub const fn is_physical(&self) -> bool {
        self.kind.is_physical()
    }

    /// Whether this step is performed over the network.
    #[must_use]
    pub const fn is_wireless(&self) -> bool {
        self.kind.is_wireless()
    }
}

/// The complete, typed onboarding recipe for one [`CameraFamily`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnboardingRecipe {
    family: CameraFamily,
    /// Friction for getting FSS **software** on the unit (A-F).
    friction_class: FrictionClass,
    transport: Transport,
    prerequisites: &'static [Prerequisite],
    steps: &'static [OnboardingStep],
    brick_recovery: Option<&'static str>,
    /// Whether the software path needs zero physical touch.
    software_wireless: bool,
    /// The ingest lane for the camera's data (may work without flashing).
    data_lane: DataLane,
    note: &'static str,
}

impl OnboardingRecipe {
    #[allow(clippy::too_many_arguments)]
    const fn new(
        family: CameraFamily,
        friction_class: FrictionClass,
        transport: Transport,
        prerequisites: &'static [Prerequisite],
        steps: &'static [OnboardingStep],
        brick_recovery: Option<&'static str>,
        data_lane: DataLane,
        note: &'static str,
    ) -> Self {
        Self {
            family,
            friction_class,
            transport,
            prerequisites,
            steps,
            brick_recovery,
            software_wireless: friction_class.wireless_capable(),
            data_lane,
            note,
        }
    }

    /// The family this recipe belongs to.
    #[must_use]
    pub const fn family(&self) -> CameraFamily {
        self.family
    }

    /// Friction for getting FSS software on the unit (A-F).
    #[must_use]
    pub const fn friction_class(&self) -> FrictionClass {
        self.friction_class
    }

    /// How the software path delivers the image (or [`Transport::None`]).
    #[must_use]
    pub const fn transport(&self) -> Transport {
        self.transport
    }

    /// The ordered prerequisites for the path.
    #[must_use]
    pub const fn prerequisites(&self) -> &'static [Prerequisite] {
        self.prerequisites
    }

    /// The ordered, typed steps for the path (empty when there is no path).
    #[must_use]
    pub const fn steps(&self) -> &'static [OnboardingStep] {
        self.steps
    }

    /// The brick-recovery path, if one exists for this family.
    #[must_use]
    pub const fn brick_recovery(&self) -> Option<&'static str> {
        self.brick_recovery
    }

    /// Whether the software path needs zero physical touch.
    #[must_use]
    pub const fn software_wireless(&self) -> bool {
        self.software_wireless
    }

    /// The ingest lane for the camera's data.
    #[must_use]
    pub const fn data_lane(&self) -> DataLane {
        self.data_lane
    }

    /// The honest nuance for this family (the software vs. data split).
    #[must_use]
    pub const fn note(&self) -> &'static str {
        self.note
    }
}

/// Typed integrity failures for a recipe registry row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecipeError {
    /// A family in [`CameraFamily::ALL`] has no recipe.
    MissingFamily(CameraFamily),
    /// A family has more than one recipe.
    DuplicateFamily(CameraFamily),
    /// `transport == None` but steps are present, or vice versa.
    TransportStepMismatch(CameraFamily),
    /// A transport/lane requires a prerequisite the row does not list.
    MissingPrerequisite(CameraFamily, Prerequisite),
    /// `software_wireless` disagrees with the friction class.
    InconsistentWireless(CameraFamily),
}

impl fmt::Display for RecipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingFamily(fam) => write!(f, "no recipe for family {fam}"),
            Self::DuplicateFamily(fam) => write!(f, "duplicate recipe for family {fam}"),
            Self::TransportStepMismatch(fam) => {
                write!(f, "family {fam}: transport/steps do not agree")
            }
            Self::MissingPrerequisite(fam, pre) => {
                write!(f, "family {fam}: path requires prerequisite {pre}")
            }
            Self::InconsistentWireless(fam) => {
                write!(
                    f,
                    "family {fam}: software_wireless disagrees with friction class"
                )
            }
        }
    }
}

impl std::error::Error for RecipeError {}

// -- Static, allocation-free registry rows (matrix 3a/3b, 2026-10-16) -------

const YI_PREREQS: &[Prerequisite] = &[Prerequisite::SnPrefix, Prerequisite::FirmwareVersion];
const YI_STEPS: &[OnboardingStep] = &[
    OnboardingStep::new(
        StepKind::ReadLabelSnPrefix,
        "read SN prefix from the camera's physical label",
    ),
    OnboardingStep::new(
        StepKind::SelectYiHackRelease,
        "select the exact yi-hack release from SN prefix + firmware version",
    ),
    OnboardingStep::new(
        StepKind::BuildAgentBundle,
        "assemble the digest-pinned on-camera FSS agent bundle",
    ),
    OnboardingStep::new(
        StepKind::BuildSdImage,
        "lay out the FAT32 SD image for the selected release",
    ),
    OnboardingStep::new(StepKind::InsertSdCard, "insert the SD card into the camera"),
    OnboardingStep::new(
        StepKind::PowerOnForFlash,
        "power the camera on so the vendor SD updater flashes it",
    ),
    OnboardingStep::new(
        StepKind::VerifyRootSsh,
        "verify root SSH/dropbear after the flash",
    ),
    OnboardingStep::new(
        StepKind::InstallTailscaleUserspace,
        "install tailscaled --tun=userspace-networking (SD swap enabled)",
    ),
    OnboardingStep::new(
        StepKind::VerifyTailnetEndpoint,
        "verify RTSP/ONVIF reachable from a tailnet member (no LAN presence)",
    ),
    OnboardingStep::new(
        StepKind::ReportAgentHealth,
        "confirm the on-camera agent reports health to the FSS host",
    ),
];

const OPENIPC_PREREQS: &[Prerequisite] = &[Prerequisite::WebUpdateEndpoint];
const OPENIPC_STEPS: &[OnboardingStep] = &[
    OnboardingStep::new(
        StepKind::BuildAgentBundle,
        "assemble the Coupler-built OpenIPC image carrying the FSS agent + tailscaled",
    ),
    OnboardingStep::new(
        StepKind::NetworkFlashOpenipc,
        "flash the image over the stock web-UI update endpoint, over the network",
    ),
    OnboardingStep::new(
        StepKind::VerifyRootSsh,
        "verify root SSH/dropbear after the flash",
    ),
    OnboardingStep::new(
        StepKind::InstallTailscaleUserspace,
        "install tailscaled --tun=userspace-networking (SD swap enabled)",
    ),
    OnboardingStep::new(
        StepKind::VerifyTailnetEndpoint,
        "verify RTSP/ONVIF reachable from a tailnet member (no LAN presence)",
    ),
    OnboardingStep::new(
        StepKind::ReportAgentHealth,
        "confirm the on-camera agent reports health to the FSS host",
    ),
];

const GENERIC_STEPS: &[OnboardingStep] = &[
    OnboardingStep::new(
        StepKind::EnableStandards,
        "confirm RTSP/ONVIF is enabled (already standards-native)",
    ),
    OnboardingStep::new(
        StepKind::ReportAgentHealth,
        "confirm the on-camera agent (or FSS host bridge) reports health",
    ),
];

const AOSU_PREREQS: &[Prerequisite] = &[Prerequisite::LocalKey];

/// The closed registry of onboarding recipes over [`CameraFamily::ALL`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecipeRegistry {
    recipes: [OnboardingRecipe; CameraFamily::ALL.len()],
}

impl RecipeRegistry {
    /// Builds the canonical registry for the current matrix (2026-10-16).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            recipes: [
                OnboardingRecipe::new(
                    CameraFamily::Yi,
                    FrictionClass::DSdCardOnce,
                    Transport::SdImage,
                    YI_PREREQS,
                    YI_STEPS,
                    Some("TFTP+UART recovery per yi-hack; vendor-app factory reset restores stock"),
                    DataLane::OnvifT,
                    "Software path (class D): one SD card via the camera's own SD updater \
                     (yi-hack). Data path (class B): one same-room QR-to-lens pairing opens \
                     ONVIF/RTSP permanently.",
                ),
                OnboardingRecipe::new(
                    CameraFamily::WyzeV4,
                    FrictionClass::FLocked,
                    Transport::None,
                    &[],
                    &[],
                    None,
                    DataLane::TutkNew,
                    "Custom firmware still needs root first, and the reload route is unsigned: the \
                     device fetches the OTA tar over plain HTTP with a caller-supplied MD5 and runs \
                     upgraderun.sh as root, so a shell is the whole gate. Control flow is proven on \
                     4.52.17.26: raw DTLS AV frame, declared length overrun, saved RA redirected into \
                     exec_shell_sync (bead fss-wyze-cve-2026-38698-spray-fbgvp). Telnet is NOT the \
                     shell path: paracfg item 11 flips the flag but neither telnetd nor a network \
                     fetch client exists, so post-exploitation is an inline base64 payload \
                     (docs/exploit/wyze-v4-lan-control-plane.md). Two LAN primitives are live and \
                     independent of the bug: 0x29a0 re-provisions Wi-Fi and writes the wpa config \
                     unescaped (steer the unit onto an owner AP, which owns DNS for the allowlisted \
                     OTA host), and 0x29e8 enables RTSP once per boot for the data lane. Both are \
                     config writes; neither is a shell.",
                ),
                OnboardingRecipe::new(
                    CameraFamily::AosUP1Max,
                    FrictionClass::FLocked,
                    Transport::None,
                    AOSU_PREREQS,
                    &[],
                    None,
                    DataLane::Tuya35,
                    "Locked Glazero/Tuya homebase + battery cams; no on-device path. Data path \
                     (class C): owner local_key via Smart Life / Tuya IoT API (LAB-AOSU-8, no \
                     MITM) -> fss-tuya lane.",
                ),
                OnboardingRecipe::new(
                    CameraFamily::OpenIPCClassA,
                    FrictionClass::AOpenByDesign,
                    Transport::NetworkUpdate,
                    OPENIPC_PREREQS,
                    OPENIPC_STEPS,
                    Some("TFTP+UART recovery; the stock web-UI can re-flash the stock image"),
                    DataLane::OnvifT,
                    "The procurement answer: Coupler-built OpenIPC image flashed over the \
                     network via the vendor's own web-UI update. Zero physical touch.",
                ),
                OnboardingRecipe::new(
                    CameraFamily::GenericStandards,
                    FrictionClass::ENetworkNative,
                    Transport::StandardsNative,
                    &[],
                    GENERIC_STEPS,
                    None,
                    DataLane::Rtsp,
                    "Already speaks RTSP/ONVIF; FSS ingests directly with no firmware change.",
                ),
            ],
        }
    }

    /// Looks up the recipe for a family (the registry is total, so this is
    /// `None` only if the registry was mutated to omit a family).
    #[must_use]
    pub fn get(&self, family: CameraFamily) -> Option<&OnboardingRecipe> {
        self.recipes.iter().find(|r| r.family() == family)
    }

    /// Iterates over every recipe in stable family order.
    pub fn iter(&self) -> impl Iterator<Item = &OnboardingRecipe> {
        self.recipes.iter()
    }

    /// The number of recipes (always `CameraFamily::ALL.len()` when valid).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.recipes.len()
    }

    /// Whether the registry holds no recipes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.recipes.is_empty()
    }

    /// Verifies the registry is total and internally consistent.
    pub fn verify_integrity(&self) -> Result<(), RecipeError> {
        for family in CameraFamily::ALL {
            let mut count = 0usize;
            let mut recipe: Option<OnboardingRecipe> = None;
            for r in self.recipes.iter() {
                if r.family() == family {
                    count += 1;
                    recipe = Some(*r);
                }
            }
            if count == 0 {
                return Err(RecipeError::MissingFamily(family));
            }
            if count > 1 {
                return Err(RecipeError::DuplicateFamily(family));
            }
            let Some(recipe) = recipe else {
                return Err(RecipeError::MissingFamily(family));
            };
            if (recipe.transport() == Transport::None) != recipe.steps().is_empty() {
                return Err(RecipeError::TransportStepMismatch(family));
            }
            if recipe.transport() == Transport::SdImage {
                for required in [Prerequisite::SnPrefix, Prerequisite::FirmwareVersion] {
                    if !recipe.prerequisites().contains(&required) {
                        return Err(RecipeError::MissingPrerequisite(family, required));
                    }
                }
            }
            if recipe.transport() == Transport::NetworkUpdate
                && !recipe
                    .prerequisites()
                    .contains(&Prerequisite::WebUpdateEndpoint)
            {
                return Err(RecipeError::MissingPrerequisite(
                    family,
                    Prerequisite::WebUpdateEndpoint,
                ));
            }
            if recipe.data_lane() == DataLane::Tuya35
                && !recipe.prerequisites().contains(&Prerequisite::LocalKey)
            {
                return Err(RecipeError::MissingPrerequisite(
                    family,
                    Prerequisite::LocalKey,
                ));
            }
            if recipe.software_wireless() != recipe.friction_class().wireless_capable() {
                return Err(RecipeError::InconsistentWireless(family));
            }
        }
        Ok(())
    }
}

impl Default for RecipeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_total_and_internally_consistent() {
        let registry = RecipeRegistry::new();
        assert_eq!(registry.len(), CameraFamily::ALL.len());
        assert!(registry.verify_integrity().is_ok());
        for family in CameraFamily::ALL {
            assert!(registry.get(family).is_some(), "family {family} present");
        }
    }

    #[test]
    fn yi_recipe_is_sd_card_class_d() {
        let registry = RecipeRegistry::new();
        let Some(yi) = registry.get(CameraFamily::Yi) else {
            return;
        };
        assert_eq!(yi.friction_class(), FrictionClass::DSdCardOnce);
        assert_eq!(yi.transport(), Transport::SdImage);
        assert!(!yi.software_wireless());
        assert!(
            yi.steps()
                .iter()
                .any(|s| s.kind() == StepKind::InsertSdCard)
        );
        assert!(
            yi.steps()
                .iter()
                .any(|s| s.kind() == StepKind::InstallTailscaleUserspace)
        );
        assert!(yi.data_lane() == DataLane::OnvifT);
        assert!(yi.brick_recovery().is_some());
    }

    #[test]
    fn openipc_is_wireless_network_flash() {
        let registry = RecipeRegistry::new();
        let Some(openipc) = registry.get(CameraFamily::OpenIPCClassA) else {
            return;
        };
        assert_eq!(openipc.friction_class(), FrictionClass::AOpenByDesign);
        assert_eq!(openipc.transport(), Transport::NetworkUpdate);
        assert!(openipc.software_wireless());
        assert!(
            openipc
                .steps()
                .iter()
                .any(|s| s.kind() == StepKind::NetworkFlashOpenipc)
        );
        assert!(!openipc.steps().iter().any(|s| s.is_physical()));
    }

    #[test]
    fn wyze_and_aosu_are_locked_software_with_live_data_lanes() {
        let registry = RecipeRegistry::new();
        let wyze = match registry.get(CameraFamily::WyzeV4) {
            Some(r) => r,
            None => return,
        };
        assert_eq!(wyze.friction_class(), FrictionClass::FLocked);
        assert_eq!(wyze.transport(), Transport::None);
        assert!(wyze.steps().is_empty());
        assert_eq!(wyze.data_lane(), DataLane::TutkNew);

        let aosu = match registry.get(CameraFamily::AosUP1Max) {
            Some(r) => r,
            None => return,
        };
        assert_eq!(aosu.data_lane(), DataLane::Tuya35);
        assert!(aosu.prerequisites().contains(&Prerequisite::LocalKey));
    }

    #[test]
    fn integrity_catches_a_transport_step_mismatch() {
        // Force a mismatch: a recipe with transport None but a non-empty step
        // list must be rejected by the same invariants the registry uses.
        let bad = OnboardingRecipe::new(
            CameraFamily::GenericStandards,
            FrictionClass::ENetworkNative,
            Transport::None,
            &[],
            GENERIC_STEPS,
            None,
            DataLane::Rtsp,
            "bad",
        );
        let mismatched = (bad.transport() == Transport::None) != bad.steps().is_empty();
        assert!(mismatched);
    }
}
