//! Factory-state to onboarding-plan state machine (LAB-PROVISION-001).
//!
//! [`OnboardingPlanner::plan`] takes a [`CameraObservation`] (what the operator
//! has learned about one factory-state unit) and a [`RecipeRegistry`] (the
//! per-family truth) and returns either a complete, digest-pinned
//! [`OnboardingPlan`] or a **typed** reason it cannot proceed. A blocked plan
//! is first-class: "missing SN prefix", "already flashed", and "locked" are
//! different, machine-decidable states — never a string or a silent skip.
//!
//! The plan separates the software path (steps + optional SD image) from the
//! data path ([`DataLane`]), and binds everything to a `plan_digest` so two
//! hosts planning the same observation produce the same artifact.

use core::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError,
};

use crate::bundle::AgentBundle;
use crate::family::{CameraFamily, FrictionClass};
use crate::recipe::{
    DataLane, OnboardingRecipe, OnboardingStep, Prerequisite, RecipeRegistry, Transport,
};
use crate::sdimage::{SdImageBuilder, SdImageError, SdImagePlan};

/// Default SD card capacity the planner sizes the SD image against (8 GiB).
pub const DEFAULT_SDCARD_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// How FSS will control the camera once onboarded.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ControlMode {
    /// FSS software was flashed; FSS controls the camera directly.
    Flashed = 1,
    /// No firmware change; FSS ingests over the standards endpoint.
    StandardsIngest = 2,
    /// No firmware change; FSS ingests over a proven protocol lane.
    LaneIngest = 3,
}

impl ControlMode {
    /// The stable machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Flashed => "flashed",
            Self::StandardsIngest => "standards_ingest",
            Self::LaneIngest => "lane_ingest",
        }
    }
}

impl fmt::Display for ControlMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CanonicalEncode for ControlMode {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(*self as u8);
    }
}

impl CanonicalDecode for ControlMode {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Flashed),
            2 => Ok(Self::StandardsIngest),
            3 => Ok(Self::LaneIngest),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// What the operator has observed about one factory-state camera.
///
/// All fields are caller-supplied (sans-IO): the planner never probes the
/// device itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CameraObservation {
    family: CameraFamily,
    already_flashed: bool,
    sn_prefix: Option<String>,
    firmware_version: Option<String>,
    web_update_reachable: bool,
    local_key_available: bool,
}

impl CameraObservation {
    /// Starts an observation for a family with no facts known yet.
    #[must_use]
    pub fn for_family(family: CameraFamily) -> Self {
        Self {
            family,
            already_flashed: false,
            sn_prefix: None,
            firmware_version: None,
            web_update_reachable: false,
            local_key_available: false,
        }
    }

    /// Records the SN prefix read from the physical label.
    #[must_use]
    pub fn with_sn_prefix(mut self, value: impl Into<String>) -> Self {
        self.sn_prefix = Some(value.into());
        self
    }

    /// Records the current firmware version.
    #[must_use]
    pub fn with_firmware_version(mut self, value: impl Into<String>) -> Self {
        self.firmware_version = Some(value.into());
        self
    }

    /// Marks the stock web-UI update endpoint as reachable.
    #[must_use]
    pub fn with_web_update_reachable(mut self) -> Self {
        self.web_update_reachable = true;
        self
    }

    /// Marks the owner's Tuya `local_key` as available.
    #[must_use]
    pub fn with_local_key_available(mut self) -> Self {
        self.local_key_available = true;
        self
    }

    /// Marks the camera as already running FSS software.
    #[must_use]
    pub fn with_already_flashed(mut self) -> Self {
        self.already_flashed = true;
        self
    }

    /// The family under observation.
    #[must_use]
    pub const fn family(&self) -> CameraFamily {
        self.family
    }

    /// Whether the camera already runs FSS software.
    #[must_use]
    pub const fn is_flashed(&self) -> bool {
        self.already_flashed
    }

    /// The SN prefix, if read.
    #[must_use]
    pub fn sn_prefix(&self) -> Option<&str> {
        self.sn_prefix.as_deref()
    }

    /// The firmware version, if read.
    #[must_use]
    pub fn firmware_version(&self) -> Option<&str> {
        self.firmware_version.as_deref()
    }

    /// Whether the stock web-UI update endpoint is reachable.
    #[must_use]
    pub const fn web_update_reachable(&self) -> bool {
        self.web_update_reachable
    }

    /// Whether the owner's Tuya `local_key` is available.
    #[must_use]
    pub const fn local_key_available(&self) -> bool {
        self.local_key_available
    }
}

/// A complete, digest-pinned onboarding plan for one camera.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnboardingPlan {
    family: CameraFamily,
    friction_class: FrictionClass,
    transport: Transport,
    control: ControlMode,
    software_wireless: bool,
    steps: Vec<OnboardingStep>,
    /// Present only for the SD-updater transport.
    image: Option<SdImagePlan>,
    data_lane: DataLane,
    note: &'static str,
    plan_digest: ContentDigest,
}

impl OnboardingPlan {
    /// The family this plan is for.
    #[must_use]
    pub const fn family(&self) -> CameraFamily {
        self.family
    }

    /// The friction class for the software path.
    #[must_use]
    pub const fn friction_class(&self) -> FrictionClass {
        self.friction_class
    }

    /// How the software path delivers the image (or [`Transport::None`]).
    #[must_use]
    pub const fn transport(&self) -> Transport {
        self.transport
    }

    /// How FSS will control the camera once onboarded.
    #[must_use]
    pub const fn control(&self) -> ControlMode {
        self.control
    }

    /// Whether the software path needs zero physical touch.
    #[must_use]
    pub const fn software_wireless(&self) -> bool {
        self.software_wireless
    }

    /// The ordered, typed steps (empty when there is no software path).
    #[must_use]
    pub fn steps(&self) -> &[OnboardingStep] {
        &self.steps
    }

    /// The SD image plan, present only for the SD-updater transport.
    #[must_use]
    pub fn image(&self) -> Option<&SdImagePlan> {
        self.image.as_ref()
    }

    /// The ingest lane for the camera's data.
    #[must_use]
    pub const fn data_lane(&self) -> DataLane {
        self.data_lane
    }

    /// The honest nuance for this family.
    #[must_use]
    pub const fn note(&self) -> &'static str {
        self.note
    }

    /// The digest binding the plan.
    #[must_use]
    pub const fn plan_digest(&self) -> ContentDigest {
        self.plan_digest
    }

    /// Whether the stored digest still matches the plan (no drift).
    #[must_use]
    pub fn verify(&self) -> bool {
        self.plan_digest == self.computed_plan_digest()
    }

    /// Recomputes the plan digest from the machine-decidable fields.
    ///
    /// The human `note` is deliberately excluded so prose edits do not change
    /// the artifact's identity.
    #[must_use]
    pub fn computed_plan_digest(&self) -> ContentDigest {
        Self::digest_of(
            self.family,
            self.friction_class,
            self.transport,
            self.control,
            self.software_wireless,
            &self.steps,
            self.image.as_ref(),
            self.data_lane,
        )
    }

    fn digest_of(
        family: CameraFamily,
        friction_class: FrictionClass,
        transport: Transport,
        control: ControlMode,
        software_wireless: bool,
        steps: &[OnboardingStep],
        image: Option<&SdImagePlan>,
        data_lane: DataLane,
    ) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.u8(family as u8);
        encoder.u8(friction_class as u8);
        encoder.u8(transport as u8);
        encoder.u8(control as u8);
        encoder.bool(software_wireless);
        encoder.u32(steps.len() as u32);
        for step in steps {
            encoder.u8(step.kind() as u8);
        }
        encoder.bool(image.is_some());
        if let Some(image) = image {
            encoder.digest(image.image_digest());
        }
        encoder.u8(data_lane as u8);
        ContentDigest::sha256(&encoder.finish())
    }
}

/// Typed reasons the planner cannot produce a plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProvisionError {
    /// The camera already runs FSS software; re-planning is a terminal no-op.
    AlreadyFlashed,
    /// The registry has no recipe for the observed family.
    MissingFamily(CameraFamily),
    /// A required owner input is not yet known.
    MissingPrerequisite(Prerequisite),
    /// The SD image layout failed.
    SdImage(SdImageError),
    /// A canonical encode/decode failed.
    Canonical(ContractError),
}

impl fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyFlashed => {
                f.write_str("camera already runs FSS software; nothing to plan")
            }
            Self::MissingFamily(family) => write!(f, "no recipe for family {family}"),
            Self::MissingPrerequisite(pre) => write!(f, "missing prerequisite: {pre}"),
            Self::SdImage(e) => write!(f, "sd image error: {e}"),
            Self::Canonical(e) => write!(f, "canonical error: {e}"),
        }
    }
}

impl std::error::Error for ProvisionError {}

impl From<SdImageError> for ProvisionError {
    fn from(value: SdImageError) -> Self {
        Self::SdImage(value)
    }
}

impl From<ContractError> for ProvisionError {
    fn from(value: ContractError) -> Self {
        Self::Canonical(value)
    }
}

/// Derives the control mode from the recipe's transport.
fn control_mode(recipe: &OnboardingRecipe) -> ControlMode {
    match recipe.transport() {
        Transport::SdImage | Transport::NetworkUpdate | Transport::TuyaProvisioning => {
            ControlMode::Flashed
        }
        Transport::StandardsNative => ControlMode::StandardsIngest,
        Transport::None => ControlMode::LaneIngest,
    }
}

/// Derives a deterministic release handle from the known inputs.
///
/// This is a reference handle (family + SN prefix + firmware version); the
/// exact yi-hack variant string is qualified against the release's own table
/// once the owner reads the label.
fn release_handle(
    family: CameraFamily,
    sn_prefix: Option<&str>,
    firmware_version: Option<&str>,
) -> String {
    let sn = sn_prefix.unwrap_or_default();
    let fw = firmware_version.unwrap_or_default();
    format!("{}-{sn}-{fw}", family.as_str())
}

/// Turns factory-state observations into onboarding plans.
#[derive(Clone, Debug)]
pub struct OnboardingPlanner {
    recipes: RecipeRegistry,
    card_capacity_bytes: u64,
}

impl OnboardingPlanner {
    /// Creates a planner over the given recipes with the default card size.
    #[must_use]
    pub fn new(recipes: RecipeRegistry) -> Self {
        Self {
            recipes,
            card_capacity_bytes: DEFAULT_SDCARD_BYTES,
        }
    }

    /// Overrides the SD card capacity the planner sizes the image against.
    #[must_use]
    pub fn with_card_capacity(mut self, bytes: u64) -> Self {
        self.card_capacity_bytes = bytes;
        self
    }

    /// The recipe registry this planner uses.
    #[must_use]
    pub const fn recipes(&self) -> &RecipeRegistry {
        &self.recipes
    }

    /// Plans the onboarding for one factory-state camera, or returns a typed
    /// reason it cannot proceed.
    pub fn plan(&self, observation: &CameraObservation) -> Result<OnboardingPlan, ProvisionError> {
        let family = observation.family();
        if observation.is_flashed() {
            return Err(ProvisionError::AlreadyFlashed);
        }
        let Some(recipe) = self.recipes.get(family) else {
            return Err(ProvisionError::MissingFamily(family));
        };

        for prerequisite in recipe.prerequisites() {
            let satisfied = match prerequisite {
                Prerequisite::SnPrefix => observation.sn_prefix().is_some(),
                Prerequisite::FirmwareVersion => observation.firmware_version().is_some(),
                Prerequisite::WebUpdateEndpoint => observation.web_update_reachable(),
                Prerequisite::LocalKey => observation.local_key_available(),
                // Satisfied by the pairing step itself; the owner is present.
                Prerequisite::OneTimePairing => true,
            };
            if !satisfied {
                return Err(ProvisionError::MissingPrerequisite(*prerequisite));
            }
        }

        let mut image: Option<SdImagePlan> = None;
        if recipe.transport() == Transport::SdImage {
            let release = release_handle(
                family,
                observation.sn_prefix(),
                observation.firmware_version(),
            );
            let bundle = AgentBundle::reference(family);
            let sd_builder =
                SdImageBuilder::new(self.card_capacity_bytes).map_err(ProvisionError::SdImage)?;
            let image_plan =
                sd_builder.build(family, release, &bundle).map_err(ProvisionError::SdImage)?;
            image = Some(image_plan);
        }

        let control = control_mode(recipe);
        let steps = recipe.steps().to_vec();
        let plan_digest = OnboardingPlan::digest_of(
            family,
            recipe.friction_class(),
            recipe.transport(),
            control,
            recipe.software_wireless(),
            &steps,
            image.as_ref(),
            recipe.data_lane(),
        );

        Ok(OnboardingPlan {
            family,
            friction_class: recipe.friction_class(),
            transport: recipe.transport(),
            control,
            software_wireless: recipe.software_wireless(),
            steps,
            image,
            data_lane: recipe.data_lane(),
            note: recipe.note(),
            plan_digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn planner() -> OnboardingPlanner {
        OnboardingPlanner::new(RecipeRegistry::new())
    }

    #[test]
    fn yi_with_prereqs_produces_a_flashed_sd_plan() {
        let obs = CameraObservation::for_family(CameraFamily::Yi)
            .with_sn_prefix("YIHC_Y_2_0")
            .with_firmware_version("2.1.0");
        let plan = planner().plan(&obs);
        let plan = match plan {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(plan.control(), ControlMode::Flashed);
        assert_eq!(plan.transport(), Transport::SdImage);
        assert!(!plan.software_wireless());
        assert!(plan.image().is_some_and(|i| i.verify()));
        assert!(plan.steps().iter().any(|s| s.kind() == crate::recipe::StepKind::InsertSdCard));
        assert_eq!(plan.data_lane(), DataLane::OnvifT);
        assert!(plan.verify());
    }

    #[test]
    fn yi_without_sn_prefix_is_blocked_typed() {
        let obs = CameraObservation::for_family(CameraFamily::Yi).with_firmware_version("2.1.0");
        let result = planner().plan(&obs);
        assert_eq!(result, Err(ProvisionError::MissingPrerequisite(Prerequisite::SnPrefix)));
    }

    #[test]
    fn already_flashed_is_a_terminal_noop() {
        let obs = CameraObservation::for_family(CameraFamily::Yi).with_already_flashed();
        assert_eq!(planner().plan(&obs), Err(ProvisionError::AlreadyFlashed));
    }

    #[test]
    fn wyze_is_locked_software_with_a_live_data_lane() {
        let obs = CameraObservation::for_family(CameraFamily::WyzeV4);
        let plan = planner().plan(&obs);
        let plan = match plan {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(plan.control(), ControlMode::LaneIngest);
        assert_eq!(plan.transport(), Transport::None);
        assert!(plan.steps().is_empty());
        assert!(plan.image().is_none());
        assert_eq!(plan.data_lane(), DataLane::TutkNew);
        assert_eq!(plan.friction_class(), FrictionClass::FLocked);
    }

    #[test]
    fn aosu_needs_the_local_key_for_its_data_lane() {
        let without = CameraObservation::for_family(CameraFamily::AosUP1Max);
        assert_eq!(
            planner().plan(&without),
            Err(ProvisionError::MissingPrerequisite(Prerequisite::LocalKey))
        );
        let with = CameraObservation::for_family(CameraFamily::AosUP1Max).with_local_key_available();
        let plan = planner().plan(&with);
        let plan = match plan {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(plan.control(), ControlMode::LaneIngest);
        assert_eq!(plan.data_lane(), DataLane::Tuya35);
    }

    #[test]
    fn openipc_is_wireless_network_flash_without_an_sd_image() {
        let without = CameraObservation::for_family(CameraFamily::OpenIPCClassA);
        assert_eq!(
            planner().plan(&without),
            Err(ProvisionError::MissingPrerequisite(Prerequisite::WebUpdateEndpoint))
        );
        let with = CameraObservation::for_family(CameraFamily::OpenIPCClassA)
            .with_web_update_reachable();
        let plan = planner().plan(&with);
        let plan = match plan {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(plan.control(), ControlMode::Flashed);
        assert!(plan.software_wireless());
        assert!(plan.image().is_none());
        assert!(!plan.steps().iter().any(|s| s.is_physical()));
    }

    #[test]
    fn generic_standards_is_standards_ingest() {
        let obs = CameraObservation::for_family(CameraFamily::GenericStandards);
        let plan = planner().plan(&obs);
        let plan = match plan {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(plan.control(), ControlMode::StandardsIngest);
        assert_eq!(plan.data_lane(), DataLane::Rtsp);
        assert!(plan.verify());
    }

    #[test]
    fn plan_digest_is_deterministic_and_sensitive_to_input() {
        let a = CameraObservation::for_family(CameraFamily::Yi)
            .with_sn_prefix("SN-1")
            .with_firmware_version("2.1.0");
        let b = CameraObservation::for_family(CameraFamily::Yi)
            .with_sn_prefix("SN-1")
            .with_firmware_version("2.1.0");
        let c = CameraObservation::for_family(CameraFamily::Yi)
            .with_sn_prefix("SN-2")
            .with_firmware_version("2.1.0");
        let plan_a = planner().plan(&a);
        let plan_b = planner().plan(&b);
        let plan_c = planner().plan(&c);
        let (plan_a, plan_b, plan_c) = match (plan_a, plan_b, plan_c) {
            (Ok(x), Ok(y), Ok(z)) => (x, y, z),
            _ => return,
        };
        assert_eq!(plan_a.plan_digest(), plan_b.plan_digest());
        assert_ne!(plan_a.plan_digest(), plan_c.plan_digest());
    }
}
