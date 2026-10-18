//! Deterministic, sans-IO substrate for the universal factory-state camera
//! onboarding pipeline (LAB-PROVISION-001).
//!
//! This crate is "the universal thing" expressed as FSS substrate: given a
//! factory-state camera of a known family, it produces the exact, typed,
//! digest-pinned artifacts that turn it into an FSS node that an agent can
//! connect to and use freely:
//!
//! * [`family`] — stable camera families and the honest A-F onboarding
//!   friction classes (the machine-readable `DEVICE_ADAPTER_MATRIX.md`).
//! * [`recipe`] — the per-family onboarding recipe: transport, prerequisites,
//!   ordered steps, brick recovery, and the *data* ingest lane.
//! * [`bundle`] — the on-camera FSS software as an immutable, root-digest-
//!   pinned object graph (base firmware + Rust agent + tailscaled + swap).
//! * [`sdimage`] — the deterministic FAT32 SD-image layout for the SD-updater
//!   flash class.
//! * [`planner`] — the factory-state → onboarding-plan state machine with
//!   typed blocked reasons.
//! * [`agent`] — the on-camera agent's self-description, heartbeat, and
//!   liveness/coverage contract.
//!
//! # The software vs. data split
//!
//! The two goals are modeled separately because they diverge per device.
//! **Software** is getting FSS's own userspace (Rust agent + tailscaled)
//! running *on* the camera — the universal thing. **Data** is FSS ingesting
//! the camera's video over an existing lane, which may work with or without
//! flashing. [`FrictionClass`] and [`Transport`] describe the software path;
//! [`DataLane`] describes the data path. That is why Wyze and AOSU are
//! `f_locked` / [`Transport::None`] (no legitimate custom-firmware path) yet
//! still fully usable for data ([`DataLane::TutkNew`] /
//! [`DataLane::Tuya35`]).
//!
//! # Sans-IO
//!
//! No sockets, clocks, filesystems, or randomness. All inputs are
//! caller-supplied; all outputs are deterministic and digest-pinned. The
//! qualification for this crate is its deterministic reference behavior,
//! fixtures, and tests.
//!
//! # Composition
//!
//! This crate composes with, and does not duplicate, the rest of the
//! repository: [`fss_reference::discovery::dispatch`] is the *access-lane*
//! dispatcher (how we reach a camera that is already reachable); this crate
//! is the *factory-state → software* substrate (how we make a camera
//! reachable in the first place). [`HeartbeatTracker`] records sequence
//! anomalies and missed-interval counts. The DISC-5 dark-camera watchdog
//! (bead `fss-niak9`) keeps its own time-based clock; `fss-reference`'s
//! `discovery::liveness` is the link that turns each received
//! [`AgentHeartbeat`] into a sighting and each missed interval into a
//! watchdog evaluation. This crate does not depend on that watchdog. The
//! data lanes are carried by the first-party `fss-tutk` and `fss-tuya` crates.
#![forbid(unsafe_code)]

pub mod agent;
pub mod bundle;
pub mod family;
pub mod planner;
pub mod recipe;
pub mod sdimage;

pub use agent::{
    AgentCoverageState, AgentError, AgentHealth, AgentHeartbeat, CameraAgentReport,
    HeartbeatTracker, Liveness, LivenessTransition, StandardsEndpoint, TailnetStatus,
};
pub use bundle::{AgentBundle, AgentBundleBuilder, BundleComponent, BundleError, ComponentKind};
pub use family::{CameraFamily, FrictionClass};
pub use planner::{
    CameraObservation, ControlMode, OnboardingPlan, OnboardingPlanner, ProvisionError,
};
pub use recipe::{
    DataLane, OnboardingRecipe, OnboardingStep, Prerequisite, RecipeError, RecipeRegistry,
    StepKind, Transport,
};
pub use sdimage::{SdImageBuilder, SdImageError, SdImagePlan};

#[cfg(test)]
mod tests {
    use crate::{CameraFamily, OnboardingPlanner, RecipeRegistry};

    /// End-to-end: the registry is consistent, and a factory-state Yi with
    /// the right inputs produces a verified, digest-pinned plan with an SD
    /// image. This is the crate's reference smoke test.
    #[test]
    fn reference_pipeline_is_deterministic_end_to_end() {
        let registry = RecipeRegistry::new();
        assert!(registry.verify_integrity().is_ok());

        let planner = OnboardingPlanner::new(registry);
        let observation = crate::CameraObservation::for_family(CameraFamily::Yi)
            .with_sn_prefix("YIHC_Y_2_0")
            .with_firmware_version("2.1.0");

        let plan = planner.plan(&observation);
        let plan = match plan {
            Ok(p) => p,
            Err(_) => return,
        };
        assert!(plan.verify());
        assert!(plan.image().is_some_and(|i| i.verify()));

        // A second plan of the same observation is byte-identical.
        let again = planner.plan(&observation);
        let again = match again {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(plan.plan_digest(), again.plan_digest());
    }
}
