#![forbid(unsafe_code)]
//! Fail-closed bridge from a current calibration monitor result to world projection and handoff modeling.

use crate::calibration_monitor::{CalibrationDisposition, CalibrationMonitorReport};
use crate::{
    ContactObservation, ContactProjection, ProjectionOptions, PropertyTwin, TrackingCamera,
    TwinError, project_contact,
};
use fss_geometry::{HandoffCamera, WorkBudget};

/// Exact twin and atlas generations a gate decision is anchored to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CalibrationGateBasis {
    /// Exact imported property package and localization atlas generations used by the monitor.
    pub twin_digest: [u8; 32],
    /// Digest of the localization atlas generation the monitor evidence was computed against.
    pub atlas_digest: [u8; 32],
    /// Digest of the frozen calibration snapshot the monitor validated the camera against.
    pub calibration_digest: [u8; 32],
    /// Identifier of the admitted tracking camera; nonzero.
    pub camera: u64,
    /// Identifier of the admitted calibration generation; nonzero.
    pub calibration: u64,
    /// Identifier of the admitted image-domain (feature extractor) generation; nonzero.
    pub image_domain: u64,
    /// Digest of the image-domain generation matching the monitor's query features.
    pub image_domain_digest: [u8; 32],
    /// Clock identifier shared by the camera and every capture inside `checked_capture`; nonzero.
    pub clock: u64,
    /// Closed interval of capture timestamps (same clock units as the camera clock) the monitor
    /// actually checked the frozen pose over; must be inside the camera's validity interval.
    pub checked_capture: [u64; 2],
}

/// Fail-closed reasons a camera or projection is refused by the calibration gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationGateError {
    /// Caller-supplied basis or capture interval is structurally invalid.
    InvalidInput,
    /// Basis digests/identifiers disagree between camera, monitor report, or query.
    BasisMismatch,
    /// Current monitor evidence invalidated the frozen calibration.
    Invalidated,
    /// Monitor evidence was too sparse or uneven to judge the calibration.
    Indeterminate,
    /// The guarded world projection itself failed.
    Twin(TwinError),
}
impl From<TwinError> for CalibrationGateError {
    fn from(value: TwinError) -> Self {
        Self::Twin(value)
    }
}
impl std::fmt::Display for CalibrationGateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid calibration gate input",
            Self::BasisMismatch => "calibration gate basis mismatch",
            Self::Invalidated => "camera calibration invalidated by current monitor evidence",
            Self::Indeterminate => {
                "camera calibration not currently observable enough for world projection"
            }
            Self::Twin(_) => "guarded world projection failed",
        })
    }
}
impl std::error::Error for CalibrationGateError {}

/// A tracking camera admitted by [`admit_tracking_camera`] together with the exact
/// [`CalibrationGateBasis`] it was validated against; projections are refused on any basis drift.
pub struct MonitoredTrackingCamera {
    camera: TrackingCamera,
    basis: CalibrationGateBasis,
}
impl std::fmt::Debug for MonitoredTrackingCamera {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonitoredTrackingCamera")
            .field("camera", &self.basis.camera)
            .field("calibration", &self.basis.calibration)
            .field("checked_capture", &self.basis.checked_capture)
            .finish_non_exhaustive()
    }
}
impl MonitoredTrackingCamera {
    /// The exact basis (digests, identifiers, and checked capture interval) this camera was admitted under.
    pub fn basis(&self) -> CalibrationGateBasis {
        self.basis
    }
    /// Projects an observation into the world, refusing when the twin digest differs from the
    /// admitted basis or the observation's capture timestamp falls outside `checked_capture`.
    pub fn project_contact(
        &self,
        twin: &PropertyTwin,
        observation: ContactObservation,
        options: ProjectionOptions,
        budget: &mut WorkBudget<'_>,
    ) -> Result<ContactProjection, CalibrationGateError> {
        if twin.digest() != self.basis.twin_digest
            || !contains(self.basis.checked_capture, observation.capture)
        {
            return Err(CalibrationGateError::BasisMismatch);
        }
        Ok(project_contact(
            twin,
            self.camera,
            observation,
            options,
            budget,
        )?)
    }
    /// Verifies a handoff camera view matches the admitted camera exactly (identifier, geometry,
    /// clock, image domain, pose, intrinsics) and that its validity window covers the frozen
    /// validity interval while `source_capture` lies inside `checked_capture`.
    pub fn check_handoff_camera(
        &self,
        view: HandoffCamera<'_>,
        source_capture: [u64; 2],
    ) -> Result<(), CalibrationGateError> {
        if !contains(self.basis.checked_capture, source_capture)
            || view.id != self.camera.camera
            || view.geometry != self.camera.geometry
            || view.clock != self.camera.clock
            || view.image_mode != self.camera.image_domain
            || view.pose != self.camera.pose
            || view.intrinsics != self.camera.intrinsics
            || view.valid.earliest() < self.camera.validity[0]
            || view.valid.latest() > self.camera.validity[1]
        {
            return Err(CalibrationGateError::BasisMismatch);
        }
        Ok(())
    }
}

/// Admits a tracking camera for world projection only if the basis is structurally valid
/// (nonzero identifiers, all-zero digests rejected, ordered capture interval), the basis
/// exactly matches the monitor report and camera metadata, the checked capture interval lies
/// within the camera's validity interval, and the report disposition is `ValidUnderPolicy`.
pub fn admit_tracking_camera(
    camera: TrackingCamera,
    report: &CalibrationMonitorReport,
    basis: CalibrationGateBasis,
) -> Result<MonitoredTrackingCamera, CalibrationGateError> {
    if [
        basis.twin_digest,
        basis.atlas_digest,
        basis.calibration_digest,
        basis.image_domain_digest,
    ]
    .contains(&[0; 32])
        || basis.camera == 0
        || basis.calibration == 0
        || basis.image_domain == 0
        || basis.clock == 0
        || basis.checked_capture[0] > basis.checked_capture[1]
    {
        return Err(CalibrationGateError::InvalidInput);
    }
    if report.twin_digest != basis.twin_digest
        || report.atlas_digest != basis.atlas_digest
        || report.calibration != basis.calibration_digest
        || report.matches.atlas != basis.atlas_digest
        || report.matches.query.image_domain != basis.image_domain_digest
        || camera.camera != basis.camera
        || camera.calibration != basis.calibration
        || camera.image_domain != basis.image_domain
        || camera.clock != basis.clock
        || basis.checked_capture[0] < camera.validity[0]
        || basis.checked_capture[1] > camera.validity[1]
        || report.matches.query.dimensions != camera.intrinsics.dimensions()
    {
        return Err(CalibrationGateError::BasisMismatch);
    }
    match report.disposition {
        CalibrationDisposition::ValidUnderPolicy => Ok(MonitoredTrackingCamera { camera, basis }),
        CalibrationDisposition::Invalidate => Err(CalibrationGateError::Invalidated),
        CalibrationDisposition::Indeterminate => Err(CalibrationGateError::Indeterminate),
    }
}
fn contains(outer: [u64; 2], inner: [u64; 2]) -> bool {
    inner[0] <= inner[1] && outer[0] <= inner[0] && inner[1] <= outer[1]
}
