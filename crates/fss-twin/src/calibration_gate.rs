#![forbid(unsafe_code)]
//! Fail-closed bridge from a current calibration monitor result to world projection.

use fss_geometry::WorkBudget;
use crate::{ContactObservation, ContactProjection, ProjectionOptions, PropertyTwin, TrackingCamera,
    TwinError, project_contact};
use crate::calibration_monitor::{CalibrationDisposition, CalibrationMonitorReport};

/// External binding between the digest-oriented monitor and process-local tracking handles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CalibrationGateBasis {
    /// Exact calibration digest used by the monitor.
    pub calibration_digest: [u8; 32],
    /// Process-local physical camera handle.
    pub camera: u64,
    /// Process-local calibration generation.
    pub calibration: u64,
    /// Process-local image-domain generation.
    pub image_domain: u64,
    /// Digest of the same image-domain transform chain used by localization.
    pub image_domain_digest: [u8; 32],
    /// Capture clock generation.
    pub clock: u64,
    /// Capture interval for which this monitor observation is admitted.
    pub checked_capture: [u64; 2],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationGateError {
    InvalidInput,
    BasisMismatch,
    Invalidated,
    Indeterminate,
    Twin(TwinError),
}
impl From<TwinError> for CalibrationGateError { fn from(value: TwinError) -> Self { Self::Twin(value) } }
impl std::fmt::Display for CalibrationGateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid calibration gate input",
            Self::BasisMismatch => "calibration gate basis mismatch",
            Self::Invalidated => "camera calibration invalidated by current monitor evidence",
            Self::Indeterminate => "camera calibration not currently observable enough for world projection",
            Self::Twin(_) => "guarded world projection failed",
        })
    }
}
impl std::error::Error for CalibrationGateError {}

/// Camera snapshot admitted only for the exact monitor capture interval.
/// The underlying camera is private so callers cannot accidentally widen the receipt.
pub struct MonitoredTrackingCamera {
    camera: TrackingCamera,
    basis: CalibrationGateBasis,
}
impl std::fmt::Debug for MonitoredTrackingCamera {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonitoredTrackingCamera").field("camera", &self.basis.camera)
            .field("calibration", &self.basis.calibration).field("checked_capture", &self.basis.checked_capture)
            .finish_non_exhaustive()
    }
}
impl MonitoredTrackingCamera {
    pub fn basis(&self) -> CalibrationGateBasis { self.basis }

    /// Project only observations captured inside the monitor's exact witnessed interval.
    /// A later observation requires a later monitor receipt; stale validity cannot leak through.
    pub fn project_contact(&self, twin: &PropertyTwin, observation: ContactObservation,
        options: ProjectionOptions, budget: &mut WorkBudget<'_>)
        -> Result<ContactProjection, CalibrationGateError> {
        if observation.capture[0] < self.basis.checked_capture[0]
            || observation.capture[1] > self.basis.checked_capture[1] {
            return Err(CalibrationGateError::BasisMismatch);
        }
        Ok(project_contact(twin, self.camera, observation, options, budget)?)
    }
}

/// Convert a monitor result into a narrow world-projection capability.
/// Invalid or indeterminate monitoring never returns the raw TrackingCamera.
pub fn admit_tracking_camera(camera: TrackingCamera, report: &CalibrationMonitorReport,
    basis: CalibrationGateBasis) -> Result<MonitoredTrackingCamera, CalibrationGateError> {
    if basis.calibration_digest == [0;32] || basis.image_domain_digest == [0;32]
        || basis.camera == 0 || basis.calibration == 0 || basis.image_domain == 0 || basis.clock == 0
        || basis.checked_capture[0] > basis.checked_capture[1] {
        return Err(CalibrationGateError::InvalidInput);
    }
    if report.calibration != basis.calibration_digest
        || report.matches.query.image_domain != basis.image_domain_digest
        || camera.camera != basis.camera || camera.calibration != basis.calibration
        || camera.image_domain != basis.image_domain || camera.clock != basis.clock
        || basis.checked_capture[0] < camera.validity[0] || basis.checked_capture[1] > camera.validity[1]
        || report.matches.query.dimensions != camera.intrinsics.dimensions() {
        return Err(CalibrationGateError::BasisMismatch);
    }
    match report.disposition {
        CalibrationDisposition::ValidUnderPolicy => Ok(MonitoredTrackingCamera { camera, basis }),
        CalibrationDisposition::Invalidate => Err(CalibrationGateError::Invalidated),
        CalibrationDisposition::Indeterminate => Err(CalibrationGateError::Indeterminate),
    }
}
