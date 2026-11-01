#![forbid(unsafe_code)]
//! Current adopted camera geometry for retained scene reconstruction.
//!
//! The owner verifies an existing FSSCAL01/02 candidate, its original camera inputs and the
//! deployment's current adoption/withdrawal history. It publishes nothing. Adoption is owner
//! authority, not a physical calibration measurement; the original conditional covariance is
//! retained without converting it to a deterministic error bound or inventing an expiry.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, LedgerAnchor, SensorId};
use fss_geometry::{GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};
use fss_twin::PropertyTwin;

use super::calibration_adoption::{
    AdoptionError, RetainedAdoption, adopted_currency, retained_adoptions_from_batches,
};
use super::site_calibration::{
    CalibratedCamera, CalibrationImageBasis, MAX_CALIBRATION_BYTES, MAX_OBSERVATION_BYTES,
    SiteCalibration, SiteCalibrationError,
};
use crate::{ReferenceDeployment, ReplayCx};

/// Semantic identity of a complete selected calibration binding, not effect authority.
pub const SCENE_CALIBRATION_DOMAIN: &str = "fss.retained_scene_calibration.v1";
/// Bound on selected distinct physical cameras.
pub const MAX_SCENE_CALIBRATION_CAMERAS: usize = 16;
/// Complete calibration and original-input byte ceiling, checked before decoding.
pub const MAX_SCENE_CALIBRATION_INPUT_BYTES: usize = 20 * 1024 * 1024;
/// Cumulative custody-read reservation across resolution and every revalidation.
pub const MAX_SCENE_CALIBRATION_AUTHORITY_BYTES: u64 = 64 * 1024 * 1024;
/// Complete authority-prefix traversal ceiling, including unrelated ledger families.
pub const MAX_SCENE_CALIBRATION_DELTAS: usize = 65_536;

/// One exact camera selection and the physical sensor actually selected by its source owner.
#[derive(Clone, Debug)]
pub struct SceneCalibrationBinding<'a> {
    /// Nonzero handle in the calibration and retained adoption.
    pub camera_handle: u64,
    /// Actual retained source sensor; not an alias inferred from the camera name.
    pub sensor_id: SensorId,
    /// Exact current adoption receipt reviewed by the caller.
    pub adoption_digest: ContentDigest,
    /// Original correspondence text or JPEG metadata pinned by the calibration.
    pub camera_input: &'a [u8],
}

/// Immutable supplied bytes; all filesystem opening remains at the caller's explicit I/O boundary.
#[derive(Clone, Copy, Debug)]
pub struct SceneCalibrationRequest<'a> {
    /// Complete canonical FSSCAL01/02 bytes, at most 4 MiB.
    pub calibration_bytes: &'a [u8],
    /// Domain-tagged calibration identity, distinct from the hash of its complete file bytes.
    pub calibration_digest: ContentDigest,
    /// Exactly one original input and source binding per selected camera.
    pub bindings: &'a [SceneCalibrationBinding<'a>],
}

/// Typed failures never fall back to nominal geometry or a different adoption.
#[derive(Debug)]
pub enum SceneCalibrationError {
    /// Invalid count, digest, duplicate camera/sensor or malformed selection.
    InvalidInput(&'static str),
    /// Imported twin, input identity, source sensor or retained authority scope differs.
    BasisMismatch(&'static str),
    /// A noncentral/raw-distorted imaging model is outside this explicit pinhole profile.
    Unsupported(&'static str),
    /// The selected camera has no retained current adoption.
    Unadopted(u64),
    /// Complete input, traversal, allocation or cumulative source-read bound exhausted.
    Limit,
    /// A required authority object cannot be read or verified.
    Custody,
    /// Existing current-adoption, withdrawal, name or generation verification refused.
    Adoption(Box<AdoptionError>),
    /// Canonical calibration/input decoding refused.
    Calibration(Box<SiteCalibrationError>),
    /// Shared geometry budget, cancellation or numeric contract refused.
    Geometry(GeometryError),
    /// Replay authority was cancelled before or after a read.
    Cancelled,
}
impl SceneCalibrationError {
    /// Stable content-free error category.
    pub const fn stable_id(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "ERR-SCENE-CALIBRATION-INPUT-001",
            Self::BasisMismatch(_) => "ERR-SCENE-CALIBRATION-BASIS-001",
            Self::Unsupported(_) => "ERR-SCENE-CALIBRATION-UNSUPPORTED-001",
            Self::Unadopted(_) | Self::Adoption(_) => "ERR-SCENE-CALIBRATION-CURRENCY-001",
            Self::Limit
            | Self::Geometry(GeometryError::BudgetExhausted | GeometryError::LimitExceeded) => {
                "ERR-SCENE-CALIBRATION-LIMIT-001"
            }
            Self::Custody => "ERR-SCENE-CALIBRATION-CUSTODY-001",
            Self::Cancelled | Self::Geometry(GeometryError::Cancelled) => {
                "ERR-SCENE-CALIBRATION-CANCELLED-001"
            }
            Self::Calibration(_) | Self::Geometry(_) => "ERR-SCENE-CALIBRATION-INPUT-001",
        }
    }
}
impl fmt::Display for SceneCalibrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(why) | Self::BasisMismatch(why) | Self::Unsupported(why) => {
                write!(f, "{}: {why}", self.stable_id())
            }
            Self::Unadopted(camera) => write!(
                f,
                "{}: camera {camera} has no current retained adoption",
                self.stable_id()
            ),
            Self::Adoption(error) => write!(f, "{}: {error}", self.stable_id()),
            Self::Calibration(error) => write!(f, "{}: {error}", self.stable_id()),
            Self::Geometry(error) => write!(f, "{}: {error}", self.stable_id()),
            _ => f.write_str(self.stable_id()),
        }
    }
}
impl std::error::Error for SceneCalibrationError {}
impl From<GeometryError> for SceneCalibrationError {
    fn from(error: GeometryError) -> Self {
        if error == GeometryError::Cancelled {
            Self::Cancelled
        } else {
            Self::Geometry(error)
        }
    }
}
impl From<SiteCalibrationError> for SceneCalibrationError {
    fn from(error: SiteCalibrationError) -> Self {
        Self::Calibration(Box::new(error))
    }
}
impl From<AdoptionError> for SceneCalibrationError {
    fn from(error: AdoptionError) -> Self {
        Self::Adoption(Box::new(error))
    }
}
type Result<T> = std::result::Result<T, SceneCalibrationError>;

/// Immutable camera geometry and provenance admitted from a current retained adoption.
#[derive(Clone, Debug)]
pub struct SceneCalibrationCamera {
    record: CalibratedCamera,
    pose: RigidPose,
    intrinsics: PinholeIntrinsics,
    image_basis: CalibrationImageBasis,
    adoption: RetainedAdoption,
}
impl SceneCalibrationCamera {
    /// Original calibrated camera including the full conditional covariance and fixed parameters.
    pub fn record(&self) -> &CalibratedCamera {
        &self.record
    }
    /// World-to-camera pose from the decoded calibration, never an input override.
    pub fn pose(&self) -> RigidPose {
        self.pose
    }
    /// Original pinhole grid from the decoded calibration.
    pub fn intrinsics(&self) -> PinholeIntrinsics {
        self.intrinsics
    }
    /// Exact original image domain, grid and original-input digest.
    pub fn image_basis(&self) -> CalibrationImageBasis {
        self.image_basis
    }
    /// Current verified camera/sensor adoption at resolution.
    pub fn adoption(&self) -> &RetainedAdoption {
        &self.adoption
    }
}

#[derive(Debug, Default)]
struct AuthorityReads {
    verified: Cell<u64>,
    reserved: Cell<u64>,
}
impl AuthorityReads {
    fn reserve(&self, maximum: usize) -> Result<()> {
        let next = self
            .reserved
            .get()
            .checked_add(maximum as u64)
            .filter(|n| *n <= MAX_SCENE_CALIBRATION_AUTHORITY_BYTES)
            .ok_or(SceneCalibrationError::Limit)?;
        self.reserved.set(next);
        Ok(())
    }
    fn observed(&self, bytes: usize) -> Result<()> {
        let next = self
            .verified
            .get()
            .checked_add(bytes as u64)
            .filter(|n| *n <= self.reserved.get())
            .ok_or(SceneCalibrationError::Limit)?;
        self.verified.set(next);
        Ok(())
    }
}

/// Sealed selected calibration owner. Revalidation renews no source or work allowance.
#[derive(Debug)]
pub struct RetainedSceneCalibration {
    calibration_record: SiteCalibration,
    cameras: Vec<SceneCalibrationCamera>,
    calibration: ContentDigest,
    file_digest: ContentDigest,
    twin_package: ContentDigest,
    twin_source: ContentDigest,
    anchor: LedgerAnchor,
    digest: ContentDigest,
    input_bytes: u64,
    reads: AuthorityReads,
}
impl RetainedSceneCalibration {
    /// Complete decoded calibration, including atlas, control, solver and covariance assumptions.
    pub fn record(&self) -> &SiteCalibration {
        &self.calibration_record
    }
    /// Complete selected inventory in ascending physical camera-handle order.
    pub fn cameras(&self) -> &[SceneCalibrationCamera] {
        &self.cameras
    }
    /// Exact selected camera; an absent camera is never inferred from a matching sensor name.
    pub fn camera(&self, handle: u64) -> Option<&SceneCalibrationCamera> {
        self.cameras
            .binary_search_by_key(&handle, |c| c.record.identity.camera)
            .ok()
            .map(|i| &self.cameras[i])
    }
    /// Domain-tagged identity carried by the canonical calibration file and adoption receipts.
    pub fn calibration_identity(&self) -> ContentDigest {
        self.calibration
    }
    /// SHA-256 of every byte of the supplied calibration file, including its trailing identity.
    pub fn calibration_file_digest(&self) -> ContentDigest {
        self.file_digest
    }
    /// Exact imported twin package.
    pub fn twin_package(&self) -> ContentDigest {
        self.twin_package
    }
    /// Exact source scene pinned by the imported twin and calibration.
    pub fn twin_source(&self) -> ContentDigest {
        self.twin_source
    }
    /// Canonical selection identity, independent of unrelated later ledger appends.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Exact authority prefix checked at resolution; this is not a physical-validity interval.
    pub fn anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
    /// Complete supplied calibration and original metadata bytes admitted once.
    pub fn input_bytes(&self) -> u64 {
        self.input_bytes
    }
    /// Actual bytes returned by successful verified authority reads, including revalidation.
    pub fn authority_read_bytes(&self) -> u64 {
        self.reads.verified.get()
    }
    /// Cumulative maximum-byte reservations, including failed reads; never renewed on retry.
    pub fn authority_reserved_bytes(&self) -> u64 {
        self.reads.reserved.get()
    }
    /// Complete supplied input plus successfully verified authority bytes processed so far.
    pub fn source_bytes(&self) -> u64 {
        self.input_bytes + self.authority_read_bytes()
    }

    /// Require the same selected current receipts, exact sensor bindings and deployment lineage.
    /// Unrelated completed JPEG/source publications may advance the authority prefix. A restored,
    /// older, divergent, superseded, withdrawn or unreadable selection is refused as a whole.
    pub fn revalidate(
        &self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
        work: &mut WorkBudget<'_>,
    ) -> Result<()> {
        checkpoint(cx, "scene_calibration:revalidate")?;
        let current = deployment.current_anchor();
        if current.site_lineage != self.anchor.site_lineage
            || current.ledger_epoch != self.anchor.ledger_epoch
            || current.commit_sequence < self.anchor.commit_sequence
        {
            return Err(SceneCalibrationError::BasisMismatch(
                "deployment lineage or retained prefix differs",
            ));
        }
        let history = read_authority(deployment, &self.reads, work, cx)?;
        if current != &self.anchor
            && !deployment
                .ledger()
                .batches()
                .iter()
                .any(|batch| batch.new_anchor == self.anchor)
        {
            return Err(SceneCalibrationError::BasisMismatch(
                "original authority prefix is not retained",
            ));
        }
        for camera in &self.cameras {
            work.charge(1024)?;
            let retained = checked_adoption(
                &history,
                self.calibration,
                self.twin_package,
                &camera.record,
                &camera.adoption.receipt.sensor_id,
                camera.adoption.digest,
            )?;
            if retained != camera.adoption {
                return Err(SceneCalibrationError::BasisMismatch(
                    "selected adoption changed",
                ));
            }
        }
        checkpoint(cx, "scene_calibration:revalidated")?;
        work.charge(0)?;
        Ok(())
    }
}

fn pin(value: ContentDigest) -> bool {
    value.algorithm() == DigestAlgorithm::Sha256 && value.bytes() != [0; 32]
}
fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage)
        .map_err(|_| SceneCalibrationError::Cancelled)
}
fn read_authority(
    deployment: &ReferenceDeployment,
    reads: &AuthorityReads,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<BTreeMap<u64, Vec<RetainedAdoption>>> {
    checkpoint(cx, "scene_calibration:authority")?;
    let batches = deployment.ledger().batches();
    if batches.len() > MAX_SCENE_CALIBRATION_DELTAS {
        return Err(SceneCalibrationError::Limit);
    }
    let mut deltas = 0_usize;
    for batch in batches {
        work.charge(32)?;
        deltas = deltas
            .checked_add(batch.deltas.len())
            .filter(|n| *n <= MAX_SCENE_CALIBRATION_DELTAS)
            .ok_or(SceneCalibrationError::Limit)?;
    }
    // Both adoption history and withdrawal reconstruction traverse this complete prefix.
    work.charge(4096 + 256 * deltas as u64 + 128 * batches.len() as u64)?;
    let mut failure = None;
    let history = retained_adoptions_from_batches(batches, |digest, maximum| {
        let read = (|| -> Result<Vec<u8>> {
            checkpoint(cx, "scene_calibration:read")?;
            reads.reserve(maximum)?;
            work.charge(256 + maximum as u64 * 4)?;
            let bytes = deployment
                .publisher()
                .spool()
                .read_bounded(digest, maximum)
                .map_err(|_| SceneCalibrationError::Custody)?;
            reads.observed(bytes.len())?;
            checkpoint(cx, "scene_calibration:read_complete")?;
            Ok(bytes)
        })();
        read.map_err(|error| {
            failure = Some(error);
            AdoptionError::InvalidRecord("bounded scene calibration authority read refused")
        })
    });
    if let Some(error) = failure {
        return Err(error);
    }
    checkpoint(cx, "scene_calibration:authority_complete")?;
    Ok(history?)
}

fn checked_adoption(
    history: &BTreeMap<u64, Vec<RetainedAdoption>>,
    calibration: ContentDigest,
    twin: ContentDigest,
    camera: &CalibratedCamera,
    sensor: &SensorId,
    expected: ContentDigest,
) -> Result<RetainedAdoption> {
    for (&handle, records) in history {
        if handle != camera.identity.camera
            && records
                .last()
                .is_some_and(|r| r.receipt.sensor_id == *sensor)
        {
            return Err(SceneCalibrationError::BasisMismatch(
                "physical sensor is bound to another camera handle",
            ));
        }
    }
    let current = adopted_currency(history, calibration, &camera.name, camera.identity, || {
        Ok(sensor.clone())
    })?
    .ok_or(SceneCalibrationError::Unadopted(camera.identity.camera))?;
    if current.digest != expected
        || current.receipt.twin_package != twin
        || current.receipt.camera_name != camera.name
        || current.receipt.camera_handle != camera.identity.camera
        || current.receipt.intrinsics_generation != camera.identity.intrinsics
        || current.receipt.extrinsics_generation != camera.identity.extrinsics
    {
        return Err(SceneCalibrationError::BasisMismatch(
            "exact current adoption, name, twin or camera tuple differs",
        ));
    }
    Ok(current)
}

/// Resolve existing adopted camera geometry without publishing or accepting any calibration.
pub fn resolve_scene_calibration(
    deployment: &ReferenceDeployment,
    request: &SceneCalibrationRequest<'_>,
    twin: &PropertyTwin,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RetainedSceneCalibration> {
    checkpoint(cx, "scene_calibration:begin")?;
    work.charge(0)?;
    if request.bindings.is_empty()
        || request.bindings.len() > MAX_SCENE_CALIBRATION_CAMERAS
        || request.calibration_bytes.len() > MAX_CALIBRATION_BYTES
        || !pin(request.calibration_digest)
    {
        return Err(SceneCalibrationError::InvalidInput(
            "calibration identity, byte bound or camera count",
        ));
    }
    let mut inputs = request.calibration_bytes.len();
    let mut handles = BTreeSet::new();
    let mut sensors = BTreeSet::new();
    for binding in request.bindings {
        if binding.camera_handle == 0
            || !pin(binding.adoption_digest)
            || binding.camera_input.is_empty()
            || binding.camera_input.len() > MAX_OBSERVATION_BYTES
            || !handles.insert(binding.camera_handle)
            || !sensors.insert(binding.sensor_id.as_str())
        {
            return Err(SceneCalibrationError::InvalidInput(
                "camera, source sensor, adoption or original input is duplicated or invalid",
            ));
        }
        inputs = inputs
            .checked_add(binding.camera_input.len())
            .filter(|n| *n <= MAX_SCENE_CALIBRATION_INPUT_BYTES)
            .ok_or(SceneCalibrationError::Limit)?;
    }
    work.charge(8192 + inputs as u64 * 8 + request.bindings.len() as u64 * 4096)?;
    let (calibration, identity) =
        SiteCalibration::decode(request.calibration_bytes, Some(request.calibration_digest))?;
    if calibration.twin_package.bytes() != twin.digest()
        || calibration.twin_source.bytes() != twin.source_scene_digest()
        || !pin(calibration.twin_package)
        || !pin(calibration.twin_source)
    {
        return Err(SceneCalibrationError::BasisMismatch(
            "calibration and imported twin package/source differ",
        ));
    }
    let reads = AuthorityReads::default();
    let history = read_authority(deployment, &reads, work, cx)?;
    let mut cameras = Vec::new();
    cameras
        .try_reserve_exact(request.bindings.len())
        .map_err(|_| SceneCalibrationError::Limit)?;
    for binding in request.bindings {
        checkpoint(cx, "scene_calibration:camera")?;
        let record = calibration
            .cameras
            .iter()
            .find(|c| c.identity.camera == binding.camera_handle)
            .ok_or(SceneCalibrationError::BasisMismatch(
                "selected camera is absent from calibration",
            ))?;
        if record.distortion != [0.0, 0.0] {
            return Err(SceneCalibrationError::Unsupported(
                "adopted scene geometry requires an original pinhole camera",
            ));
        }
        let geometry = record.pinhole_pose()?;
        let image_basis =
            calibration.camera_input_basis(binding.camera_handle, binding.camera_input)?;
        let adoption = checked_adoption(
            &history,
            identity,
            calibration.twin_package,
            record,
            &binding.sensor_id,
            binding.adoption_digest,
        )?;
        cameras.push(SceneCalibrationCamera {
            record: record.clone(),
            pose: geometry.pose,
            intrinsics: geometry.intrinsics,
            image_basis,
            adoption,
        });
    }
    cameras.sort_by_key(|c| c.record.identity.camera);
    let anchor = deployment.current_anchor().clone();
    let file_digest = ContentDigest::sha256(request.calibration_bytes);
    let mut e = CanonicalEncoder::new();
    e.text(SCENE_CALIBRATION_DOMAIN);
    e.text(&anchor.site_lineage);
    e.u64(anchor.ledger_epoch);
    e.digest(identity);
    e.digest(file_digest);
    e.digest(calibration.twin_package);
    e.digest(calibration.twin_source);
    e.u64(cameras.len() as u64);
    for camera in &cameras {
        e.u64(camera.record.identity.camera);
        e.u64(camera.record.identity.intrinsics);
        e.u64(camera.record.identity.extrinsics);
        e.text(&camera.record.name);
        e.text(camera.adoption.receipt.sensor_id.as_str());
        e.digest(camera.adoption.digest);
        e.digest(camera.image_basis.input_digest);
        e.bytes(&camera.image_basis.image.image_domain);
    }
    let bytes = e
        .finish_checked()
        .map_err(|_| SceneCalibrationError::Limit)?;
    let digest = ContentDigest::sha256(&bytes);
    checkpoint(cx, "scene_calibration:resolved")?;
    work.charge(0)?;
    Ok(RetainedSceneCalibration {
        cameras,
        calibration: identity,
        file_digest,
        twin_package: calibration.twin_package,
        twin_source: calibration.twin_source,
        anchor,
        digest,
        input_bytes: inputs as u64,
        reads,
        calibration_record: calibration,
    })
}

#[cfg(test)]
#[path = "scene_calibration_tests.rs"]
mod tests;
