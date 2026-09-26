#![forbid(unsafe_code)]
//! Owner adoption of a site calibration per camera, retained as deployment authority
//! (fss-x8j0v follow-up: retained calibration authority).
//!
//! `fss-event calibrate` writes a candidate calibration to a file and touches no deployment. An
//! adoption is the owner's approval-gated statement, retained in the deployment ledger under the
//! registered `twin_localization_receipt` family, that for one camera the calibration with this
//! digest, at this `CameraGeneration`, is the current one, and that the camera is the physical
//! source of one retained sensor.
//!
//! **Receipt** ([`AdoptionReceipt`], `FSSTLR01`, domain `fss.twin_localization_receipt.v1`): the
//! per-camera adoption generation, camera handle and owner camera name, the bound sensor id, the
//! calibration digest, its twin package (world frame), the intrinsics and extrinsics generations,
//! and a supersedes link to the prior receipt of the same camera (absent exactly for the first
//! adoption). The receipt identity is SHA-256 of its exact canonical bytes, which begin with the
//! magic and the domain tag; decoding refuses any noncanonical byte.
//!
//! **Sensor binding.** A camera handle is property-local and names the physical camera; the sensor
//! id names the stream the deployment retains from it. The owner binds them explicitly
//! (`--bind NAME:SENSOR`) and adoption verifies against retained custody that some readable sensor
//! capsule names that sensor, so a typo cannot bind a camera to a sensor that never produced
//! evidence. The binding is fixed per camera: a later adoption of the same camera must name the same
//! sensor, and a sensor bound to one camera handle cannot be bound to another
//! ([`AdoptionError::SensorConflict`]). A replaced physical camera is a new handle. Binding by
//! sensor rather than by one import keeps the adoption valid for every later recording.
//!
//! **Lifecycle** (mirrors `privacy_mask`): [`preview_adoption`] computes each proposed receipt and
//! an exact approval digest over the calibration, the bindings and every bound camera's current
//! retained adoption (or its absence); nothing is written. [`adopt`] retains exactly that
//! proposal when presented the approval: one spool object and one authority delta per adopted
//! camera on `object:twin-localization:camera-<handle>` (generation `n -> n + 1`), all in one
//! batch. An approval computed against an older state is stale and refused before any write.
//! Adoption is monotone per camera: a new adoption may not lower either generation, may not
//! re-adopt a calibration that camera already superseded, and history is never erased (every
//! earlier receipt stays in the ledger, linked from its successor). Re-presenting the approval
//! that retained the current adoptions writes nothing.
//!
//! **Currency** ([`adopted_currency`]): `corroborate --calibration` consults the retained receipts.
//! A calibrated camera whose current receipt names this calibration digest and generation is
//! `adopted_current`; a camera with adoptions whose current receipt names another calibration is
//! refused (stale when this calibration or a lower generation was adopted before, unadopted
//! otherwise) before anything is appended; a camera without any adoption keeps the owner-asserted
//! or unasserted behaviour.
//!
//! Non-claim: "observed" currency here means only that the deployment retains the owner's
//! approval-gated adoption. It is owner authority, not a physical measurement: nothing checks that
//! the camera has not moved, zoomed or been relensed since the adoption.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{
    BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    ContentDigest, ContractError, DigestAlgorithm, EvidenceDelta, ObjectId, Plane, SensorCapsule,
    SensorId, TimestampNs,
};
/// Camera identity and generations an adoption binds (fss-geometry), re-exported for callers.
pub use fss_geometry::CameraGeneration;

use super::retained::{RetainedFileImport, RetainedReadLimits};
use super::site_calibration::{SiteCalibration, valid_camera_name};
use crate::reference_deployment::{FAMILY_SENSOR_CAPSULE, FAMILY_TWIN_LOCALIZATION_RECEIPT};
use crate::{ReferenceDeployment, ReferenceError, ReplayCx};

/// Canonical adoption receipt domain (also tags the record bytes).
pub const ADOPTION_RECEIPT_DOMAIN: &str = "fss.twin_localization_receipt.v1";
/// Exact adoption approval domain (calibration, bindings and each camera's current adoption).
pub const ADOPTION_APPROVAL_DOMAIN: &str = "fss.calibration_adoption_approval.v1";
/// Maximum canonical receipt bytes.
pub const MAX_ADOPTION_RECEIPT_BYTES: usize = 4_096;
/// Maximum cameras adopted by one approval (the calibration camera ceiling).
pub const MAX_ADOPTION_CAMERAS: usize = 16;
/// Largest sensor-capsule count read while verifying that a bound sensor is retained.
pub const MAX_SENSOR_CAPSULE_READS: usize = 65_536;
/// Stable claim of every adoption: owner authority, not a physical observation.
pub const ADOPTION_CLAIM: &str = "owner_adoption_not_a_physical_observation";

const RECEIPT_MAGIC: &[u8] = b"FSSTLR01";
const RECEIPT_VERSION: u32 = 1;
const OBJECT_PREFIX: &str = "object:twin-localization:camera-";

fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// Typed refusal of an adoption or of an adoption-currency check.
#[derive(Debug)]
pub enum AdoptionError {
    /// The request is outside its contract (no binding, duplicate camera or sensor, a camera the
    /// calibration does not name, a zero generation, too many cameras).
    InvalidInput(String),
    /// No readable retained sensor capsule names the bound sensor.
    SensorUnretained(SensorId),
    /// The camera is already bound to another sensor, or the sensor to another camera handle.
    SensorConflict {
        /// Camera handle of the request.
        camera_handle: u64,
        /// Sensor of the request.
        sensor: SensorId,
        /// Why.
        reason: &'static str,
    },
    /// The adoption would lower a generation or re-adopt a calibration the camera superseded.
    Regression {
        /// Camera handle.
        camera_handle: u64,
        /// Why.
        reason: &'static str,
    },
    /// The approval matches neither this adoption over the current retained state nor the
    /// approval that retained the current adoptions.
    StaleApproval(ContentDigest),
    /// `corroborate`: the calibration (or a lower generation) was adopted for this camera and
    /// has been superseded by a later adoption.
    Stale {
        /// Owner camera name.
        camera: String,
        /// Current adoption receipt of the camera.
        current_receipt: ContentDigest,
        /// Calibration digest the current receipt names.
        current_calibration: ContentDigest,
        /// Generations the current receipt names.
        current_generation: (u64, u64),
    },
    /// `corroborate`: the camera has retained adoptions, none of which names this calibration.
    Unadopted {
        /// Owner camera name.
        camera: String,
        /// Current adoption receipt of the camera.
        current_receipt: ContentDigest,
        /// Calibration digest the current receipt names.
        current_calibration: ContentDigest,
    },
    /// `corroborate`: the recording's sensor is not the sensor the camera's adoption binds.
    SensorMismatch {
        /// Owner camera name.
        camera: String,
        /// Sensor the adoption binds.
        adopted: SensorId,
        /// Sensor of the recording.
        recorded: SensorId,
    },
    /// A retained receipt, chain or capsule does not match its authority.
    InvalidRecord(&'static str),
    /// Shared contract validation failed.
    Contract(ContractError),
    /// Spool or ledger refusal.
    Reference(Box<ReferenceError>),
    /// The recording could not be opened to read its sensor.
    Recording(String),
    /// Owner cancellation was observed before any write.
    Cancelled,
}

impl AdoptionError {
    /// Registered stable identity (`registries/ERRORS.md`).
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "ERR-CALIBRATION-ADOPTION-INPUT-001",
            Self::SensorUnretained(_) => "ERR-CALIBRATION-ADOPTION-SENSOR-UNRETAINED-001",
            Self::SensorConflict { .. } => "ERR-CALIBRATION-ADOPTION-SENSOR-CONFLICT-001",
            Self::Regression { .. } => "ERR-CALIBRATION-ADOPTION-REGRESSION-001",
            Self::StaleApproval(_) => "ERR-CALIBRATION-ADOPTION-APPROVAL-STALE-001",
            Self::Stale { .. } => "ERR-CALIBRATION-ADOPTION-STALE-001",
            Self::Unadopted { .. } => "ERR-CALIBRATION-ADOPTION-UNADOPTED-001",
            Self::SensorMismatch { .. } => "ERR-CALIBRATION-ADOPTION-SENSOR-MISMATCH-001",
            Self::InvalidRecord(_)
            | Self::Contract(_)
            | Self::Reference(_)
            | Self::Recording(_)
            | Self::Cancelled => "ERR-CALIBRATION-ADOPTION-001",
        }
    }
}

impl fmt::Display for AdoptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(why) => write!(f, "invalid calibration adoption: {why}"),
            Self::SensorUnretained(sensor) => write!(
                f,
                "no readable retained sensor capsule names sensor {sensor}; a camera is bound \
                 only to a sensor with retained evidence"
            ),
            Self::SensorConflict {
                camera_handle,
                sensor,
                reason,
            } => write!(
                f,
                "camera {camera_handle} cannot be bound to sensor {sensor}: {reason}"
            ),
            Self::Regression {
                camera_handle,
                reason,
            } => write!(f, "camera {camera_handle} adoption refused: {reason}"),
            Self::StaleApproval(digest) => write!(
                f,
                "calibration adoption approval {digest} matches neither this adoption over the \
                 cameras' current retained adoptions nor the approval that retained them"
            ),
            Self::Stale {
                camera,
                current_receipt,
                current_calibration,
                current_generation,
            } => write!(
                f,
                "camera {camera}: the calibration is stale; it was superseded by adoption \
                 receipt {current_receipt} of calibration {current_calibration} at intrinsics \
                 generation {} extrinsics generation {} (retained owner adoption, not a physical \
                 observation)",
                current_generation.0, current_generation.1
            ),
            Self::Unadopted {
                camera,
                current_receipt,
                current_calibration,
            } => write!(
                f,
                "camera {camera}: the deployment's current adoption (receipt {current_receipt}) \
                 is calibration {current_calibration}; this calibration was never adopted for \
                 the camera; adopt it first"
            ),
            Self::SensorMismatch {
                camera,
                adopted,
                recorded,
            } => write!(
                f,
                "camera {camera}: the adoption binds sensor {adopted}, but the recording comes \
                 from sensor {recorded}"
            ),
            Self::InvalidRecord(why) => write!(f, "retained calibration adoption mismatch: {why}"),
            Self::Contract(error) => write!(f, "calibration adoption contract: {error}"),
            Self::Reference(error) => write!(f, "calibration adoption retention: {error}"),
            Self::Recording(why) => write!(f, "calibration adoption recording: {why}"),
            Self::Cancelled => f.write_str("calibration adoption cancelled"),
        }
    }
}

impl std::error::Error for AdoptionError {}

impl From<ContractError> for AdoptionError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<ReferenceError> for AdoptionError {
    fn from(error: ReferenceError) -> Self {
        Self::Reference(Box::new(error))
    }
}

/// One retained adoption of one camera.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdoptionReceipt {
    /// Per-camera adoption generation (1 for the first adoption; the ledger generation).
    pub adoption: u64,
    /// Property-local camera handle (`CameraGeneration::camera`).
    pub camera_handle: u64,
    /// Owner camera name in the calibration.
    pub camera_name: String,
    /// Retained sensor the camera is the physical source of.
    pub sensor_id: SensorId,
    /// Identity of the adopted calibration (`fss.site_calibration.v1`/`v2`).
    pub calibration_digest: ContentDigest,
    /// Twin package of the calibration (its world frame).
    pub twin_package: ContentDigest,
    /// Adopted intrinsics generation.
    pub intrinsics_generation: u64,
    /// Adopted extrinsics generation.
    pub extrinsics_generation: u64,
    /// Receipt of the camera's previous adoption (`None` exactly when `adoption == 1`).
    pub supersedes: Option<ContentDigest>,
}

fn sha256_only(digest: ContentDigest) -> Result<ContentDigest, ContractError> {
    if digest.algorithm() == DigestAlgorithm::Sha256 {
        Ok(digest)
    } else {
        Err(ContractError::UnsupportedDigestAlgorithm)
    }
}

impl AdoptionReceipt {
    /// Contract: nonzero handle, generations and adoption; a valid camera name; SHA-256
    /// digests; a supersedes link exactly after the first adoption.
    pub fn validate(&self) -> Result<(), AdoptionError> {
        if self.adoption == 0
            || self.camera_handle == 0
            || self.intrinsics_generation == 0
            || self.extrinsics_generation == 0
        {
            return Err(AdoptionError::InvalidRecord(
                "handle, generations and adoption are nonzero",
            ));
        }
        if !valid_camera_name(&self.camera_name) {
            return Err(AdoptionError::InvalidRecord("invalid camera name"));
        }
        sha256_only(self.calibration_digest)?;
        sha256_only(self.twin_package)?;
        if let Some(prior) = self.supersedes {
            sha256_only(prior)?;
        }
        if (self.adoption == 1) != self.supersedes.is_none() {
            return Err(AdoptionError::InvalidRecord(
                "a receipt supersedes its predecessor exactly after the first adoption",
            ));
        }
        Ok(())
    }

    /// Exact canonical receipt bytes (the retained payload).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.bytes(RECEIPT_MAGIC);
        e.u32(RECEIPT_VERSION);
        e.text(ADOPTION_RECEIPT_DOMAIN);
        e.u64(self.adoption);
        e.u64(self.camera_handle);
        e.text(&self.camera_name);
        self.sensor_id.encode_canonical(&mut e);
        e.digest(self.calibration_digest);
        e.digest(self.twin_package);
        e.u64(self.intrinsics_generation);
        e.u64(self.extrinsics_generation);
        match self.supersedes {
            None => e.u8(0),
            Some(prior) => {
                e.u8(1);
                e.digest(prior);
            }
        }
        e.finish()
    }

    /// Receipt identity: SHA-256 of [`Self::to_bytes`] (magic and domain included).
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }

    /// Decodes exact retained bytes against their authority digest; noncanonical input fails.
    pub fn from_bytes(bytes: &[u8], expected: ContentDigest) -> Result<Self, AdoptionError> {
        let invalid = |_| AdoptionError::InvalidRecord("malformed adoption receipt");
        if bytes.len() > MAX_ADOPTION_RECEIPT_BYTES || ContentDigest::sha256(bytes) != expected {
            return Err(AdoptionError::InvalidRecord(
                "receipt bytes differ from their authority digest",
            ));
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes().map_err(invalid)? != RECEIPT_MAGIC
            || d.u32().map_err(invalid)? != RECEIPT_VERSION
            || d.text().map_err(invalid)? != ADOPTION_RECEIPT_DOMAIN
        {
            return Err(AdoptionError::InvalidRecord("not an adoption receipt"));
        }
        let adoption = d.u64().map_err(invalid)?;
        let camera_handle = d.u64().map_err(invalid)?;
        let camera_name = d.text().map_err(invalid)?.to_owned();
        let sensor_id = SensorId::decode_canonical(&mut d).map_err(invalid)?;
        let calibration_digest = d.digest().map_err(invalid)?;
        let twin_package = d.digest().map_err(invalid)?;
        let intrinsics_generation = d.u64().map_err(invalid)?;
        let extrinsics_generation = d.u64().map_err(invalid)?;
        let supersedes = match d.u8().map_err(invalid)? {
            0 => None,
            1 => Some(d.digest().map_err(invalid)?),
            _ => return Err(AdoptionError::InvalidRecord("unknown supersedes tag")),
        };
        d.ensure_finished().map_err(invalid)?;
        let receipt = Self {
            adoption,
            camera_handle,
            camera_name,
            sensor_id,
            calibration_digest,
            twin_package,
            intrinsics_generation,
            extrinsics_generation,
            supersedes,
        };
        receipt.validate()?;
        if receipt.to_bytes() != bytes {
            return Err(AdoptionError::InvalidRecord(
                "noncanonical adoption receipt",
            ));
        }
        Ok(receipt)
    }

    /// Adopted `(intrinsics, extrinsics)` generations.
    #[must_use]
    pub fn generation(&self) -> (u64, u64) {
        (self.intrinsics_generation, self.extrinsics_generation)
    }

    /// Typed JSON object of the receipt.
    #[must_use]
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\"receipt_digest\":\"{}\",\"adoption\":{},\"camera_handle\":{},",
                "\"camera_name\":\"{}\",\"sensor_id\":\"{}\",\"calibration_digest\":\"{}\",",
                "\"twin_package\":\"{}\",\"intrinsics_generation\":{},",
                "\"extrinsics_generation\":{},\"supersedes\":{},\"claim\":\"{}\"}}"
            ),
            self.digest(),
            self.adoption,
            self.camera_handle,
            self.camera_name,
            self.sensor_id,
            self.calibration_digest,
            self.twin_package,
            self.intrinsics_generation,
            self.extrinsics_generation,
            self.supersedes
                .map_or_else(|| "null".to_owned(), |d| format!("\"{d}\"")),
            ADOPTION_CLAIM,
        )
    }
}

/// One adoption as retained in the ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedAdoption {
    /// Decoded, validated receipt.
    pub receipt: AdoptionReceipt,
    /// Payload digest (= receipt digest).
    pub digest: ContentDigest,
    /// Commit sequence of the batch that retained it.
    pub committed_sequence: u64,
}

/// Ledger object of one camera's adoptions.
pub fn adoption_object_id(camera_handle: u64) -> Result<ObjectId, ContractError> {
    ObjectId::parse(format!("{OBJECT_PREFIX}{camera_handle}"))
}

/// Every retained adoption of every camera, by camera handle, each history in adoption order and
/// verified: contiguous generations from 1, each receipt decoding against its payload digest,
/// naming its object's handle, superseding exactly its predecessor, keeping the sensor, and never
/// lowering a generation. Damaged custody fails closed; it is never treated as "not adopted".
pub fn retained_adoptions(
    deployment: &ReferenceDeployment,
) -> Result<BTreeMap<u64, Vec<RetainedAdoption>>, AdoptionError> {
    // Per camera handle: (new generation, prior generation, payload, commit sequence).
    type Row = (u64, Option<u64>, ContentDigest, u64);
    let mut deltas: BTreeMap<u64, Vec<Row>> = BTreeMap::new();
    for batch in deployment.ledger().batches() {
        for delta in &batch.deltas {
            if delta.family != FAMILY_TWIN_LOCALIZATION_RECEIPT {
                continue;
            }
            let handle = delta
                .object_id
                .as_str()
                .strip_prefix(OBJECT_PREFIX)
                .and_then(|text| text.parse::<u64>().ok())
                .filter(|handle| {
                    adoption_object_id(*handle).ok().as_ref() == Some(&delta.object_id)
                })
                .ok_or(AdoptionError::InvalidRecord("adoption object id"))?;
            if delta.plane != Plane::Authority {
                return Err(AdoptionError::InvalidRecord(
                    "adoption outside authority plane",
                ));
            }
            deltas.entry(handle).or_default().push((
                delta.new_generation,
                delta.prior_generation,
                delta.payload_digest,
                batch.new_anchor.commit_sequence,
            ));
        }
    }
    let spool = deployment.publisher().spool();
    let mut out = BTreeMap::new();
    for (handle, mut generations) in deltas {
        generations.sort_unstable();
        let mut history: Vec<RetainedAdoption> = Vec::with_capacity(generations.len());
        for (index, (generation, prior, digest, committed_sequence)) in
            generations.into_iter().enumerate()
        {
            let expected = index as u64 + 1;
            if generation != expected || prior != index.checked_sub(1).map(|p| p as u64 + 1) {
                return Err(AdoptionError::InvalidRecord(
                    "adoption generations not contiguous",
                ));
            }
            let bytes = spool
                .read(digest)
                .map_err(|_| AdoptionError::InvalidRecord("adoption receipt unreadable"))?;
            let receipt = AdoptionReceipt::from_bytes(&bytes, digest)?;
            let previous = history.last();
            if receipt.adoption != generation
                || receipt.camera_handle != handle
                || receipt.supersedes != previous.map(|p| p.digest)
                || previous.is_some_and(|p| {
                    p.receipt.sensor_id != receipt.sensor_id
                        || receipt.intrinsics_generation < p.receipt.intrinsics_generation
                        || receipt.extrinsics_generation < p.receipt.extrinsics_generation
                })
            {
                return Err(AdoptionError::InvalidRecord("adoption chain mismatch"));
            }
            history.push(RetainedAdoption {
                receipt,
                digest,
                committed_sequence,
            });
        }
        out.insert(handle, history);
    }
    Ok(out)
}

/// The calibration a request adopts: its identity, world frame and cameras.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalibrationSubject {
    /// Calibration identity.
    pub calibration_digest: ContentDigest,
    /// Twin package (world frame).
    pub twin_package: ContentDigest,
    /// Calibrated cameras: owner name and generation.
    pub cameras: Vec<(String, CameraGeneration)>,
}

impl CalibrationSubject {
    /// The subject of a verified calibration and its identity.
    #[must_use]
    pub fn from_calibration(calibration: &SiteCalibration, digest: ContentDigest) -> Self {
        Self {
            calibration_digest: digest,
            twin_package: calibration.twin_package,
            cameras: calibration
                .cameras
                .iter()
                .map(|camera| (camera.name.clone(), camera.identity))
                .collect(),
        }
    }
}

/// Retention state of one camera in an adoption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionStatus {
    /// Previewed only; nothing is retained.
    Proposed,
    /// Retained by this call.
    Retained,
    /// Exactly this calibration, generation and sensor is already the camera's current adoption.
    AlreadyCurrent,
}

impl AdoptionStatus {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Retained => "retained",
            Self::AlreadyCurrent => "already_current",
        }
    }
}

/// One camera of an adoption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CameraAdoption {
    /// The receipt proposed (or retained, or already current).
    pub receipt: AdoptionReceipt,
    /// Its state.
    pub status: AdoptionStatus,
    /// The camera's current adoption before this call (`None`: never adopted).
    pub current: Option<RetainedAdoption>,
    /// The camera's predecessor of `current` (used to recognize the retaining approval).
    predecessor: Option<(u64, ContentDigest)>,
}

/// Outcome of a preview or adoption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Adoption {
    /// Calibration identity.
    pub calibration_digest: ContentDigest,
    /// Exact approval that retains the proposal over the state it was previewed against.
    pub approval: ContentDigest,
    /// Bound cameras in handle order.
    pub cameras: Vec<CameraAdoption>,
}

impl Adoption {
    /// Overall state: `retained` when this call wrote, `already_current` when every camera
    /// already is, otherwise `proposed`.
    #[must_use]
    pub fn status(&self) -> AdoptionStatus {
        if self
            .cameras
            .iter()
            .any(|c| c.status == AdoptionStatus::Retained)
        {
            AdoptionStatus::Retained
        } else if self
            .cameras
            .iter()
            .all(|c| c.status == AdoptionStatus::AlreadyCurrent)
        {
            AdoptionStatus::AlreadyCurrent
        } else {
            AdoptionStatus::Proposed
        }
    }
}

/// One bound camera in an approval: handle, name, sensor, `(intrinsics, extrinsics)` and the
/// camera's current adoption `(generation, receipt)` (`None`: never adopted).
pub type ApprovalEntry<'a> = (
    u64,
    &'a str,
    &'a SensorId,
    (u64, u64),
    Option<(u64, ContentDigest)>,
);

/// Exact approval of adopting `calibration` for `entries` (in handle order) over the current
/// retained state.
#[must_use]
pub fn approval_digest(calibration: ContentDigest, entries: &[ApprovalEntry<'_>]) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(ADOPTION_APPROVAL_DOMAIN);
    e.digest(calibration);
    e.u64(entries.len() as u64);
    for (handle, name, sensor, (intrinsics, extrinsics), current) in entries {
        e.u64(*handle);
        e.text(name);
        sensor.encode_canonical(&mut e);
        e.u64(*intrinsics);
        e.u64(*extrinsics);
        match current {
            None => e.u8(0),
            Some((adoption, receipt)) => {
                e.u8(1);
                e.u64(*adoption);
                e.digest(*receipt);
            }
        }
    }
    ContentDigest::sha256(&e.finish())
}

/// Whether some readable retained sensor capsule names `sensor` (bounded read).
fn sensor_retained(
    deployment: &ReferenceDeployment,
    sensor: &SensorId,
) -> Result<bool, AdoptionError> {
    let spool = deployment.publisher().spool();
    let mut reads = 0_usize;
    for delta in deployment
        .ledger()
        .batches()
        .iter()
        .flat_map(|batch| batch.deltas.iter())
        .filter(|delta| delta.family == FAMILY_SENSOR_CAPSULE)
    {
        reads += 1;
        if reads > MAX_SENSOR_CAPSULE_READS {
            return Err(AdoptionError::InvalidInput(format!(
                "more than {MAX_SENSOR_CAPSULE_READS} sensor capsules; the binding cannot be \
                 verified within the read bound"
            )));
        }
        // A deleted or unreadable capsule is not evidence of the sensor; it is skipped.
        let Ok(bytes) = spool.read(delta.payload_digest) else {
            continue;
        };
        if ContentDigest::sha256(&bytes) != delta.payload_digest {
            continue;
        }
        if SensorCapsule::from_canonical_bytes(&bytes).is_ok_and(|c| c.sensor_id == *sensor) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Previews an adoption of `subject` for the `(camera name, sensor)` bindings: validates every
/// binding and the monotone rule, computes each receipt and the exact approval; writes nothing.
pub fn preview_adoption(
    deployment: &ReferenceDeployment,
    subject: &CalibrationSubject,
    bindings: &[(String, SensorId)],
) -> Result<Adoption, AdoptionError> {
    if bindings.is_empty() || bindings.len() > MAX_ADOPTION_CAMERAS {
        return Err(AdoptionError::InvalidInput(
            "adopt binds 1..16 cameras".to_owned(),
        ));
    }
    sha256_only(subject.calibration_digest)?;
    let mut names = BTreeSet::new();
    let mut sensors = BTreeSet::new();
    for (name, sensor) in bindings {
        if !names.insert(name.as_str()) {
            return Err(AdoptionError::InvalidInput(format!(
                "camera {name} is bound twice"
            )));
        }
        if !sensors.insert(sensor) {
            return Err(AdoptionError::InvalidInput(format!(
                "sensor {sensor} is bound to two cameras"
            )));
        }
    }
    let history = retained_adoptions(deployment)?;
    let mut cameras: Vec<CameraAdoption> = Vec::with_capacity(bindings.len());
    for (name, sensor) in bindings {
        let generation = subject
            .cameras
            .iter()
            .find(|(camera, _)| camera == name)
            .map(|(_, generation)| *generation)
            .ok_or_else(|| {
                AdoptionError::InvalidInput(format!("the calibration names no camera {name}"))
            })?;
        let handle = generation.camera;
        if handle == 0 || generation.intrinsics == 0 || generation.extrinsics == 0 {
            return Err(AdoptionError::InvalidInput(format!(
                "camera {name} has a zero handle or generation"
            )));
        }
        if cameras.iter().any(|c| c.receipt.camera_handle == handle) {
            return Err(AdoptionError::InvalidInput(format!(
                "camera handle {handle} is bound twice"
            )));
        }
        // A sensor stays with the camera handle it was first bound to.
        if history.iter().any(|(other, adoptions)| {
            *other != handle && adoptions.iter().any(|a| a.receipt.sensor_id == *sensor)
        }) {
            return Err(AdoptionError::SensorConflict {
                camera_handle: handle,
                sensor: sensor.clone(),
                reason: "the sensor is bound to another camera handle",
            });
        }
        let past = history.get(&handle).map_or(&[][..], Vec::as_slice);
        let current = past.last().cloned();
        let predecessor = past
            .len()
            .checked_sub(2)
            .map(|index| (past[index].receipt.adoption, past[index].digest));
        let wanted = (generation.intrinsics, generation.extrinsics);
        let status = match &current {
            None => AdoptionStatus::Proposed,
            Some(current) => {
                if current.receipt.sensor_id != *sensor {
                    return Err(AdoptionError::SensorConflict {
                        camera_handle: handle,
                        sensor: sensor.clone(),
                        reason: "the camera is already bound to another sensor",
                    });
                }
                if current.receipt.calibration_digest == subject.calibration_digest
                    && current.receipt.generation() == wanted
                {
                    AdoptionStatus::AlreadyCurrent
                } else {
                    let (intrinsics, extrinsics) = current.receipt.generation();
                    if wanted.0 < intrinsics || wanted.1 < extrinsics {
                        return Err(AdoptionError::Regression {
                            camera_handle: handle,
                            reason: "a generation would be lower than the current adoption's",
                        });
                    }
                    if past
                        .iter()
                        .any(|a| a.receipt.calibration_digest == subject.calibration_digest)
                    {
                        return Err(AdoptionError::Regression {
                            camera_handle: handle,
                            reason: "the camera already superseded this calibration",
                        });
                    }
                    AdoptionStatus::Proposed
                }
            }
        };
        let receipt = match (&current, status) {
            (Some(current), AdoptionStatus::AlreadyCurrent) => current.receipt.clone(),
            _ => AdoptionReceipt {
                adoption: current.as_ref().map_or(1, |c| c.receipt.adoption + 1),
                camera_handle: handle,
                camera_name: name.clone(),
                sensor_id: sensor.clone(),
                calibration_digest: subject.calibration_digest,
                twin_package: subject.twin_package,
                intrinsics_generation: wanted.0,
                extrinsics_generation: wanted.1,
                supersedes: current.as_ref().map(|c| c.digest),
            },
        };
        receipt.validate()?;
        if receipt.to_bytes().len() > MAX_ADOPTION_RECEIPT_BYTES {
            return Err(AdoptionError::InvalidInput(
                "adoption receipt too large".to_owned(),
            ));
        }
        if current.is_none() && !sensor_retained(deployment, sensor)? {
            return Err(AdoptionError::SensorUnretained(sensor.clone()));
        }
        cameras.push(CameraAdoption {
            receipt,
            status,
            current,
            predecessor,
        });
    }
    cameras.sort_by_key(|c| c.receipt.camera_handle);
    let entries: Vec<ApprovalEntry<'_>> = cameras
        .iter()
        .map(|c| {
            (
                c.receipt.camera_handle,
                c.receipt.camera_name.as_str(),
                &c.receipt.sensor_id,
                c.receipt.generation(),
                c.current.as_ref().map(|a| (a.receipt.adoption, a.digest)),
            )
        })
        .collect();
    Ok(Adoption {
        calibration_digest: subject.calibration_digest,
        approval: approval_digest(subject.calibration_digest, &entries),
        cameras,
    })
}

/// Retains the previewed adoption when `approval` is its exact approval over the current retained
/// state; checked before any write. When every camera is already current, the fresh approval or
/// the approval that retained the current adoptions is accepted and nothing is written.
pub fn adopt(
    deployment: &mut ReferenceDeployment,
    subject: &CalibrationSubject,
    bindings: &[(String, SensorId)],
    approval: ContentDigest,
    cx: &ReplayCx,
) -> Result<Adoption, AdoptionError> {
    let preview = preview_adoption(deployment, subject, bindings)?;
    if preview.status() == AdoptionStatus::AlreadyCurrent {
        // The approval that retained the current adoptions was computed over their predecessors.
        let entries: Vec<ApprovalEntry<'_>> = preview
            .cameras
            .iter()
            .map(|c| {
                (
                    c.receipt.camera_handle,
                    c.receipt.camera_name.as_str(),
                    &c.receipt.sensor_id,
                    c.receipt.generation(),
                    c.predecessor,
                )
            })
            .collect();
        let original = approval_digest(subject.calibration_digest, &entries);
        if approval != preview.approval && approval != original {
            return Err(AdoptionError::StaleApproval(approval));
        }
        return Ok(preview);
    }
    if approval != preview.approval {
        return Err(AdoptionError::StaleApproval(approval));
    }
    cx.checkpoint("calibration_adoption:adopt")
        .map_err(|_| AdoptionError::Cancelled)?;
    let validity = CaptureInterval::new(TimestampNs(0), TimestampNs(i128::from(i64::MAX)))?;
    let mut deltas = Vec::new();
    let mut children = Vec::new();
    for camera in &preview.cameras {
        if camera.status != AdoptionStatus::Proposed {
            continue;
        }
        let payload = deployment.stage_payload(&camera.receipt.to_bytes())?;
        if payload != camera.receipt.digest() {
            return Err(AdoptionError::InvalidRecord("staged receipt digest"));
        }
        deltas.push(EvidenceDelta {
            delta_id: format!(
                "delta:calibration-adoption:{}:{}",
                hex(approval),
                camera.receipt.camera_handle
            ),
            family: FAMILY_TWIN_LOCALIZATION_RECEIPT.to_owned(),
            object_id: adoption_object_id(camera.receipt.camera_handle)?,
            prior_generation: camera.current.as_ref().map(|c| c.receipt.adoption),
            new_generation: camera.receipt.adoption,
            validity,
            plane: Plane::Authority,
            payload_digest: payload,
            witness_digest: None,
            operation_id: None,
        });
        children.push(payload);
    }
    let batch = BatchId::parse(format!("batch:calibration-adoption:{}", hex(approval)))?;
    deployment.append_batch(batch, deltas, children, cx)?;
    cx.checkpoint_post_commit("calibration_adoption:retained");
    Ok(Adoption {
        cameras: preview
            .cameras
            .into_iter()
            .map(|camera| CameraAdoption {
                status: if camera.status == AdoptionStatus::Proposed {
                    AdoptionStatus::Retained
                } else {
                    camera.status
                },
                ..camera
            })
            .collect(),
        ..preview
    })
}

/// Sensor of a retained recording (its first segment's source capsule).
pub fn recording_sensor(
    deployment: &ReferenceDeployment,
    import_identity: ContentDigest,
    limits: RetainedReadLimits,
    cx: &ReplayCx,
) -> Result<SensorId, AdoptionError> {
    let retained = RetainedFileImport::open(deployment, import_identity, limits, cx)
        .map_err(|error| AdoptionError::Recording(error.to_string()))?;
    let (capsule, _) = super::recorded_decode::source_capsule(deployment, &retained, 0)
        .map_err(|error| AdoptionError::Recording(error.to_string()))?;
    Ok(capsule.sensor_id)
}

/// Adoption currency of one calibrated camera for `corroborate --calibration`.
///
/// `Ok(None)`: the camera handle has no retained adoption (existing owner-asserted or unasserted
/// behaviour). `Ok(Some(current))`: the current adoption names exactly this calibration digest
/// and generation, and `recorded_sensor` (the sensor of the recording, read lazily and only when
/// the camera has an adoption) is the adopted sensor: the camera is `adopted_current`. Otherwise a
/// typed refusal: [`AdoptionError::Stale`] when the calibration or a generation not above this
/// one was adopted and later superseded, [`AdoptionError::Unadopted`] when the camera's adoptions
/// never named it, [`AdoptionError::SensorMismatch`] when the recording is another sensor's.
pub fn adopted_currency(
    adoptions: &BTreeMap<u64, Vec<RetainedAdoption>>,
    calibration_digest: ContentDigest,
    camera: &str,
    generation: CameraGeneration,
    recorded_sensor: impl FnOnce() -> Result<SensorId, AdoptionError>,
) -> Result<Option<RetainedAdoption>, AdoptionError> {
    let Some(history) = adoptions.get(&generation.camera) else {
        return Ok(None);
    };
    let Some(current) = history.last() else {
        return Ok(None);
    };
    let wanted = (generation.intrinsics, generation.extrinsics);
    if current.receipt.calibration_digest != calibration_digest
        || current.receipt.generation() != wanted
    {
        let (intrinsics, extrinsics) = current.receipt.generation();
        let superseded = history
            .iter()
            .any(|a| a.receipt.calibration_digest == calibration_digest)
            || (wanted.0 <= intrinsics && wanted.1 <= extrinsics);
        return Err(if superseded {
            AdoptionError::Stale {
                camera: camera.to_owned(),
                current_receipt: current.digest,
                current_calibration: current.receipt.calibration_digest,
                current_generation: current.receipt.generation(),
            }
        } else {
            AdoptionError::Unadopted {
                camera: camera.to_owned(),
                current_receipt: current.digest,
                current_calibration: current.receipt.calibration_digest,
            }
        });
    }
    let recorded = recorded_sensor()?;
    if recorded != current.receipt.sensor_id {
        return Err(AdoptionError::SensorMismatch {
            camera: camera.to_owned(),
            adopted: current.receipt.sensor_id.clone(),
            recorded,
        });
    }
    Ok(Some(current.clone()))
}

/// `fss.calibration_adoption_state.v1`: every adopted camera's current receipt and full history.
pub fn state_json(deployment: &ReferenceDeployment) -> Result<String, AdoptionError> {
    let adoptions = retained_adoptions(deployment)?;
    let cameras: Vec<String> = adoptions
        .iter()
        .filter_map(|(handle, history)| {
            let current = history.last()?;
            let past: Vec<String> = history
                .iter()
                .map(|a| {
                    let body = a.receipt.to_json();
                    let body = body.strip_suffix('}').unwrap_or(&body);
                    format!("{body},\"committed_sequence\":{}}}", a.committed_sequence)
                })
                .collect();
            Some(format!(
                "{{\"camera_handle\":{handle},\"current\":{},\"history\":[{}]}}",
                current.receipt.to_json(),
                past.join(",")
            ))
        })
        .collect();
    Ok(format!(
        concat!(
            "{{\"format\":\"fss.calibration_adoption_state.v1\",\"cameras\":[{}],",
            "\"claim\":\"{}\",\"authority_sequence\":{}}}"
        ),
        cameras.join(","),
        ADOPTION_CLAIM,
        deployment.current_anchor().commit_sequence
    ))
}

#[cfg(test)]
mod tests;
