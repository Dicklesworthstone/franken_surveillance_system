#![forbid(unsafe_code)]
//! Two-sensor corroborated zone entries from two retained recordings.
//!
//! One composition over existing pieces, no trained model: each recording runs the model-free
//! [`super::recorded_watch`] pipeline (retained decode → foreground → Kalman tracker) over the whole
//! decoded frame; each confirmed track's foot point (bottom centre of the filtered box) is projected
//! through an owner-supplied image→ground homography; ground-zone entries of the two sensors are
//! associated with the global [`super::cross_camera`] assignment under explicit time and distance
//! gates; an associated pair becomes one event revision through the zone-entry policy
//! ([`crate::evaluate_zone_entry_corroboration`]), which marks it `Corroborated` only because the
//! two supporting witnesses come from distinct sensors, capture roots and failure domains.
//!
//! The homography is an owner assertion like a zone, NOT a calibration certificate: no residual,
//! intrinsics or extrinsics are verified. Capture times are the operator's import hints
//! (`capture_time_label == "operator_assumption"`); an import with unknown capture time, or two
//! imports whose capture spans do not overlap, is refused rather than aligned by assumption. The
//! time gate is applied to the worst case over both conservative capture intervals, never to a
//! point estimate alone.
//!
//! Analysis is read-only and deterministic. Publication follows the recorded-watch authority
//! model: a candidate becomes an event only when the operator presents its exact proposal digest;
//! provenance is retained root-last and the deployment's guarded event publisher records the
//! policy decision. A `PrepareAlert` affordance is reported, never acted on: preparing or
//! dispatching an alert is a separate, separately approved effect. Synthetic scenes prove wiring,
//! not detection quality; no candidate never certifies absence by itself.
//!
//! With [`CorroborationReport::analyze_with_detector`] a verified detector package runs as a
//! cascade stage ([`super::detector_cascade`]) on each ground entry's selected frames, within one
//! explicit inference budget shared by both recordings. Its class evidence is retained in the
//! candidate's provenance (bound into the association identity and proposal digest) but is NOT an
//! edge of the policy's event: the zone-entry policy decision, the `Corroborated` state (which
//! rests only on the two sensors' own witnesses) and the `PrepareAlert` affordance are provably
//! independent of any detector score. Scores are uncalibrated; the kind stays `Unclassified`.
//!
//! Each camera also proposes a coverage record ([`super::recorded_coverage`]) over the ground
//! zones it can geometrically see (below): one witness per
//! contiguous observable interval of that sensor, every ground-zone entry of that sensor an
//! explicit interval naming its corroborated event when one exists. Both records are retained
//! together only with their exact approval digest ([`CorroborationReport::retain_coverage`]).
//!
//! Ground-zone coverage is geometric (fss-2h5zq.53, [`super::ground_visibility`]): each zone is
//! sampled on the ground plane and every sample projected into the camera (through the owner
//! homography, or an owner calibrated pose when one is supplied); with an owner scene mesh and a
//! pose, samples hidden by opaque geometry are occluded. The record carries the visible fraction,
//! the sampling policy and the occlusion model; a zone below the registered threshold is
//! `occluded` or `outside_frustum` for coverage, and without a mesh every witness says it is
//! frustum-only (`occlusion_unknown`). The threshold, the sample grid, the pose and the mesh
//! digest are bound into the pipeline generation ([`CorroborationReport::analyze_with_visibility`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{
    CanonicalEncoder, CaptureInterval, ContentDigest, ContractError, EventHypothesis, EventId,
    ObjectId,
};
use fss_geometry::WorkBudget;
use fss_object::{ObjectError, ObjectManifest};
use fss_publication::{LocalPublicationError, SlotName};

use super::cross_camera::{
    AssociationDisposition, AssociationScore, CameraObservation, CrossCameraConfig,
    CrossCameraError, associate_detailed,
};
use super::detector_cascade::{
    CascadeBudget, CascadeOutcome, CascadeSource, CascadeTrack, ClassEvidence, DetectorCascade,
    cascade_outcome_json, cascade_policy_json, class_evidence_json, select_frames,
};
use super::ground_visibility::{
    CameraPose, SceneMesh, VisibilityCamera, VisibilityError, VisibilityPolicy, assess_ground_zone,
    bind_visibility_parameters, pose_matches_homography, rectangle,
};
use super::privacy_mask::MaskBinding;
use super::privacy_mask::coverage::{ground_zone_masked, mask_coverage_zones};
use super::recorded_coverage::{
    CoverageEntry, CoverageError, CoverageExtras, CoverageFrame, CoverageInput, CoverageRecord,
    CoverageSource, CoverageStatus, CoverageZoneInput, approval_digest, build_coverage_with,
    check_approval, coverage_status, pipeline_generation, retain_coverage,
};
use super::recorded_decode::{ComponentInterpretation, RecordedDecodeError, source_capsule};
use super::recorded_watch::{
    MAX_WATCH_FRAMES, WatchDetectorConfig, WatchError, WatchLimits, WatchPlan, WatchReport,
    WatchTrackerConfig, WatchZone, bind_cascade_parameters, media_decoder_label,
    pipeline_parameters,
};
use super::{FileIngestError, RetainedFileImport};
use crate::{
    ReferenceDeployment, ReferenceError, ReferencePolicyAction, ReferencePolicyDecision, ReplayCx,
    ZoneEntryCorroboration, ZoneEntryWitness, evaluate_zone_entry_corroboration,
};

/// Maximum owner-drawn ground zones.
pub const MAX_CORROBORATION_ZONES: usize = 16;
/// Maximum corroborated candidates in one report; more is a typed refusal, never a silent drop.
pub const MAX_CORROBORATION_CANDIDATES: usize = 32;
/// Maximum time gate (60 s).
pub const MAX_TIME_GATE_NS: u64 = 60_000_000_000;
/// Boundary after provenance retention, before event authority.
pub const STAGE_RECORDED_CORROBORATION_COMMIT: &str = "recorded_corroboration:commit";

const POLICY: &[u8] = b"fss.recorded_corroboration_policy.v1:two-sensors:model-free-watch:\
whole-frame-tracking:foot-point:owner-ground-homography-not-calibration:ground-zone-entry:\
global-assignment:worst-case-interval-time-gate:distance-gate:operator-time-hints:unclassified";
const PLAN_DOMAIN: &str = "fss.recorded_corroboration_plan.v1";
const OBSERVATION_DOMAIN: &str = "fss.recorded_corroboration_observation.v1";
const ASSOCIATION_DOMAIN: &str = "fss.recorded_corroboration_association.v1";
const PROPOSAL_DOMAIN: &str = "fss.recorded_corroboration_proposal.v1";
/// Tracking runs over the whole decoded frame; zones are on the ground plane.
const TRACKING_ZONE: &str = "whole-frame";
const OPERATOR_TIME_LABEL: &str = "operator_assumption";
const UNCERTAINTY: &str = "Two recording sensors' model-free foreground tracks, projected through \
owner-supplied uncalibrated ground homographies, entered one ground zone within explicit gates; \
capture times are operator hints. Not classified, identified or calibrated.";
const ASSOCIATION_WORK: u64 = 100_000_000;

/// Typed refusal of planning, analysis, or publication.
#[derive(Debug)]
pub enum CorroborationError {
    /// The plan is outside its bounds (cameras, zones, gates, thresholds).
    InvalidPlan(&'static str),
    /// A camera's owner-supplied homography is non-finite, singular, or maps an observed image
    /// point to or beyond the horizon.
    InvalidHomography {
        /// Camera name from the plan.
        camera: String,
        /// Why the homography is refused.
        reason: &'static str,
    },
    /// Both recordings come from the same sensor: one failure domain can never corroborate itself.
    SameSensor,
    /// A recording has no operator capture-time hint; its capture time is unknown.
    TimeUnknown {
        /// Camera name from the plan.
        camera: String,
    },
    /// The two recordings' capture spans do not overlap: their clocks are unaligned or they cover
    /// different periods. Nothing is assumed.
    TimeUnaligned,
    /// An approval digest matches no candidate proposal of this exact analysis.
    StaleApproval(ContentDigest),
    /// An event with this candidate identity exists with different content.
    Conflict,
    /// A hard candidate or record bound was reached.
    Limit,
    /// Per-camera watch pipeline refusal.
    Watch(Box<WatchError>),
    /// Cross-camera association refusal.
    Association(CrossCameraError),
    /// Retained source or decode refusal.
    Decode(Box<RecordedDecodeError>),
    /// Guarded deployment publication or policy refusal.
    Reference(Box<ReferenceError>),
    /// Shared canonical validation failed.
    Contract(ContractError),
    /// Object graph construction failed.
    Object(ObjectError),
    /// Root-last publication failed.
    Publication(Box<LocalPublicationError>),
    /// Coverage retention refusal (stale approval or storage).
    Coverage(CoverageError),
    /// An owner calibrated pose is invalid for its camera: its intrinsics describe another image
    /// size, or it disagrees with the camera's ground homography.
    InvalidPose {
        /// Camera name from the plan.
        camera: String,
        /// Why the pose is refused.
        reason: &'static str,
    },
    /// Geometric visibility could not be assessed (invalid policy or zone, degenerate or
    /// over-budget scene-mesh query).
    Visibility(VisibilityError),
}

impl CorroborationError {
    /// Registered stable identity (registries/ERRORS.md) of this refusal.
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::InvalidPlan(_) => "ERR-CORROBORATE-PLAN-INVALID-001",
            Self::InvalidHomography { .. } => "ERR-CORROBORATE-HOMOGRAPHY-INVALID-001",
            Self::SameSensor => "ERR-CORROBORATE-SAME-SENSOR-001",
            Self::TimeUnknown { .. } => "ERR-CORROBORATE-TIME-UNKNOWN-001",
            Self::TimeUnaligned => "ERR-CORROBORATE-TIME-UNALIGNED-001",
            Self::StaleApproval(_) => "ERR-CORROBORATE-APPROVAL-STALE-001",
            Self::Conflict => "ERR-IDEMPOTENCY-CONFLICT-001",
            Self::Watch(error) => error.stable_id(),
            Self::Decode(error) => error.stable_id(),
            Self::Coverage(error) => error.stable_id(),
            Self::InvalidPose { .. } => "ERR-CORROBORATE-POSE-INVALID-001",
            Self::Visibility(_) => "ERR-CORROBORATE-VISIBILITY-001",
            _ => "ERR-CORROBORATE-001",
        }
    }
}

impl fmt::Display for CorroborationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPlan(why) => write!(f, "invalid corroboration plan: {why}"),
            Self::InvalidHomography { camera, reason } => {
                write!(f, "ground homography of camera {camera} refused: {reason}")
            }
            Self::SameSensor => f.write_str(
                "both recordings come from one sensor; one failure domain cannot corroborate itself",
            ),
            Self::TimeUnknown { camera } => write!(
                f,
                "recording of camera {camera} has unknown capture time (import it with capture hints)"
            ),
            Self::TimeUnaligned => f.write_str(
                "the recordings' capture spans do not overlap; clocks unaligned or different periods",
            ),
            Self::StaleApproval(digest) => {
                write!(f, "approval {digest} matches no proposal of this exact analysis")
            }
            Self::Conflict => {
                f.write_str("a different event already holds this candidate identity")
            }
            Self::Limit => f.write_str("corroboration bound exceeded"),
            Self::Watch(e) => write!(f, "corroboration tracking: {e}"),
            Self::Association(e) => write!(f, "corroboration association: {e}"),
            Self::Decode(e) => write!(f, "corroboration source: {e}"),
            Self::Reference(e) => write!(f, "corroboration deployment: {e}"),
            Self::Contract(e) => write!(f, "corroboration contract: {e}"),
            Self::Object(e) => write!(f, "corroboration manifest: {e}"),
            Self::Publication(e) => write!(f, "corroboration publication: {e}"),
            Self::Coverage(e) => write!(f, "corroboration coverage: {e}"),
            Self::InvalidPose { camera, reason } => {
                write!(f, "calibrated pose of camera {camera} refused: {reason}")
            }
            Self::Visibility(e) => write!(f, "corroboration ground visibility: {e}"),
        }
    }
}
impl std::error::Error for CorroborationError {}

impl From<WatchError> for CorroborationError {
    fn from(error: WatchError) -> Self {
        Self::Watch(Box::new(error))
    }
}
impl From<CrossCameraError> for CorroborationError {
    fn from(error: CrossCameraError) -> Self {
        Self::Association(error)
    }
}
impl From<RecordedDecodeError> for CorroborationError {
    fn from(error: RecordedDecodeError) -> Self {
        Self::Decode(Box::new(error))
    }
}
impl From<FileIngestError> for CorroborationError {
    fn from(error: FileIngestError) -> Self {
        Self::Decode(Box::new(error.into()))
    }
}
impl From<ReferenceError> for CorroborationError {
    fn from(error: ReferenceError) -> Self {
        Self::Reference(Box::new(error))
    }
}
impl From<ContractError> for CorroborationError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}
impl From<CoverageError> for CorroborationError {
    fn from(error: CoverageError) -> Self {
        Self::Coverage(error)
    }
}
impl From<VisibilityError> for CorroborationError {
    fn from(error: VisibilityError) -> Self {
        Self::Visibility(error)
    }
}
impl From<ObjectError> for CorroborationError {
    fn from(error: ObjectError) -> Self {
        Self::Object(error)
    }
}
impl From<LocalPublicationError> for CorroborationError {
    fn from(error: LocalPublicationError) -> Self {
        Self::Publication(Box::new(error))
    }
}
impl From<fss_object::SpoolError> for CorroborationError {
    fn from(error: fss_object::SpoolError) -> Self {
        Self::Publication(Box::new(LocalPublicationError::Spool(error)))
    }
}
type Result<T> = std::result::Result<T, CorroborationError>;

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage)
        .map_err(|_| RecordedDecodeError::Cancelled.into())
}
fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}
fn valid_name(name: &str, maximum: usize) -> bool {
    !name.is_empty()
        && name.len() <= maximum
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Owner-supplied planar map from decoded image pixels `(u, v, 1)` to ground-plane coordinates
/// `(x, y, w)`, row-major `h11..h33`. It is an owner assertion like a zone, not a calibration
/// certificate: nothing about lens distortion, residuals or camera pose is verified.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GroundHomography {
    /// Row-major 3x3 matrix.
    pub matrix: [f64; 9],
}

impl GroundHomography {
    /// Refuses non-finite or (relatively) singular matrices.
    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        if !self.matrix.iter().all(|v| v.is_finite()) {
            return Err("every entry must be finite");
        }
        let scale = self.matrix.iter().fold(0.0_f64, |m, v| m.max(v.abs()));
        if scale == 0.0 {
            return Err("matrix is zero");
        }
        let [a, b, c, d, e, f, g, h, i] = self.matrix.map(|v| v / scale);
        let det = a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g);
        if !det.is_finite() || det.abs() <= 1e-12 {
            return Err("matrix is singular");
        }
        Ok(())
    }

    /// Projects one image point, or `None` when it maps to or beyond the ground horizon
    /// (`w <= 0` relative to the matrix scale) or to a non-finite point.
    #[must_use]
    pub fn project(&self, u: f64, v: f64) -> Option<(f64, f64)> {
        let [a, b, c, d, e, f, g, h, i] = self.matrix;
        let w = g * u + h * v + i;
        let scale = self.matrix.iter().fold(0.0_f64, |m, x| m.max(x.abs()));
        if !w.is_finite() || w <= scale * 1e-12 {
            return None;
        }
        let x = (a * u + b * v + c) / w;
        let y = (d * u + e * v + f) / w;
        (x.is_finite() && y.is_finite()).then_some((x, y))
    }

    fn encode(&self, e: &mut CanonicalEncoder) {
        for value in self.matrix {
            e.u64(value.to_bits());
        }
    }

    /// Canonical identity of the exact matrix bits.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(PLAN_DOMAIN);
        e.text("ground-homography");
        self.encode(&mut e);
        ContentDigest::sha256(&e.finish())
    }
}

/// An owner-drawn axis-aligned ground-plane zone, in the homographies' shared ground units.
#[derive(Clone, Debug, PartialEq)]
pub struct GroundZone {
    /// Stable zone identifier: 1..=64 ASCII alphanumerics, `-` or `_`.
    pub zone_id: String,
    /// Minimum ground x.
    pub x: f64,
    /// Minimum ground y.
    pub y: f64,
    /// Positive ground width.
    pub width: f64,
    /// Positive ground height.
    pub height: f64,
}
impl GroundZone {
    fn contains(&self, x: f64, y: f64) -> bool {
        x >= self.x && x <= self.x + self.width && y >= self.y && y <= self.y + self.height
    }
}

/// One recording in the plan.
#[derive(Clone, Debug, PartialEq)]
pub struct CorroborationCamera {
    /// Operator label, 1..=32 ASCII alphanumerics, `-` or `_`; not a sensor identity.
    pub name: String,
    /// Exact completed import.
    pub import_identity: ContentDigest,
    /// Owner-supplied image→ground homography.
    pub homography: GroundHomography,
}

/// Explicit association gates.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CorroborationGates {
    /// Maximum worst-case capture-time separation over both conservative intervals, 1..=60 s.
    pub time_gate_ns: u64,
    /// Maximum ground distance between the two entry points, in ground units.
    pub distance_gate: f64,
}

/// Complete analysis identity. Resource ceilings are separate ([`WatchLimits`]).
#[derive(Clone, Debug, PartialEq)]
pub struct CorroborationPlan {
    /// Exactly two recordings.
    pub cameras: [CorroborationCamera; 2],
    /// Explicit component interpretation (shared by both recordings).
    pub interpretation: ComponentInterpretation,
    /// Ground zones in evaluation order, 1..=[`MAX_CORROBORATION_ZONES`].
    pub zones: Vec<GroundZone>,
    /// Association gates.
    pub gates: CorroborationGates,
    /// Foreground thresholds (shared).
    pub detector: WatchDetectorConfig,
    /// Tracker lifecycle policy (shared).
    pub tracker: WatchTrackerConfig,
}

impl CorroborationPlan {
    /// Validates bounds, names, zones, gates and homographies before any source is read.
    pub fn validate(&self) -> Result<()> {
        let [first, second] = &self.cameras;
        for camera in &self.cameras {
            if !valid_name(&camera.name, 32) {
                return Err(CorroborationError::InvalidPlan(
                    "camera name must be 1..32 of [A-Za-z0-9_-]",
                ));
            }
            camera.homography.validate().map_err(|reason| {
                CorroborationError::InvalidHomography {
                    camera: camera.name.clone(),
                    reason,
                }
            })?;
        }
        if first.name == second.name {
            return Err(CorroborationError::InvalidPlan("camera names must differ"));
        }
        if first.import_identity == second.import_identity {
            return Err(CorroborationError::SameSensor);
        }
        if self.zones.is_empty() || self.zones.len() > MAX_CORROBORATION_ZONES {
            return Err(CorroborationError::InvalidPlan(
                "one through sixteen ground zones are required",
            ));
        }
        let mut seen = BTreeSet::new();
        for zone in &self.zones {
            if !valid_name(&zone.zone_id, 64) {
                return Err(CorroborationError::InvalidPlan(
                    "zone id must be 1..64 of [A-Za-z0-9_-]",
                ));
            }
            if !seen.insert(zone.zone_id.as_str()) {
                return Err(CorroborationError::InvalidPlan("duplicate zone id"));
            }
            let finite = [
                zone.x,
                zone.y,
                zone.width,
                zone.height,
                zone.x + zone.width,
                zone.y + zone.height,
            ]
            .iter()
            .all(|v| v.is_finite());
            if !finite || zone.width <= 0.0 || zone.height <= 0.0 {
                return Err(CorroborationError::InvalidPlan(
                    "zone must have positive finite extent",
                ));
            }
        }
        if self.gates.time_gate_ns == 0 || self.gates.time_gate_ns > MAX_TIME_GATE_NS {
            return Err(CorroborationError::InvalidPlan(
                "time gate must be 1..60000000000 ns",
            ));
        }
        if !self.gates.distance_gate.is_finite() || self.gates.distance_gate <= 0.0 {
            return Err(CorroborationError::InvalidPlan(
                "distance gate must be finite and positive",
            ));
        }
        Ok(())
    }

    fn watch_plan(&self, camera: &CorroborationCamera, segment_count: usize) -> WatchPlan {
        WatchPlan {
            import_identity: camera.import_identity,
            interpretation: self.interpretation,
            first_segment: 0,
            segment_count,
            zones: vec![WatchZone {
                zone_id: TRACKING_ZONE.to_owned(),
                x: 0,
                y: 0,
                width: 4096,
                height: 4096,
            }],
            detector: self.detector,
            tracker: self.tracker,
        }
    }

    /// Canonical plan identity, including the fixed composition policy.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(PLAN_DOMAIN);
        e.digest(ContentDigest::sha256(POLICY));
        for camera in &self.cameras {
            e.text(&camera.name);
            e.digest(camera.import_identity);
            camera.homography.encode(&mut e);
        }
        e.u8(match self.interpretation {
            ComponentInterpretation::Grayscale => 0,
            ComponentInterpretation::YCbCr => 1,
        });
        e.u64(self.zones.len() as u64);
        for zone in &self.zones {
            e.text(&zone.zone_id);
            for value in [zone.x, zone.y, zone.width, zone.height] {
                e.u64(value.to_bits());
            }
        }
        e.u64(self.gates.time_gate_ns);
        e.u64(self.gates.distance_gate.to_bits());
        for value in [
            self.detector.base_threshold,
            self.detector.threshold_sigma,
            self.detector.learning_rate_num,
            self.detector.learning_rate_den,
        ] {
            e.u32(u32::from(value));
        }
        e.u64(self.detector.minimum_region_pixels as u64);
        e.u32(self.tracker.confirmation_hits);
        e.u32(self.tracker.maximum_missed_frames);
        e.u32(self.tracker.minimum_iou_ppm);
        ContentDigest::sha256(&e.finish())
    }
}

/// Geometric visibility inputs of ground-zone coverage. The default (registered policy, no pose,
/// no mesh) is what [`CorroborationReport::analyze`] uses: homography frustum sampling with
/// occlusion explicitly unknown.
#[derive(Clone, Copy, Debug, Default)]
pub struct GroundVisibilityPlan<'a> {
    /// Sample grid and visible-fraction threshold.
    pub policy: VisibilityPolicy,
    /// Optional owner calibrated pose per camera, in plan order.
    pub poses: [Option<CameraPose>; 2],
    /// Optional owner scene mesh (fss-twin import) shared by both cameras.
    pub mesh: Option<SceneMesh<'a>>,
}

impl GroundVisibilityPlan<'_> {
    fn encode(&self, e: &mut CanonicalEncoder) {
        e.text("ground-visibility");
        let mut parameters = Vec::new();
        for pose in &self.poses {
            bind_visibility_parameters(
                &mut parameters,
                self.policy,
                pose.as_ref(),
                self.mesh.map(|mesh| mesh.package_digest),
            );
        }
        e.u64(parameters.len() as u64);
        for value in parameters {
            e.u64(value);
        }
    }
}

/// Per-recording analysis summary.
#[derive(Clone, Debug)]
pub struct CameraSummary {
    /// Plan camera name.
    pub name: String,
    /// Exact import.
    pub import_identity: ContentDigest,
    /// Retained import root.
    pub import_root: ContentDigest,
    /// Recording sensor identity (from retained source capsules).
    pub sensor_id: String,
    /// Failure domain derived from the sensor identity.
    pub failure_domain: String,
    /// Watch plan digest of the per-camera tracking run.
    pub watch_plan_digest: ContentDigest,
    /// Watch analysis digest of the per-camera tracking run.
    pub watch_analysis_digest: ContentDigest,
    /// Frames decoded.
    pub frames: usize,
    /// Confirmed tracks (whole-frame).
    pub confirmed_tracks: usize,
    /// Union of every decoded frame's conservative capture interval.
    pub capture_span: CaptureInterval,
    /// Owner homography digest.
    pub homography_digest: ContentDigest,
    sensor_digest: ContentDigest,
    coverage_frames: Vec<CoverageFrame>,
    segment_gaps: Vec<bool>,
    dimensions: [u32; 2],
    media_format: String,
    privacy: MaskBinding,
}

/// How one ground-zone entry fared in association.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryDisposition {
    /// Stably associated with the other sensor's entry inside both gates, worst case included.
    Corroborated,
    /// The other sensor has no entry into this zone.
    NoCounterpartEntry,
    /// Every counterpart failed the time or distance gate (not proof of absence).
    NoAdmissibleCounterpart,
    /// A competing assignment is inside the margin; nothing is chosen.
    Ambiguous,
    /// Point estimates passed but the worst case over both capture intervals exceeds the time gate.
    TimeGateUncertain,
}
impl EntryDisposition {
    /// Stable spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Corroborated => "corroborated",
            Self::NoCounterpartEntry => "no_counterpart_entry",
            Self::NoAdmissibleCounterpart => "no_admissible_counterpart",
            Self::Ambiguous => "ambiguous",
            Self::TimeGateUncertain => "time_gate_uncertain",
        }
    }
}

/// One camera's confirmed track entering one ground zone.
#[derive(Clone, Debug)]
pub struct GroundEntry {
    /// Index into the plan cameras.
    pub camera: usize,
    /// Ground zone entered.
    pub zone_id: String,
    /// Tracker-local identifier; not a physical identity.
    pub track_id: u64,
    /// First confirmed segment whose foot point lies in the zone.
    pub segment: usize,
    /// Conservative capture interval of that frame.
    pub capture: CaptureInterval,
    /// Retained source-capsule payload digest of that frame.
    pub capsule_digest: ContentDigest,
    /// Filtered track box `(cx, cy, w, h)` in pixels.
    pub track_box: [i64; 4],
    /// Projected ground point of the foot point.
    pub ground: (f64, f64),
    /// Digest of the retained entry observation record.
    pub record_digest: ContentDigest,
    /// Association outcome.
    pub disposition: EntryDisposition,
    /// Detector-cascade class evidence of this entry's track (empty without a detector).
    pub class_evidence: Vec<ClassEvidence>,
    record: Vec<u8>,
}

/// Publication state of one candidate in this deployment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorroborationStatus {
    /// Proposal prepared; no event authority exists yet.
    Prepared,
    /// This exact event revision is already authoritative; it is never republished.
    AlreadyPublished,
    /// Published by this call.
    Published,
}
impl CorroborationStatus {
    /// Stable spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::AlreadyPublished => "already_published",
            Self::Published => "published",
        }
    }
}

#[derive(Clone, Debug)]
struct Provenance {
    slot: SlotName,
    manifest: ObjectManifest,
    objects: BTreeMap<ContentDigest, Vec<u8>>,
    decision: ReferencePolicyDecision,
}

/// Two sensors' associated entries into one ground zone, with the complete prepared proposal.
#[derive(Clone, Debug)]
pub struct CorroborationCandidate {
    /// Ground zone entered.
    pub zone_id: String,
    /// Indices into the report's entries: first camera, second camera.
    pub entries: [usize; 2],
    /// Worst-case capture-time separation over both intervals, in nanoseconds.
    pub worst_case_separation_ns: u128,
    /// Ground distance between the entry points.
    pub distance: f64,
    /// Unquantized association ranking score (not a probability).
    pub association_score: f64,
    identity: ContentDigest,
    proof: Provenance,
    proposal: ContentDigest,
    status: CorroborationStatus,
}
impl CorroborationCandidate {
    /// Deterministic candidate identity (the association record digest).
    #[must_use]
    pub fn identity(&self) -> ContentDigest {
        self.identity
    }
    /// Exact approval identity: event revision digest plus provenance root.
    #[must_use]
    pub fn proposal_digest(&self) -> ContentDigest {
        self.proposal
    }
    /// Event that publication would record.
    #[must_use]
    pub fn event(&self) -> &EventHypothesis {
        &self.proof.decision.event
    }
    /// Policy affordance for this event (an affordance, never an effect).
    #[must_use]
    pub fn policy_action(&self) -> ReferencePolicyAction {
        self.proof.decision.action
    }
    /// Provenance graph root retained before event authority.
    #[must_use]
    pub fn provenance_root(&self) -> ContentDigest {
        self.proof.manifest.root()
    }
    /// Current publication state.
    #[must_use]
    pub fn status(&self) -> CorroborationStatus {
        self.status
    }
}

/// Complete deterministic corroboration analysis.
#[derive(Clone, Debug)]
pub struct CorroborationReport {
    plan: CorroborationPlan,
    plan_digest: ContentDigest,
    cameras: Vec<CameraSummary>,
    entries: Vec<GroundEntry>,
    candidates: Vec<CorroborationCandidate>,
    coverage: Vec<CoverageRecord>,
    coverage_status: CoverageStatus,
    cascade: Option<CorroborationCascade>,
}

#[derive(Clone, Debug)]
struct CorroborationCascade {
    digest: ContentDigest,
    policy_json: String,
    outcomes: Vec<CascadeOutcome>,
}

struct CameraRun {
    summary: CameraSummary,
    entries: Vec<GroundEntry>,
    cascade: Option<CascadeOutcome>,
}

fn union(a: CaptureInterval, b: CaptureInterval) -> Result<CaptureInterval> {
    Ok(CaptureInterval::new(
        a.earliest.min(b.earliest),
        a.latest.max(b.latest),
    )?)
}

fn analyze_camera(
    deployment: &ReferenceDeployment,
    plan: &CorroborationPlan,
    plan_digest: ContentDigest,
    index: usize,
    limits: &WatchLimits,
    cascade: Option<(&mut DetectorCascade<'_>, &mut CascadeBudget)>,
    cx: &ReplayCx,
) -> Result<CameraRun> {
    let camera = &plan.cameras[index];
    let retained =
        RetainedFileImport::open(deployment, camera.import_identity, limits.read_limits, cx)?;
    if retained.manifest().capture_time_label != OPERATOR_TIME_LABEL {
        return Err(CorroborationError::TimeUnknown {
            camera: camera.name.clone(),
        });
    }
    let count = retained.manifest().segment_spans.len();
    if count == 0 || count > MAX_WATCH_FRAMES {
        return Err(CorroborationError::InvalidPlan(
            "each recording must hold 1..128 frames",
        ));
    }
    let (capsule, _) = source_capsule(deployment, &retained, 0)?;
    let sensor_id = capsule.sensor_id.as_str().to_owned();
    let sensor_digest = ContentDigest::sha256(sensor_id.as_bytes());
    let failure_domain = format!("recorded-sensor:{}", hex(sensor_digest));
    let import_root = retained.import_root();
    let watch_plan = plan.watch_plan(camera, count);
    let report = WatchReport::analyze(deployment, &watch_plan, limits, cx)?;
    let frames: BTreeMap<usize, _> = report.frames().iter().map(|f| (f.segment, f)).collect();
    let mut span: Option<CaptureInterval> = None;
    for frame in report.frames() {
        span = Some(match span {
            Some(old) => union(old, frame.capture)?,
            None => frame.capture,
        });
    }
    let capture_span = span.ok_or(CorroborationError::Limit)?;
    let segment_gaps: Vec<bool> = retained
        .manifest()
        .segment_spans
        .iter()
        .map(|s| s.gap_before)
        .collect();
    let coverage_frames: Vec<CoverageFrame> = report
        .frames()
        .iter()
        .map(|frame| CoverageFrame {
            segment: frame.segment,
            capture: frame.capture,
        })
        .collect();
    let homography_digest = camera.homography.digest();
    let mut entries = Vec::new();
    let mut sources = Vec::new();
    let mut confirmed = BTreeSet::new();
    for (candidate_index, candidate) in report.candidates().iter().enumerate() {
        checkpoint(cx, "recorded_corroboration:project")?;
        confirmed.insert(candidate.track_id);
        for zone in &plan.zones {
            for observation in candidate
                .observations
                .iter()
                .filter(|o| o.segment >= candidate.entry_segment)
            {
                let [cx_px, cy_px, _w, h] = observation.track_box;
                let foot = (cx_px as f64, cy_px as f64 + h as f64 / 2.0);
                let ground = camera.homography.project(foot.0, foot.1).ok_or_else(|| {
                    CorroborationError::InvalidHomography {
                        camera: camera.name.clone(),
                        reason: "an observed foot point maps to or beyond the ground horizon",
                    }
                })?;
                if !zone.contains(ground.0, ground.1) {
                    continue;
                }
                let frame = frames
                    .get(&observation.segment)
                    .ok_or(CorroborationError::Limit)?;
                let mut e = CanonicalEncoder::new();
                e.text(OBSERVATION_DOMAIN);
                e.digest(plan_digest);
                e.text(&camera.name);
                e.digest(camera.import_identity);
                e.digest(import_root);
                e.digest(sensor_digest);
                e.digest(report.plan_digest());
                e.digest(report.analysis_digest());
                e.digest(candidate.identity());
                e.text(&zone.zone_id);
                e.u64(candidate.track_id);
                e.u64(observation.segment as u64);
                e.digest(observation.capsule_digest);
                e.digest(observation.luma_digest);
                e.digest(observation.record_digest);
                for value in observation.track_box {
                    e.i128(i128::from(value));
                }
                e.u64(foot.0.to_bits());
                e.u64(foot.1.to_bits());
                e.u64(ground.0.to_bits());
                e.u64(ground.1.to_bits());
                e.digest(homography_digest);
                e.i128(frame.capture.earliest.0);
                e.i128(frame.capture.latest.0);
                let record = e.finish();
                entries.push(GroundEntry {
                    camera: index,
                    zone_id: zone.zone_id.clone(),
                    track_id: candidate.track_id,
                    segment: observation.segment,
                    capture: frame.capture,
                    capsule_digest: observation.capsule_digest,
                    track_box: observation.track_box,
                    ground,
                    record_digest: ContentDigest::sha256(&record),
                    disposition: EntryDisposition::NoCounterpartEntry,
                    class_evidence: Vec::new(),
                    record,
                });
                sources.push(candidate_index);
                break;
            }
        }
    }
    let cascade = match cascade {
        None => None,
        Some((detector, budget)) => {
            let tracks: Vec<CascadeTrack> = entries
                .iter()
                .zip(&sources)
                .map(|(entry, source)| {
                    let candidate = &report.candidates()[*source];
                    let observations: Vec<(usize, [i64; 4])> = candidate
                        .observations
                        .iter()
                        .map(|o| (o.segment, o.track_box))
                        .collect();
                    CascadeTrack {
                        track_id: entry.track_id,
                        // The whole-frame watch candidate's entry is the confirmation frame.
                        selections: select_frames(
                            entry.segment,
                            candidate.entry_segment,
                            &observations,
                            detector.config().frames_per_track,
                        ),
                    }
                })
                .collect();
            let decoded: Vec<usize> = report.frames().iter().map(|f| f.segment).collect();
            let outcome = detector
                .run(
                    deployment,
                    CascadeSource {
                        import_identity: camera.import_identity,
                        import_root,
                        interpretation: plan.interpretation,
                        media_format: report.media_format(),
                        first_segment: 0,
                        decoded_segments: &decoded,
                    },
                    &tracks,
                    budget,
                    limits,
                    cx,
                )
                .map_err(WatchError::from)?;
            for (entry, evidence) in entries.iter_mut().zip(&outcome.evidence) {
                entry.class_evidence = evidence.clone();
            }
            Some(outcome)
        }
    };
    Ok(CameraRun {
        cascade,
        summary: CameraSummary {
            name: camera.name.clone(),
            import_identity: camera.import_identity,
            import_root,
            sensor_id,
            failure_domain,
            watch_plan_digest: report.plan_digest(),
            watch_analysis_digest: report.analysis_digest(),
            frames: report.frames().len(),
            confirmed_tracks: confirmed.len(),
            capture_span,
            homography_digest,
            sensor_digest,
            coverage_frames,
            segment_gaps,
            dimensions: report.dimensions(),
            media_format: report.media_format().to_owned(),
            privacy: report.privacy_mask().clone(),
        },
        entries,
    })
}

fn midpoint(interval: CaptureInterval) -> Result<i64> {
    let middle = interval.earliest.0 + (interval.latest.0 - interval.earliest.0) / 2;
    i64::try_from(middle).map_err(|_| CorroborationError::Limit)
}

/// Largest possible separation of two instants drawn from the two conservative intervals.
fn worst_case_separation(a: CaptureInterval, b: CaptureInterval) -> u128 {
    let first = (a.latest.0 - b.earliest.0).unsigned_abs();
    let second = (b.latest.0 - a.earliest.0).unsigned_abs();
    first.max(second)
}

impl CorroborationReport {
    /// Tracks, projects, associates and prepares proposals. Reads retained custody only; writes
    /// no objects, ledger batches or events. Publication state is read from the ledger.
    pub fn analyze(
        deployment: &ReferenceDeployment,
        plan: &CorroborationPlan,
        limits: &WatchLimits,
        cx: &ReplayCx,
    ) -> Result<Self> {
        Self::analyze_with_detector(deployment, plan, limits, None, cx)
    }

    /// [`Self::analyze`] plus an optional detector cascade over each ground entry's selected
    /// frames, with one inference budget shared by both recordings. `None` is byte-for-byte
    /// [`Self::analyze`].
    pub fn analyze_with_detector(
        deployment: &ReferenceDeployment,
        plan: &CorroborationPlan,
        limits: &WatchLimits,
        detector: Option<&mut DetectorCascade<'_>>,
        cx: &ReplayCx,
    ) -> Result<Self> {
        Self::analyze_with_visibility(
            deployment,
            plan,
            limits,
            detector,
            &GroundVisibilityPlan::default(),
            cx,
        )
    }

    /// [`Self::analyze_with_detector`] with explicit geometric-visibility inputs for ground-zone
    /// coverage: sampling policy, optional owner calibrated poses and an optional owner scene
    /// mesh. Candidates, events and the non-coverage report are independent of these inputs.
    pub fn analyze_with_visibility(
        deployment: &ReferenceDeployment,
        plan: &CorroborationPlan,
        limits: &WatchLimits,
        mut detector: Option<&mut DetectorCascade<'_>>,
        visibility: &GroundVisibilityPlan<'_>,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx, "recorded_corroboration:analyze")?;
        plan.validate()?;
        visibility.policy.validate()?;
        let plan_digest = plan.digest();
        let mut allowance = detector.as_ref().map(|d| d.budget());
        let first = analyze_camera(
            deployment,
            plan,
            plan_digest,
            0,
            limits,
            detector.as_deref_mut().zip(allowance.as_mut()),
            cx,
        )?;
        let second = analyze_camera(
            deployment,
            plan,
            plan_digest,
            1,
            limits,
            detector.as_deref_mut().zip(allowance.as_mut()),
            cx,
        )?;
        let cascade = match (&detector, first.cascade, second.cascade) {
            (Some(detector), Some(a), Some(b)) => Some(CorroborationCascade {
                digest: detector.digest(),
                policy_json: cascade_policy_json(detector),
                outcomes: vec![a, b],
            }),
            _ => None,
        };
        if first.summary.sensor_id == second.summary.sensor_id {
            return Err(CorroborationError::SameSensor);
        }
        let (a, b) = (first.summary.capture_span, second.summary.capture_span);
        if a.latest < b.earliest || b.latest < a.earliest {
            return Err(CorroborationError::TimeUnaligned);
        }
        let cameras = vec![first.summary, second.summary];
        let mut entries: Vec<GroundEntry> = first.entries;
        entries.extend(second.entries);
        let config = CrossCameraConfig {
            max_time_delta_ns: i64::try_from(plan.gates.time_gate_ns)
                .map_err(|_| CorroborationError::Limit)?,
            max_position_distance: plan.gates.distance_gate,
            min_confidence: 0.0,
        };
        let mut budget = WorkBudget::new(ASSOCIATION_WORK);
        let mut pairs = Vec::new();
        for zone in &plan.zones {
            checkpoint(cx, "recorded_corroboration:associate")?;
            let side = |camera: usize| -> Result<Vec<(usize, CameraObservation)>> {
                entries
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| e.camera == camera && e.zone_id == zone.zone_id)
                    .map(|(index, e)| {
                        Ok((
                            index,
                            CameraObservation {
                                camera_id: plan.cameras[camera].name.clone(),
                                track_id: e
                                    .track_id
                                    .checked_add(1)
                                    .ok_or(CorroborationError::Limit)?,
                                timestamp_ns: midpoint(e.capture)?,
                                ground_x: e.ground.0,
                                ground_y: e.ground.1,
                            },
                        ))
                    })
                    .collect()
            };
            let left = side(0)?;
            let right = side(1)?;
            if left.is_empty() || right.is_empty() {
                continue;
            }
            let observations = |side: &[(usize, CameraObservation)]| {
                side.iter().map(|(_, o)| o.clone()).collect::<Vec<_>>()
            };
            let report = associate_detailed(
                &config,
                0,
                &observations(&left),
                &observations(&right),
                &mut budget,
            )?;
            // The report orders each side by track id; map back to entry indices.
            let locate = |side: &[(usize, CameraObservation)], track: u64| {
                side.iter()
                    .find(|(_, o)| o.track_id == track)
                    .map(|(index, _)| *index)
                    .ok_or(CorroborationError::Limit)
            };
            for (row, disposition) in report.left_dispositions().iter().enumerate() {
                let left_index = locate(&left, report.left()[row].track_id)?;
                match *disposition {
                    AssociationDisposition::NoCandidate => {
                        entries[left_index].disposition = EntryDisposition::NoAdmissibleCounterpart;
                    }
                    AssociationDisposition::Unresolved => {
                        entries[left_index].disposition = EntryDisposition::Ambiguous;
                    }
                    AssociationDisposition::Matched(column) => {
                        let right_index = locate(&right, report.right()[column].track_id)?;
                        let separation = worst_case_separation(
                            entries[left_index].capture,
                            entries[right_index].capture,
                        );
                        if separation > u128::from(plan.gates.time_gate_ns) {
                            entries[left_index].disposition = EntryDisposition::TimeGateUncertain;
                            entries[right_index].disposition = EntryDisposition::TimeGateUncertain;
                            continue;
                        }
                        let score =
                            match report.candidates()[row * report.right().len() + column].score {
                                AssociationScore::Admissible { confidence, .. } => confidence,
                                AssociationScore::Excluded(_) => {
                                    return Err(CorroborationError::Limit);
                                }
                            };
                        entries[left_index].disposition = EntryDisposition::Corroborated;
                        entries[right_index].disposition = EntryDisposition::Corroborated;
                        pairs.push((
                            zone.zone_id.clone(),
                            left_index,
                            right_index,
                            separation,
                            score,
                        ));
                    }
                }
            }
            for (column, disposition) in report.right_dispositions().iter().enumerate() {
                let right_index = locate(&right, report.right()[column].track_id)?;
                match *disposition {
                    AssociationDisposition::NoCandidate => {
                        entries[right_index].disposition =
                            EntryDisposition::NoAdmissibleCounterpart;
                    }
                    AssociationDisposition::Unresolved => {
                        entries[right_index].disposition = EntryDisposition::Ambiguous;
                    }
                    AssociationDisposition::Matched(_) => {}
                }
            }
        }
        if pairs.len() > MAX_CORROBORATION_CANDIDATES {
            return Err(CorroborationError::Limit);
        }
        let mut candidates = Vec::with_capacity(pairs.len());
        let context = CandidateContext {
            deployment,
            plan,
            plan_digest,
            cameras: &cameras,
            entries: &entries,
            cascade: cascade.as_ref().map(|c| c.digest),
        };
        for (zone_id, left, right, separation, score) in pairs {
            checkpoint(cx, "recorded_corroboration:prepare")?;
            candidates.push(context.prepare(AssociatedEntries {
                zone_id,
                pair: [left, right],
                separation,
                score,
            })?);
        }
        let basis = deployment.current_anchor().clone();
        let mut coverage = Vec::with_capacity(cameras.len());
        for (index, camera) in cameras.iter().enumerate() {
            coverage.push(camera_coverage(
                &CameraCoverageContext {
                    plan,
                    plan_digest,
                    entries: &entries,
                    candidates: &candidates,
                    basis: &basis,
                    cascade: cascade.as_ref().map(|c| c.digest),
                    visibility,
                },
                index,
                camera,
            )?);
        }
        let status = coverage_status(deployment, &coverage.iter().collect::<Vec<_>>())?;
        Ok(Self {
            plan: plan.clone(),
            plan_digest,
            cameras,
            entries,
            candidates,
            coverage,
            coverage_status: status,
            cascade,
        })
    }

    /// Detector-cascade outcomes (one per camera, plan order), if a detector was supplied.
    #[must_use]
    pub fn detector_cascade(&self) -> Option<&[CascadeOutcome]> {
        self.cascade.as_ref().map(|c| c.outcomes.as_slice())
    }

    /// Proposed (or retained) coverage, one record per camera in plan order.
    #[must_use]
    pub fn coverage(&self) -> &[CoverageRecord] {
        &self.coverage
    }

    /// Retention state of [`Self::coverage`].
    #[must_use]
    pub fn coverage_status(&self) -> CoverageStatus {
        self.coverage_status
    }

    /// Exact approval digest that retains both cameras' coverage records.
    #[must_use]
    pub fn coverage_approval(&self) -> ContentDigest {
        approval_digest(&self.coverage.iter().collect::<Vec<_>>())
    }

    /// Fails closed, before any write, when `approval` is neither this analysis's coverage
    /// proposal nor the approval of its already retained coverage.
    pub fn check_coverage_approval(
        &self,
        deployment: &ReferenceDeployment,
        approval: ContentDigest,
    ) -> Result<()> {
        check_approval(
            deployment,
            &self.coverage.iter().collect::<Vec<_>>(),
            approval,
        )?;
        Ok(())
    }

    /// Retains both cameras' coverage records in one batch with their exact approval digest
    /// (or reports them as already retained). Nothing is written without the approval.
    pub fn retain_coverage(
        &mut self,
        deployment: &mut ReferenceDeployment,
        approval: ContentDigest,
        cx: &ReplayCx,
    ) -> Result<CoverageStatus> {
        checkpoint(cx, "recorded_corroboration:coverage")?;
        let records: Vec<&CoverageRecord> = self.coverage.iter().collect();
        let status = retain_coverage(deployment, &records, approval, cx)?;
        self.coverage_status = status;
        Ok(status)
    }

    /// Plan identity.
    #[must_use]
    pub fn plan_digest(&self) -> ContentDigest {
        self.plan_digest
    }
    /// Per-recording summaries, in plan order.
    #[must_use]
    pub fn cameras(&self) -> &[CameraSummary] {
        &self.cameras
    }
    /// Every ground-zone entry of both cameras, with its association outcome.
    #[must_use]
    pub fn entries(&self) -> &[GroundEntry] {
        &self.entries
    }
    /// Corroborated candidates in deterministic (zone, track) order.
    #[must_use]
    pub fn candidates(&self) -> &[CorroborationCandidate] {
        &self.candidates
    }

    /// Publishes exactly the approved proposals. Every approval must name a proposal of this
    /// analysis, checked before any write. Already-published candidates are left untouched.
    pub fn publish(
        &mut self,
        deployment: &mut ReferenceDeployment,
        approvals: &BTreeSet<ContentDigest>,
        cx: &ReplayCx,
    ) -> Result<usize> {
        checkpoint(cx, "recorded_corroboration:revalidate")?;
        for approval in approvals {
            if !self.candidates.iter().any(|c| c.proposal == *approval) {
                return Err(CorroborationError::StaleApproval(*approval));
            }
        }
        let mut published = 0;
        for candidate in &mut self.candidates {
            if !approvals.contains(&candidate.proposal) {
                continue;
            }
            candidate.status = current_status(deployment, &candidate.proof.decision.event)?;
            if candidate.status == CorroborationStatus::AlreadyPublished {
                continue;
            }
            let proof = &candidate.proof;
            let existing = deployment
                .publisher()
                .root(&proof.slot)
                .map(|root| root.root);
            if existing.is_some_and(|root| root != proof.manifest.root()) {
                return Err(CorroborationError::Conflict);
            }
            for bytes in proof.objects.values() {
                checkpoint(cx, "recorded_corroboration:stage")?;
                let digest = deployment.publisher_mut().stage_object(bytes)?;
                deployment.publisher_mut().verify_object(digest)?;
            }
            for digest in proof.manifest.children() {
                checkpoint(cx, "recorded_corroboration:closure")?;
                deployment.publisher_mut().verify_object(*digest)?;
            }
            if existing.is_none() {
                deployment
                    .publisher_mut()
                    .stage_manifest(&proof.slot, &proof.manifest)?;
            }
            deployment.publish_and_commit(
                &proof.slot,
                &proof.manifest,
                proof.decision.event.interval,
                cx,
            )?;
            checkpoint(cx, STAGE_RECORDED_CORROBORATION_COMMIT)?;
            deployment.publish_event(&proof.decision, cx)?;
            cx.checkpoint_post_commit("recorded_corroboration:published");
            candidate.status = CorroborationStatus::Published;
            published += 1;
        }
        Ok(published)
    }

    /// Bounded deterministic JSON rendering. `publish_hint` (the exact rerun command prefix) is
    /// echoed for prepared candidates, and `alert_hint` (an alert command prefix) for published
    /// candidates whose policy affordance is `prepare_alert`, with the owner-supplied relay route
    /// left as placeholders. Neither grants anything.
    #[must_use]
    pub fn to_json(
        &self,
        authority_sequence: u64,
        publish_hint: Option<&str>,
        alert_hint: Option<&str>,
    ) -> String {
        self.to_json_with_coverage(authority_sequence, publish_hint, alert_hint, None)
    }

    /// [`Self::to_json`] with an optional pre-rendered `coverage` JSON value appended as the
    /// report's last member.
    #[must_use]
    pub fn to_json_with_coverage(
        &self,
        authority_sequence: u64,
        publish_hint: Option<&str>,
        alert_hint: Option<&str>,
        coverage_json: Option<&str>,
    ) -> String {
        let cameras: Vec<String> = self
            .cameras
            .iter()
            .map(|c| {
                format!(
                    concat!(
                        "{{\"camera\":{},\"import_identity\":\"{}\",\"import_root\":\"{}\",",
                        "\"sensor_id\":{},\"failure_domain\":\"{}\",\"frames_decoded\":{},",
                        "\"confirmed_tracks\":{},\"capture_span_ns\":[{},{}],",
                        "\"capture_time_label\":\"operator_assumption\",",
                        "\"watch_plan_digest\":\"{}\",\"watch_analysis_digest\":\"{}\",",
                        "\"ground_homography_digest\":\"{}\",",
                        "\"ground_homography\":\"owner_supplied_not_a_calibration_certificate\"}}"
                    ),
                    json_string(&c.name),
                    c.import_identity,
                    c.import_root,
                    json_string(&c.sensor_id),
                    c.failure_domain,
                    c.frames,
                    c.confirmed_tracks,
                    c.capture_span.earliest.0,
                    c.capture_span.latest.0,
                    c.watch_plan_digest,
                    c.watch_analysis_digest,
                    c.homography_digest,
                )
            })
            .collect();
        let zones: Vec<String> = self
            .plan
            .zones
            .iter()
            .map(|z| {
                format!(
                    "{{\"zone_id\":\"{}\",\"x\":{},\"y\":{},\"width\":{},\"height\":{}}}",
                    z.zone_id,
                    json_number(z.x),
                    json_number(z.y),
                    json_number(z.width),
                    json_number(z.height)
                )
            })
            .collect();
        let entries: Vec<String> = self
            .entries
            .iter()
            .map(|e| {
                format!(
                    concat!(
                        "{{\"camera\":{},\"zone_id\":\"{}\",\"track_id\":{},\"segment\":{},",
                        "\"capture_ns\":[{},{}],\"capsule_digest\":\"{}\",",
                        "\"track_box_cxcywh\":[{},{},{},{}],\"ground\":[{},{}],",
                        "\"observation_digest\":\"{}\",\"disposition\":\"{}\"{}}}"
                    ),
                    json_string(&self.plan.cameras[e.camera].name),
                    e.zone_id,
                    e.track_id,
                    e.segment,
                    e.capture.earliest.0,
                    e.capture.latest.0,
                    e.capsule_digest,
                    e.track_box[0],
                    e.track_box[1],
                    e.track_box[2],
                    e.track_box[3],
                    json_number(e.ground.0),
                    json_number(e.ground.1),
                    e.record_digest,
                    e.disposition.as_str(),
                    match self.cascade {
                        Some(_) => format!(
                            ",\"class_evidence\":{}",
                            class_evidence_json(&e.class_evidence)
                        ),
                        None => String::new(),
                    },
                )
            })
            .collect();
        let candidates: Vec<String> = self
            .candidates
            .iter()
            .map(|c| {
                let event = &c.proof.decision.event;
                let command = match (c.status, publish_hint) {
                    (CorroborationStatus::Prepared, Some(hint)) => {
                        json_string(&format!("{hint} --approve {}", c.proposal))
                    }
                    _ => "null".to_owned(),
                };
                let action = match c.proof.decision.action {
                    ReferencePolicyAction::PrepareAlert => "prepare_alert",
                    ReferencePolicyAction::Hold => "hold",
                };
                let alert = match (c.status, c.proof.decision.action, alert_hint) {
                    (
                        CorroborationStatus::Published | CorroborationStatus::AlreadyPublished,
                        ReferencePolicyAction::PrepareAlert,
                        Some(hint),
                    ) => json_string(&format!(
                        "{hint} --event-id {} --relay IP:PORT --path /PATH \
                         --plaintext-approval sha256:APPROVAL --deadline-ms MS",
                        event.event_id
                    )),
                    _ => "null".to_owned(),
                };
                format!(
                    concat!(
                        "{{\"candidate_id\":\"{}\",\"zone_id\":\"{}\",\"entries\":[{},{}],",
                        "\"worst_case_separation_ns\":{},\"ground_distance\":{},",
                        "\"association_score\":{},\"event_id\":\"{}\",\"event_kind\":\"{}\",",
                        "\"event_state\":\"{}\",\"event_revision_digest\":\"{}\",",
                        "\"policy_action\":\"{}\",\"alert_prepared\":false,",
                        "\"proposal_digest\":\"{}\",\"provenance_root\":\"{}\",",
                        "\"status\":\"{}\",\"publish_command\":{},\"alert_command\":{}}}"
                    ),
                    c.identity,
                    c.zone_id,
                    c.entries[0],
                    c.entries[1],
                    c.worst_case_separation_ns,
                    json_number(c.distance),
                    json_number(c.association_score),
                    event.event_id,
                    event.kind.as_str(),
                    event.state.as_str(),
                    event.revision_digest(),
                    action,
                    c.proposal,
                    c.proof.manifest.root(),
                    c.status.as_str(),
                    command,
                    alert,
                )
            })
            .collect();
        let count = |status| {
            self.candidates
                .iter()
                .filter(|c| c.status == status)
                .count()
        };
        format!(
            concat!(
                "{{\"format\":\"fss.recorded_corroboration_report.v1\",\"plan_digest\":\"{}\",",
                "\"policy_digest\":\"{}\",\"cameras\":[{}],\"zones\":[{}],",
                "\"time_gate_ns\":{},\"distance_gate\":{},",
                "\"time_semantics\":\"operator_capture_hints_worst_case_interval_gate\",",
                "\"entries\":[{}],\"candidate_count\":{},\"candidates\":[{}],",
                "\"prepared_count\":{},\"published_count\":{},\"already_published_count\":{},",
                "\"authority_sequence\":{},\"alert_prepared\":false,\"effects_authorized\":false,",
                "\"calibrated\":false,\"absence_certifiable\":false,",
                "\"detection_quality_claim\":false{}{}}}"
            ),
            self.plan_digest,
            ContentDigest::sha256(POLICY),
            cameras.join(","),
            zones.join(","),
            self.plan.gates.time_gate_ns,
            json_number(self.plan.gates.distance_gate),
            entries.join(","),
            self.candidates.len(),
            candidates.join(","),
            count(CorroborationStatus::Prepared),
            count(CorroborationStatus::Published),
            count(CorroborationStatus::AlreadyPublished),
            authority_sequence,
            self.cascade.as_ref().map_or_else(String::new, |c| {
                let cameras: Vec<String> = c
                    .outcomes
                    .iter()
                    .zip(&self.plan.cameras)
                    .map(|(outcome, camera)| {
                        format!(
                            "{{\"camera\":{},{}}}",
                            json_string(&camera.name),
                            cascade_outcome_json(outcome)
                        )
                    })
                    .collect();
                let total: usize = c
                    .outcomes
                    .iter()
                    .map(|o| o.inferred_segments().len())
                    .sum();
                format!(
                    ",\"detector_cascade\":{{{},\"inference_count\":{total},\"budget_scope\":\"both_recordings\",\"cameras\":[{}]}}",
                    c.policy_json,
                    cameras.join(",")
                )
            }),
            coverage_json.map_or_else(String::new, |json| format!(",\"coverage\":{json}")),
        )
    }
}

struct CameraCoverageContext<'a> {
    plan: &'a CorroborationPlan,
    plan_digest: ContentDigest,
    entries: &'a [GroundEntry],
    candidates: &'a [CorroborationCandidate],
    basis: &'a fss_core::LedgerAnchor,
    cascade: Option<ContentDigest>,
    visibility: &'a GroundVisibilityPlan<'a>,
}

fn camera_coverage(
    context: &CameraCoverageContext<'_>,
    index: usize,
    camera: &CameraSummary,
) -> Result<CoverageRecord> {
    let plan = context.plan;
    let homography = &plan.cameras[index].homography;
    let visibility_plan = context.visibility;
    let pose = visibility_plan.poses.get(index).copied().flatten();
    let mut parameters = pipeline_parameters(plan.interpretation, &plan.detector, &plan.tracker);
    parameters.extend(homography.matrix.iter().map(|value| value.to_bits()));
    bind_cascade_parameters(&mut parameters, context.cascade);
    bind_visibility_parameters(
        &mut parameters,
        visibility_plan.policy,
        pose.as_ref(),
        visibility_plan.mesh.map(|mesh| mesh.package_digest),
    );
    // A mask generation is part of the pipeline generation: witnesses never cross it.
    bind_cascade_parameters(
        &mut parameters,
        camera.privacy.policy().map(|_| camera.privacy.digest()),
    );
    // Ground zones whose image preimage may contain a masked pixel carry no witness.
    let masked: BTreeSet<String> = match camera.privacy.policy() {
        None => BTreeSet::new(),
        Some(policy) => plan
            .zones
            .iter()
            .filter(|zone| {
                ground_zone_masked(
                    policy,
                    homography.matrix,
                    [zone.x, zone.y, zone.width, zone.height],
                )
            })
            .map(|zone| zone.zone_id.clone())
            .collect(),
    };
    let policy = ContentDigest::sha256(POLICY);
    let mut zones = Vec::with_capacity(plan.zones.len());
    let mut visibilities = Vec::with_capacity(plan.zones.len());
    for zone in &plan.zones {
        let geometry = format!("{},{},{},{}", zone.x, zone.y, zone.width, zone.height);
        let polygon = rectangle(zone.x, zone.y, zone.width, zone.height);
        let camera_model = match &pose {
            Some(pose) => {
                if pose.intrinsics.dimensions() != camera.dimensions {
                    return Err(CorroborationError::InvalidPose {
                        camera: camera.name.clone(),
                        reason: "intrinsics describe another image size than the decoded frames",
                    });
                }
                if !pose_matches_homography(
                    pose,
                    &homography.matrix,
                    &polygon,
                    visibility_plan.policy,
                ) {
                    return Err(CorroborationError::InvalidPose {
                        camera: camera.name.clone(),
                        reason: "pose and ground homography disagree over the zone",
                    });
                }
                VisibilityCamera::Pose(pose)
            }
            None => VisibilityCamera::Homography(&homography.matrix),
        };
        let visible = assess_ground_zone(
            camera_model,
            camera.dimensions,
            &polygon,
            visibility_plan.mesh,
            visibility_plan.policy,
        )?;
        let zone_entries = context
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.camera == index && entry.zone_id == zone.zone_id)
            .map(|(position, entry)| CoverageEntry {
                segment: entry.segment,
                candidate: entry.record_digest,
                event_id: context
                    .candidates
                    .iter()
                    .find(|candidate| candidate.entries.contains(&position))
                    .map(|candidate| candidate.event().event_id.as_str().to_owned()),
            })
            .collect();
        zones.push(CoverageZoneInput {
            zone_id: zone.zone_id.clone(),
            pipeline_generation: pipeline_generation(
                CoverageSource::Corroborate,
                policy,
                media_decoder_label(&camera.media_format),
                &parameters,
                &zone.zone_id,
                &geometry,
            ),
            geometry,
            inside_frame: visible.observable(),
            entries: zone_entries,
        });
        visibilities.push(Some(visible));
    }
    let mut e = CanonicalEncoder::new();
    e.text(PLAN_DOMAIN);
    e.text("camera-coverage-analysis");
    e.digest(context.plan_digest);
    e.u64(index as u64);
    e.digest(camera.watch_analysis_digest);
    visibility_plan.encode(&mut e);
    let analysis_digest = ContentDigest::sha256(&e.finish());
    let last_segment = camera
        .segment_gaps
        .len()
        .checked_sub(1)
        .ok_or(CorroborationError::Limit)?;
    let extras = CoverageExtras {
        visibility: visibilities,
        refusals: Vec::new(),
        restarts: Vec::new(),
    };
    let mut record = build_coverage_with(
        &CoverageInput {
            source: CoverageSource::Corroborate,
            import_identity: camera.import_identity,
            import_root: camera.import_root,
            sensor_id: &camera.sensor_id,
            analysis_digest,
            basis: context.basis.clone(),
            capture_time_label: OPERATOR_TIME_LABEL,
            segment_gaps: &camera.segment_gaps,
            first_segment: 0,
            last_segment,
            frames: &camera.coverage_frames,
            confirmation_hits: plan.tracker.confirmation_hits,
            zones,
        },
        &extras,
    )?;
    mask_coverage_zones(&mut record, &masked)?;
    Ok(record)
}

struct CandidateContext<'a> {
    deployment: &'a ReferenceDeployment,
    plan: &'a CorroborationPlan,
    plan_digest: ContentDigest,
    cameras: &'a [CameraSummary],
    entries: &'a [GroundEntry],
    cascade: Option<ContentDigest>,
}

struct AssociatedEntries {
    zone_id: String,
    pair: [usize; 2],
    separation: u128,
    score: f64,
}

impl CandidateContext<'_> {
    fn prepare(&self, associated: AssociatedEntries) -> Result<CorroborationCandidate> {
        prepare_candidate(self, associated)
    }
}

fn prepare_candidate(
    context: &CandidateContext<'_>,
    associated: AssociatedEntries,
) -> Result<CorroborationCandidate> {
    let CandidateContext {
        deployment,
        plan,
        plan_digest,
        cameras,
        entries,
        cascade,
    } = *context;
    let AssociatedEntries {
        zone_id,
        pair,
        separation,
        score,
    } = associated;
    let [left, right] = pair.map(|index| &entries[index]);
    let distance = (left.ground.0 - right.ground.0).hypot(left.ground.1 - right.ground.1);
    let mut e = CanonicalEncoder::new();
    e.text(ASSOCIATION_DOMAIN);
    e.digest(plan_digest);
    e.text(&zone_id);
    e.digest(left.record_digest);
    e.digest(right.record_digest);
    e.u64(plan.gates.time_gate_ns);
    e.u64(plan.gates.distance_gate.to_bits());
    e.i128(i128::try_from(separation).map_err(|_| CorroborationError::Limit)?);
    e.u64(distance.to_bits());
    e.u64(score.to_bits());
    if let Some(cascade) = cascade {
        // Class evidence is bound into the candidate identity, never into the policy event.
        e.digest(cascade);
        for entry in [left, right] {
            e.u64(entry.class_evidence.len() as u64);
            for item in &entry.class_evidence {
                e.digest(item.digest);
            }
        }
    }
    let association = e.finish();
    let identity = ContentDigest::sha256(&association);
    let mut objects = BTreeMap::new();
    let mut insert = |bytes: Vec<u8>| {
        let digest = ContentDigest::sha256(&bytes);
        objects.insert(digest, bytes);
        digest
    };
    let policy = insert(POLICY.to_vec());
    insert(association);
    let mut witnesses = Vec::with_capacity(2);
    let mut children = BTreeSet::new();
    let mut track_ids = Vec::with_capacity(2);
    for entry in [left, right] {
        let camera = &cameras[entry.camera];
        let sensor = insert(camera.sensor_id.as_bytes().to_vec());
        if sensor != camera.sensor_digest {
            return Err(CorroborationError::Limit);
        }
        insert(entry.record.clone());
        for item in &entry.class_evidence {
            insert(item.record.clone());
        }
        children.insert(camera.import_root);
        children.insert(entry.capsule_digest);
        track_ids.push(format!("track:{}:{}", camera.name, entry.track_id));
        witnesses.push(ZoneEntryWitness {
            record_digest: entry.record_digest,
            sensor_digest: camera.sensor_digest,
            capsule_digest: entry.capsule_digest,
            failure_domain: camera.failure_domain.clone(),
            interval: entry.capture,
        });
    }
    let decision = evaluate_zone_entry_corroboration(ZoneEntryCorroboration {
        event_id: EventId::parse(format!("event:corroborated:{}", hex(identity)))?,
        zone_id: zone_id.clone(),
        track_ids,
        witnesses,
        association_digest: identity,
        association_domain: format!("cross-camera-association:{}", hex(plan_digest)),
        uncertainty_reason: UNCERTAINTY.to_owned(),
    })?;
    let mut e = CanonicalEncoder::new();
    e.bytes(b"FSSCORR1");
    e.u32(1);
    e.text(PROPOSAL_DOMAIN);
    e.digest(policy);
    e.digest(identity);
    e.digest(decision.event.revision_digest());
    let metadata = insert(e.finish());
    children.extend(objects.keys().copied());
    children.remove(&metadata);
    let slot = SlotName::parse(&format!("rc-{}", hex(identity)))
        .map_err(|_| CorroborationError::InvalidPlan("candidate slot name"))?;
    let manifest = ObjectManifest::new(slot.as_str(), children, Some(metadata))?;
    let mut e = CanonicalEncoder::new();
    e.text(PROPOSAL_DOMAIN);
    e.digest(decision.event.revision_digest());
    e.digest(manifest.root());
    let proposal = ContentDigest::sha256(&e.finish());
    let status = current_status(deployment, &decision.event)?;
    Ok(CorroborationCandidate {
        zone_id,
        entries: pair,
        worst_case_separation_ns: separation,
        distance,
        association_score: score,
        identity,
        proof: Provenance {
            slot,
            manifest,
            objects,
            decision,
        },
        proposal,
        status,
    })
}

fn current_status(
    deployment: &ReferenceDeployment,
    event: &EventHypothesis,
) -> Result<CorroborationStatus> {
    let object = ObjectId::parse(format!("object:event:{}", event.event_id.as_str()))?;
    let Some(current) = deployment.ledger().current().objects.get(&object) else {
        return Ok(CorroborationStatus::Prepared);
    };
    let revision = event.revision_digest();
    let exact = deployment.ledger().batches().iter().any(|batch| {
        batch.deltas.iter().any(|delta| {
            delta.object_id == object
                && delta.family == "event_revision"
                && delta.new_generation == current.generation
                && delta.payload_digest == current.payload_digest
                && delta.witness_digest == Some(revision)
        })
    });
    if exact {
        Ok(CorroborationStatus::AlreadyPublished)
    } else {
        Err(CorroborationError::Conflict)
    }
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Finite values print with Rust's shortest round-trip form; JSON has no NaN or infinity.
fn json_number(value: f64) -> String {
    if value.is_finite() {
        format!("{value:?}")
    } else {
        "null".to_owned()
    }
}

#[cfg(test)]
mod tests;
