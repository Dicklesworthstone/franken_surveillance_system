#![forbid(unsafe_code)]
//! Finite zone observations over exact source-linked ONVIF vendor claims.
//!
//! Zones are declared in raw object-coordinate units, with explicit pins to the source scope,
//! named analytics module and both transform declarations. No transform is applied, no absent
//! transform component is defaulted, and no pixel, image orientation or calibrated world basis
//! is invented. Complete vendor boxes are rounded outward onto a declared decimal grid.
//! Membership and side changes are derived claims; timestamps, dwell, physical identity,
//! coverage, absence and effect authority are deliberately not inferred.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::json_input::{self, Value};
use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, Plane, ProvenanceClass};

use crate::onvif::metadata::tracks::contract::{
    MAX_TRACK_FRAMES, MAX_TRACK_OBJECTS, TrackError, TrackFrameInput, TrackletReport,
    project_tracklets,
};
use crate::onvif::wire::{AnalyticsObject, AnalyticsTransformation};

/// Reusable exact bounded decimal/rectangle arithmetic, without source or clock authority.
#[path = "contract/geometry.rs"]
pub mod geometry;
use geometry::RectangleRelation;
pub use geometry::{COORDINATE_SCALE, MAX_COORDINATE_MAGNITUDE};

/// Immutable source-pipeline interpretation; never a calibrated scene generation.
pub const ZONE_GENERATION: &str = "gen:fss1:onvif-vendor-zones-v1";
/// Complete pure report schema/canonical domain, nested inside the retained owner's receipt.
pub const ZONE_REPORT_DOMAIN: &str = "fss.onvif_vendor_zone_projection.v1";
/// Closed operator policy schema.
pub const ZONE_POLICY_SCHEMA: &str = "fss.onvif_vendor_zone_policy.v1";
/// Explicit units and interpretation of every supplied rectangle and margin.
pub const ZONE_COORDINATES: &str = "raw_vendor_object_millionths";
/// Complete finite zone set; no hidden top-k selection.
pub const MAX_VENDOR_ZONES: usize = 16;
/// Bound before parsing any operator policy JSON.
pub const MAX_ZONE_POLICY_BYTES: usize = 64 * 1024;
/// Complete occurrence × zone matrix bound.
pub const MAX_ZONE_CELLS: usize = MAX_TRACK_OBJECTS * MAX_VENDOR_ZONES;
/// Complete frame × zone matrix bound, including empty and wrong-domain frames.
pub const MAX_ZONE_FRAME_SAMPLES: usize = MAX_TRACK_FRAMES * MAX_VENDOR_ZONES;
/// Complete transition bound; overflow refuses rather than returning a prefix.
pub const MAX_ZONE_TRANSITIONS: usize = MAX_ZONE_CELLS;
/// Complete canonical report bound.
pub const MAX_ZONE_REPORT_BYTES: usize = 8 * 1024 * 1024;
/// One nonrenewing work allowance, including the source-pair verification reservation.
pub const MAX_ZONE_WORK_UNITS: u64 = 64 * 1024 * 1024;

/// One owner-selected rectangle in an exact raw vendor-coordinate domain.
#[derive(Clone, Eq, PartialEq)]
pub struct VendorZone {
    /// Local annotation, 1..64 ASCII alphanumerics, hyphen or underscore.
    pub id: String,
    /// Exact source sensor/device/profile/parser/transport scope from the tracklet report.
    pub scope: ContentDigest,
    /// Exact named analytics module; missing modules never share an implicit domain.
    pub module_digest: ContentDigest,
    /// Exact frame transform declaration, including absence. It is not applied by this query.
    pub frame_transform_digest: ContentDigest,
    /// Exact object transform/appearance declaration, including absence. It is not applied.
    pub object_transform_digest: ContentDigest,
    /// Strict lower numeric-axis rectangle corner in millionths of raw vendor units.
    pub min: [i64; 2],
    /// Strict upper numeric-axis rectangle corner in the same declared units.
    pub max: [i64; 2],
    /// Expand the entire claimed box by this many subunits before classification.
    pub margin: u64,
}
impl fmt::Debug for VendorZone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VendorZone")
            .field("scope", &self.scope)
            .field("module_digest", &self.module_digest)
            .finish_non_exhaustive()
    }
}

/// Complete immutable zone policy, in caller-declared order.
#[derive(Clone, Eq, PartialEq)]
pub struct ZonePolicy {
    /// Every requested zone. Empty policies and duplicate local IDs are refused.
    pub zones: Vec<VendorZone>,
}
impl fmt::Debug for ZonePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZonePolicy")
            .field("zones", &self.zones.len())
            .finish_non_exhaustive()
    }
}

/// Whole-query bounds; none renew during geometry, verification or serialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZoneLimits {
    /// Complete occurrence × zone output cells.
    pub max_cells: usize,
    /// Complete frame × zone accounting rows, including empty frames.
    pub max_frame_samples: usize,
    /// Complete observed side-change output inventory.
    pub max_transitions: usize,
    /// Logical work ceiling, including the original projector's full declared allowance.
    pub max_work_units: u64,
    /// Complete canonical output-byte ceiling.
    pub max_output_bytes: usize,
}
impl Default for ZoneLimits {
    fn default() -> Self {
        Self {
            max_cells: MAX_ZONE_CELLS,
            max_frame_samples: MAX_ZONE_FRAME_SAMPLES,
            max_transitions: MAX_ZONE_TRANSITIONS,
            max_work_units: 4_000_000,
            max_output_bytes: MAX_ZONE_REPORT_BYTES,
        }
    }
}
impl ZoneLimits {
    /// Reject widening or zero bounds before any input traversal or allocation.
    pub fn validate(self) -> Result<(), ZoneError> {
        if !(1..=MAX_ZONE_CELLS).contains(&self.max_cells)
            || !(1..=MAX_ZONE_FRAME_SAMPLES).contains(&self.max_frame_samples)
            || !(1..=MAX_ZONE_TRANSITIONS).contains(&self.max_transitions)
            || !(1..=MAX_ZONE_WORK_UNITS).contains(&self.max_work_units)
            || !(1..=MAX_ZONE_REPORT_BYTES).contains(&self.max_output_bytes)
        {
            return Err(ZoneError::InvalidLimits);
        }
        Ok(())
    }
}

/// Payload-free whole-query refusal. No error is a successful empty observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZoneError {
    /// Invalid, duplicate, unsupported or unbounded operator declaration.
    InvalidPolicy,
    /// Invalid or widened execution bounds.
    InvalidLimits,
    /// Hydrated frames and the supplied source-linked tracklet report do not agree.
    InvalidInput,
    /// Complete matrix, allocation, transition or output-byte capacity was exceeded.
    Limit,
    /// The original cumulative work allowance was exhausted.
    BudgetExceeded,
    /// Current owner admission refused; this call cannot resume or return a prefix.
    Cancelled,
    /// A canonical field or preflight size was inconsistent.
    Encoding,
}
impl ZoneError {
    /// Stable diagnostic, containing no policy label, coordinate or vendor value.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidPolicy => "ERR-ONVIF-ZONES-POLICY-001",
            Self::InvalidLimits => "ERR-ONVIF-ZONES-CONFIG-001",
            Self::InvalidInput => "ERR-ONVIF-ZONES-INPUT-001",
            Self::Limit => "ERR-ONVIF-ZONES-LIMIT-001",
            Self::BudgetExceeded => "ERR-ONVIF-ZONES-BUDGET-001",
            Self::Cancelled => "ERR-ONVIF-ZONES-CANCELLED-001",
            Self::Encoding => "ERR-ONVIF-ZONES-ENCODING-001",
        }
    }
}
impl fmt::Display for ZoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for ZoneError {}

/// Relation of an entire supported vendor box, never a calibrated physical occupancy state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ZoneRelation {
    /// Complete expanded box strictly inside the declared raw-coordinate rectangle.
    Inside = 1,
    /// Complete expanded box strictly separated from that rectangle on at least one axis.
    Outside = 2,
    /// Touching, intersecting or within coordinate rounding/margin uncertainty.
    Boundary = 3,
    /// Missing, opaque, incompatible-domain or inadmissible coordinate evidence.
    Unavailable = 4,
}
impl ZoneRelation {
    /// Stable JSON spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inside => "inside",
            Self::Outside => "outside",
            Self::Boundary => "boundary",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Explicit uncertainty; none of these states is classified as outside or absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ZoneUnavailable {
    /// Source-generation scope differs from the selected zone's declaration.
    ScopeMismatch = 1,
    /// The claiming analytics module is absent or empty.
    MissingModule = 2,
    /// A different named module supplied this frame.
    ModuleMismatch = 3,
    /// The frame-coordinate declaration differs, including missing/present changes.
    FrameTransformMismatch = 4,
    /// The object-relative declaration differs, including appearance absence.
    ObjectTransformMismatch = 5,
    /// The retained source contains an uninterpreted outer event/lifecycle section.
    UninterpretedSource = 6,
    /// Frame-level opaque fields or unsupported frame-transform content.
    UnsupportedFrameContent = 7,
    /// Opaque object-level fields prevent a complete supported claim.
    UnsupportedObjectContent = 8,
    /// No appearance description was supplied.
    MissingAppearance = 9,
    /// Opaque appearance or object-transform content.
    UnsupportedAppearance = 10,
    /// No shape description was supplied.
    MissingShape = 11,
    /// Shape, box or center fields contain unsupported extensions.
    UnsupportedShape = 12,
    /// The exact decimal extent cannot fit the bounded outward-rounded coordinate domain.
    CoordinateOutOfRange = 13,
}
impl ZoneUnavailable {
    /// Stable non-disclosing JSON spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ScopeMismatch => "scope_mismatch",
            Self::MissingModule => "missing_module",
            Self::ModuleMismatch => "module_mismatch",
            Self::FrameTransformMismatch => "frame_transform_mismatch",
            Self::ObjectTransformMismatch => "object_transform_mismatch",
            Self::UninterpretedSource => "uninterpreted_source",
            Self::UnsupportedFrameContent => "unsupported_frame_content",
            Self::UnsupportedObjectContent => "unsupported_object_content",
            Self::MissingAppearance => "missing_appearance",
            Self::UnsupportedAppearance => "unsupported_appearance",
            Self::MissingShape => "missing_shape",
            Self::UnsupportedShape => "unsupported_shape",
            Self::CoordinateOutOfRange => "coordinate_out_of_range",
        }
    }
}

/// One complete occurrence × zone cell, in occurrence-major/zone-minor order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZoneCell {
    /// Index into the complete declared zone policy.
    pub zone_index: usize,
    /// Index into the exact accompanying tracklet report's occurrence inventory.
    pub occurrence_index: usize,
    /// Original frame ordinal, retained even for an unavailable cell.
    pub frame_ordinal: usize,
    /// Complete-box vendor claim relation.
    pub relation: ZoneRelation,
    /// Present exactly when relation is unavailable.
    pub reason: Option<ZoneUnavailable>,
}

/// Full frame × zone accounting; an empty frame is retained without certifying absence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZoneFrameSample {
    /// Index into the declared zone policy.
    pub zone_index: usize,
    /// Exact original frame ordinal.
    pub frame_ordinal: usize,
    /// Frame domain/opacity refusal, including on zero-object frames.
    pub basis_unavailable: Option<ZoneUnavailable>,
    /// Number of original vendor boxes definitely inside this sample's zone.
    pub inside: usize,
    /// Number definitely outside; this does not describe unreported objects.
    pub outside: usize,
    /// Number touching, intersecting or unresolved at the rectangle boundary.
    pub boundary: usize,
    /// Number with missing, unsupported or incompatible-domain evidence.
    pub unavailable: usize,
}

/// Side changes between supplied vendor samples, without path interpolation or physical time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ZoneTransitionKind {
    /// First supported inside claim after run start or an unavailable sample.
    ObservedInside = 1,
    /// An outside and later inside claim on the same unchanged vendor tracklet.
    EnteredBetweenObservations = 2,
    /// An inside and later outside claim on the same unchanged vendor tracklet.
    LeftBetweenObservations = 3,
    /// An unavailable sample interrupted previously usable side observations.
    ObservationInterrupted = 4,
}
impl ZoneTransitionKind {
    /// Stable JSON spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObservedInside => "observed_inside",
            Self::EnteredBetweenObservations => "entered_between_observations",
            Self::LeftBetweenObservations => "left_between_observations",
            Self::ObservationInterrupted => "observation_interrupted",
        }
    }
}

/// Exact endpoint handles for an observed side change or interruption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZoneTransition {
    /// Index into the declared policy.
    pub zone_index: usize,
    /// Original advisory vendor tracklet identity; this layer never stitches tracks.
    pub tracklet_identity: ContentDigest,
    /// Derived transition kind, not an EventKind or effect.
    pub kind: ZoneTransitionKind,
    /// Previous definite side's original occurrence; absent for first inside sightings.
    pub previous_occurrence: Option<usize>,
    /// Current original occurrence supplying the side claim or explicit interruption.
    pub occurrence: usize,
}

/// Complete deterministic pure projection. Current source custody belongs to its retained owner.
#[derive(Clone, Eq, PartialEq)]
pub struct ZoneReport {
    /// Exact complete owner-selected policy, including original zone order.
    pub policy: ZonePolicy,
    /// Whole-call bounds, not mutable defaults.
    pub limits: ZoneLimits,
    /// Canonical policy commitment.
    pub policy_digest: ContentDigest,
    /// Exact source-linked tracklet report used for all associations.
    pub tracklet_report_digest: ContentDigest,
    /// Commitment to every original shape input, including unavailable/opaque fields.
    pub input_digest: ContentDigest,
    /// Complete occurrence × zone matrix.
    pub cells: Vec<ZoneCell>,
    /// Complete frame × zone counts, including zero-object frames.
    pub frame_samples: Vec<ZoneFrameSample>,
    /// Every side change/interruption in current-occurrence/zone order.
    pub transitions: Vec<ZoneTransition>,
    /// Reserved verification work plus deterministic geometry/input/output work.
    pub work_units: u64,
    /// Exact canonical output byte count.
    pub encoded_bytes: usize,
    /// Canonical report digest, excluding this self-field and encoded_bytes.
    pub report_digest: ContentDigest,
}
impl ZoneReport {
    /// Membership and side transitions are derived cognition.
    pub const fn plane(&self) -> Plane {
        Plane::Cognition
    }
    /// This projection does not promote the source assertions.
    pub const fn provenance(&self) -> ProvenanceClass {
        ProvenanceClass::Derived
    }
    /// Every source geometry/association remains a vendor claim.
    pub const fn source_provenance(&self) -> ProvenanceClass {
        ProvenanceClass::VendorClaimed
    }
}
impl fmt::Debug for ZoneReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZoneReport")
            .field("report_digest", &self.report_digest)
            .field("cells", &self.cells.len())
            .field("frame_samples", &self.frame_samples.len())
            .field("transitions", &self.transitions.len())
            .field("work_units", &self.work_units)
            .finish_non_exhaustive()
    }
}

fn pin(value: ContentDigest) -> bool {
    value.algorithm() == DigestAlgorithm::Sha256 && value.bytes() != [0; 32]
}
impl ZonePolicy {
    /// Validate the complete declaration before use. Coordinates never imply a pixel grid.
    pub fn validate(&self) -> Result<(), ZoneError> {
        if self.zones.is_empty() || self.zones.len() > MAX_VENDOR_ZONES {
            return Err(ZoneError::InvalidPolicy);
        }
        let mut ids = BTreeSet::new();
        for zone in &self.zones {
            if zone.id.is_empty()
                || zone.id.len() > 64
                || !zone
                    .id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
                || !ids.insert(zone.id.as_str())
                || ![
                    zone.scope,
                    zone.module_digest,
                    zone.frame_transform_digest,
                    zone.object_transform_digest,
                ]
                .into_iter()
                .all(pin)
                || zone.margin > MAX_COORDINATE_MAGNITUDE as u64
                || (0..2).any(|axis| {
                    zone.min[axis] >= zone.max[axis]
                        || !(-MAX_COORDINATE_MAGNITUDE..=MAX_COORDINATE_MAGNITUDE)
                            .contains(&zone.min[axis])
                        || !(-MAX_COORDINATE_MAGNITUDE..=MAX_COORDINATE_MAGNITUDE)
                            .contains(&zone.max[axis])
                })
            {
                return Err(ZoneError::InvalidPolicy);
            }
        }
        Ok(())
    }

    /// Canonical semantic identity, independent of JSON whitespace and object-key order.
    pub fn digest(&self) -> Result<ContentDigest, ZoneError> {
        self.validate()?;
        let mut encoded = CanonicalEncoder::new();
        encode_policy(&mut encoded, self);
        hash(encoded)
    }

    /// Parse one bounded, closed-schema policy with exact signed JSON integer coordinates.
    pub fn parse_json(text: &str) -> Result<Self, ZoneError> {
        if text.len() > MAX_ZONE_POLICY_BYTES {
            return Err(ZoneError::InvalidPolicy);
        }
        let value = json_input::parse(text).map_err(|_| ZoneError::InvalidPolicy)?;
        let root = fields(&value, &["schema", "coordinates", "zones"])?;
        if field(root, "schema")?.text() != Some(ZONE_POLICY_SCHEMA)
            || field(root, "coordinates")?.text() != Some(ZONE_COORDINATES)
        {
            return Err(ZoneError::InvalidPolicy);
        }
        let rows = field(root, "zones")?
            .array()
            .ok_or(ZoneError::InvalidPolicy)?;
        if rows.is_empty() || rows.len() > MAX_VENDOR_ZONES {
            return Err(ZoneError::InvalidPolicy);
        }
        let mut zones = Vec::new();
        zones
            .try_reserve_exact(rows.len())
            .map_err(|_| ZoneError::Limit)?;
        for row in rows {
            let row = fields(
                row,
                &[
                    "id",
                    "scope",
                    "module_digest",
                    "frame_transform_digest",
                    "object_transform_digest",
                    "min",
                    "max",
                    "margin",
                ],
            )?;
            zones.push(VendorZone {
                id: field(row, "id")?
                    .text()
                    .ok_or(ZoneError::InvalidPolicy)?
                    .to_owned(),
                scope: json_digest(field(row, "scope")?)?,
                module_digest: json_digest(field(row, "module_digest")?)?,
                frame_transform_digest: json_digest(field(row, "frame_transform_digest")?)?,
                object_transform_digest: json_digest(field(row, "object_transform_digest")?)?,
                min: coordinates(field(row, "min")?)?,
                max: coordinates(field(row, "max")?)?,
                margin: u64::try_from(integer(field(row, "margin")?)?)
                    .map_err(|_| ZoneError::InvalidPolicy)?,
            });
        }
        let result = Self { zones };
        result.validate()?;
        Ok(result)
    }
}

fn fields<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a BTreeMap<String, Value>, ZoneError> {
    let fields = value.object().ok_or(ZoneError::InvalidPolicy)?;
    if fields.len() != keys.len() || fields.keys().any(|key| !keys.contains(&key.as_str())) {
        return Err(ZoneError::InvalidPolicy);
    }
    Ok(fields)
}
fn field<'a>(value: &'a BTreeMap<String, Value>, name: &str) -> Result<&'a Value, ZoneError> {
    value.get(name).ok_or(ZoneError::InvalidPolicy)
}
fn integer(value: &Value) -> Result<i128, ZoneError> {
    if !matches!(value, Value::Number(_)) {
        return Err(ZoneError::InvalidPolicy);
    }
    value.integer().ok_or(ZoneError::InvalidPolicy)
}
fn coordinates(value: &Value) -> Result<[i64; 2], ZoneError> {
    let pair = value
        .array()
        .filter(|p| p.len() == 2)
        .ok_or(ZoneError::InvalidPolicy)?;
    Ok([
        i64::try_from(integer(&pair[0])?).map_err(|_| ZoneError::InvalidPolicy)?,
        i64::try_from(integer(&pair[1])?).map_err(|_| ZoneError::InvalidPolicy)?,
    ])
}
fn json_digest(value: &Value) -> Result<ContentDigest, ZoneError> {
    let digest = ContentDigest::parse(value.text().ok_or(ZoneError::InvalidPolicy)?)
        .map_err(|_| ZoneError::InvalidPolicy)?;
    if !pin(digest) {
        return Err(ZoneError::InvalidPolicy);
    }
    Ok(digest)
}
fn encode_policy(e: &mut CanonicalEncoder, policy: &ZonePolicy) {
    e.text(ZONE_POLICY_SCHEMA);
    e.text(ZONE_GENERATION);
    e.text(ZONE_COORDINATES);
    e.u64(policy.zones.len() as u64);
    for zone in &policy.zones {
        e.text(&zone.id);
        for digest in [
            zone.scope,
            zone.module_digest,
            zone.frame_transform_digest,
            zone.object_transform_digest,
        ] {
            e.digest(digest);
        }
        for coordinate in zone.min.into_iter().chain(zone.max) {
            e.i128(i128::from(coordinate));
        }
        e.u64(zone.margin);
    }
}
fn hash(e: CanonicalEncoder) -> Result<ContentDigest, ZoneError> {
    Ok(ContentDigest::sha256(
        &e.finish_checked().map_err(|_| ZoneError::Encoding)?,
    ))
}

struct Meter<F> {
    admitted: F,
    used: u64,
    limit: u64,
}
impl<F: FnMut() -> bool> Meter<F> {
    fn charge(&mut self, work: u64) -> Result<(), ZoneError> {
        if !(self.admitted)() {
            return Err(ZoneError::Cancelled);
        }
        let next = self
            .used
            .checked_add(work)
            .ok_or(ZoneError::BudgetExceeded)?;
        if next > self.limit {
            return Err(ZoneError::BudgetExceeded);
        }
        self.used = next;
        Ok(())
    }
}
fn reserve<T>(count: usize) -> Result<Vec<T>, ZoneError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| ZoneError::Limit)?;
    Ok(result)
}

#[derive(Clone, Copy)]
enum BoxClaim {
    Available { min: [i64; 2], max: [i64; 2] },
    Unavailable(ZoneUnavailable),
}
#[derive(Clone, Copy)]
struct Side {
    relation: ZoneRelation,
    occurrence: usize,
}

fn unsupported_transform(transform: Option<&AnalyticsTransformation>) -> bool {
    transform.is_some_and(|t| {
        t.unsupported_extensions != 0
            || t.translate
                .as_ref()
                .is_some_and(|v| v.unsupported_extensions != 0)
            || t.scale
                .as_ref()
                .is_some_and(|v| v.unsupported_extensions != 0)
    })
}

fn frame_unavailable(
    input: &TrackFrameInput<'_>,
    tracks: &TrackletReport,
    ordinal: usize,
    zone: &VendorZone,
) -> Option<ZoneUnavailable> {
    let frame = &tracks.frames[ordinal];
    if input.scope != zone.scope {
        Some(ZoneUnavailable::ScopeMismatch)
    } else if frame.module_digest.is_none() {
        Some(ZoneUnavailable::MissingModule)
    } else if frame.module_digest != Some(zone.module_digest) {
        Some(ZoneUnavailable::ModuleMismatch)
    } else if frame.transformation_digest != zone.frame_transform_digest {
        Some(ZoneUnavailable::FrameTransformMismatch)
    } else if input.uninterpreted_source {
        Some(ZoneUnavailable::UninterpretedSource)
    } else if input.frame.unsupported_extensions != 0
        || unsupported_transform(input.frame.transformation.as_ref())
    {
        Some(ZoneUnavailable::UnsupportedFrameContent)
    } else {
        None
    }
}

fn geometry_claim<F: FnMut() -> bool>(
    object: &AnalyticsObject,
    input: &mut CanonicalEncoder,
    meter: &mut Meter<F>,
) -> Result<BoxClaim, ZoneError> {
    // Fixed presence/extension fields plus bounded lexical bytes are admitted before encoding.
    let lexical_bytes = object
        .appearance
        .as_ref()
        .and_then(|a| a.shape.as_ref())
        .map_or(0, |shape| {
            [
                &shape.bounding_box.left,
                &shape.bounding_box.right,
                &shape.bounding_box.top,
                &shape.bounding_box.bottom,
                &shape.center_of_gravity.x,
                &shape.center_of_gravity.y,
            ]
            .into_iter()
            .map(|n| n.as_str().len())
            .sum::<usize>()
        });
    meter.charge(256 + lexical_bytes as u64 * 6)?;
    input.u64(object.unsupported_extensions as u64);
    input.bool(object.appearance.is_some());
    if let Some(appearance) = &object.appearance {
        input.u64(appearance.unsupported_extensions as u64);
        input.bool(unsupported_transform(appearance.transformation.as_ref()));
        input.bool(appearance.shape.is_some());
        if let Some(shape) = &appearance.shape {
            input.u64(shape.unsupported_extensions as u64);
            input.u64(shape.bounding_box.unsupported_extensions as u64);
            input.u64(shape.center_of_gravity.unsupported_extensions as u64);
            for number in [
                &shape.bounding_box.left,
                &shape.bounding_box.right,
                &shape.bounding_box.top,
                &shape.bounding_box.bottom,
                &shape.center_of_gravity.x,
                &shape.center_of_gravity.y,
            ] {
                input.text(number.as_str());
            }
        }
    }
    if object.unsupported_extensions != 0 {
        return Ok(BoxClaim::Unavailable(
            ZoneUnavailable::UnsupportedObjectContent,
        ));
    }
    let Some(appearance) = &object.appearance else {
        return Ok(BoxClaim::Unavailable(ZoneUnavailable::MissingAppearance));
    };
    if appearance.unsupported_extensions != 0
        || unsupported_transform(appearance.transformation.as_ref())
    {
        return Ok(BoxClaim::Unavailable(
            ZoneUnavailable::UnsupportedAppearance,
        ));
    }
    let Some(shape) = &appearance.shape else {
        return Ok(BoxClaim::Unavailable(ZoneUnavailable::MissingShape));
    };
    if shape.unsupported_extensions != 0
        || shape.bounding_box.unsupported_extensions != 0
        || shape.center_of_gravity.unsupported_extensions != 0
    {
        return Ok(BoxClaim::Unavailable(ZoneUnavailable::UnsupportedShape));
    }
    let [Ok(left), Ok(right), Ok(top), Ok(bottom)] = [
        &shape.bounding_box.left,
        &shape.bounding_box.right,
        &shape.bounding_box.top,
        &shape.bounding_box.bottom,
    ]
    .map(|value| geometry::decimal_millionths(value.as_str())) else {
        return Ok(BoxClaim::Unavailable(ZoneUnavailable::CoordinateOutOfRange));
    };
    // Numeric axis minima/maxima use both named endpoints. No image-axis direction is inferred,
    // and a reflected declared transform never causes us to silently reverse a pixel basis.
    Ok(BoxClaim::Available {
        min: [left.lower.min(right.lower), top.lower.min(bottom.lower)],
        max: [left.upper.max(right.upper), top.upper.max(bottom.upper)],
    })
}

fn append_transition(report: &mut ZoneReport, transition: ZoneTransition) -> Result<(), ZoneError> {
    if report.transitions.len() == report.limits.max_transitions {
        return Err(ZoneError::Limit);
    }
    report
        .transitions
        .try_reserve(1)
        .map_err(|_| ZoneError::Limit)?;
    report.transitions.push(transition);
    Ok(())
}

fn advance(
    report: &mut ZoneReport,
    previous: &mut Option<Side>,
    cell: &ZoneCell,
    tracklet_identity: ContentDigest,
) -> Result<(), ZoneError> {
    let kind = match cell.relation {
        ZoneRelation::Unavailable => previous.map(|_| ZoneTransitionKind::ObservationInterrupted),
        ZoneRelation::Inside => match previous {
            None => Some(ZoneTransitionKind::ObservedInside),
            Some(side) if side.relation == ZoneRelation::Outside => {
                Some(ZoneTransitionKind::EnteredBetweenObservations)
            }
            _ => None,
        },
        ZoneRelation::Outside => previous
            .filter(|side| side.relation == ZoneRelation::Inside)
            .map(|_| ZoneTransitionKind::LeftBetweenObservations),
        ZoneRelation::Boundary => None,
    };
    if let Some(kind) = kind {
        append_transition(
            report,
            ZoneTransition {
                zone_index: cell.zone_index,
                tracklet_identity,
                kind,
                previous_occurrence: previous.map(|side| side.occurrence),
                occurrence: cell.occurrence_index,
            },
        )?;
    }
    match cell.relation {
        ZoneRelation::Inside | ZoneRelation::Outside => {
            *previous = Some(Side {
                relation: cell.relation,
                occurrence: cell.occurrence_index,
            })
        }
        ZoneRelation::Unavailable => *previous = None,
        // Boundary samples never establish a definite side. Retaining the preceding side only
        // permits a later pair of observed endpoints, never interpolation or sampled dwell.
        ZoneRelation::Boundary => {}
    }
    Ok(())
}

/// Derive a complete vendor-zone query under one nonrenewing allowance.
///
/// The retained caller supplies the original hydrated frames from its verified reconstruction
/// pass and that pass's exact `TrackletReport`. The original production projector is replayed
/// under its own frozen limits and compared in full; its complete declared work allowance is
/// reserved from this call before it runs. Every shape field consumed here is separately bound
/// into `input_digest`. This pure function cannot authenticate caller-provided source pins.
///
/// All independent sources, lifecycle barriers and vendor-key runs remain exactly those of the
/// supplied report. No rename, merge, missing observation or generation boundary is stitched.
/// No output prefix survives a capacity, work, cancellation or pairing refusal.
pub fn project_zones<F: FnMut() -> bool>(
    inputs: &[TrackFrameInput<'_>],
    tracks: &TrackletReport,
    policy: &ZonePolicy,
    limits: ZoneLimits,
    admitted: F,
) -> Result<ZoneReport, ZoneError> {
    limits.validate()?;
    policy.validate()?;
    let mut meter = Meter {
        admitted,
        used: 0,
        limit: limits.max_work_units,
    };
    meter.charge(1)?;
    if inputs.len() > MAX_TRACK_FRAMES
        || inputs.len() != tracks.frames.len()
        || tracks.occurrences.len() > MAX_TRACK_OBJECTS
        || tracks.tracklets.len() > MAX_TRACK_OBJECTS
    {
        return Err(ZoneError::InvalidInput);
    }
    let zones = policy.zones.len();
    let cell_count = tracks
        .occurrences
        .len()
        .checked_mul(zones)
        .ok_or(ZoneError::Limit)?;
    let sample_count = inputs.len().checked_mul(zones).ok_or(ZoneError::Limit)?;
    let state_count = tracks
        .tracklets
        .len()
        .checked_mul(zones)
        .ok_or(ZoneError::Limit)?;
    if cell_count > limits.max_cells
        || sample_count > limits.max_frame_samples
        || state_count > limits.max_cells
    {
        return Err(ZoneError::Limit);
    }
    tracks
        .limits
        .validate()
        .map_err(|_| ZoneError::InvalidInput)?;
    meter.charge(tracks.limits.max_work_units)?;
    let verified = project_tracklets(inputs, tracks.limits, || (meter.admitted)()).map_err(
        |error| match error {
            TrackError::Cancelled => ZoneError::Cancelled,
            TrackError::BudgetExceeded => ZoneError::BudgetExceeded,
            TrackError::Limit => ZoneError::Limit,
            _ => ZoneError::InvalidInput,
        },
    )?;
    // Full structural equality traverses the bounded report independently of reconstruction.
    meter.charge(verified.encoded_bytes as u64)?;
    if &verified != tracks {
        return Err(ZoneError::InvalidInput);
    }
    drop(verified);

    // The exact policy encoding is bounded before hashing; source values never enter Debug.
    let policy_bytes = policy_size(policy)?;
    meter.charge((policy_bytes as u64) * 2)?;
    let policy_digest = policy.digest()?;
    meter.charge((cell_count + sample_count + state_count + tracks.occurrences.len()) as u64)?;
    let mut states = reserve(state_count)?;
    states.resize(state_count, None);
    let mut by_occurrence = reserve(tracks.occurrences.len())?;
    by_occurrence.resize(tracks.occurrences.len(), usize::MAX);
    for (track_index, track) in tracks.tracklets.iter().enumerate() {
        meter.charge(1 + track.occurrence_indices.len() as u64)?;
        for &occurrence in &track.occurrence_indices {
            let slot = by_occurrence
                .get_mut(occurrence)
                .ok_or(ZoneError::InvalidInput)?;
            if *slot != usize::MAX {
                return Err(ZoneError::InvalidInput);
            }
            *slot = track_index;
        }
    }
    if by_occurrence.contains(&usize::MAX) {
        return Err(ZoneError::InvalidInput);
    }

    let mut report = ZoneReport {
        policy: policy.clone(),
        limits,
        policy_digest,
        tracklet_report_digest: tracks.report_digest,
        input_digest: ContentDigest::sha256(&[]),
        cells: reserve(cell_count)?,
        frame_samples: reserve(sample_count)?,
        transitions: Vec::new(),
        work_units: 0,
        encoded_bytes: 0,
        report_digest: ContentDigest::sha256(&[]),
    };
    meter.charge(128)?;
    let mut input_encoding = CanonicalEncoder::new();
    input_encoding.text("fss.onvif_vendor_zone_input.v1");
    input_encoding.digest(tracks.report_digest);
    input_encoding.u64(inputs.len() as u64);
    input_encoding.u64(tracks.occurrences.len() as u64);
    for (ordinal, input) in inputs.iter().enumerate() {
        meter.charge(64 + zones as u64)?;
        input_encoding.u64(ordinal as u64);
        input_encoding.u64(input.frame.unsupported_extensions as u64);
        input_encoding.bool(input.uninterpreted_source);
        input_encoding.bool(unsupported_transform(input.frame.transformation.as_ref()));
        input_encoding.u64(input.frame.objects.len() as u64);
        let sample_start = report.frame_samples.len();
        for (zone_index, zone) in policy.zones.iter().enumerate() {
            report.frame_samples.push(ZoneFrameSample {
                zone_index,
                frame_ordinal: ordinal,
                basis_unavailable: frame_unavailable(input, tracks, ordinal, zone),
                inside: 0,
                outside: 0,
                boundary: 0,
                unavailable: 0,
            });
        }
        for (object_index, object) in input.frame.objects.iter().enumerate() {
            meter.charge(1)?;
            let occurrence_index = tracks.frames[ordinal]
                .occurrence_start
                .checked_add(object_index)
                .ok_or(ZoneError::InvalidInput)?;
            let occurrence = tracks
                .occurrences
                .get(occurrence_index)
                .ok_or(ZoneError::InvalidInput)?;
            if occurrence.frame_ordinal != ordinal || occurrence.object_index != object_index {
                return Err(ZoneError::InvalidInput);
            }
            input_encoding.digest(occurrence.identity);
            let claim = geometry_claim(object, &mut input_encoding, &mut meter)?;
            for (zone_index, zone) in policy.zones.iter().enumerate() {
                meter.charge(32)?;
                let sample = &mut report.frame_samples[sample_start + zone_index];
                let (relation, reason) = if let Some(reason) = sample.basis_unavailable {
                    (ZoneRelation::Unavailable, Some(reason))
                } else if let BoxClaim::Unavailable(reason) = claim {
                    (ZoneRelation::Unavailable, Some(reason))
                } else if occurrence.transformation_digest != zone.object_transform_digest {
                    (
                        ZoneRelation::Unavailable,
                        Some(ZoneUnavailable::ObjectTransformMismatch),
                    )
                } else if let BoxClaim::Available { min, max } = claim {
                    let relation =
                        geometry::classify_rectangle(min, max, zone.min, zone.max, zone.margin)
                            .map_err(|_| ZoneError::InvalidPolicy)?;
                    (
                        match relation {
                            RectangleRelation::Inside => ZoneRelation::Inside,
                            RectangleRelation::Outside => ZoneRelation::Outside,
                            RectangleRelation::Boundary => ZoneRelation::Boundary,
                        },
                        None,
                    )
                } else {
                    return Err(ZoneError::InvalidInput);
                };
                match relation {
                    ZoneRelation::Inside => sample.inside += 1,
                    ZoneRelation::Outside => sample.outside += 1,
                    ZoneRelation::Boundary => sample.boundary += 1,
                    ZoneRelation::Unavailable => sample.unavailable += 1,
                }
                let cell = ZoneCell {
                    zone_index,
                    occurrence_index,
                    frame_ordinal: ordinal,
                    relation,
                    reason,
                };
                let state = &mut states[by_occurrence[occurrence_index] * zones + zone_index];
                advance(&mut report, state, &cell, occurrence.tracklet_identity)?;
                report.cells.push(cell);
            }
        }
    }
    if report.cells.len() != cell_count || report.frame_samples.len() != sample_count {
        return Err(ZoneError::InvalidInput);
    }
    let bytes = input_encoding
        .finish_checked()
        .map_err(|_| ZoneError::Encoding)?;
    meter.charge(bytes.len() as u64)?;
    report.input_digest = ContentDigest::sha256(&bytes);
    drop(bytes);
    let size = report_size(&report)?;
    if size > limits.max_output_bytes {
        return Err(ZoneError::Limit);
    }
    // Admit the full canonical encoding and hash before constructing either, including on
    // the one-byte-short failure path. No report-size guess can authorize a larger output.
    meter.charge(
        (size as u64)
            .checked_mul(2)
            .ok_or(ZoneError::BudgetExceeded)?,
    )?;
    report.work_units = meter.used;
    report.encoded_bytes = size;
    let encoded = encode_report(&report, &mut meter)?;
    if encoded.len() != size {
        return Err(ZoneError::Encoding);
    }
    report.report_digest = ContentDigest::sha256(&encoded);
    meter.charge(0)?;
    Ok(report)
}

fn policy_size(policy: &ZonePolicy) -> Result<usize, ZoneError> {
    let mut size =
        8 + ZONE_POLICY_SCHEMA.len() + 8 + ZONE_GENERATION.len() + 8 + ZONE_COORDINATES.len() + 8;
    for zone in &policy.zones {
        size = size
            .checked_add(8 + zone.id.len() + 4 * 33 + 4 * 16 + 8)
            .ok_or(ZoneError::Limit)?;
    }
    Ok(size)
}
fn report_size(report: &ZoneReport) -> Result<usize, ZoneError> {
    // Text domains + three source/policy digests + five bounds + counts + final work counter.
    let mut size = 8
        + ZONE_REPORT_DOMAIN.len()
        + 8
        + ZONE_GENERATION.len()
        + 8
        + ZONE_COORDINATES.len()
        + 3 * 33
        + 5 * 8
        + 3 * 8
        + 8;
    size = size
        .checked_add(report.cells.len().checked_mul(26).ok_or(ZoneError::Limit)?)
        .ok_or(ZoneError::Limit)?;
    size = size
        .checked_add(
            report
                .frame_samples
                .len()
                .checked_mul(49)
                .ok_or(ZoneError::Limit)?,
        )
        .ok_or(ZoneError::Limit)?;
    for transition in &report.transitions {
        size = size
            .checked_add(51 + usize::from(transition.previous_occurrence.is_some()) * 8)
            .ok_or(ZoneError::Limit)?;
    }
    Ok(size)
}
fn encode_report<F: FnMut() -> bool>(
    report: &ZoneReport,
    meter: &mut Meter<F>,
) -> Result<Vec<u8>, ZoneError> {
    let mut e = CanonicalEncoder::new();
    e.text(ZONE_REPORT_DOMAIN);
    e.text(ZONE_GENERATION);
    e.text(ZONE_COORDINATES);
    for digest in [
        report.policy_digest,
        report.tracklet_report_digest,
        report.input_digest,
    ] {
        e.digest(digest);
    }
    for n in [
        report.limits.max_cells as u64,
        report.limits.max_frame_samples as u64,
        report.limits.max_transitions as u64,
        report.limits.max_work_units,
        report.limits.max_output_bytes as u64,
    ] {
        e.u64(n);
    }
    e.u64(report.cells.len() as u64);
    for cell in &report.cells {
        meter.charge(0)?;
        e.u64(cell.zone_index as u64);
        e.u64(cell.occurrence_index as u64);
        e.u64(cell.frame_ordinal as u64);
        e.u8(cell.relation as u8);
        e.u8(cell.reason.map_or(0, |reason| reason as u8));
    }
    e.u64(report.frame_samples.len() as u64);
    for sample in &report.frame_samples {
        meter.charge(0)?;
        e.u64(sample.zone_index as u64);
        e.u64(sample.frame_ordinal as u64);
        e.u8(sample.basis_unavailable.map_or(0, |reason| reason as u8));
        for count in [
            sample.inside,
            sample.outside,
            sample.boundary,
            sample.unavailable,
        ] {
            e.u64(count as u64);
        }
    }
    e.u64(report.transitions.len() as u64);
    for transition in &report.transitions {
        meter.charge(0)?;
        e.u64(transition.zone_index as u64);
        e.digest(transition.tracklet_identity);
        e.u8(transition.kind as u8);
        e.bool(transition.previous_occurrence.is_some());
        if let Some(previous) = transition.previous_occurrence {
            e.u64(previous as u64);
        }
        e.u64(transition.occurrence as u64);
    }
    e.u64(report.work_units);
    e.finish_checked().map_err(|_| ZoneError::Encoding)
}
