#![forbid(unsafe_code)]
//! Source-linked vendor lifecycle declarations over an unchanged tracklets-v1 report.
//!
//! This overlay explains integer ObjectTree endpoints and Idle/Removed declarations.
//! It never merges tracks, infers physical identity, treats Removed as Delete, or creates
//! event, coverage or effect authority. An observed endpoint means only that its integer
//! spelling matches a separately addressable current or immediately preceding module-frame
//! occurrence. Original source custody remains the retained owner's responsibility.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{CanonicalEncoder, ContentDigest, Plane, ProvenanceClass};

use crate::onvif::metadata::tracks::contract::{
    TrackError, TrackFrameInput, TrackFrameReference, TrackletReport, project_tracklets,
};
use crate::onvif::wire::{
    AnalyticsAppearance, AnalyticsFrame, AnalyticsTransformation, LifecycleFrame,
    LifecycleOperationKind, LifecycleReference, analytics_object_key,
};

/// Independent interpretation; the original tracks-v1 generation and bytes are unchanged.
pub const LIFECYCLE_GENERATION: &str = "gen:fss1:onvif-vendor-lineage-v1";
/// Canonical complete lifecycle-overlay domain.
pub const LIFECYCLE_REPORT_DOMAIN: &str = "fss.onvif_vendor_lineage_report.v1";
/// Aggregate supplied frame ceiling, including frames without lifecycle statements.
pub const MAX_LIFECYCLE_FRAMES: usize = 1024;
/// Aggregate original object occurrence ceiling.
pub const MAX_LIFECYCLE_OBJECTS: usize = 4096;
/// Aggregate recognized operation ceiling across all source documents.
pub const MAX_LIFECYCLE_OPERATIONS: usize = 1024;
/// Aggregate operation-endpoint ceiling, separately from original object occurrences.
pub const MAX_LIFECYCLE_REFERENCES: usize = 4096;
/// Complete canonical projection ceiling.
pub const MAX_LIFECYCLE_REPORT_BYTES: usize = 4 * 1024 * 1024;
/// Hard nonrenewing logical-work ceiling, not elapsed CPU time.
pub const MAX_LIFECYCLE_WORK_UNITS: u64 = 16 * 1024 * 1024;

/// Finite association and output policy. The existing tracklet policy supplies the time gap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleLimits {
    /// All accepted input frames, including zero-statement frames.
    pub max_frames: usize,
    /// All original object descriptions, including those without Behaviour.
    pub max_objects: usize,
    /// All Rename/Split/Merge/Delete statements, without coalescing.
    pub max_operations: usize,
    /// All from/to endpoint occurrences, including unsupported and repeated references.
    pub max_references: usize,
    /// One cumulative logical item/byte allowance for this complete call.
    pub max_work_units: u64,
    /// Complete canonical bytes; refusal returns no successful prefix.
    pub max_output_bytes: usize,
}

impl Default for LifecycleLimits {
    fn default() -> Self {
        Self {
            max_frames: MAX_LIFECYCLE_FRAMES,
            max_objects: MAX_LIFECYCLE_OBJECTS,
            max_operations: MAX_LIFECYCLE_OPERATIONS,
            max_references: MAX_LIFECYCLE_REFERENCES,
            max_work_units: 4_000_000,
            max_output_bytes: MAX_LIFECYCLE_REPORT_BYTES,
        }
    }
}

impl LifecycleLimits {
    /// Check all resource ceilings before traversal or allocation.
    pub fn validate(self) -> Result<(), LifecycleError> {
        if !(1..=MAX_LIFECYCLE_FRAMES).contains(&self.max_frames)
            || !(1..=MAX_LIFECYCLE_OBJECTS).contains(&self.max_objects)
            || !(1..=MAX_LIFECYCLE_OPERATIONS).contains(&self.max_operations)
            || !(1..=MAX_LIFECYCLE_REFERENCES).contains(&self.max_references)
            || !(1..=MAX_LIFECYCLE_WORK_UNITS).contains(&self.max_work_units)
            || !(1..=MAX_LIFECYCLE_REPORT_BYTES).contains(&self.max_output_bytes)
        {
            return Err(LifecycleError::InvalidLimits);
        }
        Ok(())
    }

    /// Bind this generation and every declared ceiling.
    pub fn digest(self) -> Result<ContentDigest, LifecycleError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text("fss.onvif_vendor_lineage_policy.v1");
        e.text(LIFECYCLE_GENERATION);
        for value in [
            self.max_frames,
            self.max_objects,
            self.max_operations,
            self.max_references,
            self.max_output_bytes,
        ] {
            e.u64(value as u64);
        }
        e.u64(self.max_work_units);
        Ok(ContentDigest::sha256(
            &e.finish_checked().map_err(|_| LifecycleError::Encoding)?,
        ))
    }
}

/// One overlay frame selected from the same owner-verified original document as tracks-v1.
#[derive(Clone, Copy, Debug)]
pub struct LifecycleFrameInput<'a> {
    /// Exact position in the paired complete tracklet report.
    pub frame_ordinal: usize,
    /// Exact original XML digest, not the RTP replay-file digest.
    pub source_digest: ContentDigest,
    /// Independent additive interpretation of that original XML frame.
    pub frame: &'a LifecycleFrame,
    /// Opaque outer source/lifecycle content makes cross-frame endpoint matching unavailable.
    pub uninterpreted_source: bool,
}

/// Why no earlier module frame can support endpoints across this boundary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LifecycleBoundary {
    /// Explicit source boundary or discontinuous original locator.
    SourceBoundary,
    /// Sensor/device/profile/parser/transport scope changed.
    GenerationChanged,
    /// No nonempty named module namespace exists.
    MissingModule,
    /// Uninterpreted content can affect lifecycle or coordinate semantics.
    UninterpretedContent,
    /// Vendor time did not strictly increase.
    VendorTimeNotIncreasing,
    /// Vendor time exceeded the unchanged tracklet gap policy.
    VendorTimeGap,
    /// Frame coordinate claims changed.
    FrameTransformChanged,
}
impl LifecycleBoundary {
    /// Stable bounded report spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceBoundary => "source_boundary",
            Self::GenerationChanged => "generation_changed",
            Self::MissingModule => "missing_module",
            Self::UninterpretedContent => "uninterpreted_content",
            Self::VendorTimeNotIncreasing => "vendor_time_not_increasing",
            Self::VendorTimeGap => "vendor_time_gap",
            Self::FrameTransformChanged => "frame_transform_changed",
        }
    }
}

/// Record-level endpoint support, never the truth of a vendor relationship or physical identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleEndpointState {
    /// Matching source occurrences exist under this bounded interpretation.
    Observed,
    /// Required support or supported lifecycle meaning is unavailable.
    Unresolved,
    /// The supported local-ID interpretation has incompatible uses or a deletion/reuse conflict.
    Conflicted,
}
impl LifecycleEndpointState {
    /// Stable report spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Unresolved => "unresolved",
            Self::Conflicted => "conflicted",
        }
    }
}

/// A reason an endpoint cannot be treated as uniquely supported in this conservative subset.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LifecycleIssue {
    /// Missing integer, UUID or unrecognized reference fields; UUIDs are never matched.
    UnsupportedReference,
    /// Uninterpreted surrounding frame/source content prevents a lifecycle interpretation.
    OpaqueContent,
    /// No eligible original observation supports this role.
    NoObservation,
    /// One side repeats the same integer, including signed/zero-padded aliases.
    RepeatedReference,
    /// Multiple operations consume or produce the same local integer in one frame.
    CompetingOperations,
    /// The same operation both consumes and produces this local integer.
    SourceDestinationOverlap,
    /// A destination already occurred in the immediately preceding module frame.
    DestinationPreexists,
    /// A current occurrence reuses an integer after a vendor Delete in this unbroken scope.
    DeletedIdReused,
    /// Different operations use this integer on opposite sides; intermediate state is not simulated.
    SequentialDependency,
    /// Matching current/prior integer occurrences changed their relative coordinate claim.
    ObjectTransformChanged,
}
impl LifecycleIssue {
    /// Stable report spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedReference => "unsupported_reference",
            Self::OpaqueContent => "opaque_content",
            Self::NoObservation => "no_observation",
            Self::RepeatedReference => "repeated_reference",
            Self::CompetingOperations => "competing_operations",
            Self::SourceDestinationOverlap => "source_destination_overlap",
            Self::DestinationPreexists => "destination_preexists",
            Self::DeletedIdReused => "deleted_id_reused",
            Self::SequentialDependency => "sequential_dependency",
            Self::ObjectTransformChanged => "object_transform_changed",
        }
    }
    const fn conflict(self) -> bool {
        matches!(
            self,
            Self::RepeatedReference
                | Self::CompetingOperations
                | Self::SourceDestinationOverlap
                | Self::DestinationPreexists
                | Self::DeletedIdReused
        )
    }
}

/// Exact frame relationship of an original observation to one lifecycle declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleObservationBasis {
    /// The object was explicitly described in the declaration's frame.
    CurrentFrame,
    /// The object was described in the immediately preceding frame of the same named module.
    PreviousModuleFrame,
}
impl LifecycleObservationBasis {
    /// Stable report spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CurrentFrame => "current_frame",
            Self::PreviousModuleFrame => "previous_module_frame",
        }
    }
}

/// Exact reference into the unchanged original tracklet report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleOccurrenceRef {
    /// Explicit temporal basis, without interpolation or identity stitching.
    pub basis: LifecycleObservationBasis,
    /// Original occurrence row index in tracks-v1.
    pub occurrence_ordinal: usize,
    /// Original occurrence identity, unchanged by this overlay.
    pub occurrence_identity: ContentDigest,
    /// Original tracklets-v1 run identity, never rewritten or merged.
    pub tracklet_identity: ContentDigest,
    /// Frame row index; the lifecycle frame table retains exact source coordinates.
    pub frame_ordinal: usize,
    /// Original object position in that source frame.
    pub object_index: usize,
}

/// One source-order endpoint declaration and its finite support.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleEndpoint {
    /// Original private integer/UUID lexemes; Debug redacts both and UUIDs are never matched.
    pub reference: LifecycleReference,
    /// Record-level support classification.
    pub state: LifecycleEndpointState,
    /// At most current and immediately previous module-frame occurrences, in that order.
    pub observations: Vec<LifecycleOccurrenceRef>,
    /// All applicable reasons in stable order.
    pub issues: Vec<LifecycleIssue>,
}

/// One original ObjectTree operation, without simulation of an evolving physical identity table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleOperationRow {
    /// Exact source/frame/tree-operation commitment.
    pub identity: ContentDigest,
    /// Original frame table position.
    pub frame_ordinal: usize,
    /// Original recognized operation ordinal in this frame.
    pub operation_index: usize,
    /// Original ObjectTree child position, including unknown siblings.
    pub tree_child_index: usize,
    /// Rename, Split, Merge or Delete as declared by the vendor.
    pub kind: LifecycleOperationKind,
    /// Exact source-order from references; Delete has one.
    pub from: Vec<LifecycleEndpoint>,
    /// Exact source-order to references; Delete has none.
    pub to: Vec<LifecycleEndpoint>,
    /// Conflicted dominates unresolved, which dominates observed endpoint support.
    pub state: LifecycleEndpointState,
    /// Original unsupported operation field count.
    pub unsupported_extensions: usize,
}

/// A present Behaviour container. Idle and Removed remain separate vendor claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleBehaviourRow {
    /// Exact original Behaviour occurrence commitment.
    pub identity: ContentDigest,
    /// Exact original object occurrence; no new track identity is allocated.
    pub occurrence: LifecycleOccurrenceRef,
    /// Original child position of the Object within its frame.
    pub frame_child_index: usize,
    /// Original private reference, redacted in Debug.
    pub reference: LifecycleReference,
    /// Vendor Idle marker presence.
    pub idle: bool,
    /// Vendor Removed marker presence; never treated as Delete or physical absence.
    pub removed: bool,
    /// Original uninterpreted Behaviour fields.
    pub unsupported_extensions: usize,
    /// Record-level applicability, without classifying physical behavior.
    pub state: LifecycleEndpointState,
    /// All applicable reasons.
    pub issues: Vec<LifecycleIssue>,
}

/// A later integer occurrence after an explicit vendor Delete in the same unbroken scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleReuse {
    /// Exact deletion/occurrence pair commitment.
    pub identity: ContentDigest,
    /// Original Delete declaration identity, even when its endpoint had no observation.
    pub deleted_by_operation: ContentDigest,
    /// Original frame containing that Delete declaration.
    pub deleted_at_frame: usize,
    /// New occurrence of the same local integer, not a resurrection or physical-identity claim.
    pub occurrence: LifecycleOccurrenceRef,
}

/// Complete original frame accounting and source navigation for this overlay.
#[derive(Clone, Eq, PartialEq)]
pub struct LifecycleFrameRow {
    /// Unmodified source/frame coordinates from the paired tracklets-v1 report.
    pub reference: TrackFrameReference,
    /// Original VideoAnalytics source-child position.
    pub section_index: usize,
    /// Original frame position within its VideoAnalytics section.
    pub section_child_index: usize,
    /// Present-empty ObjectTree remains different from missing.
    pub object_tree_child_index: Option<usize>,
    /// Original private module name; presentation requires explicit disclosure.
    pub module_source: Option<String>,
    /// Original vendor UTC spelling, not a physical clock.
    pub vendor_utc_time: String,
    /// Original tracklets-v1 occurrence range start.
    pub occurrence_start: usize,
    /// Number of original objects in this frame.
    pub occurrence_count: usize,
    /// First lifecycle operation row for this frame.
    pub operation_start: usize,
    /// Number of source operation rows.
    pub operation_count: usize,
    /// First Behaviour row for this frame.
    pub behaviour_start: usize,
    /// Number of present Behaviour containers, including present-empty containers.
    pub behaviour_count: usize,
    /// Barriers considered by this overlay; unchanged tracks-v1 barriers remain separately bound.
    pub barriers: Vec<LifecycleBoundary>,
}
impl fmt::Debug for LifecycleFrameRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LifecycleFrameRow")
            .field("reference", &self.reference)
            .field("operation_count", &self.operation_count)
            .field("behaviour_count", &self.behaviour_count)
            .field("barriers", &self.barriers)
            .finish_non_exhaustive()
    }
}

/// Complete finite source-linked overlay; original tracklets are preserved unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleReport {
    /// Exact declared limits.
    pub limits: LifecycleLimits,
    /// Frozen policy identity.
    pub policy_digest: ContentDigest,
    /// Complete overlay/source input identity.
    pub input_digest: ContentDigest,
    /// Exact original tracks-v1 report used for every occurrence reference.
    pub tracklet_report_digest: ContentDigest,
    /// Every original accepted frame, including frames without lifecycle declarations.
    pub frames: Vec<LifecycleFrameRow>,
    /// Every recognized operation in source order.
    pub operations: Vec<LifecycleOperationRow>,
    /// Every present Behaviour container in source order.
    pub behaviours: Vec<LifecycleBehaviourRow>,
    /// Every observed reuse after an explicit vendor Delete within an unbroken local scope.
    pub reuses: Vec<LifecycleReuse>,
    /// Deterministic item and canonical encode/hash-byte work admitted for this call.
    pub work_units: u64,
    /// Exact complete canonical report size.
    pub encoded_bytes: usize,
    /// Complete report commitment, excluding self-digest and encoded-byte bookkeeping.
    pub report_digest: ContentDigest,
}
impl LifecycleReport {
    /// The overlay is cognition only.
    pub const fn plane(&self) -> Plane {
        Plane::Cognition
    }
    /// Endpoint matching is a deterministic derivation.
    pub const fn provenance(&self) -> ProvenanceClass {
        ProvenanceClass::Derived
    }
    /// All operation and Behaviour leaves remain vendor claims.
    pub const fn source_provenance(&self) -> ProvenanceClass {
        ProvenanceClass::VendorClaimed
    }
}

/// Payload-free atomic refusal; no successful partial report is released.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    /// Invalid or widened limits.
    InvalidLimits,
    /// Overlay and original source/report disagree or a public parser value was mutated.
    InvalidInput,
    /// Aggregate shape or output capacity exceeded.
    Limit,
    /// The complete logical work allowance was exhausted.
    BudgetExceeded,
    /// Owner admission was withdrawn.
    Cancelled,
    /// Canonical encoding failed.
    Encoding,
}
impl LifecycleError {
    /// Stable error identity without private source data.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidLimits => "ERR-ONVIF-LINEAGE-CONFIG-001",
            Self::InvalidInput => "ERR-ONVIF-LINEAGE-INPUT-001",
            Self::Limit => "ERR-ONVIF-LINEAGE-LIMIT-001",
            Self::BudgetExceeded => "ERR-ONVIF-LINEAGE-BUDGET-001",
            Self::Cancelled => "ERR-ONVIF-LINEAGE-CANCELLED-001",
            Self::Encoding => "ERR-ONVIF-LINEAGE-ENCODING-001",
        }
    }
}
impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for LifecycleError {}

struct Meter<F> {
    admitted: F,
    used: u64,
    maximum: u64,
}
impl<F: FnMut() -> bool> Meter<F> {
    fn charge(&mut self, units: u64) -> Result<(), LifecycleError> {
        if !(self.admitted)() {
            return Err(LifecycleError::Cancelled);
        }
        let total = self
            .used
            .checked_add(units)
            .ok_or(LifecycleError::BudgetExceeded)?;
        if total > self.maximum {
            return Err(LifecycleError::BudgetExceeded);
        }
        self.used = total;
        Ok(())
    }
}

/// Every field is admitted before its canonical allocation and future hash work.
struct Encoder<'a, F> {
    e: CanonicalEncoder,
    bytes: usize,
    maximum: usize,
    meter: &'a mut Meter<F>,
}
impl<'a, F: FnMut() -> bool> Encoder<'a, F> {
    fn new(meter: &'a mut Meter<F>, maximum: usize) -> Self {
        Self {
            e: CanonicalEncoder::new(),
            bytes: 0,
            maximum,
            meter,
        }
    }
    fn admit(&mut self, bytes: usize) -> Result<(), LifecycleError> {
        let total = self.bytes.checked_add(bytes).ok_or(LifecycleError::Limit)?;
        if total > self.maximum {
            return Err(LifecycleError::Limit);
        }
        self.meter.charge(
            (bytes as u64)
                .checked_mul(2)
                .ok_or(LifecycleError::BudgetExceeded)?,
        )?;
        self.bytes = total;
        Ok(())
    }
    fn text(&mut self, value: &str) -> Result<(), LifecycleError> {
        self.admit(8 + value.len())?;
        self.e.text(value);
        Ok(())
    }
    fn u64(&mut self, value: usize) -> Result<(), LifecycleError> {
        self.admit(8)?;
        self.e.u64(value as u64);
        Ok(())
    }
    fn bool(&mut self, value: bool) -> Result<(), LifecycleError> {
        self.admit(1)?;
        self.e.bool(value);
        Ok(())
    }
    fn digest(&mut self, value: ContentDigest) -> Result<(), LifecycleError> {
        self.admit(33)?;
        self.e.digest(value);
        Ok(())
    }
    fn optional_text(&mut self, value: Option<&str>) -> Result<(), LifecycleError> {
        self.bool(value.is_some())?;
        if let Some(value) = value {
            self.text(value)?;
        }
        Ok(())
    }
    fn optional_index(&mut self, value: Option<usize>) -> Result<(), LifecycleError> {
        self.bool(value.is_some())?;
        if let Some(value) = value {
            self.u64(value)?;
        }
        Ok(())
    }
    fn reference(&mut self, value: &LifecycleReference) -> Result<(), LifecycleError> {
        self.optional_text(value.object_id.as_deref())?;
        self.optional_text(value.uuid.as_deref())?;
        self.u64(value.unsupported_extensions)
    }
    fn source(&mut self, value: &TrackFrameReference) -> Result<(), LifecycleError> {
        self.u64(value.ordinal)?;
        for digest in [
            value.scope,
            value.source_identity,
            value.source_root,
            value.source_digest,
            value.frame_digest,
        ] {
            self.digest(digest)?;
        }
        self.u64(value.document_index)?;
        self.u64(value.frame_index)
    }
    fn occurrence(&mut self, value: &LifecycleOccurrenceRef) -> Result<(), LifecycleError> {
        self.text(value.basis.as_str())?;
        self.u64(value.occurrence_ordinal)?;
        self.digest(value.occurrence_identity)?;
        self.digest(value.tracklet_identity)?;
        self.u64(value.frame_ordinal)?;
        self.u64(value.object_index)
    }
    fn issues(&mut self, values: &[LifecycleIssue]) -> Result<(), LifecycleError> {
        self.u64(values.len())?;
        for value in values {
            self.text(value.as_str())?;
        }
        Ok(())
    }
    fn endpoint(&mut self, value: &LifecycleEndpoint) -> Result<(), LifecycleError> {
        self.reference(&value.reference)?;
        self.text(value.state.as_str())?;
        self.u64(value.observations.len())?;
        for observation in &value.observations {
            self.occurrence(observation)?;
        }
        self.issues(&value.issues)
    }
    fn finish(self) -> Result<(ContentDigest, usize), LifecycleError> {
        let bytes = self
            .e
            .finish_checked()
            .map_err(|_| LifecycleError::Encoding)?;
        if bytes.len() != self.bytes {
            return Err(LifecycleError::Encoding);
        }
        Ok((ContentDigest::sha256(&bytes), bytes.len()))
    }
    fn finish_report(mut self) -> Result<(ContentDigest, usize, u64), LifecycleError> {
        self.admit(8)?;
        let work = self.meter.used;
        self.e.u64(work);
        let (digest, bytes) = self.finish()?;
        Ok((digest, bytes, work))
    }
}

struct CheckedFrame {
    keys: Vec<String>,
    operation_keys: Vec<(Vec<Option<String>>, Vec<Option<String>>)>,
    opaque: bool,
}
#[derive(Clone, Copy)]
struct DeleteClaim {
    identity: ContentDigest,
    frame: usize,
}
struct ModuleState {
    time: i128,
    transformation: ContentDigest,
    objects: BTreeMap<String, usize>,
    deleted: BTreeMap<String, DeleteClaim>,
}

fn label<F: FnMut() -> bool>(
    value: &str,
    maximum: usize,
    meter: &mut Meter<F>,
) -> Result<(), LifecycleError> {
    if value.len() > maximum {
        return Err(LifecycleError::InvalidInput);
    }
    meter.charge(value.len() as u64 + 1)?;
    if value.chars().any(char::is_control) {
        return Err(LifecycleError::InvalidInput);
    }
    Ok(())
}
fn reference_key<F: FnMut() -> bool>(
    value: &LifecycleReference,
    meter: &mut Meter<F>,
) -> Result<Option<String>, LifecycleError> {
    let key = value
        .object_id
        .as_deref()
        .map(|value| {
            label(value, 64, meter)?;
            analytics_object_key(value).map_err(|_| LifecycleError::InvalidInput)
        })
        .transpose()?;
    if let Some(uuid) = &value.uuid {
        label(uuid, 256, meter)?;
    }
    Ok(key)
}

fn unknown_transform(value: &AnalyticsTransformation) -> bool {
    value.unsupported_extensions != 0
        || value
            .translate
            .as_ref()
            .is_some_and(|v| v.unsupported_extensions != 0)
        || value
            .scale
            .as_ref()
            .is_some_and(|v| v.unsupported_extensions != 0)
}
fn unknown_appearance(value: &AnalyticsAppearance) -> bool {
    value.unsupported_extensions != 0
        || value.transformation.as_ref().is_some_and(unknown_transform)
        || value.shape.as_ref().is_some_and(|v| {
            v.unsupported_extensions != 0
                || v.bounding_box.unsupported_extensions != 0
                || v.center_of_gravity.unsupported_extensions != 0
        })
        || value.class.as_ref().is_some_and(|v| {
            v.unsupported_extensions != 0
                || v.candidates
                    .iter()
                    .any(|candidate| candidate.unsupported_extensions != 0)
        })
}
fn opaque(frame: &AnalyticsFrame, overlay: &LifecycleFrame) -> Result<bool, LifecycleError> {
    let known_tree = usize::from(overlay.object_tree_child_index.is_some());
    if frame.unsupported_extensions < known_tree {
        return Err(LifecycleError::InvalidInput);
    }
    let mut unknown = overlay.has_unsupported_content()
        || frame.unsupported_extensions != known_tree
        || frame.transformation.as_ref().is_some_and(unknown_transform);
    for (object, lifecycle) in frame.objects.iter().zip(&overlay.objects) {
        let known_behaviour = usize::from(lifecycle.behaviour.is_some());
        if object.unsupported_extensions < known_behaviour {
            return Err(LifecycleError::InvalidInput);
        }
        unknown |= object.unsupported_extensions != known_behaviour
            || object.appearance.as_ref().is_some_and(unknown_appearance);
    }
    Ok(unknown)
}

fn state(issues: &[LifecycleIssue]) -> LifecycleEndpointState {
    if issues.iter().any(|issue| issue.conflict()) {
        LifecycleEndpointState::Conflicted
    } else if issues.is_empty() {
        LifecycleEndpointState::Observed
    } else {
        LifecycleEndpointState::Unresolved
    }
}
fn occurrence(
    report: &TrackletReport,
    index: usize,
    basis: LifecycleObservationBasis,
) -> LifecycleOccurrenceRef {
    let value = &report.occurrences[index];
    LifecycleOccurrenceRef {
        basis,
        occurrence_ordinal: index,
        occurrence_identity: value.identity,
        tracklet_identity: value.tracklet_identity,
        frame_ordinal: value.frame_ordinal,
        object_index: value.object_index,
    }
}

fn valid_cardinality(kind: LifecycleOperationKind, from: usize, to: usize) -> bool {
    match kind {
        LifecycleOperationKind::Rename => from == 1 && to == 1,
        LifecycleOperationKind::Split => from == 1 && to >= 2,
        LifecycleOperationKind::Merge => from >= 2 && to == 1,
        LifecycleOperationKind::Delete => from == 1 && to == 0,
    }
}

fn check_overlays<F: FnMut() -> bool>(
    sources: &[TrackFrameInput<'_>],
    overlays: &[LifecycleFrameInput<'_>],
    limits: LifecycleLimits,
    meter: &mut Meter<F>,
) -> Result<Vec<CheckedFrame>, LifecycleError> {
    if sources.len() != overlays.len() {
        return Err(LifecycleError::InvalidInput);
    }
    let mut object_count = 0usize;
    let mut operation_count = 0usize;
    let mut reference_count = 0usize;
    // Counts are admitted before cloning any raw reference or allocating per-object rows.
    for (source, overlay) in sources.iter().zip(overlays) {
        meter.charge(1)?;
        object_count = object_count
            .checked_add(overlay.frame.objects.len())
            .ok_or(LifecycleError::Limit)?;
        operation_count = operation_count
            .checked_add(overlay.frame.operations.len())
            .ok_or(LifecycleError::Limit)?;
        if object_count > limits.max_objects || operation_count > limits.max_operations {
            return Err(LifecycleError::Limit);
        }
        if source.frame.objects.len() != overlay.frame.objects.len() {
            return Err(LifecycleError::InvalidInput);
        }
        for operation in &overlay.frame.operations {
            meter.charge(1)?;
            reference_count = reference_count
                .checked_add(operation.from.len())
                .and_then(|v| v.checked_add(operation.to.len()))
                .ok_or(LifecycleError::Limit)?;
            if reference_count > limits.max_references {
                return Err(LifecycleError::Limit);
            }
        }
    }
    let mut checked = Vec::with_capacity(sources.len());
    for (ordinal, (source, overlay)) in sources.iter().zip(overlays).enumerate() {
        meter.charge(64)?;
        let frame = overlay.frame;
        if overlay.frame_ordinal != ordinal
            || overlay.source_digest != source.source_digest
            || frame.frame_index != source.frame_index
            || frame.utc_time != source.frame.utc_time
            || frame.source != source.frame.source
            || frame.section_index >= 4096
            || frame.section_child_index >= 4096
            || frame.object_tree_child_index.is_some_and(|v| v >= 4096)
            || (!frame.operations.is_empty() && frame.object_tree_child_index.is_none())
        {
            return Err(LifecycleError::InvalidInput);
        }
        label(&frame.utc_time, 30, meter)?;
        if let Some(module) = &frame.source {
            label(module, 256, meter)?;
        }
        let mut keys = Vec::with_capacity(frame.objects.len());
        let mut previous_child = None;
        for (object_index, (original, object)) in
            source.frame.objects.iter().zip(&frame.objects).enumerate()
        {
            meter.charge(64)?;
            if object.object_index != object_index
                || object.frame_child_index >= 4096
                || previous_child.is_some_and(|previous| object.frame_child_index <= previous)
                || frame.object_tree_child_index == Some(object.frame_child_index)
                || object.reference.object_id.as_deref() != Some(original.object_id.as_str())
            {
                return Err(LifecycleError::InvalidInput);
            }
            previous_child = Some(object.frame_child_index);
            keys.push(
                reference_key(&object.reference, meter)?.ok_or(LifecycleError::InvalidInput)?,
            );
        }
        let mut operation_keys = Vec::with_capacity(frame.operations.len());
        previous_child = None;
        for (index, operation) in frame.operations.iter().enumerate() {
            meter.charge(64)?;
            if operation.operation_index != index
                || operation.tree_child_index >= 4096
                || previous_child.is_some_and(|previous| operation.tree_child_index <= previous)
                || !valid_cardinality(operation.kind, operation.from.len(), operation.to.len())
            {
                return Err(LifecycleError::InvalidInput);
            }
            previous_child = Some(operation.tree_child_index);
            let mut sides = (
                Vec::with_capacity(operation.from.len()),
                Vec::with_capacity(operation.to.len()),
            );
            for (references, keys) in [
                (&operation.from, &mut sides.0),
                (&operation.to, &mut sides.1),
            ] {
                for reference in references {
                    meter.charge(64)?;
                    let key = reference_key(reference, meter)?;
                    keys.push(if reference.is_supported() { key } else { None });
                }
            }
            operation_keys.push(sides);
        }
        checked.push(CheckedFrame {
            keys,
            operation_keys,
            opaque: opaque(source.frame, frame)?
                || source.uninterpreted_source
                || overlay.uninterpreted_source,
        });
    }
    Ok(checked)
}

fn input_identity<F: FnMut() -> bool>(
    tracks: &TrackletReport,
    sources: &[TrackFrameInput<'_>],
    overlays: &[LifecycleFrameInput<'_>],
    meter: &mut Meter<F>,
) -> Result<ContentDigest, LifecycleError> {
    let mut e = Encoder::new(meter, MAX_LIFECYCLE_REPORT_BYTES);
    e.text("fss.onvif_vendor_lineage_inputs.v1")?;
    e.text(LIFECYCLE_GENERATION)?;
    e.digest(tracks.report_digest)?;
    e.u64(sources.len())?;
    for ((source, overlay), summary) in sources.iter().zip(overlays).zip(&tracks.frames) {
        let frame = overlay.frame;
        e.source(&summary.reference)?;
        e.bool(source.boundary_before)?;
        e.bool(source.uninterpreted_source)?;
        e.bool(overlay.uninterpreted_source)?;
        e.u64(frame.section_index)?;
        e.u64(frame.section_child_index)?;
        e.optional_index(frame.object_tree_child_index)?;
        e.text(&frame.utc_time)?;
        e.optional_text(frame.source.as_deref())?;
        e.u64(frame.unsupported_extensions)?;
        e.u64(frame.objects.len())?;
        for object in &frame.objects {
            e.u64(object.object_index)?;
            e.u64(object.frame_child_index)?;
            e.reference(&object.reference)?;
            e.u64(object.unsupported_extensions)?;
            e.bool(object.behaviour.is_some())?;
            if let Some(behaviour) = object.behaviour {
                e.bool(behaviour.idle)?;
                e.bool(behaviour.removed)?;
                e.u64(behaviour.unsupported_extensions)?;
            }
        }
        e.u64(frame.operations.len())?;
        for operation in &frame.operations {
            e.u64(operation.operation_index)?;
            e.u64(operation.tree_child_index)?;
            e.text(operation.kind.as_str())?;
            e.u64(operation.unsupported_extensions)?;
            for references in [&operation.from, &operation.to] {
                e.u64(references.len())?;
                for reference in references {
                    e.reference(reference)?;
                }
            }
        }
    }
    Ok(e.finish()?.0)
}

fn operation_identity<F: FnMut() -> bool>(
    source: &TrackFrameReference,
    tree_child: usize,
    operation: &crate::onvif::wire::LifecycleOperation,
    meter: &mut Meter<F>,
) -> Result<ContentDigest, LifecycleError> {
    let mut e = Encoder::new(meter, MAX_LIFECYCLE_REPORT_BYTES);
    e.text("fss.onvif_vendor_lineage_operation.v1")?;
    e.source(source)?;
    e.u64(tree_child)?;
    e.u64(operation.operation_index)?;
    e.u64(operation.tree_child_index)?;
    e.text(operation.kind.as_str())?;
    e.u64(operation.unsupported_extensions)?;
    for references in [&operation.from, &operation.to] {
        e.u64(references.len())?;
        for reference in references {
            e.reference(reference)?;
        }
    }
    Ok(e.finish()?.0)
}

fn behaviour_identity<F: FnMut() -> bool>(
    source: &TrackFrameReference,
    object: &crate::onvif::wire::LifecycleObject,
    behaviour: crate::onvif::wire::LifecycleBehaviour,
    meter: &mut Meter<F>,
) -> Result<ContentDigest, LifecycleError> {
    let mut e = Encoder::new(meter, MAX_LIFECYCLE_REPORT_BYTES);
    e.text("fss.onvif_vendor_lineage_behaviour.v1")?;
    e.source(source)?;
    e.u64(object.object_index)?;
    e.u64(object.frame_child_index)?;
    e.reference(&object.reference)?;
    e.bool(behaviour.idle)?;
    e.bool(behaviour.removed)?;
    e.u64(behaviour.unsupported_extensions)?;
    Ok(e.finish()?.0)
}

fn reuse_identity<F: FnMut() -> bool>(
    deleted: DeleteClaim,
    observation: &LifecycleOccurrenceRef,
    meter: &mut Meter<F>,
) -> Result<ContentDigest, LifecycleError> {
    let mut e = Encoder::new(meter, 1024);
    e.text("fss.onvif_vendor_lineage_reuse.v1")?;
    e.digest(deleted.identity)?;
    e.u64(deleted.frame)?;
    e.occurrence(observation)?;
    Ok(e.finish()?.0)
}

struct EndpointContext<'a> {
    tracks: &'a TrackletReport,
    current: &'a BTreeMap<String, usize>,
    previous: &'a BTreeMap<String, usize>,
    deleted: &'a BTreeMap<String, DeleteClaim>,
    from_uses: &'a BTreeMap<String, usize>,
    to_uses: &'a BTreeMap<String, usize>,
    opaque: bool,
}

fn resolve_endpoint<F: FnMut() -> bool>(
    reference: &LifecycleReference,
    key: Option<&str>,
    destination: bool,
    permits_self_endpoint: bool,
    own_side: &BTreeMap<String, usize>,
    opposite_side: &BTreeMap<String, usize>,
    context: &EndpointContext<'_>,
    meter: &mut Meter<F>,
) -> Result<LifecycleEndpoint, LifecycleError> {
    meter.charge(64)?;
    let mut issues = BTreeSet::new();
    let mut observations = Vec::new();
    if context.opaque {
        issues.insert(LifecycleIssue::OpaqueContent);
    }
    if let Some(key) = key {
        let current = context.current.get(key);
        let previous = context.previous.get(key);
        if let Some(index) = current {
            observations.push(occurrence(
                context.tracks,
                *index,
                LifecycleObservationBasis::CurrentFrame,
            ));
        }
        if let Some(index) = previous {
            observations.push(occurrence(
                context.tracks,
                *index,
                LifecycleObservationBasis::PreviousModuleFrame,
            ));
        }
        if let (Some(current), Some(previous)) = (current, previous) {
            if context.tracks.occurrences[*current].transformation_digest
                != context.tracks.occurrences[*previous].transformation_digest
            {
                issues.insert(LifecycleIssue::ObjectTransformChanged);
            }
        }
        if current.is_none() && (destination || previous.is_none()) {
            issues.insert(LifecycleIssue::NoObservation);
        }
        if own_side.get(key).copied().unwrap_or(0) > 1 {
            issues.insert(LifecycleIssue::RepeatedReference);
        }
        if opposite_side.contains_key(key) && !permits_self_endpoint {
            issues.insert(LifecycleIssue::SourceDestinationOverlap);
        }
        let (same_uses, opposite_uses) = if destination {
            (context.to_uses, context.from_uses)
        } else {
            (context.from_uses, context.to_uses)
        };
        if same_uses.get(key).copied().unwrap_or(0) > own_side.get(key).copied().unwrap_or(0) {
            issues.insert(LifecycleIssue::CompetingOperations);
        }
        if opposite_uses.contains_key(key) && !opposite_side.contains_key(key) {
            issues.insert(LifecycleIssue::SequentialDependency);
        }
        if destination
            && previous.is_some()
            && !(permits_self_endpoint && opposite_side.contains_key(key))
        {
            issues.insert(LifecycleIssue::DestinationPreexists);
        }
        if context.deleted.contains_key(key) && (current.is_some() || previous.is_some()) {
            issues.insert(LifecycleIssue::DeletedIdReused);
        }
    } else {
        issues.insert(LifecycleIssue::UnsupportedReference);
    }
    let issues: Vec<_> = issues.into_iter().collect();
    Ok(LifecycleEndpoint {
        reference: reference.clone(),
        state: state(&issues),
        observations,
        issues,
    })
}

fn key_counts(keys: &[Option<String>]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for key in keys.iter().flatten() {
        *counts.entry(key.clone()).or_insert(0) += 1;
    }
    counts
}

fn encode_report<F: FnMut() -> bool>(
    report: &LifecycleReport,
    meter: &mut Meter<F>,
) -> Result<(ContentDigest, usize, u64), LifecycleError> {
    let mut e = Encoder::new(meter, report.limits.max_output_bytes);
    e.text(LIFECYCLE_REPORT_DOMAIN)?;
    e.text(LIFECYCLE_GENERATION)?;
    e.digest(report.policy_digest)?;
    e.digest(report.input_digest)?;
    e.digest(report.tracklet_report_digest)?;
    e.u64(report.frames.len())?;
    for frame in &report.frames {
        e.source(&frame.reference)?;
        e.u64(frame.section_index)?;
        e.u64(frame.section_child_index)?;
        e.optional_index(frame.object_tree_child_index)?;
        e.optional_text(frame.module_source.as_deref())?;
        e.text(&frame.vendor_utc_time)?;
        for value in [
            frame.occurrence_start,
            frame.occurrence_count,
            frame.operation_start,
            frame.operation_count,
            frame.behaviour_start,
            frame.behaviour_count,
        ] {
            e.u64(value)?;
        }
        e.u64(frame.barriers.len())?;
        for barrier in &frame.barriers {
            e.text(barrier.as_str())?;
        }
    }
    e.u64(report.operations.len())?;
    for operation in &report.operations {
        e.digest(operation.identity)?;
        e.u64(operation.frame_ordinal)?;
        e.u64(operation.operation_index)?;
        e.u64(operation.tree_child_index)?;
        e.text(operation.kind.as_str())?;
        e.text(operation.state.as_str())?;
        e.u64(operation.unsupported_extensions)?;
        for endpoints in [&operation.from, &operation.to] {
            e.u64(endpoints.len())?;
            for endpoint in endpoints {
                e.endpoint(endpoint)?;
            }
        }
    }
    e.u64(report.behaviours.len())?;
    for behaviour in &report.behaviours {
        e.digest(behaviour.identity)?;
        e.occurrence(&behaviour.occurrence)?;
        e.u64(behaviour.frame_child_index)?;
        e.reference(&behaviour.reference)?;
        e.bool(behaviour.idle)?;
        e.bool(behaviour.removed)?;
        e.u64(behaviour.unsupported_extensions)?;
        e.text(behaviour.state.as_str())?;
        e.issues(&behaviour.issues)?;
    }
    e.u64(report.reuses.len())?;
    for reuse in &report.reuses {
        e.digest(reuse.identity)?;
        e.digest(reuse.deleted_by_operation)?;
        e.u64(reuse.deleted_at_frame)?;
        e.occurrence(&reuse.occurrence)?;
    }
    e.finish_report()
}

/// Explain vendor lifecycle declarations against an unchanged, completely verified tracks-v1 report.
///
/// The exact original projector is rerun and its complete result must equal `tracks` before any
/// graph is accepted. Its whole declared work allowance is reserved in this call's nonrenewing
/// meter; no nested subcall replenishes it. The remaining meter admits bounded item processing
/// and each canonical encode/hash byte before allocation. Cancellation and any bound refusal
/// return no successful prefix. No endpoint matching crosses a source, scope, time, transform,
/// missing-module or truly opaque boundary. Known ObjectTree/Behaviour opacity in tracks-v1 is
/// interpreted only here, so distinct original runs can be referenced but are never merged.
pub fn project_lifecycle<F: FnMut() -> bool>(
    sources: &[TrackFrameInput<'_>],
    tracks: &TrackletReport,
    overlays: &[LifecycleFrameInput<'_>],
    limits: LifecycleLimits,
    admitted: F,
) -> Result<LifecycleReport, LifecycleError> {
    limits.validate()?;
    if sources.len() > limits.max_frames || tracks.occurrences.len() > limits.max_objects {
        return Err(LifecycleError::Limit);
    }
    let mut meter = Meter {
        admitted,
        used: 0,
        maximum: limits.max_work_units,
    };
    meter.charge(1024)?; // Covers the fixed-size policy encoding and bounded call setup.
    let mut source_objects = 0usize;
    for source in sources {
        meter.charge(1)?;
        source_objects = source_objects
            .checked_add(source.frame.objects.len())
            .ok_or(LifecycleError::Limit)?;
        if source_objects > limits.max_objects {
            return Err(LifecycleError::Limit);
        }
    }
    let policy_digest = limits.digest()?;
    tracks
        .limits
        .validate()
        .map_err(|_| LifecycleError::InvalidInput)?;
    meter.charge(tracks.limits.max_work_units)?;
    let original =
        project_tracklets(sources, tracks.limits, || (meter.admitted)()).map_err(|error| {
            match error {
                TrackError::Cancelled => LifecycleError::Cancelled,
                TrackError::BudgetExceeded => LifecycleError::BudgetExceeded,
                _ => LifecycleError::InvalidInput,
            }
        })?;
    // Equality includes source pins, policy/input/report digests, every occurrence and membership.
    meter.charge(original.encoded_bytes as u64)?;
    if original != *tracks {
        return Err(LifecycleError::InvalidInput);
    }
    let checked = check_overlays(sources, overlays, limits, &mut meter)?;
    let input_digest = input_identity(tracks, sources, overlays, &mut meter)?;
    let mut report = LifecycleReport {
        limits,
        policy_digest,
        input_digest,
        tracklet_report_digest: tracks.report_digest,
        frames: Vec::with_capacity(sources.len()),
        operations: Vec::new(),
        behaviours: Vec::new(),
        reuses: Vec::new(),
        work_units: 0,
        encoded_bytes: 0,
        report_digest: ContentDigest::sha256(&[]),
    };
    let mut modules: BTreeMap<ContentDigest, ModuleState> = BTreeMap::new();
    let mut last_source: Option<&TrackFrameInput<'_>> = None;
    for (ordinal, ((source, overlay), check)) in
        sources.iter().zip(overlays).zip(&checked).enumerate()
    {
        meter.charge(64)?;
        let frame = overlay.frame;
        let summary = &tracks.frames[ordinal];
        let mut barriers = Vec::new();
        let source_gap = last_source.is_some_and(|last| {
            last.source_identity != source.source_identity
                || !((last.document_index == source.document_index
                    && last.frame_index.checked_add(1) == Some(source.frame_index))
                    || (last.document_index.checked_add(1) == Some(source.document_index)
                        && source.frame_index == 0))
        });
        if source.boundary_before || source_gap {
            barriers.push(LifecycleBoundary::SourceBoundary);
        }
        if last_source.is_some_and(|last| last.scope != source.scope) {
            barriers.push(LifecycleBoundary::GenerationChanged);
        }
        if summary.module_digest.is_none() {
            barriers.push(LifecycleBoundary::MissingModule);
        }
        if source.uninterpreted_source || overlay.uninterpreted_source {
            barriers.push(LifecycleBoundary::UninterpretedContent);
        }
        if !barriers.is_empty() {
            modules.clear();
        }
        last_source = Some(source);
        let mut previous = summary
            .module_digest
            .and_then(|module| modules.remove(&module));
        if check.opaque {
            barriers.push(LifecycleBoundary::UninterpretedContent);
        }
        if let Some(old) = &previous {
            if summary.vendor_time_ns <= old.time {
                barriers.push(LifecycleBoundary::VendorTimeNotIncreasing);
            } else if summary.vendor_time_ns - old.time
                > i128::from(tracks.limits.max_vendor_gap_ns)
            {
                barriers.push(LifecycleBoundary::VendorTimeGap);
            }
            if summary.transformation_digest != old.transformation {
                barriers.push(LifecycleBoundary::FrameTransformChanged);
            }
        }
        barriers.sort_unstable();
        barriers.dedup();
        if !barriers.is_empty() {
            previous = None;
        }
        let (previous_objects, mut deleted) = previous
            .map(|state| (state.objects, state.deleted))
            .unwrap_or_default();
        let current: BTreeMap<_, _> = check
            .keys
            .iter()
            .enumerate()
            .map(|(object_index, key)| (key.clone(), summary.occurrence_start + object_index))
            .collect();
        for (key, index) in &current {
            meter.charge(64)?;
            if let Some(claim) = deleted.get(key) {
                let observation =
                    occurrence(tracks, *index, LifecycleObservationBasis::CurrentFrame);
                let identity = reuse_identity(*claim, &observation, &mut meter)?;
                report.reuses.push(LifecycleReuse {
                    identity,
                    deleted_by_operation: claim.identity,
                    deleted_at_frame: claim.frame,
                    occurrence: observation,
                });
            }
        }
        let mut from_uses = BTreeMap::new();
        let mut to_uses = BTreeMap::new();
        for (from, to) in &check.operation_keys {
            for (keys, counts) in [(from, &mut from_uses), (to, &mut to_uses)] {
                for key in keys.iter().flatten() {
                    meter.charge(64)?;
                    *counts.entry(key.clone()).or_insert(0) += 1;
                }
            }
        }
        let operation_start = report.operations.len();
        let mut new_deletions = Vec::new();
        let context = EndpointContext {
            tracks,
            current: &current,
            previous: &previous_objects,
            deleted: &deleted,
            from_uses: &from_uses,
            to_uses: &to_uses,
            opaque: check.opaque || summary.module_digest.is_none(),
        };
        for (operation, (from, to)) in frame.operations.iter().zip(&check.operation_keys) {
            meter.charge(64)?;
            let identity = operation_identity(
                &summary.reference,
                frame
                    .object_tree_child_index
                    .ok_or(LifecycleError::InvalidInput)?,
                operation,
                &mut meter,
            )?;
            let from_counts = key_counts(from);
            let to_counts = key_counts(to);
            let mut from_rows = Vec::with_capacity(from.len());
            let mut to_rows = Vec::with_capacity(to.len());
            for (references, keys, own, other, destination, rows) in [
                (
                    &operation.from,
                    from,
                    &from_counts,
                    &to_counts,
                    false,
                    &mut from_rows,
                ),
                (
                    &operation.to,
                    to,
                    &to_counts,
                    &from_counts,
                    true,
                    &mut to_rows,
                ),
            ] {
                for (reference, key) in references.iter().zip(keys) {
                    rows.push(resolve_endpoint(
                        reference,
                        key.as_deref(),
                        destination,
                        matches!(
                            operation.kind,
                            LifecycleOperationKind::Split | LifecycleOperationKind::Merge
                        ),
                        own,
                        other,
                        &context,
                        &mut meter,
                    )?);
                }
            }
            let operation_state = if from_rows
                .iter()
                .chain(&to_rows)
                .any(|row| row.state == LifecycleEndpointState::Conflicted)
            {
                LifecycleEndpointState::Conflicted
            } else if from_rows
                .iter()
                .chain(&to_rows)
                .any(|row| row.state == LifecycleEndpointState::Unresolved)
            {
                LifecycleEndpointState::Unresolved
            } else {
                LifecycleEndpointState::Observed
            };
            if operation.kind == LifecycleOperationKind::Delete
                && !context.opaque
                && operation_state != LifecycleEndpointState::Conflicted
            {
                if let Some(Some(key)) = from.first() {
                    new_deletions.push((
                        key.clone(),
                        DeleteClaim {
                            identity,
                            frame: ordinal,
                        },
                    ));
                }
            }
            report.operations.push(LifecycleOperationRow {
                identity,
                frame_ordinal: ordinal,
                operation_index: operation.operation_index,
                tree_child_index: operation.tree_child_index,
                kind: operation.kind,
                from: from_rows,
                to: to_rows,
                state: operation_state,
                unsupported_extensions: operation.unsupported_extensions,
            });
        }
        let behaviour_start = report.behaviours.len();
        for (object, key) in frame.objects.iter().zip(&check.keys) {
            let Some(behaviour) = object.behaviour else {
                continue;
            };
            meter.charge(64)?;
            let mut issues = Vec::new();
            if !object.reference.is_supported() {
                issues.push(LifecycleIssue::UnsupportedReference);
            }
            if context.opaque {
                issues.push(LifecycleIssue::OpaqueContent);
            }
            if deleted.contains_key(key) {
                issues.push(LifecycleIssue::DeletedIdReused);
            }
            let identity = behaviour_identity(&summary.reference, object, behaviour, &mut meter)?;
            report.behaviours.push(LifecycleBehaviourRow {
                identity,
                occurrence: occurrence(
                    tracks,
                    summary.occurrence_start + object.object_index,
                    LifecycleObservationBasis::CurrentFrame,
                ),
                frame_child_index: object.frame_child_index,
                reference: object.reference.clone(),
                idle: behaviour.idle,
                removed: behaviour.removed,
                unsupported_extensions: behaviour.unsupported_extensions,
                state: state(&issues),
                issues,
            });
        }
        for (key, claim) in new_deletions {
            deleted.insert(key, claim);
        }
        if !check.opaque {
            if let Some(module) = summary.module_digest {
                modules.insert(
                    module,
                    ModuleState {
                        time: summary.vendor_time_ns,
                        transformation: summary.transformation_digest,
                        objects: current,
                        deleted,
                    },
                );
            }
        }
        report.frames.push(LifecycleFrameRow {
            reference: summary.reference.clone(),
            section_index: frame.section_index,
            section_child_index: frame.section_child_index,
            object_tree_child_index: frame.object_tree_child_index,
            module_source: frame.source.clone(),
            vendor_utc_time: frame.utc_time.clone(),
            occurrence_start: summary.occurrence_start,
            occurrence_count: summary.occurrence_count,
            operation_start,
            operation_count: report.operations.len() - operation_start,
            behaviour_start,
            behaviour_count: report.behaviours.len() - behaviour_start,
            barriers,
        });
    }
    let (digest, bytes, work) = encode_report(&report, &mut meter)?;
    report.report_digest = digest;
    report.encoded_bytes = bytes;
    report.work_units = work;
    meter.charge(0)?;
    Ok(report)
}
