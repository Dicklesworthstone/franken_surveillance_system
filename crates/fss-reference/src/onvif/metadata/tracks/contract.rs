#![forbid(unsafe_code)]
//! Bounded, source-linked runs of ONVIF vendor object occurrences.
//!
//! A tracklet means only that a named analytics module repeated the same XML
//! integer ObjectId in successive supplied frames. It is not a physical entity,
//! an FSS detector track, an independent witness, coverage, or effect authority.
//! The retained owner verifies every supplied source/frame pin; this pure function
//! cannot authenticate caller-provided pins. Opaque lifecycle information, gaps,
//! clock regressions and coordinate changes terminate a run rather than inventing
//! continuity. Every original occurrence remains separately addressable.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, Plane, ProvenanceClass};

use crate::onvif::wire::{
    AnalyticsFrame, AnalyticsTransformation, MAX_ANALYTICS_CLASSES, MAX_ANALYTICS_FRAMES,
    MAX_ANALYTICS_NUMBER_BYTES, MAX_ANALYTICS_OBJECTS_PER_FRAME, analytics_object_key,
    parse_metadata_utc_nanoseconds,
};

/// Frozen interpretation of vendor-local runs; never an identity or calibration generation.
pub const TRACKLET_GENERATION: &str = "gen:fss1:onvif-vendor-tracklets-v1";
/// Canonical report domain, distinct from retained XML/RTP source formats.
pub const TRACKLET_REPORT_DOMAIN: &str = "fss.onvif_vendor_tracklet_report.v1";
/// Hard aggregate frame ceiling across every supplied source.
pub const MAX_TRACK_FRAMES: usize = 1024;
/// Hard aggregate occurrence ceiling; repeated vendor objects count each time.
pub const MAX_TRACK_OBJECTS: usize = 4096;
/// Hard report byte ceiling for the complete canonical projection.
pub const MAX_TRACK_REPORT_BYTES: usize = 4 * 1024 * 1024;
/// Hard aggregate work ceiling for the deterministic admission schedule.
///
/// Label, transform, input and report bytes are charged explicitly. Small, bounded
/// policy/module/occurrence/run identity encodings are covered by their item charge;
/// this logical work counter is not a CPU instruction or wall-clock measurement.
pub const MAX_TRACK_WORK_UNITS: u64 = 16 * 1024 * 1024;

/// Explicit finite grouping and resource policy. Vendor time is only an assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrackLimits {
    /// Total frames admitted across all original documents.
    pub max_frames: usize,
    /// Total object occurrences, without deduplication.
    pub max_objects: usize,
    /// Total runs, including one-occurrence runs created by barriers.
    pub max_tracklets: usize,
    /// Nonrenewing work allowance for this complete call.
    pub max_work_units: u64,
    /// Complete canonical report ceiling; overflow returns no partial projection.
    pub max_output_bytes: usize,
    /// Largest strictly positive vendor-time gap permitted within a run (at most 60 seconds).
    pub max_vendor_gap_ns: u64,
}

impl Default for TrackLimits {
    fn default() -> Self {
        Self {
            max_frames: MAX_TRACK_FRAMES,
            max_objects: MAX_TRACK_OBJECTS,
            max_tracklets: MAX_TRACK_OBJECTS,
            max_work_units: 2_000_000,
            max_output_bytes: MAX_TRACK_REPORT_BYTES,
            max_vendor_gap_ns: 5_000_000_000,
        }
    }
}

impl TrackLimits {
    /// Validate all bounds before allocation or traversal.
    pub fn validate(self) -> Result<(), TrackError> {
        if !(1..=MAX_TRACK_FRAMES).contains(&self.max_frames)
            || !(1..=MAX_TRACK_OBJECTS).contains(&self.max_objects)
            || !(1..=MAX_TRACK_OBJECTS).contains(&self.max_tracklets)
            || !(1..=MAX_TRACK_WORK_UNITS).contains(&self.max_work_units)
            || !(1..=MAX_TRACK_REPORT_BYTES).contains(&self.max_output_bytes)
            || !(1..=60_000_000_000).contains(&self.max_vendor_gap_ns)
        {
            return Err(TrackError::InvalidLimits);
        }
        Ok(())
    }

    /// Bind the exact interpretation, grouping rule and every supplied resource ceiling.
    pub fn digest(self) -> Result<ContentDigest, TrackError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text("fss.onvif_vendor_tracklet_policy.v1");
        e.text(TRACKLET_GENERATION);
        for n in [
            self.max_frames,
            self.max_objects,
            self.max_tracklets,
            self.max_output_bytes,
        ] {
            e.u64(n as u64);
        }
        e.u64(self.max_work_units);
        e.u64(self.max_vendor_gap_ns);
        hash(e)
    }
}

/// One borrowed frame from an owner-verified XML or RTP document.
#[derive(Clone, Copy)]
pub struct TrackFrameInput<'a> {
    /// Exact sensor, device/profile/parser and transport-generation scope, bound by the owner.
    pub scope: ContentDigest,
    /// Original retained import/acquisition identity, never a new synthetic source.
    pub source_identity: ContentDigest,
    /// Independently selected retained root.
    pub source_root: ContentDigest,
    /// Exact XML document digest, including opaque original content.
    pub source_digest: ContentDigest,
    /// Source-bound analytics frame identity supplied by the original owner.
    pub frame_digest: ContentDigest,
    /// Original document position within that source (zero for plain XML imports).
    pub document_index: usize,
    /// Original frame position within the original XML document.
    pub frame_index: usize,
    /// Parsed vendor values. The pure projector grants them no custody or physical authority.
    pub frame: &'a AnalyticsFrame,
    /// An independent-source, transport or skipped-document boundary precedes this frame.
    pub boundary_before: bool,
    /// Opaque outer content may contain unparsed source/lifecycle transitions.
    pub uninterpreted_source: bool,
}

impl fmt::Debug for TrackFrameInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrackFrameInput")
            .field("source_identity", &self.source_identity)
            .field("frame_index", &self.frame_index)
            .finish_non_exhaustive()
    }
}

/// Why grouping starts or stops. None of these reasons establishes physical arrival/departure.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TrackBreakReason {
    /// First occurrence of this local vendor key in the current unbroken frame sequence.
    NewOccurrence,
    /// Explicit independent-source or packet/document gap supplied by the custody owner.
    SourceBoundary,
    /// Exact sensor/device/profile/parser/transport generation changed.
    GenerationChanged,
    /// An intervening frame from the same module omitted the vendor key.
    MissingOccurrence,
    /// Missing or empty analytics Source cannot identify the claiming module.
    MissingModule,
    /// Uninterpreted content prevents a lifecycle/coordinate continuity claim.
    UninterpretedContent,
    /// Vendor time repeats or regresses; even equivalent lexical times cannot join.
    VendorTimeNotIncreasing,
    /// Vendor-asserted time distance exceeds the explicit grouping policy.
    VendorTimeGap,
    /// Frame-coordinate transformation differs, including missing/present changes.
    FrameTransformChanged,
    /// Object-relative transformation differs, including missing/present changes.
    ObjectTransformChanged,
    /// The finite input ended; no physical end or absence is inferred.
    EndOfInput,
}

impl TrackBreakReason {
    /// Stable report spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NewOccurrence => "new_occurrence",
            Self::SourceBoundary => "source_boundary",
            Self::GenerationChanged => "generation_changed",
            Self::MissingOccurrence => "missing_occurrence",
            Self::MissingModule => "missing_module",
            Self::UninterpretedContent => "uninterpreted_content",
            Self::VendorTimeNotIncreasing => "vendor_time_not_increasing",
            Self::VendorTimeGap => "vendor_time_gap",
            Self::FrameTransformChanged => "frame_transform_changed",
            Self::ObjectTransformChanged => "object_transform_changed",
            Self::EndOfInput => "end_of_input",
        }
    }
}

/// Payload-free refusal. No failure returns a successful prefix or replenishes work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackError {
    /// Invalid or widened policy.
    InvalidLimits,
    /// Malformed owner pins, source positions or mutated parser values.
    InvalidInput,
    /// The same original source/document/frame locator was supplied more than once.
    DuplicateFrame,
    /// Aliased XML integer ObjectIds occurred within one supplied frame.
    DuplicateObject,
    /// Total frame, occurrence, run or canonical output capacity was exceeded.
    Limit,
    /// One cumulative validation/grouping/encoding allowance was exhausted.
    BudgetExceeded,
    /// The owner admission callback refused; no later check can resume this call.
    Cancelled,
    /// A canonical field could not be encoded.
    Encoding,
}

impl TrackError {
    /// Stable diagnostic with no vendor values or private source contents.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidLimits => "ERR-ONVIF-TRACKLETS-CONFIG-001",
            Self::InvalidInput => "ERR-ONVIF-TRACKLETS-INPUT-001",
            Self::DuplicateFrame => "ERR-ONVIF-TRACKLETS-DUPLICATE-FRAME-001",
            Self::DuplicateObject => "ERR-ONVIF-TRACKLETS-DUPLICATE-OBJECT-001",
            Self::Limit => "ERR-ONVIF-TRACKLETS-LIMIT-001",
            Self::BudgetExceeded => "ERR-ONVIF-TRACKLETS-BUDGET-001",
            Self::Cancelled => "ERR-ONVIF-TRACKLETS-CANCELLED-001",
            Self::Encoding => "ERR-ONVIF-TRACKLETS-ENCODING-001",
        }
    }
}
impl fmt::Display for TrackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for TrackError {}

/// Exact source location for every frame, including empty or isolated frames.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackFrameReference {
    /// Position in the explicitly ordered input.
    pub ordinal: usize,
    /// Exact frozen generation/source scope.
    pub scope: ContentDigest,
    /// Original custody identity.
    pub source_identity: ContentDigest,
    /// Original custody root.
    pub source_root: ContentDigest,
    /// Full original XML digest.
    pub source_digest: ContentDigest,
    /// Original source-bound analytics frame identity.
    pub frame_digest: ContentDigest,
    /// Original XML document index within the retained source.
    pub document_index: usize,
    /// Original analytics frame index within that document.
    pub frame_index: usize,
}

/// One frame's bookkeeping; public raw strings require explicit disclosure by presentation.
#[derive(Clone, Eq, PartialEq)]
pub struct TrackFrameSummary {
    /// Exact source/frame hydration coordinates.
    pub reference: TrackFrameReference,
    /// Generation-scoped module hash; absent means unknown, not an unnamed shared module.
    pub module_digest: Option<ContentDigest>,
    /// Original private vendor module spelling, never a trusted source identity.
    pub module_source: Option<String>,
    /// Original vendor timestamp spelling, never a physical capture clock.
    pub vendor_utc_time: String,
    /// Exact numerical interpretation for conservative ordering only.
    pub vendor_time_ns: i128,
    /// Exact frame-transform interpretation, including absence.
    pub transformation_digest: ContentDigest,
    /// First occurrence row; empty frames keep a zero-length range.
    pub occurrence_start: usize,
    /// Every original object in this frame, without filtering.
    pub occurrence_count: usize,
    /// All applicable frame-level grouping barriers in stable order.
    pub barriers: Vec<TrackBreakReason>,
}

/// One original vendor object occurrence. Shape/class/transform values remain at its source handle.
#[derive(Clone, Eq, PartialEq)]
pub struct TrackOccurrence {
    /// Exact source/frame/object commitment, independent of run grouping.
    pub identity: ContentDigest,
    /// The advisory vendor-local run that includes this occurrence.
    pub tracklet_identity: ContentDigest,
    /// Index of the frame summary, which owns the complete original source handle.
    pub frame_ordinal: usize,
    /// Original Object position within that original frame.
    pub object_index: usize,
    /// Original private ObjectId spelling; integer aliases are preserved, not rewritten.
    pub vendor_object_id: String,
    /// Original private module spelling, for explicitly requested local disclosure only.
    pub module_source: Option<String>,
    /// Original vendor timestamp, for explicitly requested local disclosure only.
    pub vendor_utc_time: String,
    /// Object-relative transform, including appearance/transformation absence.
    pub transformation_digest: ContentDigest,
}

/// One finite run of matching vendor claims, not an entity identity or evidence corroboration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VendorTracklet {
    /// Policy-, generation- and first-occurrence-bound advisory identity.
    pub identity: ContentDigest,
    /// Exact source-generation scope; runs never cross it.
    pub scope: ContentDigest,
    /// Exact named module, or None for an isolated unknown-module occurrence.
    pub module_digest: Option<ContentDigest>,
    /// Module/generation-scoped hash of the normalized XML integer ObjectId.
    pub vendor_key_digest: ContentDigest,
    /// All and only original occurrence row indices in input order.
    pub occurrence_indices: Vec<usize>,
    /// Why this run began.
    pub start_reasons: Vec<TrackBreakReason>,
    /// Why grouping stopped; EndOfInput is not a physical departure.
    pub end_reasons: Vec<TrackBreakReason>,
}

/// Complete deterministic projection over the supplied finite source set.
#[derive(Clone, Eq, PartialEq)]
pub struct TrackletReport {
    /// Exact limits and grouping policy, retained rather than inferred from process defaults.
    pub limits: TrackLimits,
    /// Canonical policy identity.
    pub policy_digest: ContentDigest,
    /// Commitment to every supplied source/frame pin and consumed vendor grouping field.
    pub input_digest: ContentDigest,
    /// Complete ordered frame accounting, including empty frames.
    pub frames: Vec<TrackFrameSummary>,
    /// Complete ordered object accounting, without coalescing repeated observations.
    pub occurrences: Vec<TrackOccurrence>,
    /// Runs in first-occurrence order, each terminal within this finite projection.
    pub tracklets: Vec<VendorTracklet>,
    /// Deterministic label/transform/input/report-byte and bounded item work consumed.
    pub work_units: u64,
    /// Exact complete canonical projection size.
    pub encoded_bytes: usize,
    /// Digest of the canonical report, excluding this self-field and encoded_bytes.
    pub report_digest: ContentDigest,
}

impl TrackletReport {
    /// Vendor values always remain derived cognition.
    #[must_use]
    pub const fn plane(&self) -> Plane {
        Plane::Cognition
    }
    /// The grouping is a deterministic derivation, not a physical observation.
    #[must_use]
    pub const fn provenance(&self) -> ProvenanceClass {
        ProvenanceClass::Derived
    }
    /// Original leaves remain vendor assertions, even after their custody is verified.
    #[must_use]
    pub const fn source_provenance(&self) -> ProvenanceClass {
        ProvenanceClass::VendorClaimed
    }
}

impl fmt::Debug for TrackFrameSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrackFrameSummary")
            .field("reference", &self.reference)
            .field("occurrence_count", &self.occurrence_count)
            .field("barriers", &self.barriers)
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for TrackOccurrence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrackOccurrence")
            .field("identity", &self.identity)
            .field("frame_ordinal", &self.frame_ordinal)
            .field("object_index", &self.object_index)
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for TrackletReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrackletReport")
            .field("report_digest", &self.report_digest)
            .field("frames", &self.frames.len())
            .field("occurrences", &self.occurrences.len())
            .field("tracklets", &self.tracklets.len())
            .field("work_units", &self.work_units)
            .finish_non_exhaustive()
    }
}

struct Meter<F> {
    admitted: F,
    used: u64,
    limit: u64,
}
impl<F: FnMut() -> bool> Meter<F> {
    fn charge(&mut self, amount: u64) -> Result<(), TrackError> {
        if !(self.admitted)() {
            return Err(TrackError::Cancelled);
        }
        let next = self
            .used
            .checked_add(amount)
            .ok_or(TrackError::BudgetExceeded)?;
        if next > self.limit {
            return Err(TrackError::BudgetExceeded);
        }
        self.used = next;
        Ok(())
    }
}

struct CheckedObject {
    key: String,
    transformation: ContentDigest,
}
struct CheckedFrame {
    time: i128,
    module: Option<ContentDigest>,
    transformation: ContentDigest,
    opaque: bool,
    objects: Vec<CheckedObject>,
}
struct ActiveObject {
    track: usize,
    transformation: ContentDigest,
}
struct ModuleState {
    time: i128,
    transformation: ContentDigest,
    objects: BTreeMap<String, ActiveObject>,
}

/// Group a complete finite set under one shared allowance and current owner admission.
///
/// Source order is preserved; no timestamp sorting repairs a regression or gap.
/// Separate named modules may interleave. A missing/empty module or opaque outer
/// lifecycle breaks all modules; opaque content inside a frame isolates that
/// module's frame. Repeated ObjectId integers only join when seen in successive
/// frames of that same module with compatible coordinate and generation scope.
/// Every refusal is atomic for the returned projection; no source is mutated.
pub fn project_tracklets<F: FnMut() -> bool>(
    frames: &[TrackFrameInput<'_>],
    limits: TrackLimits,
    admitted: F,
) -> Result<TrackletReport, TrackError> {
    limits.validate()?;
    if frames.len() > limits.max_frames {
        return Err(TrackError::Limit);
    }
    let mut meter = Meter {
        admitted,
        used: 0,
        limit: limits.max_work_units,
    };
    meter.charge(1)?;
    let policy = limits.digest()?;
    let (checked, input_digest) = check_inputs(frames, limits, &mut meter)?;
    let mut report = TrackletReport {
        limits,
        policy_digest: policy,
        input_digest,
        frames: Vec::new(),
        occurrences: Vec::new(),
        tracklets: Vec::new(),
        work_units: 0,
        encoded_bytes: 0,
        report_digest: ContentDigest::sha256(&[]),
    };
    let mut modules: BTreeMap<ContentDigest, ModuleState> = BTreeMap::new();
    let mut previous_scope = None;
    let mut previous_source: Option<(ContentDigest, usize, usize)> = None;

    for (ordinal, (input, check)) in frames.iter().zip(&checked).enumerate() {
        meter.charge(1)?;
        let mut reasons = Vec::new();
        let source_gap = previous_source.is_some_and(|(identity, document, frame)| {
            identity != input.source_identity
                || !((document == input.document_index
                    && frame.checked_add(1) == Some(input.frame_index))
                    || (document.checked_add(1) == Some(input.document_index)
                        && input.frame_index == 0))
        });
        if input.boundary_before || source_gap {
            reasons.push(TrackBreakReason::SourceBoundary);
        }
        if previous_scope.is_some_and(|scope| scope != input.scope) {
            reasons.push(TrackBreakReason::GenerationChanged);
        }
        if check.module.is_none() {
            reasons.push(TrackBreakReason::MissingModule);
        }
        if input.uninterpreted_source {
            reasons.push(TrackBreakReason::UninterpretedContent);
        }
        if !reasons.is_empty() {
            end_modules(&mut modules, &mut report.tracklets, &reasons, &mut meter)?;
        }
        previous_scope = Some(input.scope);
        previous_source = Some((
            input.source_identity,
            input.document_index,
            input.frame_index,
        ));
        let mut state = check.module.and_then(|key| modules.remove(&key));
        if check.opaque {
            reasons.push(TrackBreakReason::UninterpretedContent);
        }
        if let Some(old) = &state {
            if check.time <= old.time {
                reasons.push(TrackBreakReason::VendorTimeNotIncreasing);
            } else if check.time - old.time > i128::from(limits.max_vendor_gap_ns) {
                reasons.push(TrackBreakReason::VendorTimeGap);
            }
            if check.transformation != old.transformation {
                reasons.push(TrackBreakReason::FrameTransformChanged);
            }
        }
        reasons.sort_unstable();
        reasons.dedup();
        if !reasons.is_empty() {
            if let Some(old) = state.take() {
                end_objects(old.objects, &mut report.tracklets, &reasons, &mut meter)?;
            }
        }
        let mut old_objects = state.map(|old| old.objects).unwrap_or_default();
        let mut new_objects = BTreeMap::new();
        let first_occurrence = report.occurrences.len();
        for (object_index, (object, checked_object)) in
            input.frame.objects.iter().zip(&check.objects).enumerate()
        {
            meter.charge(1)?;
            let occurrence_identity = occurrence_identity(input, object_index, &object.object_id)?;
            let mut start_reasons = reasons.clone();
            let existing = old_objects.remove(&checked_object.key);
            let track = match existing {
                Some(old) if old.transformation == checked_object.transformation => old.track,
                other => {
                    if let Some(old) = other {
                        report.tracklets[old.track].end_reasons =
                            vec![TrackBreakReason::ObjectTransformChanged];
                        start_reasons.push(TrackBreakReason::ObjectTransformChanged);
                    }
                    if start_reasons.is_empty() {
                        start_reasons.push(TrackBreakReason::NewOccurrence);
                    }
                    if report.tracklets.len() == limits.max_tracklets {
                        return Err(TrackError::Limit);
                    }
                    let mut key = CanonicalEncoder::new();
                    key.text("fss.onvif_vendor_object_key.v1");
                    key.digest(input.scope);
                    optional_digest(&mut key, check.module);
                    key.text(&checked_object.key);
                    let vendor_key_digest = hash(key)?;
                    let mut identity = CanonicalEncoder::new();
                    identity.text("fss.onvif_vendor_tracklet_identity.v1");
                    identity.digest(policy);
                    identity.digest(occurrence_identity);
                    encode_reasons(&mut identity, &start_reasons);
                    let identity = hash(identity)?;
                    let index = report.tracklets.len();
                    report.tracklets.push(VendorTracklet {
                        identity,
                        scope: input.scope,
                        module_digest: check.module,
                        vendor_key_digest,
                        occurrence_indices: Vec::new(),
                        start_reasons,
                        end_reasons: Vec::new(),
                    });
                    index
                }
            };
            let occurrence_index = report.occurrences.len();
            report.tracklets[track]
                .occurrence_indices
                .push(occurrence_index);
            report.occurrences.push(TrackOccurrence {
                identity: occurrence_identity,
                tracklet_identity: report.tracklets[track].identity,
                frame_ordinal: ordinal,
                object_index,
                vendor_object_id: object.object_id.clone(),
                module_source: input.frame.source.clone(),
                vendor_utc_time: input.frame.utc_time.clone(),
                transformation_digest: checked_object.transformation,
            });
            new_objects.insert(
                checked_object.key.clone(),
                ActiveObject {
                    track,
                    transformation: checked_object.transformation,
                },
            );
        }
        end_objects(
            old_objects,
            &mut report.tracklets,
            &[TrackBreakReason::MissingOccurrence],
            &mut meter,
        )?;
        let isolated = check.module.is_none() || check.opaque || input.uninterpreted_source;
        if isolated {
            let end = if check.module.is_none() {
                TrackBreakReason::MissingModule
            } else {
                TrackBreakReason::UninterpretedContent
            };
            end_objects(new_objects, &mut report.tracklets, &[end], &mut meter)?;
        } else if let Some(module) = check.module {
            modules.insert(
                module,
                ModuleState {
                    time: check.time,
                    transformation: check.transformation,
                    objects: new_objects,
                },
            );
        }
        report.frames.push(TrackFrameSummary {
            reference: reference(ordinal, input),
            module_digest: check.module,
            module_source: input.frame.source.clone(),
            vendor_utc_time: input.frame.utc_time.clone(),
            vendor_time_ns: check.time,
            transformation_digest: check.transformation,
            occurrence_start: first_occurrence,
            occurrence_count: input.frame.objects.len(),
            barriers: reasons,
        });
    }
    end_modules(
        &mut modules,
        &mut report.tracklets,
        &[TrackBreakReason::EndOfInput],
        &mut meter,
    )?;
    // Admit complete output allocation and encode/hash work before doing either.
    let encoded_bytes = report_size(&report, &mut meter)?;
    meter.charge(
        (encoded_bytes as u64)
            .checked_mul(2)
            .ok_or(TrackError::BudgetExceeded)?,
    )?;
    report.work_units = meter.used;
    report.encoded_bytes = encoded_bytes;
    let encoded = encode_report(&report)?;
    if encoded.len() != encoded_bytes {
        return Err(TrackError::Encoding);
    }
    report.report_digest = hash_bytes(&encoded)?;
    meter.charge(0)?;
    Ok(report)
}

fn end_modules<F: FnMut() -> bool>(
    modules: &mut BTreeMap<ContentDigest, ModuleState>,
    tracks: &mut [VendorTracklet],
    reasons: &[TrackBreakReason],
    meter: &mut Meter<F>,
) -> Result<(), TrackError> {
    for (_, module) in std::mem::take(modules) {
        meter.charge(1)?;
        end_objects(module.objects, tracks, reasons, meter)?;
    }
    Ok(())
}
fn end_objects<F: FnMut() -> bool>(
    objects: BTreeMap<String, ActiveObject>,
    tracks: &mut [VendorTracklet],
    reasons: &[TrackBreakReason],
    meter: &mut Meter<F>,
) -> Result<(), TrackError> {
    for (_, active) in objects {
        meter.charge(1)?;
        tracks[active.track].end_reasons = reasons.to_vec();
    }
    Ok(())
}

fn check_inputs<F: FnMut() -> bool>(
    frames: &[TrackFrameInput<'_>],
    limits: TrackLimits,
    meter: &mut Meter<F>,
) -> Result<(Vec<CheckedFrame>, ContentDigest), TrackError> {
    let mut total = 0usize;
    let mut seen = BTreeSet::new();
    let mut source_roots = BTreeMap::new();
    let mut document_digests = BTreeMap::new();
    let mut checked = Vec::with_capacity(frames.len());
    let mut e = CanonicalEncoder::new();
    e.text("fss.onvif_vendor_tracklet_inputs.v1");
    e.text(TRACKLET_GENERATION);
    e.u64(frames.len() as u64);
    for (ordinal, input) in frames.iter().enumerate() {
        meter.charge(1)?;
        if [
            input.scope,
            input.source_identity,
            input.source_root,
            input.source_digest,
            input.frame_digest,
        ]
        .iter()
        .any(|value| value.algorithm() != DigestAlgorithm::Sha256)
            || input.frame_index >= MAX_ANALYTICS_FRAMES
            || input.document_index >= MAX_TRACK_FRAMES
            || input.frame.objects.len() > MAX_ANALYTICS_OBJECTS_PER_FRAME
        {
            return Err(TrackError::InvalidInput);
        }
        if !seen.insert((
            input.source_identity,
            input.document_index,
            input.frame_index,
        )) {
            return Err(TrackError::DuplicateFrame);
        }
        if source_roots
            .insert(input.source_identity, input.source_root)
            .is_some_and(|root| root != input.source_root)
            || document_digests
                .insert(
                    (input.source_identity, input.document_index),
                    input.source_digest,
                )
                .is_some_and(|digest| digest != input.source_digest)
        {
            return Err(TrackError::InvalidInput);
        }
        total = total
            .checked_add(input.frame.objects.len())
            .ok_or(TrackError::Limit)?;
        if total > limits.max_objects {
            return Err(TrackError::Limit);
        }
        validate_label(&input.frame.utc_time, 30, meter)?;
        let time = parse_metadata_utc_nanoseconds(&input.frame.utc_time)
            .map_err(|_| TrackError::InvalidInput)?;
        if let Some(source) = &input.frame.source {
            validate_label(source, 256, meter)?;
        }
        let module = input
            .frame
            .source
            .as_deref()
            .filter(|name| !name.is_empty())
            .map(|name| {
                let mut key = CanonicalEncoder::new();
                key.text("fss.onvif_vendor_module.v1");
                key.digest(input.scope);
                key.text(name);
                hash(key)
            })
            .transpose()?;
        let transformation = transform_digest(input.frame.transformation.as_ref(), None, meter)?;
        let mut objects = Vec::with_capacity(input.frame.objects.len());
        let mut identities = BTreeSet::new();
        for object in &input.frame.objects {
            meter.charge(1)?;
            validate_label(&object.object_id, 64, meter)?;
            let key =
                analytics_object_key(&object.object_id).map_err(|_| TrackError::InvalidInput)?;
            if !identities.insert(key.clone()) {
                return Err(TrackError::DuplicateObject);
            }
            if let Some(appearance) = &object.appearance {
                if let Some(class) = &appearance.class {
                    if class.candidates.len() > MAX_ANALYTICS_CLASSES {
                        return Err(TrackError::InvalidInput);
                    }
                    for candidate in &class.candidates {
                        validate_label(&candidate.label, 256, meter)?;
                        if let Some(value) = &candidate.likelihood {
                            validate_label(value.as_str(), MAX_ANALYTICS_NUMBER_BYTES, meter)?;
                        }
                    }
                }
            }
            let transform = transform_digest(
                object
                    .appearance
                    .as_ref()
                    .and_then(|v| v.transformation.as_ref()),
                Some(object.appearance.is_some()),
                meter,
            )?;
            objects.push(CheckedObject {
                key,
                transformation: transform,
            });
        }
        let opaque = input.frame.has_unsupported_content();
        encode_reference(&mut e, &reference(ordinal, input));
        optional_text(&mut e, input.frame.source.as_deref());
        e.text(&input.frame.utc_time);
        e.digest(transformation);
        e.bool(input.boundary_before);
        e.bool(input.uninterpreted_source);
        e.bool(opaque);
        e.u64(objects.len() as u64);
        for (original, object) in input.frame.objects.iter().zip(&objects) {
            e.text(&original.object_id);
            e.text(&object.key);
            e.digest(object.transformation);
        }
        checked.push(CheckedFrame {
            time,
            module,
            transformation,
            opaque,
            objects,
        });
    }
    let bytes = e.finish_checked().map_err(|_| TrackError::Encoding)?;
    meter.charge(bytes.len() as u64)?;
    Ok((checked, ContentDigest::sha256(&bytes)))
}

fn validate_label<F: FnMut() -> bool>(
    value: &str,
    maximum: usize,
    meter: &mut Meter<F>,
) -> Result<(), TrackError> {
    if value.len() > maximum {
        return Err(TrackError::InvalidInput);
    }
    meter.charge(value.len() as u64 + 1)?;
    if value.chars().any(char::is_control) {
        return Err(TrackError::InvalidInput);
    }
    Ok(())
}

fn transform_digest<F: FnMut() -> bool>(
    value: Option<&AnalyticsTransformation>,
    appearance_present: Option<bool>,
    meter: &mut Meter<F>,
) -> Result<ContentDigest, TrackError> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.onvif_vendor_transform.v1");
    e.bool(appearance_present.is_some());
    if let Some(present) = appearance_present {
        e.bool(present);
    }
    e.bool(value.is_some());
    if let Some(value) = value {
        for vector in [value.translate.as_ref(), value.scale.as_ref()] {
            e.bool(vector.is_some());
            if let Some(vector) = vector {
                for number in [&vector.x, &vector.y] {
                    validate_label(number.as_str(), MAX_ANALYTICS_NUMBER_BYTES, meter)?;
                    e.text(number.as_str());
                }
                e.u64(vector.unsupported_extensions as u64);
            }
        }
        e.u64(value.unsupported_extensions as u64);
    }
    let bytes = e.finish_checked().map_err(|_| TrackError::Encoding)?;
    meter.charge(bytes.len() as u64)?;
    Ok(ContentDigest::sha256(&bytes))
}

fn reference(ordinal: usize, input: &TrackFrameInput<'_>) -> TrackFrameReference {
    TrackFrameReference {
        ordinal,
        scope: input.scope,
        source_identity: input.source_identity,
        source_root: input.source_root,
        source_digest: input.source_digest,
        frame_digest: input.frame_digest,
        document_index: input.document_index,
        frame_index: input.frame_index,
    }
}
fn encode_reference(e: &mut CanonicalEncoder, value: &TrackFrameReference) {
    e.u64(value.ordinal as u64);
    for digest in [
        value.scope,
        value.source_identity,
        value.source_root,
        value.source_digest,
        value.frame_digest,
    ] {
        e.digest(digest);
    }
    e.u64(value.document_index as u64);
    e.u64(value.frame_index as u64);
}
fn occurrence_identity(
    input: &TrackFrameInput<'_>,
    object_index: usize,
    lexical: &str,
) -> Result<ContentDigest, TrackError> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.onvif_vendor_object_occurrence.v1");
    // No request ordinal: the same exact original occurrence keeps its source handle.
    for digest in [
        input.scope,
        input.source_identity,
        input.source_root,
        input.source_digest,
        input.frame_digest,
    ] {
        e.digest(digest);
    }
    e.u64(input.document_index as u64);
    e.u64(input.frame_index as u64);
    e.u64(object_index as u64);
    e.text(lexical);
    hash(e)
}
fn encode_reasons(e: &mut CanonicalEncoder, reasons: &[TrackBreakReason]) {
    e.u64(reasons.len() as u64);
    for reason in reasons {
        e.text(reason.as_str());
    }
}
fn optional_digest(e: &mut CanonicalEncoder, value: Option<ContentDigest>) {
    e.bool(value.is_some());
    if let Some(value) = value {
        e.digest(value);
    }
}
fn optional_text(e: &mut CanonicalEncoder, value: Option<&str>) {
    e.bool(value.is_some());
    if let Some(value) = value {
        e.text(value);
    }
}
fn hash(e: CanonicalEncoder) -> Result<ContentDigest, TrackError> {
    hash_bytes(&e.finish_checked().map_err(|_| TrackError::Encoding)?)
}
fn hash_bytes(bytes: &[u8]) -> Result<ContentDigest, TrackError> {
    if bytes.len() > MAX_TRACK_REPORT_BYTES {
        return Err(TrackError::Limit);
    }
    Ok(ContentDigest::sha256(bytes))
}
const PROVENANCE_DECLARATION: &str =
    "derived:vendor_claimed_sources:cognition:no_identity:no_coverage:no_effect_authority";

/// Exact canonical output size, checked before constructing the output buffer.
fn report_size<F: FnMut() -> bool>(
    report: &TrackletReport,
    meter: &mut Meter<F>,
) -> Result<usize, TrackError> {
    struct Size {
        used: usize,
        limit: usize,
    }
    impl Size {
        fn add(&mut self, n: usize) -> Result<(), TrackError> {
            self.used = self.used.checked_add(n).ok_or(TrackError::Limit)?;
            if self.used > self.limit {
                return Err(TrackError::Limit);
            }
            Ok(())
        }
        fn text(&mut self, value: &str) -> Result<(), TrackError> {
            self.add(8 + value.len())
        }
        fn text_option(&mut self, value: Option<&str>) -> Result<(), TrackError> {
            self.add(1)?;
            if let Some(value) = value {
                self.text(value)?;
            }
            Ok(())
        }
        fn digest_option(&mut self, value: Option<ContentDigest>) -> Result<(), TrackError> {
            self.add(if value.is_some() { 34 } else { 1 })
        }
        fn reasons(&mut self, reasons: &[TrackBreakReason]) -> Result<(), TrackError> {
            self.add(8)?;
            for reason in reasons {
                self.text(reason.as_str())?;
            }
            Ok(())
        }
    }
    let mut size = Size {
        used: 0,
        limit: report.limits.max_output_bytes,
    };
    for text in [
        TRACKLET_REPORT_DOMAIN,
        TRACKLET_GENERATION,
        PROVENANCE_DECLARATION,
    ] {
        size.text(text)?;
    }
    // Two digests, three collection lengths and final work count.
    size.add(2 * 33 + 4 * 8)?;
    for frame in &report.frames {
        meter.charge(1)?;
        size.add(3 * 8 + 5 * 33)?;
        size.digest_option(frame.module_digest)?;
        size.text_option(frame.module_source.as_deref())?;
        size.text(&frame.vendor_utc_time)?;
        size.add(16 + 33 + 2 * 8)?;
        size.reasons(&frame.barriers)?;
    }
    for object in &report.occurrences {
        meter.charge(1)?;
        size.add(3 * 33 + 2 * 8)?;
        size.text(&object.vendor_object_id)?;
        size.text_option(object.module_source.as_deref())?;
        size.text(&object.vendor_utc_time)?;
    }
    for track in &report.tracklets {
        meter.charge(1 + track.occurrence_indices.len() as u64)?;
        size.add(3 * 33)?;
        size.digest_option(track.module_digest)?;
        size.add(8 + track.occurrence_indices.len() * 8)?;
        size.reasons(&track.start_reasons)?;
        size.reasons(&track.end_reasons)?;
    }
    Ok(size.used)
}

fn encode_report(report: &TrackletReport) -> Result<Vec<u8>, TrackError> {
    let mut e = CanonicalEncoder::new();
    e.text(TRACKLET_REPORT_DOMAIN);
    e.text(TRACKLET_GENERATION);
    e.text(PROVENANCE_DECLARATION);
    e.digest(report.policy_digest);
    e.digest(report.input_digest);
    e.u64(report.frames.len() as u64);
    for frame in &report.frames {
        encode_reference(&mut e, &frame.reference);
        optional_digest(&mut e, frame.module_digest);
        optional_text(&mut e, frame.module_source.as_deref());
        e.text(&frame.vendor_utc_time);
        e.i128(frame.vendor_time_ns);
        e.digest(frame.transformation_digest);
        e.u64(frame.occurrence_start as u64);
        e.u64(frame.occurrence_count as u64);
        encode_reasons(&mut e, &frame.barriers);
    }
    e.u64(report.occurrences.len() as u64);
    for object in &report.occurrences {
        e.digest(object.identity);
        e.digest(object.tracklet_identity);
        e.u64(object.frame_ordinal as u64);
        e.u64(object.object_index as u64);
        e.text(&object.vendor_object_id);
        optional_text(&mut e, object.module_source.as_deref());
        e.text(&object.vendor_utc_time);
        e.digest(object.transformation_digest);
    }
    e.u64(report.tracklets.len() as u64);
    for track in &report.tracklets {
        e.digest(track.identity);
        e.digest(track.scope);
        optional_digest(&mut e, track.module_digest);
        e.digest(track.vendor_key_digest);
        e.u64(track.occurrence_indices.len() as u64);
        for index in &track.occurrence_indices {
            e.u64(*index as u64);
        }
        encode_reasons(&mut e, &track.start_reasons);
        encode_reasons(&mut e, &track.end_reasons);
    }
    e.u64(report.work_units);
    e.finish_checked().map_err(|_| TrackError::Encoding)
}
