#![forbid(unsafe_code)]
//! Pure request, source-binding and conservative time contracts for retained handoff queries.
//!
//! These public data shapes alone confer no source authentication. The containing reference
//! owner creates a sealed projection only after rebuilding package analyses from custody.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{
    CanonicalEncode, CanonicalEncoder, ClockBasis, ContentDigest, DigestAlgorithm, LedgerAnchor,
};
use fss_graph_algorithms::continuity::{
    self, ContinuityQuery, Scope, Tracklet, TrackletSupport, Transition,
};

/// Maximum distinct `(report, label, tracking policy)` recipes read by one projection pass.
pub const MAX_PACKAGE_HANDOFF_ANALYSES: usize = 4;
/// Maximum actual observations in one retained package analysis.
pub const MAX_PACKAGE_HANDOFF_FRAMES: usize = 64;
/// Maximum selected native tracklets; no selected member is silently omitted.
pub const MAX_PACKAGE_HANDOFF_TRACKS: usize = continuity::MAX_TRACKLETS;
/// Maximum original source segments verified while rebuilding analyses in one projection pass.
pub const MAX_PACKAGE_HANDOFF_FRAME_READS: usize =
    MAX_PACKAGE_HANDOFF_ANALYSES * MAX_PACKAGE_HANDOFF_FRAMES;
/// Cumulative original-byte allowance across every recipe and all final revalidation passes.
pub const MAX_PACKAGE_HANDOFF_SOURCE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Maximum UTF-8 model/label text retained by the existing package owner.
pub const MAX_PACKAGE_HANDOFF_TEXT: usize = 512;
/// Domain of the complete normalized owner request.
pub const PACKAGE_HANDOFF_REQUEST_DOMAIN: &str = "fss.package_handoff_request.v1";
/// Domain of a source-authenticated, anchor-bound projection and every explicit assumption.
pub const PACKAGE_HANDOFF_PROJECTION_DOMAIN: &str = "fss.package_handoff_projection.v1";
/// Source stream and image geometry generation, not a physical camera calibration.
pub const PACKAGE_HANDOFF_CAMERA_DOMAIN: &str = "fss.package_handoff_camera_generation.v1";
/// Exact detector/head/label comparison space; equal weights alone are insufficient.
pub const PACKAGE_HANDOFF_MODEL_DOMAIN: &str = "fss.package_handoff_model_space.v1";
/// Canonical aggregate of actual per-sensor privacy bindings in one projection.
pub const PACKAGE_HANDOFF_PRIVACY_DOMAIN: &str = "fss.package_handoff_privacy.v1";

/// A malformed declaration or an unrepresentable conservative projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageHandoffContractError {
    /// A declared identity, digest, configuration or transition is invalid.
    Invalid(&'static str),
    /// A declared collection exceeds its hard bound.
    Limit,
    /// A source capture plus declared offset cannot be represented in native signed ticks.
    TimeOverflow,
}

impl fmt::Display for PackageHandoffContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(why) => write!(f, "retained handoff declaration invalid: {why}"),
            Self::Limit => f.write_str("retained handoff declaration exceeds its hard bound"),
            Self::TimeOverflow => {
                f.write_str("aligned capture interval cannot be represented as signed nanoseconds")
            }
        }
    }
}
impl std::error::Error for PackageHandoffContractError {}

/// Explicit bounded tracker recipe, converted to the existing package owner at the I/O boundary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PackageHandoffTracking {
    /// Consecutive actual hits needed for confirmation, in `1..=64`.
    pub confirmation_hits: u32,
    /// Consecutive misses before retirement, in `1..=64`.
    pub maximum_missed_frames: u32,
    /// Minimum global-assignment IoU in parts per million, in `0..=1_000_000`.
    pub minimum_iou_ppm: u32,
}

impl PackageHandoffTracking {
    /// Check the bounded subset used by this consumer before any source is read.
    pub fn validate(self) -> Result<(), PackageHandoffContractError> {
        if !(1..=MAX_PACKAGE_HANDOFF_FRAMES as u32).contains(&self.confirmation_hits)
            || !(1..=MAX_PACKAGE_HANDOFF_FRAMES as u32).contains(&self.maximum_missed_frames)
            || self.minimum_iou_ppm > 1_000_000
        {
            return Err(PackageHandoffContractError::Invalid("tracking policy"));
        }
        Ok(())
    }

    pub(super) fn encode(self, e: &mut CanonicalEncoder) {
        e.u32(self.confirmation_hits);
        e.u32(self.maximum_missed_frames);
        e.u32(self.minimum_iou_ppm);
    }
}

/// Caller-declared interval mapping from one pinned retained stream to the common clock.
/// Neither an offset nor a digest establishes synchronization or turns `estimated` into UTC.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageClockAlignment {
    /// Exact retained import the declaration applies to.
    pub import_identity: ContentDigest,
    /// Exact source stream generation; checked against every selected capsule.
    pub stream_id: String,
    /// Original source clock basis; checked and retained without upgrading its semantics.
    pub clock_basis: ClockBasis,
    /// Inclusive additive offset interval in nanoseconds, applied to the full capture interval.
    pub offset_ns: [i64; 2],
    /// Explicit operator basis for the mapping; retained as an assumption, not fetched evidence.
    pub basis: ContentDigest,
}

impl PackageClockAlignment {
    /// Validate declaration shape without asserting that the named source exists.
    pub fn validate(&self) -> Result<(), PackageHandoffContractError> {
        if !sha(self.import_identity)
            || !sha(self.basis)
            || !identifier(&self.stream_id, continuity::MAX_ID_BYTES)
            || self.offset_ns[0] > self.offset_ns[1]
        {
            return Err(PackageHandoffContractError::Invalid("clock alignment"));
        }
        Ok(())
    }

    /// Minkowski-sum interval mapping with checked `i128` arithmetic and no narrowing.
    pub fn align(&self, capture: [i128; 2]) -> Result<[i64; 2], PackageHandoffContractError> {
        self.validate()?;
        if capture[0] > capture[1] {
            return Err(PackageHandoffContractError::Invalid(
                "source capture interval",
            ));
        }
        let lower = capture[0]
            .checked_add(i128::from(self.offset_ns[0]))
            .ok_or(PackageHandoffContractError::TimeOverflow)?;
        let upper = capture[1]
            .checked_add(i128::from(self.offset_ns[1]))
            .ok_or(PackageHandoffContractError::TimeOverflow)?;
        Ok([
            i64::try_from(lower).map_err(|_| PackageHandoffContractError::TimeOverflow)?,
            i64::try_from(upper).map_err(|_| PackageHandoffContractError::TimeOverflow)?,
        ])
    }

    pub(super) fn encode(&self, e: &mut CanonicalEncoder) {
        e.digest(self.import_identity);
        e.text(&self.stream_id);
        e.text(self.clock_basis.as_str());
        e.i128(i128::from(self.offset_ns[0]));
        e.i128(i128::from(self.offset_ns[1]));
        e.digest(self.basis);
    }
}

/// Select an exact native anonymous track from a source-rebuilt package analysis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageHandoffSelection {
    /// Query-local alias used by the directed transition declarations.
    pub id: String,
    /// Digest of a package-detection JSON report already retained by the native detector owner.
    pub report_digest: ContentDigest,
    /// Exact chosen label in that retained model vocabulary.
    pub label: String,
    /// Exact bounded tracking recipe used to reconstruct the analysis.
    pub tracking: PackageHandoffTracking,
    /// Native track identity from that reconstructed analysis, never a physical identity.
    pub track: ContentDigest,
    /// Caller-declared calibration generation; this consumer does not certify camera geometry.
    pub calibration: ContentDigest,
    /// Pinned source-to-common-clock assumption, with all original uncertainty retained.
    pub alignment: PackageClockAlignment,
}

/// Complete retained-source query; property, privacy, model and stream facts are not caller input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageHandoffRequest {
    /// Local bounded analysis session; no cross-deployment continuity is constructed.
    pub session: String,
    /// Caller-declared analysis generation, distinct from the actual authority anchor.
    pub generation: ContentDigest,
    /// Declared common clock identity shared by the explicit source alignments and transit bounds.
    pub clock: ContentDigest,
    /// Common nonnegative integer objective unit, not probability or confidence.
    pub cost_unit: String,
    /// Declared cost of a path beginning, including a singleton.
    pub birth_cost: u64,
    /// Declared cost of a path ending, including a singleton.
    pub end_cost: u64,
    /// Exact displayed-prefix request; the implicit admitted family remains complete.
    pub k: u32,
    /// Every requested native track, bounded to 32, from at most four distinct analysis recipes.
    pub selections: Vec<PackageHandoffSelection>,
    /// Caller-declared transit/cost/geometry assumptions; undeclared pairs remain unavailable.
    pub transitions: Vec<Transition>,
}

impl PackageHandoffRequest {
    /// Refuse malformed and duplicate declarations before source/authority work starts.
    pub fn validate(&self) -> Result<(), PackageHandoffContractError> {
        if self.selections.is_empty()
            || self.selections.len() > MAX_PACKAGE_HANDOFF_TRACKS
            || self.transitions.len() > continuity::MAX_TRANSITIONS
        {
            return Err(PackageHandoffContractError::Limit);
        }
        if !identifier(&self.session, continuity::MAX_ID_BYTES)
            || !identifier(&self.cost_unit, continuity::MAX_UNIT_BYTES)
            || !sha(self.generation)
            || !sha(self.clock)
            || !(1..=continuity::MAX_K).contains(&self.k)
        {
            return Err(PackageHandoffContractError::Invalid("scope or objective"));
        }
        let mut ids = BTreeSet::new();
        let mut native = BTreeSet::new();
        let mut analyses = BTreeSet::new();
        for selected in &self.selections {
            if !identifier(&selected.id, continuity::MAX_ID_BYTES)
                || !ids.insert(selected.id.as_str())
                || selected.label.is_empty()
                || selected.label.len() > MAX_PACKAGE_HANDOFF_TEXT
                || !sha(selected.report_digest)
                || !sha(selected.track)
                || !sha(selected.calibration)
                || !native.insert((selected.report_digest, selected.track))
            {
                return Err(PackageHandoffContractError::Invalid(
                    "track selection or alias",
                ));
            }
            selected.tracking.validate()?;
            selected.alignment.validate()?;
            analyses.insert((selected.report_digest, &selected.label, selected.tracking));
        }
        if analyses.len() > MAX_PACKAGE_HANDOFF_ANALYSES {
            return Err(PackageHandoffContractError::Limit);
        }
        let mut pairs = BTreeSet::new();
        for edge in &self.transitions {
            if edge.from == edge.to
                || !ids.contains(edge.from.as_str())
                || !ids.contains(edge.to.as_str())
                || !pairs.insert((&edge.from, &edge.to))
                || edge.transit[0] > edge.transit[1]
                || !sha(edge.basis)
            {
                return Err(PackageHandoffContractError::Invalid("transition"));
            }
        }
        Ok(())
    }

    /// Complete canonical request identity; input declaration order does not change it.
    pub fn digest(&self) -> Result<ContentDigest, PackageHandoffContractError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text(PACKAGE_HANDOFF_REQUEST_DOMAIN);
        e.text(&self.session);
        e.digest(self.generation);
        e.digest(self.clock);
        e.text(&self.cost_unit);
        e.u64(self.birth_cost);
        e.u64(self.end_cost);
        e.u32(self.k);
        let mut selections: Vec<_> = self.selections.iter().collect();
        selections.sort_unstable_by(|a, b| a.id.cmp(&b.id));
        e.u64(selections.len() as u64);
        for selected in selections {
            e.text(&selected.id);
            e.digest(selected.report_digest);
            e.text(&selected.label);
            selected.tracking.encode(&mut e);
            e.digest(selected.track);
            e.digest(selected.calibration);
            selected.alignment.encode(&mut e);
        }
        let mut transitions: Vec<_> = self.transitions.iter().collect();
        transitions.sort_unstable_by(|a, b| (&a.from, &a.to).cmp(&(&b.from, &b.to)));
        e.u64(transitions.len() as u64);
        for edge in transitions {
            e.text(&edge.from);
            e.text(&edge.to);
            e.u64(edge.transit[0]);
            e.u64(edge.transit[1]);
            e.u64(edge.cost);
            e.digest(edge.basis);
        }
        Ok(ContentDigest::sha256(&e.finish()))
    }
}

/// Actual assigned detector observation joined to its verified source capsule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageHandoffObservation {
    /// Original retained source-segment index.
    pub segment: u64,
    /// Exact source-capsule canonical payload digest.
    pub capsule_digest: ContentDigest,
    /// Digest of the original encoded source bytes named by that capsule.
    pub source_digest: ContentDigest,
    /// Complete original conservative source interval, before any declared clock mapping.
    pub capture: [i128; 2],
    /// Conservative mapped interval in common signed nanoseconds.
    pub aligned_capture: [i64; 2],
    /// Detector row actually assigned by the native tracker.
    pub detection_row: u64,
    /// Actual retained vocabulary index, preserved separately from the label text.
    pub class_index: u64,
    /// Original uncalibrated F32 score bits; never an association probability.
    pub score_bits: u32,
    /// Assigned detector's original clipped source-grid XYXY coordinates in 1/256 pixels.
    pub bounds: [u32; 4],
    /// Exact actual model invocation identity.
    pub inference_identity: ContentDigest,
    /// Exact output tensor digest.
    pub output_digest: ContentDigest,
    /// Exact native head projection report digest.
    pub detection_report_digest: ContentDigest,
    /// Whether this exact sample was confirmed then; later confirmation never rewrites history.
    pub confirmed: bool,
}

/// Complete public provenance of one selected track; only the reference owner authenticates it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageHandoffBinding {
    /// Query-local selection alias.
    pub id: String,
    /// Native retained package-detection JSON identity.
    pub report_digest: ContentDigest,
    /// Canonical rebuilt package-analysis identity.
    pub analysis_digest: ContentDigest,
    /// Exact package record ledger payload identity.
    pub record_digest: ContentDigest,
    /// Retained package-detection root.
    pub retained_root: ContentDigest,
    /// Exact original import identity.
    pub import_identity: ContentDigest,
    /// Exact retained import root.
    pub import_root: ContentDigest,
    /// Original package-detection retention anchor, checked within the current projection universe.
    pub retained_anchor: LedgerAnchor,
    /// Native local track identity.
    pub track: ContentDigest,
    /// Source-authenticated sensor identity used as the native camera identity.
    pub sensor_id: String,
    /// Source-authenticated stream-generation identity.
    pub stream_id: String,
    /// Original source clock basis, never upgraded by the alignment declaration.
    pub clock_basis: ClockBasis,
    /// Original retained import's time label, such as `operator_assumption` or `unknown`.
    pub capture_time_label: String,
    /// Verified constant source image dimensions `[width, height]` within this track epoch.
    pub dimensions: [u32; 2],
    /// Exact sensor/stream/dimension generation binding, not physical camera calibration.
    pub camera_generation: ContentDigest,
    /// Explicit caller-declared calibration handle, not authenticated metric geometry.
    pub calibration: ContentDigest,
    /// Complete detector/head/label comparison-space identity.
    pub model: ContentDigest,
    /// Exact detector package archive.
    pub package_digest: ContentDigest,
    /// Exact detector package manifest.
    pub manifest_digest: ContentDigest,
    /// Exact built model artifact.
    pub model_digest: ContentDigest,
    /// Exact canonical graph artifact.
    pub graph_digest: ContentDigest,
    /// Exact detector head contract.
    pub contract_digest: ContentDigest,
    /// Retained model identifier.
    pub model_id: String,
    /// Retained immutable model generation string.
    pub model_generation: String,
    /// Selected retained label.
    pub label: String,
    /// Selected retained vocabulary index.
    pub class_index: u64,
    /// Exact tracker recipe used by the rebuilt report.
    pub tracking: PackageHandoffTracking,
    /// Actual current privacy-mask binding, including the explicit no-policy marker.
    pub privacy_binding: ContentDigest,
    /// Actual current mask policy, or explicit absence of a retained mask policy.
    pub privacy_policy: Option<ContentDigest>,
    /// All explicit pinned clock assumptions.
    pub alignment: PackageClockAlignment,
    /// Every actual observation, in the native track's original display order.
    pub observations: Vec<PackageHandoffObservation>,
    /// Whether this native track was ever confirmed, without relabeling tentative observations.
    pub confirmed: bool,
}

/// Pure source-stream generation binding used by the authenticating owner.
pub fn camera_generation(
    sensor_id: &str,
    stream_id: &str,
    dimensions: [u32; 2],
) -> Result<ContentDigest, PackageHandoffContractError> {
    if !identifier(sensor_id, continuity::MAX_ID_BYTES)
        || !identifier(stream_id, continuity::MAX_ID_BYTES)
        || dimensions.contains(&0)
    {
        return Err(PackageHandoffContractError::Invalid("source generation"));
    }
    let mut e = CanonicalEncoder::new();
    e.text(PACKAGE_HANDOFF_CAMERA_DOMAIN);
    e.text(sensor_id);
    e.text(stream_id);
    e.u32(dimensions[0]);
    e.u32(dimensions[1]);
    Ok(ContentDigest::sha256(&e.finish()))
}

/// Derive the complete comparison identity from authenticated binding fields.
/// This function does not authenticate a caller-created binding.
#[must_use]
pub fn model_comparison_key(binding: &PackageHandoffBinding) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(PACKAGE_HANDOFF_MODEL_DOMAIN);
    e.digest(binding.package_digest);
    e.digest(binding.manifest_digest);
    e.digest(binding.model_digest);
    e.digest(binding.graph_digest);
    e.digest(binding.contract_digest);
    e.text(&binding.model_id);
    e.text(&binding.model_generation);
    e.text(&binding.label);
    e.u64(binding.class_index);
    ContentDigest::sha256(&e.finish())
}

/// Project consistent public bindings into the existing conditional native query.
///
/// This is a pure transformation, not a custody reader or an authority constructor. Only the
/// enclosing owner can establish that the supplied bindings came from authenticated sources.
/// Endpoints are the first and last actual matched captures in native display order; an event
/// interval, segment-number ordering or an interior extreme never substitutes for either one.
pub fn continuity_query(
    anchor: &LedgerAnchor,
    request: &PackageHandoffRequest,
    bindings: &[PackageHandoffBinding],
) -> Result<ContinuityQuery, PackageHandoffContractError> {
    request.validate()?;
    if !identifier(&anchor.site_lineage, continuity::MAX_ID_BYTES) || !sha(anchor.state_root) {
        return Err(PackageHandoffContractError::Invalid("authority anchor"));
    }
    if bindings.len() != request.selections.len() {
        return Err(PackageHandoffContractError::Invalid("complete binding set"));
    }
    let selected: BTreeMap<_, _> = request
        .selections
        .iter()
        .map(|row| (row.id.as_str(), row))
        .collect();
    let mut ids = BTreeSet::new();
    let mut assigned = BTreeSet::new();
    let mut privacy = BTreeMap::new();
    let mut alignments = BTreeMap::new();
    let mut tracklets = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let selection = selected
            .get(binding.id.as_str())
            .ok_or(PackageHandoffContractError::Invalid("unselected binding"))?;
        if !ids.insert(binding.id.as_str())
            || binding.report_digest != selection.report_digest
            || binding.track != selection.track
            || binding.label != selection.label
            || binding.tracking != selection.tracking
            || binding.calibration != selection.calibration
            || binding.alignment != selection.alignment
            || binding.alignment.import_identity != binding.import_identity
            || binding.alignment.stream_id != binding.stream_id
            || binding.alignment.clock_basis != binding.clock_basis
            || binding.retained_anchor.site_lineage != anchor.site_lineage
            || binding.retained_anchor.ledger_epoch != anchor.ledger_epoch
            || binding.retained_anchor.commit_sequence > anchor.commit_sequence
            || !sha(binding.retained_anchor.state_root)
            || !identifier(&binding.sensor_id, continuity::MAX_ID_BYTES)
            || !identifier(&binding.stream_id, continuity::MAX_ID_BYTES)
            || !matches!(
                binding.capture_time_label.as_str(),
                "operator_assumption" | "unknown"
            )
            || binding.observations.is_empty()
            || binding.observations.len() > MAX_PACKAGE_HANDOFF_FRAMES
            || binding.model_id.is_empty()
            || binding.model_id.len() > MAX_PACKAGE_HANDOFF_TEXT
            || binding.model_generation.is_empty()
            || binding.model_generation.len() > MAX_PACKAGE_HANDOFF_TEXT
            || binding.model != model_comparison_key(binding)
            || binding.camera_generation
                != camera_generation(&binding.sensor_id, &binding.stream_id, binding.dimensions)?
            || [
                binding.analysis_digest,
                binding.record_digest,
                binding.retained_root,
                binding.import_identity,
                binding.import_root,
                binding.package_digest,
                binding.manifest_digest,
                binding.model_digest,
                binding.graph_digest,
                binding.contract_digest,
                binding.privacy_binding,
            ]
            .into_iter()
            .any(|digest| !sha(digest))
            || binding.privacy_policy.is_some_and(|digest| !sha(digest))
        {
            return Err(PackageHandoffContractError::Invalid(
                "source binding disagrees with selection",
            ));
        }
        if privacy
            .insert(
                binding.sensor_id.as_str(),
                (binding.privacy_binding, binding.privacy_policy),
            )
            .is_some_and(|previous| previous != (binding.privacy_binding, binding.privacy_policy))
        {
            return Err(PackageHandoffContractError::Invalid(
                "inconsistent sensor privacy",
            ));
        }
        if alignments
            .insert(binding.import_identity, &binding.alignment)
            .is_some_and(|previous| previous != &binding.alignment)
        {
            return Err(PackageHandoffContractError::Invalid(
                "inconsistent import clock alignment",
            ));
        }
        let mut frames = BTreeSet::new();
        let [width, height] = binding.dimensions;
        let maximum_x = width
            .checked_mul(256)
            .ok_or(PackageHandoffContractError::Limit)?;
        let maximum_y = height
            .checked_mul(256)
            .ok_or(PackageHandoffContractError::Limit)?;
        for (index, observation) in binding.observations.iter().enumerate() {
            let score = f32::from_bits(observation.score_bits);
            let [x0, y0, x1, y1] = observation.bounds;
            // Even a new alias or tracking recipe cannot make one assigned detector row
            // independent evidence twice. Be conservative across model aliases as well.
            if !assigned.insert((
                observation.capsule_digest,
                observation.detection_row,
                observation.class_index,
            )) || !frames.insert((observation.segment, observation.capsule_digest))
                || observation.class_index != binding.class_index
                || observation.aligned_capture != binding.alignment.align(observation.capture)?
                || !score.is_finite()
                || !(0.0..=1.0).contains(&score)
                || x0 >= x1
                || y0 >= y1
                || x1 > maximum_x
                || y1 > maximum_y
                || observation.confirmed
                    != (index + 1 >= binding.tracking.confirmation_hits as usize)
                || [
                    observation.capsule_digest,
                    observation.source_digest,
                    observation.inference_identity,
                    observation.output_digest,
                    observation.detection_report_digest,
                ]
                .into_iter()
                .any(|digest| !sha(digest))
            {
                return Err(PackageHandoffContractError::Invalid(
                    "assigned observation binding",
                ));
            }
        }
        let first = &binding.observations[0];
        let last = &binding.observations[binding.observations.len() - 1];
        if binding.confirmed != last.confirmed || first.aligned_capture[0] > last.aligned_capture[1]
        {
            return Err(PackageHandoffContractError::Invalid(
                "track endpoints or confirmation",
            ));
        }
        let mut evidence = vec![
            binding.report_digest,
            binding.analysis_digest,
            binding.record_digest,
            binding.retained_root,
            binding.import_identity,
            binding.import_root,
            binding.track,
        ];
        evidence.sort_unstable();
        evidence.dedup();
        tracklets.push(Tracklet {
            id: binding.id.clone(),
            camera: binding.sensor_id.clone(),
            camera_generation: binding.camera_generation,
            calibration: binding.calibration,
            model: binding.model,
            evidence,
            start: first.aligned_capture,
            end: last.aligned_capture,
            support: TrackletSupport::Declared,
        });
    }
    let mut e = CanonicalEncoder::new();
    e.text(PACKAGE_HANDOFF_PRIVACY_DOMAIN);
    e.text(&anchor.site_lineage);
    e.u64(anchor.privacy_epoch);
    e.u64(privacy.len() as u64);
    for (sensor, (binding, policy)) in privacy {
        e.text(sensor);
        e.digest(binding);
        match policy {
            Some(digest) => {
                e.u8(1);
                e.digest(digest);
            }
            None => e.u8(0),
        }
    }
    tracklets.sort_unstable_by(|a, b| a.id.cmp(&b.id));
    let mut transitions = request.transitions.clone();
    transitions.sort_unstable_by(|a, b| (&a.from, &a.to).cmp(&(&b.from, &b.to)));
    Ok(ContinuityQuery {
        scope: Scope {
            property: anchor.site_lineage.clone(),
            session: request.session.clone(),
            privacy_policy: ContentDigest::sha256(&e.finish()),
            generation: request.generation,
            clock: request.clock,
        },
        time_unit: "nanoseconds".into(),
        cost_unit: request.cost_unit.clone(),
        birth_cost: request.birth_cost,
        end_cost: request.end_cost,
        k: request.k,
        tracklets,
        transitions,
    })
}

/// Canonical full projection payload after applying the same pure consistency checks.
/// The bytes bind every source fact, the full current and retention anchors, exact observation
/// order and all caller declarations. They do not themselves certify that custody was checked.
pub fn projection_bytes(
    anchor: &LedgerAnchor,
    request: &PackageHandoffRequest,
    bindings: &[PackageHandoffBinding],
) -> Result<Vec<u8>, PackageHandoffContractError> {
    let query = continuity_query(anchor, request, bindings)?;
    let mut e = CanonicalEncoder::new();
    e.text(PACKAGE_HANDOFF_PROJECTION_DOMAIN);
    e.bytes(&anchor.canonical_bytes());
    e.digest(request.digest()?);
    e.digest(query.scope.privacy_policy);
    e.text(&query.time_unit);
    let mut ordered: Vec<_> = bindings.iter().collect();
    ordered.sort_unstable_by(|a, b| a.id.cmp(&b.id));
    e.u64(ordered.len() as u64);
    for binding in ordered {
        e.text(&binding.id);
        for digest in [
            binding.report_digest,
            binding.analysis_digest,
            binding.record_digest,
            binding.retained_root,
            binding.import_identity,
            binding.import_root,
        ] {
            e.digest(digest);
        }
        e.bytes(&binding.retained_anchor.canonical_bytes());
        e.digest(binding.track);
        e.bool(binding.confirmed);
        e.text(&binding.sensor_id);
        e.text(&binding.stream_id);
        e.text(binding.clock_basis.as_str());
        e.text(&binding.capture_time_label);
        e.u32(binding.dimensions[0]);
        e.u32(binding.dimensions[1]);
        for digest in [
            binding.camera_generation,
            binding.calibration,
            binding.model,
            binding.package_digest,
            binding.manifest_digest,
            binding.model_digest,
            binding.graph_digest,
            binding.contract_digest,
        ] {
            e.digest(digest);
        }
        e.text(&binding.model_id);
        e.text(&binding.model_generation);
        e.text(&binding.label);
        e.u64(binding.class_index);
        binding.tracking.encode(&mut e);
        e.digest(binding.privacy_binding);
        match binding.privacy_policy {
            Some(digest) => {
                e.u8(1);
                e.digest(digest);
            }
            None => e.u8(0),
        }
        binding.alignment.encode(&mut e);
        e.u64(binding.observations.len() as u64);
        for observation in &binding.observations {
            e.u64(observation.segment);
            e.digest(observation.capsule_digest);
            e.digest(observation.source_digest);
            for value in observation.capture {
                e.i128(value);
            }
            for value in observation.aligned_capture {
                e.i128(i128::from(value));
            }
            e.u64(observation.detection_row);
            e.u64(observation.class_index);
            e.u32(observation.score_bits);
            for value in observation.bounds {
                e.u32(value);
            }
            e.digest(observation.inference_identity);
            e.digest(observation.output_digest);
            e.digest(observation.detection_report_digest);
            e.bool(observation.confirmed);
        }
    }
    if e.has_error() {
        return Err(PackageHandoffContractError::Limit);
    }
    Ok(e.finish())
}

fn sha(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256 && digest.bytes().iter().any(|b| *b != 0)
}

fn identifier(text: &str, maximum: usize) -> bool {
    !text.is_empty()
        && text.len() <= maximum
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":_.-".contains(&b))
}
