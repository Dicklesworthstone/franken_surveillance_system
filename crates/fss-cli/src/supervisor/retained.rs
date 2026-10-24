#![forbid(unsafe_code)]
//! Source-backed detector-class supervision over current retained package events.
//!
//! Every score comes from the exact detection assigned to a retained local track. The caller
//! pins events, sensors and package families; neither caller scores nor event probability
//! substitutes are accepted. Windows contain a cumulative set of unique observations. Repeated
//! evidence never becomes an additional likelihood increment. This is bounded class advice,
//! without geometry, physical-actor association, absence, calibration activation or effects.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{
    CanonicalEncoder, ClockBasis, ContentDigest, DigestAlgorithm, EventId, LedgerAnchor,
    SensorId,
};
use fss_fusion::{
    Calibration, Coverage, EvidenceItem, FusionOutcome, FusionPolicy, FusionQuery, LlrInterval,
    Observability, ScoreCalibration, Severity, fuse,
};
use fss_object::{SpoolError, SpoolReadBudgetUsage};
use fss_reference::agent_orient::{DeploymentHistory, OrientLimits};
use fss_reference::ingest::package_event::{PackageEvent, PackageEventError};
use fss_reference::{ReferenceDeployment, ReplayCx};

use crate::event_fusion::{EventFusionError, calibrated_score};

mod budget;
mod clock;
mod discovery;
mod input;
mod render;

use budget::package_error;
use clock::SourceClocks;

pub use discovery::{
    MAX_RETAINED_DISCOVERY_CATALOG_EVENTS, MAX_RETAINED_DISCOVERY_CATALOG_OBJECTS,
    MAX_RETAINED_DISCOVERY_EXCLUSIONS, MAX_RETAINED_DISCOVERY_HISTORY_SCAN_UNITS,
    RETAINED_DISCOVERY_REPORT_SCHEMA, RETAINED_DISCOVERY_REQUEST_SCHEMA,
    RetainedDiscoveryReport, RetainedDiscoveryRequest, RetainedDiscoverySource,
    RetainedDiscoveryValidation, revalidate_retained_discovery_sources,
    run_discovered_retained_supervisor,
};

/// Complete digest-pinned plan byte ceiling, before JSON parsing.
pub const MAX_RETAINED_SUPERVISOR_PLAN_BYTES: usize = 256 * 1024;
/// Complete report ceiling. Reports are refused, never truncated.
pub const MAX_RETAINED_SUPERVISOR_REPORT_BYTES: usize = 2 * 1024 * 1024;
/// Maximum independent native camera bindings in one plan.
pub const MAX_RETAINED_SUPERVISOR_CAMERAS: usize = 8;
/// Maximum unique retained events opened once during a run.
pub const MAX_RETAINED_SUPERVISOR_EVENTS: usize = 32;
/// Maximum cumulative evaluation windows.
pub const MAX_RETAINED_SUPERVISOR_WINDOWS: usize = 32;
/// Maximum unique native observations retained by a run.
pub const MAX_RETAINED_SUPERVISOR_OBSERVATIONS: usize = 128;
/// Total selector ceiling, including repeated selections in later windows.
pub const MAX_RETAINED_SUPERVISOR_SELECTIONS: usize = 512;
/// Versioned operator plan schema.
pub const RETAINED_SUPERVISOR_PLAN_SCHEMA: &str = "fss.retained_supervisor_plan.v1";
/// Versioned complete report schema.
pub const RETAINED_SUPERVISOR_REPORT_SCHEMA: &str = "fss.retained_supervisor_report.v1";

/// Per-sensor package and calibration applicability selected by the local owner.
#[derive(Clone, Debug)]
pub struct RetainedCameraSpec {
    /// Local alias; never substituted for native sensor identity.
    pub camera_id: String,
    /// Exact retained sensor identifier.
    pub sensor_id: String,
    /// Exact package archive digest.
    pub package_digest: ContentDigest,
    /// Exact built native model digest.
    pub model_digest: ContentDigest,
    /// Exact detection-head contract digest.
    pub contract_digest: ContentDigest,
    /// Requested class in this package's own vocabulary.
    pub class_index: u64,
    /// Additional owner-declared common causes; intrinsic causes cannot be removed.
    pub failure_domains: BTreeSet<String>,
    /// Rebuilt count calibration, or explicitly uncalibrated advice.
    pub calibration: Option<ScoreCalibration>,
}

/// One current published event and its independently expected revision root.
#[derive(Clone, Debug)]
pub struct RetainedEventPin {
    /// Configured camera whose native sensor must match.
    pub camera_id: String,
    /// Exact event, whose current package policy and track are independently reopened.
    pub event_id: EventId,
    /// Event revision root, not provenance or report root.
    pub expected_event_root: ContentDigest,
}

/// Exact native row selector; contains no supplied score or observability assertion.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RetainedObservationSelector {
    /// A declared event pin.
    pub event_id: EventId,
    /// Original source capsule payload digest.
    pub capsule_digest: ContentDigest,
    /// Exact retained segment number.
    pub segment: u64,
    /// Exact head row actually assigned to the selected event's track.
    pub detection_row: u64,
}

/// One cumulative look over `[start_ns, end_ns]`.
#[derive(Clone, Debug)]
pub struct RetainedSupervisorWindow {
    /// Consecutive index, beginning at zero.
    pub window_index: u64,
    /// Strictly increasing upper coordinate in the original source basis; never wall time.
    /// A uniform basis does not establish synchronization between cameras.
    pub end_ns: u64,
    /// New or previously selected observations; duplicates within this window refuse.
    pub observations: Vec<RetainedObservationSelector>,
}

/// Work allowances separate bounded journal observations from source-object custody reads.
#[derive(Clone, Copy, Debug)]
pub struct RetainedSupervisorLimits {
    /// Nonrefillable stored-object envelope bytes, including bounded EOF probes.
    pub max_read_bytes: u64,
    /// Nonrefillable indexed object-read attempts, including unsuccessful reads.
    pub max_read_attempts: u64,
    /// Per-journal byte ceiling for each of two fresh authority observations.
    pub max_journal_bytes: usize,
    /// Complete report byte ceiling.
    pub max_report_bytes: usize,
}

/// Untrusted specification. [`RetainedSupervisorPlan::new`] checks every field before I/O.
#[derive(Clone, Debug)]
pub struct RetainedSupervisorSpec {
    /// Independently expected deployment lineage.
    pub site_lineage: String,
    /// Class-advice hypothesis identity, not a physical actor or zone identity.
    pub hypothesis_id: String,
    /// Exact current authority state root.
    pub expected_authority_root: ContentDigest,
    /// Exact package class label shared by the configured class indices.
    pub label: String,
    /// Earliest capture coordinate in the original source basis, preserved for every window.
    pub start_ns: u64,
    /// Unique aliases and unique native sensors, with pinned package families.
    pub cameras: Vec<RetainedCameraSpec>,
    /// Unique exact current event pins; every pin must be selected at least once.
    pub events: Vec<RetainedEventPin>,
    /// Consecutive cumulative windows, including explicit empty looks.
    pub windows: Vec<RetainedSupervisorWindow>,
    /// Explicit owner prior; never inferred from calibration sample prevalence.
    pub prior: LlrInterval,
    /// Explicit read-only fusion decision policy.
    pub policy: FusionPolicy,
    /// Explicit consequence assumptions.
    pub severity: Severity,
    /// Admitted physical object-read and complete report allowances.
    pub limits: RetainedSupervisorLimits,
}

/// Immutable validated specification and canonical semantic identity.
#[derive(Clone, Debug)]
pub struct RetainedSupervisorPlan {
    spec: RetainedSupervisorSpec,
    digest: ContentDigest,
}

/// Typed refusal. No successful or partial advice report accompanies an error.
#[derive(Debug)]
pub enum RetainedSupervisorError {
    /// Malformed, contradictory or unbounded plan input.
    Plan(&'static str),
    /// A finite admitted dimension was exhausted.
    Limit(&'static str),
    /// Exact camera, event, capture, package, class or track-row binding failed.
    Selection(&'static str),
    /// Expected authority differs, or durable authority changed during the read.
    Authority,
    /// Fresh bounded journal observation failed.
    History,
    /// Owner cancellation or deadline refused a checkpoint.
    Cancelled,
    /// Existing package reader refusal, including privacy, deletion and missing custody.
    Package(PackageEventError),
    /// Existing shared native-score or calibration admission refusal.
    Fusion(EventFusionError),
    /// Existing fusion engine refusal.
    Engine(fss_fusion::FusionError),
    /// Stored-object read budget admission refused.
    ReadBudget(SpoolError),
}

impl RetainedSupervisorError {
    /// Stable diagnostic, preserving underlying source-owner identities.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Plan(_) => "ERR-SUPERVISOR-RETAINED-PLAN-001",
            Self::Limit(_) | Self::ReadBudget(_) => "ERR-SUPERVISOR-RETAINED-LIMIT-001",
            Self::Selection(_) => "ERR-SUPERVISOR-RETAINED-SELECTION-001",
            Self::Authority => "ERR-SUPERVISOR-STALE-ANCHOR-001",
            Self::History => "ERR-SUPERVISOR-RETAINED-HISTORY-001",
            Self::Cancelled => "ERR-SUPERVISOR-RETAINED-CANCELLED-001",
            Self::Package(error) => error.stable_id(),
            Self::Fusion(error) => error.stable_id(),
            Self::Engine(error) => error.stable_id(),
        }
    }
}

impl fmt::Display for RetainedSupervisorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.stable_id())?;
        match self {
            Self::Plan(reason) | Self::Limit(reason) | Self::Selection(reason) => f.write_str(reason),
            Self::Authority => f.write_str("retained supervisor authority differs or changed"),
            Self::History => f.write_str("bounded durable supervisor history unavailable"),
            Self::Cancelled => f.write_str("retained supervisor cancelled; no complete advice"),
            Self::Package(error) => write!(f, "retained supervisor source: {error}"),
            Self::Fusion(error) => write!(f, "retained supervisor calibration: {error}"),
            Self::Engine(error) => write!(f, "retained supervisor fusion: {error}"),
            Self::ReadBudget(error) => write!(f, "retained supervisor custody: {error}"),
        }
    }
}
impl std::error::Error for RetainedSupervisorError {}
type Error = RetainedSupervisorError;
type Result<T> = std::result::Result<T, Error>;

fn sha(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256 && digest.bytes() != [0; 32]
}
fn text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}
fn finish(encoder: CanonicalEncoder) -> Result<ContentDigest> {
    let bytes = encoder.finish_checked().map_err(|_| Error::Limit("canonical encoding"))?;
    Ok(ContentDigest::sha256(&bytes))
}
fn checkpoint(cx: &ReplayCx) -> Result<()> {
    cx.checkpoint("retained_supervisor:read").map_err(|_| Error::Cancelled)
}

impl RetainedSupervisorPlan {
    /// Validate and canonically bind all inputs without touching deployment or source files.
    pub fn new(mut spec: RetainedSupervisorSpec) -> Result<Self> {
        if !text(&spec.site_lineage, 192)
            || !text(&spec.hypothesis_id, 192)
            || !text(&spec.label, 128)
            || !sha(spec.expected_authority_root)
            || spec.cameras.is_empty()
            || spec.cameras.len() > MAX_RETAINED_SUPERVISOR_CAMERAS
            || spec.events.len() > MAX_RETAINED_SUPERVISOR_EVENTS
            || spec.windows.is_empty()
            || spec.windows.len() > MAX_RETAINED_SUPERVISOR_WINDOWS
        {
            return Err(Error::Plan("identity or collection bounds"));
        }
        let limits = spec.limits;
        if limits.max_read_bytes == 0 || limits.max_read_bytes > 1024 * 1024 * 1024
            || limits.max_read_attempts == 0 || limits.max_read_attempts > 100_000
            || limits.max_journal_bytes == 0 || limits.max_journal_bytes > 32 * 1024 * 1024
            || limits.max_report_bytes == 0
            || limits.max_report_bytes > MAX_RETAINED_SUPERVISOR_REPORT_BYTES
        {
            return Err(Error::Limit("read, history or output admission"));
        }
        // A native class score alone cannot authorize a corroborated recommendation.
        if spec.policy.min_independent_support < 2 {
            return Err(Error::Plan("class advice requires at least two independent supporting domains"));
        }
        let mut aliases = BTreeSet::new();
        let mut sensors = BTreeSet::new();
        let mut calibrations = BTreeMap::new();
        for camera in &spec.cameras {
            if !text(&camera.camera_id, 96)
                || !text(&camera.sensor_id, 192)
                || SensorId::parse(&camera.sensor_id).is_err()
                || !aliases.insert(camera.camera_id.clone())
                || !sensors.insert(camera.sensor_id.clone())
                || !sha(camera.package_digest) || !sha(camera.model_digest)
                || !sha(camera.contract_digest) || camera.class_index >= 256
                || camera.failure_domains.len() > 8
                || camera.failure_domains.iter().any(|d| !text(d, 192))
            {
                return Err(Error::Plan("unique camera, native sensor and package bindings"));
            }
            if let Some(c) = &camera.calibration {
                if !text(&c.generation, 160)
                    || c.bins.is_empty()
                    || c.bins.len() > fss_fusion::calibration::MAX_BINS
                {
                    return Err(Error::Plan("calibration generation or bin bound"));
                }
                let edges: Vec<_> = c.bins.iter().map(|b| b.lo_ppm).collect();
                let counts: Vec<_> = c.bins.iter().map(|b| (b.positives, b.negatives)).collect();
                let rebuilt = ScoreCalibration::from_counts(&c.generation, &edges, &counts)
                    .map_err(Error::Engine)?;
                if &rebuilt != c || calibrations.insert(c.generation.clone(), c.digest)
                    .is_some_and(|old| old != c.digest)
                {
                    return Err(Error::Plan("calibration counts, derived values or generation conflict"));
                }
            }
        }
        let mut events = BTreeSet::new();
        for event in &spec.events {
            if !aliases.contains(&event.camera_id) || !sha(event.expected_event_root)
                || !events.insert(event.event_id.clone())
            {
                return Err(Error::Plan("unique event roots and configured cameras"));
            }
        }
        let mut selected = BTreeSet::new();
        let mut selection_count = 0usize;
        let mut previous_end = None;
        for (index, window) in spec.windows.iter_mut().enumerate() {
            if window.window_index != index as u64 || window.end_ns < spec.start_ns
                || previous_end.is_some_and(|end| window.end_ns <= end)
            {
                return Err(Error::Plan("consecutive cumulative windows with increasing end times"));
            }
            previous_end = Some(window.end_ns);
            selection_count = selection_count.checked_add(window.observations.len())
                .filter(|n| *n <= MAX_RETAINED_SUPERVISOR_SELECTIONS)
                .ok_or(Error::Limit("observation selectors"))?;
            window.observations.sort();
            if window.observations.windows(2).any(|p| p[0] == p[1]) {
                return Err(Error::Plan("duplicate observation within a window"));
            }
            for observation in &window.observations {
                if !events.contains(&observation.event_id) || !sha(observation.capsule_digest) {
                    return Err(Error::Plan("observation must select a pinned event and source capsule"));
                }
                selected.insert(observation.event_id.clone());
            }
        }
        if selected != events {
            return Err(Error::Plan("unused event pins"));
        }
        spec.cameras.sort_by(|a, b| a.camera_id.cmp(&b.camera_id));
        spec.events.sort_by(|a, b| a.event_id.cmp(&b.event_id));
        // Reuse the owning engine's policy/interval admission before source work.
        let template = query(&spec, Vec::new(), 0, spec.windows[0].end_ns);
        fuse(&template).map_err(Error::Engine)?;
        let mut e = CanonicalEncoder::new();
        e.text(RETAINED_SUPERVISOR_PLAN_SCHEMA);
        e.text(&spec.site_lineage);
        e.digest(spec.expected_authority_root);
        e.digest(template.digest());
        e.u64(spec.start_ns);
        e.u64(spec.cameras.len() as u64);
        for camera in &spec.cameras {
            e.text(&camera.camera_id);
            e.text(&camera.sensor_id);
            for d in [camera.package_digest, camera.model_digest, camera.contract_digest] {
                e.digest(d);
            }
            e.u64(camera.class_index);
            e.u64(camera.failure_domains.len() as u64);
            for domain in &camera.failure_domains { e.text(domain); }
            e.bool(camera.calibration.is_some());
            if let Some(c) = &camera.calibration { e.digest(c.digest); }
        }
        e.u64(spec.events.len() as u64);
        for event in &spec.events {
            e.text(&event.camera_id);
            e.text(event.event_id.as_str());
            e.digest(event.expected_event_root);
        }
        e.u64(spec.windows.len() as u64);
        for window in &spec.windows {
            e.u64(window.window_index);
            e.u64(window.end_ns);
            e.u64(window.observations.len() as u64);
            for observation in &window.observations { encode_selector(&mut e, observation); }
        }
        e.u64(limits.max_read_bytes);
        e.u64(limits.max_read_attempts);
        e.u64(limits.max_journal_bytes as u64);
        e.u64(limits.max_report_bytes as u64);
        Ok(Self { spec, digest: finish(e)? })
    }

    /// Canonical identity of exact sources, calibration applicability, policy and limits.
    pub const fn digest(&self) -> ContentDigest { self.digest }
    /// Read-only validated specification.
    pub const fn spec(&self) -> &RetainedSupervisorSpec { &self.spec }
}

fn encode_selector(e: &mut CanonicalEncoder, observation: &RetainedObservationSelector) {
    e.text(observation.event_id.as_str());
    e.digest(observation.capsule_digest);
    e.u64(observation.segment);
    e.u64(observation.detection_row);
}

fn query(spec: &RetainedSupervisorSpec, evidence: Vec<EvidenceItem>, index: u64, end: u64) -> FusionQuery {
    FusionQuery {
        hypothesis: spec.hypothesis_id.clone(),
        kind: format!("selected_detector_class:{}", spec.label),
        prior: spec.prior,
        evidence,
        coverage: Coverage::Gap {
            reason: "selected retained detections do not certify class absence or cross-camera actor association".into(),
        },
        opportunities: Vec::new(),
        probes: Vec::new(),
        severity: spec.severity,
        policy: spec.policy.clone(),
        looks: index as u32 + 1,
        now_ns: end,
    }
}

/// Complete native binding of one deduplicated source observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedSupervisorObservation {
    /// Stable source-row identity, independent of event aliases and window count.
    pub identity: ContentDigest,
    /// Exact native sensor.
    pub sensor_id: String,
    /// Original source capsule.
    pub capsule_digest: ContentDigest,
    /// Exact retained segment.
    pub segment: u64,
    /// Conservative original capture interval (nanoseconds).
    pub capture_ns: [i128; 2],
    /// Original canonical source clock basis; never promoted to synchronized UTC.
    pub clock_basis: ClockBasis,
    /// Original retained import label: unknown or operator_assumption.
    pub capture_time_label: String,
    /// Exact package archive digest.
    pub package_digest: ContentDigest,
    /// Exact model identity.
    pub model_digest: ContentDigest,
    /// Model's named family, an intrinsic common cause across archive revisions.
    pub model_id: String,
    /// Original model generation.
    pub generation: String,
    /// Exact head contract.
    pub contract_digest: ContentDigest,
    /// Class in the original package vocabulary.
    pub class_index: u64,
    /// Original assigned head row.
    pub detection_row: u64,
    /// Original unrounded native score bits.
    pub score_bits: u32,
    /// Outward floor/ceiling score interval.
    pub score_ppm: [u32; 2],
    /// Native source-grid box, in 1/256 pixels.
    pub bounds: [u32; 4],
    /// Exact original native invocation identity.
    pub inference_identity: ContentDigest,
    /// Original output tensor identity.
    pub output_digest: ContentDigest,
    /// Original head projection report.
    pub detection_report_digest: ContentDigest,
    /// Exact selected calibration; absent means no numeric authority.
    pub calibration_digest: Option<ContentDigest>,
    /// Complete input to the unchanged fusion engine.
    pub evidence: EvidenceItem,
}

#[derive(Clone, Debug)]
struct SelectionLink {
    selector: RetainedObservationSelector,
    observation: ContentDigest,
    new_evidence: bool,
    event_root: ContentDigest,
    track: ContentDigest,
    analysis_digest: ContentDigest,
    detection_record: ContentDigest,
    detection_root: ContentDigest,
}

/// One complete class-advice look. Its inputs are unique cumulative observations.
#[derive(Clone, Debug)]
pub struct RetainedSupervisorWindowReport {
    /// Consecutive input window.
    pub window_index: u64,
    /// Upper end of the cumulative capture interval.
    pub end_ns: u64,
    /// Number of native rows added by this window.
    pub new_observations: usize,
    /// Total native rows, excluding explicit missing-camera placeholders.
    pub unique_observations: usize,
    /// Configured cameras with no new source observation in this look.
    pub cameras_without_new_observations: Vec<String>,
    /// Complete replayable engine query.
    pub query: FusionQuery,
    /// Full result, dependency clusters and counterfactuals.
    pub outcome: FusionOutcome,
    selections: Vec<SelectionLink>,
}

/// Complete bounded source-backed advice, produced only after final durable-head comparison.
#[derive(Debug)]
pub struct RetainedSupervisorReport {
    plan: RetainedSupervisorPlan,
    basis: LedgerAnchor,
    ledger_root: ContentDigest,
    effect_root: ContentDigest,
    observations: Vec<RetainedSupervisorObservation>,
    windows: Vec<RetainedSupervisorWindowReport>,
    read_before: SpoolReadBudgetUsage,
    read_after: SpoolReadBudgetUsage,
    digest: ContentDigest,
}

impl RetainedSupervisorReport {
    /// Native inputs in identity order, each present exactly once.
    pub fn observations(&self) -> &[RetainedSupervisorObservation] { &self.observations }
    /// Cumulative looks, each independently recomputed from unique evidence.
    pub fn windows(&self) -> &[RetainedSupervisorWindowReport] { &self.windows }
    /// Current authority observed before and after analysis.
    pub const fn basis(&self) -> &LedgerAnchor { &self.basis }
    /// Complete canonical report receipt.
    pub const fn digest(&self) -> ContentDigest { self.digest }
    /// Complete JSON; exceeding the selected ceiling refuses the entire report.
    pub fn to_json(&self) -> Result<String> {
        let json = render::report(self);
        if json.len() > self.plan.spec.limits.max_report_bytes { return Err(Error::Limit("complete report bytes")); }
        Ok(json)
    }
}

fn resolve(
    event: &PackageEvent,
    camera: &RetainedCameraSpec,
    selector: &RetainedObservationSelector,
    label: &str,
    start: u64,
    end: u64,
    deployment: &ReferenceDeployment,
    clocks: &mut SourceClocks,
    cx: &ReplayCx,
) -> Result<RetainedSupervisorObservation> {
    let report = event.report();
    let record = report.retained().record();
    if record.package_digest != camera.package_digest || record.model_digest != camera.model_digest
        || record.contract_digest != camera.contract_digest || report.class_index() != camera.class_index
        || report.label() != label || record.labels.get(camera.class_index as usize).map(String::as_str) != Some(label)
    { return Err(Error::Selection("package, model, head or class pin")); }
    let track = report.tracks().iter().find(|t| t.identity == event.track())
        .ok_or(Error::Selection("published track"))?;
    let observation = track.observations.iter().find(|o| {
        o.segment == selector.segment && o.capsule_digest == selector.capsule_digest
            && o.detection.as_ref().is_some_and(|d| d.0 == selector.detection_row)
    }).ok_or(Error::Selection("exact assigned track row"))?;
    let frame = record.frames.iter().find(|f| f.segment == selector.segment
        && f.capsule_digest == selector.capsule_digest).ok_or(Error::Selection("original frame"))?;
    if frame.sensor_id != camera.sensor_id || frame.capture.earliest.0 < i128::from(start)
        || frame.capture.latest.0 > i128::from(end) || frame.capture.earliest > frame.capture.latest
    { return Err(Error::Selection("native sensor or complete conservative capture interval")); }
    let source_time = clocks.read(deployment, record, frame, cx)?;
    let detection = frame.detections.iter().find(|d| d.row == selector.detection_row
        && d.class_index == camera.class_index).ok_or(Error::Selection("original class detection"))?;
    if observation.detection.as_ref().is_none_or(|d| d.1 != detection.score_bits || d.2 != detection.bounds) {
        return Err(Error::Selection("assigned detection differs from original native row"));
    }
    let (score_ppm, calibration) = calibrated_score(detection.score_bits, camera.calibration.as_ref())
        .map_err(Error::Fusion)?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.retained_supervisor_observation.v1");
    e.text(&frame.sensor_id);
    for d in [frame.capsule_digest, record.package_digest, record.model_digest, record.contract_digest] { e.digest(d); }
    e.u64(frame.segment);
    e.u64(detection.class_index);
    e.u64(detection.row);
    let identity = finish(e)?;
    let mut domains = camera.failure_domains.clone();
    // Shared source/model/calibration cannot acquire independence by changing camera aliases,
    // windows, event ids, package archive metadata or calibration generation labels.
    domains.insert(format!("model-family:{}", ContentDigest::sha256(record.model_id.as_bytes())));
    domains.insert(format!("model:{}", record.model_digest));
    domains.insert(format!("package:{}", record.package_digest));
    domains.insert(format!("head:{}", record.contract_digest));
    if let Some(c) = &camera.calibration { domains.insert(format!("calibration:{}", c.digest)); }
    let evidence = EvidenceItem {
        id: identity.to_text(), sensor: frame.sensor_id.clone(), failure_domains: domains,
        calibration, observability: Observability::Observed,
    };
    Ok(RetainedSupervisorObservation {
        identity, sensor_id: frame.sensor_id.clone(), capsule_digest: frame.capsule_digest,
        segment: frame.segment, capture_ns: [frame.capture.earliest.0, frame.capture.latest.0],
        clock_basis: source_time.clock_basis,
        capture_time_label: source_time.capture_time_label,
        package_digest: record.package_digest, model_digest: record.model_digest,
        model_id: record.model_id.clone(), generation: record.generation.clone(),
        contract_digest: record.contract_digest, class_index: detection.class_index,
        detection_row: detection.row, score_bits: detection.score_bits, score_ppm, bounds: detection.bounds,
        inference_identity: frame.inference_identity, output_digest: frame.output_digest,
        detection_report_digest: frame.detection_report_digest,
        calibration_digest: camera.calibration.as_ref().map(|c| c.digest), evidence,
    })
}

/// Read, verify and fuse exact retained native detections under one nonrefillable object budget.
///
/// The deployment's existing open/recovery limits apply before this function. Two bounded fresh
/// history reads bracket the analysis. The indexed object allowance remains tightened on this
/// handle after success or refusal; retrying cannot replenish it. This function publishes no
/// event, source, calibration, ledger record or effect and returns no partial report on refusal.
pub fn run_retained_supervisor(
    deployment: &mut ReferenceDeployment,
    plan: &RetainedSupervisorPlan,
    cx: &ReplayCx,
) -> Result<RetainedSupervisorReport> {
    checkpoint(cx)?;
    let spec = &plan.spec;
    if deployment.site_lineage() != spec.site_lineage
        || deployment.current_anchor().state_root != spec.expected_authority_root
    { return Err(Error::Authority); }
    let history_limits = OrientLimits { max_journal_bytes: spec.limits.max_journal_bytes, ..OrientLimits::default() };
    let history = DeploymentHistory::read(deployment.root(), &history_limits).map_err(|_| Error::History)?;
    checkpoint(cx)?;
    let head = history.head();
    let roots = history.roots_at(head).ok_or(Error::History)?;
    if roots.0 != *deployment.current_anchor() || history.site_lineage() != spec.site_lineage
        || history.replay_objects_root() != deployment.root().join(&deployment.layout_report().objects_relpath)
    { return Err(Error::Authority); }
    let read_before = deployment.publisher_mut()
        .tighten_read_budget(spec.limits.max_read_bytes, spec.limits.max_read_attempts)
        .map_err(Error::ReadBudget)?;
    let pins: BTreeMap<_, _> = spec.events.iter().map(|p| (p.event_id.clone(), p)).collect();
    let cameras: BTreeMap<_, _> = spec.cameras.iter().map(|c| (c.camera_id.as_str(), c)).collect();
    let mut clocks = SourceClocks::default();
    let mut opened = BTreeMap::<EventId, PackageEvent>::new();
    let mut observations = BTreeMap::<ContentDigest, RetainedSupervisorObservation>::new();
    let mut windows = Vec::with_capacity(spec.windows.len());
    for window in &spec.windows {
        checkpoint(cx)?;
        let previous_count = observations.len();
        let mut new_cameras = BTreeSet::new();
        let mut selections = Vec::with_capacity(window.observations.len());
        for selector in &window.observations {
            checkpoint(cx)?;
            let pin = pins.get(&selector.event_id).ok_or(Error::Plan("unknown event pin"))?;
            let camera = cameras.get(pin.camera_id.as_str()).ok_or(Error::Plan("unknown camera"))?;
            if !opened.contains_key(&selector.event_id) {
                let event = PackageEvent::open(deployment, &selector.event_id, cx).map_err(package_error)?;
                if event.root() != pin.expected_event_root { return Err(Error::Selection("current event revision root")); }
                opened.insert(selector.event_id.clone(), event);
            }
            let event = opened.get(&selector.event_id).ok_or(Error::Selection("opened event"))?;
            let observation = resolve(
                event, camera, selector, &spec.label, spec.start_ns, window.end_ns,
                deployment, &mut clocks, cx,
            )?;
            let identity = observation.identity;
            let new_evidence = match observations.get(&identity) {
                Some(old) if old != &observation => return Err(Error::Selection("same native row has conflicting evidence")),
                Some(_) => false,
                None => {
                    if observations.len() >= MAX_RETAINED_SUPERVISOR_OBSERVATIONS { return Err(Error::Limit("unique native observations")); }
                    observations.insert(identity, observation);
                    new_cameras.insert(camera.camera_id.clone());
                    true
                }
            };
            selections.push(SelectionLink {
                selector: selector.clone(), observation: identity, new_evidence,
                event_root: event.root(), track: event.track(), analysis_digest: event.report().digest(),
                detection_record: event.report().retained().record_digest(),
                detection_root: event.report().retained().root(),
            });
        }
        let mut evidence: Vec<_> = observations.values().map(|o| o.evidence.clone()).collect();
        for camera in &spec.cameras {
            if !observations.values().any(|o| o.sensor_id == camera.sensor_id) {
                let mut domains = camera.failure_domains.clone();
                domains.insert(format!("package:{}", camera.package_digest));
                evidence.push(EvidenceItem {
                    id: format!("unobserved:{}", camera.sensor_id), sensor: camera.sensor_id.clone(), failure_domains: domains,
                    calibration: Calibration::Uncalibrated { reason: "no selected retained class observation".into() },
                    observability: Observability::NotObservable { reason: "no source evidence selected for this camera".into() },
                });
            }
        }
        evidence.sort_by(|a, b| a.id.cmp(&b.id));
        let q = query(spec, evidence, window.window_index, window.end_ns);
        let outcome = fuse(&q).map_err(Error::Engine)?;
        windows.push(RetainedSupervisorWindowReport {
            window_index: window.window_index, end_ns: window.end_ns,
            new_observations: observations.len() - previous_count, unique_observations: observations.len(),
            cameras_without_new_observations: spec.cameras.iter()
                .filter(|c| !new_cameras.contains(&c.camera_id)).map(|c| c.camera_id.clone()).collect(),
            query: q, outcome, selections,
        });
    }
    checkpoint(cx)?;
    let after = DeploymentHistory::read(deployment.root(), &history_limits).map_err(|_| Error::Authority)?;
    checkpoint(cx)?;
    if after.site_lineage() != spec.site_lineage || after.head() != head
        || after.roots_at(head).as_ref() != Some(&roots)
        || after.replay_objects_root() != history.replay_objects_root()
        || deployment.current_anchor() != &roots.0
    { return Err(Error::Authority); }
    let read_after = deployment.publisher().spool().read_budget_usage();
    let mut report = RetainedSupervisorReport {
        plan: plan.clone(), basis: roots.0, ledger_root: roots.1, effect_root: roots.2,
        observations: observations.into_values().collect(), windows, read_before, read_after,
        digest: ContentDigest::sha256(b"unsealed retained supervisor report"),
    };
    report.digest = render::seal(&report)?;
    report.to_json()?;
    checkpoint(cx)?;
    Ok(report)
}
