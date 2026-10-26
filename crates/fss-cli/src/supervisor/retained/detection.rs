#![forbid(unsafe_code)]
//! Native class advice directly from retained detector records, including sentinel bursts.
//!
//! A detector observation needs no tracked-event publication. This owner retains that distinction:
//! every score is reopened through native source custody, while tracks, physical actors, zone
//! entries, unsampled intervals, class absence and effect authority remain unestablished.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalEncoder, CaptureInterval, ContentDigest, LedgerAnchor, ObjectId, Plane};
use fss_fusion::{Calibration, EvidenceItem, FusionOutcome, FusionQuery, Observability, fuse};
use fss_object::SpoolReadBudgetUsage;
use fss_reference::agent_orient::{DeploymentHistory, OrientLimits};
use fss_reference::ingest::historical_health::exposure::HealthExposure;
use fss_reference::ingest::package_event::{
    MAX_PACKAGE_ANALYSIS_BYTES, PACKAGE_DETECTION_FAMILY, PackageDetectionRecord,
    PackageEventError, RetainedPackageDetection,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::health::{HealthGuard, exposure_json};
use super::{
    Error, MAX_RETAINED_DISCOVERY_CATALOG_OBJECTS, MAX_RETAINED_DISCOVERY_EXCLUSIONS,
    MAX_RETAINED_DISCOVERY_HISTORY_SCAN_UNITS, MAX_RETAINED_SUPERVISOR_OBSERVATIONS,
    MAX_RETAINED_SUPERVISOR_SELECTIONS, Result, RetainedDiscoveryRequest,
    RetainedSupervisorObservation, RetainedSupervisorPlan, SourceClocks, checkpoint, finish,
    package_error, query, resolve_native_detection, sha,
};

mod input;
mod render;
mod revalidation;

pub use revalidation::{RetainedDetectionValidation, revalidate_detection_sources};

/// Exact-byte-pinned direct detector discovery request, distinct from event discovery.
pub const RETAINED_DETECTION_REQUEST_SCHEMA: &str = "fss.retained_detection_discovery.v1";
/// Complete direct detector discovery and class-advice report.
pub const RETAINED_DETECTION_REPORT_SCHEMA: &str = "fss.retained_detection_discovery_report.v1";

/// Immutable camera/class/time/calibration scope with a complete detector-catalog allowance.
#[derive(Clone, Debug)]
pub struct RetainedDetectionRequest {
    discovery: RetainedDiscoveryRequest,
    digest: ContentDigest,
}

impl RetainedDetectionRequest {
    /// Reuse validated empty-selection configuration, without accepting scores or event pins.
    pub fn new(discovery: RetainedDiscoveryRequest) -> Result<Self> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(RETAINED_DETECTION_REQUEST_SCHEMA);
        encoder.digest(discovery.digest());
        let digest = finish(encoder)?;
        Ok(Self { discovery, digest })
    }

    /// Exact camera, calibration, policy, window and resource selections.
    pub const fn template(&self) -> &RetainedSupervisorPlan {
        self.discovery.template()
    }

    /// Maximum complete current native detector-report inventory, including exclusions.
    pub const fn maximum_catalog_reports(&self) -> usize {
        self.discovery.maximum_catalog_events()
    }

    /// Canonical direct-detection request identity; never an event-discovery identity.
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// Bind unchanged configuration to explicit current authority without granting access.
    pub fn for_authority(&self, expected_authority_root: ContentDigest) -> Result<Self> {
        Self::new(self.discovery.for_authority(expected_authority_root)?)
    }

    /// Select a nonempty prefix of the immutable cumulative window schedule.
    pub fn for_window_prefix(&self, window_count: usize) -> Result<Self> {
        Self::new(self.discovery.for_window_prefix(window_count)?)
    }
}

/// An exact retained detector source disclosed by the original discovery operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedDetectionSource {
    /// Original native report JSON digest and native custody lookup identity.
    pub report_digest: ContentDigest,
    /// Exact canonical detector-record payload in the authority journal.
    pub record_digest: ContentDigest,
    /// Root-last detector/report/source closure named by its canonical publication delta.
    pub detection_root: ContentDigest,
    /// True preserves native source, deletion and privacy revalidation even for exclusions.
    /// False preserves only the original metadata-level verification claim.
    pub source_verified: bool,
    /// Exact source-bound health context for the rows that contributed to this report,
    /// including explicit lack of matching diagnostics. No selected row means no health pin.
    pub health_digest: Option<ContentDigest>,
}

#[derive(Clone, Debug)]
struct MetadataPin {
    source: RetainedDetectionSource,
    validity: CaptureInterval,
}

#[derive(Clone, Debug)]
struct Selection {
    source: RetainedDetectionSource,
    capsule_digest: ContentDigest,
    segment: u64,
    detection_row: u64,
    observation: ContentDigest,
    new_evidence: bool,
}

#[derive(Clone, Debug)]
struct Exclusion {
    source: RetainedDetectionSource,
    reason: &'static str,
    row: Option<(ContentDigest, u64, u64)>,
}

#[derive(Debug, Default)]
struct Discovery {
    catalog_objects: usize,
    catalog_reports: usize,
    metadata_reads: usize,
    source_reports_opened: usize,
    selected_reports: usize,
    selected_observations: usize,
    non_detection_frames: usize,
    history_scan_units: usize,
    exclusions: Vec<Exclusion>,
}

impl Discovery {
    fn exclude(
        &mut self,
        source: &RetainedDetectionSource,
        reason: &'static str,
        row: Option<(ContentDigest, u64, u64)>,
    ) -> Result<()> {
        if self.exclusions.len() >= MAX_RETAINED_DISCOVERY_EXCLUSIONS {
            return Err(Error::Limit("complete detector-discovery exclusions"));
        }
        self.exclusions.push(Exclusion {
            source: source.clone(),
            reason,
            row,
        });
        Ok(())
    }
}

/// One cumulative class-advice look from unique native detector rows.
#[derive(Clone, Debug)]
pub struct RetainedDetectionWindow {
    /// Consecutive configured window.
    pub window_index: u64,
    /// Complete conservative capture-interval ceiling.
    pub end_ns: u64,
    /// Unique native rows first admitted during this look.
    pub new_observations: usize,
    /// Unique native rows in this entire cumulative look.
    pub unique_observations: usize,
    /// Configured camera aliases with no new selected row; this is not absence.
    pub cameras_without_new_observations: Vec<String>,
    /// Complete replayable native-class query, including explicit unobservability.
    pub query: FusionQuery,
    /// Derived fusion outcome, dependency clusters and counterfactuals.
    pub outcome: FusionOutcome,
    selections: Vec<Selection>,
}

/// Complete direct-source advice. Construction succeeds only after final history revalidation.
#[derive(Debug)]
pub struct RetainedDetectionReport {
    request: RetainedDetectionRequest,
    discovery: Discovery,
    sources: Vec<RetainedDetectionSource>,
    observations: Vec<RetainedSupervisorObservation>,
    windows: Vec<RetainedDetectionWindow>,
    basis: LedgerAnchor,
    ledger_root: ContentDigest,
    effect_root: ContentDigest,
    read_before: SpoolReadBudgetUsage,
    read_after: SpoolReadBudgetUsage,
    health_json: String,
    digest: ContentDigest,
}

impl RetainedDetectionReport {
    /// Complete native rows in stable source-identity order, with no duplicated evidence.
    pub fn observations(&self) -> &[RetainedSupervisorObservation] {
        &self.observations
    }

    /// Consecutive cumulative windows, each recomputed from its unique native rows.
    pub fn windows(&self) -> &[RetainedDetectionWindow] {
        &self.windows
    }

    /// Exact current authority bracketed around source reads and computation.
    pub const fn basis(&self) -> &LedgerAnchor {
        &self.basis
    }

    /// Complete report receipt, including exclusions, inventories, limits and actual read cost.
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// Every originally disclosed report, including native-verified generation exclusions.
    pub fn source_inventory(&self) -> Result<Vec<RetainedDetectionSource>> {
        if self.sources.len() != self.discovery.metadata_reads {
            return Err(Error::Selection("incomplete detector source inventory"));
        }
        revalidation::inventory_digest(&self.sources, self.request.maximum_catalog_reports())?;
        Ok(self.sources.clone())
    }

    /// Complete bounded projection. An oversized report refuses instead of dropping evidence.
    pub fn to_json(&self) -> Result<String> {
        render::report(self)
    }
}

fn catalog(
    deployment: &ReferenceDeployment,
    maximum_reports: usize,
    discovery: &mut Discovery,
    cx: &ReplayCx,
) -> Result<Vec<MetadataPin>> {
    let objects = &deployment.ledger().current().objects;
    if objects.len() > MAX_RETAINED_DISCOVERY_CATALOG_OBJECTS {
        return Err(Error::Limit("complete detector object catalog"));
    }
    discovery.catalog_objects = objects.len();
    let mut by_object =
        BTreeMap::<ObjectId, (ContentDigest, ContentDigest, CaptureInterval)>::new();
    for (object, revision) in objects {
        checkpoint(cx)?;
        if revision.family != PACKAGE_DETECTION_FAMILY {
            continue;
        }
        if by_object.len() >= maximum_reports {
            return Err(Error::Limit("complete detector report catalog"));
        }
        if revision.plane != Plane::Cognition || revision.generation != 1 {
            return Err(Error::Selection(
                "native detector record plane or generation",
            ));
        }
        let suffix = object
            .as_str()
            .strip_prefix("object:package-detection:")
            .ok_or(Error::Selection("native detector object namespace"))?;
        let report = ContentDigest::parse(&format!("sha256:{suffix}"))
            .map_err(|_| Error::Selection("native detector report identity"))?;
        if !sha(report) || !sha(revision.payload_digest) {
            return Err(Error::Selection("native detector metadata digest"));
        }
        by_object.insert(
            object.clone(),
            (report, revision.payload_digest, revision.validity),
        );
    }
    discovery.catalog_reports = by_object.len();
    let mut pins = BTreeMap::new();
    // A complete bounded history pass obtains each immutable publication's actual root witness;
    // no root is guessed from a filename, source score, or object-store listing.
    for batch in deployment.ledger().batches() {
        checkpoint(cx)?;
        discovery.history_scan_units = discovery
            .history_scan_units
            .checked_add(1)
            .filter(|n| *n <= MAX_RETAINED_DISCOVERY_HISTORY_SCAN_UNITS)
            .ok_or(Error::Limit("detector catalog history work"))?;
        for delta in &batch.deltas {
            checkpoint(cx)?;
            discovery.history_scan_units = discovery
                .history_scan_units
                .checked_add(1)
                .filter(|n| *n <= MAX_RETAINED_DISCOVERY_HISTORY_SCAN_UNITS)
                .ok_or(Error::Limit("detector catalog history work"))?;
            let Some((report, record_digest, validity)) = by_object.get(&delta.object_id) else {
                continue;
            };
            let root = delta
                .witness_digest
                .filter(|root| sha(*root))
                .ok_or(Error::Selection("native detector publication root"))?;
            if delta.family != PACKAGE_DETECTION_FAMILY
                || delta.plane != Plane::Cognition
                || delta.prior_generation.is_some()
                || delta.new_generation != 1
                || delta.payload_digest != *record_digest
                || delta.validity != *validity
            {
                return Err(Error::Selection(
                    "native detector canonical publication changed",
                ));
            }
            if pins
                .insert(
                    *report,
                    MetadataPin {
                        source: RetainedDetectionSource {
                            report_digest: *report,
                            record_digest: *record_digest,
                            detection_root: root,
                            source_verified: false,
                            health_digest: None,
                        },
                        validity: *validity,
                    },
                )
                .is_some()
            {
                return Err(Error::Selection("duplicate native detector publication"));
            }
        }
    }
    if pins.len() != by_object.len() {
        return Err(Error::Selection(
            "incomplete native detector publication inventory",
        ));
    }
    Ok(pins.into_values().collect())
}

fn read_metadata(
    deployment: &ReferenceDeployment,
    pin: &MetadataPin,
    cx: &ReplayCx,
) -> Result<PackageDetectionRecord> {
    checkpoint(cx)?;
    let bytes = deployment
        .publisher()
        .spool()
        .read_bounded(pin.source.record_digest, MAX_PACKAGE_ANALYSIS_BYTES)
        .map_err(|error| package_error(PackageEventError::Spool(error)))?;
    let record = PackageDetectionRecord::decode(&bytes).map_err(package_error)?;
    let first = record
        .frames
        .first()
        .ok_or(Error::Selection("empty native detector record"))?;
    let mut validity = first.capture;
    for frame in &record.frames {
        if frame.sensor_id != first.sensor_id {
            return Err(Error::Selection("native detector record mixes sensors"));
        }
        validity.earliest = validity.earliest.min(frame.capture.earliest);
        validity.latest = validity.latest.max(frame.capture.latest);
    }
    if record.report_digest != pin.source.report_digest || validity != pin.validity {
        return Err(Error::Selection(
            "native detector metadata publication differs",
        ));
    }
    Ok(record)
}

fn verify_native(
    deployment: &ReferenceDeployment,
    source: &RetainedDetectionSource,
    record: &PackageDetectionRecord,
    cx: &ReplayCx,
) -> Result<()> {
    let native = RetainedPackageDetection::open(deployment, source.report_digest, cx)
        .map_err(package_error)?;
    if native.record() != record
        || native.record_digest() != source.record_digest
        || native.root() != source.detection_root
    {
        return Err(Error::Selection(
            "native detector source differs from metadata",
        ));
    }
    Ok(())
}

type SourceHealth = BTreeMap<(ContentDigest, u64, u64), HealthExposure>;

/// Bind only the exact native class rows selected by this immutable request. Diagnostic roots
/// unrelated to those source coordinates do not invalidate an otherwise unchanged historical
/// report. A previously unassessed source cannot silently gain numeric support on replay.
fn compute_source_health(
    deployment: &ReferenceDeployment,
    request: &RetainedDetectionRequest,
    record: &PackageDetectionRecord,
    health: &mut HealthGuard,
    cx: &ReplayCx,
) -> Result<(SourceHealth, Option<ContentDigest>)> {
    let spec = request.template().spec();
    let sensor = &record
        .frames
        .first()
        .ok_or(Error::Selection("native health source frames"))?
        .sensor_id;
    let Some(camera) = spec
        .cameras
        .iter()
        .find(|camera| &camera.sensor_id == sensor)
    else {
        return Ok((BTreeMap::new(), None));
    };
    if record.package_digest != camera.package_digest
        || record.model_digest != camera.model_digest
        || record.contract_digest != camera.contract_digest
        || record
            .labels
            .get(camera.class_index as usize)
            .map(String::as_str)
            != Some(spec.label.as_str())
    {
        return Ok((BTreeMap::new(), None));
    }
    let mut exposures = BTreeMap::new();
    for frame in &record.frames {
        checkpoint(cx)?;
        if super::discovery::enclosing_window(
            spec.start_ns,
            &spec.windows,
            frame.capture.earliest.0,
            frame.capture.latest.0,
        )
        .is_err()
        {
            continue;
        }
        for detection in &frame.detections {
            if detection.class_index != camera.class_index {
                continue;
            }
            if exposures.len() >= MAX_RETAINED_SUPERVISOR_OBSERVATIONS {
                return Err(Error::Limit("selected detector health observations"));
            }
            let key = (frame.capsule_digest, frame.segment, detection.row);
            if exposures
                .insert(key, health.assess(record, frame, deployment, cx)?)
                .is_some()
            {
                return Err(Error::Selection(
                    "duplicate source row in detector health inventory",
                ));
            }
        }
    }
    if exposures.is_empty() {
        return Ok((exposures, None));
    }
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.retained_detection_source_health.v1");
    encoder.u64(exposures.len() as u64);
    for ((capsule, segment, row), exposure) in &exposures {
        encoder.digest(*capsule);
        encoder.u64(*segment);
        encoder.u64(*row);
        encoder.bytes(exposure_json(exposure).as_bytes());
    }
    let digest = finish(encoder)?;
    Ok((exposures, Some(digest)))
}

fn history(
    deployment: &ReferenceDeployment,
    request: &RetainedDetectionRequest,
    cx: &ReplayCx,
) -> Result<(
    DeploymentHistory,
    (LedgerAnchor, ContentDigest, ContentDigest),
)> {
    checkpoint(cx)?;
    let spec = request.template().spec();
    if deployment.site_lineage() != spec.site_lineage
        || deployment.current_anchor().state_root != spec.expected_authority_root
        || cx.root_dir() != deployment.root()
    {
        return Err(Error::Authority);
    }
    let limits = OrientLimits {
        max_journal_bytes: spec.limits.max_journal_bytes,
        ..OrientLimits::default()
    };
    let history =
        DeploymentHistory::read(deployment.root(), &limits).map_err(|_| Error::History)?;
    checkpoint(cx)?;
    let roots = history.roots_at(history.head()).ok_or(Error::History)?;
    if roots.0 != *deployment.current_anchor()
        || history.site_lineage() != spec.site_lineage
        || history.replay_objects_root()
            != deployment
                .root()
                .join(&deployment.layout_report().objects_relpath)
    {
        return Err(Error::Authority);
    }
    Ok((history, roots))
}

fn revalidate_history(
    deployment: &ReferenceDeployment,
    request: &RetainedDetectionRequest,
    initial: &DeploymentHistory,
    roots: &(LedgerAnchor, ContentDigest, ContentDigest),
    cx: &ReplayCx,
) -> Result<()> {
    let (current, current_roots) = history(deployment, request, cx)?;
    if current.head() != initial.head()
        || &current_roots != roots
        || current.replay_objects_root() != initial.replay_objects_root()
    {
        return Err(Error::Authority);
    }
    Ok(())
}

/// Discover original native detector rows directly, preserving missing and excluded evidence.
///
/// Every in-scope report passes native source/privacy validation before generation filtering.
/// Complete conservative capture intervals select the first enclosing cumulative window.
/// Overlapping reports add each native row only once. No inference, event publication, tracking,
/// background work, source repair, absence certification or effect is performed.
pub fn run_discovered_detection_supervisor(
    deployment: &mut ReferenceDeployment,
    request: &RetainedDetectionRequest,
    cx: &ReplayCx,
) -> Result<RetainedDetectionReport> {
    let (initial, roots) = history(deployment, request, cx)?;
    let spec = request.template().spec();
    let before = deployment
        .publisher_mut()
        .tighten_read_budget(spec.limits.max_read_bytes, spec.limits.max_read_attempts)
        .map_err(Error::ReadBudget)?;
    let mut discovery = Discovery::default();
    let pins = catalog(
        deployment,
        request.maximum_catalog_reports(),
        &mut discovery,
        cx,
    )?;
    let mut health = HealthGuard::read(deployment, &spec.limits, cx)?;
    let last_end = spec
        .windows
        .last()
        .ok_or(Error::Plan("detector discovery windows"))?
        .end_ns;
    let mut sources = Vec::with_capacity(pins.len());
    let mut clocks = SourceClocks::default();
    let mut unique = BTreeMap::<ContentDigest, RetainedSupervisorObservation>::new();
    let mut selected = vec![Vec::<Selection>::new(); spec.windows.len()];
    for pin in pins {
        checkpoint(cx)?;
        let record = read_metadata(deployment, &pin, cx)?;
        discovery.metadata_reads += 1;
        let mut source = pin.source;
        let sensor = &record
            .frames
            .first()
            .ok_or(Error::Selection("native detector frames"))?
            .sensor_id;
        let Some(camera) = spec
            .cameras
            .iter()
            .find(|camera| &camera.sensor_id == sensor)
        else {
            discovery.exclude(&source, "sensor_outside_requested_set", None)?;
            sources.push(source);
            continue;
        };
        if pin.validity.latest.0 < i128::from(spec.start_ns)
            || pin.validity.earliest.0 > i128::from(last_end)
        {
            discovery.exclude(&source, "capture_outside_requested_interval", None)?;
            sources.push(source);
            continue;
        }
        verify_native(deployment, &source, &record, cx)?;
        source.source_verified = true;
        discovery.source_reports_opened += 1;
        let mismatch = if record.package_digest != camera.package_digest {
            Some("package_digest_mismatch")
        } else if record.model_digest != camera.model_digest {
            Some("model_digest_mismatch")
        } else if record.contract_digest != camera.contract_digest {
            Some("contract_digest_mismatch")
        } else if record
            .labels
            .get(camera.class_index as usize)
            .map(String::as_str)
            != Some(spec.label.as_str())
        {
            Some("class_label_mismatch")
        } else {
            None
        };
        if let Some(reason) = mismatch {
            discovery.exclude(&source, reason, None)?;
            sources.push(source);
            continue;
        }
        let (source_health, health_digest) =
            compute_source_health(deployment, request, &record, &mut health, cx)?;
        source.health_digest = health_digest;
        let mut selected_report = false;
        for frame in &record.frames {
            checkpoint(cx)?;
            let mut matching = false;
            for detection in &frame.detections {
                if detection.class_index != camera.class_index {
                    continue;
                }
                matching = true;
                let row = Some((frame.capsule_digest, frame.segment, detection.row));
                let index = match super::discovery::enclosing_window(
                    spec.start_ns,
                    &spec.windows,
                    frame.capture.earliest.0,
                    frame.capture.latest.0,
                ) {
                    Ok(index) => index,
                    Err(reason) => {
                        discovery.exclude(&source, reason, row)?;
                        continue;
                    }
                };
                if discovery.selected_observations >= MAX_RETAINED_SUPERVISOR_SELECTIONS {
                    return Err(Error::Limit("detector source selections"));
                }
                let mut observation = resolve_native_detection(
                    &record,
                    frame,
                    detection,
                    camera,
                    &spec.label,
                    spec.start_ns,
                    spec.windows[index].end_ns,
                    deployment,
                    &mut clocks,
                    cx,
                )?;
                let exposure = source_health
                    .get(&(frame.capsule_digest, frame.segment, detection.row))
                    .ok_or(Error::Selection(
                        "selected detector row has no health assessment",
                    ))?
                    .clone();
                super::apply_health(&mut observation, exposure);
                match unique.get(&observation.identity) {
                    Some(prior) if prior != &observation => {
                        return Err(Error::Selection(
                            "one native row has conflicting detector evidence",
                        ));
                    }
                    Some(_) => {}
                    None => {
                        if unique.len() >= MAX_RETAINED_SUPERVISOR_OBSERVATIONS {
                            return Err(Error::Limit("unique native detector observations"));
                        }
                        unique.insert(observation.identity, observation.clone());
                    }
                }
                selected[index].push(Selection {
                    source: source.clone(),
                    capsule_digest: frame.capsule_digest,
                    segment: frame.segment,
                    detection_row: detection.row,
                    observation: observation.identity,
                    new_evidence: false,
                });
                discovery.selected_observations += 1;
                selected_report = true;
            }
            if !matching {
                discovery.non_detection_frames += 1;
            }
        }
        if selected_report {
            discovery.selected_reports += 1;
        } else {
            discovery.exclude(&source, "no_selected_native_class_observation", None)?;
        }
        sources.push(source);
    }
    let mut cumulative = BTreeMap::<ContentDigest, RetainedSupervisorObservation>::new();
    let mut windows = Vec::with_capacity(spec.windows.len());
    for (window, mut selections) in spec.windows.iter().zip(selected) {
        checkpoint(cx)?;
        let previous_count = cumulative.len();
        let mut new_sensors = BTreeSet::new();
        for selection in &mut selections {
            if !cumulative.contains_key(&selection.observation) {
                let observation = unique
                    .get(&selection.observation)
                    .ok_or(Error::Selection("selected native detector row unavailable"))?
                    .clone();
                new_sensors.insert(observation.sensor_id.clone());
                cumulative.insert(selection.observation, observation);
                selection.new_evidence = true;
            }
        }
        let mut evidence: Vec<_> = cumulative.values().map(|o| o.evidence.clone()).collect();
        for camera in &spec.cameras {
            if !cumulative.values().any(|o| o.sensor_id == camera.sensor_id) {
                let mut domains = camera.failure_domains.clone();
                domains.insert(format!("package:{}", camera.package_digest));
                evidence.push(EvidenceItem {
                    id: format!("unobserved:{}", camera.sensor_id),
                    sensor: camera.sensor_id.clone(),
                    failure_domains: domains,
                    calibration: Calibration::Uncalibrated {
                        reason: "no selected retained class observation".into(),
                    },
                    observability: Observability::NotObservable {
                        reason: "no source evidence selected for this camera".into(),
                    },
                });
            }
        }
        evidence.sort_by(|a, b| a.id.cmp(&b.id));
        let query = query(spec, evidence, window.window_index, window.end_ns);
        let outcome = fuse(&query).map_err(Error::Engine)?;
        windows.push(RetainedDetectionWindow {
            window_index: window.window_index,
            end_ns: window.end_ns,
            new_observations: cumulative.len() - previous_count,
            unique_observations: cumulative.len(),
            cameras_without_new_observations: spec
                .cameras
                .iter()
                .filter(|c| !new_sensors.contains(&c.sensor_id))
                .map(|c| c.camera_id.clone())
                .collect(),
            query,
            outcome,
            selections,
        });
    }
    revalidate_history(deployment, request, &initial, &roots, cx)?;
    let after = deployment.publisher().spool().read_budget_usage();
    let mut report = RetainedDetectionReport {
        request: request.clone(),
        discovery,
        sources,
        observations: unique.into_values().collect(),
        windows,
        basis: roots.0,
        ledger_root: roots.1,
        effect_root: roots.2,
        read_before: before,
        read_after: after,
        health_json: health.to_json(),
        digest: ContentDigest::sha256(b"unsealed detector discovery report"),
    };
    report.source_inventory()?;
    report.digest = render::seal(&report)?;
    report.to_json()?;
    checkpoint(cx)?;
    Ok(report)
}
