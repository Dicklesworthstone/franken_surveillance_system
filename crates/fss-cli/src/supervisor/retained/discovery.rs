#![forbid(unsafe_code)]
//! Complete bounded discovery of retained native observations for the existing supervisor.
//!
//! Catalog metadata narrows the requested sensor/time scope only. Every relevant package event
//! must pass its native source owner before generation exclusions or exact row selection.
//! Discovery never supplies scores, invents coverage, publishes events or grants effect authority.

use fss_core::{CanonicalEncoder, ContentDigest, EventId};
use fss_object::SpoolReadBudgetUsage;
use fss_reference::agent_orient::{DeploymentHistory, OrientLimits};
use fss_reference::ingest::package_event::{PackageEvent, PackageEventError};
use fss_reference::{ReferenceDeployment, ReplayCx};

use crate::agent_json::{array, object, string};
use crate::event_fusion::render::count_calibration;

use super::{
    Error, MAX_RETAINED_SUPERVISOR_EVENTS, MAX_RETAINED_SUPERVISOR_OBSERVATIONS,
    MAX_RETAINED_SUPERVISOR_PLAN_BYTES, MAX_RETAINED_SUPERVISOR_SELECTIONS, Result,
    RetainedCameraSpec, RetainedEventPin, RetainedObservationSelector, RetainedSupervisorPlan,
    RetainedSupervisorReport, checkpoint, finish, package_error, run_retained_supervisor,
};

mod revalidation;

pub use revalidation::{
    RetainedDiscoverySource, RetainedDiscoveryValidation, revalidate_retained_discovery_sources,
};

/// Largest admitted complete current-event catalog. It includes non-package events.
pub const MAX_RETAINED_DISCOVERY_CATALOG_EVENTS: usize = 4096;
/// Hard ceiling on the complete current-object catalog, including unrelated object families.
pub const MAX_RETAINED_DISCOVERY_CATALOG_OBJECTS: usize = 65_536;
/// Complete exclusion inventory ceiling; exceeding it refuses the whole operation.
pub const MAX_RETAINED_DISCOVERY_EXCLUSIONS: usize = 4096;
/// Conservative two-pass metadata history work ceiling, in visited batch/delta units.
pub const MAX_RETAINED_DISCOVERY_HISTORY_SCAN_UNITS: usize = 16 * 1024 * 1024;
/// Exact discovery request schema and semantic digest domain.
pub const RETAINED_DISCOVERY_REQUEST_SCHEMA: &str = "fss.retained_supervisor_discovery.v1";
/// Complete discovery and native-supervision output schema.
pub const RETAINED_DISCOVERY_REPORT_SCHEMA: &str = "fss.retained_supervisor_discovery_report.v1";

/// Validated empty-selection template plus a complete catalog allowance.
#[derive(Clone, Debug)]
pub struct RetainedDiscoveryRequest {
    template: RetainedSupervisorPlan,
    maximum_catalog_events: usize,
    digest: ContentDigest,
}

impl RetainedDiscoveryRequest {
    /// Admit explicit sensor/model/class/policy/time choices before touching deployment state.
    ///
    /// The template must contain no supplied event pins or observation selectors. Its existing
    /// validation still owns camera uniqueness, calibration, policy, windows and read limits.
    pub fn new(template: RetainedSupervisorPlan, maximum_catalog_events: usize) -> Result<Self> {
        if !(1..=MAX_RETAINED_DISCOVERY_CATALOG_EVENTS).contains(&maximum_catalog_events) {
            return Err(Error::Limit("discovery catalog events"));
        }
        if !template.spec().events.is_empty()
            || template
                .spec()
                .windows
                .iter()
                .any(|window| !window.observations.is_empty())
        {
            return Err(Error::Plan(
                "discovery requires empty event pins and observation selectors",
            ));
        }
        let mut encoder = CanonicalEncoder::new();
        encoder.text(RETAINED_DISCOVERY_REQUEST_SCHEMA);
        encoder.digest(template.digest());
        encoder.u64(maximum_catalog_events as u64);
        encoder.u64(MAX_RETAINED_DISCOVERY_CATALOG_OBJECTS as u64);
        encoder.u64(MAX_RETAINED_DISCOVERY_EXCLUSIONS as u64);
        encoder.u64(MAX_RETAINED_DISCOVERY_HISTORY_SCAN_UNITS as u64);
        let digest = finish(encoder)?;
        Ok(Self {
            template,
            maximum_catalog_events,
            digest,
        })
    }

    /// Exact validated template, with no caller-selected source rows.
    pub const fn template(&self) -> &RetainedSupervisorPlan {
        &self.template
    }

    /// Maximum complete current-event inventory, including events outside package scope.
    pub const fn maximum_catalog_events(&self) -> usize {
        self.maximum_catalog_events
    }

    /// Canonical identity of the complete template and admitted catalog bounds.
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// Select an exact nonempty cumulative prefix of the already declared window schedule.
    ///
    /// All source generations, camera bindings, calibration, policy, starting time and work
    /// limits remain unchanged. This creates an inert native request; the session journal
    /// independently owns monotonic advancement, delivery acknowledgement and lifetime work.
    pub fn for_window_prefix(&self, window_count: usize) -> Result<Self> {
        if window_count == 0 || window_count > self.template.spec().windows.len() {
            return Err(Error::Plan(
                "window prefix is outside the declared schedule",
            ));
        }
        let mut spec = self.template.spec().clone();
        spec.windows.truncate(window_count);
        Self::new(
            RetainedSupervisorPlan::new(spec)?,
            self.maximum_catalog_events,
        )
    }
}

#[derive(Debug)]
struct Exclusion {
    event_id: EventId,
    event_root: ContentDigest,
    reason: &'static str,
    source_verified: bool,
    selector: Option<RetainedObservationSelector>,
}

#[derive(Debug, Default)]
struct Discovery {
    catalog_objects: usize,
    catalog_events: usize,
    non_package_events: usize,
    package_event_candidates: usize,
    metadata_reads: usize,
    ledger_batches: usize,
    ledger_deltas: usize,
    metadata_history_scan_units: usize,
    source_events_opened: usize,
    selected_events: usize,
    selected_observations: usize,
    non_detection_observations: usize,
    exclusions: Vec<Exclusion>,
}

impl Discovery {
    fn exclude(
        &mut self,
        event_id: &EventId,
        event_root: ContentDigest,
        reason: &'static str,
        source_verified: bool,
        selector: Option<RetainedObservationSelector>,
    ) -> Result<()> {
        if self.exclusions.len() >= MAX_RETAINED_DISCOVERY_EXCLUSIONS {
            return Err(Error::Limit("complete discovery exclusions"));
        }
        self.exclusions.push(Exclusion {
            event_id: event_id.clone(),
            event_root,
            reason,
            source_verified,
            selector,
        });
        Ok(())
    }
}

/// Complete discovery plus ordinary source-backed supervision, with one shared read allowance.
#[derive(Debug)]
pub struct RetainedDiscoveryReport {
    request: RetainedDiscoveryRequest,
    selected_plan: RetainedSupervisorPlan,
    discovery: Discovery,
    supervision: RetainedSupervisorReport,
    read_before: SpoolReadBudgetUsage,
    read_discovered: SpoolReadBudgetUsage,
    read_after: SpoolReadBudgetUsage,
    digest: ContentDigest,
}

impl RetainedDiscoveryReport {
    /// Exact generated plan, executable through the ordinary explicit-plan supervisor.
    pub const fn selected_plan(&self) -> &RetainedSupervisorPlan {
        &self.selected_plan
    }

    /// Existing source-backed supervisor result without discovery-specific numeric semantics.
    pub const fn supervision(&self) -> &RetainedSupervisorReport {
        &self.supervision
    }

    /// Receipt over every emitted field except the receipt itself.
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// Complete combined output. The original template's report bound covers the whole wrapper.
    pub fn to_json(&self) -> Result<String> {
        let mut fields = report_fields(self)?;
        fields.push(("receipt_digest", digest_json(self.digest)));
        let json = object(&fields);
        if json.len() > self.request.template.spec().limits.max_report_bytes {
            return Err(Error::Limit("complete discovery report bytes"));
        }
        Ok(json)
    }
}

/// Discover every matching assigned native row, then run the unchanged retained supervisor.
///
/// The complete current-object catalog and current-event catalog are admitted before source
/// reads. Non-package events are counted, not interpreted as native detector evidence. Relevant
/// missing, corrupt, deleted or private source cannot disappear through generation filtering.
/// Metadata exclusions are explicit and do not claim source verification or complete coverage.
///
/// The shared indexed-object cap is installed before catalog metadata and source reads. The
/// ordinary supervisor narrows that same cap; it cannot refund discovery work. One extra bounded
/// history observation precedes discovery, followed by the supervisor's two existing observations.
/// No partial successful advice or output is returned after any refusal.
pub fn run_discovered_retained_supervisor(
    deployment: &mut ReferenceDeployment,
    request: &RetainedDiscoveryRequest,
    cx: &ReplayCx,
) -> Result<RetainedDiscoveryReport> {
    checkpoint(cx)?;
    let template = request.template.spec();
    if deployment.site_lineage() != template.site_lineage
        || deployment.current_anchor().state_root != template.expected_authority_root
        || cx.root_dir() != deployment.root()
    {
        return Err(Error::Authority);
    }
    let limits = OrientLimits {
        max_journal_bytes: template.limits.max_journal_bytes,
        ..OrientLimits::default()
    };
    let initial =
        DeploymentHistory::read(deployment.root(), &limits).map_err(|_| Error::History)?;
    checkpoint(cx)?;
    let roots = initial.roots_at(initial.head()).ok_or(Error::History)?;
    if roots.0 != *deployment.current_anchor()
        || initial.site_lineage() != template.site_lineage
        || initial.replay_objects_root()
            != deployment
                .root()
                .join(&deployment.layout_report().objects_relpath)
    {
        return Err(Error::Authority);
    }
    let read_before = deployment
        .publisher_mut()
        .tighten_read_budget(
            template.limits.max_read_bytes,
            template.limits.max_read_attempts,
        )
        .map_err(Error::ReadBudget)?;
    let mut discovery = Discovery::default();
    let catalog = catalog(deployment, request, &mut discovery, cx)?;
    let metadata_scan_units = history_scan_units(deployment, &mut discovery, cx)?;
    let mut selected = template.clone();
    let last_end = selected
        .windows
        .last()
        .ok_or(Error::Plan("discovery windows"))?
        .end_ns;
    for event_id in catalog {
        checkpoint(cx)?;
        discovery.metadata_history_scan_units = discovery
            .metadata_history_scan_units
            .checked_add(metadata_scan_units)
            .filter(|units| *units <= MAX_RETAINED_DISCOVERY_HISTORY_SCAN_UNITS)
            .ok_or(Error::Limit("discovery metadata history work"))?;
        let (metadata, receipt) = deployment
            .current_event_authority(&event_id)
            .map_err(|error| package_error(PackageEventError::from(error)))?;
        discovery.metadata_reads += 1;
        let root = receipt.event_root;
        let has_identity = metadata
            .evidence
            .iter()
            .any(|evidence| evidence.identity_digest.is_some());
        if !has_identity {
            return Err(Error::Selection(
                "package-event metadata has no sensor identity for discovery",
            ));
        }
        let camera_in_scope = selected.cameras.iter().any(|camera| {
            let sensor = ContentDigest::sha256(camera.sensor_id.as_bytes());
            metadata
                .evidence
                .iter()
                .any(|evidence| evidence.identity_digest == Some(sensor))
        });
        if !camera_in_scope {
            discovery.exclude(&event_id, root, "sensor_outside_requested_set", false, None)?;
            continue;
        }
        if metadata.interval.latest.0 < i128::from(selected.start_ns)
            || metadata.interval.earliest.0 > i128::from(last_end)
        {
            discovery.exclude(
                &event_id,
                root,
                "capture_outside_requested_interval",
                false,
                None,
            )?;
            continue;
        }
        let event = PackageEvent::open(deployment, &event_id, cx).map_err(package_error)?;
        discovery.source_events_opened += 1;
        if event.root() != root || event.event() != &metadata {
            return Err(Error::Selection(
                "discovered event differs from current metadata",
            ));
        }
        let native = event.report().retained().record();
        let sensor = &native
            .frames
            .first()
            .ok_or(Error::Selection("discovered native source has no frames"))?
            .sensor_id;
        let camera = selected
            .cameras
            .iter()
            .find(|camera| &camera.sensor_id == sensor)
            .ok_or(Error::Selection(
                "discovered native sensor differs from requested metadata",
            ))?;
        let mismatch = if native.package_digest != camera.package_digest {
            Some("package_digest_mismatch")
        } else if native.model_digest != camera.model_digest {
            Some("model_digest_mismatch")
        } else if native.contract_digest != camera.contract_digest {
            Some("contract_digest_mismatch")
        } else if event.report().class_index() != camera.class_index {
            Some("class_index_mismatch")
        } else if event.report().label() != selected.label
            || native
                .labels
                .get(camera.class_index as usize)
                .map(String::as_str)
                != Some(selected.label.as_str())
        {
            Some("label_mismatch")
        } else {
            None
        };
        if let Some(reason) = mismatch {
            discovery.exclude(&event_id, root, reason, true, None)?;
            continue;
        }
        let camera_id = camera.camera_id.clone();
        let track = event
            .report()
            .tracks()
            .iter()
            .find(|track| track.identity == event.track())
            .ok_or(Error::Selection("discovered published track"))?;
        let mut event_selected = false;
        let mut assigned = 0_usize;
        for observation in &track.observations {
            checkpoint(cx)?;
            let Some((row, _, _, _)) = observation.detection else {
                discovery.non_detection_observations += 1;
                continue;
            };
            assigned += 1;
            let frame = native
                .frames
                .iter()
                .find(|frame| {
                    frame.segment == observation.segment
                        && frame.capsule_digest == observation.capsule_digest
                })
                .ok_or(Error::Selection("discovered original frame"))?;
            if frame.sensor_id != *sensor || frame.capture.earliest > frame.capture.latest {
                return Err(Error::Selection("discovered native sensor or capture"));
            }
            let selector = RetainedObservationSelector {
                event_id: event_id.clone(),
                capsule_digest: observation.capsule_digest,
                segment: observation.segment,
                detection_row: row,
            };
            let window = enclosing_window(
                selected.start_ns,
                &selected.windows,
                frame.capture.earliest.0,
                frame.capture.latest.0,
            );
            let index = match window {
                Ok(index) => index,
                Err(reason) => {
                    discovery.exclude(&event_id, root, reason, true, Some(selector))?;
                    continue;
                }
            };
            if !event_selected {
                if selected.events.len() >= MAX_RETAINED_SUPERVISOR_EVENTS {
                    return Err(Error::Limit("discovered selected events"));
                }
                selected.events.push(RetainedEventPin {
                    camera_id: camera_id.clone(),
                    event_id: event_id.clone(),
                    expected_event_root: root,
                });
                event_selected = true;
            }
            if discovery.selected_observations >= MAX_RETAINED_SUPERVISOR_SELECTIONS
                || selected.windows[index].observations.len()
                    >= MAX_RETAINED_SUPERVISOR_OBSERVATIONS
            {
                return Err(Error::Limit("discovered native row selectors"));
            }
            selected.windows[index].observations.push(selector);
            discovery.selected_observations += 1;
        }
        if assigned == 0 {
            discovery.exclude(&event_id, root, "no_assigned_native_detection", true, None)?;
        }
    }
    checkpoint(cx)?;
    let selected_plan = RetainedSupervisorPlan::new(selected)?;
    discovery.selected_events = selected_plan.spec().events.len();
    if plan_to_json(&selected_plan).len() > MAX_RETAINED_SUPERVISOR_PLAN_BYTES {
        return Err(Error::Limit("complete discovered plan bytes"));
    }
    let read_discovered = deployment.publisher().spool().read_budget_usage();
    let supervision = run_retained_supervisor(deployment, &selected_plan, cx)?;
    if supervision.basis != roots.0
        || supervision.ledger_root != roots.1
        || supervision.effect_root != roots.2
    {
        return Err(Error::Authority);
    }
    let read_after = deployment.publisher().spool().read_budget_usage();
    let mut report = RetainedDiscoveryReport {
        request: request.clone(),
        selected_plan,
        discovery,
        supervision,
        read_before,
        read_discovered,
        read_after,
        digest: ContentDigest::sha256(b"unsealed retained discovery report"),
    };
    let unsigned = object(&report_fields(&report)?);
    if unsigned.len() > request.template.spec().limits.max_report_bytes {
        return Err(Error::Limit("complete discovery report bytes"));
    }
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.retained_supervisor_discovery_receipt.v1");
    encoder.bytes(unsigned.as_bytes());
    report.digest = finish(encoder)?;
    report.to_json()?;
    checkpoint(cx)?;
    Ok(report)
}

fn catalog(
    deployment: &ReferenceDeployment,
    request: &RetainedDiscoveryRequest,
    discovery: &mut Discovery,
    cx: &ReplayCx,
) -> Result<Vec<EventId>> {
    let objects = &deployment.ledger().current().objects;
    if objects.len() > MAX_RETAINED_DISCOVERY_CATALOG_OBJECTS {
        return Err(Error::Limit("complete discovery object catalog"));
    }
    discovery.catalog_objects = objects.len();
    let mut candidates = Vec::new();
    for (object, revision) in objects {
        checkpoint(cx)?;
        // Event publications also have sensor-tamper companions in this namespace.
        // Only the authoritative event_revision family belongs to the event catalog.
        if revision.family != "event_revision" {
            continue;
        }
        if revision.plane != fss_core::Plane::Authority {
            return Err(Error::Selection("discovered event is outside authority"));
        }
        let event = object
            .as_str()
            .strip_prefix("object:event:")
            .ok_or(Error::Selection("discovered event object namespace"))?;
        if discovery.catalog_events >= request.maximum_catalog_events {
            return Err(Error::Limit("complete discovery event catalog"));
        }
        discovery.catalog_events += 1;
        if !event.starts_with("event:package:") {
            discovery.non_package_events += 1;
            continue;
        }
        let event = EventId::parse(event)
            .map_err(|_| Error::Selection("discovered package event identity"))?;
        candidates.push(event);
    }
    discovery.package_event_candidates = candidates.len();
    Ok(candidates)
}

fn history_scan_units(
    deployment: &ReferenceDeployment,
    discovery: &mut Discovery,
    cx: &ReplayCx,
) -> Result<usize> {
    for batch in deployment.ledger().batches() {
        checkpoint(cx)?;
        discovery.ledger_batches = discovery
            .ledger_batches
            .checked_add(1)
            .filter(|count| *count <= MAX_RETAINED_DISCOVERY_CATALOG_OBJECTS)
            .ok_or(Error::Limit("discovery ledger batches"))?;
        discovery.ledger_deltas = discovery
            .ledger_deltas
            .checked_add(batch.deltas.len())
            .filter(|count| *count <= MAX_RETAINED_DISCOVERY_HISTORY_SCAN_UNITS / 2)
            .ok_or(Error::Limit("discovery ledger deltas"))?;
    }
    // current_event_authority performs at most one latest-revision search and one full
    // prior-revision scan. This reserves a conservative complete pass for both, including
    // empty batches. Native source owners retain their own independent bounds afterward.
    discovery
        .ledger_batches
        .checked_add(discovery.ledger_deltas)
        .and_then(|units| units.checked_mul(2))
        .filter(|units| *units <= MAX_RETAINED_DISCOVERY_HISTORY_SCAN_UNITS)
        .ok_or(Error::Limit("discovery metadata history work"))
}

pub(super) fn enclosing_window(
    start: u64,
    windows: &[super::RetainedSupervisorWindow],
    earliest: i128,
    latest: i128,
) -> std::result::Result<usize, &'static str> {
    if latest < i128::from(start) {
        return Err("observation_before_requested_interval");
    }
    let Some(last) = windows.last() else {
        return Err("observation_straddles_requested_boundary");
    };
    if earliest > i128::from(last.end_ns) {
        return Err("observation_after_requested_interval");
    }
    if earliest < i128::from(start) || latest > i128::from(last.end_ns) {
        return Err("observation_straddles_requested_boundary");
    }
    windows
        .iter()
        .position(|window| latest <= i128::from(window.end_ns))
        .ok_or("observation_straddles_requested_boundary")
}

fn list(values: impl IntoIterator<Item = String>) -> String {
    array(&values.into_iter().collect::<Vec<_>>())
}

fn digest_json(digest: ContentDigest) -> String {
    string(&digest.to_text())
}

fn optional(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| value.to_string())
}

fn selector_json(selector: &RetainedObservationSelector) -> String {
    object(&[
        ("event_id", string(selector.event_id.as_str())),
        ("capsule_digest", digest_json(selector.capsule_digest)),
        ("segment", selector.segment.to_string()),
        ("detection_row", selector.detection_row.to_string()),
    ])
}

fn camera_json(camera: &RetainedCameraSpec) -> String {
    object(&[
        ("camera_id", string(&camera.camera_id)),
        ("sensor_id", string(&camera.sensor_id)),
        ("package_digest", digest_json(camera.package_digest)),
        ("model_digest", digest_json(camera.model_digest)),
        ("contract_digest", digest_json(camera.contract_digest)),
        ("class_index", camera.class_index.to_string()),
        (
            "failure_domains",
            list(camera.failure_domains.iter().map(|domain| string(domain))),
        ),
        (
            "calibration",
            camera
                .calibration
                .as_ref()
                .map_or_else(|| "null".to_owned(), count_calibration),
        ),
    ])
}

/// Serialize the complete generated existing-v1 plan without a discovery-specific execution form.
fn plan_to_json(plan: &RetainedSupervisorPlan) -> String {
    let spec = plan.spec();
    let policy = &spec.policy;
    let severity = spec.severity;
    object(&[
        ("schema", string(super::RETAINED_SUPERVISOR_PLAN_SCHEMA)),
        ("site_lineage", string(&spec.site_lineage)),
        ("hypothesis_id", string(&spec.hypothesis_id)),
        (
            "expected_authority_root",
            digest_json(spec.expected_authority_root),
        ),
        ("label", string(&spec.label)),
        ("start_ns", string(&spec.start_ns.to_string())),
        ("cameras", list(spec.cameras.iter().map(camera_json))),
        (
            "events",
            list(spec.events.iter().map(|event| {
                object(&[
                    ("camera_id", string(&event.camera_id)),
                    ("event_id", string(event.event_id.as_str())),
                    (
                        "expected_event_root",
                        digest_json(event.expected_event_root),
                    ),
                ])
            })),
        ),
        (
            "windows",
            list(spec.windows.iter().map(|window| {
                object(&[
                    ("window_index", window.window_index.to_string()),
                    ("end_ns", string(&window.end_ns.to_string())),
                    (
                        "observations",
                        list(window.observations.iter().map(selector_json)),
                    ),
                ])
            })),
        ),
        (
            "prior",
            array(&[spec.prior.lo().to_string(), spec.prior.hi().to_string()]),
        ),
        (
            "policy",
            object(&[
                ("generation", string(&policy.generation)),
                ("alert_threshold", policy.alert_threshold.to_string()),
                ("retain_threshold", policy.retain_threshold.to_string()),
                ("reject_threshold", policy.reject_threshold.to_string()),
                (
                    "min_independent_support",
                    policy.min_independent_support.to_string(),
                ),
                (
                    "urgent_single_domain_threshold",
                    policy
                        .urgent_single_domain_threshold
                        .map_or_else(|| "null".to_owned(), |value| value.to_string()),
                ),
                ("max_wait_ns", string(&policy.max_wait_ns.to_string())),
                (
                    "look_penalty_per_doubling",
                    policy.look_penalty_per_doubling.to_string(),
                ),
                (
                    "operator_confirmation_available",
                    policy.operator_confirmation_available.to_string(),
                ),
            ]),
        ),
        (
            "severity",
            object(&[
                ("expected_harm", string(&severity.expected_harm.to_string())),
                (
                    "false_alert_cost",
                    string(&severity.false_alert_cost.to_string()),
                ),
                (
                    "delay_cost_per_second",
                    string(&severity.delay_cost_per_second.to_string()),
                ),
                ("reversible", severity.reversible.to_string()),
            ]),
        ),
        (
            "limits",
            object(&[
                ("max_read_bytes", spec.limits.max_read_bytes.to_string()),
                (
                    "max_read_attempts",
                    spec.limits.max_read_attempts.to_string(),
                ),
                (
                    "max_journal_bytes",
                    spec.limits.max_journal_bytes.to_string(),
                ),
                ("max_report_bytes", spec.limits.max_report_bytes.to_string()),
            ]),
        ),
    ])
}

fn report_fields(report: &RetainedDiscoveryReport) -> Result<Vec<(&'static str, String)>> {
    let discovery = &report.discovery;
    let total_bytes = report.read_after.used_bytes - report.read_before.used_bytes;
    let total_attempts =
        report.read_after.used_read_attempts - report.read_before.used_read_attempts;
    Ok(vec![
        ("schema", string(RETAINED_DISCOVERY_REPORT_SCHEMA)),
        ("request_digest", digest_json(report.request.digest)),
        (
            "site_lineage",
            string(&report.request.template.spec().site_lineage),
        ),
        (
            "expected_authority_root",
            digest_json(report.request.template.spec().expected_authority_root),
        ),
        (
            "selected_plan_digest",
            digest_json(report.selected_plan.digest()),
        ),
        ("selected_plan", plan_to_json(&report.selected_plan)),
        (
            "source_inventory",
            list(report.source_inventory()?.iter().map(|source| {
                object(&[
                    ("event_id", string(source.event_id.as_str())),
                    ("event_root", digest_json(source.event_root)),
                    ("source_verified", source.source_verified.to_string()),
                    (
                        "health_digest",
                        source
                            .health_digest
                            .map_or_else(|| "null".to_owned(), digest_json),
                    ),
                ])
            })),
        ),
        (
            "discovery",
            object(&[
                ("catalog_objects", discovery.catalog_objects.to_string()),
                ("catalog_events", discovery.catalog_events.to_string()),
                (
                    "maximum_catalog_events",
                    report.request.maximum_catalog_events.to_string(),
                ),
                (
                    "maximum_catalog_objects",
                    MAX_RETAINED_DISCOVERY_CATALOG_OBJECTS.to_string(),
                ),
                (
                    "maximum_exclusions",
                    MAX_RETAINED_DISCOVERY_EXCLUSIONS.to_string(),
                ),
                (
                    "non_package_events",
                    discovery.non_package_events.to_string(),
                ),
                (
                    "package_event_candidates",
                    discovery.package_event_candidates.to_string(),
                ),
                ("metadata_reads", discovery.metadata_reads.to_string()),
                ("ledger_batches", discovery.ledger_batches.to_string()),
                ("ledger_deltas", discovery.ledger_deltas.to_string()),
                (
                    "metadata_history_scan_units",
                    discovery.metadata_history_scan_units.to_string(),
                ),
                (
                    "maximum_metadata_history_scan_units",
                    MAX_RETAINED_DISCOVERY_HISTORY_SCAN_UNITS.to_string(),
                ),
                (
                    "metadata_history_accounting",
                    string("conservative_two_pass_batch_and_delta_allowance"),
                ),
                (
                    "source_events_opened",
                    discovery.source_events_opened.to_string(),
                ),
                ("selected_events", discovery.selected_events.to_string()),
                (
                    "selected_observations",
                    discovery.selected_observations.to_string(),
                ),
                (
                    "unique_observations",
                    report.supervision.observations().len().to_string(),
                ),
                (
                    "non_detection_observations",
                    discovery.non_detection_observations.to_string(),
                ),
                (
                    "exclusions",
                    list(discovery.exclusions.iter().map(|exclusion| {
                        object(&[
                            ("event_id", string(exclusion.event_id.as_str())),
                            ("event_root", digest_json(exclusion.event_root)),
                            ("reason", string(exclusion.reason)),
                            ("source_verified", exclusion.source_verified.to_string()),
                            (
                                "selector",
                                exclusion
                                    .selector
                                    .as_ref()
                                    .map_or_else(|| "null".to_owned(), selector_json),
                            ),
                        ])
                    })),
                ),
            ]),
        ),
        ("supervision", report.supervision.to_json()?),
        (
            "read_usage",
            object(&[
                (
                    "accounting",
                    string("shared_conservative_stored_envelope_reservations"),
                ),
                (
                    "discovery_reserved_bytes",
                    (report.read_discovered.used_bytes - report.read_before.used_bytes).to_string(),
                ),
                (
                    "discovery_read_attempts",
                    (report.read_discovered.used_read_attempts
                        - report.read_before.used_read_attempts)
                        .to_string(),
                ),
                (
                    "supervision_reserved_bytes",
                    (report.read_after.used_bytes - report.read_discovered.used_bytes).to_string(),
                ),
                (
                    "supervision_read_attempts",
                    (report.read_after.used_read_attempts
                        - report.read_discovered.used_read_attempts)
                        .to_string(),
                ),
                ("reserved_bytes", total_bytes.to_string()),
                ("read_attempts", total_attempts.to_string()),
                (
                    "total_reserved_bytes",
                    report.read_after.used_bytes.to_string(),
                ),
                (
                    "total_read_attempts",
                    report.read_after.used_read_attempts.to_string(),
                ),
                (
                    "remaining_bytes",
                    optional(report.read_after.remaining_bytes),
                ),
                (
                    "remaining_read_attempts",
                    optional(report.read_after.remaining_read_attempts),
                ),
                ("journal_observations", "3".to_owned()),
                (
                    "open_recovery_and_filesystem_metadata_included",
                    "false".to_owned(),
                ),
            ]),
        ),
        ("effects_authorized", "false".to_owned()),
        ("supports_absence_claim", "false".to_owned()),
    ])
}

#[cfg(test)]
mod tests;
