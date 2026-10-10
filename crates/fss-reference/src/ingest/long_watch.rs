#![forbid(unsafe_code)]
//! Whole-recording zone-entry candidates over the shared native streaming perception walk.
//!
//! One foreground model and tracker survive the complete requested recording, including former
//! 128-frame boundaries. The first confirmed, actually matched track center strictly inside a
//! zone produces one candidate per `(recovery epoch, track, zone)`. This describes a sampled
//! observation, not a physical arrival or boundary crossing. Prediction-only positions never
//! produce an entry; gaps reset the decoder where necessary, foreground and tracking together.
//!
//! Analysis is read-only. Exact approvals publish source-closed, unclassified, indeterminate
//! events with `[0, 1]` probability and no alert or absence authority. Optional conservative
//! visual screening retains diagnostics and blocks the entire scan's publication on findings or
//! incomplete screening. No detector-package invocation or coverage certificate is implied.

use std::collections::BTreeSet;
use std::path::PathBuf;

use fss_core::{
    CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest, DecisionPath, EventEvidence,
    EventHypothesis, EventId, EventKind, EventState, EvidenceClass, EvidenceEdgeRelation,
    LedgerAnchor, ProbabilityInterval, SensorId,
};
use fss_object::ObjectManifest;
use fss_publication::SlotName;

use super::long_dwell::{
    LongDwellHealthSummary, LongDwellLimits, MAX_LONG_DWELL_FRAMES, ScanRule, event_status, json,
    publish_manifest, run_scan, slot,
};
use super::privacy_mask::MaskBinding;
use super::recorded_decode::RecordedDecodeError;
use super::recorded_watch::{
    SourcePublicationGuard, WatchError, WatchOptions, WatchPlan, WatchStatus, pipeline_parameters,
};
use super::sensor_health::{
    policy_bytes as health_policy_bytes, policy_digest as health_policy_digest,
};
use super::tolerant_decode::DecodeRefusal;
use crate::{ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision, ReplayCx};

/// Same source-byte, pixel, assignment and trace ceilings as the shared whole-recording walker.
pub type LongWatchLimits = LongDwellLimits;
/// Maximum source segments admitted by one complete streaming zone-entry analysis.
pub const MAX_LONG_WATCH_FRAMES: usize = MAX_LONG_DWELL_FRAMES;
/// Maximum candidates in one scan; overflow refuses the scan without omitting entries.
pub const MAX_LONG_WATCH_CANDIDATES: usize = 256;
/// Report schema for this implementation-specific read-only analysis/publication projection.
pub const LONG_WATCH_REPORT_SCHEMA: &str = "fss.long_watch_report.v1";
/// Explicit health gate reason; diagnostics do not become an assertion of sensor tampering.
pub const HEALTH_PUBLICATION_BLOCKED: &str =
    "sensor-health findings or incomplete screening block long-watch publication";

const MAX_REPORT_BYTES: usize = 1024 * 1024;
pub(super) const ANALYSIS_DOMAIN: &str = "fss.long_watch_analysis.v1";
pub(super) const ENTRY_DOMAIN: &str = "fss.long_watch_entry.v1";
const APPROVAL_DOMAIN: &str = "fss.long_watch_approval.v1";
pub(super) const POLICY: &[u8] =
    b"fss.long-watch.policy.v1:native-display-order-luma:masked-before-perception:\
running-variance:kalman-global-iou:first-confirmed-actual-match-per-epoch-track-zone:\
strict-rounded-zone-interior:operator-capture-hints:reset-background-and-tracker-on-gap:\
one-whole-range-budget:unclassified:indeterminate:hold:no-arrival:no-absence:no-alert";
const UNCERTAINTY: &str = "A confirmed foreground track was first observed inside an owner image zone in this recovery epoch. Capture times are operator assumptions; this is not a physical arrival, boundary crossing, person, identity, intent or independent corroboration.";
type Result<T> = std::result::Result<T, WatchError>;

/// One actually matched observation, with display position kept distinct from coding segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LongWatchEntry {
    pub(super) epoch: u64,
    pub(super) track: u64,
    pub(super) zone: usize,
    pub(super) position: usize,
    pub(super) segment: usize,
    pub(super) capsule_digest: ContentDigest,
    pub(super) capture: CaptureInterval,
    pub(super) filtered_box: [i64; 4],
}
impl LongWatchEntry {
    /// Tracker reset generation; track IDs cannot bridge this boundary.
    pub const fn tracker_epoch(&self) -> u64 {
        self.epoch
    }
    /// Tracker-local ID, meaningful only within this epoch and source analysis.
    pub const fn track_id(&self) -> u64 {
        self.track
    }
    /// Absolute display-order position (source segment for MJPEG).
    pub const fn position(&self) -> usize {
        self.position
    }
    /// Exact retained coding segment, which may differ from display position for B pictures.
    pub const fn segment(&self) -> usize {
        self.segment
    }
    /// Canonical source-capsule identity of this matched frame.
    pub const fn capsule_digest(&self) -> ContentDigest {
        self.capsule_digest
    }
    /// Conservative capture interval supplied by the retained import's operator hints.
    pub const fn capture(&self) -> CaptureInterval {
        self.capture
    }
}

/// Source-closed immutable candidate; only its publication classification is mutable.
#[derive(Debug)]
pub struct LongWatchCandidate {
    entry: LongWatchEntry,
    event: EventHypothesis,
    record: Vec<u8>,
    manifest: ObjectManifest,
    slot: SlotName,
    approval: ContentDigest,
    status: WatchStatus,
}
impl LongWatchCandidate {
    /// Observation that produced this entry, never a predicted track position.
    pub fn entry(&self) -> &LongWatchEntry {
        &self.entry
    }
    /// Exact approval, distinct from ordinary watch and dwell approvals.
    pub const fn proposal_digest(&self) -> ContentDigest {
        self.approval
    }
    /// Proposed event: always unclassified, indeterminate, abstained and single-sensor.
    pub fn event(&self) -> &EventHypothesis {
        &self.event
    }
    /// Whether this exact event is prepared, newly published, or already published.
    pub const fn status(&self) -> WatchStatus {
        self.status
    }
}

/// Complete bounded scan. No pixels survive analysis, and no partial inventory is publishable.
#[derive(Debug)]
pub struct LongWatchReport {
    plan: WatchPlan,
    options: WatchOptions,
    limits: LongWatchLimits,
    root: PathBuf,
    site: String,
    principal: String,
    basis: LedgerAnchor,
    import_root: ContentDigest,
    sensor: SensorId,
    privacy: MaskBinding,
    publication_guard: SourcePublicationGuard,
    analysis: Vec<u8>,
    analysis_manifest: ObjectManifest,
    analysis_slot: SlotName,
    candidates: Vec<LongWatchCandidate>,
    decoded: usize,
    unreliable: usize,
    masked_zones: usize,
    restarts: usize,
    refusals: Vec<DecodeRefusal>,
    source_bytes: u64,
    pixel_samples: u64,
    assignment_work: u64,
    jpeg_work: u64,
    media_format: String,
    health: Option<LongDwellHealthSummary>,
}

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage)
        .map_err(|_| RecordedDecodeError::Cancelled.into())
}
fn hex(digest: ContentDigest) -> String {
    digest
        .bytes()
        .iter()
        .map(|value| format!("{value:02x}"))
        .collect()
}

impl LongWatchReport {
    /// Run one whole-recording analysis with persistent foreground/tracker state and budgets.
    pub fn analyze(
        deployment: &ReferenceDeployment,
        plan: &WatchPlan,
        options: WatchOptions,
        limits: &LongWatchLimits,
        cx: &ReplayCx,
    ) -> Result<Self> {
        Self::analyze_inner(deployment, plan, options, limits, cx, false)
    }

    /// Screen the same privacy-masked pixels and block publication on any incomplete/degraded run.
    pub fn analyze_screened(
        deployment: &ReferenceDeployment,
        plan: &WatchPlan,
        options: WatchOptions,
        limits: &LongWatchLimits,
        cx: &ReplayCx,
    ) -> Result<Self> {
        Self::analyze_inner(deployment, plan, options, limits, cx, true)
    }

    fn analyze_inner(
        deployment: &ReferenceDeployment,
        plan: &WatchPlan,
        options: WatchOptions,
        limits: &LongWatchLimits,
        cx: &ReplayCx,
        screened: bool,
    ) -> Result<Self> {
        checkpoint(cx, "long_watch:analyze")?;
        let scan = run_scan(
            deployment,
            plan,
            ScanRule::ZoneEntry,
            options,
            limits,
            cx,
            screened,
        )?;
        let mut e = CanonicalEncoder::new();
        e.text(ANALYSIS_DOMAIN);
        e.digest(ContentDigest::sha256(POLICY));
        e.text(deployment.site_lineage());
        e.digest(plan.digest());
        e.digest(plan.import_identity);
        e.u64(plan.first_segment as u64);
        e.u64(plan.segment_count as u64);
        e.u64(plan.zones.len() as u64);
        for zone in &plan.zones {
            e.text(&zone.zone_id);
            for value in [zone.x, zone.y, zone.width, zone.height] {
                e.u32(value);
            }
        }
        let parameters = pipeline_parameters(plan.interpretation, &plan.detector, &plan.tracker);
        e.u64(parameters.len() as u64);
        for parameter in parameters {
            e.u64(parameter);
        }
        e.digest(scan.import_root);
        e.digest(scan.manifest_digest);
        scan.import_anchor.encode_canonical(&mut e);
        e.text(scan.sensor.as_str());
        e.text(&scan.media_format);
        e.digest(scan.privacy.digest());
        match scan.privacy.generation() {
            Some(generation) => {
                e.bool(true);
                e.u64(generation);
            }
            None => e.bool(false),
        }
        e.bool(options.tolerate_decode_refusals);
        // Resource changes are part of the reviewable computation recipe, never silent resets.
        for value in [
            limits.maximum_source_chunk_bytes,
            limits.maximum_pixel_samples,
            limits.maximum_assignment_work,
            limits.maximum_trace_bytes as u64,
            limits.decode.jpeg_work_units,
        ] {
            e.u64(value);
        }
        e.bytes(&scan.trace);
        if let Some(summary) = &scan.health {
            e.text("sensor_health");
            e.bytes(health_policy_bytes());
            summary.encode(&mut e);
        }
        let analysis = e.finish_checked()?;
        let analysis_digest = ContentDigest::sha256(&analysis);
        let mut children = BTreeSet::from([
            scan.import_root,
            analysis_digest,
            ContentDigest::sha256(POLICY),
            ContentDigest::sha256(scan.sensor.as_str().as_bytes()),
        ]);
        if let Some(policy) = scan.privacy.policy() {
            children.insert(policy.digest());
        }
        if scan.health.is_some() {
            children.insert(health_policy_digest());
        }
        let analysis_manifest =
            ObjectManifest::new("recorded-long-watch-analysis-v1", children, None)?;
        let principal = cx.io_authority().principal().to_owned();
        let mut candidates = Vec::new();
        for entry in scan.entries {
            candidates.push(prepare_candidate(
                deployment,
                entry,
                plan,
                analysis_manifest.root(),
                &scan.sensor,
                &principal,
                &scan.privacy,
            )?);
        }
        let report = Self {
            plan: plan.clone(),
            options,
            limits: *limits,
            root: deployment.root().to_path_buf(),
            site: deployment.site_lineage().to_owned(),
            principal,
            basis: deployment.current_anchor().clone(),
            import_root: scan.import_root,
            sensor: scan.sensor,
            privacy: scan.privacy,
            publication_guard: scan.publication_guard,
            analysis,
            analysis_manifest,
            analysis_slot: slot("lw-a", analysis_digest)?,
            candidates,
            decoded: scan.decoded,
            unreliable: scan.unreliable,
            masked_zones: scan.masked_zones,
            restarts: scan.restarts,
            refusals: scan.refusals,
            source_bytes: scan.source_bytes,
            pixel_samples: scan.pixel_samples,
            assignment_work: scan.assignment_work,
            jpeg_work: scan.jpeg_work,
            media_format: scan.media_format,
            health: scan.health,
        };
        report.to_json(deployment.current_anchor().commit_sequence, None)?;
        Ok(report)
    }

    /// Complete entry inventory in deterministic display-position, epoch, track and zone order.
    pub fn candidates(&self) -> &[LongWatchCandidate] {
        &self.candidates
    }
    /// Digest of the complete source-, policy-, privacy- and budget-bound native trace.
    pub fn analysis_digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.analysis)
    }
    /// Exact complete analysis closure for the read-only native replay adapter.
    pub(crate) fn replay_analysis_root(&self) -> ContentDigest {
        self.analysis_manifest.root()
    }
    /// Number of successfully decoded frames in the complete scan.
    pub const fn frames_decoded(&self) -> usize {
        self.decoded
    }
    /// Actual source-chunk bytes fetched; source cache hits do not spend another allowance.
    pub const fn source_chunk_bytes_read(&self) -> u64 {
        self.source_bytes
    }
    /// Requested screening diagnostics, or no screening claim when absent.
    pub fn health_summary(&self) -> Option<&LongDwellHealthSummary> {
        self.health.as_ref()
    }
    /// Whole-scan health gate; a clear screen never certifies sensor health or physical absence.
    pub fn publication_blocked(&self) -> bool {
        self.health
            .as_ref()
            .is_some_and(LongDwellHealthSummary::publication_blocked)
    }

    /// Publish only exact approved entries, after source/root/principal/privacy revalidation.
    /// Partial publication is root-last and resumable; an exact retry never creates another event.
    pub fn publish(
        &mut self,
        deployment: &mut ReferenceDeployment,
        approvals: &BTreeSet<ContentDigest>,
        cx: &ReplayCx,
    ) -> Result<usize> {
        checkpoint(cx, "long_watch:revalidate")?;
        if self.publication_blocked() {
            return Err(WatchError::InvalidPlan(HEALTH_PUBLICATION_BLOCKED));
        }
        if deployment.root() != self.root.as_path()
            || cx.root_dir() != deployment.root()
            || deployment.site_lineage() != self.site
            || cx.io_authority().principal() != self.principal
        {
            return Err(WatchError::Conflict);
        }
        for approval in approvals {
            if !self
                .candidates
                .iter()
                .any(|candidate| candidate.approval == *approval)
            {
                return Err(WatchError::StaleApproval(*approval));
            }
        }
        self.publication_guard.revalidate(deployment, cx)?;
        for candidate in &mut self.candidates {
            if approvals.contains(&candidate.approval) {
                candidate.status = event_status(deployment, &candidate.event)?;
            }
        }
        self.to_json(deployment.current_anchor().commit_sequence, None)?;
        if !self
            .candidates
            .iter()
            .any(|c| approvals.contains(&c.approval) && c.status == WatchStatus::Prepared)
        {
            return Ok(0);
        }
        checkpoint(cx, "long_watch:stage")?;
        for bytes in [
            self.analysis.as_slice(),
            POLICY,
            self.sensor.as_str().as_bytes(),
        ] {
            let digest = deployment.publisher_mut().stage_object(bytes)?;
            deployment.publisher_mut().verify_object(digest)?;
        }
        if self.health.is_some() {
            let digest = deployment
                .publisher_mut()
                .stage_object(health_policy_bytes())?;
            deployment.publisher_mut().verify_object(digest)?;
        }
        if let Some(policy) = self.privacy.policy() {
            let digest = deployment
                .publisher_mut()
                .stage_object(&policy.to_bytes())?;
            deployment.publisher_mut().verify_object(digest)?;
        }
        let validity = self
            .candidates
            .iter()
            .map(|c| c.event.interval)
            .reduce(|a, b| CaptureInterval {
                earliest: a.earliest.min(b.earliest),
                latest: a.latest.max(b.latest),
            })
            .ok_or(WatchError::Conflict)?;
        publish_manifest(
            deployment,
            &self.analysis_slot,
            &self.analysis_manifest,
            validity,
            cx,
        )?;
        let mut published = 0;
        for candidate in &mut self.candidates {
            if !approvals.contains(&candidate.approval)
                || candidate.status == WatchStatus::AlreadyPublished
            {
                continue;
            }
            checkpoint(cx, "long_watch:entry")?;
            let digest = deployment.publisher_mut().stage_object(&candidate.record)?;
            deployment.publisher_mut().verify_object(digest)?;
            publish_manifest(
                deployment,
                &candidate.slot,
                &candidate.manifest,
                candidate.event.interval,
                cx,
            )?;
            checkpoint(cx, "long_watch:commit")?;
            deployment.publish_event(
                &ReferencePolicyDecision {
                    event: candidate.event.clone(),
                    action: ReferencePolicyAction::Hold,
                },
                cx,
            )?;
            cx.checkpoint_post_commit("long_watch:published");
            candidate.status = WatchStatus::Published;
            published += 1;
        }
        Ok(published)
    }

    /// Complete bounded report; no candidate or diagnostic may be truncated to fit the ceiling.
    pub fn to_json(&self, authority_sequence: u64, approve_hint: Option<&str>) -> Result<String> {
        if approve_hint.is_some_and(|hint| hint.len() > 8192) {
            return Err(WatchError::Limit);
        }
        let approve_hint = if self.publication_blocked() {
            None
        } else {
            approve_hint
        };
        let candidates = self.candidates.iter().map(|c| {
            let entry = &c.entry;
            let command = match (c.status, approve_hint) {
                (WatchStatus::Prepared, Some(hint)) => json(&format!("{hint} --approve {}", c.approval)),
                _ => "null".to_owned(),
            };
            format!(concat!("{{\"event_id\":{},\"zone_id\":{},\"tracker_epoch\":{},\"track_id\":{},",
                "\"entry_position\":{},\"entry_segment\":{},\"entry_capsule_digest\":{},",
                "\"capture_earliest_ns\":{},\"capture_latest_ns\":{},\"filtered_box\":[{},{},{},{}],",
                "\"proposal_digest\":{},\"provenance_root\":{},\"status\":{},\"publish_command\":{}}}"),
                json(c.event.event_id.as_str()), json(&self.plan.zones[entry.zone].zone_id), entry.epoch,
                entry.track, entry.position, entry.segment, json(&entry.capsule_digest.to_text()),
                json(&entry.capture.earliest.0.to_string()), json(&entry.capture.latest.0.to_string()),
                entry.filtered_box[0], entry.filtered_box[1], entry.filtered_box[2], entry.filtered_box[3],
                json(&c.approval.to_text()), json(&c.manifest.root().to_text()), json(c.status.as_str()), command)
        }).collect::<Vec<_>>().join(",");
        let refusals = self
            .refusals
            .iter()
            .map(|r| {
                format!(
                    "{{\"first_segment\":{},\"last_segment\":{},\"error_id\":{}}}",
                    r.first_segment,
                    r.last_segment,
                    json(&r.error_id),
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let health = self
            .health
            .as_ref()
            .map_or_else(|| "null".to_owned(), LongDwellHealthSummary::to_json);
        let text = format!(
            concat!(
                "{{\"format\":{},\"site\":{},\"principal\":{},\"import_identity\":{},\"import_root\":{},",
                "\"plan_digest\":{},\"analysis_digest\":{},\"analysis_root\":{},\"analysis_basis_sequence\":{},",
                "\"analysis_basis_root\":{},\"authority_sequence\":{},\"first_segment\":{},\"segment_count\":{},",
                "\"frames_decoded\":{},\"unreliable_time_frames\":{},\"masked_zones\":{},\"tracking_restarts\":{},",
                "\"tolerate_decode_refusals\":{},\"decode_refusals\":[{}],\"source_chunk_bytes_read\":{},",
                "\"pixel_samples_processed\":{},\"assignment_work_admitted\":{},\"jpeg_work_units\":{},",
                "\"trace_record_bytes\":{},\"privacy_binding\":{},\"candidate_count\":{},\"candidates\":[{}],",
                "\"media_format\":{},\"capture_time_label\":\"operator_assumption\",\"sensor_health\":{},",
                "\"publication_blocked\":{},\"source_byte_budget\":{},\"pixel_sample_budget\":{},",
                "\"assignment_work_budget\":{},\"trace_byte_budget\":{},",
                "\"event_kind\":\"unclassified\",\"event_state\":\"indeterminate\",\"policy_action\":\"hold\",",
                "\"calibrated\":false,\"corroborated\":false,\"physical_arrival_proved\":false,",
                "\"absence_certifiable\":false,\"alert_authorized\":false,\"model_invoked\":false,",
                "\"qualification\":\"implemented_not_qualified\"}}"
            ),
            json(LONG_WATCH_REPORT_SCHEMA),
            json(&self.site),
            json(&self.principal),
            json(&self.plan.import_identity.to_text()),
            json(&self.import_root.to_text()),
            json(&self.plan.digest().to_text()),
            json(&self.analysis_digest().to_text()),
            json(&self.analysis_manifest.root().to_text()),
            self.basis.commit_sequence,
            json(&self.basis.state_root.to_text()),
            authority_sequence,
            self.plan.first_segment,
            self.plan.segment_count,
            self.decoded,
            self.unreliable,
            self.masked_zones,
            self.restarts,
            self.options.tolerate_decode_refusals,
            refusals,
            self.source_bytes,
            self.pixel_samples,
            self.assignment_work,
            self.jpeg_work,
            self.analysis.len(),
            json(&self.privacy.digest().to_text()),
            self.candidates.len(),
            candidates,
            json(&self.media_format),
            health,
            self.publication_blocked(),
            self.limits.maximum_source_chunk_bytes,
            self.limits.maximum_pixel_samples,
            self.limits.maximum_assignment_work,
            self.limits.maximum_trace_bytes,
        );
        if text.len() > MAX_REPORT_BYTES {
            return Err(WatchError::Limit);
        }
        Ok(text)
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_candidate(
    deployment: &ReferenceDeployment,
    entry: LongWatchEntry,
    plan: &WatchPlan,
    analysis_root: ContentDigest,
    sensor: &SensorId,
    principal: &str,
    privacy: &MaskBinding,
) -> Result<LongWatchCandidate> {
    let mut e = CanonicalEncoder::new();
    e.text(ENTRY_DOMAIN);
    e.digest(analysis_root);
    e.text(&plan.zones[entry.zone].zone_id);
    e.u64(entry.epoch);
    e.u64(entry.track);
    e.u64(entry.position as u64);
    e.u64(entry.segment as u64);
    e.digest(entry.capsule_digest);
    entry.capture.encode_canonical(&mut e);
    for value in entry.filtered_box {
        e.i128(i128::from(value));
    }
    let record = e.finish_checked()?;
    let identity = ContentDigest::sha256(&record);
    let manifest = ObjectManifest::new(
        "recorded-long-watch-entry-v1",
        [analysis_root, identity],
        None,
    )?;
    let sensor_digest = ContentDigest::sha256(sensor.as_str().as_bytes());
    let failure_domain = format!("recorded-sensor:{}", hex(sensor_digest));
    let mut evidence = vec![EventEvidence {
        digest: identity,
        class: EvidenceClass::Derived,
        failure_domain: failure_domain.clone(),
        supports: false,
        relation: EvidenceEdgeRelation::DerivedFrom,
        capsule_digest: Some(entry.capsule_digest),
        identity_digest: Some(sensor_digest),
    }];
    if let Some(policy) = privacy.policy() {
        evidence.push(EventEvidence {
            digest: policy.digest(),
            class: EvidenceClass::Assertion,
            failure_domain,
            supports: false,
            relation: EvidenceEdgeRelation::RequiredBy,
            capsule_digest: None,
            identity_digest: Some(sensor_digest),
        });
    }
    evidence.sort_by_key(|item| item.digest);
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(), event_id: EventId::parse(format!("event:long-watch:{}", hex(identity)))?,
        revision: 1, supersedes: None, state: EventState::Indeterminate, kind: EventKind::Unclassified,
        interval: entry.capture, uncertainty_reason: Some(UNCERTAINTY.to_owned()),
        zone_ids: vec![plan.zones[entry.zone].zone_id.clone()],
        track_ids: vec![format!("track:{}:{}", entry.epoch, entry.track)],
        probability: ProbabilityInterval::new(0.0, 1.0)?, evidence, model_receipts: Vec::new(),
        decision_path: DecisionPath {
            policy_generation: ContentDigest::sha256(POLICY), fingerprint: manifest.root(), abstained: true,
            abstention_reason: Some("First matched foreground-track observation in a zone; no classification, physical arrival, identity, intent, absence or alert authority.".to_owned()),
        },
    };
    event.validate()?;
    let mut e = CanonicalEncoder::new();
    e.text(APPROVAL_DOMAIN);
    e.text(deployment.site_lineage());
    e.text(principal);
    e.digest(event.revision_digest());
    e.digest(manifest.root());
    let approval = ContentDigest::sha256(&e.finish_checked()?);
    let status = event_status(deployment, &event)?;
    Ok(LongWatchCandidate {
        entry,
        event,
        record,
        manifest,
        slot: slot("lw-e", identity)?,
        approval,
        status,
    })
}
