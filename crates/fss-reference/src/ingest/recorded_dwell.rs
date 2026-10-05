#![forbid(unsafe_code)]
//! Sustained sampled occupancy over the existing retained watch pipeline (FSS-083).
//!
//! This executes the real privacy-projected decoder, foreground detector and tracker once.
//! Only matched observations at or after confirmed zone entry can contribute. It publishes
//! separately approved, source-closed, unclassified hypotheses; it never publishes the entry
//! candidates, certifies continuous presence/absence, or acquires alert authority.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use fss_core::{
    CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest, DecisionPath, EventEvidence,
    EventHypothesis, EventId, EventKind, EventState, EvidenceClass, EvidenceEdgeRelation, ObjectId,
    ProbabilityInterval, SensorId,
};
use fss_object::ObjectManifest;
use fss_publication::SlotName;

use super::detector_cascade::{ClassEvidence, DetectorCascade, class_evidence_json};
use super::privacy_mask::{MaskBinding, current_mask};
use super::recorded_decode::{RecordedDecodeError, source_capsule};
use super::recorded_watch::{
    MAX_WATCH_CANDIDATES, WatchError, WatchFrame, WatchLimits, WatchObservation, WatchOptions,
    WatchPlan, WatchReport, WatchStatus, WatchZone, decode_refusals_json, masked_plan_digest,
};
use super::zone_dwell::{DwellError, DwellPolicy, DwellSample, DwellSpan, dwell_spans};
use super::{RetainedFileImport, RetainedReadLimits};
use crate::{ReferenceDeployment, ReferencePolicyAction, ReferencePolicyDecision, ReplayCx};

/// Complete JSON output ceiling, enforced before any approved event is published.
pub const MAX_DWELL_REPORT_BYTES: usize = 2 * 1024 * 1024;
const POLICY: &str = "sampled-dwell-v1:confirmed-matches:rounded-center-half-pixel-margin:consecutive-decoded-segments:worst-case-sampling-gap:latest-first-to-earliest-last:one-per-episode:operator-time-hints:no-omissions:no-masked-zones:unclassified:hold";
const RULE_DOMAIN: &str = "fss.recorded_dwell_rule.v1";
const ANALYSIS_DOMAIN: &str = "fss.recorded_dwell_analysis.v1";
const OBSERVATION_DOMAIN: &str = "fss.recorded_dwell_observation.v1";
const CANDIDATE_DOMAIN: &str = "fss.recorded_dwell_candidate.v1";
const APPROVAL_DOMAIN: &str = "fss.recorded_dwell_approval.v1";
const UNCERTAINTY: &str = "Matched foreground-track samples inside an owner zone span the dwell threshold under operator capture hints. Not continuous occupancy, a person, intent, calibrated detection, independent corroboration, or an alert decision.";
type Result<T> = std::result::Result<T, WatchError>;

fn gate_error(error: DwellError) -> WatchError {
    match error {
        DwellError::Limit => WatchError::Limit,
        DwellError::InvalidPolicy => WatchError::InvalidPlan("invalid sampled-dwell rule"),
        DwellError::InvalidSamples => WatchError::InvalidPlan("invalid sampled-dwell sequence"),
        DwellError::ClockReversed => {
            WatchError::InvalidPlan("sampled-dwell capture clock reversed")
        }
    }
}
fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage)
        .map_err(|_| RecordedDecodeError::Cancelled.into())
}
fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}
fn json(value: &str) -> String {
    let mut out = String::from("\"");
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
fn rule_bytes(policy: DwellPolicy) -> Vec<u8> {
    let mut e = CanonicalEncoder::new();
    e.text(RULE_DOMAIN);
    e.text(POLICY);
    e.u64(policy.minimum_duration_ns);
    e.u64(policy.maximum_sample_gap_ns);
    e.u64(policy.minimum_observations as u64);
    e.finish()
}

// The public watch observation rounds centers to integer pixels. Requiring a strict interior
// integer center places the whole +/- 0.5-pixel rounding cell inside integer zone boundaries.
// Boundary cells are excluded, never guessed to be inside. This is not a Kalman covariance bound.
fn inside(observation: &WatchObservation, zone: &WatchZone) -> bool {
    let [cx, cy, width, height] = observation.track_box;
    width > 0
        && height > 0
        && i128::from(cx) > i128::from(zone.x)
        && i128::from(cy) > i128::from(zone.y)
        && i128::from(cx) < i128::from(zone.x) + i128::from(zone.width)
        && i128::from(cy) < i128::from(zone.y) + i128::from(zone.height)
}

#[derive(Clone, Debug)]
struct Observation {
    frame: WatchFrame,
    track_box: [i64; 4],
    bytes: Vec<u8>,
}
impl Observation {
    fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.bytes)
    }
}

/// One maximal observed episode and its exact, separately approved event proposal.
#[derive(Clone, Debug)]
pub struct DwellCandidate {
    zone: String,
    track: u64,
    span: DwellSpan,
    first_segment: usize,
    trigger_segment: usize,
    last_segment: usize,
    observations: Vec<Observation>,
    classes: Vec<ClassEvidence>,
    identity: ContentDigest,
    event: EventHypothesis,
    slot: SlotName,
    manifest: ObjectManifest,
    objects: BTreeMap<ContentDigest, Vec<u8>>,
    approval: ContentDigest,
    status: WatchStatus,
}
impl DwellCandidate {
    /// Immutable hypothesis, always unclassified, indeterminate and single-sensor.
    pub fn event(&self) -> &EventHypothesis {
        &self.event
    }
    /// Exact approval binds the complete event revision and source-closed provenance root.
    pub const fn proposal_digest(&self) -> ContentDigest {
        self.approval
    }
    /// First, threshold-crossing and final retained segment of this episode.
    pub const fn segments(&self) -> [usize; 3] {
        [self.first_segment, self.trigger_segment, self.last_segment]
    }
    /// Exact temporal accounting over actual matched samples.
    pub const fn span(&self) -> DwellSpan {
        self.span
    }
    /// Current publication state; a retry never creates another event.
    pub const fn status(&self) -> WatchStatus {
        self.status
    }
    /// Root retaining rule, analysis, observation records and original source custody.
    pub fn provenance_root(&self) -> ContentDigest {
        self.manifest.root()
    }
}

/// A sealed-by-construction analysis. Callers cannot supply or mutate candidate evidence.
#[derive(Clone, Debug)]
pub struct DwellReport {
    plan: WatchPlan,
    rule: DwellPolicy,
    watch: WatchReport,
    import_root: ContentDigest,
    sensor: SensorId,
    root: PathBuf,
    site: String,
    limits: RetainedReadLimits,
    analysis: Vec<u8>,
    candidates: Vec<DwellCandidate>,
    unreliable_time_frames: usize,
    masked_zones: usize,
}

impl DwellReport {
    /// Run retained watch once, then evaluate complete per-track/zone timelines. No writes.
    /// Unknown capture time is refused before decode. Source gaps and any omitted input bytes
    /// exclude affected timing rather than substituting receive time or nominal frame counts.
    /// Detector classes remain optional same-sensor annotations, never inputs to the dwell rule.
    pub fn analyze(
        deployment: &ReferenceDeployment,
        plan: &WatchPlan,
        rule: DwellPolicy,
        limits: &WatchLimits,
        detector: Option<&mut DetectorCascade<'_>>,
        options: WatchOptions,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx, "recorded_dwell:analyze")?;
        rule.validate().map_err(gate_error)?;
        plan.validate()?;
        let retained =
            RetainedFileImport::open(deployment, plan.import_identity, limits.read_limits, cx)?;
        if retained.manifest().capture_time_label != "operator_assumption" {
            return Err(WatchError::InvalidPlan(
                "sampled dwell requires explicit capture-time hints",
            ));
        }
        let import_root = retained.import_root();
        let (capsule, _) = source_capsule(deployment, &retained, plan.first_segment)?;
        let watch =
            WatchReport::analyze_with_options(deployment, plan, limits, detector, options, cx)?;
        let frames = watch.frames();
        let omissions = retained
            .manifest()
            .omission_spans
            .iter()
            .any(|span| span.len > 0);
        let first_gap = retained
            .manifest()
            .segment_spans
            .iter()
            .find(|span| span.segment_index > 0 && span.gap_before)
            .map(|span| span.segment_index);
        let reliable: Vec<bool> = frames
            .iter()
            .map(|frame| !omissions && first_gap.is_none_or(|gap| frame.segment < gap))
            .collect();
        let masked: BTreeSet<String> = plan
            .zones
            .iter()
            .filter(|zone| {
                watch.privacy_mask().policy().is_some_and(|policy| {
                    policy
                        .zone_masking([zone.x, zone.y, zone.width, zone.height])
                        .any()
                })
            })
            .map(|zone| zone.zone_id.clone())
            .collect();
        let mut e = CanonicalEncoder::new();
        e.text(ANALYSIS_DOMAIN);
        e.bytes(&rule_bytes(rule));
        e.text(deployment.site_lineage());
        e.digest(watch.plan_digest());
        e.digest(import_root);
        e.u64(frames.len() as u64);
        for (frame, reliable) in frames.iter().zip(&reliable) {
            e.u64(frame.segment as u64);
            e.digest(frame.capsule_digest);
            e.digest(frame.luma_digest);
            frame.capture.encode_canonical(&mut e);
            e.bool(*reliable);
        }
        e.u64(watch.tracking_restarts().len() as u64);
        for segment in watch.tracking_restarts() {
            e.u64(*segment as u64);
        }
        e.u64(watch.decode_refusals().len() as u64);
        for refusal in watch.decode_refusals() {
            e.u64(refusal.first_segment as u64);
            e.u64(refusal.last_segment as u64);
            e.text(&refusal.error_id);
        }
        match (watch.cascade_digest(), watch.detector_cascade()) {
            (Some(cascade), Some(outcome)) => {
                e.bool(true);
                e.digest(cascade);
                e.digest(outcome.digest(cascade));
            }
            (None, None) => e.bool(false),
            _ => return Err(WatchError::Conflict),
        }
        e.u64(watch.candidates().len() as u64);
        let mut pending = Vec::new();
        let mut seen = BTreeSet::new();
        for candidate in watch.candidates() {
            checkpoint(cx, "recorded_dwell:track")?;
            if !seen.insert((candidate.zone_id.clone(), candidate.track_id)) {
                return Err(WatchError::Conflict);
            }
            let zone = plan
                .zones
                .iter()
                .find(|zone| zone.zone_id == candidate.zone_id)
                .ok_or(WatchError::Conflict)?;
            let entry = frames
                .iter()
                .position(|frame| frame.segment == candidate.entry_segment)
                .ok_or(WatchError::Conflict)?;
            let by_segment: BTreeMap<_, _> = candidate
                .observations
                .iter()
                .map(|observation| (observation.segment, observation))
                .collect();
            if by_segment.len() != candidate.observations.len() {
                return Err(WatchError::Conflict);
            }
            let samples: Vec<_> = frames
                .iter()
                .enumerate()
                .map(|(position, frame)| DwellSample {
                    position,
                    capture: reliable[position].then_some(frame.capture),
                    matched_inside: position >= entry
                        && !masked.contains(&zone.zone_id)
                        && by_segment
                            .get(&frame.segment)
                            .is_some_and(|o| inside(o, zone)),
                    discontinuity: watch.tracking_restarts().contains(&frame.segment)
                        || (position > 0
                            && frames[position - 1].segment.checked_add(1) != Some(frame.segment)),
                })
                .collect();
            // Retain the full selection trace, including excluded and unmatched frames. It is
            // derived cognition; source capsule identities and full rules make replay inspectable.
            e.text(&candidate.zone_id);
            e.u64(candidate.track_id);
            e.u64(entry as u64);
            for (sample, frame) in samples.iter().zip(frames) {
                e.bool(sample.matched_inside);
                e.bool(sample.discontinuity);
                if let Some(observation) = by_segment.get(&frame.segment) {
                    e.bool(true);
                    for coordinate in observation.track_box {
                        e.i128(i128::from(coordinate));
                    }
                } else {
                    e.bool(false);
                }
            }
            for span in dwell_spans(&samples, rule).map_err(gate_error)? {
                if pending.len() == MAX_WATCH_CANDIDATES {
                    return Err(WatchError::Limit);
                }
                let mut observations = Vec::new();
                for frame in &frames[span.first..=span.last] {
                    let observed = by_segment.get(&frame.segment).ok_or(WatchError::Conflict)?;
                    let mut record = CanonicalEncoder::new();
                    record.text(OBSERVATION_DOMAIN);
                    record.digest(plan.import_identity);
                    record.digest(watch.plan_digest());
                    record.text(&zone.zone_id);
                    record.u64(candidate.track_id);
                    record.u64(frame.segment as u64);
                    record.digest(frame.capsule_digest);
                    record.digest(frame.luma_digest);
                    frame.capture.encode_canonical(&mut record);
                    for coordinate in observed.track_box {
                        record.i128(i128::from(coordinate));
                    }
                    observations.push(Observation {
                        frame: WatchFrame {
                            segment: frame.segment,
                            capsule_digest: frame.capsule_digest,
                            capture: frame.capture,
                            luma_digest: frame.luma_digest,
                            boxes: Vec::new(),
                        },
                        track_box: observed.track_box,
                        bytes: record.finish(),
                    });
                }
                let classes = candidate
                    .class_evidence
                    .iter()
                    .filter(|class| {
                        observations
                            .iter()
                            .any(|observation| observation.frame.segment == class.segment)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                pending.push(Pending {
                    zone: zone.zone_id.clone(),
                    track: candidate.track_id,
                    span,
                    trigger_segment: frames[span.triggered].segment,
                    observations,
                    classes,
                });
            }
        }
        pending.sort_by(|a, b| {
            (a.span.triggered, a.track, &a.zone, a.span.first).cmp(&(
                b.span.triggered,
                b.track,
                &b.zone,
                b.span.first,
            ))
        });
        let analysis = e.finish();
        let mut candidates = Vec::with_capacity(pending.len());
        for pending in pending {
            checkpoint(cx, "recorded_dwell:prepare")?;
            candidates.push(prepare(
                deployment,
                pending,
                &analysis,
                import_root,
                &capsule.sensor_id,
                watch.privacy_mask(),
                rule,
            )?);
        }
        let report = Self {
            plan: plan.clone(),
            rule,
            import_root,
            sensor: capsule.sensor_id,
            root: deployment.root().to_path_buf(),
            site: deployment.site_lineage().to_owned(),
            limits: limits.read_limits,
            analysis,
            candidates,
            unreliable_time_frames: reliable.iter().filter(|&&known| !known).count(),
            masked_zones: masked.len(),
            watch,
        };
        report.to_json(deployment.current_anchor().commit_sequence, None)?;
        Ok(report)
    }

    /// Complete candidate list, ordered by trigger position, track, zone and episode start.
    pub fn candidates(&self) -> &[DwellCandidate] {
        &self.candidates
    }
    /// Canonical complete selection trace retained with every published episode.
    pub fn analysis_digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.analysis)
    }
    /// Frames excluded from duration accounting because source timing is unreliable.
    pub const fn unreliable_time_frames(&self) -> usize {
        self.unreliable_time_frames
    }

    /// Publish only exact approved dwell proposals. Entry approvals cannot authorize this path.
    /// Recheck deletion, source identity and the current privacy generation before any writes.
    /// The existing root-last and event publishers own crash recovery and canonical revisions.
    pub fn publish(
        &mut self,
        deployment: &mut ReferenceDeployment,
        approvals: &BTreeSet<ContentDigest>,
        cx: &ReplayCx,
    ) -> Result<usize> {
        checkpoint(cx, "recorded_dwell:revalidate")?;
        if deployment.root() != self.root.as_path()
            || deployment.site_lineage() != self.site.as_str()
            || cx.root_dir() != deployment.root()
        {
            return Err(WatchError::Conflict);
        }
        deployment
            .ledger()
            .verify_durable_head()
            .map_err(crate::ReferenceError::from)?;
        let retained =
            RetainedFileImport::open(deployment, self.plan.import_identity, self.limits, cx)?;
        if retained.import_root() != self.import_root {
            return Err(WatchError::Conflict);
        }
        let privacy = current_mask(deployment, &self.sensor).map_err(RecordedDecodeError::from)?;
        if masked_plan_digest(self.plan.digest(), &privacy) != self.watch.plan_digest() {
            return Err(WatchError::InvalidPlan(
                "privacy generation changed; recompute dwell proposals",
            ));
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
        for candidate in &mut self.candidates {
            if approvals.contains(&candidate.approval) {
                candidate.status = status(deployment, &candidate.event)?;
            }
        }
        self.to_json(deployment.current_anchor().commit_sequence, None)?;
        let mut published = 0;
        for candidate in &mut self.candidates {
            if !approvals.contains(&candidate.approval)
                || candidate.status == WatchStatus::AlreadyPublished
            {
                continue;
            }
            checkpoint(cx, "recorded_dwell:stage")?;
            for bytes in candidate.objects.values() {
                checkpoint(cx, "recorded_dwell:object")?;
                let digest = deployment.publisher_mut().stage_object(bytes)?;
                deployment.publisher_mut().verify_object(digest)?;
            }
            for digest in candidate.manifest.children() {
                deployment.publisher_mut().verify_object(*digest)?;
            }
            let existing = deployment
                .publisher()
                .root(&candidate.slot)
                .map(|root| root.root);
            if existing.is_some_and(|root| root != candidate.manifest.root()) {
                return Err(WatchError::Conflict);
            }
            if existing.is_none() {
                deployment
                    .publisher_mut()
                    .stage_manifest(&candidate.slot, &candidate.manifest)?;
            }
            deployment.publish_and_commit(
                &candidate.slot,
                &candidate.manifest,
                candidate.event.interval,
                cx,
            )?;
            checkpoint(cx, "recorded_dwell:commit")?;
            deployment.publish_event(
                &ReferencePolicyDecision {
                    event: candidate.event.clone(),
                    action: ReferencePolicyAction::Hold,
                },
                cx,
            )?;
            cx.checkpoint_post_commit("recorded_dwell:published");
            candidate.status = WatchStatus::Published;
            published += 1;
        }
        Ok(published)
    }

    /// Complete, bounded JSON. No zero-candidate result is an absence certificate.
    pub fn to_json(&self, authority_sequence: u64, approve_hint: Option<&str>) -> Result<String> {
        if approve_hint.is_some_and(|hint| hint.len() > 8192) {
            return Err(WatchError::Limit);
        }
        let candidates = self.candidates.iter().map(|candidate| {
            let command = match (candidate.status, approve_hint) {
                (WatchStatus::Prepared, Some(hint)) => json(&format!("{hint} --approve {}", candidate.approval)),
                _ => "null".to_owned(),
            };
            let evidence = candidate.observations.iter().map(|o| {
                format!(
                    "{{\"segment\":{},\"observation_digest\":{},\"capsule_digest\":{},\"luma_digest\":{},\"capture_earliest_ns\":{},\"capture_latest_ns\":{},\"track_box_cxcywh\":[{},{},{},{}]}}",
                    o.frame.segment, json(&o.digest().to_text()), json(&o.frame.capsule_digest.to_text()),
                    json(&o.frame.luma_digest.to_text()), json(&o.frame.capture.earliest.0.to_string()),
                    json(&o.frame.capture.latest.0.to_string()),
                    o.track_box[0], o.track_box[1], o.track_box[2], o.track_box[3],
                )
            }).collect::<Vec<_>>().join(",");
            format!(concat!(
                "{{\"candidate_id\":{},\"zone_id\":{},\"track_id\":{},",
                "\"first_segment\":{},\"trigger_segment\":{},\"last_segment\":{},",
                "\"matched_observations\":{},\"trigger_minimum_ns\":{},\"minimum_duration_ns\":{},",
                "\"event_id\":{},\"proposal_digest\":{},\"provenance_root\":{},\"status\":{},",
                "\"publish_command\":{},\"class_evidence\":{},\"evidence\":[{}]}}"),
                json(&candidate.identity.to_text()), json(&candidate.zone), candidate.track,
                candidate.first_segment, candidate.trigger_segment, candidate.last_segment,
                candidate.span.observations, json(&candidate.span.trigger_minimum_ns.to_string()),
                json(&candidate.span.minimum_duration_ns.to_string()), json(candidate.event.event_id.as_str()),
                json(&candidate.approval.to_text()), json(&candidate.manifest.root().to_text()),
                json(candidate.status.as_str()), command, class_evidence_json(&candidate.classes), evidence,
            )
        }).collect::<Vec<_>>().join(",");
        let restarts = self
            .watch
            .tracking_restarts()
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let result = format!(
            concat!(
                "{{\"format\":\"fss.recorded_dwell_report.v1\",\"event_rule\":\"sampled_dwell\",",
                "\"import_identity\":{},\"import_root\":{},\"watch_plan_digest\":{},\"analysis_digest\":{},",
                "\"minimum_duration_ns\":{},\"maximum_sample_gap_ns\":{},\"minimum_observations\":{},",
                "\"frames_decoded\":{},\"unreliable_time_frames\":{},\"masked_zone_count\":{},",
                "\"tracking_restarts\":[{}],\"candidate_count\":{},\"candidates\":[{}],",
                "\"authority_sequence\":{},\"privacy_mask\":{},\"event_kind\":\"unclassified\",",
                "\"event_state\":\"indeterminate\",\"time_basis\":\"operator_assumption\",",
                "\"continuous_occupancy_certified\":false,\"absence_certifiable\":false,",
                "\"corroborated\":false,\"alert_authorized\":false,\"detection_quality_claim\":false{}}}"
            ),
            json(&self.plan.import_identity.to_text()),
            json(&self.import_root.to_text()),
            json(&self.watch.plan_digest().to_text()),
            json(&self.analysis_digest().to_text()),
            json(&self.rule.minimum_duration_ns.to_string()),
            json(&self.rule.maximum_sample_gap_ns.to_string()),
            self.rule.minimum_observations,
            self.watch.frames().len(),
            self.unreliable_time_frames,
            self.masked_zones,
            restarts,
            self.candidates.len(),
            candidates,
            authority_sequence,
            self.watch.privacy_mask().to_json(),
            decode_refusals_json(self.watch.decode_refusals()),
        );
        if result.len() > MAX_DWELL_REPORT_BYTES {
            return Err(WatchError::Limit);
        }
        Ok(result)
    }
}

struct Pending {
    zone: String,
    track: u64,
    span: DwellSpan,
    trigger_segment: usize,
    observations: Vec<Observation>,
    classes: Vec<ClassEvidence>,
}
fn insert(objects: &mut BTreeMap<ContentDigest, Vec<u8>>, bytes: Vec<u8>) -> ContentDigest {
    let digest = ContentDigest::sha256(&bytes);
    objects.insert(digest, bytes);
    digest
}
fn prepare(
    deployment: &ReferenceDeployment,
    pending: Pending,
    analysis: &[u8],
    import_root: ContentDigest,
    sensor: &SensorId,
    privacy: &MaskBinding,
    rule: DwellPolicy,
) -> Result<DwellCandidate> {
    let first = pending.observations.first().ok_or(WatchError::Conflict)?;
    let last = pending.observations.last().ok_or(WatchError::Conflict)?;
    let first_segment = first.frame.segment;
    let last_segment = last.frame.segment;
    let interval = CaptureInterval::new(first.frame.capture.earliest, last.frame.capture.latest)?;
    let mut e = CanonicalEncoder::new();
    e.text(CANDIDATE_DOMAIN);
    e.digest(ContentDigest::sha256(analysis));
    e.text(&pending.zone);
    e.u64(pending.track);
    e.u64(first_segment as u64);
    e.u64(pending.trigger_segment as u64);
    e.u64(last_segment as u64);
    e.u64(pending.observations.len() as u64);
    for observation in &pending.observations {
        e.digest(observation.digest());
    }
    e.u64(pending.classes.len() as u64);
    for class in &pending.classes {
        e.digest(ContentDigest::sha256(&class.record));
    }
    let identity = ContentDigest::sha256(&e.finish());
    let mut objects = BTreeMap::new();
    insert(&mut objects, analysis.to_vec());
    let policy = insert(&mut objects, rule_bytes(rule));
    let sensor_digest = insert(&mut objects, sensor.as_str().as_bytes().to_vec());
    let failure_domain = format!("recorded-sensor:{}", hex(sensor_digest));
    let mut children = BTreeSet::from([import_root]);
    let mut evidence = Vec::new();
    for observation in &pending.observations {
        let digest = insert(&mut objects, observation.bytes.clone());
        children.insert(observation.frame.capsule_digest);
        evidence.push(EventEvidence {
            digest,
            class: EvidenceClass::Derived,
            failure_domain: failure_domain.clone(),
            supports: false,
            relation: EvidenceEdgeRelation::DerivedFrom,
            capsule_digest: Some(observation.frame.capsule_digest),
            identity_digest: Some(sensor_digest),
        });
    }
    for class in &pending.classes {
        let digest = insert(&mut objects, class.record.clone());
        let observation = pending
            .observations
            .iter()
            .find(|o| o.frame.segment == class.segment)
            .ok_or(WatchError::Conflict)?;
        let supports = class.supports();
        evidence.push(EventEvidence {
            digest,
            class: EvidenceClass::Derived,
            failure_domain: failure_domain.clone(),
            supports,
            relation: if supports {
                EvidenceEdgeRelation::Supports
            } else {
                EvidenceEdgeRelation::DerivedFrom
            },
            capsule_digest: Some(observation.frame.capsule_digest),
            identity_digest: Some(sensor_digest),
        });
    }
    if let Some(mask) = privacy.policy() {
        let digest = insert(&mut objects, mask.to_bytes());
        evidence.push(EventEvidence {
            digest,
            class: EvidenceClass::Assertion,
            failure_domain,
            supports: false,
            relation: EvidenceEdgeRelation::RequiredBy,
            capsule_digest: None,
            identity_digest: Some(sensor_digest),
        });
    }
    children.extend(objects.keys().copied());
    let slot = SlotName::parse(&format!("rdw-{}", hex(identity)))
        .map_err(|_| WatchError::InvalidPlan("dwell slot identity"))?;
    let manifest = ObjectManifest::new(slot.as_str(), children, None)?;
    evidence.sort_by_key(|item| item.digest);
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(),
        event_id: EventId::parse(format!("event:dwell:{}", hex(identity)))?,
        revision: 1, supersedes: None, state: EventState::Indeterminate, kind: EventKind::Unclassified,
        interval, uncertainty_reason: Some(UNCERTAINTY.to_owned()),
        zone_ids: vec![pending.zone.clone()], track_ids: vec![format!("track:{}", pending.track)],
        probability: ProbabilityInterval::new(0.0, 1.0)?, evidence, model_receipts: Vec::new(),
        decision_path: DecisionPath {
            policy_generation: policy, fingerprint: manifest.root(), abstained: true,
            abstention_reason: Some("Sampled dwell is an uncalibrated single-sensor hypothesis. Retain and investigate; no continuous presence, absence, person, intent or alert conclusion is authorized.".to_owned()),
        },
    };
    event.validate()?;
    let mut e = CanonicalEncoder::new();
    e.text(APPROVAL_DOMAIN);
    e.digest(event.revision_digest());
    e.digest(manifest.root());
    let approval = ContentDigest::sha256(&e.finish());
    let status = status(deployment, &event)?;
    Ok(DwellCandidate {
        zone: pending.zone,
        track: pending.track,
        span: pending.span,
        first_segment,
        trigger_segment: pending.trigger_segment,
        last_segment,
        observations: pending.observations,
        classes: pending.classes,
        identity,
        event,
        slot,
        manifest,
        objects,
        approval,
        status,
    })
}
fn status(deployment: &ReferenceDeployment, event: &EventHypothesis) -> Result<WatchStatus> {
    let object = ObjectId::parse(format!("object:event:{}", event.event_id.as_str()))?;
    if !deployment.ledger().current().objects.contains_key(&object) {
        return Ok(WatchStatus::Prepared);
    }
    let (current, _) = deployment.current_event_authority(&event.event_id)?;
    if current.revision_digest() == event.revision_digest() {
        Ok(WatchStatus::AlreadyPublished)
    } else {
        Err(WatchError::Conflict)
    }
}

#[cfg(test)]
mod tests;
