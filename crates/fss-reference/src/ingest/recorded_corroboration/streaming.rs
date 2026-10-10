#![forbid(unsafe_code)]
//! Whole-recording two-camera ground-zone association over the native streaming tracker.
//!
//! The media walker is shared with long watch/dwell. Every confirmed, actually matched sample
//! is projected, so a track can first appear outside the owner's ground zone and reach it much
//! later without an artificial 128-frame restart. Gaps reset perception and track identity;
//! uncertain source timing remains diagnostic and cannot enter the interval assignment.
//!
//! The first eligible sample per source-track/zone is an observation, not proof of a physical
//! arrival. Owner homographies and capture hints remain assertions. The existing interval
//! assignment and common-cause policy own corroboration; no trained model, absence certificate,
//! or alert effect is introduced. Both complete source traces and current privacy generations
//! are prerequisites of every exact approval, including retries after event publication.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use fss_core::{
    CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest, EventEvidence,
    EvidenceClass, EvidenceEdgeRelation, LedgerAnchor,
};
use fss_object::ObjectManifest;
use fss_publication::SlotName;

use super::{
    CameraSummary, CandidateContext, CandidateEncoding, CandidateSupplement,
    CorroborationCandidate, CorroborationDependencies, CorroborationDependencyReport,
    CorroborationError, CorroborationOptions, CorroborationPlan, CorroborationStatus,
    EntryDisposition, GroundEntry, Result, associate_entries, checkpoint, current_status, hex,
    json_number, json_string, prepare_candidate_with_encoding, publish_candidates, union,
};
use crate::ingest::RetainedFileImport;
use crate::ingest::long_dwell::{
    LongDwellHealthSummary, LongDwellLimits, MAX_LONG_DWELL_FRAMES, ScanData, ScanObservation,
    ScanObserver, publish_manifest, run_observed_scan, slot,
};
use crate::ingest::privacy_mask::coverage::ground_zone_masked;
use crate::ingest::recorded_decode::{RecordedDecodeError, source_capsule};
use crate::ingest::recorded_watch::{
    SourcePublicationGuard, WatchError, WatchOptions, WatchPlan, WatchZone,
};
use crate::ingest::sensor_health::{
    policy_bytes as health_policy_bytes, policy_digest as health_policy_digest,
};
use crate::ingest::tracker::TrackStatus;
use crate::{ReferenceDeployment, ReferenceError, ReferencePolicyAction, ReplayCx};

/// Source-byte, pixel, assignment and trace ceilings, independently spent once per camera.
pub type LongCorroborationLimits = LongDwellLimits;
/// Maximum source segments per camera; no short-watch window limit applies.
pub const MAX_LONG_CORROBORATION_FRAMES: usize = MAX_LONG_DWELL_FRAMES;
/// Complete entry inventory per camera, fitting the bounded global association owner.
pub const MAX_LONG_CORROBORATION_ENTRIES_PER_CAMERA: usize = 64;
/// At most one selected pair per entry; excess is refused rather than omitted.
pub const MAX_LONG_CORROBORATION_CANDIDATES: usize = 64;
/// Versioned report schema, distinct from the historical short-watch composition.
pub const LONG_CORROBORATION_REPORT_SCHEMA: &str = "fss.long_corroboration_report.v1";
/// Cancellation boundary after provenance retention and before event authority.
pub const STAGE_LONG_CORROBORATION_COMMIT: &str = "long_corroboration:commit";
/// A health finding or incomplete scan blocks publication without asserting sensor tampering.
pub const HEALTH_PUBLICATION_BLOCKED: &str =
    "sensor-health findings or incomplete screening block long-corroboration publication";

mod recipe;
pub use recipe::{LongCorroborationRecipe, MAX_LONG_CORROBORATION_RECIPE_BYTES};

const MAX_REPORT_BYTES: usize = 1024 * 1024;
const PLAN_DOMAIN: &str = "fss.long_corroboration_plan.v1";
pub(crate) const CAMERA_DOMAIN: &str = "fss.long_corroboration_camera.v1";
const ANALYSIS_DOMAIN: &str = "fss.long_corroboration_analysis.v1";
const OBSERVATION_DOMAIN: &str = "fss.long_corroboration_observation.v1";
pub(crate) const POLICY: &[u8] = b"fss.long-corroboration.policy.v1:native-display-order-luma:\
masked-before-perception:whole-recording-running-variance-and-kalman-global-iou:\
confirmed-actual-samples:first-ground-zone-sample-per-source-track-and-epoch:\
rounded-foot-point:owner-homography:ground-zone-mask-preimage-exclusion:\
operator-capture-hints:reset-background-and-tracker-on-gap:per-camera-whole-range-budgets:\
global-interval-assignment:worst-case-time-and-distance-gates:common-cause-components:\
source-closed-exact-approval:unclassified:no-physical-arrival:no-absence:no-alert-effect";
const UNCERTAINTY: &str = "Two confirmed foreground tracks were observed in one ground zone under owner homographies and capture-time hints. This does not prove physical arrival, class, identity, intent, calibrated independence or absence.";
const SHARED_UNCERTAINTY: &str = "Two confirmed foreground tracks were observed in one ground zone under owner homographies and time hints. Shared common causes withhold independent corroboration. This does not prove physical arrival, class, identity, intent or absence.";
const _: () = assert!(UNCERTAINTY.len() <= fss_core::event::MAX_UNCERTAINTY_REASON_LEN);
const _: () = assert!(SHARED_UNCERTAINTY.len() <= fss_core::event::MAX_UNCERTAINTY_REASON_LEN);
const ENCODING: CandidateEncoding = CandidateEncoding {
    policy: POLICY,
    association_domain: "fss.long_corroboration_association.v1",
    proposal_domain: "fss.long_corroboration_proposal.v1",
    metadata_magic: b"FSSLCRR1",
    event_prefix: "event:long-corroborated",
    slot_prefix: "lc",
    uncertainty: UNCERTAINTY,
    shared_uncertainty: SHARED_UNCERTAINTY,
};

/// Source-local coordinates of one eligible sample; track keys never survive a recovery epoch.
#[derive(Clone, Debug)]
pub struct LongGroundSample {
    /// Absolute display-order position, distinct from a codec's coding segment.
    pub entry_position: usize,
    /// Tracker-local identifier; meaningful only inside the stated recovery epoch.
    pub local_track_id: u64,
    /// Foreground/tracker restart generation.
    pub tracker_epoch: u64,
    /// Digest of the privacy-masked native luma that produced this actual match.
    pub luma_digest: ContentDigest,
}

#[derive(Debug)]
struct CameraScan {
    summary: CameraSummary,
    publication_guard: SourcePublicationGuard,
    analysis: Vec<u8>,
    manifest: ObjectManifest,
    slot: SlotName,
    source_bytes: u64,
    pixel_samples: u64,
    assignment_work: u64,
    jpeg_work: u64,
    trace_bytes: usize,
    unreliable: usize,
    restarts: usize,
    masked_zones: BTreeSet<usize>,
    health: Option<LongDwellHealthSummary>,
}

/// Complete bounded analysis. Publication mutates only the exact candidate statuses.
#[derive(Debug)]
pub struct LongCorroborationReport {
    plan: CorroborationPlan,
    options: CorroborationOptions,
    limits: LongCorroborationLimits,
    plan_digest: ContentDigest,
    recipe: Vec<u8>,
    analysis_digest: ContentDigest,
    root: PathBuf,
    site: String,
    principal: String,
    basis: LedgerAnchor,
    cameras: Vec<CameraScan>,
    entries: Vec<GroundEntry>,
    samples: Vec<LongGroundSample>,
    candidates: Vec<CorroborationCandidate>,
    dependencies: CorroborationDependencyReport,
}

#[derive(Debug)]
struct RawEntry {
    track_id: u64,
    zone: usize,
    segment: usize,
    capture: CaptureInterval,
    capsule_digest: ContentDigest,
    track_box: [i64; 4],
    ground: (f64, f64),
    reliable: bool,
    sample: LongGroundSample,
}

struct GroundConsumer<'a> {
    plan: &'a CorroborationPlan,
    camera: usize,
    epoch: u64,
    initialized: bool,
    active: BTreeMap<u64, u64>,
    next_track_key: u64,
    seen: BTreeSet<(u64, usize)>,
    masked: BTreeSet<usize>,
    entries: Vec<RawEntry>,
    capture_span: Option<CaptureInterval>,
    dimensions: [u32; 2],
    restart_segments: Vec<usize>,
    error: Option<CorroborationError>,
}
impl<'a> GroundConsumer<'a> {
    fn new(plan: &'a CorroborationPlan, camera: usize) -> Self {
        Self {
            plan,
            camera,
            epoch: 0,
            initialized: false,
            active: BTreeMap::new(),
            next_track_key: 0,
            seen: BTreeSet::new(),
            masked: BTreeSet::new(),
            entries: Vec::new(),
            capture_span: None,
            dimensions: [0, 0],
            restart_segments: Vec::new(),
            error: None,
        }
    }

    fn consume(&mut self, frame: ScanObservation<'_>) -> Result<()> {
        let camera = &self.plan.cameras[self.camera];
        if !self.initialized {
            self.initialized = true;
            self.dimensions = frame.dimensions;
            if let Some(policy) = frame.privacy.policy() {
                self.masked = self
                    .plan
                    .zones
                    .iter()
                    .enumerate()
                    .filter_map(|(index, zone)| {
                        ground_zone_masked(
                            policy,
                            camera.homography.matrix,
                            [zone.x, zone.y, zone.width, zone.height],
                        )
                        .then_some(index)
                    })
                    .collect();
            }
        }
        if self.epoch != frame.epoch {
            self.active.clear();
            self.epoch = frame.epoch;
            self.restart_segments.push(frame.segment);
        }
        self.capture_span = Some(match self.capture_span {
            Some(previous) => union(previous, frame.capsule.capture)?,
            None => frame.capsule.capture,
        });
        // Only current tracks occupy state. Retired identities remain in the bounded entry
        // inventory; they cannot be reused even when a decoder recovery resets local IDs.
        self.active
            .retain(|local, _| frame.tracks.iter().any(|track| track.id == *local));
        for target in frame.tracks {
            if target.status != TrackStatus::Confirmed || target.misses != 0 {
                continue;
            }
            let key = match self.active.get(&target.id) {
                Some(key) => *key,
                None => {
                    let key = self.next_track_key;
                    self.next_track_key = key.checked_add(1).ok_or(CorroborationError::Limit)?;
                    self.active.insert(target.id, key);
                    key
                }
            };
            let track_box =
                [target.cx, target.cy, target.box_w, target.box_h].map(|v| v.round() as i64);
            let ground = camera
                .homography
                .project(
                    track_box[0] as f64,
                    track_box[1] as f64 + track_box[3] as f64 / 2.0,
                )
                .ok_or_else(|| CorroborationError::InvalidHomography {
                    camera: camera.name.clone(),
                    reason: "confirmed foot point maps beyond the ground horizon",
                })?;
            for (zone_index, zone) in self.plan.zones.iter().enumerate() {
                if self.masked.contains(&zone_index)
                    || !zone.contains(ground.0, ground.1)
                    || self.seen.contains(&(key, zone_index))
                {
                    continue;
                }
                if self.entries.len() == MAX_LONG_CORROBORATION_ENTRIES_PER_CAMERA {
                    return Err(CorroborationError::Limit);
                }
                self.seen.insert((key, zone_index));
                self.entries.push(RawEntry {
                    track_id: key,
                    zone: zone_index,
                    segment: frame.segment,
                    capture: frame.capsule.capture,
                    capsule_digest: frame.capsule_digest,
                    track_box,
                    ground,
                    reliable: frame.time_reliable,
                    sample: LongGroundSample {
                        entry_position: frame.position,
                        local_track_id: target.id,
                        tracker_epoch: frame.epoch,
                        luma_digest: frame.luma_digest,
                    },
                });
            }
        }
        Ok(())
    }
}
impl ScanObserver for GroundConsumer<'_> {
    fn observe(&mut self, frame: ScanObservation<'_>) -> std::result::Result<(), WatchError> {
        if let Err(error) = self.consume(frame) {
            self.error = Some(error);
            return Err(WatchError::InvalidPlan(
                "streaming ground-zone observer refused",
            ));
        }
        Ok(())
    }
}

impl LongCorroborationReport {
    /// Analyze two complete retained recordings with independent per-camera aggregate ceilings.
    pub fn analyze(
        deployment: &ReferenceDeployment,
        plan: &CorroborationPlan,
        options: CorroborationOptions,
        limits: &LongCorroborationLimits,
        dependencies: &CorroborationDependencies,
        cx: &ReplayCx,
    ) -> Result<Self> {
        Self::analyze_inner(deployment, plan, options, limits, dependencies, cx, false)
    }

    /// Screen each entire native scan; any finding or missing evidence blocks all publication.
    pub fn analyze_screened(
        deployment: &ReferenceDeployment,
        plan: &CorroborationPlan,
        options: CorroborationOptions,
        limits: &LongCorroborationLimits,
        dependencies: &CorroborationDependencies,
        cx: &ReplayCx,
    ) -> Result<Self> {
        Self::analyze_inner(deployment, plan, options, limits, dependencies, cx, true)
    }

    #[allow(clippy::too_many_arguments)]
    fn analyze_inner(
        deployment: &ReferenceDeployment,
        plan: &CorroborationPlan,
        options: CorroborationOptions,
        limits: &LongCorroborationLimits,
        declarations: &CorroborationDependencies,
        cx: &ReplayCx,
        screened: bool,
    ) -> Result<Self> {
        checkpoint(cx, "long_corroboration:analyze")?;
        plan.validate()?;
        declarations.validate_for(plan)?;
        limits.validate()?;
        if cx.root_dir() != deployment.root() {
            return Err(CorroborationError::Conflict);
        }
        deployment
            .ledger()
            .verify_durable_head()
            .map_err(ReferenceError::from)?;
        // Preflight BOTH recordings before either native decoder spends its work allowance.
        let mut counts = [0; 2];
        let mut sensors = Vec::with_capacity(2);
        for (index, camera) in plan.cameras.iter().enumerate() {
            let retained = RetainedFileImport::open(
                deployment,
                camera.import_identity,
                limits.decode.read_limits,
                cx,
            )?;
            if retained.manifest().capture_time_label != "operator_assumption" {
                return Err(CorroborationError::TimeUnknown {
                    camera: camera.name.clone(),
                });
            }
            counts[index] = retained.manifest().segment_spans.len();
            if !(1..=MAX_LONG_CORROBORATION_FRAMES).contains(&counts[index]) {
                return Err(CorroborationError::Limit);
            }
            let (capsule, _) = source_capsule(deployment, &retained, 0)?;
            sensors.push(capsule.sensor_id);
        }
        if sensors[0] == sensors[1] {
            return Err(CorroborationError::SameSensor);
        }
        let recipe =
            LongCorroborationRecipe::new(plan, options, limits, declarations, screened)?.to_bytes();
        let plan_digest = ContentDigest::sha256(&recipe);
        let mut cameras = Vec::with_capacity(2);
        let mut entries = Vec::new();
        let mut samples = Vec::new();
        for (index, camera) in plan.cameras.iter().enumerate() {
            checkpoint(cx, "long_corroboration:camera")?;
            // This harmless image rectangle validates the shared perception recipe. The
            // observer consumes every actual tracker sample; only owner GROUND zones select
            // entries. No placeholder image-zone entry or coverage claim is used.
            let watch = WatchPlan {
                import_identity: camera.import_identity,
                interpretation: plan.interpretation,
                first_segment: 0,
                segment_count: counts[index],
                zones: vec![WatchZone {
                    zone_id: "ground-observer".to_owned(),
                    x: 0,
                    y: 0,
                    width: 1,
                    height: 1,
                }],
                detector: plan.detector,
                tracker: plan.tracker,
            };
            let mut consumer = GroundConsumer::new(plan, index);
            let scan = run_observed_scan(
                deployment,
                &watch,
                WatchOptions {
                    tolerate_decode_refusals: options.tolerate_decode_refusals,
                },
                limits,
                cx,
                screened,
                &mut consumer,
            );
            if let Some(error) = consumer.error.take() {
                return Err(error);
            }
            let scan = scan?;
            let camera_scan = prepare_camera(
                deployment,
                plan,
                index,
                plan_digest,
                &watch,
                scan,
                &consumer,
            )?;
            for raw in consumer.entries {
                let (entry, sample) = prepare_entry(plan, index, camera_scan.manifest.root(), raw)?;
                entries.push(entry);
                samples.push(sample);
            }
            cameras.push(camera_scan);
        }
        if cameras[0].summary.capture_span.earliest > cameras[1].summary.capture_span.latest
            || cameras[1].summary.capture_span.earliest > cameras[0].summary.capture_span.latest
        {
            return Err(CorroborationError::TimeUnaligned);
        }
        let mut summaries: Vec<_> = cameras.iter().map(|c| c.summary.clone()).collect();
        let dependencies = CorroborationDependencyReport::build(declarations, &summaries)?;
        for (camera, summary) in cameras.iter_mut().zip(&mut summaries) {
            summary.failure_domain = dependencies.support_domain(&summary.name)?.to_owned();
            camera.summary.failure_domain = summary.failure_domain.clone();
        }
        let associated = associate_entries(plan, &mut entries, cx)?;
        if associated.len() > MAX_LONG_CORROBORATION_CANDIDATES {
            return Err(CorroborationError::Limit);
        }
        for association in &associated {
            let [left, right] = association.pair;
            if summaries[entries[left].camera].failure_domain
                == summaries[entries[right].camera].failure_domain
            {
                entries[left].disposition = EntryDisposition::SharedFailureDomain;
                entries[right].disposition = EntryDisposition::SharedFailureDomain;
            }
        }
        let roots: Vec<_> = cameras
            .iter()
            .map(|camera| camera.manifest.root())
            .collect();
        let evidence: Vec<_> = cameras
            .iter()
            .map(|camera| EventEvidence {
                digest: ContentDigest::sha256(&camera.analysis),
                class: EvidenceClass::Derived,
                failure_domain: camera.summary.failure_domain.clone(),
                supports: false,
                relation: EvidenceEdgeRelation::RequiredBy,
                capsule_digest: None,
                identity_digest: Some(camera.summary.sensor_digest),
            })
            .collect();
        let context = CandidateContext {
            deployment,
            plan,
            plan_digest,
            cameras: &summaries,
            entries: &entries,
            cascade: None,
            dependencies: &dependencies,
        };
        let mut candidates = Vec::with_capacity(associated.len());
        for association in associated {
            checkpoint(cx, "long_corroboration:candidate")?;
            candidates.push(prepare_candidate_with_encoding(
                &context,
                association,
                &ENCODING,
                CandidateSupplement {
                    roots: &roots,
                    evidence: &evidence,
                    principal: Some(cx.io_authority().principal()),
                },
            )?);
        }
        let mut encoder = CanonicalEncoder::new();
        encoder.text(ANALYSIS_DOMAIN);
        encoder.digest(plan_digest);
        encoder.digest(dependencies.digest());
        for root in &roots {
            encoder.digest(*root);
        }
        for entry in &entries {
            encoder.digest(entry.record_digest);
            encoder.text(entry.disposition.as_str());
        }
        for candidate in &candidates {
            encoder.digest(candidate.identity());
        }
        let report = Self {
            plan: plan.clone(),
            options,
            limits: *limits,
            plan_digest,
            recipe,
            analysis_digest: ContentDigest::sha256(&encoder.finish_checked()?),
            root: deployment.root().to_path_buf(),
            site: deployment.site_lineage().to_owned(),
            principal: cx.io_authority().principal().to_owned(),
            basis: deployment.current_anchor().clone(),
            cameras,
            entries,
            samples,
            candidates,
            dependencies,
        };
        report.to_json(deployment.current_anchor().commit_sequence, None)?;
        Ok(report)
    }

    /// Complete stable candidate inventory; association scores are ranking values, not probabilities.
    pub fn candidates(&self) -> &[CorroborationCandidate] {
        &self.candidates
    }
    /// Every eligible ground observation, including unpaired, ambiguous and time-unreliable ones.
    /// Here `track_id` is a source-wide key, distinct from the epoch-local ID in [`Self::samples`].
    pub fn entries(&self) -> &[GroundEntry] {
        &self.entries
    }
    /// Display positions and recovery-local identifiers, in the exact order of [`Self::entries`].
    pub fn samples(&self) -> &[LongGroundSample] {
        &self.samples
    }
    /// Retained canonical owner recipe, including the full matrices, zones and decoder budgets.
    pub const fn plan_digest(&self) -> ContentDigest {
        self.plan_digest
    }
    /// Identity of both complete native analyses, associations, gates and declared dependencies.
    pub const fn analysis_digest(&self) -> ContentDigest {
        self.analysis_digest
    }
    /// Complete retained camera identities and actual native work for read-only event replay.
    pub(crate) fn replay_camera_summaries(
        &self,
    ) -> impl Iterator<Item = (ContentDigest, ContentDigest, usize, u64)> + '_ {
        self.cameras.iter().map(|camera| {
            (
                camera.manifest.root(),
                ContentDigest::sha256(&camera.analysis),
                camera.summary.frames,
                camera.source_bytes,
            )
        })
    }
    /// Any requested whole-scan screening finding or incomplete screen blocks both cameras.
    pub fn publication_blocked(&self) -> bool {
        self.cameras.iter().any(|camera| {
            camera
                .health
                .as_ref()
                .is_some_and(LongDwellHealthSummary::publication_blocked)
        })
    }

    /// Publish only exact proposals after both original sources, all analyzed capsules and current
    /// masks have been revalidated. Provenance is retained root-last; an exact retry adds no event.
    pub fn publish(
        &mut self,
        deployment: &mut ReferenceDeployment,
        approvals: &BTreeSet<ContentDigest>,
        cx: &ReplayCx,
    ) -> Result<usize> {
        checkpoint(cx, "long_corroboration:revalidate")?;
        if self.publication_blocked() {
            return Err(CorroborationError::InvalidPlan(HEALTH_PUBLICATION_BLOCKED));
        }
        if deployment.root() != self.root.as_path()
            || cx.root_dir() != deployment.root()
            || deployment.site_lineage() != self.site
            || cx.io_authority().principal() != self.principal
        {
            return Err(CorroborationError::Conflict);
        }
        for approval in approvals {
            if !self
                .candidates
                .iter()
                .any(|candidate| candidate.proposal_digest() == *approval)
            {
                return Err(CorroborationError::StaleApproval(*approval));
            }
        }
        for camera in &self.cameras {
            camera.publication_guard.revalidate(deployment, cx)?;
        }
        for candidate in &mut self.candidates {
            if approvals.contains(&candidate.proposal_digest()) {
                candidate.status = current_status(deployment, candidate.event())?;
            }
        }
        self.to_json(deployment.current_anchor().commit_sequence, None)?;
        let recipe_required = self.candidates.iter().any(|candidate| {
            approvals.contains(&candidate.proposal_digest())
                && candidate.status() == CorroborationStatus::AlreadyPublished
        });
        if recipe_required
            || deployment
                .publisher()
                .spool()
                .state(self.plan_digest)
                .is_some()
        {
            let retained_recipe = deployment.publisher().spool().read(self.plan_digest)?;
            LongCorroborationRecipe::from_retained_bytes(&retained_recipe, self.plan_digest)?;
        }
        if !self.candidates.iter().any(|candidate| {
            approvals.contains(&candidate.proposal_digest())
                && candidate.status() == CorroborationStatus::Prepared
        }) {
            return Ok(0);
        }
        checkpoint(cx, "long_corroboration:stage_recipe")?;
        let recipe_digest = deployment.publisher_mut().stage_object(&self.recipe)?;
        if recipe_digest != self.plan_digest {
            return Err(fss_core::ContractError::DigestMismatch.into());
        }
        deployment.publisher_mut().verify_object(recipe_digest)?;
        for camera in &self.cameras {
            checkpoint(cx, "long_corroboration:stage_camera")?;
            for bytes in [
                camera.analysis.as_slice(),
                POLICY,
                camera.summary.sensor_id.as_bytes(),
            ] {
                let digest = deployment.publisher_mut().stage_object(bytes)?;
                deployment.publisher_mut().verify_object(digest)?;
            }
            if let Some(policy) = camera.summary.privacy.policy() {
                let digest = deployment
                    .publisher_mut()
                    .stage_object(&policy.to_bytes())?;
                deployment.publisher_mut().verify_object(digest)?;
            }
            if camera.health.is_some() {
                let digest = deployment
                    .publisher_mut()
                    .stage_object(health_policy_bytes())?;
                deployment.publisher_mut().verify_object(digest)?;
            }
            publish_manifest(
                deployment,
                &camera.slot,
                &camera.manifest,
                camera.summary.capture_span,
                cx,
            )?;
        }
        publish_candidates(
            deployment,
            &mut self.candidates,
            approvals,
            cx,
            STAGE_LONG_CORROBORATION_COMMIT,
        )
    }

    /// Render a complete bounded report before any publication. No inventory is silently truncated.
    pub fn to_json(&self, authority_sequence: u64, approve_hint: Option<&str>) -> Result<String> {
        if approve_hint.is_some_and(|hint| hint.len() > 8192) {
            return Err(CorroborationError::Limit);
        }
        let approve_hint = if self.publication_blocked() {
            None
        } else {
            approve_hint
        };
        let cameras = self
            .cameras
            .iter()
            .map(|camera| camera_json(camera, &self.plan))
            .collect::<Vec<_>>()
            .join(",");
        let zones = self
            .plan
            .zones
            .iter()
            .map(|zone| {
                format!(
                    "{{\"zone_id\":{},\"x\":{},\"y\":{},\"width\":{},\"height\":{}}}",
                    json_string(&zone.zone_id),
                    json_number(zone.x),
                    json_number(zone.y),
                    json_number(zone.width),
                    json_number(zone.height)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let entries = self.entries.iter().zip(&self.samples).map(|(entry, sample)| {
            format!(concat!("{{\"camera\":{},\"zone_id\":{},\"track_id\":{},\"local_track_id\":{},",
                "\"tracker_epoch\":{},\"entry_position\":{},\"segment\":{},\"capture_ns\":[{},{}],",
                "\"capsule_digest\":\"{}\",\"luma_digest\":\"{}\",\"track_box_cxcywh\":[{},{},{},{}],",
                "\"ground\":[{},{}],\"observation_digest\":\"{}\",\"disposition\":{}}}"),
                json_string(&self.plan.cameras[entry.camera].name), json_string(&entry.zone_id),
                entry.track_id, sample.local_track_id, sample.tracker_epoch, sample.entry_position,
                entry.segment, entry.capture.earliest.0, entry.capture.latest.0, entry.capsule_digest,
                sample.luma_digest, entry.track_box[0], entry.track_box[1], entry.track_box[2],
                entry.track_box[3], json_number(entry.ground.0), json_number(entry.ground.1),
                entry.record_digest, json_string(entry.disposition.as_str()))
        }).collect::<Vec<_>>().join(",");
        let candidates = self.candidates.iter().map(|candidate| {
            let event = candidate.event();
            let command = match (candidate.status(), approve_hint) {
                (CorroborationStatus::Prepared, Some(hint)) => json_string(&format!(
                    "{hint} --approve {}", candidate.proposal_digest())), _ => "null".to_owned(),
            };
            let action = match candidate.policy_action() {
                ReferencePolicyAction::PrepareAlert => "prepare_alert", ReferencePolicyAction::Hold => "hold",
            };
            format!(concat!("{{\"candidate_id\":\"{}\",\"zone_id\":{},\"entries\":[{},{}],",
                "\"worst_case_separation_ns\":{},\"ground_distance\":{},\"association_score\":{},",
                "\"event_id\":{},\"event_kind\":{},\"event_state\":{},\"event_revision_digest\":\"{}\",",
                "\"policy_action\":{},\"proposal_digest\":\"{}\",\"provenance_root\":\"{}\",",
                "\"status\":{},\"publish_command\":{},\"alert_prepared\":false}}"),
                candidate.identity(), json_string(&candidate.zone_id), candidate.entries[0], candidate.entries[1],
                candidate.worst_case_separation_ns, json_number(candidate.distance), json_number(candidate.association_score),
                json_string(event.event_id.as_str()), json_string(event.kind.as_str()), json_string(event.state.as_str()),
                event.revision_digest(), json_string(action), candidate.proposal_digest(), candidate.provenance_root(),
                json_string(candidate.status().as_str()), command)
        }).collect::<Vec<_>>().join(",");
        let count = |status| {
            self.candidates
                .iter()
                .filter(|candidate| candidate.status() == status)
                .count()
        };
        let text = format!(
            concat!(
                "{{\"format\":{},\"site\":{},\"principal\":{},\"plan_digest\":\"{}\",",
                "\"analysis_digest\":\"{}\",\"policy_digest\":\"{}\",\"analysis_basis_sequence\":{},",
                "\"analysis_basis_root\":\"{}\",\"authority_sequence\":{},\"cameras\":[{}],\"zones\":[{}],",
                "\"time_gate_ns\":{},\"distance_gate\":{},\"time_semantics\":\"operator_capture_hints_worst_case_interval_gate\",",
                "\"entry_count\":{},\"entries\":[{}],\"candidate_count\":{},\"candidates\":[{}],",
                "\"prepared_count\":{},\"published_count\":{},\"already_published_count\":{},\"dependencies\":{},",
                "\"publication_blocked\":{},\"tolerate_decode_refusals\":{},\"per_camera_source_byte_budget\":{},",
                "\"per_camera_pixel_sample_budget\":{},\"per_camera_assignment_work_budget\":{},",
                "\"per_camera_trace_byte_budget\":{},\"per_camera_jpeg_work_budget\":{},",
                "\"model_invoked\":false,\"calibrated\":false,\"physical_arrival_proved\":false,",
                "\"absence_certifiable\":false,\"alert_authorized\":false,\"alert_prepared\":false,",
                "\"effects_authorized\":false,\"detection_quality_claim\":false,\"qualification\":\"implemented_not_qualified\"}}"
            ),
            json_string(LONG_CORROBORATION_REPORT_SCHEMA),
            json_string(&self.site),
            json_string(&self.principal),
            self.plan_digest,
            self.analysis_digest,
            ContentDigest::sha256(POLICY),
            self.basis.commit_sequence,
            self.basis.state_root,
            authority_sequence,
            cameras,
            zones,
            self.plan.gates.time_gate_ns,
            json_number(self.plan.gates.distance_gate),
            self.entries.len(),
            entries,
            self.candidates.len(),
            candidates,
            count(CorroborationStatus::Prepared),
            count(CorroborationStatus::Published),
            count(CorroborationStatus::AlreadyPublished),
            self.dependencies.to_json(),
            self.publication_blocked(),
            self.options.tolerate_decode_refusals,
            self.limits.maximum_source_chunk_bytes,
            self.limits.maximum_pixel_samples,
            self.limits.maximum_assignment_work,
            self.limits.maximum_trace_bytes,
            self.limits.decode.jpeg_work_units
        );
        if text.len() > MAX_REPORT_BYTES {
            return Err(CorroborationError::Limit);
        }
        Ok(text)
    }
}

fn prepare_camera(
    deployment: &ReferenceDeployment,
    plan: &CorroborationPlan,
    index: usize,
    plan_digest: ContentDigest,
    watch: &WatchPlan,
    scan: ScanData,
    consumer: &GroundConsumer<'_>,
) -> Result<CameraScan> {
    let camera = &plan.cameras[index];
    let mut encoder = CanonicalEncoder::new();
    encoder.text(CAMERA_DOMAIN);
    encoder.digest(ContentDigest::sha256(POLICY));
    encoder.text(deployment.site_lineage());
    encoder.digest(plan_digest);
    encoder.text(&camera.name);
    encoder.digest(camera.import_identity);
    encoder.digest(scan.import_root);
    encoder.digest(scan.manifest_digest);
    scan.import_anchor.encode_canonical(&mut encoder);
    encoder.text(scan.sensor.as_str());
    encoder.text(&scan.media_format);
    encoder.digest(watch.digest());
    encoder.digest(camera.homography.digest());
    encoder.digest(scan.privacy.digest());
    match scan.privacy.generation() {
        Some(generation) => {
            encoder.bool(true);
            encoder.u64(generation);
        }
        None => encoder.bool(false),
    }
    encoder.u64(consumer.masked.len() as u64);
    for zone in &consumer.masked {
        encoder.text(&plan.zones[*zone].zone_id);
    }
    encoder.bytes(&scan.trace);
    if let Some(summary) = &scan.health {
        encoder.text("sensor_health");
        encoder.bytes(health_policy_bytes());
        summary.encode(&mut encoder);
    }
    let analysis = encoder.finish_checked()?;
    let digest = ContentDigest::sha256(&analysis);
    let sensor_digest = ContentDigest::sha256(scan.sensor.as_str().as_bytes());
    let mut children = BTreeSet::from([
        scan.import_root,
        plan_digest,
        digest,
        ContentDigest::sha256(POLICY),
        sensor_digest,
    ]);
    if let Some(policy) = scan.privacy.policy() {
        children.insert(policy.digest());
    }
    if scan.health.is_some() {
        children.insert(health_policy_digest());
    }
    let slot = slot("lc-a", digest)?;
    // The analysis is already an explicit child. Supplying it as metadata too would
    // duplicate the same custody edge under ObjectManifest's disjoint-role contract.
    let manifest = ObjectManifest::new("recorded-long-corroboration-camera-v1", children, None)?;
    let summary = CameraSummary {
        name: camera.name.clone(),
        import_identity: camera.import_identity,
        import_root: scan.import_root,
        sensor_id: scan.sensor.as_str().to_owned(),
        failure_domain: format!("recorded-sensor:{}", hex(sensor_digest)),
        watch_plan_digest: plan_digest,
        watch_analysis_digest: digest,
        frames: scan.decoded,
        confirmed_tracks: usize::try_from(consumer.next_track_key)
            .map_err(|_| CorroborationError::Limit)?,
        capture_span: consumer
            .capture_span
            .ok_or(RecordedDecodeError::Unavailable)?,
        homography_digest: camera.homography.digest(),
        decode_refusals: scan.refusals,
        tracking_restarts: consumer.restart_segments.clone(),
        sensor_health: None,
        sensor_digest,
        // These private compatibility fields are not used to construct streaming coverage.
        coverage_frames: Vec::new(),
        segment_gaps: Vec::new(),
        dimensions: consumer.dimensions,
        media_format: scan.media_format,
        privacy: scan.privacy,
    };
    Ok(CameraScan {
        summary,
        publication_guard: scan.publication_guard,
        analysis,
        manifest,
        slot,
        source_bytes: scan.source_bytes,
        pixel_samples: scan.pixel_samples,
        assignment_work: scan.assignment_work,
        jpeg_work: scan.jpeg_work,
        trace_bytes: scan.trace.len(),
        unreliable: scan.unreliable,
        restarts: scan.restarts,
        masked_zones: consumer.masked.clone(),
        health: scan.health,
    })
}

fn prepare_entry(
    plan: &CorroborationPlan,
    camera: usize,
    camera_root: ContentDigest,
    raw: RawEntry,
) -> Result<(GroundEntry, LongGroundSample)> {
    let zone_id = plan.zones[raw.zone].zone_id.clone();
    let mut encoder = CanonicalEncoder::new();
    encoder.text(OBSERVATION_DOMAIN);
    encoder.digest(camera_root);
    encoder.text(&plan.cameras[camera].name);
    encoder.digest(plan.cameras[camera].homography.digest());
    encoder.text(&zone_id);
    encoder.u64(raw.track_id);
    encoder.u64(raw.sample.local_track_id);
    encoder.u64(raw.sample.tracker_epoch);
    encoder.u64(raw.sample.entry_position as u64);
    encoder.u64(raw.segment as u64);
    encoder.digest(raw.capsule_digest);
    encoder.digest(raw.sample.luma_digest);
    raw.capture.encode_canonical(&mut encoder);
    encoder.bool(raw.reliable);
    for value in raw.track_box {
        encoder.i128(i128::from(value));
    }
    encoder.u64(raw.ground.0.to_bits());
    encoder.u64(raw.ground.1.to_bits());
    let record = encoder.finish_checked()?;
    let entry = GroundEntry {
        camera,
        zone_id,
        track_id: raw.track_id,
        segment: raw.segment,
        capture: raw.capture,
        capsule_digest: raw.capsule_digest,
        track_box: raw.track_box,
        ground: raw.ground,
        record_digest: ContentDigest::sha256(&record),
        disposition: if raw.reliable {
            EntryDisposition::NoCounterpartEntry
        } else {
            EntryDisposition::CaptureTimeUnreliableAfterGap
        },
        class_evidence: Vec::new(),
        record,
    };
    Ok((entry, raw.sample))
}

fn camera_json(camera: &CameraScan, plan: &CorroborationPlan) -> String {
    let summary = &camera.summary;
    let refusals = summary
        .decode_refusals
        .iter()
        .map(|refusal| {
            format!(
                "{{\"first_segment\":{},\"last_segment\":{},\"error_id\":{}}}",
                refusal.first_segment,
                refusal.last_segment,
                json_string(&refusal.error_id)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let masked = camera
        .masked_zones
        .iter()
        .map(|zone| json_string(&plan.zones[*zone].zone_id))
        .collect::<Vec<_>>()
        .join(",");
    let restarts = summary
        .tracking_restarts
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let health = camera
        .health
        .as_ref()
        .map_or_else(|| "null".to_owned(), LongDwellHealthSummary::to_json);
    format!(
        concat!(
            "{{\"camera\":{},\"import_identity\":\"{}\",\"import_root\":\"{}\",",
            "\"sensor_id\":{},\"failure_domain\":{},\"frames_decoded\":{},\"confirmed_tracks\":{},",
            "\"capture_span_ns\":[{},{}],\"capture_time_label\":\"operator_assumption\",",
            "\"analysis_digest\":\"{}\",\"analysis_root\":\"{}\",\"ground_homography_digest\":\"{}\",",
            "\"ground_homography\":\"owner_supplied_not_a_calibration_certificate\",",
            "\"unreliable_time_frames\":{},\"tracking_restarts\":{},\"tracking_restart_segments\":[{}],",
            "\"decode_refusals\":[{}],\"masked_zones\":[{}],\"privacy_binding\":\"{}\",",
            "\"privacy_generation\":{},\"source_chunk_bytes_read\":{},\"pixel_samples_processed\":{},",
            "\"assignment_work_admitted\":{},\"jpeg_work_units\":{},\"trace_record_bytes\":{},",
            "\"media_format\":{},\"sensor_health\":{}}}"
        ),
        json_string(&summary.name),
        summary.import_identity,
        summary.import_root,
        json_string(&summary.sensor_id),
        json_string(&summary.failure_domain),
        summary.frames,
        summary.confirmed_tracks,
        summary.capture_span.earliest.0,
        summary.capture_span.latest.0,
        summary.watch_analysis_digest,
        camera.manifest.root(),
        summary.homography_digest,
        camera.unreliable,
        camera.restarts,
        restarts,
        refusals,
        masked,
        summary.privacy.digest(),
        summary
            .privacy
            .generation()
            .map_or_else(|| "null".to_owned(), |value| value.to_string()),
        camera.source_bytes,
        camera.pixel_samples,
        camera.assignment_work,
        camera.jpeg_work,
        camera.trace_bytes,
        json_string(&summary.media_format),
        health
    )
}
