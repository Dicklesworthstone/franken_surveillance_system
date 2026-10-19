#![forbid(unsafe_code)]
//! Source-closed inspection and native replay of the retained sampled-dwell profile.
//!
//! The historical model-free analysis retains semantic settings but no execution ceilings.
//! Trained profiles retain the complete native decoder and model recipe. Metadata inspection
//! checks exact source, privacy and episode bindings; only native replay proves the measurements.

use super::watch::{RetainedDetector, count, digest, health, read_plan};
use super::{
    LoadedProfile, LongDwellLimits, LongEventReplayError as Error, LongEventReplayLimits,
    LongEventReplayRecipe, MAX_LONG_DWELL_FRAMES, MAX_LONG_DWELL_TRACE_BYTES,
    MAX_LONG_EVENT_ANALYSIS_BYTES, MAX_MANIFEST_BYTES, MetadataReader, Result, SourceBinding,
    checkpoint, hex, manifest, published_root, slot,
};
use crate::ingest::RetainedFileImport;
use crate::ingest::long_dwell::{
    ANALYSIS_DOMAIN, EPISODE_DOMAIN, LongDwellDetector, LongDwellReport, POLICY, POLICY_INTER,
    detector::SELECTION_POLICY,
};
use crate::ingest::long_watch::detector::{
    LongWatchDetectorRecipe, MAX_OUTCOME_BYTES, retained_inventory,
};
use crate::ingest::privacy_mask::current_mask;
use crate::ingest::recorded_decode::RecordedDecodeError;
use crate::ingest::recorded_watch::{WatchOptions, WatchPlan};
use crate::ingest::rgb_package::{MAX_RGB_PACKAGE_BYTES, RgbDetectorPackage};
use crate::ingest::sensor_health::{policy_bytes, policy_digest};
use crate::ingest::zone_dwell::{DwellPolicy, MAX_DWELL_EPISODES};
use crate::{ReferenceDeployment, ReplayCx, ScalarExecCx};
use fss_core::{
    CanonicalDecode, CanonicalDecoder, CaptureInterval, ContentDigest, EventHypothesis, EventState,
    EvidenceClass, EvidenceEdgeRelation, LedgerAnchor, SensorId,
};
use std::collections::{BTreeMap, BTreeSet};

/// Original semantic dwell settings and current ceilings, or a complete retained trained recipe.
#[derive(Clone, Debug)]
pub struct DwellReplayRecipe {
    plan: WatchPlan,
    rule: DwellPolicy,
    options: WatchOptions,
    limits: LongDwellLimits,
    source: SourceBinding,
    screened: bool,
    detector: Option<RetainedDetector>,
}
impl DwellReplayRecipe {
    /// Original source range, image zones, foreground and tracker settings.
    pub fn plan(&self) -> &WatchPlan {
        &self.plan
    }
    /// Exact sampled occupancy duration, gap and observation-count rule.
    pub const fn rule(&self) -> DwellPolicy {
        self.rule
    }
    /// Original refusal and recovery behavior.
    pub const fn options(&self) -> WatchOptions {
        self.options
    }
    /// Original complete ceilings for trained runs; current caller ceilings for model-free v1.
    pub const fn limits(&self) -> &LongDwellLimits {
        &self.limits
    }
    /// Whether the original whole-recording visual screening policy was selected.
    pub const fn screened(&self) -> bool {
        self.screened
    }
    /// Actual retained native source format, including display-ordered AVC and HEVC containers.
    pub fn media_format(&self) -> &str {
        &self.source.media_format
    }
    /// Sensor whose exact current privacy generation must match the retained analysis.
    pub fn sensor(&self) -> &SensorId {
        &self.source.sensor
    }
    /// Historical model-free dwell records did not save their source or codec reservations.
    pub const fn complete_codec_limits_retained(&self) -> bool {
        self.detector.is_some()
    }
    /// Exact retained model, execution backend, thresholds and whole-recording reservations.
    pub fn detector_recipe(&self) -> Option<&LongWatchDetectorRecipe> {
        self.detector.as_ref().map(|value| &value.recipe)
    }

    pub(super) fn analyze(
        &self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<LongDwellReport> {
        let Some(retained) = &self.detector else {
            return Ok(if self.screened {
                LongDwellReport::analyze_screened(
                    deployment,
                    &self.plan,
                    self.rule,
                    self.options,
                    &self.limits,
                    cx,
                )?
            } else {
                LongDwellReport::analyze(
                    deployment,
                    &self.plan,
                    self.rule,
                    self.options,
                    &self.limits,
                    cx,
                )?
            });
        };
        checkpoint(cx, "long_event_replay:model_admission")?;
        let scalar = ScalarExecCx::new();
        let result = (|| {
            let recipe = &retained.recipe;
            let package = RgbDetectorPackage::load_with_backend(
                &retained.archive,
                recipe.package_digest(),
                recipe.import_work_units(),
                recipe.backend(),
                cx,
                &scalar,
            )
            .map_err(|_| Error::UnsupportedProfile)?;
            recipe.verify_package(&package)?;
            let detector = LongDwellDetector::new(
                &package,
                &retained.archive,
                recipe.config(),
                *recipe.package_limits(),
                &scalar,
            )?;
            Ok(LongDwellReport::analyze_with_detector(
                deployment,
                &self.plan,
                self.rule,
                self.options,
                &self.limits,
                &detector,
                self.screened,
                cx,
            )?)
        })();
        scalar.drain_and_finalize();
        checkpoint(cx, "long_event_replay:model_complete")?;
        result
    }
}

#[derive(Clone, Copy)]
struct FrameBinding {
    segment: usize,
    capsule: ContentDigest,
    capture: CaptureInterval,
    epoch: u64,
    reliable: bool,
}

fn trace(
    bytes: &[u8],
    plan: &WatchPlan,
    inter: bool,
    limits: &LongDwellLimits,
    cx: &ReplayCx,
) -> Result<BTreeMap<usize, FrameBinding>> {
    if bytes.is_empty()
        || bytes.len() > limits.maximum_trace_bytes
        || bytes.len() > MAX_LONG_DWELL_TRACE_BYTES
    {
        return Err(Error::Limit);
    }
    let end = plan
        .first_segment
        .checked_add(plan.segment_count)
        .ok_or(Error::Limit)?;
    // Explicit decoder breaks can advance display position without adding a source capsule.
    // Bind positions to the bounded trace; never substitute a coding segment for a B picture.
    let position_end = plan
        .first_segment
        .checked_add(plan.segment_count.saturating_mul(2).saturating_add(256))
        .ok_or(Error::Limit)?;
    let mut records = CanonicalDecoder::new(bytes);
    let mut frames = BTreeMap::new();
    let mut record_count = 0_usize;
    let mut last_position = None;
    while records.remaining() != 0 {
        checkpoint(cx, "long_event_replay:trace_record")?;
        let record = records.bytes()?;
        record_count = record_count.checked_add(1).ok_or(Error::Limit)?;
        if record.is_empty()
            || record.len() > 32 * 1024
            || record_count > plan.segment_count.saturating_mul(2).saturating_add(256)
        {
            return Err(Error::Limit);
        }
        let mut probe = CanonicalDecoder::new(record);
        if probe.text()? != "fss.long_dwell_frame.v1" {
            return Err(Error::UnsupportedProfile);
        }
        if inter && probe.text().ok() == Some("break") {
            continue;
        }
        let mut d = CanonicalDecoder::new(record);
        let _domain = d.text()?;
        let position = usize::try_from(d.u64()?).map_err(|_| Error::Limit)?;
        let segment = if inter {
            usize::try_from(d.u64()?).map_err(|_| Error::Limit)?
        } else {
            position
        };
        let capsule = digest(&mut d)?;
        let capture = CaptureInterval::decode_canonical(&mut d)?;
        let reliable = d.bool()?;
        let _gap = d.bool()?;
        if !(plan.first_segment..position_end).contains(&position)
            || !(plan.first_segment..end).contains(&segment)
            || last_position.is_some_and(|previous| previous >= position)
            || capture.earliest > capture.latest
        {
            return Err(Error::InvalidRecord);
        }
        last_position = Some(position);
        if !d.bool()? {
            continue;
        }
        let epoch = d.u64()?;
        if frames.len() == MAX_LONG_DWELL_FRAMES
            || frames
                .insert(
                    position,
                    FrameBinding {
                        segment,
                        capsule,
                        capture,
                        epoch,
                        reliable,
                    },
                )
                .is_some()
        {
            return Err(Error::Limit);
        }
        // Dimensions, foreground/tracker floats and health observations are native measurements.
        // Their complete bytes are hashed here and re-derived only by explicit native replay.
    }
    records.ensure_finished()?;
    Ok(frames)
}

// The dwell producer adds its separate span-start selection policy before the shared detector
// recipe. The long-watch recipe and all existing selection tags remain byte-for-byte unchanged.
fn extensions(
    d: &mut CanonicalDecoder<'_>,
    maximum_segments: usize,
    maximum_pixels: u64,
    limits: &LongEventReplayLimits,
) -> Result<(bool, Option<RetainedDetector>)> {
    let mut tag = if d.remaining() == 0 {
        None
    } else {
        Some(d.text()?)
    };
    let screened = tag == Some("sensor_health");
    if screened {
        health(d, maximum_segments, maximum_pixels)?;
        tag = if d.remaining() == 0 {
            None
        } else {
            Some(d.text()?)
        };
    }
    let detector = match tag {
        None => None,
        Some("detector_cascade") => {
            if d.bytes()? != SELECTION_POLICY {
                return Err(Error::UnsupportedProfile);
            }
            let recipe = LongWatchDetectorRecipe::from_bytes(d.bytes()?)?;
            recipe.validate_within(&limits.execution, &limits.detector)?;
            let outcome = d.bytes()?;
            if outcome.len() > MAX_OUTCOME_BYTES {
                return Err(Error::Limit);
            }
            let inventory = retained_inventory(outcome)?;
            if inventory.recipe != recipe.digest() {
                return Err(Error::InvalidRecord);
            }
            Some(RetainedDetector {
                recipe,
                inventory,
                outcome_digest: ContentDigest::sha256(outcome),
                archive: Vec::new(),
            })
        }
        Some(_) => return Err(Error::UnsupportedProfile),
    };
    d.ensure_finished()?;
    Ok((screened, detector))
}

fn decode(
    bytes: &[u8],
    limits: &LongEventReplayLimits,
    cx: &ReplayCx,
) -> Result<(DwellReplayRecipe, BTreeMap<usize, FrameBinding>, bool)> {
    if bytes.len() > MAX_LONG_EVENT_ANALYSIS_BYTES {
        return Err(Error::Limit);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != ANALYSIS_DOMAIN {
        return Err(Error::UnsupportedProfile);
    }
    let policy = digest(&mut d)?;
    let inter = if policy == ContentDigest::sha256(POLICY) {
        false
    } else if policy == ContentDigest::sha256(POLICY_INTER) {
        true
    } else {
        return Err(Error::UnsupportedProfile);
    };
    let (site, plan) = read_plan(&mut d)?;
    let import_root = digest(&mut d)?;
    let manifest = digest(&mut d)?;
    let anchor = LedgerAnchor::decode_canonical(&mut d)?;
    if anchor.site_lineage != site {
        return Err(Error::InvalidRecord);
    }
    let sensor = SensorId::parse(d.text()?)?;
    let privacy = digest(&mut d)?;
    let rule = DwellPolicy {
        minimum_duration_ns: d.u64()?,
        maximum_sample_gap_ns: d.u64()?,
        minimum_observations: count(&mut d, MAX_LONG_DWELL_FRAMES)?,
    };
    rule.validate().map_err(|_| Error::InvalidRecord)?;
    let options = WatchOptions {
        tolerate_decode_refusals: d.bool()?,
    };
    if d.u64()? != plan.segment_count as u64 {
        return Err(Error::InvalidRecord);
    }
    let trace_bytes = d.bytes()?;
    let frames = trace(trace_bytes, &plan, inter, &limits.execution, cx)?;
    let (screened, detector) = extensions(
        &mut d,
        plan.segment_count,
        limits.execution.maximum_pixel_samples,
        limits,
    )?;
    let execution = if let Some(detector) = &detector {
        if detector.inventory.import_identity != plan.import_identity
            || trace_bytes.len() > detector.recipe.watch_limits().maximum_trace_bytes
        {
            return Err(Error::InvalidRecord);
        }
        *detector.recipe.watch_limits()
    } else {
        limits.execution
    };
    let source = SourceBinding {
        import_identity: plan.import_identity,
        import_root,
        manifest,
        anchor,
        sensor,
        privacy,
        privacy_generation: None,
        media_format: String::new(),
        first: plan.first_segment,
        count: plan.segment_count,
        capsule_bindings: BTreeMap::new(),
        capture_bindings: BTreeMap::new(),
    };
    Ok((
        DwellReplayRecipe {
            plan,
            rule,
            options,
            limits: execution,
            source,
            screened,
            detector,
        },
        frames,
        inter,
    ))
}

#[derive(Clone, Copy)]
struct Sample {
    position: usize,
    capture: CaptureInterval,
}
struct EpisodeBinding {
    analysis_root: ContentDigest,
    zone: String,
    epoch: u64,
    track: u64,
    first: Sample,
    trigger: Sample,
    last: Sample,
    observations: usize,
    trigger_duration: u128,
    duration: u128,
}
fn sample(d: &mut CanonicalDecoder<'_>) -> Result<Sample> {
    Ok(Sample {
        position: usize::try_from(d.u64()?).map_err(|_| Error::Limit)?,
        capture: CaptureInterval::decode_canonical(d)?,
    })
}
fn duration(d: &mut CanonicalDecoder<'_>) -> Result<u128> {
    let text = d.text()?;
    if text.len() > 39 {
        return Err(Error::InvalidRecord);
    }
    let value: u128 = text.parse().map_err(|_| Error::InvalidRecord)?;
    if value.to_string() != text {
        return Err(Error::InvalidRecord);
    }
    Ok(value)
}
fn elapsed(first: CaptureInterval, last: CaptureInterval) -> u128 {
    if last.earliest < first.latest {
        0
    } else {
        last.earliest.0.abs_diff(first.latest.0)
    }
}
fn episode(bytes: &[u8], event: &EventHypothesis) -> Result<EpisodeBinding> {
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != EPISODE_DOMAIN {
        return Err(Error::UnsupportedProfile);
    }
    let analysis_root = digest(&mut d)?;
    let zone = d.text()?.to_owned();
    if zone.len() > 64 {
        return Err(Error::InvalidRecord);
    }
    let epoch = d.u64()?;
    let track = d.u64()?;
    let first = sample(&mut d)?;
    let trigger = sample(&mut d)?;
    let last = sample(&mut d)?;
    let observations = count(&mut d, MAX_LONG_DWELL_FRAMES)?;
    let trigger_duration = duration(&mut d)?;
    let duration = duration(&mut d)?;
    d.ensure_finished()?;
    if track == 0
        || first.position > trigger.position
        || trigger.position > last.position
        || last
            .position
            .checked_sub(first.position)
            .and_then(|n| n.checked_add(1))
            != Some(observations)
        || event.zone_ids != [zone.as_str()]
        || event.track_ids != [format!("track:{epoch}:{track}")]
        || event.interval != CaptureInterval::new(first.capture.earliest, last.capture.latest)?
        || trigger_duration != elapsed(first.capture, trigger.capture)
        || duration != elapsed(first.capture, last.capture)
    {
        return Err(Error::InvalidRecord);
    }
    Ok(EpisodeBinding {
        analysis_root,
        zone,
        epoch,
        track,
        first,
        trigger,
        last,
        observations,
        trigger_duration,
        duration,
    })
}

pub(super) fn load(
    deployment: &ReferenceDeployment,
    event: &EventHypothesis,
    identity: ContentDigest,
    provenance_root: ContentDigest,
    limits: &LongEventReplayLimits,
    reader: &mut MetadataReader,
    cx: &ReplayCx,
) -> Result<LoadedProfile> {
    if event.state != EventState::Indeterminate
        || !event.decision_path.abstained
        || event.decision_path.fingerprint != provenance_root
        || !event.model_receipts.is_empty()
    {
        return Err(Error::UnsupportedProfile);
    }
    let entry = episode(&reader.read(deployment, identity, 4096, cx)?, event)?;
    let analysis_root = entry.analysis_root;
    let entry_manifest = manifest(
        &reader.read(deployment, provenance_root, MAX_MANIFEST_BYTES, cx)?,
        "recorded-long-dwell-episode-v1",
        2,
        false,
    )?;
    let shared = manifest(
        &reader.read(deployment, analysis_root, MAX_MANIFEST_BYTES, cx)?,
        "recorded-long-dwell-analysis-v1",
        6 + 3 + MAX_DWELL_EPISODES * 8,
        false,
    )?;
    let mut objects = BTreeMap::new();
    let mut selected = None;
    for &child in shared.children() {
        let bytes = reader.read(
            deployment,
            child,
            MAX_LONG_EVENT_ANALYSIS_BYTES.max(MAX_RGB_PACKAGE_BYTES),
            cx,
        )?;
        if CanonicalDecoder::new(&bytes).text().ok() == Some(ANALYSIS_DOMAIN)
            && selected.replace(child).is_some()
        {
            return Err(Error::InvalidRecord);
        }
        objects.insert(child, bytes);
    }
    let analysis_digest = selected.ok_or(Error::InvalidRecord)?;
    if published_root(deployment, &slot("ld-a", analysis_digest)?)? != analysis_root {
        return Err(Error::AuthorityChanged);
    }
    let (mut recipe, frames, inter) = decode(
        objects.get(&analysis_digest).ok_or(Error::InvalidRecord)?,
        limits,
        cx,
    )?;
    let policy = if inter { POLICY_INTER } else { POLICY };
    if recipe.source.anchor.site_lineage != deployment.site_lineage()
        || event.decision_path.policy_generation != ContentDigest::sha256(policy)
        || !recipe
            .plan
            .zones
            .iter()
            .any(|zone| zone.zone_id == entry.zone)
        || entry.observations < recipe.rule.minimum_observations
        || entry.trigger.position - entry.first.position + 1 < recipe.rule.minimum_observations
        || entry.trigger_duration < u128::from(recipe.rule.minimum_duration_ns)
        || entry.duration < u128::from(recipe.rule.minimum_duration_ns)
    {
        return Err(Error::InvalidRecord);
    }
    let privacy =
        current_mask(deployment, &recipe.source.sensor).map_err(RecordedDecodeError::from)?;
    if privacy.digest() != recipe.source.privacy {
        return Err(Error::PrivacyChanged);
    }
    // v1 retained the complete policy digest, which includes generation, but not its scalar field.
    // Recover the current generation only after the original digest has matched exactly.
    recipe.source.privacy_generation = privacy.generation();
    let retained = RetainedFileImport::open(
        deployment,
        recipe.source.import_identity,
        recipe.limits.decode.read_limits,
        cx,
    )?;
    recipe.source.media_format = super::watch::media_format(&retained.manifest().format)?;
    if (recipe.source.media_format != "mjpeg") != inter {
        return Err(Error::InvalidRecord);
    }
    for (&position, frame) in &frames {
        if recipe
            .source
            .capsule_bindings
            .insert(frame.segment, frame.capsule)
            .is_some_and(|previous| previous != frame.capsule)
            || recipe
                .source
                .capture_bindings
                .insert(frame.segment, frame.capture)
                .is_some_and(|previous| previous != frame.capture)
        {
            return Err(Error::InvalidRecord);
        }
        for sample in [entry.first, entry.trigger, entry.last] {
            if position == sample.position
                && (frame.capture != sample.capture
                    || frame.epoch != entry.epoch
                    || !frame.reliable)
            {
                return Err(Error::InvalidRecord);
            }
        }
    }
    if [entry.first, entry.trigger, entry.last]
        .iter()
        .any(|sample| !frames.contains_key(&sample.position))
    {
        return Err(Error::InvalidRecord);
    }
    let sensor_digest = ContentDigest::sha256(recipe.sensor().as_str().as_bytes());
    let failure_domain = format!("recorded-sensor:{}", hex(sensor_digest));
    if !event.evidence.iter().any(|edge| {
        edge.digest == identity
            && edge.class == EvidenceClass::Derived
            && !edge.supports
            && edge.relation == EvidenceEdgeRelation::DerivedFrom
            && edge.failure_domain == failure_domain
            && edge.capsule_digest.is_none()
            && edge.identity_digest == Some(sensor_digest)
    }) || objects.get(&sensor_digest).map(Vec::as_slice)
        != Some(recipe.sensor().as_str().as_bytes())
        || objects
            .get(&ContentDigest::sha256(policy))
            .map(Vec::as_slice)
            != Some(policy)
    {
        return Err(Error::InvalidRecord);
    }
    let mut expected = BTreeSet::from([
        recipe.source.import_root,
        analysis_digest,
        sensor_digest,
        ContentDigest::sha256(policy),
    ]);
    let entry_children = BTreeSet::from([identity, analysis_root]);
    let mut evidence_digests = BTreeSet::from([identity]);
    if let Some(policy) = privacy.policy() {
        if objects.get(&policy.digest()).map(Vec::as_slice) != Some(policy.to_bytes().as_slice())
            || !event.evidence.iter().any(|edge| {
                edge.digest == policy.digest()
                    && edge.class == EvidenceClass::Assertion
                    && !edge.supports
                    && edge.relation == EvidenceEdgeRelation::RequiredBy
                    && edge.failure_domain == failure_domain
                    && edge.capsule_digest.is_none()
                    && edge.identity_digest == Some(sensor_digest)
            })
        {
            return Err(Error::InvalidRecord);
        }
        expected.insert(policy.digest());
        evidence_digests.insert(policy.digest());
    }
    if recipe.screened {
        if objects.get(&policy_digest()).map(Vec::as_slice) != Some(policy_bytes()) {
            return Err(Error::InvalidRecord);
        }
        expected.insert(policy_digest());
    }
    if let Some(detector) = &mut recipe.detector {
        let model_digest = detector.recipe.package_digest();
        let recipe_digest = detector.recipe.digest();
        if objects.get(&recipe_digest).map(Vec::as_slice)
            != Some(detector.recipe.to_bytes().as_slice())
            || retained_inventory(
                objects
                    .get(&detector.outcome_digest)
                    .ok_or(Error::InvalidRecord)?,
            )?
            .recipe
                != recipe_digest
        {
            return Err(Error::InvalidRecord);
        }
        expected.extend([model_digest, recipe_digest, detector.outcome_digest]);
        let mut selected_count = 0_usize;
        for class in &detector.inventory.classes {
            let frame = frames.get(&class.position).ok_or(Error::InvalidRecord)?;
            let start = frames
                .get(&class.entry_position)
                .ok_or(Error::InvalidRecord)?;
            if class.zone >= recipe.plan.zones.len()
                || class.track == 0
                || class.position < class.entry_position
                || frame.segment != class.segment
                || frame.capsule != class.capsule
                || frame.epoch != class.epoch
                || start.epoch != class.epoch
                || !frame.reliable
                || !start.reliable
                || !objects.contains_key(&class.digest)
            {
                return Err(Error::InvalidRecord);
            }
            expected.insert(class.digest);
            if class.epoch == entry.epoch
                && class.track == entry.track
                && class.entry_position == entry.first.position
                && recipe.plan.zones[class.zone].zone_id == entry.zone
            {
                if !(entry.first.position..=entry.last.position).contains(&class.position) {
                    return Err(Error::InvalidRecord);
                }
                selected_count += 1;
                evidence_digests.insert(class.digest);
                if !event.evidence.iter().any(|edge| {
                    edge.digest == class.digest
                        && edge.class == EvidenceClass::Derived
                        && !edge.supports
                        && edge.relation == EvidenceEdgeRelation::DerivedFrom
                        && edge.failure_domain == failure_domain
                        && edge.capsule_digest == Some(class.capsule)
                        && edge.identity_digest == Some(sensor_digest)
                }) {
                    return Err(Error::InvalidRecord);
                }
            }
        }
        if selected_count == 0 || selected_count > detector.recipe.config().frames_per_track {
            return Err(Error::InvalidRecord);
        }
        detector.archive = objects.remove(&model_digest).ok_or(Error::InvalidRecord)?;
    }
    if entry_manifest
        .children()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        != entry_children
        || event
            .evidence
            .iter()
            .map(|edge| edge.digest)
            .collect::<BTreeSet<_>>()
            != evidence_digests
        || shared.children().iter().copied().collect::<BTreeSet<_>>() != expected
    {
        return Err(Error::InvalidRecord);
    }
    let source = recipe.source.clone();
    Ok(LoadedProfile {
        recipe: LongEventReplayRecipe::Dwell(recipe),
        analysis_roots: vec![analysis_root],
        analysis_digests: vec![analysis_digest],
        sources: vec![source],
    })
}
