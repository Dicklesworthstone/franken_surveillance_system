#![forbid(unsafe_code)]
//! Decode the existing long-watch profile; opaque native measurements are verified by replay.

use std::collections::{BTreeMap, BTreeSet};
use fss_core::{
    CanonicalDecode, CanonicalDecoder, CaptureInterval, ContentDigest, EventHypothesis, EventState,
    EvidenceClass, EvidenceEdgeRelation, LedgerAnchor, SensorId,
};
use crate::ingest::long_watch::{ANALYSIS_DOMAIN, ENTRY_DOMAIN, POLICY};
use crate::ingest::recorded_decode::ComponentInterpretation;
use crate::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};
use crate::ingest::sensor_health::{policy_bytes, policy_digest};
use crate::{ReferenceDeployment, ReplayCx};
use super::{
    LoadedProfile, LongEventReplayError as Error, LongEventReplayLimits, LongEventReplayRecipe,
    LongDwellLimits, MAX_LONG_DWELL_FRAMES, MAX_LONG_DWELL_TRACE_BYTES,
    MAX_LONG_EVENT_ANALYSIS_BYTES, MAX_MANIFEST_BYTES, MetadataReader, Result, SourceBinding,
    checkpoint, manifest, published_root, slot, valid_digest,
};

/// Original retained settings plus explicitly current safety ceilings for fields not saved by v1.
#[derive(Clone, Debug)]
pub struct WatchReplayRecipe {
    plan: WatchPlan,
    options: WatchOptions,
    limits: LongDwellLimits,
    source: SourceBinding,
    screened: bool,
}
impl WatchReplayRecipe {
    /// Original image-zone, foreground, tracker and source-range configuration.
    pub fn plan(&self) -> &WatchPlan { &self.plan }
    /// Original refusal/recovery behavior.
    pub const fn options(&self) -> WatchOptions { self.options }
    /// Retained aggregate source/pixel/assignment/trace/JPEG-work limits, combined with current
    /// caller safety ceilings for the codec/read fields absent from the historical format.
    pub const fn limits(&self) -> &LongDwellLimits { &self.limits }
    /// Whether the original conservative whole-scan health policy was selected.
    pub const fn screened(&self) -> bool { self.screened }
    /// Exact retained source format, whose native owner still governs decoding.
    pub fn media_format(&self) -> &str { &self.source.media_format }
    /// Sensor whose current privacy policy must match the recorded analysis.
    pub fn sensor(&self) -> &SensorId { &self.source.sensor }
    /// V1 recorded five aggregate ceilings, not the complete codec/read configuration.
    pub const fn complete_codec_limits_retained(&self) -> bool { false }
}

pub(super) fn digest(d: &mut CanonicalDecoder<'_>) -> Result<ContentDigest> {
    let value = d.digest()?;
    valid_digest(value)?;
    Ok(value)
}
pub(super) fn count(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<usize> {
    let value = usize::try_from(d.u64()?).map_err(|_| Error::Limit)?;
    if value > maximum { return Err(Error::Limit); }
    Ok(value)
}
pub(super) fn media_format(value: &str) -> Result<String> {
    if !matches!(value, "mjpeg" | "annexb" | "hevc" | "mp4avc" | "mp4hevc" | "mkvavc" | "mkvhevc") {
        return Err(Error::UnsupportedProfile);
    }
    Ok(value.to_owned())
}
pub(super) fn privacy_generation(d: &mut CanonicalDecoder<'_>) -> Result<Option<u64>> {
    if d.bool()? {
        let generation = d.u64()?;
        if generation == 0 { return Err(Error::InvalidRecord); }
        Ok(Some(generation))
    } else { Ok(None) }
}
pub(super) fn site(d: &mut CanonicalDecoder<'_>) -> Result<String> {
    let value = d.text()?;
    if value.len() > 256 || crate::reference_deployment::validate_site_lineage(value).is_err() {
        return Err(Error::InvalidRecord);
    }
    Ok(value.to_owned())
}

/// Bound every frame record without pretending parsed claims establish their native derivation.
/// Inter-coded traces contain display-order frames and explicit breaks, unlike source-order JPEG.
pub(super) fn trace_and_health(
    d: &mut CanonicalDecoder<'_>, maximum_segments: usize, maximum_trace: usize,
    maximum_pixels: u64, cx: &ReplayCx,
) -> Result<bool> {
    let trace = d.bytes()?;
    if trace.is_empty() || trace.len() > maximum_trace || trace.len() > MAX_LONG_DWELL_TRACE_BYTES {
        return Err(Error::Limit);
    }
    let mut records = CanonicalDecoder::new(trace);
    let mut count = 0_usize;
    while records.remaining() != 0 {
        checkpoint(cx, "long_event_replay:trace_record")?;
        let record = records.bytes()?;
        count = count.checked_add(1).ok_or(Error::Limit)?;
        if record.is_empty() || record.len() > 32 * 1024
            || count > maximum_segments.saturating_mul(2).saturating_add(256) {
            return Err(Error::Limit);
        }
    }
    records.ensure_finished()?;
    let screened = d.remaining() != 0;
    if screened {
        if d.text()? != "sensor_health" || d.bytes()? != policy_bytes() {
            return Err(Error::UnsupportedProfile);
        }
        let complete = d.bool()?;
        let frames = d.u64()?;
        let samples = d.u64()?;
        let findings = d.u64()?;
        // Degraded or incomplete scans cannot have published an original eligible event.
        if !complete || frames == 0 || frames > maximum_segments as u64
            || samples == 0 || samples > maximum_pixels || findings != 0 {
            return Err(Error::InvalidRecord);
        }
    }
    d.ensure_finished()?;
    Ok(screened)
}

fn decode(bytes: &[u8], limits: &LongEventReplayLimits, cx: &ReplayCx) -> Result<WatchReplayRecipe> {
    if bytes.len() > MAX_LONG_EVENT_ANALYSIS_BYTES { return Err(Error::Limit); }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != ANALYSIS_DOMAIN || digest(&mut d)? != ContentDigest::sha256(POLICY) {
        return Err(Error::UnsupportedProfile);
    }
    let site = site(&mut d)?;
    let plan_digest = digest(&mut d)?;
    let import_identity = digest(&mut d)?;
    let first_segment = usize::try_from(d.u64()?).map_err(|_| Error::Limit)?;
    let segment_count = count(&mut d, MAX_LONG_DWELL_FRAMES)?;
    if segment_count == 0 || first_segment.checked_add(segment_count).is_none() {
        return Err(Error::InvalidRecord);
    }
    let zone_count = count(&mut d, 16)?;
    let mut zones = Vec::with_capacity(zone_count);
    for _ in 0..zone_count {
        let zone_id = d.text()?;
        if zone_id.len() > 64 { return Err(Error::InvalidRecord); }
        zones.push(WatchZone {
            zone_id: zone_id.to_owned(), x: d.u32()?, y: d.u32()?,
            width: d.u32()?, height: d.u32()?,
        });
    }
    if d.u64()? != 11 { return Err(Error::UnsupportedProfile); }
    let mut p = [0_u64; 11];
    for value in &mut p { *value = d.u64()?; }
    if p[9] != 1_f64.to_bits() || p[10] != 1_f64.to_bits() {
        return Err(Error::UnsupportedProfile);
    }
    let plan = WatchPlan {
        import_identity, first_segment, segment_count, zones,
        interpretation: match p[0] {
            0 => ComponentInterpretation::Grayscale,
            1 => ComponentInterpretation::YCbCr,
            _ => return Err(Error::UnsupportedProfile),
        },
        detector: WatchDetectorConfig {
            base_threshold: u16::try_from(p[1]).map_err(|_| Error::InvalidRecord)?,
            threshold_sigma: u16::try_from(p[2]).map_err(|_| Error::InvalidRecord)?,
            learning_rate_num: u16::try_from(p[3]).map_err(|_| Error::InvalidRecord)?,
            learning_rate_den: u16::try_from(p[4]).map_err(|_| Error::InvalidRecord)?,
            minimum_region_pixels: usize::try_from(p[5]).map_err(|_| Error::Limit)?,
        },
        tracker: WatchTrackerConfig {
            confirmation_hits: u32::try_from(p[6]).map_err(|_| Error::InvalidRecord)?,
            maximum_missed_frames: u32::try_from(p[7]).map_err(|_| Error::InvalidRecord)?,
            minimum_iou_ppm: u32::try_from(p[8]).map_err(|_| Error::InvalidRecord)?,
        },
    };
    let mut admission = plan.clone();
    admission.segment_count = 1;
    admission.validate().map_err(|_| Error::InvalidRecord)?;
    if plan.digest() != plan_digest { return Err(Error::InvalidRecord); }
    let import_root = digest(&mut d)?;
    let manifest = digest(&mut d)?;
    let anchor = LedgerAnchor::decode_canonical(&mut d)?;
    if anchor.site_lineage != site { return Err(Error::InvalidRecord); }
    let sensor = SensorId::parse(d.text()?)?;
    let media_format = media_format(d.text()?)?;
    let privacy = digest(&mut d)?;
    let privacy_generation = privacy_generation(&mut d)?;
    let options = WatchOptions { tolerate_decode_refusals: d.bool()? };
    let mut execution = limits.execution;
    let source_bytes = d.u64()?;
    let pixels = d.u64()?;
    let assignment = d.u64()?;
    let trace = usize::try_from(d.u64()?).map_err(|_| Error::Limit)?;
    let jpeg_work = d.u64()?;
    if source_bytes > execution.maximum_source_chunk_bytes || pixels > execution.maximum_pixel_samples
        || assignment > execution.maximum_assignment_work || trace > execution.maximum_trace_bytes
        || jpeg_work > execution.decode.jpeg_work_units {
        return Err(Error::Limit);
    }
    execution.maximum_source_chunk_bytes = source_bytes;
    execution.maximum_pixel_samples = pixels;
    execution.maximum_assignment_work = assignment;
    execution.maximum_trace_bytes = trace;
    execution.decode.jpeg_work_units = jpeg_work;
    execution.validate()?;
    let screened = trace_and_health(&mut d, segment_count, trace, pixels, cx)?;
    Ok(WatchReplayRecipe {
        plan, options, limits: execution, screened,
        source: SourceBinding {
            import_identity, import_root, manifest, anchor, sensor, privacy, privacy_generation,
            media_format, first: first_segment, count: segment_count,
        },
    })
}

struct EntryBinding {
    analysis_root: ContentDigest,
    position: usize,
    segment: usize,
    capsule: ContentDigest,
}

fn entry_binding(bytes: &[u8], event: &EventHypothesis) -> Result<EntryBinding> {
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != ENTRY_DOMAIN { return Err(Error::UnsupportedProfile); }
    let root = digest(&mut d)?;
    let zone = d.text()?;
    let epoch = d.u64()?;
    let track = d.u64()?;
    let position = usize::try_from(d.u64()?).map_err(|_| Error::Limit)?;
    let segment = usize::try_from(d.u64()?).map_err(|_| Error::Limit)?;
    let capsule = digest(&mut d)?;
    let interval = CaptureInterval::decode_canonical(&mut d)?;
    let mut box_values = [0_i64; 4];
    for value in &mut box_values {
        *value = i64::try_from(d.i128()?).map_err(|_| Error::InvalidRecord)?;
    }
    d.ensure_finished()?;
    if event.zone_ids != [zone] || event.track_ids != [format!("track:{epoch}:{track}")]
        || event.interval != interval || track == 0 || box_values[2] <= 0 || box_values[3] <= 0 {
        return Err(Error::InvalidRecord);
    }
    Ok(EntryBinding { analysis_root: root, position, segment, capsule })
}

pub(super) fn load(
    deployment: &ReferenceDeployment, event: &EventHypothesis, identity: ContentDigest,
    provenance_root: ContentDigest, limits: &LongEventReplayLimits,
    reader: &mut MetadataReader, cx: &ReplayCx,
) -> Result<LoadedProfile> {
    if event.state != EventState::Indeterminate || !event.decision_path.abstained
        || event.decision_path.policy_generation != ContentDigest::sha256(POLICY)
        || event.decision_path.fingerprint != provenance_root || !event.model_receipts.is_empty()
        || !event.evidence.iter().any(|item| item.digest == identity
            && item.class == EvidenceClass::Derived && item.relation == EvidenceEdgeRelation::DerivedFrom
            && !item.supports) {
        return Err(Error::UnsupportedProfile);
    }
    let entry = reader.read(deployment, identity, 4096, cx)?;
    let entry = entry_binding(&entry, event)?;
    let analysis_root = entry.analysis_root;
    let entry_manifest = manifest(
        &reader.read(deployment, provenance_root, MAX_MANIFEST_BYTES, cx)?,
        "recorded-long-watch-entry-v1", 2, false,
    )?;
    if entry_manifest.children().iter().copied().collect::<BTreeSet<_>>() != BTreeSet::from([identity, analysis_root]) {
        return Err(Error::InvalidRecord);
    }
    let shared = manifest(
        &reader.read(deployment, analysis_root, MAX_MANIFEST_BYTES, cx)?,
        "recorded-long-watch-analysis-v1", 6, false,
    )?;
    let mut objects = BTreeMap::new();
    let mut selected = None;
    for &child in shared.children() {
        let bytes = reader.read(deployment, child, MAX_LONG_EVENT_ANALYSIS_BYTES, cx)?;
        if CanonicalDecoder::new(&bytes).text().ok() == Some(ANALYSIS_DOMAIN) && selected.replace(child).is_some() {
            return Err(Error::InvalidRecord);
        }
        objects.insert(child, bytes);
    }
    let analysis_digest = selected.ok_or(Error::InvalidRecord)?;
    if published_root(deployment, &slot("lw-a", analysis_digest)?)? != analysis_root {
        return Err(Error::AuthorityChanged);
    }
    let recipe = decode(objects.get(&analysis_digest).ok_or(Error::InvalidRecord)?, limits, cx)?;
    if recipe.source.anchor.site_lineage != deployment.site_lineage() { return Err(Error::InvalidRecord); }
    let privacy = crate::ingest::privacy_mask::current_mask(deployment, &recipe.source.sensor)
        .map_err(crate::ingest::recorded_decode::RecordedDecodeError::from)?;
    if privacy.digest() != recipe.source.privacy || privacy.generation() != recipe.source.privacy_generation {
        return Err(Error::PrivacyChanged);
    }
    let sensor_digest = ContentDigest::sha256(recipe.sensor().as_str().as_bytes());
    let end = recipe.source.first.checked_add(recipe.source.count).ok_or(Error::Limit)?;
    if !(recipe.source.first..end).contains(&entry.position)
        || !(recipe.source.first..end).contains(&entry.segment)
        || !event.evidence.iter().any(|item| item.digest == identity
            && item.capsule_digest == Some(entry.capsule) && item.identity_digest == Some(sensor_digest)) {
        return Err(Error::InvalidRecord);
    }
    if objects.get(&sensor_digest).map(Vec::as_slice) != Some(recipe.sensor().as_str().as_bytes())
        || objects.get(&ContentDigest::sha256(POLICY)).map(Vec::as_slice) != Some(POLICY) {
        return Err(Error::InvalidRecord);
    }
    let mut expected = BTreeSet::from([recipe.source.import_root, analysis_digest, sensor_digest, ContentDigest::sha256(POLICY)]);
    if let Some(policy) = privacy.policy() {
        if objects.get(&policy.digest()).map(Vec::as_slice) != Some(policy.to_bytes().as_slice()) {
            return Err(Error::InvalidRecord);
        }
        expected.insert(policy.digest());
    }
    if recipe.screened {
        if objects.get(&policy_digest()).map(Vec::as_slice) != Some(policy_bytes()) { return Err(Error::InvalidRecord); }
        expected.insert(policy_digest());
    }
    if shared.children().iter().copied().collect::<BTreeSet<_>>() != expected { return Err(Error::InvalidRecord); }
    let source = recipe.source.clone();
    Ok(LoadedProfile {
        recipe: LongEventReplayRecipe::Watch(recipe),
        analysis_roots: vec![analysis_root], analysis_digests: vec![analysis_digest], sources: vec![source],
    })
}
