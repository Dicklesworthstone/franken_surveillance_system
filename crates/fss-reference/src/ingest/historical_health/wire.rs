#![forbid(unsafe_code)]
//! Canonical compact receipt and the exact existing native scan recipe.

use fss_core::{CanonicalDecode, CanonicalDecoder};

use super::*;
use crate::ingest::long_dwell::limits::{decode_limits, encode_limits};
use crate::ingest::privacy_mask::{MAX_MASK_POLICY_BYTES, mask_object_id};
use crate::ingest::recorded_decode::ComponentInterpretation;
use crate::ingest::recorded_decode::h264::H264_DECODER_LABEL;
use crate::ingest::recorded_decode::h265::H265_DECODER_LABEL;
use crate::ingest::recorded_watch::{WatchDetectorConfig, WatchTrackerConfig, WatchZone};
use crate::ingest::zone_dwell::DwellPolicy;

pub(super) fn encode(record: &HistoricalHealthRecord) -> Vec<u8> {
    let mut e = CanonicalEncoder::new();
    e.text(HISTORICAL_HEALTH_RECORD_DOMAIN);
    e.bytes(POLICY);
    e.bytes(&fss_codec_mjpeg::decoder_identity());
    e.text(H264_DECODER_LABEL);
    e.text(H265_DECODER_LABEL);
    e.digest(policy_digest());
    e.text(&record.site);
    e.digest(record.import_root);
    e.digest(record.manifest_digest);
    record.source_anchor.encode_canonical(&mut e);
    e.text(record.sensor.as_str());
    e.text(record.stream.as_str());
    e.text(&record.media_format);
    record.capture_scope.encode_canonical(&mut e);
    e.text("operator_assumption");
    super::super::privacy_mask::encode_marker(&mut e, record.privacy_policy);
    e.bool(record.privacy_generation.is_some());
    if let Some(generation) = record.privacy_generation {
        e.u64(generation);
    }
    encode_plan(&mut e, &record.plan);
    match record.rule {
        ScanRule::ZoneEntry => e.u8(0),
        ScanRule::Dwell(rule) => {
            e.u8(1);
            e.u64(rule.minimum_duration_ns);
            e.u64(rule.maximum_sample_gap_ns);
            e.u64(rule.minimum_observations as u64);
        }
        ScanRule::Observed => e.u8(2),
    }
    e.bool(record.options.tolerate_decode_refusals);
    encode_limits(&mut e, &record.limits);
    record.summary.encode(&mut e);
    e.digest(record.trace_digest);
    e.u64(record.trace_bytes as u64);
    e.u64(record.unreliable as u64);
    e.u64(record.restarts as u64);
    for value in [
        record.source_bytes,
        record.pixel_samples,
        record.assignment_work,
        record.jpeg_work,
    ] {
        e.u64(value);
    }
    e.finish()
}

fn encode_plan(e: &mut CanonicalEncoder, plan: &WatchPlan) {
    e.digest(plan.digest());
    e.digest(plan.import_identity);
    e.u8(match plan.interpretation {
        ComponentInterpretation::Grayscale => 0,
        ComponentInterpretation::YCbCr => 1,
    });
    e.u64(plan.first_segment as u64);
    e.u64(plan.segment_count as u64);
    e.u64(plan.zones.len() as u64);
    for zone in &plan.zones {
        e.text(&zone.zone_id);
        for value in [zone.x, zone.y, zone.width, zone.height] {
            e.u32(value);
        }
    }
    for value in [
        plan.detector.base_threshold,
        plan.detector.threshold_sigma,
        plan.detector.learning_rate_num,
        plan.detector.learning_rate_den,
    ] {
        e.u32(u32::from(value));
    }
    e.u64(plan.detector.minimum_region_pixels as u64);
    e.u32(plan.tracker.confirmation_hits);
    e.u32(plan.tracker.maximum_missed_frames);
    e.u32(plan.tracker.minimum_iou_ppm);
    // Bind the shared native tracker's fixed process/measurement noise parameters as well.
    e.u64(1.0_f64.to_bits());
    e.u64(1.0_f64.to_bits());
}

fn usize_value(d: &mut CanonicalDecoder<'_>) -> Result<usize> {
    usize::try_from(d.u64()?).map_err(|_| HistoricalHealthError::Limit)
}
fn u16_value(d: &mut CanonicalDecoder<'_>) -> Result<u16> {
    u16::try_from(d.u32()?).map_err(|_| HistoricalHealthError::InvalidRecord)
}
fn digest(d: &mut CanonicalDecoder<'_>) -> Result<ContentDigest> {
    let digest = d.digest()?;
    valid_digest(digest)?;
    Ok(digest)
}
fn bounded_text(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<String> {
    let value = d.text()?;
    if value.is_empty() || value.len() > maximum {
        return Err(HistoricalHealthError::InvalidRecord);
    }
    Ok(value.to_owned())
}
fn decode_plan(d: &mut CanonicalDecoder<'_>) -> Result<WatchPlan> {
    let expected = digest(d)?;
    let import_identity = digest(d)?;
    let interpretation = match d.u8()? {
        0 => ComponentInterpretation::Grayscale,
        1 => ComponentInterpretation::YCbCr,
        _ => return Err(HistoricalHealthError::InvalidRecord),
    };
    let first_segment = usize_value(d)?;
    let segment_count = usize_value(d)?;
    let count = usize_value(d)?;
    if !(1..=MAX_LONG_DWELL_FRAMES).contains(&segment_count)
        || first_segment.checked_add(segment_count).is_none()
        || count == 0
        || count > 32
        || count > d.remaining() / 25
    {
        return Err(HistoricalHealthError::Limit);
    }
    let mut zones = Vec::with_capacity(count);
    for _ in 0..count {
        zones.push(WatchZone {
            zone_id: bounded_text(d, 64)?,
            x: d.u32()?,
            y: d.u32()?,
            width: d.u32()?,
            height: d.u32()?,
        });
    }
    let detector = WatchDetectorConfig {
        base_threshold: u16_value(d)?,
        threshold_sigma: u16_value(d)?,
        learning_rate_num: u16_value(d)?,
        learning_rate_den: u16_value(d)?,
        minimum_region_pixels: usize_value(d)?,
    };
    let tracker = WatchTrackerConfig {
        confirmation_hits: d.u32()?,
        maximum_missed_frames: d.u32()?,
        minimum_iou_ppm: d.u32()?,
    };
    if d.u64()? != 1.0_f64.to_bits() || d.u64()? != 1.0_f64.to_bits() {
        return Err(HistoricalHealthError::InvalidRecord);
    }
    let plan = WatchPlan {
        import_identity,
        interpretation,
        first_segment,
        segment_count,
        zones,
        detector,
        tracker,
    };
    let mut validation = plan.clone();
    validation.segment_count = 1;
    validation.validate()?;
    if plan.digest() != expected {
        return Err(HistoricalHealthError::InvalidRecord);
    }
    Ok(plan)
}

pub(super) fn decode(bytes: &[u8]) -> Result<HistoricalHealthRecord> {
    if bytes.is_empty() || bytes.len() > MAX_HISTORICAL_HEALTH_RECORD_BYTES {
        return Err(HistoricalHealthError::Limit);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != HISTORICAL_HEALTH_RECORD_DOMAIN
        || d.bytes()? != POLICY
        || d.bytes()? != fss_codec_mjpeg::decoder_identity().as_slice()
        || d.text()? != H264_DECODER_LABEL
        || d.text()? != H265_DECODER_LABEL
        || digest(&mut d)? != policy_digest()
    {
        return Err(HistoricalHealthError::InvalidRecord);
    }
    let site = bounded_text(&mut d, 256)?;
    crate::reference_deployment::validate_site_lineage(&site)?;
    let import_root = digest(&mut d)?;
    let manifest_digest = digest(&mut d)?;
    let source_anchor = LedgerAnchor::decode_canonical(&mut d)?;
    if source_anchor.site_lineage != site || source_anchor.commit_sequence == 0 {
        return Err(HistoricalHealthError::InvalidRecord);
    }
    valid_digest(source_anchor.state_root)?;
    let sensor = SensorId::parse(bounded_text(&mut d, 128)?)?;
    let stream = StreamId::parse(bounded_text(&mut d, 128)?)?;
    let media_format = bounded_text(&mut d, 16)?;
    if !matches!(
        media_format.as_str(),
        "mjpeg" | "annexb" | "hevc" | "mp4avc" | "mp4hevc" | "mkvavc" | "mkvhevc"
    ) {
        return Err(HistoricalHealthError::InvalidRecord);
    }
    let capture_scope = CaptureInterval::decode_canonical(&mut d)?;
    if capture_scope.earliest > capture_scope.latest || d.text()? != "operator_assumption" {
        return Err(HistoricalHealthError::InvalidRecord);
    }
    let privacy_policy = crate::ingest::privacy_mask::decode_marker(&mut d)?;
    let privacy_generation = if d.bool()? { Some(d.u64()?) } else { None };
    if privacy_policy.is_some() != privacy_generation.is_some() || privacy_generation == Some(0) {
        return Err(HistoricalHealthError::InvalidRecord);
    }
    let plan = decode_plan(&mut d)?;
    let rule = match d.u8()? {
        0 => ScanRule::ZoneEntry,
        1 => {
            let rule = DwellPolicy {
                minimum_duration_ns: d.u64()?,
                maximum_sample_gap_ns: d.u64()?,
                minimum_observations: usize_value(&mut d)?,
            };
            rule.validate()
                .map_err(|_| HistoricalHealthError::InvalidRecord)?;
            ScanRule::Dwell(rule)
        }
        2 => ScanRule::Observed,
        _ => return Err(HistoricalHealthError::InvalidRecord),
    };
    let options = WatchOptions {
        tolerate_decode_refusals: d.bool()?,
    };
    let limits = decode_limits(&mut d)?;
    limits.validate()?;
    let summary = LongDwellHealthSummary::decode(&mut d)?;
    let trace_digest = digest(&mut d)?;
    let trace_bytes = usize_value(&mut d)?;
    let unreliable = usize_value(&mut d)?;
    let restarts = usize_value(&mut d)?;
    let source_bytes = d.u64()?;
    let pixel_samples = d.u64()?;
    let assignment_work = d.u64()?;
    let jpeg_work = d.u64()?;
    d.ensure_finished()?;
    let range_end = plan.first_segment + plan.segment_count;
    if summary.frames_screened() > plan.segment_count
        || (summary.complete()
            && (summary.frames_screened() != plan.segment_count || unreliable != 0))
        || summary.samples_screened() != pixel_samples
        || pixel_samples > limits.maximum_pixel_samples
        || source_bytes > limits.maximum_source_chunk_bytes
        || assignment_work > limits.maximum_assignment_work
        || jpeg_work > limits.decode.jpeg_work_units
        || unreliable > summary.frames_screened()
        || restarts > plan.segment_count.saturating_mul(2).saturating_add(256)
        || !(1..=MAX_LONG_DWELL_TRACE_BYTES).contains(&trace_bytes)
        || trace_bytes > limits.maximum_trace_bytes
        || summary.findings().iter().any(|run| {
            run.first_segment < plan.first_segment as u64 || run.last_segment >= range_end as u64
        })
    {
        return Err(HistoricalHealthError::InvalidRecord);
    }
    let record = HistoricalHealthRecord {
        site,
        plan,
        rule,
        options,
        limits,
        import_root,
        manifest_digest,
        source_anchor,
        sensor,
        stream,
        media_format,
        capture_scope,
        privacy_policy,
        privacy_generation,
        summary,
        trace_digest,
        trace_bytes,
        unreliable,
        restarts,
        source_bytes,
        pixel_samples,
        assignment_work,
        jpeg_work,
    };
    if encode(&record) != bytes {
        return Err(HistoricalHealthError::InvalidRecord);
    }
    Ok(record)
}

/// Validate the privacy generation effective when this diagnostic was committed. Later policy
/// changes never rewrite an older diagnostic and never make no_findings a present-health claim.
pub(super) fn check_historical_privacy(
    record: &HistoricalHealthRecord,
    prefix: &[EvidenceDeltaBatch],
    read: &mut impl FnMut(ContentDigest, usize) -> Result<Vec<u8>>,
) -> Result<()> {
    let object = mask_object_id(&record.sensor)?;
    let mut generation = None;
    let mut policy = None;
    for delta in prefix
        .iter()
        .flat_map(|batch| &batch.deltas)
        .filter(|delta| delta.object_id == object)
    {
        let expected = generation
            .unwrap_or(0_u64)
            .checked_add(1)
            .ok_or(HistoricalHealthError::InvalidRecord)?;
        if delta.family != "privacy_mask_policy"
            || delta.plane != Plane::Authority
            || delta.prior_generation != generation
            || delta.new_generation != expected
        {
            return Err(HistoricalHealthError::InvalidRecord);
        }
        generation = Some(expected);
        policy = Some(delta.payload_digest);
    }
    if generation != record.privacy_generation || policy != record.privacy_policy {
        return Err(HistoricalHealthError::InvalidRecord);
    }
    if let Some(digest) = policy {
        let bytes = read(digest, MAX_MASK_POLICY_BYTES)?;
        let policy = PrivacyMaskPolicy::from_bytes(&bytes, digest)
            .map_err(|_| HistoricalHealthError::InvalidRecord)?;
        if policy.sensor_id() != &record.sensor {
            return Err(HistoricalHealthError::InvalidRecord);
        }
    }
    Ok(())
}
