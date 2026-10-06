#![forbid(unsafe_code)]
//! Closed reader for the existing long-dwell recipe and its bounded frame trace.
//! Parsed measurements are claims; only native replay can validate their derivation.

use super::{DwellReplayError as Error, MAX_ANALYSIS_BYTES, MAX_LONG_DWELL_FRAMES};
use crate::ingest::recorded_decode::ComponentInterpretation;
use crate::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};
use crate::ingest::sensor_health::{policy_bytes, policy_digest};
use crate::ingest::zone_dwell::DwellPolicy;
use fss_core::{
    CanonicalDecode, CanonicalDecoder, CaptureInterval, ContentDigest, LedgerAnchor, SensorId,
};

pub(super) const ANALYSIS_DOMAIN: &str = "fss.long_dwell_analysis.v1";
pub(super) const FRAME_DOMAIN: &str = "fss.long_dwell_frame.v1";
pub(super) const EPISODE_DOMAIN: &str = "fss.long_dwell_episode.v1";
// This is the immutable v1 wire profile, not an alternative execution implementation. Replay
// also compares the actual current producer's complete analysis and event digests.
pub(super) const POLICY: &[u8] =
    b"fss.long-dwell.policy.v1:mjpeg-native-luma:masked-before-perception:\
running-variance:kalman-global-iou:confirmed-actual-matches:strict-rounded-zone-interior:\
conservative-capture-endpoints:reset-background-and-tracker-on-source-or-decode-gap:\
one-whole-range-budget:unclassified:indeterminate:hold:no-absence:no-alert";
const FINDINGS: [&str; 4] = [
    "persistent_dark_field",
    "persistent_bright_field",
    "exact_frame_repetition",
    "contrast_collapse",
];

type Result<T> = std::result::Result<T, Error>;

pub(super) fn digest(d: &mut CanonicalDecoder<'_>) -> Result<ContentDigest> {
    let value = d.digest()?;
    super::valid_digest(value)?;
    Ok(value)
}
fn count(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<usize> {
    let value = usize::try_from(d.u64()?).map_err(|_| Error::Limit)?;
    if value > maximum {
        return Err(Error::Limit);
    }
    Ok(value)
}
fn interval(d: &mut CanonicalDecoder<'_>) -> Result<CaptureInterval> {
    Ok(CaptureInterval::decode_canonical(d)?)
}
fn decimal(d: &mut CanonicalDecoder<'_>) -> Result<u128> {
    let text = d.text()?;
    if text.is_empty() || text.len() > 39 || !text.bytes().all(|b| b.is_ascii_digit()) {
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

/// Recipe decoded from retained bytes, never from caller-supplied thresholds or command text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DwellReplayRecipe {
    pub(super) site: String,
    pub(super) plan: WatchPlan,
    pub(super) rule: DwellPolicy,
    pub(super) options: WatchOptions,
    pub(super) import_root: ContentDigest,
    pub(super) manifest: ContentDigest,
    pub(super) source_anchor: LedgerAnchor,
    pub(super) sensor: SensorId,
    pub(super) privacy: ContentDigest,
    pub(super) screened: bool,
}
impl DwellReplayRecipe {
    /// Exact original range, image zones and foreground/tracker parameters.
    pub fn plan(&self) -> &WatchPlan {
        &self.plan
    }
    /// Original sampled-occupancy rule; capture hints remain owner assumptions.
    pub const fn rule(&self) -> DwellPolicy {
        self.rule
    }
    /// Whether conservative-v1 screening must run on every decoded masked frame.
    pub const fn screened(&self) -> bool {
        self.screened
    }
    /// The original decoder-refusal behavior; replay cannot silently relax it.
    pub const fn options(&self) -> WatchOptions {
        self.options
    }
    /// Sensor whose current privacy projection must still match the retained recipe.
    pub fn sensor(&self) -> &SensorId {
        &self.sensor
    }

    pub(super) fn decode(bytes: &[u8], check: &mut impl FnMut() -> Result<()>) -> Result<Self> {
        check()?;
        if bytes.len() > MAX_ANALYSIS_BYTES {
            return Err(Error::Limit);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != ANALYSIS_DOMAIN || digest(&mut d)? != ContentDigest::sha256(POLICY) {
            return Err(Error::UnsupportedProfile);
        }
        let site = d.text()?;
        if site.len() > 256 || crate::reference_deployment::validate_site_lineage(site).is_err() {
            return Err(Error::InvalidRecord);
        }
        let site = site.to_owned();
        let plan_digest = digest(&mut d)?;
        let import_identity = digest(&mut d)?;
        let first_segment = usize::try_from(d.u64()?).map_err(|_| Error::Limit)?;
        let segment_count = count(&mut d, MAX_LONG_DWELL_FRAMES)?;
        if segment_count == 0 || first_segment.checked_add(segment_count).is_none() {
            return Err(Error::InvalidRecord);
        }
        let zones_count = count(&mut d, 16)?;
        let mut zones = Vec::with_capacity(zones_count);
        for _ in 0..zones_count {
            let zone_id = d.text()?;
            if zone_id.len() > 64 {
                return Err(Error::InvalidRecord);
            }
            zones.push(WatchZone {
                zone_id: zone_id.to_owned(),
                x: d.u32()?,
                y: d.u32()?,
                width: d.u32()?,
                height: d.u32()?,
            });
        }
        if d.u64()? != 11 {
            return Err(Error::UnsupportedProfile);
        }
        let mut p = [0_u64; 11];
        for value in &mut p {
            *value = d.u64()?;
        }
        if p[9] != 1_f64.to_bits() || p[10] != 1_f64.to_bits() {
            return Err(Error::UnsupportedProfile);
        }
        let plan = WatchPlan {
            import_identity,
            first_segment,
            segment_count,
            zones,
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
        let mut validation = plan.clone();
        validation.segment_count = 1;
        validation.validate().map_err(|_| Error::InvalidRecord)?;
        if plan.digest() != plan_digest {
            return Err(Error::InvalidRecord);
        }
        let import_root = digest(&mut d)?;
        let manifest = digest(&mut d)?;
        let source_anchor = LedgerAnchor::decode_canonical(&mut d)?;
        if source_anchor.site_lineage != site {
            return Err(Error::InvalidRecord);
        }
        let sensor = SensorId::parse(d.text()?)?;
        let privacy = digest(&mut d)?;
        let rule = DwellPolicy {
            minimum_duration_ns: d.u64()?,
            maximum_sample_gap_ns: d.u64()?,
            minimum_observations: count(&mut d, 128)?,
        };
        rule.validate().map_err(|_| Error::InvalidRecord)?;
        let options = WatchOptions {
            tolerate_decode_refusals: d.bool()?,
        };
        if d.u64()? != segment_count as u64 {
            return Err(Error::InvalidRecord);
        }
        let trace = d.bytes()?;
        if trace.len() > super::MAX_LONG_DWELL_TRACE_BYTES {
            return Err(Error::Limit);
        }
        let screened = d.remaining() != 0;
        if screened {
            if d.text()? != "sensor_health" || d.bytes()? != policy_bytes() {
                return Err(Error::UnsupportedProfile);
            }
            // A committed screened event is admitted only by a complete, no-findings scan.
            // A forged admission still cannot pass native replay below.
            if !d.bool()? || d.u64()? != segment_count as u64 {
                return Err(Error::InvalidRecord);
            }
            let samples = d.u64()?;
            if samples == 0 || samples > segment_count as u64 * 4_194_304 || d.u64()? != 0 {
                return Err(Error::InvalidRecord);
            }
        }
        d.ensure_finished()?;
        let mut frames = CanonicalDecoder::new(trace);
        for segment in first_segment..first_segment + segment_count {
            check()?;
            let frame = frames.bytes()?;
            // 64 tracks, 64 boxes and one bounded health observation fit comfortably.
            if frame.len() > 16_384 {
                return Err(Error::Limit);
            }
            validate_frame(
                frame,
                segment as u64,
                screened,
                options.tolerate_decode_refusals,
            )?;
        }
        frames.ensure_finished()?;
        Ok(Self {
            site,
            plan,
            rule,
            options,
            import_root,
            manifest,
            source_anchor,
            sensor,
            privacy,
            screened,
        })
    }
}

fn validate_frame(bytes: &[u8], segment: u64, screened: bool, tolerant: bool) -> Result<()> {
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != FRAME_DOMAIN || d.u64()? != segment {
        return Err(Error::InvalidRecord);
    }
    let capsule = digest(&mut d)?;
    let capture = interval(&mut d)?;
    let reliable = d.bool()?;
    let gap = d.bool()?;
    if !d.bool()? {
        if !tolerant || screened {
            return Err(Error::InvalidRecord);
        }
        let reason = d.text()?;
        if reason.is_empty() || reason.len() > 128 || !reason.starts_with("ERR-") {
            return Err(Error::InvalidRecord);
        }
        d.ensure_finished()?;
        return Ok(());
    }
    let _epoch = d.u64()?;
    let dimensions = [d.u32()?, d.u32()?];
    let pixels = u64::from(dimensions[0]) * u64::from(dimensions[1]);
    if dimensions.iter().any(|&v| v == 0 || v > 4096) || pixels > 4_194_304 {
        return Err(Error::InvalidRecord);
    }
    let luma = digest(&mut d)?;
    let _baseline = d.bool()?;
    for _ in 0..count(&mut d, 64)? {
        let mut geometry = [0_f64; 4];
        for v in &mut geometry {
            *v = f64::from_bits(d.u64()?);
        }
        if geometry.iter().any(|v| !v.is_finite()) || geometry[2] <= 0.0 || geometry[3] <= 0.0 {
            return Err(Error::InvalidRecord);
        }
    }
    let mut prior = 0;
    for _ in 0..count(&mut d, 64)? {
        let id = d.u64()?;
        if id <= prior || d.u8()? > 2 {
            return Err(Error::InvalidRecord);
        }
        prior = id;
        let _hits = d.u32()?;
        let _misses = d.u32()?;
        let mut geometry = [0_f64; 6];
        for v in &mut geometry {
            *v = f64::from_bits(d.u64()?);
        }
        if geometry.iter().any(|v| !v.is_finite()) || geometry[4] <= 0.0 || geometry[5] <= 0.0 {
            return Err(Error::InvalidRecord);
        }
    }
    if screened {
        if !reliable || gap || d.text()? != "sensor_health" {
            return Err(Error::InvalidRecord);
        }
        let observation = d.bytes()?;
        if observation.len() > 2048 {
            return Err(Error::Limit);
        }
        let mut h = CanonicalDecoder::new(observation);
        if h.text()? != "fss.sensor_health.observation.v1" || digest(&mut h)? != policy_digest() {
            return Err(Error::UnsupportedProfile);
        }
        let _source = digest(&mut h)?;
        if h.u64()? != segment || digest(&mut h)? != capsule || digest(&mut h)? != luma {
            return Err(Error::InvalidRecord);
        }
        if h.bool()? {
            let _predecessor = digest(&mut h)?;
        }
        if interval(&mut h)? != capture || [h.u32()?, h.u32()?] != dimensions {
            return Err(Error::InvalidRecord);
        }
        let _reset = h.bool()?;
        if h.u64()? != pixels || h.u64()? > pixels || h.u64()? > pixels {
            return Err(Error::InvalidRecord);
        }
        let _contrast = h.u8()?;
        let repetitions = h.u32()?;
        if repetitions == 0 || repetitions as usize > MAX_LONG_DWELL_FRAMES {
            return Err(Error::InvalidRecord);
        }
        let finding_count = h.u32()?;
        if finding_count > FINDINGS.len() as u32 {
            return Err(Error::Limit);
        }
        // The publishing gate forbids every finding, not merely an unknown finding name.
        if finding_count != 0 {
            return Err(Error::InvalidRecord);
        }
        h.ensure_finished()?;
    }
    d.ensure_finished()?;
    Ok(())
}

pub(super) fn episode_analysis(bytes: &[u8]) -> Result<ContentDigest> {
    if bytes.len() > 2048 {
        return Err(Error::Limit);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != EPISODE_DOMAIN {
        return Err(Error::UnsupportedProfile);
    }
    let root = digest(&mut d)?;
    let zone = d.text()?;
    if zone.is_empty()
        || zone.len() > 64
        || !zone
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(Error::InvalidRecord);
    }
    let _epoch = d.u64()?;
    if d.u64()? == 0 {
        return Err(Error::InvalidRecord);
    }
    let first = (d.u64()?, interval(&mut d)?);
    let trigger = (d.u64()?, interval(&mut d)?);
    let last = (d.u64()?, interval(&mut d)?);
    let observations = d.u64()?;
    let trigger_minimum = decimal(&mut d)?;
    let minimum = decimal(&mut d)?;
    d.ensure_finished()?;
    if first.0 >= trigger.0
        || trigger.0 > last.0
        || last.0.checked_sub(first.0).and_then(|n| n.checked_add(1)) != Some(observations)
        || observations > MAX_LONG_DWELL_FRAMES as u64
        || trigger_minimum != elapsed(first.1, trigger.1)
        || minimum != elapsed(first.1, last.1)
        || trigger_minimum == 0
        || minimum < trigger_minimum
    {
        return Err(Error::InvalidRecord);
    }
    Ok(root)
}
