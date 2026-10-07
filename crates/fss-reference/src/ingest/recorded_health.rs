#![forbid(unsafe_code)]
//! Conservative recorded-pipeline health admission and source-linked measurement receipts.
//!
//! The fixed visual screen is a suspicion signal, not a health or tamper certificate. A
//! temporal finding withdraws its complete qualifying run, including the prefix measured
//! before the finding became available. The recorded pipeline discards every track touching
//! that run and restarts its background model and tracker before admitting later frames.

use std::collections::BTreeSet;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncoder, CaptureInterval, ContentDigest,
    ContractError,
};

use super::sensor_health::{
    HealthError, HealthFinding, HealthFrame, HealthObservation, HealthScreen, MAX_HEALTH_FRAMES,
    MAX_HEALTH_PIXELS, POLICY_NAME, policy_digest,
};
use crate::ReplayCx;

mod coverage;
pub use coverage::RecordedHealthCoverageReceipt;

/// Maximum bytes admitted for one complete 128-frame measurement receipt.
pub const MAX_RECORDED_HEALTH_BYTES: usize = 128 * 1024;
const DOMAIN: &str = "fss.recorded_sensor_health.v1";
const ADMISSION_POLICY: &str = concat!(
    "whole-qualifying-run:discard-touched-tracks:withdraw-touched-track-spans:",
    "restart-background-and-tracker:v1",
);

/// Explicit opt-in health admission policy for a recorded watch or corroboration analysis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordedHealthPolicy {
    /// Fixed conservative-v1 measurements and complete-run withdrawal; no health certification.
    ConservativeV1,
}

/// Preserve existing identities unless the caller explicitly enables screening.
pub(crate) fn screened_plan_digest(
    plan: ContentDigest,
    policy: Option<RecordedHealthPolicy>,
) -> ContentDigest {
    match policy {
        None => plan,
        Some(RecordedHealthPolicy::ConservativeV1) => {
            let mut e = CanonicalEncoder::new();
            e.text("fss.recorded_sensor_health_plan.v1");
            e.digest(plan);
            e.digest(policy_digest());
            e.text(ADMISSION_POLICY);
            ContentDigest::sha256(&e.finish())
        }
    }
}

/// Complete bounded health measurements for one recorded source, with no image bytes.
/// A clear summary only means this screen found no qualifying degradation pattern.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedHealthSummary {
    import_identity: ContentDigest,
    import_root: ContentDigest,
    sensor_digest: ContentDigest,
    source_generation: ContentDigest,
    source_gap_segments: BTreeSet<u64>,
    decoder_restart_segments: BTreeSet<u64>,
    observations: Vec<HealthObservation>,
    affected_segments: BTreeSet<u64>,
    withdrawn_track_segments: BTreeSet<u64>,
    samples_used: u64,
}

impl RecordedHealthSummary {
    /// Exact retained import screened.
    #[must_use]
    pub const fn import_identity(&self) -> ContentDigest {
        self.import_identity
    }
    /// Retained import root screened.
    #[must_use]
    pub const fn import_root(&self) -> ContentDigest {
        self.import_root
    }
    /// Digest of the source capsule sensor identity.
    #[must_use]
    pub const fn sensor_digest(&self) -> ContentDigest {
        self.sensor_digest
    }
    /// Exact watch plan generation, including policy and current privacy binding.
    #[must_use]
    pub const fn source_generation(&self) -> ContentDigest {
        self.source_generation
    }
    /// Original manifest source gaps inside the requested range.
    #[must_use]
    pub fn source_gap_segments(&self) -> &BTreeSet<u64> {
        &self.source_gap_segments
    }
    /// Explicit native decoder recovery boundaries, independent of health tracking resets.
    #[must_use]
    pub fn decoder_restart_segments(&self) -> &BTreeSet<u64> {
        &self.decoder_restart_segments
    }
    /// Tracker/background resets required by actual decoder gaps and health recovery.
    /// Source segment numbers identify frames; temporal transitions follow observation order.
    pub(crate) fn tracking_restart_segments(&self) -> BTreeSet<u64> {
        let mut restarts = self.decoder_restart_segments.clone();
        for pair in self.observations.windows(2) {
            if !pair[0].findings.is_empty() && pair[1].findings.is_empty() {
                restarts.insert(pair[1].segment);
            }
        }
        restarts
    }

    /// Complete frame spans of tracks discarded because they touched a degradation run.
    /// Earlier positive or uncertain observations must never become absence evidence.
    #[must_use]
    pub fn withdrawn_track_segments(&self) -> &BTreeSet<u64> {
        &self.withdrawn_track_segments
    }
    /// Whether either measured degradation or a withdrawn track prevents coverage.
    #[must_use]
    pub fn excludes_coverage(&self, segment: usize) -> bool {
        self.affects(segment) || self.withdrawn_track_segments.contains(&(segment as u64))
    }

    pub(crate) fn withdraw_track_span(
        &mut self,
        first: usize,
        last: usize,
    ) -> Result<(), ContractError> {
        let first = self
            .observations
            .iter()
            .position(|frame| frame.segment == first as u64)
            .ok_or(ContractError::InvalidIdentifier)?;
        let last = self
            .observations
            .iter()
            .position(|frame| frame.segment == last as u64)
            .ok_or(ContractError::InvalidIdentifier)?;
        if first > last
            || !self.observations[first..=last]
                .iter()
                .any(|frame| self.affected_segments.contains(&frame.segment))
        {
            return Err(ContractError::InvalidIdentifier);
        }
        self.withdrawn_track_segments.extend(
            self.observations[first..=last]
                .iter()
                .map(|frame| frame.segment),
        );
        Ok(())
    }

    /// Exact source-linked measurements in decoder output order.
    #[must_use]
    pub fn observations(&self) -> &[HealthObservation] {
        &self.observations
    }

    /// Every segment in a complete qualifying degradation run.
    #[must_use]
    pub fn affected_segments(&self) -> &BTreeSet<u64> {
        &self.affected_segments
    }

    /// Whether this segment is withheld from tracking and coverage.
    #[must_use]
    pub fn affects(&self, segment: usize) -> bool {
        self.affected_segments.contains(&(segment as u64))
    }

    /// Luma samples charged to the one whole-recording screen.
    #[must_use]
    pub const fn samples_used(&self) -> u64 {
        self.samples_used
    }

    /// Fixed measurement policy identity.
    #[must_use]
    pub fn policy_digest(&self) -> ContentDigest {
        policy_digest()
    }

    /// Canonical receipt identity, binding measurements, continuity and withdrawn segments.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }

    /// Complete canonical receipt; original capsule and decoded-luma digests are retained.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.text(DOMAIN);
        e.digest(policy_digest());
        e.text(ADMISSION_POLICY);
        e.digest(self.import_identity);
        e.digest(self.import_root);
        e.digest(self.sensor_digest);
        e.digest(self.source_generation);
        e.u64(self.source_gap_segments.len() as u64);
        for segment in &self.source_gap_segments {
            e.u64(*segment);
        }
        e.u64(self.decoder_restart_segments.len() as u64);
        for segment in &self.decoder_restart_segments {
            e.u64(*segment);
        }
        e.u64(self.samples_used);
        e.u64(self.observations.len() as u64);
        for observation in &self.observations {
            e.bytes(&observation.canonical_bytes());
        }
        e.u64(self.affected_segments.len() as u64);
        for segment in &self.affected_segments {
            e.u64(*segment);
        }
        e.u64(self.withdrawn_track_segments.len() as u64);
        for segment in &self.withdrawn_track_segments {
            e.u64(*segment);
        }
        e.finish()
    }

    /// Decode bounded bytes, rederive every temporal finding and complete-run withdrawal, and
    /// require exact canonical encoding. The enclosing coverage record verifies custody digest.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_RECORDED_HEALTH_BYTES {
            return Err(ContractError::BudgetExhausted);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != DOMAIN || d.digest()? != policy_digest() || d.text()? != ADMISSION_POLICY {
            return Err(ContractError::InvalidIdentifier);
        }
        let import_identity = d.digest()?;
        let import_root = d.digest()?;
        let sensor_digest = d.digest()?;
        let source_generation = d.digest()?;
        let source_gap_segments = decode_segments(&mut d)?;
        let decoder_restart_segments = decode_segments(&mut d)?;
        let samples_used = d.u64()?;
        let count = bounded_count(d.u64()?)?;
        let mut observations = Vec::with_capacity(count);
        for _ in 0..count {
            observations.push(decode_observation(d.bytes()?)?);
        }
        let affected_count = bounded_count(d.u64()?)?;
        let mut affected_segments = BTreeSet::new();
        for _ in 0..affected_count {
            if !affected_segments.insert(d.u64()?) {
                return Err(ContractError::NonCanonicalOrdering);
            }
        }
        let withdrawn_track_segments = decode_segments(&mut d)?;
        d.ensure_finished()?;
        let summary = Self {
            import_identity,
            import_root,
            sensor_digest,
            source_generation,
            source_gap_segments,
            decoder_restart_segments,
            observations,
            affected_segments,
            withdrawn_track_segments,
            samples_used,
        };
        summary.validate()?;
        if summary.to_bytes() != bytes {
            return Err(ContractError::NonCanonicalOrdering);
        }
        Ok(summary)
    }

    /// Verify decoder order, frame bounds, chained predecessors, exact temporal counters and
    /// findings, cumulative work, and the complete affected-run set.
    pub fn validate(&self) -> Result<(), ContractError> {
        let affected = affected_segments(&self.observations)?;
        if self.observations[0].source_generation != self.source_generation
            || self.source_gap_segments.len() > MAX_HEALTH_FRAMES
            || self.decoder_restart_segments.len() > MAX_HEALTH_FRAMES
            || [
                self.import_identity,
                self.import_root,
                self.sensor_digest,
                self.source_generation,
            ]
            .iter()
            .any(|digest| digest.algorithm() != fss_core::DigestAlgorithm::Sha256)
        {
            return Err(ContractError::InvalidIdentifier);
        }
        for (index, observation) in self.observations.iter().enumerate() {
            let expected_reset = index == 0
                || self.source_gap_segments.contains(&observation.segment)
                || self.decoder_restart_segments.contains(&observation.segment);
            if observation.baseline_reset != expected_reset {
                return Err(ContractError::InvalidIdentifier);
            }
        }
        let observed_segments: BTreeSet<_> = self
            .observations
            .iter()
            .map(|frame| frame.segment)
            .collect();
        if !self.withdrawn_track_segments.is_subset(&observed_segments)
            || !self.decoder_restart_segments.is_subset(&observed_segments)
        {
            return Err(ContractError::InvalidIdentifier);
        }
        // Every contiguous withdrawal component must touch a measured degradation run.
        let mut withdrawing = false;
        let mut touches = false;
        for observation in &self.observations {
            if self.withdrawn_track_segments.contains(&observation.segment) {
                withdrawing = true;
                touches |= affected.contains(&observation.segment);
            } else if withdrawing {
                if !touches {
                    return Err(ContractError::InvalidIdentifier);
                }
                withdrawing = false;
                touches = false;
            }
        }
        if withdrawing && !touches {
            return Err(ContractError::InvalidIdentifier);
        }
        let used = self
            .observations
            .iter()
            .try_fold(0_u64, |sum, observation| {
                sum.checked_add(observation.samples)
                    .ok_or(ContractError::BudgetExhausted)
            })?;
        if affected != self.affected_segments || used != self.samples_used {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.to_bytes().len() > MAX_RECORDED_HEALTH_BYTES {
            return Err(ContractError::BudgetExhausted);
        }
        Ok(())
    }

    /// Bounded diagnostics with explicit uncertainty. No pixels or sensor location are exposed.
    #[must_use]
    pub fn to_json(&self) -> String {
        let affected = self
            .affected_segments
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>();
        let withdrawn = self
            .withdrawn_track_segments
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>();
        let gaps = self
            .source_gap_segments
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>();
        let restarts = self
            .decoder_restart_segments
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>();
        let observations = self
            .observations
            .iter()
            .map(|observation| {
                let findings = observation
                    .findings
                    .iter()
                    .map(|finding| format!("\"{}\"", finding.as_str()))
                    .collect::<Vec<_>>();
                let predecessor = observation
                    .predecessor_digest
                    .map_or_else(|| "null".to_owned(), |digest| format!("\"{digest}\""));
                format!(
                    concat!(
                        "{{\"segment\":{},\"source_generation\":\"{}\",\"capsule_digest\":\"{}\",",
                        "\"luma_digest\":\"{}\",\"observation_digest\":\"{}\",",
                        "\"predecessor_digest\":{},\"capture_ns\":[{},{}],\"dimensions\":[{},{}],",
                        "\"baseline_reset\":{},\"samples\":{},\"dark_samples\":{},",
                        "\"bright_samples\":{},\"contrast_span\":{},\"repeated_frames\":{},",
                        "\"findings\":[{}]}}"
                    ),
                    observation.segment,
                    observation.source_generation,
                    observation.capsule_digest,
                    observation.luma_digest,
                    observation.digest(),
                    predecessor,
                    observation.capture.earliest.0,
                    observation.capture.latest.0,
                    observation.dimensions[0],
                    observation.dimensions[1],
                    observation.baseline_reset,
                    observation.samples,
                    observation.dark_samples,
                    observation.bright_samples,
                    observation.contrast_span,
                    observation.repeated_frames,
                    findings.join(","),
                )
            })
            .collect::<Vec<_>>();
        format!(
            concat!(
                "{{\"policy\":\"{}\",\"policy_digest\":\"{}\",\"digest\":\"{}\",",
                "\"status\":\"{}\",\"frames_screened\":{},\"samples_used\":{},",
                "\"health_certified\":false,\"affected_segments\":[{}],",
                "\"withdrawn_track_segments\":[{}],",
                "\"import_identity\":\"{}\",\"import_root\":\"{}\",\"sensor_digest\":\"{}\",",
                "\"source_generation\":\"{}\",\"source_gap_segments\":[{}],",
                "\"decoder_restart_segments\":[{}],\"observations\":[{}]}}"
            ),
            POLICY_NAME,
            policy_digest(),
            self.digest(),
            if self.affected_segments.is_empty() {
                "clear_screen_not_health_evidence"
            } else {
                "suspected_degradation"
            },
            self.observations.len(),
            self.samples_used,
            affected.join(","),
            withdrawn.join(","),
            self.import_identity,
            self.import_root,
            self.sensor_digest,
            self.source_generation,
            gaps.join(","),
            restarts.join(","),
            observations.join(","),
        )
    }
}

fn bounded_count(value: u64) -> Result<usize, ContractError> {
    usize::try_from(value)
        .ok()
        .filter(|count| *count <= MAX_HEALTH_FRAMES)
        .ok_or(ContractError::BudgetExhausted)
}

fn decode_segments(d: &mut CanonicalDecoder<'_>) -> Result<BTreeSet<u64>, ContractError> {
    let count = bounded_count(d.u64()?)?;
    let mut segments = BTreeSet::new();
    for _ in 0..count {
        if !segments.insert(d.u64()?) {
            return Err(ContractError::NonCanonicalOrdering);
        }
    }
    Ok(segments)
}

fn decode_observation(bytes: &[u8]) -> Result<HealthObservation, ContractError> {
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != "fss.sensor_health.observation.v1" || d.digest()? != policy_digest() {
        return Err(ContractError::InvalidIdentifier);
    }
    let source_generation = d.digest()?;
    let segment = d.u64()?;
    let capsule_digest = d.digest()?;
    let luma_digest = d.digest()?;
    let predecessor_digest = if d.bool()? { Some(d.digest()?) } else { None };
    let capture = CaptureInterval::decode_canonical(&mut d)?;
    let dimensions = [d.u32()?, d.u32()?];
    let baseline_reset = d.bool()?;
    let samples = d.u64()?;
    let dark_samples = d.u64()?;
    let bright_samples = d.u64()?;
    let contrast_span = d.u8()?;
    let repeated_frames = d.u32()?;
    let count = d.u32()?;
    if count > 4 {
        return Err(ContractError::BudgetExhausted);
    }
    let mut findings = Vec::with_capacity(count as usize);
    for _ in 0..count {
        findings.push(match d.text()? {
            "persistent_dark_field" => HealthFinding::PersistentDarkField,
            "persistent_bright_field" => HealthFinding::PersistentBrightField,
            "exact_frame_repetition" => HealthFinding::ExactFrameRepetition,
            "contrast_collapse" => HealthFinding::ContrastCollapse,
            _ => return Err(ContractError::InvalidIdentifier),
        });
    }
    d.ensure_finished()?;
    let observation = HealthObservation {
        source_generation,
        segment,
        capsule_digest,
        luma_digest,
        predecessor_digest,
        capture,
        dimensions,
        baseline_reset,
        samples,
        dark_samples,
        bright_samples,
        contrast_span,
        repeated_frames,
        findings,
    };
    if observation.canonical_bytes() != bytes {
        return Err(ContractError::NonCanonicalOrdering);
    }
    Ok(observation)
}

/// Recompute the fixed screen from its recorded measurements, including every qualifying
/// prefix. This does not certify the measurements; their authority is the retained source chain.
fn affected_segments(observations: &[HealthObservation]) -> Result<BTreeSet<u64>, ContractError> {
    if observations.is_empty() || observations.len() > MAX_HEALTH_FRAMES {
        return Err(ContractError::BudgetExhausted);
    }
    let first = &observations[0];
    let mut previous: Option<&HealthObservation> = None;
    let mut segments = BTreeSet::new();
    let mut dark_run = 0_usize;
    let mut bright_run = 0_usize;
    let mut contrast_run = 0_usize;
    let mut textured = false;
    let mut affected = BTreeSet::new();
    for (index, observation) in observations.iter().enumerate() {
        let [width, height] = observation.dimensions;
        let count = u64::from(width) * u64::from(height);
        if width == 0
            || height == 0
            || width > 4096
            || height > 4096
            || count > MAX_HEALTH_PIXELS as u64
            || count != observation.samples
            || observation.dark_samples > count
            || observation.bright_samples > count
            || observation.dark_samples + observation.bright_samples > count
            || observation.capture.earliest > observation.capture.latest
            || observation.source_generation != first.source_generation
            || observation.dimensions != first.dimensions
            || !segments.insert(observation.segment)
        {
            return Err(ContractError::InvalidIdentifier);
        }
        if observation.baseline_reset {
            previous = None;
            dark_run = 0;
            bright_run = 0;
            contrast_run = 0;
            textured = false;
        }
        if observation.baseline_reset != previous.is_none()
            || observation.predecessor_digest != previous.map(HealthObservation::digest)
        {
            return Err(ContractError::InvalidIdentifier);
        }
        dark_run = if observation.dark_samples * 1_000_000 >= count * 995_000 {
            dark_run + 1
        } else {
            0
        };
        bright_run = if observation.bright_samples * 1_000_000 >= count * 995_000 {
            bright_run + 1
        } else {
            0
        };
        contrast_run = if textured && observation.contrast_span <= 2 {
            contrast_run + 1
        } else {
            0
        };
        let repeated = previous
            .filter(|p| p.luma_digest == observation.luma_digest)
            .map_or(1, |p| p.repeated_frames + 1);
        let mut expected = Vec::new();
        for (finding, run, threshold) in [
            (HealthFinding::PersistentDarkField, dark_run, 3),
            (HealthFinding::PersistentBrightField, bright_run, 3),
            (HealthFinding::ExactFrameRepetition, repeated as usize, 8),
            (HealthFinding::ContrastCollapse, contrast_run, 3),
        ] {
            if run >= threshold {
                expected.push(finding);
                let start = (index + 1)
                    .checked_sub(run)
                    .ok_or(ContractError::InvalidIdentifier)?;
                affected.extend(
                    observations[start..=index]
                        .iter()
                        .map(|frame| frame.segment),
                );
            }
        }
        if observation.repeated_frames != repeated || observation.findings != expected {
            return Err(ContractError::InvalidIdentifier);
        }
        textured |= observation.contrast_span >= 32;
        previous = Some(observation);
    }
    Ok(affected)
}

/// One screen per complete analysis: decode/health recovery never replenishes this budget.
pub(crate) struct RecordedHealthScreen {
    import_identity: ContentDigest,
    import_root: ContentDigest,
    sensor_digest: ContentDigest,
    source_generation: ContentDigest,
    source_gap_segments: BTreeSet<u64>,
    screen: HealthScreen,
    maximum_frames: usize,
    observations: Vec<HealthObservation>,
}

impl RecordedHealthScreen {
    pub(crate) fn new(
        frames: usize,
        import_identity: ContentDigest,
        import_root: ContentDigest,
        sensor: &str,
        source_generation: ContentDigest,
        source_gap_segments: BTreeSet<u64>,
    ) -> Result<Self, HealthError> {
        if !(1..=MAX_HEALTH_FRAMES).contains(&frames)
            || source_gap_segments.len() > MAX_HEALTH_FRAMES
        {
            return Err(HealthError::Limit);
        }
        Ok(Self {
            import_identity,
            import_root,
            sensor_digest: ContentDigest::sha256(sensor.as_bytes()),
            source_generation,
            source_gap_segments,
            screen: HealthScreen::with_frame_limit(
                frames as u64 * MAX_HEALTH_PIXELS as u64,
                frames,
            )?,
            maximum_frames: frames,
            observations: Vec::with_capacity(frames),
        })
    }

    pub(crate) fn observe(
        &mut self,
        frame: HealthFrame<'_>,
        cx: &ReplayCx,
    ) -> Result<bool, HealthError> {
        if frame.source_generation != self.source_generation {
            return Err(HealthError::ReplayedSource);
        }
        if self.observations.len() >= self.maximum_frames {
            return Err(HealthError::Limit);
        }
        if self.observations.iter().any(|observation| {
            observation.source_generation == frame.source_generation
                && observation.segment == frame.segment
        }) {
            return Err(HealthError::ReplayedSource);
        }
        let observation = self.screen.observe(frame, cx)?;
        let degraded = !observation.findings.is_empty();
        self.observations.push(observation);
        Ok(degraded)
    }

    pub(crate) fn finish(
        self,
        decoder_restarts: &[usize],
    ) -> Result<RecordedHealthSummary, ContractError> {
        if decoder_restarts.len() > MAX_HEALTH_FRAMES {
            return Err(ContractError::BudgetExhausted);
        }
        let summary = RecordedHealthSummary {
            import_identity: self.import_identity,
            import_root: self.import_root,
            sensor_digest: self.sensor_digest,
            source_generation: self.source_generation,
            source_gap_segments: self.source_gap_segments,
            decoder_restart_segments: decoder_restarts
                .iter()
                .map(|segment| *segment as u64)
                .collect(),
            affected_segments: affected_segments(&self.observations)?,
            withdrawn_track_segments: BTreeSet::new(),
            observations: self.observations,
            samples_used: self.screen.samples_used(),
        };
        summary.validate()?;
        Ok(summary)
    }
}

#[cfg(test)]
mod tests;
