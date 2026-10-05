#![forbid(unsafe_code)]
//! Whole-scan accumulation of the existing conservative visual-degradation measurements.

use super::{Result, WatchError, json};
use crate::ReplayCx;
use crate::ingest::recorded_decode::RecordedDecodeError;
use crate::ingest::sensor_health::{
    HealthError, HealthFinding, HealthFrame, HealthObservation, HealthScreen, POLICY_NAME,
    policy_digest,
};
use fss_core::{CanonicalEncoder, ContentDigest};

/// Maximum complete finding runs in one report; overflow refuses, never truncates diagnostics.
pub const MAX_HEALTH_FINDING_RUNS: usize = 128;
/// Explicit refusal reason for the opt-in whole-recording publication gate.
pub const HEALTH_PUBLICATION_BLOCKED: &str =
    "sensor-health findings or incomplete screening block long-dwell publication";
const FINDINGS: [HealthFinding; 4] = [
    HealthFinding::PersistentDarkField,
    HealthFinding::PersistentBrightField,
    HealthFinding::ExactFrameRepetition,
    HealthFinding::ContrastCollapse,
];

/// A maximal consecutive run of one finding, not an assertion that the sensor was tampered with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthFindingRun {
    /// Existing conservative-v1 diagnostic.
    pub finding: HealthFinding,
    /// First source position where the finding's threshold was satisfied.
    pub first_segment: u64,
    /// Last consecutive source position with the finding.
    pub last_segment: u64,
    /// Number of frames on which this finding was actually produced.
    pub affected_frames: u64,
    /// First canonical measurement, retained in the shared analysis trace.
    pub first_observation: ContentDigest,
    /// Last canonical measurement, retained in the shared analysis trace.
    pub last_observation: ContentDigest,
}

/// Complete opt-in screening diagnostics; a no-findings result is not a health certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LongDwellHealthSummary {
    complete: bool,
    frames: usize,
    samples: u64,
    findings: Vec<HealthFindingRun>,
}
impl LongDwellHealthSummary {
    /// Whether every requested position was screened with admitted continuity and timing.
    pub const fn complete(&self) -> bool { self.complete }
    /// Successfully screened decoded frames.
    pub const fn frames_screened(&self) -> usize { self.frames }
    /// Actual luma samples screened, independent of the foreground-processing counter.
    pub const fn samples_screened(&self) -> u64 { self.samples }
    /// Complete ordered finding runs. Endpoint digests resolve in the per-frame trace.
    pub fn findings(&self) -> &[HealthFindingRun] { &self.findings }
    /// Suspected degradation or incomplete screening forbids this report's event publication.
    pub fn publication_blocked(&self) -> bool { !self.complete || !self.findings.is_empty() }
    /// Diagnostic classification, never `healthy`, `tampered` or `absence`.
    pub fn status(&self) -> &'static str {
        if !self.findings.is_empty() { "suspected_degradation" }
        else if !self.complete { "incomplete" }
        else { "no_findings" }
    }
    pub(super) fn encode(&self, e: &mut CanonicalEncoder) {
        e.bool(self.complete);
        e.u64(self.frames as u64);
        e.u64(self.samples);
        e.u64(self.findings.len() as u64);
        for run in &self.findings {
            e.text(run.finding.as_str());
            e.u64(run.first_segment);
            e.u64(run.last_segment);
            e.u64(run.affected_frames);
            e.digest(run.first_observation);
            e.digest(run.last_observation);
        }
    }
    pub(super) fn to_json(&self) -> String {
        let findings = self.findings.iter().map(|run| format!(
            "{{\"finding\":{},\"first_segment\":{},\"last_segment\":{},\"affected_frames\":{},\"first_observation_digest\":{},\"last_observation_digest\":{}}}",
            json(run.finding.as_str()), run.first_segment, run.last_segment, run.affected_frames,
            json(&run.first_observation.to_text()), json(&run.last_observation.to_text()),
        )).collect::<Vec<_>>().join(",");
        format!(concat!(
            "{{\"policy\":{},\"policy_digest\":{},\"status\":{},\"complete\":{},",
            "\"frames_screened\":{},\"samples_screened\":{},\"publication_blocked\":{},",
            "\"findings\":[{}],\"measurements_embedded_in_analysis\":true,",
            "\"healthy_proved\":false,\"tamper_proved\":false,\"absence_certifiable\":false}}"),
            json(POLICY_NAME), json(&policy_digest().to_text()), json(self.status()), self.complete,
            self.frames, self.samples, self.publication_blocked(), findings,
        )
    }
}

fn failure(error: HealthError) -> WatchError {
    match error {
        HealthError::Limit => WatchError::Limit,
        HealthError::Cancelled => RecordedDecodeError::Cancelled.into(),
        HealthError::InvalidImage | HealthError::ReplayedSource =>
            RecordedDecodeError::InvalidReceipt.into(),
    }
}

#[derive(Debug)]
pub(super) struct Screening {
    screen: HealthScreen,
    summary: LongDwellHealthSummary,
    active: [Option<usize>; 4],
    reset_pending: bool,
}
impl Screening {
    pub(super) fn new(frames: usize, samples: u64) -> Result<Self> {
        Ok(Self {
            screen: HealthScreen::with_frame_limit(samples, frames).map_err(failure)?,
            summary: LongDwellHealthSummary {
                complete: true, frames: 0, samples: 0, findings: Vec::new(),
            },
            active: [None; 4],
            reset_pending: false,
        })
    }
    /// Reset comparisons only. The same screen owns the whole-scan budget and replay set.
    pub(super) fn discontinuity(&mut self) {
        self.summary.complete = false;
        self.active = [None; 4];
        self.reset_pending = true;
    }
    pub(super) fn observe(
        &mut self,
        mut frame: HealthFrame<'_>,
        time_reliable: bool,
        cx: &ReplayCx,
    ) -> Result<HealthObservation> {
        frame.gap_before |= self.reset_pending;
        let observation = self.screen.observe(frame, cx).map_err(failure)?;
        if observation.baseline_reset { self.active = [None; 4]; }
        self.reset_pending = false;
        self.summary.complete &= time_reliable && !frame.gap_before;
        self.summary.frames += 1;
        self.summary.samples = self.screen.samples_used();
        self.accept(&observation)?;
        Ok(observation)
    }
    fn accept(&mut self, observation: &HealthObservation) -> Result<()> {
        let digest = observation.digest();
        for (kind, finding) in FINDINGS.iter().enumerate() {
            if !observation.findings.contains(finding) {
                self.active[kind] = None;
                continue;
            }
            if let Some(index) = self.active[kind] {
                let run = &mut self.summary.findings[index];
                if run.last_segment.checked_add(1) == Some(observation.segment) {
                    run.last_segment = observation.segment;
                    run.last_observation = digest;
                    run.affected_frames += 1;
                    continue;
                }
            }
            if self.summary.findings.len() == MAX_HEALTH_FINDING_RUNS {
                return Err(WatchError::Limit);
            }
            self.active[kind] = Some(self.summary.findings.len());
            self.summary.findings.push(HealthFindingRun {
                finding: *finding,
                first_segment: observation.segment,
                last_segment: observation.segment,
                affected_frames: 1,
                first_observation: digest,
                last_observation: digest,
            });
        }
        Ok(())
    }
    pub(super) fn finish(mut self, requested: usize) -> LongDwellHealthSummary {
        self.summary.complete &= self.summary.frames == requested;
        self.summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::{CaptureInterval, TimestampNs};

    fn observed(segment: u64, findings: Vec<HealthFinding>) -> HealthObservation {
        HealthObservation {
            source_generation: ContentDigest::sha256(b"source"), segment,
            capsule_digest: ContentDigest::sha256(&segment.to_be_bytes()),
            luma_digest: ContentDigest::sha256(b"masked luma"), predecessor_digest: None,
            capture: CaptureInterval::point(TimestampNs(i128::from(segment))),
            dimensions: [4, 4], baseline_reset: false, samples: 16,
            dark_samples: 0, bright_samples: 0, contrast_span: 0,
            repeated_frames: 8, findings,
        }
    }

    #[test]
    fn summaries_partition_each_finding_without_losing_intermittent_runs() -> Result<()> {
        let mut screen = Screening::new(10, 160)?;
        for (segment, findings) in [
            vec![HealthFinding::ExactFrameRepetition],
            vec![HealthFinding::ExactFrameRepetition, HealthFinding::ContrastCollapse],
            vec![HealthFinding::ContrastCollapse],
            vec![],
            vec![HealthFinding::ExactFrameRepetition],
        ].into_iter().enumerate() {
            screen.accept(&observed(segment as u64, findings))?;
        }
        let runs = screen.summary.findings();
        assert_eq!(runs.len(), 3);
        assert_eq!((runs[0].first_segment, runs[0].last_segment, runs[0].affected_frames), (0, 1, 2));
        assert_eq!((runs[1].first_segment, runs[1].last_segment, runs[1].affected_frames), (1, 2, 2));
        assert_eq!((runs[2].first_segment, runs[2].last_segment, runs[2].affected_frames), (4, 4, 1));
        assert!(screen.summary.publication_blocked());
        Ok(())
    }

    #[test]
    fn a_diagnostic_bound_refuses_instead_of_hiding_a_finding() -> Result<()> {
        let mut screen = Screening::new(300, 4800)?;
        for segment in 0..MAX_HEALTH_FINDING_RUNS {
            screen.accept(&observed(segment as u64 * 2, vec![HealthFinding::ExactFrameRepetition]))?;
        }
        assert!(matches!(screen.accept(&observed(256, vec![HealthFinding::ExactFrameRepetition])), Err(WatchError::Limit)));
        Ok(())
    }

    #[test]
    fn missing_or_discontinuous_positions_never_form_a_complete_screen() -> Result<()> {
        let screen = Screening::new(1, 16)?;
        assert!(!screen.finish(1).complete());
        let mut screen = Screening::new(1, 16)?;
        screen.summary.frames = 1;
        screen.discontinuity();
        let summary = screen.finish(1);
        assert_eq!(summary.status(), "incomplete");
        assert!(summary.publication_blocked());
        Ok(())
    }
}
