#![forbid(unsafe_code)]
//! Opt-in source-bound visual degradation holds. These measurements can withhold
//! coverage and cognition; a clear screen cannot establish either coverage or absence.

use fss_core::{CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest, TimestampNs};
use fss_reference::ingest::sensor_health::{
    HealthError, HealthFinding, HealthFrame, HealthObservation, POLICY_NAME, policy_bytes,
    policy_digest, sequential::SequentialHealthScreen,
};

use crate::{CameraFrame, DaemonError};

/// Consecutive fresh clear measurements needed to release this policy's own hold.
/// Eight includes the longest fixed-policy finding horizon (exact repetition).
pub const SENSOR_HEALTH_CLEAR_FRAMES: u8 = 8;

/// Explicit visual-degradation policy selection. No policy is enabled by default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensorHealthPolicy {
    /// Fixed extreme clipping, exact repetition, and contrast-collapse screening.
    ConservativeV1,
}

impl SensorHealthPolicy {
    /// Parses only an exact, immutable supported policy name.
    pub fn parse(value: &str) -> Result<Self, DaemonError> {
        match value {
            POLICY_NAME => Ok(Self::ConservativeV1),
            _ => Err(DaemonError::InvalidConfig {
                detail: "sensor health policy must be conservative-v1".to_owned(),
            }),
        }
    }

    /// Stable policy name for diagnostics and receipts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConservativeV1 => POLICY_NAME,
        }
    }
}

/// State of this visual screen, independent of transport and source continuity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensorHealthState {
    /// Awaiting fresh observations after startup or a source gap.
    Warming,
    /// A finding or refused measurement excludes this source from coverage/cognition.
    Held,
    /// This screen has no current hold. Other coverage requirements still apply.
    Clear,
}

impl SensorHealthState {
    /// Stable spelling; clear never means independently certified healthy.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Warming => "warming",
            Self::Held => "held",
            Self::Clear => "clear",
        }
    }
}

/// Bounded read-only live screen inspection; contains no retained image pixels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CameraHealthStatus {
    /// Explicitly selected immutable policy.
    pub policy: SensorHealthPolicy,
    /// Screen's current hold state.
    pub state: SensorHealthState,
    /// Fresh successive clear observations in the current continuity segment.
    pub consecutive_clear_frames: u8,
    /// Successful measurements since daemon startup, including previous generations.
    pub observations: u64,
    /// Completed luma sample work, including failed and cancelled measurement work.
    pub samples: u64,
    /// Most recent successful source-bound measurement digest.
    pub observation_digest: Option<ContentDigest>,
    /// Findings responsible for the hold, retained through recovery warmup.
    pub findings: Vec<HealthFinding>,
    /// Stable refusal reason, retained until a full fresh clear sequence is observed.
    pub refusal: Option<&'static str>,
}

pub(crate) struct HealthTransition {
    pub(crate) evidence: Vec<u8>,
    pub(crate) held: bool,
    pub(crate) reason: &'static str,
}

pub(crate) struct CameraHealth {
    status: CameraHealthStatus,
    expected_dimensions: [u32; 2],
    screen: Option<SequentialHealthScreen>,
    generation: Option<ContentDigest>,
    admitted_since: Option<(u64, u64)>,
    latest: Option<HealthObservation>,
    latest_evidence: Option<Vec<u8>>,
    luma: Vec<u8>,
}

impl CameraHealth {
    pub(crate) fn new(policy: SensorHealthPolicy, expected_dimensions: [u32; 2]) -> Self {
        Self {
            status: CameraHealthStatus {
                policy,
                state: SensorHealthState::Warming,
                consecutive_clear_frames: 0,
                observations: 0,
                samples: 0,
                observation_digest: None,
                findings: Vec::new(),
                refusal: None,
            },
            expected_dimensions,
            screen: None,
            generation: None,
            admitted_since: None,
            latest: None,
            latest_evidence: None,
            luma: Vec::new(),
        }
    }

    pub(crate) fn status(&self) -> CameraHealthStatus {
        self.status.clone()
    }

    pub(crate) fn allows_coverage(&self) -> bool {
        self.status.state == SensorHealthState::Clear
    }

    pub(crate) fn admits_frame(&self, frame: &CameraFrame) -> bool {
        self.allows_coverage()
            && self.admitted_since.is_some_and(|(generation, sequence)| {
                frame.stream_generation == generation && frame.sequence >= sequence
            })
    }

    /// Source loss invalidates temporal comparisons and queued cognition admission.
    pub(crate) fn reset(&mut self) {
        self.screen = None;
        self.generation = None;
        self.admitted_since = None;
        self.latest = None;
        self.latest_evidence = None;
        self.status.state = SensorHealthState::Warming;
        self.status.consecutive_clear_frames = 0;
        self.status.observation_digest = None;
        self.status.findings.clear();
        self.status.refusal = None;
    }

    pub(crate) fn evidence(&self) -> Option<&[u8]> {
        self.latest_evidence.as_deref()
    }

    pub(crate) fn observe(
        &mut self,
        frame: &CameraFrame,
        contiguous: bool,
        mut checkpoint: impl FnMut() -> Result<(), HealthError>,
    ) -> Option<HealthTransition> {
        let before = self.status.state;
        let generation = source_generation(frame);
        if self.generation != Some(generation) || !contiguous {
            self.reset();
            self.generation = Some(generation);
            self.screen = Some(SequentialHealthScreen::new(generation));
        }
        let measurement = self.measure(frame, generation, contiguous, &mut checkpoint);
        match measurement {
            Ok(observation) => {
                self.status.observations = self.status.observations.saturating_add(1);
                self.status.observation_digest = Some(observation.digest());
                if observation.findings.is_empty() {
                    self.status.consecutive_clear_frames = self
                        .status
                        .consecutive_clear_frames
                        .saturating_add(1)
                        .min(SENSOR_HEALTH_CLEAR_FRAMES);
                    if self.status.consecutive_clear_frames >= SENSOR_HEALTH_CLEAR_FRAMES {
                        self.status.state = SensorHealthState::Clear;
                        self.status.findings.clear();
                        self.status.refusal = None;
                        self.admitted_since
                            .get_or_insert((frame.stream_generation, frame.sequence));
                    }
                } else {
                    self.status.state = SensorHealthState::Held;
                    self.status.consecutive_clear_frames = 0;
                    self.status.findings = observation.findings.clone();
                    self.status.refusal = None;
                    self.admitted_since = None;
                }
                self.latest = Some(observation);
            }
            Err(error) => {
                self.status.state = SensorHealthState::Held;
                self.status.consecutive_clear_frames = 0;
                self.status.observation_digest = None;
                self.status.findings.clear();
                self.status.refusal = Some(match error {
                    HealthError::InvalidImage => "invalid_image",
                    HealthError::ReplayedSource => "replayed_source",
                    HealthError::Limit => "screen_limit",
                    HealthError::Cancelled => "screen_cancelled",
                });
                self.admitted_since = None;
                self.latest = None;
                // Never compare later measurements across refused decoded input.
                self.screen = Some(SequentialHealthScreen::new(generation));
            }
        }
        let evidence = self.encode_evidence(frame);
        self.latest_evidence = Some(evidence.clone());
        (before != self.status.state).then(|| HealthTransition {
            evidence,
            held: !self.allows_coverage(),
            reason: self.reason(),
        })
    }

    fn measure(
        &mut self,
        frame: &CameraFrame,
        generation: ContentDigest,
        contiguous: bool,
        checkpoint: &mut impl FnMut() -> Result<(), HealthError>,
    ) -> Result<HealthObservation, HealthError> {
        checkpoint()?;
        // Validate before allocating scratch or iterating pixels. A resolution change
        // requires a matching manifest/decoder generation, never silent reinterpretation.
        if frame.dimensions != self.expected_dimensions
            || frame.dimensions.iter().any(|dimension| *dimension > 4096)
            || frame.pixels.validate(frame.dimensions).is_err()
        {
            return Err(HealthError::InvalidImage);
        }
        frame.pixels.extract_luma_into(&mut self.luma);
        let screen = self.screen.as_mut().ok_or(HealthError::ReplayedSource)?;
        let before_samples = screen.samples_used();
        let result = screen.observe_with_checkpoint(
            HealthFrame {
                source_generation: generation,
                segment: frame.sequence,
                capsule_digest: frame.source_digest,
                capture: capture_interval(frame),
                dimensions: frame.dimensions,
                gap_before: !contiguous || frame.discontinuity_before,
                pixels: &self.luma,
            },
            checkpoint,
        );
        self.status.samples = self
            .status
            .samples
            .saturating_add(screen.samples_used().saturating_sub(before_samples));
        result
    }

    fn reason(&self) -> &'static str {
        self.status
            .refusal
            .or_else(|| self.status.findings.first().map(|finding| finding.as_str()))
            .unwrap_or(match self.status.state {
                SensorHealthState::Warming => "awaiting_fresh_screen",
                SensorHealthState::Held => "awaiting_clear_sequence",
                SensorHealthState::Clear => "screen_hold_cleared",
            })
    }

    fn encode_evidence(&self, frame: &CameraFrame) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.daemon.sensor_health_transition.v1");
        e.bytes(policy_bytes());
        e.digest(policy_digest());
        e.text("clear_only_releases_visual_hold_requires_independent_source_continuity");
        e.u8(SENSOR_HEALTH_CLEAR_FRAMES);
        e.text(frame.sensor_id.as_str());
        e.text(frame.stream_id.as_str());
        e.u64(frame.stream_generation);
        e.u64(frame.sequence);
        e.digest(frame.source_digest);
        e.digest(source_generation(frame));
        capture_interval(frame).encode_canonical(&mut e);
        e.u32(frame.dimensions[0]);
        e.u32(frame.dimensions[1]);
        e.bool(frame.discontinuity_before);
        e.text(self.status.state.as_str());
        e.text(self.reason());
        e.u8(self.status.consecutive_clear_frames);
        e.bool(self.latest.is_some());
        if let Some(observation) = &self.latest {
            e.bytes(&observation.canonical_bytes());
        }
        e.finish()
    }
}

fn capture_interval(frame: &CameraFrame) -> CaptureInterval {
    CaptureInterval {
        earliest: TimestampNs(
            frame
                .host_receive_ns
                .saturating_sub(i128::from(frame.rtt_jitter_ns))
                .saturating_sub(i128::from(frame.node_clock_uncertainty_ns)),
        ),
        latest: TimestampNs(
            frame
                .host_receive_ns
                .saturating_add(i128::from(frame.node_clock_uncertainty_ns)),
        ),
    }
}

fn source_generation(frame: &CameraFrame) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text("fss.daemon.sensor_health_source.v1");
    e.text(frame.sensor_id.as_str());
    e.text(frame.stream_id.as_str());
    e.u64(frame.stream_generation);
    e.u32(frame.dimensions[0]);
    e.u32(frame.dimensions[1]);
    e.digest(policy_digest());
    ContentDigest::sha256(&e.finish())
}
