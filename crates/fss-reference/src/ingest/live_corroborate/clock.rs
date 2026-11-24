#![forbid(unsafe_code)]
//! Honest bounded per-camera time-offset estimation and conservative interval matching.
//!
//! Never fabricates exact camera UTC. Every live frame's media timestamp (`media_pts_ns`) is
//! bound to the host receive clock envelope (`host_receive_ns`, `rtt_jitter_ns`,
//! `node_clock_uncertainty_ns`) across a bounded sliding window, producing a conservative
//! [`BoundedCaptureInterval`] `[earliest_ns, latest_ns]` that strictly widens under jitter,
//! drift, or clock step jumps. Excessive uncertainty explicitly abstains.

use std::collections::VecDeque;

use fss_core::{
    CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest, SensorId, TimestampNs,
};

use super::LiveCorroborateError;
pub use super::match_time::{MatchDisposition, intervals_compatible, transit_compatible};

/// Canonical digest domain for per-camera bounded clock-offset estimation receipts.
pub const LIVE_CORROBORATE_CLOCK_RECEIPT_DOMAIN: &str = "fss.live_corroborate.clock_receipt.v1";

/// Maximum bounded sliding window size for per-camera clock offset samples.
pub const MAX_CLOCK_WINDOW_SIZE: usize = 256;
/// Maximum retained clock anomaly records per camera estimator.
pub const MAX_CLOCK_ANOMALIES: usize = 64;
/// Maximum admitted conservative drift expansion rate (10% = 100_000 ppm).
pub const MAX_CLOCK_DRIFT_PPM: u64 = 100_000;
/// Maximum admitted clock uncertainty ceiling (60 s).
pub const MAX_CLOCK_UNCERTAINTY_CEILING_NS: u64 = 60_000_000_000;
/// Default sliding window size (last 32 samples).
pub const DEFAULT_CLOCK_WINDOW_SIZE: usize = 32;
/// Default conservative drift margin (500 ppm).
pub const DEFAULT_CLOCK_DRIFT_PPM: u64 = 500;
/// Default step-jump detection threshold (250 ms).
pub const DEFAULT_STEP_JUMP_THRESHOLD_NS: u64 = 250_000_000;
/// Default maximum clock uncertainty permitted before temporal abstention (1 s).
pub const DEFAULT_MAX_CLOCK_UNCERTAINTY_NS: u64 = 1_000_000_000;

/// Provenance basis of a live camera's bounded capture-time interval.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ClockBasis {
    /// Camera media clock mapped conservatively via host receive envelope, RTT jitter, and node
    /// uncertainty; never assumes camera wall-clock synchronization.
    BoundedReceiveEnvelope = 1,
    /// Authenticated NTP/NTS-disciplined host and sensor reference within a declared dispersion.
    AuthenticatedNtp = 2,
    /// Explicit physical calibration shuttle/flash synchronization epoch with residual bound.
    CalibrationShuttleSync = 3,
}

impl ClockBasis {
    /// Stable lowercase spelling for canonical encodings and JSONL traces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BoundedReceiveEnvelope => "bounded_receive_envelope",
            Self::AuthenticatedNtp => "authenticated_ntp",
            Self::CalibrationShuttleSync => "calibration_shuttle_sync",
        }
    }

    /// Compact canonical tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

impl CanonicalEncode for ClockBasis {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(self.tag());
        encoder.text(self.as_str());
    }
}

/// Configuration bounds for [`CameraClockEstimator`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockEstimatorConfig {
    /// Number of recent offset observations retained in the bounded sliding window (`1..=256`).
    pub window_size: usize,
    /// Conservative drift expansion rate in parts-per-million (`0..=100_000`).
    pub max_drift_ppm: u64,
    /// Offset delta threshold (ns) above which a clock step/skew jump anomaly is recorded.
    pub step_jump_threshold_ns: u64,
    /// Maximum acceptable capture interval uncertainty (ns) before temporal abstention.
    pub max_clock_uncertainty_ns: u64,
    /// Declared provenance basis for intervals produced by this estimator.
    pub basis: ClockBasis,
}

impl Default for ClockEstimatorConfig {
    fn default() -> Self {
        Self {
            window_size: DEFAULT_CLOCK_WINDOW_SIZE,
            max_drift_ppm: DEFAULT_CLOCK_DRIFT_PPM,
            step_jump_threshold_ns: DEFAULT_STEP_JUMP_THRESHOLD_NS,
            max_clock_uncertainty_ns: DEFAULT_MAX_CLOCK_UNCERTAINTY_NS,
            basis: ClockBasis::BoundedReceiveEnvelope,
        }
    }
}

impl ClockEstimatorConfig {
    /// Validates all configuration bounds before estimator construction.
    pub fn validate(&self) -> Result<(), LiveCorroborateError> {
        if self.window_size == 0 || self.window_size > MAX_CLOCK_WINDOW_SIZE {
            return Err(LiveCorroborateError::InvalidConfig(
                "clock window_size must be in 1..=256",
            ));
        }
        if self.max_drift_ppm > MAX_CLOCK_DRIFT_PPM {
            return Err(LiveCorroborateError::InvalidConfig(
                "clock max_drift_ppm exceeds 100_000 ppm",
            ));
        }
        if self.step_jump_threshold_ns == 0 {
            return Err(LiveCorroborateError::InvalidConfig(
                "clock step_jump_threshold_ns must be positive",
            ));
        }
        if self.max_clock_uncertainty_ns == 0
            || self.max_clock_uncertainty_ns > MAX_CLOCK_UNCERTAINTY_CEILING_NS
        {
            return Err(LiveCorroborateError::InvalidConfig(
                "clock max_clock_uncertainty_ns must be in 1..=60s",
            ));
        }
        Ok(())
    }
}

/// One live packet/frame clock measurement binding stream RTP/PTS time to host receive time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockObservationSample {
    /// Camera media clock (RTP/PTS) timestamp in nanoseconds.
    pub media_pts_ns: i128,
    /// Host node monotonic or NTP-bounded receive timestamp in nanoseconds.
    pub host_receive_ns: i128,
    /// Bounded network + pipeline transport RTT/jitter envelope in nanoseconds.
    pub rtt_jitter_ns: u64,
    /// Bounded host node clock uncertainty (e.g., NTP dispersion) in nanoseconds.
    pub node_clock_uncertainty_ns: u64,
}

/// Explicit clock anomaly recorded when stream timing exhibits a jump or monotonicity fault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockAnomaly {
    /// Sudden jump in `host_receive_ns - media_pts_ns` exceeding `step_jump_threshold_ns`.
    ClockStepJump {
        /// Prior sample raw offset (`host_receive_ns - media_pts_ns`).
        previous_offset_ns: i128,
        /// Newly observed sample raw offset.
        observed_offset_ns: i128,
        /// Absolute magnitude of the offset step in nanoseconds.
        jump_magnitude_ns: u128,
    },
    /// Stream media PTS stepped backwards or stalled relative to the preceding sample.
    NonMonotonicMediaPts {
        /// Prior observed media PTS.
        previous_pts_ns: i128,
        /// Newly observed media PTS.
        observed_pts_ns: i128,
    },
    /// Host receive timestamp stepped backwards relative to the preceding sample.
    NonMonotonicHostReceive {
        /// Prior host receive timestamp.
        previous_host_ns: i128,
        /// Newly observed host receive timestamp.
        observed_host_ns: i128,
    },
}

impl ClockAnomaly {
    /// Stable lowercase kind name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClockStepJump { .. } => "clock_step_jump",
            Self::NonMonotonicMediaPts { .. } => "non_monotonic_media_pts",
            Self::NonMonotonicHostReceive { .. } => "non_monotonic_host_receive",
        }
    }
}

impl CanonicalEncode for ClockAnomaly {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
        match *self {
            Self::ClockStepJump {
                previous_offset_ns,
                observed_offset_ns,
                jump_magnitude_ns,
            } => {
                encoder.u8(1);
                encoder.i128(previous_offset_ns);
                encoder.i128(observed_offset_ns);
                encode_u128(encoder, jump_magnitude_ns);
            }
            Self::NonMonotonicMediaPts {
                previous_pts_ns,
                observed_pts_ns,
            } => {
                encoder.u8(2);
                encoder.i128(previous_pts_ns);
                encoder.i128(observed_pts_ns);
            }
            Self::NonMonotonicHostReceive {
                previous_host_ns,
                observed_host_ns,
            } => {
                encoder.u8(3);
                encoder.i128(previous_host_ns);
                encoder.i128(observed_host_ns);
            }
        }
    }
}

/// Conservative bounded capture-time interval on the common host reference clock.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedCaptureInterval {
    /// Conservative earliest possible capture instant (ns).
    pub earliest_ns: i128,
    /// Conservative latest possible capture instant (ns).
    pub latest_ns: i128,
    /// Clock provenance basis for these bounds.
    pub clock_basis: ClockBasis,
    /// Total offset/envelope uncertainty width (ns).
    pub offset_uncertainty_ns: u128,
}

impl BoundedCaptureInterval {
    /// Constructs a validated conservative capture interval (`earliest_ns <= latest_ns`).
    pub fn new(
        earliest_ns: i128,
        latest_ns: i128,
        clock_basis: ClockBasis,
    ) -> Result<Self, LiveCorroborateError> {
        if earliest_ns > latest_ns {
            return Err(LiveCorroborateError::InvertedCaptureInterval {
                earliest_ns,
                latest_ns,
            });
        }
        Ok(Self {
            earliest_ns,
            latest_ns,
            clock_basis,
            offset_uncertainty_ns: latest_ns.abs_diff(earliest_ns),
        })
    }

    /// Exact closed interval width `latest_ns - earliest_ns` in nanoseconds.
    #[must_use]
    pub fn width_ns(self) -> u128 {
        self.latest_ns.abs_diff(self.earliest_ns)
    }

    /// Worst-case uncertainty in nanoseconds (`max(width_ns, offset_uncertainty_ns)`).
    #[must_use]
    pub fn effective_uncertainty_ns(self) -> u128 {
        self.width_ns().max(self.offset_uncertainty_ns)
    }

    /// Monotonically widens this interval symmetrically by `extra_each_side_ns`.
    pub fn widen(self, extra_each_side_ns: u128) -> Result<Self, LiveCorroborateError> {
        let delta = i128::try_from(extra_each_side_ns)
            .map_err(|_| LiveCorroborateError::ArithmeticOverflow)?;
        let earliest_ns = self
            .earliest_ns
            .checked_sub(delta)
            .ok_or(LiveCorroborateError::ArithmeticOverflow)?;
        let latest_ns = self
            .latest_ns
            .checked_add(delta)
            .ok_or(LiveCorroborateError::ArithmeticOverflow)?;
        Self::new(earliest_ns, latest_ns, self.clock_basis)
    }

    /// Converts into canonical `fss_core::CaptureInterval`.
    pub fn to_capture_interval(self) -> Result<CaptureInterval, LiveCorroborateError> {
        CaptureInterval::new(TimestampNs(self.earliest_ns), TimestampNs(self.latest_ns))
            .map_err(LiveCorroborateError::Contract)
    }
}

impl CanonicalEncode for BoundedCaptureInterval {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.i128(self.earliest_ns);
        encoder.i128(self.latest_ns);
        self.clock_basis.encode_canonical(encoder);
        encode_u128(encoder, self.offset_uncertainty_ns);
    }
}

/// Sealed canonical receipt capturing a camera estimator's current bounded offset envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClockOffsetReceipt {
    /// Camera sensor identity.
    pub sensor_id: String,
    /// Declared clock basis.
    pub clock_basis: ClockBasis,
    /// Active sample count in the bounded sliding window.
    pub sample_count: usize,
    /// Conservative lower offset bound `min(t_cap - media_pts_ns)`.
    pub min_offset_ns: i128,
    /// Conservative upper offset bound `max(t_cap - media_pts_ns)`.
    pub max_offset_ns: i128,
    /// Total offset envelope width `max_offset_ns - min_offset_ns`.
    pub offset_uncertainty_ns: u128,
    /// Recent recorded clock step/monotonicity anomalies.
    pub anomalies: Vec<ClockAnomaly>,
    /// Domain-separated canonical SHA-256 digest (`LIVE_CORROBORATE_CLOCK_RECEIPT_DOMAIN`).
    pub receipt_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OffsetWindowEntry {
    media_pts_ns: i128,
    min_offset_ns: i128,
    max_offset_ns: i128,
}

/// Bounded sliding-window estimator binding one camera's media PTS clock to host receive bounds.
#[derive(Clone, Debug)]
pub struct CameraClockEstimator {
    sensor_id: String,
    config: ClockEstimatorConfig,
    window: VecDeque<OffsetWindowEntry>,
    last_sample: Option<ClockObservationSample>,
    anomalies: VecDeque<ClockAnomaly>,
}

impl CameraClockEstimator {
    /// Constructs a validated estimator for `sensor_id`.
    pub fn new(
        sensor_id: impl Into<String>,
        config: ClockEstimatorConfig,
    ) -> Result<Self, LiveCorroborateError> {
        let sensor_id = sensor_id.into();
        SensorId::parse(sensor_id.clone())?;
        config.validate()?;
        Ok(Self {
            sensor_id,
            config,
            window: VecDeque::with_capacity(config.window_size),
            last_sample: None,
            anomalies: VecDeque::new(),
        })
    }

    /// Returns the camera's sensor identifier.
    #[must_use]
    pub fn sensor_id(&self) -> &str {
        &self.sensor_id
    }

    /// Returns the estimator configuration.
    #[must_use]
    pub const fn config(&self) -> ClockEstimatorConfig {
        self.config
    }

    /// Returns the number of samples currently held in the bounded sliding window.
    #[must_use]
    pub fn sample_count(&self) -> usize {
        self.window.len()
    }

    /// Returns all currently retained clock anomalies.
    #[must_use]
    pub fn anomalies(&self) -> &VecDeque<ClockAnomaly> {
        &self.anomalies
    }

    /// Records a live clock sample and returns the resulting conservative [`BoundedCaptureInterval`].
    pub fn observe(
        &mut self,
        sample: ClockObservationSample,
    ) -> Result<BoundedCaptureInterval, LiveCorroborateError> {
        let raw_offset_ns = sample
            .host_receive_ns
            .checked_sub(sample.media_pts_ns)
            .ok_or(LiveCorroborateError::ArithmeticOverflow)?;
        let node_unc = i128::from(sample.node_clock_uncertainty_ns);
        let rtt_jitter = i128::from(sample.rtt_jitter_ns);
        let min_offset_ns = raw_offset_ns
            .checked_sub(rtt_jitter)
            .and_then(|v| v.checked_sub(node_unc))
            .ok_or(LiveCorroborateError::ArithmeticOverflow)?;
        let max_offset_ns = raw_offset_ns
            .checked_add(node_unc)
            .ok_or(LiveCorroborateError::ArithmeticOverflow)?;

        if let Some(prev) = self.last_sample {
            if sample.media_pts_ns <= prev.media_pts_ns {
                self.push_anomaly(ClockAnomaly::NonMonotonicMediaPts {
                    previous_pts_ns: prev.media_pts_ns,
                    observed_pts_ns: sample.media_pts_ns,
                });
            }
            if sample.host_receive_ns < prev.host_receive_ns {
                self.push_anomaly(ClockAnomaly::NonMonotonicHostReceive {
                    previous_host_ns: prev.host_receive_ns,
                    observed_host_ns: sample.host_receive_ns,
                });
            }
            let prev_raw_offset = prev
                .host_receive_ns
                .checked_sub(prev.media_pts_ns)
                .ok_or(LiveCorroborateError::ArithmeticOverflow)?;
            let jump_magnitude_ns = raw_offset_ns.abs_diff(prev_raw_offset);
            if jump_magnitude_ns > u128::from(self.config.step_jump_threshold_ns) {
                self.push_anomaly(ClockAnomaly::ClockStepJump {
                    previous_offset_ns: prev_raw_offset,
                    observed_offset_ns: raw_offset_ns,
                    jump_magnitude_ns,
                });
            }
        }

        if self.window.len() == self.config.window_size {
            self.window.pop_front();
        }
        self.window.push_back(OffsetWindowEntry {
            media_pts_ns: sample.media_pts_ns,
            min_offset_ns,
            max_offset_ns,
        });
        self.last_sample = Some(sample);
        self.estimate_capture_interval(sample.media_pts_ns)
    }

    /// Returns the current conservative offset hull `[min_offset_ns, max_offset_ns]` across the window.
    #[must_use]
    pub fn offset_bounds(&self) -> Option<(i128, i128)> {
        let first = self.window.front()?;
        let (mut lo, mut hi) = (first.min_offset_ns, first.max_offset_ns);
        for entry in self.window.iter().skip(1) {
            lo = lo.min(entry.min_offset_ns);
            hi = hi.max(entry.max_offset_ns);
        }
        Some((lo, hi))
    }

    /// Projects `media_pts_ns` onto a conservative [`BoundedCaptureInterval`] including drift expansion.
    pub fn estimate_capture_interval(
        &self,
        media_pts_ns: i128,
    ) -> Result<BoundedCaptureInterval, LiveCorroborateError> {
        let (min_off, max_off) = self
            .offset_bounds()
            .ok_or_else(|| LiveCorroborateError::ClockUninitialized(self.sensor_id.clone()))?;
        let anchor_pts = self.window.back().map_or(media_pts_ns, |e| e.media_pts_ns);
        let drift_u128 = media_pts_ns
            .abs_diff(anchor_pts)
            .checked_mul(u128::from(self.config.max_drift_ppm))
            .ok_or(LiveCorroborateError::ArithmeticOverflow)?
            .div_ceil(1_000_000);
        let drift =
            i128::try_from(drift_u128).map_err(|_| LiveCorroborateError::ArithmeticOverflow)?;
        let earliest_ns = media_pts_ns
            .checked_add(min_off)
            .and_then(|v| v.checked_sub(drift))
            .ok_or(LiveCorroborateError::ArithmeticOverflow)?;
        let latest_ns = media_pts_ns
            .checked_add(max_off)
            .and_then(|v| v.checked_add(drift))
            .ok_or(LiveCorroborateError::ArithmeticOverflow)?;
        BoundedCaptureInterval::new(earliest_ns, latest_ns, self.config.basis)
    }

    /// Seals a canonical [`ClockOffsetReceipt`] for audit traces and corroboration decisions.
    pub fn receipt(&self) -> Result<ClockOffsetReceipt, LiveCorroborateError> {
        let (min_offset_ns, max_offset_ns) = self
            .offset_bounds()
            .ok_or_else(|| LiveCorroborateError::ClockUninitialized(self.sensor_id.clone()))?;
        let offset_uncertainty_ns = max_offset_ns.abs_diff(min_offset_ns);
        let anomalies: Vec<ClockAnomaly> = self.anomalies.iter().copied().collect();
        let mut enc = CanonicalEncoder::new();
        enc.text(LIVE_CORROBORATE_CLOCK_RECEIPT_DOMAIN);
        enc.text(&self.sensor_id);
        self.config.basis.encode_canonical(&mut enc);
        enc.u64(self.window.len() as u64);
        enc.i128(min_offset_ns);
        enc.i128(max_offset_ns);
        encode_u128(&mut enc, offset_uncertainty_ns);
        enc.u64(anomalies.len() as u64);
        for anomaly in &anomalies {
            anomaly.encode_canonical(&mut enc);
        }
        Ok(ClockOffsetReceipt {
            sensor_id: self.sensor_id.clone(),
            clock_basis: self.config.basis,
            sample_count: self.window.len(),
            min_offset_ns,
            max_offset_ns,
            offset_uncertainty_ns,
            anomalies,
            receipt_digest: ContentDigest::sha256(&enc.finish()),
        })
    }

    fn push_anomaly(&mut self, anomaly: ClockAnomaly) {
        if self.anomalies.len() == MAX_CLOCK_ANOMALIES {
            self.anomalies.pop_front();
        }
        self.anomalies.push_back(anomaly);
    }
}

fn encode_u128(encoder: &mut CanonicalEncoder, value: u128) {
    encoder.u64((value >> 64) as u64);
    encoder.u64(value as u64);
}
