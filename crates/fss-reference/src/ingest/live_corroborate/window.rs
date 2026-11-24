#![forbid(unsafe_code)]
//! Bounded sliding-window retention of active live camera observations and confirmed tracks.
//!
//! Enforces strict memory bounds via watermark-based temporal expiration, per-camera entry caps,
//! and a global observation cap so long-running streaming corroboration never exhibits unbounded
//! heap growth.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fss_core::event::MAX_ZONE_ID_LEN;
use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, SensorId};

use crate::ingest::model_pool::{CascadeFrameReceipt, ModelDetectionSummary};

use super::LiveCorroborateError;
use super::clock::BoundedCaptureInterval;

/// Canonical digest domain for individual [`LiveObservation`] records.
pub const LIVE_CORROBORATE_OBSERVATION_DOMAIN: &str = "fss.live_corroborate.observation.v1";

/// Maximum admitted sliding-window retention span (1 hour).
pub const MAX_WINDOW_RETENTION_NS: u64 = 3_600_000_000_000;
/// Maximum global observations retained concurrently across all cameras.
pub const MAX_WINDOW_TOTAL_OBSERVATIONS: usize = 16_384;
/// Maximum observations retained concurrently per camera.
pub const MAX_WINDOW_PER_CAMERA_OBSERVATIONS: usize = 4_096;
/// Maximum raw score in parts per million (`1.0 == 1_000_000`).
pub const MAX_SCORE_PPM: u32 = 1_000_000;
/// Default sliding-window retention duration (30 s).
pub const DEFAULT_WINDOW_RETENTION_NS: u64 = 30_000_000_000;
/// Default global observation cap.
pub const DEFAULT_MAX_TOTAL_OBSERVATIONS: usize = 1_024;
/// Default per-camera observation cap.
pub const DEFAULT_MAX_PER_CAMERA_OBSERVATIONS: usize = 256;

/// One live confirmed track / detection observation submitted to streaming corroboration.
#[derive(Clone, Debug, PartialEq)]
pub struct LiveObservation {
    /// Camera sensor identity.
    pub sensor_id: String,
    /// Logical stream identity on that camera (e.g., `main`, `sub`, `rtsp:0`).
    pub stream_id: String,
    /// Logical zone identifier observed on this camera (`1..=64` bytes).
    pub zone_id: String,
    /// Non-zero camera-local confirmed track identifier (never a global physical identity).
    pub track_id: u64,
    /// Optional image-space foot-point `[u, v]` in pixels for ground-plane homography projection.
    pub foot_px: Option<[f64; 2]>,
    /// Proposed class label (e.g. `person`, `vehicle`, `unclassified`).
    pub class_label: String,
    /// Uncalibrated detector score in parts per million (`0..=1_000_000`).
    pub score_ppm: u32,
    /// Conservative host-referenced capture interval for this observation.
    pub bounded_capture: BoundedCaptureInterval,
    /// Source media capsule content digest establishing raw provenance.
    pub source_capsule_digest: ContentDigest,
    /// Immutable model execution / inference output receipt digest.
    pub model_receipt_digest: ContentDigest,
    /// Immutable `C5` `CascadeFrameReceipt` digest linking Stage-1/Stage-2 execution.
    pub cascade_receipt_digest: ContentDigest,
}

impl LiveObservation {
    /// Builds a [`LiveObservation`] directly from a `C5` [`CascadeFrameReceipt`] and one
    /// [`ModelDetectionSummary`] emitted by the resident model pool.
    ///
    /// Computes the image foot-point `[u, v]` from the bottom-center of `detection.bounds`
    /// (which are stored in 1/256-pixel XYXY units) and clamps finite F32 scores into `score_ppm`.
    pub fn from_cascade_detection(
        receipt: &CascadeFrameReceipt,
        detection: &ModelDetectionSummary,
        stream_id: impl Into<String>,
        zone_id: impl Into<String>,
        track_id: u64,
        bounded_capture: BoundedCaptureInterval,
    ) -> Result<Self, LiveCorroborateError> {
        let [x1, _y1, x2, y2] = detection.bounds;
        let foot_u = (f64::from(x1) + f64::from(x2)) / 512.0;
        let foot_v = f64::from(y2) / 256.0;
        let raw_score = detection.score();
        let score_ppm = if raw_score.is_finite() {
            let clamped = raw_score.clamp(0.0, 1.0);
            (f64::from(clamped) * f64::from(MAX_SCORE_PPM)).round() as u32
        } else {
            0
        };
        let obs = Self {
            sensor_id: receipt.sensor_id.as_str().to_owned(),
            stream_id: stream_id.into(),
            zone_id: zone_id.into(),
            track_id,
            foot_px: Some([foot_u, foot_v]),
            class_label: detection.label.clone(),
            score_ppm: score_ppm.min(MAX_SCORE_PPM),
            bounded_capture,
            source_capsule_digest: receipt.source_digest,
            model_receipt_digest: receipt
                .inference_output_digest
                .unwrap_or(receipt.receipt_digest),
            cascade_receipt_digest: receipt.receipt_digest,
        };
        obs.validate()?;
        Ok(obs)
    }

    /// Validates identifiers, bounds, score range, capture interval ordering, and finite foot-point.
    pub fn validate(&self) -> Result<(), LiveCorroborateError> {
        SensorId::parse(self.sensor_id.clone())?;
        if self.stream_id.is_empty()
            || self.stream_id.len() > 64
            || self.stream_id.chars().any(char::is_control)
        {
            return Err(LiveCorroborateError::InvalidObservation(
                "stream_id must be 1..=64 printable bytes",
            ));
        }
        if self.zone_id.is_empty()
            || self.zone_id.len() > MAX_ZONE_ID_LEN
            || self.zone_id.chars().any(char::is_control)
        {
            return Err(LiveCorroborateError::InvalidObservation(
                "zone_id must be 1..=64 printable bytes",
            ));
        }
        if self.track_id == 0 {
            return Err(LiveCorroborateError::InvalidObservation(
                "track_id must be non-zero",
            ));
        }
        if let Some([u, v]) = self.foot_px
            && (!u.is_finite() || !v.is_finite())
        {
            return Err(LiveCorroborateError::InvalidObservation(
                "foot_px coordinates must be finite",
            ));
        }
        if self.class_label.is_empty()
            || self.class_label.len() > 64
            || self.class_label.chars().any(char::is_control)
        {
            return Err(LiveCorroborateError::InvalidObservation(
                "class_label must be 1..=64 printable bytes",
            ));
        }
        if self.score_ppm > MAX_SCORE_PPM {
            return Err(LiveCorroborateError::InvalidObservation(
                "score_ppm must be in 0..=1_000_000",
            ));
        }
        if self.bounded_capture.earliest_ns > self.bounded_capture.latest_ns {
            return Err(LiveCorroborateError::InvertedCaptureInterval {
                earliest_ns: self.bounded_capture.earliest_ns,
                latest_ns: self.bounded_capture.latest_ns,
            });
        }
        Ok(())
    }

    /// Computes the canonical SHA-256 identity digest under [`LIVE_CORROBORATE_OBSERVATION_DOMAIN`].
    #[must_use]
    pub fn observation_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(LIVE_CORROBORATE_OBSERVATION_DOMAIN);
        encoder.text(&self.sensor_id);
        encoder.text(&self.stream_id);
        encoder.text(&self.zone_id);
        encoder.u64(self.track_id);
        match self.foot_px {
            Some([u, v]) => {
                encoder.bool(true);
                encoder.u64(if u == 0.0 {
                    0.0_f64.to_bits()
                } else {
                    u.to_bits()
                });
                encoder.u64(if v == 0.0 {
                    0.0_f64.to_bits()
                } else {
                    v.to_bits()
                });
            }
            None => encoder.bool(false),
        }
        encoder.text(&self.class_label);
        encoder.u32(self.score_ppm);
        self.bounded_capture.encode_canonical(&mut encoder);
        encoder.digest(self.source_capsule_digest);
        encoder.digest(self.model_receipt_digest);
        encoder.digest(self.cascade_receipt_digest);
        ContentDigest::sha256(&encoder.finish())
    }
}

/// Configuration ceilings for [`ObservationWindow`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlidingWindowConfig {
    /// Maximum age relative to watermark (ns) before an observation is evicted.
    pub retention_ns: u64,
    /// Hard upper bound on total observations retained across all cameras.
    pub max_total_observations: usize,
    /// Hard upper bound on observations retained per camera.
    pub max_observations_per_camera: usize,
}

impl Default for SlidingWindowConfig {
    fn default() -> Self {
        Self {
            retention_ns: DEFAULT_WINDOW_RETENTION_NS,
            max_total_observations: DEFAULT_MAX_TOTAL_OBSERVATIONS,
            max_observations_per_camera: DEFAULT_MAX_PER_CAMERA_OBSERVATIONS,
        }
    }
}

impl SlidingWindowConfig {
    /// Validates all retention and capacity bounds.
    pub fn validate(&self) -> Result<(), LiveCorroborateError> {
        if self.retention_ns == 0 || self.retention_ns > MAX_WINDOW_RETENTION_NS {
            return Err(LiveCorroborateError::InvalidConfig(
                "window retention_ns must be in 1..=3600s",
            ));
        }
        if self.max_total_observations < 2
            || self.max_total_observations > MAX_WINDOW_TOTAL_OBSERVATIONS
        {
            return Err(LiveCorroborateError::InvalidConfig(
                "window max_total_observations must be in 2..=16384",
            ));
        }
        if self.max_observations_per_camera == 0
            || self.max_observations_per_camera > MAX_WINDOW_PER_CAMERA_OBSERVATIONS
        {
            return Err(LiveCorroborateError::InvalidConfig(
                "window max_observations_per_camera must be in 1..=4096",
            ));
        }
        Ok(())
    }
}

/// Accounting counters returned when advancing watermark or admitting observations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvictionStats {
    /// Entries expired because `latest_ns < watermark_ns - retention_ns`.
    pub evicted_by_watermark: usize,
    /// Entries dropped to respect `max_observations_per_camera`.
    pub evicted_by_camera_cap: usize,
    /// Entries dropped to respect `max_total_observations`.
    pub evicted_by_global_cap: usize,
}

impl EvictionStats {
    /// Total observations evicted across all causes.
    #[must_use]
    pub const fn total(self) -> usize {
        self.evicted_by_watermark + self.evicted_by_camera_cap + self.evicted_by_global_cap
    }
}

#[derive(Clone, Debug)]
struct RetainedEntry {
    digest: ContentDigest,
    observation: LiveObservation,
}

/// Bounded sliding time window of active confirmed tracks and class proposals across cameras.
#[derive(Clone, Debug)]
pub struct ObservationWindow {
    config: SlidingWindowConfig,
    per_camera: BTreeMap<String, VecDeque<RetainedEntry>>,
    present_digests: BTreeSet<ContentDigest>,
    watermark_ns: Option<i128>,
    total_count: usize,
}

impl ObservationWindow {
    /// Constructs a validated empty sliding window.
    pub fn new(config: SlidingWindowConfig) -> Result<Self, LiveCorroborateError> {
        config.validate()?;
        Ok(Self {
            config,
            per_camera: BTreeMap::new(),
            present_digests: BTreeSet::new(),
            watermark_ns: None,
            total_count: 0,
        })
    }

    /// Returns the total active observation count across all cameras.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.total_count
    }

    /// Returns `true` when no observations are currently retained.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total_count == 0
    }

    /// Returns the active count retained for `sensor_id`.
    #[must_use]
    pub fn camera_len(&self, sensor_id: &str) -> usize {
        self.per_camera.get(sensor_id).map_or(0, VecDeque::len)
    }

    /// Returns the current monotonic watermark timestamp (ns), if initialized.
    #[must_use]
    pub const fn watermark_ns(&self) -> Option<i128> {
        self.watermark_ns
    }

    /// Advances the watermark monotonically and evicts expired observations.
    pub fn advance_watermark(&mut self, watermark_ns: i128) -> EvictionStats {
        let next = self
            .watermark_ns
            .map_or(watermark_ns, |cur| cur.max(watermark_ns));
        self.watermark_ns = Some(next);
        self.evict_expired()
    }

    /// Admits a validated [`LiveObservation`], updating the watermark and enforcing all bounds.
    ///
    /// Returns `(admitted, eviction_stats)` where `admitted == false` indicates an exact duplicate
    /// observation digest was already present (idempotent admission) or the observation arrived
    /// already older than the active retention cutoff.
    pub fn insert(&mut self, observation: LiveObservation) -> (bool, EvictionStats) {
        let mut stats = self.advance_watermark(observation.bounded_capture.latest_ns);
        let cutoff = self.cutoff_ns();
        if cutoff.is_some_and(|c| observation.bounded_capture.latest_ns < c) {
            return (false, stats);
        }
        let digest = observation.observation_digest();
        if !self.present_digests.insert(digest) {
            return (false, stats);
        }
        let queue = self
            .per_camera
            .entry(observation.sensor_id.clone())
            .or_default();
        queue.push_back(RetainedEntry {
            digest,
            observation,
        });
        self.total_count += 1;

        while queue.len() > self.config.max_observations_per_camera {
            if let Some(dropped) = queue.pop_front() {
                self.present_digests.remove(&dropped.digest);
                self.total_count = self.total_count.saturating_sub(1);
                stats.evicted_by_camera_cap += 1;
            }
        }

        while self.total_count > self.config.max_total_observations {
            let oldest_camera = self
                .per_camera
                .iter()
                .filter_map(|(cam, q)| {
                    q.front()
                        .map(|e| (e.observation.bounded_capture.latest_ns, cam.as_str()))
                })
                .min()
                .map(|(_, cam)| cam.to_owned());
            let Some(cam_key) = oldest_camera else {
                break;
            };
            if let Some(q) = self.per_camera.get_mut(&cam_key)
                && let Some(dropped) = q.pop_front()
            {
                self.present_digests.remove(&dropped.digest);
                self.total_count = self.total_count.saturating_sub(1);
                stats.evicted_by_global_cap += 1;
            }
        }
        self.per_camera.retain(|_, q| !q.is_empty());
        (true, stats)
    }

    /// Returns all retained observations from cameras other than `sensor_id` in deterministic order.
    #[must_use]
    pub fn counterparts_for(&self, sensor_id: &str) -> Vec<&LiveObservation> {
        let mut out = Vec::new();
        for (cam, queue) in &self.per_camera {
            if cam == sensor_id {
                continue;
            }
            for entry in queue {
                out.push(&entry.observation);
            }
        }
        out.sort_by(|a, b| {
            a.sensor_id
                .cmp(&b.sensor_id)
                .then_with(|| {
                    a.bounded_capture
                        .earliest_ns
                        .cmp(&b.bounded_capture.earliest_ns)
                })
                .then_with(|| a.track_id.cmp(&b.track_id))
                .then_with(|| a.observation_digest().cmp(&b.observation_digest()))
        });
        out
    }

    fn cutoff_ns(&self) -> Option<i128> {
        self.watermark_ns
            .map(|wm| wm.saturating_sub(i128::from(self.config.retention_ns)))
    }

    fn evict_expired(&mut self) -> EvictionStats {
        let mut stats = EvictionStats::default();
        let Some(cutoff) = self.cutoff_ns() else {
            return stats;
        };
        for queue in self.per_camera.values_mut() {
            let mut idx = 0;
            while idx < queue.len() {
                if queue[idx].observation.bounded_capture.latest_ns < cutoff {
                    if let Some(removed) = queue.remove(idx) {
                        self.present_digests.remove(&removed.digest);
                        self.total_count = self.total_count.saturating_sub(1);
                        stats.evicted_by_watermark += 1;
                    }
                } else {
                    idx += 1;
                }
            }
        }
        self.per_camera.retain(|_, q| !q.is_empty());
        stats
    }
}
