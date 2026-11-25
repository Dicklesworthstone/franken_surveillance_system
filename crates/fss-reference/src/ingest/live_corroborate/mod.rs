#![forbid(unsafe_code)]
//! Live bounded clock-offset estimation, site overlap/homography registry, and streaming
//! multi-camera corroboration with automatic `fss-fusion` milliban LLR evaluation.
//!
//! Cognition-plane orchestration only:
//! - Never fabricates exact camera UTC: every frame is projected into a conservative
//!   [`BoundedCaptureInterval`] `[earliest_ns, latest_ns]` from host-receive envelopes.
//! - Enforces transitive common-cause failure-domain contraction via [`SiteTopologyRegistry`]
//!   and `fss-fusion` cluster hulls so cameras sharing `wifi:home` / `power:main` can never
//!   inflate independence or emit `EventState::Corroborated`.
//! - Abstains explicitly (`CorroborationOutcome::ClockUncertaintyAbstained`) whenever clock skew
//!   or jitter exceeds declared operational tolerances.
//! - Retains active observations inside a strictly bounded [`ObservationWindow`] and emits
//!   canonical digests plus structured JSONL traces without granting effect authority.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use fss_core::event::EventDecodeError;
use fss_core::{ContentDigest, ContractError};
use fss_fusion::FusionError;

use crate::ingest::model_pool::CascadeFrameReceipt;

/// Honest bounded per-camera time-offset estimation.
pub mod clock;
/// Streaming cross-camera matching, `fss-fusion` milliban evaluation, and `EventHypothesis` builder.
pub mod fusion;
/// Calibrated 2D image → ground homography projection and horizon guards.
pub mod homography;
/// Conservative temporal interval and transit-corridor matching.
pub mod match_time;
/// Canonical corroboration decision receipts and structured zero-serde JSONL audit traces.
pub mod receipt;
/// Site overlap, ground-plane homography, transit-corridor, and failure-domain topology registry.
pub mod topology;
/// Bounded sliding time window of active confirmed tracks and class proposals.
pub mod window;

#[cfg(test)]
mod tests;

pub use clock::{
    BoundedCaptureInterval, CameraClockEstimator, ClockAnomaly, ClockBasis, ClockEstimatorConfig,
    ClockObservationSample, ClockOffsetReceipt, DEFAULT_CLOCK_DRIFT_PPM, DEFAULT_CLOCK_WINDOW_SIZE,
    DEFAULT_MAX_CLOCK_UNCERTAINTY_NS, DEFAULT_STEP_JUMP_THRESHOLD_NS,
    LIVE_CORROBORATE_CLOCK_RECEIPT_DOMAIN, MAX_CLOCK_ANOMALIES, MAX_CLOCK_DRIFT_PPM,
    MAX_CLOCK_UNCERTAINTY_CEILING_NS, MAX_CLOCK_WINDOW_SIZE, MatchDisposition,
    intervals_compatible, transit_compatible,
};
pub use fusion::LiveFusionConfig;
pub use receipt::{
    CorroborationOutcome, LIVE_CORROBORATE_DECISION_DOMAIN, LiveCorroborationDecision,
    MatchMechanism,
};
pub use topology::{
    CameraHomography, CameraTopologyEntry, DEFAULT_HOMOGRAPHY_TIME_GATE_NS, FailureDomainCluster,
    LIVE_CORROBORATE_CLUSTER_DOMAIN, LIVE_CORROBORATE_TOPOLOGY_DOMAIN, MAX_CORRIDOR_TRANSIT_NS,
    MAX_DECLARED_DOMAINS_PER_CAMERA, MAX_DOMAIN_TEXT_BYTES, MAX_SHARED_ZONES, MAX_TOPOLOGY_CAMERAS,
    MAX_TRANSIT_CORRIDORS, SharedZoneOverlap, SiteTopologyRegistry, SpatialRelation,
    TransitCorridor, ground_distance,
};
pub use window::{
    DEFAULT_MAX_PER_CAMERA_OBSERVATIONS, DEFAULT_MAX_TOTAL_OBSERVATIONS,
    DEFAULT_WINDOW_RETENTION_NS, EvictionStats, LIVE_CORROBORATE_OBSERVATION_DOMAIN,
    LiveObservation, MAX_SCORE_PPM, MAX_WINDOW_PER_CAMERA_OBSERVATIONS, MAX_WINDOW_RETENTION_NS,
    MAX_WINDOW_TOTAL_OBSERVATIONS, ObservationWindow, SlidingWindowConfig,
};

/// Maximum JSONL audit trace lines retained in memory by [`LiveCorroborationEngine`].
pub const MAX_RETAINED_TRACE_LINES: usize = 1_024;

/// Typed non-disclosing error surface for live multi-camera corroboration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiveCorroborateError {
    /// Configuration ceiling or threshold is outside its admitted contract.
    InvalidConfig(&'static str),
    /// Site topology, homography, shared-zone, or transit-corridor declaration is invalid.
    InvalidTopology(&'static str),
    /// Observation field is outside its admitted contract.
    InvalidObservation(&'static str),
    /// Referenced camera sensor ID is not registered in the active [`SiteTopologyRegistry`].
    UnknownCamera(String),
    /// Clock estimate requested before any timing sample was observed for this camera.
    ClockUninitialized(String),
    /// Capture interval was inverted (`earliest_ns > latest_ns`).
    InvertedCaptureInterval {
        /// Earliest bound.
        earliest_ns: i128,
        /// Latest bound.
        latest_ns: i128,
    },
    /// Exact integer timestamp or drift arithmetic overflowed `i128`/`u128`.
    ArithmeticOverflow,
    /// Underlying `fss-core` contract validation failure.
    Contract(ContractError),
    /// Canonical `EventHypothesis` verification failure.
    EventVerify(EventDecodeError),
    /// Underlying `fss-fusion` validation or evaluation failure.
    Fusion(FusionError),
}

impl LiveCorroborateError {
    /// Stable diagnostic identifier for structured logging and receipts.
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
        match self {
            Self::InvalidConfig(_) => "ERR-LIVE-CORROBORATE-CONFIG-001",
            Self::InvalidTopology(_) => "ERR-LIVE-CORROBORATE-TOPOLOGY-001",
            Self::InvalidObservation(_) | Self::UnknownCamera(_) => {
                "ERR-LIVE-CORROBORATE-OBSERVATION-001"
            }
            Self::ClockUninitialized(_) | Self::InvertedCaptureInterval { .. } => {
                "ERR-LIVE-CORROBORATE-CLOCK-001"
            }
            Self::ArithmeticOverflow => "ERR-LIVE-CORROBORATE-OVERFLOW-001",
            Self::Contract(_) | Self::EventVerify(_) => "ERR-LIVE-CORROBORATE-CONTRACT-001",
            Self::Fusion(err) => err.stable_id(),
        }
    }
}

impl fmt::Display for LiveCorroborateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(why) => write!(f, "invalid live corroboration config: {why}"),
            Self::InvalidTopology(why) => write!(f, "invalid site topology: {why}"),
            Self::InvalidObservation(why) => write!(f, "invalid live observation: {why}"),
            Self::UnknownCamera(cam) => write!(f, "unregistered camera sensor: {cam}"),
            Self::ClockUninitialized(cam) => write!(f, "clock uninitialized for camera: {cam}"),
            Self::InvertedCaptureInterval {
                earliest_ns,
                latest_ns,
            } => {
                write!(f, "inverted capture interval: {earliest_ns} > {latest_ns}")
            }
            Self::ArithmeticOverflow => f.write_str("exact timestamp arithmetic overflow"),
            Self::Contract(err) => write!(f, "contract violation: {err}"),
            Self::EventVerify(err) => write!(f, "event hypothesis verification failed: {err}"),
            Self::Fusion(err) => write!(f, "fss-fusion evaluation failed: {err}"),
        }
    }
}

impl std::error::Error for LiveCorroborateError {}

impl From<ContractError> for LiveCorroborateError {
    fn from(err: ContractError) -> Self {
        Self::Contract(err)
    }
}
impl From<EventDecodeError> for LiveCorroborateError {
    fn from(err: EventDecodeError) -> Self {
        Self::EventVerify(err)
    }
}
impl From<FusionError> for LiveCorroborateError {
    fn from(err: FusionError) -> Self {
        Self::Fusion(err)
    }
}

/// Complete validated configuration for [`LiveCorroborationEngine`].
#[derive(Clone, Debug, PartialEq)]
pub struct LiveCorroborationConfig {
    /// Per-camera bounded clock-offset estimator configuration.
    pub clock: ClockEstimatorConfig,
    /// Bounded sliding window retention and memory caps.
    pub window: SlidingWindowConfig,
    /// Calibrated `fss-fusion` milliban LLR policy and score calibrations.
    pub fusion: LiveFusionConfig,
}

impl LiveCorroborationConfig {
    /// Constructs a default configuration (with uncalibrated fail-closed fusion until calibrated).
    pub fn default_config() -> Result<Self, LiveCorroborateError> {
        Ok(Self {
            clock: ClockEstimatorConfig::default(),
            window: SlidingWindowConfig::default(),
            fusion: LiveFusionConfig::default_policy()?,
        })
    }

    /// Validates all sub-configurations.
    pub fn validate(&self) -> Result<(), LiveCorroborateError> {
        self.clock.validate()?;
        self.window.validate()?;
        self.fusion.validate()?;
        Ok(())
    }
}

/// Streaming multi-camera corroboration engine combining bounded clock estimation, site topology
/// matching, bounded track retention, and automatic `fss-fusion` milliban LLR evaluation.
#[derive(Clone, Debug)]
pub struct LiveCorroborationEngine {
    topology: SiteTopologyRegistry,
    topology_digest: ContentDigest,
    config: LiveCorroborationConfig,
    clocks: BTreeMap<String, CameraClockEstimator>,
    window: ObservationWindow,
    sequence: u64,
    traces: VecDeque<String>,
}

impl LiveCorroborationEngine {
    /// Constructs a validated streaming corroboration engine pinned to `topology`.
    pub fn new(
        topology: SiteTopologyRegistry,
        config: LiveCorroborationConfig,
    ) -> Result<Self, LiveCorroborateError> {
        topology.validate()?;
        config.validate()?;
        let topology_digest = topology.digest();
        let mut clocks = BTreeMap::new();
        for sensor_id in topology.cameras.keys() {
            clocks.insert(
                sensor_id.clone(),
                CameraClockEstimator::new(sensor_id.clone(), config.clock)?,
            );
        }
        Ok(Self {
            topology,
            topology_digest,
            config: config.clone(),
            clocks,
            window: ObservationWindow::new(config.window)?,
            sequence: 0,
            traces: VecDeque::new(),
        })
    }

    /// Returns the immutable active [`SiteTopologyRegistry`].
    #[must_use]
    pub const fn topology(&self) -> &SiteTopologyRegistry {
        &self.topology
    }
    /// Returns the canonical digest commitment of the active topology.
    #[must_use]
    pub const fn topology_digest(&self) -> ContentDigest {
        self.topology_digest
    }
    /// Returns the active configuration.
    #[must_use]
    pub const fn config(&self) -> &LiveCorroborationConfig {
        &self.config
    }
    /// Returns a read-only handle to one camera's [`CameraClockEstimator`].
    #[must_use]
    pub fn clock_estimator(&self, sensor_id: &str) -> Option<&CameraClockEstimator> {
        self.clocks.get(sensor_id)
    }
    /// Returns the number of observations currently retained in the bounded sliding window.
    #[must_use]
    pub const fn window_len(&self) -> usize {
        self.window.len()
    }

    /// Invalidates a camera after a health hold, source gap, or generation change.
    /// Other cameras retain their observations; clock estimation restarts with fresh
    /// samples, and excluded old tracks cannot match future observations.
    pub fn invalidate_camera(&mut self, sensor_id: &str) -> Result<usize, LiveCorroborateError> {
        let clock = self
            .clocks
            .get_mut(sensor_id)
            .ok_or_else(|| LiveCorroborateError::UnknownCamera(sensor_id.to_owned()))?;
        *clock = CameraClockEstimator::new(sensor_id.to_owned(), self.config.clock)?;
        Ok(self.window.invalidate_camera(sensor_id))
    }
    /// Returns the bounded ring buffer of structured JSONL audit trace records.
    #[must_use]
    pub const fn recent_traces(&self) -> &VecDeque<String> {
        &self.traces
    }

    /// Returns the sealed [`ClockOffsetReceipt`] for `sensor_id`.
    pub fn clock_receipt(
        &self,
        sensor_id: &str,
    ) -> Result<ClockOffsetReceipt, LiveCorroborateError> {
        self.clocks
            .get(sensor_id)
            .ok_or_else(|| LiveCorroborateError::UnknownCamera(sensor_id.to_owned()))?
            .receipt()
    }

    /// Records a live clock sample for `sensor_id` and returns its conservative [`BoundedCaptureInterval`].
    pub fn observe_clock_sample(
        &mut self,
        sensor_id: &str,
        sample: ClockObservationSample,
    ) -> Result<BoundedCaptureInterval, LiveCorroborateError> {
        self.clocks
            .get_mut(sensor_id)
            .ok_or_else(|| LiveCorroborateError::UnknownCamera(sensor_id.to_owned()))?
            .observe(sample)
    }

    /// Advances the sliding-window watermark monotonically and evicts expired entries.
    pub fn advance_watermark(&mut self, watermark_ns: i128) -> EvictionStats {
        self.window.advance_watermark(watermark_ns)
    }

    /// Ingests one validated [`LiveObservation`] and evaluates every admissible cross-camera pair.
    pub fn ingest_observation(
        &mut self,
        observation: LiveObservation,
    ) -> Result<Vec<LiveCorroborationDecision>, LiveCorroborateError> {
        observation.validate()?;
        if !self.topology.cameras.contains_key(&observation.sensor_id) {
            return Err(LiveCorroborateError::UnknownCamera(observation.sensor_id));
        }
        let (admitted, _) = self.window.insert(observation.clone());
        if !admitted {
            return Ok(Vec::new());
        }
        let counterparts: Vec<LiveObservation> = self
            .window
            .counterparts_for(&observation.sensor_id)
            .into_iter()
            .cloned()
            .collect();
        let mut decisions = Vec::new();
        for other in &counterparts {
            if !self.classes_compatible(&observation, other) {
                continue;
            }
            if let Some(decision) = self.evaluate_pair(&observation, other)? {
                self.record_trace(&decision);
                decisions.push(decision);
            }
        }
        Ok(decisions)
    }

    /// Streams all surviving detections from a `C5` [`CascadeFrameReceipt`] directly into the
    /// live corroborator using the supplied [`ClockObservationSample`].
    pub fn ingest_cascade_receipt(
        &mut self,
        receipt: &CascadeFrameReceipt,
        stream_id: &str,
        zone_id: &str,
        base_track_id: u64,
        clock_sample: ClockObservationSample,
    ) -> Result<Vec<LiveCorroborationDecision>, LiveCorroborateError> {
        let bounded_capture =
            self.observe_clock_sample(receipt.sensor_id.as_str(), clock_sample)?;
        let mut all_decisions = Vec::new();
        for (offset, detection) in receipt.detections.iter().enumerate() {
            let track_id = base_track_id
                .checked_add(offset as u64)
                .ok_or(LiveCorroborateError::ArithmeticOverflow)?;
            let obs = LiveObservation::from_cascade_detection(
                receipt,
                detection,
                stream_id,
                zone_id,
                track_id,
                bounded_capture,
            )?;
            all_decisions.append(&mut self.ingest_observation(obs)?);
        }
        Ok(all_decisions)
    }

    fn evaluate_pair(
        &mut self,
        obs: &LiveObservation,
        other: &LiveObservation,
    ) -> Result<Option<LiveCorroborationDecision>, LiveCorroborateError> {
        let max_unc = self.config.clock.max_clock_uncertainty_ns;
        let spatial = self.topology.evaluate_pair_geometry(
            &obs.sensor_id,
            &obs.zone_id,
            obs.foot_px,
            &other.sensor_id,
            &other.zone_id,
            other.foot_px,
        );
        let (pair, timing, mechanism_opt) = match spatial {
            SpatialRelation::GroundProximity {
                distance,
                distance_gate,
                ground_a,
                ground_b,
                time_gate_ns,
                zone_id,
            } => {
                let timing = intervals_compatible(
                    obs.bounded_capture,
                    other.bounded_capture,
                    time_gate_ns,
                    max_unc,
                );
                let mech = match timing {
                    MatchDisposition::Compatible {
                        max_separation_ns, ..
                    } => Some(MatchMechanism::GroundHomography {
                        zone_id,
                        distance,
                        distance_gate,
                        ground_a,
                        ground_b,
                        max_separation_ns,
                    }),
                    _ => None,
                };
                ([obs, other], timing, mech)
            }
            SpatialRelation::SharedZone {
                zone_id,
                max_separation_ns,
            } => {
                let timing = intervals_compatible(
                    obs.bounded_capture,
                    other.bounded_capture,
                    max_separation_ns,
                    max_unc,
                );
                let mech = match timing {
                    MatchDisposition::Compatible {
                        max_separation_ns: sep,
                        ..
                    } => Some(MatchMechanism::SharedZone {
                        zone_id,
                        max_separation_ns: sep,
                    }),
                    _ => None,
                };
                ([obs, other], timing, mech)
            }
            SpatialRelation::TransitCorridor {
                corridor_id,
                from_camera,
                from_zone,
                to_camera,
                to_zone,
                min_transit_ns,
                max_transit_ns,
                direction_a_to_b,
            } => {
                let ordered = if direction_a_to_b {
                    [obs, other]
                } else {
                    [other, obs]
                };
                let timing = transit_compatible(
                    ordered[0].bounded_capture,
                    ordered[1].bounded_capture,
                    min_transit_ns,
                    max_transit_ns,
                    max_unc,
                );
                let mech = match timing {
                    MatchDisposition::TransitCompatible {
                        min_elapsed_ns,
                        max_elapsed_ns,
                    } => Some(MatchMechanism::TransitCorridor {
                        corridor_id,
                        from_camera,
                        from_zone,
                        to_camera,
                        to_zone,
                        min_elapsed_ns,
                        max_elapsed_ns,
                    }),
                    _ => None,
                };
                (ordered, timing, mech)
            }
            SpatialRelation::HorizonRefused { .. } | SpatialRelation::NoOverlap => return Ok(None),
        };

        if let Some(mechanism) = mechanism_opt {
            let seq = self.next_sequence()?;
            let receipts = self.collect_clock_receipts(&pair[0].sensor_id, &pair[1].sensor_id);
            let decision = fusion::evaluate_matched_pair(
                seq,
                &self.topology,
                self.topology_digest,
                &self.config.fusion,
                pair,
                mechanism,
                receipts,
            )?;
            return Ok(Some(decision));
        }
        if let MatchDisposition::ClockUncertaintyAbstained {
            uncertainty_ns,
            max_allowed_ns,
        } = timing
        {
            let seq = self.next_sequence()?;
            let receipts = self.collect_clock_receipts(&pair[0].sensor_id, &pair[1].sensor_id);
            return Ok(Some(fusion::seal_clock_abstention(
                seq,
                self.topology_digest,
                receipts,
                pair,
                uncertainty_ns,
                max_allowed_ns,
            )));
        }
        Ok(None)
    }

    fn classes_compatible(&self, a: &LiveObservation, b: &LiveObservation) -> bool {
        self.config.fusion.allow_class_mismatch
            || a.class_label == b.class_label
            || a.class_label == "unclassified"
            || b.class_label == "unclassified"
    }

    fn next_sequence(&mut self) -> Result<u64, LiveCorroborateError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(LiveCorroborateError::ArithmeticOverflow)?;
        Ok(self.sequence)
    }

    fn collect_clock_receipts(&self, cam_a: &str, cam_b: &str) -> Vec<ClockOffsetReceipt> {
        [cam_a, cam_b]
            .into_iter()
            .filter_map(|cam| self.clocks.get(cam)?.receipt().ok())
            .collect()
    }

    fn record_trace(&mut self, decision: &LiveCorroborationDecision) {
        if self.traces.len() == MAX_RETAINED_TRACE_LINES {
            self.traces.pop_front();
        }
        self.traces.push_back(decision.to_jsonl());
    }
}
