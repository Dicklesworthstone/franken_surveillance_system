#![forbid(unsafe_code)]
//! Operation-specific maximum tolerable time uncertainty enforcement (FSS-089 / TIME-OPERATION-TOLERANCE-001).
//!
//! Enforces typed, bounded per-operation capture-time uncertainty budgets. Time-sensitive operations
//! (e.g. cross-camera identity association, geometry-dependent negative evidence, transit feasibility)
//! declare an exact maximum tolerable uncertainty and consequence when exceeded.
//!
//! Any operation whose clock uncertainty exceeds its declared budget fails closed with typed error
//! [`TimeToleranceError::ClockUncertaintyExceeded`] (`ERR-CLOCK-UNCERTAIN-001`), or executes an explicit
//! typed [`ExceedanceConsequence::Abstain`] or [`ExceedanceConsequence::Degrade`]. Clock uncertainty
//! is never silently ignored and never downgraded to an uncalibrated low-confidence score.
//!
//! Unknown or unsynchronised clock state remains an explicit, typed state ([`ClockSyncState`]).
//! Interval composition strictly adheres to `FORMAL-010`: uncertainty intervals can only widen as evidence
//! worsens; models cannot narrow intervals without retained synchronization evidence.

use std::collections::BTreeMap;
use std::fmt;

use fss_core::{
    CanonicalEncode, CanonicalEncoder, CaptureInterval, ClockBasis, ContentDigest,
    TimeIntervalError, TimestampNs,
};

/// Stable error identity string for capture interval uncertainty exceeding operational tolerance.
pub const ERR_CLOCK_UNCERTAIN_001: &str = "ERR-CLOCK-UNCERTAIN-001";

/// Formal theorem identity asserting conservative time-interval composition under uncertainty.
pub const FORMAL_010_THEOREM_TAG: &str = "FORMAL-010";

/// Registered surveillance operations requiring bounded capture-time uncertainty.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TimeSensitiveOperation {
    /// Cross-camera identity re-identification / track association across disjoint FOVs.
    /// Requires tight synchronization to avoid associating distinct physical subjects.
    CrossCameraIdentityAssociation,
    /// Frustum/geometry-dependent negative evidence (claiming absence of an object in a region).
    /// Requires strict time bounds; excessive uncertainty could permit passage during unobserved windows.
    GeometryDependentNegativeEvidence,
    /// Transit feasibility check (evaluating if transit between two cameras is physically possible).
    TransitFeasibilityCheck,
    /// Coverage continuity witness (certifying continuous, gap-free sensor observability).
    CoverageContinuityWitness,
    /// Multi-camera stereoscopic 3D triangulation.
    StereoTriangulation,
    /// Incident chronological causality reconstruction.
    IncidentReconstruction,
    /// General multi-sensor belief fusion.
    MultiSensorFusion,
}

impl TimeSensitiveOperation {
    /// Returns the canonical machine-readable identifier for this operation.
    #[must_use]
    pub const fn operation_id(&self) -> &'static str {
        match self {
            Self::CrossCameraIdentityAssociation => "op.cross_camera_identity_association",
            Self::GeometryDependentNegativeEvidence => "op.geometry_negative_evidence",
            Self::TransitFeasibilityCheck => "op.transit_feasibility_check",
            Self::CoverageContinuityWitness => "op.coverage_continuity_witness",
            Self::StereoTriangulation => "op.stereo_triangulation",
            Self::IncidentReconstruction => "op.incident_reconstruction",
            Self::MultiSensorFusion => "op.multi_sensor_fusion",
        }
    }

    /// Returns the default maximum tolerable capture-time uncertainty in nanoseconds.
    #[must_use]
    pub const fn default_max_uncertainty_ns(&self) -> u64 {
        match self {
            // 50 ms for cross-camera identity
            Self::CrossCameraIdentityAssociation => 50_000_000,
            // 100 ms for negative absence claims
            Self::GeometryDependentNegativeEvidence => 100_000_000,
            // 200 ms for transit feasibility
            Self::TransitFeasibilityCheck => 200_000_000,
            // 50 ms for coverage continuity
            Self::CoverageContinuityWitness => 50_000_000,
            // 20 ms for stereo 3D triangulation
            Self::StereoTriangulation => 20_000_000,
            // 250 ms for causality reconstruction
            Self::IncidentReconstruction => 250_000_000,
            // 500 ms for multi-sensor fusion
            Self::MultiSensorFusion => 500_000_000,
        }
    }

    /// Returns the default exceedance consequence for this operation.
    #[must_use]
    pub const fn default_consequence(&self) -> ExceedanceConsequence {
        match self {
            Self::CrossCameraIdentityAssociation => ExceedanceConsequence::Abstain,
            Self::GeometryDependentNegativeEvidence => ExceedanceConsequence::Abstain,
            Self::TransitFeasibilityCheck => ExceedanceConsequence::FailClosed,
            Self::CoverageContinuityWitness => ExceedanceConsequence::FailClosed,
            Self::StereoTriangulation => ExceedanceConsequence::FailClosed,
            Self::IncidentReconstruction => ExceedanceConsequence::Degrade,
            Self::MultiSensorFusion => ExceedanceConsequence::Degrade,
        }
    }

    /// Returns the default required clock evidence for this operation.
    #[must_use]
    pub const fn default_required_clock(&self) -> RequiredClockEvidence {
        match self {
            Self::CrossCameraIdentityAssociation => RequiredClockEvidence::CertifiedSynchronised,
            Self::GeometryDependentNegativeEvidence => RequiredClockEvidence::CertifiedSynchronised,
            Self::TransitFeasibilityCheck => RequiredClockEvidence::BoundedMonotonicDrift,
            Self::CoverageContinuityWitness => RequiredClockEvidence::CertifiedSynchronised,
            Self::StereoTriangulation => RequiredClockEvidence::CertifiedSynchronised,
            Self::IncidentReconstruction => RequiredClockEvidence::BoundedMonotonicDrift,
            Self::MultiSensorFusion => RequiredClockEvidence::EstimatedWithCovariance,
        }
    }
}

/// Required level of clock synchronization evidence for an operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RequiredClockEvidence {
    /// Requires a certified, synchronised clock tied to UTC or a disciplined property master.
    CertifiedSynchronised,
    /// Accepts local monotonic clock if drift is bounded within tolerance.
    BoundedMonotonicDrift,
    /// Accepts estimated clock basis with explicit covariance.
    EstimatedWithCovariance,
}

/// Typed policy consequence executed when an observation's time uncertainty exceeds tolerance.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ExceedanceConsequence {
    /// Fail closed immediately with typed error [`TimeToleranceError::ClockUncertaintyExceeded`].
    FailClosed,
    /// Abstain from making the claim or association; produce an explicit typed abstention record.
    Abstain,
    /// Degrade to an unassociated observation or broader hypothesis; never silently downgrade confidence.
    Degrade,
}

/// Explicit state of clock synchronization for a sensor observation source.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum ClockSyncState {
    /// Sensor clock is certified synchronised to a reference basis.
    Synchronised {
        /// Clock basis of the synchronised reference.
        basis: ClockBasis,
        /// Estimated residual uncertainty bound in nanoseconds.
        residual_uncertainty_ns: u64,
        /// Monotone generation number of the active clock calibration.
        clock_generation: u64,
    },
    /// Sensor clock is unsynchronised, running on free monotonic counter with bounded drift.
    Unsynchronised {
        /// Nominal basis (e.g. DeviceMonotonic).
        basis: ClockBasis,
        /// Upper bound on accumulated drift since last reference sync in nanoseconds.
        drift_bound_ns: u64,
    },
    /// Clock synchronization state is explicitly unknown (e.g. missing metadata, uncertified source).
    Unknown {
        /// Structured reason why clock state is unknown.
        reason: String,
    },
}

impl ClockSyncState {
    /// Returns true if the clock is certified synchronised.
    #[must_use]
    pub const fn is_synchronised(&self) -> bool {
        matches!(self, Self::Synchronised { .. })
    }

    /// Returns true if the clock is unsynchronised.
    #[must_use]
    pub const fn is_unsynchronised(&self) -> bool {
        matches!(self, Self::Unsynchronised { .. })
    }

    /// Returns true if the clock state is explicitly unknown.
    #[must_use]
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown { .. })
    }

    /// Returns residual uncertainty or drift bound in nanoseconds if available.
    #[must_use]
    pub const fn clock_uncertainty_ns(&self) -> Option<u64> {
        match self {
            Self::Synchronised {
                residual_uncertainty_ns,
                ..
            } => Some(*residual_uncertainty_ns),
            Self::Unsynchronised { drift_bound_ns, .. } => Some(*drift_bound_ns),
            Self::Unknown { .. } => None,
        }
    }
}

impl CanonicalEncode for ClockSyncState {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::Synchronised {
                basis,
                residual_uncertainty_ns,
                clock_generation,
            } => {
                encoder.u8(1);
                basis.encode_canonical(encoder);
                encoder.u64(*residual_uncertainty_ns);
                encoder.u64(*clock_generation);
            }
            Self::Unsynchronised {
                basis,
                drift_bound_ns,
            } => {
                encoder.u8(2);
                basis.encode_canonical(encoder);
                encoder.u64(*drift_bound_ns);
            }
            Self::Unknown { reason } => {
                encoder.u8(3);
                encoder.text(reason);
            }
        }
    }
}

/// Detailed breakdown of all contributing capture-time uncertainty sources.
///
/// Under `FORMAL-010`, each source of physical and transport delay adds monotonically
/// to the conservative uncertainty interval.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct UncertaintySources {
    /// Exposure duration uncertainty in nanoseconds (shutter open interval).
    pub exposure_ns: u64,
    /// Rolling shutter line readout delay uncertainty in nanoseconds.
    pub rolling_shutter_ns: u64,
    /// Video encoder buffering and frame grouping (GOP) delay in nanoseconds.
    pub encoding_ns: u64,
    /// Local frame buffer queue delay in nanoseconds.
    pub buffering_ns: u64,
    /// Transport network transit jitter in nanoseconds.
    pub network_ns: u64,
    /// Vendor cloud relay processing, transcode, and queue jitter in nanoseconds.
    pub vendor_relay_ns: u64,
    /// Decode reordering jitter (B-frame presentation vs decode delay) in nanoseconds.
    pub decode_reorder_ns: u64,
    /// Hardware clock tick quantization granularity in nanoseconds.
    pub clock_quantization_ns: u64,
    /// Accumulated clock offset and drift uncertainty in nanoseconds.
    pub offset_drift_ns: u64,
}

impl UncertaintySources {
    /// Creates an empty (zero-uncertainty) breakdown.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            exposure_ns: 0,
            rolling_shutter_ns: 0,
            encoding_ns: 0,
            buffering_ns: 0,
            network_ns: 0,
            vendor_relay_ns: 0,
            decode_reorder_ns: 0,
            clock_quantization_ns: 0,
            offset_drift_ns: 0,
        }
    }

    /// Computes the conservative total sum of all uncertainty sources in nanoseconds.
    ///
    /// Fails closed with [`TimeToleranceError::ArithmeticOverflow`] if intermediate sum overflows.
    pub fn total_uncertainty_ns(&self) -> Result<u128, TimeToleranceError> {
        let mut total = 0u128;
        total = total
            .checked_add(self.exposure_ns as u128)
            .ok_or(TimeToleranceError::ArithmeticOverflow)?;
        total = total
            .checked_add(self.rolling_shutter_ns as u128)
            .ok_or(TimeToleranceError::ArithmeticOverflow)?;
        total = total
            .checked_add(self.encoding_ns as u128)
            .ok_or(TimeToleranceError::ArithmeticOverflow)?;
        total = total
            .checked_add(self.buffering_ns as u128)
            .ok_or(TimeToleranceError::ArithmeticOverflow)?;
        total = total
            .checked_add(self.network_ns as u128)
            .ok_or(TimeToleranceError::ArithmeticOverflow)?;
        total = total
            .checked_add(self.vendor_relay_ns as u128)
            .ok_or(TimeToleranceError::ArithmeticOverflow)?;
        total = total
            .checked_add(self.decode_reorder_ns as u128)
            .ok_or(TimeToleranceError::ArithmeticOverflow)?;
        total = total
            .checked_add(self.clock_quantization_ns as u128)
            .ok_or(TimeToleranceError::ArithmeticOverflow)?;
        total = total
            .checked_add(self.offset_drift_ns as u128)
            .ok_or(TimeToleranceError::ArithmeticOverflow)?;
        Ok(total)
    }

    /// Conservative RTP/UVC local camera profile with low jitter and direct host capture.
    #[must_use]
    pub const fn local_rtp_profile() -> Self {
        Self {
            exposure_ns: 5_000_000,         // 5 ms exposure
            rolling_shutter_ns: 2_000_000,  // 2 ms readout
            encoding_ns: 8_000_000,         // 8 ms encode buffer
            buffering_ns: 2_000_000,        // 2 ms ring buffer
            network_ns: 3_000_000,          // 3 ms LAN jitter
            vendor_relay_ns: 0,             // Direct local stream, zero cloud relay
            decode_reorder_ns: 0,           // Low-latency I/P stream
            clock_quantization_ns: 100_000, // 100 µs clock tick
            offset_drift_ns: 1_000_000,     // 1 ms local NTP drift
        }
    }

    /// Conservative vendor-cloud relay profile with transcode queueing and wide internet transit jitter.
    #[must_use]
    pub const fn vendor_cloud_relay_profile() -> Self {
        Self {
            exposure_ns: 16_000_000,          // 16 ms exposure
            rolling_shutter_ns: 8_000_000,    // 8 ms readout
            encoding_ns: 66_000_000,          // 66 ms GOP delay
            buffering_ns: 50_000_000,         // 50 ms buffer
            network_ns: 80_000_000,           // 80 ms internet jitter
            vendor_relay_ns: 350_000_000,     // 350 ms vendor cloud ingest/transcode queue
            decode_reorder_ns: 33_000_000,    // 33 ms B-frame reorder
            clock_quantization_ns: 1_000_000, // 1 ms cloud timestamp quantization
            offset_drift_ns: 50_000_000,      // 50 ms asynchronous cloud clock drift
        }
    }
}

impl CanonicalEncode for UncertaintySources {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.exposure_ns);
        encoder.u64(self.rolling_shutter_ns);
        encoder.u64(self.encoding_ns);
        encoder.u64(self.buffering_ns);
        encoder.u64(self.network_ns);
        encoder.u64(self.vendor_relay_ns);
        encoder.u64(self.decode_reorder_ns);
        encoder.u64(self.clock_quantization_ns);
        encoder.u64(self.offset_drift_ns);
    }
}

/// A complete, verifiable capture timing evidence record for a source item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceTimeEvidence {
    /// Monotone source stream sequence number.
    pub sequence: u64,
    /// Indicates whether a sequence discontinuity or packet gap preceded this item.
    pub has_discontinuity: bool,
    /// Device-reported raw timestamp if available.
    pub device_timestamp: Option<TimestampNs>,
    /// Declared device clock basis if reported.
    pub device_clock_basis: Option<ClockBasis>,
    /// Host monotonic receive timestamp.
    pub host_receive_time: TimestampNs,
    /// Explicit clock synchronization state.
    pub sync_state: ClockSyncState,
    /// Detailed uncertainty sources breakdown.
    pub uncertainty_sources: UncertaintySources,
    /// Conservative plausible capture interval: `[earliest, latest]`.
    pub plausible_capture_interval: CaptureInterval,
    /// Content digest over this timing record.
    pub evidence_digest: ContentDigest,
}

/// Parameters for constructing [`SourceTimeEvidence`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceTimeEvidenceParams {
    /// Zero-based sequential counter within stream session.
    pub sequence: u64,
    /// Whether a stream discontinuity was observed before this frame.
    pub has_discontinuity: bool,
    /// Declared device-origin timestamp if reported.
    pub device_timestamp: Option<TimestampNs>,
    /// Declared device clock basis if reported.
    pub device_clock_basis: Option<ClockBasis>,
    /// Host monotonic receive timestamp.
    pub host_receive_time: TimestampNs,
    /// Explicit clock synchronization state.
    pub sync_state: ClockSyncState,
    /// Detailed uncertainty sources breakdown.
    pub uncertainty_sources: UncertaintySources,
    /// Conservative plausible capture interval: `[earliest, latest]`.
    pub plausible_capture_interval: CaptureInterval,
}

impl SourceTimeEvidence {
    /// Creates a builder for constructing [`SourceTimeEvidence`].
    #[must_use]
    pub const fn builder(
        sequence: u64,
        host_receive_time: TimestampNs,
    ) -> SourceTimeEvidenceBuilder {
        SourceTimeEvidenceBuilder::new(sequence, host_receive_time)
    }

    /// Constructs a verified [`SourceTimeEvidence`] record from parameters.
    pub fn new(params: SourceTimeEvidenceParams) -> Result<Self, TimeToleranceError> {
        Self::try_from(params)
    }

    /// Monotonically widens the uncertainty interval (e.g. following observed network jitter).
    ///
    /// Preserves `FORMAL-010`: widening only expands the interval, never narrows.
    pub fn widen_uncertainty(self, additional_ns: u128) -> Result<Self, TimeToleranceError> {
        if additional_ns == 0 {
            return Ok(self);
        }
        if additional_ns > (i128::MAX as u128) {
            return Err(TimeToleranceError::ArithmeticOverflow);
        }
        let half = (additional_ns / 2) as i128;
        let rem = (additional_ns % 2) as i128;

        let earliest = self
            .plausible_capture_interval
            .earliest
            .checked_sub_ns(half)
            .map_err(|_| TimeToleranceError::ArithmeticOverflow)?;
        let latest = self
            .plausible_capture_interval
            .latest
            .checked_add_ns(half + rem)
            .map_err(|_| TimeToleranceError::ArithmeticOverflow)?;

        let new_interval = CaptureInterval::new_checked(earliest, latest)?;

        let mut updated_sources = self.uncertainty_sources;
        let additional_u64 = u64::try_from(additional_ns).unwrap_or(u64::MAX);
        updated_sources.network_ns = updated_sources.network_ns.saturating_add(additional_u64);

        Self::new(SourceTimeEvidenceParams {
            sequence: self.sequence,
            has_discontinuity: self.has_discontinuity,
            device_timestamp: self.device_timestamp,
            device_clock_basis: self.device_clock_basis,
            host_receive_time: self.host_receive_time,
            sync_state: self.sync_state,
            uncertainty_sources: updated_sources,
            plausible_capture_interval: new_interval,
        })
    }

    /// Returns the plausible capture interval uncertainty in nanoseconds.
    #[must_use]
    pub fn uncertainty_ns(&self) -> u128 {
        self.plausible_capture_interval.uncertainty_ns()
    }
}

impl TryFrom<SourceTimeEvidenceParams> for SourceTimeEvidence {
    type Error = TimeToleranceError;

    fn try_from(params: SourceTimeEvidenceParams) -> Result<Self, Self::Error> {
        let total_sources = params.uncertainty_sources.total_uncertainty_ns()?;
        let interval_width = params.plausible_capture_interval.uncertainty_ns();

        // Under FORMAL-010, the interval width must be at least as wide as the sum of all declared sources
        if interval_width < total_sources {
            return Err(TimeToleranceError::NonMonotoneNarrowingAttempted {
                previous_uncertainty_ns: total_sources,
                attempted_uncertainty_ns: interval_width,
            });
        }

        let mut encoder = CanonicalEncoder::new();
        encoder.u64(params.sequence);
        encoder.u8(if params.has_discontinuity { 1 } else { 0 });
        match params.device_timestamp {
            Some(ts) => {
                encoder.u8(1);
                ts.encode_canonical(&mut encoder);
            }
            None => encoder.u8(0),
        }
        match params.device_clock_basis {
            Some(basis) => {
                encoder.u8(1);
                basis.encode_canonical(&mut encoder);
            }
            None => encoder.u8(0),
        }
        params.host_receive_time.encode_canonical(&mut encoder);
        params.sync_state.encode_canonical(&mut encoder);
        params.uncertainty_sources.encode_canonical(&mut encoder);
        params
            .plausible_capture_interval
            .encode_canonical(&mut encoder);

        let bytes = encoder.finish();
        let evidence_digest = ContentDigest::sha256(&bytes);

        Ok(Self {
            sequence: params.sequence,
            has_discontinuity: params.has_discontinuity,
            device_timestamp: params.device_timestamp,
            device_clock_basis: params.device_clock_basis,
            host_receive_time: params.host_receive_time,
            sync_state: params.sync_state,
            uncertainty_sources: params.uncertainty_sources,
            plausible_capture_interval: params.plausible_capture_interval,
            evidence_digest,
        })
    }
}

/// Builder for constructing [`SourceTimeEvidence`] with automatic conservative interval computation.
#[derive(Clone, Debug)]
pub struct SourceTimeEvidenceBuilder {
    sequence: u64,
    has_discontinuity: bool,
    device_timestamp: Option<TimestampNs>,
    device_clock_basis: Option<ClockBasis>,
    host_receive_time: TimestampNs,
    sync_state: ClockSyncState,
    uncertainty_sources: UncertaintySources,
}

impl SourceTimeEvidenceBuilder {
    /// Creates a new timing builder with sequence and host receive instant.
    #[must_use]
    pub const fn new(sequence: u64, host_receive_time: TimestampNs) -> Self {
        Self {
            sequence,
            has_discontinuity: false,
            device_timestamp: None,
            device_clock_basis: None,
            host_receive_time,
            sync_state: ClockSyncState::Unknown {
                reason: String::new(),
            },
            uncertainty_sources: UncertaintySources::zero(),
        }
    }

    /// Sets the device-reported timestamp and clock basis.
    #[must_use]
    pub fn device_time(mut self, timestamp: TimestampNs, basis: ClockBasis) -> Self {
        self.device_timestamp = Some(timestamp);
        self.device_clock_basis = Some(basis);
        self
    }

    /// Sets whether a stream discontinuity preceded this capture.
    #[must_use]
    pub fn discontinuity(mut self, has_discontinuity: bool) -> Self {
        self.has_discontinuity = has_discontinuity;
        self
    }

    /// Sets the clock synchronization state.
    #[must_use]
    pub fn sync_state(mut self, sync_state: ClockSyncState) -> Self {
        self.sync_state = sync_state;
        self
    }

    /// Sets the uncertainty sources breakdown.
    #[must_use]
    pub fn uncertainty_sources(mut self, sources: UncertaintySources) -> Self {
        self.uncertainty_sources = sources;
        self
    }

    /// Builds the verified [`SourceTimeEvidence`], computing the conservative plausible capture interval.
    pub fn build(self) -> Result<SourceTimeEvidence, TimeToleranceError> {
        let mut total_uncertainty = self.uncertainty_sources.total_uncertainty_ns()?;

        // Add clock-specific residual or drift uncertainty
        match &self.sync_state {
            ClockSyncState::Synchronised {
                residual_uncertainty_ns,
                ..
            } => {
                total_uncertainty = total_uncertainty
                    .checked_add(*residual_uncertainty_ns as u128)
                    .ok_or(TimeToleranceError::ArithmeticOverflow)?;
            }
            ClockSyncState::Unsynchronised { drift_bound_ns, .. } => {
                total_uncertainty = total_uncertainty
                    .checked_add(*drift_bound_ns as u128)
                    .ok_or(TimeToleranceError::ArithmeticOverflow)?;
            }
            ClockSyncState::Unknown { .. } => {}
        }

        if total_uncertainty > (i128::MAX as u128) {
            return Err(TimeToleranceError::ArithmeticOverflow);
        }

        let base_timestamp = match (self.device_timestamp, &self.sync_state) {
            (Some(ts), ClockSyncState::Synchronised { .. }) => ts,
            (Some(ts), ClockSyncState::Unsynchronised { .. }) => ts,
            _ => self.host_receive_time,
        };

        let half_uncertainty = (total_uncertainty / 2) as i128;
        let remainder = (total_uncertainty % 2) as i128;

        let earliest = base_timestamp
            .checked_sub_ns(half_uncertainty)
            .map_err(|_| TimeToleranceError::ArithmeticOverflow)?;
        let latest = base_timestamp
            .checked_add_ns(half_uncertainty + remainder)
            .map_err(|_| TimeToleranceError::ArithmeticOverflow)?;

        let plausible_capture_interval = CaptureInterval::new_checked(earliest, latest)?;

        SourceTimeEvidence::new(SourceTimeEvidenceParams {
            sequence: self.sequence,
            has_discontinuity: self.has_discontinuity,
            device_timestamp: self.device_timestamp,
            device_clock_basis: self.device_clock_basis,
            host_receive_time: self.host_receive_time,
            sync_state: self.sync_state,
            uncertainty_sources: self.uncertainty_sources,
            plausible_capture_interval,
        })
    }
}

/// Declared per-operation time uncertainty tolerance and policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationTimeTolerance {
    /// The target surveillance operation.
    pub operation: TimeSensitiveOperation,
    /// Maximum tolerable capture-time uncertainty in nanoseconds.
    pub max_tolerable_uncertainty_ns: u64,
    /// Action taken when uncertainty exceeds tolerance.
    pub consequence: ExceedanceConsequence,
    /// Required clock evidence level.
    pub required_clock_evidence: RequiredClockEvidence,
}

impl OperationTimeTolerance {
    /// Constructs a custom operation tolerance specification.
    #[must_use]
    pub const fn new(
        operation: TimeSensitiveOperation,
        max_tolerable_uncertainty_ns: u64,
        consequence: ExceedanceConsequence,
        required_clock_evidence: RequiredClockEvidence,
    ) -> Self {
        Self {
            operation,
            max_tolerable_uncertainty_ns,
            consequence,
            required_clock_evidence,
        }
    }

    /// Constructs the standard default specification for an operation.
    #[must_use]
    pub const fn standard(operation: TimeSensitiveOperation) -> Self {
        Self {
            operation,
            max_tolerable_uncertainty_ns: operation.default_max_uncertainty_ns(),
            consequence: operation.default_consequence(),
            required_clock_evidence: operation.default_required_clock(),
        }
    }
}

/// Typed result of enforcing an operation's time uncertainty budget against evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnforcementOutcome {
    /// Uncertainty is within declared tolerance and clock requirements are met.
    Accepted {
        /// Admitted operation.
        operation: TimeSensitiveOperation,
        /// Observed interval uncertainty in nanoseconds.
        observed_uncertainty_ns: u128,
        /// Maximum declared tolerance bound in nanoseconds.
        tolerance_ns: u64,
        /// Remaining headroom in nanoseconds: `tolerance_ns - observed_uncertainty_ns`.
        headroom_ns: u64,
    },
    /// Operation abstained from making a claim due to excess uncertainty or clock deficiency.
    Abstained {
        /// Operation that abstained.
        operation: TimeSensitiveOperation,
        /// Observed interval uncertainty in nanoseconds.
        observed_uncertainty_ns: u128,
        /// Declared tolerance bound in nanoseconds.
        tolerance_ns: u64,
        /// Structured reason explaining abstention.
        reason: String,
    },
    /// Operation degraded to an unassociated observation or broader hypothesis.
    Degraded {
        /// Operation that degraded.
        operation: TimeSensitiveOperation,
        /// Observed interval uncertainty in nanoseconds.
        observed_uncertainty_ns: u128,
        /// Declared tolerance bound in nanoseconds.
        tolerance_ns: u64,
        /// Structured description of degraded state.
        degraded_state: String,
    },
}

impl EnforcementOutcome {
    /// Returns true if the operation was accepted within budget.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    /// Returns true if the operation abstained.
    #[must_use]
    pub const fn is_abstained(&self) -> bool {
        matches!(self, Self::Abstained { .. })
    }

    /// Returns true if the operation degraded.
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        matches!(self, Self::Degraded { .. })
    }
}

/// Catalog and enforcer of per-operation time uncertainty budgets.
#[derive(Clone, Debug)]
pub struct TimeUncertaintyBudget {
    tolerances: BTreeMap<TimeSensitiveOperation, OperationTimeTolerance>,
}

impl Default for TimeUncertaintyBudget {
    fn default() -> Self {
        Self::standard()
    }
}

impl TimeUncertaintyBudget {
    /// Creates an empty budget catalog.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tolerances: BTreeMap::new(),
        }
    }

    /// Alias for creating an empty budget catalog.
    #[must_use]
    pub fn empty() -> Self {
        Self::new()
    }

    /// Creates a budget catalog populated with standard surveillance operations.
    #[must_use]
    pub fn standard() -> Self {
        let mut budget = Self::new();
        budget.register(OperationTimeTolerance::standard(
            TimeSensitiveOperation::CrossCameraIdentityAssociation,
        ));
        budget.register(OperationTimeTolerance::standard(
            TimeSensitiveOperation::GeometryDependentNegativeEvidence,
        ));
        budget.register(OperationTimeTolerance::standard(
            TimeSensitiveOperation::TransitFeasibilityCheck,
        ));
        budget.register(OperationTimeTolerance::standard(
            TimeSensitiveOperation::CoverageContinuityWitness,
        ));
        budget.register(OperationTimeTolerance::standard(
            TimeSensitiveOperation::StereoTriangulation,
        ));
        budget.register(OperationTimeTolerance::standard(
            TimeSensitiveOperation::IncidentReconstruction,
        ));
        budget.register(OperationTimeTolerance::standard(
            TimeSensitiveOperation::MultiSensorFusion,
        ));
        budget
    }

    /// Registers or overrides a tolerance specification for an operation.
    pub fn register(&mut self, tolerance: OperationTimeTolerance) {
        self.tolerances.insert(tolerance.operation, tolerance);
    }

    /// Returns the registered tolerance specification for an operation.
    pub fn tolerance_for(
        &self,
        operation: TimeSensitiveOperation,
    ) -> Result<&OperationTimeTolerance, TimeToleranceError> {
        self.tolerances
            .get(&operation)
            .ok_or(TimeToleranceError::UnregisteredOperation(operation))
    }

    /// Enforces the operation's time uncertainty budget against the provided source evidence.
    ///
    /// Evaluates:
    /// 1. Clock evidence sufficiency against `required_clock_evidence`.
    /// 2. Capture interval width against `max_tolerable_uncertainty_ns`.
    /// 3. If exceeded or deficient, executes the operation's declared [`ExceedanceConsequence`].
    pub fn enforce(
        &self,
        operation: TimeSensitiveOperation,
        evidence: &SourceTimeEvidence,
    ) -> Result<EnforcementOutcome, TimeToleranceError> {
        let tolerance = self.tolerance_for(operation)?;

        // 1. Check clock synchronization requirement
        match (&evidence.sync_state, tolerance.required_clock_evidence) {
            (ClockSyncState::Unknown { reason }, _) => {
                let msg = format!(
                    "operation {} requires synchronised clock evidence, but clock state is unknown: {reason}",
                    operation.operation_id()
                );
                return match tolerance.consequence {
                    ExceedanceConsequence::FailClosed => {
                        Err(TimeToleranceError::ClockStateUnknown {
                            operation,
                            reason: reason.clone(),
                        })
                    }
                    ExceedanceConsequence::Abstain => Ok(EnforcementOutcome::Abstained {
                        operation,
                        observed_uncertainty_ns: evidence
                            .plausible_capture_interval
                            .uncertainty_ns(),
                        tolerance_ns: tolerance.max_tolerable_uncertainty_ns,
                        reason: msg,
                    }),
                    ExceedanceConsequence::Degrade => Ok(EnforcementOutcome::Degraded {
                        operation,
                        observed_uncertainty_ns: evidence
                            .plausible_capture_interval
                            .uncertainty_ns(),
                        tolerance_ns: tolerance.max_tolerable_uncertainty_ns,
                        degraded_state: msg,
                    }),
                };
            }
            (
                ClockSyncState::Unsynchronised {
                    basis,
                    drift_bound_ns,
                },
                RequiredClockEvidence::CertifiedSynchronised,
            ) => {
                let msg = format!(
                    "operation {} requires certified synchronised clock, but clock is unsynchronised ({basis:?}, drift bound {drift_bound_ns} ns)",
                    operation.operation_id()
                );
                return match tolerance.consequence {
                    ExceedanceConsequence::FailClosed => {
                        Err(TimeToleranceError::ClockUnsynchronised {
                            operation,
                            basis: *basis,
                            drift_bound_ns: *drift_bound_ns,
                        })
                    }
                    ExceedanceConsequence::Abstain => Ok(EnforcementOutcome::Abstained {
                        operation,
                        observed_uncertainty_ns: evidence
                            .plausible_capture_interval
                            .uncertainty_ns(),
                        tolerance_ns: tolerance.max_tolerable_uncertainty_ns,
                        reason: msg,
                    }),
                    ExceedanceConsequence::Degrade => Ok(EnforcementOutcome::Degraded {
                        operation,
                        observed_uncertainty_ns: evidence
                            .plausible_capture_interval
                            .uncertainty_ns(),
                        tolerance_ns: tolerance.max_tolerable_uncertainty_ns,
                        degraded_state: msg,
                    }),
                };
            }
            _ => {}
        }

        // 2. Check uncertainty bound
        let observed_uncertainty = evidence.plausible_capture_interval.uncertainty_ns();
        let max_tolerable = tolerance.max_tolerable_uncertainty_ns as u128;

        if observed_uncertainty <= max_tolerable {
            let headroom = (max_tolerable - observed_uncertainty) as u64;
            Ok(EnforcementOutcome::Accepted {
                operation,
                observed_uncertainty_ns: observed_uncertainty,
                tolerance_ns: tolerance.max_tolerable_uncertainty_ns,
                headroom_ns: headroom,
            })
        } else {
            match tolerance.consequence {
                ExceedanceConsequence::FailClosed => {
                    Err(TimeToleranceError::ClockUncertaintyExceeded {
                        error_code: ERR_CLOCK_UNCERTAIN_001,
                        operation,
                        observed_uncertainty_ns: observed_uncertainty,
                        max_tolerable_uncertainty_ns: tolerance.max_tolerable_uncertainty_ns,
                    })
                }
                ExceedanceConsequence::Abstain => Ok(EnforcementOutcome::Abstained {
                    operation,
                    observed_uncertainty_ns: observed_uncertainty,
                    tolerance_ns: tolerance.max_tolerable_uncertainty_ns,
                    reason: format!(
                        "observed capture uncertainty ({} ns) exceeds maximum tolerable budget ({} ns)",
                        observed_uncertainty, tolerance.max_tolerable_uncertainty_ns
                    ),
                }),
                ExceedanceConsequence::Degrade => Ok(EnforcementOutcome::Degraded {
                    operation,
                    observed_uncertainty_ns: observed_uncertainty,
                    tolerance_ns: tolerance.max_tolerable_uncertainty_ns,
                    degraded_state: format!(
                        "degraded to unassociated observation: uncertainty {} ns > tolerance {} ns",
                        observed_uncertainty, tolerance.max_tolerable_uncertainty_ns
                    ),
                }),
            }
        }
    }

    /// Enforces that the operation succeeds with strict zero tolerance for exceedance (fails closed).
    pub fn enforce_strict(
        &self,
        operation: TimeSensitiveOperation,
        evidence: &SourceTimeEvidence,
    ) -> Result<EnforcementOutcome, TimeToleranceError> {
        let outcome = self.enforce(operation, evidence)?;
        match outcome {
            EnforcementOutcome::Accepted { .. } => Ok(outcome),
            EnforcementOutcome::Abstained {
                observed_uncertainty_ns,
                tolerance_ns,
                ..
            }
            | EnforcementOutcome::Degraded {
                observed_uncertainty_ns,
                tolerance_ns,
                ..
            } => Err(TimeToleranceError::ClockUncertaintyExceeded {
                error_code: ERR_CLOCK_UNCERTAIN_001,
                operation,
                observed_uncertainty_ns,
                max_tolerable_uncertainty_ns: tolerance_ns,
            }),
        }
    }
}

/// Decision outcome of a cross-camera temporal association evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AssociationDecision {
    /// Observations are temporally consistent with feasible transit between cameras.
    Consistent {
        /// Feasible transit arrival interval at the destination camera.
        transit_interval: CaptureInterval,
        /// Overlap region between predicted arrival and observed destination capture.
        overlap: CaptureInterval,
    },
    /// Transit is physically impossible: destination capture occurred outside the feasible transit window.
    PhysicallyImpossible {
        /// Reason describing the temporal impossibility.
        reason: String,
    },
    /// Association evaluation abstained due to excessive clock uncertainty or missing synchronization.
    Abstained {
        /// Reason explaining abstention.
        reason: String,
    },
    /// Temporal association is indeterminate due to boundary overlap or uncertainty.
    Indeterminate {
        /// Reason explaining indeterminacy.
        reason: String,
    },
}

impl AssociationDecision {
    /// Returns true if the association is consistent.
    #[must_use]
    pub const fn is_consistent(&self) -> bool {
        matches!(self, Self::Consistent { .. })
    }

    /// Returns true if the association was physically impossible.
    #[must_use]
    pub const fn is_physically_impossible(&self) -> bool {
        matches!(self, Self::PhysicallyImpossible { .. })
    }

    /// Returns true if the association evaluation abstained.
    #[must_use]
    pub const fn is_abstained(&self) -> bool {
        matches!(self, Self::Abstained { .. })
    }

    /// Returns true if the association is indeterminate.
    #[must_use]
    pub const fn is_indeterminate(&self) -> bool {
        matches!(self, Self::Indeterminate { .. })
    }
}

/// Evaluates cross-camera temporal association between two camera observations.
///
/// Models physical transit from camera A to camera B:
/// 1. Enforces [`TimeSensitiveOperation::CrossCameraIdentityAssociation`] tolerance on both sources.
/// 2. Predicts arrival interval: `[earliest_A + min_transit_ns, latest_A + max_transit_ns]`.
/// 3. Evaluates intersection with camera B's capture interval.
/// 4. If disjoint: returns [`AssociationDecision::PhysicallyImpossible`].
/// 5. If overlapping: returns [`AssociationDecision::Consistent`].
///
/// Adheres to `FORMAL-010`: widening uncertainty on A or B can only transition a
/// `PhysicallyImpossible` decision to `Indeterminate` or `Abstained`; it can never create
/// a stronger identity claim without evidence.
pub fn evaluate_cross_camera_association(
    budget: &TimeUncertaintyBudget,
    obs_a: &SourceTimeEvidence,
    obs_b: &SourceTimeEvidence,
    min_transit_time_ns: u64,
    max_transit_time_ns: u64,
) -> Result<AssociationDecision, TimeToleranceError> {
    if min_transit_time_ns > max_transit_time_ns {
        return Err(TimeToleranceError::InvertedInterval {
            earliest: TimestampNs(min_transit_time_ns as i128),
            latest: TimestampNs(max_transit_time_ns as i128),
        });
    }

    let op = TimeSensitiveOperation::CrossCameraIdentityAssociation;

    // Enforce tolerance on camera A
    let outcome_a = budget.enforce(op, obs_a)?;
    if let EnforcementOutcome::Abstained { reason, .. } = outcome_a {
        return Ok(AssociationDecision::Abstained {
            reason: format!("camera A timing rejected: {reason}"),
        });
    }

    // Enforce tolerance on camera B
    let outcome_b = budget.enforce(op, obs_b)?;
    if let EnforcementOutcome::Abstained { reason, .. } = outcome_b {
        return Ok(AssociationDecision::Abstained {
            reason: format!("camera B timing rejected: {reason}"),
        });
    }

    // Predict arrival window at camera B
    let min_transit = i128::from(min_transit_time_ns);
    let max_transit = i128::from(max_transit_time_ns);

    let earliest_arrival = obs_a
        .plausible_capture_interval
        .earliest
        .checked_add_ns(min_transit)
        .map_err(|_| TimeToleranceError::ArithmeticOverflow)?;
    let latest_arrival = obs_a
        .plausible_capture_interval
        .latest
        .checked_add_ns(max_transit)
        .map_err(|_| TimeToleranceError::ArithmeticOverflow)?;

    let transit_interval = CaptureInterval::new_checked(earliest_arrival, latest_arrival)?;

    if let Some(overlap) = transit_interval.intersection(obs_b.plausible_capture_interval) {
        Ok(AssociationDecision::Consistent {
            transit_interval,
            overlap,
        })
    } else {
        Ok(AssociationDecision::PhysicallyImpossible {
            reason: format!(
                "camera B capture {} is disjoint from feasible transit arrival window {}",
                obs_b.plausible_capture_interval, transit_interval
            ),
        })
    }
}

/// Errors occurring in the operation-specific time uncertainty subsystem.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TimeToleranceError {
    /// Capture interval uncertainty exceeds the operation's declared tolerance bound [ERR-CLOCK-UNCERTAIN-001].
    ClockUncertaintyExceeded {
        /// Stable machine error code: `"ERR-CLOCK-UNCERTAIN-001"`.
        error_code: &'static str,
        /// Operation whose tolerance was violated.
        operation: TimeSensitiveOperation,
        /// Observed uncertainty in nanoseconds.
        observed_uncertainty_ns: u128,
        /// Declared maximum tolerable bound in nanoseconds.
        max_tolerable_uncertainty_ns: u64,
    },
    /// Clock synchronization state is unknown when synchronised evidence was required.
    ClockStateUnknown {
        /// Operation requiring synchronised clock.
        operation: TimeSensitiveOperation,
        /// Reason clock state is unknown.
        reason: String,
    },
    /// Clock is unsynchronised when certified clock evidence was required.
    ClockUnsynchronised {
        /// Operation requiring certified synchronised clock.
        operation: TimeSensitiveOperation,
        /// Observed clock basis.
        basis: ClockBasis,
        /// Observed drift bound in nanoseconds.
        drift_bound_ns: u64,
    },
    /// Target operation is not registered in the budget catalog.
    UnregisteredOperation(TimeSensitiveOperation),
    /// Interval is inverted: earliest > latest.
    InvertedInterval {
        /// Earliest bound.
        earliest: TimestampNs,
        /// Latest bound.
        latest: TimestampNs,
    },
    /// Clock basis mismatch when comparing or intersecting intervals.
    ClockBasisMismatch {
        /// Expected basis.
        expected: ClockBasis,
        /// Actual basis observed.
        actual: ClockBasis,
    },
    /// Arithmetic overflow occurred in nanosecond timestamp or uncertainty calculation.
    ArithmeticOverflow,
    /// Operation attempted to narrow an uncertainty interval (FORMAL-010 monotonicity violation).
    NonMonotoneNarrowingAttempted {
        /// Current or baseline uncertainty in nanoseconds.
        previous_uncertainty_ns: u128,
        /// Attempted narrower uncertainty in nanoseconds.
        attempted_uncertainty_ns: u128,
    },
}

impl TimeToleranceError {
    /// Returns the stable error code string, or generic label if non-standard.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::ClockUncertaintyExceeded { error_code, .. } => error_code,
            Self::ClockStateUnknown { .. } => "ERR-CLOCK-STATE-UNKNOWN-001",
            Self::ClockUnsynchronised { .. } => "ERR-CLOCK-UNSYNCHRONISED-001",
            Self::UnregisteredOperation(_) => "ERR-OPERATION-UNREGISTERED-001",
            Self::InvertedInterval { .. } => "ERR-TIME-INTERVAL-INVERTED-001",
            Self::ClockBasisMismatch { .. } => "ERR-CLOCK-BASIS-MISMATCH-001",
            Self::ArithmeticOverflow => "ERR-ARITHMETIC-OVERFLOW-001",
            Self::NonMonotoneNarrowingAttempted { .. } => "ERR-NON-MONOTONE-NARROWING-001",
        }
    }
}

impl fmt::Display for TimeToleranceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClockUncertaintyExceeded {
                error_code,
                operation,
                observed_uncertainty_ns,
                max_tolerable_uncertainty_ns,
            } => {
                write!(
                    f,
                    "[{error_code}] operation {} time uncertainty ({} ns) exceeds declared tolerance bound ({} ns)",
                    operation.operation_id(),
                    observed_uncertainty_ns,
                    max_tolerable_uncertainty_ns
                )
            }
            Self::ClockStateUnknown { operation, reason } => {
                write!(
                    f,
                    "operation {} requires synchronised clock, but clock state is unknown: {reason}",
                    operation.operation_id()
                )
            }
            Self::ClockUnsynchronised {
                operation,
                basis,
                drift_bound_ns,
            } => {
                write!(
                    f,
                    "operation {} requires certified synchronised clock, but clock is unsynchronised ({basis:?}, drift bound {drift_bound_ns} ns)",
                    operation.operation_id()
                )
            }
            Self::UnregisteredOperation(op) => {
                write!(
                    f,
                    "operation {} is not registered in time uncertainty budget",
                    op.operation_id()
                )
            }
            Self::InvertedInterval { earliest, latest } => {
                write!(
                    f,
                    "inverted time interval: earliest ({earliest}) > latest ({latest})"
                )
            }
            Self::ClockBasisMismatch { expected, actual } => {
                write!(
                    f,
                    "clock basis mismatch: expected {expected:?}, observed {actual:?}"
                )
            }
            Self::ArithmeticOverflow => {
                write!(
                    f,
                    "arithmetic overflow in nanosecond time uncertainty calculation"
                )
            }
            Self::NonMonotoneNarrowingAttempted {
                previous_uncertainty_ns,
                attempted_uncertainty_ns,
            } => {
                write!(
                    f,
                    "[{FORMAL_010_THEOREM_TAG}] attempted to narrow uncertainty from {previous_uncertainty_ns} ns to {attempted_uncertainty_ns} ns without retained synchronization evidence"
                )
            }
        }
    }
}

impl std::error::Error for TimeToleranceError {}

impl From<TimeIntervalError> for TimeToleranceError {
    fn from(err: TimeIntervalError) -> Self {
        match err {
            TimeIntervalError::InvertedInterval { earliest, latest } => Self::InvertedInterval {
                earliest: TimestampNs(earliest),
                latest: TimestampNs(latest),
            },
            TimeIntervalError::ArithmeticOverflow => Self::ArithmeticOverflow,
            TimeIntervalError::NonMonotoneUncertaintyNarrowing => {
                Self::NonMonotoneNarrowingAttempted {
                    previous_uncertainty_ns: 0,
                    attempted_uncertainty_ns: 0,
                }
            }
            TimeIntervalError::ClockBasisMismatch { expected, actual } => {
                Self::ClockBasisMismatch { expected, actual }
            }
            _ => Self::ArithmeticOverflow,
        }
    }
}
