#![forbid(unsafe_code)]
//! Source-verified, receive-clock AVC reconstruction without a camera or invented EOF.
//!
//! This is a new deterministic interpretation of retained observations, not restoration of
//! the original live poll schedule. Equal-time arrivals precede future timer wakes; immediate
//! receiver output is drained between observations. Storage time never becomes media time.

use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm};
use fss_geometry::WorkBudget;
use fss_packet::{H264Mode, PacketError, ReorderDisposition, RtcpCompound, RtcpMode};
use fss_packet::avc::{AvcError, AvcReceiveAdmission, AvcReceiveCancellation, AvcReceiveError,
    AvcReceiveLimits, AvcReceivePoll, AvcReceiver, parse_pps, parse_sps};
use fss_publication::{LocalRootPublisher, PublishCancellation, PublishCutPoint};
use super::datagram_archive::{DatagramArchive, DatagramArchiveError, DatagramPin, RetainedDatagram};

mod profile;

/// Exact out-of-band interpretation. Parameter bytes exclude Annex-B start codes.
/// The caller retains their provenance independently; source packets do not supply missing SDP.
#[derive(Clone, Copy, Debug)]
pub struct AvcReplaySpec<'a> {
    /// Exact negotiated RTP payload number; no payload sniffing or codec fallback.
    pub payload_type: u8,
    /// Exact negotiated H.264 packetization mode.
    pub mode: H264Mode,
    /// Original sequence parameter set, not reconstructed defaults.
    pub sps: &'a [u8],
    /// Original picture parameter set for that SPS.
    pub pps: &'a [u8],
    /// All syntax, reorder, fragment and picture bounds; included in the interpretation digest.
    pub limits: AvcReceiveLimits,
    /// Whether reduced-size RTCP was explicitly selected.
    pub reduced_rtcp: bool,
    /// Independently accepted evidence for this configuration/interpretation, not access authority.
    pub configuration_evidence: ContentDigest,
}

/// Independent current-operation bounds, never decoded from retained source metadata.
#[derive(Clone, Copy, Debug)]
pub struct AvcReplayBounds {
    /// Complete input payload allowance; zero permits an empty source prefix only.
    pub max_source_bytes: u64,
    /// Finite progress/command calls, including clock advances and downstream timing commands.
    pub max_steps: u64,
    /// Absolute current storage-owner deadline, unrelated to historical receive timestamps.
    pub deadline_ns: u64,
}

/// Reconstruction errors preserve existing typed source and codec refusals.
#[derive(Debug)]
pub enum AvcReplayError {
    /// Invalid scope, parameters, lease, budget or configuration evidence.
    Configuration,
    /// Out-of-band parameter syntax failed before source I/O.
    Parameters(AvcError),
    /// Exact source read, budget, cancellation or custody failed.
    Source(DatagramArchiveError),
    /// Existing receiver refused the operation.
    Receiver(AvcReceiveError),
    /// The supplied current storage clock regressed; no progress was made.
    ClockReversed,
    /// This attempt has transferred its terminal ownership.
    Closed,
    /// Unexpected scheduler or prefix state; no successful completion is fabricated.
    Invariant,
}
impl std::fmt::Display for AvcReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AVC source reconstruction refused: {self:?}")
    }
}
impl std::error::Error for AvcReplayError {}
impl From<DatagramArchiveError> for AvcReplayError {
    fn from(e: DatagramArchiveError) -> Self { Self::Source(e) }
}
type Result<T> = std::result::Result<T, AvcReplayError>;

/// One complete, bounded output. Original observations are never collapsed into RTP dedup state.
#[derive(Debug)]
#[must_use]
pub enum AvcReplayStep {
    /// Original RTP and its actual receiver admission, including probation/duplicates.
    Rtp {
        /// Reverified durable original observation, still caller-owned after admission.
        source: RetainedDatagram,
        /// Existing typed admission, not a decoded-picture or coverage claim.
        admission: AvcReceiveAdmission,
        /// A confirmed source restart terminates this old-epoch reconstruction.
        retired: Option<AvcReceiveCancellation>,
    },
    /// RTCP remains original evidence. Invalid RTCP does not invent a video gap or wall clock.
    Rtcp {
        /// Exact retained control datagram (never an RTSP challenge or credential).
        source: RetainedDatagram,
        /// Whole compound validation, with no inferred sender-clock calibration.
        validation: std::result::Result<usize, PacketError>,
    },
    /// A malformed/refused RTP observation stopped reconstruction, preserving its exact bytes.
    InputRefused {
        /// Reverified original that could not enter the receiver.
        source: RetainedDatagram,
        /// Existing packet/epoch refusal.
        error: AvcReceiveError,
        /// All remaining receiver accounting; source custody is not deleted.
        retired: AvcReceiveCancellation,
    },
    /// Existing ordered-source, NAL, picture, gap or retirement output.
    Media {
        /// Historical virtual replay time, not the current storage clock or DTS.
        replay_ns: u64,
        /// The original receiver event, unchanged.
        event: AvcReceivePoll,
    },
    /// A recorded future arrival bounds a real receiver timer wake; no source read happened.
    ClockAdvanced {
        /// Exact virtual wake chosen before the next retained arrival.
        replay_ns: u64,
    },
    /// In-band codec termination is not transport EOF or proof that all source was consumed.
    CodecEnded {
        /// Time used by the existing receiver.
        replay_ns: u64,
        /// Existing codec terminal event, including its explicit unverified tail if any.
        event: AvcReceivePoll,
        /// Number of retained observations not consumed by this interpretation.
        remaining_datagrams: u64,
        /// Receiver retirement, without deleting original source.
        retired: AvcReceiveCancellation,
    },
    /// The exact retained prefix was drained at its final arrival time. No finish() was called.
    PrefixExhausted {
        /// Complete selected source prefix, not a stream-completeness claim.
        source: DatagramPin,
        /// No future timer was invented beyond this time.
        replay_ns: u64,
        /// Incomplete fragment/picture/queue accounting remains explicit.
        retired: AvcReceiveCancellation,
    },
    /// Terminal output was already transferred once.
    Ended,
}

/// Remaining ownership after cancellation/failure, including any output withheld after revocation.
#[derive(Debug)]
#[must_use]
pub struct AvcReplayRetirement {
    /// Exact independently selected source prefix.
    pub source: DatagramPin,
    /// Digest over source, exact configuration and deterministic scheduling policy.
    pub interpretation: ContentDigest,
    /// Number of original observations actually read in this attempt.
    pub observations_read: u64,
    /// Last virtual time reached, never inferred camera time.
    pub replay_ns: u64,
    /// Remaining receiver state; None when a terminal output already owns it.
    pub receiver: Option<AvcReceiveCancellation>,
    /// Output withheld after computation because current authority/budget was withdrawn.
    pub withheld: Option<Box<AvcReplayStep>>,
}

/// Safe clock refusals have no retirement. Every other runtime failure stops this attempt.
#[derive(Debug)]
pub struct AvcReplayFailure {
    /// Typed source/codec/operation error.
    pub reason: AvcReplayError,
    /// Complete remaining ownership when this operation fenced the replayer.
    pub retirement: Option<Box<AvcReplayRetirement>>,
}
impl std::fmt::Display for AvcReplayFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { std::fmt::Display::fmt(&self.reason, f) }
}
impl std::error::Error for AvcReplayFailure {}

/// Reconstruct the same immutable source prefix with an explicit, frozen interpretation.
/// No socket, mutation, latest-revision lookup, decoder process or payload cache is introduced.
/// A publisher is supplied per step so output windows may use that same owner between reads.
#[must_use]
#[derive(Debug)]
pub struct DatagramAvcReplay<'a> {
    archive: &'a DatagramArchive,
    receiver: Option<AvcReceiver>,
    interpretation: ContentDigest,
    packet_limits: fss_packet::PacketLimits,
    reduced_rtcp: bool,
    next: usize,
    replay_ns: u64,
    storage_ns: u64,
    bounds: AvcReplayBounds,
    steps: u64,
    poll_cost: u64,
    closed: bool,
}
impl<'a> DatagramAvcReplay<'a> {
    /// Parse and bind all parameters before reading source. The archive must be a recovered,
    /// owner-accepted inventory. Every later observation is reverified against current custody.
    pub fn new(archive: &'a DatagramArchive, spec: AvcReplaySpec<'_>, bounds: AvcReplayBounds,
        now_ns: u64) -> Result<Self> {
        if bounds.max_steps == 0 || now_ns >= bounds.deadline_ns
            || archive.pin().payload_bytes > bounds.max_source_bytes
            || spec.configuration_evidence.algorithm() != DigestAlgorithm::Sha256
            || spec.configuration_evidence.bytes() == [0; 32] || spec.payload_type > 127 {
            return Err(AvcReplayError::Configuration);
        }
        let sps = parse_sps(spec.sps, spec.limits.syntax).map_err(AvcReplayError::Parameters)?;
        let pps = parse_pps(spec.pps, &sps, spec.limits.syntax).map_err(AvcReplayError::Parameters)?;
        let receiver = AvcReceiver::new(archive.scope().binding.key(), spec.payload_type, spec.mode,
            spec.limits, (sps, pps)).map_err(AvcReplayError::Receiver)?;
        let interpretation = profile::digest(archive.pin(), spec)?;
        // Conservative traversal/copy reservation, not a calibrated performance receipt.
        let poll_cost = [spec.limits.reorder.max_bytes, spec.limits.reconstruction.max_nal_bytes,
            spec.limits.assembly.max_bytes].into_iter().try_fold(1024_u64, |sum, n| {
                sum.checked_add(u64::try_from(n).map_err(|_| AvcReplayError::Configuration)?)
                    .ok_or(AvcReplayError::Configuration)
            })?;
        Ok(Self { archive, receiver: Some(receiver), interpretation, packet_limits: spec.limits.reorder.packet,
            reduced_rtcp: spec.reduced_rtcp, next: 0, replay_ns: 0, storage_ns: now_ns,
            bounds, steps: 0, poll_cost, closed: false })
    }
    /// Full source/configuration/scheduler commitment, not proof of the original live schedule.
    pub fn interpretation(&self) -> ContentDigest { self.interpretation }
    /// Complete pinned input. Later source publications are not silently included.
    pub fn source(&self) -> DatagramPin { self.archive.pin() }
    /// Current virtual receive-clock time, independent of real-time storage admission.
    pub fn replay_ns(&self) -> u64 { self.replay_ns }
    /// Original observations read, including invalid and duplicate datagrams.
    pub fn observations_read(&self) -> u64 { self.next as u64 }

    /// Drain one receiver event, read/admit one original, or advance one timer. Never loop on
    /// Pending. Storage and work refusal stop the attempt without losing a produced output.
    pub fn step(&mut self, publisher: &LocalRootPublisher, now_ns: u64,
        cancel: &dyn PublishCancellation, budget: &mut WorkBudget<'_>)
        -> std::result::Result<AvcReplayStep, AvcReplayFailure> {
        if self.closed { return Ok(AvcReplayStep::Ended); }
        self.guard(now_ns, cancel, budget)?;
        let step = self.advance(publisher, cancel, budget).map_err(|e| self.fail(e, None))?;
        if let Err(error) = current(cancel, budget) { return Err(self.fail(error, Some(step))); }
        Ok(step)
    }
    fn advance(&mut self, publisher: &LocalRootPublisher, cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>) -> Result<AvcReplayStep> {
        budget.charge(self.poll_cost).map_err(DatagramArchiveError::Work)?;
        let event = self.receiver.as_mut().ok_or(AvcReplayError::Invariant)?
            .poll(self.replay_ns).map_err(AvcReplayError::Receiver)?;
        let wake = match event {
            AvcReceivePoll::Pending { wake_at_ns } => wake_at_ns,
            event @ AvcReceivePoll::Ended { .. } => {
                self.closed = true;
                let retired = self.take_receiver().ok_or(AvcReplayError::Invariant)?;
                return Ok(AvcReplayStep::CodecEnded { replay_ns: self.replay_ns, event,
                    remaining_datagrams: self.source().datagrams - self.next as u64, retired });
            }
            event => return Ok(AvcReplayStep::Media { replay_ns: self.replay_ns, event }),
        };
        let Some(next) = self.archive.records().get(self.next) else {
            self.closed = true;
            let retired = self.take_receiver().ok_or(AvcReplayError::Invariant)?;
            return Ok(AvcReplayStep::PrefixExhausted { source: self.source(), replay_ns: self.replay_ns, retired });
        };
        if next.received_ns < self.replay_ns { return Err(AvcReplayError::Invariant); }
        if let Some(at) = wake && at < next.received_ns {
            if at <= self.replay_ns { return Err(AvcReplayError::Invariant); }
            self.replay_ns = at;
            return Ok(AvcReplayStep::ClockAdvanced { replay_ns: at });
        }
        let source = self.archive.read(self.next as u64 + 1, publisher, cancel, budget)?;
        self.replay_ns = source.record().received_ns;
        self.next += 1;
        if source.record().channel == self.archive.scope().channels.1 {
            let mode = if self.reduced_rtcp { RtcpMode::ReducedSize } else { RtcpMode::Compound };
            let validation = RtcpCompound::parse(source.payload(), self.packet_limits, mode).map(|v| v.packet_count());
            return Ok(AvcReplayStep::Rtcp { source, validation });
        }
        let result = self.receiver.as_mut().ok_or(AvcReplayError::Invariant)?
            .ingest(self.archive.scope().binding.key(), source.payload(), self.replay_ns);
        match result {
            Ok(admission) => {
                let restart = admission.transport.transport.disposition == ReorderDisposition::RestartRequired;
                let retired = if restart { self.closed = true; self.take_receiver() } else { None };
                Ok(AvcReplayStep::Rtp { source, admission, retired })
            }
            Err(error) => {
                self.closed = true;
                let retired = self.take_receiver().ok_or(AvcReplayError::Invariant)?;
                Ok(AvcReplayStep::InputRefused { source, error, retired })
            }
        }
    }
    /// Stop without flushing a picture, reading more source or deleting any stored object.
    pub fn cancel(&mut self) -> Option<AvcReplayRetirement> {
        if self.closed && self.receiver.is_none() { return None; }
        Some(self.retire(None))
    }
    fn take_receiver(&mut self) -> Option<AvcReceiveCancellation> {
        self.receiver.take().map(|mut receiver| receiver.cancel())
    }
    fn retire(&mut self, withheld: Option<AvcReplayStep>) -> AvcReplayRetirement {
        self.closed = true;
        AvcReplayRetirement { source: self.source(), interpretation: self.interpretation,
            observations_read: self.next as u64, replay_ns: self.replay_ns,
            receiver: self.take_receiver(), withheld: withheld.map(Box::new) }
    }
    fn fail(&mut self, reason: AvcReplayError, withheld: Option<AvcReplayStep>) -> AvcReplayFailure {
        AvcReplayFailure { reason, retirement: Some(Box::new(self.retire(withheld))) }
    }
    fn guard(&mut self, now_ns: u64, cancel: &dyn PublishCancellation, budget: &mut WorkBudget<'_>)
        -> std::result::Result<(), AvcReplayFailure> {
        if self.closed { return Err(AvcReplayFailure { reason: AvcReplayError::Closed, retirement: None }); }
        if now_ns < self.storage_ns { return Err(AvcReplayFailure { reason: AvcReplayError::ClockReversed, retirement: None }); }
        let result = if now_ns >= self.bounds.deadline_ns { Err(DatagramArchiveError::Deadline.into()) }
            else if self.steps >= self.bounds.max_steps { Err(DatagramArchiveError::Limit.into()) }
            else { current(cancel, budget) };
        result.map_err(|e| self.fail(e, None))?;
        self.storage_ns = now_ns; self.steps += 1;
        Ok(())
    }
}
fn current(cancel: &dyn PublishCancellation, budget: &mut WorkBudget<'_>) -> Result<()> {
    if cancel.cancel_requested(PublishCutPoint::AfterChildrenVerified) { return Err(DatagramArchiveError::Cancelled.into()); }
    budget.charge(1).map_err(DatagramArchiveError::Work)?;
    Ok(())
}
