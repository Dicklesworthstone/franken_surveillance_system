#![forbid(unsafe_code)]
//! Finite HEVC recording reacquisition using the existing native capture owner.
//!
//! Each attempt reserves the same whole-run resource dimensions as AVC and starts
//! a new stream generation. Source EOB, physical TCP EOF, capture draining and
//! durable publication remain different observations. No socket, picture, timing,
//! credential or prepared recording is carried into a replacement connection.

mod timing;

use std::fmt;
use timing::TimingTickets;
pub use timing::{HevcTimingRefusal, HevcTimingTicket};

use fss_core::ContentDigest;
use fss_packet::hevc::{HevcAssemblyLimits, HevcConfiguration};
use fss_packet::{H265Limits, ReorderLimits, StreamKey};

use super::{
    ReconnectAttempt, ReconnectBudget, ReconnectBudgetState, ReconnectPolicy, ReconnectRefusal,
    ReconnectStatus, ReconnectStop, ReservationLedger, Schedule, retryable_transport,
};
use crate::rtsp::authentication::{DigestCredentials, DigestPolicy};
use crate::rtsp::client::{ClientConfig, ClientState};
use crate::rtsp::hevc_client::HevcClientPoll;
use crate::rtsp::hevc_client::pictures::{HevcPictureClientPoll, HevcPictureWorkReason};
use crate::rtsp::hevc_recording_capture::live::{
    AutomaticHevcRecordingStep, AutomaticLiveHevcRecording, LiveHevcRecordingConfig,
    LiveHevcRecordingConnectFailure, LiveHevcRecordingError, LiveHevcRecordingFailure,
    LiveHevcRecordingRetirement,
};
use crate::rtsp::hevc_recording_capture::{HevcCapturePoll, TimedHevcCapture};
use crate::rtsp::hevc_recording_collector::{HevcCollectionSeal, HevcRecordingCollector};
use crate::rtsp::live_hevc::{LiveHevcConfig, LiveHevcError, SocketReadiness};
use crate::rtsp::recording::RecordingScope;
use crate::rtsp::recording::hevc::HevcRecordingTiming;
use crate::rtsp::recording_collector::CollectorLimits;
use crate::rtsp::tcp::{TcpAuthority, TcpBinding, TcpLimits, TcpTotals};

// Deliberately not Debug: source identity, realm and URI are sensitive metadata.
struct Profile {
    protocol: ClientConfig,
    realm: String,
    digest: DigestPolicy,
    transport: TcpLimits,
    reorder: ReorderLimits,
    reconstruction: H265Limits,
    assembly: HevcAssemblyLimits,
    steps: u64,
    scope: RecordingScope,
    payload_type: u8,
    time_scale: u32,
    collection: CollectorLimits,
    // Distinct positions bind every original byte, including uninterpreted suffixes.
    // These internal comparison pins are not a new durable configuration format.
    parameters: [ContentDigest; 3],
}
impl Profile {
    fn new(
        live: &LiveHevcConfig,
        recording: &LiveHevcRecordingConfig,
    ) -> Result<Self, ReconnectRefusal> {
        Ok(Self {
            protocol: live.protocol.clone(),
            realm: live.realm.clone(),
            digest: live.digest_policy,
            transport: live.transport,
            reorder: live.reorder,
            reconstruction: live.reconstruction,
            assembly: live.assembly,
            steps: live.max_steps,
            scope: recording.scope.clone(),
            payload_type: recording.payload_type,
            time_scale: recording.time_scale,
            collection: recording.limits,
            parameters: parameter_pins(&recording.configuration)?,
        })
    }

    fn permits(
        &self,
        live: &LiveHevcConfig,
        recording: &LiveHevcRecordingConfig,
    ) -> Result<bool, ReconnectRefusal> {
        let limits = live.transport;
        Ok(self.protocol == live.protocol
            && self.realm == live.realm
            && self.digest == live.digest_policy
            && self.reorder == live.reorder
            && self.reconstruction == live.reconstruction
            && self.assembly == live.assembly
            && live.max_steps <= self.steps
            && limits.max_received_bytes <= self.transport.max_received_bytes
            && limits.max_sent_bytes <= self.transport.max_sent_bytes
            && limits.max_io_calls <= self.transport.max_io_calls
            && limits.max_request_bytes <= self.transport.max_request_bytes
            && limits.chunk_bytes <= self.transport.chunk_bytes
            && limits.connect_timeout_ns <= self.transport.connect_timeout_ns
            && self.scope.sensor == recording.scope.sensor
            && self.scope.stream == recording.scope.stream
            && self.payload_type == recording.payload_type
            && self.time_scale == recording.time_scale
            && self.collection == recording.limits
            && self.parameters == parameter_pins(&recording.configuration)?)
    }
}

fn parameter_pins(
    configuration: &HevcConfiguration,
) -> Result<[ContentDigest; 3], ReconnectRefusal> {
    let pin = |bytes: &[u8]| {
        ContentDigest::try_sha256(bytes).map_err(|_| ReconnectRefusal::Configuration)
    };
    Ok([
        pin(configuration.vps())?,
        pin(configuration.sps())?,
        pin(configuration.pps())?,
    ])
}

/// Refusal without source bytes, addresses, realm, credentials or server text.
#[derive(Debug)]
pub enum SupervisedHevcRecordingError {
    /// Original finite schedule, authority, scope or resource refusal.
    Supervisor(ReconnectRefusal),
    /// Original native construction refusal, including whether a socket was attempted.
    Connect(LiveHevcRecordingConnectFailure),
    /// Original native network, timing or collection refusal.
    Recording(LiveHevcRecordingError),
    /// A stale picture ticket or an impossible native timing-request transition.
    Timing(HevcTimingRefusal),
}

/// Exact terminal ownership on a failed operation. Safe corrections have no retirement.
#[must_use]
#[derive(Debug)]
pub struct SupervisedHevcRecordingFailure {
    /// Generation of the refused operation and any returned originals.
    pub key: StreamKey,
    /// Payload-free stage and reason.
    pub reason: SupervisedHevcRecordingError,
    /// Every retained native/capture layer, transferred once on fatal failure.
    pub retirement: Option<Box<LiveHevcRecordingRetirement>>,
}
impl fmt::Display for SupervisedHevcRecordingFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "supervised HEVC recording refusal: {:?}", self.reason)
    }
}
impl std::error::Error for SupervisedHevcRecordingFailure {}

/// A scheduling observation or one unchanged native HEVC recording output.
#[must_use]
#[derive(Debug)]
pub enum SupervisedHevcRecordingStep {
    /// No socket exists; absolute time, work limits and live authority still apply.
    Waiting {
        /// Exact next-generation source key.
        key: StreamKey,
        /// Earliest connection admission on the owner's monotonic clock.
        retry_at_ns: u64,
    },
    /// Handle the original terminal output before acknowledging retirement.
    Retired(StreamKey),
    /// Original wire/control/media/timing/window/terminal output, never a custody upgrade.
    Recording {
        /// Generation that produced the unchanged output.
        key: StreamKey,
        /// The existing HEVC owner's complete output, including source-only witnesses.
        output: AutomaticHevcRecordingStep,
    },
}

/// End observations are deliberately accumulated separately from capture completion.
/// A socket retirement or an EOB event can precede timing, windows and trailing originals.
#[derive(Debug, Default)]
struct SourceEnd {
    network_retired: bool,
    peer_eof: bool,
    receiver_ended: bool,
    bitstream_ended: bool,
}
impl SourceEnd {
    fn observe(&mut self, event: &HevcPictureClientPoll) {
        match event {
            HevcPictureClientPoll::Ended {
                client: Some(client),
                ..
            } if matches!(
                client.as_ref(),
                HevcClientPoll::Ended {
                    retirement: Some(_),
                    ..
                }
            ) =>
            {
                self.receiver_ended = true;
            }
            HevcPictureClientPoll::Assembly {
                retirement: Some(retirement),
                ..
            } if retirement.work.reason == HevcPictureWorkReason::EndOfBitstream => {
                self.bitstream_ended = true;
            }
            _ => {}
        }
    }

    fn completion(&self) -> Option<ReconnectStop> {
        // A source EOB is not a network outage, even if TCP EOF is also observed.
        if self.network_retired && self.bitstream_ended {
            Some(ReconnectStop::SourceEnded)
        } else if self.network_retired && self.peer_eof && self.receiver_ended {
            None
        } else {
            // No observed end closure can be invented from a local Ended state.
            Some(ReconnectStop::PermanentFailure)
        }
    }
}

/// Bounded reacquisition of one explicitly authorized native HEVC recording route.
///
/// Supply the full native and recording configurations for each attempt. The first
/// admitted profile pins media limits, exact original VPS/SPS/PPS, camera identity,
/// payload/timescale, collection limits, URI scope and authentication policy. Each
/// attempt must explicitly provide its new generation and source anchor/clock basis.
/// Only transport/work ceilings may shrink; a retry is not a configuration rollout.
///
/// Reconnection is permitted after eligible transient transport failure, or after
/// actual TCP EOF AND the native receiver/capture drain. Source EOB instead stops
/// with SourceEnded after draining; it never loops back to PLAY. Authentication,
/// corruption, source discontinuity, expired work and authority denials fail closed.
/// All outputs remain caller-owned and still require separate custody/publication.
#[must_use]
pub struct SupervisedHevcRecording {
    schedule: Schedule,
    profile: Option<Profile>,
    active: Option<AutomaticLiveHevcRecording>,
    end: SourceEnd,
    tickets: TimingTickets,
}
impl fmt::Debug for SupervisedHevcRecording {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SupervisedHevcRecording")
            .field("status", &self.schedule.status)
            .field("resources", &self.schedule.resources.state())
            .field("end", &self.end)
            .finish_non_exhaustive()
    }
}
impl SupervisedHevcRecording {
    /// Validate the finite schedule without I/O. The first admitted native profile
    /// prices a checked worst-case aggregate; use new_with_budget for a tighter grant.
    pub fn new(
        binding: TcpBinding,
        policy: ReconnectPolicy,
        now: u64,
    ) -> Result<Self, ReconnectRefusal> {
        Ok(Self {
            schedule: Schedule::new(binding, policy, now)?,
            profile: None,
            active: None,
            end: SourceEnd::default(),
            tickets: TimingTickets::default(),
        })
    }

    /// Reserve all attempts against one explicit non-replenishing aggregate grant.
    pub fn new_with_budget(
        binding: TcpBinding,
        policy: ReconnectPolicy,
        budget: ReconnectBudget,
        now: u64,
    ) -> Result<Self, ReconnectRefusal> {
        let mut owner = Self::new(binding, policy, now)?;
        owner.schedule.resources =
            ReservationLedger::bounded(budget).map_err(ReconnectRefusal::Resources)?;
        Ok(owner)
    }

    /// Scheduling only; Active/Playing are not frame, coverage or custody receipts.
    pub fn status(&self) -> ReconnectStatus {
        self.schedule.status
    }

    /// Exact route and generation for the next independent authority grant.
    pub fn expected_binding(&self) -> &TcpBinding {
        &self.schedule.binding
    }

    /// Immutable reservations, not measured traffic, CPU time or retained storage.
    pub fn resource_budget(&self) -> ReconnectBudgetState {
        self.schedule.resources.state()
    }

    /// Current native protocol state, absent while no recording owner exists.
    pub fn state(&self) -> Option<ClientState> {
        self.active.as_ref().map(AutomaticLiveHevcRecording::state)
    }

    /// Read-only current-generation recording accounting, never a mutation bypass.
    pub fn collector(&self) -> Option<&HevcRecordingCollector> {
        self.active
            .as_ref()
            .map(AutomaticLiveHevcRecording::collector)
    }

    /// Current native observations; terminal totals transfer with original retirement.
    pub fn totals(&self) -> Option<TcpTotals> {
        self.active
            .as_ref()
            .and_then(AutomaticLiveHevcRecording::totals)
    }

    /// Correlate an independent timing computation with the exact held native picture.
    /// Copies remain valid across repeated timing polls and safe value corrections,
    /// but not after success, retirement, reconnect, or transfer to another supervisor.
    /// This is an in-memory request identity, not timing evidence or a capability.
    pub fn timing_ticket(&self) -> Option<HevcTimingTicket> {
        self.tickets.current()
    }

    /// Whether the native owner needs a fresh, short-lived credential/entropy borrow.
    pub fn needs_credentials(&self) -> bool {
        self.active
            .as_ref()
            .is_some_and(AutomaticLiveHevcRecording::needs_credentials)
    }

    /// Include native capture deadlines and backoff; no wait extends the original lease.
    pub fn next_wake_ns(&self) -> Option<u64> {
        match self.schedule.status {
            ReconnectStatus::Waiting { retry_at_ns, .. } => Some(retry_at_ns),
            ReconnectStatus::Active(_) => Some(
                self.active
                    .as_ref()
                    .and_then(AutomaticLiveHevcRecording::next_wake_ns)
                    .unwrap_or(self.schedule.policy.deadline_ns)
                    .min(self.schedule.policy.deadline_ns),
            ),
            ReconnectStatus::Retired(_) => Some(self.schedule.policy.deadline_ns),
            ReconnectStatus::Stopped(_) => None,
        }
    }

    /// Reserve one entire native allowance before opening a fresh connection.
    /// An early, stale, profile-changing or resource-refused call opens no socket
    /// and consumes no attempt ordinal. Ordinary scheduler work still consumes a step.
    pub fn connect(
        &mut self,
        live: LiveHevcConfig,
        recording: LiveHevcRecordingConfig,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<ReconnectAttempt, SupervisedHevcRecordingFailure> {
        self.admit(now, authority)?;
        if live.binding != self.schedule.binding
            || live.deadline_ns != self.schedule.policy.deadline_ns
            || recording.scope.generation != self.schedule.binding.key().generation
        {
            return Err(self.refusal(ReconnectRefusal::Scope));
        }
        self.schedule.ready(now).map_err(|e| self.refusal(e))?;
        let candidate = if let Some(profile) = &self.profile {
            if !profile
                .permits(&live, &recording)
                .map_err(|e| self.refusal(e))?
            {
                return Err(self.refusal(ReconnectRefusal::Scope));
            }
            None
        } else {
            Some(Profile::new(&live, &recording).map_err(|e| self.refusal(e))?)
        };
        let attempt = self
            .schedule
            .begin_native_connection(live.transport, live.max_steps, now)
            .map_err(|e| self.refusal(e))?;
        if let Some(profile) = candidate {
            self.profile = Some(profile);
        }
        match AutomaticLiveHevcRecording::connect(live, recording, now, authority) {
            Ok(recording) => {
                self.active = Some(recording);
                self.end = SourceEnd::default();
                Ok(attempt)
            }
            Err(failure) => {
                self.schedule.ended(retryable(&failure.reason));
                Err(SupervisedHevcRecordingFailure {
                    key: attempt.key,
                    reason: SupervisedHevcRecordingError::Connect(failure),
                    retirement: None,
                })
            }
        }
    }

    /// One original recording step. Socket EOF does not skip timing, windows,
    /// trailing originals or capture failure. Retain every returned output before
    /// continuing; a prepared window is never silently published by this wrapper.
    pub fn poll(
        &mut self,
        readiness: SocketReadiness,
        credentials: &DigestCredentials<'_>,
        cnonce: [u8; 16],
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<SupervisedHevcRecordingStep, SupervisedHevcRecordingFailure> {
        self.admit(now, authority)?;
        match self.schedule.status {
            ReconnectStatus::Waiting { key, retry_at_ns } => {
                return Ok(SupervisedHevcRecordingStep::Waiting { key, retry_at_ns });
            }
            ReconnectStatus::Retired(key) => return Ok(SupervisedHevcRecordingStep::Retired(key)),
            _ => {}
        }
        let key = self.schedule.binding.key();
        let Some(recording) = self.active.as_mut() else {
            return Err(self.refusal(ReconnectRefusal::Active));
        };
        let result = recording.poll(readiness, credentials, cnonce, now, authority);
        let output = self.settle(result)?;
        match &output {
            AutomaticHevcRecordingStep::ProtocolQueued {
                transport: Some(transport),
            } => {
                self.end.network_retired = true;
                self.end.peer_eof = transport.totals.peer_eof;
            }
            AutomaticHevcRecordingStep::Capture { event, .. } => match event.as_ref() {
                HevcCapturePoll::Receiver(event) => self.end.observe(event),
                HevcCapturePoll::TimingRequired(request) => {
                    if let Err(reason) = self.tickets.observe(key, *request) {
                        return Err(self.timing_failure(reason, true));
                    }
                }
                HevcCapturePoll::Ended { .. } => {
                    self.tickets.clear();
                    self.active = None;
                    if let Some(stop) = self.end.completion() {
                        self.schedule.stop(stop);
                    } else {
                        self.schedule.ended(true);
                    }
                }
                HevcCapturePoll::Stopped { .. } => {
                    self.tickets.clear();
                    self.active = None;
                    self.schedule.ended(false);
                }
                _ => {}
            },
            AutomaticHevcRecordingStep::Ended => {
                self.tickets.clear();
                self.active = None;
                self.schedule.ended(false);
            }
            _ => {}
        }
        Ok(SupervisedHevcRecordingStep::Recording { key, output })
    }

    /// Compatibility timing admission for a synchronously handled current picture.
    /// This original signature fences generation only; it cannot identify a delayed
    /// reply from an earlier picture within that generation. Use `supply_timing_for`
    /// with `timing_ticket()` when timing can complete asynchronously or be retried.
    /// Success consumes any current ticket; safe value refusals preserve it.
    pub fn supply_timing(
        &mut self,
        key: StreamKey,
        timing: HevcRecordingTiming,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<TimedHevcCapture, SupervisedHevcRecordingFailure> {
        self.admit_generation(key, now, authority)?;
        self.supply_held_timing(timing, now, authority)
    }

    /// Apply independently supplied timing only to this ticket's exact held picture.
    /// A generation alone cannot fence a delayed reply from an earlier picture in
    /// the same session. Stale/cross-owner tickets leave native work unchanged.
    /// Safe timing-value refusals retain the ticket and original residence deadline.
    /// EOB may carry the final picture; success still does not bypass capture draining.
    pub fn supply_timing_for(
        &mut self,
        ticket: &HevcTimingTicket,
        timing: HevcRecordingTiming,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<TimedHevcCapture, SupervisedHevcRecordingFailure> {
        // Check live revocation and deadlines before considering even a stale reply.
        self.admit(now, authority)?;
        if self.schedule.status != ReconnectStatus::Active(ticket.key()) {
            return Err(self.timing_failure(HevcTimingRefusal::StaleTicket, false));
        }
        if let Err(reason) = self.tickets.admit(ticket) {
            return Err(self.timing_failure(reason, false));
        }
        self.supply_held_timing(timing, now, authority)
    }

    // Both public paths have admitted the live supervisor exactly once. Only this
    // native call can consume a held picture or its timing ticket.
    fn supply_held_timing(
        &mut self,
        timing: HevcRecordingTiming,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<TimedHevcCapture, SupervisedHevcRecordingFailure> {
        let Some(recording) = self.active.as_mut() else {
            return Err(self.refusal(ReconnectRefusal::Active));
        };
        let result = recording.supply_timing(timing, now, authority);
        let timed = self.settle(result)?;
        self.tickets.clear();
        self.end.observe(&timed.event);
        Ok(timed)
    }

    /// Seal only an actually completed prefix in the requested generation.
    /// No EOF, media timing, publication or new connection is manufactured.
    pub fn seal(
        &mut self,
        key: StreamKey,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<HevcCollectionSeal, SupervisedHevcRecordingFailure> {
        self.admit_generation(key, now, authority)?;
        let Some(recording) = self.active.as_mut() else {
            return Err(self.refusal(ReconnectRefusal::Active));
        };
        let result = recording.seal(now, authority);
        self.settle(result)
    }

    /// Caller assertion that the previous terminal originals were retained or
    /// explicitly accounted for. This is NOT a publication receipt or resource
    /// refund. A fresh owner time starts backoff only after the capture drain ended.
    pub fn acknowledge_retirement(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<ReconnectStatus, SupervisedHevcRecordingFailure> {
        self.admit(now, authority)?;
        if !matches!(self.schedule.status, ReconnectStatus::Retired(_)) {
            return Err(self.refusal(ReconnectRefusal::NoRetirement));
        }
        self.schedule.finish(true, now);
        Ok(self.schedule.status)
    }

    /// Irreversible local stop, including while revoked or draining. Return every
    /// retained layer once, without network/storage I/O or refunding reservations.
    /// Cleanup preserves an earlier terminal cause rather than rewriting it Cancelled.
    pub fn cancel(&mut self) -> Option<(StreamKey, LiveHevcRecordingRetirement)> {
        self.tickets.clear();
        if !matches!(self.schedule.status, ReconnectStatus::Stopped(_)) {
            self.schedule.stop(ReconnectStop::Cancelled);
        }
        let key = self.schedule.binding.key();
        self.active
            .take()
            .and_then(|mut recording| recording.cancel())
            .map(|retirement| (key, retirement))
    }

    fn timing_failure(
        &mut self,
        reason: HevcTimingRefusal,
        terminal: bool,
    ) -> SupervisedHevcRecordingFailure {
        let retirement = if terminal {
            self.tickets.clear();
            self.schedule.stop(ReconnectStop::PermanentFailure);
            self.active
                .take()
                .and_then(|mut recording| recording.cancel())
                .map(Box::new)
        } else {
            None
        };
        SupervisedHevcRecordingFailure {
            key: self.schedule.binding.key(),
            reason: SupervisedHevcRecordingError::Timing(reason),
            retirement,
        }
    }

    fn refusal(&self, reason: ReconnectRefusal) -> SupervisedHevcRecordingFailure {
        SupervisedHevcRecordingFailure {
            key: self.schedule.binding.key(),
            reason: SupervisedHevcRecordingError::Supervisor(reason),
            retirement: None,
        }
    }

    fn admit(
        &mut self,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<(), SupervisedHevcRecordingFailure> {
        if let Err(reason) = self.schedule.admit(now, authority) {
            let mut failure = self.refusal(reason);
            if matches!(self.schedule.status, ReconnectStatus::Stopped(_)) {
                self.tickets.clear();
                failure.retirement = self
                    .active
                    .take()
                    .and_then(|mut recording| recording.cancel())
                    .map(Box::new);
            }
            return Err(failure);
        }
        Ok(())
    }

    fn admit_generation(
        &mut self,
        key: StreamKey,
        now: u64,
        authority: &dyn TcpAuthority,
    ) -> Result<(), SupervisedHevcRecordingFailure> {
        self.admit(now, authority)?;
        if self.schedule.status != ReconnectStatus::Active(key) {
            return Err(self.refusal(ReconnectRefusal::Scope));
        }
        Ok(())
    }

    fn settle<T>(
        &mut self,
        result: Result<T, LiveHevcRecordingFailure>,
    ) -> Result<T, SupervisedHevcRecordingFailure> {
        result.map_err(|failure| {
            if failure.retirement.is_some() {
                self.tickets.clear();
                self.active = None;
                self.schedule.ended(retryable(&failure.reason));
            }
            SupervisedHevcRecordingFailure {
                key: self.schedule.binding.key(),
                reason: SupervisedHevcRecordingError::Recording(failure.reason),
                retirement: failure.retirement,
            }
        })
    }
}

fn retryable(reason: &LiveHevcRecordingError) -> bool {
    matches!(reason, LiveHevcRecordingError::Network(LiveHevcError::Transport(error))
        if retryable_transport(error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtsp::tcp::{TcpDenial, TcpError, TcpOperation};
    use std::io::ErrorKind;

    #[test]
    fn socket_retirement_or_receiver_end_alone_cannot_authorize_retry() {
        let mut end = SourceEnd::default();
        assert_eq!(end.completion(), Some(ReconnectStop::PermanentFailure));
        end.network_retired = true;
        end.peer_eof = true;
        assert_eq!(end.completion(), Some(ReconnectStop::PermanentFailure));
        end.receiver_ended = true;
        assert_eq!(end.completion(), None);
        end.network_retired = false;
        assert_eq!(end.completion(), Some(ReconnectStop::PermanentFailure));
    }

    #[test]
    fn bitstream_end_is_terminal_even_when_tcp_eof_was_also_observed() {
        let mut end = SourceEnd {
            network_retired: true,
            peer_eof: false,
            receiver_ended: false,
            bitstream_ended: true,
        };
        assert_eq!(end.completion(), Some(ReconnectStop::SourceEnded));
        end.peer_eof = true;
        end.receiver_ended = true;
        assert_eq!(end.completion(), Some(ReconnectStop::SourceEnded));
    }

    #[test]
    fn hevc_reuses_the_same_narrow_transport_retry_classification() {
        let transport = |error| LiveHevcRecordingError::Network(LiveHevcError::Transport(error));
        assert!(retryable(&transport(TcpError::Io {
            operation: TcpOperation::Read,
            kind: ErrorKind::ConnectionReset,
        })));
        for error in [
            TcpError::Denied(TcpDenial::Revoked),
            TcpError::Denied(TcpDenial::Budget),
            TcpError::Deadline,
            TcpError::WorkBudget,
            TcpError::Io {
                operation: TcpOperation::Configure,
                kind: ErrorKind::TimedOut,
            },
        ] {
            assert!(!retryable(&transport(error)));
        }
        assert!(!retryable(&LiveHevcRecordingError::Network(
            LiveHevcError::Configuration
        )));
        assert!(!retryable(&LiveHevcRecordingError::Capture(
            crate::rtsp::hevc_recording_capture::CaptureError::Closed,
        )));
    }
}
