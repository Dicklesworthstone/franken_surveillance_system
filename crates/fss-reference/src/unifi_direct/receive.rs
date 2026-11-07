#![forbid(unsafe_code)]
//! Bounded WebSocket management observations under task-scoped network I/O.
//!
//! This owner does not authenticate the camera, adopt a device, prove a stream
//! active, or retain unknown event payloads. It can dispatch explicitly
//! authorized management messages and a journal-backed stream-setting effect. WebSocket
//! ping/close responses are network writes performed by Asupersync and are
//! metered by the wrapped stream. The caller remains responsible for TLS,
//! HTTP response dispatch, identity validation, and supervisory task lifetime.

use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
    net::websocket::{Message, ServerWebSocket, WsError},
    time::timeout_at,
};
use fss_runtime::effect::CommittedEffect;
use std::{fmt, time::Duration};

use super::{
    AudioCodec, Controller, Dispatch, MessageKind, Observation, Phase, Retirement, StreamStart,
    VideoChannel,
    controller_listener::AdmissionGate,
    intent::{self, Intent, Preconditions},
    management,
    metered::{MeteredClock, MeteredIo},
    upgrade::{self, PreparedUpgrade},
};

const MAX_WAIT: Duration = Duration::from_secs(30);

/// Payload-free classification of a WebSocket or underlying I/O failure.
/// No peer-provided text, frame bytes, lengths, or opcode values are retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportFailure {
    /// The underlying transport failed with this standard error kind.
    Io(std::io::ErrorKind),
    /// An unsupported frame opcode was received.
    InvalidOpcode,
    /// The peer violated a WebSocket protocol rule.
    ProtocolViolation,
    /// A frame used reserved bits without negotiated support.
    ReservedBits,
    /// A message exceeded its configured bound.
    PayloadTooLarge,
    /// A control frame exceeded its configured bound.
    ControlFrameTooLarge,
    /// A control frame was fragmented.
    FragmentedControlFrame,
    /// A client frame was not masked.
    UnmaskedClientFrame,
    /// A server frame was unexpectedly masked.
    MaskedServerFrame,
    /// A text frame was not valid UTF-8.
    InvalidUtf8,
    /// A close frame had an invalid payload.
    InvalidClosePayload,
    /// A bounded outbound buffer could not accept another frame.
    OutboundBufferFull,
}

impl From<WsError> for TransportFailure {
    fn from(error: WsError) -> Self {
        match error {
            WsError::Io(error) => Self::Io(error.kind()),
            WsError::InvalidOpcode(_) => Self::InvalidOpcode,
            WsError::ProtocolViolation(_) => Self::ProtocolViolation,
            WsError::ReservedBitsSet => Self::ReservedBits,
            WsError::PayloadTooLarge { .. } => Self::PayloadTooLarge,
            WsError::ControlFrameTooLarge(_) => Self::ControlFrameTooLarge,
            WsError::FragmentedControlFrame => Self::FragmentedControlFrame,
            WsError::UnmaskedClientFrame => Self::UnmaskedClientFrame,
            WsError::MaskedServerFrame => Self::MaskedServerFrame,
            WsError::InvalidUtf8 => Self::InvalidUtf8,
            WsError::InvalidClosePayload => Self::InvalidClosePayload,
            WsError::OutboundBufferFull { .. } => Self::OutboundBufferFull,
        }
    }
}

/// Why an observation session was retired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stop {
    /// The peer closed or EOF was observed.
    PeerClosed,
    /// Runtime cancellation was observed.
    Cancelled,
    /// A WebSocket or metered transport error occurred.
    Transport,
    /// A WebSocket or I/O error occurred with a payload-free classification.
    TransportDetail(TransportFailure),
    /// A control frame was surfaced unexpectedly by the WebSocket layer.
    UnexpectedFrame,
    /// A complete management message was invalid for the controller state.
    Protocol(super::Error),
    /// A management write may have reached the peer and must be reconciled.
    IndeterminateWrite,
    /// Current connection admission was revoked, including for buffered messages.
    AdmissionRevoked,
}

/// One bounded observation step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Step {
    /// A syntactically valid, unauthenticated controller observation.
    Observation(Observation),
    /// A source-preserving camera event transferred to the caller.
    CameraEvent(super::events::Frame),
    /// The caller-owned startup event inbox must be drained before more input.
    StartupEventBackpressure,
    /// The wait ended without a message; this does not prove absence.
    WaitElapsed,
    /// The socket was dropped and unresolved controller facts are returned.
    Retired {
        /// The terminal observation or refusal.
        reason: Stop,
        /// Pending protocol facts that still require reconciliation.
        controller: Retirement,
    },
}

/// Payload-free refusal before polling a live session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// HTTP upgrade was not proven locally written.
    Upgrade(upgrade::Error),
    /// The requested wait is zero or exceeds the finite limit.
    WaitLimit,
    /// The connection has already been retired.
    Retired,
    /// The controller refused message preparation or dispatch state.
    Controller(super::Error),
    /// Current owner policy denied this precise management message.
    Denied,
    /// No supported management message is prepared.
    NoPrepared,
    /// Bounded message allocation failed before writing.
    Allocation,
    /// Prepared stream intent or current preconditions differ.
    Intent(intent::Error),
    /// Prepared management intent or current preconditions differ.
    ManagementIntent(management::Error),
    /// The committed permit is for another request, effect, resource or fence.
    PermitMismatch,
    /// The permit did not come from an acknowledged configured journal store.
    JournalRequired,
    /// The permit has already been claimed for a dispatch attempt.
    PermitUsed,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi management receive refusal: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Current authority for one precise management message. A MAC claim is not
/// identity; implementations must bind their independently established peer,
/// network scope, principal and current permission to the message ID and kind.
/// An implementation must also enforce any registered effect and durable intent
/// required by the message. Hello can change controller association and time sync
/// can change a remote clock; this trait does not make either operation inert.
pub trait DispatchAuthority {
    /// Revalidate permission immediately before dispatch.
    fn permits(&self, claimed_mac: [u8; 6], id: u64, kind: MessageKind) -> bool;
}

/// Current policy and lease revalidation for a camera-setting dispatch.
/// The implementation must bind the independently authenticated peer and
/// revalidate current scoped authority, preconditions and the live lease.
pub trait StreamAuthority {
    /// Check this exact claimed peer, request and committed permit.
    fn permits(&self, claimed_mac: [u8; 6], intent: Intent, permit: &CommittedEffect) -> bool;

    /// Separately authorize quiescing this exact track. Existing authorities
    /// default to refusal even if they allow stream starts.
    fn permits_quiesce(
        &self,
        _claimed_mac: [u8; 6],
        _intent: Intent,
        _permit: &CommittedEffect,
    ) -> bool {
        false
    }
}

/// Current policy and lease revalidation for a management effect.
/// The implementation binds independently authenticated peer identity and
/// current scoped authorization to the exact intent and committed permit.
pub trait ManagementAuthority {
    /// Check this exact peer, request and committed permit.
    fn permits(
        &self,
        claimed_mac: [u8; 6],
        intent: management::Intent,
        permit: &CommittedEffect,
    ) -> bool;
}

/// Refusal before a management write was attempted, retaining its permit.
#[must_use]
#[derive(Debug)]
pub struct ManagementRefusal {
    /// Payload-free refusal reason.
    pub reason: Error,
    /// Original still-owned one-use permit.
    pub permit: CommittedEffect,
}

/// Result of one claimed management dispatch; neither variant proves peer state.
#[must_use]
#[derive(Debug)]
pub enum ManagementWrite {
    /// The full message was accepted locally.
    Written {
        /// Spent permit retained for observation and reconciliation.
        permit: CommittedEffect,
    },
    /// A write may have occurred; the connection has been fenced.
    Indeterminate {
        /// Spent permit retained for reconciliation.
        permit: CommittedEffect,
        /// Outstanding controller facts.
        controller: Retirement,
    },
}

/// Refusal before a stream write was attempted. The committed permit is
/// returned so its owner can cancel or reconcile the retained obligation.
#[must_use]
#[derive(Debug)]
pub struct StreamRefusal {
    /// Payload-free refusal reason.
    pub reason: Error,
    /// Original still-owned one-use permit.
    pub permit: CommittedEffect,
}

/// Result of one claimed stream-setting dispatch. The returned permit is
/// already spent and remains required for observation and reconciliation.
#[must_use]
#[derive(Debug)]
pub enum StreamWrite {
    /// The full message was accepted locally; the remote change is not verified.
    Written {
        /// Claimed permit, retained for remote observation and reconciliation.
        permit: CommittedEffect,
    },
    /// A write may have occurred; the connection was fenced.
    Indeterminate {
        /// Claimed permit, retained for remote reconciliation.
        permit: CommittedEffect,
        /// Unresolved controller state captured when the connection was fenced.
        controller: Retirement,
    },
}

/// Result of a management dispatch; local completion is not peer receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteStep {
    /// All frame bytes were accepted by the local transport.
    Written {
        /// Controller-local message identifier.
        id: u64,
        /// Management message accepted locally.
        kind: MessageKind,
    },
    /// The connection was retired; unresolved state remains with the owner.
    Retired {
        /// Why the connection was retired.
        reason: Stop,
        /// Pending controller facts requiring reconciliation.
        controller: Retirement,
    },
}

/// One task-owned connection and its untrusted controller observations.
pub struct Session<'scope, 'task, IO> {
    socket: Option<ServerWebSocket<MeteredIo<'scope, 'task, IO>>>,
    controller: Controller,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    claimed_mac: [u8; 6],
    in_flight: Option<u64>,
    admission: Option<AdmissionGate<'scope>>,
    capture_events: bool,
    startup_events: Option<&'scope super::events::StartupInbox>,
}
impl<IO> fmt::Debug for Session<'_, '_, IO> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("phase", &self.controller.phase())
            .field("retired", &self.socket.is_none())
            .finish_non_exhaustive()
    }
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> Session<'scope, 'task, IO> {
    pub(crate) fn matches_clock(&self, clock: &MeteredClock<'_, '_>) -> bool {
        self.clock.same_mapping(clock)
    }
    /// Transfer a metered stream after the outer owner has written the exact
    /// prepared HTTP response. A local write does not authenticate the peer.
    /// With TLS, meter the raw stream below TLS as well and construct both
    /// wrappers from the same task-bound `MeteredClock`. The outer wrapper
    /// conservatively charges application bytes in addition to that meter.
    pub fn from_upgrade(
        prepared: PreparedUpgrade,
        io: MeteredIo<'scope, 'task, IO>,
        outcome: Dispatch,
        controller: Controller,
    ) -> Result<Self, Error> {
        let cx = io.runtime_context();
        let clock = io.clock();
        let claimed_mac = prepared.claimed_mac();
        let socket = prepared.finish(io, outcome).map_err(Error::Upgrade)?;
        Ok(Self {
            socket: Some(socket),
            controller,
            cx,
            clock,
            claimed_mac,
            in_flight: None,
            admission: None,
            capture_events: false,
            startup_events: None,
        })
    }

    /// Bind the admission gate from this exact accepted connection before any
    /// controller observation. The caller must also wrap its plaintext stream
    /// with this same gate before the upgrade. A source claim is not identity.
    pub fn bind_admission(&mut self, gate: AdmissionGate<'scope>) -> Result<(), Error> {
        if self.admission.is_some()
            || self.socket.is_none()
            || self.in_flight.is_some()
            || self.controller.phase() != Phase::AwaitHello
            || gate.check().is_err()
        {
            return Err(Error::Denied);
        }
        self.admission = Some(gate);
        Ok(())
    }
    pub(crate) fn admission_current(&self) -> bool {
        self.admission
            .as_ref()
            .is_none_or(|gate| gate.check().is_ok())
    }

    /// Bind one empty caller-owned event inbox before receiving startup frames.
    /// The inbox remains caller-owned across session retirement or cancellation.
    pub fn bind_startup_events(
        &mut self,
        inbox: &'scope super::events::StartupInbox,
    ) -> Result<(), Error> {
        if self.startup_events.is_some()
            || self.capture_events
            || self.socket.is_none()
            || self.in_flight.is_some()
            || self.controller.phase() != Phase::AwaitHello
            || !self.admission_current()
            || !inbox.bind()
        {
            return Err(Error::Denied);
        }
        self.startup_events = Some(inbox);
        Ok(())
    }

    // Enabled only after startup has handed the session to its supervisor.
    pub(crate) fn enable_event_capture(&mut self) {
        self.capture_events = true;
    }

    fn observe_message(&mut self, bytes: asupersync::bytes::Bytes) -> Step {
        let observed = if self.capture_events || self.startup_events.is_some() {
            self.controller.observe_event_claims(&bytes)
        } else {
            self.controller.observe(&bytes)
        };
        match observed {
            Ok(Observation::CameraEvent {
                kind,
                message_id,
                response_expected,
            }) if self.capture_events => Step::CameraEvent(super::events::Frame::new(
                kind,
                message_id,
                response_expected,
                bytes,
            )),
            Ok(Observation::CameraEvent {
                kind,
                message_id,
                response_expected,
            }) => {
                if let Some(inbox) = self.startup_events {
                    inbox.push(super::events::Frame::new(
                        kind,
                        message_id,
                        response_expected,
                        bytes,
                    ));
                }
                Step::Observation(Observation::Other)
            }
            Ok(value) => Step::Observation(value),
            Err(error) => self.stop(Stop::Protocol(error)),
        }
    }

    /// Unauthenticated claimed MAC, never a verified device identity.
    pub fn claimed_mac(&self) -> [u8; 6] {
        self.claimed_mac
    }
    /// Current local parser state, not evidence of a camera's operational state.
    pub fn phase(&self) -> Phase {
        if self.in_flight.is_some() {
            Phase::Indeterminate
        } else {
            self.controller.phase()
        }
    }

    /// Payload-free counts of camera time-sync frames observed by this session.
    pub fn time_sync_counts(&self) -> super::TimeSyncCounts {
        self.controller.time_sync_counts()
    }

    pub(crate) fn startup_time_sync_limit(&self) -> usize {
        self.controller.startup_time_sync_limit()
    }

    /// Prepare a hello reply for a previously observed camera hello.
    pub fn prepare_hello(&mut self, timestamp: &str) -> Result<(u64, MessageKind), Error> {
        if self.in_flight.is_some() || self.socket.is_none() {
            return Err(Error::Retired);
        }
        if !self.admission_current() {
            return Err(Error::Denied);
        }
        let value = self
            .controller
            .prepare_hello(timestamp)
            .map_err(Error::Controller)?;
        Ok((value.id(), value.kind()))
    }
    /// Prepare parameter agreement after the caller-measured monotonic delay.
    pub fn prepare_agreement(
        &mut self,
        timestamp: &str,
        elapsed_ns: u64,
    ) -> Result<(u64, MessageKind), Error> {
        if self.in_flight.is_some() || self.socket.is_none() {
            return Err(Error::Retired);
        }
        if !self.admission_current() {
            return Err(Error::Denied);
        }
        let value = self
            .controller
            .prepare_agreement(timestamp, elapsed_ns)
            .map_err(Error::Controller)?;
        Ok((value.id(), value.kind()))
    }
    /// Prepare a time-sync reply from a caller-supplied wall clock observation.
    pub fn prepare_time_sync(
        &mut self,
        wall_ms: u64,
        timestamp: &str,
    ) -> Result<(u64, MessageKind), Error> {
        if self.in_flight.is_some() || self.socket.is_none() {
            return Err(Error::Retired);
        }
        if !self.admission_current() {
            return Err(Error::Denied);
        }
        let value = self
            .controller
            .prepare_time_sync(wall_ms, timestamp)
            .map_err(Error::Controller)?;
        Ok((value.id(), value.kind()))
    }

    /// Bind the currently prepared management message to exact preconditions.
    /// This creates no permission and performs no I/O.
    pub fn management_intent(
        &self,
        conditions: management::Preconditions,
    ) -> Result<management::Intent, Error> {
        if self.in_flight.is_some() || self.socket.is_none() {
            return Err(Error::Retired);
        }
        if !self.admission_current() {
            return Err(Error::Denied);
        }
        let message = self.controller.prepared().ok_or(Error::NoPrepared)?;
        management::Intent::new(message, conditions).map_err(Error::ManagementIntent)
    }

    /// Dispatch one exact association, agreement, or clock message with a
    /// journal-backed one-use permit. A local write is not a verified effect.
    pub async fn dispatch_management(
        &mut self,
        intent: management::Intent,
        current: management::Preconditions,
        mut permit: CommittedEffect,
        authority: &dyn ManagementAuthority,
        wait: Duration,
    ) -> Result<ManagementWrite, ManagementRefusal> {
        macro_rules! refuse {
            ($reason:expr) => {
                return Err(ManagementRefusal {
                    reason: $reason,
                    permit,
                });
            };
        }
        if wait.is_zero() || wait > MAX_WAIT {
            refuse!(Error::WaitLimit);
        }
        if self.socket.is_none() || self.in_flight.is_some() {
            refuse!(Error::Retired);
        }
        if !self.admission_current() {
            refuse!(Error::Denied);
        }
        if !permit.journal_backed() {
            refuse!(Error::JournalRequired);
        }
        if permit.prepared().effect_class() != management::EFFECT_CLASS
            || permit.prepared().request_digest() != intent.request_digest()
            || permit.prepared().precondition_digest() != intent.precondition_digest()
            || permit.fence() != intent.fence()
            || permit.resource() != intent.resource()
        {
            refuse!(Error::PermitMismatch);
        }
        if let Err(error) = intent.check_preconditions(current) {
            refuse!(Error::ManagementIntent(error));
        }
        let Some(message) = self.controller.prepared() else {
            refuse!(Error::NoPrepared);
        };
        if let Err(error) = intent.check_message(message) {
            refuse!(Error::ManagementIntent(error));
        }
        if !authority.permits(self.claimed_mac, intent, &permit) {
            refuse!(Error::Denied);
        }
        if self.cx.checkpoint().is_err() {
            refuse!(Error::Retired);
        }
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(message.bytes().len()).is_err() {
            refuse!(Error::Allocation);
        }
        bytes.extend_from_slice(message.bytes());
        if !permit.try_claim_dispatch() {
            refuse!(Error::PermitUsed);
        }
        let Some(socket) = self.socket.as_mut() else {
            refuse!(Error::Retired);
        };
        self.in_flight = Some(intent.message_id());
        let outcome = timeout_at(
            self.cx.now() + wait,
            socket.send(self.cx, Message::binary(bytes)),
        )
        .await;
        if matches!(outcome, Ok(Ok(())))
            && self
                .controller
                .finish_dispatch(intent.message_id(), Dispatch::Written)
                .is_ok()
        {
            self.in_flight = None;
            return Ok(ManagementWrite::Written { permit });
        }
        Ok(ManagementWrite::Indeterminate {
            permit,
            controller: self.fence_interrupted(),
        })
    }
    /// Prepare a stream-setting request and its exact inert precondition binding.
    /// This does not change camera settings or confer authority to dispatch.
    pub fn prepare_stream_start(
        &mut self,
        request: &StreamStart,
        timestamp: &str,
        conditions: Preconditions,
    ) -> Result<Intent, Error> {
        if self.in_flight.is_some() || self.socket.is_none() {
            return Err(Error::Retired);
        }
        if !self.admission_current() {
            return Err(Error::Denied);
        }
        conditions.validate().map_err(Error::Intent)?;
        let message = self
            .controller
            .prepare_stream_start(request, timestamp)
            .map_err(Error::Controller)?;
        Intent::new(message, conditions).map_err(Error::Intent)
    }

    /// Prepare a one-track discard request; dispatch needs separate authority.
    /// The caller must retain and reconcile its permit. This is not restoration.
    pub fn prepare_stream_quiesce(
        &mut self,
        channel: VideoChannel,
        audio: AudioCodec,
        timestamp: &str,
        conditions: Preconditions,
    ) -> Result<Intent, Error> {
        if self.in_flight.is_some() || self.socket.is_none() {
            return Err(Error::Retired);
        }
        if !self.admission_current() {
            return Err(Error::Denied);
        }
        conditions.validate().map_err(Error::Intent)?;
        let message = self
            .controller
            .prepare_stream_quiesce(channel, audio, timestamp)
            .map_err(Error::Controller)?;
        Intent::new(message, conditions).map_err(Error::Intent)
    }

    /// Abandon a stream request that this owner has not sent. Any separately
    /// committed permit remains the caller's reconciliation obligation.
    pub fn abandon_prepared_stream(
        &mut self,
        intent: Intent,
    ) -> Result<super::AbandonedStream, Error> {
        if self.in_flight.is_some() || self.socket.is_none() {
            return Err(Error::Retired);
        }
        if !self.admission_current() {
            return Err(Error::Denied);
        }
        let message = self.controller.prepared().ok_or(Error::NoPrepared)?;
        intent.check_message(message).map_err(Error::Intent)?;
        self.controller
            .abandon_prepared_stream()
            .map_err(Error::Controller)
    }

    /// Dispatch one exact stream-setting effect under a journal-backed, one-use
    /// permit and current caller-supplied peer, precondition and lease checks.
    /// Locally written bytes are not proof of a successful remote change.
    pub async fn dispatch_stream(
        &mut self,
        intent: Intent,
        current: Preconditions,
        mut permit: CommittedEffect,
        authority: &dyn StreamAuthority,
        wait: Duration,
    ) -> Result<StreamWrite, StreamRefusal> {
        macro_rules! refuse {
            ($reason:expr) => {
                return Err(StreamRefusal {
                    reason: $reason,
                    permit,
                });
            };
        }
        if wait.is_zero() || wait > MAX_WAIT {
            refuse!(Error::WaitLimit);
        }
        if self.socket.is_none() || self.in_flight.is_some() {
            refuse!(Error::Retired);
        }
        if !self.admission_current() {
            refuse!(Error::Denied);
        }
        if !permit.journal_backed() {
            refuse!(Error::JournalRequired);
        }
        if permit.prepared().effect_class() != intent::EFFECT_CLASS
            || permit.prepared().request_digest() != intent.request_digest()
            || permit.prepared().precondition_digest() != intent.precondition_digest()
            || permit.fence() != intent.fence()
            || permit.resource() != intent.resource()
        {
            refuse!(Error::PermitMismatch);
        }
        if let Err(error) = intent.check_preconditions(current) {
            refuse!(Error::Intent(error));
        }
        let Some(message) = self.controller.prepared() else {
            refuse!(Error::NoPrepared);
        };
        if let Err(error) = intent.check_message(message) {
            refuse!(Error::Intent(error));
        }
        if !authority.permits(self.claimed_mac, intent, &permit)
            || (matches!(intent.kind(), MessageKind::QuiesceStream(_))
                && !authority.permits_quiesce(self.claimed_mac, intent, &permit))
        {
            refuse!(Error::Denied);
        }
        if self.cx.checkpoint().is_err() {
            refuse!(Error::Retired);
        }
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(message.bytes().len()).is_err() {
            refuse!(Error::Allocation);
        }
        bytes.extend_from_slice(message.bytes());
        if !permit.try_claim_dispatch() {
            refuse!(Error::PermitUsed);
        }
        let Some(socket) = self.socket.as_mut() else {
            refuse!(Error::Retired);
        };
        self.in_flight = Some(intent.message_id());
        let outcome = timeout_at(
            self.cx.now() + wait,
            socket.send(self.cx, Message::binary(bytes)),
        )
        .await;
        if matches!(outcome, Ok(Ok(())))
            && self
                .controller
                .finish_dispatch(intent.message_id(), Dispatch::Written)
                .is_ok()
        {
            self.in_flight = None;
            return Ok(StreamWrite::Written { permit });
        }
        Ok(StreamWrite::Indeterminate {
            permit,
            controller: self.fence_interrupted(),
        })
    }

    /// Refuse the legacy permitless management path. Callers must use
    /// [`Self::dispatch_management`] with a journal-backed committed effect.
    /// This method is retained only to fail closed for existing callers.
    pub async fn dispatch(
        &mut self,
        _authority: &dyn DispatchAuthority,
        _wait: Duration,
    ) -> Result<WriteStep, Error> {
        Err(Error::JournalRequired)
    }

    fn fence_interrupted(&mut self) -> Retirement {
        if let Some(id) = self.in_flight.take() {
            let _ = self.controller.finish_dispatch(id, Dispatch::Indeterminate);
        }
        drop(self.socket.take());
        self.controller.close()
    }

    fn stop(&mut self, reason: Stop) -> Step {
        drop(self.socket.take());
        Step::Retired {
            reason,
            controller: self.controller.close(),
        }
    }

    /// Observe at most one management message, or return after a finite wait.
    /// A dropped pending receive follows Asupersync's documented cancel-safe
    /// receive contract. Enabled event capture transfers exact source bytes;
    /// callers must enforce privacy and retention on those bytes.
    pub async fn next(&mut self, wait: Duration) -> Result<Step, Error> {
        if wait.is_zero() || wait > MAX_WAIT {
            return Err(Error::WaitLimit);
        }
        if self.socket.is_none() {
            return Err(Error::Retired);
        }
        if self.in_flight.is_some() {
            return Ok(Step::Retired {
                reason: Stop::IndeterminateWrite,
                controller: self.fence_interrupted(),
            });
        }
        if self.cx.checkpoint().is_err() {
            return Ok(self.stop(Stop::Cancelled));
        }
        if !self.admission_current() {
            return Ok(self.stop(Stop::AdmissionRevoked));
        }
        if let Some(inbox) = self.startup_events {
            if self.capture_events {
                if let Some(frame) = inbox.take() {
                    return Ok(Step::CameraEvent(frame));
                }
            } else if !inbox.can_receive() {
                return Ok(Step::StartupEventBackpressure);
            }
        }
        let Some(socket) = self.socket.as_mut() else {
            return Err(Error::Retired);
        };
        let next = timeout_at(self.cx.now() + wait, socket.recv(self.cx)).await;
        if !self.admission_current() {
            return Ok(self.stop(Stop::AdmissionRevoked));
        }
        match next {
            Err(_) if self.cx.is_cancelled() => Ok(self.stop(Stop::Cancelled)),
            Err(_) => Ok(Step::WaitElapsed),
            Ok(Err(_)) if self.cx.is_cancelled() => Ok(self.stop(Stop::Cancelled)),
            Ok(Err(error)) => Ok(self.stop(Stop::TransportDetail(error.into()))),
            Ok(Ok(None | Some(Message::Close(_)))) => Ok(self.stop(Stop::PeerClosed)),
            Ok(Ok(Some(Message::Binary(bytes)))) => Ok(self.observe_message(bytes)),
            Ok(Ok(Some(Message::Text(text)))) => Ok(self.observe_message(text.into())),
            Ok(Ok(Some(Message::Ping(_) | Message::Pong(_)))) => {
                Ok(self.stop(Stop::UnexpectedFrame))
            }
        }
    }

    /// Close the local socket and return outstanding controller facts.
    pub fn retire(mut self) -> Retirement {
        self.fence_interrupted()
    }
}

impl<IO> Drop for Session<'_, '_, IO> {
    fn drop(&mut self) {
        if let Some(inbox) = self.startup_events.take() {
            inbox.unbind();
        }
    }
}
