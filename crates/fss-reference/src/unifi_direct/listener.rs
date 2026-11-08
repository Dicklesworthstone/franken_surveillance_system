#![forbid(unsafe_code)]
//! One task-bound, policy-scoped TCP listener for a UniFi media stream.
//!
//! IP admission is not cryptographic camera authentication. The caller must
//! bind policy to independently established identity, controller session and
//! stream generation. This owner creates no task, reconnect loop or storage.

use super::{
    ingress::DirectIngress, metered::MeteredClock, pipeline::Pipeline, recording::Recorder,
};
use asupersync::{Cx, net::TcpListener, time::timeout_at};
use fss_core::{BudgetVector, RuntimeGrant};
use fss_packet::extended_flv::stream::Framer;
use fss_runtime::{
    execution::TaskCx,
    tcp_ingress::{MAX_CHUNK_BYTES, TcpIngress},
};
use std::{
    fmt,
    future::{Future, poll_fn},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    pin::pin,
    task::Poll,
    time::Duration,
};

const MAX_WAIT: Duration = Duration::from_secs(30);
const MAX_RESOURCE: usize = 1024;
const MAX_ACCEPT_OBSERVATIONS: usize = 128;

/// Current bounded, nonblocking authorization for this listener and peer.
/// The implementation must bind these addresses to the owner's independently
/// established camera, current session, permitted network and stream lease.
pub trait Admission {
    /// Permit the requested address and, after bind, its actual address.
    fn listener(&self, requested: SocketAddrV4, bound: Option<SocketAddrV4>) -> bool;
    /// Permit a particular incoming peer for the actual bound listener.
    fn peer(&self, bound: SocketAddrV4, source: SocketAddrV4) -> bool;
}

/// Payload-free failure; a rejected connection is closed without reading it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid scoped address, resource, bounds, clock mapping or wait.
    Configuration,
    /// Task, capability, deadline or cancellation check refused the operation.
    Authority,
    /// Current listener or peer admission refused the operation.
    Denied,
    /// Bind or accept did not complete within the finite wait.
    Deadline,
    /// Listener setup or accept failed.
    Io(std::io::ErrorKind),
    /// The accepted source owner could not be created or task-bound.
    Source,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi stream listener refused: {self:?}")
    }
}
impl std::error::Error for Error {}

fn valid_ip(ip: Ipv4Addr) -> bool {
    (ip.is_private() || ip.is_loopback() || ip.is_link_local())
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && ip != Ipv4Addr::BROADCAST
}
fn valid_wait(wait: Duration) -> bool {
    !wait.is_zero() && wait <= MAX_WAIT
}

/// A single bound listener, held inside its owning task.
pub struct Listener<'scope, 'task, 'policy> {
    listener: TcpListener,
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    policy: &'policy dyn Admission,
    requested: SocketAddrV4,
    bound: SocketAddrV4,
    resource: String,
}
impl fmt::Debug for Listener<'_, '_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Listener").finish_non_exhaustive()
    }
}

impl<'scope, 'task, 'policy> Listener<'scope, 'task, 'policy> {
    fn check(
        task: &TaskCx<'task>,
        cx: &Cx,
        clock: MeteredClock<'scope, 'task>,
        resource: &str,
    ) -> Result<(), Error> {
        if !clock.matches(task, cx) {
            return Err(Error::Configuration);
        }
        let now = clock.now().map_err(|_| Error::Authority)?;
        task.checkpoint_for(RuntimeGrant::AdapterNet, resource, now, &BudgetVector::ZERO)
            .map_err(|_| Error::Authority)?;
        task.checkpoint_for(RuntimeGrant::ReadMedia, resource, now, &BudgetVector::ZERO)
            .map_err(|_| Error::Authority)
    }

    /// Bind one explicitly authorized interface and port. Port zero requests
    /// an OS-selected port, which is rechecked by policy before it is returned.
    pub async fn bind(
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        policy: &'policy dyn Admission,
        requested: SocketAddrV4,
        resource: &str,
        wait: Duration,
    ) -> Result<Self, Error> {
        if !valid_ip(*requested.ip())
            || resource.is_empty()
            || resource.len() > MAX_RESOURCE
            || !valid_wait(wait)
        {
            return Err(Error::Configuration);
        }
        Self::check(task, cx, clock, resource)?;
        if !policy.listener(requested, None) {
            return Err(Error::Denied);
        }
        let listener = timeout_at(
            cx.now() + wait,
            TcpListener::bind(SocketAddr::V4(requested)),
        )
        .await
        .map_err(|_| Error::Deadline)?
        .map_err(|e| Error::Io(e.kind()))?;
        Self::check(task, cx, clock, resource)?;
        let bound = match listener.local_addr().map_err(|e| Error::Io(e.kind()))? {
            SocketAddr::V4(addr) => addr,
            _ => return Err(Error::Configuration),
        };
        if !valid_ip(*bound.ip()) || bound.port() == 0 || !policy.listener(requested, Some(bound)) {
            return Err(Error::Denied);
        }
        Ok(Self {
            listener,
            task,
            cx,
            clock,
            policy,
            requested,
            bound,
            resource: resource.to_owned(),
        })
    }

    /// Actual bound address, for the stream request. It is not proof that a
    /// camera can route to the listener or that the peer will authenticate.
    pub fn local_addr(&self) -> SocketAddrV4 {
        self.bound
    }

    /// Accept one connection and build a task-bound media pipeline. The policy,
    /// task capabilities and clock are rechecked on every accept poll and once
    /// after acceptance. The listener is consumed on every outcome.
    pub async fn accept(
        self,
        framer: Framer,
        recorder: Recorder,
        chunk_bytes: usize,
        max_bytes: u64,
        wait: Duration,
    ) -> Result<Pipeline, Error> {
        if !(1..=MAX_CHUNK_BYTES).contains(&chunk_bytes) || max_bytes == 0 || !valid_wait(wait) {
            return Err(Error::Configuration);
        }
        let accept = poll_fn(|context| {
            if let Err(error) = Self::check(self.task, self.cx, self.clock, &self.resource) {
                return Poll::Ready(Err(error));
            }
            if !self.policy.listener(self.requested, Some(self.bound)) {
                return Poll::Ready(Err(Error::Denied));
            }
            match self.listener.poll_accept(context) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(connection)) => Poll::Ready(Ok(connection)),
                Poll::Ready(Err(error)) => Poll::Ready(Err(Error::Io(error.kind()))),
            }
        });
        let (socket, source) = timeout_at(self.cx.now() + wait, accept)
            .await
            .map_err(|_| Error::Deadline)??;
        Self::check(self.task, self.cx, self.clock, &self.resource)?;
        let source = match source {
            SocketAddr::V4(addr) => addr,
            _ => return Err(Error::Denied),
        };
        if !valid_ip(*source.ip())
            || !self.policy.listener(self.requested, Some(self.bound))
            || !self.policy.peer(self.bound, source)
        {
            return Err(Error::Denied);
        }
        let mut tcp = TcpIngress::new(socket, &self.resource, chunk_bytes, max_bytes)
            .map_err(|_| Error::Source)?;
        tcp.bind_task(self.task).map_err(|_| Error::Source)?;
        Ok(Pipeline::new(DirectIngress::new(tcp, framer), recorder))
    }
}

/// Inputs for one controller-to-media startup. The caller supplies distinct
/// effect identities, current preconditions, an authorized stream name, and
/// current policy for both the controller and the media listener.
pub struct Start<'a> {
    /// Explicit local media interface and desired port; zero selects a port.
    pub bind: SocketAddrV4,
    /// Resource scoped by the task's network and media grants.
    pub resource: &'a str,
    /// Current listener and peer admission policy.
    pub admission: &'a dyn Admission,
    /// Requested camera track.
    pub channel: super::VideoChannel,
    /// Requested video codec.
    pub video: super::VideoCodec,
    /// Requested audio mode.
    pub audio: super::AudioCodec,
    /// Caller-supplied 16-character lowercase hexadecimal stream name.
    pub stream_name: &'a str,
    /// Distinct operation identity for the hello reply.
    pub hello: &'a fss_core::OperationId,
    /// Distinct operation identity for parameter agreement.
    pub agreement: &'a fss_core::OperationId,
    /// Distinct operation identity for the stream setting.
    pub stream: &'a fss_core::OperationId,
    /// Distinct operation identities reserved for camera time-sync requests.
    pub time_sync: &'a [fss_core::OperationId],
    /// Current management preconditions, independently established by caller.
    pub management: super::management::Preconditions,
    /// Current stream preconditions, independently established by caller.
    pub stream_conditions: super::intent::Preconditions,
    /// Maximum bytes admitted by one source read.
    pub chunk_bytes: usize,
    /// Maximum source bytes for this connection.
    pub max_bytes: u64,
    /// Finite bind timeout.
    pub bind_wait: Duration,
    /// Finite total controller conversation timeout.
    pub conversation_wait: Duration,
    /// Finite media accept timeout following the conversation.
    pub accept_wait: Duration,
}

/// Startup failure. A failed conversation may leave journaled effects open;
/// the caller must retire the controller session and reconcile those effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartError {
    /// Listener binding, authorization or peer acceptance failed.
    Listener(Error),
    /// The bound destination or stream parameters were invalid.
    Request,
    /// The controller conversation stopped or remained indeterminate.
    Conversation(super::conversation::Error),
}
impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi stream startup stopped: {self:?}")
    }
}
impl std::error::Error for StartError {}

/// One accepted source and its untrusted correlated settings reply.
#[must_use]
pub struct Started {
    /// Camera-reported settings status, not proof of a working stream.
    pub reply: super::conversation::Reply,
    /// Accepted task-bound pipeline; no media has yet been read or retained.
    pub pipeline: Pipeline,
}

/// A media connection accepted after a local stream write. Any settings reply
/// observed while waiting is returned separately as an untrusted observation.
#[must_use]
pub struct StartedBeforeReply {
    /// Local dispatch observation; it does not establish remote acceptance.
    pub dispatched: super::conversation::Dispatched,
    /// Number of clock requests answered while waiting for the media connection.
    pub time_syncs_during_accept: usize,
    /// Bounded management observations received before the media connection.
    pub observations_during_accept: Vec<super::Observation>,
    /// Accepted task-bound pipeline; no media has yet been read or retained.
    pub pipeline: Pipeline,
}

/// Caller-owned, bounded observations from a media-before-reply startup.
///
/// The owner retains this value if the startup future fails or is dropped.
/// It does not replace the effect journal or establish remote state. A missing
/// dispatch observation also does not prove that no effect was attempted.
#[derive(Debug, Default)]
pub struct StartTrace {
    attempted: bool,
    dispatched: Option<super::conversation::Dispatched>,
    clock_requests: usize,
    clock_replies_written: usize,
    observations: Vec<super::Observation>,
    protocol: super::conversation::StartupProtocolTrace,
}

impl StartTrace {
    /// Whether the caller began polling an attempt with this trace.
    pub fn attempted(&self) -> bool {
        self.attempted
    }

    /// Locally completed stream dispatch, if its completion was observed.
    pub fn dispatched(&self) -> Option<super::conversation::Dispatched> {
        self.dispatched
    }

    /// Clock requests observed after stream dispatch, including an unfinished reply.
    pub fn clock_requests(&self) -> usize {
        self.clock_requests
    }

    /// Clock replies locally written; a write is not proof of peer receipt.
    pub fn clock_replies_written(&self) -> usize {
        self.clock_replies_written
    }

    /// Other untrusted management observations made while accepting media.
    pub fn observations(&self) -> &[super::Observation] {
        &self.observations
    }

    /// Startup management and stream facts retained for reconciliation.
    pub fn protocol(&self) -> &super::conversation::StartupProtocolTrace {
        &self.protocol
    }

    /// Transfer permits and local outcomes from the caller-owned trace.
    pub fn protocol_mut(&mut self) -> &mut super::conversation::StartupProtocolTrace {
        &mut self.protocol
    }

    fn is_empty(&self) -> bool {
        !self.attempted
            && self.dispatched.is_none()
            && self.clock_requests == 0
            && self.clock_replies_written == 0
            && self.observations.is_empty()
            && !self.protocol.attempted()
    }
}

enum StartProgress {
    Confirmed(super::conversation::Reply),
    Dispatched {
        dispatched: super::conversation::Dispatched,
        time_syncs_during_accept: usize,
        observations_during_accept: Vec<super::Observation>,
    },
}

struct ScopedStreamAuthority<'a> {
    inner: &'a dyn super::receive::StreamAuthority,
    policy: &'a dyn Admission,
    requested: SocketAddrV4,
    bound: SocketAddrV4,
}
impl super::receive::StreamAuthority for ScopedStreamAuthority<'_> {
    fn permits(
        &self,
        claimed_mac: [u8; 6],
        intent: super::intent::Intent,
        permit: &fss_runtime::effect::CommittedEffect,
    ) -> bool {
        self.policy.listener(self.requested, Some(self.bound))
            && self.inner.permits(claimed_mac, intent, permit)
    }
}

/// Bind a listener, request its exact address through the owned controller,
/// and accept one policy-admitted media connection. This does not authenticate
/// a peer, verify video, publish recordings, reconnect, or settle effects.
/// The listener policy and caller's stream authority are checked together at
/// dispatch. The session remains caller-owned.
pub async fn start<IO: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin>(
    owner: &mut super::conversation::Owner<'_, '_, '_>,
    session: &mut super::receive::Session<'_, '_, IO>,
    cfg: &Start<'_>,
    framer: Framer,
    recorder: Recorder,
) -> Result<Started, StartError> {
    let mut trace = StartTrace::default();
    start_tracked(owner, session, cfg, framer, recorder, &mut trace).await
}

/// Start while retaining protocol outcomes in the caller's trace, including
/// when the future fails or is dropped before the media connection is accepted.
pub async fn start_tracked<IO: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin>(
    owner: &mut super::conversation::Owner<'_, '_, '_>,
    session: &mut super::receive::Session<'_, '_, IO>,
    cfg: &Start<'_>,
    framer: Framer,
    recorder: Recorder,
    trace: &mut StartTrace,
) -> Result<Started, StartError> {
    if !trace.is_empty() {
        return Err(StartError::Listener(Error::Configuration));
    }
    trace.attempted = true;
    let (progress, pipeline) = start_inner(
        owner, session, cfg, framer, recorder, true, trace, None, None,
    )
    .await?;
    match progress {
        StartProgress::Confirmed(reply) => Ok(Started { reply, pipeline }),
        StartProgress::Dispatched { .. } => Err(StartError::Conversation(
            super::conversation::Error::Configuration,
        )),
    }
}

/// Accept media after the local stream request write without waiting for a
/// settings reply. The caller must supervise the same session for that reply,
/// clock requests and admission changes, and reconcile the committed effects.
/// Observations accumulated during accept are returned only on successful
/// acceptance; a failed or cancelled accept can omit them and requires independent
/// reconciliation of the effects.
pub async fn start_before_reply<
    IO: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin,
>(
    owner: &mut super::conversation::Owner<'_, '_, '_>,
    session: &mut super::receive::Session<'_, '_, IO>,
    cfg: &Start<'_>,
    framer: Framer,
    recorder: Recorder,
) -> Result<StartedBeforeReply, StartError> {
    let mut trace = StartTrace::default();
    start_before_reply_tracked(owner, session, cfg, framer, recorder, &mut trace).await
}

/// Start as [`start_before_reply`] while retaining observations in `trace` on
/// ordinary failure or cancellation. Supply a fresh trace for each attempt.
/// An interrupted write remains subject to independent journal reconciliation.
pub async fn start_before_reply_tracked<
    IO: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin,
>(
    owner: &mut super::conversation::Owner<'_, '_, '_>,
    session: &mut super::receive::Session<'_, '_, IO>,
    cfg: &Start<'_>,
    framer: Framer,
    recorder: Recorder,
    trace: &mut StartTrace,
) -> Result<StartedBeforeReply, StartError> {
    if !trace.is_empty() {
        return Err(StartError::Listener(Error::Configuration));
    }
    trace.attempted = true;
    let (progress, pipeline) = start_inner(
        owner, session, cfg, framer, recorder, false, trace, None, None,
    )
    .await?;
    match progress {
        StartProgress::Dispatched {
            dispatched,
            time_syncs_during_accept,
            observations_during_accept,
        } => Ok(StartedBeforeReply {
            dispatched,
            time_syncs_during_accept,
            observations_during_accept,
            pipeline,
        }),
        StartProgress::Confirmed(_) => Err(StartError::Conversation(
            super::conversation::Error::Configuration,
        )),
    }
}

/// Start the media listener while also requesting an explicitly authorized
/// baseline motion setting. Both traces remain caller-owned on cancellation.
pub async fn start_before_reply_with_motion_tracked<
    IO: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin,
>(
    owner: &mut super::conversation::Owner<'_, '_, '_>,
    session: &mut super::receive::Session<'_, '_, IO>,
    cfg: &Start<'_>,
    framer: Framer,
    recorder: Recorder,
    trace: &mut StartTrace,
    motion: &super::conversation::StartupMotion<'_>,
    motion_trace: &mut super::conversation::StartupMotionTrace,
) -> Result<StartedBeforeReply, StartError> {
    if !trace.is_empty() || motion_trace.attempted() {
        return Err(StartError::Listener(Error::Configuration));
    }
    trace.attempted = true;
    let (progress, pipeline) = start_inner(
        owner,
        session,
        cfg,
        framer,
        recorder,
        false,
        trace,
        Some((motion, motion_trace)),
        None,
    )
    .await?;
    match progress {
        StartProgress::Dispatched {
            dispatched,
            time_syncs_during_accept,
            observations_during_accept,
        } => Ok(StartedBeforeReply {
            dispatched,
            time_syncs_during_accept,
            observations_during_accept,
            pipeline,
        }),
        StartProgress::Confirmed(_) => Err(StartError::Conversation(
            super::conversation::Error::Configuration,
        )),
    }
}

/// Start with bounded event replies, optionally alongside a motion setting.
/// A caller-owned inbox must already be bound, and both traces survive failure.
pub async fn start_before_reply_with_events_tracked<
    IO: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin,
>(
    owner: &mut super::conversation::Owner<'_, '_, '_>,
    session: &mut super::receive::Session<'_, '_, IO>,
    cfg: &Start<'_>,
    framer: Framer,
    recorder: Recorder,
    trace: &mut StartTrace,
    motion: Option<(
        &super::conversation::StartupMotion<'_>,
        &mut super::conversation::StartupMotionTrace,
    )>,
    events: &super::conversation::StartupEventReplies<'_>,
    event_trace: &mut super::conversation::StartupEventTrace,
) -> Result<StartedBeforeReply, StartError> {
    if !trace.is_empty()
        || event_trace.attempted()
        || motion.as_ref().is_some_and(|(_, t)| t.attempted())
    {
        return Err(StartError::Listener(Error::Configuration));
    }
    trace.attempted = true;
    let (progress, pipeline) = start_inner(
        owner,
        session,
        cfg,
        framer,
        recorder,
        false,
        trace,
        motion,
        Some((events, event_trace)),
    )
    .await?;
    match progress {
        StartProgress::Dispatched {
            dispatched,
            time_syncs_during_accept,
            observations_during_accept,
        } => Ok(StartedBeforeReply {
            dispatched,
            time_syncs_during_accept,
            observations_during_accept,
            pipeline,
        }),
        StartProgress::Confirmed(_) => Err(StartError::Conversation(
            super::conversation::Error::Configuration,
        )),
    }
}

async fn start_inner<IO: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin>(
    owner: &mut super::conversation::Owner<'_, '_, '_>,
    session: &mut super::receive::Session<'_, '_, IO>,
    cfg: &Start<'_>,
    framer: Framer,
    recorder: Recorder,
    wait_for_reply: bool,
    trace: &mut StartTrace,
    startup_motion: Option<(
        &super::conversation::StartupMotion<'_>,
        &mut super::conversation::StartupMotionTrace,
    )>,
    mut event_replies: Option<(
        &super::conversation::StartupEventReplies<'_>,
        &mut super::conversation::StartupEventTrace,
    )>,
) -> Result<(StartProgress, Pipeline), StartError> {
    if !valid_wait(cfg.bind_wait)
        || !valid_wait(cfg.conversation_wait)
        || !valid_wait(cfg.accept_wait)
        || !(1..=MAX_CHUNK_BYTES).contains(&cfg.chunk_bytes)
        || cfg.max_bytes == 0
    {
        return Err(StartError::Listener(Error::Configuration));
    }
    cfg.stream_conditions
        .validate()
        .map_err(|_| StartError::Request)?;
    super::StreamStart::new(
        cfg.channel,
        SocketAddrV4::new(*cfg.bind.ip(), 1),
        cfg.video,
        cfg.audio,
        cfg.stream_name,
    )
    .map_err(|_| StartError::Request)?;
    let listener = Listener::bind(
        owner.task,
        owner.cx,
        owner.clock,
        cfg.admission,
        cfg.bind,
        cfg.resource,
        cfg.bind_wait,
    )
    .await
    .map_err(StartError::Listener)?;
    let request = super::StreamStart::new(
        cfg.channel,
        listener.local_addr(),
        cfg.video,
        cfg.audio,
        cfg.stream_name,
    )
    .map_err(|_| StartError::Request)?;
    let conversation = super::conversation::Config {
        hello: cfg.hello,
        agreement: cfg.agreement,
        stream: cfg.stream,
        time_sync: cfg.time_sync,
        management: cfg.management,
        stream_conditions: cfg.stream_conditions,
        request: &request,
        wait: cfg.conversation_wait,
    };
    let stream_guard = ScopedStreamAuthority {
        inner: owner.stream_authority,
        policy: cfg.admission,
        requested: cfg.bind,
        bound: listener.local_addr(),
    };
    let mut guarded_owner = super::conversation::Owner {
        cx: owner.cx,
        task: owner.task,
        clock: owner.clock,
        effects: &mut *owner.effects,
        leases: owner.leases,
        approval: owner.approval,
        management_authority: owner.management_authority,
        stream_authority: &stream_guard,
        wall: owner.wall,
    };
    if wait_for_reply {
        let reply = guarded_owner
            .start_with_protocol_trace(session, &conversation, &mut trace.protocol)
            .await
            .map_err(StartError::Conversation)?;
        let pipeline = listener
            .accept(
                framer,
                recorder,
                cfg.chunk_bytes,
                cfg.max_bytes,
                cfg.accept_wait,
            )
            .await
            .map_err(StartError::Listener)?;
        return Ok((StartProgress::Confirmed(reply), pipeline));
    }
    let dispatched = guarded_owner
        .start_dispatched_with_protocol_trace(
            session,
            &conversation,
            startup_motion,
            event_replies
                .as_mut()
                .map(|(events, trace)| (*events, &mut **trace)),
            &mut trace.protocol,
        )
        .await
        .map_err(StartError::Conversation)?;
    trace.dispatched = Some(dispatched);
    let deadline = guarded_owner.cx.now() + cfg.accept_wait;
    let mut accept = pin!(listener.accept(
        framer,
        recorder,
        cfg.chunk_bytes,
        cfg.max_bytes,
        cfg.accept_wait
    ));
    loop {
        // Reserve before receiving: a completed observation has already
        // advanced controller state and cannot be recovered from the socket.
        if trace.observations.len() == MAX_ACCEPT_OBSERVATIONS {
            return Err(StartError::Conversation(super::conversation::Error::Limit));
        }
        trace
            .observations
            .try_reserve(1)
            .map_err(|_| StartError::Conversation(super::conversation::Error::Limit))?;
        let left = deadline
            .as_nanos()
            .checked_sub(guarded_owner.cx.now().as_nanos())
            .filter(|v| *v > 0)
            .map(Duration::from_nanos)
            .ok_or(StartError::Listener(Error::Deadline))?;
        enum Ready {
            Media(Result<Pipeline, Error>),
            Control(Result<super::receive::Step, super::receive::Error>),
        }
        let ready = timeout_at(
            deadline,
            poll_fn(|cx| {
                let mut control = pin!(session.next(left));
                if let Poll::Ready(result) = control.as_mut().poll(cx) {
                    return Poll::Ready(Ready::Control(result));
                }
                accept.as_mut().poll(cx).map(Ready::Media)
            }),
        )
        .await
        .map_err(|_| StartError::Listener(Error::Deadline))?;
        match ready {
            Ready::Media(result) => {
                return Ok((
                    StartProgress::Dispatched {
                        dispatched,
                        time_syncs_during_accept: trace.clock_replies_written,
                        observations_during_accept: trace.observations.clone(),
                    },
                    result.map_err(StartError::Listener)?,
                ));
            }
            Ready::Control(Err(error)) => {
                return Err(StartError::Conversation(
                    super::conversation::Error::SessionDetail(error),
                ));
            }
            Ready::Control(Ok(super::receive::Step::Retired { reason, controller })) => {
                trace.protocol.retain_controller_retirement(controller);
                return Err(StartError::Conversation(
                    super::conversation::Error::SessionRetired {
                        reason,
                        phase: controller.previous_phase,
                        rejected_message: controller.rejected_message,
                    },
                ));
            }
            Ready::Control(Ok(super::receive::Step::WaitElapsed)) => {
                return Err(StartError::Listener(Error::Deadline));
            }
            Ready::Control(Ok(super::receive::Step::StartupEventBackpressure)) => {
                return Err(StartError::Conversation(
                    super::conversation::Error::EventBackpressure,
                ));
            }
            Ready::Control(Ok(super::receive::Step::EventReplyBackpressure)) => {
                let Some((events, event_trace)) = event_replies.as_mut() else {
                    return Err(StartError::Conversation(
                        super::conversation::Error::EventBackpressure,
                    ));
                };
                let left = deadline
                    .as_nanos()
                    .checked_sub(guarded_owner.cx.now().as_nanos())
                    .filter(|v| *v > 0)
                    .map(Duration::from_nanos)
                    .ok_or(StartError::Listener(Error::Deadline))?;
                guarded_owner
                    .answer_startup_event(session, cfg.management, events, event_trace, left)
                    .await
                    .map_err(StartError::Conversation)?;
            }
            // This listener runs before the supervisor enables event capture.
            Ready::Control(Ok(
                super::receive::Step::CameraEvent(_) | super::receive::Step::StartupRequest(_),
            )) => {
                return Err(StartError::Conversation(
                    super::conversation::Error::Unexpected,
                ));
            }
            Ready::Control(Ok(super::receive::Step::Observation(
                super::Observation::TimeSyncRequested,
            ))) => {
                trace.clock_requests = trace
                    .clock_requests
                    .checked_add(1)
                    .ok_or(StartError::Conversation(super::conversation::Error::Limit))?;
                let index = dispatched
                    .time_syncs
                    .checked_add(trace.clock_replies_written)
                    .ok_or(StartError::Conversation(super::conversation::Error::Limit))?;
                let operation = cfg
                    .time_sync
                    .get(index)
                    .ok_or(StartError::Conversation(super::conversation::Error::Limit))?;
                let left = deadline
                    .as_nanos()
                    .checked_sub(guarded_owner.cx.now().as_nanos())
                    .filter(|v| *v > 0)
                    .map(Duration::from_nanos)
                    .ok_or(StartError::Listener(Error::Deadline))?;
                let sync_trace = trace
                    .protocol
                    .next_clock()
                    .map_err(StartError::Conversation)?;
                guarded_owner
                    .answer_time_sync_tracked(session, operation, cfg.management, left, sync_trace)
                    .await
                    .map_err(StartError::Conversation)?;
                trace.clock_replies_written += 1;
            }
            Ready::Control(Ok(super::receive::Step::Observation(observation))) => {
                trace.observations.push(observation);
            }
        }
    }
}
