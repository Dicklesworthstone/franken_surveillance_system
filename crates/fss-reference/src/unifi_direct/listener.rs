#![forbid(unsafe_code)]
//! One task-bound, policy-scoped TCP listener for UniFi media connections.
//!
//! IP admission is not cryptographic camera authentication. The caller must
//! bind policy to independently established identity, controller session and
//! stream generation. This owner creates no task, reconnect loop or storage.

use super::{
    ingress::DirectIngress, metered::MeteredClock, pipeline::Pipeline, recording::Recorder,
};
use asupersync::{Cx, net::TcpListener, time::timeout_at, types::Time};
use fss_container::flv_avc::SourceKey;
use fss_core::{BudgetVector, RuntimeGrant};
use fss_packet::extended_flv::stream::{Framer, NameProbeOwner};
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
const MAX_MEDIA_CANDIDATES: usize = 16;

/// Current bounded, nonblocking authorization for this listener and peer.
/// The implementation must bind these addresses to the owner's independently
/// established camera, current session, permitted network and stream lease.
pub trait Admission {
    /// Permit the requested address and, after bind, its actual address.
    fn listener(&self, requested: SocketAddrV4, bound: Option<SocketAddrV4>) -> bool;
    /// Permit a particular incoming peer for the actual bound listener.
    fn peer(&self, bound: SocketAddrV4, source: SocketAddrV4) -> bool;
    /// Explicitly bind a shared controller listener to one camera resource
    /// and its claimed source address. The default refuses sharing. This is
    /// not peer authentication; setup still rechecks the camera admission,
    /// listener resource, camera resource, and live task authority.
    fn controller_camera(
        &self,
        _bound: SocketAddrV4,
        _listener_resource: &str,
        _camera_resource: &str,
        _claimed_peer: Ipv4Addr,
    ) -> bool {
        false
    }
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
    /// Another accept already owns this controller listener.
    Busy,
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
        mut self,
        framer: Framer,
        recorder: Recorder,
        chunk_bytes: usize,
        max_bytes: u64,
        wait: Duration,
    ) -> Result<Pipeline, Error> {
        self.accept_next(framer, recorder, chunk_bytes, max_bytes, wait)
            .await
    }

    /// Accept one candidate while keeping this listener bound for subsequent
    /// connections. The mutable borrow prevents overlapping accepts. Each
    /// returned pipeline owns its own socket and caller-supplied source key;
    /// the caller must retire it and account for any bytes before deciding
    /// whether another connection is appropriate. This method neither selects
    /// a healthy stream nor changes camera settings. Cancellation or refusal
    /// preserves the listener, but consumes the supplied framer and recorder.
    pub async fn accept_next(
        &mut self,
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

/// A media startup that keeps the original listener for later connections.
/// Returning this owner does not select a healthy source or settle effects.
#[must_use = "retire the pipeline and explicitly supervise the retained listener"]
pub struct StartedWithListener<'scope, 'task, 'policy> {
    started: StartedBeforeReply,
    listener: Listener<'scope, 'task, 'policy>,
    requested_stream_name: [u8; 16],
}

impl<'scope, 'task, 'policy> StartedWithListener<'scope, 'task, 'policy> {
    /// Recover the first connection and listener for explicit disposition.
    /// Splitting the owner discards the request binding used for selection.
    pub fn into_parts(self) -> (StartedBeforeReply, Listener<'scope, 'task, 'policy>) {
        (self.started, self.listener)
    }
}

/// Refusal while selecting a nonempty connection. Source bytes remain with the
/// selector's candidate pipelines; no refusal authorizes another camera command.
#[derive(Debug)]
pub enum CandidateError {
    /// Invalid limits, a non-fresh initial pipeline, or an exhausted selector.
    Configuration,
    /// The finite total selection deadline elapsed.
    Deadline,
    /// All allowed candidates closed without sending data.
    EmptyLimit,
    /// The attempt limit was reached with no structurally valid header.
    NoValidHeader,
    /// The factory could not construct the next inert source owners.
    Factory(std::io::ErrorKind),
    /// The next caller-supplied source key was already used in this selection.
    DuplicateSource,
    /// Listener policy, task, network or accept failure.
    Accept(Error),
    /// First-byte probe failed; the candidate pipeline remains caller-owned.
    Probe(super::pipeline::ProbeError),
    /// Name-probe construction refused the caller's bounded configuration.
    NameConfiguration(fss_packet::extended_flv::stream::NameProbeError),
    /// Name-probe transport or task authority failed; candidates remain owned.
    NameProbe(super::pipeline::NameProbeError),
    /// The attempt limit was reached without a matching stream-name claim.
    NoMatchingName,
}
impl fmt::Display for CandidateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi media candidate selection stopped: {self:?}")
    }
}
impl std::error::Error for CandidateError {}

/// A constructor refusal returning both original owners.
#[must_use]
pub struct CandidateRefusal<'scope, 'task, 'policy> {
    /// Original listener, unchanged and still bound.
    pub listener: Listener<'scope, 'task, 'policy>,
    /// Original first pipeline.
    pub pipeline: Pipeline,
}

// Immutable selector-local template. Each distinct connection gets its own
// bounded owner; this neither authenticates a peer nor grants stream authority.
struct NameRequirement {
    event: String,
    name: String,
    byte_limit: usize,
    tag_limit: usize,
    work: u64,
}
impl NameRequirement {
    fn owner(&self) -> Result<NameProbeOwner, CandidateError> {
        NameProbeOwner::new(
            &self.event,
            &self.name,
            self.byte_limit,
            self.tag_limit,
            self.work,
        )
        .map_err(CandidateError::NameConfiguration)
    }
}

/// Bounded, caller-owned selection of the first connection to send a byte.
/// A nonempty connection is not necessarily valid media or an authenticated
/// camera. Control traffic must be supervised independently while this runs.
#[must_use = "retain the selected or unfinished pipeline and listener"]
pub struct MediaCandidates<'scope, 'task, 'policy> {
    listener: Listener<'scope, 'task, 'policy>,
    current: Option<Pipeline>,
    additional: [Option<Box<Pipeline>>; MAX_MEDIA_CANDIDATES - 1],
    parallel: bool,
    validate_header: bool,
    name_requirement: Option<NameRequirement>,
    name_rejections: usize,
    probeable: [bool; MAX_MEDIA_CANDIDATES],
    cursor: usize,
    selected: usize,
    keys: [Option<SourceKey>; MAX_MEDIA_CANDIDATES],
    attempts: usize,
    max_attempts: usize,
    chunk_bytes: usize,
    max_bytes: u64,
    deadline: Time,
    ready: bool,
    fenced: bool,
}

impl<'scope, 'task, 'policy> MediaCandidates<'scope, 'task, 'policy> {
    /// Start with the fresh first connection from a retained-listener startup.
    /// The count includes that connection. Refusal returns both owners.
    pub fn new(
        listener: Listener<'scope, 'task, 'policy>,
        pipeline: Pipeline,
        max_attempts: usize,
        chunk_bytes: usize,
        max_bytes: u64,
        wait: Duration,
    ) -> Result<Self, CandidateRefusal<'scope, 'task, 'policy>> {
        if !pipeline.is_fresh()
            || !(1..=MAX_MEDIA_CANDIDATES).contains(&max_attempts)
            || !(1..=MAX_CHUNK_BYTES).contains(&chunk_bytes)
            || max_bytes == 0
            || !valid_wait(wait)
        {
            return Err(CandidateRefusal { listener, pipeline });
        }
        let mut keys = [None; MAX_MEDIA_CANDIDATES];
        keys[0] = Some(pipeline.source_key());
        let deadline = listener.cx.now() + wait;
        Ok(Self {
            listener,
            current: Some(pipeline),
            additional: std::array::from_fn(|_| None),
            parallel: false,
            validate_header: false,
            name_requirement: None,
            name_rejections: 0,
            probeable: std::array::from_fn(|index| index == 0),
            cursor: 0,
            selected: 0,
            keys,
            attempts: 1,
            max_attempts,
            chunk_bytes,
            max_bytes,
            deadline,
            ready: false,
            fenced: false,
        })
    }

    /// Start directly in concurrent FLV-header mode. Refusal returns the
    /// original owners when the supplied limit for subsequent candidates
    /// cannot hold the shortest legal header. The first pipeline keeps its
    /// separately configured limit. This neither authenticates a peer nor proves
    /// that any subsequent media tag is valid.
    pub fn new_validating(
        listener: Listener<'scope, 'task, 'policy>,
        pipeline: Pipeline,
        max_attempts: usize,
        chunk_bytes: usize,
        max_bytes: u64,
        wait: Duration,
    ) -> Result<Self, CandidateRefusal<'scope, 'task, 'policy>> {
        if max_bytes < 13 {
            return Err(CandidateRefusal { listener, pipeline });
        }
        let mut owner = Self::new(
            listener,
            pipeline,
            max_attempts,
            chunk_bytes,
            max_bytes,
            wait,
        )?;
        owner.parallel = true;
        owner.validate_header = true;
        Ok(owner)
    }

    /// Try candidates until one sends a byte or a finite bound/refusal is met.
    /// The factory must be inert and return a fresh key for each accepted
    /// connection. A dropped borrowing wait retains the listener and current
    /// pipeline; if it was waiting to accept, the unaccepted factory products
    /// are consumed and may need to be reconstructed. Stalled candidates are
    /// retained on deadline rather than classified as empty.
    pub async fn select<F>(&mut self, factory: &mut F) -> Result<(), CandidateError>
    where
        F: FnMut(usize) -> std::io::Result<(Framer, Recorder)>,
    {
        if self.ready || self.fenced {
            return Err(CandidateError::Configuration);
        }
        if self.parallel {
            return self.select_parallel(factory).await;
        }
        loop {
            if self.listener.cx.now() >= self.deadline {
                return Err(CandidateError::Deadline);
            }
            if self.current.is_none() {
                if self.attempts >= self.max_attempts {
                    return Err(CandidateError::EmptyLimit);
                }
                let (framer, recorder) = factory(self.attempts)
                    .map_err(|error| CandidateError::Factory(error.kind()))?;
                let key = recorder.source_key();
                if self.keys[..self.attempts].contains(&Some(key)) {
                    return Err(CandidateError::DuplicateSource);
                }
                let remaining = Duration::from_nanos(
                    self.deadline
                        .as_nanos()
                        .saturating_sub(self.listener.cx.now().as_nanos()),
                );
                if remaining.is_zero() {
                    return Err(CandidateError::Deadline);
                }
                let pipeline = self
                    .listener
                    .accept_next(
                        framer,
                        recorder,
                        self.chunk_bytes,
                        self.max_bytes,
                        remaining,
                    )
                    .await
                    .map_err(CandidateError::Accept)?;
                self.keys[self.attempts] = Some(key);
                self.attempts += 1;
                self.current = Some(pipeline);
            }
            let now = self
                .listener
                .clock
                .now()
                .map_err(|_| CandidateError::Accept(Error::Authority))?;
            let probe = self
                .current
                .as_mut()
                .expect("candidate installed")
                .probe_first_byte(self.listener.task, self.listener.cx, now);
            match timeout_at(self.deadline, probe).await {
                Err(_) => return Err(CandidateError::Deadline),
                Ok(Err(error)) => return Err(CandidateError::Probe(error)),
                Ok(Ok(super::ingress::FirstByte::Data)) => {
                    self.ready = true;
                    return Ok(());
                }
                Ok(Ok(super::ingress::FirstByte::Empty)) => {
                    let retired = self
                        .current
                        .take()
                        .expect("empty candidate retained")
                        .retire();
                    debug_assert_eq!(retired.ingress.source.received, 0);
                }
            }
        }
    }

    /// Enable bounded concurrent probing before selection begins. Each live
    /// candidate remains owned even when another connection is selected.
    pub fn enable_parallel(&mut self) -> Result<(), CandidateError> {
        if self.attempts != 1
            || self.ready
            || self.name_requirement.is_some()
            || !self.current.as_ref().is_some_and(Pipeline::is_fresh)
        {
            return Err(CandidateError::Configuration);
        }
        self.parallel = true;
        Ok(())
    }

    /// Require a complete structural FLV header in parallel mode. Invalid and
    /// incomplete candidates remain caller-owned; the header is not proof of
    /// peer identity, valid subsequent tags, or successful stream effects.
    pub fn require_flv_header(&mut self) -> Result<(), CandidateError> {
        if !self.parallel
            || self.attempts != 1
            || self.ready
            || self.name_requirement.is_some()
            || !self.current.as_ref().is_some_and(Pipeline::is_fresh)
        {
            return Err(CandidateError::Configuration);
        }
        self.validate_header = true;
        Ok(())
    }

    /// Require an explicitly expected event and stream-name claim before
    /// selecting a candidate. Each admitted connection receives an independent
    /// bounded probe; rejected pipelines and their source bytes remain owned.
    /// The caller must bind these expectations to the actual stream request.
    /// A matching claim is unauthenticated and does not establish identity.
    pub fn require_stream_name(
        &mut self,
        event: &str,
        name: &str,
        byte_limit: usize,
        tag_limit: usize,
        work_per_candidate: u64,
    ) -> Result<(), CandidateError> {
        if !self.parallel
            || self.attempts != 1
            || self.ready
            || self.name_requirement.is_some()
            || !self.current.as_ref().is_some_and(Pipeline::is_fresh)
            || u64::try_from(byte_limit).map_or(true, |value| value > self.max_bytes)
        {
            return Err(CandidateError::Configuration);
        }
        let probe = NameProbeOwner::new(event, name, byte_limit, tag_limit, work_per_candidate)
            .map_err(CandidateError::NameConfiguration)?;
        let mut event_copy = String::new();
        event_copy.try_reserve_exact(event.len()).map_err(|_| {
            CandidateError::NameConfiguration(
                fss_packet::extended_flv::stream::NameProbeError::Allocation,
            )
        })?;
        event_copy.push_str(event);
        let mut name_copy = String::new();
        name_copy.try_reserve_exact(name.len()).map_err(|_| {
            CandidateError::NameConfiguration(
                fss_packet::extended_flv::stream::NameProbeError::Allocation,
            )
        })?;
        name_copy.push_str(name);
        let requirement = NameRequirement {
            event: event_copy,
            name: name_copy,
            byte_limit,
            tag_limit,
            work: work_per_candidate,
        };
        self.current
            .as_mut()
            .ok_or(CandidateError::Configuration)?
            .begin_name_probe(probe)
            .map_err(|_| CandidateError::Configuration)?;
        self.name_requirement = Some(requirement);
        Ok(())
    }

    async fn select_parallel<F>(&mut self, factory: &mut F) -> Result<(), CandidateError>
    where
        F: FnMut(usize) -> std::io::Result<(Framer, Recorder)>,
    {
        enum Observation {
            First(super::ingress::FirstByte),
            Header(super::ingress::HeaderProbe),
        }
        enum Ready {
            Probe(usize, Result<Observation, super::pipeline::ProbeError>),
            Name(
                usize,
                Result<super::ingress::NameProbeStep, super::pipeline::NameProbeError>,
            ),
            Accept(Result<Pipeline, Error>),
        }
        loop {
            let remaining = Duration::from_nanos(
                self.deadline
                    .as_nanos()
                    .saturating_sub(self.listener.cx.now().as_nanos()),
            );
            if remaining.is_zero() {
                return Err(CandidateError::Deadline);
            }
            if !self.probeable.iter().any(|value| *value) && self.attempts == self.max_attempts {
                return Err(if self.name_requirement.is_some() {
                    CandidateError::NoMatchingName
                } else if self.validate_header {
                    CandidateError::NoValidHeader
                } else {
                    CandidateError::EmptyLimit
                });
            }
            // Factory products are inert. If the wait is cancelled before an
            // accept, they may be reconstructed; accepted pipelines stay here.
            let next = if self.attempts < self.max_attempts {
                let (framer, recorder) =
                    factory(self.attempts).map_err(|e| CandidateError::Factory(e.kind()))?;
                let key = recorder.source_key();
                if self.keys[..self.attempts].contains(&Some(key)) {
                    return Err(CandidateError::DuplicateSource);
                }
                Some((framer, recorder, key))
            } else {
                None
            };
            let key = next.as_ref().map(|(_, _, key)| *key);
            let listener = &mut self.listener;
            let task = listener.task;
            let cx = listener.cx;
            let clock = listener.clock;
            let mut accept = next.map(|(framer, recorder, _)| {
                Box::pin(listener.accept_next(
                    framer,
                    recorder,
                    self.chunk_bytes,
                    self.max_bytes,
                    remaining,
                ))
            });
            let current = &mut self.current;
            let additional = &mut self.additional;
            let probeable = &self.probeable;
            let cursor = self.cursor;
            let validate_header = self.validate_header;
            let validate_name = self.name_requirement.is_some();
            let ready = timeout_at(
                self.deadline,
                poll_fn(|context| {
                    for step in 0..MAX_MEDIA_CANDIDATES {
                        let index = (cursor + step) % MAX_MEDIA_CANDIDATES;
                        if !probeable[index] {
                            continue;
                        }
                        let candidate = if index == 0 {
                            current.as_mut()
                        } else {
                            additional[index - 1].as_deref_mut()
                        };
                        if let Some(pipeline) = candidate {
                            let now = match clock.now() {
                                Ok(now) => now,
                                Err(_) => return Poll::Ready(Ready::Accept(Err(Error::Authority))),
                            };
                            if validate_name {
                                let mut probe = pin!(pipeline.probe_name_step(task, cx, now));
                                if let Poll::Ready(result) = probe.as_mut().poll(context) {
                                    return Poll::Ready(Ready::Name(index, result));
                                }
                            } else if validate_header {
                                let mut probe = pin!(pipeline.probe_header_step(task, cx, now));
                                if let Poll::Ready(result) = probe.as_mut().poll(context) {
                                    return Poll::Ready(Ready::Probe(
                                        index,
                                        result.map(Observation::Header),
                                    ));
                                }
                            } else {
                                let mut probe = pin!(pipeline.probe_first_byte(task, cx, now));
                                if let Poll::Ready(result) = probe.as_mut().poll(context) {
                                    return Poll::Ready(Ready::Probe(
                                        index,
                                        result.map(Observation::First),
                                    ));
                                }
                            }
                        }
                    }
                    if let Some(accept) = accept.as_mut() {
                        if let Poll::Ready(result) = accept.as_mut().poll(context) {
                            return Poll::Ready(Ready::Accept(result));
                        }
                    }
                    Poll::Pending
                }),
            )
            .await
            .map_err(|_| CandidateError::Deadline)?;
            drop(accept);
            match ready {
                Ready::Accept(Err(error)) => return Err(CandidateError::Accept(error)),
                Ready::Accept(Ok(pipeline)) => {
                    self.keys[self.attempts] = key;
                    self.attempts += 1;
                    let (index, slot) = self
                        .additional
                        .iter_mut()
                        .enumerate()
                        .find(|(_, slot)| slot.is_none())
                        .expect("bounded candidate slot");
                    *slot = Some(Box::new(pipeline));
                    if let Some(requirement) = &self.name_requirement {
                        let probe = match requirement.owner() {
                            Ok(probe) => probe,
                            Err(error) => {
                                self.fenced = true;
                                return Err(error);
                            }
                        };
                        if slot
                            .as_deref_mut()
                            .expect("installed candidate")
                            .begin_name_probe(probe)
                            .is_err()
                        {
                            self.fenced = true;
                            return Err(CandidateError::Configuration);
                        }
                    }
                    self.probeable[index + 1] = true;
                }
                Ready::Probe(_index, Err(error)) => return Err(CandidateError::Probe(error)),
                Ready::Name(
                    index,
                    Err(super::pipeline::NameProbeError::Ingress(
                        super::ingress::NameProbeError::Inspect(
                            fss_packet::extended_flv::stream::NameProbeError::Metadata(_)
                            | fss_packet::extended_flv::stream::NameProbeError::Framing(_)
                            | fss_packet::extended_flv::stream::NameProbeError::Provisional
                            | fss_packet::extended_flv::stream::NameProbeError::WorkLimit,
                        ),
                    )),
                ) => {
                    self.name_rejections += 1;
                    self.probeable[index] = false;
                    self.cursor = (index + 1) % MAX_MEDIA_CANDIDATES;
                }
                Ready::Name(_, Err(error)) => return Err(CandidateError::NameProbe(error)),
                Ready::Name(index, Ok(super::ingress::NameProbeStep::Matched { .. })) => {
                    self.selected = index;
                    self.ready = true;
                    return Ok(());
                }
                Ready::Name(index, Ok(super::ingress::NameProbeStep::Progress { .. })) => {
                    self.cursor = (index + 1) % MAX_MEDIA_CANDIDATES;
                    asupersync::runtime::yield_now().await;
                }
                Ready::Name(
                    index,
                    Ok(
                        super::ingress::NameProbeStep::Mismatched { .. }
                        | super::ingress::NameProbeStep::LimitReached { .. }
                        | super::ingress::NameProbeStep::Incomplete,
                    ),
                ) => {
                    self.name_rejections += 1;
                    self.probeable[index] = false;
                    self.cursor = (index + 1) % MAX_MEDIA_CANDIDATES;
                }
                Ready::Name(index, Ok(super::ingress::NameProbeStep::Empty)) => {
                    self.name_rejections += 1;
                    self.probeable[index] = false;
                    self.cursor = (index + 1) % MAX_MEDIA_CANDIDATES;
                    let retired = if index == 0 {
                        self.current.take().expect("probed candidate").retire()
                    } else {
                        self.additional[index - 1]
                            .take()
                            .expect("probed candidate")
                            .retire()
                    };
                    debug_assert_eq!(retired.ingress.source.received, 0);
                }
                Ready::Probe(
                    index,
                    Ok(
                        Observation::First(super::ingress::FirstByte::Data)
                        | Observation::Header(super::ingress::HeaderProbe::Valid),
                    ),
                ) => {
                    self.selected = index;
                    self.ready = true;
                    return Ok(());
                }
                Ready::Probe(
                    index,
                    Ok(Observation::Header(super::ingress::HeaderProbe::Progress)),
                ) => {
                    self.cursor = (index + 1) % MAX_MEDIA_CANDIDATES;
                    asupersync::runtime::yield_now().await;
                }
                Ready::Probe(
                    index,
                    Ok(Observation::Header(
                        super::ingress::HeaderProbe::Invalid
                        | super::ingress::HeaderProbe::Incomplete,
                    )),
                ) => {
                    self.probeable[index] = false;
                    self.cursor = (index + 1) % MAX_MEDIA_CANDIDATES;
                }
                Ready::Probe(
                    index,
                    Ok(
                        Observation::First(super::ingress::FirstByte::Empty)
                        | Observation::Header(super::ingress::HeaderProbe::Empty),
                    ),
                ) => {
                    self.probeable[index] = false;
                    self.cursor = (index + 1) % MAX_MEDIA_CANDIDATES;
                    let retired = if index == 0 {
                        self.current.take().expect("probed candidate").retire()
                    } else {
                        self.additional[index - 1]
                            .take()
                            .expect("probed candidate")
                            .retire()
                    };
                    debug_assert_eq!(retired.ingress.source.received, 0);
                }
            }
        }
    }

    /// The count of accepted candidate connections, including the first.
    pub fn attempts(&self) -> usize {
        self.attempts
    }

    /// Candidate name probes rejected or exhausted under the explicit policy.
    /// This count is local observation, not evidence of camera absence.
    pub fn name_rejections(&self) -> usize {
        self.name_rejections
    }

    /// Transfer a nonempty pipeline only after selection succeeds.
    pub fn take_ready(&mut self) -> Option<Pipeline> {
        if !self.ready {
            return None;
        }
        if self.selected == 0 {
            self.current.take()
        } else {
            self.additional[self.selected - 1]
                .take()
                .map(|pipeline| *pipeline)
        }
    }

    /// Recover every unfinished pipeline and the listener, including on
    /// timeout or after a different candidate was selected. An idle socket
    /// may contain unread bytes: its retirement is not proof of emptiness.
    pub fn into_parts(
        self,
    ) -> (
        Listener<'scope, 'task, 'policy>,
        Option<Pipeline>,
        [Option<Box<Pipeline>>; MAX_MEDIA_CANDIDATES - 1],
    ) {
        (self.listener, self.current, self.additional)
    }
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
    selection_reply_in_flight: bool,
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

    /// Whether a candidate-selection reply was interrupted or failed before
    /// its local completion was observed. Such an attempt must be reconciled.
    pub fn selection_reply_in_flight(&self) -> bool {
        self.selection_reply_in_flight
    }

    fn is_empty(&self) -> bool {
        !self.attempted
            && self.dispatched.is_none()
            && self.clock_requests == 0
            && self.clock_replies_written == 0
            && self.observations.is_empty()
            && !self.selection_reply_in_flight
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
    let (progress, pipeline, _listener) = start_inner(
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
    let (progress, pipeline, _listener) = start_inner(
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

/// Like [`start_before_reply_tracked`], but keeps the original media listener
/// after the first accepted connection. Callers must supervise and retire each
/// candidate, choose fresh source keys, and account for gaps themselves.
/// No reconnect, media-health test, or additional camera command is implied.
pub async fn start_before_reply_retaining_listener<'scope, 'task, 'policy, IO>(
    owner: &mut super::conversation::Owner<'_, 'scope, 'task>,
    session: &mut super::receive::Session<'_, '_, IO>,
    cfg: &Start<'policy>,
    framer: Framer,
    recorder: Recorder,
    trace: &mut StartTrace,
) -> Result<StartedWithListener<'scope, 'task, 'policy>, StartError>
where
    IO: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin,
{
    if !trace.is_empty() {
        return Err(StartError::Listener(Error::Configuration));
    }
    let requested_stream_name: [u8; 16] = cfg
        .stream_name
        .as_bytes()
        .try_into()
        .map_err(|_| StartError::Request)?;
    trace.attempted = true;
    let (progress, pipeline, listener) = start_inner(
        owner, session, cfg, framer, recorder, false, trace, None, None,
    )
    .await?;
    match progress {
        StartProgress::Dispatched {
            dispatched,
            time_syncs_during_accept,
            observations_during_accept,
        } => Ok(StartedWithListener {
            started: StartedBeforeReply {
                dispatched,
                time_syncs_during_accept,
                observations_during_accept,
                pipeline,
            },
            listener,
            requested_stream_name,
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
    let (progress, pipeline, _listener) = start_inner(
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
    let (progress, pipeline, _listener) = start_inner(
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

/// Event-aware startup that retains the media listener for candidate selection.
/// The caller still owns both traces, the controller session and every source.
pub async fn start_with_events_retaining_listener<'scope, 'task, 'policy, IO>(
    owner: &mut super::conversation::Owner<'_, 'scope, 'task>,
    session: &mut super::receive::Session<'_, '_, IO>,
    cfg: &Start<'policy>,
    framer: Framer,
    recorder: Recorder,
    trace: &mut StartTrace,
    motion: Option<(
        &super::conversation::StartupMotion<'_>,
        &mut super::conversation::StartupMotionTrace,
    )>,
    events: &super::conversation::StartupEventReplies<'_>,
    event_trace: &mut super::conversation::StartupEventTrace,
) -> Result<StartedWithListener<'scope, 'task, 'policy>, StartError>
where
    IO: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin,
{
    if !trace.is_empty()
        || event_trace.attempted()
        || motion.as_ref().is_some_and(|(_, t)| t.attempted())
    {
        return Err(StartError::Listener(Error::Configuration));
    }
    let requested_stream_name: [u8; 16] = cfg
        .stream_name
        .as_bytes()
        .try_into()
        .map_err(|_| StartError::Request)?;
    trace.attempted = true;
    let (progress, pipeline, listener) = start_inner(
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
        } => Ok(StartedWithListener {
            started: StartedBeforeReply {
                dispatched,
                time_syncs_during_accept,
                observations_during_accept,
                pipeline,
            },
            listener,
            requested_stream_name,
        }),
        StartProgress::Confirmed(_) => Err(StartError::Conversation(
            super::conversation::Error::Configuration,
        )),
    }
}

/// Startup observations retained separately from the media source owner.
/// These are local and remote claims, not authenticated device outcomes.
#[must_use]
pub struct ValidatedStartupEvidence {
    /// Local stream-dispatch observation.
    pub dispatched: super::conversation::Dispatched,
    /// Clock replies written during the initial media accept.
    pub time_syncs_during_accept: usize,
    /// Controller observations received during that accept.
    pub observations_during_accept: Vec<super::Observation>,
    requested_stream_name: [u8; 16],
}

/// Constructor refusal preserving the original listener, pipeline, and
/// observations for caller-directed disposition.
#[must_use]
pub struct ValidatedSelectionRefusal<'scope, 'task, 'policy> {
    /// Exact startup owner supplied to the constructor.
    pub startup: StartedWithListener<'scope, 'task, 'policy>,
}

/// Caller-owned validated media selection after a retained-listener startup.
/// This owner does not start a camera or independently reconcile its effects.
/// Dropping a borrowing selection wait retains this owner, while the caller
/// continues to own the controller session, effect journal and startup trace.
#[must_use = "retain or explicitly retire every candidate and startup observation"]
pub struct ValidatedMediaSelection<'scope, 'task, 'policy> {
    startup: ValidatedStartupEvidence,
    candidates: MediaCandidates<'scope, 'task, 'policy>,
}

impl<'scope, 'task, 'policy> ValidatedMediaSelection<'scope, 'task, 'policy> {
    /// Wrap an already accepted startup and install a bounded validating
    /// selector. Refusal returns the complete original startup owner.
    pub fn new(
        startup: StartedWithListener<'scope, 'task, 'policy>,
        max_attempts: usize,
        chunk_bytes: usize,
        max_bytes: u64,
        wait: Duration,
    ) -> Result<Self, ValidatedSelectionRefusal<'scope, 'task, 'policy>> {
        let StartedWithListener {
            listener,
            started,
            requested_stream_name,
        } = startup;
        let StartedBeforeReply {
            dispatched,
            time_syncs_during_accept,
            observations_during_accept,
            pipeline,
        } = started;
        match MediaCandidates::new_validating(
            listener,
            pipeline,
            max_attempts,
            chunk_bytes,
            max_bytes,
            wait,
        ) {
            Ok(candidates) => Ok(Self {
                startup: ValidatedStartupEvidence {
                    dispatched,
                    time_syncs_during_accept,
                    observations_during_accept,
                    requested_stream_name,
                },
                candidates,
            }),
            Err(CandidateRefusal { listener, pipeline }) => Err(ValidatedSelectionRefusal {
                startup: StartedWithListener {
                    listener,
                    requested_stream_name,
                    started: StartedBeforeReply {
                        dispatched,
                        time_syncs_during_accept,
                        observations_during_accept,
                        pipeline,
                    },
                },
            }),
        }
    }

    /// Borrow the exact startup observations, which do not prove remote success.
    pub fn startup(&self) -> &ValidatedStartupEvidence {
        &self.startup
    }

    /// Number of admitted candidate connections, including the initial one.
    pub fn attempts(&self) -> usize {
        self.candidates.attempts()
    }

    /// Opt into a bounded claim requirement for the locally dispatched name.
    /// The caller chooses the event; matching metadata does not authenticate
    /// a camera or establish that it accepted the stream request.
    pub fn require_stream_name(
        &mut self,
        event: &str,
        byte_limit: usize,
        tag_limit: usize,
        work_per_candidate: u64,
    ) -> Result<(), CandidateError> {
        let name = std::str::from_utf8(&self.startup.requested_stream_name)
            .map_err(|_| CandidateError::Configuration)?;
        self.candidates
            .require_stream_name(event, name, byte_limit, tag_limit, work_per_candidate)
    }

    /// Select while supervising the supplied controller. Cancellation preserves
    /// this owner; an interrupted control write still requires reconciliation.
    pub async fn select<IO, F>(
        &mut self,
        owner: &mut super::conversation::Owner<'_, 'scope, 'task>,
        session: &mut super::receive::Session<'scope, 'task, IO>,
        cfg: &Start<'_>,
        trace: &mut StartTrace,
        event_replies: Option<(
            &super::conversation::StartupEventReplies<'_>,
            &mut super::conversation::StartupEventTrace,
        )>,
        factory: &mut F,
    ) -> Result<(), CandidateControlError>
    where
        IO: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin,
        F: FnMut(usize) -> std::io::Result<(Framer, Recorder)>,
    {
        select_candidates_with_control(
            &mut self.candidates,
            owner,
            session,
            cfg,
            trace,
            event_replies,
            factory,
        )
        .await
    }

    /// Transfer the selected pipeline without disposing of other connections.
    pub fn take_ready(&mut self) -> Option<Pipeline> {
        self.candidates.take_ready()
    }

    /// Recover startup observations and all remaining candidate owners.
    pub fn into_parts(
        self,
    ) -> (
        ValidatedStartupEvidence,
        MediaCandidates<'scope, 'task, 'policy>,
    ) {
        (self.startup, self.candidates)
    }
}

/// Selection or controller failure. Both the candidate owner and startup
/// traces remain with the caller for retirement and reconciliation.
#[derive(Debug)]
pub enum CandidateControlError {
    /// Candidate selection stopped without selecting a source.
    Candidate(CandidateError),
    /// The controller, its reply effect, or its bounded trace stopped.
    Conversation(super::conversation::Error),
    /// An already-captured event or request requires caller custody.
    CapturedFrame(super::events::Frame),
}
impl fmt::Display for CandidateControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi candidate supervision stopped: {self:?}")
    }
}
impl std::error::Error for CandidateControlError {}

/// Select a nonempty media connection while servicing the same controller.
/// Bounded clock and optional startup-event replies use the original startup
/// trace, fresh operation identities and current owner authority. A dropped
/// wait preserves candidates; a dropped in-flight reply fences further use of
/// this trace until the caller reconciles it. Neither a reply nor a nonempty
/// connection proves camera identity, successful effects or valid media.
pub async fn select_candidates_with_control<'scope, 'task, 'policy, IO, F>(
    candidates: &mut MediaCandidates<'scope, 'task, 'policy>,
    owner: &mut super::conversation::Owner<'_, 'scope, 'task>,
    session: &mut super::receive::Session<'scope, 'task, IO>,
    cfg: &Start<'_>,
    trace: &mut StartTrace,
    mut event_replies: Option<(
        &super::conversation::StartupEventReplies<'_>,
        &mut super::conversation::StartupEventTrace,
    )>,
    factory: &mut F,
) -> Result<(), CandidateControlError>
where
    IO: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin,
    F: FnMut(usize) -> std::io::Result<(Framer, Recorder)>,
{
    use super::conversation::Error as ConversationError;
    let dispatched = trace.dispatched.ok_or(CandidateControlError::Conversation(
        ConversationError::Configuration,
    ))?;
    let used = dispatched
        .time_syncs
        .checked_add(trace.clock_replies_written)
        .ok_or(CandidateControlError::Conversation(
            ConversationError::Limit,
        ))?;
    if trace.selection_reply_in_flight
        || trace.clock_requests != trace.clock_replies_written
        || trace.protocol.clocks().len() != used
        || used > cfg.time_sync.len()
        || trace
            .protocol
            .clocks()
            .iter()
            .zip(cfg.time_sync)
            .any(|(prior, operation)| prior.operation() != Some(operation))
        || !std::ptr::eq(candidates.listener.task, owner.task)
        || !std::ptr::eq(candidates.listener.cx, owner.cx)
        || !candidates.listener.clock.same_mapping(&owner.clock)
        || !session.matches_clock(&owner.clock)
        || event_replies.as_ref().is_some_and(|(events, event_trace)| {
            !event_trace.attempted()
                || event_trace.attempts().len() > events.operations.len()
                || event_trace
                    .attempts()
                    .iter()
                    .zip(events.operations)
                    .any(|(prior, operation)| prior.operation() != operation)
        })
    {
        return Err(CandidateControlError::Conversation(
            ConversationError::Configuration,
        ));
    }
    let deadline = candidates.deadline;
    let mut selection = pin!(candidates.select(factory));
    loop {
        if trace.observations.len() == MAX_ACCEPT_OBSERVATIONS {
            return Err(CandidateControlError::Conversation(
                ConversationError::Limit,
            ));
        }
        trace
            .observations
            .try_reserve(1)
            .map_err(|_| CandidateControlError::Conversation(ConversationError::Limit))?;
        let left = deadline
            .as_nanos()
            .checked_sub(owner.cx.now().as_nanos())
            .filter(|v| *v > 0)
            .map(Duration::from_nanos)
            .ok_or(CandidateControlError::Candidate(CandidateError::Deadline))?;
        enum Ready {
            Media(Result<(), CandidateError>),
            Control(Result<super::receive::Step, super::receive::Error>),
        }
        let ready = timeout_at(
            deadline,
            poll_fn(|cx| {
                let mut control = pin!(session.next(left));
                if let Poll::Ready(result) = control.as_mut().poll(cx) {
                    return Poll::Ready(Ready::Control(result));
                }
                selection.as_mut().poll(cx).map(Ready::Media)
            }),
        )
        .await
        .map_err(|_| CandidateControlError::Candidate(CandidateError::Deadline))?;
        match ready {
            Ready::Media(result) => return result.map_err(CandidateControlError::Candidate),
            Ready::Control(Err(error)) => {
                return Err(CandidateControlError::Conversation(
                    ConversationError::SessionDetail(error),
                ));
            }
            Ready::Control(Ok(super::receive::Step::Retired { reason, controller })) => {
                trace.protocol.retain_controller_retirement(controller);
                return Err(CandidateControlError::Conversation(
                    ConversationError::SessionRetired {
                        reason,
                        phase: controller.previous_phase,
                        rejected_message: controller.rejected_message,
                    },
                ));
            }
            Ready::Control(Ok(super::receive::Step::WaitElapsed)) => {
                return Err(CandidateControlError::Candidate(CandidateError::Deadline));
            }
            Ready::Control(Ok(super::receive::Step::StartupEventBackpressure)) => {
                return Err(CandidateControlError::Conversation(
                    ConversationError::EventBackpressure,
                ));
            }
            Ready::Control(Ok(super::receive::Step::EventReplyBackpressure)) => {
                let Some((events, event_trace)) = event_replies.as_mut() else {
                    return Err(CandidateControlError::Conversation(
                        ConversationError::EventBackpressure,
                    ));
                };
                let left = deadline
                    .as_nanos()
                    .checked_sub(owner.cx.now().as_nanos())
                    .filter(|v| *v > 0)
                    .map(Duration::from_nanos)
                    .ok_or(CandidateControlError::Candidate(CandidateError::Deadline))?;
                trace.selection_reply_in_flight = true;
                owner
                    .answer_startup_event(session, cfg.management, events, event_trace, left)
                    .await
                    .map_err(CandidateControlError::Conversation)?;
                trace.selection_reply_in_flight = false;
            }
            Ready::Control(Ok(
                super::receive::Step::CameraEvent(frame)
                | super::receive::Step::StartupRequest(frame),
            )) => return Err(CandidateControlError::CapturedFrame(frame)),
            Ready::Control(Ok(super::receive::Step::Observation(
                super::Observation::TimeSyncRequested,
            ))) => {
                trace.clock_requests = trace.clock_requests.checked_add(1).ok_or(
                    CandidateControlError::Conversation(ConversationError::Limit),
                )?;
                let index = dispatched
                    .time_syncs
                    .checked_add(trace.clock_replies_written)
                    .ok_or(CandidateControlError::Conversation(
                        ConversationError::Limit,
                    ))?;
                let operation =
                    cfg.time_sync
                        .get(index)
                        .ok_or(CandidateControlError::Conversation(
                            ConversationError::Limit,
                        ))?;
                let left = deadline
                    .as_nanos()
                    .checked_sub(owner.cx.now().as_nanos())
                    .filter(|v| *v > 0)
                    .map(Duration::from_nanos)
                    .ok_or(CandidateControlError::Candidate(CandidateError::Deadline))?;
                let sync_trace = trace
                    .protocol
                    .next_clock()
                    .map_err(CandidateControlError::Conversation)?;
                trace.selection_reply_in_flight = true;
                owner
                    .answer_time_sync_tracked(session, operation, cfg.management, left, sync_trace)
                    .await
                    .map_err(CandidateControlError::Conversation)?;
                trace.clock_replies_written += 1;
                trace.selection_reply_in_flight = false;
            }
            Ready::Control(Ok(super::receive::Step::Observation(observation))) => {
                let rejected = matches!(
                    observation,
                    super::Observation::StreamSettingsReply {
                        success: Some(false),
                        ..
                    }
                );
                trace.observations.push(observation);
                if rejected {
                    return Err(CandidateControlError::Conversation(
                        ConversationError::Unexpected,
                    ));
                }
            }
        }
    }
}

async fn start_inner<
    'scope,
    'task,
    'policy,
    IO: asupersync::io::AsyncRead + asupersync::io::AsyncWrite + Unpin,
>(
    owner: &mut super::conversation::Owner<'_, 'scope, 'task>,
    session: &mut super::receive::Session<'_, '_, IO>,
    cfg: &Start<'policy>,
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
) -> Result<(StartProgress, Pipeline, Listener<'scope, 'task, 'policy>), StartError> {
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
    let mut listener = Listener::bind(
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
            .accept_next(
                framer,
                recorder,
                cfg.chunk_bytes,
                cfg.max_bytes,
                cfg.accept_wait,
            )
            .await
            .map_err(StartError::Listener)?;
        return Ok((StartProgress::Confirmed(reply), pipeline, listener));
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
    let (progress, pipeline) = {
        let mut accept = pin!(listener.accept_next(
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
                    break (
                        StartProgress::Dispatched {
                            dispatched,
                            time_syncs_during_accept: trace.clock_replies_written,
                            observations_during_accept: trace.observations.clone(),
                        },
                        result.map_err(StartError::Listener)?,
                    );
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
                        .answer_time_sync_tracked(
                            session,
                            operation,
                            cfg.management,
                            left,
                            sync_trace,
                        )
                        .await
                        .map_err(StartError::Conversation)?;
                    trace.clock_replies_written += 1;
                }
                Ready::Control(Ok(super::receive::Step::Observation(observation))) => {
                    trace.observations.push(observation);
                }
            }
        }
    };
    Ok((progress, pipeline, listener))
}
