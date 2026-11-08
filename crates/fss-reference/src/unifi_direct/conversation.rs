#![forbid(unsafe_code)]
//! Experimental bounded controller conversation for one already-admitted session.
//!
//! This composes existing task ownership, journal-backed effects and the
//! management session. It does not bind a listener, authenticate a peer,
//! provision Wi-Fi, verify settings or retain media. Durable journal calls are
//! synchronous; this is not a production nonblocking owner. Callers must
//! retire the session on failure and reconcile every committed operation.

use super::{
    AGREEMENT_DELAY_NS, Observation, Phase, StreamStart, intent, management,
    metered::MeteredClock,
    motion,
    receive::{
        ManagementAuthority, ManagementRefusal, ManagementWrite, MotionAuthority, MotionRefusal,
        MotionWrite, Session, Step, StreamAuthority, StreamRefusal, StreamWrite,
    },
};
use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
};
use fss_core::{ContentDigest, IdempotencyKey, OperationId, RuntimeGrant};
use fss_runtime::{
    effect::{CommitApproval, CommittedEffect, EffectCoordinator, PrepareSpec, PreparedEffect},
    execution::TaskCx,
    lease::LeaseRegistry,
};
use std::{cell::RefCell, fmt, time::Duration};

const MAX_MESSAGES: usize = 128;

/// Current wall-clock data for outgoing controller messages.
pub struct WallTime {
    /// Milliseconds since the Unix epoch, for a time-sync response.
    pub unix_ms: u64,
    /// Timestamp in the controller's accepted wire format.
    pub timestamp: String,
}
/// Supplies current wall-clock observations. Must be bounded and nonblocking.
pub trait WallClock {
    /// Observe current time; `None` refuses the operation.
    fn observe(&self) -> Option<WallTime>;
}
/// Revalidates current authorization and preconditions immediately before commit.
/// A decision must be tied to this exact preparation and must not block.
pub trait Approval {
    /// Return an approval for this preparation, or refuse it.
    fn approve(&self, prepared: &PreparedEffect) -> Option<CommitApproval>;
}

/// Exact operation identities and camera claims supplied by the caller.
pub struct Config<'a> {
    /// Distinct durable operation identity for the hello reply.
    pub hello: &'a OperationId,
    /// Distinct durable operation identity for the agreement request.
    pub agreement: &'a OperationId,
    /// Distinct durable operation identity for the stream-setting request.
    pub stream: &'a OperationId,
    /// Distinct operation identities reserved for camera-requested clock updates.
    pub time_sync: &'a [OperationId],
    /// Caller-established current management preconditions.
    pub management: management::Preconditions,
    /// Caller-established current stream preconditions.
    pub stream_conditions: intent::Preconditions,
    /// Exact requested track, destination and codecs.
    pub request: &'a StreamStart,
    /// One total deadline for the operation, no more than 30 seconds.
    pub wait: Duration,
}

/// Explicit optional motion configuration for one startup attempt.
pub struct StartupMotion<'a> {
    /// Distinct journal operation for the requested setting.
    pub operation: &'a OperationId,
    /// Exact caller-supplied current motion conditions.
    pub conditions: motion::Preconditions,
    /// Requested baseline motion state.
    pub enabled: bool,
    /// Independent current permission for this exact motion setting.
    pub authority: &'a dyn MotionAuthority,
}

/// Distinct, caller-provided operation identities for bounded startup replies.
/// The session must already have a caller-owned startup inbox bound. Unknown
/// requests require the session's separate capture opt-in and disclosure gate.
pub struct StartupEventReplies<'a> {
    /// One unique journal operation per requested reply, at most 64.
    pub operations: &'a [OperationId],
}

/// One source-bound startup reply attempt, including any still-owned permit.
pub struct StartupEventAttempt {
    operation: OperationId,
    source: ContentDigest,
    intent: Option<management::Intent>,
    dispatch_started: bool,
    pending_permit: Option<CommittedEffect>,
    written: Option<ManagementWrite>,
    refusal: Option<ManagementRefusal>,
}
impl StartupEventAttempt {
    /// Exact operation identity; it remains subject to journal reconciliation.
    pub fn operation(&self) -> &OperationId {
        &self.operation
    }
    /// Digest of the original event or request retained by the startup inbox owner.
    pub fn source(&self) -> ContentDigest {
        self.source
    }
    /// Prepared source-bound intent, if preparation completed.
    pub fn intent(&self) -> Option<management::Intent> {
        self.intent
    }
    /// True when the committed permit was handed to the dispatch future.
    pub fn dispatch_started(&self) -> bool {
        self.dispatch_started
    }
    /// A committed permit not handed to dispatch.
    pub fn take_pending_permit(&mut self) -> Option<CommittedEffect> {
        self.pending_permit.take()
    }
    /// Local outcome and its permit; neither proves remote receipt.
    pub fn take_written(&mut self) -> Option<ManagementWrite> {
        self.written.take()
    }
    /// Pre-write refusal and its still-owned permit.
    pub fn take_refusal(&mut self) -> Option<ManagementRefusal> {
        self.refusal.take()
    }
}

/// Caller-owned startup reply effects and outcomes across cancellation.
#[derive(Default)]
pub struct StartupEventTrace {
    attempted: bool,
    attempts: Vec<StartupEventAttempt>,
}
impl StartupEventTrace {
    /// Whether this trace was bound to a startup attempt.
    pub fn attempted(&self) -> bool {
        self.attempted
    }
    /// Attempts in observation order, without event payloads.
    pub fn attempts(&self) -> &[StartupEventAttempt] {
        &self.attempts
    }
    /// Access retained permits and outcomes for reconciliation.
    pub fn attempts_mut(&mut self) -> &mut [StartupEventAttempt] {
        &mut self.attempts
    }
}

/// Caller-owned motion facts preserved across startup failure or cancellation.
#[derive(Default)]
pub struct StartupMotionTrace {
    attempted: bool,
    intent: Option<motion::Intent>,
    dispatch_started: bool,
    pending_permit: Option<CommittedEffect>,
    written: Option<MotionWrite>,
    refusal: Option<MotionRefusal>,
}
impl StartupMotionTrace {
    /// Whether this trace was bound to a startup attempt.
    pub fn attempted(&self) -> bool {
        self.attempted
    }
    /// Exact inert intent once prepared.
    pub fn intent(&self) -> Option<motion::Intent> {
        self.intent
    }
    /// Whether the committed permit was handed to dispatch.
    pub fn dispatch_started(&self) -> bool {
        self.dispatch_started
    }
    /// Committed permit not yet handed to dispatch, if a later step failed.
    pub fn pending_permit(&self) -> Option<&CommittedEffect> {
        self.pending_permit.as_ref()
    }
    /// Transfer a committed but undispatched permit for reconciliation.
    pub fn take_pending_permit(&mut self) -> Option<CommittedEffect> {
        self.pending_permit.take()
    }
    /// Local write result and retained permit, if dispatch returned.
    pub fn written(&self) -> Option<&MotionWrite> {
        self.written.as_ref()
    }
    /// Pre-write refusal and retained permit, if dispatch refused.
    pub fn refusal(&self) -> Option<&MotionRefusal> {
        self.refusal.as_ref()
    }
    /// Transfer the dispatch result and permit for independent reconciliation.
    pub fn take_written(&mut self) -> Option<MotionWrite> {
        self.written.take()
    }
    /// Transfer a refused committed permit for independent reconciliation.
    pub fn take_refusal(&mut self) -> Option<MotionRefusal> {
        self.refusal.take()
    }
}

/// Caller-owned facts for one management reply or request.
///
/// The journal remains authoritative. If a dispatch future is cancelled after
/// it takes the permit, `dispatch_started` remains true with no local outcome;
/// that uncertainty must be reconciled and must not trigger an automatic retry.
#[derive(Default)]
#[must_use = "retain the attempt and reconcile any committed effect"]
pub struct ManagementTrace {
    operation: Option<OperationId>,
    intent: Option<management::Intent>,
    dispatch_started: bool,
    pending_permit: Option<CommittedEffect>,
    written: Option<ManagementWrite>,
    refusal: Option<ManagementRefusal>,
}
impl fmt::Debug for ManagementTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagementTrace")
            .field("attempted", &self.operation.is_some())
            .field("intent_prepared", &self.intent.is_some())
            .field("dispatch_started", &self.dispatch_started)
            .field("pending_permit", &self.pending_permit.is_some())
            .field("local_outcome", &self.written.is_some())
            .field("refused", &self.refusal.is_some())
            .finish_non_exhaustive()
    }
}
impl ManagementTrace {
    /// Exact caller-supplied operation, if the attempt was initialized.
    pub fn operation(&self) -> Option<&OperationId> {
        self.operation.as_ref()
    }
    /// Inert management intent, if preparation reached that point.
    pub fn intent(&self) -> Option<management::Intent> {
        self.intent
    }
    /// Whether the one-use permit was handed to the dispatch future.
    pub fn dispatch_started(&self) -> bool {
        self.dispatch_started
    }
    /// Transfer a committed permit that was never handed to dispatch.
    pub fn take_pending_permit(&mut self) -> Option<CommittedEffect> {
        self.pending_permit.take()
    }
    /// Transfer the local write outcome and its committed permit.
    pub fn take_written(&mut self) -> Option<ManagementWrite> {
        self.written.take()
    }
    /// Transfer a pre-write refusal and its committed permit.
    pub fn take_refusal(&mut self) -> Option<ManagementRefusal> {
        self.refusal.take()
    }
    pub(crate) fn indeterminate_retirement(&self) -> Option<super::Retirement> {
        match self.written.as_ref() {
            Some(ManagementWrite::Indeterminate { controller, .. }) => Some(*controller),
            _ => None,
        }
    }
}

/// The management trace used for a single camera-requested clock reply.
pub type TimeSyncTrace = ManagementTrace;

/// Caller-owned facts for a startup stream-setting attempt.
#[derive(Default)]
#[must_use = "retain the attempt and reconcile any committed effect"]
pub struct StartupStreamTrace {
    operation: Option<OperationId>,
    intent: Option<intent::Intent>,
    dispatch_started: bool,
    pending_permit: Option<CommittedEffect>,
    written: Option<StreamWrite>,
    refusal: Option<StreamRefusal>,
}
impl fmt::Debug for StartupStreamTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StartupStreamTrace")
            .field("attempted", &self.operation.is_some())
            .field("intent_prepared", &self.intent.is_some())
            .field("dispatch_started", &self.dispatch_started)
            .field("pending_permit", &self.pending_permit.is_some())
            .field("local_outcome", &self.written.is_some())
            .field("refused", &self.refusal.is_some())
            .finish_non_exhaustive()
    }
}
impl StartupStreamTrace {
    /// Exact caller-supplied operation, when initialized.
    pub fn operation(&self) -> Option<&OperationId> {
        self.operation.as_ref()
    }
    /// Inert stream intent, when prepared.
    pub fn intent(&self) -> Option<intent::Intent> {
        self.intent
    }
    /// Whether the permit was handed to the dispatch future.
    pub fn dispatch_started(&self) -> bool {
        self.dispatch_started
    }
    /// Transfer a committed permit that was not handed to dispatch.
    pub fn take_pending_permit(&mut self) -> Option<CommittedEffect> {
        self.pending_permit.take()
    }
    /// Transfer a local write result and permit.
    pub fn take_written(&mut self) -> Option<StreamWrite> {
        self.written.take()
    }
    /// Transfer a pre-write refusal and permit.
    pub fn take_refusal(&mut self) -> Option<StreamRefusal> {
        self.refusal.take()
    }
}

/// Caller-owned management and stream outcomes for one startup attempt.
#[derive(Debug, Default)]
#[must_use = "retain startup effects for independent reconciliation"]
pub struct StartupProtocolTrace {
    attempted: bool,
    hello: ManagementTrace,
    agreement: ManagementTrace,
    clocks: Vec<ManagementTrace>,
    clock_limit: usize,
    stream: StartupStreamTrace,
    controller_retirement: Option<super::Retirement>,
}
impl StartupProtocolTrace {
    /// Whether this trace was bound to a startup attempt.
    pub fn attempted(&self) -> bool {
        self.attempted
    }
    /// Hello reply facts.
    pub fn hello(&self) -> &ManagementTrace {
        &self.hello
    }
    /// Hello reply facts and retained permit.
    pub fn hello_mut(&mut self) -> &mut ManagementTrace {
        &mut self.hello
    }
    /// Parameter-agreement request facts.
    pub fn agreement(&self) -> &ManagementTrace {
        &self.agreement
    }
    /// Parameter-agreement request facts and retained permit.
    pub fn agreement_mut(&mut self) -> &mut ManagementTrace {
        &mut self.agreement
    }
    /// Clock attempts in observed order, including any incomplete attempt.
    pub fn clocks(&self) -> &[ManagementTrace] {
        &self.clocks
    }
    /// Clock attempts and their retained permits.
    pub fn clocks_mut(&mut self) -> &mut [ManagementTrace] {
        &mut self.clocks
    }
    /// Stream-setting attempt and retained permit.
    pub fn stream(&self) -> &StartupStreamTrace {
        &self.stream
    }
    /// Stream-setting attempt and retained permit.
    pub fn stream_mut(&mut self) -> &mut StartupStreamTrace {
        &mut self.stream
    }
    /// Original controller retirement if the peer closed during startup.
    pub fn controller_retirement(&self) -> Option<super::Retirement> {
        self.controller_retirement
    }
    pub(crate) fn retain_controller_retirement(&mut self, retirement: super::Retirement) {
        self.controller_retirement = Some(retirement);
    }
    pub(crate) fn next_clock(&mut self) -> Result<&mut ManagementTrace, Error> {
        if self.clocks.len() == self.clock_limit {
            return Err(Error::Limit);
        }
        self.clocks.push(ManagementTrace::default());
        self.clocks.last_mut().ok_or(Error::Limit)
    }
}

/// Payload-free reason a conversation stopped. Retire and reconcile the session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Configuration, operation identities or session state is invalid.
    Configuration,
    /// Clock observation or runtime cancellation failed.
    Clock,
    /// The total deadline elapsed.
    Deadline,
    /// The bounded message or time-sync quota was exhausted.
    Limit,
    /// Caller-owned startup event custody is full; drain it before further reads.
    EventBackpressure,
    /// The session retired or a protocol step was refused.
    Session,
    /// The session retired with a payload-free observation of the reason.
    SessionRetired {
        /// The transport or protocol reason.
        reason: super::receive::Stop,
        /// State at the moment the session was retired.
        phase: super::Phase,
        /// Known rejected message type, without its contents.
        rejected_message: Option<super::RejectedMessage>,
    },
    /// A session operation was refused before it could complete.
    SessionDetail(super::receive::Error),
    /// Effect preparation, approval or commit was refused.
    Effect,
    /// A management or stream write may have occurred.
    Indeterminate,
    /// The camera returned an unexpected message for this stage.
    Unexpected,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UniFi conversation stopped: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Correlated settings reply; this is not proof of streaming or remote state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reply {
    /// Untrusted optional camera status code.
    pub status_code: Option<i64>,
    /// Untrusted optional camera success flag.
    pub success: Option<bool>,
    /// Number of time-sync requests answered during this conversation.
    pub time_syncs: usize,
}

/// A locally written stream request whose camera reply remains outstanding.
/// This does not prove that the camera applied the setting or sent media.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Dispatched {
    /// Number of time-sync requests answered before the stream write.
    pub time_syncs: usize,
}

enum StartResult {
    Dispatched(Dispatched),
    Reply(Reply),
}

/// Runtime resources and current policies for one owned conversation.
pub struct Owner<'a, 'scope, 'task> {
    /// The already-owned runtime context.
    pub cx: &'scope Cx,
    /// The enclosing canonical task.
    pub task: &'scope TaskCx<'task>,
    /// The same task-bound clock as the session transport.
    pub clock: MeteredClock<'scope, 'task>,
    /// The journal-backed effect coordinator.
    pub effects: &'a mut EffectCoordinator,
    /// The camera lease registry, shared with live authority checks.
    pub leases: &'a RefCell<LeaseRegistry>,
    /// Current independent approval policy.
    pub approval: &'a dyn Approval,
    /// Current identity, authorization and lease checks for management writes.
    pub management_authority: &'a dyn ManagementAuthority,
    /// Current identity, authorization and lease checks for stream writes.
    pub stream_authority: &'a dyn StreamAuthority,
    /// Bounded wall-clock provider.
    pub wall: &'a dyn WallClock,
}

impl Owner<'_, '_, '_> {
    fn permit(
        &mut self,
        operation: &OperationId,
        request: ContentDigest,
        preconditions: ContentDigest,
        resource: &str,
        fence: u64,
        prepare_grant: RuntimeGrant,
        commit_grant: RuntimeGrant,
    ) -> Result<CommittedEffect, Error> {
        let key = IdempotencyKey::parse(operation.as_str()).map_err(|_| Error::Configuration)?;
        let now = self.clock.now().map_err(|_| Error::Clock)?;
        let prepared = self
            .task
            .prepare_effect(
                self.cx,
                self.effects,
                &mut self.leases.borrow_mut(),
                PrepareSpec {
                    operation,
                    idempotency_key: key,
                    request_digest: request,
                    precondition_digest: preconditions,
                    resource,
                    fence,
                    prepare_grant,
                    commit_grant,
                    terminal_predicate: "independent observation or reconciliation",
                },
                now,
            )
            .map_err(|_| Error::Effect)?;
        let approval = self.approval.approve(&prepared).ok_or(Error::Effect)?;
        let now = self.clock.now().map_err(|_| Error::Clock)?;
        self.task
            .commit_effect(
                self.cx,
                self.effects,
                &mut self.leases.borrow_mut(),
                prepared,
                now,
                approval,
            )
            .map_err(|_| Error::Effect)
    }

    async fn send_management<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        session: &mut Session<'_, '_, IO>,
        operation: &OperationId,
        conditions: management::Preconditions,
        deadline: u64,
    ) -> Result<(), Error> {
        let intent = session
            .management_intent(conditions)
            .map_err(Error::SessionDetail)?;
        let permit = self.permit(
            operation,
            intent.request_digest(),
            intent.precondition_digest(),
            &intent.resource(),
            intent.fence(),
            RuntimeGrant::CameraManagementPrepare,
            RuntimeGrant::CameraManagementCommit,
        )?;
        let wait = self.remaining(deadline)?;
        match session
            .dispatch_management(intent, conditions, permit, self.management_authority, wait)
            .await
            .map_err(|_| Error::Effect)?
        {
            ManagementWrite::Written { .. } => Ok(()),
            ManagementWrite::Indeterminate { .. } => Err(Error::Indeterminate),
        }
    }

    async fn send_management_tracked<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        session: &mut Session<'_, '_, IO>,
        operation: &OperationId,
        conditions: management::Preconditions,
        deadline: u64,
        trace: &mut ManagementTrace,
    ) -> Result<(), Error> {
        if trace.operation.as_ref() != Some(operation) || trace.intent.is_some() {
            return Err(Error::Configuration);
        }
        let intent = session
            .management_intent(conditions)
            .map_err(Error::SessionDetail)?;
        trace.intent = Some(intent);
        let permit = self.permit(
            operation,
            intent.request_digest(),
            intent.precondition_digest(),
            &intent.resource(),
            intent.fence(),
            RuntimeGrant::CameraManagementPrepare,
            RuntimeGrant::CameraManagementCommit,
        )?;
        trace.pending_permit = Some(permit);
        let left = self.remaining(deadline)?;
        let permit = trace.pending_permit.take().ok_or(Error::Effect)?;
        trace.dispatch_started = true;
        match session
            .dispatch_management(intent, conditions, permit, self.management_authority, left)
            .await
        {
            Ok(result @ ManagementWrite::Written { .. }) => {
                trace.written = Some(result);
                Ok(())
            }
            Ok(result @ ManagementWrite::Indeterminate { .. }) => {
                trace.written = Some(result);
                Err(Error::Indeterminate)
            }
            Err(refusal) => {
                trace.refusal = Some(refusal);
                Err(Error::Effect)
            }
        }
    }

    fn remaining(&self, deadline: u64) -> Result<Duration, Error> {
        self.cx.checkpoint().map_err(|_| Error::Clock)?;
        let left = deadline
            .checked_sub(self.cx.now().as_nanos())
            .filter(|n| *n > 0)
            .ok_or(Error::Deadline)?;
        Ok(Duration::from_nanos(left))
    }

    /// Resolve one already-observed startup request while its source remains
    /// in the caller-owned inbox. The trace retains every returned permit.
    pub(crate) async fn answer_startup_event<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        session: &mut Session<'_, '_, IO>,
        conditions: management::Preconditions,
        replies: &StartupEventReplies<'_>,
        trace: &mut StartupEventTrace,
        wait: Duration,
    ) -> Result<(), Error> {
        if !trace.attempted
            || wait.is_zero()
            || wait > Duration::from_secs(30)
            || !self.clock.matches(self.task, self.cx)
            || !session.matches_clock(&self.clock)
        {
            return Err(Error::Configuration);
        }
        let operation = replies
            .operations
            .get(trace.attempts.len())
            .ok_or(Error::Limit)?;
        let frame = session
            .pending_startup_event()
            .map_err(Error::SessionDetail)?
            .ok_or(Error::EventBackpressure)?;
        let deadline = self
            .cx
            .now()
            .as_nanos()
            .checked_add(u64::try_from(wait.as_nanos()).map_err(|_| Error::Configuration)?)
            .ok_or(Error::Configuration)?;
        trace.attempts.push(StartupEventAttempt {
            operation: operation.clone(),
            source: frame.digest(),
            intent: None,
            dispatch_started: false,
            pending_permit: None,
            written: None,
            refusal: None,
        });
        let index = trace.attempts.len() - 1;
        let wall = self.wall.observe().ok_or(Error::Clock)?;
        session
            .prepare_event_reply(&frame, &wall.timestamp)
            .map_err(Error::SessionDetail)?;
        let intent = session
            .management_intent(conditions)
            .map_err(Error::SessionDetail)?;
        trace.attempts[index].intent = Some(intent);
        let permit = self.permit(
            operation,
            intent.request_digest(),
            intent.precondition_digest(),
            &intent.resource(),
            intent.fence(),
            RuntimeGrant::CameraManagementPrepare,
            RuntimeGrant::CameraManagementCommit,
        )?;
        trace.attempts[index].pending_permit = Some(permit);
        let left = self.remaining(deadline)?;
        let permit = trace.attempts[index]
            .pending_permit
            .take()
            .ok_or(Error::Effect)?;
        trace.attempts[index].dispatch_started = true;
        match session
            .dispatch_management(intent, conditions, permit, self.management_authority, left)
            .await
        {
            Ok(result @ ManagementWrite::Written { .. }) => {
                trace.attempts[index].written = Some(result);
                Ok(())
            }
            Ok(result @ ManagementWrite::Indeterminate { .. }) => {
                trace.attempts[index].written = Some(result);
                Err(Error::Indeterminate)
            }
            Err(refusal) => {
                trace.attempts[index].refusal = Some(refusal);
                Err(Error::Effect)
            }
        }
    }

    async fn observe<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        session: &mut Session<'_, '_, IO>,
        cfg: &Config<'_>,
        deadline: u64,
        slice: Duration,
        syncs: &mut usize,
        messages: &mut usize,
        event_replies: &mut Option<(&StartupEventReplies<'_>, &mut StartupEventTrace)>,
        protocol_trace: &mut Option<&mut StartupProtocolTrace>,
    ) -> Result<Option<Observation>, Error> {
        let wait = self.remaining(deadline)?.min(slice);
        match session.next(wait).await.map_err(Error::SessionDetail)? {
            Step::WaitElapsed => Ok(None),
            Step::StartupEventBackpressure => Err(Error::EventBackpressure),
            Step::EventReplyBackpressure => match event_replies.as_mut() {
                Some((replies, trace)) => {
                    let left = self.remaining(deadline)?;
                    self.answer_startup_event(session, cfg.management, replies, trace, left)
                        .await?;
                    Ok(None)
                }
                None => Err(Error::EventBackpressure),
            },
            // Event capture is enabled only after this startup owner is retired.
            Step::CameraEvent(_) | Step::StartupRequest(_) => Err(Error::Unexpected),
            Step::Retired { reason, controller } => {
                if let Some(trace) = protocol_trace.as_mut() {
                    trace.retain_controller_retirement(controller);
                }
                Err(Error::SessionRetired {
                    reason,
                    phase: controller.previous_phase,
                    rejected_message: controller.rejected_message,
                })
            }
            Step::Observation(observation) => {
                *messages += 1;
                if *messages > MAX_MESSAGES {
                    return Err(Error::Limit);
                }
                if observation == Observation::TimeSyncRequested {
                    let operation = cfg.time_sync.get(*syncs).ok_or(Error::Limit)?;
                    let trace = if let Some(protocol) = protocol_trace.as_mut() {
                        let trace = protocol.next_clock()?;
                        trace.operation = Some(operation.clone());
                        Some(trace)
                    } else {
                        None
                    };
                    let wall = self.wall.observe().ok_or(Error::Clock)?;
                    session
                        .prepare_time_sync(wall.unix_ms, &wall.timestamp)
                        .map_err(Error::SessionDetail)?;
                    if let Some(trace) = trace {
                        self.send_management_tracked(
                            session,
                            operation,
                            cfg.management,
                            deadline,
                            trace,
                        )
                        .await?;
                    } else {
                        self.send_management(session, operation, cfg.management, deadline)
                            .await?;
                    }
                    *syncs += 1;
                    Ok(None)
                } else {
                    Ok(Some(observation))
                }
            }
        }
    }

    /// Answer one already-observed camera time request using a distinct durable
    /// operation. A locally written reply does not prove the camera received it.
    pub async fn answer_time_sync<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        session: &mut Session<'_, '_, IO>,
        operation: &OperationId,
        conditions: management::Preconditions,
        wait: Duration,
    ) -> Result<(), Error> {
        if wait.is_zero()
            || wait > Duration::from_secs(30)
            || !self.clock.matches(self.task, self.cx)
            || !session.matches_clock(&self.clock)
        {
            return Err(Error::Configuration);
        }
        let nanos = u64::try_from(wait.as_nanos()).map_err(|_| Error::Configuration)?;
        let deadline = self
            .cx
            .now()
            .as_nanos()
            .checked_add(nanos)
            .ok_or(Error::Configuration)?;
        let wall = self.wall.observe().ok_or(Error::Clock)?;
        session
            .prepare_time_sync(wall.unix_ms, &wall.timestamp)
            .map_err(Error::SessionDetail)?;
        self.send_management(session, operation, conditions, deadline)
            .await
    }

    /// Answer one observed clock request while retaining the journaled permit
    /// and local dispatch outcome in caller-owned state. A cancelled future
    /// leaves this trace available to the caller for explicit reconciliation.
    pub async fn answer_time_sync_tracked<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        session: &mut Session<'_, '_, IO>,
        operation: &OperationId,
        conditions: management::Preconditions,
        wait: Duration,
        trace: &mut TimeSyncTrace,
    ) -> Result<(), Error> {
        if trace.operation.is_some()
            || wait.is_zero()
            || wait > Duration::from_secs(30)
            || !self.clock.matches(self.task, self.cx)
            || !session.matches_clock(&self.clock)
        {
            return Err(Error::Configuration);
        }
        trace.operation = Some(operation.clone());
        let nanos = u64::try_from(wait.as_nanos()).map_err(|_| Error::Configuration)?;
        let deadline = self
            .cx
            .now()
            .as_nanos()
            .checked_add(nanos)
            .ok_or(Error::Configuration)?;
        let wall = self.wall.observe().ok_or(Error::Clock)?;
        session
            .prepare_time_sync(wall.unix_ms, &wall.timestamp)
            .map_err(Error::SessionDetail)?;
        self.send_management_tracked(session, operation, conditions, deadline, trace)
            .await
    }

    /// Drive hello, delayed agreement and one stream request on an existing
    /// admitted session. All effects remain open after success. A successful
    /// reply is a protocol observation, not a stream or recording receipt.
    pub async fn start<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        session: &mut Session<'_, '_, IO>,
        cfg: &Config<'_>,
    ) -> Result<Reply, Error> {
        match self
            .start_inner(session, cfg, true, None, None, None)
            .await?
        {
            StartResult::Reply(reply) => Ok(reply),
            StartResult::Dispatched(_) => Err(Error::Configuration),
        }
    }

    /// Write the stream request and return before waiting for its reply.
    /// The caller must continue supervising the same session and reconcile
    /// all committed effects; the request may still fail or never be answered.
    pub async fn start_dispatched<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        session: &mut Session<'_, '_, IO>,
        cfg: &Config<'_>,
    ) -> Result<Dispatched, Error> {
        match self
            .start_inner(session, cfg, false, None, None, None)
            .await?
        {
            StartResult::Dispatched(dispatched) => Ok(dispatched),
            StartResult::Reply(_) => Err(Error::Configuration),
        }
    }

    /// Start with one explicitly authorized motion setting, retaining its
    /// permit and local outcome in the caller's trace. Media and later replies
    /// remain the caller's responsibility after the stream write.
    pub async fn start_dispatched_with_motion<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        session: &mut Session<'_, '_, IO>,
        cfg: &Config<'_>,
        motion: &StartupMotion<'_>,
        trace: &mut StartupMotionTrace,
    ) -> Result<Dispatched, Error> {
        match self
            .start_inner(session, cfg, false, Some((motion, trace)), None, None)
            .await?
        {
            StartResult::Dispatched(dispatched) => Ok(dispatched),
            StartResult::Reply(_) => Err(Error::Configuration),
        }
    }

    /// Start while optionally handling bounded startup event replies and motion.
    /// The event inbox and traces remain caller-owned on failure or cancellation.
    pub async fn start_dispatched_with_options<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        session: &mut Session<'_, '_, IO>,
        cfg: &Config<'_>,
        motion: Option<(&StartupMotion<'_>, &mut StartupMotionTrace)>,
        events: Option<(&StartupEventReplies<'_>, &mut StartupEventTrace)>,
    ) -> Result<Dispatched, Error> {
        match self
            .start_inner(session, cfg, false, motion, events, None)
            .await?
        {
            StartResult::Dispatched(dispatched) => Ok(dispatched),
            StartResult::Reply(_) => Err(Error::Configuration),
        }
    }

    /// Run startup and retain management and stream effects in caller-owned
    /// state, including when the future is dropped or returns an error.
    pub async fn start_with_protocol_trace<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        session: &mut Session<'_, '_, IO>,
        cfg: &Config<'_>,
        trace: &mut StartupProtocolTrace,
    ) -> Result<Reply, Error> {
        match self
            .start_inner(session, cfg, true, None, None, Some(trace))
            .await?
        {
            StartResult::Reply(reply) => Ok(reply),
            StartResult::Dispatched(_) => Err(Error::Configuration),
        }
    }

    /// Start without awaiting the stream reply, retaining all protocol effects.
    pub async fn start_dispatched_with_protocol_trace<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        session: &mut Session<'_, '_, IO>,
        cfg: &Config<'_>,
        motion: Option<(&StartupMotion<'_>, &mut StartupMotionTrace)>,
        events: Option<(&StartupEventReplies<'_>, &mut StartupEventTrace)>,
        trace: &mut StartupProtocolTrace,
    ) -> Result<Dispatched, Error> {
        match self
            .start_inner(session, cfg, false, motion, events, Some(trace))
            .await?
        {
            StartResult::Dispatched(dispatched) => Ok(dispatched),
            StartResult::Reply(_) => Err(Error::Configuration),
        }
    }

    async fn start_inner<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        session: &mut Session<'_, '_, IO>,
        cfg: &Config<'_>,
        wait_for_reply: bool,
        mut startup_motion: Option<(&StartupMotion<'_>, &mut StartupMotionTrace)>,
        mut event_replies: Option<(&StartupEventReplies<'_>, &mut StartupEventTrace)>,
        mut protocol_trace: Option<&mut StartupProtocolTrace>,
    ) -> Result<StartResult, Error> {
        if cfg.wait.is_zero()
            || cfg.wait > Duration::from_secs(30)
            || cfg.time_sync.len() > session.startup_time_sync_limit()
            || !self.clock.matches(self.task, self.cx)
            || !session.matches_clock(&self.clock)
            || cfg.management.camera != cfg.stream_conditions.camera
            || cfg.management.peer_admission != cfg.stream_conditions.peer_admission
            || cfg.management.lease_fence != cfg.stream_conditions.lease_fence
            || session.phase() != Phase::AwaitHello
        {
            return Err(Error::Configuration);
        }
        let mut ids = vec![cfg.hello, cfg.agreement, cfg.stream];
        ids.extend(cfg.time_sync.iter());
        if let Some((motion, trace)) = startup_motion.as_ref() {
            if trace.attempted
                || motion.conditions.camera != cfg.management.camera
                || motion.conditions.peer_admission != cfg.management.peer_admission
                || motion.conditions.session_generation != cfg.management.session_generation
                || motion.conditions.lease_fence != cfg.management.lease_fence
                || motion.conditions.validate().is_err()
            {
                return Err(Error::Configuration);
            }
            ids.push(motion.operation);
        }
        if let Some((events, trace)) = event_replies.as_mut() {
            if trace.attempted
                || !trace.attempts.is_empty()
                || events.operations.len() > super::MAX_EVENT_REPLIES
                || !session.has_startup_inbox()
            {
                return Err(Error::Configuration);
            }
            trace
                .attempts
                .try_reserve_exact(events.operations.len())
                .map_err(|_| Error::Limit)?;
            ids.extend(events.operations.iter());
        }
        if let Some(trace) = protocol_trace.as_mut() {
            if trace.attempted || !trace.clocks.is_empty() {
                return Err(Error::Configuration);
            }
            trace
                .clocks
                .try_reserve_exact(cfg.time_sync.len())
                .map_err(|_| Error::Limit)?;
            trace.clock_limit = cfg.time_sync.len();
        }
        for (i, id) in ids.iter().enumerate() {
            if ids[..i].contains(id) {
                return Err(Error::Configuration);
            }
        }
        if let Some((_, trace)) = startup_motion.as_mut() {
            trace.attempted = true;
        }
        if let Some((_, trace)) = event_replies.as_mut() {
            trace.attempted = true;
        }
        if let Some(trace) = protocol_trace.as_mut() {
            trace.attempted = true;
        }
        let nanos = u64::try_from(cfg.wait.as_nanos()).map_err(|_| Error::Configuration)?;
        let deadline = self
            .cx
            .now()
            .as_nanos()
            .checked_add(nanos)
            .ok_or(Error::Configuration)?;
        let (mut syncs, mut messages) = (0, 0);
        loop {
            match self
                .observe(
                    session,
                    cfg,
                    deadline,
                    cfg.wait,
                    &mut syncs,
                    &mut messages,
                    &mut event_replies,
                    &mut protocol_trace,
                )
                .await?
            {
                Some(Observation::Hello) => break,
                Some(Observation::Other) | None => (),
                Some(_) => return Err(Error::Unexpected),
            }
        }
        if let Some(trace) = protocol_trace.as_mut() {
            trace.hello.operation = Some(cfg.hello.clone());
        }
        let wall = self.wall.observe().ok_or(Error::Clock)?;
        session
            .prepare_hello(&wall.timestamp)
            .map_err(Error::SessionDetail)?;
        if let Some(trace) = protocol_trace.as_mut() {
            self.send_management_tracked(
                session,
                cfg.hello,
                cfg.management,
                deadline,
                &mut trace.hello,
            )
            .await?;
        } else {
            self.send_management(session, cfg.hello, cfg.management, deadline)
                .await?;
        }
        let sent = self.cx.now().as_nanos();
        loop {
            let elapsed = self
                .cx
                .now()
                .as_nanos()
                .checked_sub(sent)
                .ok_or(Error::Clock)?;
            if elapsed >= AGREEMENT_DELAY_NS {
                break;
            }
            let slice = Duration::from_nanos(AGREEMENT_DELAY_NS - elapsed);
            match self
                .observe(
                    session,
                    cfg,
                    deadline,
                    slice,
                    &mut syncs,
                    &mut messages,
                    &mut event_replies,
                    &mut protocol_trace,
                )
                .await?
            {
                Some(Observation::Other) | None => (),
                Some(_) => return Err(Error::Unexpected),
            }
        }
        let elapsed = self
            .cx
            .now()
            .as_nanos()
            .checked_sub(sent)
            .ok_or(Error::Clock)?;
        if let Some(trace) = protocol_trace.as_mut() {
            trace.agreement.operation = Some(cfg.agreement.clone());
        }
        let wall = self.wall.observe().ok_or(Error::Clock)?;
        session
            .prepare_agreement(&wall.timestamp, elapsed)
            .map_err(Error::SessionDetail)?;
        if let Some(trace) = protocol_trace.as_mut() {
            self.send_management_tracked(
                session,
                cfg.agreement,
                cfg.management,
                deadline,
                &mut trace.agreement,
            )
            .await?;
        } else {
            self.send_management(session, cfg.agreement, cfg.management, deadline)
                .await?;
        }
        loop {
            match self
                .observe(
                    session,
                    cfg,
                    deadline,
                    cfg.wait,
                    &mut syncs,
                    &mut messages,
                    &mut event_replies,
                    &mut protocol_trace,
                )
                .await?
            {
                Some(Observation::AgreementReply) => break,
                Some(Observation::Other) | None => (),
                Some(_) => return Err(Error::Unexpected),
            }
        }
        if let Some((motion, trace)) = startup_motion.as_mut() {
            let wall = self.wall.observe().ok_or(Error::Clock)?;
            let intent = session
                .prepare_motion(motion.enabled, &wall.timestamp, motion.conditions)
                .map_err(Error::SessionDetail)?;
            trace.intent = Some(intent);
            let permit = self.permit(
                motion.operation,
                intent.request_digest(),
                intent.precondition_digest(),
                &intent.resource(),
                intent.fence(),
                RuntimeGrant::CameraSettingPrepare,
                RuntimeGrant::CameraSettingCommit,
            )?;
            trace.pending_permit = Some(permit);
            let wait = self.remaining(deadline)?;
            let permit = trace.pending_permit.take().ok_or(Error::Effect)?;
            trace.dispatch_started = true;
            match session
                .dispatch_motion(intent, motion.conditions, permit, motion.authority, wait)
                .await
            {
                Ok(result @ MotionWrite::Written { .. }) => trace.written = Some(result),
                Ok(result @ MotionWrite::Indeterminate { .. }) => {
                    trace.written = Some(result);
                    return Err(Error::Indeterminate);
                }
                Err(refusal) => {
                    trace.refusal = Some(refusal);
                    return Err(Error::Effect);
                }
            }
        }
        if let Some(trace) = protocol_trace.as_mut() {
            trace.stream.operation = Some(cfg.stream.clone());
        }
        let wall = self.wall.observe().ok_or(Error::Clock)?;
        let intent = session
            .prepare_stream_start(cfg.request, &wall.timestamp, cfg.stream_conditions)
            .map_err(Error::SessionDetail)?;
        if let Some(trace) = protocol_trace.as_mut() {
            trace.stream.intent = Some(intent);
        }
        let permit = self.permit(
            cfg.stream,
            intent.request_digest(),
            intent.precondition_digest(),
            &intent.resource(),
            intent.fence(),
            RuntimeGrant::CameraSettingPrepare,
            RuntimeGrant::CameraSettingCommit,
        )?;
        if let Some(trace) = protocol_trace.as_mut() {
            trace.stream.pending_permit = Some(permit);
            let wait = self.remaining(deadline)?;
            let permit = trace.stream.pending_permit.take().ok_or(Error::Effect)?;
            trace.stream.dispatch_started = true;
            match session
                .dispatch_stream(
                    intent,
                    cfg.stream_conditions,
                    permit,
                    self.stream_authority,
                    wait,
                )
                .await
            {
                Ok(result @ StreamWrite::Written { .. }) => trace.stream.written = Some(result),
                Ok(result @ StreamWrite::Indeterminate { .. }) => {
                    trace.stream.written = Some(result);
                    return Err(Error::Indeterminate);
                }
                Err(refusal) => {
                    trace.stream.refusal = Some(refusal);
                    return Err(Error::Effect);
                }
            }
        } else {
            let wait = self.remaining(deadline)?;
            match session
                .dispatch_stream(
                    intent,
                    cfg.stream_conditions,
                    permit,
                    self.stream_authority,
                    wait,
                )
                .await
                .map_err(|_| Error::Effect)?
            {
                StreamWrite::Written { .. } => (),
                StreamWrite::Indeterminate { .. } => return Err(Error::Indeterminate),
            }
        }
        if !wait_for_reply {
            return Ok(StartResult::Dispatched(Dispatched { time_syncs: syncs }));
        }
        loop {
            match self
                .observe(
                    session,
                    cfg,
                    deadline,
                    cfg.wait,
                    &mut syncs,
                    &mut messages,
                    &mut event_replies,
                    &mut protocol_trace,
                )
                .await?
            {
                Some(Observation::StreamSettingsReply {
                    status_code,
                    success,
                    ..
                }) => {
                    return Ok(StartResult::Reply(Reply {
                        status_code,
                        success,
                        time_syncs: syncs,
                    }));
                }
                Some(Observation::Other) | None => (),
                Some(_) => return Err(Error::Unexpected),
            }
        }
    }
}
