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
    receive::{ManagementAuthority, ManagementWrite, Session, Step, StreamAuthority, StreamWrite},
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

const MAX_SYNC: usize = 8;
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

    fn remaining(&self, deadline: u64) -> Result<Duration, Error> {
        self.cx.checkpoint().map_err(|_| Error::Clock)?;
        let left = deadline
            .checked_sub(self.cx.now().as_nanos())
            .filter(|n| *n > 0)
            .ok_or(Error::Deadline)?;
        Ok(Duration::from_nanos(left))
    }

    async fn observe<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        session: &mut Session<'_, '_, IO>,
        cfg: &Config<'_>,
        deadline: u64,
        slice: Duration,
        syncs: &mut usize,
        messages: &mut usize,
    ) -> Result<Option<Observation>, Error> {
        let wait = self.remaining(deadline)?.min(slice);
        match session.next(wait).await.map_err(Error::SessionDetail)? {
            Step::WaitElapsed => Ok(None),
            Step::Retired { reason, controller } => Err(Error::SessionRetired {
                reason,
                phase: controller.previous_phase,
                rejected_message: controller.rejected_message,
            }),
            Step::Observation(observation) => {
                *messages += 1;
                if *messages > MAX_MESSAGES {
                    return Err(Error::Limit);
                }
                if observation == Observation::TimeSyncRequested {
                    let operation = cfg.time_sync.get(*syncs).ok_or(Error::Limit)?;
                    let wall = self.wall.observe().ok_or(Error::Clock)?;
                    session
                        .prepare_time_sync(wall.unix_ms, &wall.timestamp)
                        .map_err(Error::SessionDetail)?;
                    self.send_management(session, operation, cfg.management, deadline)
                        .await?;
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

    /// Drive hello, delayed agreement and one stream request on an existing
    /// admitted session. All effects remain open after success. A successful
    /// reply is a protocol observation, not a stream or recording receipt.
    pub async fn start<IO: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        session: &mut Session<'_, '_, IO>,
        cfg: &Config<'_>,
    ) -> Result<Reply, Error> {
        if cfg.wait.is_zero()
            || cfg.wait > Duration::from_secs(30)
            || cfg.time_sync.len() > MAX_SYNC
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
        for (i, id) in ids.iter().enumerate() {
            if ids[..i].contains(id) {
                return Err(Error::Configuration);
            }
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
                .observe(session, cfg, deadline, cfg.wait, &mut syncs, &mut messages)
                .await?
            {
                Some(Observation::Hello) => break,
                Some(Observation::Other) | None => (),
                Some(_) => return Err(Error::Unexpected),
            }
        }
        let wall = self.wall.observe().ok_or(Error::Clock)?;
        session
            .prepare_hello(&wall.timestamp)
            .map_err(Error::SessionDetail)?;
        self.send_management(session, cfg.hello, cfg.management, deadline)
            .await?;
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
                .observe(session, cfg, deadline, slice, &mut syncs, &mut messages)
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
        let wall = self.wall.observe().ok_or(Error::Clock)?;
        session
            .prepare_agreement(&wall.timestamp, elapsed)
            .map_err(Error::SessionDetail)?;
        self.send_management(session, cfg.agreement, cfg.management, deadline)
            .await?;
        loop {
            match self
                .observe(session, cfg, deadline, cfg.wait, &mut syncs, &mut messages)
                .await?
            {
                Some(Observation::AgreementReply) => break,
                Some(Observation::Other) | None => (),
                Some(_) => return Err(Error::Unexpected),
            }
        }
        let wall = self.wall.observe().ok_or(Error::Clock)?;
        let intent = session
            .prepare_stream_start(cfg.request, &wall.timestamp, cfg.stream_conditions)
            .map_err(Error::SessionDetail)?;
        let permit = self.permit(
            cfg.stream,
            intent.request_digest(),
            intent.precondition_digest(),
            &intent.resource(),
            intent.fence(),
            RuntimeGrant::CameraSettingPrepare,
            RuntimeGrant::CameraSettingCommit,
        )?;
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
        loop {
            match self
                .observe(session, cfg, deadline, cfg.wait, &mut syncs, &mut messages)
                .await?
            {
                Some(Observation::StreamSettingsReply {
                    status_code,
                    success,
                    ..
                }) => {
                    return Ok(Reply {
                        status_code,
                        success,
                        time_syncs: syncs,
                    });
                }
                Some(Observation::Other) | None => (),
                Some(_) => return Err(Error::Unexpected),
            }
        }
    }
}
