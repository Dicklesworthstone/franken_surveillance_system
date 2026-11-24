#![forbid(unsafe_code)]
//! Bounded caller-driven supervision of one HTTP-started managed A/V recorder.
//!
//! Each step returns its exact event, including publication receipts. EOF is
//! the only automatic reconnect trigger. The caller must retain events, drain
//! the previous-generation boundary, reconcile camera effects, and supervise
//! the returned owners on shutdown. This is not a crash-restart service,
//! physical-device authentication, or a claim of uninterrupted coverage.

use std::{collections::VecDeque, future::Future, pin::Pin, time::Duration};

use asupersync::Cx;
use fss_container::flv_avc::SourceKey;
use fss_core::{BudgetVector, ContentDigest};
use fss_runtime::execution::TaskCx;

use super::{
    media_av_archive as archive, media_av_managed as managed, media_av_reconnect as reconnect,
    media_av_startup as startup, media_reaccept,
};
use crate::unifi_direct::{
    av_owned_sink, av_recovered_startup, listener, media_reconnect, metered::MeteredClock,
    pipeline, source_coordinator::ArchiveAdmission,
};

/// Finite policy for each reconnect; it does not authorize a camera write.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Successor connection and media bounds.
    pub successor: reconnect::SuccessorConfig,
    /// Maximum accepts for each EOF transition, from 1 through 128.
    pub attempts_per_eof: usize,
    /// Caller-selected retention scope of the settled archives.
    pub retention: ContentDigest,
    /// Successor A/V bootstrap policy.
    pub bootstrap: av_owned_sink::BootstrapPolicy,
    /// Optional audio configuration without source evidence.
    pub supplied_unverified_audio: Option<[u8; 2]>,
}

/// Old source facts and muxer retained after the archives were reused.
#[must_use = "retain and reconcile the previous source and effect"]
pub struct Boundary {
    /// Previous connection facts and its finished muxer.
    pub previous: reconnect::ReusedPrevious,
    /// Any original tails not transferred by the reconnect owner.
    pub retired: VecDeque<media_reconnect::Retired>,
    /// Reserved accept attempts used in this transition.
    pub attempts: usize,
    /// The original per-transition attempt bound.
    pub max_attempts: usize,
    /// Most recently reserved source claim.
    pub last: Option<SourceKey>,
}

/// Exact active or stopped owner. Refused phases are never retried implicitly.
#[must_use = "retain and reconcile the current phase"]
pub enum Phase<'scope, 'task, 'policy> {
    /// Managed recording, including its finite rollover plan.
    Recording(Box<managed::Managed>),
    /// Publication of the old tail or bounded successor acceptance.
    Reconnecting(Box<reconnect::Transition<'scope, 'task, 'policy>>),
    /// Rollover custody is held while its blocking check is drained.
    Verifying(Box<reconnect::ReuseVerification<'scope, 'task, 'policy>>),
    /// Bootstrap of an accepted successor.
    Starting(Box<startup::Driver>),
    /// The stopped original recording could not enter reconnect.
    BeginStopped(Box<reconnect::BeginRefusal<'scope, 'task, 'policy>>),
    /// The recording was detached but its listener was unexpectedly absent.
    Detached(Box<archive::Parts>),
    /// Archive reuse refused while retaining its exact owners.
    ReuseStopped(Box<reconnect::ReuseRefusal<'scope, 'task, 'policy>>),
    /// Verified reuse could not be completed; its exact owners remain retained.
    VerificationStopped(Box<reconnect::VerifyFinishRefusal<'scope, 'task, 'policy>>),
    /// Bootstrap-to-recording attachment refused with its original owners.
    StartupStopped(Box<startup::TransitionRefusal>),
    /// The successor recorder could not reattach to the parked manager.
    ResumeStopped(Box<archive::Driver>),
}

/// Every observable step; payloads and receipts belong to the caller.
#[must_use]
pub enum Step {
    /// Task, runtime, clock or wait did not match; no work was polled.
    Configuration,
    /// One managed recording event.
    Recording(Box<managed::Step>),
    /// A recorded EOF was transferred to the reconnect owner.
    ReconnectStarted,
    /// The prior boundary must be taken before another reconnect.
    BoundaryPending,
    /// The stopped managed recording could not be parked; it remains owned.
    ParkStopped,
    /// Reconnect setup refused; the exact refusal remains in the phase.
    BeginStopped,
    /// An exact old-tail publication or successor-accept event.
    Reconnecting(Box<reconnect::AutoStep>),
    /// A reconnect refusal or interrupted wait needs caller action.
    ReconnectBlocked,
    /// Archives were reused, and the previous boundary is retained.
    ArchivesReused,
    /// Existing rollover custody requires a bounded blocking check.
    VerificationPrepared,
    /// One exact custody verification decision or completion.
    Verifying(Box<reconnect::VerifyStep>),
    /// Verification failed, was canceled, or needs explicit retry.
    VerificationBlocked,
    /// Verified custody could not be transferred to bootstrap.
    VerificationStopped,
    /// Reuse refused; the exact refusal remains in the phase.
    ReuseStopped,
    /// One exact bootstrap event.
    Starting(Box<startup::Step>),
    /// Bootstrap stopped and requires caller reconciliation.
    StartupBlocked,
    /// Bootstrap could not become an archive recorder.
    StartupStopped,
    /// The successor could not be reattached to its parked manager.
    ResumeStopped,
    /// The successor is attached and managed recording can continue.
    Resumed,
    /// A stopped phase or an internal ownership inconsistency needs recovery.
    Stopped,
}

/// All retained owners, including unjoined workers, returned to the caller.
#[must_use = "drain and reconcile every retained owner"]
pub struct Parts<'scope, 'task, 'policy> {
    /// Current recording or exact stopped transition.
    pub phase: Option<Phase<'scope, 'task, 'policy>>,
    /// Listener when not held by the reconnect phase or a refusal.
    pub listener: Option<listener::Listener<'scope, 'task, 'policy>>,
    /// Original management state while disconnected.
    pub parked: Option<Box<managed::Parked<'scope, 'task>>>,
    /// Previous generation awaiting transfer to the caller.
    pub boundary: Option<Box<Boundary>>,
    /// Exact caller-selected policy.
    pub config: Config,
    /// Original runtime-to-task clock mapping.
    pub clock: MeteredClock<'scope, 'task>,
    /// An EOF event was returned to the caller.
    pub eof_seen: bool,
    /// A successor was accepted and its readiness was returned.
    pub accepted_ready: bool,
    /// Bootstrap readiness was returned to the caller.
    pub bootstrap_ready: bool,
    /// A successful custody-check completion was returned to the caller.
    pub verification_ready: bool,
    /// Custody verification cannot continue without explicit action.
    pub verification_blocked: bool,
    /// A reconnect decision needs explicit acknowledgment.
    pub reconnect_blocked: bool,
    /// The blocked result was a listener refusal eligible for explicit retry.
    pub reconnect_retryable: bool,
    /// Startup requires explicit recovery.
    pub startup_blocked: bool,
    /// An ownership transfer was refused.
    pub park_stopped: bool,
}

impl ReconnectingRecovery {
    /// Fence new work and request cancellation of retained workers.
    /// A cancellation request is not a completed drain or effect settlement.
    pub fn abort(&mut self) {
        self.tail.abort();
        self.previous.av.abort();
        if let Some(parked) = self.parked.as_mut() {
            parked.abort();
        }
    }

    /// Join the original tail worker and retain the exact completion.
    /// Repeated calls do not consume an already retained completion.
    pub async fn join_tail(&mut self) -> bool {
        if self.tail_completion.is_some() {
            return true;
        }
        if let Some(done) = self.tail.join().await {
            self.tail_completion = Some(done);
            true
        } else {
            false
        }
    }

    /// Join the predecessor A/V worker and retain the exact completion.
    /// Repeated calls do not consume an already retained completion.
    pub async fn join_previous(&mut self) -> bool {
        if self.previous_completion.is_some() {
            return true;
        }
        if let Some(done) = self.previous.av.join().await {
            self.previous_completion = Some(done);
            true
        } else {
            false
        }
    }
}

/// One owner, with no background work beyond its retained worker handles.
#[must_use = "recover and reconcile all owners"]
pub struct Supervisor<'scope, 'task, 'policy> {
    parts: Parts<'scope, 'task, 'policy>,
}

/// Scoped bindings returned when a reconnecting supervisor is detached.
#[must_use = "account for the listener and its original clock bindings"]
pub struct ReconnectingScope<'scope, 'task, 'policy> {
    /// Original bound listener, which may still hold accepted socket state.
    pub listener: listener::Listener<'scope, 'task, 'policy>,
    /// Supervisor clock mapping.
    pub clock: MeteredClock<'scope, 'task>,
    /// Parked manager's original clock mapping, when parked state exists.
    pub parked_clock: Option<MeteredClock<'scope, 'task>>,
}

/// Listener-independent owners and exact decision state from reconnection.
/// This is volatile recovery custody and does not authorize a camera effect.
#[must_use = "drain all workers, retain source custody and reconcile the effect"]
pub struct ReconnectingRecovery {
    /// Original effect, active candidate and source tails.
    pub bridge: media_reaccept::Detached,
    /// Old source archive worker and its remaining plan.
    pub tail: crate::unifi_direct::retirement_source::Driver,
    /// Previous A/V worker and camera/source claims.
    pub previous: reconnect::Previous,
    /// Whether tail completion was observed.
    pub tail_finished: bool,
    /// Whether the tail was fenced.
    pub tail_fenced: bool,
    /// Parked generation plan, allowances and workers, if present.
    pub parked: Option<Box<managed::DetachedParked>>,
    /// Previous generation pending transfer, if present.
    pub boundary: Option<Box<Boundary>>,
    /// Original finite reconnect policy.
    pub config: Config,
    /// An EOF event was returned to the caller.
    pub eof_seen: bool,
    /// An accepted successor was reported ready.
    pub accepted_ready: bool,
    /// Bootstrap readiness was reported.
    pub bootstrap_ready: bool,
    /// Custody verification readiness was reported.
    pub verification_ready: bool,
    /// Custody verification requires caller action.
    pub verification_blocked: bool,
    /// Reconnect requires caller action.
    pub reconnect_blocked: bool,
    /// The blocked result was eligible for explicit retry.
    pub reconnect_retryable: bool,
    /// Startup requires explicit recovery.
    pub startup_blocked: bool,
    /// A management ownership transfer was refused.
    pub park_stopped: bool,
    /// Joined old-tail publication, retained for reconciliation.
    pub tail_completion: Option<crate::unifi_direct::source_worker::Completion>,
    /// Joined predecessor A/V publication, retained for reconciliation.
    pub previous_completion: Option<crate::unifi_direct::av_worker::UnknownTimeCompletion>,
}

#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn recording_step<'a, 'scope: 'a, 'task: 'scope>(
    manager: &'a mut managed::Managed,
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    wait: Duration,
    source: ArchiveAdmission<'a>,
    av: ArchiveAdmission<'a>,
    supply_cost: &'a BudgetVector,
    rollover: ArchiveAdmission<'a>,
) -> Pin<Box<dyn Future<Output = managed::Step> + 'a>> {
    Box::pin(manager.step(task, cx, clock, wait, source, av, supply_cost, rollover))
}

#[inline(never)]
fn reconnect_step<'a, 'scope: 'a, 'task: 'scope, 'policy: 'a>(
    transition: &'a mut reconnect::Transition<'scope, 'task, 'policy>,
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    source: ArchiveAdmission<'a>,
    config: reconnect::SuccessorConfig,
) -> Pin<Box<dyn Future<Output = reconnect::AutoStep> + 'a>> {
    Box::pin(transition.step_auto(task, cx, clock, source, config))
}

#[inline(never)]
fn verify_step<'a, 'scope: 'a, 'task: 'scope, 'policy: 'a>(
    verification: &'a mut reconnect::ReuseVerification<'scope, 'task, 'policy>,
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    wait: Duration,
    admission: ArchiveAdmission<'a>,
) -> Pin<Box<dyn Future<Output = reconnect::VerifyStep> + 'a>> {
    Box::pin(verification.step(task, cx, clock, wait, admission))
}

#[inline(never)]
fn startup_step<'a, 'scope: 'a, 'task: 'scope>(
    driver: &'a mut startup::Driver,
    task: &'scope TaskCx<'task>,
    cx: &'scope Cx,
    clock: MeteredClock<'scope, 'task>,
    wait: Duration,
    source: ArchiveAdmission<'a>,
) -> Pin<Box<dyn Future<Output = startup::Step> + 'a>> {
    Box::pin(driver.step(task, cx, clock, wait, source))
}

impl<'scope, 'task, 'policy> Supervisor<'scope, 'task, 'policy> {
    /// Bind a live managed recorder to its original listener and clock.
    /// On refusal both original owners are returned unchanged.
    #[allow(clippy::result_large_err)]
    pub fn new(
        manager: Box<managed::Managed>,
        listener: listener::Listener<'scope, 'task, 'policy>,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        config: Config,
    ) -> Result<
        Box<Self>,
        (
            Box<managed::Managed>,
            listener::Listener<'scope, 'task, 'policy>,
        ),
    > {
        if !(1..=128).contains(&config.attempts_per_eof)
            || !listener.matches_context(task, cx, clock)
            || !manager.matches_listener(&listener)
        {
            return Err((manager, listener));
        }
        Ok(Box::new(Self {
            parts: Parts {
                phase: Some(Phase::Recording(manager)),
                listener: Some(listener),
                parked: None,
                boundary: None,
                config,
                clock,
                eof_seen: false,
                accepted_ready: false,
                bootstrap_ready: false,
                verification_ready: false,
                verification_blocked: false,
                reconnect_blocked: false,
                reconnect_retryable: false,
                startup_blocked: false,
                park_stopped: false,
            },
        }))
    }

    /// Transfer the old source facts before allowing the next EOF transition.
    pub fn take_boundary(&mut self) -> Option<Box<Boundary>> {
        self.parts.boundary.take()
    }

    /// Acknowledge a canceled accept wait and its reserved connection claim.
    pub fn acknowledge_interrupted(&mut self) -> Option<SourceKey> {
        let Some(Phase::Reconnecting(transition)) = self.parts.phase.as_mut() else {
            return None;
        };
        let key = transition.acknowledge_interrupted()?;
        self.parts.reconnect_blocked = false;
        self.parts.reconnect_retryable = false;
        Some(key)
    }

    /// Explicitly permit another bounded decision after an accept refusal.
    /// Interrupted accepts must first use `acknowledge_interrupted`.
    pub fn authorize_reconnect_retry(&mut self) -> bool {
        if self.parts.reconnect_blocked
            && self.parts.reconnect_retryable
            && matches!(self.parts.phase, Some(Phase::Reconnecting(_)))
        {
            self.parts.reconnect_blocked = false;
            self.parts.reconnect_retryable = false;
            true
        } else {
            false
        }
    }

    /// Permit a fresh custody-worker admission after a definite start refusal.
    pub fn authorize_verification_retry(&mut self) -> bool {
        let Some(Phase::Verifying(verification)) = self.parts.phase.as_mut() else {
            return false;
        };
        if self.parts.verification_blocked && verification.authorize_start_retry() {
            self.parts.verification_blocked = false;
            true
        } else {
            false
        }
    }

    /// Transfer the full phase and all retained owners without joining work.
    pub fn into_parts(self: Box<Self>) -> Parts<'scope, 'task, 'policy> {
        self.parts
    }

    /// Separate a reconnecting phase from its scoped listener and clocks.
    /// Other phases or inconsistent separate listener ownership are refused
    /// with the original supervisor intact. No work is drained or resumed.
    pub fn detach_reconnecting(
        self: Box<Self>,
    ) -> Result<
        (
            ReconnectingScope<'scope, 'task, 'policy>,
            Box<ReconnectingRecovery>,
        ),
        Box<Self>,
    > {
        if self.parts.listener.is_some()
            || !matches!(&self.parts.phase, Some(Phase::Reconnecting(_)))
        {
            return Err(self);
        }
        let Parts {
            phase,
            listener: _,
            parked,
            boundary,
            config,
            clock,
            eof_seen,
            accepted_ready,
            bootstrap_ready,
            verification_ready,
            verification_blocked,
            reconnect_blocked,
            reconnect_retryable,
            startup_blocked,
            park_stopped,
        } = self.parts;
        let Some(Phase::Reconnecting(transition)) = phase else {
            unreachable!("phase checked above")
        };
        let reconnect::Parts {
            bridge,
            tail,
            previous,
            tail_finished,
            tail_fenced,
        } = (*transition).into_parts();
        let (listener, bridge) = bridge.into_parts().split_listener();
        let (parked_clock, parked) = match parked {
            Some(parked) => {
                let (clock, detached) = parked.split_scope();
                (Some(clock), Some(detached))
            }
            None => (None, None),
        };
        Ok((
            ReconnectingScope {
                listener,
                clock,
                parked_clock,
            },
            Box::new(ReconnectingRecovery {
                bridge,
                tail,
                previous,
                tail_finished,
                tail_fenced,
                parked,
                boundary,
                config,
                eof_seen,
                accepted_ready,
                bootstrap_ready,
                verification_ready,
                verification_blocked,
                reconnect_blocked,
                reconnect_retryable,
                startup_blocked,
                park_stopped,
                tail_completion: None,
                previous_completion: None,
            }),
        ))
    }

    /// Drive one bounded decision. Every returned event must be retained.
    #[allow(clippy::too_many_arguments)]
    pub async fn step(
        &mut self,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        wait: Duration,
        source: ArchiveAdmission<'_>,
        av: ArchiveAdmission<'_>,
        supply_cost: &BudgetVector,
        rollover: ArchiveAdmission<'_>,
    ) -> Step {
        if wait.is_zero()
            || wait > Duration::from_secs(30)
            || !clock.matches(task, cx)
            || !self.parts.clock.same_mapping(&clock)
        {
            return Step::Configuration;
        }
        if self.parts.park_stopped {
            return Step::ParkStopped;
        }
        match self.parts.phase.as_mut() {
            Some(Phase::Recording(manager)) if !self.parts.eof_seen => {
                let event = recording_step(
                    manager,
                    task,
                    cx,
                    clock,
                    wait,
                    source,
                    av,
                    supply_cost,
                    rollover,
                )
                .await;
                if matches!(
                    &event,
                    managed::Step::Recording(archive::AllowanceStep::Recording(
                        archive::Step::Media(pipeline::Step::Eof)
                    ))
                ) {
                    self.parts.eof_seen = true;
                }
                Step::Recording(Box::new(event))
            }
            Some(Phase::Recording(_)) => self.begin_reconnect(task, cx, clock),
            Some(Phase::Reconnecting(_)) if self.parts.reconnect_blocked => Step::ReconnectBlocked,
            Some(Phase::Reconnecting(_)) if self.parts.accepted_ready => self.finish_reuse(),
            Some(Phase::Reconnecting(transition)) => {
                let event = reconnect_step(
                    transition,
                    task,
                    cx,
                    clock,
                    source,
                    self.parts.config.successor,
                )
                .await;
                match &event {
                    reconnect::AutoStep::Ready(_) => self.parts.accepted_ready = true,
                    reconnect::AutoStep::Refused(reconnect::AutoError::Admission(
                        media_reconnect::Error::Listener(_),
                    )) => {
                        self.parts.reconnect_blocked = true;
                        self.parts.reconnect_retryable = true;
                    }
                    reconnect::AutoStep::Refused(_)
                    | reconnect::AutoStep::Interrupted
                    | reconnect::AutoStep::TailFenced => self.parts.reconnect_blocked = true,
                    _ => (),
                }
                Step::Reconnecting(Box::new(event))
            }
            Some(Phase::Verifying(_)) if self.parts.verification_blocked => {
                Step::VerificationBlocked
            }
            Some(Phase::Verifying(_)) if self.parts.verification_ready => {
                self.finish_verification()
            }
            Some(Phase::Verifying(verification)) => {
                let event = verify_step(verification, task, cx, clock, wait, av).await;
                match &event {
                    reconnect::VerifyStep::Ready => self.parts.verification_ready = true,
                    reconnect::VerifyStep::Completed(done)
                        if done.runtime.is_ok()
                            && matches!(&done.outcome, av_recovered_startup::Outcome::Verified) =>
                    {
                        self.parts.verification_ready = true
                    }
                    reconnect::VerifyStep::Completed(_)
                    | reconnect::VerifyStep::StartRefused(_)
                    | reconnect::VerifyStep::Stopped
                    | reconnect::VerifyStep::Configuration => {
                        self.parts.verification_blocked = true
                    }
                    _ => (),
                }
                Step::Verifying(Box::new(event))
            }
            Some(Phase::Starting(_)) if self.parts.startup_blocked => Step::StartupBlocked,
            Some(Phase::Starting(_)) if self.parts.bootstrap_ready => {
                self.finish_startup(task, cx, clock)
            }
            Some(Phase::Starting(driver)) => {
                let event = startup_step(driver, task, cx, clock, wait, source).await;
                match &event {
                    startup::Step::Ready => self.parts.bootstrap_ready = true,
                    startup::Step::SourceRefused { .. }
                    | startup::Step::StartRefused(_)
                    | startup::Step::SourceRetryRequired
                    | startup::Step::SourceUnavailable
                    | startup::Step::Forward { .. }
                    | startup::Step::Eof
                    | startup::Step::LimitReached
                    | startup::Step::MediaError(_)
                    | startup::Step::Fenced
                    | startup::Step::Configuration
                    | startup::Step::Halted => self.parts.startup_blocked = true,
                    _ => (),
                }
                Step::Starting(Box::new(event))
            }
            _ => Step::Stopped,
        }
    }

    #[inline(never)]
    fn begin_reconnect(
        &mut self,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
    ) -> Step {
        if self.parts.boundary.is_some() {
            return Step::BoundaryPending;
        }
        let manager = match self.parts.phase.take() {
            Some(Phase::Recording(manager)) => manager,
            other => {
                self.parts.phase = other;
                return Step::Stopped;
            }
        };
        let (parked, recording) = match manager.park_for_reconnect(task, cx, clock) {
            Ok(owners) => owners,
            Err(manager) => {
                self.parts.phase = Some(Phase::Recording(manager));
                self.parts.park_stopped = true;
                return Step::ParkStopped;
            }
        };
        let Some(listener) = self.parts.listener.take() else {
            self.parts.parked = Some(parked);
            self.parts.phase = Some(Phase::Detached(recording));
            return Step::Stopped;
        };
        self.parts.parked = Some(parked);
        match reconnect::Transition::new(*recording, listener, self.parts.config.attempts_per_eof) {
            Ok(mut transition) => {
                // A long unfinished GOP can contain hundreds of source
                // records. Publish bounded batches before attempting reuse;
                // one root per record can exhaust an otherwise empty store.
                if !transition.enable_batching(256, 1024 * 1024) {
                    self.parts.phase = Some(Phase::Reconnecting(Box::new(transition)));
                    self.parts.reconnect_blocked = true;
                    self.parts.reconnect_retryable = false;
                    return Step::ReconnectBlocked;
                }
                self.parts.phase = Some(Phase::Reconnecting(Box::new(transition)));
                Step::ReconnectStarted
            }
            Err(refusal) => {
                self.parts.phase = Some(Phase::BeginStopped(Box::new(refusal)));
                Step::BeginStopped
            }
        }
    }

    #[inline(never)]
    fn finish_reuse(&mut self) -> Step {
        let transition = match self.parts.phase.take() {
            Some(Phase::Reconnecting(transition)) => transition,
            other => {
                self.parts.phase = other;
                return Step::Stopped;
            }
        };
        match transition.begin_reusing(
            self.parts.config.retention,
            self.parts.config.bootstrap,
            self.parts.config.supplied_unverified_audio,
        ) {
            Err(refusal) => {
                self.parts.phase = Some(Phase::ReuseStopped(refusal));
                Step::ReuseStopped
            }
            Ok(reconnect::BeginReuse::Ready(ready)) => self.attach_reused(ready),
            Ok(reconnect::BeginReuse::Verify(verification)) => {
                self.parts.phase = Some(Phase::Verifying(verification));
                self.parts.accepted_ready = false;
                Step::VerificationPrepared
            }
        }
    }

    #[inline(never)]
    fn finish_verification(&mut self) -> Step {
        let verification = match self.parts.phase.take() {
            Some(Phase::Verifying(verification)) => verification,
            other => {
                self.parts.phase = other;
                return Step::Stopped;
            }
        };
        match verification.finish(
            self.parts.config.retention,
            self.parts.config.bootstrap,
            self.parts.config.supplied_unverified_audio,
        ) {
            Ok(ready) => {
                self.parts.verification_ready = false;
                self.attach_reused(ready)
            }
            Err(refusal) => {
                self.parts.phase = Some(Phase::VerificationStopped(refusal));
                Step::VerificationStopped
            }
        }
    }

    #[inline(never)]
    fn attach_reused(
        &mut self,
        ready: Box<reconnect::ReusedReady<'scope, 'task, 'policy>>,
    ) -> Step {
        let reconnect::ReusedReady {
            startup,
            listener,
            previous,
            retired,
            attempts,
            max_attempts,
            last,
        } = *ready;
        self.parts.boundary = Some(Box::new(Boundary {
            previous,
            retired,
            attempts,
            max_attempts,
            last,
        }));
        self.parts.listener = Some(listener);
        self.parts.phase = Some(Phase::Starting(Box::new(startup)));
        self.parts.accepted_ready = false;
        Step::ArchivesReused
    }

    #[inline(never)]
    fn finish_startup(
        &mut self,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
    ) -> Step {
        let startup = match self.parts.phase.take() {
            Some(Phase::Starting(startup)) => startup,
            other => {
                self.parts.phase = other;
                return Step::Stopped;
            }
        };
        let driver = match startup.finish_boxed() {
            Ok(driver) => driver,
            Err(refusal) => {
                self.parts.phase = Some(Phase::StartupStopped(refusal));
                return Step::StartupStopped;
            }
        };
        let Some(parked) = self.parts.parked.take() else {
            self.parts.phase = Some(Phase::ResumeStopped(driver));
            return Step::ResumeStopped;
        };
        match parked.resume(driver, task, cx, clock) {
            Ok(manager) => {
                self.parts.phase = Some(Phase::Recording(manager));
                self.parts.eof_seen = false;
                self.parts.bootstrap_ready = false;
                Step::Resumed
            }
            Err((parked, driver)) => {
                self.parts.parked = Some(parked);
                self.parts.phase = Some(Phase::ResumeStopped(driver));
                Step::ResumeStopped
            }
        }
    }
}
