#![forbid(unsafe_code)]
//! Finite, caller-driven provisioning and rollover for HTTP-started A/V.
//!
//! Generation choices are in memory and must be retained by the caller; this
//! is not a crash-restart supervisor or an independent custody proof. Each
//! `step` returns an observation and the caller owns every such observation.

use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
    time::Duration,
};

use asupersync::{Cx, time::timeout_at};
use fss_container::flv_avc::SourceKey;
use fss_core::{BudgetVector, ContentDigest};
use fss_runtime::execution::TaskCx;

use super::media_av_archive as archive;
use crate::unifi_direct::{
    av_rollover_generation::{self, Identity, Plan},
    av_rollover_supplies::{self, Created},
    av_rollover_worker,
    metered::MeteredClock,
    recording_provision::SupplyCustody,
    recording_session::AudioAllowancePolicy,
    source_coordinator::ArchiveAdmission,
    source_worker,
};

/// Exact recording or rollover owner. Stopped outcomes are never retried.
#[must_use = "retain or reconcile the complete recording owner"]
pub enum Owner {
    /// Normal source and archive scheduling.
    Recording(Box<archive::Driver>),
    /// Prior custody check; the boolean records successful admission.
    Preflight(Box<archive::RolloverPreflight>, bool),
    /// Successor transition; the boolean records successful admission.
    Switching(Box<archive::Rollover>, bool),
    /// Prior custody could not be verified.
    PreflightStopped(Box<archive::RolloverPreflightResult>),
    /// The successor switch could not be safely attached.
    SwitchStopped(Box<archive::RolloverResult>),
}

/// Original generation identity and storage authority after supply transfer.
#[must_use = "retain for later inspection and recovery"]
pub struct Custody {
    /// Caller-selected finite generation identity.
    pub identity: Identity,
    /// Exact creation paths, replay and pin-custody authorities.
    pub storage: SupplyCustody,
}

/// A drained failed creator and its independently observed task result.
#[must_use = "reconcile partial creation before another attempt"]
pub struct CreatorFailure {
    /// Generation whose creation was attempted, unless owner state was inconsistent.
    pub identity: Option<Identity>,
    /// All original and partially created owners.
    pub retirement: av_rollover_supplies::Retirement,
    /// Runtime and creation outcome.
    pub completion: av_rollover_supplies::Completion,
}

/// One complete scheduling observation.
#[must_use]
pub enum Step {
    /// Invalid bounds or mismatched task, runtime or clock; no work was polled.
    Configuration,
    /// Cancellation or task authority stopped the owner.
    Aborted,
    /// One finite generation was selected; no storage work was started.
    Planned(Identity),
    /// The selected creator was admitted to the blocking pool.
    CreatorStarted,
    /// Creator admission refused and will not be retried implicitly.
    CreatorStartRefused(av_rollover_supplies::StartError),
    /// The creator's exact completion and owners require reconciliation.
    CreatorFailed,
    /// Fresh stores are ready and retained by this owner.
    CreatorReady,
    /// Created store paths or pin scope differ from the selected identity.
    CreatorBindingRefused,
    /// The finite plan is exhausted; existing recording may still continue.
    PlanExhausted,
    /// Planning failed and will not be retried implicitly.
    PlanRefused(av_rollover_generation::Error),
    /// Normal audio-allowance or recording result.
    Recording(archive::AllowanceStep),
    /// A capacity-stopped stream is waiting for fresh supplies.
    AwaitingSupplies(crate::unifi_direct::av_worker::RolloverNeed),
    /// The next transition cannot proceed without explicit reconciliation.
    InterventionRequired,
    /// The original source and successor entered preflight without I/O.
    PreflightPrepared,
    /// A rollover worker was admitted.
    RolloverStarted,
    /// Worker admission refused; its original owner remains retained.
    RolloverStartRefused(av_rollover_worker::StartError),
    /// The exact worker is still running after the bounded wait.
    RolloverWaiting,
    /// The predecessor was checked and its successor is ready to start.
    PreflightReady,
    /// The pending segment was reattached to a verified successor.
    Resumed(fss_publication::RootLedgerReceipt),
    /// An uncertain or failed transition requires explicit reconciliation.
    RolloverStopped,
    /// An owner could not be transferred; all other owners remain retained.
    OwnershipUnavailable,
}

/// All owners returned without joining or discarding active work.
#[must_use = "drain active workers and account for every owner"]
pub struct Parts {
    /// Recording, transition, or unresolved outcome.
    pub owner: Option<Owner>,
    /// Remaining finite generation plan.
    pub plan: Plan,
    /// Exact unstarted or running creator, if any.
    pub creator: Option<av_rollover_supplies::Worker>,
    /// Generation selected for the creator.
    pub creator_identity: Option<Identity>,
    /// Whether creator admission succeeded.
    pub creator_started: bool,
    /// A creator admission refusal needing an explicit retry decision.
    pub creator_refused: bool,
    /// Joined creator result not yet transferred.
    pub creator_completion: Option<av_rollover_supplies::Completion>,
    /// Successfully created, unused successor.
    pub ready: Option<(Identity, Created)>,
    /// A created successor did not match its selected generation identity.
    pub creator_binding_refused: bool,
    /// Failed or partially created successor.
    pub failure: Option<CreatorFailure>,
    /// Installed creation custody in generation order.
    pub custody: VecDeque<Custody>,
    /// Explicit finite audio allowance.
    pub audio: AudioAllowancePolicy,
    /// A stopped or exhausted generation plan.
    pub plan_stopped: bool,
    /// A rollover admission was refused.
    pub rollover_refused: bool,
    /// Cancellation permanently stopped automatic admission.
    pub aborted: bool,
}

/// One bounded automatic owner; no background task escapes this value.
#[must_use = "abort, drain, and retain all owners"]
pub struct Managed {
    parts: Parts,
    custody_limit: usize,
}

/// Recording policy and all non-recording owners held during reconnection.
/// The source and camera effect are held separately by the reconnect owner.
/// Neither the source key nor the camera claim authenticates a physical camera.
#[must_use = "resume or retain the generation plan and all worker custody"]
pub struct Parked<'scope, 'task> {
    parts: Parts,
    custody_limit: usize,
    previous_key: SourceKey,
    camera_claim: ContentDigest,
    clock: MeteredClock<'scope, 'task>,
}

/// Parked management custody without the scoped clock binding.
/// This is a recovery owner, not authority to resume the recording.
#[must_use = "drain and reconcile the parked management custody"]
pub struct DetachedParked {
    /// Generation plan, allowance and any active workers.
    pub parts: Parts,
    /// Original finite custody limit.
    pub custody_limit: usize,
    /// Previous caller-supplied source identity.
    pub previous_key: SourceKey,
    /// Previous caller-supplied camera claim.
    pub camera_claim: ContentDigest,
}

impl DetachedParked {
    /// Permanently stop admission and request cancellation of retained work.
    /// Parking normally leaves `owner` empty; unexpected owners are still
    /// cancelled and retained instead of being silently discarded.
    pub fn abort(&mut self) {
        self.parts.aborted = true;
        if let Some(creator) = &self.parts.creator { creator.abort(); }
        match self.parts.owner.as_mut() {
            Some(Owner::Recording(driver)) => driver.abort(),
            Some(Owner::Preflight(worker, _)) => worker.abort(),
            Some(Owner::Switching(worker, _)) => worker.abort(),
            _ => (),
        }
    }

    /// Join the admitted creator and retain its exact completion in `parts`.
    /// A false result does not itself prove that no work remains.
    pub async fn join_creator(&mut self) -> bool {
        if self.parts.creator_completion.is_some() { return true; }
        if !self.parts.creator_started { return false; }
        let Some(worker) = self.parts.creator.as_mut() else { return false; };
        if let Some(done) = worker.join().await {
            self.parts.creator_completion = Some(done);
            true
        } else { false }
    }
}

impl<'scope, 'task> Parked<'scope, 'task> {
    /// Separate the scoped clock while retaining all policy and worker state.
    /// This does not cancel, join, or authorize resumption of any work.
    pub fn split_scope(self: Box<Self>) -> (MeteredClock<'scope, 'task>, Box<DetachedParked>) {
        let Self { parts, custody_limit, previous_key, camera_claim, clock } = *self;
        (clock, Box::new(DetachedParked { parts, custody_limit, previous_key, camera_claim }))
    }

    /// Recover every retained non-recording owner without starting work.
    pub fn into_parts(self: Box<Self>) -> Parts {
        self.parts
    }

    /// Attach a live successor while preserving the original plan, allowance,
    /// and worker custody. On refusal both inputs are returned unchanged.
    /// A matching caller-supplied camera claim is not an identity proof. The
    /// caller must independently bind the successor to the retained listener
    /// and committed effect, and reconcile that effect when appropriate.
    #[inline(never)]
    pub fn resume(
        mut self: Box<Self>,
        driver: Box<archive::Driver>,
        task: &TaskCx<'task>,
        cx: &Cx,
        clock: MeteredClock<'scope, 'task>,
    ) -> Result<Box<Managed>, (Box<Self>, Box<archive::Driver>)> {
        let (key, claim) = driver.source_claim();
        if !clock.matches(task, cx)
            || !self.clock.same_mapping(&clock)
            || !driver.bound_to_task(task)
            || driver.is_halted()
            || self.parts.aborted
            || self.parts.owner.is_some()
            || claim != self.camera_claim
            || key.connection <= self.previous_key.connection
            || key.generation < self.previous_key.generation
        {
            return Err((self, driver));
        }
        self.parts.owner = Some(Owner::Recording(driver));
        Ok(Box::new(Managed { parts: self.parts, custody_limit: self.custody_limit }))
    }
}

impl Managed {
    /// Whether the current recording source attempt still requires joining.
    pub fn is_recording_source_running(&self) -> bool {
        matches!(&self.parts.owner, Some(Owner::Recording(driver)) if driver.is_source_running())
    }

    /// Whether the current recording A/V attempt still requires joining.
    pub fn is_recording_av_running(&self) -> bool {
        matches!(&self.parts.owner, Some(Owner::Recording(driver)) if driver.is_av_running())
    }

    /// Whether a creator or rollover attempt still requires joining.
    pub fn is_background_running(&self) -> bool {
        self.parts.creator.as_ref().is_some_and(|worker| worker.is_running())
            || match &self.parts.owner {
                Some(Owner::Preflight(worker, _)) => worker.is_running(),
                Some(Owner::Switching(worker, _)) => worker.is_running(),
                _ => false,
            }
    }

    pub(super) fn matches_listener(&self, listener: &crate::unifi_direct::listener::Listener<'_, '_, '_>) -> bool {
        !self.parts.aborted && matches!(self.parts.owner.as_ref(), Some(Owner::Recording(driver))
            if !driver.is_halted() && driver.matches_listener(listener))
    }

    /// Separate a stopped, drained recording for a reconnect while retaining
    /// the exact plan, audio budget and creator/rollover custody. The caller
    /// decides whether the observed stop warrants reconnecting; a halt alone
    /// is not proof of EOF. Active creator handles stay owned and are not
    /// cancelled or polled by this operation. The caller must supply the same
    /// clock mapping used by the listener; this method checks task and runtime
    /// identity but cannot independently inspect the listener's mapping.
    #[inline(never)]
    pub fn park_for_reconnect<'scope, 'task>(
        mut self: Box<Self>,
        task: &TaskCx<'task>,
        cx: &Cx,
        clock: MeteredClock<'scope, 'task>,
    ) -> Result<(Box<Parked<'scope, 'task>>, Box<archive::Parts>), Box<Self>> {
        if self.parts.aborted || !clock.matches(task, cx)
            || !matches!(self.parts.owner.as_ref(), Some(Owner::Recording(driver)) if driver.is_halted() && driver.bound_to_task(task))
        {
            return Err(self);
        }
        let Some(Owner::Recording(driver)) = self.parts.owner.take() else {
            unreachable!("recording owner was checked above")
        };
        match (*driver).into_parts() {
            Ok(recording) => {
                let parked = Parked {
                    previous_key: recording.key,
                    camera_claim: recording.camera_claim,
                    parts: self.parts,
                    custody_limit: self.custody_limit,
                    clock,
                };
                Ok((Box::new(parked), Box::new(recording)))
            }
            Err(driver) => {
                self.parts.owner = Some(Owner::Recording(Box::new(driver)));
                Err(self)
            }
        }
    }

    /// Bind one live driver to a finite caller-authorized generation plan.
    /// The caller must independently establish storage and pin custody.
    pub fn new(
        driver: archive::Driver,
        plan: Plan,
        audio: AudioAllowancePolicy,
        custody_limit: usize,
    ) -> Result<Self, (archive::Driver, Plan, AudioAllowancePolicy)> {
        if !(1..=128).contains(&custody_limit) {
            return Err((driver, plan, audio));
        }
        Ok(Self {
            parts: Parts {
                owner: Some(Owner::Recording(Box::new(driver))),
                plan,
                creator: None,
                creator_identity: None,
                creator_started: false,
                creator_refused: false,
                creator_completion: None,
                ready: None,
                creator_binding_refused: false,
                failure: None,
                custody: VecDeque::new(),
                audio,
                plan_stopped: false,
                rollover_refused: false,
                aborted: false,
            },
            custody_limit,
        })
    }

    /// Transfer one installed creator's exact path and authority.
    pub fn take_custody(&mut self) -> Option<Custody> {
        self.parts.custody.pop_front()
    }

    /// Permit a fresh creator admission after a definite start refusal.
    pub fn authorize_creator_retry(&mut self) -> bool {
        if !self.parts.aborted
            && self.parts.creator_refused
            && !self.parts.creator_started
            && self.parts.creator.is_some()
        {
            self.parts.creator_refused = false;
            true
        } else {
            false
        }
    }

    /// Permit another rollover admission after a definite start refusal.
    pub fn authorize_rollover_retry(&mut self) -> bool {
        if !self.parts.aborted && self.parts.rollover_refused {
            self.parts.rollover_refused = false;
            true
        } else {
            false
        }
    }

    /// Permanently stop new work and request cancellation of each owner.
    pub fn abort(&mut self) {
        self.parts.aborted = true;
        if let Some(creator) = &self.parts.creator {
            creator.abort();
        }
        match self.parts.owner.as_mut() {
            Some(Owner::Recording(driver)) => driver.abort(),
            Some(Owner::Preflight(worker, _)) => worker.abort(),
            Some(Owner::Switching(worker, _)) => worker.abort(),
            _ => (),
        }
    }

    /// Join an admitted creator even after cancellation.
    pub async fn join_creator(&mut self) -> bool {
        if self.parts.creator_completion.is_some() {
            return true;
        }
        if !self.parts.creator_started {
            return false;
        }
        let Some(worker) = self.parts.creator.as_mut() else {
            return false;
        };
        if let Some(done) = worker.join().await {
            self.parts.creator_completion = Some(done);
            true
        } else {
            false
        }
    }

    /// Join an admitted rollover stage even after cancellation.
    pub async fn join_rollover(&mut self) -> bool {
        match self.parts.owner.as_mut() {
            Some(Owner::Preflight(worker, true)) => worker.join().await,
            Some(Owner::Switching(worker, true)) => worker.join().await,
            _ => false,
        }
    }

    /// Join media workers when the recording driver owns them. A rollover
    /// transition has already paused the source and retired its A/V worker.
    /// Preserve returned completions alongside this owner for reconciliation.
    pub async fn join_recording_workers(
        &mut self,
    ) -> (
        Option<source_worker::Completion>,
        Option<crate::unifi_direct::av_worker::UnknownTimeCompletion>,
    ) {
        let source = self.join_recording_source().await;
        let av = self.join_recording_av().await;
        (source, av)
    }

    /// Join only the active source attempt; the caller owns any completion.
    pub async fn join_recording_source(&mut self) -> Option<source_worker::Completion> {
        match self.parts.owner.as_mut() {
            Some(Owner::Recording(driver)) => driver.join_source().await,
            _ => None,
        }
    }

    /// Join only the active A/V attempt; the caller owns any completion.
    pub async fn join_recording_av(&mut self) -> Option<crate::unifi_direct::av_worker::UnknownTimeCompletion> {
        match self.parts.owner.as_mut() {
            Some(Owner::Recording(driver)) => driver.join_av().await,
            _ => None,
        }
    }

    /// Transfer all owners, including active workers, without pretending to drain them.
    pub fn into_parts(self) -> Parts {
        self.parts
    }

    /// Drive one bounded decision without implicitly retrying failed effects.
    pub async fn step<'scope, 'task>(
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
        if self.parts.aborted {
            return Step::Aborted;
        }
        if wait.is_zero() || wait > Duration::from_secs(30) || !clock.matches(task, cx) {
            return Step::Configuration;
        }
        if cx.checkpoint().is_err() {
            self.abort();
            return Step::Aborted;
        }
        let Ok(now) = clock.now() else {
            return Step::Configuration;
        };
        if task.checkpoint(now, &BudgetVector::ZERO).is_err() {
            self.abort();
            return Step::Aborted;
        }
        let bound = match self.parts.owner.as_ref() {
            Some(Owner::Recording(driver)) => driver.bound_to_task(task),
            Some(Owner::Preflight(worker, _)) => worker.bound_to_task(task),
            Some(Owner::Switching(worker, _)) => worker.bound_to_task(task),
            _ => true,
        };
        if !bound {
            return Step::Configuration;
        }

        // A transition owns the paused stream until its exact outcome is collected.
        if matches!(
            self.parts.owner,
            Some(Owner::Preflight(..) | Owner::Switching(..))
        ) {
            return self.drive_rollover(task, cx, clock, wait, rollover).await;
        }
        if !matches!(self.parts.owner, Some(Owner::Recording(_))) {
            return Step::InterventionRequired;
        }

        // A stopped source must not start or plan additional archive work.
        // Any already-admitted creator remains owned and can be joined via
        // `join_creator`; this check does not assert quiescence or recovery.
        if matches!(self.parts.owner.as_ref(), Some(Owner::Recording(driver)) if driver.is_halted()) {
            return Step::Recording(archive::AllowanceStep::Recording(archive::Step::Halted));
        }

        if !self.parts.plan_stopped
            && self.parts.creator.is_none()
            && self.parts.ready.is_none()
            && self.parts.failure.is_none()
            && self.parts.custody.len() < self.custody_limit
        {
            match self.parts.plan.next_worker() {
                Ok(Some((identity, worker))) => {
                    self.parts.creator_identity = Some(identity.clone());
                    self.parts.creator = Some(worker);
                    return Step::Planned(identity);
                }
                Ok(None) => {
                    self.parts.plan_stopped = true;
                    return Step::PlanExhausted;
                }
                Err(error) => {
                    self.parts.plan_stopped = true;
                    return Step::PlanRefused(error);
                }
            }
        }
        if !self.parts.creator_started && !self.parts.creator_refused {
            if let Some(creator) = self.parts.creator.as_mut() {
                return match creator.start(task, cx, clock, supply_cost) {
                    Ok(()) => {
                        self.parts.creator_started = true;
                        Step::CreatorStarted
                    }
                    Err(error) => {
                        self.parts.creator_refused = true;
                        Step::CreatorStartRefused(error)
                    }
                };
            }
        }
        if self.parts.creator_started && self.parts.creator_completion.is_none() {
            let done = poll_fn(|context| {
                let mut join = pin!(self.join_creator());
                Poll::Ready(matches!(join.as_mut().poll(context), Poll::Ready(true)))
            })
            .await;
            let _ = done;
        }
        if self.parts.creator_completion.is_some() {
            let Some(completion) = self.parts.creator_completion.take() else {
                return Step::OwnershipUnavailable;
            };
            let Some(creator) = self.parts.creator.take() else {
                self.parts.creator_completion = Some(completion);
                return Step::OwnershipUnavailable;
            };
            let mut retirement = match creator.retire() {
                Ok(retirement) => retirement,
                Err(creator) => {
                    self.parts.creator = Some(creator);
                    self.parts.creator_completion = Some(completion);
                    return Step::OwnershipUnavailable;
                }
            };
            let identity = self.parts.creator_identity.take();
            self.parts.creator_started = false;
            if let Some(identity) = identity.as_ref() {
                if completion.runtime.is_ok()
                    && completion.outcome == av_rollover_supplies::Outcome::Ready
                {
                    if let Some(created) = retirement.take_supplies() {
                        let matches = created.root == identity.journal_root
                            && created.switch_custody.as_ref().is_some_and(|custody| {
                                custody.root == identity.pin_root
                                    && custody.scope == identity.pin_scope
                            });
                        self.parts.ready = Some((identity.clone(), created));
                        if matches {
                            return Step::CreatorReady;
                        }
                        self.parts.creator_binding_refused = true;
                        return Step::CreatorBindingRefused;
                    }
                }
            }
            self.parts.failure = Some(CreatorFailure {
                identity,
                retirement,
                completion,
            });
            return Step::CreatorFailed;
        }

        let need = match self.parts.owner.as_ref() {
            Some(Owner::Recording(driver)) => driver.rollover_need(),
            _ => None,
        };
        if let Some(need) = need {
            if self.parts.creator_binding_refused {
                return Step::InterventionRequired;
            }
            if self.parts.rollover_refused {
                return Step::InterventionRequired;
            }
            if self.parts.ready.is_none() {
                if self.parts.creator_started && self.parts.creator_completion.is_none() {
                    let _ = timeout_at(cx.now() + wait, self.join_creator()).await;
                    return Step::AwaitingSupplies(need);
                }
                return if self.parts.failure.is_some()
                    || self.parts.creator_refused
                    || self.parts.plan_stopped
                    || self.parts.custody.len() >= self.custody_limit
                {
                    Step::InterventionRequired
                } else {
                    Step::AwaitingSupplies(need)
                };
            }
            return self.prepare_rollover();
        }
        let Some(Owner::Recording(driver)) = self.parts.owner.as_mut() else {
            return Step::OwnershipUnavailable;
        };
        Step::Recording(
            driver
                .step_with_audio_allowance(&mut self.parts.audio, task, cx, clock, wait, source, av)
                .await,
        )
    }

    async fn drive_rollover<'scope, 'task>(
        &mut self,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        wait: Duration,
        admission: ArchiveAdmission<'_>,
    ) -> Step {
        if self.parts.rollover_refused {
            return Step::InterventionRequired;
        }
        let Some(owner) = self.parts.owner.as_mut() else {
            return Step::OwnershipUnavailable;
        };
        match owner {
            Owner::Preflight(worker, started) => {
                if !*started {
                    return match worker.start(task, cx, clock, admission.resource, admission.cost) {
                        Ok(()) => {
                            *started = true;
                            Step::RolloverStarted
                        }
                        Err(error) => {
                            self.parts.rollover_refused = true;
                            Step::RolloverStartRefused(error)
                        }
                    };
                }
                if !matches!(timeout_at(cx.now() + wait, worker.join()).await, Ok(true)) {
                    return Step::RolloverWaiting;
                }
            }
            Owner::Switching(worker, started) => {
                if !*started {
                    return match worker.start(task, cx, clock, admission.resource, admission.cost) {
                        Ok(()) => {
                            *started = true;
                            Step::RolloverStarted
                        }
                        Err(error) => {
                            self.parts.rollover_refused = true;
                            Step::RolloverStartRefused(error)
                        }
                    };
                }
                if !matches!(timeout_at(cx.now() + wait, worker.join()).await, Ok(true)) {
                    return Step::RolloverWaiting;
                }
            }
            _ => return Step::OwnershipUnavailable,
        }
        self.finish_rollover()
    }

    /// Move the large preflight owners outside the async decision frame.
    #[inline(never)]
    fn prepare_rollover(&mut self) -> Step {
        let Some((identity, created)) = self.parts.ready.take() else {
            return Step::OwnershipUnavailable;
        };
        let driver = match self.parts.owner.take() {
            Some(Owner::Recording(driver)) => driver,
            other => {
                self.parts.owner = other;
                self.parts.ready = Some((identity, created));
                return Step::OwnershipUnavailable;
            }
        };
        let Created { root, replay, io, journal_limits, switch_custody, supplies } = created;
        match archive::RolloverPreflight::prepare(*driver, supplies) {
            Ok(preflight) => {
                self.parts.custody.push_back(Custody {
                    identity,
                    storage: SupplyCustody { root, replay, io, journal_limits, switch_custody },
                });
                self.parts.owner = Some(Owner::Preflight(Box::new(preflight), false));
                Step::PreflightPrepared
            }
            Err(refusal) => {
                self.parts.owner = Some(Owner::Recording(Box::new(refusal.driver)));
                self.parts.ready = Some((identity, Created {
                    root, replay, io, journal_limits, switch_custody, supplies: refusal.supplies,
                }));
                self.parts.rollover_refused = true;
                Step::InterventionRequired
            }
        }
    }

    /// Transfer a drained rollover result without enlarging the async frame.
    #[inline(never)]
    fn finish_rollover(&mut self) -> Step {
        let Some(owner) = self.parts.owner.take() else {
            return Step::OwnershipUnavailable;
        };
        match owner {
            Owner::Preflight(worker, started) => match worker.finish_boxed() {
                Ok(result) => match *result {
                archive::RolloverPreflightResult::Ready(worker) => {
                    self.parts.owner = Some(Owner::Switching(Box::new(worker), false));
                    Step::PreflightReady
                }
                stopped => {
                    self.parts.owner = Some(Owner::PreflightStopped(Box::new(stopped)));
                    Step::RolloverStopped
                }
                },
                Err(worker) => {
                    self.parts.owner = Some(Owner::Preflight(worker, started));
                    Step::OwnershipUnavailable
                }
            },
            Owner::Switching(worker, started) => match worker.finish_boxed() {
                Ok(result) => match *result {
                archive::RolloverResult::Resumed { driver, receipt } => {
                    self.parts.owner = Some(Owner::Recording(Box::new(driver)));
                    Step::Resumed(receipt)
                }
                stopped => {
                    self.parts.owner = Some(Owner::SwitchStopped(Box::new(stopped)));
                    Step::RolloverStopped
                }
                },
                Err(worker) => {
                    self.parts.owner = Some(Owner::Switching(worker, started));
                    Step::OwnershipUnavailable
                }
            },
            owner => {
                self.parts.owner = Some(owner);
                Step::OwnershipUnavailable
            }
        }
    }
}
