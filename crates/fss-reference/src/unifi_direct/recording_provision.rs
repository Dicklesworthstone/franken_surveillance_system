#![forbid(unsafe_code)]
//! Drive fresh rollover-store creation alongside a managed camera session.
//!
//! The caller still chooses the new root, switch and pin custodian. No camera
//! identity, restart recovery, or independent storage domain is inferred.

use std::{
    cell::Cell,
    future::{Future, poll_fn},
    pin::pin,
    sync::Arc,
    task::Poll,
    time::Duration,
};

use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
};
use fss_core::{BudgetVector, OperationId};
use fss_object::{SpoolIo, effect_journal::EffectJournalLimits};
use fss_runtime::execution::TaskCx;

use super::{
    av_rollover_generation, av_rollover_supplies, conversation, recording_session,
    metered::MeteredClock,
    recording_rollover::{ManagedSession, ManagedStep},
    source_coordinator::ArchiveAdmission,
};
use crate::ReplayCx;

/// Original creation path and authority retained after stores are installed.
#[must_use = "retain the path and authority for later recovery"]
pub struct SupplyCustody {
    /// Exclusive successor directory.
    pub root: std::path::PathBuf,
    /// Authority bound to the directory's parent.
    pub replay: Arc<ReplayCx>,
    /// Capability used to create the stores.
    pub io: Arc<dyn SpoolIo>,
    /// Exact journal limits needed for inspection and recovery.
    pub journal_limits: EffectJournalLimits,
    /// Pin-custody creation configuration, if the worker created the switch.
    pub switch_custody: Option<av_rollover_supplies::SwitchCustody>,
}

/// Managed camera session and one independently drained store creator.
#[must_use = "drain the creator and retain the complete session and storage state"]
pub struct ProvisioningSession<'scope, 'task, IO> {
    managed: ManagedSession<'scope, 'task, IO>,
    worker: Option<av_rollover_supplies::Worker>,
    started: bool,
    start_refused: bool,
    completion: Option<av_rollover_supplies::Completion>,
    ready: Option<av_rollover_supplies::Created>,
    failed: Option<av_rollover_supplies::Retirement>,
    custody: Option<SupplyCustody>,
    plan: Option<av_rollover_generation::Plan>,
    plan_stopped: bool,
    aborted: Cell<bool>,
}

/// Refused selected-stream provisioning retains the complete recording,
/// audio allowance and generation plan without starting storage work.
#[must_use = "recover all returned recording and provisioning owners"]
pub struct SelectedRefusal<'scope, 'task, IO> {
    /// Selected recording owners and exact refusal stage.
    pub recording: recording_session::SelectedRefusal<'scope, 'task, IO>,
    /// Unused, caller-authorized audio allowance.
    pub audio: recording_session::AudioAllowancePolicy,
    /// Unused, caller-authorized storage generation plan.
    pub plan: av_rollover_generation::Plan,
}

/// One camera, storage admission, or completed-creation outcome.
#[must_use = "account for the complete control and storage outcomes"]
pub enum Step {
    /// The wait bound is invalid; no camera or provisioning work was polled.
    Configuration,
    /// Cancellation was requested; drain and recover all retained owners.
    /// No new camera, rollover, or creation work is started by this driver.
    Aborted,
    /// A new bounded generation was chosen; no filesystem work has started.
    SupplyPlanned(av_rollover_generation::Identity),
    /// The caller's finite generation plan has no workers left.
    PlanExhausted,
    /// Planning refused without starting filesystem work.
    PlanRefused(av_rollover_generation::Error),
    /// The creator was started; no camera work was polled in this step.
    SupplyStarted,
    /// Admission failed; no automatic retry is performed.
    SupplyStartRefused(av_rollover_supplies::StartError),
    /// Created stores entered the managed session; custody remains in this owner.
    SupplyInstalled(av_rollover_supplies::Completion),
    /// Creation failed or was interrupted; partial owners remain available.
    SupplyFailed(av_rollover_supplies::Completion),
    /// A storage owner could not be transferred; everything remains retained.
    SupplyOwnershipUnavailable,
    /// A complete managed-session outcome, including any control result.
    Managed(ManagedStep),
}

/// Exact resources returned when the provisioning driver is retired.
#[must_use = "drain any worker and account for every returned owner"]
pub struct Owners<'scope, 'task, IO> {
    /// Original managed camera and recording owner.
    pub managed: ManagedSession<'scope, 'task, IO>,
    /// Unstarted or still-running creator, if any.
    pub worker: Option<av_rollover_supplies::Worker>,
    /// Whether this owner admitted the creator and must join it.
    pub started: bool,
    /// Whether admission was refused and needs an explicit retry decision.
    pub start_refused: bool,
    /// Joined result awaiting ownership transfer, if any.
    pub completion: Option<av_rollover_supplies::Completion>,
    /// Created supplies not yet accepted by the managed owner.
    pub ready: Option<av_rollover_supplies::Created>,
    /// Failed or interrupted creation with all partial owners.
    pub failed: Option<av_rollover_supplies::Retirement>,
    /// Original storage path and replay authority for installed supplies.
    pub custody: Option<SupplyCustody>,
    /// Remaining generation plan, if installed.
    pub plan: Option<av_rollover_generation::Plan>,
    /// Whether exhaustion or a planning refusal stopped automatic planning.
    pub plan_stopped: bool,
    /// Cancellation was requested; this owner must not restart work.
    pub aborted: bool,
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> ProvisioningSession<'scope, 'task, IO> {
    /// Bind a managed recording to a finite generation plan without I/O.
    pub fn from_plan(
        managed: ManagedSession<'scope, 'task, IO>,
        plan: av_rollover_generation::Plan,
    ) -> Self {
        Self {
            managed,
            worker: None,
            started: false,
            start_refused: false,
            completion: None,
            ready: None,
            failed: None,
            custody: None,
            plan: Some(plan),
            plan_stopped: false,
            aborted: Cell::new(false),
        }
    }

    /// Bind a selected A/V stream and caller-authorized generation plan.
    /// This performs no I/O or device authentication; all owners are returned
    /// unchanged at the stage where selected-stream admission refuses.
    pub fn begin_selected(
        selected: recording_session::SelectedRecording<'scope, 'task, IO>,
        audio: recording_session::AudioAllowancePolicy,
        plan: av_rollover_generation::Plan,
    ) -> Result<Self, SelectedRefusal<'scope, 'task, IO>> {
        match recording_session::Session::begin_selected(selected) {
            Ok(session) => Ok(Self::from_plan(ManagedSession::new(session, audio), plan)),
            Err(recording) => Err(SelectedRefusal { recording, audio, plan }),
        }
    }

    /// Bind an unstarted creator and the existing managed session without I/O.
    pub fn new(
        managed: ManagedSession<'scope, 'task, IO>,
        worker: av_rollover_supplies::Worker,
    ) -> Self {
        Self {
            managed,
            worker: Some(worker),
            started: false,
            start_refused: false,
            completion: None,
            ready: None,
            failed: None,
            custody: None,
            plan: None,
            plan_stopped: false,
            aborted: Cell::new(false),
        }
    }

    /// Borrow the existing controller across recording and rollover stages.
    /// Cancellation permanently closes this driver's control access.
    pub fn control(
        &mut self,
    ) -> Option<super::recording_session::Control<'_, 'scope, 'task, IO>> {
        if self.aborted.get() {
            return None;
        }
        self.managed.control()
    }

    /// Permit another admission attempt after an explicit start refusal.
    pub fn authorize_start_retry(&mut self) -> bool {
        if !self.aborted.get() && self.start_refused && !self.started && self.worker.is_some() {
            self.start_refused = false;
            true
        } else {
            false
        }
    }

    /// Transfer retained path and authority after installed supplies were observed.
    pub fn take_custody(&mut self) -> Option<SupplyCustody> {
        self.custody.take()
    }

    /// Transfer failed creation state for explicit inspection or reconciliation.
    pub fn take_failed(&mut self) -> Option<av_rollover_supplies::Retirement> {
        self.failed.take()
    }

    /// Install one bounded caller-authorized generation plan without I/O.
    /// An existing plan is never replaced or silently restarted.
    pub fn set_plan(
        &mut self,
        plan: av_rollover_generation::Plan,
    ) -> Result<(), av_rollover_generation::Plan> {
        if self.aborted.get() || self.plan.is_some() {
            return Err(plan);
        }
        self.plan = Some(plan);
        self.plan_stopped = false;
        Ok(())
    }

    /// Authorize another finite generation series after exhaustion was
    /// observed and all creator outcomes and custody have been transferred.
    /// No work starts here; cancellation and outstanding owners refuse renewal.
    pub fn extend_plan(&mut self, count: u64) -> Result<(), av_rollover_generation::Error> {
        if self.aborted.get()
            || !self.plan_stopped
            || self.worker.is_some()
            || self.started
            || self.completion.is_some()
            || self.ready.is_some()
            || self.failed.is_some()
            || self.custody.is_some()
        {
            return Err(av_rollover_generation::Error::Configuration);
        }
        let plan = self
            .plan
            .as_mut()
            .ok_or(av_rollover_generation::Error::Configuration)?;
        plan.extend(count)?;
        self.plan_stopped = false;
        Ok(())
    }

    /// Stage the next caller-authorized generation after the previous creator
    /// and its custody have been accounted for. An existing creator or
    /// unresolved result is never overwritten.
    pub fn offer_worker(
        &mut self,
        worker: av_rollover_supplies::Worker,
    ) -> Result<(), av_rollover_supplies::Worker> {
        if self.aborted.get()
            || self.worker.is_some()
            || self.started
            || self.completion.is_some()
            || self.ready.is_some()
            || self.failed.is_some()
            || self.custody.is_some()
        {
            return Err(worker);
        }
        self.worker = Some(worker);
        self.start_refused = false;
        Ok(())
    }

    /// Permanently stop this driver and request cancellation of creation and
    /// any rollover. Active operations must still be joined and all owners
    /// recovered; a new driver requires an explicit recovery decision.
    pub fn abort(&self) {
        self.aborted.set(true);
        if let Some(worker) = &self.worker {
            worker.abort();
        }
        self.managed.abort();
    }

    /// Join the active creator while retaining the complete result.
    pub async fn join_supply(&mut self) -> bool {
        if self.completion.is_some() {
            return true;
        }
        if !self.started {
            return false;
        }
        let Some(worker) = self.worker.as_mut() else {
            return false;
        };
        if let Some(completion) = worker.join().await {
            self.completion = Some(completion);
            true
        } else {
            false
        }
    }

    /// Join an active rollover after cancellation, retaining its owner.
    pub async fn join_rollover(&mut self) -> bool {
        self.managed.join().await
    }

    async fn poll_supply_once(&mut self) -> bool {
        poll_fn(|context| {
            let mut future = pin!(self.join_supply());
            Poll::Ready(matches!(future.as_mut().poll(context), Poll::Ready(true)))
        })
        .await
    }

    /// Advance one bounded step, polling creation without waiting before
    /// allowing the managed camera session to run. Completion and control
    /// outcomes are returned on separate calls and never discarded.
    pub async fn step(
        &mut self,
        owner: &mut conversation::Owner<'_, 'scope, 'task>,
        operation: &OperationId,
        wait: Duration,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        av_archive: ArchiveAdmission<'_>,
        source_archive: ArchiveAdmission<'_>,
        supply_cost: &BudgetVector,
    ) -> Step {
        if wait.is_zero() || wait > Duration::from_secs(30) {
            return Step::Configuration;
        }
        let context_valid = owner.cx.checkpoint().is_ok()
            && owner.clock.matches(owner.task, owner.cx)
            && owner.clock.matches(task, cx)
            && clock.matches(task, cx)
            && self.managed.clocks_match(&owner.clock, &clock);
        if context_valid
            && !self.aborted.get()
            && !self.plan_stopped
            && self.worker.is_none()
            && !self.started
            && self.completion.is_none()
            && self.ready.is_none()
            && self.failed.is_none()
            && self.custody.is_none()
        {
            if let Some(plan) = self.plan.as_mut() {
                match plan.next_worker() {
                    Ok(Some((identity, worker))) => {
                        self.worker = Some(worker);
                        self.start_refused = false;
                        return Step::SupplyPlanned(identity);
                    }
                    Ok(None) => {
                        self.plan_stopped = true;
                        return Step::PlanExhausted;
                    }
                    Err(error) => {
                        self.plan_stopped = true;
                        return Step::PlanRefused(error);
                    }
                }
            }
        }
        if context_valid
            && !self.aborted.get()
            && !self.started
            && !self.start_refused
            && self.worker.is_some()
        {
            let Some(worker) = self.worker.as_mut() else {
                return Step::SupplyOwnershipUnavailable;
            };
            match worker.start(task, cx, clock, supply_cost) {
                Ok(()) => {
                    self.started = true;
                    return Step::SupplyStarted;
                }
                Err(error) => {
                    self.start_refused = true;
                    return Step::SupplyStartRefused(error);
                }
            }
        }
        if owner.cx.checkpoint().is_err() {
            if let Some(worker) = &self.worker {
                worker.abort();
            }
        }
        if self.started && self.completion.is_none() {
            self.poll_supply_once().await;
        }
        if self.completion.is_some() && self.worker.is_some() {
            let Some(completion) = self.completion.take() else {
                return Step::SupplyOwnershipUnavailable;
            };
            let Some(worker) = self.worker.take() else {
                self.completion = Some(completion);
                return Step::SupplyOwnershipUnavailable;
            };
            let mut retired = match worker.retire() {
                Ok(retired) => retired,
                Err(worker) => {
                    self.worker = Some(worker);
                    self.completion = Some(completion);
                    return Step::SupplyOwnershipUnavailable;
                }
            };
            self.started = false;
            if completion.runtime.is_ok()
                && completion.outcome == av_rollover_supplies::Outcome::Ready
            {
                if let Some(created) = retired.take_supplies() {
                    self.ready = Some(created);
                    // The event is retained until the supplies are installed.
                    self.completion = Some(completion);
                } else {
                    self.failed = Some(retired);
                    return Step::SupplyFailed(completion);
                }
            } else {
                self.failed = Some(retired);
                return Step::SupplyFailed(completion);
            }
        }
        if self.aborted.get() {
            return Step::Aborted;
        }
        if self.ready.is_some() && self.custody.is_none() {
            let Some(created) = self.ready.take() else {
                return Step::SupplyOwnershipUnavailable;
            };
            let av_rollover_supplies::Created {
                root,
                replay,
                io,
                journal_limits,
                switch_custody,
                supplies,
            } = created;
            match self.managed.provide(supplies) {
                Ok(()) => {
                    self.custody = Some(SupplyCustody {
                        root,
                        replay,
                        io,
                        journal_limits,
                        switch_custody,
                    });
                    return match self.completion.take() {
                        Some(completion) => Step::SupplyInstalled(completion),
                        None => Step::SupplyOwnershipUnavailable,
                    };
                }
                Err(supplies) => {
                    self.ready = Some(av_rollover_supplies::Created {
                        root,
                        replay,
                        io,
                        journal_limits,
                        switch_custody,
                        supplies,
                    })
                }
            }
        }
        Step::Managed(
            self.managed
                .step(
                    owner,
                    operation,
                    wait,
                    task,
                    cx,
                    clock,
                    av_archive,
                    source_archive,
                )
                .await,
        )
    }

    /// Recover every current owner, including a running or failed creator.
    pub fn into_parts(self) -> Owners<'scope, 'task, IO> {
        Owners {
            managed: self.managed,
            worker: self.worker,
            started: self.started,
            start_refused: self.start_refused,
            completion: self.completion,
            ready: self.ready,
            failed: self.failed,
            custody: self.custody,
            plan: self.plan,
            plan_stopped: self.plan_stopped,
            aborted: self.aborted.get(),
        }
    }
}
