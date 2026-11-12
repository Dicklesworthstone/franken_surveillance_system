#![forbid(unsafe_code)]
//! Retained generation admission for a managed video provisioning session.
//! This is not a restart supervisor or proof of custody independence.

use asupersync::{
    Cx,
    io::{AsyncRead, AsyncWrite},
};
use fss_core::{BudgetVector, OperationId};
use fss_runtime::execution::TaskCx;
use std::{
    cell::Cell,
    collections::VecDeque,
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
    time::Duration,
};

use super::{
    av_rollover_generation::{
        BootstrapCompletion, BootstrapOutcome, BootstrapRetirement, BootstrapStartError,
        BootstrapWorker, CreatorObservation, Identity, ReservationCompletion, ReservationInputs,
        ReservationOutcome, ReservationRequest, ReservationRetirement, ReservationStartError,
        ReservationWorker,
    },
    av_rollover_supplies, conversation,
    metered::MeteredClock,
    source_coordinator::ArchiveAdmission,
    video_provision,
    video_session::ManagedSession,
};

/// One retained reservation and its associated video provisioning owner.
#[must_use = "drain both workers and retain every resulting owner"]
pub struct RetainedSession<'scope, 'task, IO> {
    inner: video_provision::ProvisioningSession<'scope, 'task, IO>,
    bootstrap: Option<BootstrapWorker>,
    bootstrap_started: bool,
    bootstrap_refused: bool,
    bootstrap_completion: Option<BootstrapCompletion>,
    bootstrap_retirement: Option<BootstrapRetirement>,
    reservation: Option<ReservationWorker>,
    started: bool,
    start_refused: bool,
    completion: Option<ReservationCompletion>,
    retirement: Option<ReservationRetirement>,
    automatic: Option<AutomaticState>,
    aborted: Cell<bool>,
}

/// Finite automatic generation allowance and its retained creator custody.
/// These are local creator observations, not independent storage proof.
pub struct AutomaticState {
    /// Additional reservations still authorized by this bounded owner.
    pub remaining: u64,
    /// Installed creator custody retained in generation order.
    pub custody: VecDeque<video_provision::SupplyCustody>,
    /// Maximum custody entries admitted by this finite allowance.
    pub custody_limit: usize,
    /// A local observation could not be matched; explicit reconciliation is required.
    pub stopped: bool,
}

/// One observation; all storage and controller owners remain with the session.
#[must_use = "account for the complete reservation or session outcome"]
pub enum Step {
    /// Bootstrap worker admitted; no reservation or creator has started.
    BootstrapStarted,
    /// Bootstrap admission refused; retry needs an explicit decision.
    BootstrapStartRefused(BootstrapStartError),
    /// Bootstrap succeeded and its retained plan entered an unstarted reservation.
    BootstrapReady,
    /// Bootstrap stopped or needs reconciliation; all partial owners are retained.
    BootstrapStopped(BootstrapCompletion),
    /// Reservation or reconciliation worker admitted; no creator started by this step.
    ReservationStarted,
    /// Admission was refused; an explicit retry decision is needed.
    ReservationStartRefused(ReservationStartError),
    /// A retained reservation is bound to the unstarted creator.
    Reserved(Identity),
    /// A caller reference or local creator observation was recorded at this head.
    /// Neither establishes independent verification or physical custody.
    Reconciled(fss_runtime::effect_journal::EffectJournalPin),
    /// Successful creation could not be bound to the pending identity.
    /// The completion and all storage owners remain available to the caller.
    AutomaticRefused(av_rollover_supplies::Completion),
    /// Automatic handling is fenced until its owners are explicitly reconciled.
    AutomaticStopped,
    /// The finite allowance is spent and a further rollover needs supplies.
    /// The original managed result is returned for control and custody accounting.
    AutomaticExhausted(video_provision::Step),
    /// Reservation or reconciliation failed, was cancelled, or requires inspection.
    ReservationStopped(ReservationCompletion),
    /// Ownership transfer was unavailable; original owners remain retained.
    OwnershipUnavailable,
    /// A normal video provisioning or controller outcome.
    Session(video_provision::Step),
    /// Cancellation was requested; drain and retain all owners.
    Aborted,
}

/// Exact remaining owners when the wrapper is retired.
#[must_use = "drain running workers and reconcile retained outcomes"]
pub struct Owners<'scope, 'task, IO> {
    /// Underlying session, including any active creator or rollover.
    pub inner: video_provision::ProvisioningSession<'scope, 'task, IO>,
    /// Original bootstrap worker, if not yet retired.
    pub bootstrap: Option<BootstrapWorker>,
    /// Whether the bootstrap must be joined.
    pub bootstrap_started: bool,
    /// Bootstrap admission refusal needing an explicit retry.
    pub bootstrap_refused: bool,
    /// Joined bootstrap completion awaiting transfer.
    pub bootstrap_completion: Option<BootstrapCompletion>,
    /// Drained bootstrap metadata and any partial storage owners.
    pub bootstrap_retirement: Option<BootstrapRetirement>,
    /// Original reservation worker if not yet retired.
    pub reservation: Option<ReservationWorker>,
    /// Whether the reservation must be joined.
    pub started: bool,
    /// Admission refusal needing an explicit retry.
    pub start_refused: bool,
    /// Joined completion awaiting ownership transfer.
    pub completion: Option<ReservationCompletion>,
    /// Drained plan and reservation outcome, including any unstarted candidate.
    pub retirement: Option<ReservationRetirement>,
    /// Bounded automation state, including every untransferred custody owner.
    pub automatic: Option<AutomaticState>,
    /// Cancellation was requested.
    pub aborted: bool,
}

impl<'scope, 'task, IO: AsyncRead + AsyncWrite + Unpin> RetainedSession<'scope, 'task, IO> {
    /// Bind a managed owner and one unstarted reservation, without I/O.
    pub fn new(
        managed: ManagedSession<'scope, 'task, IO>,
        reservation: ReservationWorker,
    ) -> Result<Self, (ManagedSession<'scope, 'task, IO>, ReservationWorker)> {
        if !reservation.is_unstarted_reservation() {
            return Err((managed, reservation));
        }
        Ok(Self {
            inner: video_provision::ProvisioningSession::waiting(managed),
            bootstrap: None,
            bootstrap_started: false,
            bootstrap_refused: false,
            bootstrap_completion: None,
            bootstrap_retirement: None,
            reservation: Some(reservation),
            started: false,
            start_refused: false,
            completion: None,
            retirement: None,
            automatic: None,
            aborted: Cell::new(false),
        })
    }

    /// Bind a managed owner and unstarted retained-plan bootstrap without I/O.
    pub fn with_bootstrap(
        managed: ManagedSession<'scope, 'task, IO>,
        bootstrap: BootstrapWorker,
    ) -> Result<Self, (ManagedSession<'scope, 'task, IO>, BootstrapWorker)> {
        if !bootstrap.is_unstarted() {
            return Err((managed, bootstrap));
        }
        Ok(Self {
            inner: video_provision::ProvisioningSession::waiting(managed),
            bootstrap: Some(bootstrap),
            bootstrap_started: false,
            bootstrap_refused: false,
            bootstrap_completion: None,
            bootstrap_retirement: None,
            reservation: None,
            started: false,
            start_refused: false,
            completion: None,
            retirement: None,
            automatic: None,
            aborted: Cell::new(false),
        })
    }

    /// Borrow controller access while the retained reservation is in progress.
    pub fn control(&mut self) -> Option<super::recording_session::Control<'_, 'scope, 'task, IO>> {
        if self.aborted.get() {
            None
        } else {
            self.inner.control()
        }
    }

    /// Transfer installed storage custody from the underlying session.
    pub fn take_custody(&mut self) -> Option<video_provision::SupplyCustody> {
        self.automatic
            .as_mut()
            .and_then(|state| state.custody.pop_front())
            .or_else(|| self.inner.take_custody())
    }

    /// Enable bounded local creator observations before the first operation.
    /// `additional` is the maximum number of later reservations, not a retention
    /// or service guarantee. Custody remains owned until explicitly taken.
    pub fn enable_creator_observation(&mut self, additional: u64) -> bool {
        if self.aborted.get()
            || self.automatic.is_some()
            || additional > 8
            || self.bootstrap_started
            || self.bootstrap_completion.is_some()
            || self.bootstrap_retirement.is_some()
            || self.started
            || self.completion.is_some()
            || self.retirement.is_some()
            || !self.inner.creator_quiescent()
        {
            return false;
        }
        let mut custody = VecDeque::new();
        let capacity = usize::try_from(additional + 1).unwrap_or(usize::MAX);
        if custody.try_reserve_exact(capacity).is_err() {
            return false;
        }
        self.automatic = Some(AutomaticState {
            remaining: additional,
            custody,
            custody_limit: capacity,
            stopped: false,
        });
        true
    }

    /// Authorize another finite batch after the previous local observation and
    /// creator custody have been handed off. This performs no storage I/O.
    /// A subsequent step must admit and drain the new reservation worker.
    pub fn renew_creator_observation(&mut self, additional: u64) -> bool {
        if self.aborted.get()
            || !(1..=8).contains(&additional)
            || self.bootstrap.is_some()
            || self.bootstrap_started
            || self.bootstrap_completion.is_some()
            || self.reservation.is_some()
            || self.started
            || self.completion.is_some()
            || !self.inner.creator_quiescent()
        {
            return false;
        }
        let Some(automatic) = self.automatic.as_mut() else {
            return false;
        };
        if automatic.stopped || automatic.remaining != 0 || !automatic.custody.is_empty() {
            return false;
        }
        let Some(retirement) = self.retirement.as_ref() else {
            return false;
        };
        if retirement.fenced
            || retirement.aborted
            || retirement.inputs.plan.pending().is_some()
            || !matches!(
                &retirement.inputs.request,
                ReservationRequest::ObservedCreator(_)
            )
            || !matches!(&retirement.outcome, Some(ReservationOutcome::Reconciled(pin)) if retirement.inputs.plan.head() == Some(*pin))
        {
            return false;
        }
        let capacity = additional as usize;
        if automatic.custody.try_reserve_exact(capacity).is_err() {
            return false;
        }
        let Some(mut retirement) = self.retirement.take() else {
            return false;
        };
        if retirement.inputs.plan.remaining() == 0 && retirement.inputs.plan.extend(1).is_err() {
            self.retirement = Some(retirement);
            return false;
        }
        let old_request =
            std::mem::replace(&mut retirement.inputs.request, ReservationRequest::Reserve);
        match ReservationWorker::new(retirement.inputs) {
            Ok(worker) => {
                self.reservation = Some(worker);
                self.start_refused = false;
                automatic.remaining = additional - 1;
                automatic.custody_limit = capacity;
                true
            }
            Err(mut inputs) => {
                inputs.request = old_request;
                retirement.inputs = inputs;
                self.retirement = Some(retirement);
                automatic.stopped = true;
                false
            }
        }
    }

    fn observe_installed_creator(&mut self, completion: &av_rollover_supplies::Completion) -> bool {
        let Some(automatic) = self.automatic.as_ref() else {
            return false;
        };
        if automatic.stopped || automatic.custody.len() >= automatic.custody_limit {
            return false;
        }
        let Some(identity) = self
            .retirement
            .as_ref()
            .and_then(|r| r.inputs.plan.pending())
        else {
            return false;
        };
        let Some(custody) = self.inner.custody() else {
            return false;
        };
        let Some(observation) = CreatorObservation::from_installed(identity, custody, completion)
        else {
            return false;
        };
        let Some(automatic) = self.automatic.as_mut() else {
            return false;
        };
        let Some(custody) = self.inner.take_custody() else {
            return false;
        };
        automatic.custody.push_back(custody);
        let Some(mut retirement) = self.retirement.take() else {
            return false;
        };
        let old_request = std::mem::replace(
            &mut retirement.inputs.request,
            ReservationRequest::ObservedCreator(observation),
        );
        match ReservationWorker::new(retirement.inputs) {
            Ok(worker) => {
                self.reservation = Some(worker);
                self.start_refused = false;
                true
            }
            Err(mut inputs) => {
                inputs.request = old_request;
                retirement.inputs = inputs;
                self.retirement = Some(retirement);
                false
            }
        }
    }

    /// Transfer a failed or partial creator for explicit reconciliation.
    pub fn take_failed(&mut self) -> Option<av_rollover_supplies::Retirement> {
        self.inner.take_failed()
    }

    /// Transfer the reservation plan and outcome only once the creator and its
    /// custody are accounted for. This does not settle the reservation.
    pub fn take_reservation(&mut self) -> Option<ReservationRetirement> {
        if self.bootstrap.is_none()
            && !self.bootstrap_started
            && self.bootstrap_completion.is_none()
            && self.reservation.is_none()
            && !self.started
            && self.completion.is_none()
            && self.inner.creator_quiescent()
            && self
                .automatic
                .as_ref()
                .is_none_or(|state| state.custody.is_empty())
        {
            self.retirement.take()
        } else {
            None
        }
    }

    /// Transfer bootstrap custody only after the reservation, creator and
    /// their outcomes have been accounted for; this does not assert independence.
    pub fn take_bootstrap(&mut self) -> Option<BootstrapRetirement> {
        if self.bootstrap.is_none()
            && !self.bootstrap_started
            && self.bootstrap_completion.is_none()
            && self.reservation.is_none()
            && !self.started
            && self.completion.is_none()
            && self.retirement.is_none()
            && self.inner.creator_quiescent()
            && self
                .automatic
                .as_ref()
                .is_none_or(|state| state.custody.is_empty())
        {
            self.bootstrap_retirement.take()
        } else {
            None
        }
    }

    /// Install another caller-prepared reservation after all previous owners
    /// have been transferred. This never manufactures reconciliation evidence.
    pub fn offer_reservation(
        &mut self,
        reservation: ReservationWorker,
    ) -> Result<(), ReservationWorker> {
        if self.aborted.get()
            || self.bootstrap.is_some()
            || self.bootstrap_started
            || self.bootstrap_completion.is_some()
            || self.bootstrap_retirement.is_some()
            || self.reservation.is_some()
            || self.started
            || self.completion.is_some()
            || self.retirement.is_some()
            || !self.inner.creator_quiescent()
            || !reservation.is_unstarted_reservation()
        {
            return Err(reservation);
        }
        self.reservation = Some(reservation);
        self.start_refused = false;
        Ok(())
    }

    /// Install one caller-prepared reconciliation after prior custody is returned.
    /// The caller must assess the evidence; a digest alone does not prove it.
    pub fn offer_reconciliation(
        &mut self,
        reconciliation: ReservationWorker,
    ) -> Result<(), ReservationWorker> {
        if self.aborted.get()
            || self.bootstrap.is_some()
            || self.bootstrap_started
            || self.bootstrap_completion.is_some()
            || self.bootstrap_retirement.is_some()
            || self.reservation.is_some()
            || self.started
            || self.completion.is_some()
            || self.retirement.is_some()
            || !self.inner.creator_quiescent()
            || !reconciliation.is_unstarted_reconciliation()
        {
            return Err(reconciliation);
        }
        self.reservation = Some(reconciliation);
        self.start_refused = false;
        Ok(())
    }

    /// Permit another bootstrap admission after a pre-start refusal.
    pub fn authorize_bootstrap_retry(&mut self) -> bool {
        if !self.aborted.get()
            && self.bootstrap_refused
            && !self.bootstrap_started
            && self.bootstrap.is_some()
        {
            self.bootstrap_refused = false;
            true
        } else {
            false
        }
    }

    /// Permit a further admission attempt after a pre-start refusal.
    pub fn authorize_reservation_retry(&mut self) -> bool {
        if !self.aborted.get() && self.start_refused && !self.started && self.reservation.is_some()
        {
            self.start_refused = false;
            true
        } else {
            false
        }
    }

    /// Stop new work and request cancellation of both reservation and creator.
    pub fn abort(&mut self) {
        self.aborted.set(true);
        if let Some(bootstrap) = &self.bootstrap {
            bootstrap.abort();
        }
        if let Some(reservation) = &self.reservation {
            reservation.abort();
        }
        self.inner.abort();
    }

    /// Drain the active bootstrap while retaining its result.
    pub async fn join_bootstrap(&mut self) -> bool {
        if self.bootstrap_completion.is_some() {
            return true;
        }
        if !self.bootstrap_started {
            return false;
        }
        let Some(bootstrap) = self.bootstrap.as_mut() else {
            return false;
        };
        if let Some(completion) = bootstrap.join().await {
            self.bootstrap_completion = Some(completion);
            true
        } else {
            false
        }
    }

    /// Drain the active reservation while retaining its completion.
    pub async fn join_reservation(&mut self) -> bool {
        if self.completion.is_some() {
            return true;
        }
        if !self.started {
            return false;
        }
        let Some(reservation) = self.reservation.as_mut() else {
            return false;
        };
        if let Some(completion) = reservation.join().await {
            self.completion = Some(completion);
            true
        } else {
            false
        }
    }

    /// Drain the creator after cancellation.
    pub async fn join_supply(&mut self) -> bool {
        self.inner.join_supply().await
    }
    /// Drain an active rollover after cancellation.
    pub async fn join_rollover(&mut self) -> bool {
        self.inner.join_rollover().await
    }

    /// Advance one bounded step. Pending reservation work never blocks the
    /// controller path; no creator starts before a successful retained receipt.
    pub async fn step(
        &mut self,
        owner: &mut conversation::Owner<'_, 'scope, 'task>,
        operation: &OperationId,
        wait: Duration,
        task: &'scope TaskCx<'task>,
        cx: &'scope Cx,
        clock: MeteredClock<'scope, 'task>,
        av: ArchiveAdmission<'_>,
        source: ArchiveAdmission<'_>,
        cost: &BudgetVector,
    ) -> Step {
        if !self.aborted.get() && self.automatic.as_ref().is_some_and(|state| state.stopped) {
            return Step::AutomaticStopped;
        }
        if !self.aborted.get()
            && !self.bootstrap_started
            && !self.bootstrap_refused
            && self.bootstrap.is_some()
        {
            if owner.cx.checkpoint().is_err()
                || !owner.clock.matches(owner.task, owner.cx)
                || !owner.clock.matches(task, cx)
                || !clock.matches(task, cx)
                || !self.inner.clocks_match(&owner.clock, &clock)
            {
                self.bootstrap_refused = true;
                return Step::BootstrapStartRefused(BootstrapStartError::Context);
            }
            let Some(bootstrap) = self.bootstrap.as_mut() else {
                return Step::OwnershipUnavailable;
            };
            return match bootstrap.start(task, cx, clock, cost) {
                Ok(()) => {
                    self.bootstrap_started = true;
                    Step::BootstrapStarted
                }
                Err(error) => {
                    self.bootstrap_refused = true;
                    Step::BootstrapStartRefused(error)
                }
            };
        }
        if owner.cx.checkpoint().is_err() {
            if let Some(bootstrap) = &self.bootstrap {
                bootstrap.abort();
            }
        }
        if self.bootstrap_started && self.bootstrap_completion.is_none() {
            poll_fn(|context| {
                let mut future = pin!(self.join_bootstrap());
                Poll::Ready(matches!(future.as_mut().poll(context), Poll::Ready(true)))
            })
            .await;
        }
        if self.bootstrap_completion.is_some() && self.bootstrap.is_some() {
            let Some(completion) = self.bootstrap_completion.take() else {
                return Step::OwnershipUnavailable;
            };
            let Some(bootstrap) = self.bootstrap.take() else {
                self.bootstrap_completion = Some(completion);
                return Step::OwnershipUnavailable;
            };
            let mut retirement = match bootstrap.retire() {
                Ok(retirement) => retirement,
                Err(bootstrap) => {
                    self.bootstrap = Some(bootstrap);
                    self.bootstrap_completion = Some(completion);
                    return Step::OwnershipUnavailable;
                }
            };
            self.bootstrap_started = false;
            let safe = !self.aborted.get()
                && completion.runtime.is_ok()
                && !completion.cancellation_requested
                && completion.outcome == BootstrapOutcome::Ready
                && !retirement.fenced;
            if safe {
                if let Some(plan) = retirement.take_ready() {
                    let inputs = ReservationInputs {
                        plan,
                        request: ReservationRequest::Reserve,
                        journal_resource: retirement.storage.journal_root.clone(),
                        custody_resource: retirement.storage.custody_root.clone(),
                        journal_replay: retirement.storage.journal_replay.clone(),
                        custody_replay: retirement.storage.custody_replay.clone(),
                    };
                    match ReservationWorker::new(inputs) {
                        Ok(reservation) => {
                            self.reservation = Some(reservation);
                            self.bootstrap_retirement = Some(retirement);
                            return Step::BootstrapReady;
                        }
                        Err(inputs) => {
                            retirement.ready = Some(inputs.plan);
                        }
                    }
                }
            }
            self.bootstrap_retirement = Some(retirement);
            return Step::BootstrapStopped(completion);
        }
        if !self.aborted.get() && !self.started && !self.start_refused && self.reservation.is_some()
        {
            if owner.cx.checkpoint().is_err()
                || !owner.clock.matches(owner.task, owner.cx)
                || !owner.clock.matches(task, cx)
                || !clock.matches(task, cx)
                || !self.inner.clocks_match(&owner.clock, &clock)
            {
                self.start_refused = true;
                return Step::ReservationStartRefused(ReservationStartError::Context);
            }
            let Some(reservation) = self.reservation.as_mut() else {
                return Step::OwnershipUnavailable;
            };
            return match reservation.start(task, cx, clock, cost) {
                Ok(()) => {
                    self.started = true;
                    Step::ReservationStarted
                }
                Err(error) => {
                    self.start_refused = true;
                    Step::ReservationStartRefused(error)
                }
            };
        }
        if owner.cx.checkpoint().is_err() {
            if let Some(reservation) = &self.reservation {
                reservation.abort();
            }
        }
        if self.started && self.completion.is_none() {
            poll_fn(|context| {
                let mut future = pin!(self.join_reservation());
                Poll::Ready(matches!(future.as_mut().poll(context), Poll::Ready(true)))
            })
            .await;
        }
        if self.completion.is_some() && self.reservation.is_some() {
            let Some(completion) = self.completion.take() else {
                return Step::OwnershipUnavailable;
            };
            let Some(reservation) = self.reservation.take() else {
                self.completion = Some(completion);
                return Step::OwnershipUnavailable;
            };
            let mut retirement = match reservation.retire() {
                Ok(retirement) => retirement,
                Err(reservation) => {
                    self.reservation = Some(reservation);
                    self.completion = Some(completion);
                    return Step::OwnershipUnavailable;
                }
            };
            self.started = false;
            let safe = !self.aborted.get()
                && completion.runtime.is_ok()
                && !completion.indeterminate
                && !completion.cancellation_requested
                && !retirement.fenced
                && !retirement.aborted;
            let matches_pending = match &retirement.outcome {
                Some(ReservationOutcome::Reserved { identity, .. }) => {
                    retirement.inputs.plan.pending() == Some(identity)
                }
                _ => false,
            };
            if safe && matches_pending {
                if let Some(ReservationOutcome::Reserved { identity, worker }) =
                    retirement.outcome.take()
                {
                    match self.inner.offer_worker(worker) {
                        Ok(()) => {
                            self.retirement = Some(retirement);
                            return Step::Reserved(identity);
                        }
                        Err(worker) => {
                            retirement.outcome =
                                Some(ReservationOutcome::Reserved { identity, worker });
                        }
                    }
                }
            }
            if safe {
                if let Some(ReservationOutcome::Reconciled(pin)) = &retirement.outcome {
                    if matches!(
                        &retirement.inputs.request,
                        ReservationRequest::Reconcile { .. }
                            | ReservationRequest::ObservedCreator(_)
                    ) && retirement.inputs.plan.pending().is_none()
                        && retirement.inputs.plan.head() == Some(*pin)
                    {
                        let pin = *pin;
                        let observed = matches!(
                            &retirement.inputs.request,
                            ReservationRequest::ObservedCreator(_)
                        );
                        if observed
                            && self
                                .automatic
                                .as_ref()
                                .is_some_and(|state| state.remaining > 0)
                        {
                            if retirement.inputs.plan.remaining() == 0
                                && retirement.inputs.plan.extend(1).is_err()
                            {
                                if let Some(automatic) = self.automatic.as_mut() {
                                    automatic.stopped = true;
                                }
                                self.retirement = Some(retirement);
                                return Step::ReservationStopped(completion);
                            }
                            let old_request = std::mem::replace(
                                &mut retirement.inputs.request,
                                ReservationRequest::Reserve,
                            );
                            match ReservationWorker::new(retirement.inputs) {
                                Ok(worker) => {
                                    self.reservation = Some(worker);
                                    if let Some(automatic) = self.automatic.as_mut() {
                                        automatic.remaining -= 1;
                                    }
                                    return Step::Reconciled(pin);
                                }
                                Err(mut inputs) => {
                                    inputs.request = old_request;
                                    retirement.inputs = inputs;
                                    if let Some(automatic) = self.automatic.as_mut() {
                                        automatic.stopped = true;
                                    }
                                    self.retirement = Some(retirement);
                                    return Step::ReservationStopped(completion);
                                }
                            }
                        }
                        self.retirement = Some(retirement);
                        return Step::Reconciled(pin);
                    }
                }
            }
            self.retirement = Some(retirement);
            return Step::ReservationStopped(completion);
        }
        if self.aborted.get() {
            return Step::Aborted;
        }
        let step = self
            .inner
            .step(owner, operation, wait, task, cx, clock, av, source, cost)
            .await;
        if self.automatic.is_some() {
            if let video_provision::Step::SupplyInstalled(completion) = step {
                if self.observe_installed_creator(&completion) {
                    return Step::Session(video_provision::Step::SupplyInstalled(completion));
                }
                if let Some(automatic) = self.automatic.as_mut() {
                    automatic.stopped = true;
                }
                return Step::AutomaticRefused(completion);
            }
        }
        let exhausted = self
            .automatic
            .as_ref()
            .is_some_and(|state| state.remaining == 0)
            && self.retirement.as_ref().is_some_and(|retirement| {
                matches!(&retirement.outcome, Some(ReservationOutcome::Reconciled(_)))
            })
            && matches!(
                &step,
                video_provision::Step::Managed(
                    super::video_session::ManagedStep::SuppliesRequired(_)
                )
            );
        if exhausted {
            Step::AutomaticExhausted(step)
        } else {
            Step::Session(step)
        }
    }

    /// Recover all owners, including an undrained reservation or creator.
    pub fn into_parts(self) -> Owners<'scope, 'task, IO> {
        Owners {
            inner: self.inner,
            bootstrap: self.bootstrap,
            bootstrap_started: self.bootstrap_started,
            bootstrap_refused: self.bootstrap_refused,
            bootstrap_completion: self.bootstrap_completion,
            bootstrap_retirement: self.bootstrap_retirement,
            reservation: self.reservation,
            started: self.started,
            start_refused: self.start_refused,
            completion: self.completion,
            retirement: self.retirement,
            automatic: self.automatic,
            aborted: self.aborted.get(),
        }
    }
}
