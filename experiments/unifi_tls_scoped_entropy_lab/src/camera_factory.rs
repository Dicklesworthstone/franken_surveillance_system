#![forbid(unsafe_code)]
//! Experimental camera-specific setup factory for the fleet supervisor.
//!
//! Owner-enrolled plans are added explicitly; discovering a network claim is
//! neither enrollment nor permission to use credentials or change a camera.

use crate::{
    camera_setup,
    fleet_leased::{self, AutomaticWork, PlanRegistrationRefusal, RetryCompletion},
    owned::offload::Lease,
    prepared_camera::{self, Attempt, Parameters},
};
use fss_core::OperationId;
use fss_reference::unifi_direct::{
    camera_api::VideoProfileLimits,
    discovery::{
        fleet::{Enrollment, Fleet, State},
        pump::CameraWork,
    },
    setup,
};
use std::{cell::RefCell, io, rc::Rc, sync::Arc};

const MAX_CAMERAS: usize = 128;
const MAX_ATTEMPTS: usize = 16;

/// A caller-generated, public run nonce for distinct local operation IDs.
/// The caller must ensure uniqueness across restarts and retain the journal.
#[derive(Clone, Copy)]
pub struct RunId([u8; 16]);
impl RunId {
    /// Refuse the all-zero nonce. Randomness and uniqueness are caller duties.
    pub fn new(nonce: [u8; 16]) -> io::Result<Self> {
        if nonce == [0; 16] {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self(nonce))
    }
    /// Consume a task-owned trial-run entropy lease to create a fresh run ID.
    /// The lease requires the `trial:run-identity-entropy` resource; its bytes
    /// are not reused for TLS. Cross-restart uniqueness is probabilistic.
    pub fn from_lease(lease: Lease<'_, '_>) -> io::Result<Self> {
        Self::new(lease.trial_public_nonce()?)
    }
    /// Produce the operation identity for one bounded enrollment/attempt pair.
    pub fn operation(&self, index: usize, attempt: usize) -> io::Result<OperationId> {
        if index >= MAX_CAMERAS || attempt >= MAX_ATTEMPTS {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let nonce: String = self.0.iter().map(|byte| format!("{byte:02x}")).collect();
        OperationId::parse(format!(
            "operation:unifi-auto-{nonce}-{index:04x}-{attempt:02x}"
        ))
        .map_err(|_| io::ErrorKind::InvalidInput.into())
    }
}

/// An owner-supplied camera plan and the state retained for its attempts.
/// Fields that can grant authority remain supplied and owned by the caller.
#[must_use = "retain the plan and its attempt records for reconciliation"]
pub struct Plan<'work, 'owner, 'report, 'scope, 'task, 'policy> {
    parameters: Parameters<'work, 'report, 'scope, 'task, 'policy>,
    owner: Rc<RefCell<setup::Owner<'owner, 'scope, 'task>>>,
    spool: Rc<RefCell<fss_object::StagingSpool>>,
    limit: usize,
    profile: Option<VideoProfileLimits>,
    attempts: Vec<Rc<RefCell<Attempt<'scope, 'task>>>>,
}
impl<'work, 'owner, 'report, 'scope, 'task, 'policy>
    Plan<'work, 'owner, 'report, 'scope, 'task, 'policy>
{
    /// Construct an unadmitted plan. Registration validates its bounds and binding.
    pub fn new(
        parameters: Parameters<'work, 'report, 'scope, 'task, 'policy>,
        owner: Rc<RefCell<setup::Owner<'owner, 'scope, 'task>>>,
        spool: Rc<RefCell<fss_object::StagingSpool>>,
        limit: usize,
        profile: Option<VideoProfileLimits>,
    ) -> Self {
        Self {
            parameters,
            owner,
            spool,
            limit,
            profile,
            attempts: Vec::new(),
        }
    }

    /// Number of attempt records still retained by this plan.
    pub fn attempt_count(&self) -> usize {
        self.attempts.len()
    }

    /// Retain one attempt for inspection or worker draining after factory retirement.
    pub fn attempt(&self, ordinal: usize) -> Option<Rc<RefCell<Attempt<'scope, 'task>>>> {
        self.attempts.get(ordinal).cloned()
    }

    /// Retain the exact setup owner for effect reconciliation.
    pub fn owner(&self) -> Rc<RefCell<setup::Owner<'owner, 'scope, 'task>>> {
        self.owner.clone()
    }

    /// Retain the evidence spool associated with this plan.
    pub fn spool(&self) -> Rc<RefCell<fss_object::StagingSpool>> {
        self.spool.clone()
    }
}

/// A plan could not be registered; the exact plan is returned to its caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// Plan or enrollment does not match this factory's fleet.
    Binding,
    /// This inventory index already has a plan.
    Duplicate,
    /// Camera/attempt bounds or profile limits are invalid.
    Configuration,
    /// The bounded owner could not reserve storage.
    Allocation,
}

/// Why an atomic plan registration and selection rearm was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatedRefusal {
    /// The plan itself was not admissible.
    Plan(Refusal),
    /// The setup owner could not safely admit or rearm this plan.
    Supervisor(PlanRegistrationRefusal),
}

/// Effect on the automatic setup owner's selection latch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Registration {
    /// No selection had failed; the plan is available for future selection.
    Available,
    /// This factory's exact missing-plan selection was safely rearmed.
    Rearmed,
}

/// Caller-owned plan inventory. Work is constructed only when the supervisor
/// asks for a ready enrollment. All attempt traces and workers remain retained.
/// Dropping this owner is not restart recovery; retire its attempts explicitly.
#[must_use = "retain plans and reconcile their attempts before dropping the factory"]
pub struct Factory<'fleet, 'work, 'owner, 'report, 'scope, 'task, 'policy> {
    fleet: &'fleet Fleet<'report>,
    run: RunId,
    identity: Arc<()>,
    plans: Vec<Plan<'work, 'owner, 'report, 'scope, 'task, 'policy>>,
}

impl<'fleet, 'work, 'owner, 'report, 'scope, 'task, 'policy>
    Factory<'fleet, 'work, 'owner, 'report, 'scope, 'task, 'policy>
where
    'owner: 'work,
    'report: 'work,
    'scope: 'work,
    'task: 'scope,
    'policy: 'scope,
{
    /// Bind an empty plan inventory to one caller-selected fleet and run ID.
    pub fn new(fleet: &'fleet Fleet<'report>, run: RunId) -> io::Result<Self> {
        let mut plans = Vec::new();
        plans
            .try_reserve_exact(MAX_CAMERAS)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        Ok(Self {
            fleet,
            run,
            identity: Arc::new(()),
            plans,
        })
    }

    /// Check whether this factory is bound to this exact fleet owner.
    pub fn matches_fleet(&self, fleet: &Fleet<'_>) -> bool {
        std::ptr::eq(self.fleet, fleet)
    }

    /// Add a newly owner-enrolled camera without polling or starting work.
    pub fn register(
        &mut self,
        mut plan: Plan<'work, 'owner, 'report, 'scope, 'task, 'policy>,
    ) -> Result<
        (),
        (
            Refusal,
            Plan<'work, 'owner, 'report, 'scope, 'task, 'policy>,
        ),
    > {
        if !std::ptr::eq(self.fleet, plan.parameters.fleet)
            || self.fleet.enrollment(plan.parameters.index) != Some(plan.parameters.enrollment)
        {
            return Err((Refusal::Binding, plan));
        }
        if self
            .plans
            .iter()
            .any(|existing| existing.parameters.index == plan.parameters.index)
        {
            return Err((Refusal::Duplicate, plan));
        }
        if self.plans.len() == MAX_CAMERAS
            || !(1..=MAX_ATTEMPTS).contains(&plan.limit)
            || plan.profile.is_some_and(|limits| {
                setup::Trace::default()
                    .require_reported_video(limits)
                    .is_err()
            })
        {
            return Err((Refusal::Configuration, plan));
        }
        if plan.attempts.try_reserve_exact(plan.limit).is_err() {
            return Err((Refusal::Allocation, plan));
        }
        self.plans.push(plan);
        Ok(())
    }

    /// Register a plan and rearm only this factory's preceding missing-plan
    /// selection. Other failures and effect outcomes still require their own
    /// reconciliation. The exact plan is returned unchanged on refusal.
    pub fn register_with_supervisor<'other, 'pending, W>(
        &mut self,
        plan: Plan<'work, 'owner, 'report, 'scope, 'task, 'policy>,
        automatic: &mut AutomaticWork<'other, 'report, 'pending, W>,
    ) -> Result<
        Registration,
        (
            CoordinatedRefusal,
            Plan<'work, 'owner, 'report, 'scope, 'task, 'policy>,
        ),
    > {
        let index = plan.parameters.index;
        let rearm = match automatic.check_plan_registration(self.fleet, index, &self.identity) {
            Ok(rearm) => rearm,
            Err(reason) => return Err((CoordinatedRefusal::Supervisor(reason), plan)),
        };
        if let Err((reason, plan)) = self.register(plan) {
            return Err((CoordinatedRefusal::Plan(reason), plan));
        }
        automatic.commit_plan_registration(index, rearm);
        Ok(if rearm {
            Registration::Rearmed
        } else {
            Registration::Available
        })
    }

    /// Number of retained attempts for an enrolled camera.
    pub fn attempt_count(&self, index: usize) -> Option<usize> {
        self.plans
            .iter()
            .find(|plan| plan.parameters.index == index)
            .map(|plan| plan.attempts.len())
    }

    /// Retain one exact attempt for inspection, draining or reconciliation.
    pub fn attempt(
        &self,
        index: usize,
        ordinal: usize,
    ) -> Option<Rc<RefCell<Attempt<'scope, 'task>>>> {
        self.plans
            .iter()
            .find(|plan| plan.parameters.index == index)?
            .attempts
            .get(ordinal)
            .cloned()
    }

    /// Produce one fresh unpolled attempt for a ready, exactly matched plan.
    /// A previous unstarted, undrained or uncancelled prepared attempt prevents
    /// another. The retry coordinator, not this method, decides when to rearm.
    pub fn take(
        &mut self,
        index: usize,
        enrollment: Enrollment,
    ) -> io::Result<CameraWork<'work, RetryCompletion<Result<setup::Outcome, camera_setup::Error>>>>
    {
        if self.fleet.enrollment(index) != Some(enrollment) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if !matches!(self.fleet.state(index), Some(State::Ready { .. })) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let Some(plan) = self
            .plans
            .iter_mut()
            .find(|plan| plan.parameters.index == index)
        else {
            return Err(fleet_leased::missing_plan(self.identity.clone(), index));
        };
        if plan.parameters.enrollment != enrollment {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if plan.attempts.len() == plan.limit {
            return Err(io::Error::other("camera setup attempt limit reached"));
        }
        if let Some(previous) = plan.attempts.last() {
            let previous = previous
                .try_borrow()
                .map_err(|_| io::ErrorKind::WouldBlock)?;
            if !previous.started()
                || !previous.workers_drained()
                || (previous.trace().operation().is_some()
                    && !previous.trace().preparation_cancelled())
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }
        let operation = self.run.operation(index, plan.attempts.len())?;
        let mut attempt = Attempt::new(operation);
        if let Some(limits) = plan.profile {
            attempt
                .trace_mut()
                .map_err(|_| io::ErrorKind::InvalidInput)?
                .require_reported_video(limits)
                .map_err(|_| io::ErrorKind::InvalidInput)?;
        }
        let attempt = Rc::new(RefCell::new(attempt));
        let prepared = prepared_camera::prepare(
            plan.parameters.clone(),
            plan.owner.clone(),
            plan.spool.clone(),
            attempt.clone(),
        )
        .map_err(|_| io::ErrorKind::InvalidInput)?;
        let (_, _, operation, work) = prepared.into_parts();
        plan.attempts.push(attempt);
        Ok(Box::pin(async move {
            RetryCompletion {
                operation,
                output: work.await,
            }
        }))
    }

    /// Return all plans and retained attempt records to their owner.
    pub fn into_plans(self) -> Vec<Plan<'work, 'owner, 'report, 'scope, 'task, 'policy>> {
        self.plans
    }
}
