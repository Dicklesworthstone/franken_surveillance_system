#![forbid(unsafe_code)]
//! Canonically owned, synchronous execution of bounded native work.
//!
//! The closure is entered only after task registration. Its context exclusively
//! borrows the original authority and region tree, so neither can be finalized
//! or replaced while the work runs. The closure must own its native resources
//! and return only its result/retirement data, after closing those resources.
//! Only this outer boundary can publish the task's terminal receipt.
//!
//! This module does not spawn, detach, preempt, read clocks, or manufacture
//! Asupersync capabilities. It preserves the cancellation-only `Cx<cap::None>`
//! underneath `AuthorityCx`. A blocking operation still needs a bounded native
//! timeout and cooperative checkpoints. An unwind leaves the task active and
//! visible in the canonical tree; it never manufactures a cancellation receipt.

use std::cell::{RefCell, RefMut};

use fss_core::effect::{Obligation, ObligationState};
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, ObligationId, RegionError, RegionId,
    RegionState, RegionTree, RuntimeGrant, TaskId, TaskOutcome, TaskReceipt, TimestampNs,
};

use crate::authority::{AuthorityCx, AuthorityError};
use crate::budget::LedgerError;
use crate::grant::GrantError;
use crate::obligation::ObligationTerminal;

/// Identity and caller-observed registration time for one actual execution.
#[derive(Clone, Debug)]
pub struct TaskSpec {
    /// One task identity, never reused within its canonical region.
    pub task_id: TaskId,
    /// Time in the same explicitly supplied clock domain as the authority deadline.
    pub started_at: TimestampNs,
}

/// A closure's domain result and proposed terminal classification.
///
/// Returning this value does not itself complete a task. `run_owned` validates
/// it and publishes the receipt after the closure has returned. `output` must
/// contain result or retirement data, not live native resources or work handles.
pub struct TaskCompletion<T> {
    /// The native result, including partial custody and domain failures.
    pub output: T,
    /// Domain classification after native resources have been closed.
    pub outcome: TaskOutcome,
    /// Caller-observed completion time; cannot precede any observed checkpoint.
    pub completed_at: TimestampNs,
}

/// A returned native result and the independent canonical receipt result.
pub struct TaskRun<T> {
    /// Always preserved once the closure returns, even if receipt validation fails.
    pub output: T,
    /// A refused receipt leaves the task active for explicit recovery.
    pub receipt: Result<TaskReceipt, ExecutionError>,
}

/// A refusal at an owned execution boundary.
#[derive(Debug)]
pub enum ExecutionError {
    /// The actual authority, tree or lifecycle refused the operation.
    Authority(AuthorityError),
    /// A required resource-scoped capability is absent.
    Grant(GrantError),
    /// An atomic multidimensional debit did not fit the remaining allowance.
    Budget(LedgerError),
    /// The caller's clock moved backwards.
    ClockRegression {
        /// Latest previously observed time.
        previous: TimestampNs,
        /// Rejected time.
        observed: TimestampNs,
    },
    /// New I/O or cleanup work reached the scope's exact deadline.
    Deadline {
        /// Immutable scope deadline.
        deadline: TimestampNs,
        /// Caller-observed time at refusal.
        observed: TimestampNs,
    },
    /// Cleanup requires an explicit transition to drain.
    NotDraining,
    /// A nested callback tried to enter while this context was already borrowed.
    BoundaryBusy,
    /// The active task registration no longer matches this execution.
    RegistrationChanged,
    /// Terminal classification, time or reconciliation evidence is inconsistent.
    InvalidCompletion,
    /// A caller attempted to account for dimensions the ledger does not meter.
    UnmeteredCost,
    /// An obligation names another operation.
    ObligationOwnerMismatch,
}

impl std::fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authority(error) => write!(f, "owned task authority: {error}"),
            Self::Grant(error) => write!(f, "owned task grant: {error}"),
            Self::Budget(error) => write!(f, "owned task budget: {error}"),
            Self::ClockRegression { previous, observed } => write!(
                f,
                "owned task clock regressed from {} to {}",
                previous.0, observed.0
            ),
            Self::Deadline { deadline, observed } => write!(
                f,
                "owned task deadline {} reached at {}",
                deadline.0, observed.0
            ),
            Self::NotDraining => f.write_str("owned task cleanup requires explicit drain"),
            Self::BoundaryBusy => f.write_str("owned task boundary is already borrowed"),
            Self::RegistrationChanged => f.write_str("owned task registration changed"),
            Self::InvalidCompletion => f.write_str("owned task completion is inconsistent"),
            Self::UnmeteredCost => f.write_str("owned task cost names an unmetered dimension"),
            Self::ObligationOwnerMismatch => f.write_str("owned task obligation owner mismatch"),
        }
    }
}

impl std::error::Error for ExecutionError {}

impl From<AuthorityError> for ExecutionError {
    fn from(error: AuthorityError) -> Self {
        Self::Authority(error)
    }
}

impl From<RegionError> for ExecutionError {
    fn from(error: RegionError) -> Self {
        Self::Authority(AuthorityError::Region(error))
    }
}

struct ExecutionState<'a> {
    authority: &'a mut AuthorityCx,
    tree: &'a mut RegionTree,
    last_observed: TimestampNs,
    draining: bool,
    cancellation_requested: bool,
    deadline_reached: bool,
}

/// A non-cloneable context for the closure currently executing one registered task.
///
/// The private `RefCell` permits the `&self` checkpoints required by existing
/// native authority callbacks. It exposes no mutable authority, ledger, or tree.
/// It is not `Sync` and cannot become a shared asynchronous task supervisor.
pub struct TaskCx<'a> {
    state: RefCell<ExecutionState<'a>>,
    context: ContextAuthority,
    region: RegionId,
    task_id: TaskId,
    registered_at: TimestampNs,
}

impl<'a> TaskCx<'a> {
    /// Immutable authority metadata for existing request/custody interfaces.
    /// This snapshot does not replace live admission through this task context.
    pub fn context(&self) -> &ContextAuthority {
        &self.context
    }

    /// Canonical region that owns this execution.
    pub fn region(&self) -> &RegionId {
        &self.region
    }

    /// Canonical task identity.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    fn state(&self) -> Result<RefMut<'_, ExecutionState<'a>>, ExecutionError> {
        self.state
            .try_borrow_mut()
            .map_err(|_| ExecutionError::BoundaryBusy)
    }

    fn check_registration(&self, state: &ExecutionState<'_>) -> Result<(), ExecutionError> {
        state.authority.require_bound(state.tree)?;
        let node = state.tree.get(&self.region)?;
        if node.active_tasks.get(&self.task_id) != Some(&self.registered_at)
            || node.completed_tasks.contains_key(&self.task_id)
        {
            return Err(ExecutionError::RegistrationChanged);
        }
        Ok(())
    }

    fn observe_time(
        state: &mut ExecutionState<'_>,
        now: TimestampNs,
    ) -> Result<(), ExecutionError> {
        if now < state.last_observed {
            return Err(ExecutionError::ClockRegression {
                previous: state.last_observed,
                observed: now,
            });
        }
        // Even a refused admission observes time. Retrying with an older clock
        // cannot restore a deadline or erase an intervening refusal.
        state.last_observed = now;
        Ok(())
    }

    fn check_deadline(
        &self,
        state: &mut ExecutionState<'_>,
        now: TimestampNs,
    ) -> Result<(), ExecutionError> {
        if let Some(deadline) = self.context.deadline
            && now >= deadline
        {
            state.deadline_reached = true;
            return Err(ExecutionError::Deadline {
                deadline,
                observed: now,
            });
        }
        Ok(())
    }

    fn admit(
        &self,
        now: TimestampNs,
        cost: &BudgetVector,
        grant: Option<(RuntimeGrant, &str)>,
        cleanup: bool,
    ) -> Result<(), ExecutionError> {
        let mut state = self.state()?;
        self.check_registration(&state)?;
        Self::observe_time(&mut state, now)?;
        self.check_deadline(&mut state, now)?;
        if cleanup {
            if !state.draining || state.tree.get(&self.region)?.state != RegionState::Draining {
                return Err(ExecutionError::NotDraining);
            }
        } else {
            state.authority.require_active(state.tree)?;
        }
        if let Some((grant, resource)) = grant {
            state
                .authority
                .require_grant_for(grant, resource)
                .map_err(ExecutionError::Grant)?;
        }
        if cost.privacy_exposure() != 0.0 || cost.operator_attention_seconds() != 0.0 {
            return Err(ExecutionError::UnmeteredCost);
        }
        let ExecutionState {
            authority, tree, ..
        } = &mut *state;
        authority
            .budget_mut(tree)?
            .spend_vector(cost)
            .map_err(ExecutionError::Budget)
    }

    /// Admit new bounded work and debit its complete metered cost atomically.
    /// Capability-sensitive boundaries additionally use `checkpoint_for`.
    pub fn checkpoint(&self, now: TimestampNs, cost: &BudgetVector) -> Result<(), ExecutionError> {
        self.admit(now, cost, None, false)
    }

    /// Admit new work for one exact resource after checking its current grant.
    pub fn checkpoint_for(
        &self,
        grant: RuntimeGrant,
        resource: &str,
        now: TimestampNs,
        cost: &BudgetVector,
    ) -> Result<(), ExecutionError> {
        self.admit(now, cost, Some((grant, resource)), false)
    }

    /// Admit bounded cleanup after `begin_drain`, within the original deadline
    /// and remaining allowance. Adapters keep new receive/start/effect work on
    /// `checkpoint`; this method never reopens that admission path.
    pub fn cleanup_checkpoint(
        &self,
        now: TimestampNs,
        cost: &BudgetVector,
    ) -> Result<(), ExecutionError> {
        self.admit(now, cost, None, true)
    }

    /// Resource-scoped cleanup admission; it does not restore cancelled work.
    pub fn cleanup_checkpoint_for(
        &self,
        grant: RuntimeGrant,
        resource: &str,
        now: TimestampNs,
        cost: &BudgetVector,
    ) -> Result<(), ExecutionError> {
        self.admit(now, cost, Some((grant, resource)), true)
    }

    /// Request cancellation of this canonical scope and its descendants.
    /// Metadata-only shutdown remains possible after the execution deadline.
    pub fn request_cancellation(&self, now: TimestampNs) -> Result<(), ExecutionError> {
        let mut state = self.state()?;
        self.check_registration(&state)?;
        Self::observe_time(&mut state, now)?;
        let ExecutionState {
            authority, tree, ..
        } = &mut *state;
        authority.request_cancellation(tree, now)?;
        state.cancellation_requested = true;
        Ok(())
    }

    /// Stop admitting new work and enter canonical drain. A normal completed
    /// capture may drain successfully; an explicitly cancelled task cannot later
    /// publish `Success`. Existing obligations remain live until resolved.
    pub fn begin_drain(&self, now: TimestampNs) -> Result<(), ExecutionError> {
        let mut state = self.state()?;
        self.check_registration(&state)?;
        Self::observe_time(&mut state, now)?;
        if state.draining {
            return Ok(());
        }
        let ExecutionState {
            authority, tree, ..
        } = &mut *state;
        tree.request_drain(&self.region, Some("owned task admission closed"), now)?;
        authority.begin_drain(tree, now)?;
        state.draining = true;
        Ok(())
    }

    /// Reflect canonical cancellation into the existing Asupersync primitive.
    /// Drain also closes admission; this method does not itself prove quiescence.
    pub fn is_cancel_requested(&self) -> Result<bool, ExecutionError> {
        let state = self.state()?;
        self.check_registration(&state)?;
        state
            .authority
            .is_cancel_requested(state.tree)
            .map_err(ExecutionError::Authority)
    }

    /// Inspect remaining metered capacity without exposing a mutable ledger.
    pub fn remaining_budget(&self) -> Result<BudgetVector, ExecutionError> {
        let state = self.state()?;
        self.check_registration(&state)?;
        Ok(state.authority.budget().remaining())
    }

    /// Register an obligation before starting consequential work. The obligation
    /// must name this scope's operation, and remains canonical after this task ends.
    pub fn register_obligation(
        &self,
        obligation: Obligation,
        now: TimestampNs,
    ) -> Result<(), ExecutionError> {
        let mut state = self.state()?;
        self.check_registration(&state)?;
        Self::observe_time(&mut state, now)?;
        self.check_deadline(&mut state, now)?;
        if obligation.operation_id != self.context.operation_id {
            return Err(ExecutionError::ObligationOwnerMismatch);
        }
        let ExecutionState {
            authority, tree, ..
        } = &mut *state;
        authority.register_obligation(tree, obligation)?;
        Ok(())
    }

    /// Resolve an owned obligation using the canonical transition rules. This is
    /// a metadata transition, including during drain; it does not perform I/O or
    /// infer completion of storage, network or physical work.
    pub fn resolve_obligation(
        &self,
        obligation_id: &ObligationId,
        terminal: ObligationTerminal,
        proof_digest: Option<ContentDigest>,
        reconciliation_note: Option<&str>,
        now: TimestampNs,
    ) -> Result<(), ExecutionError> {
        let mut state = self.state()?;
        self.check_registration(&state)?;
        Self::observe_time(&mut state, now)?;
        let node = state.tree.get(&self.region)?;
        let obligation = node
            .obligations
            .get(obligation_id)
            .ok_or_else(|| RegionError::ObligationNotFound(obligation_id.clone()))?;
        if obligation.operation_id != self.context.operation_id {
            return Err(ExecutionError::ObligationOwnerMismatch);
        }
        let ExecutionState {
            authority, tree, ..
        } = &mut *state;
        authority.resolve_obligation(
            tree,
            obligation_id,
            terminal,
            proof_digest,
            reconciliation_note,
        )?;
        Ok(())
    }

    fn complete_after_return(
        self,
        outcome: TaskOutcome,
        now: TimestampNs,
    ) -> Result<TaskReceipt, ExecutionError> {
        let mut state = self.state.into_inner();
        state.authority.require_bound(state.tree)?;
        Self::observe_time(&mut state, now)?;
        let node = state.tree.get(&self.region)?;
        if node.active_tasks.get(&self.task_id) != Some(&self.registered_at)
            || node.completed_tasks.contains_key(&self.task_id)
        {
            return Err(ExecutionError::RegistrationChanged);
        }
        match &outcome {
            TaskOutcome::Success if state.cancellation_requested || state.deadline_reached => {
                return Err(ExecutionError::InvalidCompletion);
            }
            TaskOutcome::Success
                if self
                    .context
                    .deadline
                    .is_some_and(|deadline| now >= deadline) =>
            {
                return Err(ExecutionError::Deadline {
                    deadline: self
                        .context
                        .deadline
                        .ok_or(ExecutionError::InvalidCompletion)?,
                    observed: now,
                });
            }
            TaskOutcome::Cancelled if !state.cancellation_requested => {
                return Err(ExecutionError::InvalidCompletion);
            }
            TaskOutcome::Failed(reason) | TaskOutcome::Indeterminate(reason)
                if reason.trim().is_empty()
                    || reason.len() > 256
                    || reason.chars().any(char::is_control) =>
            {
                return Err(ExecutionError::InvalidCompletion);
            }
            _ => {}
        }
        if matches!(outcome, TaskOutcome::Indeterminate(_))
            && !node.obligations.values().any(|obligation| {
                obligation.operation_id == self.context.operation_id
                    && (obligation.state == ObligationState::Pending
                        || (obligation.state == ObligationState::Indeterminate
                            && node
                                .reconciliation_obligations
                                .get(&obligation.obligation_id)
                                .is_some_and(|note| !note.trim().is_empty())))
            })
        {
            return Err(ExecutionError::InvalidCompletion);
        }
        state
            .tree
            .complete_task(&self.region, &self.task_id, outcome, now)
            .map_err(ExecutionError::from)
    }
}

/// Execute one synchronous, canonically registered task.
///
/// Admission failures leave the closure uncalled. The exclusive authority/tree
/// borrows last for the complete execution. The only terminal transition occurs
/// after the closure returns, preserving its output even if completion is refused.
/// A panic deliberately unwinds without removing the active task registration.
///
/// ```compile_fail
/// # #![forbid(unsafe_code)]
/// use fss_core::{RegionTree, TaskOutcome, TimestampNs};
/// use fss_runtime::authority::AuthorityCx;
/// use fss_runtime::execution::{TaskCompletion, TaskSpec, run_owned};
/// fn close_live_work(authority: &mut AuthorityCx, tree: &mut RegionTree, spec: TaskSpec) {
///     let region = authority.region().clone();
///     let _ = run_owned(authority, tree, spec, |_| {
///         // The execution boundary still exclusively owns the actual tree.
///         let _ = tree.finalize(&region, TimestampNs(3));
///         TaskCompletion { output: (), outcome: TaskOutcome::Success, completed_at: TimestampNs(4) }
///     });
/// }
/// ```
pub fn run_owned<T>(
    authority: &mut AuthorityCx,
    tree: &mut RegionTree,
    spec: TaskSpec,
    work: impl FnOnce(&TaskCx<'_>) -> TaskCompletion<T>,
) -> Result<TaskRun<T>, ExecutionError> {
    authority.require_active(tree)?;
    let node = tree.get(authority.region())?;
    let previous = node
        .active_tasks
        .values()
        .copied()
        .chain(
            node.completed_tasks
                .values()
                .map(|receipt| receipt.completed_at),
        )
        .fold(node.created_at, TimestampNs::max);
    if spec.started_at < previous {
        return Err(ExecutionError::ClockRegression {
            previous,
            observed: spec.started_at,
        });
    }
    let context = node.authority.clone();
    if let Some(deadline) = context.deadline
        && spec.started_at >= deadline
    {
        return Err(ExecutionError::Deadline {
            deadline,
            observed: spec.started_at,
        });
    }
    let region = authority.region().clone();
    tree.register_task(&region, spec.task_id.clone(), spec.started_at)?;
    let cx = TaskCx {
        state: RefCell::new(ExecutionState {
            authority,
            tree,
            last_observed: spec.started_at,
            draining: false,
            cancellation_requested: false,
            deadline_reached: false,
        }),
        context,
        region,
        task_id: spec.task_id,
        registered_at: spec.started_at,
    };
    let TaskCompletion {
        output,
        outcome,
        completed_at,
    } = work(&cx);
    let receipt = cx.complete_after_return(outcome, completed_at);
    Ok(TaskRun { output, receipt })
}
