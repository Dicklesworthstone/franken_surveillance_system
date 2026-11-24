#![forbid(unsafe_code)]
//! Structured `asupersync::Cx` + canonical [`RegionTree`] runner enforcing `request -> drain -> finalize`.
//!
//! Semantic plane: `"authority"`.
//!
//! Binds real `asupersync` tasks (`runtime_cx.spawn(...)`) directly to canonical
//! `fss_core::RegionTree` task registrations and durable obligations so that region
//! closure verifies `active_tasks == 0` and `leaked_obligations == 0`, and non-cooperative
//! tasks draining past the deadline settle honestly as `TaskOutcome::Indeterminate` +
//! `ObligationTerminal::Indeterminate` with a reconciliation note rather than being
//! silently dropped.

use std::fmt;
use std::future::Future;
use std::time::Duration;

use asupersync::Cx;
use asupersync::runtime::{JoinError, TaskHandle};
use fss_core::effect::Obligation;
use fss_core::{
    BudgetVector, ContentDigest, ObligationId, QuiescenceProof, RegionError, RegionId, RegionKind,
    RegionTree, RootAuthoritySpec, TaskId, TaskOutcome, TimestampNs,
};

use crate::asupersync_ops::boundaries::{BoundaryError, CxTimerBoundary};
use crate::authority::{AuthorityCx, AuthorityError};
use crate::obligation::{ObligationTerminal, tree_report};

/// Typed refusal emitted by [`StructuredRegionRunner`].
#[derive(Debug)]
pub enum RegionRunError {
    /// Authority or grant/budget verification failed.
    Authority(AuthorityError),
    /// Canonical region tree rejected a lifecycle transition.
    Region(RegionError),
    /// Cooperative timer/cancellation boundary failed.
    Boundary(BoundaryError),
    /// Asupersync runtime refused task admission.
    SpawnFailed {
        /// Task identifier that was not admitted.
        task_id: String,
        /// Secret-free spawn failure detail.
        detail: String,
    },
    /// Quiescence verification detected live tasks or leaked obligations at finalize.
    QuiescenceViolation {
        /// Remaining active tasks across the region tree.
        active_tasks: usize,
        /// Remaining non-terminal obligations across the region tree.
        leaked_obligations: usize,
    },
}

impl fmt::Display for RegionRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(err) => write!(f, "structured region authority error: {err}"),
            Self::Region(err) => write!(f, "structured region tree error: {err}"),
            Self::Boundary(err) => write!(f, "structured region boundary error: {err}"),
            Self::SpawnFailed { task_id, detail } => {
                write!(f, "structured region failed to spawn `{task_id}`: {detail}")
            }
            Self::QuiescenceViolation {
                active_tasks,
                leaked_obligations,
            } => write!(
                f,
                "structured region quiescence violated: active_tasks={active_tasks}, leaked_obligations={leaked_obligations}"
            ),
        }
    }
}

impl std::error::Error for RegionRunError {}

impl From<AuthorityError> for RegionRunError {
    fn from(err: AuthorityError) -> Self {
        Self::Authority(err)
    }
}

impl From<RegionError> for RegionRunError {
    fn from(err: RegionError) -> Self {
        Self::Region(err)
    }
}

impl From<BoundaryError> for RegionRunError {
    fn from(err: BoundaryError) -> Self {
        Self::Boundary(err)
    }
}

/// Lightweight handle describing one task owned by [`StructuredRegionRunner`].
///
/// The runner retains ownership of the underlying `asupersync::runtime::TaskHandle`
/// so callers cannot accidentally drop or leak a spawned task before region drain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopedTaskHandle {
    /// Canonical task identifier registered in [`RegionTree`].
    pub task_id: TaskId,
    /// Optional durable obligation paired with this task.
    pub obligation_id: Option<ObligationId>,
}

/// Verified quiescence receipt returned after `request -> drain -> finalize`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegionRunReceipt {
    /// Canonical root [`QuiescenceProof`] minted by [`RegionTree::finalize`].
    pub quiescence_proof: QuiescenceProof,
    /// Remaining active tasks across the entire region tree (guaranteed `0`).
    pub active_tasks: usize,
    /// Remaining non-terminal leaked obligations across the entire region tree (guaranteed `0`).
    pub leaked_obligations: usize,
    /// Count of tracked tasks completing with [`TaskOutcome::Success`].
    pub completed_tasks: usize,
    /// Count of tracked tasks completing with [`TaskOutcome::Cancelled`].
    pub cancelled_tasks: usize,
    /// Count of tracked tasks completing with [`TaskOutcome::Failed`].
    pub failed_tasks: usize,
    /// Count of tracked tasks completing with [`TaskOutcome::Indeterminate`].
    pub indeterminate_tasks: usize,
}

struct TrackedRegionTask {
    task_id: TaskId,
    obligation_id: Option<ObligationId>,
    handle: TaskHandle<TaskOutcome>,
}

/// Structured region executor pairing canonical [`AuthorityCx`] + [`RegionTree`] with
/// region-owned `asupersync::Cx` task spawning and deterministic `request -> drain -> finalize`.
pub struct StructuredRegionRunner {
    authority: AuthorityCx,
    tree: RegionTree,
    tasks: Vec<TrackedRegionTask>,
    cancel_requested: bool,
}

impl StructuredRegionRunner {
    /// Wraps an already constructed canonical root `(AuthorityCx, RegionTree)`.
    #[must_use]
    pub fn new(authority: AuthorityCx, tree: RegionTree) -> Self {
        Self {
            authority,
            tree,
            tasks: Vec::new(),
            cancel_requested: false,
        }
    }

    /// Constructs a canonical `ProcessRegion` root and wraps it in a [`StructuredRegionRunner`].
    pub fn from_root(
        spec: RootAuthoritySpec,
        process_region: RegionId,
        budget: BudgetVector,
        now: TimestampNs,
    ) -> Result<Self, RegionRunError> {
        let (authority, tree) =
            AuthorityCx::root(spec, process_region, RegionKind::Process, budget, now)?;
        Ok(Self::new(authority, tree))
    }

    /// Borrows the owning root [`AuthorityCx`].
    #[must_use]
    pub const fn authority(&self) -> &AuthorityCx {
        &self.authority
    }

    /// Mutably borrows the owning root [`AuthorityCx`].
    pub fn authority_mut(&mut self) -> &mut AuthorityCx {
        &mut self.authority
    }

    /// Borrows the canonical [`RegionTree`].
    #[must_use]
    pub const fn tree(&self) -> &RegionTree {
        &self.tree
    }

    /// Mutably borrows the canonical [`RegionTree`].
    pub fn tree_mut(&mut self) -> &mut RegionTree {
        &mut self.tree
    }

    /// Returns total currently active tasks across every region in [`RegionTree`].
    #[must_use]
    pub fn active_tasks(&self) -> usize {
        self.tree.iter().map(|node| node.active_tasks.len()).sum()
    }

    /// Returns total non-terminal leaked obligations across every region in [`RegionTree`].
    #[must_use]
    pub fn leaked_obligations(&self) -> usize {
        tree_report(&self.tree)
            .iter()
            .map(|report| report.leaked.len())
            .sum()
    }

    /// Returns the number of tracked `asupersync` tasks owned by this runner.
    #[must_use]
    pub fn tracked_task_count(&self) -> usize {
        self.tasks.len()
    }

    /// Spawns a region-owned `asupersync` task bound to `task_id` and optional durable `obligation`.
    ///
    /// Fails closed if either `runtime_cx` or the canonical [`AuthorityCx`] is already cancelled.
    pub fn spawn_task<F, Fut>(
        &mut self,
        runtime_cx: &Cx,
        task_id: TaskId,
        obligation: Option<Obligation>,
        now: TimestampNs,
        work: F,
    ) -> Result<ScopedTaskHandle, RegionRunError>
    where
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future<Output = TaskOutcome> + Send + 'static,
    {
        CxTimerBoundary::checkpoint(runtime_cx)?;
        if self.cancel_requested || self.authority.is_cancel_requested(&self.tree)? {
            return Err(RegionRunError::Boundary(BoundaryError::Cancelled));
        }

        let region_id = self.authority.region().clone();
        self.tree.register_task(&region_id, task_id.clone(), now)?;
        let obligation_id = if let Some(ob) = obligation {
            let ob_id = ob.obligation_id.clone();
            if let Err(err) = self.authority.register_obligation(&mut self.tree, ob) {
                let _ = self.tree.complete_task(
                    &region_id,
                    &task_id,
                    TaskOutcome::Failed("obligation_registration_failed".to_owned()),
                    now,
                );
                return Err(RegionRunError::Authority(err));
            }
            Some(ob_id)
        } else {
            None
        };

        let handle = match runtime_cx.spawn(move |child_cx| async move { work(child_cx).await }) {
            Ok(handle) => handle,
            Err(err) => {
                let _ = self.tree.complete_task(
                    &region_id,
                    &task_id,
                    TaskOutcome::Failed(format!("asupersync_spawn_refused:{err}")),
                    now,
                );
                if let Some(ob_id) = &obligation_id {
                    let _ = self.authority.resolve_obligation(
                        &mut self.tree,
                        ob_id,
                        ObligationTerminal::Failed,
                        Some(ContentDigest::sha256(b"asupersync_spawn_refused")),
                        None,
                    );
                }
                return Err(RegionRunError::SpawnFailed {
                    task_id: task_id.as_str().to_owned(),
                    detail: err.to_string(),
                });
            }
        };

        self.tasks.push(TrackedRegionTask {
            task_id: task_id.clone(),
            obligation_id: obligation_id.clone(),
            handle,
        });

        Ok(ScopedTaskHandle {
            task_id,
            obligation_id,
        })
    }

    /// Phase 1 (`request`): propagates cancellation across the canonical region tree and
    /// aborts all tracked `asupersync` tasks cooperatively.
    pub fn request_cancellation(&mut self, now: TimestampNs) -> Result<(), RegionRunError> {
        if !self.cancel_requested {
            self.authority.request_cancellation(&mut self.tree, now)?;
            self.cancel_requested = true;
        }
        for task in &self.tasks {
            if !task.handle.is_finished() {
                task.handle.abort();
            }
        }
        Ok(())
    }

    /// Executes Phases 1–3 (`request -> drain -> finalize`), joining every tracked task under
    /// `drain_timeout`, retiring every paired obligation cleanly, and verifying zero active tasks
    /// and zero leaked obligations before returning [`RegionRunReceipt`].
    pub async fn drain_and_finalize(
        mut self,
        runtime_cx: &Cx,
        drain_timeout: Duration,
        now: TimestampNs,
    ) -> Result<RegionRunReceipt, RegionRunError> {
        if !self.cancel_requested {
            self.request_cancellation(now)?;
        }
        self.authority.begin_drain(&mut self.tree, now)?;

        let mut completed_tasks = 0_usize;
        let mut cancelled_tasks = 0_usize;
        let mut failed_tasks = 0_usize;
        let mut indeterminate_tasks = 0_usize;

        let region_id = self.authority.region().clone();
        let tracked = std::mem::take(&mut self.tasks);
        for mut task in tracked {
            let outcome = match CxTimerBoundary::with_timeout(
                runtime_cx,
                drain_timeout,
                task.handle.join(runtime_cx),
            )
            .await
            {
                Ok(Ok(task_outcome)) => task_outcome,
                Ok(Err(JoinError::Cancelled(_))) => TaskOutcome::Cancelled,
                Ok(Err(JoinError::Panicked(_))) => {
                    TaskOutcome::Indeterminate("task_panicked_during_drain".to_owned())
                }
                Ok(Err(JoinError::PolledAfterCompletion)) => {
                    TaskOutcome::Indeterminate("task_polled_after_completion".to_owned())
                }
                Err(BoundaryError::DeadlineExceeded { .. }) => {
                    task.handle.abort();
                    TaskOutcome::Indeterminate("task_exceeded_drain_timeout".to_owned())
                }
                Err(BoundaryError::Cancelled) => {
                    if let Ok(Some(finished)) = task.handle.try_join() {
                        finished
                    } else {
                        task.handle.abort();
                        TaskOutcome::Cancelled
                    }
                }
                Err(_) => TaskOutcome::Indeterminate("drain_boundary_error".to_owned()),
            };

            let (ob_terminal, proof_bytes, recon_note): (
                ObligationTerminal,
                Option<Vec<u8>>,
                Option<String>,
            ) = match &outcome {
                TaskOutcome::Success => {
                    completed_tasks = completed_tasks.saturating_add(1);
                    (
                        ObligationTerminal::Completed,
                        Some(format!("task_completed:{}", task.task_id.as_str()).into_bytes()),
                        None,
                    )
                }
                TaskOutcome::Cancelled => {
                    cancelled_tasks = cancelled_tasks.saturating_add(1);
                    (
                        ObligationTerminal::Drained,
                        Some(format!("task_drained:{}", task.task_id.as_str()).into_bytes()),
                        None,
                    )
                }
                TaskOutcome::Failed(reason) => {
                    failed_tasks = failed_tasks.saturating_add(1);
                    (
                        ObligationTerminal::Failed,
                        Some(
                            format!("task_failed:{}:{reason}", task.task_id.as_str()).into_bytes(),
                        ),
                        None,
                    )
                }
                TaskOutcome::Indeterminate(reason) => {
                    indeterminate_tasks = indeterminate_tasks.saturating_add(1);
                    (
                        ObligationTerminal::Indeterminate,
                        None,
                        Some(format!(
                            "reconcile task {}: {reason}",
                            task.task_id.as_str()
                        )),
                    )
                }
            };

            let _ = self
                .tree
                .complete_task(&region_id, &task.task_id, outcome, now)?;
            if let Some(ob_id) = &task.obligation_id {
                let proof = proof_bytes.as_deref().map(ContentDigest::sha256);
                self.authority.resolve_obligation(
                    &mut self.tree,
                    ob_id,
                    ob_terminal,
                    proof,
                    recon_note.as_deref(),
                )?;
            }
        }

        let active_tasks = self.active_tasks();
        let leaked_obligations = self.leaked_obligations();
        if active_tasks != 0 || leaked_obligations != 0 {
            return Err(RegionRunError::QuiescenceViolation {
                active_tasks,
                leaked_obligations,
            });
        }

        let quiescence_proof = self.authority.finalize(&mut self.tree, now)?;
        Ok(RegionRunReceipt {
            quiescence_proof,
            active_tasks,
            leaked_obligations,
            completed_tasks,
            cancelled_tasks,
            failed_tasks,
            indeterminate_tasks,
        })
    }
}
