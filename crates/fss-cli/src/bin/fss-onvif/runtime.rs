#![forbid(unsafe_code)]
//! Small request-owned native boundary shared by ONVIF onboarding and handoff reads.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use fss_core::{
    BudgetVector, ContentDigest, OperationId, RegionId, RegionKind, RootAuthoritySpec,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::execution::{ExecutionError, TaskCompletion, TaskCx, TaskSpec, run_owned};

const AUTHORITY: &str = "ERR-ONVIF-AUTHORITY-001";
const DEADLINE: &str = "ERR-ONVIF-DEADLINE-001";
const BUDGET: &str = "ERR-ONVIF-BUDGET-001";
const CANCELLED: &str = "ERR-ONVIF-CANCELLED-001";

fn execution_error(error: &ExecutionError) -> &'static str {
    match error {
        ExecutionError::Deadline { .. } | ExecutionError::ClockRegression { .. } => DEADLINE,
        ExecutionError::Budget(_) | ExecutionError::UnmeteredCost => BUDGET,
        _ => AUTHORITY,
    }
}

pub(crate) struct Request {
    pub(crate) approval: ContentDigest,
    pub(crate) principal: String,
    pub(crate) timeout_ns: u64,
    pub(crate) bytes: u64,
    pub(crate) network_bytes: u64,
    pub(crate) storage_operations: u64,
    pub(crate) network: bool,
    pub(crate) write: bool,
    pub(crate) secrets: bool,
}

/// A live TaskCx is carried through every clock, wait, file and socket boundary.
pub(crate) struct Scope<'a, 'task> {
    task: &'a TaskCx<'task>,
    clock: &'a dyn Clock,
    observed_ns: Cell<u64>,
    charged_ms: Cell<u64>,
    resource: &'a str,
    deadline: u64,
}
impl Scope<'_, '_> {
    pub(crate) fn cancelled(&self) -> Result<bool, &'static str> {
        self.task
            .is_cancel_requested()
            .map_err(|error| execution_error(&error))
    }

    pub(crate) fn now(&self) -> Result<u64, &'static str> {
        if self.cancelled()? {
            return Err(CANCELLED);
        }
        self.task
            .checkpoint(
                TimestampNs(i128::from(self.observed_ns.get())),
                &BudgetVector::ZERO,
            )
            .map_err(|error| execution_error(&error))?;
        let now = self.clock.elapsed_ns().ok_or(DEADLINE)?;
        if now < self.observed_ns.get() || now >= self.deadline {
            return Err(DEADLINE);
        }
        let milliseconds = now.div_ceil(1_000_000);
        let mut cost = BudgetVector::ZERO;
        cost.latency_ms = milliseconds.saturating_sub(self.charged_ms.get());
        // A refused checkpoint still observes time in the canonical task. Keep
        // the local closure clock at least as recent as that attempted boundary.
        self.observed_ns.set(now);
        self.task
            .checkpoint(TimestampNs(i128::from(now)), &cost)
            .map_err(|error| execution_error(&error))?;
        self.charged_ms.set(milliseconds);
        Ok(now)
    }

    pub(crate) fn admit(
        &self,
        grant: RuntimeGrant,
        file_operation: bool,
    ) -> Result<u64, &'static str> {
        let now = self.now()?;
        let mut cost = BudgetVector::ZERO;
        cost.storage_operations = u64::from(file_operation);
        self.task
            .checkpoint_for(grant, self.resource, TimestampNs(i128::from(now)), &cost)
            .map_err(|error| execution_error(&error))?;
        Ok(now)
    }

    pub(crate) fn input(&self) -> Result<(), &'static str> {
        self.admit(RuntimeGrant::ReadMedia, true).map(|_| ())
    }
    pub(crate) fn output(&self) -> Result<(), &'static str> {
        self.admit(RuntimeGrant::ObjectStage, true)?;
        self.admit(RuntimeGrant::ObjectPublish, false).map(|_| ())
    }

    pub(crate) fn wait(&self, deadline: u64) -> Result<(), &'static str> {
        let now = self.admit(RuntimeGrant::AdapterNet, false)?;
        if deadline > self.deadline || now >= deadline {
            return Err(DEADLINE);
        }
        let delay = (deadline - now).min(1_000_000);
        std::thread::sleep(Duration::from_nanos(delay));
        self.admit(RuntimeGrant::AdapterNet, false).map(|_| ())
    }
}

/// Explicit declaration from the durable owner, after its commit has succeeded.
/// This is result metadata only: it grants no authority and performs no publication.
/// It must never wrap an uncommitted preparation or an uncertain write outcome.
#[allow(
    dead_code,
    reason = "Shared boundary is also included by read-only ONVIF commands"
)]
pub(crate) struct Committed<T> {
    value: T,
}
impl<T> Committed<T> {
    #[allow(
        dead_code,
        reason = "Shared boundary is also included by read-only ONVIF commands"
    )]
    pub(crate) fn new(value: T) -> Self {
        Self { value }
    }
}

/// The durable publication outcome and its independent request-retirement state.
/// Failure to retire a request does not unpublish its already committed result.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CommittedCompletion<T> {
    pub(crate) value: T,
    /// Late cancellation, expiry, budget or authority failure after durable commit.
    pub(crate) post_commit_error: Option<&'static str>,
    /// Task drain/receipt or region closure could not be proved; recovery is required.
    pub(crate) finalization_error: Option<&'static str>,
}

struct WorkValue<T> {
    value: T,
    committed: bool,
}

trait Clock {
    fn elapsed_ns(&self) -> Option<u64>;
}
struct NativeClock(Instant);
impl Clock for NativeClock {
    fn elapsed_ns(&self) -> Option<u64> {
        u64::try_from(self.0.elapsed().as_nanos()).ok()
    }
}

/// Preserve only an explicitly committed output across a later boundary failure.
fn late_error<T>(
    result: &mut Result<WorkValue<T>, &'static str>,
    error: &'static str,
    recorded: &mut Option<&'static str>,
) {
    match result {
        Ok(value) if value.committed => {
            recorded.get_or_insert(error);
        }
        Ok(_) => *result = Err(error),
        Err(_) => {}
    }
}

/// Native handles must be owned inside `work`. Callers return only bounded metadata.
/// Ordinary reads are released only after final authorization and full finalization.
pub(crate) fn run<T>(
    request: Request,
    work: impl FnOnce(&Scope<'_, '_>) -> Result<T, &'static str>,
) -> Result<T, &'static str> {
    run_with_clock(
        request,
        |scope| {
            work(scope).map(|value| WorkValue {
                value,
                committed: false,
            })
        },
        || NativeClock(Instant::now()),
    )
    .map(|completed| completed.value)
}

/// Run a write whose owner explicitly marks its successful durable result.
/// Every failure before that marker remains an ordinary error. After it, the
/// publication identifiers survive cancellation, deadlines and retirement failures;
/// callers must expose both error fields instead of claiming clean completion.
#[allow(
    dead_code,
    reason = "Shared boundary is also included by read-only ONVIF commands"
)]
pub(crate) fn run_committing<T>(
    request: Request,
    work: impl FnOnce(&Scope<'_, '_>) -> Result<Committed<T>, &'static str>,
) -> Result<CommittedCompletion<T>, &'static str> {
    run_committing_with_clock(request, work, || NativeClock(Instant::now()))
}

fn run_committing_with_clock<T, C: Clock>(
    request: Request,
    work: impl FnOnce(&Scope<'_, '_>) -> Result<Committed<T>, &'static str>,
    open_clock: impl FnOnce() -> C,
) -> Result<CommittedCompletion<T>, &'static str> {
    if !request.write {
        return Err(AUTHORITY);
    }
    run_with_clock(
        request,
        |scope| {
            work(scope).map(|value| WorkValue {
                value: value.value,
                committed: true,
            })
        },
        open_clock,
    )
}

fn run_with_clock<T, C: Clock>(
    request: Request,
    work: impl FnOnce(&Scope<'_, '_>) -> Result<WorkValue<T>, &'static str>,
    open_clock: impl FnOnce() -> C,
) -> Result<CommittedCompletion<T>, &'static str> {
    let allowance = BudgetVector::builder()
        .bytes(request.bytes)
        .network_bytes(request.network_bytes)
        .storage_operations(request.storage_operations)
        .latency_ms(request.timeout_ns.div_ceil(1_000_000))
        .build()
        .map_err(|_| BUDGET)?;
    let mut grants = vec![RuntimeGrant::ReadMedia];
    if request.network {
        grants.push(RuntimeGrant::AdapterNet);
    }
    if request.write {
        grants.extend([RuntimeGrant::ObjectStage, RuntimeGrant::ObjectPublish]);
    }
    if request.secrets {
        grants.push(RuntimeGrant::AdapterAuth);
    }
    let spec = RootAuthoritySpec {
        trace_id: "trace:onvif-operator".into(),
        operation_id: OperationId::parse("operation:onvif-operator").map_err(|_| AUTHORITY)?,
        principal: request.principal,
        capabilities: grants
            .iter()
            .map(|grant| grant.as_str().to_owned())
            .collect(),
        deadline: Some(TimestampNs(i128::from(request.timeout_ns))),
        priority: 10,
        budgets: allowance,
        privacy_scope: "privacy:owner-private-onvif-metadata".into(),
        retention_scope: "retention:explicit-onvif-operator-output".into(),
        anchor_universe: request.approval,
        generation: 1,
    };
    let resource = format!("onvif-operator:{}", request.approval.to_text());
    let (mut process, mut tree) = AuthorityCx::root(
        spec.clone(),
        RegionId::new("region:onvif-process").map_err(|_| AUTHORITY)?,
        RegionKind::Process,
        allowance,
        TimestampNs(0),
    )
    .map_err(|_| AUTHORITY)?;
    let mut scoped = process.grants().clone();
    for grant in grants {
        scoped = scoped.with_scope(grant, BTreeSet::from([resource.clone()]));
    }
    process.narrow_grants(scoped).map_err(|_| AUTHORITY)?;
    let mut property = process
        .scope_down(
            &mut tree,
            RegionId::new("region:onvif-property").map_err(|_| AUTHORITY)?,
            RegionKind::Property,
            allowance,
            spec.clone(),
            TimestampNs(0),
        )
        .map_err(|_| AUTHORITY)?;
    let mut sensor = property
        .scope_down(
            &mut tree,
            RegionId::new("region:onvif-sensor").map_err(|_| AUTHORITY)?,
            RegionKind::Sensor,
            allowance,
            spec,
            TimestampNs(0),
        )
        .map_err(|_| AUTHORITY)?;
    let mut reservation = BudgetVector::ZERO;
    reservation.bytes = request.bytes;
    reservation.network_bytes = request.network_bytes;
    let completed = run_owned(
        &mut sensor,
        &mut tree,
        TaskSpec {
            task_id: TaskId::new("task:onvif-operator").map_err(|_| AUTHORITY)?,
            started_at: TimestampNs(0),
        },
        |task| {
            let initial = task
                .checkpoint(TimestampNs(0), &reservation)
                .map_err(|error| execution_error(&error));
            // The clock is opened only after live authority admits the operation.
            let mut elapsed = 0;
            let mut post_commit_error = None;
            let mut finalization_error = None;
            let mut cancellation_reflected = false;
            let mut result = initial.and_then(|()| {
                let clock = open_clock();
                let scope = Scope {
                    task,
                    clock: &clock,
                    observed_ns: Cell::new(0),
                    charged_ms: Cell::new(0),
                    resource: &resource,
                    deadline: request.timeout_ns,
                };
                let mut result = work(&scope);
                if result.is_ok()
                    && let Err(error) = scope.now()
                {
                    late_error(&mut result, error, &mut post_commit_error);
                }
                // Metadata-only closure time is observed after native handles have dropped.
                elapsed = scope.observed_ns.get();
                match clock.elapsed_ns() {
                    Some(now) if now >= elapsed => elapsed = now,
                    _ => late_error(&mut result, DEADLINE, &mut post_commit_error),
                }
                if elapsed >= request.timeout_ns {
                    late_error(&mut result, DEADLINE, &mut post_commit_error);
                }
                match task.is_cancel_requested() {
                    Ok(true) => {
                        match task.request_cancellation(TimestampNs(i128::from(elapsed))) {
                            Ok(()) => cancellation_reflected = true,
                            Err(error) => late_error(
                                &mut result,
                                execution_error(&error),
                                &mut finalization_error,
                            ),
                        }
                        late_error(&mut result, CANCELLED, &mut post_commit_error);
                    }
                    Ok(false) => {}
                    Err(error) => {
                        late_error(&mut result, execution_error(&error), &mut post_commit_error)
                    }
                }
                result
            });
            let now = TimestampNs(i128::from(elapsed));
            if let Err(error) = task.begin_drain(now) {
                late_error(
                    &mut result,
                    execution_error(&error),
                    &mut finalization_error,
                );
            }
            // Task retirement and durable publication have separate outcomes.
            // A cancelled request is never relabelled Success merely because its
            // owner had already committed a recoverable publication.
            let outcome = if cancellation_reflected {
                TaskOutcome::Cancelled
            } else if let Some(error) = finalization_error
                .or(post_commit_error)
                .or_else(|| result.as_ref().err().copied())
            {
                TaskOutcome::Failed(error.into())
            } else {
                TaskOutcome::Success
            };
            TaskCompletion {
                output: (result, elapsed, post_commit_error, finalization_error),
                outcome,
                completed_at: now,
            }
        },
    );
    let (mut result, elapsed, post_commit_error, mut finalization_error) = match completed {
        Ok(completed) => {
            let (mut result, elapsed, post_commit_error, mut finalization_error) = completed.output;
            if let Err(error) = completed.receipt {
                late_error(
                    &mut result,
                    execution_error(&error),
                    &mut finalization_error,
                );
            }
            (result, elapsed, post_commit_error, finalization_error)
        }
        Err(error) => (Err(execution_error(&error)), 0, None, None),
    };
    let closed = (|| {
        let now = TimestampNs(i128::from(elapsed));
        if tree.get(sensor.region())?.state != fss_core::RegionState::Draining {
            sensor.request_cancellation(&mut tree, now)?;
            sensor.begin_drain(&mut tree, now)?;
        }
        sensor.finalize(&mut tree, now)?;
        property.release_scope_reservation(&tree, &mut sensor)?;
        property.request_cancellation(&mut tree, now)?;
        property.begin_drain(&mut tree, now)?;
        property.finalize(&mut tree, now)?;
        process.release_scope_reservation(&tree, &mut property)?;
        process.request_cancellation(&mut tree, now)?;
        process.begin_drain(&mut tree, now)?;
        process.finalize(&mut tree, now)?;
        Ok::<(), fss_runtime::authority::AuthorityError>(())
    })();
    if closed.is_err() {
        late_error(&mut result, AUTHORITY, &mut finalization_error);
    }
    result.map(|value| CommittedCompletion {
        value: value.value,
        post_commit_error,
        finalization_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_cancellation_closes_admission_and_keeps_cancelled_outcome() {
        let request = Request {
            approval: ContentDigest::sha256(b"onvif-cancelled-fixture"),
            principal: "principal:fixture".into(),
            timeout_ns: 1_000_000_000,
            bytes: 1024,
            network_bytes: 0,
            storage_operations: 16,
            network: false,
            write: false,
            secrets: false,
        };
        let result: Result<(), _> = run(request, |scope| {
            let now = scope.now()?;
            scope
                .task
                .request_cancellation(TimestampNs(i128::from(now)))
                .map_err(|error| execution_error(&error))?;
            assert_eq!(scope.input(), Err(CANCELLED));
            // A callback cannot hide the cancellation by returning ordinary success.
            Ok(())
        });
        assert_eq!(result, Err(CANCELLED));
    }

    struct TestClock<'a>(&'a Cell<u64>);
    impl Clock for TestClock<'_> {
        fn elapsed_ns(&self) -> Option<u64> {
            Some(self.0.get())
        }
    }

    fn writing_request() -> Request {
        Request {
            approval: ContentDigest::sha256(b"onvif-durable-fixture"),
            principal: "principal:fixture".into(),
            timeout_ns: 1_000_000_000,
            bytes: 1024,
            network_bytes: 0,
            storage_operations: 16,
            network: false,
            write: true,
            secrets: false,
        }
    }

    fn publication() -> (ContentDigest, ContentDigest) {
        (
            ContentDigest::sha256(b"retained-import-identity"),
            ContentDigest::sha256(b"durable-publication-root"),
        )
    }

    fn cancel(scope: &Scope<'_, '_>) -> Result<(), &'static str> {
        scope
            .task
            .request_cancellation(TimestampNs(i128::from(scope.observed_ns.get())))
            .map_err(|error| execution_error(&error))
    }

    #[test]
    fn committed_publication_preserves_identifiers_after_cancellation() {
        let result = run_committing(writing_request(), |scope| {
            scope.output()?;
            let committed = Committed::new(publication());
            cancel(scope)?;
            assert_eq!(scope.output(), Err(CANCELLED));
            Ok(committed)
        });
        assert_eq!(
            result,
            Ok(CommittedCompletion {
                value: publication(),
                post_commit_error: Some(CANCELLED),
                finalization_error: None,
            })
        );
    }

    #[test]
    fn committed_publication_preserves_identifiers_at_exact_deadline() {
        let clock = Cell::new(0);
        let request = writing_request();
        let deadline = request.timeout_ns;
        let result = run_committing_with_clock(
            request,
            |scope| {
                scope.output()?;
                let committed = Committed::new(publication());
                clock.set(deadline);
                Ok(committed)
            },
            || TestClock(&clock),
        );
        assert_eq!(
            result,
            Ok(CommittedCompletion {
                value: publication(),
                post_commit_error: Some(DEADLINE),
                finalization_error: None,
            })
        );
    }

    #[test]
    fn cancelled_before_publication_remains_an_error() {
        let clock = Cell::new(0);
        let result = run_committing_with_clock(
            writing_request(),
            |scope| {
                cancel(scope)?;
                scope.output()?;
                Ok(Committed::new(publication()))
            },
            || TestClock(&clock),
        );
        assert_eq!(result, Err(CANCELLED));
    }

    #[test]
    fn failed_publication_is_not_promoted_by_committing_runner() {
        let clock = Cell::new(0);
        let result = run_committing_with_clock(
            writing_request(),
            |scope| {
                scope.output()?;
                Err::<Committed<()>, _>("ERR-FIXTURE-PUBLICATION-FAILED")
            },
            || TestClock(&clock),
        );
        assert_eq!(result, Err("ERR-FIXTURE-PUBLICATION-FAILED"));
    }

    #[test]
    fn committed_publication_exposes_independent_finalization_failure() {
        let clock = Cell::new(0);
        let result = run_committing_with_clock(
            writing_request(),
            |scope| {
                scope.output()?;
                let obligation = fss_runtime::obligation::new_obligation(
                    "obligation:onvif-pending-cleanup",
                    scope.task.context().operation_id.clone(),
                    "local cleanup verified",
                )
                .map_err(|_| AUTHORITY)?;
                scope
                    .task
                    .register_obligation(obligation, TimestampNs(0))
                    .map_err(|error| execution_error(&error))?;
                let committed = Committed::new(publication());
                cancel(scope)?;
                Ok(committed)
            },
            || TestClock(&clock),
        );
        assert_eq!(
            result,
            Ok(CommittedCompletion {
                value: publication(),
                post_commit_error: Some(CANCELLED),
                finalization_error: Some(AUTHORITY),
            })
        );
    }

    #[test]
    fn committing_runner_requires_write_authority_before_entering_callback() {
        let mut request = writing_request();
        request.write = false;
        let called = Cell::new(false);
        let result = run_committing(request, |_| {
            called.set(true);
            Ok(Committed::new(publication()))
        });
        assert_eq!(result, Err(AUTHORITY));
        assert!(!called.get());
    }

    #[test]
    fn ordinary_read_does_not_release_output_at_exact_deadline() {
        let clock = Cell::new(0);
        let mut request = writing_request();
        request.write = false;
        let deadline = request.timeout_ns;
        let result = run_with_clock(
            request,
            |scope| {
                scope.input()?;
                clock.set(deadline);
                Ok(WorkValue {
                    value: publication(),
                    committed: false,
                })
            },
            || TestClock(&clock),
        );
        assert_eq!(result, Err(DEADLINE));
    }

    #[test]
    fn clean_committed_publication_reports_complete_retirement() {
        let clock = Cell::new(0);
        let result = run_committing_with_clock(
            writing_request(),
            |scope| {
                scope.output()?;
                Ok(Committed::new(publication()))
            },
            || TestClock(&clock),
        );
        assert_eq!(
            result,
            Ok(CommittedCompletion {
                value: publication(),
                post_commit_error: None,
                finalization_error: None,
            })
        );
    }

    #[test]
    fn deadline_between_release_check_and_drain_keeps_committed_result() {
        struct ClosingClock {
            first: Cell<bool>,
            deadline: u64,
        }
        impl Clock for ClosingClock {
            fn elapsed_ns(&self) -> Option<u64> {
                Some(if self.first.replace(false) {
                    0
                } else {
                    self.deadline
                })
            }
        }
        let request = writing_request();
        let deadline = request.timeout_ns;
        let result = run_committing_with_clock(
            request,
            |_| Ok(Committed::new(publication())),
            || ClosingClock {
                first: Cell::new(true),
                deadline,
            },
        );
        assert_eq!(
            result,
            Ok(CommittedCompletion {
                value: publication(),
                post_commit_error: Some(DEADLINE),
                finalization_error: None,
            })
        );
    }
}
