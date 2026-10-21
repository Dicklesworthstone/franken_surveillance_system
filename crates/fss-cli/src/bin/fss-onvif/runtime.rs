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
    start: Instant,
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
        let now = u64::try_from(self.start.elapsed().as_nanos()).map_err(|_| DEADLINE)?;
        if now < self.observed_ns.get() || now >= self.deadline {
            return Err(DEADLINE);
        }
        let milliseconds = now.div_ceil(1_000_000);
        let mut cost = BudgetVector::ZERO;
        cost.latency_ms = milliseconds.saturating_sub(self.charged_ms.get());
        self.task
            .checkpoint(TimestampNs(i128::from(now)), &cost)
            .map_err(|error| execution_error(&error))?;
        self.observed_ns.set(now);
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

/// Native handles must be owned inside `work`. Callers return only bounded metadata.
/// No value is reported until all three ownership regions have finalized.
pub(crate) fn run<T>(
    request: Request,
    work: impl FnOnce(&Scope<'_, '_>) -> Result<T, &'static str>,
) -> Result<T, &'static str> {
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
            let result = initial.and_then(|()| {
                let scope = Scope {
                    task,
                    start: Instant::now(),
                    observed_ns: Cell::new(0),
                    charged_ms: Cell::new(0),
                    resource: &resource,
                    deadline: request.timeout_ns,
                };
                let result = work(&scope).and_then(|value| {
                    scope.now()?;
                    Ok(value)
                });
                // Metadata-only closure time is observed after native handles have dropped.
                let cancelled = task
                    .is_cancel_requested()
                    .map_err(|error| execution_error(&error))?;
                elapsed = u64::try_from(scope.start.elapsed().as_nanos()).map_err(|_| DEADLINE)?;
                if cancelled {
                    task.request_cancellation(TimestampNs(i128::from(elapsed)))
                        .map_err(|error| execution_error(&error))?;
                    Err(CANCELLED)
                } else {
                    result
                }
            });
            let now = TimestampNs(i128::from(elapsed));
            let drain = task
                .begin_drain(now)
                .map_err(|error| execution_error(&error));
            let result = result.and_then(|value| drain.map(|()| value));
            let outcome = match &result {
                Ok(_) => TaskOutcome::Success,
                Err(code) if *code == CANCELLED => TaskOutcome::Cancelled,
                Err(code) => TaskOutcome::Failed((*code).into()),
            };
            TaskCompletion {
                output: (result, elapsed),
                outcome,
                completed_at: now,
            }
        },
    );
    let (result, elapsed) = match completed {
        Ok(completed) => {
            let (result, elapsed) = completed.output;
            (
                match completed.receipt {
                    Ok(_) => result,
                    Err(error) => Err(execution_error(&error)),
                },
                elapsed,
            )
        }
        Err(error) => (Err(execution_error(&error)), 0),
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
    closed.map_err(|_| AUTHORITY)?;
    result
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
}
