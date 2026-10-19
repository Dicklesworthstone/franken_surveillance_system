#![forbid(unsafe_code)]
//! The actual bounded capture is owned by Process → Property → Sensor regions.
//! Native resources stay in the synchronous callback; only result data returns.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::time::Instant;

use fss_cli::agent_json::{array, budget, object, string};
use fss_core::{
    BudgetVector, ContentDigest, ObligationId, OperationId, RegionId, RegionKind, RegionTree,
    RootAuthoritySpec, RuntimeGrant, TaskId, TaskOutcome, TaskReceipt, TimestampNs,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::execution::{ExecutionError, TaskCompletion, TaskCx, TaskSpec, run_owned};
use fss_runtime::obligation::{ObligationTerminal, new_obligation};

use super::{AttemptOutcome, Failure, MAX_CREDENTIAL_BYTES, Options, SourceConfig, Statistics};

const CUSTODY_ID: &str = "obligation:rtsp-capture-custody";
const CUSTODY_PREDICATE: &str =
    "native archive/source publication is settled or the exact remaining custody is retained";
const STORAGE_GRANTS: [RuntimeGrant; 4] = [
    RuntimeGrant::ReadMedia,
    RuntimeGrant::ObjectStage,
    RuntimeGrant::ObjectPublish,
    RuntimeGrant::RetentionCommit,
];

pub(super) fn failure(error: &ExecutionError) -> Failure {
    match error {
        ExecutionError::Deadline { .. } | ExecutionError::ClockRegression { .. } => {
            Failure::Deadline
        }
        ExecutionError::Budget(_) | ExecutionError::UnmeteredCost => Failure::WorkBudget,
        _ => Failure::Authority,
    }
}

/// The labels name the exact already-approved route, custody destinations and
/// credential source. Native callers also compare their concrete binding/path.
pub(super) struct Resources {
    network: String,
    storage: String,
    secret: String,
}

/// Every clock read, wait, filesystem, secret and socket callback carries its
/// currently executing TaskCx. No ambient clock or detached supervisor exists.
pub(super) struct TaskClock {
    start: Instant,
    observed_ns: Cell<u64>,
    charged_ms: Cell<u64>,
    storage_admissions: Cell<u64>,
}

impl TaskClock {
    fn start(task: &TaskCx<'_>) -> Result<Self, Failure> {
        task.checkpoint(TimestampNs(0), &BudgetVector::ZERO)
            .map_err(|error| failure(&error))?;
        Ok(Self {
            start: Instant::now(),
            observed_ns: Cell::new(0),
            charged_ms: Cell::new(0),
            storage_admissions: Cell::new(0),
        })
    }

    fn admit(
        &self,
        task: &TaskCx<'_>,
        grants: &[RuntimeGrant],
        resource: &str,
        storage: bool,
        draining: bool,
    ) -> Result<u64, Failure> {
        // Validate the live owner before consulting its clock. The second check
        // observes actual time and atomically charges the newly elapsed interval.
        let checkpoint = |now, cost: &BudgetVector| {
            if draining {
                task.cleanup_checkpoint(TimestampNs(i128::from(now)), cost)
            } else {
                task.checkpoint(TimestampNs(i128::from(now)), cost)
            }
        };
        checkpoint(self.observed_ns.get(), &BudgetVector::ZERO).map_err(|error| failure(&error))?;
        let now = self.elapsed()?;
        for grant in grants {
            let admitted = if draining {
                task.cleanup_checkpoint_for(
                    *grant,
                    resource,
                    TimestampNs(i128::from(now)),
                    &BudgetVector::ZERO,
                )
            } else {
                task.checkpoint_for(
                    *grant,
                    resource,
                    TimestampNs(i128::from(now)),
                    &BudgetVector::ZERO,
                )
            };
            admitted.map_err(|error| failure(&error))?;
        }
        let milliseconds = now.div_ceil(1_000_000);
        let mut cost = BudgetVector::ZERO;
        cost.latency_ms = milliseconds.saturating_sub(self.charged_ms.get());
        cost.storage_operations = u64::from(storage);
        checkpoint(now, &cost).map_err(|error| failure(&error))?;
        self.charged_ms.set(milliseconds);
        if storage {
            self.storage_admissions
                .set(self.storage_admissions.get().saturating_add(1));
        }
        Ok(now)
    }

    pub(super) fn now(&self, task: &TaskCx<'_>, draining: bool) -> Result<u64, Failure> {
        self.admit(task, &[], "", false, draining)
    }

    pub(super) fn storage(
        &self,
        task: &TaskCx<'_>,
        resources: &Resources,
        draining: bool,
    ) -> Result<u64, Failure> {
        self.admit(task, &STORAGE_GRANTS, &resources.storage, true, draining)
    }

    pub(super) fn network(&self, task: &TaskCx<'_>, resources: &Resources) -> Result<u64, Failure> {
        self.admit(
            task,
            &[RuntimeGrant::AdapterNet],
            &resources.network,
            false,
            false,
        )
    }

    pub(super) fn secret(&self, task: &TaskCx<'_>, resources: &Resources) -> Result<u64, Failure> {
        self.admit(
            task,
            &[RuntimeGrant::AdapterAuth],
            &resources.secret,
            true,
            false,
        )
    }

    pub(super) fn metadata_now(&self, task: &TaskCx<'_>) -> Result<u64, Failure> {
        // Cancellation closes work admission, not the owner's ability to enter
        // drain or record the real time of already-closed resources.
        task.is_cancel_requested()
            .map_err(|error| failure(&error))?;
        self.elapsed()
    }

    /// Metadata-only final observation after the native resources have returned.
    /// It never extends admission or turns a late completion into success.
    fn elapsed(&self) -> Result<u64, Failure> {
        let now = u64::try_from(self.start.elapsed().as_nanos()).map_err(|_| Failure::Deadline)?;
        if now < self.observed_ns.get() {
            return Err(Failure::Deadline);
        }
        self.observed_ns.set(now);
        Ok(now)
    }
}

pub(super) struct CaptureRuntime {
    process: AuthorityCx,
    property: AuthorityCx,
    sensor: AuthorityCx,
    tree: RegionTree,
    resources: Resources,
    allowance: BudgetVector,
    reservation: BudgetVector,
    deadline_ns: u64,
    task_id: TaskId,
    custody_id: ObligationId,
}

pub(super) struct RuntimeResult {
    pub(super) result: Result<(), Failure>,
    pub(super) report: String,
    pub(super) closure_failed: bool,
}

struct Returned {
    native: Result<(), Failure>,
    boundary: Option<Failure>,
    elapsed_ns: u64,
    storage_admissions: u64,
}

impl CaptureRuntime {
    pub(super) fn new(
        options: &Options,
        source: Option<&SourceConfig>,
        approval: ContentDigest,
    ) -> Result<Self, Failure> {
        let transport = options.live_config().transport;
        let deadline_ns = options
            .timeout_ns
            .checked_add(options.drain_timeout_ns)
            .ok_or(Failure::Configuration)?;
        let byte_budget = options
            .publication_limits()
            .spool
            .max_total_bytes
            .checked_add(options.max_received_bytes())
            .and_then(|budget| {
                budget.checked_add(source.map_or(0, |s| s.storage.spool.max_total_bytes))
            })
            .and_then(|budget| {
                budget.checked_add(if options.authentication.is_some() {
                    MAX_CREDENTIAL_BYTES as u64 + 1 + 16 * options.max_steps
                } else {
                    0
                })
            })
            .ok_or(Failure::Configuration)?;
        let network_budget = transport
            .max_received_bytes
            .checked_add(transport.max_sent_bytes)
            .ok_or(Failure::Configuration)?;
        let storage_budget = options
            .max_steps
            .checked_mul(64)
            .and_then(|budget| {
                budget.checked_add(source.map_or(0, |s| s.limits.max_datagrams as u64 * 64))
            })
            .ok_or(Failure::Configuration)?;
        let allowance = BudgetVector::builder()
            .bytes(byte_budget)
            .network_bytes(network_budget)
            .storage_operations(storage_budget)
            .latency_ms(deadline_ns.div_ceil(1_000_000))
            .build()
            .map_err(|_| Failure::Configuration)?;
        let mut capabilities = STORAGE_GRANTS
            .iter()
            .map(|grant| grant.as_str().to_owned())
            .collect::<Vec<_>>();
        capabilities.push(RuntimeGrant::AdapterNet.as_str().to_owned());
        if options.authentication.is_some() {
            capabilities.push(RuntimeGrant::AdapterAuth.as_str().to_owned());
        }
        let spec = RootAuthoritySpec {
            trace_id: "trace:rtsp-capture".into(),
            operation_id: OperationId::parse("operation:rtsp-capture")
                .map_err(|_| Failure::Configuration)?,
            principal: options.principal.clone(),
            capabilities,
            deadline: Some(TimestampNs(i128::from(deadline_ns))),
            priority: 10,
            budgets: allowance,
            privacy_scope: "privacy:owner-original-rtsp-custody".into(),
            retention_scope: "retention:explicit-original-rtsp-scope".into(),
            anchor_universe: approval,
            generation: options.recording_config().scope.generation,
        };
        let resources = Resources {
            network: format!("rtsp-route:{}", approval.to_text()),
            storage: format!("rtsp-custody:{}", approval.to_text()),
            secret: format!("rtsp-credential:{}", approval.to_text()),
        };
        let (mut process, mut tree) = AuthorityCx::root(
            spec.clone(),
            RegionId::new("region:rtsp-process").map_err(|_| Failure::Configuration)?,
            RegionKind::Process,
            allowance,
            TimestampNs(0),
        )
        .map_err(|_| Failure::Authority)?;
        let mut grants = process.grants().clone().with_scope(
            RuntimeGrant::AdapterNet,
            BTreeSet::from([resources.network.clone()]),
        );
        for grant in STORAGE_GRANTS {
            grants = grants.with_scope(grant, BTreeSet::from([resources.storage.clone()]));
        }
        if options.authentication.is_some() {
            grants = grants.with_scope(
                RuntimeGrant::AdapterAuth,
                BTreeSet::from([resources.secret.clone()]),
            );
        }
        process
            .narrow_grants(grants)
            .map_err(|_| Failure::Authority)?;
        let mut property = process
            .scope_down(
                &mut tree,
                RegionId::new("region:rtsp-property").map_err(|_| Failure::Configuration)?,
                RegionKind::Property,
                allowance,
                spec.clone(),
                TimestampNs(0),
            )
            .map_err(|_| Failure::Authority)?;
        let sensor = property
            .scope_down(
                &mut tree,
                RegionId::new("region:rtsp-sensor").map_err(|_| Failure::Configuration)?,
                RegionKind::Sensor,
                allowance,
                spec,
                TimestampNs(0),
            )
            .map_err(|_| Failure::Authority)?;
        let mut reservation = BudgetVector::ZERO;
        reservation.bytes = byte_budget;
        reservation.network_bytes = network_budget;
        Ok(Self {
            process,
            property,
            sensor,
            tree,
            resources,
            allowance,
            reservation,
            deadline_ns,
            task_id: TaskId::new("task:rtsp-capture").map_err(|_| Failure::Configuration)?,
            custody_id: ObligationId::parse(CUSTODY_ID).map_err(|_| Failure::Configuration)?,
        })
    }

    pub(super) fn run(
        &mut self,
        stats: &mut Statistics,
        work: impl FnOnce(&TaskCx<'_>, &TaskClock, &Resources, &mut Statistics) -> Result<(), Failure>,
    ) -> RuntimeResult {
        let registration = TaskSpec {
            task_id: self.task_id.clone(),
            started_at: TimestampNs(0),
        };
        let reservation = self.reservation;
        let custody_id = &self.custody_id;
        let resources = &self.resources;
        let result = run_owned(&mut self.sensor, &mut self.tree, registration, |task| {
            let mut clock = None;
            let native = (|| {
                let custody = new_obligation(
                    custody_id.as_str(),
                    task.context().operation_id.clone(),
                    CUSTODY_PREDICATE,
                )
                .map_err(|_| Failure::Configuration)?;
                task.register_obligation(custody, TimestampNs(0))
                    .map_err(|error| failure(&error))?;
                // These are declared worst-case native allowances, not invented
                // observations of actual bytes. The native byte/work caps remain.
                task.checkpoint(TimestampNs(0), &reservation)
                    .map_err(|error| failure(&error))?;
                clock = Some(TaskClock::start(task)?);
                work(
                    task,
                    clock.as_ref().ok_or(Failure::State)?,
                    resources,
                    stats,
                )
            })();
            // The native callback has returned: socket, capture, archive owners,
            // publishers, credentials and entropy handles have all been dropped.
            let mut boundary = None;
            let elapsed_ns = match &clock {
                Some(clock) => match clock.elapsed() {
                    Ok(now) => now,
                    Err(error) => {
                        boundary = Some(error);
                        clock.observed_ns.get()
                    }
                },
                None => 0,
            };
            let now = TimestampNs(i128::from(elapsed_ns));
            let custody = AttemptOutcome::new(native, stats);
            if !custody.recovery_required {
                let terminal = if stats.snapshot_digest.is_some() {
                    ObligationTerminal::Completed
                } else {
                    ObligationTerminal::Failed
                };
                if let Err(error) =
                    task.resolve_obligation(custody_id, terminal, stats.snapshot_digest, None, now)
                {
                    boundary = Some(failure(&error));
                }
            }
            if let Err(error) = task.begin_drain(now) {
                boundary = Some(failure(&error));
            }
            let outcome = if custody.recovery_required {
                TaskOutcome::Indeterminate("rtsp_publication_recovery_required".into())
            } else if let Some(error) = boundary {
                TaskOutcome::Failed(error.code().into())
            } else {
                match native {
                    Ok(()) => TaskOutcome::Success,
                    Err(error) => TaskOutcome::Failed(error.code().into()),
                }
            };
            TaskCompletion {
                output: Returned {
                    native,
                    boundary,
                    elapsed_ns,
                    storage_admissions: clock.as_ref().map_or(0, |c| c.storage_admissions.get()),
                },
                outcome,
                completed_at: now,
            }
        });
        let (returned, receipt, entered) = match result {
            Ok(run) => (run.output, run.receipt, true),
            Err(error) => (
                Returned {
                    native: Err(failure(&error)),
                    boundary: Some(failure(&error)),
                    elapsed_ns: 0,
                    storage_admissions: 0,
                },
                Err(error),
                false,
            ),
        };
        let receipt_failure = receipt.as_ref().err().map(failure);
        let quiescent = self.close(returned.elapsed_ns);
        let closure_failed = returned.boundary.is_some() || receipt_failure.is_some() || !quiescent;
        let effective = match returned.native {
            Err(error) => Err(error),
            Ok(()) => returned
                .boundary
                .or(receipt_failure)
                .or((!quiescent).then_some(Failure::Storage))
                .map_or(Ok(()), Err),
        };
        RuntimeResult {
            result: effective,
            report: self.report(&returned, &receipt, entered, quiescent),
            closure_failed,
        }
    }

    fn close(&mut self, now: u64) -> bool {
        let close = (|| {
            let now = TimestampNs(i128::from(now));
            if self.tree.get(self.sensor.region())?.state != fss_core::RegionState::Draining {
                self.sensor.request_cancellation(&mut self.tree, now)?;
                self.sensor.begin_drain(&mut self.tree, now)?;
            }
            self.sensor.finalize(&mut self.tree, now)?;
            self.property
                .release_scope_reservation(&self.tree, &mut self.sensor)?;
            self.property.request_cancellation(&mut self.tree, now)?;
            self.property.begin_drain(&mut self.tree, now)?;
            self.property.finalize(&mut self.tree, now)?;
            self.process
                .release_scope_reservation(&self.tree, &mut self.property)?;
            self.process.request_cancellation(&mut self.tree, now)?;
            self.process.begin_drain(&mut self.tree, now)?;
            self.process.finalize(&mut self.tree, now)?;
            Ok::<(), fss_runtime::authority::AuthorityError>(())
        })();
        close.is_ok()
    }

    fn report(
        &self,
        returned: &Returned,
        receipt: &Result<TaskReceipt, ExecutionError>,
        entered: bool,
        quiescent: bool,
    ) -> String {
        let remaining = self.sensor.budget().remaining();
        let mut charged = self.allowance;
        charged.bytes = charged.bytes.saturating_sub(remaining.bytes);
        charged.network_bytes = charged
            .network_bytes
            .saturating_sub(remaining.network_bytes);
        charged.storage_operations = charged
            .storage_operations
            .saturating_sub(remaining.storage_operations);
        charged.latency_ms = charged.latency_ms.saturating_sub(remaining.latency_ms);
        let node = self.tree.get(self.sensor.region()).ok();
        let pending = node.map_or_else(
            || "null".into(),
            |node| {
                array(
                    &node
                        .obligations
                        .values()
                        .filter(|o| o.state == fss_core::ObligationState::Pending)
                        .map(|o| {
                            object(&[
                                ("id", string(o.obligation_id.as_str())),
                                ("terminal_predicate", string(&o.terminal_predicate)),
                                (
                                    "recovery_input_fields",
                                    array(&[
                                        string("journal_anchor"),
                                        string("candidate_pin"),
                                        string("confirmed_pin"),
                                        string("unrecorded_work_receipt"),
                                        string("snapshot_digest"),
                                        string("datagram_source"),
                                        string("unsealed_rtp_bytes"),
                                        string("unsealed_pictures"),
                                        string("unpublished_prepared_bytes"),
                                        string("unpublished_prepared_pictures"),
                                    ]),
                                ),
                            ])
                        })
                        .collect::<Vec<_>>(),
                )
            },
        );
        let custody_state = node
            .and_then(|node| node.obligations.get(&self.custody_id))
            .map_or("unavailable", |o| match o.state {
                fss_core::ObligationState::Pending => "pending",
                fss_core::ObligationState::Verified => "verified",
                fss_core::ObligationState::Failed => "failed",
                fss_core::ObligationState::Cancelled => "cancelled",
                fss_core::ObligationState::Indeterminate => "indeterminate",
            });
        let proof = self
            .tree
            .get(self.process.region())
            .ok()
            .and_then(|root| root.quiescence_proof.as_ref());
        object(&[
            ("execution", string("synchronous_owned")),
            (
                "region_chain",
                array(&[
                    string("ProcessRegion"),
                    string("PropertyRegion"),
                    string("SensorRegion"),
                ]),
            ),
            ("closure_returned", entered.to_string()),
            ("native_resources_closed", entered.to_string()),
            (
                "closed_resource_scope",
                string("local_capture_socket_archives_publishers_credentials_entropy"),
            ),
            (
                "quiescent",
                (quiescent && node.is_some() && proof.is_some()).to_string(),
            ),
            (
                "quiescence_proof",
                proof.map_or_else(
                    || "null".into(),
                    |proof| {
                        object(&[
                            ("region_id", string(proof.region_id.as_str())),
                            ("proof_digest", string(&proof.proof_digest.to_text())),
                            ("closed_ns", proof.closed_at.0.to_string()),
                            ("total_tasks", proof.total_tasks.to_string()),
                            ("total_obligations", proof.total_obligations.to_string()),
                            (
                                "indeterminate_obligations",
                                proof.indeterminate_obligations.to_string(),
                            ),
                        ])
                    },
                ),
            ),
            (
                "active_tasks",
                node.map_or_else(|| "null".into(), |node| node.active_tasks.len().to_string()),
            ),
            (
                "task_receipt",
                receipt
                    .as_ref()
                    .map_or_else(|_| "null".into(), task_receipt),
            ),
            (
                "receipt_error",
                receipt
                    .as_ref()
                    .err()
                    .map_or_else(|| "null".into(), |e| string(failure(e).code())),
            ),
            ("pending_obligations", pending),
            ("custody_state", string(custody_state)),
            (
                "closure_error",
                returned
                    .native
                    .as_ref()
                    .err()
                    .map_or_else(|| "null".into(), |e| string(e.code())),
            ),
            (
                "closure_boundary_error",
                returned
                    .boundary
                    .map_or_else(|| "null".into(), |e| string(e.code())),
            ),
            ("deadline_ns", self.deadline_ns.to_string()),
            ("elapsed_ns", returned.elapsed_ns.to_string()),
            (
                "budget",
                object(&[
                    ("allowance", budget(&self.allowance)),
                    ("charged", budget(&charged)),
                    ("remaining", budget(&remaining)),
                ]),
            ),
            (
                "reservation",
                object(&[
                    ("bytes", self.reservation.bytes.to_string()),
                    ("network_bytes", self.reservation.network_bytes.to_string()),
                ]),
            ),
            (
                "byte_accounting",
                string("declared_native_ceiling_reserved_up_front"),
            ),
            ("latency_accounting", string("admitted_elapsed_ceiling_ms")),
            (
                "storage_admissions",
                returned.storage_admissions.to_string(),
            ),
        ])
    }
}

fn task_receipt(receipt: &TaskReceipt) -> String {
    let (outcome, reason) = match &receipt.outcome {
        TaskOutcome::Success => ("success", None),
        TaskOutcome::Cancelled => ("cancelled", None),
        TaskOutcome::Failed(reason) => ("failed", Some(reason.as_str())),
        TaskOutcome::Indeterminate(reason) => ("indeterminate", Some(reason.as_str())),
    };
    object(&[
        ("task_id", string(receipt.task_id.as_str())),
        ("region_id", string(receipt.region_id.as_str())),
        ("outcome", string(outcome)),
        ("reason", reason.map_or_else(|| "null".into(), string)),
        ("registered_ns", receipt.registered_at.0.to_string()),
        ("completed_ns", receipt.completed_at.0.to_string()),
    ])
}

#[cfg(test)]
#[path = "runtime_boundary_tests.rs"]
mod tests;
