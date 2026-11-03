#![forbid(unsafe_code)]
//! Actual Process → Property → Sensor ownership for bounded native JPEG work.
//!
//! Only retirement data escapes the synchronous task. The terminal diagnostic is
//! written after its native resources have returned and canonical closure is known.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::io::Write;
use std::time::{Duration, Instant};

use fss_cli::agent_json::{array, budget, object, string};
use fss_core::{
    BudgetVector, ContentDigest, ObligationId, ObligationState, OperationId, RegionId, RegionKind,
    RegionState, RegionTree, RootAuthoritySpec, RuntimeGrant, TaskId, TaskOutcome, TaskReceipt,
    TimestampNs,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::execution::{ExecutionError, TaskCompletion, TaskCx, TaskSpec, run_owned};
use fss_runtime::obligation::{ObligationTerminal, new_obligation};

use super::operation::{self, Effect, Owner, Report};
use super::plan::Options;
use crate::authentication::MAX_CREDENTIAL_BYTES;

const CONFIG: &str = "ERR-CAPTURE-RTSP-CONFIG-001";
const AUTHORITY: &str = "ERR-CAPTURE-RTSP-AUTHORITY-001";
const DEADLINE: &str = "ERR-CAPTURE-RTSP-DEADLINE-001";
const WORK: &str = "ERR-CAPTURE-RTSP-WORK-001";
const STORAGE: &str = "ERR-CAPTURE-RTSP-STORAGE-001";
const CUSTODY_ID: &str = "obligation:rtsp-jpeg-source-custody";
const CUSTODY_PREDICATE: &str =
    "original datagram publication is settled or its exact uncertain candidate remains explicit";
const STORAGE_GRANTS: [RuntimeGrant; 4] = [
    RuntimeGrant::ReadMedia,
    RuntimeGrant::ObjectStage,
    RuntimeGrant::ObjectPublish,
    RuntimeGrant::RetentionCommit,
];

fn failure(error: &ExecutionError) -> &'static str {
    match error {
        ExecutionError::Deadline { .. } | ExecutionError::ClockRegression { .. } => DEADLINE,
        ExecutionError::Budget(_) | ExecutionError::UnmeteredCost => WORK,
        _ => AUTHORITY,
    }
}

/// Labels bind the complete approved root, route, limits and optional credential file.
struct Resources {
    storage: String,
    network: String,
    secret: String,
}

/// Non-cloneable live task admission, including both sides of every clock read.
struct NativeOwner<'task, 'scope> {
    task: &'task TaskCx<'scope>,
    resources: &'task Resources,
    start: Instant,
    deadline_ns: u64,
    observed_ns: Cell<u64>,
    charged_ms: Cell<u64>,
    storage_admissions: Cell<u64>,
}

impl<'task, 'scope> NativeOwner<'task, 'scope> {
    fn new(
        task: &'task TaskCx<'scope>,
        resources: &'task Resources,
        deadline_ns: u64,
    ) -> Result<Self, &'static str> {
        task.checkpoint(TimestampNs(0), &BudgetVector::ZERO)
            .map_err(|error| failure(&error))?;
        Ok(Self {
            task,
            resources,
            start: Instant::now(),
            deadline_ns,
            observed_ns: Cell::new(0),
            charged_ms: Cell::new(0),
            storage_admissions: Cell::new(0),
        })
    }

    fn elapsed(&self) -> Result<u64, &'static str> {
        let now = u64::try_from(self.start.elapsed().as_nanos()).map_err(|_| DEADLINE)?;
        if now < self.observed_ns.get() {
            return Err(DEADLINE);
        }
        self.observed_ns.set(now);
        Ok(now)
    }

    /// Only observe already-finished work; this cannot reopen effect admission.
    fn retirement_time(&self) -> Result<u64, &'static str> {
        self.task
            .is_cancel_requested()
            .map_err(|error| failure(&error))?;
        self.elapsed()
    }
}

impl Owner for NativeOwner<'_, '_> {
    fn checkpoint(&self, effect: Effect) -> Result<u64, &'static str> {
        self.task
            .checkpoint(
                TimestampNs(i128::from(self.observed_ns.get())),
                &BudgetVector::ZERO,
            )
            .map_err(|error| failure(&error))?;
        let now = self.elapsed()?;
        let (grants, resource, storage): (&[RuntimeGrant], &str, bool) = match effect {
            Effect::Clock => (&[], "", false),
            Effect::StorageRead => (&[RuntimeGrant::ReadMedia], &self.resources.storage, true),
            // Existing-root recovery acquires locks and may settle metadata. Replay
            // has these exact storage grants but cannot acquire network or secrets.
            Effect::StorageWrite => (&STORAGE_GRANTS, &self.resources.storage, true),
            Effect::Network => (&[RuntimeGrant::AdapterNet], &self.resources.network, false),
            Effect::Secret => (&[RuntimeGrant::AdapterAuth], &self.resources.secret, true),
            Effect::Output => (&[RuntimeGrant::ReadMedia], &self.resources.storage, true),
        };
        let timestamp = TimestampNs(i128::from(now));
        for grant in grants {
            self.task
                .checkpoint_for(*grant, resource, timestamp, &BudgetVector::ZERO)
                .map_err(|error| failure(&error))?;
        }
        let milliseconds = now.div_ceil(1_000_000);
        let mut cost = BudgetVector::ZERO;
        cost.latency_ms = milliseconds.saturating_sub(self.charged_ms.get());
        cost.storage_operations = u64::from(storage);
        self.task
            .checkpoint(timestamp, &cost)
            .map_err(|error| failure(&error))?;
        self.charged_ms.set(milliseconds);
        if storage {
            self.storage_admissions
                .set(self.storage_admissions.get().saturating_add(1));
        }
        Ok(now)
    }

    fn wait(&self, wake_at_ns: Option<u64>) -> Result<(), &'static str> {
        let now = self.checkpoint(Effect::Clock)?;
        let remaining = self.deadline_ns.checked_sub(now).ok_or(DEADLINE)?;
        let delay = 1_000_000_u64
            .min(remaining)
            .min(wake_at_ns.map_or(u64::MAX, |wake| wake.saturating_sub(now)));
        if delay != 0 {
            std::thread::sleep(Duration::from_nanos(delay));
        }
        self.checkpoint(Effect::Clock)?;
        Ok(())
    }
}

fn multiply(value: u64, count: u64) -> Result<u64, &'static str> {
    value.checked_mul(count).ok_or(CONFIG)
}

fn sum(values: &[u64]) -> Result<u64, &'static str> {
    values.iter().try_fold(0_u64, |total, value| {
        total.checked_add(*value).ok_or(CONFIG)
    })
}

/// The ledger reserves declared finite ceilings, never claims invented actual bytes.
/// The archive, transport, decoder and JSON writer retain their independent hard caps.
fn allowances(options: &Options) -> Result<(BudgetVector, BudgetVector), &'static str> {
    let capture = options.replay.is_none();
    let network = if capture {
        sum(&[
            options.transport.max_received_bytes,
            options.transport.max_sent_bytes,
        ])?
    } else {
        0
    };
    let authentication = if capture && options.authentication.is_some() {
        sum(&[
            MAX_CREDENTIAL_BYTES as u64 + 1,
            multiply(options.max_steps, 16)?,
        ])?
    } else {
        0
    };
    let bytes = sum(&[
        options.storage.spool.max_total_bytes,
        options.archive.max_payload_bytes,
        network,
        multiply(options.jpeg.max_frame_bytes as u64, 2)?,
        // Includes native coefficient/scratch and luma storage; this is a reusable
        // workspace ceiling, not a claim of retained derivative images.
        multiply(options.decode.maximum_pixels as u64, 16)?,
        multiply(options.reorder.max_bytes as u64, 2)?,
        multiply(options.archive.max_datagrams as u64, 1024)?,
        multiply(options.jpeg.max_fragment_packets as u64, 512)?,
        multiply(options.jpeg.max_cached_quantizers as u64, 1024)?,
        options.transport.max_request_bytes as u64,
        options.report_bytes as u64,
        authentication,
        65_536,
    ])?;
    let operations = sum(&[
        multiply(options.max_steps, 64)?,
        multiply(options.archive.max_datagrams as u64, 64)?,
        multiply(options.storage.max_scan_entries as u64, 32)?,
        multiply(options.storage.spool.max_scan_entries as u64, 32)?,
        // Even one-byte short writes plus bounded Interrupted retries cannot
        // renew the output allowance or exhaust a hidden unmetered call loop.
        multiply(options.report_bytes as u64, 12)?,
        128,
    ])?;
    let allowance = BudgetVector::builder()
        .bytes(bytes)
        .network_bytes(network)
        .storage_operations(operations)
        .latency_ms(options.timeout_ns.div_ceil(1_000_000))
        .build()
        .map_err(|_| CONFIG)?;
    let mut reservation = BudgetVector::ZERO;
    reservation.bytes = bytes;
    reservation.network_bytes = network;
    Ok((allowance, reservation))
}

struct Runtime {
    process: AuthorityCx,
    property: AuthorityCx,
    sensor: AuthorityCx,
    tree: RegionTree,
    resources: Resources,
    allowance: BudgetVector,
    reservation: BudgetVector,
    task_id: TaskId,
    custody_id: ObligationId,
    deadline_ns: u64,
    replay: bool,
}

struct Returned {
    report: Option<Report>,
    result: Result<(), &'static str>,
    boundary: Option<&'static str>,
    elapsed_ns: u64,
    storage_admissions: u64,
}

impl Runtime {
    fn new(options: &Options, approval: ContentDigest) -> Result<Self, &'static str> {
        let (allowance, reservation) = allowances(options)?;
        let replay = options.replay.is_some();
        let resources = Resources {
            storage: format!("rtsp-jpeg-custody:{}", approval.to_text()),
            network: format!("rtsp-jpeg-route:{}", approval.to_text()),
            secret: format!("rtsp-jpeg-credential:{}", approval.to_text()),
        };
        let mut capabilities = STORAGE_GRANTS
            .iter()
            .map(|grant| grant.as_str().to_owned())
            .collect::<Vec<_>>();
        if !replay {
            capabilities.push(RuntimeGrant::AdapterNet.as_str().to_owned());
            if options.authentication.is_some() {
                capabilities.push(RuntimeGrant::AdapterAuth.as_str().to_owned());
            }
        }
        let spec = RootAuthoritySpec {
            trace_id: "trace:rtsp-jpeg-capture".into(),
            operation_id: OperationId::parse("operation:rtsp-jpeg-capture").map_err(|_| CONFIG)?,
            principal: options.principal.clone(),
            capabilities,
            deadline: Some(TimestampNs(i128::from(options.timeout_ns))),
            priority: 10,
            budgets: allowance,
            privacy_scope: "privacy:owner-original-rtsp-jpeg-custody".into(),
            retention_scope: "retention:explicit-original-rtsp-scope".into(),
            anchor_universe: approval,
            generation: options.scope.binding.key().generation,
        };
        let (mut process, mut tree) = AuthorityCx::root(
            spec.clone(),
            RegionId::new("region:rtsp-jpeg-process").map_err(|_| CONFIG)?,
            RegionKind::Process,
            allowance,
            TimestampNs(0),
        )
        .map_err(|_| AUTHORITY)?;
        let mut grants = process.grants().clone();
        for grant in STORAGE_GRANTS {
            grants = grants.with_scope(grant, BTreeSet::from([resources.storage.clone()]));
        }
        if !replay {
            grants = grants.with_scope(
                RuntimeGrant::AdapterNet,
                BTreeSet::from([resources.network.clone()]),
            );
            if options.authentication.is_some() {
                grants = grants.with_scope(
                    RuntimeGrant::AdapterAuth,
                    BTreeSet::from([resources.secret.clone()]),
                );
            }
        }
        process.narrow_grants(grants).map_err(|_| AUTHORITY)?;
        let mut property = process
            .scope_down(
                &mut tree,
                RegionId::new("region:rtsp-jpeg-property").map_err(|_| CONFIG)?,
                RegionKind::Property,
                allowance,
                spec.clone(),
                TimestampNs(0),
            )
            .map_err(|_| AUTHORITY)?;
        let sensor = property
            .scope_down(
                &mut tree,
                RegionId::new("region:rtsp-jpeg-sensor").map_err(|_| CONFIG)?,
                RegionKind::Sensor,
                allowance,
                spec,
                TimestampNs(0),
            )
            .map_err(|_| AUTHORITY)?;
        Ok(Self {
            process,
            property,
            sensor,
            tree,
            resources,
            allowance,
            reservation,
            task_id: TaskId::new("task:rtsp-jpeg-capture").map_err(|_| CONFIG)?,
            custody_id: ObligationId::parse(CUSTODY_ID).map_err(|_| CONFIG)?,
            deadline_ns: options.timeout_ns,
            replay,
        })
    }

    fn run(&mut self, options: &Options, out: &mut dyn Write) -> Result<(), &'static str> {
        let registration = TaskSpec {
            task_id: self.task_id.clone(),
            started_at: TimestampNs(0),
        };
        let resources = &self.resources;
        let custody_id = &self.custody_id;
        let reservation = self.reservation;
        let deadline_ns = self.deadline_ns;
        let replay = self.replay;
        let execution = run_owned(&mut self.sensor, &mut self.tree, registration, |task| {
            let mut owner = None;
            let mut report = None;
            let mut registered = false;
            let mut result = (|| {
                let custody = new_obligation(
                    custody_id.as_str(),
                    task.context().operation_id.clone(),
                    CUSTODY_PREDICATE,
                )
                .map_err(|_| CONFIG)?;
                task.register_obligation(custody, TimestampNs(0))
                    .map_err(|error| failure(&error))?;
                registered = true;
                task.checkpoint(TimestampNs(0), &reservation)
                    .map_err(|error| failure(&error))?;
                owner = Some(NativeOwner::new(task, resources, deadline_ns)?);
                let live = owner.as_ref().ok_or(AUTHORITY)?;
                report = Some(operation::run(options, live, out));
                report.as_ref().ok_or(AUTHORITY)?.result
            })();
            // Native work has returned: no socket, publisher, credentials, frame,
            // archive owner or entropy handle may remain in the result report.
            let mut boundary = None;
            let elapsed_ns = match &owner {
                Some(owner) => {
                    if let Err(error) = owner.checkpoint(Effect::Clock)
                        && result.is_ok()
                    {
                        result = Err(error);
                    }
                    match owner.retirement_time() {
                        Ok(now) => now,
                        Err(error) => {
                            boundary = Some(error);
                            owner.observed_ns.get()
                        }
                    }
                }
                None => 0,
            };
            if elapsed_ns >= deadline_ns && result.is_ok() {
                result = Err(DEADLINE);
            }
            let now = TimestampNs(i128::from(elapsed_ns));
            let recovery = report.as_ref().is_some_and(Report::recovery_required);
            if registered && !recovery {
                let proof = report
                    .as_ref()
                    .and_then(|report| report.pin.map(|pin| pin.head));
                // Replay must not promote an earlier pin after a later custody
                // revalidation failed. Capture retains its already-durable source.
                let terminal = if proof.is_some() && (!replay || result.is_ok()) {
                    ObligationTerminal::Completed
                } else {
                    ObligationTerminal::Failed
                };
                if let Err(error) = task.resolve_obligation(custody_id, terminal, proof, None, now)
                {
                    boundary = Some(failure(&error));
                }
            }
            if let Err(error) = task.begin_drain(now) {
                boundary = Some(failure(&error));
            }
            let outcome = if recovery {
                // A candidate is not a durability proof. Keep the original
                // obligation pending so finalization cannot claim quiescence.
                TaskOutcome::Indeterminate("rtsp_jpeg_source_recovery_required".into())
            } else if let Some(error) = boundary.or(result.err()) {
                TaskOutcome::Failed(error.into())
            } else {
                TaskOutcome::Success
            };
            TaskCompletion {
                output: Returned {
                    report,
                    result,
                    boundary,
                    elapsed_ns,
                    storage_admissions: owner.as_ref().map_or(0, |o| o.storage_admissions.get()),
                },
                outcome,
                completed_at: now,
            }
        });
        let (mut returned, receipt, entered) = match execution {
            Ok(run) => (run.output, run.receipt, true),
            Err(error) => (
                Returned {
                    report: None,
                    result: Err(failure(&error)),
                    boundary: Some(failure(&error)),
                    elapsed_ns: 0,
                    storage_admissions: 0,
                },
                Err(error),
                false,
            ),
        };
        let receipt_error = receipt.as_ref().err().map(failure);
        let quiescent = self.close(returned.elapsed_ns);
        let closure_failed = returned.boundary.is_some() || receipt_error.is_some() || !quiescent;
        let result = returned.result.and_then(|()| {
            returned
                .boundary
                .or(receipt_error)
                .or((!quiescent).then_some(STORAGE))
                .map_or(Ok(()), Err)
        });
        let runtime = self.report(&returned, &receipt, entered, quiescent);
        if let Some(report) = returned.report.as_mut() {
            report.result = result;
            // Bounded diagnostic output is retirement data, not resumed task work.
            // A failed write still fails the command; it cannot change the receipt.
            report.finish(out, runtime, closure_failed)
        } else {
            result
        }
    }

    fn close(&mut self, elapsed_ns: u64) -> bool {
        let close = (|| {
            let now = TimestampNs(i128::from(elapsed_ns));
            if self.tree.get(self.sensor.region())?.state != RegionState::Draining {
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
                        .filter(|obligation| obligation.state == ObligationState::Pending)
                        .map(|obligation| {
                            object(&[
                                ("id", string(obligation.obligation_id.as_str())),
                                ("terminal_predicate", string(&obligation.terminal_predicate)),
                                (
                                    "recovery_input_fields",
                                    array(&[
                                        string("source_prefix"),
                                        string("unconfirmed_candidate"),
                                    ]),
                                ),
                            ])
                        })
                        .collect::<Vec<_>>(),
                )
            },
        );
        let custody = node.and_then(|node| node.obligations.get(&self.custody_id));
        let custody_state = custody.map_or("unavailable", |obligation| match obligation.state {
            ObligationState::Pending => "pending",
            ObligationState::Verified => "verified",
            ObligationState::Failed => "failed",
            ObligationState::Cancelled => "cancelled",
            ObligationState::Indeterminate => "indeterminate",
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
                string(if self.replay {
                    "local_archive_publisher_reconstruction_decoder"
                } else {
                    "local_socket_archive_publisher_credentials_entropy_reconstruction_decoder"
                }),
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
                    .map_or_else(|| "null".into(), |error| string(failure(error))),
            ),
            ("pending_obligations", pending),
            ("custody_state", string(custody_state)),
            (
                "closure_error",
                returned.result.err().map_or_else(|| "null".into(), string),
            ),
            (
                "closure_boundary_error",
                returned.boundary.map_or_else(|| "null".into(), string),
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
                "storage_accounting",
                string("admitted_owner_boundaries_including_secret_and_output"),
            ),
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

pub(super) fn execute(options: &Options) -> Result<(), &'static str> {
    execute_with_output(options, &mut std::io::stdout())
}

pub(super) fn execute_with_output(
    options: &Options,
    out: &mut dyn Write,
) -> Result<(), &'static str> {
    options.admit()?;
    let mut runtime = Runtime::new(options, options.digest()?)?;
    runtime.run(options, out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn options(replay: bool) -> Result<Options, &'static str> {
        let digest = ContentDigest::sha256(b"JPEG runtime authority fixture").to_text();
        let mut arguments = vec![
            "--root",
            "/tmp/fss-jpeg-runtime-no-io",
            "--peer",
            "127.0.0.1:8554",
            "--authority",
            "127.0.0.1:8554",
            "--presentation",
            "/camera",
            "--control-root",
            "/",
            "--sensor-id",
            "sensor:jpeg-runtime",
            "--stream-id",
            "stream:jpeg-runtime",
            "--generation",
            "1",
            "--ingress",
            "1",
            "--ssrc",
            "7",
            "--anchor",
            &digest,
            "--receive-clock",
            &digest,
            "--retention-evidence",
            &digest,
            "--owner-authorized",
            "yes",
            "--plaintext",
            "yes",
            "--retain-originals",
            "yes",
        ];
        if replay {
            arguments.insert(0, "replay");
            arguments.extend([
                "--prefix-head",
                &digest,
                "--prefix-datagrams",
                "1",
                "--prefix-bytes",
                "1",
                "--configuration-evidence",
                &digest,
                "--reduced-rtcp",
                "no",
            ]);
        }
        let mut options = Options::parse(
            &arguments
                .into_iter()
                .map(OsString::from)
                .collect::<Vec<_>>(),
        )?;
        options.approval = Some(options.digest()?);
        Ok(options)
    }

    fn exercise(
        runtime: &mut Runtime,
        work: impl FnOnce(&TaskCx<'_>, &Resources) -> Result<(u64, TaskOutcome), &'static str>,
    ) -> Result<TaskReceipt, &'static str> {
        let resources = &runtime.resources;
        let run = run_owned(
            &mut runtime.sensor,
            &mut runtime.tree,
            TaskSpec {
                task_id: runtime.task_id.clone(),
                started_at: TimestampNs(0),
            },
            |task| {
                let (output, outcome, completed_at) = match work(task, resources) {
                    Ok((now, outcome)) => (Ok(()), outcome, TimestampNs(i128::from(now))),
                    Err(error) => (
                        Err(error),
                        TaskOutcome::Failed(error.into()),
                        TimestampNs(0),
                    ),
                };
                TaskCompletion {
                    output,
                    outcome,
                    completed_at,
                }
            },
        )
        .map_err(|error| failure(&error))?;
        run.output?;
        run.receipt.map_err(|error| failure(&error))
    }

    #[test]
    fn replay_live_owner_admits_recovery_and_refuses_network_secret_and_other_scope()
    -> Result<(), &'static str> {
        let options = options(true)?;
        let mut runtime = Runtime::new(&options, options.digest()?)?;
        assert_eq!(runtime.allowance.network_bytes, 0);
        let receipt = exercise(&mut runtime, |task, resources| {
            let owner = NativeOwner::new(task, resources, options.timeout_ns)?;
            owner.checkpoint(Effect::StorageWrite)?;
            owner.checkpoint(Effect::StorageRead)?;
            assert_eq!(owner.checkpoint(Effect::Network), Err(AUTHORITY));
            assert_eq!(owner.checkpoint(Effect::Secret), Err(AUTHORITY));
            let now = owner.checkpoint(Effect::Clock)?;
            assert!(
                task.checkpoint_for(
                    RuntimeGrant::ReadMedia,
                    "another-approved-root",
                    TimestampNs(i128::from(now)),
                    &BudgetVector::ZERO,
                )
                .is_err()
            );
            assert_eq!(owner.storage_admissions.get(), 2);
            task.begin_drain(TimestampNs(i128::from(now)))
                .map_err(|error| failure(&error))?;
            Ok((now, TaskOutcome::Success))
        })?;
        assert_eq!(receipt.outcome, TaskOutcome::Success);
        assert!(runtime.close(u64::try_from(receipt.completed_at.0).map_err(|_| DEADLINE)?));
        Ok(())
    }

    #[test]
    fn cancellation_revokes_existing_owner_without_erasing_actual_storage_charge()
    -> Result<(), &'static str> {
        let options = options(false)?;
        let mut runtime = Runtime::new(&options, options.digest()?)?;
        let receipt = exercise(&mut runtime, |task, resources| {
            let owner = NativeOwner::new(task, resources, options.timeout_ns)?;
            owner.checkpoint(Effect::Network)?;
            owner.checkpoint(Effect::StorageRead)?;
            let remaining = task.remaining_budget().map_err(|error| failure(&error))?;
            let now = owner.retirement_time()?;
            task.request_cancellation(TimestampNs(i128::from(now)))
                .map_err(|error| failure(&error))?;
            assert_eq!(owner.checkpoint(Effect::StorageRead), Err(AUTHORITY));
            assert_eq!(owner.wait(None), Err(AUTHORITY));
            assert_eq!(
                task.remaining_budget().map_err(|error| failure(&error))?,
                remaining
            );
            assert_eq!(owner.storage_admissions.get(), 1);
            task.begin_drain(TimestampNs(i128::from(now)))
                .map_err(|error| failure(&error))?;
            Ok((now, TaskOutcome::Cancelled))
        })?;
        assert_eq!(receipt.outcome, TaskOutcome::Cancelled);
        assert!(runtime.close(u64::try_from(receipt.completed_at.0).map_err(|_| DEADLINE)?));
        Ok(())
    }

    #[test]
    fn uncertain_source_candidate_keeps_canonical_custody_pending_after_task_return()
    -> Result<(), &'static str> {
        let options = options(false)?;
        let mut runtime = Runtime::new(&options, options.digest()?)?;
        let receipt = exercise(&mut runtime, |task, _| {
            let obligation = new_obligation(
                CUSTODY_ID,
                task.context().operation_id.clone(),
                CUSTODY_PREDICATE,
            )
            .map_err(|_| CONFIG)?;
            task.register_obligation(obligation, TimestampNs(0))
                .map_err(|error| failure(&error))?;
            task.begin_drain(TimestampNs(1))
                .map_err(|error| failure(&error))?;
            Ok((
                1,
                TaskOutcome::Indeterminate("rtsp_jpeg_source_recovery_required".into()),
            ))
        })?;
        assert!(matches!(receipt.outcome, TaskOutcome::Indeterminate(_)));
        assert!(!runtime.close(1));
        let sensor = runtime
            .tree
            .get(runtime.sensor.region())
            .map_err(|_| AUTHORITY)?;
        assert!(sensor.active_tasks.is_empty());
        assert_eq!(sensor.state, RegionState::Draining);
        assert_eq!(
            sensor.obligations.get(&runtime.custody_id).map(|o| o.state),
            Some(ObligationState::Pending)
        );
        assert!(sensor.quiescence_proof.is_none());
        assert!(
            runtime
                .tree
                .get(runtime.process.region())
                .map_err(|_| AUTHORITY)?
                .quiescence_proof
                .is_none()
        );
        Ok(())
    }
}
