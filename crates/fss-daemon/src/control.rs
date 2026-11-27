#![forbid(unsafe_code)]
//! `ControlPlaneRegion` owning the local `fss-ipc` UDS server, lock-free live status snapshots,
//! and sub-500ms `SubscribeDeltas` fan-out.
//!
//! Semantic plane: `"authority"`.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

use fss_core::contract_basis::reference_contract_basis;
use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, DeltaPriority, ErrorId, MeaningfulDeltaClass,
    OperationId,
};
use fss_ipc::{
    ActiveScrubStatus, BoundedControlOp, CameraLiveStatus, CameraRetentionForecast,
    ControlOperationState, DaemonIpcHandler, DeltaEventSummary, DeltaStreamSink,
    ERR_IPC_SERVER_SHUTDOWN_001, ERR_IPC_WIRE_CORRUPT_001, IpcResponse, IpcServer, IpcServerConfig,
    LiveDaemonStatus, RequestContext, RingWatermarkStatus, StreamEndReason, parse_error_id,
};

pub use crate::control_client::{
    DaemonRuntimeDescriptor, query_camera_retention_forecast, query_live_daemon_status,
    request_live_daemon_stop,
};
use crate::error::{DaemonError, ERR_DAEMON_CONTROL_APPROVAL_001, ERR_DAEMON_UNKNOWN_CAMERA_001};

mod delta_log;
mod forwarding;
pub mod journal;
mod manifest_reload;

use manifest_reload::ManifestReloadSource;
pub use manifest_reload::{
    DAEMON_MANIFEST_RELOAD_APPROVAL_DOMAIN, manifest_reload_approval_digest,
};

use delta_log::BufferedDeltaLog;
use forwarding::ForwardedBatches;
use journal::{ControlHistoryReport, ControlProgress, ControlReplayLookup, DurableControlJournal};

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;

/// Canonical digest domain for graceful daemon shutdown approval digests.
pub const DAEMON_SHUTDOWN_APPROVAL_DOMAIN: &str = "fss.daemon.shutdown_approval.v1";
/// Canonical digest domain for non-secret local runtime descriptors (`daemon.meta.json`).
pub const DAEMON_RUNTIME_DESCRIPTOR_DOMAIN: &str = "fss.daemon.runtime_descriptor.v1";
/// Schema identifier for `<root>/run/daemon.meta.json`.
pub const DAEMON_RUNTIME_DESCRIPTOR_SCHEMA: &str = "fss.daemon_runtime_descriptor.v1";
/// Non-secret owner-only runtime metadata filename inside `<root>/run/`.
pub const DAEMON_RUNTIME_META_FILENAME: &str = "daemon.meta.json";
/// Closed target sentinel for `BoundedControlOp::StopCamera` requesting graceful daemon shutdown.
pub const DAEMON_STOP_TARGET: &str = "daemon:all";

pub(crate) const CAP_OBSERVE_STATUS: &str = "CAP-OBSERVE-STATUS-001";

const MAX_DELTA_BUS_EVENTS: usize = 4_096;
// Accepted work remains FIFO until the supervisor drains it; pressure never evicts a command.
const MAX_QUEUED_CONTROL_COMMANDS: usize = 1_024;
const SUBSCRIBE_WAIT_SLICE: Duration = Duration::from_millis(20);
const SUBSCRIBE_IDLE_WINDOW: Duration = Duration::from_millis(450);

/// Computes the deterministic approval digest required to authorize graceful daemon shutdown.
#[must_use]
pub fn daemon_stop_approval_digest(
    deployment_id: &str,
    root_digest: ContentDigest,
) -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.text("fss.canonical.v1");
    enc.text(DAEMON_SHUTDOWN_APPROVAL_DOMAIN);
    enc.text(deployment_id);
    enc.digest(root_digest);
    enc.text(DAEMON_STOP_TARGET);
    ContentDigest::sha256(&enc.finish())
}

/// Computes the deterministic approval digest for a camera or maintenance bounded control op.
/// Manifest reload instead requires `manifest_reload_approval_digest` from a live preview.
#[must_use]
pub fn control_op_approval_digest(
    deployment_id: &str,
    op: BoundedControlOp,
    target_camera_id: Option<&str>,
) -> ContentDigest {
    let mut enc = CanonicalEncoder::new();
    enc.text("fss.canonical.v1");
    enc.text(DAEMON_SHUTDOWN_APPROVAL_DOMAIN);
    enc.text(deployment_id);
    enc.text(op.as_str());
    match target_camera_id {
        Some(cam) => {
            enc.bool(true);
            enc.text(cam);
        }
        None => enc.bool(false),
    }
    ContentDigest::sha256(&enc.finish())
}

/// Queued bounded control command drained by the supervisor loop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingControlCommand {
    /// Assigned operation identifier.
    pub operation_id: OperationId,
    /// Closed bounded control operation.
    pub op: BoundedControlOp,
    /// Optional target camera identifier.
    pub target_camera_id: Option<String>,
    /// Verified approval digest.
    pub approval_digest: ContentDigest,
}

/// Forwarded canonical delta batch write hook implemented by [`crate::storage::StorageEngine`].
pub trait ForwardBatchWriter: Send + Sync + 'static {
    /// Validates and commits forwarded canonical `EvidenceDeltaBatch` bytes via `CommitCombiner`.
    fn forward_delta_batch(
        &self,
        batch_bytes: &[u8],
    ) -> Result<(u64, ContentDigest, ContentDigest), DaemonError>;

    /// Forwards one exact request using a stable caller key and complete request digest.
    ///
    /// The digest binds the canonical batch bytes, approval and authenticated context.
    /// The default supports only this process's retained admission records. Durable
    /// implementations must reject changed requests, reserve before mutation and retain
    /// ambiguous attempts without redispatching them.
    fn forward_delta_batch_idempotent(
        &self,
        _idempotency_key: ContentDigest,
        _request_digest: ContentDigest,
        batch_bytes: &[u8],
    ) -> Result<ForwardBatchReceipt, DaemonError> {
        let (commit_sequence, history_root, state_root) = self.forward_delta_batch(batch_bytes)?;
        Ok(ForwardBatchReceipt {
            commit_sequence,
            history_root,
            state_root,
            replayed: false,
        })
    }

    /// Whether exact-request reservations and receipts survive cache eviction and restart.
    ///
    /// Returning true permits the handler to evict settled in-memory records. The writer
    /// must retain both conflicts and unresolved outcomes, including an unwind or crash
    /// after dispatch, so another lookup can never silently perform the write again.
    fn supports_durable_idempotency(&self) -> bool {
        false
    }
}

/// Verified result of a forwarded canonical batch or an exact durable replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForwardBatchReceipt {
    /// Original authoritative commit sequence.
    pub commit_sequence: u64,
    /// Original committed history root.
    pub history_root: ContentDigest,
    /// Original committed state root.
    pub state_root: ContentDigest,
    /// True when the writer returned an existing receipt without a new mutation.
    pub replayed: bool,
}

/// Point-in-time status snapshot published lock-free from supervisor to IPC readers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlStatusSnapshot {
    /// Authoritative ledger head commit sequence.
    pub head_commit_sequence: u64,
    /// Authoritative history-chain root digest.
    pub history_root: ContentDigest,
    /// Authoritative state root digest.
    pub state_root: ContentDigest,
    /// Per-camera live telemetry rows.
    pub cameras: Vec<CameraLiveStatus>,
    /// Retention ring occupancy watermark.
    pub ring: RingWatermarkStatus,
    /// Latest incremental scrubber status.
    pub scrub: ActiveScrubStatus,
}

/// Shared zero-contention control-plane state bridging `IpcServer` workers and `DaemonSupervisor`.
pub struct ControlPlaneShared {
    started_at: Instant,
    deployment_id: String,
    deployment_root_digest: ContentDigest,
    known_cameras: Vec<String>,
    head_commit_sequence: AtomicU64,
    next_op_seq: AtomicU64,
    shutdown_requested: AtomicBool,
    status_snapshot: RwLock<ControlStatusSnapshot>,
    retention_forecasts: RwLock<BTreeMap<String, CameraRetentionForecast>>,
    manifest_reload_source: RwLock<Option<ManifestReloadSource>>,
    delta_log: Mutex<BufferedDeltaLog>,
    delta_notify: Condvar,
    control_queue: Mutex<VecDeque<PendingControlCommand>>,
    control_journal: Mutex<Option<DurableControlJournal>>,
    forwarded_batches: ForwardedBatches,
    forward_writer: Arc<dyn ForwardBatchWriter>,
}

impl ControlPlaneShared {
    /// Constructs process-local control-plane state for embedded callers and fixtures.
    /// `DaemonSupervisor` uses the durable constructor before opening camera drivers.
    #[must_use]
    pub fn new(
        deployment_id: impl Into<String>,
        deployment_root_digest: ContentDigest,
        known_cameras: Vec<String>,
        initial_status: ControlStatusSnapshot,
        forward_writer: Arc<dyn ForwardBatchWriter>,
    ) -> Arc<Self> {
        Self::build(
            deployment_id.into(),
            deployment_root_digest,
            known_cameras,
            initial_status,
            forward_writer,
            None,
        )
    }

    /// Binds durable intake to the daemon's control owner. Recovery never reconstructs a queue.
    pub(crate) fn new_durable(
        deployment_id: String,
        deployment_root_digest: ContentDigest,
        known_cameras: Vec<String>,
        initial_status: ControlStatusSnapshot,
        forward_writer: Arc<dyn ForwardBatchWriter>,
        journal: DurableControlJournal,
    ) -> Arc<Self> {
        Self::build(
            deployment_id,
            deployment_root_digest,
            known_cameras,
            initial_status,
            forward_writer,
            Some(journal),
        )
    }

    fn build(
        deployment_id: String,
        deployment_root_digest: ContentDigest,
        known_cameras: Vec<String>,
        initial_status: ControlStatusSnapshot,
        forward_writer: Arc<dyn ForwardBatchWriter>,
        journal: Option<DurableControlJournal>,
    ) -> Arc<Self> {
        let initial_seq = initial_status.head_commit_sequence;
        Arc::new(Self {
            started_at: Instant::now(),
            deployment_id,
            deployment_root_digest,
            known_cameras,
            head_commit_sequence: AtomicU64::new(initial_seq),
            next_op_seq: AtomicU64::new(1),
            shutdown_requested: AtomicBool::new(false),
            status_snapshot: RwLock::new(initial_status),
            retention_forecasts: RwLock::new(BTreeMap::new()),
            manifest_reload_source: RwLock::new(None),
            delta_log: Mutex::new(BufferedDeltaLog::new(initial_seq)),
            delta_notify: Condvar::new(),
            control_queue: Mutex::new(VecDeque::new()),
            control_journal: Mutex::new(journal),
            forwarded_batches: ForwardedBatches::default(),
            forward_writer,
        })
    }

    pub(crate) fn publish_retention_forecasts(
        &self,
        rows: BTreeMap<String, CameraRetentionForecast>,
    ) {
        if let Ok(mut snapshot) = self.retention_forecasts.write() {
            *snapshot = rows;
        }
    }

    /// Publishes an updated live status snapshot for O(1) IPC reads.
    pub fn publish_status(&self, snapshot: ControlStatusSnapshot) {
        self.head_commit_sequence
            .fetch_max(snapshot.head_commit_sequence, Ordering::AcqRel);
        if let Ok(mut guard) = self.status_snapshot.write() {
            *guard = snapshot;
        }
    }

    /// Pushes one committed delta summary to the live fan-out bus and wakes all subscribers.
    pub fn publish_delta_summary(
        &self,
        commit_sequence: u64,
        delta_digest: ContentDigest,
        delta_class: MeaningfulDeltaClass,
        priority: DeltaPriority,
        summary: impl Into<String>,
    ) {
        let event = DeltaEventSummary {
            delta_class,
            priority,
            summary: summary.into(),
        };
        let Ok(summary_canonical) = event.try_canonical_bytes() else {
            return;
        };
        if let Ok(mut log) = self.delta_log.lock() {
            log.push(commit_sequence, delta_digest, summary_canonical);
            // A subscriber opening against this head must also see its retained summary.
            self.head_commit_sequence
                .fetch_max(commit_sequence, Ordering::AcqRel);
            self.delta_notify.notify_all();
        }
    }

    /// Returns `true` once graceful shutdown has been requested (via IPC or signal/caller).
    #[must_use]
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::Acquire)
    }

    /// Marks graceful shutdown requested and immediately wakes all waiting delta subscribers.
    pub fn request_shutdown(&self) {
        // Serialize shutdown with the final admission check and insertion.
        // A poisoned queue must still allow the daemon to shut down.
        let _queue = match self.control_queue.lock() {
            Ok(queue) => queue,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.shutdown_requested.store(true, Ordering::Release);
        self.delta_notify.notify_all();
    }

    /// Borrows the atomic shutdown flag for cooperative `CxTimerBoundary` tick waits.
    pub(crate) fn shutdown_flag(&self) -> &AtomicBool {
        &self.shutdown_requested
    }

    /// Transfers one bounded turn, retaining dispatch fences for durable owners.
    /// Use `control_history` for inspection; draining transfers execution ownership.
    #[must_use]
    pub fn drain_control_commands(&self) -> Vec<PendingControlCommand> {
        let durable = self
            .control_journal
            .lock()
            .map(|journal| journal.is_some())
            .unwrap_or(true);
        if !durable {
            return match self.control_queue.lock() {
                Ok(mut queue) => queue.drain(..).collect(),
                Err(_) => Vec::new(),
            };
        }
        let allowance = self.queued_control_command_count().unwrap_or_default();
        let mut commands = Vec::with_capacity(allowance);
        for _ in 0..allowance {
            match self.take_control_command() {
                Ok(Some(command)) => commands.push(command),
                Ok(None) | Err(_) => break,
            }
        }
        commands
    }

    /// Bounded current/recovered history. A process-local owner returns `None`.
    pub fn control_history(
        &self,
        maximum: usize,
    ) -> Result<Option<ControlHistoryReport>, DaemonError> {
        let guard = self
            .control_journal
            .lock()
            .map_err(|_| DaemonError::LockPoisoned {
                component: "control_journal",
            })?;
        guard
            .as_ref()
            .map(|journal| {
                journal
                    .inspect(maximum)
                    .map_err(DaemonError::ControlHistory)
            })
            .transpose()
    }

    pub(crate) fn record_control_progress(
        &self,
        operation_id: &OperationId,
        progress: ControlProgress,
    ) -> Result<(), DaemonError> {
        let result = self
            .control_journal
            .lock()
            .map_err(|_| DaemonError::LockPoisoned {
                component: "control_journal",
            })
            .and_then(|mut guard| match guard.as_mut() {
                Some(journal) => journal
                    .transition(operation_id, progress)
                    .map_err(DaemonError::ControlHistory),
                None => Ok(()),
            });
        if result.is_err() {
            // Some callers hold the queue. Never acquire its mutex in the opposite order.
            self.shutdown_requested.store(true, Ordering::Release);
            self.delta_notify.notify_all();
        }
        result
    }

    fn retain_control(
        &self,
        ctx: &RequestContext,
        op: BoundedControlOp,
        target: Option<&str>,
        approval: ContentDigest,
        idempotency_key: Option<ContentDigest>,
    ) -> Result<PendingControlCommand, DaemonError> {
        let mut guard = self
            .control_journal
            .lock()
            .map_err(|_| DaemonError::LockPoisoned {
                component: "control_journal",
            })?;
        match guard.as_mut() {
            Some(journal) => {
                let result = journal
                    .admit_request(ctx, op, target, approval, idempotency_key)
                    .map_err(DaemonError::ControlHistory);
                if journal.is_poisoned() {
                    self.shutdown_requested.store(true, Ordering::Release);
                    self.delta_notify.notify_all();
                }
                result
            }
            None if idempotency_key.is_some() => Err(DaemonError::ControlHistory(
                fss_runtime::effect_journal::EffectPersistenceError::InvalidHistory(
                    "keyed control requires durable intake",
                ),
            )),
            None => Ok(PendingControlCommand {
                operation_id: self.alloc_operation_id(op),
                op,
                target_camera_id: target.map(str::to_owned),
                approval_digest: approval,
            }),
        }
    }

    /// Looks up a retained key while the caller owns the queue admission lock.
    /// Returning a replay never restores live dispatch authority or changes history.
    fn replay_control(
        &self,
        ctx: &RequestContext,
        op: BoundedControlOp,
        target: Option<&str>,
        approval: ContentDigest,
        idempotency_key: Option<ContentDigest>,
    ) -> Option<IpcResponse> {
        let key = idempotency_key?;
        let Ok(guard) = self.control_journal.lock() else {
            return Some(make_refused(
                ctx.request_id,
                crate::error::ERR_DAEMON_SHUTDOWN_001,
                "durable control history is unavailable",
                false,
            ));
        };
        let Some(journal) = guard.as_ref() else {
            return Some(make_refused(
                ctx.request_id,
                fss_ipc::ERR_IPC_CAPABILITY_DENIED_001,
                "keyed control requires a durable control owner",
                false,
            ));
        };
        match journal.replay(ctx, key, op, target, approval) {
            Ok(ControlReplayLookup::Missing) => None,
            Ok(ControlReplayLookup::Match(entry)) => Some(IpcResponse::ControlReplayed {
                request_id: ctx.request_id,
                operation_id: entry.command.operation_id.clone(),
                progress: entry.progress,
                recovered: entry.recovered,
            }),
            Ok(ControlReplayLookup::Conflict) => Some(make_refused(
                ctx.request_id,
                "ERR-IDEMPOTENCY-CONFLICT-001",
                "control retry key is already bound to different request authority or intent",
                false,
            )),
            Err(error) => Some(make_refused(
                ctx.request_id,
                DaemonError::ControlHistory(error).error_id(),
                "control retry history could not be verified",
                false,
            )),
        }
    }

    /// Freezes the size of one supervisor turn without removing unstarted work.
    pub(crate) fn queued_control_command_count(&self) -> Result<usize, DaemonError> {
        self.control_queue
            .lock()
            .map(|queue| queue.len())
            .map_err(|_| DaemonError::LockPoisoned {
                component: "control_queue",
            })
    }

    /// Transfers only the next command; later commands retain their queue owner if
    /// execution fails after this transfer.
    pub(crate) fn take_control_command(
        &self,
    ) -> Result<Option<PendingControlCommand>, DaemonError> {
        let mut queue = self
            .control_queue
            .lock()
            .map_err(|_| DaemonError::LockPoisoned {
                component: "control_queue",
            })?;
        if self.is_shutdown_requested() {
            return Ok(None);
        }
        if let Some(command) = queue.front()
            && command.op != BoundedControlOp::TriggerScrub
        {
            self.record_control_progress(&command.operation_id, ControlProgress::DispatchStarted)?;
        }
        Ok(queue.pop_front())
    }

    /// Closes admission and transfers definitely unstarted commands to shutdown.
    /// Recover the owned queue even when poisoned, while preserving the error.
    pub(crate) fn cancel_unstarted_controls(
        &self,
    ) -> (Vec<PendingControlCommand>, Option<DaemonError>) {
        let (mut queue, mut error) = match self.control_queue.lock() {
            Ok(queue) => (queue, None),
            Err(poisoned) => (
                poisoned.into_inner(),
                Some(DaemonError::LockPoisoned {
                    component: "control_queue",
                }),
            ),
        };
        self.shutdown_requested.store(true, Ordering::Release);
        let commands: Vec<_> = queue.drain(..).collect();
        for command in &commands {
            if let Err(cause) = self.record_control_progress(
                &command.operation_id,
                ControlProgress::CancelledBeforeExecution,
            ) {
                error.get_or_insert(cause);
            }
        }
        self.delta_notify.notify_all();
        (commands, error)
    }

    /// Returns the expected canonical shutdown approval digest for this daemon.
    #[must_use]
    pub fn expected_stop_approval(&self) -> ContentDigest {
        daemon_stop_approval_digest(&self.deployment_id, self.deployment_root_digest)
    }

    fn alloc_operation_id(&self, op: BoundedControlOp) -> OperationId {
        let seq = self.next_op_seq.fetch_add(1, Ordering::Relaxed);
        if let Ok(id) = OperationId::parse(format!("op:ctrl:{}:{seq}", op.as_str())) {
            return id;
        }
        loop {
            if let Ok(id) = OperationId::parse("op:ctrl:0") {
                return id;
            }
        }
    }
}

struct DaemonIpcHandlerAdapter {
    shared: Arc<ControlPlaneShared>,
}

impl DaemonIpcHandler for DaemonIpcHandlerAdapter {
    fn head_commit_sequence(&self) -> u64 {
        self.shared.head_commit_sequence.load(Ordering::Acquire)
    }

    fn submit_delta_batch(
        &self,
        ctx: &RequestContext,
        idempotency_key: ContentDigest,
        batch_bytes: &[u8],
        approval_digest: Option<ContentDigest>,
    ) -> IpcResponse {
        self.shared.forwarded_batches.submit(
            &self.shared,
            ctx,
            idempotency_key,
            batch_bytes,
            approval_digest,
        )
    }

    fn query_retention_forecast(&self, ctx: &RequestContext, camera_id: &str) -> IpcResponse {
        if !ctx
            .granted_capabilities
            .iter()
            .any(|cap| cap == CAP_OBSERVE_STATUS)
        {
            return make_refused(
                ctx.request_id,
                fss_ipc::ERR_IPC_CAPABILITY_DENIED_001,
                "retention forecast requires CAP-OBSERVE-STATUS-001",
                false,
            );
        }
        let Ok(rows) = self.shared.retention_forecasts.read() else {
            return make_refused(
                ctx.request_id,
                ERR_IPC_WIRE_CORRUPT_001,
                "forecast unavailable",
                true,
            );
        };
        match rows.get(camera_id) {
            Some(row) => IpcResponse::RetentionForecast {
                request_id: ctx.request_id,
                forecast: row.clone(),
            },
            None => make_refused(
                ctx.request_id,
                ERR_DAEMON_UNKNOWN_CAMERA_001,
                "unknown camera",
                false,
            ),
        }
    }

    fn preview_manifest_reload(&self, ctx: &RequestContext) -> IpcResponse {
        if !ctx
            .granted_capabilities
            .iter()
            .any(|cap| cap == CAP_OBSERVE_STATUS)
        {
            return make_refused(
                ctx.request_id,
                fss_ipc::ERR_IPC_CAPABILITY_DENIED_001,
                "manifest reload preview requires CAP-OBSERVE-STATUS-001",
                false,
            );
        }
        match self.shared.read_manifest_reload_preview(ctx) {
            Ok(preview) => IpcResponse::ManifestReloadPreview {
                request_id: ctx.request_id,
                active_manifest_digest: preview.active_manifest_digest,
                candidate_manifest_digest: preview.candidate_manifest_digest,
                approval_digest: preview.approval_digest,
            },
            Err(response) => response,
        }
    }

    fn query_live_status(
        &self,
        ctx: &RequestContext,
        include_cameras: bool,
        include_ring: bool,
    ) -> IpcResponse {
        let Ok(snap) = self.shared.status_snapshot.read().map(|g| g.clone()) else {
            return make_refused(
                ctx.request_id,
                ERR_IPC_WIRE_CORRUPT_001,
                "status snapshot unavailable",
                true,
            );
        };
        let uptime_ms =
            u64::try_from(self.shared.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        IpcResponse::LiveStatus(LiveDaemonStatus {
            request_id: ctx.request_id,
            daemon_uptime_ms: uptime_ms,
            head_commit_sequence: snap.head_commit_sequence,
            history_root: snap.history_root,
            state_root: snap.state_root,
            active_connections: 1,
            cameras: if include_cameras {
                snap.cameras
            } else {
                Vec::new()
            },
            ring: if include_ring { Some(snap.ring) } else { None },
            scrub: snap.scrub,
        })
    }

    fn subscribe_deltas(
        &self,
        ctx: &RequestContext,
        since_commit_seq: u64,
        max_batch: u32,
        sink: &mut DeltaStreamSink<'_>,
    ) -> StreamEndReason {
        let mut bus_cursor = match self.shared.delta_log.lock() {
            Ok(guard) => {
                let head = self.shared.head_commit_sequence.load(Ordering::Acquire);
                match guard.start(since_commit_seq, head) {
                    Ok(cursor) => cursor,
                    Err(reason) => return reason,
                }
            }
            Err(_) => return StreamEndReason::DaemonShuttingDown,
        };
        if max_batch == 0 {
            return StreamEndReason::BatchLimitReached;
        }

        let deadline = Instant::now() + SUBSCRIBE_IDLE_WINDOW;
        loop {
            if ctx.is_cancelled() {
                return StreamEndReason::Cancelled;
            }
            if self.shared.is_shutdown_requested() {
                return StreamEndReason::DaemonShuttingDown;
            }
            let batch = match self.shared.delta_log.lock() {
                Ok(guard) => {
                    match guard.read_after(bus_cursor, max_batch.saturating_sub(sink.emitted())) {
                        Ok(batch) => batch,
                        Err(reason) => return reason,
                    }
                }
                Err(_) => return StreamEndReason::DaemonShuttingDown,
            };
            for event in batch.events {
                if sink
                    .emit_delta(
                        event.commit_sequence,
                        event.delta_digest,
                        event.summary_canonical,
                    )
                    .is_err()
                {
                    return StreamEndReason::Cancelled;
                }
                bus_cursor.advance(event.bus_seq, event.commit_sequence);
            }
            let Ok(guard) = self.shared.delta_log.lock() else {
                return StreamEndReason::DaemonShuttingDown;
            };
            if let Some(reason) = batch.end_reason {
                // Socket writes release the log lock. Recheck any loss or same-commit
                // remainder that appeared while the previously copied batch was delivered.
                return guard.finish(bus_cursor, reason);
            }
            match guard.has_pending(bus_cursor) {
                Ok(true) => continue,
                Err(reason) => return reason,
                Ok(false) => {}
            }
            if Instant::now() >= deadline {
                return StreamEndReason::Completed;
            }
            let wait = deadline
                .saturating_duration_since(Instant::now())
                .min(SUBSCRIBE_WAIT_SLICE);
            let _ = self.shared.delta_notify.wait_timeout(guard, wait);
        }
    }

    fn submit_bounded_control(
        &self,
        ctx: &RequestContext,
        op: BoundedControlOp,
        target_camera_id: Option<&str>,
        approval_digest: ContentDigest,
    ) -> IpcResponse {
        self.submit_control(ctx, op, target_camera_id, approval_digest, None)
    }

    fn submit_idempotent_control(
        &self,
        ctx: &RequestContext,
        idempotency_key: ContentDigest,
        op: BoundedControlOp,
        target_camera_id: Option<&str>,
        approval_digest: ContentDigest,
    ) -> IpcResponse {
        self.submit_control(
            ctx,
            op,
            target_camera_id,
            approval_digest,
            Some(idempotency_key),
        )
    }
}

impl DaemonIpcHandlerAdapter {
    fn submit_control(
        &self,
        ctx: &RequestContext,
        op: BoundedControlOp,
        target_camera_id: Option<&str>,
        approval_digest: ContentDigest,
        idempotency_key: Option<ContentDigest>,
    ) -> IpcResponse {
        if ctx.is_cancelled() {
            return IpcResponse::Cancelled {
                request_id: ctx.request_id,
            };
        }
        if op == BoundedControlOp::StopCamera && target_camera_id == Some(DAEMON_STOP_TARGET) {
            if approval_digest != self.shared.expected_stop_approval() {
                return make_refused(
                    ctx.request_id,
                    ERR_DAEMON_CONTROL_APPROVAL_001,
                    "shutdown approval digest mismatch",
                    false,
                );
            }
            let _queue = match self.shared.control_queue.lock() {
                Ok(queue) => queue,
                // Shutdown retains ownership even when another queue user panicked.
                Err(poisoned) => poisoned.into_inner(),
            };
            if ctx.is_cancelled() {
                return IpcResponse::Cancelled {
                    request_id: ctx.request_id,
                };
            }
            if let Some(response) = self.shared.replay_control(
                ctx,
                op,
                target_camera_id,
                approval_digest,
                idempotency_key,
            ) {
                return response;
            }
            let command = match self.shared.retain_control(
                ctx,
                op,
                target_camera_id,
                approval_digest,
                idempotency_key,
            ) {
                Ok(command) => command,
                Err(error) => {
                    return make_refused(
                        ctx.request_id,
                        error.error_id(),
                        "control intake was not acknowledged; inspect durable history before retry",
                        false,
                    );
                }
            };
            if ctx.is_cancelled() {
                if let Err(error) = self.shared.record_control_progress(
                    &command.operation_id,
                    ControlProgress::CancelledBeforeExecution,
                ) {
                    return make_refused(
                        ctx.request_id,
                        error.error_id(),
                        "shutdown cancellation custody is uncertain; inspect durable history before retry",
                        false,
                    );
                }
                return IpcResponse::Cancelled {
                    request_id: ctx.request_id,
                };
            }
            if let Err(error) = self
                .shared
                .record_control_progress(&command.operation_id, ControlProgress::DispatchStarted)
            {
                return make_refused(
                    ctx.request_id,
                    error.error_id(),
                    "shutdown dispatch custody is uncertain; inspect durable history before retry",
                    false,
                );
            }
            self.shared
                .shutdown_requested
                .store(true, Ordering::Release);
            self.shared.delta_notify.notify_all();
            if let Err(error) = self
                .shared
                .record_control_progress(&command.operation_id, ControlProgress::SubsystemReturned)
            {
                return make_refused(
                    ctx.request_id,
                    error.error_id(),
                    "shutdown requested, but its durable return boundary is uncertain",
                    false,
                );
            }
            return IpcResponse::ControlAccepted {
                request_id: ctx.request_id,
                operation_id: command.operation_id,
                state: ControlOperationState::Accepted,
            };
        }
        if idempotency_key.is_none() && self.shared.is_shutdown_requested() {
            return make_refused(
                ctx.request_id,
                ERR_IPC_SERVER_SHUTDOWN_001,
                "daemon is draining for shutdown",
                true,
            );
        }
        if op.requires_camera_id() && target_camera_id.is_none() {
            return make_refused(
                ctx.request_id,
                ERR_IPC_WIRE_CORRUPT_001,
                "bounded camera control requires a target camera",
                false,
            );
        }
        if matches!(
            op,
            BoundedControlOp::ReloadManifest | BoundedControlOp::TriggerScrub
        ) && target_camera_id.is_some()
        {
            return make_refused(
                ctx.request_id,
                ERR_IPC_WIRE_CORRUPT_001,
                "deployment-wide control does not accept a target camera",
                false,
            );
        }
        if op == BoundedControlOp::ReloadManifest && idempotency_key.is_none() {
            return make_refused(
                ctx.request_id,
                ERR_DAEMON_CONTROL_APPROVAL_001,
                "manifest reload requires an exact live preview approval and durable retry key",
                false,
            );
        }
        if op != BoundedControlOp::ReloadManifest
            && approval_digest
                != control_op_approval_digest(&self.shared.deployment_id, op, target_camera_id)
        {
            return make_refused(
                ctx.request_id,
                ERR_DAEMON_CONTROL_APPROVAL_001,
                "control approval digest does not match the exact deployment, operation and target",
                false,
            );
        }
        if idempotency_key.is_none()
            && let Some(cam_id) = target_camera_id
            && !self.shared.known_cameras.iter().any(|c| c == cam_id)
        {
            return make_refused(
                ctx.request_id,
                ERR_DAEMON_UNKNOWN_CAMERA_001,
                &format!("unknown target camera `{cam_id}`"),
                false,
            );
        }
        let Ok(mut queue) = self.shared.control_queue.lock() else {
            return make_refused(
                ctx.request_id,
                crate::error::ERR_DAEMON_SHUTDOWN_001,
                "control queue is unavailable; no command was admitted",
                false,
            );
        };
        // Cancellation and shutdown can arrive while waiting for queue admission.
        if ctx.is_cancelled() {
            return IpcResponse::Cancelled {
                request_id: ctx.request_id,
            };
        }
        // Resolve retained keys before current admission limits. A retry is inspection,
        // including during shutdown or after its camera leaves the current manifest.
        if let Some(response) =
            self.shared
                .replay_control(ctx, op, target_camera_id, approval_digest, idempotency_key)
        {
            return response;
        }
        if self.shared.is_shutdown_requested() {
            return make_refused(
                ctx.request_id,
                ERR_IPC_SERVER_SHUTDOWN_001,
                "daemon is draining for shutdown",
                true,
            );
        }
        if let Some(cam_id) = target_camera_id
            && !self.shared.known_cameras.iter().any(|c| c == cam_id)
        {
            return make_refused(
                ctx.request_id,
                ERR_DAEMON_UNKNOWN_CAMERA_001,
                &format!("unknown target camera `{cam_id}`"),
                false,
            );
        }
        if queue.len() >= MAX_QUEUED_CONTROL_COMMANDS {
            return make_refused(
                ctx.request_id,
                "ERR-BUDGET-EXHAUSTED-001",
                "bounded control queue is full; wait for the supervisor to drain and retry",
                true,
            );
        }
        if op == BoundedControlOp::ReloadManifest {
            // File I/O is bounded but must not hold the admission mutex. Resolve the
            // retained key first so exact retries remain inspectable after source drift.
            drop(queue);
            let preview = match self.shared.read_manifest_reload_preview(ctx) {
                Ok(preview) => preview,
                Err(response) => return response,
            };
            queue = match self.shared.control_queue.lock() {
                Ok(queue) => queue,
                Err(_) => {
                    return make_refused(
                        ctx.request_id,
                        crate::error::ERR_DAEMON_SHUTDOWN_001,
                        "control queue is unavailable; no command was admitted",
                        false,
                    );
                }
            };
            if ctx.is_cancelled() {
                return IpcResponse::Cancelled {
                    request_id: ctx.request_id,
                };
            }
            // Another request may have claimed the same key while the file was read.
            if let Some(response) = self.shared.replay_control(
                ctx,
                op,
                target_camera_id,
                approval_digest,
                idempotency_key,
            ) {
                return response;
            }
            if self.shared.is_shutdown_requested() {
                return make_refused(
                    ctx.request_id,
                    ERR_IPC_SERVER_SHUTDOWN_001,
                    "daemon is draining for shutdown",
                    true,
                );
            }
            let active_unchanged = match self.shared.manifest_reload_preview_is_current(&preview) {
                Ok(unchanged) => unchanged,
                Err(error) => {
                    return make_refused(
                        ctx.request_id,
                        error.error_id(),
                        "manifest reload source is unavailable",
                        false,
                    );
                }
            };
            if !active_unchanged || approval_digest != preview.approval_digest {
                return make_refused(
                    ctx.request_id,
                    ERR_DAEMON_CONTROL_APPROVAL_001,
                    "manifest reload approval does not bind the current active and candidate generations; preview again",
                    false,
                );
            }
            if queue.len() >= MAX_QUEUED_CONTROL_COMMANDS {
                return make_refused(
                    ctx.request_id,
                    "ERR-BUDGET-EXHAUSTED-001",
                    "bounded control queue is full; wait for the supervisor to drain and retry",
                    true,
                );
            }
        }
        let command = match self.shared.retain_control(
            ctx,
            op,
            target_camera_id,
            approval_digest,
            idempotency_key,
        ) {
            Ok(command) => command,
            Err(error) => {
                return make_refused(
                    ctx.request_id,
                    error.error_id(),
                    "control intake was not acknowledged; inspect durable history before retry",
                    false,
                );
            }
        };
        // Cancellation may arrive during journal I/O. Retain its disposition before any
        // queue publication, rather than losing the request or dispatching cancelled work.
        if ctx.is_cancelled() || self.shared.is_shutdown_requested() {
            if let Err(error) = self.shared.record_control_progress(
                &command.operation_id,
                ControlProgress::CancelledBeforeExecution,
            ) {
                return make_refused(
                    ctx.request_id,
                    error.error_id(),
                    "control cancellation custody is uncertain; inspect durable history before retry",
                    false,
                );
            }
            return if ctx.is_cancelled() {
                IpcResponse::Cancelled {
                    request_id: ctx.request_id,
                }
            } else {
                make_refused(
                    ctx.request_id,
                    ERR_IPC_SERVER_SHUTDOWN_001,
                    "daemon closed admission while retaining the request; control cancelled before execution",
                    true,
                )
            };
        }
        let operation_id = command.operation_id.clone();
        queue.push_back(command);
        IpcResponse::ControlAccepted {
            request_id: ctx.request_id,
            operation_id,
            state: ControlOperationState::Queued,
        }
    }
}

/// Running local UDS IPC server owned by `ControlPlaneRegion`.
pub struct ControlPlaneServer {
    ipc_root: PathBuf,
    daemon_instance_id: String,
    descriptor: DaemonRuntimeDescriptor,
    shared: Arc<ControlPlaneShared>,
    server: Option<IpcServer>,
}

impl ControlPlaneServer {
    /// Binds `<ipc_root>/run/daemon.sock` (`0600`), writes `daemon.meta.json` (`0600`), and
    /// returns the owning [`ControlPlaneServer`].
    pub fn start(
        ipc_root: PathBuf,
        site_id: String,
        daemon_instance_id: String,
        manifest_digest: ContentDigest,
        started_at_ns: i128,
        shared: Arc<ControlPlaneShared>,
    ) -> Result<Self, DaemonError> {
        let basis_digest = reference_contract_basis().basis_digest();
        let config = IpcServerConfig::new(&ipc_root, &site_id, basis_digest, &daemon_instance_id);
        let handler = Arc::new(DaemonIpcHandlerAdapter {
            shared: Arc::clone(&shared),
        });
        let server = IpcServer::bind(config, handler)?;
        let socket_path = server.socket_path().to_path_buf();
        let descriptor = DaemonRuntimeDescriptor {
            site_id,
            daemon_instance_id: daemon_instance_id.clone(),
            pid: std::process::id(),
            manifest_digest,
            contract_basis_digest: basis_digest,
            socket_path,
            started_at_ns,
        };
        let _ = descriptor.write_atomic(&ipc_root)?;
        Ok(Self {
            ipc_root,
            daemon_instance_id,
            descriptor,
            shared,
            server: Some(server),
        })
    }

    /// Returns the bound Unix domain socket path.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.descriptor.socket_path
    }

    /// Returns the non-secret runtime descriptor written to `<ipc_root>/run/daemon.meta.json`.
    #[must_use]
    pub const fn descriptor(&self) -> &DaemonRuntimeDescriptor {
        &self.descriptor
    }

    /// Borrows the shared lock-free control-plane state.
    #[must_use]
    pub fn shared(&self) -> &Arc<ControlPlaneShared> {
        &self.shared
    }

    /// Cooperatively stops the IPC server, wakes all subscribers, joins all connection threads,
    /// and unlinks the owned socket and runtime descriptor.
    pub fn shutdown(mut self) -> Result<(), DaemonError> {
        self.shared.request_shutdown();
        if let Some(server) = self.server.take() {
            server.shutdown()?;
        }
        DaemonRuntimeDescriptor::remove_if_owned(&self.ipc_root, &self.daemon_instance_id);
        Ok(())
    }
}

impl Drop for ControlPlaneServer {
    fn drop(&mut self) {
        self.shared.request_shutdown();
        if let Some(server) = self.server.take() {
            let _ = server.shutdown();
        }
        DaemonRuntimeDescriptor::remove_if_owned(&self.ipc_root, &self.daemon_instance_id);
    }
}

fn make_refused(request_id: u64, error_id_str: &str, reason: &str, retryable: bool) -> IpcResponse {
    let error_id = parse_error_id(error_id_str)
        .or_else(|_| ErrorId::parse(ERR_IPC_WIRE_CORRUPT_001))
        .unwrap_or_else(|_| fallback_error_id());
    IpcResponse::Refused {
        request_id,
        error_id,
        reason: reason.to_owned(),
        retryable,
    }
}

fn fallback_error_id() -> ErrorId {
    loop {
        if let Ok(id) = ErrorId::parse("ERR-DAEMON-IPC-001") {
            return id;
        }
    }
}
