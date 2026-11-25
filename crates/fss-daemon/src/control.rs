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
    ActiveScrubStatus, BoundedControlOp, CameraLiveStatus, ControlOperationState, DaemonIpcHandler,
    DeltaEventSummary, DeltaStreamSink, ERR_IPC_SERVER_SHUTDOWN_001, ERR_IPC_WIRE_CORRUPT_001,
    IpcResponse, IpcServer, IpcServerConfig, LiveDaemonStatus, RequestContext, RingWatermarkStatus,
    StreamEndReason, parse_error_id,
};

pub use crate::control_client::{
    DaemonRuntimeDescriptor, query_live_daemon_status, request_live_daemon_stop,
};
use crate::error::{DaemonError, ERR_DAEMON_CONTROL_APPROVAL_001, ERR_DAEMON_UNKNOWN_CAMERA_001};

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

const MAX_DELTA_BUS_EVENTS: usize = 4_096;
const MAX_IDEMPOTENCY_ENTRIES: usize = 1_024;
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

#[derive(Clone, Debug)]
struct BufferedDeltaEvent {
    bus_seq: u64,
    commit_sequence: u64,
    delta_digest: ContentDigest,
    summary_canonical: Vec<u8>,
}

/// Shared zero-contention control-plane state bridging `IpcServer` workers and `DaemonSupervisor`.
pub struct ControlPlaneShared {
    started_at: Instant,
    deployment_id: String,
    deployment_root_digest: ContentDigest,
    known_cameras: Vec<String>,
    head_commit_sequence: AtomicU64,
    next_bus_seq: AtomicU64,
    next_op_seq: AtomicU64,
    shutdown_requested: AtomicBool,
    status_snapshot: RwLock<ControlStatusSnapshot>,
    delta_log: Mutex<VecDeque<BufferedDeltaEvent>>,
    delta_notify: Condvar,
    control_queue: Mutex<VecDeque<PendingControlCommand>>,
    idempotency_cache: Mutex<BTreeMap<ContentDigest, (u64, ContentDigest, ContentDigest)>>,
    forward_writer: Arc<dyn ForwardBatchWriter>,
}

impl ControlPlaneShared {
    /// Constructs shared control-plane state for `deployment_id`.
    #[must_use]
    pub fn new(
        deployment_id: impl Into<String>,
        deployment_root_digest: ContentDigest,
        known_cameras: Vec<String>,
        initial_status: ControlStatusSnapshot,
        forward_writer: Arc<dyn ForwardBatchWriter>,
    ) -> Arc<Self> {
        let initial_seq = initial_status.head_commit_sequence;
        Arc::new(Self {
            started_at: Instant::now(),
            deployment_id: deployment_id.into(),
            deployment_root_digest,
            known_cameras,
            head_commit_sequence: AtomicU64::new(initial_seq),
            next_bus_seq: AtomicU64::new(1),
            next_op_seq: AtomicU64::new(1),
            shutdown_requested: AtomicBool::new(false),
            status_snapshot: RwLock::new(initial_status),
            delta_log: Mutex::new(VecDeque::with_capacity(256)),
            delta_notify: Condvar::new(),
            control_queue: Mutex::new(VecDeque::new()),
            idempotency_cache: Mutex::new(BTreeMap::new()),
            forward_writer,
        })
    }

    /// Publishes an updated live status snapshot for O(1) IPC reads.
    pub fn publish_status(&self, snapshot: ControlStatusSnapshot) {
        self.head_commit_sequence
            .store(snapshot.head_commit_sequence, Ordering::Release);
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
        self.head_commit_sequence
            .fetch_max(commit_sequence, Ordering::AcqRel);
        if let Ok(mut log) = self.delta_log.lock() {
            if log.len() >= MAX_DELTA_BUS_EVENTS {
                log.pop_front();
            }
            let bus_seq = self.next_bus_seq.fetch_add(1, Ordering::AcqRel);
            log.push_back(BufferedDeltaEvent {
                bus_seq,
                commit_sequence,
                delta_digest,
                summary_canonical,
            });
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

    /// Drains all queued bounded control commands for execution on the supervisor loop.
    #[must_use]
    pub fn drain_control_commands(&self) -> Vec<PendingControlCommand> {
        match self.control_queue.lock() {
            Ok(mut guard) => guard.drain(..).collect(),
            Err(_) => Vec::new(),
        }
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
        _approval_digest: Option<ContentDigest>,
    ) -> IpcResponse {
        if self.shared.is_shutdown_requested() {
            return make_refused(
                ctx.request_id,
                ERR_IPC_SERVER_SHUTDOWN_001,
                "daemon is draining for shutdown",
                true,
            );
        }
        if let Ok(cache) = self.shared.idempotency_cache.lock()
            && let Some(&(commit_sequence, history_root, state_root)) = cache.get(&idempotency_key)
        {
            return IpcResponse::DeltaBatchCommitted {
                request_id: ctx.request_id,
                commit_sequence,
                history_root,
                state_root,
            };
        }
        match self.shared.forward_writer.forward_delta_batch(batch_bytes) {
            Ok((commit_sequence, history_root, state_root)) => {
                if let Ok(mut cache) = self.shared.idempotency_cache.lock() {
                    if cache.len() >= MAX_IDEMPOTENCY_ENTRIES
                        && let Some(first_key) = cache.keys().next().copied()
                    {
                        cache.remove(&first_key);
                    }
                    cache.insert(idempotency_key, (commit_sequence, history_root, state_root));
                }
                self.shared.publish_delta_summary(
                    commit_sequence,
                    ContentDigest::sha256(batch_bytes),
                    MeaningfulDeltaClass::MaterialState,
                    DeltaPriority::Normal,
                    format!("forwarded_batch seq={commit_sequence}"),
                );
                IpcResponse::DeltaBatchCommitted {
                    request_id: ctx.request_id,
                    commit_sequence,
                    history_root,
                    state_root,
                }
            }
            Err(err) => make_refused(
                ctx.request_id,
                err.error_id(),
                &err.to_string(),
                matches!(err, DaemonError::StorageQuotaPinned { .. }),
            ),
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
        let head = self.shared.head_commit_sequence.load(Ordering::Acquire);
        if since_commit_seq > head {
            return StreamEndReason::CursorStale;
        }
        if max_batch == 0 {
            return StreamEndReason::BatchLimitReached;
        }

        let mut bus_cursor: u64 = match self.shared.delta_log.lock() {
            Ok(guard) => {
                // Replay any already-buffered event strictly newer than `since_commit_seq`;
                // otherwise start strictly after the latest already-seen bus sequence so live
                // control-op deltas emitted at the current commit sequence are never dropped.
                if let Some(first_new) = guard
                    .iter()
                    .find(|ev| ev.commit_sequence > since_commit_seq)
                {
                    first_new.bus_seq.saturating_sub(1)
                } else {
                    guard.back().map_or(0, |ev| ev.bus_seq)
                }
            }
            Err(_) => return StreamEndReason::DaemonShuttingDown,
        };
        let deadline = Instant::now() + SUBSCRIBE_IDLE_WINDOW;
        loop {
            if ctx.is_cancelled() {
                return StreamEndReason::Cancelled;
            }
            if self.shared.is_shutdown_requested() {
                return StreamEndReason::DaemonShuttingDown;
            }
            let pending: Vec<BufferedDeltaEvent> = match self.shared.delta_log.lock() {
                Ok(guard) => guard
                    .iter()
                    .filter(|ev| ev.bus_seq > bus_cursor)
                    .cloned()
                    .collect(),
                Err(_) => return StreamEndReason::DaemonShuttingDown,
            };
            for ev in pending {
                if sink.emitted() >= max_batch {
                    return StreamEndReason::BatchLimitReached;
                }
                if sink
                    .emit_delta(ev.commit_sequence, ev.delta_digest, ev.summary_canonical)
                    .is_err()
                {
                    return StreamEndReason::Cancelled;
                }
                bus_cursor = ev.bus_seq;
                if sink.emitted() >= max_batch {
                    return StreamEndReason::BatchLimitReached;
                }
            }
            if Instant::now() >= deadline {
                return StreamEndReason::Completed;
            }
            let Ok(guard) = self.shared.delta_log.lock() else {
                return StreamEndReason::DaemonShuttingDown;
            };
            if guard.back().is_some_and(|ev| ev.bus_seq > bus_cursor) {
                continue;
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
            self.shared.request_shutdown();
            return IpcResponse::ControlAccepted {
                request_id: ctx.request_id,
                operation_id: self.shared.alloc_operation_id(op),
                state: ControlOperationState::Accepted,
            };
        }
        if self.shared.is_shutdown_requested() {
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
        if approval_digest
            != control_op_approval_digest(&self.shared.deployment_id, op, target_camera_id)
        {
            return make_refused(
                ctx.request_id,
                ERR_DAEMON_CONTROL_APPROVAL_001,
                "control approval digest does not match the exact deployment, operation and target",
                false,
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
        if self.shared.is_shutdown_requested() {
            return make_refused(
                ctx.request_id,
                ERR_IPC_SERVER_SHUTDOWN_001,
                "daemon is draining for shutdown",
                true,
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
        let operation_id = self.shared.alloc_operation_id(op);
        queue.push_back(PendingControlCommand {
            operation_id: operation_id.clone(),
            op,
            target_camera_id: target_camera_id.map(str::to_owned),
            approval_digest,
        });
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
