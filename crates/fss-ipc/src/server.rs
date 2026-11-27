#![forbid(unsafe_code)]
//! Bounded, owner-authenticated local Unix-domain-socket IPC server with cooperative shutdown.
//!
//! Every accepted connection and companion request executor is owned by [`IpcServer`]; shutdown
//! and drop cancel all active request tokens, drain in-flight workers, join every OS thread,
//! and unlink the socket only if its `(dev, ino)` still matches the bound socket.

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fss_core::{CanonicalEncode, ContentDigest, ErrorId, PrincipalId, RegionId};
use fss_runtime::asupersync_ops::{
    MAX_SCOPED_GROUP_THREADS, ScopedWorkerGroup, ScopedWorkerSpawner, WorkerCancelToken,
    WorkerGroupBounds,
};

use crate::cancel::CancelRegistry;
pub use crate::cancel::{CancelReason, RequestCancelToken};
use crate::error::IpcError;
use crate::protocol::{BoundedControlOp, HandshakeRequest, IpcResponse, StreamEndReason};
use crate::security::{
    SocketInode, default_run_dir, default_socket_path, deployment_root_digest, harden_bound_socket,
    prepare_socket_for_bind, remove_owned_socket,
};
use crate::server_conn::{handle_connection, reject_connection_limit};
use crate::transport::{FrameFlags, MAX_RESPONSE_FRAME_BYTES, write_frame};

const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(2);

/// Authenticated execution context supplied to [`DaemonIpcHandler`] callbacks.
#[derive(Clone)]
pub struct RequestContext {
    /// Server-assigned connection identifier.
    pub connection_id: u64,
    /// Client-assigned correlation identifier for this request.
    pub request_id: u64,
    /// Verified deployment identifier.
    pub deployment_id: String,
    /// Verified canonical `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Authenticated local principal.
    pub principal: PrincipalId,
    /// Granted opaque capabilities for this session.
    pub granted_capabilities: Vec<String>,
    /// Cooperative cancellation token for this in-flight request.
    pub cancel: RequestCancelToken,
}

impl RequestContext {
    /// Returns true if the request has been cooperatively cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }
}

/// Bounded streaming sink handed to [`DaemonIpcHandler::subscribe_deltas`].
pub struct DeltaStreamSink<'a> {
    request_id: u64,
    writer: &'a Mutex<UnixStream>,
    cancel: &'a RequestCancelToken,
    emitted: u32,
    max_batch: u32,
}

impl<'a> DeltaStreamSink<'a> {
    pub(crate) const fn new(
        request_id: u64,
        writer: &'a Mutex<UnixStream>,
        cancel: &'a RequestCancelToken,
        max_batch: u32,
    ) -> Self {
        Self {
            request_id,
            writer,
            cancel,
            emitted: 0,
            max_batch,
        }
    }

    /// Emits one `IpcResponse::DeltaEvent` frame to the subscribed client.
    ///
    /// Fails closed immediately if the request was cancelled, `max_batch` is exhausted,
    /// or the client disconnected.
    pub fn emit_delta(
        &mut self,
        commit_sequence: u64,
        delta_digest: ContentDigest,
        summary_canonical: Vec<u8>,
    ) -> Result<(), IpcError> {
        if self.cancel.is_cancelled() || self.emitted >= self.max_batch {
            return Err(IpcError::Cancelled {
                request_id: self.request_id,
            });
        }
        let response = IpcResponse::DeltaEvent {
            request_id: self.request_id,
            commit_sequence,
            delta_digest,
            summary_canonical,
        };
        let payload = response.try_canonical_bytes()?;
        let mut guard = self.writer.lock().map_err(|_| IpcError::ConnectionClosed)?;
        if let Err(err) = write_frame(
            &mut *guard,
            FrameFlags::RESPONSE.union(FrameFlags::STREAM),
            &payload,
            MAX_RESPONSE_FRAME_BYTES,
        ) {
            if matches!(err, IpcError::ConnectionClosed) {
                self.cancel.cancel(CancelReason::PeerDisconnected);
            }
            return Err(err);
        }
        self.emitted = self.emitted.saturating_add(1);
        Ok(())
    }

    /// Number of delta events emitted so far in this subscription.
    #[must_use]
    pub const fn emitted(&self) -> u32 {
        self.emitted
    }
}

/// Service trait implemented by the local supervisor daemon to handle authenticated IPC requests.
pub trait DaemonIpcHandler: Send + Sync + 'static {
    /// Authorizes requested opaque capabilities and returns the granted subset.
    fn authorize_handshake(
        &self,
        request: &HandshakeRequest,
    ) -> Result<Vec<String>, (ErrorId, String)> {
        Ok(request.capabilities.clone())
    }

    /// Returns the current ledger head commit sequence advertised in `HandshakeAccepted`.
    fn head_commit_sequence(&self) -> u64 {
        0
    }

    /// Commits a forwarded canonical `EvidenceDeltaBatch` to the single-writer ledger.
    fn submit_delta_batch(
        &self,
        ctx: &RequestContext,
        idempotency_key: ContentDigest,
        batch_bytes: &[u8],
        approval_digest: Option<ContentDigest>,
    ) -> IpcResponse;

    /// Returns a live telemetry snapshot of cameras, retention ring, scrub state, and ledger head.
    fn query_live_status(
        &self,
        ctx: &RequestContext,
        include_cameras: bool,
        include_ring: bool,
    ) -> IpcResponse;

    /// Looks up one camera's forecast or returns a typed refusal for unsupported handlers.
    fn query_retention_forecast(&self, ctx: &RequestContext, _camera_id: &str) -> IpcResponse {
        crate::server_conn::make_refused(
            ctx.request_id,
            crate::error::ERR_IPC_CAPABILITY_DENIED_001,
            "retention forecast unavailable",
            false,
        )
    }

    /// Reads a configured manifest candidate without admitting a reload.
    /// Older handlers fail closed rather than issuing an unbound approval.
    fn preview_manifest_reload(&self, ctx: &RequestContext) -> IpcResponse {
        crate::server_conn::make_refused(
            ctx.request_id,
            crate::error::ERR_IPC_CAPABILITY_DENIED_001,
            "manifest reload preview unavailable",
            false,
        )
    }

    /// Streams committed deltas after `since_commit_seq` (up to `max_batch`) and returns end reason.
    fn subscribe_deltas(
        &self,
        ctx: &RequestContext,
        since_commit_seq: u64,
        max_batch: u32,
        sink: &mut DeltaStreamSink<'_>,
    ) -> StreamEndReason;

    /// Admits one closed-enum bounded supervisor control operation.
    fn submit_bounded_control(
        &self,
        ctx: &RequestContext,
        op: BoundedControlOp,
        target_camera_id: Option<&str>,
        approval_digest: ContentDigest,
    ) -> IpcResponse;

    /// Admits or replays a durably keyed control. The default never falls back to
    /// unkeyed dispatch, since that would discard the caller's retry guarantee.
    fn submit_idempotent_control(
        &self,
        ctx: &RequestContext,
        _idempotency_key: ContentDigest,
        _op: BoundedControlOp,
        _target_camera_id: Option<&str>,
        _approval_digest: ContentDigest,
    ) -> IpcResponse {
        crate::server_conn::make_refused(
            ctx.request_id,
            crate::error::ERR_IPC_CAPABILITY_DENIED_001,
            "durable idempotent control is unavailable",
            false,
        )
    }
}

/// Configuration for binding an owner-authenticated [`IpcServer`].
#[derive(Clone, Debug)]
pub struct IpcServerConfig {
    /// Deployment root directory (`<deployment>`).
    pub deployment_root: PathBuf,
    /// Stable deployment identifier pinned during handshake.
    pub deployment_id: String,
    /// Canonical `ContractBasis::basis_digest()` pinned during handshake.
    pub contract_basis_digest: ContentDigest,
    /// Stable daemon instance identifier returned in `HandshakeAccepted`.
    pub daemon_instance_id: String,
    /// Hard maximum simultaneous client connections (default `64`).
    pub max_connections: usize,
    /// Timeout for completing the initial handshake (default `5s`).
    pub handshake_timeout: Duration,
    /// Timeout for individual frame reads and writes (default `10s`).
    pub io_timeout: Duration,
    /// Idle connection timeout when no request is in flight (default `30s`).
    pub idle_timeout: Duration,
    /// Bounded connect-probe timeout for stale-socket detection (default `250ms`).
    pub probe_timeout: Duration,
}

impl IpcServerConfig {
    /// Constructs a server configuration with safe production defaults.
    #[must_use]
    pub fn new(
        deployment_root: impl Into<PathBuf>,
        deployment_id: impl Into<String>,
        contract_basis_digest: ContentDigest,
        daemon_instance_id: impl Into<String>,
    ) -> Self {
        Self {
            deployment_root: deployment_root.into(),
            deployment_id: deployment_id.into(),
            contract_basis_digest,
            daemon_instance_id: daemon_instance_id.into(),
            max_connections: 64,
            handshake_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
            probe_timeout: Duration::from_millis(250),
        }
    }
}

pub(crate) struct SharedServerState {
    pub(crate) config: IpcServerConfig,
    pub(crate) deployment_root_digest: ContentDigest,
    pub(crate) handler: Arc<dyn DaemonIpcHandler>,
    pub(crate) shutdown: AtomicBool,
    pub(crate) active_connections: AtomicUsize,
    pub(crate) next_connection_id: AtomicU64,
    pub(crate) cancel_registry: CancelRegistry,
}

/// Owner-authenticated Unix-domain-socket IPC server with cooperative shutdown and drain.
pub struct IpcServer {
    socket_path: PathBuf,
    socket_inode: SocketInode,
    shared: Arc<SharedServerState>,
    worker_group: Option<ScopedWorkerGroup>,
}

impl IpcServer {
    /// Validates runtime directory security, recovers stale sockets, binds `daemon.sock` (`0600`),
    /// and starts the owned accept loop inside a region-owned Asupersync [`ScopedWorkerGroup`].
    pub fn bind(
        config: IpcServerConfig,
        handler: Arc<dyn DaemonIpcHandler>,
    ) -> Result<Self, IpcError> {
        if config.max_connections == 0 {
            return Err(IpcError::InvalidFrame {
                reason: "max_connections must be at least 1".to_owned(),
            });
        }
        if config.deployment_id.is_empty() || config.daemon_instance_id.is_empty() {
            return Err(IpcError::HandshakeMismatch {
                reason: "deployment_id and daemon_instance_id must be non-empty".to_owned(),
            });
        }
        let run_dir = default_run_dir(&config.deployment_root);
        let socket_path = default_socket_path(&config.deployment_root);
        let owner_uid = prepare_socket_for_bind(&run_dir, &socket_path, config.probe_timeout)?;

        let listener = UnixListener::bind(&socket_path)
            .map_err(|err| IpcError::io("bind_unix_socket", err))?;
        let socket_inode = match harden_bound_socket(&socket_path, owner_uid) {
            Ok(inode) => inode,
            Err(err) => {
                drop(listener);
                let _ = std::fs::remove_file(&socket_path);
                return Err(err);
            }
        };
        listener
            .set_nonblocking(true)
            .map_err(|err| IpcError::io("set_listener_nonblocking", err))?;

        let max_workers = config
            .max_connections
            .saturating_add(1)
            .clamp(2, MAX_SCOPED_GROUP_THREADS);
        let min_threads = max_workers.min(18);
        let region_id = RegionId::new("region:control_plane:ipc_server").map_err(|err| {
            IpcError::InvalidFrame {
                reason: format!("invalid IPC worker region id: {err}"),
            }
        })?;
        let bounds = WorkerGroupBounds::new(
            region_id,
            "fss-ipc",
            min_threads,
            max_workers,
            max_workers,
            Duration::from_secs(5),
        )
        .map_err(|err| {
            IpcError::io(
                "configure_ipc_worker_group",
                io::Error::other(err.to_string()),
            )
        })?;
        let worker_group = match ScopedWorkerGroup::new(bounds) {
            Ok(group) => group,
            Err(err) => {
                drop(listener);
                remove_owned_socket(&socket_path, socket_inode);
                return Err(IpcError::io(
                    "init_ipc_worker_group",
                    io::Error::other(err.to_string()),
                ));
            }
        };

        let root_digest = deployment_root_digest(&config.deployment_root);
        let shared = Arc::new(SharedServerState {
            config,
            deployment_root_digest: root_digest,
            handler,
            shutdown: AtomicBool::new(false),
            active_connections: AtomicUsize::new(0),
            next_connection_id: AtomicU64::new(1),
            cancel_registry: CancelRegistry::default(),
        });

        let accept_shared = Arc::clone(&shared);
        let accept_spawner = worker_group.spawner();
        if let Err(err) = worker_group.spawn_worker(move |cancel| {
            run_accept_loop(listener, accept_shared, accept_spawner, cancel);
        }) {
            let _ = worker_group.drain_and_shutdown();
            remove_owned_socket(&socket_path, socket_inode);
            return Err(IpcError::io(
                "spawn_accept_worker",
                io::Error::other(err.to_string()),
            ));
        }

        Ok(Self {
            socket_path,
            socket_inode,
            shared,
            worker_group: Some(worker_group),
        })
    }

    /// Returns the bound Unix socket path (`<deployment>/run/daemon.sock`).
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Returns the canonical deployment root digest pinned by this server.
    #[must_use]
    pub fn deployment_root_digest(&self) -> ContentDigest {
        self.shared.deployment_root_digest
    }

    /// Returns the number of currently active authenticated connections.
    #[must_use]
    pub fn active_connections(&self) -> usize {
        self.shared.active_connections.load(Ordering::Acquire)
    }

    /// Cooperatively shuts down the server, cancels all in-flight requests, joins every owned
    /// Asupersync worker, and removes the owned socket file.
    pub fn shutdown(mut self) -> Result<(), IpcError> {
        self.shutdown_inner();
        Ok(())
    }

    fn shutdown_inner(&mut self) {
        self.shared.shutdown.store(true, Ordering::Release);
        self.shared
            .cancel_registry
            .cancel_all(CancelReason::ServerShutdown);
        if let Some(group) = self.worker_group.take() {
            let _receipt = group.drain_and_shutdown();
        }
        remove_owned_socket(&self.socket_path, self.socket_inode);
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        self.shutdown_inner();
    }
}

fn run_accept_loop(
    listener: UnixListener,
    shared: Arc<SharedServerState>,
    spawner: ScopedWorkerSpawner,
    cancel: WorkerCancelToken,
) {
    while !shared.shutdown.load(Ordering::Acquire) && !cancel.is_cancelled() {
        match listener.accept() {
            Ok((stream, _addr)) => {
                if shared.shutdown.load(Ordering::Acquire) || cancel.is_cancelled() {
                    drop(stream);
                    break;
                }
                if !try_acquire_connection_slot(&shared) {
                    reject_connection_limit(stream, shared.config.max_connections);
                    continue;
                }
                let conn_id = shared.next_connection_id.fetch_add(1, Ordering::Relaxed);
                let worker_shared = Arc::clone(&shared);
                if spawner
                    .spawn_worker(move |_worker_cancel| {
                        let _slot_guard = ConnectionSlotGuard {
                            shared: Arc::clone(&worker_shared),
                        };
                        handle_connection(conn_id, stream, &worker_shared);
                    })
                    .is_err()
                {
                    shared.active_connections.fetch_sub(1, Ordering::AcqRel);
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                if cancel
                    .sleep_cooperative(ACCEPT_POLL_INTERVAL, ACCEPT_POLL_INTERVAL)
                    .is_err()
                {
                    break;
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                if shared.shutdown.load(Ordering::Acquire) || cancel.is_cancelled() {
                    break;
                }
                if cancel
                    .sleep_cooperative(ACCEPT_POLL_INTERVAL, ACCEPT_POLL_INTERVAL)
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

struct ConnectionSlotGuard {
    shared: Arc<SharedServerState>,
}

impl Drop for ConnectionSlotGuard {
    fn drop(&mut self) {
        self.shared
            .active_connections
            .fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_connection_slot(shared: &SharedServerState) -> bool {
    let limit = shared.config.max_connections;
    let mut current = shared.active_connections.load(Ordering::Acquire);
    while current < limit {
        match shared.active_connections.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
    false
}
