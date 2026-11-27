#![forbid(unsafe_code)]
//! Canonical owner-authenticated local Unix-domain-socket IPC protocol and write-forwarding channel.
//!
//! `fss-ipc` provides the deterministic, serde-free local control and write-forwarding plane
//! between local FSS tools/agents and the owning site supervisor daemon:
//! - Owner-only filesystem boundary (`<deployment>/run` at `0700`, `daemon.sock` at `0600`)
//!   refusing symlinks, non-sockets, and group/world permissions.
//! - Bounded stale-socket detection and safe recovery on daemon bind.
//! - Length-framed binary wire format (`FSSI`) with pre-allocation request (`64 KiB`) and
//!   response (`4 MiB`) caps and RFC 3720 CRC32C checksums.
//! - Mutually pinned handshake binding protocol version, deployment identity/root digest,
//!   `ContractBasis` digest, `PrincipalId`, and opaque capability IDs (never raw secrets).
//! - Narrow typed operations (`SubmitDeltaBatch`, `QueryLiveStatus`, `SubscribeDeltas`,
//!   `SubmitBoundedControl`, `CancelRequest`) with cooperative cancellation and zero orphan threads.
//! - Automatic offline direct read-only fallback (`DeploymentClient::connect_or_direct`) with
//!   explicit `ERR-DAEMON-OFFLINE-001` refusal guidance for live-only mutations.

/// Cooperative request cancellation tokens backed by atomics and detached Asupersync `Cx`.
pub mod cancel;
/// Owner-authenticated client and delta subscription iterator.
pub mod client;
/// Bounded control operations, stream end reasons, and canonical delta summaries.
pub mod control;
/// Live daemon discovery and offline direct fallback router.
pub mod deployment;
/// Typed IPC errors and stable `ERR-...-NNN` identifiers.
pub mod error;
/// Mutually pinned handshake request and response messages.
pub mod handshake;
/// Canonical serde-free request, control, and response messages.
pub mod protocol;
/// Owner-only runtime directory/socket security validation and stale-socket recovery.
pub mod security;
/// Bounded concurrent local UDS server with cooperative shutdown and drain.
pub mod server;
mod server_conn;
/// Live daemon telemetry status types.
pub mod status;
/// Deterministic serde-free JSONL operation tracing.
pub mod trace;
/// Length-framed binary wire transport with pre-allocation bounds and checksums.
pub mod transport;

pub use cancel::{CancelReason, RequestCancelToken};
pub use client::{DeltaSubscription, DeltaSubscriptionItem, IpcClient, IpcClientConfig};
pub use deployment::{DeploymentChannel, DeploymentClient};
pub use error::{
    ERR_DAEMON_OFFLINE_001, ERR_IPC_CANCELLED_001, ERR_IPC_CAPABILITY_DENIED_001,
    ERR_IPC_CONNECTION_LIMIT_001, ERR_IPC_DAEMON_RUNNING_001, ERR_IPC_FRAME_TOO_LARGE_001,
    ERR_IPC_HANDSHAKE_MISMATCH_001, ERR_IPC_SECURITY_VIOLATION_001, ERR_IPC_SERVER_SHUTDOWN_001,
    ERR_IPC_TIMEOUT_001, ERR_IPC_WIRE_CORRUPT_001, IPC_ERROR_IDS, IpcError, daemon_start_guidance,
    parse_error_id,
};
pub use handshake::{
    HandshakeAccepted, HandshakeRejected, HandshakeRequest, HandshakeResponse,
    IPC_HANDSHAKE_DIGEST_DOMAIN, MAX_DEPLOYMENT_ID_BYTES, MAX_REASON_BYTES,
};
pub use protocol::{
    BoundedControlOp, ControlOperationState, DeltaEventSummary, IPC_DELTA_SUMMARY_DIGEST_DOMAIN,
    IPC_REQUEST_DIGEST_DOMAIN, IPC_RESPONSE_DIGEST_DOMAIN, IpcRequest, IpcResponse,
    RetainedControlProgress, StreamEndReason,
};
pub use security::{
    DAEMON_SOCKET_NAME, FORBIDDEN_GROUP_WORLD_MASK, IPC_DEPLOYMENT_ROOT_DIGEST_DOMAIN,
    MAX_CAPABILITY_ID_LEN, MAX_HANDSHAKE_CAPABILITIES, OWNER_ONLY_DIR_MODE, OWNER_ONLY_SOCKET_MODE,
    RUN_DIR_NAME, SocketInode, SocketProbeState, default_run_dir, default_socket_path,
    deployment_root_digest, validate_capabilities, validate_capability_id,
};
pub use server::{DaemonIpcHandler, DeltaStreamSink, IpcServer, IpcServerConfig, RequestContext};
pub use status::{
    ActiveScrubStatus, CameraLiveStatus, CameraRetentionForecast, LiveDaemonStatus,
    MAX_CAMERA_ID_BYTES, MAX_CAMERAS_IN_STATUS, OldestRetentionWindow, RingWatermarkStatus,
};
pub use trace::{IpcTraceEvent, format_trace_jsonl};
pub use transport::{
    FrameFlags, IPC_FRAME_MAGIC, IPC_FRAME_OVERHEAD_BYTES, IPC_HEADER_BYTES, IPC_PROTOCOL_VERSION,
    IPC_TRAILER_BYTES, MAX_REQUEST_FRAME_BYTES, MAX_REQUEST_PAYLOAD_BYTES,
    MAX_RESPONSE_FRAME_BYTES, MAX_RESPONSE_PAYLOAD_BYTES, PollFrame, WireFrame,
    compute_frame_checksum, crc32c, decode_frame_from_slice, encode_frame_header,
    encode_frame_to_vec, poll_read_frame, read_frame, write_frame,
};
