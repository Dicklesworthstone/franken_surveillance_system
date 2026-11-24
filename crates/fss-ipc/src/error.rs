#![forbid(unsafe_code)]
//! Typed errors and stable error identifiers for `fss-ipc`.

use core::fmt;
use std::io;
use std::path::{Path, PathBuf};

use fss_core::{ContractError, ErrorId};

/// Local daemon socket is absent or unreachable; direct read-only fallback is available.
pub const ERR_DAEMON_OFFLINE_001: &str = "ERR-DAEMON-OFFLINE-001";

/// Protocol handshake rejected due to version, deployment, or contract-basis mismatch.
pub const ERR_IPC_HANDSHAKE_MISMATCH_001: &str = "ERR-IPC-HANDSHAKE-MISMATCH-001";

/// Declared wire frame length exceeded the hard pre-allocation limit.
pub const ERR_IPC_FRAME_TOO_LARGE_001: &str = "ERR-IPC-FRAME-TOO-LARGE-001";

/// Wire frame magic, flags, checksum, or canonical payload encoding was corrupt.
pub const ERR_IPC_WIRE_CORRUPT_001: &str = "ERR-IPC-WIRE-CORRUPT-001";

/// Local runtime directory or socket failed symlink, ownership, or permission checks.
pub const ERR_IPC_SECURITY_VIOLATION_001: &str = "ERR-IPC-SECURITY-VIOLATION-001";

/// A live daemon already owns the deployment socket path.
pub const ERR_IPC_DAEMON_RUNNING_001: &str = "ERR-IPC-DAEMON-RUNNING-001";

/// The daemon reached its bounded concurrent IPC connection limit.
pub const ERR_IPC_CONNECTION_LIMIT_001: &str = "ERR-IPC-CONNECTION-LIMIT-001";

/// An in-flight IPC request was cooperatively cancelled.
pub const ERR_IPC_CANCELLED_001: &str = "ERR-IPC-CANCELLED-001";

/// An IPC connect, read, write, or handshake operation exceeded its timeout bound.
pub const ERR_IPC_TIMEOUT_001: &str = "ERR-IPC-TIMEOUT-001";

/// A requested capability identifier was invalid, secret-bearing, or unauthorized.
pub const ERR_IPC_CAPABILITY_DENIED_001: &str = "ERR-IPC-CAPABILITY-DENIED-001";

/// The local IPC daemon is shutting down and no longer admits new requests.
pub const ERR_IPC_SERVER_SHUTDOWN_001: &str = "ERR-IPC-SERVER-SHUTDOWN-001";

/// All stable error identifiers introduced by `fss-ipc`.
pub const IPC_ERROR_IDS: &[&str] = &[
    ERR_DAEMON_OFFLINE_001,
    ERR_IPC_HANDSHAKE_MISMATCH_001,
    ERR_IPC_FRAME_TOO_LARGE_001,
    ERR_IPC_WIRE_CORRUPT_001,
    ERR_IPC_SECURITY_VIOLATION_001,
    ERR_IPC_DAEMON_RUNNING_001,
    ERR_IPC_CONNECTION_LIMIT_001,
    ERR_IPC_CANCELLED_001,
    ERR_IPC_TIMEOUT_001,
    ERR_IPC_CAPABILITY_DENIED_001,
    ERR_IPC_SERVER_SHUTDOWN_001,
];

/// Parses a validated stable error identifier into [`ErrorId`].
pub fn parse_error_id(id: &str) -> Result<ErrorId, IpcError> {
    ErrorId::parse(id).map_err(IpcError::Contract)
}

/// Formats canonical operator guidance for starting the local site supervisor daemon.
#[must_use]
pub fn daemon_start_guidance(deployment_root: &Path) -> String {
    format!(
        "Start the local supervisor with: fss site run --root {}",
        deployment_root.display()
    )
}

/// Typed failures produced by the owner-authenticated local IPC layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpcError {
    /// A live daemon already responds on the configured Unix socket.
    DaemonAlreadyRunning {
        /// Path of the active Unix socket.
        socket_path: PathBuf,
    },
    /// No live local daemon is reachable on the deployment Unix socket.
    DaemonOffline {
        /// Deployment root path.
        deployment_root: PathBuf,
        /// Expected Unix socket path.
        socket_path: PathBuf,
        /// Machine-safe offline reason.
        reason: String,
        /// Operator remediation command guidance.
        guidance: String,
    },
    /// The runtime directory or socket path is a symlink or unexpected file type.
    InsecurePath {
        /// Rejected filesystem path.
        path: PathBuf,
        /// Why the path failed security verification.
        reason: String,
    },
    /// The runtime directory or socket path has forbidden permission bits or owner mismatch.
    InsecurePermissions {
        /// Rejected filesystem path.
        path: PathBuf,
        /// Observed POSIX permission mode bits (`mode & 0o777`).
        mode: u32,
        /// Why the permissions were rejected.
        reason: String,
    },
    /// A frame exceeded the hard pre-allocation request or response ceiling.
    FrameTooLarge {
        /// Declared or encoded total frame size in bytes.
        actual: usize,
        /// Hard frame limit in bytes.
        limit: usize,
    },
    /// A wire frame violated magic, flags, framing, or structural bounds.
    InvalidFrame {
        /// Structural framing failure description.
        reason: String,
    },
    /// Frame checksum did not match the exact header and payload bytes.
    ChecksumMismatch {
        /// Checksum declared in the frame trailer.
        expected: [u8; 4],
        /// Checksum computed over the received frame bytes.
        actual: [u8; 4],
    },
    /// Peer declared an unsupported wire or handshake protocol version.
    UnsupportedProtocolVersion {
        /// Expected supported protocol version.
        expected: u16,
        /// Version advertised by the peer.
        actual: u16,
    },
    /// Handshake deployment identity, root digest, or contract basis did not match.
    HandshakeMismatch {
        /// Which pinned handshake field failed verification.
        reason: String,
    },
    /// The daemon explicitly rejected the client handshake.
    HandshakeRejected {
        /// Stable error identifier returned by the daemon.
        error_id: ErrorId,
        /// Non-secret rejection reason.
        reason: String,
        /// Protocol version expected by the daemon.
        expected_protocol_version: u16,
    },
    /// A capability string was malformed, exceeded bounds, or resembled a raw credential.
    InvalidCapability {
        /// Validation refusal description.
        reason: String,
    },
    /// A canonical `fss-core` contract or codec check failed.
    Contract(ContractError),
    /// The daemon refused an authenticated request with a typed error.
    Refused {
        /// Correlated client request identifier.
        request_id: u64,
        /// Stable error identifier.
        error_id: ErrorId,
        /// Non-secret refusal reason.
        reason: String,
        /// Whether retrying under unchanged or refreshed conditions may succeed.
        retryable: bool,
    },
    /// The request was cooperatively cancelled before completion.
    Cancelled {
        /// Cancelled request identifier.
        request_id: u64,
    },
    /// A bounded socket connect, read, write, or handshake operation timed out.
    Timeout {
        /// Static operation label.
        operation: &'static str,
    },
    /// The peer closed the Unix socket before completing the exchange.
    ConnectionClosed,
    /// The daemon refused a connection because its bounded concurrency limit was reached.
    ConnectionLimitReached {
        /// Configured maximum simultaneous connections.
        limit: usize,
    },
    /// An operating-system I/O error occurred on a socket or filesystem boundary.
    Io {
        /// Static operation label.
        operation: &'static str,
        /// Coarse I/O error category.
        kind: io::ErrorKind,
        /// Sanitized error detail.
        detail: String,
    },
}

impl IpcError {
    /// Constructs a typed [`IpcError::DaemonOffline`] with canonical start guidance.
    #[must_use]
    pub fn daemon_offline(
        deployment_root: &Path,
        socket_path: &Path,
        reason: impl Into<String>,
    ) -> Self {
        Self::DaemonOffline {
            deployment_root: deployment_root.to_path_buf(),
            socket_path: socket_path.to_path_buf(),
            reason: reason.into(),
            guidance: daemon_start_guidance(deployment_root),
        }
    }

    /// Wraps an `std::io::Error` with a static operation label.
    #[must_use]
    pub fn io(operation: &'static str, err: io::Error) -> Self {
        Self::Io {
            operation,
            kind: err.kind(),
            detail: err.to_string(),
        }
    }

    /// Returns the stable machine-readable error identifier associated with this error.
    #[must_use]
    pub fn error_id(&self) -> &str {
        match self {
            Self::DaemonAlreadyRunning { .. } => ERR_IPC_DAEMON_RUNNING_001,
            Self::DaemonOffline { .. } => ERR_DAEMON_OFFLINE_001,
            Self::InsecurePath { .. } | Self::InsecurePermissions { .. } => {
                ERR_IPC_SECURITY_VIOLATION_001
            }
            Self::FrameTooLarge { .. } => ERR_IPC_FRAME_TOO_LARGE_001,
            Self::InvalidFrame { .. } | Self::ChecksumMismatch { .. } | Self::Contract(_) => {
                ERR_IPC_WIRE_CORRUPT_001
            }
            Self::UnsupportedProtocolVersion { .. } | Self::HandshakeMismatch { .. } => {
                ERR_IPC_HANDSHAKE_MISMATCH_001
            }
            Self::HandshakeRejected { error_id, .. } | Self::Refused { error_id, .. } => {
                error_id.as_str()
            }
            Self::InvalidCapability { .. } => ERR_IPC_CAPABILITY_DENIED_001,
            Self::Cancelled { .. } => ERR_IPC_CANCELLED_001,
            Self::Timeout { .. } => ERR_IPC_TIMEOUT_001,
            Self::ConnectionClosed => ERR_IPC_SERVER_SHUTDOWN_001,
            Self::ConnectionLimitReached { .. } => ERR_IPC_CONNECTION_LIMIT_001,
            Self::Io { .. } => ERR_IPC_WIRE_CORRUPT_001,
        }
    }
}

impl From<ContractError> for IpcError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DaemonAlreadyRunning { socket_path } => {
                write!(
                    f,
                    "{ERR_IPC_DAEMON_RUNNING_001}: live daemon already running on {}",
                    socket_path.display()
                )
            }
            Self::DaemonOffline {
                socket_path,
                reason,
                guidance,
                ..
            } => write!(
                f,
                "{ERR_DAEMON_OFFLINE_001}: daemon offline at {} ({reason}). {guidance}",
                socket_path.display()
            ),
            Self::InsecurePath { path, reason } => write!(
                f,
                "{ERR_IPC_SECURITY_VIOLATION_001}: insecure path {}: {reason}",
                path.display()
            ),
            Self::InsecurePermissions { path, mode, reason } => write!(
                f,
                "{ERR_IPC_SECURITY_VIOLATION_001}: insecure permissions {mode:04o} on {}: {reason}",
                path.display()
            ),
            Self::FrameTooLarge { actual, limit } => write!(
                f,
                "{ERR_IPC_FRAME_TOO_LARGE_001}: frame size {actual} bytes exceeds limit {limit} bytes"
            ),
            Self::InvalidFrame { reason } => {
                write!(
                    f,
                    "{ERR_IPC_WIRE_CORRUPT_001}: invalid wire frame: {reason}"
                )
            }
            Self::ChecksumMismatch { expected, actual } => write!(
                f,
                "{ERR_IPC_WIRE_CORRUPT_001}: frame checksum mismatch (expected {expected:02x?}, actual {actual:02x?})"
            ),
            Self::UnsupportedProtocolVersion { expected, actual } => write!(
                f,
                "{ERR_IPC_HANDSHAKE_MISMATCH_001}: unsupported IPC protocol version {actual} (expected {expected})"
            ),
            Self::HandshakeMismatch { reason } => {
                write!(
                    f,
                    "{ERR_IPC_HANDSHAKE_MISMATCH_001}: handshake mismatch: {reason}"
                )
            }
            Self::HandshakeRejected {
                error_id,
                reason,
                expected_protocol_version,
            } => write!(
                f,
                "{error_id}: handshake rejected (expected protocol v{expected_protocol_version}): {reason}"
            ),
            Self::InvalidCapability { reason } => {
                write!(
                    f,
                    "{ERR_IPC_CAPABILITY_DENIED_001}: invalid capability: {reason}"
                )
            }
            Self::Contract(err) => write!(f, "{ERR_IPC_WIRE_CORRUPT_001}: canonical codec: {err}"),
            Self::Refused {
                request_id,
                error_id,
                reason,
                retryable,
            } => write!(
                f,
                "{error_id}: request {request_id} refused (retryable={retryable}): {reason}"
            ),
            Self::Cancelled { request_id } => {
                write!(f, "{ERR_IPC_CANCELLED_001}: request {request_id} cancelled")
            }
            Self::Timeout { operation } => {
                write!(f, "{ERR_IPC_TIMEOUT_001}: IPC timeout during {operation}")
            }
            Self::ConnectionClosed => write!(f, "IPC connection closed by peer"),
            Self::ConnectionLimitReached { limit } => write!(
                f,
                "{ERR_IPC_CONNECTION_LIMIT_001}: daemon reached max_connections={limit}"
            ),
            Self::Io {
                operation,
                kind,
                detail,
            } => write!(f, "IPC I/O error during {operation} ({kind:?}): {detail}"),
        }
    }
}

impl std::error::Error for IpcError {}
