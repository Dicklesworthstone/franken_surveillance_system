#![forbid(unsafe_code)]
//! Live daemon discovery with automatic offline direct read-only fallback.

use std::path::{Path, PathBuf};

use fss_core::{ContentDigest, ContractBasis, PrincipalId};

use crate::client::{IpcClient, IpcClientConfig};
use crate::error::{ERR_DAEMON_OFFLINE_001, IpcError, daemon_start_guidance, parse_error_id};
use crate::protocol::{BoundedControlOp, IpcResponse};
use crate::security::default_socket_path;
use crate::trace::IpcTraceEvent;

/// Active deployment access channel: either live authenticated UDS IPC or offline direct fallback.
pub enum DeploymentChannel {
    /// Connected and handshake-verified against a running local supervisor daemon.
    LiveDaemon(IpcClient),
    /// No local daemon is listening; callers may open read-only v2 MVCC projections directly.
    OfflineDirect {
        /// Deployment root directory for direct read-only projection access.
        root: PathBuf,
        /// Non-secret explanation of why the live daemon channel was unavailable.
        fallback_reason: String,
    },
}

impl DeploymentChannel {
    /// Returns true when backed by a live authenticated daemon connection.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        matches!(self, Self::LiveDaemon(_))
    }

    /// Submits a live-only bounded control request, returning `ERR-DAEMON-OFFLINE-001` when offline.
    pub fn submit_bounded_control(
        &mut self,
        request_id: u64,
        op: BoundedControlOp,
        target_camera_id: Option<String>,
        approval_digest: ContentDigest,
    ) -> Result<IpcResponse, IpcError> {
        match self {
            Self::LiveDaemon(client) => {
                client.submit_bounded_control(request_id, op, target_camera_id, approval_digest)
            }
            Self::OfflineDirect {
                root,
                fallback_reason,
            } => Err(IpcError::daemon_offline(
                root,
                &default_socket_path(root),
                fallback_reason.clone(),
            )),
        }
    }

    /// Builds a typed [`IpcResponse::Refused`] carrying `ERR-DAEMON-OFFLINE-001` and exact
    /// supervisor-start guidance when operating offline.
    pub fn offline_refusal_response(
        request_id: u64,
        root: &Path,
        fallback_reason: &str,
    ) -> Result<IpcResponse, IpcError> {
        let error_id = parse_error_id(ERR_DAEMON_OFFLINE_001)?;
        Ok(IpcResponse::Refused {
            request_id,
            error_id,
            reason: format!("{fallback_reason}. {}", daemon_start_guidance(root)),
            retryable: true,
        })
    }

    /// Emits an offline fallback trace record for diagnostic parity with live IPC traces.
    #[must_use]
    pub fn offline_trace_event(request_id: u64, op: &str) -> IpcTraceEvent {
        IpcTraceEvent {
            req_id: request_id,
            op: op.to_owned(),
            frame_bytes: 0,
            rtt_us: 0,
            outcome: ERR_DAEMON_OFFLINE_001.to_owned(),
            fallback_used: true,
        }
    }
}

/// Entrypoint for discovering and connecting to a deployment's local daemon with offline fallback.
pub struct DeploymentClient;

impl DeploymentClient {
    /// Probes `<root>/run/daemon.sock` and returns either [`DeploymentChannel::LiveDaemon`] or
    /// [`DeploymentChannel::OfflineDirect`].
    ///
    /// Security violations (symlinks, world/group-writable permissions) and live handshake
    /// mismatches (wrong deployment or `ContractBasis`) ALWAYS fail closed and never silently
    /// fall back to offline mode.
    pub fn connect_or_direct(
        root: impl Into<PathBuf>,
        expected_deployment: impl Into<String>,
        contract_basis: &ContractBasis,
        principal: PrincipalId,
    ) -> Result<DeploymentChannel, IpcError> {
        Self::connect_or_direct_with_capabilities(
            root,
            expected_deployment,
            contract_basis,
            principal,
            Vec::new(),
        )
    }

    /// Same as [`Self::connect_or_direct`] while requesting explicit opaque capability IDs.
    pub fn connect_or_direct_with_capabilities(
        root: impl Into<PathBuf>,
        expected_deployment: impl Into<String>,
        contract_basis: &ContractBasis,
        principal: PrincipalId,
        capabilities: Vec<String>,
    ) -> Result<DeploymentChannel, IpcError> {
        let root_path = root.into();
        let config = IpcClientConfig::from_contract_basis(
            root_path.clone(),
            expected_deployment,
            contract_basis,
            principal,
            capabilities,
        );
        match IpcClient::connect(config) {
            Ok(client) => Ok(DeploymentChannel::LiveDaemon(client)),
            Err(IpcError::DaemonOffline { reason, .. }) => Ok(DeploymentChannel::OfflineDirect {
                root: root_path,
                fallback_reason: reason,
            }),
            Err(err) => Err(err),
        }
    }
}
