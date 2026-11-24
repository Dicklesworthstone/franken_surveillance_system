#![forbid(unsafe_code)]
//! Non-secret runtime descriptor (`<root>/run/daemon.meta.json`) and local UDS IPC client
//! helpers (`query_live_daemon_status`, `request_live_daemon_stop`).
//!
//! Semantic plane: `"authority"`.

use std::fs::{self, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use fss_core::json_input::{self, Value};
use fss_core::{CanonicalEncoder, ContentDigest, OperationId, PrincipalId};
use fss_ipc::{
    BoundedControlOp, ControlOperationState, IpcClient, IpcClientConfig, IpcError, IpcResponse,
    LiveDaemonStatus, default_run_dir, default_socket_path, deployment_root_digest,
};

use crate::control::{
    DAEMON_RUNTIME_DESCRIPTOR_DOMAIN, DAEMON_RUNTIME_DESCRIPTOR_SCHEMA,
    DAEMON_RUNTIME_META_FILENAME, DAEMON_STOP_TARGET, daemon_stop_approval_digest,
};
use crate::error::DaemonError;
use crate::telemetry::escape_json;

/// Non-secret owner-only runtime descriptor persisted at `<root>/run/daemon.meta.json` (`0600`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonRuntimeDescriptor {
    /// Stable site / deployment identifier.
    pub site_id: String,
    /// Stable daemon instance identifier.
    pub daemon_instance_id: String,
    /// OS process identifier of the running supervisor.
    pub pid: u32,
    /// Canonical SHA-256 digest of the active site manifest.
    pub manifest_digest: ContentDigest,
    /// Canonical SHA-256 digest of the active `ContractBasis`.
    pub contract_basis_digest: ContentDigest,
    /// Canonical path to the bound Unix domain socket (`daemon.sock`).
    pub socket_path: PathBuf,
    /// Daemon start timestamp in nanoseconds.
    pub started_at_ns: i128,
}

impl DaemonRuntimeDescriptor {
    /// Computes the canonical digest of this descriptor under [`DAEMON_RUNTIME_DESCRIPTOR_DOMAIN`].
    #[must_use]
    pub fn descriptor_digest(&self) -> ContentDigest {
        let mut enc = CanonicalEncoder::new();
        enc.text("fss.canonical.v1");
        enc.text(DAEMON_RUNTIME_DESCRIPTOR_DOMAIN);
        enc.text(&self.site_id);
        enc.text(&self.daemon_instance_id);
        enc.u32(self.pid);
        enc.digest(self.manifest_digest);
        enc.digest(self.contract_basis_digest);
        enc.i128(self.started_at_ns);
        ContentDigest::sha256(&enc.finish())
    }

    /// Atomically writes `<ipc_root>/run/daemon.meta.json` with strict `0600` permissions.
    pub fn write_atomic(&self, ipc_root: &Path) -> Result<PathBuf, DaemonError> {
        let run_dir = default_run_dir(ipc_root);
        let final_path = run_dir.join(DAEMON_RUNTIME_META_FILENAME);
        let tmp_path = run_dir.join(format!("{DAEMON_RUNTIME_META_FILENAME}.tmp.{}", self.pid));
        let json = self.to_json();
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|err| DaemonError::io("create_daemon_meta_tmp", err))?;
        file.write_all(json.as_bytes())
            .map_err(|err| DaemonError::io("write_daemon_meta_tmp", err))?;
        file.sync_all()
            .map_err(|err| DaemonError::io("sync_daemon_meta_tmp", err))?;
        drop(file);
        fs::set_permissions(&tmp_path, Permissions::from_mode(0o600))
            .map_err(|err| DaemonError::io("chmod_daemon_meta_tmp", err))?;
        fs::rename(&tmp_path, &final_path)
            .map_err(|err| DaemonError::io("rename_daemon_meta", err))?;
        Ok(final_path)
    }

    /// Reads `<ipc_root>/run/daemon.meta.json` if present.
    pub fn read_from_root(ipc_root: &Path) -> Result<Self, DaemonError> {
        let path = default_run_dir(ipc_root).join(DAEMON_RUNTIME_META_FILENAME);
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(DaemonError::Ipc(IpcError::daemon_offline(
                    ipc_root,
                    &default_socket_path(ipc_root),
                    "daemon runtime descriptor does not exist",
                )));
            }
            Err(err) => return Err(DaemonError::io("read_daemon_meta", err)),
        };
        Self::parse_json(&text)
    }

    /// Removes `<ipc_root>/run/daemon.meta.json` if it belongs to this daemon instance.
    pub fn remove_if_owned(ipc_root: &Path, daemon_instance_id: &str) {
        let path = default_run_dir(ipc_root).join(DAEMON_RUNTIME_META_FILENAME);
        if let Ok(existing) = Self::read_from_root(ipc_root)
            && existing.daemon_instance_id == daemon_instance_id
        {
            let _ = fs::remove_file(path);
        }
    }

    /// Renders deterministic non-secret JSON for `daemon.meta.json`.
    #[must_use]
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\"schema\":\"{}\",\"site_id\":\"{}\",\"daemon_instance_id\":\"{}\",",
                "\"pid\":{},\"manifest_digest\":\"{}\",\"contract_basis_digest\":\"{}\",",
                "\"socket_path\":\"{}\",\"started_at_ns\":\"{}\",\"descriptor_digest\":\"{}\"}}"
            ),
            DAEMON_RUNTIME_DESCRIPTOR_SCHEMA,
            escape_json(&self.site_id),
            escape_json(&self.daemon_instance_id),
            self.pid,
            self.manifest_digest.to_text(),
            self.contract_basis_digest.to_text(),
            escape_json(&self.socket_path.to_string_lossy()),
            self.started_at_ns,
            self.descriptor_digest().to_text(),
        )
    }

    /// Parses a [`DaemonRuntimeDescriptor`] from UTF-8 JSON without Serde.
    pub fn parse_json(text: &str) -> Result<Self, DaemonError> {
        let val = json_input::parse(text).map_err(|err| DaemonError::InvalidManifest {
            detail: format!("invalid daemon runtime descriptor JSON: {err}"),
        })?;
        let obj = val.object().ok_or_else(|| DaemonError::InvalidManifest {
            detail: "daemon runtime descriptor must be a JSON object".to_owned(),
        })?;
        let get_str = |key: &str| -> Result<&str, DaemonError> {
            obj.get(key)
                .and_then(Value::text)
                .ok_or_else(|| DaemonError::InvalidManifest {
                    detail: format!("daemon descriptor missing `{key}`"),
                })
        };
        let pid_i128 = obj.get("pid").and_then(Value::integer).ok_or_else(|| {
            DaemonError::InvalidManifest {
                detail: "daemon descriptor missing integer `pid`".to_owned(),
            }
        })?;
        let pid = u32::try_from(pid_i128).map_err(|_| DaemonError::InvalidManifest {
            detail: "daemon descriptor `pid` out of range".to_owned(),
        })?;
        let started_at_ns = obj
            .get("started_at_ns")
            .and_then(Value::integer)
            .ok_or_else(|| DaemonError::InvalidManifest {
                detail: "daemon descriptor missing `started_at_ns`".to_owned(),
            })?;
        Ok(Self {
            site_id: get_str("site_id")?.to_owned(),
            daemon_instance_id: get_str("daemon_instance_id")?.to_owned(),
            pid,
            manifest_digest: ContentDigest::parse(get_str("manifest_digest")?)?,
            contract_basis_digest: ContentDigest::parse(get_str("contract_basis_digest")?)?,
            socket_path: PathBuf::from(get_str("socket_path")?),
            started_at_ns,
        })
    }
}

fn connect_local_daemon(
    deployment_root: &Path,
    site_id_override: Option<&str>,
    principal: PrincipalId,
) -> Result<(DaemonRuntimeDescriptor, String, IpcClient), DaemonError> {
    let descriptor = DaemonRuntimeDescriptor::read_from_root(deployment_root)?;
    let deployment_id = site_id_override.unwrap_or(&descriptor.site_id).to_owned();
    let client = IpcClient::connect(IpcClientConfig {
        deployment_root: deployment_root.to_path_buf(),
        deployment_id: deployment_id.clone(),
        contract_basis_digest: descriptor.contract_basis_digest,
        principal,
        capabilities: vec!["CAP-OBSERVE-STATUS-001".to_owned()],
        io_timeout: Duration::from_secs(5),
    })?;
    Ok((descriptor, deployment_id, client))
}

/// Connects to a running local `fss-daemon` over UDS and fetches its [`LiveDaemonStatus`].
pub fn query_live_daemon_status(
    deployment_root: &Path,
    site_id_override: Option<&str>,
    principal: PrincipalId,
) -> Result<(DaemonRuntimeDescriptor, LiveDaemonStatus), DaemonError> {
    let (descriptor, _, mut client) =
        connect_local_daemon(deployment_root, site_id_override, principal)?;
    let req_id = client.next_request_id();
    match client.query_live_status(req_id, true, true)? {
        IpcResponse::LiveStatus(status) => Ok((descriptor, status)),
        IpcResponse::Refused {
            request_id,
            error_id,
            reason,
            retryable,
        } => Err(DaemonError::Ipc(IpcError::Refused {
            request_id,
            error_id,
            reason,
            retryable,
        })),
        other => Err(DaemonError::Ipc(IpcError::InvalidFrame {
            reason: format!(
                "unexpected IPC response for QueryLiveStatus: req_id={}",
                other.request_id()
            ),
        })),
    }
}

/// Connects to a running local `fss-daemon` over UDS and issues a clean graceful shutdown request.
pub fn request_live_daemon_stop(
    deployment_root: &Path,
    site_id_override: Option<&str>,
    principal: PrincipalId,
) -> Result<(DaemonRuntimeDescriptor, OperationId, ControlOperationState), DaemonError> {
    let (descriptor, deployment_id, mut client) =
        connect_local_daemon(deployment_root, site_id_override, principal)?;
    let root_digest = deployment_root_digest(deployment_root);
    let approval = daemon_stop_approval_digest(&deployment_id, root_digest);
    let req_id = client.next_request_id();
    match client.submit_bounded_control(
        req_id,
        BoundedControlOp::StopCamera,
        Some(DAEMON_STOP_TARGET.to_owned()),
        approval,
    )? {
        IpcResponse::ControlAccepted {
            operation_id,
            state,
            ..
        } => Ok((descriptor, operation_id, state)),
        IpcResponse::Refused {
            request_id,
            error_id,
            reason,
            retryable,
        } => Err(DaemonError::Ipc(IpcError::Refused {
            request_id,
            error_id,
            reason,
            retryable,
        })),
        other => Err(DaemonError::Ipc(IpcError::InvalidFrame {
            reason: format!(
                "unexpected IPC response for StopDaemon: req_id={}",
                other.request_id()
            ),
        })),
    }
}
