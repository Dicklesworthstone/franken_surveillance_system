#![forbid(unsafe_code)]
//! Owner-only Unix filesystem security, symlink refusal, and stale-socket recovery.

use std::collections::BTreeSet;
use std::fs::{self, DirBuilder, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fss_core::{CanonicalEncoder, ContentDigest, validate_id};

use crate::error::IpcError;

/// Canonical runtime directory name beneath a deployment root.
pub const RUN_DIR_NAME: &str = "run";

/// Canonical local daemon Unix socket filename beneath `<deployment>/run`.
pub const DAEMON_SOCKET_NAME: &str = "daemon.sock";

/// Required POSIX mode for `<deployment>/run` (owner read/write/execute only).
pub const OWNER_ONLY_DIR_MODE: u32 = 0o700;

/// Required POSIX mode for `<deployment>/run/daemon.sock` (owner read/write only).
pub const OWNER_ONLY_SOCKET_MODE: u32 = 0o600;

/// Mask of group and world permission bits that must always be zero.
pub const FORBIDDEN_GROUP_WORLD_MASK: u32 = 0o077;

/// Canonical digest domain for pinning a deployment root identity across IPC handshakes.
pub const IPC_DEPLOYMENT_ROOT_DIGEST_DOMAIN: &str = "fss.ipc.deployment_root.v1";

/// Maximum number of opaque capability identifiers admitted in one handshake.
pub const MAX_HANDSHAKE_CAPABILITIES: usize = 64;

/// Maximum byte length of a single opaque capability identifier.
pub const MAX_CAPABILITY_ID_LEN: usize = 128;

/// Device and inode identity of a bound Unix socket for safe owner-verified unlink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketInode {
    /// Filesystem device identifier.
    pub dev: u64,
    /// Filesystem inode number.
    pub ino: u64,
}

/// Liveness result returned by a bounded local socket connect probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketProbeState {
    /// A live daemon accepted or queued the probe connection.
    Live,
    /// A socket file exists on disk, but the kernel returned `ECONNREFUSED`.
    Stale,
    /// No socket file exists at the target path.
    Missing,
}

/// Returns the default runtime directory `<deployment_root>/run`.
#[must_use]
pub fn default_run_dir(deployment_root: &Path) -> PathBuf {
    deployment_root.join(RUN_DIR_NAME)
}

/// Returns the default daemon Unix socket path `<deployment_root>/run/daemon.sock`.
#[must_use]
pub fn default_socket_path(deployment_root: &Path) -> PathBuf {
    default_run_dir(deployment_root).join(DAEMON_SOCKET_NAME)
}

/// Computes the canonical domain-separated SHA-256 digest of a deployment root path.
///
/// Uses `fs::canonicalize` when the deployment root exists on disk so platform symlink
/// prefixes (such as `/var` vs `/private/var` on macOS) resolve identically for server
/// and client processes.
#[must_use]
pub fn deployment_root_digest(deployment_root: &Path) -> ContentDigest {
    let resolved =
        fs::canonicalize(deployment_root).unwrap_or_else(|_| deployment_root.to_path_buf());
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.canonical.v1");
    encoder.text(IPC_DEPLOYMENT_ROOT_DIGEST_DOMAIN);
    encoder.bytes(resolved.as_os_str().as_encoded_bytes());
    ContentDigest::sha256(&encoder.finish())
}

/// Validates a single opaque capability identifier and refuses credential-like values.
pub fn validate_capability_id(capability: &str) -> Result<(), IpcError> {
    if capability.is_empty() || capability.len() > MAX_CAPABILITY_ID_LEN {
        return Err(IpcError::InvalidCapability {
            reason: format!(
                "capability length must be 1..={MAX_CAPABILITY_ID_LEN} bytes (got {})",
                capability.len()
            ),
        });
    }
    validate_id(capability).map_err(|_| IpcError::InvalidCapability {
        reason: "capability identifier must use portable opaque ID alphabet only".to_owned(),
    })?;
    let lower = capability.to_ascii_lowercase();
    const FORBIDDEN_SECRET_PREFIXES: &[&str] = &[
        "bearer:",
        "basic:",
        "password:",
        "secret:",
        "token:",
        "apikey:",
        "api_key:",
        "sk_live",
        "sk_test",
        "ghp_",
        "eyj",
    ];
    if FORBIDDEN_SECRET_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
    {
        return Err(IpcError::InvalidCapability {
            reason: "raw credentials or secret-like tokens may never cross the IPC wire".to_owned(),
        });
    }
    Ok(())
}

/// Validates a handshake capability list for count bounds, uniqueness, and opaque syntax.
pub fn validate_capabilities(capabilities: &[String]) -> Result<(), IpcError> {
    if capabilities.len() > MAX_HANDSHAKE_CAPABILITIES {
        return Err(IpcError::InvalidCapability {
            reason: format!(
                "capability list length {} exceeds max {MAX_HANDSHAKE_CAPABILITIES}",
                capabilities.len()
            ),
        });
    }
    let mut seen = BTreeSet::new();
    for cap in capabilities {
        validate_capability_id(cap)?;
        if !seen.insert(cap.as_str()) {
            return Err(IpcError::InvalidCapability {
                reason: format!("duplicate capability identifier: {cap}"),
            });
        }
    }
    Ok(())
}

/// Validates wire-carried diagnostic text (bounded length, no embedded NULs).
pub fn validate_wire_text(
    field: &'static str,
    text: &str,
    max_bytes: usize,
) -> Result<(), IpcError> {
    if text.len() > max_bytes {
        return Err(IpcError::InvalidFrame {
            reason: format!("{field} length {} exceeds limit {max_bytes}", text.len()),
        });
    }
    if text.bytes().any(|b| b == 0) {
        return Err(IpcError::InvalidFrame {
            reason: format!("{field} contains forbidden NUL byte"),
        });
    }
    Ok(())
}

/// Validates or creates the owner-only `0700` runtime directory `<deployment>/run`.
///
/// Refuses symlinks, non-directories, and any group/world permission bits (`mode & 0o077 != 0`).
/// Returns the verified owner UID on success.
pub fn validate_or_create_run_dir(run_dir: &Path) -> Result<u32, IpcError> {
    match fs::symlink_metadata(run_dir) {
        Ok(meta) => verify_run_dir_metadata(run_dir, &meta),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(OWNER_ONLY_DIR_MODE);
            builder
                .create(run_dir)
                .map_err(|create_err| IpcError::io("create_run_dir", create_err))?;
            fs::set_permissions(run_dir, Permissions::from_mode(OWNER_ONLY_DIR_MODE))
                .map_err(|perm_err| IpcError::io("chmod_run_dir", perm_err))?;
            let meta = fs::symlink_metadata(run_dir)
                .map_err(|stat_err| IpcError::io("stat_run_dir", stat_err))?;
            verify_run_dir_metadata(run_dir, &meta)
        }
        Err(err) => Err(IpcError::io("stat_run_dir", err)),
    }
}

/// Verifies metadata for an existing runtime directory without following symlinks.
fn verify_run_dir_metadata(run_dir: &Path, meta: &fs::Metadata) -> Result<u32, IpcError> {
    let file_type = meta.file_type();
    if file_type.is_symlink() {
        return Err(IpcError::InsecurePath {
            path: run_dir.to_path_buf(),
            reason: "runtime directory must not be a symlink".to_owned(),
        });
    }
    if !file_type.is_dir() {
        return Err(IpcError::InsecurePath {
            path: run_dir.to_path_buf(),
            reason: "runtime path exists and is not a directory".to_owned(),
        });
    }
    let mode = meta.permissions().mode() & 0o777;
    if (mode & FORBIDDEN_GROUP_WORLD_MASK) != 0 {
        return Err(IpcError::InsecurePermissions {
            path: run_dir.to_path_buf(),
            mode,
            reason: "runtime directory grants group or world access (must be 0700)".to_owned(),
        });
    }
    if (mode & OWNER_ONLY_DIR_MODE) != OWNER_ONLY_DIR_MODE {
        return Err(IpcError::InsecurePermissions {
            path: run_dir.to_path_buf(),
            mode,
            reason: "runtime directory must grant owner rwx (0700)".to_owned(),
        });
    }
    Ok(meta.uid())
}

/// Probes whether an existing Unix socket has a live listener or is a stale file.
pub fn probe_socket_liveness(
    socket_path: &Path,
    timeout: Duration,
) -> Result<SocketProbeState, IpcError> {
    let deadline = Instant::now() + timeout;
    loop {
        match UnixStream::connect(socket_path) {
            Ok(stream) => {
                drop(stream);
                return Ok(SocketProbeState::Live);
            }
            Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {
                return Ok(SocketProbeState::Stale);
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(SocketProbeState::Missing);
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                // Full listen backlog indicates an active daemon owns the socket.
                return Ok(SocketProbeState::Live);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                if Instant::now() >= deadline {
                    return Err(IpcError::Timeout {
                        operation: "probe_socket_liveness",
                    });
                }
            }
            Err(err) => return Err(IpcError::io("probe_socket_liveness", err)),
        }
    }
}

/// Prepares `<deployment>/run/daemon.sock` for server bind with stale-socket recovery.
///
/// Refuses symlinks, non-sockets, group/world-accessible runtime directories, and live daemons.
/// Removes a stale socket file only after confirming `ECONNREFUSED` and re-verifying that the
/// path is still a non-symlink Unix socket.
pub fn prepare_socket_for_bind(
    run_dir: &Path,
    socket_path: &Path,
    probe_timeout: Duration,
) -> Result<u32, IpcError> {
    let owner_uid = validate_or_create_run_dir(run_dir)?;
    let meta = match fs::symlink_metadata(socket_path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(owner_uid),
        Err(err) => return Err(IpcError::io("stat_existing_socket", err)),
    };
    verify_socket_entry_type(socket_path, &meta)?;
    if meta.uid() != owner_uid {
        return Err(IpcError::InsecurePermissions {
            path: socket_path.to_path_buf(),
            mode: meta.permissions().mode() & 0o777,
            reason: "existing socket owner does not match runtime directory owner".to_owned(),
        });
    }
    match probe_socket_liveness(socket_path, probe_timeout)? {
        SocketProbeState::Live => Err(IpcError::DaemonAlreadyRunning {
            socket_path: socket_path.to_path_buf(),
        }),
        SocketProbeState::Missing => Ok(owner_uid),
        SocketProbeState::Stale => {
            // Re-verify immediately before unlink so we never remove a symlink or regular file.
            let recheck = fs::symlink_metadata(socket_path)
                .map_err(|err| IpcError::io("recheck_stale_socket", err))?;
            verify_socket_entry_type(socket_path, &recheck)?;
            fs::remove_file(socket_path).map_err(|err| IpcError::io("remove_stale_socket", err))?;
            Ok(owner_uid)
        }
    }
}

/// Hardens a freshly bound Unix socket to strictly `0600` and returns its inode identity.
pub fn harden_bound_socket(socket_path: &Path, expected_uid: u32) -> Result<SocketInode, IpcError> {
    fs::set_permissions(socket_path, Permissions::from_mode(OWNER_ONLY_SOCKET_MODE))
        .map_err(|err| IpcError::io("chmod_socket", err))?;
    let meta =
        fs::symlink_metadata(socket_path).map_err(|err| IpcError::io("stat_bound_socket", err))?;
    verify_socket_entry_type(socket_path, &meta)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != OWNER_ONLY_SOCKET_MODE {
        return Err(IpcError::InsecurePermissions {
            path: socket_path.to_path_buf(),
            mode,
            reason: "bound socket permissions must be strictly 0600".to_owned(),
        });
    }
    if meta.uid() != expected_uid {
        return Err(IpcError::InsecurePermissions {
            path: socket_path.to_path_buf(),
            mode,
            reason: "bound socket owner mismatch".to_owned(),
        });
    }
    Ok(SocketInode {
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

/// Removes a socket file only if it is still a non-symlink socket with the exact bound inode.
pub fn remove_owned_socket(socket_path: &Path, expected: SocketInode) {
    if let Ok(meta) = fs::symlink_metadata(socket_path) {
        let ft = meta.file_type();
        if !ft.is_symlink()
            && ft.is_socket()
            && meta.dev() == expected.dev
            && meta.ino() == expected.ino
        {
            let _ = fs::remove_file(socket_path);
        }
    }
}

/// Validates runtime directory and socket security before a client connects.
///
/// Missing `run` directory or missing `daemon.sock` returns [`IpcError::DaemonOffline`].
/// Any symlink, non-socket, group/world permission bit, or owner mismatch fails closed with
/// [`IpcError::InsecurePath`] or [`IpcError::InsecurePermissions`].
pub fn validate_socket_for_client(
    deployment_root: &Path,
    run_dir: &Path,
    socket_path: &Path,
) -> Result<(), IpcError> {
    let run_meta = match fs::symlink_metadata(run_dir) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(IpcError::daemon_offline(
                deployment_root,
                socket_path,
                "runtime directory does not exist",
            ));
        }
        Err(err) => return Err(IpcError::io("stat_client_run_dir", err)),
    };
    let run_uid = verify_run_dir_metadata(run_dir, &run_meta)?;

    let sock_meta = match fs::symlink_metadata(socket_path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(IpcError::daemon_offline(
                deployment_root,
                socket_path,
                "daemon socket file does not exist",
            ));
        }
        Err(err) => return Err(IpcError::io("stat_client_socket", err)),
    };
    verify_socket_entry_type(socket_path, &sock_meta)?;
    let sock_mode = sock_meta.permissions().mode() & 0o777;
    if (sock_mode & FORBIDDEN_GROUP_WORLD_MASK) != 0 || sock_mode != OWNER_ONLY_SOCKET_MODE {
        return Err(IpcError::InsecurePermissions {
            path: socket_path.to_path_buf(),
            mode: sock_mode,
            reason: "daemon socket permissions must be strictly 0600".to_owned(),
        });
    }
    if sock_meta.uid() != run_uid {
        return Err(IpcError::InsecurePermissions {
            path: socket_path.to_path_buf(),
            mode: sock_mode,
            reason: "daemon socket owner does not match runtime directory owner".to_owned(),
        });
    }
    Ok(())
}

fn verify_socket_entry_type(socket_path: &Path, meta: &fs::Metadata) -> Result<(), IpcError> {
    let file_type = meta.file_type();
    if file_type.is_symlink() {
        return Err(IpcError::InsecurePath {
            path: socket_path.to_path_buf(),
            reason: "daemon socket path must not be a symlink".to_owned(),
        });
    }
    if !file_type.is_socket() {
        return Err(IpcError::InsecurePath {
            path: socket_path.to_path_buf(),
            reason: "daemon socket path is not a Unix domain socket".to_owned(),
        });
    }
    Ok(())
}
