#![forbid(unsafe_code)]
//! Owner-only (`0700`/`0600`) filesystem guards, symlink refusal, and atomic durability helpers.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::SecretError;

/// Required POSIX directory mode mask for vault directories (owner-only).
pub const VAULT_DIR_MODE: u32 = 0o700;

/// Required POSIX regular-file mode for encrypted vault files (owner-only).
pub const VAULT_FILE_MODE: u32 = 0o600;

static TEMP_FILE_SEQ: AtomicU64 = AtomicU64::new(1);

#[cfg(target_os = "macos")]
const O_NOFOLLOW_FLAG: i32 = 0x0100;

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "x86")))]
const O_NOFOLLOW_FLAG: i32 = 0o400_000;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const O_NOFOLLOW_FLAG: i32 = 0o100_000;

/// Ensures `dir` exists as a non-symlink directory with owner-only (`mode & 0o077 == 0`) permissions.
pub fn ensure_secure_dir(dir: &Path) -> Result<(), SecretError> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => validate_dir_metadata(&meta),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            create_secure_dir(dir)?;
            let meta = fs::symlink_metadata(dir).map_err(|io_err| SecretError::StorageIo {
                operation: "stat_vault_dir",
                kind: format!("{:?}", io_err.kind()),
            })?;
            validate_dir_metadata(&meta)
        }
        Err(err) => Err(SecretError::StorageIo {
            operation: "stat_vault_dir",
            kind: format!("{:?}", err.kind()),
        }),
    }
}

/// Validates an existing directory is not a symlink and has no group/other permission bits.
pub fn validate_secure_dir(dir: &Path) -> Result<(), SecretError> {
    let meta = fs::symlink_metadata(dir).map_err(|err| SecretError::StorageIo {
        operation: "stat_vault_dir",
        kind: format!("{:?}", err.kind()),
    })?;
    validate_dir_metadata(&meta)
}

#[cfg(unix)]
fn create_secure_dir(dir: &Path) -> Result<(), SecretError> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(VAULT_DIR_MODE);
    builder.create(dir).map_err(|err| SecretError::StorageIo {
        operation: "create_vault_dir",
        kind: format!("{:?}", err.kind()),
    })
}

#[cfg(not(unix))]
fn create_secure_dir(dir: &Path) -> Result<(), SecretError> {
    fs::create_dir(dir).map_err(|err| SecretError::StorageIo {
        operation: "create_vault_dir",
        kind: format!("{:?}", err.kind()),
    })
}

fn validate_dir_metadata(meta: &Metadata) -> Result<(), SecretError> {
    if meta.file_type().is_symlink() {
        return Err(SecretError::InsecurePermissions {
            detail: "vault directory must not be a symlink".to_string(),
        });
    }
    if !meta.is_dir() {
        return Err(SecretError::InsecurePermissions {
            detail: "vault directory path is not a directory".to_string(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(SecretError::InsecurePermissions {
                detail: format!(
                    "vault directory permissions {mode:04o} expose group or world access (require 0700)"
                ),
            });
        }
    }
    Ok(())
}

/// Validates a regular vault file is not a symlink, has link count 1, and has `mode & 0o077 == 0`.
pub fn validate_secure_file(path: &Path) -> Result<Metadata, SecretError> {
    let meta = fs::symlink_metadata(path).map_err(|err| SecretError::StorageIo {
        operation: "stat_vault_file",
        kind: format!("{:?}", err.kind()),
    })?;
    validate_file_metadata(&meta)?;
    Ok(meta)
}

fn validate_file_metadata(meta: &Metadata) -> Result<(), SecretError> {
    if meta.file_type().is_symlink() {
        return Err(SecretError::InsecurePermissions {
            detail: "vault file must not be a symlink".to_string(),
        });
    }
    if !meta.is_file() {
        return Err(SecretError::InsecurePermissions {
            detail: "vault path is not a regular file".to_string(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(SecretError::InsecurePermissions {
                detail: format!(
                    "vault file permissions {mode:04o} expose group or world access (require 0600)"
                ),
            });
        }
        if meta.nlink() != 1 {
            return Err(SecretError::InsecurePermissions {
                detail: format!(
                    "vault file has link count {} (hardlinks are refused)",
                    meta.nlink()
                ),
            });
        }
    }
    Ok(())
}

/// Reads a bounded regular file after enforcing directory, symlink, and `0600` permission checks.
pub fn read_secure_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, SecretError> {
    if let Some(parent) = path.parent() {
        validate_secure_dir(parent)?;
    }
    let pre_meta = validate_secure_file(path)?;

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")
        )
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(O_NOFOLLOW_FLAG);
    }
    let file = options.open(path).map_err(|err| SecretError::StorageIo {
        operation: "open_vault_file",
        kind: format!("{:?}", err.kind()),
    })?;

    let fd_meta = file.metadata().map_err(|err| SecretError::StorageIo {
        operation: "fstat_vault_file",
        kind: format!("{:?}", err.kind()),
    })?;
    validate_file_metadata(&fd_meta)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if fd_meta.dev() != pre_meta.dev() || fd_meta.ino() != pre_meta.ino() {
            return Err(SecretError::InsecurePermissions {
                detail: "vault file identity changed during open".to_string(),
            });
        }
    }

    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX - 1)
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|err| SecretError::StorageIo {
            operation: "read_vault_file",
            kind: format!("{:?}", err.kind()),
        })?;
    if bytes.len() > max_bytes {
        return Err(SecretError::Tampered {
            detail: "vault file exceeds maximum size limit",
        });
    }
    Ok(bytes)
}

/// Atomically writes `contents` to `dir/filename` via `0600` temp file -> `sync_all` -> rename -> dir `sync_all`.
pub fn write_secure_atomic(dir: &Path, filename: &str, contents: &[u8]) -> Result<(), SecretError> {
    ensure_secure_dir(dir)?;
    let target_path = dir.join(filename);
    if let Ok(meta) = fs::symlink_metadata(&target_path) {
        validate_file_metadata(&meta)?;
    }

    let seq = TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
    let temp_name = format!(".{filename}.tmp.{}.{seq}", std::process::id());
    let temp_path = dir.join(temp_name);

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(VAULT_FILE_MODE);
    }

    let mut temp_file = options
        .open(&temp_path)
        .map_err(|err| SecretError::StorageIo {
            operation: "create_vault_temp",
            kind: format!("{:?}", err.kind()),
        })?;

    if let Err(err) = temp_file.write_all(contents) {
        drop(temp_file);
        let _ = fs::remove_file(&temp_path);
        return Err(SecretError::StorageIo {
            operation: "write_vault_temp",
            kind: format!("{:?}", err.kind()),
        });
    }
    if let Err(err) = temp_file.sync_all() {
        drop(temp_file);
        let _ = fs::remove_file(&temp_path);
        return Err(SecretError::StorageIo {
            operation: "fsync_vault_temp",
            kind: format!("{:?}", err.kind()),
        });
    }
    drop(temp_file);

    if let Err(err) = fs::rename(&temp_path, &target_path) {
        let _ = fs::remove_file(&temp_path);
        return Err(SecretError::StorageIo {
            operation: "rename_vault_file",
            kind: format!("{:?}", err.kind()),
        });
    }

    sync_directory(dir)?;
    let _ = validate_secure_file(&target_path)?;
    Ok(())
}

fn sync_directory(dir: &Path) -> Result<(), SecretError> {
    let dir_file = File::open(dir).map_err(|err| SecretError::StorageIo {
        operation: "open_vault_dir_sync",
        kind: format!("{:?}", err.kind()),
    })?;
    dir_file.sync_all().map_err(|err| SecretError::StorageIo {
        operation: "fsync_vault_dir",
        kind: format!("{:?}", err.kind()),
    })
}
