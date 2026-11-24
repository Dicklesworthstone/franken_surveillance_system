#![forbid(unsafe_code)]
//! Low-level filesystem, locking, digest-stem, and closure helpers for local publication.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File, TryLockError};
use std::io;
use std::path::Path;
use std::sync::Arc;

use fss_core::ContentDigest;
use fss_object::{MAX_INTERRUPTED_ATTEMPTS, SpoolIo, SpoolLock, SpoolRecoveryReport};

use super::{LOCAL_LOCK_FILE, LocalIoOperation, LocalPublicationError};

pub(super) fn compute_closure(
    manifests: &BTreeMap<ContentDigest, &[ContentDigest]>,
    root: ContentDigest,
    children: &[ContentDigest],
) -> BTreeSet<ContentDigest> {
    let mut seen = BTreeSet::from([root]);
    let mut pending = children.to_vec();
    while let Some(digest) = pending.pop() {
        if seen.insert(digest)
            && let Some(grandchildren) = manifests.get(&digest)
        {
            pending.extend_from_slice(grandchildren);
        }
    }
    seen
}

/// Spool objects, admitted or corrupt, that no closure in `referenced` reaches.
pub(super) fn unreferenced_spool_objects(
    spool: &SpoolRecoveryReport,
    referenced: &BTreeSet<ContentDigest>,
) -> Vec<ContentDigest> {
    let spool_objects = spool
        .admitted
        .iter()
        .copied()
        .chain(spool.corrupt.iter().map(|corrupt| corrupt.digest))
        .collect::<BTreeSet<_>>();
    spool_objects.difference(referenced).copied().collect()
}

/// Whether `path` is a directory, without following a symlink. Absent is `false`; any other file
/// type is [`LocalPublicationError::InvalidLayout`], the class the open reports.
pub(super) fn directory_present(
    io: &dyn SpoolIo,
    path: &Path,
) -> Result<bool, LocalPublicationError> {
    match io.symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(true),
        Ok(_) => Err(LocalPublicationError::InvalidLayout {
            path: path.to_path_buf(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(LocalIoOperation::Inspect, path, &error)),
    }
}

pub(super) fn io_error(
    operation: LocalIoOperation,
    path: &Path,
    error: &io::Error,
) -> LocalPublicationError {
    LocalPublicationError::Io {
        operation,
        path: path.to_path_buf(),
        kind: error.kind(),
    }
}

pub(super) fn acquire_lock(
    io: &Arc<dyn SpoolIo>,
    root: &Path,
) -> Result<SpoolLock, LocalPublicationError> {
    let path = root.join(LOCAL_LOCK_FILE);
    match io.symlink_metadata(&path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(LocalPublicationError::InvalidLayout { path });
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(LocalIoOperation::Inspect, &path, &error)),
    }
    let file = io
        .open_lock(&path)
        .map_err(|error| io_error(LocalIoOperation::OpenLock, &path, &error))?;
    match SpoolLock::try_acquire(file, Arc::clone(io)) {
        Ok(lock) => Ok(lock),
        Err(TryLockError::WouldBlock) => Err(LocalPublicationError::Locked { path }),
        Err(TryLockError::Error(error)) => Err(io_error(LocalIoOperation::Lock, &path, &error)),
    }
}

pub(super) fn ensure_subdirectory(
    io: &dyn SpoolIo,
    path: &Path,
) -> Result<(), LocalPublicationError> {
    match io.create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(io_error(LocalIoOperation::CreateDirectory, path, &error)),
    }
    let metadata = io
        .symlink_metadata(path)
        .map_err(|error| io_error(LocalIoOperation::Inspect, path, &error))?;
    if !metadata.file_type().is_dir() {
        return Err(LocalPublicationError::InvalidLayout {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

/// Writes all of `bytes` through `io`, resuming after partial writes.
///
/// A write that accepts zero bytes is [`io::ErrorKind::WriteZero`]. An
/// [`io::ErrorKind::Interrupted`] write transferred nothing, so it is retried at the same offset,
/// exactly as the spool's own staging write does; the [`MAX_INTERRUPTED_ATTEMPTS`]-th consecutive
/// interruption at one offset is returned, and the caller reports it as
/// [`LocalIoOperation::WriteTemp`]. Any other error is returned at once. The loop is bounded:
/// every iteration either advances by at least one byte or spends one of the interrupted attempts
/// allowed at the current offset.
pub(super) fn write_all(io: &dyn SpoolIo, file: &mut File, bytes: &[u8]) -> io::Result<()> {
    let mut written = 0_usize;
    let mut interrupted = 0_u32;
    while let Some(rest) = bytes.get(written..).filter(|rest| !rest.is_empty()) {
        match io.write(file, rest) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write whole buffer",
                ));
            }
            Ok(accepted) => {
                written = written.saturating_add(accepted.min(rest.len()));
                interrupted = 0;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                interrupted = interrupted.saturating_add(1);
                if interrupted >= MAX_INTERRUPTED_ATTEMPTS {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(super) fn scan_directory(
    io: &dyn SpoolIo,
    dir: &Path,
    bound: usize,
) -> Result<Vec<(OsString, fs::FileType)>, LocalPublicationError> {
    let mut entries = io
        .read_dir(dir)
        .map_err(|error| io_error(LocalIoOperation::ScanDirectory, dir, &error))?;
    let mut found = Vec::new();
    while let Some(entry) = io.next_dir_entry(&mut entries) {
        let entry =
            entry.map_err(|error| io_error(LocalIoOperation::ScanDirectory, dir, &error))?;
        if found.len() >= bound {
            // Bounded scan: this entry is the first one past `bound`. The rest of the directory
            // is never listed, so only a lower bound on its size is known.
            return Err(LocalPublicationError::EntryLimit {
                directory: dir.to_path_buf(),
                maximum: bound,
                at_least: bound.saturating_add(1),
            });
        }
        let file_type = io
            .entry_file_type(&entry)
            .map_err(|error| io_error(LocalIoOperation::Inspect, &entry.path(), &error))?;
        found.push((entry.file_name(), file_type));
    }
    found.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(found)
}

/// Reads at most `limit` bytes; `Ok(None)` means the file is longer than `limit`.
pub(super) fn read_bounded(
    io: &dyn SpoolIo,
    path: &Path,
    limit: u64,
) -> Result<Option<Vec<u8>>, LocalPublicationError> {
    let mut file = io
        .open_read(path)
        .map_err(|error| io_error(LocalIoOperation::ReadRecord, path, &error))?;
    let bytes = io
        .read_bounded(&mut file, limit.saturating_add(1))
        .map_err(|error| io_error(LocalIoOperation::ReadRecord, path, &error))?;
    if bytes.len() as u64 > limit {
        return Ok(None);
    }
    Ok(Some(bytes))
}

/// `<algorithm>-<64 lowercase hex>`: a file-name-safe rendering of a content digest.
pub(super) fn digest_file_stem(digest: ContentDigest) -> String {
    digest.to_text().replacen(':', "-", 1)
}

pub(super) fn parse_digest_file_stem(stem: &str) -> Option<ContentDigest> {
    let (algorithm, hex) = stem.split_once('-')?;
    let digest = ContentDigest::parse(format!("{algorithm}:{hex}")).ok()?;
    (digest_file_stem(digest) == stem).then_some(digest)
}

/// The directory holding the record at `path`, whose fsync makes the record's creation, rename,
/// or removal durable. A path without a non-empty parent is [`LocalPublicationError::InvalidLayout`]:
/// there is no directory to fsync, and silently fsyncing another one would claim durability that
/// was never observed.
pub(super) fn record_directory(path: &Path) -> Result<&Path, LocalPublicationError> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => Ok(parent),
        Some(_) | None => Err(LocalPublicationError::InvalidLayout {
            path: path.to_path_buf(),
        }),
    }
}
