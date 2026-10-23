#![forbid(unsafe_code)]
//! Exact admitted regular files and a metered, revocable read-only capability.

use std::fmt;
use std::fs::{self, DirEntry, File, FileType, Metadata, ReadDir, TryLockError};
use std::io::{self, Read, Seek};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_ledger::{JournalFileMetadata, JournalReadIo};
use fss_object::SpoolIo;

use super::{BackupError, BackupLimits, ReplayCx, Result};

mod destination;
pub(super) use destination::{PinnedSpoolIo, WriteTree};

/// All parents must already be owned ordinary directories. No normalization follows links.
pub(super) fn checked_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir | Component::Prefix(_) => return Err(BackupError::InvalidPath),
            Component::CurDir => continue,
            _ => current.push(component),
        }
        let meta = fs::symlink_metadata(&current)?;
        if meta.file_type().is_symlink() {
            return Err(BackupError::Unsupported("symlink"));
        }
        if current != absolute && !meta.is_dir() {
            return Err(BackupError::InvalidPath);
        }
    }
    Ok(current)
}

pub(super) fn directory(path: &Path) -> Result<PathBuf> {
    let path = checked_path(path)?;
    if !fs::symlink_metadata(&path)?.is_dir() {
        return Err(BackupError::InvalidPath);
    }
    Ok(path)
}

pub(super) fn fresh_path(path: &Path, forbidden: &[&Path]) -> Result<PathBuf> {
    let name = path.file_name().ok_or(BackupError::InvalidPath)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let path = directory(parent)?.join(name);
    for other in forbidden {
        let other = directory(other)?;
        if path.starts_with(&other) || other.starts_with(&path) {
            return Err(BackupError::InvalidPath);
        }
    }
    match fs::symlink_metadata(&path) {
        Ok(_) => Err(BackupError::DestinationExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(path),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn regular(meta: &Metadata) -> Result<()> {
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(BackupError::Unsupported("nonregular_file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            return Err(BackupError::Unsupported("hardlink"));
        }
    }
    #[cfg(not(unix))]
    return Err(BackupError::Unsupported("file_identity_platform"));
    Ok(())
}

pub(super) fn same_file(a: &Metadata, b: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (
            a.dev(),
            a.ino(),
            a.len(),
            a.mtime(),
            a.mtime_nsec(),
            a.ctime(),
            a.ctime_nsec(),
        ) == (
            b.dev(),
            b.ino(),
            b.len(),
            b.mtime(),
            b.mtime_nsec(),
            b.ctime(),
            b.ctime_nsec(),
        )
    }
    #[cfg(not(unix))]
    {
        let _ = (a, b);
        false
    }
}

pub(super) fn open_file(path: &Path, cx: &ReplayCx) -> Result<File> {
    checked_path(path)?;
    let admitted = fs::symlink_metadata(path)?;
    regular(&admitted)?;
    let file = crate::ingest::file_adapter::open_admitted_source(cx, path, &admitted)
        .map_err(|_| BackupError::Changed)?;
    let opened = file.metadata()?;
    regular(&opened)?;
    if !same_file(&admitted, &opened) {
        return Err(BackupError::Changed);
    }
    Ok(file)
}

/// Detect only presence, never create or follow an independent agent directory.
pub(super) fn agent_present(root: &Path, gate: &dyn Fn() -> Result<()>) -> Result<bool> {
    gate()?;
    let path = root.join("agent");
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    directory(&path)?;
    let populated = fs::read_dir(path)?.next().transpose()?.is_some();
    gate()?;
    Ok(populated)
}

/// Existing file descriptions are locked without creating/truncating any source state.
pub(super) fn source_locks(
    root: &Path,
    cx: &ReplayCx,
    gate: &dyn Fn() -> Result<()>,
) -> Result<(Vec<File>, bool)> {
    let with_agent = agent_present(root, gate)?;
    let mut locks = Vec::new();
    let agent_locks = if with_agent { super::agent::LOCKS } else { &[] };
    for relative in [
        "objects/LOCK",
        "objects/spool/LOCK",
        "ledger/journal.fssj",
        "effects/journal.fssj",
    ]
    .into_iter()
    .chain(agent_locks.iter().copied())
    .chain(with_agent.then_some("agent/sessions/journal.fssj"))
    {
        gate()?;
        let path = root.join(relative);
        let file = open_file(&path, cx)?;
        if relative.ends_with("LOCK") && file.metadata()?.len() != 0 {
            return Err(BackupError::Unsupported("lock_contents"));
        }
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(BackupError::Locked),
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }
        if !same_file(&file.metadata()?, &fs::symlink_metadata(path)?) {
            return Err(BackupError::Changed);
        }
        locks.push(file);
    }
    if agent_present(root, gate)? != with_agent {
        return Err(BackupError::Changed);
    }
    Ok((locks, with_agent))
}

pub(super) struct ReadIo<'a> {
    cx: &'a ReplayCx,
    gate: &'a (dyn Fn() -> Result<()> + Sync),
    calls: AtomicU64,
    bytes: AtomicU64,
    max_calls: u64,
    max_bytes: u64,
    failure: Mutex<Option<BackupError>>,
}
impl fmt::Debug for ReadIo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackupReadIo").finish_non_exhaustive()
    }
}
impl<'a> ReadIo<'a> {
    pub(super) fn cx(&self) -> &ReplayCx {
        self.cx
    }

    pub(super) fn new(
        cx: &'a ReplayCx,
        gate: &'a (dyn Fn() -> Result<()> + Sync),
        limits: BackupLimits,
    ) -> Self {
        // Inventory, semantic rehashing, copied-byte checks and a final inventory share one
        // allowance. Graphs whose repeated closure reads exceed it refuse instead of looping.
        Self {
            cx,
            gate,
            calls: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            max_calls: (limits.max_files as u64)
                .saturating_mul(128)
                .saturating_add(10_000),
            max_bytes: limits
                .max_total_bytes
                .saturating_mul(16)
                .saturating_add((limits.max_manifest_bytes as u64).saturating_mul(4)),
            failure: Mutex::new(None),
        }
    }
    fn fail(&self, error: BackupError) -> io::Error {
        if let Ok(mut failure) = self.failure.lock()
            && failure.is_none()
        {
            *failure = Some(error);
        }
        io::ErrorKind::PermissionDenied.into()
    }
    pub(super) fn check(&self) -> Result<()> {
        if let Some(error) = self
            .failure
            .lock()
            .map_err(|_| BackupError::Corrupt("io_owner"))?
            .as_ref()
        {
            return Err(error.clone());
        }
        (self.gate)()
    }
    pub(super) fn call(&self) -> io::Result<()> {
        self.check().map_err(|error| self.fail(error))?;
        if self
            .calls
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < self.max_calls).then(|| n + 1)
            })
            .is_err()
        {
            return Err(self.fail(BackupError::Limit("io_calls")));
        }
        Ok(())
    }
    fn forbidden<T>(&self) -> io::Result<T> {
        Err(self.fail(BackupError::Corrupt("read_only_io")))
    }
    pub(super) fn read_exact(&self, path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
        let result = self.read_exact_inner(path, max_bytes);
        self.check()?;
        result
    }
    /// A destination owner supplies an already pinned regular-file description. No caller
    /// path, including a /proc spelling, is accepted as a substitute for that description.
    pub(super) fn read_owned(&self, file: &mut File, max_bytes: u64) -> Result<Vec<u8>> {
        self.check()?;
        let before = file.metadata()?;
        regular(&before)?;
        if before.len() > max_bytes {
            return Err(BackupError::Limit("file_bytes"));
        }
        file.rewind()?;
        let result = SpoolIo::read_bounded(self, file, max_bytes.saturating_add(1));
        self.check()?;
        let bytes = result?;
        if bytes.len() as u64 != before.len() || !same_file(&before, &file.metadata()?) {
            return Err(BackupError::Changed);
        }
        Ok(bytes)
    }
    fn read_exact_inner(&self, path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
        self.call()?;
        let mut file = open_file(path, self.cx)?;
        let before = file.metadata()?;
        if before.len() > max_bytes {
            return Err(BackupError::Limit("file_bytes"));
        }
        let result = SpoolIo::read_bounded(self, &mut file, max_bytes.saturating_add(1));
        self.check()?;
        let bytes = result?;
        if bytes.len() as u64 != before.len()
            || !same_file(&before, &file.metadata()?)
            || !same_file(&before, &fs::symlink_metadata(path)?)
        {
            return Err(BackupError::Changed);
        }
        checked_path(path)?;
        Ok(bytes)
    }
}
impl JournalReadIo for ReadIo<'_> {
    fn symlink_metadata(&self, path: &Path) -> io::Result<JournalFileMetadata> {
        let meta = SpoolIo::symlink_metadata(self, path)?;
        Ok(JournalFileMetadata {
            is_file: meta.is_file(),
            is_symlink: meta.file_type().is_symlink(),
            len: meta.len(),
        })
    }
    fn read_bounded(&self, path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
        self.read_exact(path, max_bytes as u64)
            .map_err(|error| self.fail(error))
    }
}
impl SpoolIo for ReadIo<'_> {
    fn create_dir_all(&self, _: &Path) -> io::Result<()> {
        self.forbidden()
    }
    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        SpoolIo::symlink_metadata(self, path)
    }
    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.call()?;
        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Err(self.fail(BackupError::Unsupported("symlink")));
        }
        if meta.is_file() {
            regular(&meta).map_err(|error| self.fail(error))?;
        }
        Ok(meta)
    }
    fn open_lock(&self, _: &Path) -> io::Result<File> {
        self.forbidden()
    }
    fn try_lock(&self, _: &File) -> std::result::Result<(), TryLockError> {
        Err(TryLockError::Error(
            self.fail(BackupError::Corrupt("read_only_io")),
        ))
    }
    fn try_lock_shared(&self, _: &File) -> std::result::Result<(), TryLockError> {
        Err(TryLockError::Error(
            self.fail(BackupError::Corrupt("read_only_io")),
        ))
    }
    fn create_dir(&self, _: &Path) -> io::Result<()> {
        self.forbidden()
    }
    fn read_dir(&self, path: &Path) -> io::Result<ReadDir> {
        self.call()?;
        directory(path).map_err(|error| self.fail(error))?;
        fs::read_dir(path)
    }
    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        if let Err(error) = self.call() {
            return Some(Err(error));
        }
        entries.next()
    }
    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> {
        self.call()?;
        entry.file_type()
    }
    fn create_new(&self, _: &Path) -> io::Result<File> {
        self.forbidden()
    }
    fn write(&self, _: &mut File, _: &[u8]) -> io::Result<usize> {
        self.forbidden()
    }
    fn sync_file(&self, _: &File) -> io::Result<()> {
        self.forbidden()
    }
    fn open_read(&self, path: &Path) -> io::Result<File> {
        self.call()?;
        open_file(path, self.cx).map_err(|error| self.fail(error))
    }
    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        self.call()?;
        let meta = file.metadata()?;
        regular(&meta).map_err(|error| self.fail(error))?;
        let admitted = limit.min(meta.len().saturating_add(1));
        if self
            .bytes
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                n.checked_add(admitted)
                    .filter(|next| *next <= self.max_bytes)
            })
            .is_err()
        {
            return Err(self.fail(BackupError::Limit("read_bytes")));
        }
        let mut bytes = Vec::new();
        let mut left = admitted;
        let mut interruptions = 0;
        let mut buffer = [0_u8; 65_536];
        while left > 0 {
            self.call()?;
            let wanted = left.min(buffer.len() as u64) as usize;
            match file.read(&mut buffer[..wanted]) {
                Ok(0) => break,
                Ok(n) => {
                    bytes.extend_from_slice(&buffer[..n]);
                    left -= n as u64;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted && interruptions < 8 => {
                    interruptions += 1;
                }
                Err(error) => return Err(error),
            }
        }
        self.bytes
            .fetch_sub(admitted - bytes.len() as u64, Ordering::SeqCst);
        if !same_file(&meta, &file.metadata()?) {
            return Err(self.fail(BackupError::Changed));
        }
        self.check().map_err(|error| self.fail(error))?;
        Ok(bytes)
    }
    fn rename(&self, _: &Path, _: &Path) -> io::Result<()> {
        self.forbidden()
    }
    fn remove_file(&self, _: &Path) -> io::Result<()> {
        self.forbidden()
    }
    fn sync_directory(&self, _: &Path) -> io::Result<()> {
        self.forbidden()
    }
    fn hard_link(&self, _: &Path, _: &Path) -> io::Result<()> {
        self.forbidden()
    }
}
