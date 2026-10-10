#![forbid(unsafe_code)]
//! Request-owned, read-only capability with a single nonrefillable I/O and byte allowance.

use std::fmt;
use std::fs::{DirEntry, File, FileType, Metadata, ReadDir, TryLockError};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use fss_object::SpoolIo;
use super::{CustodyAuditError, CustodyAuditLimits};

pub(super) struct AuditIo<'a, F> {
    inner: &'a dyn SpoolIo,
    cancelled: &'a F,
    limits: CustodyAuditLimits,
    failure: AtomicU8,
    calls: AtomicU64,
    bytes: AtomicU64,
    peak: AtomicU64,
}
impl<F> fmt::Debug for AuditIo<'_, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadOnlyCustodyAuditIo").finish_non_exhaustive()
    }
}
impl<'a, F: Fn() -> bool + Sync> AuditIo<'a, F> {
    pub(super) fn new(inner: &'a dyn SpoolIo, limits: CustodyAuditLimits, cancelled: &'a F) -> Self {
        Self { inner, cancelled, limits, failure: AtomicU8::new(0), calls: AtomicU64::new(0), bytes: AtomicU64::new(0), peak: AtomicU64::new(0) }
    }
    fn fail(&self, reason: u8) {
        let _ = self.failure.compare_exchange(0, reason, Ordering::SeqCst, Ordering::SeqCst);
    }
    pub(super) fn check(&self) -> Result<(), CustodyAuditError> {
        if (self.cancelled)() { self.fail(1); }
        match self.failure.load(Ordering::SeqCst) {
            0 => Ok(()),
            1 => Err(CustodyAuditError::Cancelled),
            2 => Err(CustodyAuditError::Limit("io_calls")),
            3 => Err(CustodyAuditError::Limit("read_bytes")),
            _ => Err(CustodyAuditError::IoContract),
        }
    }
    fn call(&self) -> io::Result<()> {
        self.check().map_err(|_| io::Error::from(io::ErrorKind::Interrupted))?;
        if self.calls.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            (n < self.limits.max_io_calls).then(|| n + 1)
        }).is_err() {
            self.fail(2);
            return Err(io::ErrorKind::Other.into());
        }
        Ok(())
    }
    fn forbid<T>(&self) -> io::Result<T> {
        self.fail(4);
        Err(io::ErrorKind::PermissionDenied.into())
    }
    pub(super) fn calls(&self) -> u64 { self.calls.load(Ordering::SeqCst) }
    pub(super) fn bytes(&self) -> u64 { self.bytes.load(Ordering::SeqCst) }
    pub(super) fn peak(&self) -> u64 { self.peak.load(Ordering::SeqCst) }
}
impl<F: Fn() -> bool + Sync> SpoolIo for AuditIo<'_, F> {
    fn create_dir_all(&self, _: &Path) -> io::Result<()> { self.forbid() }
    fn metadata(&self, path: &Path) -> io::Result<Metadata> { self.call()?; self.inner.metadata(path) }
    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> { self.call()?; self.inner.symlink_metadata(path) }
    fn open_lock(&self, _: &Path) -> io::Result<File> { self.forbid() }
    fn try_lock(&self, _: &File) -> Result<(), TryLockError> {
        self.fail(4); Err(TryLockError::Error(io::ErrorKind::PermissionDenied.into()))
    }
    fn try_lock_shared(&self, _: &File) -> Result<(), TryLockError> {
        self.fail(4); Err(TryLockError::Error(io::ErrorKind::PermissionDenied.into()))
    }
    fn create_dir(&self, _: &Path) -> io::Result<()> { self.forbid() }
    fn read_dir(&self, path: &Path) -> io::Result<ReadDir> { self.call()?; self.inner.read_dir(path) }
    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        if let Err(error) = self.call() { return Some(Err(error)); }
        self.inner.next_dir_entry(entries)
    }
    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> { self.call()?; self.inner.entry_file_type(entry) }
    fn create_new(&self, _: &Path) -> io::Result<File> { self.forbid() }
    fn write(&self, _: &mut File, _: &[u8]) -> io::Result<usize> { self.forbid() }
    fn sync_file(&self, _: &File) -> io::Result<()> { self.forbid() }
    fn open_read(&self, path: &Path) -> io::Result<File> { self.call()?; self.inner.open_read(path) }
    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        self.call()?;
        // Reserve before the syscall. A failed read may have transferred bytes; its allowance
        // stays charged. Only a successful bounded result can refund the unused reservation.
        match self.bytes.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            n.checked_add(limit).filter(|next| *next <= self.limits.max_read_bytes)
        }) {
            Ok(previous) => { self.peak.fetch_max(previous + limit, Ordering::SeqCst); }
            Err(_) => {
                self.fail(3);
                return Err(io::ErrorKind::Other.into());
            }
        }
        let result = self.inner.read_bounded(file, limit);
        if let Ok(bytes) = &result {
            if bytes.len() as u64 > limit {
                self.fail(4);
                return Err(io::ErrorKind::InvalidData.into());
            }
            self.bytes.fetch_sub(limit - bytes.len() as u64, Ordering::SeqCst);
        }
        self.check().map_err(|_| io::Error::from(io::ErrorKind::Interrupted))?;
        result
    }
    fn rename(&self, _: &Path, _: &Path) -> io::Result<()> { self.forbid() }
    fn remove_file(&self, _: &Path) -> io::Result<()> { self.forbid() }
    fn sync_directory(&self, _: &Path) -> io::Result<()> { self.forbid() }
    fn hard_link(&self, _: &Path, _: &Path) -> io::Result<()> { self.forbid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_object::HostSpoolIo;

    #[test]
    fn mutation_methods_are_refused_before_reaching_the_inner_capability() {
        let cancelled = || false;
        let io = AuditIo::new(&HostSpoolIo, CustodyAuditLimits::default(), &cancelled);
        let path = Path::new("never-created-by-custody-audit");
        assert!(io.create_dir_all(path).is_err());
        assert!(io.create_dir(path).is_err());
        assert!(io.create_new(path).is_err());
        assert!(io.open_lock(path).is_err());
        assert!(io.remove_file(path).is_err());
        assert!(io.rename(path, path).is_err());
        assert!(io.hard_link(path, path).is_err());
        assert!(io.sync_directory(path).is_err());
        assert_eq!(io.check(), Err(CustodyAuditError::IoContract));
        assert_eq!(io.calls(), 0);
    }

    #[test]
    fn failed_read_allowances_cannot_be_refunded_into_an_unbounded_retry_loop()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!("fss-audit-write-only-{}", std::process::id()));
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
        let cancelled = || false;
        let io = AuditIo::new(&HostSpoolIo, CustodyAuditLimits {
            max_read_bytes: 150, ..CustodyAuditLimits::default()
        }, &cancelled);
        let first = io.read_bounded(&mut file, 100);
        let second = io.read_bounded(&mut file, 100);
        drop(file);
        std::fs::remove_file(path)?;
        assert!(first.is_err());
        assert!(second.is_err());
        assert_eq!(io.bytes(), 100);
        assert_eq!(io.peak(), 100);
        assert_eq!(io.check(), Err(CustodyAuditError::Limit("read_bytes")));
        Ok(())
    }
}
