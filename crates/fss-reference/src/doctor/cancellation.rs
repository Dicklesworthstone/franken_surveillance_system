#![forbid(unsafe_code)]
//! Request-owned cancellation at the read-only doctor's capability boundaries.

use std::fmt;
use std::fs::{DirEntry, File, FileType, Metadata, ReadDir, TryLockError};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use fss_ledger::{JournalFileMetadata, JournalReadIo};
use fss_object::SpoolIo;
use fss_publication::LockTableSource;

use super::{DoctorIo, DoctorLimits, DoctorReport, inspect_deployment_with};

/// Inspects a deployment through the host's read-only capabilities until cancellation.
///
/// Cancellation is sticky for this request and returns None, never a healthy, missing, or
/// corrupt deployment report. Each capability call is admitted before it starts and checked
/// again after it completes; an already-running bounded host call cannot be preempted.
#[must_use]
pub fn inspect_deployment_cancellable(
    root: &Path,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Option<DoctorReport> {
    inspect_deployment_with_cancellation(root, DoctorIo::host(), DoctorLimits::default(), cancelled)
}

/// Inspects a deployment through explicit read-only capabilities with request cancellation.
///
/// The ordinary doctor and its report identities are unchanged while the request is live.
/// Once cancellation is observed, no further call reaches any wrapped capability and the
/// partial report is discarded. Mutating and locking methods are refused even while live.
#[must_use]
pub fn inspect_deployment_with_cancellation(
    root: &Path,
    io: DoctorIo<'_>,
    limits: DoctorLimits,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Option<DoctorReport> {
    let admission = ReadAdmission {
        cancelled,
        observed: AtomicBool::new(false),
    };
    admission.check().ok()?;
    let fs = CancellableSpool {
        inner: io.fs,
        admission: &admission,
    };
    let files = CancellableJournal {
        inner: io.files,
        admission: &admission,
    };
    let lock_table = CancellableLockTable {
        inner: io.lock_table,
        admission: &admission,
    };
    let report = inspect_deployment_with(
        root,
        DoctorIo {
            fs: &fs,
            files: &files,
            lock_table: &lock_table,
        },
        limits,
    );
    admission.check().ok()?;
    Some(report)
}

struct ReadAdmission<'a> {
    cancelled: &'a (dyn Fn() -> bool + Sync),
    observed: AtomicBool,
}

impl fmt::Debug for ReadAdmission<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadAdmission")
            .field("cancelled", &self.observed.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl ReadAdmission<'_> {
    fn check(&self) -> io::Result<()> {
        if self.observed.load(Ordering::Acquire) || (self.cancelled)() {
            self.observed.store(true, Ordering::Release);
            Err(io::Error::other("deployment read authority cancelled"))
        } else {
            Ok(())
        }
    }

    fn call<T>(&self, operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        self.check()?;
        let result = operation();
        self.check()?;
        result
    }
}

fn mutation_refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "read-only doctor cannot mutate or acquire locks",
    )
}

#[derive(Debug)]
struct CancellableSpool<'a> {
    inner: &'a dyn SpoolIo,
    admission: &'a ReadAdmission<'a>,
}

impl SpoolIo for CancellableSpool<'_> {
    fn create_dir_all(&self, _: &Path) -> io::Result<()> {
        Err(mutation_refused())
    }

    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.admission.call(|| self.inner.metadata(path))
    }

    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.admission.call(|| self.inner.symlink_metadata(path))
    }

    fn open_lock(&self, _: &Path) -> io::Result<File> {
        Err(mutation_refused())
    }

    fn try_lock(&self, _: &File) -> Result<(), TryLockError> {
        Err(TryLockError::Error(mutation_refused()))
    }

    fn try_lock_shared(&self, _: &File) -> Result<(), TryLockError> {
        Err(TryLockError::Error(mutation_refused()))
    }

    fn unlock(&self, _: &File) -> io::Result<()> {
        Err(mutation_refused())
    }

    fn create_dir(&self, _: &Path) -> io::Result<()> {
        Err(mutation_refused())
    }

    fn read_dir(&self, path: &Path) -> io::Result<ReadDir> {
        self.admission.call(|| self.inner.read_dir(path))
    }

    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        if let Err(error) = self.admission.check() {
            return Some(Err(error));
        }
        let result = self.inner.next_dir_entry(entries);
        match self.admission.check() {
            Ok(()) => result,
            Err(error) => Some(Err(error)),
        }
    }

    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> {
        self.admission.call(|| self.inner.entry_file_type(entry))
    }

    fn create_new(&self, _: &Path) -> io::Result<File> {
        Err(mutation_refused())
    }

    fn write(&self, _: &mut File, _: &[u8]) -> io::Result<usize> {
        Err(mutation_refused())
    }

    fn sync_file(&self, _: &File) -> io::Result<()> {
        Err(mutation_refused())
    }

    fn open_read(&self, path: &Path) -> io::Result<File> {
        self.admission.call(|| self.inner.open_read(path))
    }

    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        self.admission.call(|| self.inner.read_bounded(file, limit))
    }

    fn rename(&self, _: &Path, _: &Path) -> io::Result<()> {
        Err(mutation_refused())
    }

    fn remove_file(&self, _: &Path) -> io::Result<()> {
        Err(mutation_refused())
    }

    fn sync_directory(&self, _: &Path) -> io::Result<()> {
        Err(mutation_refused())
    }

    fn hard_link(&self, _: &Path, _: &Path) -> io::Result<()> {
        Err(mutation_refused())
    }
}

struct CancellableJournal<'a> {
    inner: &'a dyn JournalReadIo,
    admission: &'a ReadAdmission<'a>,
}

impl JournalReadIo for CancellableJournal<'_> {
    fn symlink_metadata(&self, path: &Path) -> io::Result<JournalFileMetadata> {
        self.admission.call(|| self.inner.symlink_metadata(path))
    }

    fn read_bounded(&self, path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
        self.admission
            .call(|| self.inner.read_bounded(path, maximum))
    }
}

#[derive(Debug)]
struct CancellableLockTable<'a> {
    inner: &'a dyn LockTableSource,
    admission: &'a ReadAdmission<'a>,
}

impl LockTableSource for CancellableLockTable<'_> {
    fn read_lock_table(&self, maximum: usize) -> io::Result<String> {
        self.admission.call(|| self.inner.read_lock_table(maximum))
    }
}

#[cfg(test)]
mod tests;
