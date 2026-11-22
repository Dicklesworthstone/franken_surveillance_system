#![forbid(unsafe_code)]
//! Failure-first request cancellation tests; the doctor never mutates the inspected root.

use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_ledger::{HostJournalReadIo, JournalFileMetadata, JournalReadIo};
use fss_object::{HostSpoolIo, RecordingSpoolIo, SpoolIo};
use fss_publication::LockTableSource;

use super::{
    CancellableJournal, CancellableLockTable, CancellableSpool, DoctorIo, DoctorLimits,
    ReadAdmission, inspect_deployment_with, inspect_deployment_with_cancellation,
};

type TestResult = Result<(), Box<dyn Error>>;

fn fresh_root(tag: &str) -> io::Result<PathBuf> {
    let root = std::env::temp_dir().join(format!(
        "fss-doctor-cancellation-{tag}-{}",
        std::process::id()
    ));
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(root)
}

struct JournalProbe<'a> {
    metadata: AtomicUsize,
    reads: AtomicUsize,
    stop_after_read: Option<&'a AtomicBool>,
}

impl JournalReadIo for JournalProbe<'_> {
    fn symlink_metadata(&self, path: &Path) -> io::Result<JournalFileMetadata> {
        self.metadata.fetch_add(1, Ordering::SeqCst);
        HostJournalReadIo.symlink_metadata(path)
    }

    fn read_bounded(&self, path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let result = HostJournalReadIo.read_bounded(path, maximum);
        if let Some(stopped) = self.stop_after_read {
            stopped.store(true, Ordering::SeqCst);
        }
        result
    }
}

#[derive(Debug, Default)]
struct LockProbe<'a> {
    calls: AtomicUsize,
    stop_after_read: Option<&'a AtomicBool>,
}

impl LockTableSource for LockProbe<'_> {
    fn read_lock_table(&self, _: usize) -> io::Result<String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(stopped) = self.stop_after_read {
            stopped.store(true, Ordering::SeqCst);
        }
        Ok(String::new())
    }
}

#[test]
fn precancelled_doctor_never_touches_any_capability() {
    let fs = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let files = JournalProbe {
        metadata: AtomicUsize::new(0),
        reads: AtomicUsize::new(0),
        stop_after_read: None,
    };
    let locks = LockProbe::default();
    let report = inspect_deployment_with_cancellation(
        Path::new("this-root-must-not-be-observed"),
        DoctorIo {
            fs: &fs,
            files: &files,
            lock_table: &locks,
        },
        DoctorLimits::default(),
        &|| true,
    );
    assert!(report.is_none());
    assert!(fs.calls().is_empty());
    assert_eq!(files.metadata.load(Ordering::SeqCst), 0);
    assert_eq!(files.reads.load(Ordering::SeqCst), 0);
    assert_eq!(locks.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn cancellation_during_layout_read_cannot_escape_as_a_missing_or_corrupt_report() -> TestResult {
    let root = fresh_root("during-layout")?;
    fs::create_dir_all(&root)?;
    let layout = b"deliberately invalid layout\n";
    fs::write(root.join(crate::DEPLOYMENT_LAYOUT_FILENAME), layout)?;
    let stopped = AtomicBool::new(false);
    let fs = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let files = JournalProbe {
        metadata: AtomicUsize::new(0),
        reads: AtomicUsize::new(0),
        stop_after_read: Some(&stopped),
    };
    let locks = LockProbe::default();
    let report = inspect_deployment_with_cancellation(
        &root,
        DoctorIo {
            fs: &fs,
            files: &files,
            lock_table: &locks,
        },
        DoctorLimits::default(),
        &|| stopped.load(Ordering::SeqCst),
    );
    assert!(report.is_none());
    assert_eq!(files.reads.load(Ordering::SeqCst), 1);
    assert_eq!(locks.calls.load(Ordering::SeqCst), 0);
    assert!(fs.is_read_only());
    assert_eq!(
        std::fs::read(root.join(crate::DEPLOYMENT_LAYOUT_FILENAME))?,
        layout
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn observed_cancellation_stays_closed_across_files_journals_and_lock_table() {
    let stopped = AtomicBool::new(false);
    let cancelled = || stopped.load(Ordering::SeqCst);
    let admission = ReadAdmission {
        cancelled: &cancelled,
        observed: AtomicBool::new(false),
    };
    let fs = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let files = JournalProbe {
        metadata: AtomicUsize::new(0),
        reads: AtomicUsize::new(0),
        stop_after_read: None,
    };
    let locks = LockProbe {
        calls: AtomicUsize::new(0),
        stop_after_read: Some(&stopped),
    };
    let locked = CancellableLockTable {
        inner: &locks,
        admission: &admission,
    };
    assert!(locked.read_lock_table(1024).is_err());
    stopped.store(false, Ordering::SeqCst);
    let spool = CancellableSpool {
        inner: &fs,
        admission: &admission,
    };
    let journal = CancellableJournal {
        inner: &files,
        admission: &admission,
    };
    let path = Path::new("must-not-be-observed-after-stop");
    assert!(spool.symlink_metadata(path).is_err());
    assert!(journal.symlink_metadata(path).is_err());
    assert!(journal.read_bounded(path, 32).is_err());
    assert!(locked.read_lock_table(1024).is_err());
    assert!(fs.calls().is_empty());
    assert_eq!(files.metadata.load(Ordering::SeqCst), 0);
    assert_eq!(files.reads.load(Ordering::SeqCst), 0);
    assert_eq!(locks.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn live_cancellable_doctor_preserves_the_ordinary_report() -> TestResult {
    let root = fresh_root("live-report")?;
    fs::create_dir_all(&root)?;
    fs::write(root.join(crate::DEPLOYMENT_LAYOUT_FILENAME), b"invalid\n")?;
    let ordinary = inspect_deployment_with(&root, DoctorIo::host(), DoctorLimits::default());
    let cancellable = inspect_deployment_with_cancellation(
        &root,
        DoctorIo::host(),
        DoctorLimits::default(),
        &|| false,
    );
    assert_eq!(cancellable, Some(ordinary));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn read_only_admission_cannot_forward_mutations_even_while_live() {
    let fs = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let admission = ReadAdmission {
        cancelled: &|| false,
        observed: AtomicBool::new(false),
    };
    let spool = CancellableSpool {
        inner: &fs,
        admission: &admission,
    };
    let path = Path::new("must-not-be-created");
    assert!(spool.create_dir_all(path).is_err());
    assert!(spool.create_dir(path).is_err());
    assert!(spool.create_new(path).is_err());
    assert!(spool.open_lock(path).is_err());
    assert!(spool.remove_file(path).is_err());
    assert!(spool.rename(path, path).is_err());
    assert!(spool.hard_link(path, path).is_err());
    assert!(spool.sync_directory(path).is_err());
    assert!(fs.calls().is_empty());
}
