#![forbid(unsafe_code)]
//! Integration contract tests for local publication non-mutating inspection (DOCTOR0).
//!
//! Asserts:
//! - Differential against [`LocalRootPublisher::open`] across a clean publication, every
//!   [`PublishCutPoint`] (enumerated by exhaustive matches with no wildcard arm), a corrupt root
//!   record, foreign entries and symlinks, a redundant root temp, a legacy spool, an interrupted
//!   holds migration, and missing layouts. Every report field is compared with the open's; the
//!   documented extras (`durability_not_resynced`, `redundant_temps`, `holds_migration_pending`,
//!   `missing_layout`) are asserted exactly.
//! - Linkage differential ([`inspect_linkage`] against [`LedgeredRootPublisher::reconcile`] on a
//!   copy): a pending root left by [`LedgerCutPoint::AfterRootDurable`], an unbacked ledger
//!   claim, and both together.
//! - Limits: the scan bound at N and N+1, and 10k orphaned root temps against a small scan bound,
//!   give the same typed [`LocalPublicationError::EntryLimit`] from inspect and open.
//! - Read-only proof: every inspection runs through [`LockHookSpoolIo`], which records each call
//!   through [`RecordingSpoolIo`] (a mutating or locking call fails the step) and, on every read
//!   call, try-locks `<root>/LOCK`, `<root>/spool/LOCK`, and the ledger journal exclusively; a
//!   lock that is not free fails the step. The `LOCK` files the publisher left stay in place. A
//!   tree digest (path, type, size, mode, mtime and ctime in nanoseconds, content, and the root)
//!   is identical before and after, and no `LOCK` is created where none existed.
//! - Read-only copy: [`DenyWritesSpoolIo`] refuses every mutating call with `EROFS`; inspection
//!   through it equals the host inspection and needs no privilege. The 0o555-directory proof
//!   needs an unprivileged uid; it is `#[ignore]`d by default and fails (never passes) when the
//!   process can still create a file in the tree.
//! - Writer detection through the real host lock table: a live publisher is
//!   `Held { ProcLocks, pid }`, a shared holder is `SharedHolder { ProcLocks, pid }`, and after
//!   release the state is `NotObserved`. Recorded lock-table lines cover hex device numbers,
//!   `FLOCK` `READ` and `WRITE`, ignored `POSIX` and `OFDLCK` entries, and `->` waiter lines. The
//!   opt-in probe race: while the shared probe on `<root>/LOCK` is held, the open fails with
//!   [`LocalPublicationError::Locked`] naming `<root>/LOCK`.
//! - Every step prints one CAPLOG record whose verdict, expected, and observed values are computed
//!   from the checks it made.

use std::error::Error;
use std::fmt;
use std::fs::{self, DirEntry, File, FileType, Metadata, OpenOptions, ReadDir, TryLockError};
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, DigestAlgorithm, EvidenceDelta, Plane, Sha256Hasher,
    TimestampNs, sha256,
};
use fss_ledger::{
    DurableLedgerLimits, DurableReferenceLedger, HostJournalReadIo, IncompleteTailPolicy,
    JournalFileMetadata, JournalReadIo, inspect_durable_with_io,
};
use fss_object::{
    CorruptionKind, HostSpoolIo, MAX_OBJECT_BYTES, ObjectManifest, RecordingSpoolIo,
    SPOOL_HOLDS_DIR, SPOOL_HOLDS_MIGRATION_DIR, SPOOL_LOCK_FILE, SpoolError, SpoolIo, SpoolIoCall,
    SpoolLimits,
};
use fss_publication::{
    BrokenRoot, BrokenRootReason, HostLockTableSource, LOCAL_LOCK_FILE, LOCAL_ROOTS_DIR,
    LOCAL_SPOOL_DIR, LedgerCutPoint, LedgeredRootPublisher, LocalInspection, LocalIoOperation,
    LocalPublicationError, LocalPublicationLimits, LocalPublicationState, LocalRootPublisher,
    LockTableSource, PublishCutPoint, ROOT_REACHABILITY_FAMILY, RootLedgerReconciliation, SlotName,
    StringLockTableSource, UnknownLockReason, VisibleRoot, WriterDetectionOptions, WriterLockBasis,
    WriterState, decode_st_dev, detect_writers, inspect, inspect_linkage, inspect_with_io,
    inspect_with_ledger_journal, inspect_with_options, read_verified, read_verified_with_io,
    root_reachability_object_id,
};

type TestResult = Result<(), Box<dyn Error>>;

const SITE: &str = "site-lineage-1";

// ---------------------------------------------------------------------------------------------
// CAPLOG step accounting: every value logged is the value a check compared.
// ---------------------------------------------------------------------------------------------

/// A value a CAPLOG record carries as JSON.
trait CapValue {
    fn cap_json(&self) -> String;
}

impl CapValue for bool {
    fn cap_json(&self) -> String {
        self.to_string()
    }
}

impl CapValue for usize {
    fn cap_json(&self) -> String {
        self.to_string()
    }
}

impl CapValue for u64 {
    fn cap_json(&self) -> String {
        self.to_string()
    }
}

impl CapValue for &str {
    fn cap_json(&self) -> String {
        json_string(self)
    }
}

impl CapValue for String {
    fn cap_json(&self) -> String {
        json_string(self)
    }
}

impl<T: CapValue> CapValue for Option<T> {
    fn cap_json(&self) -> String {
        match self {
            Some(value) => value.cap_json(),
            None => "null".to_owned(),
        }
    }
}

fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_object(pairs: &[(String, String)]) -> String {
    let body: Vec<String> = pairs
        .iter()
        .map(|(key, value)| format!("{}:{}", json_string(key), value))
        .collect();
    format!("{{{}}}", body.join(","))
}

/// One CAPLOG step. Checks record expected and observed values; the verdict is computed from them.
struct CapStep {
    step: String,
    start: Instant,
    expected: Vec<(String, String)>,
    observed: Vec<(String, String)>,
    mismatches: Vec<String>,
}

impl CapStep {
    fn new(step: impl Into<String>) -> Self {
        Self {
            step: step.into(),
            start: Instant::now(),
            expected: Vec::new(),
            observed: Vec::new(),
            mismatches: Vec::new(),
        }
    }

    /// An exact expectation on a JSON-representable value.
    fn check<T: CapValue + PartialEq + fmt::Debug>(&mut self, key: &str, expected: T, observed: T) {
        if expected != observed {
            self.mismatches.push(format!(
                "{key}: expected {expected:?}, observed {observed:?}"
            ));
        }
        self.expected.push((key.to_owned(), expected.cap_json()));
        self.observed.push((key.to_owned(), observed.cap_json()));
    }

    /// An exact expectation whose two sides are logged by their `Debug` form.
    fn check_debug<T: PartialEq + fmt::Debug + ?Sized>(
        &mut self,
        key: &str,
        expected: &T,
        observed: &T,
    ) {
        let expected_text = format!("{expected:?}");
        let observed_text = format!("{observed:?}");
        if expected != observed {
            self.mismatches.push(format!(
                "{key}: expected {expected_text}, observed {observed_text}"
            ));
        }
        self.expected
            .push((key.to_owned(), json_string(&expected_text)));
        self.observed
            .push((key.to_owned(), json_string(&observed_text)));
    }

    /// An exact equality on a large value; the record logs whether the two sides were equal.
    fn check_equal<T: PartialEq + fmt::Debug + ?Sized>(
        &mut self,
        key: &str,
        expected: &T,
        observed: &T,
    ) {
        let equal = expected == observed;
        if !equal {
            self.mismatches.push(format!(
                "{key}: expected {expected:?}, observed {observed:?}"
            ));
        }
        self.expected.push((key.to_owned(), json_string("equal")));
        self.observed.push((
            key.to_owned(),
            json_string(if equal { "equal" } else { "differs" }),
        ));
    }

    /// Logs a measured value that is not itself an expectation (a bound is checked separately).
    fn observe_only(&mut self, key: &str, observed: usize) {
        self.observed.push((key.to_owned(), observed.to_string()));
    }

    fn emit(&self, verdict: &str, exit: i32) {
        println!(
            "CAPLOG {{\"step\":{},\"verdict\":{},\"exit\":{},\"duration_ms\":{},\"expected\":{},\"observed\":{}}}",
            json_string(&self.step),
            json_string(verdict),
            exit,
            self.start.elapsed().as_millis(),
            json_object(&self.expected),
            json_object(&self.observed),
        );
    }

    /// Emits the step; the verdict is `pass` only when every check matched.
    fn finish(self) -> TestResult {
        if self.mismatches.is_empty() {
            self.emit("pass", 0);
            Ok(())
        } else {
            self.emit("fail", 1);
            Err(format!("{}: {}", self.step, self.mismatches.join("; ")).into())
        }
    }

    /// Emits a skip carrying the condition the test observed, then fails: a skip is never a pass.
    fn skip(mut self, reason: String) -> TestResult {
        self.observed
            .push(("skip_reason".to_owned(), json_string(&reason)));
        self.emit("skip", 1);
        Err(format!("{}: skipped, never a pass: {reason}", self.step).into())
    }
}

// ---------------------------------------------------------------------------------------------
// Lock probes and inode stamps.
// ---------------------------------------------------------------------------------------------

/// Outcome of an exclusive try-lock taken on a fresh open file description.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LockProbe {
    /// The exclusive lock was free; it was taken and released at once.
    Acquired,
    /// Someone holds a conflicting lock.
    WouldBlock,
    /// No entry exists at the path.
    NoFile,
    /// The entry is not a regular file; nothing to lock.
    NotRegular,
    /// Opening or locking failed.
    Failed(io::ErrorKind),
}

impl LockProbe {
    const fn is_violation(self) -> bool {
        match self {
            Self::WouldBlock | Self::Failed(_) => true,
            Self::Acquired | Self::NoFile | Self::NotRegular => false,
        }
    }
}

fn probe_exclusive(path: &Path) -> LockProbe {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return LockProbe::NoFile,
        Err(error) => return LockProbe::Failed(error.kind()),
        Ok(meta) if !meta.is_file() => return LockProbe::NotRegular,
        Ok(_) => {}
    }
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) => return LockProbe::Failed(error.kind()),
    };
    match file.try_lock() {
        Ok(()) => LockProbe::Acquired,
        Err(TryLockError::WouldBlock) => LockProbe::WouldBlock,
        Err(TryLockError::Error(error)) => LockProbe::Failed(error.kind()),
    }
}

/// Inode stamp of a path. A write, truncate, chmod, or rename by any uid changes its ctime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileStamp {
    dev: u64,
    ino: u64,
    len: u64,
    mode: u32,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

fn stamp(path: &Path) -> Option<FileStamp> {
    fs::symlink_metadata(path).ok().map(|meta| FileStamp {
        dev: meta.dev(),
        ino: meta.ino(),
        len: meta.len(),
        mode: meta.mode(),
        mtime: (meta.mtime(), meta.mtime_nsec()),
        ctime: (meta.ctime(), meta.ctime_nsec()),
    })
}

// ---------------------------------------------------------------------------------------------
// Recording journal read capability (for the ledger side of the linkage).
// ---------------------------------------------------------------------------------------------

/// One journal read-capability call, as issued.
#[derive(Clone, Debug, Eq, PartialEq)]
enum JournalCall {
    SymlinkMetadata {
        path: PathBuf,
    },
    ReadBounded {
        path: PathBuf,
        max_bytes: usize,
        returned: Option<usize>,
    },
}

/// A recorded call with the lock probes and inode stamps taken around it.
#[derive(Clone, Debug)]
struct JournalObservation {
    call: JournalCall,
    probe_before: LockProbe,
    probe_after: LockProbe,
    stamp_before: Option<FileStamp>,
    stamp_after: Option<FileStamp>,
}

impl JournalObservation {
    fn violation(&self) -> Option<String> {
        if self.probe_before.is_violation() || self.probe_after.is_violation() {
            return Some(format!(
                "{:?}: journal lock not free around the call ({:?} before, {:?} after)",
                self.call, self.probe_before, self.probe_after
            ));
        }
        if self.stamp_before != self.stamp_after {
            return Some(format!(
                "{:?}: journal inode changed across the call ({:?} -> {:?})",
                self.call, self.stamp_before, self.stamp_after
            ));
        }
        None
    }
}

/// Recording [`JournalReadIo`]: records every call and, around each one, try-locks the journal
/// exclusively on a fresh open file description and stamps its inode.
struct RecordingJournalReadIo {
    observations: Mutex<Vec<JournalObservation>>,
}

impl RecordingJournalReadIo {
    fn new() -> Self {
        Self {
            observations: Mutex::new(Vec::new()),
        }
    }

    fn observations(&self) -> Vec<JournalObservation> {
        self.observations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn calls(&self) -> Vec<JournalCall> {
        self.observations()
            .into_iter()
            .map(|observation| observation.call)
            .collect()
    }

    fn mutating_calls(&self) -> Vec<String> {
        self.observations()
            .iter()
            .filter_map(JournalObservation::violation)
            .collect()
    }

    fn observe<R>(
        &self,
        path: &Path,
        run: impl FnOnce() -> io::Result<R>,
        describe: impl FnOnce(&io::Result<R>) -> JournalCall,
    ) -> io::Result<R> {
        let probe_before = probe_exclusive(path);
        let stamp_before = stamp(path);
        let result = run();
        let stamp_after = stamp(path);
        let probe_after = probe_exclusive(path);
        let call = describe(&result);
        self.observations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(JournalObservation {
                call,
                probe_before,
                probe_after,
                stamp_before,
                stamp_after,
            });
        result
    }
}

impl JournalReadIo for RecordingJournalReadIo {
    fn symlink_metadata(&self, path: &Path) -> io::Result<JournalFileMetadata> {
        self.observe(
            path,
            || HostJournalReadIo.symlink_metadata(path),
            |_| JournalCall::SymlinkMetadata {
                path: path.to_path_buf(),
            },
        )
    }

    fn read_bounded(&self, path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
        self.observe(
            path,
            || HostJournalReadIo.read_bounded(path, max_bytes),
            |result| JournalCall::ReadBounded {
                path: path.to_path_buf(),
                max_bytes,
                returned: result.as_ref().ok().map(Vec::len),
            },
        )
    }
}

// ---------------------------------------------------------------------------------------------
// Spool capabilities.
// ---------------------------------------------------------------------------------------------

/// Records every call through [`RecordingSpoolIo`] and, on every read call, try-locks each named
/// lock file exclusively on a fresh open file description while the inspection is reading. A
/// lock held anywhere during the inspection shows up as a `WouldBlock` probe.
#[derive(Debug)]
struct LockHookSpoolIo {
    inner: RecordingSpoolIo,
    lock_paths: Vec<PathBuf>,
    probes: Mutex<Vec<(SpoolIoCall, PathBuf, LockProbe)>>,
}

impl LockHookSpoolIo {
    fn new(lock_paths: Vec<PathBuf>) -> Self {
        Self {
            inner: RecordingSpoolIo::new(Arc::new(HostSpoolIo)),
            lock_paths,
            probes: Mutex::new(Vec::new()),
        }
    }

    fn probe(&self, call: SpoolIoCall) {
        let outcomes: Vec<(SpoolIoCall, PathBuf, LockProbe)> = self
            .lock_paths
            .iter()
            .map(|path| (call, path.clone(), probe_exclusive(path)))
            .collect();
        self.probes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(outcomes);
    }

    fn probes(&self) -> Vec<(SpoolIoCall, PathBuf, LockProbe)> {
        self.probes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn lock_violations(&self) -> Vec<String> {
        self.probes()
            .into_iter()
            .filter(|(_, _, probe)| probe.is_violation())
            .map(|(call, path, probe)| format!("{call}: {} {probe:?}", path.display()))
            .collect()
    }

    fn acquired_on(&self, path: &Path) -> usize {
        self.probes()
            .iter()
            .filter(|(_, probed, probe)| probed == path && *probe == LockProbe::Acquired)
            .count()
    }
}

impl SpoolIo for LockHookSpoolIo {
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        self.inner.create_dir_all(path)
    }
    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.probe(SpoolIoCall::Metadata);
        self.inner.metadata(path)
    }
    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.probe(SpoolIoCall::SymlinkMetadata);
        self.inner.symlink_metadata(path)
    }
    fn open_lock(&self, path: &Path) -> io::Result<File> {
        self.inner.open_lock(path)
    }
    fn try_lock(&self, file: &File) -> Result<(), TryLockError> {
        self.inner.try_lock(file)
    }
    fn try_lock_shared(&self, file: &File) -> Result<(), TryLockError> {
        self.inner.try_lock_shared(file)
    }
    fn create_dir(&self, path: &Path) -> io::Result<()> {
        self.inner.create_dir(path)
    }
    fn read_dir(&self, path: &Path) -> io::Result<ReadDir> {
        self.probe(SpoolIoCall::ReadDir);
        self.inner.read_dir(path)
    }
    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        self.probe(SpoolIoCall::NextDirEntry);
        self.inner.next_dir_entry(entries)
    }
    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> {
        self.probe(SpoolIoCall::EntryFileType);
        self.inner.entry_file_type(entry)
    }
    fn create_new(&self, path: &Path) -> io::Result<File> {
        self.inner.create_new(path)
    }
    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(file, bytes)
    }
    fn sync_file(&self, file: &File) -> io::Result<()> {
        self.inner.sync_file(file)
    }
    fn open_read(&self, path: &Path) -> io::Result<File> {
        self.probe(SpoolIoCall::OpenRead);
        self.inner.open_read(path)
    }
    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        self.probe(SpoolIoCall::Read);
        self.inner.read_bounded(file, limit)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.inner.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.inner.remove_file(path)
    }
    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        self.inner.sync_directory(path)
    }
    fn hard_link(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.inner.hard_link(from, to)
    }
}

/// A read-only filesystem without privilege: every mutating or locking call fails with `EROFS`
/// and is recorded; reads go to the host.
#[derive(Debug, Default)]
struct DenyWritesSpoolIo {
    denied: Mutex<Vec<SpoolIoCall>>,
}

impl DenyWritesSpoolIo {
    fn deny(&self, call: SpoolIoCall) -> io::Error {
        self.denied
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(call);
        io::Error::from(io::ErrorKind::ReadOnlyFilesystem)
    }

    fn denied(&self) -> Vec<SpoolIoCall> {
        self.denied
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl SpoolIo for DenyWritesSpoolIo {
    fn create_dir_all(&self, _path: &Path) -> io::Result<()> {
        Err(self.deny(SpoolIoCall::CreateDirAll))
    }
    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        HostSpoolIo.metadata(path)
    }
    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        HostSpoolIo.symlink_metadata(path)
    }
    fn open_lock(&self, _path: &Path) -> io::Result<File> {
        Err(self.deny(SpoolIoCall::OpenLock))
    }
    fn try_lock(&self, _file: &File) -> Result<(), TryLockError> {
        Err(TryLockError::Error(self.deny(SpoolIoCall::TryLock)))
    }
    fn try_lock_shared(&self, _file: &File) -> Result<(), TryLockError> {
        Err(TryLockError::Error(self.deny(SpoolIoCall::TryLockShared)))
    }
    fn create_dir(&self, _path: &Path) -> io::Result<()> {
        Err(self.deny(SpoolIoCall::CreateDir))
    }
    fn read_dir(&self, path: &Path) -> io::Result<ReadDir> {
        HostSpoolIo.read_dir(path)
    }
    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        HostSpoolIo.next_dir_entry(entries)
    }
    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> {
        HostSpoolIo.entry_file_type(entry)
    }
    fn create_new(&self, _path: &Path) -> io::Result<File> {
        Err(self.deny(SpoolIoCall::CreateNew))
    }
    fn write(&self, _file: &mut File, _bytes: &[u8]) -> io::Result<usize> {
        Err(self.deny(SpoolIoCall::Write))
    }
    fn sync_file(&self, _file: &File) -> io::Result<()> {
        Err(self.deny(SpoolIoCall::SyncFile))
    }
    fn open_read(&self, path: &Path) -> io::Result<File> {
        HostSpoolIo.open_read(path)
    }
    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        HostSpoolIo.read_bounded(file, limit)
    }
    fn rename(&self, _from: &Path, _to: &Path) -> io::Result<()> {
        Err(self.deny(SpoolIoCall::Rename))
    }
    fn remove_file(&self, _path: &Path) -> io::Result<()> {
        Err(self.deny(SpoolIoCall::RemoveFile))
    }
    fn sync_directory(&self, _path: &Path) -> io::Result<()> {
        Err(self.deny(SpoolIoCall::SyncDirectory))
    }
    fn hard_link(&self, _from: &Path, _to: &Path) -> io::Result<()> {
        Err(self.deny(SpoolIoCall::HardLink))
    }
}

/// Host capability whose shared try-lock is the probe-race hook: while the probe's shared lock on
/// `<root>/LOCK` is held, it runs [`LocalRootPublisher::open`] and keeps the outcome.
#[derive(Debug)]
struct ProbeRaceSpoolIo {
    root: PathBuf,
    limits: LocalPublicationLimits,
    open_while_probed: Mutex<Vec<Result<(), LocalPublicationError>>>,
}

impl ProbeRaceSpoolIo {
    fn outcomes(&self) -> Vec<Result<(), LocalPublicationError>> {
        self.open_while_probed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl SpoolIo for ProbeRaceSpoolIo {
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        HostSpoolIo.create_dir_all(path)
    }
    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        HostSpoolIo.metadata(path)
    }
    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        HostSpoolIo.symlink_metadata(path)
    }
    fn open_lock(&self, path: &Path) -> io::Result<File> {
        HostSpoolIo.open_lock(path)
    }
    fn try_lock(&self, file: &File) -> Result<(), TryLockError> {
        HostSpoolIo.try_lock(file)
    }
    fn try_lock_shared(&self, file: &File) -> Result<(), TryLockError> {
        HostSpoolIo.try_lock_shared(file)?;
        let outcome = LocalRootPublisher::open(&self.root, self.limits).map(|_| ());
        self.open_while_probed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(outcome);
        Ok(())
    }
    fn create_dir(&self, path: &Path) -> io::Result<()> {
        HostSpoolIo.create_dir(path)
    }
    fn read_dir(&self, path: &Path) -> io::Result<ReadDir> {
        HostSpoolIo.read_dir(path)
    }
    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        HostSpoolIo.next_dir_entry(entries)
    }
    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> {
        HostSpoolIo.entry_file_type(entry)
    }
    fn create_new(&self, path: &Path) -> io::Result<File> {
        HostSpoolIo.create_new(path)
    }
    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        HostSpoolIo.write(file, bytes)
    }
    fn sync_file(&self, file: &File) -> io::Result<()> {
        HostSpoolIo.sync_file(file)
    }
    fn open_read(&self, path: &Path) -> io::Result<File> {
        HostSpoolIo.open_read(path)
    }
    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        HostSpoolIo.read_bounded(file, limit)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        HostSpoolIo.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        HostSpoolIo.remove_file(path)
    }
    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        HostSpoolIo.sync_directory(path)
    }
    fn hard_link(&self, from: &Path, to: &Path) -> io::Result<()> {
        HostSpoolIo.hard_link(from, to)
    }
}

/// Host capability whose second `symlink_metadata` of any path reports it gone: a lock file
/// replaced between the stat and the re-stat of the lock-table check.
#[derive(Debug)]
struct ReplacingSpoolIo {
    re_stat_count: AtomicUsize,
}

impl SpoolIo for ReplacingSpoolIo {
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        HostSpoolIo.create_dir_all(path)
    }
    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        HostSpoolIo.metadata(path)
    }
    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        if self.re_stat_count.fetch_add(1, Ordering::SeqCst) == 0 {
            HostSpoolIo.symlink_metadata(path)
        } else {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }
    fn open_lock(&self, path: &Path) -> io::Result<File> {
        HostSpoolIo.open_lock(path)
    }
    fn try_lock(&self, file: &File) -> Result<(), TryLockError> {
        HostSpoolIo.try_lock(file)
    }
    fn try_lock_shared(&self, file: &File) -> Result<(), TryLockError> {
        HostSpoolIo.try_lock_shared(file)
    }
    fn create_dir(&self, path: &Path) -> io::Result<()> {
        HostSpoolIo.create_dir(path)
    }
    fn read_dir(&self, path: &Path) -> io::Result<ReadDir> {
        HostSpoolIo.read_dir(path)
    }
    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        HostSpoolIo.next_dir_entry(entries)
    }
    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> {
        HostSpoolIo.entry_file_type(entry)
    }
    fn create_new(&self, path: &Path) -> io::Result<File> {
        HostSpoolIo.create_new(path)
    }
    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        HostSpoolIo.write(file, bytes)
    }
    fn sync_file(&self, file: &File) -> io::Result<()> {
        HostSpoolIo.sync_file(file)
    }
    fn open_read(&self, path: &Path) -> io::Result<File> {
        HostSpoolIo.open_read(path)
    }
    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        HostSpoolIo.read_bounded(file, limit)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        HostSpoolIo.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        HostSpoolIo.remove_file(path)
    }
    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        HostSpoolIo.sync_directory(path)
    }
    fn hard_link(&self, from: &Path, to: &Path) -> io::Result<()> {
        HostSpoolIo.hard_link(from, to)
    }
}

#[derive(Debug)]
struct FailingLockTableSource(io::ErrorKind);

impl LockTableSource for FailingLockTableSource {
    fn read_lock_table(&self, _max_bytes: usize) -> io::Result<String> {
        Err(io::Error::from(self.0))
    }
}

// ---------------------------------------------------------------------------------------------
// Enumerations: exhaustive matches, no wildcard arm.
// ---------------------------------------------------------------------------------------------

/// Successor of each [`PublishCutPoint`] in publication order; a new cut point does not compile
/// until it is placed here.
const fn next_cut_point(point: PublishCutPoint) -> Option<PublishCutPoint> {
    match point {
        PublishCutPoint::AfterChildrenVerified => Some(PublishCutPoint::AfterManifestBody),
        PublishCutPoint::AfterManifestBody => Some(PublishCutPoint::AfterRootTempWrite),
        PublishCutPoint::AfterRootTempWrite => Some(PublishCutPoint::AfterRootRename),
        PublishCutPoint::AfterRootRename => None,
    }
}

const fn cut_point_ordinal(point: PublishCutPoint) -> usize {
    match point {
        PublishCutPoint::AfterChildrenVerified => 0,
        PublishCutPoint::AfterManifestBody => 1,
        PublishCutPoint::AfterRootTempWrite => 2,
        PublishCutPoint::AfterRootRename => 3,
    }
}

const CUT_POINT_COUNT: usize = cut_point_ordinal(PublishCutPoint::AfterRootRename) + 1;

/// Every [`PublishCutPoint`], derived by walking [`next_cut_point`] from the first one.
const ALL_PUBLISH_CUT_POINTS: [PublishCutPoint; CUT_POINT_COUNT] = {
    let mut points = [PublishCutPoint::AfterChildrenVerified; CUT_POINT_COUNT];
    let mut current = PublishCutPoint::AfterChildrenVerified;
    let mut index = 1;
    while index < CUT_POINT_COUNT {
        if let Some(next) = next_cut_point(current) {
            points[index] = next;
            current = next;
        }
        index += 1;
    }
    points
};

/// Successor of each [`LedgerCutPoint`]; exhaustive, so a new ledger cut point must be placed.
const fn next_ledger_cut_point(point: LedgerCutPoint) -> Option<LedgerCutPoint> {
    match point {
        LedgerCutPoint::AfterRootDurable => None,
    }
}

// ---------------------------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------------------------

fn fresh_root(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("local_inspect_contract")
        .join(test_name);
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn limits(max_roots: usize, max_scan: usize) -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        max_roots,
        16,
        max_roots,
        max_scan,
        SpoolLimits::new(64, 1 << 20, 4096, 64),
    )
}

fn slot(name: &str) -> Result<SlotName, Box<dyn Error>> {
    Ok(SlotName::parse(name)?)
}

fn publish(
    publisher: &mut LocalRootPublisher,
    slot_name: &str,
    payload: &[u8],
) -> Result<ContentDigest, Box<dyn Error>> {
    let child = publisher.stage_object(payload)?;
    let manifest = ObjectManifest::new("clip", [child], None)?;
    publisher.publish(&slot(slot_name)?, &manifest)?;
    Ok(manifest.root())
}

fn copy_dir_filtered(src: &Path, dst: &Path, skip_lock: bool) -> TestResult {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        if skip_lock && entry.file_name() == LOCAL_LOCK_FILE {
            continue;
        }
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            copy_dir_filtered(&src_path, &dst_path, skip_lock)?;
        } else if ft.is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(&src_path)?, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn copy_dir_all(src: &Path, dst: &Path) -> TestResult {
    copy_dir_filtered(src, dst, false)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct TreeEntry {
    rel_path: String,
    kind: u8,
    size: u64,
    mode: u32,
    mtime: (i64, i64),
    ctime: (i64, i64),
    content: [u8; 32],
}

fn tree_entry(base: &Path, path: &Path) -> Result<TreeEntry, Box<dyn Error>> {
    let meta = fs::symlink_metadata(path)?;
    let rel = path.strip_prefix(base)?.to_string_lossy().to_string();
    let file_type = meta.file_type();
    let (kind, content) = if file_type.is_dir() {
        (1, [0_u8; 32])
    } else if file_type.is_symlink() {
        (2, sha256(fs::read_link(path)?.to_string_lossy().as_bytes()))
    } else {
        (0, sha256(&fs::read(path)?))
    };
    Ok(TreeEntry {
        rel_path: if rel.is_empty() { ".".to_owned() } else { rel },
        kind,
        size: meta.len(),
        mode: meta.mode(),
        mtime: (meta.mtime(), meta.mtime_nsec()),
        ctime: (meta.ctime(), meta.ctime_nsec()),
        content,
    })
}

fn collect_tree(base: &Path, dir: &Path, entries: &mut Vec<TreeEntry>) -> TestResult {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let tree = tree_entry(base, &path)?;
        let is_dir = tree.kind == 1;
        entries.push(tree);
        if is_dir {
            collect_tree(base, &path, entries)?;
        }
    }
    Ok(())
}

/// Digest over every entry under `root` and `root` itself (`absent` when `root` does not exist):
/// a created-and-removed temp file still changes the parent directory's mtime and ctime.
fn tree_digest(root: &Path) -> Result<String, Box<dyn Error>> {
    if !root.exists() {
        return Ok("absent".to_owned());
    }
    let mut entries = vec![tree_entry(root, root)?];
    collect_tree(root, root, &mut entries)?;
    entries.sort();
    let mut hasher = Sha256Hasher::new();
    for entry in &entries {
        hasher.update(entry.rel_path.as_bytes());
        hasher.update(&[0, entry.kind]);
        hasher.update(&entry.size.to_be_bytes());
        hasher.update(&entry.mode.to_be_bytes());
        hasher.update(&entry.mtime.0.to_be_bytes());
        hasher.update(&entry.mtime.1.to_be_bytes());
        hasher.update(&entry.ctime.0.to_be_bytes());
        hasher.update(&entry.ctime.1.to_be_bytes());
        hasher.update(&entry.content);
    }
    Ok(ContentDigest::new(DigestAlgorithm::Sha256, hasher.finalize()?).to_text())
}

/// Sets every directory under and including `root` to 0o555 and restores the modes on drop.
struct ReadOnlyTreeGuard {
    paths: Vec<(PathBuf, u32)>,
}

impl ReadOnlyTreeGuard {
    fn make_read_only(root: &Path) -> io::Result<Self> {
        let mut guard = Self { paths: Vec::new() };
        guard.collect_and_set(root)?;
        Ok(guard)
    }

    fn collect_and_set(&mut self, dir: &Path) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if fs::symlink_metadata(&path)?.is_dir() {
                self.collect_and_set(&path)?;
            }
        }
        self.paths
            .push((dir.to_path_buf(), fs::symlink_metadata(dir)?.mode()));
        fs::set_permissions(dir, fs::Permissions::from_mode(0o555))
    }
}

impl Drop for ReadOnlyTreeGuard {
    fn drop(&mut self) {
        for (path, mode) in self.paths.iter().rev() {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(*mode));
        }
    }
}

fn lock_paths(root: &Path, journal: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = vec![
        root.join(LOCAL_LOCK_FILE),
        root.join(LOCAL_SPOOL_DIR).join(SPOOL_LOCK_FILE),
    ];
    paths.extend(journal.map(Path::to_path_buf));
    paths
}

/// Inspects through [`LockHookSpoolIo`] with the default (lock-table) writer check and checks the
/// read-only proof: no mutating call, every `LOCK` (and the journal) exclusively lockable during
/// every read, and an unchanged tree digest.
fn inspect_hooked(
    step: &mut CapStep,
    key: &str,
    root: &Path,
    journal: Option<&Path>,
    limits: LocalPublicationLimits,
) -> Result<Result<LocalInspection, LocalPublicationError>, Box<dyn Error>> {
    let io = LockHookSpoolIo::new(lock_paths(root, journal));
    let digest_before = tree_digest(root)?;
    let result = inspect_with_ledger_journal(
        &io,
        root,
        journal,
        limits,
        None,
        WriterDetectionOptions::default(),
    );
    step.check(
        &format!("{key}_tree_digest"),
        digest_before,
        tree_digest(root)?,
    );
    step.check_debug(
        &format!("{key}_mutating_calls"),
        &Vec::<SpoolIoCall>::new(),
        &io.inner.mutating_calls(),
    );
    step.check_debug(
        &format!("{key}_lock_violations"),
        &Vec::<String>::new(),
        &io.lock_violations(),
    );
    Ok(result)
}

type RootIdentity = (SlotName, ContentDigest, ContentDigest, usize);

fn root_identities(roots: &[VisibleRoot]) -> Vec<RootIdentity> {
    roots
        .iter()
        .map(|root| {
            (
                root.slot.clone(),
                root.root,
                root.record_digest,
                root.child_count,
            )
        })
        .collect()
}

fn root_states(roots: &[VisibleRoot]) -> Vec<LocalPublicationState> {
    roots.iter().map(|root| root.state).collect()
}

/// Compares every field of the inspection report with the open's recovery report. The only
/// documented difference is the root state: the open fsyncs (`Durable`), inspection never does
/// (`Visible`, with `durability_not_resynced`).
fn check_matches_open(
    step: &mut CapStep,
    inspection: &LocalInspection,
    opened: &LocalRootPublisher,
) {
    let open_report = opened.recovery_report();
    let report = &inspection.report;
    step.check_equal("spool_vs_open", &open_report.spool, &report.spool);
    step.check_equal(
        "roots_vs_open",
        &root_identities(&open_report.roots),
        &root_identities(&report.roots),
    );
    step.check_debug(
        "open_root_states",
        &vec![LocalPublicationState::Durable; open_report.roots.len()],
        &root_states(&open_report.roots),
    );
    step.check_debug(
        "inspect_root_states",
        &vec![LocalPublicationState::Visible; report.roots.len()],
        &root_states(&report.roots),
    );
    step.check_equal(
        "broken_roots_vs_open",
        &open_report.broken_roots,
        &report.broken_roots,
    );
    step.check_equal(
        "orphaned_temps_vs_open",
        &open_report.orphaned_temps,
        &report.orphaned_temps,
    );
    step.check_equal(
        "unreferenced_objects_vs_open",
        &open_report.unreferenced_objects,
        &report.unreferenced_objects,
    );
    step.check_equal(
        "tombstones_vs_open",
        &open_report.tombstones,
        &report.tombstones,
    );
    step.check_equal("foreign_vs_open", &open_report.foreign, &report.foreign);
    step.check(
        "durability_not_resynced",
        !report.roots.is_empty(),
        inspection.durability_not_resynced,
    );
}

fn check_extras(
    step: &mut CapStep,
    inspection: &LocalInspection,
    holds_migration_pending: bool,
    missing_layout: bool,
) {
    step.check(
        "holds_migration_pending",
        holds_migration_pending,
        inspection.holds_migration_pending,
    );
    step.check("missing_layout", missing_layout, inspection.missing_layout);
    step.check("spool_over_capacity", false, inspection.spool_over_capacity);
    step.check_debug(
        "writer_state",
        &WriterState::not_observed(),
        &inspection.writer_state,
    );
}

// ---------------------------------------------------------------------------------------------
// Differential corpora.
// ---------------------------------------------------------------------------------------------

#[test]
fn test_local_cut_point_enumeration() -> TestResult {
    let mut step = CapStep::new("local_cut_point_enumeration");
    let ordinals: Vec<usize> = ALL_PUBLISH_CUT_POINTS
        .iter()
        .map(|point| cut_point_ordinal(*point))
        .collect();
    step.check_debug(
        "ordinals_in_order",
        &(0..CUT_POINT_COUNT).collect::<Vec<_>>(),
        &ordinals,
    );
    step.check_debug(
        "last_cut_point_has_no_successor",
        &None,
        &ALL_PUBLISH_CUT_POINTS
            .last()
            .and_then(|point| next_cut_point(*point)),
    );
    step.check_debug(
        "ledger_cut_points",
        &None,
        &next_ledger_cut_point(LedgerCutPoint::AfterRootDurable),
    );
    step.finish()
}

#[test]
fn test_local_differential_clean() -> TestResult {
    let mut step = CapStep::new("local_differential_clean");
    let root = fresh_root("differential_clean")?;
    let copy = fresh_root("differential_clean_copy")?;
    let l = limits(8, 32);
    {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        publish(&mut publisher, "slot-a", b"payload-a")?;
        publish(&mut publisher, "slot-b", b"payload-b")?;
    }
    copy_dir_all(&root, &copy)?;

    let inspection = inspect_hooked(&mut step, "inspect", &root, None, l)??;
    let opened = LocalRootPublisher::open(&copy, l)?;
    check_matches_open(&mut step, &inspection, &opened);
    check_extras(&mut step, &inspection, false, false);
    step.check("roots_count", 2_usize, inspection.report.roots.len());
    step.check_debug(
        "redundant_temps",
        &Vec::<PathBuf>::new(),
        &inspection.redundant_temps,
    );
    step.check("broken_slots", 0_usize, inspection.broken_slots.len());
    step.check("root_closures", 2_usize, inspection.root_closures.len());
    step.check("possibly_stale", false, inspection.possibly_stale);
    step.check("possibly_in_flight", false, inspection.possibly_in_flight);
    step.check("is_clean", true, inspection.is_clean());
    step.finish()
}

#[test]
fn test_local_differential_publish_cut_points() -> TestResult {
    let mut failures = Vec::new();
    for cut_point in ALL_PUBLISH_CUT_POINTS {
        if let Err(error) = cut_point_corpus(cut_point) {
            failures.push(error.to_string());
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n").into())
    }
}

fn cut_point_corpus(cut_point: PublishCutPoint) -> TestResult {
    let mut step = CapStep::new(format!("local_cut_{cut_point}"));
    let root = fresh_root(&format!("cut_{cut_point}"))?;
    let copy = fresh_root(&format!("cut_{cut_point}_copy"))?;
    let l = limits(8, 32);
    {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        let child = publisher.stage_object(b"leaf-bytes")?;
        let manifest = ObjectManifest::new("clip", [child], None)?;
        publisher.inject_crash_at(cut_point);
        let outcome = publisher.publish(&slot("cut-slot")?, &manifest).map(|_| ());
        step.check_debug(
            "publish",
            &Err(LocalPublicationError::InjectedCrash { point: cut_point }),
            &outcome,
        );
    }
    copy_dir_all(&root, &copy)?;

    let inspection = inspect_hooked(&mut step, "inspect", &root, None, l)??;
    let opened = LocalRootPublisher::open(&copy, l)?;
    check_matches_open(&mut step, &inspection, &opened);
    check_extras(&mut step, &inspection, false, false);
    let (roots, orphaned_temps) = match cut_point {
        PublishCutPoint::AfterChildrenVerified | PublishCutPoint::AfterManifestBody => {
            (0_usize, 0_usize)
        }
        PublishCutPoint::AfterRootTempWrite => (0, 1),
        PublishCutPoint::AfterRootRename => (1, 0),
    };
    step.check("roots_count", roots, inspection.report.roots.len());
    step.check(
        "orphaned_temps_count",
        orphaned_temps,
        inspection.report.orphaned_temps.len(),
    );
    step.check_debug(
        "redundant_temps",
        &Vec::<PathBuf>::new(),
        &inspection.redundant_temps,
    );
    step.finish()
}

#[test]
fn test_local_differential_corrupt_root_record() -> TestResult {
    let mut step = CapStep::new("local_differential_corrupt_root_record");
    let root = fresh_root("differential_corrupt_root_record")?;
    let copy = fresh_root("differential_corrupt_root_record_copy")?;
    let l = limits(8, 32);
    {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        publish(&mut publisher, "broken-slot", b"payload")?;
    }
    fs::write(
        root.join(LOCAL_ROOTS_DIR).join("broken-slot.root"),
        b"corrupted non-json bytes",
    )?;
    copy_dir_all(&root, &copy)?;

    let inspection = inspect_hooked(&mut step, "inspect", &root, None, l)??;
    let opened = LocalRootPublisher::open(&copy, l)?;
    check_matches_open(&mut step, &inspection, &opened);
    let broken = slot("broken-slot")?;
    step.check(
        "inspect_broken_slot",
        true,
        inspection.is_broken_slot(&broken),
    );
    step.check("open_broken_slot", true, opened.is_broken_slot(&broken));
    step.check(
        "broken_roots_count",
        1_usize,
        inspection.report.broken_roots.len(),
    );
    step.check("roots_count", 0_usize, inspection.report.roots.len());
    step.finish()
}

#[test]
fn test_local_differential_foreign_entries_and_symlinks() -> TestResult {
    let mut step = CapStep::new("local_differential_foreign_entries_and_symlinks");
    let root = fresh_root("differential_foreign_entries_and_symlinks")?;
    let copy = fresh_root("differential_foreign_entries_and_symlinks_copy")?;
    let l = limits(8, 32);
    drop(LocalRootPublisher::open(&root, l)?);

    fs::write(
        root.join(LOCAL_ROOTS_DIR).join("foreign_record.txt"),
        b"foreign",
    )?;
    let ext_dir = fresh_root("differential_foreign_external")?;
    let ext_target = ext_dir.join("target.txt");
    fs::write(&ext_target, b"external")?;
    std::os::unix::fs::symlink(
        &ext_target,
        root.join(LOCAL_ROOTS_DIR).join("symlink_entry.root"),
    )?;
    copy_dir_all(&root, &copy)?;

    let external_digest = tree_digest(&ext_dir)?;
    let inspection = inspect_hooked(&mut step, "inspect", &root, None, l)??;
    step.check(
        "symlink_target_tree_digest",
        external_digest,
        tree_digest(&ext_dir)?,
    );
    let opened = LocalRootPublisher::open(&copy, l)?;
    check_matches_open(&mut step, &inspection, &opened);
    // A name outside the record grammar is foreign; a `.root` name held by a symlink is a broken
    // root record (never followed, never admitted), exactly as the open classifies both.
    step.check_debug(
        "foreign",
        &vec![Path::new(LOCAL_ROOTS_DIR).join("foreign_record.txt")],
        &inspection.report.foreign,
    );
    step.check("foreign_count", 1_usize, inspection.report.foreign.len());
    step.check_debug(
        "broken_roots",
        &vec![BrokenRoot {
            path: Path::new(LOCAL_ROOTS_DIR).join("symlink_entry.root"),
            reason: BrokenRootReason::NotRegularFile,
        }],
        &inspection.report.broken_roots,
    );
    step.check_debug(
        "broken_slots",
        &vec![slot("symlink_entry")?],
        &inspection.broken_slots.iter().cloned().collect::<Vec<_>>(),
    );
    step.finish()
}

#[test]
fn test_local_differential_redundant_temp() -> TestResult {
    let mut step = CapStep::new("local_differential_redundant_temp");
    let root = fresh_root("differential_redundant_temp")?;
    let copy = fresh_root("differential_redundant_temp_copy")?;
    let l = limits(8, 32);
    {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        publish(&mut publisher, "alpha", b"leaf")?;
    }
    let redundant = root.join(LOCAL_ROOTS_DIR).join("alpha.root.tmp");
    fs::write(&redundant, b"redundant temporary content")?;
    copy_dir_all(&root, &copy)?;

    let inspection = inspect_hooked(&mut step, "inspect", &root, None, l)??;
    step.check_debug(
        "redundant_temps",
        &vec![PathBuf::from("roots/alpha.root.tmp")],
        &inspection.redundant_temps,
    );
    step.check("inspect_kept_temp", true, redundant.exists());
    step.check("is_clean", false, inspection.is_clean());
    step.check("possibly_in_flight", true, inspection.possibly_in_flight);

    let copy_redundant = copy.join(LOCAL_ROOTS_DIR).join("alpha.root.tmp");
    let opened = LocalRootPublisher::open(&copy, l)?;
    step.check("open_removed_temp", false, copy_redundant.exists());
    check_matches_open(&mut step, &inspection, &opened);
    step.check("roots_count", 1_usize, inspection.report.roots.len());
    step.finish()
}

#[test]
fn test_local_differential_legacy_spool() -> TestResult {
    let mut step = CapStep::new("local_differential_legacy_spool");
    let root = fresh_root("differential_legacy_spool")?;
    let copy = fresh_root("differential_legacy_spool_copy")?;
    let l = limits(8, 32);
    {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        publish(&mut publisher, "slot-legacy", b"legacy payload")?;
    }
    let holds = root.join(LOCAL_SPOOL_DIR).join(SPOOL_HOLDS_DIR);
    fs::remove_dir_all(&holds)?;
    copy_dir_all(&root, &copy)?;

    let inspection = inspect_hooked(&mut step, "inspect", &root, None, l)??;
    step.check("inspect_created_holds", false, holds.exists());
    let opened = LocalRootPublisher::open(&copy, l)?;
    step.check(
        "open_migrated_holds",
        true,
        copy.join(LOCAL_SPOOL_DIR).join(SPOOL_HOLDS_DIR).is_dir(),
    );
    check_matches_open(&mut step, &inspection, &opened);
    check_extras(&mut step, &inspection, true, false);
    step.check("roots_count", 1_usize, inspection.report.roots.len());
    step.finish()
}

#[test]
fn test_local_differential_interrupted_migration() -> TestResult {
    let mut step = CapStep::new("local_differential_interrupted_migration");
    let root = fresh_root("differential_interrupted_migration")?;
    let copy = fresh_root("differential_interrupted_migration_copy")?;
    let l = limits(8, 32);
    {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        publish(&mut publisher, "alpha", b"leaf")?;
    }
    let spool = root.join(LOCAL_SPOOL_DIR);
    fs::remove_dir_all(spool.join(SPOOL_HOLDS_DIR))?;
    fs::create_dir_all(spool.join(SPOOL_HOLDS_MIGRATION_DIR))?;
    copy_dir_all(&root, &copy)?;

    let inspection = inspect_hooked(&mut step, "inspect", &root, None, l)??;
    check_extras(&mut step, &inspection, true, false);
    step.check_debug(
        "foreign",
        &Vec::<PathBuf>::new(),
        &inspection.report.foreign,
    );
    step.check("is_clean", false, inspection.is_clean());
    let opened = LocalRootPublisher::open(&copy, l)?;
    step.check(
        "open_completed_holds",
        true,
        copy.join(LOCAL_SPOOL_DIR).join(SPOOL_HOLDS_DIR).is_dir(),
    );
    check_matches_open(&mut step, &inspection, &opened);
    step.finish()
}

#[test]
fn test_local_differential_missing_layout() -> TestResult {
    let mut step = CapStep::new("local_differential_missing_layout");
    let l = limits(8, 32);

    let absent = fresh_root("differential_missing_layout")?.join("never-created");
    let absent_inspection = inspect_hooked(&mut step, "absent_root", &absent, None, l)??;
    step.check(
        "absent_root_missing_layout",
        true,
        absent_inspection.missing_layout,
    );
    step.check("absent_root_created", false, absent.exists());
    step.check_debug(
        "absent_root_writer_state",
        &WriterState::NoLockFile {
            basis: "proc_locks",
        },
        &absent_inspection.writer_state,
    );

    let empty = fresh_root("differential_missing_layout_empty")?;
    let copy = fresh_root("differential_missing_layout_empty_copy")?;
    let empty_inspection = inspect_hooked(&mut step, "empty_root", &empty, None, l)??;
    step.check(
        "empty_root_missing_layout",
        true,
        empty_inspection.missing_layout,
    );
    step.check(
        "empty_root_roots_created",
        false,
        empty.join(LOCAL_ROOTS_DIR).exists(),
    );
    let opened = LocalRootPublisher::open(&copy, l)?;
    step.check(
        "open_created_roots",
        true,
        copy.join(LOCAL_ROOTS_DIR).is_dir(),
    );
    check_matches_open(&mut step, &empty_inspection, &opened);
    step.finish()
}

// ---------------------------------------------------------------------------------------------
// Limits.
// ---------------------------------------------------------------------------------------------

#[test]
fn test_local_limits_n_and_n_plus_one() -> TestResult {
    let mut step = CapStep::new("local_limits_n_and_n_plus_one");
    let root = fresh_root("limits_n_and_n_plus_one")?;
    let copy = fresh_root("limits_n_and_n_plus_one_copy")?;
    let l_roomy = limits(8, 32);
    {
        let mut publisher = LocalRootPublisher::open(&root, l_roomy)?;
        publish(&mut publisher, "slot-1", b"c1")?;
        publish(&mut publisher, "slot-2", b"c2")?;
    }
    let l_exact = limits(2, 2);
    let at_n = inspect_hooked(&mut step, "at_n", &root, None, l_exact)??;
    step.check("at_n_roots", 2_usize, at_n.report.roots.len());

    {
        let mut publisher = LocalRootPublisher::open(&root, l_roomy)?;
        publish(&mut publisher, "slot-3", b"c3")?;
    }
    copy_dir_all(&root, &copy)?;

    let inspect_err = inspect_hooked(&mut step, "at_n_plus_1", &root, None, l_exact)?.map(|_| ());
    step.check_debug(
        "inspect_at_n_plus_1",
        &Err(LocalPublicationError::EntryLimit {
            directory: root.join(LOCAL_ROOTS_DIR),
            maximum: 2,
            at_least: 3,
        }),
        &inspect_err,
    );
    let open_err = LocalRootPublisher::open(&copy, l_exact).map(|_| ());
    step.check_debug(
        "open_at_n_plus_1",
        &Err(LocalPublicationError::EntryLimit {
            directory: copy.join(LOCAL_ROOTS_DIR),
            maximum: 2,
            at_least: 3,
        }),
        &open_err,
    );
    step.finish()
}

#[test]
fn test_local_limit_10k_orphaned_entries() -> TestResult {
    let mut step = CapStep::new("local_limit_10k_orphaned_entries");
    let root = fresh_root("limit_10k_orphaned_entries")?;
    let copy = fresh_root("limit_10k_orphaned_entries_copy")?;
    let max_scan = 64_usize;
    let l = limits(8, max_scan);
    drop(LocalRootPublisher::open(&root, l)?);
    let roots_dir = root.join(LOCAL_ROOTS_DIR);
    let orphans = 10_000_usize;
    for index in 0..orphans {
        fs::write(roots_dir.join(format!("orphan-{index:05}.root.tmp")), b"x")?;
    }
    copy_dir_all(&root, &copy)?;
    step.check(
        "orphan_files_on_disk",
        orphans,
        fs::read_dir(&roots_dir)?.count(),
    );

    let recording = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let digest_before = tree_digest(&root)?;
    let inspect_err = inspect_with_io(
        &recording,
        &root,
        l,
        None,
        WriterDetectionOptions::default(),
    )
    .map(|_| ());
    step.check("tree_digest", digest_before, tree_digest(&root)?);
    step.check_debug(
        "inspect",
        &Err(LocalPublicationError::EntryLimit {
            directory: roots_dir.clone(),
            maximum: max_scan,
            at_least: max_scan + 1,
        }),
        &inspect_err,
    );
    step.check_debug(
        "inspect_mutating_calls",
        &Vec::<SpoolIoCall>::new(),
        &recording.mutating_calls(),
    );
    // The scan stops at the first entry past the bound: a small constant number of reads beyond
    // `max_scan` (the spool and the other directories), never one read per orphan.
    let dir_reads = recording.call_count(SpoolIoCall::NextDirEntry);
    step.observe_only("next_dir_entry_calls", dir_reads);
    step.check(
        "next_dir_entry_calls_bounded_by_scan_limit",
        true,
        dir_reads <= max_scan + 1 + 32,
    );

    let open_err = LocalRootPublisher::open(&copy, l).map(|_| ());
    step.check_debug(
        "open",
        &Err(LocalPublicationError::EntryLimit {
            directory: copy.join(LOCAL_ROOTS_DIR),
            maximum: max_scan,
            at_least: max_scan + 1,
        }),
        &open_err,
    );
    step.finish()
}

// ---------------------------------------------------------------------------------------------
// Read-only proofs.
// ---------------------------------------------------------------------------------------------

#[test]
fn test_local_read_only_tree_digest_proof() -> TestResult {
    let mut step = CapStep::new("local_read_only_tree_digest_proof");
    let root = fresh_root("read_only_tree_digest_proof")?;
    let l = limits(8, 32);
    {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        publish(&mut publisher, "slot-test", b"payload")?;
    }
    // The LOCK files the publisher created stay in place; the hook try-locks each of them
    // exclusively during every read the inspection makes.
    let locks = lock_paths(&root, None);
    step.check_debug(
        "lock_files_present",
        &vec![true, true],
        &locks.iter().map(|path| path.is_file()).collect::<Vec<_>>(),
    );

    let io = LockHookSpoolIo::new(locks.clone());
    let digest_before = tree_digest(&root)?;
    let inspection =
        inspect_with_ledger_journal(&io, &root, None, l, None, WriterDetectionOptions::default())?;
    step.check("tree_digest", digest_before, tree_digest(&root)?);
    step.check_debug(
        "mutating_calls",
        &Vec::<SpoolIoCall>::new(),
        &io.inner.mutating_calls(),
    );
    step.check_debug(
        "lock_violations",
        &Vec::<String>::new(),
        &io.lock_violations(),
    );
    for (index, path) in locks.iter().enumerate() {
        step.check(
            &format!("lock_{index}_probes_acquired"),
            true,
            io.acquired_on(path) > 0,
        );
    }
    step.check("roots_count", 1_usize, inspection.report.roots.len());
    step.check_debug(
        "writer_state",
        &WriterState::not_observed(),
        &inspection.writer_state,
    );

    // Control: while a writer holds the spool LOCK, the hook reports it and the lock table
    // shows the holder; the lock-free inspection still completes.
    let spool_lock = root.join(LOCAL_SPOOL_DIR).join(SPOOL_LOCK_FILE);
    let writer = File::open(&spool_lock)?;
    writer
        .try_lock()
        .map_err(|error| format!("control writer lock: {error:?}"))?;
    let held = LockHookSpoolIo::new(locks);
    let under_writer = inspect_with_ledger_journal(
        &held,
        &root,
        None,
        l,
        None,
        WriterDetectionOptions::default(),
    )
    .map(|found| found.writer_state);
    drop(writer);
    step.check_debug(
        "control_writer_state",
        &Ok(WriterState::Held {
            basis: WriterLockBasis::ProcLocks,
            pid_hint: Some(std::process::id()),
        }),
        &under_writer,
    );
    step.check(
        "control_writer_flagged",
        true,
        !held.lock_violations().is_empty(),
    );
    step.finish()
}

#[test]
fn test_local_read_only_no_lock_created() -> TestResult {
    let mut step = CapStep::new("local_read_only_no_lock_created");
    let root = fresh_root("read_only_no_lock_created")?;
    let copy = fresh_root("read_only_no_lock_created_copy")?;
    let l = limits(8, 32);
    {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        publish(&mut publisher, "slot-nolock", b"payload")?;
    }
    // A copy of the layout made without any LOCK entry: a deployment no writer has opened here.
    copy_dir_filtered(&root, &copy, true)?;
    let locks = lock_paths(&copy, None);
    step.check_debug(
        "lock_files_before",
        &vec![false, false],
        &locks.iter().map(|path| path.exists()).collect::<Vec<_>>(),
    );

    let inspection = inspect_hooked(&mut step, "inspect", &copy, None, l)??;
    step.check_debug(
        "lock_files_after",
        &vec![false, false],
        &locks.iter().map(|path| path.exists()).collect::<Vec<_>>(),
    );
    step.check_debug(
        "writer_state",
        &WriterState::NoLockFile {
            basis: "proc_locks",
        },
        &inspection.writer_state,
    );
    step.check("roots_count", 1_usize, inspection.report.roots.len());
    step.finish()
}

#[test]
fn test_local_read_only_recording_io_proof() -> TestResult {
    let mut step = CapStep::new("local_read_only_recording_io_proof");
    let root = fresh_root("read_only_recording_io_proof")?;
    let l = limits(8, 32);
    {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        publish(&mut publisher, "rec-slot", b"recording data")?;
    }

    let recording = Arc::new(RecordingSpoolIo::new(Arc::new(HostSpoolIo)));
    let io: Arc<dyn SpoolIo> = recording.clone();
    let inspection = inspect_with_options(io, &root, l, None, WriterDetectionOptions::default())?;
    step.check("roots_count", 1_usize, inspection.report.roots.len());
    let calls = recording.calls();
    step.check("calls_recorded", true, !calls.is_empty());
    step.check_debug(
        "mutating_calls",
        &Vec::<SpoolIoCall>::new(),
        &recording.mutating_calls(),
    );
    let read_set = [
        SpoolIoCall::Metadata,
        SpoolIoCall::SymlinkMetadata,
        SpoolIoCall::ReadDir,
        SpoolIoCall::NextDirEntry,
        SpoolIoCall::EntryFileType,
        SpoolIoCall::OpenRead,
        SpoolIoCall::Read,
    ];
    step.check_debug(
        "calls_outside_read_set",
        &Vec::<SpoolIoCall>::new(),
        &calls
            .iter()
            .copied()
            .filter(|call| !read_set.contains(call))
            .collect::<Vec<_>>(),
    );
    step.finish()
}

#[test]
fn test_local_read_only_copy_unprivileged() -> TestResult {
    let mut step = CapStep::new("local_read_only_copy_unprivileged");
    let root = fresh_root("read_only_copy_unprivileged")?;
    let copy = fresh_root("read_only_copy_unprivileged_copy")?;
    let l = limits(8, 32);
    {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        publish(&mut publisher, "ro-slot", b"ro data")?;
    }
    fs::write(
        root.join(LOCAL_ROOTS_DIR).join("ro-slot.root.tmp"),
        b"redundant",
    )?;
    copy_dir_all(&root, &copy)?;

    // Needs no privilege: every mutating call fails with EROFS whatever the uid.
    let deny = DenyWritesSpoolIo::default();
    let digest_before = tree_digest(&copy)?;
    let denied_inspection =
        inspect_with_io(&deny, &copy, l, None, WriterDetectionOptions::default())?;
    step.check("tree_digest", digest_before, tree_digest(&copy)?);
    step.check_debug("denied_calls", &Vec::<SpoolIoCall>::new(), &deny.denied());
    let host_inspection = inspect(&copy, l)?;
    step.check_equal("inspection_vs_host", &host_inspection, &denied_inspection);
    step.check("roots_count", 1_usize, denied_inspection.report.roots.len());
    step.check(
        "redundant_temps_count",
        1_usize,
        denied_inspection.redundant_temps.len(),
    );

    // Control: the open cannot run on the same capability; its first call is refused.
    let open_deny = Arc::new(DenyWritesSpoolIo::default());
    let io: Arc<dyn SpoolIo> = open_deny.clone();
    let open_err = LocalRootPublisher::open_with_io(&copy, l, io).map(|_| ());
    step.check_debug(
        "control_open",
        &Err(LocalPublicationError::Io {
            operation: LocalIoOperation::CreateDirectory,
            path: copy.clone(),
            kind: io::ErrorKind::ReadOnlyFilesystem,
        }),
        &open_err,
    );
    step.check_debug(
        "control_open_denied_calls",
        &vec![SpoolIoCall::CreateDirAll],
        &open_deny.denied(),
    );
    step.finish()
}

#[test]
#[ignore = "needs an unprivileged uid (a 0o555 tree does not stop CAP_DAC_OVERRIDE); a privileged run fails, never passes"]
fn test_local_read_only_filesystem_copy() -> TestResult {
    let mut step = CapStep::new("local_read_only_filesystem_copy");
    let root = fresh_root("read_only_filesystem_copy")?;
    let ro_root = fresh_root("read_only_filesystem_copy_ro")?;
    let l = limits(8, 32);
    {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        publish(&mut publisher, "ro-slot", b"ro data")?;
    }
    copy_dir_all(&root, &ro_root)?;
    let guard = ReadOnlyTreeGuard::make_read_only(&ro_root)?;

    let sentinel = ro_root.join("sentinel.tmp");
    if OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&sentinel)
        .is_ok()
    {
        let _ = fs::remove_file(&sentinel);
        drop(guard);
        return step.skip("privileged: create_new succeeded in a 0o555 directory".to_owned());
    }

    let result = inspect(&ro_root, l).map(|found| found.report.roots.len());
    drop(guard);
    step.check_debug("inspect_roots", &Ok(1_usize), &result);
    step.finish()
}

// ---------------------------------------------------------------------------------------------
// Writer detection.
// ---------------------------------------------------------------------------------------------

#[test]
fn test_local_writer_detection_proc_locks_real_publisher() -> TestResult {
    let mut step = CapStep::new("local_writer_detection_proc_locks_real_publisher");
    let root = fresh_root("writer_detection_proc_locks_real_publisher")?;
    let l = limits(8, 32);
    let pid = Some(std::process::id());
    let held_state = WriterState::Held {
        basis: WriterLockBasis::ProcLocks,
        pid_hint: pid,
    };

    // A real publisher holds both LOCKs; the default options read the host lock table.
    let publisher = LocalRootPublisher::open(&root, l)?;
    let held = inspect_with_options(
        Arc::new(HostSpoolIo),
        &root,
        l,
        Some(&HostLockTableSource),
        WriterDetectionOptions::default(),
    )?;
    step.check_debug("held_writer_state", &held_state, &held.writer_state);
    step.check("held_possibly_stale", true, held.possibly_stale);
    step.check("held_possibly_in_flight", true, held.possibly_in_flight);
    step.check("held_is_clean", false, held.is_clean());
    let held_default = inspect(&root, l)?;
    step.check_debug(
        "held_default_inspect_writer_state",
        &held_state,
        &held_default.writer_state,
    );
    drop(publisher);

    let released = inspect_with_options(
        Arc::new(HostSpoolIo),
        &root,
        l,
        Some(&HostLockTableSource),
        WriterDetectionOptions::default(),
    )?;
    step.check_debug(
        "released_writer_state",
        &WriterState::not_observed(),
        &released.writer_state,
    );
    step.check("released_is_clean", true, released.is_clean());

    // A real shared (READ) flock on <root>/LOCK is a shared holder, not a writer.
    let reader = File::open(root.join(LOCAL_LOCK_FILE))?;
    reader
        .try_lock_shared()
        .map_err(|error| format!("shared lock: {error:?}"))?;
    let shared = inspect_with_options(
        Arc::new(HostSpoolIo),
        &root,
        l,
        Some(&HostLockTableSource),
        WriterDetectionOptions::default(),
    )?;
    drop(reader);
    step.check_debug(
        "shared_writer_state",
        &WriterState::SharedHolder {
            basis: WriterLockBasis::ProcLocks,
            pid_hint: pid,
        },
        &shared.writer_state,
    );
    step.check("shared_possibly_stale", true, shared.possibly_stale);
    step.finish()
}

#[test]
fn test_local_writer_detection_held_and_released() -> TestResult {
    let mut step = CapStep::new("local_writer_detection_held_and_released");
    let root = fresh_root("writer_detection_held_and_released")?;
    let l = limits(8, 32);
    let probe_options = WriterDetectionOptions {
        probe_shared_lock: true,
        self_holds_lock: false,
    };

    let publisher = LocalRootPublisher::open(&root, l)?;
    let held = inspect_with_options(
        Arc::new(HostSpoolIo),
        &root,
        l,
        Some(&HostLockTableSource),
        probe_options,
    )?;
    step.check_debug(
        "probe_held",
        &WriterState::Held {
            basis: WriterLockBasis::SharedTryLock,
            pid_hint: None,
        },
        &held.writer_state,
    );
    drop(publisher);

    let released = inspect_with_options(
        Arc::new(HostSpoolIo),
        &root,
        l,
        Some(&HostLockTableSource),
        probe_options,
    )?;
    step.check_debug(
        "probe_released",
        &WriterState::not_held(),
        &released.writer_state,
    );
    step.finish()
}

#[test]
fn test_local_writer_detection_probe_race() -> TestResult {
    let mut step = CapStep::new("local_writer_detection_probe_race");
    let root = fresh_root("writer_detection_probe_race")?;
    let l = limits(8, 32);
    drop(LocalRootPublisher::open(&root, l)?);

    // The opt-in probe takes a shared lock on the first lock path, `<root>/LOCK` (the
    // publication lock the open acquires first; there is no `<root>/objects/LOCK`). While the
    // probe holds it, the hook runs the open, which must fail with the typed Locked error.
    let race = ProbeRaceSpoolIo {
        root: root.clone(),
        limits: l,
        open_while_probed: Mutex::new(Vec::new()),
    };
    let inspection = inspect_with_io(
        &race,
        &root,
        l,
        None,
        WriterDetectionOptions {
            probe_shared_lock: true,
            self_holds_lock: false,
        },
    )?;
    step.check_debug(
        "open_while_probe_held",
        &vec![Err(LocalPublicationError::Locked {
            path: root.join(LOCAL_LOCK_FILE),
        })],
        &race.outcomes(),
    );
    step.check_debug(
        "probe_state",
        &WriterState::not_held(),
        &inspection.writer_state,
    );
    let after = LocalRootPublisher::open(&root, l).map(|publisher| publisher.limits().max_roots);
    step.check_debug("open_after_probe_released", &Ok(8_usize), &after);
    drop(after);

    // A shared hold on the spool LOCK blocks the open's second lock with the spool's typed error.
    let spool_lock = root.join(LOCAL_SPOOL_DIR).join(SPOOL_LOCK_FILE);
    let holder = File::open(&spool_lock)?;
    HostSpoolIo
        .try_lock_shared(&holder)
        .map_err(|error| format!("try_lock_shared failed: {error:?}"))?;
    let blocked = LocalRootPublisher::open(&root, l).map(|_| ());
    drop(holder);
    step.check_debug(
        "open_while_spool_lock_shared",
        &Err(LocalPublicationError::Spool(SpoolError::Locked {
            path: spool_lock,
        })),
        &blocked,
    );
    step.finish()
}

#[test]
fn test_local_writer_detection_lock_table_cases() -> TestResult {
    let mut step = CapStep::new("local_writer_detection_lock_table_cases");
    let root = fresh_root("writer_detection_lock_table_cases")?;
    let l = limits(8, 32);
    drop(LocalRootPublisher::open(&root, l)?);

    let spool_lock = root.join(LOCAL_SPOOL_DIR).join(SPOOL_LOCK_FILE);
    let meta = fs::symlink_metadata(&spool_lock)?;
    let (maj, min) = decode_st_dev(meta.dev());
    let ino = meta.ino();
    let dev = format!("{maj:02x}:{min:02x}");
    // A device with hex letters that is not this file's device: parsed as hex it mismatches;
    // parsed as decimal it would not parse at all.
    let other_dev = if (maj, min) == (0x1a, 0x2b) {
        "2b:1a"
    } else {
        "1a:2b"
    };
    let held = |pid: u32| WriterState::Held {
        basis: WriterLockBasis::ProcLocks,
        pid_hint: Some(pid),
    };
    let cases: Vec<(&str, String, WriterState)> = vec![
        (
            "flock_write",
            format!("1: FLOCK  ADVISORY  WRITE 4242 {dev}:{ino} 0 EOF\n"),
            held(4242),
        ),
        (
            "flock_read",
            format!("1: FLOCK  ADVISORY  READ  4243 {dev}:{ino} 0 EOF\n"),
            WriterState::SharedHolder {
                basis: WriterLockBasis::ProcLocks,
                pid_hint: Some(4243),
            },
        ),
        (
            "waiter_after_holder",
            format!(
                "1: FLOCK  ADVISORY  WRITE 4242 {dev}:{ino} 0 EOF\n1: -> FLOCK  ADVISORY  WRITE 9999 {dev}:{ino} 0 EOF\n"
            ),
            held(4242),
        ),
        (
            "waiter_only",
            format!("1: -> FLOCK  ADVISORY  WRITE 9999 {dev}:{ino} 0 EOF\n"),
            WriterState::not_observed(),
        ),
        (
            "posix_write_ignored",
            format!("1: POSIX  ADVISORY  WRITE 4244 {dev}:{ino} 0 EOF\n"),
            WriterState::not_observed(),
        ),
        (
            "posix_read_ignored",
            format!("1: POSIX  ADVISORY  READ  4245 {dev}:{ino} 0 EOF\n"),
            WriterState::not_observed(),
        ),
        (
            "ofdlck_write_ignored",
            format!("1: OFDLCK ADVISORY  WRITE -1 {dev}:{ino} 0 EOF\n"),
            WriterState::not_observed(),
        ),
        (
            "posix_then_flock",
            format!(
                "1: POSIX  ADVISORY  WRITE 4244 {dev}:{ino} 0 EOF\n2: FLOCK  ADVISORY  WRITE 4246 {dev}:{ino} 0 EOF\n"
            ),
            held(4246),
        ),
        (
            "hex_device_zero_padded",
            format!("1: FLOCK  ADVISORY  WRITE 4247 {maj:04x}:{min:04x}:{ino} 0 EOF\n"),
            held(4247),
        ),
        (
            "hex_device_letters_mismatch",
            format!("1: FLOCK  ADVISORY  WRITE 4248 {other_dev}:{ino} 0 EOF\n"),
            WriterState::Unknown {
                reason: UnknownLockReason::DeviceMismatch,
            },
        ),
        (
            "other_inode_ignored",
            format!("1: FLOCK  ADVISORY  WRITE 4249 {dev}:{} 0 EOF\n", ino + 1),
            WriterState::not_observed(),
        ),
        (
            "unparseable_line",
            "unparseable line without colon format\n".to_owned(),
            WriterState::Unknown {
                reason: UnknownLockReason::ParseError,
            },
        ),
        (
            "over_budget",
            "x".repeat(1024 * 1024 + 1),
            WriterState::Unknown {
                reason: UnknownLockReason::OverBudget,
            },
        ),
    ];
    for (name, table, expected) in cases {
        let source = StringLockTableSource(table);
        let state = detect_writers(
            &HostSpoolIo,
            std::slice::from_ref(&spool_lock),
            Some(&source),
            WriterDetectionOptions::default(),
        );
        step.check_debug(name, &expected, &state);
    }

    let self_held = detect_writers(
        &HostSpoolIo,
        std::slice::from_ref(&spool_lock),
        Some(&StringLockTableSource(format!(
            "1: FLOCK  ADVISORY  WRITE 4242 {dev}:{ino} 0 EOF\n"
        ))),
        WriterDetectionOptions {
            probe_shared_lock: true,
            self_holds_lock: true,
        },
    );
    step.check_debug("self_held", &WriterState::NotProbed, &self_held);
    step.finish()
}

#[test]
fn test_local_writer_detection_lock_symlink_or_dir() -> TestResult {
    let mut step = CapStep::new("local_writer_detection_lock_symlink_or_dir");
    let root = fresh_root("writer_detection_lock_symlink_or_dir")?;
    let l = limits(8, 32);
    let spool_dir = root.join(LOCAL_SPOOL_DIR);
    fs::create_dir_all(&spool_dir)?;
    let spool_lock = spool_dir.join(SPOOL_LOCK_FILE);
    fs::create_dir(&spool_lock)?;

    let invalid = WriterState::invalid_layout("non_regular_lock_file");
    let state_dir = detect_writers(
        &HostSpoolIo,
        std::slice::from_ref(&spool_lock),
        None,
        WriterDetectionOptions::default(),
    );
    step.check_debug("directory_lock", &invalid, &state_dir);
    let open_res = LocalRootPublisher::open(&root, l).map(|_| ());
    step.check_debug(
        "open_directory_lock",
        &Err(LocalPublicationError::Spool(SpoolError::InvalidLayout {
            path: spool_lock.clone(),
        })),
        &open_res,
    );

    fs::remove_dir(&spool_lock)?;
    let dummy_target = root.join("dummy_lock_target");
    fs::write(&dummy_target, b"dummy")?;
    std::os::unix::fs::symlink(&dummy_target, &spool_lock)?;
    let state_sym = detect_writers(
        &HostSpoolIo,
        std::slice::from_ref(&spool_lock),
        None,
        WriterDetectionOptions::default(),
    );
    step.check_debug("symlink_lock", &invalid, &state_sym);
    step.finish()
}

#[test]
fn test_local_writer_detection_round3_cases() -> TestResult {
    let mut step = CapStep::new("local_writer_detection_round3_cases");
    let root = fresh_root("writer_detection_round3_cases")?;
    let l = limits(8, 32);
    drop(LocalRootPublisher::open(&root, l)?);
    let spool_lock = root.join(LOCAL_SPOOL_DIR).join(SPOOL_LOCK_FILE);

    let cases: Vec<(&str, &dyn LockTableSource, WriterState)> = vec![
        (
            "missing_lock_table",
            &FailingLockTableSource(io::ErrorKind::NotFound),
            WriterState::Unknown {
                reason: UnknownLockReason::NoLockTable,
            },
        ),
        (
            "unreadable_lock_table",
            &FailingLockTableSource(io::ErrorKind::PermissionDenied),
            WriterState::Unknown {
                reason: UnknownLockReason::Unreadable,
            },
        ),
    ];
    for (name, source, expected) in cases {
        let state = detect_writers(
            &HostSpoolIo,
            std::slice::from_ref(&spool_lock),
            Some(source),
            WriterDetectionOptions::default(),
        );
        step.check_debug(name, &expected, &state);
    }
    let empty = StringLockTableSource(String::new());
    let state_empty = detect_writers(
        &HostSpoolIo,
        std::slice::from_ref(&spool_lock),
        Some(&empty),
        WriterDetectionOptions::default(),
    );
    step.check_debug(
        "empty_lock_table",
        &WriterState::not_observed(),
        &state_empty,
    );

    let replacing = ReplacingSpoolIo {
        re_stat_count: AtomicUsize::new(0),
    };
    let state_replaced = detect_writers(
        &replacing,
        std::slice::from_ref(&spool_lock),
        Some(&empty),
        WriterDetectionOptions::default(),
    );
    step.check_debug(
        "lock_file_replaced",
        &WriterState::Unknown {
            reason: UnknownLockReason::LockFileReplaced,
        },
        &state_replaced,
    );
    step.finish()
}

#[test]
fn test_local_read_verified() -> TestResult {
    let mut step = CapStep::new("local_read_verified");
    let root = fresh_root("read_verified")?;
    let l = limits(8, 32);
    let payload: &[u8] = b"payload for lock-free read_verified";
    let digest = {
        let mut publisher = LocalRootPublisher::open(&root, l)?;
        let child = publisher.stage_object(payload)?;
        let manifest = ObjectManifest::new("clip", [child], None)?;
        publisher.publish(&slot("read-slot")?, &manifest)?;
        child
    };

    let io = LockHookSpoolIo::new(lock_paths(&root, None));
    let digest_before = tree_digest(&root)?;
    let data = read_verified_with_io(&root, digest, MAX_OBJECT_BYTES, &io)?;
    step.check("payload_len", payload.len(), data.len());
    step.check("payload_equal", true, data.as_slice() == payload);

    let mut raw = digest.bytes();
    raw[0] ^= 0x01;
    let bad_digest = ContentDigest::new(DigestAlgorithm::Sha256, raw);
    let missing = read_verified(&root, bad_digest, MAX_OBJECT_BYTES);
    step.check_debug(
        "absent_digest",
        &Err(LocalPublicationError::Spool(SpoolError::Corrupt {
            digest: bad_digest,
            kind: CorruptionKind::Vanished,
        })),
        &missing,
    );
    step.check("tree_digest", digest_before, tree_digest(&root)?);
    step.check_debug(
        "mutating_calls",
        &Vec::<SpoolIoCall>::new(),
        &io.inner.mutating_calls(),
    );
    step.check_debug(
        "lock_violations",
        &Vec::<String>::new(),
        &io.lock_violations(),
    );
    step.finish()
}

// ---------------------------------------------------------------------------------------------
// Root-ledger linkage differentials.
// ---------------------------------------------------------------------------------------------

/// A deployment: the publication root and, beside it (never inside it), the ledger journal.
struct Deployment {
    base: PathBuf,
    root: PathBuf,
    journal: PathBuf,
}

fn deployment(name: &str) -> Result<Deployment, Box<dyn Error>> {
    let base = fresh_root(name)?;
    Ok(Deployment {
        root: base.join("publication"),
        journal: base.join("ledger.journal"),
        base,
    })
}

fn interval() -> Result<CaptureInterval, Box<dyn Error>> {
    Ok(CaptureInterval::new(
        TimestampNs(1_000),
        TimestampNs(2_000),
    )?)
}

/// Publishes and ledgers `slot-a`; returns its root.
fn ledger_slot_a(
    publisher: &mut LocalRootPublisher,
    ledger: &mut DurableReferenceLedger,
) -> Result<ContentDigest, Box<dyn Error>> {
    let child = publisher.stage_object(b"clip-1")?;
    let manifest = ObjectManifest::new("clip", [child], None)?;
    LedgeredRootPublisher::new(publisher, ledger).publish_and_commit(
        &slot("slot-a")?,
        &manifest,
        interval()?,
    )?;
    Ok(manifest.root())
}

/// Leaves `slot-b` durable on disk and unledgered through [`LedgerCutPoint::AfterRootDurable`].
fn pending_slot_b(
    step: &mut CapStep,
    publisher: &mut LocalRootPublisher,
    ledger: &mut DurableReferenceLedger,
) -> Result<ContentDigest, Box<dyn Error>> {
    let child = publisher.stage_object(b"clip-2")?;
    let manifest = ObjectManifest::new("clip", [child], None)?;
    let mut coordinator = LedgeredRootPublisher::new(publisher, ledger);
    coordinator.inject_crash_at(LedgerCutPoint::AfterRootDurable);
    let crash = coordinator
        .publish_and_commit(&slot("slot-b")?, &manifest, interval()?)
        .map(|_| ());
    step.check(
        "after_root_durable_crash",
        "Err(InjectedCrash { point: AfterRootDurable })".to_owned(),
        format!("{crash:?}"),
    );
    Ok(manifest.root())
}

/// Appends a reachability claim for `slot-unbacked` naming `root` with no durable root behind it.
fn unbacked_claim(ledger: &mut DurableReferenceLedger, root: ContentDigest) -> TestResult {
    let delta = EvidenceDelta {
        delta_id: "delta:unbacked".to_owned(),
        family: ROOT_REACHABILITY_FAMILY.to_owned(),
        object_id: root_reachability_object_id(&slot("slot-unbacked")?)?,
        prior_generation: None,
        new_generation: 1,
        validity: interval()?,
        plane: Plane::Authority,
        payload_digest: root,
        witness_digest: None,
        operation_id: None,
    };
    let batch = ledger.prepare_batch(BatchId::parse("batch:unbacked")?, vec![delta], [])?;
    ledger.append(batch)?;
    Ok(())
}

/// Runs both sides: [`inspect_linkage`] over the read-only inspections of `deployment`, and
/// [`LedgeredRootPublisher::reconcile`] over the opens of a copy.
fn linkage_both_sides(
    step: &mut CapStep,
    deployment: &Deployment,
    l: LocalPublicationLimits,
) -> Result<(RootLedgerReconciliation, RootLedgerReconciliation), Box<dyn Error>> {
    let copy = fresh_root(&format!(
        "{}_copy",
        deployment
            .base
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default()
    ))?;
    copy_dir_all(&deployment.base, &copy)?;

    let journal_before = stamp(&deployment.journal);
    let local = inspect_hooked(
        step,
        "local_inspect",
        &deployment.root,
        Some(&deployment.journal),
        l,
    )??;
    let recorder = RecordingJournalReadIo::new();
    let ledger = inspect_durable_with_io(
        &recorder,
        &deployment.journal,
        SITE,
        DurableLedgerLimits::default(),
    )?;
    step.check_debug(
        "journal_mutating_calls",
        &Vec::<String>::new(),
        &recorder.mutating_calls(),
    );
    step.check_debug(
        "journal_stamp",
        &journal_before,
        &stamp(&deployment.journal),
    );
    let inspected = inspect_linkage(&local, &ledger);

    let mut open_publisher = LocalRootPublisher::open(copy.join("publication"), l)?;
    let mut open_ledger = DurableReferenceLedger::open(
        copy.join("ledger.journal"),
        SITE,
        IncompleteTailPolicy::Reject,
    )?;
    let reconciled =
        LedgeredRootPublisher::new(&mut open_publisher, &mut open_ledger).reconcile()?;
    Ok((inspected, reconciled))
}

fn check_linkage_matches(
    step: &mut CapStep,
    inspected: &RootLedgerReconciliation,
    reconciled: &RootLedgerReconciliation,
) {
    step.check_equal(
        "ledgered_vs_reconcile",
        &reconciled.ledgered,
        &inspected.ledgered,
    );
    step.check_equal(
        "pending_vs_reconcile",
        &reconciled.pending,
        &inspected.pending,
    );
    step.check_equal(
        "not_durable_vs_reconcile",
        &reconciled.not_durable,
        &inspected.not_durable,
    );
    step.check_equal(
        "conflicts_vs_reconcile",
        &reconciled.conflicts,
        &inspected.conflicts,
    );
    step.check_equal(
        "unledgerable_vs_reconcile",
        &reconciled.unledgerable,
        &inspected.unledgerable,
    );
    step.check_equal(
        "unbacked_vs_reconcile",
        &reconciled.unbacked_ledger_claims,
        &inspected.unbacked_ledger_claims,
    );
    step.check_equal("broken_vs_reconcile", &reconciled.broken, &inspected.broken);
    step.check(
        "ledger_tail_incomplete",
        None::<u64>,
        inspected.ledger_tail_incomplete,
    );
    step.check(
        "reconcile_durability_not_resynced",
        false,
        reconciled.durability_not_resynced,
    );
    step.check(
        "inspect_durability_not_resynced",
        true,
        inspected.durability_not_resynced,
    );
}

fn slots_of<T>(items: &[T], slot_of: impl Fn(&T) -> &SlotName) -> Vec<SlotName> {
    items.iter().map(|item| slot_of(item).clone()).collect()
}

#[test]
fn test_linkage_after_root_durable_differential() -> TestResult {
    let mut step = CapStep::new("linkage_after_root_durable_differential");
    let deployment = deployment("linkage_after_root_durable_differential")?;
    let l = limits(8, 32);
    let (root_a, root_b) = {
        let mut ledger =
            DurableReferenceLedger::open(&deployment.journal, SITE, IncompleteTailPolicy::Reject)?;
        let mut publisher = LocalRootPublisher::open(&deployment.root, l)?;
        let root_a = ledger_slot_a(&mut publisher, &mut ledger)?;
        let root_b = pending_slot_b(&mut step, &mut publisher, &mut ledger)?;
        (root_a, root_b)
    };

    let (inspected, reconciled) = linkage_both_sides(&mut step, &deployment, l)?;
    check_linkage_matches(&mut step, &inspected, &reconciled);
    step.check_debug(
        "ledgered",
        &vec![(slot("slot-a")?, root_a)],
        &inspected
            .ledgered
            .iter()
            .map(|entry| (entry.slot.clone(), entry.root))
            .collect::<Vec<_>>(),
    );
    step.check_debug(
        "pending",
        &vec![(slot("slot-b")?, root_b)],
        &inspected
            .pending
            .iter()
            .map(|entry| (entry.slot.clone(), entry.root))
            .collect::<Vec<_>>(),
    );
    step.check(
        "unbacked_count",
        0_usize,
        inspected.unbacked_ledger_claims.len(),
    );
    step.finish()
}

#[test]
fn test_linkage_unbacked_claim_differential() -> TestResult {
    let mut step = CapStep::new("linkage_unbacked_claim_differential");
    let deployment = deployment("linkage_unbacked_claim_differential")?;
    let l = limits(8, 32);
    let root_a = {
        let mut ledger =
            DurableReferenceLedger::open(&deployment.journal, SITE, IncompleteTailPolicy::Reject)?;
        let mut publisher = LocalRootPublisher::open(&deployment.root, l)?;
        let root_a = ledger_slot_a(&mut publisher, &mut ledger)?;
        unbacked_claim(&mut ledger, root_a)?;
        root_a
    };

    let (inspected, reconciled) = linkage_both_sides(&mut step, &deployment, l)?;
    check_linkage_matches(&mut step, &inspected, &reconciled);
    step.check_debug(
        "unbacked_claims",
        &vec![(
            root_reachability_object_id(&slot("slot-unbacked")?)?,
            Some(slot("slot-unbacked")?),
            root_a,
        )],
        &inspected
            .unbacked_ledger_claims
            .iter()
            .map(|claim| {
                (
                    claim.object_id.clone(),
                    claim.slot.clone(),
                    claim.ledgered_root,
                )
            })
            .collect::<Vec<_>>(),
    );
    step.check_debug(
        "ledgered_slots",
        &vec![slot("slot-a")?],
        &slots_of(&inspected.ledgered, |entry| &entry.slot),
    );
    step.check("pending_count", 0_usize, inspected.pending.len());
    step.finish()
}

#[test]
fn test_linkage_differential() -> TestResult {
    let mut step = CapStep::new("local_inspect_linkage");
    let deployment = deployment("linkage_differential")?;
    let l = limits(8, 32);
    {
        let mut ledger =
            DurableReferenceLedger::open(&deployment.journal, SITE, IncompleteTailPolicy::Reject)?;
        let mut publisher = LocalRootPublisher::open(&deployment.root, l)?;
        let root_a = ledger_slot_a(&mut publisher, &mut ledger)?;
        pending_slot_b(&mut step, &mut publisher, &mut ledger)?;
        unbacked_claim(&mut ledger, root_a)?;
    }

    let (inspected, reconciled) = linkage_both_sides(&mut step, &deployment, l)?;
    check_linkage_matches(&mut step, &inspected, &reconciled);
    step.check_debug(
        "ledgered_slots",
        &vec![slot("slot-a")?],
        &slots_of(&inspected.ledgered, |entry| &entry.slot),
    );
    step.check_debug(
        "pending_slots",
        &vec![slot("slot-b")?],
        &slots_of(&inspected.pending, |entry| &entry.slot),
    );
    step.check(
        "unbacked_count",
        1_usize,
        inspected.unbacked_ledger_claims.len(),
    );
    step.check("broken_count", 0_usize, inspected.broken.len());
    step.finish()
}

#[test]
fn test_linkage_read_only_recording_io_proof() -> TestResult {
    let mut step = CapStep::new("linkage_read_only_recording_io_proof");
    let deployment = deployment("linkage_read_only_recording_io_proof")?;
    let l = limits(8, 32);
    {
        let mut ledger =
            DurableReferenceLedger::open(&deployment.journal, SITE, IncompleteTailPolicy::Reject)?;
        let mut publisher = LocalRootPublisher::open(&deployment.root, l)?;
        ledger_slot_a(&mut publisher, &mut ledger)?;
    }

    let local = inspect_hooked(
        &mut step,
        "local_inspect",
        &deployment.root,
        Some(&deployment.journal),
        l,
    )??;
    let recorder = RecordingJournalReadIo::new();
    let limits = DurableLedgerLimits::default();
    let ledger = inspect_durable_with_io(&recorder, &deployment.journal, SITE, limits)?;
    let journal_len = usize::try_from(fs::metadata(&deployment.journal)?.len())?;
    step.check_debug(
        "journal_calls",
        &vec![
            JournalCall::SymlinkMetadata {
                path: deployment.journal.clone(),
            },
            JournalCall::ReadBounded {
                path: deployment.journal.clone(),
                max_bytes: limits.max_journal_bytes + 1,
                returned: Some(journal_len),
            },
        ],
        &recorder.calls(),
    );
    step.check_debug(
        "journal_mutating_calls",
        &Vec::<String>::new(),
        &recorder.mutating_calls(),
    );
    step.check(
        "journal_lock_probes_acquired",
        4_usize,
        recorder
            .observations()
            .iter()
            .flat_map(|observation| [observation.probe_before, observation.probe_after])
            .filter(|probe| *probe == LockProbe::Acquired)
            .count(),
    );
    let linkage = inspect_linkage(&local, &ledger);
    step.check_debug(
        "ledgered_slots",
        &vec![slot("slot-a")?],
        &slots_of(&linkage.ledgered, |entry| &entry.slot),
    );
    step.finish()
}
