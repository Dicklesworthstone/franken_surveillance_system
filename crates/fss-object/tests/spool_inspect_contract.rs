#![forbid(unsafe_code)]
//! Integration contract tests for spool inspection without locks, repair, or mutation (DOCTOR0).
//!
//! Asserts:
//! - Differential against [`StagingSpool::open`]: the inspection report equals the open's
//!   recovery report for a clean spool, orphaned staging, a corrupt object, a foreign entry, a
//!   symlink, a legacy spool (no holds directory), and a missing layout; the extras
//!   (`holds_migration_pending`, `missing_layout`) are asserted exactly.
//! - Limits: the scan bound at N and N+1, and 10k orphaned staging entries against a small scan
//!   bound, give the same typed [`SpoolError::EntryLimit`] from inspect and open, after a bounded
//!   number of directory reads.
//! - Read-only proof: every inspection runs through [`LockHookSpoolIo`], which records each call
//!   through [`RecordingSpoolIo`] (a mutating or locking call fails the step) and, on every read
//!   call, try-locks the spool `LOCK` exclusively; a lock that is not free fails the step. A tree
//!   digest (path, type, size, mode, mtime and ctime in nanoseconds, content, and the root) is
//!   identical before and after, and no `LOCK` is created where none existed. Controls prove the
//!   recorder and the lock hook can fail.
//! - Read-only copy: [`DenyWritesSpoolIo`] refuses every mutating call with `EROFS`; inspection
//!   through it equals the host inspection and needs no privilege. The 0o555-directory proof needs
//!   an unprivileged uid; it is `#[ignore]`d by default and fails (never passes) when the process
//!   can still create a file in the tree.
//! - Lock-free verified payload reads through [`read_verified_payload`], with exact errors.
//! - Every step prints one CAPLOG record whose verdict, expected, and observed values are computed
//!   from the checks it made.

use std::error::Error;
use std::fmt;
use std::fs::{self, DirEntry, File, FileType, Metadata, OpenOptions, ReadDir, TryLockError};
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use fss_core::{ContentDigest, DigestAlgorithm, Sha256Hasher, sha256};
use fss_object::{
    CorruptionKind, ForeignEntry, ForeignReason, HostSpoolIo, MAX_OBJECT_BYTES, OrphanedStaging,
    RecordingSpoolIo, SPOOL_HOLDS_DIR, SPOOL_LOCK_FILE, SPOOL_OBJECTS_DIR, SPOOL_STAGING_DIR,
    SpoolError, SpoolInspection, SpoolIo, SpoolIoCall, SpoolLimits, StagingSpool, inspect,
    inspect_with_io, read_verified_payload,
};

type TestResult = Result<(), Box<dyn Error>>;

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
// Read-only capabilities.
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

    fn acquired(&self) -> usize {
        self.probes()
            .iter()
            .filter(|(_, _, probe)| *probe == LockProbe::Acquired)
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

/// Inspects through [`LockHookSpoolIo`] and checks the read-only proof: no mutating call, the
/// spool `LOCK` exclusively lockable during every read, and an unchanged tree digest.
fn inspect_hooked(
    step: &mut CapStep,
    key: &str,
    root: &Path,
    limits: &SpoolLimits,
) -> Result<Result<SpoolInspection, SpoolError>, Box<dyn Error>> {
    let io = LockHookSpoolIo::new(vec![root.join(SPOOL_LOCK_FILE)]);
    let digest_before = tree_digest(root)?;
    let result = inspect_with_io(root, limits, &io);
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

// ---------------------------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------------------------

fn fresh_root(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("spool_inspect_contract")
        .join(test_name);
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn limits(max_objects: usize, max_scan: usize) -> SpoolLimits {
    SpoolLimits::new(max_objects, 1 << 20, 4096, max_scan)
}

fn hex(digest: ContentDigest) -> String {
    digest.to_text().trim_start_matches("sha256:").to_owned()
}

fn staged_spool(root: &Path, payloads: &[&[u8]]) -> Result<Vec<ContentDigest>, Box<dyn Error>> {
    let mut spool = StagingSpool::open(root, limits(16, 32))?;
    let mut digests = Vec::new();
    for payload in payloads {
        let receipt = spool.stage_bytes(payload)?;
        spool.verify(receipt.digest)?;
        digests.push(receipt.digest);
    }
    digests.sort();
    Ok(digests)
}

fn copy_dir_filtered(src: &Path, dst: &Path, skip_lock: bool) -> TestResult {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        if skip_lock && entry.file_name() == SPOOL_LOCK_FILE {
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

fn check_flags(step: &mut CapStep, inspection: &SpoolInspection, holds: bool, missing: bool) {
    step.check(
        "holds_migration_pending",
        holds,
        inspection.holds_migration_pending,
    );
    step.check("missing_layout", missing, inspection.missing_layout);
    step.check("over_capacity", false, inspection.over_capacity);
}

// ---------------------------------------------------------------------------------------------
// Differential corpora.
// ---------------------------------------------------------------------------------------------

#[test]
fn test_spool_differential_clean() -> TestResult {
    let mut step = CapStep::new("spool_differential_clean");
    let root = fresh_root("differential_clean")?;
    let copy = fresh_root("differential_clean_copy")?;
    let l = limits(16, 32);
    let digests = staged_spool(&root, &[b"hello world", b"another verified object"])?;
    copy_dir_all(&root, &copy)?;

    let inspection = inspect_hooked(&mut step, "inspect", &root, &l)??;
    let opened = StagingSpool::open(&copy, l)?;
    step.check_equal(
        "report_vs_open",
        opened.recovery_report(),
        &inspection.report,
    );
    step.check_debug("admitted", &digests, &inspection.report.admitted);
    step.check("admitted_count", 2_usize, inspection.report.admitted.len());
    check_flags(&mut step, &inspection, false, false);
    step.check("is_clean", true, inspection.is_clean());
    step.finish()
}

#[test]
fn test_spool_differential_orphaned_staging() -> TestResult {
    let mut step = CapStep::new("spool_differential_orphaned_staging");
    let root = fresh_root("differential_orphaned_staging")?;
    let copy = fresh_root("differential_orphaned_staging_copy")?;
    let l = limits(16, 32);
    staged_spool(&root, &[b"verified object"])?;

    let orphan_bytes: &[u8] = b"uncommitted bytes in progress";
    let claimed = ContentDigest::new(DigestAlgorithm::Sha256, sha256(orphan_bytes));
    let orphan_name = format!("{}.0.tmp", hex(claimed));
    fs::write(
        root.join(SPOOL_STAGING_DIR).join(&orphan_name),
        orphan_bytes,
    )?;
    copy_dir_all(&root, &copy)?;

    let inspection = inspect_hooked(&mut step, "inspect", &root, &l)??;
    let opened = StagingSpool::open(&copy, l)?;
    step.check_equal(
        "report_vs_open",
        opened.recovery_report(),
        &inspection.report,
    );
    step.check_debug(
        "orphaned_staging",
        &vec![OrphanedStaging {
            path: Path::new(SPOOL_STAGING_DIR).join(&orphan_name),
            bytes: u64::try_from(orphan_bytes.len())?,
            claimed_digest: claimed,
        }],
        &inspection.report.orphaned_staging,
    );
    check_flags(&mut step, &inspection, false, false);
    step.check("is_clean", false, inspection.is_clean());
    step.finish()
}

#[test]
fn test_spool_differential_corrupt_object() -> TestResult {
    let mut step = CapStep::new("spool_differential_corrupt_object");
    let root = fresh_root("differential_corrupt_object")?;
    let copy = fresh_root("differential_corrupt_object_copy")?;
    let l = limits(16, 32);
    let digests = staged_spool(&root, &[b"payload to be corrupted"])?;
    let digest = digests.first().copied().ok_or("no staged digest")?;

    let obj_path = root.join(SPOOL_OBJECTS_DIR).join(hex(digest));
    let mut bytes = fs::read(&obj_path)?;
    let last = bytes.last_mut().ok_or("empty object file")?;
    *last ^= 0xFF;
    fs::write(&obj_path, bytes)?;
    copy_dir_all(&root, &copy)?;

    let inspection = inspect_hooked(&mut step, "inspect", &root, &l)??;
    let opened = StagingSpool::open(&copy, l)?;
    step.check_equal(
        "report_vs_open",
        opened.recovery_report(),
        &inspection.report,
    );
    step.check_debug(
        "corrupt_digests",
        &vec![digest],
        &inspection
            .report
            .corrupt
            .iter()
            .map(|corrupt| corrupt.digest)
            .collect::<Vec<_>>(),
    );
    step.check("admitted_count", 0_usize, inspection.report.admitted.len());
    check_flags(&mut step, &inspection, false, false);
    step.finish()
}

#[test]
fn test_spool_differential_foreign_entries() -> TestResult {
    let mut step = CapStep::new("spool_differential_foreign_entries");
    let root = fresh_root("differential_foreign_entries")?;
    let copy = fresh_root("differential_foreign_entries_copy")?;
    let l = limits(16, 32);
    staged_spool(&root, &[b"data"])?;
    fs::write(
        root.join(SPOOL_OBJECTS_DIR).join("not_a_hex_digest.txt"),
        b"intruder",
    )?;
    copy_dir_all(&root, &copy)?;

    let inspection = inspect_hooked(&mut step, "inspect", &root, &l)??;
    let opened = StagingSpool::open(&copy, l)?;
    step.check_equal(
        "report_vs_open",
        opened.recovery_report(),
        &inspection.report,
    );
    step.check_debug(
        "foreign",
        &vec![ForeignEntry {
            path: Path::new(SPOOL_OBJECTS_DIR).join("not_a_hex_digest.txt"),
            reason: ForeignReason::UnrecognizedName,
        }],
        &inspection.report.foreign,
    );
    check_flags(&mut step, &inspection, false, false);
    step.finish()
}

#[test]
fn test_spool_differential_symlink_entry() -> TestResult {
    let mut step = CapStep::new("spool_differential_symlink_entry");
    let root = fresh_root("differential_symlink_entry")?;
    let copy = fresh_root("differential_symlink_entry_copy")?;
    let l = limits(16, 32);
    staged_spool(&root, &[b"data"])?;

    let ext_dir = fresh_root("differential_symlink_external")?;
    let target_file = ext_dir.join("external.txt");
    fs::write(&target_file, b"target")?;
    std::os::unix::fs::symlink(&target_file, root.join(SPOOL_STAGING_DIR).join("link.tmp"))?;
    copy_dir_all(&root, &copy)?;

    let target_digest = tree_digest(&ext_dir)?;
    let inspection = inspect_hooked(&mut step, "inspect", &root, &l)??;
    step.check(
        "symlink_target_tree_digest",
        target_digest,
        tree_digest(&ext_dir)?,
    );
    let opened = StagingSpool::open(&copy, l)?;
    step.check_equal(
        "report_vs_open",
        opened.recovery_report(),
        &inspection.report,
    );
    step.check_debug(
        "foreign_paths",
        &vec![Path::new(SPOOL_STAGING_DIR).join("link.tmp")],
        &inspection
            .report
            .foreign
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<Vec<_>>(),
    );
    step.check_debug(
        "foreign_reasons_vs_open",
        &opened
            .recovery_report()
            .foreign
            .iter()
            .map(|entry| entry.reason)
            .collect::<Vec<_>>(),
        &inspection
            .report
            .foreign
            .iter()
            .map(|entry| entry.reason)
            .collect::<Vec<_>>(),
    );
    step.check(
        "orphaned_count",
        0_usize,
        inspection.report.orphaned_staging.len(),
    );
    step.finish()
}

#[test]
fn test_spool_differential_legacy_spool() -> TestResult {
    let mut step = CapStep::new("spool_differential_legacy_spool");
    let root = fresh_root("differential_legacy_spool")?;
    let copy = fresh_root("differential_legacy_spool_copy")?;
    let l = limits(16, 32);
    let digests = staged_spool(&root, &[b"data"])?;
    fs::remove_dir_all(root.join(SPOOL_HOLDS_DIR))?;
    copy_dir_all(&root, &copy)?;

    let inspection = inspect_hooked(&mut step, "inspect", &root, &l)??;
    step.check(
        "inspect_created_holds",
        false,
        root.join(SPOOL_HOLDS_DIR).exists(),
    );
    let opened = StagingSpool::open(&copy, l)?;
    step.check(
        "open_migrated_holds",
        true,
        copy.join(SPOOL_HOLDS_DIR).is_dir(),
    );
    step.check_equal(
        "report_vs_open",
        opened.recovery_report(),
        &inspection.report,
    );
    step.check_debug("admitted", &digests, &inspection.report.admitted);
    check_flags(&mut step, &inspection, true, false);
    step.check("is_clean", false, inspection.is_clean());
    step.finish()
}

#[test]
fn test_spool_differential_missing_layout() -> TestResult {
    let mut step = CapStep::new("spool_differential_missing_layout");
    let l = limits(16, 32);

    // An existing but empty root: open creates objects/ and staging/, inspect only reports it.
    let root = fresh_root("differential_missing_layout")?;
    let copy = fresh_root("differential_missing_layout_copy")?;
    let inspection = inspect_hooked(&mut step, "empty_root", &root, &l)??;
    step.check(
        "empty_root_objects_created",
        false,
        root.join(SPOOL_OBJECTS_DIR).exists(),
    );
    let opened = StagingSpool::open(&copy, l)?;
    step.check(
        "open_created_objects",
        true,
        copy.join(SPOOL_OBJECTS_DIR).is_dir(),
    );
    step.check_equal(
        "report_vs_open",
        opened.recovery_report(),
        &inspection.report,
    );
    check_flags(&mut step, &inspection, false, true);

    // A root that does not exist at all is reported missing and is not created.
    let absent = root.join("never-created");
    let absent_inspection = inspect_hooked(&mut step, "absent_root", &absent, &l)??;
    step.check(
        "absent_root_missing_layout",
        true,
        absent_inspection.missing_layout,
    );
    step.check("absent_root_created", false, absent.exists());
    step.finish()
}

// ---------------------------------------------------------------------------------------------
// Limits.
// ---------------------------------------------------------------------------------------------

#[test]
fn test_spool_limits_n_and_n_plus_one() -> TestResult {
    let mut step = CapStep::new("spool_limits_n_and_n_plus_one");
    let root = fresh_root("limits_n_and_n_plus_one")?;
    let copy = fresh_root("limits_n_and_n_plus_one_copy")?;
    staged_spool(&root, &[b"obj1", b"obj2"])?;

    let l_exact = limits(2, 2);
    let at_n = inspect_hooked(&mut step, "at_n", &root, &l_exact)??;
    step.check("at_n_admitted", 2_usize, at_n.report.admitted.len());

    staged_spool(&root, &[b"obj3"])?;
    copy_dir_all(&root, &copy)?;

    let inspect_err = inspect_hooked(&mut step, "at_n_plus_1", &root, &l_exact)?.map(|_| ());
    step.check_debug(
        "inspect_at_n_plus_1",
        &Err(SpoolError::EntryLimit {
            directory: root.join(SPOOL_OBJECTS_DIR),
            maximum: 2,
        }),
        &inspect_err,
    );
    let open_err = StagingSpool::open(&copy, l_exact).map(|_| ());
    step.check_debug(
        "open_at_n_plus_1",
        &Err(SpoolError::EntryLimit {
            directory: copy.join(SPOOL_OBJECTS_DIR),
            maximum: 2,
        }),
        &open_err,
    );
    step.finish()
}

#[test]
fn test_spool_limit_10k_orphaned_entries() -> TestResult {
    let mut step = CapStep::new("spool_limit_10k_orphaned_entries");
    let root = fresh_root("limit_10k_orphaned_entries")?;
    let copy = fresh_root("limit_10k_orphaned_entries_copy")?;
    staged_spool(&root, &[b"the only verified object"])?;
    let staging = root.join(SPOOL_STAGING_DIR);
    let orphans = 10_000_usize;
    for index in 0..orphans {
        let claimed = ContentDigest::new(
            DigestAlgorithm::Sha256,
            sha256(format!("orphan-{index}").as_bytes()),
        );
        fs::write(staging.join(format!("{}.0.tmp", hex(claimed))), b"x")?;
    }
    copy_dir_all(&root, &copy)?;
    step.check(
        "orphan_files_on_disk",
        orphans,
        fs::read_dir(&staging)?.count(),
    );

    let max_scan = 64_usize;
    let l = limits(16, max_scan);
    let recording = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let digest_before = tree_digest(&root)?;
    let inspect_err = inspect_with_io(&root, &l, &recording).map(|_| ());
    step.check("tree_digest", digest_before, tree_digest(&root)?);
    step.check_debug(
        "inspect",
        &Err(SpoolError::EntryLimit {
            directory: staging.clone(),
            maximum: max_scan,
        }),
        &inspect_err,
    );
    step.check_debug(
        "inspect_mutating_calls",
        &Vec::<SpoolIoCall>::new(),
        &recording.mutating_calls(),
    );
    // The scan stops at the first entry past the bound: the whole spool is listed with a small
    // constant number of reads beyond `max_scan`, never with one read per orphan.
    let dir_reads = recording.call_count(SpoolIoCall::NextDirEntry);
    step.observe_only("next_dir_entry_calls", dir_reads);
    step.check(
        "next_dir_entry_calls_bounded_by_scan_limit",
        true,
        dir_reads <= max_scan + 1 + 16,
    );

    let open_err = StagingSpool::open(&copy, l).map(|_| ());
    step.check_debug(
        "open",
        &Err(SpoolError::EntryLimit {
            directory: copy.join(SPOOL_STAGING_DIR),
            maximum: max_scan,
        }),
        &open_err,
    );
    step.finish()
}

// ---------------------------------------------------------------------------------------------
// Read-only proofs.
// ---------------------------------------------------------------------------------------------

#[test]
fn test_spool_read_only_tree_digest_proof() -> TestResult {
    let mut step = CapStep::new("spool_read_only_tree_digest_proof");
    let root = fresh_root("read_only_tree_digest_proof")?;
    let l = limits(16, 32);
    staged_spool(&root, &[b"verified object payload"])?;
    let orphan_digest = ContentDigest::new(DigestAlgorithm::Sha256, sha256(b"staged content"));
    fs::write(
        root.join(SPOOL_STAGING_DIR)
            .join(format!("{}.0.tmp", hex(orphan_digest))),
        b"staged content",
    )?;
    fs::write(
        root.join(SPOOL_OBJECTS_DIR).join("foreign_file.bin"),
        b"foreign bytes",
    )?;
    let lock = root.join(SPOOL_LOCK_FILE);
    step.check("lock_present_before", true, lock.is_file());

    // The LOCK the open left behind stays in place: the hook try-locks it during every read.
    let io = LockHookSpoolIo::new(vec![lock.clone()]);
    let digest_before = tree_digest(&root)?;
    let inspection = inspect_with_io(&root, &l, &io)?;
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
    step.check("lock_probes_all_acquired", io.probes().len(), io.acquired());
    step.check("lock_probes_taken", true, io.acquired() > 0);
    step.check("admitted_count", 1_usize, inspection.report.admitted.len());
    step.check(
        "orphaned_count",
        1_usize,
        inspection.report.orphaned_staging.len(),
    );
    step.check("foreign_count", 1_usize, inspection.report.foreign.len());

    // Control: while a writer holds the LOCK, the hook reports it and inspection still works.
    let writer = File::open(&lock)?;
    writer
        .try_lock()
        .map_err(|error| format!("control writer lock: {error:?}"))?;
    let held = LockHookSpoolIo::new(vec![lock.clone()]);
    let under_writer = inspect_with_io(&root, &l, &held).map(|found| found.report.admitted.len());
    drop(writer);
    step.check_debug("control_writer_inspect", &Ok(1_usize), &under_writer);
    step.check(
        "control_writer_lock_violations",
        held.probes().len(),
        held.lock_violations().len(),
    );
    step.finish()
}

#[test]
fn test_spool_read_only_no_lock_created() -> TestResult {
    let mut step = CapStep::new("spool_read_only_no_lock_created");
    let root = fresh_root("read_only_no_lock_created")?;
    let copy = fresh_root("read_only_no_lock_created_copy")?;
    let l = limits(16, 32);
    staged_spool(&root, &[b"object without a lock file"])?;
    // A copy of the layout made without the LOCK entry: a spool that no writer has opened here.
    copy_dir_filtered(&root, &copy, true)?;
    step.check(
        "lock_present_before",
        false,
        copy.join(SPOOL_LOCK_FILE).exists(),
    );

    let inspection = inspect_hooked(&mut step, "inspect", &copy, &l)??;
    step.check("lock_created", false, copy.join(SPOOL_LOCK_FILE).exists());
    step.check("admitted_count", 1_usize, inspection.report.admitted.len());
    step.finish()
}

#[test]
fn test_spool_read_only_recording_io_proof() -> TestResult {
    let mut step = CapStep::new("spool_read_only_recording_io_proof");
    let root = fresh_root("read_only_recording_io_proof")?;
    let control = fresh_root("read_only_recording_io_proof_control")?;
    let l = limits(16, 32);
    staged_spool(&root, &[b"data for recording io"])?;
    copy_dir_all(&root, &control)?;

    let recording = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let inspection = inspect_with_io(&root, &l, &recording)?;
    step.check("admitted_count", 1_usize, inspection.report.admitted.len());
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

    // Control: the same recorder sees the open's lock and fsync calls.
    let open_recording = Arc::new(RecordingSpoolIo::new(Arc::new(HostSpoolIo)));
    let io: Arc<dyn SpoolIo> = open_recording.clone();
    let opened = StagingSpool::open_with_io(&control, l, io)?;
    drop(opened);
    let open_mutating = open_recording.mutating_calls();
    step.check(
        "control_open_takes_lock",
        true,
        open_mutating.contains(&SpoolIoCall::OpenLock)
            && open_mutating.contains(&SpoolIoCall::TryLock),
    );
    step.finish()
}

#[test]
fn test_spool_read_only_copy_unprivileged() -> TestResult {
    let mut step = CapStep::new("spool_read_only_copy_unprivileged");
    let root = fresh_root("read_only_copy_unprivileged")?;
    let copy = fresh_root("read_only_copy_unprivileged_copy")?;
    let l = limits(16, 32);
    staged_spool(&root, &[b"data on a write-refusing capability"])?;
    let orphan_digest = ContentDigest::new(DigestAlgorithm::Sha256, sha256(b"orphan"));
    fs::write(
        root.join(SPOOL_STAGING_DIR)
            .join(format!("{}.0.tmp", hex(orphan_digest))),
        b"orphan",
    )?;
    copy_dir_all(&root, &copy)?;

    // Needs no privilege: every mutating call fails with EROFS whatever the uid.
    let deny = DenyWritesSpoolIo::default();
    let digest_before = tree_digest(&copy)?;
    let denied_inspection = inspect_with_io(&copy, &l, &deny)?;
    step.check("tree_digest", digest_before, tree_digest(&copy)?);
    step.check_debug("denied_calls", &Vec::<SpoolIoCall>::new(), &deny.denied());
    let host_inspection = inspect(&copy, &l)?;
    step.check_equal("inspection_vs_host", &host_inspection, &denied_inspection);
    step.check(
        "orphaned_count",
        1_usize,
        denied_inspection.report.orphaned_staging.len(),
    );

    // Control: the open cannot run on the same capability.
    let open_deny = Arc::new(DenyWritesSpoolIo::default());
    let io: Arc<dyn SpoolIo> = open_deny.clone();
    let open_kind = match StagingSpool::open_with_io(&copy, l, io) {
        Err(SpoolError::Io { kind, .. }) => Some(kind),
        Ok(_) | Err(_) => None,
    };
    step.check_debug(
        "control_open_error_kind",
        &Some(io::ErrorKind::ReadOnlyFilesystem),
        &open_kind,
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
fn test_spool_read_only_filesystem_copy() -> TestResult {
    let mut step = CapStep::new("spool_read_only_filesystem_copy");
    let root = fresh_root("read_only_filesystem_copy")?;
    let ro_root = fresh_root("read_only_filesystem_copy_ro")?;
    let l = limits(16, 32);
    staged_spool(&root, &[b"data on ro filesystem"])?;
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

    let result = inspect(&ro_root, &l).map(|found| found.report.admitted.len());
    drop(guard);
    step.check_debug("inspect_admitted", &Ok(1_usize), &result);
    step.finish()
}

#[test]
fn test_spool_read_verified_payload_lock_free() -> TestResult {
    let mut step = CapStep::new("spool_read_verified_payload_lock_free");
    let root = fresh_root("read_verified_payload_lock_free")?;
    let payload: &[u8] = b"immutable verified content bytes";
    let digests = staged_spool(&root, &[payload])?;
    let digest = digests.first().copied().ok_or("no staged digest")?;

    let io = LockHookSpoolIo::new(vec![root.join(SPOOL_LOCK_FILE)]);
    let digest_before = tree_digest(&root)?;
    let read = read_verified_payload(&root, digest, MAX_OBJECT_BYTES, &io)?;
    step.check("payload_len", payload.len(), read.len());
    step.check("payload_equal", true, read.as_slice() == payload);

    let mut raw = digest.bytes();
    raw[0] ^= 0x01;
    let bad_digest = ContentDigest::new(DigestAlgorithm::Sha256, raw);
    let missing = read_verified_payload(&root, bad_digest, MAX_OBJECT_BYTES, &io);
    step.check_debug(
        "absent_digest",
        &Err(SpoolError::Corrupt {
            digest: bad_digest,
            kind: CorruptionKind::Vanished,
        }),
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
