#![forbid(unsafe_code)]
//! Integration contract tests for durable reference ledger non-mutating inspection (DOCTOR0).
//!
//! Asserts:
//! - Differential against [`DurableReferenceLedger::open`] across the clean ledger, every
//!   [`AppendPhase`] via fault injection (enumerated by exhaustive matches with no wildcard arm),
//!   foreign trailing bytes, the byte limit at N and N+1, an oversize journal (rejected from its
//!   stat length before any read), a missing journal, and invalid layouts.
//! - Read-only proof: every inspection runs through [`RecordingJournalReadIo`], which records each
//!   call, try-locks the journal exclusively around it, and stamps the journal inode (device,
//!   inode, length, mode, mtime and ctime in nanoseconds) before and after it. A lock that is not
//!   free or a changed stamp is a mutating call. Two controls prove the recorder can fail.
//! - Read-only proof: a tree digest (relative path, type, size, mode, mtime and ctime in
//!   nanoseconds, content, and the root directory itself) is identical before and after.
//! - Read-only copy: the unprivileged proof runs on a copy through the recorder and needs no
//!   privilege. The 0o555-directory proof needs an unprivileged uid; it is `#[ignore]`d by
//!   default and fails (never passes) when the process can still create a file in the tree.
//! - Every step prints one CAPLOG record whose verdict, expected, and observed values are computed
//!   from the checks it made.

use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, DigestAlgorithm, EvidenceDelta, ObjectId, Plane,
    Sha256Hasher, TimestampNs, sha256,
};
use fss_ledger::{
    AppendPhase, DurableLedgerError, DurableLedgerLimits, DurableLedgerStatus,
    DurableReferenceLedger, ForeignRange, HostJournalReadIo, IncompleteTailPolicy, JournalError,
    JournalFileMetadata, JournalReadIo, LedgerInspection, inspect_durable_with_io,
};

type TestResult = Result<(), Box<dyn Error>>;

const SITE: &str = "site-ledger-inspect";

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
// Read-only recorder for the journal read capability.
// ---------------------------------------------------------------------------------------------

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
        Err(fs::TryLockError::WouldBlock) => LockProbe::WouldBlock,
        Err(fs::TryLockError::Error(error)) => LockProbe::Failed(error.kind()),
    }
}

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
/// exclusively on a fresh open file description and stamps its inode. [`JournalReadIo`] exposes
/// only reads, so a mutating inspection has to bypass the capability; the lock probe and the
/// stamps are what see such a bypass.
struct RecordingJournalReadIo<T: JournalReadIo> {
    inner: T,
    observations: Mutex<Vec<JournalObservation>>,
}

impl<T: JournalReadIo> RecordingJournalReadIo<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
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

    /// Calls around which the journal was locked or changed.
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

impl<T: JournalReadIo> JournalReadIo for RecordingJournalReadIo<T> {
    fn symlink_metadata(&self, path: &Path) -> io::Result<JournalFileMetadata> {
        self.observe(
            path,
            || self.inner.symlink_metadata(path),
            |_| JournalCall::SymlinkMetadata {
                path: path.to_path_buf(),
            },
        )
    }

    fn read_bounded(&self, path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
        self.observe(
            path,
            || self.inner.read_bounded(path, max_bytes),
            |result| JournalCall::ReadBounded {
                path: path.to_path_buf(),
                max_bytes,
                returned: result.as_ref().ok().map(Vec::len),
            },
        )
    }
}

/// Control capability: reads like the host, then appends one byte inside `read_bounded`, as a
/// mutating inspection would. The recorder must flag that call.
struct AppendingJournalReadIo;

impl JournalReadIo for AppendingJournalReadIo {
    fn symlink_metadata(&self, path: &Path) -> io::Result<JournalFileMetadata> {
        HostJournalReadIo.symlink_metadata(path)
    }

    fn read_bounded(&self, path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
        let bytes = HostJournalReadIo.read_bounded(path, max_bytes)?;
        let mut file = OpenOptions::new().append(true).open(path)?;
        file.write_all(&[0])?;
        Ok(bytes)
    }
}

/// Inspects through a fresh recorder and checks that no call was mutating.
fn inspect_recorded(
    step: &mut CapStep,
    key: &str,
    path: &Path,
    limits: DurableLedgerLimits,
) -> (
    Result<LedgerInspection, DurableLedgerError>,
    Vec<JournalCall>,
) {
    let recorder = RecordingJournalReadIo::new(HostJournalReadIo);
    let result = inspect_durable_with_io(&recorder, path, SITE, limits);
    step.check_debug(
        &format!("{key}_mutating_calls"),
        &Vec::<String>::new(),
        &recorder.mutating_calls(),
    );
    (result, recorder.calls())
}

fn present_calls(path: &Path, max_journal_bytes: usize, file_len: usize) -> Vec<JournalCall> {
    vec![
        JournalCall::SymlinkMetadata {
            path: path.to_path_buf(),
        },
        JournalCall::ReadBounded {
            path: path.to_path_buf(),
            max_bytes: max_journal_bytes + 1,
            returned: Some(file_len),
        },
    ]
}

fn stat_only_calls(path: &Path) -> Vec<JournalCall> {
    vec![JournalCall::SymlinkMetadata {
        path: path.to_path_buf(),
    }]
}

// ---------------------------------------------------------------------------------------------
// Append-phase enumeration: exhaustive matches, no wildcard arm.
// ---------------------------------------------------------------------------------------------

/// Successor of each [`AppendPhase`] in declaration order. A new phase does not compile until it
/// is given an arm here, which places it in [`ALL_APPEND_PHASES`].
const fn next_append_phase(phase: AppendPhase) -> Option<AppendPhase> {
    match phase {
        AppendPhase::BodyWrite => Some(AppendPhase::BodySync),
        AppendPhase::BodySync => Some(AppendPhase::CommitWrite),
        AppendPhase::CommitWrite => Some(AppendPhase::CommitSync),
        AppendPhase::CommitSync => Some(AppendPhase::ReconcileRead),
        AppendPhase::ReconcileRead => Some(AppendPhase::ReconcileTruncate),
        AppendPhase::ReconcileTruncate => Some(AppendPhase::ReconcileSync),
        AppendPhase::ReconcileSync => Some(AppendPhase::ReconcileSeek),
        AppendPhase::ReconcileSeek => None,
    }
}

/// Declaration ordinal of each phase; exhaustive, so it too changes with the enum.
const fn append_phase_ordinal(phase: AppendPhase) -> usize {
    match phase {
        AppendPhase::BodyWrite => 0,
        AppendPhase::BodySync => 1,
        AppendPhase::CommitWrite => 2,
        AppendPhase::CommitSync => 3,
        AppendPhase::ReconcileRead => 4,
        AppendPhase::ReconcileTruncate => 5,
        AppendPhase::ReconcileSync => 6,
        AppendPhase::ReconcileSeek => 7,
    }
}

const APPEND_PHASE_COUNT: usize = append_phase_ordinal(AppendPhase::ReconcileSeek) + 1;

/// Every [`AppendPhase`], derived by walking [`next_append_phase`] from the first phase.
const ALL_APPEND_PHASES: [AppendPhase; APPEND_PHASE_COUNT] = {
    let mut phases = [AppendPhase::BodyWrite; APPEND_PHASE_COUNT];
    let mut current = AppendPhase::BodyWrite;
    let mut index = 1;
    while index < APPEND_PHASE_COUNT {
        if let Some(next) = next_append_phase(current) {
            phases[index] = next;
            current = next;
        }
        index += 1;
    }
    phases
};

/// What an append armed to fail after `phase` leaves on disk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PhaseOutcome {
    /// The record body is on disk without its commit trailer: an incomplete tail.
    IncompleteTail,
    /// The commit trailer is on disk; only the acknowledgement was lost.
    CommittedUnacknowledged,
    /// Append never reaches this phase (reconciliation only), so the append commits.
    NoAppendFaultPoint,
}

const fn phase_outcome(phase: AppendPhase) -> PhaseOutcome {
    match phase {
        AppendPhase::BodyWrite | AppendPhase::BodySync => PhaseOutcome::IncompleteTail,
        AppendPhase::CommitWrite | AppendPhase::CommitSync => PhaseOutcome::CommittedUnacknowledged,
        AppendPhase::ReconcileRead
        | AppendPhase::ReconcileTruncate
        | AppendPhase::ReconcileSync
        | AppendPhase::ReconcileSeek => PhaseOutcome::NoAppendFaultPoint,
    }
}

// ---------------------------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------------------------

fn fresh_dir(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("durable_inspect_contract")
        .join(test_name);
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn create_delta(tag: &str, object: &str) -> Result<EvidenceDelta, Box<dyn Error>> {
    Ok(EvidenceDelta {
        delta_id: format!("delta:{tag}"),
        family: "reachability".to_owned(),
        object_id: ObjectId::parse(format!("object:{object}"))?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
        plane: Plane::Authority,
        payload_digest: ContentDigest::sha256(format!("payload:{tag}").as_bytes()),
        witness_digest: Some(ContentDigest::sha256(format!("witness:{tag}").as_bytes())),
        operation_id: None,
    })
}

fn commit_batch(durable: &mut DurableReferenceLedger, name: &str, object: &str) -> TestResult {
    let batch = durable.prepare_batch(
        BatchId::parse(format!("batch:{name}"))?,
        vec![create_delta(name, object)?],
        [],
    )?;
    durable.append(batch)?;
    Ok(())
}

fn write_ledger(path: &Path, batches: &[(&str, &str)]) -> TestResult {
    let mut ledger = DurableReferenceLedger::open(path, SITE, IncompleteTailPolicy::Reject)?;
    for (name, object) in batches {
        commit_batch(&mut ledger, name, object)?;
    }
    Ok(())
}

fn append_bytes(path: &Path, bytes: &[u8]) -> TestResult {
    let mut file = OpenOptions::new().append(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn file_len(path: &Path) -> Result<usize, Box<dyn Error>> {
    Ok(usize::try_from(fs::metadata(path)?.len())?)
}

fn copy_dir_all(src: &Path, dst: &Path) -> TestResult {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            copy_dir_all(&src_path, &dst_path)?;
        } else if ft.is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(&src_path)?, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
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

/// Digest over every entry under `root` and `root` itself: a created-and-removed temp file still
/// changes the parent directory's mtime and ctime.
fn tree_digest(root: &Path) -> Result<String, Box<dyn Error>> {
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

fn status_name(status: DurableLedgerStatus) -> &'static str {
    match status {
        DurableLedgerStatus::Absent => "absent",
        DurableLedgerStatus::Present => "present",
    }
}

fn ledger_error_class(error: &DurableLedgerError) -> String {
    match error {
        DurableLedgerError::Journal(JournalError::IncompleteTail { offset }) => {
            format!("journal.incomplete_tail(offset={offset})")
        }
        DurableLedgerError::Journal(JournalError::Corrupt { offset, kind }) => {
            format!("journal.corrupt(offset={offset},kind={kind:?})")
        }
        DurableLedgerError::Journal(JournalError::AppendIndeterminate {
            sequence,
            phase,
            source,
        }) => format!(
            "journal.append_indeterminate(sequence={sequence},phase={phase:?},source={:?}:{source})",
            source.kind()
        ),
        DurableLedgerError::InvalidLayout { path } => {
            format!("invalid_layout(path={})", path.display())
        }
        DurableLedgerError::OverBudget { limit, actual } => {
            format!("over_budget(limit={limit},actual={actual})")
        }
        other => format!("unexpected({other:?})"),
    }
}

fn outcome_class<T>(result: &Result<T, DurableLedgerError>) -> String {
    match result {
        Ok(_) => "ok".to_owned(),
        Err(error) => ledger_error_class(error),
    }
}

// ---------------------------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------------------------

#[test]
fn test_durable_append_phase_enumeration() -> TestResult {
    let mut step = CapStep::new("durable_append_phase_enumeration");
    let ordinals: Vec<usize> = ALL_APPEND_PHASES
        .iter()
        .map(|phase| append_phase_ordinal(*phase))
        .collect();
    let expected: Vec<usize> = (0..APPEND_PHASE_COUNT).collect();
    step.check_debug("ordinals_in_order", &expected, &ordinals);
    step.check_debug(
        "last_phase_has_no_successor",
        &None,
        &ALL_APPEND_PHASES
            .last()
            .and_then(|phase| next_append_phase(*phase)),
    );
    step.check("phase_count", 8_usize, ALL_APPEND_PHASES.len());
    step.finish()
}

#[test]
fn test_durable_differential_clean() -> TestResult {
    let mut step = CapStep::new("durable_differential_clean");
    let dir = fresh_dir("differential_clean")?;
    let copy = fresh_dir("differential_clean_copy")?;
    let journal = dir.join("clean.journal");
    write_ledger(&journal, &[("b1", "o1"), ("b2", "o2")])?;
    copy_dir_all(&dir, &copy)?;

    let len = file_len(&journal)?;
    let limits = DurableLedgerLimits::default();
    let digest_before = tree_digest(&dir)?;
    let (result, calls) = inspect_recorded(&mut step, "inspect", &journal, limits);
    step.check("tree_digest", digest_before, tree_digest(&dir)?);
    let inspection = result?;
    step.check_debug(
        "inspect_calls",
        &present_calls(&journal, limits.max_journal_bytes, len),
        &calls,
    );

    let opened = DurableReferenceLedger::open(
        copy.join("clean.journal"),
        SITE,
        IncompleteTailPolicy::Reject,
    )?;
    step.check("status", "present", status_name(inspection.status));
    step.check("inspect_batch_count", 2_usize, inspection.batches.len());
    step.check("open_batch_count", 2_usize, opened.batches().len());
    step.check_equal(
        "batches_vs_open",
        opened.batches(),
        inspection.batches.as_slice(),
    );
    step.check_debug(
        "anchor_vs_open",
        &opened.current().anchor,
        &inspection.snapshot.anchor,
    );
    step.check(
        "committed_len",
        u64::try_from(len)?,
        inspection.committed_len,
    );
    step.check("incomplete_tail", None::<u64>, inspection.incomplete_tail);
    step.check_debug(
        "foreign_range",
        &None::<ForeignRange>,
        &inspection.foreign_range,
    );
    step.check("is_clean", true, inspection.is_clean());
    step.finish()
}

#[test]
fn test_durable_differential_append_phases() -> TestResult {
    let mut failures = Vec::new();
    for phase in ALL_APPEND_PHASES {
        if let Err(error) = append_phase_corpus(phase) {
            failures.push(error.to_string());
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n").into())
    }
}

fn append_phase_corpus(phase: AppendPhase) -> TestResult {
    let outcome = phase_outcome(phase);
    let mut step = CapStep::new(format!("durable_phase_{phase:?}"));
    let dir = fresh_dir(&format!("phase_{phase:?}"))?;
    let copy_reject = fresh_dir(&format!("phase_{phase:?}_reject"))?;
    let copy_trunc = fresh_dir(&format!("phase_{phase:?}_trunc"))?;
    let journal = dir.join("phase.journal");

    let mut ledger = DurableReferenceLedger::open(&journal, SITE, IncompleteTailPolicy::Reject)?;
    commit_batch(&mut ledger, "initial", "init_obj")?;
    let len_before_fault = file_len(&journal)?;
    let second_batch = ledger.prepare_batch(
        BatchId::parse("batch:faulted")?,
        vec![create_delta("faulted", "fault_obj")?],
        [],
    )?;
    ledger.fail_journal_after_phase(phase);
    let append_result = ledger.append(second_batch).map(|_| ());
    let expected_append = match outcome {
        PhaseOutcome::IncompleteTail | PhaseOutcome::CommittedUnacknowledged => format!(
            "journal.append_indeterminate(sequence=2,phase={phase:?},source=Other:injected failure after {phase:?})"
        ),
        PhaseOutcome::NoAppendFaultPoint => "ok".to_owned(),
    };
    step.check("append", expected_append, outcome_class(&append_result));
    drop(ledger);

    copy_dir_all(&dir, &copy_reject)?;
    copy_dir_all(&dir, &copy_trunc)?;
    let len = file_len(&journal)?;
    let limits = DurableLedgerLimits::default();
    let digest_before = tree_digest(&dir)?;
    let (result, calls) = inspect_recorded(&mut step, "inspect", &journal, limits);
    step.check("tree_digest", digest_before, tree_digest(&dir)?);
    let inspection = result?;
    step.check_debug(
        "inspect_calls",
        &present_calls(&journal, limits.max_journal_bytes, len),
        &calls,
    );
    step.check_debug(
        "foreign_range",
        &None::<ForeignRange>,
        &inspection.foreign_range,
    );

    let reject_path = copy_reject.join("phase.journal");
    let trunc_path = copy_trunc.join("phase.journal");
    match outcome {
        PhaseOutcome::IncompleteTail => {
            let committed = u64::try_from(len_before_fault)?;
            step.check(
                "incomplete_tail",
                Some(committed),
                inspection.incomplete_tail,
            );
            step.check("committed_len", committed, inspection.committed_len);
            step.check("inspect_batch_count", 1_usize, inspection.batches.len());
            let reject =
                DurableReferenceLedger::open(&reject_path, SITE, IncompleteTailPolicy::Reject);
            step.check(
                "open_reject",
                format!("journal.incomplete_tail(offset={committed})"),
                outcome_class(&reject),
            );
            let truncated =
                DurableReferenceLedger::open(&trunc_path, SITE, IncompleteTailPolicy::Truncate)?;
            step.check(
                "open_truncate_batch_count",
                1_usize,
                truncated.batches().len(),
            );
            step.check_equal(
                "batches_vs_open_truncate",
                truncated.batches(),
                inspection.batches.as_slice(),
            );
            step.check(
                "open_truncate_file_len",
                committed,
                fs::metadata(&trunc_path)?.len(),
            );
        }
        PhaseOutcome::CommittedUnacknowledged | PhaseOutcome::NoAppendFaultPoint => {
            step.check("incomplete_tail", None::<u64>, inspection.incomplete_tail);
            step.check(
                "committed_len",
                u64::try_from(len)?,
                inspection.committed_len,
            );
            step.check("inspect_batch_count", 2_usize, inspection.batches.len());
            let opened =
                DurableReferenceLedger::open(&reject_path, SITE, IncompleteTailPolicy::Reject)?;
            step.check("open_reject_batch_count", 2_usize, opened.batches().len());
            step.check_equal(
                "batches_vs_open",
                opened.batches(),
                inspection.batches.as_slice(),
            );
        }
    }
    step.finish()
}

#[test]
fn test_durable_differential_foreign_trailing_bytes() -> TestResult {
    let mut step = CapStep::new("durable_differential_foreign_trailing_bytes");
    let dir = fresh_dir("differential_foreign_trailing_bytes")?;
    let copy = fresh_dir("differential_foreign_trailing_bytes_copy")?;
    let journal = dir.join("foreign.journal");
    write_ledger(&journal, &[("b1", "o1")])?;
    let committed = u64::try_from(file_len(&journal)?)?;
    let garbage: &[u8] = b"foreign trailing garbage bytes";
    append_bytes(&journal, garbage)?;
    copy_dir_all(&dir, &copy)?;

    let len = file_len(&journal)?;
    let limits = DurableLedgerLimits::default();
    let digest_before = tree_digest(&dir)?;
    let (result, calls) = inspect_recorded(&mut step, "inspect", &journal, limits);
    step.check("tree_digest", digest_before, tree_digest(&dir)?);
    let inspection = result?;
    step.check_debug(
        "inspect_calls",
        &present_calls(&journal, limits.max_journal_bytes, len),
        &calls,
    );
    step.check_debug(
        "foreign_range",
        &Some(ForeignRange {
            offset: committed,
            length: u64::try_from(garbage.len())?,
            digest: ContentDigest::sha256(garbage),
        }),
        &inspection.foreign_range,
    );
    step.check("incomplete_tail", None::<u64>, inspection.incomplete_tail);
    step.check("committed_len", committed, inspection.committed_len);
    step.check("inspect_batch_count", 1_usize, inspection.batches.len());
    step.check("is_clean", false, inspection.is_clean());

    let expected_open = format!("journal.corrupt(offset={committed},kind=RecordMagic)");
    let copy_journal = copy.join("foreign.journal");
    let reject = DurableReferenceLedger::open(&copy_journal, SITE, IncompleteTailPolicy::Reject);
    step.check("open_reject", expected_open.clone(), outcome_class(&reject));
    let truncate =
        DurableReferenceLedger::open(&copy_journal, SITE, IncompleteTailPolicy::Truncate);
    step.check("open_truncate", expected_open, outcome_class(&truncate));
    step.check(
        "open_left_copy_untouched",
        u64::try_from(len)?,
        fs::metadata(&copy_journal)?.len(),
    );
    step.finish()
}

#[test]
fn test_durable_limits_n_and_n_plus_one() -> TestResult {
    let mut step = CapStep::new("durable_limits_n_and_n_plus_one");
    let dir = fresh_dir("limits_n_and_n_plus_one")?;
    let journal = dir.join("limits.journal");
    write_ledger(&journal, &[("b1", "o1")])?;
    let len = file_len(&journal)?;

    let (exact, exact_calls) =
        inspect_recorded(&mut step, "at_n", &journal, DurableLedgerLimits::from(len));
    step.check_debug(
        "at_n_calls",
        &present_calls(&journal, len, len),
        &exact_calls,
    );
    step.check(
        "at_n_batch_count",
        Some(1_usize),
        exact
            .as_ref()
            .ok()
            .map(|inspection| inspection.batches.len()),
    );
    step.check("at_n", "ok".to_owned(), outcome_class(&exact));

    let under = len - 1;
    let (over, over_calls) = inspect_recorded(
        &mut step,
        "at_n_minus_1",
        &journal,
        DurableLedgerLimits::from(under),
    );
    step.check_debug(
        "at_n_minus_1_calls",
        &stat_only_calls(&journal),
        &over_calls,
    );
    step.check(
        "at_n_minus_1",
        format!("over_budget(limit={under},actual={len})"),
        outcome_class(&over),
    );
    step.finish()
}

#[test]
fn test_durable_oversize_journal_rejected_before_read() -> TestResult {
    let mut step = CapStep::new("durable_oversize_journal_rejected_before_read");
    let dir = fresh_dir("oversize_journal_rejected_before_read")?;
    let journal = dir.join("oversize.journal");
    write_ledger(&journal, &[("b1", "o1")])?;
    append_bytes(&journal, &vec![0x5a_u8; 1 << 20])?;
    let len = file_len(&journal)?;
    let limit = 4096_usize;

    let digest_before = tree_digest(&dir)?;
    let (result, calls) = inspect_recorded(
        &mut step,
        "inspect",
        &journal,
        DurableLedgerLimits::from(limit),
    );
    step.check("tree_digest", digest_before, tree_digest(&dir)?);
    step.check(
        "inspect",
        format!("over_budget(limit={limit},actual={len})"),
        outcome_class(&result),
    );
    step.check_debug(
        "inspect_calls_without_read",
        &stat_only_calls(&journal),
        &calls,
    );
    step.finish()
}

#[test]
fn test_durable_missing_journal() -> TestResult {
    let mut step = CapStep::new("durable_missing_journal");
    let dir = fresh_dir("missing_journal")?;
    let missing = dir.join("nonexistent.journal");

    let digest_before = tree_digest(&dir)?;
    let (result, calls) = inspect_recorded(
        &mut step,
        "inspect",
        &missing,
        DurableLedgerLimits::default(),
    );
    step.check("tree_digest", digest_before, tree_digest(&dir)?);
    let inspection = result?;
    step.check_debug("inspect_calls", &stat_only_calls(&missing), &calls);
    step.check("status", "absent", status_name(inspection.status));
    step.check("inspect_batch_count", 0_usize, inspection.batches.len());
    step.check("committed_len", 0_u64, inspection.committed_len);
    step.check("journal_created", false, missing.exists());
    step.finish()
}

#[test]
fn test_durable_invalid_layout() -> TestResult {
    let mut step = CapStep::new("durable_invalid_layout");
    let dir = fresh_dir("invalid_layout")?;

    let dir_journal = dir.join("dir.journal");
    fs::create_dir(&dir_journal)?;
    let target_file = dir.join("target.file");
    fs::write(&target_file, b"target")?;
    let symlink_journal = dir.join("symlink.journal");
    std::os::unix::fs::symlink(&target_file, &symlink_journal)?;

    let digest_before = tree_digest(&dir)?;
    for (key, path) in [("directory", &dir_journal), ("symlink", &symlink_journal)] {
        let (result, calls) =
            inspect_recorded(&mut step, key, path, DurableLedgerLimits::default());
        step.check(
            key,
            format!("invalid_layout(path={})", path.display()),
            outcome_class(&result),
        );
        step.check_debug(&format!("{key}_calls"), &stat_only_calls(path), &calls);
    }
    step.check("tree_digest", digest_before, tree_digest(&dir)?);
    step.finish()
}

#[test]
fn test_durable_read_only_tree_digest_proof() -> TestResult {
    let mut step = CapStep::new("durable_read_only_tree_digest_proof");
    let dir = fresh_dir("read_only_tree_digest_proof")?;
    let journal = dir.join("proof.journal");
    write_ledger(&journal, &[("b1", "o1")])?;

    let digest_before = tree_digest(&dir)?;
    let (result, _) = inspect_recorded(
        &mut step,
        "inspect",
        &journal,
        DurableLedgerLimits::default(),
    );
    let digest_after = tree_digest(&dir)?;
    step.check("tree_digest", digest_before, digest_after);
    step.check(
        "inspect_batch_count",
        Some(1_usize),
        result
            .as_ref()
            .ok()
            .map(|inspection| inspection.batches.len()),
    );
    step.finish()
}

#[test]
fn test_durable_read_only_recording_io_proof() -> TestResult {
    let mut step = CapStep::new("durable_read_only_recording_io_proof");
    let dir = fresh_dir("read_only_recording_io_proof")?;
    let journal = dir.join("recording.journal");
    write_ledger(&journal, &[("b1", "o1")])?;
    let len = file_len(&journal)?;
    let limits = DurableLedgerLimits::default();

    // The inspection itself: every call is a read, the journal is exclusively lockable around
    // each call, and its inode never changes.
    let recorder = RecordingJournalReadIo::new(HostJournalReadIo);
    let inspection = inspect_durable_with_io(&recorder, &journal, SITE, limits)?;
    step.check("inspect_batch_count", 1_usize, inspection.batches.len());
    step.check_debug(
        "calls",
        &present_calls(&journal, limits.max_journal_bytes, len),
        &recorder.calls(),
    );
    step.check_debug(
        "mutating_calls",
        &Vec::<String>::new(),
        &recorder.mutating_calls(),
    );
    step.check(
        "lock_probes_acquired",
        4_usize,
        recorder
            .observations()
            .iter()
            .flat_map(|observation| [observation.probe_before, observation.probe_after])
            .filter(|probe| *probe == LockProbe::Acquired)
            .count(),
    );

    // Control 1: while a writer holds the exclusive journal lock, the recorder flags every call,
    // and the lock-free inspection still succeeds.
    let writer = File::open(&journal)?;
    writer
        .try_lock()
        .map_err(|error| format!("control writer lock: {error:?}"))?;
    let held = RecordingJournalReadIo::new(HostJournalReadIo);
    let under_writer = inspect_durable_with_io(&held, &journal, SITE, limits).map(|_| ());
    drop(writer);
    step.check(
        "control_writer_inspect",
        "ok".to_owned(),
        outcome_class(&under_writer),
    );
    step.check(
        "control_writer_mutating_calls",
        2_usize,
        held.mutating_calls().len(),
    );

    // Control 2: a capability that appends inside `read_bounded` is flagged on that call only.
    let control_dir = fresh_dir("read_only_recording_io_proof_control")?;
    let control_journal = control_dir.join("control.journal");
    write_ledger(&control_journal, &[("b1", "o1")])?;
    let appending = RecordingJournalReadIo::new(AppendingJournalReadIo);
    let control_result =
        inspect_durable_with_io(&appending, &control_journal, SITE, limits).map(|_| ());
    step.check(
        "control_append_inspect",
        "ok".to_owned(),
        outcome_class(&control_result),
    );
    let flagged: Vec<bool> = appending
        .observations()
        .iter()
        .map(|observation| observation.violation().is_some())
        .collect();
    step.check_debug("control_append_flagged", &vec![false, true], &flagged);
    step.finish()
}

#[test]
fn test_durable_read_only_copy_unprivileged() -> TestResult {
    let mut step = CapStep::new("durable_read_only_copy_unprivileged");
    let dir = fresh_dir("read_only_copy_unprivileged")?;
    let copy = fresh_dir("read_only_copy_unprivileged_copy")?;
    let journal = dir.join("ro.journal");
    write_ledger(&journal, &[("b1", "o1")])?;
    copy_dir_all(&dir, &copy)?;
    let copy_journal = copy.join("ro.journal");
    let len = file_len(&copy_journal)?;
    let limits = DurableLedgerLimits::default();

    // Needs no privilege: the inode stamps (no uid can set a ctime back), the exclusive lock
    // probes, and the tree digest see a write whoever makes it.
    let digest_before = tree_digest(&copy)?;
    let (result, calls) = inspect_recorded(&mut step, "inspect", &copy_journal, limits);
    step.check("tree_digest", digest_before, tree_digest(&copy)?);
    let inspection = result?;
    step.check_debug(
        "inspect_calls",
        &present_calls(&copy_journal, limits.max_journal_bytes, len),
        &calls,
    );
    step.check("inspect_batch_count", 1_usize, inspection.batches.len());
    step.finish()
}

#[test]
#[ignore = "needs an unprivileged uid (a 0o555 tree does not stop CAP_DAC_OVERRIDE); a privileged run fails, never passes"]
fn test_durable_read_only_filesystem_copy() -> TestResult {
    let mut step = CapStep::new("durable_read_only_filesystem_copy");
    let dir = fresh_dir("read_only_filesystem_copy")?;
    let ro_dir = fresh_dir("read_only_filesystem_copy_ro")?;
    let journal = dir.join("ro.journal");
    write_ledger(&journal, &[("b1", "o1")])?;
    copy_dir_all(&dir, &ro_dir)?;
    let guard = ReadOnlyTreeGuard::make_read_only(&ro_dir)?;

    let sentinel = ro_dir.join("sentinel.tmp");
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

    let (result, _) = inspect_recorded(
        &mut step,
        "inspect",
        &ro_dir.join("ro.journal"),
        DurableLedgerLimits::default(),
    );
    drop(guard);
    step.check(
        "inspect_batch_count",
        Some(1_usize),
        result
            .as_ref()
            .ok()
            .map(|inspection| inspection.batches.len()),
    );
    step.finish()
}
