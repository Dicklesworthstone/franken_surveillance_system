#![forbid(unsafe_code)]
//! Integration contract tests for effect journal non-mutating inspection (DOCTOR0).
//!
//! Asserts:
//! - Differential against [`DurableEffectJournal::open`] for a verified, an indeterminate
//!   (lost-ACK), a failed, a cancelled, and an all-five-states journal: the replayed journal, the
//!   per-state obligation counts (exact, and recounted from the open side), and the indeterminate
//!   operations with their reconcile affordance. A discharged obligation is never folded into
//!   pending.
//! - Foreign trailing bytes, the byte limit at N and N+1, an oversize journal (rejected from its
//!   stat length before any read), a missing journal, and invalid layouts, all with exact results.
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
    ContentDigest, DigestAlgorithm, EffectIntent, EffectState, IdempotencyKey, ObligationId,
    ObligationState, OperationId, Sha256Hasher, TimestampNs, sha256,
};
use fss_ledger::{
    DurableLedgerLimits, ForeignRange, HostJournalReadIo, IncompleteTailPolicy, JournalError,
    JournalFileMetadata, JournalReadIo,
};
use fss_reference::{
    DurableEffectError, DurableEffectJournal, EFFECT_RECONCILE_AFFORDANCE, EffectJournalInspection,
    EffectJournalStatus, ObligationCounts,
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
    max_journal_bytes: usize,
) -> (
    Result<EffectJournalInspection, DurableEffectError>,
    Vec<JournalCall>,
) {
    let recorder = RecordingJournalReadIo::new(HostJournalReadIo);
    let result = DurableEffectJournal::inspect_with_io(&recorder, path, max_journal_bytes);
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
// Fixtures.
// ---------------------------------------------------------------------------------------------

const DEFAULT_LIMIT: usize = DurableLedgerLimits::DEFAULT_MAX_JOURNAL_BYTES;

fn fresh_dir(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("effect_journal_inspect_contract")
        .join(test_name);
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn sample_intent(op: &OperationId) -> Result<EffectIntent, Box<dyn Error>> {
    Ok(EffectIntent {
        operation_id: op.clone(),
        idempotency_key: IdempotencyKey::parse(format!("idempotency:{}", op.as_str()))?,
        effect_class: "alert.dispatch".to_string(),
        request_digest: ContentDigest::sha256(b"request_payload"),
        precondition_digest: ContentDigest::sha256(b"preconditions_payload"),
    })
}

/// Where one operation's lifecycle is driven before the journal is inspected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fate {
    /// Prepared only: the obligation stays pending.
    Pending,
    /// Committed, accepted, observed, verified: the obligation is verified.
    Verified,
    /// Committed, then failed with proof and a reason: the obligation is failed.
    Failed,
    /// Cancelled from prepared with cancel proof: the obligation is cancelled.
    Cancelled,
    /// Committed, then marked indeterminate (lost ACK): the obligation is indeterminate.
    Indeterminate,
}

fn drive(
    journal: &mut DurableEffectJournal,
    name: &str,
    fate: Fate,
) -> Result<OperationId, Box<dyn Error>> {
    let op = OperationId::parse(format!("op:{name}"))?;
    let obligation = ObligationId::parse(format!("obligation:{name}"))?;
    let _ = journal.prepare(
        sample_intent(&op)?,
        obligation,
        "channel_ack",
        TimestampNs(100),
    )?;
    let digest = ContentDigest::sha256(format!("result:{name}").as_bytes());
    match fate {
        Fate::Pending => {}
        Fate::Verified => {
            let _ =
                journal.transition(&op, EffectState::Committed, TimestampNs(110), None, None)?;
            let _ = journal.transition(
                &op,
                EffectState::AdapterAccepted,
                TimestampNs(115),
                None,
                None,
            )?;
            let _ = journal.transition(
                &op,
                EffectState::Observed,
                TimestampNs(120),
                Some(digest),
                None,
            )?;
            let _ = journal.transition(
                &op,
                EffectState::Verified,
                TimestampNs(125),
                Some(digest),
                None,
            )?;
        }
        Fate::Failed => {
            let _ =
                journal.transition(&op, EffectState::Committed, TimestampNs(110), None, None)?;
            let _ = journal.transition(
                &op,
                EffectState::Failed,
                TimestampNs(120),
                Some(digest),
                Some("provider_rejected".to_owned()),
            )?;
        }
        Fate::Cancelled => {
            let _ = journal.transition(
                &op,
                EffectState::Cancelled,
                TimestampNs(105),
                Some(digest),
                None,
            )?;
        }
        Fate::Indeterminate => {
            let _ =
                journal.transition(&op, EffectState::Committed, TimestampNs(110), None, None)?;
            let _ = journal.mark_indeterminate(&op, TimestampNs(120), "lost_ack_timeout")?;
        }
    }
    Ok(op)
}

fn write_journal(path: &Path, plan: &[(&str, Fate)]) -> Result<Vec<OperationId>, Box<dyn Error>> {
    let mut journal = DurableEffectJournal::open(path, IncompleteTailPolicy::Reject)?;
    let mut indeterminate = Vec::new();
    for (name, fate) in plan {
        let op = drive(&mut journal, name, *fate)?;
        if *fate == Fate::Indeterminate {
            indeterminate.push(op);
        }
    }
    indeterminate.sort();
    Ok(indeterminate)
}

/// Per-state counts recounted from the mutating open's replayed obligations.
fn counts_from_open(journal: &DurableEffectJournal) -> ObligationCounts {
    let mut counts = ObligationCounts::default();
    for obligation in journal.obligations() {
        counts.total += 1;
        match obligation.state {
            ObligationState::Pending => counts.pending += 1,
            ObligationState::Verified => counts.verified += 1,
            ObligationState::Failed => counts.failed += 1,
            ObligationState::Cancelled => counts.cancelled += 1,
            ObligationState::Indeterminate => counts.indeterminate += 1,
        }
    }
    counts
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

fn status_name(status: EffectJournalStatus) -> &'static str {
    match status {
        EffectJournalStatus::Absent => "absent",
        EffectJournalStatus::Present => "present",
    }
}

fn effect_error_class(error: &DurableEffectError) -> String {
    match error {
        DurableEffectError::Journal(JournalError::IncompleteTail { offset }) => {
            format!("journal.incomplete_tail(offset={offset})")
        }
        DurableEffectError::Journal(JournalError::Corrupt { offset, kind }) => {
            format!("journal.corrupt(offset={offset},kind={kind:?})")
        }
        DurableEffectError::InvalidLayout { path } => {
            format!("invalid_layout(path={})", path.display())
        }
        DurableEffectError::OverBudget { limit, actual } => {
            format!("over_budget(limit={limit},actual={actual})")
        }
        other => format!("unexpected({other:?})"),
    }
}

fn outcome_class<T>(result: &Result<T, DurableEffectError>) -> String {
    match result {
        Ok(_) => "ok".to_owned(),
        Err(error) => effect_error_class(error),
    }
}

// ---------------------------------------------------------------------------------------------
// Differential corpora over obligation states.
// ---------------------------------------------------------------------------------------------

fn obligation_corpus(
    step_name: &str,
    plan: &[(&str, Fate)],
    expected: ObligationCounts,
) -> TestResult {
    let mut step = CapStep::new(step_name);
    let dir = fresh_dir(step_name)?;
    let copy = fresh_dir(&format!("{step_name}_copy"))?;
    let journal_path = dir.join("effects.fssj");
    let expected_indeterminate = write_journal(&journal_path, plan)?;
    copy_dir_all(&dir, &copy)?;

    let len = file_len(&journal_path)?;
    let digest_before = tree_digest(&dir)?;
    let (result, calls) = inspect_recorded(&mut step, "inspect", &journal_path, DEFAULT_LIMIT);
    step.check("tree_digest", digest_before, tree_digest(&dir)?);
    let inspection = result?;
    step.check_debug(
        "inspect_calls",
        &present_calls(&journal_path, DEFAULT_LIMIT, len),
        &calls,
    );

    let opened =
        DurableEffectJournal::open(copy.join("effects.fssj"), IncompleteTailPolicy::Reject)?;
    step.check("status", "present", status_name(inspection.status));
    step.check("is_clean", true, inspection.is_clean());
    step.check_debug(
        "obligation_counts",
        &expected,
        &inspection.obligation_counts,
    );
    step.check_debug(
        "open_obligation_counts",
        &expected,
        &counts_from_open(&opened),
    );
    step.check(
        "terminal",
        expected.verified + expected.failed + expected.cancelled,
        inspection.obligation_counts.terminal(),
    );
    step.check_equal(
        "journal_vs_open",
        &Some(opened.effect_journal()),
        &inspection.journal.as_ref(),
    );
    let observed_indeterminate: Vec<(OperationId, String)> = inspection
        .indeterminate_operations
        .iter()
        .map(|info| (info.operation_id.clone(), info.reconcile_affordance.clone()))
        .collect();
    let expected_pairs: Vec<(OperationId, String)> = expected_indeterminate
        .into_iter()
        .map(|op| (op, EFFECT_RECONCILE_AFFORDANCE.to_owned()))
        .collect();
    step.check_debug(
        "indeterminate_operations",
        &expected_pairs,
        &observed_indeterminate,
    );
    step.check("incomplete_tail", None::<u64>, inspection.incomplete_tail);
    step.check_debug(
        "foreign_range",
        &None::<ForeignRange>,
        &inspection.foreign_range,
    );
    step.finish()
}

#[test]
fn test_effect_journal_differential_clean() -> TestResult {
    obligation_corpus(
        "effect_journal_differential_clean",
        &[("clean:1", Fate::Verified)],
        ObligationCounts {
            total: 1,
            verified: 1,
            ..ObligationCounts::default()
        },
    )
}

#[test]
fn test_effect_journal_differential_indeterminate_lost_ack() -> TestResult {
    obligation_corpus(
        "effect_journal_differential_indeterminate_lost_ack",
        &[("lostack:1", Fate::Indeterminate)],
        ObligationCounts {
            total: 1,
            indeterminate: 1,
            ..ObligationCounts::default()
        },
    )
}

#[test]
fn test_effect_journal_differential_failed() -> TestResult {
    obligation_corpus(
        "effect_journal_differential_failed",
        &[("failed:1", Fate::Failed), ("failed:2", Fate::Failed)],
        ObligationCounts {
            total: 2,
            failed: 2,
            ..ObligationCounts::default()
        },
    )
}

#[test]
fn test_effect_journal_differential_cancelled() -> TestResult {
    obligation_corpus(
        "effect_journal_differential_cancelled",
        &[
            ("cancelled:1", Fate::Cancelled),
            ("cancelled:2", Fate::Cancelled),
            ("cancelled:3", Fate::Cancelled),
        ],
        ObligationCounts {
            total: 3,
            cancelled: 3,
            ..ObligationCounts::default()
        },
    )
}

#[test]
fn test_effect_journal_differential_all_obligation_states() -> TestResult {
    obligation_corpus(
        "effect_journal_differential_all_obligation_states",
        &[
            ("mixed:pending", Fate::Pending),
            ("mixed:verified", Fate::Verified),
            ("mixed:failed:1", Fate::Failed),
            ("mixed:failed:2", Fate::Failed),
            ("mixed:cancelled:1", Fate::Cancelled),
            ("mixed:cancelled:2", Fate::Cancelled),
            ("mixed:cancelled:3", Fate::Cancelled),
            ("mixed:indeterminate", Fate::Indeterminate),
        ],
        ObligationCounts {
            total: 8,
            pending: 1,
            verified: 1,
            failed: 2,
            cancelled: 3,
            indeterminate: 1,
        },
    )
}

// ---------------------------------------------------------------------------------------------
// Tail, limit, and layout corpora.
// ---------------------------------------------------------------------------------------------

#[test]
fn test_effect_journal_differential_foreign_trailing_bytes() -> TestResult {
    let mut step = CapStep::new("effect_journal_differential_foreign_trailing_bytes");
    let dir = fresh_dir("differential_foreign_trailing_bytes")?;
    let copy = fresh_dir("differential_foreign_trailing_bytes_copy")?;
    let journal_path = dir.join("effects.fssj");
    write_journal(&journal_path, &[("foreign:1", Fate::Pending)])?;
    let committed = u64::try_from(file_len(&journal_path)?)?;
    let garbage: &[u8] = b"foreign garbage bytes appended to journal";
    append_bytes(&journal_path, garbage)?;
    copy_dir_all(&dir, &copy)?;

    let len = file_len(&journal_path)?;
    let digest_before = tree_digest(&dir)?;
    let (result, calls) = inspect_recorded(&mut step, "inspect", &journal_path, DEFAULT_LIMIT);
    step.check("tree_digest", digest_before, tree_digest(&dir)?);
    let inspection = result?;
    step.check_debug(
        "inspect_calls",
        &present_calls(&journal_path, DEFAULT_LIMIT, len),
        &calls,
    );
    step.check("status", "present", status_name(inspection.status));
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
    step.check_debug(
        "obligation_counts",
        &ObligationCounts {
            total: 1,
            pending: 1,
            ..ObligationCounts::default()
        },
        &inspection.obligation_counts,
    );
    step.check("is_clean", false, inspection.is_clean());

    let expected_open = format!("journal.corrupt(offset={committed},kind=RecordMagic)");
    let copy_journal = copy.join("effects.fssj");
    let reject = DurableEffectJournal::open(&copy_journal, IncompleteTailPolicy::Reject);
    step.check("open_reject", expected_open.clone(), outcome_class(&reject));
    let truncate = DurableEffectJournal::open(&copy_journal, IncompleteTailPolicy::Truncate);
    step.check("open_truncate", expected_open, outcome_class(&truncate));
    step.check(
        "open_left_copy_untouched",
        u64::try_from(len)?,
        fs::metadata(&copy_journal)?.len(),
    );
    step.finish()
}

#[test]
fn test_effect_journal_limits_n_and_n_plus_one() -> TestResult {
    let mut step = CapStep::new("effect_journal_limits_n_and_n_plus_one");
    let dir = fresh_dir("limits_n_and_n_plus_one")?;
    let journal_path = dir.join("limits.fssj");
    write_journal(&journal_path, &[("limits:1", Fate::Pending)])?;
    let len = file_len(&journal_path)?;

    let (exact, exact_calls) = inspect_recorded(&mut step, "at_n", &journal_path, len);
    step.check_debug(
        "at_n_calls",
        &present_calls(&journal_path, len, len),
        &exact_calls,
    );
    step.check("at_n", "ok".to_owned(), outcome_class(&exact));
    step.check(
        "at_n_obligations",
        Some(1_usize),
        exact
            .as_ref()
            .ok()
            .map(|inspection| inspection.obligation_counts.total),
    );

    let under = len - 1;
    let (over, over_calls) = inspect_recorded(&mut step, "at_n_minus_1", &journal_path, under);
    step.check_debug(
        "at_n_minus_1_calls",
        &stat_only_calls(&journal_path),
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
fn test_effect_journal_oversize_journal_rejected_before_read() -> TestResult {
    let mut step = CapStep::new("effect_journal_oversize_journal_rejected_before_read");
    let dir = fresh_dir("oversize_journal_rejected_before_read")?;
    let journal_path = dir.join("oversize.fssj");
    write_journal(&journal_path, &[("oversize:1", Fate::Pending)])?;
    append_bytes(&journal_path, &vec![0x5a_u8; 1 << 20])?;
    let len = file_len(&journal_path)?;
    let limit = 4096_usize;

    let digest_before = tree_digest(&dir)?;
    let (result, calls) = inspect_recorded(&mut step, "inspect", &journal_path, limit);
    step.check("tree_digest", digest_before, tree_digest(&dir)?);
    step.check(
        "inspect",
        format!("over_budget(limit={limit},actual={len})"),
        outcome_class(&result),
    );
    step.check_debug(
        "inspect_calls_without_read",
        &stat_only_calls(&journal_path),
        &calls,
    );
    step.finish()
}

#[test]
fn test_effect_journal_missing_journal() -> TestResult {
    let mut step = CapStep::new("effect_journal_missing_journal");
    let dir = fresh_dir("missing_journal")?;
    let missing = dir.join("nonexistent.fssj");

    let digest_before = tree_digest(&dir)?;
    let (result, calls) = inspect_recorded(&mut step, "inspect", &missing, DEFAULT_LIMIT);
    step.check("tree_digest", digest_before, tree_digest(&dir)?);
    let inspection = result?;
    step.check_debug("inspect_calls", &stat_only_calls(&missing), &calls);
    step.check("status", "absent", status_name(inspection.status));
    step.check("is_absent", true, inspection.is_absent());
    step.check("journal_replayed", false, inspection.journal.is_some());
    step.check_debug(
        "obligation_counts",
        &ObligationCounts::default(),
        &inspection.obligation_counts,
    );
    step.check("journal_created", false, missing.exists());
    step.finish()
}

#[test]
fn test_effect_journal_invalid_layout() -> TestResult {
    let mut step = CapStep::new("effect_journal_invalid_layout");
    let dir = fresh_dir("invalid_layout")?;

    let dir_journal = dir.join("dir.fssj");
    fs::create_dir(&dir_journal)?;
    let target_file = dir.join("target.file");
    fs::write(&target_file, b"target")?;
    let symlink_journal = dir.join("symlink.fssj");
    std::os::unix::fs::symlink(&target_file, &symlink_journal)?;

    let digest_before = tree_digest(&dir)?;
    for (key, path) in [("directory", &dir_journal), ("symlink", &symlink_journal)] {
        let (result, calls) = inspect_recorded(&mut step, key, path, DEFAULT_LIMIT);
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

// ---------------------------------------------------------------------------------------------
// Read-only proofs.
// ---------------------------------------------------------------------------------------------

#[test]
fn test_effect_journal_read_only_tree_digest_proof() -> TestResult {
    let mut step = CapStep::new("effect_journal_read_only_tree_digest_proof");
    let dir = fresh_dir("read_only_tree_digest_proof")?;
    let journal_path = dir.join("proof.fssj");
    write_journal(&journal_path, &[("proof:1", Fate::Indeterminate)])?;

    let digest_before = tree_digest(&dir)?;
    let (result, _) = inspect_recorded(&mut step, "inspect", &journal_path, DEFAULT_LIMIT);
    let digest_after = tree_digest(&dir)?;
    step.check("tree_digest", digest_before, digest_after);
    step.check(
        "inspect_indeterminate",
        Some(1_usize),
        result
            .as_ref()
            .ok()
            .map(|inspection| inspection.obligation_counts.indeterminate),
    );
    step.finish()
}

#[test]
fn test_effect_journal_read_only_recording_io_proof() -> TestResult {
    let mut step = CapStep::new("effect_journal_read_only_recording_io_proof");
    let dir = fresh_dir("read_only_recording_io_proof")?;
    let journal_path = dir.join("recording.fssj");
    write_journal(&journal_path, &[("rec:1", Fate::Pending)])?;
    let len = file_len(&journal_path)?;

    // The inspection itself: every call is a read, the journal is exclusively lockable around
    // each call, and its inode never changes.
    let recorder = RecordingJournalReadIo::new(HostJournalReadIo);
    let inspection =
        DurableEffectJournal::inspect_with_io(&recorder, &journal_path, DEFAULT_LIMIT)?;
    step.check("status", "present", status_name(inspection.status));
    step.check_debug(
        "calls",
        &present_calls(&journal_path, DEFAULT_LIMIT, len),
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
    let writer = File::open(&journal_path)?;
    writer
        .try_lock()
        .map_err(|error| format!("control writer lock: {error:?}"))?;
    let held = RecordingJournalReadIo::new(HostJournalReadIo);
    let under_writer =
        DurableEffectJournal::inspect_with_io(&held, &journal_path, DEFAULT_LIMIT).map(|_| ());
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
    let control_journal = control_dir.join("control.fssj");
    write_journal(&control_journal, &[("control:1", Fate::Pending)])?;
    let appending = RecordingJournalReadIo::new(AppendingJournalReadIo);
    let control_result =
        DurableEffectJournal::inspect_with_io(&appending, &control_journal, DEFAULT_LIMIT)
            .map(|_| ());
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
fn test_effect_journal_read_only_copy_unprivileged() -> TestResult {
    let mut step = CapStep::new("effect_journal_read_only_copy_unprivileged");
    let dir = fresh_dir("read_only_copy_unprivileged")?;
    let copy = fresh_dir("read_only_copy_unprivileged_copy")?;
    let journal_path = dir.join("ro.fssj");
    write_journal(&journal_path, &[("ro:1", Fate::Indeterminate)])?;
    copy_dir_all(&dir, &copy)?;
    let copy_journal = copy.join("ro.fssj");
    let len = file_len(&copy_journal)?;

    // Needs no privilege: the inode stamps (no uid can set a ctime back), the exclusive lock
    // probes, and the tree digest see a write whoever makes it.
    let digest_before = tree_digest(&copy)?;
    let (result, calls) = inspect_recorded(&mut step, "inspect", &copy_journal, DEFAULT_LIMIT);
    step.check("tree_digest", digest_before, tree_digest(&copy)?);
    let inspection = result?;
    step.check_debug(
        "inspect_calls",
        &present_calls(&copy_journal, DEFAULT_LIMIT, len),
        &calls,
    );
    step.check_debug(
        "obligation_counts",
        &ObligationCounts {
            total: 1,
            indeterminate: 1,
            ..ObligationCounts::default()
        },
        &inspection.obligation_counts,
    );
    step.finish()
}

#[test]
#[ignore = "needs an unprivileged uid (a 0o555 tree does not stop CAP_DAC_OVERRIDE); a privileged run fails, never passes"]
fn test_effect_journal_read_only_filesystem_copy() -> TestResult {
    let mut step = CapStep::new("effect_journal_read_only_filesystem_copy");
    let dir = fresh_dir("read_only_filesystem_copy")?;
    let ro_dir = fresh_dir("read_only_filesystem_copy_ro")?;
    let journal_path = dir.join("ro.fssj");
    write_journal(&journal_path, &[("ro:1", Fate::Pending)])?;
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

    let (result, _) =
        inspect_recorded(&mut step, "inspect", &ro_dir.join("ro.fssj"), DEFAULT_LIMIT);
    drop(guard);
    step.check("inspect", "ok".to_owned(), outcome_class(&result));
    step.finish()
}
