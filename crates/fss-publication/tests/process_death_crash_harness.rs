#![forbid(unsafe_code)]
//! Real process-death crash harness over the staging spool, the root-last local publisher, and
//! the canonical ledger commit (FSS-017/FSS-018, fss-x4a.7.5 and fss-x4a.7.6).
//!
//! The in-process crash tests elsewhere in this crate poison an instance and keep the process
//! alive. This harness kills the process instead.
//!
//! # Roles
//!
//! * **Child.** [`process_death_child_entry`] is a no-op unless [`CHILD_ENV`] is set. When it is
//!   set, the test binary is the child: it runs one publish workload against a real directory
//!   named by [`CHILD_DIR_ENV`]. The workload opens a [`LocalRootPublisher`], stages three
//!   objects in its spool, publishes one root with [`LocalRootPublisher::publish`], opens the
//!   [`DurableReferenceLedger`], and commits the root with
//!   [`LedgeredRootPublisher::commit_root`]. The child calls [`std::process::abort`] immediately
//!   before its `N`th filesystem operation. Abort raises `SIGABRT`: there is no unwinding, no
//!   destructor runs, nothing is flushed, and no lock is released except by the kernel.
//! * **Parent.** [`process_death_sweep_over_spool_publisher_and_ledger`] first runs a child with
//!   no cut. That child reports its complete, numbered operation trace, so `total_ops` is
//!   measured, not assumed. For each selected `N` in `0..=total_ops`, the parent spawns a child
//!   that aborts before operation `N` and asserts it died by `SIGABRT` at exactly the traced
//!   operation. It then reopens the spool, publisher, and ledger in the parent, checks the
//!   invariants below against an oracle computed from the trace prefix, re-runs the publish to
//!   completion, and reopens again.
//!
//! # Counting operations deterministically
//!
//! The child opens the publisher through the test constructor [`LocalRootPublisher::open_with_io`]
//! with a wrapping [`SpoolIo`] capability. Every filesystem call of the publisher and of its
//! owned spool (reads included) goes through that one value and gets the next index. The ledger
//! is not routed through the capability, and `fss-ledger` is unchanged. Its operations are
//! counted as follows:
//!
//! * `ledger_open` is counted by the workload immediately before [`DurableReferenceLedger::open`].
//! * The four mutating journal steps of the one append (`journal_body_write`,
//!   `journal_body_sync`, `journal_commit_write`, `journal_commit_sync`) are the last four
//!   operations of the workload. To abort before step `k + 1`, the child arms the existing
//!   one-shot hook [`DurableReferenceLedger::fail_journal_after_phase`] for step `k`. The hook
//!   fires after step `k` has been applied to the file, the append returns
//!   [`RootLedgerError::LedgerIndeterminate`] without any further file operation, and the child
//!   aborts on receiving it. To abort before `journal_body_write`, the child aborts
//!   immediately after the preceding counted operation (a spool read). Between that read and the
//!   body write the journal only inspects its own length, so the disk state is the same.
//!
//! No wall clock, sleep, or kill signal is involved. The parent checks that each abort
//! happened at the same traced operation as the no-cut run, and that two independent sweeps
//! observe byte-identical post-crash and final states for every `N`.
//!
//! # Invariants checked after every abort
//!
//! * (a) A root reported `Durable` has every closure object `Verified` in the spool, and each
//!   object's raw bytes on disk rehash to its digest independently of the spool.
//! * (b) The ledger never names a root that is not durable on disk. An [`UnbackedLedgerClaim`]
//!   appears only in the damage probe, where the harness flips a byte of the root record.
//! * (c) A durable, unledgered root is reported as explicit [`RootLedgerState::PendingLedger`].
//! * (d) Orphaned staging files are reported, exactly as the trace predicts, and never admitted.
//!   An incomplete ledger tail is refused by an `IncompleteTailPolicy::Reject` open.
//! * (e) Re-running the same publish converges. The slot ends with exactly one ledger batch,
//!   further retries return [`RootLedgerOutcome::AlreadyLedgered`], and the final state matches
//!   the no-cut reference except for the reported orphaned staging files, which are never
//!   deleted implicitly. The whole sweep runs twice in separate directories, and both runs
//!   must produce byte-identical post-crash and final states.
//!
//! # Bounded sweep
//!
//! Aborting before a read-only operation leaves the same disk state as aborting before the next
//! mutating operation. The sweep therefore covers every `N` whose operation is mutating
//! (directory creation, lock-file creation, create, write, fsync, rename, remove, ledger open,
//! and the four journal steps), every `N` at a phase boundary, `N = 0`, and
//! `N = total_ops`. Every distinct post-crash disk state is visited. The read-only operations
//! between them are visited at a deterministic stride of [`READ_ONLY_STRIDE`]. The number of
//! spawned children is bounded by [`MAX_STEPS_PER_SWEEP`] per sweep.
//!
//! # What this does not prove
//!
//! Abort is not power loss. The kernel page cache survives the process, so a write that was
//! never fsynced is still visible to the parent. This harness proves crash consistency against
//! process death only. It does not test torn sectors, reordered writeback, lost directory
//! entries after a missing fsync, or storage that ignores flushes.
//!
//! `std::process::abort` is used rather than `std::process::exit`. Workspace lints do not
//! forbid it, and it is the stronger cut: `exit` still runs `atexit` handlers and flushes Rust's
//! standard output, while `abort` delivers `SIGABRT` with no cleanup at all. Neither kind of
//! termination runs destructors of live values. The child runs in a scratch working directory so
//! that a core dump, if the host keeps one, never lands in the source tree.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::OsString;
use std::fs::{self, DirEntry, File, FileType, Metadata, ReadDir, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use fss_core::{CaptureInterval, ContentDigest, TimestampNs};
use fss_ledger::{
    AppendPhase, DurableLedgerError, DurableReferenceLedger, IncompleteTailPolicy, JournalError,
};
use fss_object::{
    HostSpoolIo, ObjectManifest, SPOOL_OBJECT_HEADER_LEN, SpoolIo, SpoolLimits, SpoolObjectState,
    VerifiedObjectCatalog,
};
use fss_publication::{
    BrokenRootReason, LOCAL_ROOTS_DIR, LOCAL_SPOOL_DIR, LedgeredRootPublisher,
    LocalPublicationError, LocalPublicationLimits, LocalPublicationState, LocalRootPublisher,
    ROOT_RECORD_SUFFIX, ROOT_TEMP_SUFFIX, RootLedgerError, RootLedgerOutcome, RootLedgerState,
    SlotName, UnbackedLedgerClaim, root_reachability_batch_id,
};

type TestResult = Result<(), Box<dyn Error>>;

/// Environment variable that turns the child entry on: `<scenario>:count` or
/// `<scenario>:step=<N>:total=<total_ops>`.
const CHILD_ENV: &str = "FSS_PROCESS_DEATH_CHILD";
/// Environment variable naming the child's publication and ledger directory.
const CHILD_DIR_ENV: &str = "FSS_PROCESS_DEATH_DIR";
/// Exact libtest name of the child entry.
const CHILD_TEST: &str = "process_death_child_entry";
/// The one workload this harness knows.
const SCENARIO: &str = "single_root_v1";

const TRACE_PREFIX: &str = "FSS-PROCESS-DEATH-TRACE ";
const ABORT_PREFIX: &str = "FSS-PROCESS-DEATH-ABORT ";
const DONE_PREFIX: &str = "FSS-PROCESS-DEATH-DONE ";

const LINEAGE: &str = "site:one";
const SLOT: &str = "event-0001";
const PAYLOADS: [&[u8]; 3] = [
    b"clip-segment-0001",
    b"clip-segment-0002",
    b"event-metadata-v1",
];
const PUBLICATION_DIR: &str = "publication";
const JOURNAL_FILE: &str = "ledger.journal";

const PHASES: [&str; 5] = [
    "open",
    "spool_staging",
    "root_publication",
    "ledger_commit",
    "complete",
];
const PHASE_OPEN: u8 = 0;
const PHASE_STAGING: u8 = 1;
const PHASE_PUBLICATION: u8 = 2;
const PHASE_LEDGER: u8 = 3;

/// The four mutating steps of one journal append, in order.
const JOURNAL_OPS: [&str; 4] = [
    "journal_body_write",
    "journal_body_sync",
    "journal_commit_write",
    "journal_commit_sync",
];
/// Hook armed to abort before `JOURNAL_OPS[k + 1]`: it fires after `JOURNAL_OPS[k]` is applied.
const JOURNAL_FAULT_AFTER: [AppendPhase; 3] = [
    AppendPhase::BodyWrite,
    AppendPhase::BodySync,
    AppendPhase::CommitWrite,
];
const JOURNAL_OP_COUNT: u64 = 4;

/// Calls that change the file system, or the ledger file. Every such `N` is swept.
const MUTATING_CALLS: [&str; 14] = [
    "create_dir_all",
    "open_lock",
    "create_dir",
    "create_new",
    "write",
    "sync_file",
    "rename",
    "remove_file",
    "sync_directory",
    "ledger_open",
    "journal_body_write",
    "journal_body_sync",
    "journal_commit_write",
    "journal_commit_sync",
];
/// Deterministic stride over read-only operations between the mutating ones.
const READ_ONLY_STRIDE: u64 = 5;
/// Upper bound on crashed children per sweep; it keeps the whole test well under a minute.
const MAX_STEPS_PER_SWEEP: usize = 128;

// ---------------------------------------------------------------------------------------------
// Shared fixture
// ---------------------------------------------------------------------------------------------

fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(8, 16, 8, 64, SpoolLimits::new(64, 1 << 20, 4096, 64))
}

fn validity() -> Result<CaptureInterval, Box<dyn Error>> {
    Ok(CaptureInterval::new(
        TimestampNs(1_000),
        TimestampNs(2_000),
    )?)
}

fn slot() -> Result<SlotName, Box<dyn Error>> {
    Ok(SlotName::parse(SLOT)?)
}

fn manifest_of(digests: &[ContentDigest]) -> Result<ObjectManifest, Box<dyn Error>> {
    match digests {
        [first, second, metadata] => Ok(ObjectManifest::new(
            "event_archive",
            [*first, *second],
            Some(*metadata),
        )?),
        _ => Err(format!("expected three staged digests, got {}", digests.len()).into()),
    }
}

fn stage_fixture(local: &mut LocalRootPublisher) -> Result<Vec<ContentDigest>, Box<dyn Error>> {
    let mut digests = Vec::with_capacity(PAYLOADS.len());
    for payload in PAYLOADS {
        digests.push(local.stage_object(payload)?);
    }
    Ok(digests)
}

fn open_ledger(
    path: &Path,
    policy: IncompleteTailPolicy,
) -> Result<DurableReferenceLedger, Box<dyn Error>> {
    Ok(DurableReferenceLedger::open(path, LINEAGE, policy)?)
}

fn root_record_name() -> String {
    format!("{SLOT}{ROOT_RECORD_SUFFIX}")
}

fn root_temp_name() -> String {
    format!("{SLOT}{ROOT_RECORD_SUFFIX}{ROOT_TEMP_SUFFIX}")
}

// ---------------------------------------------------------------------------------------------
// Child role
// ---------------------------------------------------------------------------------------------

/// Where the child terminates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Cut {
    /// Run to completion and report the trace.
    Never,
    /// Abort immediately before the counted operation with this index.
    Before(u64),
    /// Abort immediately after the counted operation with this index returns.
    After(u64),
}

/// Host filesystem wrapped with a deterministic operation counter and one abort point.
///
/// Counters, phase, and trace are per instance; nothing is shared through global state.
#[derive(Debug)]
struct CrashIo {
    host: HostSpoolIo,
    base: PathBuf,
    cut: Cut,
    next: AtomicU64,
    phase: AtomicU8,
    trace: Mutex<Vec<String>>,
}

struct Ticket {
    index: u64,
    line: String,
}

/// Terminates the whole process with `SIGABRT` after reporting where.
fn die(when: &str, line: &str) -> ! {
    println!("{ABORT_PREFIX}{when} {line}");
    std::process::abort()
}

impl CrashIo {
    fn new(base: &Path, cut: Cut) -> Self {
        Self {
            host: HostSpoolIo,
            base: base.to_path_buf(),
            cut,
            next: AtomicU64::new(0),
            phase: AtomicU8::new(PHASE_OPEN),
            trace: Mutex::new(Vec::new()),
        }
    }

    fn set_phase(&self, phase: u8) {
        self.phase.store(phase, Ordering::SeqCst);
    }

    fn counted(&self) -> u64 {
        self.next.load(Ordering::SeqCst)
    }

    fn relative(&self, path: &Path) -> String {
        let shown = path.strip_prefix(&self.base).map_or_else(
            |_| path.display().to_string(),
            |rel| rel.display().to_string(),
        );
        if shown.is_empty() {
            ".".to_owned()
        } else {
            shown
        }
    }

    /// Counts one operation and aborts first if it is the cut.
    fn enter(&self, call: &str, path: &str) -> Ticket {
        let index = self.next.fetch_add(1, Ordering::SeqCst);
        let phase = PHASES
            .get(usize::from(self.phase.load(Ordering::SeqCst)))
            .copied()
            .unwrap_or("unknown");
        let line = format!("{index} {phase} {call} {path}");
        if self.cut == Cut::Before(index) {
            die("before", &line);
        }
        self.trace
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line.clone());
        Ticket { index, line }
    }

    /// Aborts right after the operation returns if it is the cut.
    fn leave(&self, ticket: &Ticket) {
        if self.cut == Cut::After(ticket.index) {
            die("after", &ticket.line);
        }
    }

    fn call<T>(&self, call: &str, path: &str, operation: impl FnOnce(&HostSpoolIo) -> T) -> T {
        let ticket = self.enter(call, path);
        let result = operation(&self.host);
        self.leave(&ticket);
        result
    }

    fn at(
        &self,
        call: &str,
        path: &Path,
        operation: impl FnOnce(&HostSpoolIo) -> io::Result<()>,
    ) -> io::Result<()> {
        let shown = self.relative(path);
        self.call(call, &shown, operation)
    }

    fn lines(&self) -> Vec<String> {
        self.trace
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl SpoolIo for CrashIo {
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        self.at("create_dir_all", path, |host| host.create_dir_all(path))
    }

    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.call("metadata", &self.relative(path), |host| host.metadata(path))
    }

    fn symlink_metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.call("symlink_metadata", &self.relative(path), |host| {
            host.symlink_metadata(path)
        })
    }

    fn open_lock(&self, path: &Path) -> io::Result<File> {
        self.call("open_lock", &self.relative(path), |host| {
            host.open_lock(path)
        })
    }

    fn try_lock(&self, file: &File) -> Result<(), TryLockError> {
        self.call("try_lock", "-", |host| host.try_lock(file))
    }

    fn create_dir(&self, path: &Path) -> io::Result<()> {
        self.at("create_dir", path, |host| host.create_dir(path))
    }

    fn read_dir(&self, path: &Path) -> io::Result<ReadDir> {
        self.call("read_dir", &self.relative(path), |host| host.read_dir(path))
    }

    fn next_dir_entry(&self, entries: &mut ReadDir) -> Option<io::Result<DirEntry>> {
        self.call("next_dir_entry", "-", |host| host.next_dir_entry(entries))
    }

    fn entry_file_type(&self, entry: &DirEntry) -> io::Result<FileType> {
        self.call("entry_file_type", &self.relative(&entry.path()), |host| {
            host.entry_file_type(entry)
        })
    }

    fn create_new(&self, path: &Path) -> io::Result<File> {
        self.call("create_new", &self.relative(path), |host| {
            host.create_new(path)
        })
    }

    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
        self.call("write", "-", |host| host.write(file, bytes))
    }

    fn sync_file(&self, file: &File) -> io::Result<()> {
        self.call("sync_file", "-", |host| host.sync_file(file))
    }

    fn open_read(&self, path: &Path) -> io::Result<File> {
        self.call("open_read", &self.relative(path), |host| {
            host.open_read(path)
        })
    }

    fn read_bounded(&self, file: &mut File, limit: u64) -> io::Result<Vec<u8>> {
        self.call("read", "-", |host| host.read_bounded(file, limit))
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let shown = format!("{}->{}", self.relative(from), self.relative(to));
        self.call("rename", &shown, |host| host.rename(from, to))
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.at("remove_file", path, |host| host.remove_file(path))
    }

    fn sync_directory(&self, path: &Path) -> io::Result<()> {
        self.at("sync_directory", path, |host| host.sync_directory(path))
    }
}

/// Parsed [`CHILD_ENV`] value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildMode {
    Count,
    Abort { step: u64, total: u64 },
}

fn parse_child_mode(spec: &str) -> Result<ChildMode, Box<dyn Error>> {
    let rest = spec
        .strip_prefix(SCENARIO)
        .and_then(|rest| rest.strip_prefix(':'))
        .ok_or_else(|| format!("unknown child scenario in {spec:?}"))?;
    if rest == "count" {
        return Ok(ChildMode::Count);
    }
    let (step, total) = rest
        .strip_prefix("step=")
        .and_then(|rest| rest.split_once(":total="))
        .ok_or_else(|| format!("malformed child spec {spec:?}"))?;
    Ok(ChildMode::Abort {
        step: step.parse()?,
        total: total.parse()?,
    })
}

/// Child entry. A no-op unless the parent sets [`CHILD_ENV`]; see the module documentation.
#[test]
fn process_death_child_entry() -> TestResult {
    let Some(spec) = std::env::var_os(CHILD_ENV) else {
        return Ok(());
    };
    let spec = spec
        .into_string()
        .map_err(|raw: OsString| format!("non-UTF-8 child spec {raw:?}"))?;
    let dir = std::env::var_os(CHILD_DIR_ENV)
        .map(PathBuf::from)
        .ok_or("child directory is not set")?;
    run_child(parse_child_mode(&spec)?, &dir)
}

fn run_child(mode: ChildMode, dir: &Path) -> TestResult {
    let (cut, journal_fault) = match mode {
        ChildMode::Count => (Cut::Never, None),
        ChildMode::Abort { step, total } => {
            let journal_base = total
                .checked_sub(JOURNAL_OP_COUNT)
                .ok_or("total_ops is smaller than the journal tail")?;
            if step < journal_base {
                (Cut::Before(step), None)
            } else if step == journal_base {
                let previous = step
                    .checked_sub(1)
                    .ok_or("journal body write is operation 0")?;
                (Cut::After(previous), None)
            } else if step < total {
                let offset = usize::try_from(step - journal_base - 1)?;
                let phase = JOURNAL_FAULT_AFTER
                    .get(offset)
                    .copied()
                    .ok_or("journal step out of range")?;
                (Cut::Never, Some((phase, step, journal_base)))
            } else {
                (Cut::Never, None)
            }
        }
    };
    let io = Arc::new(CrashIo::new(dir, cut));
    let slot = slot()?;
    let journal = dir.join(JOURNAL_FILE);

    io.set_phase(PHASE_OPEN);
    let spool_io: Arc<dyn SpoolIo> = io.clone();
    let mut local =
        LocalRootPublisher::open_with_io(dir.join(PUBLICATION_DIR), limits(), spool_io)?;

    io.set_phase(PHASE_STAGING);
    let manifest = manifest_of(&stage_fixture(&mut local)?)?;

    io.set_phase(PHASE_PUBLICATION);
    local.publish(&slot, &manifest)?;

    io.set_phase(PHASE_LEDGER);
    let ticket = io.enter("ledger_open", JOURNAL_FILE);
    let mut ledger = open_ledger(&journal, IncompleteTailPolicy::Reject)?;
    io.leave(&ticket);
    if let Some((phase, _, _)) = journal_fault {
        ledger.fail_journal_after_phase(phase);
    }
    let committed = {
        let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
        coordinator.commit_root(&slot, validity()?)
    };
    match (committed, journal_fault) {
        (Ok(receipt), None) => {
            if receipt.outcome != RootLedgerOutcome::Committed {
                return Err(format!("fresh commit returned {:?}", receipt.outcome).into());
            }
            for label in JOURNAL_OPS {
                let ticket = io.enter(label, JOURNAL_FILE);
                io.leave(&ticket);
            }
        }
        (Err(RootLedgerError::LedgerIndeterminate { .. }), Some((_, step, journal_base))) => {
            // The hook fired after a journal step was applied; nothing else touched the disk.
            if io.counted() != journal_base {
                return Err(format!(
                    "journal tail starts at {} but the trace put it at {journal_base}",
                    io.counted()
                )
                .into());
            }
            let offset = usize::try_from(step - journal_base)?;
            let label = JOURNAL_OPS.get(offset).ok_or("journal step out of range")?;
            die(
                "before",
                &format!("{step} ledger_commit {label} {JOURNAL_FILE}"),
            );
        }
        (Ok(receipt), Some(_)) => {
            return Err(format!("armed journal hook did not fire: {receipt:?}").into());
        }
        (Err(error), _) => return Err(error.into()),
    }

    match mode {
        ChildMode::Count => {
            let lines = io.lines();
            for line in &lines {
                println!("{TRACE_PREFIX}{line}");
            }
            println!("{DONE_PREFIX}{}", lines.len());
            Ok(())
        }
        ChildMode::Abort { step, total } if step == total => {
            die("before", &format!("{total} complete end_of_workload -"))
        }
        ChildMode::Abort { step, .. } => {
            Err(format!("child finished the workload without reaching cut {step}").into())
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Parent role: trace, oracle, snapshots
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
struct TraceOp {
    index: u64,
    phase: String,
    call: String,
    path: String,
}

impl TraceOp {
    fn parse(text: &str) -> Result<Self, Box<dyn Error>> {
        let parts: Vec<&str> = text.split(' ').collect();
        match parts.as_slice() {
            [index, phase, call, path] => Ok(Self {
                index: index.parse()?,
                phase: (*phase).to_owned(),
                call: (*call).to_owned(),
                path: (*path).to_owned(),
            }),
            _ => Err(format!("malformed trace line {text:?}").into()),
        }
    }

    fn line(&self) -> String {
        format!("{} {} {} {}", self.index, self.phase, self.call, self.path)
    }

    fn is_mutating(&self) -> bool {
        MUTATING_CALLS.contains(&self.call.as_str())
    }
}

/// What the disk must show after an abort before operation `N`, derived from the trace prefix.
#[derive(Debug, Default)]
struct Expected {
    /// Staging file names created and not renamed away.
    orphans: BTreeSet<String>,
    /// Objects renamed into place.
    admitted: BTreeSet<ContentDigest>,
    root_temp_created: bool,
    root_renamed: bool,
    body_written: bool,
    commit_written: bool,
}

impl Expected {
    fn from_prefix(performed: &[TraceOp]) -> Result<Self, Box<dyn Error>> {
        let staging = format!("{PUBLICATION_DIR}/{LOCAL_SPOOL_DIR}/staging/");
        let objects = format!("{PUBLICATION_DIR}/{LOCAL_SPOOL_DIR}/objects/");
        let root_temp = format!("{PUBLICATION_DIR}/{LOCAL_ROOTS_DIR}/{}", root_temp_name());
        let root_record = format!("{PUBLICATION_DIR}/{LOCAL_ROOTS_DIR}/{}", root_record_name());
        let mut expected = Self::default();
        for op in performed {
            match op.call.as_str() {
                "create_new" => {
                    if let Some(name) = op.path.strip_prefix(&staging) {
                        expected.orphans.insert(name.to_owned());
                    } else if op.path == root_temp {
                        expected.root_temp_created = true;
                    }
                }
                "rename" => {
                    let (from, to) = op
                        .path
                        .split_once("->")
                        .ok_or_else(|| format!("malformed rename {:?}", op.path))?;
                    if let Some(name) = from.strip_prefix(&staging) {
                        expected.orphans.remove(name);
                    }
                    if let Some(hex) = to.strip_prefix(&objects) {
                        expected
                            .admitted
                            .insert(ContentDigest::parse(format!("sha256:{hex}"))?);
                    }
                    if to == root_record {
                        expected.root_renamed = true;
                    }
                }
                "journal_body_write" => expected.body_written = true,
                "journal_commit_write" => expected.commit_written = true,
                _ => {}
            }
        }
        Ok(expected)
    }

    const fn root_temp_orphaned(&self) -> bool {
        self.root_temp_created && !self.root_renamed
    }

    const fn incomplete_tail(&self) -> bool {
        self.body_written && !self.commit_written
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Entry {
    Dir,
    File(Vec<u8>),
    Other,
}

type Snapshot = BTreeMap<String, Entry>;

/// Every entry under `root` with its exact bytes, keyed by relative path.
fn snapshot(root: &Path) -> Result<Snapshot, Box<dyn Error>> {
    let mut entries = BTreeMap::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        for entry in fs::read_dir(root.join(&relative))? {
            let entry = entry?;
            let child = relative.join(entry.file_name());
            let key = child.to_string_lossy().into_owned();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                entries.insert(key, Entry::Dir);
                pending.push(child);
            } else if file_type.is_file() {
                entries.insert(key, Entry::File(fs::read(entry.path())?));
            } else {
                entries.insert(key, Entry::Other);
            }
        }
    }
    Ok(entries)
}

fn staging_prefix() -> String {
    format!("{PUBLICATION_DIR}/{LOCAL_SPOOL_DIR}/staging/")
}

/// The snapshot without staging files, which are the only allowed divergence from the reference.
fn core_of(state: &Snapshot) -> Snapshot {
    let staging = staging_prefix();
    state
        .iter()
        .filter(|(key, _)| !key.starts_with(&staging))
        .map(|(key, entry)| (key.clone(), entry.clone()))
        .collect()
}

fn staging_names(state: &Snapshot) -> BTreeSet<String> {
    let staging = staging_prefix();
    state
        .keys()
        .filter_map(|key| key.strip_prefix(&staging).map(str::to_owned))
        .collect()
}

fn differing_keys(left: &Snapshot, right: &Snapshot) -> Vec<String> {
    left.keys()
        .chain(right.keys())
        .filter(|key| left.get(*key) != right.get(*key))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn fresh_dir(path: &Path) -> Result<PathBuf, Box<dyn Error>> {
    match fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    fs::create_dir_all(path)?;
    Ok(path.to_path_buf())
}

fn spawn_child(dir: &Path, cwd: &Path, spec: &str) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new(std::env::current_exe()?)
        .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, spec)
        .env(CHILD_DIR_ENV, dir)
        .current_dir(cwd)
        .output()?)
}

#[cfg(unix)]
fn died_by_abort(status: ExitStatus) -> bool {
    use std::os::unix::process::ExitStatusExt;
    const SIGABRT: i32 = 6;
    status.signal() == Some(SIGABRT)
}

#[cfg(not(unix))]
fn died_by_abort(status: ExitStatus) -> bool {
    // Outside Unix, abort ends the process with a nonzero code that libtest never uses.
    status.code().is_some_and(|code| code != 0 && code != 101)
}

/// Harness lines in a child's stdout. libtest prints `test <name> ... ` without a newline before
/// the test body runs, so a harness line may follow that text on the same line.
fn prefixed_lines<'a>(stdout: &'a str, prefix: &str) -> Vec<&'a str> {
    stdout
        .lines()
        .filter_map(|line| line.split_once(prefix).map(|(_, rest)| rest))
        .collect()
}

fn expected_abort_line(step: u64, trace: &[TraceOp]) -> Result<String, Box<dyn Error>> {
    let total = trace.len() as u64;
    let journal_base = total
        .checked_sub(JOURNAL_OP_COUNT)
        .ok_or("trace is shorter than the journal tail")?;
    if step == total {
        return Ok(format!("before {total} complete end_of_workload -"));
    }
    if step == journal_base {
        let previous = step
            .checked_sub(1)
            .and_then(|at| usize::try_from(at).ok())
            .and_then(|at| trace.get(at))
            .ok_or("no operation before the journal tail")?;
        return Ok(format!("after {}", previous.line()));
    }
    let op = trace
        .get(usize::try_from(step)?)
        .ok_or_else(|| format!("no traced operation {step}"))?;
    Ok(format!("before {}", op.line()))
}

/// Deterministic sweep set; see the module documentation.
fn selected_steps(trace: &[TraceOp]) -> Vec<u64> {
    let total = trace.len() as u64;
    (0..=total)
        .filter(|&step| {
            let Some(op) = usize::try_from(step).ok().and_then(|at| trace.get(at)) else {
                return true;
            };
            let previous = step
                .checked_sub(1)
                .and_then(|at| usize::try_from(at).ok())
                .and_then(|at| trace.get(at));
            let next = usize::try_from(step + 1).ok().and_then(|at| trace.get(at));
            step == 0
                || op.is_mutating()
                || previous.is_none_or(|previous| previous.phase != op.phase)
                || next.is_none_or(|next| next.phase != op.phase)
                || step % READ_ONLY_STRIDE == 0
        })
        .collect()
}

/// Reference objects and state, from the no-cut child.
struct Reference {
    trace: Vec<TraceOp>,
    digests: Vec<ContentDigest>,
    root: ContentDigest,
    core: Snapshot,
}

fn count_run(sweep: &Path, cwd: &Path) -> Result<Reference, Box<dyn Error>> {
    let dir = fresh_dir(&sweep.join("count"))?;
    let output = spawn_child(&dir, cwd, &format!("{SCENARIO}:count"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "no-cut child failed: {:?}\n{stdout}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let trace = prefixed_lines(&stdout, TRACE_PREFIX)
        .into_iter()
        .map(TraceOp::parse)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        prefixed_lines(&stdout, DONE_PREFIX),
        vec![trace.len().to_string()],
        "no-cut child did not report a complete trace"
    );
    for (position, op) in trace.iter().enumerate() {
        assert_eq!(op.index, position as u64, "trace is not densely numbered");
    }
    let tail: Vec<&str> = trace
        .iter()
        .rev()
        .take(JOURNAL_OPS.len())
        .map(|op| op.call.as_str())
        .collect();
    assert_eq!(tail, JOURNAL_OPS.iter().rev().copied().collect::<Vec<_>>());
    let before_journal = trace
        .iter()
        .rev()
        .nth(JOURNAL_OPS.len())
        .ok_or("trace has no operation before the journal tail")?;
    assert_eq!(
        (before_journal.phase.as_str(), before_journal.call.as_str()),
        ("ledger_commit", "read"),
        "the journal tail must follow a counted spool read"
    );
    let phase_order: Vec<&str> = trace.iter().fold(Vec::new(), |mut order, op| {
        if order.last() != Some(&op.phase.as_str()) {
            order.push(op.phase.as_str());
        }
        order
    });
    assert_eq!(
        phase_order,
        ["open", "spool_staging", "root_publication", "ledger_commit"]
    );

    let digests = PAYLOADS.map(ContentDigest::sha256).to_vec();
    let root = manifest_of(&digests)?.root();
    let slot = slot()?;
    {
        let mut local = LocalRootPublisher::open(dir.join(PUBLICATION_DIR), limits())?;
        assert!(local.recovery_report().is_clean());
        let mut ledger = open_ledger(&dir.join(JOURNAL_FILE), IncompleteTailPolicy::Reject)?;
        let coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
        assert!(matches!(
            coordinator.state(&slot)?,
            RootLedgerState::Ledgered { root: ledgered, .. } if ledgered == root
        ));
        assert!(coordinator.reconcile()?.is_clean());
    }
    let core = core_of(&snapshot(&dir)?);
    Ok(Reference {
        trace,
        digests,
        root,
        core,
    })
}

// ---------------------------------------------------------------------------------------------
// Parent role: one crashed step
// ---------------------------------------------------------------------------------------------

struct StepOutcome {
    phase: String,
    classes: BTreeSet<&'static str>,
    post_crash: Snapshot,
    final_state: Snapshot,
}

const CLASS_ABSENT: &str = "absent_after_crash";
const CLASS_DURABLE_CLOSURE: &str = "a_durable_closure_verified";
const CLASS_CLAIM_BACKED: &str = "b_ledger_claim_backed_by_durable_root";
const CLASS_UNBACKED_ON_DAMAGE: &str = "b_unbacked_claim_only_after_deliberate_damage";
const CLASS_PENDING: &str = "c_pending_ledger";
const CLASS_ORPHANED_STAGING: &str = "d_orphaned_staging_reported_not_admitted";
const CLASS_INCOMPLETE_TAIL: &str = "d_incomplete_ledger_tail_refused";
const CLASS_ORPHANED_ROOT_TEMP: &str = "d_orphaned_root_temp_refused_then_discarded";
const CLASS_UNREFERENCED: &str = "unreferenced_objects_reported";
const CLASS_CONVERGED: &str = "e_converged_single_batch_already_ledgered";

fn crash_and_recover(
    sweep: &Path,
    cwd: &Path,
    step: u64,
    reference: &Reference,
) -> Result<StepOutcome, Box<dyn Error>> {
    let trace = &reference.trace;
    let total = trace.len() as u64;
    let dir = fresh_dir(&sweep.join(format!("step-{step:04}")))?;
    let publication = dir.join(PUBLICATION_DIR);
    let journal = dir.join(JOURNAL_FILE);
    let slot = slot()?;

    let output = spawn_child(&dir, cwd, &format!("{SCENARIO}:step={step}:total={total}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        died_by_abort(output.status),
        "step {step}: child did not die by abort: {:?}\n{stdout}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        prefixed_lines(&stdout, ABORT_PREFIX),
        vec![expected_abort_line(step, trace)?],
        "step {step}: child aborted at a different operation than the trace predicts"
    );
    let phase = usize::try_from(step)
        .ok()
        .and_then(|at| trace.get(at))
        .map_or_else(|| "complete".to_owned(), |op| op.phase.clone());
    let performed = trace
        .get(..usize::try_from(step)?)
        .ok_or("step beyond the trace")?;
    let expected = Expected::from_prefix(performed)?;
    let post_crash = snapshot(&dir)?;
    let mut classes = BTreeSet::new();

    // Raw disk, before any owner reopens it.
    let staging_on_disk = staging_names(&post_crash);
    assert_eq!(
        staging_on_disk, expected.orphans,
        "step {step}: staging files on disk"
    );
    let root_key = format!("{PUBLICATION_DIR}/{LOCAL_ROOTS_DIR}/{}", root_record_name());
    let temp_key = format!("{PUBLICATION_DIR}/{LOCAL_ROOTS_DIR}/{}", root_temp_name());
    assert_eq!(
        post_crash.contains_key(&root_key),
        expected.root_renamed,
        "step {step}: root record"
    );
    assert_eq!(
        post_crash.contains_key(&temp_key),
        expected.root_temp_orphaned(),
        "step {step}: root temporary record"
    );
    let raw_journal = if journal.exists() {
        Some(fss_ledger::inspect(&journal)?)
    } else {
        None
    };
    let raw_committed = raw_journal
        .as_ref()
        .map_or(0, |report| report.records().len());
    let raw_incomplete = raw_journal
        .as_ref()
        .is_some_and(|report| report.incomplete_tail().is_some());
    assert_eq!(
        raw_committed,
        usize::from(expected.commit_written),
        "step {step}: journal records"
    );
    assert_eq!(
        raw_incomplete,
        expected.incomplete_tail(),
        "step {step}: journal tail"
    );
    // (b) at the byte level: a committed ledger record implies a root record on disk.
    if raw_committed > 0 {
        assert!(
            post_crash.contains_key(&root_key),
            "step {step}: ledger names a root with no record"
        );
    }

    // First reopen in the parent: classification and invariants (a) to (d).
    {
        let mut local = LocalRootPublisher::open(&publication, limits())?;
        let report = local.recovery_report().clone();
        let orphan_names: BTreeSet<String> = report
            .spool
            .orphaned_staging
            .iter()
            .map(|orphan| {
                orphan
                    .path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default()
            })
            .collect();
        assert_eq!(
            orphan_names, expected.orphans,
            "step {step}: reported orphans"
        );
        let admitted: BTreeSet<ContentDigest> = report.spool.admitted.iter().copied().collect();
        assert_eq!(admitted, expected.admitted, "step {step}: admitted objects");
        for orphan in &report.spool.orphaned_staging {
            if !expected.admitted.contains(&orphan.claimed_digest) {
                assert_eq!(
                    local.spool().state(orphan.claimed_digest),
                    None,
                    "step {step}: an orphaned staging file was admitted"
                );
            }
        }
        if !expected.orphans.is_empty() {
            classes.insert(CLASS_ORPHANED_STAGING);
        }
        assert!(
            report.spool.corrupt.is_empty(),
            "step {step}: corrupt objects"
        );
        assert!(
            report.spool.foreign.is_empty(),
            "step {step}: foreign spool entries"
        );
        assert!(report.foreign.is_empty(), "step {step}: foreign entries");
        assert!(report.broken_roots.is_empty(), "step {step}: broken roots");
        let expected_temps: Vec<PathBuf> = if expected.root_temp_orphaned() {
            vec![Path::new(LOCAL_ROOTS_DIR).join(root_temp_name())]
        } else {
            Vec::new()
        };
        assert_eq!(
            report.orphaned_temps, expected_temps,
            "step {step}: orphaned temps"
        );

        // (a) A durable root's closure is verified in the spool and rehashes from raw bytes.
        let durable: Vec<_> = local
            .visible_roots()
            .filter(|visible| visible.state == LocalPublicationState::Durable)
            .cloned()
            .collect();
        assert_eq!(
            durable.len(),
            usize::from(expected.root_renamed),
            "step {step}: durable roots"
        );
        let mut referenced = BTreeSet::new();
        for visible in &durable {
            assert_eq!(visible.root, reference.root);
            let closure = local
                .root_closure(&visible.slot)
                .ok_or("durable root without a closure")?;
            for object in &closure {
                assert_eq!(
                    local.spool().state(*object),
                    Some(SpoolObjectState::Verified)
                );
                local.spool().require_verified(*object)?;
                let raw = fs::read(local.spool().object_path(*object))?;
                let payload = raw
                    .get(SPOOL_OBJECT_HEADER_LEN..)
                    .ok_or("object shorter than its header")?;
                assert_eq!(
                    ContentDigest::sha256(payload),
                    *object,
                    "step {step}: raw rehash"
                );
            }
            referenced.extend(closure);
            classes.insert(CLASS_DURABLE_CLOSURE);
        }
        let unreferenced: Vec<ContentDigest> =
            expected.admitted.difference(&referenced).copied().collect();
        assert_eq!(
            report.unreferenced_objects, unreferenced,
            "step {step}: unreferenced"
        );
        if !unreferenced.is_empty() {
            classes.insert(CLASS_UNREFERENCED);
        }

        // An incomplete ledger tail is refused, never admitted; truncation is an explicit choice.
        let mut ledger =
            match DurableReferenceLedger::open(&journal, LINEAGE, IncompleteTailPolicy::Reject) {
                Ok(ledger) => {
                    assert!(
                        !expected.incomplete_tail(),
                        "step {step}: incomplete tail was admitted"
                    );
                    ledger
                }
                Err(DurableLedgerError::Journal(JournalError::IncompleteTail { .. })) => {
                    assert!(
                        expected.incomplete_tail(),
                        "step {step}: unexpected incomplete tail"
                    );
                    classes.insert(CLASS_INCOMPLETE_TAIL);
                    open_ledger(&journal, IncompleteTailPolicy::Truncate)?
                }
                Err(error) => {
                    return Err(format!("step {step}: ledger reopen failed: {error}").into());
                }
            };
        assert_eq!(ledger.batches().len(), usize::from(expected.commit_written));

        {
            let coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
            let reconciliation = coordinator.reconcile()?;
            // (b) No claim is unbacked and no slot conflicts unless the harness damaged a record.
            assert_eq!(
                reconciliation.unbacked_ledger_claims,
                Vec::<UnbackedLedgerClaim>::new()
            );
            assert!(reconciliation.conflicts.is_empty());
            assert!(reconciliation.not_durable.is_empty());
            assert!(reconciliation.unledgerable.is_empty());
            let state = coordinator.state(&slot)?;
            match (expected.root_renamed, expected.commit_written) {
                (false, false) => {
                    assert_eq!(state, RootLedgerState::Absent, "step {step}");
                    assert!(
                        reconciliation.pending.is_empty() && reconciliation.ledgered.is_empty()
                    );
                    classes.insert(CLASS_ABSENT);
                }
                (true, false) => {
                    // (c) Durable but unledgered is explicit.
                    assert!(
                        matches!(&state, RootLedgerState::PendingLedger(pending) if pending.root == reference.root),
                        "step {step}: {state:?}"
                    );
                    assert_eq!(reconciliation.pending.len(), 1);
                    assert!(reconciliation.ledgered.is_empty());
                    classes.insert(CLASS_PENDING);
                }
                (true, true) => {
                    assert!(
                        matches!(&state, RootLedgerState::Ledgered { root, .. } if *root == reference.root),
                        "step {step}: {state:?}"
                    );
                    assert_eq!(reconciliation.ledgered.len(), 1);
                    assert!(reconciliation.pending.is_empty());
                    classes.insert(CLASS_CLAIM_BACKED);
                }
                (false, true) => {
                    return Err(format!(
                        "step {step}: ledger committed before the root was visible"
                    )
                    .into());
                }
            }
        }

        // (e) Re-run the same publish to completion.
        let digests = stage_fixture(&mut local)?;
        assert_eq!(digests, reference.digests);
        let manifest = manifest_of(&digests)?;
        assert_eq!(manifest.root(), reference.root);
        if expected.root_temp_orphaned() {
            {
                let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
                let refused = coordinator.publish_and_commit(&slot, &manifest, validity()?);
                assert!(
                    matches!(
                        refused,
                        Err(RootLedgerError::Local(
                            LocalPublicationError::OrphanedTemp { .. }
                        ))
                    ),
                    "step {step}: orphaned root temp was not refused: {refused:?}"
                );
            }
            assert_eq!(local.discard_orphaned_temps()?, 1);
            classes.insert(CLASS_ORPHANED_ROOT_TEMP);
        }
        let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
        let first = coordinator.publish_and_commit(&slot, &manifest, validity()?)?;
        let expected_outcome = if expected.commit_written {
            RootLedgerOutcome::AlreadyLedgered
        } else {
            RootLedgerOutcome::Committed
        };
        assert_eq!(first.outcome, expected_outcome, "step {step}: first retry");
        assert_eq!(first.root, reference.root);
        let again = coordinator.publish_and_commit(&slot, &manifest, validity()?)?;
        assert_eq!(again.outcome, RootLedgerOutcome::AlreadyLedgered);
        assert_eq!(again.anchor, first.anchor);
        let commit = coordinator.commit_root(&slot, validity()?)?;
        assert_eq!(commit.outcome, RootLedgerOutcome::AlreadyLedgered);
        assert!(coordinator.reconcile()?.is_clean());
        let batch_id = root_reachability_batch_id(&slot)?;
        assert_eq!(
            ledger.batches().len(),
            1,
            "step {step}: batches after convergence"
        );
        assert!(
            ledger
                .batches()
                .iter()
                .all(|batch| batch.batch_id == batch_id)
        );
    }

    // Second reopen: the converged state is stable and retries stay idempotent.
    {
        let mut local = LocalRootPublisher::open(&publication, limits())?;
        let report = local.recovery_report().clone();
        assert!(report.broken_roots.is_empty() && report.orphaned_temps.is_empty());
        assert!(
            report.unreferenced_objects.is_empty(),
            "step {step}: unreferenced after convergence"
        );
        let orphan_count = report.spool.orphaned_staging.len();
        assert_eq!(
            orphan_count,
            expected.orphans.len(),
            "step {step}: orphans after convergence"
        );
        let mut ledger = open_ledger(&journal, IncompleteTailPolicy::Reject)?;
        let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
        assert!(matches!(
            coordinator.state(&slot)?,
            RootLedgerState::Ledgered { root, .. } if root == reference.root
        ));
        assert!(coordinator.reconcile()?.is_clean());
        let retry = coordinator.commit_root(&slot, validity()?)?;
        assert_eq!(retry.outcome, RootLedgerOutcome::AlreadyLedgered);
        assert_eq!(ledger.batches().len(), 1);
    }
    let final_state = snapshot(&dir)?;
    let core_diff = differing_keys(&core_of(&final_state), &reference.core);
    assert!(
        core_diff.is_empty(),
        "step {step}: final state diverges from the reference: {core_diff:?}"
    );
    assert_eq!(
        staging_names(&final_state),
        expected.orphans,
        "step {step}: final staging"
    );
    classes.insert(CLASS_CONVERGED);

    // Damage probe: the only way an unbacked ledger claim may appear.
    let record = publication.join(LOCAL_ROOTS_DIR).join(root_record_name());
    let mut bytes = fs::read(&record)?;
    let last = bytes.last_mut().ok_or("empty root record")?;
    *last ^= 0x01;
    fs::write(&record, bytes)?;
    {
        let mut local = LocalRootPublisher::open(&publication, limits())?;
        let broken: Vec<BrokenRootReason> = local
            .recovery_report()
            .broken_roots
            .iter()
            .map(|broken| broken.reason.clone())
            .collect();
        assert_eq!(broken, vec![BrokenRootReason::ChecksumMismatch]);
        assert!(local.root(&slot).is_none());
        let mut ledger = open_ledger(&journal, IncompleteTailPolicy::Reject)?;
        let coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
        let reconciliation = coordinator.reconcile()?;
        assert_eq!(reconciliation.unbacked_ledger_claims.len(), 1);
        assert_eq!(
            reconciliation.unbacked_ledger_claims[0].slot.as_ref(),
            Some(&slot)
        );
        assert_eq!(
            reconciliation.unbacked_ledger_claims[0].ledgered_root,
            reference.root
        );
        assert!(matches!(
            coordinator.state(&slot)?,
            RootLedgerState::LedgerWithoutDurableRoot { ledgered_root } if ledgered_root == reference.root
        ));
        classes.insert(CLASS_UNBACKED_ON_DAMAGE);
    }

    Ok(StepOutcome {
        phase,
        classes,
        post_crash,
        final_state,
    })
}

struct Sweep {
    trace: Vec<TraceOp>,
    steps: Vec<u64>,
    outcomes: BTreeMap<u64, StepOutcome>,
}

fn run_sweep(sweep: &Path, cwd: &Path) -> Result<Sweep, Box<dyn Error>> {
    fresh_dir(sweep)?;
    let reference = count_run(sweep, cwd)?;
    let steps = selected_steps(&reference.trace);
    assert!(
        steps.len() <= MAX_STEPS_PER_SWEEP,
        "sweep of {} steps exceeds the bound {MAX_STEPS_PER_SWEEP}",
        steps.len()
    );
    let mut outcomes = BTreeMap::new();
    for &step in &steps {
        let outcome = crash_and_recover(sweep, cwd, step, &reference)?;
        eprintln!(
            "{{\"suite\":\"process_death_crash_harness\",\"sweep\":\"{}\",\"step\":{step},\"phase\":\"{}\",\"classes\":{:?}}}",
            sweep
                .file_name()
                .map(|name| name.to_string_lossy())
                .unwrap_or_default(),
            outcome.phase,
            outcome.classes
        );
        outcomes.insert(step, outcome);
    }
    Ok(Sweep {
        trace: reference.trace,
        steps,
        outcomes,
    })
}

#[test]
fn process_death_sweep_over_spool_publisher_and_ledger() -> TestResult {
    let started = Instant::now();
    let base =
        fresh_dir(&Path::new(env!("CARGO_TARGET_TMPDIR")).join("process_death_crash_harness"))?;
    let cwd = fresh_dir(&base.join("child-cwd"))?;
    let first = run_sweep(&base.join("sweep-a"), &cwd)?;
    let second = run_sweep(&base.join("sweep-b"), &cwd)?;

    // Two independent sweeps see the same trace, the same cuts, and byte-identical states.
    assert_eq!(
        first.trace, second.trace,
        "operation trace is not deterministic"
    );
    assert_eq!(first.steps, second.steps);
    for (step, left) in &first.outcomes {
        let right = second
            .outcomes
            .get(step)
            .ok_or_else(|| format!("step {step} missing from the second sweep"))?;
        let crash_diff = differing_keys(&left.post_crash, &right.post_crash);
        assert!(
            crash_diff.is_empty(),
            "step {step}: post-crash states differ: {crash_diff:?}"
        );
        let final_diff = differing_keys(&left.final_state, &right.final_state);
        assert!(
            final_diff.is_empty(),
            "step {step}: final states differ: {final_diff:?}"
        );
        assert_eq!(left.classes, right.classes, "step {step}: classes differ");
    }

    let total_ops = first.trace.len();
    let swept = first.steps.len();
    let mut by_phase: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_class: BTreeMap<&str, usize> = BTreeMap::new();
    for outcome in first.outcomes.values() {
        *by_phase.entry(outcome.phase.as_str()).or_default() += 1;
        for class in &outcome.classes {
            *by_class.entry(*class).or_default() += 1;
        }
    }
    for phase in ["spool_staging", "root_publication", "ledger_commit"] {
        assert!(
            by_phase.get(phase).copied().unwrap_or_default() > 0,
            "no crash step landed in phase {phase}: {by_phase:?}"
        );
    }
    for class in [
        CLASS_ABSENT,
        CLASS_DURABLE_CLOSURE,
        CLASS_CLAIM_BACKED,
        CLASS_PENDING,
        CLASS_ORPHANED_STAGING,
        CLASS_ORPHANED_ROOT_TEMP,
        CLASS_UNREFERENCED,
    ] {
        assert!(
            by_class.get(class).copied().unwrap_or_default() > 0,
            "no crash step exercised {class}: {by_class:?}"
        );
    }
    // Aborts after the body write and after the body fsync are the only torn-tail states.
    assert_eq!(by_class.get(CLASS_INCOMPLETE_TAIL).copied(), Some(2));
    assert_eq!(by_class.get(CLASS_CONVERGED).copied(), Some(swept));
    assert_eq!(by_class.get(CLASS_UNBACKED_ON_DAMAGE).copied(), Some(swept));

    eprintln!(
        "{{\"suite\":\"process_death_crash_harness\",\"total_ops\":{total_ops},\"steps_per_sweep\":{swept},\"sweeps\":2,\"by_phase\":{by_phase:?},\"by_class\":{by_class:?},\"elapsed_ms\":{}}}",
        started.elapsed().as_millis()
    );
    Ok(())
}
