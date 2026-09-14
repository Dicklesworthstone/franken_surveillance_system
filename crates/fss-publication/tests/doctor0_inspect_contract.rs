#![forbid(unsafe_code)]
//! Contract tests for fss-2h5zq.66 non-mutating inspection: every entry point leaves the tree
//! byte-identical, bounds hold at N and fail typed at N+1, the root-ledger linkage equals
//! `reconcile()` on a copy apart from its documented extras, and writer states are never
//! flattened into a clean snapshot.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use fss_core::{CaptureInterval, ContentDigest, TimestampNs};
use fss_ledger::{
    DurableLedgerError, DurableLedgerLimits, DurableLedgerStatus, DurableReferenceLedger,
    IncompleteTailPolicy, RepairError,
};
use fss_object::{HostSpoolIo, ObjectManifest, SPOOL_LOCK_FILE, SpoolError, SpoolLimits};
use fss_publication::{
    LOCAL_LOCK_FILE, LOCAL_ROOTS_DIR, LOCAL_SPOOL_DIR, LedgeredRootPublisher, LocalInspection,
    LocalPublicationError, LocalPublicationLimits, LocalPublicationState, LocalRootPublisher,
    LockTableSource, ROOT_RECORD_SUFFIX, ROOT_TEMP_SUFFIX, SlotName, StringLockTableSource,
    UnknownLockReason, WriterDetectionOptions, WriterLockBasis, WriterState, decode_st_dev,
    inspect_linkage,
};

type TestResult = Result<(), Box<dyn Error>>;

const LINEAGE: &str = "site:doctor0";

fn fresh(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("doctor0_inspect_contract")
        .join(name);
    match fs::remove_dir_all(&base) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    fs::create_dir_all(&base)?;
    Ok(base)
}

fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(8, 16, 8, 64, SpoolLimits::new(64, 1 << 20, 4096, 64))
}

fn slot(name: &str) -> Result<SlotName, Box<dyn Error>> {
    Ok(SlotName::parse(name)?)
}

fn validity() -> Result<CaptureInterval, Box<dyn Error>> {
    Ok(CaptureInterval::new(
        TimestampNs(1_000),
        TimestampNs(2_000),
    )?)
}

/// One staged-and-verified child under a fresh manifest.
fn manifest(
    publisher: &mut LocalRootPublisher,
    payload: &[u8],
) -> Result<ObjectManifest, Box<dyn Error>> {
    let child = publisher.stage_object(payload)?;
    Ok(ObjectManifest::new("event_archive", [child], None)?)
}

/// Digest over relative path, mode, size, mtime, ctime, inode, link count, content, and listing.
fn tree_digest(root: &Path) -> Result<BTreeMap<PathBuf, String>, Box<dyn Error>> {
    let mut out = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let meta = fs::symlink_metadata(&path)?;
        let rel = path.strip_prefix(root)?.to_path_buf();
        let common = format!(
            "mode={:o} size={} mtime={}.{} ctime={}.{} ino={} nlink={}",
            meta.mode(),
            meta.size(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec(),
            meta.ino(),
            meta.nlink()
        );
        let detail = if meta.file_type().is_symlink() {
            format!("link -> {}", fs::read_link(&path)?.display())
        } else if meta.file_type().is_dir() {
            let mut names = Vec::new();
            for entry in fs::read_dir(&path)? {
                let entry = entry?;
                names.push(entry.file_name().to_string_lossy().into_owned());
                pending.push(entry.path());
            }
            names.sort();
            format!("dir [{}]", names.join(","))
        } else {
            format!("file {}", ContentDigest::sha256(&fs::read(&path)?))
        };
        out.insert(rel, format!("{common} {detail}"));
    }
    Ok(out)
}

fn assert_same_tree(label: &str, before: &BTreeMap<PathBuf, String>, root: &Path) -> TestResult {
    let after = tree_digest(root)?;
    if &after != before {
        return Err(format!("tree changed by {label}: before={before:#?} after={after:#?}").into());
    }
    Ok(())
}

fn copy_tree(from: &Path, to: &Path) -> TestResult {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let dest = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &dest)?;
        } else {
            fs::copy(entry.path(), &dest)?;
        }
    }
    Ok(())
}

/// Inspection with an injected empty lock table: deterministic `not_observed` on Linux.
fn inspect_quiet(
    root: &Path,
    limits: LocalPublicationLimits,
) -> Result<LocalInspection, LocalPublicationError> {
    fss_publication::inspect_with_io(
        &HostSpoolIo,
        root,
        limits,
        Some(&StringLockTableSource(String::new())),
        WriterDetectionOptions::default(),
    )
}

/// A deployment with a ledgered root, a local-only (pending) root, and an incomplete ledger tail.
#[test]
fn linkage_with_ledger_tail_is_read_only_and_equals_reconcile_on_a_copy() -> TestResult {
    let base = fresh("linkage")?;
    let publication = base.join("publication");
    let journal = base.join("ledger.journal");
    {
        let mut ledger =
            DurableReferenceLedger::open(&journal, LINEAGE, IncompleteTailPolicy::Reject)?;
        let mut local = LocalRootPublisher::open(&publication, limits())?;
        let committed = manifest(&mut local, b"clip-committed")?;
        LedgeredRootPublisher::new(&mut local, &mut ledger).publish_and_commit(
            &slot("committed")?,
            &committed,
            validity()?,
        )?;
        let pending = manifest(&mut local, b"clip-pending")?;
        local.publish(&slot("pending")?, &pending)?;
    }
    let committed_len = fs::metadata(&journal)?.len();
    let head = fs::read(&journal)?;
    OpenOptions::new()
        .append(true)
        .open(&journal)?
        .write_all(head.get(..4).ok_or("short journal")?)?;

    let before = tree_digest(&base)?;
    let local = inspect_quiet(&publication, limits())?;
    assert_same_tree("local inspect", &before, &base)?;
    let ledger = fss_ledger::inspect_durable(&journal, LINEAGE, DurableLedgerLimits::default())?;
    assert_same_tree("inspect_durable", &before, &base)?;
    let same = DurableReferenceLedger::inspect(&journal, LINEAGE, DurableLedgerLimits::default())?;
    assert_same_tree("DurableReferenceLedger::inspect", &before, &base)?;
    let linkage = inspect_linkage(&local, &ledger);
    assert_same_tree("inspect_linkage", &before, &base)?;

    assert_eq!(same, ledger);
    assert_eq!(ledger.status, DurableLedgerStatus::Present);
    assert_eq!(ledger.batches.len(), 1);
    assert_eq!(ledger.committed_len, committed_len);
    assert_eq!(ledger.incomplete_tail, Some(committed_len));
    assert_eq!(ledger.foreign_range, None);

    // Inspection observed no fsync: every admitted root stays Visible.
    assert_eq!(local.report.roots.len(), 2);
    assert!(
        local
            .report
            .roots
            .iter()
            .all(|root| root.state == LocalPublicationState::Visible)
    );
    assert!(local.durability_not_resynced);
    assert_eq!(
        local.writer_state,
        WriterState::NotObserved {
            basis: "proc_locks",
            scope: "this_host_this_pid_namespace",
        }
    );
    assert!(local.is_clean());

    assert_eq!(linkage.ledger_tail_incomplete, Some(committed_len));
    assert!(linkage.durability_not_resynced);
    assert!(!linkage.is_clean());
    assert_eq!(
        linkage
            .ledgered
            .iter()
            .map(|root| root.slot.clone())
            .collect::<Vec<_>>(),
        vec![slot("committed")?]
    );
    assert_eq!(
        linkage
            .pending
            .iter()
            .map(|root| root.slot.clone())
            .collect::<Vec<_>>(),
        vec![slot("pending")?]
    );
    assert!(linkage.not_durable.is_empty());

    // The mutating path on a copy: the open truncates the tail, then reconcile().
    let copy = fresh("linkage_copy")?;
    copy_tree(&base, &copy)?;
    let mut ledger_copy = DurableReferenceLedger::open(
        copy.join("ledger.journal"),
        LINEAGE,
        IncompleteTailPolicy::Truncate,
    )?;
    let mut local_copy = LocalRootPublisher::open(copy.join("publication"), limits())?;
    let reconciled = LedgeredRootPublisher::new(&mut local_copy, &mut ledger_copy).reconcile()?;
    let mut documented = linkage.clone();
    documented.ledger_tail_incomplete = None;
    documented.durability_not_resynced = false;
    assert_eq!(documented, reconciled);
    Ok(())
}

/// The roots listing bound: N entries inspect, N+1 is the typed limit the open also returns.
#[test]
fn root_scan_limit_holds_at_n_and_fails_typed_at_n_plus_one() -> TestResult {
    let base = fresh("scan_limit")?;
    let root = base.join("publication");
    {
        let mut publisher = LocalRootPublisher::open(&root, limits())?;
        let first = manifest(&mut publisher, b"clip-1")?;
        publisher.publish(&slot("one")?, &first)?;
        let second = manifest(&mut publisher, b"clip-2")?;
        publisher.publish(&slot("two")?, &second)?;
    }
    for name in ["ghost1", "ghost2"] {
        fs::write(
            root.join(LOCAL_ROOTS_DIR)
                .join(format!("{name}{ROOT_RECORD_SUFFIX}{ROOT_TEMP_SUFFIX}")),
            b"partial",
        )?;
    }
    // roots/ now holds exactly four entries; spool/objects/ holds four objects.
    let spool = SpoolLimits::new(4, 1 << 20, 4096, 4);
    let at_n = LocalPublicationLimits::new(2, 16, 2, 4, spool);
    let over_n = LocalPublicationLimits::new(2, 16, 2, 3, spool);

    let before = tree_digest(&base)?;
    let inspected = inspect_quiet(&root, at_n)?;
    assert_eq!(inspected.report.roots.len(), 2);
    assert_eq!(inspected.report.orphaned_temps.len(), 2);
    let roots_dir = root.join(LOCAL_ROOTS_DIR);
    match inspect_quiet(&root, over_n) {
        Err(LocalPublicationError::EntryLimit {
            directory,
            maximum,
            at_least,
        }) => {
            assert_eq!(directory, roots_dir);
            assert_eq!(maximum, 3);
            assert_eq!(at_least, 4);
        }
        other => return Err(format!("expected EntryLimit at N+1, got {other:?}").into()),
    }
    let spool_root = root.join(LOCAL_SPOOL_DIR);
    let spool_at_n = fss_object::inspect(&spool_root, &spool)?;
    assert_eq!(spool_at_n.report.admitted.len(), 4);
    let spool_over = SpoolLimits::new(3, 1 << 20, 4096, 3);
    match fss_object::inspect(&spool_root, &spool_over) {
        Err(SpoolError::EntryLimit { directory, maximum }) => {
            assert_eq!(directory, spool_root.join("objects"));
            assert_eq!(maximum, 3);
        }
        other => return Err(format!("expected spool EntryLimit at N+1, got {other:?}").into()),
    }
    assert_same_tree("scan-limit inspections", &before, &base)?;

    // The mutating open fails with the same typed limit on a copy.
    let copy = fresh("scan_limit_copy")?;
    copy_tree(&base, &copy)?;
    let copy_root = copy.join("publication");
    match LocalRootPublisher::open(&copy_root, over_n) {
        Err(LocalPublicationError::EntryLimit {
            directory,
            maximum,
            at_least,
        }) => {
            assert_eq!(directory, copy_root.join(LOCAL_ROOTS_DIR));
            assert_eq!(maximum, 3);
            assert_eq!(at_least, 4);
        }
        other => return Err(format!("expected the open's EntryLimit, got {other:?}").into()),
    }
    Ok(())
}

/// `read_verified` returns exactly N payload bytes at cap N and refuses them at cap N-1.
#[test]
fn read_verified_cap_holds_at_n_and_refuses_n_plus_one() -> TestResult {
    let base = fresh("read_cap")?;
    let root = base.join("publication");
    let payload = b"0123456789";
    let digest = {
        let mut publisher = LocalRootPublisher::open(&root, limits())?;
        publisher.stage_object(payload)?
    };
    let before = tree_digest(&base)?;
    assert_eq!(
        fss_publication::read_verified(&root, digest, payload.len())?,
        payload.to_vec()
    );
    match fss_publication::read_verified(&root, digest, payload.len() - 1) {
        Err(LocalPublicationError::Spool(SpoolError::Corrupt { digest: named, .. })) => {
            assert_eq!(named, digest);
        }
        other => return Err(format!("expected a refused over-cap read, got {other:?}").into()),
    }
    assert_same_tree("read_verified", &before, &base)?;
    Ok(())
}

/// The journal byte cap: a journal of L bytes inspects at cap L and is `OverBudget` at L-1.
#[test]
fn ledger_journal_cap_holds_at_n_and_refuses_n_plus_one() -> TestResult {
    let base = fresh("journal_cap")?;
    let journal = base.join("ledger.journal");
    {
        let mut ledger =
            DurableReferenceLedger::open(&journal, LINEAGE, IncompleteTailPolicy::Reject)?;
        let publication = base.join("publication");
        let mut local = LocalRootPublisher::open(&publication, limits())?;
        let committed = manifest(&mut local, b"clip-cap")?;
        LedgeredRootPublisher::new(&mut local, &mut ledger).publish_and_commit(
            &slot("cap")?,
            &committed,
            validity()?,
        )?;
    }
    let len = usize::try_from(fs::metadata(&journal)?.len())?;
    let before = tree_digest(&base)?;

    let at_n = fss_ledger::inspect_durable(&journal, LINEAGE, len)?;
    assert_eq!(at_n.batches.len(), 1);
    assert_eq!(at_n.committed_len, u64::try_from(len)?);
    match fss_ledger::inspect_durable(&journal, LINEAGE, len - 1) {
        Err(DurableLedgerError::OverBudget { limit, actual }) => {
            assert_eq!(limit, len - 1);
            assert_eq!(actual, len);
        }
        other => return Err(format!("expected OverBudget at N+1, got {other:?}").into()),
    }
    assert_eq!(
        DurableReferenceLedger::inspect(&journal, LINEAGE, len)?,
        at_n
    );
    match DurableReferenceLedger::inspect(&journal, LINEAGE, len - 1) {
        Err(DurableLedgerError::OverBudget { limit, actual }) => {
            assert_eq!((limit, actual), (len - 1, len));
        }
        other => return Err(format!("expected OverBudget at N+1, got {other:?}").into()),
    }
    let doctor = fss_ledger::doctor_bounded(&journal, len)?;
    assert_eq!(doctor.committed_len(), u64::try_from(len)?);
    match fss_ledger::doctor_bounded(&journal, len - 1) {
        Err(RepairError::OverBudget { limit, actual }) => {
            assert_eq!((limit, actual), (len - 1, len));
        }
        other => return Err(format!("expected doctor OverBudget at N+1, got {other:?}").into()),
    }
    assert_same_tree("journal cap inspections", &before, &base)?;

    let missing = base.join("missing.journal");
    let absent = fss_ledger::inspect_durable(&missing, LINEAGE, len)?;
    assert_eq!(absent.status, DurableLedgerStatus::Absent);
    assert!(absent.batches.is_empty());
    assert!(!missing.exists());
    Ok(())
}

/// A lock table that replaces `LOCK` (new inode) while it is read, and names the old inode as an
/// exclusive holder.
#[derive(Debug)]
struct ReplacingLockTable {
    lock: PathBuf,
    line: String,
}

impl LockTableSource for ReplacingLockTable {
    fn read_lock_table(&self, _max_bytes: usize) -> io::Result<String> {
        let replacement = self.lock.with_extension("replacement");
        fs::write(&replacement, b"")?;
        fs::rename(&replacement, &self.lock)?;
        Ok(self.line.clone())
    }
}

fn flock_line(path: &Path, mode: &str) -> Result<String, Box<dyn Error>> {
    let meta = fs::symlink_metadata(path)?;
    let (major, minor) = decode_st_dev(meta.dev());
    Ok(format!(
        "1: FLOCK  ADVISORY  {mode} 4242 {major:02x}:{minor:02x}:{} 0 EOF\n",
        meta.ino()
    ))
}

fn published_root(name: &str) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let base = fresh(name)?;
    let root = base.join("publication");
    let mut publisher = LocalRootPublisher::open(&root, limits())?;
    let only = manifest(&mut publisher, b"clip-only")?;
    publisher.publish(&slot("only")?, &only)?;
    Ok((base, root))
}

#[cfg(target_os = "linux")]
#[test]
fn replaced_lock_file_is_unknown_not_held() -> TestResult {
    let (_base, root) = published_root("lock_replaced")?;
    let lock = root.join(LOCAL_LOCK_FILE);
    let line = flock_line(&lock, "WRITE")?;

    // Control: the same entry against the unchanged file is a holder.
    let held = fss_publication::inspect_with_io(
        &HostSpoolIo,
        &root,
        limits(),
        Some(&StringLockTableSource(line.clone())),
        WriterDetectionOptions::default(),
    )?;
    assert_eq!(
        held.writer_state,
        WriterState::Held {
            basis: WriterLockBasis::ProcLocks,
            pid_hint: Some(4242),
        }
    );
    assert!(held.possibly_stale);
    assert!(held.possibly_in_flight);
    assert!(!held.is_clean());

    let original_ino = fs::symlink_metadata(&lock)?.ino();
    let replaced = fss_publication::inspect_with_io(
        &HostSpoolIo,
        &root,
        limits(),
        Some(&ReplacingLockTable {
            lock: lock.clone(),
            line,
        }),
        WriterDetectionOptions::default(),
    )?;
    assert_ne!(fs::symlink_metadata(&lock)?.ino(), original_ino);
    assert_eq!(
        replaced.writer_state,
        WriterState::Unknown {
            reason: UnknownLockReason::LockFileReplaced,
        }
    );
    assert!(replaced.possibly_stale);
    assert!(!replaced.is_clean());
    Ok(())
}

#[derive(Debug)]
struct FailingTable(io::ErrorKind);

impl LockTableSource for FailingTable {
    fn read_lock_table(&self, _max_bytes: usize) -> io::Result<String> {
        Err(io::Error::from(self.0))
    }
}

fn inspect_writer(
    root: &Path,
    table: &dyn LockTableSource,
    options: WriterDetectionOptions,
) -> Result<LocalInspection, LocalPublicationError> {
    fss_publication::inspect_with_io(&HostSpoolIo, root, limits(), Some(table), options)
}

/// Only a check that ran and saw no writer is clean; unknown, shared, unprobed, and
/// lock-file-missing states never are, and unknown or shared ones mark the snapshot stale.
#[cfg(target_os = "linux")]
#[test]
fn writer_states_are_never_flattened_into_a_clean_snapshot() -> TestResult {
    let (base, root) = published_root("writer_states")?;
    let before = tree_digest(&base)?;
    let quiet = WriterDetectionOptions::default();

    let clear = inspect_writer(&root, &StringLockTableSource(String::new()), quiet)?;
    assert_eq!(clear.writer_state, WriterState::not_observed());
    assert!(!clear.possibly_stale);
    assert!(clear.is_clean());
    assert_eq!(clear.report.roots.len(), 1);
    assert_eq!(
        clear.report.roots.first().map(|root| root.state),
        Some(LocalPublicationState::Visible)
    );

    let unknown = inspect_writer(&root, &FailingTable(io::ErrorKind::NotFound), quiet)?;
    assert_eq!(
        unknown.writer_state,
        WriterState::Unknown {
            reason: UnknownLockReason::NoLockTable,
        }
    );
    assert!(unknown.possibly_stale);
    assert!(!unknown.is_clean());
    assert_eq!(unknown.report, clear.report);

    let unreadable = inspect_writer(&root, &FailingTable(io::ErrorKind::PermissionDenied), quiet)?;
    assert_eq!(
        unreadable.writer_state,
        WriterState::Unknown {
            reason: UnknownLockReason::Unreadable,
        }
    );
    assert!(unreadable.possibly_stale);
    assert!(!unreadable.is_clean());

    let shared_line = flock_line(&root.join(LOCAL_LOCK_FILE), "READ")?;
    let shared = inspect_writer(&root, &StringLockTableSource(shared_line), quiet)?;
    assert_eq!(
        shared.writer_state,
        WriterState::SharedHolder {
            basis: WriterLockBasis::ProcLocks,
            pid_hint: Some(4242),
        }
    );
    assert!(shared.possibly_stale);
    assert!(!shared.is_clean());

    let waiter_line =
        flock_line(&root.join(LOCAL_LOCK_FILE), "WRITE")?.replacen("1: ", "1: -> ", 1);
    let waiter = inspect_writer(&root, &StringLockTableSource(waiter_line), quiet)?;
    assert_eq!(waiter.writer_state, WriterState::not_observed());

    let self_held = inspect_writer(
        &root,
        &StringLockTableSource(String::new()),
        WriterDetectionOptions {
            probe_shared_lock: false,
            self_holds_lock: true,
        },
    )?;
    assert_eq!(self_held.writer_state, WriterState::NotProbed);
    assert!(!self_held.possibly_stale);
    assert!(!self_held.is_clean());
    assert_same_tree("writer-state inspections", &before, &base)?;

    fs::remove_file(root.join(LOCAL_LOCK_FILE))?;
    fs::remove_file(root.join(LOCAL_SPOOL_DIR).join(SPOOL_LOCK_FILE))?;
    let after_removal = tree_digest(&base)?;
    let no_lock = inspect_writer(&root, &StringLockTableSource(String::new()), quiet)?;
    assert_eq!(
        no_lock.writer_state,
        WriterState::NoLockFile {
            basis: "proc_locks",
        }
    );
    assert!(!no_lock.possibly_stale);
    assert!(!no_lock.is_clean());
    assert!(!root.join(LOCAL_LOCK_FILE).exists());
    assert_same_tree("inspection without lock files", &after_removal, &base)?;
    Ok(())
}

/// The deployment layout: deployment `<d>`, publication root `<d>/objects`, canonical ledger
/// `<d>/ledger/journal.fssj`. A flock on the journal (what a ledger repair apply holds) is a
/// writer only when the journal is passed explicitly; nothing is derived from the publication
/// root.
#[cfg(target_os = "linux")]
#[test]
fn ledger_journal_flock_on_the_deployment_layout_is_a_writer() -> TestResult {
    let deployment = fresh("deployment_layout")?;
    let publication = deployment.join("objects");
    let journal = deployment.join("ledger").join("journal.fssj");
    fs::create_dir_all(deployment.join("ledger"))?;
    {
        let mut ledger =
            DurableReferenceLedger::open(&journal, LINEAGE, IncompleteTailPolicy::Reject)?;
        let mut local = LocalRootPublisher::open(&publication, limits())?;
        let committed = manifest(&mut local, b"clip-layout")?;
        LedgeredRootPublisher::new(&mut local, &mut ledger).publish_and_commit(
            &slot("layout")?,
            &committed,
            validity()?,
        )?;
    }
    let before = tree_digest(&deployment)?;
    let quiet = WriterDetectionOptions::default();

    let holder = fs::File::open(&journal)?;
    holder.try_lock()?;
    let held = fss_publication::inspect_with_ledger_journal(
        &HostSpoolIo,
        &publication,
        Some(&journal),
        limits(),
        None,
        quiet,
    )?;
    assert_eq!(
        held.writer_state,
        WriterState::Held {
            basis: WriterLockBasis::ProcLocks,
            pid_hint: Some(std::process::id()),
        }
    );
    assert!(held.possibly_stale);
    assert!(held.possibly_in_flight);
    assert!(!held.is_clean());
    assert_eq!(
        held.report.roots.first().map(|root| root.state),
        Some(LocalPublicationState::Visible)
    );

    // Without the explicit journal the same flock is outside the checked lock files.
    let unchecked =
        fss_publication::inspect_with_io(&HostSpoolIo, &publication, limits(), None, quiet)?;
    assert_eq!(unchecked.writer_state, WriterState::not_observed());
    drop(holder);

    let released = fss_publication::inspect_with_ledger_journal(
        &HostSpoolIo,
        &publication,
        Some(&journal),
        limits(),
        None,
        quiet,
    )?;
    assert_eq!(released.writer_state, WriterState::not_observed());
    assert!(!released.possibly_stale);
    assert!(released.is_clean());

    let probed = fss_publication::inspect_with_ledger_journal(
        &HostSpoolIo,
        &publication,
        Some(&journal),
        limits(),
        None,
        WriterDetectionOptions {
            probe_shared_lock: true,
            self_holds_lock: false,
        },
    )?;
    assert_eq!(probed.writer_state, WriterState::not_held());
    assert_same_tree("deployment-layout inspections", &before, &deployment)?;

    // With every lock file gone, the lock-table path reports no lock file.
    fs::remove_file(publication.join(LOCAL_LOCK_FILE))?;
    fs::remove_file(publication.join(LOCAL_SPOOL_DIR).join(SPOOL_LOCK_FILE))?;
    fs::remove_file(&journal)?;
    let none = fss_publication::inspect_with_ledger_journal(
        &HostSpoolIo,
        &publication,
        Some(&journal),
        limits(),
        None,
        quiet,
    )?;
    assert_eq!(
        none.writer_state,
        WriterState::NoLockFile {
            basis: "proc_locks",
        }
    );
    assert!(!none.is_clean());
    Ok(())
}

/// An absent root is reported missing, never as a clean empty deployment, and is not created.
#[test]
fn absent_root_is_missing_layout_and_never_created() -> TestResult {
    let base = fresh("absent")?;
    let root = base.join("publication");
    let inspected = inspect_quiet(&root, limits())?;
    assert!(inspected.missing_layout);
    assert!(!inspected.is_clean());
    assert!(inspected.report.roots.is_empty());
    assert!(!root.exists());
    Ok(())
}
