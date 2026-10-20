#![forbid(unsafe_code)]
#![cfg(unix)]
//! Cold-process upload recovery: durable intent, bounded spend, and exact reconciliation.
//!
//! The provider outlives every uploader, authority tree, transport, and journal handle.
//! Abrupt transport exits happen after the provider effect but before any return to the owner.

mod multipart_support;

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BudgetVector, ContentDigest, ObligationState, OperationId, RegionId, RegionKind, RegionState,
    RuntimeGrant, TaskId, TimestampNs,
};
use fss_object::multipart::{
    MultipartError, MultipartPhase, MultipartRecovery, MultipartSession, MultipartTransport,
    PartReceipt, Reconciliation, TransportCx, TransportOperation, UploadId, UploadIntent, UploadIo,
    UploadJournal, UploadJournalPin,
};
use fss_object::planner::{ChunkPolicy, MIN_PART_SIZE, PlannedChunk, plan_chunks};
use fss_object::upload_journal::{FileUploadJournal, UploadJournalLimits};
use fss_object::uploader::StagedUpload;
use fss_object::{
    FaultInjectingSpoolIo, HostSpoolIo, SPOOL_OBJECTS_DIR, SpoolFaultPlan, SpoolIoCall,
};
use multipart_support::{MemoryTransport, RESOURCE, Store, Test, property, spec};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

/// Only tiny, independently owned fixture directories are removed by this guard.
struct Directory(PathBuf);

impl Directory {
    fn new() -> io::Result<Self> {
        for _ in 0..16 {
            let ordinal = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "fss-durable-upload-{}-{ordinal}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "durable upload fixture namespace exhausted",
        ))
    }

    fn objects(&self) -> io::Result<Vec<PathBuf>> {
        let mut paths = fs::read_dir(self.0.join(SPOOL_OBJECTS_DIR))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<io::Result<Vec<_>>>()?;
        paths.sort();
        Ok(paths)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct DispatchControl {
    crash_after: Cell<Option<TransportOperation>>,
    fail_journal_after: Cell<Option<TransportOperation>>,
    fail_next_append: Cell<bool>,
    fail_after_append: Cell<bool>,
}

/// Wrap the existing provider oracle; its independent store survives every cold reopen.
struct CrashTransport {
    inner: MemoryTransport,
    control: Rc<DispatchControl>,
}

impl CrashTransport {
    fn new(store: Rc<RefCell<Store>>, control: Rc<DispatchControl>) -> Self {
        Self {
            inner: MemoryTransport { store },
            control,
        }
    }

    fn returned(&self, operation: TransportOperation) {
        if self.control.fail_journal_after.get() == Some(operation) {
            self.control.fail_journal_after.set(None);
            self.control.fail_next_append.set(true);
        }
        if self.control.crash_after.get() == Some(operation) {
            self.control.crash_after.set(None);
            panic!("simulated process exit after {operation:?} provider effect");
        }
    }
}

impl MultipartTransport for CrashTransport {
    fn initiate(
        &mut self,
        cx: &mut TransportCx<'_>,
        intent: &UploadIntent,
    ) -> Result<UploadId, String> {
        let result = self.inner.initiate(cx, intent)?;
        self.returned(TransportOperation::Initiate);
        Ok(result)
    }

    fn upload_part(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        chunk: &PlannedChunk,
        bytes: &[u8],
        content_digest: ContentDigest,
    ) -> Result<PartReceipt, String> {
        let result = self
            .inner
            .upload_part(cx, upload, chunk, bytes, content_digest)?;
        self.returned(TransportOperation::UploadPart);
        Ok(result)
    }

    fn complete(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        intent: &UploadIntent,
        parts: &[PartReceipt],
    ) -> Result<(), String> {
        self.inner.complete(cx, upload, intent, parts)?;
        self.returned(TransportOperation::Complete);
        Ok(())
    }

    fn abort(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        intent: &UploadIntent,
    ) -> Result<(), String> {
        self.inner.abort(cx, upload, intent)?;
        self.returned(TransportOperation::Abort);
        Ok(())
    }

    fn reconcile(
        &mut self,
        cx: &mut TransportCx<'_>,
        intent: &UploadIntent,
    ) -> Result<Reconciliation, String> {
        let result = self.inner.reconcile(cx, intent)?;
        self.returned(TransportOperation::Reconcile);
        Ok(result)
    }
}

fn policy() -> ChunkPolicy {
    ChunkPolicy {
        part_size: MIN_PART_SIZE,
    }
}

fn root() -> ContentDigest {
    ContentDigest::sha256(b"durable-upload-manifest")
}

fn allowance() -> BudgetVector {
    let mut allowance = BudgetVector::ZERO;
    allowance.bytes = 128;
    allowance.network_bytes = 128;
    allowance.storage_operations = 12;
    allowance
}

fn stage<'a>(
    parent: &'a mut fss_runtime::authority::AuthorityCx,
    tree: &mut fss_core::RegionTree,
    transport: &'a mut CrashTransport,
) -> Result<StagedUpload<'a, CrashTransport>, Box<dyn std::error::Error>> {
    Ok(StagedUpload::stage(
        parent,
        tree,
        transport,
        OperationId::parse("operation:durable-upload")?,
        3,
        policy(),
        root(),
        spec("operation:durable-upload", allowance())?,
        RESOURCE,
        TimestampNs(1),
    )?)
}

fn call_count(store: &Rc<RefCell<Store>>, operation: TransportOperation) -> usize {
    store
        .borrow()
        .calls
        .iter()
        .filter(|actual| **actual == operation)
        .count()
}

fn recover<'a>(
    parent: &'a mut fss_runtime::authority::AuthorityCx,
    tree: &mut fss_core::RegionTree,
    transport: &'a mut CrashTransport,
    journal: &'a mut dyn UploadJournal,
    minimum: UploadJournalPin,
    expected: &UploadIntent,
    now: TimestampNs,
) -> Result<StagedUpload<'a, CrashTransport>, Box<dyn std::error::Error>> {
    let recovery = MultipartRecovery::read(journal, minimum)?;
    let child = spec("operation:durable-upload", recovery.remaining_budget())?;
    Ok(StagedUpload::recover(
        parent, tree, transport, journal, recovery, expected, child, now,
    )?)
}

fn emit(property: &str, cases: usize) {
    println!(
        "{{\"family\":\"FSS-064\",\"property\":\"{property}\",\"cases\":{cases},\"verdict\":\"pass\"}}"
    );
}

fn limits() -> UploadJournalLimits {
    UploadJournalLimits {
        max_records: 128,
        max_checkpoint_bytes: 16 * 1024,
        max_total_bytes: 512 * 1024,
        max_read_bytes: 2 * 1024 * 1024,
    }
}

fn create(directory: &Directory) -> Result<FileUploadJournal, MultipartError> {
    FileUploadJournal::create(&directory.0, limits(), Arc::new(HostSpoolIo))
}

fn reopen(
    directory: &Directory,
    minimum: UploadJournalPin,
) -> Result<FileUploadJournal, MultipartError> {
    FileUploadJournal::open(&directory.0, limits(), Arc::new(HostSpoolIo), minimum)
}

/// Fault at the persistence contract boundary while keeping successful records on real disk.
struct GuardedJournal {
    inner: FileUploadJournal,
    control: Rc<DispatchControl>,
}

/// Capture the real protocol encoder's bytes; filesystem tests never invent checkpoint fields.
#[derive(Default)]
struct RecordingJournal {
    records: Vec<(UploadJournalPin, Vec<u8>)>,
}

impl UploadJournal for RecordingJournal {
    fn head(&self) -> Option<UploadJournalPin> {
        self.records.last().map(|(pin, _)| *pin)
    }

    fn latest(&self) -> Option<&[u8]> {
        self.records.last().map(|(_, bytes)| bytes.as_slice())
    }

    fn contains(&self, pin: UploadJournalPin) -> bool {
        self.records.iter().any(|(actual, _)| *actual == pin)
    }

    fn append(
        &mut self,
        expected: Option<UploadJournalPin>,
        checkpoint: &[u8],
    ) -> Result<UploadJournalPin, MultipartError> {
        if expected != self.head() || self.records.len() >= 32 {
            return Err(MultipartError::Persistence(
                "fixture journal boundary".into(),
            ));
        }
        let sequence = self.head().map_or(1, |pin| pin.sequence + 1);
        let mut identity = sequence.to_le_bytes().to_vec();
        identity.extend_from_slice(checkpoint);
        let pin = UploadJournalPin {
            sequence,
            root: ContentDigest::sha256(&identity),
        };
        self.records.push((pin, checkpoint.to_vec()));
        Ok(pin)
    }
}

fn checkpoint_trace(abort_before_start: bool) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut journal = RecordingJournal::default();
    let (_root_owner, mut parent, mut tree) = property()?;
    let mut child = parent.scope_down(
        &mut tree,
        RegionId::new("region:protocol-checkpoint")?,
        RegionKind::ObjectStore,
        allowance(),
        spec("operation:durable-upload", allowance())?,
        TimestampNs(1),
    )?;
    let control = Rc::new(DispatchControl::default());
    let mut transport = CrashTransport::new(MemoryTransport::default().store, control);
    let mut session = MultipartSession::prepare(
        &mut transport,
        &plan_chunks(3, policy())?,
        root(),
        OperationId::parse("operation:durable-upload")?,
        RESOURCE,
        TimestampNs(1),
    )?;
    session.attach_journal(
        &mut journal,
        UploadIo {
            authority: &mut child,
            tree: &tree,
            now: TimestampNs(1),
        },
        Vec::new(),
    )?;
    if abort_before_start {
        session.abort(UploadIo {
            authority: &mut child,
            tree: &tree,
            now: TimestampNs(2),
        })?;
    } else {
        session.start(UploadIo {
            authority: &mut child,
            tree: &tree,
            now: TimestampNs(2),
        })?;
    }
    drop(session);
    Ok(journal
        .records
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect())
}

impl UploadJournal for GuardedJournal {
    fn head(&self) -> Option<UploadJournalPin> {
        self.inner.head()
    }

    fn latest(&self) -> Option<&[u8]> {
        self.inner.latest()
    }

    fn contains(&self, pin: UploadJournalPin) -> bool {
        self.inner.contains(pin)
    }

    fn append(
        &mut self,
        expected: Option<UploadJournalPin>,
        checkpoint: &[u8],
    ) -> Result<UploadJournalPin, MultipartError> {
        if self.control.fail_next_append.replace(false) {
            return Err(MultipartError::Persistence(
                "injected durable checkpoint failure".into(),
            ));
        }
        let pin = self.inner.append(expected, checkpoint)?;
        if self.control.fail_after_append.replace(false) {
            return Err(MultipartError::Persistence(
                "checkpoint committed but append acknowledgement was lost".into(),
            ));
        }
        Ok(pin)
    }
}

#[test]
fn journal_excludes_other_writers_and_reopens_only_at_an_independent_pin() -> Test {
    let checkpoints = checkpoint_trace(false)?;
    assert!(checkpoints.len() >= 3);
    let directory = Directory::new()?;
    let mut journal = create(&directory)?;
    assert_eq!(journal.head(), None);
    let first = journal.append(None, &checkpoints[0])?;
    assert!(create(&directory).is_err());
    assert!(reopen(&directory, first).is_err());
    let second = journal.append(Some(first), &checkpoints[1])?;
    assert!(second.sequence > first.sequence);
    assert!(journal.contains(first));
    assert!(journal.append(Some(first), &checkpoints[2]).is_err());
    assert_eq!(journal.head(), Some(second));
    drop(journal);

    let reopened = reopen(&directory, first)?;
    assert_eq!(reopened.head(), Some(second));
    assert_eq!(reopened.latest(), Some(checkpoints[1].as_slice()));
    drop(reopened);
    assert!(
        reopen(
            &directory,
            UploadJournalPin {
                sequence: second.sequence,
                root: ContentDigest::sha256(b"another independently pinned journal"),
            },
        )
        .is_err()
    );
    emit("exclusive-writer-independent-minimum", 8);
    Ok(())
}

#[test]
fn corrupted_missing_and_rolled_back_records_cannot_be_recovered() -> Test {
    let checkpoints = checkpoint_trace(false)?;
    assert!(checkpoints.len() >= 3);
    for damage in 0..3 {
        let directory = Directory::new()?;
        let mut journal = create(&directory)?;
        let first = journal.append(None, &checkpoints[0])?;
        let first_files = directory.objects()?;
        let second = journal.append(Some(first), &checkpoints[1])?;
        let second_files = directory.objects()?;
        let middle = second_files
            .iter()
            .find(|path| !first_files.contains(path))
            .ok_or("second record file missing")?
            .clone();
        let third = journal.append(Some(second), &checkpoints[2])?;
        let last = directory
            .objects()?
            .into_iter()
            .find(|path| !second_files.contains(path))
            .ok_or("third record file missing")?;
        drop(journal);

        match damage {
            0 => {
                let mut bytes = fs::read(&middle)?;
                *bytes.last_mut().ok_or("empty journal record")? ^= 1;
                fs::write(&middle, bytes)?;
            }
            1 => fs::remove_file(&middle)?,
            _ => fs::remove_file(&last)?,
        }
        assert!(reopen(&directory, third).is_err());
        if damage != 2 {
            assert!(reopen(&directory, first).is_err());
        }
    }
    emit("corrupt-gap-and-minimum-rollback-refused", 3);
    Ok(())
}

#[test]
fn two_valid_successors_of_one_checkpoint_are_a_fork_not_a_latest_choice() -> Test {
    let initiated = checkpoint_trace(false)?;
    let aborted = checkpoint_trace(true)?;
    assert_eq!(initiated[0], aborted[0]);
    assert_ne!(initiated[1], aborted[1]);
    let left = Directory::new()?;
    let right = Directory::new()?;
    let mut left_journal = create(&left)?;
    let common = left_journal.append(None, &initiated[0])?;
    left_journal.append(Some(common), &initiated[1])?;
    drop(left_journal);
    let mut right_journal = create(&right)?;
    assert_eq!(right_journal.append(None, &aborted[0])?, common);
    right_journal.append(Some(common), &aborted[1])?;
    drop(right_journal);
    for source in right.objects()? {
        let target = left
            .0
            .join(SPOOL_OBJECTS_DIR)
            .join(source.file_name().ok_or("record filename missing")?);
        if !target.exists() {
            fs::copy(source, target)?;
        }
    }
    assert!(reopen(&left, common).is_err());
    emit("valid-fork-is-not-provider-recovery", 1);
    Ok(())
}

#[test]
fn append_and_reopen_obey_explicit_record_and_read_limits() -> Test {
    let checkpoints = checkpoint_trace(false)?;
    assert!(checkpoints.len() >= 3);
    let directory = Directory::new()?;
    let mut small = limits();
    small.max_records = 2;
    let mut journal = FileUploadJournal::create(&directory.0, small, Arc::new(HostSpoolIo))?;
    let first = journal.append(None, &checkpoints[0])?;
    let second = journal.append(Some(first), &checkpoints[1])?;
    assert!(journal.append(Some(second), &checkpoints[2]).is_err());
    assert_eq!(journal.head(), Some(second));
    drop(journal);

    let mut one_record = limits();
    one_record.max_records = 1;
    assert!(
        FileUploadJournal::open(&directory.0, one_record, Arc::new(HostSpoolIo), first).is_err()
    );
    let mut one_byte = limits();
    one_byte.max_read_bytes = 1;
    assert!(FileUploadJournal::open(&directory.0, one_byte, Arc::new(HostSpoolIo), first).is_err());
    let reopened = reopen(&directory, second)?;
    assert_eq!(reopened.latest(), Some(checkpoints[1].as_slice()));
    emit("bounded-journal-append-and-recovery", 4);
    Ok(())
}

#[test]
fn a_valid_older_checkpoint_cannot_reset_durable_phase_or_spend() -> Test {
    let checkpoints = checkpoint_trace(false)?;
    let directory = Directory::new()?;
    let mut journal = create(&directory)?;
    let mut head = None;
    for checkpoint in &checkpoints {
        head = Some(journal.append(head, checkpoint)?);
    }
    let files = directory.objects()?;
    assert!(journal.append(head, &checkpoints[0]).is_err());
    assert!(
        journal
            .append(head, b"not a canonical upload checkpoint")
            .is_err()
    );
    assert_eq!(journal.head(), head);
    assert_eq!(directory.objects()?, files);
    assert!(
        !journal.is_poisoned(),
        "pure invalid input must not perform ambiguous I/O"
    );
    let minimum = head.ok_or("fixture head missing")?;
    drop(journal);
    let reopened = reopen(&directory, minimum)?;
    assert_eq!(reopened.head(), Some(minimum));
    emit("semantic-rewind-and-malformed-checkpoint-refused", 2);
    Ok(())
}

#[test]
fn symlink_aliases_and_replaced_live_roots_cannot_redirect_journal_ownership() -> Test {
    use std::os::unix::fs::symlink;

    let checkpoints = checkpoint_trace(false)?;
    let directory = Directory::new()?;
    let root_path = directory.0.join("journal");
    let alias = directory.0.join("alias");
    let moved = directory.0.join("moved");
    let mut journal = FileUploadJournal::create(&root_path, limits(), Arc::new(HostSpoolIo))?;
    let first = journal.append(None, &checkpoints[0])?;
    drop(journal);
    symlink(&root_path, &alias)?;
    assert!(FileUploadJournal::create(&alias, limits(), Arc::new(HostSpoolIo)).is_err());
    assert!(FileUploadJournal::open(&alias, limits(), Arc::new(HostSpoolIo), first).is_err());

    let mut journal = FileUploadJournal::open(&root_path, limits(), Arc::new(HostSpoolIo), first)?;
    fs::rename(&root_path, &moved)?;
    fs::create_dir(&root_path)?;
    assert!(journal.append(Some(first), &checkpoints[1]).is_err());
    assert!(journal.is_poisoned());
    assert_eq!(journal.head(), Some(first));
    assert_eq!(fs::read_dir(&root_path)?.count(), 0);
    drop(journal);
    let reopened = FileUploadJournal::open(&moved, limits(), Arc::new(HostSpoolIo), first)?;
    assert_eq!(reopened.head(), Some(first));
    emit("symlink-and-root-replacement-refused", 4);
    Ok(())
}

#[test]
fn actual_filesystem_failures_never_invent_a_committed_head_and_require_cold_open() -> Test {
    let checkpoints = checkpoint_trace(false)?;
    let counts = {
        let directory = Directory::new()?;
        let io = Arc::new(FaultInjectingSpoolIo::new(SpoolFaultPlan::new()));
        let mut journal = FileUploadJournal::create(&directory.0, limits(), io.clone())?;
        journal.append(None, &checkpoints[0])?;
        SpoolIoCall::ALL
            .into_iter()
            .map(|call| (call, io.calls(call)))
            .collect::<Vec<_>>()
    };
    let next = |call| {
        counts
            .iter()
            .find(|(actual, _)| *actual == call)
            .map(|(_, count)| count + 1)
            .expect("all spool calls have baseline counts")
    };
    for (call, after, retained, orphan) in [
        (SpoolIoCall::Write, false, false, false),
        (SpoolIoCall::SyncFile, false, false, false),
        (SpoolIoCall::Rename, false, false, false),
        (SpoolIoCall::Rename, true, true, false),
        (SpoolIoCall::SyncDirectory, false, true, false),
        (SpoolIoCall::SyncDirectory, true, true, false),
        (SpoolIoCall::Write, false, false, true),
    ] {
        let directory = Directory::new()?;
        let plan = if after {
            SpoolFaultPlan::new().fail_after_applying(call, next(call), io::ErrorKind::Other)
        } else {
            SpoolFaultPlan::new().fail(call, next(call), io::ErrorKind::Other)
        };
        let plan = if orphan {
            plan.fail(
                SpoolIoCall::RemoveFile,
                next(SpoolIoCall::RemoveFile),
                io::ErrorKind::PermissionDenied,
            )
        } else {
            plan
        };
        let io = Arc::new(FaultInjectingSpoolIo::new(plan));
        let mut journal = FileUploadJournal::create(&directory.0, limits(), io.clone())?;
        let first = journal.append(None, &checkpoints[0])?;
        assert!(journal.append(Some(first), &checkpoints[1]).is_err());
        assert!(
            io.all_fired(),
            "fault {call:?}, after={after}, orphan={orphan}"
        );
        assert!(journal.is_poisoned());
        assert_eq!(journal.head(), Some(first));
        assert!(journal.append(Some(first), &checkpoints[1]).is_err());
        drop(journal);

        let mut reopened = reopen(&directory, first)?;
        assert_eq!(
            reopened.latest(),
            Some(checkpoints[usize::from(retained)].as_slice()),
        );
        assert_eq!(reopened.orphaned_staging_count(), usize::from(orphan));
        if retained {
            assert_eq!(
                reopened.head().ok_or("recovered head missing")?.sequence,
                first.sequence + 1
            );
        } else {
            assert_eq!(reopened.head(), Some(first));
            reopened.append(Some(first), &checkpoints[1])?;
        }
    }
    emit("real-io-faults-retain-ambiguity-and-orphans", 7);
    Ok(())
}

#[test]
fn abrupt_exit_after_each_provider_mutation_cold_reopens_uncertain_without_resend() -> Test {
    for operation in [
        TransportOperation::Initiate,
        TransportOperation::UploadPart,
        TransportOperation::Complete,
        TransportOperation::Abort,
    ] {
        let directory = Directory::new()?;
        let store = MemoryTransport::default().store;
        let control = Rc::new(DispatchControl::default());
        let (minimum, expected) = {
            let mut journal = create(&directory)?;
            let (_root_owner, mut parent, mut tree) = property()?;
            let mut transport = CrashTransport::new(store.clone(), control.clone());
            let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
            let minimum = upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
            let expected = upload.intent().clone();
            if operation != TransportOperation::Initiate {
                upload.start(&tree, TimestampNs(2))?;
            }
            if matches!(
                operation,
                TransportOperation::Complete | TransportOperation::Abort
            ) {
                upload.upload_part(&tree, TimestampNs(3), 0, b"abc")?;
            }
            control.crash_after.set(Some(operation));
            let exited = catch_unwind(AssertUnwindSafe(|| match operation {
                TransportOperation::Initiate => upload.start(&tree, TimestampNs(4)),
                TransportOperation::UploadPart => upload
                    .upload_part(&tree, TimestampNs(4), 0, b"abc")
                    .map(|_| ()),
                TransportOperation::Complete => {
                    upload.finish(&mut tree, TimestampNs(4)).map(|_| ())
                }
                TransportOperation::Abort => upload.cancel(&mut tree, TimestampNs(4)).map(|_| ()),
                TransportOperation::Reconcile => unreachable!(),
            }));
            assert!(
                exited.is_err(),
                "the provider must exit before returning its ACK"
            );
            assert_eq!(call_count(&store, operation), 1);
            (minimum, expected)
        };

        let mut journal = reopen(&directory, minimum)?;
        let (_root_owner, mut parent, mut tree) = property()?;
        let mut transport = CrashTransport::new(store.clone(), control);
        let mut upload = recover(
            &mut parent,
            &mut tree,
            &mut transport,
            &mut journal,
            minimum,
            &expected,
            TimestampNs(5),
        )?;
        assert_eq!(upload.phase(), MultipartPhase::Uncertain(operation));
        let calls = store.borrow().calls.clone();
        assert!(upload.start(&tree, TimestampNs(5)).is_err());
        assert!(
            upload
                .upload_part(&tree, TimestampNs(5), 0, b"abc")
                .is_err()
        );
        assert!(upload.finish(&mut tree, TimestampNs(5)).is_err());
        assert!(upload.cancel(&mut tree, TimestampNs(5)).is_err());
        assert!(
            upload
                .upload_chunks(
                    &tree,
                    || TimestampNs(5),
                    |_| panic!("uncertain recovered owner read payload"),
                )
                .is_err()
        );
        assert_eq!(store.borrow().calls, calls);

        let phase = upload.reconcile(&mut tree, TimestampNs(6))?;
        match operation {
            TransportOperation::Initiate => {
                assert_eq!(phase, MultipartPhase::Uploading);
                assert_eq!(upload.confirmed_parts(), 0);
                upload.cancel(&mut tree, TimestampNs(7))?;
            }
            TransportOperation::UploadPart => {
                assert_eq!(phase, MultipartPhase::Uploading);
                assert_eq!(upload.confirmed_parts(), 1);
                upload.upload_chunks(
                    &tree,
                    || TimestampNs(7),
                    |_| panic!("provider-confirmed part was reread after recovery"),
                )?;
                upload.finish(&mut tree, TimestampNs(8))?;
            }
            TransportOperation::Complete => assert_eq!(phase, MultipartPhase::Completed),
            TransportOperation::Abort => assert_eq!(phase, MultipartPhase::Aborted),
            TransportOperation::Reconcile => unreachable!(),
        }
        assert_eq!(call_count(&store, operation), 1);
        assert_eq!(call_count(&store, TransportOperation::Reconcile), 1);
        assert_eq!(tree.get(upload.region())?.state, RegionState::Closed);
    }
    emit("cold-exit-every-mutation-no-blind-resend", 4);
    Ok(())
}

#[test]
fn lost_part_intent_survives_restart_even_when_provider_reports_no_part() -> Test {
    let directory = Directory::new()?;
    let store = MemoryTransport::default().store;
    let control = Rc::new(DispatchControl::default());
    let (minimum, expected) = {
        let mut journal = create(&directory)?;
        let (_root_owner, mut parent, mut tree) = property()?;
        let mut transport = CrashTransport::new(store.clone(), control.clone());
        let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
        let minimum = upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
        let expected = upload.intent().clone();
        upload.start(&tree, TimestampNs(2))?;
        store.borrow_mut().fault_once = Some(TransportOperation::UploadPart);
        store.borrow_mut().fail_before_effect = true;
        assert!(
            upload
                .upload_part(&tree, TimestampNs(3), 0, b"abc")
                .is_err()
        );
        assert!(store.borrow().parts.is_empty());
        (minimum, expected)
    };

    let mut journal = reopen(&directory, minimum)?;
    let (_root_owner, mut parent, mut tree) = property()?;
    let mut transport = CrashTransport::new(store.clone(), control);
    let mut upload = recover(
        &mut parent,
        &mut tree,
        &mut transport,
        &mut journal,
        minimum,
        &expected,
        TimestampNs(4),
    )?;
    assert_eq!(
        upload.reconcile(&mut tree, TimestampNs(5))?,
        MultipartPhase::Uploading
    );
    assert_eq!(upload.confirmed_parts(), 0);
    assert!(
        upload
            .upload_part(&tree, TimestampNs(6), 0, b"xyz")
            .is_err()
    );
    assert_eq!(call_count(&store, TransportOperation::UploadPart), 1);
    let receipt = upload.upload_part(&tree, TimestampNs(7), 0, b"abc")?;
    assert_eq!(receipt.content_digest, ContentDigest::sha256(b"abc"));
    assert_eq!(call_count(&store, TransportOperation::UploadPart), 2);
    upload.finish(&mut tree, TimestampNs(8))?;
    assert_eq!(upload.cumulative_consumed()?.bytes, 6);
    emit("cold-recovery-retains-first-part-digest", 5);
    Ok(())
}

#[test]
fn repeated_cold_recovery_preserves_dynamic_transport_spend_and_remaining_allowance() -> Test {
    let directory = Directory::new()?;
    let store = MemoryTransport::default().store;
    store.borrow_mut().envelope_bytes = 7;
    let control = Rc::new(DispatchControl::default());
    let (minimum, expected) = {
        let mut journal = create(&directory)?;
        let (_root_owner, mut parent, mut tree) = property()?;
        let mut transport = CrashTransport::new(store.clone(), control.clone());
        let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
        let minimum = upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
        let expected = upload.intent().clone();
        control.crash_after.set(Some(TransportOperation::Initiate));
        assert!(catch_unwind(AssertUnwindSafe(|| upload.start(&tree, TimestampNs(2)))).is_err());
        (minimum, expected)
    };
    store.borrow_mut().unknown = true;

    for completed_queries in 0_u64..3 {
        let mut journal = reopen(&directory, minimum)?;
        let (_root_owner, mut parent, mut tree) = property()?;
        let mut transport = CrashTransport::new(store.clone(), control.clone());
        let now = TimestampNs(i128::from(3 + completed_queries * 2));
        let mut upload = recover(
            &mut parent,
            &mut tree,
            &mut transport,
            &mut journal,
            minimum,
            &expected,
            now,
        )?;
        let prior_calls = completed_queries + 1;
        let consumed = upload.cumulative_consumed()?;
        assert_eq!(consumed.storage_operations, prior_calls);
        assert_eq!(consumed.bytes, prior_calls * 7);
        assert_eq!(consumed.network_bytes, prior_calls * 7);
        assert_eq!(
            upload.budget().remaining().storage_operations,
            12 - prior_calls
        );
        assert_eq!(
            upload.budget().remaining().network_bytes,
            128 - prior_calls * 7
        );
        assert_eq!(
            upload.reconcile(&mut tree, TimestampNs(now.0 + 1))?,
            MultipartPhase::Uncertain(TransportOperation::Initiate)
        );
        assert_eq!(
            upload.cumulative_consumed()?.storage_operations,
            prior_calls + 1
        );
        assert_eq!(
            upload.cumulative_consumed()?.network_bytes,
            (prior_calls + 1) * 7
        );
    }
    assert_eq!(call_count(&store, TransportOperation::Initiate), 1);
    assert_eq!(call_count(&store, TransportOperation::Reconcile), 3);
    let journal = reopen(&directory, minimum)?;
    let recovery = MultipartRecovery::read(&journal, minimum)?;
    assert_eq!(recovery.remaining_budget().storage_operations, 8);
    assert_eq!(recovery.remaining_budget().network_bytes, 100);
    emit("cold-restarts-preserve-transport-budget", 3);
    Ok(())
}

#[test]
fn write_ahead_failure_prevents_provider_dispatch_and_poisons_live_retries() -> Test {
    let directory = Directory::new()?;
    let store = MemoryTransport::default().store;
    let control = Rc::new(DispatchControl::default());
    let (minimum, expected) = {
        let mut journal = GuardedJournal {
            inner: create(&directory)?,
            control: control.clone(),
        };
        let (_root_owner, mut parent, mut tree) = property()?;
        let before = parent.budget().remaining();
        let mut transport = CrashTransport::new(store.clone(), control.clone());
        let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
        let minimum = upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
        let expected = upload.intent().clone();
        control.fail_next_append.set(true);
        assert!(upload.start(&tree, TimestampNs(2)).is_err());
        assert!(store.borrow().calls.is_empty());
        assert!(upload.start(&tree, TimestampNs(3)).is_err());
        assert!(upload.cancel(&mut tree, TimestampNs(3)).is_err());
        let node = tree.get(upload.region())?;
        assert_eq!(
            node.obligations[upload.obligation()].state,
            ObligationState::Pending
        );
        assert!(node.quiescence_proof.is_none());
        drop(upload);
        assert_eq!(
            before.bytes - parent.budget().remaining().bytes,
            allowance().bytes
        );
        (minimum, expected)
    };
    let mut journal = reopen(&directory, minimum)?;
    let (_root_owner, mut parent, mut tree) = property()?;
    let mut transport = CrashTransport::new(store.clone(), control);
    let mut upload = recover(
        &mut parent,
        &mut tree,
        &mut transport,
        &mut journal,
        minimum,
        &expected,
        TimestampNs(4),
    )?;
    assert_eq!(upload.phase(), MultipartPhase::Prepared);
    upload.upload_chunks(&tree, || TimestampNs(5), |_| b"abc".to_vec())?;
    upload.finish(&mut tree, TimestampNs(6))?;
    assert_eq!(call_count(&store, TransportOperation::Initiate), 1);
    emit("failed-write-ahead-forbids-dispatch-and-refund", 6);
    Ok(())
}

#[test]
fn initial_checkpoint_failure_retains_pending_owner_and_blocks_all_provider_work() -> Test {
    let directory = Directory::new()?;
    let store = MemoryTransport::default().store;
    let control = Rc::new(DispatchControl::default());
    let mut journal = GuardedJournal {
        inner: create(&directory)?,
        control: control.clone(),
    };
    let (_root_owner, mut parent, mut tree) = property()?;
    let before = parent.budget().remaining();
    let mut transport = CrashTransport::new(store.clone(), control.clone());
    let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
    control.fail_next_append.set(true);
    assert!(
        upload
            .attach_journal(&tree, TimestampNs(1), &mut journal)
            .is_err()
    );
    assert!(upload.start(&tree, TimestampNs(2)).is_err());
    assert!(upload.cancel(&mut tree, TimestampNs(2)).is_err());
    assert!(store.borrow().calls.is_empty());
    let node = tree.get(upload.region())?;
    assert_eq!(
        node.obligations[upload.obligation()].state,
        ObligationState::Pending
    );
    assert_ne!(node.state, RegionState::Closed);
    drop(upload);
    assert_eq!(
        before.bytes - parent.budget().remaining().bytes,
        allowance().bytes
    );
    emit("failed-initial-checkpoint-keeps-obligation", 5);
    Ok(())
}

#[test]
fn failed_acknowledgement_checkpoint_recovers_uncertainty_for_every_mutation() -> Test {
    for operation in [
        TransportOperation::Initiate,
        TransportOperation::UploadPart,
        TransportOperation::Complete,
        TransportOperation::Abort,
    ] {
        let directory = Directory::new()?;
        let store = MemoryTransport::default().store;
        let control = Rc::new(DispatchControl::default());
        let (minimum, expected) = {
            let mut journal = GuardedJournal {
                inner: create(&directory)?,
                control: control.clone(),
            };
            let (_root_owner, mut parent, mut tree) = property()?;
            let mut transport = CrashTransport::new(store.clone(), control.clone());
            let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
            let minimum = upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
            let expected = upload.intent().clone();
            if operation != TransportOperation::Initiate {
                upload.start(&tree, TimestampNs(2))?;
            }
            if matches!(
                operation,
                TransportOperation::Complete | TransportOperation::Abort
            ) {
                upload.upload_part(&tree, TimestampNs(3), 0, b"abc")?;
            }
            control.fail_journal_after.set(Some(operation));
            let result = match operation {
                TransportOperation::Initiate => upload.start(&tree, TimestampNs(4)),
                TransportOperation::UploadPart => upload
                    .upload_part(&tree, TimestampNs(4), 0, b"abc")
                    .map(|_| ()),
                TransportOperation::Complete => {
                    upload.finish(&mut tree, TimestampNs(4)).map(|_| ())
                }
                TransportOperation::Abort => upload.cancel(&mut tree, TimestampNs(4)).map(|_| ()),
                TransportOperation::Reconcile => unreachable!(),
            };
            assert!(result.is_err());
            assert!(
                !control.fail_next_append.get(),
                "the outcome append must be attempted"
            );
            assert_eq!(upload.phase(), MultipartPhase::Uncertain(operation));
            assert_eq!(
                tree.get(upload.region())?.obligations[upload.obligation()].state,
                ObligationState::Pending,
            );
            let calls = store.borrow().calls.clone();
            assert!(upload.reconcile(&mut tree, TimestampNs(5)).is_err());
            assert!(upload.finish(&mut tree, TimestampNs(5)).is_err());
            assert!(upload.cancel(&mut tree, TimestampNs(5)).is_err());
            assert_eq!(store.borrow().calls, calls);
            (minimum, expected)
        };

        let mut journal = reopen(&directory, minimum)?;
        let (_root_owner, mut parent, mut tree) = property()?;
        let mut transport = CrashTransport::new(store.clone(), control);
        let mut upload = recover(
            &mut parent,
            &mut tree,
            &mut transport,
            &mut journal,
            minimum,
            &expected,
            TimestampNs(6),
        )?;
        assert_eq!(upload.phase(), MultipartPhase::Uncertain(operation));
        let phase = upload.reconcile(&mut tree, TimestampNs(7))?;
        assert_eq!(
            phase,
            match operation {
                TransportOperation::Complete => MultipartPhase::Completed,
                TransportOperation::Abort => MultipartPhase::Aborted,
                _ => MultipartPhase::Uploading,
            },
        );
        assert_eq!(call_count(&store, operation), 1);
    }
    emit("failed-postcall-checkpoint-withholds-success", 4);
    Ok(())
}

#[test]
fn recovery_refuses_changed_authority_resource_and_replenished_budget_before_attachment() -> Test {
    let directory = Directory::new()?;
    let store = MemoryTransport::default().store;
    let control = Rc::new(DispatchControl::default());
    let (minimum, expected) = {
        let mut journal = create(&directory)?;
        let (_root_owner, mut parent, mut tree) = property()?;
        let mut transport = CrashTransport::new(store.clone(), control.clone());
        let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
        let minimum = upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
        let expected = upload.intent().clone();
        upload.start(&tree, TimestampNs(2))?;
        (minimum, expected)
    };
    let mut alternate_transport = MemoryTransport::default();
    let alternate = MultipartSession::prepare(
        &mut alternate_transport,
        &plan_chunks(3, policy())?,
        root(),
        OperationId::parse("operation:durable-upload")?,
        "archive:another-store/evidence-object",
        TimestampNs(1),
    )?
    .intent()
    .clone();
    for mutation in 0..7 {
        let mut journal = reopen(&directory, minimum)?;
        let head = journal.head();
        let recovery = MultipartRecovery::read(&journal, minimum)?;
        let mut child = spec("operation:durable-upload", recovery.remaining_budget())?;
        match mutation {
            0 => child.principal = "principal:unrelated".into(),
            1 => child.trace_id = "trace:unrelated".into(),
            2 => child.anchor_universe = ContentDigest::sha256(b"different authority anchor"),
            3 => child.generation += 1,
            4 => child.privacy_scope = "privacy:unrelated".into(),
            5 => child.budgets.storage_operations += 1,
            _ => {}
        }
        let (_root_owner, mut parent, mut tree) = property()?;
        let before = parent.budget().remaining();
        let nodes = tree.iter().count();
        let calls = store.borrow().calls.clone();
        let mut transport = CrashTransport::new(store.clone(), control.clone());
        let intent = if mutation == 6 { &alternate } else { &expected };
        assert!(
            StagedUpload::recover(
                &mut parent,
                &mut tree,
                &mut transport,
                &mut journal,
                recovery,
                intent,
                child,
                TimestampNs(3),
            )
            .is_err()
        );
        assert_eq!(tree.iter().count(), nodes);
        assert_eq!(parent.budget().remaining(), before);
        assert_eq!(journal.head(), head);
        assert_eq!(store.borrow().calls, calls);
    }
    emit(
        "foreign-authority-intent-and-budget-refused-before-ownership",
        7,
    );
    Ok(())
}

#[test]
fn durable_completion_survives_blocked_local_finalization_without_resend_or_double_refund() -> Test
{
    let directory = Directory::new()?;
    let store = MemoryTransport::default().store;
    let control = Rc::new(DispatchControl::default());
    let (minimum, expected, proof) = {
        let mut journal = create(&directory)?;
        let (_root_owner, mut parent, mut tree) = property()?;
        let before = parent.budget().remaining();
        let mut transport = CrashTransport::new(store.clone(), control.clone());
        let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
        let minimum = upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
        let expected = upload.intent().clone();
        upload.upload_chunks(&tree, || TimestampNs(2), |_| b"abc".to_vec())?;
        let task = TaskId::new("task:old-process-finalizer")?;
        tree.register_task(upload.region(), task, TimestampNs(2))?;
        assert!(upload.finish(&mut tree, TimestampNs(3)).is_err());
        assert_eq!(upload.phase(), MultipartPhase::Completed);
        let node = tree.get(upload.region())?;
        assert_eq!(node.state, RegionState::Draining);
        let proof = node.obligations[upload.obligation()]
            .proof_digest
            .ok_or("durable completion proof missing")?;
        drop(upload);
        assert_eq!(
            before.bytes - parent.budget().remaining().bytes,
            allowance().bytes
        );
        (minimum, expected, proof)
    };
    let calls = store.borrow().calls.clone();
    let mut journal = reopen(&directory, minimum)?;
    let (_root_owner, mut parent, mut tree) = property()?;
    let before = parent.budget().remaining();
    let mut transport = CrashTransport::new(store.clone(), control);
    let mut upload = recover(
        &mut parent,
        &mut tree,
        &mut transport,
        &mut journal,
        minimum,
        &expected,
        TimestampNs(4),
    )?;
    assert_eq!(upload.phase(), MultipartPhase::Completed);
    let receipt = upload.finish(&mut tree, TimestampNs(5))?;
    assert_eq!(receipt.digest(), proof);
    assert_eq!(upload.finish(&mut tree, TimestampNs(6))?, receipt);
    assert_eq!(upload.cumulative_consumed()?.bytes, 3);
    assert_eq!(upload.cumulative_consumed()?.storage_operations, 3);
    assert_eq!(tree.get(upload.region())?.state, RegionState::Closed);
    assert_eq!(store.borrow().calls, calls);
    drop(upload);
    assert_eq!(parent.budget().remaining(), before);
    emit("cold-terminal-finalization-is-local-and-refunds-once", 7);
    Ok(())
}

#[test]
fn indeterminate_settlement_survives_restart_and_cannot_reopen_provider_work() -> Test {
    let directory = Directory::new()?;
    let store = MemoryTransport::default().store;
    let control = Rc::new(DispatchControl::default());
    let note = "operator owns unresolved initiation readback";
    let reference = ContentDigest::sha256(b"retained operator follow-up record");
    let (minimum, expected, retained) = {
        let mut journal = create(&directory)?;
        let (_root_owner, mut parent, mut tree) = property()?;
        let mut transport = CrashTransport::new(store.clone(), control.clone());
        let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
        let minimum = upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
        let expected = upload.intent().clone();
        store.borrow_mut().fault_once = Some(TransportOperation::Initiate);
        assert!(upload.start(&tree, TimestampNs(2)).is_err());
        let task = TaskId::new("task:unresolved-local-finalizer")?;
        tree.register_task(upload.region(), task, TimestampNs(2))?;
        assert!(
            upload
                .settle_indeterminate(&mut tree, TimestampNs(3), note, reference)
                .is_err()
        );
        let retained = upload
            .indeterminate_receipt()
            .ok_or("receipt missing")?
            .clone();
        assert_eq!(
            tree.get(upload.region())?.obligations[upload.obligation()].state,
            ObligationState::Indeterminate,
        );
        (minimum, expected, retained)
    };
    let calls = store.borrow().calls.clone();
    let mut journal = reopen(&directory, minimum)?;
    let (_root_owner, mut parent, mut tree) = property()?;
    let mut transport = CrashTransport::new(store.clone(), control);
    let mut upload = recover(
        &mut parent,
        &mut tree,
        &mut transport,
        &mut journal,
        minimum,
        &expected,
        TimestampNs(4),
    )?;
    assert_eq!(upload.indeterminate_receipt(), Some(&retained));
    assert!(upload.start(&tree, TimestampNs(5)).is_err());
    assert!(upload.reconcile(&mut tree, TimestampNs(5)).is_err());
    assert!(upload.cancel(&mut tree, TimestampNs(5)).is_err());
    assert!(
        upload
            .settle_indeterminate(&mut tree, TimestampNs(5), "changed note", reference)
            .is_err()
    );
    let settled = upload.settle_indeterminate(&mut tree, TimestampNs(6), note, reference)?;
    assert_eq!(settled, retained);
    assert_eq!(
        upload.settle_indeterminate(&mut tree, TimestampNs(7), note, reference)?,
        retained,
    );
    assert_eq!(
        upload.phase(),
        MultipartPhase::Uncertain(TransportOperation::Initiate)
    );
    assert_eq!(tree.get(upload.region())?.state, RegionState::Closed);
    assert_eq!(store.borrow().calls, calls);
    emit(
        "cold-indeterminate-closure-retains-proof-and-fences-provider",
        7,
    );
    Ok(())
}

#[test]
fn narrowed_deadline_survives_a_third_process_and_expired_cleanup_remains_owned() -> Test {
    let directory = Directory::new()?;
    let store = MemoryTransport::default().store;
    let control = Rc::new(DispatchControl::default());
    let (minimum, expected) = {
        let mut journal = create(&directory)?;
        let (_root_owner, mut parent, mut tree) = property()?;
        let mut transport = CrashTransport::new(store.clone(), control.clone());
        let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
        let minimum = upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
        let expected = upload.intent().clone();
        upload.start(&tree, TimestampNs(2))?;
        (minimum, expected)
    };
    let restriction_pin = {
        let mut journal = reopen(&directory, minimum)?;
        let recovery = MultipartRecovery::read(&journal, minimum)?;
        let mut child = spec("operation:durable-upload", recovery.remaining_budget())?;
        child.deadline = Some(TimestampNs(8));
        let (_root_owner, mut parent, mut tree) = property()?;
        let mut transport = CrashTransport::new(store.clone(), control.clone());
        let mut upload = StagedUpload::recover(
            &mut parent,
            &mut tree,
            &mut transport,
            &mut journal,
            recovery,
            &expected,
            child,
            TimestampNs(3),
        )?;
        upload.checkpoint(&tree, TimestampNs(4))?
    };

    let mut journal = reopen(&directory, restriction_pin)?;
    let recovery = MultipartRecovery::read(&journal, restriction_pin)?;
    assert_eq!(recovery.deadline(), Some(TimestampNs(8)));
    let mut widened = spec("operation:durable-upload", recovery.remaining_budget())?;
    widened.deadline = Some(TimestampNs(9));
    let (_root_owner, mut parent, mut tree) = property()?;
    let before = parent.budget().remaining();
    let nodes = tree.iter().count();
    let mut transport = CrashTransport::new(store.clone(), control);
    assert!(
        StagedUpload::recover(
            &mut parent,
            &mut tree,
            &mut transport,
            &mut journal,
            recovery,
            &expected,
            widened,
            TimestampNs(9),
        )
        .is_err()
    );
    assert_eq!(parent.budget().remaining(), before);
    assert_eq!(tree.iter().count(), nodes);

    let recovery = MultipartRecovery::read(&journal, restriction_pin)?;
    let mut child = spec("operation:durable-upload", recovery.remaining_budget())?;
    child.deadline = Some(TimestampNs(8));
    let mut upload = StagedUpload::recover(
        &mut parent,
        &mut tree,
        &mut transport,
        &mut journal,
        recovery,
        &expected,
        child,
        TimestampNs(9),
    )?;
    assert_eq!(upload.phase(), MultipartPhase::Uploading);
    assert!(
        upload
            .upload_part(&tree, TimestampNs(9), 0, b"abc")
            .is_err()
    );
    assert_eq!(call_count(&store, TransportOperation::UploadPart), 0);
    upload.cancel(&mut tree, TimestampNs(10))?;
    assert_eq!(call_count(&store, TransportOperation::Initiate), 1);
    assert_eq!(call_count(&store, TransportOperation::Abort), 1);
    assert_eq!(tree.get(upload.region())?.state, RegionState::Closed);
    emit("third-process-retains-narrowed-deadline-and-cleanup", 6);
    Ok(())
}

#[test]
fn durable_stop_preserves_pending_prepared_uploading_and_uncertain_owners_across_restart() -> Test {
    for phase in 0..3 {
        let directory = Directory::new()?;
        let store = MemoryTransport::default().store;
        let control = Rc::new(DispatchControl::default());
        let (minimum, expected, stopped_phase, spent) = {
            let mut journal = create(&directory)?;
            let (_root_owner, mut parent, mut tree) = property()?;
            let before = parent.budget().remaining();
            let mut transport = CrashTransport::new(store.clone(), control.clone());
            let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
            upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
            let expected = upload.intent().clone();
            if phase != 0 {
                upload.start(&tree, TimestampNs(2))?;
                if phase == 2 {
                    store.borrow_mut().fault_once = Some(TransportOperation::UploadPart);
                    assert!(
                        upload
                            .upload_part(&tree, TimestampNs(3), 0, b"abc")
                            .is_err()
                    );
                } else {
                    upload.upload_part(&tree, TimestampNs(3), 0, b"abc")?;
                }
            }
            let stopped_phase = upload.phase();
            let spent = upload.cumulative_consumed()?;
            let calls = store.borrow().calls.clone();
            upload.request_cancellation(&mut tree, TimestampNs(4))?;
            let minimum = upload.journal_pin().ok_or("durable stop pin missing")?;
            assert_eq!(upload.phase(), stopped_phase);
            assert_eq!(upload.cumulative_consumed()?, spent);
            let node = tree.get(upload.region())?;
            assert!(node.authority.cancellation_reason.is_some());
            assert_eq!(
                node.obligations[upload.obligation()].state,
                ObligationState::Pending
            );
            assert!(node.quiescence_proof.is_none());
            assert!(upload.finish(&mut tree, TimestampNs(4)).is_err());
            assert!(
                upload
                    .upload_chunks(
                        &tree,
                        || TimestampNs(4),
                        |_| panic!("stopped owner read a payload source"),
                    )
                    .is_err()
            );
            assert_eq!(store.borrow().calls, calls);
            assert_eq!(upload.cumulative_consumed()?, spent);
            drop(upload);
            assert_eq!(
                before.bytes - parent.budget().remaining().bytes,
                allowance().bytes
            );
            (minimum, expected, stopped_phase, spent)
        };

        let mut journal = reopen(&directory, minimum)?;
        let (_root_owner, mut parent, mut tree) = property()?;
        let mut transport = CrashTransport::new(store.clone(), control);
        let mut upload = recover(
            &mut parent,
            &mut tree,
            &mut transport,
            &mut journal,
            minimum,
            &expected,
            TimestampNs(5),
        )?;
        assert_eq!(upload.phase(), stopped_phase);
        assert_eq!(upload.cumulative_consumed()?, spent);
        assert!(
            tree.get(upload.region())?
                .authority
                .cancellation_reason
                .is_some()
        );
        let calls = store.borrow().calls.clone();
        assert!(upload.finish(&mut tree, TimestampNs(5)).is_err());
        assert!(
            upload
                .upload_chunks(
                    &tree,
                    || TimestampNs(5),
                    |_| panic!("recovered stopped owner read a payload source"),
                )
                .is_err()
        );
        assert_eq!(store.borrow().calls, calls);
        if phase == 2 {
            assert_eq!(
                upload.reconcile(&mut tree, TimestampNs(6))?,
                MultipartPhase::Uploading,
            );
        }
        upload.cancel(&mut tree, TimestampNs(7))?;
        assert_eq!(tree.get(upload.region())?.state, RegionState::Closed);
        assert_eq!(call_count(&store, TransportOperation::Complete), 0);
        assert_eq!(
            call_count(&store, TransportOperation::Abort),
            usize::from(phase != 0)
        );
    }
    emit("durable-stop-preserves-owned-cleanup-through-restart", 3);
    Ok(())
}

#[test]
fn stop_append_refusal_and_lost_ack_recover_only_the_record_that_committed() -> Test {
    for committed in [false, true] {
        let directory = Directory::new()?;
        let store = MemoryTransport::default().store;
        let control = Rc::new(DispatchControl::default());
        let (minimum, expected) = {
            let mut journal = GuardedJournal {
                inner: create(&directory)?,
                control: control.clone(),
            };
            let (_root_owner, mut parent, mut tree) = property()?;
            let before = parent.budget().remaining();
            let mut transport = CrashTransport::new(store.clone(), control.clone());
            let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
            let minimum = upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
            let expected = upload.intent().clone();
            upload.upload_chunks(&tree, || TimestampNs(2), |_| b"abc".to_vec())?;
            let calls = store.borrow().calls.clone();
            let spent = upload.cumulative_consumed()?;
            control.fail_next_append.set(!committed);
            control.fail_after_append.set(committed);
            assert!(
                upload
                    .request_cancellation(&mut tree, TimestampNs(3))
                    .is_err()
            );
            assert!(upload.durability_failed());
            assert!(!control.fail_next_append.get());
            assert!(!control.fail_after_append.get());
            let node = tree.get(upload.region())?;
            assert!(node.authority.cancellation_reason.is_none());
            assert_eq!(
                node.obligations[upload.obligation()].state,
                ObligationState::Pending
            );
            assert!(node.quiescence_proof.is_none());
            assert!(
                upload
                    .request_cancellation(&mut tree, TimestampNs(4))
                    .is_err()
            );
            assert!(upload.finish(&mut tree, TimestampNs(4)).is_err());
            assert!(upload.cancel(&mut tree, TimestampNs(4)).is_err());
            assert!(
                upload
                    .upload_chunks(
                        &tree,
                        || TimestampNs(4),
                        |_| panic!("failed stop persistence released payload access"),
                    )
                    .is_err()
            );
            assert_eq!(upload.cumulative_consumed()?, spent);
            assert_eq!(store.borrow().calls, calls);
            drop(upload);
            assert_eq!(
                before.bytes - parent.budget().remaining().bytes,
                allowance().bytes
            );
            (minimum, expected)
        };

        let mut journal = reopen(&directory, minimum)?;
        let (_root_owner, mut parent, mut tree) = property()?;
        let mut transport = CrashTransport::new(store.clone(), control);
        let mut upload = recover(
            &mut parent,
            &mut tree,
            &mut transport,
            &mut journal,
            minimum,
            &expected,
            TimestampNs(5),
        )?;
        assert_eq!(
            tree.get(upload.region())?
                .authority
                .cancellation_reason
                .is_some(),
            committed,
        );
        let calls = store.borrow().calls.clone();
        let recovered_pin = upload.journal_pin();
        upload.request_cancellation(&mut tree, TimestampNs(5))?;
        if committed {
            assert_eq!(upload.journal_pin(), recovered_pin);
        }
        assert!(upload.finish(&mut tree, TimestampNs(6)).is_err());
        assert_eq!(store.borrow().calls, calls);
        upload.cancel(&mut tree, TimestampNs(7))?;
        assert_eq!(call_count(&store, TransportOperation::Abort), 1);
        assert_eq!(call_count(&store, TransportOperation::Complete), 0);
        assert_eq!(tree.get(upload.region())?.state, RegionState::Closed);
    }
    emit("stop-persistence-before-and-after-commit-faults", 2);
    Ok(())
}

#[test]
fn stop_retry_is_local_but_wrong_owner_and_backdated_requests_are_refused() -> Test {
    let directory = Directory::new()?;
    let store = MemoryTransport::default().store;
    let control = Rc::new(DispatchControl::default());
    let mut journal = create(&directory)?;
    let (_root_owner, mut parent, mut tree) = property()?;
    let (_other_root, _other_parent, mut wrong_tree) = property()?;
    let mut transport = CrashTransport::new(store.clone(), control);
    let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
    upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
    let initial = upload.journal_pin();
    assert!(
        upload
            .request_cancellation(&mut wrong_tree, TimestampNs(2))
            .is_err()
    );
    assert!(
        upload
            .request_cancellation(&mut tree, TimestampNs(0))
            .is_err()
    );
    assert_eq!(upload.journal_pin(), initial);
    assert!(
        tree.get(upload.region())?
            .authority
            .cancellation_reason
            .is_none()
    );

    upload.request_cancellation(&mut tree, TimestampNs(2))?;
    let accepted = upload.journal_pin();
    assert_ne!(accepted, initial);
    upload.request_cancellation(&mut tree, TimestampNs(2))?;
    upload.request_cancellation(&mut tree, TimestampNs(3))?;
    assert_eq!(upload.journal_pin(), accepted);
    assert!(
        upload
            .request_cancellation(&mut wrong_tree, TimestampNs(3))
            .is_err()
    );
    assert!(
        upload
            .request_cancellation(&mut tree, TimestampNs(1))
            .is_err()
    );
    let receipt = upload.cancel(&mut tree, TimestampNs(4))?;
    let closed = upload.journal_pin();
    upload.request_cancellation(&mut tree, TimestampNs(5))?;
    assert_eq!(upload.journal_pin(), closed);
    assert!(
        upload
            .request_cancellation(&mut tree, TimestampNs(3))
            .is_err()
    );
    assert_eq!(upload.cancel(&mut tree, TimestampNs(6))?, receipt);
    assert!(store.borrow().calls.is_empty());
    assert_eq!(upload.cumulative_consumed()?, BudgetVector::ZERO);
    emit("stop-retry-clock-owner-and-closed-idempotence", 8);
    Ok(())
}

#[test]
fn stop_does_not_erase_a_completed_provider_outcome_or_replay_its_publication() -> Test {
    for lost_ack in [false, true] {
        let directory = Directory::new()?;
        let store = MemoryTransport::default().store;
        let control = Rc::new(DispatchControl::default());
        let mut journal = create(&directory)?;
        let (_root_owner, mut parent, mut tree) = property()?;
        let mut transport = CrashTransport::new(store.clone(), control);
        let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
        upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
        upload.upload_chunks(&tree, || TimestampNs(2), |_| b"abc".to_vec())?;
        let receipt = if lost_ack {
            store.borrow_mut().fault_once = Some(TransportOperation::Complete);
            assert!(upload.finish(&mut tree, TimestampNs(3)).is_err());
            upload.request_cancellation(&mut tree, TimestampNs(4))?;
            assert_eq!(
                upload.reconcile(&mut tree, TimestampNs(5))?,
                MultipartPhase::Completed,
            );
            upload.finish(&mut tree, TimestampNs(6))?
        } else {
            let receipt = upload.finish(&mut tree, TimestampNs(3))?;
            let closed = upload.journal_pin();
            assert!(
                upload
                    .request_cancellation(&mut tree, TimestampNs(4))
                    .is_err()
            );
            assert_eq!(upload.journal_pin(), closed);
            receipt
        };
        let calls = store.borrow().calls.clone();
        let spent = upload.cumulative_consumed()?;
        assert_eq!(upload.finish(&mut tree, TimestampNs(7))?, receipt);
        if lost_ack {
            let pin = upload.journal_pin();
            upload.request_cancellation(&mut tree, TimestampNs(8))?;
            assert_eq!(upload.journal_pin(), pin);
        }
        let node = tree.get(upload.region())?;
        assert_eq!(node.state, RegionState::Closed);
        assert_eq!(
            node.obligations[upload.obligation()].state,
            ObligationState::Verified
        );
        assert_eq!(
            node.obligations[upload.obligation()].proof_digest,
            Some(receipt.digest())
        );
        assert_eq!(store.borrow().calls, calls);
        assert_eq!(upload.cumulative_consumed()?, spent);
        assert_eq!(call_count(&store, TransportOperation::Complete), 1);
        assert_eq!(call_count(&store, TransportOperation::Abort), 0);
    }
    emit("stop-preserves-known-completion-and-local-receipts", 2);
    Ok(())
}

#[test]
fn durable_publish_revocation_survives_cold_recovery_and_an_acknowledgement_loss() -> Test {
    for lost_ack in [false, true] {
        let directory = Directory::new()?;
        let store = MemoryTransport::default().store;
        let control = Rc::new(DispatchControl::default());
        let (minimum, expected) = {
            let mut journal = GuardedJournal {
                inner: create(&directory)?,
                control: control.clone(),
            };
            let (_root_owner, mut parent, mut tree) = property()?;
            let mut transport = CrashTransport::new(store.clone(), control.clone());
            let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
            let minimum = upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
            let expected = upload.intent().clone();
            upload.upload_chunks(&tree, || TimestampNs(2), |_| b"abc".to_vec())?;
            let restricted = upload.grants().clone().with_scope(
                RuntimeGrant::ObjectPublish,
                BTreeSet::from(["archive:somewhere-else".into()]),
            );
            control.fail_after_append.set(lost_ack);
            let result = upload.narrow_grants_durable(&tree, TimestampNs(3), restricted);
            assert_eq!(result.is_err(), lost_ack);
            assert_eq!(upload.durability_failed(), lost_ack);
            let calls = store.borrow().calls.clone();
            assert!(upload.finish(&mut tree, TimestampNs(4)).is_err());
            assert_eq!(store.borrow().calls, calls);
            (minimum, expected)
        };

        let mut journal = reopen(&directory, minimum)?;
        let (_root_owner, mut parent, mut tree) = property()?;
        let mut transport = CrashTransport::new(store.clone(), control);
        let mut upload = recover(
            &mut parent,
            &mut tree,
            &mut transport,
            &mut journal,
            minimum,
            &expected,
            TimestampNs(5),
        )?;
        assert!(
            upload
                .grants()
                .require_grant_for(RuntimeGrant::ObjectPublish, RESOURCE)
                .is_err()
        );
        upload
            .grants()
            .require_grant_for(RuntimeGrant::ObjectStage, RESOURCE)?;
        upload
            .grants()
            .require_grant_for(RuntimeGrant::AdapterNet, RESOURCE)?;
        let calls = store.borrow().calls.clone();
        assert!(upload.finish(&mut tree, TimestampNs(6)).is_err());
        assert_eq!(store.borrow().calls, calls);
        upload.cancel(&mut tree, TimestampNs(7))?;
        assert_eq!(call_count(&store, TransportOperation::Complete), 0);
        assert_eq!(call_count(&store, TransportOperation::Abort), 1);
        assert_eq!(tree.get(upload.region())?.state, RegionState::Closed);
    }
    emit("cold-recovery-retains-publication-revocation", 2);
    Ok(())
}
