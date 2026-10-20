#![forbid(unsafe_code)]
#![cfg(unix)]
//! Accepted recovery restrictions and local terminal closure survive real cold opens.

mod multipart_support;

use std::cell::{Cell, RefCell};
use std::fs;
use std::io;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BudgetVector, ContentDigest, ObligationState, OperationId, RegionId, RegionKind, RegionState,
    RuntimeGrant, TaskId, TimestampNs,
};
use fss_object::HostSpoolIo;
use fss_object::multipart::{
    MultipartError, MultipartPhase, MultipartRecovery, MultipartSession, TransportOperation,
    UploadIntent, UploadIo, UploadJournal, UploadJournalPin,
};
use fss_object::planner::{ChunkPolicy, MIN_PART_SIZE, plan_chunks};
use fss_object::upload_journal::{FileUploadJournal, UploadJournalLimits};
use fss_object::uploader::StagedUpload;
use multipart_support::{MemoryTransport, RESOURCE, Store, StorePhase, Test, property, spec};

static NEXT: AtomicU64 = AtomicU64::new(0);
const OPERATION: &str = "operation:recovered-authority";

struct Directory(PathBuf);

impl Directory {
    fn new() -> io::Result<Self> {
        for _ in 0..32 {
            let path = std::env::temp_dir().join(format!(
                "fss-recovered-authority-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::other("fixture namespace exhausted"))
    }

    fn create(&self) -> Result<FileUploadJournal, MultipartError> {
        FileUploadJournal::create(&self.0, limits(), Arc::new(HostSpoolIo))
    }

    fn open(&self, minimum: UploadJournalPin) -> Result<FileUploadJournal, MultipartError> {
        self.open_with(minimum, limits())
    }

    fn open_with(
        &self,
        minimum: UploadJournalPin,
        limits: UploadJournalLimits,
    ) -> Result<FileUploadJournal, MultipartError> {
        FileUploadJournal::open(&self.0, limits, Arc::new(HostSpoolIo), minimum)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn limits() -> UploadJournalLimits {
    UploadJournalLimits {
        max_records: 128,
        max_checkpoint_bytes: 16 * 1024,
        max_total_bytes: 512 * 1024,
        max_read_bytes: 4 * 1024 * 1024,
    }
}

fn allowance() -> BudgetVector {
    let mut budget = BudgetVector::ZERO;
    budget.bytes = 128;
    budget.network_bytes = 128;
    budget.storage_operations = 12;
    budget
}

fn policy() -> ChunkPolicy {
    ChunkPolicy {
        part_size: MIN_PART_SIZE,
    }
}

fn root() -> ContentDigest {
    ContentDigest::sha256(b"recovered-authority-manifest")
}

fn stage<'a>(
    parent: &'a mut fss_runtime::authority::AuthorityCx,
    tree: &mut fss_core::RegionTree,
    transport: &'a mut MemoryTransport,
) -> Result<StagedUpload<'a, MemoryTransport>, Box<dyn std::error::Error>> {
    Ok(StagedUpload::stage(
        parent,
        tree,
        transport,
        OperationId::parse(OPERATION)?,
        3,
        policy(),
        root(),
        spec(OPERATION, allowance())?,
        RESOURCE,
        TimestampNs(1),
    )?)
}

fn active_fixture(
    directory: &Directory,
    store: &Rc<RefCell<Store>>,
    upload_part: bool,
) -> Result<(UploadJournalPin, UploadIntent), Box<dyn std::error::Error>> {
    let mut journal = directory.create()?;
    let (_root, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport {
        store: store.clone(),
    };
    let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
    let minimum = upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
    let expected = upload.intent().clone();
    upload.start(&tree, TimestampNs(2))?;
    if upload_part {
        upload.upload_part(&tree, TimestampNs(3), 0, b"abc")?;
    }
    Ok((minimum, expected))
}

#[test]
fn immediate_drop_after_recovery_cannot_erase_later_time_deadline_or_grants() -> Test {
    let directory = Directory::new()?;
    let store = MemoryTransport::default().store;
    let (minimum, expected) = active_fixture(&directory, &store, false)?;
    let original_consumed;
    {
        let mut journal = directory.open(minimum)?;
        let recovery = MultipartRecovery::read(&journal, minimum)?;
        original_consumed = recovery.consumed();
        let mut child = spec(OPERATION, recovery.remaining_budget())?;
        child.deadline = Some(TimestampNs(40));
        child
            .capabilities
            .retain(|id| id != RuntimeGrant::ObjectPublish.as_str());
        let (_root, mut parent, mut tree) = property()?;
        let mut transport = MemoryTransport {
            store: store.clone(),
        };
        let upload = StagedUpload::recover(
            &mut parent,
            &mut tree,
            &mut transport,
            &mut journal,
            recovery,
            &expected,
            child,
            TimestampNs(50),
        )?;
        assert_eq!(upload.cumulative_consumed()?, original_consumed);
        // No caller checkpoint or operation occurs before this simulated exit.
        drop(upload);
    }
    let mut journal = directory.open(minimum)?;
    let recovery = MultipartRecovery::read(&journal, minimum)?;
    assert_eq!(recovery.observed_at(), TimestampNs(50));
    assert_eq!(recovery.deadline(), Some(TimestampNs(40)));
    assert_eq!(recovery.consumed(), original_consumed);
    assert!(
        !recovery
            .effective_authority()
            .has_capability(RuntimeGrant::ObjectPublish.as_str())
    );
    let (_root, mut parent, mut tree) = property()?;
    let before = parent.budget().remaining();
    let nodes = tree.iter().count();
    let head = journal.head();
    let mut transport = MemoryTransport {
        store: store.clone(),
    };
    for now in [TimestampNs(49), TimestampNs(60)] {
        let widened = spec(OPERATION, recovery.remaining_budget())?;
        assert!(
            StagedUpload::recover(
                &mut parent,
                &mut tree,
                &mut transport,
                &mut journal,
                recovery.clone(),
                &expected,
                widened,
                now,
            )
            .is_err()
        );
        assert_eq!(parent.budget().remaining(), before);
        assert_eq!(tree.iter().count(), nodes);
        assert_eq!(journal.head(), head);
    }
    let mut child = spec(OPERATION, recovery.remaining_budget())?;
    child.deadline = Some(TimestampNs(40));
    child
        .capabilities
        .retain(|id| id != RuntimeGrant::ObjectPublish.as_str());
    let mut upload = StagedUpload::recover(
        &mut parent,
        &mut tree,
        &mut transport,
        &mut journal,
        recovery,
        &expected,
        child,
        TimestampNs(60),
    )?;
    assert!(
        upload
            .upload_part(&tree, TimestampNs(60), 0, b"abc")
            .is_err()
    );
    upload.cancel(&mut tree, TimestampNs(60))?;
    assert_eq!(tree.get(upload.region())?.state, RegionState::Closed);
    assert_eq!(
        store.borrow().calls,
        [TransportOperation::Initiate, TransportOperation::Abort],
    );
    Ok(())
}

struct FailingRestoreJournal {
    inner: FileUploadJournal,
    fail: bool,
    after_append: bool,
}

impl UploadJournal for FailingRestoreJournal {
    fn head(&self) -> Option<UploadJournalPin> {
        self.inner.head()
    }
    fn latest(&self) -> Option<&[u8]> {
        self.inner.latest()
    }
    fn contains(&self, pin: UploadJournalPin) -> bool {
        self.inner.contains(pin)
    }
    fn reserve_capacity(&mut self, records: usize, bytes: usize) -> Result<(), MultipartError> {
        self.inner.reserve_capacity(records, bytes)
    }
    fn append(
        &mut self,
        expected: Option<UploadJournalPin>,
        checkpoint: &[u8],
    ) -> Result<UploadJournalPin, MultipartError> {
        if self.fail {
            self.fail = false;
            if self.after_append {
                self.inner.append(expected, checkpoint)?;
            }
            return Err(MultipartError::Persistence(
                "injected lost restore acknowledgement".into(),
            ));
        }
        self.inner.append(expected, checkpoint)
    }
}

#[test]
fn refused_or_ambiguous_restore_append_never_strands_a_new_runtime_child() -> Test {
    for after_append in [false, true] {
        let directory = Directory::new()?;
        let store = MemoryTransport::default().store;
        let (minimum, expected) = active_fixture(&directory, &store, false)?;
        let mut journal = FailingRestoreJournal {
            inner: directory.open(minimum)?,
            fail: true,
            after_append,
        };
        let recovery = MultipartRecovery::read(&journal, minimum)?;
        let before_head = recovery.head();
        let mut child = spec(OPERATION, recovery.remaining_budget())?;
        child.deadline = Some(TimestampNs(20));
        let (_root, mut parent, mut tree) = property()?;
        let before = parent.budget().remaining();
        let nodes = tree.iter().count();
        let mut transport = MemoryTransport {
            store: store.clone(),
        };
        assert!(
            StagedUpload::recover(
                &mut parent,
                &mut tree,
                &mut transport,
                &mut journal,
                recovery,
                &expected,
                child,
                TimestampNs(10),
            )
            .is_err()
        );
        assert_eq!(parent.budget().remaining(), before);
        assert_eq!(tree.iter().count(), nodes);
        assert_eq!(store.borrow().calls, [TransportOperation::Initiate]);
        drop(journal);
        let journal = directory.open(minimum)?;
        let recovered = MultipartRecovery::read(&journal, minimum)?;
        if after_append {
            assert!(recovered.head().sequence > before_head.sequence);
            assert_eq!(recovered.observed_at(), TimestampNs(10));
            assert_eq!(recovered.deadline(), Some(TimestampNs(20)));
        } else {
            assert_eq!(recovered.head(), before_head);
            assert_eq!(recovered.observed_at(), TimestampNs(2));
        }
    }
    Ok(())
}

#[test]
fn protocol_cancellation_refusals_survive_a_fresh_authority_tree() -> Test {
    for started in [false, true] {
        let directory = Directory::new()?;
        let store = MemoryTransport::default().store;
        let minimum = {
            let mut journal = directory.create()?;
            let (_root, mut parent, mut tree) = property()?;
            let mut child = parent.scope_down(
                &mut tree,
                RegionId::new("region:protocol")?,
                RegionKind::ObjectStore,
                allowance(),
                spec(OPERATION, allowance())?,
                TimestampNs(1),
            )?;
            let mut transport = MemoryTransport {
                store: store.clone(),
            };
            let plan = plan_chunks(3, policy())?;
            let mut session = MultipartSession::prepare(
                &mut transport,
                &plan,
                root(),
                OperationId::parse(OPERATION)?,
                RESOURCE,
                TimestampNs(1),
            )?;
            let minimum = session.attach_journal(
                &mut journal,
                UploadIo {
                    authority: &mut child,
                    tree: &tree,
                    now: TimestampNs(1),
                },
                Vec::new(),
            )?;
            if started {
                session.start(UploadIo {
                    authority: &mut child,
                    tree: &tree,
                    now: TimestampNs(2),
                })?;
            }
            child.request_cancellation(&mut tree, TimestampNs(3))?;
            let io = UploadIo {
                authority: &mut child,
                tree: &tree,
                now: TimestampNs(3),
            };
            let result = if started {
                session.upload_part(io, &plan, 0, b"abc").map(|_| ())
            } else {
                session.start(io).map(|_| ())
            };
            assert_eq!(result, Err(MultipartError::CancellationRequested));
            minimum
        };
        let mut journal = directory.open(minimum)?;
        let recovery = MultipartRecovery::read(&journal, minimum)?;
        assert!(recovery.cancelled());
        assert_eq!(recovery.observed_at(), TimestampNs(3));
        assert_eq!(recovery.owner_state()?, None);
        assert_eq!(recovery.confirmed_parts(), 0);
        let (_root, mut parent, mut tree) = property()?;
        let mut child = parent.scope_down(
            &mut tree,
            RegionId::new("region:protocol")?,
            RegionKind::ObjectStore,
            recovery.remaining_budget(),
            spec(OPERATION, recovery.remaining_budget())?,
            TimestampNs(4),
        )?;
        let mut transport = MemoryTransport {
            store: store.clone(),
        };
        assert!(
            MultipartSession::restore(
                &mut transport,
                &mut journal,
                &recovery,
                UploadIo {
                    authority: &mut child,
                    tree: &tree,
                    now: TimestampNs(4),
                },
            )
            .is_err()
        );
        child.request_cancellation(&mut tree, TimestampNs(4))?;
        let mut session = MultipartSession::restore(
            &mut transport,
            &mut journal,
            &recovery,
            UploadIo {
                authority: &mut child,
                tree: &tree,
                now: TimestampNs(4),
            },
        )?;
        session.abort(UploadIo {
            authority: &mut child,
            tree: &tree,
            now: TimestampNs(4),
        })?;
        let expected = if started {
            vec![TransportOperation::Initiate, TransportOperation::Abort]
        } else {
            Vec::new()
        };
        assert_eq!(store.borrow().calls, expected);
    }
    Ok(())
}

#[test]
fn protocol_deadline_refusal_records_its_clock_before_cold_recovery() -> Test {
    let directory = Directory::new()?;
    let minimum = {
        let mut journal = directory.create()?;
        let (_root, mut parent, mut tree) = property()?;
        let mut child_spec = spec(OPERATION, allowance())?;
        child_spec.deadline = Some(TimestampNs(10));
        let mut child = parent.scope_down(
            &mut tree,
            RegionId::new("region:protocol")?,
            RegionKind::ObjectStore,
            allowance(),
            child_spec,
            TimestampNs(1),
        )?;
        let mut transport = MemoryTransport::default();
        let store = transport.store.clone();
        let mut session = MultipartSession::prepare(
            &mut transport,
            &plan_chunks(3, policy())?,
            root(),
            OperationId::parse(OPERATION)?,
            RESOURCE,
            TimestampNs(1),
        )?;
        let minimum = session.attach_journal(
            &mut journal,
            UploadIo {
                authority: &mut child,
                tree: &tree,
                now: TimestampNs(1),
            },
            Vec::new(),
        )?;
        assert_eq!(
            session.start(UploadIo {
                authority: &mut child,
                tree: &tree,
                now: TimestampNs(10),
            }),
            Err(MultipartError::Deadline),
        );
        assert!(store.borrow().calls.is_empty());
        minimum
    };
    let journal = directory.open(minimum)?;
    let recovery = MultipartRecovery::read(&journal, minimum)?;
    assert_eq!(recovery.observed_at(), TimestampNs(10));
    assert_eq!(recovery.consumed(), BudgetVector::ZERO);
    assert_eq!(
        recovery.validate_restore(&journal, TimestampNs(9)),
        Err(MultipartError::ClockRegression),
    );
    Ok(())
}

struct StopBeforeSettlement {
    inner: FileUploadJournal,
    store: Rc<RefCell<Store>>,
    terminal_appends: Cell<usize>,
}

impl UploadJournal for StopBeforeSettlement {
    fn head(&self) -> Option<UploadJournalPin> {
        self.inner.head()
    }
    fn latest(&self) -> Option<&[u8]> {
        self.inner.latest()
    }
    fn contains(&self, pin: UploadJournalPin) -> bool {
        self.inner.contains(pin)
    }
    fn reserve_capacity(&mut self, records: usize, bytes: usize) -> Result<(), MultipartError> {
        self.inner.reserve_capacity(records, bytes)
    }
    fn append(
        &mut self,
        expected: Option<UploadJournalPin>,
        checkpoint: &[u8],
    ) -> Result<UploadJournalPin, MultipartError> {
        if self.store.borrow().phase == StorePhase::Completed {
            let previous = self.terminal_appends.get();
            self.terminal_appends.set(previous + 1);
            if previous > 0 {
                return Err(MultipartError::Persistence(
                    "simulated exit before local settlement record".into(),
                ));
            }
        }
        self.inner.append(expected, checkpoint)
    }
}

#[test]
fn last_journal_slot_closes_a_cold_terminal_owner_and_full_history_retries_locally() -> Test {
    let directory = Directory::new()?;
    let store = MemoryTransport::default().store;
    let (minimum, expected, terminal_head, proof) = {
        let mut journal = StopBeforeSettlement {
            inner: directory.create()?,
            store: store.clone(),
            terminal_appends: Cell::new(0),
        };
        let (_root, mut parent, mut tree) = property()?;
        let mut transport = MemoryTransport {
            store: store.clone(),
        };
        let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
        let minimum = upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
        let expected = upload.intent().clone();
        upload.upload_chunks(&tree, || TimestampNs(2), |_| b"abc".to_vec())?;
        assert!(upload.finish(&mut tree, TimestampNs(3)).is_err());
        drop(upload);
        let recovery = MultipartRecovery::read(&journal, minimum)?;
        assert_eq!(recovery.phase(), MultipartPhase::Completed);
        assert_eq!(recovery.owner_state()?, Some(ObligationState::Pending));
        (
            minimum,
            expected,
            recovery.head(),
            recovery.completion_receipt()?.digest(),
        )
    };
    let mut full = limits();
    full.max_records = terminal_head.sequence as usize + 1;
    let completed_head;
    {
        let mut journal = directory.open_with(minimum, full)?;
        let recovery = MultipartRecovery::read(&journal, minimum)?;
        let child = spec(OPERATION, recovery.remaining_budget())?;
        let (_root, mut parent, mut tree) = property()?;
        let before = parent.budget().remaining();
        let mut transport = MemoryTransport {
            store: store.clone(),
        };
        let mut upload = StagedUpload::recover(
            &mut parent,
            &mut tree,
            &mut transport,
            &mut journal,
            recovery,
            &expected,
            child,
            TimestampNs(50),
        )?;
        assert_eq!(upload.journal_pin(), Some(terminal_head));
        assert_eq!(upload.finish(&mut tree, TimestampNs(51))?.digest(), proof);
        completed_head = upload.journal_pin().ok_or("missing completion pin")?;
        assert_eq!(completed_head.sequence, full.max_records as u64);
        assert_eq!(upload.finish(&mut tree, TimestampNs(52))?.digest(), proof);
        assert_eq!(upload.journal_pin(), Some(completed_head));
        assert_eq!(tree.get(upload.region())?.state, RegionState::Closed);
        drop(upload);
        assert_eq!(parent.budget().remaining(), before);
    }
    let calls = store.borrow().calls.clone();
    let mut journal = directory.open_with(completed_head, full)?;
    let recovery = MultipartRecovery::read(&journal, completed_head)?;
    assert_eq!(recovery.owner_state()?, Some(ObligationState::Verified));
    let child = spec(OPERATION, recovery.remaining_budget())?;
    let (_root, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport {
        store: store.clone(),
    };
    let mut upload = StagedUpload::recover(
        &mut parent,
        &mut tree,
        &mut transport,
        &mut journal,
        recovery,
        &expected,
        child,
        TimestampNs(60),
    )?;
    assert_eq!(upload.finish(&mut tree, TimestampNs(61))?.digest(), proof);
    assert_eq!(upload.journal_pin(), Some(completed_head));
    assert_eq!(store.borrow().calls, calls);
    Ok(())
}

#[test]
fn full_indeterminate_history_closes_locally_without_rewriting_private_followup() -> Test {
    let directory = Directory::new()?;
    let store = MemoryTransport::default().store;
    let note = "operator owns retained remote reconciliation";
    let reference = ContentDigest::sha256(b"owned follow-up record");
    let (minimum, expected, terminal_head, receipt) = {
        let mut journal = directory.create()?;
        let (_root, mut parent, mut tree) = property()?;
        let mut transport = MemoryTransport {
            store: store.clone(),
        };
        let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
        let minimum = upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
        let expected = upload.intent().clone();
        store.borrow_mut().fault_once = Some(TransportOperation::Initiate);
        assert!(upload.start(&tree, TimestampNs(2)).is_err());
        tree.register_task(
            upload.region(),
            TaskId::new("task:hold-local-finalization")?,
            TimestampNs(2),
        )?;
        assert!(
            upload
                .settle_indeterminate(&mut tree, TimestampNs(3), note, reference)
                .is_err()
        );
        let receipt = upload
            .indeterminate_receipt()
            .ok_or("missing receipt")?
            .clone();
        (
            minimum,
            expected,
            upload.journal_pin().ok_or("missing terminal pin")?,
            receipt,
        )
    };
    let mut full = limits();
    full.max_records = terminal_head.sequence as usize;
    let mut journal = directory.open_with(minimum, full)?;
    let recovery = MultipartRecovery::read(&journal, minimum)?;
    assert_eq!(
        recovery.owner_state()?,
        Some(ObligationState::Indeterminate)
    );
    assert_eq!(recovery.reconciliation_reference()?, Some(reference));
    let child = spec(OPERATION, recovery.remaining_budget())?;
    let calls = store.borrow().calls.clone();
    let (_root, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport {
        store: store.clone(),
    };
    let mut upload = StagedUpload::recover(
        &mut parent,
        &mut tree,
        &mut transport,
        &mut journal,
        recovery,
        &expected,
        child,
        TimestampNs(4),
    )?;
    assert!(upload.reconcile(&mut tree, TimestampNs(4)).is_err());
    assert_eq!(
        upload.settle_indeterminate(&mut tree, TimestampNs(5), note, reference)?,
        receipt,
    );
    assert_eq!(upload.journal_pin(), Some(terminal_head));
    assert_eq!(tree.get(upload.region())?.state, RegionState::Closed);
    assert_eq!(store.borrow().calls, calls);
    Ok(())
}

#[test]
fn bounded_journal_refuses_completion_before_provider_dispatch_or_charge() -> Test {
    let directory = Directory::new()?;
    let store = MemoryTransport::default().store;
    let (minimum, expected) = active_fixture(&directory, &store, true)?;
    let (head, consumed) = {
        let journal = directory.open(minimum)?;
        let recovery = MultipartRecovery::read(&journal, minimum)?;
        (recovery.head(), recovery.consumed())
    };
    let mut bounded = limits();
    // Recovery and its next owner checkpoint fit, but a dispatch/ACK/receipt do not.
    bounded.max_records = head.sequence as usize + 3;
    let mut journal = directory.open_with(minimum, bounded)?;
    let recovery = MultipartRecovery::read(&journal, minimum)?;
    let child = spec(OPERATION, recovery.remaining_budget())?;
    let (_root, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport {
        store: store.clone(),
    };
    let mut upload = StagedUpload::recover(
        &mut parent,
        &mut tree,
        &mut transport,
        &mut journal,
        recovery,
        &expected,
        child,
        TimestampNs(4),
    )?;
    assert!(upload.finish(&mut tree, TimestampNs(5)).is_err());
    assert_eq!(upload.phase(), MultipartPhase::Uploading);
    assert_eq!(upload.cumulative_consumed()?, consumed);
    assert!(!upload.durability_failed());
    assert_eq!(
        store.borrow().calls,
        [TransportOperation::Initiate, TransportOperation::UploadPart],
    );
    assert_eq!(
        tree.get(upload.region())?.obligations[upload.obligation()].state,
        ObligationState::Pending,
    );
    Ok(())
}

#[test]
fn acknowledged_stop_is_visible_before_any_runtime_cancellation_checkpoint() -> Test {
    let directory = Directory::new()?;
    let minimum = {
        let mut journal = directory.create()?;
        let (_root, mut parent, mut tree) = property()?;
        let mut transport = MemoryTransport::default();
        let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
        let minimum = upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
        upload.request_cancellation(&mut tree, TimestampNs(2))?;
        // Immediate process exit, before another owner/protocol checkpoint can
        // copy the now-cancelled live tree into the enclosing protocol flag.
        minimum
    };
    let journal = directory.open(minimum)?;
    let recovery = MultipartRecovery::read(&journal, minimum)?;
    assert!(!recovery.cancelled());
    assert!(recovery.owner_cancelled()?);
    assert_eq!(recovery.owner_state()?, Some(ObligationState::Pending));
    assert_eq!(recovery.consumed(), BudgetVector::ZERO);
    Ok(())
}

struct SnapshotJournal {
    pin: UploadJournalPin,
    bytes: Vec<u8>,
}

impl UploadJournal for SnapshotJournal {
    fn head(&self) -> Option<UploadJournalPin> {
        Some(self.pin)
    }
    fn latest(&self) -> Option<&[u8]> {
        Some(&self.bytes)
    }
    fn contains(&self, pin: UploadJournalPin) -> bool {
        pin == self.pin
    }
    fn append(
        &mut self,
        _: Option<UploadJournalPin>,
        _: &[u8],
    ) -> Result<UploadJournalPin, MultipartError> {
        Err(MultipartError::Persistence("read-only fixture".into()))
    }
}

#[test]
fn inert_owner_summaries_refuse_unrelated_intent_and_forged_terminal_proof() -> Test {
    let directory = Directory::new()?;
    let (minimum, proof) = {
        let mut journal = directory.create()?;
        let (_root, mut parent, mut tree) = property()?;
        let mut transport = MemoryTransport::default();
        let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
        let minimum = upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
        upload.upload_chunks(&tree, || TimestampNs(2), |_| b"abc".to_vec())?;
        let proof = upload.finish(&mut tree, TimestampNs(3))?.digest();
        (minimum, proof)
    };
    let journal = directory.open(minimum)?;
    let recovery = MultipartRecovery::read(&journal, minimum)?;
    assert_eq!(recovery.owner_state()?, Some(ObligationState::Verified));
    let original = journal.latest().ok_or("missing checkpoint")?;
    let owner = recovery.owner_metadata();
    assert!(original.ends_with(owner));
    for digest in [recovery.intent().digest(), proof] {
        let matches: Vec<_> = owner
            .windows(32)
            .enumerate()
            .filter_map(|(index, bytes)| (bytes == digest.bytes()).then_some(index))
            .collect();
        assert_eq!(matches.len(), 1, "fixture digest must occur exactly once");
        let mut bytes = original.to_vec();
        let offset = bytes.len() - owner.len() + matches[0];
        bytes[offset..offset + 32]
            .copy_from_slice(&ContentDigest::sha256(b"unrelated owned proof").bytes());
        let snapshot = SnapshotJournal {
            pin: UploadJournalPin {
                sequence: 1,
                root: ContentDigest::sha256(&bytes),
            },
            bytes,
        };
        // Both nested records remain canonical; the cross-record ownership
        // relation is what the redacted projection must additionally reject.
        let forged = MultipartRecovery::read(&snapshot, snapshot.pin)?;
        assert_eq!(forged.phase(), MultipartPhase::Completed);
        assert_eq!(forged.owner_state(), Err(MultipartError::InvalidCheckpoint));
        assert_eq!(
            forged.owner_cancelled(),
            Err(MultipartError::InvalidCheckpoint)
        );
        assert_eq!(
            forged.reconciliation_reference(),
            Err(MultipartError::InvalidCheckpoint),
        );
    }
    Ok(())
}
