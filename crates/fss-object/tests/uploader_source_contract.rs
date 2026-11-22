#![forbid(unsafe_code)]
//! Fallible source ranges retain bounded work, durable spend and upload ownership.

mod multipart_support;

use std::cell::{Cell, RefCell};
use std::io;
use std::rc::Rc;

use fss_core::{BudgetVector, ContentDigest, ObligationState, OperationId, TimestampNs};
use fss_object::multipart::{
    MultipartError, MultipartPhase, MultipartRecovery, TransportOperation, UploadJournal,
    UploadJournalPin, validate_checkpoint_transition,
};
use fss_object::planner::{ChunkPolicy, MIN_PART_SIZE, PlannedChunk};
use fss_object::uploader::{ChunkUploadError, StagedUpload, UploaderError, minimum_upload_budget};
use multipart_support::{MemoryTransport, RESOURCE, Test, budget, property, spec};

fn policy() -> ChunkPolicy {
    ChunkPolicy {
        part_size: MIN_PART_SIZE,
    }
}

fn stage<'a>(
    parent: &'a mut fss_runtime::authority::AuthorityCx,
    tree: &mut fss_core::RegionTree,
    transport: &'a mut MemoryTransport,
    bytes: u64,
    allowance: BudgetVector,
    deadline: Option<TimestampNs>,
) -> Result<StagedUpload<'a, MemoryTransport>, Box<dyn std::error::Error>> {
    let mut child = spec("operation:source-upload", allowance)?;
    child.deadline = deadline;
    Ok(StagedUpload::stage(
        parent,
        tree,
        transport,
        OperationId::parse("operation:source-upload")?,
        bytes,
        policy(),
        ContentDigest::sha256(b"source-upload-root"),
        child,
        RESOURCE,
        TimestampNs(1),
    )?)
}

fn source_failure() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "private source path")
}

#[test]
fn source_bound_refuses_before_initiation_or_source_access() -> Test {
    for maximum in [0, 2] {
        let (_root_owner, mut parent, mut tree) = property()?;
        let mut transport = MemoryTransport::default();
        let store = transport.store.clone();
        let mut upload = stage(&mut parent, &mut tree, &mut transport, 3, budget(), None)?;
        let error = upload
            .try_upload_chunks(
                &tree,
                maximum,
                || TimestampNs(2),
                |_| -> Result<Vec<u8>, io::Error> { panic!("oversized source must not be read") },
            )
            .expect_err("source buffer bound must reject");
        assert!(matches!(
            error,
            ChunkUploadError::SourceLimit {
                chunk: PlannedChunk { index: 0, offset: 0, len: 3 },
                maximum: bound,
            } if bound == maximum
        ));
        assert_eq!(upload.phase(), MultipartPhase::Prepared);
        assert_eq!(*upload.budget().consumed(), BudgetVector::ZERO);
        assert!(store.borrow().calls.is_empty());
        upload.cancel(&mut tree, TimestampNs(3))?;
    }
    Ok(())
}

#[test]
fn source_error_preserves_exact_range_owner_and_retry_cost() -> Test {
    let (_root_owner, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let mut upload = stage(&mut parent, &mut tree, &mut transport, 3, budget(), None)?;
    let error = upload
        .try_upload_chunks(&tree, 3, || TimestampNs(2), |_| Err(source_failure()))
        .expect_err("source failure must be retained");
    assert!(!error.to_string().contains("private source path"));
    assert!(matches!(
        error,
        ChunkUploadError::Source {
            chunk: PlannedChunk { index: 0, offset: 0, len: 3 },
            error,
        } if error.kind() == io::ErrorKind::UnexpectedEof
    ));
    assert_eq!(upload.phase(), MultipartPhase::Uploading);
    assert_eq!(upload.confirmed_parts(), 0);
    assert_eq!(upload.budget().consumed().bytes, 3);
    assert_eq!(upload.budget().consumed().network_bytes, 0);
    assert_eq!(upload.budget().consumed().storage_operations, 2);
    assert_eq!(
        tree.get(upload.region())?.obligations[upload.obligation()].state,
        ObligationState::Pending
    );
    assert_eq!(store.borrow().calls, vec![TransportOperation::Initiate]);
    upload.try_upload_chunks(
        &tree,
        3,
        || TimestampNs(3),
        |_| Ok::<_, io::Error>(b"abc".to_vec()),
    )?;
    upload.finish(&mut tree, TimestampNs(4))?;
    assert_eq!(upload.budget().consumed().bytes, 9);
    assert_eq!(upload.budget().consumed().network_bytes, 3);
    assert_eq!(upload.budget().consumed().storage_operations, 5);
    assert_eq!(
        store.borrow().calls,
        vec![
            TransportOperation::Initiate,
            TransportOperation::UploadPart,
            TransportOperation::Complete,
        ]
    );
    Ok(())
}

#[test]
fn exact_offsets_and_tail_are_supplied_once_per_unconfirmed_part() -> Test {
    let (_root_owner, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport::default();
    let size = MIN_PART_SIZE + 3;
    let mut upload = stage(&mut parent, &mut tree, &mut transport, size, budget(), None)?;
    let mut observed = Vec::new();
    upload.try_upload_chunks(
        &tree,
        MIN_PART_SIZE,
        || TimestampNs(2),
        |chunk| {
            observed.push(chunk);
            Ok::<_, io::Error>(vec![b'x'; chunk.len as usize])
        },
    )?;
    assert_eq!(
        observed,
        vec![
            PlannedChunk {
                index: 0,
                offset: 0,
                len: MIN_PART_SIZE
            },
            PlannedChunk {
                index: 1,
                offset: MIN_PART_SIZE,
                len: 3
            },
        ]
    );
    let consumed = *upload.budget().consumed();
    assert_eq!(consumed.bytes, 2 * size);
    assert_eq!(consumed.network_bytes, size);
    upload.try_upload_chunks(
        &tree,
        0,
        || TimestampNs(3),
        |_| -> Result<Vec<u8>, io::Error> { panic!("confirmed part must not be reread") },
    )?;
    assert_eq!(*upload.budget().consumed(), consumed);
    upload.finish(&mut tree, TimestampNs(4))?;
    Ok(())
}

#[test]
fn short_or_long_source_buffers_never_dispatch_a_part() -> Test {
    for bytes in [b"ab".to_vec(), b"abcd".to_vec()] {
        let (_root_owner, mut parent, mut tree) = property()?;
        let mut transport = MemoryTransport::default();
        let store = transport.store.clone();
        let mut upload = stage(&mut parent, &mut tree, &mut transport, 3, budget(), None)?;
        assert!(matches!(
            upload.try_upload_chunks(
                &tree,
                3,
                || TimestampNs(2),
                |_| Ok::<_, io::Error>(bytes.clone()),
            ),
            Err(ChunkUploadError::Upload(UploaderError::Protocol(
                MultipartError::PartConflict { index: 0 }
            )))
        ));
        assert_eq!(store.borrow().calls, vec![TransportOperation::Initiate]);
        assert_eq!(upload.budget().consumed().bytes, 3);
        assert_eq!(upload.budget().consumed().network_bytes, 0);
        assert_eq!(upload.phase(), MultipartPhase::Uploading);
        upload.cancel(&mut tree, TimestampNs(3))?;
    }
    Ok(())
}

#[test]
fn local_and_payload_allowance_is_checked_before_source_access() -> Test {
    let (_root_owner, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let allowance = minimum_upload_budget(3, policy())?;
    let mut upload = stage(&mut parent, &mut tree, &mut transport, 3, allowance, None)?;
    assert!(matches!(
        upload.try_upload_chunks(
            &tree,
            3,
            || TimestampNs(2),
            |_| -> Result<Vec<u8>, io::Error> {
                panic!("an unadmitted source buffer must not be read")
            },
        ),
        Err(ChunkUploadError::Upload(UploaderError::Authority(_)))
    ));
    assert_eq!(store.borrow().calls, vec![TransportOperation::Initiate]);
    assert_eq!(upload.budget().consumed().bytes, 0);
    assert_eq!(upload.budget().consumed().network_bytes, 0);
    upload.cancel(&mut tree, TimestampNs(3))?;
    Ok(())
}

#[test]
fn source_retries_cannot_spend_the_part_and_cleanup_reserve() -> Test {
    let (_root_owner, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport::default();
    let mut allowance = budget();
    allowance.storage_operations = minimum_upload_budget(3, policy())?.storage_operations;
    let mut upload = stage(&mut parent, &mut tree, &mut transport, 3, allowance, None)?;
    for _ in 0..3 {
        assert!(matches!(
            upload.try_upload_chunks(&tree, 3, || TimestampNs(2), |_| Err(source_failure())),
            Err(ChunkUploadError::Source { .. })
        ));
    }
    assert_eq!(upload.budget().remaining().storage_operations, 2);
    assert!(matches!(
        upload.try_upload_chunks(
            &tree,
            3,
            || TimestampNs(2),
            |_| -> Result<Vec<u8>, io::Error> {
                panic!("source retries must preserve cleanup allowance")
            },
        ),
        Err(ChunkUploadError::Upload(UploaderError::Protocol(
            MultipartError::CleanupReserve
        )))
    ));
    assert_eq!(upload.budget().consumed().bytes, 9);
    upload.cancel(&mut tree, TimestampNs(3))?;
    Ok(())
}

#[test]
fn cancellation_before_source_does_not_initiate_remote_work() -> Test {
    let (root_owner, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let mut upload = stage(&mut parent, &mut tree, &mut transport, 3, budget(), None)?;
    root_owner.request_cancellation(&mut tree, TimestampNs(2))?;
    assert!(matches!(
        upload.try_upload_chunks(
            &tree,
            3,
            || TimestampNs(2),
            |_| -> Result<Vec<u8>, io::Error> { panic!("cancelled source must not be read") },
        ),
        Err(ChunkUploadError::Upload(
            UploaderError::CancellationRequested { confirmed_parts: 0 }
        ))
    ));
    assert!(store.borrow().calls.is_empty());
    upload.cancel(&mut tree, TimestampNs(3))?;
    Ok(())
}

#[test]
fn late_or_regressed_source_clock_blocks_part_dispatch_even_after_read_failure() -> Test {
    for (after_source, fail_source) in [
        (TimestampNs(3), false),
        (TimestampNs(5), false),
        (TimestampNs(5), true),
    ] {
        let (_root_owner, mut parent, mut tree) = property()?;
        let mut transport = MemoryTransport::default();
        let store = transport.store.clone();
        let mut upload = stage(
            &mut parent,
            &mut tree,
            &mut transport,
            3,
            budget(),
            Some(TimestampNs(5)),
        )?;
        let mut times = [TimestampNs(2), TimestampNs(4), after_source].into_iter();
        let mut reads = 0;
        let result = upload.try_upload_chunks(
            &tree,
            3,
            || times.next().expect("three source-driver clock samples"),
            |_| {
                reads += 1;
                if fail_source {
                    Err(source_failure())
                } else {
                    Ok(b"abc".to_vec())
                }
            },
        );
        assert!(matches!(
            result,
            Err(ChunkUploadError::Upload(UploaderError::Protocol(
                MultipartError::Deadline | MultipartError::ClockRegression
            )))
        ));
        assert_eq!(reads, 1);
        assert_eq!(store.borrow().calls, vec![TransportOperation::Initiate]);
        assert_eq!(upload.budget().consumed().bytes, 3);
        assert_eq!(upload.budget().consumed().network_bytes, 0);
        assert_eq!(upload.phase(), MultipartPhase::Uploading);
        upload.cancel(&mut tree, TimestampNs(6))?;
    }
    Ok(())
}

struct Journal {
    records: Vec<(UploadJournalPin, Vec<u8>)>,
    observed: Rc<RefCell<BudgetVector>>,
    fail_source_append_once: Rc<Cell<bool>>,
}

impl Default for Journal {
    fn default() -> Self {
        Self {
            records: Vec::new(),
            observed: Rc::new(RefCell::new(BudgetVector::ZERO)),
            fail_source_append_once: Rc::new(Cell::new(false)),
        }
    }
}

impl UploadJournal for Journal {
    fn head(&self) -> Option<UploadJournalPin> {
        self.records.last().map(|(pin, _)| *pin)
    }

    fn latest(&self) -> Option<&[u8]> {
        self.records.last().map(|(_, bytes)| bytes.as_slice())
    }

    fn contains(&self, pin: UploadJournalPin) -> bool {
        self.records.iter().any(|(recorded, _)| *recorded == pin)
    }

    fn reserve_capacity(
        &mut self,
        additional_records: usize,
        max_checkpoint_bytes: usize,
    ) -> Result<(), MultipartError> {
        if self.records.len().saturating_add(additional_records) > 128
            || max_checkpoint_bytes > 128 * 1024
        {
            return Err(MultipartError::InvalidCheckpoint);
        }
        Ok(())
    }

    fn append(
        &mut self,
        expected: Option<UploadJournalPin>,
        checkpoint: &[u8],
    ) -> Result<UploadJournalPin, MultipartError> {
        if self.head() != expected {
            return Err(MultipartError::RecoveryPinMismatch);
        }
        self.reserve_capacity(1, checkpoint.len())?;
        validate_checkpoint_transition(self.latest(), checkpoint)?;
        let sequence = self.records.len() as u64 + 1;
        let mut bound = sequence.to_be_bytes().to_vec();
        if let Some(previous) = expected {
            bound.extend_from_slice(&previous.root.bytes());
        }
        bound.extend_from_slice(checkpoint);
        let pin = UploadJournalPin {
            sequence,
            root: ContentDigest::sha256(&bound),
        };
        self.records.push((pin, checkpoint.to_vec()));
        let consumed = MultipartRecovery::read(self, pin)?.consumed();
        *self.observed.borrow_mut() = consumed;
        // Model an acknowledgement lost after the source allowance was durable.
        if consumed.bytes > consumed.network_bytes && self.fail_source_append_once.replace(false) {
            return Err(MultipartError::InvalidCheckpoint);
        }
        Ok(pin)
    }
}

#[test]
fn failed_source_work_is_durable_before_read_and_survives_cold_recovery() -> Test {
    let (root_owner, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let mut journal = Journal::default();
    let observed = journal.observed.clone();
    let mut upload = stage(&mut parent, &mut tree, &mut transport, 3, budget(), None)?;
    let intent = upload.intent().clone();
    let minimum = upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
    assert!(matches!(
        upload.try_upload_chunks(
            &tree,
            3,
            || TimestampNs(2),
            |_| {
                let durable = *observed.borrow();
                assert_eq!(durable.bytes, 3);
                assert_eq!(durable.network_bytes, 0);
                assert_eq!(durable.storage_operations, 2);
                Err(source_failure())
            }
        ),
        Err(ChunkUploadError::Source { .. })
    ));
    drop(upload);
    drop(parent);
    drop(tree);
    drop(root_owner);
    let recovery = MultipartRecovery::read(&journal, minimum)?;
    assert_eq!(recovery.phase(), MultipartPhase::Uploading);
    assert_eq!(recovery.consumed().bytes, 3);
    let child = spec("operation:source-upload", recovery.remaining_budget())?;
    let (_root_owner, mut parent, mut tree) = property()?;
    let mut upload = StagedUpload::recover(
        &mut parent,
        &mut tree,
        &mut transport,
        &mut journal,
        recovery,
        &intent,
        child,
        TimestampNs(3),
    )?;
    upload.try_upload_chunks(
        &tree,
        3,
        || TimestampNs(4),
        |_| Ok::<_, io::Error>(b"abc".to_vec()),
    )?;
    upload.finish(&mut tree, TimestampNs(5))?;
    assert_eq!(upload.cumulative_consumed()?.bytes, 9);
    assert_eq!(upload.cumulative_consumed()?.network_bytes, 3);
    assert_eq!(upload.cumulative_consumed()?.storage_operations, 5);
    assert_eq!(
        store.borrow().calls,
        vec![
            TransportOperation::Initiate,
            TransportOperation::UploadPart,
            TransportOperation::Complete,
        ]
    );
    Ok(())
}

#[test]
fn ambiguous_source_admission_append_never_calls_the_source() -> Test {
    let (_root_owner, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let mut journal = Journal::default();
    journal.fail_source_append_once.set(true);
    let mut upload = stage(&mut parent, &mut tree, &mut transport, 3, budget(), None)?;
    let minimum = upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
    assert!(
        upload
            .try_upload_chunks(
                &tree,
                3,
                || TimestampNs(2),
                |_| -> Result<Vec<u8>, io::Error> {
                    panic!("unacknowledged source admission must block the read")
                },
            )
            .is_err()
    );
    assert!(upload.durability_failed());
    assert_eq!(store.borrow().calls, vec![TransportOperation::Initiate]);
    drop(upload);
    let recovery = MultipartRecovery::read(&journal, minimum)?;
    assert_eq!(recovery.phase(), MultipartPhase::Uploading);
    assert_eq!(recovery.consumed().bytes, 3);
    assert_eq!(recovery.consumed().network_bytes, 0);
    assert_eq!(recovery.owner_state()?, Some(ObligationState::Pending));
    Ok(())
}
