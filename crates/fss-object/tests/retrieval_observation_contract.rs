#![forbid(unsafe_code)]
//! Independent retrieval verifies real bytes under a fresh bounded read owner.
mod multipart_support;
use fss_core::{
    ContentDigest, RegionId, RegionKind, RegionState, RegionTree, RootAuthoritySpec, RuntimeGrant,
    TimestampNs,
};
use fss_object::multipart::{
    MultipartError, MultipartRecovery, UploadIntent, UploadJournal, UploadJournalPin,
    validate_checkpoint_transition,
};
use fss_object::planner::{ChunkPolicy, MIN_PART_SIZE};
use fss_object::uploader::{
    MAX_RETRIEVAL_RANGE_BYTES, RetrievalCx, RetrievalObservation, RetrievalOutcome,
    RetrievalReceipt, RetrievalTransport, StagedUpload, UploaderError,
};
use fss_runtime::authority::AuthorityCx;
use multipart_support::{MemoryTransport, RESOURCE, Store, Test, budget, spec};
use std::cell::RefCell;
use std::rc::Rc;
#[derive(Default, Clone)]
struct Journal(Vec<(UploadJournalPin, Vec<u8>)>);

impl UploadJournal for Journal {
    fn origin_binding(&self) -> Option<ContentDigest> {
        Some(ContentDigest::sha256(b"retrieval-test-origin"))
    }
    fn head(&self) -> Option<UploadJournalPin> {
        self.0.last().map(|(pin, _)| *pin)
    }
    fn latest(&self) -> Option<&[u8]> {
        self.0.last().map(|(_, bytes)| bytes.as_slice())
    }
    fn contains(&self, pin: UploadJournalPin) -> bool {
        self.0.iter().any(|(candidate, _)| *candidate == pin)
    }
    fn reserve_capacity(&mut self, count: usize, bytes: usize) -> Result<(), MultipartError> {
        if self.0.len().saturating_add(count) > 1024 || bytes > 128 * 1024 {
            return Err(MultipartError::InvalidCheckpoint);
        }
        Ok(())
    }
    fn append(
        &mut self,
        expected: Option<UploadJournalPin>,
        bytes: &[u8],
    ) -> Result<UploadJournalPin, MultipartError> {
        if expected != self.head() {
            return Err(MultipartError::RecoveryPinMismatch);
        }
        self.reserve_capacity(1, bytes.len())?;
        validate_checkpoint_transition(self.latest(), bytes)?;
        let sequence = self.0.len() as u64 + 1;
        let mut envelope = sequence.to_be_bytes().to_vec();
        if let Some(previous) = expected {
            envelope.extend_from_slice(&previous.root.bytes());
        }
        envelope.extend_from_slice(bytes);
        let pin = UploadJournalPin {
            sequence,
            root: ContentDigest::sha256(&envelope),
        };
        self.0.push((pin, bytes.to_vec()));
        Ok(pin)
    }
}

fn all_spec(operation: &str) -> Result<RootAuthoritySpec, Box<dyn std::error::Error>> {
    let mut value = spec(operation, budget())?;
    value.capabilities.extend([
        RuntimeGrant::AdapterAuth.as_str().into(),
        RuntimeGrant::ReadMedia.as_str().into(),
    ]);
    Ok(value)
}
fn property() -> Result<(AuthorityCx, AuthorityCx, RegionTree), Box<dyn std::error::Error>> {
    let (mut root, mut tree) = AuthorityCx::root(
        all_spec("operation:reader-root")?,
        RegionId::new("region:reader-root")?,
        RegionKind::Process,
        budget(),
        TimestampNs(0),
    )?;
    let parent = root.scope_down(
        &mut tree,
        RegionId::new("region:reader-property")?,
        RegionKind::Property,
        budget(),
        all_spec("operation:reader-parent")?,
        TimestampNs(0),
    )?;
    Ok((root, parent, tree))
}
fn read_spec() -> Result<RootAuthoritySpec, Box<dyn std::error::Error>> {
    let mut value = all_spec("operation:independent-retrieval")?;
    value.capabilities = [
        RuntimeGrant::AdapterAuth,
        RuntimeGrant::AdapterNet,
        RuntimeGrant::ReadMedia,
    ]
    .into_iter()
    .map(|grant| grant.as_str().into())
    .collect();
    value.deadline = Some(TimestampNs(200));
    Ok(value)
}
struct Fixture {
    journal: Journal,
    recovery: MultipartRecovery,
    intent: UploadIntent,
    bytes: Vec<u8>,
}
fn fixture(length: usize) -> Result<Fixture, Box<dyn std::error::Error>> {
    let bytes: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
    let mut journal = Journal::default();
    let store = Rc::new(RefCell::new(Store::default()));
    let intent = {
        let (_root, mut parent, mut tree) = property()?;
        let mut transport = MemoryTransport { store };
        let mut child = all_spec("operation:completed-upload")?;
        child
            .capabilities
            .retain(|cap| cap != RuntimeGrant::ReadMedia.as_str());
        child.deadline = Some(TimestampNs(10));
        let mut upload = StagedUpload::stage(
            &mut parent,
            &mut tree,
            &mut transport,
            child.operation_id.clone(),
            bytes.len() as u64,
            ChunkPolicy {
                part_size: MIN_PART_SIZE,
            },
            ContentDigest::sha256(b"a-manifest-root-is-not-the-object-digest"),
            child,
            RESOURCE,
            TimestampNs(1),
        )?;
        upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
        let intent = upload.intent().clone();
        upload.upload_chunks(
            &tree,
            || TimestampNs(2),
            |chunk| bytes[chunk.offset as usize..(chunk.offset + chunk.len) as usize].to_vec(),
        )?;
        upload.finish(&mut tree, TimestampNs(3))?;
        intent
    };
    let recovery = MultipartRecovery::read(&journal, journal.head().ok_or("missing head")?)?;
    Ok(Fixture {
        journal,
        recovery,
        intent,
        bytes,
    })
}
#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    Corrupt,
    Short,
    Transport,
    Expire,
}
struct Reader {
    bytes: Vec<u8>,
    calls: Vec<(u64, u64)>,
    fault: Fault,
}
impl Reader {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            calls: vec![],
            fault: Fault::None,
        }
    }
}
impl RetrievalTransport for Reader {
    fn retrieve_range(
        &mut self,
        cx: &mut RetrievalCx<'_>,
        intent: &UploadIntent,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, String> {
        assert_eq!(cx.expected_bytes(), self.bytes.len() as u64);
        let transport = cx.transport_context();
        assert!(transport.is_media_retrieval());
        assert!(transport.is_read_only_observation());
        assert_eq!(transport.resource(), intent.resource());
        assert_eq!(transport.authority().grants().len(), 3);
        assert!(
            transport
                .authority()
                .require_grant_for(RuntimeGrant::ObjectPublish, intent.resource())
                .is_err()
        );
        assert!(
            transport
                .authority()
                .require_grant_for(RuntimeGrant::ObserveStatus, intent.resource())
                .is_err()
        );
        assert!(length <= MAX_RETRIEVAL_RANGE_BYTES);
        transport
            .charge_io(transport.now(), 0, length)
            .map_err(|e| e.to_string())?;
        self.calls.push((offset, length));
        let mut result = self.bytes[offset as usize..(offset + length) as usize].to_vec();
        match self.fault {
            Fault::None => {}
            Fault::Corrupt => result[0] ^= 1,
            Fault::Short => {
                result.pop();
            }
            Fault::Transport => return Err("private provider text must be discarded".into()),
            Fault::Expire => {
                let _ = transport.checkpoint(TimestampNs(200));
            }
        }
        Ok(result)
    }
}
fn now() -> Result<TimestampNs, UploaderError> {
    Ok(TimestampNs(20))
}
#[test]
fn cold_completed_upload_is_verified_after_its_deadline_without_changing_history() -> Test {
    let f = fixture(MIN_PART_SIZE as usize + 17)?;
    let before = f.journal.0.clone();
    let old_spend = f.recovery.consumed();
    let (_root, mut parent, mut tree) = property()?;
    let mut reader = Reader::new(&f.bytes);
    let mut owner = RetrievalObservation::begin(
        &mut parent,
        &mut tree,
        &f.journal,
        &f.recovery,
        &f.intent,
        ContentDigest::sha256(&f.bytes),
        read_spec()?,
        TimestampNs(20),
    )?;
    let region = owner.region().clone();
    let receipt = owner.verify(&mut tree, &mut reader, now)?;
    assert_eq!(receipt.outcome(), RetrievalOutcome::Verified);
    assert_eq!(receipt.bytes_read(), f.bytes.len() as u64);
    assert_eq!(receipt.verified_parts(), 2);
    assert_eq!(receipt.attempted_ranges(), 21);
    assert_eq!(receipt.expected_digest(), ContentDigest::sha256(&f.bytes));
    assert_ne!(receipt.expected_digest(), receipt.manifest_root());
    assert_eq!(
        receipt.completion_digest(),
        f.recovery.completion_receipt()?.digest()
    );
    assert_eq!(receipt.source_pin(), f.recovery.head());
    assert!(owner.is_settled());
    assert_eq!(owner.settle(&mut tree, TimestampNs(21))?, receipt);
    assert!(
        owner
            .verify(&mut tree, &mut reader, || Ok(TimestampNs(21)))
            .is_err()
    );
    drop(owner);
    assert_eq!(tree.get(&region)?.state, RegionState::Closed);
    assert_eq!(*parent.budget().consumed(), receipt.consumed());
    assert_eq!(f.journal.0, before);
    assert_eq!(f.recovery.consumed(), old_spend);
    assert_eq!(RetrievalReceipt::decode(&receipt.encode()?)?, receipt);
    Ok(())
}
#[test]
fn corrupt_short_failed_and_expired_reads_never_prove_retrieval() -> Test {
    let f = fixture(317)?;
    for fault in [
        Fault::Corrupt,
        Fault::Short,
        Fault::Transport,
        Fault::Expire,
    ] {
        let (_root, mut parent, mut tree) = property()?;
        let mut reader = Reader::new(&f.bytes);
        reader.fault = fault;
        let mut owner = RetrievalObservation::begin(
            &mut parent,
            &mut tree,
            &f.journal,
            &f.recovery,
            &f.intent,
            ContentDigest::sha256(&f.bytes),
            read_spec()?,
            TimestampNs(20),
        )?;
        let error = owner
            .verify(&mut tree, &mut reader, now)
            .err()
            .ok_or("fault accepted")?;
        assert!(!error.to_string().contains("private provider"));
        let receipt = owner.settle(&mut tree, owner.observed_at())?;
        assert_eq!(
            receipt.outcome(),
            match fault {
                Fault::Corrupt | Fault::Short => RetrievalOutcome::Mismatch,
                _ => RetrievalOutcome::Unknown,
            }
        );
        assert_eq!(receipt.attempted_ranges(), 1);
        assert_eq!(receipt.verified_parts(), 0);
        assert!(owner.is_settled());
        assert_eq!(RetrievalReceipt::decode(&receipt.encode()?)?, receipt);
    }
    Ok(())
}
#[test]
fn all_parts_matching_does_not_replace_the_independent_whole_digest() -> Test {
    let f = fixture(73)?;
    let (_root, mut parent, mut tree) = property()?;
    let mut reader = Reader::new(&f.bytes);
    let mut owner = RetrievalObservation::begin(
        &mut parent,
        &mut tree,
        &f.journal,
        &f.recovery,
        &f.intent,
        ContentDigest::sha256(b"another-object"),
        read_spec()?,
        TimestampNs(20),
    )?;
    assert!(owner.verify(&mut tree, &mut reader, now).is_err());
    let receipt = owner.settle(&mut tree, TimestampNs(21))?;
    assert_eq!(receipt.verified_parts(), 1);
    assert_eq!(receipt.outcome(), RetrievalOutcome::Mismatch);
    Ok(())
}
#[test]
fn budget_exhaustion_stops_before_a_second_range_and_preserves_partial_work() -> Test {
    let f = fixture(MAX_RETRIEVAL_RANGE_BYTES as usize + 1)?;
    let (_root, mut parent, mut tree) = property()?;
    let mut reader = Reader::new(&f.bytes);
    let mut spec = read_spec()?;
    spec.budgets.storage_operations = 1;
    let mut owner = RetrievalObservation::begin(
        &mut parent,
        &mut tree,
        &f.journal,
        &f.recovery,
        &f.intent,
        ContentDigest::sha256(&f.bytes),
        spec,
        TimestampNs(20),
    )?;
    assert!(owner.verify(&mut tree, &mut reader, now).is_err());
    let receipt = owner.settle(&mut tree, TimestampNs(21))?;
    assert_eq!(receipt.outcome(), RetrievalOutcome::Unknown);
    assert_eq!(receipt.bytes_read(), MAX_RETRIEVAL_RANGE_BYTES);
    assert_eq!(receipt.attempted_ranges(), 1);
    assert_eq!(reader.calls.len(), 1);
    assert_eq!(receipt.verified_parts(), 0);
    Ok(())
}
#[test]
fn cancelled_reader_has_no_provider_call_and_can_settle() -> Test {
    let f = fixture(73)?;
    let (_root, mut parent, mut tree) = property()?;
    let mut reader = Reader::new(&f.bytes);
    let mut owner = RetrievalObservation::begin(
        &mut parent,
        &mut tree,
        &f.journal,
        &f.recovery,
        &f.intent,
        ContentDigest::sha256(&f.bytes),
        read_spec()?,
        TimestampNs(20),
    )?;
    tree.request_drain(owner.region(), Some("cancel read"), TimestampNs(20))?;
    assert!(owner.verify(&mut tree, &mut reader, now).is_err());
    let receipt = owner.settle(&mut tree, TimestampNs(21))?;
    assert_eq!(receipt.outcome(), RetrievalOutcome::NotObserved);
    assert!(reader.calls.is_empty());
    assert!(owner.is_settled());
    Ok(())
}

#[test]
fn status_only_mutation_scope_reuse_and_privacy_changes_cannot_create_a_reader() -> Test {
    let f = fixture(73)?;
    for case in 0..4 {
        let (_root, mut parent, mut tree) = property()?;
        let mut child = read_spec()?;
        match case {
            0 => {
                child
                    .capabilities
                    .retain(|cap| cap != RuntimeGrant::ReadMedia.as_str());
                child
                    .capabilities
                    .push(RuntimeGrant::ObserveStatus.as_str().into());
            }
            1 => child
                .capabilities
                .push(RuntimeGrant::ObjectPublish.as_str().into()),
            2 => child.operation_id = f.intent.operation().clone(),
            _ => child.privacy_scope = "privacy:changed".into(),
        }
        let before = *parent.budget().consumed();
        assert!(
            RetrievalObservation::begin(
                &mut parent,
                &mut tree,
                &f.journal,
                &f.recovery,
                &f.intent,
                ContentDigest::sha256(&f.bytes),
                child,
                TimestampNs(20)
            )
            .is_err()
        );
        assert_eq!(*parent.budget().consumed(), before);
    }
    Ok(())
}

#[test]
fn final_deadline_or_failed_clock_cannot_publish_a_verified_receipt() -> Test {
    let f = fixture(73)?;
    for fail_clock in [false, true] {
        let (_root, mut parent, mut tree) = property()?;
        let mut reader = Reader::new(&f.bytes);
        let mut owner = RetrievalObservation::begin(
            &mut parent,
            &mut tree,
            &f.journal,
            &f.recovery,
            &f.intent,
            ContentDigest::sha256(&f.bytes),
            read_spec()?,
            TimestampNs(20),
        )?;
        let mut calls = 0;
        let result = owner.verify(&mut tree, &mut reader, || {
            calls += 1;
            if calls == 4 {
                if fail_clock {
                    Err(MultipartError::ClockRegression.into())
                } else {
                    Ok(TimestampNs(200))
                }
            } else {
                now()
            }
        });
        assert!(result.is_err());
        assert_eq!(calls, 4);
        assert_eq!(reader.calls.len(), 1);
        let receipt = owner.settle(&mut tree, owner.observed_at())?;
        assert_eq!(receipt.outcome(), RetrievalOutcome::Unknown);
        assert_eq!(receipt.verified_parts(), 1);
    }
    Ok(())
}

#[test]
fn receipt_is_strict_bounded_and_contains_no_media_or_provider_tokens() -> Test {
    let f = fixture(73)?;
    let (_root, mut parent, mut tree) = property()?;
    let mut reader = Reader::new(&f.bytes);
    let mut owner = RetrievalObservation::begin(
        &mut parent,
        &mut tree,
        &f.journal,
        &f.recovery,
        &f.intent,
        ContentDigest::sha256(&f.bytes),
        read_spec()?,
        TimestampNs(20),
    )?;
    let receipt = owner.verify(&mut tree, &mut reader, now)?;
    let bytes = receipt.encode()?;
    assert_eq!(RetrievalReceipt::decode(&bytes)?, receipt);
    for end in 0..bytes.len() {
        assert!(RetrievalReceipt::decode(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(RetrievalReceipt::decode(&trailing).is_err());
    let mut invalid_count = bytes.clone();
    *invalid_count.last_mut().ok_or("empty receipt")? = 127;
    assert!(RetrievalReceipt::decode(&invalid_count).is_err());
    assert!(!bytes.windows(f.bytes.len()).any(|window| window == f.bytes));
    Ok(())
}
