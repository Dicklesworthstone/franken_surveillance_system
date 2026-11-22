#![forbid(unsafe_code)]
//! A fresh read can confirm completion without reopening historical mutation
//! ownership, replacing its receipt, or granting another upload allowance.

mod multipart_support;

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use fss_core::{
    BudgetVector, ContentDigest, ObligationState, OperationId, RegionId, RegionKind, RegionState,
    RegionTree, RootAuthoritySpec, RuntimeGrant, TimestampNs,
};
use fss_object::multipart::{
    MultipartError, MultipartPhase, MultipartRecovery, MultipartTransport, PartReceipt,
    ProviderUploadState, Reconciliation, TransportCx, TransportOperation, UploadId, UploadIntent,
    UploadJournal, UploadJournalPin, validate_checkpoint_transition,
};
use fss_object::planner::{ChunkPolicy, MIN_PART_SIZE, PlannedChunk};
use fss_object::uploader::{
    CompletionObservation, CompletionObservationOutcome, CompletionObservationReceipt, StagedUpload,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::grant::GrantSet;
use multipart_support::{MemoryTransport, RESOURCE, Store, Test, spec};

const UPLOAD: &str = "operation:lost-complete";
const OBSERVATION: &str = "operation:observe-complete";

#[derive(Default, Clone)]
struct Journal(Vec<(UploadJournalPin, Vec<u8>)>);

impl UploadJournal for Journal {
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
        if self.0.len().saturating_add(count) > 128 || bytes > 128 * 1024 {
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

fn allowance() -> BudgetVector {
    let mut value = BudgetVector::ZERO;
    value.bytes = 4096;
    value.network_bytes = 4096;
    value.storage_operations = 32;
    value
}

fn all_spec(operation: &str) -> Result<RootAuthoritySpec, Box<dyn std::error::Error>> {
    let mut value = spec(operation, allowance())?;
    value.capabilities.extend([
        RuntimeGrant::AdapterAuth.as_str().into(),
        RuntimeGrant::ObserveStatus.as_str().into(),
    ]);
    Ok(value)
}

fn property() -> Result<(AuthorityCx, AuthorityCx, RegionTree), Box<dyn std::error::Error>> {
    let (mut root, mut tree) = AuthorityCx::root(
        all_spec("operation:root")?,
        RegionId::new("region:root")?,
        RegionKind::Process,
        allowance(),
        TimestampNs(0),
    )?;
    let property = root.scope_down(
        &mut tree,
        RegionId::new("region:property")?,
        RegionKind::Property,
        allowance(),
        all_spec("operation:property")?,
        TimestampNs(0),
    )?;
    Ok((root, property, tree))
}

fn observation_spec() -> Result<RootAuthoritySpec, Box<dyn std::error::Error>> {
    let mut value = all_spec(OBSERVATION)?;
    value.capabilities = [
        RuntimeGrant::AdapterAuth,
        RuntimeGrant::AdapterNet,
        RuntimeGrant::ObserveStatus,
    ]
    .into_iter()
    .map(|grant| grant.as_str().into())
    .collect();
    value.deadline = Some(TimestampNs(200));
    value.budgets.bytes = 128;
    value.budgets.network_bytes = 128;
    value.budgets.storage_operations = 2;
    Ok(value)
}

struct Fixture {
    journal: Journal,
    recovery: MultipartRecovery,
    intent: UploadIntent,
    proof: ContentDigest,
    store: Rc<RefCell<Store>>,
}

fn fixture(revoked: Option<RuntimeGrant>) -> Result<Fixture, Box<dyn std::error::Error>> {
    let store = Rc::new(RefCell::new(Store::default()));
    let mut journal = Journal::default();
    let (intent, proof) = {
        let (_root, mut parent, mut tree) = property()?;
        let mut transport = MemoryTransport {
            store: store.clone(),
        };
        let mut child = all_spec(UPLOAD)?;
        child
            .capabilities
            .retain(|cap| cap != RuntimeGrant::ObserveStatus.as_str());
        child.deadline = Some(TimestampNs(10));
        let mut upload = StagedUpload::stage(
            &mut parent,
            &mut tree,
            &mut transport,
            OperationId::parse(UPLOAD)?,
            3,
            ChunkPolicy {
                part_size: MIN_PART_SIZE,
            },
            ContentDigest::sha256(b"original-root"),
            child,
            RESOURCE,
            TimestampNs(1),
        )?;
        upload.attach_journal(&tree, TimestampNs(1), &mut journal)?;
        let intent = upload.intent().clone();
        upload.upload_chunks(&tree, || TimestampNs(2), |_| b"abc".to_vec())?;
        store.borrow_mut().fault_once = Some(TransportOperation::Complete);
        assert!(upload.finish(&mut tree, TimestampNs(3)).is_err());
        if let Some(revoked) = revoked {
            let mut grants = GrantSet::empty();
            for grant in [
                RuntimeGrant::ObjectStage,
                RuntimeGrant::ObjectPublish,
                RuntimeGrant::AdapterAuth,
                RuntimeGrant::AdapterNet,
            ] {
                if grant != revoked {
                    grants = grants.with_scope(grant, BTreeSet::from([RESOURCE.to_owned()]));
                }
            }
            upload.narrow_grants_durable(&tree, TimestampNs(4), grants)?;
        }
        let followup = upload.journal_pin().ok_or("missing head")?.root;
        let receipt = upload.settle_indeterminate(
            &mut tree,
            TimestampNs(5),
            "read-only follow-up required",
            followup,
        )?;
        (intent, receipt.digest())
    };
    let minimum = journal.head().ok_or("missing final pin")?;
    let recovery = MultipartRecovery::read(&journal, minimum)?;
    Ok(Fixture {
        journal,
        recovery,
        intent,
        proof,
        store,
    })
}

struct Probe(MemoryTransport);
impl MultipartTransport for Probe {
    fn initiate(&mut self, _: &mut TransportCx<'_>, _: &UploadIntent) -> Result<UploadId, String> {
        self.0
            .store
            .borrow_mut()
            .calls
            .push(TransportOperation::Initiate);
        Err("a completion observer must never initiate".into())
    }
    fn upload_part(
        &mut self,
        _: &mut TransportCx<'_>,
        _: &UploadId,
        _: &PlannedChunk,
        _: &[u8],
        _: ContentDigest,
    ) -> Result<PartReceipt, String> {
        self.0
            .store
            .borrow_mut()
            .calls
            .push(TransportOperation::UploadPart);
        Err("a completion observer must never upload a part".into())
    }
    fn complete(
        &mut self,
        _: &mut TransportCx<'_>,
        _: &UploadId,
        _: &UploadIntent,
        _: &[PartReceipt],
    ) -> Result<(), String> {
        self.0
            .store
            .borrow_mut()
            .calls
            .push(TransportOperation::Complete);
        Err("a completion observer must never repeat completion".into())
    }
    fn abort(
        &mut self,
        _: &mut TransportCx<'_>,
        _: &UploadId,
        _: &UploadIntent,
    ) -> Result<(), String> {
        self.0
            .store
            .borrow_mut()
            .calls
            .push(TransportOperation::Abort);
        Err("a completion observer must never abort".into())
    }
    fn reconcile(
        &mut self,
        cx: &mut TransportCx<'_>,
        intent: &UploadIntent,
    ) -> Result<Reconciliation, String> {
        assert!(cx.is_read_only_observation());
        assert!(!cx.is_durable());
        assert_eq!(cx.operation(), TransportOperation::Reconcile);
        assert_eq!(
            cx.deadline().map_err(|e| e.to_string())?,
            Some(TimestampNs(200))
        );
        assert_eq!(cx.authority().grants().len(), 3);
        assert!(!cx.authority().grants().has(RuntimeGrant::ObjectStage));
        assert!(!cx.authority().grants().has(RuntimeGrant::ObjectPublish));
        self.0.reconcile(cx, intent)
    }
}

#[test]
fn lost_complete_can_be_observed_after_original_deadline_without_rewriting_history() -> Test {
    let f = fixture(None)?;
    let original = f.journal.0.clone();
    let before = f.recovery.consumed();
    let (_root, mut parent, mut tree) = property()?;
    let mut probe = Probe(MemoryTransport {
        store: f.store.clone(),
    });
    let mut observation = CompletionObservation::begin(
        &mut parent,
        &mut tree,
        &f.journal,
        &f.recovery,
        &f.intent,
        observation_spec()?,
        TimestampNs(100),
    )?;
    let region = observation.region().clone();
    let receipt = observation.observe(&mut tree, &mut probe, TimestampNs(101))?;
    assert_eq!(receipt.outcome(), CompletionObservationOutcome::Completed);
    assert!(receipt.completion_digest().is_some());
    assert_eq!(receipt.indeterminate_receipt_digest(), f.proof);
    assert_eq!(receipt.source_pin(), f.recovery.head());
    assert_eq!(receipt.source_operation(), &OperationId::parse(UPLOAD)?);
    assert_eq!(receipt.operation(), &OperationId::parse(OBSERVATION)?);
    assert_eq!(receipt.consumed().storage_operations, 1);
    assert!(observation.is_settled());
    assert_eq!(tree.get(&region)?.state, RegionState::Closed);
    assert_eq!(observation.settle(&mut tree, TimestampNs(150))?, receipt);
    drop(observation);
    assert_eq!(parent.budget().consumed().storage_operations, 1);
    assert_eq!(f.journal.0, original);
    assert_eq!(f.recovery.consumed(), before);
    assert_eq!(
        f.recovery.owner_state()?,
        Some(ObligationState::Indeterminate)
    );
    assert_eq!(
        f.recovery.phase(),
        MultipartPhase::Uncertain(TransportOperation::Complete)
    );
    assert_eq!(
        f.store.borrow().calls,
        [
            TransportOperation::Initiate,
            TransportOperation::UploadPart,
            TransportOperation::Complete,
            TransportOperation::Reconcile
        ]
    );
    let bytes = receipt.encode()?;
    assert_eq!(CompletionObservationReceipt::decode(&bytes)?, receipt);
    assert_eq!(ContentDigest::sha256(&bytes), receipt.digest()?);
    assert!(
        !bytes
            .windows(b"opaque-provider-token".len())
            .any(|part| part == b"opaque-provider-token")
    );
    Ok(())
}

#[test]
fn unknown_is_a_closed_new_read_without_an_upgrade_or_an_automatic_retry() -> Test {
    let f = fixture(None)?;
    f.store.borrow_mut().unknown = true;
    let (_root, mut parent, mut tree) = property()?;
    let mut probe = Probe(MemoryTransport {
        store: f.store.clone(),
    });
    let mut observation = CompletionObservation::begin(
        &mut parent,
        &mut tree,
        &f.journal,
        &f.recovery,
        &f.intent,
        observation_spec()?,
        TimestampNs(100),
    )?;
    let receipt = observation.observe(&mut tree, &mut probe, TimestampNs(101))?;
    assert_eq!(receipt.outcome(), CompletionObservationOutcome::Unknown);
    assert_eq!(receipt.completion_digest(), None);
    assert!(observation.is_settled());
    assert!(
        observation
            .observe(&mut tree, &mut probe, TimestampNs(102))
            .is_err()
    );
    assert_eq!(f.store.borrow().calls.len(), 4);
    assert_eq!(
        f.recovery.owner_state()?,
        Some(ObligationState::Indeterminate)
    );
    Ok(())
}

#[test]
fn failed_read_keeps_spend_and_requires_explicit_settlement_before_refund() -> Test {
    let f = fixture(None)?;
    {
        let mut store = f.store.borrow_mut();
        store.fault_once = Some(TransportOperation::Reconcile);
        store.envelope_bytes = 7;
        store.checkpoint_once = Some(TimestampNs(120));
    }
    let (_root, mut parent, mut tree) = property()?;
    let mut probe = Probe(MemoryTransport {
        store: f.store.clone(),
    });
    let mut observation = CompletionObservation::begin(
        &mut parent,
        &mut tree,
        &f.journal,
        &f.recovery,
        &f.intent,
        observation_spec()?,
        TimestampNs(100),
    )?;
    assert!(
        observation
            .observe(&mut tree, &mut probe, TimestampNs(101))
            .is_err()
    );
    assert!(!observation.is_settled());
    assert_eq!(observation.observed_at(), TimestampNs(120));
    assert_eq!(observation.budget().consumed().network_bytes, 7);
    assert!(
        observation
            .observe(&mut tree, &mut probe, TimestampNs(121))
            .is_err()
    );
    let receipt = observation.settle(&mut tree, TimestampNs(122))?;
    assert_eq!(receipt.outcome(), CompletionObservationOutcome::Unknown);
    assert_eq!(receipt.observed_at(), TimestampNs(122));
    assert_eq!(receipt.consumed().storage_operations, 1);
    assert_eq!(receipt.consumed().network_bytes, 7);
    drop(observation);
    assert_eq!(parent.budget().consumed().network_bytes, 7);
    assert_eq!(parent.budget().consumed().storage_operations, 1);
    Ok(())
}

#[test]
fn contradictory_or_nonterminal_provider_answers_cannot_confirm_completion() -> Test {
    let f = fixture(None)?;
    let upload = f.recovery.upload_id().ok_or("missing upload")?.clone();
    let parts: Vec<_> = f.recovery.part_receipts().cloned().collect();
    let complete = ProviderUploadState::Completed {
        upload: upload.clone(),
        manifest_root: f.intent.manifest_root(),
        parts: parts.clone(),
    };
    let mut wrong_checksum = parts.clone();
    wrong_checksum[0].content_digest = ContentDigest::sha256(b"wrong");
    let mut wrong_token = parts.clone();
    wrong_token[0].etag.0 = "changed-provider-token".into();
    let states = [
        (ContentDigest::sha256(b"wrong-intent"), complete),
        (
            f.intent.digest(),
            ProviderUploadState::Completed {
                upload: UploadId("different-upload".into()),
                manifest_root: f.intent.manifest_root(),
                parts: parts.clone(),
            },
        ),
        (
            f.intent.digest(),
            ProviderUploadState::Completed {
                upload: upload.clone(),
                manifest_root: ContentDigest::sha256(b"wrong-root"),
                parts: parts.clone(),
            },
        ),
        (
            f.intent.digest(),
            ProviderUploadState::Completed {
                upload: upload.clone(),
                manifest_root: f.intent.manifest_root(),
                parts: vec![],
            },
        ),
        (
            f.intent.digest(),
            ProviderUploadState::Completed {
                upload: upload.clone(),
                manifest_root: f.intent.manifest_root(),
                parts: wrong_checksum,
            },
        ),
        (
            f.intent.digest(),
            ProviderUploadState::Completed {
                upload: upload.clone(),
                manifest_root: f.intent.manifest_root(),
                parts: wrong_token,
            },
        ),
        (
            f.intent.digest(),
            ProviderUploadState::Active {
                upload: upload.clone(),
                parts,
            },
        ),
        (f.intent.digest(), ProviderUploadState::Aborted { upload }),
        (f.intent.digest(), ProviderUploadState::NotStarted),
    ];
    for (intent_digest, state) in states {
        f.store.borrow_mut().observation = Some(Reconciliation {
            intent_digest,
            state,
        });
        let (_root, mut parent, mut tree) = property()?;
        let mut probe = Probe(MemoryTransport {
            store: f.store.clone(),
        });
        let mut observation = CompletionObservation::begin(
            &mut parent,
            &mut tree,
            &f.journal,
            &f.recovery,
            &f.intent,
            observation_spec()?,
            TimestampNs(100),
        )?;
        assert!(
            observation
                .observe(&mut tree, &mut probe, TimestampNs(101))
                .is_err()
        );
        let receipt = observation.settle(&mut tree, TimestampNs(102))?;
        assert_eq!(receipt.outcome(), CompletionObservationOutcome::Unknown);
        assert_eq!(receipt.completion_digest(), None);
        assert!(observation.is_settled());
    }
    Ok(())
}

#[test]
fn source_net_and_secret_revocations_survive_fresh_parent_authority() -> Test {
    for revoked in [RuntimeGrant::AdapterAuth, RuntimeGrant::AdapterNet] {
        let f = fixture(Some(revoked))?;
        let (_root, mut parent, mut tree) = property()?;
        assert!(CompletionObservation::validate_source(&f.recovery, &f.intent).is_err());
        assert!(
            CompletionObservation::begin(
                &mut parent,
                &mut tree,
                &f.journal,
                &f.recovery,
                &f.intent,
                observation_spec()?,
                TimestampNs(100)
            )
            .is_err()
        );
        assert_eq!(*parent.budget().consumed(), BudgetVector::ZERO);
        assert_eq!(f.store.borrow().calls.len(), 3);
    }
    Ok(())
}

#[test]
fn broadened_scope_missing_finite_deadline_or_effect_grants_refuse_before_reservation() -> Test {
    let f = fixture(None)?;
    let base = observation_spec()?;
    let mut variants = vec![];
    let mut value = base.clone();
    value.deadline = None;
    variants.push(value);
    let mut value = base.clone();
    value.deadline = Some(TimestampNs(100));
    variants.push(value);
    let mut value = base.clone();
    value
        .capabilities
        .push(RuntimeGrant::ObjectStage.as_str().into());
    variants.push(value);
    let mut value = base.clone();
    value.operation_id = f.intent.operation().clone();
    variants.push(value);
    let mut value = base.clone();
    value.privacy_scope = "privacy:different".into();
    variants.push(value);
    let mut value = base.clone();
    value.retention_scope = "retention:different".into();
    variants.push(value);
    let mut value = base.clone();
    value.principal = "principal:different".into();
    variants.push(value);
    let mut value = base.clone();
    value.anchor_universe = ContentDigest::sha256(b"different-anchor");
    variants.push(value);
    let mut value = base.clone();
    value.generation += 1;
    variants.push(value);
    let mut value = base.clone();
    value.priority = 0;
    variants.push(value);
    let mut value = base.clone();
    value.budgets.storage_operations = 0;
    variants.push(value);
    for value in variants {
        let (_root, mut parent, mut tree) = property()?;
        assert!(
            CompletionObservation::begin(
                &mut parent,
                &mut tree,
                &f.journal,
                &f.recovery,
                &f.intent,
                value,
                TimestampNs(100)
            )
            .is_err()
        );
        assert_eq!(*parent.budget().consumed(), BudgetVector::ZERO);
    }
    let (_root, mut parent, mut tree) = property()?;
    let mut grants = GrantSet::empty();
    for grant in [
        RuntimeGrant::AdapterNet,
        RuntimeGrant::AdapterAuth,
        RuntimeGrant::ObserveStatus,
    ] {
        grants = grants.with_scope(grant, BTreeSet::from(["archive:different-target".into()]));
    }
    parent.narrow_grants(grants)?;
    assert!(
        CompletionObservation::begin(
            &mut parent,
            &mut tree,
            &f.journal,
            &f.recovery,
            &f.intent,
            base,
            TimestampNs(100)
        )
        .is_err()
    );
    assert_eq!(*parent.budget().consumed(), BudgetVector::ZERO);
    Ok(())
}

#[test]
fn cancellation_and_expiry_before_dispatch_leave_not_observed_zero_spend() -> Test {
    let f = fixture(None)?;
    for cancelled in [false, true] {
        let (_root, mut parent, mut tree) = property()?;
        let mut probe = Probe(MemoryTransport {
            store: f.store.clone(),
        });
        let mut observation = CompletionObservation::begin(
            &mut parent,
            &mut tree,
            &f.journal,
            &f.recovery,
            &f.intent,
            observation_spec()?,
            TimestampNs(100),
        )?;
        let now = if cancelled {
            tree.request_drain(
                observation.region(),
                Some("explicit stop"),
                TimestampNs(101),
            )?;
            TimestampNs(102)
        } else {
            TimestampNs(200)
        };
        assert!(observation.observe(&mut tree, &mut probe, now).is_err());
        let receipt = observation.settle(&mut tree, now)?;
        assert_eq!(receipt.outcome(), CompletionObservationOutcome::NotObserved);
        assert_eq!(receipt.consumed(), BudgetVector::ZERO);
        assert!(observation.is_settled());
    }
    assert_eq!(f.store.borrow().calls.len(), 3);
    Ok(())
}

#[test]
fn fresh_deadline_stays_effective_during_reconcile_and_later_time_is_retained() -> Test {
    let f = fixture(None)?;
    f.store.borrow_mut().checkpoint_once = Some(TimestampNs(200));
    let (_root, mut parent, mut tree) = property()?;
    let mut probe = Probe(MemoryTransport {
        store: f.store.clone(),
    });
    let mut observation = CompletionObservation::begin(
        &mut parent,
        &mut tree,
        &f.journal,
        &f.recovery,
        &f.intent,
        observation_spec()?,
        TimestampNs(100),
    )?;
    assert!(
        observation
            .observe(&mut tree, &mut probe, TimestampNs(101))
            .is_err()
    );
    assert_eq!(observation.observed_at(), TimestampNs(200));
    assert!(observation.settle(&mut tree, TimestampNs(199)).is_err());
    let receipt = observation.settle(&mut tree, TimestampNs(201))?;
    assert_eq!(receipt.outcome(), CompletionObservationOutcome::Unknown);
    assert_eq!(receipt.consumed().storage_operations, 1);
    assert_eq!(receipt.observed_at(), TimestampNs(201));
    assert_eq!(f.store.borrow().calls.len(), 3);
    Ok(())
}

#[test]
fn changed_source_head_and_unpinned_intent_refuse_without_new_work() -> Test {
    let f = fixture(None)?;
    let mut stale = f.journal.clone();
    let _ = stale.0.pop();
    let (_root, mut parent, mut tree) = property()?;
    assert!(
        CompletionObservation::begin(
            &mut parent,
            &mut tree,
            &stale,
            &f.recovery,
            &f.intent,
            observation_spec()?,
            TimestampNs(100)
        )
        .is_err()
    );
    assert_eq!(*parent.budget().consumed(), BudgetVector::ZERO);
    let mut transport = MemoryTransport::default();
    let plan = f.recovery.plan().clone();
    let wrong = fss_object::multipart::MultipartSession::prepare(
        &mut transport,
        &plan,
        ContentDigest::sha256(b"other-root"),
        OperationId::parse(UPLOAD)?,
        RESOURCE,
        TimestampNs(0),
    )?;
    assert!(CompletionObservation::validate_source(&f.recovery, wrong.intent()).is_err());
    assert_eq!(f.store.borrow().calls.len(), 3);
    Ok(())
}

#[test]
fn retained_observation_rejects_truncation_extra_bytes_and_changed_result_tag() -> Test {
    let f = fixture(None)?;
    f.store.borrow_mut().unknown = true;
    let (_root, mut parent, mut tree) = property()?;
    let mut probe = Probe(MemoryTransport {
        store: f.store.clone(),
    });
    let mut observation = CompletionObservation::begin(
        &mut parent,
        &mut tree,
        &f.journal,
        &f.recovery,
        &f.intent,
        observation_spec()?,
        TimestampNs(100),
    )?;
    let receipt = observation.observe(&mut tree, &mut probe, TimestampNs(101))?;
    let bytes = receipt.encode()?;
    for length in 0..bytes.len() {
        assert!(CompletionObservationReceipt::decode(&bytes[..length]).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(CompletionObservationReceipt::decode(&extra).is_err());
    let mut changed = bytes;
    let index = changed.len() - 2;
    changed[index] = 2; // Completed without its required completion proof.
    assert!(CompletionObservationReceipt::decode(&changed).is_err());
    Ok(())
}

struct OriginSnapshot<'a> {
    journal: &'a Journal,
    origin: Option<ContentDigest>,
}
impl UploadJournal for OriginSnapshot<'_> {
    fn origin_binding(&self) -> Option<ContentDigest> {
        self.origin
    }
    fn head(&self) -> Option<UploadJournalPin> {
        self.journal.head()
    }
    fn latest(&self) -> Option<&[u8]> {
        self.journal.latest()
    }
    fn contains(&self, pin: UploadJournalPin) -> bool {
        self.journal.contains(pin)
    }
    fn append(
        &mut self,
        _: Option<UploadJournalPin>,
        _: &[u8],
    ) -> Result<UploadJournalPin, MultipartError> {
        Err(MultipartError::Persistence(
            "read-only origin fixture".into(),
        ))
    }
}

struct OriginProbe {
    inner: Probe,
    expected: ContentDigest,
}
impl MultipartTransport for OriginProbe {
    fn initiate(
        &mut self,
        cx: &mut TransportCx<'_>,
        intent: &UploadIntent,
    ) -> Result<UploadId, String> {
        self.inner.initiate(cx, intent)
    }
    fn upload_part(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        chunk: &PlannedChunk,
        bytes: &[u8],
        digest: ContentDigest,
    ) -> Result<PartReceipt, String> {
        self.inner.upload_part(cx, upload, chunk, bytes, digest)
    }
    fn complete(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        intent: &UploadIntent,
        parts: &[PartReceipt],
    ) -> Result<(), String> {
        self.inner.complete(cx, upload, intent, parts)
    }
    fn abort(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        intent: &UploadIntent,
    ) -> Result<(), String> {
        self.inner.abort(cx, upload, intent)
    }
    fn reconcile(
        &mut self,
        cx: &mut TransportCx<'_>,
        intent: &UploadIntent,
    ) -> Result<Reconciliation, String> {
        assert_eq!(cx.origin_binding(), Some(self.expected));
        self.inner.reconcile(cx, intent)
    }
}

#[test]
fn immutable_custody_origin_reaches_the_fresh_read_only_transport() -> Test {
    let f = fixture(None)?;
    assert_eq!(f.recovery.origin_binding(), None);
    let origin = ContentDigest::sha256(b"fixture-only-independent-custody-origin");
    let journal = OriginSnapshot {
        journal: &f.journal,
        origin: Some(origin),
    };
    let recovery = MultipartRecovery::read(&journal, f.recovery.head())?;
    let (_root, mut parent, mut tree) = property()?;
    let mut transport = OriginProbe {
        inner: Probe(MemoryTransport {
            store: f.store.clone(),
        }),
        expected: origin,
    };
    let mut observation = CompletionObservation::begin(
        &mut parent,
        &mut tree,
        &journal,
        &recovery,
        &f.intent,
        observation_spec()?,
        TimestampNs(100),
    )?;
    let receipt = observation.observe(&mut tree, &mut transport, TimestampNs(101))?;
    assert_eq!(receipt.outcome(), CompletionObservationOutcome::Completed);
    assert_eq!(recovery.origin_binding(), Some(origin));
    assert_eq!(f.journal.head(), Some(f.recovery.head()));
    Ok(())
}

#[test]
fn same_checkpoint_and_head_cannot_hide_changed_or_lost_custody_origin() -> Test {
    let f = fixture(None)?;
    let origin = ContentDigest::sha256(b"first-fixture-origin");
    let original = OriginSnapshot {
        journal: &f.journal,
        origin: Some(origin),
    };
    let recovery = MultipartRecovery::read(&original, f.recovery.head())?;
    for changed in [None, Some(ContentDigest::sha256(b"other-fixture-origin"))] {
        let journal = OriginSnapshot {
            journal: &f.journal,
            origin: changed,
        };
        assert_eq!(journal.head(), original.head());
        assert_eq!(journal.latest(), original.latest());
        assert!(matches!(
            recovery.validate_restore(&journal, TimestampNs(100)),
            Err(MultipartError::RecoveryPinMismatch)
        ));
        let (_root, mut parent, mut tree) = property()?;
        assert!(
            CompletionObservation::begin(
                &mut parent,
                &mut tree,
                &journal,
                &recovery,
                &f.intent,
                observation_spec()?,
                TimestampNs(100)
            )
            .is_err()
        );
        assert_eq!(*parent.budget().consumed(), BudgetVector::ZERO);
    }
    assert_eq!(f.store.borrow().calls.len(), 3);
    Ok(())
}
