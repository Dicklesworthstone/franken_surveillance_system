#![forbid(unsafe_code)]
//! Restart, custody, admission and dispatch-boundary contracts without camera access.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::reference_contract_basis;
use fss_ipc::{
    ActiveScrubStatus, ControlOperationState, DaemonIpcHandler, IpcResponse, RequestCancelToken,
    RingWatermarkStatus,
};
use fss_object::{
    HostSpoolIo,
    effect_journal::{EffectJournalLimits, FileEffectJournal},
};

use super::*;
use crate::control::{
    ControlPlaneShared, ControlStatusSnapshot, DaemonIpcHandlerAdapter, ForwardBatchWriter,
    control_op_approval_digest,
};
use crate::error::DaemonError;

type Test = Result<(), Box<dyn std::error::Error>>;
const SITE: &str = "site-durable-controls";
const CAMERA: &str = "sensor:front";

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Result<Self, std::io::Error> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let root = std::env::temp_dir().join(format!(
            "fss-control-history-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root)?;
        Ok(Self(root.canonicalize()?))
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context() -> Result<RequestContext, fss_core::ContractError> {
    Ok(RequestContext {
        connection_id: 23,
        request_id: 41,
        deployment_id: SITE.to_owned(),
        contract_basis_digest: reference_contract_basis().basis_digest(),
        principal: PrincipalId::parse("principal:control-owner")?,
        granted_capabilities: vec![
            "CAP-OBSERVE-STATUS-001".to_owned(),
            "CAP-AGENT-CAMERA-CONTROL-001".to_owned(),
            "CAP-OBSERVE-STATUS-001".to_owned(),
        ],
        cancel: RequestCancelToken::new(),
    })
}

fn scope() -> Scope {
    Scope {
        deployment_id: SITE.to_owned(),
        root_digest: ContentDigest::sha256(b"control test deployment"),
        basis_digest: reference_contract_basis().basis_digest(),
    }
}

fn admit(
    journal: &mut DurableControlJournal,
    op: BoundedControlOp,
) -> Result<PendingControlCommand, Box<dyn std::error::Error>> {
    let target = op.requires_camera_id().then_some(CAMERA);
    Ok(journal.admit(
        &context()?,
        op,
        target,
        control_op_approval_digest(SITE, op, target),
    )?)
}

#[test]
fn cold_recovery_preserves_all_boundaries_without_restoring_dispatch_authority() -> Test {
    let root = TempRoot::new()?;
    let mut journal = DurableControlJournal::open(&root.0, SITE, Arc::new(HostSpoolIo))?;
    let queued = admit(&mut journal, BoundedControlOp::StartCamera)?;
    let started = admit(&mut journal, BoundedControlOp::StopCamera)?;
    journal.transition(&started.operation_id, ControlProgress::DispatchStarted)?;
    let returned = admit(&mut journal, BoundedControlOp::SnapshotCamera)?;
    journal.transition(&returned.operation_id, ControlProgress::DispatchStarted)?;
    journal.transition(&returned.operation_id, ControlProgress::SubsystemReturned)?;
    let cancelled = admit(&mut journal, BoundedControlOp::TriggerScrub)?;
    journal.transition(
        &cancelled.operation_id,
        ControlProgress::CancelledBeforeExecution,
    )?;
    let before = journal.inspect(4)?;
    assert!(before.entries.iter().all(|entry| !entry.recovered));
    drop(journal);

    let mut reopened = DurableControlJournal::open(&root.0, SITE, Arc::new(HostSpoolIo))?;
    let recovered = reopened.inspect(4)?;
    assert_eq!(recovered.head, before.head);
    assert_eq!(recovered.total_entries, 4);
    assert!(recovered.entries.iter().all(|entry| entry.recovered));
    assert_eq!(
        recovered
            .entries
            .iter()
            .map(|entry| entry.progress)
            .collect::<Vec<_>>(),
        vec![
            ControlProgress::NeverStarted,
            ControlProgress::DispatchStarted,
            ControlProgress::SubsystemReturned,
            ControlProgress::CancelledBeforeExecution,
        ]
    );
    assert_eq!(recovered.entries[0].command, queued);
    assert_eq!(recovered.entries[0].principal, context()?.principal);
    assert_eq!(
        recovered.entries[0].contract_basis_digest,
        context()?.contract_basis_digest
    );
    assert_eq!(recovered.entries[0].request_id, 41);
    assert_eq!(recovered.entries[0].connection_id, 23);
    assert_eq!(
        recovered.entries[0].granted_capabilities,
        vec![
            "CAP-AGENT-CAMERA-CONTROL-001".to_owned(),
            "CAP-OBSERVE-STATUS-001".to_owned(),
        ]
    );
    for command in [&queued, &started, &returned, &cancelled] {
        assert!(
            reopened
                .transition(&command.operation_id, ControlProgress::DispatchStarted)
                .is_err()
        );
    }
    assert_eq!(reopened.inspect(4)?.head, before.head);
    let fresh = admit(&mut reopened, BoundedControlOp::StartCamera)?;
    assert_ne!(fresh.operation_id, queued.operation_id);
    let bounded = reopened.inspect(2)?;
    assert_eq!(bounded.total_entries, 5);
    assert_eq!(bounded.omitted_entries, 3);
    assert_eq!(
        bounded.entries.last().map(|entry| &entry.command),
        Some(&fresh)
    );
    assert!(
        bounded
            .entries
            .last()
            .is_some_and(|entry| entry.accepted_sequence > before.head.sequence)
    );
    assert!(bounded.to_json().contains("\"automatic_replay\":false"));
    assert!(
        bounded
            .to_json()
            .contains("\"semantic_completion_proved\":false")
    );
    assert!(reopened.inspect(0).is_err());
    assert!(
        reopened
            .inspect(MAX_CONTROL_INSPECTION_ENTRIES + 1)
            .is_err()
    );
    Ok(())
}

#[derive(Debug)]
struct MemoryStore {
    records: Vec<Vec<u8>>,
    pins: Vec<EffectJournalPin>,
    maximum: usize,
    lose_ack_at: Option<usize>,
}

impl MemoryStore {
    fn new(maximum: usize, lose_ack_at: Option<usize>) -> Self {
        Self {
            records: Vec::new(),
            pins: Vec::new(),
            maximum,
            lose_ack_at,
        }
    }
}

impl EffectJournalStore for MemoryStore {
    fn head(&self) -> Option<EffectJournalPin> {
        self.pins.last().copied()
    }
    fn records(&self) -> &[Vec<u8>] {
        &self.records
    }
    fn contains(&self, pin: EffectJournalPin) -> bool {
        self.pins.contains(&pin)
    }
    fn reserve_capacity(
        &mut self,
        count: usize,
        bytes: usize,
    ) -> Result<(), EffectPersistenceError> {
        if self.records.len().saturating_add(count) > self.maximum
            || bytes > MAX_CONTROL_RECORD_BYTES
        {
            return Err(EffectPersistenceError::Capacity);
        }
        Ok(())
    }
    fn append(
        &mut self,
        expected: Option<EffectJournalPin>,
        record: &[u8],
    ) -> Result<EffectJournalPin, EffectPersistenceError> {
        if self.head() != expected {
            return Err(EffectPersistenceError::PinMismatch);
        }
        self.reserve_capacity(1, record.len())?;
        let sequence = self.records.len() as u64 + 1;
        let mut bytes = sequence.to_be_bytes().to_vec();
        if let Some(previous) = expected {
            bytes.extend_from_slice(&previous.root.bytes());
        }
        bytes.extend_from_slice(record);
        let pin = EffectJournalPin {
            sequence,
            root: ContentDigest::sha256(&bytes),
        };
        self.records.push(record.to_vec());
        self.pins.push(pin);
        if self.lose_ack_at == Some(self.records.len()) {
            return Err(EffectPersistenceError::Storage(
                "injected lost append acknowledgement".to_owned(),
            ));
        }
        Ok(pin)
    }
}

#[test]
fn lost_append_acknowledgement_fences_owner_and_never_resurrects_live_work() -> Test {
    for failure_record in [2, 3] {
        let mut journal = DurableControlJournal::from_store(
            scope(),
            Box::new(MemoryStore::new(16, Some(failure_record))),
            true,
        )?;
        if failure_record == 2 {
            assert!(admit(&mut journal, BoundedControlOp::StopCamera).is_err());
        } else {
            let command = admit(&mut journal, BoundedControlOp::StopCamera)?;
            assert!(
                journal
                    .transition(&command.operation_id, ControlProgress::DispatchStarted)
                    .is_err()
            );
        }
        assert!(journal.is_poisoned());
        assert!(matches!(
            journal.inspect(1),
            Err(EffectPersistenceError::Poisoned)
        ));
        assert!(admit(&mut journal, BoundedControlOp::StartCamera).is_err());
        let DurableControlJournal { scope, store, .. } = journal;
        let mut recovered = DurableControlJournal::from_store(scope, store, false)?;
        let report = recovered.inspect(1)?;
        assert_eq!(report.total_entries, 1);
        assert_eq!(
            report.entries[0].progress,
            if failure_record == 2 {
                ControlProgress::NeverStarted
            } else {
                ControlProgress::DispatchStarted
            }
        );
        assert!(
            recovered
                .transition(
                    &report.entries[0].command.operation_id,
                    ControlProgress::DispatchStarted
                )
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn admission_reserves_remaining_boundaries_before_accepting_more_work() -> Test {
    let mut journal =
        DurableControlJournal::from_store(scope(), Box::new(MemoryStore::new(4, None)), true)?;
    let first = admit(&mut journal, BoundedControlOp::StopCamera)?;
    let head = journal.inspect(1)?.head;
    assert!(admit(&mut journal, BoundedControlOp::StartCamera).is_err());
    assert!(!journal.is_poisoned());
    assert_eq!(journal.inspect(1)?.head, head);
    journal.transition(&first.operation_id, ControlProgress::DispatchStarted)?;
    journal.transition(&first.operation_id, ControlProgress::SubsystemReturned)?;
    assert_eq!(journal.inspect(1)?.head.sequence, 4);
    Ok(())
}

#[test]
fn foreign_context_and_illegal_progress_cannot_change_retained_history() -> Test {
    let mut journal =
        DurableControlJournal::from_store(scope(), Box::new(MemoryStore::new(32, None)), true)?;
    let initial = journal.inspect(1)?.head;
    for wrong_basis in [false, true] {
        let mut context = context()?;
        if wrong_basis {
            context.contract_basis_digest = ContentDigest::sha256(b"other contract");
        } else {
            context.deployment_id = "site-other".to_owned();
        }
        assert!(
            journal
                .admit(
                    &context,
                    BoundedControlOp::TriggerScrub,
                    None,
                    control_op_approval_digest(SITE, BoundedControlOp::TriggerScrub, None)
                )
                .is_err()
        );
        assert_eq!(journal.inspect(1)?.head, initial);
    }
    let command = admit(&mut journal, BoundedControlOp::StopCamera)?;
    assert!(
        journal
            .transition(&command.operation_id, ControlProgress::SubsystemReturned)
            .is_err()
    );
    journal.transition(&command.operation_id, ControlProgress::DispatchStarted)?;
    let started = journal.inspect(1)?.head;
    assert!(
        journal
            .transition(
                &command.operation_id,
                ControlProgress::CancelledBeforeExecution
            )
            .is_err()
    );
    assert!(
        journal
            .transition(&command.operation_id, ControlProgress::DispatchStarted)
            .is_err()
    );
    assert_eq!(journal.inspect(1)?.head, started);
    Ok(())
}

#[test]
fn existing_history_refuses_foreign_site_missing_pins_and_partial_bootstrap() -> Test {
    let root = TempRoot::new()?;
    assert!(inspect_control_history(&root.0, SITE, Arc::new(HostSpoolIo), 1).is_err());
    assert!(
        !root.0.join("control-history").exists(),
        "inspection must never create history"
    );
    let mut journal = DurableControlJournal::open(&root.0, SITE, Arc::new(HostSpoolIo))?;
    admit(&mut journal, BoundedControlOp::StopCamera)?;
    let expected = journal.inspect(1)?.head;
    drop(journal);
    assert!(DurableControlJournal::open(&root.0, "site-other", Arc::new(HostSpoolIo)).is_err());
    assert_eq!(
        inspect_control_history(&root.0, SITE, Arc::new(HostSpoolIo), 1)?.head,
        expected
    );
    fs::rename(
        root.0.join("control-history-pins"),
        root.0.join("saved-pins"),
    )?;
    assert!(DurableControlJournal::open(&root.0, SITE, Arc::new(HostSpoolIo)).is_err());
    assert!(!root.0.join("control-history-pins").exists());

    let partial = TempRoot::new()?;
    fs::create_dir(partial.0.join("control-history"))?;
    assert!(DurableControlJournal::open(&partial.0, SITE, Arc::new(HostSpoolIo)).is_err());
    assert!(!partial.0.join("control-history-pins").exists());
    Ok(())
}

#[test]
fn journal_ahead_of_checkpoint_is_preserved_and_refused_instead_of_adopted() -> Test {
    let root = TempRoot::new()?;
    let mut journal = DurableControlJournal::open(&root.0, SITE, Arc::new(HostSpoolIo))?;
    let command = admit(&mut journal, BoundedControlOp::StopCamera)?;
    let pin = journal.inspect(1)?.head;
    let pending = codec::encode(
        &journal.scope,
        &codec::Record::Progress {
            operation_id: command.operation_id,
            progress: ControlProgress::DispatchStarted,
        },
    )?;
    drop(journal);
    let mut raw = FileEffectJournal::open(
        root.0.join("control-history"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        pin,
    )?;
    let unacknowledged = raw.append(Some(pin), &pending)?;
    drop(raw);
    for _ in 0..2 {
        assert!(matches!(
            DurableControlJournal::open(&root.0, SITE, Arc::new(HostSpoolIo)),
            Err(EffectPersistenceError::PinMismatch)
        ));
    }
    let raw = FileEffectJournal::open(
        root.0.join("control-history"),
        EffectJournalLimits::default(),
        Arc::new(HostSpoolIo),
        pin,
    )?;
    assert_eq!(raw.head(), Some(unacknowledged));
    Ok(())
}

struct NoForwardWrites;
impl ForwardBatchWriter for NoForwardWrites {
    fn forward_delta_batch(
        &self,
        _: &[u8],
    ) -> Result<(u64, ContentDigest, ContentDigest), DaemonError> {
        Err(DaemonError::InvalidConfig {
            detail: "control fixture cannot write evidence".to_owned(),
        })
    }
}

fn handler(journal: DurableControlJournal) -> DaemonIpcHandlerAdapter {
    DaemonIpcHandlerAdapter {
        shared: ControlPlaneShared::new_durable(
            SITE.to_owned(),
            ContentDigest::sha256(b"ipc root"),
            vec![CAMERA.to_owned()],
            ControlStatusSnapshot {
                head_commit_sequence: 0,
                history_root: ContentDigest::sha256(b"history"),
                state_root: ContentDigest::sha256(b"state"),
                cameras: Vec::new(),
                ring: RingWatermarkStatus {
                    used_bytes: 0,
                    capacity_bytes: 1024,
                    watermark_percent: 0,
                },
                scrub: ActiveScrubStatus::Idle,
            },
            Arc::new(NoForwardWrites),
            journal,
        ),
    }
}

fn submit(
    handler: &DaemonIpcHandlerAdapter,
    op: BoundedControlOp,
) -> Result<OperationId, Box<dyn std::error::Error>> {
    let target = op.requires_camera_id().then_some(CAMERA);
    match handler.submit_bounded_control(
        &context()?,
        op,
        target,
        control_op_approval_digest(SITE, op, target),
    ) {
        IpcResponse::ControlAccepted {
            operation_id,
            state: ControlOperationState::Queued,
            ..
        } => Ok(operation_id),
        other => Err(format!("control not admitted: {other:?}").into()),
    }
}

#[test]
fn actual_control_handler_retains_before_ack_and_never_requeues_after_restart() -> Test {
    let root = TempRoot::new()?;
    let journal = DurableControlJournal::open(&root.0, SITE, Arc::new(HostSpoolIo))?;
    let owner = handler(journal);
    let id = submit(&owner, BoundedControlOp::StopCamera)?;
    let retained = owner
        .shared
        .control_history(1)?
        .ok_or("missing durable history")?;
    assert_eq!(retained.entries[0].command.operation_id, id);
    assert_eq!(retained.entries[0].progress, ControlProgress::NeverStarted);
    assert_eq!(owner.shared.queued_control_command_count()?, 1);
    drop(owner); // Crash before transfer: no graceful cancellation or subsystem call.

    let journal = DurableControlJournal::open(&root.0, SITE, Arc::new(HostSpoolIo))?;
    let restarted = handler(journal);
    assert_eq!(restarted.shared.queued_control_command_count()?, 0);
    assert!(restarted.shared.take_control_command()?.is_none());
    let next = submit(&restarted, BoundedControlOp::StopCamera)?;
    assert_ne!(next, id);
    let transfer = restarted
        .shared
        .take_control_command()?
        .ok_or("missing fresh command")?;
    assert_eq!(transfer.operation_id, next);
    let report = restarted
        .shared
        .control_history(2)?
        .ok_or("missing durable history")?;
    assert_eq!(report.entries[0].progress, ControlProgress::NeverStarted);
    assert_eq!(report.entries[1].progress, ControlProgress::DispatchStarted);
    drop(restarted); // Crash after dispatch fence: outcome remains indeterminate.
    let inspected = inspect_control_history(&root.0, SITE, Arc::new(HostSpoolIo), 2)?;
    assert_eq!(
        inspected.entries[1].progress,
        ControlProgress::DispatchStarted
    );
    Ok(())
}

#[test]
fn shutdown_cancellation_is_durable_and_scrub_transfer_does_not_claim_dispatch() -> Test {
    let root = TempRoot::new()?;
    let journal = DurableControlJournal::open(&root.0, SITE, Arc::new(HostSpoolIo))?;
    let owner = handler(journal);
    let scrub = submit(&owner, BoundedControlOp::TriggerScrub)?;
    let deferred = owner
        .shared
        .take_control_command()?
        .ok_or("missing scrub")?;
    assert_eq!(deferred.operation_id, scrub);
    assert_eq!(
        owner
            .shared
            .control_history(1)?
            .ok_or("missing history")?
            .entries[0]
            .progress,
        ControlProgress::NeverStarted
    );
    let stop = submit(&owner, BoundedControlOp::StopCamera)?;
    let (cancelled, error) = owner.shared.cancel_unstarted_controls();
    assert!(error.is_none());
    assert_eq!(cancelled.len(), 1);
    assert_eq!(cancelled[0].operation_id, stop);
    owner
        .shared
        .record_control_progress(&scrub, ControlProgress::CancelledBeforeExecution)?;
    drop(owner);
    let inspected = inspect_control_history(&root.0, SITE, Arc::new(HostSpoolIo), 2)?;
    assert!(
        inspected
            .entries
            .iter()
            .all(|entry| entry.progress == ControlProgress::CancelledBeforeExecution)
    );
    Ok(())
}

#[test]
fn failed_dispatch_fence_closes_admission_without_transferring_the_command() -> Test {
    let journal =
        DurableControlJournal::from_store(scope(), Box::new(MemoryStore::new(16, Some(3))), true)?;
    let owner = handler(journal);
    let id = submit(&owner, BoundedControlOp::StopCamera)?;
    assert!(owner.shared.take_control_command().is_err());
    assert!(owner.shared.is_shutdown_requested());
    assert_eq!(owner.shared.queued_control_command_count()?, 1);
    assert!(owner.shared.take_control_command()?.is_none());
    let journal = owner
        .shared
        .control_journal
        .lock()
        .map_err(|_| "control journal lock poisoned")?
        .take()
        .ok_or("missing journal")?;
    drop(owner);
    let DurableControlJournal { scope, store, .. } = journal;
    let recovered = DurableControlJournal::from_store(scope, store, false)?;
    let report = recovered.inspect(1)?;
    assert_eq!(report.entries[0].command.operation_id, id);
    assert_eq!(report.entries[0].progress, ControlProgress::DispatchStarted);
    Ok(())
}

#[test]
fn corrupt_retained_control_bytes_never_become_recovered_authority() -> Test {
    let root = TempRoot::new()?;
    let mut journal = DurableControlJournal::open(&root.0, SITE, Arc::new(HostSpoolIo))?;
    admit(&mut journal, BoundedControlOp::StopCamera)?;
    drop(journal);
    let object = fs::read_dir(root.0.join("control-history/objects"))?
        .next()
        .ok_or("missing journal object")??
        .path();
    let mut bytes = fs::read(&object)?;
    let last = bytes.last_mut().ok_or("empty journal object")?;
    *last ^= 1;
    fs::write(&object, bytes)?;
    assert!(inspect_control_history(&root.0, SITE, Arc::new(HostSpoolIo), 1).is_err());
    assert!(DurableControlJournal::open(&root.0, SITE, Arc::new(HostSpoolIo)).is_err());
    Ok(())
}


#[test]
fn keyed_retry_binds_exact_authority_and_intent_but_not_transport_correlation() -> Test {
    let mut journal =
        DurableControlJournal::from_store(scope(), Box::new(MemoryStore::new(32, None)), true)?;
    let key = ContentDigest::sha256(b"one intended camera stop");
    let op = BoundedControlOp::StopCamera;
    let approval = control_op_approval_digest(SITE, op, Some(CAMERA));
    let original = context()?;
    let command = journal.admit_request(&original, op, Some(CAMERA), approval, Some(key))?;
    let head = journal.inspect(1)?.head;

    let mut retry = original.clone();
    retry.request_id += 10;
    retry.connection_id += 20;
    retry.granted_capabilities.reverse();
    retry.granted_capabilities.dedup();
    let ControlReplayLookup::Match(entry) =
        journal.replay(&retry, key, op, Some(CAMERA), approval)?
    else {
        return Err("exact retry did not find retained control".into());
    };
    assert_eq!(entry.command, command);
    assert_eq!(entry.request_id, original.request_id);
    assert_eq!(entry.connection_id, original.connection_id);
    assert_eq!(entry.progress, ControlProgress::NeverStarted);
    assert!(!entry.recovered);

    let mut other_principal = retry.clone();
    other_principal.principal = PrincipalId::parse("principal:other-owner")?;
    let mut other_grants = retry.clone();
    other_grants.granted_capabilities.clear();
    for changed in [&other_principal, &other_grants] {
        assert!(matches!(
            journal.replay(changed, key, op, Some(CAMERA), approval)?,
            ControlReplayLookup::Conflict
        ));
    }
    for (changed_op, changed_target, changed_approval) in [
        (BoundedControlOp::StartCamera, Some(CAMERA), approval),
        (op, Some("sensor:back"), approval),
        (op, Some(CAMERA), ContentDigest::sha256(b"other approval")),
    ] {
        assert!(matches!(
            journal.replay(&retry, key, changed_op, changed_target, changed_approval)?,
            ControlReplayLookup::Conflict
        ));
    }
    for wrong_basis in [false, true] {
        let mut foreign = retry.clone();
        if wrong_basis {
            foreign.contract_basis_digest = ContentDigest::sha256(b"other basis");
        } else {
            foreign.deployment_id = "site-other".to_owned();
        }
        assert!(journal.replay(&foreign, key, op, Some(CAMERA), approval).is_err());
    }
    for invalid_key in [
        ContentDigest::new(fss_core::DigestAlgorithm::Sha256, [0; 32]),
        ContentDigest::new(fss_core::DigestAlgorithm::Blake3, [1; 32]),
        ContentDigest::new_laboratory(fss_core::DigestAlgorithm::Sha256, [1; 32]),
    ] {
        assert!(journal.replay(&retry, invalid_key, op, Some(CAMERA), approval).is_err());
        assert!(journal.admit_request(
            &retry, op, Some(CAMERA), approval, Some(invalid_key),
        ).is_err());
    }
    assert_eq!(journal.inspect(1)?.head, head);
    assert!(journal.admit_request(&retry, op, Some(CAMERA), approval, Some(key)).is_err());

    let independent_key = ContentDigest::sha256(b"a second intentional camera stop");
    assert!(matches!(
        journal.replay(&retry, independent_key, op, Some(CAMERA), approval)?,
        ControlReplayLookup::Missing
    ));
    let independent =
        journal.admit_request(&retry, op, Some(CAMERA), approval, Some(independent_key))?;
    assert_ne!(independent.operation_id, command.operation_id);
    assert_eq!(journal.inspect(2)?.total_entries, 2);
    Ok(())
}

#[test]
fn keyed_history_reopens_every_boundary_without_reconstructing_live_work() -> Test {
    let root = TempRoot::new()?;
    let mut journal = DurableControlJournal::open(&root.0, SITE, Arc::new(HostSpoolIo))?;
    let ctx = context()?;
    let op = BoundedControlOp::StopCamera;
    let approval = control_op_approval_digest(SITE, op, Some(CAMERA));
    let boundaries = [
        ControlProgress::NeverStarted,
        ControlProgress::DispatchStarted,
        ControlProgress::SubsystemReturned,
        ControlProgress::CancelledBeforeExecution,
    ];
    let mut originals = Vec::new();
    for (index, progress) in boundaries.into_iter().enumerate() {
        let key = ContentDigest::sha256(&[index as u8 + 1]);
        let command = journal.admit_request(&ctx, op, Some(CAMERA), approval, Some(key))?;
        if matches!(progress, ControlProgress::DispatchStarted | ControlProgress::SubsystemReturned) {
            journal.transition(&command.operation_id, ControlProgress::DispatchStarted)?;
        }
        if matches!(progress, ControlProgress::SubsystemReturned | ControlProgress::CancelledBeforeExecution) {
            journal.transition(&command.operation_id, progress)?;
        }
        originals.push((key, command, progress));
    }
    // Existing tag-1 admissions stay readable alongside additive keyed admissions.
    let legacy = admit(&mut journal, op)?;
    let before = journal.inspect(5)?;
    assert_eq!(before.entries[4].idempotency_key, None);
    drop(journal);

    let reopened = DurableControlJournal::open(&root.0, SITE, Arc::new(HostSpoolIo))?;
    let mut owner = handler(reopened);
    Arc::get_mut(&mut owner.shared).ok_or("unexpected shared owner")?.known_cameras.clear();
    assert_eq!(owner.shared.queued_control_command_count()?, 0);
    assert!(matches!(
        owner.submit_idempotent_control(
            &ctx, ContentDigest::sha256(b"fresh removed-camera control"), op, Some(CAMERA), approval,
        ),
        IpcResponse::Refused { error_id, .. }
            if error_id.as_str() == crate::error::ERR_DAEMON_UNKNOWN_CAMERA_001
    ));
    for (key, command, progress) in originals {
        assert_eq!(
            owner.submit_idempotent_control(&ctx, key, op, Some(CAMERA), approval),
            IpcResponse::ControlReplayed {
                request_id: ctx.request_id,
                operation_id: command.operation_id.clone(),
                progress,
                recovered: true,
            }
        );
        assert!(owner.shared.record_control_progress(
            &command.operation_id,
            ControlProgress::DispatchStarted,
        ).is_err());
    }
    assert_eq!(owner.shared.queued_control_command_count()?, 0);
    assert!(owner.shared.take_control_command()?.is_none());
    let after = owner.shared.control_history(5)?.ok_or("missing history")?;
    assert_eq!(after.head, before.head);
    assert_eq!(after.entries[4].command, legacy);
    assert!(after.to_json().contains("\"idempotency_key\":null"));
    assert!(after.to_json().contains("\"automatic_replay\":false"));
    assert!(after.to_json().contains("\"semantic_completion_proved\":false"));
    Ok(())
}

#[test]
fn concurrent_keyed_retries_admit_exactly_one_command_and_one_history_record() -> Test {
    let journal =
        DurableControlJournal::from_store(scope(), Box::new(MemoryStore::new(32, None)), true)?;
    let owner = Arc::new(handler(journal));
    let key = ContentDigest::sha256(b"concurrent intended stop");
    let op = BoundedControlOp::StopCamera;
    let approval = control_op_approval_digest(SITE, op, Some(CAMERA));
    let mut callers = Vec::new();
    for index in 0..8 {
        let mut ctx = context()?;
        ctx.connection_id += index;
        ctx.request_id += index;
        callers.push(ctx);
    }
    let responses = std::thread::scope(|scope| {
        let handles: Vec<_> = callers.into_iter().map(|ctx| {
            let owner = Arc::clone(&owner);
            scope.spawn(move || {
                owner.submit_idempotent_control(&ctx, key, op, Some(CAMERA), approval)
            })
        }).collect();
        handles.into_iter().map(|handle| {
            handle.join().map_err(|_| "control caller panicked")
        }).collect::<Result<Vec<_>, _>>()
    })?;
    let mut admitted = 0;
    let mut ids = Vec::new();
    for response in responses {
        match response {
            IpcResponse::ControlAccepted { operation_id, state: ControlOperationState::Queued, .. } => {
                admitted += 1;
                ids.push(operation_id);
            }
            IpcResponse::ControlReplayed {
                operation_id, progress: ControlProgress::NeverStarted, recovered: false, ..
            } => ids.push(operation_id),
            other => return Err(format!("unexpected concurrent result: {other:?}").into()),
        }
    }
    assert_eq!(admitted, 1);
    assert!(ids.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(owner.shared.queued_control_command_count()?, 1);
    let before = owner.shared.control_history(1)?.ok_or("missing history")?;
    assert_eq!(before.total_entries, 1);
    assert_eq!(before.head.sequence, 2);

    let command = owner.shared.take_control_command()?.ok_or("missing admitted command")?;
    assert_eq!(command.operation_id, ids[0]);
    for progress in [ControlProgress::DispatchStarted, ControlProgress::SubsystemReturned] {
        if progress == ControlProgress::SubsystemReturned {
            owner.shared.record_control_progress(&command.operation_id, progress)?;
        }
        let before = owner.shared.control_history(1)?.ok_or("missing history")?.head;
        assert_eq!(
            owner.submit_idempotent_control(&context()?, key, op, Some(CAMERA), approval),
            IpcResponse::ControlReplayed {
                request_id: context()?.request_id,
                operation_id: command.operation_id.clone(),
                progress,
                recovered: false,
            }
        );
        assert_eq!(owner.shared.control_history(1)?.ok_or("missing history")?.head, before);
    }
    assert_eq!(owner.shared.queued_control_command_count()?, 0);
    Ok(())
}

#[test]
fn keyed_retry_survives_full_queue_and_shutdown_without_admitting_fresh_work() -> Test {
    let journal = DurableControlJournal::from_store(
        scope(),
        Box::new(MemoryStore::new(4_000, None)),
        true,
    )?;
    let owner = handler(journal);
    let ctx = context()?;
    let op = BoundedControlOp::StopCamera;
    let approval = control_op_approval_digest(SITE, op, Some(CAMERA));
    let limit = crate::control::MAX_QUEUED_CONTROL_COMMANDS;
    let key = ContentDigest::sha256(&0_u64.to_be_bytes());
    let mut first = None;
    for index in 0..limit {
        let response = owner.submit_idempotent_control(
            &ctx,
            ContentDigest::sha256(&(index as u64).to_be_bytes()),
            op,
            Some(CAMERA),
            approval,
        );
        let IpcResponse::ControlAccepted { operation_id, .. } = response else {
            return Err(format!("queue refused below capacity: {response:?}").into());
        };
        if index == 0 {
            first = Some(operation_id);
        }
    }
    let operation_id = first.ok_or("missing first operation")?;
    let head = owner.shared.control_history(1)?.ok_or("missing history")?.head;
    assert_eq!(
        owner.submit_idempotent_control(&ctx, key, op, Some(CAMERA), approval),
        IpcResponse::ControlReplayed {
            request_id: ctx.request_id,
            operation_id: operation_id.clone(),
            progress: ControlProgress::NeverStarted,
            recovered: false,
        }
    );
    assert_eq!(owner.shared.control_history(1)?.ok_or("missing history")?.head, head);
    let fresh = ContentDigest::sha256(b"fresh action beyond queue limit");
    assert!(matches!(
        owner.submit_idempotent_control(&ctx, fresh, op, Some(CAMERA), approval),
        IpcResponse::Refused { error_id, .. } if error_id.as_str() == "ERR-BUDGET-EXHAUSTED-001"
    ));
    assert_eq!(owner.shared.queued_control_command_count()?, limit);
    let (cancelled, error) = owner.shared.cancel_unstarted_controls();
    assert!(error.is_none());
    assert_eq!(cancelled.len(), limit);
    let stopped_head = owner.shared.control_history(1)?.ok_or("missing history")?.head;
    assert_eq!(
        owner.submit_idempotent_control(&ctx, key, op, Some(CAMERA), approval),
        IpcResponse::ControlReplayed {
            request_id: ctx.request_id,
            operation_id,
            progress: ControlProgress::CancelledBeforeExecution,
            recovered: false,
        }
    );
    assert!(matches!(
        owner.submit_idempotent_control(&ctx, fresh, op, Some(CAMERA), approval),
        IpcResponse::Refused { error_id, .. }
            if error_id.as_str() == fss_ipc::ERR_IPC_SERVER_SHUTDOWN_001
    ));
    assert_eq!(owner.shared.queued_control_command_count()?, 0);
    assert_eq!(owner.shared.control_history(1)?.ok_or("missing history")?.head, stopped_head);
    Ok(())
}

#[test]
fn keyed_lost_acknowledgements_are_fenced_then_recovered_only_as_inert_receipts() -> Test {
    let ctx = context()?;
    let key = ContentDigest::sha256(b"lost acknowledgement control");
    let op = BoundedControlOp::StopCamera;
    let approval = control_op_approval_digest(SITE, op, Some(CAMERA));
    for failure_record in [2, 3, 4] {
        let mut journal = DurableControlJournal::from_store(
            scope(),
            Box::new(MemoryStore::new(16, Some(failure_record))),
            true,
        )?;
        let admitted = journal.admit_request(&ctx, op, Some(CAMERA), approval, Some(key));
        if failure_record == 2 {
            assert!(admitted.is_err());
        } else {
            let command = admitted?;
            let dispatch = journal.transition(&command.operation_id, ControlProgress::DispatchStarted);
            if failure_record == 3 {
                assert!(dispatch.is_err());
            } else {
                dispatch?;
                assert!(journal.transition(&command.operation_id, ControlProgress::SubsystemReturned).is_err());
            }
        }
        assert!(matches!(
            journal.replay(&ctx, key, op, Some(CAMERA), approval),
            Err(EffectPersistenceError::Poisoned)
        ));
        let DurableControlJournal { scope, store, .. } = journal;
        let mut recovered = DurableControlJournal::from_store(scope, store, false)?;
        let expected = match failure_record {
            2 => ControlProgress::NeverStarted,
            3 => ControlProgress::DispatchStarted,
            _ => ControlProgress::SubsystemReturned,
        };
        let ControlReplayLookup::Match(entry) =
            recovered.replay(&ctx, key, op, Some(CAMERA), approval)?
        else {
            return Err("retained lost-ack request was not found".into());
        };
        assert_eq!(entry.progress, expected);
        assert!(entry.recovered);
        let operation_id = entry.command.operation_id.clone();
        let before = recovered.inspect(1)?.head;
        assert!(recovered.transition(&operation_id, ControlProgress::DispatchStarted).is_err());
        assert_eq!(recovered.inspect(1)?.head, before);
    }
    Ok(())
}

#[test]
fn canonical_history_with_duplicate_key_is_refused_without_choosing_an_operation() -> Test {
    let mut journal =
        DurableControlJournal::from_store(scope(), Box::new(MemoryStore::new(16, None)), true)?;
    let key = ContentDigest::sha256(b"one key");
    let op = BoundedControlOp::StopCamera;
    journal.admit_request(
        &context()?, op, Some(CAMERA),
        control_op_approval_digest(SITE, op, Some(CAMERA)), Some(key),
    )?;
    let mut duplicate = journal.entries[0].clone();
    duplicate.accepted_sequence += 1;
    duplicate.command.operation_id =
        codec::operation_id(&journal.scope, op, duplicate.accepted_sequence)?;
    let bytes = codec::encode(&journal.scope, &codec::Record::Accepted(duplicate))?;
    let DurableControlJournal { scope, mut store, .. } = journal;
    store.append(store.head(), &bytes)?;
    assert!(DurableControlJournal::from_store(scope, store, false).is_err());
    Ok(())
}


#[test]
fn live_keyed_control_reconnect_reuses_receipt_and_refuses_changed_grants() -> Test {
    let root = TempRoot::new()?;
    let journal = DurableControlJournal::open(&root.0, SITE, Arc::new(HostSpoolIo))?;
    let owner = Arc::new(handler(journal));
    let basis = reference_contract_basis();
    let server = fss_ipc::IpcServer::bind(
        fss_ipc::IpcServerConfig::new(&root.0, SITE, basis.basis_digest(), "daemon:keyed-test"),
        owner.clone(),
    )?;
    let ctx = context()?;
    let mut capabilities = ctx.granted_capabilities.clone();
    capabilities.sort();
    capabilities.dedup();
    let config = fss_ipc::IpcClientConfig::from_contract_basis(
        &root.0, SITE, &basis, ctx.principal.clone(), capabilities.clone(),
    );
    let mut first_client = fss_ipc::IpcClient::connect(config)?;
    let key = ContentDigest::sha256(b"live keyed request");
    let op = BoundedControlOp::StopCamera;
    let approval = control_op_approval_digest(SITE, op, Some(CAMERA));
    let response = first_client.submit_idempotent_control(
        101, key, op, Some(CAMERA.to_owned()), approval,
    )?;
    let IpcResponse::ControlAccepted { operation_id, state: ControlOperationState::Queued, .. } = response else {
        return Err(format!("keyed wire intake refused: {response:?}").into());
    };
    drop(first_client);

    capabilities.reverse();
    let mut retry_client = fss_ipc::IpcClient::connect(
        fss_ipc::IpcClientConfig::from_contract_basis(
            &root.0, SITE, &basis, ctx.principal.clone(), capabilities,
        ),
    )?;
    assert_eq!(
        retry_client.submit_idempotent_control(202, key, op, Some(CAMERA.to_owned()), approval)?,
        IpcResponse::ControlReplayed {
            request_id: 202,
            operation_id: operation_id.clone(),
            progress: ControlProgress::NeverStarted,
            recovered: false,
        }
    );
    let mut changed_client = fss_ipc::IpcClient::connect(
        fss_ipc::IpcClientConfig::from_contract_basis(
            &root.0, SITE, &basis, ctx.principal, vec!["CAP-OBSERVE-STATUS-001".to_owned()],
        ),
    )?;
    assert!(matches!(
        changed_client.submit_idempotent_control(303, key, op, Some(CAMERA.to_owned()), approval)?,
        IpcResponse::Refused { error_id, retryable: false, .. }
            if error_id.as_str() == "ERR-IDEMPOTENCY-CONFLICT-001"
    ));
    assert_eq!(owner.shared.queued_control_command_count()?, 1);
    let history = owner.shared.control_history(1)?.ok_or("missing history")?;
    assert_eq!(history.total_entries, 1);
    assert_eq!(history.head.sequence, 2);
    assert_eq!(history.entries[0].command.operation_id, operation_id);
    server.shutdown()?;
    Ok(())
}

#[test]
fn keyed_daemon_shutdown_replays_its_retained_return_boundary_without_new_history() -> Test {
    let journal =
        DurableControlJournal::from_store(scope(), Box::new(MemoryStore::new(16, None)), true)?;
    let owner = handler(journal);
    let ctx = context()?;
    let key = ContentDigest::sha256(b"one shutdown request");
    let op = BoundedControlOp::StopCamera;
    let target = Some(crate::control::DAEMON_STOP_TARGET);
    let approval = owner.shared.expected_stop_approval();
    let first = owner.submit_idempotent_control(&ctx, key, op, target, approval);
    let IpcResponse::ControlAccepted { operation_id, .. } = first else {
        return Err(format!("shutdown not accepted: {first:?}").into());
    };
    assert!(owner.shared.is_shutdown_requested());
    let head = owner.shared.control_history(1)?.ok_or("missing history")?.head;
    assert_eq!(
        owner.submit_idempotent_control(&ctx, key, op, target, approval),
        IpcResponse::ControlReplayed {
            request_id: ctx.request_id,
            operation_id,
            progress: ControlProgress::SubsystemReturned,
            recovered: false,
        }
    );
    assert_eq!(owner.shared.control_history(1)?.ok_or("missing history")?.head, head);
    assert_eq!(owner.shared.queued_control_command_count()?, 0);
    Ok(())
}
