#![forbid(unsafe_code)]
//! Contract tests for committing durable root reachability to the canonical ledger (FSS-018 plan
//! step 9, fss-x4a.7.6).
//!
//! Ordering under test: the root is made disk-durable first, then its reachability is committed as
//! one `EvidenceDeltaBatch`. A durable root that is not in the ledger is an explicit
//! `PendingLedger` state, never silent, and a retry never appends a second batch.
//!
//! Every test owns one real directory under `CARGO_TARGET_TMPDIR`, named after the test. Each
//! scenario emits one bounded, secret-free structured log line.

use std::error::Error;
use std::fmt::Debug;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, ContractError, EvidenceDelta, EvidenceDeltaBatch,
    ObjectId, Plane, TimestampNs,
};
use fss_ledger::{
    AppendPhase, DurableAppendReconciliation, DurableLedgerError, DurableReferenceLedger,
    IncompleteTailPolicy, LedgerOracle, ObjectRead, OracleLimits, encode_batch,
};
use fss_object::{ObjectManifest, SpoolLimits};
use fss_publication::{
    InjectedIoFault, IoFaultPoint, LOCAL_ROOTS_DIR, LedgerCutPoint, LedgeredRootPublisher,
    LocalPublicationError, LocalPublicationLimits, LocalPublicationState, LocalRootPublisher,
    MAX_LEDGERED_SLOT_BYTES, PublicationError, ROOT_LEDGER_ERROR_CODES, ROOT_REACHABILITY_FAMILY,
    ROOT_RECORD_SUFFIX, RootLedgerError, RootLedgerGuidance, RootLedgerOutcome, RootLedgerState,
    SlotName, root_reachability_batch_id, root_reachability_object_id,
};

type TestResult = Result<(), Box<dyn Error>>;

const SEED: u64 = 0x0018_7009;
const LINEAGE: &str = "site:one";

struct Paths {
    publication: PathBuf,
    journal: PathBuf,
}

/// Returns fresh, not-yet-existing paths owned by exactly one test.
fn fresh(test_name: &str) -> Result<Paths, Box<dyn Error>> {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("root_ledger_linkage_contract")
        .join(test_name);
    match fs::remove_dir_all(&base) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    fs::create_dir_all(&base)?;
    Ok(Paths {
        publication: base.join("publication"),
        journal: base.join("ledger.journal"),
    })
}

fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(8, 16, 8, 64, SpoolLimits::new(64, 1 << 20, 4096, 64))
}

fn open_ledger(path: &Path) -> Result<DurableReferenceLedger, Box<dyn Error>> {
    Ok(DurableReferenceLedger::open(
        path,
        LINEAGE,
        IncompleteTailPolicy::Reject,
    )?)
}

fn validity() -> Result<CaptureInterval, Box<dyn Error>> {
    Ok(CaptureInterval::new(
        TimestampNs(1_000),
        TimestampNs(2_000),
    )?)
}

fn slot(name: &str) -> Result<SlotName, Box<dyn Error>> {
    Ok(SlotName::parse(name)?)
}

fn expect_err<T: Debug>(
    result: Result<T, RootLedgerError>,
) -> Result<RootLedgerError, Box<dyn Error>> {
    match result {
        Ok(value) => Err(format!("expected a root-ledger error, got {value:?}").into()),
        Err(error) => Ok(error),
    }
}

fn log_scenario(scenario: &str, detail: &str) {
    eprintln!(
        "{{\"suite\":\"root_ledger_linkage_contract\",\"scenario\":\"{scenario}\",\"seed\":{SEED},\"lineage\":\"{LINEAGE}\",\"detail\":\"{detail}\",\"repro\":\"cargo +nightly-2026-08-31 test -p fss-publication --test root_ledger_linkage_contract {scenario}\"}}"
    );
}

/// Two leaf children plus typed metadata, staged and verified in the spool.
fn event_manifest(publisher: &mut LocalRootPublisher) -> Result<ObjectManifest, Box<dyn Error>> {
    let first = publisher.stage_object(b"clip-segment-0001")?;
    let second = publisher.stage_object(b"clip-segment-0002")?;
    let metadata = publisher.stage_object(b"event-metadata-v1")?;
    Ok(ObjectManifest::new(
        "event_archive",
        [first, second],
        Some(metadata),
    )?)
}

/// A foreign authority batch appended directly to the ledger, bypassing the coordinator.
fn foreign_batch(
    ledger: &DurableReferenceLedger,
    batch_id: &str,
    object_id: ObjectId,
    family: &str,
    payload: ContentDigest,
) -> Result<EvidenceDeltaBatch, Box<dyn Error>> {
    let delta = EvidenceDelta {
        delta_id: format!("delta:foreign:{batch_id}"),
        family: family.to_owned(),
        object_id,
        prior_generation: None,
        new_generation: 1,
        validity: validity()?,
        plane: Plane::Authority,
        payload_digest: payload,
        witness_digest: None,
        operation_id: None,
    };
    Ok(ledger.prepare_batch(BatchId::parse(batch_id)?, vec![delta], [])?)
}

fn pending_root(state: &RootLedgerState) -> Option<ContentDigest> {
    match state {
        RootLedgerState::PendingLedger(pending) => Some(pending.root),
        _ => None,
    }
}

#[test]
fn publish_then_ledger_shows_root_at_next_anchor() -> TestResult {
    let paths = fresh("publish_then_ledger_shows_root_at_next_anchor")?;
    let mut local = LocalRootPublisher::open(&paths.publication, limits())?;
    let manifest = event_manifest(&mut local)?;
    let mut ledger = open_ledger(&paths.journal)?;
    let slot = slot("event-0001")?;
    let before = ledger.current().anchor.clone();

    let receipt = {
        let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
        assert_eq!(coordinator.state(&slot)?, RootLedgerState::Absent);
        coordinator.publish_and_commit(&slot, &manifest, validity()?)?
    };

    assert_eq!(receipt.outcome, RootLedgerOutcome::Committed);
    assert_eq!(receipt.root, manifest.root());
    assert_eq!(receipt.slot, slot);
    assert_eq!(receipt.anchor.commit_sequence, before.commit_sequence + 1);
    assert_eq!(receipt.anchor, ledger.current().anchor);
    assert_eq!(receipt.batch_id, root_reachability_batch_id(&slot)?);
    // The closure summary is the root plus its three direct children.
    assert_eq!(receipt.closure_object_count, 4);

    let object_id = root_reachability_object_id(&slot)?;
    let revision = ledger
        .current()
        .objects
        .get(&object_id)
        .ok_or("ledger does not show the root reachability object")?;
    assert_eq!(revision.payload_digest, manifest.root());
    assert_eq!(revision.family, ROOT_REACHABILITY_FAMILY);
    assert_eq!(revision.plane, Plane::Authority);
    assert_eq!(revision.generation, 1);

    assert_eq!(ledger.batches().len(), 1);
    let batch = &ledger.batches()[0];
    assert_eq!(batch.basis_anchor, before);
    let mut expected_children = manifest.children().to_vec();
    expected_children.sort_unstable();
    assert_eq!(batch.children, expected_children);
    assert_eq!(batch.deltas.len(), 1);
    assert_eq!(batch.deltas[0].payload_digest, manifest.root());

    assert_eq!(
        local.root(&slot).map(|root| root.state),
        Some(LocalPublicationState::Durable)
    );
    {
        let coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
        assert!(matches!(
            coordinator.state(&slot)?,
            RootLedgerState::Ledgered { root, ref anchor, .. }
                if root == manifest.root() && anchor.commit_sequence == 1
        ));
        assert!(coordinator.reconcile()?.is_clean());
    }
    log_scenario(
        "publish_then_ledger_shows_root_at_next_anchor",
        "durable root committed at sequence 1",
    );
    Ok(())
}

#[test]
fn crash_after_durable_before_ledger_commit_is_pending_then_reconciles_once() -> TestResult {
    let paths = fresh("crash_after_durable_before_ledger_commit")?;
    let slot = slot("event-0001")?;
    let root;
    {
        let mut local = LocalRootPublisher::open(&paths.publication, limits())?;
        let manifest = event_manifest(&mut local)?;
        root = manifest.root();
        let mut ledger = open_ledger(&paths.journal)?;
        {
            let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
            coordinator.inject_crash_at(LedgerCutPoint::AfterRootDurable);
            let error = expect_err(coordinator.publish_and_commit(&slot, &manifest, validity()?))?;
            assert!(matches!(
                error,
                RootLedgerError::InjectedCrash {
                    point: LedgerCutPoint::AfterRootDurable
                }
            ));
            assert_eq!(error.guidance(), RootLedgerGuidance::ReopenAndReconcile);
            // The dead instance refuses to commit anything.
            let refused = expect_err(coordinator.commit_root(&slot, validity()?))?;
            assert!(matches!(
                refused,
                RootLedgerError::Local(LocalPublicationError::Poisoned)
            ));
        }
        assert!(local.is_poisoned());
        assert_eq!(
            local.root(&slot).map(|visible| visible.state),
            Some(LocalPublicationState::Durable)
        );
        assert!(ledger.batches().is_empty());
    }

    // Reopen both owners: the durable root is explicitly pending, never silently ledgered.
    let mut local = LocalRootPublisher::open(&paths.publication, limits())?;
    let mut ledger = open_ledger(&paths.journal)?;
    assert!(ledger.batches().is_empty());
    {
        let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
        let state = coordinator.state(&slot)?;
        assert_eq!(pending_root(&state), Some(root));
        let report = coordinator.reconcile()?;
        assert!(!report.is_clean());
        assert_eq!(report.pending.len(), 1);
        assert_eq!(report.pending[0].slot, slot);
        assert_eq!(report.pending[0].root, root);
        assert_eq!(report.pending[0].closure_object_count, 4);
        assert!(report.ledgered.is_empty());

        let committed = coordinator.commit_root(&slot, validity()?)?;
        assert_eq!(committed.outcome, RootLedgerOutcome::Committed);
        assert_eq!(committed.anchor.commit_sequence, 1);

        // A second retry is idempotent: no duplicate batch, same anchor.
        let retried = coordinator.commit_root(&slot, validity()?)?;
        assert_eq!(retried.outcome, RootLedgerOutcome::AlreadyLedgered);
        assert_eq!(retried.anchor, committed.anchor);
        assert_eq!(retried.batch_id, committed.batch_id);
        assert!(coordinator.reconcile()?.is_clean());
    }
    assert_eq!(ledger.batches().len(), 1);
    drop(ledger);

    let reopened = open_ledger(&paths.journal)?;
    assert_eq!(reopened.batches().len(), 1);
    assert_eq!(reopened.batches()[0].deltas[0].payload_digest, root);
    log_scenario(
        "crash_after_durable_before_ledger_commit_is_pending_then_reconciles_once",
        "pending after reopen, one batch after two retries",
    );
    Ok(())
}

#[test]
fn indeterminate_append_that_committed_is_never_reappended() -> TestResult {
    let paths = fresh("indeterminate_append_that_committed")?;
    let slot = slot("event-0001")?;
    let root;
    {
        let mut local = LocalRootPublisher::open(&paths.publication, limits())?;
        let manifest = event_manifest(&mut local)?;
        root = manifest.root();
        let mut ledger = open_ledger(&paths.journal)?;
        ledger.fail_journal_after_phase(AppendPhase::CommitSync);
        let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
        let error = expect_err(coordinator.publish_and_commit(&slot, &manifest, validity()?))?;
        match &error {
            RootLedgerError::LedgerIndeterminate { pending, sequence } => {
                assert_eq!(pending.root, root);
                assert_eq!(*sequence, 1);
            }
            other => return Err(format!("expected LedgerIndeterminate, got {other:?}").into()),
        }
        assert_eq!(error.guidance(), RootLedgerGuidance::ReconcileLedgerAppend);
        // Until the append is reconciled, no further commit is attempted.
        let blocked = expect_err(coordinator.commit_root(&slot, validity()?))?;
        assert!(matches!(
            blocked,
            RootLedgerError::LedgerReconciliationRequired { sequence: 1 }
        ));
        // Simulated process death: nothing is reconciled in this process.
    }

    let mut local = LocalRootPublisher::open(&paths.publication, limits())?;
    let mut ledger = open_ledger(&paths.journal)?;
    assert_eq!(ledger.batches().len(), 1);
    {
        let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
        assert!(matches!(
            coordinator.state(&slot)?,
            RootLedgerState::Ledgered { root: found, .. } if found == root
        ));
        let retried = coordinator.commit_root(&slot, validity()?)?;
        assert_eq!(retried.outcome, RootLedgerOutcome::AlreadyLedgered);
        assert_eq!(retried.anchor.commit_sequence, 1);
    }
    assert_eq!(ledger.batches().len(), 1);
    log_scenario(
        "indeterminate_append_that_committed_is_never_reappended",
        "commit_sync fault; reopen shows ledgered; retry appends nothing",
    );
    Ok(())
}

#[test]
fn indeterminate_append_reconciled_in_process_resolves_state() -> TestResult {
    let paths = fresh("indeterminate_append_reconciled_in_process")?;
    let slot = slot("event-0001")?;
    let mut local = LocalRootPublisher::open(&paths.publication, limits())?;
    let manifest = event_manifest(&mut local)?;
    let mut ledger = open_ledger(&paths.journal)?;
    ledger.fail_journal_after_phase(AppendPhase::CommitSync);
    {
        let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
        let error = expect_err(coordinator.publish_and_commit(&slot, &manifest, validity()?))?;
        assert!(matches!(error, RootLedgerError::LedgerIndeterminate { .. }));
        assert!(matches!(
            expect_err(coordinator.state(&slot))?,
            RootLedgerError::LedgerReconciliationRequired { sequence: 1 }
        ));
        let reconciliation = coordinator.reconcile_ledger_append(IncompleteTailPolicy::Reject)?;
        assert_eq!(
            reconciliation,
            DurableAppendReconciliation::Committed {
                sequence: 1,
                batch_id: root_reachability_batch_id(&slot)?,
            }
        );
        assert!(matches!(
            coordinator.state(&slot)?,
            RootLedgerState::Ledgered { root, .. } if root == manifest.root()
        ));
        let retried = coordinator.commit_root(&slot, validity()?)?;
        assert_eq!(retried.outcome, RootLedgerOutcome::AlreadyLedgered);
    }
    assert_eq!(ledger.batches().len(), 1);
    log_scenario(
        "indeterminate_append_reconciled_in_process_resolves_state",
        "reconciled committed; retry appends nothing",
    );
    Ok(())
}

#[test]
fn indeterminate_append_that_did_not_commit_is_pending_after_reopen() -> TestResult {
    let paths = fresh("indeterminate_append_not_committed")?;
    let slot = slot("event-0001")?;
    let root;
    {
        let mut local = LocalRootPublisher::open(&paths.publication, limits())?;
        let manifest = event_manifest(&mut local)?;
        root = manifest.root();
        let mut ledger = open_ledger(&paths.journal)?;
        ledger.fail_journal_after_phase(AppendPhase::BodyWrite);
        let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
        let error = expect_err(coordinator.publish_and_commit(&slot, &manifest, validity()?))?;
        assert!(matches!(error, RootLedgerError::LedgerIndeterminate { .. }));
    }

    let mut local = LocalRootPublisher::open(&paths.publication, limits())?;
    let mut ledger =
        DurableReferenceLedger::open(&paths.journal, LINEAGE, IncompleteTailPolicy::Truncate)?;
    assert!(ledger.batches().is_empty());
    {
        let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
        assert_eq!(pending_root(&coordinator.state(&slot)?), Some(root));
        let committed = coordinator.commit_root(&slot, validity()?)?;
        assert_eq!(committed.outcome, RootLedgerOutcome::Committed);
        assert_eq!(committed.anchor.commit_sequence, 1);
    }
    assert_eq!(ledger.batches().len(), 1);
    log_scenario(
        "indeterminate_append_that_did_not_commit_is_pending_after_reopen",
        "body_write fault; reopen shows pending; one commit",
    );
    Ok(())
}

#[test]
fn stale_anchor_rejection_leaves_root_durable_unledgered() -> TestResult {
    let paths = fresh("stale_anchor_rejection")?;
    let slot = slot("event-0001")?;
    let mut local = LocalRootPublisher::open(&paths.publication, limits())?;
    let manifest = event_manifest(&mut local)?;
    let mut ledger = open_ledger(&paths.journal)?;
    local.publish(&slot, &manifest)?;

    let prepared = {
        let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
        coordinator.prepare_root_batch(&slot, validity()?)?
    };
    // Another authority writer advances the head between prepare and commit.
    let foreign = foreign_batch(
        &ledger,
        "batch:foreign:1",
        ObjectId::parse("object:foreign:1")?,
        "sensor_capsule",
        ContentDigest::sha256(b"foreign"),
    )?;
    ledger.append(foreign)?;

    {
        let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
        let error = expect_err(coordinator.commit_prepared(&slot, prepared))?;
        match &error {
            RootLedgerError::DurableUnledgered { pending, cause } => {
                assert_eq!(pending.root, manifest.root());
                assert_eq!(pending.slot, slot);
                assert!(matches!(
                    cause.as_ref(),
                    PublicationError::Ledger(DurableLedgerError::Contract(
                        ContractError::StaleAnchor
                    ))
                ));
            }
            other => return Err(format!("expected DurableUnledgered, got {other:?}").into()),
        }
        assert_eq!(error.code(), "ERR-PUBLICATION-LEDGER-UNLEDGERED-001");
        assert_eq!(error.guidance(), RootLedgerGuidance::RetryLedgerCommit);
        // The root stays durable and is explicitly pending.
        assert_eq!(
            pending_root(&coordinator.state(&slot)?),
            Some(manifest.root())
        );

        // Retrying against the current head commits exactly once.
        let committed = coordinator.commit_root(&slot, validity()?)?;
        assert_eq!(committed.outcome, RootLedgerOutcome::Committed);
        assert_eq!(committed.anchor.commit_sequence, 2);
    }
    assert_eq!(
        local.root(&slot).map(|root| root.state),
        Some(LocalPublicationState::Durable)
    );
    assert_eq!(ledger.batches().len(), 2);
    log_scenario(
        "stale_anchor_rejection_leaves_root_durable_unledgered",
        "stale prepared batch refused; rebased commit at sequence 2",
    );
    Ok(())
}

#[test]
fn batch_id_conflict_rejection_leaves_root_durable_unledgered() -> TestResult {
    let paths = fresh("batch_id_conflict_rejection")?;
    let slot = slot("event-0001")?;
    let mut local = LocalRootPublisher::open(&paths.publication, limits())?;
    let manifest = event_manifest(&mut local)?;
    let mut ledger = open_ledger(&paths.journal)?;
    // A foreign writer already used the deterministic batch identity for different content.
    let foreign = foreign_batch(
        &ledger,
        root_reachability_batch_id(&slot)?.as_str(),
        ObjectId::parse("object:foreign:1")?,
        "sensor_capsule",
        ContentDigest::sha256(b"foreign"),
    )?;
    ledger.append(foreign)?;
    let journal_before = fs::read(&paths.journal)?;

    {
        let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
        let error = expect_err(coordinator.publish_and_commit(&slot, &manifest, validity()?))?;
        match &error {
            RootLedgerError::DurableUnledgered { pending, cause } => {
                assert_eq!(pending.root, manifest.root());
                assert!(matches!(
                    cause.as_ref(),
                    PublicationError::DuplicateBatchId(_)
                ));
            }
            other => return Err(format!("expected DurableUnledgered, got {other:?}").into()),
        }
        assert_eq!(error.guidance(), RootLedgerGuidance::RepairLedgerIdentity);
        assert_eq!(
            pending_root(&coordinator.state(&slot)?),
            Some(manifest.root())
        );
    }
    assert_eq!(
        local.root(&slot).map(|root| root.state),
        Some(LocalPublicationState::Durable)
    );
    assert_eq!(fs::read(&paths.journal)?, journal_before);
    assert_eq!(ledger.batches().len(), 1);
    log_scenario(
        "batch_id_conflict_rejection_leaves_root_durable_unledgered",
        "reused batch id refused before journal I/O",
    );
    Ok(())
}

#[test]
fn ledger_slot_conflict_is_typed_and_appends_nothing() -> TestResult {
    let paths = fresh("ledger_slot_conflict")?;
    let durable_slot = slot("event-0001")?;
    let unpublished_slot = slot("event-0002")?;
    let mut local = LocalRootPublisher::open(&paths.publication, limits())?;
    let manifest = event_manifest(&mut local)?;
    let mut ledger = open_ledger(&paths.journal)?;
    let other_root = ContentDigest::sha256(b"another publication directory's root");
    // The root is durable first; foreign claims for both slots then land in the ledger.
    local.publish(&durable_slot, &manifest)?;
    for (batch_id, claimed) in [
        ("batch:foreign:claim-1", &durable_slot),
        ("batch:foreign:claim-2", &unpublished_slot),
    ] {
        let foreign = foreign_batch(
            &ledger,
            batch_id,
            root_reachability_object_id(claimed)?,
            ROOT_REACHABILITY_FAMILY,
            other_root,
        )?;
        ledger.append(foreign)?;
    }
    let journal_before = fs::read(&paths.journal)?;

    {
        let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
        let error = expect_err(coordinator.commit_root(&durable_slot, validity()?))?;
        assert!(matches!(
            error,
            RootLedgerError::LedgerConflict { ref slot, local_root, ledgered_root }
                if *slot == durable_slot
                    && local_root == manifest.root()
                    && ledgered_root == other_root
        ));
        assert_eq!(error.code(), "ERR-PUBLICATION-LEDGER-CONFLICT-001");
        assert_eq!(error.guidance(), RootLedgerGuidance::RepairLedgerIdentity);
        assert!(matches!(
            coordinator.state(&durable_slot)?,
            RootLedgerState::LedgerConflict { durable_root, ledgered_root, .. }
                if durable_root == manifest.root() && ledgered_root == other_root
        ));

        // A slot the ledger already assigns to another root is refused before any disk mutation.
        let refused =
            expect_err(coordinator.publish_and_commit(&unpublished_slot, &manifest, validity()?))?;
        assert!(matches!(
            refused,
            RootLedgerError::LedgerConflict { local_root, ledgered_root, .. }
                if local_root == manifest.root() && ledgered_root == other_root
        ));
        assert!(matches!(
            coordinator.state(&unpublished_slot)?,
            RootLedgerState::LedgerWithoutDurableRoot { ledgered_root } if ledgered_root == other_root
        ));

        let report = coordinator.reconcile()?;
        assert!(!report.is_clean());
        assert_eq!(report.conflicts.len(), 1);
        assert_eq!(report.conflicts[0].slot, durable_slot);
        assert_eq!(report.unbacked_ledger_claims.len(), 1);
        assert_eq!(
            report.unbacked_ledger_claims[0].slot.as_ref(),
            Some(&unpublished_slot)
        );
    }
    assert!(local.root(&unpublished_slot).is_none());
    assert_eq!(fs::read(&paths.journal)?, journal_before);
    assert_eq!(ledger.batches().len(), 2);
    log_scenario(
        "ledger_slot_conflict_is_typed_and_appends_nothing",
        "ledger names another root; durable conflict reported, unpublished slot refused before disk",
    );
    Ok(())
}

#[test]
fn directory_fsync_failure_never_reaches_the_ledger() -> TestResult {
    let paths = fresh("directory_fsync_failure_never_reaches_ledger")?;
    let slot = slot("event-0001")?;
    let root;
    {
        let mut local = LocalRootPublisher::open_with_injected_io_fault(
            &paths.publication,
            limits(),
            InjectedIoFault::new(IoFaultPoint::RootDirectorySync, ErrorKind::Other),
        )?;
        let manifest = event_manifest(&mut local)?;
        root = manifest.root();
        let mut ledger = open_ledger(&paths.journal)?;
        {
            let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
            let error = expect_err(coordinator.publish_and_commit(&slot, &manifest, validity()?))?;
            assert!(matches!(
                error,
                RootLedgerError::Local(LocalPublicationError::Indeterminate { .. })
            ));
            assert!(matches!(
                coordinator.state(&slot)?,
                RootLedgerState::VisibleNotDurable { root: found } if found == root
            ));
            let refused = expect_err(coordinator.commit_root(&slot, validity()?))?;
            assert!(matches!(
                refused,
                RootLedgerError::Local(LocalPublicationError::Poisoned)
            ));
        }
        assert!(ledger.batches().is_empty());
    }
    let mut local = LocalRootPublisher::open(&paths.publication, limits())?;
    let mut ledger = open_ledger(&paths.journal)?;
    let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
    assert_eq!(pending_root(&coordinator.state(&slot)?), Some(root));
    assert_eq!(
        coordinator.commit_root(&slot, validity()?)?.outcome,
        RootLedgerOutcome::Committed
    );
    log_scenario(
        "directory_fsync_failure_never_reaches_the_ledger",
        "visible-not-durable root never ledgered; pending after reopen",
    );
    Ok(())
}

#[test]
fn ledger_claim_without_durable_root_is_reported_explicitly() -> TestResult {
    let paths = fresh("ledger_claim_without_durable_root")?;
    let slot = slot("event-0001")?;
    let root;
    {
        let mut local = LocalRootPublisher::open(&paths.publication, limits())?;
        let manifest = event_manifest(&mut local)?;
        root = manifest.root();
        let mut ledger = open_ledger(&paths.journal)?;
        let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
        coordinator.publish_and_commit(&slot, &manifest, validity()?)?;
    }
    // External damage after the commit: the root record no longer verifies.
    let record = paths
        .publication
        .join(LOCAL_ROOTS_DIR)
        .join(format!("{slot}{ROOT_RECORD_SUFFIX}"));
    let mut bytes = fs::read(&record)?;
    let last = bytes.last_mut().ok_or("empty root record")?;
    *last ^= 0x01;
    fs::write(&record, bytes)?;

    let mut local = LocalRootPublisher::open(&paths.publication, limits())?;
    let mut ledger = open_ledger(&paths.journal)?;
    let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
    let report = coordinator.reconcile()?;
    assert!(!report.is_clean());
    assert_eq!(report.unbacked_ledger_claims.len(), 1);
    let claim = &report.unbacked_ledger_claims[0];
    assert_eq!(claim.slot.as_ref(), Some(&slot));
    assert_eq!(claim.ledgered_root, root);
    assert_eq!(claim.object_id, root_reachability_object_id(&slot)?);
    assert!(matches!(
        coordinator.state(&slot)?,
        RootLedgerState::LedgerWithoutDurableRoot { ledgered_root } if ledgered_root == root
    ));
    let refused = expect_err(coordinator.commit_root(&slot, validity()?))?;
    assert!(matches!(refused, RootLedgerError::NotDurable { .. }));
    log_scenario(
        "ledger_claim_without_durable_root_is_reported_explicitly",
        "broken record after commit surfaces as an unbacked claim",
    );
    Ok(())
}

#[test]
fn committed_batches_agree_with_ledger_oracle() -> TestResult {
    let paths = fresh("committed_batches_agree_with_ledger_oracle")?;
    let mut local = LocalRootPublisher::open(&paths.publication, limits())?;
    let mut ledger = open_ledger(&paths.journal)?;
    let leaf_manifest = event_manifest(&mut local)?;
    let leaf_slot = slot("event-0001")?;
    let extra = local.stage_object(b"clip-segment-0003")?;
    let parent_slot = slot("case-0001")?;

    let mut committed = Vec::new();
    for (slot, manifest) in [
        (leaf_slot.clone(), leaf_manifest.clone()),
        (
            parent_slot.clone(),
            ObjectManifest::new("case_bundle", [leaf_manifest.root(), extra], None)?,
        ),
    ] {
        local.publish(&slot, &manifest)?;
        let mut oracle =
            LedgerOracle::rebuild(LINEAGE, OracleLimits::CEILING, ledger.batches().to_vec())?;
        let prepared = {
            let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
            coordinator.prepare_root_batch(&slot, validity()?)?
        };
        // The oracle's independent state-root algebra prepares the identical batch.
        let expected = oracle.prepare_batch(
            prepared.batch_id.clone(),
            prepared.deltas.clone(),
            prepared.children.iter().copied(),
        )?;
        assert_eq!(expected, prepared);
        let receipt = {
            let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
            coordinator.commit_prepared(&slot, prepared.clone())?
        };
        let oracle_receipt = oracle.append(prepared)?;
        assert_eq!(oracle_receipt.anchor, receipt.anchor);
        assert_eq!(oracle_receipt.anchor, ledger.current().anchor);
        let view = oracle.view_at(receipt.anchor.commit_sequence)?;
        match view.object(&root_reachability_object_id(&slot)?) {
            ObjectRead::Present {
                revision,
                committed_sequence,
            } => {
                assert_eq!(revision.payload_digest, manifest.root());
                assert_eq!(committed_sequence, receipt.anchor.commit_sequence);
            }
            ObjectRead::AbsentAtAnchor { .. } => {
                return Err("oracle does not show the committed root".into());
            }
        }
        committed.push((slot, manifest, receipt));
    }

    // The parent's closure summary descends into the visible leaf root.
    let (_, parent_manifest, parent_receipt) = &committed[1];
    assert_eq!(parent_receipt.closure_object_count, 6);
    let parent_batch = &ledger.batches()[1];
    assert_eq!(parent_batch.children.len(), 5);
    assert!(parent_batch.children.contains(&leaf_manifest.root()));
    for child in leaf_manifest.children() {
        assert!(parent_batch.children.contains(child));
    }
    assert!(!parent_batch.children.contains(&parent_manifest.root()));

    let oracle = LedgerOracle::rebuild(LINEAGE, OracleLimits::CEILING, ledger.batches().to_vec())?;
    assert_eq!(oracle.fingerprint().head_anchor, ledger.current().anchor);
    assert_eq!(oracle.batch_count(), 2);
    assert_eq!(oracle.view_at(2)?.snapshot(), *ledger.current());
    log_scenario(
        "committed_batches_agree_with_ledger_oracle",
        "two roots, nested closure; oracle prepare/append/rebuild agree",
    );
    Ok(())
}

#[test]
fn batch_bytes_are_deterministic_for_same_inputs() -> TestResult {
    let mut encoded = Vec::new();
    for name in ["deterministic_batch_a", "deterministic_batch_b"] {
        let paths = fresh(name)?;
        let slot = slot("event-0001")?;
        let mut local = LocalRootPublisher::open(&paths.publication, limits())?;
        let manifest = event_manifest(&mut local)?;
        let mut ledger = open_ledger(&paths.journal)?;
        local.publish(&slot, &manifest)?;
        let (first, second) = {
            let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
            (
                coordinator.prepare_root_batch(&slot, validity()?)?,
                coordinator.prepare_root_batch(&slot, validity()?)?,
            )
        };
        assert_eq!(encode_batch(&first)?, encode_batch(&second)?);
        {
            let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
            coordinator.commit_prepared(&slot, first.clone())?;
        }
        assert_eq!(ledger.batches(), [first.clone()].as_slice());
        encoded.push((
            encode_batch(&first)?,
            first.batch_digest,
            fs::read(&paths.journal)?,
        ));
    }
    assert_eq!(encoded[0].0, encoded[1].0);
    assert_eq!(encoded[0].1, encoded[1].1);
    assert_eq!(encoded[0].2, encoded[1].2);

    // A different validity interval is a different batch.
    let paths = fresh("deterministic_batch_c")?;
    let slot = slot("event-0001")?;
    let mut local = LocalRootPublisher::open(&paths.publication, limits())?;
    let manifest = event_manifest(&mut local)?;
    let mut ledger = open_ledger(&paths.journal)?;
    local.publish(&slot, &manifest)?;
    let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
    let shifted = coordinator.prepare_root_batch(
        &slot,
        CaptureInterval::new(TimestampNs(1_000), TimestampNs(2_001))?,
    )?;
    assert_ne!(encode_batch(&shifted)?, encoded[0].0);
    log_scenario(
        "batch_bytes_are_deterministic_for_same_inputs",
        "identical bytes across two directories and two prepares",
    );
    Ok(())
}

#[test]
fn ledger_identity_bound_is_typed_and_checked_before_io() -> TestResult {
    let fits = slot(&"a".repeat(MAX_LEDGERED_SLOT_BYTES))?;
    assert!(root_reachability_object_id(&fits)?.len() <= 128);
    assert!(root_reachability_batch_id(&fits)?.len() <= 128);
    let too_long = slot(&"a".repeat(MAX_LEDGERED_SLOT_BYTES + 1))?;
    assert!(matches!(
        root_reachability_object_id(&too_long),
        Err(RootLedgerError::SlotNotLedgerable { length, maximum, .. })
            if length == MAX_LEDGERED_SLOT_BYTES + 1 && maximum == MAX_LEDGERED_SLOT_BYTES
    ));

    let paths = fresh("ledger_identity_bound")?;
    let mut local = LocalRootPublisher::open(&paths.publication, limits())?;
    let manifest = event_manifest(&mut local)?;
    let mut ledger = open_ledger(&paths.journal)?;
    {
        let mut coordinator = LedgeredRootPublisher::new(&mut local, &mut ledger);
        let error = expect_err(coordinator.publish_and_commit(&too_long, &manifest, validity()?))?;
        assert!(matches!(error, RootLedgerError::SlotNotLedgerable { .. }));
        assert_eq!(error.guidance(), RootLedgerGuidance::RejectInput);
    }
    // Refused before the disk publication, so nothing is durable-but-unledgerable.
    assert!(local.root(&too_long).is_none());
    assert!(ledger.batches().is_empty());
    log_scenario(
        "ledger_identity_bound_is_typed_and_checked_before_io",
        "slot above ledger identity bound refused before any publication",
    );
    Ok(())
}

#[test]
fn every_root_ledger_error_code_is_registered() -> TestResult {
    let registry = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../registries/ERRORS.md"),
    )?;
    for code in ROOT_LEDGER_ERROR_CODES {
        assert!(
            registry.contains(&format!("| `{code}` |")),
            "{code} is not registered in registries/ERRORS.md"
        );
    }
    Ok(())
}
