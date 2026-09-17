use std::error::Error;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BudgetVector, Completeness, HydrationArtifact, HydrationLevel, HydrationPurpose,
    HydrationRequestSpec,
};
use fss_ledger::AppendPhase;

use super::*;
use super::super::tests::{basis, params, register};

type TestResult = Result<(), Box<dyn Error>>;
static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

// Retain uniquely owned fault-test journals for inspection; never delete an existing path.
fn unused_path() -> Result<PathBuf, Box<dyn Error>> {
    for _ in 0..128 {
        let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("fss-session-{}-{serial}.journal", std::process::id()));
        if !path.exists() { return Ok(path); }
    }
    Err("test journal path capacity exhausted".into())
}

fn opened() -> Result<(DurableSessionStore, AgentSession), Box<dyn Error>> {
    let mut store = DurableSessionStore::create(unused_path()?, DurableSessionLimits::default())?;
    let session = store.open(params()?, basis(), TimestampNs(10))?;
    Ok((store, session))
}

#[test]
fn restart_retains_closed_identity_and_original_opening_parameters() -> TestResult {
    let (mut store, session) = opened()?;
    store.close(&session.principal_id, &session.session_id, TimestampNs(20))?;
    let root = store.committed_root();
    let path = store.path().to_path_buf();
    drop(store);
    let mut restored = DurableSessionStore::open_existing(path, root, DurableSessionLimits::default())?;
    assert!(matches!(restored.open(params()?, basis(), TimestampNs(30)),
        Err(DurableSessionError::Session(ReferenceSessionError::Unavailable))));
    Ok(())
}

#[test]
fn failed_expiry_read_is_committed_before_the_refusal() -> TestResult {
    let (mut store, session) = opened()?;
    let old = store.committed_root();
    assert!(matches!(store.session(&session.principal_id, &session.session_id, TimestampNs(1_000)),
        Err(DurableSessionError::Session(ReferenceSessionError::Unavailable))));
    assert_ne!(store.committed_root(), old);
    let path = store.path().to_path_buf();
    let root = store.committed_root();
    drop(store);
    let mut store = DurableSessionStore::open_existing(path, root, DurableSessionLimits::default())?;
    assert!(matches!(store.open(params()?, basis(), TimestampNs(10)),
        Err(DurableSessionError::Session(ReferenceSessionError::Unavailable))));
    Ok(())
}

#[test]
fn exact_retry_and_same_time_read_do_not_append() -> TestResult {
    let (mut store, session) = opened()?;
    let before = store.verify_storage()?;
    assert_eq!(store.open(params()?, basis(), TimestampNs(10))?, session);
    assert_eq!(store.session(&session.principal_id, &session.session_id, TimestampNs(10))?, session);
    assert_eq!(store.verify_storage()?, before);
    Ok(())
}

#[test]
fn every_append_phase_fences_until_exact_reconciliation() -> TestResult {
    for (phase, committed) in [
        (AppendPhase::BodyWrite, false), (AppendPhase::BodySync, false),
        (AppendPhase::CommitWrite, true), (AppendPhase::CommitSync, true),
    ] {
        let (mut store, session) = opened()?;
        let root = store.committed_root();
        store.journal.fail_after_phase(phase);
        assert!(matches!(store.close(&session.principal_id, &session.session_id, TimestampNs(20)),
            Err(DurableSessionError::Journal(_))));
        assert!(store.needs_reconciliation());
        assert!(matches!(store.session(&session.principal_id, &session.session_id, TimestampNs(21)),
            Err(DurableSessionError::ReconciliationRequired)));
        if !committed {
            let before = std::fs::read(store.path())?;
            assert!(store.reconcile_pending(IncompleteTailPolicy::Reject).is_err());
            assert_eq!(std::fs::read(store.path())?, before);
            assert!(store.needs_reconciliation());
        }
        let outcome = store.reconcile_pending(IncompleteTailPolicy::Truncate)?;
        assert_eq!(outcome, if committed { SessionAppendRecovery::Committed } else { SessionAppendRecovery::NotCommitted });
        assert!(!store.needs_reconciliation());
        assert_eq!(store.committed_root() != root, committed);
        let result = store.session(&session.principal_id, &session.session_id, TimestampNs(21));
        if committed {
            assert!(matches!(result, Err(DurableSessionError::Session(ReferenceSessionError::Unavailable))));
        } else {
            assert!(result.is_ok());
        }
        assert!(store.reconcile_pending(IncompleteTailPolicy::Reject).is_err());
        store.verify_storage()?;
    }
    Ok(())
}

#[test]
fn missing_or_empty_journal_is_never_an_implicit_new_store() -> TestResult {
    let path = unused_path()?;
    assert!(DurableSessionStore::open_existing(&path, ContentDigest::sha256(b"missing"), DurableSessionLimits::default()).is_err());
    assert!(!path.exists());
    OpenOptions::new().write(true).create_new(true).open(&path)?;
    assert!(matches!(DurableSessionStore::inspect(&path, DurableSessionLimits::default()), Err(DurableSessionError::InvalidHistory)));
    Ok(())
}

#[test]
fn create_never_overwrites_and_reopen_rejects_a_stale_tip() -> TestResult {
    let (mut store, session) = opened()?;
    let old = store.committed_root();
    store.close(&session.principal_id, &session.session_id, TimestampNs(20))?;
    let path = store.path().to_path_buf();
    let bytes = std::fs::read(&path)?;
    drop(store);
    assert!(DurableSessionStore::create(&path, DurableSessionLimits::default()).is_err());
    assert_eq!(std::fs::read(&path)?, bytes);
    assert!(matches!(DurableSessionStore::open_existing(&path, old, DurableSessionLimits::default()), Err(DurableSessionError::RootMismatch)));
    Ok(())
}

#[test]
fn reaching_record_capacity_never_acknowledges_or_forgets_a_close() -> TestResult {
    let limits = DurableSessionLimits { max_records: 2, ..DurableSessionLimits::default() };
    let mut store = DurableSessionStore::create(unused_path()?, limits)?;
    let session = store.open(params()?, basis(), TimestampNs(10))?;
    let before = std::fs::read(store.path())?;
    assert!(matches!(store.close(&session.principal_id, &session.session_id, TimestampNs(20)), Err(DurableSessionError::CapacityExceeded)));
    assert!(store.needs_reconciliation());
    assert_eq!(std::fs::read(store.path())?, before);
    assert!(matches!(store.session(&session.principal_id, &session.session_id, TimestampNs(21)), Err(DurableSessionError::ReconciliationRequired)));
    Ok(())
}

#[test]
fn byte_capacity_preflight_and_v1_record_framing_are_exact() -> TestResult {
    let empty = ReferenceSessionStore::default().checkpoint(MAX_SESSION_CHECKPOINT_BYTES)?;
    let exact = empty.as_bytes().len() + RECORD_OVERHEAD_BYTES;
    let path = unused_path()?;
    let too_small = DurableSessionLimits { max_journal_bytes: exact - 1, ..DurableSessionLimits::default() };
    assert!(matches!(DurableSessionStore::create(&path, too_small), Err(DurableSessionError::CapacityExceeded)));
    assert!(!path.exists());
    let store = DurableSessionStore::create(&path, DurableSessionLimits { max_journal_bytes: exact, ..DurableSessionLimits::default() })?;
    assert_eq!(usize::try_from(store.journal.committed_len())?, exact);
    Ok(())
}

#[test]
fn old_record_corruption_is_detected_by_full_verification() -> TestResult {
    let (store, _) = opened()?;
    let mut file = OpenOptions::new().read(true).write(true).open(store.path())?;
    file.seek(SeekFrom::Start(90))?;
    let mut byte = [0];
    file.read_exact(&mut byte)?;
    byte[0] ^= 1;
    file.seek(SeekFrom::Start(90))?;
    file.write_all(&byte)?;
    file.sync_all()?;
    assert!(store.verify_storage().is_err());
    Ok(())
}

#[test]
fn foreign_application_records_and_torn_tails_are_not_repaired_on_open() -> TestResult {
    let (store, _) = opened()?;
    let path = store.path().to_path_buf();
    drop(store);
    let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
    journal.append(7, b"not a session checkpoint")?;
    let root = journal.last_root();
    drop(journal);
    let mut file = OpenOptions::new().append(true).open(&path)?;
    file.write_all(b"FSSJ")?;
    file.sync_all()?;
    let before = std::fs::read(&path)?;
    assert!(DurableSessionStore::open_existing(&path, root, DurableSessionLimits::default()).is_err());
    assert!(DurableSessionStore::inspect(&path, DurableSessionLimits::default()).is_err());
    assert_eq!(std::fs::read(&path)?, before);
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlink_journals_are_refused() -> TestResult {
    let (store, _) = opened()?;
    let link = unused_path()?;
    std::os::unix::fs::symlink(store.path(), &link)?;
    assert!(matches!(DurableSessionStore::inspect(&link, DurableSessionLimits::default()), Err(DurableSessionError::InvalidLayout)));
    Ok(())
}

fn hydration_fixture() -> Result<(DurableSessionStore, AgentSession, SessionAlias, HydrationRequest, ReferenceHydrationCatalog), Box<dyn Error>> {
    let (mut store, session) = opened()?;
    let mut catalog = ReferenceHydrationCatalog::new();
    let descriptor = register(&mut catalog, "evidence:durable-hydration")?;
    let artifact = HydrationArtifact::publish(
        HydrationLevel::H0, "application/fss+json", b"{}".to_vec(), [descriptor.subject_digest],
        Completeness::Complete, None,
    )?;
    catalog.register_artifact(&descriptor.handle_id, descriptor.descriptor_digest, artifact)?;
    let alias = store.bind(&session.principal_id, &SessionBindingRequest {
        session_id: session.session_id.clone(), generation: 0,
        handle_id: descriptor.handle_id.clone(), descriptor_digest: descriptor.descriptor_digest,
    }, &catalog, TimestampNs(10))?;
    let request = HydrationRequest::publish(HydrationRequestSpec {
        contract_basis: basis(), session_id: session.session_id.clone(),
        handle_id: descriptor.handle_id, expected_descriptor_digest: descriptor.descriptor_digest,
        expected_subject_digest: descriptor.subject_digest, anchor: session.current_anchor.clone(),
        requested_level: HydrationLevel::H0, allow_lower_level: false,
        available_capabilities: session.capabilities.clone(),
        authorized_privacy_classes: session.privacy_scope.clone(),
        budget: BudgetVector::builder().tokens(10).bytes(64).build()?,
        purpose: HydrationPurpose::Qualification, continuation: None, issued_at: TimestampNs(10),
    })?;
    Ok((store, session, alias, request, catalog))
}

#[test]
fn delivered_hydration_charge_survives_restart() -> TestResult {
    let (mut store, session, alias, request, mut catalog) = hydration_fixture()?;
    let response = store.hydrate(&session.principal_id, &alias, &request, &mut catalog, TimestampNs(10))?;
    assert_eq!(response.receipt.cost.tokens, 1);
    let root = store.committed_root();
    let path = store.path().to_path_buf();
    drop(store);
    let mut store = DurableSessionStore::open_existing(path, root, DurableSessionLimits::default())?;
    assert_eq!(store.remaining_token_budget(&session.principal_id, &session.session_id, TimestampNs(10))?, 99);
    assert_eq!(store.resolve(&session.principal_id, &alias, &catalog, TimestampNs(10))?.subject_digest, request.expected_subject_digest);
    Ok(())
}

#[test]
fn ambiguous_hydration_never_publishes_catalog_changes_or_refunds_a_committed_charge() -> TestResult {
    let (mut store, session, alias, request, mut catalog) = hydration_fixture()?;
    let cursors = catalog.issued_cursor_count();
    store.journal.fail_after_phase(AppendPhase::CommitSync);
    assert!(store.hydrate(&session.principal_id, &alias, &request, &mut catalog, TimestampNs(10)).is_err());
    assert_eq!(catalog.issued_cursor_count(), cursors);
    assert_eq!(store.reconcile_pending(IncompleteTailPolicy::Reject)?, SessionAppendRecovery::Committed);
    assert_eq!(store.remaining_token_budget(&session.principal_id, &session.session_id, TimestampNs(10))?, 99);
    store.verify_storage()?;
    Ok(())
}
