#![forbid(unsafe_code)]
//! Real session journal crash cuts. These fixtures test presentation custody, not native evidence;
//! deployment integration tests separately reopen the real package-event source inventory.

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::AgentSession;
use fss_ledger::{AppendPhase, IncompleteTailPolicy};

use super::*;
use crate::agent_session::checkpoint::journal::{SessionAppendRecovery, inspect_session_bytes};
use crate::agent_session::checkpoint::tests::{basis, params};
use crate::agent_session::work_claims::WorkClaimLimits;

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;
static NEXT_PATH: AtomicU64 = AtomicU64::new(0);
const PRIVATE_REPORT: &[u8] = br#"{"private":"synthetic supervision journal fixture"}"#;

#[path = "tests/event_health.rs"]
mod event_health;

fn unused_path() -> TestResult<PathBuf> {
    for _ in 0..128 {
        let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-durable-supervision-{}-{serial}.journal", std::process::id()
        ));
        if !path.exists() { return Ok(path); }
    }
    Err("bounded supervision fault-test path inventory exhausted".into())
}

fn opened() -> TestResult<(DurableSessionStore, AgentSession)> {
    let mut store = DurableSessionStore::create(unused_path()?, DurableSessionLimits::default())?;
    let mut input = params()?;
    input.capabilities.extend([
        "CAP-AGENT-SESSION-READ-001".to_owned(),
        "CAP-AGENT-SESSION-WRITE-001".to_owned(),
        "CAP-AGENT-SITUATION-READ-001".to_owned(),
        "CAP-AGENT-INVESTIGATE-001".to_owned(),
    ]);
    let session = store.open(input, basis(), TimestampNs(10))?;
    Ok((store, session))
}

fn registration(session: &AgentSession) -> SupervisionRegistration {
    let configuration = br#"{"profile":"finite synthetic journal fixture"}"#.to_vec();
    SupervisionRegistration {
        session_id: session.session_id.clone(),
        subscription_id: "durable-supervision-fixture".to_owned(),
        configuration_digest: ContentDigest::sha256(&configuration),
        configuration,
        max_read_bytes: 10_000,
        max_read_attempts: 100,
        maximum_attempts: 16,
        max_report_bytes: 4096,
    }
}

fn anchor(session: &AgentSession) -> LedgerAnchor {
    let mut anchor = session.current_anchor.clone();
    anchor.state_root = ContentDigest::sha256(b"synthetic admitted native authority");
    anchor
}

fn sources() -> TestResult<Vec<SupervisionSourcePin>> {
    Ok(vec![
        SupervisionSourcePin {
            event_id: EventId::parse("event:package:metadata-only")?,
            event_root: ContentDigest::sha256(b"exact metadata-only excluded source root"),
            source_verified: false,
            health_digest: None,
        },
        SupervisionSourcePin {
            event_id: EventId::parse("event:package:native-opened")?,
            event_root: ContentDigest::sha256(b"exact native opened source root"),
            source_verified: true,
            health_digest: None,
        },
    ])
}

fn reserve(
    store: &mut DurableSessionStore, session: &AgentSession, state: &SupervisionSubscription,
) -> TestResult<(SupervisionSubscription, SupervisionReservation)> {
    let state = store.reserve_supervision(&session.principal_id, state, &anchor(session), TimestampNs(10))?;
    let reservation = state.reservation().ok_or("reserved attempt")?.clone();
    Ok((state, reservation))
}

fn publish(
    store: &mut DurableSessionStore, session: &AgentSession, state: &SupervisionSubscription,
    reservation: &SupervisionReservation,
) -> TestResult<SupervisionSubscription> {
    Ok(store.publish_supervision(
        &session.principal_id, state, reservation, PRIVATE_REPORT.to_vec(), sources()?,
        ContentDigest::sha256(b"synthetic native report receipt"), TimestampNs(10),
    )?)
}

fn phases() -> [(AppendPhase, bool); 4] {
    [
        (AppendPhase::BodyWrite, false), (AppendPhase::BodySync, false),
        (AppendPhase::CommitWrite, true), (AppendPhase::CommitSync, true),
    ]
}

fn reconcile(store: &mut DurableSessionStore, committed: bool) -> TestResult {
    assert!(store.needs_reconciliation());
    if !committed {
        let bytes = fs::read(store.path())?;
        assert!(store.reconcile_pending(IncompleteTailPolicy::Reject).is_err());
        assert_eq!(fs::read(store.path())?, bytes);
    }
    assert_eq!(store.reconcile_pending(IncompleteTailPolicy::Truncate)?,
        if committed { SessionAppendRecovery::Committed } else { SessionAppendRecovery::NotCommitted });
    assert!(!store.needs_reconciliation());
    Ok(())
}

fn restart(store: DurableSessionStore) -> TestResult<DurableSessionStore> {
    let path = store.path().to_path_buf();
    let root = store.committed_root();
    drop(store);
    Ok(DurableSessionStore::open_existing(path, root, DurableSessionLimits::default())?)
}

fn retained(store: &DurableSessionStore) -> TestResult<Vec<SupervisionSubscription>> {
    Ok(inspect_session_bytes(
        &fs::read(store.path())?, DurableSessionLimits::default(), WorkClaimLimits::default(),
    )?.supervisions)
}

#[test]
fn work_reservation_commits_before_work_and_survives_every_crash_cut() -> TestResult {
    for (phase, committed) in phases() {
        let (mut store, session) = opened()?;
        let registration = registration(&session);
        let state = store.register_supervision(&session.principal_id, registration.clone(), TimestampNs(10))?;
        let before = store.committed_root();
        store.journal.fail_after_phase(phase);
        assert!(store.reserve_supervision(&session.principal_id, &state, &anchor(&session), TimestampNs(10)).is_err());
        assert!(matches!(
            store.register_supervision(&session.principal_id, registration.clone(), TimestampNs(10)),
            Err(DurableSupervisionError::Session(error))
                if matches!(*error, DurableSessionError::ReconciliationRequired)
        ));
        reconcile(&mut store, committed)?;
        assert_eq!(store.committed_root() != before, committed);
        let mut store = restart(store)?;
        let recovered = store.register_supervision(&session.principal_id, registration.clone(), TimestampNs(10))?;
        assert_eq!(recovered.attempts_reserved(), u32::from(committed));
        assert_eq!(recovered.reserved_bytes(), if committed { registration.max_read_bytes } else { 0 });
        let (next, _) = reserve(&mut store, &session, &recovered)?;
        assert_eq!(next.attempts_reserved(), u32::from(committed) + 1);
        assert_eq!(next.reserved_read_attempts(),
            u64::from(next.attempts_reserved()) * registration.max_read_attempts);
        assert_eq!(retained(&store)?, vec![next]);
    }
    Ok(())
}

#[test]
fn publication_cuts_never_release_an_uncommitted_private_report() -> TestResult {
    for (phase, committed) in phases() {
        let (mut store, session) = opened()?;
        let registration = registration(&session);
        let state = store.register_supervision(&session.principal_id, registration.clone(), TimestampNs(10))?;
        let (state, reservation) = reserve(&mut store, &session, &state)?;
        let before = store.committed_root();
        store.journal.fail_after_phase(phase);
        assert!(publish(&mut store, &session, &state, &reservation).is_err());
        reconcile(&mut store, committed)?;
        assert_eq!(store.committed_root() != before, committed);
        let mut store = restart(store)?;
        let mut state = store.register_supervision(&session.principal_id, registration.clone(), TimestampNs(10))?;
        assert_eq!(state.pending().is_some(), committed);
        assert_eq!(state.reservation().is_none(), committed);
        assert_eq!(state.attempts_reserved(), 1);
        if !committed {
            // A restarted computation reserves again; the abandoned work is never refunded.
            let (reserved, retry) = reserve(&mut store, &session, &state)?;
            state = publish(&mut store, &session, &reserved, &retry)?;
        }
        let pending = state.pending().ok_or("durable report")?;
        assert_eq!(pending.payload_digest(), ContentDigest::sha256(PRIVATE_REPORT));
        assert_eq!(pending.payload_len(), PRIVATE_REPORT.len());
        assert_eq!(pending.source_inventory(), sources()?);
        assert_eq!(pending.anchor(), &anchor(&session));
        assert!(!format!("{pending:?}").contains("synthetic supervision journal fixture"));
        assert_eq!(retained(&store)?, vec![state]);
    }
    Ok(())
}

#[test]
fn pending_revalidation_release_is_one_use_and_failure_never_returns_private_bytes() -> TestResult {
    for (phase, committed) in phases() {
        let (mut store, session) = opened()?;
        let registration = registration(&session);
        let state = store.register_supervision(&session.principal_id, registration.clone(), TimestampNs(10))?;
        let (state, reservation) = reserve(&mut store, &session, &state)?;
        let state = publish(&mut store, &session, &state, &reservation)?;
        let receipt = state.pending().ok_or("pending")?.receipt();
        let (state, validation) = reserve(&mut store, &session, &state)?;
        store.journal.fail_after_phase(phase);
        assert!(store.release_supervision_payload(
            &session.principal_id, &state, &validation, receipt, TimestampNs(10),
        ).is_err());
        reconcile(&mut store, committed)?;
        let mut store = restart(store)?;
        let state = store.register_supervision(&session.principal_id, registration.clone(), TimestampNs(10))?;
        assert_eq!(state.reservation().is_none(), committed);
        assert_eq!(state.pending().ok_or("retained")?.receipt(), receipt);
        let (state, validation) = reserve(&mut store, &session, &state)?;
        let (released, payload) = store.release_supervision_payload(
            &session.principal_id, &state, &validation, receipt, TimestampNs(10),
        )?;
        assert_eq!(payload, PRIVATE_REPORT);
        assert_eq!(released.attempts_reserved(), 3);
        let before = store.committed_root();
        assert!(store.release_supervision_payload(
            &session.principal_id, &released, &validation, receipt, TimestampNs(10),
        ).is_err());
        assert_eq!(store.committed_root(), before);
        assert_eq!(released.last_acknowledged(), None);
    }
    Ok(())
}

#[test]
fn ack_crash_cuts_retry_exactly_and_cannot_consume_the_next_delivery() -> TestResult {
    for (phase, committed) in phases() {
        let (mut store, session) = opened()?;
        let registration = registration(&session);
        let state = store.register_supervision(&session.principal_id, registration.clone(), TimestampNs(10))?;
        let (state, reservation) = reserve(&mut store, &session, &state)?;
        let state = publish(&mut store, &session, &state, &reservation)?;
        let first = state.pending().ok_or("pending first")?.receipt();
        let (state, validation) = reserve(&mut store, &session, &state)?;
        store.journal.fail_after_phase(phase);
        assert!(store.acknowledge_supervision(
            &session.principal_id, &state, Some(&validation), first, &anchor(&session), TimestampNs(10),
        ).is_err());
        reconcile(&mut store, committed)?;
        let mut store = restart(store)?;
        let mut state = store.register_supervision(&session.principal_id, registration.clone(), TimestampNs(10))?;
        assert_eq!(state.last_acknowledged(), if committed { Some(first) } else { None });
        assert_eq!(state.pending().is_none(), committed);
        if !committed {
            let (reserved, validation) = reserve(&mut store, &session, &state)?;
            state = store.acknowledge_supervision(
                &session.principal_id, &reserved, Some(&validation), first, &anchor(&session), TimestampNs(10),
            )?;
        }
        let (reserved, reservation) = reserve(&mut store, &session, &state)?;
        let next = publish(&mut store, &session, &reserved, &reservation)?;
        let second = next.pending().ok_or("pending second")?.receipt();
        assert_ne!(first, second);
        let before = store.committed_root();
        assert_eq!(store.acknowledge_supervision(
            &session.principal_id, &next, None, first, &anchor(&session), TimestampNs(10),
        )?, next);
        assert_eq!(store.committed_root(), before);
        let mut store = restart(store)?;
        let state = store.register_supervision(&session.principal_id, registration, TimestampNs(10))?;
        assert_eq!(state.pending().ok_or("successor retained")?.receipt(), second);
        assert_eq!(state.last_acknowledged(), Some(first));
    }
    Ok(())
}

#[test]
fn abandoned_work_scope_drift_and_expiry_never_reset_lifetime_allowances() -> TestResult {
    let (mut store, session) = opened()?;
    let mut registration = registration(&session);
    registration.maximum_attempts = 2;
    let state = store.register_supervision(&session.principal_id, registration.clone(), TimestampNs(10))?;
    let (state, abandoned) = reserve(&mut store, &session, &state)?;
    let mut store = restart(store)?;
    let recovered = store.register_supervision(&session.principal_id, registration.clone(), TimestampNs(10))?;
    assert_eq!(state, recovered);
    let (state, final_attempt) = reserve(&mut store, &session, &recovered)?;
    assert_ne!(abandoned.receipt(), final_attempt.receipt());
    let before = store.committed_root();
    assert!(matches!(
        store.reserve_supervision(&session.principal_id, &state, &anchor(&session), TimestampNs(10)),
        Err(DurableSupervisionError::CapacityExceeded)
    ));
    assert!(publish(&mut store, &session, &state, &abandoned).is_err());
    let mut changed = registration.clone();
    changed.maximum_attempts = 3;
    assert!(matches!(
        store.register_supervision(&session.principal_id, changed, TimestampNs(10)),
        Err(DurableSupervisionError::Conflict)
    ));
    assert_eq!(store.committed_root(), before);
    let state = publish(&mut store, &session, &state, &final_attempt)?;
    let receipt = state.pending().ok_or("final pending")?.receipt();
    let before = store.committed_root();
    assert!(store.acknowledge_supervision(
        &session.principal_id, &state, None, receipt, &anchor(&session), TimestampNs(10),
    ).is_err());
    assert_eq!(store.committed_root(), before);
    assert!(store.discard_supervision(
        &PrincipalId::parse("principal:other")?, &state, receipt, &anchor(&session), TimestampNs(10),
    ).is_err());
    assert!(store.discard_supervision(
        &session.principal_id, &state, receipt, &anchor(&session), TimestampNs(1000),
    ).is_err());
    let history = retained(&store)?;
    assert_eq!(history[0].attempts_reserved(), 2);
    assert_eq!(history[0].reserved_bytes(), 20_000);
    assert_eq!(history[0].pending().ok_or("expired pending retained")?.receipt(), receipt);
    assert_eq!(history[0].last_acknowledged(), None);
    Ok(())
}

#[test]
fn explicit_discard_is_not_ack_and_retries_do_not_discard_a_successor() -> TestResult {
    let (mut store, session) = opened()?;
    let registration = registration(&session);
    let state = store.register_supervision(&session.principal_id, registration.clone(), TimestampNs(10))?;
    let (state, reservation) = reserve(&mut store, &session, &state)?;
    let state = publish(&mut store, &session, &state, &reservation)?;
    let receipt = state.pending().ok_or("discard target")?.receipt();
    let before = store.committed_root();
    assert!(store.discard_supervision(
        &session.principal_id, &state, ContentDigest::sha256(b"wrong receipt"),
        &anchor(&session), TimestampNs(10),
    ).is_err());
    assert_eq!(store.committed_root(), before);
    let discarded = store.discard_supervision(
        &session.principal_id, &state, receipt, &anchor(&session), TimestampNs(10),
    )?;
    assert_eq!(discarded.last_acknowledged(), None);
    assert_eq!(discarded.last_discarded(), Some(receipt));
    assert_eq!(discarded.attempts_reserved(), 1);
    assert!(discarded.pending().is_none());
    let (state, reservation) = reserve(&mut store, &session, &discarded)?;
    let successor = publish(&mut store, &session, &state, &reservation)?;
    let before = store.committed_root();
    assert_eq!(store.discard_supervision(
        &session.principal_id, &successor, receipt, &anchor(&session), TimestampNs(10),
    )?, successor);
    assert_eq!(store.committed_root(), before);
    let mut store = restart(store)?;
    assert_eq!(store.register_supervision(&session.principal_id, registration, TimestampNs(10))?, successor);
    Ok(())
}

#[test]
fn malformed_configuration_inventory_and_generation_are_refused_without_publication() -> TestResult {
    let (mut store, session) = opened()?;
    let mut bad = registration(&session);
    bad.configuration.push(b' ');
    assert!(bad.validate().is_err());
    let registration = registration(&session);
    let state = store.register_supervision(&session.principal_id, registration, TimestampNs(10))?;
    let mut wrong_generation = anchor(&session);
    wrong_generation.privacy_epoch += 1;
    let before = store.committed_root();
    assert!(matches!(store.reserve_supervision(
        &session.principal_id, &state, &wrong_generation, TimestampNs(10),
    ), Err(DurableSupervisionError::StaleScope)));
    assert_eq!(store.committed_root(), before);
    let (state, reservation) = reserve(&mut store, &session, &state)?;
    let mut duplicates = sources()?;
    duplicates.push(duplicates[0].clone());
    let before = store.committed_root();
    assert!(store.publish_supervision(
        &session.principal_id, &state, &reservation, PRIVATE_REPORT.to_vec(), duplicates,
        ContentDigest::sha256(b"synthetic native receipt"), TimestampNs(10),
    ).is_err());
    assert!(store.publish_supervision(
        &session.principal_id, &state, &reservation, vec![b'x'; 4097], sources()?,
        ContentDigest::sha256(b"synthetic native receipt"), TimestampNs(10),
    ).is_err());
    assert_eq!(store.committed_root(), before);
    assert_eq!(retained(&store)?, vec![state]);
    Ok(())
}
