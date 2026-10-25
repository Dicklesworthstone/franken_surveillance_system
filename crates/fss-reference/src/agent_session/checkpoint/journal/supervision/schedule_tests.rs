#![forbid(unsafe_code)]
//! Durable schedule progression uses real journal crash cuts. Native integration separately
//! verifies that each prefix executes its complete original source windows and score bindings.

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

fn unused_path() -> TestResult<PathBuf> {
    for _ in 0..128 {
        let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-supervision-schedule-{}-{serial}.journal", std::process::id(),
        ));
        if !path.exists() { return Ok(path); }
    }
    Err("bounded schedule fault-test path inventory exhausted".into())
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
    let configuration = br#"{"fixture":"immutable three-window schedule"}"#.to_vec();
    SupervisionRegistration {
        session_id: session.session_id.clone(),
        subscription_id: "supervision-schedule-fixture".into(),
        configuration_digest: ContentDigest::sha256(&configuration), configuration,
        max_read_bytes: 10_000, max_read_attempts: 100, maximum_attempts: 16,
        max_report_bytes: 4096,
    }
}

fn anchor(session: &AgentSession) -> LedgerAnchor {
    let mut anchor = session.current_anchor.clone();
    anchor.state_root = ContentDigest::sha256(b"synthetic scheduled authority");
    anchor
}

fn reserve(store: &mut DurableSessionStore, session: &AgentSession,
    state: &SupervisionSubscription) -> TestResult<(SupervisionSubscription, SupervisionReservation)>
{
    let state = store.reserve_supervision(
        &session.principal_id, state, &anchor(session), TimestampNs(10),
    )?;
    let reservation = state.reservation().ok_or("reserved schedule attempt")?.clone();
    Ok((state, reservation))
}

fn publish(store: &mut DurableSessionStore, session: &AgentSession,
    state: &SupervisionSubscription) -> TestResult<SupervisionSubscription>
{
    let (state, reservation) = reserve(store, session, state)?;
    Ok(store.publish_supervision(
        &session.principal_id, &state, &reservation,
        br#"{"private":"synthetic cumulative native report"}"#.to_vec(), Vec::new(),
        ContentDigest::sha256(b"synthetic native schedule report"), TimestampNs(10),
    )?)
}

fn discard(store: &mut DurableSessionStore, session: &AgentSession,
    state: &SupervisionSubscription) -> TestResult<(SupervisionSubscription, ContentDigest)>
{
    let receipt = state.pending().ok_or("pending schedule report")?.receipt();
    let state = store.discard_supervision(
        &session.principal_id, state, receipt, &anchor(session), TimestampNs(10),
    )?;
    Ok((state, receipt))
}

fn acknowledge(store: &mut DurableSessionStore, session: &AgentSession,
    state: &SupervisionSubscription) -> TestResult<(SupervisionSubscription, ContentDigest)>
{
    let receipt = state.pending().ok_or("pending schedule report")?.receipt();
    let (state, reservation) = reserve(store, session, state)?;
    let state = store.acknowledge_supervision(
        &session.principal_id, &state, Some(&reservation), receipt,
        &anchor(session), TimestampNs(10),
    )?;
    Ok((state, receipt))
}

fn restart(store: DurableSessionStore) -> TestResult<DurableSessionStore> {
    let path = store.path().to_owned();
    let root = store.committed_root();
    drop(store);
    Ok(DurableSessionStore::open_existing(path, root, DurableSessionLimits::default())?)
}

fn phases() -> [(AppendPhase, bool); 4] {
    [(AppendPhase::BodyWrite, false), (AppendPhase::BodySync, false),
     (AppendPhase::CommitWrite, true), (AppendPhase::CommitSync, true)]
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
    Ok(())
}

#[test]
fn configure_crash_cuts_leave_no_intermediate_unscheduled_registration() -> TestResult {
    for (phase, committed) in phases() {
        let (mut store, session) = opened()?;
        let registration = registration(&session);
        let before = store.committed_root();
        store.journal.fail_after_phase(phase);
        assert!(store.configure_supervision_schedule(
            &session.principal_id, &registration, 3, TimestampNs(10),
        ).is_err());
        assert!(store.inspect_supervision(
            &session.principal_id, &registration, TimestampNs(10),
        ).is_err());
        reconcile(&mut store, committed)?;
        assert_eq!(store.committed_root() != before, committed);
        let mut store = restart(store)?;
        let inspection = inspect_session_bytes(
            &fs::read(store.path())?, DurableSessionLimits::default(), WorkClaimLimits::default(),
        )?;
        assert_eq!(inspection.supervisions.len(), if committed { 1 } else { 0 });
        if committed {
            assert_eq!(inspection.supervisions[0].active_window_count(), Some(1));
            assert_eq!(inspection.supervisions[0].attempts_reserved(), 0);
        } else {
            assert!(store.inspect_supervision(
                &session.principal_id, &registration, TimestampNs(10),
            ).is_err());
        }
        let recovered_root = store.committed_root();
        let state = store.configure_supervision_schedule(
            &session.principal_id, &registration, 3, TimestampNs(10),
        )?;
        assert_eq!(state.active_window_count(), Some(1));
        assert_eq!(state.schedule().ok_or("schedule")?.total_windows(), 3);
        assert_eq!(state.attempts_reserved(), 0);
        assert_eq!(store.committed_root() == recovered_root, committed);
    }
    Ok(())
}

#[test]
fn progression_requires_exact_terminal_receipt_and_never_skips_or_consumes_successors() -> TestResult {
    let (mut store, session) = opened()?;
    let registration = registration(&session);
    let configured = store.configure_supervision_schedule(
        &session.principal_id, &registration, 3, TimestampNs(10),
    )?;
    assert!(store.advance_supervision_window(
        &session.principal_id, &configured, 2, ContentDigest::sha256(b"no delivery"),
        &anchor(&session), TimestampNs(10),
    ).is_err());
    let first = publish(&mut store, &session, &configured)?;
    assert_eq!(first.pending().ok_or("first pending")?.active_window_count(), Some(1));
    let first_receipt = first.pending().ok_or("first pending")?.receipt();
    assert!(store.advance_supervision_window(
        &session.principal_id, &first, 2, first_receipt, &anchor(&session), TimestampNs(10),
    ).is_err());
    let (resolved, first_receipt) = discard(&mut store, &session, &first)?;
    assert_eq!(resolved.schedule().ok_or("schedule")?.resolved_acknowledged(), Some(false));
    for (count, receipt) in [(3, first_receipt), (2, ContentDigest::sha256(b"wrong terminal"))] {
        assert!(store.advance_supervision_window(
            &session.principal_id, &resolved, count, receipt, &anchor(&session), TimestampNs(10),
        ).is_err());
    }
    let second = store.advance_supervision_window(
        &session.principal_id, &resolved, 2, first_receipt, &anchor(&session), TimestampNs(10),
    )?;
    assert_eq!(second.active_window_count(), Some(2));
    assert_eq!(second.attempts_reserved(), first.attempts_reserved());
    let pending = publish(&mut store, &session, &second)?;
    let before_retry = store.committed_root();
    assert_eq!(store.advance_supervision_window(
        &session.principal_id, &pending, 2, first_receipt, &anchor(&session), TimestampNs(10),
    )?, pending);
    assert_eq!(store.committed_root(), before_retry);
    assert_eq!(store.configure_supervision_schedule(
        &session.principal_id, &registration, 3, TimestampNs(10),
    )?, pending);
    assert_eq!(store.committed_root(), before_retry);
    let (resolved, second_receipt) = acknowledge(&mut store, &session, &pending)?;
    assert_eq!(resolved.schedule().ok_or("schedule")?.resolved_acknowledged(), Some(true));
    let third = store.advance_supervision_window(
        &session.principal_id, &resolved, 3, second_receipt, &anchor(&session), TimestampNs(10),
    )?;
    assert_eq!(third.active_window_count(), Some(3));
    assert!(store.advance_supervision_window(
        &session.principal_id, &third, 2, first_receipt, &anchor(&session), TimestampNs(10),
    ).is_err());
    let pending = publish(&mut store, &session, &third)?;
    let (resolved, third_receipt) = discard(&mut store, &session, &pending)?;
    assert!(store.advance_supervision_window(
        &session.principal_id, &resolved, 4, third_receipt, &anchor(&session), TimestampNs(10),
    ).is_err());
    Ok(())
}

#[test]
fn advance_crash_cuts_recover_one_prefix_and_keep_abandoned_work_charged() -> TestResult {
    for (phase, committed) in phases() {
        let (mut store, session) = opened()?;
        let registration = registration(&session);
        let state = store.configure_supervision_schedule(
            &session.principal_id, &registration, 3, TimestampNs(10),
        )?;
        let pending = publish(&mut store, &session, &state)?;
        let (resolved, receipt) = discard(&mut store, &session, &pending)?;
        let (interrupted, abandoned) = reserve(&mut store, &session, &resolved)?;
        let before = store.committed_root();
        store.journal.fail_after_phase(phase);
        assert!(store.advance_supervision_window(
            &session.principal_id, &interrupted, 2, receipt, &anchor(&session), TimestampNs(10),
        ).is_err());
        reconcile(&mut store, committed)?;
        assert_eq!(store.committed_root() != before, committed);
        let mut store = restart(store)?;
        let recovered = store.inspect_supervision(
            &session.principal_id, &registration, TimestampNs(10),
        )?;
        assert_eq!(recovered.active_window_count(), Some(if committed { 2 } else { 1 }));
        assert_eq!(recovered.reservation().is_none(), committed);
        assert_eq!(recovered.attempts_reserved(), 2);
        assert_eq!(recovered.reserved_bytes(), 20_000);
        let before_retry = store.committed_root();
        let advanced = store.advance_supervision_window(
            &session.principal_id, &recovered, 2, receipt, &anchor(&session), TimestampNs(10),
        )?;
        assert_eq!(store.committed_root() == before_retry, committed);
        assert_eq!(advanced.active_window_count(), Some(2));
        assert!(advanced.reservation().is_none());
        assert_eq!(advanced.reserved_read_attempts(), 200);
        assert!(store.publish_supervision(
            &session.principal_id, &advanced, &abandoned, b"stale work".to_vec(), Vec::new(),
            ContentDigest::sha256(b"stale receipt"), TimestampNs(10),
        ).is_err());
        let successor = publish(&mut store, &session, &advanced)?;
        assert_eq!(successor.pending().ok_or("pending successor")?.active_window_count(), Some(2));
        let before = store.committed_root();
        assert_eq!(store.advance_supervision_window(
            &session.principal_id, &successor, 2, receipt, &anchor(&session), TimestampNs(10),
        )?, successor);
        assert_eq!(store.committed_root(), before);
    }
    Ok(())
}

#[test]
fn a_new_publication_clears_terminal_permission_and_old_ack_cannot_restore_it() -> TestResult {
    let (mut store, session) = opened()?;
    let registration = registration(&session);
    let state = store.configure_supervision_schedule(
        &session.principal_id, &registration, 2, TimestampNs(10),
    )?;
    let first = publish(&mut store, &session, &state)?;
    let (resolved, old_receipt) = acknowledge(&mut store, &session, &first)?;
    assert_eq!(resolved.schedule().ok_or("schedule")?.resolved_receipt(), Some(old_receipt));
    let newer = publish(&mut store, &session, &resolved)?;
    assert_eq!(newer.schedule().ok_or("schedule")?.resolved_receipt(), None);
    let before = store.committed_root();
    assert_eq!(store.acknowledge_supervision(
        &session.principal_id, &newer, None, old_receipt, &anchor(&session), TimestampNs(10),
    )?, newer);
    assert_eq!(store.committed_root(), before);
    assert!(store.advance_supervision_window(
        &session.principal_id, &newer, 2, old_receipt, &anchor(&session), TimestampNs(10),
    ).is_err());
    let (resolved, new_receipt) = discard(&mut store, &session, &newer)?;
    assert_ne!(old_receipt, new_receipt);
    assert!(store.advance_supervision_window(
        &session.principal_id, &resolved, 2, old_receipt, &anchor(&session), TimestampNs(10),
    ).is_err());
    let next = store.advance_supervision_window(
        &session.principal_id, &resolved, 2, new_receipt, &anchor(&session), TimestampNs(10),
    )?;
    assert_eq!(next.active_window_count(), Some(2));
    Ok(())
}

#[test]
fn schedule_configuration_never_resets_charged_work_or_changes_immutable_scope() -> TestResult {
    let (mut store, session) = opened()?;
    let registration = registration(&session);
    let before = store.committed_root();
    for count in [0, MAX_SUPERVISION_WINDOWS + 1, u32::MAX] {
        assert!(store.configure_supervision_schedule(
            &session.principal_id, &registration, count, TimestampNs(10),
        ).is_err());
    }
    assert_eq!(store.committed_root(), before);
    let legacy = store.register_supervision(
        &session.principal_id, registration.clone(), TimestampNs(10),
    )?;
    assert_eq!(legacy.active_window_count(), None);
    let (charged, _) = reserve(&mut store, &session, &legacy)?;
    let before = store.committed_root();
    assert!(store.configure_supervision_schedule(
        &session.principal_id, &registration, 3, TimestampNs(10),
    ).is_err());
    assert_eq!(store.committed_root(), before);
    assert_eq!(store.inspect_supervision(
        &session.principal_id, &registration, TimestampNs(10),
    )?, charged);
    let mut unused = registration.clone();
    unused.subscription_id = "unused-explicit-opt-in".into();
    store.register_supervision(&session.principal_id, unused.clone(), TimestampNs(10))?;
    let configured = store.configure_supervision_schedule(
        &session.principal_id, &unused, 3, TimestampNs(10),
    )?;
    assert_eq!(configured.active_window_count(), Some(1));
    let before = store.committed_root();
    assert!(store.configure_supervision_schedule(
        &session.principal_id, &unused, 2, TimestampNs(10),
    ).is_err());
    unused.configuration.push(b' ');
    unused.configuration_digest = ContentDigest::sha256(&unused.configuration);
    assert!(store.configure_supervision_schedule(
        &session.principal_id, &unused, 3, TimestampNs(10),
    ).is_err());
    assert_eq!(store.committed_root(), before);
    Ok(())
}

#[test]
fn lifetime_attempt_ceiling_survives_successful_advances_and_cold_retry() -> TestResult {
    let (mut store, session) = opened()?;
    let mut registration = registration(&session);
    registration.maximum_attempts = 2;
    let mut state = store.configure_supervision_schedule(
        &session.principal_id, &registration, 3, TimestampNs(10),
    )?;
    for target_count in [2, 3] {
        let pending = publish(&mut store, &session, &state)?;
        let (resolved, receipt) = discard(&mut store, &session, &pending)?;
        state = store.advance_supervision_window(
            &session.principal_id, &resolved, target_count, receipt,
            &anchor(&session), TimestampNs(10),
        )?;
    }
    assert_eq!(state.active_window_count(), Some(3));
    let mut store = restart(store)?;
    let before = store.committed_root();
    let recovered = store.configure_supervision_schedule(
        &session.principal_id, &registration, 3, TimestampNs(10),
    )?;
    assert_eq!(recovered, state);
    assert_eq!(recovered.attempts_reserved(), 2);
    assert_eq!(recovered.reserved_bytes(), 20_000);
    assert_eq!(recovered.reserved_read_attempts(), 200);
    assert!(matches!(store.reserve_supervision(
        &session.principal_id, &recovered, &anchor(&session), TimestampNs(10),
    ), Err(DurableSupervisionError::CapacityExceeded)));
    assert_eq!(store.committed_root(), before);
    assert_eq!(store.inspect_supervision(
        &session.principal_id, &registration, TimestampNs(10),
    )?, recovered);
    Ok(())
}
