#![forbid(unsafe_code)]
//! Exact configuration recovery follows the real durable session owner, without native work.

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{AgentSession, AgentSessionParams};
use fss_ledger::{AppendPhase, IncompleteTailPolicy};

use super::*;
use crate::agent_session::SessionRefresh;
use crate::agent_session::checkpoint::journal::{SessionAppendRecovery, inspect_session_bytes};
use crate::agent_session::checkpoint::tests::{basis, params};
use crate::agent_session::work_claims::WorkClaimLimits;

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;
static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

fn unused_path() -> TestResult<PathBuf> {
    for _ in 0..128 {
        let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-supervision-recovery-{}-{serial}.journal", std::process::id(),
        ));
        if !path.exists() { return Ok(path); }
    }
    Err("bounded recovery-test path inventory exhausted".into())
}

fn session_params() -> TestResult<AgentSessionParams> {
    let mut input = params()?;
    input.capabilities.extend([
        "CAP-AGENT-SESSION-READ-001".to_owned(),
        "CAP-AGENT-SESSION-WRITE-001".to_owned(),
        "CAP-AGENT-SITUATION-READ-001".to_owned(),
        "CAP-AGENT-INVESTIGATE-001".to_owned(),
    ]);
    Ok(input)
}

fn opened() -> TestResult<(DurableSessionStore, AgentSession)> {
    let mut store = DurableSessionStore::create(unused_path()?, DurableSessionLimits::default())?;
    let session = store.open(session_params()?, basis(), TimestampNs(10))?;
    Ok((store, session))
}

fn registration(session: &AgentSession) -> SupervisionRegistration {
    // Whitespace and a terminal newline are intentional: recovery returns original file bytes,
    // not a reconstructed equivalent JSON document with a different file identity.
    let configuration = b" {\n  \"profile\" : \"exact stored recovery recipe\"\n }\n".to_vec();
    SupervisionRegistration {
        session_id: session.session_id.clone(), subscription_id: "recover-exact-scope".into(),
        configuration_digest: ContentDigest::sha256(&configuration), configuration,
        max_read_bytes: 10_000, max_read_attempts: 100,
        maximum_attempts: 1, max_report_bytes: 4096,
    }
}

fn anchor(session: &AgentSession) -> LedgerAnchor {
    let mut anchor = session.current_anchor.clone();
    anchor.state_root = ContentDigest::sha256(b"synthetic admitted recovery fixture authority");
    anchor
}

fn pending(
    store: &mut DurableSessionStore,
    session: &AgentSession,
    state: &SupervisionSubscription,
) -> TestResult<SupervisionSubscription> {
    let state = store.reserve_supervision(
        &session.principal_id, state, &anchor(session), TimestampNs(10),
    )?;
    let reservation = state.reservation().ok_or("reserved native attempt")?.clone();
    Ok(store.publish_supervision(
        &session.principal_id, &state, &reservation,
        br#"{"private":"not returned by registration recovery"}"#.to_vec(),
        Vec::new(), ContentDigest::sha256(b"synthetic private report receipt"), TimestampNs(10),
    )?)
}

fn retained(store: &DurableSessionStore) -> TestResult<Vec<SupervisionSubscription>> {
    Ok(inspect_session_bytes(
        &fs::read(store.path())?, DurableSessionLimits::default(), WorkClaimLimits::default(),
    )?.supervisions)
}

fn lookup(store: &mut DurableSessionStore, session: &AgentSession) -> TestResult<SupervisionRegistration> {
    Ok(store.recover_supervision_registration(
        &session.principal_id, &session.session_id, "recover-exact-scope", TimestampNs(10),
    )?)
}

#[test]
fn exact_configuration_recovers_after_restart_and_exhaustion_without_changing_pending_work() -> TestResult {
    for scheduled in [false, true] {
        let (mut store, session) = opened()?;
        let original = registration(&session);
        let initial = if scheduled {
            store.configure_supervision_schedule(&session.principal_id, &original, 3, TimestampNs(10))?
        } else {
            store.register_supervision(&session.principal_id, original.clone(), TimestampNs(10))?
        };
        let pending = pending(&mut store, &session, &initial)?;
        let before_root = store.committed_root();
        let before_bytes = fs::read(store.path())?;
        assert_eq!(lookup(&mut store, &session)?, original);
        assert_eq!(retained(&store)?, vec![pending.clone()]);
        assert_eq!(store.committed_root(), before_root);
        assert_eq!(fs::read(store.path())?, before_bytes);

        let path = store.path().to_owned();
        drop(store);
        let mut store = DurableSessionStore::open_existing(path, before_root, DurableSessionLimits::default())?;
        assert_eq!(lookup(&mut store, &session)?, original);
        assert!(matches!(
            store.reserve_supervision(&session.principal_id, &pending, &anchor(&session), TimestampNs(10)),
            Err(DurableSupervisionError::CapacityExceeded)
        ));
        assert_eq!(lookup(&mut store, &session)?, original);
        assert_eq!(store.committed_root(), before_root);
        assert_eq!(fs::read(store.path())?, before_bytes);
        let recovered = retained(&store)?;
        assert_eq!(recovered, vec![pending]);
        assert_eq!(recovered[0].attempts_reserved(), 1);
        assert_eq!(recovered[0].reserved_bytes(), 10_000);
        assert_eq!(recovered[0].reserved_read_attempts(), 100);
        assert_eq!(recovered[0].active_window_count(), scheduled.then_some(1));
    }
    Ok(())
}

#[test]
fn recovery_refuses_unknown_foreign_and_invalid_selectors_without_creating_subscriptions() -> TestResult {
    let (mut store, session) = opened()?;
    let original = registration(&session);
    store.register_supervision(&session.principal_id, original.clone(), TimestampNs(10))?;
    let mut second = session_params()?;
    second.session_id = SessionId::parse("session:another-live-owner-scope")?;
    let second = store.open(second, basis(), TimestampNs(10))?;
    let before = fs::read(store.path())?;
    let oversized = "a".repeat(129);
    for label in ["", "../other", "not allowed", "missing", oversized.as_str()] {
        assert!(store.recover_supervision_registration(
            &session.principal_id, &session.session_id, label, TimestampNs(10),
        ).is_err());
    }
    assert!(store.recover_supervision_registration(
        &PrincipalId::parse("principal:foreign")?, &session.session_id,
        &original.subscription_id, TimestampNs(10),
    ).is_err());
    assert!(store.recover_supervision_registration(
        &session.principal_id, &SessionId::parse("session:unknown")?,
        &original.subscription_id, TimestampNs(10),
    ).is_err());
    assert!(store.recover_supervision_registration(
        &second.principal_id, &second.session_id, &original.subscription_id, TimestampNs(10),
    ).is_err());
    assert_eq!(fs::read(store.path())?, before);
    assert_eq!(retained(&store)?.len(), 1);
    assert_eq!(lookup(&mut store, &session)?, original);
    Ok(())
}

#[test]
fn recovery_requires_the_original_live_authority_projection_and_lease() -> TestResult {
    for changed in ["unrelated_grant", "required_grant", "closed", "expired"] {
        let (mut store, session) = opened()?;
        let original = registration(&session);
        let state = store.register_supervision(&session.principal_id, original, TimestampNs(10))?;
        let state = pending(&mut store, &session, &state)?;
        match changed {
            "unrelated_grant" | "required_grant" => {
                let mut capabilities = session.capabilities.clone();
                assert!(capabilities.remove(if changed == "unrelated_grant" {
                    "capability:hydrate:H0"
                } else {
                    "CAP-AGENT-INVESTIGATE-001"
                }));
                store.refresh(&session.principal_id, &session.session_id, SessionRefresh {
                    expected_session_digest: session.session_digest(),
                    current_anchor: session.current_anchor.clone(),
                    capabilities, privacy_scope: session.privacy_scope.clone(),
                }, TimestampNs(10))?;
            }
            "closed" => store.close(&session.principal_id, &session.session_id, TimestampNs(10))?,
            _ => {}
        }
        let now = if changed == "expired" { TimestampNs(session.expires_at_ns) } else { TimestampNs(10) };
        let result = store.recover_supervision_registration(
            &session.principal_id, &session.session_id, "recover-exact-scope", now,
        );
        if changed.ends_with("grant") {
            assert!(matches!(result, Err(DurableSupervisionError::StaleScope)));
        } else {
            assert!(result.is_err());
        }
        assert_eq!(retained(&store)?, vec![state]);
        let path = store.path().to_owned();
        let root = store.committed_root();
        drop(store);
        let mut store = DurableSessionStore::open_existing(path, root, DurableSessionLimits::default())?;
        assert!(store.recover_supervision_registration(
            &session.principal_id, &session.session_id, "recover-exact-scope", now,
        ).is_err());
    }
    Ok(())
}

#[test]
fn recovery_cannot_bypass_an_uncertain_append_or_reconcile_it_implicitly() -> TestResult {
    let (mut store, session) = opened()?;
    let original = registration(&session);
    let state = store.register_supervision(&session.principal_id, original.clone(), TimestampNs(10))?;
    store.journal.fail_after_phase(AppendPhase::CommitWrite);
    assert!(store.reserve_supervision(
        &session.principal_id, &state, &anchor(&session), TimestampNs(10),
    ).is_err());
    let interrupted = fs::read(store.path())?;
    assert!(matches!(
        store.recover_supervision_registration(
            &session.principal_id, &session.session_id, &original.subscription_id, TimestampNs(10),
        ),
        Err(DurableSupervisionError::Session(error))
            if matches!(*error, DurableSessionError::ReconciliationRequired)
    ));
    assert!(store.needs_reconciliation());
    assert_eq!(fs::read(store.path())?, interrupted);
    assert_eq!(store.reconcile_pending(IncompleteTailPolicy::Truncate)?, SessionAppendRecovery::Committed);
    let before = fs::read(store.path())?;
    assert_eq!(lookup(&mut store, &session)?, original);
    assert_eq!(fs::read(store.path())?, before);
    assert_eq!(retained(&store)?[0].attempts_reserved(), 1);
    Ok(())
}

#[test]
fn lookup_has_no_durable_wire_encoding() -> TestResult {
    let (store, session) = opened()?;
    let record = Record {
        principal: session.principal_id.clone(), session: session.session_id.clone(), now: TimestampNs(10),
        session_digest: store.checkpoint_digest,
        before_state: ContentDigest::sha256(b"before recovery"),
        after_state: ContentDigest::sha256(b"no recovery transition is legitimate"),
        command: Command::Lookup("recover-exact-scope".into()),
    };
    assert!(matches!(codec::encode_record(&record), Err(DurableSessionError::InvalidHistory)));
    Ok(())
}
