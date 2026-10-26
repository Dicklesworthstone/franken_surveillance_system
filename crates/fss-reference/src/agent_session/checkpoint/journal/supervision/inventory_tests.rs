#![forbid(unsafe_code)]
//! Metadata discovery is isolated, bounded, durable and incapable of releasing retained content.

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{AgentSession, AgentSessionParams};
use fss_ledger::{AppendPhase, IncompleteTailPolicy};

use super::*;
use crate::agent_session::SessionRefresh;
use crate::agent_session::checkpoint::journal::SessionAppendRecovery;
use crate::agent_session::checkpoint::tests::{basis, params};

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;
static NEXT_PATH: AtomicU64 = AtomicU64::new(0);
const PRIVATE_CONFIGURATION: &[u8] = b"private inventory configuration must never appear";
const PRIVATE_REPORT: &[u8] = b"private retained inventory report must never appear";
const PRIVATE_SOURCE: &str = "event:package:private-inventory-source-must-never-appear";
const REQUIRED_CAPABILITIES: [&str; 4] = [
    "CAP-AGENT-SESSION-READ-001", "CAP-AGENT-SESSION-WRITE-001",
    "CAP-AGENT-SITUATION-READ-001", "CAP-AGENT-INVESTIGATE-001",
];

fn unused_path() -> TestResult<PathBuf> {
    for _ in 0..128 {
        let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-supervision-inventory-{}-{serial}.journal", std::process::id(),
        ));
        if !path.exists() { return Ok(path); }
    }
    Err("bounded inventory-test path inventory exhausted".into())
}

fn session_params() -> TestResult<AgentSessionParams> {
    let mut input = params()?;
    input.capabilities.extend(REQUIRED_CAPABILITIES.map(str::to_owned));
    Ok(input)
}

fn opened() -> TestResult<(DurableSessionStore, AgentSession)> {
    let mut store = DurableSessionStore::create(unused_path()?, DurableSessionLimits::default())?;
    let session = store.open(session_params()?, basis(), TimestampNs(10))?;
    Ok((store, session))
}

fn registration(session: &AgentSession, name: &str) -> SupervisionRegistration {
    SupervisionRegistration {
        session_id: session.session_id.clone(), subscription_id: name.to_owned(),
        configuration: PRIVATE_CONFIGURATION.to_vec(),
        configuration_digest: ContentDigest::sha256(PRIVATE_CONFIGURATION),
        max_read_bytes: 10_000, max_read_attempts: 100, maximum_attempts: 5,
        max_report_bytes: 4096,
    }
}

fn anchor(session: &AgentSession) -> LedgerAnchor {
    let mut anchor = session.current_anchor.clone();
    anchor.state_root = ContentDigest::sha256(b"synthetic inventory authority");
    anchor
}

fn reserve(store: &mut DurableSessionStore, session: &AgentSession,
    state: &SupervisionSubscription) -> TestResult<(SupervisionSubscription, SupervisionReservation)>
{
    let state = store.reserve_supervision(
        &session.principal_id, state, &anchor(session), TimestampNs(10),
    )?;
    let reservation = state.reservation().ok_or("charged inventory attempt")?.clone();
    Ok((state, reservation))
}

fn publish(store: &mut DurableSessionStore, session: &AgentSession,
    state: &SupervisionSubscription) -> TestResult<SupervisionSubscription>
{
    let (state, reservation) = reserve(store, session, state)?;
    Ok(store.publish_supervision(
        &session.principal_id, &state, &reservation, PRIVATE_REPORT.to_vec(),
        vec![SupervisionSourcePin {
            event_id: EventId::parse(PRIVATE_SOURCE)?,
            event_root: ContentDigest::sha256(b"private inventory source root"),
            source_verified: true,
        }],
        ContentDigest::sha256(b"original inventory native report receipt"), TimestampNs(10),
    )?)
}

fn refresh(store: &mut DurableSessionStore, session: &AgentSession,
    capabilities: std::collections::BTreeSet<String>,
    privacy_scope: std::collections::BTreeSet<String>, current_anchor: LedgerAnchor,
) -> TestResult<AgentSession> {
    Ok(store.refresh(&session.principal_id, &session.session_id, SessionRefresh {
        expected_session_digest: session.session_digest(), current_anchor,
        capabilities, privacy_scope,
    }, TimestampNs(10))?)
}

#[test]
fn inventory_discovers_only_owning_session_in_deterministic_bounded_order() -> TestResult {
    let (mut store, session) = opened()?;
    assert!(store.supervision_inventory(&session, TimestampNs(10))?.is_empty());
    for index in (0..MAX_SESSION_SUPERVISION_SUBSCRIPTIONS).rev() {
        store.register_supervision(&session.principal_id,
            registration(&session, &format!("bounded-{index}")), TimestampNs(10))?;
    }
    let mut other = session_params()?;
    other.session_id = SessionId::parse("session:other-inventory-owner")?;
    let other = store.open(other, basis(), TimestampNs(10))?;
    store.register_supervision(&other.principal_id,
        registration(&other, "other-private-subscription"), TimestampNs(10))?;
    let before = fs::read(store.path())?;
    let inventory = store.supervision_inventory(&session, TimestampNs(20))?;
    assert_eq!(inventory.len(), MAX_SESSION_SUPERVISION_SUBSCRIPTIONS);
    assert_eq!(inventory.iter().map(|entry| entry.subscription_id.clone()).collect::<Vec<_>>(),
        (0..MAX_SESSION_SUPERVISION_SUBSCRIPTIONS).map(|i| format!("bounded-{i}")).collect::<Vec<_>>());
    assert!(inventory.iter().all(|entry| entry.authority_current));
    assert_eq!(store.supervision_inventory(&other, TimestampNs(20))?[0].subscription_id,
        "other-private-subscription");
    assert!(!format!("{inventory:?}").contains("other-private-subscription"));
    assert!(matches!(store.register_supervision(&session.principal_id,
        registration(&session, "overflow"), TimestampNs(10)),
        Err(DurableSupervisionError::CapacityExceeded)));
    assert_eq!(fs::read(store.path())?, before);
    Ok(())
}

#[test]
fn cold_inventory_preserves_pending_interrupted_work_schedule_and_every_lifetime_charge() -> TestResult {
    let (mut store, session) = opened()?;
    let original = registration(&session, "recover-without-remembering-name");
    let state = store.configure_supervision_schedule(
        &session.principal_id, &original, 3, TimestampNs(10),
    )?;
    let state = publish(&mut store, &session, &state)?;
    let acknowledged = state.pending().ok_or("first delivery")?.receipt();
    let (state, validation) = reserve(&mut store, &session, &state)?;
    let state = store.acknowledge_supervision(&session.principal_id, &state, Some(&validation),
        acknowledged, &anchor(&session), TimestampNs(10))?;
    let state = store.advance_supervision_window(&session.principal_id, &state, 2,
        acknowledged, &anchor(&session), TimestampNs(10))?;
    let state = publish(&mut store, &session, &state)?;
    let discarded = state.pending().ok_or("second delivery")?.receipt();
    let state = store.discard_supervision(&session.principal_id, &state,
        discarded, &anchor(&session), TimestampNs(10))?;
    let state = store.advance_supervision_window(&session.principal_id, &state, 3,
        discarded, &anchor(&session), TimestampNs(10))?;
    let state = publish(&mut store, &session, &state)?;
    let (state, unfinished) = reserve(&mut store, &session, &state)?;
    assert_eq!(state.attempts_reserved(), original.maximum_attempts);
    let expected = store.supervision_inventory(&session, TimestampNs(20))?;
    let path = store.path().to_owned();
    let root = store.committed_root();
    let before = fs::read(&path)?;
    let checkpoint = store.checkpoint_digest;
    drop(store);
    let mut store = DurableSessionStore::open_existing(path, root, DurableSessionLimits::default())?;
    for now in [TimestampNs(20), TimestampNs(30)] {
        assert_eq!(store.supervision_inventory(&session, now)?, expected);
    }
    let entry = &expected[0];
    assert_eq!(entry.state_digest, state.digest());
    assert_eq!(entry.authority_digest, state.authority_digest);
    assert!(entry.authority_current);
    assert_eq!(entry.configuration_digest, original.configuration_digest);
    assert_eq!((entry.max_read_bytes, entry.max_read_attempts, entry.maximum_attempts,
        entry.max_report_bytes), (10_000, 100, 5, 4096));
    assert_eq!((entry.attempts_reserved, entry.reserved_bytes, entry.reserved_read_attempts),
        (5, 50_000, 500));
    assert_eq!(entry.reservation, Some(unfinished));
    assert_eq!(entry.reservation_generations_current, Some(true));
    assert_eq!(entry.schedule.as_ref(), state.schedule());
    let schedule = entry.schedule.as_ref().ok_or("retained schedule")?;
    assert_eq!((schedule.active_window_count(), schedule.total_windows()), (3, 3));
    assert_eq!(schedule.last_advance().ok_or("last advance")?.after_receipt(), discarded);
    assert_eq!(entry.last_acknowledged, Some(acknowledged));
    assert_eq!(entry.last_discarded, Some(discarded));
    let pending = entry.pending.as_ref().ok_or("pending metadata")?;
    let original_pending = state.pending().ok_or("pending retained state")?;
    assert_eq!(pending.receipt, original_pending.receipt());
    assert_eq!(pending.report_receipt, original_pending.report_receipt());
    assert_eq!(pending.anchor, *original_pending.anchor());
    assert_eq!(pending.payload_digest, ContentDigest::sha256(PRIVATE_REPORT));
    assert_eq!(pending.payload_len, PRIVATE_REPORT.len());
    assert_eq!(pending.active_window_count, Some(3));
    assert!(pending.generations_current);
    let rendered = format!("{expected:?}");
    for private in [std::str::from_utf8(PRIVATE_CONFIGURATION)?,
        std::str::from_utf8(PRIVATE_REPORT)?, PRIVATE_SOURCE] {
        assert!(!rendered.contains(private));
    }
    // Read-only discovery does not create a later clock checkpoint or renew exhausted work.
    let live = store.memory.sessions.get(&session.session_id).ok_or("live owner")?;
    assert_eq!(live.last_observed_at, TimestampNs(10));
    assert_eq!(live.spent_tokens, 0);
    assert_eq!(store.checkpoint_digest, checkpoint);
    assert_eq!(store.committed_root(), root);
    assert_eq!(fs::read(store.path())?, before);
    assert!(matches!(store.reserve_supervision(&session.principal_id, &state,
        &anchor(&session), TimestampNs(10)), Err(DurableSupervisionError::CapacityExceeded)));
    assert_eq!(fs::read(store.path())?, before);
    Ok(())
}

#[test]
fn inventory_preserves_terminal_schedule_disposition_without_implicit_progression() -> TestResult {
    for acknowledged in [false, true] {
        let (mut store, session) = opened()?;
        let state = store.configure_supervision_schedule(&session.principal_id,
            &registration(&session, "terminal-prefix"), 2, TimestampNs(10))?;
        let state = publish(&mut store, &session, &state)?;
        let receipt = state.pending().ok_or("delivery")?.receipt();
        let state = if acknowledged {
            let (state, reservation) = reserve(&mut store, &session, &state)?;
            store.acknowledge_supervision(&session.principal_id, &state, Some(&reservation),
                receipt, &anchor(&session), TimestampNs(10))?
        } else {
            store.discard_supervision(&session.principal_id, &state, receipt,
                &anchor(&session), TimestampNs(10))?
        };
        let before = fs::read(store.path())?;
        let inventory = store.supervision_inventory(&session, TimestampNs(20))?;
        assert_eq!(inventory[0].state_digest, state.digest());
        assert!(inventory[0].pending.is_none());
        let schedule = inventory[0].schedule.as_ref().ok_or("terminal schedule")?;
        assert_eq!(schedule.active_window_count(), 1);
        assert_eq!(schedule.resolved_receipt(), Some(receipt));
        assert_eq!(schedule.resolved_acknowledged(), Some(acknowledged));
        assert!(schedule.last_advance().is_none());
        assert_eq!(fs::read(store.path())?, before);
    }
    Ok(())
}

#[test]
fn narrower_scope_retains_metadata_with_original_authority_but_cannot_recover_configuration() -> TestResult {
    let (mut store, session) = opened()?;
    let original = registration(&session, "narrowed-owner");
    let state = store.register_supervision(&session.principal_id, original.clone(), TimestampNs(10))?;
    let state = publish(&mut store, &session, &state)?;
    let before = store.supervision_inventory(&session, TimestampNs(10))?;
    let mut capabilities = session.capabilities.clone();
    assert!(capabilities.remove("capability:hydrate:H0"));
    let current = refresh(&mut store, &session, capabilities,
        session.privacy_scope.clone(), session.current_anchor.clone())?;
    let bytes = fs::read(store.path())?;
    assert!(matches!(store.supervision_inventory(&session, TimestampNs(10)),
        Err(DurableSupervisionError::StaleScope)));
    let after = store.supervision_inventory(&current, TimestampNs(10))?;
    let mut expected = before;
    expected[0].authority_current = false;
    assert_eq!(after, expected);
    assert_eq!(after[0].state_digest, state.digest());
    assert!(matches!(store.recover_supervision_registration(&current.principal_id,
        &current.session_id, &original.subscription_id, TimestampNs(10)),
        Err(DurableSupervisionError::StaleScope)));
    assert_eq!(fs::read(store.path())?, bytes);
    Ok(())
}

#[test]
fn historical_report_and_reservation_keep_original_anchors_when_interpretations_change() -> TestResult {
    let (mut store, session) = opened()?;
    let state = store.register_supervision(&session.principal_id,
        registration(&session, "stale-interpretation"), TimestampNs(10))?;
    let state = publish(&mut store, &session, &state)?;
    let (state, reservation) = reserve(&mut store, &session, &state)?;
    let mut changed_anchor = session.current_anchor.clone();
    changed_anchor.commit_sequence += 1;
    changed_anchor.policy_epoch += 1;
    changed_anchor.state_root = ContentDigest::sha256(b"new interpretation authority");
    let current = refresh(&mut store, &session, session.capabilities.clone(),
        session.privacy_scope.clone(), changed_anchor.clone())?;
    let entry = store.supervision_inventory(&current, TimestampNs(10))?.remove(0);
    assert!(entry.authority_current);
    assert_eq!(entry.reservation_generations_current, Some(false));
    assert_eq!(entry.reservation, Some(reservation));
    let pending = entry.pending.ok_or("stale retained report")?;
    assert!(!pending.generations_current);
    assert_eq!(&pending.anchor, state.pending().ok_or("original pending")?.anchor());
    assert_ne!(pending.anchor, changed_anchor);
    assert_eq!(entry.state_digest, state.digest());
    Ok(())
}

#[test]
fn forged_and_stale_session_snapshots_cannot_discover_subscription_names() -> TestResult {
    let (mut store, session) = opened()?;
    store.register_supervision(&session.principal_id,
        registration(&session, "private-owned-name"), TimestampNs(10))?;
    let before = fs::read(store.path())?;
    for changed in ["principal", "session", "capabilities", "privacy", "generation", "anchor", "budget"] {
        let mut forged = session.clone();
        match changed {
            "principal" => forged.principal_id = PrincipalId::parse("principal:unrelated")?,
            "session" => forged.session_id = SessionId::parse("session:missing")?,
            "capabilities" => { forged.capabilities.insert("CAP-FORGED".to_owned()); }
            "privacy" => { forged.privacy_scope.insert("private:forged".to_owned()); }
            "generation" => forged.symbol_table_generation += 1,
            "anchor" => forged.current_anchor.commit_sequence += 1,
            _ => forged.token_budget += 1,
        }
        let error = store.supervision_inventory(&forged, TimestampNs(10))
            .expect_err("forged caller session is not an authority record");
        assert!(!format!("{error:?} {error}").contains("private-owned-name"));
    }
    assert_eq!(fs::read(store.path())?, before);
    let rotated = store.rotate_symbols(&session.principal_id, &session.session_id,
        session.symbol_table_generation, TimestampNs(10))?;
    assert!(matches!(store.supervision_inventory(&session, TimestampNs(10)),
        Err(DurableSupervisionError::StaleScope)));
    assert_eq!(store.supervision_inventory(&rotated, TimestampNs(10))?.len(), 1);
    Ok(())
}

#[test]
fn denied_metadata_scope_does_not_reveal_whether_subscriptions_exist() -> TestResult {
    for missing in REQUIRED_CAPABILITIES.into_iter().chain(["private:property"]) {
        for populated in [false, true] {
            let (mut store, session) = opened()?;
            if populated {
                store.register_supervision(&session.principal_id,
                    registration(&session, "hidden-denied-subscription"), TimestampNs(10))?;
            }
            let mut capabilities = session.capabilities.clone();
            let mut privacy_scope = session.privacy_scope.clone();
            if missing == "private:property" { assert!(privacy_scope.remove(missing)); }
            else { assert!(capabilities.remove(missing)); }
            let current = refresh(&mut store, &session, capabilities, privacy_scope,
                session.current_anchor.clone())?;
            let before = fs::read(store.path())?;
            assert!(matches!(store.supervision_inventory(&current, TimestampNs(10)),
                Err(DurableSupervisionError::StaleScope)));
            assert_eq!(fs::read(store.path())?, before);
        }
    }
    Ok(())
}

#[test]
fn closed_expired_and_regressed_time_refuse_without_clock_or_budget_mutation() -> TestResult {
    for unavailable in ["closed", "expired", "clock_regression"] {
        let (mut store, session) = opened()?;
        store.register_supervision(&session.principal_id,
            registration(&session, "unavailable-owner"), TimestampNs(10))?;
        if unavailable == "closed" {
            store.close(&session.principal_id, &session.session_id, TimestampNs(10))?;
        }
        let now = match unavailable {
            "expired" => TimestampNs(session.expires_at_ns),
            "clock_regression" => TimestampNs(9),
            _ => TimestampNs(10),
        };
        let root = store.committed_root();
        let before = fs::read(store.path())?;
        assert!(matches!(store.supervision_inventory(&session, now),
            Err(DurableSupervisionError::Session(_))));
        assert_eq!(store.committed_root(), root);
        assert_eq!(fs::read(store.path())?, before);
    }
    Ok(())
}

#[test]
fn inventory_cannot_publish_or_repair_an_uncertain_append() -> TestResult {
    for (phase, committed) in [
        (AppendPhase::BodyWrite, false), (AppendPhase::BodySync, false),
        (AppendPhase::CommitWrite, true), (AppendPhase::CommitSync, true),
    ] {
        let (mut store, session) = opened()?;
        let state = store.register_supervision(&session.principal_id,
            registration(&session, "ambiguous-progress"), TimestampNs(10))?;
        store.journal.fail_after_phase(phase);
        assert!(store.reserve_supervision(&session.principal_id, &state,
            &anchor(&session), TimestampNs(10)).is_err());
        let before = fs::read(store.path())?;
        assert!(matches!(store.supervision_inventory(&session, TimestampNs(10)),
            Err(DurableSupervisionError::Session(error))
                if matches!(*error, DurableSessionError::ReconciliationRequired)));
        assert!(store.needs_reconciliation());
        assert_eq!(fs::read(store.path())?, before);
        assert_eq!(store.reconcile_pending(IncompleteTailPolicy::Truncate)?,
            if committed { SessionAppendRecovery::Committed } else { SessionAppendRecovery::NotCommitted });
        let inventory = store.supervision_inventory(&session, TimestampNs(10))?;
        assert_eq!(inventory[0].attempts_reserved, u32::from(committed));
        assert_eq!(inventory[0].reservation.is_some(), committed);
    }
    Ok(())
}

#[test]
fn inventory_requires_the_complete_pinned_history_before_returning_metadata() -> TestResult {
    for mutation in ["older_body", "trailer", "torn_tail"] {
        let (mut store, session) = opened()?;
        store.register_supervision(&session.principal_id,
            registration(&session, "pinned-history"), TimestampNs(10))?;
        let mut bytes = fs::read(store.path())?;
        match mutation {
            "older_body" => bytes[100] ^= 1,
            "trailer" => { bytes.pop(); }
            _ => bytes.extend_from_slice(b"incomplete foreign tail"),
        }
        fs::write(store.path(), &bytes)?;
        assert!(store.supervision_inventory(&session, TimestampNs(10)).is_err());
        assert_eq!(fs::read(store.path())?, bytes);
    }
    Ok(())
}
