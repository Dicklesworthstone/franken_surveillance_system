#![forbid(unsafe_code)]
//! Real journal crash cuts. Anchor strings are explicitly synthetic state-machine inputs;
//! deployment integration tests separately prove exact native history resolution and sealing.

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

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

fn unused_path() -> TestResult<PathBuf> {
    for _ in 0..128 {
        let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-durable-follow-{}-{serial}.journal",
            std::process::id()
        ));
        if !path.exists() {
            return Ok(path);
        }
    }
    Err("bounded fault-test path inventory exhausted".into())
}

fn opened() -> TestResult<(DurableSessionStore, AgentSession)> {
    let mut store = DurableSessionStore::create(unused_path()?, DurableSessionLimits::default())?;
    let mut input = params()?;
    input.capabilities.extend([
        "CAP-AGENT-SESSION-READ-001".to_owned(),
        "CAP-AGENT-SESSION-WRITE-001".to_owned(),
        "CAP-AGENT-SITUATION-READ-001".to_owned(),
    ]);
    let session = store.open(input, basis(), TimestampNs(10))?;
    Ok((store, session))
}

fn token(commit: u64) -> String {
    format!("anchor:0123456789abcdef:{commit}:none:{}", "0".repeat(64))
}

fn registration(session: &AgentSession) -> FollowRegistration {
    FollowRegistration {
        session_id: session.session_id.clone(),
        subscription_id: "durable-follow-fixture".to_owned(),
        since: token(0),
        view: AgentView::Brief,
        max_entries: 1,
        semantic_history: ContentDigest::sha256(b"synthetic frozen semantic profile"),
    }
}

fn pending(state: &FollowSubscription) -> TestResult<PendingFollowDelivery> {
    let from = AnchorToken::parse(state.acknowledged_anchor()).ok_or("synthetic token")?;
    let mut pending = PendingFollowDelivery {
        since: state.acknowledged_anchor.clone(),
        result: token(from.position().commit_sequence + 1),
        horizon: token(2),
        input_continuation: None,
        next_continuation: None,
        page_start: 0,
        page_len: 1,
        total_items: 1,
        page_digest: ContentDigest::sha256(b"synthetic exact native page"),
        result_fingerprint: ContentDigest::sha256(b"synthetic exact result fingerprint"),
        receipt: ContentDigest::sha256(&[]),
    };
    pending.receipt = pending.computed_receipt(state);
    pending.validate_for(state)?;
    Ok(pending)
}

fn phases() -> [(AppendPhase, bool); 4] {
    [
        (AppendPhase::BodyWrite, false),
        (AppendPhase::BodySync, false),
        (AppendPhase::CommitWrite, true),
        (AppendPhase::CommitSync, true),
    ]
}

fn reconcile(store: &mut DurableSessionStore, committed: bool) -> TestResult {
    assert!(store.needs_reconciliation());
    if !committed {
        let bytes = fs::read(store.path())?;
        assert!(
            store
                .reconcile_pending(IncompleteTailPolicy::Reject)
                .is_err()
        );
        assert_eq!(fs::read(store.path())?, bytes);
    }
    assert_eq!(
        store.reconcile_pending(IncompleteTailPolicy::Truncate)?,
        if committed {
            SessionAppendRecovery::Committed
        } else {
            SessionAppendRecovery::NotCommitted
        }
    );
    assert!(!store.needs_reconciliation());
    Ok(())
}

fn restart(store: DurableSessionStore) -> TestResult<DurableSessionStore> {
    let path = store.path().to_path_buf();
    let root = store.committed_root();
    drop(store);
    Ok(DurableSessionStore::open_existing(
        path,
        root,
        DurableSessionLimits::default(),
    )?)
}

#[test]
fn pending_delivery_survives_each_committed_cut_and_uncommitted_cuts_never_release_it() -> TestResult
{
    for (phase, committed) in phases() {
        let (mut store, session) = opened()?;
        let registration = registration(&session);
        let state =
            store.register_follow(&session.principal_id, registration.clone(), TimestampNs(10))?;
        let pending = pending(&state)?;
        let receipt = pending.receipt();
        let before = store.committed_root();
        store.journal.fail_after_phase(phase);
        let failure = store.publish_follow_delivery(
            &session.principal_id,
            &state,
            pending.clone(),
            TimestampNs(10),
        );
        assert!(
            matches!(failure, Err(DurableFollowError::Session(error)) if matches!(*error, DurableSessionError::Journal(_)))
        );
        assert!(matches!(
            store.register_follow(&session.principal_id, registration.clone(), TimestampNs(10)),
            Err(DurableFollowError::Session(error)) if matches!(*error, DurableSessionError::ReconciliationRequired)
        ));
        reconcile(&mut store, committed)?;
        assert_eq!(store.committed_root() != before, committed);
        let mut store = restart(store)?;
        let state =
            store.register_follow(&session.principal_id, registration.clone(), TimestampNs(10))?;
        assert_eq!(state.pending().is_some(), committed);
        assert_eq!(state.acknowledged_anchor(), registration.since);
        if committed {
            assert_eq!(
                state.pending().ok_or("recovered pending")?.receipt(),
                receipt
            );
        } else {
            store.publish_follow_delivery(
                &session.principal_id,
                &state,
                pending,
                TimestampNs(10),
            )?;
        }
        let result = store.acknowledge_follow(
            &session.principal_id,
            &session.session_id,
            &registration.subscription_id,
            receipt,
            TimestampNs(10),
        )?;
        assert_eq!(result.acknowledged_anchor(), token(1));
        assert!(result.pending().is_none());
        let inspection = inspect_session_bytes(
            &fs::read(store.path())?,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
        )?;
        assert_eq!(inspection.follows, vec![result]);
    }
    Ok(())
}

#[test]
fn lost_ack_at_each_crash_cut_recovers_once_and_never_consumes_the_next_delivery() -> TestResult {
    for (phase, committed) in phases() {
        let (mut store, session) = opened()?;
        let registration = registration(&session);
        let state =
            store.register_follow(&session.principal_id, registration.clone(), TimestampNs(10))?;
        let first = pending(&state)?;
        let receipt = first.receipt();
        store.publish_follow_delivery(&session.principal_id, &state, first, TimestampNs(10))?;
        let before = store.committed_root();
        store.journal.fail_after_phase(phase);
        assert!(
            store
                .acknowledge_follow(
                    &session.principal_id,
                    &session.session_id,
                    &registration.subscription_id,
                    receipt,
                    TimestampNs(10),
                )
                .is_err()
        );
        reconcile(&mut store, committed)?;
        assert_eq!(store.committed_root() != before, committed);
        let mut store = restart(store)?;
        let recovered =
            store.register_follow(&session.principal_id, registration.clone(), TimestampNs(10))?;
        assert_eq!(recovered.pending().is_none(), committed);
        assert_eq!(recovered.last_acknowledged() == Some(receipt), committed);
        let result = store.acknowledge_follow(
            &session.principal_id,
            &session.session_id,
            &registration.subscription_id,
            receipt,
            TimestampNs(10),
        )?;
        assert_eq!(result.acknowledged_anchor(), token(1));
        let second = pending(&result)?;
        let second_receipt = second.receipt();
        assert_ne!(second_receipt, receipt);
        let second = store.publish_follow_delivery(
            &session.principal_id,
            &result,
            second,
            TimestampNs(10),
        )?;
        let before_retry = store.committed_root();
        assert_eq!(
            store.acknowledge_follow(
                &session.principal_id,
                &session.session_id,
                &registration.subscription_id,
                receipt,
                TimestampNs(10),
            )?,
            second
        );
        assert_eq!(store.committed_root(), before_retry);
        assert_eq!(
            second.pending().ok_or("successor pending")?.receipt(),
            second_receipt
        );
        let mut store = restart(store)?;
        assert_eq!(
            store.register_follow(&session.principal_id, registration, TimestampNs(10))?,
            second
        );
    }
    Ok(())
}

#[test]
fn retained_delivery_geometry_cannot_skip_a_transition_or_create_an_unreadable_page() -> TestResult
{
    let (mut store, session) = opened()?;
    let state = store.register_follow(
        &session.principal_id,
        registration(&session),
        TimestampNs(10),
    )?;
    let valid = pending(&state)?;
    let mut skipped = valid.clone();
    skipped.result = token(2);
    let mut beyond_horizon = valid.clone();
    beyond_horizon.horizon = token(0);
    let mut cross_journals = valid.clone();
    cross_journals.horizon = token(2).replace(":none:", ":e1:");
    let mut wrong_site = valid.clone();
    wrong_site.horizon = token(2).replace("0123456789abcdef", "fedcba9876543210");
    let mut oversized_cursor = valid.clone();
    oversized_cursor.total_items = 2;
    oversized_cursor.next_continuation = Some("x".repeat(MAX_TOKEN_BYTES + 1));
    let before = store.committed_root();
    for mut forged in [
        skipped,
        beyond_horizon,
        cross_journals,
        wrong_site,
        oversized_cursor,
    ] {
        // Even a recomputed receipt cannot make an impossible transition admissible.
        forged.receipt = forged.computed_receipt(&state);
        assert!(
            store
                .publish_follow_delivery(&session.principal_id, &state, forged, TimestampNs(10))
                .is_err()
        );
        assert_eq!(store.committed_root(), before);
    }
    store.publish_follow_delivery(&session.principal_id, &state, valid, TimestampNs(10))?;
    Ok(())
}

#[test]
fn scope_change_and_subscription_capacity_never_rewrite_retained_progress() -> TestResult {
    let (mut store, session) = opened()?;
    let registration = registration(&session);
    let state =
        store.register_follow(&session.principal_id, registration.clone(), TimestampNs(10))?;
    let before = store.committed_root();
    let mut changed = registration.clone();
    changed.semantic_history = ContentDigest::sha256(b"changed and later closed mission facet");
    assert!(matches!(
        store.register_follow(&session.principal_id, changed, TimestampNs(10)),
        Err(DurableFollowError::StaleScope)
    ));
    assert_eq!(store.committed_root(), before);
    for index in 1..MAX_SESSION_FOLLOW_SUBSCRIPTIONS {
        let mut another = registration.clone();
        another.subscription_id = format!("subscription-{index}");
        store.register_follow(&session.principal_id, another, TimestampNs(10))?;
    }
    let before = store.committed_root();
    let mut overflow = registration.clone();
    overflow.subscription_id = "one-too-many".to_owned();
    assert!(matches!(
        store.register_follow(&session.principal_id, overflow, TimestampNs(10)),
        Err(DurableFollowError::CapacityExceeded)
    ));
    assert_eq!(store.committed_root(), before);
    assert_eq!(
        store.register_follow(&session.principal_id, registration, TimestampNs(10))?,
        state
    );
    assert_eq!(store.committed_root(), before);
    Ok(())
}
