#![forbid(unsafe_code)]

use std::error::Error;

use fss_core::AgentSession;
use fss_ledger::{AppendPhase, IncompleteTailPolicy, Journal};

use super::*;
use super::super::tests::{fixture, reopen, successor};
use crate::agent_session::checkpoint::journal::SessionAppendRecovery;
use crate::agent_session::ReferenceSessionError;

type TestResult = Result<(), Box<dyn Error>>;

fn change(session: &AgentSession, revision: &WorkspaceRevision) -> (SessionRefresh, WorkspaceWrite) {
    let mut request = successor(revision);
    request.mode = WorkspaceWriteMode::Rebase;
    request.capsule.current_anchor.commit_sequence += 1;
    request.capsule.current_anchor.state_root = ContentDigest::sha256(b"rebased-authority");
    request.capsule.situation_capsule_digest = "situation:0002".to_owned();
    request.capsule.decision_digest = "decision:0002".to_owned();
    request.capsule.epistemic_debt.extend(request.capsule.assumptions.clone());
    request.capsule.assumptions.clear();
    request.capsule.next_actions.clear();
    let refresh = SessionRefresh {
        expected_session_digest: session.session_digest(),
        current_anchor: request.capsule.current_anchor.clone(),
        capabilities: session.capabilities.clone(), privacy_scope: session.privacy_scope.clone(),
    };
    (refresh, request)
}

#[test]
fn rebase_commits_anchor_invalidation_and_workspace_in_one_record() -> TestResult {
    let (mut store, session, request) = fixture()?;
    let first = store.publish_workspace(&session.principal_id, request, TimestampNs(20))?;
    let (refresh, request) = change(&session, &first.result);
    let before = store.verify_storage()?.records;
    let result = store.rebase_workspace(&session.principal_id, refresh.clone(), request, TimestampNs(30))?;
    assert_eq!(store.verify_storage()?.records, before + 1);
    let mut store = reopen(store)?;
    let current = store.session(&session.principal_id, &session.session_id, TimestampNs(30))?;
    assert_eq!(current.current_anchor, refresh.current_anchor);
    assert_eq!(current.symbol_table_generation, session.symbol_table_generation + 1);
    assert_eq!(current.token_budget, session.token_budget);
    let resumed = store.resume_workspace(&session.principal_id, &session.session_id, result.result.digest(), TimestampNs(30))?;
    assert!(!resumed.result.rebase_required);
    assert_eq!(resumed.result.revision, result.result);
    assert_eq!(resumed.session_checkpoint_digest, result.session_checkpoint_digest);
    assert_eq!(resumed.workspace_checkpoint_digest, result.workspace_checkpoint_digest);
    assert_eq!(result.result.invalidated_actions(), first.result.capsule().next_actions.as_slice());
    assert!(result.result.capsule().next_actions.is_empty());
    assert!(result.result.capsule().assumptions.is_empty());
    assert!(result.result.capsule().epistemic_debt.contains(&"assumption:coverage".to_owned()));
    Ok(())
}

#[test]
fn refused_rebase_discards_refresh_but_durably_preserves_observed_time() -> TestResult {
    let (mut store, session, request) = fixture()?;
    let first = store.publish_workspace(&session.principal_id, request, TimestampNs(20))?;
    let (refresh, mut request) = change(&session, &first.result);
    request.capsule.open_obligations.clear();
    assert!(matches!(store.rebase_workspace(&session.principal_id, refresh, request, TimestampNs(30)),
        Err(DurableWorkspaceError::Refused(WorkspaceError::PreservationRequired))));
    let mut store = reopen(store)?;
    assert!(matches!(store.session(&session.principal_id, &session.session_id, TimestampNs(29)),
        Err(DurableSessionError::Session(ReferenceSessionError::ClockRegression))));
    assert_eq!(store.session(&session.principal_id, &session.session_id, TimestampNs(30))?, session);
    let resumed = store.resume_workspace(&session.principal_id, &session.session_id, first.result.digest(), TimestampNs(30))?;
    assert!(!resumed.result.superseded);
    assert_eq!(resumed.workspace_checkpoint_digest, first.workspace_checkpoint_digest);
    Ok(())
}

#[test]
fn failed_privacy_reprojection_cannot_half_apply_grant_revocation() -> TestResult {
    let (mut store, session, request) = fixture()?;
    let first = store.publish_workspace(&session.principal_id, request, TimestampNs(20))?;
    let (mut refresh, request) = change(&session, &first.result);
    refresh.privacy_scope.clear();
    assert!(matches!(store.rebase_workspace(&session.principal_id, refresh, request, TimestampNs(30)),
        Err(DurableWorkspaceError::Refused(WorkspaceError::Unavailable))));
    let mut store = reopen(store)?;
    assert_eq!(store.session(&session.principal_id, &session.session_id, TimestampNs(30))?, session);
    assert!(store.resume_workspace(&session.principal_id, &session.session_id, first.result.digest(), TimestampNs(30)).is_ok());
    Ok(())
}

#[test]
fn exact_retry_after_restart_and_later_work_never_reruns_old_refresh() -> TestResult {
    let (mut store, session, initial) = fixture()?;
    let first = store.publish_workspace(&session.principal_id, initial, TimestampNs(20))?;
    let (refresh, request) = change(&session, &first.result);
    let rebased = store.rebase_workspace(&session.principal_id, refresh.clone(), request.clone(), TimestampNs(30))?;
    let newer = store.publish_workspace(&session.principal_id, successor(&rebased.result), TimestampNs(30))?;
    let mut store = reopen(store)?;
    let before = store.verify_storage()?;
    let retry = store.rebase_workspace(&session.principal_id, refresh.clone(), request.clone(), TimestampNs(30))?;
    assert_eq!(retry.result, rebased.result);
    assert_eq!(retry.committed_root, newer.committed_root);
    assert_eq!(store.verify_storage()?, before);
    let current = store.session(&session.principal_id, &session.session_id, TimestampNs(30))?;
    let mut future = current.current_anchor.clone(); future.commit_sequence += 1;
    future.state_root = ContentDigest::sha256(b"third-anchor");
    store.refresh(&session.principal_id, &session.session_id, SessionRefresh {
        expected_session_digest: current.session_digest(), current_anchor: future.clone(),
        capabilities: current.capabilities, privacy_scope: current.privacy_scope,
    }, TimestampNs(40))?;
    let retry = store.rebase_workspace(&session.principal_id, refresh, request, TimestampNs(40))?;
    assert_eq!(retry.result, rebased.result);
    assert_eq!(store.session(&session.principal_id, &session.session_id, TimestampNs(40))?.current_anchor, future);
    let old = store.resume_workspace(&session.principal_id, &session.session_id, retry.result.digest(), TimestampNs(40))?;
    assert!(old.result.rebase_required);
    assert_eq!(old.result.head_digest, newer.result.digest());
    Ok(())
}

#[test]
fn changed_refresh_is_not_a_retry_even_with_the_same_capsule() -> TestResult {
    let (mut store, session, initial) = fixture()?;
    let first = store.publish_workspace(&session.principal_id, initial, TimestampNs(20))?;
    let (refresh, request) = change(&session, &first.result);
    let done = store.rebase_workspace(&session.principal_id, refresh.clone(), request.clone(), TimestampNs(30))?;
    let current = store.session(&session.principal_id, &session.session_id, TimestampNs(30))?;
    let mut changed = refresh;
    changed.expected_session_digest = current.session_digest();
    assert!(matches!(store.rebase_workspace(&session.principal_id, changed, request, TimestampNs(30)),
        Err(DurableWorkspaceError::Refused(WorkspaceError::InvalidAnchor))));
    assert_eq!(store.committed_root(), done.committed_root);
    Ok(())
}

#[test]
fn current_authority_is_rechecked_before_returning_a_committed_retry() -> TestResult {
    let (mut store, session, initial) = fixture()?;
    let first = store.publish_workspace(&session.principal_id, initial, TimestampNs(20))?;
    let (refresh, request) = change(&session, &first.result);
    store.rebase_workspace(&session.principal_id, refresh.clone(), request.clone(), TimestampNs(30))?;
    let current = store.session(&session.principal_id, &session.session_id, TimestampNs(30))?;
    store.refresh(&session.principal_id, &session.session_id, SessionRefresh {
        expected_session_digest: current.session_digest(), current_anchor: current.current_anchor,
        capabilities: BTreeSet::new(), privacy_scope: current.privacy_scope,
    }, TimestampNs(40))?;
    let mut store = reopen(store)?;
    assert!(matches!(store.rebase_workspace(&session.principal_id, refresh, request, TimestampNs(40)),
        Err(DurableWorkspaceError::Refused(WorkspaceError::Unavailable))));
    Ok(())
}

#[test]
fn expiry_during_rebase_records_tombstone_instead_of_an_anchor_move() -> TestResult {
    let (mut store, session, initial) = fixture()?;
    let first = store.publish_workspace(&session.principal_id, initial, TimestampNs(20))?;
    let (refresh, request) = change(&session, &first.result);
    assert!(matches!(store.rebase_workspace(&session.principal_id, refresh, request, TimestampNs(1000)),
        Err(DurableWorkspaceError::Refused(WorkspaceError::Session(ReferenceSessionError::Unavailable)))));
    let mut store = reopen(store)?;
    assert!(matches!(store.session(&session.principal_id, &session.session_id, TimestampNs(20)),
        Err(DurableSessionError::Session(ReferenceSessionError::Unavailable))));
    Ok(())
}

#[test]
fn stale_session_cas_and_forged_anchor_cannot_mutate_the_workspace() -> TestResult {
    for variant in 0..3 {
        let (mut store, session, initial) = fixture()?;
        let first = store.publish_workspace(&session.principal_id, initial, TimestampNs(20))?;
        let (mut refresh, mut request) = change(&session, &first.result);
        match variant {
            0 => refresh.expected_session_digest = ContentDigest::sha256(b"wrong-precondition"),
            1 => request.expected_head = Some(ContentDigest::sha256(b"wrong-head")),
            _ => {
                refresh.current_anchor.site_lineage = "site:other".to_owned();
                request.capsule.current_anchor = refresh.current_anchor.clone();
            }
        }
        assert!(store.rebase_workspace(&session.principal_id, refresh, request, TimestampNs(30)).is_err());
        let mut store = reopen(store)?;
        assert_eq!(store.session(&session.principal_id, &session.session_id, TimestampNs(30))?, session);
        let old = store.resume_workspace(&session.principal_id, &session.session_id, first.result.digest(), TimestampNs(30))?;
        assert_eq!(old.workspace_checkpoint_digest, first.workspace_checkpoint_digest);
    }
    Ok(())
}

#[test]
fn append_cut_matrix_cannot_recover_only_one_half_of_a_rebase() -> TestResult {
    for (phase, committed) in [(AppendPhase::BodyWrite, false), (AppendPhase::BodySync, false),
        (AppendPhase::CommitWrite, true), (AppendPhase::CommitSync, true)]
    {
        let (mut store, session, initial) = fixture()?;
        let first = store.publish_workspace(&session.principal_id, initial, TimestampNs(20))?;
        let (refresh, request) = change(&session, &first.result);
        let before = store.committed_root();
        store.journal.fail_after_phase(phase);
        assert!(store.rebase_workspace(&session.principal_id, refresh.clone(), request.clone(), TimestampNs(30)).is_err());
        assert!(store.needs_reconciliation());
        assert_eq!(store.reconcile_pending(IncompleteTailPolicy::Truncate)?,
            if committed { SessionAppendRecovery::Committed } else { SessionAppendRecovery::NotCommitted });
        assert_eq!(store.committed_root() != before, committed);
        let actual = store.session(&session.principal_id, &session.session_id, TimestampNs(30))?;
        assert_eq!(actual.current_anchor, if committed { refresh.current_anchor.clone() } else { session.current_anchor.clone() });
        let old = store.resume_workspace(&session.principal_id, &session.session_id, first.result.digest(), TimestampNs(30))?;
        assert_eq!(old.result.superseded, committed);
        let mut store = reopen(store)?;
        let done = store.rebase_workspace(&session.principal_id, refresh, request, TimestampNs(30))?;
        assert_eq!(done.result.capsule().revision, 1);
        store.verify_storage()?;
    }
    Ok(())
}

#[test]
fn canonical_rebase_record_truncations_and_rehashed_refresh_forgery_fail() -> TestResult {
    let (mut store, session, initial) = fixture()?;
    let first = store.publish_workspace(&session.principal_id, initial, TimestampNs(20))?;
    let (refresh, request) = change(&session, &first.result);
    let mut state = store.read_workspace_state()?.ok_or("missing workspace")?;
    let before_workspace = state.digest;
    let mut memory = store.memory.clone();
    memory.refresh(&session.principal_id, &session.session_id, refresh.clone(), TimestampNs(30))?;
    let revision = state.store.publish(&mut memory, &session.principal_id, request, TimestampNs(30))?;
    let record = RebaseRecord {
        before_session: store.checkpoint_digest, before_workspace,
        after_session: memory.checkpoint(store.limits.max_checkpoint_bytes)?.digest(),
        after_workspace: checkpoint_digest(&state.store)?, refresh,
        observed_at: TimestampNs(30), revision: revision.as_bytes(),
    };
    let payload = record.encode(store.limits)?;
    for end in 0..payload.len() { assert!(RebaseRecord::decode(&payload[..end], store.limits).is_err()); }
    let mut trailing = payload.clone(); trailing.push(0);
    assert!(RebaseRecord::decode(&trailing, store.limits).is_err());
    let mut forged = record;
    forged.refresh.expected_session_digest = ContentDigest::sha256(b"wrong-cas-with-valid-checksum");
    let bytes = forged.encode(store.limits)?;
    let path = store.path().to_path_buf(); drop(store);
    let mut raw = Journal::open(&path, IncompleteTailPolicy::Reject)?;
    raw.append(WORKSPACE_WRITE_RECORD_KIND, &bytes)?;
    let root = raw.last_root(); drop(raw);
    assert!(matches!(DurableSessionStore::open_existing(path, root, DurableSessionLimits::default()),
        Err(DurableSessionError::InvalidHistory)));
    Ok(())
}

#[test]
fn refresh_grant_decoding_is_bounded_and_rejects_duplicates() -> TestResult {
    let mut e = CanonicalEncoder::new(); e.u64(u64::MAX);
    assert!(grants(&mut CanonicalDecoder::new(&e.finish()), &mut 1, &mut 10).is_err());
    let mut e = CanonicalEncoder::new(); e.u64(2); e.text("cap:a"); e.text("cap:a");
    assert!(grants(&mut CanonicalDecoder::new(&e.finish()), &mut 2, &mut 20).is_err());
    let mut e = CanonicalEncoder::new(); e.u64(1); e.text("cap:a");
    assert!(grants(&mut CanonicalDecoder::new(&e.finish()), &mut 1, &mut 4).is_err());
    Ok(())
}
