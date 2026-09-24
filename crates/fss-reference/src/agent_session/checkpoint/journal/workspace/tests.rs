#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    AgentSession, AgentSessionParams, BudgetVector, ContractBasis, ContractBasisRegistryBytes,
    LedgerAnchor, MissionId, SessionCapsule, SessionCapsuleParams,
};
use fss_ledger::{AppendPhase, IncompleteTailPolicy, Journal};

use super::super::{ReferenceSessionError, SessionAppendRecovery, SessionRefresh};
use super::*;

type TestResult = Result<(), Box<dyn Error>>;
static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

fn unused_path() -> Result<PathBuf, Box<dyn Error>> {
    for _ in 0..128 {
        let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-workspace-journal-{}-{serial}",
            std::process::id()
        ));
        if !path.exists() {
            return Ok(path);
        }
    }
    Err("test path capacity exhausted".into())
}

fn basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(
        ContractBasisRegistryBytes::new(
            b"schemas",
            b"operations",
            b"views",
            b"capabilities",
            b"errors",
            b"costs",
            "fss-reference:workspace-journal-test",
        )
        .with_accepted_nightly("nightly-2026-08-31"),
    )
}

fn fixture_with_limits(
    limits: DurableSessionLimits,
) -> Result<(DurableSessionStore, AgentSession, WorkspaceWrite), Box<dyn Error>> {
    let mut store = DurableSessionStore::create(unused_path()?, limits)?;
    store.initialize_workspaces(WorkspaceLimits::default())?;
    let principal = PrincipalId::parse("principal:owner")?;
    let session_id = SessionId::parse("session:workspace-journal")?;
    let anchor = LedgerAnchor::genesis("site:workspace-journal");
    let session = store.open(
        AgentSessionParams {
            session_id: session_id.clone(),
            mission_id: MissionId::parse("mission:workspace-journal")?,
            principal_id: principal.clone(),
            capabilities: BTreeSet::from(["capability:read".to_owned()]),
            privacy_scope: BTreeSet::from(["private:property".to_owned()]),
            current_anchor: anchor.clone(),
            view_id: "AVIEW-001".to_owned(),
            token_budget: 100,
            symbol_table_generation: 0,
            last_acknowledged_situation_fingerprint: None,
            created_at_ns: 0,
            expires_at_ns: 1000,
        },
        basis(),
        TimestampNs(10),
    )?;
    let capsule = SessionCapsule::new(SessionCapsuleParams {
        session_id,
        revision: 0,
        principal: principal.as_str().to_owned(),
        capability_projection: vec!["capability:read".to_owned()],
        objective_digest: "objective:0001".to_owned(),
        base_anchor: anchor.clone(),
        current_anchor: anchor,
        situation_capsule_digest: "situation:0001".to_owned(),
        active_hypotheses: vec!["hypothesis:protected".to_owned()],
        assumptions: vec!["assumption:coverage".to_owned()],
        unknowns: vec!["unknown:blind-spot".to_owned()],
        not_observable_domains: vec!["domain:rear-gate".to_owned()],
        epistemic_debt: vec!["debt:calibration".to_owned()],
        open_obligations: vec!["obligation:indeterminate-alert".to_owned()],
        budget_ledger: BudgetVector::builder().tokens(100).bytes(4096).build()?,
        bookmarked_evidence: vec![ContentDigest::sha256(b"retained-source")],
        next_actions: vec!["action:review-before-dispatch".to_owned()],
        decision_digest: "decision:0001".to_owned(),
    })?;
    Ok((
        store,
        session,
        WorkspaceWrite {
            expected_head: None,
            capsule,
            mode: WorkspaceWriteMode::Advance,
        },
    ))
}
pub(super) fn fixture()
-> Result<(DurableSessionStore, AgentSession, WorkspaceWrite), Box<dyn Error>> {
    fixture_with_limits(DurableSessionLimits::default())
}
pub(super) fn successor(revision: &WorkspaceRevision) -> WorkspaceWrite {
    let mut capsule = revision.capsule().clone();
    capsule.revision += 1;
    WorkspaceWrite {
        expected_head: Some(revision.digest()),
        capsule,
        mode: WorkspaceWriteMode::Advance,
    }
}
pub(super) fn reopen(store: DurableSessionStore) -> Result<DurableSessionStore, Box<dyn Error>> {
    let path = store.path().to_path_buf();
    let root = store.committed_root();
    let limits = store.limits;
    drop(store);
    Ok(DurableSessionStore::open_existing(path, root, limits)?)
}

#[test]
fn initialization_is_one_way_and_exact_retry_never_resets_history() -> TestResult {
    let (mut store, session, request) = fixture()?;
    let first = store.publish_workspace(&session.principal_id, request, TimestampNs(20))?;
    assert_eq!(
        store.initialize_workspaces(WorkspaceLimits::default())?,
        first.committed_root
    );
    assert!(matches!(
        store.initialize_workspaces(WorkspaceLimits {
            max_workspaces: 1,
            ..WorkspaceLimits::default()
        }),
        Err(DurableWorkspaceError::LimitsMismatch)
    ));
    let mut store = reopen(store)?;
    let resumed = store.resume_workspace(
        &session.principal_id,
        &session.session_id,
        first.result.digest(),
        TimestampNs(20),
    )?;
    assert_eq!(resumed.result.revision, first.result);
    Ok(())
}

#[test]
fn publication_and_clock_are_one_record_and_recover_identically() -> TestResult {
    let (mut store, session, request) = fixture()?;
    let before = store.verify_storage()?.records;
    let result = store.publish_workspace(&session.principal_id, request, TimestampNs(20))?;
    assert_eq!(store.verify_storage()?.records, before + 1);
    let mut store = reopen(store)?;
    assert!(matches!(
        store.resume_workspace(
            &session.principal_id,
            &session.session_id,
            result.result.digest(),
            TimestampNs(19)
        ),
        Err(DurableWorkspaceError::Refused(WorkspaceError::Session(
            ReferenceSessionError::ClockRegression
        )))
    ));
    let restored = store.resume_workspace(
        &session.principal_id,
        &session.session_id,
        result.result.digest(),
        TimestampNs(20),
    )?;
    assert_eq!(
        restored.workspace_checkpoint_digest,
        result.workspace_checkpoint_digest
    );
    assert_eq!(
        restored.session_checkpoint_digest,
        result.session_checkpoint_digest
    );
    assert_eq!(restored.committed_root, result.committed_root);
    assert_eq!(restored.result.revision, result.result);
    Ok(())
}

#[test]
fn lost_ack_retry_after_restart_and_later_revision_never_rewinds_head() -> TestResult {
    let (mut store, session, request) = fixture()?;
    let first = store.publish_workspace(&session.principal_id, request.clone(), TimestampNs(20))?;
    let second = store.publish_workspace(
        &session.principal_id,
        successor(&first.result),
        TimestampNs(20),
    )?;
    let mut store = reopen(store)?;
    let records = store.verify_storage()?.records;
    let retry = store.publish_workspace(&session.principal_id, request, TimestampNs(20))?;
    assert_eq!(retry.result, first.result);
    assert_eq!(retry.committed_root, second.committed_root);
    assert_eq!(store.verify_storage()?.records, records);
    let old = store.resume_workspace(
        &session.principal_id,
        &session.session_id,
        first.result.digest(),
        TimestampNs(20),
    )?;
    assert!(old.result.superseded);
    assert_eq!(old.result.head_digest, second.result.digest());
    Ok(())
}

#[test]
fn omission_refusal_preserves_clock_without_publishing_a_revision() -> TestResult {
    let (mut store, session, request) = fixture()?;
    let first = store.publish_workspace(&session.principal_id, request, TimestampNs(20))?;
    let mut bad = successor(&first.result);
    bad.capsule.open_obligations.clear();
    assert!(matches!(
        store.publish_workspace(&session.principal_id, bad, TimestampNs(30)),
        Err(DurableWorkspaceError::Refused(
            WorkspaceError::PreservationRequired
        ))
    ));
    let mut store = reopen(store)?;
    assert!(matches!(
        store.session(&session.principal_id, &session.session_id, TimestampNs(29)),
        Err(DurableSessionError::Session(
            ReferenceSessionError::ClockRegression
        ))
    ));
    let resumed = store.resume_workspace(
        &session.principal_id,
        &session.session_id,
        first.result.digest(),
        TimestampNs(30),
    )?;
    assert!(!resumed.result.superseded);
    assert_eq!(
        resumed.workspace_checkpoint_digest,
        first.workspace_checkpoint_digest
    );
    Ok(())
}

#[test]
fn expiry_refusal_is_durable_and_never_reopens_the_session() -> TestResult {
    let (mut store, session, request) = fixture()?;
    let first = store.publish_workspace(&session.principal_id, request, TimestampNs(20))?;
    assert!(matches!(
        store.resume_workspace(
            &session.principal_id,
            &session.session_id,
            first.result.digest(),
            TimestampNs(1000)
        ),
        Err(DurableWorkspaceError::Refused(WorkspaceError::Session(
            ReferenceSessionError::Unavailable
        )))
    ));
    let mut store = reopen(store)?;
    assert!(matches!(
        store.resume_workspace(
            &session.principal_id,
            &session.session_id,
            first.result.digest(),
            TimestampNs(20)
        ),
        Err(DurableWorkspaceError::Refused(WorkspaceError::Session(
            ReferenceSessionError::Unavailable
        )))
    ));
    Ok(())
}

#[test]
fn revoked_grants_block_restored_history_and_exact_retries() -> TestResult {
    let (mut store, session, request) = fixture()?;
    let first = store.publish_workspace(&session.principal_id, request.clone(), TimestampNs(20))?;
    store.refresh(
        &session.principal_id,
        &session.session_id,
        SessionRefresh {
            expected_session_digest: session.session_digest(),
            current_anchor: session.current_anchor.clone(),
            capabilities: BTreeSet::new(),
            privacy_scope: session.privacy_scope.clone(),
        },
        TimestampNs(30),
    )?;
    let mut store = reopen(store)?;
    assert!(matches!(
        store.resume_workspace(
            &session.principal_id,
            &session.session_id,
            first.result.digest(),
            TimestampNs(30)
        ),
        Err(DurableWorkspaceError::Refused(WorkspaceError::Unavailable))
    ));
    assert!(
        store
            .publish_workspace(&session.principal_id, request, TimestampNs(30))
            .is_err()
    );
    Ok(())
}

#[test]
fn wrong_principal_and_unknown_revision_never_disclose_history() -> TestResult {
    let (mut store, session, request) = fixture()?;
    let first = store.publish_workspace(&session.principal_id, request, TimestampNs(20))?;
    let stranger = PrincipalId::parse("principal:stranger")?;
    let before = store.committed_root();
    let wrong = store.resume_workspace(
        &stranger,
        &session.session_id,
        first.result.digest(),
        TimestampNs(30),
    );
    let absent = store.resume_workspace(
        &stranger,
        &session.session_id,
        ContentDigest::sha256(b"absent"),
        TimestampNs(30),
    );
    assert_eq!(
        wrong.err().ok_or("expected refusal")?.to_string(),
        absent.err().ok_or("expected refusal")?.to_string()
    );
    assert_eq!(store.committed_root(), before);
    Ok(())
}

#[test]
fn every_append_phase_withholds_revision_and_reconciles_both_states() -> TestResult {
    for (phase, committed) in [
        (AppendPhase::BodyWrite, false),
        (AppendPhase::BodySync, false),
        (AppendPhase::CommitWrite, true),
        (AppendPhase::CommitSync, true),
    ] {
        let (mut store, session, request) = fixture()?;
        let mut reference_sessions = store.memory.clone();
        let mut reference = ReferenceWorkspaceStore::default();
        let expected = reference.publish(
            &mut reference_sessions,
            &session.principal_id,
            request.clone(),
            TimestampNs(20),
        )?;
        let before = store.committed_root();
        store.journal.fail_after_phase(phase);
        assert!(matches!(
            store.publish_workspace(&session.principal_id, request.clone(), TimestampNs(20)),
            Err(DurableWorkspaceError::Durability(
                DurableSessionError::Journal(_)
            ))
        ));
        assert!(store.needs_reconciliation());
        assert!(
            store
                .resume_workspace(
                    &session.principal_id,
                    &session.session_id,
                    expected.digest(),
                    TimestampNs(20)
                )
                .is_err()
        );
        if !committed {
            let bytes = std::fs::read(store.path())?;
            assert!(
                store
                    .reconcile_pending(IncompleteTailPolicy::Reject)
                    .is_err()
            );
            assert_eq!(std::fs::read(store.path())?, bytes);
        }
        assert_eq!(
            store.reconcile_pending(IncompleteTailPolicy::Truncate)?,
            if committed {
                SessionAppendRecovery::Committed
            } else {
                SessionAppendRecovery::NotCommitted
            }
        );
        assert_eq!(store.committed_root() != before, committed);
        let resumed = store.resume_workspace(
            &session.principal_id,
            &session.session_id,
            expected.digest(),
            TimestampNs(20),
        );
        if committed {
            assert_eq!(resumed?.result.revision, expected);
        } else {
            assert!(resumed.is_err());
        }
        let retry = store.publish_workspace(&session.principal_id, request, TimestampNs(20))?;
        assert_eq!(retry.result, expected);
        store.verify_storage()?;
    }
    Ok(())
}

#[test]
fn capacity_failure_cannot_acknowledge_an_uncommitted_workspace() -> TestResult {
    let (mut store, session, request) = fixture_with_limits(DurableSessionLimits {
        max_records: 3,
        ..DurableSessionLimits::default()
    })?;
    let bytes = std::fs::read(store.path())?;
    assert!(matches!(
        store.publish_workspace(&session.principal_id, request, TimestampNs(20)),
        Err(DurableWorkspaceError::Durability(
            DurableSessionError::CapacityExceeded
        ))
    ));
    assert!(store.needs_reconciliation());
    assert_eq!(std::fs::read(store.path())?, bytes);
    Ok(())
}

#[test]
fn rehashed_forged_after_state_and_duplicate_initialization_are_rejected() -> TestResult {
    for bad_init in [false, true] {
        let (mut store, session, request) = fixture()?;
        let state = store.read_workspace_state()?.ok_or("missing state")?;
        let payload = if bad_init {
            encode_init(
                store.checkpoint_digest,
                WorkspaceLimits::default(),
                state.digest,
            )?
        } else {
            let mut reference = state.store.clone();
            let mut memory = store.memory.clone();
            let revision =
                reference.publish(&mut memory, &session.principal_id, request, TimestampNs(20))?;
            encode_write(
                store.checkpoint_digest,
                state.digest,
                ContentDigest::sha256(b"forged-session"),
                checkpoint_digest(&reference)?,
                WorkspaceWriteMode::Advance,
                TimestampNs(20),
                revision.as_bytes(),
            )?
        };
        let path = store.path().to_path_buf();
        drop(store);
        let mut raw = Journal::open(&path, IncompleteTailPolicy::Reject)?;
        raw.append(
            if bad_init {
                WORKSPACE_INIT_RECORD_KIND
            } else {
                WORKSPACE_WRITE_RECORD_KIND
            },
            &payload,
        )?;
        let root = raw.last_root();
        drop(raw);
        assert!(matches!(
            DurableSessionStore::open_existing(path, root, DurableSessionLimits::default()),
            Err(DurableSessionError::InvalidHistory)
        ));
    }
    Ok(())
}

#[test]
fn write_records_are_replayed_not_trusted_as_snapshots() -> TestResult {
    let (mut store, session, request) = fixture()?;
    let state = store.read_workspace_state()?.ok_or("missing state")?;
    let mut reference = state.store.clone();
    let mut memory = store.memory.clone();
    let revision =
        reference.publish(&mut memory, &session.principal_id, request, TimestampNs(20))?;
    let payload = encode_write(
        store.checkpoint_digest,
        state.digest,
        memory
            .checkpoint(store.limits.max_checkpoint_bytes)?
            .digest(),
        checkpoint_digest(&reference)?,
        WorkspaceWriteMode::Advance,
        TimestampNs(20),
        revision.as_bytes(),
    )?;
    for end in 0..payload.len() {
        let mut memory = store.memory.clone();
        let mut state = Some(state.clone());
        assert!(replay_write(&payload[..end], &mut memory, &mut state, store.limits).is_err());
    }
    let mut trailing = payload.clone();
    trailing.push(0);
    assert!(
        replay_write(
            &trailing,
            &mut store.memory.clone(),
            &mut Some(state),
            store.limits
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn head_names_the_exact_latest_revision_and_refuses_other_principals() -> TestResult {
    let (mut store, session, request) = fixture()?;
    assert!(matches!(
        store.workspace_head(&session.principal_id, &session.session_id, TimestampNs(15)),
        Err(DurableWorkspaceError::Refused(WorkspaceError::Unavailable))
    ));
    let first = store.publish_workspace(&session.principal_id, request, TimestampNs(20))?;
    let second = store.publish_workspace(
        &session.principal_id,
        successor(&first.result),
        TimestampNs(21),
    )?;
    let mut store = reopen(store)?;
    let head = store.workspace_head(&session.principal_id, &session.session_id, TimestampNs(22))?;
    assert_eq!(head.result.head_digest, second.result.digest());
    assert_eq!(head.result.revision, second.result);
    assert!(!head.result.superseded && !head.result.rebase_required);
    let stranger = PrincipalId::parse("principal:stranger")?;
    assert!(matches!(
        store.workspace_head(&stranger, &session.session_id, TimestampNs(23)),
        Err(DurableWorkspaceError::Refused(WorkspaceError::Session(
            ReferenceSessionError::Unavailable
        )))
    ));
    Ok(())
}
