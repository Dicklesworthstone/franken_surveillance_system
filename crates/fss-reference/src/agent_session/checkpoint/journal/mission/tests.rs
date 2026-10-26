#![forbid(unsafe_code)]
//! Real shared-journal persistence and failure cuts over explicitly synthetic custody facts.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    AgentSession, BudgetVector, MissionLifecycleState, SessionCapsule, SessionCapsuleParams,
};
use fss_ledger::{AppendPhase, IncompleteTailPolicy, Journal};

use super::*;
use crate::agent_session::checkpoint::journal::{SessionAppendRecovery, inspect_session_bytes};
use crate::agent_session::mission::tests::{basis, criterion, facts, params};
use crate::agent_session::work_claims::WorkClaimLimits;
use crate::agent_session::workspace::{WorkspaceLimits, WorkspaceWrite, WorkspaceWriteMode};
use crate::agent_session::{ReferenceSessionError, SessionRefresh};

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;
static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

fn unused_path() -> TestResult<PathBuf> {
    for _ in 0..128 {
        let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-mission-journal-{}-{serial}",
            std::process::id()
        ));
        if !path.exists() {
            return Ok(path);
        }
    }
    Err("bounded mission fixture paths exhausted".into())
}

fn opened() -> TestResult<(DurableSessionStore, AgentSession, MissionPlanCriterion)> {
    let mut store = DurableSessionStore::create(unused_path()?, DurableSessionLimits::default())?;
    store.initialize_workspaces(WorkspaceLimits::default())?;
    let session = store.open(params()?, basis(), TimestampNs(10))?;
    let criterion = criterion(&session)?;
    let capsule = SessionCapsule::new(SessionCapsuleParams {
        session_id: session.session_id.clone(),
        revision: 0,
        principal: session.principal_id.as_str().to_owned(),
        capability_projection: session.capabilities.iter().cloned().collect(),
        objective_digest: criterion.mission_record_digest.to_text(),
        base_anchor: session.current_anchor.clone(),
        current_anchor: session.current_anchor.clone(),
        situation_capsule_digest: ContentDigest::sha256(b"synthetic initial situation").to_text(),
        active_hypotheses: Vec::new(),
        assumptions: Vec::new(),
        unknowns: vec!["Physical threat remains unverified.".to_owned()],
        not_observable_domains: Vec::new(),
        epistemic_debt: Vec::new(),
        open_obligations: Vec::new(),
        budget_ledger: BudgetVector::builder()
            .tokens(session.token_budget)
            .bytes(4096)
            .build()?,
        bookmarked_evidence: Vec::new(),
        next_actions: Vec::new(),
        decision_digest: ContentDigest::sha256(b"synthetic initial decision").to_text(),
    })?;
    store.publish_workspace(
        &session.principal_id,
        WorkspaceWrite {
            expected_head: None,
            capsule,
            mode: WorkspaceWriteMode::Advance,
        },
        TimestampNs(10),
    )?;
    Ok((store, session, criterion))
}

fn reopened(store: DurableSessionStore) -> TestResult<DurableSessionStore> {
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
fn shared_replay_retains_exact_history_and_retries_never_append_or_refill() -> TestResult {
    let (mut store, session, c) = opened()?;
    assert!(
        store
            .mission_head_for_projection(&session, TimestampNs(10))?
            .is_none()
    );
    let first = store.register_mission_plan(&session.principal_id, c.clone(), TimestampNs(10))?;
    let second = store.assess_mission_plan(
        &session.principal_id,
        &session.session_id,
        c.mission_record_digest,
        first.digest(),
        facts(&c),
        TimestampNs(10),
    )?;
    assert_eq!(second.state(), MissionLifecycleState::Resolved);
    let before = fs::read(store.path())?;
    let snapshot = inspect_session_bytes(
        &before,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    assert_eq!(snapshot.missions, vec![first.clone(), second.clone()]);
    let mut store = reopened(store)?;
    assert_eq!(
        store.register_mission_plan(&session.principal_id, c.clone(), TimestampNs(10))?,
        second
    );
    assert_eq!(
        store.assess_mission_plan(
            &session.principal_id,
            &session.session_id,
            c.mission_record_digest,
            first.digest(),
            facts(&c),
            TimestampNs(10)
        )?,
        second
    );
    assert_eq!(
        store.mission_head_for_projection(&session, TimestampNs(10))?,
        Some(second.clone())
    );
    assert_eq!(
        store.mission_history(
            &session.principal_id,
            &session.session_id,
            c.mission_record_digest,
            TimestampNs(10)
        )?,
        vec![first, second]
    );
    assert_eq!(fs::read(store.path())?, before);
    assert_eq!(
        store.remaining_token_budget(
            &session.principal_id,
            &session.session_id,
            TimestampNs(10)
        )?,
        session.token_budget
    );
    Ok(())
}

#[test]
fn every_append_cut_withholds_uncommitted_terminal_state_and_replays_once() -> TestResult {
    for (phase, committed) in [
        (AppendPhase::BodyWrite, false),
        (AppendPhase::BodySync, false),
        (AppendPhase::CommitWrite, true),
        (AppendPhase::CommitSync, true),
    ] {
        let (mut store, session, c) = opened()?;
        let first =
            store.register_mission_plan(&session.principal_id, c.clone(), TimestampNs(10))?;
        let before_root = store.committed_root();
        store.journal.fail_after_phase(phase);
        assert!(
            store
                .assess_mission_plan(
                    &session.principal_id,
                    &session.session_id,
                    c.mission_record_digest,
                    first.digest(),
                    facts(&c),
                    TimestampNs(10)
                )
                .is_err()
        );
        assert!(store.needs_reconciliation());
        assert!(matches!(
            store.mission_head_for_projection(&session, TimestampNs(10)),
            Err(DurableMissionError::Durability(
                DurableSessionError::ReconciliationRequired
            ))
        ));
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
        assert_eq!(store.committed_root() != before_root, committed);
        let mut store = reopened(store)?;
        let retained = store.mission_history(
            &session.principal_id,
            &session.session_id,
            c.mission_record_digest,
            TimestampNs(10),
        )?;
        assert_eq!(retained.len(), if committed { 2 } else { 1 });
        assert_eq!(
            retained
                .last()
                .ok_or("retained mission")?
                .state()
                .is_terminal(),
            committed
        );
        let terminal = store.assess_mission_plan(
            &session.principal_id,
            &session.session_id,
            c.mission_record_digest,
            first.digest(),
            facts(&c),
            TimestampNs(10),
        )?;
        assert_eq!(terminal.state(), MissionLifecycleState::Resolved);
        assert_eq!(
            store
                .mission_history(
                    &session.principal_id,
                    &session.session_id,
                    c.mission_record_digest,
                    TimestampNs(10)
                )?
                .len(),
            2
        );
    }
    Ok(())
}

#[test]
fn semantic_replay_rejects_hash_valid_fabricated_state_and_unknown_command() -> TestResult {
    for unknown in [false, true] {
        let (mut store, session, c) = opened()?;
        let first =
            store.register_mission_plan(&session.principal_id, c.clone(), TimestampNs(10))?;
        let restored = store.read_mission_history()?;
        let mut payload = encode(&Record {
            principal: session.principal_id.clone(),
            session: session.session_id.clone(),
            now: TimestampNs(10),
            session_digest: store.checkpoint_digest,
            before_state: restored.missions.digest(),
            after_state: ContentDigest::sha256(b"fabricated terminal owner state"),
            command: Command::Assess {
                mission_record_digest: c.mission_record_digest,
                expected_head: first.digest(),
                facts: facts(&c),
            },
        })?;
        if unknown {
            payload.push(0);
        }
        let path = store.path().to_path_buf();
        drop(store);
        let mut raw = Journal::open(&path, IncompleteTailPolicy::Reject)?;
        raw.append(MISSION_COMMAND_RECORD_KIND, &payload)?;
        drop(raw);
        assert!(
            inspect_session_bytes(
                &fs::read(&path)?,
                DurableSessionLimits::default(),
                WorkClaimLimits::default()
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn original_workspace_record_and_current_authority_gate_every_read_or_write() -> TestResult {
    let (mut store, session, c) = opened()?;
    let original_bytes = fs::read(store.path())?;
    let mut wrong = c.clone();
    wrong.mission_record_digest = ContentDigest::sha256(b"another mission record");
    assert!(matches!(
        store.register_mission_plan(&session.principal_id, wrong, TimestampNs(10)),
        Err(DurableMissionError::Refused(MissionError::ScopeMismatch))
    ));
    assert_eq!(fs::read(store.path())?, original_bytes);
    store.register_mission_plan(&session.principal_id, c.clone(), TimestampNs(10))?;
    let before = fs::read(store.path())?;
    let mut forged = session.clone();
    forged.token_budget += 1;
    assert!(matches!(
        store.mission_head_for_projection(&forged, TimestampNs(10)),
        Err(DurableMissionError::Refused(MissionError::ScopeMismatch))
    ));
    assert!(
        store
            .mission_head_for_projection(&session, TimestampNs(20))?
            .is_some()
    );
    assert_eq!(fs::read(store.path())?, before);
    let refreshed = store.refresh(
        &session.principal_id,
        &session.session_id,
        SessionRefresh {
            expected_session_digest: session.session_digest(),
            current_anchor: session.current_anchor.clone(),
            capabilities: session.capabilities.clone(),
            privacy_scope: BTreeSet::new(),
        },
        TimestampNs(20),
    )?;
    assert!(matches!(
        store.mission_head_for_projection(&refreshed, TimestampNs(20)),
        Err(DurableMissionError::Refused(MissionError::Unauthorized))
    ));
    assert!(matches!(
        store.mission_head(
            &session.principal_id,
            &session.session_id,
            c.mission_record_digest,
            TimestampNs(30)
        ),
        Err(DurableMissionError::Refused(MissionError::Unauthorized))
    ));
    assert!(matches!(
        store.mission_head(
            &session.principal_id,
            &session.session_id,
            c.mission_record_digest,
            TimestampNs(10_000)
        ),
        Err(DurableMissionError::Durability(
            DurableSessionError::Session(ReferenceSessionError::Unavailable)
        ))
    ));
    let inspected = inspect_session_bytes(
        &fs::read(store.path())?,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    assert_eq!(inspected.missions.len(), 1);
    assert!(inspected.sessions.first().ok_or("retained session")?.closed);
    assert_eq!(
        inspected
            .sessions
            .first()
            .ok_or("retained session")?
            .last_observed_at,
        TimestampNs(10_000)
    );
    Ok(())
}

#[test]
fn later_supervision_and_workspace_reads_preserve_mission_family() -> TestResult {
    use super::super::supervision::SupervisionRegistration;
    let (mut store, session, c) = opened()?;
    let before = store.follow_semantic_journal_root()?;
    let first = store.register_mission_plan(&session.principal_id, c.clone(), TimestampNs(10))?;
    assert_ne!(store.follow_semantic_journal_root()?, before);
    let configuration = b"synthetic supervision configuration".to_vec();
    store.register_supervision(
        &session.principal_id,
        SupervisionRegistration {
            session_id: session.session_id.clone(),
            subscription_id: "fixture".to_owned(),
            configuration_digest: ContentDigest::sha256(&configuration),
            configuration,
            max_read_bytes: 100,
            max_read_attempts: 1,
            maximum_attempts: 1,
            max_report_bytes: 100,
        },
        TimestampNs(10),
    )?;
    let workspace =
        store.workspace_head(&session.principal_id, &session.session_id, TimestampNs(10))?;
    assert_eq!(
        workspace.result.revision.capsule().objective_digest,
        c.mission_record_digest.to_text()
    );
    assert_eq!(
        store.mission_head_for_projection(&session, TimestampNs(10))?,
        Some(first)
    );
    let inspected = inspect_session_bytes(
        &fs::read(store.path())?,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    assert_eq!(inspected.missions.len(), 1);
    assert_eq!(inspected.supervisions.len(), 1);
    Ok(())
}

#[test]
fn projection_and_history_preserve_read_only_legacy_authority() -> TestResult {
    for enrolled in [false, true] {
        let (mut store, session, c) = opened()?;
        let expected = if enrolled {
            Some(store.register_mission_plan(&session.principal_id, c.clone(), TimestampNs(10))?)
        } else {
            None
        };
        let mut capabilities = session.capabilities.clone();
        capabilities.remove("CAP-AGENT-SESSION-WRITE-001");
        capabilities.remove("CAP-AGENT-PLAN-PREPARE-001");
        let narrowed = store.refresh(
            &session.principal_id,
            &session.session_id,
            SessionRefresh {
                expected_session_digest: session.session_digest(),
                current_anchor: session.current_anchor.clone(),
                capabilities,
                privacy_scope: session.privacy_scope.clone(),
            },
            TimestampNs(20),
        )?;
        let before = fs::read(store.path())?;
        assert_eq!(
            store.mission_head_for_projection(&narrowed, TimestampNs(20))?,
            expected
        );
        assert_eq!(fs::read(store.path())?, before);
        assert_eq!(
            store.mission_head(
                &session.principal_id,
                &session.session_id,
                c.mission_record_digest,
                TimestampNs(20)
            )?,
            expected
        );
        assert!(matches!(
            store.register_mission_plan(&session.principal_id, c, TimestampNs(20)),
            Err(DurableMissionError::Refused(MissionError::Unauthorized))
        ));
        assert_eq!(fs::read(store.path())?, before);
    }
    Ok(())
}
