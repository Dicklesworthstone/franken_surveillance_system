#![forbid(unsafe_code)]

use std::error::Error;

use fss_core::{AgentSessionParams, BudgetVector, ContractBasisRegistryBytes};

use super::*;
use crate::SessionRefresh;

type TestResult = Result<(), Box<dyn Error>>;

fn basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(
        ContractBasisRegistryBytes::new(
            b"schemas", b"operations", b"views", b"capabilities", b"errors", b"costs",
            "fss-reference:workspace-test",
        )
        .with_accepted_nightly("nightly-2026-08-31"),
    )
}

struct Fixture {
    sessions: ReferenceSessionStore,
    workspaces: ReferenceWorkspaceStore,
    principal: PrincipalId,
    capsule: SessionCapsule,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let principal = PrincipalId::parse("principal:owner")?;
        let session_id = SessionId::parse("session:workspace-test")?;
        let anchor = LedgerAnchor::genesis("site:workspace-test");
        let mut sessions = ReferenceSessionStore::default();
        sessions.open(AgentSessionParams {
            session_id: session_id.clone(),
            mission_id: MissionId::parse("mission:workspace-test")?,
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
        }, basis(), TimestampNs(10))?;
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
        Ok(Self { sessions, workspaces: ReferenceWorkspaceStore::default(), principal, capsule })
    }

    fn write(&mut self, write: WorkspaceWrite) -> Result<WorkspaceRevision, WorkspaceError> {
        self.workspaces.publish(&mut self.sessions, &self.principal, write, TimestampNs(20))
    }

    fn initial(&self) -> WorkspaceWrite {
        WorkspaceWrite { expected_head: None, capsule: self.capsule.clone(), mode: WorkspaceWriteMode::Advance }
    }

    fn append(&self, previous: &WorkspaceRevision) -> WorkspaceWrite {
        let mut capsule = previous.capsule.clone();
        capsule.revision += 1;
        WorkspaceWrite { expected_head: Some(previous.digest), capsule, mode: WorkspaceWriteMode::Advance }
    }

    fn move_anchor(&mut self) -> Result<LedgerAnchor, Box<dyn Error>> {
        let session = self.sessions.session(&self.principal, &self.capsule.session_id, TimestampNs(20))?;
        let mut anchor = session.current_anchor.clone();
        anchor.commit_sequence += 1;
        anchor.state_root = ContentDigest::sha256(b"successor");
        self.sessions.refresh(&self.principal, &self.capsule.session_id, SessionRefresh {
            expected_session_digest: session.session_digest(),
            current_anchor: anchor.clone(),
            capabilities: session.capabilities.clone(),
            privacy_scope: session.privacy_scope.clone(),
        }, TimestampNs(20))?;
        Ok(anchor)
    }
}

#[test]
fn exact_retry_does_not_append_or_spend_storage() -> TestResult {
    let mut f = Fixture::new()?;
    let request = f.initial();
    let first = f.write(request.clone())?;
    let bytes = f.workspaces.retained_bytes();
    let second = f.write(request)?;
    assert_eq!(first, second);
    assert_eq!(f.workspaces.retained_bytes(), bytes);
    assert_eq!(first.digest(), ContentDigest::sha256(first.as_bytes()));
    Ok(())
}

#[test]
fn stale_writer_and_identity_reuse_cannot_overwrite() -> TestResult {
    let mut f = Fixture::new()?;
    let first = f.write(f.initial())?;
    let request = f.append(&first);
    let second = f.write(request.clone())?;
    let mut conflicting = request;
    conflicting.capsule.unknowns.push("unknown:competing-write".to_owned());
    assert!(matches!(f.write(conflicting), Err(WorkspaceError::StaleHead)));
    let mut skipped = f.append(&second);
    skipped.capsule.revision += 1;
    assert!(matches!(f.write(skipped), Err(WorkspaceError::InvalidRevision)));
    let mut stale = f.append(&second);
    stale.expected_head = Some(first.digest());
    assert!(matches!(f.write(stale), Err(WorkspaceError::StaleHead)));
    let old = f.workspaces.resume(&mut f.sessions, &f.principal, &f.capsule.session_id, first.digest(), TimestampNs(20))?;
    assert!(old.superseded);
    assert!(!old.rebase_required);
    assert_eq!(old.revision, first);
    assert_eq!(old.head_digest, second.digest());
    Ok(())
}

#[test]
fn retry_of_earlier_revision_never_rewinds_head() -> TestResult {
    let mut f = Fixture::new()?;
    let request = f.initial();
    let first = f.write(request.clone())?;
    let second = f.write(f.append(&first))?;
    assert_eq!(f.write(request)?, first);
    let resumed = f.workspaces.resume(&mut f.sessions, &f.principal, &f.capsule.session_id, first.digest(), TimestampNs(20))?;
    assert_eq!(resumed.head_digest, second.digest());
    Ok(())
}

#[test]
fn every_protected_omission_is_refused_atomically() -> TestResult {
    let mut f = Fixture::new()?;
    let first = f.write(f.initial())?;
    let bytes = f.workspaces.retained_bytes();
    for field in 0..7 {
        let mut request = f.append(&first);
        match field {
            0 => request.capsule.unknowns.clear(),
            1 => request.capsule.not_observable_domains.clear(),
            2 => request.capsule.epistemic_debt.clear(),
            3 => request.capsule.open_obligations.clear(),
            4 => request.capsule.bookmarked_evidence.clear(),
            5 => request.capsule.assumptions.clear(),
            _ => request.capsule.active_hypotheses.clear(),
        }
        assert!(matches!(f.write(request), Err(WorkspaceError::PreservationRequired)));
        assert_eq!(f.workspaces.retained_bytes(), bytes);
    }
    Ok(())
}

#[test]
fn rebase_is_explicit_and_retains_invalidated_actions() -> TestResult {
    let mut f = Fixture::new()?;
    let first = f.write(f.initial())?;
    let anchor = f.move_anchor()?;
    let stale = f.workspaces.resume(&mut f.sessions, &f.principal, &f.capsule.session_id, first.digest(), TimestampNs(20))?;
    assert!(stale.rebase_required);
    let mut request = f.append(&first);
    request.capsule.current_anchor = anchor;
    assert!(matches!(f.write(request.clone()), Err(WorkspaceError::RebaseRequired)));
    request.mode = WorkspaceWriteMode::Rebase;
    assert!(matches!(f.write(request.clone()), Err(WorkspaceError::PreservationRequired)));
    request.capsule.situation_capsule_digest = "situation:0002".to_owned();
    request.capsule.decision_digest = "decision:0002".to_owned();
    request.capsule.epistemic_debt.extend(first.capsule.assumptions.clone());
    request.capsule.next_actions.clear();
    let rebased = f.write(request.clone())?;
    assert_eq!(rebased.invalidated_actions(), first.capsule.next_actions.as_slice());
    assert!(rebased.capsule.next_actions.is_empty());
    assert_eq!(rebased.capsule.open_obligations, first.capsule.open_obligations);
    assert_eq!(f.write(request)?, rebased);
    Ok(())
}

#[test]
fn wrong_principal_expiry_and_closed_session_cannot_read_or_write() -> TestResult {
    let mut f = Fixture::new()?;
    let first = f.write(f.initial())?;
    let wrong = PrincipalId::parse("principal:other")?;
    assert!(matches!(f.workspaces.resume(&mut f.sessions, &wrong, &f.capsule.session_id, first.digest(), TimestampNs(20)), Err(WorkspaceError::Session(_))));
    assert!(matches!(f.workspaces.resume(&mut f.sessions, &f.principal, &f.capsule.session_id, first.digest(), TimestampNs(1000)), Err(WorkspaceError::Session(_))));
    assert!(matches!(f.write(f.initial()), Err(WorkspaceError::Session(_))));
    Ok(())
}

#[test]
fn narrowed_privacy_denies_even_an_exact_retry() -> TestResult {
    let mut f = Fixture::new()?;
    let request = f.initial();
    let first = f.write(request.clone())?;
    let session = f.sessions.session(&f.principal, &f.capsule.session_id, TimestampNs(20))?;
    f.sessions.refresh(&f.principal, &f.capsule.session_id, SessionRefresh {
        expected_session_digest: session.session_digest(),
        current_anchor: session.current_anchor.clone(),
        capabilities: session.capabilities.clone(),
        privacy_scope: BTreeSet::new(),
    }, TimestampNs(20))?;
    assert!(matches!(f.write(request), Err(WorkspaceError::Unavailable)));
    assert!(matches!(f.workspaces.resume(&mut f.sessions, &f.principal, &f.capsule.session_id, first.digest(), TimestampNs(20)), Err(WorkspaceError::Unavailable)));
    Ok(())
}

#[test]
fn zero_capacity_and_revision_exhaustion_are_not_unlimited() -> TestResult {
    let mut f = Fixture::new()?;
    f.workspaces = ReferenceWorkspaceStore::with_limits(WorkspaceLimits { max_workspaces: 0, ..WorkspaceLimits::default() });
    assert!(matches!(f.write(f.initial()), Err(WorkspaceError::CapacityExceeded)));
    f.workspaces = ReferenceWorkspaceStore::with_limits(WorkspaceLimits { max_revisions_per_workspace: 1, ..WorkspaceLimits::default() });
    let request = f.initial();
    let first = f.write(request.clone())?;
    assert_eq!(f.write(request)?, first);
    assert!(matches!(f.write(f.append(&first)), Err(WorkspaceError::CapacityExceeded)));
    Ok(())
}

#[test]
fn oversized_and_mutated_capsules_cannot_enter_history() -> TestResult {
    let mut f = Fixture::new()?;
    let mut request = f.initial();
    request.capsule.unknowns = vec!["x".repeat(MAX_ITEM_BYTES + 1)];
    assert!(matches!(f.write(request), Err(WorkspaceError::CapacityExceeded)));
    let mut request = f.initial();
    request.capsule.decision_digest = "INVALID".to_owned();
    assert!(matches!(f.write(request), Err(WorkspaceError::Contract(_))));
    assert_eq!(f.workspaces.retained_bytes(), 0);
    Ok(())
}

#[test]
fn equal_sequence_fork_and_independent_epoch_regression_are_refused() -> TestResult {
    let mut old = LedgerAnchor::genesis("site:fork-test");
    old.commit_sequence = 8;
    old.adapter_registry_epoch = 4;
    let mut fork = old.clone();
    fork.state_root = ContentDigest::sha256(b"fork");
    assert!(!anchor_successor(&old, &fork));
    fork.commit_sequence = 9;
    fork.adapter_registry_epoch = 3;
    assert!(!anchor_successor(&old, &fork));
    fork.adapter_registry_epoch = 4;
    assert!(anchor_successor(&old, &fork));
    fork.site_lineage = "site:other".to_owned();
    assert!(!anchor_successor(&old, &fork));
    Ok(())
}

#[test]
fn deterministic_replay_produces_identical_revision_roots() -> TestResult {
    let mut left = Fixture::new()?;
    let mut right = Fixture::new()?;
    let a = left.write(left.initial())?;
    let b = right.write(right.initial())?;
    assert_eq!(a, b);
    let a2 = left.write(left.append(&a))?;
    let b2 = right.write(right.append(&b))?;
    assert_eq!(a2, b2);
    Ok(())
}
