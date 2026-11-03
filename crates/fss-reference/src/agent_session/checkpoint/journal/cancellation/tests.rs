#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{AgentSession, AgentSessionParams, MissionId};
use fss_ledger::{AppendPhase, IncompleteTailPolicy};

use super::*;
use crate::agent_session::checkpoint::journal::{
    SessionAppendRecovery, inspect_session_bytes, read_report,
};
use crate::agent_session::work_claims::WorkClaimLimits;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    path: PathBuf,
    store: DurableSessionStore,
    session: AgentSession,
}
impl Fixture {
    fn new() -> TestResult<Self> {
        let path = std::env::temp_dir().join(format!(
            "fss-session-cancel-{}-{}.journal",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut store = DurableSessionStore::create(&path, DurableSessionLimits::default())?;
        let session = store.open(
            AgentSessionParams {
                session_id: SessionId::parse("session:cancel-test")?,
                mission_id: MissionId::parse("mission:cancel-test")?,
                principal_id: PrincipalId::parse("principal:owner")?,
                capabilities: BTreeSet::from(["CAP-AGENT-SESSION-READ-001".into()]),
                privacy_scope: BTreeSet::from(["private:property".into()]),
                current_anchor: LedgerAnchor::genesis("site:cancel-test"),
                view_id: "AVIEW-002".into(),
                token_budget: 1000,
                symbol_table_generation: 0,
                last_acknowledged_situation_fingerprint: None,
                created_at_ns: 0,
                expires_at_ns: 1000,
            },
            fss_core::reference_contract_basis(),
            TimestampNs(10),
        )?;
        Ok(Self {
            path,
            store,
            session,
        })
    }
    fn plan(&self) -> SessionCancellationPlan {
        SessionCancellationPlan {
            session_id: self.session.session_id.clone(),
            principal: self.session.principal_id.clone(),
            session_digest: self.session.session_digest(),
            checkpoint_digest: self.store.checkpoint_digest,
            journal_root: self.store.committed_root(),
            basis_anchor: self.session.current_anchor.clone(),
            authority_root: ContentDigest::sha256(b"authority"),
            effect_root: ContentDigest::sha256(b"effects"),
            observed_at: TimestampNs(20),
            unresolved_obligations: vec!["obligation:kept".into()],
            retained_plans: vec!["plan:kept".into()],
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[test]
fn one_atomic_record_retains_exact_approval_and_tombstone() -> TestResult {
    let mut fixture = Fixture::new()?;
    let plan = fixture.plan();
    let before = fixture.store.records;
    let receipt = fixture.store.cancel_session_authority(&plan)?;
    assert_eq!(fixture.store.records, before + 1);
    let bytes = std::fs::read(&fixture.path)?;
    let state = inspect_session_bytes(
        &bytes,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    assert!(state.sessions[0].closed);
    assert_eq!(state.sessions[0].last_observed_at, TimestampNs(20));
    let report = read_report(&fixture.path, DurableSessionLimits::default())?;
    assert_eq!(
        retained_receipt(&report, &plan.principal, &plan.session_id)?,
        Some(receipt)
    );
    assert!(
        retained_receipt(
            &report,
            &PrincipalId::parse("principal:other")?,
            &plan.session_id
        )?
        .is_none()
    );
    assert!(fixture.store.cancel_session_authority(&plan).is_err());
    assert_eq!(std::fs::read(&fixture.path)?, bytes);
    fixture.store.verify_storage()?;
    Ok(())
}

#[test]
fn exact_predecessor_owner_and_time_fail_before_any_append() -> TestResult {
    let mut fixture = Fixture::new()?;
    let original = fixture.plan();
    let before = std::fs::read(&fixture.path)?;
    for variant in 0..5 {
        let mut changed = original.clone();
        match variant {
            0 => changed.principal = PrincipalId::parse("principal:other")?,
            1 => changed.journal_root = ContentDigest::sha256(b"other journal"),
            2 => changed.checkpoint_digest = ContentDigest::sha256(b"other checkpoint"),
            3 => changed.observed_at = TimestampNs(9),
            _ => changed.observed_at = TimestampNs(1000),
        }
        assert!(fixture.store.cancel_session_authority(&changed).is_err());
        assert_eq!(std::fs::read(&fixture.path)?, before);
        assert!(!fixture.store.needs_reconciliation());
    }
    Ok(())
}

#[test]
fn every_append_cut_preserves_atomic_witness_and_closure() -> TestResult {
    for (phase, committed) in [
        (AppendPhase::BodyWrite, false),
        (AppendPhase::BodySync, false),
        (AppendPhase::CommitWrite, true),
        (AppendPhase::CommitSync, true),
    ] {
        let mut fixture = Fixture::new()?;
        let plan = fixture.plan();
        fixture.store.journal.fail_after_phase(phase);
        assert!(matches!(
            fixture.store.cancel_session_authority(&plan),
            Err(DurableSessionError::Journal(_))
        ));
        assert!(fixture.store.needs_reconciliation());
        assert_eq!(
            fixture
                .store
                .reconcile_pending(IncompleteTailPolicy::Truncate)?,
            if committed {
                SessionAppendRecovery::Committed
            } else {
                SessionAppendRecovery::NotCommitted
            }
        );
        let bytes = std::fs::read(&fixture.path)?;
        let state = inspect_session_bytes(
            &bytes,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
        )?;
        let report = fss_ledger::recover_bytes(&bytes)?;
        assert_eq!(state.sessions[0].closed, committed);
        assert_eq!(
            retained_receipt(&report, &plan.principal, &plan.session_id)?.is_some(),
            committed
        );
        if committed {
            assert_eq!(
                retained_receipt(&report, &plan.principal, &plan.session_id)?
                    .ok_or("receipt")?
                    .plan
                    .approval_digest()?,
                plan.approval_digest()?
            );
        }
        fixture.store.verify_storage()?;
    }
    Ok(())
}

#[test]
fn replay_rejects_rebound_predecessor_and_forged_post_state() -> TestResult {
    let fixture = Fixture::new()?;
    let plan = fixture.plan();
    let mut memory = fixture.store.memory.clone();
    apply(&mut memory, &plan, plan.journal_root, fixture.store.limits)?;
    let after = memory
        .checkpoint(fixture.store.limits.max_checkpoint_bytes)?
        .digest();
    let root = ContentDigest::sha256(b"synthetic cancellation root");
    let bytes = record_bytes(&plan, after)?;
    assert!(
        replay_command(
            &bytes,
            &mut fixture.store.memory.clone(),
            ContentDigest::sha256(b"foreign predecessor"),
            root,
            fixture.store.limits
        )
        .is_err()
    );
    let forged = record_bytes(&plan, ContentDigest::sha256(b"forged checkpoint"))?;
    assert!(
        replay_command(
            &forged,
            &mut fixture.store.memory.clone(),
            plan.journal_root,
            root,
            fixture.store.limits
        )
        .is_err()
    );
    let mut unsorted = plan;
    unsorted.unresolved_obligations = vec!["obligation:z".into(), "obligation:a".into()];
    assert!(unsorted.approval_digest().is_err());
    Ok(())
}
