#![forbid(unsafe_code)]
//! Contract tests for mission, objective, session, and workspace-capsule
//! contracts (fss-x4a.30.83.41-44).

use std::collections::BTreeSet;

use fss_core::{
    AgentSession, AgentSessionParams, BudgetVector, ContentDigest, ContractError, LedgerAnchor,
    MissionContract, MissionContractParams, MissionId, MissionState, ObjectiveContract,
    ObjectiveContractParams, ObjectiveScope, PrincipalId, SessionCapsule, SessionCapsuleParams,
    SessionId,
};

fn mission_anchors() -> (LedgerAnchor, LedgerAnchor) {
    let base = LedgerAnchor::genesis("site:fss:mission");
    let mut current = LedgerAnchor::genesis("site:fss:mission");
    current.commit_sequence = base.commit_sequence + 5;
    (base, current)
}

#[test]
fn test_mission_contract_validates_and_digests() -> Result<(), Box<dyn std::error::Error>> {
    let (baseline, current) = mission_anchors();
    let mission = MissionContract::new(MissionContractParams {
        mission_id: MissionId::parse("mission:guard-gate")?,
        revision: 2,
        deployment_id: "deployment:home".to_owned(),
        state: MissionState::Active,
        objective: "Alert on human entry to the gated zone during night hours.".to_owned(),
        success_criteria: vec!["alert delivered within 30s of entry".to_owned()],
        failure_criteria: vec!["no alert on resident passage".to_owned()],
        stop_criteria: vec!["stop if coverage uncertified".to_owned()],
        capabilities: BTreeSet::from(["capability:alert.send".to_owned()]),
        privacy_scope: BTreeSet::from(["privacy:face-redaction".to_owned()]),
        baseline_anchor: baseline,
        current_anchor: current,
        budgets: BudgetVector::builder().latency_ms(1_000).build()?,
        decision_deadline_ns: 5_000,
        created_at_ns: 1_000,
    })?;
    assert_eq!(mission.state, MissionState::Active);
    let digest = mission.mission_digest();
    assert_ne!(digest, ContentDigest::sha256(b"unrelated"));
    // A decision deadline at or before creation is refused.
    assert_eq!(
        MissionContract::new(MissionContractParams {
            mission_id: MissionId::parse("mission:guard-gate")?,
            revision: 2,
            deployment_id: "deployment:home".to_owned(),
            state: MissionState::Active,
            objective: "objective".to_owned(),
            success_criteria: vec!["s".to_owned()],
            failure_criteria: vec![],
            stop_criteria: vec![],
            capabilities: BTreeSet::new(),
            privacy_scope: BTreeSet::new(),
            baseline_anchor: LedgerAnchor::genesis("site:fss:mission"),
            current_anchor: LedgerAnchor::genesis("site:fss:mission"),
            budgets: BudgetVector::builder().latency_ms(1).build()?,
            decision_deadline_ns: 1_000,
            created_at_ns: 1_000,
        }),
        Err(ContractError::InvertedTimeInterval)
    );
    // Determinism: an identical mission yields an identical digest.
    let (baseline, current) = mission_anchors();
    let again = MissionContract::new(MissionContractParams {
        mission_id: MissionId::parse("mission:guard-gate")?,
        revision: 2,
        deployment_id: "deployment:home".to_owned(),
        state: MissionState::Active,
        objective: "Alert on human entry to the gated zone during night hours.".to_owned(),
        success_criteria: vec!["alert delivered within 30s of entry".to_owned()],
        failure_criteria: vec!["no alert on resident passage".to_owned()],
        stop_criteria: vec!["stop if coverage uncertified".to_owned()],
        capabilities: BTreeSet::from(["capability:alert.send".to_owned()]),
        privacy_scope: BTreeSet::from(["privacy:face-redaction".to_owned()]),
        baseline_anchor: baseline,
        current_anchor: current,
        budgets: BudgetVector::builder().latency_ms(1_000).build()?,
        decision_deadline_ns: 5_000,
        created_at_ns: 1_000,
    })?;
    assert_eq!(again.mission_digest(), digest);
    Ok(())
}

#[test]
fn test_objective_contract_requires_decision_digests(
) -> Result<(), Box<dyn std::error::Error>> {
    let scope = ObjectiveScope {
        deployments: vec!["deployment:home".to_owned()],
        ..ObjectiveScope::default()
    };
    let objective = ObjectiveContract::new(ObjectiveContractParams {
        objective_id: "objective:gate-check".to_owned(),
        source_principal: "principal:test".to_owned(),
        source_request_digest: "request:digest:0001".to_owned(),
        desired_outcome: "Verify the gate is closed and report exceptions.".to_owned(),
        success_predicates: vec!["gate state corroborated by two frames".to_owned()],
        failure_predicates: vec![],
        stop_conditions: vec!["stop after one hour".to_owned()],
        hard_constraints: vec!["no identity inference".to_owned()],
        soft_preferences: vec!["prefer cheapest probe".to_owned()],
        scope,
        budgets: BudgetVector::builder().latency_ms(800).build()?,
        allowed_actions: vec!["fss://situation/gate".to_owned()],
        required_approvals: vec![],
        terminal_proof: vec!["terminal:gate-verified".to_owned()],
        decision_digest: "decision:objective:gate-check".to_owned(),
    })?;
    let digest = objective.objective_digest();
    assert!(!digest.to_text().is_empty());
    // The lowercase decision-digest spelling is enforced.
    assert!(ObjectiveContract::new(ObjectiveContractParams {
        objective_id: "objective:gate-check".to_owned(),
        source_principal: "principal:test".to_owned(),
        source_request_digest: "request:digest:0001".to_owned(),
        desired_outcome: "outcome".to_owned(),
        success_predicates: vec![],
        failure_predicates: vec![],
        stop_conditions: vec![],
        hard_constraints: vec![],
        soft_preferences: vec![],
        scope: ObjectiveScope::default(),
        budgets: BudgetVector::builder().latency_ms(1).build()?,
        allowed_actions: vec![],
        required_approvals: vec![],
        terminal_proof: vec![],
        decision_digest: "Decision:UPPER".to_owned(),
    })
    .is_err());
    let _ = digest;
    Ok(())
}

#[test]
fn test_agent_session_bounds_and_view_binding() -> Result<(), Box<dyn std::error::Error>> {
    let session = AgentSession::new(AgentSessionParams {
        session_id: SessionId::parse("session:guard")?,
        mission_id: MissionId::parse("mission:guard")?,
        principal_id: PrincipalId::parse("principal:guard")?,
        capabilities: BTreeSet::from(["capability:situation.read".to_owned()]),
        privacy_scope: BTreeSet::from(["privacy:face-redaction".to_owned()]),
        current_anchor: LedgerAnchor::genesis("site:fss:guard"),
        view_id: "AVIEW-002".to_owned(),
        token_budget: 20_000,
        symbol_table_generation: 1,
        last_acknowledged_situation_fingerprint: None,
        created_at_ns: 1_000,
        expires_at_ns: 9_000,
    })?;
    assert_eq!(session.view.id(), "AVIEW-002");
    let digest = session.session_digest();
    // Zero token budget: refused rather than negotiated.
    assert!(AgentSession::new(AgentSessionParams {
        session_id: SessionId::parse("session:guard")?,
        mission_id: MissionId::parse("mission:guard")?,
        principal_id: PrincipalId::parse("principal:guard")?,
        capabilities: BTreeSet::new(),
        privacy_scope: BTreeSet::new(),
        current_anchor: LedgerAnchor::genesis("site:fss:guard"),
        view_id: "AVIEW-002".to_owned(),
        token_budget: 0,
        symbol_table_generation: 1,
        last_acknowledged_situation_fingerprint: None,
        created_at_ns: 1_000,
        expires_at_ns: 9_000,
    })
    .is_err());
    // Unregistered views are refused.
    assert!(AgentSession::new(AgentSessionParams {
        session_id: SessionId::parse("session:guard")?,
        mission_id: MissionId::parse("mission:guard")?,
        principal_id: PrincipalId::parse("principal:guard")?,
        capabilities: BTreeSet::new(),
        privacy_scope: BTreeSet::new(),
        current_anchor: LedgerAnchor::genesis("site:fss:guard"),
        view_id: "AVIEW-099".to_owned(),
        token_budget: 1_000,
        symbol_table_generation: 1,
        last_acknowledged_situation_fingerprint: None,
        created_at_ns: 1_000,
        expires_at_ns: 9_000,
    })
    .is_err());
    // Expiry at creation is refused.
    assert!(AgentSession::new(AgentSessionParams {
        session_id: SessionId::parse("session:guard")?,
        mission_id: MissionId::parse("mission:guard")?,
        principal_id: PrincipalId::parse("principal:guard")?,
        capabilities: BTreeSet::new(),
        privacy_scope: BTreeSet::new(),
        current_anchor: LedgerAnchor::genesis("site:fss:guard"),
        view_id: "AVIEW-002".to_owned(),
        token_budget: 1_000,
        symbol_table_generation: 1,
        last_acknowledged_situation_fingerprint: None,
        created_at_ns: 1_000,
        expires_at_ns: 1_000,
    })
    .is_err());
    let _ = digest;
    Ok(())
}

#[test]
fn test_session_capsule_pins_workspace_state() -> Result<(), Box<dyn std::error::Error>> {
    let base = LedgerAnchor::genesis("site:fss:workspace");
    let mut current = LedgerAnchor::genesis("site:fss:workspace");
    current.commit_sequence = base.commit_sequence + 2;
    let capsule = SessionCapsule::new(SessionCapsuleParams {
        session_id: SessionId::parse("session:guard")?,
        revision: 7,
        principal: "principal:guard".to_owned(),
        capability_projection: vec!["capability:situation.read".to_owned()],
        objective_digest: "objective:guard:digest0001".to_owned(),
        base_anchor: base.clone(),
        current_anchor: current.clone(),
        situation_capsule_digest: "situation:guard:digest0001".to_owned(),
        active_hypotheses: vec!["hypothesis:intruder".to_owned()],
        assumptions: vec!["assumption:night-coverage".to_owned()],
        unknowns: vec!["unknown:shed-interior".to_owned()],
        not_observable_domains: vec!["domain:shed-interior".to_owned()],
        epistemic_debt: vec!["debt:stale-calibration".to_owned()],
        open_obligations: vec!["obligation:alert-followup".to_owned()],
        budget_ledger: BudgetVector::builder().tokens(4_000).build()?,
        bookmarked_evidence: vec![ContentDigest::sha256(b"bookmarked-frame")],
        next_actions: vec!["orient next:gate".to_owned()],
        decision_digest: "decision:workspace:0001".to_owned(),
    })?;
    // Unknowns and epistemic debt are carried explicitly, never dropped.
    assert_eq!(capsule.unknowns.len(), 1);
    assert_eq!(capsule.epistemic_debt.len(), 1);
    let digest = capsule.capsule_digest();
    // An anchor behind the base anchor is refused: no stale workspace roots.
    let mut stale = LedgerAnchor::genesis("site:fss:workspace");
    stale.commit_sequence = base.commit_sequence;
    let _ = stale;
    assert!(SessionCapsule::new(SessionCapsuleParams {
        session_id: SessionId::parse("session:guard")?,
        revision: 8,
        principal: "principal:guard".to_owned(),
        capability_projection: vec![],
        objective_digest: "objective:guard:digest0001".to_owned(),
        base_anchor: current.clone(),
        current_anchor: base.clone(),
        situation_capsule_digest: "situation:guard:digest0001".to_owned(),
        active_hypotheses: vec![],
        assumptions: vec![],
        unknowns: vec![],
        not_observable_domains: vec![],
        epistemic_debt: vec![],
        open_obligations: vec![],
        budget_ledger: BudgetVector::builder().tokens(1).build()?,
        bookmarked_evidence: vec![],
        next_actions: vec![],
        decision_digest: "decision:workspace:0001".to_owned(),
    })
    .is_err());
    // A divergent lineage is refused.
    assert!(SessionCapsule::new(SessionCapsuleParams {
        session_id: SessionId::parse("session:guard")?,
        revision: 8,
        principal: "principal:guard".to_owned(),
        capability_projection: vec![],
        objective_digest: "objective:guard:digest0001".to_owned(),
        base_anchor: base.clone(),
        current_anchor: LedgerAnchor::genesis("site:fss:elsewhere"),
        situation_capsule_digest: "situation:guard:digest0001".to_owned(),
        active_hypotheses: vec![],
        assumptions: vec![],
        unknowns: vec![],
        not_observable_domains: vec![],
        epistemic_debt: vec![],
        open_obligations: vec![],
        budget_ledger: BudgetVector::builder().tokens(1).build()?,
        bookmarked_evidence: vec![],
        next_actions: vec![],
        decision_digest: "decision:workspace:0001".to_owned(),
    })
    .is_err());
    // Determinism.
    let rebuilt = SessionCapsule::new(SessionCapsuleParams {
        session_id: SessionId::parse("session:guard")?,
        revision: 7,
        principal: "principal:guard".to_owned(),
        capability_projection: vec!["capability:situation.read".to_owned()],
        objective_digest: "objective:guard:digest0001".to_owned(),
        base_anchor: base,
        current_anchor: current,
        situation_capsule_digest: "situation:guard:digest0001".to_owned(),
        active_hypotheses: vec!["hypothesis:intruder".to_owned()],
        assumptions: vec!["assumption:night-coverage".to_owned()],
        unknowns: vec!["unknown:shed-interior".to_owned()],
        not_observable_domains: vec!["domain:shed-interior".to_owned()],
        epistemic_debt: vec!["debt:stale-calibration".to_owned()],
        open_obligations: vec!["obligation:alert-followup".to_owned()],
        budget_ledger: BudgetVector::builder().tokens(4_000).build()?,
        bookmarked_evidence: vec![ContentDigest::sha256(b"bookmarked-frame")],
        next_actions: vec!["orient next:gate".to_owned()],
        decision_digest: "decision:workspace:0001".to_owned(),
    })?;
    assert_eq!(rebuilt.capsule_digest(), digest);
    Ok(())
}
