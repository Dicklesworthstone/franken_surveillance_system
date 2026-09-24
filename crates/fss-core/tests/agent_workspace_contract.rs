#![forbid(unsafe_code)]
//! Contract tests for hypothesis workspace, control plan, and feedback
//! proposal (fss-x4a.30.83.52/.56/.61).

use std::collections::BTreeSet;

use fss_core::{
    AgentFeedbackProposal, AgentOperation, BudgetVector, CanonicalEncode, CompetitionPolicy,
    ContentDigest, ControlEdge, ControlPlan, ControlStep, ControlStepKind, FeedbackPrivacyClass,
    FeedbackProposalKind, HypothesisWorkspace, LedgerAnchor, PrincipalId, RequestedDisposition,
    SessionId, StepReversibility, StepRisk, StepRobustness, WorkspaceHypothesis,
    WorkspaceHypothesisStatus,
};

fn hypothesis(id: &str, status: WorkspaceHypothesisStatus) -> WorkspaceHypothesis {
    WorkspaceHypothesis {
        hypothesis_id: id.to_owned(),
        proposition: format!("proposition for {id}"),
        status,
        supporting_evidence: vec!["evidence:a".to_owned()],
        contradicting_evidence: vec![],
        missing_evidence: vec!["evidence:missing".to_owned()],
        assumptions: vec!["assumption:night".to_owned()],
        invalidators: vec!["invalidator:recalibration".to_owned()],
        predictions: vec!["predicts footprints".to_owned()],
        distinguishing_tests: vec!["gait classification".to_owned()],
        consequences_accept: vec!["dispatch patrol".to_owned()],
        consequences_reject: vec!["log only".to_owned()],
        consequences_unresolved: vec!["keep recording".to_owned()],
    }
}

#[test]
fn test_hypothesis_workspace_pins_competition_policy() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = HypothesisWorkspace::new(
        "workspace:gate",
        "objective:gate",
        LedgerAnchor::genesis("site:fss:workspace"),
        2,
        vec![
            hypothesis("hypothesis:intruder", WorkspaceHypothesisStatus::Leading),
            hypothesis("hypothesis:wildlife", WorkspaceHypothesisStatus::Weakened),
        ],
        CompetitionPolicy {
            loss_model_id: "loss:protected-world".to_owned(),
            tie_break_policy: "prefer leading, retain high-loss".to_owned(),
            retain_high_loss_alternatives: true,
        },
        "decision:workspace:gate",
    )?;
    // Protected high-loss alternatives are retained against ranking.
    assert!(workspace.competition_policy.retain_high_loss_alternatives);
    let digest = workspace.workspace_digest();
    // Duplicate hypothesis identities are refused.
    let duplicated = vec![
        hypothesis("hypothesis:intruder", WorkspaceHypothesisStatus::Leading),
        hypothesis("hypothesis:intruder", WorkspaceHypothesisStatus::Weakened),
    ];
    assert!(
        HypothesisWorkspace::new(
            "workspace:gate",
            "objective:gate",
            LedgerAnchor::genesis("site:fss:workspace"),
            2,
            duplicated,
            CompetitionPolicy {
                loss_model_id: "loss:protected-world".to_owned(),
                tie_break_policy: "tie".to_owned(),
                retain_high_loss_alternatives: true,
            },
            "decision:workspace:gate",
        )
        .is_err()
    );
    let _ = digest;
    Ok(())
}

fn plan_step(step_id: &str, kind: ControlStepKind) -> ControlStep {
    ControlStep {
        step_id: step_id.to_owned(),
        kind,
        owner: "fss-situation".to_owned(),
        verb: "orient".to_owned(),
        robustness_class: StepRobustness::RobustAcrossEnvelope,
        supported_world_ids: vec!["world:gate:protected".to_owned()],
        unsafe_world_ids: vec![],
        preconditions: vec![],
        read_witnesses: vec![],
        write_witnesses: vec![],
        negative_witnesses: vec![],
        required_capabilities: vec!["capability:situation.read".to_owned()],
        budget_json: "{\"latencyMs\":100}".to_owned(),
        expected_information_gain: 0.5,
        expected_objective_gain: 0.25,
        risk: StepRisk::None,
        privacy_exposure: 0.0,
        reversibility: StepReversibility::ReadOnly,
        success_transition: vec![],
        failure_transition: vec![],
        cancel_transition: vec![],
        indeterminate_transition: vec![],
        terminal_proof: vec![],
    }
}

#[test]
fn test_control_plan_validates_graph() -> Result<(), Box<dyn std::error::Error>> {
    let plan = ControlPlan::compile(
        "plan:gate-watch",
        "objective:gate-watch",
        LedgerAnchor::genesis("site:fss:plan"),
        "frame:gate:digest0001",
        ContentDigest::sha256(b"world-envelope"),
        None,
        vec!["capability:situation.read".to_owned()],
        BudgetVector::builder().latency_ms(500).build()?,
        vec![
            plan_step("step:orient", ControlStepKind::Observe),
            plan_step("step:decide", ControlStepKind::Decide),
        ],
        vec![ControlEdge {
            from: "step:orient".to_owned(),
            to: "step:decide".to_owned(),
            condition: "coverage certified".to_owned(),
            priority: 1,
        }],
        vec!["step:orient".to_owned()],
        vec!["decision delivered".to_owned()],
        "decision:plan:gate-watch",
    )?;
    assert_eq!(plan.steps.len(), 2);
    assert_eq!(plan.edges.len(), 1);
    let digest = plan.plan_digest();
    // Dangling edges are refused.
    assert!(
        ControlPlan::compile(
            "plan:gate-watch",
            "objective:gate-watch",
            LedgerAnchor::genesis("site:fss:plan"),
            "frame:gate:digest0001",
            ContentDigest::sha256(b"world-envelope"),
            None,
            vec!["capability:situation.read".to_owned()],
            BudgetVector::builder().latency_ms(500).build()?,
            vec![plan_step("step:orient", ControlStepKind::Observe)],
            vec![ControlEdge {
                from: "step:orient".to_owned(),
                to: "step:ghost".to_owned(),
                condition: "c".to_owned(),
                priority: 1,
            }],
            vec!["step:orient".to_owned()],
            vec!["t".to_owned()],
            "decision:plan:gate-watch",
        )
        .is_err()
    );
    let _ = digest;
    Ok(())
}

#[test]
fn test_feedback_proposal_never_mutates_active_policy() -> Result<(), Box<dyn std::error::Error>> {
    let proposal = AgentFeedbackProposal::new(
        "feedback:gate-summary",
        PrincipalId::parse("principal:operator")?,
        SessionId::parse("session:operator")?,
        LedgerAnchor::genesis("site:fss:feedback"),
        "{\"summaryId\":\"s1\"}".to_owned(),
        FeedbackProposalKind::BadSummary,
        "The summary dropped the coverage-loss heartbeat.".to_owned(),
        vec!["decision:feedback:0001".to_owned()],
        vec![],
        RequestedDisposition::OperatorReview,
        FeedbackPrivacyClass::Operational,
        1_000,
    )?;
    // CONSTITUTIONAL: recording never mutates active policy — pinned in the
    // canonical encoding, whose final byte is the literal false flag.
    {
        let mut encoder = fss_core::CanonicalEncoder::new();
        proposal.encode_canonical(&mut encoder);
        let bytes = encoder.finish();
        assert_eq!(
            bytes[bytes.len() - 1],
            0,
            "policy mutation flag must encode false"
        );
    }
    assert_eq!(
        proposal.requested_disposition,
        RequestedDisposition::OperatorReview
    );
    assert_eq!(proposal.kind, FeedbackProposalKind::BadSummary);
    // Evidence handles carry the lowercase digest spelling.
    assert!(
        AgentFeedbackProposal::new(
            "feedback:x",
            PrincipalId::parse("principal:operator")?,
            SessionId::parse("session:operator")?,
            LedgerAnchor::genesis("site:fss:feedback"),
            "{}".to_owned(),
            FeedbackProposalKind::Correction,
            "statement".to_owned(),
            vec!["UPPER:not-digest".to_owned()],
            vec![],
            RequestedDisposition::RecordOnly,
            FeedbackPrivacyClass::Public,
            1_000,
        )
        .is_err()
    );
    let _ = BTreeSet::<String>::new();
    let _ = AgentOperation::Feedback;
    Ok(())
}
