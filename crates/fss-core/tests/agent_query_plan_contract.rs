#![forbid(unsafe_code)]
//! Contract tests for the compiled agent query plan (fss-x4a.30.83.50).

use fss_core::contract_basis::reference_contract_basis;
use fss_core::{
    AgentOperation, AgentQueryPlan, BudgetVector, ContentDigest, ContractBasisError,
    ContractError, LedgerAnchor, MissionId, QueryCompletenessRequested, QueryInterpretation,
    SessionId,
};

fn interpretation(id: &str) -> QueryInterpretation {
    QueryInterpretation::new(
        id,
        "Read the night-window coverage for the gate.".to_owned(),
        true,
        true,
        None,
    )
    .unwrap_or_else(|_| unreachable!("valid interpretation"))
}

#[test]
fn test_query_plan_compiles_with_selected_interpretation(
) -> Result<(), Box<dyn std::error::Error>> {
    let plan = AgentQueryPlan::compile(
        "query-plan:gate:0001",
        MissionId::parse("mission:guard")?,
        SessionId::parse("session:guard")?,
        &reference_contract_basis(),
        "AOP-005",
        ContentDigest::sha256(b"show me night gate coverage"),
        vec![],
        LedgerAnchor::genesis("site:fss:guard"),
        "Show night-window coverage for the gate.".to_owned(),
        vec!["fss://coverage/gate/night".to_owned()],
        vec!["domain:coverage".to_owned()],
        vec!["capability:situation.read".to_owned()],
        vec!["privacy:face-redaction".to_owned()],
        QueryCompletenessRequested::Bounded,
        BudgetVector::builder().latency_ms(400).build()?,
        vec![interpretation("interp:coverage"), interpretation("interp:health")],
        "interp:coverage",
        BudgetVector::builder().latency_ms(350).build()?,
        "AVIEW-003",
        1_000,
    )?;
    assert_eq!(plan.operation(), AgentOperation::Query);
    assert_eq!(plan.interpretations().len(), 2);
    assert_eq!(plan.selected_interpretation(), "interp:coverage");
    assert_eq!(plan.output_view().id(), "AVIEW-003");
    let digest = plan.plan_digest();
    let again = AgentQueryPlan::compile(
        "query-plan:gate:0001",
        MissionId::parse("mission:guard")?,
        SessionId::parse("session:guard")?,
        &reference_contract_basis(),
        "AOP-005",
        ContentDigest::sha256(b"show me night gate coverage"),
        vec![],
        LedgerAnchor::genesis("site:fss:guard"),
        "Show night-window coverage for the gate.".to_owned(),
        vec!["fss://coverage/gate/night".to_owned()],
        vec!["domain:coverage".to_owned()],
        vec!["capability:situation.read".to_owned()],
        vec!["privacy:face-redaction".to_owned()],
        QueryCompletenessRequested::Bounded,
        BudgetVector::builder().latency_ms(400).build()?,
        vec![interpretation("interp:coverage"), interpretation("interp:health")],
        "interp:coverage",
        BudgetVector::builder().latency_ms(350).build()?,
        "AVIEW-003",
        1_000,
    )?;
    assert_eq!(digest, again.plan_digest());
    Ok(())
}

#[test]
fn test_query_plan_refuses_effect_rows_and_outside_selections(
) -> Result<(), Box<dyn std::error::Error>> {
    let basis = reference_contract_basis();
    // Effect rows never serve query plans, whatever their payload.
    assert!(AgentQueryPlan::compile(
        "query-plan:x",
        MissionId::parse("mission:guard")?,
        SessionId::parse("session:guard")?,
        &basis,
        "AOP-008",
        ContentDigest::sha256(b"text"),
        vec![],
        LedgerAnchor::genesis("site:fss:guard"),
        "objective".to_owned(),
        vec![],
        vec![],
        vec![],
        vec![],
        QueryCompletenessRequested::BestEffort,
        BudgetVector::builder().latency_ms(1).build()?,
        vec![interpretation("interp:a")],
        "interp:a",
        BudgetVector::builder().latency_ms(1).build()?,
        "AVIEW-005",
        1_000,
    )
    .is_err());
    // A selection outside the enumerated interpretations is opaque: refused.
    assert_eq!(
        AgentQueryPlan::compile(
            "query-plan:x",
            MissionId::parse("mission:guard")?,
            SessionId::parse("session:guard")?,
            &basis,
            "AOP-005",
            ContentDigest::sha256(b"text"),
            vec![],
            LedgerAnchor::genesis("site:fss:guard"),
            "objective".to_owned(),
            vec![],
            vec![],
            vec![],
            vec![],
            QueryCompletenessRequested::BestEffort,
            BudgetVector::builder().latency_ms(1).build()?,
            vec![interpretation("interp:a")],
            "interp:not-enumerated",
            BudgetVector::builder().latency_ms(1).build()?,
            "AVIEW-003",
            1_000,
        ),
        Err(ContractBasisError::Contract(ContractError::NotFound))
    );
    // Unregistered output views are refused.
    assert!(AgentQueryPlan::compile(
        "query-plan:x",
        MissionId::parse("mission:guard")?,
        SessionId::parse("session:guard")?,
        &basis,
        "AOP-005",
        ContentDigest::sha256(b"text"),
        vec![],
        LedgerAnchor::genesis("site:fss:guard"),
        "objective".to_owned(),
        vec![],
        vec![],
        vec![],
        vec![],
        QueryCompletenessRequested::BestEffort,
        BudgetVector::builder().latency_ms(1).build()?,
        vec![interpretation("interp:a")],
        "interp:a",
        BudgetVector::builder().latency_ms(1).build()?,
        "AVIEW-099",
        1_000,
    )
    .is_err());
    Ok(())
}
