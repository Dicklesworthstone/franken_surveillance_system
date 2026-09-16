#![forbid(unsafe_code)]
//! Contract tests for the durable investigation record (fss-x4a.30.83.51).

use std::collections::BTreeSet;

use fss_core::contract_basis::reference_contract_basis;
use fss_core::{
    CaseDiscriminator, CaseHypothesis, ContentDigest, ContractError, InvestigationLifecycle,
    InvestigationState, InvestigationStateParams, KnownStatement, KnowledgeState, LedgerAnchor,
    MissionId,
};

fn hypothesis(id: &str) -> CaseHypothesis {
    CaseHypothesis {
        hypothesis_id: id.to_owned(),
        description: format!("hypothesis {id}"),
        epistemic_state: KnowledgeState::Estimated,
        predictions: vec![format!("{id} predicts footprints")],
        evidence: vec![ContentDigest::sha256(id.as_bytes())],
        contradictions: vec![],
    }
}

fn params(
    hypotheses: Vec<CaseHypothesis>,
    discriminators: Vec<CaseDiscriminator>,
    stop_rules: Vec<String>,
) -> InvestigationStateParams {
    InvestigationStateParams {
        investigation_id: "investigation:gate".to_owned(),
        contract_basis: reference_contract_basis(),
        mission_id: MissionId::parse("mission:guard").unwrap_or_else(|_| unreachable!()),
        revision: 1,
        state: InvestigationLifecycle::Active,
        question: "Who entered the gate at night?".to_owned(),
        decision_informed: "whether to dispatch a patrol".to_owned(),
        basis_anchor: LedgerAnchor::genesis("site:fss:investigation"),
        hypotheses,
        knowns: vec![KnownStatement {
            statement_id: "statement:gate-latched".to_owned(),
            text: "The gate latch shows fresh scuffing.".to_owned(),
            epistemic_state: KnowledgeState::Estimated,
            basis: vec!["evidence:frame-0042".to_owned()],
        }],
        unknowns: vec![KnownStatement {
            statement_id: "statement:shed-interior".to_owned(),
            text: "The shed interior has not been observed.".to_owned(),
            epistemic_state: KnowledgeState::NotObservable,
            basis: vec!["coverage:shed-gap".to_owned()],
        }],
        discriminators,
        probes: vec!["probe:replay-night-window".to_owned()],
        stop_rules,
        decision_deadline_ns: 9_000,
    }
}

#[test]
fn test_investigation_requires_competition_and_carries_epistemics(
) -> Result<(), Box<dyn std::error::Error>> {
    // A single-hypothesis case preserves no alternative: refused.
    let single = vec![hypothesis("hypothesis:intruder")];
    assert_eq!(
        InvestigationState::new(params(single, vec![], vec!["stop after 24h".to_owned()])),
        Err(ContractError::EvidenceRequired)
    );
    // Two competing hypotheses with a separating discriminator: accepted.
    let competing = vec![
        hypothesis("hypothesis:intruder"),
        hypothesis("hypothesis:wildlife"),
    ];
    let discriminator = CaseDiscriminator {
        discriminator_id: "discriminator:gait".to_owned(),
        description: "Bipedal gait separates human from animal.".to_owned(),
        separates: vec![
            "hypothesis:intruder".to_owned(),
            "hypothesis:wildlife".to_owned(),
        ],
        expected_outcomes: vec![
            "bipedal:intruder supported".to_owned(),
            "quadruped:wildlife supported".to_owned(),
        ],
    };
    let record = InvestigationState::new(params(
        competing.clone(),
        vec![discriminator],
        vec![
            "stop after 24h".to_owned(),
            "stop if coverage uncertified".to_owned(),
        ],
    ))?;
    assert_eq!(record.hypotheses.len(), 2);
    assert_eq!(record.state, InvestigationLifecycle::Active);
    // Knowns and unknowns carry their epistemic states explicitly.
    assert_eq!(record.knowns[0].epistemic_state, KnowledgeState::Estimated);
    assert_eq!(record.unknowns[0].epistemic_state, KnowledgeState::NotObservable);
    // Determinism.
    let rebuilt = InvestigationState::new(params(
        competing,
        vec![CaseDiscriminator {
            discriminator_id: "discriminator:gait".to_owned(),
            description: "Bipedal gait separates human from animal.".to_owned(),
            separates: vec![
                "hypothesis:intruder".to_owned(),
                "hypothesis:wildlife".to_owned(),
            ],
            expected_outcomes: vec![
                "bipedal:intruder supported".to_owned(),
                "quadruped:wildlife supported".to_owned(),
            ],
        }],
        vec![
            "stop after 24h".to_owned(),
            "stop if coverage uncertified".to_owned(),
        ],
    ))?;
    assert_eq!(rebuilt.investigation_digest(), record.investigation_digest());
    Ok(())
}

#[test]
fn test_investigation_discriminators_must_separate_existing_hypotheses(
) -> Result<(), Box<dyn std::error::Error>> {
    let competing = vec![
        hypothesis("hypothesis:intruder"),
        hypothesis("hypothesis:wildlife"),
    ];
    // A discriminator naming a hypothesis that does not exist is refused.
    let dangling = vec![CaseDiscriminator {
        discriminator_id: "discriminator:bad".to_owned(),
        description: "Names a ghost hypothesis.".to_owned(),
        separates: vec![
            "hypothesis:intruder".to_owned(),
            "hypothesis:ghost".to_owned(),
        ],
        expected_outcomes: vec!["a".to_owned(), "b".to_owned()],
    }];
    assert_eq!(
        InvestigationState::new(params(competing.clone(), dangling, vec!["stop".to_owned()])),
        Err(ContractError::NotFound)
    );
    // Missing stop rules are refused: no bounded end.
    assert_eq!(
        InvestigationState::new(params(competing, vec![], vec![])),
        Err(ContractError::EvidenceRequired)
    );
    let _ = BTreeSet::<String>::new();
    Ok(())
}
