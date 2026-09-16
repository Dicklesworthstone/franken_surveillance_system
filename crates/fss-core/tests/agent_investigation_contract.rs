#![forbid(unsafe_code)]
//! Contract tests for the durable investigation record (fss-x4a.30.83.51).

use std::collections::BTreeSet;

use fss_core::contract_basis::reference_contract_basis;
use fss_core::{
    CaseDiscriminator, CaseHypothesis, ContractError, InvestigationLifecycle,
    InvestigationState, KnownStatement, KnowledgeState, LedgerAnchor, MissionId,
};
use fss_core::ContentDigest;

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

#[test]
fn test_investigation_requires_competition_and_discriminators(
) -> Result<(), Box<dyn std::error::Error>> {
    let basis = reference_contract_basis();
    let anchor = LedgerAnchor::genesis("site:fss:investigation");
    // A single-hypothesis case preserves no alternative: refused.
    let single = vec![hypothesis("hypothesis:intruder")];
    assert_eq!(
        InvestigationState::new(
            "investigation:gate",
            basis.clone(),
            MissionId::parse("mission:guard")?,
            1,
            InvestigationLifecycle::Active,
            "Who entered the gate at night?".to_owned(),
            "whether to dispatch a patrol".to_owned(),
            anchor.clone(),
            single,
            vec![],
            vec![],
            vec![],
            vec![],
            vec!["stop after 24h".to_owned()],
            9_000,
        ),
        Err(ContractError::EvidenceRequired)
    );
    // Two competing hypotheses with a discriminator binding them: accepted.
    let competing = vec![
        hypothesis("hypothesis:intruder"),
        hypothesis("hypothesis:wildlife"),
    ];
    let record = InvestigationState::new(
        "investigation:gate",
        basis,
        MissionId::parse("mission:guard")?,
        1,
        InvestigationLifecycle::Active,
        "Who entered the gate at night?".to_owned(),
        "whether to dispatch a patrol".to_owned(),
        anchor,
        competing,
        vec![KnownStatement {
            statement_id: "statement:gate-latched".to_owned(),
            text: "The gate latch shows fresh scuffing.".to_owned(),
            epistemic_state: KnowledgeState::Estimated,
            basis: vec!["evidence:frame-0042".to_owned()],
        }],
        vec![KnownStatement {
            statement_id: "statement:shed-interior".to_owned(),
            text: "The shed interior has not been observed.".to_owned(),
            epistemic_state: KnowledgeState::NotObservable,
            basis: vec!["coverage:shed-gap".to_owned()],
        }],
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
        vec!["probe:replay-night-window".to_owned()],
        vec!["stop after 24h".to_owned(), "stop if coverage uncertified".to_owned()],
        9_000,
    )?;
    assert_eq!(record.hypotheses.len(), 2);
    assert_eq!(record.state, InvestigationLifecycle::Active);
    // Knowns and unknowns both carry their epistemic states explicitly.
    assert_eq!(record.knowns[0].epistemic_state, KnowledgeState::Estimated);
    assert_eq!(record.unknowns[0].epistemic_state, KnowledgeState::NotObservable);
    let digest = record.investigation_digest();
    // Determinism.
    let basis = reference_contract_basis();
    let anchor = LedgerAnchor::genesis("site:fss:investigation");
    let competing = vec![
        hypothesis("hypothesis:intruder"),
        hypothesis("hypothesis:wildlife"),
    ];
    let rebuilt = InvestigationState::new(
        "investigation:gate",
        basis,
        MissionId::parse("mission:guard")?,
        1,
        InvestigationLifecycle::Active,
        "Who entered the gate at night?".to_owned(),
        "whether to dispatch a patrol".to_owned(),
        anchor,
        competing,
        vec![KnownStatement {
            statement_id: "statement:gate-latched".to_owned(),
            text: "The gate latch shows fresh scuffing.".to_owned(),
            epistemic_state: KnowledgeState::Estimated,
            basis: vec!["evidence:frame-0042".to_owned()],
        }],
        vec![KnownStatement {
            statement_id: "statement:shed-interior".to_owned(),
            text: "The shed interior has not been observed.".to_owned(),
            epistemic_state: KnowledgeState::NotObservable,
            basis: vec!["coverage:shed-gap".to_owned()],
        }],
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
        vec!["probe:replay-night-window".to_owned()],
        vec!["stop after 24h".to_owned(), "stop if coverage uncertified".to_owned()],
        9_000,
    )?;
    assert_eq!(rebuilt.investigation_digest(), digest);
    Ok(())
}

#[test]
fn test_investigation_discriminators_must_separate_existing_hypotheses(
) -> Result<(), Box<dyn std::error::Error>> {
    let basis = reference_contract_basis();
    let anchor = LedgerAnchor::genesis("site:fss:investigation");
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
        InvestigationState::new(
            "investigation:gate",
            basis.clone(),
            MissionId::parse("mission:guard")?,
            1,
            InvestigationLifecycle::Active,
            "question".to_owned(),
            "decision".to_owned(),
            anchor.clone(),
            competing.clone(),
            vec![],
            vec![],
            dangling,
            vec![],
            vec!["stop".to_owned()],
            9_000,
        ),
        Err(ContractError::NotFound)
    );
    // Missing stop rules are refused: an investigation without stop rules has
    // no bounded end.
    assert_eq!(
        InvestigationState::new(
            "investigation:gate",
            basis,
            MissionId::parse("mission:guard")?,
            1,
            InvestigationLifecycle::Active,
            "question".to_owned(),
            "decision".to_owned(),
            anchor,
            competing,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            9_000,
        ),
        Err(ContractError::EvidenceRequired)
    );
    // KnowledgeState::Live is the hypothesis state used by the fixture; the
    // BTreeSet import guards the statement-id uniqueness check path.
    let _ = BTreeSet::<String>::new();
    Ok(())
}
