#![forbid(unsafe_code)]
use super::*;
use crate::agent_session::SessionRefresh;
use fss_core::{
    AgentSessionParams, CaseHypothesis, ContractBasisRegistryBytes, KnowledgeState, KnownStatement,
    LedgerAnchor, MissionId,
};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

pub(super) fn basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
        b"schemas",
        b"operations",
        b"views",
        b"capabilities",
        b"errors",
        b"costs",
        "test:cases",
    ))
}

pub(super) fn params(id: &str) -> Result<AgentSessionParams, Box<dyn Error>> {
    Ok(AgentSessionParams {
        session_id: SessionId::parse(id)?,
        principal_id: PrincipalId::parse("principal:owner")?,
        mission_id: MissionId::parse("mission:cases")?,
        capabilities: BTreeSet::from([CAPABILITY_INVESTIGATE.to_owned()]),
        privacy_scope: BTreeSet::from(["private:property".to_owned()]),
        current_anchor: LedgerAnchor::genesis("site:cases"),
        view_id: "AVIEW-001".to_owned(),
        token_budget: 100,
        symbol_table_generation: 0,
        last_acknowledged_situation_fingerprint: None,
        created_at_ns: 0,
        expires_at_ns: 1_000,
    })
}

pub(super) fn opening() -> Result<InvestigationCommand, Box<dyn Error>> {
    let p = params("session:a")?;
    Ok(InvestigationCommand::Open {
        privacy_class: "private:property".to_owned(),
        record: Box::new(InvestigationState::new(InvestigationStateParams {
            investigation_id: "case:window".to_owned(),
            contract_basis: basis(),
            mission_id: p.mission_id,
            revision: 1,
            state: InvestigationLifecycle::Draft,
            question: "What caused the observation?".to_owned(),
            decision_informed: "Which evidence should be inspected next?".to_owned(),
            basis_anchor: p.current_anchor,
            hypotheses: ["hypothesis:a", "hypothesis:b"]
                .into_iter()
                .map(|id| CaseHypothesis {
                    hypothesis_id: id.to_owned(),
                    description: id.to_owned(),
                    epistemic_state: KnowledgeState::Unknown,
                    predictions: vec!["inspect the crop".to_owned()],
                    evidence: vec![],
                    contradictions: vec![],
                })
                .collect(),
            knowns: vec![],
            unknowns: vec![KnownStatement {
                statement_id: "unknown:coverage".to_owned(),
                text: "Side view is unavailable".to_owned(),
                epistemic_state: KnowledgeState::NotObservable,
                basis: vec![],
            }],
            discriminators: vec![],
            probes: vec!["probe:crop".to_owned()],
            stop_rules: vec!["bounded assessment".to_owned()],
            decision_deadline_ns: 100,
        })?),
    })
}

struct Fixture {
    sessions: ReferenceSessionStore,
    cases: ReferenceInvestigationStore,
    p: AgentSessionParams,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let p = params("session:a")?;
        let mut sessions = ReferenceSessionStore::default();
        sessions.open(p.clone(), basis(), TimestampNs(1))?;
        Ok(Self {
            sessions,
            cases: ReferenceInvestigationStore::new(InvestigationLimits::default())?,
            p,
        })
    }
    fn run(
        &mut self,
        c: &InvestigationCommand,
        now: i128,
    ) -> Result<InvestigationRevision, InvestigationError> {
        self.cases.execute(
            &mut self.sessions,
            &self.p.principal_id,
            &self.p.session_id,
            c,
            TimestampNs(now),
        )
    }
    fn change(
        &mut self,
        r: &InvestigationRevision,
        change: InvestigationChange,
    ) -> Result<InvestigationRevision, InvestigationError> {
        self.run(
            &InvestigationCommand::Change {
                case_id: r.record.investigation_id.clone(),
                expected: r.digest(),
                change,
            },
            10,
        )
    }
    fn head(&mut self, now: i128) -> Result<InvestigationRevision, InvestigationError> {
        self.run(
            &InvestigationCommand::Inspect {
                case_id: "case:window".to_owned(),
                revision: None,
            },
            now,
        )
    }
}
fn evidence() -> ContentDigest {
    ContentDigest::sha256(b"authorized source citation")
}
fn conclusion(refuted: bool) -> InvestigationChange {
    InvestigationChange::Conclude {
        refuted,
        stop_rule: "bounded assessment".to_owned(),
        assessment: evidence(),
        residual_unknowns: BTreeSet::from(["unknown:coverage".to_owned()]),
    }
}
fn assess(
    f: &mut Fixture,
    r: &InvestigationRevision,
    id: &str,
    disposition: HypothesisDisposition,
) -> Result<InvestigationRevision, InvestigationError> {
    let r = f.change(
        r,
        InvestigationChange::Cite {
            hypothesis: id.to_owned(),
            evidence: evidence(),
            contradicts: disposition != HypothesisDisposition::Supported,
        },
    )?;
    f.change(
        &r,
        InvestigationChange::Assess {
            hypothesis: id.to_owned(),
            evidence: evidence(),
            disposition,
        },
    )
}

#[test]
fn exact_open_retry_preserves_progress_history_and_terminal_identity() -> TestResult {
    let mut f = Fixture::new()?;
    let command = opening()?;
    let first = f.run(&command, 10)?;
    let active = f.change(&first, InvestigationChange::Activate)?;
    assert_eq!(f.run(&command, 10)?, active);
    assert_eq!(active.predecessor(), Some(first.digest()));
    let old = f.run(
        &InvestigationCommand::Inspect {
            case_id: "case:window".to_owned(),
            revision: Some(first.digest()),
        },
        10,
    )?;
    assert_eq!(old, first);
    let cancelled = f.change(
        &active,
        InvestigationChange::SetState {
            state: InvestigationLifecycle::Cancelled,
            reason: evidence(),
        },
    )?;
    let closed = f.change(
        &cancelled,
        InvestigationChange::SetState {
            state: InvestigationLifecycle::Closed,
            reason: evidence(),
        },
    )?;
    assert_eq!(f.run(&command, 10)?, closed);
    assert_eq!(
        f.change(&closed, InvestigationChange::Activate),
        Err(InvestigationError::InvalidTransition)
    );
    Ok(())
}

#[test]
fn citations_dispositions_and_knowledge_states_remain_orthogonal() -> TestResult {
    let mut f = Fixture::new()?;
    let first = f.run(&opening()?, 10)?;
    let r = f.change(&first, InvestigationChange::Activate)?;
    let r = assess(&mut f, &r, "hypothesis:a", HypothesisDisposition::Supported)?;
    assert_eq!(
        f.change(&r, conclusion(false)),
        Err(InvestigationError::UnresolvedAlternatives)
    );
    let r = assess(&mut f, &r, "hypothesis:b", HypothesisDisposition::Refuted)?;
    let done = f.change(&r, conclusion(false))?;
    assert_eq!(done.record.state, InvestigationLifecycle::Resolved);
    assert_eq!(done.record.unknowns, first.record.unknowns);
    assert_eq!(done.record.probes, first.record.probes);
    assert_eq!(done.record.hypotheses.len(), 2);
    assert!(
        done.record
            .hypotheses
            .iter()
            .all(|h| h.epistemic_state == KnowledgeState::Unknown)
    );
    assert!(done.control.is_terminal());
    Ok(())
}

#[test]
fn missing_citations_and_wrong_evidence_side_cannot_advance_dispositions() -> TestResult {
    let mut f = Fixture::new()?;
    let r = f.run(&opening()?, 10)?;
    let r = f.change(&r, InvestigationChange::Activate)?;
    let change = InvestigationChange::Assess {
        hypothesis: "hypothesis:a".to_owned(),
        evidence: evidence(),
        disposition: HypothesisDisposition::Refuted,
    };
    assert_eq!(
        f.change(&r, change.clone()),
        Err(InvestigationError::EvidenceRequired)
    );
    let r = f.change(
        &r,
        InvestigationChange::Cite {
            hypothesis: "hypothesis:a".to_owned(),
            evidence: evidence(),
            contradicts: false,
        },
    )?;
    assert_eq!(
        f.change(&r, change),
        Err(InvestigationError::EvidenceRequired)
    );
    assert_eq!(f.head(10)?, r);
    Ok(())
}

#[test]
fn refutation_is_final_and_terminal_refutation_requires_all_alternatives() -> TestResult {
    let mut f = Fixture::new()?;
    let r = f.run(&opening()?, 10)?;
    let r = f.change(&r, InvestigationChange::Activate)?;
    let r = assess(&mut f, &r, "hypothesis:a", HypothesisDisposition::Refuted)?;
    assert_eq!(
        f.change(&r, conclusion(true)),
        Err(InvestigationError::UnresolvedAlternatives)
    );
    let cited = f.change(
        &r,
        InvestigationChange::Cite {
            hypothesis: "hypothesis:a".to_owned(),
            evidence: evidence(),
            contradicts: false,
        },
    )?;
    assert_eq!(
        f.change(
            &cited,
            InvestigationChange::Assess {
                hypothesis: "hypothesis:a".to_owned(),
                evidence: evidence(),
                disposition: HypothesisDisposition::Supported
            }
        ),
        Err(InvestigationError::InvalidTransition)
    );
    let r = assess(
        &mut f,
        &cited,
        "hypothesis:b",
        HypothesisDisposition::Refuted,
    )?;
    assert_eq!(
        f.change(&r, conclusion(true))?.record.state,
        InvestigationLifecycle::Refuted
    );
    Ok(())
}

#[test]
fn conclusion_cannot_drop_unknowns_or_invent_a_stop_rule() -> TestResult {
    let mut f = Fixture::new()?;
    let r = f.run(&opening()?, 10)?;
    let r = f.change(&r, InvestigationChange::Activate)?;
    for (rule, residuals) in [
        ("invented", BTreeSet::from(["unknown:coverage".to_owned()])),
        ("bounded assessment", BTreeSet::new()),
    ] {
        assert_eq!(
            f.change(
                &r,
                InvestigationChange::Conclude {
                    refuted: false,
                    stop_rule: rule.to_owned(),
                    assessment: evidence(),
                    residual_unknowns: residuals
                }
            ),
            Err(InvestigationError::ResidualsRequired)
        );
        assert_eq!(f.head(10)?, r);
    }
    Ok(())
}

#[test]
fn second_session_can_continue_but_cannot_overwrite_a_newer_revision() -> TestResult {
    let mut f = Fixture::new()?;
    let old = f.run(&opening()?, 10)?;
    let current = f.change(&old, InvestigationChange::Activate)?;
    let p = params("session:b")?;
    f.sessions.open(p.clone(), basis(), TimestampNs(10))?;
    f.p = p;
    assert_eq!(
        f.change(&old, InvestigationChange::Activate),
        Err(InvestigationError::StaleRevision)
    );
    let next = f.change(
        &current,
        InvestigationChange::SetState {
            state: InvestigationLifecycle::AwaitingEvidence,
            reason: evidence(),
        },
    )?;
    assert_eq!(next.author_session, f.p.session_id);
    assert_eq!(next.predecessor(), Some(current.digest()));
    Ok(())
}

#[test]
fn unauthorized_domains_do_not_disclose_current_or_historical_revisions() -> TestResult {
    for variant in 0..3 {
        let mut f = Fixture::new()?;
        let r = f.run(&opening()?, 10)?;
        let mut p = params("session:other")?;
        match variant {
            0 => p.principal_id = PrincipalId::parse("principal:other")?,
            1 => p.mission_id = MissionId::parse("mission:other")?,
            _ => p.privacy_scope.clear(),
        }
        f.sessions.open(p.clone(), basis(), TimestampNs(10))?;
        f.p = p;
        for revision in [None, Some(r.digest())] {
            assert_eq!(
                f.run(
                    &InvestigationCommand::Inspect {
                        case_id: "case:window".to_owned(),
                        revision
                    },
                    10
                ),
                Err(InvestigationError::Unavailable)
            );
        }
    }
    Ok(())
}

#[test]
fn narrowing_grants_and_world_drift_are_rechecked_before_mutation() -> TestResult {
    for drift in [false, true] {
        let mut f = Fixture::new()?;
        let r = f.run(&opening()?, 10)?;
        let s = f
            .sessions
            .session(&f.p.principal_id, &f.p.session_id, TimestampNs(10))?;
        let mut anchor = s.current_anchor.clone();
        let mut grants = s.capabilities.clone();
        if drift {
            anchor.commit_sequence += 1;
        } else {
            grants.clear();
        }
        f.sessions.refresh(
            &f.p.principal_id,
            &f.p.session_id,
            SessionRefresh {
                expected_session_digest: s.session_digest(),
                current_anchor: anchor,
                capabilities: grants,
                privacy_scope: s.privacy_scope,
            },
            TimestampNs(10),
        )?;
        assert_eq!(
            f.change(&r, InvestigationChange::Activate),
            Err(if drift {
                InvestigationError::StaleBasis
            } else {
                InvestigationError::Denied
            })
        );
    }
    Ok(())
}

#[test]
fn exact_deadline_allows_uncertainty_and_cancel_but_not_fabricated_completion() -> TestResult {
    let mut f = Fixture::new()?;
    let r = f.run(&opening()?, 10)?;
    let r = f.change(&r, InvestigationChange::Activate)?;
    let command = |change| InvestigationCommand::Change {
        case_id: "case:window".to_owned(),
        expected: r.digest(),
        change,
    };
    assert_eq!(
        f.run(&command(conclusion(false)), 100),
        Err(InvestigationError::DeadlineElapsed)
    );
    let uncertain = f.run(
        &command(InvestigationChange::SetState {
            state: InvestigationLifecycle::Indeterminate,
            reason: evidence(),
        }),
        100,
    )?;
    assert_eq!(uncertain.record.unknowns, r.record.unknowns);
    assert_eq!(
        f.run(&opening()?, 99),
        Err(InvestigationError::ClockRegression)
    );
    assert_eq!(
        f.run(
            &InvestigationCommand::Change {
                case_id: "case:window".to_owned(),
                expected: uncertain.digest(),
                change: InvestigationChange::Activate
            },
            101
        ),
        Err(InvestigationError::DeadlineElapsed)
    );
    Ok(())
}

#[test]
fn failed_revision_capacity_never_changes_the_retained_head() -> TestResult {
    let mut f = Fixture::new()?;
    f.cases = ReferenceInvestigationStore::new(InvestigationLimits {
        max_revisions: 1,
        ..InvestigationLimits::default()
    })?;
    let r = f.run(&opening()?, 10)?;
    assert_eq!(
        f.change(&r, InvestigationChange::Activate),
        Err(InvestigationError::CapacityExceeded)
    );
    assert_eq!(f.head(10)?, r);
    assert_eq!(f.cases.revisions, 1);
    Ok(())
}

#[test]
fn public_record_mutations_and_nested_size_overflows_are_refused() -> TestResult {
    for variant in 0..5 {
        let mut f = Fixture::new()?;
        let mut command = opening()?;
        if let InvestigationCommand::Open { record, .. } = &mut command {
            match variant {
                0 => record.revision = 0,
                1 => record.state = InvestigationLifecycle::Resolved,
                2 => record.hypotheses[0].predictions = vec!["x".to_owned(); 129],
                3 => record.unknowns.push(record.unknowns[0].clone()),
                _ => record.hypotheses[0].contradictions = vec![evidence(); 129],
            }
        }
        assert!(f.run(&command, 10).is_err());
        assert_eq!(f.cases.revisions, 0);
    }
    Ok(())
}

#[test]
fn fresh_execution_is_byte_and_revision_identical() -> TestResult {
    let mut a = Fixture::new()?;
    let mut b = Fixture::new()?;
    let a1 = a.run(&opening()?, 10)?;
    let b1 = b.run(&opening()?, 10)?;
    let a2 = a.change(&a1, InvestigationChange::Activate)?;
    let b2 = b.change(&b1, InvestigationChange::Activate)?;
    assert_eq!(a2.try_canonical_bytes()?, b2.try_canonical_bytes()?);
    assert_eq!(a2.digest(), b2.digest());
    Ok(())
}
