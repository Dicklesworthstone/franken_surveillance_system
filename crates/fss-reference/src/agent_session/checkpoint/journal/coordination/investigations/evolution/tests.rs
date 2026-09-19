#![forbid(unsafe_code)]
use std::error::Error;
use fss_core::{AgentSessionParams, KnownStatement};
use crate::agent_session::SessionRefresh;
use super::*;
use super::super::tests::{basis, params, opening};

type TestResult = Result<(), Box<dyn Error>>;

fn root(text: &str) -> ContentDigest { ContentDigest::sha256(text.as_bytes()) }

struct Fixture { sessions: ReferenceSessionStore, cases: ReferenceInvestigationStore, p: AgentSessionParams }
impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let p = params("session:evolution")?;
        let mut sessions = ReferenceSessionStore::default();
        sessions.open(p.clone(), basis(), TimestampNs(1))?;
        Ok(Self { sessions, cases: ReferenceInvestigationStore::new(InvestigationLimits::default())?, p })
    }
    fn run(&mut self, command: &InvestigationCommand) -> Result<InvestigationRevision, InvestigationError> {
        self.cases.execute(&mut self.sessions, &self.p.principal_id, &self.p.session_id, command, TimestampNs(10))
    }
    fn open(&mut self) -> Result<InvestigationRevision, Box<dyn Error>> {
        let mut command = opening()?;
        if let InvestigationCommand::Open { record, .. } = &mut command {
            record.hypotheses[0].epistemic_state = KnowledgeState::Estimated;
            record.hypotheses[0].evidence.push(root("old"));
            record.hypotheses[1].contradictions.push(root("counter"));
            record.knowns.push(KnownStatement { statement_id: "known:continuity".to_owned(),
                text: "Continuity was observed".to_owned(), epistemic_state: KnowledgeState::Known,
                basis: vec!["basis:prior".to_owned()] });
        }
        Ok(self.run(&command)?)
    }
    fn change(&mut self, head: &InvestigationRevision, change: InvestigationChange)
        -> Result<InvestigationRevision, InvestigationError>
    {
        self.run(&InvestigationCommand::Change { case_id: head.record.investigation_id.clone(), expected: head.digest(), change })
    }
    fn evolve(&mut self, head: &InvestigationRevision, change: InvestigationEvolution)
        -> Result<InvestigationRevision, InvestigationError>
    {
        self.cases.evolve(&mut self.sessions, &self.p.principal_id, &self.p.session_id,
            &InvestigationEvolutionRequest { case_id: head.record.investigation_id.clone(), expected: head.digest(), change }, TimestampNs(10))
    }
    fn advance(&mut self) -> Result<LedgerAnchor, Box<dyn Error>> {
        let session = self.sessions.session(&self.p.principal_id, &self.p.session_id, TimestampNs(10))?;
        let mut anchor = session.current_anchor.clone();
        anchor.commit_sequence += 1;
        self.sessions.refresh(&self.p.principal_id, &self.p.session_id, SessionRefresh {
            expected_session_digest: session.session_digest(), current_anchor: anchor.clone(),
            capabilities: session.capabilities, privacy_scope: session.privacy_scope,
        }, TimestampNs(10))?;
        Ok(anchor)
    }
    fn rebase(&mut self, head: &InvestigationRevision) -> Result<InvestigationRevision, Box<dyn Error>> {
        let anchor = self.advance()?;
        Ok(self.evolve(head, InvestigationEvolution::Rebase { anchor, witness: root("basis changed") })?)
    }
}

pub(super) fn expansion() -> InvestigationEvolution {
    InvestigationEvolution::Expand {
        hypothesis: Box::new(CaseHypothesis { hypothesis_id: "hypothesis:c".to_owned(),
            description: "A third explanation".to_owned(), epistemic_state: KnowledgeState::Unknown,
            predictions: vec!["new observation".to_owned()], evidence: vec![], contradictions: vec![] }),
        discriminator: Box::new(CaseDiscriminator { discriminator_id: "discriminator:c".to_owned(),
            description: "Check the independent view".to_owned(),
            separates: vec!["hypothesis:a".to_owned(), "hypothesis:c".to_owned()],
            expected_outcomes: vec!["present".to_owned(), "absent".to_owned()] }),
        probe: "probe:independent".to_owned(),
    }
}

fn readmit(h: &str, evidence: ContentDigest, contradicts: bool) -> InvestigationEvolution {
    InvestigationEvolution::ReadmitCitation { citation: InvestigationCitation {
        hypothesis: h.to_owned(), evidence, contradicts }, witness: root("owner readmission receipt") }
}
fn assess(h: &str, evidence: ContentDigest, disposition: HypothesisDisposition) -> InvestigationChange {
    InvestigationChange::Assess { hypothesis: h.to_owned(), evidence, disposition }
}

#[test]
fn rebase_preserves_evidence_residuals_deadline_and_exact_predecessor() -> TestResult {
    let mut f = Fixture::new()?;
    let prior = f.open()?;
    let active = f.change(&prior, InvestigationChange::Activate)?;
    let supported = f.change(&active, assess("hypothesis:a", root("old"), HypothesisDisposition::Supported))?;
    let next = f.rebase(&supported)?;
    assert_eq!(next.predecessor(), Some(supported.digest()));
    assert_eq!(next.record.state, InvestigationLifecycle::AwaitingEvidence);
    assert_eq!(next.record.decision_deadline_ns, prior.record.decision_deadline_ns);
    assert_eq!(next.record.unknowns, prior.record.unknowns);
    assert_eq!(next.record.hypotheses[0].evidence, prior.record.hypotheses[0].evidence);
    assert_eq!(next.record.hypotheses[1].contradictions, prior.record.hypotheses[1].contradictions);
    assert_eq!(next.record.knowns[0].epistemic_state, KnowledgeState::Stale);
    assert_eq!(next.record.hypotheses[0].epistemic_state, KnowledgeState::Stale);
    assert!(next.control.hypotheses().values().all(|d| *d == HypothesisDisposition::Live));
    let validity = next.validity().ok_or("missing validity")?;
    assert_eq!(validity.source_anchor, prior.record.basis_anchor);
    assert_eq!(validity.source_revision, supported.digest());
    let historical = f.run(&InvestigationCommand::Inspect { case_id: prior.record.investigation_id.clone(), revision: Some(supported.digest()) })?;
    assert_eq!(historical, supported);
    Ok(())
}

#[test]
fn repeated_cite_does_not_launder_inherited_support_after_rebase() -> TestResult {
    let mut f = Fixture::new()?;
    let old = f.open()?;
    let rebased = f.rebase(&old)?;
    let active = f.change(&rebased, InvestigationChange::Activate)?;
    let repeated = f.change(&active, InvestigationChange::Cite { hypothesis: "hypothesis:a".to_owned(), evidence: root("old"), contradicts: false })?;
    assert_eq!(f.change(&repeated, assess("hypothesis:a", root("old"), HypothesisDisposition::Supported)), Err(InvestigationError::EvidenceRequired));
    let admitted = f.evolve(&repeated, readmit("hypothesis:a", root("old"), false))?;
    let supported = f.change(&admitted, assess("hypothesis:a", root("old"), HypothesisDisposition::Supported))?;
    assert_eq!(supported.record.hypotheses[0].epistemic_state, KnowledgeState::Stale);
    assert_eq!(supported.validity().ok_or("missing validity")?.readmissions().len(), 1);
    Ok(())
}

#[test]
fn inherited_root_cannot_move_to_another_hypothesis_or_side_to_escape_invalidation() -> TestResult {
    let mut f = Fixture::new()?;
    let old = f.open()?;
    let rebased = f.rebase(&old)?;
    let active = f.change(&rebased, InvestigationChange::Activate)?;
    let admitted = f.evolve(&active, readmit("hypothesis:a", root("old"), false))?;
    let attached = f.change(&admitted, InvestigationChange::Cite { hypothesis: "hypothesis:b".to_owned(), evidence: root("old"), contradicts: false })?;
    assert_eq!(f.change(&attached, assess("hypothesis:b", root("old"), HypothesisDisposition::Supported)), Err(InvestigationError::EvidenceRequired));
    let current = f.run(&InvestigationCommand::Inspect { case_id: "case:window".to_owned(), revision: None })?;
    let opposite = f.change(&current, InvestigationChange::Cite { hypothesis: "hypothesis:a".to_owned(), evidence: root("old"), contradicts: true })?;
    assert_eq!(f.change(&opposite, assess("hypothesis:a", root("old"), HypothesisDisposition::Refuted)), Err(InvestigationError::EvidenceRequired));
    Ok(())
}

#[test]
fn fresh_evidence_works_and_another_rebase_invalidates_previous_readmissions() -> TestResult {
    let mut f = Fixture::new()?;
    let old = f.open()?;
    let rebased = f.rebase(&old)?;
    let active = f.change(&rebased, InvestigationChange::Activate)?;
    let admitted = f.evolve(&active, readmit("hypothesis:a", root("old"), false))?;
    let fresh = f.change(&admitted, InvestigationChange::Cite { hypothesis: "hypothesis:b".to_owned(), evidence: root("fresh"), contradicts: false })?;
    let supported = f.change(&fresh, assess("hypothesis:b", root("fresh"), HypothesisDisposition::Supported))?;
    let again = f.rebase(&supported)?;
    let validity = again.validity().ok_or("missing validity")?;
    assert!(validity.readmissions().is_empty());
    assert!(validity.inherited_roots().contains(&root("fresh")));
    assert!(validity.needs_readmission("hypothesis:a", root("old"), false));
    Ok(())
}

#[test]
fn new_alternative_preserves_prior_refutation_and_blocks_premature_conclusion() -> TestResult {
    let mut f = Fixture::new()?;
    let old = f.open()?;
    let active = f.change(&old, InvestigationChange::Activate)?;
    let supported = f.change(&active, assess("hypothesis:a", root("old"), HypothesisDisposition::Supported))?;
    let refuted = f.change(&supported, assess("hypothesis:b", root("counter"), HypothesisDisposition::Refuted))?;
    let expanded = f.evolve(&refuted, expansion())?;
    assert_eq!(expanded.record.hypotheses[..2], refuted.record.hypotheses[..]);
    assert_eq!(expanded.control.hypotheses().get("hypothesis:b"), Some(&HypothesisDisposition::Refuted));
    assert_eq!(expanded.control.hypotheses().get("hypothesis:c"), Some(&HypothesisDisposition::Live));
    assert_eq!(expanded.record.knowns, old.record.knowns);
    assert_eq!(expanded.record.unknowns, old.record.unknowns);
    assert_eq!(expanded.record.stop_rules, old.record.stop_rules);
    assert_eq!(f.change(&expanded, InvestigationChange::Conclude { refuted: false, stop_rule: "bounded assessment".to_owned(),
        assessment: root("conclusion"), residual_unknowns: BTreeSet::from(["unknown:coverage".to_owned()]) }), Err(InvestigationError::UnresolvedAlternatives));
    Ok(())
}

#[test]
fn expansion_refuses_fake_knowledge_duplicate_ids_and_non_discriminating_probes() -> TestResult {
    let mut f = Fixture::new()?;
    let old = f.open()?;
    for mutation in 0..6 {
        let mut candidate = expansion();
        if let InvestigationEvolution::Expand { hypothesis: h, discriminator: d, .. } = &mut candidate {
            match mutation {
                0 => h.epistemic_state = KnowledgeState::Known,
                1 => h.evidence.push(root("pretend observation")),
                2 => d.separates[0] = "hypothesis:missing".to_owned(),
                3 => d.expected_outcomes[1] = d.expected_outcomes[0].clone(),
                4 => d.separates[0] = d.separates[1].clone(),
                _ => h.predictions.clear(),
            }
        }
        assert!(f.evolve(&old, candidate).is_err());
        assert_eq!(f.cases.entries.get("case:window").ok_or("missing entry")?.head, old);
    }
    let expanded = f.evolve(&old, expansion())?;
    assert_eq!(f.evolve(&expanded, expansion()), Err(InvestigationError::Conflict));
    Ok(())
}

#[test]
fn rebase_requires_the_actual_forward_session_anchor_and_unchanged_contract() -> TestResult {
    let mut f = Fixture::new()?;
    let old = f.open()?;
    let actual = f.advance()?;
    let mut wrong = actual.clone(); wrong.commit_sequence += 1;
    for anchor in [old.record.basis_anchor.clone(), wrong] {
        assert_eq!(f.evolve(&old, InvestigationEvolution::Rebase { anchor, witness: root("w") }), Err(InvestigationError::StaleBasis));
    }
    let entry = f.sessions.sessions.get_mut(&f.p.session_id).ok_or("missing session")?;
    entry.basis = ContractBasis::from_registry_bytes(fss_core::ContractBasisRegistryBytes::new(
        b"schemas", b"operations", b"views", b"capabilities", b"errors", b"costs", "test:other",
    ));
    assert_eq!(f.evolve(&old, InvestigationEvolution::Rebase { anchor: actual, witness: root("w") }), Err(InvestigationError::StaleBasis));
    Ok(())
}

#[test]
fn stale_revision_wrong_principal_and_revoked_capability_cannot_evolve() -> TestResult {
    let mut f = Fixture::new()?;
    let old = f.open()?;
    let expanded = f.evolve(&old, expansion())?;
    assert_eq!(f.evolve(&old, expansion()), Err(InvestigationError::StaleRevision));
    let request = InvestigationEvolutionRequest { case_id: "case:window".to_owned(), expected: expanded.digest(), change: expansion() };
    assert_eq!(f.cases.evolve(&mut f.sessions, &PrincipalId::parse("principal:other")?, &f.p.session_id, &request, TimestampNs(10)), Err(InvestigationError::Unavailable));
    f.sessions.sessions.get_mut(&f.p.session_id).ok_or("missing session")?.session.capabilities.clear();
    assert_eq!(f.evolve(&expanded, expansion()), Err(InvestigationError::Denied));
    Ok(())
}

#[test]
fn terminal_cases_and_elapsed_deadlines_cannot_be_reopened_or_extended() -> TestResult {
    let mut f = Fixture::new()?;
    let old = f.open()?;
    let cancelled = f.change(&old, InvestigationChange::SetState { state: InvestigationLifecycle::Cancelled, reason: root("stop") })?;
    let anchor = f.advance()?;
    assert_eq!(f.evolve(&cancelled, InvestigationEvolution::Rebase { anchor, witness: root("w") }), Err(InvestigationError::InvalidTransition));
    let mut f = Fixture::new()?;
    let old = f.open()?;
    let anchor = f.advance()?;
    let request = InvestigationEvolutionRequest { case_id: "case:window".to_owned(), expected: old.digest(),
        change: InvestigationEvolution::Rebase { anchor, witness: root("w") } };
    assert_eq!(f.cases.evolve(&mut f.sessions, &f.p.principal_id, &f.p.session_id, &request, TimestampNs(100)), Err(InvestigationError::DeadlineElapsed));
    assert_eq!(f.cases.entries.get("case:window").ok_or("missing entry")?.head, old);
    Ok(())
}

#[test]
fn rebased_conclusion_must_acknowledge_stale_previously_known_premises() -> TestResult {
    let mut f = Fixture::new()?;
    let old = f.open()?;
    let rebased = f.rebase(&old)?;
    let mut r = f.change(&rebased, InvestigationChange::Activate)?;
    for (h, e, side, disposition) in [
        ("hypothesis:a", root("old"), false, HypothesisDisposition::Supported),
        ("hypothesis:b", root("counter"), true, HypothesisDisposition::Refuted),
    ] {
        r = f.evolve(&r, readmit(h, e, side))?;
        r = f.change(&r, assess(h, e, disposition))?;
    }
    let mut residuals = BTreeSet::from(["unknown:coverage".to_owned()]);
    let conclude = |residual_unknowns| InvestigationChange::Conclude { refuted: false,
        stop_rule: "bounded assessment".to_owned(), assessment: root("conclusion"), residual_unknowns };
    assert_eq!(f.change(&r, conclude(residuals.clone())), Err(InvestigationError::ResidualsRequired));
    residuals.insert("known:continuity".to_owned());
    let ended = f.change(&r, conclude(residuals))?;
    assert_eq!(ended.record.state, InvestigationLifecycle::Resolved);
    assert_eq!(ended.record.knowns[0].epistemic_state, KnowledgeState::Stale);
    Ok(())
}

#[test]
fn capacity_exhaustion_keeps_old_head_and_each_rebase_witness_changes_identity() -> TestResult {
    let mut f = Fixture::new()?;
    let old = f.open()?;
    let target = f.advance()?;
    let mut other = f.cases.clone();
    let a = f.evolve(&old, InvestigationEvolution::Rebase { anchor: target.clone(), witness: root("one") })?;
    let b = other.evolve(&mut f.sessions, &f.p.principal_id, &f.p.session_id, &InvestigationEvolutionRequest {
        case_id: "case:window".to_owned(), expected: old.digest(),
        change: InvestigationEvolution::Rebase { anchor: target, witness: root("two") } }, TimestampNs(10))?;
    assert_ne!(a.digest(), b.digest());
    f.cases.limits.max_revisions = f.cases.revisions;
    assert_eq!(f.evolve(&a, expansion()), Err(InvestigationError::CapacityExceeded));
    assert_eq!(f.cases.entries.get("case:window").ok_or("missing entry")?.head, a);
    Ok(())
}

#[test]
fn all_nine_knowledge_states_are_preserved_or_conservatively_invalidated() -> TestResult {
    for state in [KnowledgeState::Known, KnowledgeState::Estimated, KnowledgeState::Unknown,
        KnowledgeState::Conflicted, KnowledgeState::Stale, KnowledgeState::NotObservable,
        KnowledgeState::Redacted, KnowledgeState::Indeterminate, KnowledgeState::NotApplicable]
    {
        let mut f = Fixture::new()?;
        let mut command = opening()?;
        if let InvestigationCommand::Open { record, .. } = &mut command {
            record.hypotheses[0].epistemic_state = state;
            record.unknowns[0].epistemic_state = state;
        }
        let old = f.run(&command)?;
        assert_eq!(old.digest(), old.canonical_digest(INVESTIGATION_REVISION_DOMAIN));
        let new = f.rebase(&old)?;
        let expected = if matches!(state, KnowledgeState::Known | KnowledgeState::Estimated) { KnowledgeState::Stale } else { state };
        assert_eq!(new.record.hypotheses[0].epistemic_state, expected);
        assert_eq!(new.record.unknowns[0].epistemic_state, expected);
        assert_eq!(new.digest(), new.canonical_digest(EVOLVED_REVISION_DOMAIN));
    }
    Ok(())
}
