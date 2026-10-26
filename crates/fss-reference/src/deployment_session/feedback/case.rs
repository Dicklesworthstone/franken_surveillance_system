#![forbid(unsafe_code)]
//! Explicit feedback-to-investigation materialization through the existing case owner.
//!
//! The immutable feedback remains the allegation. Opening a draft gives it competing
//! explanations, a fixed review deadline and an ordinary case lifecycle; it never adjudicates
//! its truth, admits caller-supplied citations, executes a probe, or activates a correction.

use std::collections::BTreeSet;
use std::path::Path;

use fss_core::{
    AgentFeedbackProposal, CanonicalEncode, CaseDiscriminator, CaseHypothesis, ContentDigest,
    ContractBasis, FeedbackPrivacyClass, InvestigationLifecycle, InvestigationState,
    InvestigationStateParams, KnowledgeState, KnownStatement, MissionId, RequestedDisposition,
};
use fss_object::ObjectManifest;

use super::{FeedbackRequest, FeedbackTarget, PublishedFeedback, render_json, slot, target_json};
use crate::agent_session::checkpoint::journal::coordination::investigations::{
    CAPABILITY_INVESTIGATE, InvestigationCommand, InvestigationError, InvestigationRevision,
};
use crate::deployment_session::{
    DeploymentSessionError, MAX_RECORD_BYTES, PUBLICATIONS_RELPATH, SessionJournal,
    SessionPosition, hex, read_published,
};

/// The original feedback evidence time, plus one evidence-clock day. Retrying never renews it.
pub const CASE_REVIEW_LIFETIME_NS: i128 = 24 * 60 * 60 * 1_000_000_000;

/// Original opening content and the current native case revision admitted by the case owner.
#[derive(Clone, Debug, PartialEq)]
pub struct OpenedFeedbackCase {
    /// Immutable draft passed to the native owner. Its digest identifies the original intent.
    pub opening: InvestigationState,
    /// Current case head, which may have evolved since the original feedback request.
    pub revision: InvestigationRevision,
    /// Exact immutable feedback graph that grounds this draft's submission statement.
    pub feedback_root: ContentDigest,
    /// Committed session-journal root after the native case command; pinning is separate.
    pub journal_root: ContentDigest,
}

/// A case identity names one exact feedback publication; later retries never mint a second case.
#[must_use]
pub fn identity(feedback_root: ContentDigest) -> String {
    format!("case:feedback:{}", hex(feedback_root))
}

fn refused(reason: impl Into<String>) -> DeploymentSessionError {
    DeploymentSessionError::FeedbackRefused(reason.into())
}

fn invalid(reason: impl Into<String>) -> DeploymentSessionError {
    DeploymentSessionError::StoreInvalid(reason.into())
}

/// Verify the complete exact source shape, including an occupied slot from an older producer.
/// The generic publication reader alone authenticates hashes, not this feedback profile.
fn verify_feedback(
    root: &Path,
    published: &PublishedFeedback,
) -> Result<(), DeploymentSessionError> {
    let retained = read_published(root, &slot(&published.proposal.feedback_id)?)?
        .ok_or_else(|| invalid("the feedback source publication is unavailable"))?;
    let canonical = published.proposal.try_canonical_bytes()?;
    let rendering = ContentDigest::sha256(render_json(&published.proposal).as_bytes());
    if retained.root != published.root
        || retained.record != canonical
        || retained.children != vec![rendering]
    {
        return Err(invalid(
            "the feedback source differs from its exact canonical and rendered records",
        ));
    }
    let manifest_bytes = fss_publication::read_verified(
        root.join(PUBLICATIONS_RELPATH),
        published.root,
        MAX_RECORD_BYTES,
    )
    .map_err(|_| invalid("the feedback source manifest is unavailable"))?;
    let manifest = ObjectManifest::from_canonical_bytes(&manifest_bytes)
        .map_err(|_| invalid("the feedback source manifest is malformed"))?;
    let metadata = ContentDigest::sha256(&canonical);
    let expected = BTreeSet::from([metadata, rendering]);
    if manifest.kind() != "agent-feedback"
        || manifest.root() != published.root
        || manifest.metadata_digest() != Some(metadata)
        || manifest.children().len() != expected.len()
        || manifest.children().iter().copied().collect::<BTreeSet<_>>() != expected
    {
        return Err(invalid(
            "the feedback source manifest has another kind or child closure",
        ));
    }
    Ok(())
}

/// Only custody of the feedback submission is known here. Its literal statement and evidence
/// sides stay in the original graph; arbitrary cited digests are not admitted as case evidence.
fn opening(
    feedback: &AgentFeedbackProposal,
    feedback_root: ContentDigest,
    mission: MissionId,
    basis: ContractBasis,
) -> Result<InvestigationState, DeploymentSessionError> {
    let deadline = feedback
        .created_at_ns
        .checked_add(CASE_REVIEW_LIFETIME_NS)
        .ok_or_else(|| {
            refused("the original feedback review deadline exceeds the evidence-clock bound")
        })?;
    let case_id = identity(feedback_root);
    let alternatives = [
        (
            "supported",
            "The feedback statement is supported for its stated target and original evidence basis.",
            "Authorized source-owner evidence supports the exact original feedback statement.",
        ),
        (
            "contradicted",
            "The feedback statement is contradicted or misattributes the observed outcome.",
            "Authorized counterevidence contradicts the statement or exposes the attribution error.",
        ),
        (
            "unresolved",
            "Available evidence is insufficient or inapplicable to resolve the feedback statement.",
            "Missing custody, coverage, independence or applicability prevents a warranted conclusion.",
        ),
    ];
    let hypotheses: Vec<_> = alternatives
        .iter()
        .map(|(suffix, description, prediction)| CaseHypothesis {
            hypothesis_id: format!("{case_id}:{suffix}"),
            description: (*description).to_owned(),
            epistemic_state: KnowledgeState::Unknown,
            predictions: vec![(*prediction).to_owned()],
            evidence: Vec::new(),
            contradictions: Vec::new(),
        })
        .collect();
    Ok(InvestigationState::new(InvestigationStateParams {
        investigation_id: case_id.clone(),
        contract_basis: basis,
        mission_id: mission,
        revision: 1,
        state: InvestigationLifecycle::Draft,
        question: format!(
            "Should the {} proposal in retained feedback {} be supported, contradicted, or left unresolved?",
            feedback.kind.as_str(), feedback.feedback_id,
        ),
        decision_informed: "Whether this feedback warrants a separate corrective, validation, or policy-review plan. This draft cannot activate a change.".to_owned(),
        basis_anchor: feedback.basis_anchor.clone(),
        hypotheses: hypotheses.clone(),
        knowns: vec![KnownStatement {
            statement_id: "known:feedback-submission".to_owned(),
            text: format!(
                "Principal {} submitted feedback {} in session {}. Its exact literal statement, target and both evidence lists are retained under {}. This establishes the submission, not the truth of its claim.",
                feedback.principal_id.as_str(), feedback.feedback_id,
                feedback.session_id.as_str(), feedback_root.to_text(),
            ),
            epistemic_state: KnowledgeState::Known,
            basis: vec![feedback_root.to_text()],
        }],
        unknowns: vec![
            KnownStatement {
                statement_id: "unknown:feedback-source-admission".to_owned(),
                text: "Supporting and contradicting handles in the feedback remain caller-supplied citations until their source owners admit custody, scope and applicability. Neither evidence side was automatically attached to a hypothesis.".to_owned(),
                epistemic_state: KnowledgeState::Unknown,
                basis: vec![feedback_root.to_text()],
            },
            KnownStatement {
                statement_id: "unknown:feedback-truth".to_owned(),
                text: "The target's physical correctness, causal attribution and the feedback statement's validity remain unresolved; an operator or agent label is not independent outcome evidence.".to_owned(),
                epistemic_state: KnowledgeState::Unknown,
                basis: vec![feedback_root.to_text()],
            },
            KnownStatement {
                statement_id: "unknown:feedback-remedy".to_owned(),
                text: "The appropriate remedy, required validation, current applicability and full review resource cost remain unknown. Case conclusions confer no policy, model, privacy, retention or effect authority.".to_owned(),
                epistemic_state: KnowledgeState::Unknown,
                basis: vec![feedback_root.to_text()],
            },
        ],
        discriminators: vec![CaseDiscriminator {
            discriminator_id: format!("{case_id}:source-check"),
            description: "Inspect the exact retained feedback, then independently admit relevant source-owner evidence and counterevidence at its declared basis before assessing the alternatives.".to_owned(),
            separates: hypotheses.iter().map(|h| h.hypothesis_id.clone()).collect(),
            expected_outcomes: vec![
                "The exact statement has sufficient authorized supporting evidence.".to_owned(),
                "Verified counterevidence contradicts the statement or its attribution.".to_owned(),
                "Custody, coverage, independence or applicability remains insufficient.".to_owned(),
            ],
        }],
        // These are review questions, not invented executable probe handles.
        probes: Vec::new(),
        stop_rules: vec![
            "Retain unresolved uncertainty when source custody or attribution cannot be established.".to_owned(),
            "Conclude only after support, contradiction and every remaining unknown are explicitly assessed.".to_owned(),
        ],
        decision_deadline_ns: deadline,
    })?)
}

/// Run while feedback retains the admitted session-journal lock. The caller pins any successful
/// command or typed case refusal and preserves a returned revision even if pinning later fails.
pub(super) fn open(
    root: &Path,
    request: &FeedbackRequest,
    published: &PublishedFeedback,
    position: &SessionPosition,
    journal: &mut SessionJournal,
    now: fss_core::TimestampNs,
) -> Result<OpenedFeedbackCase, DeploymentSessionError> {
    let session = &position.session;
    if request.disposition != RequestedDisposition::OpenCase
        || published.proposal.requested_disposition != RequestedDisposition::OpenCase
        || published.proposal.privacy_class != FeedbackPrivacyClass::Private
        || published.proposal.session_id != session.session_id
        || published.proposal.principal_id != session.principal_id
        || published.proposal.basis_anchor != session.current_anchor
        || published.proposal.target_json != target_json(&request.target)
        || *position.workspace.contract_basis() != published.orientation.capsule().contract_basis
        || published.session != *session
    {
        return Err(refused(
            "feedback-case materialization requires the exact original private session submission",
        ));
    }
    // Initialization is administrative, so check the current case grants before enabling it.
    if !session.capabilities.contains(CAPABILITY_INVESTIGATE)
        || !session.capabilities.contains("CAP-AGENT-CASE-WRITE-001")
        || !session
            .privacy_scope
            .contains(super::super::investigation::CASE_PRIVACY_CLASS)
    {
        return Err(DeploymentSessionError::CaseRefused(
            InvestigationError::Denied,
        ));
    }
    // Ordinary feedback may record an allegation about a named plan. Turning it into private
    // mission cognition must also admit the plan's original owner, not just its existence.
    if let FeedbackTarget::Plan(plan_id) = &request.target {
        let (plan, plan_root, _) = super::super::plan::read_control_plan(root, plan_id)?;
        if plan.plan_id
            != super::super::plan::PlanRecord::identity(
                &plan.session_id,
                &plan.anchor_token,
                plan.plan_approval,
            )
            || plan.session_id != session.session_id
            || plan.mission_id != session.mission_id
            || plan.principal != session.principal_id
        {
            return Err(refused(
                "the feedback source plan identity or session, mission and principal ownership is invalid",
            ));
        }
        let bytes = fss_publication::read_verified(
            root.join(PUBLICATIONS_RELPATH),
            plan_root,
            MAX_RECORD_BYTES,
        )
        .map_err(|_| invalid("the feedback source plan manifest is unavailable"))?;
        let manifest = ObjectManifest::from_canonical_bytes(&bytes)
            .map_err(|_| invalid("the feedback source plan manifest is malformed"))?;
        let metadata = ContentDigest::sha256(&plan.to_bytes());
        let expected = BTreeSet::from([metadata, plan.control_plan_digest]);
        if manifest.kind() != "agent-plan"
            || manifest.root() != plan_root
            || manifest.metadata_digest() != Some(metadata)
            || manifest.children().len() != expected.len()
            || manifest.children().iter().copied().collect::<BTreeSet<_>>() != expected
        {
            return Err(invalid(
                "the feedback source plan manifest has another kind or child closure",
            ));
        }
    }
    verify_feedback(root, published)?;
    let opening = opening(
        &published.proposal,
        published.root,
        session.mission_id.clone(),
        position.workspace.contract_basis().clone(),
    )?;
    journal.enable_cases()?;
    let revision = journal.store.investigate(
        &session.principal_id,
        &session.session_id,
        InvestigationCommand::Open {
            record: Box::new(opening.clone()),
            privacy_class: super::super::investigation::CASE_PRIVACY_CLASS.to_owned(),
        },
        now,
    )?;
    Ok(OpenedFeedbackCase {
        opening,
        revision,
        feedback_root: published.root,
        journal_root: journal.store.committed_root(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_session::ReferenceSessionStore;
    use crate::agent_session::checkpoint::journal::coordination::investigations::{
        InvestigationChange, InvestigationLimits, ReferenceInvestigationStore,
    };
    use fss_core::{
        AgentSessionParams, FeedbackProposalKind, LedgerAnchor, PrincipalId, SessionId, TimestampNs,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn feedback(statement: String) -> TestResult<AgentFeedbackProposal> {
        Ok(AgentFeedbackProposal::new(
            "feedback:case-source",
            PrincipalId::parse("principal:case-review")?,
            SessionId::parse("session:case-review")?,
            LedgerAnchor::genesis("site:case-review"),
            "{\"kind\":\"event\",\"id\":\"event:source\"}",
            FeedbackProposalKind::Adjudication,
            statement,
            vec![ContentDigest::sha256(b"unverified caller support").to_text()],
            vec![ContentDigest::sha256(b"unverified caller counterevidence").to_text()],
            RequestedDisposition::OpenCase,
            FeedbackPrivacyClass::Private,
            10,
        )?)
    }

    #[test]
    fn complete_literal_feedback_stays_cited_without_becoming_case_truth() -> TestResult {
        let source = feedback("@/outside/policy.json --activate ".repeat(496))?;
        let source_root = ContentDigest::sha256(&source.try_canonical_bytes()?);
        let draft = opening(
            &source,
            source_root,
            MissionId::parse("mission:case-review")?,
            fss_core::reference_contract_basis(),
        )?;
        assert_eq!(draft.investigation_id, identity(source_root));
        assert_eq!(draft.decision_deadline_ns, 10 + CASE_REVIEW_LIFETIME_NS);
        assert_eq!(draft.knowns.len(), 1);
        assert_eq!(draft.knowns[0].basis, vec![source_root.to_text()]);
        assert!(draft.knowns[0].text.contains("not the truth of its claim"));
        assert_eq!(draft.hypotheses.len(), 3);
        assert!(draft.hypotheses.iter().all(|h| {
            h.epistemic_state == KnowledgeState::Unknown
                && h.evidence.is_empty()
                && h.contradictions.is_empty()
        }));
        assert!(
            draft
                .unknowns
                .iter()
                .all(|s| s.epistemic_state == KnowledgeState::Unknown)
        );
        assert!(draft.probes.is_empty());
        assert!(!draft.question.contains("@/outside"));
        assert!(draft.try_canonical_bytes()?.len() < 8192);
        assert!(source.statement.len() > 8192);
        assert!(source.statement.contains("--activate"));
        assert_ne!(
            identity(source_root),
            identity(ContentDigest::sha256(b"another feedback"))
        );
        Ok(())
    }

    #[test]
    fn feedback_draft_cannot_bypass_case_authority_or_renew_an_elapsed_opening() -> TestResult {
        let source = feedback("Review the exact source with its original deadline.".to_owned())?;
        let basis = fss_core::reference_contract_basis();
        let mission = MissionId::parse("mission:case-review")?;
        let draft = opening(
            &source,
            ContentDigest::sha256(&source.try_canonical_bytes()?),
            mission.clone(),
            basis.clone(),
        )?;
        for (capabilities, now, expected) in [
            (
                BTreeSet::from([super::super::CAPABILITY_FEEDBACK.to_owned()]),
                TimestampNs(10),
                InvestigationError::Denied,
            ),
            (
                BTreeSet::from([CAPABILITY_INVESTIGATE.to_owned()]),
                TimestampNs(draft.decision_deadline_ns),
                InvestigationError::DeadlineElapsed,
            ),
        ] {
            let mut sessions = ReferenceSessionStore::default();
            sessions.open(
                AgentSessionParams {
                    session_id: source.session_id.clone(),
                    principal_id: source.principal_id.clone(),
                    mission_id: mission.clone(),
                    capabilities,
                    privacy_scope: BTreeSet::from(["private:property".to_owned()]),
                    current_anchor: source.basis_anchor.clone(),
                    view_id: "AVIEW-003".to_owned(),
                    token_budget: 1000,
                    symbol_table_generation: 0,
                    last_acknowledged_situation_fingerprint: None,
                    created_at_ns: 0,
                    expires_at_ns: draft.decision_deadline_ns + 1000,
                },
                basis.clone(),
                now,
            )?;
            let mut cases = ReferenceInvestigationStore::new(InvestigationLimits::default())?;
            assert_eq!(
                cases.execute(
                    &mut sessions,
                    &source.principal_id,
                    &source.session_id,
                    &InvestigationCommand::Open {
                        record: Box::new(draft.clone()),
                        privacy_class: "private:property".to_owned(),
                    },
                    now,
                ),
                Err(expected),
            );
            assert_eq!(cases.heads().count(), 0);
        }
        let mut overflow = source;
        overflow.created_at_ns = i128::MAX;
        assert!(matches!(
            opening(
                &overflow,
                ContentDigest::sha256(b"overflow"),
                mission,
                basis
            ),
            Err(DeploymentSessionError::FeedbackRefused(_)),
        ));
        Ok(())
    }

    #[test]
    fn original_opening_recovers_evolved_case_without_reset_or_deadline_renewal() -> TestResult {
        let source = feedback("Review the original event attribution.".to_owned())?;
        let basis = fss_core::reference_contract_basis();
        let mission = MissionId::parse("mission:case-review")?;
        let draft = opening(
            &source,
            ContentDigest::sha256(&source.try_canonical_bytes()?),
            mission.clone(),
            basis.clone(),
        )?;
        let mut sessions = ReferenceSessionStore::default();
        sessions.open(
            AgentSessionParams {
                session_id: source.session_id.clone(),
                principal_id: source.principal_id.clone(),
                mission_id: mission,
                capabilities: BTreeSet::from([CAPABILITY_INVESTIGATE.to_owned()]),
                privacy_scope: BTreeSet::from(["private:property".to_owned()]),
                current_anchor: source.basis_anchor.clone(),
                view_id: "AVIEW-003".to_owned(),
                token_budget: 1000,
                symbol_table_generation: 0,
                last_acknowledged_situation_fingerprint: None,
                created_at_ns: 0,
                expires_at_ns: CASE_REVIEW_LIFETIME_NS + 1000,
            },
            basis,
            TimestampNs(10),
        )?;
        let mut cases = ReferenceInvestigationStore::new(InvestigationLimits::default())?;
        let command = InvestigationCommand::Open {
            record: Box::new(draft.clone()),
            privacy_class: "private:property".to_owned(),
        };
        let first = cases.execute(
            &mut sessions,
            &source.principal_id,
            &source.session_id,
            &command,
            TimestampNs(10),
        )?;
        let active = cases.execute(
            &mut sessions,
            &source.principal_id,
            &source.session_id,
            &InvestigationCommand::Change {
                case_id: draft.investigation_id.clone(),
                expected: first.digest(),
                change: InvestigationChange::Activate,
            },
            TimestampNs(11),
        )?;
        let after_deadline = cases.execute(
            &mut sessions,
            &source.principal_id,
            &source.session_id,
            &command,
            TimestampNs(draft.decision_deadline_ns + 1),
        )?;
        assert_eq!(after_deadline, active);
        assert_eq!(after_deadline.record().revision, 2);
        assert_eq!(
            after_deadline.record().decision_deadline_ns,
            draft.decision_deadline_ns
        );
        assert_eq!(cases.heads().count(), 1);
        Ok(())
    }
}
