#![forbid(unsafe_code)]

use super::*;
use crate::deployment_session::episode::{EpisodeRecord, TerminalOutcome};
use crate::deployment_session::plan::AlertRoute;
use fss_core::{
    AgentView, EpisodeOutcome, EpisodeOutcomeState, EpisodePrediction, ExecutionEpisode,
    FeedbackPrivacyClass, LedgerAnchor, MissionId, PrincipalId, PromotionState,
    RequestedDisposition, SessionId, TimestampNs,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fixture(
    kind: FeedbackProposalKind,
) -> TestResult<(
    PlanRecord,
    MissionRecord,
    PublishedEpisode,
    AgentFeedbackProposal,
)> {
    let session = SessionId::parse("session:learning-capture")?;
    let mission_id = MissionId::parse("mission:learning-capture")?;
    let principal = PrincipalId::parse("principal:learning-capture")?;
    let anchor = LedgerAnchor::genesis("site:learning-capture");
    let plan = PlanRecord {
        plan_id: "plan:learning-capture".to_owned(),
        session_id: session.clone(),
        mission_id: mission_id.clone(),
        principal: principal.clone(),
        anchor_token: "anchor:fixture".to_owned(),
        intent: "alert".to_owned(),
        event_id: "event:learning-capture".to_owned(),
        event_revision: ContentDigest::sha256(b"event revision"),
        route: AlertRoute {
            relay: "127.0.0.1:9".to_owned(),
            path: "/alert".to_owned(),
            plaintext_approval: ContentDigest::sha256(b"approved local route"),
            deadline_ms: 1000,
        },
        operation_id: "operation:learning-capture".to_owned(),
        obligation_id: "obligation:learning-capture".to_owned(),
        plan_approval: ContentDigest::sha256(b"plan approval"),
        control_plan_digest: ContentDigest::sha256(b"control plan"),
        case: None,
        created_at: TimestampNs(10),
    };
    let mission = MissionRecord {
        mission_id,
        session_id: session.clone(),
        principal: principal.clone(),
        site_lineage: anchor.site_lineage.clone(),
        mission: "Protect the door.".to_owned(),
        objective: "Alert the owner on a corroborated entry.".to_owned(),
        opening_anchor_token: plan.anchor_token.clone(),
        view: AgentView::Brief,
        token_budget: 32000,
        created_at: TimestampNs(10),
    };
    let episode = ExecutionEpisode::new(
        EpisodeRecord::identity(&plan.plan_id),
        session.clone(),
        mission.mission_id.as_str(),
        anchor.clone(),
        anchor.clone(),
        ContentDigest::sha256(&plan.to_bytes()).to_text(),
        vec![EpisodePrediction {
            prediction_id: "prediction:warranted".to_owned(),
            statement: "The reported entry warrants an alert.".to_owned(),
            expected_state: "warranted".to_owned(),
            observed_state: None,
            error: None,
        }],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        EpisodeOutcome {
            state: EpisodeOutcomeState::Cancelled,
            success_predicates: Vec::new(),
            failed_predicates: Vec::new(),
            indeterminate_predicates: vec!["warranted".to_owned()],
        },
        "{\"dispatches\":0,\"effectSpanNs\":0}",
        Vec::new(),
        vec![
            "The underlying physical event remains unobserved.".to_owned(),
            "Agent tokens, compute and operator attention were not metered.".to_owned(),
        ],
        plan.control_plan_digest.to_text(),
    )?;
    let published = PublishedEpisode {
        record: EpisodeRecord {
            plan_id: plan.plan_id.clone(),
            mission_id: mission.mission_id.clone(),
            principal: principal.clone(),
            operation_id: plan.operation_id.clone(),
            terminal_state: TerminalOutcome::Withdrawn,
            episode,
            recorded_at: TimestampNs(200),
        },
        root: ContentDigest::sha256(b"retained episode root"),
        rendering: ContentDigest::sha256(b"retained episode rendering"),
    };
    let feedback = AgentFeedbackProposal::new(
        "feedback:learning-capture",
        principal,
        session,
        anchor,
        super::super::feedback::target_json(&FeedbackTarget::Plan(plan.plan_id.clone())),
        kind,
        "Review this procedure against independent held-out incidents.",
        vec![ContentDigest::sha256(b"retained plan root").to_text()],
        Vec::new(),
        RequestedDisposition::CreateLearningProposal,
        FeedbackPrivacyClass::Private,
        100,
    )?;
    Ok((plan, mission, published, feedback))
}

#[test]
fn capture_preserves_uncertainty_instead_of_learning_success_from_a_label() -> TestResult {
    for kind in [
        FeedbackProposalKind::Helpful,
        FeedbackProposalKind::Harmful,
        FeedbackProposalKind::PolicyCandidate,
    ] {
        let (plan, mission, episode, feedback) = fixture(kind)?;
        let blueprint = compile(&Sources {
            feedback: &feedback,
            feedback_root: ContentDigest::sha256(b"original feedback root"),
            plan: &plan,
            plan_root: ContentDigest::sha256(b"retained plan root"),
            episode: &episode,
            mission: &mission,
            evidence: vec![episode.root],
        })?;
        assert_eq!(blueprint.proposal.statement, feedback.statement);
        assert_eq!(
            blueprint.proposal.source_episode_id,
            episode.record.episode.episode_id
        );
        assert_eq!(blueprint.proposal.promotion_state, PromotionState::Captured);
        assert_eq!(blueprint.proposal.confidence_numerator, 0);
        assert_eq!(blueprint.proposal.helpful_outcomes, 0);
        assert_eq!(blueprint.proposal.harmful_outcomes, 0);
        assert_eq!(
            blueprint.experience.evidence_strength,
            EvidenceStrength::SingleEpisode
        );
        assert_eq!(blueprint.experience.confidence_numerator, 0);
        assert_eq!(blueprint.experience.cost, BudgetVector::ZERO);
        assert_eq!(blueprint.experience.objective, mission.objective);
        assert_eq!(blueprint.experience.created_at_ns, 200);
        assert_eq!(blueprint.proposal.review_after_ns, Some(200 + REVIEW_NS));
        assert_eq!(blueprint.proposal.expiry_ns, Some(200 + EXPIRY_NS));
        assert!(
            blueprint
                .experience
                .initial_epistemic_map
                .iter()
                .any(|statement| {
                    statement.statement_id == "prediction:warranted"
                        && statement.epistemic_state == KnowledgeState::Estimated
                })
        );
        for mandatory in [COST_UNKNOWN, EFFICACY_UNKNOWN] {
            assert!(
                blueprint
                    .experience
                    .initial_epistemic_map
                    .iter()
                    .any(|statement| {
                        statement.epistemic_state == KnowledgeState::Unknown
                            && statement.text == mandatory
                    })
            );
            assert!(
                blueprint
                    .missing_evidence
                    .iter()
                    .any(|entry| entry == mandatory)
            );
        }
        assert!(blueprint.experience.predictive_signals.is_empty());
        assert!(blueprint.experience.misleading_signals.is_empty());
        assert!(blueprint.proposal.counterexamples.is_empty());
        assert!(!blueprint.proposal.required_validation.is_empty());
        assert!(
            blueprint
                .proposal
                .applicability_json
                .contains("held-out validation")
        );
        let decoded = decode_experience(&blueprint.experience.canonical_bytes())?;
        assert_eq!(decoded, blueprint.experience);
    }
    Ok(())
}

#[test]
fn source_substitution_changes_content_without_minting_a_second_capture_identity() -> TestResult {
    let (plan, mission, mut episode, feedback) = fixture(FeedbackProposalKind::PolicyCandidate)?;
    let first = compile(&Sources {
        feedback: &feedback,
        feedback_root: ContentDigest::sha256(b"original feedback root"),
        plan: &plan,
        plan_root: ContentDigest::sha256(b"retained plan root"),
        episode: &episode,
        mission: &mission,
        evidence: vec![episode.root],
    })?;
    episode.root = ContentDigest::sha256(b"replaced episode root");
    let replaced = compile(&Sources {
        feedback: &feedback,
        feedback_root: ContentDigest::sha256(b"original feedback root"),
        plan: &plan,
        plan_root: ContentDigest::sha256(b"retained plan root"),
        episode: &episode,
        mission: &mission,
        evidence: vec![episode.root],
    })?;
    assert_eq!(
        first.experience.experience_id,
        replaced.experience.experience_id
    );
    assert_eq!(first.proposal.proposal_id, replaced.proposal.proposal_id);
    assert_ne!(
        first.experience.canonical_bytes(),
        replaced.experience.canonical_bytes()
    );
    assert_ne!(
        first.proposal.canonical_bytes(),
        replaced.proposal.canonical_bytes()
    );
    Ok(())
}
