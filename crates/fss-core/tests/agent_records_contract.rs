#![forbid(unsafe_code)]
//! Contract tests for the durable agent record types (fss-x4a.30.83.57-62).

use fss_core::{
    AgentFinding, AttributionCauseClass, AttributionHypothesis, BudgetVector, CanonicalEncode,
    CanonicalEncoder, ContractError, EpisodeOutcome, EpisodeOutcomeState, EpisodePrediction,
    EvidenceStrength, ExecutionEpisode, ExperienceCapsule, KnownStatement, LearningClass,
    LearningProposal, LedgerAnchor, MissionId, PromotionState, SessionId, WorkClaim,
    WorkClaimState,
};

fn cost() -> BudgetVector {
    BudgetVector::builder()
        .latency_ms(50)
        .build()
        .unwrap_or_else(|_| unreachable!())
}

#[test]
fn test_work_claim_never_confers_effect_authority() -> Result<(), Box<dyn std::error::Error>> {
    let claim = WorkClaim::new(
        "claim:gate-review",
        Some("case:gate".to_owned()),
        "session:guard",
        "{\"zones\":[\"gate\"]}".to_owned(),
        LedgerAnchor::genesis("site:fss:claims"),
        3,
        1_000,
        9_000,
        WorkClaimState::Active,
        vec!["claim:dependency".to_owned()],
        "{\"done\":2,\"total\":5}".to_owned(),
        None,
    )?;
    // CONSTITUTIONAL: a work claim never confers effect authority. The
    // canonical encoding terminates with the literal false flag, so every
    // claim digest binds the refusal.
    assert!(!claim.claim_digest().to_text().is_empty());
    // The trailing encoded flag is the literal effect-authority refusal.
    {
        let mut encoder = CanonicalEncoder::new();
        claim.encode_canonical(&mut encoder);
        let bytes = encoder.finish();
        assert_eq!(
            bytes[bytes.len() - 1],
            0,
            "effect authority flag must encode false"
        );
    }
    // Fencing: lease incarnation must be at least 1.
    assert!(
        WorkClaim::new(
            "claim:x",
            None,
            "session:guard",
            "{}",
            LedgerAnchor::genesis("site:fss:claims"),
            0,
            1_000,
            9_000,
            WorkClaimState::Offered,
            vec![],
            "{}",
            None,
        )
        .is_err()
    );
    // Expiry must be after creation.
    assert!(
        WorkClaim::new(
            "claim:x",
            None,
            "session:guard",
            "{}",
            LedgerAnchor::genesis("site:fss:claims"),
            1,
            1_000,
            1_000,
            WorkClaimState::Offered,
            vec![],
            "{}",
            None,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn test_finding_requires_evidence_and_states() -> Result<(), Box<dyn std::error::Error>> {
    let finding = AgentFinding::new(
        "finding:gate-0042",
        MissionId::parse("mission:guard")?,
        Some("branch:gate".to_owned()),
        "principal:guard",
        LedgerAnchor::genesis("site:fss:findings"),
        "The gate scuffing is consistent with a boot heel.".to_owned(),
        fss_core::KnowledgeState::Estimated,
        vec!["evidence:frame-0042".to_owned()],
        vec![],
        vec!["assumption:night-lighting".to_owned()],
        vec!["coverage:gate-window".to_owned()],
        vec!["receipt:decode-frame-0042".to_owned()],
        vec!["object:gate-latch".to_owned()],
        vec!["follow-up:compare-previous-nights".to_owned()],
        1_000,
    )?;
    assert_eq!(finding.epistemic_state, fss_core::KnowledgeState::Estimated);
    let digest = finding.finding_digest();
    // A finding without supporting evidence is an unanchored claim.
    assert_eq!(
        AgentFinding::new(
            "finding:x",
            MissionId::parse("mission:guard")?,
            None,
            "principal:guard",
            LedgerAnchor::genesis("site:fss:findings"),
            "claim".to_owned(),
            fss_core::KnowledgeState::Known,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            1_000,
        ),
        Err(ContractError::EvidenceRequired)
    );
    let _ = digest;
    Ok(())
}

#[test]
fn test_learning_proposal_starts_captured_and_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let proposal = LearningProposal::record(
        "learning:gate-night-001",
        LearningClass::CoverageGeometryLesson,
        "episode:gate-0042",
        "Night gate coverage improves after recalibration.".to_owned(),
        "{\"deployment\":\"home\"}".to_owned(),
        vec!["evidence:recalibration-run".to_owned()],
        vec![],
        vec![],
        750_000,
        3,
        0,
        vec!["held-out night window".to_owned()],
        Some(90_000),
        Some(180_000),
        vec!["revive if recalibration repeats".to_owned()],
        "decision:learning:0001",
    )?;
    // Silent activation is structurally impossible: new proposals start
    // captured, and only the promotion ladder moves them.
    assert_eq!(proposal.promotion_state, PromotionState::Captured);
    let again = LearningProposal::record(
        "learning:gate-night-001",
        LearningClass::CoverageGeometryLesson,
        "episode:gate-0042",
        "Night gate coverage improves after recalibration.".to_owned(),
        "{\"deployment\":\"home\"}".to_owned(),
        vec!["evidence:recalibration-run".to_owned()],
        vec![],
        vec![],
        750_000,
        3,
        0,
        vec!["held-out night window".to_owned()],
        Some(90_000),
        Some(180_000),
        vec!["revive if recalibration repeats".to_owned()],
        "decision:learning:0001",
    )?;
    assert_eq!(proposal.proposal_digest(), again.proposal_digest());
    // Micro-confidence bound.
    assert!(
        LearningProposal::record(
            "learning:x",
            LearningClass::FactCandidate,
            "episode:x",
            "statement".to_owned(),
            "{}",
            vec!["evidence:x".to_owned()],
            vec![],
            vec![],
            1_000_001,
            0,
            0,
            vec![],
            None,
            None,
            vec![],
            "decision:learning:x",
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn test_experience_capsule_carries_signals_and_bounds() -> Result<(), Box<dyn std::error::Error>> {
    let capsule = ExperienceCapsule::new(
        "experience:gate-night",
        MissionId::parse("mission:guard")?,
        vec!["deployment:home".to_owned()],
        LedgerAnchor::genesis("site:fss:experience"),
        "{\"zones\":[\"gate\"],\"hours\":\"night\"}".to_owned(),
        "Watch the gate at night.".to_owned(),
        vec![KnownStatement {
            statement_id: "statement:coverage-ok".to_owned(),
            text: "Coverage certified for the window.".to_owned(),
            epistemic_state: fss_core::KnowledgeState::Known,
            basis: vec!["coverage:gate-window".to_owned()],
        }],
        vec!["session.open".to_owned(), "query".to_owned()],
        "Partial: detected but misclassified once.".to_owned(),
        vec!["signal:thermal-contrast".to_owned()],
        vec!["signal:headlight-flare".to_owned()],
        vec!["assumption:no-rain".to_owned()],
        cost(),
        vec!["applies to night gates".to_owned()],
        EvidenceStrength::SingleEpisode,
        600_000,
        30,
        "privacy:operational",
        1_000,
    )?;
    assert_eq!(capsule.evidence_strength, EvidenceStrength::SingleEpisode);
    assert_eq!(capsule.failed_assumptions.len(), 1);
    let digest = capsule.experience_digest();
    let rebuilt = ExperienceCapsule::new(
        "experience:gate-night",
        MissionId::parse("mission:guard")?,
        vec!["deployment:home".to_owned()],
        LedgerAnchor::genesis("site:fss:experience"),
        "{\"zones\":[\"gate\"],\"hours\":\"night\"}".to_owned(),
        "Watch the gate at night.".to_owned(),
        vec![KnownStatement {
            statement_id: "statement:coverage-ok".to_owned(),
            text: "Coverage certified for the window.".to_owned(),
            epistemic_state: fss_core::KnowledgeState::Known,
            basis: vec!["coverage:gate-window".to_owned()],
        }],
        vec!["session.open".to_owned(), "query".to_owned()],
        "Partial: detected but misclassified once.".to_owned(),
        vec!["signal:thermal-contrast".to_owned()],
        vec!["signal:headlight-flare".to_owned()],
        vec!["assumption:no-rain".to_owned()],
        cost(),
        vec!["applies to night gates".to_owned()],
        EvidenceStrength::SingleEpisode,
        600_000,
        30,
        "privacy:operational",
        1_000,
    )?;
    assert_eq!(digest, rebuilt.experience_digest());
    Ok(())
}

#[test]
fn test_execution_episode_records_predictions_and_outcome() -> Result<(), Box<dyn std::error::Error>>
{
    let episode = ExecutionEpisode::new(
        "episode:gate-0042",
        SessionId::parse("session:guard")?,
        "objective:gate-check",
        LedgerAnchor::genesis("site:fss:episodes"),
        LedgerAnchor::genesis("site:fss:episodes"),
        "plan:gate-check:digest0001",
        vec![EpisodePrediction {
            prediction_id: "prediction:entry-alert".to_owned(),
            statement: "Entry triggers an alert within 30s.".to_owned(),
            expected_state: "alert-delivered".to_owned(),
            observed_state: Some("alert-delivered".to_owned()),
            error: Some(0.25),
        }],
        vec!["receipt:step-1".to_owned()],
        vec![],
        vec!["obligation:log-retention".to_owned()],
        EpisodeOutcome {
            state: EpisodeOutcomeState::Succeeded,
            success_predicates: vec!["alert delivered".to_owned()],
            failed_predicates: vec![],
            indeterminate_predicates: vec![],
        },
        "{\"cpuMillis\":420}".to_owned(),
        vec![AttributionHypothesis {
            cause_class: AttributionCauseClass::Calibration,
            statement: "Residual error traces to pre-recalibration frames.".to_owned(),
            supporting_evidence: vec!["evidence:frame-0042".to_owned()],
            contradicting_evidence: vec![],
            confidence_numerator: 700_000,
        }],
        vec!["residual:shed-interior-unobserved".to_owned()],
        "decision:episode:0001",
    )?;
    assert_eq!(episode.outcome.state, EpisodeOutcomeState::Succeeded);
    assert_eq!(episode.predictions.len(), 1);
    let digest = episode.episode_digest();
    let rebuilt = ExecutionEpisode::new(
        "episode:gate-0042",
        SessionId::parse("session:guard")?,
        "objective:gate-check",
        LedgerAnchor::genesis("site:fss:episodes"),
        LedgerAnchor::genesis("site:fss:episodes"),
        "plan:gate-check:digest0001",
        vec![EpisodePrediction {
            prediction_id: "prediction:entry-alert".to_owned(),
            statement: "Entry triggers an alert within 30s.".to_owned(),
            expected_state: "alert-delivered".to_owned(),
            observed_state: Some("alert-delivered".to_owned()),
            error: Some(0.25),
        }],
        vec!["receipt:step-1".to_owned()],
        vec![],
        vec!["obligation:log-retention".to_owned()],
        EpisodeOutcome {
            state: EpisodeOutcomeState::Succeeded,
            success_predicates: vec!["alert delivered".to_owned()],
            failed_predicates: vec![],
            indeterminate_predicates: vec![],
        },
        "{\"cpuMillis\":420}".to_owned(),
        vec![AttributionHypothesis {
            cause_class: AttributionCauseClass::Calibration,
            statement: "Residual error traces to pre-recalibration frames.".to_owned(),
            supporting_evidence: vec!["evidence:frame-0042".to_owned()],
            contradicting_evidence: vec![],
            confidence_numerator: 700_000,
        }],
        vec!["residual:shed-interior-unobserved".to_owned()],
        "decision:episode:0001",
    )?;
    assert_eq!(digest, rebuilt.episode_digest());
    // Attribution confidence is micro-bounded.
    let mut over = episode.clone();
    over.attribution_hypotheses[0].confidence_numerator = 1_000_001;
    assert_ne!(over.episode_digest(), digest);
    Ok(())
}
