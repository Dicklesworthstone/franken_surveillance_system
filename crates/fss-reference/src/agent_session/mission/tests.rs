#![forbid(unsafe_code)]
//! Synthetic owner-boundary facts, never evidence of a real effect or physical event.

use super::*;
use fss_core::{AgentSession, AgentSessionParams, ContractBasisRegistryBytes};
use std::error::Error;

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

pub(crate) fn basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(ContractBasisRegistryBytes::new(
        b"schemas",
        b"operations",
        b"views",
        b"capabilities",
        b"errors",
        b"costs",
        "fss-reference:mission-test",
    ))
}

pub(crate) fn params() -> TestResult<AgentSessionParams> {
    Ok(AgentSessionParams {
        session_id: SessionId::parse("session:mission-owner-fixture")?,
        mission_id: MissionId::parse("mission:fixture")?,
        principal_id: PrincipalId::parse("principal:owner")?,
        capabilities: [
            "CAP-AGENT-SESSION-READ-001",
            "CAP-AGENT-SESSION-WRITE-001",
            "CAP-AGENT-SITUATION-READ-001",
            "CAP-AGENT-PLAN-PREPARE-001",
            "CAP-AGENT-INVESTIGATE-001",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        privacy_scope: BTreeSet::from(["private:property".to_owned()]),
        current_anchor: LedgerAnchor::genesis("site:mission-owner-fixture"),
        view_id: "AVIEW-002".to_owned(),
        token_budget: 4096,
        symbol_table_generation: 0,
        last_acknowledged_situation_fingerprint: None,
        created_at_ns: 0,
        expires_at_ns: 10_000,
    })
}

pub(crate) fn criterion(session: &AgentSession) -> TestResult<MissionPlanCriterion> {
    Ok(MissionPlanCriterion {
        session_id: session.session_id.clone(),
        mission_id: session.mission_id.clone(),
        principal: session.principal_id.clone(),
        mission_record_digest: ContentDigest::sha256(b"synthetic retained mission record"),
        plan_id: "plan:fixture".to_owned(),
        plan_record_digest: ContentDigest::sha256(b"synthetic canonical plan record"),
        plan_root: ContentDigest::sha256(b"synthetic plan publication"),
        control_plan_digest: ContentDigest::sha256(b"synthetic control plan rendering"),
        operation_id: OperationId::parse("operation:fixture")?,
        obligation_id: ObligationId::parse("obligation:fixture")?,
        event_id: EventId::parse("event:fixture")?,
        event_revision: ContentDigest::sha256(b"synthetic event revision"),
        contract_basis: basis(),
        baseline_anchor: session.current_anchor.clone(),
        decision_deadline: TimestampNs(100),
    })
}

pub(crate) fn facts(c: &MissionPlanCriterion) -> MissionAssessmentFacts {
    let proof = ContentDigest::sha256(b"synthetic exact terminal proof");
    MissionAssessmentFacts {
        anchor: c.baseline_anchor.clone(),
        evidence_time: TimestampNs(10),
        effect_journal_present: true,
        effect_journal_root: ContentDigest::sha256(b"synthetic effect prefix"),
        effect_record_count: 4,
        event_revision: Some(c.event_revision),
        operation: Some(MissionOperationFacts {
            operation_id: c.operation_id.clone(),
            state: MissionOperationState::Verified,
            dispatched: true,
            receipt_digest: ContentDigest::sha256(b"synthetic verified receipt"),
            result_digest: Some(proof),
        }),
        obligation: Some(MissionObligationFacts {
            obligation_id: c.obligation_id.clone(),
            operation_id: c.operation_id.clone(),
            state: MissionObligationState::Verified,
            proof_digest: Some(proof),
        }),
        episode: Some(MissionEpisodeFacts {
            episode_id: "episode:fixture".to_owned(),
            record_digest: ContentDigest::sha256(b"synthetic episode record"),
            publication_root: ContentDigest::sha256(b"synthetic episode publication"),
            plan_record_digest: c.plan_record_digest,
            control_plan_digest: c.control_plan_digest,
            operation_id: c.operation_id.clone(),
            outcome: MissionEpisodeOutcome::Verified,
        }),
        closure: MissionClosureFacts {
            witness_digest: ContentDigest::sha256(b"complete empty owned inventory"),
            unsettled_plans: 0,
            active_cases: 0,
            active_claims: 0,
            active_supervisions: 0,
        },
    }
}

fn opened() -> TestResult<(ReferenceSessionStore, AgentSession, MissionPlanCriterion)> {
    let mut sessions = ReferenceSessionStore::default();
    let session = sessions.open(params()?, basis(), TimestampNs(10))?;
    let criterion = criterion(&session)?;
    Ok((sessions, session, criterion))
}

#[test]
fn only_exact_proven_owner_outcomes_can_terminalize() -> TestResult {
    for (operation, obligation, episode, dispatched, expected) in [
        (
            MissionOperationState::Verified,
            MissionObligationState::Verified,
            MissionEpisodeOutcome::Verified,
            true,
            MissionLifecycleState::Resolved,
        ),
        (
            MissionOperationState::Failed,
            MissionObligationState::Failed,
            MissionEpisodeOutcome::Failed,
            true,
            MissionLifecycleState::Failed,
        ),
        (
            MissionOperationState::Cancelled,
            MissionObligationState::Cancelled,
            MissionEpisodeOutcome::Cancelled,
            false,
            MissionLifecycleState::Cancelled,
        ),
    ] {
        let (mut sessions, session, criterion) = opened()?;
        let mut store = ReferenceMissionStore::default();
        let initial = store.register(
            &mut sessions,
            &session.principal_id,
            criterion.clone(),
            TimestampNs(10),
        )?;
        assert_eq!(initial.state(), MissionLifecycleState::AwaitingEvidence);
        assert!(initial.assessment().is_none());
        let mut observed = facts(&criterion);
        let op = observed.operation.as_mut().ok_or("operation fixture")?;
        op.state = operation;
        op.dispatched = dispatched;
        observed
            .obligation
            .as_mut()
            .ok_or("obligation fixture")?
            .state = obligation;
        observed.episode.as_mut().ok_or("episode fixture")?.outcome = episode;
        let terminal = store.assess(
            &mut sessions,
            &session.principal_id,
            &session.session_id,
            criterion.mission_record_digest,
            initial.digest(),
            observed.clone(),
            TimestampNs(10),
        )?;
        assert_eq!(terminal.state(), expected);
        assert_eq!(terminal.parent_digest(), Some(initial.digest()));
        assert_eq!(
            terminal.digest(),
            ContentDigest::sha256(terminal.as_bytes())
        );
        assert_eq!(
            store.assess(
                &mut sessions,
                &session.principal_id,
                &session.session_id,
                criterion.mission_record_digest,
                initial.digest(),
                observed,
                TimestampNs(10)
            )?,
            terminal
        );
        assert_eq!(
            store
                .history(
                    &mut sessions,
                    &session.principal_id,
                    &session.session_id,
                    criterion.mission_record_digest,
                    TimestampNs(10)
                )?
                .len(),
            2
        );
        assert_eq!(
            store.register(
                &mut sessions,
                &session.principal_id,
                criterion,
                TimestampNs(10)
            )?,
            terminal
        );
    }
    Ok(())
}

#[test]
fn missing_stale_incomplete_or_other_owned_work_never_means_success() -> TestResult {
    let (_, _, c) = opened()?;
    let mut variants = Vec::new();
    let mut f = facts(&c);
    f.operation = None;
    variants.push(f);
    let mut f = facts(&c);
    f.obligation = None;
    variants.push(f);
    let mut f = facts(&c);
    f.episode = None;
    variants.push(f);
    let mut f = facts(&c);
    f.event_revision = None;
    variants.push(f);
    let mut f = facts(&c);
    f.event_revision = Some(ContentDigest::sha256(b"newer event"));
    variants.push(f);
    let mut f = facts(&c);
    f.anchor.privacy_epoch += 1;
    variants.push(f);
    let mut f = facts(&c);
    f.anchor.state_root = ContentDigest::sha256(b"foreign root at the same commit position");
    variants.push(f);
    let mut f = facts(&c);
    f.closure.unsettled_plans = 1;
    variants.push(f);
    let mut f = facts(&c);
    f.closure.active_cases = 1;
    variants.push(f);
    let mut f = facts(&c);
    f.closure.active_claims = 1;
    variants.push(f);
    let mut f = facts(&c);
    f.closure.active_supervisions = 1;
    variants.push(f);
    let mut f = facts(&c);
    f.obligation.as_mut().ok_or("obligation")?.proof_digest = None;
    variants.push(f);
    let mut f = facts(&c);
    f.operation.as_mut().ok_or("operation")?.result_digest =
        Some(ContentDigest::sha256(b"different proof"));
    variants.push(f);
    let mut f = facts(&c);
    f.episode.as_mut().ok_or("episode")?.outcome = MissionEpisodeOutcome::Withdrawn;
    variants.push(f);
    for f in variants {
        assert_eq!(evaluate(&c, &f)?, MissionLifecycleState::AwaitingEvidence);
    }
    let mut f = facts(&c);
    f.operation.as_mut().ok_or("operation")?.state = MissionOperationState::AdapterAccepted;
    assert_eq!(evaluate(&c, &f)?, MissionLifecycleState::Executing);
    f.operation.as_mut().ok_or("operation")?.state = MissionOperationState::Indeterminate;
    f.evidence_time = TimestampNs(900);
    assert_eq!(evaluate(&c, &f)?, MissionLifecycleState::Reconciling);
    let revision = MissionRevision::new(
        c,
        1,
        Some(ContentDigest::sha256(b"parent")),
        Some(f),
        TimestampNs(900),
    )?;
    assert!(revision.deadline_reached());
    assert!(!revision.state().is_terminal());
    Ok(())
}

#[test]
fn immutable_criteria_exact_cas_and_old_retries_never_rewind_history() -> TestResult {
    let (mut sessions, session, c) = opened()?;
    let mut store = ReferenceMissionStore::default();
    let first = store.register(
        &mut sessions,
        &session.principal_id,
        c.clone(),
        TimestampNs(10),
    )?;
    let mut waiting = facts(&c);
    waiting.episode = None;
    let second = store.assess(
        &mut sessions,
        &session.principal_id,
        &session.session_id,
        c.mission_record_digest,
        first.digest(),
        waiting.clone(),
        TimestampNs(10),
    )?;
    assert!(matches!(
        store.assess(
            &mut sessions,
            &session.principal_id,
            &session.session_id,
            c.mission_record_digest,
            first.digest(),
            facts(&c),
            TimestampNs(10)
        ),
        Err(MissionError::Conflict)
    ));
    let third = store.assess(
        &mut sessions,
        &session.principal_id,
        &session.session_id,
        c.mission_record_digest,
        second.digest(),
        facts(&c),
        TimestampNs(10),
    )?;
    assert_eq!(
        store.assess(
            &mut sessions,
            &session.principal_id,
            &session.session_id,
            c.mission_record_digest,
            first.digest(),
            waiting.clone(),
            TimestampNs(10)
        )?,
        second
    );
    assert_eq!(
        store.head(
            &mut sessions,
            &session.principal_id,
            &session.session_id,
            c.mission_record_digest,
            TimestampNs(10)
        )?,
        Some(third.clone())
    );
    assert!(matches!(
        store.assess(
            &mut sessions,
            &session.principal_id,
            &session.session_id,
            c.mission_record_digest,
            third.digest(),
            waiting,
            TimestampNs(10)
        ),
        Err(MissionError::Terminal)
    ));
    let mut changed = c.clone();
    changed.decision_deadline = TimestampNs(200);
    assert!(matches!(
        store.register(
            &mut sessions,
            &session.principal_id,
            changed,
            TimestampNs(10)
        ),
        Err(MissionError::Conflict)
    ));
    assert_eq!(
        store.head(
            &mut sessions,
            &session.principal_id,
            &session.session_id,
            c.mission_record_digest,
            TimestampNs(10)
        )?,
        Some(third)
    );
    Ok(())
}

#[test]
fn authorization_precedes_private_scope_and_expiry_is_not_refilled() -> TestResult {
    let (mut sessions, session, c) = opened()?;
    let mut store = ReferenceMissionStore::default();
    store.register(
        &mut sessions,
        &session.principal_id,
        c.clone(),
        TimestampNs(10),
    )?;
    let outsider = PrincipalId::parse("principal:outsider")?;
    assert!(matches!(
        store.head(
            &mut sessions,
            &outsider,
            &session.session_id,
            c.mission_record_digest,
            TimestampNs(10)
        ),
        Err(MissionError::Session(ReferenceSessionError::Unavailable))
    ));
    sessions
        .sessions
        .get_mut(&session.session_id)
        .ok_or("session")?
        .spent_tokens = 123;
    store.register(
        &mut sessions,
        &session.principal_id,
        c.clone(),
        TimestampNs(20),
    )?;
    assert_eq!(
        sessions
            .sessions
            .get(&session.session_id)
            .ok_or("session")?
            .spent_tokens,
        123
    );
    sessions
        .sessions
        .get_mut(&session.session_id)
        .ok_or("session")?
        .session
        .privacy_scope
        .clear();
    assert!(matches!(
        store.head(
            &mut sessions,
            &session.principal_id,
            &session.session_id,
            c.mission_record_digest,
            TimestampNs(30)
        ),
        Err(MissionError::Unauthorized)
    ));
    assert!(matches!(
        store.head(
            &mut sessions,
            &session.principal_id,
            &session.session_id,
            c.mission_record_digest,
            TimestampNs(10_000)
        ),
        Err(MissionError::Session(ReferenceSessionError::Unavailable))
    ));
    assert!(
        sessions
            .sessions
            .get(&session.session_id)
            .ok_or("session")?
            .closed
    );
    assert_eq!(store.retained().len(), 1);
    Ok(())
}

#[test]
fn complete_encoding_preserves_presence_proofs_and_bounds() -> TestResult {
    let (_, _, c) = opened()?;
    let mut e = CanonicalEncoder::new();
    c.encode(&mut e);
    let bytes = e.finish();
    let mut d = CanonicalDecoder::new(&bytes);
    assert_eq!(MissionPlanCriterion::decode(&mut d)?, c);
    d.ensure_finished()?;
    let f = facts(&c);
    let mut e = CanonicalEncoder::new();
    f.encode(&mut e);
    let bytes = e.finish();
    let mut d = CanonicalDecoder::new(&bytes);
    assert_eq!(MissionAssessmentFacts::decode(&mut d)?, f);
    d.ensure_finished()?;
    let mut absent = f.clone();
    absent.operation = None;
    absent.obligation = None;
    absent.episode = None;
    absent.effect_record_count = 0;
    absent.effect_journal_root = ContentDigest::new(DigestAlgorithm::Sha256, [0; 32]);
    absent.effect_journal_present = false;
    let first = MissionRevision::new(c.clone(), 1, None, Some(absent.clone()), TimestampNs(10))?;
    absent.effect_journal_present = true;
    let second = MissionRevision::new(c.clone(), 1, None, Some(absent), TimestampNs(10))?;
    assert_ne!(first.digest(), second.digest());
    let mut oversized = c.clone();
    oversized.plan_id = "p".repeat(MAX_ID_BYTES + 1);
    assert!(matches!(
        oversized.validate(),
        Err(MissionError::InvalidRequest)
    ));
    let mut wrong = f.clone();
    wrong.obligation.as_mut().ok_or("obligation")?.operation_id =
        OperationId::parse("operation:foreign")?;
    assert!(matches!(
        wrong.validate(&c),
        Err(MissionError::ScopeMismatch)
    ));
    let mut wrong = f;
    wrong.closure.active_cases = MAX_CLOSURE_ITEMS + 1;
    assert!(matches!(
        wrong.validate(&c),
        Err(MissionError::InvalidRequest)
    ));
    Ok(())
}

#[test]
fn finite_history_refuses_without_dropping_prior_revisions() -> TestResult {
    let (mut sessions, session, c) = opened()?;
    let mut store = ReferenceMissionStore::default();
    let mut head = store.register(
        &mut sessions,
        &session.principal_id,
        c.clone(),
        TimestampNs(10),
    )?;
    for ordinal in 1..MAX_MISSION_REVISIONS {
        let mut f = facts(&c);
        f.episode = None;
        f.closure.witness_digest = ContentDigest::sha256(&ordinal.to_le_bytes());
        head = store.assess(
            &mut sessions,
            &session.principal_id,
            &session.session_id,
            c.mission_record_digest,
            head.digest(),
            f,
            TimestampNs(10),
        )?;
    }
    let before = store.digest();
    assert!(matches!(
        store.assess(
            &mut sessions,
            &session.principal_id,
            &session.session_id,
            c.mission_record_digest,
            head.digest(),
            facts(&c),
            TimestampNs(10)
        ),
        Err(MissionError::CapacityExceeded)
    ));
    assert_eq!(store.digest(), before);
    assert_eq!(store.retained().len(), MAX_MISSION_REVISIONS);
    Ok(())
}

#[test]
fn recorded_evidence_and_effect_prefixes_cannot_roll_back_or_be_replaced() -> TestResult {
    let (mut sessions, session, c) = opened()?;
    let mut store = ReferenceMissionStore::default();
    let initial = store.register(
        &mut sessions,
        &session.principal_id,
        c.clone(),
        TimestampNs(10),
    )?;
    let mut observed = facts(&c);
    observed.episode = None;
    observed.anchor.commit_sequence = 2;
    observed.anchor.state_root = ContentDigest::sha256(b"observed evidence prefix two");
    let current = store.assess(
        &mut sessions,
        &session.principal_id,
        &session.session_id,
        c.mission_record_digest,
        initial.digest(),
        observed.clone(),
        TimestampNs(10),
    )?;
    let mut variants = Vec::new();
    let mut f = observed.clone();
    f.effect_record_count -= 1;
    variants.push(f);
    let mut f = observed.clone();
    f.effect_journal_root = ContentDigest::sha256(b"replaced same-length effect prefix");
    variants.push(f);
    let mut f = observed.clone();
    f.effect_journal_present = false;
    f.effect_record_count = 0;
    f.effect_journal_root = ContentDigest::new(DigestAlgorithm::Sha256, [0; 32]);
    f.operation = None;
    f.obligation = None;
    variants.push(f);
    let mut f = observed.clone();
    f.anchor.commit_sequence = 1;
    f.anchor.state_root = ContentDigest::sha256(b"rolled-back evidence prefix one");
    variants.push(f);
    let mut f = observed.clone();
    f.anchor.state_root = ContentDigest::sha256(b"replaced evidence prefix two");
    variants.push(f);
    let before = store.digest();
    for f in variants {
        assert!(matches!(
            store.assess(
                &mut sessions,
                &session.principal_id,
                &session.session_id,
                c.mission_record_digest,
                current.digest(),
                f,
                TimestampNs(10)
            ),
            Err(MissionError::ScopeMismatch)
        ));
        assert_eq!(store.digest(), before);
    }
    let mut successor = observed.clone();
    successor.anchor.commit_sequence = 3;
    successor.anchor.state_root = ContentDigest::sha256(b"observed evidence prefix three");
    successor.effect_record_count += 1;
    successor.effect_journal_root = ContentDigest::sha256(b"observed effect prefix five");
    let head = store.assess(
        &mut sessions,
        &session.principal_id,
        &session.session_id,
        c.mission_record_digest,
        current.digest(),
        successor,
        TimestampNs(10),
    )?;
    // The historical retry remains valid and never replaces the newer head.
    assert_eq!(
        store.assess(
            &mut sessions,
            &session.principal_id,
            &session.session_id,
            c.mission_record_digest,
            initial.digest(),
            observed,
            TimestampNs(10)
        )?,
        current
    );
    assert_eq!(
        store.head(
            &mut sessions,
            &session.principal_id,
            &session.session_id,
            c.mission_record_digest,
            TimestampNs(10)
        )?,
        Some(head)
    );
    Ok(())
}
