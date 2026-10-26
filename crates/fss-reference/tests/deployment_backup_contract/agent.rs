#![forbid(unsafe_code)]
//! Native populated-agent recovery, including historical leases and uncertainty.

use std::collections::BTreeSet;

use fss_core::{
    AgentView, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaseDiscriminator,
    CaseHypothesis, FeedbackProposalKind, KnowledgeState, KnownStatement, PrincipalId,
    PromotionState, RequestedDisposition,
};
use fss_object::ObjectManifest;
use fss_publication::{LocalRootPublisher, SlotName};
use fss_reference::agent_session::checkpoint::journal::coordination::investigations::InvestigationChange;
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, DurableSessionStore,
};
use fss_reference::agent_session::work_claims::WorkClaimLimits;
use fss_reference::agent_session::workspace::{
    WorkspaceRevision, WorkspaceWrite, WorkspaceWriteMode,
};
use fss_reference::deployment_session::claims::{
    ClaimAction, ClaimChange, ClaimRequest, ClaimWork, work_claim,
};
use fss_reference::deployment_session::episode::{CloseRequest, TerminalOutcome, close_plan};
use fss_reference::deployment_session::feedback::{
    FeedbackRequest, FeedbackTarget, publish_feedback,
};
use fss_reference::deployment_session::investigation::{
    CaseAction, CaseDeadline, CaseDraft, InvestigateRequest, investigate,
};
use fss_reference::deployment_session::learning::PublishedLearning;
use fss_reference::deployment_session::plan::{PlanRecord, publish_plan, read_control_plan};
use fss_reference::deployment_session::{
    AgentRecoveryRecord, DeploymentSessionError, HandoffRequest, OpenSessionRequest, OpenedSession,
    ResumeRequest, open_session, prepare_handoff, publication_limits, resume_session,
};

use super::*;

fn request() -> Test<OpenSessionRequest> {
    Ok(OpenSessionRequest {
        mission: "Retain the unresolved north gate investigation".into(),
        objective: "Preserve uncertainty and hand over exact evidence".into(),
        principal: PrincipalId::parse(PRINCIPAL)?,
        view: AgentView::Brief,
        token_budget: 100_000,
    })
}

fn case_draft() -> CaseDraft {
    CaseDraft {
        case_id: "case:backup-north-gate".into(),
        question: "Was the gate movement caused by a person or by wind?".into(),
        decision_informed: "Whether more observations are needed".into(),
        hypotheses: ["person", "wind"]
            .into_iter()
            .map(|id| CaseHypothesis {
                hypothesis_id: format!("hypothesis:{id}"),
                description: format!("The movement was caused by {id}"),
                epistemic_state: KnowledgeState::Unknown,
                predictions: vec![format!("An additional view would distinguish {id}")],
                evidence: Vec::new(),
                contradictions: Vec::new(),
            })
            .collect(),
        knowns: Vec::new(),
        unknowns: vec![KnownStatement {
            statement_id: "unknown:cause".into(),
            text: "The cause is not established".into(),
            epistemic_state: KnowledgeState::Unknown,
            basis: Vec::new(),
        }],
        discriminators: vec![CaseDiscriminator {
            discriminator_id: "discriminator:second-view".into(),
            description: "Read an independently retained second view".into(),
            separates: vec!["hypothesis:person".into(), "hypothesis:wind".into()],
            expected_outcomes: vec!["person visible".into(), "no person visible".into()],
        }],
        probes: vec!["probe:review-second-view".into()],
        stop_rules: vec!["Preserve unknown if neither alternative is established".into()],
        deadline: CaseDeadline::After(3_600_000_000_000),
    }
}

fn retained_plan(opened: &OpenedSession) -> PlanRecord {
    let approval = ContentDigest::sha256(b"historical-plan-approval");
    PlanRecord {
        plan_id: PlanRecord::identity(
            &opened.session.session_id,
            &opened.orientation.anchor_token,
            approval,
        ),
        session_id: opened.session.session_id.clone(),
        mission_id: opened.session.mission_id.clone(),
        principal: opened.session.principal_id.clone(),
        anchor_token: opened.orientation.anchor_token.clone(),
        intent: "alert".into(),
        event_id: "event:retained-plan-fixture".into(),
        event_revision: ContentDigest::sha256(b"retained-event-revision"),
        route: fss_reference::deployment_session::plan::AlertRoute {
            relay: "127.0.0.1:9".into(),
            path: "/fss/alert".into(),
            plaintext_approval: ContentDigest::sha256(b"historical-route-approval"),
            deadline_ms: 5_000,
        },
        operation_id: "operation:retained-plan-fixture".into(),
        obligation_id: "obligation:retained-plan-fixture".into(),
        plan_approval: approval,
        control_plan_digest: ContentDigest::sha256(b"exact-native-plan-child"),
        case: None,
        created_at: TimestampNs(0),
    }
}

fn advance_fixture_workspace(fixture: &Fixture, opened: &OpenedSession) -> Test<WorkspaceRevision> {
    let journal = fixture.source.join("agent/sessions/journal.fssj");
    let mut store = DurableSessionStore::open_existing_with_coordination(
        &journal,
        opened.journal_root,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    let mut capsule = opened.revision.capsule().clone();
    capsule.revision += 1;
    capsule
        .unknowns
        .push("The gate movement's cause remains unresolved".into());
    let revision = store
        .publish_workspace(
            &opened.session.principal_id,
            WorkspaceWrite {
                expected_head: Some(opened.revision.digest()),
                capsule,
                mode: WorkspaceWriteMode::Advance,
            },
            TimestampNs(0),
        )?
        .result;
    fs::write(
        fixture.source.join("agent/sessions/ROOT"),
        format!("{}\n", store.committed_root().to_text()),
    )?;
    Ok(revision)
}

#[test]
fn populated_agent_roundtrip_keeps_native_history_and_fences_all_deployment_writers() -> Test {
    let f = Fixture::new("agent-roundtrip")?;
    let opened = open_session(&f.source, &request()?)?;
    let advanced_workspace = advance_fixture_workspace(&f, &opened)?;
    let case_request = InvestigateRequest {
        session_id: opened.session.session_id.clone(),
        principal: opened.session.principal_id.clone(),
        action: CaseAction::Open(Box::new(case_draft())),
    };
    let case = investigate(&f.source, &case_request)?
        .revision
        .ok_or("missing case")?;
    let active = investigate(
        &f.source,
        &InvestigateRequest {
            action: CaseAction::Change {
                case_id: case.record().investigation_id.clone(),
                expected: case.digest(),
                change: InvestigationChange::Activate,
            },
            ..case_request.clone()
        },
    )?
    .revision
    .ok_or("missing active case")?;
    let claim_request = ClaimRequest {
        session_id: opened.session.session_id.clone(),
        principal: opened.session.principal_id.clone(),
        action: ClaimAction::Acquire {
            case_id: active.record().investigation_id.clone(),
            work: ClaimWork::Case,
            lease_ms: 60_000,
            dependencies: BTreeSet::new(),
        },
    };
    let claim = work_claim(&f.source, &claim_request)?
        .claim
        .ok_or("missing claim")?;
    let handoff = prepare_handoff(
        &f.source,
        &HandoffRequest {
            session_id: opened.session.session_id.clone(),
            principal: opened.session.principal_id.clone(),
            note: Some("Cause remains unknown; do not renew the copied lease".into()),
        },
    )?
    .publish(&[b"retained-handoff-rendering".to_vec()])?;
    let plan = retained_plan(&opened);
    let plan_root = publish_plan(&f.source, &plan, b"exact-native-plan-child")?;
    let before = bytes_under(&f.source)?;
    let state = inspect_agent_state(
        &f.source,
        f.limits,
        BackupLimits::default(),
        &Grant,
        &f.cx()?,
    )?;
    assert!(!state.restored);
    assert_eq!(state.summary.session_count, 1);
    assert_eq!(state.summary.claim_count, 1);
    assert_eq!(state.summary.case_count, 1);
    assert_eq!(state.summary.publication_count, 3);
    assert!(state.summary.workspace_revision_count > 1);
    assert!(
        state
            .sessions
            .workspace_revisions
            .contains(&opened.revision)
    );
    assert!(
        state
            .sessions
            .workspace_revisions
            .contains(&advanced_workspace)
    );
    assert_eq!(
        advanced_workspace.parent_digest(),
        Some(opened.revision.digest())
    );
    assert_eq!(state.sessions.claims, vec![claim.clone()]);
    assert_eq!(state.sessions.cases, vec![active]);
    assert_eq!(
        state.sessions.cases[0].record().unknowns[0].epistemic_state,
        KnowledgeState::Unknown
    );
    assert!(state.publications.iter().any(|item| matches!(
        &item.record,
        AgentRecoveryRecord::Handoff(record) if **record == handoff.record
    )));
    let manifest = f.plan()?;
    assert_eq!(manifest.profile(), AGENT_BACKUP_PROFILE);
    assert_eq!(manifest.agent_state(), Some(&state.summary));
    let bundle = f.directory.0.join("agent-bundle");
    create_backup(
        &f.source,
        &bundle,
        manifest.digest(),
        f.limits,
        BackupLimits::default(),
        &Grant,
        &f.cx()?,
    )?;
    assert_eq!(
        inspect_backup(
            &bundle,
            manifest.digest(),
            BackupLimits::default(),
            &Grant,
            &f.cx()?
        )?,
        manifest,
    );
    assert_eq!(
        bytes_under(&f.source)?,
        before,
        "inspection and backup changed source state"
    );
    // A cold restore has no source deployment available at its former path.
    fs::rename(&f.source, f.directory.0.join("source-offline"))?;
    let restored = f.directory.0.join("agent-restored");
    let receipt = restore_backup(
        &bundle,
        &restored,
        manifest.digest(),
        BackupLimits::default(),
        &Grant,
        &f.cx()?,
    )?;
    assert_ne!(receipt.destination_anchor(), manifest.source_anchor());
    let fence_bytes =
        fss_publication::read_verified(restored.join("objects"), receipt.fence_digest(), 4096)?;
    let fence = RestoreFence::from_bytes(&fence_bytes, receipt.fence_digest())?;
    assert!(fence.agent_state_read_only());
    assert_eq!(fence.source_manifest(), manifest.digest());
    assert_eq!(fence.to_bytes(), fence_bytes);
    let recovered = inspect_agent_state(
        &restored,
        f.limits,
        BackupLimits::default(),
        &Grant,
        &f.cx()?,
    )?;
    assert!(recovered.restored);
    assert_eq!(recovered.summary, state.summary);
    assert_eq!(recovered.sessions, state.sessions);
    assert_eq!(recovered.publications, state.publications);
    for (path, bytes) in before.iter().filter(|(path, _)| path.starts_with("agent")) {
        assert_eq!(
            &fs::read(restored.join(path))?,
            bytes,
            "agent bytes changed: {path:?}"
        );
    }
    let inspected_before = bytes_under(&restored)?;
    let (read_plan, read_root, child) = read_control_plan(&restored, &plan.plan_id)?;
    assert_eq!(read_plan, plan);
    assert_eq!(read_root, plan_root);
    assert_eq!(child, b"exact-native-plan-child");
    assert!(matches!(
        open_session(&restored, &request()?),
        Err(DeploymentSessionError::StoreInvalid(_))
    ));
    assert!(matches!(
        resume_session(
            &restored,
            &ResumeRequest {
                handoff_id: handoff.record.capsule.handoff_id,
                principal: opened.session.principal_id.clone(),
            }
        ),
        Err(DeploymentSessionError::StoreInvalid(_))
    ));
    assert!(matches!(
        investigate(
            &restored,
            &InvestigateRequest {
                action: CaseAction::Inspect {
                    case_id: case.record().investigation_id.clone(),
                    revision: None
                },
                ..case_request
            }
        ),
        Err(DeploymentSessionError::StoreInvalid(_))
    ));
    assert!(matches!(
        work_claim(
            &restored,
            &ClaimRequest {
                action: ClaimAction::Change {
                    claim_id: claim.claim().claim_id.clone(),
                    expected: claim.digest(),
                    change: ClaimChange::Renew { lease_ms: 120_000 },
                },
                ..claim_request
            }
        ),
        Err(DeploymentSessionError::StoreInvalid(_))
    ));
    let mut new_plan = plan.clone();
    new_plan.plan_id = "plan:copied-authority-must-not-publish".into();
    assert!(matches!(
        publish_plan(&restored, &new_plan, b"exact-native-plan-child"),
        Err(DeploymentSessionError::StoreInvalid(_))
    ));
    assert_eq!(
        bytes_under(&restored)?,
        inspected_before,
        "restored reads or refusals mutated history"
    );
    Ok(())
}

#[test]
fn populated_agent_backup_preserves_closed_session_checkpoint_without_reopening_identity() -> Test {
    let f = Fixture::new("agent-closed")?;
    let opened = open_session(&f.source, &request()?)?;
    let journal = f.source.join("agent/sessions/journal.fssj");
    let mut store = DurableSessionStore::open_existing_with_coordination(
        &journal,
        opened.journal_root,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    store.close(
        &opened.session.principal_id,
        &opened.session.session_id,
        TimestampNs(0),
    )?;
    fs::write(
        f.source.join("agent/sessions/ROOT"),
        format!("{}\n", store.committed_root().to_text()),
    )?;
    drop(store);
    let before = inspect_agent_state(
        &f.source,
        f.limits,
        BackupLimits::default(),
        &Grant,
        &f.cx()?,
    )?;
    assert_eq!(before.summary.closed_session_count, 1);
    assert!(before.sessions.sessions[0].closed);
    let manifest = f.plan()?;
    let bundle = f.directory.0.join("bundle");
    create_backup(
        &f.source,
        &bundle,
        manifest.digest(),
        f.limits,
        BackupLimits::default(),
        &Grant,
        &f.cx()?,
    )?;
    let destination = f.directory.0.join("restored");
    restore_backup(
        &bundle,
        &destination,
        manifest.digest(),
        BackupLimits::default(),
        &Grant,
        &f.cx()?,
    )?;
    let after = inspect_agent_state(
        &destination,
        f.limits,
        BackupLimits::default(),
        &Grant,
        &f.cx()?,
    )?;
    assert_eq!(after.sessions, before.sessions);
    assert!(after.restored);
    assert!(open_session(&destination, &request()?).is_err());
    Ok(())
}

#[test]
fn populated_agent_backup_refuses_stale_pins_tails_and_rehashed_invalid_history_without_repair()
-> Test {
    for corruption in [
        "pin",
        "tail",
        "foreign-record",
        "staging",
        "unknown-subtree",
    ] {
        let f = Fixture::new(&format!("agent-{corruption}"))?;
        open_session(&f.source, &request()?)?;
        let approved = f.plan()?.digest();
        match corruption {
            "pin" => fs::write(
                f.source.join("agent/sessions/ROOT"),
                format!(
                    "{}\n",
                    ContentDigest::sha256(b"stale-independent-pin").to_text()
                ),
            )?,
            "tail" => fs::OpenOptions::new()
                .append(true)
                .open(f.source.join("agent/sessions/journal.fssj"))?
                .write_all(b"not a committed agent record")?,
            "foreign-record" => {
                let mut journal = fss_ledger::Journal::open(
                    f.source.join("agent/sessions/journal.fssj"),
                    fss_ledger::IncompleteTailPolicy::Reject,
                )?;
                journal.append(0x7777, b"cryptographically valid but semantically foreign")?;
                fs::write(
                    f.source.join("agent/sessions/ROOT"),
                    format!("{}\n", journal.last_root().to_text()),
                )?;
            }
            "staging" => fs::write(
                f.source
                    .join("agent/publications/spool/staging/uncommitted"),
                b"uncommitted",
            )?,
            _ => fs::create_dir(f.source.join("agent/unowned-archive"))?,
        }
        let before = bytes_under(&f.source)?;
        assert!(
            f.plan().is_err(),
            "plan admitted corrupt native state: {corruption}"
        );
        assert!(
            inspect_agent_state(
                &f.source,
                f.limits,
                BackupLimits::default(),
                &Grant,
                &f.cx()?,
            )
            .is_err(),
            "inspector admitted corrupt native state: {corruption}"
        );
        let bundle = f.directory.0.join("must-not-exist");
        assert!(
            create_backup(
                &f.source,
                &bundle,
                approved,
                f.limits,
                BackupLimits::default(),
                &Grant,
                &f.cx()?,
            )
            .is_err()
        );
        assert!(!bundle.exists());
        assert_eq!(bytes_under(&f.source)?, before);
    }
    Ok(())
}

#[test]
fn populated_agent_backup_holds_every_independent_writer_and_rejects_payload_tampering() -> Test {
    let f = Fixture::new("agent-locks")?;
    open_session(&f.source, &request()?)?;
    for relative in [
        "agent/sessions/LOCK",
        "agent/sessions/journal.fssj",
        "agent/publications/LOCK",
        "agent/publications/spool/LOCK",
    ] {
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(f.source.join(relative))?;
        lock.try_lock()?;
        assert_eq!(
            f.plan().unwrap_err().to_string(),
            BackupError::Locked.to_string()
        );
    }
    let manifest = f.plan()?;
    let bundle = f.directory.0.join("bundle");
    create_backup(
        &f.source,
        &bundle,
        manifest.digest(),
        f.limits,
        BackupLimits::default(),
        &Grant,
        &f.cx()?,
    )?;
    let pin = bundle.join("payload/agent/sessions/ROOT");
    fs::write(pin, b"changed after independent manifest approval")?;
    let destination = f.directory.0.join("must-not-exist");
    assert!(
        restore_backup(
            &bundle,
            &destination,
            manifest.digest(),
            BackupLimits::default(),
            &Grant,
            &f.cx()?,
        )
        .is_err()
    );
    assert!(!destination.exists());
    Ok(())
}

#[test]
fn populated_agent_core_v1_restore_allows_fresh_sessions_without_copied_leases() -> Test {
    let f = Fixture::new("agent-core-compatibility")?;
    let manifest = f.plan()?;
    assert_eq!(manifest.profile(), BACKUP_PROFILE);
    assert!(manifest.agent_state().is_none());
    let bundle = f.directory.0.join("bundle");
    create_backup(
        &f.source,
        &bundle,
        manifest.digest(),
        f.limits,
        BackupLimits::default(),
        &Grant,
        &f.cx()?,
    )?;
    let restored = f.directory.0.join("restored");
    let receipt = restore_backup(
        &bundle,
        &restored,
        manifest.digest(),
        BackupLimits::default(),
        &Grant,
        &f.cx()?,
    )?;
    let fence_bytes =
        fss_publication::read_verified(restored.join("objects"), receipt.fence_digest(), 4096)?;
    let fence = RestoreFence::from_bytes(&fence_bytes, receipt.fence_digest())?;
    assert!(!fence.agent_state_read_only());
    assert_eq!(fence.source_manifest(), manifest.digest());
    assert_eq!(fence.to_bytes(), fence_bytes);
    assert!(!restored.join("agent/sessions/journal.fssj").exists());
    let opened = open_session(&restored, &request()?)?;
    let state = inspect_agent_state(
        &restored,
        f.limits,
        BackupLimits::default(),
        &Grant,
        &f.cx()?,
    )?;
    assert!(state.restored, "the permanent alert fence remains present");
    assert_eq!(state.summary.session_count, 1);
    assert_eq!(state.summary.claim_count, 0);
    assert_eq!(state.summary.case_count, 0);
    assert_eq!(state.sessions.sessions[0].session, opened.session);
    assert!(!f.source.join("agent/sessions/journal.fssj").exists());
    Ok(())
}

#[test]
fn populated_agent_writers_refuse_linked_ancestors_and_hardlinked_history_aliases() -> Test {
    use std::os::unix::fs::symlink;

    for alias in [
        "agent",
        "agent/sessions",
        "agent/publications",
        "agent/publications/roots",
        "agent/publications/spool",
        "agent/sessions/journal.fssj",
    ] {
        let f = Fixture::new("agent-writer-alias")?;
        let opened = open_session(&f.source, &request()?)?;
        let plan = retained_plan(&opened);
        let manifest = f.plan()?;
        let bundle = f.directory.0.join("bundle");
        create_backup(
            &f.source,
            &bundle,
            manifest.digest(),
            f.limits,
            BackupLimits::default(),
            &Grant,
            &f.cx()?,
        )?;
        let restored = f.directory.0.join("restored");
        restore_backup(
            &bundle,
            &restored,
            manifest.digest(),
            BackupLimits::default(),
            &Grant,
            &f.cx()?,
        )?;
        let before = bytes_under(&restored)?;
        let live_path = f.source.join(alias);
        fs::rename(&live_path, f.directory.0.join("original-agent-path"))?;
        if alias.ends_with("journal.fssj") {
            fs::hard_link(restored.join(alias), &live_path)?;
        } else {
            symlink(restored.join(alias), &live_path)?;
        }
        assert!(
            matches!(
                open_session(&f.source, &request()?),
                Err(DeploymentSessionError::StoreInvalid(_))
            ),
            "session writer admitted restored-state alias: {alias}"
        );
        assert!(
            matches!(
                publish_plan(&f.source, &plan, b"exact-native-plan-child"),
                Err(DeploymentSessionError::StoreInvalid(_))
            ),
            "publication writer admitted restored-state alias: {alias}"
        );
        assert_eq!(
            bytes_under(&restored)?,
            before,
            "aliased writer changed restored history: {alias}"
        );
    }
    Ok(())
}

struct CapturedLearningFixture {
    opened: OpenedSession,
    request: FeedbackRequest,
    learning: PublishedLearning,
}

fn capture_learning(f: &Fixture) -> Test<CapturedLearningFixture> {
    let mut opening = request()?;
    opening.view = AgentView::EpistemicMap;
    let opened = open_session(&f.source, &opening)?;
    let plan = retained_plan(&opened);
    publish_plan(&f.source, &plan, b"exact-native-plan-child")?;
    // Exercise the ordinary native terminal close and feedback owners. A withdrawn plan
    // needs no network peer and must preserve the uncertainty of the physical event.
    let owner = f.open()?;
    let closed = close_plan(
        &f.source,
        &CloseRequest {
            session_id: opened.session.session_id.clone(),
            principal: opened.session.principal_id.clone(),
            plan_id: plan.plan_id.clone(),
        },
        &|episode| {
            format!(
                "synthetic episode custody rendering: {}",
                episode.episode_id
            )
        },
    )?;
    drop(owner);
    assert_eq!(
        closed.episode.record.terminal_state,
        TerminalOutcome::Withdrawn
    );
    let request = FeedbackRequest {
        session_id: opened.session.session_id.clone(),
        principal: opened.session.principal_id.clone(),
        target: FeedbackTarget::Plan(plan.plan_id),
        kind: FeedbackProposalKind::RunbookCandidate,
        statement: "Review the withdrawn alert procedure without inferring effectiveness.".into(),
        supporting: vec![closed.episode.root],
        contradicting: Vec::new(),
        disposition: RequestedDisposition::CreateLearningProposal,
    };
    let published = publish_feedback(&f.source, &request)?;
    assert!(
        published.learning_refusal.is_none(),
        "{:?}",
        published.learning_refusal
    );
    let learning = published.learning.ok_or("learning capture missing")?;
    assert!(learning.committed);
    assert_eq!(learning.proposal.promotion_state, PromotionState::Captured);
    assert_eq!(learning.proposal.confidence_numerator, 0);
    assert_eq!(learning.proposal.helpful_outcomes, 0);
    assert_eq!(learning.proposal.harmful_outcomes, 0);
    Ok(CapturedLearningFixture {
        opened,
        request,
        learning,
    })
}

fn learning_slot(learning: &PublishedLearning) -> Test<SlotName> {
    let digest = ContentDigest::sha256(learning.experience.experience_id.as_bytes()).to_text();
    Ok(SlotName::parse(&format!(
        "learning-{}",
        digest
            .strip_prefix("sha256:")
            .ok_or("learning slot digest")?,
    ))?)
}

fn publication_object(directory: &Path, digest: ContentDigest) -> Test<PathBuf> {
    let text = digest.to_text();
    Ok(directory.join("spool/objects").join(
        text.strip_prefix("sha256:")
            .ok_or("publication object digest")?,
    ))
}

fn learning_binding(
    directory: &Path,
    learning: &PublishedLearning,
) -> Test<(ObjectManifest, ContentDigest, Vec<u8>)> {
    let manifest = ObjectManifest::from_canonical_bytes(&fss_publication::read_verified(
        directory,
        learning.root,
        1024 * 1024,
    )?)?;
    let mut found = None;
    for digest in manifest.children() {
        let bytes = fss_publication::read_verified(directory, *digest, 1024 * 1024)?;
        if CanonicalDecoder::new(&bytes)
            .text()
            .is_ok_and(|domain| domain == "fss.reference_agent_learning_capture.v1")
        {
            assert!(
                found.is_none(),
                "a capture has exactly one canonical source binding"
            );
            found = Some((*digest, bytes));
        }
    }
    let (digest, bytes) = found.ok_or("learning source binding missing")?;
    Ok((manifest, digest, bytes))
}

#[test]
fn captured_learning_backup_roundtrip_keeps_original_binding_and_exact_retry() -> Test {
    let f = Fixture::new("learning-roundtrip")?;
    let captured = capture_learning(&f)?;
    // Later workspace cognition must not replace the originally captured workspace binding.
    let mut current = captured.opened.clone();
    current.journal_root =
        ContentDigest::parse(fs::read_to_string(f.source.join("agent/sessions/ROOT"))?.trim_end())?;
    let advanced = advance_fixture_workspace(&f, &current)?;
    let state = inspect_agent_state(
        &f.source,
        f.limits,
        BackupLimits::default(),
        &Grant,
        &f.cx()?,
    )?;
    assert!(
        state
            .sessions
            .workspace_revisions
            .contains(&captured.opened.revision)
    );
    assert!(state.sessions.workspace_revisions.contains(&advanced));
    let publication = state
        .publications
        .iter()
        .find(|item| item.root == captured.learning.root)
        .ok_or("captured learning absent from native recovery report")?;
    assert!(matches!(
        &publication.record,
        AgentRecoveryRecord::Learning(experience) if **experience == captured.learning.experience
    ));
    for digest in [
        captured.learning.experience_digest,
        captured.learning.proposal_digest,
        captured.learning.feedback_root,
        captured.learning.plan_root,
        captured.learning.episode_root,
    ] {
        assert!(
            publication.children.contains(&digest),
            "missing copied source {digest}"
        );
    }
    let directory = f.source.join("agent/publications");
    let (_, binding_digest, binding_bytes) = learning_binding(&directory, &captured.learning)?;
    assert!(publication.children.contains(&binding_digest));
    assert_eq!(
        fss_publication::read_verified(&directory, captured.learning.proposal_digest, 1024 * 1024)?,
        captured.learning.proposal.try_canonical_bytes()?,
    );
    let source_before = bytes_under(&f.source)?;
    let manifest = f.plan()?;
    let bundle = f.bundle("learning-bundle", &manifest)?;
    assert_eq!(manifest.profile(), AGENT_BACKUP_PROFILE);
    assert_eq!(manifest.agent_state(), Some(&state.summary));
    assert_eq!(bytes_under(&f.source)?, source_before);

    let offline = f.directory.0.join("learning-source-offline");
    fs::rename(&f.source, &offline)?;
    let restored = f.directory.0.join("learning-restored");
    let receipt = restore_backup(
        &bundle,
        &restored,
        manifest.digest(),
        BackupLimits::default(),
        &Grant,
        &f.cx()?,
    )?;
    let fence = RestoreFence::from_bytes(
        &fss_publication::read_verified(restored.join("objects"), receipt.fence_digest(), 4096)?,
        receipt.fence_digest(),
    )?;
    assert!(fence.agent_state_read_only());
    let recovered = inspect_agent_state(
        &restored,
        f.limits,
        BackupLimits::default(),
        &Grant,
        &f.cx()?,
    )?;
    assert!(recovered.restored);
    assert_eq!(recovered.summary, state.summary);
    assert_eq!(recovered.sessions, state.sessions);
    assert_eq!(recovered.publications, state.publications);
    for (path, bytes) in source_before
        .iter()
        .filter(|(path, _)| path.starts_with("agent"))
    {
        assert_eq!(
            &fs::read(restored.join(path))?,
            bytes,
            "changed recovered bytes {path:?}"
        );
    }
    let restored_publications = restored.join("agent/publications");
    let (_, restored_binding, restored_binding_bytes) =
        learning_binding(&restored_publications, &captured.learning)?;
    assert_eq!(restored_binding, binding_digest);
    assert_eq!(restored_binding_bytes, binding_bytes);
    assert_eq!(
        fss_publication::read_verified(
            &restored_publications,
            captured.learning.proposal_digest,
            1024 * 1024,
        )?,
        captured.learning.proposal.try_canonical_bytes()?,
    );
    let restored_before = bytes_under(&restored)?;
    // The exact original request is not authority to resume writing to a historical restore.
    assert!(matches!(
        publish_feedback(&restored, &captured.request),
        Err(DeploymentSessionError::StoreInvalid(_))
    ));
    assert_eq!(
        inspect_agent_state(
            &restored,
            f.limits,
            BackupLimits::default(),
            &Grant,
            &f.cx()?
        )?,
        recovered,
    );
    assert_eq!(bytes_under(&restored)?, restored_before);

    // Restore completion does not make an exact retry on the original live source a new
    // capture, renew its review/expiry, or bind it to the later same-anchor workspace.
    fs::rename(&offline, &f.source)?;
    let original_before = bytes_under(&f.source)?;
    let retry = publish_feedback(&f.source, &captured.request)?;
    assert!(
        retry.learning_refusal.is_none(),
        "{:?}",
        retry.learning_refusal
    );
    let retry = retry.learning.ok_or("exact learning retry missing")?;
    assert!(!retry.committed);
    assert_eq!(retry.root, captured.learning.root);
    assert_eq!(retry.experience, captured.learning.experience);
    assert_eq!(retry.proposal, captured.learning.proposal);
    assert_eq!(retry.experience_digest, captured.learning.experience_digest);
    assert_eq!(retry.proposal_digest, captured.learning.proposal_digest);
    assert_eq!(retry.evidence, captured.learning.evidence);
    assert_eq!(retry.missing_evidence, captured.learning.missing_evidence);
    assert_eq!(bytes_under(&f.source)?, original_before);
    assert_eq!(bytes_under(&restored)?, restored_before);
    Ok(())
}

fn replace_capture_digest(bytes: &mut [u8], field: usize, replacement: ContentDigest) -> Test {
    let (start, end) = {
        let mut d = CanonicalDecoder::new(bytes);
        assert_eq!(d.text()?, "fss.reference_agent_learning_capture.v1");
        d.bytes()?; // captured ContractBasis
        d.text()?; // session
        d.text()?; // mission
        d.text()?; // principal
        for _ in 0..field {
            d.digest()?;
        }
        let start = bytes.len() - d.remaining();
        d.digest()?;
        (start, bytes.len() - d.remaining())
    };
    let mut encoded = CanonicalEncoder::new();
    encoded.digest(replacement);
    let encoded = encoded.finish();
    assert_eq!(end - start, encoded.len());
    bytes[start..end].copy_from_slice(&encoded);
    Ok(())
}

fn rehash_learning_corruption(
    f: &Fixture,
    learning: &PublishedLearning,
    corruption: &str,
) -> Test<ContentDigest> {
    let directory = f.source.join("agent/publications");
    let (manifest, old_binding, mut binding_bytes) = learning_binding(&directory, learning)?;
    let mut children: Vec<_> = manifest
        .children()
        .iter()
        .copied()
        .filter(|digest| *digest != learning.experience_digest && *digest != old_binding)
        .collect();
    let slot = learning_slot(learning)?;
    // Model an out-of-contract replacement while retaining the original root record for
    // inspection. Production publication still refuses to replace an occupied immutable slot.
    fs::rename(
        directory
            .join("roots")
            .join(format!("{}.root", slot.as_str())),
        f.directory.0.join("original-learning.root"),
    )?;
    let mut publisher = LocalRootPublisher::open(&directory, publication_limits())?;
    match corruption {
        "proposal" => {
            let mut proposal = learning.proposal.clone();
            proposal.promotion_state = PromotionState::Promoted;
            let changed = publisher.stage_object(&proposal.try_canonical_bytes()?)?;
            children.retain(|digest| *digest != learning.proposal_digest);
            children.push(changed);
            // Rehash the binding too, so this is a semantically false promoted candidate
            // with valid object hashes, not merely a missing old child.
            replace_capture_digest(&mut binding_bytes, 6, changed)?;
        }
        "binding" => {
            replace_capture_digest(
                &mut binding_bytes,
                0,
                ContentDigest::sha256(b"workspace revision never retained by this session"),
            )?;
        }
        _ => return Err("unknown learning corruption".into()),
    }
    children.push(publisher.stage_object(&binding_bytes)?);
    let replacement =
        ObjectManifest::new("agent-learning", children, Some(learning.experience_digest))?;
    let root = publisher.publish(&slot, &replacement)?.root;
    drop(publisher);
    assert_ne!(root, learning.root);
    let inspection = fss_publication::inspect(&directory, publication_limits())?;
    assert!(
        !inspection.is_broken_slot(&slot),
        "all replacement object hashes are valid"
    );
    assert_eq!(
        inspection
            .root(&slot)
            .ok_or("replacement root missing")?
            .root,
        root
    );
    Ok(root)
}

#[test]
fn captured_learning_backup_refuses_rehashed_candidate_and_binding_without_repair() -> Test {
    for corruption in ["proposal", "binding"] {
        let f = Fixture::new(&format!("learning-rehashed-{corruption}"))?;
        let captured = capture_learning(&f)?;
        let approved = f.plan()?.digest();
        let replacement = rehash_learning_corruption(&f, &captured.learning, corruption)?;
        let before = bytes_under(&f.source)?;
        assert!(
            matches!(
                inspect_agent_state(
                    &f.source,
                    f.limits,
                    BackupLimits::default(),
                    &Grant,
                    &f.cx()?
                ),
                Err(BackupError::Corrupt("agent_learning_closure"))
            ),
            "semantic recovery admitted {corruption}"
        );
        assert!(f.plan().is_err());
        let forbidden = f.directory.0.join("must-not-back-up");
        assert!(
            create_backup(
                &f.source,
                &forbidden,
                approved,
                f.limits,
                BackupLimits::default(),
                &Grant,
                &f.cx()?,
            )
            .is_err()
        );
        assert!(!forbidden.exists());
        assert_eq!(
            bytes_under(&f.source)?,
            before,
            "recovery repaired {corruption}"
        );

        // An identical feedback retry must not bless or overwrite the substituted graph.
        match publish_feedback(&f.source, &captured.request) {
            Err(_) => {}
            Ok(answer) => {
                assert!(answer.learning.is_none());
                assert!(answer.learning_refusal.is_some());
            }
        }
        let inspection =
            fss_publication::inspect(f.source.join("agent/publications"), publication_limits())?;
        assert_eq!(
            inspection
                .root(&learning_slot(&captured.learning)?)
                .ok_or("replacement lost")?
                .root,
            replacement,
        );
    }
    Ok(())
}

#[test]
fn captured_learning_restore_refuses_damaged_proposal_or_binding_payload_before_creation() -> Test {
    for corruption in ["proposal", "binding"] {
        let f = Fixture::new(&format!("learning-bundle-{corruption}"))?;
        let captured = capture_learning(&f)?;
        let manifest = f.plan()?;
        let bundle = f.bundle("learning-bundle", &manifest)?;
        let (_, binding, _) =
            learning_binding(&f.source.join("agent/publications"), &captured.learning)?;
        let selected = if corruption == "proposal" {
            captured.learning.proposal_digest
        } else {
            binding
        };
        let path = publication_object(&bundle.join("payload/agent/publications"), selected)?;
        let mut bytes = fs::read(&path)?;
        bytes.push(0);
        fs::write(path, bytes)?;
        let source_before = bytes_under(&f.source)?;
        assert!(
            inspect_backup(
                &bundle,
                manifest.digest(),
                BackupLimits::default(),
                &Grant,
                &f.cx()?,
            )
            .is_err()
        );
        let destination = f.directory.0.join("must-not-restore");
        assert!(
            restore_backup(
                &bundle,
                &destination,
                manifest.digest(),
                BackupLimits::default(),
                &Grant,
                &f.cx()?,
            )
            .is_err()
        );
        assert!(!destination.exists());
        assert_eq!(bytes_under(&f.source)?, source_before);
    }
    Ok(())
}
