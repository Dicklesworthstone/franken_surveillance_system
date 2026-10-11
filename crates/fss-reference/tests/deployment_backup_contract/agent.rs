#![forbid(unsafe_code)]
//! Native populated-agent recovery, including historical leases and uncertainty.

use std::collections::BTreeSet;

use fss_core::{
    AgentView, CaseDiscriminator, CaseHypothesis, KnownStatement, KnowledgeState, PrincipalId,
};
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, DurableSessionStore,
};
use fss_reference::agent_session::checkpoint::journal::coordination::investigations::InvestigationChange;
use fss_reference::agent_session::work_claims::WorkClaimLimits;
use fss_reference::deployment_session::claims::{
    ClaimAction, ClaimChange, ClaimRequest, ClaimWork, work_claim,
};
use fss_reference::deployment_session::investigation::{
    CaseAction, CaseDeadline, CaseDraft, InvestigateRequest, investigate,
};
use fss_reference::deployment_session::plan::{PlanRecord, publish_plan, read_control_plan};
use fss_reference::deployment_session::{
    AgentRecoveryRecord, DeploymentSessionError, HandoffRequest, OpenSessionRequest, OpenedSession,
    ResumeRequest, open_session, prepare_handoff, resume_session,
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

#[test]
fn populated_agent_roundtrip_keeps_native_history_and_fences_all_deployment_writers() -> Test {
    let f = Fixture::new("agent-roundtrip")?;
    let opened = open_session(&f.source, &request()?)?;
    let case_request = InvestigateRequest {
        session_id: opened.session.session_id.clone(),
        principal: opened.session.principal_id.clone(),
        action: CaseAction::Open(Box::new(case_draft())),
    };
    let case = investigate(&f.source, &case_request)?.revision.ok_or("missing case")?;
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
    )?.revision.ok_or("missing active case")?;
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
    let claim = work_claim(&f.source, &claim_request)?.claim.ok_or("missing claim")?;
    let handoff = prepare_handoff(
        &f.source,
        &HandoffRequest {
            session_id: opened.session.session_id.clone(),
            principal: opened.session.principal_id.clone(),
            note: Some("Cause remains unknown; do not renew the copied lease".into()),
        },
    )?.publish(&[b"retained-handoff-rendering".to_vec()])?;
    let plan = retained_plan(&opened);
    let plan_root = publish_plan(&f.source, &plan, b"exact-native-plan-child")?;
    let before = bytes_under(&f.source)?;
    let state = inspect_agent_state(
        &f.source, f.limits, BackupLimits::default(), &Grant, &f.cx()?,
    )?;
    assert!(!state.restored);
    assert_eq!(state.summary.session_count, 1);
    assert_eq!(state.summary.claim_count, 1);
    assert_eq!(state.summary.case_count, 1);
    assert_eq!(state.summary.publication_count, 3);
    assert!(state.summary.workspace_revision_count > 1);
    assert_eq!(state.sessions.claims, vec![claim.clone()]);
    assert_eq!(state.sessions.cases, vec![active]);
    assert_eq!(state.sessions.cases[0].record().unknowns[0].epistemic_state, KnowledgeState::Unknown);
    assert!(state.publications.iter().any(|item| matches!(
        &item.record,
        AgentRecoveryRecord::Handoff(record) if **record == handoff.record
    )));
    let manifest = f.plan()?;
    assert_eq!(manifest.profile(), AGENT_BACKUP_PROFILE);
    assert_eq!(manifest.agent_state(), Some(&state.summary));
    let bundle = f.directory.0.join("agent-bundle");
    create_backup(
        &f.source, &bundle, manifest.digest(), f.limits, BackupLimits::default(), &Grant, &f.cx()?,
    )?;
    assert_eq!(
        inspect_backup(&bundle, manifest.digest(), BackupLimits::default(), &Grant, &f.cx()?)?,
        manifest,
    );
    assert_eq!(bytes_under(&f.source)?, before, "inspection and backup changed source state");
    // A cold restore has no source deployment available at its former path.
    fs::rename(&f.source, f.directory.0.join("source-offline"))?;
    let restored = f.directory.0.join("agent-restored");
    let receipt = restore_backup(
        &bundle, &restored, manifest.digest(), BackupLimits::default(), &Grant, &f.cx()?,
    )?;
    assert_ne!(receipt.destination_anchor(), manifest.source_anchor());
    let fence_bytes = fss_publication::read_verified(
        restored.join("objects"), receipt.fence_digest(), 4096,
    )?;
    let fence = RestoreFence::from_bytes(&fence_bytes, receipt.fence_digest())?;
    assert!(fence.agent_state_read_only());
    assert_eq!(fence.source_manifest(), manifest.digest());
    assert_eq!(fence.to_bytes(), fence_bytes);
    let recovered = inspect_agent_state(
        &restored, f.limits, BackupLimits::default(), &Grant, &f.cx()?,
    )?;
    assert!(recovered.restored);
    assert_eq!(recovered.summary, state.summary);
    assert_eq!(recovered.sessions, state.sessions);
    assert_eq!(recovered.publications, state.publications);
    for (path, bytes) in before.iter().filter(|(path, _)| path.starts_with("agent")) {
        assert_eq!(&fs::read(restored.join(path))?, bytes, "agent bytes changed: {path:?}");
    }
    let inspected_before = bytes_under(&restored)?;
    let (read_plan, read_root, child) = read_control_plan(&restored, &plan.plan_id)?;
    assert_eq!(read_plan, plan);
    assert_eq!(read_root, plan_root);
    assert_eq!(child, b"exact-native-plan-child");
    assert!(matches!(open_session(&restored, &request()?), Err(DeploymentSessionError::StoreInvalid(_))));
    assert!(matches!(
        resume_session(&restored, &ResumeRequest {
            handoff_id: handoff.record.capsule.handoff_id,
            principal: opened.session.principal_id.clone(),
        }),
        Err(DeploymentSessionError::StoreInvalid(_))
    ));
    assert!(matches!(
        investigate(&restored, &InvestigateRequest {
            action: CaseAction::Inspect { case_id: case.record().investigation_id.clone(), revision: None },
            ..case_request
        }),
        Err(DeploymentSessionError::StoreInvalid(_))
    ));
    assert!(matches!(
        work_claim(&restored, &ClaimRequest {
            action: ClaimAction::Change {
                claim_id: claim.claim().claim_id.clone(),
                expected: claim.digest(),
                change: ClaimChange::Renew { lease_ms: 120_000 },
            },
            ..claim_request
        }),
        Err(DeploymentSessionError::StoreInvalid(_))
    ));
    let mut new_plan = plan.clone();
    new_plan.plan_id = "plan:copied-authority-must-not-publish".into();
    assert!(matches!(
        publish_plan(&restored, &new_plan, b"exact-native-plan-child"),
        Err(DeploymentSessionError::StoreInvalid(_))
    ));
    assert_eq!(bytes_under(&restored)?, inspected_before, "restored reads or refusals mutated history");
    Ok(())
}

#[test]
fn populated_agent_backup_preserves_closed_session_checkpoint_without_reopening_identity() -> Test {
    let f = Fixture::new("agent-closed")?;
    let opened = open_session(&f.source, &request()?)?;
    let journal = f.source.join("agent/sessions/journal.fssj");
    let mut store = DurableSessionStore::open_existing_with_coordination(
        &journal, opened.journal_root, DurableSessionLimits::default(), WorkClaimLimits::default(),
    )?;
    store.close(&opened.session.principal_id, &opened.session.session_id, TimestampNs(0))?;
    fs::write(f.source.join("agent/sessions/ROOT"), format!("{}\n", store.committed_root().to_text()))?;
    drop(store);
    let before = inspect_agent_state(&f.source, f.limits, BackupLimits::default(), &Grant, &f.cx()?)?;
    assert_eq!(before.summary.closed_session_count, 1);
    assert!(before.sessions.sessions[0].closed);
    let manifest = f.plan()?;
    let bundle = f.directory.0.join("bundle");
    create_backup(&f.source, &bundle, manifest.digest(), f.limits, BackupLimits::default(), &Grant, &f.cx()?)?;
    let destination = f.directory.0.join("restored");
    restore_backup(&bundle, &destination, manifest.digest(), BackupLimits::default(), &Grant, &f.cx()?)?;
    let after = inspect_agent_state(&destination, f.limits, BackupLimits::default(), &Grant, &f.cx()?)?;
    assert_eq!(after.sessions, before.sessions);
    assert!(after.restored);
    assert!(open_session(&destination, &request()?).is_err());
    Ok(())
}

#[test]
fn populated_agent_backup_refuses_stale_pins_tails_and_rehashed_invalid_history_without_repair() -> Test {
    for corruption in ["pin", "tail", "foreign-record", "staging", "unknown-subtree"] {
        let f = Fixture::new(&format!("agent-{corruption}"))?;
        open_session(&f.source, &request()?)?;
        let approved = f.plan()?.digest();
        match corruption {
            "pin" => fs::write(
                f.source.join("agent/sessions/ROOT"),
                format!("{}\n", ContentDigest::sha256(b"stale-independent-pin").to_text()),
            )?,
            "tail" => fs::OpenOptions::new().append(true)
                .open(f.source.join("agent/sessions/journal.fssj"))?
                .write_all(b"not a committed agent record")?,
            "foreign-record" => {
                let mut journal = fss_ledger::Journal::open(
                    f.source.join("agent/sessions/journal.fssj"),
                    fss_ledger::IncompleteTailPolicy::Reject,
                )?;
                journal.append(0x7777, b"cryptographically valid but semantically foreign")?;
                fs::write(f.source.join("agent/sessions/ROOT"), format!("{}\n", journal.last_root().to_text()))?;
            }
            "staging" => fs::write(
                f.source.join("agent/publications/spool/staging/uncommitted"), b"uncommitted",
            )?,
            _ => fs::create_dir(f.source.join("agent/unowned-archive"))?,
        }
        let before = bytes_under(&f.source)?;
        assert!(f.plan().is_err(), "plan admitted corrupt native state: {corruption}");
        assert!(inspect_agent_state(
            &f.source, f.limits, BackupLimits::default(), &Grant, &f.cx()?,
        ).is_err(), "inspector admitted corrupt native state: {corruption}");
        let bundle = f.directory.0.join("must-not-exist");
        assert!(create_backup(
            &f.source, &bundle, approved, f.limits,
            BackupLimits::default(), &Grant, &f.cx()?,
        ).is_err());
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
        let lock = fs::OpenOptions::new().read(true).write(true).open(f.source.join(relative))?;
        lock.try_lock()?;
        assert_eq!(f.plan().unwrap_err().to_string(), BackupError::Locked.to_string());
    }
    let manifest = f.plan()?;
    let bundle = f.directory.0.join("bundle");
    create_backup(&f.source, &bundle, manifest.digest(), f.limits, BackupLimits::default(), &Grant, &f.cx()?)?;
    let pin = bundle.join("payload/agent/sessions/ROOT");
    fs::write(pin, b"changed after independent manifest approval")?;
    let destination = f.directory.0.join("must-not-exist");
    assert!(restore_backup(
        &bundle, &destination, manifest.digest(), BackupLimits::default(), &Grant, &f.cx()?,
    ).is_err());
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
        &f.source, &bundle, manifest.digest(), f.limits, BackupLimits::default(), &Grant, &f.cx()?,
    )?;
    let restored = f.directory.0.join("restored");
    let receipt = restore_backup(
        &bundle, &restored, manifest.digest(), BackupLimits::default(), &Grant, &f.cx()?,
    )?;
    let fence_bytes = fss_publication::read_verified(
        restored.join("objects"), receipt.fence_digest(), 4096,
    )?;
    let fence = RestoreFence::from_bytes(&fence_bytes, receipt.fence_digest())?;
    assert!(!fence.agent_state_read_only());
    assert_eq!(fence.source_manifest(), manifest.digest());
    assert_eq!(fence.to_bytes(), fence_bytes);
    assert!(!restored.join("agent/sessions/journal.fssj").exists());
    let opened = open_session(&restored, &request()?)?;
    let state = inspect_agent_state(
        &restored, f.limits, BackupLimits::default(), &Grant, &f.cx()?,
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
            &f.source, &bundle, manifest.digest(), f.limits, BackupLimits::default(), &Grant, &f.cx()?,
        )?;
        let restored = f.directory.0.join("restored");
        restore_backup(
            &bundle, &restored, manifest.digest(), BackupLimits::default(), &Grant, &f.cx()?,
        )?;
        let before = bytes_under(&restored)?;
        let live_path = f.source.join(alias);
        fs::rename(&live_path, f.directory.0.join("original-agent-path"))?;
        if alias.ends_with("journal.fssj") {
            fs::hard_link(restored.join(alias), &live_path)?;
        } else {
            symlink(restored.join(alias), &live_path)?;
        }
        assert!(matches!(
            open_session(&f.source, &request()?),
            Err(DeploymentSessionError::StoreInvalid(_))
        ), "session writer admitted restored-state alias: {alias}");
        assert!(matches!(
            publish_plan(&f.source, &plan, b"exact-native-plan-child"),
            Err(DeploymentSessionError::StoreInvalid(_))
        ), "publication writer admitted restored-state alias: {alias}");
        assert_eq!(bytes_under(&restored)?, before, "aliased writer changed restored history: {alias}");
    }
    Ok(())
}
