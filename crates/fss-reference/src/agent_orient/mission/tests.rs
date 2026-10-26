#![forbid(unsafe_code)]
//! Synthetic pure projections test request preservation, never physical mission completion.

use std::error::Error;

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn snapshot() -> DeploymentSnapshot {
    DeploymentSnapshot {
        site_lineage: "site:mission-projection".to_owned(),
        doctor_verdict: DoctorVerdict::Healthy,
        position: HistoryPosition {
            commit_sequence: 0,
            effect_records: None,
        },
        anchor: LedgerAnchor::genesis("site:mission-projection"),
        ledger_root: ContentDigest::sha256(b"synthetic empty ledger"),
        batch_count: 0,
        event_ledger_root: None,
        evidence_ledger_root: None,
        import_ledger_root: None,
        ledger_tail_uncommitted: false,
        family_counts: BTreeMap::new(),
        completed_imports: Vec::new(),
        deletions_committed: 0,
        effect_journal_present: false,
        effect_journal_digest: ContentDigest::sha256(&[]),
        effect_journal_root: ContentDigest::sha256(&[]),
        effect_tail_uncommitted: false,
        obligations: Vec::new(),
        operations: Vec::new(),
        events: Vec::new(),
        historical_health: Vec::new(),
        sensor_liveness: Vec::new(),
        coverage: Vec::new(),
        source_coverage: Vec::new(),
        retained_absences: BTreeMap::new(),
        sensor_newest_evidence: BTreeMap::new(),
        coverage_evidence_unattributed: false,
        latest_evidence_time: TimestampNs(0),
        deletions: crate::deletion::DeletionIndex::default(),
        files_read: 2,
        bytes_read: 256,
    }
}

fn request() -> TestResult<OrientRequest> {
    Ok(OrientRequest {
        view: AgentView::Brief,
        principal: PrincipalId::parse("principal:mission-projection")?,
        budget_tokens: None,
    })
}

fn binding() -> TestResult<OrientSessionBinding> {
    let mission_id = MissionId::parse("mission:mission-projection")?;
    let session_id = SessionId::parse("session:mission-projection")?;
    Ok(OrientSessionBinding {
        mission_id: mission_id.clone(),
        session_id: session_id.clone(),
        mission: Some(OrientMissionBrief {
            mission_id,
            session_id,
            principal: request()?.principal,
            site_lineage: snapshot().site_lineage,
            mission: "Keep the exact requested mission.\n Preserve this spacing.".to_owned(),
            objective: "Determine whether the east door opened; do not infer an answer.".to_owned(),
            record_digest: ContentDigest::sha256(b"synthetic authenticated mission record"),
        }),
        mission_progress: None,
        cases: Vec::new(),
        plans: Vec::new(),
        claims: Vec::new(),
        findings: Vec::new(),
        supervisions: Some(Vec::new()),
        trauma_warnings: Some(Vec::new()),
    })
}

#[test]
fn literal_goal_is_critical_context_without_rendering_success_as_mission_success() -> TestResult {
    let binding = binding()?;
    let mission = binding.mission.as_ref().ok_or("mission fixture")?;
    let oriented = orient_deployment_for(
        &snapshot(),
        &request()?,
        &OrientLimits::default(),
        Some(&binding),
    )?;
    assert_eq!(oriented.objective.desired_outcome, mission.objective);
    assert_eq!(
        oriented.objective.source_request_digest,
        mission.record_digest.to_text()
    );
    assert_eq!(
        oriented.objective.objective_id,
        oriented.capsule().frame.objective_id
    );
    assert!(oriented.objective.success_predicates.is_empty());
    assert!(oriented.objective.failure_predicates.is_empty());
    assert!(oriented.objective.stop_conditions.is_empty());
    assert!(oriented.objective.terminal_proof.is_empty());
    assert_eq!(oriented.objective.allowed_actions, vec!["session.orient"]);
    assert!(
        oriented
            .objective
            .hard_constraints
            .iter()
            .any(|line| line.starts_with("Read-only:"))
    );
    let summary = oriented
        .publication
        .context_pack
        .items
        .iter()
        .find(|item| item.item_id == "context:frame:summary")
        .ok_or("protected frame summary")?;
    assert!(summary.content.contains(&mission.mission));
    assert!(summary.content.contains(&mission.objective));
    assert!(
        oriented
            .publication
            .context_pack
            .items
            .iter()
            .any(|item| item.kind == "unknown" && item.content == COMPLETION_UNKNOWN)
    );
    assert!(
        oriented
            .publication
            .compression_receipt
            .critical_preservation
            .is_lossless()
    );
    let retained = oriented
        .capsule()
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id() == CLAIM)
        .ok_or("retained request cell")?;
    assert_eq!(retained.evidence_digests(), vec![mission.record_digest]);
    assert!(!retained.is_irreversible_effect_premise(TimestampNs::ZERO));
    assert!(oriented.capsule().mission_state.is_none());
    Ok(())
}

#[test]
fn goal_and_record_identity_change_fingerprints_but_unchanged_retries_do_not() -> TestResult {
    let original = binding()?;
    let render = |binding: &OrientSessionBinding| {
        orient_deployment_for(
            &snapshot(),
            &request()?,
            &OrientLimits::default(),
            Some(binding),
        )
        .map_err(Into::<Box<dyn Error>>::into)
    };
    let first = render(&original)?;
    let retry = render(&original)?;
    assert_eq!(
        first.capsule().decision_fingerprint()?,
        retry.capsule().decision_fingerprint()?
    );
    assert_eq!(first.objective, retry.objective);
    let mut changed = original.clone();
    changed
        .mission
        .as_mut()
        .ok_or("mission fixture")?
        .objective
        .push_str(" Preserve uncertainty.");
    let changed = render(&changed)?;
    assert_ne!(first.capsule().capsule_id, changed.capsule().capsule_id);
    assert_ne!(
        first.capsule().decision_fingerprint()?,
        changed.capsule().decision_fingerprint()?
    );
    let mut changed_record = original;
    changed_record
        .mission
        .as_mut()
        .ok_or("mission fixture")?
        .record_digest = ContentDigest::sha256(b"different authenticated mission record");
    let changed_record = render(&changed_record)?;
    assert_ne!(
        first.objective.objective_id,
        changed_record.objective.objective_id
    );
    assert_ne!(
        first.objective.decision_digest,
        changed_record.objective.decision_digest
    );
    assert_ne!(
        first.capsule().decision_fingerprint()?,
        changed_record.capsule().decision_fingerprint()?
    );
    Ok(())
}

#[test]
fn foreign_scope_and_invalid_text_refuse_before_disclosure() -> TestResult {
    let original = binding()?;
    let mut foreign_principal = original.clone();
    foreign_principal
        .mission
        .as_mut()
        .ok_or("mission fixture")?
        .principal = PrincipalId::parse("principal:other")?;
    let mut foreign_session = original.clone();
    foreign_session
        .mission
        .as_mut()
        .ok_or("mission fixture")?
        .session_id = SessionId::parse("session:other")?;
    let mut foreign_mission = original.clone();
    foreign_mission
        .mission
        .as_mut()
        .ok_or("mission fixture")?
        .mission_id = MissionId::parse("mission:other")?;
    let mut foreign_site = original.clone();
    foreign_site
        .mission
        .as_mut()
        .ok_or("mission fixture")?
        .site_lineage = "site:other".to_owned();
    for binding in [
        foreign_principal,
        foreign_session,
        foreign_mission,
        foreign_site,
    ] {
        assert!(matches!(
            project(&snapshot(), &request()?, Some(&binding)),
            Err(ContractError::EvidenceRequired)
        ));
    }
    let mut invalid = original;
    invalid
        .mission
        .as_mut()
        .ok_or("mission fixture")?
        .objective
        .clear();
    assert!(matches!(
        project(&snapshot(), &request()?, Some(&invalid)),
        Err(ContractError::InvalidIdentifier)
    ));
    Ok(())
}

#[test]
fn absent_goal_is_explicit_and_tiny_views_cannot_drop_a_present_goal() -> TestResult {
    let snapshot = snapshot();
    let request = request()?;
    assert!(project(&snapshot, &request, None)?.unknown.is_empty());
    let mut unavailable = binding()?;
    unavailable.mission = None;
    let missing = project(&snapshot, &request, Some(&unavailable))?;
    assert!(missing.objective_id.is_none());
    assert!(missing.cells.is_empty());
    assert!(missing.proof_roots.is_empty());
    assert_eq!(missing.unknown.len(), 1);
    assert!(missing.unknown[0].contains("has not been loaded"));
    let binding = binding()?;
    for view in [AgentView::Pulse, AgentView::Brief, AgentView::EpistemicMap] {
        let constrained = OrientRequest {
            view,
            budget_tokens: Some(1),
            ..request.clone()
        };
        assert!(matches!(
            orient_deployment_for(
                &snapshot,
                &constrained,
                &OrientLimits::default(),
                Some(&binding)
            ),
            Err(OrientError::ContextBudgetExceeded {
                budget_tokens: 1,
                ..
            })
        ));
    }
    Ok(())
}
