#![forbid(unsafe_code)]
//! Pure projection contracts; retained metadata is synthetic, never current source evidence.

use std::error::Error;

use super::*;
use crate::agent_session::checkpoint::journal::supervision::PendingSupervisionInventory;

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

fn snapshot() -> DeploymentSnapshot {
    DeploymentSnapshot {
        site_lineage: "site:supervision-projection".to_owned(),
        doctor_verdict: DoctorVerdict::Healthy,
        position: HistoryPosition {
            commit_sequence: 0,
            effect_records: None,
        },
        anchor: LedgerAnchor::genesis("site:supervision-projection"),
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
        principal: PrincipalId::parse("principal:supervision-projection")?,
        budget_tokens: None,
    })
}

fn binding(entries: Option<Vec<SupervisionInventoryEntry>>) -> TestResult<OrientSessionBinding> {
    Ok(OrientSessionBinding {
        session_id: SessionId::parse("session:supervision-projection")?,
        mission_id: MissionId::parse("mission:supervision-projection")?,
        mission: None,
        cases: Vec::new(),
        plans: Vec::new(),
        claims: Vec::new(),
        findings: Vec::new(),
        supervisions: entries,
        trauma_warnings: None,
    })
}

fn entry() -> SupervisionInventoryEntry {
    SupervisionInventoryEntry {
        subscription_id: "retained-patrol".to_owned(),
        state_digest: ContentDigest::sha256(b"synthetic retained subscription state"),
        authority_digest: ContentDigest::sha256(b"synthetic original authority"),
        authority_current: true,
        configuration_digest: ContentDigest::sha256(b"private configuration is not projected"),
        max_read_bytes: 4096,
        max_read_attempts: 4,
        maximum_attempts: 4,
        max_report_bytes: 4096,
        attempts_reserved: 2,
        reserved_bytes: 8192,
        reserved_read_attempts: 8,
        reservation: None,
        reservation_generations_current: None,
        pending: Some(PendingSupervisionInventory {
            receipt: ContentDigest::sha256(b"exact pending delivery"),
            report_receipt: ContentDigest::sha256(b"historical native report receipt"),
            anchor: snapshot().anchor,
            payload_digest: ContentDigest::sha256(b"private report is not projected"),
            payload_len: 32,
            active_window_count: None,
            generations_current: true,
        }),
        schedule: None,
        last_acknowledged: None,
        last_discarded: None,
    }
}

#[test]
fn unavailable_inventory_is_explicitly_unknown_and_never_observed_empty() -> TestResult {
    let snapshot = snapshot();
    let request = request()?;
    let unavailable = project(&snapshot, &request, Some(&binding(None)?))?;
    assert_eq!(unavailable.unknown.len(), 1);
    assert!(unavailable.unknown[0].contains("no absence of pending work is established"));
    assert!(unavailable.cells.is_empty());
    assert!(unavailable.proof_roots.is_empty());
    assert!(unavailable.affordances.is_empty());
    let empty = project(&snapshot, &request, Some(&binding(Some(Vec::new()))?))?;
    assert!(empty.unknown.is_empty());
    assert!(empty.cells.is_empty());
    assert!(empty.at_risk.is_empty());
    assert!(empty.affordances.is_empty());
    Ok(())
}

#[test]
fn exact_pending_receipt_survives_context_selection_or_the_budget_refuses() -> TestResult {
    let snapshot = snapshot();
    let entry = entry();
    let receipt = entry
        .pending
        .as_ref()
        .ok_or("pending fixture")?
        .receipt
        .to_text();
    let binding = binding(Some(vec![entry]))?;
    let request = request()?;
    let oriented = orient_deployment_for(
        &snapshot,
        &request,
        &OrientLimits::default(),
        Some(&binding),
    )?;
    assert!(oriented.supervision_inventory_available);
    assert_eq!(oriented.supervision_inventory.len(), 1);
    assert!(oriented.capsule().frame.unknown.iter().any(
        |line| line == "Current validity of retained supervision report sources is unverified."
    ));
    assert!(
        !oriented
            .capsule()
            .frame
            .unknown
            .iter()
            .any(|line| line.contains(&receipt))
    );
    assert!(
        oriented
            .publication
            .context_pack
            .items
            .iter()
            .any(|item| item.kind == "at_risk" && item.content.contains(&receipt))
    );
    assert!(
        oriented
            .publication
            .context_pack
            .items
            .iter()
            .any(|item| item.kind == "unknown"
                && item.content.contains("retained supervision report sources"))
    );
    assert!(
        oriented
            .publication
            .compression_receipt
            .critical_preservation
            .is_lossless()
    );
    let affordance = oriented
        .capsule()
        .affordances
        .iter()
        .find(|affordance| affordance.affordance_id == AFFORDANCE)
        .ok_or("recovery affordance")?;
    assert_eq!(affordance.operation, "session.orient");
    assert!(affordance.target.starts_with("fss://deployment/"));
    assert_eq!(
        affordance.required_capabilities,
        BTreeSet::from([CAPABILITY_SITUATION_READ.to_owned()])
    );
    assert!(affordance.rationale.contains("--list yes"));
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

#[test]
fn metadata_identity_tracks_authority_and_interpretations_without_anchor_restatement_churn()
-> TestResult {
    let snapshot = snapshot();
    let request = request()?;
    let initial = binding(Some(vec![entry()]))?;
    let baseline = project(&snapshot, &request, Some(&initial))?;
    assert_eq!(baseline.proof_roots.len(), 1);
    let mut position_only = snapshot.clone();
    position_only.anchor.commit_sequence += 1;
    position_only.anchor.state_root = ContentDigest::sha256(b"unrelated later authority position");
    let restated = project(&position_only, &request, Some(&initial))?;
    assert_eq!(restated.proof_roots, baseline.proof_roots);
    assert_eq!(restated.at_risk, baseline.at_risk);
    assert_eq!(restated.unknown, baseline.unknown);
    let mut narrowed = entry();
    narrowed.authority_current = false;
    let narrowed = project(&snapshot, &request, Some(&binding(Some(vec![narrowed]))?))?;
    assert_ne!(narrowed.proof_roots, baseline.proof_roots);
    assert!(narrowed.at_risk[0].contains("original authority differs"));
    // Resume may collect the same retained state before and after refreshing the session's
    // interpretation anchor. The owner-relative flag is not a change to this snapshot's facts.
    let mut old_session_comparison = entry();
    old_session_comparison
        .pending
        .as_mut()
        .ok_or("pending fixture")?
        .generations_current = false;
    let old_binding = binding(Some(vec![old_session_comparison.clone()]))?;
    let before_rebase = project(&snapshot, &request, Some(&old_binding))?;
    assert_eq!(before_rebase.proof_roots, baseline.proof_roots);
    assert_eq!(before_rebase.at_risk, baseline.at_risk);
    assert_eq!(before_rebase.unknown, baseline.unknown);
    let normalized = inventory_at(&[old_session_comparison.clone()], &snapshot.anchor);
    assert!(
        normalized[0]
            .pending
            .as_ref()
            .ok_or("normalized pending")?
            .generations_current
    );
    assert_eq!(
        normalized[0].state_digest,
        old_session_comparison.state_digest
    );
    let before_rebase = orient_deployment_for(
        &snapshot,
        &request,
        &OrientLimits::default(),
        Some(&old_binding),
    )?;
    let after_rebase = orient_deployment_for(
        &snapshot,
        &request,
        &OrientLimits::default(),
        Some(&initial),
    )?;
    assert_eq!(
        before_rebase.capsule().decision_fingerprint()?,
        after_rebase.capsule().decision_fingerprint()?
    );
    assert_eq!(
        before_rebase.supervision_inventory,
        after_rebase.supervision_inventory
    );
    let mut changed = snapshot;
    changed.anchor.policy_epoch += 1;
    let normalized = inventory_at(&[entry()], &changed.anchor);
    assert!(
        !normalized[0]
            .pending
            .as_ref()
            .ok_or("changed pending")?
            .generations_current
    );
    let changed = project(&changed, &request, Some(&initial))?;
    assert_ne!(changed.proof_roots, baseline.proof_roots);
    assert!(changed.at_risk[0].contains("historical generations differ"));
    Ok(())
}
