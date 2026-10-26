#![forbid(unsafe_code)]
//! Canonical historical-memory projection and critical compression contracts.

use std::error::Error;

use fss_core::AttributionCauseClass;

use super::*;
use crate::deployment_session::trauma_guard::{TRAUMA_GUARD_DOMAIN, TRAUMA_HALF_LIFE_NS};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn snapshot() -> DeploymentSnapshot {
    DeploymentSnapshot {
        site_lineage: "site:trauma-projection".to_owned(),
        doctor_verdict: DoctorVerdict::Healthy,
        position: HistoryPosition {
            commit_sequence: 0,
            effect_records: None,
        },
        anchor: LedgerAnchor::genesis("site:trauma-projection"),
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

fn warning(label: &str) -> TestResult<AntiPatternWarning> {
    let target = format!("{{\"id\":\"event:{label}\",\"kind\":\"event\"}}");
    let cause = AttributionCauseClass::Hypothesis;
    let ids = vec![format!("feedback:a-{label}"), format!("feedback:b-{label}")];
    let digest = digest_of(TRAUMA_GUARD_DOMAIN, |encoder| {
        encoder.text(&target);
        encoder.text(cause.as_str());
        encoder.u32(ids.len() as u32);
        for id in &ids {
            encoder.text(id);
        }
    })
    .to_text();
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or("sha256 warning identity")?;
    let mut roots = vec![
        ContentDigest::sha256(format!("publication a {label}").as_bytes()),
        ContentDigest::sha256(format!("publication b {label}").as_bytes()),
    ];
    roots.sort();
    let warning = AntiPatternWarning {
        warning_id: format!("trauma-guard:{}", hex.chars().take(32).collect::<String>()),
        target_json: target,
        cause_class: cause,
        negative_count: ids.len(),
        half_life_ns: TRAUMA_HALF_LIFE_NS,
        decay_weight_ppm: 2_000_000,
        cited_record_ids: ids,
        cited_evidence_digests: roots,
        active_policy_mutation: false,
    };
    warning.validate()?;
    Ok(warning)
}

#[test]
fn unavailable_memory_is_not_an_observed_empty_history() -> TestResult {
    let unavailable = project(None)?;
    let empty = project(Some(&[]))?;
    assert!(
        unavailable
            .unknown
            .iter()
            .any(|value| value.contains("no absence of harmful history"))
    );
    assert!(unavailable.cells.is_empty());
    assert!(unavailable.proof_roots.is_empty());
    assert!(empty.unknown.is_empty());
    assert!(empty.cells.is_empty());
    assert!(empty.at_risk.is_empty());
    assert!(empty.warnings.is_empty());
    Ok(())
}

#[test]
fn exact_sources_are_canonical_and_historical_applicability_remains_unknown() -> TestResult {
    let first = warning("first")?;
    let second = warning("second")?;
    let forward = project(Some(&[first.clone(), second.clone()]))?;
    let reverse = project(Some(&[second.clone(), first.clone()]))?;
    assert_eq!(forward.at_risk, reverse.at_risk);
    assert_eq!(forward.proof_roots, reverse.proof_roots);
    assert_eq!(
        forward.unknown,
        vec!["Applicability of historical harmful outcomes to the current mission is unverified."]
    );
    for warning in [&first, &second] {
        assert!(forward.proof_roots.contains(&warning.canonical_digest()));
        for digest in &warning.cited_evidence_digests {
            assert!(forward.proof_roots.contains(digest));
        }
        assert!(
            forward
                .at_risk
                .iter()
                .any(|risk| risk.contains(&warning.summary()))
        );
        assert!(forward.warnings.contains(&warning.summary()));
    }
    for cell in &forward.cells {
        let params = cell.to_params();
        assert_eq!(params.knowledge_state, KnowledgeState::Known);
        assert_eq!(params.provenance, ProvenanceClass::Derived);
        assert!(params.statement.contains("Retained historical advisory"));
        assert!(
            params
                .statement
                .contains("do not establish the current target state")
        );
        assert!(
            params
                .statement
                .contains("permission to change policy or execute effects")
        );
    }
    let mut aged = first.clone();
    aged.decay_weight_ppm = 1_000_000;
    let aged = project(Some(&[aged]))?;
    let original = project(Some(&[first]))?;
    assert_eq!(aged.unknown, original.unknown);
    assert_ne!(aged.proof_roots, original.proof_roots);
    assert_ne!(aged.at_risk, original.at_risk);
    Ok(())
}

#[test]
fn mutated_authority_flags_duplicate_identities_and_unbounded_input_are_refused() -> TestResult {
    let warning = warning("refusals")?;
    let mut forbidden = warning.clone();
    forbidden.active_policy_mutation = true;
    assert!(matches!(
        project(Some(&[forbidden])),
        Err(ContractError::DerivedLayerAuthorityForbidden)
    ));
    assert!(matches!(
        project(Some(&[warning.clone(), warning.clone()])),
        Err(ContractError::NonCanonicalOrdering)
    ));
    assert!(matches!(
        project(Some(&vec![warning.clone(); MAX_TRAUMA_WARNINGS + 1])),
        Err(ContractError::BudgetExhausted)
    ));
    let mut missing_evidence = warning;
    missing_evidence.cited_evidence_digests.clear();
    assert!(matches!(
        project(Some(&[missing_evidence])),
        Err(ContractError::EvidenceRequired)
    ));
    Ok(())
}

#[test]
fn same_anchor_advisory_changes_fingerprint_and_cannot_disappear_under_a_small_budget() -> TestResult
{
    let snapshot = snapshot();
    let request = OrientRequest {
        view: AgentView::Brief,
        principal: PrincipalId::parse("principal:trauma-projection")?,
        budget_tokens: None,
    };
    let warning = warning("protected")?;
    let before = orient_deployment_with_advisories(
        &snapshot,
        &request,
        &OrientLimits::default(),
        Some(&[]),
    )?;
    let after = orient_deployment_with_advisories(
        &snapshot,
        &request,
        &OrientLimits::default(),
        Some(std::slice::from_ref(&warning)),
    )?;
    assert_eq!(before.capsule().anchor, after.capsule().anchor);
    assert_ne!(
        before.capsule().decision_fingerprint()?,
        after.capsule().decision_fingerprint()?
    );
    let selected = &after.publication.context_pack.items;
    assert!(
        selected
            .iter()
            .any(|item| item.kind == "at_risk" && item.content.contains(&warning.warning_id))
    );
    for digest in &warning.cited_evidence_digests {
        assert!(
            selected
                .iter()
                .any(|item| item.kind == "at_risk" && item.content.contains(&digest.to_text()))
        );
    }
    assert!(selected.iter().any(|item| {
        item.kind == "unknown"
            && item
                .content
                .contains("Applicability of historical harmful outcomes")
    }));
    assert!(
        after
            .publication
            .compression_receipt
            .critical_preservation
            .is_lossless()
    );
    let retry = orient_deployment_with_advisories(
        &snapshot,
        &request,
        &OrientLimits::default(),
        Some(std::slice::from_ref(&warning)),
    )?;
    assert_eq!(
        retry.capsule().decision_fingerprint()?,
        after.capsule().decision_fingerprint()?
    );
    for view in [AgentView::Pulse, AgentView::Brief, AgentView::EpistemicMap] {
        let constrained = OrientRequest {
            view,
            budget_tokens: Some(1),
            ..request.clone()
        };
        assert!(matches!(
            orient_deployment_with_advisories(
                &snapshot,
                &constrained,
                &OrientLimits::default(),
                Some(std::slice::from_ref(&warning)),
            ),
            Err(OrientError::ContextBudgetExceeded {
                budget_tokens: 1,
                ..
            })
        ));
    }
    Ok(())
}
