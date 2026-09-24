#![forbid(unsafe_code)]
//! Unit tests for the read-only orientation compiler over real on-disk deployments.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::{
    AffordanceClass, AgentView, BudgetVector, ContentDigest, ContextAuthority, EventId,
    KnowledgeState, OperationId, PrincipalId, RootAuthoritySpec,
};

use super::{
    AFFORDANCE_PLAN, AFFORDANCE_REORIENT, CLAIM_COVERAGE, CLAIM_LEDGER_HEAD, DeploymentReadError,
    OrientError, OrientLimits, OrientRequest, WORLD_UNOBSERVED_ACTIVITY, explain_event,
    orient_deployment, read_deployment,
};
use crate::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult = Result<(), Box<dyn Error>>;

fn fresh_root(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = std::env::temp_dir().join(format!(
        "fss-agent-orient-unit-{tag}-{}",
        std::process::id()
    ));
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(root)
}

fn empty_deployment(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = fresh_root(tag)?;
    let spec = RootAuthoritySpec {
        trace_id: format!("trace:orient-unit-{tag}"),
        operation_id: OperationId::parse(format!("operation:orient-unit-{tag}"))?,
        principal: format!("operator:orient-unit-{tag}"),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"orient-unit"),
        generation: 1,
    };
    let authority = ContextAuthority::new_root(spec)?;
    let scratch = std::env::temp_dir().join(format!(
        "fss-agent-orient-unit-cx-{tag}-{}",
        std::process::id()
    ));
    let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority, scratch,
    )?);
    drop(ReferenceDeployment::open(&root, "site:orient-unit", &cx)?);
    Ok(root)
}

fn request(view: AgentView) -> Result<OrientRequest, Box<dyn Error>> {
    Ok(OrientRequest {
        view,
        principal: PrincipalId::parse("principal:orient-unit")?,
        budget_tokens: None,
    })
}

#[test]
fn missing_and_foreign_roots_are_not_deployments() -> TestResult {
    let missing = fresh_root("missing")?;
    assert!(matches!(
        read_deployment(&missing, &OrientLimits::default()),
        Err(DeploymentReadError::NotADeployment { .. })
    ));
    fs::create_dir_all(&missing)?;
    fs::write(missing.join("notes.txt"), b"not a deployment")?;
    assert!(matches!(
        read_deployment(&missing, &OrientLimits::default()),
        Err(DeploymentReadError::NotADeployment { .. })
    ));
    fs::remove_dir_all(&missing)?;
    Ok(())
}

#[test]
fn empty_deployment_orients_to_not_observable_without_invented_facts() -> TestResult {
    let root = empty_deployment("empty")?;
    let limits = OrientLimits::default();
    let snapshot = read_deployment(&root, &limits)?;
    assert!(snapshot.events.is_empty());
    assert_eq!(snapshot.batch_count, 0);
    assert_eq!(snapshot.anchor.commit_sequence, 0);

    let brief = orient_deployment(&snapshot, &request(AgentView::Brief)?, &limits)?;
    let capsule = brief.capsule();
    capsule.validate()?;
    brief.publication.verify()?;
    assert!(
        capsule
            .frame
            .knowledge_cells
            .iter()
            .all(|cell| !cell.claim_id().starts_with("claim:event:"))
    );
    let coverage = capsule
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| cell.claim_id() == CLAIM_COVERAGE)
        .ok_or("coverage cell missing")?;
    assert_eq!(coverage.knowledge_state(), KnowledgeState::NotObservable);
    assert!(
        capsule
            .frame
            .knowledge_cells
            .iter()
            .any(|cell| cell.claim_id() == CLAIM_LEDGER_HEAD
                && cell.knowledge_state() == KnowledgeState::Known)
    );
    assert_eq!(brief.epistemic_state, KnowledgeState::NotObservable);
    assert!(
        capsule
            .frame
            .world_envelope
            .adversarial_residuals
            .iter()
            .any(|world| world.world_id == WORLD_UNOBSERVED_ACTIVITY && world.protected)
    );
    assert!(capsule.obligations.is_empty());
    assert!(brief.indeterminate_effects.is_empty());
    let plan = capsule
        .affordances
        .iter()
        .find(|candidate| candidate.affordance_id == AFFORDANCE_PLAN)
        .ok_or("plan affordance missing")?;
    assert_eq!(plan.class, AffordanceClass::Unavailable);
    assert!(!capsule.frame.next.contains(&AFFORDANCE_PLAN.to_owned()));

    // Deterministic: the same committed bytes compile to the same fingerprint.
    let again = orient_deployment(
        &read_deployment(&root, &limits)?,
        &request(AgentView::Brief)?,
        &limits,
    )?;
    assert_eq!(
        again.capsule().decision_fingerprint()?,
        capsule.decision_fingerprint()?
    );
    assert_eq!(
        again.publication.publication_digest,
        brief.publication.publication_digest
    );

    let pulse = orient_deployment(&snapshot, &request(AgentView::Pulse)?, &limits)?;
    assert_eq!(
        pulse
            .capsule()
            .affordances
            .iter()
            .map(|candidate| candidate.affordance_id.as_str())
            .collect::<Vec<_>>(),
        vec![AFFORDANCE_REORIENT]
    );
    assert_eq!(
        pulse.publication.compression_receipt.view_id,
        AgentView::Pulse.id()
    );

    assert!(explain_event(&snapshot, &brief, &EventId::parse("event:none")?)?.is_none());
    fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn too_small_budget_is_refused_not_truncated() -> TestResult {
    let root = empty_deployment("budget")?;
    let limits = OrientLimits::default();
    let snapshot = read_deployment(&root, &limits)?;
    let mut tiny = request(AgentView::Brief)?;
    tiny.budget_tokens = Some(8);
    assert!(matches!(
        orient_deployment(&snapshot, &tiny, &limits),
        Err(OrientError::ContextBudgetExceeded {
            budget_tokens: 8,
            ..
        })
    ));
    assert!(matches!(
        orient_deployment(&snapshot, &request(AgentView::Case)?, &limits),
        Err(OrientError::UnsupportedView(AgentView::Case))
    ));
    fs::remove_dir_all(&root)?;
    Ok(())
}
