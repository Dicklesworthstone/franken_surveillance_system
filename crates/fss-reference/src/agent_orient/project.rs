#![forbid(unsafe_code)]
//! Budget-checked orientation projection entrypoints (`orient_deployment*`) for [`super`].

use std::collections::BTreeSet;

use fss_core::{
    AgentView, BudgetVector, ContractError, OperationId, OrientBudget, ResourcePressure,
    orient_projection,
};

use super::capsule::compile_capsule;
use super::frontier::{orientation_objective, orientation_validity};
use super::supervision;
use super::types::{
    DIRECT_EVENT_EXPANSION_LIMIT, DeploymentOrientation, DeploymentSnapshot, MAX_DEPLOYMENT_EVENTS,
    OrientError, OrientLimits, OrientRequest, OrientSessionBinding, ProjectionPurpose,
    UNBOUND_SESSION_DEGRADATION,
};
use crate::ReferenceError;
use crate::deployment_session::trauma_guard::AntiPatternWarning;
use crate::situation::EffectCellKind;
use crate::situation_guard::ReferenceSituation;
use crate::situation_sections::{
    ReferenceProjectionSpec, project_reference_situation_with_source_omissions,
};

/// Section entry budget of the AOP-003 projection for one view.
fn orient_budget(view: AgentView) -> Result<OrientBudget, ContractError> {
    let tokens = view.target_tokens();
    OrientBudget::new((tokens / 30).max(4), (tokens / 10).max(8))
}

fn projection_spec(
    view: AgentView,
    tokens: u64,
    degraded: bool,
) -> Result<ReferenceProjectionSpec, ContractError> {
    let available = BudgetVector::builder()
        .tokens(tokens)
        .bytes(4 * 1024 * 1024)
        .build()
        .map_err(|_| ContractError::BudgetExhausted)?;
    Ok(ReferenceProjectionSpec {
        view_id: view.id().to_owned(),
        available_resources: available,
        reserved_resources: BudgetVector::ZERO,
        pressure: if degraded {
            ResourcePressure::Elevated
        } else {
            ResourcePressure::Nominal
        },
        degraded_dimensions: if degraded {
            BTreeSet::from(["tokens".to_owned()])
        } else {
            BTreeSet::new()
        },
        target_tokens: tokens,
    })
}

fn is_budget_refusal(error: &ReferenceError) -> bool {
    matches!(
        error,
        ReferenceError::Contract(ContractError::BudgetExhausted)
    )
}

/// Compiles one read-only orientation of `snapshot` for `request`.
///
/// Supported views are `pulse`, `brief`, and `epistemic_map`. Every published event is ranked by
/// consequence; the view carries the per-event cells of its top-ranked events (and of every event
/// with contradicting evidence or open tamper) inline, summarizes the rest, and aggregates every
/// per-event world into one world per kind that keeps the kind's maximum severity and protection.
/// The compression receipt keeps priced event or exact-anchor inventory expansion paths.
/// Critical context (protected worlds, epistemic boundaries, risks, obligations, next and
/// blocked affordances) is
/// never truncated: if it does not fit the admitted budget the orientation is refused with
/// [`OrientError::ContextBudgetExceeded`].
pub fn orient_deployment(
    snapshot: &DeploymentSnapshot,
    request: &OrientRequest,
    limits: &OrientLimits,
) -> Result<DeploymentOrientation, OrientError> {
    orient_deployment_for(snapshot, request, limits, None)
}

/// [`orient_deployment`] with the capsule bound to a durable session and mission instead of the
/// deterministic read-only identity; everything else is compiled identically.
pub fn orient_deployment_for(
    snapshot: &DeploymentSnapshot,
    request: &OrientRequest,
    limits: &OrientLimits,
    session: Option<&OrientSessionBinding>,
) -> Result<DeploymentOrientation, OrientError> {
    orient_deployment_for_with_advisories(
        snapshot,
        request,
        limits,
        session,
        session.and_then(|binding| binding.trauma_warnings.as_deref()),
        &[],
        ProjectionPurpose::Orientation,
    )
}

/// Compiles a stateless orientation with already verified, principal-projected advisory history.
///
/// The caller admits the publication reads and projects them to `request.principal` before this
/// pure compiler is invoked. Advisory warnings enter the canonical capsule, protected context,
/// fingerprint and compression receipt before sealing. `None` explicitly means unavailable.
pub fn orient_deployment_with_advisories(
    snapshot: &DeploymentSnapshot,
    request: &OrientRequest,
    limits: &OrientLimits,
    advisory_warnings: Option<&[AntiPatternWarning]>,
) -> Result<DeploymentOrientation, OrientError> {
    orient_deployment_for_with_advisories(
        snapshot,
        request,
        limits,
        None,
        advisory_warnings,
        &[],
        ProjectionPurpose::Orientation,
    )
}

/// Native admitted session snapshots preserve rebase warnings in mandatory context.
pub(crate) fn orient_deployment_for_workspace(
    snapshot: &DeploymentSnapshot,
    request: &OrientRequest,
    limits: &OrientLimits,
    session: &OrientSessionBinding,
    workspace_invalidations: &[String],
) -> Result<DeploymentOrientation, OrientError> {
    orient_deployment_for_with_advisories(
        snapshot,
        request,
        limits,
        Some(session),
        session.trauma_warnings.as_deref(),
        workspace_invalidations,
        ProjectionPurpose::AdmittedWorkspace,
    )
}

/// AOP-006's authenticated selected probe view uses its additive basis only for this reply.
/// The session, retained workspace, cases, native subscription and every ordinary view keep their
/// original exact contract basis; this is neither a session migration nor a grant expansion.
pub(crate) fn orient_deployment_for_probe(
    snapshot: &DeploymentSnapshot,
    request: &OrientRequest,
    limits: &OrientLimits,
    session: &OrientSessionBinding,
    workspace_invalidations: &[String],
) -> Result<DeploymentOrientation, OrientError> {
    if !matches!(request.view, AgentView::Case | AgentView::Forensic) {
        return Err(OrientError::UnsupportedView(request.view));
    }
    orient_deployment_for_with_advisories(
        snapshot,
        request,
        limits,
        Some(session),
        session.trauma_warnings.as_deref(),
        workspace_invalidations,
        ProjectionPurpose::AdmittedProbe,
    )
}

fn orient_deployment_for_with_advisories(
    snapshot: &DeploymentSnapshot,
    request: &OrientRequest,
    limits: &OrientLimits,
    session: Option<&OrientSessionBinding>,
    advisory_warnings: Option<&[AntiPatternWarning]>,
    workspace_invalidations: &[String],
    purpose: ProjectionPurpose,
) -> Result<DeploymentOrientation, OrientError> {
    if !matches!(
        request.view,
        AgentView::Pulse | AgentView::Brief | AgentView::EpistemicMap
    ) && !(session.is_some()
        && match purpose {
            ProjectionPurpose::AdmittedWorkspace => request.view == AgentView::Case,
            ProjectionPurpose::AdmittedProbe => {
                matches!(request.view, AgentView::Case | AgentView::Forensic)
            }
            ProjectionPurpose::Orientation => false,
        })
    {
        return Err(OrientError::UnsupportedView(request.view));
    }
    if snapshot.events.len() > limits.max_events.min(MAX_DEPLOYMENT_EVENTS) {
        return Err(OrientError::TooManyEvents {
            published: snapshot.events.len(),
            maximum: limits.max_events.min(MAX_DEPLOYMENT_EVENTS),
        });
    }
    let cases = session.map_or(&[][..], |binding| binding.cases.as_slice());
    let plans = session.map_or(&[][..], |binding| binding.plans.as_slice());
    let claims = session.map_or(&[][..], |binding| binding.claims.as_slice());
    let findings = session.map_or(&[][..], |binding| binding.findings.as_slice());
    let mut compiled = compile_capsule(
        snapshot,
        request,
        session,
        advisory_warnings,
        workspace_invalidations,
        purpose,
    )?;
    if let Some(binding) = session {
        compiled.capsule.mission_id = binding.mission_id.clone();
        compiled.capsule.session_id = binding.session_id.clone();
        compiled
            .degradation
            .retain(|line| line != UNBOUND_SESSION_DEGRADATION);
    }
    let mut degradation = compiled.degradation;
    let mut situation = ReferenceSituation::new(compiled.capsule, compiled.proof_roots);
    if !compiled.effect_cells.is_empty() {
        // Each effect cell was compiled from its exact journal receipt; binding it and sealing the
        // finished capsule keeps it from being dropped, duplicated, or relabeled (fss-6sph6).
        for (operation_id, state, cell) in &compiled.effect_cells {
            situation.bind_effect_cell(EffectCellKind::LocalState, operation_id, *state, cell)?;
        }
        situation.seal_effect_bindings()?;
    }
    let target = u64::from(request.view.target_tokens());
    let maximum = u64::from(request.view.maximum_tokens());
    let project = |situation: ReferenceSituation, tokens: u64, degraded: bool| {
        project_reference_situation_with_source_omissions(
            situation,
            &projection_spec(request.view, tokens, degraded)?,
            &compiled.source,
        )
    };
    let (publication, target_tokens) = match request.budget_tokens {
        Some(tokens) => match project(situation, tokens, false) {
            Ok(publication) => (publication, tokens),
            Err(error) if is_budget_refusal(&error) => {
                return Err(OrientError::ContextBudgetExceeded {
                    view: request.view,
                    budget_tokens: tokens,
                });
            }
            Err(error) => return Err(error.into()),
        },
        None => match project(situation.clone(), target, false) {
            Ok(publication) => (publication, target),
            Err(error) if is_budget_refusal(&error) => match project(situation, maximum, true) {
                Ok(publication) => {
                    degradation.push(format!(
                        "The critical context exceeds the {} target of {target} tokens; it \
                         was admitted at the registered maximum of {maximum} tokens.",
                        request.view.name()
                    ));
                    (publication, maximum)
                }
                Err(error) if is_budget_refusal(&error) => {
                    return Err(OrientError::ContextBudgetExceeded {
                        view: request.view,
                        budget_tokens: maximum,
                    });
                }
                Err(error) => return Err(error.into()),
            },
            Err(error) => return Err(error.into()),
        },
    };
    let capsule = &publication.situation.capsule;
    let projection = orient_projection(capsule, orient_budget(request.view)?)?;
    let requested = BudgetVector::builder()
        .tokens(target_tokens)
        .build()
        .map_err(|_| ContractError::BudgetExhausted)?;
    let consumed = BudgetVector::builder()
        .tokens(publication.context_pack.token_count)
        .bytes(snapshot.bytes_read)
        .storage_operations(snapshot.files_read)
        .build()
        .map_err(|_| ContractError::BudgetExhausted)?;
    degradation.push(
        "Latency and CPU time are not metered by this reference path; consumed reports reads and \
         context tokens only."
            .to_owned(),
    );
    let summarized = compiled
        .hydration
        .iter()
        .filter(|slot| !slot.cells_inline)
        .count();
    if !compiled.hydration.is_empty() {
        let expansion = if compiled.hydration.len() > DIRECT_EVENT_EXPANSION_LIMIT {
            "the receipted exact-anchor metadata inventory enumerates every event, and separate \
             explanations must match that inventory anchor"
        } else {
            "each event hydrates through its receipted handle"
        };
        degradation.push(format!(
            "{} per-event worlds are aggregated into class worlds and {summarized} of {} events \
             are summarized; {expansion}.",
            compiled.aggregated_world_count,
            compiled.hydration.len()
        ));
    }
    let open_obligations = capsule.obligations.clone();
    let mut indeterminate_effects: Vec<OperationId> = snapshot
        .indeterminate_operations()
        .iter()
        .map(|operation| operation.intent.operation_id.clone())
        .collect();
    indeterminate_effects.sort();
    let request_digest = request.digest_at(&snapshot.anchor);
    let objective = orientation_objective(
        snapshot,
        request,
        capsule,
        request_digest,
        requested,
        compiled.coverage.as_ref(),
        session,
    )?;
    Ok(DeploymentOrientation {
        mission_progress: session.and_then(|binding| binding.mission_progress.clone()),
        view: request.view,
        projection,
        target_tokens,
        open_obligations,
        indeterminate_effects,
        degradation,
        warnings: compiled.warnings,
        contradictions: compiled.contradictions,
        epistemic_state: compiled.epistemic_state,
        requested,
        consumed,
        request_digest,
        objective,
        attention: compiled.attention,
        epistemic_debt: compiled.epistemic_debt,
        validity: orientation_validity(snapshot),
        hydration: compiled.hydration,
        headline_event: compiled.headline_event,
        candidate_world_count: compiled.candidate_world_count,
        aggregated_world_count: compiled.aggregated_world_count,
        privacy_generation_id: format!("privacy-epoch:{}", snapshot.anchor.privacy_epoch),
        latest_deletion_closure_id: snapshot
            .deletions
            .entries()
            .last()
            .map(|entry| entry.plan_digest.to_text()),
        anchor_token: compiled.anchor_token,
        coverage: compiled.coverage,
        active_investigations: cases.iter().map(|case| case.case_id.clone()).collect(),
        active_plans: plans.iter().map(|plan| plan.plan_id.clone()).collect(),
        active_claims: claims.iter().map(|claim| claim.claim_id.clone()).collect(),
        active_findings: findings
            .iter()
            .map(|finding| finding.finding_id.clone())
            .collect(),
        supervision_inventory: session
            .and_then(|binding| binding.supervisions.as_deref())
            .map(|entries| supervision::inventory_at(entries, &snapshot.anchor))
            .unwrap_or_default(),
        supervision_inventory_available: session
            .is_some_and(|binding| binding.supervisions.is_some()),
        publication,
    })
}
