#![forbid(unsafe_code)]
//! Execution of `fss orient` (stateless read-only and durable-session-bound AOP-003).

use fss_core::{
    AgentView, BudgetVector, CanonicalEncode, CanonicalEncoder, Completeness, ContentDigest,
    ContractBasisError, ExecutionBoundary, KnowledgeState, PrincipalId, ResponseOutcome,
    ResponseSafeRetry, SessionId,
};
use fss_reference::agent_orient::{
    CAPABILITY_SITUATION_READ, DeploymentOrientation, DeploymentSnapshot, OrientError,
    OrientLimits, OrientRequest, orient_deployment_with_advisories,
};

use super::args::{ERR_AGENT_CONTEXT_INCOMPLETE, OrientArgs};
use super::capsule_json::{CapsuleOverrides, contexts, orient_payload, situation_capsule_payload};
use super::diagnostics::{
    RenderError, internal_failure_with_detail, read_only_boundary, read_refusal, rendered,
};
use super::history;
use super::response::{ResponseParts, build_response};
use crate::agent_json;
use crate::error::ExitIdentity;

fn orient_response(
    orientation: &DeploymentOrientation,
    session: Option<&fss_reference::deployment_session::orient::OrientedSession>,
) -> Result<String, Box<dyn std::error::Error>> {
    let capsule = orientation.capsule();
    let publication = &orientation.publication;
    let mut proof_pointers: Vec<String> = orientation
        .proof_roots()
        .iter()
        .map(|root| root.to_text())
        .collect();
    proof_pointers.push(publication.publication_digest.to_text());
    proof_pointers.push(orientation.projection.projection_digest().to_text());
    // The reusable anchor token of the committed position this answer is pinned to: the
    // `--since` argument of `fss follow`.
    proof_pointers.push(orientation.anchor_token.clone());
    let (_, affordance_context) = contexts(orientation);
    let affordance_objects = agent_json::affordance_objects(
        &capsule.frame.next,
        &capsule.affordances,
        &affordance_context,
    )
    .ok_or(RenderError("next affordance objects"))?;
    let mut degradation = orientation.degradation.clone();
    let mut warnings = orientation.warnings.clone();
    let (payload_json, boundary) = if let Some(read) = session {
        if let Some(progress) = &orientation.mission_progress {
            // Match mission-bind/mission-assess: callers can recover an exact retained
            // predecessor even when it is historical or still at enrollment revision zero.
            let mission_head = progress.revision.digest().to_text();
            proof_pointers.retain(|pointer| pointer != &mission_head);
            proof_pointers.insert(0, mission_head);
        }
        proof_pointers.push(read.revision.digest().to_text());
        proof_pointers.push(read.journal_root.to_text());
        let workspace = read.revision.capsule();
        let extra_debt = if read.anchor_moved {
            workspace.assumptions.iter().map(|entry| {
                agent_json::workspace_debt_item(entry, &format!(
                    "The retained workspace remains at {}; the read-only situation is at {}. Explicit rebase is required before reusing anchor-bound assumptions or actions.",
                    read.workspace_anchor_token, orientation.anchor_token,
                ))
            }).collect()
        } else {
            Vec::new()
        };
        if read.anchor_moved {
            warnings.push(format!(
                "The deployment position moved beyond the retained workspace ({} -> {}); {} assumption(s) are invalidated. This read did not rebase the workspace, renew its lease, or authorize any action.",
                read.workspace_anchor_token, orientation.anchor_token, read.invalidated.len(),
            ));
        }
        if read.runtime_time {
            degradation.push(format!(
                "Session workspace snapshot: workspace revision {} and its original anchor remain unchanged. Runtime clock admission is durably pinned; previousAnchor identifies the retained workspace and meaningfulDelta is null because historical session state was not reconstructed.",
                workspace.revision,
            ));
            degradation.push(format!(
                "The session lease expires at admitted runtime time {} ns; this read does not extend it or consume its durable token budget.",
                read.session.expires_at_ns,
            ));
        } else {
            degradation.push(format!(
                "Read-only session snapshot: workspace revision {} and its original anchor remain unchanged. previousAnchor identifies that retained workspace; meaningfulDelta is null because historical session state was not reconstructed.",
                workspace.revision,
            ));
            degradation.push(format!(
                "The session lease expires at evidence time {} ns; this read does not extend it or consume its durable token budget.",
                read.session.expires_at_ns,
            ));
        }
        let payload = situation_capsule_payload(
            orientation,
            &CapsuleOverrides {
                previous_anchor: Some(&workspace.current_anchor),
                meaningful_delta: None,
                extra_debt,
                symbol_table_generation: read.session.symbol_table_generation,
            },
        )?;
        let boundary = ExecutionBoundary {
            completed: vec![format!(
                "Read session {} and authenticated workspace revision {} at session journal root {}; compiled the current {} situation at commit {}.",
                read.session.session_id.as_str(), workspace.revision, read.journal_root,
                orientation.view.name(), capsule.anchor.commit_sequence,
            )],
            not_started: vec![
                "Every listed affordance, effect, workspace rebase, lease renewal, and durable budget mutation.".to_owned(),
            ],
            possibly_occurred: Vec::new(),
            preserved_truth: vec![
                if read.runtime_time {
                    "Runtime time was admitted and pinned in the session journal. Evidence, effects, workspace, grants and cumulative token spend were unchanged.".to_owned()
                } else {
                    "Existing deployment and session files were read under a temporary journal lock; no file was created, written, or repaired.".to_owned()
                },
            ],
            invalidated: read.invalidated.clone(),
        };
        (payload, boundary)
    } else {
        degradation.push(
            "No previous anchor was supplied: meaningfulDelta is null and no change is claimed."
                .to_owned(),
        );
        (
            orient_payload(orientation)?,
            read_only_boundary(format!(
                "Compiled the {} situation at commit {}.",
                orientation.view.name(),
                capsule.anchor.commit_sequence,
            )),
        )
    };
    build_response(ResponseParts {
        operation: "session.orient",
        request_digest: session.map_or(orientation.request_digest, |read| read.request_digest),
        principal: capsule.principal_id.clone(),
        session_id: Some(capsule.session_id.as_str().to_owned()),
        mission_id: Some(capsule.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view: orientation.view,
        capability: CAPABILITY_SITUATION_READ,
        outcome: ResponseOutcome::Ok,
        error_id: None,
        payload_schema: "fss.situation_capsule.v1",
        payload_json,
        epistemic_state: orientation.epistemic_state,
        completeness: capsule.completeness,
        warnings,
        contradictions: orientation.contradictions.clone(),
        degradation,
        budgets_json: agent_json::budget_summary(&orientation.requested, &orientation.consumed),
        proof_pointers,
        affordances: capsule.frame.next.clone(),
        affordance_objects,
        decision_fingerprint: capsule.decision_fingerprint()?,
        compression_receipt_id: Some(publication.compression_receipt.receipt_id.clone()),
        continuation: publication.context_pack.continuation.clone(),
        recovery_class: "safe_read_retry",
        safe_retry: ResponseSafeRetry::YesSameRequest,
        boundary,
        created_at_ns: capsule.created_at.0,
        workspace_revision: session.map(|read| read.revision.capsule().revision),
        idempotency_key: None,
    })
}

pub(crate) fn budget_refusal(
    snapshot: &DeploymentSnapshot,
    request_digest: ContentDigest,
    view: AgentView,
    principal: &PrincipalId,
    budget_tokens: u64,
    reason: String,
) -> Result<String, Box<dyn std::error::Error>> {
    let requested = BudgetVector::builder()
        .tokens(budget_tokens)
        .build()
        .map_err(|_| ContractBasisError::Contract(fss_core::ContractError::BudgetExhausted))?;
    build_response(ResponseParts {
        operation: "session.orient",
        request_digest,
        principal: principal.clone(),
        session_id: None,
        mission_id: None,
        anchor: snapshot.anchor.clone(),
        view,
        capability: CAPABILITY_SITUATION_READ,
        outcome: ResponseOutcome::Refused,
        error_id: Some(ERR_AGENT_CONTEXT_INCOMPLETE),
        payload_schema: "fss.situation_capsule.v1",
        payload_json: "null".to_owned(),
        epistemic_state: KnowledgeState::Unknown,
        completeness: Completeness::Partial,
        warnings: Vec::new(),
        contradictions: Vec::new(),
        degradation: vec![
            reason,
            "Critical context is never truncated; request --view brief or --view epistemic_map, \
             or a larger --budget-tokens up to the view maximum."
                .to_owned(),
        ],
        budgets_json: agent_json::budget_summary(&requested, &BudgetVector::ZERO),
        proof_pointers: vec![snapshot.anchor.state_root.to_text()],
        affordances: Vec::new(),
        affordance_objects: Vec::new(),
        decision_fingerprint: request_digest,
        compression_receipt_id: None,
        continuation: None,
        recovery_class: "never_unchanged",
        safe_retry: ResponseSafeRetry::No,
        boundary: read_only_boundary(format!(
            "Read the deployment at commit {}; no situation was published.",
            snapshot.anchor.commit_sequence
        )),
        created_at_ns: snapshot.latest_evidence_time.0,
        workspace_revision: None,
        idempotency_key: None,
    })
}

/// Executes `orient`, returning the rendered response and its exit identity.
#[must_use]
pub fn execute_orient(args: &OrientArgs) -> (String, ExitIdentity) {
    execute_orient_with_time(args, None)
}

pub(crate) fn execute_orient_with_time(
    args: &OrientArgs,
    clock: crate::session_time::Clock<'_>,
) -> (String, ExitIdentity) {
    execute_orient_with_control(args, clock, &crate::RequestControl::uncancelled())
}

/// Keep unsessioned reads under their request owner's cooperative cancellation.
/// Bound-session writes retain their existing clock, durable owner and outcome semantics.
pub(crate) fn execute_orient_with_control(
    args: &OrientArgs,
    clock: crate::session_time::Clock<'_>,
    control: &crate::RequestControl<'_>,
) -> (String, ExitIdentity) {
    if let Some(session_id) = &args.session {
        return execute_session_orient(args, session_id, clock);
    }
    if control.is_cancelled() {
        return crate::request_control::cancelled_read("orient", &args.root);
    }
    let limits = OrientLimits::default();
    let (snapshot, _) =
        match history::read_with_control("orient", &args.root, &limits, None, control) {
            Ok(snapshot) => snapshot,
            Err(refusal) => return refusal,
        };
    let request = OrientRequest {
        view: args.view,
        principal: args.principal.clone(),
        budget_tokens: args.budget_tokens,
    };
    let request_digest = request.digest_at(&snapshot.anchor);
    let cancelled = || {
        crate::request_control::cancelled_snapshot_read(
            crate::request_control::CancelledRead {
                command: "orient",
                operation: "session.orient",
                root: &args.root,
                request_digest,
                principal: &args.principal,
                view: args.view,
                capability: CAPABILITY_SITUATION_READ,
                payload_schema: "fss.situation_capsule.v1",
            },
            &snapshot,
        )
    };
    if control.is_cancelled() {
        return cancelled();
    }
    let trauma_result =
        fss_reference::deployment_session::trauma_guard::derive_trauma_guard_warnings(
            &args.root,
            &args.principal,
            snapshot.latest_evidence_time.0.max(0),
        );
    if control.is_cancelled() {
        return cancelled();
    }
    let trauma_warnings = match trauma_result {
        Ok(warnings) => warnings,
        Err(error) => {
            let operation = crate::session_cmd::Operation {
                command: "orient",
                name: "session.orient",
                capability: CAPABILITY_SITUATION_READ,
                payload_schema: "fss.situation_capsule.v1",
                view: args.view,
                root: args.root.clone(),
                principal: args.principal.clone(),
                request: request_digest.to_text().into_bytes(),
            };
            // Preserve the native refusal without reopening history after this read's
            // snapshot. In particular, cancellation rendering never seeks another anchor.
            let response = match error {
                fss_reference::deployment_session::DeploymentSessionError::Time(
                    fss_reference::deployment_session::SessionTimeError::Cancelled,
                ) => return cancelled(),
                fss_reference::deployment_session::DeploymentSessionError::Read(error) => {
                    read_refusal("orient", &args.root, &error)
                }
                other => match crate::session_cmd::classify(other) {
                    Ok(refusal) => rendered(
                        crate::session_cmd::refusal_response(
                            &operation,
                            &snapshot.anchor,
                            snapshot.latest_evidence_time.0,
                            refusal,
                            None,
                        ),
                        ExitIdentity::AGENT_REFUSED,
                        "orient",
                        &args.root,
                    ),
                    Err(unclassified) => internal_failure_with_detail(
                        "orient",
                        &args.root,
                        &format!("unclassified session error: {unclassified}"),
                    ),
                },
            };
            return if control.is_cancelled() {
                cancelled()
            } else {
                response
            };
        }
    };
    let orientation =
        orient_deployment_with_advisories(&snapshot, &request, &limits, Some(&trauma_warnings));
    if control.is_cancelled() {
        return cancelled();
    }
    let response = match orientation {
        Ok(orientation) => rendered(
            orient_response(&orientation, None),
            ExitIdentity::SUCCESS,
            "orient",
            &args.root,
        ),
        Err(error @ OrientError::ContextBudgetExceeded { budget_tokens, .. }) => rendered(
            budget_refusal(
                &snapshot,
                request_digest,
                args.view,
                &args.principal,
                budget_tokens,
                error.to_string(),
            ),
            ExitIdentity::AGENT_REFUSED,
            "orient",
            &args.root,
        ),
        Err(error @ OrientError::TooManyEvents { .. }) => rendered(
            budget_refusal(
                &snapshot,
                request_digest,
                args.view,
                &args.principal,
                args.budget_tokens
                    .unwrap_or_else(|| u64::from(args.view.maximum_tokens())),
                error.to_string(),
            ),
            ExitIdentity::AGENT_REFUSED,
            "orient",
            &args.root,
        ),
        Err(error @ (OrientError::UnsupportedView(_) | OrientError::Contract(_))) => {
            internal_failure_with_detail("orient", &args.root, &error.to_string())
        }
    };
    if control.is_cancelled() {
        return cancelled();
    }
    response
}

/// Refuse a complete bound-session projection that cannot fit its registered wire fields.
/// Context selection has already preserved the native critical context; these additive
/// workspace fields must also fit without truncating old assumptions or invalidations.
fn session_orient_wire_refusal(
    read: &fss_reference::deployment_session::orient::OrientedSession,
) -> Option<String> {
    // schemas/situation_capsule.v1.json: epistemicDebt.maxItems = 1024.
    let assumptions = &read.revision.capsule().assumptions;
    let additional_debt = if read.anchor_moved {
        assumptions.len()
    } else {
        0
    };
    let combined_debt = read
        .orientation
        .epistemic_debt
        .len()
        .saturating_add(additional_debt);
    if combined_debt > 1024 {
        return Some(format!(
            "The complete session orientation requires {combined_debt} epistemic-debt items; \
             the registered situation capsule admits at most 1024. Retained assumptions \
             cannot be silently omitted."
        ));
    }
    // Match workspace_debt_item's exact ID extraction. The registered debtId is nonempty
    // and at most 256 Unicode characters. Its assumption/deferredReason fields have no
    // schema length ceiling, so do not invent one here. Rust chars match JSON code points.
    if read.anchor_moved
        && assumptions.iter().any(|entry| {
            let (debt_id, _) = entry.split_once(": ").unwrap_or((entry, entry));
            debt_id.is_empty() || debt_id.chars().count() > 256
        })
    {
        return Some(
            "A retained assumption cannot be represented by the registered epistemic-debt \
             identity limit of 1..256 characters. Its identity cannot be truncated."
                .to_owned(),
        );
    }
    // schemas/agent_response_envelope.v1.json: executionBoundary.invalidated admits at
    // most 256 nonempty strings, each at most 1024 Unicode characters.
    if read.invalidated.len() > 256 {
        return Some(format!(
            "The complete session orientation requires {} invalidation entries; the \
             registered execution boundary admits at most 256. Invalidations cannot \
             be silently omitted.",
            read.invalidated.len(),
        ));
    }
    if read
        .invalidated
        .iter()
        .any(|entry| entry.is_empty() || entry.chars().count() > 1024)
    {
        return Some(
            "An invalidation cannot fit the registered execution boundary's nonempty \
             1024-character entry limit. Its statement cannot be truncated."
                .to_owned(),
        );
    }
    None
}

fn session_orient_operation(
    args: &OrientArgs,
    session_id: &SessionId,
) -> crate::session_cmd::Operation {
    let mut request_bytes = CanonicalEncoder::new();
    session_id.encode_canonical(&mut request_bytes);
    request_bytes.text(args.view.name());
    request_bytes.bool(args.budget_tokens.is_some());
    if let Some(tokens) = args.budget_tokens {
        request_bytes.u64(tokens);
    }
    crate::session_cmd::Operation {
        command: "orient",
        name: "session.orient",
        capability: CAPABILITY_SITUATION_READ,
        payload_schema: "fss.situation_capsule.v1",
        view: args.view,
        root: args.root.clone(),
        principal: args.principal.clone(),
        request: request_bytes.finish(),
    }
}

/// A current situation for one authenticated durable session, after any runtime clock admission.
fn execute_session_orient(
    args: &OrientArgs,
    session_id: &SessionId,
    clock: crate::session_time::Clock<'_>,
) -> (String, ExitIdentity) {
    use fss_reference::deployment_session::orient::{OrientSessionRequest, orient_session};

    let request = OrientSessionRequest {
        session_id: session_id.clone(),
        principal: args.principal.clone(),
        view: args.view,
        budget_tokens: args.budget_tokens,
    };
    let operation = session_orient_operation(args, session_id);
    match orient_session(crate::session_time::context(&args.root, clock), &request) {
        Ok(read) => {
            if let Some(reason) = session_orient_wire_refusal(&read) {
                return crate::session_cmd::refuse_typed_with_boundary(
                    &operation,
                    crate::session_cmd::Refusal {
                        error_id: ERR_AGENT_CONTEXT_INCOMPLETE,
                        reason,
                        guidance: "The complete view exceeds a registered continuity bound. Preserve the original workspace and explicitly create a bounded successor before retrying; this read neither truncates context nor rewrites the workspace.",
                        recovery_class: "never_unchanged",
                        safe_retry: ResponseSafeRetry::No,
                    },
                    ExitIdentity::AGENT_REFUSED,
                    Some(ExecutionBoundary {
                        completed: vec!["Authenticated the current session snapshot; its complete response exceeds registered wire bounds.".to_owned()],
                        not_started: vec!["Situation response delivery and every listed action.".to_owned()],
                        possibly_occurred: Vec::new(),
                        preserved_truth: vec![if clock.is_some() {
                            "Session clock admission was persisted; evidence, effects, workspace, lease and durable budget remain unchanged.".to_owned()
                        } else {
                            "No deployment or session file was created, written or repaired; workspace, lease and durable budget remain unchanged.".to_owned()
                        }],
                        invalidated: Vec::new(),
                    }),
                );
            }
            rendered(
                orient_response(&read.orientation, Some(&read)),
                ExitIdentity::SUCCESS,
                "orient",
                &args.root,
            )
        }
        Err(error) => crate::session_cmd::refuse(&operation, error),
    }
}
