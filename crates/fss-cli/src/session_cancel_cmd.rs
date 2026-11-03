#![forbid(unsafe_code)]
//! AOP-010 `cancel --session`: exact local owner approval revokes future session authority.
//! The registered cognitive envelope reports the session tombstone and preserved obligations;
//! it never fabricates an external-effect receipt or grants cancellation from a stored session.

use std::path::PathBuf;

use fss_core::{
    AgentCognitiveEnvelope, AgentView, BudgetVector, CognitiveAnswerClass, Completeness,
    ContentDigest, ContextAuthority, EnvelopeBudget, EnvelopeContinuity, EnvelopeCoverage,
    EnvelopeEpistemic, EnvelopeProposition, ExecutionBoundary, KnowledgeState, OperationId,
    PrincipalId, ResponseOutcome, ResponseSafeRetry, RootAuthoritySpec, SessionId,
};
use fss_reference::agent_orient::{DeploymentHistory, OrientLimits};
use fss_reference::deployment_session::cancellation::{
    CAP_SESSION_CANCEL, SessionCancellation, SessionCancellationError, SessionCancellationOutcome,
    cancel_session,
};

use crate::agent_json;
use crate::error::{CliError, ExitIdentity};
use crate::orient_cmd::{
    RenderError, ResponseParts, build_response, collect_options, internal_failure, principal,
    read_refusal, rendered, required_root, take,
};
use crate::session_cmd::{
    ERR_AUTH_DENIED, ERR_PRECONDITION_STALE, Operation, Refusal, refuse, refuse_typed,
    refuse_typed_with_boundary,
};
use crate::token::ArgToken;

/// Exact session revocation request; target selection is exclusive with alert cancellation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionCancelArgs {
    /// Existing owner-controlled deployment.
    pub root: PathBuf,
    /// Retained session identity.
    pub session: SessionId,
    /// Current local owner identity, matched to the retained session principal.
    pub principal: PrincipalId,
    /// Exact preview approval; absence performs only bounded inspection.
    pub approve: Option<ContentDigest>,
}

/// Select the explicit session target before applying the strict target-specific grammar.
#[must_use]
pub fn selects_session(tokens: &[ArgToken]) -> bool {
    tokens
        .iter()
        .skip(1)
        .any(|token| token.as_str() == "--session" || token.as_str().starts_with("--session="))
}

/// Parse the existing AOP-010 operation's session target without accepting mixed effect scope.
pub fn parse_session_cancel_args(tokens: &[ArgToken]) -> Result<SessionCancelArgs, CliError> {
    let values = collect_options(
        "cancel",
        tokens,
        &["--root", "--session", "--principal", "--approve"],
    )?;
    let (_, value, index) = take(&values, "--session").ok_or_else(|| CliError::MissingValue {
        option: "--session".into(),
        command: Some("cancel".into()),
        expected: "the exact session identity".into(),
    })?;
    let malformed = |option: &str, value: &str, reason: &str, index| CliError::MalformedValue {
        option: option.into(),
        value: value.into(),
        reason: reason.into(),
        command: Some("cancel".into()),
        index,
    };
    let session = SessionId::parse(value.clone()).map_err(|_| {
        malformed(
            "--session",
            value,
            "expected a bounded session identity",
            *index,
        )
    })?;
    let approve = take(&values, "--approve")
        .map(|(_, value, index)| {
            ContentDigest::parse(value).map_err(|_| {
                malformed(
                    "--approve",
                    value,
                    "expected the exact SHA-256 preview approval",
                    *index,
                )
            })
        })
        .transpose()?;
    if approve.is_some_and(|digest| {
        digest.algorithm() != fss_core::DigestAlgorithm::Sha256 || digest.is_laboratory()
    }) {
        let (_, value, index) =
            take(&values, "--approve").ok_or_else(|| CliError::MissingValue {
                option: "--approve".into(),
                command: Some("cancel".into()),
                expected: "SHA-256 approval".into(),
            })?;
        return Err(malformed(
            "--approve",
            value,
            "expected the exact SHA-256 preview approval",
            *index,
        ));
    }
    Ok(SessionCancelArgs {
        root: required_root("cancel", &values)?,
        session,
        principal: principal("cancel", &values)?,
        approve,
    })
}

fn boundary(completed: String, proposed: bool) -> ExecutionBoundary {
    ExecutionBoundary {
        completed: vec![completed],
        not_started: if proposed { vec!["Session revocation awaits the exact owner approval.".into()] } else { Vec::new() },
        possibly_occurred: Vec::new(),
        preserved_truth: vec![
            "Authority ledger, effect journal, source custody, plans and work progress are unchanged. Session cancellation does not prove delivery, cancel a dispatched effect, settle an obligation or complete a mission.".into(),
            "Live claim leases are preserved; an admitted same-mission session may explicitly reclaim a closed owner's work under the exact claim revision and a new fencing incarnation.".into(),
        ],
        invalidated: if proposed { Vec::new() } else { vec!["The cancelled session's aliases and future session-authorized operations are revoked. Old handoffs cannot reopen it.".into()] },
    }
}

fn response(answer: &SessionCancellation) -> Result<String, Box<dyn std::error::Error>> {
    let plan = &answer.plan;
    let approval = plan.approval_digest()?;
    let proposed = answer.outcome == SessionCancellationOutcome::Proposed;
    let status = match answer.outcome {
        SessionCancellationOutcome::Proposed => "proposed",
        SessionCancellationOutcome::Cancelled => "cancelled",
        SessionCancellationOutcome::AlreadyCancelled => "already_cancelled",
    };
    let completed = format!(
        "Session {} authority {status}; exact approval {approval}.",
        plan.session_id
    );
    let mut propositions = vec![EnvelopeProposition {
        id: "session-cancellation:authority".into(),
        statement: if proposed {
            format!(
                "{completed} Approving this exact request revokes future session use, clears aliases and preserves a durable tombstone. Nothing has been revoked by this preview."
            )
        } else {
            format!(
                "{completed} The original approval and authority-revocation tombstone share one committed session-journal record. No session budget or lease was refilled."
            )
        },
        state: KnowledgeState::Known,
        provenance: "derived".into(),
        evidence: vec![approval.to_text(), plan.journal_root.to_text()],
    }];
    propositions.push(EnvelopeProposition {
        id: "session-cancellation:external-obligations".into(),
        statement: format!("At the original approval position, {} outstanding obligations and {} active mission plans remain retained. Their terminal outcomes are not established by session revocation. Exact retries preserve this historical inventory; inspect each operation for its current state.", plan.unresolved_obligations.len(), plan.retained_plans.len()),
        state: KnowledgeState::Known, provenance: "derived".into(),
        evidence: vec![plan.effect_root.to_text(), plan.authority_root.to_text()],
    });
    for plan_id in &plan.retained_plans {
        propositions.push(EnvelopeProposition {
            id: plan_id.clone(),
            statement: format!("Plan {plan_id} remains retained; its effect and any unresolved obligation require their own explicit lifecycle operation."),
            state: KnowledgeState::Known, provenance: "derived".into(), evidence: vec![approval.to_text()],
        });
    }
    let domain = format!("fss://session/{}/authority", plan.session_id);
    let mut proof_pointers = vec![
        format!("session-cancellation-approval:{approval}"),
        approval.to_text(),
        plan.journal_root.to_text(),
        plan.checkpoint_digest.to_text(),
        plan.authority_root.to_text(),
        plan.effect_root.to_text(),
        answer.workspace.digest().to_text(),
    ];
    if let Some(receipt) = &answer.receipt {
        proof_pointers.push(format!(
            "session-cancellation-receipt:{}",
            receipt.journal_root
        ));
        proof_pointers.push(receipt.journal_root.to_text());
        proof_pointers.push(receipt.checkpoint_digest.to_text());
    }
    let payload = AgentCognitiveEnvelope::new(
        fss_core::reference_contract_basis(), format!("request:cancel:{approval}"),
        format!("response:cancel:{approval}"), format!("trace:cancel:{approval}"),
        "cancel", "cancel", AgentView::Operation.id(), CognitiveAnswerClass::EffectStatus,
        plan.basis_anchor.clone(),
        EnvelopeEpistemic { propositions, assumptions: Vec::new(), invalidators: vec!["Later operation and plan transitions may change the retained historical obligation inventory.".into()] },
        EnvelopeCoverage { authorized_domain: vec![domain.clone()], observed_domain: vec![domain],
            not_observable_domain: vec!["external-delivery-and-physical-event-truth".into()],
            omitted_count: 0, omission_reasons: Vec::new(), stop_reason: "complete".into() },
        EnvelopeBudget { requested_json: agent_json::budget(&BudgetVector::ZERO),
            consumed_json: agent_json::budget(&BudgetVector::ZERO), remaining_json: agent_json::budget(&BudgetVector::ZERO),
            degraded_dimensions: vec!["bytes".into(), "storageOperations".into(), "cpuMillis".into()],
            marginal_work_declined: Vec::new() },
        Vec::new(), Vec::new(),
        EnvelopeContinuity { cursor: None, reanchor_triggers: vec!["A changed live preview requires a newly reviewed approval.".into()],
            session_capsule_digest: Some(answer.workspace.digest().to_text()), unresolved_obligations: plan.unresolved_obligations.clone() },
        approval.to_text(),
    )?;
    let payload_json = agent_json::cognitive_envelope(&payload, &[], &[]).ok_or(RenderError(
        "session cancellation cognitive payload refused",
    ))?;
    let mut degradation = vec![
        "Bounded native journal, pin and publication-custody verification is not fully metered in the budget fields; no zero-cost claim is made.".into(),
        "The owner-authorized local process supplies fresh CAP-AGENT-CANCEL-001; the principal label binds the retained owner and is not remote authentication.".into(),
    ];
    if proposed {
        degradation.push(format!("Approve exactly {approval} with `fss cancel --session {} --approve {approval}` on the same deployment and principal.", plan.session_id));
    }
    if answer.pin_repair_pending {
        degradation.push(if proposed {
            "The verified session journal extends its ROOT pin. This preview did not repair the pin; committing the exact approval pins the resulting cancellation record.".into()
        } else {
            "The verified session journal extends its ROOT pin. A committed cancellation remains effective; the exact approved retry repairs the pin without appending another cancellation.".into()
        });
    }
    build_response(ResponseParts {
        operation: "cancel",
        request_digest: approval,
        principal: plan.principal.clone(),
        session_id: Some(plan.session_id.as_str().into()),
        mission_id: Some(answer.session.mission_id.as_str().into()),
        anchor: plan.basis_anchor.clone(),
        view: AgentView::Operation,
        capability: CAP_SESSION_CANCEL,
        outcome: ResponseOutcome::Ok,
        error_id: None,
        payload_schema: AgentCognitiveEnvelope::SCHEMA,
        payload_json,
        epistemic_state: KnowledgeState::Known,
        completeness: Completeness::Complete,
        warnings: Vec::new(),
        contradictions: Vec::new(),
        degradation,
        budgets_json: agent_json::budget_summary(&BudgetVector::ZERO, &BudgetVector::ZERO),
        proof_pointers,
        affordances: Vec::new(),
        affordance_objects: Vec::new(),
        decision_fingerprint: approval,
        compression_receipt_id: None,
        continuation: None,
        recovery_class: if proposed {
            "operator_action_required"
        } else {
            "never_unchanged"
        },
        safe_retry: ResponseSafeRetry::YesSameRequest,
        boundary: boundary(completed, proposed),
        created_at_ns: plan.observed_at.0,
        workspace_revision: Some(answer.workspace.capsule().revision),
        idempotency_key: Some(format!("session-cancellation:{approval}")),
    })
}

/// Execute through the same native owner used by MCP, with a fresh local capability boundary.
#[must_use]
pub fn execute_session_cancel(args: &SessionCancelArgs) -> (String, ExitIdentity) {
    let operation = Operation {
        command: "cancel",
        name: "cancel",
        capability: CAP_SESSION_CANCEL,
        payload_schema: AgentCognitiveEnvelope::SCHEMA,
        view: AgentView::Operation,
        root: args.root.clone(),
        principal: args.principal.clone(),
        request: args.session.as_str().as_bytes().to_vec(),
    };
    let history = match DeploymentHistory::read(&args.root, &OrientLimits::default()) {
        Ok(history) => history,
        Err(error) => return read_refusal("cancel", &args.root, &error),
    };
    let authority = (|| -> Result<ContextAuthority, Box<dyn std::error::Error>> {
        Ok(ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:session-cancellation".into(),
            operation_id: OperationId::parse("operation:session-cancellation")?,
            principal: args.principal.as_str().into(),
            capabilities: vec![CAP_SESSION_CANCEL.into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(256 * 1024 * 1024)
                .storage_operations(8192)
                .build()?,
            privacy_scope: "privacy:local-authorized-files".into(),
            retention_scope: "retention:existing-deployment-policy".into(),
            anchor_universe: ContentDigest::sha256(history.site_lineage().as_bytes()),
            generation: 1,
        })?)
    })();
    let authority = match authority {
        Ok(authority) => authority,
        Err(_) => return internal_failure("cancel", &args.root),
    };
    match cancel_session(&args.root, &args.session, &authority, args.approve) {
        Ok(answer) => rendered(response(&answer), ExitIdentity::SUCCESS, "cancel", &args.root),
        Err(SessionCancellationError::Session(error)) => refuse(&operation, error),
        Err(SessionCancellationError::Unauthorized) => refuse_typed(&operation, Refusal {
            error_id: ERR_AUTH_DENIED, reason: "Fresh owner cancellation authority was refused.".into(),
            guidance: "Use the current owner-authorized local process and the retained session principal.",
            recovery_class: "operator_action_required", safe_retry: ResponseSafeRetry::No,
        }, ExitIdentity::AGENT_REFUSED),
        Err(SessionCancellationError::ApprovalMismatch) => refuse_typed(&operation, Refusal {
            error_id: ERR_PRECONDITION_STALE, reason: "The exact session cancellation approval differs from the retained or current request.".into(),
            guidance: "Read a fresh cancellation preview and review its complete scope before approving.",
            recovery_class: "operator_action_required", safe_retry: ResponseSafeRetry::No,
        }, ExitIdentity::AGENT_REFUSED),
        Err(SessionCancellationError::CommitUncertain) => {
            let mut execution = boundary("The approved session-journal append was attempted; its acknowledgement is unresolved.".into(), false);
            execution.possibly_occurred.push("The exact approved session revocation may already be durable. Reopen and repeat that approval to recover it; do not open replacement work until its state is known.".into());
            execution.invalidated.clear();
            refuse_typed_with_boundary(&operation, Refusal {
                error_id: crate::session_cmd::ERR_AGENT_SESSION_STORE_INVALID,
                reason: "Session revocation append acknowledgement is unresolved.".into(),
                guidance: "Retry the same exact approved request to recover its committed receipt; an incomplete journal tail requires explicit recovery.",
                recovery_class: "reconciliation_required", safe_retry: ResponseSafeRetry::YesSameRequest,
            }, ExitIdentity::AGENT_REFUSED, Some(execution))
        }
    }
}
