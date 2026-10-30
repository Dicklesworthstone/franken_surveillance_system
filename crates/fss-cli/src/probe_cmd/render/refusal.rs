#![forbid(unsafe_code)]
//! Bounded durable-progress disclosure when even a complete refusal context cannot be packaged.

use super::*;

#[cfg(test)]
mod tests;

/// Null payload explicitly withholds incomplete cognition. The existing outer partial contract
/// still preserves exact durable receipts, so a packaging failure cannot erase recovery custody.
pub(in crate::probe_cmd) fn progress_refusal(
    args: &ProbeArgs,
    context: &ProbeContext,
    delivery: Option<&SupervisionSessionDelivery>,
    charge: Option<&ProbeCharge>,
    failure: &ProbeFailure,
    case: Option<&CaseProjection<'_>>,
) -> Result<String> {
    let capsule = context.oriented.orientation.capsule();
    let mut completed = Vec::new();
    let mut proofs = vec![
        context.oriented.journal_root,
        context.ledger_root,
        context.effect_root,
    ];
    let historical = matches!(
        args.case.as_ref(),
        Some(fss_reference::deployment_session::probe::case::CaseProbeAction::InspectCitation(_))
    );
    if !historical && let Some(progress) = progress(args, context, delivery) {
        proofs.extend([progress.configuration, progress.state]);
        completed.push(format!("{} subscription state {}; configuration {}; lifetime attempts {}/{}; reserved bytes {}; indexed reads {}.", if delivery.is_some() { "Returned native" } else { "Last admitted pre-action" }, progress.state, progress.configuration, progress.attempts, progress.maximum, progress.bytes, progress.reads));
        if let Some(pending) = progress.pending {
            proofs.extend([
                pending.receipt,
                pending.report,
                pending.payload,
                pending.root,
            ]);
            completed.push(format!("Known pending receipt {}; report {}; payload {}; bytes {}; historical authority {}; cumulative windows {:?}. This metadata is not current source validation or an implicit ACK.", pending.receipt, pending.report, pending.payload, pending.bytes, pending.root, pending.windows));
        }
        for (label, receipt) in [
            ("last acknowledged", progress.last_ack),
            ("last discarded", progress.last_discard),
        ] {
            if let Some(receipt) = receipt {
                proofs.push(receipt);
                completed.push(format!(
                    "Exact returned/pre-action {label} receipt {receipt}."
                ));
            }
        }
    }
    for (label, receipt) in [
        ("ACK", failure.acknowledged),
        ("discard", failure.discarded),
        ("advance", failure.advanced),
    ] {
        if let Some(receipt) = receipt {
            proofs.push(receipt);
            completed.push(format!(
                "Native failure reports definitely committed {label} receipt {receipt}."
            ));
        }
    }
    if let Some(attempts) = failure.attempts_reserved {
        completed.push(format!("Failed native owner reports {attempts} definitely reserved lifetime attempts; unreported later progress remains unknown."));
    }
    if let Some(case) = case {
        case.append_recovery(&mut completed, &mut proofs);
    }
    if let Some(case) = args.case.as_ref() {
        let target = case.target();
        completed.push(format!("Exact recovery selector: case {}; predecessor {}; hypothesis {}; side {}; subscription {}. Use explicit probe-citation under the current reader session.", target.case_id, target.expected, target.hypothesis, if target.contradicts { "contradiction" } else { "support" }, args.request.subscription_id));
    }
    let mut consumed = BudgetVector::ZERO;
    if let Some(charge) = charge {
        consumed.tokens = charge.quoted_tokens;
        proofs.push(charge.journal_root);
        completed.push(format!("Definitely committed output charge {} tokens at {}; remaining lifetime tokens {}. This refusal adds no charge and never refunds the committed debit.", charge.quoted_tokens, charge.journal_root, charge.remaining_tokens));
    }
    let mut requested = BudgetVector::ZERO;
    requested.tokens = consumed.tokens;
    proofs.sort();
    proofs.dedup();
    let decision = request_identity("fss.cli.retained_probe_projection.v1", |e| {
        e.digest(args.digest());
        e.text("incomplete_context_durable_progress");
        e.text(failure.identity);
        for proof in &proofs {
            e.digest(*proof);
        }
    });
    let output = build_probe_response(ResponseParts {
        operation: COMMAND,
        request_digest: args.digest(),
        principal: args.request.principal.clone(),
        session_id: Some(args.request.session_id.as_str().to_owned()),
        mission_id: Some(capsule.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view: args.request.view,
        capability: CAPABILITY,
        outcome: ResponseOutcome::Partial,
        error_id: Some("ERR-AGENT-CONTEXT-INCOMPLETE-001"),
        payload_schema: SCHEMA,
        payload_json: "null".to_owned(),
        epistemic_state: KnowledgeState::Indeterminate,
        completeness: Completeness::Partial,
        warnings: vec![format!("Complete cognitive context, native report and detailed failure context are withheld; the selected view was not widened. This is bounded durable-progress metadata only. Original boundary diagnostic: {}.", failure.identity)],
        contradictions: Vec::new(),
        degradation: vec!["No complete context pack or compression receipt is claimed. Protected warnings, contradictions and uncertainty remain in the retained state and require fresh admission before a decision. Outer token figures report only a known prior output debit; other dimensions are unmetered here.".to_owned()],
        budgets_json: agent_json::budget_summary(&requested, &consumed),
        proof_pointers: proofs.iter().map(|proof| proof.to_text()).collect(),
        affordances: Vec::new(),
        affordance_objects: Vec::new(),
        decision_fingerprint: decision,
        compression_receipt_id: None,
        continuation: None,
        recovery_class: "operator_action_required",
        safe_retry: ResponseSafeRetry::YesAfterReconcile,
        boundary: ExecutionBoundary {
            completed,
            not_started: vec!["No automatic source retry, case relink, ACK, successor poll, assessment or external effect follows this refusal.".to_owned()],
            possibly_occurred: if failure.journal_may_have_changed { vec!["Additional unreported journal/clock/root-pin/work progress may have committed; absence from this response is not proof of absence.".to_owned()] } else { Vec::new() },
            preserved_truth: vec!["Known native/case/charge receipts above remain retained; they confer no physical truth, current source availability or refreshed grant. Use probe-citation with the original exact case/predecessor/hypothesis/side for historical linkage, and probe-inspect for current owned progress; a new link requires an explicitly inspected subscription-state.".to_owned()],
            invalidated: vec!["Complete protected context was not delivered; do not decide from this recovery response.".to_owned()],
        },
        created_at_ns: capsule.created_at.0,
        workspace_revision: Some(context.oriented.revision.capsule().revision),
        idempotency_key: None,
    })?;
    if output.len() > MAX_PROBE_OUTPUT_BYTES
        || (output.len() as u64).div_ceil(4) > u64::from(args.request.view.maximum_tokens())
    {
        return Err(RenderError("bounded durable-progress refusal exceeds selected view").into());
    }
    Ok(output)
}
