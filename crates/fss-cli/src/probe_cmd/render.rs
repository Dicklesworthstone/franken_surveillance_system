#![forbid(unsafe_code)]
//! Registered cognitive output; private native JSON never crosses this transport boundary.

use fss_core::{
    AgentCognitiveEnvelope, AgentCognitiveEnvelopeV2, BudgetVector, CognitiveAnswerClass,
    Completeness, ContentDigest, EnvelopeBudget, EnvelopeContinuity, EnvelopeCoverage,
    EnvelopeEpistemic, EnvelopeProposition, ExecutionBoundary, KnowledgeState, ResponseOutcome,
    ResponseSafeRetry,
};
use fss_reference::agent_session::checkpoint::journal::supervision::SupervisionSchedule;
use fss_reference::deployment_session::probe::{ProbeCharge, ProbeContext};
use fss_reference::deployment_session::supervision::{
    SupervisionSessionDelivery, SupervisionSessionOutcome,
};

use super::{
    CAPABILITY, COMMAND, MAX_PROBE_OUTPUT_BYTES, ProbeArgs, ProbeFailure, SCHEMA, compression,
    projection,
};
use crate::agent_json::{self, EvidenceHandle, object};
use crate::orient_cmd::{RenderError, ResponseParts, build_probe_response, request_identity};
use crate::supervisor::retained::session::{NativeSupervisionRequest, released_report};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

mod case;
pub(super) use case::CaseProjection;
mod refusal;
pub(super) use refusal::progress_refusal;

/// Private complete response, released only after its quoted token charge is durable.
pub(super) struct Prepared {
    pub text: String,
    pub quoted_tokens: u64,
}

struct Pending {
    receipt: ContentDigest,
    report: ContentDigest,
    payload: ContentDigest,
    root: ContentDigest,
    bytes: usize,
    windows: Option<u32>,
}

struct Progress<'a> {
    configuration: ContentDigest,
    state: ContentDigest,
    pending: Option<Pending>,
    maximum: u32,
    attempts: u32,
    max_bytes: u64,
    max_reads: u64,
    bytes: u64,
    reads: u64,
    last_ack: Option<ContentDigest>,
    last_discard: Option<ContentDigest>,
    schedule: Option<&'a SupervisionSchedule>,
}

fn progress<'a>(
    args: &ProbeArgs,
    context: &'a ProbeContext,
    delivery: Option<&'a SupervisionSessionDelivery>,
) -> Option<Progress<'a>> {
    if let Some(delivery) = delivery {
        let state = &delivery.subscription;
        let reg = state.registration();
        return Some(Progress {
            configuration: reg.configuration_digest,
            state: state.digest(),
            pending: state.pending().map(|p| Pending {
                receipt: p.receipt(),
                report: p.report_receipt(),
                payload: p.payload_digest(),
                root: p.anchor().state_root,
                bytes: p.payload_len(),
                windows: p.active_window_count(),
            }),
            maximum: reg.maximum_attempts,
            attempts: state.attempts_reserved(),
            max_bytes: reg.max_read_bytes,
            max_reads: reg.max_read_attempts,
            bytes: state.reserved_bytes(),
            reads: state.reserved_read_attempts(),
            last_ack: state.last_acknowledged(),
            last_discard: state.last_discarded(),
            schedule: state.schedule(),
        });
    }
    context
        .oriented
        .orientation
        .supervision_inventory
        .iter()
        .find(|entry| entry.subscription_id == args.request.subscription_id)
        .map(|entry| Progress {
            configuration: entry.configuration_digest,
            state: entry.state_digest,
            pending: entry.pending.as_ref().map(|p| Pending {
                receipt: p.receipt,
                report: p.report_receipt,
                payload: p.payload_digest,
                root: p.anchor.state_root,
                bytes: p.payload_len,
                windows: p.active_window_count,
            }),
            maximum: entry.maximum_attempts,
            attempts: entry.attempts_reserved,
            max_bytes: entry.max_read_bytes,
            max_reads: entry.max_read_attempts,
            bytes: entry.reserved_bytes,
            reads: entry.reserved_read_attempts,
            last_ack: entry.last_acknowledged,
            last_discard: entry.last_discarded,
            schedule: entry.schedule.as_ref(),
        })
}

fn optional(value: Option<ContentDigest>) -> String {
    value.map_or_else(|| "none".to_owned(), |value| value.to_text())
}

fn proposition(
    id: &str,
    statement: String,
    state: KnowledgeState,
    evidence: &[ContentDigest],
) -> EnvelopeProposition {
    EnvelopeProposition {
        id: format!("probe:{id}"),
        statement,
        state,
        provenance: "derived".to_owned(),
        evidence: evidence.iter().map(|value| value.to_text()).collect(),
    }
}

fn handle(digest: ContentDigest, kind: &str) -> EvidenceHandle {
    EvidenceHandle {
        handle_id: format!("fss://proof/{digest}"),
        object_digest: digest,
        kind: kind.to_owned(),
        hydration: "H0",
        allowed_hydration: vec!["H0"],
        privacy_class: "private:property".to_owned(),
        availability: "available",
        estimated_cost: BudgetVector::default(),
        required_capability: Some(CAPABILITY.to_owned()),
    }
}

fn add_handle(handles: &mut Vec<EvidenceHandle>, digest: ContentDigest, kind: &str) {
    if !handles.iter().any(|h| h.object_digest == digest) {
        handles.push(handle(digest, kind));
    }
}

pub(super) fn response(
    args: &ProbeArgs,
    context: &ProbeContext,
    delivery: Option<&SupervisionSessionDelivery>,
    native: Option<&NativeSupervisionRequest>,
    charge: Option<&ProbeCharge>,
    failure: Option<&ProbeFailure>,
) -> Result<Prepared> {
    response_with_case(args, context, delivery, native, charge, failure, None)
}

#[allow(clippy::too_many_arguments)] // independent durable native/case/charge outcomes stay explicit
pub(super) fn response_with_case(
    args: &ProbeArgs,
    context: &ProbeContext,
    delivery: Option<&SupervisionSessionDelivery>,
    native: Option<&NativeSupervisionRequest>,
    charge: Option<&ProbeCharge>,
    failure: Option<&ProbeFailure>,
    case: Option<&CaseProjection<'_>>,
) -> Result<Prepared> {
    let orientation = &context.oriented.orientation;
    if orientation.view != args.request.view {
        return Err(RenderError("probe context differs from explicitly selected view").into());
    }
    let capsule = orientation.capsule();
    let frame = capsule.decision_fingerprint()?;
    let historical_case_read = matches!(
        args.case.as_ref(),
        Some(fss_reference::deployment_session::probe::case::CaseProbeAction::InspectCitation(_))
    );
    // A historical case reader need not own the original subscription. A coincidentally equal
    // label in the reader's current session cannot become the historical operation's progress.
    let progress = if historical_case_read {
        None
    } else {
        progress(args, context, delivery)
    };
    let mut propositions: Vec<_> = orientation
        .publication
        .context_pack
        .items
        .iter()
        .map(|item| EnvelopeProposition {
            id: item.item_id.clone(),
            statement: item.content.clone(),
            state: item.epistemic_state,
            provenance: "derived".to_owned(),
            evidence: item.basis.iter().cloned().collect(),
        })
        .collect();
    let mut handles = Vec::new();
    let mut proof = vec![
        frame,
        context.oriented.journal_root,
        context.ledger_root,
        context.effect_root,
    ];
    let upstream = &orientation.publication.compression_receipt;
    proof.extend([
        upstream.receipt_digest(),
        orientation.publication.context_pack.pack_digest,
    ]);
    propositions.push(proposition(
        "upstream-context-compression",
        format!(
            "Upstream pack {}; receipt {} ({}); stop {}; reference tokens {}/{}; completeness [{}]; expansion handles [{}]. These source-selection omissions remain in force; packaging grants no expansion authority.",
            orientation.publication.context_pack.pack_digest,
            upstream.receipt_id,
            upstream.receipt_digest(),
            upstream.stop_reason.as_str(),
            upstream.actual_tokens,
            upstream.target_tokens,
            upstream.completeness.iter().map(|row| format!("{}:{}:omitted={}", row.domain, row.state.as_str(), row.omitted_count)).collect::<Vec<_>>().join("; "),
            upstream.expansion_handles.iter().map(|h| format!("{}: {}; cost {}", h.handle, h.purpose, agent_json::budget(&h.estimated_cost))).collect::<Vec<_>>().join("; "),
        ),
        KnowledgeState::Known,
        &[upstream.receipt_digest(), orientation.publication.context_pack.pack_digest],
    ));
    let mut not_observable = vec!["This probe does not certify physical class absence, present camera health, cross-camera actor identity, synchronized camera clocks or effect authority.".to_owned()];
    let mut warnings = orientation.warnings.clone();
    warnings.push("Historical retained-source supervision; advice is not a physical fact, independent corroboration or an authorized effect. Inspection and terminal actions release no native report.".to_owned());
    let mut completed = vec![format!(
        "Admitted live session, CASE-WRITE and protected {} context.",
        args.request.view.name()
    )];
    let mut observed = vec![if historical_case_read {
        format!(
            "current case-reader session:{}; historical subscription label:{}",
            args.request.session_id.as_str(),
            args.request.subscription_id
        )
    } else {
        format!(
            "session:{};subscription:{}",
            args.request.session_id.as_str(),
            args.request.subscription_id
        )
    }];
    let mut omissions = vec!["Original spatial detector rows, model numeric internals and media are represented by exact native payload/source identities; this H0 decision projection does not hydrate them.".to_owned()];
    let mut omitted_count = 0_u64;
    let mut boundary_unknown = Vec::new();
    if let Some(p) = &progress {
        proof.extend([p.configuration, p.state]);
        propositions.push(proposition("progress", format!(
            "Subscription {}; exact state {}; configuration {}; lifetime native attempts {}/{}; reserved stored-envelope bytes {}; indexed reads {}; no refund. Last ACK {}; discard {}. {}",
            args.request.subscription_id, p.state, p.configuration, p.attempts, p.maximum, p.bytes, p.reads,
            optional(p.last_ack), optional(p.last_discard),
            if delivery.is_some() { "Exact returned native state." } else { "Pre-action metadata; later progress unknown." },
        ), KnowledgeState::Known, &[p.state]));
        if let Some(pending) = &p.pending {
            add_handle(
                &mut handles,
                pending.receipt,
                "retained_supervision_delivery_receipt",
            );
            proof.extend([
                pending.receipt,
                pending.report,
                pending.payload,
                pending.root,
            ]);
            propositions.push(proposition("pending", format!(
                "Pending delivery {}; report {}; historical authority {}; payload {}; {} bytes; cumulative prefix {:?}. This exact receipt must be explicitly acknowledged or discarded. Metadata does not revalidate/disclose sources.",
                pending.receipt, pending.report, pending.root, pending.payload, pending.bytes, pending.windows,
            ), KnowledgeState::Known, &[pending.receipt, pending.report, pending.payload]));
        }
        if let Some(schedule) = p.schedule {
            let advance = schedule.last_advance();
            propositions.push(proposition("schedule", format!(
                "Cumulative windows {}/{}; terminal receipt {}; acknowledged {:?}; advance {} after {}. Explicit adjacent advance does not evaluate its successor or establish elapsed wall time.",
                schedule.active_window_count(), schedule.total_windows(), optional(schedule.resolved_receipt()),
                schedule.resolved_acknowledged(), optional(advance.map(|a| a.receipt())), optional(advance.map(|a| a.after_receipt())),
            ), KnowledgeState::Known, &[p.state]));
        }
        for (digest, kind) in [
            (p.last_ack, "retained_supervision_acknowledgement"),
            (p.last_discard, "retained_supervision_discard"),
        ] {
            if let Some(digest) = digest {
                add_handle(&mut handles, digest, kind);
                proof.push(digest);
            }
        }
    }
    if let Some(delivery) = delivery {
        proof.push(delivery.journal_root);
        let (status, validation) = match &delivery.outcome {
            SupervisionSessionOutcome::Inspected => ("inspected without source work", None),
            SupervisionSessionOutcome::ScheduleConfigured => {
                return Err(RenderError("probe cannot configure a schedule").into());
            }
            SupervisionSessionOutcome::WindowAdvanced => (
                "advanced exactly one predeclared window without evaluating a successor",
                None,
            ),
            SupervisionSessionOutcome::Report {
                replayed,
                validation,
                ..
            } => (
                if *replayed {
                    "replayed the exact historical pending report after current native source validation"
                } else {
                    "evaluated native sources and durably retained the complete pending report"
                },
                validation.as_ref(),
            ),
            SupervisionSessionOutcome::Acknowledged {
                receipt,
                validation,
            } => {
                propositions.push(proposition("acknowledged", format!("Explicitly acknowledged exact delivery {receipt}; no successor was polled and no case conclusion was inferred."), KnowledgeState::Known, &[*receipt]));
                ("acknowledged the exact receipt", validation.as_ref())
            }
            SupervisionSessionOutcome::Discarded(receipt) => {
                propositions.push(proposition("discarded", format!("Explicitly discarded exact delivery {receipt}; this is abandonment, not acknowledgement or evidence of absence."), KnowledgeState::Known, &[*receipt]));
                ("discarded the exact receipt", None)
            }
        };
        completed.push(format!("Native owner {status}."));
        propositions.push(proposition("outcome", format!("Native owner {status}. Current authority {}; ledger {}; effect journal {}; session journal {}. No automatic ACK, assessment or effect.",
            delivery.head.anchor.state_root, delivery.head.ledger_root, delivery.head.effect_root, delivery.journal_root), KnowledgeState::Known, &[delivery.journal_root]));
        if let Some(validation) = validation {
            proof.push(validation.receipt);
            add_handle(
                &mut handles,
                validation.receipt,
                "retained_supervision_current_validation",
            );
            propositions.push(proposition("source-revalidation", format!("Current historical-source validation {}; authority {}; reserved bytes {}; indexed reads {}. Retained disclosure only; current physical conditions unknown.", validation.receipt, validation.basis.state_root, validation.reserved_bytes, validation.read_attempts), KnowledgeState::Known, &[validation.receipt]));
        }
        if failure.is_none() {
            let native = native.ok_or(RenderError("native probe owner missing"))?;
            if let Some(report) = released_report(delivery, native)? {
                let pending = delivery
                    .subscription
                    .pending()
                    .ok_or(RenderError("released probe receipt missing"))?;
                let projected = projection::project(&report, pending.report_receipt())?;
                // Only the released complete payload passed native read-back and current source
                // admission. Semantic/model/source identities stay provenance pointers: their
                // presence in a report is not a retrievable-object availability assertion.
                add_handle(
                    &mut handles,
                    pending.report_receipt(),
                    "retained_supervision_report_receipt",
                );
                add_handle(
                    &mut handles,
                    pending.payload_digest(),
                    "retained_supervision_payload",
                );
                observed.push(format!(
                    "{} complete native windows; {} source-linked observations",
                    projected.window_count, projected.observation_count
                ));
                omitted_count = projected.observation_count as u64;
                propositions.extend(projected.propositions);
                not_observable.extend(projected.not_observable);
                // Every native provenance digest remains in the required, verified pack item's
                // basis. Repeating the complete inventory again as outer pointers adds no proof.
            }
        }
    }
    if let Some(failure) = failure {
        warnings.push(failure.reason.clone());
        warnings.push("Protected context is the last admitted snapshot. Native payload is withheld; inspect the owned subscription before any recovery action. A refusal is not an empty match set or certified silence.".to_owned());
        omissions.push("The complete requested report was withheld after a native, context or delivery boundary refusal; no successful partial report was substituted.".to_owned());
        if failure.journal_may_have_changed {
            boundary_unknown.push("Session clock/root-pin, work reservation or delivery state may have committed; no automatic retry or refund occurred.".to_owned());
        }
        propositions.push(proposition("refusal", format!("{}: {}; definitely committed attempt count reported by failed native call {:?}; exact committed ACK {}, discard {}, advance {}. Unreported progress remains unknown.", failure.identity, failure.reason, failure.attempts_reserved, optional(failure.acknowledged), optional(failure.discarded), optional(failure.advanced)), KnowledgeState::Indeterminate, &[]));
        for digest in [failure.acknowledged, failure.discarded, failure.advanced]
            .into_iter()
            .flatten()
        {
            proof.push(digest);
            add_handle(
                &mut handles,
                digest,
                "retained_supervision_committed_progress",
            );
        }
    }
    if let Some(charge) = charge {
        proof.push(charge.journal_root);
        propositions.push(proposition("token-charge", format!("Durable quoted-token charge {}; journal {}; remaining lifetime tokens {}. No refill; each explicit delivery has its own quote.", charge.quoted_tokens, charge.journal_root, charge.remaining_tokens), KnowledgeState::Known, &[charge.journal_root]));
        completed.push(format!(
            "Charged {} quoted tokens before release; checkpoint {}.",
            charge.quoted_tokens, charge.journal_root
        ));
    }
    if let Some(case) = case {
        case.append(
            args,
            &mut propositions,
            &mut proof,
            &mut handles,
            &mut completed,
            &mut not_observable,
            &mut omissions,
        )?;
    }
    let coverage = EnvelopeCoverage {
        authorized_domain: vec![if historical_case_read {
            "current principal/mission/privacy visibility of the exact historical case citation; no source or original-session authority is revived".to_owned()
        } else {
            format!(
                "existing owned retained-source subscription {}",
                args.request.subscription_id
            )
        }],
        observed_domain: observed,
        not_observable_domain: not_observable,
        omitted_count,
        omission_reasons: omissions,
        stop_reason: if failure.is_some() {
            "explicit refusal; retained progress requires inspection"
        } else if historical_case_read {
            "one exact historical case-citation lookup completed; no native source action or relink"
        } else {
            "one explicit bounded native action completed; no automatic successor"
        }
        .to_owned(),
    };
    propositions.push(proposition(
        "packaging-scope",
        "Required contextPack carries every admitted proposition and protected qualification; this envelope is its exact summary subset. Upstream context compression and native/H0 source omissions remain separate; packaging is lossless only for admitted cognition.".to_owned(),
        KnowledgeState::Known,
        &[upstream.receipt_digest()],
    ));
    let epistemic = EnvelopeEpistemic {
        propositions,
        assumptions: vec!["Configured calibration applicability and failure-domain declarations remain owner assertions. Source validation is historical and local to the named authority.".to_owned()],
        invalidators: context.oriented.invalidated.iter().cloned().chain([
            "Any current source deletion, privacy/custody denial, session expiry, grant narrowing, journal change or interpretation-generation change requires fresh native admission.".to_owned(),
        ]).collect(),
    };
    let (pack, receipt) =
        compression::package(args, context, &epistemic, &coverage, &handles, &warnings)?;
    // V2 requires the complete typed pack, so detailed cognition is carried once there. The
    // concise envelope is an exact subset, not a second, silently abbreviated native inventory.
    // Selection never changes the required pack, its receipt or protected uncertainty/coverage.
    let summary = if failure.is_none() && matches!(case, Some(CaseProjection::Linked(_))) {
        // Successful linkage carries the complete native report plus exact citation custody.
        // V2 requires readers to consume the pack, which already contains every proposition,
        // assumption and invalidation. Do not duplicate those facts in a second summary and
        // crowd a valid small report out of its selected view. The sealed outcome selects
        // the same representation before and after charging; pack/receipt identity is unchanged.
        EnvelopeEpistemic {
            propositions: Vec::new(),
            assumptions: Vec::new(),
            invalidators: Vec::new(),
        }
    } else {
        EnvelopeEpistemic {
            propositions: epistemic
                .propositions
                .iter()
                .filter(|proposition| {
                    matches!(
                        proposition.id.as_str(),
                        "probe:pending"
                            | "probe:outcome"
                            | "probe:token-charge"
                            | "probe:refusal"
                            | "probe:acknowledged"
                            | "probe:discarded"
                            | "probe:packaging-scope"
                            | "probe:case-linked"
                            | "probe:case-citation-absent"
                    )
                })
                .cloned()
                .collect(),
            assumptions: epistemic.assumptions.clone(),
            invalidators: epistemic.invalidators.clone(),
        }
    };
    proof.extend([pack.pack_digest, receipt.receipt_digest()]);
    let mut assemble = |quoted_tokens: u64| -> Result<String> {
        let mut requested = vec![("context_token_quote", quoted_tokens.to_string())];
        let mut consumed = vec![(
            "session_journal_bytes_read",
            context.session_bytes_read.to_string(),
        )];
        let mut remaining = vec![(
            "session_tokens",
            charge
                .map_or(context.remaining_tokens, |c| c.remaining_tokens)
                .to_string(),
        )];
        if let Some(charge) = charge {
            consumed.push(("context_token_quote", charge.quoted_tokens.to_string()));
        }
        if let Some(p) = &progress {
            requested.extend([
                ("native_attempts", p.maximum.to_string()),
                (
                    "native_reserved_bytes",
                    (u64::from(p.maximum) * p.max_bytes).to_string(),
                ),
                (
                    "native_reserved_reads",
                    (u64::from(p.maximum) * p.max_reads).to_string(),
                ),
            ]);
            consumed.extend([
                ("native_attempts_at_snapshot", p.attempts.to_string()),
                ("native_reserved_bytes_at_snapshot", p.bytes.to_string()),
                ("native_reserved_reads_at_snapshot", p.reads.to_string()),
            ]);
            if failure.is_none() {
                remaining.push((
                    "native_attempts",
                    p.maximum.saturating_sub(p.attempts).to_string(),
                ));
            }
        }
        let requested = object(&requested);
        let consumed = object(&consumed);
        let remaining = object(&remaining);
        let mut output_requested = BudgetVector::ZERO;
        output_requested.tokens = quoted_tokens;
        let mut output_consumed = BudgetVector::ZERO;
        output_consumed.tokens = charge.map_or(0, |charge| charge.quoted_tokens);
        let output_budgets = agent_json::budget_summary(&output_requested, &output_consumed);
        let meter = "Native attempts reserve full read caps without refund. Output quote=ceil(full serialized UTF-8 bytes/4)+512 final-accounting tokens, including required pack/receipt. Outer vectors price output tokens only; other zero dimensions are unmetered. Cognitive counters retain native work; bounded metadata work is additional; refusal metadata uncharged.".to_owned();
        proof.sort();
        proof.dedup();
        let decision = request_identity("fss.cli.retained_probe_projection.v1", |e| {
            e.digest(args.digest());
            e.digest(frame);
            for p in &proof {
                e.digest(*p);
            }
            if let Some(f) = failure {
                e.text(f.identity);
                e.text(&f.reason);
            }
        });
        let text = args.digest().to_text();
        let hex = text
            .strip_prefix("sha256:")
            .ok_or(RenderError("probe request digest differs"))?;
        let envelope = AgentCognitiveEnvelope::new(
        capsule.contract_basis.clone(), format!("request:investigate:{hex}"), format!("response:investigate:{hex}"),
        format!("trace:investigate:{hex}"), COMMAND, args.name(), args.request.view.id(),
        if failure.is_some() { CognitiveAnswerClass::Refusal } else { CognitiveAnswerClass::BoundedSummary },
        capsule.anchor.clone(), summary.clone(), coverage.clone(),
        EnvelopeBudget { requested_json: requested.clone(), consumed_json: consumed.clone(), remaining_json: remaining.clone(),
            degraded_dimensions: vec![meter.clone()], marginal_work_declined: vec!["No automatic ACK, successor poll, live acquisition, case assessment or effect.".to_owned()] },
        handles.iter().map(|h| h.handle_id.clone()).collect(), Vec::new(),
        EnvelopeContinuity { cursor: None, reanchor_triggers: vec!["Any authority, source custody, session grant or journal change; the pending delivery retains its original report anchor.".to_owned()],
            session_capsule_digest: Some(frame.to_text()), unresolved_obligations: capsule.obligations.iter().map(|o| o.as_str().to_owned()).collect() },
        decision.to_text(),
    )?;
        let envelope = AgentCognitiveEnvelopeV2::new(envelope, pack.clone(), receipt.clone())?;
        let payload = agent_json::cognitive_envelope_v2(&envelope, &handles, &[])
            .ok_or(RenderError("probe cognitive envelope differs"))?;
        let output = build_probe_response(ResponseParts {
        operation: COMMAND, request_digest: args.digest(), principal: args.request.principal.clone(),
        session_id: Some(args.request.session_id.as_str().to_owned()), mission_id: Some(capsule.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(), view: args.request.view, capability: CAPABILITY,
        outcome: if failure.is_some() { ResponseOutcome::Partial } else { ResponseOutcome::Ok }, error_id: failure.map(|f| f.identity),
        payload_schema: SCHEMA, payload_json: payload, epistemic_state: if failure.is_some() { KnowledgeState::Indeterminate } else { orientation.epistemic_state },
        completeness: if failure.is_some() { Completeness::Partial } else { Completeness::Bounded },
        warnings: warnings.clone(), contradictions: orientation.contradictions.clone(), degradation: vec![meter],
        budgets_json: output_budgets,
        proof_pointers: proof.iter().map(|p| p.to_text()).collect(), affordances: Vec::new(), affordance_objects: Vec::new(),
        decision_fingerprint: decision, compression_receipt_id: Some(receipt.receipt_id.clone()), continuation: None,
        recovery_class: if failure.is_some() { "operator_action_required" } else { "safe_read_retry" },
        safe_retry: if failure.is_some() { ResponseSafeRetry::YesAfterReconcile } else { ResponseSafeRetry::YesSameRequest },
        boundary: ExecutionBoundary { completed: completed.clone(), not_started: vec!["Automatic acknowledgement, successor evaluation, case assessment and every device/provider effect.".to_owned()],
            possibly_occurred: boundary_unknown.clone(),
            preserved_truth: vec!["Only the existing agent session journal may change. Native source custody and original pending payload/receipt remain owned by retained supervision; no ledger event or effect is fabricated.".to_owned()],
            invalidated: context.oriented.invalidated.clone() },
        created_at_ns: capsule.created_at.0, workspace_revision: Some(context.oriented.revision.capsule().revision), idempotency_key: None,
    })?;
        if output.len() > MAX_PROBE_OUTPUT_BYTES {
            return Err(RenderError("complete probe response exceeds 256 KiB").into());
        }
        Ok(output)
    };
    let (output, quoted_tokens) = if let Some(charge) = charge {
        (assemble(charge.quoted_tokens)?, charge.quoted_tokens)
    } else {
        // The first serialization is private. Its complete bytes price both exact proof objects,
        // all wire overhead and the outer envelope; no source work or charge occurs here.
        let preview = assemble(0)?;
        let quote = (preview.len() as u64).div_ceil(4).saturating_add(512);
        (assemble(quote)?, quote)
    };
    let wire_tokens = (output.len() as u64).div_ceil(4);
    let maximum_tokens = u64::from(args.request.view.maximum_tokens());
    // A refusal is also a bounded transport response. If its complete protected context cannot
    // fit, the caller preserves durable progress through the explicit null-payload fallback.
    if quoted_tokens > maximum_tokens
        || wire_tokens > maximum_tokens
        || (failure.is_none()
            && (quoted_tokens > context.remaining_tokens || wire_tokens > quoted_tokens))
    {
        return Err(std::io::Error::other(format!(
            "complete serialized probe is {} bytes ({} quoted tokens); selected {} ceiling is {}, remaining session allowance is {}. Complete native payload withheld without ACK; an explicitly selected forensic view has a separate registered bound",
            output.len(), quoted_tokens, args.request.view.name(), args.request.view.maximum_tokens(), context.remaining_tokens,
        )).into());
    }
    Ok(Prepared {
        text: output,
        quoted_tokens,
    })
}
