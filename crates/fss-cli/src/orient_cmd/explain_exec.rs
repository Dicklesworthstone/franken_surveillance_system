#![forbid(unsafe_code)]
//! Execution and response assembly for `fss explain` (AOP-011).

use fss_core::{
    ActionAffordance, AgentCognitiveEnvelope, AgentView, CanonicalEncode, CognitiveAnswerClass,
    Completeness, ContentDigest, EnvelopeBudget, EnvelopeCoverage, EnvelopeEpistemic,
    EnvelopeProposition, EventId, EventState, KnowledgeState, LedgerAnchor, ResponseOutcome,
    ResponseSafeRetry,
};
use fss_reference::agent_orient::{
    AFFORDANCE_REORIENT, CAPABILITY_EXPLAIN, DeploymentOrientation, DeploymentSnapshot,
    EventExplanation, OrientError, OrientLimits, OrientRequest, orient_deployment,
};

use super::args::{
    ERR_AGENT_CONTEXT_INCOMPLETE, ERR_AGENT_EVENT_NOT_FOUND, ExplainArgs, ExplainTarget,
};
use super::cognitive::{CognitiveParts, cognitive_payload_with_budget, explanation_handles};
use super::diagnostics::{
    internal_failure_with_detail, read_only_boundary, rendered, request_identity,
};
use super::response::{ResponseParts, build_response};
use super::{
    custody, evidence, explain_options, fusion, history, learning_explain, what_changed, what_if,
};
use crate::agent_json;
use crate::error::ExitIdentity;

fn explanation_response(
    orientation: &DeploymentOrientation,
    explanation: &EventExplanation,
    request_digest: ContentDigest,
    support: &evidence::SupportReview,
    custody_checked: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let event = &explanation.event.event;
    let physical = explanation
        .cells
        .iter()
        .find(|cell| cell.claim_id().ends_with(":unknown-presence"))
        .map_or(KnowledgeState::Unknown, |cell| cell.knowledge_state());
    let mut propositions: Vec<EnvelopeProposition> = explanation
        .cells
        .iter()
        .map(|cell| EnvelopeProposition {
            id: cell.claim_id().to_owned(),
            statement: cell.disclosable_statement().to_owned(),
            state: cell.knowledge_state(),
            provenance: cell.provenance().as_str().to_owned(),
            evidence: cell
                .evidence_digests()
                .iter()
                .map(|digest| digest.to_text())
                .collect(),
        })
        .collect();
    // The event's per-event worlds (the members its orientation aggregates): each remains
    // exactly as possible as the event's physical-presence claim is uncertain.
    propositions.extend(explanation.worlds.iter().map(|world| {
        EnvelopeProposition {
            id: world.world_id.clone(),
            statement: format!(
                "{}{} world, consequence severity {}: {}",
                if explanation.residual_ids.contains(&world.world_id) {
                    "Adversarial residual"
                } else {
                    "Material alternative"
                },
                if world.protected { " (protected)" } else { "" },
                world.consequence_severity,
                world.description
            ),
            state: physical,
            provenance: "derived".to_owned(),
            evidence: world
                .evidence
                .iter()
                .map(|digest| digest.to_text())
                .collect(),
        }
    }));
    let mut invalidators = explanation.would_change.clone();
    invalidators.extend(
        explanation
            .cells
            .iter()
            .filter(|cell| !cell.contradictions().is_empty())
            .map(|cell| {
                format!(
                    "{} is contradicted by {} retained root(s).",
                    cell.claim_id(),
                    cell.contradictions().len()
                )
            }),
    );
    propositions.extend(support.propositions.iter().cloned());
    invalidators.extend(support.invalidators.iter().cloned());
    let mut assumptions = explanation.assumptions.clone();
    assumptions.extend(support.assumptions.iter().cloned());
    let answer_class = if event.state == EventState::Indeterminate {
        CognitiveAnswerClass::Indeterminate
    } else {
        CognitiveAnswerClass::HypothesisSet
    };
    let (payload, next_ids, next_objects) = cognitive_payload_with_budget(
        orientation,
        request_digest,
        "explain",
        support.view,
        CognitiveParts {
            answer_class,
            epistemic: EnvelopeEpistemic {
                propositions,
                assumptions,
                invalidators,
            },
            coverage: EnvelopeCoverage {
                authorized_domain: event.zone_ids.clone(),
                observed_domain: explanation.event.failure_domains().into_iter().collect(),
                not_observable_domain: vec![
                    "site activity outside the retained recording".to_owned(),
                ],
                omitted_count: 0,
                omission_reasons: Vec::new(),
                stop_reason: "complete".to_owned(),
            },
            evidence_handles: explanation_handles(explanation),
            next_actions: explanation.affordances.clone(),
            decision_digest: support.receipt.receipt_digest(),
        },
        Some(custody::budget(support, custody_checked)),
    )?;
    let contradictions = explanation
        .cells
        .iter()
        .filter(|cell| {
            !cell.contradictions().is_empty()
                || cell.knowledge_state() == KnowledgeState::Conflicted
        })
        .map(|cell| cell.claim_id().to_owned())
        .collect();
    let mut warnings = explanation.warnings.clone();
    warnings.extend(support.warnings.iter().cloned());
    warnings.push(
        "An explanation grants no effect authority; it binds the committed revision only."
            .to_owned(),
    );
    let mut proof_pointers = vec![
        explanation.receipt.receipt_digest().to_text(),
        explanation.event.revision_digest.to_text(),
        explanation.event.event_root.to_text(),
    ];
    proof_pointers.extend(
        explanation
            .receipt
            .evidence_subgraph()
            .iter()
            .map(|digest| digest.to_text()),
    );
    proof_pointers.extend(support.proof_pointers.iter().cloned());
    proof_pointers.sort();
    proof_pointers.dedup();
    let capsule = orientation.capsule();
    build_response(ResponseParts {
        operation: "explain",
        request_digest,
        principal: capsule.principal_id.clone(),
        session_id: Some(capsule.session_id.as_str().to_owned()),
        mission_id: Some(capsule.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view: support.view,
        capability: CAPABILITY_EXPLAIN,
        outcome: ResponseOutcome::Ok,
        error_id: None,
        payload_schema: AgentCognitiveEnvelope::SCHEMA,
        payload_json: payload,
        epistemic_state: physical,
        completeness: Completeness::Partial,
        warnings,
        contradictions,
        degradation: vec![
            if custody_checked {
                custody::METER_SCOPE.to_owned()
            } else {
                "Latency and CPU time are not metered by this reference path; consumed reports \
             reads, orientation context tokens and the separately priced support brief."
                    .to_owned()
            },
            support.cost_statement.clone(),
        ],
        budgets_json: agent_json::budget_summary(&support.requested, &support.consumed),
        proof_pointers,
        affordances: next_ids,
        affordance_objects: next_objects,
        decision_fingerprint: support.receipt.receipt_digest(),
        compression_receipt_id: None,
        continuation: None,
        recovery_class: "safe_read_retry",
        safe_retry: ResponseSafeRetry::YesSameRequest,
        boundary: read_only_boundary(format!(
            "Explained {} revision {} at commit {}.",
            event.event_id.as_str(),
            event.revision,
            capsule.anchor.commit_sequence
        )),
        created_at_ns: capsule.created_at.0,
        workspace_revision: None,
        idempotency_key: None,
    })
}

fn unknown_event_response(
    snapshot: &DeploymentSnapshot,
    orientation: &DeploymentOrientation,
    event_id: &EventId,
    request_digest: ContentDigest,
    view: AgentView,
    token_limit: u64,
    historical: Option<&history::HistoricalScope>,
) -> Result<String, Box<dyn std::error::Error>> {
    let capsule = orientation.capsule();
    let evidence = if snapshot.batch_count == 0 {
        snapshot.anchor.state_root
    } else {
        snapshot.ledger_root
    };
    let statement = format!(
        "No committed event_revision delta names {} at commit {}; {} event(s) are published.",
        event_id.as_str(),
        capsule.anchor.commit_sequence,
        snapshot.events.len()
    );
    let decision = request_identity("fss.cli.explain.not_found.v1", |encoder| {
        encoder.text(event_id.as_str());
        capsule.anchor.encode_canonical(encoder);
        encoder.digest(evidence);
        if let Some(scope) = historical {
            scope.encode_request(encoder);
        }
    });
    let reorient: Vec<ActionAffordance> = capsule
        .affordances
        .iter()
        .filter(|candidate| candidate.affordance_id == AFFORDANCE_REORIENT)
        .cloned()
        .collect();
    let mut requested = orientation.requested;
    requested.tokens = token_limit;
    let mut consumed = orientation.consumed;
    let mut propositions = vec![EnvelopeProposition {
        id: "claim:event-index:requested".to_owned(),
        statement,
        state: KnowledgeState::Known,
        provenance: "derived".to_owned(),
        evidence: vec![evidence.to_text()],
    }];
    if let Some(scope) = historical {
        consumed.tokens = consumed.tokens.saturating_add(scope.context_tokens());
        if consumed.tokens > token_limit {
            return explain_options::orientation_refusal(
                snapshot,
                request_digest,
                view,
                &capsule.principal_id,
                token_limit,
                "Historical scope does not fit the admitted context budget.".to_owned(),
            );
        }
        propositions.insert(0, scope.proposition());
    }
    let (payload, next_ids, next_objects) = cognitive_payload_with_budget(
        orientation,
        request_digest,
        "explain",
        view,
        CognitiveParts {
            answer_class: CognitiveAnswerClass::Refusal,
            epistemic: EnvelopeEpistemic {
                propositions,
                assumptions: Vec::new(),
                invalidators: vec![
                    "A later commit that publishes the event would answer the question.".to_owned(),
                ],
            },
            coverage: EnvelopeCoverage {
                authorized_domain: vec!["committed event_revision deltas".to_owned()],
                observed_domain: vec!["committed event_revision deltas".to_owned()],
                not_observable_domain: Vec::new(),
                omitted_count: 0,
                omission_reasons: Vec::new(),
                stop_reason: "complete".to_owned(),
            },
            evidence_handles: Vec::new(),
            next_actions: reorient,
            decision_digest: decision,
        },
        Some(EnvelopeBudget {
            requested_json: agent_json::budget(&requested),
            consumed_json: agent_json::budget(&consumed),
            remaining_json: agent_json::remaining(&requested, &consumed),
            degraded_dimensions: Vec::new(),
            marginal_work_declined: Vec::new(),
        }),
    )?;
    build_response(ResponseParts {
        operation: "explain",
        request_digest,
        principal: capsule.principal_id.clone(),
        session_id: Some(capsule.session_id.as_str().to_owned()),
        mission_id: Some(capsule.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(),
        view,
        capability: CAPABILITY_EXPLAIN,
        outcome: ResponseOutcome::Refused,
        error_id: Some(ERR_AGENT_EVENT_NOT_FOUND),
        payload_schema: AgentCognitiveEnvelope::SCHEMA,
        payload_json: payload,
        epistemic_state: KnowledgeState::Known,
        completeness: Completeness::Complete,
        warnings: historical.map_or_else(Vec::new, |scope| vec![scope.warning()]),
        contradictions: Vec::new(),
        degradation: Vec::new(),
        budgets_json: agent_json::budget_summary(&requested, &consumed),
        proof_pointers: vec![evidence.to_text()],
        affordances: next_ids,
        affordance_objects: next_objects,
        decision_fingerprint: decision,
        compression_receipt_id: None,
        continuation: None,
        recovery_class: "refresh_and_retry",
        safe_retry: ResponseSafeRetry::YesAfterRefresh,
        boundary: read_only_boundary(format!(
            "Searched every committed event revision at commit {}.",
            capsule.anchor.commit_sequence
        )),
        created_at_ns: capsule.created_at.0,
        workspace_revision: None,
        idempotency_key: None,
    })
}

/// Executes `explain`, returning the rendered response and its exit identity.
#[must_use]
pub fn execute_explain(args: &ExplainArgs) -> (String, ExitIdentity) {
    execute_explain_with_time(args, None)
}

pub(crate) fn execute_explain_with_time(
    args: &ExplainArgs,
    clock: crate::session_time::Clock<'_>,
) -> (String, ExitIdentity) {
    execute_explain_with_control(args, clock, &crate::RequestControl::uncancelled())
}

/// Keep event metadata, selected learning, optional custody and final delivery under one owner.
/// Completed session-clock admission retains its existing durable outcome on cancellation.
pub(crate) fn execute_explain_with_control(
    args: &ExplainArgs,
    clock: crate::session_time::Clock<'_>,
    control: &crate::RequestControl<'_>,
) -> (String, ExitIdentity) {
    let (event_id, question) = match &args.target {
        ExplainTarget::Learning {
            session,
            publication_root,
        } => {
            return learning_explain::execute(args, session, *publication_root, clock, control);
        }
        ExplainTarget::Event(event_id) => (event_id, fss_core::ExplainQuestion::Why),
        ExplainTarget::EventWhyNot(event_id) => (event_id, fss_core::ExplainQuestion::WhyNot),
        ExplainTarget::EventCounterfactual { event_id, scenario } => {
            return what_if::execute(args, event_id, scenario, control);
        }
        ExplainTarget::EventComparison {
            event_id,
            from_revision_digest,
            to_revision_digest,
        } => {
            return what_changed::execute(
                args,
                event_id,
                *from_revision_digest,
                *to_revision_digest,
                control,
            );
        }
    };
    if control.is_cancelled() {
        return crate::request_control::cancelled_read("explain", &args.root);
    }
    let Some(token_limit) = explain_options::limit(args.view, args.budget_tokens) else {
        return internal_failure_with_detail(
            "explain",
            &args.root,
            &format!(
                "invalid explain view {} or budget {:?}",
                args.view.name(),
                args.budget_tokens
            ),
        );
    };
    // No ambient clock is consulted on the existing, unchecked path.
    let started = args.custody.then(std::time::Instant::now);
    let cancelled =
        || control.is_cancelled() || started.is_some_and(|at| at.elapsed() >= custody::TIMEOUT);
    let limits = OrientLimits::default();
    let (snapshot, historical) =
        match history::read_with_control("explain", &args.root, &limits, args.at.as_ref(), control)
        {
            Ok(read) => read,
            Err(refusal) => return refusal,
        };
    let request_digest = request_identity("fss.cli.explain.request.v1", |encoder| {
        encoder.text(event_id.as_str());
        if question == fss_core::ExplainQuestion::WhyNot {
            encoder.text("question=why_not");
        }
        args.principal.encode_canonical(encoder);
        snapshot.anchor.encode_canonical(encoder);
        if let Some(scope) = &historical {
            scope.encode_request(encoder);
        }
        // Preserve every old request digest when custody was not explicitly requested.
        if args.custody {
            encoder.text("custody=yes");
        }
        if args.view != AgentView::DecisionDiff {
            encoder.text("view");
            encoder.text(args.view.id());
        }
        if let Some(tokens) = args.budget_tokens {
            encoder.text("budget_tokens");
            encoder.u64(tokens);
        }
        if let Some(path) = &args.score_calibration {
            encoder.text("score_calibration");
            encoder.text(&path.to_string_lossy());
        }
        if let Some(policy) = &args.fusion_policy {
            encoder.text("fusion_policy");
            encoder.text(policy);
        }
    });
    let interrupted = || cancelled_explanation(args, &snapshot, request_digest);
    if control.is_cancelled() {
        return interrupted();
    }
    // Every early success/refusal below is pure output from this same verified snapshot.
    // A single final gate also covers cancellation while a refusal is being rendered.
    let response = (|| {
        // For compact `decision_diff` explanations without custody expansion, compile the
        // prerequisite orientation at `Pulse` first (with principal-admitted trauma advisories,
        // matching `orient_exec`) so normal watch/corroborated events keep ample token headroom
        // for `EvidenceSupportBrief` within the registered 1,800-token cap; fall back to `Brief`
        // when `Pulse` itself cannot fit or when `Forensic`/custody is asked.
        let brief_request = OrientRequest {
            view: AgentView::Brief,
            principal: args.principal.clone(),
            // An explicit total allowance also caps the prerequisite orientation. The rest is
            // charged cumulatively by the support and optional custody projections.
            budget_tokens: args
                .budget_tokens
                .map(|tokens| tokens.min(u64::from(AgentView::Brief.maximum_tokens()))),
        };
        let orientation_result = if args.view == AgentView::DecisionDiff && !args.custody {
            let advisory_warnings =
                fss_reference::deployment_session::trauma_guard::derive_trauma_guard_warnings(
                    &args.root,
                    &args.principal,
                    snapshot.latest_evidence_time.0.max(0),
                )
                .ok();
            let pulse_request = OrientRequest {
                view: AgentView::Pulse,
                principal: args.principal.clone(),
                budget_tokens: args
                    .budget_tokens
                    .map(|tokens| tokens.min(u64::from(AgentView::Pulse.maximum_tokens()))),
            };
            match fss_reference::agent_orient::orient_deployment_with_advisories(
                &snapshot,
                &pulse_request,
                &limits,
                advisory_warnings.as_deref(),
            ) {
                Ok(orientation) => Ok(orientation),
                Err(OrientError::ContextBudgetExceeded { .. }) => {
                    orient_deployment(&snapshot, &brief_request, &limits)
                }
                Err(other) => Err(other),
            }
        } else {
            orient_deployment(&snapshot, &brief_request, &limits)
        };
        if control.is_cancelled() {
            return interrupted();
        }
        let orientation = match orientation_result {
            Ok(orientation) => orientation,
            Err(
                error @ (OrientError::ContextBudgetExceeded { .. }
                | OrientError::TooManyEvents { .. }),
            ) => {
                return rendered(
                    explain_options::orientation_refusal(
                        &snapshot,
                        request_digest,
                        args.view,
                        &args.principal,
                        token_limit,
                        error.to_string(),
                    ),
                    ExitIdentity::AGENT_REFUSED,
                    "explain",
                    &args.root,
                );
            }
            Err(error @ (OrientError::UnsupportedView(_) | OrientError::Contract(_))) => {
                return internal_failure_with_detail("explain", &args.root, &error.to_string());
            }
        };
        let explanation_result = fss_reference::agent_orient::explain_event_with_question(
            &snapshot,
            &orientation,
            event_id,
            question,
        );
        if control.is_cancelled() {
            return interrupted();
        }
        match explanation_result {
            Ok(Some(explanation)) => {
                let support_result = evidence::compile(
                    &snapshot,
                    &orientation,
                    &explanation,
                    args.view,
                    token_limit,
                );
                if control.is_cancelled() {
                    return interrupted();
                }
                let mut support = match support_result {
                    Ok(support) => support,
                    Err(error) => {
                        return rendered(
                            evidence::refusal(
                                &orientation,
                                &explanation,
                                request_digest,
                                evidence::refusal_id(&error),
                                args.view,
                                token_limit,
                            ),
                            ExitIdentity::AGENT_REFUSED,
                            "explain",
                            &args.root,
                        );
                    }
                };
                if args.custody {
                    let audit_limits =
                        fss_publication::custody_audit::CustodyAuditLimits::default();
                    let checked = match &historical {
                        Some(scope) => crate::custody_review::check_event_at(
                            &args.root,
                            &snapshot,
                            event_id,
                            audit_limits,
                            scope,
                            &cancelled,
                        ),
                        None => crate::custody_review::check_event(
                            &args.root,
                            &snapshot,
                            event_id,
                            audit_limits,
                            &cancelled,
                        ),
                    }
                    .and_then(|review| custody::augment(&mut support, &review));
                    if control.is_cancelled() {
                        return interrupted();
                    }
                    if let Err(error) = checked {
                        return rendered(
                            custody::refusal(
                                &orientation,
                                &explanation,
                                request_digest,
                                &support,
                                &error,
                            ),
                            ExitIdentity::AGENT_REFUSED,
                            "explain",
                            &args.root,
                        );
                    }
                }
                if args.score_calibration.is_some() {
                    if control.is_cancelled() {
                        return interrupted();
                    }
                    let augmented = fusion::augment(&mut support, &explanation, args);
                    if control.is_cancelled() {
                        return interrupted();
                    }
                    if let Err(error) = augmented {
                        return rendered(
                            fusion::refusal(
                                &orientation,
                                &explanation,
                                request_digest,
                                &support,
                                &error,
                            ),
                            ExitIdentity::AGENT_REFUSED,
                            "explain",
                            &args.root,
                        );
                    }
                }
                if let Some(scope) = &historical
                    && scope.augment(&mut support).is_err()
                {
                    return rendered(
                        evidence::refusal(
                            &orientation,
                            &explanation,
                            request_digest,
                            ERR_AGENT_CONTEXT_INCOMPLETE,
                            args.view,
                            token_limit,
                        ),
                        ExitIdentity::AGENT_REFUSED,
                        "explain",
                        &args.root,
                    );
                }
                let response = explanation_response(
                    &orientation,
                    &explanation,
                    request_digest,
                    &support,
                    args.custody,
                );
                if cancelled() {
                    return rendered(
                        custody::refusal(
                            &orientation,
                            &explanation,
                            request_digest,
                            &support,
                            &crate::custody_review::CustodyReviewError::Cancelled,
                        ),
                        ExitIdentity::AGENT_REFUSED,
                        "explain",
                        &args.root,
                    );
                }
                match response {
                    Ok(json) if json.len().saturating_add(1) <= evidence::MAX_RESPONSE_BYTES => {
                        (json, ExitIdentity::SUCCESS)
                    }
                    Ok(_) if args.custody => rendered(
                        custody::refusal(
                            &orientation,
                            &explanation,
                            request_digest,
                            &support,
                            &crate::custody_review::CustodyReviewError::ContextBound,
                        ),
                        ExitIdentity::AGENT_REFUSED,
                        "explain",
                        &args.root,
                    ),
                    Ok(_) => rendered(
                        evidence::refusal(
                            &orientation,
                            &explanation,
                            request_digest,
                            ERR_AGENT_CONTEXT_INCOMPLETE,
                            args.view,
                            token_limit,
                        ),
                        ExitIdentity::AGENT_REFUSED,
                        "explain",
                        &args.root,
                    ),
                    Err(error) => {
                        internal_failure_with_detail("explain", &args.root, &error.to_string())
                    }
                }
            }
            Ok(None) => rendered(
                unknown_event_response(
                    &snapshot,
                    &orientation,
                    event_id,
                    request_digest,
                    args.view,
                    token_limit,
                    historical.as_ref(),
                ),
                ExitIdentity::AGENT_REFUSED,
                "explain",
                &args.root,
            ),
            Err(error) => internal_failure_with_detail("explain", &args.root, &error.to_string()),
        }
    })();
    if control.is_cancelled() {
        interrupted()
    } else {
        response
    }
}

pub(super) fn cancelled_explanation(
    args: &ExplainArgs,
    snapshot: &DeploymentSnapshot,
    request_digest: ContentDigest,
) -> (String, ExitIdentity) {
    cancelled_explanation_at(
        args,
        &snapshot.anchor,
        snapshot.latest_evidence_time.0,
        request_digest,
    )
}

pub(super) fn cancelled_explanation_at(
    args: &ExplainArgs,
    anchor: &LedgerAnchor,
    observed_at_ns: i128,
    request_digest: ContentDigest,
) -> (String, ExitIdentity) {
    crate::request_control::cancelled_anchored_read(
        crate::request_control::CancelledRead {
            command: "explain",
            operation: "explain",
            root: &args.root,
            request_digest,
            principal: &args.principal,
            view: args.view,
            capability: CAPABILITY_EXPLAIN,
            payload_schema: AgentCognitiveEnvelope::SCHEMA,
        },
        anchor,
        observed_at_ns,
    )
}
