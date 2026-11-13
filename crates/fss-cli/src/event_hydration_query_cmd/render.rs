#![forbid(unsafe_code)]
//! Registered hydration objects with the ordinary protected cognitive and response envelopes.

use fss_core::{
    AgentCognitiveEnvelope, BudgetVector, CognitiveAnswerClass, Completeness, EnvelopeBudget,
    EnvelopeContinuity, EnvelopeCoverage, EnvelopeEpistemic, EnvelopeProposition,
    ExecutionBoundary, HydrationLevel, KnowledgeCell, KnowledgeState, ResponseOutcome,
    ResponseSafeRetry,
};
use fss_reference::deployment_session::evidence_hydration::{
    EVIDENCE_HYDRATION_CAPABILITY, EvidenceHydrationAnswer, EvidenceHydrationCharge,
    EvidenceHydrationObservation,
};

use super::{EventHydrationQueryArgs, view, wire};
use crate::agent_json;
use crate::error::ExitIdentity;
use crate::json_output::{object, string};
use crate::orient_cmd::{
    RenderError, ResponseParts, build_event_hydration_response, contexts, rendered,
    request_identity,
};

pub(super) fn boundary(completed: String, committed: bool) -> ExecutionBoundary {
    ExecutionBoundary {
        completed: vec![completed],
        not_started: vec!["No source-media hydration, model execution, device contact or external effect was requested.".to_owned()],
        possibly_occurred: if committed { Vec::new() } else { vec!["A failed or lost response may follow an agent-journal append. Inspect the retained session before repeating a non-continuation request.".to_owned()] },
        preserved_truth: vec![
            "Authority/effect history and retained source objects remain read-only. The exclusive agent journal records aliases, session charges and progressive cursor consumption.".to_owned(),
            "This is evidence about a retained event revision; it grants no physical identity, absence, continuous coverage or effect authority.".to_owned(),
        ],
        invalidated: if committed { vec!["A successfully consumed hydration continuation cannot be reused, including after process restart. A repeated non-continuation request incurs a new charge.".to_owned()] } else { Vec::new() },
    }
}

fn proposition(cell: &KnowledgeCell) -> EnvelopeProposition {
    EnvelopeProposition {
        id: cell.claim_id().to_owned(),
        statement: cell.disclosable_statement().to_owned(),
        state: cell.knowledge_state(),
        provenance: cell.provenance().as_str().to_owned(),
        evidence: cell
            .evidence_digests()
            .iter()
            .map(|digest| digest.to_text())
            .collect(),
    }
}

pub(super) fn response(
    args: &EventHydrationQueryArgs,
    answer: &EvidenceHydrationAnswer,
) -> Result<String, Box<dyn std::error::Error>> {
    answer
        .response
        .validate_for(&answer.request, &answer.descriptor)?;
    let orientation = &answer.orientation;
    let capsule = orientation.capsule();
    let receipt = &answer.response.receipt;
    let h1 = receipt.delivered_level == Some(HydrationLevel::H1);
    let native_cells = &answer.explanation.cells;
    let mut propositions: Vec<_> = capsule
        .frame
        .knowledge_cells
        .iter()
        .filter(|cell| {
            !h1 || !native_cells
                .iter()
                .any(|native| native.claim_id() == cell.claim_id())
        })
        .map(proposition)
        .collect();
    if h1 {
        propositions.extend(native_cells.iter().map(proposition));
    }
    // Every selected protected alternative is retained even at H0; the H1 explanation adds
    // complete per-event alternatives that did not fit the orientation's inline event budget.
    let world_envelope = &capsule.frame.world_envelope;
    let mut worlds = std::collections::BTreeMap::new();
    for (world, residual) in world_envelope
        .alternatives
        .iter()
        .map(|world| (world, false))
        .chain(
            world_envelope
                .adversarial_residuals
                .iter()
                .map(|world| (world, true)),
        )
    {
        worlds.insert(world.world_id.clone(), (world, residual));
    }
    if h1 {
        for world in &answer.explanation.worlds {
            worlds.insert(
                world.world_id.clone(),
                (
                    world,
                    answer.explanation.residual_ids.contains(&world.world_id),
                ),
            );
        }
    }
    propositions.extend(worlds.values().map(|(world, residual)| {
        EnvelopeProposition {
            id: world.world_id.clone(),
            statement: format!(
                "{} world{}; consequence severity {}: {}",
                if *residual {
                    "Adversarial residual"
                } else {
                    "Material alternative"
                },
                if world.protected { " (protected)" } else { "" },
                world.consequence_severity,
                world.description
            ),
            state: KnowledgeState::Unknown,
            provenance: "derived".to_owned(),
            evidence: world
                .evidence
                .iter()
                .map(|digest| digest.to_text())
                .collect(),
        }
    }));
    propositions.push(EnvelopeProposition {
        id: "hydration:committed-admission".to_owned(),
        statement: format!("Delivered {} metadata for exact retained revision {} under descriptor {}. The session journal committed {} quoted tokens; {} lifetime tokens remain. Native artifact integrity does not promote any event claim's knowledge state.",
            receipt.delivered_level.map_or("unavailable", |level| level.as_str()), answer.descriptor.subject_digest,
            answer.descriptor.descriptor_digest, answer.charged_tokens, answer.remaining_tokens),
        state: KnowledgeState::Known, provenance: "derived".to_owned(),
        evidence: vec![receipt.receipt_digest.to_text(), answer.journal_root.to_text()],
    });
    let mut assumptions = if h1 {
        answer.explanation.assumptions.clone()
    } else {
        Vec::new()
    };
    assumptions.push("The supplied principal is the local operator's audit identity, not remote authentication. Retained metadata does not establish source-media availability or physical truth.".to_owned());
    let mut invalidators = orientation.validity.invalidators.clone();
    invalidators.extend(receipt.invalidators.iter().cloned());
    if h1 {
        invalidators.extend(answer.explanation.would_change.iter().cloned());
        invalidators.extend(native_cells.iter().flat_map(|cell| cell.contradictions().iter()
            .map(move |root| format!("Claim {} retains counterevidence root {}; this contradicts the recorded claim and is not supporting evidence.",
                cell.claim_id(), root.to_text()))));
    }
    let (_, affordance_context) = contexts(orientation);
    let actions: Vec<_> = capsule
        .affordances
        .iter()
        .filter(|action| {
            matches!(
                action.affordance_id.as_str(),
                "affordance:orient:reorient"
                    | "affordance:orient:doctor"
                    | "affordance:orient:follow"
            )
        })
        .map(|action| action.affordance_id.clone())
        .collect();
    let action_objects =
        agent_json::affordance_objects(&actions, &capsule.affordances, &affordance_context)
            .ok_or(RenderError("event hydration affordance objects"))?;
    let handles = vec![agent_json::EvidenceHandle {
        handle_id: answer.descriptor.handle_id.clone(),
        object_digest: answer.descriptor.subject_digest,
        kind: answer.descriptor.semantic_type.clone(),
        hydration: receipt.delivered_level.map_or("H0", |level| level.as_str()),
        allowed_hydration: answer
            .descriptor
            .levels
            .iter()
            .map(|level| level.as_str())
            .collect(),
        privacy_class: answer.descriptor.privacy_class.clone(),
        availability: receipt.availability.as_str(),
        estimated_cost: answer.descriptor.estimated_costs[&HydrationLevel::H1],
        required_capability: Some(EVIDENCE_HYDRATION_CAPABILITY.to_owned()),
    }];
    let frame_digest = capsule.frame.frame_digest()?;
    let decision = request_identity(
        "fss.cli.event_evidence_hydration.context_decision.v1",
        |encoder| {
            encoder.digest(receipt.receipt_digest);
            encoder.digest(answer.journal_root);
            encoder.digest(frame_digest);
        },
    );
    let request_digest = answer.request.request_digest;
    let native_request_text = request_digest.to_text();
    let hex = native_request_text
        .strip_prefix("sha256:")
        .unwrap_or(&native_request_text);
    let next = receipt
        .continuation
        .as_ref()
        .map(|cursor| cursor.token().to_owned());
    let cognitive = AgentCognitiveEnvelope::new(
        capsule.contract_basis.clone(), format!("request:query:{hex}"), format!("response:query:{hex}"), format!("trace:query:{hex}"),
        "query", "query", view(args.request.level).id(), CognitiveAnswerClass::BoundedSummary, capsule.anchor.clone(),
        EnvelopeEpistemic { propositions, assumptions, invalidators },
        EnvelopeCoverage {
            authorized_domain: vec![answer.event_handle.clone()], observed_domain: vec![answer.event_handle.clone()],
            not_observable_domain: vec!["original-source-media-availability".to_owned(), "physical-event-truth-outside-retained-metadata".to_owned()],
            omitted_count: 0, omission_reasons: Vec::new(), stop_reason: "complete-selected-hydration-level".to_owned(),
        },
        EnvelopeBudget {
            requested_json: agent_json::budget(&answer.request.budget), consumed_json: agent_json::budget(&receipt.cost),
            remaining_json: agent_json::remaining(&answer.request.budget, &receipt.cost),
            degraded_dimensions: vec!["quoted-resources-not-measured-work".to_owned(), "cpu-and-output-token-measurement-unavailable".to_owned()],
            marginal_work_declined: Vec::new(),
        }, handles.iter().map(|handle| handle.handle_id.clone()).collect(), actions.clone(),
        EnvelopeContinuity {
            cursor: next.clone(), reanchor_triggers: vec!["Any authority/effect prefix, privacy, deletion, custody, descriptor, session generation or session-grant change requires fresh admission.".to_owned()],
            session_capsule_digest: None, unresolved_obligations: capsule.obligations.iter().map(|id| id.as_str().to_owned()).collect(),
        }, decision.to_text(),
    )?;
    let cognition = agent_json::cognitive_envelope(&cognitive, &handles, &action_objects)
        .ok_or(RenderError("event hydration cognitive envelope"))?;
    let payload = object(&[
        ("schema", string(EvidenceHydrationAnswer::SCHEMA)),
        ("cognition", cognition),
        ("eventHandle", string(&answer.event_handle)),
        ("anchorToken", string(answer.anchor_token.as_str())),
        ("descriptor", wire::descriptor(&answer.descriptor)),
        ("request", wire::request(&answer.request)),
        ("receipt", wire::receipt(receipt)),
        (
            "artifact",
            answer
                .response
                .artifact
                .as_ref()
                .map_or_else(|| "null".to_owned(), wire::artifact),
        ),
        (
            "admission",
            object(&[
                ("journalRoot", string(&answer.journal_root.to_text())),
                ("chargedTokens", answer.charged_tokens.to_string()),
                ("remainingTokens", answer.remaining_tokens.to_string()),
                (
                    "sessionGeneration",
                    answer.session.symbol_table_generation.to_string(),
                ),
            ]),
        ),
    ]);
    let mut warnings = orientation.warnings.clone();
    if h1 {
        warnings.extend(answer.explanation.warnings.iter().cloned());
    }
    warnings.push("Hydration returns immutable metadata and semantic assertions about the retained revision. Original claim states, contradictions and protected alternatives remain explicit. No source media, H2 artifact, H3 evidence or H4 laboratory payload is admitted.".to_owned());
    let mut contradictions = orientation.contradictions.clone();
    if h1 {
        contradictions.extend(
            native_cells
                .iter()
                .filter(|cell| {
                    !cell.contradictions().is_empty()
                        || cell.knowledge_state() == KnowledgeState::Conflicted
                })
                .map(|cell| cell.claim_id().to_owned()),
        );
        contradictions.sort();
        contradictions.dedup();
    }
    let mut proofs: Vec<_> = receipt
        .proof_roots
        .iter()
        .map(|digest| digest.to_text())
        .collect();
    proofs.extend([
        receipt.receipt_digest.to_text(),
        answer.journal_root.to_text(),
        answer.descriptor.descriptor_digest.to_text(),
    ]);
    build_event_hydration_response(ResponseParts {
        operation: "query", request_digest, principal: args.request.principal.clone(),
        session_id: Some(answer.session.session_id.as_str().to_owned()), mission_id: Some(answer.session.mission_id.as_str().to_owned()),
        anchor: capsule.anchor.clone(), view: view(args.request.level), capability: EVIDENCE_HYDRATION_CAPABILITY,
        outcome: ResponseOutcome::Ok, error_id: None, payload_schema: EvidenceHydrationAnswer::SCHEMA, payload_json: payload,
        epistemic_state: KnowledgeState::Unknown, completeness: receipt.completeness, warnings, contradictions,
        degradation: vec!["Resource vectors contain a fixed native token price and metadata read ceilings, not measured work. The quoted token charge is durable; metadata bytes/read attempts share bounded admission, while CPU, actual output tokens and filesystem syscall overhead are not metered. The 60-second deadline is cooperative.".to_owned()],
        budgets_json: agent_json::budget_summary(&answer.request.budget, &receipt.cost), proof_pointers: proofs,
        affordances: actions, affordance_objects: action_objects, decision_fingerprint: decision,
        compression_receipt_id: None, continuation: next,
        recovery_class: if receipt.continuation.is_some() { "resume_from_continuation" } else { "never_unchanged" }, safe_retry: ResponseSafeRetry::No,
        boundary: boundary("Exact metadata custody was revalidated and the native artifact was released only after the same session journal synchronized its charge and cursor state.".to_owned(), true),
        created_at_ns: receipt.issued_at.0, workspace_revision: None, idempotency_key: None,
    })
}

/// Refusal at an already observed historical anchor, with no additional storage reads.
pub(super) fn uncommitted_refusal(
    args: &EventHydrationQueryArgs,
    observed: &EvidenceHydrationObservation,
    error_id: &'static str,
) -> (String, ExitIdentity) {
    let result = (|| -> Result<String, Box<dyn std::error::Error>> {
        let decision = request_identity("fss.cli.event_evidence_hydration.refusal.v1", |encoder| {
            encoder.text(args.request.session_id.as_str());
            encoder.text(args.request.principal.as_str());
            encoder.u64(args.request.generation);
            encoder.text(args.request.event_id.as_str());
            encoder.digest(args.request.expected_revision);
            encoder.text(args.request.expected_anchor.as_str());
            encoder.text(args.request.level.as_str());
            encoder.u64(args.request.budget_tokens);
            encoder.bool(args.request.expected_descriptor.is_some());
            if let Some(descriptor) = args.request.expected_descriptor {
                encoder.digest(descriptor);
            }
            encoder.bool(args.request.continuation.is_some());
            if let Some(cursor) = &args.request.continuation {
                encoder.digest(cursor.cursor_digest);
            }
            encoder.text(error_id);
        });
        let requested = BudgetVector::builder()
            .tokens(args.request.budget_tokens)
            .build()?;
        let confirmed = BudgetVector::ZERO;
        build_event_hydration_response(ResponseParts {
            operation: "query", request_digest: decision, principal: args.request.principal.clone(),
            session_id: Some(args.request.session_id.as_str().to_owned()), mission_id: None,
            anchor: observed.anchor.clone(), view: view(args.request.level), capability: EVIDENCE_HYDRATION_CAPABILITY,
            outcome: ResponseOutcome::Refused, error_id: Some(error_id), payload_schema: EvidenceHydrationAnswer::SCHEMA,
            payload_json: "null".to_owned(), epistemic_state: KnowledgeState::Unknown, completeness: Completeness::Partial,
            warnings: vec!["No hydrated artifact was disclosed. This is the historical metadata anchor observed during admission, not a fresh custody assertion or proof of session authorization.".to_owned()],
            contradictions: Vec::new(),
            degradation: vec!["Consumed budget reports only definitely confirmed disclosure receipts. An uncertain journal append or lost response can still have charged the session; zero confirmed cost is not a refund or a known current balance.".to_owned()],
            budgets_json: agent_json::budget_summary(&requested, &confirmed), proof_pointers: Vec::new(),
            affordances: Vec::new(), affordance_objects: Vec::new(), decision_fingerprint: decision,
            compression_receipt_id: None, continuation: None, recovery_class: "operator_action_required", safe_retry: ResponseSafeRetry::No,
            boundary: boundary("Exact session, grant, metadata or disclosure admission refused. Inspect retained session state before retrying any uncertain persistence failure.".to_owned(), false),
            created_at_ns: observed.observed_at.0, workspace_revision: None, idempotency_key: None,
        })
    })();
    rendered(result, ExitIdentity::AGENT_REFUSED, "query", &args.root)
}

/// A known committed charge is preserved even when final custody, formatting or transport fails.
pub(super) fn charged_refusal(
    args: &EventHydrationQueryArgs,
    charge: &EvidenceHydrationCharge,
    error_id: &'static str,
) -> (String, ExitIdentity) {
    let result = (|| -> Result<String, Box<dyn std::error::Error>> {
        let decision = request_identity(
            "fss.cli.event_evidence_hydration.charged_refusal.v1",
            |encoder| {
                encoder.digest(charge.journal_root);
                encoder.text(error_id);
            },
        );
        let requested = BudgetVector::builder()
            .tokens(args.request.budget_tokens)
            .build()?;
        let consumed = BudgetVector::builder()
            .tokens(charge.charged_tokens)
            .build()?;
        build_event_hydration_response(ResponseParts {
            operation: "query", request_digest: decision, principal: args.request.principal.clone(),
            session_id: Some(args.request.session_id.as_str().to_owned()), mission_id: None,
            anchor: charge.anchor.clone(), view: view(args.request.level), capability: EVIDENCE_HYDRATION_CAPABILITY,
            outcome: ResponseOutcome::Refused, error_id: Some(error_id), payload_schema: EvidenceHydrationAnswer::SCHEMA,
            payload_json: "null".to_owned(), epistemic_state: KnowledgeState::Unknown, completeness: Completeness::Partial,
            warnings: vec![format!("Hydrated payload withheld after durable admission at {}. {} quoted tokens remain charged; {} session tokens remain. This historical admission anchor is not an assertion that current custody is unchanged.", charge.journal_root, charge.charged_tokens, charge.remaining_tokens)],
            contradictions: Vec::new(), degradation: vec!["The complete payload was withheld; neither an empty result nor a refund is implied. Inspect the session before retrying.".to_owned()],
            budgets_json: agent_json::budget_summary(&requested, &consumed), proof_pointers: vec![charge.journal_root.to_text()],
            affordances: Vec::new(), affordance_objects: Vec::new(), decision_fingerprint: decision,
            compression_receipt_id: None, continuation: None, recovery_class: "reconciliation_required", safe_retry: ResponseSafeRetry::No,
            boundary: boundary(format!("Session admission {} committed {} tokens before the later refusal. Any consumed cursor stays consumed.", charge.journal_root, charge.charged_tokens), true),
            created_at_ns: charge.observed_at.0, workspace_revision: None, idempotency_key: None,
        })
    })();
    rendered(result, ExitIdentity::AGENT_REFUSED, "query", &args.root)
}
