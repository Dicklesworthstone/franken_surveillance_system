#![forbid(unsafe_code)]
//! Complete adjacent revision metadata through the existing AOP-011 cognitive envelope.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use fss_core::json_input::{self, Value};
use fss_core::{
    ActionAffordance, AgentCognitiveEnvelope, BudgetVector, CognitiveAnswerClass, Completeness,
    ContentDigest, ContextAuthority, EnvelopeBudget, EnvelopeCoverage, EnvelopeEpistemic,
    EnvelopeProposition, EventId, ExplainQuestion, KnowledgeCell, KnowledgeState, OperationId,
    ResponseOutcome, ResponseSafeRetry, RootAuthoritySpec, TimestampNs,
};
use fss_reference::ReplayCx;
use fss_reference::agent_event_changes::{
    DeploymentEventChanges, EventChangesError, EventChangesLimits, EventChangesObservation,
    EventChangesRequest, prepare_event_changes_in_deployment,
};

use super::{
    CAPABILITY_EXPLAIN, CognitiveParts, ERR_AGENT_CONTEXT_INCOMPLETE, ExplainArgs, RenderError,
    ResponseParts, agent_json, build_response, cognitive_payload_with_budget, evidence,
    execution_diagnostic, internal_failure, read_only_boundary, rendered, request_identity,
};
use crate::error::ExitIdentity;

const DEADLINE: Duration = Duration::from_secs(60);
const MAX_STATEMENT_BYTES: usize = 16_384;
const MAX_PROPOSITIONS: usize = 4_096;
const SCOPE: &str = "This is a complete comparison of two exact adjacent committed event records. Before/after values describe retained declarations, including their uncertainty, not a new physical observation or a causal explanation. The selected later revision is the current head under the observed authority/effect prefix.";
const METER: &str = "One immutable metadata allowance covers history, both selected publication closures and final revalidation. Payload bytes/read attempts are exact; tokens conservatively add semantic UTF-8 bytes/4 to the existing orientation and support brief. CPU, full output tokenization, syscall overhead and elapsed latency are not measured. The 60-second deadline is cooperative.";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn json(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => out.push_str(value),
        Value::Text(value) => out.push_str(&crate::json_output::string(value)),
        Value::Array(values) => {
            out.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                json(value, out);
            }
            out.push(']');
        }
        Value::Object(values) => {
            out.push('{');
            for (index, (key, value)) in values.iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                out.push_str(&crate::json_output::string(key));
                out.push(':');
                json(value, out);
            }
            out.push('}');
        }
    }
}

fn row(
    out: &mut Vec<EnvelopeProposition>,
    path: &str,
    value: &Value,
    proof: &[String],
) -> Result<()> {
    let mut statement = format!("Recorded adjacent event metadata {path}: ");
    json(value, &mut statement);
    if out.len() >= MAX_PROPOSITIONS || statement.len() > MAX_STATEMENT_BYTES {
        return Err(RenderError("complete event comparison exceeds proposition bounds").into());
    }
    out.push(EnvelopeProposition {
        id: format!("claim:event-changes:{path}"),
        statement,
        state: KnowledgeState::Known,
        provenance: "derived".to_owned(),
        evidence: proof.to_vec(),
    });
    Ok(())
}

fn field_rows(
    out: &mut Vec<EnvelopeProposition>,
    path: &str,
    value: &Value,
    proof: &[String],
) -> Result<()> {
    if let Value::Array(values) = value {
        if !values.is_empty() {
            for (index, value) in values.iter().enumerate() {
                row(out, &format!("{path}:{index}"), value, proof)?;
            }
            return Ok(());
        }
    }
    row(out, path, value, proof)
}

fn comparison_rows(read: &DeploymentEventChanges) -> Result<Vec<EnvelopeProposition>> {
    let value = json_input::parse(read.report.to_json())?;
    let fields = value
        .object()
        .ok_or(RenderError("event comparison object"))?;
    let expected = [
        "anchorToken",
        "changes",
        "comparisonDigest",
        "from",
        "policyDigest",
        "question",
        "schema",
        "to",
    ];
    if fields.len() != expected.len() || expected.iter().any(|key| !fields.contains_key(*key)) {
        return Err(RenderError("event comparison root fields").into());
    }
    let proof = vec![
        read.comparison_digest.to_text(),
        read.receipt.receipt_digest().to_text(),
        read.report.from().revision_digest().to_text(),
        read.report.to().revision_digest().to_text(),
        read.report.from_publication_root().to_text(),
        read.report.to_publication_root().to_text(),
    ];
    let mut rows = Vec::new();
    for (key, value) in fields {
        if matches!(key.as_str(), "from" | "to") {
            let record = value
                .object()
                .ok_or(RenderError("event comparison revision wrapper"))?;
            let expected = [
                "commitSequence",
                "publicationRoot",
                "revision",
                "revisionDigest",
            ];
            if record.len() != expected.len()
                || expected.iter().any(|key| !record.contains_key(*key))
            {
                return Err(RenderError("event comparison revision fields").into());
            }
            for (field, value) in record {
                if field == "revision" {
                    let revision = value
                        .object()
                        .ok_or(RenderError("complete native event record"))?;
                    for (field, value) in revision {
                        field_rows(&mut rows, &format!("{key}:revision:{field}"), value, &proof)?;
                    }
                } else {
                    row(&mut rows, &format!("{key}:{field}"), value, &proof)?;
                }
            }
        } else {
            field_rows(&mut rows, key, value, &proof)?;
        }
    }
    Ok(rows)
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

/// Priced and checked while the immutable metadata owner still protects final admission.
struct Plan {
    epistemic: EnvelopeEpistemic,
    requested: BudgetVector,
    consumed: BudgetVector,
    handles: Vec<agent_json::EvidenceHandle>,
    actions: Vec<ActionAffordance>,
    warnings: Vec<String>,
    contradictions: Vec<String>,
    proofs: Vec<String>,
    decision: ContentDigest,
    physical: KnowledgeState,
    support_cost: String,
}

impl Plan {
    fn compile(
        args: &ExplainArgs,
        read: &DeploymentEventChanges,
        limits: EventChangesLimits,
    ) -> Result<Self> {
        let token_limit = super::explain_options::limit(args.view, args.budget_tokens)
            .ok_or(RenderError("event comparison allowance"))?;
        if read.receipt.question() != ExplainQuestion::WhatChanged {
            return Err(RenderError("event comparison question").into());
        }
        let mut current = read.explanation.clone();
        current.receipt = read.receipt.clone();
        let support = evidence::compile(
            &read.snapshot,
            &read.orientation,
            &current,
            args.view,
            token_limit,
        )?;
        if support.receipt.question() != ExplainQuestion::WhatChanged {
            return Err(RenderError("event comparison support receipt question").into());
        }
        let capsule = read.orientation.capsule();
        let mut propositions = comparison_rows(read)?;
        let mut cells = BTreeMap::new();
        for cell in capsule.frame.knowledge_cells.iter().chain(&current.cells) {
            cells.insert(cell.claim_id().to_owned(), cell);
        }
        propositions.extend(cells.values().map(|cell| proposition(cell)));
        let mut worlds = BTreeMap::new();
        for (world, residual) in capsule
            .frame
            .world_envelope
            .alternatives
            .iter()
            .map(|world| (world, false))
            .chain(
                capsule
                    .frame
                    .world_envelope
                    .adversarial_residuals
                    .iter()
                    .map(|world| (world, true)),
            )
            .chain(
                current
                    .worlds
                    .iter()
                    .map(|world| (world, current.residual_ids.contains(&world.world_id))),
            )
        {
            worlds.insert(world.world_id.clone(), (world, residual));
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
        let added_propositions = propositions.len();
        propositions.extend(support.propositions.iter().cloned());
        let mut assumptions = current.assumptions.clone();
        assumptions.push(SCOPE.to_owned());
        assumptions.extend(support.assumptions.iter().cloned());
        let mut invalidators = read.orientation.validity.invalidators.clone();
        invalidators.extend(current.would_change.iter().cloned());
        invalidators.extend(support.invalidators.iter().cloned());
        for cell in cells.values() {
            for digest in cell.contradictions() {
                invalidators.push(format!("Claim {} retains contradicting evidence {}; this is counterevidence, not supporting evidence.", cell.claim_id(), digest));
            }
        }
        let mut warnings = read.orientation.warnings.clone();
        warnings.extend(current.warnings.iter().cloned());
        warnings.extend(support.warnings.iter().cloned());
        warnings.push("Both exact event records and every changed native field are present. Metadata custody is verified; original evidence payloads are not read or disclosed. Historical values receive no restored authority and this comparison changes no event, policy or effect.".to_owned());
        let mut proofs = support.proof_pointers.clone();
        proofs.extend(
            read.receipt
                .evidence_subgraph()
                .iter()
                .map(|digest| digest.to_text()),
        );
        proofs.extend([
            read.comparison_digest.to_text(),
            read.receipt.receipt_digest().to_text(),
            support.receipt.receipt_digest().to_text(),
        ]);
        proofs.sort();
        proofs.dedup();
        let frame_digest = capsule.frame.frame_digest()?;
        let decision = request_identity("fss.cli.event_changes.context_decision.v1", |encoder| {
            encoder.digest(read.request_digest);
            encoder.digest(read.comparison_digest);
            encoder.digest(read.receipt.receipt_digest());
            encoder.digest(support.receipt.receipt_digest());
            encoder.digest(frame_digest);
        });
        let mut requested = limits.allowance()?;
        requested.tokens = token_limit;
        let mut consumed = support.consumed;
        let mut extra_bytes = 0_u64;
        let mut add = |text: &str| -> Result<()> {
            extra_bytes = extra_bytes
                .checked_add(text.len() as u64)
                .ok_or(RenderError("event comparison semantic byte overflow"))?;
            Ok(())
        };
        for proposition in &propositions[..added_propositions] {
            for text in [
                &proposition.id,
                &proposition.statement,
                &proposition.provenance,
            ] {
                add(text)?;
            }
            add(proposition.state.as_str())?;
            for proof in &proposition.evidence {
                add(proof)?;
            }
        }
        for text in assumptions
            .iter()
            .chain(&invalidators)
            .chain(&warnings)
            .chain(&proofs)
        {
            add(text)?;
        }
        add(METER)?;
        consumed.tokens = consumed
            .tokens
            .checked_add(extra_bytes.div_ceil(4))
            .ok_or(RenderError("event comparison token overflow"))?;
        if consumed.tokens > token_limit || propositions.len() > MAX_PROPOSITIONS {
            return Err(RenderError(
                "complete comparison and protected context exceed the selected allowance",
            )
            .into());
        }
        let mut handle_rows = BTreeMap::new();
        for (revision, publication) in [
            (read.report.from(), read.report.from_publication_root()),
            (read.report.to(), read.report.to_publication_root()),
        ] {
            handle_rows.insert(revision.revision_digest(), "event_revision");
            handle_rows.insert(publication, "event_manifest");
        }
        let handles = handle_rows
            .into_iter()
            .map(|(digest, kind)| agent_json::EvidenceHandle {
                handle_id: format!("fss://proof/{digest}"),
                object_digest: digest,
                kind: kind.to_owned(),
                hydration: "H0",
                allowed_hydration: vec!["H0"],
                privacy_class: super::EVENT_PRIVACY_CLASS.to_owned(),
                availability: "available",
                estimated_cost: BudgetVector::ZERO,
                required_capability: Some(CAPABILITY_EXPLAIN.to_owned()),
            })
            .collect();
        let physical = current
            .cells
            .iter()
            .find(|cell| cell.claim_id().ends_with(":unknown-presence"))
            .map_or(KnowledgeState::Unknown, |cell| cell.knowledge_state());
        let mut contradictions = read.orientation.contradictions.clone();
        contradictions.extend(
            cells
                .values()
                .filter(|cell| {
                    !cell.contradictions().is_empty()
                        || cell.knowledge_state() == KnowledgeState::Conflicted
                })
                .map(|cell| cell.claim_id().to_owned()),
        );
        contradictions.sort();
        contradictions.dedup();
        Ok(Self {
            epistemic: EnvelopeEpistemic {
                propositions,
                assumptions,
                invalidators,
            },
            requested,
            consumed,
            handles,
            actions: current.affordances.clone(),
            warnings,
            contradictions,
            proofs,
            decision,
            physical,
            support_cost: support.cost_statement,
        })
    }

    /// Only pure serialization and final counter copying happen after native final admission.
    fn render(&self, args: &ExplainArgs, read: &DeploymentEventChanges) -> Result<String> {
        let mut consumed = self.consumed;
        consumed.bytes = read.read_usage.read_bytes;
        consumed.storage_operations = read.read_usage.read_objects;
        let handles = [read.report.from(), read.report.to()]
            .map(|event| {
                format!(
                    "fss://event/{}/revision/{}",
                    event.event_id.as_str(),
                    event.revision
                )
            })
            .to_vec();
        let (payload, actions, action_objects) = cognitive_payload_with_budget(
            &read.orientation, read.request_digest, "explain", args.view,
            CognitiveParts {
                answer_class: CognitiveAnswerClass::BoundedSummary, epistemic: self.epistemic.clone(),
                coverage: EnvelopeCoverage {
                    authorized_domain: handles.clone(), observed_domain: handles,
                    not_observable_domain: vec!["original-source-media-availability".to_owned(), "physical-causes-or-truth-inferred-from-record-changes".to_owned()],
                    omitted_count: 0, omission_reasons: Vec::new(), stop_reason: "complete-exact-adjacent-revision-comparison".to_owned(),
                }, evidence_handles: self.handles.clone(), next_actions: self.actions.clone(), decision_digest: self.decision,
            },
            Some(EnvelopeBudget {
                requested_json: agent_json::budget(&self.requested), consumed_json: agent_json::budget(&consumed), remaining_json: agent_json::remaining(&self.requested, &consumed),
                degraded_dimensions: vec![METER.to_owned()], marginal_work_declined: vec!["Original evidence hydration, hypothetical branches, event/policy updates and effects.".to_owned()],
            }),
        )?;
        let capsule = read.orientation.capsule();
        build_response(ResponseParts {
            operation: "explain", request_digest: read.request_digest, principal: args.principal.clone(),
            session_id: Some(capsule.session_id.as_str().to_owned()), mission_id: Some(capsule.mission_id.as_str().to_owned()),
            anchor: capsule.anchor.clone(), view: args.view, capability: CAPABILITY_EXPLAIN,
            outcome: ResponseOutcome::Ok, error_id: None, payload_schema: AgentCognitiveEnvelope::SCHEMA, payload_json: payload,
            epistemic_state: self.physical, completeness: Completeness::Complete, warnings: self.warnings.clone(), contradictions: self.contradictions.clone(),
            degradation: vec![METER.to_owned(), self.support_cost.clone()], budgets_json: agent_json::budget_summary(&self.requested, &consumed),
            proof_pointers: self.proofs.clone(), affordances: actions, affordance_objects: action_objects, decision_fingerprint: self.decision,
            compression_receipt_id: None, continuation: None, recovery_class: "safe_read_retry", safe_retry: ResponseSafeRetry::YesSameRequest,
            boundary: read_only_boundary("Compared both exact adjacent event records and every native field after final selected-metadata and authority/effect revalidation. No source-media read, publisher lock, recovery, session write, event revision or effect occurred.".to_owned()),
            created_at_ns: capsule.created_at.0, workspace_revision: None, idempotency_key: None,
        })
    }
}

fn refused(
    args: &ExplainArgs,
    request_digest: ContentDigest,
    observation: &EventChangesObservation,
    error_id: &'static str,
    reason: &str,
) -> (String, ExitIdentity) {
    let result = (|| -> Result<String> {
        let mut requested = EventChangesLimits::default().allowance()?;
        requested.tokens =
            super::explain_options::limit(args.view, args.budget_tokens).unwrap_or(0);
        let mut consumed = BudgetVector::ZERO;
        consumed.bytes = observation.read_usage.read_bytes;
        consumed.storage_operations = observation.read_usage.read_objects;
        build_response(ResponseParts {
            operation: "explain", request_digest, principal: args.principal.clone(), session_id: None, mission_id: None,
            anchor: observation.anchor.clone(), view: args.view, capability: CAPABILITY_EXPLAIN,
            outcome: ResponseOutcome::Refused, error_id: Some(error_id), payload_schema: AgentCognitiveEnvelope::SCHEMA, payload_json: "null".to_owned(),
            epistemic_state: KnowledgeState::Unknown, completeness: Completeness::Partial,
            warnings: vec![reason.to_owned(), "No comparison prefix was delivered. The response anchor is an already observed metadata scope, not a renewed assertion of current custody. Explicitly refresh exact revision pins or request a sufficient registered view; no allowance was widened.".to_owned()],
            contradictions: Vec::new(), degradation: vec!["Only completed payload reads are reported. Failed projection work has no completed token receipt and is not claimed to be free.".to_owned()],
            budgets_json: agent_json::budget_summary(&requested, &consumed), proof_pointers: Vec::new(), affordances: Vec::new(), affordance_objects: Vec::new(),
            decision_fingerprint: request_digest, compression_receipt_id: None, continuation: None, recovery_class: "refresh_and_retry", safe_retry: ResponseSafeRetry::YesAfterRefresh,
            boundary: read_only_boundary("The complete exact adjacent event comparison was withheld. No source-media or fallback read was performed to render this refusal.".to_owned()),
            created_at_ns: observation.observed_at.0, workspace_revision: None, idempotency_key: None,
        })
    })();
    rendered(result, ExitIdentity::AGENT_REFUSED, "explain", &args.root)
}

fn failed(
    args: &ExplainArgs,
    request_digest: ContentDigest,
    error: EventChangesError,
) -> (String, ExitIdentity) {
    if let Some(observation) = &error.observation {
        refused(
            args,
            request_digest,
            observation,
            error.code(),
            error.reason(),
        )
    } else {
        (
            execution_diagnostic(
                "explain",
                &args.root,
                error.code(),
                ExitIdentity::AGENT_REFUSED,
            ),
            ExitIdentity::AGENT_REFUSED,
        )
    }
}

pub(super) fn execute(
    args: &ExplainArgs,
    event_id: &EventId,
    from_revision_digest: ContentDigest,
    to_revision_digest: ContentDigest,
) -> (String, ExitIdentity) {
    if args.at.is_some()
        || args.custody
        || args.score_calibration.is_some()
        || args.fusion_policy.is_some()
    {
        return (
            execution_diagnostic(
                "explain",
                &args.root,
                "ERR-AGENT-PROTOCOL-001",
                ExitIdentity::AGENT_REFUSED,
            ),
            ExitIdentity::AGENT_REFUSED,
        );
    }
    let request = EventChangesRequest {
        event_id: event_id.clone(),
        from_revision_digest,
        to_revision_digest,
        principal: args.principal.clone(),
        expected_anchor: None,
        view: args.view,
        budget_tokens: args.budget_tokens,
    };
    let input = request_identity("fss.cli.event_changes.request_scope.v1", |encoder| {
        encoder.text(event_id.as_str());
        encoder.digest(from_revision_digest);
        encoder.digest(to_revision_digest);
        encoder.text(args.principal.as_str());
        encoder.text(args.view.id());
        encoder.bool(args.budget_tokens.is_some());
        if let Some(tokens) = args.budget_tokens {
            encoder.u64(tokens);
        }
    });
    if let Err(error) = request.validate() {
        return failed(args, input, error);
    }
    let limits = EventChangesLimits::default();
    let allowance = match limits.allowance() {
        Ok(allowance) => allowance,
        Err(error) => return failed(args, input, error),
    };
    let authority = match OperationId::parse("operation:explain-event-changes")
        .map_err(|_| ())
        .and_then(|operation_id| {
            ContextAuthority::new_root(RootAuthoritySpec {
                trace_id: "trace:explain-event-changes".to_owned(),
                operation_id,
                principal: args.principal.as_str().to_owned(),
                capabilities: vec![CAPABILITY_EXPLAIN.to_owned(), "ADP-REPLAY-001".to_owned()],
                deadline: Some(TimestampNs(60_000_000_000)),
                priority: 10,
                budgets: allowance,
                privacy_scope: "privacy:event-metadata".to_owned(),
                retention_scope: "retention:current-deletion-restrictions".to_owned(),
                anchor_universe: input,
                generation: 1,
            })
            .map_err(|_| ())
        }) {
        Ok(authority) => authority,
        Err(()) => return internal_failure("explain", &args.root),
    };
    let cx = match ReplayCx::from_context_authority_read_only(&authority, &args.root) {
        Ok(cx) => cx,
        Err(_) => return internal_failure("explain", &args.root),
    };
    let started = Instant::now();
    let cancelled = || authority.cancellation_reason.is_some() || started.elapsed() >= DEADLINE;
    let prepared =
        match prepare_event_changes_in_deployment(&args.root, &request, limits, &cx, &cancelled) {
            Ok(prepared) => prepared,
            Err(error) => {
                cx.drain_and_finalize();
                return failed(args, input, error);
            }
        };
    let observation = EventChangesObservation {
        anchor: prepared.answer().snapshot.anchor.clone(),
        anchor_token: prepared.answer().anchor_token.clone(),
        observed_at: prepared.answer().snapshot.latest_evidence_time,
        read_usage: prepared.answer().read_usage,
    };
    let plan = match Plan::compile(args, prepared.answer(), limits) {
        Ok(plan) => plan,
        Err(_) => {
            drop(prepared);
            cx.drain_and_finalize();
            return refused(
                args,
                input,
                &observation,
                ERR_AGENT_CONTEXT_INCOMPLETE,
                "The complete comparison and protected current context do not fit the selected response allowance.",
            );
        }
    };
    match plan.render(args, prepared.answer()) {
        Ok(output)
            if output.len().saturating_add(1) <= evidence::MAX_RESPONSE_BYTES && !cancelled() => {}
        _ => {
            drop(prepared);
            cx.drain_and_finalize();
            return refused(
                args,
                input,
                &observation,
                ERR_AGENT_CONTEXT_INCOMPLETE,
                "Complete comparison output exceeded the selected byte/context allowance or cooperative deadline.",
            );
        }
    }
    let answer = match prepared.finish() {
        Ok(answer) => answer,
        Err(error) => {
            cx.drain_and_finalize();
            return failed(args, input, error);
        }
    };
    cx.drain_and_finalize();
    // No callback or I/O follows successful final admission; only exact counters and pure JSON.
    match plan.render(args, &answer) {
        Ok(output) if output.len().saturating_add(1) <= evidence::MAX_RESPONSE_BYTES => {
            (output, ExitIdentity::SUCCESS)
        }
        _ => refused(
            args,
            answer.request_digest,
            &EventChangesObservation {
                anchor: answer.snapshot.anchor.clone(),
                anchor_token: answer.anchor_token.clone(),
                observed_at: answer.snapshot.latest_evidence_time,
                read_usage: answer.read_usage,
            },
            ERR_AGENT_CONTEXT_INCOMPLETE,
            "The complete final response exceeds its registered output bounds; no partial comparison was delivered.",
        ),
    }
}
