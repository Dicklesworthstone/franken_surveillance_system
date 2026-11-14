#![forbid(unsafe_code)]
//! Hypothetical declared-source loss under current immutable metadata authority.
//!
//! Complete numerical artifacts share one bounded read allowance with protected current context
//! and final custody revalidation. This path never opens media or alters a deployment.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use fss_core::json_input::{self, Value};
use fss_core::{
    ActionAffordance, AgentCognitiveEnvelope, AgentView, BudgetVector, CognitiveAnswerClass, Completeness,
    ContentDigest, ContextAuthority, EnvelopeBudget, EnvelopeCoverage, EnvelopeEpistemic,
    EnvelopeProposition, EventId, ExplainQuestion, KnowledgeCell, KnowledgeState, LedgerAnchor, OperationId,
    ResponseOutcome, ResponseSafeRetry, RootAuthoritySpec, TimestampNs,
};
use fss_reference::ReplayCx;
use fss_reference::agent_event_changes::EventChangesLimits as MetadataLimits;
use fss_reference::agent_follow::snapshot_anchor_token;
use fss_reference::agent_orient::{
    DeploymentOrientation, DeploymentSnapshot, EventExplanation, OrientRequest, explain_event,
    orient_deployment,
};
use fss_reference::retained_source::{
    ImmutableRetainedSource, RetainedReadUsage, verify_event_lineage,
};
use crate::event_counterfactual::{EventCounterfactual, EventCounterfactualRequest};

use super::{
    CAPABILITY_EXPLAIN, CognitiveParts, ERR_AGENT_CONTEXT_INCOMPLETE, ExplainArgs, RenderError,
    ResponseParts, agent_json, build_response, cognitive_payload_with_budget, evidence,
    execution_diagnostic, internal_failure, read_only_boundary, rendered, request_identity,
};
use crate::error::ExitIdentity;

const DEADLINE: Duration = Duration::from_secs(60);
const MAX_STATEMENT_BYTES: usize = 16_384;
const MAX_PROPOSITIONS: usize = 4_096;
const SCOPE: &str = "This is hypothetical loss of explicitly selected declared failure domains, using caller-supplied raw scores and verified calibration counts. It preserves the complete current event declaration and recomputes both numerical queries. It does not replay the historical decision, establish physical sensor independence or coverage, or grant effect authority.";
const METER: &str = "One immutable metadata allowance covers history, current event publication lineages and final revalidation. Payload bytes/read attempts are exact; tokens conservatively add semantic UTF-8 bytes/4 to the existing orientation and support brief. CPU, full output tokenization, syscall overhead and elapsed latency are not measured. The 60-second deadline is cooperative.";

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

fn pointer_segment(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn artifact_rows(
    out: &mut Vec<EnvelopeProposition>,
    pointer: &str,
    value: &Value,
    proof: &[String],
) -> Result<()> {
    let mut encoded = String::new();
    json(value, &mut encoded);
    // Keep complete small subtrees together so repeating labels and proofs does not crowd out
    // the computation. Oversized containers split at exact JSON pointers, never by truncation.
    if encoded.len() > 2_048 {
        match value {
            Value::Object(fields) if !fields.is_empty() => {
                for (name, value) in fields {
                    artifact_rows(out, &format!("{pointer}/{}", pointer_segment(name)), value, proof)?;
                }
                return Ok(());
            }
            Value::Array(values) if !values.is_empty() => {
                for (index, value) in values.iter().enumerate() {
                    artifact_rows(out, &format!("{pointer}/{index}"), value, proof)?;
                }
                return Ok(());
            }
            _ => {}
        }
    }
    let statement = format!("Hypothetical source-loss artifact at {pointer}: {encoded}");
    if out.len() >= MAX_PROPOSITIONS || statement.len() > MAX_STATEMENT_BYTES {
        return Err(RenderError("complete counterfactual exceeds proposition bounds").into());
    }
    out.push(EnvelopeProposition {
        id: format!("claim:event-counterfactual:row:{}", out.len()),
        statement,
        state: KnowledgeState::Unknown,
        provenance: "derived".to_owned(),
        evidence: proof.to_vec(),
    });
    Ok(())
}

fn counterfactual_rows(report: &EventCounterfactual) -> Result<Vec<EnvelopeProposition>> {
    let complete = report.to_json()?;
    let value = json_input::parse(&complete)?;
    let fields = value.object().ok_or(RenderError("complete counterfactual object"))?;
    let proof = vec![report.digest().to_text()];
    let mut rows = Vec::new();
    for (name, value) in fields {
        artifact_rows(&mut rows, &format!("/{}", pointer_segment(name)), value, &proof)?;
    }
    Ok(rows)
}

struct CounterfactualRead {
    snapshot: DeploymentSnapshot,
    orientation: DeploymentOrientation,
    explanation: EventExplanation,
    report: EventCounterfactual,
    request_digest: ContentDigest,
    read_usage: RetainedReadUsage,
}

struct Observation {
    anchor: LedgerAnchor,
    observed_at: TimestampNs,
    read_usage: RetainedReadUsage,
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
        read: &CounterfactualRead,
        limits: MetadataLimits,
    ) -> Result<Self> {
        let token_limit = super::explain_options::limit(args.view, args.budget_tokens)
            .ok_or(RenderError("event counterfactual allowance"))?;
        if read.report.receipt().question() != ExplainQuestion::WhatIf {
            return Err(RenderError("event counterfactual question").into());
        }
        let mut current = read.explanation.clone();
        current.receipt = read.report.receipt().clone();
        let support = evidence::compile(
            &read.snapshot,
            &read.orientation,
            &current,
            args.view,
            token_limit,
        )?;
        if support.receipt.question() != ExplainQuestion::WhatIf {
            return Err(RenderError("event counterfactual support receipt question").into());
        }
        let capsule = read.orientation.capsule();
        let mut propositions = counterfactual_rows(&read.report)?;
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
        warnings.push("The complete numerical baseline, projected query, results and caller assumptions are present alongside the original event. Current metadata custody is verified; original source and model payloads are not read. Every derived scenario is hypothetical and supplies no new physical claim or authority.".to_owned());
        let mut proofs = support.proof_pointers.clone();
        proofs.extend(
            read.report.receipt()
                .evidence_subgraph()
                .iter()
                .map(|digest| digest.to_text()),
        );
        proofs.extend([
            read.report.digest().to_text(),
            read.report.receipt().receipt_digest().to_text(),
            support.receipt.receipt_digest().to_text(),
        ]);
        proofs.sort();
        proofs.dedup();
        let frame_digest = capsule.frame.frame_digest()?;
        let decision = request_identity("fss.cli.event_counterfactual.context_decision.v1", |encoder| {
            encoder.digest(read.request_digest);
            encoder.digest(read.report.digest());
            encoder.digest(read.report.receipt().receipt_digest());
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
                .ok_or(RenderError("event counterfactual semantic byte overflow"))?;
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
            .ok_or(RenderError("event counterfactual token overflow"))?;
        if consumed.tokens > token_limit || propositions.len() > MAX_PROPOSITIONS {
            return Err(RenderError(
                "complete counterfactual and protected context exceed the selected allowance",
            )
            .into());
        }
        let mut handle_rows = BTreeMap::new();
        handle_rows.insert(read.explanation.event.revision_digest, "event_revision");
        handle_rows.insert(read.explanation.event.event_root, "event_manifest");
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
        // A hypothetical numerical answer is never a fresh physical observation.
        let physical = KnowledgeState::Unknown;
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
    fn render(&self, args: &ExplainArgs, read: &CounterfactualRead) -> Result<String> {
        let mut consumed = self.consumed;
        consumed.bytes = read.read_usage.read_bytes;
        consumed.storage_operations = read.read_usage.read_objects;
        let event = &read.explanation.event.event;
        let handles = vec![format!(
            "fss://event/{}/revision/{}", event.event_id.as_str(), event.revision
        )];
        let (payload, actions, action_objects) = cognitive_payload_with_budget(
            &read.orientation, read.request_digest, "explain", args.view,
            CognitiveParts {
                answer_class: CognitiveAnswerClass::BoundedSummary, epistemic: self.epistemic.clone(),
                coverage: EnvelopeCoverage {
                    authorized_domain: handles.clone(), observed_domain: handles,
                    not_observable_domain: vec!["original-source-media-availability".to_owned(), "physical-sensor-independence".to_owned(), "current-physical-coverage".to_owned(), "physical-truth-of-hypothetical-source-loss".to_owned()],
                    omitted_count: 0, omission_reasons: Vec::new(), stop_reason: "complete-hypothetical-declared-domain-loss".to_owned(),
                }, evidence_handles: self.handles.clone(), next_actions: self.actions.clone(), decision_digest: self.decision,
            },
            Some(EnvelopeBudget {
                requested_json: agent_json::budget(&self.requested), consumed_json: agent_json::budget(&consumed), remaining_json: agent_json::remaining(&self.requested, &consumed),
                degraded_dimensions: vec![METER.to_owned()], marginal_work_declined: vec!["Original evidence hydration, sensor-identity inference, historical-policy replay, event/policy updates and effects.".to_owned()],
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
            boundary: read_only_boundary("Recomputed complete caller-declared source-loss sensitivity after current metadata and authority/effect revalidation. No source-media read, publisher lock, recovery, session write, event revision or effect occurred.".to_owned()),
            created_at_ns: capsule.created_at.0, workspace_revision: None, idempotency_key: None,
        })
    }
}

fn refused(
    args: &ExplainArgs,
    request_digest: ContentDigest,
    observation: &Observation,
    error_id: &'static str,
    reason: &str,
) -> (String, ExitIdentity) {
    let result = (|| -> Result<String> {
        let mut requested = MetadataLimits::default().allowance()?;
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
            warnings: vec![reason.to_owned(), "No hypothetical artifact prefix was delivered. The response anchor is an already observed metadata scope, not a renewed assertion of current custody. Explicitly refresh the exact revision pin or request a sufficient registered view; no allowance was widened.".to_owned()],
            contradictions: Vec::new(), degradation: vec!["Only completed payload reads are reported. Failed projection work has no completed token receipt and is not claimed to be free.".to_owned()],
            budgets_json: agent_json::budget_summary(&requested, &consumed), proof_pointers: Vec::new(), affordances: Vec::new(), affordance_objects: Vec::new(),
            decision_fingerprint: request_digest, compression_receipt_id: None, continuation: None, recovery_class: "refresh_and_retry", safe_retry: ResponseSafeRetry::YesAfterRefresh,
            boundary: read_only_boundary("The complete hypothetical source-loss analysis was withheld. No source-media or fallback read was performed to render this refusal.".to_owned()),
            created_at_ns: observation.observed_at.0, workspace_revision: None, idempotency_key: None,
        })
    })();
    rendered(result, ExitIdentity::AGENT_REFUSED, "explain", &args.root)
}

type Failure = (&'static str, &'static str);

pub(super) fn execute(
    args: &ExplainArgs,
    event_id: &EventId,
    scenario: &str,
) -> (String, ExitIdentity) {
    if args.at.is_some()
        || args.custody
        || args.score_calibration.is_some()
        || args.fusion_policy.is_some()
        || super::explain_options::limit(args.view, args.budget_tokens).is_none()
    {
        return (
            execution_diagnostic("explain", &args.root, "ERR-AGENT-PROTOCOL-001", ExitIdentity::AGENT_REFUSED),
            ExitIdentity::AGENT_REFUSED,
        );
    }
    let request = match EventCounterfactualRequest::parse(scenario) {
        Ok(request) => request,
        Err(error) => {
            return (
                execution_diagnostic("explain", &args.root, error.stable_id(), ExitIdentity::AGENT_REFUSED),
                ExitIdentity::AGENT_REFUSED,
            );
        }
    };
    let input = request_identity("fss.cli.event_counterfactual.request_scope.v1", |encoder| {
        encoder.text(event_id.as_str());
        encoder.digest(request.request_digest());
        encoder.text(args.principal.as_str());
        encoder.text(args.view.id());
        encoder.bool(args.budget_tokens.is_some());
        if let Some(tokens) = args.budget_tokens {
            encoder.u64(tokens);
        }
    });
    let limits = MetadataLimits::default();
    let allowance = match limits.allowance() {
        Ok(allowance) => allowance,
        Err(_) => return internal_failure("explain", &args.root),
    };
    let authority = match OperationId::parse("operation:explain-event-counterfactual")
        .map_err(|_| ())
        .and_then(|operation_id| {
            ContextAuthority::new_root(RootAuthoritySpec {
                trace_id: "trace:explain-event-counterfactual".to_owned(),
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
    let owner = match ImmutableRetainedSource::open_cancellable(&args.root, limits.read, &cx, &cancelled) {
        Ok(owner) => owner,
        Err(_) => {
            cx.drain_and_finalize();
            return (
                execution_diagnostic("explain", &args.root, ERR_AGENT_CONTEXT_INCOMPLETE, ExitIdentity::AGENT_REFUSED),
                ExitIdentity::AGENT_REFUSED,
            );
        }
    };
    let mut observation = Observation {
        anchor: owner.snapshot().anchor.clone(),
        observed_at: owner.snapshot().latest_evidence_time,
        read_usage: owner.usage(),
    };
    let prepared = (|| -> std::result::Result<(CounterfactualRead, Plan), Failure> {
        let selected = owner.snapshot().event(event_id).ok_or((
            "ERR-AGENT-EVENT-NOT-FOUND-001",
            "No currently retained event has the requested exact identity.",
        ))?;
        if selected.event.revision_digest() != request.expected_revision()
            || selected.revision_digest != request.expected_revision()
            || selected.revisions.last() != Some(&selected.event)
        {
            return Err((
                "ERR-AGENT-RESNAPSHOT-001",
                "The supplied exact event revision is no longer the current retained head.",
            ));
        }
        // The protected context and support graph can refer to other current events. Register
        // every such canonical metadata dependency with this same owner for final rereading.
        for retained in &owner.snapshot().events {
            let publications = verify_event_lineage(
                &owner,
                &retained.revisions,
                limits.read.snapshot.max_object_bytes,
            ).map_err(|_| (
                ERR_AGENT_CONTEXT_INCOMPLETE,
                "Current event publication metadata could not be verified under this allowance.",
            ))?;
            if publications.last().copied() != Some((retained.event_root, retained.committed_sequence))
                || retained.revision_digest != retained.event.revision_digest()
                || retained.revisions.last() != Some(&retained.event)
            {
                return Err((
                    ERR_AGENT_CONTEXT_INCOMPLETE,
                    "Current event records do not agree with their exact committed publications.",
                ));
            }
        }
        if cancelled() || cx.checkpoint("event_counterfactual:compile").is_err() {
            return Err(("ERR-AUTH-DENIED-001", "The immutable metadata deadline or authority expired."));
        }
        let mut snapshot = owner.snapshot().clone();
        snapshot.bytes_read = owner.usage().read_bytes;
        snapshot.files_read = owner.usage().read_objects;
        let orientation = orient_deployment(
            &snapshot,
            &OrientRequest {
                view: AgentView::Brief,
                principal: args.principal.clone(),
                budget_tokens: args.budget_tokens.map(|tokens| tokens.min(u64::from(AgentView::Brief.maximum_tokens()))),
            },
            &limits.read.snapshot,
        ).map_err(|_| (
            ERR_AGENT_CONTEXT_INCOMPLETE,
            "The protected current orientation cannot fit the selected allowance.",
        ))?;
        let explanation = explain_event(&snapshot, &orientation, event_id)
            .map_err(|_| (ERR_AGENT_CONTEXT_INCOMPLETE, "The complete current explanation is unavailable."))?
            .ok_or(("ERR-AGENT-EVENT-NOT-FOUND-001", "The exact current event explanation is unavailable."))?;
        let report = request.compute(&explanation).map_err(|error| (
            error.stable_id(),
            "The complete hypothetical request does not match the retained event or exceeds its numerical bounds.",
        ))?;
        let token = snapshot_anchor_token(&snapshot);
        let request_digest = request_identity("fss.cli.event_counterfactual.request.v1", |encoder| {
            encoder.digest(input);
            encoder.text(&token);
            encoder.u64(limits.read.max_read_bytes as u64);
            encoder.u64(limits.read.max_read_objects as u64);
        });
        let mut read = CounterfactualRead {
            snapshot, orientation, explanation, report, request_digest, read_usage: owner.usage(),
        };
        let plan = Plan::compile(args, &read, limits).map_err(|_| (
            ERR_AGENT_CONTEXT_INCOMPLETE,
            "The whole hypothetical artifact and protected current context do not fit the selected allowance.",
        ))?;
        match plan.render(args, &read) {
            Ok(output) if output.len().saturating_add(1) <= evidence::MAX_RESPONSE_BYTES && !cancelled() => {}
            _ => return Err((
                ERR_AGENT_CONTEXT_INCOMPLETE,
                "The complete output exceeds its byte/context allowance or cooperative deadline.",
            )),
        }
        owner.revalidate_snapshot_metadata().map_err(|_| (
            ERR_AGENT_CONTEXT_INCOMPLETE,
            "Protected current context metadata changed before the complete answer could be admitted.",
        ))?;
        owner.revalidate().map_err(|_| (
            ERR_AGENT_CONTEXT_INCOMPLETE,
            "Current metadata custody or authority changed before the complete answer could be admitted.",
        ))?;
        // No callback, source read or renewed allowance follows the final authority observation.
        read.read_usage = owner.usage();
        read.snapshot.bytes_read = read.read_usage.read_bytes;
        read.snapshot.files_read = read.read_usage.read_objects;
        read.orientation.consumed.bytes = read.read_usage.read_bytes;
        read.orientation.consumed.storage_operations = read.read_usage.read_objects;
        Ok((read, plan))
    })();
    observation.read_usage = owner.usage();
    drop(owner);
    cx.drain_and_finalize();
    match prepared {
        Ok((read, plan)) => match plan.render(args, &read) {
            Ok(output) if output.len().saturating_add(1) <= evidence::MAX_RESPONSE_BYTES => {
                (output, ExitIdentity::SUCCESS)
            }
            _ => refused(
                args, read.request_digest, &observation, ERR_AGENT_CONTEXT_INCOMPLETE,
                "The complete final response exceeds its registered bounds; no hypothetical prefix was delivered.",
            ),
        },
        Err((code, reason)) => refused(args, input, &observation, code, reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_pointer_projection_keeps_escaped_keys_empty_shapes_and_large_subtrees() {
        let source = format!(
            "{{\"a/b~c\":[],\"empty\":{{}},\"large\":{{\"text\":{}}}}}",
            crate::json_output::string(&"x".repeat(2_100)),
        );
        let value = json_input::parse(&source).unwrap();
        let mut rows = Vec::new();
        artifact_rows(&mut rows, "", &value, &[]).unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows[0].statement.contains("at /a~1b~0c: []"));
        assert!(rows[1].statement.contains("at /empty: {}"));
        assert!(rows[2].statement.contains("at /large/text: "));
        assert!(rows[2].statement.contains(&"x".repeat(2_100)));
        assert!(rows.iter().all(|row| row.state == KnowledgeState::Unknown));
    }

    #[test]
    fn oversized_scalar_refuses_instead_of_truncating_the_computation() {
        let value = Value::Text("x".repeat(MAX_STATEMENT_BYTES));
        let mut rows = Vec::new();
        assert!(artifact_rows(&mut rows, "/source", &value, &[]).is_err());
        assert!(rows.is_empty());
    }
}
