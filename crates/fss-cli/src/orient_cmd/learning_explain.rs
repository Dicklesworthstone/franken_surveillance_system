#![forbid(unsafe_code)]
//! Complete, selected advisory metadata under current read authority. No orientation or learning
//! inventory is rendered, so a large inventory cannot hide an otherwise admissible exact root.

use fss_core::{
    AgentCognitiveEnvelope, BudgetVector, CanonicalEncode, CognitiveAnswerClass, Completeness,
    ContentDigest, EnvelopeBudget, EnvelopeContinuity, EnvelopeCoverage, EnvelopeEpistemic,
    EnvelopeProposition, ExecutionBoundary, KnowledgeState, ResponseOutcome, ResponseSafeRetry,
    SessionId,
};
use fss_reference::agent_orient::CAPABILITY_EXPLAIN;
use fss_reference::deployment_session::DeploymentSessionError;
use fss_reference::deployment_session::learning::{
    InspectLearningRequest, LearningInspection, inspect_learning,
};

use super::{ERR_AGENT_CONTEXT_INCOMPLETE, ExplainArgs, RenderError, ResponseParts};
use crate::agent_json::{self, EvidenceHandle};
use crate::error::ExitIdentity;
use crate::session_cmd::{Operation, Refusal};

const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const ERR_LEARNING_UNSUPPORTED: &str = "ERR-AGENT-LEARNING-UNSUPPORTED-001";

fn boundary(completed: &str) -> ExecutionBoundary {
    ExecutionBoundary {
        completed: vec![completed.to_owned()],
        not_started: vec![
            "Learning validation, promotion, activation, effect execution, and source-media disclosure."
                .to_owned(),
        ],
        possibly_occurred: Vec::new(),
        preserved_truth: vec![
            "Existing session and publication locks protected this read; no file, journal, pin, \
             workspace revision, lease, grant, or durable token charge was created or changed."
                .to_owned(),
            "The retained candidate and its original review/expiry times remain unchanged."
                .to_owned(),
        ],
        invalidated: Vec::new(),
    }
}

fn operation(args: &ExplainArgs, session: &SessionId, root: ContentDigest) -> Operation {
    let request = super::request_identity("fss.cli.learning_explain.request.v1", |encoder| {
        session.encode_canonical(encoder);
        root.encode_canonical(encoder);
        encoder.text(args.view.id());
        match args.budget_tokens {
            Some(tokens) => {
                encoder.text("explicit");
                encoder.u64(tokens);
            }
            None => encoder.text("default"),
        }
    });
    Operation {
        command: "explain",
        name: "explain",
        capability: CAPABILITY_EXPLAIN,
        payload_schema: AgentCognitiveEnvelope::SCHEMA,
        view: args.view,
        root: args.root.clone(),
        principal: args.principal.clone(),
        request: request.to_text().into_bytes(),
    }
}

fn refuse(
    args: &ExplainArgs,
    session: &SessionId,
    root: ContentDigest,
    error: DeploymentSessionError,
) -> (String, ExitIdentity) {
    let operation = operation(args, session, root);
    let refusal = match error {
        DeploymentSessionError::Read(read) => {
            return super::read_refusal("explain", &args.root, &read);
        }
        DeploymentSessionError::FeedbackRefused(_) => Refusal {
            error_id: ERR_LEARNING_UNSUPPORTED,
            reason:
                "The selected learning is unavailable under this session or its retained custody."
                    .to_owned(),
            guidance: "Use a captured learning root owned by this session with a complete retained \
                       source closure; no private candidate detail is disclosed by this refusal.",
            recovery_class: "never_unchanged",
            safe_retry: ResponseSafeRetry::No,
        },
        other => match crate::session_cmd::classify(other) {
            Ok(refusal) => refusal,
            Err(_) => return super::internal_failure("explain", &args.root),
        },
    };
    crate::session_cmd::refuse_typed_with_boundary(
        &operation,
        refusal,
        ExitIdentity::AGENT_REFUSED,
        Some(boundary(
            "Selected learning inspection was refused without publishing private detail.",
        )),
    )
}

fn context_refusal(
    args: &ExplainArgs,
    session: &SessionId,
    root: ContentDigest,
) -> (String, ExitIdentity) {
    crate::session_cmd::refuse_typed_with_boundary(
        &operation(args, session, root),
        Refusal {
            error_id: ERR_AGENT_CONTEXT_INCOMPLETE,
            reason: "The complete selected learning metadata and mandatory uncertainty do not fit \
                     the admitted response allowance."
                .to_owned(),
            guidance: "Request --view forensic with a sufficient --budget-tokens allowance within \
                       this session's current grant. No statement, condition, counterexample, \
                       source citation, or validation requirement is silently omitted.",
            recovery_class: "never_unchanged",
            safe_retry: ResponseSafeRetry::No,
        },
        ExitIdentity::AGENT_REFUSED,
        Some(boundary(
            "Verified selected metadata; the complete response was withheld at its bound.",
        )),
    )
}

fn proposition(
    id: impl Into<String>,
    statement: impl Into<String>,
    state: KnowledgeState,
    provenance: &str,
    evidence: &[String],
) -> EnvelopeProposition {
    EnvelopeProposition {
        id: id.into(),
        statement: statement.into(),
        state,
        provenance: provenance.to_owned(),
        evidence: evidence.to_vec(),
    }
}

fn retained_list(
    out: &mut Vec<EnvelopeProposition>,
    prefix: &str,
    values: &[String],
    evidence: &[String],
) {
    for (index, value) in values.iter().enumerate() {
        out.push(proposition(
            format!("{prefix}:{index}"),
            value.clone(),
            KnowledgeState::Unknown,
            "remembered",
            evidence,
        ));
    }
}

fn optional_time(value: Option<i128>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| value.to_string())
}

fn propositions(read: &LearningInspection) -> Vec<EnvelopeProposition> {
    let learning = &read.learning;
    let proposal = &learning.proposal;
    let experience = &learning.experience;
    let proposal_evidence = vec![learning.proposal_digest.to_text()];
    let experience_evidence = vec![learning.experience_digest.to_text()];
    let mut out = vec![
        proposition(
            "learning:identity",
            agent_json::object(&[
                ("proposalId", agent_json::string(&proposal.proposal_id)),
                ("class", agent_json::string(proposal.class.as_str())),
                (
                    "sourceEpisodeId",
                    agent_json::string(&proposal.source_episode_id),
                ),
                (
                    "decisionDigest",
                    agent_json::string(&proposal.decision_digest),
                ),
                (
                    "canonicalDigest",
                    agent_json::string(&proposal.proposal_digest().to_text()),
                ),
            ]),
            KnowledgeState::Known,
            "remembered",
            &proposal_evidence,
        ),
        proposition(
            "learning:statement",
            proposal.statement.clone(),
            KnowledgeState::Unknown,
            "remembered",
            &proposal_evidence,
        ),
        proposition(
            "learning:applicability",
            proposal.applicability_json.clone(),
            KnowledgeState::Unknown,
            "remembered",
            &proposal_evidence,
        ),
        proposition(
            "learning:status",
            agent_json::object(&[
                (
                    "promotionState",
                    agent_json::string(proposal.promotion_state.as_str()),
                ),
                (
                    "confidenceNumerator",
                    proposal.confidence_numerator.to_string(),
                ),
                ("confidenceDenominator", "1000000".to_owned()),
                ("helpfulOutcomes", proposal.helpful_outcomes.to_string()),
                ("harmfulOutcomes", proposal.harmful_outcomes.to_string()),
                ("reviewAfterNs", optional_time(proposal.review_after_ns)),
                ("expiryNs", optional_time(proposal.expiry_ns)),
                ("observedEvidenceTimeNs", read.observed_at_ns.to_string()),
                (
                    "reviewDue",
                    proposal.review_after_ns.map_or_else(
                        || "null".to_owned(),
                        |time| (read.observed_at_ns >= time).to_string(),
                    ),
                ),
                (
                    "expired",
                    proposal.expiry_ns.map_or_else(
                        || "null".to_owned(),
                        |time| (read.observed_at_ns >= time).to_string(),
                    ),
                ),
                (
                    "supportingCount",
                    proposal.supporting_evidence.len().to_string(),
                ),
                (
                    "contradictingCount",
                    proposal.contradicting_evidence.len().to_string(),
                ),
                (
                    "counterexampleCount",
                    proposal.counterexamples.len().to_string(),
                ),
                (
                    "validationCount",
                    proposal.required_validation.len().to_string(),
                ),
                (
                    "revivalCount",
                    proposal.revival_conditions.len().to_string(),
                ),
            ]),
            KnowledgeState::Known,
            "derived",
            &proposal_evidence,
        ),
        proposition(
            "experience:identity",
            agent_json::object(&[
                (
                    "experienceId",
                    agent_json::string(&experience.experience_id),
                ),
                (
                    "missionId",
                    agent_json::string(experience.mission_id.as_str()),
                ),
                (
                    "evidenceStrength",
                    agent_json::string(experience.evidence_strength.as_str()),
                ),
                (
                    "confidenceNumerator",
                    experience.confidence_numerator.to_string(),
                ),
                ("confidenceDenominator", "1000000".to_owned()),
                (
                    "decayHalfLifeDays",
                    experience.decay_half_life_days.to_string(),
                ),
                (
                    "privacyClass",
                    agent_json::string(&experience.privacy_class),
                ),
                ("createdAtNs", experience.created_at_ns.to_string()),
                (
                    "canonicalDigest",
                    agent_json::string(&experience.experience_digest().to_text()),
                ),
                (
                    "deploymentScopeCount",
                    experience.deployment_scope.len().to_string(),
                ),
                (
                    "initialEpistemicMapCount",
                    experience.initial_epistemic_map.len().to_string(),
                ),
                ("operationCount", experience.operations.len().to_string()),
                (
                    "predictiveSignalCount",
                    experience.predictive_signals.len().to_string(),
                ),
                (
                    "misleadingSignalCount",
                    experience.misleading_signals.len().to_string(),
                ),
                (
                    "failedAssumptionCount",
                    experience.failed_assumptions.len().to_string(),
                ),
                (
                    "applicabilityCount",
                    experience.applicability.len().to_string(),
                ),
            ]),
            KnowledgeState::Known,
            "remembered",
            &experience_evidence,
        ),
        proposition(
            "experience:basis",
            agent_json::evidence_anchor(&experience.basis_anchor),
            KnowledgeState::Known,
            "remembered",
            &experience_evidence,
        ),
        proposition(
            "experience:situation-signature",
            experience.situation_signature_json.clone(),
            KnowledgeState::Unknown,
            "remembered",
            &experience_evidence,
        ),
        proposition(
            "experience:objective",
            experience.objective.clone(),
            KnowledgeState::Unknown,
            "remembered",
            &experience_evidence,
        ),
        proposition(
            "experience:outcome",
            experience.outcome.clone(),
            KnowledgeState::Unknown,
            "remembered",
            &experience_evidence,
        ),
        proposition(
            "experience:cost",
            agent_json::budget(&experience.cost),
            KnowledgeState::Known,
            "remembered",
            &experience_evidence,
        ),
        proposition(
            "episode:resource-use",
            learning.original_resource_use_json.clone(),
            KnowledgeState::Unknown,
            "remembered",
            &[learning.episode_root.to_text()],
        ),
        proposition(
            "capture:custody",
            agent_json::object(&[
                ("learningRoot", agent_json::string(&learning.root.to_text())),
                (
                    "experienceDigest",
                    agent_json::string(&learning.experience_digest.to_text()),
                ),
                (
                    "proposalDigest",
                    agent_json::string(&learning.proposal_digest.to_text()),
                ),
                (
                    "episodeRoot",
                    agent_json::string(&learning.episode_root.to_text()),
                ),
                (
                    "feedbackRoot",
                    agent_json::string(&learning.feedback_root.to_text()),
                ),
                (
                    "planRoot",
                    agent_json::string(&learning.plan_root.to_text()),
                ),
                (
                    "capturedWorkspaceDigest",
                    agent_json::string(&read.captured_workspace_digest.to_text()),
                ),
                (
                    "missingEvidenceCount",
                    learning.missing_evidence.len().to_string(),
                ),
            ]),
            KnowledgeState::Known,
            "observed",
            &[learning.root.to_text()],
        ),
        proposition(
            "current:authority",
            agent_json::object(&[
                (
                    "sessionId",
                    agent_json::string(read.session.session_id.as_str()),
                ),
                (
                    "principalId",
                    agent_json::string(read.session.principal_id.as_str()),
                ),
                ("anchor", agent_json::evidence_anchor(&read.current_anchor)),
                (
                    "anchorToken",
                    agent_json::string(&read.current_anchor_token),
                ),
                (
                    "workspaceDigest",
                    agent_json::string(&read.revision.digest().to_text()),
                ),
                (
                    "journalRoot",
                    agent_json::string(&read.journal_root.to_text()),
                ),
                ("remainingSessionTokens", read.remaining_tokens.to_string()),
            ]),
            KnowledgeState::Known,
            "observed",
            &[read.journal_root.to_text()],
        ),
    ];
    for (prefix, values) in [
        ("learning:supporting", &proposal.supporting_evidence),
        ("learning:contradicting", &proposal.contradicting_evidence),
        ("learning:counterexample", &proposal.counterexamples),
        ("learning:validation", &proposal.required_validation),
        ("learning:revival", &proposal.revival_conditions),
    ] {
        retained_list(&mut out, prefix, values, &proposal_evidence);
    }
    for (prefix, values) in [
        ("experience:scope", &experience.deployment_scope),
        ("experience:operation", &experience.operations),
        ("experience:predictive", &experience.predictive_signals),
        ("experience:misleading", &experience.misleading_signals),
        (
            "experience:failed-assumption",
            &experience.failed_assumptions,
        ),
        ("experience:applicability", &experience.applicability),
    ] {
        retained_list(&mut out, prefix, values, &experience_evidence);
    }
    for (index, statement) in experience.initial_epistemic_map.iter().enumerate() {
        out.push(proposition(
            format!("experience:initial:{index}"),
            agent_json::object(&[
                ("statementId", agent_json::string(&statement.statement_id)),
                ("text", agent_json::string(&statement.text)),
                (
                    "epistemicState",
                    agent_json::string(statement.epistemic_state.as_str()),
                ),
                ("basis", agent_json::strings(&statement.basis)),
            ]),
            KnowledgeState::Unknown,
            "remembered",
            &experience_evidence,
        ));
    }
    retained_list(
        &mut out,
        "unknown:learning",
        &learning.missing_evidence,
        &[learning.root.to_text()],
    );
    out.push(proposition(
        "unknown:current-applicability",
        "The complete historical candidate is remembered. Current applicability, causal \
         effectiveness, validation, and promotion remain unestablished; an empty list of \
         counterexamples does not prove that none exist.",
        KnowledgeState::Unknown,
        "derived",
        &proposal_evidence,
    ));
    out.push(proposition(
        "unknown:read-cost",
        "Verified input bytes and file reads are measured lower bounds; output tokens use the \
         reference UTF-8 byte/4 estimate. Additional metadata checks, replay CPU, latency, and \
         energy are unmetered. Budget zeros do not establish zero actual resource use. This read \
         neither charges nor replenishes the durable session budget.",
        KnowledgeState::Unknown,
        "derived",
        &[read.journal_root.to_text()],
    ));
    out
}

fn handles(read: &LearningInspection) -> Vec<EvidenceHandle> {
    let learning = &read.learning;
    [
        (learning.root, "learning_manifest", "H0"),
        (learning.experience_digest, "experience_capsule", "H2"),
        (learning.proposal_digest, "learning_proposal", "H2"),
        (learning.episode_root, "execution_episode_manifest", "H0"),
        (learning.feedback_root, "feedback_manifest", "H0"),
        (learning.plan_root, "plan_manifest", "H0"),
    ]
    .into_iter()
    .map(|(digest, kind, hydration)| {
        let mut cost = BudgetVector::ZERO;
        cost.bytes = read
            .objects
            .iter()
            .find(|(object, _)| *object == digest)
            .map_or(0, |(_, length)| *length);
        EvidenceHandle {
            handle_id: format!("fss://proof/{digest}"),
            object_digest: digest,
            kind: kind.to_owned(),
            hydration,
            allowed_hydration: if hydration == "H2" {
                vec!["H0", "H2"]
            } else {
                vec!["H0"]
            },
            privacy_class: read.learning.experience.privacy_class.clone(),
            availability: "available",
            estimated_cost: cost,
            required_capability: Some(CAPABILITY_EXPLAIN.to_owned()),
        }
    })
    .collect()
}

fn render(
    args: &ExplainArgs,
    read: &LearningInspection,
    request_digest: ContentDigest,
    decision_digest: ContentDigest,
    consumed: &BudgetVector,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut requested = BudgetVector::ZERO;
    requested.tokens = read.effective_budget_tokens;
    let handles = handles(read);
    let request_text = request_digest.to_text();
    let hex = request_text
        .strip_prefix("sha256:")
        .ok_or(RenderError("request digest"))?;
    let learning = &read.learning;
    let envelope = AgentCognitiveEnvelope::new(
        learning.contract_basis.clone(),
        format!("request:explain:{hex}"),
        format!("response:explain:{hex}"),
        format!("trace:explain:{hex}"),
        "explain",
        "inspect_learning",
        args.view.id(),
        CognitiveAnswerClass::LearningProposal,
        learning.experience.basis_anchor.clone(),
        EnvelopeEpistemic {
            propositions: propositions(read),
            assumptions: vec![
                "Retained fields describe the original capture; their attribution is not a new \
                 assertion of present-world truth.".to_owned(),
            ],
            invalidators: vec![
                "Current authority, session ownership, expiry, private scope, workspace/journal \
                 pins, or selected publication custody changes require a fresh admitted read."
                    .to_owned(),
            ],
        },
        EnvelopeCoverage {
            authorized_domain: vec!["Exact selected learning and its owned retained metadata closure.".to_owned()],
            observed_domain: vec![
                "Complete retained proposal and experience fields, original episode resource-use, \
                 all source identities, and mandatory uncertainty.".to_owned(),
            ],
            not_observable_domain: vec![
                "Current causal effectiveness, unrecorded counterexamples, and unmeasured costs.".to_owned(),
                "Source media and other sessions' private candidates.".to_owned(),
            ],
            omitted_count: 0,
            omission_reasons: Vec::new(),
            stop_reason: "Complete selected metadata; no inventory or unrelated candidate was rendered.".to_owned(),
        },
        EnvelopeBudget {
            requested_json: agent_json::budget(&requested),
            consumed_json: agent_json::budget(consumed),
            remaining_json: agent_json::remaining(&requested, consumed),
            degraded_dimensions: vec![
                "bytes/storageOperations are measured lower bounds; tokens are a reference estimate; \
                 unmetered dimensions have zero lower bounds, not proven zero actual use.".to_owned(),
            ],
            marginal_work_declined: vec![
                "No full inventory, validation experiment, promotion, or source-media hydration.".to_owned(),
            ],
        },
        handles.iter().map(|handle| handle.handle_id.clone()).collect(),
        Vec::new(),
        EnvelopeContinuity {
            cursor: None,
            reanchor_triggers: vec![
                "Re-read when current session authority, retained custody, or evidence time changes.".to_owned(),
            ],
            session_capsule_digest: Some(read.revision.digest().to_text()),
            unresolved_obligations: vec![
                "Review all retained validation requirements and counterexamples before any future \
                 promotion; this read grants no promotion or effect authority.".to_owned(),
            ],
        },
        decision_digest.to_text(),
    )?;
    let payload_json = agent_json::cognitive_envelope(&envelope, &handles, &[])
        .ok_or(RenderError("selected learning envelope"))?;
    let mut proofs = handles
        .iter()
        .map(|handle| handle.object_digest.to_text())
        .collect::<Vec<_>>();
    for (digest, _) in &read.objects {
        let text = digest.to_text();
        if !proofs.contains(&text) {
            proofs.push(text);
        }
    }
    proofs.push(read.revision.digest().to_text());
    proofs.push(read.journal_root.to_text());
    super::build_response(ResponseParts {
        operation: "explain",
        request_digest,
        principal: args.principal.clone(),
        session_id: Some(read.session.session_id.as_str().to_owned()),
        mission_id: Some(read.session.mission_id.as_str().to_owned()),
        anchor: read.current_anchor.clone(),
        view: args.view,
        capability: CAPABILITY_EXPLAIN,
        outcome: ResponseOutcome::Ok,
        error_id: None,
        payload_schema: AgentCognitiveEnvelope::SCHEMA,
        payload_json,
        epistemic_state: KnowledgeState::Unknown,
        completeness: Completeness::Partial,
        warnings: Vec::new(),
        contradictions: Vec::new(),
        degradation: vec![
            "All selected retained metadata is carried. Current applicability and causal \
             attribution remain unknown; the proposal remains advisory."
                .to_owned(),
        ],
        budgets_json: agent_json::budget_summary(&requested, consumed),
        proof_pointers: proofs,
        affordances: Vec::new(),
        affordance_objects: Vec::new(),
        decision_fingerprint: decision_digest,
        compression_receipt_id: None,
        continuation: None,
        recovery_class: "none",
        safe_retry: ResponseSafeRetry::YesSameRequest,
        boundary: boundary(
            "Verified and read the complete selected learning metadata under current authority.",
        ),
        created_at_ns: read.observed_at_ns,
        workspace_revision: Some(read.revision.capsule().revision),
        idempotency_key: None,
    })
}

pub(super) fn execute(
    args: &ExplainArgs,
    session: &SessionId,
    publication_root: ContentDigest,
) -> (String, ExitIdentity) {
    // Also protect internal typed callers; the public parser rejects mixed selectors before I/O.
    if args.at.is_some()
        || args.custody
        || args.score_calibration.is_some()
        || args.fusion_policy.is_some()
    {
        return super::internal_failure("explain", &args.root);
    }
    let read = match inspect_learning(
        &args.root,
        &InspectLearningRequest {
            session_id: session.clone(),
            principal: args.principal.clone(),
            publication_root,
            view: args.view,
            budget_tokens: args.budget_tokens,
        },
    ) {
        Ok(read) => read,
        Err(error) => return refuse(args, session, publication_root, error),
    };
    let request_digest =
        super::request_identity("fss.cli.learning_explain.request.v1", |encoder| {
            session.encode_canonical(encoder);
            publication_root.encode_canonical(encoder);
            args.principal.encode_canonical(encoder);
            encoder.text(args.view.id());
            match args.budget_tokens {
                Some(tokens) => {
                    encoder.text("explicit");
                    encoder.u64(tokens);
                }
                None => encoder.text("default"),
            }
            encoder.u64(read.effective_budget_tokens);
            encoder.u64(read.remaining_tokens);
            read.current_anchor.encode_canonical(encoder);
            encoder.text(&read.current_anchor_token);
            read.revision.digest().encode_canonical(encoder);
            read.journal_root.encode_canonical(encoder);
            encoder.text(&read.observed_at_ns.to_string());
        });
    let decision_digest =
        super::request_identity("fss.cli.learning_explain.decision.v1", |encoder| {
            request_digest.encode_canonical(encoder);
            read.learning.root.encode_canonical(encoder);
            read.learning.proposal_digest.encode_canonical(encoder);
            read.learning.experience_digest.encode_canonical(encoder);
            read.captured_workspace_digest.encode_canonical(encoder);
            encoder.text(&read.learning.original_resource_use_json);
            for unknown in &read.learning.missing_evidence {
                encoder.text(unknown);
            }
        });
    let mut consumed = BudgetVector::ZERO;
    consumed.bytes = read.bytes_read;
    consumed.storage_operations = read.files_read;
    // Account for the complete wire answer including its own budget fields. A bounded fixed
    // point is deterministic and never silently drops required content to meet the ceiling.
    for _ in 0..8 {
        let answer = match render(args, &read, request_digest, decision_digest, &consumed) {
            Ok(answer) => answer,
            Err(_) => return context_refusal(args, session, publication_root),
        };
        let bytes = u64::try_from(answer.len()).unwrap_or(u64::MAX);
        let tokens = bytes.saturating_add(3) / 4;
        if answer.len() > MAX_RESPONSE_BYTES || tokens > read.effective_budget_tokens {
            return context_refusal(args, session, publication_root);
        }
        let total_bytes = read.bytes_read.saturating_add(bytes);
        if consumed.tokens == tokens && consumed.bytes == total_bytes {
            return (answer, ExitIdentity::SUCCESS);
        }
        consumed.tokens = tokens;
        consumed.bytes = total_bytes;
    }
    context_refusal(args, session, publication_root)
}
