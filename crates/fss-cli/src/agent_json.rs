#![forbid(unsafe_code)]
//! Deterministic JSON rendering of the fss-core agent contract types.
//!
//! The fss-core contract types carry canonical binary encoders and digests but no JSON form. This
//! module renders each type field by field, in declaration order, under the camelCase spelling of
//! its registered schema where one exists (`agent_response_envelope.v1`,
//! `agent_cognitive_envelope.v1`, `agent_contract_basis.v1`, `semantic_context_pack.v1`,
//! `semantic_compression_receipt.v1`) and the camelCase spelling of the Rust field otherwise. It
//! adds no field the type does not carry and drops none it does, so the JSON is a faithful view of
//! the typed value; every digest printed is the type's own canonical digest.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use fss_core::{
    ActionAffordance, AffordanceClass, AgentCognitiveEnvelope, AgentOperation,
    AgentResponseEnvelope, BudgetVector, ContentDigest, ContextItem, ContractBasis,
    ControlEnvelope, KnowledgeCell, KnowledgeStateBasis, LedgerAnchor, OrientOmissionTarget,
    OrientProjection, PossibleWorld, ResourceState, SemanticCompressionReceipt,
    SemanticContextPack, SituationFrame, StaleBasis, WorldEnvelope,
};

use crate::diagnostic::escape_json_str;

/// A JSON string literal.
#[must_use]
pub fn string(value: &str) -> String {
    format!("\"{}\"", escape_json_str(value))
}

/// A JSON string literal or `null`.
#[must_use]
pub fn optional_string(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), string)
}

/// A JSON array of string literals.
#[must_use]
pub fn strings<I, S>(values: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let items: Vec<String> = values
        .into_iter()
        .map(|value| string(value.as_ref()))
        .collect();
    format!("[{}]", items.join(","))
}

/// A JSON array of digest texts.
#[must_use]
pub fn digests<'a, I>(values: I) -> String
where
    I: IntoIterator<Item = &'a ContentDigest>,
{
    strings(values.into_iter().map(|digest| digest.to_text()))
}

/// A JSON array of already-rendered values.
#[must_use]
pub fn array(items: &[String]) -> String {
    format!("[{}]", items.join(","))
}

/// A JSON object from `(key, rendered value)` pairs, in the given order.
#[must_use]
pub fn object(fields: &[(&str, String)]) -> String {
    let mut out = String::from("{");
    for (index, (key, value)) in fields.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let _ = write!(out, "\"{key}\":{value}");
    }
    out.push('}');
    out
}

fn digest(value: ContentDigest) -> String {
    string(&value.to_text())
}

fn number(value: f64) -> String {
    if value.is_finite() {
        format!("{value}")
    } else {
        "null".to_owned()
    }
}

fn set(values: &BTreeSet<String>) -> String {
    strings(values)
}

/// `LedgerAnchor` (the Rust anchor shape; `evidence_anchor.v1` names other fields).
#[must_use]
pub fn anchor(value: &LedgerAnchor) -> String {
    object(&[
        ("siteLineage", string(&value.site_lineage)),
        ("ledgerEpoch", value.ledger_epoch.to_string()),
        ("commitSequence", value.commit_sequence.to_string()),
        (
            "adapterRegistryEpoch",
            value.adapter_registry_epoch.to_string(),
        ),
        ("schemaEpoch", value.schema_epoch.to_string()),
        ("policyEpoch", value.policy_epoch.to_string()),
        ("privacyEpoch", value.privacy_epoch.to_string()),
        ("stateRoot", digest(value.state_root)),
    ])
}

/// `ContractBasis` as `fss.agent_contract_basis.v1`.
#[must_use]
pub fn contract_basis(value: &ContractBasis) -> String {
    object(&[
        ("schema", string("fss.agent_contract_basis.v1")),
        ("semanticProtocol", string(&value.semantic_protocol)),
        ("schemaCatalogDigest", digest(value.schema_catalog_digest)),
        (
            "ontologyGenerationId",
            string(&value.ontology_generation_id),
        ),
        (
            "operationRegistryDigest",
            digest(value.operation_registry_digest),
        ),
        ("viewRegistryDigest", digest(value.view_registry_digest)),
        (
            "capabilityRegistryDigest",
            digest(value.capability_registry_digest),
        ),
        ("errorRegistryDigest", digest(value.error_registry_digest)),
        ("costRegistryDigest", digest(value.cost_registry_digest)),
        ("producerReleaseId", string(&value.producer_release_id)),
        (
            "acceptedNightly",
            optional_string(value.accepted_nightly.as_deref()),
        ),
    ])
}

/// `BudgetVector` under the registered budget-vector spelling.
#[must_use]
pub fn budget(value: &BudgetVector) -> String {
    object(&[
        ("latencyMs", value.latency_ms.to_string()),
        ("tokens", value.tokens.to_string()),
        ("bytes", value.bytes.to_string()),
        ("modelCalls", value.model_calls.to_string()),
        ("cpuMillis", value.cpu_millis.to_string()),
        ("acceleratorMillis", value.accelerator_millis.to_string()),
        ("energyMilliJoules", value.energy_millijoules.to_string()),
        ("networkBytes", value.network_bytes.to_string()),
        ("storageOperations", value.storage_operations.to_string()),
        ("privacyExposure", number(value.privacy_exposure())),
        (
            "operatorAttentionSeconds",
            number(value.operator_attention_seconds()),
        ),
    ])
}

/// Per-dimension `requested - consumed`, floored at zero.
#[must_use]
pub fn remaining(requested: &BudgetVector, consumed: &BudgetVector) -> String {
    object(&[
        (
            "latencyMs",
            requested
                .latency_ms
                .saturating_sub(consumed.latency_ms)
                .to_string(),
        ),
        (
            "tokens",
            requested.tokens.saturating_sub(consumed.tokens).to_string(),
        ),
        (
            "bytes",
            requested.bytes.saturating_sub(consumed.bytes).to_string(),
        ),
        (
            "modelCalls",
            requested
                .model_calls
                .saturating_sub(consumed.model_calls)
                .to_string(),
        ),
        (
            "cpuMillis",
            requested
                .cpu_millis
                .saturating_sub(consumed.cpu_millis)
                .to_string(),
        ),
        (
            "acceleratorMillis",
            requested
                .accelerator_millis
                .saturating_sub(consumed.accelerator_millis)
                .to_string(),
        ),
        (
            "energyMilliJoules",
            requested
                .energy_millijoules
                .saturating_sub(consumed.energy_millijoules)
                .to_string(),
        ),
        (
            "networkBytes",
            requested
                .network_bytes
                .saturating_sub(consumed.network_bytes)
                .to_string(),
        ),
        (
            "storageOperations",
            requested
                .storage_operations
                .saturating_sub(consumed.storage_operations)
                .to_string(),
        ),
        (
            "privacyExposure",
            number((requested.privacy_exposure() - consumed.privacy_exposure()).max(0.0)),
        ),
        (
            "operatorAttentionSeconds",
            number(
                (requested.operator_attention_seconds() - consumed.operator_attention_seconds())
                    .max(0.0),
            ),
        ),
    ])
}

/// The response budget summary: requested, consumed, and remaining vectors.
#[must_use]
pub fn budget_summary(requested: &BudgetVector, consumed: &BudgetVector) -> String {
    object(&[
        ("requested", budget(requested)),
        ("consumed", budget(consumed)),
        ("remaining", remaining(requested, consumed)),
    ])
}

fn hex(value: ContentDigest) -> String {
    let text = value.to_text();
    text.split_once(':')
        .map_or(text.clone(), |(_, hex)| hex.to_owned())
}

fn state_basis(value: &KnowledgeStateBasis) -> String {
    match value {
        KnowledgeStateBasis::Redaction(marker) => object(&[
            ("basisKind", string("redaction")),
            (
                "redaction",
                object(&[
                    ("reason", string(marker.reason.as_str())),
                    (
                        "privacyGeneration",
                        string(marker.privacy_generation.as_str()),
                    ),
                ]),
            ),
        ]),
        KnowledgeStateBasis::Stale(StaleBasis::OlderAnchor { valid_at, current }) => object(&[
            ("basisKind", string("stale")),
            (
                "stale",
                object(&[
                    ("staleKind", string("older_anchor")),
                    ("validAt", anchor(valid_at)),
                    ("current", anchor(current)),
                ]),
            ),
        ]),
        KnowledgeStateBasis::Stale(StaleBasis::OlderGeneration { valid_at, current }) => object(&[
            ("basisKind", string("stale")),
            (
                "stale",
                object(&[
                    ("staleKind", string("older_generation")),
                    ("validAt", valid_at.0.to_string()),
                    ("current", current.0.to_string()),
                ]),
            ),
        ]),
        KnowledgeStateBasis::Reconciliation(basis) => object(&[
            ("basisKind", string("reconciliation")),
            (
                "reconciliation",
                object(&[
                    (
                        "unresolvedOutcomeRoot",
                        string(&hex(basis.unresolved_outcome_root)),
                    ),
                    (
                        "branches",
                        strings(basis.branches.iter().map(|branch| branch.as_str())),
                    ),
                ]),
            ),
        ]),
        KnowledgeStateBasis::Unknown(reason) => object(&[
            ("basisKind", string("unknown")),
            ("unknown", object(&[("reason", string(reason.as_str()))])),
        ]),
    }
}

/// `KnowledgeCell`: a redacted cell prints only its withheld-statement marker.
#[must_use]
pub fn knowledge_cell(value: &KnowledgeCell) -> String {
    object(&[
        ("cellId", string(value.claim_id())),
        ("statement", string(value.disclosable_statement())),
        ("knowledgeState", string(value.knowledge_state().as_str())),
        ("provenanceClass", string(value.provenance().as_str())),
        (
            "hypothesisDisposition",
            optional_string(value.hypothesis().map(|disposition| disposition.as_str())),
        ),
        ("supportingEvidence", digests(&value.evidence_digests())),
        ("contradictingEvidence", digests(value.contradictions())),
        (
            "expiresAtNs",
            value
                .valid_until()
                .map_or_else(|| "null".to_owned(), |at| at.0.to_string()),
        ),
        (
            "stateBasis",
            value
                .state_basis()
                .map_or_else(|| "null".to_owned(), state_basis),
        ),
        ("cellDigest", digest(value.cell_digest())),
    ])
}

fn world(value: &PossibleWorld) -> String {
    object(&[
        ("worldId", string(&value.world_id)),
        ("description", string(&value.description)),
        ("claimIds", set(&value.claim_ids)),
        ("evidence", digests(&value.evidence)),
        (
            "consequenceSeverity",
            value.consequence_severity.to_string(),
        ),
        ("protected", value.protected.to_string()),
    ])
}

/// `WorldEnvelope` with its validated envelope digest.
#[must_use]
pub fn world_envelope(value: &WorldEnvelope) -> String {
    let alternatives: Vec<String> = value.alternatives.iter().map(world).collect();
    let residuals: Vec<String> = value.adversarial_residuals.iter().map(world).collect();
    object(&[
        ("envelopeId", string(&value.envelope_id)),
        ("objectiveId", string(&value.objective_id)),
        ("anchor", anchor(&value.anchor)),
        ("nominalClaimIds", set(&value.nominal_claim_ids)),
        (
            "certifiedCoreClaimIds",
            set(&value.certified_core_claim_ids),
        ),
        ("materialAlternativeWorlds", array(&alternatives)),
        ("adversarialResiduals", array(&residuals)),
        ("commonInvariants", set(&value.common_invariants)),
        (
            "coverageBoundaryHandles",
            set(&value.coverage_boundary_handles),
        ),
        (
            "digest",
            value
                .envelope_digest()
                .map_or_else(|_| "null".to_owned(), digest),
        ),
    ])
}

/// Registered `robustnessClass` spelling of an affordance class (`agent_affordance.v1`).
#[must_use]
pub const fn robustness_class(class: AffordanceClass) -> &'static str {
    match class {
        AffordanceClass::Robust => "robust_across_envelope",
        AffordanceClass::Conditional => "conditional_on_named_worlds",
        AffordanceClass::Probe => "information_gathering",
        AffordanceClass::Wait => "wait_and_watch",
        AffordanceClass::Blocked => "blocked",
        AffordanceClass::Unavailable => "unavailable",
    }
}

/// `ActionAffordance`: a listed next move, never an executed one.
#[must_use]
pub fn affordance(value: &ActionAffordance) -> String {
    object(&[
        ("affordanceId", string(&value.affordance_id)),
        ("operation", string(&value.operation)),
        (
            "operationId",
            optional_string(
                AgentOperation::from_name(&value.operation)
                    .ok()
                    .map(AgentOperation::id),
            ),
        ),
        ("target", string(&value.target)),
        ("rationale", string(&value.rationale)),
        ("robustnessClass", string(robustness_class(value.class))),
        ("compatibleWorldIds", set(&value.supported_worlds)),
        ("unsafeWorldIds", set(&value.unsafe_worlds)),
        ("requiredCapabilities", set(&value.required_capabilities)),
        ("costVector", budget(&value.cost)),
        ("reversible", value.reversible.to_string()),
        (
            "branchPredicate",
            optional_string(value.branch_predicate.as_deref()),
        ),
    ])
}

/// `SituationFrame` with its validated frame digest.
#[must_use]
pub fn situation_frame(value: &SituationFrame) -> String {
    let cells: Vec<String> = value.knowledge_cells.iter().map(knowledge_cell).collect();
    object(&[
        ("frameId", string(&value.frame_id)),
        ("objectiveId", string(&value.objective_id)),
        ("anchor", anchor(&value.anchor)),
        ("worldEnvelope", world_envelope(&value.world_envelope)),
        ("knowledgeCells", array(&cells)),
        ("now", strings(&value.now)),
        ("changed", strings(&value.changed)),
        ("why", strings(&value.why)),
        ("unknown", strings(&value.unknown)),
        ("atRisk", strings(&value.at_risk)),
        ("next", strings(&value.next)),
        ("evidenceHandles", set(&value.evidence_handles)),
        (
            "frameDigest",
            value
                .frame_digest()
                .map_or_else(|_| "null".to_owned(), digest),
        ),
    ])
}

/// `ResourceState` with its canonical digest.
#[must_use]
pub fn resource_state(value: &ResourceState) -> String {
    object(&[
        ("available", budget(&value.available)),
        ("reserved", budget(&value.reserved)),
        ("pressure", string(value.pressure.as_str())),
        ("degradedDimensions", set(&value.degraded_dimensions)),
        ("stateDigest", digest(value.state_digest())),
    ])
}

/// `ControlEnvelope`: the categorized affordance frontier.
#[must_use]
pub fn control_envelope(value: &ControlEnvelope) -> String {
    let branches: Vec<String> = value
        .branch_conditions
        .iter()
        .map(|branch| {
            object(&[
                ("conditionId", string(&branch.condition_id)),
                ("worldIds", set(&branch.world_ids)),
                ("enabledAffordanceIds", set(&branch.enabled_affordance_ids)),
                (
                    "disabledAffordanceIds",
                    set(&branch.disabled_affordance_ids),
                ),
            ])
        })
        .collect();
    object(&[
        ("robustAffordanceIds", set(&value.robust_affordance_ids)),
        (
            "conditionalAffordanceIds",
            set(&value.conditional_affordance_ids),
        ),
        (
            "informationGatheringAffordanceIds",
            set(&value.information_gathering_affordance_ids),
        ),
        ("waitAffordanceIds", set(&value.wait_affordance_ids)),
        ("blockedAffordanceIds", set(&value.blocked_affordance_ids)),
        ("robustInvariants", set(&value.robust_invariants)),
        ("branchConditions", array(&branches)),
        ("envelopeDigest", digest(value.envelope_digest)),
        ("controlDigest", digest(value.control_digest())),
    ])
}

fn context_item(value: &ContextItem) -> String {
    object(&[
        ("itemId", string(&value.item_id)),
        ("kind", string(&value.kind)),
        ("epistemicState", string(value.epistemic_state.as_str())),
        ("content", string(&value.content)),
        ("basis", set(&value.basis)),
        ("expansionHandles", set(&value.expansion_handles)),
    ])
}

/// `SemanticContextPack` as `fss.semantic_context_pack.v1` (anchor keeps the Rust shape).
#[must_use]
pub fn context_pack(value: &SemanticContextPack) -> String {
    let items: Vec<String> = value.items.iter().map(context_item).collect();
    object(&[
        ("schema", string("fss.semantic_context_pack.v1")),
        ("contractBasis", contract_basis(&value.contract_basis)),
        ("packId", string(&value.pack_id)),
        ("missionId", string(value.mission_id.as_str())),
        ("sessionId", string(value.session_id.as_str())),
        ("viewId", string(&value.view_id)),
        ("anchor", anchor(&value.anchor)),
        ("situationFingerprint", digest(value.situation_fingerprint)),
        ("items", array(&items)),
        (
            "compressionReceiptId",
            string(&value.compression_receipt_id),
        ),
        ("tokenCount", value.token_count.to_string()),
        ("packDigest", digest(value.pack_digest)),
        (
            "continuation",
            optional_string(value.continuation.as_deref()),
        ),
        ("createdAtNs", value.created_at.0.to_string()),
    ])
}

/// `SemanticCompressionReceipt` as `fss.semantic_compression_receipt.v1`.
#[must_use]
pub fn compression_receipt(value: &SemanticCompressionReceipt) -> String {
    let transforms: Vec<String> = value
        .transforms
        .iter()
        .map(|transform| {
            object(&[
                ("kind", string(transform.kind.as_str())),
                ("scope", string(&transform.scope)),
                ("lossClass", string(transform.loss_class.as_str())),
                ("details", optional_string(transform.details.as_deref())),
            ])
        })
        .collect();
    let completeness: Vec<String> = value
        .completeness
        .iter()
        .map(|row| {
            object(&[
                ("domain", string(&row.domain)),
                ("state", string(row.state.as_str())),
                ("omittedCount", row.omitted_count.to_string()),
            ])
        })
        .collect();
    let handles: Vec<String> = value
        .expansion_handles
        .iter()
        .map(|handle| {
            object(&[
                ("handle", string(&handle.handle)),
                ("purpose", string(&handle.purpose)),
                ("estimatedCost", budget(&handle.estimated_cost)),
            ])
        })
        .collect();
    let critical = &value.critical_preservation;
    object(&[
        ("schema", string("fss.semantic_compression_receipt.v1")),
        ("receiptId", string(&value.receipt_id)),
        ("sourceAnchor", anchor(&value.source_anchor)),
        ("viewId", string(&value.view_id)),
        ("targetTokens", value.target_tokens.to_string()),
        ("selectedClasses", set(&value.selected_classes)),
        ("omittedClasses", set(&value.omitted_classes)),
        ("transforms", array(&transforms)),
        ("completeness", array(&completeness)),
        (
            "criticalPreservation",
            object(&[
                (
                    "knownCriticalItems",
                    critical.known_critical_items.to_string(),
                ),
                (
                    "omittedCriticalItems",
                    critical.omitted_critical_items.to_string(),
                ),
                (
                    "omittedInvalidations",
                    critical.omitted_invalidations.to_string(),
                ),
                (
                    "omittedContradictions",
                    critical.omitted_contradictions.to_string(),
                ),
            ]),
        ),
        ("actualTokens", value.actual_tokens.to_string()),
        ("actualBytes", value.actual_bytes.to_string()),
        ("expansionHandles", array(&handles)),
        (
            "selectionFrontierDigest",
            value
                .selection_frontier_digest
                .map_or_else(|| "null".to_owned(), digest),
        ),
        ("stopReason", string(value.stop_reason.as_str())),
        ("outputDigest", digest(value.output_digest)),
        ("receiptDigest", digest(value.receipt_digest())),
    ])
}

/// `OrientProjection` (AOP-003 section projection) with its canonical digest.
#[must_use]
pub fn orient_projection(value: &OrientProjection) -> String {
    let omissions: Vec<String> = value
        .omissions
        .iter()
        .map(|omission| {
            object(&[
                (
                    "target",
                    string(match omission.target {
                        OrientOmissionTarget::Section(section) => section.as_str(),
                        OrientOmissionTarget::EvidenceHandles => "evidence_handles",
                    }),
                ),
                ("omittedEntries", omission.omitted_entries.to_string()),
            ])
        })
        .collect();
    object(&[
        ("capsuleId", string(&value.capsule_id)),
        ("revision", value.revision.to_string()),
        ("missionId", string(value.mission_id.as_str())),
        ("sessionId", string(value.session_id.as_str())),
        ("principalId", string(value.principal_id.as_str())),
        ("anchor", anchor(&value.anchor)),
        ("completeness", string(value.completeness.as_str())),
        ("now", strings(&value.now)),
        ("changed", strings(&value.changed)),
        ("why", strings(&value.why)),
        ("unknown", strings(&value.unknown)),
        ("atRisk", strings(&value.at_risk)),
        ("next", strings(&value.next)),
        ("evidenceHandles", strings(&value.evidence_handles)),
        ("omissions", array(&omissions)),
        ("projectionDigest", digest(value.projection_digest())),
    ])
}

/// `AgentCognitiveEnvelope` as `fss.agent_cognitive_envelope.v1`.
#[must_use]
pub fn cognitive_envelope(value: &AgentCognitiveEnvelope) -> String {
    let propositions: Vec<String> = value
        .epistemic
        .propositions
        .iter()
        .map(|proposition| {
            object(&[
                ("id", string(&proposition.id)),
                ("statement", string(&proposition.statement)),
                ("state", string(proposition.state.as_str())),
                ("provenance", string(&proposition.provenance)),
                ("evidence", strings(&proposition.evidence)),
            ])
        })
        .collect();
    let coverage = &value.coverage;
    let budget_block = &value.budget;
    let continuity = &value.continuity;
    object(&[
        ("schema", string(AgentCognitiveEnvelope::SCHEMA)),
        ("contractBasis", contract_basis(&value.contract_basis)),
        ("requestId", string(&value.request_id)),
        ("responseId", string(&value.response_id)),
        ("traceId", string(&value.trace_id)),
        ("operationId", string(value.operation.id())),
        ("semanticVerb", string(&value.semantic_verb)),
        ("viewId", string(value.view.id())),
        ("answerClass", string(value.answer_class.as_str())),
        ("basisAnchor", anchor(&value.basis_anchor)),
        (
            "epistemic",
            object(&[
                ("propositions", array(&propositions)),
                ("assumptions", strings(&value.epistemic.assumptions)),
                ("invalidators", strings(&value.epistemic.invalidators)),
            ]),
        ),
        (
            "coverage",
            object(&[
                ("authorizedDomain", strings(&coverage.authorized_domain)),
                ("observedDomain", strings(&coverage.observed_domain)),
                (
                    "notObservableDomain",
                    strings(&coverage.not_observable_domain),
                ),
                ("omittedCount", coverage.omitted_count.to_string()),
                ("omissionReasons", strings(&coverage.omission_reasons)),
                ("stopReason", string(&coverage.stop_reason)),
            ]),
        ),
        (
            "budget",
            object(&[
                ("requested", budget_block.requested_json.clone()),
                ("consumed", budget_block.consumed_json.clone()),
                ("remaining", budget_block.remaining_json.clone()),
                (
                    "degradedDimensions",
                    strings(&budget_block.degraded_dimensions),
                ),
                (
                    "marginalWorkDeclined",
                    strings(&budget_block.marginal_work_declined),
                ),
            ]),
        ),
        ("evidenceHandles", strings(&value.evidence_handles)),
        ("nextActions", strings(&value.next_actions)),
        (
            "continuity",
            object(&[
                ("cursor", optional_string(continuity.cursor.as_deref())),
                ("reanchorTriggers", strings(&continuity.reanchor_triggers)),
                (
                    "sessionCapsuleDigest",
                    optional_string(continuity.session_capsule_digest.as_deref()),
                ),
                (
                    "unresolvedObligations",
                    strings(&continuity.unresolved_obligations),
                ),
            ]),
        ),
        ("decisionDigest", string(&value.decision_digest)),
        ("envelopeDigest", digest(value.envelope_digest())),
    ])
}

/// `AgentResponseEnvelope` as `fss.agent_response_envelope.v1`.
///
/// Pinned JSON fields (`payload`, `budgets`, `effectivePrivacyProjection`) are embedded verbatim;
/// the payload digest is the SHA-256 of exactly those payload bytes.
#[must_use]
pub fn response_envelope(value: &AgentResponseEnvelope) -> String {
    let boundary = &value.execution_boundary;
    object(&[
        ("schema", string(AgentResponseEnvelope::SCHEMA)),
        ("contractBasis", contract_basis(&value.contract_basis)),
        ("operationId", string(value.operation.id())),
        ("requestId", string(&value.request_id)),
        ("responseRevision", value.response_revision.to_string()),
        ("principalId", string(&value.principal_id)),
        ("sessionId", optional_string(value.session_id.as_deref())),
        ("missionId", optional_string(value.mission_id.as_deref())),
        ("traceId", string(&value.trace_id)),
        ("inputAnchor", anchor(&value.input_anchor)),
        (
            "outputAnchor",
            value
                .output_anchor
                .as_ref()
                .map_or_else(|| "null".to_owned(), anchor),
        ),
        (
            "workspaceRevision",
            value
                .workspace_revision
                .map_or_else(|| "null".to_owned(), |revision| revision.to_string()),
        ),
        ("effectiveViewId", string(value.effective_view.id())),
        (
            "effectiveCapabilities",
            strings(&value.effective_capabilities),
        ),
        (
            "effectivePrivacyProjection",
            value.effective_privacy_projection_json.clone(),
        ),
        ("outcome", string(value.outcome.as_str())),
        ("taskId", optional_string(value.task_id.as_deref())),
        (
            "taskState",
            optional_string(value.task_state.map(|state| state.as_str())),
        ),
        ("errorId", optional_string(value.error_id.as_deref())),
        ("payloadSchema", string(&value.payload_schema)),
        ("payload", value.payload_json.clone()),
        ("payloadDigest", digest(value.payload_digest)),
        ("epistemicState", string(value.epistemic_state.as_str())),
        ("completeness", string(value.completeness.as_str())),
        ("warnings", strings(&value.warnings)),
        ("contradictions", strings(&value.contradictions)),
        ("degradation", strings(&value.degradation)),
        ("budgets", value.budgets_json.clone()),
        ("proofPointers", strings(&value.proof_pointers)),
        ("affordances", strings(&value.affordances)),
        ("decisionFingerprint", digest(value.decision_fingerprint)),
        (
            "compressionReceiptId",
            optional_string(value.compression_receipt_id.as_deref()),
        ),
        (
            "validUntilNs",
            value
                .valid_until_ns
                .map_or_else(|| "null".to_owned(), |at| at.to_string()),
        ),
        (
            "continuation",
            optional_string(value.continuation.as_deref()),
        ),
        (
            "idempotencyKey",
            optional_string(value.idempotency_key.as_deref()),
        ),
        ("recoveryClass", string(&value.recovery_class)),
        ("safeRetry", string(value.safe_retry.as_str())),
        ("resnapshotRequired", value.resnapshot_required.to_string()),
        (
            "executionBoundary",
            object(&[
                ("completed", strings(&boundary.completed)),
                ("notStarted", strings(&boundary.not_started)),
                ("possiblyOccurred", strings(&boundary.possibly_occurred)),
                ("preservedTruth", strings(&boundary.preserved_truth)),
                ("invalidated", strings(&boundary.invalidated)),
            ]),
        ),
        ("createdAtNs", value.created_at_ns.to_string()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_escaped_and_objects_keep_order() {
        assert_eq!(string("a\"b\n"), "\"a\\\"b\\n\"");
        assert_eq!(optional_string(None), "null");
        assert_eq!(strings(["x", "y"]), "[\"x\",\"y\"]");
        assert_eq!(
            object(&[("b", "1".to_owned()), ("a", "[]".to_owned())]),
            "{\"b\":1,\"a\":[]}"
        );
    }

    #[test]
    fn budget_remaining_saturates_per_dimension() -> Result<(), Box<dyn std::error::Error>> {
        let requested = BudgetVector::builder().tokens(100).bytes(10).build()?;
        let consumed = BudgetVector::builder().tokens(40).bytes(50).build()?;
        let text = remaining(&requested, &consumed);
        assert!(text.contains("\"tokens\":60"));
        assert!(text.contains("\"bytes\":0"));
        assert_eq!(number(f64::NAN), "null");
        Ok(())
    }

    #[test]
    fn affordance_classes_map_to_registered_robustness_classes() {
        assert_eq!(
            robustness_class(AffordanceClass::Probe),
            "information_gathering"
        );
        assert_eq!(robustness_class(AffordanceClass::Wait), "wait_and_watch");
        assert_eq!(
            robustness_class(AffordanceClass::Unavailable),
            "unavailable"
        );
    }
}
