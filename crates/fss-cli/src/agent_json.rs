#![forbid(unsafe_code)]
//! Deterministic JSON rendering of the fss-core agent contract types under their registered
//! schemas.
//!
//! The fss-core contract types carry canonical binary encoders and digests but no JSON form. This
//! module renders each type under its registered schema (`situation_capsule.v1`,
//! `agent_situation_frame.v1`, `agent_world_envelope.v1`, `agent_knowledge_cell.v1`,
//! `agent_affordance.v1`, `evidence_anchor.v1`, `semantic_context_pack.v1`,
//! `semantic_compression_receipt.v1`, `agent_objective_contract.v1`,
//! `agent_cognitive_envelope.v1`, and `agent_response_envelope.v1`); the machine-readable schemas
//! are the contract, and every field they require is rendered from the typed value or its
//! compiling context. Where a required field has no counterpart in the reference data the
//! schema's explicit form is used (`null`, an empty set, or the repository's typed `fss-na:`
//! not-applicable sentinel), never an invented value; every such mapping is recorded as a drift
//! entry in `architecture/agent_contracts.json`. Every digest printed is the type's own canonical
//! digest.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use fss_core::{
    ActionAffordance, AffordanceClass, AgentCognitiveEnvelope, AgentOperation,
    AgentResponseEnvelope, BudgetVector, Completeness, ContentDigest, ContextItem, ContractBasis,
    ControlEnvelope, CoverageContinuity, CoverageStopReason, CoverageWitness, KnowledgeCell,
    KnowledgeState, KnowledgeStateBasis, LedgerAnchor, ObjectiveContract, OperationMode,
    PossibleWorld, ResourceState, SemanticCompressionReceipt, SemanticContextPack, StaleBasis,
    WorldEnvelope,
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

/// A JSON number; a non-finite value (refused upstream by the typed constructors) renders as
/// `null`, which every registered numeric field rejects, so it can never pass as a value.
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

fn hex(value: ContentDigest) -> String {
    let text = value.to_text();
    text.split_once(':')
        .map_or(text.clone(), |(_, hex)| hex.to_owned())
}

/// The repository's typed not-applicable sentinel for a required digest-shaped field
/// (`fss-na:<sha256 of "<schema>/sentinel/<field>/<reason>">`, as `model_receipt` emits): it
/// satisfies the schema grammar, never parses as a [`ContentDigest`], and so can never be
/// mistaken for a content address.
#[must_use]
pub fn not_applicable_sentinel(schema: &str, field: &str, reason: &str) -> String {
    format!(
        "fss-na:{}",
        hex(ContentDigest::sha256(
            format!("{schema}/sentinel/{field}/{reason}").as_bytes()
        ))
    )
}

/// Reason every deployment-scope anchor gives for its device and stream generation sentinels.
pub const DEPLOYMENT_SCOPE_ANCHOR: &str = "deployment_scope_anchor";

/// `LedgerAnchor` as `fss.evidence_anchor.v1`.
///
/// `deploymentId` is the site lineage, `observationEpoch` the ledger epoch, `capsuleSequence`
/// the commit sequence, `authorityRoot` the state root, and `adapterEpoch` the adapter-registry
/// epoch. A deployment-scope anchor pins every device and stream generation through its commit
/// but names no single one, so `deviceGeneration`/`streamGeneration` carry the typed
/// not-applicable sentinel; no model, calibration, graph, or search generation is consumed by an
/// orientation, so those are `null`. The privacy epoch has no anchor slot in the schema; it is
/// the answer's privacy `policyGenerationId`.
#[must_use]
pub fn evidence_anchor(value: &LedgerAnchor) -> String {
    object(&[
        ("schema", string("fss.evidence_anchor.v1")),
        ("deploymentId", string(&value.site_lineage)),
        ("observationEpoch", value.ledger_epoch.to_string()),
        ("capsuleSequence", value.commit_sequence.to_string()),
        ("authorityRoot", digest(value.state_root)),
        (
            "deviceGeneration",
            string(&not_applicable_sentinel(
                "fss.evidence_anchor.v1",
                "deviceGeneration",
                DEPLOYMENT_SCOPE_ANCHOR,
            )),
        ),
        (
            "streamGeneration",
            string(&not_applicable_sentinel(
                "fss.evidence_anchor.v1",
                "streamGeneration",
                DEPLOYMENT_SCOPE_ANCHOR,
            )),
        ),
        ("schemaEpoch", value.schema_epoch.to_string()),
        ("policyEpoch", value.policy_epoch.to_string()),
        ("adapterEpoch", value.adapter_registry_epoch.to_string()),
        ("modelGeneration", "null".to_owned()),
        ("calibrationGeneration", "null".to_owned()),
        ("graphGeneration", "null".to_owned()),
        ("searchGeneration", "null".to_owned()),
    ])
}

/// `CoverageWitness` as `fss.coverage_witness.v1`. Completeness maps `complete` to
/// `complete_for_declared_domain`, `bounded`/`partial` to `partial`, and every other state to
/// `uncertified`; the digest is the witness's own canonical digest.
#[must_use]
pub fn coverage_witness(value: &CoverageWitness) -> String {
    object(&[
        ("schema", string("fss.coverage_witness.v1")),
        ("anchor", evidence_anchor(&value.anchor)),
        ("authorizedDomain", set(&value.authorized_domain)),
        ("observedDomain", set(&value.observed_domain)),
        ("excludedDomain", set(&value.excluded_domain)),
        (
            "continuity",
            string(match value.continuity {
                CoverageContinuity::Continuous => "continuous",
                CoverageContinuity::Gapped => "gapped",
                CoverageContinuity::Unknown => "unknown",
            }),
        ),
        (
            "completeness",
            string(match value.completeness {
                Completeness::Complete => "complete_for_declared_domain",
                Completeness::Bounded | Completeness::Partial => "partial",
                _ => "uncertified",
            }),
        ),
        ("negativePredicate", string(&value.negative_predicate)),
        (
            "stopReason",
            string(match value.stop_reason {
                CoverageStopReason::Complete => "complete",
                CoverageStopReason::BudgetExhausted => "budget_exhausted",
                CoverageStopReason::Cancelled => "cancelled",
                CoverageStopReason::SourceGap => "source_gap",
                CoverageStopReason::AuthorizationFiltered => "authorization_filtered",
                CoverageStopReason::Unsupported => "unsupported",
                CoverageStopReason::Error => "error",
            }),
        ),
        ("witnessDigest", digest(value.witness_digest())),
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

/// The privacy projection an answer is served under (`purpose`, policy generation, domains).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyProjection {
    /// Why the data is read.
    pub purpose: String,
    /// Exact privacy policy generation (the anchor's privacy epoch).
    pub policy_generation_id: String,
    /// Data domains the answer may carry.
    pub visible_domains: Vec<String>,
    /// Data domains withheld from the answer.
    pub redacted_domains: Vec<String>,
}

impl PrivacyProjection {
    /// `situation_capsule.v1` `privacyProjection` spelling.
    #[must_use]
    pub fn capsule_json(&self) -> String {
        object(&[
            ("policyGenerationId", string(&self.policy_generation_id)),
            ("purpose", string(&self.purpose)),
            ("visibleDomains", strings(&self.visible_domains)),
            ("redactedDomains", strings(&self.redacted_domains)),
        ])
    }

    /// `agent_response_envelope.v1` `effectivePrivacyProjection` spelling.
    #[must_use]
    pub fn envelope_json(&self) -> String {
        object(&[
            ("purpose", string(&self.purpose)),
            ("policyGenerationId", string(&self.policy_generation_id)),
            ("allowedDomains", strings(&self.visible_domains)),
            ("redactedDomains", strings(&self.redacted_domains)),
        ])
    }
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
                    ("validAt", evidence_anchor(valid_at)),
                    ("current", evidence_anchor(current)),
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

/// Whether a knowledge state is an epistemic boundary (anything but known or not applicable).
#[must_use]
pub const fn is_boundary(state: KnowledgeState) -> bool {
    !matches!(state, KnowledgeState::Known | KnowledgeState::NotApplicable)
}

/// Context every knowledge cell of one answer is rendered under.
#[derive(Clone, Copy, Debug)]
pub struct CellContext<'a> {
    /// Anchor every cell is based on.
    pub anchor: &'a LedgerAnchor,
    /// Mission the cells serve.
    pub mission_id: &'a str,
    /// Observable changes that invalidate every cell of the answer.
    pub invalidators: &'a [String],
}

/// `claim:<subject>:<predicate>` → (`<subject>`, `<predicate>`).
fn subject_predicate(claim_id: &str) -> (&str, &str) {
    let body = claim_id.strip_prefix("claim:").unwrap_or(claim_id);
    body.rsplit_once(':').unwrap_or((body, "holds"))
}

/// Whether a cell can change the next action: an epistemic boundary or a contradicted claim.
#[must_use]
pub fn can_change_action(cell: &KnowledgeCell) -> bool {
    is_boundary(cell.knowledge_state()) || !cell.contradictions().is_empty()
}

/// `KnowledgeCell` as `fss.agent_knowledge_cell.v1`: a redacted cell prints only its
/// withheld-statement marker as its value.
#[must_use]
pub fn knowledge_cell(value: &KnowledgeCell, context: &CellContext<'_>) -> String {
    let state = value.knowledge_state();
    let (subject, predicate) = subject_predicate(value.claim_id());
    let anchor = context.anchor;
    let mut fields = vec![
        ("schema", string("fss.agent_knowledge_cell.v1")),
        ("cellId", string(value.claim_id())),
        ("subject", string(subject)),
        ("predicate", string(predicate)),
        ("value", string(value.disclosable_statement())),
        ("knowledgeState", string(state.as_str())),
        ("provenanceClass", string(value.provenance().as_str())),
        ("basisAnchor", evidence_anchor(anchor)),
        (
            "validity",
            object(&[
                (
                    "temporal",
                    strings([format!(
                        "anchor:epoch:{}:commit:{}",
                        anchor.ledger_epoch, anchor.commit_sequence
                    )]),
                ),
                ("spatial", strings(Vec::<String>::new())),
                (
                    "policy",
                    strings([format!("policy-epoch:{}", anchor.policy_epoch)]),
                ),
                ("model", strings(Vec::<String>::new())),
                (
                    "privacy",
                    strings([format!("privacy-epoch:{}", anchor.privacy_epoch)]),
                ),
                ("invalidators", strings(context.invalidators)),
            ]),
        ),
        ("supportingEvidence", digests(&value.evidence_digests())),
        ("contradictingEvidence", digests(value.contradictions())),
        (
            "uncertainty",
            object(&[(
                "kind",
                string(match state {
                    KnowledgeState::Known | KnowledgeState::NotApplicable => "none",
                    KnowledgeState::Estimated => "qualitative",
                    _ => "unknown",
                }),
            )]),
        ),
        (
            "completeness",
            string(match state {
                KnowledgeState::Known => "complete_for_domain",
                KnowledgeState::NotApplicable => "not_applicable",
                _ => "uncertified",
            }),
        ),
        (
            "decisionRelevance",
            object(&[
                ("missions", strings([context.mission_id])),
                ("canChangeAction", can_change_action(value).to_string()),
                (
                    "priorityClass",
                    string(if !value.contradictions().is_empty() {
                        "critical"
                    } else if is_boundary(state) {
                        "high"
                    } else {
                        "normal"
                    }),
                ),
            ]),
        ),
        (
            "expiresAtNs",
            value
                .valid_until()
                .map_or_else(|| "null".to_owned(), |at| at.0.to_string()),
        ),
    ];
    if let Some(disposition) = value.hypothesis() {
        fields.push(("hypothesisDisposition", string(disposition.as_str())));
    }
    if let Some(basis) = value.state_basis() {
        fields.push(("stateBasis", state_basis(basis)));
    }
    object(&fields)
}

/// Registered consequence class of a consequence severity (0 negligible .. 5 critical).
#[must_use]
pub const fn consequence_class(severity: u8) -> &'static str {
    match severity {
        0 => "negligible",
        1 => "low",
        2 | 3 => "moderate",
        4 => "high",
        _ => "critical",
    }
}

/// Registered protected-loss class of a residual's consequence severity.
#[must_use]
pub const fn protected_loss_class(severity: u8) -> &'static str {
    match severity {
        0 | 1 => "low",
        2 | 3 => "moderate",
        4 => "high",
        _ => "critical",
    }
}

fn proof_handle(value: &ContentDigest) -> String {
    format!("fss://proof/{value}")
}

/// Affordances of one class kind whose compatible worlds include `world_id`.
fn discriminators(affordances: &[ActionAffordance], world_id: &str) -> Vec<String> {
    affordances
        .iter()
        .filter(|candidate| {
            candidate.class == AffordanceClass::Probe
                && candidate.supported_worlds.contains(world_id)
        })
        .map(|candidate| candidate.affordance_id.clone())
        .collect()
}

fn clamps(affordances: &[ActionAffordance]) -> Vec<String> {
    affordances
        .iter()
        .filter(|candidate| {
            matches!(
                candidate.class,
                AffordanceClass::Blocked | AffordanceClass::Unavailable
            )
        })
        .map(|candidate| candidate.affordance_id.clone())
        .collect()
}

fn alternative_world(value: &PossibleWorld, affordances: &[ActionAffordance]) -> String {
    object(&[
        ("worldId", string(&value.world_id)),
        ("summary", string(&value.description)),
        ("plausibility", string("possible")),
        (
            "consequenceClass",
            string(consequence_class(value.consequence_severity)),
        ),
        ("compatibleClaimIds", set(&value.claim_ids)),
        ("contradictionIds", strings(Vec::<String>::new())),
        ("assumptionIds", strings(Vec::<String>::new())),
        (
            "evidenceHandles",
            strings(value.evidence.iter().map(proof_handle)),
        ),
        (
            "discriminatorAffordanceIds",
            strings(discriminators(affordances, &value.world_id)),
        ),
        ("invalidators", strings(Vec::<String>::new())),
    ])
}

fn residual_world(value: &PossibleWorld, affordances: &[ActionAffordance]) -> String {
    object(&[
        ("residualId", string(&value.world_id)),
        ("summary", string(&value.description)),
        (
            "protectedLossClass",
            string(protected_loss_class(value.consequence_severity)),
        ),
        (
            "whyNotRuledOut",
            strings(
                value
                    .evidence
                    .iter()
                    .map(|root| format!("Evidence root {root} keeps it live.")),
            ),
        ),
        ("affectedScopes", set(&value.claim_ids)),
        (
            "bestAvailableDiscriminatorIds",
            strings(discriminators(affordances, &value.world_id)),
        ),
        ("requiredClampIds", strings(clamps(affordances))),
    ])
}

/// World-selection facts that the typed envelope does not carry.
#[derive(Clone, Copy, Debug)]
pub struct WorldSelection<'a> {
    /// Every world the deployment keeps live before aggregation.
    pub candidate_world_count: usize,
    /// Why selection stopped.
    pub stop_reason: &'a str,
}

/// `WorldEnvelope` as `fss.agent_world_envelope.v1`.
#[must_use]
pub fn world_envelope(
    value: &WorldEnvelope,
    affordances: &[ActionAffordance],
    cells: &[KnowledgeCell],
    selection: &WorldSelection<'_>,
) -> String {
    let alternatives: Vec<String> = value
        .alternatives
        .iter()
        .map(|world| alternative_world(world, affordances))
        .collect();
    let residuals: Vec<String> = value
        .adversarial_residuals
        .iter()
        .map(|world| residual_world(world, affordances))
        .collect();
    let dimensions: Vec<String> = cells
        .iter()
        .filter(|cell| is_boundary(cell.knowledge_state()))
        .map(|cell| {
            object(&[
                (
                    "dimensionId",
                    string(&format!("dimension:{}", cell.claim_id())),
                ),
                ("question", string(cell.disclosable_statement())),
                ("knowledgeState", string(cell.knowledge_state().as_str())),
                (
                    "decisionImpact",
                    string(
                        if cell.knowledge_state() == KnowledgeState::Conflicted
                            || !cell.contradictions().is_empty()
                        {
                            "critical"
                        } else {
                            "high"
                        },
                    ),
                ),
                (
                    "evidenceHandles",
                    strings(cell.evidence_digests().iter().map(proof_handle)),
                ),
                ("discriminatorAffordanceIds", strings(Vec::<String>::new())),
            ])
        })
        .collect();
    let envelope_digest = value.envelope_digest().ok();
    let retained = value.alternatives.len() + value.adversarial_residuals.len();
    let protected_residuals = value
        .adversarial_residuals
        .iter()
        .filter(|world| world.protected)
        .count();
    object(&[
        ("schema", string("fss.agent_world_envelope.v1")),
        ("envelopeId", string(&value.envelope_id)),
        ("objectiveId", string(&value.objective_id)),
        ("anchor", evidence_anchor(&value.anchor)),
        ("nominalClaimIds", set(&value.nominal_claim_ids)),
        (
            "certifiedCoreClaimIds",
            set(&value.certified_core_claim_ids),
        ),
        ("certifiedAbsences", "[]".to_owned()),
        ("materialAlternativeWorlds", array(&alternatives)),
        ("adversarialResiduals", array(&residuals)),
        ("commonInvariants", set(&value.common_invariants)),
        ("unresolvedDimensions", array(&dimensions)),
        ("collapseAffordanceIds", strings(Vec::<String>::new())),
        (
            "coverageBoundaryHandles",
            set(&value.coverage_boundary_handles),
        ),
        (
            "selectionWitness",
            object(&[
                (
                    "candidateWorldCount",
                    selection.candidate_world_count.to_string(),
                ),
                ("retainedWorldCount", retained.to_string()),
                ("dominatedWorldCount", "0".to_owned()),
                ("protectedResidualCount", protected_residuals.to_string()),
                ("stopReason", string(selection.stop_reason)),
                (
                    "decisionPathDigest",
                    envelope_digest.map_or_else(|| "null".to_owned(), digest),
                ),
            ]),
        ),
        (
            "digest",
            envelope_digest.map_or_else(|| "null".to_owned(), digest),
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

/// Registered `effectClass` of an operation mode.
#[must_use]
pub const fn effect_class(mode: OperationMode) -> &'static str {
    match mode {
        OperationMode::Read
        | OperationMode::ReadWait
        | OperationMode::ReadCompile
        | OperationMode::ReadCompute => "none",
        OperationMode::EffectCommit | OperationMode::LifecycleEffect => "external_consequential",
        OperationMode::SessionControl
        | OperationMode::CognitionWrite
        | OperationMode::PlanPrepare
        | OperationMode::ContinuityPublish
        | OperationMode::AdvisoryWrite
        | OperationMode::DiagnosticPrepare => "cognition",
    }
}

/// Context every affordance of one answer is rendered under.
#[derive(Clone, Copy, Debug)]
pub struct AffordanceContext<'a> {
    /// Anchor the affordance was classified at.
    pub anchor: &'a LedgerAnchor,
    /// World envelope it was classified against.
    pub world_envelope_id: &'a str,
    /// The anchor's evidence time: no affordance is claimed valid past its anchor.
    pub expires_at_ns: i128,
    /// Observable changes that invalidate the listing.
    pub invalidators: &'a [String],
}

/// `ActionAffordance` as `fss.agent_affordance.v1`: a listed next move, never an executed one.
///
/// The reference frontier does not estimate value or risk: `valueVector` and the numeric
/// `riskVector` components are 0 and `sensitivity` says so (a registered drift, not a claim of
/// zero value). An unregistered operation name cannot be rendered and yields `None`.
#[must_use]
pub fn affordance(value: &ActionAffordance, context: &AffordanceContext<'_>) -> Option<String> {
    let operation = AgentOperation::from_name(&value.operation).ok()?;
    let effect = effect_class(operation.mode());
    let executable = !matches!(
        value.class,
        AffordanceClass::Blocked | AffordanceClass::Unavailable
    );
    let zero_value = object(&[
        ("decisionLossReduction", "0".to_owned()),
        ("informationGain", "0".to_owned()),
        ("coverageGain", "0".to_owned()),
        ("obligationReduction", "0".to_owned()),
    ]);
    Some(object(&[
        ("schema", string("fss.agent_affordance.v1")),
        ("affordanceId", string(&value.affordance_id)),
        ("operationId", string(operation.id())),
        ("purpose", string(&value.rationale)),
        ("basisAnchor", evidence_anchor(context.anchor)),
        ("worldEnvelopeId", string(context.world_envelope_id)),
        ("robustnessClass", string(robustness_class(value.class))),
        ("compatibleWorldIds", set(&value.supported_worlds)),
        ("unsafeWorldIds", set(&value.unsafe_worlds)),
        ("targets", strings([value.target.as_str()])),
        ("requiredCapabilities", set(&value.required_capabilities)),
        ("inputSchema", string(operation.request_payload_schema())),
        ("outputView", string(operation.default_view())),
        ("preconditions", "[]".to_owned()),
        ("invalidators", strings(context.invalidators)),
        ("expiresAtNs", context.expires_at_ns.max(0).to_string()),
        (
            "idempotencyClass",
            string(if effect == "none" {
                "read"
            } else {
                "not_retryable"
            }),
        ),
        ("effectClass", string(effect)),
        (
            "reversibility",
            string(if effect == "none" {
                "not_applicable"
            } else if value.reversible {
                "reversible"
            } else {
                "irreversible"
            }),
        ),
        (
            "expectedEvidence",
            strings(operation.response_payload_schemas().iter().copied()),
        ),
        ("valueVector", zero_value),
        ("costVector", budget(&value.cost)),
        (
            "riskVector",
            object(&[
                ("safety", "0".to_owned()),
                ("privacy", "0".to_owned()),
                ("duplication", "0".to_owned()),
                ("irreversibility", "0".to_owned()),
                (
                    "worstCase",
                    string(if executable {
                        "The answer is stale once the ledger head advances."
                    } else {
                        "Not executable in this build; listing it grants no authority."
                    }),
                ),
            ]),
        ),
        (
            "sensitivity",
            strings(["value and risk are not estimated by the reference frontier"]),
        ),
        ("reason", string(&value.rationale)),
        (
            "stopCondition",
            string(match value.class {
                AffordanceClass::Wait => "The ledger head advances past the anchor.",
                AffordanceClass::Blocked | AffordanceClass::Unavailable => {
                    "Not executable in this build."
                }
                _ => "One answer is returned.",
            }),
        ),
    ]))
}

/// Renders `ids` as affordance objects found in `affordances`; `None` if any id is missing or
/// unrenderable (a response never lists an affordance it cannot describe).
#[must_use]
pub fn affordance_objects(
    ids: &[String],
    affordances: &[ActionAffordance],
    context: &AffordanceContext<'_>,
) -> Option<Vec<String>> {
    ids.iter()
        .map(|id| {
            affordances
                .iter()
                .find(|candidate| candidate.affordance_id == *id)
                .and_then(|candidate| affordance(candidate, context))
        })
        .collect()
}

/// `ResourceState` as the capsule's `resourceState` section.
#[must_use]
pub fn resource_state(value: &ResourceState) -> String {
    object(&[
        ("available", budget(&value.available)),
        ("reserved", budget(&value.reserved)),
        ("pressure", string(value.pressure.as_str())),
        ("degradedDimensions", set(&value.degraded_dimensions)),
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

/// `SemanticContextPack` as `fss.semantic_context_pack.v1`.
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
        ("anchor", evidence_anchor(&value.anchor)),
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
            let mut fields = vec![
                ("kind", string(transform.kind.as_str())),
                ("scope", string(&transform.scope)),
                ("lossClass", string(transform.loss_class.as_str())),
            ];
            if let Some(details) = transform.details.as_deref() {
                fields.push(("details", string(details)));
            }
            object(&fields)
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
        ("sourceAnchor", evidence_anchor(&value.source_anchor)),
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
    ])
}

/// `ObjectiveContract` as `fss.agent_objective_contract.v1`.
///
/// `softPreferences` and `timeIntervals` are rendered only when empty (their typed form is text,
/// the schema's is a weighted object): an orientation carries neither.
#[must_use]
pub fn objective_contract(value: &ObjectiveContract) -> Option<String> {
    if !value.soft_preferences.is_empty() || !value.scope.time_intervals.is_empty() {
        return None;
    }
    let scope = &value.scope;
    Some(object(&[
        ("schema", string(ObjectiveContract::SCHEMA)),
        ("objectiveId", string(&value.objective_id)),
        (
            "source",
            object(&[
                ("principal", string(&value.source_principal)),
                ("requestDigest", string(&value.source_request_digest)),
                ("naturalLanguage", "null".to_owned()),
            ]),
        ),
        ("desiredOutcome", string(&value.desired_outcome)),
        ("successPredicates", strings(&value.success_predicates)),
        ("failurePredicates", strings(&value.failure_predicates)),
        ("stopConditions", strings(&value.stop_conditions)),
        ("hardConstraints", strings(&value.hard_constraints)),
        ("softPreferences", "[]".to_owned()),
        (
            "scope",
            object(&[
                ("deployments", strings(&scope.deployments)),
                ("zones", strings(&scope.zones)),
                ("subjects", strings(&scope.subjects)),
                ("devices", strings(&scope.devices)),
                ("timeIntervals", "[]".to_owned()),
                ("dataClasses", strings(&scope.data_classes)),
            ]),
        ),
        ("budgets", budget(&value.budgets)),
        ("allowedActions", strings(&value.allowed_actions)),
        ("requiredApprovals", strings(&value.required_approvals)),
        ("terminalProof", strings(&value.terminal_proof)),
        ("decisionDigest", string(&value.decision_digest)),
    ]))
}

/// One `agent_cognitive_envelope.v1` evidence handle: an object the answer names, at the
/// hydration level it carries, with the levels a caller may request next.
#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceHandle {
    /// Stable handle identity (the string the typed envelope carries).
    pub handle_id: String,
    /// Digest of the object.
    pub object_digest: ContentDigest,
    /// Object kind.
    pub kind: String,
    /// Level the answer carries.
    pub hydration: &'static str,
    /// Levels a caller may request.
    pub allowed_hydration: Vec<&'static str>,
    /// Privacy class.
    pub privacy_class: String,
    /// Availability (verified read-back).
    pub availability: &'static str,
    /// Conservative price of the next level.
    pub estimated_cost: BudgetVector,
    /// Capability the next level requires.
    pub required_capability: Option<String>,
}

fn evidence_handle(value: &EvidenceHandle) -> String {
    object(&[
        ("handleId", string(&value.handle_id)),
        ("objectDigest", digest(value.object_digest)),
        ("kind", string(&value.kind)),
        ("hydration", string(value.hydration)),
        ("allowedHydration", strings(&value.allowed_hydration)),
        ("privacyClass", string(&value.privacy_class)),
        ("availability", string(value.availability)),
        ("estimatedCost", budget(&value.estimated_cost)),
        (
            "requiredCapability",
            optional_string(value.required_capability.as_deref()),
        ),
    ])
}

/// `AgentCognitiveEnvelope` as `fss.agent_cognitive_envelope.v1`.
///
/// The typed envelope carries evidence-handle and next-action identities; `handles` and
/// `next_actions` are their registered objects, in the same order. `None` when the objects do not
/// match the identities exactly.
#[must_use]
pub fn cognitive_envelope(
    value: &AgentCognitiveEnvelope,
    handles: &[EvidenceHandle],
    next_actions: &[String],
) -> Option<String> {
    if handles.len() != value.evidence_handles.len()
        || handles
            .iter()
            .zip(&value.evidence_handles)
            .any(|(handle, id)| handle.handle_id != *id)
        || next_actions.len() != value.next_actions.len()
    {
        return None;
    }
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
    let handles: Vec<String> = handles.iter().map(evidence_handle).collect();
    let coverage = &value.coverage;
    let budget_block = &value.budget;
    let continuity = &value.continuity;
    Some(object(&[
        ("schema", string(AgentCognitiveEnvelope::SCHEMA)),
        ("contractBasis", contract_basis(&value.contract_basis)),
        ("requestId", string(&value.request_id)),
        ("responseId", string(&value.response_id)),
        ("traceId", string(&value.trace_id)),
        ("operationId", string(value.operation.id())),
        ("semanticVerb", string(&value.semantic_verb)),
        ("viewId", string(value.view.id())),
        ("answerClass", string(value.answer_class.as_str())),
        ("basisAnchor", evidence_anchor(&value.basis_anchor)),
        ("resultAnchor", "null".to_owned()),
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
        ("evidenceHandles", array(&handles)),
        ("nextActions", array(next_actions)),
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
    ]))
}

/// `AgentResponseEnvelope` as `fss.agent_response_envelope.v1`.
///
/// Pinned JSON fields (`payload`, `budgets`, `effectivePrivacyProjection`) are embedded verbatim;
/// the payload digest is the SHA-256 of exactly those payload bytes. The typed envelope carries
/// affordance identities; `affordances` are their registered objects in the same order (`None`
/// when the counts differ).
#[must_use]
pub fn response_envelope(value: &AgentResponseEnvelope, affordances: &[String]) -> Option<String> {
    if affordances.len() != value.affordances.len() {
        return None;
    }
    let boundary = &value.execution_boundary;
    Some(object(&[
        ("schema", string(AgentResponseEnvelope::SCHEMA)),
        ("contractBasis", contract_basis(&value.contract_basis)),
        ("operationId", string(value.operation.id())),
        ("requestId", string(&value.request_id)),
        ("responseRevision", value.response_revision.to_string()),
        ("principalId", string(&value.principal_id)),
        ("sessionId", optional_string(value.session_id.as_deref())),
        ("missionId", optional_string(value.mission_id.as_deref())),
        ("traceId", string(&value.trace_id)),
        ("inputAnchor", evidence_anchor(&value.input_anchor)),
        (
            "outputAnchor",
            value
                .output_anchor
                .as_ref()
                .map_or_else(|| "null".to_owned(), evidence_anchor),
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
        ("affordances", array(affordances)),
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
    ]))
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

    #[test]
    fn not_applicable_sentinels_never_parse_as_content_digests() {
        let sentinel =
            not_applicable_sentinel("fss.evidence_anchor.v1", "deviceGeneration", "reason");
        assert!(sentinel.starts_with("fss-na:"));
        assert_eq!(sentinel.len(), "fss-na:".len() + 64);
        assert!(ContentDigest::parse(&sentinel).is_err());
        assert_ne!(
            sentinel,
            not_applicable_sentinel("fss.evidence_anchor.v1", "streamGeneration", "reason")
        );
    }

    #[test]
    fn claim_identities_split_into_subject_and_predicate() {
        assert_eq!(
            subject_predicate("claim:deployment:ledger-head"),
            ("deployment", "ledger-head")
        );
        assert_eq!(
            subject_predicate("claim:event:event:watch:ab:lifecycle"),
            ("event:event:watch:ab", "lifecycle")
        );
        assert_eq!(subject_predicate("claim:site"), ("site", "holds"));
    }

    #[test]
    fn severities_map_to_registered_consequence_classes() {
        assert_eq!(consequence_class(0), "negligible");
        assert_eq!(consequence_class(5), "critical");
        assert_eq!(protected_loss_class(0), "low");
        assert_eq!(protected_loss_class(4), "high");
    }
}
