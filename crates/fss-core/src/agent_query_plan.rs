#![forbid(unsafe_code)]
//! The compiled agent query plan (fss.agent_query_plan.v1).
//!
//! Normative source: `schemas/agent_query_plan.v1.json`
//! (`registries/SCHEMAS.md` `SCHEMA-AGENT-QUERY-PLAN-001`). Free-form
//! language compiles into this inspectable plan; it never crosses an effect
//! boundary: the serving operation must be a registered read/compute row
//! whose request payload schema is this plan's schema identity.
//!
//! Interpretations are enumerated and the selected interpretation must be
//! one of them - an opaque selection outside the enumerated alternatives is
//! refused.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use crate::agent_operation::AgentOperation;
use crate::agent_view::AgentView;
use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::ContractError;
use crate::contract_basis::ContractBasisError;
use crate::contract_basis::registered_operation;
use crate::decision_card_v1::EvidenceAnchorRecordV1;
use crate::digest::ContentDigest;
use crate::evidence::LedgerAnchor;
use crate::ids::validate_id;
use crate::json_input::{self, Value};
use crate::{BudgetVector, MissionId, SessionId};

/// Binary wire magic header for versioned [`AgentQueryPlan`] envelopes (`SCHEMA-AGENT-QUERY-001`).
pub const AGENT_QUERY_PLAN_WIRE_MAGIC: [u8; 8] = *b"FSSAQP01";
/// Supported durable binary format version for [`AgentQueryPlan`].
pub const AGENT_QUERY_PLAN_FORMAT_VERSION: u32 = 1;
/// Hard ceiling on serialized binary wire bytes of one [`AgentQueryPlan`] (512 KiB).
pub const MAX_AGENT_QUERY_PLAN_WIRE_BYTES: usize = 512 * 1024;

/// Typed error returned by [`AgentQueryPlan`] binary or JSON codecs (`SCHEMA-AGENT-QUERY-001`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentQueryPlanCodecError {
    /// Wire envelope lacked [`AGENT_QUERY_PLAN_WIRE_MAGIC`].
    InvalidMagic,
    /// Wire envelope declared an unsupported format version.
    UnsupportedVersion {
        /// Observed format version.
        version: u32,
    },
    /// Schema discriminator disagreed with `fss.agent_query_plan.v1`.
    SchemaMismatch {
        /// Expected schema string.
        expected: &'static str,
        /// Observed schema string.
        observed: String,
    },
    /// Payload size exceeded hard ceiling.
    BoundsExceeded {
        /// Observed bytes.
        observed: usize,
        /// Hard ceiling.
        maximum: usize,
    },
    /// Binary or JSON payload was malformed, truncated, or carried unknown/duplicate fields.
    MalformedPayload(String),
    /// Binary trailing SHA-256 commitment failed verification.
    ChecksumMismatch,
    /// Semantic contract or ContractBasis compilation validation failed.
    Contract(ContractBasisError),
}

impl fmt::Display for AgentQueryPlanCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for AgentQueryPlanCodecError {}

impl From<ContractBasisError> for AgentQueryPlanCodecError {
    fn from(value: ContractBasisError) -> Self {
        Self::Contract(value)
    }
}

/// Requested completeness of one compiled query (registered enum).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryCompletenessRequested {
    /// Best effort; no completeness guarantee.
    BestEffort,
    /// Complete only within the declared bound.
    Bounded,
    /// A certified absence is an acceptable answer.
    CertifiedAbsence,
    /// Complete enough for the decision.
    DecisionComplete,
}

impl QueryCompletenessRequested {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BestEffort => "best_effort",
            Self::Bounded => "bounded",
            Self::CertifiedAbsence => "certified_absence",
            Self::DecisionComplete => "decision_complete",
        }
    }

    /// Parses the stable registry spelling.
    pub fn parse(raw: &str) -> Result<Self, ContractError> {
        match raw {
            "best_effort" => Ok(Self::BestEffort),
            "bounded" => Ok(Self::Bounded),
            "certified_absence" => Ok(Self::CertifiedAbsence),
            "decision_complete" => Ok(Self::DecisionComplete),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// One enumerated interpretation of the natural-language objective.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryInterpretation {
    /// Stable interpretation identity.
    pub interpretation_id: String,
    /// What this reading of the objective means.
    pub description: String,
    /// Whether this reading is material to the decision.
    pub material: bool,
    /// Whether safe-read semantics are the default for this reading.
    pub safe_read_default: bool,
    /// Required clarification, when the reading is ambiguous.
    pub required_clarification: Option<String>,
}

impl QueryInterpretation {
    /// Validates one interpretation against the schema constraints.
    pub fn new(
        interpretation_id: impl Into<String>,
        description: impl Into<String>,
        material: bool,
        safe_read_default: bool,
        required_clarification: Option<String>,
    ) -> Result<Self, ContractError> {
        let interpretation_id = interpretation_id.into();
        let description = description.into();
        validate_id(&interpretation_id)?;
        if interpretation_id.len() > 256
            || description.is_empty()
            || description.len() > 8192
            || description.chars().any(char::is_control)
        {
            return Err(ContractError::InvalidIdentifier);
        }
        if let Some(ref clar) = required_clarification
            && (clar.len() > 2048 || clar.chars().any(char::is_control))
        {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self {
            interpretation_id,
            description,
            material,
            safe_read_default,
            required_clarification,
        })
    }
}

/// The compiled, inspectable query plan (AOP-003/005/009/011/014 payload).
#[derive(Clone, Debug, PartialEq)]
pub struct AgentQueryPlan {
    query_plan_id: String,
    mission_id: MissionId,
    session_id: SessionId,
    operation: AgentOperation,
    original_text_digest: ContentDigest,
    taint_sources: Vec<String>,
    basis_anchor: LedgerAnchor,
    objective: String,
    resolved_targets: Vec<String>,
    domains: Vec<String>,
    capability_projection: Vec<String>,
    privacy_projection: Vec<String>,
    completeness_requested: QueryCompletenessRequested,
    budget: BudgetVector,
    interpretations: Vec<QueryInterpretation>,
    selected_interpretation: String,
    estimated_cost: BudgetVector,
    output_view: AgentView,
    created_at_ns: i128,
}

impl AgentQueryPlan {
    /// Schema identity implemented by this type.
    pub const SCHEMA: &str = "fss.agent_query_plan.v1";

    /// Compiles and validates a query plan (fail closed).
    ///
    /// Enforcement at this boundary:
    /// - `operation_id` must resolve to a registered read/compute row whose
    ///   registered request payload schema is this plan's schema identity
    ///   (AOP-003/005/009/011/014) - plans never serve effect rows;
    /// - `output_view` must be a registered view;
    /// - `selected_interpretation` must be one of the enumerated
    ///   interpretations (1..=16);
    /// - all collection bounds and identifier alphabets follow the schema.
    #[allow(clippy::too_many_arguments)]
    pub fn compile(
        query_plan_id: impl Into<String>,
        mission_id: MissionId,
        session_id: SessionId,
        basis: &crate::ContractBasis,
        operation_id: &str,
        original_text_digest: ContentDigest,
        taint_sources: Vec<String>,
        basis_anchor: LedgerAnchor,
        objective: impl Into<String>,
        resolved_targets: Vec<String>,
        domains: Vec<String>,
        capability_projection: Vec<String>,
        privacy_projection: Vec<String>,
        completeness_requested: QueryCompletenessRequested,
        budget: BudgetVector,
        interpretations: Vec<QueryInterpretation>,
        selected_interpretation: impl Into<String>,
        estimated_cost: BudgetVector,
        output_view_id: &str,
        created_at_ns: i128,
    ) -> Result<Self, ContractBasisError> {
        let operation = registered_operation(basis, &Self::serving_operation(operation_id)?)?;
        let _ = operation;
        let query_plan_id = query_plan_id.into();
        validate_id(&query_plan_id)
            .map_err(|_| ContractBasisError::Contract(ContractError::InvalidIdentifier))?;
        if query_plan_id.len() > 256 {
            return Err(ContractBasisError::Contract(
                ContractError::InvalidIdentifier,
            ));
        }
        if taint_sources.len() > 64
            || resolved_targets.len() > 128
            || domains.len() > 128
            || capability_projection.len() > 256
            || privacy_projection.len() > 128
        {
            return Err(ContractBasisError::Contract(
                ContractError::CountBoundExceeded,
            ));
        }
        for source in &taint_sources {
            validate_id(source)
                .map_err(|_| ContractBasisError::Contract(ContractError::InvalidIdentifier))?;
            if source.len() > 256 {
                return Err(ContractBasisError::Contract(
                    ContractError::InvalidIdentifier,
                ));
            }
        }
        for target in &resolved_targets {
            validate_schema_token(target)?;
        }
        for domain in &domains {
            if domain.is_empty() || domain.len() > 1024 || domain.chars().any(char::is_control) {
                return Err(ContractBasisError::Contract(
                    ContractError::InvalidIdentifier,
                ));
            }
        }
        for cap in &capability_projection {
            validate_schema_token(cap)?;
        }
        for priv_item in &privacy_projection {
            validate_schema_token(priv_item)?;
        }
        if !budget.is_valid() || !estimated_cost.is_valid() {
            return Err(ContractBasisError::Contract(
                ContractError::EvidenceRequired,
            ));
        }
        if created_at_ns < 0 {
            return Err(ContractBasisError::Contract(
                ContractError::InvalidIdentifier,
            ));
        }
        let objective = objective.into();
        if objective.is_empty() || objective.len() > 8192 || objective.chars().any(char::is_control)
        {
            return Err(ContractBasisError::Contract(
                ContractError::InvalidIdentifier,
            ));
        }
        if interpretations.is_empty() || interpretations.len() > 16 {
            return Err(ContractBasisError::Contract(
                ContractError::CountBoundExceeded,
            ));
        }
        let mut seen_interp_ids = BTreeSet::new();
        for interpretation in &interpretations {
            if !seen_interp_ids.insert(interpretation.interpretation_id.as_str()) {
                return Err(ContractBasisError::Contract(
                    ContractError::InvalidIdentifier,
                ));
            }
        }
        let selected_interpretation = selected_interpretation.into();
        if !interpretations
            .iter()
            .any(|interpretation| interpretation.interpretation_id == selected_interpretation)
        {
            return Err(ContractBasisError::Contract(ContractError::NotFound));
        }
        let output_view = AgentView::from_id(output_view_id)
            .map_err(|_| ContractBasisError::Contract(ContractError::InvalidIdentifier))?;
        Ok(Self {
            query_plan_id,
            mission_id,
            session_id,
            operation,
            original_text_digest,
            taint_sources,
            basis_anchor,
            objective,
            resolved_targets,
            domains,
            capability_projection,
            privacy_projection,
            completeness_requested,
            budget,
            interpretations,
            selected_interpretation,
            estimated_cost,
            output_view,
            created_at_ns,
        })
    }

    /// Resolves the plan-serving operation or refuses effect rows and rows
    /// whose payload is not this plan.
    fn serving_operation(operation_id: &str) -> Result<String, ContractBasisError> {
        let operation = AgentOperation::from_id(operation_id)
            .map_err(|_| ContractBasisError::Contract(ContractError::InvalidIdentifier))?;
        if operation.effectful() || operation.request_payload_schema() != Self::SCHEMA {
            return Err(ContractBasisError::Contract(
                ContractError::InvalidEffectTransition,
            ));
        }
        Ok(operation.name().to_owned())
    }

    /// Returns the plan identity.
    #[must_use]
    pub fn query_plan_id(&self) -> &str {
        &self.query_plan_id
    }

    /// Returns the resolved serving operation.
    #[must_use]
    pub const fn operation(&self) -> AgentOperation {
        self.operation
    }

    /// Returns the bounded target identities or collection scopes selected by the plan.
    #[must_use]
    pub fn resolved_targets(&self) -> &[String] {
        &self.resolved_targets
    }

    /// Returns the enumerated interpretations.
    #[must_use]
    pub fn interpretations(&self) -> &[QueryInterpretation] {
        &self.interpretations
    }

    /// Returns the selected interpretation identity.
    #[must_use]
    pub fn selected_interpretation(&self) -> &str {
        &self.selected_interpretation
    }

    /// Returns the registered output view.
    #[must_use]
    pub const fn output_view(&self) -> AgentView {
        self.output_view
    }

    /// Compiled query plans belong to query cognition and NEVER grant effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Returns the mission identity.
    #[must_use]
    pub const fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    /// Returns the session identity.
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the canonical digest of the original prompt/query text.
    #[must_use]
    pub const fn original_text_digest(&self) -> ContentDigest {
        self.original_text_digest
    }

    /// Returns the explicit taint sources carried into this compiled plan.
    #[must_use]
    pub fn taint_sources(&self) -> &[String] {
        &self.taint_sources
    }

    /// Returns the pinned basis anchor.
    #[must_use]
    pub const fn basis_anchor(&self) -> &LedgerAnchor {
        &self.basis_anchor
    }

    /// Returns the objective text.
    #[must_use]
    pub fn objective(&self) -> &str {
        &self.objective
    }

    /// Returns the bounded query domains.
    #[must_use]
    pub fn domains(&self) -> &[String] {
        &self.domains
    }

    /// Returns the capability projection.
    #[must_use]
    pub fn capability_projection(&self) -> &[String] {
        &self.capability_projection
    }

    /// Returns the privacy projection.
    #[must_use]
    pub fn privacy_projection(&self) -> &[String] {
        &self.privacy_projection
    }

    /// Returns the requested completeness class.
    #[must_use]
    pub const fn completeness_requested(&self) -> QueryCompletenessRequested {
        self.completeness_requested
    }

    /// Returns the declared budget vector.
    #[must_use]
    pub const fn budget(&self) -> BudgetVector {
        self.budget
    }

    /// Returns the estimated cost vector.
    #[must_use]
    pub const fn estimated_cost(&self) -> BudgetVector {
        self.estimated_cost
    }

    /// Returns the deterministic creation timestamp in nanoseconds.
    #[must_use]
    pub const fn created_at_ns(&self) -> i128 {
        self.created_at_ns
    }

    /// Returns the domain-separated canonical digest under the schema identity.
    #[must_use]
    pub fn plan_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
    }

    /// Encodes this compiled query plan into bounded checksummed binary bytes (`FSSAQP01` v1).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, AgentQueryPlanCodecError> {
        let digest = self.plan_digest();
        let mut enc = CanonicalEncoder::new();
        enc.u32(AGENT_QUERY_PLAN_FORMAT_VERSION);
        self.encode_canonical(&mut enc);
        enc.digest(digest);
        let body = enc
            .finish_checked()
            .map_err(|e| AgentQueryPlanCodecError::MalformedPayload(e.to_string()))?;
        let total = AGENT_QUERY_PLAN_WIRE_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_AGENT_QUERY_PLAN_WIRE_BYTES {
            return Err(AgentQueryPlanCodecError::BoundsExceeded {
                observed: total,
                maximum: MAX_AGENT_QUERY_PLAN_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&AGENT_QUERY_PLAN_WIRE_MAGIC);
        out.extend_from_slice(&AGENT_QUERY_PLAN_FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and cryptographically verifies binary [`AgentQueryPlan`] bytes (`FSSAQP01` v1).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AgentQueryPlanCodecError> {
        if bytes.len() > MAX_AGENT_QUERY_PLAN_WIRE_BYTES {
            return Err(AgentQueryPlanCodecError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_AGENT_QUERY_PLAN_WIRE_BYTES,
            });
        }
        if bytes.len() < 12 || bytes[..8] != AGENT_QUERY_PLAN_WIRE_MAGIC {
            return Err(AgentQueryPlanCodecError::InvalidMagic);
        }
        let header_ver = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if header_ver != AGENT_QUERY_PLAN_FORMAT_VERSION {
            return Err(AgentQueryPlanCodecError::UnsupportedVersion {
                version: header_ver,
            });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let body_ver = dec
            .u32()
            .map_err(|e| AgentQueryPlanCodecError::MalformedPayload(e.to_string()))?;
        if body_ver != header_ver {
            return Err(AgentQueryPlanCodecError::UnsupportedVersion { version: body_ver });
        }
        let plan = Self::decode_canonical(&mut dec)
            .map_err(|e| AgentQueryPlanCodecError::MalformedPayload(e.to_string()))?;
        let stored_digest = dec
            .digest()
            .map_err(|e| AgentQueryPlanCodecError::MalformedPayload(e.to_string()))?;
        dec.ensure_finished().map_err(|_| {
            AgentQueryPlanCodecError::MalformedPayload(
                "trailing bytes after AgentQueryPlan envelope".to_owned(),
            )
        })?;
        if plan.plan_digest() != stored_digest {
            return Err(AgentQueryPlanCodecError::ChecksumMismatch);
        }
        Ok(plan)
    }

    /// Emits deterministic canonical JSON conforming strictly to `schemas/agent_query_plan.v1.json`.
    pub fn to_canonical_json(
        &self,
        device_generation: &str,
        stream_generation: &str,
    ) -> Result<String, AgentQueryPlanCodecError> {
        let anchor_rec = EvidenceAnchorRecordV1::from_ledger_anchor(
            &self.basis_anchor,
            device_generation,
            stream_generation,
        )
        .map_err(|e| AgentQueryPlanCodecError::MalformedPayload(e.to_string()))?;
        let mut out = String::with_capacity(1024);
        out.push('{');
        push_key(&mut out, "basisAnchor");
        anchor_rec.write_canonical_json(&mut out);
        out.push(',');
        push_key(&mut out, "budget");
        write_budget_json(&mut out, self.budget);
        out.push(',');
        push_key(&mut out, "capabilityProjection");
        write_str_array(&mut out, &self.capability_projection);
        out.push(',');
        push_kv_str(
            &mut out,
            "completenessRequested",
            self.completeness_requested.as_str(),
        );
        out.push(',');
        push_key(&mut out, "createdAtNs");
        out.push_str(&self.created_at_ns.to_string());
        out.push(',');
        push_key(&mut out, "domains");
        write_str_array(&mut out, &self.domains);
        out.push(',');
        push_key(&mut out, "estimatedCost");
        write_budget_json(&mut out, self.estimated_cost);
        out.push(',');
        push_key(&mut out, "interpretations");
        out.push('[');
        for (i, interp) in self.interpretations.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('{');
            push_kv_str(&mut out, "description", &interp.description);
            out.push(',');
            push_kv_str(&mut out, "interpretationId", &interp.interpretation_id);
            out.push(',');
            push_key(&mut out, "material");
            out.push_str(if interp.material { "true" } else { "false" });
            if let Some(ref clar) = interp.required_clarification {
                out.push(',');
                push_kv_str(&mut out, "requiredClarification", clar);
            }
            out.push(',');
            push_key(&mut out, "safeReadDefault");
            out.push_str(if interp.safe_read_default {
                "true"
            } else {
                "false"
            });
            out.push('}');
        }
        out.push(']');
        out.push(',');
        push_kv_str(&mut out, "missionId", self.mission_id.as_str());
        out.push(',');
        push_kv_str(&mut out, "objective", &self.objective);
        out.push(',');
        push_kv_str(&mut out, "operationId", self.operation.id());
        out.push(',');
        push_kv_str(
            &mut out,
            "originalTextDigest",
            &self.original_text_digest.to_text(),
        );
        out.push(',');
        push_kv_str(&mut out, "outputView", self.output_view.id());
        out.push(',');
        push_key(&mut out, "privacyProjection");
        write_str_array(&mut out, &self.privacy_projection);
        out.push(',');
        push_kv_str(&mut out, "queryPlanId", &self.query_plan_id);
        out.push(',');
        push_key(&mut out, "resolvedTargets");
        write_str_array(&mut out, &self.resolved_targets);
        out.push(',');
        push_kv_str(&mut out, "schema", Self::SCHEMA);
        out.push(',');
        push_kv_str(
            &mut out,
            "selectedInterpretation",
            &self.selected_interpretation,
        );
        out.push(',');
        push_kv_str(&mut out, "sessionId", self.session_id.as_str());
        out.push(',');
        push_key(&mut out, "taintSources");
        write_str_array(&mut out, &self.taint_sources);
        out.push('}');
        Ok(out)
    }

    /// Strictly parses and compiles a JSON document against `schemas/agent_query_plan.v1.json`
    /// and the active `basis`, rejecting unknown fields, duplicate keys, wrong schema, effectful
    /// operations, unenumerated interpretations, invalid budgets, and trailing input.
    pub fn from_json_with_basis(
        text: &str,
        basis: &crate::ContractBasis,
    ) -> Result<Self, AgentQueryPlanCodecError> {
        const ALLOWED: &[&str] = &[
            "schema",
            "queryPlanId",
            "missionId",
            "sessionId",
            "operationId",
            "originalTextDigest",
            "taintSources",
            "basisAnchor",
            "objective",
            "resolvedTargets",
            "domains",
            "timeDomain",
            "spatialDomain",
            "capabilityProjection",
            "privacyProjection",
            "completenessRequested",
            "freshnessRequirement",
            "budget",
            "interpretations",
            "selectedInterpretation",
            "estimatedCost",
            "outputView",
            "preparedIntentDraftId",
            "createdAtNs",
        ];
        let val = json_input::parse(text)
            .map_err(|e| AgentQueryPlanCodecError::MalformedPayload(e.to_string()))?;
        let obj = val.object().ok_or_else(|| {
            AgentQueryPlanCodecError::MalformedPayload("root must be a JSON object".to_owned())
        })?;
        for k in obj.keys() {
            if !ALLOWED.contains(&k.as_str()) {
                return Err(AgentQueryPlanCodecError::MalformedPayload(format!(
                    "unknown property '{k}' in agent_query_plan (additionalProperties: false)"
                )));
            }
        }
        let schema = req_str(obj, "schema")?;
        if schema != Self::SCHEMA {
            return Err(AgentQueryPlanCodecError::SchemaMismatch {
                expected: Self::SCHEMA,
                observed: schema.to_owned(),
            });
        }
        let query_plan_id = req_str(obj, "queryPlanId")?.to_owned();
        let mission_id = MissionId::parse(req_str(obj, "missionId")?)
            .map_err(|e| AgentQueryPlanCodecError::Contract(ContractBasisError::Contract(e)))?;
        let session_id = SessionId::parse(req_str(obj, "sessionId")?)
            .map_err(|e| AgentQueryPlanCodecError::Contract(ContractBasisError::Contract(e)))?;
        let operation_id = req_str(obj, "operationId")?;
        let original_text_digest = ContentDigest::parse(req_str(obj, "originalTextDigest")?)
            .map_err(|e| AgentQueryPlanCodecError::Contract(ContractBasisError::Contract(e)))?;
        let taint_sources = req_str_vec(obj, "taintSources", 64)?;
        let basis_anchor = parse_basis_anchor(obj.get("basisAnchor").ok_or_else(|| {
            AgentQueryPlanCodecError::MalformedPayload("missing basisAnchor".to_owned())
        })?)?;
        let objective = req_str(obj, "objective")?.to_owned();
        let resolved_targets = req_str_vec(obj, "resolvedTargets", 128)?;
        let domains = req_str_vec(obj, "domains", 128)?;
        for opt_domain in ["timeDomain", "spatialDomain"] {
            if let Some(v) = obj.get(opt_domain) {
                match v {
                    Value::Null => {}
                    Value::Text(s) if s.len() <= 2048 && !s.chars().any(char::is_control) => {}
                    _ => {
                        return Err(AgentQueryPlanCodecError::MalformedPayload(format!(
                            "{opt_domain} must be null or string <= 2048 bytes without control chars"
                        )));
                    }
                }
            }
        }
        if let Some(v) = obj.get("freshnessRequirement") {
            match v {
                Value::Text(s)
                    if !s.is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control) => {}
                _ => {
                    return Err(AgentQueryPlanCodecError::MalformedPayload(
                        "freshnessRequirement must be non-empty string <= 1024 bytes".to_owned(),
                    ));
                }
            }
        }
        if let Some(v) = obj.get("preparedIntentDraftId") {
            match v {
                Value::Null => {}
                Value::Text(s) => validate_schema_token(s)?,
                _ => {
                    return Err(AgentQueryPlanCodecError::MalformedPayload(
                        "preparedIntentDraftId must be valid token string or null".to_owned(),
                    ));
                }
            }
        }
        let capability_projection = req_str_vec(obj, "capabilityProjection", 256)?;
        let privacy_projection = req_str_vec(obj, "privacyProjection", 128)?;
        let completeness_requested =
            QueryCompletenessRequested::parse(req_str(obj, "completenessRequested")?)
                .map_err(|e| AgentQueryPlanCodecError::Contract(ContractBasisError::Contract(e)))?;
        let budget = parse_budget_json(obj.get("budget").ok_or_else(|| {
            AgentQueryPlanCodecError::MalformedPayload("missing budget".to_owned())
        })?)?;
        let estimated_cost = parse_budget_json(obj.get("estimatedCost").ok_or_else(|| {
            AgentQueryPlanCodecError::MalformedPayload("missing estimatedCost".to_owned())
        })?)?;
        let interps_val = obj.get("interpretations").ok_or_else(|| {
            AgentQueryPlanCodecError::MalformedPayload("missing interpretations".to_owned())
        })?;
        let interps_arr = interps_val.array().ok_or_else(|| {
            AgentQueryPlanCodecError::MalformedPayload("interpretations must be array".to_owned())
        })?;
        if interps_arr.is_empty() || interps_arr.len() > 16 {
            return Err(AgentQueryPlanCodecError::Contract(
                ContractBasisError::Contract(ContractError::CountBoundExceeded),
            ));
        }
        let mut interpretations = Vec::with_capacity(interps_arr.len());
        for item in interps_arr {
            interpretations.push(parse_interpretation_json(item)?);
        }
        let selected_interpretation = req_str(obj, "selectedInterpretation")?.to_owned();
        let output_view_id = req_str(obj, "outputView")?;
        let created_at_ns = match obj.get("createdAtNs").ok_or_else(|| {
            AgentQueryPlanCodecError::MalformedPayload("missing createdAtNs".to_owned())
        })? {
            Value::Number(s) => s.parse::<i128>().map_err(|_| {
                AgentQueryPlanCodecError::MalformedPayload("createdAtNs must be integer".to_owned())
            })?,
            _ => {
                return Err(AgentQueryPlanCodecError::MalformedPayload(
                    "createdAtNs must be integer".to_owned(),
                ));
            }
        };

        Ok(Self::compile(
            query_plan_id,
            mission_id,
            session_id,
            basis,
            operation_id,
            original_text_digest,
            taint_sources,
            basis_anchor,
            objective,
            resolved_targets,
            domains,
            capability_projection,
            privacy_projection,
            completeness_requested,
            budget,
            interpretations,
            selected_interpretation,
            estimated_cost,
            output_view_id,
            created_at_ns,
        )?)
    }
}

impl CanonicalEncode for AgentQueryPlan {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        encoder.text(&self.query_plan_id);
        self.mission_id.encode_canonical(encoder);
        self.session_id.encode_canonical(encoder);
        encoder.text(self.operation.id());
        encoder.digest(self.original_text_digest);
        encoder.u32(self.taint_sources.len() as u32);
        for source in &self.taint_sources {
            encoder.text(source);
        }
        self.basis_anchor.encode_canonical(encoder);
        encoder.text(&self.objective);
        encoder.u32(self.resolved_targets.len() as u32);
        for target in &self.resolved_targets {
            encoder.text(target);
        }
        encoder.u32(self.domains.len() as u32);
        for domain in &self.domains {
            encoder.text(domain);
        }
        encoder.u32(self.capability_projection.len() as u32);
        for capability in &self.capability_projection {
            encoder.text(capability);
        }
        encoder.u32(self.privacy_projection.len() as u32);
        for projection in &self.privacy_projection {
            encoder.text(projection);
        }
        encoder.text(self.completeness_requested.as_str());
        self.budget.encode_canonical(encoder);
        encoder.u32(self.interpretations.len() as u32);
        for interpretation in &self.interpretations {
            encoder.text(&interpretation.interpretation_id);
            encoder.text(&interpretation.description);
            encoder.bool(interpretation.material);
            encoder.bool(interpretation.safe_read_default);
            match &interpretation.required_clarification {
                Some(clarification) => {
                    encoder.bool(true);
                    encoder.text(clarification);
                }
                None => encoder.bool(false),
            }
        }
        encoder.text(&self.selected_interpretation);
        self.estimated_cost.encode_canonical(encoder);
        encoder.text(self.output_view.id());
        encoder.i128(self.created_at_ns);
    }
}

impl CanonicalDecode for AgentQueryPlan {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let schema = decoder.text()?;
        if schema != Self::SCHEMA {
            return Err(ContractError::InvalidIdentifier);
        }
        let query_plan_id = decoder.text()?.to_owned();
        validate_id(&query_plan_id)?;
        if query_plan_id.len() > 256 {
            return Err(ContractError::InvalidIdentifier);
        }
        let mission_id = MissionId::decode_canonical(decoder)?;
        let session_id = SessionId::decode_canonical(decoder)?;
        let op_id = decoder.text()?;
        let operation = AgentOperation::from_id(op_id)?;
        if operation.effectful() || operation.request_payload_schema() != Self::SCHEMA {
            return Err(ContractError::InvalidEffectTransition);
        }
        let original_text_digest = decoder.digest()?;
        let taint_sources = decode_bounded_str_vec(decoder, 64)?;
        for s in &taint_sources {
            validate_id(s)?;
        }
        let basis_anchor = LedgerAnchor::decode_canonical(decoder)?;
        let objective = decoder.text()?.to_owned();
        if objective.is_empty() || objective.len() > 8192 || objective.chars().any(char::is_control)
        {
            return Err(ContractError::InvalidIdentifier);
        }
        let resolved_targets = decode_bounded_str_vec(decoder, 128)?;
        for t in &resolved_targets {
            validate_schema_token_contract(t)?;
        }
        let domains = decode_bounded_str_vec(decoder, 128)?;
        for d in &domains {
            if d.is_empty() || d.len() > 1024 || d.chars().any(char::is_control) {
                return Err(ContractError::InvalidIdentifier);
            }
        }
        let capability_projection = decode_bounded_str_vec(decoder, 256)?;
        for c in &capability_projection {
            validate_schema_token_contract(c)?;
        }
        let privacy_projection = decode_bounded_str_vec(decoder, 128)?;
        for p in &privacy_projection {
            validate_schema_token_contract(p)?;
        }
        let completeness_requested = QueryCompletenessRequested::parse(decoder.text()?)?;
        let budget = <BudgetVector as CanonicalDecode>::decode_canonical(decoder)?;
        if !budget.is_valid() {
            return Err(ContractError::EvidenceRequired);
        }
        let interp_count = decoder.u32()? as usize;
        if interp_count == 0
            || interp_count > 16
            || interp_count.saturating_mul(16) > decoder.remaining()
        {
            return Err(ContractError::CountBoundExceeded);
        }
        let mut interpretations = Vec::with_capacity(interp_count);
        let mut seen = BTreeSet::new();
        for _ in 0..interp_count {
            let iid = decoder.text()?.to_owned();
            let desc = decoder.text()?.to_owned();
            let material = decoder.bool()?;
            let safe_read_default = decoder.bool()?;
            let required_clarification = if decoder.bool()? {
                Some(decoder.text()?.to_owned())
            } else {
                None
            };
            let interp = QueryInterpretation::new(
                iid,
                desc,
                material,
                safe_read_default,
                required_clarification,
            )?;
            if !seen.insert(interp.interpretation_id.clone()) {
                return Err(ContractError::InvalidIdentifier);
            }
            interpretations.push(interp);
        }
        let selected_interpretation = decoder.text()?.to_owned();
        if !seen.contains(&selected_interpretation) {
            return Err(ContractError::NotFound);
        }
        let estimated_cost = <BudgetVector as CanonicalDecode>::decode_canonical(decoder)?;
        if !estimated_cost.is_valid() {
            return Err(ContractError::EvidenceRequired);
        }
        let output_view = AgentView::from_id(decoder.text()?)?;
        let created_at_ns = decoder.i128()?;
        if created_at_ns < 0 {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self {
            query_plan_id,
            mission_id,
            session_id,
            operation,
            original_text_digest,
            taint_sources,
            basis_anchor,
            objective,
            resolved_targets,
            domains,
            capability_projection,
            privacy_projection,
            completeness_requested,
            budget,
            interpretations,
            selected_interpretation,
            estimated_cost,
            output_view,
            created_at_ns,
        })
    }
}

fn validate_schema_token_contract(value: &str) -> Result<(), ContractError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 256 || !bytes[0].is_ascii_alphanumeric() {
        return Err(ContractError::InvalidIdentifier);
    }
    if !bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'.' | b'_' | b'+' | b'/' | b'-'))
    {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_schema_token(value: &str) -> Result<(), ContractBasisError> {
    validate_schema_token_contract(value).map_err(ContractBasisError::Contract)
}

fn decode_bounded_str_vec(
    decoder: &mut CanonicalDecoder<'_>,
    max_items: usize,
) -> Result<Vec<String>, ContractError> {
    let count = decoder.u32()? as usize;
    if count > max_items || count.saturating_mul(8) > decoder.remaining() {
        return Err(ContractError::CountBoundExceeded);
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(decoder.text()?.to_owned());
    }
    Ok(out)
}

fn push_escaped_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn push_key(out: &mut String, key: &str) {
    push_escaped_str(out, key);
    out.push(':');
}

fn push_kv_str(out: &mut String, key: &str, val: &str) {
    push_key(out, key);
    push_escaped_str(out, val);
}

fn write_str_array(out: &mut String, items: &[String]) {
    out.push('[');
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_escaped_str(out, item);
    }
    out.push(']');
}

fn write_f64(out: &mut String, v: f64) {
    let norm = if v == 0.0 { 0.0 } else { v };
    out.push_str(&norm.to_string());
}

fn write_budget_json(out: &mut String, b: BudgetVector) {
    out.push('{');
    push_key(out, "acceleratorMillis");
    out.push_str(&b.accelerator_millis.to_string());
    out.push(',');
    push_key(out, "bytes");
    out.push_str(&b.bytes.to_string());
    out.push(',');
    push_key(out, "cpuMillis");
    out.push_str(&b.cpu_millis.to_string());
    out.push(',');
    push_key(out, "energyMilliJoules");
    out.push_str(&b.energy_millijoules.to_string());
    out.push(',');
    push_key(out, "latencyMs");
    out.push_str(&b.latency_ms.to_string());
    out.push(',');
    push_key(out, "modelCalls");
    out.push_str(&b.model_calls.to_string());
    out.push(',');
    push_key(out, "networkBytes");
    out.push_str(&b.network_bytes.to_string());
    out.push(',');
    push_key(out, "operatorAttentionSeconds");
    write_f64(out, b.operator_attention_seconds());
    out.push(',');
    push_key(out, "privacyExposure");
    write_f64(out, b.privacy_exposure());
    out.push(',');
    push_key(out, "storageOperations");
    out.push_str(&b.storage_operations.to_string());
    out.push(',');
    push_key(out, "tokens");
    out.push_str(&b.tokens.to_string());
    out.push('}');
}

fn req_str<'a>(
    obj: &'a BTreeMap<String, Value>,
    key: &str,
) -> Result<&'a str, AgentQueryPlanCodecError> {
    obj.get(key)
        .ok_or_else(|| AgentQueryPlanCodecError::MalformedPayload(format!("missing {key}")))?
        .text()
        .ok_or_else(|| AgentQueryPlanCodecError::MalformedPayload(format!("{key} must be string")))
}

fn req_str_vec(
    obj: &BTreeMap<String, Value>,
    key: &str,
    max_items: usize,
) -> Result<Vec<String>, AgentQueryPlanCodecError> {
    let arr = obj
        .get(key)
        .ok_or_else(|| AgentQueryPlanCodecError::MalformedPayload(format!("missing {key}")))?
        .array()
        .ok_or_else(|| {
            AgentQueryPlanCodecError::MalformedPayload(format!("{key} must be array"))
        })?;
    if arr.len() > max_items {
        return Err(AgentQueryPlanCodecError::Contract(
            ContractBasisError::Contract(ContractError::CountBoundExceeded),
        ));
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item.text().ok_or_else(|| {
            AgentQueryPlanCodecError::MalformedPayload(format!("{key} items must be strings"))
        })?;
        out.push(s.to_owned());
    }
    Ok(out)
}

fn req_u64_num(obj: &BTreeMap<String, Value>, key: &str) -> Result<u64, AgentQueryPlanCodecError> {
    match obj
        .get(key)
        .ok_or_else(|| AgentQueryPlanCodecError::MalformedPayload(format!("missing {key}")))?
    {
        Value::Number(s) => s
            .parse::<u64>()
            .map_err(|_| AgentQueryPlanCodecError::MalformedPayload(format!("{key} must be u64"))),
        _ => Err(AgentQueryPlanCodecError::MalformedPayload(format!(
            "{key} must be integer"
        ))),
    }
}

fn req_f64_num(obj: &BTreeMap<String, Value>, key: &str) -> Result<f64, AgentQueryPlanCodecError> {
    match obj
        .get(key)
        .ok_or_else(|| AgentQueryPlanCodecError::MalformedPayload(format!("missing {key}")))?
    {
        Value::Number(s) => {
            let v = s.parse::<f64>().map_err(|_| {
                AgentQueryPlanCodecError::MalformedPayload(format!("{key} must be number"))
            })?;
            if !v.is_finite() || v < 0.0 {
                return Err(AgentQueryPlanCodecError::MalformedPayload(format!(
                    "{key} must be finite >= 0"
                )));
            }
            Ok(if v == 0.0 { 0.0 } else { v })
        }
        _ => Err(AgentQueryPlanCodecError::MalformedPayload(format!(
            "{key} must be number"
        ))),
    }
}

fn parse_budget_json(val: &Value) -> Result<BudgetVector, AgentQueryPlanCodecError> {
    const ALLOWED: &[&str] = &[
        "latencyMs",
        "tokens",
        "bytes",
        "modelCalls",
        "cpuMillis",
        "acceleratorMillis",
        "energyMilliJoules",
        "networkBytes",
        "storageOperations",
        "privacyExposure",
        "operatorAttentionSeconds",
    ];
    let obj = val.object().ok_or_else(|| {
        AgentQueryPlanCodecError::MalformedPayload("budget must be JSON object".to_owned())
    })?;
    for k in obj.keys() {
        if !ALLOWED.contains(&k.as_str()) {
            return Err(AgentQueryPlanCodecError::MalformedPayload(format!(
                "unknown budget property '{k}'"
            )));
        }
    }
    let model_calls = u32::try_from(req_u64_num(obj, "modelCalls")?).map_err(|_| {
        AgentQueryPlanCodecError::MalformedPayload("modelCalls exceeds u32".to_owned())
    })?;
    BudgetVector::builder()
        .latency_ms(req_u64_num(obj, "latencyMs")?)
        .tokens(req_u64_num(obj, "tokens")?)
        .bytes(req_u64_num(obj, "bytes")?)
        .model_calls(model_calls)
        .cpu_millis(req_u64_num(obj, "cpuMillis")?)
        .accelerator_millis(req_u64_num(obj, "acceleratorMillis")?)
        .energy_millijoules(req_u64_num(obj, "energyMilliJoules")?)
        .network_bytes(req_u64_num(obj, "networkBytes")?)
        .storage_operations(req_u64_num(obj, "storageOperations")?)
        .privacy_exposure(req_f64_num(obj, "privacyExposure")?)
        .operator_attention_seconds(req_f64_num(obj, "operatorAttentionSeconds")?)
        .build()
        .map_err(|e| AgentQueryPlanCodecError::Contract(ContractBasisError::Contract(e.into())))
}

fn parse_interpretation_json(val: &Value) -> Result<QueryInterpretation, AgentQueryPlanCodecError> {
    const ALLOWED: &[&str] = &[
        "interpretationId",
        "description",
        "material",
        "safeReadDefault",
        "requiredClarification",
    ];
    let obj = val.object().ok_or_else(|| {
        AgentQueryPlanCodecError::MalformedPayload("interpretation must be JSON object".to_owned())
    })?;
    for k in obj.keys() {
        if !ALLOWED.contains(&k.as_str()) {
            return Err(AgentQueryPlanCodecError::MalformedPayload(format!(
                "unknown interpretation property '{k}'"
            )));
        }
    }
    let iid = req_str(obj, "interpretationId")?;
    let desc = req_str(obj, "description")?;
    let material = obj
        .get("material")
        .and_then(Value::boolean)
        .ok_or_else(|| {
            AgentQueryPlanCodecError::MalformedPayload("material must be bool".to_owned())
        })?;
    let safe_read_default = obj
        .get("safeReadDefault")
        .and_then(Value::boolean)
        .ok_or_else(|| {
            AgentQueryPlanCodecError::MalformedPayload("safeReadDefault must be bool".to_owned())
        })?;
    let required_clarification = match obj.get("requiredClarification") {
        None | Some(Value::Null) => None,
        Some(Value::Text(s)) => Some(s.clone()),
        Some(_) => {
            return Err(AgentQueryPlanCodecError::MalformedPayload(
                "requiredClarification must be string or null".to_owned(),
            ));
        }
    };
    QueryInterpretation::new(
        iid,
        desc,
        material,
        safe_read_default,
        required_clarification,
    )
    .map_err(|e| AgentQueryPlanCodecError::Contract(ContractBasisError::Contract(e)))
}

fn parse_basis_anchor(val: &Value) -> Result<LedgerAnchor, AgentQueryPlanCodecError> {
    let rec = EvidenceAnchorRecordV1::from_json_value(val)
        .map_err(|e| AgentQueryPlanCodecError::MalformedPayload(e.to_string()))?;
    let state_root = ContentDigest::parse(&rec.authority_root)
        .map_err(|e| AgentQueryPlanCodecError::Contract(ContractBasisError::Contract(e)))?;
    Ok(LedgerAnchor {
        site_lineage: rec.deployment_id,
        ledger_epoch: rec.observation_epoch,
        commit_sequence: rec.capsule_sequence,
        adapter_registry_epoch: rec.adapter_epoch,
        schema_epoch: rec.schema_epoch,
        policy_epoch: rec.policy_epoch,
        privacy_epoch: rec.privacy_epoch.unwrap_or(0),
        state_root,
    })
}
