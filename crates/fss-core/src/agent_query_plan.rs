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

use crate::agent_operation::AgentOperation;
use crate::contract_basis::registered_operation;
use crate::agent_view::AgentView;
use crate::canonical::{CanonicalEncode, CanonicalEncoder};
use crate::contract::ContractError;
use crate::contract_basis::ContractBasisError;
use crate::digest::ContentDigest;
use crate::evidence::LedgerAnchor;
use crate::ids::validate_id;
use crate::{BudgetVector, MissionId, SessionId, TimestampNs};

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
        validate_id(&query_plan_id).map_err(|_| {
            ContractBasisError::Contract(ContractError::InvalidIdentifier)
        })?;
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
            validate_id(source).map_err(|_| {
                ContractBasisError::Contract(ContractError::InvalidIdentifier)
            })?;
            if source.len() > 256 {
                return Err(ContractBasisError::Contract(
                    ContractError::InvalidIdentifier,
                ));
            }
        }
        let objective = objective.into();
        if objective.is_empty() || objective.len() > 8192 {
            return Err(ContractBasisError::Contract(
                ContractError::InvalidIdentifier,
            ));
        }
        if interpretations.is_empty() || interpretations.len() > 16 {
            return Err(ContractBasisError::Contract(
                ContractError::CountBoundExceeded,
            ));
        }
        let selected_interpretation = selected_interpretation.into();
        if !interpretations
            .iter()
            .any(|interpretation| interpretation.interpretation_id == selected_interpretation)
        {
            return Err(ContractBasisError::Contract(
                ContractError::NotFound,
            ));
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
        let operation = AgentOperation::from_id(operation_id).map_err(|_| {
            ContractBasisError::Contract(ContractError::InvalidIdentifier)
        })?;
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

    /// Returns the domain-separated canonical digest under the schema identity.
    #[must_use]
    pub fn plan_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
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
