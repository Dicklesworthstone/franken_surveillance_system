#![forbid(unsafe_code)]
//! The agent cognitive envelope (fss.agent_cognitive_envelope.v1) and the
//! agent response envelope (fss.agent_response_envelope.v1).
//!
//! Both mirror their registered schema documents with validated
//! constructors, canonical encoding, and schema-identity digests. The
//! response envelope is the single decision-bearing reply contract of
//! `fss/1`: it preserves epistemic state, completeness, warnings,
//! contradictions, degradation, budgets, proof pointers, affordances,
//! recovery class, safe-retry guidance, and the execution boundary summary
//! — none of which may be silently omitted.

use crate::agent::ContractBasis;
use crate::agent_operation::AgentOperation;
use crate::agent_view::AgentView;
use crate::canonical::{CanonicalEncode, CanonicalEncoder};
use crate::contract::{ContractError, KnowledgeState};
use crate::contract_basis::ContractBasisError;
use crate::digest::ContentDigest;
use crate::evidence::LedgerAnchor;
use crate::contract_basis::registered_operation;

fn check_str(value: &str, max_len: usize) -> Result<(), ContractError> {
    if value.is_empty() || value.len() > max_len {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(())
}

fn bounded(list: &[String], max_items: usize, max_len: usize) -> Result<(), ContractError> {
    if list.len() > max_items {
        return Err(ContractError::CountBoundExceeded);
    }
    for entry in list {
        check_str(entry, max_len)?;
    }
    Ok(())
}

fn check_decision_digest(value: &str) -> Result<(), ContractError> {
    let bytes = value.as_bytes();
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if bytes.len() < 8
        || bytes.len() > 256
        || !alnum(bytes[0])
        || !bytes[1..]
            .iter()
            .all(|&b| alnum(b) || matches!(b, b':' | b'+' | b'.' | b'_' | b'-'))
    {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// AgentCognitiveEnvelope (fss.agent_cognitive_envelope.v1)
// ---------------------------------------------------------------------------

/// Registered answer classes of a cognitive envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CognitiveAnswerClass {
    /// Direct fact.
    DirectFact,
    /// Bounded summary.
    BoundedSummary,
    /// Hypothesis set.
    HypothesisSet,
    /// Recommendation.
    Recommendation,
    /// Plan.
    Plan,
    /// Effect status.
    EffectStatus,
    /// Obligation status.
    ObligationStatus,
    /// Learning proposal.
    LearningProposal,
    /// Refusal.
    Refusal,
    /// Indeterminate.
    Indeterminate,
}

impl CognitiveAnswerClass {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectFact => "direct_fact",
            Self::BoundedSummary => "bounded_summary",
            Self::HypothesisSet => "hypothesis_set",
            Self::Recommendation => "recommendation",
            Self::Plan => "plan",
            Self::EffectStatus => "effect_status",
            Self::ObligationStatus => "obligation_status",
            Self::LearningProposal => "learning_proposal",
            Self::Refusal => "refusal",
            Self::Indeterminate => "indeterminate",
        }
    }
}

/// One proposition in the envelope's epistemic block.
#[derive(Clone, Debug, PartialEq)]
pub struct EnvelopeProposition {
    /// Proposition identity.
    pub id: String,
    /// Statement text.
    pub statement: String,
    /// Explicit knowledge state.
    pub state: KnowledgeState,
    /// Provenance class spelling.
    pub provenance: String,
    /// Evidence handles.
    pub evidence: Vec<String>,
}

/// Epistemic block of a cognitive envelope.
#[derive(Clone, Debug, PartialEq)]
pub struct EnvelopeEpistemic {
    /// Propositions.
    pub propositions: Vec<EnvelopeProposition>,
    /// Assumptions.
    pub assumptions: Vec<String>,
    /// Invalidators.
    pub invalidators: Vec<String>,
}

/// Coverage block of a cognitive envelope.
#[derive(Clone, Debug, PartialEq)]
pub struct EnvelopeCoverage {
    /// Authorized domain handles.
    pub authorized_domain: Vec<String>,
    /// Observed domain handles.
    pub observed_domain: Vec<String>,
    /// Domains that were not observable.
    pub not_observable_domain: Vec<String>,
    /// How many entries were omitted.
    pub omitted_count: u64,
    /// Why entries were omitted.
    pub omission_reasons: Vec<String>,
    /// Why observation stopped.
    pub stop_reason: String,
}

/// Budget block of a cognitive envelope.
#[derive(Clone, Debug, PartialEq)]
pub struct EnvelopeBudget {
    /// Requested budget (pinned canonical JSON).
    pub requested_json: String,
    /// Consumed budget (pinned canonical JSON).
    pub consumed_json: String,
    /// Remaining budget (pinned canonical JSON).
    pub remaining_json: String,
    /// Degraded dimensions.
    pub degraded_dimensions: Vec<String>,
    /// Marginal work declined.
    pub marginal_work_declined: Vec<String>,
}

/// Continuity block of a cognitive envelope.
#[derive(Clone, Debug, PartialEq)]
pub struct EnvelopeContinuity {
    /// Continuation cursor, when the answer continues.
    pub cursor: Option<String>,
    /// Triggers that require re-anchoring.
    pub reanchor_triggers: Vec<String>,
    /// Session capsule digest, when continuity is workspace-bound.
    pub session_capsule_digest: Option<String>,
    /// Unresolved obligations.
    pub unresolved_obligations: Vec<String>,
}

/// The agent cognitive envelope (decision-bearing read answer).
#[derive(Clone, Debug, PartialEq)]
pub struct AgentCognitiveEnvelope {
    /// Exact contract basis.
    pub contract_basis: ContractBasis,
    /// Request this envelope answers.
    pub request_id: String,
    /// Response identity.
    pub response_id: String,
    /// Trace identity.
    pub trace_id: String,
    /// Serving registered operation.
    pub operation: AgentOperation,
    /// Semantic verb of the answer.
    pub semantic_verb: String,
    /// Registered view the answer is rendered in.
    pub view: AgentView,
    /// Answer class.
    pub answer_class: CognitiveAnswerClass,
    /// Basis anchor.
    pub basis_anchor: LedgerAnchor,
    /// Epistemic block.
    pub epistemic: EnvelopeEpistemic,
    /// Coverage block.
    pub coverage: EnvelopeCoverage,
    /// Budget block.
    pub budget: EnvelopeBudget,
    /// Evidence handles.
    pub evidence_handles: Vec<String>,
    /// Next actions.
    pub next_actions: Vec<String>,
    /// Continuity block.
    pub continuity: EnvelopeContinuity,
    /// Decision digest.
    pub decision_digest: String,
}

impl AgentCognitiveEnvelope {
    /// Schema identity implemented by this type.
    pub const SCHEMA: &str = "fss.agent_cognitive_envelope.v1";

    /// Validates and constructs a cognitive envelope.
    #[allow(clippy::too_many_arguments)] // constructor mirrors the registered schema field list 1:1
    pub fn new(
        contract_basis: ContractBasis,
        request_id: impl Into<String>,
        response_id: impl Into<String>,
        trace_id: impl Into<String>,
        operation_id: &str,
        semantic_verb: impl Into<String>,
        view_id: &str,
        answer_class: CognitiveAnswerClass,
        basis_anchor: LedgerAnchor,
        epistemic: EnvelopeEpistemic,
        coverage: EnvelopeCoverage,
        budget: EnvelopeBudget,
        evidence_handles: Vec<String>,
        next_actions: Vec<String>,
        continuity: EnvelopeContinuity,
        decision_digest: impl Into<String>,
    ) -> Result<Self, ContractBasisError> {
        let operation = AgentOperation::from_id(operation_id)
            .or_else(|_| AgentOperation::from_name(operation_id))
            .map_err(ContractBasisError::Contract)?;
        registered_operation(&contract_basis, operation.name())?;
        let view = AgentView::from_id(view_id)
            .map_err(|_| ContractBasisError::Contract(ContractError::InvalidIdentifier))?;
        let request_id = request_id.into();
        check_str(&request_id, 256).map_err(ContractBasisError::Contract)?;
        let response_id = response_id.into();
        check_str(&response_id, 256).map_err(ContractBasisError::Contract)?;
        let trace_id = trace_id.into();
        check_str(&trace_id, 256).map_err(ContractBasisError::Contract)?;
        let semantic_verb = semantic_verb.into();
        check_str(&semantic_verb, 64).map_err(ContractBasisError::Contract)?;
        if epistemic.propositions.len() > 4096
            || epistemic.assumptions.len() > 4096
            || epistemic.invalidators.len() > 4096
            || coverage.authorized_domain.len() > 4096
            || coverage.observed_domain.len() > 4096
            || coverage.not_observable_domain.len() > 4096
            || coverage.omission_reasons.len() > 64
            || budget.degraded_dimensions.len() > 4096
            || budget.marginal_work_declined.len() > 4096
            || evidence_handles.len() > 4096
            || next_actions.len() > 64
            || continuity.reanchor_triggers.len() > 4096
            || continuity.unresolved_obligations.len() > 4096
        {
            return Err(ContractBasisError::Contract(
                ContractError::CountBoundExceeded,
            ));
        }
        for proposition in &epistemic.propositions {
            check_str(&proposition.id, 256).map_err(ContractBasisError::Contract)?;
            check_str(&proposition.statement, 16_384).map_err(ContractBasisError::Contract)?;
            check_str(&proposition.provenance, 64).map_err(ContractBasisError::Contract)?;
            bounded(&proposition.evidence, 256, 4096).map_err(ContractBasisError::Contract)?;
        }
        check_str(&coverage.stop_reason, 1024).map_err(ContractBasisError::Contract)?;
        for json in [
            &budget.requested_json,
            &budget.consumed_json,
            &budget.remaining_json,
        ] {
            check_str(json, 65_536).map_err(ContractBasisError::Contract)?;
        }
        if let Some(cursor) = &continuity.cursor {
            check_str(cursor, 4096).map_err(ContractBasisError::Contract)?;
        }
        let decision_digest = decision_digest.into();
        check_decision_digest(&decision_digest).map_err(ContractBasisError::Contract)?;
        Ok(Self {
            contract_basis,
            request_id,
            response_id,
            trace_id,
            operation,
            semantic_verb,
            view,
            answer_class,
            basis_anchor,
            epistemic,
            coverage,
            budget,
            evidence_handles,
            next_actions,
            continuity,
            decision_digest,
        })
    }

    /// Returns the domain-separated canonical digest under the schema identity.
    #[must_use]
    pub fn envelope_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
    }
}

impl CanonicalEncode for AgentCognitiveEnvelope {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        self.contract_basis.encode_canonical(encoder);
        encoder.text(&self.request_id);
        encoder.text(&self.response_id);
        encoder.text(&self.trace_id);
        encoder.text(self.operation.id());
        encoder.text(&self.semantic_verb);
        encoder.text(self.view.id());
        encoder.text(self.answer_class.as_str());
        self.basis_anchor.encode_canonical(encoder);
        encoder.u32(self.epistemic.propositions.len() as u32);
        for proposition in &self.epistemic.propositions {
            encoder.text(&proposition.id);
            encoder.text(&proposition.statement);
            proposition.state.encode_canonical(encoder);
            encoder.text(&proposition.provenance);
            encoder.u32(proposition.evidence.len() as u32);
            for handle in &proposition.evidence {
                encoder.text(handle);
            }
        }
        encoder.u32(self.epistemic.assumptions.len() as u32);
        for assumption in &self.epistemic.assumptions {
            encoder.text(assumption);
        }
        encoder.u32(self.epistemic.invalidators.len() as u32);
        for invalidator in &self.epistemic.invalidators {
            encoder.text(invalidator);
        }
        for group in [
            &self.coverage.authorized_domain,
            &self.coverage.observed_domain,
            &self.coverage.not_observable_domain,
        ] {
            encoder.u32(group.len() as u32);
            for entry in group {
                encoder.text(entry);
            }
        }
        encoder.u64(self.coverage.omitted_count);
        encoder.u32(self.coverage.omission_reasons.len() as u32);
        for reason in &self.coverage.omission_reasons {
            encoder.text(reason);
        }
        encoder.text(&self.coverage.stop_reason);
        encoder.text(&self.budget.requested_json);
        encoder.text(&self.budget.consumed_json);
        encoder.text(&self.budget.remaining_json);
        encoder.u32(self.budget.degraded_dimensions.len() as u32);
        for dimension in &self.budget.degraded_dimensions {
            encoder.text(dimension);
        }
        encoder.u32(self.budget.marginal_work_declined.len() as u32);
        for declined in &self.budget.marginal_work_declined {
            encoder.text(declined);
        }
        encoder.u32(self.evidence_handles.len() as u32);
        for handle in &self.evidence_handles {
            encoder.text(handle);
        }
        encoder.u32(self.next_actions.len() as u32);
        for action in &self.next_actions {
            encoder.text(action);
        }
        match &self.continuity.cursor {
            Some(cursor) => {
                encoder.bool(true);
                encoder.text(cursor);
            }
            None => encoder.bool(false),
        }
        encoder.u32(self.continuity.reanchor_triggers.len() as u32);
        for trigger in &self.continuity.reanchor_triggers {
            encoder.text(trigger);
        }
        match &self.continuity.session_capsule_digest {
            Some(digest) => {
                encoder.bool(true);
                encoder.text(digest);
            }
            None => encoder.bool(false),
        }
        encoder.u32(self.continuity.unresolved_obligations.len() as u32);
        for obligation in &self.continuity.unresolved_obligations {
            encoder.text(obligation);
        }
        encoder.text(&self.decision_digest);
    }
}
