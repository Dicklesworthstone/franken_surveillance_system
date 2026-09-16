#![forbid(unsafe_code)]
//! The durable investigation record (fss.investigation_state.v1).
//!
//! Normative source: `schemas/investigation_state.v1.json`. This is the
//! schema-faithful case record served by `investigate` (AOP-006): a competing
//! hypothesis set (at least two, by construction), knowns with explicit
//! epistemic states, unknowns that are carried rather than dropped,
//! discriminators that separate hypotheses with expected outcomes, probe
//! handles, stop rules, and a decision deadline. Orthogonality is preserved:
//! every statement carries its own [`KnowledgeState`].

use std::collections::BTreeSet;

use crate::agent::ContractBasis;
use crate::canonical::{CanonicalEncode, CanonicalEncoder};
use crate::contract::{ContractError, KnowledgeState};
use crate::digest::ContentDigest;
use crate::evidence::LedgerAnchor;
use crate::ids::validate_id;
use crate::MissionId;

/// Lifecycle state of an investigation (registered enum).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvestigationLifecycle {
    /// Drafted, not yet active.
    Draft,
    /// Actively discriminating between hypotheses.
    Active,
    /// Waiting on probe evidence.
    AwaitingEvidence,
    /// Waiting on an operator approval.
    AwaitingApproval,
    /// Blocked by authority, coverage, or budget.
    Blocked,
    /// Reached a terminal answer.
    Resolved,
    /// The question was refuted as posed.
    Refuted,
    /// Cancelled by its owner.
    Cancelled,
    /// Outcome cannot yet be established.
    Indeterminate,
    /// Closed and archived.
    Closed,
}

impl InvestigationLifecycle {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::AwaitingEvidence => "awaiting_evidence",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Blocked => "blocked",
            Self::Resolved => "resolved",
            Self::Refuted => "refuted",
            Self::Cancelled => "cancelled",
            Self::Indeterminate => "indeterminate",
            Self::Closed => "closed",
        }
    }
}

/// One competing hypothesis with its own predictions and evidence.
#[derive(Clone, Debug, PartialEq)]
pub struct CaseHypothesis {
    /// Stable hypothesis identity.
    pub hypothesis_id: String,
    /// What the hypothesis claims.
    pub description: String,
    /// Epistemic state of the hypothesis (orthogonal typed coordinate).
    pub epistemic_state: KnowledgeState,
    /// What the hypothesis predicts.
    pub predictions: Vec<String>,
    /// Supporting evidence digests.
    pub evidence: Vec<ContentDigest>,
    /// Contradicting evidence digests.
    pub contradictions: Vec<ContentDigest>,
}

/// One known statement with explicit epistemic state and basis.
#[derive(Clone, Debug, PartialEq)]
pub struct KnownStatement {
    /// Stable statement identity.
    pub statement_id: String,
    /// The statement text.
    pub text: String,
    /// Epistemic state (never flattened into confidence).
    pub epistemic_state: KnowledgeState,
    /// Basis handles backing the statement.
    pub basis: Vec<String>,
}

/// One discriminator separating at least two hypotheses.
#[derive(Clone, Debug, PartialEq)]
pub struct CaseDiscriminator {
    /// Stable discriminator identity.
    pub discriminator_id: String,
    /// What observation the discriminator would produce.
    pub description: String,
    /// Hypothesis identities it separates (at least two).
    pub separates: Vec<String>,
    /// Expected outcomes per separated hypothesis.
    pub expected_outcomes: Vec<String>,
}

/// The durable investigation record (AOP-006 `investigate` payload).
#[derive(Clone, Debug, PartialEq)]
pub struct InvestigationState {
    /// Stable investigation identity.
    pub investigation_id: String,
    /// Exact semantic contract universe.
    pub contract_basis: ContractBasis,
    /// Mission the investigation serves.
    pub mission_id: MissionId,
    /// Monotone revision.
    pub revision: u64,
    /// Lifecycle state.
    pub state: InvestigationLifecycle,
    /// The investigation question.
    pub question: String,
    /// Which decision this investigation informs.
    pub decision_informed: String,
    /// Basis authority anchor.
    pub basis_anchor: LedgerAnchor,
    /// Competing hypotheses (at least two by construction).
    pub hypotheses: Vec<CaseHypothesis>,
    /// Known statements.
    pub knowns: Vec<KnownStatement>,
    /// Unknowns carried explicitly.
    pub unknowns: Vec<KnownStatement>,
    /// Discriminators separating hypotheses.
    pub discriminators: Vec<CaseDiscriminator>,
    /// Probe handles.
    pub probes: Vec<String>,
    /// Stop rules (at least one by construction).
    pub stop_rules: Vec<String>,
    /// Absolute decision deadline.
    pub decision_deadline_ns: i128,
}

/// Canonical digest domain of one investigation record.
pub const INVESTIGATION_STATE_DIGEST_DOMAIN: &str = "fss.investigation_state.v1";

fn validate_portable(value: &str, max_len: usize) -> Result<(), ContractError> {
    validate_id(value)?;
    if value.len() > max_len {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(())
}

fn check_portable(value: &str, max_len: usize) -> Result<(), ContractError> {
    validate_id(value)?;
    if value.len() > max_len {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(())
}

/// Validated parameters for an investigation record.
#[derive(Clone, Debug)]
pub struct InvestigationStateParams {
    /// Stable investigation identity.
    pub investigation_id: String,
    /// Exact semantic contract universe.
    pub contract_basis: ContractBasis,
    /// Mission the investigation serves.
    pub mission_id: MissionId,
    /// Monotone revision.
    pub revision: u64,
    /// Lifecycle state.
    pub state: InvestigationLifecycle,
    /// The investigation question.
    pub question: String,
    /// Which decision this investigation informs.
    pub decision_informed: String,
    /// Basis authority anchor.
    pub basis_anchor: LedgerAnchor,
    /// Competing hypotheses (at least two).
    pub hypotheses: Vec<CaseHypothesis>,
    /// Known statements.
    pub knowns: Vec<KnownStatement>,
    /// Unknowns carried explicitly.
    pub unknowns: Vec<KnownStatement>,
    /// Discriminators separating hypotheses.
    pub discriminators: Vec<CaseDiscriminator>,
    /// Probe handles.
    pub probes: Vec<String>,
    /// Stop rules (at least one).
    pub stop_rules: Vec<String>,
    /// Absolute decision deadline.
    pub decision_deadline_ns: i128,
}

impl InvestigationState {
    /// Schema identity implemented by this type.
    pub const SCHEMA: &str = "fss.investigation_state.v1";

    /// Validates and constructs an investigation record.
    ///
    /// Competition is structural: fewer than two hypotheses is refused.
    /// Every discriminator must separate at least two hypotheses that exist,
    /// and stop rules are mandatory (at least one).
    pub fn new(params: InvestigationStateParams) -> Result<Self, ContractError> {
        let InvestigationStateParams {
            investigation_id,
            contract_basis,
            mission_id,
            revision,
            state,
            question,
            decision_informed,
            basis_anchor,
            hypotheses,
            knowns,
            unknowns,
            discriminators,
            probes,
            stop_rules,
            decision_deadline_ns,
        } = params;
        validate_portable(&investigation_id, 256)?;
        if question.is_empty() || question.len() > 8192 {
            return Err(ContractError::InvalidIdentifier);
        }
        if decision_informed.is_empty() || decision_informed.len() > 1024 {
            return Err(ContractError::InvalidIdentifier);
        }
        if hypotheses.len() < 2 || hypotheses.len() > 64 {
            return Err(ContractError::EvidenceRequired);
        }
        let ids: BTreeSet<&str> =
            hypotheses.iter().map(|h| h.hypothesis_id.as_str()).collect();
        if ids.len() != hypotheses.len() {
            return Err(ContractError::InvalidIdentifier);
        }
        for hypothesis in &hypotheses {
            check_portable(&hypothesis.hypothesis_id, 256)?;
            if hypothesis.description.is_empty() || hypothesis.description.len() > 8192 {
                return Err(ContractError::InvalidIdentifier);
            }
        }
        if knowns.len() > 256 || unknowns.len() > 256 {
            return Err(ContractError::CountBoundExceeded);
        }
        for statement in knowns.iter().chain(&unknowns) {
            check_portable(&statement.statement_id, 256)?;
            if statement.text.is_empty() || statement.text.len() > 8192 {
                return Err(ContractError::InvalidIdentifier);
            }
            if statement.basis.len() > 256 {
                return Err(ContractError::CountBoundExceeded);
            }
            for basis in &statement.basis {
                check_portable(basis, 256)?;
            }
        }
        if discriminators.len() > 128 {
            return Err(ContractError::CountBoundExceeded);
        }
        for discriminator in &discriminators {
            check_portable(&discriminator.discriminator_id, 256)?;
            if discriminator.description.is_empty()
                || discriminator.description.len() > 8192
            {
                return Err(ContractError::InvalidIdentifier);
            }
            if discriminator.separates.len() < 2 || discriminator.separates.len() > 64 {
                return Err(ContractError::EvidenceRequired);
            }
            for separated in &discriminator.separates {
                if !ids.contains(separated.as_str()) {
                    return Err(ContractError::NotFound);
                }
            }
            if discriminator.expected_outcomes.len() < 2
                || discriminator.expected_outcomes.len() > 64
            {
                return Err(ContractError::EvidenceRequired);
            }
            for outcome in &discriminator.expected_outcomes {
                if outcome.is_empty() || outcome.len() > 1024 {
                    return Err(ContractError::InvalidIdentifier);
                }
            }
        }
        if probes.len() > 128 {
            return Err(ContractError::CountBoundExceeded);
        }
        for probe in &probes {
            check_portable(probe, 256)?;
        }
        if stop_rules.is_empty() || stop_rules.len() > 64 {
            return Err(ContractError::EvidenceRequired);
        }
        for rule in &stop_rules {
            if rule.is_empty() || rule.len() > 1024 {
                return Err(ContractError::InvalidIdentifier);
            }
        }
        Ok(Self {
            investigation_id,
            contract_basis,
            mission_id,
            revision,
            state,
            question,
            decision_informed,
            basis_anchor,
            hypotheses,
            knowns,
            unknowns,
            discriminators,
            probes,
            stop_rules,
            decision_deadline_ns,
        })
    }

    /// Returns the domain-separated canonical digest under the schema identity.
    #[must_use]
    pub fn investigation_digest(&self) -> ContentDigest {
        self.canonical_digest(Self::SCHEMA)
    }
}

impl CanonicalEncode for InvestigationState {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::SCHEMA);
        encoder.text(&self.investigation_id);
        self.contract_basis.encode_canonical(encoder);
        self.mission_id.encode_canonical(encoder);
        encoder.u64(self.revision);
        encoder.text(self.state.as_str());
        encoder.text(&self.question);
        encoder.text(&self.decision_informed);
        self.basis_anchor.encode_canonical(encoder);
        encoder.u32(self.hypotheses.len() as u32);
        for hypothesis in &self.hypotheses {
            encoder.text(&hypothesis.hypothesis_id);
            encoder.text(&hypothesis.description);
            hypothesis.epistemic_state.encode_canonical(encoder);
            encoder.u32(hypothesis.predictions.len() as u32);
            for prediction in &hypothesis.predictions {
                encoder.text(prediction);
            }
            encoder.u32(hypothesis.evidence.len() as u32);
            for evidence in &hypothesis.evidence {
                encoder.digest(*evidence);
            }
            encoder.u32(hypothesis.contradictions.len() as u32);
            for contradiction in &hypothesis.contradictions {
                encoder.digest(*contradiction);
            }
        }
        for group in [&self.knowns, &self.unknowns] {
            encoder.u32(group.len() as u32);
            for statement in group {
                encoder.text(&statement.statement_id);
                encoder.text(&statement.text);
                statement.epistemic_state.encode_canonical(encoder);
                encoder.u32(statement.basis.len() as u32);
                for basis in &statement.basis {
                    encoder.text(basis);
                }
            }
        }
        encoder.u32(self.discriminators.len() as u32);
        for discriminator in &self.discriminators {
            encoder.text(&discriminator.discriminator_id);
            encoder.text(&discriminator.description);
            encoder.u32(discriminator.separates.len() as u32);
            for separated in &discriminator.separates {
                encoder.text(separated);
            }
            encoder.u32(discriminator.expected_outcomes.len() as u32);
            for outcome in &discriminator.expected_outcomes {
                encoder.text(outcome);
            }
        }
        encoder.u32(self.probes.len() as u32);
        for probe in &self.probes {
            encoder.text(probe);
        }
        encoder.u32(self.stop_rules.len() as u32);
        for rule in &self.stop_rules {
            encoder.text(rule);
        }
        encoder.i128(self.decision_deadline_ns);
    }
}
