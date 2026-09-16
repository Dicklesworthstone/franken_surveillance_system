#![forbid(unsafe_code)]
//! Registered `fss/1` agent views (AVIEW-001..AVIEW-008).
//!
//! Normative sources (truth hierarchy, highest tier first):
//! - `architecture/agent_views.json` (`fss.agent_views.v1`): the dedicated
//!   machine registry owning the view surface.
//! - `registries/AGENT_VIEWS.md` and `registries/AGENT_CONTRACTS.md`: human
//!   mirrors; `AVIEW-###` remains one stable identity across both.
//!
//! Every listed registry field is queryable as a typed accessor. The canonical
//! encoding covers every field except the prose `purpose` and the registry
//! `status` metadata (both pinned by the registry mirrors and the
//! `agent_operation_registry_checker`, never decision-bearing on their own).
//! The canonical text row format is:
//!
//! ```text
//! id|name|owner|targetTokens|maximumTokens|gate|requiredSections[;...]
//! ```
//!
//! Sections join on `;`. Any tampered field fails closed: canonical decode
//! reconstructs the row and must match a registered row exactly. Token bounds
//! are decision-bearing budget discipline: `target <= maximum` and both
//! nonzero are enforced at construction and use boundaries.

use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::ContractError;
use crate::digest::ContentDigest;
use crate::AgentOperation;
use core::fmt;

/// Registry schema identity of the dedicated view registry.
pub const SCHEMA_AGENT_VIEWS: &str = "fss.agent_views.v1";

/// Qualification gate shared by every registered view row.
pub const REGISTERED_VIEW_GATE: &str = "QL-AGENT-001";

/// Number of registered views (`AVIEW-001`..`AVIEW-008`).
pub const REGISTERED_VIEW_COUNT: usize = 8;

/// Canonical digest domain of one registered view row.
pub const VIEW_ROW_DIGEST_DOMAIN: &str = "fss.agent.view.row.v1";

/// A registered `fss/1` agent view (`AVIEW-001`..`AVIEW-008`).
///
/// Variant order is the registry row order and the canonical ordering.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AgentView {
    /// `AVIEW-001` `pulse`: tiny high-severity meaningful delta, sensor
    /// health, coverage loss, effect uncertainty, obligation heartbeat.
    Pulse,
    /// `AVIEW-002` `brief`: primary mission SituationCapsule.
    Brief,
    /// `AVIEW-003` `case`: investigation question, hypotheses, evidence,
    /// contradictions, unknowns, discriminators, stop rule.
    Case,
    /// `AVIEW-004` `forensic`: broad exact evidence graph, source spans,
    /// receipts, derivations, replay handles.
    Forensic,
    /// `AVIEW-005` `operation`: one durable plan/effect/task with progress,
    /// expected terminal proof, obligations, reconciliation.
    Operation,
    /// `AVIEW-006` `handoff`: minimum sufficient resume state.
    Handoff,
    /// `AVIEW-007` `decision_diff`: why a conclusion or preferred affordance
    /// changed, and what would reverse it.
    DecisionDiff,
    /// `AVIEW-008` `epistemic_map`: knowledge-state map with certified core,
    /// absences, alternatives, residuals, coverage, gaps, redactions.
    EpistemicMap,
}

/// Required-section slice type for view accessors.
pub type ViewSectionList = &'static [&'static str];

impl AgentView {
    /// Every registered view in canonical registry order.
    pub const ALL_VIEWS: [AgentView; REGISTERED_VIEW_COUNT] = [
        Self::Pulse,
        Self::Brief,
        Self::Case,
        Self::Forensic,
        Self::Operation,
        Self::Handoff,
        Self::DecisionDiff,
        Self::EpistemicMap,
    ];

    /// Returns the stable registry row ID (`AVIEW-001`..`AVIEW-008`).
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Pulse => "AVIEW-001",
            Self::Brief => "AVIEW-002",
            Self::Case => "AVIEW-003",
            Self::Forensic => "AVIEW-004",
            Self::Operation => "AVIEW-005",
            Self::Handoff => "AVIEW-006",
            Self::DecisionDiff => "AVIEW-007",
            Self::EpistemicMap => "AVIEW-008",
        }
    }

    /// Returns the stable canonical view name (`pulse`, ...).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pulse => "pulse",
            Self::Brief => "brief",
            Self::Case => "case",
            Self::Forensic => "forensic",
            Self::Operation => "operation",
            Self::Handoff => "handoff",
            Self::DecisionDiff => "decision_diff",
            Self::EpistemicMap => "epistemic_map",
        }
    }

    /// Parses a view from its stable row ID (`AVIEW-001`..`AVIEW-008`).
    pub fn from_id(id: &str) -> Result<Self, ContractError> {
        match id {
            "AVIEW-001" => Ok(Self::Pulse),
            "AVIEW-002" => Ok(Self::Brief),
            "AVIEW-003" => Ok(Self::Case),
            "AVIEW-004" => Ok(Self::Forensic),
            "AVIEW-005" => Ok(Self::Operation),
            "AVIEW-006" => Ok(Self::Handoff),
            "AVIEW-007" => Ok(Self::DecisionDiff),
            "AVIEW-008" => Ok(Self::EpistemicMap),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }

    /// Parses a view from its stable canonical name (`pulse`, ...).
    pub fn from_name(name: &str) -> Result<Self, ContractError> {
        match name {
            "pulse" => Ok(Self::Pulse),
            "brief" => Ok(Self::Brief),
            "case" => Ok(Self::Case),
            "forensic" => Ok(Self::Forensic),
            "operation" => Ok(Self::Operation),
            "handoff" => Ok(Self::Handoff),
            "decision_diff" => Ok(Self::DecisionDiff),
            "epistemic_map" => Ok(Self::EpistemicMap),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }

    /// Returns the owning subsystem crate from the registry row.
    #[must_use]
    pub const fn owner(self) -> &'static str {
        match self {
            Self::Pulse | Self::Forensic => "fss-context-pack",
            Self::Brief => "fss-situation",
            Self::Case => "fss-investigation",
            Self::Operation => "fss-obligation",
            Self::Handoff => "fss-handoff",
            Self::DecisionDiff => "fss-explain",
            Self::EpistemicMap => "fss-knowledge",
        }
    }

    /// Returns the registry prose purpose of this view.
    #[must_use]
    pub const fn purpose(self) -> &'static str {
        match self {
            Self::Pulse => {
                "tiny high-severity meaningful delta, sensor-health, coverage-loss, effect-uncertainty, and obligation heartbeat"
            }
            Self::Brief => {
                "primary mission SituationCapsule answering what is established, what materially different worlds remain possible, what changed, why it matters, and what is robustly or conditionally safe to do next"
            }
            Self::Case => {
                "investigation question, competing hypotheses, evidence, contradictions, unknowns, discriminators, and stop rule"
            }
            Self::Forensic => {
                "broad exact evidence graph, source spans, receipts, alternative derivations, and replay handles"
            }
            Self::Operation => {
                "one durable plan/effect/task, progress, expected terminal proof, obligations, and reconciliation"
            }
            Self::Handoff => {
                "minimum sufficient state for another agent to resume without rediscovery or hidden staleness"
            }
            Self::DecisionDiff => {
                "why a conclusion, priority, hypothesis, plan, or preferred affordance changed"
            }
            Self::EpistemicMap => {
                "known/estimated/unknown/conflicted/stale/not-observable/redacted/indeterminate map plus certified core, material alternative worlds, coverage, gaps, and redactions"
            }
        }
    }

    /// Returns the target token bound of this view.
    #[must_use]
    pub const fn target_tokens(self) -> u32 {
        match self {
            Self::Pulse => 120,
            Self::Brief => 800,
            Self::Case => 3_000,
            Self::Forensic => 8_000,
            Self::Operation => 600,
            Self::Handoff => 1_800,
            Self::DecisionDiff => 900,
            Self::EpistemicMap => 1_500,
        }
    }

    /// Returns the maximum token bound of this view.
    #[must_use]
    pub const fn maximum_tokens(self) -> u32 {
        match self {
            Self::Pulse => 300,
            Self::Brief => 1_600,
            Self::Case => 5_000,
            Self::Forensic => 16_000,
            Self::Operation => 1_200,
            Self::Handoff => 3_200,
            Self::DecisionDiff => 1_800,
            Self::EpistemicMap => 3_000,
        }
    }

    /// Returns the required sections of this view (registry spellings).
    #[must_use]
    pub const fn required_sections(self) -> ViewSectionList {
        match self {
            Self::Pulse => &[
                "criticalChanges",
                "coverageChanges",
                "effectUncertainty",
                "urgentObligations",
                "continuity",
            ],
            Self::Brief => &[
                "now",
                "certified",
                "possible",
                "changed",
                "why",
                "unknown",
                "atRisk",
                "controlEnvelope",
                "next",
            ],
            Self::Case => &[
                "question",
                "hypotheses",
                "evidence",
                "contradictions",
                "unknowns",
                "discriminators",
                "stopRule",
            ],
            Self::Forensic => &[
                "evidenceGraph",
                "sourceHandles",
                "receipts",
                "derivations",
                "replay",
            ],
            Self::Operation => &[
                "state",
                "progress",
                "proofExpected",
                "obligations",
                "reconciliation",
            ],
            Self::Handoff => &[
                "mission",
                "situation",
                "cases",
                "plans",
                "obligations",
                "unknowns",
                "budgets",
                "authority",
                "next",
            ],
            Self::DecisionDiff => &[
                "basisBefore",
                "basisAfter",
                "changedEvidence",
                "invalidatedAssumptions",
                "decisionImpact",
                "whatWouldReverse",
            ],
            Self::EpistemicMap => &[
                "states",
                "certifiedCore",
                "certifiedAbsences",
                "materialAlternatives",
                "adversarialResiduals",
                "coverage",
                "contradictions",
                "gaps",
                "redactions",
                "nextDiscriminators",
            ],
        }
    }

    /// Returns the qualification gate of this view row.
    #[must_use]
    pub const fn gate(self) -> &'static str {
        REGISTERED_VIEW_GATE
    }

    /// Returns the deterministic canonical text row encoding.
    ///
    /// Field order and delimiters are documented on the module. The row
    /// literal is pinned against the typed accessors by unit tests and
    /// against the machine registry by the views section of
    /// `scripts/agent_operation_registry_checker.py`.
    #[must_use]
    pub const fn canonical_row_encoding(self) -> &'static str {
        match self {
            Self::Pulse => {
                "AVIEW-001|pulse|fss-context-pack|120|300|QL-AGENT-001|criticalChanges;coverageChanges;effectUncertainty;urgentObligations;continuity"
            }
            Self::Brief => {
                "AVIEW-002|brief|fss-situation|800|1600|QL-AGENT-001|now;certified;possible;changed;why;unknown;atRisk;controlEnvelope;next"
            }
            Self::Case => {
                "AVIEW-003|case|fss-investigation|3000|5000|QL-AGENT-001|question;hypotheses;evidence;contradictions;unknowns;discriminators;stopRule"
            }
            Self::Forensic => {
                "AVIEW-004|forensic|fss-context-pack|8000|16000|QL-AGENT-001|evidenceGraph;sourceHandles;receipts;derivations;replay"
            }
            Self::Operation => {
                "AVIEW-005|operation|fss-obligation|600|1200|QL-AGENT-001|state;progress;proofExpected;obligations;reconciliation"
            }
            Self::Handoff => {
                "AVIEW-006|handoff|fss-handoff|1800|3200|QL-AGENT-001|mission;situation;cases;plans;obligations;unknowns;budgets;authority;next"
            }
            Self::DecisionDiff => {
                "AVIEW-007|decision_diff|fss-explain|900|1800|QL-AGENT-001|basisBefore;basisAfter;changedEvidence;invalidatedAssumptions;decisionImpact;whatWouldReverse"
            }
            Self::EpistemicMap => {
                "AVIEW-008|epistemic_map|fss-knowledge|1500|3000|QL-AGENT-001|states;certifiedCore;certifiedAbsences;materialAlternatives;adversarialResiduals;coverage;contradictions;gaps;redactions;nextDiscriminators"
            }
        }
    }

    /// Validates the row invariants at construction and use boundaries.
    pub fn validate_row(self) -> Result<(), ContractError> {
        if self.target_tokens() == 0 || self.maximum_tokens() < self.target_tokens() {
            return Err(ContractError::BudgetExhausted);
        }
        if !self.gate().starts_with("QL-") || !self.owner().starts_with("fss-") {
            return Err(ContractError::InvalidIdentifier);
        }
        if self.required_sections().is_empty() {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(())
    }

    /// Returns whether this view is the registered default view of `operation`.
    #[must_use]
    pub fn is_default_for(self, operation: AgentOperation) -> bool {
        operation.default_view() == self.id()
    }

    /// Returns the domain-separated canonical digest of the full row.
    #[must_use]
    pub fn row_digest(self) -> ContentDigest {
        self.canonical_digest(VIEW_ROW_DIGEST_DOMAIN)
    }
}

impl CanonicalEncode for AgentView {
    /// Encodes every registered row field in the documented fixed order.
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.id());
        encoder.text(self.name());
        encoder.text(self.owner());
        encoder.u32(self.target_tokens());
        encoder.u32(self.maximum_tokens());
        encoder.text(self.gate());
        encoder.u32(self.required_sections().len() as u32);
        for section in self.required_sections() {
            encoder.text(section);
        }
    }
}

impl CanonicalDecode for AgentView {
    /// Decodes a row and fails closed unless the fields reconstruct a
    /// registered row.
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let id = decoder.text()?;
        let name = decoder.text()?;
        let owner = decoder.text()?;
        let target = decoder.u32()?;
        let maximum = decoder.u32()?;
        let gate = decoder.text()?;
        let section_len = decoder.u32()?;
        let mut sections = Vec::with_capacity(section_len.min(16) as usize);
        for _ in 0..section_len {
            sections.push(decoder.text()?.to_owned());
        }
        let candidate = Self::from_id(id)?;
        let matches = candidate.id() == id
            && candidate.name() == name
            && candidate.owner() == owner
            && candidate.target_tokens() == target
            && candidate.maximum_tokens() == maximum
            && candidate.gate() == gate
            && candidate.required_sections().len() == sections.len()
            && candidate
                .required_sections()
                .iter()
                .zip(sections.iter())
                .all(|(a, b)| a == b);
        if !matches {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(candidate)
    }
}

impl fmt::Display for AgentView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl core::str::FromStr for AgentView {
    type Err = ContractError;

    /// Parses by canonical name only; stable IDs are never accepted as names
    /// (same laundering rule as `ProvenanceClass` and `AgentOperation`).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s)
    }
}
