//! Resource, control-envelope, context-pack, and semantic-compression contracts.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    ActionAffordance, AffordanceClass, BudgetVector, CanonicalEncode, CanonicalEncoder,
    Completeness, ContentDigest, ContractBasis, ContractError, KnowledgeState, LedgerAnchor,
    MissionId, SessionId, TimestampNs, WorldEnvelope,
};

const MAX_CONTEXT_ITEMS: usize = 1_024;
const MAX_TEXT_BYTES: usize = 16 * 1_024;

/// Coarse pressure class used to make resource-driven degradation explicit.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResourcePressure {
    /// All declared resource dimensions are comfortably available.
    Nominal,
    /// At least one resource dimension is approaching its operating bound.
    Elevated,
    /// One or more dimensions require an explicit degraded execution path.
    Constrained,
    /// Only critical work and safe terminalization should proceed.
    Critical,
}

impl ResourcePressure {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nominal => "nominal",
            Self::Elevated => "elevated",
            Self::Constrained => "constrained",
            Self::Critical => "critical",
        }
    }
}

impl CanonicalEncode for ResourcePressure {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

/// Available and reserved resources at one exact situation anchor.
#[derive(Clone, Debug, PartialEq)]
pub struct ResourceState {
    /// Total resource budget currently available to the session.
    pub available: BudgetVector,
    /// Budget already reserved for active work and terminal obligations.
    pub reserved: BudgetVector,
    /// Coarse pressure classification.
    pub pressure: ResourcePressure,
    /// Dimensions whose normal execution path has been explicitly degraded.
    pub degraded_dimensions: BTreeSet<String>,
}

impl ResourceState {
    /// Constructs and validates a resource state.
    pub fn new(
        available: BudgetVector,
        reserved: BudgetVector,
        pressure: ResourcePressure,
        degraded_dimensions: impl IntoIterator<Item = String>,
    ) -> Result<Self, ContractError> {
        let state = Self {
            available,
            reserved,
            pressure,
            degraded_dimensions: degraded_dimensions.into_iter().collect(),
        };
        state.validate()?;
        Ok(state)
    }

    /// Validates finite resource values and reservation bounds.
    pub fn validate(&self) -> Result<(), ContractError> {
        if !self.available.is_valid()
            || !self.reserved.is_valid()
            || !self.reserved.fits_within(self.available)
            || self.degraded_dimensions.iter().any(|value| value.is_empty())
        {
            return Err(ContractError::BudgetExhausted);
        }
        Ok(())
    }

    /// Returns the canonical resource-state digest.
    #[must_use]
    pub fn state_digest(&self) -> ContentDigest {
        self.canonical_digest("fss.agent_resource_state.v1")
    }
}

impl CanonicalEncode for ResourceState {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encode_budget(self.available, encoder);
        encode_budget(self.reserved, encoder);
        self.pressure.encode_canonical(encoder);
        encode_text_set(&self.degraded_dimensions, encoder);
    }
}

/// One observable branch represented in the categorized control envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchCondition {
    /// Stable content-derived condition identity.
    pub condition_id: String,
    /// Retained worlds in which the condition is relevant.
    pub world_ids: BTreeSet<String>,
    /// Affordances enabled when the predicate holds.
    pub enabled_affordance_ids: BTreeSet<String>,
    /// Affordances disabled when the predicate holds.
    pub disabled_affordance_ids: BTreeSet<String>,
}

impl CanonicalEncode for BranchCondition {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.condition_id);
        encode_text_set(&self.world_ids, encoder);
        encode_text_set(&self.enabled_affordance_ids, encoder);
        encode_text_set(&self.disabled_affordance_ids, encoder);
    }
}

/// Deterministic classification of the complete current affordance frontier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlEnvelope {
    /// Affordances safe and useful in every retained world.
    pub robust_affordance_ids: BTreeSet<String>,
    /// Affordances gated by an observable branch predicate.
    pub conditional_affordance_ids: BTreeSet<String>,
    /// Information-gathering affordances.
    pub information_gathering_affordance_ids: BTreeSet<String>,
    /// Bounded wait/watch affordances.
    pub wait_affordance_ids: BTreeSet<String>,
    /// Blocked or unavailable affordances retained for explanation.
    pub blocked_affordance_ids: BTreeSet<String>,
    /// Invariants shared by every retained possible world.
    pub robust_invariants: BTreeSet<String>,
    /// Observable branch conditions for conditional control.
    pub branch_conditions: Vec<BranchCondition>,
    /// Exact possible-world envelope digest.
    pub envelope_digest: ContentDigest,
}

impl ControlEnvelope {
    /// Classifies a complete affordance frontier against an exact world envelope.
    pub fn from_affordances(
        worlds: &WorldEnvelope,
        affordances: &[ActionAffordance],
    ) -> Result<Self, ContractError> {
        worlds.validate()?;
        let mut robust_affordance_ids = BTreeSet::new();
        let mut conditional_affordance_ids = BTreeSet::new();
        let mut information_gathering_affordance_ids = BTreeSet::new();
        let mut wait_affordance_ids = BTreeSet::new();
        let mut blocked_affordance_ids = BTreeSet::new();
        let mut branches: BTreeMap<String, BranchCondition> = BTreeMap::new();
        let mut seen = BTreeSet::new();

        for affordance in affordances {
            affordance.validate_against(worlds)?;
            if affordance.affordance_id.is_empty()
                || !seen.insert(affordance.affordance_id.clone())
            {
                return Err(ContractError::NonCanonicalOrdering);
            }
            match affordance.class {
                AffordanceClass::Robust => {
                    robust_affordance_ids.insert(affordance.affordance_id.clone());
                }
                AffordanceClass::Conditional => {
                    conditional_affordance_ids.insert(affordance.affordance_id.clone());
                    let predicate = affordance
                        .branch_predicate
                        .as_deref()
                        .ok_or(ContractError::EvidenceRequired)?;
                    let condition_id = format!(
                        "condition:{}",
                        ContentDigest::sha256(predicate.as_bytes())
                    );
                    let branch = branches.entry(condition_id.clone()).or_insert_with(|| {
                        BranchCondition {
                            condition_id,
                            world_ids: BTreeSet::new(),
                            enabled_affordance_ids: BTreeSet::new(),
                            disabled_affordance_ids: BTreeSet::new(),
                        }
                    });
                    branch
                        .world_ids
                        .extend(affordance.supported_worlds.iter().cloned());
                    branch
                        .world_ids
                        .extend(affordance.unsafe_worlds.iter().cloned());
                    branch
                        .enabled_affordance_ids
                        .insert(affordance.affordance_id.clone());
                    if !affordance.unsafe_worlds.is_empty() {
                        branch
                            .disabled_affordance_ids
                            .insert(affordance.affordance_id.clone());
                    }
                }
                AffordanceClass::Probe => {
                    information_gathering_affordance_ids
                        .insert(affordance.affordance_id.clone());
                }
                AffordanceClass::Wait => {
                    wait_affordance_ids.insert(affordance.affordance_id.clone());
                }
                AffordanceClass::Blocked | AffordanceClass::Unavailable => {
                    blocked_affordance_ids.insert(affordance.affordance_id.clone());
                }
            }
        }

        let envelope = Self {
            robust_affordance_ids,
            conditional_affordance_ids,
            information_gathering_affordance_ids,
            wait_affordance_ids,
            blocked_affordance_ids,
            robust_invariants: worlds.common_invariants.clone(),
            branch_conditions: branches.into_values().collect(),
            envelope_digest: worlds.envelope_digest(),
        };
        envelope.validate_against(worlds, affordances)?;
        Ok(envelope)
    }

    /// Proves that the envelope is the exact deterministic classification of the frontier.
    pub fn validate_against(
        &self,
        worlds: &WorldEnvelope,
        affordances: &[ActionAffordance],
    ) -> Result<(), ContractError> {
        let expected = Self::from_affordances_unchecked(worlds, affordances)?;
        if self != &expected {
            return Err(ContractError::DigestMismatch);
        }
        Ok(())
    }

    /// Returns the canonical categorized-control digest.
    #[must_use]
    pub fn control_digest(&self) -> ContentDigest {
        self.canonical_digest("fss.agent_control_envelope.v1")
    }

    fn from_affordances_unchecked(
        worlds: &WorldEnvelope,
        affordances: &[ActionAffordance],
    ) -> Result<Self, ContractError> {
        let mut robust_affordance_ids = BTreeSet::new();
        let mut conditional_affordance_ids = BTreeSet::new();
        let mut information_gathering_affordance_ids = BTreeSet::new();
        let mut wait_affordance_ids = BTreeSet::new();
        let mut blocked_affordance_ids = BTreeSet::new();
        let mut branches: BTreeMap<String, BranchCondition> = BTreeMap::new();
        let mut seen = BTreeSet::new();

        for affordance in affordances {
            affordance.validate_against(worlds)?;
            if affordance.affordance_id.is_empty()
                || !seen.insert(affordance.affordance_id.clone())
            {
                return Err(ContractError::NonCanonicalOrdering);
            }
            match affordance.class {
                AffordanceClass::Robust => {
                    robust_affordance_ids.insert(affordance.affordance_id.clone());
                }
                AffordanceClass::Conditional => {
                    conditional_affordance_ids.insert(affordance.affordance_id.clone());
                    let predicate = affordance
                        .branch_predicate
                        .as_deref()
                        .ok_or(ContractError::EvidenceRequired)?;
                    let condition_id = format!(
                        "condition:{}",
                        ContentDigest::sha256(predicate.as_bytes())
                    );
                    let branch = branches.entry(condition_id.clone()).or_insert_with(|| {
                        BranchCondition {
                            condition_id,
                            world_ids: BTreeSet::new(),
                            enabled_affordance_ids: BTreeSet::new(),
                            disabled_affordance_ids: BTreeSet::new(),
                        }
                    });
                    branch
                        .world_ids
                        .extend(affordance.supported_worlds.iter().cloned());
                    branch
                        .world_ids
                        .extend(affordance.unsafe_worlds.iter().cloned());
                    branch
                        .enabled_affordance_ids
                        .insert(affordance.affordance_id.clone());
                    if !affordance.unsafe_worlds.is_empty() {
                        branch
                            .disabled_affordance_ids
                            .insert(affordance.affordance_id.clone());
                    }
                }
                AffordanceClass::Probe => {
                    information_gathering_affordance_ids
                        .insert(affordance.affordance_id.clone());
                }
                AffordanceClass::Wait => {
                    wait_affordance_ids.insert(affordance.affordance_id.clone());
                }
                AffordanceClass::Blocked | AffordanceClass::Unavailable => {
                    blocked_affordance_ids.insert(affordance.affordance_id.clone());
                }
            }
        }

        Ok(Self {
            robust_affordance_ids,
            conditional_affordance_ids,
            information_gathering_affordance_ids,
            wait_affordance_ids,
            blocked_affordance_ids,
            robust_invariants: worlds.common_invariants.clone(),
            branch_conditions: branches.into_values().collect(),
            envelope_digest: worlds.envelope_digest(),
        })
    }
}

impl CanonicalEncode for ControlEnvelope {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encode_text_set(&self.robust_affordance_ids, encoder);
        encode_text_set(&self.conditional_affordance_ids, encoder);
        encode_text_set(&self.information_gathering_affordance_ids, encoder);
        encode_text_set(&self.wait_affordance_ids, encoder);
        encode_text_set(&self.blocked_affordance_ids, encoder);
        encode_text_set(&self.robust_invariants, encoder);
        let mut branches = self.branch_conditions.clone();
        branches.sort_by(|left, right| left.condition_id.cmp(&right.condition_id));
        encoder.u64(branches.len() as u64);
        for branch in &branches {
            branch.encode_canonical(encoder);
        }
        encoder.digest(self.envelope_digest);
    }
}

/// One bounded semantic item selected into an agent context pack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextItem {
    /// Stable item identity.
    pub item_id: String,
    /// Semantic class used by the compression receipt.
    pub kind: String,
    /// Explicit epistemic state.
    pub epistemic_state: KnowledgeState,
    /// Compact semantic content, never raw private media.
    pub content: String,
    /// Evidence, claim, world, obligation, or affordance identities supporting the item.
    pub basis: BTreeSet<String>,
    /// Priced handles capable of expanding omitted detail.
    pub expansion_handles: BTreeSet<String>,
}

impl ContextItem {
    /// Validates one bounded context item.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.item_id.is_empty()
            || self.kind.is_empty()
            || self.content.is_empty()
            || self.content.len() > MAX_TEXT_BYTES
            || self.basis.is_empty()
            || self.basis.iter().any(|value| value.is_empty())
            || self.expansion_handles.iter().any(|value| value.is_empty())
        {
            return Err(ContractError::EvidenceRequired);
        }
        Ok(())
    }
}

impl CanonicalEncode for ContextItem {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.item_id);
        encoder.text(&self.kind);
        encoder.text(self.epistemic_state.as_str());
        encoder.text(&self.content);
        encode_text_set(&self.basis, encoder);
        encode_text_set(&self.expansion_handles, encoder);
    }
}

/// Rooted, bounded semantic context selected for one exact situation frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticContextPack {
    /// Stable pack identity.
    pub pack_id: String,
    /// Exact semantic contract basis.
    pub contract_basis: ContractBasis,
    /// Mission identity.
    pub mission_id: MissionId,
    /// Session identity.
    pub session_id: SessionId,
    /// Stable registered view identity.
    pub view_id: String,
    /// Exact authority anchor.
    pub anchor: LedgerAnchor,
    /// Digest of the complete source situation frame.
    pub situation_fingerprint: ContentDigest,
    /// Canonically ordered selected items.
    pub items: Vec<ContextItem>,
    /// Identity of the compression receipt explaining this selection.
    pub compression_receipt_id: String,
    /// Deterministic reference token estimate.
    pub token_count: u64,
    /// Continuation for optional omitted detail.
    pub continuation: Option<String>,
    /// Caller-supplied creation time.
    pub created_at: TimestampNs,
    /// Digest of the complete body, excluding this field.
    pub pack_digest: ContentDigest,
}

impl SemanticContextPack {
    /// Publishes a deterministic pack after sorting and validating every selected item.
    #[allow(clippy::too_many_arguments)]
    pub fn publish(
        pack_id: impl Into<String>,
        contract_basis: ContractBasis,
        mission_id: MissionId,
        session_id: SessionId,
        view_id: impl Into<String>,
        anchor: LedgerAnchor,
        situation_fingerprint: ContentDigest,
        mut items: Vec<ContextItem>,
        compression_receipt_id: impl Into<String>,
        continuation: Option<String>,
        created_at: TimestampNs,
    ) -> Result<Self, ContractError> {
        items.sort_by(|left, right| left.item_id.cmp(&right.item_id));
        let token_count = reference_token_count(&items);
        let mut pack = Self {
            pack_id: pack_id.into(),
            contract_basis,
            mission_id,
            session_id,
            view_id: view_id.into(),
            anchor,
            situation_fingerprint,
            items,
            compression_receipt_id: compression_receipt_id.into(),
            token_count,
            continuation,
            created_at,
            pack_digest: ContentDigest::sha256(b"unpublished-context-pack"),
        };
        pack.validate_body()?;
        pack.pack_digest = pack.computed_digest();
        Ok(pack)
    }

    /// Recomputes the digest with the digest field omitted.
    #[must_use]
    pub fn computed_digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.encode_body(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }

    /// Validates ordering, token accounting, and content identity.
    pub fn verify(&self) -> Result<(), ContractError> {
        self.validate_body()?;
        if self.pack_digest != self.computed_digest() {
            return Err(ContractError::DigestMismatch);
        }
        Ok(())
    }

    /// Returns the canonical encoded byte count used by the compression receipt.
    #[must_use]
    pub fn encoded_bytes(&self) -> u64 {
        self.canonical_bytes().len() as u64
    }

    fn validate_body(&self) -> Result<(), ContractError> {
        if self.pack_id.is_empty()
            || self.view_id.is_empty()
            || self.compression_receipt_id.is_empty()
            || self.contract_basis.semantic_protocol != "fss/1"
            || self.items.is_empty()
            || self.items.len() > MAX_CONTEXT_ITEMS
            || self
                .continuation
                .as_deref()
                .is_some_and(str::is_empty)
            || self.token_count != reference_token_count(&self.items)
        {
            return Err(ContractError::EvidenceRequired);
        }
        let mut prior: Option<&str> = None;
        for item in &self.items {
            item.validate()?;
            if prior.is_some_and(|value| value >= item.item_id.as_str()) {
                return Err(ContractError::NonCanonicalOrdering);
            }
            prior = Some(&item.item_id);
        }
        Ok(())
    }

    fn encode_body(&self, encoder: &mut CanonicalEncoder) {
        encoder.text("fss.semantic_context_pack.v1");
        encoder.text(&self.pack_id);
        self.contract_basis.encode_canonical(encoder);
        self.mission_id.encode_canonical(encoder);
        self.session_id.encode_canonical(encoder);
        encoder.text(&self.view_id);
        self.anchor.encode_canonical(encoder);
        encoder.digest(self.situation_fingerprint);
        encoder.u64(self.items.len() as u64);
        for item in &self.items {
            item.encode_canonical(encoder);
        }
        encoder.text(&self.compression_receipt_id);
        encoder.u64(self.token_count);
        match &self.continuation {
            Some(value) => {
                encoder.bool(true);
                encoder.text(value);
            }
            None => encoder.bool(false),
        }
        self.created_at.encode_canonical(encoder);
    }
}

impl CanonicalEncode for SemanticContextPack {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        self.encode_body(encoder);
        encoder.digest(self.pack_digest);
    }
}

/// Compression transform applied to one semantic class or item group.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CompressionTransformKind {
    /// Select a bounded subset.
    Select,
    /// Aggregate equivalent values.
    Aggregate,
    /// Cluster related values.
    Cluster,
    /// Remove exact semantic duplicates.
    Deduplicate,
    /// Quantize a numeric representation.
    Quantize,
    /// Truncate optional detail.
    Truncate,
    /// Produce a decision-preserving summary.
    Summarize,
    /// Apply an explicit privacy redaction.
    Redact,
}

impl CompressionTransformKind {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::Aggregate => "aggregate",
            Self::Cluster => "cluster",
            Self::Deduplicate => "deduplicate",
            Self::Quantize => "quantize",
            Self::Truncate => "truncate",
            Self::Summarize => "summarize",
            Self::Redact => "redact",
        }
    }
}

/// Information-loss class of a compression transform.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CompressionLossClass {
    /// Exact semantic content is preserved.
    Lossless,
    /// The transformation is proved to preserve the current decision.
    DecisionPreserving,
    /// Optional information is omitted within an explicit bound.
    BoundedLoss,
    /// Information is intentionally removed by privacy policy.
    Redaction,
}

impl CompressionLossClass {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lossless => "lossless",
            Self::DecisionPreserving => "decision_preserving",
            Self::BoundedLoss => "bounded_loss",
            Self::Redaction => "redaction",
        }
    }
}

/// One explicit transformation in a semantic-compression receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompressionTransform {
    /// Transform class.
    pub kind: CompressionTransformKind,
    /// Semantic scope affected.
    pub scope: String,
    /// Declared information-loss class.
    pub loss_class: CompressionLossClass,
    /// Optional bounded explanation.
    pub details: Option<String>,
}

impl CanonicalEncode for CompressionTransform {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.kind.as_str());
        encoder.text(&self.scope);
        encoder.text(self.loss_class.as_str());
        match &self.details {
            Some(value) => {
                encoder.bool(true);
                encoder.text(value);
            }
            None => encoder.bool(false),
        }
    }
}

/// Completeness of one semantic domain after selection and compression.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompressionCompleteness {
    /// Semantic domain identity.
    pub domain: String,
    /// Completeness state.
    pub state: Completeness,
    /// Number of known omitted items in the domain.
    pub omitted_count: u64,
}

impl CanonicalEncode for CompressionCompleteness {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.domain);
        encoder.u8(completeness_code(self.state));
        encoder.u64(self.omitted_count);
    }
}

/// Proof that decision-critical content was not lost by compression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CriticalPreservation {
    /// Number of critical items known to the selector.
    pub known_critical_items: u64,
    /// Critical items omitted from the output. Must remain zero.
    pub omitted_critical_items: u64,
    /// Invalidations omitted from the output. Must remain zero.
    pub omitted_invalidations: u64,
    /// Contradictions omitted from the output. Must remain zero.
    pub omitted_contradictions: u64,
}

impl CriticalPreservation {
    /// Returns true only when every critical class is preserved.
    #[must_use]
    pub const fn is_lossless(self) -> bool {
        self.omitted_critical_items == 0
            && self.omitted_invalidations == 0
            && self.omitted_contradictions == 0
    }
}

impl CanonicalEncode for CriticalPreservation {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.known_critical_items);
        encoder.u64(self.omitted_critical_items);
        encoder.u64(self.omitted_invalidations);
        encoder.u64(self.omitted_contradictions);
    }
}

/// Priced handle for expanding optional omitted context.
#[derive(Clone, Debug, PartialEq)]
pub struct ExpansionHandle {
    /// Stable semantic handle.
    pub handle: String,
    /// What additional context the handle provides.
    pub purpose: String,
    /// Conservative expansion cost.
    pub estimated_cost: BudgetVector,
}

impl CanonicalEncode for ExpansionHandle {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.handle);
        encoder.text(&self.purpose);
        encode_budget(self.estimated_cost, encoder);
    }
}

/// Why semantic selection stopped.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CompressionStopReason {
    /// Every eligible item was selected.
    Complete,
    /// The target output budget was reached.
    TargetBudget,
    /// A hard output budget was reached.
    HardBudget,
    /// No remaining item was relevant to the decision.
    NoMoreRelevant,
    /// Capability or privacy policy withheld remaining items.
    Unauthorized,
    /// Source material was incomplete.
    SourceIncomplete,
    /// Selection failed with an explicit error.
    Error,
}

impl CompressionStopReason {
    /// Returns the stable schema spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::TargetBudget => "target_budget",
            Self::HardBudget => "hard_budget",
            Self::NoMoreRelevant => "no_more_relevant",
            Self::Unauthorized => "unauthorized",
            Self::SourceIncomplete => "source_incomplete",
            Self::Error => "error",
        }
    }
}

/// Proof-bearing record of semantic context selection and omission.
#[derive(Clone, Debug, PartialEq)]
pub struct SemanticCompressionReceipt {
    /// Stable receipt identity.
    pub receipt_id: String,
    /// Exact source authority anchor.
    pub source_anchor: LedgerAnchor,
    /// Registered view identity.
    pub view_id: String,
    /// Target output token budget under the reference estimator.
    pub target_tokens: u64,
    /// Semantic classes represented in the selected output.
    pub selected_classes: BTreeSet<String>,
    /// Optional semantic classes omitted from the selected output.
    pub omitted_classes: BTreeSet<String>,
    /// Explicit transforms applied.
    pub transforms: Vec<CompressionTransform>,
    /// Domain-by-domain completeness.
    pub completeness: Vec<CompressionCompleteness>,
    /// Proof that critical classes were preserved.
    pub critical_preservation: CriticalPreservation,
    /// Actual reference token count.
    pub actual_tokens: u64,
    /// Actual canonical context-pack byte count.
    pub actual_bytes: u64,
    /// Priced expansion handles for omitted optional detail.
    pub expansion_handles: Vec<ExpansionHandle>,
    /// Digest of the selector frontier, when retained.
    pub selection_frontier_digest: Option<ContentDigest>,
    /// Why selection stopped.
    pub stop_reason: CompressionStopReason,
    /// Exact selected context-pack digest.
    pub output_digest: ContentDigest,
}

impl SemanticCompressionReceipt {
    /// Validates the receipt independently of its selected context pack.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.receipt_id.is_empty()
            || self.view_id.is_empty()
            || self.actual_tokens > self.target_tokens
            || !self.critical_preservation.is_lossless()
            || !self.selected_classes.is_disjoint(&self.omitted_classes)
            || self.selected_classes.iter().any(|value| value.is_empty())
            || self.omitted_classes.iter().any(|value| value.is_empty())
        {
            return Err(ContractError::BudgetExhausted);
        }
        if self.stop_reason == CompressionStopReason::Complete && !self.omitted_classes.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        if !self.omitted_classes.is_empty() && self.expansion_handles.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        let mut completeness_domains = BTreeSet::new();
        for row in &self.completeness {
            if row.domain.is_empty()
                || !completeness_domains.insert(row.domain.as_str())
                || row.state == Completeness::Stale
            {
                return Err(ContractError::NonCanonicalOrdering);
            }
        }
        let mut handles = BTreeSet::new();
        for handle in &self.expansion_handles {
            if handle.handle.is_empty()
                || handle.purpose.is_empty()
                || !handle.estimated_cost.is_valid()
                || !handles.insert(handle.handle.as_str())
            {
                return Err(ContractError::EvidenceRequired);
            }
        }
        for transform in &self.transforms {
            if transform.scope.is_empty()
                || transform
                    .details
                    .as_deref()
                    .is_some_and(str::is_empty)
            {
                return Err(ContractError::EvidenceRequired);
            }
        }
        Ok(())
    }

    /// Cross-checks the receipt against the exact selected context pack.
    pub fn validate_for(&self, pack: &SemanticContextPack) -> Result<(), ContractError> {
        self.validate()?;
        pack.verify()?;
        let selected_kinds: BTreeSet<_> = pack.items.iter().map(|item| item.kind.clone()).collect();
        if self.receipt_id != pack.compression_receipt_id
            || self.source_anchor != pack.anchor
            || self.view_id != pack.view_id
            || self.actual_tokens != pack.token_count
            || self.actual_bytes != pack.encoded_bytes()
            || self.output_digest != pack.pack_digest
            || !selected_kinds.is_subset(&self.selected_classes)
        {
            return Err(ContractError::DigestMismatch);
        }
        Ok(())
    }

    /// Returns the canonical receipt digest.
    #[must_use]
    pub fn receipt_digest(&self) -> ContentDigest {
        self.canonical_digest("fss.semantic_compression_receipt.v1")
    }
}

impl CanonicalEncode for SemanticCompressionReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.receipt_id);
        self.source_anchor.encode_canonical(encoder);
        encoder.text(&self.view_id);
        encoder.u64(self.target_tokens);
        encode_text_set(&self.selected_classes, encoder);
        encode_text_set(&self.omitted_classes, encoder);
        encoder.u64(self.transforms.len() as u64);
        for transform in &self.transforms {
            transform.encode_canonical(encoder);
        }
        let mut completeness = self.completeness.clone();
        completeness.sort_by(|left, right| left.domain.cmp(&right.domain));
        encoder.u64(completeness.len() as u64);
        for row in &completeness {
            row.encode_canonical(encoder);
        }
        self.critical_preservation.encode_canonical(encoder);
        encoder.u64(self.actual_tokens);
        encoder.u64(self.actual_bytes);
        let mut handles = self.expansion_handles.clone();
        handles.sort_by(|left, right| left.handle.cmp(&right.handle));
        encoder.u64(handles.len() as u64);
        for handle in &handles {
            handle.encode_canonical(encoder);
        }
        match self.selection_frontier_digest {
            Some(value) => {
                encoder.bool(true);
                encoder.digest(value);
            }
            None => encoder.bool(false),
        }
        encoder.text(self.stop_reason.as_str());
        encoder.digest(self.output_digest);
    }
}

/// Deterministic dependency-free token estimate used only by the reference selector.
#[must_use]
pub fn reference_token_count(items: &[ContextItem]) -> u64 {
    let bytes = items.iter().fold(0_u64, |total, item| {
        let item_bytes = item
            .item_id
            .len()
            .saturating_add(item.kind.len())
            .saturating_add(item.content.len())
            .saturating_add(item.basis.iter().map(String::len).sum::<usize>())
            .saturating_add(
                item.expansion_handles
                    .iter()
                    .map(String::len)
                    .sum::<usize>(),
            );
        total.saturating_add(item_bytes as u64)
    });
    bytes.saturating_add(3) / 4
}

fn encode_text_set(values: &BTreeSet<String>, encoder: &mut CanonicalEncoder) {
    encoder.u64(values.len() as u64);
    for value in values {
        encoder.text(value);
    }
}

fn encode_budget(value: BudgetVector, encoder: &mut CanonicalEncoder) {
    encoder.u64(value.latency_ms);
    encoder.u64(value.tokens);
    encoder.u64(value.bytes);
    encoder.u32(value.model_calls);
    encoder.u64(value.cpu_millis);
    encoder.u64(value.accelerator_millis);
    encoder.u64(value.energy_millijoules);
    encoder.u64(value.network_bytes);
    encoder.u64(value.storage_operations);
    encoder.u64(canonical_f64_bits(value.privacy_exposure));
    encoder.u64(canonical_f64_bits(value.operator_attention_seconds));
}

fn canonical_f64_bits(value: f64) -> u64 {
    if value == 0.0 {
        0
    } else if value.is_nan() {
        0x7ff8_0000_0000_0000
    } else {
        value.to_bits()
    }
}

fn completeness_code(value: Completeness) -> u8 {
    match value {
        Completeness::Complete => 1,
        Completeness::Bounded => 2,
        Completeness::Partial => 3,
        Completeness::Unknown => 4,
        Completeness::NotObservable => 5,
        Completeness::Unauthorized => 6,
        Completeness::Stale => 7,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContractBasis, LedgerAnchor};

    fn basis() -> ContractBasis {
        ContractBasis::from_registry_bytes(
            b"schemas",
            b"operations",
            b"views",
            b"capabilities",
            b"errors",
            b"costs",
            "fss:test",
            None,
        )
    }

    fn world() -> WorldEnvelope {
        let anchor = LedgerAnchor::genesis("site:projection");
        WorldEnvelope {
            envelope_id: "world-envelope:test".to_owned(),
            objective_id: "objective:test".to_owned(),
            anchor,
            nominal_claim_ids: BTreeSet::from(["claim:test".to_owned()]),
            certified_core_claim_ids: BTreeSet::from(["claim:test".to_owned()]),
            alternatives: vec![crate::PossibleWorld {
                world_id: "world:test".to_owned(),
                description: "retained world".to_owned(),
                claim_ids: BTreeSet::from(["claim:test".to_owned()]),
                evidence: vec![ContentDigest::sha256(b"evidence")],
                consequence_severity: 1,
                protected: true,
            }],
            adversarial_residuals: Vec::new(),
            common_invariants: BTreeSet::from(["invariant:test".to_owned()]),
            coverage_boundary_handles: BTreeSet::from(["fss://coverage/test".to_owned()]),
        }
    }

    #[test]
    fn reservations_must_fit_and_float_dimensions_must_be_finite() {
        let available = BudgetVector {
            latency_ms: 10,
            privacy_exposure: 1.0,
            operator_attention_seconds: 1.0,
            ..BudgetVector::default()
        };
        let reserved = BudgetVector {
            latency_ms: 11,
            ..BudgetVector::default()
        };
        assert_eq!(
            ResourceState::new(available, reserved, ResourcePressure::Nominal, []),
            Err(ContractError::BudgetExhausted)
        );
        let invalid = BudgetVector {
            privacy_exposure: f64::NAN,
            ..BudgetVector::default()
        };
        assert!(!invalid.is_valid());
    }

    #[test]
    fn control_envelope_is_an_exact_partition() -> Result<(), ContractError> {
        let worlds = world();
        let retained = worlds.world_ids();
        let affordances = vec![ActionAffordance {
            affordance_id: "affordance:test".to_owned(),
            operation: "wait".to_owned(),
            target: "fss://test".to_owned(),
            rationale: "bounded wait".to_owned(),
            class: AffordanceClass::Wait,
            supported_worlds: retained,
            unsafe_worlds: BTreeSet::new(),
            required_capabilities: BTreeSet::new(),
            cost: BudgetVector::default(),
            reversible: true,
            branch_predicate: None,
        }];
        let envelope = ControlEnvelope::from_affordances(&worlds, &affordances)?;
        assert_eq!(
            envelope.wait_affordance_ids,
            BTreeSet::from(["affordance:test".to_owned()])
        );
        envelope.validate_against(&worlds, &affordances)
    }

    #[test]
    fn context_pack_and_compression_receipt_cross_verify() -> Result<(), ContractError> {
        let anchor = LedgerAnchor::genesis("site:projection");
        let item = ContextItem {
            item_id: "context:critical".to_owned(),
            kind: "critical".to_owned(),
            epistemic_state: KnowledgeState::Known,
            content: "one decision-critical statement".to_owned(),
            basis: BTreeSet::from(["claim:test".to_owned()]),
            expansion_handles: BTreeSet::new(),
        };
        let pack = SemanticContextPack::publish(
            "context-pack:test",
            basis(),
            MissionId::parse("mission:test")?,
            SessionId::parse("session:test")?,
            "AVIEW-001",
            anchor.clone(),
            ContentDigest::sha256(b"frame"),
            vec![item],
            "compression:test",
            None,
            TimestampNs(1),
        )?;
        let receipt = SemanticCompressionReceipt {
            receipt_id: "compression:test".to_owned(),
            source_anchor: anchor,
            view_id: "AVIEW-001".to_owned(),
            target_tokens: pack.token_count,
            selected_classes: BTreeSet::from(["critical".to_owned()]),
            omitted_classes: BTreeSet::new(),
            transforms: vec![CompressionTransform {
                kind: CompressionTransformKind::Select,
                scope: "critical".to_owned(),
                loss_class: CompressionLossClass::Lossless,
                details: None,
            }],
            completeness: vec![CompressionCompleteness {
                domain: "critical".to_owned(),
                state: Completeness::Complete,
                omitted_count: 0,
            }],
            critical_preservation: CriticalPreservation {
                known_critical_items: 1,
                omitted_critical_items: 0,
                omitted_invalidations: 0,
                omitted_contradictions: 0,
            },
            actual_tokens: pack.token_count,
            actual_bytes: pack.encoded_bytes(),
            expansion_handles: Vec::new(),
            selection_frontier_digest: None,
            stop_reason: CompressionStopReason::Complete,
            output_digest: pack.pack_digest,
        };
        receipt.validate_for(&pack)
    }

    #[test]
    fn critical_omission_is_never_a_valid_receipt() {
        let receipt = SemanticCompressionReceipt {
            receipt_id: "compression:test".to_owned(),
            source_anchor: LedgerAnchor::genesis("site:projection"),
            view_id: "AVIEW-001".to_owned(),
            target_tokens: 10,
            selected_classes: BTreeSet::new(),
            omitted_classes: BTreeSet::from(["critical".to_owned()]),
            transforms: Vec::new(),
            completeness: Vec::new(),
            critical_preservation: CriticalPreservation {
                known_critical_items: 1,
                omitted_critical_items: 1,
                omitted_invalidations: 0,
                omitted_contradictions: 0,
            },
            actual_tokens: 0,
            actual_bytes: 0,
            expansion_handles: Vec::new(),
            selection_frontier_digest: None,
            stop_reason: CompressionStopReason::HardBudget,
            output_digest: ContentDigest::sha256(b"empty"),
        };
        assert_eq!(receipt.validate(), Err(ContractError::BudgetExhausted));
    }
}
