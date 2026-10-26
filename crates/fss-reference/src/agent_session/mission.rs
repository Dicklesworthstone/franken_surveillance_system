#![forbid(unsafe_code)]
//! Explicit, immutable mission evaluation over one selected own-session plan.
//!
//! PlanOutcomeV1 is a narrow cognition profile, not a natural-language predicate interpreter.
//! The native owner authenticates and verifies the cited plan, episode and effect custody before
//! constructing assessment facts. This store derives lifecycle state; no caller supplies a desired
//! mission state, and no transition grants, dispatches, retries or cancels an external effect.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractBasis, ContractError, DigestAlgorithm, EventId, LedgerAnchor, MissionId,
    MissionLifecycleState, ObligationId, OperationId, PrincipalId, SessionId, TimestampNs,
};

use super::{ReferenceSessionError, ReferenceSessionStore};

/// Maximum enrolled session/mission-record identities, including terminal histories.
pub const MAX_MISSIONS: usize = 32;
/// Maximum immutable revisions in one mission history. Old revisions are never evicted.
pub const MAX_MISSION_REVISIONS: usize = 128;
/// Aggregate immutable revisions across this reference owner.
pub const MAX_MISSION_HISTORY_REVISIONS: usize = 512;
/// Complete criterion, assessment or revision ceiling; no successful prefix is returned.
pub const MAX_MISSION_RECORD_BYTES: usize = 64 * 1024;
const MAX_ID_BYTES: usize = 256;
const MAX_CLOSURE_ITEMS: u32 = 4096;
const CRITERION_DOMAIN: &str = "fss.reference_mission_plan_criterion.v1";
const REVISION_DOMAIN: &str = "fss.reference_mission_revision.v1";
const STATE_DOMAIN: &str = "fss.reference_mission_state.v1";

#[cfg(test)]
pub(crate) mod tests;

/// Stable refusals deliberately omit private criterion, plan and episode identities.
#[derive(Debug)]
pub enum MissionError {
    /// Live session admission failed; clock or expiry changes remain owned by that store.
    Session(ReferenceSessionError),
    /// Current grants do not admit mission intent or private plan metadata.
    Unauthorized,
    /// A bounded profile, identifier, proof or assessment is malformed.
    InvalidRequest,
    /// Session, mission, immutable record, interpretation basis or source scope differs.
    ScopeMismatch,
    /// An exact predecessor or immutable criterion differs from retained history.
    Conflict,
    /// A terminal revision cannot be changed by a later assessment.
    Terminal,
    /// Retained capacity is exhausted; old history is preserved.
    CapacityExceeded,
}

impl fmt::Display for MissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Session(_) => "mission session unavailable",
            Self::Unauthorized => "mission authority unavailable",
            Self::InvalidRequest => "invalid bounded mission request",
            Self::ScopeMismatch => "mission scope or interpretation basis differs",
            Self::Conflict => "mission criterion or predecessor differs",
            Self::Terminal => "terminal mission revision is immutable",
            Self::CapacityExceeded => "mission history capacity exhausted",
        })
    }
}
impl std::error::Error for MissionError {}
impl From<ReferenceSessionError> for MissionError {
    fn from(value: ReferenceSessionError) -> Self {
        Self::Session(value)
    }
}
type Result<T> = std::result::Result<T, MissionError>;

pub(crate) fn sha(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256
        && !digest.is_laboratory()
        && digest.bytes() != [0; 32]
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b':' | b'.' | b'_' | b'+' | b'/' | b'-')
        })
}

pub(crate) fn same_generations(a: &LedgerAnchor, b: &LedgerAnchor) -> bool {
    a.site_lineage == b.site_lineage
        && a.ledger_epoch == b.ledger_epoch
        && a.adapter_registry_epoch == b.adapter_registry_epoch
        && a.schema_epoch == b.schema_epoch
        && a.policy_epoch == b.policy_epoch
        && a.privacy_epoch == b.privacy_epoch
}

fn valid_anchor(anchor: &LedgerAnchor) -> bool {
    !anchor.site_lineage.is_empty() && anchor.site_lineage.len() <= 512 && sha(anchor.state_root)
}

/// Owner-selected PlanOutcomeV1 contract. Every field is immutable after enrollment.
///
/// Success means the selected plan's exact current event revision and proven effect/obligation
/// outcome, with a matching closed episode and no other unsettled owned work. It never certifies
/// physical threat, appropriateness of an alert, or completion inferred from the prose goal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionPlanCriterion {
    /// Existing authenticated session.
    pub session_id: SessionId,
    /// Existing mission identity; it is insufficient as an ownership key on its own.
    pub mission_id: MissionId,
    /// Existing owning principal.
    pub principal: PrincipalId,
    /// Exact original MissionRecord digest pinned by this session's workspace.
    pub mission_record_digest: ContentDigest,
    /// Exact selected own-session plan identity.
    pub plan_id: String,
    /// SHA-256 of the canonical PlanRecord.
    pub plan_record_digest: ContentDigest,
    /// Verified root-last plan publication root.
    pub plan_root: ContentDigest,
    /// Exact canonical control-plan rendering digest.
    pub control_plan_digest: ContentDigest,
    /// Effect operation named by the selected plan.
    pub operation_id: OperationId,
    /// Terminal-proof obligation named by that plan.
    pub obligation_id: ObligationId,
    /// Event lineage named by that plan.
    pub event_id: EventId,
    /// Exact event revision the selected plan was compiled against.
    pub event_revision: ContentDigest,
    /// Complete interpretation basis of the enrolling session.
    pub contract_basis: ContractBasis,
    /// Exact live session anchor at enrollment, not a fabricated plan compile anchor.
    pub baseline_anchor: LedgerAnchor,
    /// Explicit evidence-clock deadline; exhaustion alone never proves effect cancellation.
    pub decision_deadline: TimestampNs,
}

impl MissionPlanCriterion {
    /// Registered bounded execution profile, never parsed from natural language.
    pub const PROFILE: &str = "plan_outcome.v1";

    /// Validate all bounded identity and proof coordinates before materialization.
    pub fn validate(&self) -> Result<()> {
        if ![
            self.session_id.as_str(),
            self.mission_id.as_str(),
            self.principal.as_str(),
            &self.plan_id,
            self.operation_id.as_str(),
            self.obligation_id.as_str(),
            self.event_id.as_str(),
        ]
        .into_iter()
        .all(identifier)
            || !self.plan_id.starts_with("plan:")
            || ![
                self.mission_record_digest,
                self.plan_record_digest,
                self.plan_root,
                self.control_plan_digest,
                self.event_revision,
            ]
            .into_iter()
            .all(sha)
            || !valid_anchor(&self.baseline_anchor)
            || self.decision_deadline.0 <= 0
            || self.contract_basis.validate().is_err()
        {
            return Err(MissionError::InvalidRequest);
        }
        Ok(())
    }

    /// Exact criterion identity; metadata updates cannot replace the selected goal.
    pub fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        self.encode(&mut e);
        ContentDigest::sha256(&e.finish())
    }

    pub(crate) fn encode(&self, e: &mut CanonicalEncoder) {
        e.text(CRITERION_DOMAIN);
        e.text(Self::PROFILE);
        self.session_id.encode_canonical(e);
        self.mission_id.encode_canonical(e);
        self.principal.encode_canonical(e);
        e.digest(self.mission_record_digest);
        e.text(&self.plan_id);
        e.digest(self.plan_record_digest);
        e.digest(self.plan_root);
        e.digest(self.control_plan_digest);
        self.operation_id.encode_canonical(e);
        self.obligation_id.encode_canonical(e);
        self.event_id.encode_canonical(e);
        e.digest(self.event_revision);
        self.contract_basis.encode_canonical(e);
        self.baseline_anchor.encode_canonical(e);
        e.i128(self.decision_deadline.0);
    }

    pub(crate) fn decode(d: &mut CanonicalDecoder<'_>) -> std::result::Result<Self, ContractError> {
        if d.text()? != CRITERION_DOMAIN || d.text()? != Self::PROFILE {
            return Err(ContractError::DigestMismatch);
        }
        let value = Self {
            session_id: SessionId::parse(text(d)?)?,
            mission_id: MissionId::parse(text(d)?)?,
            principal: PrincipalId::parse(text(d)?)?,
            mission_record_digest: d.digest()?,
            plan_id: text(d)?,
            plan_record_digest: d.digest()?,
            plan_root: d.digest()?,
            control_plan_digest: d.digest()?,
            operation_id: OperationId::parse(text(d)?)?,
            obligation_id: ObligationId::parse(text(d)?)?,
            event_id: EventId::parse(text(d)?)?,
            event_revision: d.digest()?,
            contract_basis: ContractBasis::decode_canonical(d)?,
            baseline_anchor: LedgerAnchor::decode_canonical(d)?,
            decision_deadline: TimestampNs(d.i128()?),
        };
        value
            .validate()
            .map_err(|_| ContractError::EvidenceRequired)?;
        Ok(value)
    }
}

macro_rules! projected_state {
    ($name:ident, $description:literal, {$($variant:ident => $spelling:literal),+ $(,)?}) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum $name { $(#[doc = $spelling] $variant),+ }
        impl $name {
            /// Exact registered owner spelling, without a new effect vocabulary.
            pub const fn as_str(self) -> &'static str { match self { $(Self::$variant => $spelling),+ } }
            /// Parse only one explicitly supported owner state.
            pub fn parse(value: &str) -> Result<Self> {
                match value { $($spelling => Ok(Self::$variant),)+ _ => Err(MissionError::InvalidRequest) }
            }
        }
    };
}

projected_state!(MissionOperationState, "Read-only projection of a registered effect lifecycle state.", {
    Prepared => "prepared", Committed => "committed", AdapterAccepted => "adapter_accepted",
    Observed => "observed", Verified => "verified", Failed => "failed", Cancelled => "cancelled",
    Indeterminate => "indeterminate"
});
projected_state!(MissionObligationState, "Read-only projection of a registered obligation lifecycle state.", {
    Pending => "pending", Verified => "verified", Failed => "failed",
    Indeterminate => "indeterminate", Cancelled => "cancelled"
});
projected_state!(MissionEpisodeOutcome, "Read-only outcome of the exact published plan episode.", {
    Verified => "verified", Failed => "failed", Cancelled => "cancelled", Withdrawn => "withdrawn"
});

/// Exact journal-owned operation facts admitted by the native effect projection boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionOperationFacts {
    /// Exact operation identity.
    pub operation_id: OperationId,
    /// Registered effect lifecycle state, not an inferred physical outcome.
    pub state: MissionOperationState,
    /// Whether external dispatch was committed at any point.
    pub dispatched: bool,
    /// Exact verified journal-owned operation receipt.
    pub receipt_digest: ContentDigest,
    /// Exact result/observation proof retained by that receipt.
    pub result_digest: Option<ContentDigest>,
}

/// Exact journal-owned obligation associated with the selected operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionObligationFacts {
    /// Exact obligation identity.
    pub obligation_id: ObligationId,
    /// Owning operation, checked independently of the obligation label.
    pub operation_id: OperationId,
    /// Registered obligation state.
    pub state: MissionObligationState,
    /// Terminal proof; it must equal the operation's result proof for completion.
    pub proof_digest: Option<ContentDigest>,
}

/// Immutable closed episode, revalidated from its root-last publication by the native owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionEpisodeFacts {
    /// Exact retained episode identity.
    pub episode_id: String,
    /// SHA-256 of the complete private episode record.
    pub record_digest: ContentDigest,
    /// Exact episode publication root.
    pub publication_root: ContentDigest,
    /// Episode's exact PlanRecord identity.
    pub plan_record_digest: ContentDigest,
    /// Episode's exact control-plan decision identity.
    pub control_plan_digest: ContentDigest,
    /// Operation closed by this episode.
    pub operation_id: OperationId,
    /// Typed retained terminal outcome. Withdrawal alone cannot prove cancellation in v1.
    pub outcome: MissionEpisodeOutcome,
}

/// Bounded complete native inventory witness for owned session work and shared mission cases.
/// No zero is inferred from a missing, partial or unauthorized inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionClosureFacts {
    /// Exact scoped inventory digest, including the counts and every admitted item identity.
    pub witness_digest: ContentDigest,
    /// Other owned plans not safely closed.
    pub unsettled_plans: u32,
    /// Same-principal mission investigations that remain active, including shared-session cases.
    pub active_cases: u32,
    /// Owned work claims that remain active.
    pub active_claims: u32,
    /// Owned supervision with a pending report, reservation or active schedule.
    pub active_supervisions: u32,
}

impl MissionClosureFacts {
    /// All owned work is closed according to a complete, verified native inventory.
    pub const fn is_clear(&self) -> bool {
        self.unsettled_plans == 0
            && self.active_cases == 0
            && self.active_claims == 0
            && self.active_supervisions == 0
    }
}

/// Current custody facts; callers cannot request a lifecycle state or supply a success boolean.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionAssessmentFacts {
    /// Exact authoritative evidence snapshot evaluated by the native owner.
    pub anchor: LedgerAnchor,
    /// Runtime-owned evidence clock, not an agent-selected time.
    pub evidence_time: TimestampNs,
    /// Distinguishes an absent effect journal from a present empty journal.
    pub effect_journal_present: bool,
    /// Exact durable effect-journal prefix root, zero only for an empty journal.
    pub effect_journal_root: ContentDigest,
    /// Complete committed effect record count at the same native snapshot.
    pub effect_record_count: u64,
    /// Current retained revision of the selected event; None is unresolved, never absence proof.
    pub event_revision: Option<ContentDigest>,
    /// Exact operation if present in the complete effect snapshot.
    pub operation: Option<MissionOperationFacts>,
    /// Exact associated obligation if present.
    pub obligation: Option<MissionObligationFacts>,
    /// Exact closed episode if present and all immutable links verify.
    pub episode: Option<MissionEpisodeFacts>,
    /// Complete scope-bound inventory of other owned work.
    pub closure: MissionClosureFacts,
}

impl MissionAssessmentFacts {
    /// Validate complete bounded native facts against the immutable execution target.
    pub fn validate(&self, criterion: &MissionPlanCriterion) -> Result<()> {
        if !valid_anchor(&self.anchor)
            || self.evidence_time.0 < 0
            || self.effect_journal_root.algorithm() != DigestAlgorithm::Sha256
            || self.effect_journal_root.is_laboratory()
            || self.effect_record_count > 1_000_000
            || (!self.effect_journal_present && self.effect_record_count != 0)
            || (self.effect_record_count > 0 && !sha(self.effect_journal_root))
            || (self.effect_record_count == 0 && self.effect_journal_root.bytes() != [0; 32])
            || self.event_revision.is_some_and(|value| !sha(value))
            || !sha(self.closure.witness_digest)
            || [
                self.closure.unsettled_plans,
                self.closure.active_cases,
                self.closure.active_claims,
                self.closure.active_supervisions,
            ]
            .into_iter()
            .any(|count| count > MAX_CLOSURE_ITEMS)
        {
            return Err(MissionError::InvalidRequest);
        }
        if let Some(operation) = &self.operation {
            if operation.operation_id != criterion.operation_id {
                return Err(MissionError::ScopeMismatch);
            }
            if !sha(operation.receipt_digest)
                || operation.result_digest.is_some_and(|value| !sha(value))
                || self.effect_record_count == 0
            {
                return Err(MissionError::InvalidRequest);
            }
        }
        if let Some(obligation) = &self.obligation {
            if obligation.operation_id != criterion.operation_id
                || obligation.obligation_id != criterion.obligation_id
            {
                return Err(MissionError::ScopeMismatch);
            }
            if obligation.proof_digest.is_some_and(|value| !sha(value))
                || self.effect_record_count == 0
            {
                return Err(MissionError::InvalidRequest);
            }
        }
        if let Some(episode) = &self.episode {
            if episode.operation_id != criterion.operation_id
                || episode.plan_record_digest != criterion.plan_record_digest
                || episode.control_plan_digest != criterion.control_plan_digest
            {
                return Err(MissionError::ScopeMismatch);
            }
            if !identifier(&episode.episode_id)
                || ![
                    episode.record_digest,
                    episode.publication_root,
                    episode.plan_record_digest,
                    episode.control_plan_digest,
                ]
                .into_iter()
                .all(sha)
            {
                return Err(MissionError::InvalidRequest);
            }
        }
        Ok(())
    }

    pub(crate) fn encode(&self, e: &mut CanonicalEncoder) {
        self.anchor.encode_canonical(e);
        e.i128(self.evidence_time.0);
        e.bool(self.effect_journal_present);
        e.digest(self.effect_journal_root);
        e.u64(self.effect_record_count);
        optional_digest(e, self.event_revision);
        e.bool(self.operation.is_some());
        if let Some(value) = &self.operation {
            value.operation_id.encode_canonical(e);
            e.text(value.state.as_str());
            e.bool(value.dispatched);
            e.digest(value.receipt_digest);
            optional_digest(e, value.result_digest);
        }
        e.bool(self.obligation.is_some());
        if let Some(value) = &self.obligation {
            value.obligation_id.encode_canonical(e);
            value.operation_id.encode_canonical(e);
            e.text(value.state.as_str());
            optional_digest(e, value.proof_digest);
        }
        e.bool(self.episode.is_some());
        if let Some(value) = &self.episode {
            e.text(&value.episode_id);
            e.digest(value.record_digest);
            e.digest(value.publication_root);
            e.digest(value.plan_record_digest);
            e.digest(value.control_plan_digest);
            value.operation_id.encode_canonical(e);
            e.text(value.outcome.as_str());
        }
        e.digest(self.closure.witness_digest);
        e.u32(self.closure.unsettled_plans);
        e.u32(self.closure.active_cases);
        e.u32(self.closure.active_claims);
        e.u32(self.closure.active_supervisions);
    }

    pub(crate) fn decode(d: &mut CanonicalDecoder<'_>) -> std::result::Result<Self, ContractError> {
        let anchor = LedgerAnchor::decode_canonical(d)?;
        let evidence_time = TimestampNs(d.i128()?);
        let effect_journal_present = d.bool()?;
        let effect_journal_root = d.digest()?;
        let effect_record_count = d.u64()?;
        let event_revision = decode_optional_digest(d)?;
        let operation = if d.bool()? {
            Some(MissionOperationFacts {
                operation_id: OperationId::parse(text(d)?)?,
                state: MissionOperationState::parse(d.text()?)
                    .map_err(|_| ContractError::EvidenceRequired)?,
                dispatched: d.bool()?,
                receipt_digest: d.digest()?,
                result_digest: decode_optional_digest(d)?,
            })
        } else {
            None
        };
        let obligation = if d.bool()? {
            Some(MissionObligationFacts {
                obligation_id: ObligationId::parse(text(d)?)?,
                operation_id: OperationId::parse(text(d)?)?,
                state: MissionObligationState::parse(d.text()?)
                    .map_err(|_| ContractError::EvidenceRequired)?,
                proof_digest: decode_optional_digest(d)?,
            })
        } else {
            None
        };
        let episode = if d.bool()? {
            Some(MissionEpisodeFacts {
                episode_id: text(d)?,
                record_digest: d.digest()?,
                publication_root: d.digest()?,
                plan_record_digest: d.digest()?,
                control_plan_digest: d.digest()?,
                operation_id: OperationId::parse(text(d)?)?,
                outcome: MissionEpisodeOutcome::parse(d.text()?)
                    .map_err(|_| ContractError::EvidenceRequired)?,
            })
        } else {
            None
        };
        let closure = MissionClosureFacts {
            witness_digest: d.digest()?,
            unsettled_plans: d.u32()?,
            active_cases: d.u32()?,
            active_claims: d.u32()?,
            active_supervisions: d.u32()?,
        };
        Ok(Self {
            anchor,
            evidence_time,
            effect_journal_present,
            effect_journal_root,
            effect_record_count,
            event_revision,
            operation,
            obligation,
            episode,
            closure,
        })
    }
}

/// Immutable, canonically encoded lifecycle revision. Terminal evaluations remain as-of their
/// exact source snapshot; later drift cannot silently rewrite them or restart their effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionRevision {
    criterion: MissionPlanCriterion,
    revision: u64,
    parent: Option<ContentDigest>,
    state: MissionLifecycleState,
    assessment: Option<MissionAssessmentFacts>,
    recorded_at: TimestampNs,
    bytes: Vec<u8>,
    digest: ContentDigest,
}

impl MissionRevision {
    /// Immutable profile and original custody targets.
    pub const fn criterion(&self) -> &MissionPlanCriterion {
        &self.criterion
    }
    /// Zero-based monotone history position.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    /// Complete canonical revision digest.
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Exact predecessor; None only at enrollment.
    pub const fn parent_digest(&self) -> Option<ContentDigest> {
        self.parent
    }
    /// Lifecycle derived from this revision's exact facts.
    pub const fn state(&self) -> MissionLifecycleState {
        self.state
    }
    /// Retained assessment facts, absent at enrollment.
    pub const fn assessment(&self) -> Option<&MissionAssessmentFacts> {
        self.assessment.as_ref()
    }
    /// Runtime-owned evidence clock captured in this revision.
    pub const fn recorded_at(&self) -> TimestampNs {
        self.recorded_at
    }
    /// Deadline pressure is orthogonal to terminal proof and never cancels an effect.
    pub fn deadline_reached(&self) -> bool {
        self.recorded_at >= self.criterion.decision_deadline
    }
    /// Complete immutable private encoding, suitable for protected handoff custody.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Exact retained roots; these do not grant evidence hydration or effect authority.
    pub fn proof_roots(&self) -> Vec<ContentDigest> {
        let c = &self.criterion;
        let mut roots = BTreeSet::from([
            self.digest,
            c.digest(),
            c.mission_record_digest,
            c.plan_record_digest,
            c.plan_root,
            c.control_plan_digest,
            c.event_revision,
        ]);
        if let Some(f) = &self.assessment {
            roots.insert(f.anchor.state_root);
            roots.insert(f.closure.witness_digest);
            if sha(f.effect_journal_root) {
                roots.insert(f.effect_journal_root);
            }
            roots.extend(f.event_revision);
            if let Some(value) = &f.operation {
                roots.insert(value.receipt_digest);
                roots.extend(value.result_digest);
            }
            if let Some(value) = &f.obligation {
                roots.extend(value.proof_digest);
            }
            if let Some(value) = &f.episode {
                roots.insert(value.record_digest);
                roots.insert(value.publication_root);
            }
        }
        roots.into_iter().collect()
    }

    fn new(
        criterion: MissionPlanCriterion,
        revision: u64,
        parent: Option<ContentDigest>,
        assessment: Option<MissionAssessmentFacts>,
        recorded_at: TimestampNs,
    ) -> Result<Self> {
        criterion.validate()?;
        let state = match &assessment {
            None => MissionLifecycleState::AwaitingEvidence,
            Some(facts) => evaluate(&criterion, facts)?,
        };
        let mut e = CanonicalEncoder::new();
        e.text(REVISION_DOMAIN);
        criterion.encode(&mut e);
        e.u64(revision);
        optional_digest(&mut e, parent);
        e.text(state.as_str());
        e.i128(recorded_at.0);
        e.bool(assessment.is_some());
        if let Some(facts) = &assessment {
            facts.encode(&mut e);
        }
        let bytes = e
            .finish_checked()
            .map_err(|_| MissionError::InvalidRequest)?;
        if bytes.len() > MAX_MISSION_RECORD_BYTES {
            return Err(MissionError::CapacityExceeded);
        }
        let digest = ContentDigest::sha256(&bytes);
        Ok(Self {
            criterion,
            revision,
            parent,
            state,
            assessment,
            recorded_at,
            bytes,
            digest,
        })
    }
}

fn evaluate(c: &MissionPlanCriterion, f: &MissionAssessmentFacts) -> Result<MissionLifecycleState> {
    f.validate(c)?;
    use MissionLifecycleState as State;
    if f.operation
        .as_ref()
        .is_some_and(|o| o.state == MissionOperationState::Indeterminate)
        || f.obligation
            .as_ref()
            .is_some_and(|o| o.state == MissionObligationState::Indeterminate)
    {
        return Ok(State::Reconciling);
    }
    if !same_generations(&c.baseline_anchor, &f.anchor)
        || f.anchor.commit_sequence < c.baseline_anchor.commit_sequence
        || (f.anchor.commit_sequence == c.baseline_anchor.commit_sequence
            && f.anchor.state_root != c.baseline_anchor.state_root)
        || f.event_revision != Some(c.event_revision)
    {
        return Ok(State::AwaitingEvidence);
    }
    let Some(operation) = &f.operation else {
        return Ok(State::AwaitingEvidence);
    };
    if matches!(
        operation.state,
        MissionOperationState::Committed
            | MissionOperationState::AdapterAccepted
            | MissionOperationState::Observed
    ) {
        return Ok(State::Executing);
    }
    let (Some(obligation), Some(episode)) = (&f.obligation, &f.episode) else {
        return Ok(State::AwaitingEvidence);
    };
    if !f.closure.is_clear()
        || obligation.proof_digest.is_none()
        || obligation.proof_digest != operation.result_digest
    {
        return Ok(State::AwaitingEvidence);
    }
    Ok(match (operation.state, obligation.state, episode.outcome) {
        (
            MissionOperationState::Verified,
            MissionObligationState::Verified,
            MissionEpisodeOutcome::Verified,
        ) if operation.dispatched => State::Resolved,
        (
            MissionOperationState::Failed,
            MissionObligationState::Failed,
            MissionEpisodeOutcome::Failed,
        ) => State::Failed,
        (
            MissionOperationState::Cancelled,
            MissionObligationState::Cancelled,
            MissionEpisodeOutcome::Cancelled,
        ) if !operation.dispatched => State::Cancelled,
        _ => State::AwaitingEvidence,
    })
}

type MissionKey = (PrincipalId, SessionId, ContentDigest);

/// Bounded deterministic reference owner. Native custody verification is an explicit prerequisite.
#[derive(Clone, Debug, Default)]
pub struct ReferenceMissionStore {
    histories: BTreeMap<MissionKey, Vec<MissionRevision>>,
}

impl ReferenceMissionStore {
    /// Enroll exactly one immutable profile, or return its current head on an exact retry.
    pub fn register(
        &mut self,
        memory: &mut ReferenceSessionStore,
        principal: &PrincipalId,
        criterion: MissionPlanCriterion,
        now: TimestampNs,
    ) -> Result<MissionRevision> {
        let (session, basis) = admit(memory, principal, &criterion.session_id, now)?;
        criterion.validate()?;
        if criterion.principal != *principal
            || criterion.mission_id != session.mission_id
            || criterion.contract_basis != basis
        {
            return Err(MissionError::ScopeMismatch);
        }
        let key = (
            principal.clone(),
            criterion.session_id.clone(),
            criterion.mission_record_digest,
        );
        if let Some(history) = self.histories.get(&key) {
            let head = history.last().ok_or(MissionError::InvalidRequest)?;
            if head.criterion != criterion {
                return Err(MissionError::Conflict);
            }
            return Ok(head.clone());
        }
        if criterion.baseline_anchor != session.current_anchor || criterion.decision_deadline <= now
        {
            return Err(MissionError::ScopeMismatch);
        }
        if self.histories.len() >= MAX_MISSIONS
            || self.revision_count() >= MAX_MISSION_HISTORY_REVISIONS
        {
            return Err(MissionError::CapacityExceeded);
        }
        let revision = MissionRevision::new(criterion, 0, None, None, now)?;
        self.histories.insert(key, vec![revision.clone()]);
        Ok(revision)
    }

    /// Derive one immutable revision under exact predecessor CAS. Replaying an already committed
    /// request returns that exact revision without rewinding a later head or spending new quota.
    #[allow(clippy::too_many_arguments)] // Keep authority, CAS and runtime time separate from facts.
    pub fn assess(
        &mut self,
        memory: &mut ReferenceSessionStore,
        principal: &PrincipalId,
        session: &SessionId,
        mission_record_digest: ContentDigest,
        expected_head: ContentDigest,
        facts: MissionAssessmentFacts,
        now: TimestampNs,
    ) -> Result<MissionRevision> {
        let (live, basis) = admit(memory, principal, session, now)?;
        let count = self.revision_count();
        let key = (principal.clone(), session.clone(), mission_record_digest);
        let history = self.histories.get_mut(&key).ok_or(MissionError::Conflict)?;
        let head = history.last().ok_or(MissionError::InvalidRequest)?;
        if head.criterion.contract_basis != basis
            || head.criterion.mission_id != live.mission_id
            || facts.evidence_time != now
            || facts.anchor.site_lineage != live.current_anchor.site_lineage
            || facts.anchor.ledger_epoch != live.current_anchor.ledger_epoch
            || facts.anchor.commit_sequence < live.current_anchor.commit_sequence
            || (facts.anchor.commit_sequence == live.current_anchor.commit_sequence
                && facts.anchor.state_root != live.current_anchor.state_root)
        {
            return Err(MissionError::ScopeMismatch);
        }
        facts.validate(&head.criterion)?;
        if let Some(existing) = history.iter().find(|revision| {
            revision.assessment.as_ref() == Some(&facts)
                && (revision.parent == Some(expected_head) || revision.digest == expected_head)
        }) {
            return Ok(existing.clone());
        }
        // A source prefix already observed by this owner is an independent custody pin. A
        // shorter or replaced valid journal cannot masquerade as fresh missing evidence.
        // Exact retained retries above still return their immutable historical result.
        if let Some(previous) = &head.assessment {
            if facts.anchor.site_lineage != previous.anchor.site_lineage
                || facts.anchor.ledger_epoch != previous.anchor.ledger_epoch
                || facts.anchor.commit_sequence < previous.anchor.commit_sequence
                || (facts.anchor.commit_sequence == previous.anchor.commit_sequence
                    && facts.anchor.state_root != previous.anchor.state_root)
                || (previous.effect_journal_present && !facts.effect_journal_present)
                || facts.effect_record_count < previous.effect_record_count
                || (facts.effect_record_count == previous.effect_record_count
                    && facts.effect_journal_root != previous.effect_journal_root)
            {
                return Err(MissionError::ScopeMismatch);
            }
        }
        if head.digest != expected_head {
            return Err(MissionError::Conflict);
        }
        if head.state.is_terminal() {
            return Err(MissionError::Terminal);
        }
        if history.len() >= MAX_MISSION_REVISIONS || count >= MAX_MISSION_HISTORY_REVISIONS {
            return Err(MissionError::CapacityExceeded);
        }
        let revision = MissionRevision::new(
            head.criterion.clone(),
            head.revision + 1,
            Some(head.digest),
            Some(facts),
            now,
        )?;
        history.push(revision.clone());
        Ok(revision)
    }

    /// Current admitted lifecycle; None means no enrolled executable profile, not success.
    pub fn head(
        &self,
        memory: &mut ReferenceSessionStore,
        principal: &PrincipalId,
        session: &SessionId,
        mission_record_digest: ContentDigest,
        now: TimestampNs,
    ) -> Result<Option<MissionRevision>> {
        Ok(self
            .history(memory, principal, session, mission_record_digest, now)?
            .pop())
    }

    /// Complete bounded immutable history after live admission; no hidden record is exposed first.
    pub fn history(
        &self,
        memory: &mut ReferenceSessionStore,
        principal: &PrincipalId,
        session: &SessionId,
        mission_record_digest: ContentDigest,
        now: TimestampNs,
    ) -> Result<Vec<MissionRevision>> {
        let (live, basis) = admit_read(memory, principal, session, now)?;
        if !sha(mission_record_digest) {
            return Err(MissionError::InvalidRequest);
        }
        let Some(history) =
            self.histories
                .get(&(principal.clone(), session.clone(), mission_record_digest))
        else {
            return Ok(Vec::new());
        };
        let head = history.last().ok_or(MissionError::InvalidRequest)?;
        if head.criterion.contract_basis != basis || head.criterion.mission_id != live.mission_id {
            return Err(MissionError::ScopeMismatch);
        }
        Ok(history.clone())
    }

    pub(crate) fn retained(&self) -> Vec<MissionRevision> {
        self.histories.values().flatten().cloned().collect()
    }
    fn revision_count(&self) -> usize {
        self.histories.values().map(Vec::len).sum()
    }
    pub(crate) fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(STATE_DOMAIN);
        e.u64(self.histories.len() as u64);
        for history in self.histories.values() {
            e.u64(history.len() as u64);
            for revision in history {
                e.digest(revision.digest);
            }
        }
        ContentDigest::sha256(&e.finish())
    }
}

pub(crate) fn admit(
    memory: &mut ReferenceSessionStore,
    principal: &PrincipalId,
    session: &SessionId,
    now: TimestampNs,
) -> Result<(fss_core::AgentSession, ContractBasis)> {
    let entry = memory.live_entry(principal, session, now)?;
    if ![
        "CAP-AGENT-SESSION-READ-001",
        "CAP-AGENT-SESSION-WRITE-001",
        "CAP-AGENT-SITUATION-READ-001",
        "CAP-AGENT-PLAN-PREPARE-001",
    ]
    .iter()
    .all(|grant| entry.session.capabilities.contains(*grant))
        || !entry.session.privacy_scope.contains("private:property")
    {
        return Err(MissionError::Unauthorized);
    }
    Ok((entry.session.clone(), entry.basis.clone()))
}

/// Reading retained progress never requires permission to enroll or assess a mission.
pub(crate) fn admit_read(
    memory: &mut ReferenceSessionStore,
    principal: &PrincipalId,
    session: &SessionId,
    now: TimestampNs,
) -> Result<(fss_core::AgentSession, ContractBasis)> {
    let entry = memory.live_entry(principal, session, now)?;
    if !["CAP-AGENT-SESSION-READ-001", "CAP-AGENT-SITUATION-READ-001"]
        .iter()
        .all(|grant| entry.session.capabilities.contains(*grant))
        || !entry.session.privacy_scope.contains("private:property")
    {
        return Err(MissionError::Unauthorized);
    }
    Ok((entry.session.clone(), entry.basis.clone()))
}

pub(crate) fn optional_digest(e: &mut CanonicalEncoder, value: Option<ContentDigest>) {
    e.bool(value.is_some());
    if let Some(value) = value {
        e.digest(value);
    }
}
pub(crate) fn decode_optional_digest(
    d: &mut CanonicalDecoder<'_>,
) -> std::result::Result<Option<ContentDigest>, ContractError> {
    Ok(if d.bool()? { Some(d.digest()?) } else { None })
}
pub(crate) fn text(d: &mut CanonicalDecoder<'_>) -> std::result::Result<String, ContractError> {
    let value = d.text()?;
    if value.len() > MAX_ID_BYTES {
        return Err(ContractError::CountBoundExceeded);
    }
    Ok(value.to_owned())
}
