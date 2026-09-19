//! Registered `fss/1` agent operations (AOP-001..AOP-014).
//!
//! Normative sources (truth hierarchy, highest tier first):
//! - `architecture/agent_operations.json` (`fss.agent_operations.v1`): the dedicated
//!   machine registry owning the executable/public operation surface.
//! - `architecture/fss1_public_registry.json` (`gen:fss1:public-v1`): the frozen public
//!   operation registry pinned by `REFERENCE_OPERATION_REGISTRY_DIGEST`.
//! - `registries/AGENT_OPERATIONS.md` and `registries/AGENT_CONTRACTS.md`: human mirrors;
//!   `AOP-###` remains one stable identity across both (cross-registry reconciliation).
//!
//! Every listed registry field is queryable as a typed accessor. The canonical encoding
//! covers every field except the prose `purpose` (descriptive metadata pinned by the
//! registry mirrors and the `agent_operation_registry_checker`, never decision-bearing
//! on its own). The canonical text row format is:
//!
//! ```text
//! id|name|mode|owner|defaultView|requestPayload|responsePayloads[;...]|inputSchema|outputSchema|effectful|durable|gate|capabilities[;...]|retryClasses[;...]
//! ```
//!
//! lists join on `;`, booleans spell `0`/`1`, and no field may contain `|`, `;`, or a
//! newline. Any tampered field fails closed: canonical decode reconstructs the row and
//! must match a registered row exactly.
//!
//! Effect authority is typed at the mode level: only `effect_commit` and
//! `lifecycle_effect` rows are effectful; only read/compute rows may refine the
//! possibility envelope (`worldEnvelopeRule`); `commit` is the sole operation that
//! starts a prepared plan's effects.

use crate::agent::{
    ActionAffordance, AffordanceClass, ContractBasis, HandoffCapsule, HandoffPublishParams,
    ReconciliationBasis, SituationCapsule,
};
use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::continuation::{ContinuationCursor, ContinuationError, ContinuationScope};
use crate::contract::ContractError;
use crate::contract_basis::{ContractBasisError, registered_operation};
use crate::digest::ContentDigest;
use crate::evidence::LedgerAnchor;
use crate::{
    BudgetVector, Completeness, HypothesisDisposition, MissionId, PrincipalId, RuntimeOutcome,
    SessionId, TimestampNs,
};
use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

/// Number of registered operations (`AOP-001`..`AOP-014`).
pub const REGISTERED_OPERATION_COUNT: usize = 14;

/// Canonical digest domain of one registered operation row.
pub const OPERATION_ROW_DIGEST_DOMAIN: &str = "fss.agent.operation.row.v1";

/// Frozen public-registry generation pinning the reference operation registry digest.
pub const OPERATION_REGISTRY_GENERATION: &str = "gen:fss1:public-v1";

/// Qualification gate shared by every registered operation row.
pub const REGISTERED_OPERATION_GATE: &str = "QL-AGENT-001";

/// How an operation interacts with the planes it touches.
///
/// Derived verbatim from the `mode` column of `architecture/agent_operations.json`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OperationMode {
    /// Establish, restore, or terminate a session and its contract basis.
    SessionControl,
    /// Bounded read that publishes no durable artifact by itself.
    Read,
    /// Bounded read that parks on a wake contract until a predicate or deadline fires.
    ReadWait,
    /// Compile a bounded read plan and execute it over one anchor.
    ReadCompile,
    /// Read plus derived computation over retained evidence.
    ReadCompute,
    /// Durable write inside the cognition plane (cases, hypotheses, work claims).
    CognitionWrite,
    /// Compile an immutable witnessed contingent plan without crossing the effect boundary.
    PlanPrepare,
    /// Revalidate and start the exact prepared plan under effect obligations.
    EffectCommit,
    /// Request, drain, reconcile or compensate, and finalize owned work.
    LifecycleEffect,
    /// Publish a root-last portable continuity capsule.
    ContinuityPublish,
    /// Append evidence-linked corrections or learning proposals without silent activation.
    AdvisoryWrite,
    /// Diagnose consistency and produce sealed repair affordances.
    DiagnosticPrepare,
}

impl OperationMode {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionControl => "session_control",
            Self::Read => "read",
            Self::ReadWait => "read_wait",
            Self::ReadCompile => "read_compile",
            Self::ReadCompute => "read_compute",
            Self::CognitionWrite => "cognition_write",
            Self::PlanPrepare => "plan_prepare",
            Self::EffectCommit => "effect_commit",
            Self::LifecycleEffect => "lifecycle_effect",
            Self::ContinuityPublish => "continuity_publish",
            Self::AdvisoryWrite => "advisory_write",
            Self::DiagnosticPrepare => "diagnostic_prepare",
        }
    }

    /// Parses a mode from its stable registry spelling.
    pub fn from_name(name: &str) -> Result<Self, ContractError> {
        match name {
            "session_control" => Ok(Self::SessionControl),
            "read" => Ok(Self::Read),
            "read_wait" => Ok(Self::ReadWait),
            "read_compile" => Ok(Self::ReadCompile),
            "read_compute" => Ok(Self::ReadCompute),
            "cognition_write" => Ok(Self::CognitionWrite),
            "plan_prepare" => Ok(Self::PlanPrepare),
            "effect_commit" => Ok(Self::EffectCommit),
            "lifecycle_effect" => Ok(Self::LifecycleEffect),
            "continuity_publish" => Ok(Self::ContinuityPublish),
            "advisory_write" => Ok(Self::AdvisoryWrite),
            "diagnostic_prepare" => Ok(Self::DiagnosticPrepare),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }

    /// Returns whether this mode mutates the effect plane.
    ///
    /// Only `effect_commit` and `lifecycle_effect` rows may be effectful; every other
    /// mode is refused with [`ContractError::OperationEffectModeMismatch`] when paired
    /// with `effectful = true`.
    #[must_use]
    pub const fn affects_effect_plane(self) -> bool {
        matches!(self, Self::EffectCommit | Self::LifecycleEffect)
    }

    /// Returns whether operations of this mode may refine the possibility envelope.
    ///
    /// Registry `worldEnvelopeRule`: "read/compute operations may refine the possibility
    /// envelope; effect operations consume only affordances whose robustness class and
    /// named-world basis remain valid at commit."
    #[must_use]
    pub const fn refines_possibility_envelope(self) -> bool {
        matches!(
            self,
            Self::Read | Self::ReadWait | Self::ReadCompile | Self::ReadCompute
        )
    }

    /// Returns whether operations of this mode consume effect affordances at commit.
    #[must_use]
    pub const fn consumes_effect_affordances(self) -> bool {
        matches!(self, Self::EffectCommit)
    }

    /// Returns whether operations of this mode publish durable artifacts.
    ///
    /// Pure reads, compiled reads, and read-compute rows are non-durable
    /// (`AOP-003`, `AOP-005`, `AOP-011`); every other registered row is durable.
    #[must_use]
    pub const fn requires_durability(self) -> bool {
        !matches!(self, Self::Read | Self::ReadCompile | Self::ReadCompute)
    }

    /// Returns the canonical 1-based wire byte tag (registry row order of distinct modes).
    #[must_use]
    pub const fn to_code(self) -> u8 {
        match self {
            Self::SessionControl => 1,
            Self::Read => 2,
            Self::ReadWait => 3,
            Self::ReadCompile => 4,
            Self::ReadCompute => 5,
            Self::CognitionWrite => 6,
            Self::PlanPrepare => 7,
            Self::EffectCommit => 8,
            Self::LifecycleEffect => 9,
            Self::ContinuityPublish => 10,
            Self::AdvisoryWrite => 11,
            Self::DiagnosticPrepare => 12,
        }
    }

    /// Decodes a mode from its canonical 1-based wire byte tag.
    pub const fn from_code(code: u8) -> Result<Self, ContractError> {
        match code {
            1 => Ok(Self::SessionControl),
            2 => Ok(Self::Read),
            3 => Ok(Self::ReadWait),
            4 => Ok(Self::ReadCompile),
            5 => Ok(Self::ReadCompute),
            6 => Ok(Self::CognitionWrite),
            7 => Ok(Self::PlanPrepare),
            8 => Ok(Self::EffectCommit),
            9 => Ok(Self::LifecycleEffect),
            10 => Ok(Self::ContinuityPublish),
            11 => Ok(Self::AdvisoryWrite),
            12 => Ok(Self::DiagnosticPrepare),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl CanonicalEncode for OperationMode {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for OperationMode {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        Self::from_name(decoder.text()?)
    }
}

impl fmt::Display for OperationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Registered retry class of an operation row.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OperationRetryClass {
    /// Retrying unchanged is never safe (effects, session negotiation).
    NeverUnchanged,
    /// Bounded backoff retry is safe.
    Backoff,
    /// Only an operator action can unblock the attempt.
    OperatorActionRequired,
    /// Resume from the recorded continuation instead of restarting.
    ResumeFromContinuation,
    /// Idempotent read retry is safe.
    SafeReadRetry,
    /// Refresh stale inputs and retry.
    RefreshAndRetry,
    /// Rebase onto the current anchor before retrying.
    RebaseRequired,
    /// Reconcile or compensate the indeterminate outcome before retrying.
    ReconciliationRequired,
}

impl OperationRetryClass {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NeverUnchanged => "never_unchanged",
            Self::Backoff => "backoff",
            Self::OperatorActionRequired => "operator_action_required",
            Self::ResumeFromContinuation => "resume_from_continuation",
            Self::SafeReadRetry => "safe_read_retry",
            Self::RefreshAndRetry => "refresh_and_retry",
            Self::RebaseRequired => "rebase_required",
            Self::ReconciliationRequired => "reconciliation_required",
        }
    }

    /// Parses a retry class from its stable registry spelling.
    pub fn from_name(name: &str) -> Result<Self, ContractError> {
        match name {
            "never_unchanged" => Ok(Self::NeverUnchanged),
            "backoff" => Ok(Self::Backoff),
            "operator_action_required" => Ok(Self::OperatorActionRequired),
            "resume_from_continuation" => Ok(Self::ResumeFromContinuation),
            "safe_read_retry" => Ok(Self::SafeReadRetry),
            "refresh_and_retry" => Ok(Self::RefreshAndRetry),
            "rebase_required" => Ok(Self::RebaseRequired),
            "reconciliation_required" => Ok(Self::ReconciliationRequired),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

impl CanonicalEncode for OperationRetryClass {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.as_str());
    }
}

impl CanonicalDecode for OperationRetryClass {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        OperationRetryClass::from_name(decoder.text()?)
    }
}

/// A registered `fss/1` operation row (`AOP-001`..`AOP-014`).
///
/// Variant order is the registry row order and the canonical ordering.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AgentOperation {
    /// `AOP-001` `session.open`: negotiate principal, mission, authority, privacy
    /// projection, budgets, views, and the initial SituationCapsule.
    SessionOpen,
    /// `AOP-002` `session.resume`: restore an explicit workspace/handoff root, compare it
    /// with current state, and enumerate stale or invalidated assumptions.
    SessionResume,
    /// `AOP-003` `session.orient`: return the smallest sufficient current SituationCapsule
    /// for the mission, authority, and budget.
    SessionOrient,
    /// `AOP-004` `session.follow`: stream meaningful deltas and obligation progress from
    /// an exact continuation cursor.
    SessionFollow,
    /// `AOP-005` `query`: execute a bounded typed or natural-language-compiled read over
    /// one anchor with completeness and cost receipts.
    Query,
    /// `AOP-006` `investigate`: create or advance a durable case with competing
    /// hypotheses, evidence tasks, work claims, discriminators, and stop rules.
    Investigate,
    /// `AOP-007` `plan`: compile a desired outcome or information objective into an
    /// immutable witnessed contingent plan without crossing the effect boundary.
    Plan,
    /// `AOP-008` `commit`: revalidate and start the exact prepared plan under idempotency,
    /// leases, fencing, approval, and terminal-proof obligations.
    Commit,
    /// `AOP-009` `wait`: observe cases, plans, effects, transfers, and obligations until a
    /// predicate, deadline, or meaningful delta fires.
    Wait,
    /// `AOP-010` `cancel`: request, drain, reconcile or compensate, and finalize owned
    /// work without erasing its durable record.
    Cancel,
    /// `AOP-011` `explain`: answer why, why-not, what-changed, or what-if with a minimal
    /// evidence/decision subgraph and expansion handles.
    Explain,
    /// `AOP-012` `handoff`: publish a root-last portable capsule containing mission,
    /// workspace, cases, plans, obligations, budgets, authority, uncertainty, and
    /// continuations.
    Handoff,
    /// `AOP-013` `feedback`: record a correction, outcome signal, adjudication, or
    /// evidence-linked learning proposal without silently changing active truth or policy.
    Feedback,
    /// `AOP-014` `doctor`: diagnose deployment, evidence, cognition, workspace, cases,
    /// obligations, and protocol consistency and produce sealed repair affordances.
    Doctor,
}

/// Required capability slice type for row accessors.
pub type CapabilityList = &'static [&'static str];

/// Response payload schema slice type for row accessors.
pub type ResponseSchemaList = &'static [&'static str];

/// Retry class slice type for row accessors.
pub type RetryClassList = &'static [OperationRetryClass];

impl AgentOperation {
    /// Registry schema identity of the dedicated operation registry.
    pub const SCHEMA_AGENT_OPERATIONS: &str = "fss.agent_operations.v1";

    /// Every registered operation in canonical registry order.
    pub const ALL_OPERATIONS: [AgentOperation; REGISTERED_OPERATION_COUNT] = [
        Self::SessionOpen,
        Self::SessionResume,
        Self::SessionOrient,
        Self::SessionFollow,
        Self::Query,
        Self::Investigate,
        Self::Plan,
        Self::Commit,
        Self::Wait,
        Self::Cancel,
        Self::Explain,
        Self::Handoff,
        Self::Feedback,
        Self::Doctor,
    ];

    /// Returns the stable registry row ID (`AOP-001`..`AOP-014`).
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::SessionOpen => "AOP-001",
            Self::SessionResume => "AOP-002",
            Self::SessionOrient => "AOP-003",
            Self::SessionFollow => "AOP-004",
            Self::Query => "AOP-005",
            Self::Investigate => "AOP-006",
            Self::Plan => "AOP-007",
            Self::Commit => "AOP-008",
            Self::Wait => "AOP-009",
            Self::Cancel => "AOP-010",
            Self::Explain => "AOP-011",
            Self::Handoff => "AOP-012",
            Self::Feedback => "AOP-013",
            Self::Doctor => "AOP-014",
        }
    }

    /// Returns the stable canonical operation name (`session.open`, ...).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SessionOpen => "session.open",
            Self::SessionResume => "session.resume",
            Self::SessionOrient => "session.orient",
            Self::SessionFollow => "session.follow",
            Self::Query => "query",
            Self::Investigate => "investigate",
            Self::Plan => "plan",
            Self::Commit => "commit",
            Self::Wait => "wait",
            Self::Cancel => "cancel",
            Self::Explain => "explain",
            Self::Handoff => "handoff",
            Self::Feedback => "feedback",
            Self::Doctor => "doctor",
        }
    }

    /// Parses an operation from its stable row ID (`AOP-001`..`AOP-014`).
    pub fn from_id(id: &str) -> Result<Self, ContractError> {
        match id {
            "AOP-001" => Ok(Self::SessionOpen),
            "AOP-002" => Ok(Self::SessionResume),
            "AOP-003" => Ok(Self::SessionOrient),
            "AOP-004" => Ok(Self::SessionFollow),
            "AOP-005" => Ok(Self::Query),
            "AOP-006" => Ok(Self::Investigate),
            "AOP-007" => Ok(Self::Plan),
            "AOP-008" => Ok(Self::Commit),
            "AOP-009" => Ok(Self::Wait),
            "AOP-010" => Ok(Self::Cancel),
            "AOP-011" => Ok(Self::Explain),
            "AOP-012" => Ok(Self::Handoff),
            "AOP-013" => Ok(Self::Feedback),
            "AOP-014" => Ok(Self::Doctor),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }

    /// Parses an operation from its stable canonical name (`session.open`, ...).
    pub fn from_name(name: &str) -> Result<Self, ContractError> {
        match name {
            "session.open" => Ok(Self::SessionOpen),
            "session.resume" => Ok(Self::SessionResume),
            "session.orient" => Ok(Self::SessionOrient),
            "session.follow" => Ok(Self::SessionFollow),
            "query" => Ok(Self::Query),
            "investigate" => Ok(Self::Investigate),
            "plan" => Ok(Self::Plan),
            "commit" => Ok(Self::Commit),
            "wait" => Ok(Self::Wait),
            "cancel" => Ok(Self::Cancel),
            "explain" => Ok(Self::Explain),
            "handoff" => Ok(Self::Handoff),
            "feedback" => Ok(Self::Feedback),
            "doctor" => Ok(Self::Doctor),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }

    /// Returns the owning subsystem crate from the registry row.
    #[must_use]
    pub const fn owner(self) -> &'static str {
        match self {
            Self::SessionOpen | Self::SessionResume => "fss-agent-session",
            Self::SessionOrient => "fss-situation",
            Self::SessionFollow => "fss-context-pack",
            Self::Query => "fss-query-plan",
            Self::Investigate => "fss-investigation",
            Self::Plan => "fss-agent-plan",
            Self::Commit => "fss-effect",
            Self::Wait | Self::Cancel => "fss-obligation",
            Self::Explain => "fss-explain",
            Self::Handoff => "fss-handoff",
            Self::Feedback => "fss-learning",
            Self::Doctor => "fss-doctor",
        }
    }

    /// Returns the operation mode from the registry row.
    #[must_use]
    pub const fn mode(self) -> OperationMode {
        match self {
            Self::SessionOpen | Self::SessionResume => OperationMode::SessionControl,
            Self::SessionOrient => OperationMode::Read,
            Self::SessionFollow | Self::Wait => OperationMode::ReadWait,
            Self::Query => OperationMode::ReadCompile,
            Self::Investigate => OperationMode::CognitionWrite,
            Self::Plan => OperationMode::PlanPrepare,
            Self::Commit => OperationMode::EffectCommit,
            Self::Cancel => OperationMode::LifecycleEffect,
            Self::Explain => OperationMode::ReadCompute,
            Self::Handoff => OperationMode::ContinuityPublish,
            Self::Feedback => OperationMode::AdvisoryWrite,
            Self::Doctor => OperationMode::DiagnosticPrepare,
        }
    }

    /// Returns the registry prose purpose of this operation.
    #[must_use]
    pub const fn purpose(self) -> &'static str {
        match self {
            Self::SessionOpen => {
                "negotiate principal, mission, authority, privacy projection, budgets, views, and the initial SituationCapsule"
            }
            Self::SessionResume => {
                "restore an explicit workspace/handoff root, compare it with current state, and enumerate stale or invalidated assumptions"
            }
            Self::SessionOrient => {
                "return the smallest sufficient current SituationCapsule for the mission, authority, and budget"
            }
            Self::SessionFollow => {
                "stream meaningful deltas and obligation progress from an exact continuation cursor"
            }
            Self::Query => {
                "execute a bounded typed or natural-language-compiled read over one anchor with completeness and cost receipts"
            }
            Self::Investigate => {
                "create or advance a durable case with competing hypotheses, evidence tasks, work claims, discriminators, and stop rules"
            }
            Self::Plan => {
                "compile a desired outcome or information objective into an immutable witnessed contingent plan without crossing the effect boundary"
            }
            Self::Commit => {
                "revalidate and start the exact prepared plan under idempotency, leases, fencing, approval, and terminal-proof obligations"
            }
            Self::Wait => {
                "observe cases, plans, effects, transfers, and obligations until a predicate, deadline, or meaningful delta fires"
            }
            Self::Cancel => {
                "request, drain, reconcile or compensate, and finalize owned work without erasing its durable record"
            }
            Self::Explain => {
                "answer why, why-not, what-changed, or what-if with a minimal evidence/decision subgraph and expansion handles"
            }
            Self::Handoff => {
                "publish a root-last portable capsule containing mission, workspace, cases, plans, obligations, budgets, authority, uncertainty, and continuations"
            }
            Self::Feedback => {
                "record a correction, outcome signal, adjudication, or evidence-linked learning proposal without silently changing active truth or policy"
            }
            Self::Doctor => {
                "diagnose deployment, evidence, cognition, workspace, cases, obligations, and protocol consistency and produce sealed repair affordances"
            }
        }
    }

    /// Returns the default registered view ID (`AVIEW-001`..`AVIEW-008`).
    #[must_use]
    pub const fn default_view(self) -> &'static str {
        match self {
            Self::SessionOpen | Self::SessionOrient => "AVIEW-002",
            Self::SessionResume | Self::Handoff => "AVIEW-006",
            Self::SessionFollow => "AVIEW-001",
            Self::Query | Self::Investigate => "AVIEW-003",
            Self::Plan | Self::Explain | Self::Feedback => "AVIEW-007",
            Self::Commit | Self::Wait | Self::Cancel => "AVIEW-005",
            Self::Doctor => "AVIEW-004",
        }
    }

    /// Returns the typed request payload schema of this operation.
    #[must_use]
    pub const fn request_payload_schema(self) -> &'static str {
        match self {
            Self::SessionOpen => concat!("fss.agent_mission", ".v1"),
            Self::SessionResume => concat!("fss.agent_handoff_capsule", ".v1"),
            Self::SessionOrient
            | Self::SessionFollow
            | Self::Query
            | Self::Wait
            | Self::Cancel
            | Self::Explain
            | Self::Doctor => concat!("fss.agent_query_plan", ".v1"),
            Self::Investigate => concat!("fss.investigation_state", ".v1"),
            Self::Plan => concat!("fss.agent_objective_contract", ".v1"),
            Self::Commit => concat!("fss.agent_control_plan", ".v1"),
            Self::Handoff => concat!("fss.agent_session_capsule", ".v1"),
            Self::Feedback => concat!("fss.agent_feedback_proposal", ".v1"),
        }
    }

    /// Returns the typed response payload schemas of this operation.
    #[must_use]
    pub const fn response_payload_schemas(self) -> ResponseSchemaList {
        match self {
            Self::SessionOpen | Self::SessionResume | Self::SessionOrient => {
                &[concat!("fss.situation_capsule", ".v1")]
            }
            Self::SessionFollow => &[
                concat!("fss.agent_meaningful_delta", ".v1"),
                concat!("fss.situation_capsule", ".v1"),
            ],
            Self::Query | Self::Explain => &[concat!("fss.agent_cognitive_envelope", ".v1")],
            Self::Investigate => &[
                concat!("fss.investigation_state", ".v1"),
                concat!("fss.agent_cognitive_envelope", ".v1"),
            ],
            Self::Plan => &[concat!("fss.agent_control_plan", ".v1")],
            Self::Commit | Self::Cancel => &[
                concat!("fss.operation_receipt", ".v1"),
                concat!("fss.agent_cognitive_envelope", ".v1"),
            ],
            Self::Wait => &[
                concat!("fss.agent_cognitive_envelope", ".v1"),
                concat!("fss.operation_receipt", ".v1"),
            ],
            Self::Handoff => &[concat!("fss.agent_handoff_capsule", ".v1")],
            Self::Feedback => &[
                concat!("fss.agent_feedback_proposal", ".v1"),
                concat!("fss.experience_capsule", ".v1"),
            ],
            Self::Doctor => &[
                concat!("fss.agent_cognitive_envelope", ".v1"),
                concat!("fss.evidence_bundle", ".v1"),
            ],
        }
    }

    /// Returns the required capability IDs of this operation.
    #[must_use]
    pub const fn required_capabilities(self) -> CapabilityList {
        match self {
            Self::SessionOpen => &["CAP-AGENT-SESSION-OPEN-001"],
            Self::SessionResume => &["CAP-AGENT-SESSION-READ-001"],
            Self::SessionOrient | Self::SessionFollow | Self::Wait => {
                &["CAP-AGENT-SITUATION-READ-001"]
            }
            Self::Query => &["CAP-AGENT-QUERY-001"],
            Self::Investigate => &["CAP-AGENT-CASE-WRITE-001"],
            Self::Plan => &["CAP-AGENT-PLAN-PREPARE-001"],
            Self::Commit => &["CAP-AGENT-PLAN-COMMIT-001"],
            Self::Cancel => &["CAP-AGENT-CANCEL-001"],
            Self::Explain => &["CAP-AGENT-EXPLAIN-001"],
            Self::Handoff => &["CAP-AGENT-HANDOFF-WRITE-001"],
            Self::Feedback => &["CAP-AGENT-FEEDBACK-001"],
            Self::Doctor => &["CAP-REPAIR-PREPARE-001"],
        }
    }

    /// Returns the registered retry classes of this operation.
    #[must_use]
    pub const fn retry_classes(self) -> RetryClassList {
        match self {
            Self::SessionOpen => &[
                OperationRetryClass::NeverUnchanged,
                OperationRetryClass::Backoff,
                OperationRetryClass::OperatorActionRequired,
                OperationRetryClass::ResumeFromContinuation,
            ],
            Self::SessionResume => &[
                OperationRetryClass::SafeReadRetry,
                OperationRetryClass::RefreshAndRetry,
                OperationRetryClass::RebaseRequired,
                OperationRetryClass::OperatorActionRequired,
                OperationRetryClass::ResumeFromContinuation,
            ],
            Self::SessionOrient => &[
                OperationRetryClass::SafeReadRetry,
                OperationRetryClass::RefreshAndRetry,
                OperationRetryClass::RebaseRequired,
                OperationRetryClass::Backoff,
                OperationRetryClass::ResumeFromContinuation,
            ],
            Self::SessionFollow | Self::Query => &[
                OperationRetryClass::SafeReadRetry,
                OperationRetryClass::RefreshAndRetry,
                OperationRetryClass::RebaseRequired,
                OperationRetryClass::Backoff,
                OperationRetryClass::ResumeFromContinuation,
            ],
            Self::Investigate => &[
                OperationRetryClass::RefreshAndRetry,
                OperationRetryClass::RebaseRequired,
                OperationRetryClass::Backoff,
                OperationRetryClass::ReconciliationRequired,
                OperationRetryClass::OperatorActionRequired,
                OperationRetryClass::ResumeFromContinuation,
            ],
            Self::Plan => &[
                OperationRetryClass::RefreshAndRetry,
                OperationRetryClass::RebaseRequired,
                OperationRetryClass::Backoff,
                OperationRetryClass::OperatorActionRequired,
                OperationRetryClass::ResumeFromContinuation,
            ],
            Self::Commit => &[
                OperationRetryClass::NeverUnchanged,
                OperationRetryClass::Backoff,
                OperationRetryClass::ReconciliationRequired,
                OperationRetryClass::OperatorActionRequired,
                OperationRetryClass::ResumeFromContinuation,
            ],
            Self::Wait => &[
                OperationRetryClass::SafeReadRetry,
                OperationRetryClass::RefreshAndRetry,
                OperationRetryClass::Backoff,
                OperationRetryClass::ReconciliationRequired,
                OperationRetryClass::ResumeFromContinuation,
            ],
            Self::Cancel => &[
                OperationRetryClass::NeverUnchanged,
                OperationRetryClass::Backoff,
                OperationRetryClass::ReconciliationRequired,
                OperationRetryClass::OperatorActionRequired,
                OperationRetryClass::ResumeFromContinuation,
            ],
            Self::Explain => &[
                OperationRetryClass::SafeReadRetry,
                OperationRetryClass::RefreshAndRetry,
                OperationRetryClass::RebaseRequired,
                OperationRetryClass::ResumeFromContinuation,
            ],
            Self::Handoff => &[
                OperationRetryClass::RefreshAndRetry,
                OperationRetryClass::RebaseRequired,
                OperationRetryClass::Backoff,
                OperationRetryClass::ReconciliationRequired,
                OperationRetryClass::OperatorActionRequired,
                OperationRetryClass::ResumeFromContinuation,
            ],
            Self::Feedback => &[
                OperationRetryClass::RefreshAndRetry,
                OperationRetryClass::RebaseRequired,
                OperationRetryClass::Backoff,
                OperationRetryClass::ReconciliationRequired,
                OperationRetryClass::OperatorActionRequired,
            ],
            Self::Doctor => &[
                OperationRetryClass::SafeReadRetry,
                OperationRetryClass::RefreshAndRetry,
                OperationRetryClass::Backoff,
                OperationRetryClass::ResumeFromContinuation,
            ],
        }
    }

    /// Returns whether this operation can produce an effect.
    ///
    /// Exactly `AOP-008` `commit` and `AOP-010` `cancel` are effectful.
    #[must_use]
    pub const fn effectful(self) -> bool {
        self.mode().affects_effect_plane()
    }

    /// Returns whether this operation publishes durable artifacts.
    #[must_use]
    pub const fn durable(self) -> bool {
        self.mode().requires_durability()
    }

    /// Returns the qualification gate of this operation row.
    #[must_use]
    pub const fn gate(self) -> &'static str {
        REGISTERED_OPERATION_GATE
    }

    /// Returns the frozen public-registry generation of this operation row.
    #[must_use]
    pub const fn generation(self) -> &'static str {
        OPERATION_REGISTRY_GENERATION
    }

    /// Returns the deterministic canonical text row encoding.
    ///
    /// Field order and delimiters are documented on the module. The row literal is
    /// pinned against the typed accessors by unit tests and against the machine
    /// registry by `scripts/agent_operation_registry_checker.py`.
    #[must_use]
    pub const fn canonical_row_encoding(self) -> &'static str {
        match self {
            Self::SessionOpen => {
                "AOP-001|session.open|session_control|fss-agent-session|AVIEW-002|fss.agent_mission.v1|fss.situation_capsule.v1|fss.agent_request_envelope.v1|fss.agent_response_envelope.v1|0|1|QL-AGENT-001|CAP-AGENT-SESSION-OPEN-001|never_unchanged;backoff;operator_action_required;resume_from_continuation"
            }
            Self::SessionResume => {
                "AOP-002|session.resume|session_control|fss-agent-session|AVIEW-006|fss.agent_handoff_capsule.v1|fss.situation_capsule.v1|fss.agent_request_envelope.v1|fss.agent_response_envelope.v1|0|1|QL-AGENT-001|CAP-AGENT-SESSION-READ-001|safe_read_retry;refresh_and_retry;rebase_required;operator_action_required;resume_from_continuation"
            }
            Self::SessionOrient => {
                "AOP-003|session.orient|read|fss-situation|AVIEW-002|fss.agent_query_plan.v1|fss.situation_capsule.v1|fss.agent_request_envelope.v1|fss.agent_response_envelope.v1|0|0|QL-AGENT-001|CAP-AGENT-SITUATION-READ-001|safe_read_retry;refresh_and_retry;rebase_required;backoff;resume_from_continuation"
            }
            Self::SessionFollow => {
                "AOP-004|session.follow|read_wait|fss-context-pack|AVIEW-001|fss.agent_query_plan.v1|fss.agent_meaningful_delta.v1;fss.situation_capsule.v1|fss.agent_request_envelope.v1|fss.agent_response_envelope.v1|0|1|QL-AGENT-001|CAP-AGENT-SITUATION-READ-001|safe_read_retry;refresh_and_retry;rebase_required;backoff;resume_from_continuation"
            }
            Self::Query => {
                "AOP-005|query|read_compile|fss-query-plan|AVIEW-003|fss.agent_query_plan.v1|fss.agent_cognitive_envelope.v1|fss.agent_request_envelope.v1|fss.agent_response_envelope.v1|0|0|QL-AGENT-001|CAP-AGENT-QUERY-001|safe_read_retry;refresh_and_retry;rebase_required;backoff;resume_from_continuation"
            }
            Self::Investigate => {
                "AOP-006|investigate|cognition_write|fss-investigation|AVIEW-003|fss.investigation_state.v1|fss.investigation_state.v1;fss.agent_cognitive_envelope.v1|fss.agent_request_envelope.v1|fss.agent_response_envelope.v1|0|1|QL-AGENT-001|CAP-AGENT-CASE-WRITE-001|refresh_and_retry;rebase_required;backoff;reconciliation_required;operator_action_required;resume_from_continuation"
            }
            Self::Plan => {
                "AOP-007|plan|plan_prepare|fss-agent-plan|AVIEW-007|fss.agent_objective_contract.v1|fss.agent_control_plan.v1|fss.agent_request_envelope.v1|fss.agent_response_envelope.v1|0|1|QL-AGENT-001|CAP-AGENT-PLAN-PREPARE-001|refresh_and_retry;rebase_required;backoff;operator_action_required;resume_from_continuation"
            }
            Self::Commit => {
                "AOP-008|commit|effect_commit|fss-effect|AVIEW-005|fss.agent_control_plan.v1|fss.operation_receipt.v1;fss.agent_cognitive_envelope.v1|fss.agent_request_envelope.v1|fss.agent_response_envelope.v1|1|1|QL-AGENT-001|CAP-AGENT-PLAN-COMMIT-001|never_unchanged;backoff;reconciliation_required;operator_action_required;resume_from_continuation"
            }
            Self::Wait => {
                "AOP-009|wait|read_wait|fss-obligation|AVIEW-005|fss.agent_query_plan.v1|fss.agent_cognitive_envelope.v1;fss.operation_receipt.v1|fss.agent_request_envelope.v1|fss.agent_response_envelope.v1|0|1|QL-AGENT-001|CAP-AGENT-SITUATION-READ-001|safe_read_retry;refresh_and_retry;backoff;reconciliation_required;resume_from_continuation"
            }
            Self::Cancel => {
                "AOP-010|cancel|lifecycle_effect|fss-obligation|AVIEW-005|fss.agent_query_plan.v1|fss.operation_receipt.v1;fss.agent_cognitive_envelope.v1|fss.agent_request_envelope.v1|fss.agent_response_envelope.v1|1|1|QL-AGENT-001|CAP-AGENT-CANCEL-001|never_unchanged;backoff;reconciliation_required;operator_action_required;resume_from_continuation"
            }
            Self::Explain => {
                "AOP-011|explain|read_compute|fss-explain|AVIEW-007|fss.agent_query_plan.v1|fss.agent_cognitive_envelope.v1|fss.agent_request_envelope.v1|fss.agent_response_envelope.v1|0|0|QL-AGENT-001|CAP-AGENT-EXPLAIN-001|safe_read_retry;refresh_and_retry;rebase_required;resume_from_continuation"
            }
            Self::Handoff => {
                "AOP-012|handoff|continuity_publish|fss-handoff|AVIEW-006|fss.agent_session_capsule.v1|fss.agent_handoff_capsule.v1|fss.agent_request_envelope.v1|fss.agent_response_envelope.v1|0|1|QL-AGENT-001|CAP-AGENT-HANDOFF-WRITE-001|refresh_and_retry;rebase_required;backoff;reconciliation_required;operator_action_required;resume_from_continuation"
            }
            Self::Feedback => {
                "AOP-013|feedback|advisory_write|fss-learning|AVIEW-007|fss.agent_feedback_proposal.v1|fss.agent_feedback_proposal.v1;fss.experience_capsule.v1|fss.agent_request_envelope.v1|fss.agent_response_envelope.v1|0|1|QL-AGENT-001|CAP-AGENT-FEEDBACK-001|refresh_and_retry;rebase_required;backoff;reconciliation_required;operator_action_required"
            }
            Self::Doctor => {
                "AOP-014|doctor|diagnostic_prepare|fss-doctor|AVIEW-004|fss.agent_query_plan.v1|fss.agent_cognitive_envelope.v1;fss.evidence_bundle.v1|fss.agent_request_envelope.v1|fss.agent_response_envelope.v1|0|1|QL-AGENT-001|CAP-REPAIR-PREPARE-001|safe_read_retry;refresh_and_retry;backoff;resume_from_continuation"
            }
        }
    }

    /// Validates the row invariants at construction and use boundaries.
    ///
    /// Fails closed on effect/mode contradiction, durability contradiction, and any
    /// malformed or unregistered field spelling. Registered rows always pass; decoded
    /// rows must still pass to surface tampering as typed refusals.
    pub fn validate_row(self) -> Result<(), ContractError> {
        let mode = self.mode();
        if mode.affects_effect_plane() != self.effectful() {
            return Err(ContractError::OperationEffectModeMismatch);
        }
        if mode.requires_durability() != self.durable() {
            return Err(ContractError::OperationEffectModeMismatch);
        }
        if self.effectful() && !self.durable() {
            return Err(ContractError::OperationEffectModeMismatch);
        }
        if !self.gate().starts_with("QL-") {
            return Err(ContractError::InvalidIdentifier);
        }
        for schema in self.response_payload_schemas() {
            if !schema.starts_with("fss.") {
                return Err(ContractError::InvalidIdentifier);
            }
        }
        for capability in self.required_capabilities() {
            if !capability.starts_with("CAP-") {
                return Err(ContractError::InvalidIdentifier);
            }
        }
        for retry in self.retry_classes() {
            let spelled = retry.as_str();
            if spelled.is_empty() {
                return Err(ContractError::InvalidIdentifier);
            }
        }
        Ok(())
    }

    /// Returns the domain-separated canonical digest of the full row.
    #[must_use]
    pub fn row_digest(self) -> ContentDigest {
        self.canonical_digest(OPERATION_ROW_DIGEST_DOMAIN)
    }
}

impl CanonicalEncode for AgentOperation {
    /// Encodes every registered row field in the documented fixed order.
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.id());
        encoder.text(self.name());
        self.mode().encode_canonical(encoder);
        encoder.text(self.owner());
        encoder.text(self.default_view());
        encoder.text(self.request_payload_schema());
        encoder.u32(self.response_payload_schemas().len() as u32);
        for schema in self.response_payload_schemas() {
            encoder.text(schema);
        }
        encoder.text(concat!("fss.agent_request_envelope", ".v1"));
        encoder.text(concat!("fss.agent_response_envelope", ".v1"));
        encoder.bool(self.effectful());
        encoder.bool(self.durable());
        encoder.text(self.gate());
        encoder.u32(self.required_capabilities().len() as u32);
        for capability in self.required_capabilities() {
            encoder.text(capability);
        }
        encoder.u32(self.retry_classes().len() as u32);
        for retry in self.retry_classes() {
            retry.encode_canonical(encoder);
        }
    }
}

impl CanonicalDecode for AgentOperation {
    /// Decodes a row and fails closed unless the fields reconstruct a registered row.
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let id = decoder.text()?;
        let name = decoder.text()?;
        let mode = OperationMode::decode_canonical(decoder)?;
        let owner = decoder.text()?;
        let default_view = decoder.text()?;
        let request_payload = decoder.text()?;
        let response_len = decoder.u32()?;
        let mut responses = Vec::with_capacity(response_len.min(8) as usize);
        for _ in 0..response_len {
            responses.push(decoder.text()?.to_owned());
        }
        let input_schema = decoder.text()?;
        let output_schema = decoder.text()?;
        let effectful = decoder.bool()?;
        let durable = decoder.bool()?;
        let gate = decoder.text()?;
        let capability_len = decoder.u32()?;
        let mut capabilities = Vec::with_capacity(capability_len.min(8) as usize);
        for _ in 0..capability_len {
            capabilities.push(decoder.text()?.to_owned());
        }
        let retry_len = decoder.u32()?;
        let mut retries = Vec::with_capacity(retry_len.min(8) as usize);
        for _ in 0..retry_len {
            retries.push(OperationRetryClass::decode_canonical(decoder)?);
        }
        let candidate = Self::from_id(id)?;
        let matches = candidate.id() == id
            && candidate.name() == name
            && candidate.mode() == mode
            && candidate.owner() == owner
            && candidate.default_view() == default_view
            && candidate.request_payload_schema() == request_payload
            && candidate.response_payload_schemas().len() == responses.len()
            && candidate
                .response_payload_schemas()
                .iter()
                .zip(responses.iter())
                .all(|(a, b)| a == b)
            && input_schema == concat!("fss.agent_request_envelope", ".v1")
            && output_schema == concat!("fss.agent_response_envelope", ".v1")
            && candidate.effectful() == effectful
            && candidate.durable() == durable
            && candidate.gate() == gate
            && candidate.required_capabilities().len() == capabilities.len()
            && candidate
                .required_capabilities()
                .iter()
                .zip(capabilities.iter())
                .all(|(a, b)| a == b)
            && candidate.retry_classes().len() == retries.len()
            && candidate
                .retry_classes()
                .iter()
                .zip(retries.iter())
                .all(|(a, b)| a == b);
        if !matches {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(candidate)
    }
}

impl fmt::Display for AgentOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl core::str::FromStr for AgentOperation {
    type Err = ContractError;

    /// Parses by canonical name only; stable IDs are never accepted as names
    /// (same laundering rule as `ProvenanceClass`).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s)
    }
}

/// The six pinned registry digests of a [`ContractBasis`], as typed identities.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BasisRegistryKind {
    /// JSON Schema catalog.
    SchemaCatalog,
    /// Public operation registry.
    Operations,
    /// Registered views.
    Views,
    /// Capability registry.
    Capabilities,
    /// Error registry.
    Errors,
    /// Operation cost registry.
    Costs,
}

impl BasisRegistryKind {
    /// Returns the stable registry spelling used in drift enumeration.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SchemaCatalog => "schema_catalog",
            Self::Operations => "operations",
            Self::Views => "views",
            Self::Capabilities => "capabilities",
            Self::Errors => "errors",
            Self::Costs => "costs",
        }
    }

    /// Returns the pinned digest of this registry inside `basis`.
    #[must_use]
    pub fn digest_of(self, basis: &ContractBasis) -> ContentDigest {
        match self {
            Self::SchemaCatalog => basis.schema_catalog_digest,
            Self::Operations => basis.operation_registry_digest,
            Self::Views => basis.view_registry_digest,
            Self::Capabilities => basis.capability_registry_digest,
            Self::Errors => basis.error_registry_digest,
            Self::Costs => basis.cost_registry_digest,
        }
    }
}

impl fmt::Display for BasisRegistryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One enumerated difference between a recorded session/handoff root and the
/// current authority state (AOP-002 `session.resume`).
///
/// Resume never silently accepts drift: every difference is enumerated as a
/// typed entry so the driver can accept or rebase explicitly. Enumeration order
/// is deterministic and follows the field order of `ContractBasis` followed by
/// the anchor axis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResumeInvalidation {
    /// The recorded semantic protocol differs from the current protocol.
    ProtocolDrift {
        /// Protocol identity recorded in the root.
        recorded: String,
        /// Current protocol identity.
        current: String,
    },
    /// The recorded ontology generation differs from the current generation.
    OntologyDrift {
        /// Ontology generation recorded in the root.
        recorded: String,
        /// Current ontology generation.
        current: String,
    },
    /// The recorded producer release identity differs from the current one.
    ProducerReleaseDrift {
        /// Producer release recorded in the root.
        recorded: String,
        /// Current producer release.
        current: String,
    },
    /// A pinned registry digest differs from the current digest. The recorded
    /// generation itself still exists, so resuming after explicit rebase is
    /// meaningful.
    RegistryDrift {
        /// The registry whose pinned digest drifted.
        registry: BasisRegistryKind,
    },
    /// A recorded registry digest is tombstoned: that generation was superseded
    /// and erased, so the root cannot be resumed without a full rebuild of the
    /// invalidated registry's derived state.
    TombstonedRegistryDigest {
        /// The registry whose pinned digest is tombstoned.
        registry: BasisRegistryKind,
    },
    /// The recorded anchor's deployment lineage diverges from the current
    /// lineage: the recorded history is not an ancestor of current state.
    AnchorLineageDivergence,
    /// The recorded anchor is strictly newer than the current anchor: the root
    /// claims history the current authority does not have.
    AnchorNotStrictlyOlder,
}

/// Typed outcome of classifying a `session.resume` root against current state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumeAssessment {
    invalidations: Vec<ResumeInvalidation>,
}

impl ResumeAssessment {
    /// Returns every enumerated invalidation, in deterministic enumeration order.
    #[must_use]
    pub fn invalidations(&self) -> &[ResumeInvalidation] {
        &self.invalidations
    }

    /// Returns whether the root matches current state with no invalidation.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.invalidations.is_empty()
    }
}

/// Classifies a `session.resume` root (AOP-002) against current state.
///
/// Unlike request-time staleness checks ([`fss_core::contract_basis`]
/// `check_basis_freshness`/`refuse_stale_anchor`, which fail closed), resume
/// converts staleness into an explicit, complete inventory: the caller must
/// accept or rebase every enumerated invalidation. An anchor equal to the
/// current anchor is NOT an invalidation (nothing was missed); lineage
/// divergence or a strictly newer recorded anchor is.
#[must_use]
pub fn classify_session_resume(
    recorded: &ContractBasis,
    current: &ContractBasis,
    recorded_anchor: &LedgerAnchor,
    current_anchor: &LedgerAnchor,
    tombstoned_digests: &[ContentDigest],
) -> ResumeAssessment {
    let registry_order = [
        BasisRegistryKind::SchemaCatalog,
        BasisRegistryKind::Operations,
        BasisRegistryKind::Views,
        BasisRegistryKind::Capabilities,
        BasisRegistryKind::Errors,
        BasisRegistryKind::Costs,
    ];
    let mut invalidations = Vec::new();
    if recorded.semantic_protocol != current.semantic_protocol {
        invalidations.push(ResumeInvalidation::ProtocolDrift {
            recorded: recorded.semantic_protocol.clone(),
            current: current.semantic_protocol.clone(),
        });
    }
    if recorded.ontology_generation_id != current.ontology_generation_id {
        invalidations.push(ResumeInvalidation::OntologyDrift {
            recorded: recorded.ontology_generation_id.clone(),
            current: current.ontology_generation_id.clone(),
        });
    }
    if recorded.producer_release_id != current.producer_release_id {
        invalidations.push(ResumeInvalidation::ProducerReleaseDrift {
            recorded: recorded.producer_release_id.clone(),
            current: current.producer_release_id.clone(),
        });
    }
    for registry in registry_order {
        let recorded_digest = registry.digest_of(recorded);
        if tombstoned_digests.contains(&recorded_digest) {
            invalidations.push(ResumeInvalidation::TombstonedRegistryDigest { registry });
        } else if recorded_digest != registry.digest_of(current) {
            invalidations.push(ResumeInvalidation::RegistryDrift { registry });
        }
    }
    if recorded_anchor.site_lineage != current_anchor.site_lineage {
        invalidations.push(ResumeInvalidation::AnchorLineageDivergence);
    } else if (
        recorded_anchor.ledger_epoch,
        recorded_anchor.commit_sequence,
    ) > (current_anchor.ledger_epoch, current_anchor.commit_sequence)
    {
        invalidations.push(ResumeInvalidation::AnchorNotStrictlyOlder);
    }
    ResumeAssessment { invalidations }
}

/// Driver-facing frame section of an orient projection (AOP-003).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OrientSection {
    /// Current situation statements.
    Now,
    /// Meaningful changes.
    Changed,
    /// Causal or evidentiary explanation.
    Why,
    /// Material unknowns and contradictions.
    Unknown,
    /// Risks, invalidators, and urgent obligations.
    AtRisk,
    /// Nondominated next affordance identities.
    Next,
}

impl OrientSection {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Now => "now",
            Self::Changed => "changed",
            Self::Why => "why",
            Self::Unknown => "unknown",
            Self::AtRisk => "at_risk",
            Self::Next => "next",
        }
    }

    /// Returns the canonical wire tag (frame declaration order).
    #[must_use]
    pub const fn to_code(self) -> u32 {
        match self {
            Self::Now => 1,
            Self::Changed => 2,
            Self::Why => 3,
            Self::Unknown => 4,
            Self::AtRisk => 5,
            Self::Next => 6,
        }
    }
}

impl fmt::Display for OrientSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What an orient omission dropped (AOP-003).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OrientOmissionTarget {
    /// Entries of one driver-facing frame section.
    Section(OrientSection),
    /// Sorted evidence handles beyond the handle budget.
    EvidenceHandles,
}

impl OrientOmissionTarget {
    /// Returns the canonical wire tag.
    #[must_use]
    pub const fn to_code(self) -> u32 {
        match self {
            Self::Section(section) => section.to_code(),
            Self::EvidenceHandles => 7,
        }
    }
}

/// Entry budget of one orient projection (AOP-003).
///
/// Both bounds must be at least 1: an orient read that admits nothing is
/// refused with [`ContractError::BudgetExhausted`] rather than returning an
/// empty projection that looks like a complete answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrientBudget {
    max_per_section: u32,
    max_evidence_handles: u32,
}

impl OrientBudget {
    /// Validates and constructs a projection budget.
    pub fn new(max_per_section: u32, max_evidence_handles: u32) -> Result<Self, ContractError> {
        if max_per_section == 0 || max_evidence_handles == 0 {
            return Err(ContractError::BudgetExhausted);
        }
        Ok(Self {
            max_per_section,
            max_evidence_handles,
        })
    }

    /// Returns the per-section entry bound.
    #[must_use]
    pub const fn max_per_section(&self) -> u32 {
        self.max_per_section
    }

    /// Returns the evidence-handle bound.
    #[must_use]
    pub const fn max_evidence_handles(&self) -> u32 {
        self.max_evidence_handles
    }
}

/// One typed omission of an orient projection.
///
/// Omissions are never silent: entries dropped by the budget are enumerated
/// with their target and count, so compactness can never flatten `unknown`,
/// `at_risk`, or `next` content into absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrientOmission {
    /// What was dropped.
    pub target: OrientOmissionTarget,
    /// How many entries were dropped.
    pub omitted_entries: u32,
}

/// The smallest-sufficient read projection of a [`SituationCapsule`] (AOP-003
/// `session.orient`).
///
/// A pure read product: it publishes no durable artifact and carries affordance
/// identities only (never affordance authority). Every section is bounded by
/// the caller's budget with typed omissions for everything dropped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrientProjection {
    /// Capsule identity the projection was derived from.
    pub capsule_id: String,
    /// Monotone capsule revision of the source capsule.
    pub revision: u64,
    /// Mission identity.
    pub mission_id: MissionId,
    /// Session identity.
    pub session_id: SessionId,
    /// Principal identity.
    pub principal_id: PrincipalId,
    /// Exact current anchor (equals the frame anchor; validated).
    pub anchor: LedgerAnchor,
    /// Completeness of the source capsule for its mission and view.
    pub completeness: Completeness,
    /// Current situation statements (bounded).
    pub now: Vec<String>,
    /// Meaningful changes (bounded).
    pub changed: Vec<String>,
    /// Causal or evidentiary explanations (bounded).
    pub why: Vec<String>,
    /// Material unknowns and contradictions (bounded).
    pub unknown: Vec<String>,
    /// Risks, invalidators, and urgent obligations (bounded).
    pub at_risk: Vec<String>,
    /// Nondominated next affordance identities (bounded).
    pub next: Vec<String>,
    /// Evidence handles, sorted and bounded.
    pub evidence_handles: Vec<String>,
    /// Typed omissions: sections or handles dropped by the budget.
    pub omissions: Vec<OrientOmission>,
}

/// Canonical digest domain of one orient projection.
pub const ORIENT_PROJECTION_DIGEST_DOMAIN: &str = "fss.agent.orient.projection.v1";

impl OrientProjection {
    /// Returns the domain-separated canonical digest of this projection.
    #[must_use]
    pub fn projection_digest(&self) -> ContentDigest {
        self.canonical_digest(ORIENT_PROJECTION_DIGEST_DOMAIN)
    }

    /// Returns the retained entries of one section.
    #[must_use]
    pub fn section(&self, section: OrientSection) -> &[String] {
        match section {
            OrientSection::Now => &self.now,
            OrientSection::Changed => &self.changed,
            OrientSection::Why => &self.why,
            OrientSection::Unknown => &self.unknown,
            OrientSection::AtRisk => &self.at_risk,
            OrientSection::Next => &self.next,
        }
    }
}

impl CanonicalEncode for OrientProjection {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.capsule_id);
        encoder.u64(self.revision);
        encoder.text(self.mission_id.as_str());
        encoder.text(self.session_id.as_str());
        encoder.text(self.principal_id.as_str());
        self.anchor.encode_canonical(encoder);
        self.completeness.encode_canonical(encoder);
        for section in [
            OrientSection::Now,
            OrientSection::Changed,
            OrientSection::Why,
            OrientSection::Unknown,
            OrientSection::AtRisk,
            OrientSection::Next,
        ] {
            let entries = self.section(section);
            encoder.u32(entries.len() as u32);
            for entry in entries {
                encoder.text(entry);
            }
        }
        encoder.u32(self.evidence_handles.len() as u32);
        for handle in &self.evidence_handles {
            encoder.text(handle);
        }
        encoder.u32(self.omissions.len() as u32);
        for omission in &self.omissions {
            encoder.u32(omission.target.to_code());
            encoder.u32(omission.omitted_entries);
        }
    }
}

/// Projects the smallest-sufficient orient read of `capsule` under `budget`
/// (AOP-003 `session.orient`).
///
/// Fails closed if the capsule is invalid (stale anchor, refused knowledge
/// cells) or the budget admits nothing. Selection keeps entries in their frame
/// order up to the bound and enumerates every dropped entry as a typed
/// omission; evidence handles are kept in sorted order.
pub fn orient_projection(
    capsule: &SituationCapsule,
    budget: OrientBudget,
) -> Result<OrientProjection, ContractError> {
    capsule.validate()?;
    let frame = &capsule.frame;
    let clip = |entries: &[String], section: OrientSection, omissions: &mut Vec<OrientOmission>| {
        if entries.len() > budget.max_per_section as usize {
            omissions.push(OrientOmission {
                target: OrientOmissionTarget::Section(section),
                omitted_entries: (entries.len() - budget.max_per_section as usize) as u32,
            });
        }
        entries
            .iter()
            .take(budget.max_per_section as usize)
            .cloned()
            .collect::<Vec<String>>()
    };
    let mut omissions = Vec::new();
    let now = clip(&frame.now, OrientSection::Now, &mut omissions);
    let changed = clip(&frame.changed, OrientSection::Changed, &mut omissions);
    let why = clip(&frame.why, OrientSection::Why, &mut omissions);
    let unknown = clip(&frame.unknown, OrientSection::Unknown, &mut omissions);
    let at_risk = clip(&frame.at_risk, OrientSection::AtRisk, &mut omissions);
    let next = clip(&frame.next, OrientSection::Next, &mut omissions);
    let handle_total = frame.evidence_handles.len();
    let evidence_handles: Vec<String> = frame
        .evidence_handles
        .iter()
        .take(budget.max_evidence_handles as usize)
        .cloned()
        .collect();
    if handle_total > evidence_handles.len() {
        omissions.push(OrientOmission {
            target: OrientOmissionTarget::EvidenceHandles,
            omitted_entries: (handle_total - evidence_handles.len()) as u32,
        });
    }
    Ok(OrientProjection {
        capsule_id: capsule.capsule_id.clone(),
        revision: capsule.revision,
        mission_id: capsule.mission_id.clone(),
        session_id: capsule.session_id.clone(),
        principal_id: capsule.principal_id.clone(),
        anchor: capsule.anchor.clone(),
        completeness: capsule.completeness,
        now,
        changed,
        why,
        unknown,
        at_risk,
        next,
        evidence_handles,
        omissions,
    })
}

/// Bounded wake contract of one `session.follow` read (AOP-004).
///
/// A follow read is always bounded twice: by an entry budget and by a wake
/// deadline no later than the cursor's validated expiry. An unbounded follow
/// is refused, never silently truncated into unbounded waiting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FollowWakeContract {
    max_entries: u32,
    deadline: TimestampNs,
}

impl FollowWakeContract {
    /// Validates and constructs a wake contract.
    ///
    /// `max_entries` must be at least 1 and `deadline` must be strictly after
    /// `now`; otherwise the wake admits nothing and is refused with
    /// [`ContinuationError::UnboundedWake`].
    pub fn new(
        max_entries: u32,
        deadline: TimestampNs,
        now: TimestampNs,
    ) -> Result<Self, ContinuationError> {
        if max_entries == 0 || deadline <= now {
            return Err(ContinuationError::UnboundedWake);
        }
        Ok(Self {
            max_entries,
            deadline,
        })
    }

    /// Returns the entry bound of one delivered batch.
    #[must_use]
    pub const fn max_entries(&self) -> u32 {
        self.max_entries
    }

    /// Returns the absolute wake deadline.
    #[must_use]
    pub const fn deadline(&self) -> TimestampNs {
        self.deadline
    }
}

/// The admitted plan of one `session.follow` read (AOP-004).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FollowBatchPlan {
    /// Entries deliverable in this bounded batch.
    pub deliverable_entries: u32,
    /// Whether this batch reaches the cursor's immutable upper bound.
    pub caught_up: bool,
    /// Cursor position after this batch is delivered.
    pub resume_position: u64,
    /// When the read must wake at the latest (deadline or cursor expiry).
    pub wake_at: TimestampNs,
}

/// Admits one bounded `session.follow` read over an exact continuation cursor
/// (AOP-004).
///
/// Fails closed unless:
/// - the cursor drives a registered `FollowStream` scope ([`ContinuationError::WrongStream`]);
/// - the cursor is unexpired at `now` ([`ContinuationError::Expired`]);
/// - the cursor position is within its immutable bound ([`ContinuationError::OutOfRange`]);
/// - the wake contract is bounded ([`ContinuationError::UnboundedWake`]); and
/// - the wake deadline lies within the cursor's validated lifetime
///   ([`ContinuationError::WakeBeyondExpiry`]).
///
/// The deliverable batch is the smaller of the wake budget and the entries
/// remaining before the cursor's upper bound; `caught_up` reports whether the
/// batch reaches that bound.
pub fn admit_follow_read(
    cursor: &ContinuationCursor,
    wake: FollowWakeContract,
    now: TimestampNs,
) -> Result<FollowBatchPlan, ContinuationError> {
    if cursor.scope != ContinuationScope::FollowStream {
        return Err(ContinuationError::WrongStream);
    }
    cursor.validate_at(now)?;
    if wake.max_entries() == 0 {
        return Err(ContinuationError::UnboundedWake);
    }
    if wake.deadline() > cursor.expires_at {
        return Err(ContinuationError::WakeBeyondExpiry);
    }
    if cursor.position > cursor.upper_bound {
        return Err(ContinuationError::OutOfRange);
    }
    let remaining = cursor.upper_bound - cursor.position;
    let deliverable = u32::try_from(remaining.min(u64::from(wake.max_entries())))
        .map_err(|_| ContinuationError::OutOfRange)?;
    let resume_position = cursor.position + u64::from(deliverable);
    Ok(FollowBatchPlan {
        deliverable_entries: deliverable,
        caught_up: resume_position == cursor.upper_bound,
        resume_position,
        wake_at: wake.deadline().min(cursor.expires_at),
    })
}

/// Produces the successor cursor after one admitted follow batch delivered
/// `delivered_entries` entries (AOP-004, retry class `resume_from_continuation`).
///
/// The successor links the delivered batch through the predecessor digest and
/// resumes exactly at [`FollowBatchPlan::resume_position`]; the resume anchor
/// must stay within the cursor's lineage and epoch, and expiry can only shrink.
pub fn advance_follow_cursor(
    cursor: &ContinuationCursor,
    delivered_entries: u32,
    new_resume_anchor: LedgerAnchor,
    issued_at: TimestampNs,
    expires_at: TimestampNs,
) -> Result<ContinuationCursor, ContinuationError> {
    if delivered_entries == 0 {
        return Err(ContinuationError::NonMonotone);
    }
    let new_position = cursor
        .position
        .checked_add(u64::from(delivered_entries))
        .ok_or(ContinuationError::OutOfRange)?;
    cursor.advance(
        new_position,
        new_resume_anchor,
        cursor.selection_witness,
        issued_at,
        expires_at,
    )
}

/// Canonical digest domain of one bounded query read receipt.
pub const QUERY_READ_RECEIPT_DIGEST_DOMAIN: &str = "fss.agent.query.read.receipt.v1";

/// Typed receipt of one admitted `query` read (AOP-005).
///
/// A compiled read is complete only within its explicit top-k boundary, so the
/// receipt always reports [`Completeness::Bounded`] and binds the anchor, the
/// entry bound, and the read-relevant cost dimensions. The receipt is a pure
/// read product: it carries no durable artifact and no effect authority.
#[derive(Clone, Debug, PartialEq)]
pub struct QueryReadReceipt {
    operation: AgentOperation,
    anchor: LedgerAnchor,
    max_entries: u32,
    completeness: Completeness,
    cost: BudgetVector,
}

impl QueryReadReceipt {
    /// Returns the resolved operation row (always `AOP-005`).
    #[must_use]
    pub const fn operation(&self) -> AgentOperation {
        self.operation
    }

    /// Returns the exact anchor the read is compiled over (one-anchor scope).
    #[must_use]
    pub const fn anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }

    /// Returns the compiled entry bound.
    #[must_use]
    pub const fn max_entries(&self) -> u32 {
        self.max_entries
    }

    /// Returns the completeness class (always `Bounded` for compiled reads).
    #[must_use]
    pub const fn completeness(&self) -> Completeness {
        self.completeness
    }

    /// Returns the bound cost of the read.
    #[must_use]
    pub const fn cost(&self) -> &BudgetVector {
        &self.cost
    }

    /// Returns the domain-separated canonical digest of this receipt.
    #[must_use]
    pub fn receipt_digest(&self) -> ContentDigest {
        self.canonical_digest(QUERY_READ_RECEIPT_DIGEST_DOMAIN)
    }
}

impl CanonicalEncode for QueryReadReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.operation.name());
        self.anchor.encode_canonical(encoder);
        encoder.u32(self.max_entries);
        self.completeness.encode_canonical(encoder);
        self.cost.encode_canonical(encoder);
    }
}

/// Admits one bounded compiled read (AOP-005 `query`).
///
/// Fail closed unless:
/// - `operation_name` resolves under `basis` to exactly the registered `query`
///   row ([`ContractError::NotFound`] for any other operation - this boundary
///   never compiles reads for other rows); and
/// - the entry bound is at least 1 and the latency cost bound is positive
///   ([`ContractError::BudgetExhausted`]): a compiled read that admits nothing
///   is refused rather than answered with a deceptively complete receipt.
///
/// Refusals are typed [`ContractBasisError`]s; budget refusals ride the
/// `Contract` variant so the stable code of the underlying refusal survives.
pub fn admit_query_read(
    basis: &ContractBasis,
    anchor: &LedgerAnchor,
    operation_name: &str,
    max_entries: u32,
    cost: BudgetVector,
) -> Result<QueryReadReceipt, ContractBasisError> {
    let operation = registered_operation(basis, operation_name)?;
    if operation != AgentOperation::Query {
        return Err(ContractBasisError::Contract(ContractError::NotFound));
    }
    if max_entries == 0 || cost.latency_ms == 0 {
        return Err(ContractBasisError::Contract(ContractError::BudgetExhausted));
    }
    Ok(QueryReadReceipt {
        operation,
        anchor: anchor.clone(),
        max_entries,
        completeness: Completeness::Bounded,
        cost,
    })
}

/// Canonical digest domain of one durable investigation case state.
pub const INVESTIGATION_CASE_DIGEST_DOMAIN: &str = "fss.agent.investigation.case.v1";

/// One durable investigation case (AOP-006 `investigate`, cognition_write).
///
/// Preserves competing alternatives: a case is created with at least two live
/// hypotheses and every disposition advance follows a monotone, one-way
/// transition table - strength decreases and refutation is final. Stopping is
/// refused while any hypothesis is still live, so a case can never coalesce
/// away open alternatives into a false terminal answer.
#[derive(Clone, Debug, PartialEq)]
pub struct InvestigationCaseState {
    case_id: String,
    mission_id: MissionId,
    hypotheses: BTreeMap<String, HypothesisDisposition>,
    terminal: bool,
}

impl InvestigationCaseState {
    /// Creates a durable case with at least two competing live hypotheses.
    pub fn create(
        case_id: impl Into<String>,
        mission_id: MissionId,
        hypotheses: &BTreeSet<String>,
    ) -> Result<Self, ContractError> {
        let case_id = case_id.into();
        if case_id.is_empty() || hypotheses.len() < 2 {
            // A single-hypothesis "case" preserves no alternative to discriminate.
            return Err(ContractError::EvidenceRequired);
        }
        let mut state = BTreeMap::new();
        for hypothesis in hypotheses {
            if hypothesis.is_empty() {
                return Err(ContractError::InvalidIdentifier);
            }
            state.insert(hypothesis.clone(), HypothesisDisposition::Live);
        }
        Ok(Self {
            case_id,
            mission_id,
            hypotheses: state,
            terminal: false,
        })
    }

    /// Returns the stable case identity.
    #[must_use]
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    /// Returns the owning mission.
    #[must_use]
    pub const fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    /// Returns the hypothesis dispositions in canonical (sorted) order.
    #[must_use]
    pub fn hypotheses(&self) -> &BTreeMap<String, HypothesisDisposition> {
        &self.hypotheses
    }

    /// Returns whether the case reached a terminal answer or was superseded.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.terminal
    }

    /// Advances one hypothesis's disposition along the registered transition table.
    ///
    /// Legal one-way moves (registered monotone table, AOP-006):
    /// `live -> supported | disfavored | refuted`, `supported -> disfavored | refuted`,
    /// `disfavored -> refuted`. Refutation is final; no transition ever relabels a
    /// refuted or advanced hypothesis back toward `live`.
    pub fn advance_hypothesis(
        &mut self,
        hypothesis: &str,
        to: HypothesisDisposition,
    ) -> Result<(), ContractError> {
        if self.terminal {
            return Err(ContractError::CaseStopBlocked);
        }
        let current = self
            .hypotheses
            .get(hypothesis)
            .ok_or(ContractError::NotFound)?;
        let legal = matches!(
            (current, to),
            (
                HypothesisDisposition::Live,
                HypothesisDisposition::Supported
            ) | (
                HypothesisDisposition::Live,
                HypothesisDisposition::Disfavored
            ) | (HypothesisDisposition::Live, HypothesisDisposition::Refuted)
                | (
                    HypothesisDisposition::Supported,
                    HypothesisDisposition::Disfavored
                )
                | (
                    HypothesisDisposition::Supported,
                    HypothesisDisposition::Refuted
                )
                | (
                    HypothesisDisposition::Disfavored,
                    HypothesisDisposition::Refuted
                )
        );
        if !legal {
            return Err(ContractError::HypothesisTransitionIllegal);
        }
        self.hypotheses.insert(hypothesis.to_owned(), to);
        Ok(())
    }

    /// Stops the case with a terminal answer.
    ///
    /// Refused while any hypothesis is still live: stopping with open
    /// alternatives would flatten unresolved possibility into a false
    /// terminal disposition.
    pub fn stop(&mut self, resolution: HypothesisDisposition) -> Result<(), ContractError> {
        if self.terminal {
            return Err(ContractError::CaseStopBlocked);
        }
        let live = self
            .hypotheses
            .values()
            .any(|disposition| *disposition == HypothesisDisposition::Live);
        if live {
            return Err(ContractError::CaseStopBlocked);
        }
        if !matches!(
            resolution,
            HypothesisDisposition::Resolved | HypothesisDisposition::Superseded
        ) {
            return Err(ContractError::HypothesisTransitionIllegal);
        }
        self.terminal = true;
        Ok(())
    }

    /// Marks the case superseded by a newer revision. Allowed at any state.
    pub fn supersede(&mut self) -> Result<(), ContractError> {
        if self.terminal {
            return Err(ContractError::CaseStopBlocked);
        }
        self.terminal = true;
        Ok(())
    }

    /// Returns the domain-separated canonical digest of this case state.
    #[must_use]
    pub fn case_digest(&self) -> ContentDigest {
        self.canonical_digest(INVESTIGATION_CASE_DIGEST_DOMAIN)
    }
}

impl CanonicalEncode for InvestigationCaseState {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.case_id);
        encoder.text(self.mission_id.as_str());
        encoder.u32(self.hypotheses.len() as u32);
        for (hypothesis, disposition) in &self.hypotheses {
            encoder.text(hypothesis);
            disposition.encode_canonical(encoder);
        }
        encoder.bool(self.terminal);
    }
}

/// Canonical digest domain of one immutable prepared plan.
pub const PREPARED_PLAN_DIGEST_DOMAIN: &str = "fss.agent.prepared.plan.v1";

/// One immutable step of a prepared plan (AOP-007).
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PreparedPlanStep {
    /// Registered operation this step will request when committed.
    pub operation: AgentOperation,
    /// Stable semantic target identity (`fss://...`).
    pub target: String,
}

impl PreparedPlanStep {
    /// Validates one step: registered operation, stable target spelling.
    pub fn new(
        operation: AgentOperation,
        target: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let target = target.into();
        if !target.starts_with("fss://") {
            return Err(ContractError::InvalidIdentifier);
        }
        operation.validate_row()?;
        Ok(Self { operation, target })
    }
}

/// An immutable witnessed contingent plan compiled by `plan` (AOP-007).
///
/// Preparation never crosses the effect boundary: the plan is a recommendation
/// artifact and carries no effect authority. Steps naming effect rows
/// ([`AgentOperation::Commit`] / [`AgentOperation::Cancel`]) are recorded as
/// contingent and only ever start through `commit` (AOP-008) against a valid
/// affordance; [`requires_commit`](Self::requires_commit) reports that
/// obligation explicitly.
#[derive(Clone, Debug, PartialEq)]
pub struct PreparedPlan {
    plan_id: String,
    objective_id: String,
    steps: Vec<PreparedPlanStep>,
    witnesses: Vec<ContentDigest>,
    plan_digest: ContentDigest,
}

impl PreparedPlan {
    /// Compiles an immutable plan and seals its digest.
    ///
    /// Fails closed on an empty objective, an empty step list, an invalid step,
    /// or unsorted witnesses. Witnesses are normalized to strictly ascending
    /// digest order so the sealed digest is order-deterministic.
    pub fn prepare(
        plan_id: impl Into<String>,
        objective_id: impl Into<String>,
        steps: Vec<PreparedPlanStep>,
        mut witnesses: Vec<ContentDigest>,
    ) -> Result<Self, ContractError> {
        let plan_id = plan_id.into();
        let objective_id = objective_id.into();
        if plan_id.is_empty() || objective_id.is_empty() || steps.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        for step in &steps {
            if !step.target.starts_with("fss://") {
                return Err(ContractError::InvalidIdentifier);
            }
            step.operation.validate_row()?;
        }
        if witnesses.len() > 1 {
            witnesses.sort();
            witnesses.dedup();
        }
        let mut plan = Self {
            plan_id,
            objective_id,
            steps,
            witnesses,
            plan_digest: ContentDigest::sha256(b"unsealed"),
        };
        let mut encoder = CanonicalEncoder::new();
        plan.encode_canonical(&mut encoder);
        plan.plan_digest = ContentDigest::sha256(&encoder.finish());
        Ok(plan)
    }

    /// Returns the stable plan identity.
    #[must_use]
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    /// Returns the objective the plan serves.
    #[must_use]
    pub fn objective_id(&self) -> &str {
        &self.objective_id
    }

    /// Returns the immutable step list in compilation order.
    #[must_use]
    pub fn steps(&self) -> &[PreparedPlanStep] {
        &self.steps
    }

    /// Returns the precondition witness digests (strictly ascending).
    #[must_use]
    pub fn witnesses(&self) -> &[ContentDigest] {
        &self.witnesses
    }

    /// Returns the sealed plan digest (identity of the exact immutable plan).
    #[must_use]
    pub const fn plan_digest(&self) -> ContentDigest {
        self.plan_digest
    }

    /// Returns whether the plan contains contingent effect steps that only
    /// `commit` may start.
    #[must_use]
    pub fn requires_commit(&self) -> bool {
        self.steps.iter().any(|step| step.operation.effectful())
    }

    /// Returns the plan's domain-separated digest under the plan domain.
    #[must_use]
    pub fn sealed_plan_digest(&self) -> ContentDigest {
        self.canonical_digest(PREPARED_PLAN_DIGEST_DOMAIN)
    }
}

impl CanonicalEncode for PreparedPlan {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.plan_id);
        encoder.text(&self.objective_id);
        encoder.u32(self.steps.len() as u32);
        for step in &self.steps {
            encoder.text(step.operation.name());
            encoder.text(&step.target);
        }
        encoder.u32(self.witnesses.len() as u32);
        for witness in &self.witnesses {
            encoder.digest(*witness);
        }
    }
}

/// Canonical digest domain of one commit admission receipt.
pub const COMMIT_RECEIPT_DIGEST_DOMAIN: &str = "fss.agent.commit.receipt.v1";

/// Typed receipt of one admitted `commit` (AOP-008).
///
/// Binds the exact immutable plan digest, the consumed affordance identity,
/// the anchor the admission was evaluated against, and the deterministic start
/// time. The receipt is produced by admission only: terminal proof remains an
/// effect-journal obligation of the started plan.
#[derive(Clone, Debug, PartialEq)]
pub struct CommitReceipt {
    plan_digest: ContentDigest,
    affordance_id: String,
    anchor: LedgerAnchor,
    started_at: TimestampNs,
}

impl CommitReceipt {
    /// Returns the sealed digest of the exact plan being committed.
    #[must_use]
    pub const fn plan_digest(&self) -> ContentDigest {
        self.plan_digest
    }

    /// Returns the consumed affordance identity.
    #[must_use]
    pub fn affordance_id(&self) -> &str {
        &self.affordance_id
    }

    /// Returns the anchor the admission was evaluated against.
    #[must_use]
    pub const fn anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }

    /// Returns the deterministic start time.
    #[must_use]
    pub const fn started_at(&self) -> TimestampNs {
        self.started_at
    }

    /// Returns the domain-separated canonical digest of this receipt.
    #[must_use]
    pub fn receipt_digest(&self) -> ContentDigest {
        self.canonical_digest(COMMIT_RECEIPT_DIGEST_DOMAIN)
    }
}

impl CanonicalEncode for CommitReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.digest(self.plan_digest);
        encoder.text(&self.affordance_id);
        self.anchor.encode_canonical(encoder);
        encoder.i128(self.started_at.0);
    }
}

/// Admits one `commit` of an exact prepared plan through a valid effect
/// affordance (AOP-008).
///
/// Registry rule (`worldEnvelopeRule`): effect operations consume only
/// affordances whose robustness class and named-world basis remain valid at
/// commit. Fail closed unless:
/// - the operation resolves under `basis` to exactly the registered `commit`
///   row (AOP-008);
/// - the affordance names the `commit` operation and targets exactly this
///   plan's identity ([`ContractError::NotFound`]);
/// - the affordance class is consumable at commit ([`ContractError::InvalidEffectTransition`]):
///   `Blocked`/`Unavailable` affordances are not consumable, and `Probe`/`Wait`
///   affordances are not effect affordances at all; and
/// - the affordance names a non-empty supported-world basis
///   ([`ContractError::InvalidEffectTransition`]).
///
/// Committing a plan without contingent effect steps is refused: there is
/// nothing to revalidate and start.
pub fn admit_commit(
    basis: &ContractBasis,
    plan: &PreparedPlan,
    affordance: &ActionAffordance,
    anchor: &LedgerAnchor,
    now: TimestampNs,
) -> Result<CommitReceipt, ContractBasisError> {
    let operation = registered_operation(basis, "commit")?;
    if operation != AgentOperation::Commit {
        return Err(ContractBasisError::Contract(ContractError::NotFound));
    }
    if affordance.operation != "commit" || affordance.target != plan.plan_id() {
        return Err(ContractBasisError::Contract(ContractError::NotFound));
    }
    if !plan.requires_commit() {
        return Err(ContractBasisError::Contract(
            ContractError::InvalidEffectTransition,
        ));
    }
    let consumable = matches!(
        affordance.class,
        AffordanceClass::Robust | AffordanceClass::Conditional
    );
    if !consumable || affordance.supported_worlds.is_empty() {
        return Err(ContractBasisError::Contract(
            ContractError::InvalidEffectTransition,
        ));
    }
    Ok(CommitReceipt {
        plan_digest: plan.plan_digest(),
        affordance_id: affordance.affordance_id.clone(),
        anchor: anchor.clone(),
        started_at: now,
    })
}

/// Bounded wake contract of one `wait` read (AOP-009).
///
/// A wait is always deadline-bounded: waking in the past or without a
/// deadline is refused. The deadline is absolute, matching the registry wake
/// rule "observe ... until a predicate, deadline, or meaningful delta fires".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitWakeContract {
    deadline: TimestampNs,
    issued_at: TimestampNs,
}

impl WaitWakeContract {
    /// Validates and constructs a wait wake contract.
    pub fn new(deadline: TimestampNs, now: TimestampNs) -> Result<Self, ContractError> {
        if deadline <= now {
            return Err(ContractError::InvertedTimeInterval);
        }
        Ok(Self {
            deadline,
            issued_at: now,
        })
    }

    /// Returns the absolute wake deadline.
    #[must_use]
    pub const fn deadline(&self) -> TimestampNs {
        self.deadline
    }

    /// Returns the issue time.
    #[must_use]
    pub const fn issued_at(&self) -> TimestampNs {
        self.issued_at
    }
}

/// What woke one `wait` read (AOP-009).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitWake {
    /// The observed predicate fired before the deadline.
    PredicateFired,
    /// The deadline elapsed without the predicate firing.
    DeadlineReached,
}

/// Gates a wait retry on effect reconciliation (AOP-009, retry class
/// `reconciliation_required`).
///
/// Waking with an indeterminate effect outcome and retrying without a
/// recorded reconciliation basis would coalesce effect uncertainty into a
/// fresh attempt; that transition is refused until the caller binds the
/// reconciliation (compensation or verified-no-effect) basis.
pub fn require_reconciliation_before_retry(
    outcome: RuntimeOutcome,
    reconciled: Option<&ReconciliationBasis>,
) -> Result<(), ContractError> {
    if outcome == RuntimeOutcome::Indeterminate && reconciled.is_none() {
        return Err(ContractError::InvalidEffectTransition);
    }
    Ok(())
}

/// Stages of a `cancel` lifecycle (AOP-010, lifecycle_effect).
///
/// The registered order is request -> drain -> finalize; no stage may be
/// skipped, and finalization preserves the intent digest so the durable
/// record of the cancelled work is never erased.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CancelStage {
    /// Cancellation was requested; owned work must drain.
    Requested,
    /// Owned work is draining; no new effect steps may start.
    Draining,
    /// Drain completed; reconciliation or compensation was recorded.
    Finalized,
}

impl CancelStage {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Draining => "draining",
            Self::Finalized => "finalized",
        }
    }
}

/// Durable record of one `cancel` lifecycle over one effect intent (AOP-010).
///
/// The intent digest is pinned at request time and every stage transition is
/// folded into the running record digest: the cancelled work stays provable
/// after finalization (nothing erases the durable record).
#[derive(Clone, Debug, PartialEq)]
pub struct CancellationRecord {
    intent_digest: ContentDigest,
    stage: CancelStage,
    record_digest: ContentDigest,
}

impl CancellationRecord {
    /// Opens a cancellation request over one effect intent.
    pub fn request(intent_digest: ContentDigest, now: TimestampNs) -> Self {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("requested");
        encoder.digest(intent_digest);
        encoder.i128(now.0);
        Self {
            intent_digest,
            stage: CancelStage::Requested,
            record_digest: ContentDigest::sha256(&encoder.finish()),
        }
    }

    /// Returns the pinned effect intent digest.
    #[must_use]
    pub const fn intent_digest(&self) -> ContentDigest {
        self.intent_digest
    }

    /// Returns the current stage.
    #[must_use]
    pub const fn stage(&self) -> CancelStage {
        self.stage
    }

    /// Returns the running durable record digest.
    #[must_use]
    pub const fn record_digest(&self) -> ContentDigest {
        self.record_digest
    }

    /// Advances to the next stage.
    ///
    /// Drain must precede finalize; finalizing closes the lifecycle and
    /// folds the closing time into the record digest. Any skip is refused as
    /// an invalid effect transition.
    pub fn advance(&mut self, now: TimestampNs) -> Result<(), ContractError> {
        let next = match self.stage {
            CancelStage::Requested => CancelStage::Draining,
            CancelStage::Draining => CancelStage::Finalized,
            CancelStage::Finalized => return Err(ContractError::InvalidEffectTransition),
        };
        self.stage = next;
        let mut encoder = CanonicalEncoder::new();
        encoder.digest(self.record_digest);
        encoder.text(next.as_str());
        encoder.i128(now.0);
        self.record_digest = ContentDigest::sha256(&encoder.finish());
        Ok(())
    }
}

/// One bounded `explain` answer (AOP-011, read_compute).
///
/// Binds the question kind, the exact subject digest, a bounded minimal
/// evidence subgraph in strictly ascending order, and bounded expansion
/// handles. Pure read product: non-durable, no effect authority.
#[derive(Clone, Debug, PartialEq)]
pub struct ExplainReceipt {
    question: ExplainQuestion,
    subject: ContentDigest,
    evidence_subgraph: Vec<ContentDigest>,
    expansion_handles: Vec<String>,
}

/// The registered explain question kinds (AOP-011).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExplainQuestion {
    /// Why did the subject happen or hold?
    Why,
    /// Why did the subject not happen?
    WhyNot,
    /// What changed about the subject?
    WhatChanged,
    /// What would change under a hypothetical branch?
    WhatIf,
}

impl ExplainQuestion {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Why => "why",
            Self::WhyNot => "why_not",
            Self::WhatChanged => "what_changed",
            Self::WhatIf => "what_if",
        }
    }
}

/// Canonical digest domain of one explain receipt.
pub const EXPLAIN_RECEIPT_DIGEST_DOMAIN: &str = "fss.agent.explain.receipt.v1";

impl ExplainReceipt {
    /// Compiles a bounded explanation receipt.
    ///
    /// Fails closed on an empty subject subgraph (an explanation with no
    /// evidence is an unanchored claim) or unsorted input; the subgraph is
    /// normalized to strictly ascending order.
    pub fn compile(
        question: ExplainQuestion,
        subject: ContentDigest,
        mut evidence_subgraph: Vec<ContentDigest>,
        expansion_handles: Vec<String>,
        max_handles: u32,
    ) -> Result<Self, ContractError> {
        if evidence_subgraph.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        evidence_subgraph.sort_unstable();
        evidence_subgraph.dedup();
        let expansion_handles: Vec<String> = expansion_handles
            .into_iter()
            .take(max_handles as usize)
            .collect();
        Ok(Self {
            question,
            subject,
            evidence_subgraph,
            expansion_handles,
        })
    }

    /// Returns the question kind.
    #[must_use]
    pub const fn question(&self) -> ExplainQuestion {
        self.question
    }

    /// Returns the subject digest.
    #[must_use]
    pub const fn subject(&self) -> ContentDigest {
        self.subject
    }

    /// Returns the minimal evidence subgraph (strictly ascending).
    #[must_use]
    pub fn evidence_subgraph(&self) -> &[ContentDigest] {
        &self.evidence_subgraph
    }

    /// Returns the bounded expansion handles.
    #[must_use]
    pub fn expansion_handles(&self) -> &[String] {
        &self.expansion_handles
    }

    /// Returns the domain-separated canonical digest of this receipt.
    #[must_use]
    pub fn receipt_digest(&self) -> ContentDigest {
        self.canonical_digest(EXPLAIN_RECEIPT_DIGEST_DOMAIN)
    }
}

impl CanonicalEncode for ExplainReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.question.as_str());
        encoder.digest(self.subject);
        encoder.u32(self.evidence_subgraph.len() as u32);
        for digest in &self.evidence_subgraph {
            encoder.digest(*digest);
        }
        encoder.u32(self.expansion_handles.len() as u32);
        for handle in &self.expansion_handles {
            encoder.text(handle);
        }
    }
}

/// Admits one `handoff` publication through the registered row (AOP-012).
///
/// Resolves the operation through the fail-closed registered boundary and
/// requires a strictly positive portable lifetime (a zero-lifetime capsule is
/// refused; publication itself reuses the existing root-last
/// [`HandoffCapsule::publish`] with its child-closure and digest rules).
pub fn admit_handoff(
    basis: &ContractBasis,
    params: HandoffPublishParams,
) -> Result<HandoffCapsule, ContractBasisError> {
    let operation = registered_operation(basis, "handoff")?;
    if operation != AgentOperation::Handoff {
        return Err(ContractBasisError::Contract(ContractError::NotFound));
    }
    if params.expires_at <= params.created_at {
        return Err(ContractBasisError::Contract(
            ContractError::InvertedTimeInterval,
        ));
    }
    HandoffCapsule::publish(params).map_err(ContractBasisError::Contract)
}

/// Registered feedback proposal kinds (AOP-013).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackKind {
    /// A correction to a recorded belief or statement.
    Correction,
    /// An outcome signal from executed work.
    OutcomeSignal,
    /// An adjudication of a proposal or contradiction.
    Adjudication,
    /// An evidence-linked learning proposal.
    LearningProposal,
}

impl FeedbackKind {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Correction => "correction",
            Self::OutcomeSignal => "outcome_signal",
            Self::Adjudication => "adjudication",
            Self::LearningProposal => "learning_proposal",
        }
    }
}

/// Canonical digest domain of one feedback proposal.
pub const FEEDBACK_PROPOSAL_DIGEST_DOMAIN: &str = "fss.agent.feedback.proposal.v1";

/// One durable feedback proposal (AOP-013, advisory_write).
///
/// Advisory by construction: the type has no activation path. A proposal
/// records a correction, outcome signal, adjudication, or learning proposal
/// with its evidence; changing active truth or policy requires a separate,
/// explicitly authorized decision - recording a proposal never silently
/// changes anything.
#[derive(Clone, Debug, PartialEq)]
pub struct FeedbackProposal {
    kind: FeedbackKind,
    statement: String,
    evidence: Vec<ContentDigest>,
}

impl FeedbackProposal {
    /// Records a feedback proposal.
    ///
    /// Fails closed without evidence ([`ContractError::EvidenceRequired`] -
    /// every proposal is evidence-linked), an empty statement, or more
    /// evidence entries than the bound. Evidence normalizes to strictly
    /// ascending deduplicated order.
    pub fn record(
        kind: FeedbackKind,
        statement: impl Into<String>,
        mut evidence: Vec<ContentDigest>,
        max_evidence: u32,
    ) -> Result<Self, ContractError> {
        let statement = statement.into();
        if statement.is_empty() {
            return Err(ContractError::InvalidIdentifier);
        }
        if evidence.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        evidence.sort_unstable();
        evidence.dedup();
        evidence.truncate(max_evidence as usize);
        if evidence.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        Ok(Self {
            kind,
            statement,
            evidence,
        })
    }

    /// Returns the proposal kind.
    #[must_use]
    pub const fn kind(&self) -> FeedbackKind {
        self.kind
    }

    /// Returns the proposal statement.
    #[must_use]
    pub fn statement(&self) -> &str {
        &self.statement
    }

    /// Returns the linked evidence (strictly ascending).
    #[must_use]
    pub fn evidence(&self) -> &[ContentDigest] {
        &self.evidence
    }

    /// Returns the domain-separated canonical digest of this proposal.
    #[must_use]
    pub fn proposal_digest(&self) -> ContentDigest {
        self.canonical_digest(FEEDBACK_PROPOSAL_DIGEST_DOMAIN)
    }
}

impl CanonicalEncode for FeedbackProposal {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.kind.as_str());
        encoder.text(&self.statement);
        encoder.u32(self.evidence.len() as u32);
        for digest in &self.evidence {
            encoder.digest(*digest);
        }
    }
}

/// Diagnosed subsystem domains of a doctor report (AOP-014).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DiagnosisDomain {
    /// Deployment layout and custody.
    Deployment,
    /// Evidence integrity and coverage.
    Evidence,
    /// Cognition and hydration consistency.
    Cognition,
    /// Workspace and session continuity.
    Workspace,
    /// Investigation cases.
    Cases,
    /// Obligations and effect uncertainty.
    Obligations,
    /// Protocol and registry consistency.
    Protocol,
}

impl DiagnosisDomain {
    /// Returns the stable registry spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deployment => "deployment",
            Self::Evidence => "evidence",
            Self::Cognition => "cognition",
            Self::Workspace => "workspace",
            Self::Cases => "cases",
            Self::Obligations => "obligations",
            Self::Protocol => "protocol",
        }
    }
}

/// One sealed repair affordance of a doctor report.
///
/// A named identity only: the report can never apply a repair - applying is a
/// separate authorized effect decision outside `doctor`'s prepare-only mode.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RepairAffordance {
    /// Stable affordance identity (`fss://repair/...`).
    pub repair_id: String,
    /// The diagnosed domain the repair addresses.
    pub domain: DiagnosisDomain,
}

/// One durable doctor report (AOP-014, diagnostic_prepare).
///
/// Diagnose-only by construction: unhealthy findings must each carry a sealed
/// repair affordance, healthy findings must carry none, and the type exposes
/// no way to apply anything. The report digest binds every finding and
/// affordance.
#[derive(Clone, Debug, PartialEq)]
pub struct DoctorReport {
    findings: Vec<(DiagnosisDomain, bool)>,
    repairs: Vec<RepairAffordance>,
    report_digest: ContentDigest,
}

/// Canonical digest domain of one doctor report.
pub const DOCTOR_REPORT_DIGEST_DOMAIN: &str = "fss.agent.doctor.report.v1";

impl DoctorReport {
    /// Compiles a diagnosis report.
    ///
    /// Fails closed on duplicate domains ([`ContractError::InvalidIdentifier`])
    /// and on the diagnose-only pairing rules: an unhealthy finding without a
    /// sealed repair affordance ([`ContractError::EvidenceRequired`]) or a
    /// repair affordance addressing a healthy or absent domain
    /// ([`ContractError::InvalidEffectTransition`]). Findings are stored in
    /// canonical domain order; repairs sorted by (domain, id).
    pub fn diagnose(
        findings: Vec<(DiagnosisDomain, bool)>,
        repairs: Vec<RepairAffordance>,
    ) -> Result<Self, ContractError> {
        let mut sorted = findings;
        sorted.sort();
        for pair in sorted.windows(2) {
            if pair[0].0 == pair[1].0 {
                return Err(ContractError::InvalidIdentifier);
            }
        }
        let unhealthy: BTreeSet<DiagnosisDomain> = sorted
            .iter()
            .filter(|(_, healthy)| !healthy)
            .map(|(domain, _)| *domain)
            .collect();
        let mut sorted_repairs = repairs;
        sorted_repairs.sort();
        for (index, repair) in sorted_repairs.iter().enumerate() {
            if !repair.repair_id.starts_with("fss://repair/") {
                return Err(ContractError::InvalidIdentifier);
            }
            if !unhealthy.contains(&repair.domain) {
                return Err(ContractError::InvalidEffectTransition);
            }
            if sorted_repairs[..index]
                .iter()
                .any(|prior| prior.repair_id == repair.repair_id)
            {
                return Err(ContractError::InvalidIdentifier);
            }
        }
        for domain in &unhealthy {
            if !sorted_repairs.iter().any(|repair| &repair.domain == domain) {
                return Err(ContractError::EvidenceRequired);
            }
        }
        let mut report = Self {
            findings: sorted,
            repairs: sorted_repairs,
            report_digest: ContentDigest::sha256(b"unsealed"),
        };
        let mut encoder = CanonicalEncoder::new();
        report.encode_canonical(&mut encoder);
        report.report_digest = ContentDigest::sha256(&encoder.finish());
        Ok(report)
    }

    /// Returns the findings in canonical domain order.
    #[must_use]
    pub fn findings(&self) -> &[(DiagnosisDomain, bool)] {
        &self.findings
    }

    /// Returns the sealed repair affordances.
    #[must_use]
    pub fn repairs(&self) -> &[RepairAffordance] {
        &self.repairs
    }

    /// Returns the sealed report digest.
    #[must_use]
    pub const fn report_digest(&self) -> ContentDigest {
        self.report_digest
    }

    /// Returns the domain-separated canonical digest of this report.
    #[must_use]
    pub fn sealed_report_digest(&self) -> ContentDigest {
        self.canonical_digest(DOCTOR_REPORT_DIGEST_DOMAIN)
    }
}

impl CanonicalEncode for DoctorReport {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u32(self.findings.len() as u32);
        for (domain, healthy) in &self.findings {
            encoder.text(domain.as_str());
            encoder.bool(*healthy);
        }
        encoder.u32(self.repairs.len() as u32);
        for repair in &self.repairs {
            encoder.text(&repair.repair_id);
            encoder.text(repair.domain.as_str());
        }
    }
}
