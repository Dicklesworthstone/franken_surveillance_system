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

use crate::canonical::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder};
use crate::contract::ContractError;
use crate::digest::ContentDigest;
use core::fmt;
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
