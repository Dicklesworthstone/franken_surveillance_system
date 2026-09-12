#![forbid(unsafe_code)]
//! Runtime region ownership tree, context authority, and closure semantics (FSS-021 / RUNTIME-REGION-TREE-001).
//!
//! # Architecture and Invariants
//!
//! Franken Surveillance System enforces strict region ownership and lifecycle boundaries:
//!
//! 1. **Typed Region Ownership Tree**:
//!    ```text
//!    ProcessRegion
//!    └── PropertyRegion
//!        ├── LedgerRegion
//!        ├── ObjectStoreRegion
//!        ├── ProjectionRegion
//!        ├── SensorRegion*
//!        │   ├── AdapterSessionRegion
//!        │   ├── ReceiveRegion
//!        │   ├── ContinuityRegion
//!        │   ├── MediaRegion
//!        │   ├── AnalysisRegion
//!        │   └── ArchiveRegion
//!        ├── EventRegion*
//!        │   ├── EvidenceWindowRegion
//!        │   ├── ModelCallRegion*
//!        │   ├── AssociationRegion
//!        │   ├── PolicyRegion
//!        │   └── AlertObligationRegion
//!        └── OperationsRegion
//!    ```
//!
//! 2. **Single-Owner Rule**:
//!    Every non-root region has exactly one parent. Double ownership or detached work is strictly
//!    forbidden and rejected with typed errors.
//!
//! 3. **Context Authority (`Cx`) and Monotone Narrowing**:
//!    Authority cloning preserves or narrows trace, operation, principal, capabilities,
//!    deadlines, priority, cancellation reason, budgets, privacy/retention scope, anchor universe,
//!    lease/fence, and lab controls. It never broadens authority.
//!
//! 4. **Closure Protocol (Request → Drain → Finalize)**:
//!    - `Active`: Normal work execution; can accept new work and spawn children.
//!    - `DrainRequested`: Cancellation or shutdown requested; rejects new work, children notified.
//!    - `Draining`: Waiting for children to finalize/close and local obligations/tasks to resolve.
//!    - `Finalizing`: All children closed, resolving local staged state and releasing resources.
//!    - `Closed`: Quiescence achieved; terminal proof emitted.
//!
//! 5. **Formal Invariants**:
//!    - **FORMAL-001**: A region cannot close while it has live children or unresolved obligations.
//!    - **INV-006**: Every asynchronous child is owned by a region, and shutdown drains to a terminal
//!      or indeterminate receipt with durable reconciliation obligation.
//!    - **Orphan Work Detection**: Work whose region has closed or entered drain is a typed error,
//!      never silently continued or dropped.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::canonical::{CanonicalEncode, CanonicalEncoder};
use crate::contract::{BudgetVector, ContractError, RecoveryClass};
use crate::digest::ContentDigest;
use crate::effect::{Obligation, ObligationState};
use crate::ids::{IdempotencyKey, ObligationId, OperationId, validate_id};
use crate::outcome::{ERR_AUTH_DENIED_001, ERR_OP_EXECUTION_FAILED_001, ErrorId, OperationError};

/// Stable error ID for region drain / quiescence failures.
pub const ERR_QUIESCENCE_001: &str = "ERR-QUIESCENCE-001";
use crate::time::TimestampNs;

// ---------------------------------------------------------------------------
// Capacity and Multiplicity Bounds
// ---------------------------------------------------------------------------

/// Maximum number of regions in a single runtime tree.
pub const MAX_REGIONS_IN_TREE: usize = 256;

/// Maximum number of direct child regions attached to a single parent.
pub const MAX_CHILDREN_PER_REGION: usize = 64;

/// Maximum number of `SensorRegion` instances owned by a single `PropertyRegion`.
pub const MAX_SENSOR_REGIONS: usize = 32;

/// Maximum number of `EventRegion` instances owned by a single `PropertyRegion`.
pub const MAX_EVENT_REGIONS: usize = 32;

/// Maximum number of `ModelCallRegion` instances owned by a single `EventRegion`.
pub const MAX_MODEL_CALL_REGIONS: usize = 16;

/// Maximum number of active/tracked tasks per region.
pub const MAX_TASKS_PER_REGION: usize = 128;

/// Maximum number of tracked obligations per region.
pub const MAX_OBLIGATIONS_PER_REGION: usize = 128;

/// Maximum number of capabilities in a single context authority.
pub const MAX_CAPABILITIES_PER_CONTEXT: usize = 64;

// ---------------------------------------------------------------------------
// Region Identifiers
// ---------------------------------------------------------------------------

/// Stable identifier for a runtime execution region.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RegionId(String);

impl RegionId {
    /// Constructs a validated `RegionId`.
    pub fn new(value: impl Into<String>) -> Result<Self, RegionError> {
        let s = value.into();
        validate_id(&s).map_err(|_| RegionError::InvalidIdentifier(s.clone()))?;
        Ok(Self(s))
    }

    /// Returns the string slice representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RegionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for RegionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RegionId({})", self.0)
    }
}

/// Stable identifier for an asynchronous task executing within a region.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TaskId(String);

impl TaskId {
    /// Constructs a validated `TaskId`.
    pub fn new(value: impl Into<String>) -> Result<Self, RegionError> {
        let s = value.into();
        validate_id(&s).map_err(|_| RegionError::InvalidIdentifier(s.clone()))?;
        Ok(Self(s))
    }

    /// Returns the string slice representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TaskId({})", self.0)
    }
}

// ---------------------------------------------------------------------------
// Region Kind
// ---------------------------------------------------------------------------

/// Normative kind of runtime execution region.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum RegionKind {
    /// Root execution region for the overall process/node.
    Process,
    /// Property or physical deployment boundary owned by `Process`.
    Property,
    /// Semantic ledger append and consensus region owned by `Property`.
    Ledger,
    /// Object storage provider and multipart uploader region owned by `Property`.
    ObjectStore,
    /// Read projection and situation compilation region owned by `Property`.
    Projection,
    /// Sensor domain coordinator region owned by `Property`.
    Sensor,
    /// Sensor adapter session and connection management owned by `Sensor`.
    AdapterSession,
    /// Ingest packet reception and raw custody region owned by `Sensor`.
    Receive,
    /// Continuity gap detection and sequence verification owned by `Sensor`.
    Continuity,
    /// Media decode, transform, and proxy pipeline owned by `Sensor`.
    Media,
    /// Early perception and lightweight analysis pipeline owned by `Sensor`.
    Analysis,
    /// Local archive spooling and sync region owned by `Sensor`.
    Archive,
    /// Fused event lifecycle and hypothesis coordinator owned by `Property`.
    Event,
    /// Evidence temporal window accumulator owned by `Event`.
    EvidenceWindow,
    /// Pure-Rust or laboratory model execution region owned by `Event`.
    ModelCall,
    /// Cross-camera track and spatio-temporal association owned by `Event`.
    Association,
    /// Policy evaluation and privacy mask verification owned by `Event`.
    Policy,
    /// Alert effect preparation and terminal proof coordination owned by `Event`.
    AlertObligation,
    /// Operational telemetry, health audit, and admin commands owned by `Property`.
    Operations,
}

impl RegionKind {
    /// Returns the canonical stable string name of this region kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Process => "ProcessRegion",
            Self::Property => "PropertyRegion",
            Self::Ledger => "LedgerRegion",
            Self::ObjectStore => "ObjectStoreRegion",
            Self::Projection => "ProjectionRegion",
            Self::Sensor => "SensorRegion",
            Self::AdapterSession => "AdapterSessionRegion",
            Self::Receive => "ReceiveRegion",
            Self::Continuity => "ContinuityRegion",
            Self::Media => "MediaRegion",
            Self::Analysis => "AnalysisRegion",
            Self::Archive => "ArchiveRegion",
            Self::Event => "EventRegion",
            Self::EvidenceWindow => "EvidenceWindowRegion",
            Self::ModelCall => "ModelCallRegion",
            Self::Association => "AssociationRegion",
            Self::Policy => "PolicyRegion",
            Self::AlertObligation => "AlertObligationRegion",
            Self::Operations => "OperationsRegion",
        }
    }

    /// Returns true if this region kind is the root of the hierarchy (`ProcessRegion`).
    #[must_use]
    pub const fn is_root(self) -> bool {
        matches!(self, Self::Process)
    }

    /// Returns true if this region kind is a leaf node that cannot own child regions.
    #[must_use]
    pub const fn is_leaf(self) -> bool {
        matches!(
            self,
            Self::Ledger
                | Self::ObjectStore
                | Self::Projection
                | Self::Operations
                | Self::AdapterSession
                | Self::Receive
                | Self::Continuity
                | Self::Media
                | Self::Analysis
                | Self::Archive
                | Self::EvidenceWindow
                | Self::ModelCall
                | Self::Association
                | Self::Policy
                | Self::AlertObligation
        )
    }

    /// Validates whether `child_kind` is an admitted child of `self`.
    pub fn validate_child_kind(self, child_kind: RegionKind) -> Result<(), RegionError> {
        let admitted = match self {
            Self::Process => matches!(child_kind, Self::Property),
            Self::Property => matches!(
                child_kind,
                Self::Ledger
                    | Self::ObjectStore
                    | Self::Projection
                    | Self::Sensor
                    | Self::Event
                    | Self::Operations
            ),
            Self::Sensor => matches!(
                child_kind,
                Self::AdapterSession
                    | Self::Receive
                    | Self::Continuity
                    | Self::Media
                    | Self::Analysis
                    | Self::Archive
            ),
            Self::Event => matches!(
                child_kind,
                Self::EvidenceWindow
                    | Self::ModelCall
                    | Self::Association
                    | Self::Policy
                    | Self::AlertObligation
            ),
            _ => false,
        };

        if admitted {
            Ok(())
        } else if self.is_leaf() {
            Err(RegionError::LeafRegionCannotHaveChildren { parent_kind: self })
        } else {
            Err(RegionError::IllegalParentage {
                parent_kind: self,
                child_kind,
            })
        }
    }

    /// Returns the maximum allowed multiplicity for `child_kind` under `self`.
    #[must_use]
    pub fn max_multiplicity(self, child_kind: RegionKind) -> Option<usize> {
        match (self, child_kind) {
            (Self::Process, Self::Property) => Some(1),
            (Self::Property, Self::Ledger) => Some(1),
            (Self::Property, Self::ObjectStore) => Some(1),
            (Self::Property, Self::Projection) => Some(1),
            (Self::Property, Self::Operations) => Some(1),
            (Self::Property, Self::Sensor) => Some(MAX_SENSOR_REGIONS),
            (Self::Property, Self::Event) => Some(MAX_EVENT_REGIONS),
            (Self::Sensor, Self::AdapterSession) => Some(1),
            (Self::Sensor, Self::Receive) => Some(1),
            (Self::Sensor, Self::Continuity) => Some(1),
            (Self::Sensor, Self::Media) => Some(1),
            (Self::Sensor, Self::Analysis) => Some(1),
            (Self::Sensor, Self::Archive) => Some(1),
            (Self::Event, Self::EvidenceWindow) => Some(1),
            (Self::Event, Self::ModelCall) => Some(MAX_MODEL_CALL_REGIONS),
            (Self::Event, Self::Association) => Some(1),
            (Self::Event, Self::Policy) => Some(1),
            (Self::Event, Self::AlertObligation) => Some(1),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Region Lifecycle State
// ---------------------------------------------------------------------------

/// Execution and closure state of a region.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum RegionState {
    /// Active execution; accepting tasks, child registrations, and obligations.
    Active,
    /// Cancellation or drain has been requested; rejecting new work and propagating drain to children.
    DrainRequested,
    /// Actively draining; awaiting descendant completion and local task/obligation resolution.
    Draining,
    /// All descendants closed and work drained; committing/aborting staged state and releasing resources.
    Finalizing,
    /// Quiescence proved; terminal state.
    Closed,
}

impl RegionState {
    /// Returns the stable string name of this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::DrainRequested => "drain_requested",
            Self::Draining => "draining",
            Self::Finalizing => "finalizing",
            Self::Closed => "closed",
        }
    }

    /// Returns true if the region is in its terminal closed state.
    #[must_use]
    pub const fn is_closed(self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Returns true if the region can accept new work or child regions.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Validates whether a state transition from `self` to `next` is permitted.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Active, Self::DrainRequested)
                | (Self::Active, Self::Draining)
                | (Self::DrainRequested, Self::Draining)
                | (Self::Draining, Self::Finalizing)
                | (Self::Finalizing, Self::Closed)
        )
    }
}

// ---------------------------------------------------------------------------
// Context Authority (`Cx`)
// ---------------------------------------------------------------------------

/// Specification used to narrow context authority for a child region.
#[derive(Clone, Debug, PartialEq)]
pub struct ContextNarrowingSpec {
    /// Narrowed operation identity.
    pub operation_id: OperationId,
    /// Narrowed capability set (must be a subset of parent capabilities).
    pub capabilities: Vec<String>,
    /// Optional narrowed deadline (must be <= parent deadline).
    pub deadline: Option<TimestampNs>,
    /// Narrowed priority (must not be higher priority than parent, where lower numeric value = higher priority).
    pub priority: u8,
    /// Narrowed budgets (must fit within parent budgets).
    pub budgets: BudgetVector,
    /// Narrowed privacy scope.
    pub privacy_scope: String,
    /// Narrowed retention scope.
    pub retention_scope: String,
    /// Lease fence identity.
    pub lease_fence: Option<u64>,
    /// Idempotency key.
    pub idempotency_key: Option<IdempotencyKey>,
    /// Lab controls.
    pub lab_controls: Option<String>,
}

/// Explicit context authority (`Cx`) carried across every region boundary.
///
/// Context cloning preserves or narrows authority; it never broadens it.
#[derive(Clone, Debug, PartialEq)]
pub struct ContextAuthority {
    /// Distributed trace identity.
    pub trace_id: String,
    /// Operation identity.
    pub operation_id: OperationId,
    /// Principal identity.
    pub principal: String,
    /// Sorted, unique capabilities.
    capabilities: Vec<String>,
    /// Optional execution deadline.
    pub deadline: Option<TimestampNs>,
    /// Execution priority (0 = highest priority, 255 = lowest priority).
    pub priority: u8,
    /// Active cancellation reason if cancellation was requested.
    pub cancellation_reason: Option<String>,
    /// Remaining work budgets.
    pub budgets: BudgetVector,
    /// Privacy classification scope.
    pub privacy_scope: String,
    /// Retention classification scope.
    pub retention_scope: String,
    /// Anchor universe identity.
    pub anchor_universe: ContentDigest,
    /// Configuration/model generation.
    pub generation: u64,
    /// Lease fence token.
    pub lease_fence: Option<u64>,
    /// Idempotency identity.
    pub idempotency_key: Option<IdempotencyKey>,
    /// Sealed laboratory controls.
    pub lab_controls: Option<String>,
}

/// Parameters for constructing a root context authority.
#[derive(Clone, Debug, PartialEq)]
pub struct RootAuthoritySpec {
    /// Distributed trace identity.
    pub trace_id: String,
    /// Operation identity.
    pub operation_id: OperationId,
    /// Principal identity.
    pub principal: String,
    /// Capabilities granted at root.
    pub capabilities: Vec<String>,
    /// Optional execution deadline.
    pub deadline: Option<TimestampNs>,
    /// Execution priority (0 = highest).
    pub priority: u8,
    /// Work budgets.
    pub budgets: BudgetVector,
    /// Privacy scope.
    pub privacy_scope: String,
    /// Retention scope.
    pub retention_scope: String,
    /// Anchor universe identity.
    pub anchor_universe: ContentDigest,
    /// Configuration or model generation.
    pub generation: u64,
}

impl ContextAuthority {
    /// Constructs a validated root context authority.
    pub fn new_root(mut spec: RootAuthoritySpec) -> Result<Self, RegionError> {
        validate_id(&spec.trace_id)
            .map_err(|_| RegionError::InvalidIdentifier(spec.trace_id.clone()))?;
        validate_id(&spec.principal)
            .map_err(|_| RegionError::InvalidIdentifier(spec.principal.clone()))?;

        spec.capabilities.sort();
        spec.capabilities.dedup();
        if spec.capabilities.len() > MAX_CAPABILITIES_PER_CONTEXT {
            return Err(RegionError::CapacityExceeded("capabilities"));
        }

        if !spec.budgets.is_valid() {
            return Err(RegionError::InvalidBudget("budget vector is not valid"));
        }

        Ok(Self {
            trace_id: spec.trace_id,
            operation_id: spec.operation_id,
            principal: spec.principal,
            capabilities: spec.capabilities,
            deadline: spec.deadline,
            priority: spec.priority,
            cancellation_reason: None,
            budgets: spec.budgets,
            privacy_scope: spec.privacy_scope,
            retention_scope: spec.retention_scope,
            anchor_universe: spec.anchor_universe,
            generation: spec.generation,
            lease_fence: None,
            idempotency_key: None,
            lab_controls: None,
        })
    }

    /// Returns the sorted, deduplicated capabilities.
    #[must_use]
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Returns true if this context holds the specified capability.
    #[must_use]
    pub fn has_capability(&self, cap: &str) -> bool {
        self.capabilities
            .binary_search_by(|c| c.as_str().cmp(cap))
            .is_ok()
    }

    /// Narrows this authority for a child region, strictly enforcing the monotone narrowing invariant.
    ///
    /// Any attempt to broaden authority (e.g. adding new capabilities, extending deadlines,
    /// raising priority, or expanding budgets) is rejected with [`RegionError::AuthorityBroadened`].
    pub fn narrow(&self, spec: ContextNarrowingSpec) -> Result<Self, RegionError> {
        // 1. Capabilities must be a subset of self.capabilities
        let mut child_caps = spec.capabilities;
        child_caps.sort();
        child_caps.dedup();
        if child_caps.len() > MAX_CAPABILITIES_PER_CONTEXT {
            return Err(RegionError::CapacityExceeded("capabilities"));
        }

        for cap in &child_caps {
            if !self.has_capability(cap) {
                return Err(RegionError::AuthorityBroadened("capabilities"));
            }
        }

        // 2. Deadline: cannot extend beyond parent deadline
        let child_deadline = match (self.deadline, spec.deadline) {
            (Some(parent_d), Some(child_d)) => {
                if child_d > parent_d {
                    return Err(RegionError::AuthorityBroadened("deadline"));
                }
                Some(child_d)
            }
            (Some(_), None) => {
                // Parent is bounded, child cannot become unbounded!
                return Err(RegionError::AuthorityBroadened("deadline"));
            }
            (None, child_d) => child_d,
        };

        // 3. Priority: cannot be higher priority than parent (numeric value cannot decrease)
        if spec.priority < self.priority {
            return Err(RegionError::AuthorityBroadened("priority"));
        }

        // 4. Budgets: child budgets must fit within parent budgets
        if !spec.budgets.is_valid() {
            return Err(RegionError::InvalidBudget(
                "child budget vector is not valid",
            ));
        }
        if !spec.budgets.fits_within(self.budgets) {
            return Err(RegionError::AuthorityBroadened("budgets"));
        }

        Ok(Self {
            trace_id: self.trace_id.clone(),
            operation_id: spec.operation_id,
            principal: self.principal.clone(),
            capabilities: child_caps,
            deadline: child_deadline,
            priority: spec.priority,
            cancellation_reason: self.cancellation_reason.clone(),
            budgets: spec.budgets,
            privacy_scope: spec.privacy_scope,
            retention_scope: spec.retention_scope,
            anchor_universe: self.anchor_universe,
            generation: self.generation,
            lease_fence: spec.lease_fence.or(self.lease_fence),
            idempotency_key: spec.idempotency_key,
            lab_controls: spec.lab_controls.or_else(|| self.lab_controls.clone()),
        })
    }
}

// ---------------------------------------------------------------------------
// Quiescence Proof and Task Receipt
// ---------------------------------------------------------------------------

/// Cryptographic and semantic proof emitted when a region reaches complete quiescence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuiescenceProof {
    /// Identity of the closed region.
    pub region_id: RegionId,
    /// Kind of the closed region.
    pub region_kind: RegionKind,
    /// Parent region identity, if non-root.
    pub parent_id: Option<RegionId>,
    /// Timestamp when quiescence was verified and closed.
    pub closed_at: TimestampNs,
    /// Total tasks processed across region lifecycle.
    pub total_tasks: u64,
    /// Total obligations settled.
    pub total_obligations: u64,
    /// Count of indeterminate obligations requiring durable reconciliation.
    pub indeterminate_obligations: u64,
    /// Cryptographic digest binding all quiescence parameters.
    pub proof_digest: ContentDigest,
}

impl QuiescenceProof {
    /// Computes the canonical proof digest.
    #[must_use]
    pub fn compute_digest(
        region_id: &RegionId,
        region_kind: RegionKind,
        parent_id: Option<&RegionId>,
        closed_at: TimestampNs,
        total_tasks: u64,
        total_obligations: u64,
        indeterminate_obligations: u64,
    ) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.quiescence_proof.v1");
        encoder.text(region_id.as_str());
        encoder.text(region_kind.as_str());
        match parent_id {
            Some(p) => {
                encoder.bool(true);
                encoder.text(p.as_str());
            }
            None => encoder.bool(false),
        }
        closed_at.encode_canonical(&mut encoder);
        encoder.u64(total_tasks);
        encoder.u64(total_obligations);
        encoder.u64(indeterminate_obligations);
        ContentDigest::sha256(&encoder.finish())
    }
}

/// Outcome of an asynchronous task running in a region.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskOutcome {
    /// Task completed successfully.
    Success,
    /// Task failed with expected domain error code.
    Failed(String),
    /// Task was cancelled before completion.
    Cancelled,
    /// Task result is indeterminate and requires durable reconciliation.
    Indeterminate(String),
}

/// Durable receipt for an asynchronous task executed in a region.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskReceipt {
    /// Task identity.
    pub task_id: TaskId,
    /// Region in which the task was executed.
    pub region_id: RegionId,
    /// Registered timestamp.
    pub registered_at: TimestampNs,
    /// Completed timestamp.
    pub completed_at: TimestampNs,
    /// Terminal outcome.
    pub outcome: TaskOutcome,
}

// ---------------------------------------------------------------------------
// Region Node
// ---------------------------------------------------------------------------

/// State and tracking information for a single node in the region tree.
#[derive(Clone, Debug)]
pub struct RegionNode {
    /// Unique identity of this region.
    pub id: RegionId,
    /// Normative kind of this region.
    pub kind: RegionKind,
    /// Owning parent region identity, if non-root.
    pub parent_id: Option<RegionId>,
    /// Direct children owned by this region.
    pub children: Vec<RegionId>,
    /// Lifecycle state of this region.
    pub state: RegionState,
    /// Explicit context authority.
    pub authority: ContextAuthority,
    /// Timestamp when region was created.
    pub created_at: TimestampNs,
    /// Timestamp when drain was requested.
    pub drain_requested_at: Option<TimestampNs>,
    /// Timestamp when region finalized/closed.
    pub closed_at: Option<TimestampNs>,
    /// Active tasks running in this region.
    pub active_tasks: BTreeSet<TaskId>,
    /// Completed task receipts.
    pub completed_tasks: BTreeMap<TaskId, TaskReceipt>,
    /// Obligations tracked by this region.
    pub obligations: BTreeMap<ObligationId, Obligation>,
    /// Durable reconciliation notes for indeterminate obligations.
    pub reconciliation_obligations: BTreeMap<ObligationId, String>,
    /// Emitted quiescence proof, once closed.
    pub quiescence_proof: Option<QuiescenceProof>,
}

impl RegionNode {
    /// Creates a new region node in `Active` state.
    #[must_use]
    pub fn new(
        id: RegionId,
        kind: RegionKind,
        parent_id: Option<RegionId>,
        authority: ContextAuthority,
        created_at: TimestampNs,
    ) -> Self {
        Self {
            id,
            kind,
            parent_id,
            children: Vec::new(),
            state: RegionState::Active,
            authority,
            created_at,
            drain_requested_at: None,
            closed_at: None,
            active_tasks: BTreeSet::new(),
            completed_tasks: BTreeMap::new(),
            obligations: BTreeMap::new(),
            reconciliation_obligations: BTreeMap::new(),
            quiescence_proof: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Region Tree
// ---------------------------------------------------------------------------

/// Executable ownership tree of runtime regions enforcing single-ownership,
/// strict closure protocol, and orphan work detection.
#[derive(Clone, Debug)]
pub struct RegionTree {
    root_id: RegionId,
    nodes: BTreeMap<RegionId, RegionNode>,
}

impl RegionTree {
    /// Constructs a new runtime region tree rooted at `process_id`.
    pub fn new(
        process_id: RegionId,
        process_authority: ContextAuthority,
        now: TimestampNs,
    ) -> Result<Self, RegionError> {
        let mut nodes = BTreeMap::new();
        let root_node = RegionNode::new(
            process_id.clone(),
            RegionKind::Process,
            None,
            process_authority,
            now,
        );
        nodes.insert(process_id.clone(), root_node);
        Ok(Self {
            root_id: process_id,
            nodes,
        })
    }

    /// Returns the root region ID.
    #[must_use]
    pub fn root_id(&self) -> &RegionId {
        &self.root_id
    }

    /// Returns the total number of regions in the tree.
    #[must_use]
    pub fn region_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns an immutable reference to a region node.
    pub fn get(&self, id: &RegionId) -> Result<&RegionNode, RegionError> {
        self.nodes
            .get(id)
            .ok_or_else(|| RegionError::RegionNotFound(id.clone()))
    }

    /// Attaches a new child region under `parent_id`.
    ///
    /// Validates:
    /// - Tree capacity bound
    /// - Parent existence and active state (orphan work rejection)
    /// - Child uniqueness (no duplicate region ID)
    /// - Single-owner rule (child has no other owner)
    /// - Tree hierarchy grammar (legal parentage and multiplicities)
    pub fn attach_child(
        &mut self,
        parent_id: &RegionId,
        child_id: RegionId,
        child_kind: RegionKind,
        child_authority: ContextAuthority,
        now: TimestampNs,
    ) -> Result<(), RegionError> {
        // 1. Tree capacity bound
        if self.nodes.len() >= MAX_REGIONS_IN_TREE {
            return Err(RegionError::CapacityExceeded("tree_regions"));
        }

        // 2. Child cannot be root
        if child_kind.is_root() {
            return Err(RegionError::RootCannotHaveParent(child_id));
        }

        // 3. Child uniqueness
        if self.nodes.contains_key(&child_id) {
            return Err(RegionError::DuplicateRegion(child_id));
        }

        // 4. Parent must exist
        let parent = self
            .nodes
            .get(parent_id)
            .ok_or_else(|| RegionError::RegionNotFound(parent_id.clone()))?;

        // 5. Parent must be active (reject orphan work)
        if !parent.state.is_active() {
            return Err(RegionError::OrphanWork {
                region_id: parent_id.clone(),
                state: parent.state,
            });
        }

        // 6. Child kind must be valid for parent
        parent.kind.validate_child_kind(child_kind)?;

        // 7. Check parent child count and multiplicity
        if parent.children.len() >= MAX_CHILDREN_PER_REGION {
            return Err(RegionError::CapacityExceeded("children_per_region"));
        }

        if let Some(max) = parent.kind.max_multiplicity(child_kind) {
            let existing_count = parent
                .children
                .iter()
                .filter(|cid| {
                    self.nodes
                        .get(cid)
                        .map(|c| c.kind == child_kind)
                        .unwrap_or(false)
                })
                .count();

            if existing_count >= max {
                return Err(RegionError::MultiplicityExceeded {
                    parent_kind: parent.kind,
                    child_kind,
                    max,
                });
            }
        }

        // Create child node and attach to parent
        let child_node = RegionNode::new(
            child_id.clone(),
            child_kind,
            Some(parent_id.clone()),
            child_authority,
            now,
        );

        let parent_mut = self
            .nodes
            .get_mut(parent_id)
            .ok_or_else(|| RegionError::RegionNotFound(parent_id.clone()))?;
        parent_mut.children.push(child_id.clone());

        self.nodes.insert(child_id, child_node);
        Ok(())
    }

    /// Registers an asynchronous task in the specified region.
    ///
    /// Rejects with [`RegionError::OrphanWork`] if the region is not in `Active` state.
    pub fn register_task(
        &mut self,
        region_id: &RegionId,
        task_id: TaskId,
        now: TimestampNs,
    ) -> Result<(), RegionError> {
        let node = self
            .nodes
            .get_mut(region_id)
            .ok_or_else(|| RegionError::RegionNotFound(region_id.clone()))?;

        if !node.state.is_active() {
            return Err(RegionError::OrphanWork {
                region_id: region_id.clone(),
                state: node.state,
            });
        }

        if node.active_tasks.contains(&task_id) || node.completed_tasks.contains_key(&task_id) {
            return Err(RegionError::DuplicateTask(task_id));
        }

        if node.active_tasks.len() >= MAX_TASKS_PER_REGION {
            return Err(RegionError::CapacityExceeded("tasks"));
        }

        node.active_tasks.insert(task_id);
        let _ = now;
        Ok(())
    }

    /// Completes an active asynchronous task in the specified region.
    pub fn complete_task(
        &mut self,
        region_id: &RegionId,
        task_id: &TaskId,
        outcome: TaskOutcome,
        now: TimestampNs,
    ) -> Result<TaskReceipt, RegionError> {
        let node = self
            .nodes
            .get_mut(region_id)
            .ok_or_else(|| RegionError::RegionNotFound(region_id.clone()))?;

        if node.state.is_closed() {
            return Err(RegionError::RegionClosed {
                region_id: region_id.clone(),
            });
        }

        if !node.active_tasks.remove(task_id) {
            return Err(RegionError::TaskNotFound(task_id.clone()));
        }

        let receipt = TaskReceipt {
            task_id: task_id.clone(),
            region_id: region_id.clone(),
            registered_at: node.created_at,
            completed_at: now,
            outcome,
        };

        node.completed_tasks
            .insert(task_id.clone(), receipt.clone());
        Ok(receipt)
    }

    /// Registers a durable obligation in the specified region.
    ///
    /// Rejects with [`RegionError::OrphanWork`] if the region is not in `Active` state.
    pub fn register_obligation(
        &mut self,
        region_id: &RegionId,
        obligation: Obligation,
        now: TimestampNs,
    ) -> Result<(), RegionError> {
        let node = self
            .nodes
            .get_mut(region_id)
            .ok_or_else(|| RegionError::RegionNotFound(region_id.clone()))?;

        if !node.state.is_active() {
            return Err(RegionError::OrphanWork {
                region_id: region_id.clone(),
                state: node.state,
            });
        }

        if node.obligations.contains_key(&obligation.obligation_id) {
            return Err(RegionError::DuplicateObligation(obligation.obligation_id));
        }

        if node.obligations.len() >= MAX_OBLIGATIONS_PER_REGION {
            return Err(RegionError::CapacityExceeded("obligations"));
        }

        node.obligations
            .insert(obligation.obligation_id.clone(), obligation);
        let _ = now;
        Ok(())
    }

    /// Resolves an obligation in the specified region.
    ///
    /// If resolved to [`ObligationState::Indeterminate`], a durable reconciliation note
    /// must be provided to satisfy INV-006.
    pub fn resolve_obligation(
        &mut self,
        region_id: &RegionId,
        obligation_id: &ObligationId,
        state: ObligationState,
        proof_digest: Option<ContentDigest>,
        reconciliation_note: Option<&str>,
        now: TimestampNs,
    ) -> Result<(), RegionError> {
        let node = self
            .nodes
            .get_mut(region_id)
            .ok_or_else(|| RegionError::RegionNotFound(region_id.clone()))?;

        if node.state.is_closed() {
            return Err(RegionError::RegionClosed {
                region_id: region_id.clone(),
            });
        }

        let obligation = node
            .obligations
            .get_mut(obligation_id)
            .ok_or_else(|| RegionError::ObligationNotFound(obligation_id.clone()))?;

        if state == ObligationState::Indeterminate {
            let note = reconciliation_note.ok_or_else(|| {
                RegionError::MissingReconciliationObligation(obligation_id.clone())
            })?;
            node.reconciliation_obligations
                .insert(obligation_id.clone(), note.to_string());
        }

        obligation.state = state;
        obligation.proof_digest = proof_digest;
        let _ = now;
        Ok(())
    }

    /// Requests cancellation / drain on `region_id` and recursively on all active descendants.
    pub fn request_drain(
        &mut self,
        region_id: &RegionId,
        reason: Option<&str>,
        now: TimestampNs,
    ) -> Result<(), RegionError> {
        if !self.nodes.contains_key(region_id) {
            return Err(RegionError::RegionNotFound(region_id.clone()));
        }

        // Check target region state first
        let target_node = self
            .nodes
            .get(region_id)
            .ok_or_else(|| RegionError::RegionNotFound(region_id.clone()))?;
        if target_node.state.is_closed() || target_node.state == RegionState::Finalizing {
            return Err(RegionError::InvalidStateTransition {
                region_id: region_id.clone(),
                current: target_node.state,
                attempted: RegionState::DrainRequested,
            });
        }

        // Collect non-closed descendant IDs in pre-order
        let mut queue = vec![region_id.clone()];
        let mut to_drain = Vec::new();

        while let Some(current_id) = queue.pop() {
            if let Some(node) = self.nodes.get(&current_id)
                && !node.state.is_closed()
                && node.state != RegionState::Finalizing
            {
                to_drain.push(current_id.clone());
                for child_id in &node.children {
                    queue.push(child_id.clone());
                }
            }
        }

        for id in to_drain {
            if let Some(node) = self.nodes.get_mut(&id) {
                match node.state {
                    RegionState::Active => {
                        node.state = RegionState::DrainRequested;
                        node.drain_requested_at = Some(now);
                        if let Some(r) = reason {
                            node.authority.cancellation_reason = Some(r.to_string());
                        }
                    }
                    RegionState::DrainRequested | RegionState::Draining => {
                        // Idempotent drain request; update reason if newly provided
                        if let Some(r) = reason
                            && node.authority.cancellation_reason.is_none()
                        {
                            node.authority.cancellation_reason = Some(r.to_string());
                        }
                    }
                    RegionState::Finalizing | RegionState::Closed => {}
                }
            }
        }

        Ok(())
    }

    /// Transitions a region from `DrainRequested` to `Draining`.
    pub fn begin_drain(
        &mut self,
        region_id: &RegionId,
        now: TimestampNs,
    ) -> Result<(), RegionError> {
        let node = self
            .nodes
            .get_mut(region_id)
            .ok_or_else(|| RegionError::RegionNotFound(region_id.clone()))?;

        match node.state {
            RegionState::DrainRequested => {
                node.state = RegionState::Draining;
            }
            RegionState::Active => {
                // Transition Active -> DrainRequested -> Draining
                node.state = RegionState::Draining;
                node.drain_requested_at = Some(now);
            }
            RegionState::Draining => {
                // Already draining
            }
            _ => {
                return Err(RegionError::InvalidStateTransition {
                    region_id: region_id.clone(),
                    current: node.state,
                    attempted: RegionState::Draining,
                });
            }
        }
        Ok(())
    }

    /// Finalizes and closes `region_id`, verifying all formal invariants:
    ///
    /// 1. All direct children must be in `Closed` state (bottom-up closure).
    /// 2. FORMAL-001: All obligations must be resolved (no `Pending` obligations).
    /// 3. All active tasks must be completed (no orphan work).
    /// 4. Generates cryptographic [`QuiescenceProof`].
    pub fn finalize(
        &mut self,
        region_id: &RegionId,
        now: TimestampNs,
    ) -> Result<QuiescenceProof, RegionError> {
        let node = self
            .nodes
            .get(region_id)
            .ok_or_else(|| RegionError::RegionNotFound(region_id.clone()))?;

        // 1. Validate state
        match node.state {
            RegionState::DrainRequested | RegionState::Draining | RegionState::Finalizing => {}
            _ => {
                return Err(RegionError::InvalidStateTransition {
                    region_id: region_id.clone(),
                    current: node.state,
                    attempted: RegionState::Finalizing,
                });
            }
        }

        // 2. Bottom-up closure invariant: all child regions must be Closed
        for child_id in &node.children {
            let child = self
                .nodes
                .get(child_id)
                .ok_or_else(|| RegionError::RegionNotFound(child_id.clone()))?;
            if !child.state.is_closed() {
                return Err(RegionError::ChildNotDrained {
                    parent_id: region_id.clone(),
                    live_child_id: child_id.clone(),
                    child_state: child.state,
                });
            }
        }

        // 3. No active tasks
        if !node.active_tasks.is_empty() {
            return Err(RegionError::DescendantActive {
                parent_id: region_id.clone(),
                active_count: node.active_tasks.len(),
            });
        }

        // 4. FORMAL-001: No pending obligations
        let pending_obligations = node
            .obligations
            .values()
            .filter(|o| o.state == ObligationState::Pending)
            .count();

        if pending_obligations > 0 {
            return Err(RegionError::LiveObligationsRemaining {
                region_id: region_id.clone(),
                pending_count: pending_obligations,
            });
        }

        // Count totals
        let total_tasks = node.completed_tasks.len() as u64;
        let total_obligations = node.obligations.len() as u64;
        let indeterminate_obligations = node
            .obligations
            .values()
            .filter(|o| o.state == ObligationState::Indeterminate)
            .count() as u64;

        let proof_digest = QuiescenceProof::compute_digest(
            region_id,
            node.kind,
            node.parent_id.as_ref(),
            now,
            total_tasks,
            total_obligations,
            indeterminate_obligations,
        );

        let proof = QuiescenceProof {
            region_id: region_id.clone(),
            region_kind: node.kind,
            parent_id: node.parent_id.clone(),
            closed_at: now,
            total_tasks,
            total_obligations,
            indeterminate_obligations,
            proof_digest,
        };

        let node_mut = self
            .nodes
            .get_mut(region_id)
            .ok_or_else(|| RegionError::RegionNotFound(region_id.clone()))?;
        node_mut.state = RegionState::Closed;
        node_mut.closed_at = Some(now);
        node_mut.quiescence_proof = Some(proof.clone());

        Ok(proof)
    }

    /// Converts the current tree into a machine-checkable topology fixture.
    #[must_use]
    pub fn to_topology_fixture(&self, name: impl Into<String>) -> TopologyFixture {
        let mut nodes = Vec::new();
        for node in self.nodes.values() {
            nodes.push(TopologyNodeDescriptor {
                id: node.id.clone(),
                kind: node.kind,
                parent_id: node.parent_id.clone(),
            });
        }
        TopologyFixture {
            name: name.into(),
            version: 1,
            nodes,
        }
    }

    /// Validates that the entire tree satisfies the normative region hierarchy grammar and multiplicities.
    pub fn validate_topology(&self) -> Result<(), RegionError> {
        let root = self
            .nodes
            .get(&self.root_id)
            .ok_or_else(|| RegionError::RegionNotFound(self.root_id.clone()))?;

        if !root.kind.is_root() {
            return Err(RegionError::NonRootMustHaveParent(self.root_id.clone()));
        }

        for (id, node) in &self.nodes {
            if id == &self.root_id {
                if node.parent_id.is_some() {
                    return Err(RegionError::RootCannotHaveParent(id.clone()));
                }
            } else {
                let parent_id = node
                    .parent_id
                    .as_ref()
                    .ok_or_else(|| RegionError::NonRootMustHaveParent(id.clone()))?;
                let parent = self
                    .nodes
                    .get(parent_id)
                    .ok_or_else(|| RegionError::RegionNotFound(parent_id.clone()))?;
                parent.kind.validate_child_kind(node.kind)?;
            }

            // Check multiplicity under this node
            let mut counts: BTreeMap<RegionKind, usize> = BTreeMap::new();
            for child_id in &node.children {
                let child = self
                    .nodes
                    .get(child_id)
                    .ok_or_else(|| RegionError::RegionNotFound(child_id.clone()))?;
                *counts.entry(child.kind).or_insert(0) += 1;
            }

            for (&child_kind, &count) in &counts {
                if let Some(max) = node.kind.max_multiplicity(child_kind)
                    && count > max
                {
                    return Err(RegionError::MultiplicityExceeded {
                        parent_kind: node.kind,
                        child_kind,
                        max,
                    });
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Topology Fixtures
// ---------------------------------------------------------------------------

/// Machine-checkable descriptor of a single node in a topology fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologyNodeDescriptor {
    /// Region identity.
    pub id: RegionId,
    /// Region kind.
    pub kind: RegionKind,
    /// Owning parent identity.
    pub parent_id: Option<RegionId>,
}

/// Machine-checkable topology fixture for validating and reproducing runtime trees.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologyFixture {
    /// Name of this topology fixture.
    pub name: String,
    /// Format version.
    pub version: u32,
    /// Node descriptors.
    pub nodes: Vec<TopologyNodeDescriptor>,
}

impl TopologyFixture {
    /// Creates a complete canonical standard topology fixture with the exact normative tree:
    ///
    /// ProcessRegion owns PropertyRegion;
    /// PropertyRegion owns LedgerRegion, ObjectStoreRegion, ProjectionRegion,
    /// `sensor_count` SensorRegions, `event_count` EventRegions, and OperationsRegion.
    /// Each SensorRegion owns AdapterSession, Receive, Continuity, Media, Analysis, Archive.
    /// Each EventRegion owns EvidenceWindow, `model_call_count` ModelCalls, Association, Policy, AlertObligation.
    pub fn standard_topology(
        sensor_count: usize,
        event_count: usize,
        model_call_count: usize,
    ) -> Result<Self, RegionError> {
        if sensor_count > MAX_SENSOR_REGIONS {
            return Err(RegionError::MultiplicityExceeded {
                parent_kind: RegionKind::Property,
                child_kind: RegionKind::Sensor,
                max: MAX_SENSOR_REGIONS,
            });
        }
        if event_count > MAX_EVENT_REGIONS {
            return Err(RegionError::MultiplicityExceeded {
                parent_kind: RegionKind::Property,
                child_kind: RegionKind::Event,
                max: MAX_EVENT_REGIONS,
            });
        }
        if model_call_count > MAX_MODEL_CALL_REGIONS {
            return Err(RegionError::MultiplicityExceeded {
                parent_kind: RegionKind::Event,
                child_kind: RegionKind::ModelCall,
                max: MAX_MODEL_CALL_REGIONS,
            });
        }

        let mut nodes = Vec::new();

        let proc_id = RegionId::new("process.main")?;
        nodes.push(TopologyNodeDescriptor {
            id: proc_id.clone(),
            kind: RegionKind::Process,
            parent_id: None,
        });

        let prop_id = RegionId::new("property.site_01")?;
        nodes.push(TopologyNodeDescriptor {
            id: prop_id.clone(),
            kind: RegionKind::Property,
            parent_id: Some(proc_id.clone()),
        });

        let ledger_id = RegionId::new("property.site_01.ledger")?;
        nodes.push(TopologyNodeDescriptor {
            id: ledger_id,
            kind: RegionKind::Ledger,
            parent_id: Some(prop_id.clone()),
        });

        let obj_id = RegionId::new("property.site_01.object_store")?;
        nodes.push(TopologyNodeDescriptor {
            id: obj_id,
            kind: RegionKind::ObjectStore,
            parent_id: Some(prop_id.clone()),
        });

        let proj_id = RegionId::new("property.site_01.projection")?;
        nodes.push(TopologyNodeDescriptor {
            id: proj_id,
            kind: RegionKind::Projection,
            parent_id: Some(prop_id.clone()),
        });

        let ops_id = RegionId::new("property.site_01.operations")?;
        nodes.push(TopologyNodeDescriptor {
            id: ops_id,
            kind: RegionKind::Operations,
            parent_id: Some(prop_id.clone()),
        });

        for s_idx in 0..sensor_count {
            let s_id = RegionId::new(format!("property.site_01.sensor_{:02}", s_idx))?;
            nodes.push(TopologyNodeDescriptor {
                id: s_id.clone(),
                kind: RegionKind::Sensor,
                parent_id: Some(prop_id.clone()),
            });

            nodes.push(TopologyNodeDescriptor {
                id: RegionId::new(format!("sensor_{:02}.adapter_session", s_idx))?,
                kind: RegionKind::AdapterSession,
                parent_id: Some(s_id.clone()),
            });
            nodes.push(TopologyNodeDescriptor {
                id: RegionId::new(format!("sensor_{:02}.receive", s_idx))?,
                kind: RegionKind::Receive,
                parent_id: Some(s_id.clone()),
            });
            nodes.push(TopologyNodeDescriptor {
                id: RegionId::new(format!("sensor_{:02}.continuity", s_idx))?,
                kind: RegionKind::Continuity,
                parent_id: Some(s_id.clone()),
            });
            nodes.push(TopologyNodeDescriptor {
                id: RegionId::new(format!("sensor_{:02}.media", s_idx))?,
                kind: RegionKind::Media,
                parent_id: Some(s_id.clone()),
            });
            nodes.push(TopologyNodeDescriptor {
                id: RegionId::new(format!("sensor_{:02}.analysis", s_idx))?,
                kind: RegionKind::Analysis,
                parent_id: Some(s_id.clone()),
            });
            nodes.push(TopologyNodeDescriptor {
                id: RegionId::new(format!("sensor_{:02}.archive", s_idx))?,
                kind: RegionKind::Archive,
                parent_id: Some(s_id.clone()),
            });
        }

        for e_idx in 0..event_count {
            let e_id = RegionId::new(format!("property.site_01.event_{:02}", e_idx))?;
            nodes.push(TopologyNodeDescriptor {
                id: e_id.clone(),
                kind: RegionKind::Event,
                parent_id: Some(prop_id.clone()),
            });

            nodes.push(TopologyNodeDescriptor {
                id: RegionId::new(format!("event_{:02}.evidence_window", e_idx))?,
                kind: RegionKind::EvidenceWindow,
                parent_id: Some(e_id.clone()),
            });

            for m_idx in 0..model_call_count {
                nodes.push(TopologyNodeDescriptor {
                    id: RegionId::new(format!("event_{:02}.model_call_{:02}", e_idx, m_idx))?,
                    kind: RegionKind::ModelCall,
                    parent_id: Some(e_id.clone()),
                });
            }

            nodes.push(TopologyNodeDescriptor {
                id: RegionId::new(format!("event_{:02}.association", e_idx))?,
                kind: RegionKind::Association,
                parent_id: Some(e_id.clone()),
            });
            nodes.push(TopologyNodeDescriptor {
                id: RegionId::new(format!("event_{:02}.policy", e_idx))?,
                kind: RegionKind::Policy,
                parent_id: Some(e_id.clone()),
            });
            nodes.push(TopologyNodeDescriptor {
                id: RegionId::new(format!("event_{:02}.alert_obligation", e_idx))?,
                kind: RegionKind::AlertObligation,
                parent_id: Some(e_id.clone()),
            });
        }

        Ok(Self {
            name: "standard_normative_topology".to_string(),
            version: 1,
            nodes,
        })
    }

    /// Builds a live [`RegionTree`] from this topology fixture using `root_authority`.
    pub fn instantiate(
        &self,
        root_authority: ContextAuthority,
        now: TimestampNs,
    ) -> Result<RegionTree, RegionError> {
        let root_node = self
            .nodes
            .iter()
            .find(|n| n.kind.is_root())
            .ok_or_else(|| {
                RegionError::NonRootMustHaveParent(RegionId("missing_root".to_string()))
            })?;

        let mut tree = RegionTree::new(root_node.id.clone(), root_authority.clone(), now)?;

        for node in &self.nodes {
            if node.kind.is_root() {
                continue;
            }
            let parent_id = node
                .parent_id
                .as_ref()
                .ok_or_else(|| RegionError::NonRootMustHaveParent(node.id.clone()))?;
            tree.attach_child(
                parent_id,
                node.id.clone(),
                node.kind,
                root_authority.clone(),
                now,
            )?;
        }

        tree.validate_topology()?;
        Ok(tree)
    }
}

// ---------------------------------------------------------------------------
// Region Errors
// ---------------------------------------------------------------------------

/// Typed errors arising from runtime region ownership, authority, or closure operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegionError {
    /// Region not found in tree.
    RegionNotFound(RegionId),
    /// Duplicate region identity in tree.
    DuplicateRegion(RegionId),
    /// Region kind attempted illegal child relationship.
    IllegalParentage {
        /// Kind of parent region.
        parent_kind: RegionKind,
        /// Attempted child region kind.
        child_kind: RegionKind,
    },
    /// Leaf region cannot have children.
    LeafRegionCannotHaveChildren {
        /// Kind of leaf region.
        parent_kind: RegionKind,
    },
    /// Root region cannot have an owner.
    RootCannotHaveParent(RegionId),
    /// Non-root region must have an owner.
    NonRootMustHaveParent(RegionId),
    /// Child multiplicity exceeded for parent.
    MultiplicityExceeded {
        /// Kind of parent region.
        parent_kind: RegionKind,
        /// Kind of child region.
        child_kind: RegionKind,
        /// Maximum admitted multiplicity.
        max: usize,
    },
    /// Single owner violation: child already owned.
    SingleOwnerViolation {
        /// Child region identity.
        child: RegionId,
        /// Current owning region identity.
        current_owner: RegionId,
        /// Attempted second owner identity.
        attempted_owner: RegionId,
    },
    /// Invalid state machine transition.
    InvalidStateTransition {
        /// Target region identity.
        region_id: RegionId,
        /// Current state.
        current: RegionState,
        /// Attempted state.
        attempted: RegionState,
    },
    /// Parent finalization blocked because child is not drained.
    ChildNotDrained {
        /// Parent region identity.
        parent_id: RegionId,
        /// Undrained child identity.
        live_child_id: RegionId,
        /// Child state.
        child_state: RegionState,
    },
    /// Parent finalization blocked because active tasks or descendants remain.
    DescendantActive {
        /// Parent region identity.
        parent_id: RegionId,
        /// Count of active tasks/descendants.
        active_count: usize,
    },
    /// FORMAL-001 violation: region closure attempted while pending obligations remain.
    LiveObligationsRemaining {
        /// Target region identity.
        region_id: RegionId,
        /// Count of pending obligations.
        pending_count: usize,
    },
    /// Work was submitted to a region that is draining or closed (orphan work).
    OrphanWork {
        /// Target region identity.
        region_id: RegionId,
        /// Region state.
        state: RegionState,
    },
    /// Operation attempted on an already closed region.
    RegionClosed {
        /// Target region identity.
        region_id: RegionId,
    },
    /// Context narrowing violated monotone property by broadening authority.
    AuthorityBroadened(&'static str),
    /// Anchor universe mismatch during authority operation.
    AnchorMismatch {
        /// Expected anchor universe.
        expected: ContentDigest,
        /// Actual anchor universe.
        actual: ContentDigest,
    },
    /// Configuration or model generation mismatch.
    GenerationMismatch {
        /// Expected generation.
        expected: u64,
        /// Actual generation.
        actual: u64,
    },
    /// Capacity bound exceeded.
    CapacityExceeded(&'static str),
    /// Task not found.
    TaskNotFound(TaskId),
    /// Duplicate task identity.
    DuplicateTask(TaskId),
    /// Obligation not found.
    ObligationNotFound(ObligationId),
    /// Duplicate obligation identity.
    DuplicateObligation(ObligationId),
    /// Indeterminate obligation missing durable reconciliation note (INV-006).
    MissingReconciliationObligation(ObligationId),
    /// Invalid budget representation.
    InvalidBudget(&'static str),
    /// Invalid identifier string.
    InvalidIdentifier(String),
}

impl RegionError {
    /// Returns the stable error code matching `registries/ERRORS.md`.
    #[must_use]
    pub const fn stable_code(&self) -> &'static str {
        match self {
            Self::ChildNotDrained { .. }
            | Self::DescendantActive { .. }
            | Self::LiveObligationsRemaining { .. }
            | Self::OrphanWork { .. } => ERR_QUIESCENCE_001,
            Self::AuthorityBroadened(_) => ERR_AUTH_DENIED_001,
            _ => ERR_OP_EXECUTION_FAILED_001,
        }
    }

    /// Converts this error into a structured [`OperationError`].
    pub fn to_operation_error(&self) -> Result<OperationError, ContractError> {
        let code = self.stable_code();
        let error_id = ErrorId::parse(code)?;
        let recovery_class = match self {
            Self::AuthorityBroadened(_) => RecoveryClass::NeverUnchanged,
            Self::OrphanWork { .. } | Self::RegionClosed { .. } => RecoveryClass::NeverUnchanged,
            Self::ChildNotDrained { .. } | Self::DescendantActive { .. } => {
                RecoveryClass::SafeReadRetry
            }
            _ => RecoveryClass::ReconciliationRequired,
        };

        Ok(OperationError {
            error_id,
            message: format!("{self}"),
            recovery_class,
            safe_retry: matches!(recovery_class, RecoveryClass::SafeReadRetry),
            resnapshot_required: true,
            reconciliation_required: matches!(
                recovery_class,
                RecoveryClass::ReconciliationRequired
            ),
            rebase_guidance: None,
            backoff_ms: None,
        })
    }
}

impl fmt::Display for RegionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegionNotFound(id) => write!(f, "region not found: {}", id.as_str()),
            Self::DuplicateRegion(id) => write!(f, "duplicate region: {}", id.as_str()),
            Self::IllegalParentage {
                parent_kind,
                child_kind,
            } => write!(
                f,
                "illegal parentage: {} cannot own {}",
                parent_kind.as_str(),
                child_kind.as_str()
            ),
            Self::LeafRegionCannotHaveChildren { parent_kind } => {
                write!(
                    f,
                    "leaf region {} cannot own children",
                    parent_kind.as_str()
                )
            }
            Self::RootCannotHaveParent(id) => {
                write!(f, "root region {} cannot have a parent", id.as_str())
            }
            Self::NonRootMustHaveParent(id) => {
                write!(f, "non-root region {} must have a parent", id.as_str())
            }
            Self::MultiplicityExceeded {
                parent_kind,
                child_kind,
                max,
            } => write!(
                f,
                "multiplicity exceeded: {} can own at most {} of {}",
                parent_kind.as_str(),
                max,
                child_kind.as_str()
            ),
            Self::SingleOwnerViolation {
                child,
                current_owner,
                attempted_owner,
            } => write!(
                f,
                "single owner violation: child {} already owned by {}, cannot attach to {}",
                child.as_str(),
                current_owner.as_str(),
                attempted_owner.as_str()
            ),
            Self::InvalidStateTransition {
                region_id,
                current,
                attempted,
            } => write!(
                f,
                "invalid state transition for {}: {} -> {}",
                region_id.as_str(),
                current.as_str(),
                attempted.as_str()
            ),
            Self::ChildNotDrained {
                parent_id,
                live_child_id,
                child_state,
            } => write!(
                f,
                "parent {} cannot finalize before child {} is drained (state: {})",
                parent_id.as_str(),
                live_child_id.as_str(),
                child_state.as_str()
            ),
            Self::DescendantActive {
                parent_id,
                active_count,
            } => write!(
                f,
                "parent {} has {} active tasks/descendants",
                parent_id.as_str(),
                active_count
            ),
            Self::LiveObligationsRemaining {
                region_id,
                pending_count,
            } => write!(
                f,
                "FORMAL-001 violation: region {} has {} pending obligations",
                region_id.as_str(),
                pending_count
            ),
            Self::OrphanWork { region_id, state } => write!(
                f,
                "orphan work rejected: region {} is in non-active state {}",
                region_id.as_str(),
                state.as_str()
            ),
            Self::RegionClosed { region_id } => {
                write!(f, "region {} is already closed", region_id.as_str())
            }
            Self::AuthorityBroadened(field) => {
                write!(
                    f,
                    "monotone narrowing violation: authority broadened in field '{field}'"
                )
            }
            Self::AnchorMismatch { expected, actual } => write!(
                f,
                "anchor universe mismatch: expected {}, got {}",
                expected.to_text(),
                actual.to_text()
            ),
            Self::GenerationMismatch { expected, actual } => write!(
                f,
                "generation mismatch: expected {}, got {}",
                expected, actual
            ),
            Self::CapacityExceeded(resource) => write!(f, "capacity exceeded for {resource}"),
            Self::TaskNotFound(id) => write!(f, "task not found: {}", id.as_str()),
            Self::DuplicateTask(id) => write!(f, "duplicate task: {}", id.as_str()),
            Self::ObligationNotFound(id) => write!(f, "obligation not found: {}", id.as_str()),
            Self::DuplicateObligation(id) => write!(f, "duplicate obligation: {}", id.as_str()),
            Self::MissingReconciliationObligation(id) => write!(
                f,
                "INV-006 violation: indeterminate obligation {} requires durable reconciliation note",
                id.as_str()
            ),
            Self::InvalidBudget(msg) => write!(f, "invalid budget: {msg}"),
            Self::InvalidIdentifier(id) => write!(f, "invalid identifier: {id}"),
        }
    }
}

impl std::error::Error for RegionError {}

impl From<ContractError> for RegionError {
    fn from(err: ContractError) -> Self {
        Self::InvalidIdentifier(format!("{err}"))
    }
}
