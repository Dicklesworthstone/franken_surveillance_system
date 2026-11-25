#![forbid(unsafe_code)]
//! Deterministic ATP object-graph closure verifier (`FSS-127`, `fss-x4a.13.11`).
//!
//! Verifies complete bottom-up reachability, content integrity, non-collapsed custody floors,
//! authority/privacy projections, and cycle/tombstone/invalidation/indeterminate absence over
//! immutable object graphs without collapsing `staged`, `verified`, `visible`, `durable`,
//! `replicated`, `protected`, and `retrievable` states.
//!
//! Key guarantees:
//! - **Authority-before-expansion:** capability/privacy/generation projection is checked BEFORE
//!   reading bytes or following outgoing edges of any node; unauthorized or redacted subgraphs
//!   never expand.
//! - **Non-collapse custody ladder:** a `Staged` object never satisfies `Verified`; a `Replicated`
//!   object never satisfies `Retrievable`; an `Indeterminate` object never upgrades to verified.
//! - **Deterministic canonical post-order:** verified members are emitted in strict bottom-up
//!   dependency order with canonical digest tie-break so root-last publication always exposes
//!   every child before every parent.
//! - **Fail-closed bounded traversal:** explicit ceilings on nodes, edges, depth, and bytes plus
//!   cooperative cancellation preserve partial verified evidence while refusing to emit a
//!   `VerifiedComplete` verdict.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, ContractError};

use crate::{InMemoryObjectStore, ObjectError, ObjectState};

/// Registered digest domain for [`ClosureVerificationWitness`] (`FSS-127`).
pub const ATP_CLOSURE_WITNESS_DOMAIN: &str = "fss.atp_object_graph_closure_witness.v1";
/// Binary wire header magic for serialized closure witnesses.
pub const CLOSURE_WITNESS_MAGIC: [u8; 8] = *b"FSSCLW01";
/// Supported durable format version for [`ClosureVerificationWitness`].
pub const CLOSURE_WITNESS_VERSION: u32 = 1;
/// Hard ceiling on nodes traversed in one closure verification pass.
pub const MAX_CLOSURE_NODES: usize = 65_536;
/// Hard ceiling on directed edges traversed in one closure verification pass.
pub const MAX_CLOSURE_EDGES: usize = 262_144;
/// Hard ceiling on graph depth from root to leaf.
pub const MAX_CLOSURE_DEPTH: u32 = 128;
/// Hard ceiling on verified cumulative bytes per pass (1 GiB).
pub const MAX_CLOSURE_BYTES: u64 = 1024 * 1024 * 1024;
/// Hard ceiling on serialized witness wire size (4 MiB).
pub const MAX_CLOSURE_WITNESS_WIRE_BYTES: usize = 4 * 1024 * 1024;
/// Hard ceiling on UTF-8 bytes in diagnostic labels.
pub const MAX_CLOSURE_LABEL_BYTES: usize = 256;

/// Strictly ordered custody ladder. Never collapses distinct durability/retrievability milestones.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CustodyLevel {
    /// Bytes written to staging area only; NOT verified and NEVER readable as closure truth.
    Staged = 1,
    /// Bytes independently rehashed to match canonical content digest.
    Verified = 2,
    /// Manifest/object exposed in local visible catalog after child closure proof.
    Visible = 3,
    /// Fs-synced / journal-durable on local authoritative storage.
    Durable = 4,
    /// Replicated across policy-required independent failure domains.
    Replicated = 5,
    /// Protected by retention policy / legal hold / erasure-coded redundancy.
    Protected = 6,
    /// Witnessed by a verified proof-of-retrievability readback challenge.
    Retrievable = 7,
}

impl CustodyLevel {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Verified => "verified",
            Self::Visible => "visible",
            Self::Durable => "durable",
            Self::Replicated => "replicated",
            Self::Protected => "protected",
            Self::Retrievable => "retrievable",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::Staged),
            2 => Ok(Self::Verified),
            3 => Ok(Self::Visible),
            4 => Ok(Self::Durable),
            5 => Ok(Self::Replicated),
            6 => Ok(Self::Protected),
            7 => Ok(Self::Retrievable),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Typed dependency edge class traversed during ATP object-graph closure verification.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ClosureEdgeKind {
    /// Direct child object declared by an `ObjectManifest`.
    ManifestChild = 1,
    /// Typed metadata object pinned by an `ObjectManifest`.
    Metadata = 2,
    /// Derivative dependency (e.g. transcoded/indexed/extracted artifact).
    Derived = 3,
    /// Content-addressed cache edge.
    Cache = 4,
    /// Replica-set or archive-pack membership edge.
    Replica = 5,
    /// Resumable transfer/upload journal custody edge.
    Journal = 6,
}

impl ClosureEdgeKind {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ManifestChild => "manifest_child",
            Self::Metadata => "metadata",
            Self::Derived => "derived",
            Self::Cache => "cache",
            Self::Replica => "replica",
            Self::Journal => "journal",
        }
    }
}

/// One typed outgoing dependency edge in an immutable object graph.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ClosureEdge {
    /// Edge semantic class.
    pub kind: ClosureEdgeKind,
    /// Target immutable object digest.
    pub target: ContentDigest,
}

/// Observed state of one object inspected by [`ObjectGraphSource`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InspectedObject {
    /// Present and content-integrity verified at an exact custody level.
    Present {
        /// Highest proven custody milestone for this object.
        custody: CustodyLevel,
        /// Exact canonical byte length of the object payload.
        byte_len: u64,
        /// True when this object was reconstructed via repair symbols and re-verified.
        post_repair_verified: bool,
        /// Outgoing dependency edges (manifest children, metadata, derived, cache, replica, journal).
        edges: Vec<ClosureEdge>,
    },
    /// Object is absent from storage.
    Missing,
    /// Object bytes are staged only (not yet rehashed/verified).
    StagedOnly {
        /// Staged byte count.
        byte_len: u64,
    },
    /// Object was permanently tombstoned by deletion authority.
    Tombstoned,
    /// Manifest lost publication authority because a descendant was tombstoned/invalidated.
    InvalidatedManifest,
    /// Stored bytes failed canonical SHA-256 rehash or post-repair digest verification.
    Corrupt {
        /// Diagnostic mismatch reason.
        reason: String,
    },
    /// Remote/archive custody could not be resolved (e.g. lagging listing or timeout).
    Indeterminate {
        /// Machine-readable reason custody remains unresolved.
        reason: String,
    },
}

/// Explicit authority, privacy, and generation projection evaluated BEFORE node expansion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosureAuthorityContext {
    /// Exact pinned `ContractBasis` / ledger anchor digest.
    pub contract_basis_digest: ContentDigest,
    /// Active authority generation (must match `expected_authority_generation`).
    pub authority_generation: u64,
    /// Expected authority generation pinned by the caller.
    pub expected_authority_generation: u64,
    /// Active privacy epoch.
    pub privacy_epoch: u64,
    /// True while read/verify capability remains active.
    pub capability_active: bool,
    /// True while privacy projection authorization remains active.
    pub privacy_active: bool,
    /// Objects explicitly redacted/restricted under the caller's privacy/capability projection.
    pub restricted_objects: BTreeSet<ContentDigest>,
    /// Edge classes permitted for traversal under this projection.
    pub allowed_edge_kinds: BTreeSet<ClosureEdgeKind>,
}

impl ClosureAuthorityContext {
    /// Constructs a full-edge active authority context pinned to `contract_basis_digest`.
    #[must_use]
    pub fn active_all_edges(
        contract_basis_digest: ContentDigest,
        authority_generation: u64,
        privacy_epoch: u64,
    ) -> Self {
        let allowed_edge_kinds = [
            ClosureEdgeKind::ManifestChild,
            ClosureEdgeKind::Metadata,
            ClosureEdgeKind::Derived,
            ClosureEdgeKind::Cache,
            ClosureEdgeKind::Replica,
            ClosureEdgeKind::Journal,
        ]
        .into_iter()
        .collect();
        Self {
            contract_basis_digest,
            authority_generation,
            expected_authority_generation: authority_generation,
            privacy_epoch,
            capability_active: true,
            privacy_active: true,
            restricted_objects: BTreeSet::new(),
            allowed_edge_kinds,
        }
    }

    fn validate_session(&self) -> Result<(), ClosureError> {
        if !self.capability_active {
            return Err(ClosureError::AuthorityRevoked {
                reason: "closure verification capability revoked".to_owned(),
            });
        }
        if !self.privacy_active {
            return Err(ClosureError::AuthorityRevoked {
                reason: "privacy projection authorization revoked".to_owned(),
            });
        }
        if self.authority_generation != self.expected_authority_generation {
            return Err(ClosureError::StaleGeneration {
                expected: self.expected_authority_generation,
                observed: self.authority_generation,
            });
        }
        Ok(())
    }
}

/// Hard traversal bounds for one closure verification run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosureBudget {
    /// Maximum unique objects visited.
    pub max_nodes: usize,
    /// Maximum directed dependency edges inspected.
    pub max_edges: usize,
    /// Maximum path depth from root (`0` allows root leaf only).
    pub max_depth: u32,
    /// Maximum cumulative verified payload bytes accounted.
    pub max_bytes: u64,
}

impl ClosureBudget {
    /// Validates all budget fields against hard protocol ceilings.
    pub fn new(
        max_nodes: usize,
        max_edges: usize,
        max_depth: u32,
        max_bytes: u64,
    ) -> Result<Self, ClosureError> {
        if max_nodes == 0
            || max_nodes > MAX_CLOSURE_NODES
            || max_edges > MAX_CLOSURE_EDGES
            || max_depth > MAX_CLOSURE_DEPTH
            || max_bytes == 0
            || max_bytes > MAX_CLOSURE_BYTES
        {
            return Err(ClosureError::InvalidBudget);
        }
        Ok(Self {
            max_nodes,
            max_edges,
            max_depth,
            max_bytes,
        })
    }

    /// Standard generous bounded defaults.
    pub const DEFAULT: Self = Self {
        max_nodes: 4_096,
        max_edges: 16_384,
        max_depth: 64,
        max_bytes: 256 * 1024 * 1024,
    };
}

/// Non-collapsed terminal verdict of one object-graph closure verification pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClosureVerdict {
    /// Every reachable object and edge passed authorization, integrity, and custody-floor proofs.
    VerifiedComplete = 1,
    /// Graph is incomplete (missing objects, staged-only bytes, or custody below required floor).
    Incomplete = 2,
    /// Traversal halted at an unauthorized/redacted object or disallowed edge class.
    Unauthorized = 3,
    /// Graph contains corrupt bytes, tombstoned members, invalidated manifests, or a cycle.
    CorruptOrInvalidated = 4,
    /// At least one reachable object has indeterminate remote/archive custody.
    Indeterminate = 5,
    /// Traversal hit a node, edge, depth, or byte budget ceiling before completing closure.
    BudgetExceeded = 6,
    /// Cooperative cancellation was observed before completing closure.
    Cancelled = 7,
}

impl ClosureVerdict {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedComplete => "verified_complete",
            Self::Incomplete => "incomplete",
            Self::Unauthorized => "unauthorized",
            Self::CorruptOrInvalidated => "corrupt_or_invalidated",
            Self::Indeterminate => "indeterminate",
            Self::BudgetExceeded => "budget_exceeded",
            Self::Cancelled => "cancelled",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::VerifiedComplete),
            2 => Ok(Self::Incomplete),
            3 => Ok(Self::Unauthorized),
            4 => Ok(Self::CorruptOrInvalidated),
            5 => Ok(Self::Indeterminate),
            6 => Ok(Self::BudgetExceeded),
            7 => Ok(Self::Cancelled),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Safe operator/agent recovery guidance emitted alongside every closure witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClosureRecoveryGuidance {
    /// Complete closure verified; safe to proceed with root-last publication (grants no authority).
    ReadyForRootPublication = 1,
    /// Fetch, repair, verify, or replicate missing/below-floor children before retrying.
    WaitForMissingOrStagedChildren = 2,
    /// Reconcile unresolved remote/archive custody obligations before concluding.
    ReconcileIndeterminateCustody = 3,
    /// Quarantine corrupt or invalidated objects and rebuild from clean authoritative custody.
    QuarantineAndRepairCorruptGraph = 4,
    /// Re-authorize capability/privacy projection or prune restricted subgraphs before retry.
    ReauthorizeOrPruneRestrictedSubgraph = 5,
    /// Increase traversal budget within protocol ceilings or partition the manifest graph.
    RaiseTraversalBudget = 6,
    /// Cancellation observed; retry cleanly against a pinned anchor when ready.
    RetryFromCleanState = 7,
}

impl ClosureRecoveryGuidance {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadyForRootPublication => "ready_for_root_publication",
            Self::WaitForMissingOrStagedChildren => "wait_for_missing_or_staged_children",
            Self::ReconcileIndeterminateCustody => "reconcile_indeterminate_custody",
            Self::QuarantineAndRepairCorruptGraph => "quarantine_and_repair_corrupt_graph",
            Self::ReauthorizeOrPruneRestrictedSubgraph => {
                "reauthorize_or_prune_restricted_subgraph"
            }
            Self::RaiseTraversalBudget => "raise_traversal_budget",
            Self::RetryFromCleanState => "retry_from_clean_state",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::ReadyForRootPublication),
            2 => Ok(Self::WaitForMissingOrStagedChildren),
            3 => Ok(Self::ReconcileIndeterminateCustody),
            4 => Ok(Self::QuarantineAndRepairCorruptGraph),
            5 => Ok(Self::ReauthorizeOrPruneRestrictedSubgraph),
            6 => Ok(Self::RaiseTraversalBudget),
            7 => Ok(Self::RetryFromCleanState),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// One verified object recorded in bottom-up dependency order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosureMember {
    /// Canonical object content digest.
    pub digest: ContentDigest,
    /// Highest proven custody milestone observed.
    pub custody: CustodyLevel,
    /// Exact canonical payload bytes verified.
    pub byte_len: u64,
    /// Minimum graph depth from root (`0` for root).
    pub depth: u32,
    /// Number of direct outgoing edges verified from this member.
    pub child_edge_count: u32,
    /// True if reconstructed via repair symbols and post-repair digest verified.
    pub post_repair_verified: bool,
}

/// Typed classification of a closure defect that prevented `VerifiedComplete`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClosureDefectKind {
    /// Object is absent from storage.
    Missing = 1,
    /// Object exists only in `Staged` state (unverified).
    StagedOnly = 2,
    /// Object verified, but below required [`CustodyLevel`] floor.
    BelowCustodyFloor = 3,
    /// Object was permanently tombstoned.
    Tombstoned = 4,
    /// Manifest was invalidated by descendant deletion.
    InvalidatedManifest = 5,
    /// Stored bytes failed canonical digest verification.
    Corrupt = 6,
    /// Directed cycle detected in dependency edges.
    CycleDetected = 7,
    /// Object or edge blocked by capability/privacy projection before expansion.
    UnauthorizedOrRedacted = 8,
    /// Object custody state is indeterminate (unresolved remote/archive state).
    Indeterminate = 9,
    /// Traversal exceeded configured node/edge/depth/byte budget.
    BudgetExceeded = 10,
    /// Traversal halted due to cooperative cancellation.
    Cancelled = 11,
}

impl ClosureDefectKind {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::StagedOnly => "staged_only",
            Self::BelowCustodyFloor => "below_custody_floor",
            Self::Tombstoned => "tombstoned",
            Self::InvalidatedManifest => "invalidated_manifest",
            Self::Corrupt => "corrupt",
            Self::CycleDetected => "cycle_detected",
            Self::UnauthorizedOrRedacted => "unauthorized_or_redacted",
            Self::Indeterminate => "indeterminate",
            Self::BudgetExceeded => "budget_exceeded",
            Self::Cancelled => "cancelled",
        }
    }

    const fn tag(&self) -> u8 {
        match self {
            Self::Missing => 1,
            Self::StagedOnly => 2,
            Self::BelowCustodyFloor => 3,
            Self::Tombstoned => 4,
            Self::InvalidatedManifest => 5,
            Self::Corrupt => 6,
            Self::CycleDetected => 7,
            Self::UnauthorizedOrRedacted => 8,
            Self::Indeterminate => 9,
            Self::BudgetExceeded => 10,
            Self::Cancelled => 11,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::Missing),
            2 => Ok(Self::StagedOnly),
            3 => Ok(Self::BelowCustodyFloor),
            4 => Ok(Self::Tombstoned),
            5 => Ok(Self::InvalidatedManifest),
            6 => Ok(Self::Corrupt),
            7 => Ok(Self::CycleDetected),
            8 => Ok(Self::UnauthorizedOrRedacted),
            9 => Ok(Self::Indeterminate),
            10 => Ok(Self::BudgetExceeded),
            11 => Ok(Self::Cancelled),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// One typed defect observed during object-graph closure verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosureDefect {
    /// Offending object digest.
    pub digest: ContentDigest,
    /// Machine-readable defect classification.
    pub kind: ClosureDefectKind,
    /// Bounded diagnostic detail (secret-free).
    pub detail: String,
}

/// Typed pre-flight or wire-codec error for [`ClosureVerifier`] and [`ClosureVerificationWitness`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClosureError {
    /// Required custody floor cannot be `Staged` (staged bytes are never verified truth).
    InvalidCustodyFloor,
    /// Traversal budget violated hard bounds.
    InvalidBudget,
    /// Capability or privacy authorization was revoked before expansion.
    AuthorityRevoked {
        /// Revocation detail.
        reason: String,
    },
    /// Authority generation drifted from pinned expectation.
    StaleGeneration {
        /// Expected authority generation.
        expected: u64,
        /// Observed authority generation.
        observed: u64,
    },
    /// Wire witness lacked [`CLOSURE_WITNESS_MAGIC`].
    InvalidMagic,
    /// Wire witness declared an unsupported format version.
    UnsupportedVersion {
        /// Observed format version.
        version: u32,
    },
    /// Wire witness was truncated, malformed, or contained trailing bytes.
    MalformedWire(String),
    /// Wire witness checksum failed verification.
    ChecksumMismatch,
    /// Wire witness exceeded hard size or item ceilings.
    BoundsExceeded {
        /// Observed count or byte length.
        observed: usize,
        /// Maximum permitted bound.
        maximum: usize,
    },
    /// Canonical encoding failed.
    Encoding(String),
}

impl ClosureError {
    /// Stable error identity.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidCustodyFloor => "ERR-ATP-CLOSURE-INVALID-FLOOR-001",
            Self::InvalidBudget => "ERR-ATP-CLOSURE-INVALID-BUDGET-001",
            Self::AuthorityRevoked { .. } => "ERR-ATP-CLOSURE-AUTHORITY-REVOKED-001",
            Self::StaleGeneration { .. } => "ERR-ATP-CLOSURE-STALE-GENERATION-001",
            Self::InvalidMagic => "ERR-ATP-CLOSURE-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-ATP-CLOSURE-UNSUPPORTED-VERSION-001",
            Self::MalformedWire(_) => "ERR-ATP-CLOSURE-MALFORMED-WIRE-001",
            Self::ChecksumMismatch => "ERR-ATP-CLOSURE-CHECKSUM-MISMATCH-001",
            Self::BoundsExceeded { .. } => "ERR-ATP-CLOSURE-BOUNDS-001",
            Self::Encoding(_) => "ERR-ATP-CLOSURE-ENCODING-001",
        }
    }
}

impl fmt::Display for ClosureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for ClosureError {}

/// Canonical, checksummed witness recording the exact result of one object-graph closure pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosureVerificationWitness {
    /// Durable format version (`CLOSURE_WITNESS_VERSION`).
    pub format_version: u32,
    /// Root object digest verified.
    pub root: ContentDigest,
    /// Exact pinned `ContractBasis` / anchor digest.
    pub contract_basis_digest: ContentDigest,
    /// Active authority generation pinned into this witness.
    pub authority_generation: u64,
    /// Active privacy epoch pinned into this witness.
    pub privacy_epoch: u64,
    /// Minimum custody milestone required across the entire closure.
    pub required_custody_floor: CustodyLevel,
    /// Non-collapsed terminal verdict.
    pub verdict: ClosureVerdict,
    /// Safe next-action guidance.
    pub guidance: ClosureRecoveryGuidance,
    /// Verified members in deterministic bottom-up post-order (children always precede parents).
    pub ordered_members: Vec<ClosureMember>,
    /// Total directed edges inspected.
    pub edge_count: u64,
    /// Maximum graph depth observed.
    pub max_observed_depth: u32,
    /// Cumulative verified payload bytes across `ordered_members`.
    pub total_verified_bytes: u64,
    /// Typed defects encountered (always empty iff `verdict == ClosureVerdict::VerifiedComplete`).
    pub defects: Vec<ClosureDefect>,
    /// Domain-separated SHA-256 commitment (`fss.atp_object_graph_closure_witness.v1`).
    pub witness_digest: ContentDigest,
}

impl ClosureVerificationWitness {
    /// True iff the entire reachable closure passed every check with zero defects.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.verdict == ClosureVerdict::VerifiedComplete && self.defects.is_empty()
    }

    /// Computes the canonical SHA-256 commitment digest over every field except `witness_digest`.
    pub fn compute_digest(&self) -> Result<ContentDigest, ClosureError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(ATP_CLOSURE_WITNESS_DOMAIN);
        self.encode_body(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|err| ClosureError::Encoding(err.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.digest(self.root);
        enc.digest(self.contract_basis_digest);
        enc.u64(self.authority_generation);
        enc.u64(self.privacy_epoch);
        enc.u8(self.required_custody_floor.tag());
        enc.u8(self.verdict.tag());
        enc.u8(self.guidance.tag());
        enc.u64(self.ordered_members.len() as u64);
        for m in &self.ordered_members {
            enc.digest(m.digest);
            enc.u8(m.custody.tag());
            enc.u64(m.byte_len);
            enc.u32(m.depth);
            enc.u32(m.child_edge_count);
            enc.bool(m.post_repair_verified);
        }
        enc.u64(self.edge_count);
        enc.u32(self.max_observed_depth);
        enc.u64(self.total_verified_bytes);
        enc.u64(self.defects.len() as u64);
        for defect in &self.defects {
            enc.digest(defect.digest);
            enc.u8(defect.kind.tag());
            enc.text(&defect.detail);
        }
    }

    /// Serializes this witness to canonical checksummed wire bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ClosureError> {
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        enc.digest(self.witness_digest);
        let body = enc
            .finish_checked()
            .map_err(|err| ClosureError::Encoding(err.to_string()))?;
        let total = CLOSURE_WITNESS_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_CLOSURE_WITNESS_WIRE_BYTES {
            return Err(ClosureError::BoundsExceeded {
                observed: total,
                maximum: MAX_CLOSURE_WITNESS_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&CLOSURE_WITNESS_MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and verifies a binary [`ClosureVerificationWitness`].
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ClosureError> {
        if bytes.len() > MAX_CLOSURE_WITNESS_WIRE_BYTES {
            return Err(ClosureError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_CLOSURE_WITNESS_WIRE_BYTES,
            });
        }
        if bytes.len() < 12 || bytes[..8] != CLOSURE_WITNESS_MAGIC {
            return Err(ClosureError::InvalidMagic);
        }
        let header_version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if header_version != CLOSURE_WITNESS_VERSION {
            return Err(ClosureError::UnsupportedVersion {
                version: header_version,
            });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let format_version = dec
            .u32()
            .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;
        if format_version != header_version {
            return Err(ClosureError::UnsupportedVersion {
                version: format_version,
            });
        }
        let root = dec
            .digest()
            .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;
        let contract_basis_digest = dec
            .digest()
            .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;
        let authority_generation = dec
            .u64()
            .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;
        let privacy_epoch = dec
            .u64()
            .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;
        let required_custody_floor = CustodyLevel::from_tag(
            dec.u8()
                .map_err(|err| ClosureError::MalformedWire(err.to_string()))?,
        )
        .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;
        if required_custody_floor == CustodyLevel::Staged {
            return Err(ClosureError::InvalidCustodyFloor);
        }
        let verdict = ClosureVerdict::from_tag(
            dec.u8()
                .map_err(|err| ClosureError::MalformedWire(err.to_string()))?,
        )
        .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;
        let guidance = ClosureRecoveryGuidance::from_tag(
            dec.u8()
                .map_err(|err| ClosureError::MalformedWire(err.to_string()))?,
        )
        .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;

        let member_count = usize::try_from(
            dec.u64()
                .map_err(|err| ClosureError::MalformedWire(err.to_string()))?,
        )
        .map_err(|_| ClosureError::BoundsExceeded {
            observed: usize::MAX,
            maximum: MAX_CLOSURE_NODES,
        })?;
        // Each encoded ClosureMember is at least 33 + 1 + 8 + 4 + 4 + 1 = 51 bytes.
        if member_count > MAX_CLOSURE_NODES || member_count.saturating_mul(51) > dec.remaining() {
            return Err(ClosureError::BoundsExceeded {
                observed: member_count,
                maximum: MAX_CLOSURE_NODES,
            });
        }
        let mut ordered_members = Vec::with_capacity(member_count);
        for _ in 0..member_count {
            let digest = dec
                .digest()
                .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;
            let custody = CustodyLevel::from_tag(
                dec.u8()
                    .map_err(|err| ClosureError::MalformedWire(err.to_string()))?,
            )
            .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;
            let byte_len = dec
                .u64()
                .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;
            let depth = dec
                .u32()
                .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;
            let child_edge_count = dec
                .u32()
                .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;
            let post_repair_verified = dec
                .bool()
                .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;
            ordered_members.push(ClosureMember {
                digest,
                custody,
                byte_len,
                depth,
                child_edge_count,
                post_repair_verified,
            });
        }

        let edge_count = dec
            .u64()
            .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;
        let max_observed_depth = dec
            .u32()
            .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;
        let total_verified_bytes = dec
            .u64()
            .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;

        let defect_count = usize::try_from(
            dec.u64()
                .map_err(|err| ClosureError::MalformedWire(err.to_string()))?,
        )
        .map_err(|_| ClosureError::BoundsExceeded {
            observed: usize::MAX,
            maximum: MAX_CLOSURE_NODES,
        })?;
        // Each encoded ClosureDefect is at least 33 + 1 + 4 = 38 bytes.
        if defect_count > MAX_CLOSURE_NODES || defect_count.saturating_mul(38) > dec.remaining() {
            return Err(ClosureError::BoundsExceeded {
                observed: defect_count,
                maximum: MAX_CLOSURE_NODES,
            });
        }
        let mut defects = Vec::with_capacity(defect_count);
        for _ in 0..defect_count {
            let digest = dec
                .digest()
                .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;
            let kind = ClosureDefectKind::from_tag(
                dec.u8()
                    .map_err(|err| ClosureError::MalformedWire(err.to_string()))?,
            )
            .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;
            let detail = dec
                .text()
                .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;
            if detail.len() > MAX_CLOSURE_LABEL_BYTES {
                return Err(ClosureError::BoundsExceeded {
                    observed: detail.len(),
                    maximum: MAX_CLOSURE_LABEL_BYTES,
                });
            }
            defects.push(ClosureDefect {
                digest,
                kind,
                detail: detail.to_owned(),
            });
        }

        let stored_digest = dec
            .digest()
            .map_err(|err| ClosureError::MalformedWire(err.to_string()))?;
        dec.ensure_finished()
            .map_err(|_| ClosureError::MalformedWire("trailing bytes after witness".to_owned()))?;

        let witness = Self {
            format_version,
            root,
            contract_basis_digest,
            authority_generation,
            privacy_epoch,
            required_custody_floor,
            verdict,
            guidance,
            ordered_members,
            edge_count,
            max_observed_depth,
            total_verified_bytes,
            defects,
            witness_digest: stored_digest,
        };
        let computed = witness.compute_digest()?;
        if computed != stored_digest {
            return Err(ClosureError::ChecksumMismatch);
        }
        if (witness.verdict == ClosureVerdict::VerifiedComplete) != witness.defects.is_empty() {
            return Err(ClosureError::MalformedWire(
                "witness verdict contradicts defect list".to_owned(),
            ));
        }
        Ok(witness)
    }

    /// Emits one secret-free structured JSON-lines summary of this closure proof.
    #[must_use]
    pub fn to_jsonl_line(&self, scenario: &str, seed: u64, repro_cmd: &str) -> String {
        format!(
            concat!(
                "{{\"schema\":\"fss.atp_object_graph_closure_witness.v1\",",
                "\"scenario\":\"{}\",\"seed\":{},",
                "\"root\":\"{}\",\"contractBasisDigest\":\"{}\",",
                "\"authorityGeneration\":{},\"privacyEpoch\":{},",
                "\"requiredFloor\":\"{}\",\"verdict\":\"{}\",\"guidance\":\"{}\",",
                "\"verifiedNodes\":{},\"edges\":{},\"maxDepth\":{},\"verifiedBytes\":{},",
                "\"defectCount\":{},\"witnessDigest\":\"{}\",\"repro\":\"{}\"}}"
            ),
            json_escape(scenario),
            seed,
            self.root,
            self.contract_basis_digest,
            self.authority_generation,
            self.privacy_epoch,
            self.required_custody_floor.as_str(),
            self.verdict.as_str(),
            self.guidance.as_str(),
            self.ordered_members.len(),
            self.edge_count,
            self.max_observed_depth,
            self.total_verified_bytes,
            self.defects.len(),
            self.witness_digest,
            json_escape(repro_cmd),
        )
    }
}

/// Abstract read-only custody backend queried by [`ClosureVerifier`].
pub trait ObjectGraphSource {
    /// Inspects one content-addressed object, re-verifying integrity and returning its custody
    /// state and direct outgoing dependency edges.
    fn inspect_object(&self, digest: ContentDigest) -> InspectedObject;
}

impl ObjectGraphSource for InMemoryObjectStore {
    fn inspect_object(&self, digest: ContentDigest) -> InspectedObject {
        if self.is_tombstoned(digest) {
            return InspectedObject::Tombstoned;
        }
        if self.is_invalidated_manifest(digest) {
            return InspectedObject::InvalidatedManifest;
        }
        match self.state(digest) {
            None => InspectedObject::Missing,
            Some(ObjectState::Tombstoned) => InspectedObject::Tombstoned,
            Some(ObjectState::Staged) => InspectedObject::StagedOnly { byte_len: 0 },
            Some(ObjectState::Verified) => match self.read_verified(digest) {
                Ok(bytes) => {
                    let byte_len = bytes.len() as u64;
                    match self.published_manifest(digest) {
                        Ok(manifest) => {
                            let mut edges = Vec::with_capacity(manifest.children().len());
                            for &child in manifest.children() {
                                let kind = if manifest.metadata_digest() == Some(child) {
                                    ClosureEdgeKind::Metadata
                                } else {
                                    ClosureEdgeKind::ManifestChild
                                };
                                edges.push(ClosureEdge {
                                    kind,
                                    target: child,
                                });
                            }
                            InspectedObject::Present {
                                custody: CustodyLevel::Visible,
                                byte_len,
                                post_repair_verified: false,
                                edges,
                            }
                        }
                        Err(ObjectError::ManifestNotPublished(_)) => InspectedObject::Present {
                            custody: CustodyLevel::Verified,
                            byte_len,
                            post_repair_verified: false,
                            edges: Vec::new(),
                        },
                        Err(ObjectError::Corrupt(_)) => InspectedObject::Corrupt {
                            reason: "manifest root/body integrity mismatch".to_owned(),
                        },
                        Err(ObjectError::Tombstoned(_)) => InspectedObject::Tombstoned,
                        Err(ObjectError::NotVerified(_)) => InspectedObject::InvalidatedManifest,
                        Err(_) => InspectedObject::Missing,
                    }
                }
                Err(ObjectError::Corrupt(_)) => InspectedObject::Corrupt {
                    reason: "stored payload failed canonical SHA-256 rehash".to_owned(),
                },
                Err(ObjectError::Tombstoned(_)) => InspectedObject::Tombstoned,
                Err(ObjectError::NotVerified(_)) => InspectedObject::StagedOnly { byte_len: 0 },
                Err(_) => InspectedObject::Missing,
            },
        }
    }
}

/// Deterministic multi-tier ATP/archive object graph catalog implementing [`ObjectGraphSource`].
///
/// Models every custody milestone (`Staged` through `Retrievable`), post-repair verification,
/// tombstones, invalidated manifests, corrupt payloads, indeterminate remote custody, and
/// heterogeneous dependency edges (`ManifestChild`, `Metadata`, `Derived`, `Cache`, `Replica`,
/// `Journal`).
#[derive(Clone, Debug, Default)]
pub struct AtpArchiveGraphCatalog {
    entries: BTreeMap<ContentDigest, InspectedObject>,
}

impl AtpArchiveGraphCatalog {
    /// Creates an empty catalog.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts or replaces an inspected object entry for `digest`.
    pub fn insert(&mut self, digest: ContentDigest, object: InspectedObject) {
        self.entries.insert(digest, object);
    }

    /// Number of entries in this catalog.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the catalog contains zero entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl ObjectGraphSource for AtpArchiveGraphCatalog {
    fn inspect_object(&self, digest: ContentDigest) -> InspectedObject {
        self.entries
            .get(&digest)
            .cloned()
            .unwrap_or(InspectedObject::Missing)
    }
}

/// Deterministic bounded ATP object-graph closure verifier (`FSS-127`).
pub struct ClosureVerifier;

#[derive(Clone, Copy, Eq, PartialEq)]
enum VisitMark {
    Visiting,
    Done,
}

struct Frame {
    digest: ContentDigest,
    depth: u32,
    custody: CustodyLevel,
    byte_len: u64,
    post_repair_verified: bool,
    child_edge_count: u32,
    pending_children: Vec<ContentDigest>,
    next_child_idx: usize,
    all_children_ok: bool,
}

impl ClosureVerifier {
    /// Verifies the complete reachable closure of `root` in `source` under `authority`,
    /// `required_custody_floor`, and `budget`.
    ///
    /// `should_cancel` is polled at every traversal boundary so cooperative cancellation stops
    /// immediately without claiming `VerifiedComplete`, while preserving already-verified partial
    /// members for diagnosis.
    pub fn verify_closure<S, F>(
        source: &S,
        root: ContentDigest,
        authority: &ClosureAuthorityContext,
        required_custody_floor: CustodyLevel,
        budget: ClosureBudget,
        mut should_cancel: F,
    ) -> Result<ClosureVerificationWitness, ClosureError>
    where
        S: ObjectGraphSource,
        F: FnMut(usize) -> bool,
    {
        if required_custody_floor == CustodyLevel::Staged {
            return Err(ClosureError::InvalidCustodyFloor);
        }
        authority.validate_session()?;

        let mut marks: BTreeMap<ContentDigest, VisitMark> = BTreeMap::new();
        let mut member_ok: BTreeMap<ContentDigest, bool> = BTreeMap::new();
        let mut ordered_members: Vec<ClosureMember> = Vec::new();
        let mut defects: Vec<ClosureDefect> = Vec::new();
        let mut stack: Vec<Frame> = Vec::new();

        let mut visited_nodes: usize = 0;
        let mut edge_count: u64 = 0;
        let mut max_observed_depth: u32 = 0;
        let mut total_verified_bytes: u64 = 0;
        let mut steps: usize = 0;
        let mut halted_budget = false;
        let mut halted_cancel = false;

        // Helper closure-like macro-free push: enters one node if not already visited.
        enum EnterOutcome {
            Pushed(Frame),
            AlreadyDone(bool),
            Defect,
            HaltCancel,
            HaltBudget,
        }

        let enter_node = |digest: ContentDigest,
                          depth: u32,
                          marks: &mut BTreeMap<ContentDigest, VisitMark>,
                          member_ok: &BTreeMap<ContentDigest, bool>,
                          defects: &mut Vec<ClosureDefect>,
                          visited_nodes: &mut usize,
                          edge_count: &mut u64,
                          max_observed_depth: &mut u32,
                          total_verified_bytes: &mut u64,
                          steps: &mut usize,
                          should_cancel: &mut F|
         -> EnterOutcome {
            *steps = steps.saturating_add(1);
            if should_cancel(*steps) {
                defects.push(ClosureDefect {
                    digest,
                    kind: ClosureDefectKind::Cancelled,
                    detail: "cooperative cancellation observed during closure traversal".to_owned(),
                });
                return EnterOutcome::HaltCancel;
            }
            match marks.get(&digest) {
                Some(VisitMark::Visiting) => {
                    defects.push(ClosureDefect {
                        digest,
                        kind: ClosureDefectKind::CycleDetected,
                        detail: "directed cycle detected in object dependency graph".to_owned(),
                    });
                    return EnterOutcome::Defect;
                }
                Some(VisitMark::Done) => {
                    return EnterOutcome::AlreadyDone(
                        member_ok.get(&digest).copied().unwrap_or(false),
                    );
                }
                None => {}
            }
            if depth > budget.max_depth {
                defects.push(ClosureDefect {
                    digest,
                    kind: ClosureDefectKind::BudgetExceeded,
                    detail: format!("depth {depth} exceeds max_depth {}", budget.max_depth),
                });
                return EnterOutcome::HaltBudget;
            }
            if *visited_nodes >= budget.max_nodes {
                defects.push(ClosureDefect {
                    digest,
                    kind: ClosureDefectKind::BudgetExceeded,
                    detail: format!("visited nodes exceed max_nodes {}", budget.max_nodes),
                });
                return EnterOutcome::HaltBudget;
            }

            // AUTHORITY-BEFORE-EXPANSION: check privacy/capability restriction BEFORE inspecting bytes!
            if authority.restricted_objects.contains(&digest) {
                marks.insert(digest, VisitMark::Done);
                defects.push(ClosureDefect {
                    digest,
                    kind: ClosureDefectKind::UnauthorizedOrRedacted,
                    detail: "object restricted under active privacy/capability projection"
                        .to_owned(),
                });
                return EnterOutcome::Defect;
            }

            *visited_nodes += 1;
            *max_observed_depth = (*max_observed_depth).max(depth);

            match source.inspect_object(digest) {
                InspectedObject::Missing => {
                    marks.insert(digest, VisitMark::Done);
                    defects.push(ClosureDefect {
                        digest,
                        kind: ClosureDefectKind::Missing,
                        detail: "referenced object is missing from custody".to_owned(),
                    });
                    EnterOutcome::Defect
                }
                InspectedObject::StagedOnly { .. } => {
                    marks.insert(digest, VisitMark::Done);
                    defects.push(ClosureDefect {
                        digest,
                        kind: ClosureDefectKind::StagedOnly,
                        detail: "object is staged only and not yet verified".to_owned(),
                    });
                    EnterOutcome::Defect
                }
                InspectedObject::Tombstoned => {
                    marks.insert(digest, VisitMark::Done);
                    defects.push(ClosureDefect {
                        digest,
                        kind: ClosureDefectKind::Tombstoned,
                        detail: "object is permanently tombstoned".to_owned(),
                    });
                    EnterOutcome::Defect
                }
                InspectedObject::InvalidatedManifest => {
                    marks.insert(digest, VisitMark::Done);
                    defects.push(ClosureDefect {
                        digest,
                        kind: ClosureDefectKind::InvalidatedManifest,
                        detail: "manifest lost publication authority due to descendant deletion"
                            .to_owned(),
                    });
                    EnterOutcome::Defect
                }
                InspectedObject::Corrupt { reason } => {
                    marks.insert(digest, VisitMark::Done);
                    defects.push(ClosureDefect {
                        digest,
                        kind: ClosureDefectKind::Corrupt,
                        detail: clamp_label(&reason),
                    });
                    EnterOutcome::Defect
                }
                InspectedObject::Indeterminate { reason } => {
                    marks.insert(digest, VisitMark::Done);
                    defects.push(ClosureDefect {
                        digest,
                        kind: ClosureDefectKind::Indeterminate,
                        detail: clamp_label(&reason),
                    });
                    EnterOutcome::Defect
                }
                InspectedObject::Present {
                    custody,
                    byte_len,
                    post_repair_verified,
                    edges,
                } => {
                    if custody == CustodyLevel::Staged {
                        marks.insert(digest, VisitMark::Done);
                        defects.push(ClosureDefect {
                            digest,
                            kind: ClosureDefectKind::StagedOnly,
                            detail: "object custody is staged (unverified)".to_owned(),
                        });
                        return EnterOutcome::Defect;
                    }
                    if custody < required_custody_floor {
                        marks.insert(digest, VisitMark::Done);
                        defects.push(ClosureDefect {
                            digest,
                            kind: ClosureDefectKind::BelowCustodyFloor,
                            detail: format!(
                                "observed custody '{}' below required floor '{}'",
                                custody.as_str(),
                                required_custody_floor.as_str()
                            ),
                        });
                        return EnterOutcome::Defect;
                    }
                    let next_bytes = total_verified_bytes.saturating_add(byte_len);
                    if next_bytes > budget.max_bytes {
                        defects.push(ClosureDefect {
                            digest,
                            kind: ClosureDefectKind::BudgetExceeded,
                            detail: format!(
                                "verified bytes {next_bytes} exceed max_bytes {}",
                                budget.max_bytes
                            ),
                        });
                        return EnterOutcome::HaltBudget;
                    }

                    // Sort and deduplicate edges deterministically (canonical CGSE tie-break).
                    let mut canonical_edges = edges;
                    canonical_edges.sort_unstable();
                    canonical_edges.dedup();

                    let mut all_children_ok = true;
                    let mut pending_children = Vec::new();
                    let mut seen_targets = BTreeSet::new();
                    for edge in canonical_edges {
                        if (*edge_count as usize) >= budget.max_edges {
                            defects.push(ClosureDefect {
                                digest: edge.target,
                                kind: ClosureDefectKind::BudgetExceeded,
                                detail: format!("edges exceed max_edges {}", budget.max_edges),
                            });
                            return EnterOutcome::HaltBudget;
                        }
                        *edge_count += 1;
                        if !authority.allowed_edge_kinds.contains(&edge.kind) {
                            all_children_ok = false;
                            defects.push(ClosureDefect {
                                digest: edge.target,
                                kind: ClosureDefectKind::UnauthorizedOrRedacted,
                                detail: format!(
                                    "edge kind '{}' not permitted by active projection",
                                    edge.kind.as_str()
                                ),
                            });
                            continue;
                        }
                        if seen_targets.insert(edge.target) {
                            pending_children.push(edge.target);
                        }
                    }

                    *total_verified_bytes = next_bytes;
                    marks.insert(digest, VisitMark::Visiting);
                    let child_edge_count =
                        u32::try_from(pending_children.len()).unwrap_or(u32::MAX);
                    EnterOutcome::Pushed(Frame {
                        digest,
                        depth,
                        custody,
                        byte_len,
                        post_repair_verified,
                        child_edge_count,
                        pending_children,
                        next_child_idx: 0,
                        all_children_ok,
                    })
                }
            }
        };

        match enter_node(
            root,
            0,
            &mut marks,
            &member_ok,
            &mut defects,
            &mut visited_nodes,
            &mut edge_count,
            &mut max_observed_depth,
            &mut total_verified_bytes,
            &mut steps,
            &mut should_cancel,
        ) {
            EnterOutcome::Pushed(frame) => stack.push(frame),
            EnterOutcome::AlreadyDone(_) | EnterOutcome::Defect => {}
            EnterOutcome::HaltCancel => halted_cancel = true,
            EnterOutcome::HaltBudget => halted_budget = true,
        }

        while !halted_cancel && !halted_budget {
            let Some(top) = stack.last_mut() else {
                break;
            };
            if top.next_child_idx < top.pending_children.len() {
                let child = top.pending_children[top.next_child_idx];
                let child_depth = top.depth.saturating_add(1);
                top.next_child_idx += 1;
                match enter_node(
                    child,
                    child_depth,
                    &mut marks,
                    &member_ok,
                    &mut defects,
                    &mut visited_nodes,
                    &mut edge_count,
                    &mut max_observed_depth,
                    &mut total_verified_bytes,
                    &mut steps,
                    &mut should_cancel,
                ) {
                    EnterOutcome::Pushed(frame) => stack.push(frame),
                    EnterOutcome::AlreadyDone(ok) => {
                        if !ok && let Some(parent) = stack.last_mut() {
                            parent.all_children_ok = false;
                        }
                    }
                    EnterOutcome::Defect => {
                        if let Some(parent) = stack.last_mut() {
                            parent.all_children_ok = false;
                        }
                    }
                    EnterOutcome::HaltCancel => halted_cancel = true,
                    EnterOutcome::HaltBudget => halted_budget = true,
                }
            } else if let Some(done) = stack.pop() {
                marks.insert(done.digest, VisitMark::Done);
                member_ok.insert(done.digest, done.all_children_ok);
                if done.all_children_ok {
                    ordered_members.push(ClosureMember {
                        digest: done.digest,
                        custody: done.custody,
                        byte_len: done.byte_len,
                        depth: done.depth,
                        child_edge_count: done.child_edge_count,
                        post_repair_verified: done.post_repair_verified,
                    });
                } else if let Some(parent) = stack.last_mut() {
                    parent.all_children_ok = false;
                }
            }
        }

        let (verdict, guidance) = classify_outcome(&defects, halted_cancel, halted_budget);
        let verified_bytes: u64 = ordered_members
            .iter()
            .fold(0u64, |acc, m| acc.saturating_add(m.byte_len));

        let mut witness = ClosureVerificationWitness {
            format_version: CLOSURE_WITNESS_VERSION,
            root,
            contract_basis_digest: authority.contract_basis_digest,
            authority_generation: authority.authority_generation,
            privacy_epoch: authority.privacy_epoch,
            required_custody_floor,
            verdict,
            guidance,
            ordered_members,
            edge_count,
            max_observed_depth,
            total_verified_bytes: verified_bytes,
            defects,
            witness_digest: ContentDigest::sha256(b"unsealed-closure-witness"),
        };
        witness.witness_digest = witness.compute_digest()?;
        Ok(witness)
    }
}

fn classify_outcome(
    defects: &[ClosureDefect],
    halted_cancel: bool,
    halted_budget: bool,
) -> (ClosureVerdict, ClosureRecoveryGuidance) {
    if defects.is_empty() && !halted_cancel && !halted_budget {
        return (
            ClosureVerdict::VerifiedComplete,
            ClosureRecoveryGuidance::ReadyForRootPublication,
        );
    }
    if halted_cancel
        || defects
            .iter()
            .any(|d| d.kind == ClosureDefectKind::Cancelled)
    {
        return (
            ClosureVerdict::Cancelled,
            ClosureRecoveryGuidance::RetryFromCleanState,
        );
    }
    if halted_budget
        || defects
            .iter()
            .any(|d| d.kind == ClosureDefectKind::BudgetExceeded)
    {
        return (
            ClosureVerdict::BudgetExceeded,
            ClosureRecoveryGuidance::RaiseTraversalBudget,
        );
    }
    if defects.iter().any(|d| {
        matches!(
            d.kind,
            ClosureDefectKind::Corrupt
                | ClosureDefectKind::Tombstoned
                | ClosureDefectKind::InvalidatedManifest
                | ClosureDefectKind::CycleDetected
        )
    }) {
        return (
            ClosureVerdict::CorruptOrInvalidated,
            ClosureRecoveryGuidance::QuarantineAndRepairCorruptGraph,
        );
    }
    if defects
        .iter()
        .any(|d| d.kind == ClosureDefectKind::UnauthorizedOrRedacted)
    {
        return (
            ClosureVerdict::Unauthorized,
            ClosureRecoveryGuidance::ReauthorizeOrPruneRestrictedSubgraph,
        );
    }
    if defects
        .iter()
        .any(|d| d.kind == ClosureDefectKind::Indeterminate)
    {
        return (
            ClosureVerdict::Indeterminate,
            ClosureRecoveryGuidance::ReconcileIndeterminateCustody,
        );
    }
    (
        ClosureVerdict::Incomplete,
        ClosureRecoveryGuidance::WaitForMissingOrStagedChildren,
    )
}

fn clamp_label(raw: &str) -> String {
    if raw.len() <= MAX_CLOSURE_LABEL_BYTES {
        return raw.to_owned();
    }
    let mut end = MAX_CLOSURE_LABEL_BYTES;
    while end > 0 && !raw.is_char_boundary(end) {
        end -= 1;
    }
    raw[..end].to_owned()
}

fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}
