#![forbid(unsafe_code)]
//! Certified d-separation and shared-failure-domain causal independence analysis
//! (`FSS-161`, `fss-x4a.23.11`).
//!
//! Composes directly over capability- and privacy-filtered [`ImmutableGraphProjection`]
//! (`FSS-151`) and owner-declared [`FailureDomain`] sets (`failure_domains.rs`) to answer
//! whether two evidence/sensor variable sets `X` and `Y` are d-separated given conditioning set
//! `Z` (`X ⊥ Y | Z`):
//!
//! - **Capability-first causal DAG projection ([`CausalDag`]):** delegates node/edge filtering to
//!   [`ImmutableGraphProjection::build`] BEFORE expansion, validates strict acyclicity via
//!   deterministic Kahn topological sort (refusing cycles fail-closed), and preserves
//!   [`AbsenceBoundary`] so redacted/gapped views can NEVER launder apparent independence into
//!   certified independence.
//! - **Exact `O(|V| + |E|)` Bayes-Ball engine ([`CausalDag::evaluate_d_separation`]):** evaluates
//!   active paths under canonical CGSE tie-break order with checked work budgets, cooperative
//!   cancellation, and shortest canonical [`ActivePathWitness`] reconstruction + self-verification.
//! - **Independent Moralized Ancestral Graph reference oracle
//!   ([`CausalDag::oracle_d_separation_moralized_ancestral`]):** completely separate Lauritzen
//!   graph-moralization algorithm (`Ancestors(X ∪ Y ∪ Z)` -> marry co-parents -> remove `Z` ->
//!   undirected reachability) for 100% differential certification.
//! - **Shared-failure-domain corroboration compiler ([`CausalDag::from_failure_domains`] and
//!   [`CausalDag::assess_corroboration_independence`]):** compiles owner-declared `Power`,
//!   `Network`, `Clock`, and `Host` failure domains into directed common-cause forks
//!   `failure/<kind>/<id> -> sensor/<member>` and observation colliders `sensor/<member> -> zone/<zone>`,
//!   proving mathematically that sensors sharing an unconditioned failure domain are NOT
//!   independent corroborators.
//! - **Bounded checksummed binary receipt (`FSSDSE01` v1):** sealed under
//!   `fss.graph.d_separation_receipt.v1`; derived cognition only (`grants_effect_authority() == false`).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    LedgerAnchor, Plane, Sha256Hasher,
};

use crate::GraphBudget;
use crate::coverage::{SENSOR_PREFIX, SensorCoverageProjection, ZONE_PREFIX};
use crate::failure_domains::{FailureDomain, analyse_failure_domains};
use crate::projection::{
    AbsenceBoundary, GraphUniverse, ImmutableGraphProjection, ProjectionAuthorityScope,
    ProjectionEdgeSpec, ProjectionError, ProjectionNodeSpec, ProjectionOrientation,
};

/// Registered digest domain for canonical [`CausalDag`] commitments (`FSS-161`).
pub const GRAPH_CAUSAL_DAG_DOMAIN: &str = "fss.graph.causal_dag.v1";
/// Registered digest domain for sealed [`DSeparationReceipt`] commitments (`FSS-161`).
pub const GRAPH_D_SEPARATION_RECEIPT_DOMAIN: &str = "fss.graph.d_separation_receipt.v1";
/// Binary wire header magic for serialized [`DSeparationReceipt`].
pub const D_SEPARATION_WIRE_MAGIC: [u8; 8] = *b"FSSDSE01";
/// Current wire format version for [`DSeparationReceipt`].
pub const D_SEPARATION_WIRE_VERSION: u32 = 1;
/// Hard ceiling on nodes in one [`CausalDag`].
pub const MAX_CAUSAL_NODES: usize = 4_096;
/// Hard ceiling on directed edges in one [`CausalDag`].
pub const MAX_CAUSAL_EDGES: usize = 16_384;
/// Hard ceiling on variable identities in any single query set (`X`, `Y`, or `Z`).
pub const MAX_QUERY_SET_LEN: usize = 256;
/// Hard ceiling on dominant traversal operations in one d-separation query.
pub const MAX_D_SEP_OPERATIONS: u64 = 1_000_000;
/// Hard ceiling on serialized [`DSeparationReceipt`] wire bytes (512 KiB).
pub const MAX_D_SEPARATION_WIRE_BYTES: usize = 512 * 1024;
/// Maximum UTF-8 bytes in query identifiers and labels.
pub const MAX_D_SEP_LABEL_BYTES: usize = 128;

const WIRE_HEADER_BYTES: usize = 16;
const WIRE_CHECKSUM_BYTES: usize = 32;

/// Safe operator/agent recovery guidance for a refused d-separation analysis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DSeparationGuidance {
    /// Remove directed cycles, self-loops, overlapping query sets, or unknown nodes.
    RepairCausalGraphOrQuery,
    /// Re-authorize capability, privacy projection, universe, or current authority generation.
    ReauthorizeProjection,
    /// Increase declared operation budget or narrow the causal subgraph before re-running.
    IncreaseBudgetOrNarrowGraph,
    /// Cooperative cancellation observed; safe to retry cleanly from the pinned anchor.
    RetryFromPinnedAnchor,
    /// Reject corrupt or unsupported binary receipt bytes and re-evaluate from pinned DAG.
    RejectCorruptReceipt,
}

/// Typed fail-closed error returned by [`CausalDag`] and [`DSeparationReceipt`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DSeparationError {
    /// Underlying [`ImmutableGraphProjection`] authority, privacy, or input refusal.
    Projection(ProjectionError),
    /// Directed graph contains a cycle and therefore is not a valid causal DAG.
    CycleDetected {
        /// Canonically sorted member node IDs belonging to or blocked by the cycle.
        cycle_nodes: Vec<String>,
    },
    /// Invalid query set (empty `X`/`Y`, overlapping `X`/`Y`/`Z`, duplicate or unknown node IDs).
    InvalidInput(String),
    /// Configured node, edge, query-set, or wire-size ceiling exceeded.
    BoundsExceeded {
        /// Observed count or byte length.
        observed: usize,
        /// Hard maximum allowed.
        maximum: usize,
    },
    /// Dominant operation budget exhausted before traversal finished.
    BudgetExhausted {
        /// Operations charged when refusal triggered.
        used: u64,
        /// Active operation ceiling.
        limit: u64,
    },
    /// Cooperative cancellation observed cleanly with no partial answer.
    Cancelled,
    /// Internal witness consistency check failed (defensive belt-and-suspenders guard).
    InconsistentWitness(String),
    /// Binary receipt magic header mismatch.
    InvalidMagic,
    /// Binary receipt format version unsupported.
    UnsupportedVersion {
        /// Unsupported version tag observed.
        version: u32,
    },
    /// Binary receipt checksum or self-digest verification failed.
    ChecksumMismatch,
    /// Binary receipt was truncated, oversized, or structurally malformed.
    MalformedWire(String),
}

impl DSeparationError {
    /// Registered stable machine error identity.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Projection(_) => "ERR-GRAPH-DSEP-PROJECTION-001",
            Self::CycleDetected { .. } => "ERR-GRAPH-DSEP-CYCLE-001",
            Self::InvalidInput(_) => "ERR-GRAPH-DSEP-INVALID-INPUT-001",
            Self::BoundsExceeded { .. } => "ERR-GRAPH-DSEP-BOUNDS-001",
            Self::BudgetExhausted { .. } => "ERR-GRAPH-DSEP-BUDGET-001",
            Self::Cancelled => "ERR-GRAPH-DSEP-CANCELLED-001",
            Self::InconsistentWitness(_) => "ERR-GRAPH-DSEP-WITNESS-001",
            Self::InvalidMagic | Self::UnsupportedVersion { .. } => "ERR-SCHEMA-UNSUPPORTED-001",
            Self::ChecksumMismatch => "ERR-NEG-CHECKSUM-MISMATCH-001",
            Self::MalformedWire(_) => "ERR-GRAPH-DSEP-MALFORMED-WIRE-001",
        }
    }

    /// Safe recovery guidance for this refusal.
    #[must_use]
    pub const fn guidance(&self) -> DSeparationGuidance {
        match self {
            Self::Projection(
                ProjectionError::AuthorityRevoked(_)
                | ProjectionError::StaleAuthorityGeneration { .. },
            ) => DSeparationGuidance::ReauthorizeProjection,
            Self::Projection(ProjectionError::Cancelled) | Self::Cancelled => {
                DSeparationGuidance::RetryFromPinnedAnchor
            }
            Self::Projection(_)
            | Self::CycleDetected { .. }
            | Self::InvalidInput(_)
            | Self::BoundsExceeded { .. } => DSeparationGuidance::RepairCausalGraphOrQuery,
            Self::BudgetExhausted { .. } => DSeparationGuidance::IncreaseBudgetOrNarrowGraph,
            Self::InconsistentWitness(_)
            | Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::ChecksumMismatch
            | Self::MalformedWire(_) => DSeparationGuidance::RejectCorruptReceipt,
        }
    }
}

impl fmt::Display for DSeparationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.code(), self)
    }
}

impl Error for DSeparationError {}

impl From<ProjectionError> for DSeparationError {
    fn from(value: ProjectionError) -> Self {
        Self::Projection(value)
    }
}

/// Checked work budget for d-separation queries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DSeparationBudget {
    /// Maximum dominant BFS/ancestor/edge inspection operations admitted.
    pub max_operations: u64,
}

impl DSeparationBudget {
    /// Constructs a concrete bounded budget clamped to [`MAX_D_SEP_OPERATIONS`].
    #[must_use]
    pub const fn new(max_operations: u64) -> Self {
        Self { max_operations }
    }

    /// Default hard ceiling budget ([`MAX_D_SEP_OPERATIONS`]).
    #[must_use]
    pub const fn ceiling() -> Self {
        Self {
            max_operations: MAX_D_SEP_OPERATIONS,
        }
    }
}

/// Non-collapsed d-separation verdict preserving projection completeness (`FSS-161`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DSeparationVerdict {
    /// `X ⊥ Y | Z` holds AND the backing projection carries [`AbsenceBoundary::CertifiedComplete`].
    CertifiedDSeparated = 1,
    /// `X ⊥ Y | Z` holds on the visible projection ONLY; redacted/gapped nodes prevent certifying
    /// global independence (an unobserved common cause may exist in omitted evidence!).
    DSeparatedOnPartialView = 2,
    /// Concrete open active path exists between `X` and `Y` given `Z` (positive dependence evidence).
    DConnected = 3,
}

impl DSeparationVerdict {
    /// Stable canonical string spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CertifiedDSeparated => "certified_d_separated",
            Self::DSeparatedOnPartialView => "d_separated_on_partial_view",
            Self::DConnected => "d_connected",
        }
    }

    /// True iff no active path was found on the visible graph (whether certified or partial).
    #[must_use]
    pub const fn is_d_separated_on_projection(self) -> bool {
        matches!(
            self,
            Self::CertifiedDSeparated | Self::DSeparatedOnPartialView
        )
    }

    /// True iff global independence is certified on a complete non-redacted projection.
    #[must_use]
    pub const fn certifies_independence(self) -> bool {
        matches!(self, Self::CertifiedDSeparated)
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, DSeparationError> {
        match tag {
            1 => Ok(Self::CertifiedDSeparated),
            2 => Ok(Self::DSeparatedOnPartialView),
            3 => Ok(Self::DConnected),
            other => Err(DSeparationError::MalformedWire(format!(
                "unknown DSeparationVerdict tag {other}"
            ))),
        }
    }
}

/// Direction of the directed DAG edge traversed to arrive at a path node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathStepDirection {
    /// Starting node belonging to `X`.
    Start = 0,
    /// Traversed forward along a directed edge `prev -> node`.
    Forward = 1,
    /// Traversed backward against a directed edge `prev <- node`.
    Backward = 2,
}

impl PathStepDirection {
    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, DSeparationError> {
        match tag {
            0 => Ok(Self::Start),
            1 => Ok(Self::Forward),
            2 => Ok(Self::Backward),
            other => Err(DSeparationError::MalformedWire(format!(
                "unknown PathStepDirection tag {other}"
            ))),
        }
    }
}

/// One node along a concrete active d-connecting path witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivePathStep {
    /// Stable node identity in the causal DAG.
    pub node_id: String,
    /// Direction traversed from the previous node to reach `node_id`.
    pub direction_from_prev: PathStepDirection,
}

/// Structural classification of an internal triple `(left, middle, right)` on an active path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActiveTripleKind {
    /// `left -> middle -> right` with `middle ∉ Z`.
    ChainForward = 1,
    /// `left <- middle <- right` with `middle ∉ Z`.
    ChainBackward = 2,
    /// `left <- middle -> right` (common-cause fork!) with `middle ∉ Z`.
    Fork = 3,
    /// `left -> middle <- right` (collider!) with `middle ∈ Z` or a descendant of `middle` in `Z`.
    ColliderActivated = 4,
}

impl ActiveTripleKind {
    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, DSeparationError> {
        match tag {
            1 => Ok(Self::ChainForward),
            2 => Ok(Self::ChainBackward),
            3 => Ok(Self::Fork),
            4 => Ok(Self::ColliderActivated),
            other => Err(DSeparationError::MalformedWire(format!(
                "unknown ActiveTripleKind tag {other}"
            ))),
        }
    }
}

/// One verified internal triple on an active path explaining why information flows through `middle`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveTriple {
    /// Center node of the triple.
    pub middle_node_id: String,
    /// Causal structure active at `middle_node_id`.
    pub kind: ActiveTripleKind,
}

/// Concrete vertex-simple open active path proving `X` and `Y` are d-connected given `Z`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivePathWitness {
    /// Ordered steps from `x ∈ X` to `y ∈ Y`.
    pub steps: Vec<ActivePathStep>,
    /// Classified internal triples (`len == steps.len().saturating_sub(2)`).
    pub triples: Vec<ActiveTriple>,
}

impl ActivePathWitness {
    /// Returns all common-cause fork centers (`left <- middle -> right`) along this open path.
    #[must_use]
    pub fn fork_causes(&self) -> Vec<&str> {
        self.triples
            .iter()
            .filter(|t| t.kind == ActiveTripleKind::Fork)
            .map(|t| t.middle_node_id.as_str())
            .collect()
    }

    fn encode_canonical(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.steps.len() as u32);
        for step in &self.steps {
            enc.text(&step.node_id);
            enc.u8(step.direction_from_prev.tag());
        }
        enc.u32(self.triples.len() as u32);
        for triple in &self.triples {
            enc.text(&triple.middle_node_id);
            enc.u8(triple.kind.tag());
        }
    }

    fn decode_canonical(dec: &mut CanonicalDecoder<'_>) -> Result<Self, DSeparationError> {
        let step_len =
            dec.u32()
                .map_err(|e| DSeparationError::MalformedWire(e.to_string()))? as usize;
        if !(2..=MAX_CAUSAL_NODES).contains(&step_len) {
            return Err(DSeparationError::MalformedWire(format!(
                "active path step count {step_len} out of valid range 2..={MAX_CAUSAL_NODES}"
            )));
        }
        let mut steps = Vec::with_capacity(step_len);
        for i in 0..step_len {
            let node_id = dec
                .text()
                .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?
                .to_owned();
            validate_label(&node_id, MAX_D_SEP_LABEL_BYTES, "path_step.node_id")?;
            let direction_from_prev = PathStepDirection::from_tag(
                dec.u8()
                    .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?,
            )?;
            if i == 0 && direction_from_prev != PathStepDirection::Start {
                return Err(DSeparationError::MalformedWire(
                    "first active path step must have direction Start".to_owned(),
                ));
            }
            if i > 0 && direction_from_prev == PathStepDirection::Start {
                return Err(DSeparationError::MalformedWire(
                    "non-initial active path step cannot have direction Start".to_owned(),
                ));
            }
            steps.push(ActivePathStep {
                node_id,
                direction_from_prev,
            });
        }
        let triple_len =
            dec.u32()
                .map_err(|e| DSeparationError::MalformedWire(e.to_string()))? as usize;
        if triple_len != step_len.saturating_sub(2) {
            return Err(DSeparationError::MalformedWire(format!(
                "active path triple count {triple_len} must equal step_len - 2 ({})",
                step_len.saturating_sub(2)
            )));
        }
        let mut triples = Vec::with_capacity(triple_len);
        for i in 0..triple_len {
            let middle_node_id = dec
                .text()
                .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?
                .to_owned();
            if middle_node_id != steps[i + 1].node_id {
                return Err(DSeparationError::MalformedWire(
                    "active triple middle_node_id disagrees with step sequence".to_owned(),
                ));
            }
            let kind = ActiveTripleKind::from_tag(
                dec.u8()
                    .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?,
            )?;
            triples.push(ActiveTriple {
                middle_node_id,
                kind,
            });
        }
        Ok(Self { steps, triples })
    }
}

/// Sealed, checksummed d-separation evaluation receipt (`FSSDSE01` v1, `FSS-161`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DSeparationReceipt {
    /// Wire format version (`1`).
    pub format_version: u32,
    /// Stable query identifier.
    pub query_id: String,
    /// Registered graph universe of the backing projection.
    pub universe: GraphUniverse,
    /// Pinned ledger anchor of the backing projection.
    pub anchor: LedgerAnchor,
    /// Pinned history root of the backing projection.
    pub history_root: ContentDigest,
    /// Underlying `FSS-151` projection digest.
    pub projection_digest: ContentDigest,
    /// Canonical causal DAG commitment digest under [`GRAPH_CAUSAL_DAG_DOMAIN`].
    pub dag_digest: ContentDigest,
    /// Non-collapsed absence boundary inherited from the capability-filtered projection.
    pub absence_boundary: AbsenceBoundary,
    /// Canonically sorted query source set `X`.
    pub source_set_x: Vec<String>,
    /// Canonically sorted query target set `Y`.
    pub target_set_y: Vec<String>,
    /// Canonically sorted conditioning set `Z`.
    pub conditioning_set_z: Vec<String>,
    /// Non-collapsed verdict (`CertifiedDSeparated`, `DSeparatedOnPartialView`, or `DConnected`).
    pub verdict: DSeparationVerdict,
    /// Concrete simple active path witness iff `verdict == DSeparationVerdict::DConnected`.
    pub active_path: Option<ActivePathWitness>,
    /// Total dominant operations charged during ancestor marking and Bayes-Ball traversal.
    pub operations_used: u64,
    /// Domain-separated SHA-256 commitment under [`GRAPH_D_SEPARATION_RECEIPT_DOMAIN`].
    pub receipt_digest: ContentDigest,
}

impl DSeparationReceipt {
    /// Derived graph cognition NEVER grants effect authority (`GRAPH-INV-004`).
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Computes canonical SHA-256 commitment digest under [`GRAPH_D_SEPARATION_RECEIPT_DOMAIN`].
    pub fn compute_digest(&self) -> Result<ContentDigest, DSeparationError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(GRAPH_D_SEPARATION_RECEIPT_DOMAIN);
        self.encode_fields(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn encode_fields(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.text(&self.query_id);
        enc.u8(self.universe as u8);
        self.anchor.encode_canonical(enc);
        enc.digest(self.history_root);
        enc.digest(self.projection_digest);
        enc.digest(self.dag_digest);
        self.absence_boundary.encode_canonical(enc);
        encode_string_vec(enc, &self.source_set_x);
        encode_string_vec(enc, &self.target_set_y);
        encode_string_vec(enc, &self.conditioning_set_z);
        enc.u8(self.verdict.tag());
        match &self.active_path {
            None => enc.u8(0),
            Some(path) => {
                enc.u8(1);
                path.encode_canonical(enc);
            }
        }
        enc.u64(self.operations_used);
    }

    /// Verifies structural invariants, verdict/absence coherence, and commitment digest.
    pub fn verify_self(&self) -> Result<(), DSeparationError> {
        if self.format_version != D_SEPARATION_WIRE_VERSION {
            return Err(DSeparationError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        validate_label(&self.query_id, MAX_D_SEP_LABEL_BYTES, "query_id")?;
        validate_canonical_set(&self.source_set_x, false, "source_set_x")?;
        validate_canonical_set(&self.target_set_y, false, "target_set_y")?;
        validate_canonical_set(&self.conditioning_set_z, true, "conditioning_set_z")?;
        let x_set: BTreeSet<&str> = self.source_set_x.iter().map(String::as_str).collect();
        let y_set: BTreeSet<&str> = self.target_set_y.iter().map(String::as_str).collect();
        for y in &self.target_set_y {
            if x_set.contains(y.as_str()) {
                return Err(DSeparationError::MalformedWire(
                    "receipt source_set_x and target_set_y overlap".to_owned(),
                ));
            }
        }
        for z in &self.conditioning_set_z {
            if x_set.contains(z.as_str()) || y_set.contains(z.as_str()) {
                return Err(DSeparationError::MalformedWire(
                    "receipt conditioning_set_z overlaps X or Y".to_owned(),
                ));
            }
        }
        match self.verdict {
            DSeparationVerdict::CertifiedDSeparated => {
                if !self.absence_boundary.certifies_absence() {
                    return Err(DSeparationError::MalformedWire(
                        "CertifiedDSeparated is forbidden when absence_boundary is uncertified"
                            .to_owned(),
                    ));
                }
                if self.active_path.is_some() {
                    return Err(DSeparationError::MalformedWire(
                        "CertifiedDSeparated cannot carry an active_path witness".to_owned(),
                    ));
                }
            }
            DSeparationVerdict::DSeparatedOnPartialView => {
                if self.absence_boundary.certifies_absence() {
                    return Err(DSeparationError::MalformedWire(
                        "DSeparatedOnPartialView disagrees with CertifiedComplete absence_boundary"
                            .to_owned(),
                    ));
                }
                if self.active_path.is_some() {
                    return Err(DSeparationError::MalformedWire(
                        "DSeparatedOnPartialView cannot carry an active_path witness".to_owned(),
                    ));
                }
            }
            DSeparationVerdict::DConnected => {
                let Some(path) = &self.active_path else {
                    return Err(DSeparationError::MalformedWire(
                        "DConnected verdict must include a concrete ActivePathWitness".to_owned(),
                    ));
                };
                if path.steps.len() < 2 || path.triples.len() != path.steps.len().saturating_sub(2)
                {
                    return Err(DSeparationError::MalformedWire(
                        "ActivePathWitness step/triple lengths inconsistent".to_owned(),
                    ));
                }
                if !x_set.contains(path.steps[0].node_id.as_str())
                    || !y_set.contains(path.steps[path.steps.len() - 1].node_id.as_str())
                {
                    return Err(DSeparationError::MalformedWire(
                        "ActivePathWitness endpoints do not belong to X and Y".to_owned(),
                    ));
                }
                let mut distinct_steps = BTreeSet::new();
                for step in &path.steps {
                    if !distinct_steps.insert(step.node_id.as_str()) {
                        return Err(DSeparationError::MalformedWire(
                            "ActivePathWitness repeats a vertex".to_owned(),
                        ));
                    }
                }
                for (i, triple) in path.triples.iter().enumerate() {
                    let in_dir = path.steps[i + 1].direction_from_prev;
                    let out_dir = path.steps[i + 2].direction_from_prev;
                    let expected_kind = match (in_dir, out_dir) {
                        (PathStepDirection::Forward, PathStepDirection::Forward) => {
                            ActiveTripleKind::ChainForward
                        }
                        (PathStepDirection::Backward, PathStepDirection::Backward) => {
                            ActiveTripleKind::ChainBackward
                        }
                        (PathStepDirection::Backward, PathStepDirection::Forward) => {
                            ActiveTripleKind::Fork
                        }
                        (PathStepDirection::Forward, PathStepDirection::Backward) => {
                            ActiveTripleKind::ColliderActivated
                        }
                        _ => {
                            return Err(DSeparationError::MalformedWire(
                                "ActivePathWitness contains invalid step directions".to_owned(),
                            ));
                        }
                    };
                    if triple.kind != expected_kind
                        || triple.middle_node_id != path.steps[i + 1].node_id
                    {
                        return Err(DSeparationError::MalformedWire(
                            "ActivePathWitness triple disagrees with step directions".to_owned(),
                        ));
                    }
                }
            }
        }
        if self.compute_digest()? != self.receipt_digest {
            return Err(DSeparationError::ChecksumMismatch);
        }
        Ok(())
    }

    /// Encodes into its versioned, checksummed `FSSDSE01` v1 binary wire envelope.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, DSeparationError> {
        self.verify_self()?;
        let mut enc = CanonicalEncoder::new();
        self.encode_fields(&mut enc);
        enc.digest(self.receipt_digest);
        let payload = enc
            .finish_checked()
            .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?;
        let total = WIRE_HEADER_BYTES
            .checked_add(payload.len())
            .and_then(|n| n.checked_add(WIRE_CHECKSUM_BYTES))
            .ok_or(DSeparationError::BoundsExceeded {
                observed: usize::MAX,
                maximum: MAX_D_SEPARATION_WIRE_BYTES,
            })?;
        if total > MAX_D_SEPARATION_WIRE_BYTES {
            return Err(DSeparationError::BoundsExceeded {
                observed: total,
                maximum: MAX_D_SEPARATION_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&D_SEPARATION_WIRE_MAGIC);
        out.extend_from_slice(&D_SEPARATION_WIRE_VERSION.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        let mut hasher = Sha256Hasher::new();
        hasher.update(GRAPH_D_SEPARATION_RECEIPT_DOMAIN.as_bytes());
        hasher.update(&out);
        let checksum = hasher
            .finalize()
            .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?;
        out.extend_from_slice(&checksum);
        Ok(out)
    }

    /// Strictly decodes an `FSSDSE01` v1 binary wire envelope, failing closed on tamper or drift.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DSeparationError> {
        let min_len = WIRE_HEADER_BYTES + WIRE_CHECKSUM_BYTES;
        if bytes.len() < min_len {
            return Err(DSeparationError::MalformedWire(format!(
                "wire length {} below minimum {min_len}",
                bytes.len()
            )));
        }
        if bytes.len() > MAX_D_SEPARATION_WIRE_BYTES {
            return Err(DSeparationError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_D_SEPARATION_WIRE_BYTES,
            });
        }
        if bytes[..8] != D_SEPARATION_WIRE_MAGIC {
            return Err(DSeparationError::InvalidMagic);
        }
        let version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if version != D_SEPARATION_WIRE_VERSION {
            return Err(DSeparationError::UnsupportedVersion { version });
        }
        let declared_len =
            u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
        let expected_total = WIRE_HEADER_BYTES
            .checked_add(declared_len)
            .and_then(|n| n.checked_add(WIRE_CHECKSUM_BYTES))
            .ok_or_else(|| {
                DSeparationError::MalformedWire("declared payload length overflow".to_owned())
            })?;
        if bytes.len() != expected_total {
            return Err(DSeparationError::MalformedWire(format!(
                "wire length {} disagrees with declared payload length {declared_len}",
                bytes.len()
            )));
        }
        let split_at = bytes.len() - WIRE_CHECKSUM_BYTES;
        let (body, trailer) = bytes.split_at(split_at);
        let mut hasher = Sha256Hasher::new();
        hasher.update(GRAPH_D_SEPARATION_RECEIPT_DOMAIN.as_bytes());
        hasher.update(body);
        let computed = hasher
            .finalize()
            .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?;
        if computed.as_slice() != trailer {
            return Err(DSeparationError::ChecksumMismatch);
        }

        let mut dec = CanonicalDecoder::new(&body[WIRE_HEADER_BYTES..]);
        let format_version = dec
            .u32()
            .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?;
        let query_id = dec
            .text()
            .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?
            .to_owned();
        let universe = decode_universe(
            dec.u8()
                .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?,
        )?;
        let anchor = LedgerAnchor::decode_canonical(&mut dec)
            .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?;
        let history_root = dec
            .digest()
            .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?;
        let projection_digest = dec
            .digest()
            .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?;
        let dag_digest = dec
            .digest()
            .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?;
        let absence_boundary = AbsenceBoundary::decode_canonical(&mut dec)?;
        let source_set_x = decode_string_vec(&mut dec)?;
        let target_set_y = decode_string_vec(&mut dec)?;
        let conditioning_set_z = decode_string_vec(&mut dec)?;
        let verdict = DSeparationVerdict::from_tag(
            dec.u8()
                .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?,
        )?;
        let active_path = match dec
            .u8()
            .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?
        {
            0 => None,
            1 => Some(ActivePathWitness::decode_canonical(&mut dec)?),
            other => {
                return Err(DSeparationError::MalformedWire(format!(
                    "unknown active_path option tag {other}"
                )));
            }
        };
        let operations_used = dec
            .u64()
            .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?;
        let receipt_digest = dec
            .digest()
            .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?;
        dec.ensure_finished()
            .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?;

        let receipt = Self {
            format_version,
            query_id,
            universe,
            anchor,
            history_root,
            projection_digest,
            dag_digest,
            absence_boundary,
            source_set_x,
            target_set_y,
            conditioning_set_z,
            verdict,
            active_path,
            operations_used,
            receipt_digest,
        };
        receipt.verify_self()?;
        Ok(receipt)
    }
}

/// Non-collapsed corroboration independence status over a set of candidate sensors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorroborationIndependenceStatus {
    /// Every distinct sensor pair is `CertifiedDSeparated` on a complete non-redacted projection.
    IndependentOnCertifiedProjection,
    /// No active confounding path was observed, but projection redactions/gaps forbid certification.
    UncertifiedPartialView,
    /// At least one sensor pair is d-connected (e.g., shares a common `FailureDomain` or conditioned collider).
    ConfoundedBySharedDomains,
}

/// Pairwise sensor d-separation finding inside [`CorroborationIndependenceReport`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairwiseCorroborationFinding {
    /// First sensor node ID (`sensor/<id>`).
    pub sensor_a: String,
    /// Second sensor node ID (`sensor/<id>`).
    pub sensor_b: String,
    /// Full d-separation receipt for `{sensor_a} ⊥ {sensor_b} | conditioned`.
    pub receipt: DSeparationReceipt,
    /// Common-cause fork nodes (`failure/<kind>/<id>` or causal forks) confounding this pair.
    pub shared_fork_causes: Vec<String>,
}

/// Multi-sensor corroboration independence report compiled over a [`CausalDag`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorroborationIndependenceReport {
    /// Non-collapsed overall independence status.
    pub status: CorroborationIndependenceStatus,
    /// Canonical pairwise checks in ascending `(sensor_a, sensor_b)` order.
    pub pair_findings: Vec<PairwiseCorroborationFinding>,
    /// Total dominant operations charged across all pairwise queries.
    pub total_operations: u64,
}

impl CorroborationIndependenceReport {
    /// Corroboration analysis is derived cognition and never grants effect authority.
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }
}

/// Immutable, capability-filtered, canonically sorted directed acyclic causal graph (`FSS-161`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CausalDag {
    projection: ImmutableGraphProjection,
    /// Stable node IDs indexed by canonical dense node index (verified through `FSS-151` handles).
    node_ids: Vec<String>,
    /// Sorted outgoing neighbor indices `u -> v` per dense node index `u`.
    children: Vec<Vec<u32>>,
    /// Sorted incoming parent indices `p -> v` per dense node index `v`.
    parents: Vec<Vec<u32>>,
    /// Deterministic Kahn min-heap topological ordering of dense node indices.
    topological_order: Vec<u32>,
    /// Domain-separated commitment digest under [`GRAPH_CAUSAL_DAG_DOMAIN`].
    dag_digest: ContentDigest,
}

impl CausalDag {
    /// Builds a capability-filtered [`CausalDag`] directly from raw node and directed edge specs.
    ///
    /// Capability and privacy filtering run BEFORE expansion inside
    /// [`ImmutableGraphProjection::build`]; any directed cycle or self-loop fails closed with
    /// [`DSeparationError::CycleDetected`].
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        universe: GraphUniverse,
        anchor: LedgerAnchor,
        history_root: ContentDigest,
        authority: &ProjectionAuthorityScope,
        raw_nodes: Vec<ProjectionNodeSpec>,
        raw_edges: Vec<ProjectionEdgeSpec>,
        requested_absence: AbsenceBoundary,
        cancelled: bool,
    ) -> Result<Self, DSeparationError> {
        if raw_nodes.len() > MAX_CAUSAL_NODES {
            return Err(DSeparationError::BoundsExceeded {
                observed: raw_nodes.len(),
                maximum: MAX_CAUSAL_NODES,
            });
        }
        if raw_edges.len() > MAX_CAUSAL_EDGES {
            return Err(DSeparationError::BoundsExceeded {
                observed: raw_edges.len(),
                maximum: MAX_CAUSAL_EDGES,
            });
        }
        let projection = ImmutableGraphProjection::build(
            universe,
            ProjectionOrientation::Directed,
            anchor,
            history_root,
            authority,
            raw_nodes,
            raw_edges,
            requested_absence,
            cancelled,
        )?;
        Self::from_projection(projection)
    }

    /// Compiles a validated directed [`ImmutableGraphProjection`] into a [`CausalDag`], certifying
    /// strict acyclicity via deterministic Kahn topological sort.
    pub fn from_projection(projection: ImmutableGraphProjection) -> Result<Self, DSeparationError> {
        if projection.orientation() != ProjectionOrientation::Directed {
            return Err(DSeparationError::InvalidInput(
                "CausalDag requires ProjectionOrientation::Directed".to_owned(),
            ));
        }
        let n = projection.node_count();
        let m = projection.edge_count();
        if n > MAX_CAUSAL_NODES {
            return Err(DSeparationError::BoundsExceeded {
                observed: n,
                maximum: MAX_CAUSAL_NODES,
            });
        }
        if m > MAX_CAUSAL_EDGES {
            return Err(DSeparationError::BoundsExceeded {
                observed: m,
                maximum: MAX_CAUSAL_EDGES,
            });
        }

        let mut node_ids: Vec<String> = Vec::with_capacity(n);
        for handle in projection.node_handles() {
            node_ids.push(projection.node(handle)?.node_id.clone());
        }

        let mut children: Vec<Vec<u32>> = vec![Vec::new(); n];
        let mut parents: Vec<Vec<u32>> = vec![Vec::new(); n];
        let mut indegree: Vec<usize> = vec![0; n];

        for edge_handle in projection.edge_handles() {
            let edge = projection.edge(edge_handle)?;
            if edge.source_index == edge.target_index {
                let id = node_ids[edge.source_index as usize].clone();
                return Err(DSeparationError::CycleDetected {
                    cycle_nodes: vec![id],
                });
            }
            let u = edge.source_index as usize;
            let v = edge.target_index as usize;
            if !children[u].contains(&edge.target_index) {
                children[u].push(edge.target_index);
                parents[v].push(edge.source_index);
                indegree[v] += 1;
            }
        }
        for adj in &mut children {
            adj.sort_unstable();
        }
        for par in &mut parents {
            par.sort_unstable();
        }

        // Deterministic Kahn min-order topological sort (using BTreeSet for canonical smallest-index selection).
        let mut ready: BTreeSet<u32> = BTreeSet::new();
        for (idx, &deg) in indegree.iter().enumerate() {
            if deg == 0 {
                ready.insert(idx as u32);
            }
        }
        let mut topological_order = Vec::with_capacity(n);
        while let Some(u) = ready.pop_first() {
            topological_order.push(u);
            for &v in &children[u as usize] {
                indegree[v as usize] -= 1;
                if indegree[v as usize] == 0 {
                    ready.insert(v);
                }
            }
        }

        if topological_order.len() != n {
            let mut cycle_nodes: Vec<String> = indegree
                .iter()
                .enumerate()
                .filter(|(_, deg)| **deg > 0)
                .map(|(idx, _)| node_ids[idx].clone())
                .collect();
            cycle_nodes.sort();
            return Err(DSeparationError::CycleDetected { cycle_nodes });
        }

        let dag_digest = compute_dag_digest(&projection, &topological_order)?;
        Ok(Self {
            projection,
            node_ids,
            children,
            parents,
            topological_order,
            dag_digest,
        })
    }

    /// Compiles an authorized [`SensorCoverageProjection`] plus owner-declared [`FailureDomain`]
    /// sets into a [`CausalDag`] in [`GraphUniverse::GSensor`].
    ///
    /// First cross-checks the coverage projection and failure declarations via the existing
    /// certified [`analyse_failure_domains`] (`ALG-BRIDGE-001`), then builds directed causal forks
    /// `failure/<kind>/<id> -> sensor/<member>` and observation edges `sensor/<member> -> zone/<zone>`
    /// (for witnessed pairs `witnesses > 0`).
    #[allow(clippy::too_many_arguments)]
    pub fn from_failure_domains(
        coverage: &SensorCoverageProjection,
        domains: &[FailureDomain],
        anchor: LedgerAnchor,
        history_root: ContentDigest,
        authority: &ProjectionAuthorityScope,
        requested_absence: AbsenceBoundary,
        cancelled: bool,
    ) -> Result<Self, DSeparationError> {
        if cancelled {
            return Err(DSeparationError::Cancelled);
        }
        // Validate projection consistency & unknown-member refusal through existing ALG-BRIDGE-001 bridge!
        let _bridge_check = analyse_failure_domains(
            coverage,
            domains,
            GraphBudget {
                max_operations: crate::failure_domains::MAX_FAILURE_OPERATIONS,
                max_output_entries: crate::failure_domains::MAX_FAILURE_OUTPUT_ENTRIES,
            },
        )
        .map_err(|e| DSeparationError::InvalidInput(e.to_string()))?;

        let mut node_map: BTreeMap<String, ProjectionNodeSpec> = BTreeMap::new();
        let mut raw_edges: Vec<ProjectionEdgeSpec> = Vec::new();

        for ((sensor, zone), &witness_count) in &coverage.witnesses {
            let sensor_node = format!("{SENSOR_PREFIX}{sensor}");
            node_map
                .entry(sensor_node.clone())
                .or_insert_with(|| ProjectionNodeSpec {
                    node_id: sensor_node.clone(),
                    plane: Plane::Cognition,
                    payload_digest: ContentDigest::sha256(sensor_node.as_bytes()),
                });
            let zone_node = format!("{ZONE_PREFIX}{zone}");
            node_map
                .entry(zone_node.clone())
                .or_insert_with(|| ProjectionNodeSpec {
                    node_id: zone_node.clone(),
                    plane: Plane::Cognition,
                    payload_digest: ContentDigest::sha256(zone_node.as_bytes()),
                });
            if witness_count > 0 {
                raw_edges.push(ProjectionEdgeSpec {
                    source_id: sensor_node,
                    target_id: zone_node,
                    relation: "observes_zone".to_owned(),
                    weight: witness_count,
                });
            }
        }

        for domain in domains {
            let failure_node = domain.node_id();
            node_map
                .entry(failure_node.clone())
                .or_insert_with(|| ProjectionNodeSpec {
                    node_id: failure_node.clone(),
                    plane: Plane::Authority,
                    payload_digest: ContentDigest::sha256(failure_node.as_bytes()),
                });
            for member in domain.members() {
                let sensor_node = format!("{SENSOR_PREFIX}{member}");
                raw_edges.push(ProjectionEdgeSpec {
                    source_id: failure_node.clone(),
                    target_id: sensor_node,
                    relation: format!("shared_{}_domain", domain.kind().as_str()),
                    weight: 1,
                });
            }
        }

        Self::build(
            GraphUniverse::GSensor,
            anchor,
            history_root,
            authority,
            node_map.into_values().collect(),
            raw_edges,
            requested_absence,
            cancelled,
        )
    }

    /// Underlying capability-filtered [`ImmutableGraphProjection`].
    #[must_use]
    pub const fn projection(&self) -> &ImmutableGraphProjection {
        &self.projection
    }

    /// Canonical commitment digest of this causal DAG under [`GRAPH_CAUSAL_DAG_DOMAIN`].
    #[must_use]
    pub const fn dag_digest(&self) -> ContentDigest {
        self.dag_digest
    }

    /// Non-collapsed absence boundary inherited from the underlying projection.
    #[must_use]
    pub const fn absence_boundary(&self) -> &AbsenceBoundary {
        self.projection.absence_boundary()
    }

    /// Deterministic Kahn topological order of canonical dense node indices.
    #[must_use]
    pub fn topological_order(&self) -> &[u32] {
        &self.topological_order
    }

    /// Resolves a visible node ID to its canonical dense index.
    #[must_use]
    pub fn node_index(&self, node_id: &str) -> Option<u32> {
        self.projection
            .handle_for_node_id(node_id)
            .map(|handle| handle.index())
    }

    /// Evaluates `X ⊥ Y | Z` using exact `O(|V| + |E|)` Shachter Bayes-Ball traversal with
    /// deterministic CGSE ordering, shortest simple [`ActivePathWitness`] reconstruction +
    /// verification, explicit budget charging, cooperative cancellation, and sealed receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_d_separation(
        &self,
        query_id: &str,
        x_ids: &[String],
        y_ids: &[String],
        z_ids: &[String],
        budget: DSeparationBudget,
        cancelled: bool,
    ) -> Result<DSeparationReceipt, DSeparationError> {
        if cancelled {
            return Err(DSeparationError::Cancelled);
        }
        validate_label(query_id, MAX_D_SEP_LABEL_BYTES, "query_id")?;
        let (x_sorted, x_idx) = self.resolve_query_set(x_ids, false, "X")?;
        let (y_sorted, y_idx) = self.resolve_query_set(y_ids, false, "Y")?;
        let (z_sorted, z_idx) = self.resolve_query_set(z_ids, true, "Z")?;
        ensure_pairwise_disjoint(&x_idx, &y_idx, &z_idx)?;

        let n = self.projection.node_count();
        let limit = budget.max_operations.min(MAX_D_SEP_OPERATIONS);
        let mut ops = 0_u64;

        let mut in_y = vec![false; n];
        for &y in &y_idx {
            in_y[y as usize] = true;
        }
        let mut in_z = vec![false; n];
        for &z in &z_idx {
            in_z[z as usize] = true;
        }

        // Phase 1: Mark all ancestors of Z (inclusive) via bounded reverse BFS.
        let mut is_ancestor_of_z = vec![false; n];
        let mut anc_queue: VecDeque<u32> = VecDeque::new();
        for &z in &z_idx {
            charge_op(&mut ops, limit)?;
            is_ancestor_of_z[z as usize] = true;
            anc_queue.push_back(z);
        }
        while let Some(v) = anc_queue.pop_front() {
            for &p in &self.parents[v as usize] {
                charge_op(&mut ops, limit)?;
                if !is_ancestor_of_z[p as usize] {
                    is_ancestor_of_z[p as usize] = true;
                    anc_queue.push_back(p);
                }
            }
        }

        // Phase 2: Exact Bayes-Ball BFS over state (node, incoming_dir_bit).
        // dir_bit = 0 => FromChild (arrived walking backward child -> parent)
        // dir_bit = 1 => FromParent (arrived walking forward parent -> child)
        // Mark every x in X as visited in BOTH directions at distance 0 so no shortest walk
        // ever bounces back into X.
        let mut visited = vec![[false; 2]; n];
        let mut parent_state: Vec<[Option<(u32, u8)>; 2]> = vec![[None; 2]; n];
        let mut queue: VecDeque<(u32, u8)> = VecDeque::new();

        for &x in &x_idx {
            visited[x as usize] = [true, true];
        }

        let mut hit_state: Option<(u32, u8)> = None;

        // Seed immediate edges leaving X in canonical sorted order.
        'seed: for &x in &x_idx {
            // Backward along p -> x arrives at p as FromChild (0).
            for &p in &self.parents[x as usize] {
                charge_op(&mut ops, limit)?;
                if !visited[p as usize][0] {
                    visited[p as usize][0] = true;
                    parent_state[p as usize][0] = Some((x, 2)); // 2 = Start sentinel
                    if in_y[p as usize] {
                        hit_state = Some((p, 0));
                        break 'seed;
                    }
                    queue.push_back((p, 0));
                }
            }
            // Forward along x -> c arrives at c as FromParent (1).
            for &c in &self.children[x as usize] {
                charge_op(&mut ops, limit)?;
                if !visited[c as usize][1] {
                    visited[c as usize][1] = true;
                    parent_state[c as usize][1] = Some((x, 2)); // 2 = Start sentinel
                    if in_y[c as usize] {
                        hit_state = Some((c, 1));
                        break 'seed;
                    }
                    queue.push_back((c, 1));
                }
            }
        }

        while hit_state.is_none() {
            let Some((v, dir)) = queue.pop_front() else {
                break;
            };
            let v_usize = v as usize;
            let conditioned = in_z[v_usize];

            if dir == 0 {
                // Arrived FromChild (child -> v backward).
                // Active iff v is NOT in Z: can go UP to parents (ChainBackward) and DOWN to children (Fork).
                if !conditioned {
                    for &p in &self.parents[v_usize] {
                        charge_op(&mut ops, limit)?;
                        if !visited[p as usize][0] {
                            visited[p as usize][0] = true;
                            parent_state[p as usize][0] = Some((v, dir));
                            if in_y[p as usize] {
                                hit_state = Some((p, 0));
                                break;
                            }
                            queue.push_back((p, 0));
                        }
                    }
                    if hit_state.is_some() {
                        break;
                    }
                    for &c in &self.children[v_usize] {
                        charge_op(&mut ops, limit)?;
                        if !visited[c as usize][1] {
                            visited[c as usize][1] = true;
                            parent_state[c as usize][1] = Some((v, dir));
                            if in_y[c as usize] {
                                hit_state = Some((c, 1));
                                break;
                            }
                            queue.push_back((c, 1));
                        }
                    }
                }
            } else {
                // Arrived FromParent (parent -> v forward).
                // If v NOT in Z: can continue DOWN to children (ChainForward).
                if !conditioned {
                    for &c in &self.children[v_usize] {
                        charge_op(&mut ops, limit)?;
                        if !visited[c as usize][1] {
                            visited[c as usize][1] = true;
                            parent_state[c as usize][1] = Some((v, dir));
                            if in_y[c as usize] {
                                hit_state = Some((c, 1));
                                break;
                            }
                            queue.push_back((c, 1));
                        }
                    }
                }
                if hit_state.is_some() {
                    break;
                }
                // If v is in Z OR has a descendant in Z: collider is activated -> can go UP to parents!
                if is_ancestor_of_z[v_usize] {
                    for &p in &self.parents[v_usize] {
                        charge_op(&mut ops, limit)?;
                        if !visited[p as usize][0] {
                            visited[p as usize][0] = true;
                            parent_state[p as usize][0] = Some((v, dir));
                            if in_y[p as usize] {
                                hit_state = Some((p, 0));
                                break;
                            }
                            queue.push_back((p, 0));
                        }
                    }
                }
            }
        }

        let (verdict, active_path) = if let Some((target_node, target_dir)) = hit_state {
            let witness = self.reconstruct_and_verify_active_path(
                target_node,
                target_dir,
                &parent_state,
                &in_z,
                &is_ancestor_of_z,
            )?;
            (DSeparationVerdict::DConnected, Some(witness))
        } else if self.absence_boundary().certifies_absence() {
            (DSeparationVerdict::CertifiedDSeparated, None)
        } else {
            (DSeparationVerdict::DSeparatedOnPartialView, None)
        };

        let mut receipt = DSeparationReceipt {
            format_version: D_SEPARATION_WIRE_VERSION,
            query_id: query_id.to_owned(),
            universe: self.projection.universe(),
            anchor: self.projection.anchor().clone(),
            history_root: self.projection.history_root(),
            projection_digest: self.projection.generation().projection_digest,
            dag_digest: self.dag_digest,
            absence_boundary: self.absence_boundary().clone(),
            source_set_x: x_sorted,
            target_set_y: y_sorted,
            conditioning_set_z: z_sorted,
            verdict,
            active_path,
            operations_used: ops,
            receipt_digest: ContentDigest::sha256(b"unsealed-dsep-receipt"),
        };
        receipt.receipt_digest = receipt.compute_digest()?;
        receipt.verify_self()?;
        Ok(receipt)
    }

    /// Independent reference oracle using Lauritzen's **Moralized Ancestral Graph** criterion:
    ///
    /// 1. Compute `A = Ancestors(X ∪ Y ∪ Z)` (inclusive).
    /// 2. Build the undirected induced subgraph on `A`.
    /// 3. **Moralize:** add an undirected edge between every pair of distinct co-parents of every `v ∈ A`.
    /// 4. Remove all vertices in `Z`.
    /// 5. Return `true` iff no vertex in `Y` is reachable from `X` in the resulting undirected graph.
    ///
    /// Shares ZERO traversal logic with Bayes-Ball and certifies `evaluate_d_separation` differentially.
    pub fn oracle_d_separation_moralized_ancestral(
        &self,
        x_ids: &[String],
        y_ids: &[String],
        z_ids: &[String],
    ) -> Result<bool, DSeparationError> {
        let (_, x_idx) = self.resolve_query_set(x_ids, false, "X")?;
        let (_, y_idx) = self.resolve_query_set(y_ids, false, "Y")?;
        let (_, z_idx) = self.resolve_query_set(z_ids, true, "Z")?;
        ensure_pairwise_disjoint(&x_idx, &y_idx, &z_idx)?;

        let n = self.projection.node_count();
        let mut in_ancestral = vec![false; n];
        let mut queue = VecDeque::new();
        for &seed in x_idx.iter().chain(y_idx.iter()).chain(z_idx.iter()) {
            if !in_ancestral[seed as usize] {
                in_ancestral[seed as usize] = true;
                queue.push_back(seed);
            }
        }
        while let Some(v) = queue.pop_front() {
            for &p in &self.parents[v as usize] {
                if !in_ancestral[p as usize] {
                    in_ancestral[p as usize] = true;
                    queue.push_back(p);
                }
            }
        }

        let mut in_z = vec![false; n];
        for &z in &z_idx {
            in_z[z as usize] = true;
        }

        // Build undirected moralized graph over A \ Z.
        let mut moral_adj: Vec<BTreeSet<u32>> = vec![BTreeSet::new(); n];
        for v in 0..n {
            if !in_ancestral[v] {
                continue;
            }
            let active_parents: Vec<u32> = self.parents[v]
                .iter()
                .copied()
                .filter(|&p| in_ancestral[p as usize])
                .collect();
            if !in_z[v] {
                for &p in &active_parents {
                    if !in_z[p as usize] {
                        moral_adj[v].insert(p);
                        moral_adj[p as usize].insert(v as u32);
                    }
                }
            }
            // Marry all pairs of parents of v (even when v IS in Z! That is how colliders open!).
            for i in 0..active_parents.len() {
                let p1 = active_parents[i];
                if in_z[p1 as usize] {
                    continue;
                }
                for &p2 in &active_parents[i + 1..] {
                    if !in_z[p2 as usize] {
                        moral_adj[p1 as usize].insert(p2);
                        moral_adj[p2 as usize].insert(p1);
                    }
                }
            }
        }

        let mut in_y = vec![false; n];
        for &y in &y_idx {
            in_y[y as usize] = true;
        }
        let mut seen = vec![false; n];
        let mut bfs = VecDeque::new();
        for &x in &x_idx {
            seen[x as usize] = true;
            bfs.push_back(x);
        }
        while let Some(u) = bfs.pop_front() {
            if in_y[u as usize] {
                return Ok(false); // d-connected!
            }
            for &nxt in &moral_adj[u as usize] {
                if !seen[nxt as usize] {
                    seen[nxt as usize] = true;
                    bfs.push_back(nxt);
                }
            }
        }
        Ok(true) // d-separated!
    }

    /// Evaluates pairwise causal independence across candidate `sensor_node_ids` (e.g.
    /// `"sensor/cam-a"`, `"sensor/cam-b"`) given `conditioned_ids`, flagging every shared
    /// failure-domain fork or active path that invalidates independent corroboration.
    pub fn assess_corroboration_independence(
        &self,
        query_prefix: &str,
        sensor_node_ids: &[String],
        conditioned_ids: &[String],
        budget: DSeparationBudget,
        cancelled: bool,
    ) -> Result<CorroborationIndependenceReport, DSeparationError> {
        if cancelled {
            return Err(DSeparationError::Cancelled);
        }
        validate_label(query_prefix, MAX_D_SEP_LABEL_BYTES, "query_prefix")?;
        let (sensors, _) = self.resolve_query_set(sensor_node_ids, false, "sensors")?;
        if sensors.len() < 2 {
            return Err(DSeparationError::InvalidInput(
                "corroboration independence assessment requires at least 2 distinct sensors"
                    .to_owned(),
            ));
        }

        let limit = budget.max_operations.min(MAX_D_SEP_OPERATIONS);
        let mut total_operations = 0_u64;
        let mut pair_findings = Vec::new();
        let mut any_confounded = false;
        let mut any_partial = false;

        for i in 0..sensors.len() {
            for j in (i + 1)..sensors.len() {
                let remaining = limit.saturating_sub(total_operations);
                let qid = format!("{query_prefix}:{i}:{j}");
                let receipt = self.evaluate_d_separation(
                    &qid,
                    &[sensors[i].clone()],
                    &[sensors[j].clone()],
                    conditioned_ids,
                    DSeparationBudget::new(remaining),
                    cancelled,
                )?;
                total_operations = total_operations
                    .checked_add(receipt.operations_used)
                    .ok_or(DSeparationError::BudgetExhausted {
                        used: u64::MAX,
                        limit,
                    })?;
                if total_operations > limit {
                    return Err(DSeparationError::BudgetExhausted {
                        used: total_operations,
                        limit,
                    });
                }
                let shared_fork_causes = receipt
                    .active_path
                    .as_ref()
                    .map(|p| p.fork_causes().into_iter().map(ToOwned::to_owned).collect())
                    .unwrap_or_default();
                match receipt.verdict {
                    DSeparationVerdict::DConnected => any_confounded = true,
                    DSeparationVerdict::DSeparatedOnPartialView => any_partial = true,
                    DSeparationVerdict::CertifiedDSeparated => {}
                }
                pair_findings.push(PairwiseCorroborationFinding {
                    sensor_a: sensors[i].clone(),
                    sensor_b: sensors[j].clone(),
                    receipt,
                    shared_fork_causes,
                });
            }
        }

        let status = if any_confounded {
            CorroborationIndependenceStatus::ConfoundedBySharedDomains
        } else if any_partial {
            CorroborationIndependenceStatus::UncertifiedPartialView
        } else {
            CorroborationIndependenceStatus::IndependentOnCertifiedProjection
        };

        Ok(CorroborationIndependenceReport {
            status,
            pair_findings,
            total_operations,
        })
    }

    fn resolve_query_set(
        &self,
        ids: &[String],
        allow_empty: bool,
        label: &str,
    ) -> Result<(Vec<String>, Vec<u32>), DSeparationError> {
        if !allow_empty && ids.is_empty() {
            return Err(DSeparationError::InvalidInput(format!(
                "query set {label} must not be empty"
            )));
        }
        if ids.len() > MAX_QUERY_SET_LEN {
            return Err(DSeparationError::BoundsExceeded {
                observed: ids.len(),
                maximum: MAX_QUERY_SET_LEN,
            });
        }
        let mut sorted: Vec<String> = ids.to_vec();
        sorted.sort();
        for pair in sorted.windows(2) {
            if pair[0] == pair[1] {
                return Err(DSeparationError::InvalidInput(format!(
                    "duplicate node '{}' in query set {label}",
                    pair[0]
                )));
            }
        }
        let mut indices = Vec::with_capacity(sorted.len());
        for id in &sorted {
            validate_label(id, MAX_D_SEP_LABEL_BYTES, label)?;
            let idx = self.node_index(id).ok_or_else(|| {
                DSeparationError::InvalidInput(format!(
                    "unknown or redacted node '{id}' in query set {label}"
                ))
            })?;
            indices.push(idx);
        }
        Ok((sorted, indices))
    }

    fn reconstruct_and_verify_active_path(
        &self,
        target_node: u32,
        target_dir: u8,
        parent_state: &[[Option<(u32, u8)>; 2]],
        in_z: &[bool],
        is_ancestor_of_z: &[bool],
    ) -> Result<ActivePathWitness, DSeparationError> {
        let mut rev: Vec<(u32, PathStepDirection)> = Vec::new();
        let mut cur_node = target_node;
        let mut cur_dir = target_dir;
        let max_hops = self.projection.node_count().saturating_mul(2) + 2;

        let mut reached_start = false;
        for _ in 0..max_hops {
            let step_dir = if cur_dir == 0 {
                PathStepDirection::Backward
            } else {
                PathStepDirection::Forward
            };
            rev.push((cur_node, step_dir));
            let Some((prev_node, prev_dir)) = parent_state[cur_node as usize][cur_dir as usize]
            else {
                return Err(DSeparationError::InconsistentWitness(
                    "broken parent pointer during active path reconstruction".to_owned(),
                ));
            };
            if prev_dir == 2 {
                rev.push((prev_node, PathStepDirection::Start));
                reached_start = true;
                break;
            }
            cur_node = prev_node;
            cur_dir = prev_dir;
        }
        if !reached_start {
            return Err(DSeparationError::InconsistentWitness(
                "active path reconstruction exceeded max_hops without reaching start".to_owned(),
            ));
        }
        rev.reverse();

        // Verify vertex-simplicity, real DAG edges, and Pearl active-triple rules!
        let mut seen_nodes = BTreeSet::new();
        let mut steps = Vec::with_capacity(rev.len());
        for (idx, &(node_idx, dir)) in rev.iter().enumerate() {
            if !seen_nodes.insert(node_idx) {
                return Err(DSeparationError::InconsistentWitness(
                    "reconstructed active path repeated a vertex".to_owned(),
                ));
            }
            if idx > 0 {
                let prev_idx = rev[idx - 1].0;
                let valid_edge = match dir {
                    PathStepDirection::Forward => self.children[prev_idx as usize]
                        .binary_search(&node_idx)
                        .is_ok(),
                    PathStepDirection::Backward => self.parents[prev_idx as usize]
                        .binary_search(&node_idx)
                        .is_ok(),
                    PathStepDirection::Start => false,
                };
                if !valid_edge {
                    return Err(DSeparationError::InconsistentWitness(
                        "reconstructed active path edge does not exist in DAG".to_owned(),
                    ));
                }
            }
            steps.push(ActivePathStep {
                node_id: self.node_ids[node_idx as usize].clone(),
                direction_from_prev: dir,
            });
        }

        let mut triples = Vec::with_capacity(rev.len().saturating_sub(2));
        for i in 1..rev.len().saturating_sub(1) {
            let mid_idx = rev[i].0 as usize;
            let in_dir = rev[i].1;
            let out_dir = rev[i + 1].1;
            let kind = match (in_dir, out_dir) {
                (PathStepDirection::Forward, PathStepDirection::Forward) => {
                    if in_z[mid_idx] {
                        return Err(DSeparationError::InconsistentWitness(
                            "ChainForward blocked by Z".to_owned(),
                        ));
                    }
                    ActiveTripleKind::ChainForward
                }
                (PathStepDirection::Backward, PathStepDirection::Backward) => {
                    if in_z[mid_idx] {
                        return Err(DSeparationError::InconsistentWitness(
                            "ChainBackward blocked by Z".to_owned(),
                        ));
                    }
                    ActiveTripleKind::ChainBackward
                }
                (PathStepDirection::Backward, PathStepDirection::Forward) => {
                    if in_z[mid_idx] {
                        return Err(DSeparationError::InconsistentWitness(
                            "Fork blocked by Z".to_owned(),
                        ));
                    }
                    ActiveTripleKind::Fork
                }
                (PathStepDirection::Forward, PathStepDirection::Backward) => {
                    if !is_ancestor_of_z[mid_idx] {
                        return Err(DSeparationError::InconsistentWitness(
                            "Collider not activated by Z or descendant".to_owned(),
                        ));
                    }
                    ActiveTripleKind::ColliderActivated
                }
                _ => {
                    return Err(DSeparationError::InconsistentWitness(
                        "invalid direction pair in active triple".to_owned(),
                    ));
                }
            };
            triples.push(ActiveTriple {
                middle_node_id: steps[i].node_id.clone(),
                kind,
            });
        }

        Ok(ActivePathWitness { steps, triples })
    }
}

fn compute_dag_digest(
    projection: &ImmutableGraphProjection,
    topological_order: &[u32],
) -> Result<ContentDigest, DSeparationError> {
    let mut enc = CanonicalEncoder::new();
    enc.text(GRAPH_CAUSAL_DAG_DOMAIN);
    enc.digest(projection.generation().projection_digest);
    enc.u32(topological_order.len() as u32);
    for &idx in topological_order {
        enc.u32(idx);
    }
    let bytes = enc
        .finish_checked()
        .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?;
    Ok(ContentDigest::sha256(&bytes))
}

fn ensure_pairwise_disjoint(x: &[u32], y: &[u32], z: &[u32]) -> Result<(), DSeparationError> {
    let x_set: BTreeSet<u32> = x.iter().copied().collect();
    for &v in y {
        if x_set.contains(&v) {
            return Err(DSeparationError::InvalidInput(
                "query sets X and Y must be disjoint".to_owned(),
            ));
        }
    }
    let y_set: BTreeSet<u32> = y.iter().copied().collect();
    for &v in z {
        if x_set.contains(&v) || y_set.contains(&v) {
            return Err(DSeparationError::InvalidInput(
                "conditioning set Z must be disjoint from X and Y".to_owned(),
            ));
        }
    }
    Ok(())
}

fn charge_op(used: &mut u64, limit: u64) -> Result<(), DSeparationError> {
    let next = used
        .checked_add(1)
        .ok_or(DSeparationError::BudgetExhausted {
            used: u64::MAX,
            limit,
        })?;
    if next > limit {
        return Err(DSeparationError::BudgetExhausted { used: next, limit });
    }
    *used = next;
    Ok(())
}

fn encode_string_vec(enc: &mut CanonicalEncoder, values: &[String]) {
    enc.u32(values.len() as u32);
    for v in values {
        enc.text(v);
    }
}

fn decode_string_vec(dec: &mut CanonicalDecoder<'_>) -> Result<Vec<String>, DSeparationError> {
    let len = dec
        .u32()
        .map_err(|e| DSeparationError::MalformedWire(e.to_string()))? as usize;
    if len > MAX_QUERY_SET_LEN {
        return Err(DSeparationError::BoundsExceeded {
            observed: len,
            maximum: MAX_QUERY_SET_LEN,
        });
    }
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        let s = dec
            .text()
            .map_err(|e| DSeparationError::MalformedWire(e.to_string()))?
            .to_owned();
        validate_label(&s, MAX_D_SEP_LABEL_BYTES, "query_set_member")?;
        out.push(s);
    }
    Ok(out)
}

fn validate_canonical_set(
    values: &[String],
    allow_empty: bool,
    label: &str,
) -> Result<(), DSeparationError> {
    if !allow_empty && values.is_empty() {
        return Err(DSeparationError::MalformedWire(format!(
            "{label} must not be empty"
        )));
    }
    if values.len() > MAX_QUERY_SET_LEN {
        return Err(DSeparationError::BoundsExceeded {
            observed: values.len(),
            maximum: MAX_QUERY_SET_LEN,
        });
    }
    for v in values {
        validate_label(v, MAX_D_SEP_LABEL_BYTES, label)?;
    }
    for pair in values.windows(2) {
        if pair[0] >= pair[1] {
            return Err(DSeparationError::MalformedWire(format!(
                "{label} is not strictly sorted ascending"
            )));
        }
    }
    Ok(())
}

fn validate_label(value: &str, max_len: usize, label: &str) -> Result<(), DSeparationError> {
    if value.is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
        return Err(DSeparationError::InvalidInput(format!(
            "{label} invalid length or contains control characters"
        )));
    }
    Ok(())
}

fn decode_universe(tag: u8) -> Result<GraphUniverse, DSeparationError> {
    match tag {
        1 => Ok(GraphUniverse::GPhys),
        2 => Ok(GraphUniverse::HVis),
        3 => Ok(GraphUniverse::GSensor),
        4 => Ok(GraphUniverse::GTime),
        5 => Ok(GraphUniverse::GAssoc),
        6 => Ok(GraphUniverse::GEvidence),
        7 => Ok(GraphUniverse::GEffect),
        8 => Ok(GraphUniverse::GObject),
        9 => Ok(GraphUniverse::GAuth),
        10 => Ok(GraphUniverse::GMemory),
        11 => Ok(GraphUniverse::GAgent),
        12 => Ok(GraphUniverse::GWorld),
        other => Err(DSeparationError::MalformedWire(format!(
            "unknown GraphUniverse tag {other}"
        ))),
    }
}
