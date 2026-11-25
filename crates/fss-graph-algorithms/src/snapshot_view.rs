#![forbid(unsafe_code)]
//! O(1) `Arc`-shared graph snapshot views and deterministic invalidation (`FSS-152`, `fss-x4a.23.2`).
//!
//! Directly composes [`ImmutableGraphProjection`] (`FSS-151`) to give concurrent readers zero-copy
//! O(1) snapshot handles (`Arc`-cloned, never cloning node/edge/CSR buffers) with strict snapshot
//! isolation and explicit fail-closed invalidation across all 12 registered FSS graph universes:
//!
//! - **O(1) shared views (`GraphSnapshotView`):** cloning or acquiring a snapshot view performs a
//!   single `Arc::clone` (`shares_backing_projection` proves `Arc::ptr_eq` identity), allowing
//!   in-flight readers to execute certified algorithms (such as `ALG-BRIDGE-001`) against their
//!   exact immutable anchor even while newer projections publish concurrently.
//! - **Non-collapsing per-universe catalog (`GraphSnapshotCatalog`):** maintains independent
//!   monotonic snapshot generations per [`GraphUniverse`] with bounded history retention and
//!   explicit capability/privacy/authority-generation validation before acquisition or publication.
//! - **Exact typed invalidation (`SnapshotInvalidationReason`):** stale views never silently read
//!   newer state or pass freshness checks; invalidation classifies exact cause (`AnchorAdvanced`,
//!   `AuthorityGenerationChanged`, `PrivacyEpochChanged`, `LineageOrHistoryDiverged`,
//!   `ProjectionReplaced`, or `ExplicitRevocation`).
//! - **Bounded checksummed publication receipts (`FSSGSV01` v1):** sealed under
//!   `fss.graph.snapshot_publication_receipt.v1`.

use std::collections::{BTreeMap, VecDeque};
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, LedgerAnchor};

use crate::bridges::{BridgeAnalysis, GraphBudget, analyse_bridges};
use crate::graph::GraphError;
use crate::projection::{
    AbsenceBoundary, EdgeHandle, GraphUniverse, ImmutableGraphProjection, NodeHandle,
    ProjectionAuthorityScope, ProjectionEdge, ProjectionError, ProjectionGeneration,
    ProjectionNode,
};

/// Registered digest domain for [`SnapshotPublicationReceipt`] commitments (`FSS-152`).
pub const GRAPH_SNAPSHOT_PUBLICATION_DOMAIN: &str = "fss.graph.snapshot_publication_receipt.v1";
/// Binary wire header magic for serialized snapshot publication receipts.
pub const SNAPSHOT_RECEIPT_MAGIC: [u8; 8] = *b"FSSGSV01";
/// Supported durable format version for [`SnapshotPublicationReceipt`].
pub const SNAPSHOT_RECEIPT_VERSION: u32 = 1;
/// Maximum historical publication receipts retained per universe in [`GraphSnapshotCatalog`].
pub const MAX_RETAINED_SNAPSHOT_HISTORY: usize = 64;
/// Hard ceiling on diagnostic label/reason bytes.
pub const MAX_SNAPSHOT_LABEL_BYTES: usize = 256;
/// Hard ceiling on serialized receipt wire bytes (64 KiB).
pub const MAX_SNAPSHOT_RECEIPT_WIRE_BYTES: usize = 64 * 1024;

/// Exact typed reason a previously acquired [`GraphSnapshotView`] is no longer current.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotInvalidationReason {
    /// Ledger commit sequence advanced past the snapshot's pinned anchor.
    AnchorAdvanced {
        /// Snapshot's pinned commit sequence.
        old_sequence: u64,
        /// Active catalog's current commit sequence.
        new_sequence: u64,
    },
    /// Active authority generation superseded the snapshot's generation.
    AuthorityGenerationChanged {
        /// Snapshot's authority generation.
        old_generation: u64,
        /// Active authority generation.
        new_generation: u64,
    },
    /// Active privacy policy epoch changed (re-projection required to enforce updated redactions).
    PrivacyEpochChanged {
        /// Snapshot's privacy epoch.
        old_epoch: u64,
        /// Active privacy epoch.
        new_epoch: u64,
    },
    /// Site lineage or canonical history chain diverged from the snapshot's basis.
    LineageOrHistoryDiverged,
    /// Projection at the same anchor was replaced by a newer projection digest.
    ProjectionReplaced,
    /// Universe snapshot was explicitly revoked (e.g. privacy/retention revocation or purge).
    ExplicitRevocation {
        /// Machine-readable revocation reason.
        reason: String,
    },
}

/// Non-collapsed freshness verdict for a [`GraphSnapshotView`] against [`GraphSnapshotCatalog`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotFreshness {
    /// View matches the exact active published snapshot for its universe.
    Current,
    /// View is stale or invalidated; caller must re-acquire a fresh snapshot view before acting.
    Invalidated {
        /// Exact typed invalidation cause.
        reason: SnapshotInvalidationReason,
        /// Current monotonic view generation of the catalog for this universe (0 if revoked).
        current_view_generation: u64,
        /// Current active projection digest if a replacement is published (`None` if revoked).
        current_projection_digest: Option<ContentDigest>,
    },
}

/// Safe operator/agent recovery guidance for a refused snapshot operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotGuidance {
    /// Re-authorize revoked capability, privacy epoch, authority generation, or universe scope.
    ReauthorizeSnapshot,
    /// Re-acquire a current O(1) snapshot view from the catalog and refresh generational handles.
    ReacquireCurrentSnapshot,
    /// Publish an authorized immutable projection for this universe before querying.
    PublishInitialProjection,
    /// Repair regressed anchor sequence or invalid revocation/input labels.
    RepairSnapshotInput,
    /// Cooperative cancellation observed; retry when ready.
    RetryWhenReady,
    /// Reject corrupt or unsupported binary receipt bytes.
    RejectCorruptReceipt,
}

/// Typed error returned by [`GraphSnapshotView`], [`GraphSnapshotCatalog`], or receipt codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotViewError {
    /// Underlying projection error (e.g. stale handle or revoked authority).
    Projection(ProjectionError),
    /// Underlying certified graph algorithm error.
    Algorithm(GraphError),
    /// Active authority/privacy/generation disagreed with projection or catalog state.
    AuthorityMismatch(String),
    /// No active snapshot is currently published for `universe` (never published or revoked).
    UniverseUnavailable {
        /// Requested universe.
        universe: GraphUniverse,
        /// Optional explicit revocation reason if revoked.
        revocation_reason: Option<String>,
    },
    /// Publication attempted to regress `commit_sequence` within the same site lineage.
    AnchorRegression {
        /// Previously published sequence.
        previous_sequence: u64,
        /// Attempted regressed sequence.
        attempted_sequence: u64,
    },
    /// Operation required a current snapshot, but the supplied view was invalidated.
    ViewInvalidated {
        /// Exact invalidation cause.
        reason: SnapshotInvalidationReason,
    },
    /// Cooperative cancellation observed before completing publish/acquire.
    Cancelled,
    /// Invalid label or bound exceeded.
    InvalidInput(String),
    /// Wire length exceeded hard protocol ceiling.
    BoundsExceeded {
        /// Observed bytes.
        observed: usize,
        /// Hard ceiling.
        maximum: usize,
    },
    /// Binary receipt lacked [`SNAPSHOT_RECEIPT_MAGIC`].
    InvalidMagic,
    /// Binary receipt declared an unsupported version.
    UnsupportedVersion {
        /// Observed version.
        version: u32,
    },
    /// Binary receipt was truncated, non-canonical, or malformed.
    MalformedWire(String),
    /// Receipt canonical checksum failed verification.
    ChecksumMismatch,
    /// Canonical encoder failure.
    Encoding(String),
}

impl SnapshotViewError {
    /// Stable canonical machine error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Projection(_) => "ERR-GRAPH-SNAPSHOT-PROJECTION-001",
            Self::Algorithm(_) => "ERR-GRAPH-SNAPSHOT-ALGORITHM-001",
            Self::AuthorityMismatch(_) => "ERR-GRAPH-SNAPSHOT-AUTHORITY-001",
            Self::UniverseUnavailable { .. } => "ERR-GRAPH-SNAPSHOT-UNAVAILABLE-001",
            Self::AnchorRegression { .. } => "ERR-GRAPH-SNAPSHOT-ANCHOR-REGRESSION-001",
            Self::ViewInvalidated { .. } => "ERR-GRAPH-SNAPSHOT-INVALIDATED-001",
            Self::Cancelled => "ERR-GRAPH-SNAPSHOT-CANCELLED-001",
            Self::InvalidInput(_) => "ERR-GRAPH-SNAPSHOT-INVALID-INPUT-001",
            Self::BoundsExceeded { .. } => "ERR-GRAPH-SNAPSHOT-BOUNDS-001",
            Self::InvalidMagic => "ERR-GRAPH-SNAPSHOT-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-GRAPH-SNAPSHOT-UNSUPPORTED-VERSION-001",
            Self::MalformedWire(_) => "ERR-GRAPH-SNAPSHOT-MALFORMED-WIRE-001",
            Self::ChecksumMismatch => "ERR-GRAPH-SNAPSHOT-CHECKSUM-MISMATCH-001",
            Self::Encoding(_) => "ERR-GRAPH-SNAPSHOT-ENCODING-001",
        }
    }

    /// Safe operator/agent recovery guidance.
    #[must_use]
    pub const fn guidance(&self) -> SnapshotGuidance {
        match self {
            Self::Projection(ProjectionError::StaleHandleGeneration { .. })
            | Self::ViewInvalidated { .. } => SnapshotGuidance::ReacquireCurrentSnapshot,
            Self::Projection(ProjectionError::AuthorityRevoked(_))
            | Self::Projection(ProjectionError::StaleAuthorityGeneration { .. })
            | Self::AuthorityMismatch(_) => SnapshotGuidance::ReauthorizeSnapshot,
            Self::UniverseUnavailable { .. } => SnapshotGuidance::PublishInitialProjection,
            Self::AnchorRegression { .. }
            | Self::InvalidInput(_)
            | Self::BoundsExceeded { .. }
            | Self::Projection(_)
            | Self::Algorithm(_) => SnapshotGuidance::RepairSnapshotInput,
            Self::Cancelled => SnapshotGuidance::RetryWhenReady,
            Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::MalformedWire(_)
            | Self::ChecksumMismatch
            | Self::Encoding(_) => SnapshotGuidance::RejectCorruptReceipt,
        }
    }
}

impl fmt::Display for SnapshotViewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for SnapshotViewError {}

impl From<ProjectionError> for SnapshotViewError {
    fn from(value: ProjectionError) -> Self {
        Self::Projection(value)
    }
}

impl From<GraphError> for SnapshotViewError {
    fn from(value: GraphError) -> Self {
        Self::Algorithm(value)
    }
}

/// O(1) `Arc`-shared read-only snapshot view pinned to one immutable [`ImmutableGraphProjection`].
///
/// Cloning a `GraphSnapshotView` performs a single atomic reference-count increment (zero node,
/// edge, or CSR copying) and preserves full snapshot isolation across concurrent catalog updates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphSnapshotView {
    view_generation: u64,
    projection: Arc<ImmutableGraphProjection>,
}

impl GraphSnapshotView {
    /// Monotonic catalog view generation assigned on publication (`>= 1`).
    #[must_use]
    pub const fn view_generation(&self) -> u64 {
        self.view_generation
    }

    /// Exact typed graph universe of this snapshot.
    #[must_use]
    pub fn universe(&self) -> GraphUniverse {
        self.projection.universe()
    }

    /// Exact pinned ledger anchor.
    #[must_use]
    pub fn anchor(&self) -> &LedgerAnchor {
        self.projection.anchor()
    }

    /// Exact pinned canonical history-chain root.
    #[must_use]
    pub fn history_root(&self) -> ContentDigest {
        self.projection.history_root()
    }

    /// Exact cryptographic generation stamp bound to all handles issued by this view.
    #[must_use]
    pub fn generation(&self) -> ProjectionGeneration {
        self.projection.generation()
    }

    /// Non-collapsed absence boundary preserved by this view.
    #[must_use]
    pub fn absence_boundary(&self) -> &AbsenceBoundary {
        self.projection.absence_boundary()
    }

    /// Borrow the underlying immutable projection directly without copying.
    #[must_use]
    pub fn projection(&self) -> &ImmutableGraphProjection {
        &self.projection
    }

    /// Proves O(1) zero-copy backing-projection sharing (`Arc::ptr_eq`).
    #[must_use]
    pub fn shares_backing_projection(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.projection, &other.projection)
    }

    /// Current live strong reference count of the shared `Arc<ImmutableGraphProjection>`.
    #[must_use]
    pub fn strong_ref_count(&self) -> usize {
        Arc::strong_count(&self.projection)
    }

    /// Looks up a generational [`NodeHandle`] by stable external `node_id`.
    #[must_use]
    pub fn handle_for_node_id(&self, node_id: &str) -> Option<NodeHandle> {
        self.projection.handle_for_node_id(node_id)
    }

    /// Dereferences `handle`, failing closed on stale or cross-snapshot generation handles.
    pub fn node(&self, handle: NodeHandle) -> Result<&ProjectionNode, SnapshotViewError> {
        Ok(self.projection.node(handle)?)
    }

    /// Dereferences `handle`, failing closed on stale or cross-snapshot generation handles.
    pub fn edge(&self, handle: EdgeHandle) -> Result<&ProjectionEdge, SnapshotViewError> {
        Ok(self.projection.edge(handle)?)
    }

    /// Expands canonical neighbors for `handle`, failing closed on stale generation handles.
    pub fn neighbors(
        &self,
        handle: NodeHandle,
    ) -> Result<Vec<(NodeHandle, EdgeHandle)>, SnapshotViewError> {
        Ok(self.projection.neighbors(handle)?)
    }

    /// Runs certified `ALG-BRIDGE-001` (`analyse_bridges`) over this immutable snapshot view.
    pub fn analyse_bridges(
        &self,
        root: Option<&str>,
        budget: GraphBudget,
    ) -> Result<BridgeAnalysis, SnapshotViewError> {
        let simple = self.projection.to_undirected_simple_graph()?;
        Ok(analyse_bridges(&simple, root, budget)?)
    }
}

/// Sealed receipt recording one atomic snapshot publication into [`GraphSnapshotCatalog`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotPublicationReceipt {
    /// Wire format version (`SNAPSHOT_RECEIPT_VERSION`).
    pub format_version: u32,
    /// Graph universe updated by this publication.
    pub universe: GraphUniverse,
    /// Monotonic view generation assigned to the newly published snapshot (`>= 1`).
    pub view_generation: u64,
    /// Previous view generation replaced (`0` on initial publication).
    pub previous_view_generation: u64,
    /// Exact ledger commit sequence pinned by the published snapshot.
    pub anchor_sequence: u64,
    /// Authority generation pinned by the published snapshot.
    pub authority_generation: u64,
    /// Privacy policy epoch pinned by the published snapshot.
    pub privacy_epoch: u64,
    /// Digest of the newly published [`ImmutableGraphProjection`].
    pub projection_digest: ContentDigest,
    /// Digest of the superseded projection, if any.
    pub superseded_projection_digest: Option<ContentDigest>,
    /// True iff this snapshot's absence boundary certifies absence.
    pub certifies_absence: bool,
    /// Domain-separated SHA-256 commitment (`fss.graph.snapshot_publication_receipt.v1`).
    pub receipt_digest: ContentDigest,
}

impl SnapshotPublicationReceipt {
    /// Recomputes the domain-separated SHA-256 commitment.
    pub fn compute_digest(&self) -> Result<ContentDigest, SnapshotViewError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(GRAPH_SNAPSHOT_PUBLICATION_DOMAIN);
        self.encode_body(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| SnapshotViewError::Encoding(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn verify_self(&self) -> Result<(), SnapshotViewError> {
        if self.format_version != SNAPSHOT_RECEIPT_VERSION {
            return Err(SnapshotViewError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        if self.view_generation == 0 || self.previous_view_generation >= self.view_generation {
            return Err(SnapshotViewError::MalformedWire(
                "view_generation must be >= 1 and strictly greater than previous_view_generation"
                    .to_owned(),
            ));
        }
        if (self.previous_view_generation > 0) != self.superseded_projection_digest.is_some() {
            return Err(SnapshotViewError::MalformedWire(
                "superseded_projection_digest must be present iff previous_view_generation > 0"
                    .to_owned(),
            ));
        }
        if self.compute_digest()? != self.receipt_digest {
            return Err(SnapshotViewError::ChecksumMismatch);
        }
        Ok(())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.text(self.universe.as_str());
        enc.u64(self.view_generation);
        enc.u64(self.previous_view_generation);
        enc.u64(self.anchor_sequence);
        enc.u64(self.authority_generation);
        enc.u64(self.privacy_epoch);
        enc.digest(self.projection_digest);
        match self.superseded_projection_digest {
            Some(d) => {
                enc.u8(1);
                enc.digest(d);
            }
            None => enc.u8(0),
        }
        enc.bool(self.certifies_absence);
    }

    /// Encodes this publication receipt into bounded checksummed binary bytes (`FSSGSV01` v1).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, SnapshotViewError> {
        self.verify_self()?;
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        enc.digest(self.receipt_digest);
        let body = enc
            .finish_checked()
            .map_err(|e| SnapshotViewError::Encoding(e.to_string()))?;
        let total = SNAPSHOT_RECEIPT_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_SNAPSHOT_RECEIPT_WIRE_BYTES {
            return Err(SnapshotViewError::BoundsExceeded {
                observed: total,
                maximum: MAX_SNAPSHOT_RECEIPT_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&SNAPSHOT_RECEIPT_MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and verifies a binary [`SnapshotPublicationReceipt`] (`FSSGSV01` v1).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SnapshotViewError> {
        if bytes.len() > MAX_SNAPSHOT_RECEIPT_WIRE_BYTES {
            return Err(SnapshotViewError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_SNAPSHOT_RECEIPT_WIRE_BYTES,
            });
        }
        if bytes.len() < 12 || bytes[..8] != SNAPSHOT_RECEIPT_MAGIC {
            return Err(SnapshotViewError::InvalidMagic);
        }
        let header_ver = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if header_ver != SNAPSHOT_RECEIPT_VERSION {
            return Err(SnapshotViewError::UnsupportedVersion {
                version: header_ver,
            });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let format_version = dec
            .u32()
            .map_err(|e| SnapshotViewError::MalformedWire(e.to_string()))?;
        if format_version != header_ver {
            return Err(SnapshotViewError::UnsupportedVersion {
                version: format_version,
            });
        }
        let universe = parse_universe(
            dec.text()
                .map_err(|e| SnapshotViewError::MalformedWire(e.to_string()))?,
        )?;
        let view_generation = dec
            .u64()
            .map_err(|e| SnapshotViewError::MalformedWire(e.to_string()))?;
        let previous_view_generation = dec
            .u64()
            .map_err(|e| SnapshotViewError::MalformedWire(e.to_string()))?;
        let anchor_sequence = dec
            .u64()
            .map_err(|e| SnapshotViewError::MalformedWire(e.to_string()))?;
        let authority_generation = dec
            .u64()
            .map_err(|e| SnapshotViewError::MalformedWire(e.to_string()))?;
        let privacy_epoch = dec
            .u64()
            .map_err(|e| SnapshotViewError::MalformedWire(e.to_string()))?;
        let projection_digest = dec
            .digest()
            .map_err(|e| SnapshotViewError::MalformedWire(e.to_string()))?;
        let superseded_projection_digest = match dec
            .u8()
            .map_err(|e| SnapshotViewError::MalformedWire(e.to_string()))?
        {
            0 => None,
            1 => Some(
                dec.digest()
                    .map_err(|e| SnapshotViewError::MalformedWire(e.to_string()))?,
            ),
            other => {
                return Err(SnapshotViewError::MalformedWire(format!(
                    "invalid superseded tag {other}"
                )));
            }
        };
        let certifies_absence = dec
            .bool()
            .map_err(|e| SnapshotViewError::MalformedWire(e.to_string()))?;
        let stored_digest = dec
            .digest()
            .map_err(|e| SnapshotViewError::MalformedWire(e.to_string()))?;
        dec.ensure_finished().map_err(|_| {
            SnapshotViewError::MalformedWire("trailing bytes after snapshot receipt".to_owned())
        })?;

        let receipt = Self {
            format_version,
            universe,
            view_generation,
            previous_view_generation,
            anchor_sequence,
            authority_generation,
            privacy_epoch,
            projection_digest,
            superseded_projection_digest,
            certifies_absence,
            receipt_digest: stored_digest,
        };
        receipt.verify_self()?;
        Ok(receipt)
    }
}

#[derive(Clone, Debug)]
struct UniverseSlot {
    next_generation: u64,
    active: Option<GraphSnapshotView>,
    revocation_reason: Option<String>,
    history: VecDeque<SnapshotPublicationReceipt>,
}

impl Default for UniverseSlot {
    fn default() -> Self {
        Self {
            next_generation: 1,
            active: None,
            revocation_reason: None,
            history: VecDeque::new(),
        }
    }
}

/// Multi-universe catalog publishing O(1) `Arc`-shared [`GraphSnapshotView`] instances with
/// deterministic invalidation tracking (`FSS-152`).
#[derive(Clone, Debug, Default)]
pub struct GraphSnapshotCatalog {
    slots: BTreeMap<GraphUniverse, UniverseSlot>,
}

impl GraphSnapshotCatalog {
    /// Creates an empty snapshot catalog.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: BTreeMap::new(),
        }
    }

    /// Atomically publishes an authorized [`ImmutableGraphProjection`] as the current O(1)
    /// `Arc`-shared view for its [`GraphUniverse`].
    ///
    /// Existing readers holding prior [`GraphSnapshotView`] clones retain full immutable access
    /// to their pinned projection while freshness checks immediately report exact invalidation.
    pub fn publish(
        &mut self,
        projection: ImmutableGraphProjection,
        authority: &ProjectionAuthorityScope,
        cancelled: bool,
    ) -> Result<SnapshotPublicationReceipt, SnapshotViewError> {
        if cancelled {
            return Err(SnapshotViewError::Cancelled);
        }
        validate_authority_for_universe(authority, projection.universe())?;
        let p_gen = projection.generation();
        if p_gen.authority_generation != authority.authority_generation
            || p_gen.privacy_epoch != authority.privacy_epoch
        {
            return Err(SnapshotViewError::AuthorityMismatch(format!(
                "projection auth/privacy ({}/{}) differs from active scope ({}/{})",
                p_gen.authority_generation,
                p_gen.privacy_epoch,
                authority.authority_generation,
                authority.privacy_epoch
            )));
        }

        let universe = projection.universe();
        let slot = self.slots.entry(universe).or_default();
        let (previous_view_generation, superseded_projection_digest) = match &slot.active {
            Some(prev) => {
                if prev.anchor().site_lineage == projection.anchor().site_lineage
                    && projection.anchor().commit_sequence < prev.anchor().commit_sequence
                {
                    return Err(SnapshotViewError::AnchorRegression {
                        previous_sequence: prev.anchor().commit_sequence,
                        attempted_sequence: projection.anchor().commit_sequence,
                    });
                }
                (
                    prev.view_generation,
                    Some(prev.generation().projection_digest),
                )
            }
            None => (0, None),
        };

        let view_generation = slot.next_generation;
        slot.next_generation = slot.next_generation.saturating_add(1);
        let certifies_absence = projection.absence_boundary().certifies_absence();
        let anchor_sequence = projection.anchor().commit_sequence;
        let projection_digest = p_gen.projection_digest;

        let new_view = GraphSnapshotView {
            view_generation,
            projection: Arc::new(projection),
        };
        slot.active = Some(new_view);
        slot.revocation_reason = None;

        let mut receipt = SnapshotPublicationReceipt {
            format_version: SNAPSHOT_RECEIPT_VERSION,
            universe,
            view_generation,
            previous_view_generation,
            anchor_sequence,
            authority_generation: p_gen.authority_generation,
            privacy_epoch: p_gen.privacy_epoch,
            projection_digest,
            superseded_projection_digest,
            certifies_absence,
            receipt_digest: ContentDigest::sha256(b"unsealed-snapshot-receipt"),
        };
        receipt.receipt_digest = receipt.compute_digest()?;
        if slot.history.len() >= MAX_RETAINED_SNAPSHOT_HISTORY {
            slot.history.pop_front();
        }
        slot.history.push_back(receipt.clone());
        Ok(receipt)
    }

    /// Acquires an O(1) `Arc`-cloned [`GraphSnapshotView`] for `universe` after enforcing active
    /// capability, privacy epoch, and authority generation equality.
    pub fn acquire_view(
        &self,
        universe: GraphUniverse,
        authority: &ProjectionAuthorityScope,
        cancelled: bool,
    ) -> Result<GraphSnapshotView, SnapshotViewError> {
        if cancelled {
            return Err(SnapshotViewError::Cancelled);
        }
        validate_authority_for_universe(authority, universe)?;
        let Some(slot) = self.slots.get(&universe) else {
            return Err(SnapshotViewError::UniverseUnavailable {
                universe,
                revocation_reason: None,
            });
        };
        let Some(active) = &slot.active else {
            return Err(SnapshotViewError::UniverseUnavailable {
                universe,
                revocation_reason: slot.revocation_reason.clone(),
            });
        };
        let a_gen = active.generation();
        if a_gen.authority_generation != authority.authority_generation
            || a_gen.privacy_epoch != authority.privacy_epoch
        {
            return Err(SnapshotViewError::AuthorityMismatch(format!(
                "active snapshot auth/privacy ({}/{}) does not match caller ({}/{}); re-project before reading",
                a_gen.authority_generation,
                a_gen.privacy_epoch,
                authority.authority_generation,
                authority.privacy_epoch
            )));
        }
        // O(1) Arc clone — zero node/edge/CSR copying!
        Ok(active.clone())
    }

    /// Explicitly revokes the active snapshot for `universe` (e.g. privacy/retention revocation).
    ///
    /// Already-cloned views remain memory-safe and immutable, while freshness checks immediately
    /// report [`SnapshotInvalidationReason::ExplicitRevocation`] and new acquisitions fail closed.
    pub fn revoke_universe(
        &mut self,
        universe: GraphUniverse,
        reason: &str,
    ) -> Result<(), SnapshotViewError> {
        if reason.is_empty()
            || reason.len() > MAX_SNAPSHOT_LABEL_BYTES
            || reason.chars().any(char::is_control)
        {
            return Err(SnapshotViewError::InvalidInput(
                "revocation reason must be 1..=256 non-control UTF-8 bytes".to_owned(),
            ));
        }
        let slot = self.slots.entry(universe).or_default();
        slot.active = None;
        slot.revocation_reason = Some(reason.to_owned());
        Ok(())
    }

    /// Evaluates whether `view` is still the exact active snapshot in this catalog, returning a
    /// non-collapsed [`SnapshotFreshness`] classification.
    #[must_use]
    pub fn check_freshness(&self, view: &GraphSnapshotView) -> SnapshotFreshness {
        let Some(slot) = self.slots.get(&view.universe()) else {
            return SnapshotFreshness::Invalidated {
                reason: SnapshotInvalidationReason::ExplicitRevocation {
                    reason: "universe_not_registered_in_catalog".to_owned(),
                },
                current_view_generation: 0,
                current_projection_digest: None,
            };
        };
        let Some(active) = &slot.active else {
            return SnapshotFreshness::Invalidated {
                reason: SnapshotInvalidationReason::ExplicitRevocation {
                    reason: slot
                        .revocation_reason
                        .clone()
                        .unwrap_or_else(|| "universe_revoked".to_owned()),
                },
                current_view_generation: 0,
                current_projection_digest: None,
            };
        };
        if active.view_generation == view.view_generation
            && active.generation() == view.generation()
        {
            return SnapshotFreshness::Current;
        }
        let old_g = view.generation();
        let new_g = active.generation();
        let reason = if old_g.privacy_epoch != new_g.privacy_epoch {
            SnapshotInvalidationReason::PrivacyEpochChanged {
                old_epoch: old_g.privacy_epoch,
                new_epoch: new_g.privacy_epoch,
            }
        } else if old_g.authority_generation != new_g.authority_generation {
            SnapshotInvalidationReason::AuthorityGenerationChanged {
                old_generation: old_g.authority_generation,
                new_generation: new_g.authority_generation,
            }
        } else if view.anchor().site_lineage != active.anchor().site_lineage {
            SnapshotInvalidationReason::LineageOrHistoryDiverged
        } else if old_g.anchor_sequence != new_g.anchor_sequence {
            SnapshotInvalidationReason::AnchorAdvanced {
                old_sequence: old_g.anchor_sequence,
                new_sequence: new_g.anchor_sequence,
            }
        } else if view.history_root() != active.history_root() {
            SnapshotInvalidationReason::LineageOrHistoryDiverged
        } else {
            SnapshotInvalidationReason::ProjectionReplaced
        };
        SnapshotFreshness::Invalidated {
            reason,
            current_view_generation: active.view_generation,
            current_projection_digest: Some(new_g.projection_digest),
        }
    }

    /// Fails closed with [`SnapshotViewError::ViewInvalidated`] if `view` is stale or if
    /// `authority` has drifted/revoked.
    pub fn require_current(
        &self,
        view: &GraphSnapshotView,
        authority: &ProjectionAuthorityScope,
    ) -> Result<(), SnapshotViewError> {
        validate_authority_for_universe(authority, view.universe())?;
        let v_gen = view.generation();
        if v_gen.authority_generation != authority.authority_generation {
            return Err(SnapshotViewError::ViewInvalidated {
                reason: SnapshotInvalidationReason::AuthorityGenerationChanged {
                    old_generation: v_gen.authority_generation,
                    new_generation: authority.authority_generation,
                },
            });
        }
        if v_gen.privacy_epoch != authority.privacy_epoch {
            return Err(SnapshotViewError::ViewInvalidated {
                reason: SnapshotInvalidationReason::PrivacyEpochChanged {
                    old_epoch: v_gen.privacy_epoch,
                    new_epoch: authority.privacy_epoch,
                },
            });
        }
        match self.check_freshness(view) {
            SnapshotFreshness::Current => Ok(()),
            SnapshotFreshness::Invalidated { reason, .. } => {
                Err(SnapshotViewError::ViewInvalidated { reason })
            }
        }
    }

    /// Returns bounded publication receipt history for `universe` in oldest-to-newest order.
    #[must_use]
    pub fn history_for(&self, universe: GraphUniverse) -> Vec<SnapshotPublicationReceipt> {
        self.slots
            .get(&universe)
            .map(|s| s.history.iter().cloned().collect())
            .unwrap_or_default()
    }
}

fn validate_authority_for_universe(
    authority: &ProjectionAuthorityScope,
    universe: GraphUniverse,
) -> Result<(), SnapshotViewError> {
    if !authority.capability_active {
        return Err(SnapshotViewError::Projection(
            ProjectionError::AuthorityRevoked("graph snapshot capability revoked".to_owned()),
        ));
    }
    if !authority.privacy_active {
        return Err(SnapshotViewError::Projection(
            ProjectionError::AuthorityRevoked("graph snapshot privacy revoked".to_owned()),
        ));
    }
    if authority.authority_generation != authority.expected_authority_generation {
        return Err(SnapshotViewError::Projection(
            ProjectionError::StaleAuthorityGeneration {
                expected: authority.expected_authority_generation,
                observed: authority.authority_generation,
            },
        ));
    }
    if !authority.allowed_universes.contains(&universe) {
        return Err(SnapshotViewError::Projection(
            ProjectionError::AuthorityRevoked(format!(
                "graph universe '{}' not authorized",
                universe.as_str()
            )),
        ));
    }
    Ok(())
}

fn parse_universe(raw: &str) -> Result<GraphUniverse, SnapshotViewError> {
    match raw {
        "G_phys" => Ok(GraphUniverse::GPhys),
        "H_vis" => Ok(GraphUniverse::HVis),
        "G_sensor" => Ok(GraphUniverse::GSensor),
        "G_time" => Ok(GraphUniverse::GTime),
        "G_assoc" => Ok(GraphUniverse::GAssoc),
        "G_evidence" => Ok(GraphUniverse::GEvidence),
        "G_effect" => Ok(GraphUniverse::GEffect),
        "G_object" => Ok(GraphUniverse::GObject),
        "G_auth" => Ok(GraphUniverse::GAuth),
        "G_memory" => Ok(GraphUniverse::GMemory),
        "G_agent" => Ok(GraphUniverse::GAgent),
        "G_world" => Ok(GraphUniverse::GWorld),
        other => Err(SnapshotViewError::MalformedWire(format!(
            "unknown graph universe '{other}'"
        ))),
    }
}
