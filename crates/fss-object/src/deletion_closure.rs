#![forbid(unsafe_code)]
//! Graph-complete archive deletion traversal (`FSS-133`, `fss-x4a.13.17`).
//!
//! Implements the normative deletion-closure protocol in `docs/ATP_ARCHIVE_AND_REPLICATION.md` §10:
//!
//! 1. **Complete nine-class artifact enumeration:** walks every reachable dependency from a target
//!    root across `SourceChunk`, `DerivativeChunk`, `Manifest`, `RepairSymbol`, `LocalReplica`,
//!    `RemoteReplica`, `IndexOrCache`, `TransferJournalOrStaging`, and `ExportedBundleInCustody`.
//! 2. **Evidence-hold and shared-reference protection:** blocks execution whenever ANY reachable
//!    member carries an active legal/evidence hold OR is still referenced by a live parent outside
//!    the deletion closure (reporting exact `DeletionBlocker` entries).
//! 3. **Honest non-deletion of unknown external copies:** copies outside FSS custody
//!    (`UnknownExternalCopy`) are retained verbatim in plans and receipts and are NEVER claimed
//!    deleted.
//! 4. **Two-step plan -> revalidate -> apply -> tombstone root -> verify unreachability:**
//!    revalidates exact `ContractBasis`, live authority generation, and non-empty owner approval
//!    digest before deleting any bytes; propagates remote/provider ambiguity as
//!    [`DeletionClosureState::Indeterminate`] rather than falsely succeeding; publishes the
//!    canonical tombstone root only after complete child deletion; and executes an independent
//!    post-tombstone scan that detects adversarial hidden references
//!    ([`DeletionClosureState::HiddenReferenceLeakDetected`]) rather than claiming
//!    [`DeletionClosureState::UnreachabilityVerified`].
//! 5. **Bounded checksummed binary wire receipt (`FSSDCL01` v1):** sealed under
//!    `fss.atp_deletion_closure_receipt.v1`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, TimestampNs,
};

use crate::closure::CustodyLevel;

/// Registered digest domain for [`DeletionClosurePlan`] commitments (`FSS-133`).
pub const ATP_DELETION_CLOSURE_PLAN_DOMAIN: &str = "fss.atp_deletion_closure_plan.v1";
/// Registered digest domain for published deletion tombstone roots (`FSS-133`).
pub const ATP_DELETION_TOMBSTONE_ROOT_DOMAIN: &str = "fss.atp_deletion_tombstone_root.v1";
/// Registered digest domain for sealed [`DeletionClosureReceipt`] commitments (`FSS-133`).
pub const ATP_DELETION_CLOSURE_RECEIPT_DOMAIN: &str = "fss.atp_deletion_closure_receipt.v1";
/// Binary wire header magic for serialized deletion closure receipts.
pub const DELETION_RECEIPT_MAGIC: [u8; 8] = *b"FSSDCL01";
/// Supported durable format version for [`DeletionClosureReceipt`].
pub const DELETION_RECEIPT_VERSION: u32 = 1;
/// Hard ceiling on reachable artifacts in one deletion closure pass.
pub const MAX_DELETION_CLOSURE_NODES: usize = 65_536;
/// Hard ceiling on traversal depth from deletion root.
pub const MAX_DELETION_CLOSURE_DEPTH: u32 = 128;
/// Hard ceiling on unknown external copy disclosures per deletion plan.
pub const MAX_UNKNOWN_EXTERNAL_COPIES: usize = 1_024;
/// Hard ceiling on UTF-8 bytes in labels, hold IDs, and diagnostic text.
pub const MAX_DELETION_LABEL_BYTES: usize = 256;
/// Hard ceiling on serialized deletion receipt wire bytes (4 MiB).
pub const MAX_DELETION_RECEIPT_WIRE_BYTES: usize = 4 * 1024 * 1024;

/// All nine normative artifact classes under FSS custody (`docs/ATP_ARCHIVE_AND_REPLICATION.md` §10).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DeletionArtifactClass {
    /// Original immutable source media/evidence chunk.
    SourceChunk = 1,
    /// Derivative transcoded/cropped/extracted chunk.
    DerivativeChunk = 2,
    /// Manifest linking chunks, metadata, or sub-manifests.
    Manifest = 3,
    /// RaptorQ / erasure-coding repair symbol object.
    RepairSymbol = 4,
    /// Local storage / spool replica.
    LocalReplica = 5,
    /// Remote cloud/archive provider replica.
    RemoteReplica = 6,
    /// Derived search index, embedding, graph relation, or cache artifact.
    IndexOrCache = 7,
    /// Transfer journal or uncommitted staging object.
    TransferJournalOrStaging = 8,
    /// Exported evidence bundle still retained under FSS custody.
    ExportedBundleInCustody = 9,
}

impl DeletionArtifactClass {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceChunk => "source_chunk",
            Self::DerivativeChunk => "derivative_chunk",
            Self::Manifest => "manifest",
            Self::RepairSymbol => "repair_symbol",
            Self::LocalReplica => "local_replica",
            Self::RemoteReplica => "remote_replica",
            Self::IndexOrCache => "index_or_cache",
            Self::TransferJournalOrStaging => "transfer_journal_or_staging",
            Self::ExportedBundleInCustody => "exported_bundle_in_custody",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }
}

/// Non-collapsed deletion closure execution state (`docs/ATP_ARCHIVE_AND_REPLICATION.md` §10).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeletionClosureState {
    /// Complete graph closure enumerated; zero bytes deleted yet.
    Planned = 1,
    /// Blocked by an active evidence hold or live parent outside the deletion closure.
    BlockedByHoldOrSharedReference = 2,
    /// All planned children deleted and canonical tombstone root published, pending unreachability check.
    TombstoneRootPublished = 3,
    /// Independent post-tombstone verification confirmed zero reachable artifacts or hidden refs.
    UnreachabilityVerified = 4,
    /// Post-tombstone scan detected a surviving reachable artifact or hidden reference (leak!).
    HiddenReferenceLeakDetected = 5,
    /// At least one provider/remote deletion outcome was ambiguous; reconciliation required.
    Indeterminate = 6,
    /// Cooperative cancellation observed before execution committed.
    Cancelled = 7,
}

impl DeletionClosureState {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::BlockedByHoldOrSharedReference => "blocked_by_hold_or_shared_reference",
            Self::TombstoneRootPublished => "tombstone_root_published",
            Self::UnreachabilityVerified => "unreachability_verified",
            Self::HiddenReferenceLeakDetected => "hidden_reference_leak_detected",
            Self::Indeterminate => "indeterminate",
            Self::Cancelled => "cancelled",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::Planned),
            2 => Ok(Self::BlockedByHoldOrSharedReference),
            3 => Ok(Self::TombstoneRootPublished),
            4 => Ok(Self::UnreachabilityVerified),
            5 => Ok(Self::HiddenReferenceLeakDetected),
            6 => Ok(Self::Indeterminate),
            7 => Ok(Self::Cancelled),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Safe operator/agent recovery guidance for a refused or incomplete deletion closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeletionGuidance {
    /// Obtain explicit owner deletion approval and active deletion/privacy capability.
    ObtainOwnerDeletionApproval,
    /// Re-plan against current `ContractBasis` and authority generation.
    ReplanAgainstCurrentBasis,
    /// Release active evidence holds or include live external parents before re-planning.
    ResolveHoldsOrSharedParents,
    /// Purge surviving hidden references and rerun unreachability verification.
    PurgeHiddenReferencesAndReverify,
    /// Reconcile ambiguous remote provider deletions before publishing final verification.
    ReconcileIndeterminateDeletions,
    /// Fix invalid target root, bounds, or label inputs.
    RepairDeletionInput,
    /// Cooperative cancellation observed; safe to retry cleanly from sealed plan.
    RetryWhenReady,
    /// Reject corrupt or unsupported binary deletion receipt bytes.
    RejectCorruptReceipt,
}

/// Typed error returned by [`DeletionClosureExecutor`] or [`DeletionClosureReceipt`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeletionClosureError {
    /// Deletion capability, privacy authorization, or explicit owner approval missing/revoked.
    AuthorityRevoked(String),
    /// Basis anchor, authority generation, or privacy epoch drifted between plan and execute.
    StalePlanOrAuthority(String),
    /// Requested root digest is not present in the archive deletion catalog.
    UnknownRoot(ContentDigest),
    /// Attempted to execute a plan that is blocked by active holds or external live parents.
    BlockedByHoldOrSharedReference {
        /// Number of blocking holds/references.
        blocker_count: usize,
    },
    /// Cooperative cancellation observed before execution committed.
    Cancelled,
    /// Traversal exceeded node, depth, or wire ceilings.
    BoundsExceeded {
        /// Observed size/count.
        observed: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Invalid label, duplicate entry, or invariant violation.
    InvalidInput(String),
    /// Binary receipt lacked [`DELETION_RECEIPT_MAGIC`].
    InvalidMagic,
    /// Binary receipt declared an unsupported version.
    UnsupportedVersion {
        /// Observed version.
        version: u32,
    },
    /// Binary receipt was truncated, non-canonical, or structurally inconsistent.
    MalformedWire(String),
    /// Receipt or plan checksum failed verification.
    ChecksumMismatch,
    /// Canonical encoder failure.
    Encoding(String),
}

impl DeletionClosureError {
    /// Stable canonical machine error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AuthorityRevoked(_) => "ERR-ATP-DELETION-AUTHORITY-REVOKED-001",
            Self::StalePlanOrAuthority(_) => "ERR-ATP-DELETION-STALE-PLAN-001",
            Self::UnknownRoot(_) => "ERR-ATP-DELETION-UNKNOWN-ROOT-001",
            Self::BlockedByHoldOrSharedReference { .. } => "ERR-ATP-DELETION-BLOCKED-001",
            Self::Cancelled => "ERR-ATP-DELETION-CANCELLED-001",
            Self::BoundsExceeded { .. } => "ERR-ATP-DELETION-BOUNDS-001",
            Self::InvalidInput(_) => "ERR-ATP-DELETION-INVALID-INPUT-001",
            Self::InvalidMagic => "ERR-ATP-DELETION-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-ATP-DELETION-UNSUPPORTED-VERSION-001",
            Self::MalformedWire(_) => "ERR-ATP-DELETION-MALFORMED-WIRE-001",
            Self::ChecksumMismatch => "ERR-ATP-DELETION-CHECKSUM-MISMATCH-001",
            Self::Encoding(_) => "ERR-ATP-DELETION-ENCODING-001",
        }
    }

    /// Safe operator/agent recovery guidance.
    #[must_use]
    pub const fn guidance(&self) -> DeletionGuidance {
        match self {
            Self::AuthorityRevoked(_) => DeletionGuidance::ObtainOwnerDeletionApproval,
            Self::StalePlanOrAuthority(_) => DeletionGuidance::ReplanAgainstCurrentBasis,
            Self::BlockedByHoldOrSharedReference { .. } => {
                DeletionGuidance::ResolveHoldsOrSharedParents
            }
            Self::UnknownRoot(_) | Self::BoundsExceeded { .. } | Self::InvalidInput(_) => {
                DeletionGuidance::RepairDeletionInput
            }
            Self::Cancelled => DeletionGuidance::RetryWhenReady,
            Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::MalformedWire(_)
            | Self::ChecksumMismatch
            | Self::Encoding(_) => DeletionGuidance::RejectCorruptReceipt,
        }
    }
}

impl fmt::Display for DeletionClosureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for DeletionClosureError {}

/// Explicit deletion authority context requiring non-`None` owner approval digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletionAuthorityContext {
    /// Exact pinned `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Active authority generation.
    pub authority_generation: u64,
    /// Expected authority generation pinned at planning time.
    pub expected_authority_generation: u64,
    /// Active privacy epoch.
    pub privacy_epoch: u64,
    /// True while deletion capability remains active.
    pub deletion_capability_active: bool,
    /// True while privacy authorization remains active.
    pub privacy_active: bool,
    /// Explicit owner deletion approval commitment (`None` fails closed!).
    pub owner_approval_digest: Option<ContentDigest>,
}

impl DeletionAuthorityContext {
    /// Constructs an active, owner-approved deletion authority context.
    #[must_use]
    pub const fn approved(
        contract_basis_digest: ContentDigest,
        authority_generation: u64,
        privacy_epoch: u64,
        owner_approval_digest: ContentDigest,
    ) -> Self {
        Self {
            contract_basis_digest,
            authority_generation,
            expected_authority_generation: authority_generation,
            privacy_epoch,
            deletion_capability_active: true,
            privacy_active: true,
            owner_approval_digest: Some(owner_approval_digest),
        }
    }

    fn validate_active(&self) -> Result<ContentDigest, DeletionClosureError> {
        if !self.deletion_capability_active {
            return Err(DeletionClosureError::AuthorityRevoked(
                "deletion capability revoked".to_owned(),
            ));
        }
        if !self.privacy_active {
            return Err(DeletionClosureError::AuthorityRevoked(
                "privacy authorization revoked".to_owned(),
            ));
        }
        let Some(approval) = self.owner_approval_digest else {
            return Err(DeletionClosureError::AuthorityRevoked(
                "explicit owner deletion approval digest is required".to_owned(),
            ));
        };
        if self.authority_generation != self.expected_authority_generation {
            return Err(DeletionClosureError::StalePlanOrAuthority(format!(
                "authority_generation ({}) != expected ({})",
                self.authority_generation, self.expected_authority_generation
            )));
        }
        Ok(approval)
    }
}

/// Disclosure of an external copy outside FSS custody (reported honestly, NEVER claimed deleted).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownExternalCopy {
    /// Stable copy disclosure identity.
    pub copy_id: String,
    /// External destination description (e.g. `"offline-usb-export-2026-10"`).
    pub destination_label: String,
    /// Reason FSS cannot verify deletion of this copy.
    pub note: String,
}

/// Typed blocker preventing execution of a deletion closure plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletionBlocker {
    /// Digest of the protected artifact inside the deletion closure.
    pub target_digest: ContentDigest,
    /// Either `"active_evidence_hold"` or `"live_external_parent"`.
    pub kind: String,
    /// Hold identity or external parent digest hex.
    pub reference_id: String,
}

/// One node in the FSS archive custody graph inspected during deletion closure traversal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletionGraphNode {
    /// Canonical content digest of this artifact.
    pub digest: ContentDigest,
    /// Normative artifact class (`docs/ATP_ARCHIVE_AND_REPLICATION.md` §10).
    pub class: DeletionArtifactClass,
    /// Exact payload byte size.
    pub byte_len: u64,
    /// Current custody milestone.
    pub custody: CustodyLevel,
    /// Active evidence/legal hold IDs protecting this artifact.
    pub active_holds: BTreeSet<String>,
    /// Outgoing child/derivative/repair/replica/index/journal dependency digests.
    pub dependencies: BTreeSet<ContentDigest>,
    /// Hidden/secondary reference aliases (e.g. orphaned index/cache/staging pointers) tested
    /// during post-tombstone adversarial unreachability verification.
    pub hidden_reference_aliases: BTreeSet<ContentDigest>,
    /// False once this artifact has been purged from FSS custody.
    pub reachable: bool,
    /// If `true`, deleting this node fails to clear one of its hidden aliases (adversarial test hook).
    pub simulate_surviving_hidden_ref: Option<ContentDigest>,
}

/// In-memory reference archive deletion graph supporting complete traversal, reverse-parent
/// shared-reference checks, deletion application, and post-tombstone unreachability scans.
#[derive(Clone, Debug, Default)]
pub struct ArchiveDeletionCatalog {
    nodes: BTreeMap<ContentDigest, DeletionGraphNode>,
    /// Hidden dangling/surviving references mapped from root/member digest -> live alias digest.
    surviving_hidden_refs: BTreeMap<ContentDigest, BTreeSet<ContentDigest>>,
    /// Published tombstone roots keyed by deleted target root digest.
    tombstones: BTreeMap<ContentDigest, ContentDigest>,
    /// Latest execution per root, bound to the catalog state immediately after apply.
    executions: BTreeMap<ContentDigest, (ContentDigest, DeletionClosureReceipt)>,
}

impl ArchiveDeletionCatalog {
    /// Creates an empty archive deletion catalog.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a reachable artifact node in FSS custody.
    pub fn insert(&mut self, node: DeletionGraphNode) {
        self.nodes.insert(node.digest, node);
    }

    /// Returns a node by digest.
    #[must_use]
    pub fn get(&self, digest: &ContentDigest) -> Option<&DeletionGraphNode> {
        self.nodes.get(digest)
    }

    /// Returns the published tombstone root digest for `root_digest`, if tombstoned.
    #[must_use]
    pub fn tombstone_for(&self, root_digest: &ContentDigest) -> Option<ContentDigest> {
        self.tombstones.get(root_digest).copied()
    }

    /// Computes a canonical digest of the catalog's current live node set & holds (basis check).
    pub fn catalog_state_digest(&self) -> Result<ContentDigest, DeletionClosureError> {
        let mut enc = CanonicalEncoder::new();
        enc.text("fss.atp_deletion_catalog_state.v1");
        enc.u64(self.nodes.len() as u64);
        for (digest, node) in &self.nodes {
            enc.digest(*digest);
            enc.u8(node.class.tag());
            enc.u64(node.byte_len);
            enc.bool(node.reachable);
            enc.u64(node.active_holds.len() as u64);
            for h in &node.active_holds {
                enc.text(h);
            }
            enc.u64(node.dependencies.len() as u64);
            for dep in &node.dependencies {
                enc.digest(*dep);
            }
            enc.u64(node.hidden_reference_aliases.len() as u64);
            for alias in &node.hidden_reference_aliases {
                enc.digest(*alias);
            }
        }
        let bytes = enc
            .finish_checked()
            .map_err(|e| DeletionClosureError::Encoding(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Enumerate each live inbound edge once, including secondary index/cache aliases.
    fn external_references<'a>(
        &'a self,
        members: &'a BTreeSet<ContentDigest>,
    ) -> impl Iterator<Item = (ContentDigest, ContentDigest)> + 'a {
        self.nodes
            .iter()
            .filter(move |(parent, node)| node.reachable && !members.contains(*parent))
            .flat_map(move |(parent, node)| {
                node.dependencies
                    .union(&node.hidden_reference_aliases)
                    .filter(move |target| members.contains(*target))
                    .map(move |target| (*parent, *target))
            })
    }
}

/// One planned member inside a [`DeletionClosurePlan`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedDeletionMember {
    /// Canonical artifact digest.
    pub digest: ContentDigest,
    /// Normative artifact class.
    pub class: DeletionArtifactClass,
    /// Exact payload byte size.
    pub byte_len: u64,
    /// Traversal depth from root (`0` for root).
    pub depth: u32,
}

/// Sealed immutable graph-complete deletion closure plan (`fss.atp_deletion_closure_plan.v1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletionClosurePlan {
    /// Root digest targeted for graph-complete deletion.
    pub root_digest: ContentDigest,
    /// Pinned `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Pinned catalog state digest at planning time (revalidated before apply!).
    pub catalog_state_digest: ContentDigest,
    /// Pinned authority generation.
    pub authority_generation: u64,
    /// Pinned privacy epoch.
    pub privacy_epoch: u64,
    /// Owner deletion approval digest bound to this plan.
    pub owner_approval_digest: ContentDigest,
    /// Ordered planned members to delete across all 9 artifact classes.
    pub members: Vec<PlannedDeletionMember>,
    /// Active holds or live external parents blocking deletion (non-empty => cannot execute).
    pub blockers: Vec<DeletionBlocker>,
    /// External copies outside FSS custody (NEVER claimed deleted).
    pub unknown_external_copies: Vec<UnknownExternalCopy>,
    /// Total planned bytes under FSS custody.
    pub total_planned_bytes: u64,
    /// Timestamp when the plan was sealed.
    pub planned_at: TimestampNs,
    /// Domain-separated SHA-256 commitment (`fss.atp_deletion_closure_plan.v1`).
    pub plan_digest: ContentDigest,
}

impl DeletionClosurePlan {
    /// True iff active evidence holds or live external parents block execution.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        !self.blockers.is_empty()
    }

    /// Recomputes the canonical plan digest (`fss.atp_deletion_closure_plan.v1`).
    pub fn compute_digest(&self) -> Result<ContentDigest, DeletionClosureError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(ATP_DELETION_CLOSURE_PLAN_DOMAIN);
        enc.digest(self.root_digest);
        enc.digest(self.contract_basis_digest);
        enc.digest(self.catalog_state_digest);
        enc.u64(self.authority_generation);
        enc.u64(self.privacy_epoch);
        enc.digest(self.owner_approval_digest);
        enc.u64(self.members.len() as u64);
        for m in &self.members {
            enc.digest(m.digest);
            enc.u8(m.class.tag());
            enc.u64(m.byte_len);
            enc.u32(m.depth);
        }
        enc.u64(self.blockers.len() as u64);
        for b in &self.blockers {
            enc.digest(b.target_digest);
            enc.text(&b.kind);
            enc.text(&b.reference_id);
        }
        enc.u64(self.unknown_external_copies.len() as u64);
        for ext in &self.unknown_external_copies {
            enc.text(&ext.copy_id);
            enc.text(&ext.destination_label);
            enc.text(&ext.note);
        }
        enc.u64(self.total_planned_bytes);
        self.planned_at.encode_canonical(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| DeletionClosureError::Encoding(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn verify_self(&self) -> Result<(), DeletionClosureError> {
        if self.compute_digest()? != self.plan_digest {
            return Err(DeletionClosureError::ChecksumMismatch);
        }
        Ok(())
    }
}

/// Sealed graph-complete deletion execution and unreachability receipt (`FSSDCL01` v1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletionClosureReceipt {
    /// Wire format version (`DELETION_RECEIPT_VERSION`).
    pub format_version: u32,
    /// Sealed plan digest.
    pub plan_digest: ContentDigest,
    /// Deleted root digest.
    pub root_digest: ContentDigest,
    /// Published tombstone root digest (present iff all child deletions finished cleanly).
    pub tombstone_root_digest: Option<ContentDigest>,
    /// Pinned `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Active authority generation.
    pub authority_generation: u64,
    /// Active privacy epoch.
    pub privacy_epoch: u64,
    /// Explicit owner deletion approval digest.
    pub owner_approval_digest: ContentDigest,
    /// Non-collapsed terminal deletion state.
    pub state: DeletionClosureState,
    /// Ordered digests deleted under FSS custody.
    pub deleted_digests: Vec<ContentDigest>,
    /// Ordered digests whose remote/provider deletion remained indeterminate.
    pub indeterminate_digests: Vec<ContentDigest>,
    /// Ordered digests/aliases discovered still reachable during post-tombstone scan (leak!).
    pub surviving_hidden_references: Vec<ContentDigest>,
    /// External copies outside FSS custody (explicitly reported, NEVER claimed deleted).
    pub unknown_external_copies: Vec<UnknownExternalCopy>,
    /// Total bytes deleted under FSS custody.
    pub deleted_bytes: u64,
    /// Timestamp when this receipt was sealed.
    pub completed_at: TimestampNs,
    /// Domain-separated SHA-256 commitment (`fss.atp_deletion_closure_receipt.v1`).
    pub receipt_digest: ContentDigest,
}

impl DeletionClosureReceipt {
    /// Recomputes the domain-separated canonical SHA-256 digest.
    pub fn compute_digest(&self) -> Result<ContentDigest, DeletionClosureError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(ATP_DELETION_CLOSURE_RECEIPT_DOMAIN);
        self.encode_body(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| DeletionClosureError::Encoding(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn verify_self(&self) -> Result<(), DeletionClosureError> {
        if self.format_version != DELETION_RECEIPT_VERSION {
            return Err(DeletionClosureError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        if self.state == DeletionClosureState::UnreachabilityVerified
            && (self.tombstone_root_digest.is_none()
                || !self.indeterminate_digests.is_empty()
                || !self.surviving_hidden_references.is_empty()
                || self.deleted_digests.is_empty()
                || !self.deleted_digests.contains(&self.root_digest))
        {
            return Err(DeletionClosureError::MalformedWire(
                "UnreachabilityVerified receipt requires tombstone root, root in deleted_digests, zero indeterminate, and zero leaked references"
                    .to_owned(),
            ));
        }
        if self.state == DeletionClosureState::HiddenReferenceLeakDetected
            && (self.surviving_hidden_references.is_empty()
                || self.tombstone_root_digest.is_none()
                || !self.indeterminate_digests.is_empty())
        {
            return Err(DeletionClosureError::MalformedWire(
                "HiddenReferenceLeakDetected requires tombstone root, zero indeterminate, and non-empty surviving_hidden_references"
                    .to_owned(),
            ));
        }
        if self.state == DeletionClosureState::Indeterminate
            && (self.indeterminate_digests.is_empty() || self.tombstone_root_digest.is_some())
        {
            return Err(DeletionClosureError::MalformedWire(
                "Indeterminate deletion receipt requires non-empty indeterminate_digests and no tombstone root"
                    .to_owned(),
            ));
        }
        let del_set: BTreeSet<ContentDigest> = self.deleted_digests.iter().copied().collect();
        if self
            .indeterminate_digests
            .iter()
            .any(|d| del_set.contains(d))
        {
            return Err(DeletionClosureError::MalformedWire(
                "deleted_digests and indeterminate_digests must be disjoint".to_owned(),
            ));
        }
        for pair in self.deleted_digests.windows(2) {
            if pair[0] >= pair[1] {
                return Err(DeletionClosureError::MalformedWire(
                    "deleted_digests must be strictly ascending".to_owned(),
                ));
            }
        }
        for pair in self.indeterminate_digests.windows(2) {
            if pair[0] >= pair[1] {
                return Err(DeletionClosureError::MalformedWire(
                    "indeterminate_digests must be strictly ascending".to_owned(),
                ));
            }
        }
        for pair in self.surviving_hidden_references.windows(2) {
            if pair[0] >= pair[1] {
                return Err(DeletionClosureError::MalformedWire(
                    "surviving_hidden_references must be strictly ascending".to_owned(),
                ));
            }
        }
        for pair in self.unknown_external_copies.windows(2) {
            if pair[0].copy_id >= pair[1].copy_id {
                return Err(DeletionClosureError::MalformedWire(
                    "unknown_external_copies must be strictly ordered by copy_id".to_owned(),
                ));
            }
        }
        if self.compute_digest()? != self.receipt_digest {
            return Err(DeletionClosureError::ChecksumMismatch);
        }
        Ok(())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.digest(self.plan_digest);
        enc.digest(self.root_digest);
        match self.tombstone_root_digest {
            Some(d) => {
                enc.u8(1);
                enc.digest(d);
            }
            None => enc.u8(0),
        }
        enc.digest(self.contract_basis_digest);
        enc.u64(self.authority_generation);
        enc.u64(self.privacy_epoch);
        enc.digest(self.owner_approval_digest);
        enc.u8(self.state.tag());
        enc.u64(self.deleted_digests.len() as u64);
        for d in &self.deleted_digests {
            enc.digest(*d);
        }
        enc.u64(self.indeterminate_digests.len() as u64);
        for d in &self.indeterminate_digests {
            enc.digest(*d);
        }
        enc.u64(self.surviving_hidden_references.len() as u64);
        for d in &self.surviving_hidden_references {
            enc.digest(*d);
        }
        enc.u64(self.unknown_external_copies.len() as u64);
        for ext in &self.unknown_external_copies {
            enc.text(&ext.copy_id);
            enc.text(&ext.destination_label);
            enc.text(&ext.note);
        }
        enc.u64(self.deleted_bytes);
        self.completed_at.encode_canonical(enc);
    }

    /// Encodes this deletion receipt into bounded checksummed binary bytes (`FSSDCL01` v1).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, DeletionClosureError> {
        self.verify_self()?;
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        enc.digest(self.receipt_digest);
        let body = enc
            .finish_checked()
            .map_err(|e| DeletionClosureError::Encoding(e.to_string()))?;
        let total = DELETION_RECEIPT_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_DELETION_RECEIPT_WIRE_BYTES {
            return Err(DeletionClosureError::BoundsExceeded {
                observed: total,
                maximum: MAX_DELETION_RECEIPT_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&DELETION_RECEIPT_MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and verifies a binary [`DeletionClosureReceipt`] (`FSSDCL01` v1).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeletionClosureError> {
        if bytes.len() > MAX_DELETION_RECEIPT_WIRE_BYTES {
            return Err(DeletionClosureError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_DELETION_RECEIPT_WIRE_BYTES,
            });
        }
        if bytes.len() < 12 || bytes[..8] != DELETION_RECEIPT_MAGIC {
            return Err(DeletionClosureError::InvalidMagic);
        }
        let header_ver = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if header_ver != DELETION_RECEIPT_VERSION {
            return Err(DeletionClosureError::UnsupportedVersion {
                version: header_ver,
            });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let format_version = dec
            .u32()
            .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?;
        if format_version != header_ver {
            return Err(DeletionClosureError::UnsupportedVersion {
                version: format_version,
            });
        }
        let plan_digest = dec
            .digest()
            .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?;
        let root_digest = dec
            .digest()
            .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?;
        let tombstone_root_digest = match dec
            .u8()
            .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?
        {
            0 => None,
            1 => Some(
                dec.digest()
                    .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?,
            ),
            other => {
                return Err(DeletionClosureError::MalformedWire(format!(
                    "invalid tombstone tag {other}"
                )));
            }
        };
        let contract_basis_digest = dec
            .digest()
            .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?;
        let authority_generation = dec
            .u64()
            .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?;
        let privacy_epoch = dec
            .u64()
            .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?;
        let owner_approval_digest = dec
            .digest()
            .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?;
        let state = DeletionClosureState::from_tag(
            dec.u8()
                .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?,
        )
        .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?;

        let deleted_digests = decode_digest_vec(&mut dec, MAX_DELETION_CLOSURE_NODES)?;
        let indeterminate_digests = decode_digest_vec(&mut dec, MAX_DELETION_CLOSURE_NODES)?;
        let surviving_hidden_references = decode_digest_vec(&mut dec, MAX_DELETION_CLOSURE_NODES)?;

        let ext_count = usize::try_from(
            dec.u64()
                .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?,
        )
        .map_err(|_| DeletionClosureError::BoundsExceeded {
            observed: usize::MAX,
            maximum: MAX_UNKNOWN_EXTERNAL_COPIES,
        })?;
        if ext_count > MAX_UNKNOWN_EXTERNAL_COPIES || ext_count.saturating_mul(15) > dec.remaining()
        {
            return Err(DeletionClosureError::BoundsExceeded {
                observed: ext_count,
                maximum: MAX_UNKNOWN_EXTERNAL_COPIES,
            });
        }
        let mut unknown_external_copies = Vec::with_capacity(ext_count);
        for _ in 0..ext_count {
            let copy_id = dec
                .text()
                .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?
                .to_owned();
            let destination_label = dec
                .text()
                .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?
                .to_owned();
            let note = dec
                .text()
                .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?
                .to_owned();
            validate_label(&copy_id, MAX_DELETION_LABEL_BYTES, "copy_id")
                .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?;
            validate_label(
                &destination_label,
                MAX_DELETION_LABEL_BYTES,
                "destination_label",
            )
            .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?;
            validate_label(&note, MAX_DELETION_LABEL_BYTES, "note")
                .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?;
            unknown_external_copies.push(UnknownExternalCopy {
                copy_id,
                destination_label,
                note,
            });
        }

        let deleted_bytes = dec
            .u64()
            .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?;
        let completed_at = TimestampNs::decode_canonical(&mut dec)
            .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?;
        let stored_digest = dec
            .digest()
            .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?;
        dec.ensure_finished().map_err(|_| {
            DeletionClosureError::MalformedWire("trailing bytes after deletion receipt".to_owned())
        })?;

        let receipt = Self {
            format_version,
            plan_digest,
            root_digest,
            tombstone_root_digest,
            contract_basis_digest,
            authority_generation,
            privacy_epoch,
            owner_approval_digest,
            state,
            deleted_digests,
            indeterminate_digests,
            surviving_hidden_references,
            unknown_external_copies,
            deleted_bytes,
            completed_at,
            receipt_digest: stored_digest,
        };
        receipt.verify_self()?;
        Ok(receipt)
    }
}

/// Deterministic graph-complete deletion planner, applier, and unreachability verifier (`FSS-133`).
pub struct DeletionClosureExecutor;

impl DeletionClosureExecutor {
    /// Enumerates the complete bounded deletion closure from `root_digest`, recording every
    /// evidence hold, live external parent blocker, and unknown external copy disclosure.
    pub fn plan_closure(
        catalog: &ArchiveDeletionCatalog,
        root_digest: ContentDigest,
        authority: &DeletionAuthorityContext,
        mut unknown_external_copies: Vec<UnknownExternalCopy>,
        planned_at: TimestampNs,
        cancelled: bool,
    ) -> Result<DeletionClosurePlan, DeletionClosureError> {
        if cancelled {
            return Err(DeletionClosureError::Cancelled);
        }
        let owner_approval_digest = authority.validate_active()?;
        if unknown_external_copies.len() > MAX_UNKNOWN_EXTERNAL_COPIES {
            return Err(DeletionClosureError::BoundsExceeded {
                observed: unknown_external_copies.len(),
                maximum: MAX_UNKNOWN_EXTERNAL_COPIES,
            });
        }
        unknown_external_copies.sort_by(|a, b| a.copy_id.cmp(&b.copy_id));
        for ext in &unknown_external_copies {
            validate_label(&ext.copy_id, MAX_DELETION_LABEL_BYTES, "copy_id")?;
            validate_label(
                &ext.destination_label,
                MAX_DELETION_LABEL_BYTES,
                "destination_label",
            )?;
            validate_label(&ext.note, MAX_DELETION_LABEL_BYTES, "note")?;
        }
        for pair in unknown_external_copies.windows(2) {
            if pair[0].copy_id == pair[1].copy_id {
                return Err(DeletionClosureError::InvalidInput(format!(
                    "duplicate unknown_external_copy '{}'",
                    pair[0].copy_id
                )));
            }
        }

        if !catalog.nodes.get(&root_digest).is_some_and(|n| n.reachable) {
            return Err(DeletionClosureError::UnknownRoot(root_digest));
        }

        // Bounded BFS closure over every reachable dependency and hidden reference alias.
        let mut visited: BTreeMap<ContentDigest, u32> = BTreeMap::new();
        let mut queue: VecDeque<(ContentDigest, u32)> = VecDeque::new();
        visited.insert(root_digest, 0);
        queue.push_back((root_digest, 0));

        while let Some((curr, depth)) = queue.pop_front() {
            let Some(node) = catalog.nodes.get(&curr) else {
                continue;
            };
            if !node.reachable {
                continue;
            }
            let next_depth = depth.saturating_add(1);
            for next in node
                .dependencies
                .iter()
                .chain(node.hidden_reference_aliases.iter())
            {
                if visited.contains_key(next) {
                    continue;
                }
                let child = catalog.nodes.get(next).ok_or_else(|| {
                    DeletionClosureError::InvalidInput(format!(
                        "archive closure is incomplete: {curr} references unknown artifact {next}"
                    ))
                })?;
                if !child.reachable {
                    continue;
                }
                if next_depth > MAX_DELETION_CLOSURE_DEPTH {
                    return Err(DeletionClosureError::BoundsExceeded {
                        observed: next_depth as usize,
                        maximum: MAX_DELETION_CLOSURE_DEPTH as usize,
                    });
                }
                if visited.len() >= MAX_DELETION_CLOSURE_NODES {
                    return Err(DeletionClosureError::BoundsExceeded {
                        observed: visited.len() + 1,
                        maximum: MAX_DELETION_CLOSURE_NODES,
                    });
                }
                visited.insert(*next, next_depth);
                queue.push_back((*next, next_depth));
            }
        }

        let closure_set: BTreeSet<ContentDigest> = visited.keys().copied().collect();
        let mut members: Vec<PlannedDeletionMember> = Vec::with_capacity(visited.len());
        let mut blockers: Vec<DeletionBlocker> = Vec::new();
        let mut total_planned_bytes = 0_u64;

        for (&digest, &depth) in &visited {
            let Some(node) = catalog.nodes.get(&digest) else {
                continue;
            };
            for hold_id in &node.active_holds {
                blockers.push(DeletionBlocker {
                    target_digest: digest,
                    kind: "active_evidence_hold".to_owned(),
                    reference_id: hold_id.clone(),
                });
            }
            total_planned_bytes =
                total_planned_bytes
                    .checked_add(node.byte_len)
                    .ok_or_else(|| {
                        DeletionClosureError::InvalidInput(
                            "deletion closure exceeds u64 byte accounting".to_owned(),
                        )
                    })?;
            members.push(PlannedDeletionMember {
                digest,
                class: node.class,
                byte_len: node.byte_len,
                depth,
            });
        }

        for (parent, target) in catalog.external_references(&closure_set) {
            blockers.push(DeletionBlocker {
                target_digest: target,
                kind: "live_external_parent".to_owned(),
                reference_id: parent.to_string(),
            });
        }

        // Canonical deterministic order: ascending `(depth, digest)` (manifests/indexes before leaves).
        members.sort_by_key(|a| (a.depth, a.digest));
        blockers.sort_by(|a, b| {
            (a.target_digest, a.kind.as_str(), a.reference_id.as_str()).cmp(&(
                b.target_digest,
                b.kind.as_str(),
                b.reference_id.as_str(),
            ))
        });

        let catalog_state_digest = catalog.catalog_state_digest()?;
        let mut plan = DeletionClosurePlan {
            root_digest,
            contract_basis_digest: authority.contract_basis_digest,
            catalog_state_digest,
            authority_generation: authority.authority_generation,
            privacy_epoch: authority.privacy_epoch,
            owner_approval_digest,
            members,
            blockers,
            unknown_external_copies,
            total_planned_bytes,
            planned_at,
            plan_digest: ContentDigest::sha256(b"unsealed-deletion-plan"),
        };
        plan.plan_digest = plan.compute_digest()?;
        Ok(plan)
    }

    /// Revalidates `plan` against live catalog state and authority, applies child deletions,
    /// publishes a canonical tombstone root, and executes an independent post-tombstone
    /// adversarial unreachability scan.
    pub fn execute_and_verify(
        catalog: &mut ArchiveDeletionCatalog,
        plan: &DeletionClosurePlan,
        authority: &DeletionAuthorityContext,
        remote_indeterminate_targets: &BTreeSet<ContentDigest>,
        completed_at: TimestampNs,
        cancelled: bool,
    ) -> Result<DeletionClosureReceipt, DeletionClosureError> {
        if cancelled {
            return Err(DeletionClosureError::Cancelled);
        }
        plan.verify_self()?;
        let approval = authority.validate_active()?;
        if authority.contract_basis_digest != plan.contract_basis_digest
            || authority.authority_generation != plan.authority_generation
            || authority.privacy_epoch != plan.privacy_epoch
            || approval != plan.owner_approval_digest
        {
            return Err(DeletionClosureError::StalePlanOrAuthority(
                "authority, privacy, basis, or approval drifted since deletion planning".to_owned(),
            ));
        }
        if plan.is_blocked() {
            return Err(DeletionClosureError::BlockedByHoldOrSharedReference {
                blocker_count: plan.blockers.len(),
            });
        }
        let current_catalog_digest = catalog.catalog_state_digest()?;
        let previous = catalog
            .executions
            .get(&plan.root_digest)
            .filter(|(_, receipt)| receipt.plan_digest == plan.plan_digest);
        let expected_state = previous.map_or(plan.catalog_state_digest, |(state, _)| *state);
        if current_catalog_digest != expected_state {
            return Err(DeletionClosureError::StalePlanOrAuthority(
                "archive deletion catalog mutated after planning or apply; replan required"
                    .to_owned(),
            ));
        }
        if let Some((_, receipt)) = previous {
            if receipt.state != DeletionClosureState::Indeterminate {
                return Ok(receipt.clone());
            }
        } else {
            // A checksum only proves the supplied fields agree. Re-derive membership and
            // holds from this catalog before accepting a new plan for destructive execution.
            let witnessed = Self::plan_closure(
                catalog,
                plan.root_digest,
                authority,
                plan.unknown_external_copies.clone(),
                plan.planned_at,
                false,
            )?;
            if witnessed != *plan {
                return Err(DeletionClosureError::StalePlanOrAuthority(
                    "deletion plan does not match the witnessed archive closure".to_owned(),
                ));
            }
        }

        let mut deleted_set = BTreeSet::new();
        let mut deleted_bytes = 0;
        let mut completed_at = completed_at.max(plan.planned_at);
        if let Some((_, receipt)) = previous {
            deleted_set.extend(receipt.deleted_digests.iter().copied());
            deleted_bytes = receipt.deleted_bytes;
            completed_at = completed_at.max(receipt.completed_at);
        }
        let indeterminate_set: BTreeSet<_> = plan
            .members
            .iter()
            .map(|member| member.digest)
            .filter(|digest| {
                remote_indeterminate_targets.contains(digest) && !deleted_set.contains(digest)
            })
            .collect();
        if let Some((_, receipt)) = previous
            && receipt
                .indeterminate_digests
                .iter()
                .copied()
                .eq(indeterminate_set.iter().copied())
        {
            return Ok(receipt.clone());
        }
        ensure_terminal_receipt_fits(catalog, plan)?;
        for member in &plan.members {
            if deleted_set.contains(&member.digest) || indeterminate_set.contains(&member.digest) {
                continue;
            }
            if let Some(node) = catalog.nodes.get_mut(&member.digest) {
                // Keep the path to every outstanding replica discoverable for a fresh
                // plan, even if the authority or an unrelated catalog row later changes.
                if !indeterminate_set.is_empty()
                    && (node.digest == plan.root_digest
                        || !node.dependencies.is_empty()
                        || !node.hidden_reference_aliases.is_empty()
                        || node.simulate_surviving_hidden_ref.is_some())
                {
                    continue;
                }
                node.reachable = false;
                deleted_set.insert(member.digest);
                // Planning proved the sum of all distinct member sizes fits u64.
                deleted_bytes += node.byte_len;
                if let Some(leaked_alias) = node.simulate_surviving_hidden_ref {
                    catalog
                        .surviving_hidden_refs
                        .entry(member.digest)
                        .or_default()
                        .insert(leaked_alias);
                }
            }
        }

        let deleted_digests: Vec<_> = deleted_set.iter().copied().collect();
        if !indeterminate_set.is_empty() {
            let receipt = seal_deletion_receipt(
                plan,
                None,
                DeletionClosureState::Indeterminate,
                deleted_digests,
                indeterminate_set.into_iter().collect(),
                Vec::new(),
                deleted_bytes,
                completed_at,
            )?;
            catalog.executions.insert(
                plan.root_digest,
                (catalog.catalog_state_digest()?, receipt.clone()),
            );
            return Ok(receipt);
        }

        // Publish canonical tombstone root only after every planned member was deleted.
        let tombstone_root_digest = compute_tombstone_root(plan, &deleted_digests, completed_at)?;
        catalog
            .tombstones
            .insert(plan.root_digest, tombstone_root_digest);

        // Independent post-tombstone unreachability scan: detect any surviving node OR hidden ref!
        let mut leaks = BTreeSet::new();
        for member in &plan.members {
            if catalog
                .nodes
                .get(&member.digest)
                .is_some_and(|n| n.reachable)
            {
                leaks.insert(member.digest);
            }
            if let Some(hidden) = catalog.surviving_hidden_refs.get(&member.digest) {
                for &alias in hidden {
                    leaks.insert(alias);
                }
            }
        }
        leaks.extend(
            catalog
                .external_references(&deleted_set)
                .map(|(parent, _)| parent),
        );
        let surviving_hidden_references: Vec<ContentDigest> = leaks.into_iter().collect();

        let final_state = if surviving_hidden_references.is_empty() {
            DeletionClosureState::UnreachabilityVerified
        } else {
            DeletionClosureState::HiddenReferenceLeakDetected
        };

        let receipt = seal_deletion_receipt(
            plan,
            Some(tombstone_root_digest),
            final_state,
            deleted_digests,
            Vec::new(),
            surviving_hidden_references,
            deleted_bytes,
            completed_at,
        )?;
        catalog.executions.insert(
            plan.root_digest,
            (catalog.catalog_state_digest()?, receipt.clone()),
        );
        Ok(receipt)
    }
}

/// Reserve room for the final FSSDCL01 proof before retiring any member. Partial proofs
/// omit the tombstone and contain disjoint subsets of the same members, so also fit.
fn ensure_terminal_receipt_fits(
    catalog: &ArchiveDeletionCatalog,
    plan: &DeletionClosurePlan,
) -> Result<(), DeletionClosureError> {
    // V1 has six tagged 32-byte digests in a terminal envelope (including the checksum),
    // two one-byte tags, seven u64 fields, a timestamp, the body version and the header.
    const DIGEST_BYTES: usize = 33;
    const TERMINAL_ENVELOPE_BYTES: usize = 12 + 4 + 6 * DIGEST_BYTES + 2 + 7 * 8 + 16;
    let disclosure_bytes: usize = plan
        .unknown_external_copies
        .iter()
        .map(|copy| 3 * 8 + copy.copy_id.len() + copy.destination_label.len() + copy.note.len())
        .sum();
    let member_proof_bytes =
        TERMINAL_ENVELOPE_BYTES + plan.members.len() * DIGEST_BYTES + disclosure_bytes;

    let mut aliases = BTreeSet::new();
    for member in &plan.members {
        if let Some(survivors) = catalog.surviving_hidden_refs.get(&member.digest) {
            aliases.extend(survivors.iter().copied());
        }
        if let Some(alias) = catalog
            .get(&member.digest)
            .filter(|node| node.reachable)
            .and_then(|node| node.simulate_surviving_hidden_ref)
        {
            aliases.insert(alias);
        }
        if aliases.len() > MAX_DELETION_CLOSURE_NODES {
            return Err(DeletionClosureError::BoundsExceeded {
                observed: aliases.len(),
                maximum: MAX_DELETION_CLOSURE_NODES,
            });
        }
        let required = member_proof_bytes + aliases.len() * DIGEST_BYTES;
        if required > MAX_DELETION_RECEIPT_WIRE_BYTES {
            return Err(DeletionClosureError::BoundsExceeded {
                observed: required,
                maximum: MAX_DELETION_RECEIPT_WIRE_BYTES,
            });
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn seal_deletion_receipt(
    plan: &DeletionClosurePlan,
    tombstone_root_digest: Option<ContentDigest>,
    state: DeletionClosureState,
    deleted_digests: Vec<ContentDigest>,
    indeterminate_digests: Vec<ContentDigest>,
    surviving_hidden_references: Vec<ContentDigest>,
    deleted_bytes: u64,
    completed_at: TimestampNs,
) -> Result<DeletionClosureReceipt, DeletionClosureError> {
    let mut receipt = DeletionClosureReceipt {
        format_version: DELETION_RECEIPT_VERSION,
        plan_digest: plan.plan_digest,
        root_digest: plan.root_digest,
        tombstone_root_digest,
        contract_basis_digest: plan.contract_basis_digest,
        authority_generation: plan.authority_generation,
        privacy_epoch: plan.privacy_epoch,
        owner_approval_digest: plan.owner_approval_digest,
        state,
        deleted_digests,
        indeterminate_digests,
        surviving_hidden_references,
        unknown_external_copies: plan.unknown_external_copies.clone(),
        deleted_bytes,
        completed_at,
        receipt_digest: ContentDigest::sha256(b"unsealed-deletion-receipt"),
    };
    receipt.receipt_digest = receipt.compute_digest()?;
    Ok(receipt)
}

fn compute_tombstone_root(
    plan: &DeletionClosurePlan,
    deleted_digests: &[ContentDigest],
    published_at: TimestampNs,
) -> Result<ContentDigest, DeletionClosureError> {
    let mut enc = CanonicalEncoder::new();
    enc.text(ATP_DELETION_TOMBSTONE_ROOT_DOMAIN);
    enc.digest(plan.plan_digest);
    enc.digest(plan.root_digest);
    enc.digest(plan.owner_approval_digest);
    enc.u64(deleted_digests.len() as u64);
    for d in deleted_digests {
        enc.digest(*d);
    }
    published_at.encode_canonical(&mut enc);
    let bytes = enc
        .finish_checked()
        .map_err(|e| DeletionClosureError::Encoding(e.to_string()))?;
    Ok(ContentDigest::sha256(&bytes))
}

fn decode_digest_vec(
    dec: &mut CanonicalDecoder<'_>,
    max_len: usize,
) -> Result<Vec<ContentDigest>, DeletionClosureError> {
    let count = usize::try_from(
        dec.u64()
            .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?,
    )
    .map_err(|_| DeletionClosureError::BoundsExceeded {
        observed: usize::MAX,
        maximum: max_len,
    })?;
    if count > max_len || count.saturating_mul(32) > dec.remaining() {
        return Err(DeletionClosureError::BoundsExceeded {
            observed: count,
            maximum: max_len,
        });
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(
            dec.digest()
                .map_err(|e| DeletionClosureError::MalformedWire(e.to_string()))?,
        );
    }
    Ok(out)
}

fn validate_label(value: &str, max_len: usize, label: &str) -> Result<(), DeletionClosureError> {
    if value.is_empty() || value.len() > max_len {
        return Err(DeletionClosureError::InvalidInput(format!(
            "{label} length {} outside 1..={max_len}",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(DeletionClosureError::InvalidInput(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}
