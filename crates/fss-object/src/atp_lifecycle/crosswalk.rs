#![forbid(unsafe_code)]
//! Layer-qualified ATP lifecycle states and exhaustive legacy document crosswalk.
//!
//! Mirrors `architecture/atp_lifecycles.json` and `registries/ATP_LIFECYCLES.md`.
//! Three distinct layers are preserved without collapse:
//! 1. [`SemanticTransferState`] (`atp.semantic.*`) — `docs/ATP_AND_DISTRIBUTED_EVIDENCE.md`;
//! 2. [`ArchivePublicationState`] (`atp.archive.*`) + [`ArchiveObjectState`] (`atp.archive_object.*`)
//!    — `docs/ATP_ARCHIVE_AND_REPLICATION.md` & `docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md`;
//! 3. [`PathState`] (`atp.path.*`) — `docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md`.
//!
//! No transport may invent unlisted aliases or silently discard legacy spellings.

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContractError,
};

use super::AtpLifecycleError;

/// Non-collapsible terminology registered in `architecture/atp_lifecycles.json`.
pub const NON_COLLAPSE_TERMS: [&str; 11] = [
    "offered",
    "received",
    "verified",
    "graph_closed",
    "durable",
    "committed",
    "published",
    "replicated",
    "retrievable",
    "protected",
    "complete",
];

/// Distinct ATP lifecycle layers.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LifecycleLayer {
    /// End-to-end semantic transfer protocol (`atp.semantic.*`).
    SemanticTransfer,
    /// Archive publication lifecycle (`atp.archive.*`).
    ArchivePublication,
    /// Per-object archive custody ladder (`atp.archive_object.*`).
    ArchiveObjectCustody,
    /// Multipath transport path lifecycle (`atp.path.*`).
    Path,
}

impl LifecycleLayer {
    /// Stable machine identifier matching `architecture/atp_lifecycles.json`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SemanticTransfer => "semantic_transfer",
            Self::ArchivePublication => "archive_publication",
            Self::ArchiveObjectCustody => "archive_object_custody",
            Self::Path => "path",
        }
    }
}

impl CanonicalEncode for LifecycleLayer {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        let tag: u8 = match self {
            Self::SemanticTransfer => 1,
            Self::ArchivePublication => 2,
            Self::ArchiveObjectCustody => 3,
            Self::Path => 4,
        };
        encoder.u8(tag);
    }
}

impl CanonicalDecode for LifecycleLayer {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::SemanticTransfer),
            2 => Ok(Self::ArchivePublication),
            3 => Ok(Self::ArchiveObjectCustody),
            4 => Ok(Self::Path),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Layer 1: Normative semantic transfer lifecycle (`atp.semantic.*`).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SemanticTransferState {
    /// Initial transfer proposal before reservation.
    Proposed,
    /// Quota, journal space, authority, and fence reserved.
    Reserved,
    /// Sender offered bytes/chunks; distinct from received and verified.
    Offered,
    /// Active chunk/symbol reception in progress.
    Receiving,
    /// Every declared child verified against its canonical digest.
    ChildrenVerified,
    /// Complete manifest dependency closure verified.
    GraphClosed,
    /// Destination durability contract satisfied across required failure domains.
    DurabilitySatisfied,
    /// Atomic root pointer committed under active fence.
    RootCommitted,
    /// Domain-separated canonical transfer receipt sealed after commit.
    ReceiptSealed,
    /// Policy, capability, or manifest refusal before receipt.
    Rejected,
    /// Safely stopped after path drain and child classification; no root committed.
    Aborted,
    /// Corrupt or policy-violating bytes held for diagnosis, never published.
    Quarantined,
    /// Remote semantic commit may have occurred; owns a durable reconciliation obligation.
    Indeterminate,
    /// Completed transfer superseded by a newer generation.
    Superseded,
}

impl SemanticTransferState {
    /// Complete ordered list of all semantic transfer states.
    pub const ALL: [Self; 14] = [
        Self::Proposed,
        Self::Reserved,
        Self::Offered,
        Self::Receiving,
        Self::ChildrenVerified,
        Self::GraphClosed,
        Self::DurabilitySatisfied,
        Self::RootCommitted,
        Self::ReceiptSealed,
        Self::Rejected,
        Self::Aborted,
        Self::Quarantined,
        Self::Indeterminate,
        Self::Superseded,
    ];

    /// Layer-qualified canonical state key.
    #[must_use]
    pub const fn canonical_id(self) -> &'static str {
        match self {
            Self::Proposed => "atp.semantic.proposed",
            Self::Reserved => "atp.semantic.reserved",
            Self::Offered => "atp.semantic.offered",
            Self::Receiving => "atp.semantic.receiving",
            Self::ChildrenVerified => "atp.semantic.children_verified",
            Self::GraphClosed => "atp.semantic.graph_closed",
            Self::DurabilitySatisfied => "atp.semantic.durability_satisfied",
            Self::RootCommitted => "atp.semantic.root_committed",
            Self::ReceiptSealed => "atp.semantic.receipt_sealed",
            Self::Rejected => "atp.semantic.rejected",
            Self::Aborted => "atp.semantic.aborted",
            Self::Quarantined => "atp.semantic.quarantined",
            Self::Indeterminate => "atp.semantic.indeterminate",
            Self::Superseded => "atp.semantic.superseded",
        }
    }

    /// Document spelling for this state.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Proposed => "Proposed",
            Self::Reserved => "Reserved",
            Self::Offered => "Offered",
            Self::Receiving => "Receiving",
            Self::ChildrenVerified => "ChildrenVerified",
            Self::GraphClosed => "GraphClosed",
            Self::DurabilitySatisfied => "DurabilitySatisfied",
            Self::RootCommitted => "RootCommitted",
            Self::ReceiptSealed => "ReceiptSealed",
            Self::Rejected => "Rejected",
            Self::Aborted => "Aborted",
            Self::Quarantined => "Quarantined",
            Self::Indeterminate => "Indeterminate",
            Self::Superseded => "Superseded",
        }
    }

    /// True for terminal semantic outcomes (including `ReceiptSealed`, which may only supersede).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::ReceiptSealed
                | Self::Rejected
                | Self::Aborted
                | Self::Quarantined
                | Self::Indeterminate
                | Self::Superseded
        )
    }

    /// Exact legal transition relation matching `architecture/atp_lifecycles.json`.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Proposed,
                Self::Reserved | Self::Rejected | Self::Aborted
            ) | (
                Self::Reserved,
                Self::Offered | Self::Rejected | Self::Aborted
            ) | (
                Self::Offered,
                Self::Receiving | Self::Aborted | Self::Quarantined
            ) | (
                Self::Receiving,
                Self::ChildrenVerified | Self::Aborted | Self::Quarantined
            ) | (
                Self::ChildrenVerified,
                Self::GraphClosed | Self::Aborted | Self::Quarantined
            ) | (
                Self::GraphClosed,
                Self::DurabilitySatisfied | Self::Aborted | Self::Quarantined
            ) | (
                Self::DurabilitySatisfied,
                Self::RootCommitted | Self::Aborted | Self::Quarantined | Self::Indeterminate
            ) | (
                Self::RootCommitted,
                Self::ReceiptSealed | Self::Indeterminate
            ) | (Self::ReceiptSealed, Self::Superseded)
        )
    }
}

impl CanonicalEncode for SemanticTransferState {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        let tag: u8 = match self {
            Self::Proposed => 1,
            Self::Reserved => 2,
            Self::Offered => 3,
            Self::Receiving => 4,
            Self::ChildrenVerified => 5,
            Self::GraphClosed => 6,
            Self::DurabilitySatisfied => 7,
            Self::RootCommitted => 8,
            Self::ReceiptSealed => 9,
            Self::Rejected => 10,
            Self::Aborted => 11,
            Self::Quarantined => 12,
            Self::Indeterminate => 13,
            Self::Superseded => 14,
        };
        encoder.u8(tag);
    }
}

impl CanonicalDecode for SemanticTransferState {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Proposed),
            2 => Ok(Self::Reserved),
            3 => Ok(Self::Offered),
            4 => Ok(Self::Receiving),
            5 => Ok(Self::ChildrenVerified),
            6 => Ok(Self::GraphClosed),
            7 => Ok(Self::DurabilitySatisfied),
            8 => Ok(Self::RootCommitted),
            9 => Ok(Self::ReceiptSealed),
            10 => Ok(Self::Rejected),
            11 => Ok(Self::Aborted),
            12 => Ok(Self::Quarantined),
            13 => Ok(Self::Indeterminate),
            14 => Ok(Self::Superseded),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Layer 2: Reconciled archive publication lifecycle (`atp.archive.*`).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ArchivePublicationState {
    /// Initial archive publication plan.
    Planned,
    /// Destination generation and operation budget reserved.
    Reserved,
    /// Manifest schema, digest, limits, and policy verified.
    ManifestVerified,
    /// Children and symbols scheduled and fetching.
    Fetching,
    /// Unpublished bytes staged locally/remotely awaiting digest verification.
    Staged,
    /// Every staged object verified against its canonical digest.
    ObjectVerified,
    /// Complete manifest graph closure verified.
    GraphClosed,
    /// Privacy transforms, policy epoch, root generation, and authorization verified before exposure.
    ExposureReady,
    /// Root marker published last under active fence.
    RootPublished,
    /// Required independent failure-domain replicas verified.
    ReplicaQualified,
    /// Witnessed proof-of-retrievability sample passed.
    RetrievabilityVerified,
    /// Archive publication complete (strictly requires `RetrievabilityVerified`).
    Complete,
    /// Periodic post-completion integrity scrub verified.
    Scrubbed,
    /// Graph-complete deletion/retirement terminal state.
    Retired,
    /// Corrupt or unauthorized bytes quarantined for diagnosis.
    Quarantined,
    /// Cleanly cancelled after path drain and staged-child classification.
    Cancelled,
    /// Terminal non-indeterminate archive failure.
    Failed,
    /// Remote publication commit unresolved; owns a durable reconciliation obligation.
    Indeterminate,
}

impl ArchivePublicationState {
    /// Complete ordered list of all archive publication states.
    pub const ALL: [Self; 18] = [
        Self::Planned,
        Self::Reserved,
        Self::ManifestVerified,
        Self::Fetching,
        Self::Staged,
        Self::ObjectVerified,
        Self::GraphClosed,
        Self::ExposureReady,
        Self::RootPublished,
        Self::ReplicaQualified,
        Self::RetrievabilityVerified,
        Self::Complete,
        Self::Scrubbed,
        Self::Retired,
        Self::Quarantined,
        Self::Cancelled,
        Self::Failed,
        Self::Indeterminate,
    ];

    /// Layer-qualified canonical state key.
    #[must_use]
    pub const fn canonical_id(self) -> &'static str {
        match self {
            Self::Planned => "atp.archive.planned",
            Self::Reserved => "atp.archive.reserved",
            Self::ManifestVerified => "atp.archive.manifest_verified",
            Self::Fetching => "atp.archive.fetching",
            Self::Staged => "atp.archive.staged",
            Self::ObjectVerified => "atp.archive.object_verified",
            Self::GraphClosed => "atp.archive.graph_closed",
            Self::ExposureReady => "atp.archive.exposure_ready",
            Self::RootPublished => "atp.archive.root_published",
            Self::ReplicaQualified => "atp.archive.replica_qualified",
            Self::RetrievabilityVerified => "atp.archive.retrievability_verified",
            Self::Complete => "atp.archive.complete",
            Self::Scrubbed => "atp.archive.scrubbed",
            Self::Retired => "atp.archive.retired",
            Self::Quarantined => "atp.archive.quarantined",
            Self::Cancelled => "atp.archive.cancelled",
            Self::Failed => "atp.archive.failed",
            Self::Indeterminate => "atp.archive.indeterminate",
        }
    }

    /// Schema `state` enum spelling matching `schemas/transfer_receipt.v1.json`.
    #[must_use]
    pub const fn receipt_state_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Reserved => "reserved",
            Self::ManifestVerified => "manifest_verified",
            Self::Fetching => "fetching",
            Self::Staged => "staged",
            Self::ObjectVerified => "object_verified",
            Self::GraphClosed => "graph_closed",
            Self::ExposureReady => "exposure_ready",
            Self::RootPublished => "root_published",
            Self::ReplicaQualified => "replica_qualified",
            Self::RetrievabilityVerified => "retrievability_verified",
            Self::Complete => "complete",
            Self::Scrubbed => "scrubbed",
            Self::Retired => "retired",
            Self::Quarantined => "quarantined",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::Indeterminate => "indeterminate",
        }
    }

    /// Document spelling for this state.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Planned => "Planned",
            Self::Reserved => "Reserved",
            Self::ManifestVerified => "ManifestVerified",
            Self::Fetching => "Fetching",
            Self::Staged => "Staged",
            Self::ObjectVerified => "ObjectVerified",
            Self::GraphClosed => "GraphClosed",
            Self::ExposureReady => "ExposureReady",
            Self::RootPublished => "RootPublished",
            Self::ReplicaQualified => "ReplicaQualified",
            Self::RetrievabilityVerified => "RetrievabilityVerified",
            Self::Complete => "Complete",
            Self::Scrubbed => "Scrubbed",
            Self::Retired => "Retired",
            Self::Quarantined => "Quarantined",
            Self::Cancelled => "Cancelled",
            Self::Failed => "Failed",
            Self::Indeterminate => "Indeterminate",
        }
    }

    /// True for terminal archive outcomes.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Retired
                | Self::Quarantined
                | Self::Cancelled
                | Self::Failed
                | Self::Indeterminate
        )
    }

    /// True once root publication has durably occurred.
    #[must_use]
    pub const fn has_published_root(self) -> bool {
        matches!(
            self,
            Self::RootPublished
                | Self::ReplicaQualified
                | Self::RetrievabilityVerified
                | Self::Complete
                | Self::Scrubbed
                | Self::Retired
        )
    }

    /// Exact legal transition relation matching `architecture/atp_lifecycles.json`.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Planned,
                Self::Reserved | Self::Cancelled | Self::Failed
            ) | (
                Self::Reserved,
                Self::ManifestVerified | Self::Cancelled | Self::Failed
            ) | (
                Self::ManifestVerified,
                Self::Fetching | Self::Cancelled | Self::Failed | Self::Quarantined
            ) | (
                Self::Fetching,
                Self::Staged | Self::Cancelled | Self::Failed | Self::Quarantined
            ) | (
                Self::Staged,
                Self::ObjectVerified | Self::Cancelled | Self::Failed | Self::Quarantined
            ) | (
                Self::ObjectVerified,
                Self::GraphClosed | Self::Cancelled | Self::Failed | Self::Quarantined
            ) | (
                Self::GraphClosed,
                Self::ExposureReady | Self::Cancelled | Self::Failed | Self::Quarantined
            ) | (
                Self::ExposureReady,
                Self::RootPublished
                    | Self::Cancelled
                    | Self::Failed
                    | Self::Quarantined
                    | Self::Indeterminate
            ) | (
                Self::RootPublished,
                Self::ReplicaQualified | Self::Failed | Self::Indeterminate
            ) | (
                Self::ReplicaQualified,
                Self::RetrievabilityVerified | Self::Failed | Self::Indeterminate
            ) | (Self::RetrievabilityVerified, Self::Complete | Self::Failed)
                | (Self::Complete, Self::Scrubbed | Self::Retired)
                | (
                    Self::Scrubbed,
                    Self::Scrubbed | Self::Retired | Self::Quarantined
                )
        )
    }
}

impl CanonicalEncode for ArchivePublicationState {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        let tag: u8 = match self {
            Self::Planned => 1,
            Self::Reserved => 2,
            Self::ManifestVerified => 3,
            Self::Fetching => 4,
            Self::Staged => 5,
            Self::ObjectVerified => 6,
            Self::GraphClosed => 7,
            Self::ExposureReady => 8,
            Self::RootPublished => 9,
            Self::ReplicaQualified => 10,
            Self::RetrievabilityVerified => 11,
            Self::Complete => 12,
            Self::Scrubbed => 13,
            Self::Retired => 14,
            Self::Quarantined => 15,
            Self::Cancelled => 16,
            Self::Failed => 17,
            Self::Indeterminate => 18,
        };
        encoder.u8(tag);
    }
}

impl CanonicalDecode for ArchivePublicationState {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Planned),
            2 => Ok(Self::Reserved),
            3 => Ok(Self::ManifestVerified),
            4 => Ok(Self::Fetching),
            5 => Ok(Self::Staged),
            6 => Ok(Self::ObjectVerified),
            7 => Ok(Self::GraphClosed),
            8 => Ok(Self::ExposureReady),
            9 => Ok(Self::RootPublished),
            10 => Ok(Self::ReplicaQualified),
            11 => Ok(Self::RetrievabilityVerified),
            12 => Ok(Self::Complete),
            13 => Ok(Self::Scrubbed),
            14 => Ok(Self::Retired),
            15 => Ok(Self::Quarantined),
            16 => Ok(Self::Cancelled),
            17 => Ok(Self::Failed),
            18 => Ok(Self::Indeterminate),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Layer 2b: Per-object archive custody states (`docs/ATP_ARCHIVE_AND_REPLICATION.md §8`).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ArchiveObjectState {
    /// Bytes staged locally under content identity.
    LocalStaged,
    /// Bytes durably committed to local spool.
    LocalDurable,
    /// Bytes staged remotely under unpublished generation.
    RemoteStaged,
    /// Remote child digests verified independently.
    RemoteChildrenVerified,
    /// Remote root marker published last.
    RemoteRootPublished,
    /// Required independent failure-domain replication policy satisfied.
    ReplicationPolicySatisfied,
    /// Witnessed retrievability sample passed.
    RetrievabilitySamplePassed,
}

impl ArchiveObjectState {
    /// Complete ordered progression.
    pub const ALL: [Self; 7] = [
        Self::LocalStaged,
        Self::LocalDurable,
        Self::RemoteStaged,
        Self::RemoteChildrenVerified,
        Self::RemoteRootPublished,
        Self::ReplicationPolicySatisfied,
        Self::RetrievabilitySamplePassed,
    ];

    /// Layer-qualified canonical state key.
    #[must_use]
    pub const fn canonical_id(self) -> &'static str {
        match self {
            Self::LocalStaged => "atp.archive_object.local_staged",
            Self::LocalDurable => "atp.archive_object.local_durable",
            Self::RemoteStaged => "atp.archive_object.remote_staged",
            Self::RemoteChildrenVerified => "atp.archive_object.remote_children_verified",
            Self::RemoteRootPublished => "atp.archive_object.remote_root_published",
            Self::ReplicationPolicySatisfied => "atp.archive_object.replication_policy_satisfied",
            Self::RetrievabilitySamplePassed => "atp.archive_object.retrievability_sample_passed",
        }
    }

    /// Strict step-by-step monotone forward progression (never skips, never rewinds).
    #[must_use]
    pub const fn can_advance_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::LocalStaged, Self::LocalDurable)
                | (Self::LocalDurable, Self::RemoteStaged)
                | (Self::RemoteStaged, Self::RemoteChildrenVerified)
                | (Self::RemoteChildrenVerified, Self::RemoteRootPublished)
                | (Self::RemoteRootPublished, Self::ReplicationPolicySatisfied)
                | (
                    Self::ReplicationPolicySatisfied,
                    Self::RetrievabilitySamplePassed
                )
        )
    }
}

impl CanonicalEncode for ArchiveObjectState {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        let tag: u8 = match self {
            Self::LocalStaged => 1,
            Self::LocalDurable => 2,
            Self::RemoteStaged => 3,
            Self::RemoteChildrenVerified => 4,
            Self::RemoteRootPublished => 5,
            Self::ReplicationPolicySatisfied => 6,
            Self::RetrievabilitySamplePassed => 7,
        };
        encoder.u8(tag);
    }
}

impl CanonicalDecode for ArchiveObjectState {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::LocalStaged),
            2 => Ok(Self::LocalDurable),
            3 => Ok(Self::RemoteStaged),
            4 => Ok(Self::RemoteChildrenVerified),
            5 => Ok(Self::RemoteRootPublished),
            6 => Ok(Self::ReplicationPolicySatisfied),
            7 => Ok(Self::RetrievabilitySamplePassed),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Layer 3: Multipath transport path lifecycle (`atp.path.*`).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PathState {
    /// Newly discovered transport path.
    Discover,
    /// Policy-admitted candidate path awaiting probe.
    Candidate,
    /// Path currently under health/latency probe.
    Probing,
    /// Authorized active transfer path permitted to deliver data.
    Active,
    /// Degraded or faulted path; may not expose data.
    Suspect,
    /// Draining all in-flight operations, buffers, and handles prior to close.
    Draining,
    /// Terminal closed path with zero remaining live work.
    Closed,
}

impl PathState {
    /// Complete ordered progression.
    pub const ALL: [Self; 7] = [
        Self::Discover,
        Self::Candidate,
        Self::Probing,
        Self::Active,
        Self::Suspect,
        Self::Draining,
        Self::Closed,
    ];

    /// Layer-qualified canonical state key.
    #[must_use]
    pub const fn canonical_id(self) -> &'static str {
        match self {
            Self::Discover => "atp.path.discover",
            Self::Candidate => "atp.path.candidate",
            Self::Probing => "atp.path.probing",
            Self::Active => "atp.path.active",
            Self::Suspect => "atp.path.suspect",
            Self::Draining => "atp.path.draining",
            Self::Closed => "atp.path.closed",
        }
    }

    /// Document spelling.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Discover => "Discover",
            Self::Candidate => "Candidate",
            Self::Probing => "Probing",
            Self::Active => "Active",
            Self::Suspect => "Suspect",
            Self::Draining => "Draining",
            Self::Closed => "Closed",
        }
    }

    /// Only an `Active` path may expose or deliver verified bytes.
    #[must_use]
    pub const fn can_expose_data(self) -> bool {
        matches!(self, Self::Active)
    }

    /// True only for `Closed`.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Exact legal transition relation matching `architecture/atp_lifecycles.json`.
    /// Note: closing from `Draining` additionally requires `live_work == 0` in the path reducer.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Discover, Self::Candidate | Self::Draining)
                | (Self::Candidate, Self::Probing | Self::Draining)
                | (Self::Probing, Self::Active | Self::Suspect | Self::Draining)
                | (Self::Active, Self::Suspect | Self::Draining)
                | (Self::Suspect, Self::Probing | Self::Draining)
                | (Self::Draining, Self::Closed)
        )
    }
}

impl CanonicalEncode for PathState {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        let tag: u8 = match self {
            Self::Discover => 1,
            Self::Candidate => 2,
            Self::Probing => 3,
            Self::Active => 4,
            Self::Suspect => 5,
            Self::Draining => 6,
            Self::Closed => 7,
        };
        encoder.u8(tag);
    }
}

impl CanonicalDecode for PathState {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        match decoder.u8()? {
            1 => Ok(Self::Discover),
            2 => Ok(Self::Candidate),
            3 => Ok(Self::Probing),
            4 => Ok(Self::Active),
            5 => Ok(Self::Suspect),
            6 => Ok(Self::Draining),
            7 => Ok(Self::Closed),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Unified layer-qualified canonical state preserving strict layer separation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CanonicalLifecycleState {
    /// Semantic transfer layer state (`atp.semantic.*`).
    Semantic(SemanticTransferState),
    /// Archive publication layer state (`atp.archive.*`).
    Archive(ArchivePublicationState),
    /// Archive object custody layer state (`atp.archive_object.*`).
    ArchiveObject(ArchiveObjectState),
    /// Multipath transport path layer state (`atp.path.*`).
    Path(PathState),
}

impl CanonicalLifecycleState {
    /// Owning lifecycle layer.
    #[must_use]
    pub const fn layer(self) -> LifecycleLayer {
        match self {
            Self::Semantic(_) => LifecycleLayer::SemanticTransfer,
            Self::Archive(_) => LifecycleLayer::ArchivePublication,
            Self::ArchiveObject(_) => LifecycleLayer::ArchiveObjectCustody,
            Self::Path(_) => LifecycleLayer::Path,
        }
    }

    /// Layer-qualified canonical state key (`atp.<layer>.<state>`).
    #[must_use]
    pub const fn canonical_id(self) -> &'static str {
        match self {
            Self::Semantic(s) => s.canonical_id(),
            Self::Archive(s) => s.canonical_id(),
            Self::ArchiveObject(s) => s.canonical_id(),
            Self::Path(s) => s.canonical_id(),
        }
    }
}

/// Classification of how a document spelling resolves in the crosswalk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyMappingKind {
    /// The spelling is itself a distinct registered canonical state.
    DistinctCanonical,
    /// The legacy document spelling maps deterministically to a canonical state in the same layer.
    MappedAlias,
    /// The spelling originated in a mixed prose diagram and is rehomed to its owning layer.
    LayerRehomed,
}

impl LegacyMappingKind {
    /// Stable spelling matching `architecture/atp_lifecycles.json`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DistinctCanonical => "distinct_canonical",
            Self::MappedAlias => "mapped_alias",
            Self::LayerRehomed => "layer_rehomed",
        }
    }
}

/// Result of resolving a layer-qualified or legacy document state spelling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrosswalkResolution {
    /// Resolved layer-qualified canonical state.
    pub canonical: CanonicalLifecycleState,
    /// Whether the input was distinct canonical, an alias, or layer-rehomed.
    pub mapping: LegacyMappingKind,
    /// Normative document owning the resolved spelling.
    pub source_document: &'static str,
}

/// Resolves a canonical layer-qualified state key or a registered legacy document spelling.
///
/// Fails closed with [`AtpLifecycleError::AmbiguousBareSpelling`] when a bare spelling shared
/// across layers (`Reserved`, `Receiving`, `GraphClosed`, `Quarantined`, `Indeterminate`) is
/// passed without `layer_hint`, and fails closed with [`AtpLifecycleError::UnknownStateSpelling`]
/// on any unlisted alias so no transport can invent ad-hoc state names.
pub fn resolve_state_spelling(
    spelling: &str,
    layer_hint: Option<LifecycleLayer>,
) -> Result<CrosswalkResolution, AtpLifecycleError> {
    if let Some(canonical) = parse_canonical_id(spelling) {
        if let Some(expected) = layer_hint
            && canonical.layer() != expected
        {
            return Err(AtpLifecycleError::LayerMismatch {
                spelling: spelling.to_owned(),
                expected,
                actual: canonical.layer(),
            });
        }
        return Ok(CrosswalkResolution {
            canonical,
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "architecture/atp_lifecycles.json",
        });
    }

    // Ambiguous bare spellings shared across semantic_transfer and archive_publication.
    match spelling {
        "Reserved" | "reserved" => {
            return match layer_hint {
                Some(LifecycleLayer::SemanticTransfer) => Ok(CrosswalkResolution {
                    canonical: CanonicalLifecycleState::Semantic(SemanticTransferState::Reserved),
                    mapping: LegacyMappingKind::DistinctCanonical,
                    source_document: "docs/ATP_AND_DISTRIBUTED_EVIDENCE.md",
                }),
                Some(LifecycleLayer::ArchivePublication) => Ok(CrosswalkResolution {
                    canonical: CanonicalLifecycleState::Archive(ArchivePublicationState::Reserved),
                    mapping: LegacyMappingKind::DistinctCanonical,
                    source_document: "docs/ATP_ARCHIVE_AND_REPLICATION.md",
                }),
                _ => Err(AtpLifecycleError::AmbiguousBareSpelling {
                    spelling: spelling.to_owned(),
                }),
            };
        }
        "Receiving" => {
            return match layer_hint {
                Some(LifecycleLayer::SemanticTransfer) => Ok(CrosswalkResolution {
                    canonical: CanonicalLifecycleState::Semantic(SemanticTransferState::Receiving),
                    mapping: LegacyMappingKind::DistinctCanonical,
                    source_document: "docs/ATP_AND_DISTRIBUTED_EVIDENCE.md",
                }),
                Some(LifecycleLayer::ArchivePublication) => Ok(CrosswalkResolution {
                    canonical: CanonicalLifecycleState::Archive(ArchivePublicationState::Fetching),
                    mapping: LegacyMappingKind::MappedAlias,
                    source_document: "docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md",
                }),
                _ => Err(AtpLifecycleError::AmbiguousBareSpelling {
                    spelling: spelling.to_owned(),
                }),
            };
        }
        "GraphClosed" | "graph_closed" => {
            return match layer_hint {
                Some(LifecycleLayer::SemanticTransfer) => Ok(CrosswalkResolution {
                    canonical: CanonicalLifecycleState::Semantic(
                        SemanticTransferState::GraphClosed,
                    ),
                    mapping: LegacyMappingKind::DistinctCanonical,
                    source_document: "docs/ATP_AND_DISTRIBUTED_EVIDENCE.md",
                }),
                Some(LifecycleLayer::ArchivePublication) => Ok(CrosswalkResolution {
                    canonical: CanonicalLifecycleState::Archive(
                        ArchivePublicationState::GraphClosed,
                    ),
                    mapping: LegacyMappingKind::DistinctCanonical,
                    source_document: "docs/ATP_ARCHIVE_AND_REPLICATION.md",
                }),
                _ => Err(AtpLifecycleError::AmbiguousBareSpelling {
                    spelling: spelling.to_owned(),
                }),
            };
        }
        "Quarantined" | "quarantined" => {
            return match layer_hint {
                Some(LifecycleLayer::SemanticTransfer) => Ok(CrosswalkResolution {
                    canonical: CanonicalLifecycleState::Semantic(
                        SemanticTransferState::Quarantined,
                    ),
                    mapping: LegacyMappingKind::DistinctCanonical,
                    source_document: "docs/ATP_AND_DISTRIBUTED_EVIDENCE.md",
                }),
                Some(LifecycleLayer::ArchivePublication) => Ok(CrosswalkResolution {
                    canonical: CanonicalLifecycleState::Archive(
                        ArchivePublicationState::Quarantined,
                    ),
                    mapping: LegacyMappingKind::DistinctCanonical,
                    source_document: "docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md",
                }),
                _ => Err(AtpLifecycleError::AmbiguousBareSpelling {
                    spelling: spelling.to_owned(),
                }),
            };
        }
        "Indeterminate" | "indeterminate" => {
            return match layer_hint {
                Some(LifecycleLayer::SemanticTransfer) => Ok(CrosswalkResolution {
                    canonical: CanonicalLifecycleState::Semantic(
                        SemanticTransferState::Indeterminate,
                    ),
                    mapping: LegacyMappingKind::DistinctCanonical,
                    source_document: "docs/ATP_AND_DISTRIBUTED_EVIDENCE.md",
                }),
                Some(LifecycleLayer::ArchivePublication) => Ok(CrosswalkResolution {
                    canonical: CanonicalLifecycleState::Archive(
                        ArchivePublicationState::Indeterminate,
                    ),
                    mapping: LegacyMappingKind::DistinctCanonical,
                    source_document: "docs/ATP_ARCHIVE_AND_REPLICATION.md",
                }),
                _ => Err(AtpLifecycleError::AmbiguousBareSpelling {
                    spelling: spelling.to_owned(),
                }),
            };
        }
        _ => {}
    }

    let resolved = match spelling {
        // Archive publication distinct canonical and legacy crosswalk entries.
        "Planned" | "planned" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Archive(ArchivePublicationState::Planned),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_ARCHIVE_AND_REPLICATION.md",
        },
        "ManifestVerified" | "manifest_verified" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Archive(ArchivePublicationState::ManifestVerified),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_ARCHIVE_AND_REPLICATION.md",
        },
        "ManifestValidated" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Archive(ArchivePublicationState::ManifestVerified),
            mapping: LegacyMappingKind::MappedAlias,
            source_document: "docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md",
        },
        "PathsDiscovered" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Path(PathState::Candidate),
            mapping: LegacyMappingKind::LayerRehomed,
            source_document: "docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md",
        },
        "ChildrenScheduled" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Archive(ArchivePublicationState::Fetching),
            mapping: LegacyMappingKind::MappedAlias,
            source_document: "docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md",
        },
        "Fetching" | "fetching" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Archive(ArchivePublicationState::Fetching),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_ARCHIVE_AND_REPLICATION.md",
        },
        "Staged" | "staged" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Archive(ArchivePublicationState::Staged),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_ARCHIVE_AND_REPLICATION.md",
        },
        "ChildVerified" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Archive(ArchivePublicationState::ObjectVerified),
            mapping: LegacyMappingKind::MappedAlias,
            source_document: "docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md",
        },
        "ObjectVerified" | "object_verified" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Archive(ArchivePublicationState::ObjectVerified),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_ARCHIVE_AND_REPLICATION.md",
        },
        "GraphClosureVerified" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Archive(ArchivePublicationState::GraphClosed),
            mapping: LegacyMappingKind::MappedAlias,
            source_document: "docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md",
        },
        "ExposureReady" | "exposure_ready" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Archive(ArchivePublicationState::ExposureReady),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md",
        },
        "RootPublished" | "root_published" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Archive(ArchivePublicationState::RootPublished),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_ARCHIVE_AND_REPLICATION.md",
        },
        "ReplicaQualified" | "replica_qualified" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Archive(ArchivePublicationState::ReplicaQualified),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md",
        },
        "RetrievabilityVerified" | "retrievability_verified" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Archive(
                ArchivePublicationState::RetrievabilityVerified,
            ),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_ARCHIVE_AND_REPLICATION.md",
        },
        "Complete" | "complete" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Archive(ArchivePublicationState::Complete),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_ARCHIVE_AND_REPLICATION.md",
        },
        "Scrubbed" | "scrubbed" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Archive(ArchivePublicationState::Scrubbed),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md",
        },
        "Retired" | "retired" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Archive(ArchivePublicationState::Retired),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md",
        },
        "Cancelled" | "cancelled" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Archive(ArchivePublicationState::Cancelled),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_ARCHIVE_AND_REPLICATION.md",
        },
        "Failed" | "failed" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Archive(ArchivePublicationState::Failed),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_ARCHIVE_AND_REPLICATION.md",
        },

        // Semantic transfer unambiguous spellings.
        "Proposed" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Semantic(SemanticTransferState::Proposed),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_AND_DISTRIBUTED_EVIDENCE.md",
        },
        "Offered" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Semantic(SemanticTransferState::Offered),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_AND_DISTRIBUTED_EVIDENCE.md",
        },
        "ChildrenVerified" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Semantic(SemanticTransferState::ChildrenVerified),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_AND_DISTRIBUTED_EVIDENCE.md",
        },
        "DurabilitySatisfied" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Semantic(
                SemanticTransferState::DurabilitySatisfied,
            ),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_AND_DISTRIBUTED_EVIDENCE.md",
        },
        "RootCommitted" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Semantic(SemanticTransferState::RootCommitted),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_AND_DISTRIBUTED_EVIDENCE.md",
        },
        "ReceiptSealed" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Semantic(SemanticTransferState::ReceiptSealed),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_AND_DISTRIBUTED_EVIDENCE.md",
        },
        "Rejected" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Semantic(SemanticTransferState::Rejected),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_AND_DISTRIBUTED_EVIDENCE.md",
        },
        "Aborted" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Semantic(SemanticTransferState::Aborted),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_AND_DISTRIBUTED_EVIDENCE.md",
        },
        "Superseded" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Semantic(SemanticTransferState::Superseded),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_AND_DISTRIBUTED_EVIDENCE.md",
        },

        // Archive object custody spellings.
        "local_staged" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::ArchiveObject(ArchiveObjectState::LocalStaged),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_ARCHIVE_AND_REPLICATION.md",
        },
        "local_durable" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::ArchiveObject(ArchiveObjectState::LocalDurable),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_ARCHIVE_AND_REPLICATION.md",
        },
        "remote_staged" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::ArchiveObject(ArchiveObjectState::RemoteStaged),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_ARCHIVE_AND_REPLICATION.md",
        },
        "remote_children_verified" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::ArchiveObject(
                ArchiveObjectState::RemoteChildrenVerified,
            ),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_ARCHIVE_AND_REPLICATION.md",
        },
        "remote_root_published" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::ArchiveObject(
                ArchiveObjectState::RemoteRootPublished,
            ),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_ARCHIVE_AND_REPLICATION.md",
        },
        "replication_policy_satisfied" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::ArchiveObject(
                ArchiveObjectState::ReplicationPolicySatisfied,
            ),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_ARCHIVE_AND_REPLICATION.md",
        },
        "retrievability_sample_passed" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::ArchiveObject(
                ArchiveObjectState::RetrievabilitySamplePassed,
            ),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_ARCHIVE_AND_REPLICATION.md",
        },

        // Path lifecycle spellings.
        "Discover" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Path(PathState::Discover),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md",
        },
        "Candidate" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Path(PathState::Candidate),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md",
        },
        "Probing" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Path(PathState::Probing),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md",
        },
        "Active" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Path(PathState::Active),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md",
        },
        "Suspect" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Path(PathState::Suspect),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md",
        },
        "Draining" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Path(PathState::Draining),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md",
        },
        "Closed" => CrosswalkResolution {
            canonical: CanonicalLifecycleState::Path(PathState::Closed),
            mapping: LegacyMappingKind::DistinctCanonical,
            source_document: "docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md",
        },

        _ => {
            return Err(AtpLifecycleError::UnknownStateSpelling {
                spelling: spelling.to_owned(),
            });
        }
    };

    if let Some(expected) = layer_hint
        && resolved.canonical.layer() != expected
    {
        return Err(AtpLifecycleError::LayerMismatch {
            spelling: spelling.to_owned(),
            expected,
            actual: resolved.canonical.layer(),
        });
    }

    Ok(resolved)
}

fn parse_canonical_id(id: &str) -> Option<CanonicalLifecycleState> {
    for state in SemanticTransferState::ALL {
        if state.canonical_id() == id {
            return Some(CanonicalLifecycleState::Semantic(state));
        }
    }
    for state in ArchivePublicationState::ALL {
        if state.canonical_id() == id {
            return Some(CanonicalLifecycleState::Archive(state));
        }
    }
    for state in ArchiveObjectState::ALL {
        if state.canonical_id() == id {
            return Some(CanonicalLifecycleState::ArchiveObject(state));
        }
    }
    for state in PathState::ALL {
        if state.canonical_id() == id {
            return Some(CanonicalLifecycleState::Path(state));
        }
    }
    None
}
