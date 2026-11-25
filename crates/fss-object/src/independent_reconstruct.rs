#![forbid(unsafe_code)]
//! Independent reconstruction of archive roots from raw manifests (`FSS-135`, `fss-x4a.13.19`).
//!
//! Proves `docs/ATP_ARCHIVE_AND_REPLICATION.md` §12 ("full reconstruction from manifests on an
//! independent implementation"): given ONLY raw immutable content-addressed blobs (manifest bytes
//! and leaf bytes) plus optional GF(256) repair symbol sets — with ZERO access to local stores,
//! database indexes, or ledger metadata — independently:
//!
//! 1. **Re-parses every `ObjectManifest`** from raw bytes via [`ObjectManifest::from_canonical_bytes`]
//!    and verifies `ContentDigest::sha256(bytes) == expected_digest` on every manifest and leaf.
//! 2. **Recurses bottom-up with strict cycle and depth bounds** (`MAX_RECONSTRUCT_NODES`,
//!    `MAX_RECONSTRUCT_DEPTH`, `MAX_RECONSTRUCT_TOTAL_BYTES`), emitting exact bottom-up canonical
//!    post-order matching `FSS-127` [`crate::closure::ClosureVerifier`] for differential proof!
//! 3. **Recovers missing blobs via `FSS-128` [`PostRepairDigestGate`]:** when a referenced child
//!    blob is absent from the raw blob store but a sealed [`RepairPlan`] + [`RepairLease`] +
//!    GF(256) [`RepairSymbolEnvelope`] set is supplied, invokes `PostRepairDigestGate::reconstruct_and_verify`
//!    and admits the recovered bytes ONLY upon [`RepairGateState::VerifiedCanonicalMatch`] (any
//!    mismatch or corruption fails closed into [`ReconstructionVerdict::CorruptOrQuarantined`]).
//! 4. **Never invents authority (`XFER-INV-006`):** independent reconstruction is a read-only
//!    integrity proof; `grants_effect_authority == true` fails closed.
//! 5. **Seals a bounded checksummed [`IndependentReconstructionProof`] (`FSSIRP01` v1):** domain
//!    `fss.atp_independent_reconstruction_proof.v1`.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, TimestampNs,
};

use crate::ObjectManifest;
use crate::repair_gate::{
    PostRepairDigestGate, RepairAuthorityContext, RepairGateState, RepairLease, RepairPlan,
    RepairSymbolEnvelope,
};

/// Registered digest domain for [`IndependentReconstructionProof`] (`FSS-135`).
pub const ATP_INDEPENDENT_RECONSTRUCTION_DOMAIN: &str =
    "fss.atp_independent_reconstruction_proof.v1";
/// Binary wire header magic for serialized independent reconstruction proofs.
pub const RECONSTRUCTION_PROOF_MAGIC: [u8; 8] = *b"FSSIRP01";
/// Supported durable format version for [`IndependentReconstructionProof`].
pub const RECONSTRUCTION_PROOF_VERSION: u32 = 1;
/// Hard ceiling on nodes reconstructed in one bounded pass.
pub const MAX_RECONSTRUCT_NODES: usize = 65_536;
/// Hard ceiling on manifest nesting depth.
pub const MAX_RECONSTRUCT_DEPTH: u32 = 128;
/// Hard ceiling on cumulative verified payload bytes (1 GiB).
pub const MAX_RECONSTRUCT_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
/// Hard ceiling on serialized proof wire bytes (4 MiB).
pub const MAX_RECONSTRUCT_PROOF_WIRE_BYTES: usize = 4 * 1024 * 1024;
/// Hard ceiling on diagnostic label bytes.
pub const MAX_RECONSTRUCT_LABEL_BYTES: usize = 256;

/// Non-collapsed verdict of an independent manifest-only reconstruction run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconstructionVerdict {
    /// Every manifest and child leaf reconstructed, verified against its exact SHA-256 digest,
    /// and matched the expected archive root bit-identically.
    VerifiedComplete = 1,
    /// At least one manifest or leaf blob was missing and unrecoverable via repair symbols.
    IncompleteMissingBlobs = 2,
    /// At least one blob, manifest encoding, or post-repair reconstruction failed canonical digest
    /// verification or contained a cycle.
    CorruptOrQuarantined = 3,
}

impl ReconstructionVerdict {
    /// Stable canonical machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedComplete => "verified_complete",
            Self::IncompleteMissingBlobs => "incomplete_missing_blobs",
            Self::CorruptOrQuarantined => "corrupt_or_quarantined",
        }
    }

    const fn tag(self) -> u8 {
        self as u8
    }

    fn from_tag(tag: u8) -> Result<Self, ContractError> {
        match tag {
            1 => Ok(Self::VerifiedComplete),
            2 => Ok(Self::IncompleteMissingBlobs),
            3 => Ok(Self::CorruptOrQuarantined),
            _ => Err(ContractError::InvalidIdentifier),
        }
    }
}

/// Safe operator/agent recovery guidance for a refused or defective independent reconstruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconstructionGuidance {
    /// Independent archive root reconstruction matched bit-identically; ready for audit/restore.
    ArchiveRootVerified,
    /// Fetch missing blobs or supply valid GF(256) repair symbols for the exact generation.
    FetchMissingBlobsOrRepair,
    /// Quarantine corrupt blobs/manifests and restore from an independent healthy replica.
    QuarantineAndRestoreFromHealthyReplica,
    /// Re-authorize revoked read/repair capability or strip forbidden effect authority.
    ReauthorizeReconstruction,
    /// Cooperative cancellation observed; safe to retry cleanly from raw blobs.
    RetryWhenReady,
    /// Reject corrupt or unsupported binary reconstruction proof bytes.
    RejectCorruptProof,
}

/// Typed error returned by [`IndependentArchiveReconstructor`] or proof wire codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconstructionError {
    /// Capability/privacy revoked or effect authority illegally attached (`XFER-INV-006`).
    AuthorityRefused(String),
    /// Cooperative cancellation observed before reconstruction completed.
    Cancelled,
    /// Traversal exceeded node, depth, byte, or wire bounds.
    BoundsExceeded {
        /// Observed size/count.
        observed: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Invalid input label or invariant violation.
    InvalidInput(String),
    /// Binary proof lacked [`RECONSTRUCTION_PROOF_MAGIC`].
    InvalidMagic,
    /// Binary proof declared an unsupported version.
    UnsupportedVersion {
        /// Observed version.
        version: u32,
    },
    /// Binary proof was truncated, non-canonical, or structurally inconsistent.
    MalformedWire(String),
    /// Proof canonical checksum failed verification.
    ChecksumMismatch,
    /// Canonical encoder failure.
    Encoding(String),
}

impl ReconstructionError {
    /// Stable canonical machine error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AuthorityRefused(_) => "ERR-ATP-RECONSTRUCT-AUTHORITY-001",
            Self::Cancelled => "ERR-ATP-RECONSTRUCT-CANCELLED-001",
            Self::BoundsExceeded { .. } => "ERR-ATP-RECONSTRUCT-BOUNDS-001",
            Self::InvalidInput(_) => "ERR-ATP-RECONSTRUCT-INVALID-INPUT-001",
            Self::InvalidMagic => "ERR-ATP-RECONSTRUCT-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-ATP-RECONSTRUCT-UNSUPPORTED-VERSION-001",
            Self::MalformedWire(_) => "ERR-ATP-RECONSTRUCT-MALFORMED-WIRE-001",
            Self::ChecksumMismatch => "ERR-ATP-RECONSTRUCT-CHECKSUM-MISMATCH-001",
            Self::Encoding(_) => "ERR-ATP-RECONSTRUCT-ENCODING-001",
        }
    }

    /// Safe recovery guidance.
    #[must_use]
    pub const fn guidance(&self) -> ReconstructionGuidance {
        match self {
            Self::AuthorityRefused(_) => ReconstructionGuidance::ReauthorizeReconstruction,
            Self::Cancelled => ReconstructionGuidance::RetryWhenReady,
            Self::BoundsExceeded { .. } | Self::InvalidInput(_) => {
                ReconstructionGuidance::FetchMissingBlobsOrRepair
            }
            Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::MalformedWire(_)
            | Self::ChecksumMismatch
            | Self::Encoding(_) => ReconstructionGuidance::RejectCorruptProof,
        }
    }
}

impl fmt::Display for ReconstructionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for ReconstructionError {}

/// Optional GF(256) repair fallback bundle supplied alongside cold raw archive blobs.
#[derive(Clone, Debug)]
pub struct RepairFallbackBundle {
    /// Sealed immutable repair plan for the target object digest.
    pub plan: RepairPlan,
    /// Active fenced repair lease.
    pub lease: RepairLease,
    /// Minimum fence required.
    pub min_fence: u64,
    /// Available GF(256) source + repair symbol envelopes.
    pub symbols: Vec<RepairSymbolEnvelope>,
}

/// Cold raw-blob archive snapshot containing ZERO local store metadata, indexes, or ledger state.
#[derive(Clone, Debug, Default)]
pub struct ColdArchiveBlobSet {
    /// Raw immutable blobs (both `ObjectManifest` bytes and opaque leaf chunk bytes) keyed by claimed digest.
    pub blobs: BTreeMap<ContentDigest, Vec<u8>>,
    /// Explicit set of digests known to be manifest blobs (root is always parsed as a manifest if
    /// parseable, and any child whose raw bytes parse as `fss.object_manifest.v1` is recursed!).
    pub repair_fallbacks: BTreeMap<ContentDigest, RepairFallbackBundle>,
}

impl ColdArchiveBlobSet {
    /// Creates an empty cold blob set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts raw bytes under their true SHA-256 digest.
    pub fn insert_verified_blob(&mut self, bytes: Vec<u8>) -> ContentDigest {
        let digest = ContentDigest::sha256(&bytes);
        self.blobs.insert(digest, bytes);
        digest
    }

    /// Inserts raw bytes under an arbitrary claimed digest (supports adversarial corruption tests).
    pub fn insert_claimed_blob(&mut self, claimed_digest: ContentDigest, bytes: Vec<u8>) {
        self.blobs.insert(claimed_digest, bytes);
    }

    /// Attaches a GF(256) repair fallback bundle for a missing child digest.
    pub fn insert_repair_fallback(&mut self, target: ContentDigest, bundle: RepairFallbackBundle) {
        self.repair_fallbacks.insert(target, bundle);
    }
}

/// One independently reconstructed and SHA-256 verified object in canonical bottom-up post-order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconstructedMember {
    /// Verified canonical SHA-256 digest.
    pub digest: ContentDigest,
    /// True iff this object is an `ObjectManifest`; false for opaque leaf chunks.
    pub is_manifest: bool,
    /// Verified canonical payload byte length.
    pub byte_len: u64,
    /// True iff reconstructed from GF(256) repair symbols via `FSS-128` post-repair digest gate.
    pub recovered_via_repair: bool,
    /// Number of direct children declared (0 for leaf chunks).
    pub child_count: u32,
}

/// Typed defect observed during independent reconstruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconstructionDefect {
    /// Offending expected object digest.
    pub digest: ContentDigest,
    /// Machine-readable classification (`missing_blob`, `digest_mismatch`, `cycle_detected`,
    /// `repair_quarantined`, `corrupt_root_manifest`).
    pub kind: String,
    /// Secret-free diagnostic detail.
    pub detail: String,
}

/// Sealed independent manifest-only reconstruction proof (`FSSIRP01` v1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndependentReconstructionProof {
    /// Wire format version (`RECONSTRUCTION_PROOF_VERSION`).
    pub format_version: u32,
    /// Expected sealed archive root digest.
    pub expected_root_digest: ContentDigest,
    /// Pinned `ContractBasis` digest.
    pub contract_basis_digest: ContentDigest,
    /// Active authority generation.
    pub authority_generation: u64,
    /// Active privacy epoch.
    pub privacy_epoch: u64,
    /// Non-collapsed reconstruction verdict.
    pub verdict: ReconstructionVerdict,
    /// Verified members in strict bottom-up canonical post-order (children strictly before parents).
    pub ordered_members: Vec<ReconstructedMember>,
    /// Typed defects encountered (empty iff `verdict == VerifiedComplete`).
    pub defects: Vec<ReconstructionDefect>,
    /// Cumulative verified payload bytes across all unique reconstructed members.
    pub total_verified_bytes: u64,
    /// Count of members recovered via GF(256) repair symbols and verified by post-repair gate.
    pub repaired_member_count: u32,
    /// Maximum nesting depth observed (`0` for root-only manifest).
    pub max_observed_depth: u32,
    /// Timestamp when this proof was sealed.
    pub verified_at: TimestampNs,
    /// Domain-separated SHA-256 commitment (`fss.atp_independent_reconstruction_proof.v1`).
    pub proof_digest: ContentDigest,
}

impl IndependentReconstructionProof {
    /// True iff every manifest and child reconstructed and matched `expected_root_digest`.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.verdict, ReconstructionVerdict::VerifiedComplete)
    }

    /// Recomputes the domain-separated SHA-256 commitment (`fss.atp_independent_reconstruction_proof.v1`).
    pub fn compute_digest(&self) -> Result<ContentDigest, ReconstructionError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(ATP_INDEPENDENT_RECONSTRUCTION_DOMAIN);
        self.encode_body(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| ReconstructionError::Encoding(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    fn verify_self(&self) -> Result<(), ReconstructionError> {
        if self.format_version != RECONSTRUCTION_PROOF_VERSION {
            return Err(ReconstructionError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        if self.verdict == ReconstructionVerdict::VerifiedComplete
            && (!self.defects.is_empty()
                || self.ordered_members.last().map(|m| m.digest) != Some(self.expected_root_digest))
        {
            return Err(ReconstructionError::MalformedWire(
                "VerifiedComplete proof must have zero defects and terminate at expected_root_digest"
                    .to_owned(),
            ));
        }
        if self.verdict != ReconstructionVerdict::VerifiedComplete && self.defects.is_empty() {
            return Err(ReconstructionError::MalformedWire(
                "non-complete reconstruction proof must record at least one typed defect"
                    .to_owned(),
            ));
        }
        let mut seen = BTreeSet::new();
        let mut actual_repaired = 0_u32;
        let mut actual_bytes = 0_u64;
        for m in &self.ordered_members {
            if !seen.insert(m.digest) {
                return Err(ReconstructionError::MalformedWire(
                    "duplicate member digest in ordered_members".to_owned(),
                ));
            }
            if m.recovered_via_repair {
                actual_repaired = actual_repaired.saturating_add(1);
            }
            actual_bytes = actual_bytes.saturating_add(m.byte_len);
        }
        if actual_repaired != self.repaired_member_count
            || actual_bytes != self.total_verified_bytes
            || self.ordered_members.len() > MAX_RECONSTRUCT_NODES
            || self.defects.len() > MAX_RECONSTRUCT_NODES
            || self.total_verified_bytes > MAX_RECONSTRUCT_TOTAL_BYTES
            || self.max_observed_depth > MAX_RECONSTRUCT_DEPTH
        {
            return Err(ReconstructionError::MalformedWire(
                "proof summary counters or bounds disagree with ordered_members".to_owned(),
            ));
        }
        if self.compute_digest()? != self.proof_digest {
            return Err(ReconstructionError::ChecksumMismatch);
        }
        Ok(())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.digest(self.expected_root_digest);
        enc.digest(self.contract_basis_digest);
        enc.u64(self.authority_generation);
        enc.u64(self.privacy_epoch);
        enc.u8(self.verdict.tag());
        enc.u64(self.ordered_members.len() as u64);
        for m in &self.ordered_members {
            enc.digest(m.digest);
            enc.bool(m.is_manifest);
            enc.u64(m.byte_len);
            enc.bool(m.recovered_via_repair);
            enc.u32(m.child_count);
        }
        enc.u64(self.defects.len() as u64);
        for def in &self.defects {
            enc.digest(def.digest);
            enc.text(&def.kind);
            enc.text(&def.detail);
        }
        enc.u64(self.total_verified_bytes);
        enc.u32(self.repaired_member_count);
        enc.u32(self.max_observed_depth);
        self.verified_at.encode_canonical(enc);
    }

    /// Encodes this proof into bounded checksummed binary bytes (`FSSIRP01` v1).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ReconstructionError> {
        self.verify_self()?;
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        enc.digest(self.proof_digest);
        let body = enc
            .finish_checked()
            .map_err(|e| ReconstructionError::Encoding(e.to_string()))?;
        let total = RECONSTRUCTION_PROOF_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_RECONSTRUCT_PROOF_WIRE_BYTES {
            return Err(ReconstructionError::BoundsExceeded {
                observed: total,
                maximum: MAX_RECONSTRUCT_PROOF_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&RECONSTRUCTION_PROOF_MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and verifies a binary [`IndependentReconstructionProof`] (`FSSIRP01` v1).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ReconstructionError> {
        if bytes.len() > MAX_RECONSTRUCT_PROOF_WIRE_BYTES {
            return Err(ReconstructionError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_RECONSTRUCT_PROOF_WIRE_BYTES,
            });
        }
        if bytes.len() < 12 || bytes[..8] != RECONSTRUCTION_PROOF_MAGIC {
            return Err(ReconstructionError::InvalidMagic);
        }
        let header_ver = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if header_ver != RECONSTRUCTION_PROOF_VERSION {
            return Err(ReconstructionError::UnsupportedVersion {
                version: header_ver,
            });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let format_version = dec
            .u32()
            .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?;
        if format_version != header_ver {
            return Err(ReconstructionError::UnsupportedVersion {
                version: format_version,
            });
        }
        let expected_root_digest = dec
            .digest()
            .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?;
        let contract_basis_digest = dec
            .digest()
            .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?;
        let authority_generation = dec
            .u64()
            .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?;
        let privacy_epoch = dec
            .u64()
            .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?;
        let verdict = ReconstructionVerdict::from_tag(
            dec.u8()
                .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?,
        )
        .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?;

        let member_count = usize::try_from(
            dec.u64()
                .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?,
        )
        .map_err(|_| ReconstructionError::BoundsExceeded {
            observed: usize::MAX,
            maximum: MAX_RECONSTRUCT_NODES,
        })?;
        if member_count > MAX_RECONSTRUCT_NODES || member_count.saturating_mul(46) > dec.remaining()
        {
            return Err(ReconstructionError::BoundsExceeded {
                observed: member_count,
                maximum: MAX_RECONSTRUCT_NODES,
            });
        }
        let mut ordered_members = Vec::with_capacity(member_count);
        for _ in 0..member_count {
            ordered_members.push(ReconstructedMember {
                digest: dec
                    .digest()
                    .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?,
                is_manifest: dec
                    .bool()
                    .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?,
                byte_len: dec
                    .u64()
                    .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?,
                recovered_via_repair: dec
                    .bool()
                    .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?,
                child_count: dec
                    .u32()
                    .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?,
            });
        }

        let defect_count = usize::try_from(
            dec.u64()
                .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?,
        )
        .map_err(|_| ReconstructionError::BoundsExceeded {
            observed: usize::MAX,
            maximum: MAX_RECONSTRUCT_NODES,
        })?;
        if defect_count > MAX_RECONSTRUCT_NODES || defect_count.saturating_mul(42) > dec.remaining()
        {
            return Err(ReconstructionError::BoundsExceeded {
                observed: defect_count,
                maximum: MAX_RECONSTRUCT_NODES,
            });
        }
        let mut defects = Vec::with_capacity(defect_count);
        for _ in 0..defect_count {
            let digest = dec
                .digest()
                .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?;
            let kind = dec
                .text()
                .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?
                .to_owned();
            let detail = dec
                .text()
                .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?
                .to_owned();
            validate_label(&kind, MAX_RECONSTRUCT_LABEL_BYTES, "defect_kind")
                .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?;
            validate_label(&detail, MAX_RECONSTRUCT_LABEL_BYTES, "defect_detail")
                .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?;
            defects.push(ReconstructionDefect {
                digest,
                kind,
                detail,
            });
        }

        let total_verified_bytes = dec
            .u64()
            .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?;
        let repaired_member_count = dec
            .u32()
            .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?;
        let max_observed_depth = dec
            .u32()
            .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?;
        let verified_at = TimestampNs::decode_canonical(&mut dec)
            .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?;
        let stored_digest = dec
            .digest()
            .map_err(|e| ReconstructionError::MalformedWire(e.to_string()))?;
        dec.ensure_finished().map_err(|_| {
            ReconstructionError::MalformedWire(
                "trailing bytes after reconstruction proof".to_owned(),
            )
        })?;

        let proof = Self {
            format_version,
            expected_root_digest,
            contract_basis_digest,
            authority_generation,
            privacy_epoch,
            verdict,
            ordered_members,
            defects,
            total_verified_bytes,
            repaired_member_count,
            max_observed_depth,
            verified_at,
            proof_digest: stored_digest,
        };
        proof.verify_self()?;
        Ok(proof)
    }
}

/// Independent cold-state manifest-only archive root reconstructor (`FSS-135`).
pub struct IndependentArchiveReconstructor;

impl IndependentArchiveReconstructor {
    /// Reconstructs and verifies the entire archive object graph rooted at `expected_root_digest`
    /// using ONLY raw bytes (and optional GF(256) repair bundles) from `cold_blobs`.
    pub fn reconstruct_root(
        cold_blobs: &ColdArchiveBlobSet,
        expected_root_digest: ContentDigest,
        authority: &RepairAuthorityContext,
        now: TimestampNs,
        cancelled: bool,
    ) -> Result<IndependentReconstructionProof, ReconstructionError> {
        if cancelled {
            return Err(ReconstructionError::Cancelled);
        }
        if authority.grants_effect_authority {
            return Err(ReconstructionError::AuthorityRefused(
                "independent archive reconstruction cannot carry effect authority (XFER-INV-006)"
                    .to_owned(),
            ));
        }
        if !authority.repair_capability_active || !authority.privacy_active {
            return Err(ReconstructionError::AuthorityRefused(
                "reconstruction capability or privacy authorization revoked".to_owned(),
            ));
        }
        if authority.authority_generation != authority.expected_authority_generation {
            return Err(ReconstructionError::AuthorityRefused(format!(
                "stale authority generation {} != expected {}",
                authority.authority_generation, authority.expected_authority_generation
            )));
        }

        let mut ctx = WalkState {
            cold_blobs,
            authority,
            now,
            visiting: BTreeSet::new(),
            completed: BTreeSet::new(),
            failed: BTreeSet::new(),
            ordered_members: Vec::new(),
            defects: Vec::new(),
            total_verified_bytes: 0,
            reserved_verified_bytes: 0,
            repaired_member_count: 0,
            max_observed_depth: 0,
            saw_corrupt: false,
        };
        ctx.visit(expected_root_digest, 0, true)?;

        let verdict = if ctx.defects.is_empty() {
            ReconstructionVerdict::VerifiedComplete
        } else if ctx.saw_corrupt {
            ReconstructionVerdict::CorruptOrQuarantined
        } else {
            ReconstructionVerdict::IncompleteMissingBlobs
        };

        let mut proof = IndependentReconstructionProof {
            format_version: RECONSTRUCTION_PROOF_VERSION,
            expected_root_digest,
            contract_basis_digest: authority.contract_basis_digest,
            authority_generation: authority.authority_generation,
            privacy_epoch: authority.privacy_epoch,
            verdict,
            ordered_members: ctx.ordered_members,
            defects: ctx.defects,
            total_verified_bytes: ctx.total_verified_bytes,
            repaired_member_count: ctx.repaired_member_count,
            max_observed_depth: ctx.max_observed_depth,
            verified_at: now,
            proof_digest: ContentDigest::sha256(b"unsealed-independent-reconstruction-proof"),
        };
        proof.proof_digest = proof.compute_digest()?;
        Ok(proof)
    }
}

struct WalkState<'a> {
    cold_blobs: &'a ColdArchiveBlobSet,
    authority: &'a RepairAuthorityContext,
    now: TimestampNs,
    visiting: BTreeSet<ContentDigest>,
    completed: BTreeSet<ContentDigest>,
    failed: BTreeSet<ContentDigest>,
    ordered_members: Vec<ReconstructedMember>,
    defects: Vec<ReconstructionDefect>,
    total_verified_bytes: u64,
    reserved_verified_bytes: u64,
    repaired_member_count: u32,
    max_observed_depth: u32,
    saw_corrupt: bool,
}

impl WalkState<'_> {
    fn record_defect(
        &mut self,
        digest: ContentDigest,
        kind: &str,
        detail: String,
        is_corrupt: bool,
        mark_failed: bool,
    ) -> Result<(), ReconstructionError> {
        if self.defects.len() >= MAX_RECONSTRUCT_NODES {
            return Err(ReconstructionError::BoundsExceeded {
                observed: self.defects.len().saturating_add(1),
                maximum: MAX_RECONSTRUCT_NODES,
            });
        }
        if is_corrupt {
            self.saw_corrupt = true;
        }
        if mark_failed {
            self.failed.insert(digest);
        }
        self.defects.push(ReconstructionDefect {
            digest,
            kind: kind.to_owned(),
            detail,
        });
        Ok(())
    }

    fn visit(
        &mut self,
        expected: ContentDigest,
        depth: u32,
        must_be_manifest: bool,
    ) -> Result<(), ReconstructionError> {
        if self.completed.contains(&expected) || self.failed.contains(&expected) {
            return Ok(());
        }
        if depth > MAX_RECONSTRUCT_DEPTH {
            return Err(ReconstructionError::BoundsExceeded {
                observed: depth as usize,
                maximum: MAX_RECONSTRUCT_DEPTH as usize,
            });
        }
        if !self.visiting.insert(expected) {
            return self.record_defect(
                expected,
                "cycle_detected",
                "cyclic manifest reference detected during independent reconstruction".to_owned(),
                true,
                false,
            );
        }
        if self
            .ordered_members
            .len()
            .saturating_add(self.visiting.len())
            > MAX_RECONSTRUCT_NODES
        {
            self.visiting.remove(&expected);
            return Err(ReconstructionError::BoundsExceeded {
                observed: self
                    .ordered_members
                    .len()
                    .saturating_add(self.visiting.len() + 1),
                maximum: MAX_RECONSTRUCT_NODES,
            });
        }
        self.max_observed_depth = self.max_observed_depth.max(depth);

        // Step 1: Acquire raw bytes from cold blob store OR GF(256) repair fallback!
        let (raw_bytes, recovered_via_repair) = if let Some(blob) =
            self.cold_blobs.blobs.get(&expected)
        {
            let actual = ContentDigest::sha256(blob);
            if actual != expected {
                self.visiting.remove(&expected);
                return self.record_defect(
                    expected,
                    "digest_mismatch",
                    format!("raw blob sha256 {actual} != expected {expected}"),
                    true,
                    true,
                );
            }
            (blob.clone(), false)
        } else if let Some(bundle) = self.cold_blobs.repair_fallbacks.get(&expected) {
            if bundle.plan.target_object_digest != expected {
                self.visiting.remove(&expected);
                return self.record_defect(
                    expected,
                    "repair_quarantined",
                    "repair bundle target_object_digest disagrees with expected digest".to_owned(),
                    true,
                    true,
                );
            }
            match PostRepairDigestGate::reconstruct_and_verify(
                &bundle.plan,
                self.authority,
                &bundle.lease,
                bundle.min_fence,
                &bundle.symbols,
                self.now,
                false,
                false,
            ) {
                Ok(res)
                    if res.receipt.state == RepairGateState::VerifiedCanonicalMatch
                        && res.verified_bytes.is_some() =>
                {
                    let bytes = res.verified_bytes.unwrap_or_default();
                    if ContentDigest::sha256(&bytes) != expected {
                        self.visiting.remove(&expected);
                        return self.record_defect(
                            expected,
                            "repair_quarantined",
                            "post-repair sha256 re-check failed".to_owned(),
                            true,
                            true,
                        );
                    }
                    (bytes, true)
                }
                Ok(res) => {
                    self.visiting.remove(&expected);
                    return self.record_defect(
                        expected,
                        "repair_quarantined",
                        format!("repair gate returned {}", res.receipt.state.as_str()),
                        true,
                        true,
                    );
                }
                Err(err) => {
                    self.visiting.remove(&expected);
                    return self.record_defect(
                        expected,
                        "repair_quarantined",
                        err.code().to_owned(),
                        true,
                        true,
                    );
                }
            }
        } else {
            self.visiting.remove(&expected);
            return self.record_defect(
                expected,
                "missing_blob",
                "blob absent from cold archive store and no repair bundle provided".to_owned(),
                false,
                true,
            );
        };

        let byte_len = raw_bytes.len() as u64;
        let next_reserved = self.reserved_verified_bytes.saturating_add(byte_len);
        if next_reserved > MAX_RECONSTRUCT_TOTAL_BYTES {
            self.visiting.remove(&expected);
            return Err(ReconstructionError::BoundsExceeded {
                observed: usize::try_from(next_reserved).unwrap_or(usize::MAX),
                maximum: usize::try_from(MAX_RECONSTRUCT_TOTAL_BYTES).unwrap_or(usize::MAX),
            });
        }
        self.reserved_verified_bytes = next_reserved;

        // Step 2: Independently attempt canonical `ObjectManifest` parsing.
        let parsed_manifest = ObjectManifest::from_canonical_bytes(&raw_bytes);
        let (is_manifest, child_count) = match parsed_manifest {
            Ok(manifest) => {
                if manifest.root() != expected {
                    self.reserved_verified_bytes =
                        self.reserved_verified_bytes.saturating_sub(byte_len);
                    self.visiting.remove(&expected);
                    return self.record_defect(
                        expected,
                        "corrupt_root_manifest",
                        "manifest computed root differs from verified blob digest".to_owned(),
                        true,
                        true,
                    );
                }
                // Recurse through children in canonical FSS-127 ClosureVerifier order
                // (`ManifestChild` digests before `Metadata` digest), bottom-up post-order.
                let metadata_digest = manifest.metadata_digest();
                for &child in manifest.children() {
                    if Some(child) != metadata_digest {
                        self.visit(child, depth.saturating_add(1), false)?;
                    }
                }
                if let Some(meta) = metadata_digest {
                    self.visit(meta, depth.saturating_add(1), false)?;
                }
                (true, manifest.children().len() as u32)
            }
            Err(_) if must_be_manifest => {
                self.reserved_verified_bytes =
                    self.reserved_verified_bytes.saturating_sub(byte_len);
                self.visiting.remove(&expected);
                return self.record_defect(
                    expected,
                    "corrupt_root_manifest",
                    "root blob failed independent fss.object_manifest.v1 parsing".to_owned(),
                    true,
                    true,
                );
            }
            Err(_) => (false, 0),
        };

        self.visiting.remove(&expected);
        self.completed.insert(expected);
        self.total_verified_bytes = self.total_verified_bytes.saturating_add(byte_len);
        if recovered_via_repair {
            self.repaired_member_count = self.repaired_member_count.saturating_add(1);
        }
        self.ordered_members.push(ReconstructedMember {
            digest: expected,
            is_manifest,
            byte_len,
            recovered_via_repair,
            child_count,
        });
        Ok(())
    }
}

fn validate_label(value: &str, max_len: usize, label: &str) -> Result<(), ReconstructionError> {
    if value.is_empty() || value.len() > max_len {
        return Err(ReconstructionError::InvalidInput(format!(
            "{label} length {} outside 1..={max_len}",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(ReconstructionError::InvalidInput(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}
