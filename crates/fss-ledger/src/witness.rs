#![forbid(unsafe_code)]
//! Positive, negative, and hierarchical semantic ledger witnesses (`FSS-103`, `fss-x4a.9.10`).
//!
//! Provides canonical, domain-separated, checksummed proofs over one exact [`LedgerAnchor`] and
//! history-chain root:
//! - [`PositiveWitness`]: attests that one [`ObjectId`] exists at an exact [`ObjectRevision`] and
//!   `committed_sequence`, optionally backed by an `O(log N)` [`MerkleProof`] inclusion proof.
//! - [`NegativeWitness`]: attests absence ONLY alongside an explicit [`CoverageWitness`] pinned to
//!   the exact same anchor, keeping `certified` strictly equal to `coverage.certifies_absence()`
//!   (never upgrading gapped, partial, excluded, unknown, or stale-generation coverage into
//!   certified negative truth), optionally backed by an `O(log N)` non-inclusion [`MerkleProof`].
//! - [`HierarchicalWitness`]: composes canonical child witnesses over a named scope while enforcing
//!   strict single-anchor/single-history-root agreement, bounded depth and fan-out, permutation
//!   invariance, and non-inflation of uncertified negative children.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    ContentDigest, CoverageWitness, LedgerAnchor, ObjectId, ObjectRevision,
};

use crate::epochs::MerkleEpochLedger;
use crate::merkle::{MerkleProof, MerkleProofError, MerkleProofKind, decode_plane, verify_proof};
use crate::oracle::{LedgerOracle, MAX_ORACLE_TEXT_BYTES, ObjectRead};

/// Registered digest domain for [`SemanticWitness`] commitments (`FSS-103`).
pub const LEDGER_SEMANTIC_WITNESS_DOMAIN: &str = "fss.ledger_semantic_witness.v1";
/// Binary wire header magic for serialized semantic witnesses.
pub const SEMANTIC_WITNESS_MAGIC: [u8; 8] = *b"FSSWIT01";
/// Supported durable format version for [`SemanticWitness`].
pub const SEMANTIC_WITNESS_VERSION: u32 = 1;
/// Maximum direct children in one [`HierarchicalWitness`].
pub const MAX_HIERARCHICAL_CHILDREN: usize = 1_024;
/// Maximum nesting depth for [`HierarchicalWitness`].
pub const MAX_WITNESS_DEPTH: u32 = 32;
/// Maximum binary wire length of one [`SemanticWitness`] (1 MiB).
pub const MAX_WITNESS_WIRE_BYTES: usize = 1024 * 1024;
/// Maximum UTF-8 bytes in scope labels.
pub const MAX_WITNESS_LABEL_BYTES: usize = 256;

/// Safe next action for a refused semantic witness operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessGuidance {
    /// Positive read found the object absent; issue a negative witness with explicit coverage.
    IssueNegativeWitnessWithCoverage,
    /// Negative read found the object present; issue a positive witness instead.
    IssuePositiveWitness,
    /// Coverage does not certify absence; treat negative result as uncertified / not-observable.
    TreatAbsenceAsUncertified,
    /// Anchor or history root disagrees with the ledger; re-anchor against a verified head.
    ReanchorAgainstVerifiedHead,
    /// Mixed anchors/epochs in hierarchy; split witnesses by exact anchor before composing.
    SplitByExactAnchor,
    /// Merkle proof failed verification; reject tampered or stale proof and re-prove.
    RejectAndReproveMerkle,
    /// Wire witness is corrupt or out of bounds; reject and re-issue from canonical storage.
    RejectCorruptWitness,
    /// Format version is unsupported; upgrade reader or re-issue at a supported version.
    UpgradeOrReissue,
    /// Cooperative cancellation observed; retry from pinned anchor when ready.
    RetryFromPinnedAnchor,
}

/// Typed failure returned by semantic witness construction, verification, or wire decode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WitnessError {
    /// Positive witness requested for an object absent at the anchor.
    ObjectAbsent {
        /// Queried object identity.
        object_id: ObjectId,
        /// Commit sequence queried.
        sequence: u64,
    },
    /// Negative witness requested for an object present at the anchor.
    ObjectPresent {
        /// Queried object identity.
        object_id: ObjectId,
        /// Commit sequence queried.
        sequence: u64,
    },
    /// Coverage witness failed absence certification (`CoverageWitness::certifies_absence() == false`).
    AbsenceNotCertified,
    /// Anchor sequence is beyond committed head or disagrees with committed anchor/history root.
    AnchorMismatch {
        /// Offending commit sequence.
        sequence: u64,
        /// Machine-readable mismatch detail.
        detail: String,
    },
    /// Observed committed object revision disagreed with positive witness claims.
    RevisionMismatch {
        /// Object identity whose revision disagreed.
        object_id: ObjectId,
    },
    /// Hierarchical composition attempted to mix witnesses from distinct anchors or history roots.
    MixedAnchorInHierarchy,
    /// Attached Merkle inclusion or non-inclusion proof failed verification or disagreed with kind.
    InvalidMerkleProof(String),
    /// Cooperative cancellation observed before completing witness construction/verification.
    Cancelled,
    /// Wire witness lacked [`SEMANTIC_WITNESS_MAGIC`].
    InvalidMagic,
    /// Wire witness declared an unsupported format version.
    UnsupportedVersion {
        /// Observed format version.
        version: u32,
    },
    /// Wire witness was truncated, malformed, or violated structural invariants.
    MalformedWire(String),
    /// Wire witness checksum failed verification.
    ChecksumMismatch,
    /// Witness count, depth, label, or wire size exceeded hard bounds.
    BoundsExceeded {
        /// Observed length, count, or depth.
        observed: usize,
        /// Hard protocol ceiling.
        maximum: usize,
    },
    /// Canonical encoding failed.
    Encoding(String),
}

impl WitnessError {
    /// Registered stable error identity.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ObjectAbsent { .. } => "ERR-LEDGER-WITNESS-OBJECT-ABSENT-001",
            Self::ObjectPresent { .. } => "ERR-LEDGER-WITNESS-OBJECT-PRESENT-001",
            Self::AbsenceNotCertified => "ERR-LEDGER-WITNESS-ABSENCE-UNCERTIFIED-001",
            Self::AnchorMismatch { .. } => "ERR-LEDGER-WITNESS-ANCHOR-MISMATCH-001",
            Self::RevisionMismatch { .. } => "ERR-LEDGER-WITNESS-REVISION-MISMATCH-001",
            Self::MixedAnchorInHierarchy => "ERR-LEDGER-WITNESS-MIXED-ANCHOR-001",
            Self::InvalidMerkleProof(_) => "ERR-LEDGER-WITNESS-MERKLE-PROOF-001",
            Self::Cancelled => "ERR-LEDGER-WITNESS-CANCELLED-001",
            Self::InvalidMagic => "ERR-LEDGER-WITNESS-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-LEDGER-WITNESS-UNSUPPORTED-VERSION-001",
            Self::MalformedWire(_) => "ERR-LEDGER-WITNESS-MALFORMED-WIRE-001",
            Self::ChecksumMismatch => "ERR-LEDGER-WITNESS-CHECKSUM-MISMATCH-001",
            Self::BoundsExceeded { .. } => "ERR-LEDGER-WITNESS-BOUNDS-001",
            Self::Encoding(_) => "ERR-LEDGER-WITNESS-ENCODING-001",
        }
    }

    /// Safe recovery guidance for this refusal.
    #[must_use]
    pub const fn guidance(&self) -> WitnessGuidance {
        match self {
            Self::ObjectAbsent { .. } => WitnessGuidance::IssueNegativeWitnessWithCoverage,
            Self::ObjectPresent { .. } => WitnessGuidance::IssuePositiveWitness,
            Self::AbsenceNotCertified => WitnessGuidance::TreatAbsenceAsUncertified,
            Self::AnchorMismatch { .. } | Self::RevisionMismatch { .. } => {
                WitnessGuidance::ReanchorAgainstVerifiedHead
            }
            Self::MixedAnchorInHierarchy => WitnessGuidance::SplitByExactAnchor,
            Self::InvalidMerkleProof(_) => WitnessGuidance::RejectAndReproveMerkle,
            Self::Cancelled => WitnessGuidance::RetryFromPinnedAnchor,
            Self::UnsupportedVersion { .. } => WitnessGuidance::UpgradeOrReissue,
            Self::InvalidMagic
            | Self::MalformedWire(_)
            | Self::ChecksumMismatch
            | Self::BoundsExceeded { .. }
            | Self::Encoding(_) => WitnessGuidance::RejectCorruptWitness,
        }
    }
}

impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for WitnessError {}

impl From<MerkleProofError> for WitnessError {
    fn from(value: MerkleProofError) -> Self {
        Self::InvalidMerkleProof(value.to_string())
    }
}

/// Positive semantic witness proving one object's exact committed revision at a pinned anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PositiveWitness {
    /// Exact canonical ledger anchor.
    pub anchor: LedgerAnchor,
    /// Canonical history-chain root through `anchor.commit_sequence`.
    pub history_root: ContentDigest,
    /// Object identity proven present.
    pub object_id: ObjectId,
    /// Exact committed object revision.
    pub revision: ObjectRevision,
    /// Commit sequence at which `revision` became canonical (`<= anchor.commit_sequence`).
    pub committed_sequence: u64,
    /// Optional standalone `O(log N)` Merkle inclusion proof against `anchor.state_root`.
    pub merkle_proof: Option<MerkleProof>,
    /// Domain-separated SHA-256 commitment (`fss.ledger_semantic_witness.v1`).
    pub witness_digest: ContentDigest,
}

impl PositiveWitness {
    /// Constructs a positive witness from a committed [`LedgerOracle`] anchor.
    pub fn from_oracle(
        oracle: &LedgerOracle,
        sequence: u64,
        object_id: &ObjectId,
    ) -> Result<Self, WitnessError> {
        let view = oracle
            .view_at(sequence)
            .map_err(|err| WitnessError::AnchorMismatch {
                sequence,
                detail: err.to_string(),
            })?;
        match view.object(object_id) {
            ObjectRead::Present {
                revision,
                committed_sequence,
            } => Self::seal(
                view.anchor().clone(),
                view.history_root(),
                object_id.clone(),
                revision.clone(),
                committed_sequence,
                None,
            ),
            ObjectRead::AbsentAtAnchor { .. } => Err(WitnessError::ObjectAbsent {
                object_id: object_id.clone(),
                sequence,
            }),
        }
    }

    /// Constructs a Merkle-backed positive witness from [`MerkleEpochLedger`] at its head anchor.
    pub fn from_merkle_ledger(
        ledger: &MerkleEpochLedger,
        object_id: &ObjectId,
    ) -> Result<Self, WitnessError> {
        let anchor = ledger.head_anchor().clone();
        let history_root = ledger.history_root();
        let revision = ledger
            .get_object(object_id)
            .cloned()
            .ok_or_else(|| WitnessError::ObjectAbsent {
                object_id: object_id.clone(),
                sequence: anchor.commit_sequence,
            })?;
        let proof = ledger
            .prove_object(object_id)
            .map_err(|err| WitnessError::InvalidMerkleProof(err.to_string()))?;
        Self::seal(
            anchor.clone(),
            history_root,
            object_id.clone(),
            revision,
            anchor.commit_sequence,
            Some(proof),
        )
    }

    /// Seals and validates a positive witness from explicit verified fields.
    pub fn seal(
        anchor: LedgerAnchor,
        history_root: ContentDigest,
        object_id: ObjectId,
        revision: ObjectRevision,
        committed_sequence: u64,
        merkle_proof: Option<MerkleProof>,
    ) -> Result<Self, WitnessError> {
        validate_anchor_bounds(&anchor)?;
        if committed_sequence > anchor.commit_sequence {
            return Err(WitnessError::AnchorMismatch {
                sequence: committed_sequence,
                detail: "committed_sequence exceeds witness anchor commit_sequence".to_owned(),
            });
        }
        let mut witness = Self {
            anchor,
            history_root,
            object_id,
            revision,
            committed_sequence,
            merkle_proof,
            witness_digest: ContentDigest::sha256(b"unsealed-positive-witness"),
        };
        witness.verify_merkle_proof()?;
        witness.witness_digest = witness.compute_digest()?;
        Ok(witness)
    }

    /// Recomputes the domain-separated commitment digest.
    pub fn compute_digest(&self) -> Result<ContentDigest, WitnessError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(LEDGER_SEMANTIC_WITNESS_DOMAIN);
        enc.u32(SEMANTIC_WITNESS_VERSION);
        self.encode_body(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|err| WitnessError::Encoding(err.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Verifies the attached `MerkleProof`, if present, against `self.anchor.state_root`.
    pub fn verify_merkle_proof(&self) -> Result<(), WitnessError> {
        let Some(proof) = &self.merkle_proof else {
            return Ok(());
        };
        verify_proof(self.anchor.state_root, &self.object_id, proof)?;
        match &proof.kind {
            MerkleProofKind::Inclusion { revision } if revision == &self.revision => Ok(()),
            MerkleProofKind::Inclusion { .. } => Err(WitnessError::RevisionMismatch {
                object_id: self.object_id.clone(),
            }),
            MerkleProofKind::NonInclusion(_) => Err(WitnessError::InvalidMerkleProof(
                "positive witness cannot carry a non-inclusion Merkle proof".to_owned(),
            )),
        }
    }

    /// Verifies local structural invariants, optional Merkle proof, and self-commitment digest.
    pub fn verify_self_invariants(&self) -> Result<(), WitnessError> {
        validate_anchor_bounds(&self.anchor)?;
        if self.committed_sequence > self.anchor.commit_sequence {
            return Err(WitnessError::AnchorMismatch {
                sequence: self.committed_sequence,
                detail: "committed_sequence exceeds witness anchor commit_sequence".to_owned(),
            });
        }
        self.verify_merkle_proof()?;
        if self.compute_digest()? != self.witness_digest {
            return Err(WitnessError::ChecksumMismatch);
        }
        Ok(())
    }

    /// Verifies checksum, optional Merkle proof, anchor/history root, and exact object revision
    /// against `oracle`.
    pub fn verify_against_oracle(&self, oracle: &LedgerOracle) -> Result<(), WitnessError> {
        self.verify_self_invariants()?;
        let view = oracle
            .view_at_anchor(&self.anchor)
            .map_err(|err| WitnessError::AnchorMismatch {
                sequence: self.anchor.commit_sequence,
                detail: err.to_string(),
            })?;
        if view.history_root() != self.history_root {
            return Err(WitnessError::AnchorMismatch {
                sequence: self.anchor.commit_sequence,
                detail: "history_root disagrees with oracle".to_owned(),
            });
        }
        match view.object(&self.object_id) {
            ObjectRead::Present {
                revision,
                committed_sequence,
            } if revision == &self.revision && committed_sequence == self.committed_sequence => {
                Ok(())
            }
            ObjectRead::Present { .. } => Err(WitnessError::RevisionMismatch {
                object_id: self.object_id.clone(),
            }),
            ObjectRead::AbsentAtAnchor { .. } => Err(WitnessError::ObjectAbsent {
                object_id: self.object_id.clone(),
                sequence: self.anchor.commit_sequence,
            }),
        }
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.u8(1); // Positive tag
        self.anchor.encode_canonical(enc);
        enc.digest(self.history_root);
        self.object_id.encode_canonical(enc);
        self.revision.encode_canonical(enc);
        enc.u64(self.committed_sequence);
        match &self.merkle_proof {
            Some(proof) => {
                enc.bool(true);
                proof.encode_canonical(enc);
            }
            None => enc.bool(false),
        }
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, WitnessError> {
        let anchor = LedgerAnchor::decode_canonical(dec)
            .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
        validate_anchor_bounds(&anchor)?;
        let history_root = dec
            .digest()
            .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
        let object_id = ObjectId::decode_canonical(dec)
            .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
        let revision = decode_object_revision(dec)?;
        let committed_sequence = dec
            .u64()
            .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
        if committed_sequence > anchor.commit_sequence {
            return Err(WitnessError::MalformedWire(
                "committed_sequence exceeds anchor commit_sequence".to_owned(),
            ));
        }
        let has_proof = dec
            .bool()
            .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
        let merkle_proof = if has_proof {
            Some(
                MerkleProof::decode_canonical(dec)
                    .map_err(|err| WitnessError::MalformedWire(err.to_string()))?,
            )
        } else {
            None
        };
        let stored_digest = dec
            .digest()
            .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
        let witness = Self {
            anchor,
            history_root,
            object_id,
            revision,
            committed_sequence,
            merkle_proof,
            witness_digest: stored_digest,
        };
        witness.verify_merkle_proof()?;
        if witness.compute_digest()? != stored_digest {
            return Err(WitnessError::ChecksumMismatch);
        }
        Ok(witness)
    }
}

/// Negative semantic witness pairing exact absence with a mandatory [`CoverageWitness`].
///
/// An uncertified coverage witness (gapped, partial, excluded, unknown, or generation-drifted) is
/// preserved honestly with `certified == false` and NEVER upgraded into certified absence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeWitness {
    /// Exact canonical ledger anchor.
    pub anchor: LedgerAnchor,
    /// Canonical history-chain root through `anchor.commit_sequence`.
    pub history_root: ContentDigest,
    /// Queried object identity absent at `anchor`.
    pub object_id: ObjectId,
    /// Mandatory coverage witness pinned to `anchor`.
    pub coverage: CoverageWitness,
    /// Optional standalone `O(log N)` Merkle non-inclusion proof against `anchor.state_root`.
    pub merkle_proof: Option<MerkleProof>,
    /// True iff `coverage.certifies_absence()` holds (never inflated).
    pub certified: bool,
    /// Domain-separated SHA-256 commitment (`fss.ledger_semantic_witness.v1`).
    pub witness_digest: ContentDigest,
}

impl NegativeWitness {
    /// Constructs a negative witness from a committed [`LedgerOracle`] anchor and explicit
    /// [`CoverageWitness`].
    pub fn from_oracle(
        oracle: &LedgerOracle,
        sequence: u64,
        object_id: &ObjectId,
        coverage: CoverageWitness,
    ) -> Result<Self, WitnessError> {
        let view = oracle
            .view_at(sequence)
            .map_err(|err| WitnessError::AnchorMismatch {
                sequence,
                detail: err.to_string(),
            })?;
        match view.object(object_id) {
            ObjectRead::Present { .. } => Err(WitnessError::ObjectPresent {
                object_id: object_id.clone(),
                sequence,
            }),
            ObjectRead::AbsentAtAnchor { .. } => Self::seal(
                view.anchor().clone(),
                view.history_root(),
                object_id.clone(),
                coverage,
                None,
            ),
        }
    }

    /// Constructs a Merkle-backed negative witness from [`MerkleEpochLedger`] at its head anchor.
    pub fn from_merkle_ledger(
        ledger: &MerkleEpochLedger,
        object_id: &ObjectId,
        coverage: CoverageWitness,
    ) -> Result<Self, WitnessError> {
        let anchor = ledger.head_anchor().clone();
        let history_root = ledger.history_root();
        if ledger.get_object(object_id).is_some() {
            return Err(WitnessError::ObjectPresent {
                object_id: object_id.clone(),
                sequence: anchor.commit_sequence,
            });
        }
        let proof = ledger
            .prove_object(object_id)
            .map_err(|err| WitnessError::InvalidMerkleProof(err.to_string()))?;
        Self::seal(anchor, history_root, object_id.clone(), coverage, Some(proof))
    }

    /// Seals and validates a negative witness, binding `coverage.anchor == anchor` and
    /// `certified == coverage.certifies_absence()`.
    pub fn seal(
        anchor: LedgerAnchor,
        history_root: ContentDigest,
        object_id: ObjectId,
        coverage: CoverageWitness,
        merkle_proof: Option<MerkleProof>,
    ) -> Result<Self, WitnessError> {
        validate_anchor_bounds(&anchor)?;
        if coverage.anchor != anchor {
            return Err(WitnessError::AnchorMismatch {
                sequence: anchor.commit_sequence,
                detail: "coverage witness anchor disagrees with negative witness anchor".to_owned(),
            });
        }
        let certified = coverage.certifies_absence();
        let mut witness = Self {
            anchor,
            history_root,
            object_id,
            coverage,
            merkle_proof,
            certified,
            witness_digest: ContentDigest::sha256(b"unsealed-negative-witness"),
        };
        witness.verify_merkle_proof()?;
        witness.witness_digest = witness.compute_digest()?;
        Ok(witness)
    }

    /// Fails closed unless this negative witness genuinely certifies absence.
    pub fn require_certified_absence(&self) -> Result<(), WitnessError> {
        if self.certified && self.coverage.certifies_absence() {
            Ok(())
        } else {
            Err(WitnessError::AbsenceNotCertified)
        }
    }

    /// Recomputes the domain-separated commitment digest.
    pub fn compute_digest(&self) -> Result<ContentDigest, WitnessError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(LEDGER_SEMANTIC_WITNESS_DOMAIN);
        enc.u32(SEMANTIC_WITNESS_VERSION);
        self.encode_body(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|err| WitnessError::Encoding(err.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Verifies the attached non-inclusion `MerkleProof`, if present.
    pub fn verify_merkle_proof(&self) -> Result<(), WitnessError> {
        let Some(proof) = &self.merkle_proof else {
            return Ok(());
        };
        verify_proof(self.anchor.state_root, &self.object_id, proof)?;
        match &proof.kind {
            MerkleProofKind::NonInclusion(_) => Ok(()),
            MerkleProofKind::Inclusion { .. } => Err(WitnessError::InvalidMerkleProof(
                "negative witness cannot carry an inclusion Merkle proof".to_owned(),
            )),
        }
    }

    /// Verifies local structural invariants, coverage anchor/certification agreement, optional
    /// Merkle proof, and self-commitment digest.
    pub fn verify_self_invariants(&self) -> Result<(), WitnessError> {
        validate_anchor_bounds(&self.anchor)?;
        if self.coverage.anchor != self.anchor {
            return Err(WitnessError::AnchorMismatch {
                sequence: self.anchor.commit_sequence,
                detail: "coverage anchor disagrees with witness anchor".to_owned(),
            });
        }
        if self.certified != self.coverage.certifies_absence() {
            return Err(WitnessError::MalformedWire(
                "negative witness certified flag disagrees with coverage witness".to_owned(),
            ));
        }
        self.verify_merkle_proof()?;
        if self.compute_digest()? != self.witness_digest {
            return Err(WitnessError::ChecksumMismatch);
        }
        Ok(())
    }

    /// Verifies checksum, coverage anchor binding, optional Merkle proof, and object absence
    /// against `oracle`.
    pub fn verify_against_oracle(&self, oracle: &LedgerOracle) -> Result<(), WitnessError> {
        self.verify_self_invariants()?;
        let view = oracle
            .view_at_anchor(&self.anchor)
            .map_err(|err| WitnessError::AnchorMismatch {
                sequence: self.anchor.commit_sequence,
                detail: err.to_string(),
            })?;
        if view.history_root() != self.history_root {
            return Err(WitnessError::AnchorMismatch {
                sequence: self.anchor.commit_sequence,
                detail: "history_root disagrees with oracle".to_owned(),
            });
        }
        match view.object(&self.object_id) {
            ObjectRead::AbsentAtAnchor { .. } => Ok(()),
            ObjectRead::Present { .. } => Err(WitnessError::ObjectPresent {
                object_id: self.object_id.clone(),
                sequence: self.anchor.commit_sequence,
            }),
        }
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.u8(2); // Negative tag
        self.anchor.encode_canonical(enc);
        enc.digest(self.history_root);
        self.object_id.encode_canonical(enc);
        self.coverage.encode_canonical(enc);
        match &self.merkle_proof {
            Some(proof) => {
                enc.bool(true);
                proof.encode_canonical(enc);
            }
            None => enc.bool(false),
        }
        enc.bool(self.certified);
    }

    fn decode_body(dec: &mut CanonicalDecoder<'_>) -> Result<Self, WitnessError> {
        let anchor = LedgerAnchor::decode_canonical(dec)
            .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
        validate_anchor_bounds(&anchor)?;
        let history_root = dec
            .digest()
            .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
        let object_id = ObjectId::decode_canonical(dec)
            .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
        let coverage = CoverageWitness::decode_canonical(dec)
            .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
        if coverage.anchor != anchor {
            return Err(WitnessError::AnchorMismatch {
                sequence: anchor.commit_sequence,
                detail: "coverage anchor disagrees with negative witness anchor".to_owned(),
            });
        }
        let has_proof = dec
            .bool()
            .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
        let merkle_proof = if has_proof {
            Some(
                MerkleProof::decode_canonical(dec)
                    .map_err(|err| WitnessError::MalformedWire(err.to_string()))?,
            )
        } else {
            None
        };
        let certified = dec
            .bool()
            .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
        if certified != coverage.certifies_absence() {
            return Err(WitnessError::MalformedWire(
                "negative witness certified flag contradicts coverage".to_owned(),
            ));
        }
        let stored_digest = dec
            .digest()
            .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
        let witness = Self {
            anchor,
            history_root,
            object_id,
            coverage,
            merkle_proof,
            certified,
            witness_digest: stored_digest,
        };
        witness.verify_merkle_proof()?;
        if witness.compute_digest()? != stored_digest {
            return Err(WitnessError::ChecksumMismatch);
        }
        Ok(witness)
    }
}

/// Hierarchical scope roll-up composing multiple same-anchor child witnesses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HierarchicalWitness {
    /// Human/machine-readable bounded scope label (e.g. `zone:driveway` or `site:main`).
    pub scope_label: String,
    /// Exact shared canonical ledger anchor across all descendants.
    pub anchor: LedgerAnchor,
    /// Exact shared canonical history-chain root across all descendants.
    pub history_root: ContentDigest,
    /// Nesting height (`1` for leaf children, `1 + max(child.height)` for nested hierarchies).
    pub height: u32,
    /// Canonically ordered unique child witnesses (sorted by `witness_digest`).
    pub children: Vec<SemanticWitness>,
    /// True iff every negative descendant in this hierarchy is certified (never inflated).
    pub all_negative_certified: bool,
    /// Domain-separated SHA-256 commitment (`fss.ledger_semantic_witness.v1`).
    pub witness_digest: ContentDigest,
}

impl HierarchicalWitness {
    /// Composes `children` into one deterministic, single-anchor hierarchical witness.
    ///
    /// Sorts and deduplicates children by `witness_digest` so composition is permutation-invariant.
    /// Refuses empty child lists, mixed anchors/history roots, depth > [`MAX_WITNESS_DEPTH`], or
    /// cooperative cancellation.
    pub fn compose(
        scope_label: impl Into<String>,
        children: Vec<SemanticWitness>,
        cancelled: bool,
    ) -> Result<Self, WitnessError> {
        if cancelled {
            return Err(WitnessError::Cancelled);
        }
        let scope_label = scope_label.into();
        if scope_label.is_empty() || scope_label.len() > MAX_WITNESS_LABEL_BYTES {
            return Err(WitnessError::BoundsExceeded {
                observed: scope_label.len(),
                maximum: MAX_WITNESS_LABEL_BYTES,
            });
        }
        if children.is_empty() || children.len() > MAX_HIERARCHICAL_CHILDREN {
            return Err(WitnessError::BoundsExceeded {
                observed: children.len(),
                maximum: MAX_HIERARCHICAL_CHILDREN,
            });
        }
        let anchor = children[0].anchor().clone();
        let history_root = children[0].history_root();
        validate_anchor_bounds(&anchor)?;

        let mut max_child_height = 0u32;
        for child in &children {
            child.verify_self_invariants_depth(MAX_WITNESS_DEPTH - 1)?;
            if child.anchor() != &anchor || child.history_root() != history_root {
                return Err(WitnessError::MixedAnchorInHierarchy);
            }
            max_child_height = max_child_height.max(child.height());
        }
        let height = max_child_height
            .checked_add(1)
            .ok_or(WitnessError::BoundsExceeded {
                observed: usize::MAX,
                maximum: MAX_WITNESS_DEPTH as usize,
            })?;
        if height > MAX_WITNESS_DEPTH {
            return Err(WitnessError::BoundsExceeded {
                observed: height as usize,
                maximum: MAX_WITNESS_DEPTH as usize,
            });
        }

        let mut canonical_children = children;
        canonical_children.sort_by_key(SemanticWitness::witness_digest);
        canonical_children.dedup_by_key(|w| w.witness_digest());

        let all_negative_certified = canonical_children
            .iter()
            .all(SemanticWitness::all_negative_certified);

        let mut witness = Self {
            scope_label,
            anchor,
            history_root,
            height,
            children: canonical_children,
            all_negative_certified,
            witness_digest: ContentDigest::sha256(b"unsealed-hierarchical-witness"),
        };
        witness.witness_digest = witness.compute_digest()?;
        Ok(witness)
    }

    /// Recomputes the domain-separated commitment digest.
    pub fn compute_digest(&self) -> Result<ContentDigest, WitnessError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(LEDGER_SEMANTIC_WITNESS_DOMAIN);
        enc.u32(SEMANTIC_WITNESS_VERSION);
        self.encode_body(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|err| WitnessError::Encoding(err.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Verifies local structural invariants recursively without needing a full ledger handle.
    pub fn verify_self_invariants_depth(&self, remaining_depth: u32) -> Result<(), WitnessError> {
        if remaining_depth == 0 {
            return Err(WitnessError::BoundsExceeded {
                observed: (MAX_WITNESS_DEPTH + 1) as usize,
                maximum: MAX_WITNESS_DEPTH as usize,
            });
        }
        if self.scope_label.is_empty() || self.scope_label.len() > MAX_WITNESS_LABEL_BYTES {
            return Err(WitnessError::BoundsExceeded {
                observed: self.scope_label.len(),
                maximum: MAX_WITNESS_LABEL_BYTES,
            });
        }
        validate_anchor_bounds(&self.anchor)?;
        if self.height == 0 || self.height > MAX_WITNESS_DEPTH {
            return Err(WitnessError::BoundsExceeded {
                observed: self.height as usize,
                maximum: MAX_WITNESS_DEPTH as usize,
            });
        }
        if self.children.is_empty() || self.children.len() > MAX_HIERARCHICAL_CHILDREN {
            return Err(WitnessError::BoundsExceeded {
                observed: self.children.len(),
                maximum: MAX_HIERARCHICAL_CHILDREN,
            });
        }
        if !self
            .children
            .windows(2)
            .all(|pair| pair[0].witness_digest() < pair[1].witness_digest())
        {
            return Err(WitnessError::MalformedWire(
                "hierarchical children are not uniquely ordered by witness_digest".to_owned(),
            ));
        }
        let mut max_child_height = 0u32;
        let mut computed_all_neg = true;
        for child in &self.children {
            if child.anchor() != &self.anchor || child.history_root() != self.history_root {
                return Err(WitnessError::MixedAnchorInHierarchy);
            }
            child.verify_self_invariants_depth(remaining_depth - 1)?;
            max_child_height = max_child_height.max(child.height());
            computed_all_neg &= child.all_negative_certified();
        }
        if max_child_height.saturating_add(1) != self.height {
            return Err(WitnessError::MalformedWire(
                "hierarchical height disagrees with child heights".to_owned(),
            ));
        }
        if self.all_negative_certified != computed_all_neg {
            return Err(WitnessError::MalformedWire(
                "hierarchical certification flag contradicts children".to_owned(),
            ));
        }
        if self.compute_digest()? != self.witness_digest {
            return Err(WitnessError::ChecksumMismatch);
        }
        Ok(())
    }

    /// Verifies this hierarchy and every descendant against `oracle`.
    pub fn verify_against_oracle(
        &self,
        oracle: &LedgerOracle,
        cancelled: bool,
    ) -> Result<(), WitnessError> {
        if cancelled {
            return Err(WitnessError::Cancelled);
        }
        self.verify_self_invariants_depth(MAX_WITNESS_DEPTH)?;
        for child in &self.children {
            child.verify_against_oracle(oracle, cancelled)?;
        }
        Ok(())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.u8(3); // Hierarchical tag
        enc.text(&self.scope_label);
        self.anchor.encode_canonical(enc);
        enc.digest(self.history_root);
        enc.u32(self.height);
        enc.u64(self.children.len() as u64);
        for child in &self.children {
            child.encode_inner(enc);
        }
        enc.bool(self.all_negative_certified);
    }

    fn decode_body(
        dec: &mut CanonicalDecoder<'_>,
        remaining_depth: u32,
    ) -> Result<Self, WitnessError> {
        if remaining_depth == 0 {
            return Err(WitnessError::BoundsExceeded {
                observed: (MAX_WITNESS_DEPTH + 1) as usize,
                maximum: MAX_WITNESS_DEPTH as usize,
            });
        }
        let scope_label = dec
            .text()
            .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
        if scope_label.is_empty() || scope_label.len() > MAX_WITNESS_LABEL_BYTES {
            return Err(WitnessError::BoundsExceeded {
                observed: scope_label.len(),
                maximum: MAX_WITNESS_LABEL_BYTES,
            });
        }
        let anchor = LedgerAnchor::decode_canonical(dec)
            .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
        validate_anchor_bounds(&anchor)?;
        let history_root = dec
            .digest()
            .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
        let height = dec
            .u32()
            .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
        if height == 0 || height > MAX_WITNESS_DEPTH {
            return Err(WitnessError::BoundsExceeded {
                observed: height as usize,
                maximum: MAX_WITNESS_DEPTH as usize,
            });
        }
        let child_count = usize::try_from(
            dec.u64()
                .map_err(|err| WitnessError::MalformedWire(err.to_string()))?,
        )
        .map_err(|_| WitnessError::BoundsExceeded {
            observed: usize::MAX,
            maximum: MAX_HIERARCHICAL_CHILDREN,
        })?;
        // Each encoded child witness takes at least 64 bytes (tag + anchor + history_root + digest).
        if child_count == 0
            || child_count > MAX_HIERARCHICAL_CHILDREN
            || child_count.saturating_mul(64) > dec.remaining()
        {
            return Err(WitnessError::BoundsExceeded {
                observed: child_count,
                maximum: MAX_HIERARCHICAL_CHILDREN,
            });
        }
        let mut children = Vec::with_capacity(child_count);
        let mut seen_digests = BTreeSet::new();
        let mut max_child_height = 0u32;
        for _ in 0..child_count {
            let child = SemanticWitness::decode_inner(dec, remaining_depth - 1)?;
            if child.anchor() != &anchor || child.history_root() != history_root {
                return Err(WitnessError::MixedAnchorInHierarchy);
            }
            if !seen_digests.insert(child.witness_digest()) {
                return Err(WitnessError::MalformedWire(
                    "duplicate child witness in hierarchy".to_owned(),
                ));
            }
            max_child_height = max_child_height.max(child.height());
            children.push(child);
        }
        if !children
            .windows(2)
            .all(|pair| pair[0].witness_digest() < pair[1].witness_digest())
        {
            return Err(WitnessError::MalformedWire(
                "hierarchical children are not in canonical digest order".to_owned(),
            ));
        }
        if max_child_height.saturating_add(1) != height {
            return Err(WitnessError::MalformedWire(
                "hierarchical height disagrees with child heights".to_owned(),
            ));
        }
        let all_negative_certified = dec
            .bool()
            .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
        let computed_neg = children.iter().all(SemanticWitness::all_negative_certified);
        if all_negative_certified != computed_neg {
            return Err(WitnessError::MalformedWire(
                "hierarchical certification flag contradicts children".to_owned(),
            ));
        }
        let stored_digest = dec
            .digest()
            .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
        let witness = Self {
            scope_label: scope_label.to_owned(),
            anchor,
            history_root,
            height,
            children,
            all_negative_certified,
            witness_digest: stored_digest,
        };
        if witness.compute_digest()? != stored_digest {
            return Err(WitnessError::ChecksumMismatch);
        }
        Ok(witness)
    }
}

/// Unified typed semantic ledger witness covering positive, negative, and hierarchical proofs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SemanticWitness {
    /// Positive object-presence proof.
    Positive(PositiveWitness),
    /// Coverage-backed object-absence proof.
    Negative(NegativeWitness),
    /// Single-anchor hierarchical composition of child witnesses.
    Hierarchical(HierarchicalWitness),
}

impl SemanticWitness {
    /// Exact pinned canonical anchor.
    #[must_use]
    pub const fn anchor(&self) -> &LedgerAnchor {
        match self {
            Self::Positive(w) => &w.anchor,
            Self::Negative(w) => &w.anchor,
            Self::Hierarchical(w) => &w.anchor,
        }
    }

    /// Exact pinned canonical history-chain root.
    #[must_use]
    pub const fn history_root(&self) -> ContentDigest {
        match self {
            Self::Positive(w) => w.history_root,
            Self::Negative(w) => w.history_root,
            Self::Hierarchical(w) => w.history_root,
        }
    }

    /// Domain-separated commitment digest (`fss.ledger_semantic_witness.v1`).
    #[must_use]
    pub const fn witness_digest(&self) -> ContentDigest {
        match self {
            Self::Positive(w) => w.witness_digest,
            Self::Negative(w) => w.witness_digest,
            Self::Hierarchical(w) => w.witness_digest,
        }
    }

    /// Nesting height (`0` for leaf positive/negative witnesses; `>= 1` for hierarchical).
    #[must_use]
    pub const fn height(&self) -> u32 {
        match self {
            Self::Positive(_) | Self::Negative(_) => 0,
            Self::Hierarchical(w) => w.height,
        }
    }

    /// True iff no negative leaf in this witness is uncertified.
    #[must_use]
    pub const fn all_negative_certified(&self) -> bool {
        match self {
            Self::Positive(_) => true,
            Self::Negative(w) => w.certified,
            Self::Hierarchical(w) => w.all_negative_certified,
        }
    }

    /// Verifies this witness against `oracle`.
    pub fn verify_against_oracle(
        &self,
        oracle: &LedgerOracle,
        cancelled: bool,
    ) -> Result<(), WitnessError> {
        if cancelled {
            return Err(WitnessError::Cancelled);
        }
        match self {
            Self::Positive(w) => w.verify_against_oracle(oracle),
            Self::Negative(w) => w.verify_against_oracle(oracle),
            Self::Hierarchical(w) => w.verify_against_oracle(oracle, cancelled),
        }
    }

    /// Verifies all local structural, Merkle, coverage, and digest invariants recursively.
    pub fn verify_self_invariants(&self) -> Result<(), WitnessError> {
        self.verify_self_invariants_depth(MAX_WITNESS_DEPTH)
    }

    fn verify_self_invariants_depth(&self, remaining_depth: u32) -> Result<(), WitnessError> {
        match self {
            Self::Positive(w) => w.verify_self_invariants(),
            Self::Negative(w) => w.verify_self_invariants(),
            Self::Hierarchical(w) => w.verify_self_invariants_depth(remaining_depth),
        }
    }

    /// Encodes this witness into bounded, checksummed binary wire bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, WitnessError> {
        self.verify_self_invariants()?;
        let mut enc = CanonicalEncoder::new();
        self.encode_inner(&mut enc);
        let body = enc
            .finish_checked()
            .map_err(|err| WitnessError::Encoding(err.to_string()))?;
        let total = SEMANTIC_WITNESS_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_WITNESS_WIRE_BYTES {
            return Err(WitnessError::BoundsExceeded {
                observed: total,
                maximum: MAX_WITNESS_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&SEMANTIC_WITNESS_MAGIC);
        out.extend_from_slice(&SEMANTIC_WITNESS_VERSION.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and verifies a binary [`SemanticWitness`].
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, WitnessError> {
        if bytes.len() > MAX_WITNESS_WIRE_BYTES {
            return Err(WitnessError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_WITNESS_WIRE_BYTES,
            });
        }
        if bytes.len() < 12 || bytes[..8] != SEMANTIC_WITNESS_MAGIC {
            return Err(WitnessError::InvalidMagic);
        }
        let version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if version != SEMANTIC_WITNESS_VERSION {
            return Err(WitnessError::UnsupportedVersion { version });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let witness = Self::decode_inner(&mut dec, MAX_WITNESS_DEPTH)?;
        dec.ensure_finished()
            .map_err(|_| WitnessError::MalformedWire("trailing bytes after witness".to_owned()))?;
        Ok(witness)
    }

    fn encode_inner(&self, enc: &mut CanonicalEncoder) {
        match self {
            Self::Positive(w) => {
                w.encode_body(enc);
                enc.digest(w.witness_digest);
            }
            Self::Negative(w) => {
                w.encode_body(enc);
                enc.digest(w.witness_digest);
            }
            Self::Hierarchical(w) => {
                w.encode_body(enc);
                enc.digest(w.witness_digest);
            }
        }
    }

    fn decode_inner(
        dec: &mut CanonicalDecoder<'_>,
        remaining_depth: u32,
    ) -> Result<Self, WitnessError> {
        match dec
            .u8()
            .map_err(|err| WitnessError::MalformedWire(err.to_string()))?
        {
            1 => Ok(Self::Positive(PositiveWitness::decode_body(dec)?)),
            2 => Ok(Self::Negative(NegativeWitness::decode_body(dec)?)),
            3 => Ok(Self::Hierarchical(HierarchicalWitness::decode_body(
                dec,
                remaining_depth,
            )?)),
            other => Err(WitnessError::MalformedWire(format!(
                "unknown witness tag {other}"
            ))),
        }
    }
}

fn validate_anchor_bounds(anchor: &LedgerAnchor) -> Result<(), WitnessError> {
    if anchor.site_lineage.is_empty() || anchor.site_lineage.len() > MAX_ORACLE_TEXT_BYTES {
        return Err(WitnessError::BoundsExceeded {
            observed: anchor.site_lineage.len(),
            maximum: MAX_ORACLE_TEXT_BYTES,
        });
    }
    Ok(())
}

fn decode_object_revision(dec: &mut CanonicalDecoder<'_>) -> Result<ObjectRevision, WitnessError> {
    let generation = dec
        .u64()
        .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
    let family = dec
        .text()
        .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
    if family.is_empty() || family.len() > MAX_ORACLE_TEXT_BYTES {
        return Err(WitnessError::BoundsExceeded {
            observed: family.len(),
            maximum: MAX_ORACLE_TEXT_BYTES,
        });
    }
    let plane = decode_plane(dec)
        .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
    let payload_digest = dec
        .digest()
        .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
    let validity = CaptureInterval::decode_canonical(dec)
        .map_err(|err| WitnessError::MalformedWire(err.to_string()))?;
    Ok(ObjectRevision {
        generation,
        family: family.to_owned(),
        plane,
        payload_digest,
        validity,
    })
}
