#![forbid(unsafe_code)]
//! Unified [`CanonicalLedgerBackend`] trait implemented by both v1 [`LedgerOracle`] and
//! v2 [`MerkleEpochLedger`].

use std::error::Error;

use fss_core::{ContentDigest, EvidenceDeltaBatch, LedgerAnchor, ObjectId, ObjectRevision};

use crate::epochs::{EpochLedgerError, MerkleEpochLedger};
use crate::merkle::MerkleProof;
use crate::oracle::{CommitReceipt, LedgerOracle, OracleError};

/// Common canonical ledger backend surface implemented by both the v1 in-memory small-fixture
/// oracle ([`LedgerOracle`]) and the v2 segmented Radix-Merkle production engine
/// ([`MerkleEpochLedger`]).
pub trait CanonicalLedgerBackend {
    /// Typed backend error returned by admission, persistence, or proof operations.
    type Error: Error + Send + Sync + 'static;

    /// Returns the latest committed canonical [`LedgerAnchor`].
    fn head_anchor(&self) -> &LedgerAnchor;

    /// Returns the latest committed sequence number (`0` at genesis).
    fn commit_sequence(&self) -> u64 {
        self.head_anchor().commit_sequence
    }

    /// Returns the append-only canonical history-chain root through the head commit.
    fn history_root(&self) -> ContentDigest;

    /// Returns the canonical state root committed in the head anchor.
    fn state_root(&self) -> ContentDigest {
        self.head_anchor().state_root
    }

    /// Looks up the latest committed [`ObjectRevision`] for `object_id`, if present.
    fn get_object(&self, object_id: &ObjectId) -> Option<&ObjectRevision>;

    /// Returns the number of distinct live (including tombstoned) objects at the head.
    fn live_object_count(&self) -> u64;

    /// Validates and atomically commits one canonical [`EvidenceDeltaBatch`].
    fn append_batch(&mut self, batch: EvidenceDeltaBatch) -> Result<CommitReceipt, Self::Error>;

    /// Generates a standalone `O(log N)` Merkle inclusion or non-inclusion proof for `object_id`
    /// against [`Self::state_root`], when supported by the backend.
    ///
    /// Backends without a Merkle accumulator (such as v1 [`LedgerOracle`]) return `Ok(None)`.
    fn prove_object(&self, object_id: &ObjectId) -> Result<Option<MerkleProof>, Self::Error> {
        let _ = object_id;
        Ok(None)
    }

    /// Returns true if this backend maintains a Merkle state tree and emits [`MerkleProof`]s.
    fn supports_merkle_proofs(&self) -> bool {
        false
    }
}

impl CanonicalLedgerBackend for LedgerOracle {
    type Error = OracleError;

    fn head_anchor(&self) -> &LedgerAnchor {
        Self::head_anchor(self)
    }

    fn history_root(&self) -> ContentDigest {
        self.head_history_root()
    }

    fn get_object(&self, object_id: &ObjectId) -> Option<&ObjectRevision> {
        self.head_object(object_id)
    }

    fn live_object_count(&self) -> u64 {
        self.head_object_count() as u64
    }

    fn append_batch(&mut self, batch: EvidenceDeltaBatch) -> Result<CommitReceipt, Self::Error> {
        self.append(batch)
    }
}

impl CanonicalLedgerBackend for MerkleEpochLedger {
    type Error = EpochLedgerError;

    fn head_anchor(&self) -> &LedgerAnchor {
        Self::head_anchor(self)
    }

    fn history_root(&self) -> ContentDigest {
        Self::history_root(self)
    }

    fn get_object(&self, object_id: &ObjectId) -> Option<&ObjectRevision> {
        Self::get_object(self, object_id)
    }

    fn live_object_count(&self) -> u64 {
        Self::live_object_count(self)
    }

    fn append_batch(&mut self, batch: EvidenceDeltaBatch) -> Result<CommitReceipt, Self::Error> {
        Self::append_batch(self, batch)
    }

    fn prove_object(&self, object_id: &ObjectId) -> Result<Option<MerkleProof>, Self::Error> {
        Self::prove_object(self, object_id).map(Some)
    }

    fn supports_merkle_proofs(&self) -> bool {
        true
    }
}
