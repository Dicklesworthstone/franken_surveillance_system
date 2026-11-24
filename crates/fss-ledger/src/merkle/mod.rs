#![forbid(unsafe_code)]
//! Canonical domain-separated 16-ary path-compressed Radix-Merkle accumulator.
//!
//! Every live (including tombstoned) [`ObjectId`] is keyed by its 256-bit domain-separated
//! hash (`key_hash = sha256(DOMAIN_KEY || canonical_object_id)`) and stored in a deterministic
//! 64-level nibble-indexed radix trie. Updating `k` objects touches only `O(k log N)` nodes,
//! yields an order-independent canonical state root, and supports standalone `O(log N)`
//! inclusion and non-inclusion [`MerkleProof`] generation and verification.

mod proof;
mod snapshot;
mod trie;

#[cfg(test)]
mod tests;

use std::error::Error;
use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    ContentDigest, ContractError, DigestAlgorithm, LedgerAnchor, MAX_CANONICAL_TEXT_BYTES,
    ObjectId, ObjectRevision, Plane, Sha256Hasher,
};

pub use proof::{
    MerkleNodeSnapshot, MerkleProof, MerkleProofError, MerkleProofKind, MerkleProofStep,
    NonInclusionReason, verify_proof,
};
pub use trie::RadixMerkleTrie;

/// Registered canonical digest domain for keying [`ObjectId`]s into the v2 radix-Merkle trie.
pub const MERKLE_KEY_DOMAIN: &str = "fss.ledger.merkle.key.v2";
/// Registered canonical digest domain for v2 radix-Merkle leaf digests.
pub const MERKLE_LEAF_DOMAIN: &str = "fss.ledger.merkle.leaf.v2";
/// Registered canonical digest domain for v2 radix-Merkle internal node digests.
pub const MERKLE_NODE_DOMAIN: &str = "fss.ledger.merkle.node.v2";
/// Registered canonical digest domain for the empty v2 radix-Merkle tree root.
pub const MERKLE_EMPTY_DOMAIN: &str = "fss.ledger.merkle.empty.v2";

/// Number of nibble levels in a 256-bit SHA-256 key hash.
pub const KEY_NIBBLE_LEN: usize = 64;

/// Errors raised during radix-Merkle trie operations or snapshot decoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MerkleError {
    /// Two distinct [`ObjectId`]s hashed to the same 256-bit key hash.
    KeyHashCollision {
        /// Existing object identity in the trie.
        existing: ObjectId,
        /// Offered distinct object identity with the same key hash.
        offered: ObjectId,
    },
    /// Canonical encoding or decoding violated a core contract bound.
    Contract(ContractError),
    /// A serialized trie snapshot violated a structural invariant.
    InvalidSnapshot(&'static str),
}

impl fmt::Display for MerkleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyHashCollision { existing, offered } => write!(
                formatter,
                "merkle key-hash collision between {existing} and {offered}"
            ),
            Self::Contract(error) => write!(formatter, "merkle canonical contract error: {error}"),
            Self::InvalidSnapshot(reason) => {
                write!(formatter, "invalid merkle trie snapshot: {reason}")
            }
        }
    }
}

impl Error for MerkleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::KeyHashCollision { .. } | Self::InvalidSnapshot(_) => None,
        }
    }
}

impl From<ContractError> for MerkleError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

/// Computes the canonical empty v2 radix-Merkle tree root.
#[must_use]
pub fn empty_root() -> ContentDigest {
    let mut hasher = Sha256Hasher::new();
    hash_canonical_text(&mut hasher, MERKLE_EMPTY_DOMAIN);
    finalize_sha256_digest(hasher)
}

/// Constructs the v2 genesis [`LedgerAnchor`] bound to [`empty_root`].
#[must_use]
pub fn merkle_genesis_anchor(site_lineage: impl Into<String>) -> LedgerAnchor {
    LedgerAnchor {
        site_lineage: site_lineage.into(),
        ledger_epoch: 0,
        commit_sequence: 0,
        adapter_registry_epoch: 0,
        schema_epoch: 1,
        policy_epoch: 1,
        privacy_epoch: 1,
        state_root: empty_root(),
    }
}

/// Computes `sha256(DOMAIN_KEY || canonical_object_id)` for indexing `object_id` in the trie.
#[must_use]
pub fn key_hash_for_object(object_id: &ObjectId) -> [u8; 32] {
    let mut hasher = Sha256Hasher::new();
    hash_canonical_text(&mut hasher, MERKLE_KEY_DOMAIN);
    hash_canonical_text(&mut hasher, object_id.as_str());
    finalize_sha256_bytes(hasher)
}

/// Returns the nibble (`0..16`) at index `depth` (`0..64`) of a 32-byte key hash.
#[must_use]
#[inline]
pub const fn nibble_at(key_hash: &[u8; 32], depth: usize) -> u8 {
    let byte = key_hash[depth / 2];
    if depth.is_multiple_of(2) {
        byte >> 4
    } else {
        byte & 0x0f
    }
}

/// Expands a 32-byte key hash into its 64 big-endian nibbles (`0..16`).
#[must_use]
pub fn expand_nibbles(key_hash: &[u8; 32]) -> [u8; KEY_NIBBLE_LEN] {
    let mut nibbles = [0_u8; KEY_NIBBLE_LEN];
    let mut idx = 0;
    while idx < 32 {
        nibbles[idx * 2] = key_hash[idx] >> 4;
        nibbles[idx * 2 + 1] = key_hash[idx] & 0x0f;
        idx += 1;
    }
    nibbles
}

/// Computes `sha256(DOMAIN_LEAF || canonical_object_id || canonical_object_revision)`.
pub fn leaf_digest(
    object_id: &ObjectId,
    revision: &ObjectRevision,
) -> Result<ContentDigest, MerkleError> {
    if object_id.as_str().len() > MAX_CANONICAL_TEXT_BYTES
        || revision.family.len() > MAX_CANONICAL_TEXT_BYTES
    {
        return Err(MerkleError::Contract(ContractError::InvalidIdentifier));
    }
    let mut hasher = Sha256Hasher::new();
    hash_canonical_text(&mut hasher, MERKLE_LEAF_DOMAIN);
    hash_canonical_text(&mut hasher, object_id.as_str());
    hasher.update(&revision.generation.to_be_bytes());
    hash_canonical_text(&mut hasher, &revision.family);
    hash_canonical_text(&mut hasher, revision.plane.as_str());
    hash_canonical_digest(&mut hasher, revision.payload_digest);
    hasher.update(&revision.validity.earliest.0.to_be_bytes());
    hasher.update(&revision.validity.latest.0.to_be_bytes());
    Ok(finalize_sha256_digest(hasher))
}

/// Computes `sha256(DOMAIN_NODE || depth || path_prefix_nibbles || child_bitmap_u16 || children...)`.
///
/// `child_digests` must be supplied in strictly ascending nibble order matching the set bits of
/// `child_bitmap`.
pub fn internal_node_digest(
    depth: u8,
    path_prefix_nibbles: &[u8],
    child_bitmap: u16,
    child_digests: &[ContentDigest],
) -> Result<ContentDigest, MerkleError> {
    if usize::from(depth) >= KEY_NIBBLE_LEN {
        return Err(MerkleError::InvalidSnapshot("internal node depth >= 64"));
    }
    if path_prefix_nibbles.len() > usize::from(depth) {
        return Err(MerkleError::InvalidSnapshot(
            "path prefix longer than node depth",
        ));
    }
    if path_prefix_nibbles.iter().any(|&nibble| nibble >= 16) {
        return Err(MerkleError::InvalidSnapshot("nibble value >= 16"));
    }
    let expected_children = usize::try_from(child_bitmap.count_ones())
        .map_err(|_| MerkleError::InvalidSnapshot("child count conversion overflow"))?;
    if expected_children < 2 || child_digests.len() != expected_children {
        return Err(MerkleError::InvalidSnapshot(
            "internal node child count mismatch",
        ));
    }

    let mut hasher = Sha256Hasher::new();
    hash_canonical_text(&mut hasher, MERKLE_NODE_DOMAIN);
    hasher.update(&[depth]);
    hash_canonical_bytes(&mut hasher, path_prefix_nibbles);
    hasher.update(&child_bitmap.to_be_bytes());
    for digest in child_digests {
        hash_canonical_digest(&mut hasher, *digest);
    }
    Ok(finalize_sha256_digest(hasher))
}

/// Encodes an [`ObjectRevision`] canonically matching `ObjectRevision::encode_canonical`.
pub(crate) fn encode_object_revision(revision: &ObjectRevision, encoder: &mut CanonicalEncoder) {
    revision.encode_canonical(encoder);
}

/// Decodes an [`ObjectRevision`] from canonical bytes encoded by [`encode_object_revision`].
pub(crate) fn decode_object_revision(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<ObjectRevision, ContractError> {
    let generation = decoder.u64()?;
    let family = decoder.text()?.to_owned();
    if family.is_empty() {
        return Err(ContractError::InvalidIdentifier);
    }
    let plane = decode_plane(decoder)?;
    let payload_digest = decoder.digest()?;
    let validity = CaptureInterval::decode_canonical(decoder)?;
    Ok(ObjectRevision {
        generation,
        family,
        plane,
        payload_digest,
        validity,
    })
}

/// Decodes a [`Plane`] from its canonical text representation.
pub(crate) fn decode_plane(decoder: &mut CanonicalDecoder<'_>) -> Result<Plane, ContractError> {
    match decoder.text()? {
        "authority" => Ok(Plane::Authority),
        "cognition" => Ok(Plane::Cognition),
        "effect" => Ok(Plane::Effect),
        _ => Err(ContractError::InvalidIdentifier),
    }
}

#[inline]
fn hash_canonical_bytes(hasher: &mut Sha256Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[inline]
fn hash_canonical_text(hasher: &mut Sha256Hasher, text: &str) {
    hash_canonical_bytes(hasher, text.as_bytes());
}

#[inline]
fn hash_canonical_digest(hasher: &mut Sha256Hasher, digest: ContentDigest) {
    let tag: u8 = match digest.algorithm() {
        DigestAlgorithm::Sha256 => 1,
        DigestAlgorithm::Blake3 => 2,
    };
    hasher.update(&[tag]);
    hasher.update(&digest.bytes());
}

#[inline]
fn finalize_sha256_bytes(hasher: Sha256Hasher) -> [u8; 32] {
    // Single node / key / leaf inputs are strictly bounded to tens of kilobytes,
    // far below the SHA-256 2^61-byte FIPS limit.
    hasher.finalize().unwrap_or_default()
}

#[inline]
fn finalize_sha256_digest(hasher: Sha256Hasher) -> ContentDigest {
    ContentDigest::new(DigestAlgorithm::Sha256, finalize_sha256_bytes(hasher))
}
