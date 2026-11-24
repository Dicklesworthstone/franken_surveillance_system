#![forbid(unsafe_code)]
//! Standalone `O(log N)` Merkle inclusion and non-inclusion proofs and verifier.

use std::error::Error;
use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, ObjectId, ObjectRevision,
};

use super::{
    KEY_NIBBLE_LEN, MerkleError, decode_object_revision, empty_root, encode_object_revision,
    internal_node_digest, key_hash_for_object, leaf_digest, nibble_at,
};

/// One internal-node hop along the root-to-target path in a [`MerkleProof`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleProofStep {
    /// Branching nibble depth (`0..64`) of this internal node.
    pub depth: u8,
    /// Compressed nibble prefix (`[start_depth..depth)`), each nibble in `0..16`.
    pub path_prefix: Vec<u8>,
    /// Populated-child bitmask (`count_ones() >= 2`).
    pub child_bitmap: u16,
    /// Non-empty sibling digests in ascending nibble order, excluding the target branch nibble.
    pub sibling_digests: Vec<ContentDigest>,
}

/// Complete digest snapshot of a terminal internal node witnessing non-inclusion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleNodeSnapshot {
    /// Branching nibble depth (`0..64`) of the terminal internal node.
    pub depth: u8,
    /// Compressed nibble prefix (`[start_depth..depth)`), each nibble in `0..16`.
    pub path_prefix: Vec<u8>,
    /// Populated-child bitmask (`count_ones() >= 2`).
    pub child_bitmap: u16,
    /// All non-empty child digests in ascending nibble order.
    pub child_digests: Vec<ContentDigest>,
}

/// Cryptographic reason proving a queried [`ObjectId`] is absent from the trie.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NonInclusionReason {
    /// The trie is completely empty (`root == empty_root()`).
    EmptyTree,
    /// The path reached a leaf belonging to a different [`ObjectId`].
    DifferentLeaf {
        /// Object identity residing at the terminal leaf slot.
        existing_object_id: ObjectId,
        /// Revision committed for `existing_object_id`.
        existing_revision: ObjectRevision,
    },
    /// The path reached an internal node whose child slot for the target nibble is empty.
    EmptyChildSlot {
        /// Complete digest snapshot of the terminal internal node.
        terminal_node: MerkleNodeSnapshot,
    },
    /// The path diverged inside a compressed internal node prefix.
    PrefixMismatch {
        /// Complete digest snapshot of the terminal internal node.
        terminal_node: MerkleNodeSnapshot,
    },
}

/// Payload distinguishing an inclusion proof from a non-inclusion proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MerkleProofKind {
    /// Proves that the queried [`ObjectId`] is present with the exact `revision`.
    Inclusion {
        /// Committed revision of the queried object (which may be a tombstoned revision).
        revision: ObjectRevision,
    },
    /// Proves that the queried [`ObjectId`] does not exist in the trie.
    NonInclusion(NonInclusionReason),
}

/// Standalone `O(log N)` inclusion or non-inclusion proof against a v2 Merkle state root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleProof {
    /// Inclusion or non-inclusion witness payload.
    pub kind: MerkleProofKind,
    /// Root-to-terminal internal node proof hops in top-down order.
    pub steps: Vec<MerkleProofStep>,
}

impl MerkleProof {
    /// Returns true if this proof attests inclusion of the queried object.
    #[must_use]
    pub const fn is_inclusion(&self) -> bool {
        matches!(self.kind, MerkleProofKind::Inclusion { .. })
    }

    /// Returns the proven [`ObjectRevision`] if this is an inclusion proof.
    #[must_use]
    pub const fn included_revision(&self) -> Option<&ObjectRevision> {
        match &self.kind {
            MerkleProofKind::Inclusion { revision } => Some(revision),
            MerkleProofKind::NonInclusion(_) => None,
        }
    }
}

/// Typed rejection returned by [`verify_proof`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MerkleProofError {
    /// An internal node depth is out of `0..64` or not strictly monotone down the path.
    InvalidDepth,
    /// A compressed path prefix does not match its expected length or contains invalid nibbles.
    InvalidPathPrefix,
    /// A step's compressed prefix does not match the queried key hash.
    PathMismatch,
    /// An internal node has fewer than two populated children.
    DegenerateInternalNode,
    /// The queried branch nibble bit is unset in an ancestor step's bitmap.
    BranchBitUnset,
    /// Sibling or child digest count does not match the child bitmap.
    ChildDigestCountMismatch,
    /// A non-inclusion proof named the queried object itself as the colliding leaf.
    KeyActuallyIncluded,
    /// The existing leaf in a `DifferentLeaf` non-inclusion proof does not lie on the proved path.
    ExistingLeafPathMismatch,
    /// An `EmptyChildSlot` proof named a slot that is actually occupied in the bitmap.
    ChildSlotNotEmpty,
    /// A `PrefixMismatch` proof had a prefix that actually matched the queried key.
    PrefixActuallyMatches,
    /// An `EmptyTree` proof carried non-empty path steps.
    NonEmptyStepsForEmptyTree,
    /// Reconstructed root digest does not equal the trusted state root.
    RootMismatch {
        /// Trusted root supplied by the verifier.
        expected: ContentDigest,
        /// Root reconstructed from the proof.
        computed: ContentDigest,
    },
    /// Underlying hashing or canonical-encoding contract failure.
    Merkle(MerkleError),
}

impl fmt::Display for MerkleProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDepth => formatter.write_str("merkle proof has invalid node depth"),
            Self::InvalidPathPrefix => {
                formatter.write_str("merkle proof has invalid compressed path prefix")
            }
            Self::PathMismatch => {
                formatter.write_str("merkle proof path prefix does not match queried key")
            }
            Self::DegenerateInternalNode => {
                formatter.write_str("merkle proof internal node has fewer than 2 children")
            }
            Self::BranchBitUnset => {
                formatter.write_str("merkle proof branch bit is unset in ancestor bitmap")
            }
            Self::ChildDigestCountMismatch => {
                formatter.write_str("merkle proof child digest count mismatches bitmap")
            }
            Self::KeyActuallyIncluded => {
                formatter.write_str("non-inclusion proof references the queried object itself")
            }
            Self::ExistingLeafPathMismatch => {
                formatter.write_str("non-inclusion leaf does not lie on the verified trie path")
            }
            Self::ChildSlotNotEmpty => {
                formatter.write_str("empty-child-slot proof points to a populated child slot")
            }
            Self::PrefixActuallyMatches => {
                formatter.write_str("prefix-mismatch proof prefix actually matches queried key")
            }
            Self::NonEmptyStepsForEmptyTree => {
                formatter.write_str("empty-tree non-inclusion proof must have zero steps")
            }
            Self::RootMismatch { expected, computed } => write!(
                formatter,
                "merkle proof root mismatch: expected {expected}, computed {computed}"
            ),
            Self::Merkle(error) => write!(formatter, "merkle proof hash error: {error}"),
        }
    }
}

impl Error for MerkleProofError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Merkle(error) => Some(error),
            _ => None,
        }
    }
}

impl From<MerkleError> for MerkleProofError {
    fn from(value: MerkleError) -> Self {
        Self::Merkle(value)
    }
}

/// Independently verifies a [`MerkleProof`] for `object_id` against `expected_root`.
pub fn verify_proof(
    expected_root: ContentDigest,
    object_id: &ObjectId,
    proof: &MerkleProof,
) -> Result<(), MerkleProofError> {
    let query_hash = key_hash_for_object(object_id);

    if let MerkleProofKind::NonInclusion(NonInclusionReason::EmptyTree) = &proof.kind {
        if !proof.steps.is_empty() {
            return Err(MerkleProofError::NonEmptyStepsForEmptyTree);
        }
        let empty = empty_root();
        if empty != expected_root {
            return Err(MerkleProofError::RootMismatch {
                expected: expected_root,
                computed: empty,
            });
        }
        return Ok(());
    }

    let next_start_depth = validate_ancestor_steps(&proof.steps, &query_hash)?;

    let terminal_digest = match &proof.kind {
        MerkleProofKind::Inclusion { revision } => leaf_digest(object_id, revision)?,
        MerkleProofKind::NonInclusion(NonInclusionReason::EmptyTree) => {
            return Err(MerkleProofError::NonEmptyStepsForEmptyTree);
        }
        MerkleProofKind::NonInclusion(NonInclusionReason::DifferentLeaf {
            existing_object_id,
            existing_revision,
        }) => {
            if existing_object_id == object_id {
                return Err(MerkleProofError::KeyActuallyIncluded);
            }
            let existing_hash = key_hash_for_object(existing_object_id);
            verify_hash_matches_steps(&proof.steps, &existing_hash)?;
            leaf_digest(existing_object_id, existing_revision)?
        }
        MerkleProofKind::NonInclusion(NonInclusionReason::EmptyChildSlot { terminal_node }) => {
            verify_terminal_snapshot_header(terminal_node, next_start_depth)?;
            let prefix_matches = terminal_node
                .path_prefix
                .iter()
                .enumerate()
                .all(|(off, &n)| nibble_at(&query_hash, next_start_depth + off) == n);
            if !prefix_matches {
                return Err(MerkleProofError::PathMismatch);
            }
            let target_nibble = nibble_at(&query_hash, usize::from(terminal_node.depth));
            if (terminal_node.child_bitmap & (1_u16 << target_nibble)) != 0 {
                return Err(MerkleProofError::ChildSlotNotEmpty);
            }
            internal_node_digest(
                terminal_node.depth,
                &terminal_node.path_prefix,
                terminal_node.child_bitmap,
                &terminal_node.child_digests,
            )?
        }
        MerkleProofKind::NonInclusion(NonInclusionReason::PrefixMismatch { terminal_node }) => {
            verify_terminal_snapshot_header(terminal_node, next_start_depth)?;
            if terminal_node.path_prefix.is_empty() {
                return Err(MerkleProofError::PrefixActuallyMatches);
            }
            let diverges = terminal_node
                .path_prefix
                .iter()
                .enumerate()
                .any(|(off, &n)| nibble_at(&query_hash, next_start_depth + off) != n);
            if !diverges {
                return Err(MerkleProofError::PrefixActuallyMatches);
            }
            internal_node_digest(
                terminal_node.depth,
                &terminal_node.path_prefix,
                terminal_node.child_bitmap,
                &terminal_node.child_digests,
            )?
        }
    };

    let mut current_digest = terminal_digest;
    for step in proof.steps.iter().rev() {
        let branch_nibble = nibble_at(&query_hash, usize::from(step.depth));
        current_digest = fold_proof_step(step, branch_nibble, current_digest)?;
    }

    if current_digest != expected_root {
        return Err(MerkleProofError::RootMismatch {
            expected: expected_root,
            computed: current_digest,
        });
    }
    Ok(())
}

fn validate_ancestor_steps(
    steps: &[MerkleProofStep],
    query_hash: &[u8; 32],
) -> Result<usize, MerkleProofError> {
    let mut start_depth = 0_usize;
    for step in steps {
        let depth = usize::from(step.depth);
        if depth >= KEY_NIBBLE_LEN || depth < start_depth {
            return Err(MerkleProofError::InvalidDepth);
        }
        if step.path_prefix.len() != depth - start_depth
            || step.path_prefix.iter().any(|&n| n >= 16)
        {
            return Err(MerkleProofError::InvalidPathPrefix);
        }
        for (offset, &expected_nibble) in step.path_prefix.iter().enumerate() {
            if nibble_at(query_hash, start_depth + offset) != expected_nibble {
                return Err(MerkleProofError::PathMismatch);
            }
        }
        let child_count = usize::try_from(step.child_bitmap.count_ones())
            .map_err(|_| MerkleProofError::ChildDigestCountMismatch)?;
        if child_count < 2 {
            return Err(MerkleProofError::DegenerateInternalNode);
        }
        let branch_nibble = nibble_at(query_hash, depth);
        if (step.child_bitmap & (1_u16 << branch_nibble)) == 0 {
            return Err(MerkleProofError::BranchBitUnset);
        }
        if step.sibling_digests.len() != child_count - 1 {
            return Err(MerkleProofError::ChildDigestCountMismatch);
        }
        start_depth = depth + 1;
    }
    Ok(start_depth)
}

fn verify_hash_matches_steps(
    steps: &[MerkleProofStep],
    key_hash: &[u8; 32],
) -> Result<(), MerkleProofError> {
    let mut start_depth = 0_usize;
    for step in steps {
        let depth = usize::from(step.depth);
        for (offset, &expected_nibble) in step.path_prefix.iter().enumerate() {
            if nibble_at(key_hash, start_depth + offset) != expected_nibble {
                return Err(MerkleProofError::ExistingLeafPathMismatch);
            }
        }
        let branch_nibble = nibble_at(key_hash, depth);
        if (step.child_bitmap & (1_u16 << branch_nibble)) == 0 {
            return Err(MerkleProofError::ExistingLeafPathMismatch);
        }
        start_depth = depth + 1;
    }
    Ok(())
}

fn verify_terminal_snapshot_header(
    snapshot: &MerkleNodeSnapshot,
    start_depth: usize,
) -> Result<(), MerkleProofError> {
    let depth = usize::from(snapshot.depth);
    if depth >= KEY_NIBBLE_LEN || depth < start_depth {
        return Err(MerkleProofError::InvalidDepth);
    }
    if snapshot.path_prefix.len() != depth - start_depth
        || snapshot.path_prefix.iter().any(|&n| n >= 16)
    {
        return Err(MerkleProofError::InvalidPathPrefix);
    }
    let child_count = usize::try_from(snapshot.child_bitmap.count_ones())
        .map_err(|_| MerkleProofError::ChildDigestCountMismatch)?;
    if child_count < 2 {
        return Err(MerkleProofError::DegenerateInternalNode);
    }
    if snapshot.child_digests.len() != child_count {
        return Err(MerkleProofError::ChildDigestCountMismatch);
    }
    Ok(())
}

fn fold_proof_step(
    step: &MerkleProofStep,
    branch_nibble: u8,
    child_digest: ContentDigest,
) -> Result<ContentDigest, MerkleProofError> {
    let mut child_digests = Vec::with_capacity(step.sibling_digests.len() + 1);
    let mut siblings = step.sibling_digests.iter().copied();
    for nibble in 0_u8..16 {
        if (step.child_bitmap & (1_u16 << nibble)) != 0 {
            if nibble == branch_nibble {
                child_digests.push(child_digest);
            } else {
                let sibling = siblings
                    .next()
                    .ok_or(MerkleProofError::ChildDigestCountMismatch)?;
                child_digests.push(sibling);
            }
        }
    }
    if siblings.next().is_some() {
        return Err(MerkleProofError::ChildDigestCountMismatch);
    }
    Ok(internal_node_digest(
        step.depth,
        &step.path_prefix,
        step.child_bitmap,
        &child_digests,
    )?)
}

impl CanonicalEncode for MerkleProofStep {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(self.depth);
        encoder.bytes(&self.path_prefix);
        encoder.u8((self.child_bitmap >> 8) as u8);
        encoder.u8((self.child_bitmap & 0xff) as u8);
        encoder.u64(self.sibling_digests.len() as u64);
        for digest in &self.sibling_digests {
            encoder.digest(*digest);
        }
    }
}

impl CanonicalDecode for MerkleProofStep {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let depth = decoder.u8()?;
        let path_prefix = decoder.bytes()?.to_vec();
        let hi = decoder.u8()?;
        let lo = decoder.u8()?;
        let child_bitmap = u16::from_be_bytes([hi, lo]);
        let count = usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidDigest)?;
        if count > 16 {
            return Err(ContractError::InvalidDigest);
        }
        let mut sibling_digests = Vec::with_capacity(count);
        for _ in 0..count {
            sibling_digests.push(decoder.digest()?);
        }
        Ok(Self {
            depth,
            path_prefix,
            child_bitmap,
            sibling_digests,
        })
    }
}

impl CanonicalEncode for MerkleNodeSnapshot {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u8(self.depth);
        encoder.bytes(&self.path_prefix);
        encoder.u8((self.child_bitmap >> 8) as u8);
        encoder.u8((self.child_bitmap & 0xff) as u8);
        encoder.u64(self.child_digests.len() as u64);
        for digest in &self.child_digests {
            encoder.digest(*digest);
        }
    }
}

impl CanonicalDecode for MerkleNodeSnapshot {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let depth = decoder.u8()?;
        let path_prefix = decoder.bytes()?.to_vec();
        let hi = decoder.u8()?;
        let lo = decoder.u8()?;
        let child_bitmap = u16::from_be_bytes([hi, lo]);
        let count = usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidDigest)?;
        if count > 16 {
            return Err(ContractError::InvalidDigest);
        }
        let mut child_digests = Vec::with_capacity(count);
        for _ in 0..count {
            child_digests.push(decoder.digest()?);
        }
        Ok(Self {
            depth,
            path_prefix,
            child_bitmap,
            child_digests,
        })
    }
}

impl CanonicalEncode for MerkleProof {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        match &self.kind {
            MerkleProofKind::Inclusion { revision } => {
                encoder.tag(1);
                encode_object_revision(revision, encoder);
            }
            MerkleProofKind::NonInclusion(NonInclusionReason::EmptyTree) => {
                encoder.tag(2);
            }
            MerkleProofKind::NonInclusion(NonInclusionReason::DifferentLeaf {
                existing_object_id,
                existing_revision,
            }) => {
                encoder.tag(3);
                existing_object_id.encode_canonical(encoder);
                encode_object_revision(existing_revision, encoder);
            }
            MerkleProofKind::NonInclusion(NonInclusionReason::EmptyChildSlot { terminal_node }) => {
                encoder.tag(4);
                terminal_node.encode_canonical(encoder);
            }
            MerkleProofKind::NonInclusion(NonInclusionReason::PrefixMismatch { terminal_node }) => {
                encoder.tag(5);
                terminal_node.encode_canonical(encoder);
            }
        }
        encoder.u64(self.steps.len() as u64);
        for step in &self.steps {
            step.encode_canonical(encoder);
        }
    }
}

impl CanonicalDecode for MerkleProof {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let kind = match decoder.tag()? {
            1 => MerkleProofKind::Inclusion {
                revision: decode_object_revision(decoder)?,
            },
            2 => MerkleProofKind::NonInclusion(NonInclusionReason::EmptyTree),
            3 => MerkleProofKind::NonInclusion(NonInclusionReason::DifferentLeaf {
                existing_object_id: ObjectId::decode_canonical(decoder)?,
                existing_revision: decode_object_revision(decoder)?,
            }),
            4 => MerkleProofKind::NonInclusion(NonInclusionReason::EmptyChildSlot {
                terminal_node: MerkleNodeSnapshot::decode_canonical(decoder)?,
            }),
            5 => MerkleProofKind::NonInclusion(NonInclusionReason::PrefixMismatch {
                terminal_node: MerkleNodeSnapshot::decode_canonical(decoder)?,
            }),
            _ => return Err(ContractError::InvalidIdentifier),
        };
        let step_count =
            usize::try_from(decoder.u64()?).map_err(|_| ContractError::InvalidDigest)?;
        if step_count > KEY_NIBBLE_LEN {
            return Err(ContractError::InvalidDigest);
        }
        let mut steps = Vec::with_capacity(step_count);
        for _ in 0..step_count {
            steps.push(MerkleProofStep::decode_canonical(decoder)?);
        }
        Ok(Self { kind, steps })
    }
}
