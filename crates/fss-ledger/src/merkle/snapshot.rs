#![forbid(unsafe_code)]
//! Compact structural snapshot encoding, decoding, and whole-trie digest verification.

use std::sync::Arc;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, ObjectId,
};

use super::trie::{InternalNode, LeafNode, RadixMerkleTrie, TrieNode};
use super::{
    KEY_NIBBLE_LEN, MerkleError, decode_object_revision, encode_object_revision,
    internal_node_digest, key_hash_for_object, leaf_digest, nibble_at,
};

const SNAPSHOT_TAG_EMPTY: u8 = 0;
const SNAPSHOT_TAG_LEAF: u8 = 1;
const SNAPSHOT_TAG_INTERNAL: u8 = 2;

impl RadixMerkleTrie {
    /// Encodes a compact, deterministic structural snapshot of this trie into `encoder`.
    ///
    /// Used by verified checkpoint files; [`Self::decode_snapshot`] validates all structural
    /// invariants and optionally recomputes every digest.
    pub(crate) fn encode_snapshot(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.len);
        match &self.root {
            None => encoder.tag(SNAPSHOT_TAG_EMPTY),
            Some(root) => encode_node_snapshot(root, encoder),
        }
    }

    /// Decodes a compact structural snapshot from `decoder`, verifying every structural invariant.
    ///
    /// When `verify_digests` is `true`, every leaf and internal node digest is independently
    /// recomputed from scratch; when `false` (used when the surrounding checkpoint's whole-file
    /// SHA-256 is already verified), all structural invariants, path-key consistency, object
    /// counts, and `expected_root` equality are still verified.
    pub(crate) fn decode_snapshot(
        decoder: &mut CanonicalDecoder<'_>,
        expected_root: ContentDigest,
        verify_digests: bool,
    ) -> Result<Self, MerkleError> {
        let declared_len = decoder.u64()?;
        let mut counted_leaves = 0_u64;
        let tag = decoder.tag()?;
        let root = match tag {
            SNAPSHOT_TAG_EMPTY => None,
            SNAPSHOT_TAG_LEAF | SNAPSHOT_TAG_INTERNAL => Some(decode_node_snapshot(
                decoder,
                tag,
                0,
                &mut Vec::new(),
                &mut counted_leaves,
                verify_digests,
            )?),
            _ => return Err(MerkleError::InvalidSnapshot("unknown trie node tag")),
        };
        if counted_leaves != declared_len {
            return Err(MerkleError::InvalidSnapshot(
                "leaf count mismatch in snapshot",
            ));
        }
        let trie = Self {
            root,
            len: counted_leaves,
        };
        if trie.root() != expected_root {
            return Err(MerkleError::InvalidSnapshot(
                "decoded trie root does not match expected merkle_state_root",
            ));
        }
        Ok(trie)
    }

    /// Recomputes and verifies every key hash, leaf digest, and internal node digest in the trie.
    pub fn verify_all_digests(&self) -> Result<(), MerkleError> {
        let Some(root) = &self.root else {
            return if self.len == 0 {
                Ok(())
            } else {
                Err(MerkleError::InvalidSnapshot("non-zero len on empty root"))
            };
        };
        let mut count = 0_u64;
        verify_node_recursive(root, 0, &mut Vec::new(), &mut count)?;
        if count != self.len {
            return Err(MerkleError::InvalidSnapshot("leaf count drift"));
        }
        Ok(())
    }
}

fn encode_node_snapshot(node: &TrieNode, encoder: &mut CanonicalEncoder) {
    match node {
        TrieNode::Leaf(leaf) => {
            encoder.tag(SNAPSHOT_TAG_LEAF);
            encoder.bytes(&leaf.key_hash);
            leaf.object_id.encode_canonical(encoder);
            encode_object_revision(&leaf.revision, encoder);
            encoder.digest(leaf.digest);
        }
        TrieNode::Internal(internal) => {
            encoder.tag(SNAPSHOT_TAG_INTERNAL);
            encoder.u8(internal.depth);
            encoder.bytes(&internal.prefix);
            encoder.u8((internal.child_bitmap >> 8) as u8);
            encoder.u8((internal.child_bitmap & 0xff) as u8);
            encoder.digest(internal.digest);
            for (nibble, child) in &internal.children {
                encoder.u8(*nibble);
                encode_node_snapshot(child, encoder);
            }
        }
    }
}

fn decode_node_snapshot(
    decoder: &mut CanonicalDecoder<'_>,
    tag: u8,
    start_depth: usize,
    path_nibbles: &mut Vec<u8>,
    counted_leaves: &mut u64,
    verify_digests: bool,
) -> Result<TrieNode, MerkleError> {
    match tag {
        SNAPSHOT_TAG_LEAF => {
            let key_slice = decoder.bytes()?;
            let key_hash: [u8; 32] = key_slice
                .try_into()
                .map_err(|_| MerkleError::InvalidSnapshot("leaf key_hash must be 32 bytes"))?;
            let object_id = ObjectId::decode_canonical(decoder)?;
            let revision = decode_object_revision(decoder)?;
            let digest = decoder.digest()?;

            for (idx, &expected_nibble) in path_nibbles.iter().enumerate() {
                if nibble_at(&key_hash, idx) != expected_nibble {
                    return Err(MerkleError::InvalidSnapshot(
                        "leaf key_hash does not match its trie path",
                    ));
                }
            }
            if verify_digests {
                if key_hash_for_object(&object_id) != key_hash {
                    return Err(MerkleError::InvalidSnapshot(
                        "leaf key_hash does not match object_id",
                    ));
                }
                if leaf_digest(&object_id, &revision)? != digest {
                    return Err(MerkleError::InvalidSnapshot("leaf digest mismatch"));
                }
            }

            *counted_leaves = counted_leaves
                .checked_add(1)
                .ok_or(MerkleError::Contract(ContractError::ArithmeticOverflow))?;
            Ok(TrieNode::Leaf(Arc::new(LeafNode {
                key_hash,
                object_id,
                revision,
                digest,
            })))
        }
        SNAPSHOT_TAG_INTERNAL => {
            let depth = decoder.u8()?;
            let depth_usize = usize::from(depth);
            if depth_usize >= KEY_NIBBLE_LEN || depth_usize < start_depth {
                return Err(MerkleError::InvalidSnapshot("invalid internal node depth"));
            }
            let prefix = decoder.bytes()?.to_vec();
            if prefix.len() != depth_usize - start_depth {
                return Err(MerkleError::InvalidSnapshot(
                    "internal node prefix mismatch",
                ));
            }
            if prefix.iter().any(|&n| n >= 16) {
                return Err(MerkleError::InvalidSnapshot("invalid prefix nibble"));
            }
            let hi = decoder.u8()?;
            let lo = decoder.u8()?;
            let child_bitmap = u16::from_be_bytes([hi, lo]);
            let child_count = usize::try_from(child_bitmap.count_ones())
                .map_err(|_| MerkleError::InvalidSnapshot("child count overflow"))?;
            if child_count < 2 {
                return Err(MerkleError::InvalidSnapshot(
                    "internal node has fewer than 2 children",
                ));
            }
            let digest = decoder.digest()?;

            let saved_path_len = path_nibbles.len();
            path_nibbles.extend_from_slice(&prefix);

            let mut children = Vec::with_capacity(child_count);
            let mut prev_nibble: Option<u8> = None;
            let mut reconstructed_bitmap = 0_u16;
            for _ in 0..child_count {
                let nibble = decoder.u8()?;
                if nibble >= 16 {
                    return Err(MerkleError::InvalidSnapshot("invalid child nibble"));
                }
                if prev_nibble.is_some_and(|prev| nibble <= prev) {
                    return Err(MerkleError::InvalidSnapshot(
                        "children not strictly ordered",
                    ));
                }
                prev_nibble = Some(nibble);
                reconstructed_bitmap |= 1_u16 << nibble;

                path_nibbles.push(nibble);
                let child_tag = decoder.tag()?;
                let child = decode_node_snapshot(
                    decoder,
                    child_tag,
                    depth_usize + 1,
                    path_nibbles,
                    counted_leaves,
                    verify_digests,
                )?;
                path_nibbles.pop();
                children.push((nibble, child));
            }
            path_nibbles.truncate(saved_path_len);

            if reconstructed_bitmap != child_bitmap {
                return Err(MerkleError::InvalidSnapshot(
                    "child_bitmap does not match decoded children",
                ));
            }

            let mut node = InternalNode {
                depth,
                prefix,
                child_bitmap,
                children,
                digest,
            };
            if verify_digests {
                let expected = node.digest;
                node.recompute_digest()?;
                if node.digest != expected {
                    return Err(MerkleError::InvalidSnapshot(
                        "internal node digest mismatch",
                    ));
                }
            }
            Ok(TrieNode::Internal(Arc::new(node)))
        }
        _ => Err(MerkleError::InvalidSnapshot("unknown trie node tag")),
    }
}

fn verify_node_recursive(
    node: &TrieNode,
    start_depth: usize,
    path_nibbles: &mut Vec<u8>,
    counted_leaves: &mut u64,
) -> Result<(), MerkleError> {
    match node {
        TrieNode::Leaf(leaf) => {
            if key_hash_for_object(&leaf.object_id) != leaf.key_hash {
                return Err(MerkleError::InvalidSnapshot("leaf key_hash mismatch"));
            }
            for (idx, &expected) in path_nibbles.iter().enumerate() {
                if nibble_at(&leaf.key_hash, idx) != expected {
                    return Err(MerkleError::InvalidSnapshot("leaf path mismatch"));
                }
            }
            if leaf_digest(&leaf.object_id, &leaf.revision)? != leaf.digest {
                return Err(MerkleError::InvalidSnapshot("leaf digest mismatch"));
            }
            *counted_leaves = counted_leaves
                .checked_add(1)
                .ok_or(MerkleError::Contract(ContractError::ArithmeticOverflow))?;
            Ok(())
        }
        TrieNode::Internal(internal) => {
            let depth = usize::from(internal.depth);
            if depth >= KEY_NIBBLE_LEN || depth < start_depth {
                return Err(MerkleError::InvalidSnapshot("invalid internal depth"));
            }
            if internal.prefix.len() != depth - start_depth {
                return Err(MerkleError::InvalidSnapshot("invalid internal prefix len"));
            }
            let mut digests = Vec::with_capacity(internal.children.len());
            let mut bitmap = 0_u16;
            let saved = path_nibbles.len();
            path_nibbles.extend_from_slice(&internal.prefix);
            let mut prev: Option<u8> = None;
            for (nibble, child) in &internal.children {
                if *nibble >= 16 || prev.is_some_and(|p| *nibble <= p) {
                    return Err(MerkleError::InvalidSnapshot("invalid child nibble order"));
                }
                prev = Some(*nibble);
                bitmap |= 1_u16 << *nibble;
                path_nibbles.push(*nibble);
                verify_node_recursive(child, depth + 1, path_nibbles, counted_leaves)?;
                path_nibbles.pop();
                digests.push(child.digest());
            }
            path_nibbles.truncate(saved);
            if bitmap != internal.child_bitmap {
                return Err(MerkleError::InvalidSnapshot("child_bitmap mismatch"));
            }
            let recomputed =
                internal_node_digest(internal.depth, &internal.prefix, bitmap, &digests)?;
            if recomputed != internal.digest {
                return Err(MerkleError::InvalidSnapshot("internal digest mismatch"));
            }
            Ok(())
        }
    }
}
