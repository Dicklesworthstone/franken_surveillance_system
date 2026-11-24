#![forbid(unsafe_code)]
//! Persistent 16-ary path-compressed Radix-Merkle trie implementation.
//!
//! Structural sharing via [`Arc`] makes cloning a [`RadixMerkleTrie`] `O(1)` and path updates
//! `O(k log N)` for `k` modified objects, with in-place mutation whenever a trie has no live
//! staged clones.

use std::sync::Arc;

use fss_core::{ContentDigest, ContractError, ObjectId, ObjectRevision};

use super::proof::{
    MerkleNodeSnapshot, MerkleProof, MerkleProofKind, MerkleProofStep, NonInclusionReason,
};
use super::{
    KEY_NIBBLE_LEN, MerkleError, empty_root, internal_node_digest, key_hash_for_object,
    leaf_digest, nibble_at,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LeafNode {
    pub(super) key_hash: [u8; 32],
    pub(super) object_id: ObjectId,
    pub(super) revision: ObjectRevision,
    pub(super) digest: ContentDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct InternalNode {
    /// Nibble depth (`0..64`) where this internal node branches.
    pub(super) depth: u8,
    /// Compressed nibble prefix (`[start_depth..depth)`), each byte in `0..16`.
    pub(super) prefix: Vec<u8>,
    /// Bitmask of populated child nibbles (`0..16`); always has `count_ones() >= 2`.
    pub(super) child_bitmap: u16,
    /// Populated children in strictly ascending nibble order.
    pub(super) children: Vec<(u8, TrieNode)>,
    /// Cached canonical internal node digest.
    pub(super) digest: ContentDigest,
}

impl InternalNode {
    pub(super) fn recompute_digest(&mut self) -> Result<(), MerkleError> {
        let mut digests = [ContentDigest::new(fss_core::DigestAlgorithm::Sha256, [0_u8; 32]); 16];
        let count = self.children.len();
        for (slot, (_, child)) in digests.iter_mut().zip(self.children.iter()) {
            *slot = child.digest();
        }
        self.digest = internal_node_digest(
            self.depth,
            &self.prefix,
            self.child_bitmap,
            &digests[..count],
        )?;
        Ok(())
    }

    fn find_child_index(&self, nibble: u8) -> Option<usize> {
        self.children.iter().position(|(n, _)| *n == nibble)
    }

    fn snapshot(&self) -> MerkleNodeSnapshot {
        MerkleNodeSnapshot {
            depth: self.depth,
            path_prefix: self.prefix.clone(),
            child_bitmap: self.child_bitmap,
            child_digests: self.children.iter().map(|(_, c)| c.digest()).collect(),
        }
    }

    fn proof_step(&self, excluded_nibble: u8) -> MerkleProofStep {
        let sibling_digests = self
            .children
            .iter()
            .filter(|(n, _)| *n != excluded_nibble)
            .map(|(_, c)| c.digest())
            .collect();
        MerkleProofStep {
            depth: self.depth,
            path_prefix: self.prefix.clone(),
            child_bitmap: self.child_bitmap,
            sibling_digests,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum TrieNode {
    Leaf(Arc<LeafNode>),
    Internal(Arc<InternalNode>),
}

impl TrieNode {
    #[inline]
    pub(super) fn digest(&self) -> ContentDigest {
        match self {
            Self::Leaf(leaf) => leaf.digest,
            Self::Internal(node) => node.digest,
        }
    }
}

/// Deterministic incremental 16-ary path-compressed Radix-Merkle accumulator.
///
/// Cloning is `O(1)` via structural sharing. Updating `k` keys mutates only the `O(k log N)`
/// nodes along their root-to-leaf paths, preserving order-independence of [`Self::root`].
/// Tombstoned [`ObjectId`]s remain stored with their tombstoned [`ObjectRevision`] so they
/// remain cryptographically distinguishable from never-existed IDs.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RadixMerkleTrie {
    pub(super) root: Option<TrieNode>,
    pub(super) len: u64,
}

impl RadixMerkleTrie {
    /// Creates an empty radix-Merkle trie.
    #[must_use]
    pub const fn new() -> Self {
        Self { root: None, len: 0 }
    }

    /// Returns true if the trie contains no objects.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the number of distinct object identities stored (including tombstoned objects).
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Returns the canonical v2 state root of the trie in `O(1)`.
    #[must_use]
    pub fn root(&self) -> ContentDigest {
        self.root.as_ref().map_or_else(empty_root, TrieNode::digest)
    }

    /// Looks up the current [`ObjectRevision`] of `object_id` in `O(log N)`.
    #[must_use]
    pub fn get(&self, object_id: &ObjectId) -> Option<&ObjectRevision> {
        let key_hash = key_hash_for_object(object_id);
        let mut cursor = self.root.as_ref()?;
        let mut start_depth = 0_usize;
        loop {
            match cursor {
                TrieNode::Leaf(leaf) => {
                    return if leaf.key_hash == key_hash && &leaf.object_id == object_id {
                        Some(&leaf.revision)
                    } else {
                        None
                    };
                }
                TrieNode::Internal(node) => {
                    let depth = usize::from(node.depth);
                    for (offset, &expected_nibble) in node.prefix.iter().enumerate() {
                        if nibble_at(&key_hash, start_depth + offset) != expected_nibble {
                            return None;
                        }
                    }
                    let branch_nibble = nibble_at(&key_hash, depth);
                    let child_idx = node.find_child_index(branch_nibble)?;
                    cursor = &node.children[child_idx].1;
                    start_depth = depth + 1;
                }
            }
        }
    }

    /// Inserts or updates `object_id` with `revision` in `O(log N)`, returning any prior revision.
    ///
    /// On error, the trie is left unchanged.
    pub fn insert(
        &mut self,
        object_id: ObjectId,
        revision: ObjectRevision,
    ) -> Result<Option<ObjectRevision>, MerkleError> {
        let key_hash = key_hash_for_object(&object_id);
        let digest = leaf_digest(&object_id, &revision)?;
        let new_leaf = LeafNode {
            key_hash,
            object_id,
            revision,
            digest,
        };

        let Some(root) = self.root.as_mut() else {
            self.root = Some(TrieNode::Leaf(Arc::new(new_leaf)));
            self.len = 1;
            return Ok(None);
        };

        let previous = insert_into_node(root, 0, new_leaf)?;
        if previous.is_none() {
            self.len = self
                .len
                .checked_add(1)
                .ok_or(MerkleError::Contract(ContractError::ArithmeticOverflow))?;
        }
        Ok(previous)
    }

    /// Applies an entire batch of `(ObjectId, ObjectRevision)` updates atomically in `O(k log N)`.
    ///
    /// If any update fails, `self` remains bit-identical to its prior state.
    pub fn apply_batch(
        &mut self,
        entries: impl IntoIterator<Item = (ObjectId, ObjectRevision)>,
    ) -> Result<ContentDigest, MerkleError> {
        let mut staged = self.clone();
        for (object_id, revision) in entries {
            let _ = staged.insert(object_id, revision)?;
        }
        *self = staged;
        Ok(self.root())
    }

    /// Iterates over all `(ObjectId, ObjectRevision)` pairs in deterministic canonical key-hash order.
    pub fn iter(&self) -> impl Iterator<Item = (&ObjectId, &ObjectRevision)> {
        let mut stack = Vec::new();
        if let Some(root) = &self.root {
            stack.push(root);
        }
        TrieIter { stack }
    }

    /// Generates an `O(log N)` standalone Merkle inclusion or non-inclusion proof for `object_id`.
    pub fn prove(&self, object_id: &ObjectId) -> Result<MerkleProof, MerkleError> {
        let Some(mut cursor) = self.root.as_ref() else {
            return Ok(MerkleProof {
                kind: MerkleProofKind::NonInclusion(NonInclusionReason::EmptyTree),
                steps: Vec::new(),
            });
        };

        let key_hash = key_hash_for_object(object_id);
        let mut steps = Vec::new();
        let mut start_depth = 0_usize;

        loop {
            match cursor {
                TrieNode::Leaf(leaf) => {
                    if &leaf.object_id == object_id {
                        return Ok(MerkleProof {
                            kind: MerkleProofKind::Inclusion {
                                revision: leaf.revision.clone(),
                            },
                            steps,
                        });
                    }
                    return Ok(MerkleProof {
                        kind: MerkleProofKind::NonInclusion(NonInclusionReason::DifferentLeaf {
                            existing_object_id: leaf.object_id.clone(),
                            existing_revision: leaf.revision.clone(),
                        }),
                        steps,
                    });
                }
                TrieNode::Internal(node) => {
                    let depth = usize::from(node.depth);
                    let prefix_mismatch = node
                        .prefix
                        .iter()
                        .enumerate()
                        .any(|(offset, &n)| nibble_at(&key_hash, start_depth + offset) != n);
                    if prefix_mismatch {
                        return Ok(MerkleProof {
                            kind: MerkleProofKind::NonInclusion(
                                NonInclusionReason::PrefixMismatch {
                                    terminal_node: node.snapshot(),
                                },
                            ),
                            steps,
                        });
                    }

                    let branch_nibble = nibble_at(&key_hash, depth);
                    let Some(child_idx) = node.find_child_index(branch_nibble) else {
                        return Ok(MerkleProof {
                            kind: MerkleProofKind::NonInclusion(
                                NonInclusionReason::EmptyChildSlot {
                                    terminal_node: node.snapshot(),
                                },
                            ),
                            steps,
                        });
                    };

                    steps.push(node.proof_step(branch_nibble));
                    cursor = &node.children[child_idx].1;
                    start_depth = depth + 1;
                }
            }
        }
    }
}

fn insert_into_node(
    slot: &mut TrieNode,
    start_depth: usize,
    new_leaf: LeafNode,
) -> Result<Option<ObjectRevision>, MerkleError> {
    match slot {
        TrieNode::Leaf(existing_arc) => {
            if existing_arc.object_id == new_leaf.object_id {
                let old_rev = existing_arc.revision.clone();
                let leaf = Arc::make_mut(existing_arc);
                leaf.revision = new_leaf.revision;
                leaf.digest = new_leaf.digest;
                return Ok(Some(old_rev));
            }
            if existing_arc.key_hash == new_leaf.key_hash {
                return Err(MerkleError::KeyHashCollision {
                    existing: existing_arc.object_id.clone(),
                    offered: new_leaf.object_id,
                });
            }

            let mut div_depth = start_depth;
            while div_depth < KEY_NIBBLE_LEN
                && nibble_at(&existing_arc.key_hash, div_depth)
                    == nibble_at(&new_leaf.key_hash, div_depth)
            {
                div_depth += 1;
            }
            if div_depth >= KEY_NIBBLE_LEN {
                return Err(MerkleError::KeyHashCollision {
                    existing: existing_arc.object_id.clone(),
                    offered: new_leaf.object_id,
                });
            }

            let mut prefix = Vec::with_capacity(div_depth.saturating_sub(start_depth));
            for d in start_depth..div_depth {
                prefix.push(nibble_at(&new_leaf.key_hash, d));
            }

            let existing_nibble = nibble_at(&existing_arc.key_hash, div_depth);
            let new_nibble = nibble_at(&new_leaf.key_hash, div_depth);
            let existing_node = TrieNode::Leaf(Arc::clone(existing_arc));
            let new_node = TrieNode::Leaf(Arc::new(new_leaf));
            let children = if existing_nibble < new_nibble {
                vec![(existing_nibble, existing_node), (new_nibble, new_node)]
            } else {
                vec![(new_nibble, new_node), (existing_nibble, existing_node)]
            };
            let child_bitmap = (1_u16 << existing_nibble) | (1_u16 << new_nibble);
            let mut internal = InternalNode {
                depth: div_depth as u8,
                prefix,
                child_bitmap,
                children,
                digest: empty_root(),
            };
            internal.recompute_digest()?;
            *slot = TrieNode::Internal(Arc::new(internal));
            Ok(None)
        }
        TrieNode::Internal(internal_arc) => {
            let mismatch_pos = internal_arc
                .prefix
                .iter()
                .enumerate()
                .position(|(offset, &n)| nibble_at(&new_leaf.key_hash, start_depth + offset) != n);

            if let Some(m) = mismatch_pos {
                let split_depth = start_depth + m;
                let common_prefix = internal_arc.prefix[..m].to_vec();
                let existing_nibble = internal_arc.prefix[m];
                let new_nibble = nibble_at(&new_leaf.key_hash, split_depth);

                let mut shrunk_existing = (**internal_arc).clone();
                shrunk_existing.prefix = internal_arc.prefix[m + 1..].to_vec();
                shrunk_existing.recompute_digest()?;

                let existing_node = TrieNode::Internal(Arc::new(shrunk_existing));
                let new_node = TrieNode::Leaf(Arc::new(new_leaf));
                let children = if existing_nibble < new_nibble {
                    vec![(existing_nibble, existing_node), (new_nibble, new_node)]
                } else {
                    vec![(new_nibble, new_node), (existing_nibble, existing_node)]
                };
                let child_bitmap = (1_u16 << existing_nibble) | (1_u16 << new_nibble);
                let mut parent = InternalNode {
                    depth: split_depth as u8,
                    prefix: common_prefix,
                    child_bitmap,
                    children,
                    digest: empty_root(),
                };
                parent.recompute_digest()?;
                *slot = TrieNode::Internal(Arc::new(parent));
                return Ok(None);
            }

            let depth = usize::from(internal_arc.depth);
            let branch_nibble = nibble_at(&new_leaf.key_hash, depth);
            let internal = Arc::make_mut(internal_arc);
            let previous = if let Some(idx) = internal.find_child_index(branch_nibble) {
                insert_into_node(&mut internal.children[idx].1, depth + 1, new_leaf)?
            } else {
                let insert_pos = internal
                    .children
                    .iter()
                    .position(|(n, _)| *n > branch_nibble)
                    .unwrap_or(internal.children.len());
                internal.children.insert(
                    insert_pos,
                    (branch_nibble, TrieNode::Leaf(Arc::new(new_leaf))),
                );
                internal.child_bitmap |= 1_u16 << branch_nibble;
                None
            };
            internal.recompute_digest()?;
            Ok(previous)
        }
    }
}

struct TrieIter<'a> {
    stack: Vec<&'a TrieNode>,
}

impl<'a> Iterator for TrieIter<'a> {
    type Item = (&'a ObjectId, &'a ObjectRevision);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(node) = self.stack.pop() {
            match node {
                TrieNode::Leaf(leaf) => return Some((&leaf.object_id, &leaf.revision)),
                TrieNode::Internal(internal) => {
                    for (_, child) in internal.children.iter().rev() {
                        self.stack.push(child);
                    }
                }
            }
        }
        None
    }
}
