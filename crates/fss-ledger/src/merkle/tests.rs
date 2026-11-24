#![forbid(unsafe_code)]
//! Unit and randomized reference tests for the v2 Radix-Merkle accumulator.

use std::collections::BTreeMap;
use std::error::Error;

use fss_core::{
    CanonicalDecode, CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest, ObjectId,
    ObjectRevision, Plane, TimestampNs,
};

use super::{
    KEY_NIBBLE_LEN, MERKLE_EMPTY_DOMAIN, MERKLE_KEY_DOMAIN, MERKLE_LEAF_DOMAIN, MERKLE_NODE_DOMAIN,
    MerkleError, MerkleProof, MerkleProofError, MerkleProofKind, NonInclusionReason,
    RadixMerkleTrie, empty_root, expand_nibbles, internal_node_digest, key_hash_for_object,
    leaf_digest, verify_proof,
};

type TestResult = Result<(), Box<dyn Error>>;

/// Independent naive sorted-map reference Merkle calculator.
///
/// Recomputes the exact v2 radix-Merkle root from scratch via pure divide-and-conquer
/// over a sorted vector of `(expanded_key_nibbles, leaf_digest)` without sharing any
/// trie mutation, path-splitting, or caching code with [`RadixMerkleTrie`].
pub(crate) fn naive_merkle_root(
    objects: &BTreeMap<ObjectId, ObjectRevision>,
) -> Result<ContentDigest, MerkleError> {
    if objects.is_empty() {
        return Ok(empty_root());
    }
    let mut leaves: Vec<([u8; KEY_NIBBLE_LEN], ContentDigest)> = Vec::with_capacity(objects.len());
    for (object_id, revision) in objects {
        let nibbles = expand_nibbles(&key_hash_for_object(object_id));
        let digest = leaf_digest(object_id, revision)?;
        leaves.push((nibbles, digest));
    }
    leaves.sort_by_key(|a| a.0);
    naive_subtree_root(&leaves, 0)
}

fn naive_subtree_root(
    leaves: &[([u8; KEY_NIBBLE_LEN], ContentDigest)],
    start_depth: usize,
) -> Result<ContentDigest, MerkleError> {
    if leaves.len() == 1 {
        return Ok(leaves[0].1);
    }
    let first = &leaves[0].0;
    let last = &leaves[leaves.len() - 1].0;
    let mut branch_depth = start_depth;
    while branch_depth < KEY_NIBBLE_LEN && first[branch_depth] == last[branch_depth] {
        branch_depth += 1;
    }
    if branch_depth >= KEY_NIBBLE_LEN {
        return Err(MerkleError::InvalidSnapshot("duplicate key hash in naive"));
    }
    let prefix = &first[start_depth..branch_depth];
    let mut child_bitmap = 0_u16;
    let mut child_digests = Vec::new();
    let mut idx = 0_usize;
    while idx < leaves.len() {
        let nibble = leaves[idx].0[branch_depth];
        let mut end = idx + 1;
        while end < leaves.len() && leaves[end].0[branch_depth] == nibble {
            end += 1;
        }
        child_bitmap |= 1_u16 << nibble;
        child_digests.push(naive_subtree_root(&leaves[idx..end], branch_depth + 1)?);
        idx = end;
    }
    internal_node_digest(branch_depth as u8, prefix, child_bitmap, &child_digests)
}

fn make_rev(
    generation: u64,
    family: &str,
    plane: Plane,
    tag: &str,
) -> Result<ObjectRevision, Box<dyn Error>> {
    let start = i128::from(generation) * 100;
    Ok(ObjectRevision {
        generation,
        family: family.to_owned(),
        plane,
        payload_digest: ContentDigest::sha256(tag.as_bytes()),
        validity: CaptureInterval::new(TimestampNs(start), TimestampNs(start + 50))?,
    })
}

fn obj(name: &str) -> Result<ObjectId, Box<dyn Error>> {
    Ok(ObjectId::parse(format!("object:{name}"))?)
}

/// Deterministic Xorshift64* PRNG for repeatable randomized tests.
struct Rng(u64);

impl Rng {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn gen_range(&mut self, upper: usize) -> usize {
        (self.next_u64() as usize) % upper
    }
}

#[test]
fn streaming_hashers_match_canonical_encoder_bit_for_bit() -> TestResult {
    // Empty root matches CanonicalEncoder::text(MERKLE_EMPTY_DOMAIN)
    let mut enc = CanonicalEncoder::new();
    enc.text(MERKLE_EMPTY_DOMAIN);
    assert_eq!(empty_root(), ContentDigest::sha256(&enc.finish_checked()?));

    // Key hash matches CanonicalEncoder
    let id = obj("cam-01:frame-42")?;
    let mut enc = CanonicalEncoder::new();
    enc.text(MERKLE_KEY_DOMAIN);
    id.encode_canonical(&mut enc);
    assert_eq!(
        key_hash_for_object(&id),
        ContentDigest::sha256(&enc.finish_checked()?).bytes()
    );

    // Leaf digest matches CanonicalEncoder
    let rev = make_rev(3, "sensor_capsule", Plane::Authority, "payload-42")?;
    let mut enc = CanonicalEncoder::new();
    enc.text(MERKLE_LEAF_DOMAIN);
    id.encode_canonical(&mut enc);
    rev.encode_canonical(&mut enc);
    assert_eq!(
        leaf_digest(&id, &rev)?,
        ContentDigest::sha256(&enc.finish_checked()?)
    );

    // Internal node digest matches CanonicalEncoder
    let d0 = ContentDigest::sha256(b"child-0");
    let d1 = ContentDigest::sha256(b"child-1");
    let prefix = [1_u8, 10_u8, 15_u8];
    let bitmap: u16 = (1 << 2) | (1 << 11);
    let mut enc = CanonicalEncoder::new();
    enc.text(MERKLE_NODE_DOMAIN);
    enc.u8(5);
    enc.bytes(&prefix);
    enc.u8((bitmap >> 8) as u8);
    enc.u8((bitmap & 0xff) as u8);
    enc.digest(d0);
    enc.digest(d1);
    assert_eq!(
        internal_node_digest(5, &prefix, bitmap, &[d0, d1])?,
        ContentDigest::sha256(&enc.finish_checked()?)
    );
    Ok(())
}

#[test]
fn empty_single_update_tombstone_and_batch_semantics() -> TestResult {
    let mut trie = RadixMerkleTrie::new();
    let mut model = BTreeMap::new();
    assert!(trie.is_empty());
    assert_eq!(trie.len(), 0);
    assert_eq!(trie.root(), empty_root());
    assert_eq!(trie.root(), naive_merkle_root(&model)?);

    // Non-inclusion on empty tree
    let id_a = obj("alpha")?;
    let proof_empty = trie.prove(&id_a)?;
    assert_eq!(
        proof_empty.kind,
        MerkleProofKind::NonInclusion(NonInclusionReason::EmptyTree)
    );
    verify_proof(trie.root(), &id_a, &proof_empty)?;

    // Single insert
    let rev_a1 = make_rev(1, "sensor_capsule", Plane::Authority, "a1")?;
    assert_eq!(trie.insert(id_a.clone(), rev_a1.clone())?, None);
    model.insert(id_a.clone(), rev_a1.clone());
    assert_eq!(trie.len(), 1);
    assert_eq!(trie.get(&id_a), Some(&rev_a1));
    assert_eq!(trie.root(), leaf_digest(&id_a, &rev_a1)?);
    assert_eq!(trie.root(), naive_merkle_root(&model)?);

    // Inclusion on single leaf + DifferentLeaf non-inclusion on another ID
    let id_missing = obj("never-existed")?;
    let inc_a = trie.prove(&id_a)?;
    assert_eq!(inc_a.included_revision(), Some(&rev_a1));
    verify_proof(trie.root(), &id_a, &inc_a)?;
    let non_inc = trie.prove(&id_missing)?;
    assert!(matches!(
        non_inc.kind,
        MerkleProofKind::NonInclusion(NonInclusionReason::DifferentLeaf { .. })
    ));
    verify_proof(trie.root(), &id_missing, &non_inc)?;

    // Update existing key
    let rev_a2 = make_rev(2, "sensor_capsule", Plane::Authority, "a2")?;
    assert_eq!(trie.insert(id_a.clone(), rev_a2.clone())?, Some(rev_a1));
    model.insert(id_a.clone(), rev_a2.clone());
    assert_eq!(trie.len(), 1);
    assert_eq!(trie.root(), naive_merkle_root(&model)?);

    // Tombstone: stored in trie with tombstoned revision, distinguishable from never-existed
    let rev_a_tomb = make_rev(3, "tombstone", Plane::Authority, "tombstone:a")?;
    assert_eq!(trie.insert(id_a.clone(), rev_a_tomb.clone())?, Some(rev_a2));
    model.insert(id_a.clone(), rev_a_tomb.clone());
    assert_eq!(trie.len(), 1);
    assert_eq!(trie.get(&id_a), Some(&rev_a_tomb));
    let tomb_proof = trie.prove(&id_a)?;
    assert!(tomb_proof.is_inclusion());
    assert_eq!(tomb_proof.included_revision(), Some(&rev_a_tomb));
    verify_proof(trie.root(), &id_a, &tomb_proof)?;

    // Batch multi-key update
    let mut batch_entries = Vec::new();
    for i in 0..32_u32 {
        let id = obj(&format!("batch-key-{i:03}"))?;
        let rev = make_rev(1, "world_fact", Plane::Cognition, &format!("p-{i}"))?;
        model.insert(id.clone(), rev.clone());
        batch_entries.push((id, rev));
    }
    let root = trie.apply_batch(batch_entries)?;
    assert_eq!(trie.len(), 33);
    assert_eq!(root, naive_merkle_root(&model)?);
    trie.verify_all_digests()?;
    Ok(())
}

#[test]
fn insertion_and_update_order_independence() -> TestResult {
    let mut items = Vec::new();
    for i in 0..120_u32 {
        let id = obj(&format!("node-{i:04}"))?;
        let rev = make_rev(
            u64::from(i % 5) + 1,
            if i % 7 == 0 { "tombstone" } else { "obs" },
            match i % 3 {
                0 => Plane::Authority,
                1 => Plane::Cognition,
                _ => Plane::Effect,
            },
            &format!("val-{i}"),
        )?;
        items.push((id, rev));
    }

    let mut forward = RadixMerkleTrie::new();
    let mut reverse = RadixMerkleTrie::new();
    let mut shuffled = RadixMerkleTrie::new();
    let mut model = BTreeMap::new();

    for (id, rev) in &items {
        forward.insert(id.clone(), rev.clone())?;
        model.insert(id.clone(), rev.clone());
    }
    for (id, rev) in items.iter().rev() {
        reverse.insert(id.clone(), rev.clone())?;
    }

    let mut perm = items.clone();
    let mut rng = Rng::new(0xA11C_E5EED);
    for i in (1..perm.len()).rev() {
        let j = rng.gen_range(i + 1);
        perm.swap(i, j);
    }
    for (id, rev) in perm {
        shuffled.insert(id, rev)?;
    }

    let expected = naive_merkle_root(&model)?;
    assert_eq!(forward.root(), expected);
    assert_eq!(reverse.root(), expected);
    assert_eq!(shuffled.root(), expected);
    assert_eq!(forward, reverse);
    assert_eq!(forward, shuffled);
    Ok(())
}

#[test]
fn inclusion_non_inclusion_all_cases_and_tampered_proof_rejection() -> TestResult {
    let mut trie = RadixMerkleTrie::new();
    let mut included_ids = Vec::new();
    for i in 0..80_u32 {
        let id = obj(&format!("present-{i:04}"))?;
        let rev = make_rev(1, "sensor_capsule", Plane::Authority, &format!("p-{i}"))?;
        trie.insert(id.clone(), rev)?;
        included_ids.push(id);
    }
    let root = trie.root();

    // Verify all inclusion proofs & canonical encode/decode round-trip
    for id in &included_ids {
        let proof = trie.prove(id)?;
        assert!(proof.is_inclusion());
        verify_proof(root, id, &proof)?;

        let encoded = proof.try_canonical_bytes()?;
        let decoded = MerkleProof::from_canonical_bytes(&encoded)?;
        assert_eq!(decoded, proof);
        verify_proof(root, id, &decoded)?;
    }

    // Exercise non-inclusion variants (DifferentLeaf, EmptyChildSlot)
    let mut saw_diff_leaf = false;
    let mut saw_empty_slot = false;
    for i in 0..2_000_u32 {
        let probe = obj(&format!("absent-probe-{i:05}"))?;
        let proof = trie.prove(&probe)?;
        assert!(!proof.is_inclusion());
        verify_proof(root, &probe, &proof)?;
        match &proof.kind {
            MerkleProofKind::NonInclusion(NonInclusionReason::DifferentLeaf { .. }) => {
                saw_diff_leaf = true;
            }
            MerkleProofKind::NonInclusion(NonInclusionReason::EmptyChildSlot { .. }) => {
                saw_empty_slot = true;
            }
            _ => {}
        }
        if saw_diff_leaf && saw_empty_slot {
            break;
        }
    }
    assert!(saw_diff_leaf, "expected DifferentLeaf non-inclusion case");
    assert!(saw_empty_slot, "expected EmptyChildSlot non-inclusion case");

    // Deterministic PrefixMismatch test: construct a 2-key trie whose keys share nibble 0
    let first_id = obj("prefix-base")?;
    let target_n0 = super::nibble_at(&key_hash_for_object(&first_id), 0);
    let mut second_id = None;
    let mut mismatch_probe = None;
    for i in 0..256_u32 {
        let candidate = obj(&format!("prefix-cand-{i}"))?;
        let n0 = super::nibble_at(&key_hash_for_object(&candidate), 0);
        if n0 == target_n0 && second_id.is_none() {
            second_id = Some(candidate);
        } else if n0 != target_n0 && mismatch_probe.is_none() {
            mismatch_probe = Some(candidate);
        }
        if second_id.is_some() && mismatch_probe.is_some() {
            break;
        }
    }
    let second_id = second_id.ok_or("could not find second key sharing nibble 0")?;
    let mismatch_probe = mismatch_probe.ok_or("could not find probe with distinct nibble 0")?;
    let mut compressed_trie = RadixMerkleTrie::new();
    compressed_trie.insert(
        first_id.clone(),
        make_rev(1, "sensor_capsule", Plane::Authority, "c1")?,
    )?;
    compressed_trie.insert(
        second_id,
        make_rev(1, "sensor_capsule", Plane::Authority, "c2")?,
    )?;
    let pm_proof = compressed_trie.prove(&mismatch_probe)?;
    assert!(
        matches!(
            pm_proof.kind,
            MerkleProofKind::NonInclusion(NonInclusionReason::PrefixMismatch { .. })
        ),
        "expected PrefixMismatch non-inclusion case, got {:?}",
        pm_proof.kind
    );
    verify_proof(compressed_trie.root(), &mismatch_probe, &pm_proof)?;
    // Replaying a PrefixMismatch proof against an actually-matching key must fail closed!
    assert_eq!(
        verify_proof(compressed_trie.root(), &first_id, &pm_proof),
        Err(MerkleProofError::PrefixActuallyMatches)
    );

    // Tampered proofs must be rejected
    let target = &included_ids[0];
    let valid_proof = trie.prove(target)?;

    // 1. Wrong root
    let wrong_root = ContentDigest::sha256(b"wrong-root");
    assert!(matches!(
        verify_proof(wrong_root, target, &valid_proof),
        Err(MerkleProofError::RootMismatch { .. })
    ));

    // 2. Wrong object_id against another object's inclusion proof
    let other_target = &included_ids[1];
    assert!(verify_proof(root, other_target, &valid_proof).is_err());

    // 3. Tampered revision inside inclusion proof
    let mut tampered_rev = valid_proof.clone();
    if let MerkleProofKind::Inclusion { revision } = &mut tampered_rev.kind {
        revision.generation += 1;
    }
    assert!(matches!(
        verify_proof(root, target, &tampered_rev),
        Err(MerkleProofError::RootMismatch { .. })
    ));

    // 4. Tampered sibling digest
    let mut tampered_sib = valid_proof.clone();
    if let Some(step) = tampered_sib.steps.first_mut()
        && let Some(sib) = step.sibling_digests.first_mut()
    {
        *sib = ContentDigest::sha256(b"forged-sibling");
    }
    assert!(matches!(
        verify_proof(root, target, &tampered_sib),
        Err(MerkleProofError::RootMismatch { .. })
    ));

    // 5. Forged DifferentLeaf non-inclusion claiming the included object itself
    let forged_non_inc = MerkleProof {
        kind: MerkleProofKind::NonInclusion(NonInclusionReason::DifferentLeaf {
            existing_object_id: target.clone(),
            existing_revision: trie.get(target).ok_or("target missing from trie")?.clone(),
        }),
        steps: valid_proof.steps.clone(),
    };
    assert_eq!(
        verify_proof(root, target, &forged_non_inc),
        Err(MerkleProofError::KeyActuallyIncluded)
    );

    // 6. Forged EmptyTree proof against non-empty root
    let forged_empty = MerkleProof {
        kind: MerkleProofKind::NonInclusion(NonInclusionReason::EmptyTree),
        steps: Vec::new(),
    };
    assert!(matches!(
        verify_proof(root, target, &forged_empty),
        Err(MerkleProofError::RootMismatch { .. })
    ));

    Ok(())
}

#[test]
fn randomized_insert_update_tombstone_matches_naive_reference() -> TestResult {
    let mut rng = Rng::new(0xDEC0_DE55_1234_5678);
    let mut trie = RadixMerkleTrie::new();
    let mut model: BTreeMap<ObjectId, ObjectRevision> = BTreeMap::new();
    let key_space = 180_usize;

    for step in 0..400_u64 {
        let batch_size = rng.gen_range(5) + 1;
        let mut updates = BTreeMap::new();
        for _ in 0..batch_size {
            let k = rng.gen_range(key_space);
            let id = obj(&format!("rnd-{k:04}"))?;
            let existing = updates.get(&id).or_else(|| model.get(&id));
            let (next_gen, plane) = match existing {
                Some(prev) => (prev.generation + 1, prev.plane),
                None => (
                    1,
                    match k % 3 {
                        0 => Plane::Authority,
                        1 => Plane::Cognition,
                        _ => Plane::Effect,
                    },
                ),
            };
            let family = if rng.gen_range(6) == 0 {
                "tombstone"
            } else {
                "sensor_capsule"
            };
            let rev = make_rev(
                next_gen,
                family,
                plane,
                &format!("s{step}-k{k}-g{next_gen}"),
            )?;
            updates.insert(id, rev);
        }

        for (id, rev) in &updates {
            model.insert(id.clone(), rev.clone());
        }
        let root = trie.apply_batch(updates)?;
        let expected = naive_merkle_root(&model)?;
        assert_eq!(root, expected, "root diverged at step {step}");
        assert_eq!(trie.len(), model.len() as u64);

        if step % 50 == 0 {
            let probe_present = obj(&format!("rnd-{:04}", rng.gen_range(key_space)))?;
            let proof = trie.prove(&probe_present)?;
            assert_eq!(proof.is_inclusion(), model.contains_key(&probe_present));
            verify_proof(root, &probe_present, &proof)?;
        }
    }

    // Verify snapshot encode/decode round-trip
    let mut enc = CanonicalEncoder::new();
    trie.encode_snapshot(&mut enc);
    let bytes = enc.finish_checked()?;
    let mut dec = fss_core::CanonicalDecoder::new(&bytes);
    let restored = RadixMerkleTrie::decode_snapshot(&mut dec, trie.root(), true)?;
    dec.ensure_finished()?;
    assert_eq!(restored, trie);
    Ok(())
}
