#![forbid(unsafe_code)]
//! Contract, property/differential, and scale verification suite for the v2
//! incremental Radix-Merkle accumulator, segmented epoch journals, verified checkpoints,
//! and unified [`CanonicalLedgerBackend`] trait.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, ObjectId, ObjectRevision, Plane,
    TimestampNs,
};
use fss_ledger::{
    CanonicalLedgerBackend, EpochLedgerConfig, EpochLedgerError, IncompleteTailPolicy,
    KEY_NIBBLE_LEN, LedgerOracle, MerkleEpochLedger, OracleError, OracleLimits, empty_root,
    expand_nibbles, internal_node_digest, key_hash_for_object, leaf_digest, verify_proof,
};

type TestResult = Result<(), Box<dyn Error>>;

const SITE: &str = "site:merkle-epoch-contract";

/// Independent naive sorted-map reference Merkle calculator (completely separate from trie).
fn naive_merkle_root(
    objects: &BTreeMap<ObjectId, ObjectRevision>,
) -> Result<ContentDigest, Box<dyn Error>> {
    if objects.is_empty() {
        return Ok(empty_root());
    }
    let mut leaves: Vec<([u8; KEY_NIBBLE_LEN], ContentDigest)> = Vec::with_capacity(objects.len());
    for (id, rev) in objects {
        leaves.push((
            expand_nibbles(&key_hash_for_object(id)),
            leaf_digest(id, rev)?,
        ));
    }
    leaves.sort_by_key(|a| a.0);
    naive_subtree(&leaves, 0)
}

fn naive_subtree(
    leaves: &[([u8; KEY_NIBBLE_LEN], ContentDigest)],
    start_depth: usize,
) -> Result<ContentDigest, Box<dyn Error>> {
    if leaves.len() == 1 {
        return Ok(leaves[0].1);
    }
    let first = &leaves[0].0;
    let last = &leaves[leaves.len() - 1].0;
    let mut branch_depth = start_depth;
    while branch_depth < KEY_NIBBLE_LEN && first[branch_depth] == last[branch_depth] {
        branch_depth += 1;
    }
    let prefix = &first[start_depth..branch_depth];
    let mut bitmap = 0_u16;
    let mut digests = Vec::new();
    let mut idx = 0_usize;
    while idx < leaves.len() {
        let nibble = leaves[idx].0[branch_depth];
        let mut end = idx + 1;
        while end < leaves.len() && leaves[end].0[branch_depth] == nibble {
            end += 1;
        }
        bitmap |= 1_u16 << nibble;
        digests.push(naive_subtree(&leaves[idx..end], branch_depth + 1)?);
        idx = end;
    }
    Ok(internal_node_digest(
        branch_depth as u8,
        prefix,
        bitmap,
        &digests,
    )?)
}

fn fresh_dir(label: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("fss-merkle-epoch-contract")
        .join(label);
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

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

    fn range(&mut self, upper: usize) -> usize {
        (self.next_u64() as usize) % upper
    }
}

fn make_delta(
    tag: &str,
    object_id: ObjectId,
    prior: Option<u64>,
    new_gen: u64,
    family: &str,
    plane: Plane,
) -> Result<EvidenceDelta, Box<dyn Error>> {
    let start = i128::from(new_gen) * 100;
    Ok(EvidenceDelta {
        delta_id: format!("delta:{tag}"),
        family: family.to_owned(),
        object_id,
        prior_generation: prior,
        new_generation: new_gen,
        validity: CaptureInterval::new(TimestampNs(start), TimestampNs(start + 25))?,
        plane,
        payload_digest: ContentDigest::sha256(format!("payload:{tag}").as_bytes()),
        witness_digest: None,
        operation_id: None,
    })
}

fn drive_backend_smoke<B: CanonicalLedgerBackend>(
    backend: &mut B,
    batch1: fss_core::EvidenceDeltaBatch,
    batch2: fss_core::EvidenceDeltaBatch,
    probe_present: &ObjectId,
    probe_absent: &ObjectId,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(backend.commit_sequence(), 0);
    assert_eq!(backend.live_object_count(), 0);

    let r1 = backend.append_batch(batch1)?;
    assert_eq!(r1.sequence, 1);
    assert_eq!(backend.commit_sequence(), 1);
    assert_eq!(backend.history_root(), r1.history_root);
    assert_eq!(backend.state_root(), r1.anchor.state_root);

    let r2 = backend.append_batch(batch2)?;
    assert_eq!(r2.sequence, 2);
    assert_eq!(backend.commit_sequence(), 2);
    assert_eq!(backend.live_object_count(), 2);
    assert!(backend.get_object(probe_present).is_some());
    assert!(backend.get_object(probe_absent).is_none());

    let proof_present = backend.prove_object(probe_present)?;
    let proof_absent = backend.prove_object(probe_absent)?;
    if backend.supports_merkle_proofs() {
        let p_in = proof_present.ok_or("merkle backend must return inclusion proof")?;
        let p_out = proof_absent.ok_or("merkle backend must return non-inclusion proof")?;
        assert!(p_in.is_inclusion());
        assert!(!p_out.is_inclusion());
        verify_proof(backend.state_root(), probe_present, &p_in)?;
        verify_proof(backend.state_root(), probe_absent, &p_out)?;
    } else {
        assert!(proof_present.is_none());
        assert!(proof_absent.is_none());
    }
    Ok(())
}

#[test]
fn canonical_ledger_backend_trait_works_for_v1_oracle_and_v2_merkle_ledger() -> TestResult {
    let id_a = ObjectId::parse("object:cam:a")?;
    let id_b = ObjectId::parse("object:cam:b")?;
    let id_missing = ObjectId::parse("object:cam:never")?;

    let d1 = make_delta(
        "1",
        id_a.clone(),
        None,
        1,
        "sensor_capsule",
        Plane::Authority,
    )?;
    let d2 = make_delta("2", id_b.clone(), None, 1, "world_fact", Plane::Cognition)?;

    // Drive v1 LedgerOracle through CanonicalLedgerBackend
    let mut oracle = LedgerOracle::new(SITE, OracleLimits::CEILING)?;
    let ob1 = oracle.prepare_batch(BatchId::parse("batch:1")?, vec![d1.clone()], [])?;
    // Prepare second batch after committing first via helper
    let mut oracle_for_prep = LedgerOracle::new(SITE, OracleLimits::CEILING)?;
    oracle_for_prep.append(ob1.clone())?;
    let ob2 = oracle_for_prep.prepare_batch(BatchId::parse("batch:2")?, vec![d2.clone()], [])?;
    assert!(!oracle.supports_merkle_proofs());
    drive_backend_smoke(&mut oracle, ob1, ob2, &id_a, &id_missing)?;

    // Drive v2 MerkleEpochLedger through CanonicalLedgerBackend
    let dir = fresh_dir("backend-trait-v2")?;
    let mut merkle = MerkleEpochLedger::open(
        &dir,
        SITE,
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )?;
    let mb1 = merkle.prepare_batch(BatchId::parse("batch:1")?, vec![d1], [])?;
    let dir_prep = fresh_dir("backend-trait-v2-prep")?;
    let mut prep = MerkleEpochLedger::open(
        &dir_prep,
        SITE,
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )?;
    prep.append_batch(mb1.clone())?;
    let mb2 = prep.prepare_batch(BatchId::parse("batch:2")?, vec![d2], [])?;
    assert!(merkle.supports_merkle_proofs());
    drive_backend_smoke(&mut merkle, mb1, mb2, &id_a, &id_missing)?;
    Ok(())
}

/// Differential property test: 1,000 randomized EvidenceDeltaBatch operations (creates, updates,
/// tombstones, plus injected generation/plane/duplicate conflicts) driven through BOTH v1
/// `LedgerOracle` and v2 `MerkleEpochLedger` and cross-checked against `naive_merkle_root`.
#[test]
fn differential_1000_randomized_batches_match_oracle_and_naive_merkle() -> TestResult {
    let dir = fresh_dir("differential-1000")?;
    let cfg = EpochLedgerConfig {
        max_epoch_bytes: 256 * 1024,
        max_batches_per_epoch: 120,
        checkpoint_stride: 100,
        max_objects: None,
    };

    let mut oracle = LedgerOracle::new(SITE, OracleLimits::CEILING)?;
    let mut merkle = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    let mut rng = Rng::new(0x5EED_CAFE_2026_1000);
    let key_space = 250_usize;

    let mut committed_oracle_batches: Vec<fss_core::EvidenceDeltaBatch> = Vec::new();
    let mut committed_merkle_batches: Vec<fss_core::EvidenceDeltaBatch> = Vec::new();

    for step in 1..=1_000_u64 {
        let mode = rng.range(20);
        if mode == 0 && !committed_oracle_batches.is_empty() {
            // Inject duplicate batch resubmission -> BOTH must reject with DuplicateBatch!
            let idx = rng.range(committed_oracle_batches.len());
            let o_res = oracle.append(committed_oracle_batches[idx].clone());
            let m_res = merkle.append_batch(committed_merkle_batches[idx].clone());
            assert!(matches!(o_res, Err(OracleError::DuplicateBatch { .. })));
            assert!(matches!(
                m_res,
                Err(EpochLedgerError::DuplicateBatch { .. })
            ));
            continue;
        }

        if mode == 1 && !committed_oracle_batches.is_empty() {
            // Inject generation conflict -> BOTH must reject with GenerationConflict!
            let k = rng.range(key_space);
            let obj_id = ObjectId::parse(format!("object:diff-{k:04}"))?;
            let bad_prior = match oracle.get_object(&obj_id) {
                Some(rev) => Some(rev.generation + 5),
                None => Some(1),
            };
            let bad_delta = make_delta(
                &format!("bad-gen-{step}"),
                obj_id,
                bad_prior,
                bad_prior.map_or(2, |g| g + 1),
                "sensor_capsule",
                Plane::Authority,
            )?;
            let bid = BatchId::parse(format!("batch:bad-gen-{step}"))?;
            assert!(matches!(
                oracle.prepare_batch(bid.clone(), vec![bad_delta.clone()], []),
                Err(OracleError::GenerationConflict { .. })
            ));
            assert!(matches!(
                merkle.prepare_batch(bid, vec![bad_delta], []),
                Err(EpochLedgerError::GenerationConflict { .. })
            ));
            continue;
        }

        if mode == 2 && oracle.live_object_count() > 0 {
            // Inject plane conflict on an existing object -> BOTH must reject with PlaneConflict!
            let mut found = None;
            for k in 0..key_space {
                let candidate = ObjectId::parse(format!("object:diff-{k:04}"))?;
                if let Some(rev) = oracle.get_object(&candidate) {
                    found = Some((candidate, rev.generation, rev.plane));
                    break;
                }
            }
            if let Some((obj_id, committed_gen, committed_plane)) = found {
                let wrong_plane = match committed_plane {
                    Plane::Authority => Plane::Cognition,
                    Plane::Cognition => Plane::Effect,
                    Plane::Effect => Plane::Authority,
                };
                let bad_delta = make_delta(
                    &format!("bad-plane-{step}"),
                    obj_id,
                    Some(committed_gen),
                    committed_gen + 1,
                    "sensor_capsule",
                    wrong_plane,
                )?;
                let bid = BatchId::parse(format!("batch:bad-plane-{step}"))?;
                assert!(matches!(
                    oracle.prepare_batch(bid.clone(), vec![bad_delta.clone()], []),
                    Err(OracleError::PlaneConflict { .. })
                ));
                assert!(matches!(
                    merkle.prepare_batch(bid, vec![bad_delta], []),
                    Err(EpochLedgerError::PlaneConflict { .. })
                ));
                continue;
            }
        }

        // Valid randomized multi-delta batch (creates, updates, tombstones)
        let delta_count = rng.range(4) + 1;
        let mut chosen = BTreeMap::new();
        for sub in 0..delta_count {
            let k = rng.range(key_space);
            let obj_id = ObjectId::parse(format!("object:diff-{k:04}"))?;
            if chosen.contains_key(&obj_id) {
                continue;
            }
            let (prior, new_gen, plane) = match oracle.get_object(&obj_id) {
                Some(rev) => (Some(rev.generation), rev.generation + 1, rev.plane),
                None => (
                    None,
                    1,
                    match k % 3 {
                        0 => Plane::Authority,
                        1 => Plane::Cognition,
                        _ => Plane::Effect,
                    },
                ),
            };
            let family = if rng.range(7) == 0 {
                "tombstone"
            } else {
                "sensor_capsule"
            };
            let d = make_delta(
                &format!("s{step}-{sub}-k{k}"),
                obj_id.clone(),
                prior,
                new_gen,
                family,
                plane,
            )?;
            chosen.insert(obj_id, d);
        }
        let deltas: Vec<EvidenceDelta> = chosen.into_values().collect();
        let bid = BatchId::parse(format!("batch:seq-{step}"))?;

        let o_batch = oracle.prepare_batch(bid.clone(), deltas.clone(), [])?;
        let m_batch = merkle.prepare_batch(bid, deltas, [])?;
        oracle.append(o_batch.clone())?;
        merkle.append_batch(m_batch.clone())?;
        committed_oracle_batches.push(o_batch);
        committed_merkle_batches.push(m_batch);

        assert_eq!(oracle.commit_sequence(), merkle.commit_sequence());
        assert_eq!(oracle.live_object_count(), merkle.live_object_count());

        // Periodically verify full state map equality, naive Merkle root, and proofs
        if step % 50 == 0 || step == 1_000 {
            let oracle_map = oracle.view_at(oracle.head_sequence())?.snapshot().objects;
            let merkle_map = merkle.snapshot_objects();
            assert_eq!(merkle_map, oracle_map, "object map diverged at step {step}");

            let expected_merkle = naive_merkle_root(&oracle_map)?;
            assert_eq!(
                merkle.state_root(),
                expected_merkle,
                "merkle root diverged at step {step}"
            );

            // Spot-check inclusion & non-inclusion proofs
            let probe_k = rng.range(key_space);
            let probe_id = ObjectId::parse(format!("object:diff-{probe_k:04}"))?;
            let proof = merkle.prove_object(&probe_id)?;
            assert_eq!(proof.is_inclusion(), oracle_map.contains_key(&probe_id));
            verify_proof(merkle.state_root(), &probe_id, &proof)?;
        }
    }

    // Reopen from latest checkpoint & verify full chain from genesis
    let expected_seq = merkle.commit_sequence();
    let expected_root = merkle.state_root();
    let expected_hist = merkle.history_root();
    let expected_objs = merkle.live_object_count();
    drop(merkle);

    let reopened = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    assert_eq!(reopened.commit_sequence(), expected_seq);
    assert_eq!(reopened.state_root(), expected_root);
    assert_eq!(reopened.history_root(), expected_hist);
    assert_eq!(reopened.live_object_count(), expected_objs);
    let report = reopened.verify_full_chain()?;
    assert_eq!(report.batches_verified, expected_seq);
    assert_eq!(report.live_objects, expected_objs);
    Ok(())
}

fn run_scale_benchmark(
    label: &str,
    total_live_objects: usize,
    objects_per_batch: usize,
    probe_commits: usize,
) -> TestResult {
    let dir = fresh_dir(label)?;
    let total_load_batches = total_live_objects.div_ceil(objects_per_batch) as u64;
    let cfg = EpochLedgerConfig {
        max_epoch_bytes: 64 * 1024 * 1024,
        max_batches_per_epoch: 10_000,
        checkpoint_stride: total_load_batches,
        max_objects: None,
    };

    let mut ledger = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    let mut created = 0_usize;
    let mut batch_idx = 0_u64;
    while created < total_live_objects {
        batch_idx += 1;
        let count = objects_per_batch.min(total_live_objects - created);
        let mut deltas = Vec::with_capacity(count);
        for offset in 0..count {
            let id_num = created + offset;
            let obj_id = ObjectId::parse(format!("object:scale-{id_num:07}"))?;
            deltas.push(make_delta(
                &format!("load-{id_num}"),
                obj_id,
                None,
                1,
                "sensor_capsule",
                Plane::Authority,
            )?);
        }
        let batch = ledger.prepare_batch(
            BatchId::parse(format!("batch:load-{batch_idx}"))?,
            deltas,
            [],
        )?;
        ledger.append_batch(batch)?;
        created += count;
    }

    assert_eq!(ledger.live_object_count(), total_live_objects as u64);

    // Measure incremental single-object update commits on top of N live objects
    let t_append = Instant::now();
    for p in 0..probe_commits {
        batch_idx += 1;
        let obj_id = ObjectId::parse(format!("object:scale-{p:07}"))?;
        let d = make_delta(
            &format!("upd-{p}"),
            obj_id,
            Some(1),
            2,
            "sensor_capsule",
            Plane::Authority,
        )?;
        let batch = ledger.prepare_batch(
            BatchId::parse(format!("batch:upd-{batch_idx}"))?,
            vec![d],
            [],
        )?;
        ledger.append_batch(batch)?;
    }
    let append_us = t_append.elapsed().as_micros() / (probe_commits as u128);

    // Emit final checkpoint right at head and record size
    let cp = ledger.force_checkpoint()?;
    let expected_seq = ledger.commit_sequence();
    let expected_root = ledger.state_root();
    let checkpoint_bytes = cp.file_bytes;
    drop(ledger);

    // Measure cold-open from checkpoint
    let t_open = Instant::now();
    let reopened = MerkleEpochLedger::open(&dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    let open_ms = t_open.elapsed().as_millis();

    assert_eq!(reopened.commit_sequence(), expected_seq);
    assert_eq!(reopened.state_root(), expected_root);
    assert_eq!(reopened.live_object_count(), total_live_objects as u64);
    assert_eq!(reopened.recovery_summary().replayed_tail_batches, 0);

    // Verify O(log N) inclusion and non-inclusion proofs at full scale
    let present_id = ObjectId::parse("object:scale-0000000")?;
    let absent_id = ObjectId::parse("object:scale-missing")?;
    let p_in = reopened.prove_object(&present_id)?;
    let p_out = reopened.prove_object(&absent_id)?;
    assert!(p_in.is_inclusion());
    assert!(!p_out.is_inclusion());
    verify_proof(reopened.state_root(), &present_id, &p_in)?;
    verify_proof(reopened.state_root(), &absent_id, &p_out)?;

    println!(
        "{{\"commit_seq\":{},\"live_objects\":{},\"append_us\":{},\"open_ms\":{},\"checkpoint_bytes\":{}}}",
        expected_seq, total_live_objects, append_us, open_ms, checkpoint_bytes
    );
    Ok(())
}

#[test]
fn scale_benchmark_10k_live_objects_jsonl() -> TestResult {
    run_scale_benchmark("scale-10k", 10_000, 200, 20)
}

#[test]
#[ignore = "heavy 100k scale benchmark; run explicitly with --ignored --nocapture"]
fn scale_benchmark_100k_live_objects_jsonl() -> TestResult {
    run_scale_benchmark("scale-100k", 100_000, 1_000, 20)
}
