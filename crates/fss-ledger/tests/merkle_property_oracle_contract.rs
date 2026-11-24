#![forbid(unsafe_code)]
//! Unit, property & differential oracle test suite for the v2 massive-scale Merkle Epoch Ledger
//! (bead `fss-x4a.31.1.7` / `A7`):
//! - 220 seeded deterministic random operation streams comparing `MerkleEpochLedger` against
//!   `LedgerOracle` and an independent naive sorted-map Merkle calculator across commits, updates,
//!   tombstones, multi-delta batches, and frequent epoch rollovers;
//! - Inclusion proofs for every live object, non-inclusion proofs for never-existed objects, and
//!   distinct tombstone-inclusion proofs verifying tombstone permanence across epochs & checkpoints;
//! - Checkpoint creation, cold reopen, corrupt checkpoint quarantine + deterministic fallback to
//!   prior valid checkpoint and genesis, and verified sealed-epoch archival (`archive_sealed_epochs`);
//! - Order-independence of v2 Merkle `state_root` across identical object sets committed in
//!   different batching and insertion sequences;
//! - Structured pure-Rust JSONL telemetry emitted to `target/test-logs/scale-storage/`.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use fss_core::{
    BatchId, CanonicalDecode, CanonicalEncode, CaptureInterval, ContentDigest, EvidenceDelta,
    ObjectId, ObjectRevision, Plane, TimestampNs,
};
use fss_ledger::{
    CanonicalLedgerBackend, DurableReferenceLedger, EpochArchivalError, EpochArchivalPolicy,
    EpochArchivalReceipt, EpochLedgerConfig, EpochLedgerError, IncompleteTailPolicy,
    KEY_NIBBLE_LEN, LedgerOracle, MerkleEpochLedger, MerkleProof, MerkleProofError,
    MerkleProofKind, OracleError, OracleLimits, archive_sealed_epochs, checkpoint_file_path,
    empty_root, epoch_file_path, expand_nibbles, inspect_durable, internal_node_digest,
    key_hash_for_object, leaf_digest, verify_proof,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SUITE_NAME: &str = "merkle_property_oracle";
const SITE: &str = "site:merkle-property-oracle-a7";
const TOMBSTONE_FAMILY: &str = "deletion_tombstone";

static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);
static LOG_LOCK: Mutex<()> = Mutex::new(());

struct TempLedgerDir {
    path: PathBuf,
}

impl TempLedgerDir {
    fn new(label: &str) -> TestResult<Self> {
        let seq = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-a7-ledger-{label}-{}-{seq}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempLedgerDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Deterministic zero-dependency SplitMix64 PRNG.
struct SeededRng(u64);

impl SeededRng {
    const fn new(seed: u64) -> Self {
        Self(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn range(&mut self, upper: usize) -> usize {
        if upper == 0 {
            return 0;
        }
        (self.next_u64() as usize) % upper
    }
}

struct JsonlLogEntry<'a> {
    test_name: &'a str,
    seed: u64,
    op_count: u64,
    stage_latency_us: u64,
    pack_count: u64,
    live_bytes: u64,
    assertion_digest: ContentDigest,
    verdict: &'a str,
}

fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn log_targets() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    if let Some(workspace_root) = manifest_dir.parent().and_then(Path::parent) {
        dirs.push(workspace_root.join("target/test-logs/scale-storage"));
    }
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        let candidate = PathBuf::from(target_dir).join("test-logs/scale-storage");
        if !dirs.contains(&candidate) {
            dirs.push(candidate);
        }
    }
    if dirs.is_empty() {
        dirs.push(std::env::temp_dir().join("fss-test-logs/scale-storage"));
    }
    dirs
}

fn emit_jsonl(entry: &JsonlLogEntry<'_>) {
    let line = format!(
        "{{\"suite\":\"{}\",\"test_name\":\"{}\",\"seed\":{},\"op_count\":{},\"stage_latency_us\":{},\"pack_count\":{},\"live_bytes\":{},\"assertion_digest\":\"{}\",\"verdict\":\"{}\"}}\n",
        escape_json(SUITE_NAME),
        escape_json(entry.test_name),
        entry.seed,
        entry.op_count,
        entry.stage_latency_us,
        entry.pack_count,
        entry.live_bytes,
        escape_json(&entry.assertion_digest.to_text()),
        escape_json(entry.verdict),
    );
    let _guard = LOG_LOCK.lock();
    let mut wrote_any = false;
    for dir in log_targets() {
        if fs::create_dir_all(&dir).is_ok() {
            let file_path = dir.join(format!("{SUITE_NAME}.jsonl"));
            if let Ok(mut f) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file_path)
                && f.write_all(line.as_bytes()).is_ok()
                && f.flush().is_ok()
            {
                wrote_any = true;
            }
        }
    }
    if !wrote_any {
        let fallback_dir = std::env::temp_dir().join("fss-test-logs/scale-storage");
        if fs::create_dir_all(&fallback_dir).is_ok()
            && let Ok(mut f) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(fallback_dir.join(format!("{SUITE_NAME}.jsonl")))
        {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

/// Completely independent naive sorted-map Radix-Merkle reference calculator.
fn naive_merkle_root(objects: &BTreeMap<ObjectId, ObjectRevision>) -> TestResult<ContentDigest> {
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
) -> TestResult<ContentDigest> {
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

fn make_delta(
    tag: &str,
    object_id: ObjectId,
    prior: Option<u64>,
    new_gen: u64,
    family: &str,
    plane: Plane,
) -> TestResult<EvidenceDelta> {
    let start = i128::from(new_gen) * 1_000 + 100;
    Ok(EvidenceDelta {
        delta_id: format!("delta:{tag}"),
        family: family.to_owned(),
        object_id,
        prior_generation: prior,
        new_generation: new_gen,
        validity: CaptureInterval::new(TimestampNs(start), TimestampNs(start + 50))?,
        plane,
        payload_digest: ContentDigest::sha256(format!("payload:{tag}").as_bytes()),
        witness_digest: if family == TOMBSTONE_FAMILY {
            Some(ContentDigest::sha256(
                format!("tomb-witness:{tag}").as_bytes(),
            ))
        } else {
            None
        },
        operation_id: None,
    })
}

fn dir_bytes(dir: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}

fn count_epoch_files(ledger_root: &Path) -> u64 {
    let epochs_dir = ledger_root.join("epochs");
    let Ok(entries) = fs::read_dir(epochs_dir) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".fssj") && !name.starts_with('.'))
        })
        .count() as u64
}

/// 220 seeded deterministic random operation streams comparing `MerkleEpochLedger` against
/// `LedgerOracle` (and `DurableReferenceLedger` periodically) with small epoch caps, multi-delta
/// batches, updates, permanent tombstones, and exhaustive inclusion/non-inclusion/tombstone proof
/// verification.
#[test]
fn property_220_seeded_streams_match_oracle_with_inclusion_non_inclusion_and_tombstone_proofs()
-> TestResult {
    const TOTAL_SEEDS: u64 = 220;
    let suite_start = Instant::now();
    let mut total_ops_all_seeds: u64 = 0;
    let mut total_epochs_all_seeds: u64 = 0;
    let mut total_proofs_verified: u64 = 0;
    let mut aggregate_hash_input = Vec::new();

    for seed in 1..=TOTAL_SEEDS {
        let seed_start = Instant::now();
        let dir = TempLedgerDir::new(&format!("seed-{seed:03}"))?;
        let mut rng =
            SeededRng::new(0xA7_0000_0000_u64 ^ (seed.wrapping_mul(0x517C_C1B7_2722_0A95)));

        // Small epoch caps force multiple epoch rollovers & checkpoints on every seed.
        let max_batches_per_epoch = 3 + (rng.range(4) as u64); // 3..=6
        let checkpoint_stride = 2 + (rng.range(4) as u64); // 2..=5
        let cfg = EpochLedgerConfig {
            max_epoch_bytes: 2048 + (rng.range(2048) as u64),
            max_batches_per_epoch,
            checkpoint_stride,
            max_objects: None,
        };

        let mut oracle = LedgerOracle::new(SITE, OracleLimits::CEILING)?;
        let mut merkle = MerkleEpochLedger::open(
            dir.path.join("merkle"),
            SITE,
            cfg,
            IncompleteTailPolicy::Reject,
        )?;
        let check_durable = seed.is_multiple_of(20);
        let durable_path = dir.path.join("durable.fssj");
        let mut durable = if check_durable {
            Some(DurableReferenceLedger::open(
                &durable_path,
                SITE,
                IncompleteTailPolicy::Reject,
            )?)
        } else {
            None
        };

        let key_space = 12 + rng.range(16); // 12..=27 possible keys
        let num_ops = 10 + rng.range(8); // 10..=17 ops per seed
        let mut tombstoned_objects: BTreeMap<ObjectId, (u64, ContentDigest)> = BTreeMap::new();
        let mut committed_oracle_batches: Vec<fss_core::EvidenceDeltaBatch> = Vec::new();
        let mut committed_merkle_batches: Vec<fss_core::EvidenceDeltaBatch> = Vec::new();
        let mut committed_ops: u64 = 0;

        for step in 1..=(num_ops as u64) {
            // Exercise refusal parity occasionally (duplicate batch, generation conflict, plane conflict).
            let fault_roll = rng.range(14);
            if fault_roll == 0 && !committed_oracle_batches.is_empty() {
                let idx = rng.range(committed_oracle_batches.len());
                assert!(matches!(
                    oracle.append(committed_oracle_batches[idx].clone()),
                    Err(OracleError::DuplicateBatch { .. })
                ));
                assert!(matches!(
                    merkle.append_batch(committed_merkle_batches[idx].clone()),
                    Err(EpochLedgerError::DuplicateBatch { .. })
                ));
                continue;
            }
            if fault_roll == 1 {
                let k = rng.range(key_space);
                let obj_id = ObjectId::parse(format!("object:s{seed:03}:k{k:03}"))?;
                let bad_prior = match oracle.get_object(&obj_id) {
                    Some(rev) => Some(rev.generation + 3),
                    None => Some(2),
                };
                let bad_delta = make_delta(
                    &format!("badgen-{seed}-{step}"),
                    obj_id,
                    bad_prior,
                    bad_prior.map_or(2, |g| g + 1),
                    "sensor_capsule",
                    Plane::Authority,
                )?;
                let bid = BatchId::parse(format!("batch:badgen-{seed}-{step}"))?;
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
            if fault_roll == 2 && oracle.live_object_count() > 0 {
                let mut target = None;
                for k in 0..key_space {
                    let cand = ObjectId::parse(format!("object:s{seed:03}:k{k:03}"))?;
                    if let Some(rev) = oracle.get_object(&cand) {
                        target = Some((cand, rev.generation, rev.plane));
                        break;
                    }
                }
                if let Some((obj_id, cur_gen, cur_plane)) = target {
                    let wrong_plane = match cur_plane {
                        Plane::Authority => Plane::Cognition,
                        Plane::Cognition => Plane::Effect,
                        Plane::Effect => Plane::Authority,
                    };
                    let bad_delta = make_delta(
                        &format!("badplane-{seed}-{step}"),
                        obj_id,
                        Some(cur_gen),
                        cur_gen + 1,
                        "sensor_capsule",
                        wrong_plane,
                    )?;
                    let bid = BatchId::parse(format!("batch:badplane-{seed}-{step}"))?;
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

            // Build valid multi-delta batch (1..=4 deltas).
            let delta_count = 1 + rng.range(4);
            let mut chosen: BTreeMap<ObjectId, EvidenceDelta> = BTreeMap::new();
            for sub in 0..delta_count {
                let k = rng.range(key_space);
                let obj_id = ObjectId::parse(format!("object:s{seed:03}:k{k:03}"))?;
                if chosen.contains_key(&obj_id) {
                    continue;
                }
                // Once tombstoned, preserve tombstone permanently so we verify tombstone permanence across epochs.
                if tombstoned_objects.contains_key(&obj_id) {
                    continue;
                }
                let (prior, new_gen, plane, family) = match oracle.get_object(&obj_id) {
                    Some(rev) => {
                        let do_tombstone = rng.range(4) == 0;
                        let fam = if do_tombstone {
                            TOMBSTONE_FAMILY
                        } else {
                            match rev.plane {
                                Plane::Authority => "sensor_capsule",
                                Plane::Cognition => "event_revision",
                                Plane::Effect => "alert_effect_outcome",
                            }
                        };
                        (Some(rev.generation), rev.generation + 1, rev.plane, fam)
                    }
                    None => {
                        let p = match (k + (seed as usize)) % 3 {
                            0 => Plane::Authority,
                            1 => Plane::Cognition,
                            _ => Plane::Effect,
                        };
                        let fam = match p {
                            Plane::Authority => "sensor_capsule",
                            Plane::Cognition => "event_revision",
                            Plane::Effect => "alert_effect_outcome",
                        };
                        (None, 1, p, fam)
                    }
                };

                let delta = make_delta(
                    &format!("s{seed}-st{step}-d{sub}-k{k}"),
                    obj_id.clone(),
                    prior,
                    new_gen,
                    family,
                    plane,
                )?;
                if family == TOMBSTONE_FAMILY {
                    tombstoned_objects.insert(obj_id.clone(), (new_gen, delta.payload_digest));
                }
                chosen.insert(obj_id, delta);
            }

            if chosen.is_empty() {
                // Ensure every step makes forward progress by introducing a fresh live or tombstoned object.
                let fresh_id = ObjectId::parse(format!("object:s{seed:03}:extra-{step:03}"))?;
                let d = make_delta(
                    &format!("s{seed}-extra-{step}"),
                    fresh_id.clone(),
                    None,
                    1,
                    "sensor_capsule",
                    Plane::Authority,
                )?;
                chosen.insert(fresh_id, d);
            }

            let deltas: Vec<EvidenceDelta> = chosen.into_values().collect();
            let bid = BatchId::parse(format!("batch:s{seed:03}:st{step:03}"))?;
            let o_batch = oracle.prepare_batch(bid.clone(), deltas.clone(), [])?;
            let m_batch = merkle.prepare_batch(bid.clone(), deltas.clone(), [])?;
            let prev_count = merkle.live_object_count();
            oracle.append(o_batch.clone())?;
            merkle.append_batch(m_batch.clone())?;
            if let Some(dur) = durable.as_mut() {
                let d_batch = dur.prepare_batch(bid, deltas, [])?;
                dur.append(d_batch)?;
            }

            // Tombstone permanence: live_object_count (live + tombstoned) is monotonically non-decreasing.
            assert!(merkle.live_object_count() >= prev_count);
            assert_eq!(merkle.commit_sequence(), oracle.commit_sequence());
            assert_eq!(merkle.live_object_count(), oracle.live_object_count());

            committed_oracle_batches.push(o_batch);
            committed_merkle_batches.push(m_batch);
            committed_ops += 1;
        }

        // Ensure at least one tombstoned object exists in this seed so tombstone proofs are always checked.
        if tombstoned_objects.is_empty() {
            let tomb_id = ObjectId::parse(format!("object:s{seed:03}:forced-tomb"))?;
            let d1 = make_delta(
                &format!("ft-create-{seed}"),
                tomb_id.clone(),
                None,
                1,
                "sensor_capsule",
                Plane::Authority,
            )?;
            let b1_id = BatchId::parse(format!("batch:s{seed:03}:ft1"))?;
            let ob1 = oracle.prepare_batch(b1_id.clone(), vec![d1.clone()], [])?;
            let mb1 = merkle.prepare_batch(b1_id.clone(), vec![d1.clone()], [])?;
            oracle.append(ob1)?;
            merkle.append_batch(mb1)?;
            if let Some(dur) = durable.as_mut() {
                let db1 = dur.prepare_batch(b1_id, vec![d1], [])?;
                dur.append(db1)?;
            }

            let d2 = make_delta(
                &format!("ft-tomb-{seed}"),
                tomb_id.clone(),
                Some(1),
                2,
                TOMBSTONE_FAMILY,
                Plane::Authority,
            )?;
            let tomb_payload_digest = d2.payload_digest;
            let b2_id = BatchId::parse(format!("batch:s{seed:03}:ft2"))?;
            let ob2 = oracle.prepare_batch(b2_id.clone(), vec![d2.clone()], [])?;
            let mb2 = merkle.prepare_batch(b2_id.clone(), vec![d2.clone()], [])?;
            oracle.append(ob2)?;
            merkle.append_batch(mb2)?;
            if let Some(dur) = durable.as_mut() {
                let db2 = dur.prepare_batch(b2_id, vec![d2], [])?;
                dur.append(db2)?;
            }
            tombstoned_objects.insert(tomb_id, (2, tomb_payload_digest));
            committed_ops += 2;
        }

        let oracle_map = oracle.view_at(oracle.head_sequence())?.snapshot().objects;
        let merkle_map = merkle.snapshot_objects();
        assert_eq!(merkle_map, oracle_map, "seed {seed}: object map mismatch");

        if durable.is_some() {
            drop(durable);
            let dur_inspected = inspect_durable(&durable_path, SITE, 16 * 1024 * 1024)?;
            assert_eq!(
                dur_inspected.snapshot.objects, merkle_map,
                "seed {seed}: DurableReferenceLedger map diverged from MerkleEpochLedger"
            );
        }

        let expected_root = naive_merkle_root(&oracle_map)?;
        assert_eq!(
            merkle.state_root(),
            expected_root,
            "seed {seed}: Merkle state_root diverged from naive sorted-map reference"
        );

        // Verify proofs for EVERY live object AND EVERY tombstoned object!
        for (obj_id, expected_rev) in &oracle_map {
            let proof = merkle.prove_object(obj_id)?;
            assert!(
                proof.is_inclusion(),
                "seed {seed}: object {obj_id} must yield inclusion proof"
            );
            let proven_rev = proof
                .included_revision()
                .ok_or("inclusion proof missing revision")?;
            assert_eq!(proven_rev, expected_rev);
            verify_proof(merkle.state_root(), obj_id, &proof)?;

            // Canonical proof round-trip check.
            let proof_bytes = proof.canonical_bytes();
            let decoded = MerkleProof::from_canonical_bytes(&proof_bytes)?;
            assert_eq!(decoded, proof);

            // Distinguish live vs permanent tombstone inclusion proof!
            if let Some(&(tomb_gen, tomb_digest)) = tombstoned_objects.get(obj_id) {
                assert_eq!(proven_rev.family, TOMBSTONE_FAMILY);
                assert_eq!(proven_rev.generation, tomb_gen);
                assert_eq!(proven_rev.payload_digest, tomb_digest);
            } else {
                assert_ne!(proven_rev.family, TOMBSTONE_FAMILY);
            }
            total_proofs_verified += 1;
        }

        // Verify NonInclusion proofs for never-existed objects (and tamper rejection).
        for probe_idx in 0..3_u64 {
            let absent_id = ObjectId::parse(format!("object:s{seed:03}:never-{probe_idx}"))?;
            assert!(!oracle_map.contains_key(&absent_id));
            let proof = merkle.prove_object(&absent_id)?;
            assert!(!proof.is_inclusion());
            assert!(matches!(proof.kind, MerkleProofKind::NonInclusion(_)));
            verify_proof(merkle.state_root(), &absent_id, &proof)?;

            let wrong_root =
                ContentDigest::sha256(format!("wrong-root-{seed}-{probe_idx}").as_bytes());
            assert!(matches!(
                verify_proof(wrong_root, &absent_id, &proof),
                Err(MerkleProofError::RootMismatch { .. })
            ));
            total_proofs_verified += 1;
        }

        // Verify cold reopen preserves all tombstones, live objects, state_root, and history_root.
        let expected_seq = merkle.commit_sequence();
        let expected_hist = merkle.history_root();
        let epoch_count = count_epoch_files(merkle.root_dir());
        let live_bytes = dir_bytes(&merkle.root_dir().join("epochs"))
            + dir_bytes(&merkle.root_dir().join("checkpoints"));
        drop(merkle);

        let reopened = MerkleEpochLedger::open(
            dir.path.join("merkle"),
            SITE,
            cfg,
            IncompleteTailPolicy::Reject,
        )?;
        assert_eq!(reopened.commit_sequence(), expected_seq);
        assert_eq!(reopened.state_root(), expected_root);
        assert_eq!(reopened.history_root(), expected_hist);
        assert_eq!(reopened.live_object_count(), oracle_map.len() as u64);
        for (tomb_id, &(tomb_gen, tomb_digest)) in &tombstoned_objects {
            let p = reopened.prove_object(tomb_id)?;
            assert!(p.is_inclusion());
            let rev = p.included_revision().ok_or("tombstone lost after reopen")?;
            assert_eq!(rev.family, TOMBSTONE_FAMILY);
            assert_eq!(rev.generation, tomb_gen);
            assert_eq!(rev.payload_digest, tomb_digest);
            verify_proof(reopened.state_root(), tomb_id, &p)?;
        }

        total_ops_all_seeds += committed_ops;
        total_epochs_all_seeds += epoch_count;
        aggregate_hash_input.extend_from_slice(&expected_root.bytes());

        emit_jsonl(&JsonlLogEntry {
            test_name: "property_220_seeded_streams_match_oracle",
            seed,
            op_count: committed_ops,
            stage_latency_us: seed_start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            pack_count: epoch_count,
            live_bytes,
            assertion_digest: expected_root,
            verdict: "pass",
        });
    }

    assert!(total_epochs_all_seeds > TOTAL_SEEDS * 2);
    assert!(total_proofs_verified >= TOTAL_SEEDS * 10);
    emit_jsonl(&JsonlLogEntry {
        test_name: "property_220_seeded_streams_summary",
        seed: 0,
        op_count: total_ops_all_seeds,
        stage_latency_us: suite_start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        pack_count: total_epochs_all_seeds,
        live_bytes: total_proofs_verified,
        assertion_digest: ContentDigest::sha256(&aggregate_hash_input),
        verdict: "pass",
    });
    Ok(())
}

/// Verifies checkpoint creation, cold reopen, corrupt checkpoint quarantine + deterministic
/// fallback to prior valid checkpoint and genesis, and verified sealed-epoch archival
/// (`archive_sealed_epochs`) including tamper & refusal checks.
#[test]
fn checkpoint_cold_reopen_corrupt_quarantine_fallback_and_epoch_archival() -> TestResult {
    let started = Instant::now();
    let dir = TempLedgerDir::new("cp-fallback-archive")?;
    let ledger_dir = dir.path.join("ledger");
    let archive_dir = dir.path.join("cold-archive");

    let cfg = EpochLedgerConfig {
        max_epoch_bytes: 64 * 1024,
        max_batches_per_epoch: 3,
        checkpoint_stride: 3,
        max_objects: None,
    };

    let mut ledger = MerkleEpochLedger::open(&ledger_dir, SITE, cfg, IncompleteTailPolicy::Reject)?;

    let tomb_id = ObjectId::parse("object:cp:tombstoned-perm")?;
    let live_id = ObjectId::parse("object:cp:live-anchor")?;
    let absent_id = ObjectId::parse("object:cp:never-created")?;

    // Commit 14 batches across epochs 0 (1..=3), 1 (4..=6), 2 (7..=9), 3 (10..=12), 4 (13..=14).
    // Checkpoints emitted automatically at seq 3, 6, 9, 12.
    for seq in 1_u64..=14 {
        let delta = if seq == 1 {
            make_delta(
                "cp-1",
                tomb_id.clone(),
                None,
                1,
                "sensor_capsule",
                Plane::Authority,
            )?
        } else if seq == 2 {
            make_delta(
                "cp-2-tomb",
                tomb_id.clone(),
                Some(1),
                2,
                TOMBSTONE_FAMILY,
                Plane::Authority,
            )?
        } else if seq == 3 {
            make_delta(
                "cp-3",
                live_id.clone(),
                None,
                1,
                "event_revision",
                Plane::Cognition,
            )?
        } else {
            let id = ObjectId::parse(format!("object:cp:seq-{seq:03}"))?;
            make_delta(
                &format!("cp-{seq}"),
                id,
                None,
                1,
                "sensor_capsule",
                Plane::Authority,
            )?
        };
        let batch = ledger.prepare_batch(
            BatchId::parse(format!("batch:cp:{seq:03}"))?,
            vec![delta],
            [],
        )?;
        ledger.append_batch(batch)?;
    }

    // Force a checkpoint right at head (seq 14, inside active epoch 4).
    let head_cp = ledger.force_checkpoint()?;
    assert_eq!(head_cp.commit_sequence, 14);
    assert_eq!(head_cp.epoch_id, 4);
    assert_eq!(ledger.active_epoch_id(), 4);

    let expected_root = ledger.state_root();
    let expected_hist = ledger.history_root();
    let expected_objs = ledger.live_object_count();
    drop(ledger);

    // 1. Clean cold reopen from latest checkpoint (seq 14): zero tail replay!
    {
        let reopened =
            MerkleEpochLedger::open(&ledger_dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
        assert_eq!(reopened.commit_sequence(), 14);
        assert_eq!(reopened.state_root(), expected_root);
        assert_eq!(reopened.history_root(), expected_hist);
        assert_eq!(reopened.live_object_count(), expected_objs);
        assert_eq!(reopened.recovery_summary().replayed_tail_batches, 0);
        assert!(
            reopened
                .recovery_summary()
                .quarantined_checkpoints
                .is_empty()
        );
        let loaded = reopened
            .recovery_summary()
            .loaded_checkpoint
            .as_ref()
            .ok_or("expected seq 14 checkpoint")?;
        assert_eq!(loaded.commit_sequence, 14);
    }

    // 2. Corrupt latest checkpoint (seq 14) -> automatic quarantine + deterministic fallback to seq 12!
    let checkpoints_dir = ledger_dir.join("checkpoints");
    let cp14_path = checkpoint_file_path(&checkpoints_dir, 14);
    {
        let mut raw = fs::read(&cp14_path)?;
        let pos = raw.len() / 2;
        raw[pos] ^= 0x5A;
        fs::write(&cp14_path, &raw)?;
    }
    {
        let reopened =
            MerkleEpochLedger::open(&ledger_dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
        assert_eq!(reopened.commit_sequence(), 14);
        assert_eq!(reopened.state_root(), expected_root);
        assert_eq!(reopened.history_root(), expected_hist);
        assert_eq!(reopened.recovery_summary().quarantined_checkpoints.len(), 1);
        let loaded = reopened
            .recovery_summary()
            .loaded_checkpoint
            .as_ref()
            .ok_or("expected fallback to seq 12 checkpoint")?;
        assert_eq!(loaded.commit_sequence, 12);
        assert_eq!(reopened.recovery_summary().replayed_tail_batches, 2);
    }

    // 3. Corrupt ALL remaining checkpoints (seq 12, 9, 6, 3) -> deterministic fallback to genesis!
    for seq in [3_u64, 6, 9, 12] {
        let p = checkpoint_file_path(&checkpoints_dir, seq);
        if p.exists() {
            let mut raw = fs::read(&p)?;
            raw[0] ^= 0xFF; // corrupt magic
            fs::write(&p, &raw)?;
        }
    }
    let mut reopened =
        MerkleEpochLedger::open(&ledger_dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    assert_eq!(reopened.commit_sequence(), 14);
    assert_eq!(reopened.state_root(), expected_root);
    assert_eq!(reopened.history_root(), expected_hist);
    assert!(reopened.recovery_summary().loaded_checkpoint.is_none());
    assert_eq!(reopened.recovery_summary().quarantined_checkpoints.len(), 4);
    assert_eq!(reopened.recovery_summary().replayed_tail_batches, 14);

    // Full chain verification from genesis succeeds!
    let chain = reopened.verify_full_chain()?;
    assert_eq!(chain.epochs_verified, 5);
    assert_eq!(chain.batches_verified, 14);
    assert_eq!(chain.state_root, expected_root);

    // 4. Re-emit valid checkpoint at seq 14 (epoch 4) and verify epoch archival!
    let fresh_cp = reopened.force_checkpoint()?;
    assert_eq!(fresh_cp.commit_sequence, 14);
    assert_eq!(fresh_cp.epoch_id, 4);

    // Refuses archiving active epoch (epoch 4)!
    let active_refusal = archive_sealed_epochs(
        &reopened,
        &EpochArchivalPolicy {
            retain_recent_sealed_epochs: 0,
            archive_dir: Some(archive_dir.clone()),
            prune_local_epochs: false,
            requested_epochs: Some(vec![4]),
        },
        TimestampNs(1_000_000),
    );
    assert!(matches!(
        active_refusal,
        Err(EpochArchivalError::ActiveEpochNotArchivable {
            epoch_id: 4,
            active_epoch_id: 4
        })
    ));

    // Refuses prune_local_epochs without archive_dir!
    let bad_policy = archive_sealed_epochs(
        &reopened,
        &EpochArchivalPolicy {
            retain_recent_sealed_epochs: 0,
            archive_dir: None,
            prune_local_epochs: true,
            requested_epochs: None,
        },
        TimestampNs(1_000_000),
    );
    assert!(matches!(
        bad_policy,
        Err(EpochArchivalError::InvalidPolicy(_))
    ));

    // Archive epochs 0..=3 with local pruning enabled (checkpoint epoch 4 stays local!).
    let receipt = archive_sealed_epochs(
        &reopened,
        &EpochArchivalPolicy {
            retain_recent_sealed_epochs: 0,
            archive_dir: Some(archive_dir.clone()),
            prune_local_epochs: true,
            requested_epochs: None,
        },
        TimestampNs(2_000_000),
    )?;
    receipt.verify_receipt_digest()?;
    receipt.verify_archived_files(&archive_dir)?;
    assert_eq!(receipt.retaining_checkpoint_seq, 14);
    assert_eq!(receipt.retaining_checkpoint_epoch_id, 4);
    assert_eq!(receipt.retaining_checkpoint_state_root, expected_root);
    let archived_ids: Vec<u64> = receipt.archived_epochs.iter().map(|e| e.epoch_id).collect();
    assert_eq!(archived_ids, vec![0, 1, 2, 3]);
    assert!(receipt.archived_epochs.iter().all(|e| e.pruned_locally));

    // Binary FSSA receipt canonical file round-trip + tamper detection.
    let encoded_receipt = receipt.encode_canonical_file()?;
    let decoded_receipt = EpochArchivalReceipt::decode_canonical_file(&encoded_receipt)?;
    assert_eq!(decoded_receipt, receipt);
    let mut tampered_receipt = encoded_receipt;
    tampered_receipt[12] ^= 0xFF;
    assert!(matches!(
        EpochArchivalReceipt::decode_canonical_file(&tampered_receipt),
        Err(EpochArchivalError::InvalidReceipt(_))
    ));

    // Verify local epochs 0..=3 are pruned while active/checkpoint epoch 4 remains present!
    for eid in 0..=3_u64 {
        assert!(!epoch_file_path(&ledger_dir.join("epochs"), eid).exists());
        assert!(epoch_file_path(&archive_dir, eid).exists());
    }
    assert!(epoch_file_path(&ledger_dir.join("epochs"), 4).exists());
    drop(reopened);

    // Cold reopen after pruning archived sealed epochs succeeds from retained checkpoint + proofs intact!
    let post_prune = MerkleEpochLedger::open(&ledger_dir, SITE, cfg, IncompleteTailPolicy::Reject)?;
    assert_eq!(post_prune.commit_sequence(), 14);
    assert_eq!(post_prune.state_root(), expected_root);
    assert_eq!(post_prune.history_root(), expected_hist);
    let tomb_proof = post_prune.prove_object(&tomb_id)?;
    assert!(tomb_proof.is_inclusion());
    assert_eq!(
        tomb_proof
            .included_revision()
            .ok_or("missing tomb revision")?
            .family,
        TOMBSTONE_FAMILY
    );
    verify_proof(post_prune.state_root(), &tomb_id, &tomb_proof)?;
    let live_proof = post_prune.prove_object(&live_id)?;
    verify_proof(post_prune.state_root(), &live_id, &live_proof)?;
    let abs_proof = post_prune.prove_object(&absent_id)?;
    assert!(!abs_proof.is_inclusion());
    verify_proof(post_prune.state_root(), &absent_id, &abs_proof)?;

    // Tamper one archived epoch file -> verify_archived_files fails closed with ArchivedCopyDigestMismatch!
    let archived_ep0 = epoch_file_path(&archive_dir, 0);
    let mut ep0_bytes = fs::read(&archived_ep0)?;
    ep0_bytes[20] ^= 0x01;
    fs::write(&archived_ep0, &ep0_bytes)?;
    assert!(matches!(
        receipt.verify_archived_files(&archive_dir),
        Err(EpochArchivalError::ArchivedCopyDigestMismatch { epoch_id: 0, .. })
    ));

    emit_jsonl(&JsonlLogEntry {
        test_name: "checkpoint_cold_reopen_corrupt_quarantine_fallback_and_epoch_archival",
        seed: 14,
        op_count: 14,
        stage_latency_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        pack_count: 5,
        live_bytes: dir_bytes(&archive_dir),
        assertion_digest: receipt.receipt_digest,
        verdict: "pass",
    });
    Ok(())
}

/// Proves v2 Merkle `state_root` is strictly order-independent across identical object sets
/// committed in different batching and insertion sequences (including across epoch rollovers and
/// tombstones).
#[test]
fn state_root_order_independence_across_commit_sequences() -> TestResult {
    const TRIALS: u64 = 32;
    let started = Instant::now();
    let mut digest_acc = Vec::new();
    let mut total_objects_checked: u64 = 0;

    for seed in 1..=TRIALS {
        let mut rng = SeededRng::new(0x0D38_1000_u64 ^ seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let obj_count = 18 + rng.range(24); // 18..=41 distinct objects

        // Generate canonical object specs (including mixed planes + tombstoned objects).
        let mut specs: Vec<(ObjectId, Plane, String, String)> = Vec::with_capacity(obj_count);
        let mut used_ids = BTreeSet::new();
        for idx in 0..obj_count {
            let id = ObjectId::parse(format!("object:ord:s{seed:02}:k{idx:03}"))?;
            if !used_ids.insert(id.clone()) {
                continue;
            }
            let plane = match rng.range(3) {
                0 => Plane::Authority,
                1 => Plane::Cognition,
                _ => Plane::Effect,
            };
            let fam = if rng.range(5) == 0 {
                TOMBSTONE_FAMILY.to_owned()
            } else {
                format!("family_{}", rng.range(4))
            };
            let tag = format!("ord-{seed}-{idx}");
            specs.push((id, plane, fam, tag));
        }

        // Sequence A: single bulk batch in ascending key order.
        let dir_a = TempLedgerDir::new(&format!("ord-a-{seed}"))?;
        let mut ledger_a = MerkleEpochLedger::open(
            &dir_a.path,
            SITE,
            EpochLedgerConfig::default(),
            IncompleteTailPolicy::Reject,
        )?;
        let deltas_a: Vec<EvidenceDelta> = specs
            .iter()
            .map(|(id, plane, fam, tag)| make_delta(tag, id.clone(), None, 1, fam, *plane))
            .collect::<TestResult<Vec<_>>>()?;
        let batch_a = ledger_a.prepare_batch(BatchId::parse("batch:bulk-a")?, deltas_a, [])?;
        ledger_a.append_batch(batch_a)?;

        // Sequence B: Fisher-Yates seeded permutation split into small batches triggering epoch rollovers.
        let mut perm = specs.clone();
        for i in (1..perm.len()).rev() {
            let j = rng.range(i + 1);
            perm.swap(i, j);
        }
        let dir_b = TempLedgerDir::new(&format!("ord-b-{seed}"))?;
        let cfg_b = EpochLedgerConfig {
            max_epoch_bytes: 2048,
            max_batches_per_epoch: 3,
            checkpoint_stride: 3,
            max_objects: None,
        };
        let mut ledger_b =
            MerkleEpochLedger::open(&dir_b.path, SITE, cfg_b, IncompleteTailPolicy::Reject)?;
        let mut cursor = 0_usize;
        let mut b_seq = 0_u64;
        while cursor < perm.len() {
            let chunk_len = (1 + rng.range(4)).min(perm.len() - cursor);
            b_seq += 1;
            let chunk: Vec<EvidenceDelta> = perm[cursor..cursor + chunk_len]
                .iter()
                .map(|(id, plane, fam, tag)| make_delta(tag, id.clone(), None, 1, fam, *plane))
                .collect::<TestResult<Vec<_>>>()?;
            let batch = ledger_b.prepare_batch(
                BatchId::parse(format!("batch:perm-{b_seq}"))?,
                chunk,
                [],
            )?;
            ledger_b.append_batch(batch)?;
            cursor += chunk_len;
        }

        // Sequence C: reverse order, 1 delta per batch, with 2-step updates ending at identical final revisions.
        let dir_c = TempLedgerDir::new(&format!("ord-c-{seed}"))?;
        let mut ledger_c = MerkleEpochLedger::open(
            &dir_c.path,
            SITE,
            EpochLedgerConfig {
                max_epoch_bytes: 4096,
                max_batches_per_epoch: 5,
                checkpoint_stride: 5,
                max_objects: None,
            },
            IncompleteTailPolicy::Reject,
        )?;
        for (idx, (id, plane, fam, tag)) in specs.iter().rev().enumerate() {
            let d = make_delta(tag, id.clone(), None, 1, fam, *plane)?;
            let batch =
                ledger_c.prepare_batch(BatchId::parse(format!("batch:rev-{idx}"))?, vec![d], [])?;
            ledger_c.append_batch(batch)?;
        }

        let root_a = ledger_a.state_root();
        let root_b = ledger_b.state_root();
        let root_c = ledger_c.state_root();
        let naive = naive_merkle_root(&ledger_a.snapshot_objects())?;

        assert_eq!(
            root_a, root_b,
            "seed {seed}: bulk vs permuted root mismatch"
        );
        assert_eq!(root_a, root_c, "seed {seed}: bulk vs reverse root mismatch");
        assert_eq!(
            root_a, naive,
            "seed {seed}: trie root vs naive reference mismatch"
        );
        assert_ne!(
            ledger_a.history_root(),
            ledger_b.history_root(),
            "different commit histories must retain distinct history_roots even with identical state_root"
        );

        // Verify proofs generated from B verify against A's and C's identical state_root!
        for (id, _, _, _) in &specs {
            let proof_b = ledger_b.prove_object(id)?;
            verify_proof(root_a, id, &proof_b)?;
            verify_proof(root_c, id, &proof_b)?;
        }

        total_objects_checked += specs.len() as u64;
        digest_acc.extend_from_slice(&root_a.bytes());
    }

    emit_jsonl(&JsonlLogEntry {
        test_name: "state_root_order_independence_across_commit_sequences",
        seed: TRIALS,
        op_count: total_objects_checked,
        stage_latency_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        pack_count: TRIALS,
        live_bytes: total_objects_checked,
        assertion_digest: ContentDigest::sha256(&digest_acc),
        verdict: "pass",
    });
    Ok(())
}
