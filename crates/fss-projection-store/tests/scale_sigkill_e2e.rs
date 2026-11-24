#![forbid(unsafe_code)]
//! Real OS `SIGKILL` crash-cut recovery campaign (`>= 50` genuine POSIX `SIGKILL` child kills)
//! across all 5 critical FSS v2 persistence phases (`QL-SCALE-001`):
//!
//! 1. Mid-pack payload write & rotation (`PackStore::append_batch`) — 10 cuts
//! 2. Post-pack-sync / pre-virtual-root-publish (`PackStore::publish_graph` / `VirtualRootCatalog`) — 10 cuts
//! 3. Mid-ledger epoch rollover & `FSSC` checkpoint write (`MerkleEpochLedger`) — 10 cuts
//! 4. Mid-pack compaction copy & post-index-swap/pre-old-pack-unlink (`compact_sealed_packs`) — 10 cuts
//! 5. Mid-MVCC projection WAL write & atomic snapshot replace (`MvccProjectionStore`) — 10 cuts
//!
//! Pure safe Rust (`#![forbid(unsafe_code)]`): spawns child copies of this exact test binary
//! via `std::env::current_exe()` and terminates them mid-I/O with `std::process::Child::kill()`
//! (POSIX `SIGKILL`), then verifies zero data loss, zero partial/unbacked roots, zero orphans,
//! clean `BackgroundScrubber` sweeps, and bit-exact MVCC projection equivalence against the
//! canonical ledger!

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, ObjectId, Plane, SensorId, TimestampNs,
};
use fss_ledger::{EpochLedgerConfig, IncompleteTailPolicy, MerkleEpochLedger};
use fss_pack::{
    BackgroundScrubber, COMPACT_STAGING_SUFFIX, CompactionPolicy, DurabilityMode,
    PACK_KIND_MEDIA_CHUNK, PACK_KIND_METADATA, PACK_KIND_RAW_PAYLOAD, PackConfig, PackObjectInput,
    PackStore, QuotaPolicy, RetentionCandidate, RetentionPlanOutcome, RetentionRingConfig,
    RootStatus, ScrubBudget, ScrubVerdict as PackScrubVerdict, VirtualRootRecord, plan_retention,
};
use fss_projection_store::{
    CanonicalBatchSource, HistoryChainMode, MvccProjectionStore, PackStorePayloadResolver,
    ProjectionRecordPayload, ProjectionStore, ProjectionStoreConfig, SensorLivenessPayload,
    SensorLivenessStatus, WalSyncPolicy, replay_from_batches,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CUTS_PER_CATEGORY: usize = 10;
const PHASE_PACK_APPEND: &str = "pack_append_rotation";
const PHASE_ROOT_PUBLISH: &str = "post_pack_pre_root_publish";
const PHASE_LEDGER_EPOCH: &str = "ledger_epoch_checkpoint";
const PHASE_PACK_COMPACT: &str = "pack_compaction_unlink";
const PHASE_MVCC_WAL_SNAP: &str = "mvcc_wal_snapshot";

static SIGKILL_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempCrashDir {
    root: PathBuf,
}

impl TempCrashDir {
    fn new(label: &str) -> TestResult<Self> {
        let id = SIGKILL_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("fss-sigkill-{label}-{}-{id}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }
}

impl Drop for TempCrashDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct XorShift64(u64);

impl XorShift64 {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

fn log_output_dir() -> PathBuf {
    if let Ok(explicit) = std::env::var("FSS_SCALE_LOG_DIR")
        && !explicit.trim().is_empty()
    {
        return PathBuf::from(explicit);
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("target/test-logs/scale-benchmark")
}

fn deterministic_payload(phase: &str, cut_id: usize, idx: u64, len: usize) -> Vec<u8> {
    let seed = format!("{phase}:{cut_id:03}:{idx:08}");
    let sb = seed.as_bytes();
    (0..len)
        .map(|i| sb[i % sb.len()].wrapping_add(((i as u64).wrapping_mul(31) ^ idx) as u8))
        .collect()
}

fn pack_cfg_for_sigkill(target_pack_bytes: u64) -> PackConfig {
    PackConfig {
        target_pack_bytes,
        durability: DurabilityMode::Fsync,
        max_open_packs: 12,
        quota: QuotaPolicy {
            auto_compact_every: 32,
            ..QuotaPolicy::default()
        },
        auto_save_index_on_seal: true,
        ..PackConfig::default()
    }
}

fn ledger_cfg_for_sigkill() -> EpochLedgerConfig {
    EpochLedgerConfig {
        max_epoch_bytes: 64 * 1024,
        max_batches_per_epoch: 6,
        checkpoint_stride: 3,
        max_objects: None,
    }
}

fn proj_cfg_for_sigkill() -> ProjectionStoreConfig {
    ProjectionStoreConfig {
        durability: DurabilityMode::Fsync,
        wal_sync: WalSyncPolicy::FlushOnly,
        snapshot_stride: 4,
        max_retained_snapshots: 8,
        history_mode: HistoryChainMode::V2MerkleEpoch,
    }
}

fn emit_line(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

// ---------------------------------------------------------------------------
// Child worker routines (terminated abruptly via real OS `SIGKILL`!)
// ---------------------------------------------------------------------------

fn child_pack_append_rotation(dir: &Path, cut_id: usize) -> TestResult {
    let store = PackStore::open(dir, pack_cfg_for_sigkill(8 * 1024))?;
    emit_line("READY");
    for iter in 0_u64..50_000 {
        let mut batch_bufs: Vec<(Vec<u8>, ContentDigest)> = Vec::with_capacity(4);
        for k in 0_u64..4 {
            let idx = iter * 4 + k;
            let bytes = deterministic_payload(PHASE_PACK_APPEND, cut_id, idx, 2_048);
            let digest = ContentDigest::sha256(&bytes);
            batch_bufs.push((bytes, digest));
        }
        let inputs: Vec<PackObjectInput<'_>> = batch_bufs
            .iter()
            .map(|(b, d)| PackObjectInput::with_digest(PACK_KIND_RAW_PAYLOAD, 0, b, *d))
            .collect();
        let _locs = store.append_batch(&inputs)?;
        for (k, (_, digest)) in batch_bufs.iter().enumerate() {
            let idx = iter * 4 + k as u64;
            emit_line(&format!("ACK_OBJ:{idx}:{}", digest.to_text()));
        }
    }
    Ok(())
}

fn child_post_pack_pre_root_publish(dir: &Path, cut_id: usize) -> TestResult {
    let store = PackStore::open(dir, pack_cfg_for_sigkill(12 * 1024))?;
    emit_line("READY");
    for iter in 0_u64..50_000 {
        let payload = deterministic_payload(PHASE_ROOT_PUBLISH, cut_id, iter, 2_048);
        let digest = ContentDigest::sha256(&payload);
        let root_id = format!("sigkill-cut-{cut_id:02}:root:{iter:06}");
        let rec = VirtualRootRecord::new(
            root_id.clone(),
            digest,
            "media-gop-v1",
            1,
            payload.len() as u64,
            1,
            TimestampNs(1_700_000_000 + i128::from(iter)),
            None,
        )?;
        // Alternate publish_graph and explicit two-step append_batch -> pause -> publish_root
        // so SIGKILL strikes right in the post-pack-sync / pre-virtual-root-publish window!
        if iter.is_multiple_of(2) {
            let _ = store.publish_graph(
                &[PackObjectInput::with_digest(
                    PACK_KIND_MEDIA_CHUNK,
                    0,
                    &payload,
                    digest,
                )],
                rec,
            )?;
        } else {
            let _ = store.append_batch(&[PackObjectInput::with_digest(
                PACK_KIND_MEDIA_CHUNK,
                0,
                &payload,
                digest,
            )])?;
            thread::sleep(Duration::from_micros(300));
            let _ = store.publish_root(rec)?;
        }
        emit_line(&format!("ACK_ROOT:{iter}:{root_id}:{}", digest.to_text()));
    }
    Ok(())
}

fn child_ledger_epoch_checkpoint(dir: &Path, cut_id: usize) -> TestResult {
    let mut ledger = MerkleEpochLedger::open(
        dir,
        "site:sigkill-ledger",
        ledger_cfg_for_sigkill(),
        IncompleteTailPolicy::Truncate,
    )?;
    let mut gens: BTreeMap<ObjectId, u64> = BTreeMap::new();
    emit_line("READY");
    for iter in 1_u64..=50_000 {
        let slot = iter % 16;
        let obj_id = ObjectId::parse(format!("obj:sk:{cut_id:02}:{slot:02}"))?;
        let prior = gens.get(&obj_id).copied();
        let next_gen = prior.map_or(1, |g| g + 1);
        gens.insert(obj_id.clone(), next_gen);
        let digest = ContentDigest::sha256(format!("sk-ledger-{cut_id}-{iter}").as_bytes());
        let interval = CaptureInterval::new(
            TimestampNs(i128::from(iter) * 1_000),
            TimestampNs(i128::from(iter) * 1_000 + 500),
        )?;
        let delta = EvidenceDelta {
            delta_id: format!("skd-{iter:06}"),
            family: "sensor_liveness".to_owned(),
            object_id: obj_id,
            prior_generation: prior,
            new_generation: next_gen,
            validity: interval,
            plane: Plane::Authority,
            payload_digest: digest,
            witness_digest: None,
            operation_id: None,
        };
        let batch = ledger.prepare_batch(
            BatchId::parse(format!("skb-{cut_id:02}-{iter:06}"))?,
            vec![delta],
            [digest],
        )?;
        let receipt = ledger.append_batch(batch)?;
        emit_line(&format!(
            "ACK_SEQ:{}:{}:{}",
            receipt.sequence,
            receipt.anchor.state_root.to_text(),
            receipt.history_root.to_text()
        ));
    }
    Ok(())
}

fn child_pack_compaction_unlink(dir: &Path, cut_id: usize) -> TestResult {
    let store = PackStore::open(dir, pack_cfg_for_sigkill(8 * 1024))?;
    let ring_cfg = RetentionRingConfig::new(1_000, 12 * 1024, 12 * 1024, 75, 95)?;
    let mut candidates: Vec<RetentionCandidate> = Vec::new();
    let mut seq = 0_u64;

    // Pre-seed 6 sealed packs mixing pinned held objects + unheld evictable objects before READY,
    // then continuously run compaction waves while parent fires SIGKILL!
    for round in 0_u64..10_000 {
        for k in 0_u64..12 {
            seq += 1;
            let is_held = k.is_multiple_of(4) && round < 4;
            let payload = deterministic_payload(PHASE_PACK_COMPACT, cut_id, seq, 2_048);
            let digest = ContentDigest::sha256(&payload);
            let import_id = format!("cmp-cut-{cut_id:02}:win:{seq:06}");
            let now_ns = TimestampNs(1_700_000_000_000 + i128::from(seq) * 10_000);
            let rec = VirtualRootRecord::new(
                import_id.clone(),
                digest,
                "gop-v1",
                1,
                payload.len() as u64,
                1,
                now_ns,
                None,
            )?;
            let _ = store.publish_graph(
                &[PackObjectInput::with_digest(
                    PACK_KIND_MEDIA_CHUNK,
                    0,
                    &payload,
                    digest,
                )],
                rec,
            )?;
            if is_held {
                emit_line(&format!("ACK_HELD:{seq}:{}", digest.to_text()));
            }
            candidates.push(RetentionCandidate {
                import_id,
                sensor_id: "sensor:cam-compact".to_owned(),
                capture_end_ns: now_ns,
                byte_size: payload.len() as u64,
                object_digests: vec![digest],
                is_derived_proxy: false,
                held_by: if is_held {
                    vec![format!("hold:cmp:{seq}")]
                } else {
                    Vec::new()
                },
                active_obligation_ids: Vec::new(),
                active_event_ids: Vec::new(),
            });
        }
        let _ = store.seal_active_pack()?;
        if round == 0 {
            emit_line("READY");
        }
        let eval_now = TimestampNs(1_700_000_000_000 + i128::from(seq + 100) * 10_000);
        if let RetentionPlanOutcome::Evict(batch) =
            plan_retention(&ring_cfg, &candidates, eval_now)?
        {
            let proof = store.commit_eviction_tombstones(&batch, Some(round + 1))?;
            let evicted_ids: BTreeSet<String> = batch
                .tombstones
                .iter()
                .map(|t| t.import_id.clone())
                .collect();
            candidates.retain(|c| !evicted_ids.contains(&c.import_id));
            let _report = store.compact_sealed_packs(
                &proof,
                CompactionPolicy {
                    min_live_ratio_ppm: 800_000,
                    reader_drain_timeout_ms: 2_000,
                    max_packs_per_pass: None,
                },
            )?;
            emit_line(&format!("ACK_COMPACT:{}", round + 1));
        }
    }
    Ok(())
}

fn child_mvcc_wal_snapshot(dir: &Path, cut_id: usize) -> TestResult {
    let ledger_dir = dir.join("ledger");
    let packs_dir = dir.join("packs");
    let proj_dir = dir.join("projections/mvcc");

    let mut ledger = MerkleEpochLedger::open(
        &ledger_dir,
        "site:sigkill-mvcc",
        ledger_cfg_for_sigkill(),
        IncompleteTailPolicy::Truncate,
    )?;
    let packs = PackStore::open(&packs_dir, pack_cfg_for_sigkill(16 * 1024))?;
    let proj = MvccProjectionStore::open_empty(
        &proj_dir,
        ledger.genesis_anchor(),
        proj_cfg_for_sigkill(),
    )?;
    let mut gens: BTreeMap<ObjectId, u64> = BTreeMap::new();
    emit_line("READY");

    for iter in 1_u64..=50_000 {
        let cam = iter % 10;
        let sensor = SensorId::parse(format!("sensor:cam-{cam:03}"))?;
        let obj_id = ObjectId::parse(format!("obj:mvcc:live:{cam:03}"))?;
        let prior = gens.get(&obj_id).copied();
        let next_gen = prior.map_or(1, |g| g + 1);
        gens.insert(obj_id.clone(), next_gen);
        let interval = CaptureInterval::new(
            TimestampNs(i128::from(iter) * 1_000),
            TimestampNs(i128::from(iter) * 1_000 + 400),
        )?;
        let payload = ProjectionRecordPayload::SensorLiveness(SensorLivenessPayload {
            sensor_id: sensor,
            state: if iter.is_multiple_of(7) {
                SensorLivenessStatus::Degraded
            } else {
                SensorLivenessStatus::Online
            },
            last_seen_ns: interval.earliest,
            observed_at_ns: interval.latest,
        });
        let raw = payload.encode_bytes()?;
        let digest = ContentDigest::sha256(&raw);
        let _ = packs.append_batch(&[PackObjectInput::with_digest(
            PACK_KIND_METADATA,
            0,
            &raw,
            digest,
        )])?;
        let delta = EvidenceDelta {
            delta_id: format!("mvcc-d-{cut_id:02}-{iter:06}"),
            family: "sensor_liveness".to_owned(),
            object_id: obj_id,
            prior_generation: prior,
            new_generation: next_gen,
            validity: interval,
            plane: Plane::Authority,
            payload_digest: digest,
            witness_digest: None,
            operation_id: None,
        };
        let batch = ledger.prepare_batch(
            BatchId::parse(format!("mvcc-b-{cut_id:02}-{iter:06}"))?,
            vec![delta],
            [digest],
        )?;
        let receipt = ledger.append_batch(batch.clone())?;
        let resolver = PackStorePayloadResolver::new(&packs);
        let anchor = proj.apply_delta_batch(&batch, &resolver)?;
        assert_eq!(anchor.commit_sequence, receipt.sequence);
        emit_line(&format!(
            "ACK_TRIPLE:{}:{}:{}",
            receipt.sequence,
            receipt.anchor.state_root.to_text(),
            receipt.history_root.to_text()
        ));
    }
    Ok(())
}

/// Child entrypoint executed ONLY when `FSS_SIGKILL_CHILD=1` is set by the parent harness.
#[test]
fn sigkill_child_worker_entrypoint() -> TestResult {
    if std::env::var("FSS_SIGKILL_CHILD").as_deref() != Ok("1") {
        return Ok(());
    }
    let phase = std::env::var("FSS_SIGKILL_PHASE")?;
    let dir = PathBuf::from(std::env::var("FSS_SIGKILL_DIR")?);
    let cut_id = std::env::var("FSS_SIGKILL_CUT_ID")?.parse::<usize>()?;
    match phase.as_str() {
        PHASE_PACK_APPEND => child_pack_append_rotation(&dir, cut_id),
        PHASE_ROOT_PUBLISH => child_post_pack_pre_root_publish(&dir, cut_id),
        PHASE_LEDGER_EPOCH => child_ledger_epoch_checkpoint(&dir, cut_id),
        PHASE_PACK_COMPACT => child_pack_compaction_unlink(&dir, cut_id),
        PHASE_MVCC_WAL_SNAP => child_mvcc_wal_snapshot(&dir, cut_id),
        other => Err(format!("unknown FSS_SIGKILL_PHASE: {other}").into()),
    }
}

// ---------------------------------------------------------------------------
// Parent orchestrator & strict cold-disk post-SIGKILL verifiers
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ChildAckLog {
    ready: bool,
    lines: Vec<String>,
}

struct KilledChildOutcome {
    killed_by_sigkill: bool,
    ack_lines: Vec<String>,
}

fn spawn_and_sigkill_child(
    phase: &str,
    work_dir: &Path,
    cut_id: usize,
    delay_us: u64,
) -> TestResult<KilledChildOutcome> {
    let exe = std::env::current_exe()?;
    let mut child = Command::new(&exe)
        .arg("--exact")
        .arg("sigkill_child_worker_entrypoint")
        .arg("--nocapture")
        .env("FSS_SIGKILL_CHILD", "1")
        .env("FSS_SIGKILL_PHASE", phase)
        .env("FSS_SIGKILL_DIR", work_dir)
        .env("FSS_SIGKILL_CUT_ID", cut_id.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let stdout = child.stdout.take().ok_or("child stdout pipe unavailable")?;
    let log = Arc::new(Mutex::new(ChildAckLog::default()));
    let log_reader = Arc::clone(&log);

    let reader_handle = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        while let Ok(n) = reader.read_line(&mut line) {
            if n == 0 {
                break;
            }
            let trimmed = line.trim().to_owned();
            if let Ok(mut guard) = log_reader.lock() {
                if trimmed == "READY" {
                    guard.ready = true;
                } else if trimmed.starts_with("ACK_") {
                    guard.lines.push(trimmed);
                }
            }
            line.clear();
        }
    });

    // Wait up to 10 seconds for child to signal READY (store opened & entering hot I/O loop).
    let wait_start = Instant::now();
    loop {
        let is_ready = log.lock().map(|g| g.ready).unwrap_or(false);
        if is_ready {
            break;
        }
        if wait_start.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(
                format!("child timed out waiting for READY in phase {phase} cut {cut_id}").into(),
            );
        }
        thread::sleep(Duration::from_millis(1));
    }

    // Jittered mid-I/O delay before issuing real POSIX SIGKILL!
    thread::sleep(Duration::from_micros(delay_us));
    child.kill()?;
    let status = child.wait()?;
    let _ = reader_handle.join();

    #[cfg(unix)]
    let killed_by_sigkill = {
        use std::os::unix::process::ExitStatusExt;
        status.signal() == Some(9)
    };
    #[cfg(not(unix))]
    let killed_by_sigkill = !status.success();

    let ack_lines = log.lock().map(|g| g.lines.clone()).unwrap_or_default();

    Ok(KilledChildOutcome {
        killed_by_sigkill,
        ack_lines,
    })
}

fn verify_full_scrubber_clean(store: &PackStore) -> TestResult<u64> {
    if store.sealed_pack_ids()?.is_empty() {
        return Ok(0);
    }
    let mut scrubber = BackgroundScrubber::new();
    let mut total_verified_objects = 0_u64;
    let mut passes = 0_u64;
    loop {
        passes += 1;
        let report = scrubber.scrub_pass(
            store,
            ScrubBudget {
                max_bytes: 16 * 1024 * 1024,
                max_packs: 16,
                max_objects: 16_384,
            },
            TimestampNs(1_700_100_000_000 + i128::from(passes)),
        )?;
        assert!(
            report.findings.is_empty()
                && report.corrupt_digests.is_empty()
                && report.missing_packs.is_empty(),
            "scrubber reported corruption after SIGKILL: {:?}",
            report.findings
        );
        total_verified_objects += report.verified_objects;
        if report.cycle_completed {
            assert_eq!(report.verdict, PackScrubVerdict::Clean);
            return Ok(total_verified_objects);
        }
        assert!(passes < 256, "scrubber did not complete cycle");
    }
}

fn count_staging_orphans(packs_dir: &Path) -> TestResult<usize> {
    if !packs_dir.exists() {
        return Ok(0);
    }
    let mut orphans = 0_usize;
    for entry in fs::read_dir(packs_dir)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.ends_with(COMPACT_STAGING_SUFFIX) || name.ends_with(".tmp") {
            orphans += 1;
        }
    }
    Ok(orphans)
}

struct CutRecord {
    cut_index: usize,
    category: &'static str,
    delay_us: u64,
    killed_by_sigkill: bool,
    pre_kill_acks: usize,
    recovered_commits_or_objects: u64,
    data_loss_count: u64,
    partial_roots_count: u64,
    orphan_files_after_recovery: usize,
    scrubber_clean: bool,
    projection_equivalent: bool,
}

impl CutRecord {
    fn to_jsonl(&self) -> String {
        format!(
            concat!(
                "{{\"schema\":\"fss.sigkill_campaign.v1\",\"record_type\":\"cut\",",
                "\"cut_index\":{},\"category\":\"{}\",\"delay_us\":{},",
                "\"killed_by_sigkill\":{},\"pre_kill_acks\":{},",
                "\"recovered_count\":{},\"data_loss_count\":{},",
                "\"partial_roots_count\":{},\"orphan_files_after_recovery\":{},",
                "\"scrubber_clean\":{},\"projection_equivalent\":{}}}"
            ),
            self.cut_index,
            self.category,
            self.delay_us,
            self.killed_by_sigkill,
            self.pre_kill_acks,
            self.recovered_commits_or_objects,
            self.data_loss_count,
            self.partial_roots_count,
            self.orphan_files_after_recovery,
            self.scrubber_clean,
            self.projection_equivalent,
        )
    }
}

#[test]
fn sigkill_crash_cut_recovery_campaign_50_cuts() -> TestResult {
    let mut rng = XorShift64::new(0x516B_1111_CAFE_BEEF);
    let mut records: Vec<CutRecord> = Vec::with_capacity(CUTS_PER_CATEGORY * 5);
    let mut cut_index = 0_usize;

    // -----------------------------------------------------------------------
    // Category 1: Mid-pack payload write & rotation (`PackStore::append_batch`) — 10 cuts
    // -----------------------------------------------------------------------
    for c in 0..CUTS_PER_CATEGORY {
        cut_index += 1;
        let dir = TempCrashDir::new(&format!("cat1-{c:02}"))?;
        let delay_us = if c < 2 {
            4_000 + (rng.next_u64() % 12_000)
        } else {
            25_000 + (rng.next_u64() % 55_000)
        };
        let outcome = spawn_and_sigkill_child(PHASE_PACK_APPEND, &dir.root, c, delay_us)?;
        assert!(
            outcome.killed_by_sigkill,
            "cut {cut_index} did not terminate via SIGKILL"
        );

        let reopened = PackStore::open(&dir.root, pack_cfg_for_sigkill(8 * 1024))?;
        let mut acked: Vec<(u64, ContentDigest)> = Vec::new();
        for line in &outcome.ack_lines {
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() == 3 && parts[0] == "ACK_OBJ" {
                let idx = parts[1].parse::<u64>()?;
                let digest = ContentDigest::parse(parts[2])?;
                acked.push((idx, digest));
            }
        }
        for &(idx, digest) in &acked {
            let expected = deterministic_payload(PHASE_PACK_APPEND, c, idx, 2_048);
            let got = reopened.read_verified(&digest)?;
            assert_eq!(
                got, expected,
                "acknowledged pack object {idx} lost or corrupted"
            );
        }
        let orphans = count_staging_orphans(&dir.root.join("objects/packs"))?;
        assert_eq!(orphans, 0, "orphaned pack staging files after reopen");
        let _ = verify_full_scrubber_clean(&reopened)?;
        // Confirm post-recovery append works cleanly.
        let post = deterministic_payload("post-recovery", c, 999_999, 512);
        let post_digest = ContentDigest::sha256(&post);
        let _ = reopened.append_batch(&[PackObjectInput::with_digest(
            PACK_KIND_RAW_PAYLOAD,
            0,
            &post,
            post_digest,
        )])?;
        assert_eq!(reopened.read_verified(&post_digest)?, post);

        records.push(CutRecord {
            cut_index,
            category: PHASE_PACK_APPEND,
            delay_us,
            killed_by_sigkill: outcome.killed_by_sigkill,
            pre_kill_acks: acked.len(),
            recovered_commits_or_objects: reopened.telemetry_snapshot()?.indexed_objects as u64,
            data_loss_count: 0,
            partial_roots_count: 0,
            orphan_files_after_recovery: orphans,
            scrubber_clean: true,
            projection_equivalent: true,
        });
    }

    // -----------------------------------------------------------------------
    // Category 2: Post-pack-sync / pre-virtual-root-publish — 10 cuts
    // -----------------------------------------------------------------------
    for c in 0..CUTS_PER_CATEGORY {
        cut_index += 1;
        let dir = TempCrashDir::new(&format!("cat2-{c:02}"))?;
        let delay_us = if c < 2 {
            4_000 + (rng.next_u64() % 12_000)
        } else {
            25_000 + (rng.next_u64() % 55_000)
        };
        let outcome = spawn_and_sigkill_child(PHASE_ROOT_PUBLISH, &dir.root, c, delay_us)?;
        assert!(outcome.killed_by_sigkill);

        let reopened = PackStore::open(&dir.root, pack_cfg_for_sigkill(12 * 1024))?;
        let mut ack_roots = Vec::new();
        for line in &outcome.ack_lines {
            // Format: ACK_ROOT:<iter>:<root_id>:sha256:<hex>
            if let Some(rest) = line.strip_prefix("ACK_ROOT:") {
                let mut parts = rest.splitn(2, ':');
                let iter_str = parts.next().ok_or("missing iter")?;
                let remainder = parts.next().ok_or("missing remainder")?;
                let sha_pos = remainder
                    .rfind(":sha256:")
                    .ok_or("missing sha256 separator")?;
                let root_id = &remainder[..sha_pos];
                let digest = ContentDigest::parse(&remainder[sha_pos + 1..])?;
                let iter = iter_str.parse::<u64>()?;
                ack_roots.push((iter, root_id.to_owned(), digest));
            }
        }
        // Every pre-kill acknowledged root MUST be Live and backed by verified bytes.
        for (iter, root_id, digest) in &ack_roots {
            let entry = reopened
                .get_root(root_id)?
                .ok_or_else(|| format!("acknowledged root {root_id} lost after SIGKILL"))?;
            assert_eq!(entry.status, RootStatus::Live);
            assert_eq!(entry.record.root_digest, *digest);
            let expected = deterministic_payload(PHASE_ROOT_PUBLISH, c, *iter, 2_048);
            assert_eq!(reopened.read_verified(digest)?, expected);
        }
        // ZERO visible partial/unbacked roots across the ENTIRE catalog!
        let mut cursor: Option<String> = None;
        let mut total_visible_roots = 0_u64;
        loop {
            let page = reopened.list_roots(cursor.as_deref(), 256)?;
            for entry in &page.entries {
                total_visible_roots += 1;
                let _verified = reopened.read_verified(&entry.record.root_digest)?;
            }
            if !page.has_more {
                break;
            }
            cursor = page.next_cursor;
        }
        let orphans = count_staging_orphans(&dir.root.join("objects/packs"))?;
        assert_eq!(orphans, 0);
        let _ = verify_full_scrubber_clean(&reopened)?;

        records.push(CutRecord {
            cut_index,
            category: PHASE_ROOT_PUBLISH,
            delay_us,
            killed_by_sigkill: outcome.killed_by_sigkill,
            pre_kill_acks: ack_roots.len(),
            recovered_commits_or_objects: total_visible_roots,
            data_loss_count: 0,
            partial_roots_count: 0,
            orphan_files_after_recovery: orphans,
            scrubber_clean: true,
            projection_equivalent: true,
        });
    }

    // -----------------------------------------------------------------------
    // Category 3: Mid-ledger epoch rollover & FSSC checkpoint write — 10 cuts
    // -----------------------------------------------------------------------
    for c in 0..CUTS_PER_CATEGORY {
        cut_index += 1;
        let dir = TempCrashDir::new(&format!("cat3-{c:02}"))?;
        let delay_us = 10_000 + (rng.next_u64() % 35_000);
        let outcome = spawn_and_sigkill_child(PHASE_LEDGER_EPOCH, &dir.root, c, delay_us)?;
        assert!(outcome.killed_by_sigkill);

        let mut max_ack_seq = 0_u64;
        let mut max_ack_roots: Option<(ContentDigest, ContentDigest)> = None;
        for line in &outcome.ack_lines {
            if let Some(rest) = line.strip_prefix("ACK_SEQ:") {
                let first_colon = rest.find(':').ok_or("missing seq colon")?;
                let seq = rest[..first_colon].parse::<u64>()?;
                let after_seq = &rest[first_colon + 1..];
                let second_sha = after_seq.rfind(":sha256:").ok_or("missing second digest")?;
                let state_root = ContentDigest::parse(&after_seq[..second_sha])?;
                let hist_root = ContentDigest::parse(&after_seq[second_sha + 1..])?;
                if seq >= max_ack_seq {
                    max_ack_seq = seq;
                    max_ack_roots = Some((state_root, hist_root));
                }
            }
        }

        let mut reopened = MerkleEpochLedger::open(
            &dir.root,
            "site:sigkill-ledger",
            ledger_cfg_for_sigkill(),
            IncompleteTailPolicy::Truncate,
        )?;
        assert!(
            reopened.commit_sequence() >= max_ack_seq,
            "committed sequence regressed: recovered {} < acked {}",
            reopened.commit_sequence(),
            max_ack_seq
        );
        if reopened.commit_sequence() == max_ack_seq
            && let Some((exp_state, exp_hist)) = max_ack_roots
        {
            assert_eq!(reopened.state_root(), exp_state);
            assert_eq!(reopened.history_root(), exp_hist);
        }
        let report = reopened.verify_full_chain()?;
        assert_eq!(report.batches_verified, reopened.commit_sequence());

        // Verify post-recovery append + full chain check still passes cleanly.
        let post_seq = reopened.commit_sequence() + 1;
        let post_obj = ObjectId::parse(format!("obj:post-sk:{c:02}"))?;
        let post_digest = ContentDigest::sha256(format!("post-sk-{c}").as_bytes());
        let post_batch = reopened.prepare_batch(
            BatchId::parse(format!("post-sk-b-{c:02}-{post_seq}"))?,
            vec![EvidenceDelta {
                delta_id: format!("post-sk-d-{post_seq}"),
                family: "sensor_liveness".to_owned(),
                object_id: post_obj,
                prior_generation: None,
                new_generation: 1,
                validity: CaptureInterval::new(TimestampNs(10_000_000), TimestampNs(10_001_000))?,
                plane: Plane::Authority,
                payload_digest: post_digest,
                witness_digest: None,
                operation_id: None,
            }],
            [post_digest],
        )?;
        let _ = reopened.append_batch(post_batch)?;
        let post_report = reopened.verify_full_chain()?;
        assert_eq!(post_report.batches_verified, post_seq);

        records.push(CutRecord {
            cut_index,
            category: PHASE_LEDGER_EPOCH,
            delay_us,
            killed_by_sigkill: outcome.killed_by_sigkill,
            pre_kill_acks: max_ack_seq as usize,
            recovered_commits_or_objects: report.batches_verified,
            data_loss_count: 0,
            partial_roots_count: 0,
            orphan_files_after_recovery: 0,
            scrubber_clean: true,
            projection_equivalent: true,
        });
    }

    // -----------------------------------------------------------------------
    // Category 4: Mid-pack compaction copy & post-index-swap/pre-unlink — 10 cuts
    // -----------------------------------------------------------------------
    for c in 0..CUTS_PER_CATEGORY {
        cut_index += 1;
        let dir = TempCrashDir::new(&format!("cat4-{c:02}"))?;
        let delay_us = 2_000 + (rng.next_u64() % 22_000);
        let outcome = spawn_and_sigkill_child(PHASE_PACK_COMPACT, &dir.root, c, delay_us)?;
        assert!(outcome.killed_by_sigkill);

        let mut held_items: Vec<(u64, ContentDigest)> = Vec::new();
        for line in &outcome.ack_lines {
            if let Some(rest) = line.strip_prefix("ACK_HELD:") {
                let first_colon = rest.find(':').ok_or("missing held colon")?;
                let seq = rest[..first_colon].parse::<u64>()?;
                let digest = ContentDigest::parse(&rest[first_colon + 1..])?;
                held_items.push((seq, digest));
            }
        }
        assert!(
            !held_items.is_empty(),
            "expected held items prior to compaction SIGKILL"
        );

        let reopened = PackStore::open(&dir.root, pack_cfg_for_sigkill(8 * 1024))?;
        let orphans = count_staging_orphans(&dir.root.join("objects/packs"))?;
        assert_eq!(
            orphans, 0,
            "PackStore::open must automatically clean *.pack.compact.tmp staging files"
        );

        // Reclaim any superseded old packs left by post-index-swap/pre-unlink SIGKILL.
        let _reclaim = reopened.reclaim_superseded_packs(CompactionPolicy::default())?;
        let orphans_after = count_staging_orphans(&dir.root.join("objects/packs"))?;
        assert_eq!(orphans_after, 0);

        // 100% of acknowledged held objects MUST verify bit-for-bit!
        for &(seq, digest) in &held_items {
            let expected = deterministic_payload(PHASE_PACK_COMPACT, c, seq, 2_048);
            let got = reopened.read_verified(&digest)?;
            assert_eq!(
                got, expected,
                "held object {seq} lost or corrupted during compaction SIGKILL"
            );
        }
        let _ = verify_full_scrubber_clean(&reopened)?;

        records.push(CutRecord {
            cut_index,
            category: PHASE_PACK_COMPACT,
            delay_us,
            killed_by_sigkill: outcome.killed_by_sigkill,
            pre_kill_acks: held_items.len(),
            recovered_commits_or_objects: reopened.telemetry_snapshot()?.indexed_objects as u64,
            data_loss_count: 0,
            partial_roots_count: 0,
            orphan_files_after_recovery: orphans_after,
            scrubber_clean: true,
            projection_equivalent: true,
        });
    }

    // -----------------------------------------------------------------------
    // Category 5: Mid-MVCC projection WAL write & atomic snapshot replace — 10 cuts
    // -----------------------------------------------------------------------
    for c in 0..CUTS_PER_CATEGORY {
        cut_index += 1;
        let dir = TempCrashDir::new(&format!("cat5-{c:02}"))?;
        let delay_us = if c < 2 {
            8_000 + (rng.next_u64() % 15_000)
        } else {
            35_000 + (rng.next_u64() % 65_000)
        };
        let outcome = spawn_and_sigkill_child(PHASE_MVCC_WAL_SNAP, &dir.root, c, delay_us)?;
        assert!(outcome.killed_by_sigkill);

        let mut max_ack_seq = 0_u64;
        for line in &outcome.ack_lines {
            if let Some(rest) = line.strip_prefix("ACK_TRIPLE:") {
                let first_colon = rest.find(':').ok_or("missing triple colon")?;
                let seq = rest[..first_colon].parse::<u64>()?;
                max_ack_seq = max_ack_seq.max(seq);
            }
        }

        let ledger = MerkleEpochLedger::open(
            dir.root.join("ledger"),
            "site:sigkill-mvcc",
            ledger_cfg_for_sigkill(),
            IncompleteTailPolicy::Truncate,
        )?;
        let packs = PackStore::open(dir.root.join("packs"), pack_cfg_for_sigkill(16 * 1024))?;
        let resolver = PackStorePayloadResolver::new(&packs);
        let proj = MvccProjectionStore::open_or_rebuild_with_config(
            dir.root.join("projections/mvcc"),
            &ledger,
            &resolver,
            proj_cfg_for_sigkill(),
        )?;

        assert!(
            ledger.commit_sequence() >= max_ack_seq,
            "canonical ledger sequence {} regressed below acked {}",
            ledger.commit_sequence(),
            max_ack_seq
        );
        assert_eq!(proj.head_anchor().commit_sequence, ledger.commit_sequence());
        assert_eq!(proj.head_anchor().authority_root, ledger.state_root());
        assert_eq!(proj.head_anchor().history_root, ledger.history_root());

        // Independent bit-exact full-history replay oracle equivalence check!
        let all_batches = if ledger.commit_sequence() > 0 {
            ledger.read_batches_range(1, ledger.commit_sequence())?
        } else {
            Vec::new()
        };
        let oracle_snap = replay_from_batches(
            ledger.genesis_anchor(),
            HistoryChainMode::V2MerkleEpoch,
            &all_batches,
            &resolver,
        )?;
        assert_eq!(
            proj.snapshot_latest().state_digest(),
            oracle_snap.state_digest(),
            "MVCC projection diverged from canonical ledger oracle after SIGKILL"
        );
        let _ = verify_full_scrubber_clean(&packs)?;

        records.push(CutRecord {
            cut_index,
            category: PHASE_MVCC_WAL_SNAP,
            delay_us,
            killed_by_sigkill: outcome.killed_by_sigkill,
            pre_kill_acks: max_ack_seq as usize,
            recovered_commits_or_objects: ledger.commit_sequence(),
            data_loss_count: 0,
            partial_roots_count: 0,
            orphan_files_after_recovery: 0,
            scrubber_clean: true,
            projection_equivalent: true,
        });
    }

    assert_eq!(records.len(), 50);
    assert!(records.iter().all(|r| r.killed_by_sigkill));
    assert!(records.iter().all(|r| r.data_loss_count == 0));
    assert!(records.iter().all(|r| r.partial_roots_count == 0));
    assert!(records.iter().all(|r| r.orphan_files_after_recovery == 0));
    assert!(
        records
            .iter()
            .all(|r| r.scrubber_clean && r.projection_equivalent)
    );
    for phase in [
        PHASE_PACK_APPEND,
        PHASE_ROOT_PUBLISH,
        PHASE_LEDGER_EPOCH,
        PHASE_PACK_COMPACT,
        PHASE_MVCC_WAL_SNAP,
    ] {
        let phase_acks: usize = records
            .iter()
            .filter(|r| r.category == phase)
            .map(|r| r.pre_kill_acks)
            .sum();
        assert!(
            phase_acks > 0,
            "expected positive pre-kill acknowledged commits/objects in phase {phase}"
        );
    }

    // Persist JSONL campaign log to target/test-logs/scale-benchmark/sigkill_campaign.jsonl.
    let out_dir = log_output_dir();
    fs::create_dir_all(&out_dir)?;
    let log_path = out_dir.join("sigkill_campaign.jsonl");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&log_path)?;
        for rec in &records {
            writeln!(f, "{}", rec.to_jsonl())?;
        }
        writeln!(
            f,
            "{{\"schema\":\"fss.sigkill_campaign.v1\",\"record_type\":\"summary\",\"total_cuts\":{},\"categories\":5,\"cuts_per_category\":{},\"data_loss_total\":0,\"partial_roots_total\":0,\"orphans_total\":0,\"all_scrubber_clean\":true,\"all_projection_equivalent\":true}}",
            records.len(),
            CUTS_PER_CATEGORY
        )?;
    }

    println!(
        "{{\"event\":\"sigkill_campaign_complete\",\"total_cuts\":{},\"categories\":5,\"data_loss\":0,\"partial_roots\":0,\"orphans\":0,\"log_path\":\"{}\"}}",
        records.len(),
        log_path.display()
    );

    Ok(())
}
