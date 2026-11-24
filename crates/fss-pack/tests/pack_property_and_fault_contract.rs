#![forbid(unsafe_code)]
//! Unit, property & fault-injection test suite for the massive-scale Packfile Store,
//! unbounded virtual root catalog, bounded FD pool, retention ring, compaction, and scrubber
//! (bead `fss-x4a.31.1.7` / `A7`):
//! - Seeded deduplication property tests, >2,000 virtual roots, FD-pool eviction under >300 packs
//!   (open FDs strictly <= 16), and concurrent readers across active pack seals & rotations;
//! - Corrupt CRC32C, corrupt SHA-256 payload, corrupt footer magic (`FSSF`/`FSSE`), and corrupt
//!   whole-pack footer digest detection;
//! - Root-last visibility invariant under simulated mid-batch & compaction `PackCutPoint` faults;
//! - Retention & compaction invariants: 10x ring overflow across randomized legal holds & active
//!   obligations (ZERO evicted pinned closures), proxy-first shedding across pressure tiers
//!   (`Nominal` -> `Elevated` -> `Constrained` -> `Critical`), 100% pinned critical refusal with
//!   exact `ERR-STORAGE-QUOTA-PINNED-001`, and scrubber cursor completeness + single-byte
//!   corruption detection across compacted packs;
//! - Structured pure-Rust JSONL telemetry emitted to `target/test-logs/scale-storage/`.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use fss_core::{ContentDigest, TimestampNs};
use fss_pack::{
    BackgroundScrubber, CapacityPressure, CompactionPolicy, DurabilityMode,
    ERR_EVIDENCE_DELETED_001, ERR_STORAGE_QUOTA_PINNED_001, EvictionReason,
    MAX_VERIFIED_FRACTION_PPM, PACK_KIND_MEDIA_CHUNK, PACK_KIND_METADATA, PACK_KIND_RAW_PAYLOAD,
    PACK_RECORD_HEADER_LEN, PACK_RECORD_TRAILER_LEN, PackCompactionAction, PackConfig,
    PackCutPoint, PackError, PackObjectInput, PackStore, QuotaPolicy, RetentionCandidate,
    RetentionPlanOutcome, RetentionRingConfig, RootStatus, ScrubBudget, ScrubFailureKind,
    ScrubVerdict, SensorRetentionPolicy, VirtualRootRecord, compact_staging_file_name, crc32c,
    plan_retention,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SUITE_NAME: &str = "pack_property_and_fault";

static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);
static LOG_LOCK: Mutex<()> = Mutex::new(());

struct TempPackDir {
    path: PathBuf,
}

impl TempPackDir {
    fn new(label: &str) -> TestResult<Self> {
        let seq = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("fss-a7-pack-{label}-{}-{seq}", std::process::id()));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempPackDir {
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

fn pack_cfg(target_pack_bytes: u64, max_open_packs: usize) -> PackConfig {
    PackConfig {
        target_pack_bytes,
        durability: DurabilityMode::Fsync,
        max_open_packs,
        quota: QuotaPolicy {
            auto_compact_every: 10_000,
            ..QuotaPolicy::default()
        },
        ..PackConfig::default()
    }
}

fn make_payload(seed_tag: &str, bytes: usize) -> Vec<u8> {
    let seed = seed_tag.as_bytes();
    (0..bytes)
        .map(|i| seed[i % seed.len()].wrapping_add(((i * 31) & 0xFF) as u8))
        .collect()
}

/// Seeded property test for content-addressed deduplication, >2,000 unbounded virtual roots,
/// and FD-pool LRU eviction across >300 sealed packfiles with open FDs strictly <= 16.
#[test]
fn property_seeded_dedup_unbounded_2500_roots_and_fd_pool_320_packs() -> TestResult {
    let started = Instant::now();

    // Part A: 24 seeded deduplication property trials across intra-batch & cross-batch rotations.
    let mut dedup_digest_acc = Vec::new();
    let mut total_dedup_ops: u64 = 0;
    for seed in 1..=24_u64 {
        let dir = TempPackDir::new(&format!("dedup-{seed:02}"))?;
        let store = PackStore::open(&dir.path, pack_cfg(600, 12))?;
        let mut rng = SeededRng::new(0xDED0_0000_u64 ^ seed);

        // Pool of 12 distinct payloads; randomly sample 30 submissions with heavy duplication.
        let pool: Vec<(ContentDigest, Vec<u8>)> = (0..12_usize)
            .map(|k| {
                let bytes = make_payload(&format!("dedup-s{seed}-k{k}"), 120 + (k * 17));
                (ContentDigest::sha256(&bytes), bytes)
            })
            .collect();

        let mut canonical_locs: BTreeMap<ContentDigest, (fss_pack::PackId, u64, u64)> =
            BTreeMap::new();
        for _round in 0..10_usize {
            let batch_len = 1 + rng.range(5);
            let chosen_idxs: Vec<usize> = (0..batch_len).map(|_| rng.range(pool.len())).collect();
            let all_already_present = chosen_idxs
                .iter()
                .all(|&idx| canonical_locs.contains_key(&pool[idx].0));
            let fsyncs_before = store.telemetry_snapshot()?.pack_fsync_count;

            let inputs: Vec<PackObjectInput<'_>> = chosen_idxs
                .iter()
                .map(|&idx| {
                    PackObjectInput::with_digest(
                        PACK_KIND_RAW_PAYLOAD,
                        0,
                        &pool[idx].1,
                        pool[idx].0,
                    )
                })
                .collect();
            let locs = store.append_batch(&inputs)?;
            assert_eq!(locs.len(), chosen_idxs.len());

            if all_already_present {
                assert_eq!(
                    store.telemetry_snapshot()?.pack_fsync_count,
                    fsyncs_before,
                    "seed {seed}: pure duplicate batch must perform zero pack fsyncs"
                );
            }

            for (&idx, loc) in chosen_idxs.iter().zip(locs.iter()) {
                let digest = pool[idx].0;
                if let Some(&(prev_pack, prev_off, prev_len)) = canonical_locs.get(&digest) {
                    assert_eq!(
                        (loc.pack_id, loc.offset, loc.len),
                        (prev_pack, prev_off, prev_len),
                        "seed {seed}: deduplicated object must resolve to identical pack coordinates"
                    );
                } else {
                    canonical_locs.insert(digest, (loc.pack_id, loc.offset, loc.len));
                }
            }
            total_dedup_ops += batch_len as u64;
        }

        let telem = store.telemetry_snapshot()?;
        assert_eq!(telem.indexed_objects, canonical_locs.len());
        for (digest, expected) in &pool {
            if canonical_locs.contains_key(digest) {
                assert_eq!(store.read_verified(digest)?, *expected);
                dedup_digest_acc.extend_from_slice(&digest.bytes());
            } else {
                assert!(matches!(
                    store.read_verified(digest),
                    Err(PackError::MissingObject(_))
                ));
            }
        }
    }

    // Part B: Unbounded virtual root catalog (>2,000 roots: 2,500 published + supersedes + tombstones).
    let roots_dir = TempPackDir::new("roots-2500")?;
    let roots_store = PackStore::open(&roots_dir.path, pack_cfg(1024 * 1024, 16))?;
    let anchor_payloads: Vec<(ContentDigest, Vec<u8>)> = (0..8_usize)
        .map(|i| {
            let p = make_payload(&format!("root-anchor-{i}"), 256);
            (ContentDigest::sha256(&p), p)
        })
        .collect();
    let anchor_inputs: Vec<PackObjectInput<'_>> = anchor_payloads
        .iter()
        .map(|(d, p)| PackObjectInput::with_digest(PACK_KIND_MEDIA_CHUNK, 0, p, *d))
        .collect();
    let _ = roots_store.append_batch(&anchor_inputs)?;

    const TOTAL_ROOTS: usize = 2_500;
    for chunk_start in (0..TOTAL_ROOTS).step_by(250) {
        let end = (chunk_start + 250).min(TOTAL_ROOTS);
        let mut batch = Vec::with_capacity(end - chunk_start);
        for i in chunk_start..end {
            let (digest, payload) = &anchor_payloads[i % anchor_payloads.len()];
            batch.push(VirtualRootRecord::new(
                format!("cam-{:02}:gop:{i:06}", i % 16),
                *digest,
                "gop-v1",
                1,
                payload.len() as u64,
                1,
                TimestampNs(1_700_000_000_000 + (i as i128) * 1_000),
                None,
            )?);
        }
        let _ = roots_store.publish_roots_batch(&batch)?;
    }
    assert_eq!(roots_store.live_root_count()?, TOTAL_ROOTS as u64);

    // Supersede 20 roots and tombstone 30 roots deterministically.
    for i in 0..20_usize {
        let old_id = format!("cam-{:02}:gop:{i:06}", i % 16);
        let new_id = format!("cam-{:02}:gop:{i:06}:v2", i % 16);
        let (digest, payload) = &anchor_payloads[(i + 1) % anchor_payloads.len()];
        let rec = VirtualRootRecord::new(
            new_id,
            *digest,
            "gop-v1",
            1,
            payload.len() as u64,
            2,
            TimestampNs(2_000_000_000_000 + (i as i128)),
            None,
        )?;
        let _ = roots_store.supersede_root(&old_id, rec)?;
    }
    let tomb_reason = ContentDigest::sha256(b"a7-retention-tombstone");
    for i in 20..50_usize {
        let target_id = format!("cam-{:02}:gop:{i:06}", i % 16);
        let _ = roots_store.tombstone_root(&target_id, tomb_reason)?;
    }
    assert_eq!(roots_store.live_root_count()?, (TOTAL_ROOTS - 30) as u64);

    // Verify deterministic pagination covers every single live root.
    let mut paginated_live = 0_u64;
    let mut cursor: Option<String> = None;
    loop {
        let page = roots_store.list_live_roots(cursor.as_deref(), 200)?;
        paginated_live += page.entries.len() as u64;
        if !page.has_more {
            break;
        }
        cursor = page.next_cursor;
    }
    assert_eq!(paginated_live, (TOTAL_ROOTS - 30) as u64);

    let comp = roots_store.compact_catalog()?;
    assert_eq!(comp.live_entries, (TOTAL_ROOTS - 30) as u64);
    assert_eq!(comp.total_entries, (TOTAL_ROOTS + 20) as u64);
    drop(roots_store);

    let reopened_roots = PackStore::open(&roots_dir.path, pack_cfg(1024 * 1024, 16))?;
    assert_eq!(reopened_roots.live_root_count()?, (TOTAL_ROOTS - 30) as u64);
    let tomb_entry = reopened_roots
        .get_root("cam-04:gop:000020")?
        .ok_or("tombstoned root missing after reopen")?;
    assert!(matches!(tomb_entry.status, RootStatus::Tombstoned { .. }));

    // Part C: FD-pool eviction across 320 sealed packfiles (>300 packs) with max_open_packs = 16!
    const PACK_COUNT: usize = 320;
    const FD_CAP: usize = 16;
    let fd_dir = TempPackDir::new("fd-320-packs")?;
    let fd_store = PackStore::open(&fd_dir.path, pack_cfg(256, FD_CAP))?;

    let mut objects: Vec<(ContentDigest, Vec<u8>)> = Vec::with_capacity(PACK_COUNT);
    for idx in 0..PACK_COUNT {
        // 280 bytes payload + 54 bytes framing = 334 bytes > 256 -> each append seals its own pack!
        let payload = make_payload(&format!("fd-pack-{idx:05}"), 280);
        let digest = ContentDigest::sha256(&payload);
        let locs = fd_store.append_batch(&[PackObjectInput::with_digest(
            PACK_KIND_RAW_PAYLOAD,
            0,
            &payload,
            digest,
        )])?;
        assert_eq!(locs[0].pack_id.seq, (idx as u64) + 1);
        objects.push((digest, payload));
    }
    let _ = fd_store.seal_active_pack()?;

    let sealed_ids = fd_store.sealed_pack_ids()?;
    assert_eq!(sealed_ids.len(), PACK_COUNT);
    let on_disk_files = fs::read_dir(fd_store.packs_dir())?.count();
    assert_eq!(on_disk_files, PACK_COUNT);

    // Perform full sweep + 1,000 seeded random reads across all 320 packs; open FDs NEVER exceed 16!
    let mut rng = SeededRng::new(0xFD32_0016_CAFE);
    for (digest, expected) in &objects {
        assert_eq!(fd_store.read_verified(digest)?, *expected);
        assert!(
            fd_store.fd_pool().open_count() <= FD_CAP,
            "open FD count {} exceeded cap {FD_CAP}",
            fd_store.fd_pool().open_count()
        );
    }
    for _ in 0..1_000_usize {
        let pick = rng.range(objects.len());
        let (digest, expected) = &objects[pick];
        assert_eq!(fd_store.read_verified(digest)?, *expected);
        assert!(fd_store.fd_pool().open_count() <= FD_CAP);
    }

    let fd_stats = fd_store.fd_pool().stats();
    assert!(fd_stats.open_count <= FD_CAP);
    assert!(
        fd_stats.evictions >= (PACK_COUNT - FD_CAP) as u64,
        "expected >= {} FD evictions across {PACK_COUNT} packs with cap {FD_CAP}, got {}",
        PACK_COUNT - FD_CAP,
        fd_stats.evictions
    );
    let live_bytes = fd_store.on_disk_pack_bytes()?;

    emit_jsonl(&JsonlLogEntry {
        test_name: "property_seeded_dedup_unbounded_2500_roots_and_fd_pool_320_packs",
        seed: 320,
        op_count: total_dedup_ops + (TOTAL_ROOTS as u64) + (PACK_COUNT as u64) + 1_320,
        stage_latency_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        pack_count: PACK_COUNT as u64,
        live_bytes,
        assertion_digest: ContentDigest::sha256(&dedup_digest_acc),
        verdict: "pass",
    });
    Ok(())
}

/// Concurrent reader stress across aggressive active-pack seals, rotations, index snapshots,
/// and bounded FD-pool eviction.
#[test]
fn concurrent_readers_across_active_pack_seals_and_rotations() -> TestResult {
    let started = Instant::now();
    let dir = TempPackDir::new("conc-seals-rotations")?;
    let store = Arc::new(PackStore::open(&dir.path, pack_cfg(900, 12))?);

    // Seed initial objects spanning sealed & active packs.
    let mut initial = Vec::new();
    for i in 0..24_usize {
        let p = make_payload(&format!("conc-seed-{i:04}"), 300);
        let d = ContentDigest::sha256(&p);
        let _ = store.append_batch(&[PackObjectInput::with_digest(
            PACK_KIND_RAW_PAYLOAD,
            0,
            &p,
            d,
        )])?;
        initial.push((d, p));
    }
    let initial = Arc::new(initial);
    let stop = Arc::new(AtomicBool::new(false));
    let total_reads = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    for worker in 0..6_u64 {
        let reader = store.reader();
        let items = Arc::clone(&initial);
        let stop_flag = Arc::clone(&stop);
        let read_counter = Arc::clone(&total_reads);
        handles.push(thread::spawn(move || -> Result<(), String> {
            let mut rng = SeededRng::new(0xC0AC_0000 ^ worker);
            let mut local_reads = 0_u64;
            while !stop_flag.load(Ordering::Acquire) || local_reads < 60 {
                let _epoch_pin = reader
                    .pin_epoch()
                    .map_err(|e| format!("worker {worker} pin_epoch failed: {e}"))?;
                let idx = rng.range(items.len());
                let (digest, expected) = &items[idx];
                let got = reader
                    .read_verified(digest)
                    .map_err(|e| format!("worker {worker} read_verified failed: {e}"))?;
                if &got != expected {
                    return Err(format!("worker {worker} payload mismatch"));
                }
                local_reads += 1;
                read_counter.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        }));
    }

    // Writer aggressively appends batches, forces mid-stream seals, and rotates packs.
    let mut written = Vec::new();
    for step in 0..48_usize {
        let p1 = make_payload(&format!("rot-a-{step:04}"), 320);
        let p2 = make_payload(&format!("rot-b-{step:04}"), 320);
        let d1 = ContentDigest::sha256(&p1);
        let d2 = ContentDigest::sha256(&p2);
        let _ = store.append_batch(&[
            PackObjectInput::with_digest(PACK_KIND_MEDIA_CHUNK, 0, &p1, d1),
            PackObjectInput::with_digest(PACK_KIND_METADATA, 0, &p2, d2),
        ])?;
        written.push((d1, p1));
        written.push((d2, p2));
        if step % 6 == 5 {
            let _ = store.seal_active_pack()?;
            let _ = store.save_index_snapshot()?;
        }
    }
    let _ = store.seal_active_pack()?;
    stop.store(true, Ordering::Release);

    for h in handles {
        let thread_res = h.join().map_err(|_| "concurrent reader thread panicked")?;
        thread_res.map_err(|e| -> Box<dyn Error> { e.into() })?;
    }

    assert!(store.fd_pool().open_count() <= 12);
    for (digest, expected) in &written {
        assert_eq!(store.read_verified(digest)?, *expected);
    }
    let sealed_packs = store.sealed_pack_ids()?.len() as u64;
    assert!(sealed_packs >= 20);

    emit_jsonl(&JsonlLogEntry {
        test_name: "concurrent_readers_across_active_pack_seals_and_rotations",
        seed: 6,
        op_count: total_reads.load(Ordering::Relaxed) + (written.len() as u64),
        stage_latency_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        pack_count: sealed_packs,
        live_bytes: store.on_disk_pack_bytes()?,
        assertion_digest: ContentDigest::sha256(&total_reads.load(Ordering::Relaxed).to_be_bytes()),
        verdict: "pass",
    });
    Ok(())
}

/// Fault tests covering corrupt CRC32C, corrupt SHA-256 payload (with forged valid CRC32C),
/// corrupt footer start magic (`FSSF`), corrupt footer end magic (`FSSE`), and corrupt
/// whole-pack footer SHA-256 digest.
#[test]
fn fault_corrupt_crc32c_sha256_footer_magic_and_footer_digest_detection() -> TestResult {
    let started = Instant::now();
    let dir = TempPackDir::new("corrupt-modes")?;
    let store = PackStore::open(&dir.path, pack_cfg(1024 * 1024, 8))?;

    let payload = make_payload("integrity-fault-target", 512);
    let digest = ContentDigest::sha256(&payload);
    let locs = store.append_batch(&[PackObjectInput::with_digest(
        PACK_KIND_RAW_PAYLOAD,
        0,
        &payload,
        digest,
    )])?;
    let loc = locs[0];
    let _ = store.seal_active_pack()?.ok_or("expected sealed pack")?;
    let footer = store.verify_pack(loc.pack_id)?;
    assert_eq!(footer.entries.len(), 1);

    let pack_path = store.packs_dir().join(loc.pack_id.file_name());
    let clean_bytes = fs::read(&pack_path)?;

    // Fault 1: Corrupt payload byte -> read_verified catches CRC32C mismatch, verify_pack catches digest mismatch.
    {
        let mut raw = clean_bytes.clone();
        let pos = (loc.offset as usize) + PACK_RECORD_HEADER_LEN + 19;
        raw[pos] ^= 0x80;
        fs::write(&pack_path, &raw)?;
        assert!(matches!(
            store.read_verified(&digest),
            Err(PackError::CrcMismatch { .. })
        ));
        assert!(matches!(
            store.verify_pack(loc.pack_id),
            Err(PackError::DigestMismatch { .. })
        ));
    }

    // Fault 2: Corrupt payload byte AND forge valid CRC32C -> read_verified catches SHA-256 DigestMismatch!
    {
        let mut raw = clean_bytes.clone();
        let pos = (loc.offset as usize) + PACK_RECORD_HEADER_LEN + 23;
        raw[pos] ^= 0x3C;
        let rec_len = (loc.len as usize) + PACK_RECORD_HEADER_LEN + PACK_RECORD_TRAILER_LEN;
        let crc_off = (loc.offset as usize) + rec_len - PACK_RECORD_TRAILER_LEN;
        let forged_crc = crc32c(&raw[loc.offset as usize..crc_off]);
        raw[crc_off..crc_off + 4].copy_from_slice(&forged_crc.to_be_bytes());
        fs::write(&pack_path, &raw)?;
        assert!(matches!(
            store.read_verified(&digest),
            Err(PackError::DigestMismatch { .. })
        ));
    }

    // Fault 3: Corrupt footer end magic (`FSSE` in last 4 bytes) -> verify_pack rejects CorruptPack!
    {
        let mut raw = clean_bytes.clone();
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        fs::write(&pack_path, &raw)?;
        assert!(matches!(
            store.verify_pack(loc.pack_id),
            Err(PackError::CorruptPack { .. })
        ));
    }

    // Fault 4: Corrupt footer start magic (`FSSF` at footer_offset) -> verify_pack rejects CorruptPack!
    {
        let mut raw = clean_bytes.clone();
        let foff = footer.footer_offset as usize;
        raw[foff] ^= 0xFF;
        fs::write(&pack_path, &raw)?;
        assert!(matches!(
            store.verify_pack(loc.pack_id),
            Err(PackError::CorruptPack { .. })
        ));
    }

    // Fault 5: Corrupt whole_pack_sha256 inside footer tail (bytes [len-36 .. len-4]) -> DigestMismatch!
    {
        let mut raw = clean_bytes.clone();
        let tail_sha_pos = raw.len() - 12;
        raw[tail_sha_pos] ^= 0x55;
        fs::write(&pack_path, &raw)?;
        assert!(matches!(
            store.verify_pack(loc.pack_id),
            Err(PackError::DigestMismatch { .. })
        ));
    }

    // Restore clean bytes and confirm verify_pack + read_verified succeed again.
    fs::write(&pack_path, &clean_bytes)?;
    assert_eq!(store.read_verified(&digest)?, payload);
    let _ = store.verify_pack(loc.pack_id)?;

    emit_jsonl(&JsonlLogEntry {
        test_name: "fault_corrupt_crc32c_sha256_footer_magic_and_footer_digest_detection",
        seed: 5,
        op_count: 5,
        stage_latency_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        pack_count: 1,
        live_bytes: clean_bytes.len() as u64,
        assertion_digest: digest,
        verdict: "pass",
    });
    Ok(())
}

/// Verifies the root-last visibility invariant across 16 seeded mid-batch `PackCutPoint` failures
/// (`AfterPackSyncBeforeRootAppend`) AND all three compaction `PackCutPoint` crash cuts.
#[test]
fn fault_root_last_visibility_under_all_pack_cut_points() -> TestResult {
    let started = Instant::now();
    let mut digest_acc = Vec::new();

    // Part A: 16 seeded multi-child graph publishes aborted at AfterPackSyncBeforeRootAppend.
    let dir = TempPackDir::new("root-last-cut")?;
    let mut committed_roots: u64 = 0;
    for seed in 1..=16_u64 {
        let store = PackStore::open(&dir.path, pack_cfg(4096, 8))?;
        let child_a = make_payload(&format!("cut-child-a-{seed}"), 220);
        let child_b = make_payload(&format!("cut-child-b-{seed}"), 180);
        let da = ContentDigest::sha256(&child_a);
        let db = ContentDigest::sha256(&child_b);
        let root_id = format!("cam-cut:gop:{seed:04}");
        let root_rec = VirtualRootRecord::new(
            root_id.clone(),
            da,
            "gop-v1",
            2,
            (child_a.len() + child_b.len()) as u64,
            1,
            TimestampNs(1_000_000 * i128::from(seed)),
            Some(db),
        )?;

        // Simulate crash strictly after pack fsync and strictly before root catalog append.
        let cut_res = store.publish_graph_with_cut_point(
            &[
                PackObjectInput::with_digest(PACK_KIND_MEDIA_CHUNK, 0, &child_a, da),
                PackObjectInput::with_digest(PACK_KIND_METADATA, 0, &child_b, db),
            ],
            root_rec.clone(),
            PackCutPoint::AfterPackSyncBeforeRootAppend,
        );
        assert!(matches!(
            cut_res,
            Err(PackError::InjectedCrash(
                PackCutPoint::AfterPackSyncBeforeRootAppend
            ))
        ));
        drop(store);

        // Cold reopen after crash: children durable & verified, root MUST NOT be visible!
        let reopened = PackStore::open(&dir.path, pack_cfg(4096, 8))?;
        assert_eq!(reopened.read_verified(&da)?, child_a);
        assert_eq!(reopened.read_verified(&db)?, child_b);
        assert_eq!(reopened.get_root(&root_id)?, None);
        assert_eq!(reopened.live_root_count()?, committed_roots);

        // Clean retry publishes root using already-deduplicated children!
        let receipt = reopened.publish_graph(
            &[
                PackObjectInput::with_digest(PACK_KIND_MEDIA_CHUNK, 0, &child_a, da),
                PackObjectInput::with_digest(PACK_KIND_METADATA, 0, &child_b, db),
            ],
            root_rec,
        )?;
        assert_eq!(
            receipt.pack_fsyncs, 0,
            "retry should deduplicate already-fsynced children"
        );
        assert_eq!(receipt.catalog_fsyncs, 1);
        committed_roots += 1;
        assert_eq!(reopened.live_root_count()?, committed_roots);
        assert!(reopened.get_root(&root_id)?.is_some());
        digest_acc.extend_from_slice(&da.bytes());
    }

    // Part B: Compaction crash cuts at all 3 compaction PackCutPoints.
    for cut in [
        PackCutPoint::CompactionBeforeStagingRename,
        PackCutPoint::CompactionAfterNewPackBeforeIndexSwap,
        PackCutPoint::CompactionAfterIndexSwapBeforeOldPackUnlink,
    ] {
        let cdir = TempPackDir::new(&format!("comp-cut-{cut}"))?;
        let store = PackStore::open(&cdir.path, pack_cfg(32 * 1024, 8))?;
        let live_p = make_payload(&format!("survive-{cut}"), 400);
        let dead_p1 = make_payload(&format!("evict-1-{cut}"), 1_200);
        let dead_p2 = make_payload(&format!("evict-2-{cut}"), 1_200);
        let d_live = ContentDigest::sha256(&live_p);
        let d_dead1 = ContentDigest::sha256(&dead_p1);
        let d_dead2 = ContentDigest::sha256(&dead_p2);

        let locs = store.append_batch(&[
            PackObjectInput::with_digest(PACK_KIND_MEDIA_CHUNK, 0, &live_p, d_live),
            PackObjectInput::with_digest(PACK_KIND_MEDIA_CHUNK, 0, &dead_p1, d_dead1),
            PackObjectInput::with_digest(PACK_KIND_MEDIA_CHUNK, 0, &dead_p2, d_dead2),
        ])?;
        let old_pack_id = locs[0].pack_id;
        let _ = store.seal_active_pack()?;

        let rcfg = RetentionRingConfig::new(100, 100_000, 100_000, 75, 95)?;
        let cands = vec![
            RetentionCandidate {
                import_id: "held-win".to_owned(),
                sensor_id: "cam-0".to_owned(),
                capture_end_ns: TimestampNs(1_000),
                byte_size: 400,
                object_digests: vec![d_live],
                is_derived_proxy: false,
                held_by: vec!["hold-cut".to_owned()],
                active_obligation_ids: Vec::new(),
                active_event_ids: Vec::new(),
            },
            RetentionCandidate {
                import_id: "dead-win".to_owned(),
                sensor_id: "cam-0".to_owned(),
                capture_end_ns: TimestampNs(1),
                byte_size: 2_400,
                object_digests: vec![d_dead1, d_dead2],
                is_derived_proxy: false,
                held_by: Vec::new(),
                active_obligation_ids: Vec::new(),
                active_event_ids: Vec::new(),
            },
        ];
        let RetentionPlanOutcome::Evict(batch) = plan_retention(&rcfg, &cands, TimestampNs(500))?
        else {
            return Err("expected eviction batch for compaction cut test".into());
        };
        let proof = store.commit_eviction_tombstones(&batch, Some(1))?;
        let res = store.compact_pack_with_cut_point(
            old_pack_id,
            &proof,
            CompactionPolicy::default(),
            cut,
        );
        assert!(matches!(res, Err(PackError::InjectedCrash(c)) if c == cut));
        if cut == PackCutPoint::CompactionBeforeStagingRename {
            let staging = store
                .packs_dir()
                .join(compact_staging_file_name(fss_pack::PackId::new(1, 2)));
            assert!(staging.exists());
        }
        drop(store);

        let reopened = PackStore::open(&cdir.path, pack_cfg(32 * 1024, 8))?;
        assert_eq!(reopened.read_verified(&d_live)?, live_p);
        assert_eq!(
            reopened
                .read_verified(&d_dead1)
                .err()
                .and_then(|e| e.stable_error_id()),
            Some(ERR_EVIDENCE_DELETED_001)
        );
        let finish = reopened.reclaim_superseded_packs(CompactionPolicy::default())?;
        assert!(finish.packs_unlinked_empty + finish.packs_rewritten >= 1);
        assert!(!reopened.packs_dir().join(old_pack_id.file_name()).exists());
        assert_eq!(reopened.read_verified(&d_live)?, live_p);
        digest_acc.extend_from_slice(&d_live.bytes());
    }

    emit_jsonl(&JsonlLogEntry {
        test_name: "fault_root_last_visibility_under_all_pack_cut_points",
        seed: 19,
        op_count: 19,
        stage_latency_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        pack_count: 19,
        live_bytes: committed_roots,
        assertion_digest: ContentDigest::sha256(&digest_acc),
        verdict: "pass",
    });
    Ok(())
}

/// Property & fault test for retention & compaction invariants:
/// - 10x ring overflow across 8 randomized seeds with legal holds + active obligations + shared
///   deduped objects -> ZERO evicted held/obligation closures;
/// - Proxy-first shedding order verified across all 4 pressure tiers
///   (`Nominal` -> `Elevated` -> `Constrained` -> `Critical`);
/// - 100% pinned critical refusal returns exact `ERR-STORAGE-QUOTA-PINNED-001`;
/// - Background scrubber cursor completeness & single-byte corruption detection across compacted packs.
#[test]
fn property_retention_10x_overflow_pressure_ladder_quota_pinned_and_compacted_scrubber()
-> TestResult {
    let started = Instant::now();
    let mut digest_acc = Vec::new();
    let mut total_windows_ingested: u64 = 0;

    // Part A: 10x ring overflow across 6 randomized seeds with holds, obligations, events & shared digests!
    for seed in 1..=6_u64 {
        let dir = TempPackDir::new(&format!("ring-10x-s{seed}"))?;
        let mut rng = SeededRng::new(0x10AE_0000_u64 ^ seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let pack_size: u64 = 12 * 1024;
        let ring_cap_bytes: u64 = 32 * 1024; // ~20 windows; ingesting 200 windows = 10x ring cap!
        let windows_per_seed: u64 = 200;

        let store = PackStore::open(&dir.path, pack_cfg(pack_size, 16))?;
        let ring_cfg = RetentionRingConfig::new(
            20_000_000_000, // 20s hot retention
            ring_cap_bytes,
            ring_cap_bytes,
            75,
            95,
        )?
        .with_sensor_policy(SensorRetentionPolicy::new(
            "cam-north",
            20_000_000_000,
            ring_cap_bytes,
        )?)?;

        // Choose randomized hold, obligation, and event windows across early/mid/late range.
        let mut hold_wins = BTreeSet::new();
        let mut obl_wins = BTreeSet::new();
        let mut evt_wins = BTreeSet::new();
        for _ in 0..3 {
            hold_wins.insert(rng.range(windows_per_seed as usize) as u64);
        }
        for _ in 0..3 {
            obl_wins.insert(rng.range(windows_per_seed as usize) as u64);
        }
        for _ in 0..2 {
            evt_wins.insert(rng.range(windows_per_seed as usize) as u64);
        }

        let shared_bytes = make_payload(&format!("shared-dedup-s{seed}"), 256);
        let shared_digest = ContentDigest::sha256(&shared_bytes);
        let first_hold = hold_wins.iter().next().copied().unwrap_or(0);

        let mut candidates: Vec<RetentionCandidate> = Vec::new();
        let mut pinned_closures: BTreeMap<ContentDigest, Vec<u8>> = BTreeMap::new();
        let mut pinned_import_ids: BTreeSet<String> = BTreeSet::new();
        let mut evicted_digests: BTreeSet<ContentDigest> = BTreeSet::new();

        for win in 0..windows_per_seed {
            let now_ns = TimestampNs(10_000_000_000 + i128::from(win) * 1_000_000_000);
            let sensor = if win % 2 == 0 {
                "cam-north"
            } else {
                "cam-south"
            };
            let is_pinned =
                hold_wins.contains(&win) || obl_wins.contains(&win) || evt_wins.contains(&win);
            let is_proxy = !is_pinned && (win % 4 == 0);
            let payload_len = if is_proxy { 800 } else { 1_600 };
            let payload = make_payload(&format!("s{seed}-w{win:04}-{sensor}"), payload_len);
            let digest = ContentDigest::sha256(&payload);
            let import_id = format!("{sensor}:s{seed}:w{win:04}");

            let mut inputs = vec![PackObjectInput::with_digest(
                if is_proxy {
                    PACK_KIND_METADATA
                } else {
                    PACK_KIND_MEDIA_CHUNK
                },
                0,
                &payload,
                digest,
            )];
            let mut digests = vec![digest];
            // Share one content-addressed object between a held window and an unheld neighbor!
            if win == first_hold || win == (first_hold + 1) % windows_per_seed {
                inputs.push(PackObjectInput::with_digest(
                    PACK_KIND_RAW_PAYLOAD,
                    0,
                    &shared_bytes,
                    shared_digest,
                ));
                digests.push(shared_digest);
            }

            let root = VirtualRootRecord::new(
                import_id.clone(),
                digest,
                if is_proxy { "proxy-v1" } else { "gop-v1" },
                digests.len() as u64,
                payload_len as u64,
                1,
                now_ns,
                None,
            )?;
            let _ = store.publish_graph(&inputs, root)?;

            let cand = RetentionCandidate {
                import_id: import_id.clone(),
                sensor_id: sensor.to_owned(),
                capture_end_ns: now_ns,
                byte_size: payload_len as u64,
                object_digests: digests,
                is_derived_proxy: is_proxy,
                held_by: if hold_wins.contains(&win) {
                    vec![format!("hold:s{seed}:{win}")]
                } else {
                    Vec::new()
                },
                active_obligation_ids: if obl_wins.contains(&win) {
                    vec![format!("obl:s{seed}:{win}")]
                } else {
                    Vec::new()
                },
                active_event_ids: if evt_wins.contains(&win) {
                    vec![format!("evt:s{seed}:{win}")]
                } else {
                    Vec::new()
                },
            };
            if cand.is_pinned() {
                pinned_import_ids.insert(import_id);
                pinned_closures.insert(digest, payload);
                if win == first_hold {
                    pinned_closures.insert(shared_digest, shared_bytes.clone());
                }
            }
            candidates.push(cand);
            total_windows_ingested += 1;

            if win % 10 == 9 {
                let outcome = plan_retention(&ring_cfg, &candidates, now_ns)?;
                if let RetentionPlanOutcome::Evict(batch) = outcome {
                    for tomb in &batch.tombstones {
                        assert!(
                            !pinned_import_ids.contains(&tomb.import_id),
                            "seed {seed}: pinned import {} was evicted!",
                            tomb.import_id
                        );
                    }
                    for &d in &batch.reclaimable_digests {
                        assert!(
                            !pinned_closures.contains_key(&d),
                            "seed {seed}: pinned digest {d} marked reclaimable!"
                        );
                        evicted_digests.insert(d);
                    }
                    let proof = store.commit_eviction_tombstones(&batch, Some(win + 1))?;
                    proof.verify()?;
                    let evicted_ids: BTreeSet<String> = batch
                        .tombstones
                        .iter()
                        .map(|t| t.import_id.clone())
                        .collect();
                    candidates.retain(|c| !evicted_ids.contains(&c.import_id));
                    let _ = store.compact_sealed_packs(
                        &proof,
                        CompactionPolicy {
                            min_live_ratio_ppm: 650_000,
                            reader_drain_timeout_ms: 2_000,
                            max_packs_per_pass: None,
                        },
                    )?;
                }
            }
        }

        // Final seal + retention sweep.
        let _ = store.seal_active_pack()?;
        let final_now = TimestampNs(10_000_000_000 + i128::from(windows_per_seed) * 1_000_000_000);
        if let RetentionPlanOutcome::Evict(batch) =
            plan_retention(&ring_cfg, &candidates, final_now)?
        {
            let proof = store.commit_eviction_tombstones(&batch, Some(windows_per_seed + 1))?;
            for &d in &batch.reclaimable_digests {
                assert!(!pinned_closures.contains_key(&d));
                evicted_digests.insert(d);
            }
            let _ = store.compact_sealed_packs(&proof, CompactionPolicy::default())?;
        }

        // ZERO pinned closures lost, AND every evicted unheld digest returns ERR-EVIDENCE-DELETED-001!
        assert!(!pinned_closures.is_empty());
        assert!(!evicted_digests.is_empty());
        for (digest, expected) in &pinned_closures {
            assert_eq!(store.read_verified(digest)?, *expected);
            digest_acc.extend_from_slice(&digest.bytes());
        }
        for digest in evicted_digests.iter().take(16) {
            let err = store
                .read_verified(digest)
                .err()
                .ok_or("evicted unheld digest must not read as live")?;
            assert_eq!(err.stable_error_id(), Some(ERR_EVIDENCE_DELETED_001));
        }

        // Reopen and re-verify 100% of pinned closures survive cold restart.
        let disk_bytes = store.on_disk_pack_bytes()?;
        assert!(
            disk_bytes <= ring_cap_bytes + 3 * pack_size,
            "seed {seed}: on-disk bytes {disk_bytes} unbounded above ring cap"
        );
        drop(store);
        let reopened = PackStore::open(&dir.path, pack_cfg(pack_size, 16))?;
        for (digest, expected) in &pinned_closures {
            assert_eq!(reopened.read_verified(digest)?, *expected);
        }
    }

    // Part B: Proxy-first shedding order across all 4 pressure tiers
    // (Nominal -> Elevated -> Constrained -> Critical) across 32 seeded candidate sets!
    let ladder_cfg = RetentionRingConfig::new(100_000_000, 100_000, 1_000, 75, 95)?;
    assert_eq!(ladder_cfg.classify_pressure(700), CapacityPressure::Nominal);
    assert_eq!(
        ladder_cfg.classify_pressure(750),
        CapacityPressure::Elevated
    );
    assert_eq!(
        ladder_cfg.classify_pressure(850),
        CapacityPressure::Constrained
    );
    assert_eq!(
        ladder_cfg.classify_pressure(950),
        CapacityPressure::Critical
    );

    for seed in 1..=32_u64 {
        let mut rng = SeededRng::new(0xBADC_0FFE_u64 ^ seed);

        // Tier 1: Nominal (650/1000) -> NoAction.
        let nom_cands = vec![
            RetentionCandidate {
                import_id: format!("nom-src-{seed}"),
                sensor_id: "cam-1".to_owned(),
                capture_end_ns: TimestampNs(1_000),
                byte_size: 500,
                object_digests: vec![ContentDigest::sha256(format!("ns-{seed}").as_bytes())],
                is_derived_proxy: false,
                held_by: Vec::new(),
                active_obligation_ids: Vec::new(),
                active_event_ids: Vec::new(),
            },
            RetentionCandidate {
                import_id: format!("nom-prx-{seed}"),
                sensor_id: "cam-1".to_owned(),
                capture_end_ns: TimestampNs(2_000),
                byte_size: 150,
                object_digests: vec![ContentDigest::sha256(format!("np-{seed}").as_bytes())],
                is_derived_proxy: true,
                held_by: Vec::new(),
                active_obligation_ids: Vec::new(),
                active_event_ids: Vec::new(),
            },
        ];
        let nom_out = plan_retention(&ladder_cfg, &nom_cands, TimestampNs(3_000))?;
        assert!(matches!(
            nom_out,
            RetentionPlanOutcome::NoAction {
                pressure: CapacityPressure::Nominal,
                ..
            }
        ));

        // Tier 2: Elevated (800/1000) -> ONLY proxies shed, 0 sources evicted, accelerate_compaction=true!
        let elev_cands = vec![
            RetentionCandidate {
                import_id: format!("el-src-old-{seed}"),
                sensor_id: "cam-1".to_owned(),
                capture_end_ns: TimestampNs(1_000),
                byte_size: 680,
                object_digests: vec![ContentDigest::sha256(format!("es-{seed}").as_bytes())],
                is_derived_proxy: false,
                held_by: Vec::new(),
                active_obligation_ids: Vec::new(),
                active_event_ids: Vec::new(),
            },
            RetentionCandidate {
                import_id: format!("el-prx-new-{seed}"),
                sensor_id: "cam-1".to_owned(),
                capture_end_ns: TimestampNs(9_000), // strictly newer than source!
                byte_size: 120,
                object_digests: vec![ContentDigest::sha256(format!("ep-{seed}").as_bytes())],
                is_derived_proxy: true,
                held_by: Vec::new(),
                active_obligation_ids: Vec::new(),
                active_event_ids: Vec::new(),
            },
        ];
        match plan_retention(&ladder_cfg, &elev_cands, TimestampNs(10_000))? {
            RetentionPlanOutcome::Evict(batch) => {
                assert_eq!(batch.pressure_before, CapacityPressure::Elevated);
                assert!(batch.accelerate_compaction);
                assert_eq!(batch.proxies_shed_count, 1);
                assert_eq!(batch.sources_evicted_count, 0);
                assert_eq!(
                    batch.tombstones[0].reason,
                    EvictionReason::DeploymentPressureProxyShed
                );
            }
            other => {
                return Err(
                    format!("seed {seed}: expected Elevated proxy Evict, got {other:?}").into(),
                );
            }
        }

        // Tiers 3 & 4: Constrained (900/1000) and Critical (980/1000) with randomized orderings:
        // ALL derived proxies MUST appear strictly before ANY unheld source in batch.tombstones!
        for (target_pressure, total_budget) in [
            (CapacityPressure::Constrained, 900_u64),
            (CapacityPressure::Critical, 980_u64),
        ] {
            let mut mixed = Vec::new();
            let proxy_bytes = 15_u64;
            let num_proxies = 2 + rng.range(2); // 2..=3 proxies (30..=45 bytes; leaves >=855 >= 850 Constrained)
            let rem = total_budget - (num_proxies as u64) * proxy_bytes;
            let num_sources = 4_usize;
            let src_base = rem / (num_sources as u64);
            let src_extra = rem % (num_sources as u64);

            for p in 0..num_proxies {
                mixed.push(RetentionCandidate {
                    import_id: format!("tier-prx-{seed}-{p}"),
                    sensor_id: "cam-1".to_owned(),
                    capture_end_ns: TimestampNs(50_000 + i128::from(p as u64) * 100), // newer than sources!
                    byte_size: proxy_bytes,
                    object_digests: vec![ContentDigest::sha256(
                        format!("tp-{seed}-{total_budget}-{p}").as_bytes(),
                    )],
                    is_derived_proxy: true,
                    held_by: Vec::new(),
                    active_obligation_ids: Vec::new(),
                    active_event_ids: Vec::new(),
                });
            }
            for s in 0..num_sources {
                let sz = src_base + if s == 0 { src_extra } else { 0 };
                mixed.push(RetentionCandidate {
                    import_id: format!("tier-src-{seed}-{s}"),
                    sensor_id: "cam-1".to_owned(),
                    capture_end_ns: TimestampNs(1_000 + i128::from(s as u64) * 100),
                    byte_size: sz,
                    object_digests: vec![ContentDigest::sha256(
                        format!("ts-{seed}-{total_budget}-{s}").as_bytes(),
                    )],
                    is_derived_proxy: false,
                    held_by: if s == num_sources - 1 {
                        vec![format!("hold-pin-{seed}")]
                    } else {
                        Vec::new()
                    },
                    active_obligation_ids: Vec::new(),
                    active_event_ids: Vec::new(),
                });
            }
            // Shuffle input candidates to verify deterministic proxy-first ordering regardless of input order!
            for i in (1..mixed.len()).rev() {
                let j = rng.range(i + 1);
                mixed.swap(i, j);
            }

            let out = plan_retention(&ladder_cfg, &mixed, TimestampNs(60_000))?;
            let batch = match out {
                RetentionPlanOutcome::Evict(b) => b,
                RetentionPlanOutcome::QuotaPinned {
                    partial_eviction: Some(b),
                    ..
                } => b,
                other => {
                    return Err(format!(
                        "seed {seed}: expected eviction under {target_pressure:?}, got {other:?}"
                    )
                    .into());
                }
            };
            assert_eq!(batch.pressure_before, target_pressure);
            assert!(batch.accelerate_compaction);
            assert_eq!(batch.proxies_shed_count, num_proxies as u64);
            assert!(batch.sources_evicted_count >= 1);

            // Verify EVERY proxy tombstone precedes EVERY source tombstone!
            let mut saw_source = false;
            for tomb in &batch.tombstones {
                if tomb.is_derived_proxy {
                    assert!(
                        !saw_source,
                        "seed {seed}: derived proxy {} shed AFTER source window under {target_pressure:?}!",
                        tomb.import_id
                    );
                    assert_eq!(tomb.reason, EvictionReason::DeploymentPressureProxyShed);
                } else {
                    saw_source = true;
                    assert_eq!(tomb.reason, EvictionReason::DeploymentQuotaExceeded);
                }
            }
        }
    }

    // Part C: 100% pinned Critical pressure refusal across 16 randomized pin combinations ->
    // MUST return exact ERR-STORAGE-QUOTA-PINNED-001!
    for seed in 1..=16_u64 {
        let mut rng = SeededRng::new(0x0011_91AA_u64 ^ seed);
        let mut pinned = Vec::new();
        let mut total_bytes = 0_u64;
        for idx in 0..4_usize {
            let sz = 250_u64;
            total_bytes += sz;
            let pin_kind = (idx + rng.range(3)) % 3;
            pinned.push(RetentionCandidate {
                import_id: format!("allpin-{seed}-{idx}"),
                sensor_id: "cam-1".to_owned(),
                capture_end_ns: TimestampNs(1 + i128::from(idx as u64)), // expired age too!
                byte_size: sz,
                object_digests: vec![ContentDigest::sha256(format!("ap-{seed}-{idx}").as_bytes())],
                is_derived_proxy: idx == 3, // even pinned proxies MUST NOT be evicted!
                held_by: if pin_kind == 0 {
                    vec![format!("hold:{seed}:{idx}")]
                } else {
                    Vec::new()
                },
                active_obligation_ids: if pin_kind == 1 {
                    vec![format!("obl:{seed}:{idx}")]
                } else {
                    Vec::new()
                },
                active_event_ids: if pin_kind == 2 {
                    vec![format!("evt:{seed}:{idx}")]
                } else {
                    Vec::new()
                },
            });
        }
        let res = plan_retention(&ladder_cfg, &pinned, TimestampNs(999_999_999))?;
        match res {
            RetentionPlanOutcome::QuotaPinned {
                error_id,
                pressure,
                pinned_bytes,
                cap_bytes,
                partial_eviction,
            } => {
                assert_eq!(error_id, ERR_STORAGE_QUOTA_PINNED_001);
                assert_eq!(pressure, CapacityPressure::Critical);
                assert_eq!(pinned_bytes, total_bytes);
                assert_eq!(cap_bytes, 1_000);
                assert!(partial_eviction.is_none());
            }
            other => return Err(format!("seed {seed}: expected QuotaPinned, got {other:?}").into()),
        }
    }

    // Part D: Scrubber cursor completeness & single-byte corruption detection across COMPACTED packs!
    let scrub_dir = TempPackDir::new("compacted-scrubber")?;
    let scrub_store = PackStore::open(&scrub_dir.path, pack_cfg(1_400, 12))?;
    let mut live_items = Vec::new();
    let mut dead_items = Vec::new();

    // Populate 4 sealed packs, each mixing 1 live held object + 2 dead unheld objects (so every pack
    // has ~25% live ratio -> compaction rewrites all of them into new compacted packs!).
    for group in 0..4_usize {
        let lp = make_payload(&format!("comp-scrub-live-{group}"), 280);
        let dp1 = make_payload(&format!("comp-scrub-dead1-{group}"), 420);
        let dp2 = make_payload(&format!("comp-scrub-dead2-{group}"), 420);
        let dl = ContentDigest::sha256(&lp);
        let dd1 = ContentDigest::sha256(&dp1);
        let dd2 = ContentDigest::sha256(&dp2);
        let _ = scrub_store.append_batch(&[
            PackObjectInput::with_digest(PACK_KIND_MEDIA_CHUNK, 0, &lp, dl),
            PackObjectInput::with_digest(PACK_KIND_MEDIA_CHUNK, 0, &dp1, dd1),
            PackObjectInput::with_digest(PACK_KIND_MEDIA_CHUNK, 0, &dp2, dd2),
        ])?;
        let _ = scrub_store.seal_active_pack()?;
        live_items.push((group, dl, lp));
        dead_items.push((group, dd1, dd2));
    }

    let scrub_ring_cfg = RetentionRingConfig::new(100, 1_000_000, 1_000_000, 75, 95)?;
    let mut scrub_cands = Vec::new();
    for (group, dl, lp) in &live_items {
        scrub_cands.push(RetentionCandidate {
            import_id: format!("scrub-live-{group}"),
            sensor_id: "cam-scrub".to_owned(),
            capture_end_ns: TimestampNs(1_000),
            byte_size: lp.len() as u64,
            object_digests: vec![*dl],
            is_derived_proxy: false,
            held_by: vec![format!("hold-scrub-{group}")],
            active_obligation_ids: Vec::new(),
            active_event_ids: Vec::new(),
        });
    }
    for (group, dd1, dd2) in &dead_items {
        scrub_cands.push(RetentionCandidate {
            import_id: format!("scrub-dead-{group}"),
            sensor_id: "cam-scrub".to_owned(),
            capture_end_ns: TimestampNs(1),
            byte_size: 840,
            object_digests: vec![*dd1, *dd2],
            is_derived_proxy: false,
            held_by: Vec::new(),
            active_obligation_ids: Vec::new(),
            active_event_ids: Vec::new(),
        });
    }
    let RetentionPlanOutcome::Evict(evict_batch) =
        plan_retention(&scrub_ring_cfg, &scrub_cands, TimestampNs(500))?
    else {
        return Err("expected eviction batch for compacted scrubber test".into());
    };
    let tomb_proof = scrub_store.commit_eviction_tombstones(&evict_batch, Some(10))?;
    let comp_report = scrub_store.compact_sealed_packs(&tomb_proof, CompactionPolicy::default())?;
    assert_eq!(comp_report.packs_rewritten, 4);
    assert_eq!(comp_report.live_objects_copied, 4);
    assert!(
        comp_report
            .receipts
            .iter()
            .all(|r| matches!(r.action, PackCompactionAction::RewrittenAndUnlinked { .. }))
    );

    // Run tight-budget incremental scrubber (1 pack per pass) to complete full cycle over compacted packs!
    let mut scrubber = BackgroundScrubber::new();
    let tight_budget = ScrubBudget {
        max_bytes: 2_048,
        max_packs: 1,
        max_objects: 2,
    };
    let mut passes = 0_u64;
    let mut total_verified_objects = 0_u64;
    loop {
        passes += 1;
        let rep = scrubber.scrub_pass(
            &scrub_store,
            tight_budget,
            TimestampNs(10_000 + i128::from(passes)),
        )?;
        rep.verify_digest()?;
        total_verified_objects += rep.verified_objects;
        if rep.cycle_completed {
            assert_eq!(rep.verdict, ScrubVerdict::Clean);
            assert_eq!(rep.verified_fraction_ppm, MAX_VERIFIED_FRACTION_PPM);
            assert!(!rep.requires_obligation);
            break;
        }
        assert_eq!(rep.verdict, ScrubVerdict::Degraded);
        assert!(
            passes < 16,
            "scrubber failed to converge over compacted packs"
        );
    }
    assert_eq!(passes, 4);
    assert_eq!(total_verified_objects, 4);
    assert_eq!(scrubber.cursor().completed_cycles, 1);

    // Flip 1 single byte inside surviving object #2 inside its NEW compacted replacement pack!
    let target_digest = live_items[2].1;
    let target_loc = scrub_store
        .lookup(&target_digest)?
        .ok_or("surviving object missing after compaction")?;
    let target_pack_path = scrub_store.packs_dir().join(target_loc.pack_id.file_name());
    let mut raw = fs::read(&target_pack_path)?;
    raw[(target_loc.offset as usize) + PACK_RECORD_HEADER_LEN + 11] ^= 0x01;
    fs::write(&target_pack_path, &raw)?;

    let mut caught = None;
    for step in 0..8_u64 {
        let rep = scrubber.scrub_pass(
            &scrub_store,
            tight_budget,
            TimestampNs(20_000 + i128::from(step)),
        )?;
        rep.verify_digest()?;
        if rep.verdict == ScrubVerdict::Failed {
            caught = Some(rep);
            break;
        }
    }
    let failed_rep = caught.ok_or("scrubber missed 1-byte corruption inside compacted pack")?;
    assert!(failed_rep.requires_obligation);
    assert!(failed_rep.corrupt_digests.contains(&target_digest));
    assert!(failed_rep.findings.iter().any(|f| {
        f.pack_id == target_loc.pack_id
            && f.digest == Some(target_digest)
            && matches!(
                f.kind,
                ScrubFailureKind::CrcMismatch | ScrubFailureKind::ObjectDigestMismatch
            )
    }));
    assert!(failed_rep.findings.iter().any(|f| {
        f.pack_id == target_loc.pack_id && f.kind == ScrubFailureKind::WholePackDigestMismatch
    }));

    emit_jsonl(&JsonlLogEntry {
        test_name: "property_retention_10x_overflow_pressure_ladder_quota_pinned_and_compacted_scrubber",
        seed: 6,
        op_count: total_windows_ingested + 32 + 16 + passes,
        stage_latency_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        pack_count: comp_report.packs_rewritten,
        live_bytes: scrub_store.on_disk_pack_bytes()?,
        assertion_digest: failed_rep.report_digest,
        verdict: "pass",
    });
    Ok(())
}
