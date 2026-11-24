#![forbid(unsafe_code)]
//! FD-limit stress, concurrent rotation, and scale/throughput tests for `fss-pack`.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Instant;

use fss_core::{ClockBasis, ContentDigest, TimestampNs};
use fss_pack::{
    DurabilityMode, MEDIA_FRAME_FLAG_CONFIG, MEDIA_FRAME_FLAG_KEYFRAME, MediaChunkBuilder,
    MediaChunkView, MediaCodec, PACK_KIND_MEDIA_CHUNK, PACK_KIND_METADATA, PACK_KIND_RAW_PAYLOAD,
    PackConfig, PackObjectInput, PackStore, QuotaPolicy, VirtualRootRecord,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static STRESS_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempStressDir {
    path: PathBuf,
}

impl TempStressDir {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let id = STRESS_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-pack-stress-{label}-{}-{id}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempStressDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Deterministic xorshift64 PRNG (zero external dependencies).
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

#[test]
fn fd_limit_stress_150_sealed_packs_bounded_to_8_open_fds() -> TestResult {
    let dir = TempStressDir::new("fd-limit-150")?;
    let cfg = PackConfig {
        target_pack_bytes: 256,
        durability: DurabilityMode::Fsync,
        max_open_packs: 8,
        ..PackConfig::default()
    };
    let store = PackStore::open(&dir.path, cfg)?;

    let mut objects: Vec<(ContentDigest, Vec<u8>)> = Vec::with_capacity(150);
    for idx in 0_u32..150 {
        // Each record is 54 + 260 = 314 bytes > 256, so every append seals cleanly into its own packfile.
        let payload = format!("pack-stress-object-{idx:05}-")
            .repeat(12)
            .into_bytes();
        let digest = ContentDigest::sha256(&payload);
        let locs = store.append_batch(&[PackObjectInput::with_digest(
            PACK_KIND_RAW_PAYLOAD,
            0,
            &payload,
            digest,
        )])?;
        assert_eq!(locs[0].pack_id.seq, u64::from(idx) + 1);
        objects.push((digest, payload));
    }
    let _ = store.seal_active_pack()?;

    // Verify all 150 packfiles exist on disk.
    let packs_dir = dir.path.join("objects").join("packs");
    let pack_file_count = fs::read_dir(&packs_dir)?.count();
    assert_eq!(pack_file_count, 150);

    // Random reads across all 150 sealed packfiles, strictly verifying open FD count <= 8.
    let mut rng = XorShift64::new(0x5EED_CAFE_BABE_1234);
    for (digest, expected) in &objects {
        let got = store.read_verified(digest)?;
        assert_eq!(&got, expected);
        assert!(store.fd_pool().open_count() <= 8);
    }
    for _ in 0..850 {
        let pick = (rng.next_u64() as usize) % objects.len();
        let (digest, expected) = &objects[pick];
        let got = store.read_verified(digest)?;
        assert_eq!(&got, expected);
        assert!(store.fd_pool().open_count() <= 8);
    }

    let stats = store.fd_pool().stats();
    assert!(stats.open_count <= 8);
    assert!(
        stats.evictions >= 142,
        "expected >= 142 LRU evictions across 150 packs with cap 8, got {}",
        stats.evictions
    );
    Ok(())
}

#[test]
fn concurrent_readers_never_block_or_fail_during_active_writer_rotations() -> TestResult {
    let dir = TempStressDir::new("concurrent-rotation")?;
    let cfg = PackConfig {
        target_pack_bytes: 1024,
        durability: DurabilityMode::Fsync,
        max_open_packs: 6,
        ..PackConfig::default()
    };
    let store = Arc::new(PackStore::open(&dir.path, cfg)?);

    // Seed initial objects spanning several sealed packs and an active pack.
    let mut seed_objects = Vec::new();
    for i in 0_u32..16 {
        let payload = format!("concurrent-seed-object-{i:04}-")
            .repeat(16)
            .into_bytes();
        let digest = ContentDigest::sha256(&payload);
        let _ = store.append_batch(&[PackObjectInput::with_digest(
            PACK_KIND_RAW_PAYLOAD,
            0,
            &payload,
            digest,
        )])?;
        seed_objects.push((digest, payload));
    }
    let seed_objects = Arc::new(seed_objects);
    let stop = Arc::new(AtomicBool::new(false));
    let total_reads = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    for worker_id in 0_u64..4 {
        let reader = store.reader();
        let seeds = Arc::clone(&seed_objects);
        let stop_flag = Arc::clone(&stop);
        let reads_counter = Arc::clone(&total_reads);
        handles.push(thread::spawn(move || -> Result<(), String> {
            let mut rng = XorShift64::new(0x000A_11CE_0001 + worker_id);
            while !stop_flag.load(Ordering::Relaxed) {
                let idx = (rng.next_u64() as usize) % seeds.len();
                let (digest, expected) = &seeds[idx];
                let got = reader
                    .read_verified(digest)
                    .map_err(|e| format!("reader {worker_id} failed: {e}"))?;
                if &got != expected {
                    return Err(format!("reader {worker_id} payload mismatch"));
                }
                reads_counter.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        }));
    }

    // Writer aggressively appends batches causing repeated pack sealing and rotation.
    for batch_idx in 0_u32..32 {
        let p_a = format!("writer-rotation-batch-{batch_idx:04}-a")
            .repeat(14)
            .into_bytes();
        let p_b = format!("writer-rotation-batch-{batch_idx:04}-b")
            .repeat(14)
            .into_bytes();
        let _ = store.append_batch(&[
            PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, &p_a),
            PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, &p_b),
        ])?;
    }
    let _ = store.seal_active_pack()?;
    stop.store(true, Ordering::Relaxed);

    for handle in handles {
        let thread_res = handle.join().map_err(|_| "reader thread panicked")?;
        thread_res.map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    }
    assert!(total_reads.load(Ordering::Relaxed) > 0);
    assert!(store.fd_pool().open_count() <= 6);
    Ok(())
}

#[test]
fn scale_and_throughput_wyze_60_frame_gop_and_10k_virtual_roots() -> TestResult {
    let dir = TempStressDir::new("scale-throughput")?;
    let cfg = PackConfig {
        target_pack_bytes: 128 * 1024 * 1024,
        durability: DurabilityMode::Fsync,
        max_open_packs: 16,
        quota: QuotaPolicy {
            auto_compact_every: 20_000,
            ..QuotaPolicy::default()
        },
        ..PackConfig::default()
    };
    let store = PackStore::open(&dir.path, cfg)?;

    // Part 1: Simulated 3-second 20 FPS Wyze H.264 GOP (60 frames: 1 IDR keyframe 32 KiB +
    // 59 delta frames 4 KiB each = ~268 KiB, ~715 kbps) + GOP metadata -> 1 media chunk object
    // + 1 metadata object + 1 virtual root with group-commit fsync!
    let mut frames: Vec<Vec<u8>> = Vec::with_capacity(60);
    for i in 0_usize..60 {
        let len = if i == 0 { 32 * 1024 } else { 4 * 1024 };
        let mut buf = vec![0_u8; len];
        // Synthetic Annex-B start code + deterministic NAL body.
        buf[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        buf[4] = if i == 0 { 0x65 } else { 0x41 };
        for (pos, byte) in buf[5..].iter_mut().enumerate() {
            *byte = ((i.wrapping_mul(29).wrapping_add(pos)) & 0xFF) as u8;
        }
        frames.push(buf);
    }
    let metadata_blob = br#"{"camera":"wyze-front-porch","fps":20,"gop_seconds":3,"frames":60}"#;

    let gop_start = Instant::now();
    let mut chunk_builder = MediaChunkBuilder::new(
        "wyze-front-porch-main",
        MediaCodec::H264,
        ClockBasis::DeviceMonotonic,
    )?;
    for (idx, frame) in frames.iter().enumerate() {
        let flags = if idx == 0 {
            MEDIA_FRAME_FLAG_KEYFRAME | MEDIA_FRAME_FLAG_CONFIG
        } else {
            0
        };
        let _ = chunk_builder.push_frame(
            idx as u64 + 1,
            TimestampNs(1_700_000_000_000_000_000 + (idx as i128) * 50_000_000),
            flags,
            frame,
        )?;
    }
    let built_chunk = chunk_builder.build()?;
    let meta_digest = ContentDigest::sha256(metadata_blob);
    let root_record = VirtualRootRecord::new(
        "wyze-front-porch:gop:000001",
        built_chunk.chunk_digest,
        "media-gop-v1",
        2,
        (built_chunk.bytes.len() + metadata_blob.len()) as u64,
        1,
        built_chunk.window_start_ns,
        Some(meta_digest),
    )?;
    let graph_receipt = store.publish_graph(
        &[
            PackObjectInput::with_digest(
                PACK_KIND_MEDIA_CHUNK,
                0,
                &built_chunk.bytes,
                built_chunk.chunk_digest,
            ),
            PackObjectInput::with_digest(PACK_KIND_METADATA, 0, metadata_blob, meta_digest),
        ],
        root_record,
    )?;
    let gop_write_ms = gop_start.elapsed().as_secs_f64() * 1000.0;

    assert_eq!(graph_receipt.pack_fsyncs, 1);
    assert_eq!(graph_receipt.catalog_fsyncs, 1);
    assert!(
        gop_write_ms < 150.0,
        "60-frame GOP publish took {gop_write_ms:.2} ms (limit < 150 ms)"
    );

    // Measure O(1) index lookup latency and verify all 60 frames inside the single FSMC object.
    let lookup_start = Instant::now();
    let loc = store
        .lookup(&built_chunk.chunk_digest)?
        .ok_or("GOP chunk missing from index")?;
    let index_lookup_us = lookup_start.elapsed().as_secs_f64() * 1_000_000.0;

    let read_back = store.read_verified(&built_chunk.chunk_digest)?;
    let view = MediaChunkView::parse(&read_back)?;
    assert_eq!(view.frame_count(), 60);
    view.verify_all_frames()?;
    assert_eq!(view.frame_bytes(0)?, frames[0].as_slice());
    assert_eq!(view.frame_bytes(59)?, frames[59].as_slice());

    // Emit structured JSONL telemetry for the 60-frame Wyze GOP ingest.
    println!(
        "{{\"pack_id\":\"{}\",\"objects\":{},\"raw_bytes\":{},\"fsync_count\":{},\"write_ms\":{:.3},\"index_lookup_us\":{:.3}}}",
        loc.pack_id,
        graph_receipt.child_locations.len(),
        built_chunk.bytes.len() + metadata_blob.len(),
        graph_receipt.pack_fsyncs + graph_receipt.catalog_fsyncs,
        gop_write_ms,
        index_lookup_us
    );

    // Part 2: Insert 10,500 virtual roots (exceeding 10,000+ roots with zero 128-root wall)
    // and benchmark O(1) root catalog lookup + compaction + reopen recovery.
    let total_extra_roots = 10_500_usize;
    let batch_size = 500_usize;
    let roots_start = Instant::now();
    for chunk_start in (0..total_extra_roots).step_by(batch_size) {
        let end = (chunk_start + batch_size).min(total_extra_roots);
        let mut batch = Vec::with_capacity(end - chunk_start);
        for i in chunk_start..end {
            batch.push(VirtualRootRecord::new(
                format!("cam-yard:gop:{i:06}"),
                built_chunk.chunk_digest,
                "media-gop-v1",
                1,
                built_chunk.bytes.len() as u64,
                1,
                TimestampNs(1_700_000_000_000_000_000 + (i as i128) * 3_000_000_000),
                None,
            )?);
        }
        let _ = store.publish_roots_batch(&batch)?;
    }
    let roots_write_ms = roots_start.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(store.live_root_count()?, (total_extra_roots + 1) as u64);

    // Measure O(1) root lookup across 10,501 roots.
    let root_lookup_start = Instant::now();
    for probe in [0_usize, 2_500, 5_250, 9_999, 10_499] {
        let id = format!("cam-yard:gop:{probe:06}");
        let entry = store.get_root(&id)?.ok_or("missing root in 10k catalog")?;
        assert_eq!(entry.record.root_digest, built_chunk.chunk_digest);
    }
    let root_lookup_us = (root_lookup_start.elapsed().as_secs_f64() * 1_000_000.0) / 5.0;

    // Verify deterministic pagination over the 10k+ catalog.
    let page = store.list_roots(Some("cam-yard:gop:005000"), 100)?;
    assert_eq!(page.entries.len(), 100);
    assert!(page.has_more);
    assert_eq!(page.entries[0].record.root_id, "cam-yard:gop:005001");

    // Emit structured JSONL telemetry for the 10,500-root catalog scale test.
    let telemetry = store.telemetry_snapshot()?;
    println!(
        "{{\"pack_id\":\"{}\",\"objects\":{},\"raw_bytes\":{},\"fsync_count\":{},\"write_ms\":{:.3},\"index_lookup_us\":{:.3}}}",
        loc.pack_id,
        telemetry.live_roots,
        telemetry.total_payload_bytes,
        telemetry.pack_fsync_count + telemetry.catalog_fsync_count,
        roots_write_ms,
        root_lookup_us
    );

    // Compact 10,501 roots into catalog.snap and verify full recovery on reopen.
    let compact = store.compact_catalog()?;
    assert_eq!(compact.live_entries, (total_extra_roots + 1) as u64);
    let _ = store.save_index_snapshot()?;
    drop(store);

    let reopened = PackStore::open(&dir.path, cfg)?;
    assert_eq!(reopened.live_root_count()?, (total_extra_roots + 1) as u64);
    assert!(reopened.get_root("cam-yard:gop:010499")?.is_some());
    Ok(())
}
