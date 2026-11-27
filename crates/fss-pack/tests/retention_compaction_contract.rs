#![forbid(unsafe_code)]
//! Comprehensive contract, fault-injection, and E2E tests for bead `fss-x4a.31.1.4` (`A4`):
//! hold-safe automated retention ring, online packfile compaction, reader-epoch drain barrier,
//! crash-cut recovery, and rate-limited incremental background doctor scrubber.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use fss_core::{ContentDigest, TimestampNs};
use fss_pack::{
    BackgroundScrubber, CapacityPressure, CompactionPolicy, DurabilityMode,
    ERR_EVIDENCE_DELETED_001, ERR_STORAGE_QUOTA_PINNED_001, EvictionReason,
    MAX_VERIFIED_FRACTION_PPM, PACK_KIND_MEDIA_CHUNK, PACK_KIND_METADATA, PACK_KIND_RAW_PAYLOAD,
    PACK_RECORD_HEADER_LEN, PackCompactionAction, PackConfig, PackCutPoint, PackError,
    PackObjectInput, PackStore, RetentionCandidate, RetentionPlanOutcome, RetentionRingConfig,
    RootStatus, ScrubBudget, ScrubFailureKind, ScrubVerdict, SensorRetentionPolicy,
    TombstoneCommitProof, VirtualRootRecord, compact_staging_file_name, plan_retention,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempTestDir {
    path: PathBuf,
}

impl TempTestDir {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let id = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-pack-ret-comp-{label}-{}-{id}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempTestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn pack_cfg(target_pack_bytes: u64) -> PackConfig {
    PackConfig {
        target_pack_bytes,
        durability: DurabilityMode::Fsync,
        max_open_packs: 16,
        ..PackConfig::default()
    }
}

fn make_payload(tag: &str, bytes: usize) -> Vec<u8> {
    let seed = tag.as_bytes();
    (0..bytes)
        .map(|i| seed[i % seed.len()].wrapping_add((i as u8).wrapping_mul(17)))
        .collect()
}

/// E2E Proof 1: Rolling 500-window ingest (10x ring cap) with 3 active legal holds,
/// 5 corroborated active events, active obligations, and derived proxies.
#[test]
fn rolling_500_window_e2e_bounded_ring_preserves_holds_sheds_proxies_and_reclaims_packs()
-> TestResult {
    let dir = TempTestDir::new("rolling-500-ring")?;
    let pack_size: u64 = 16 * 1024; // 16 KiB packs
    let ring_cap_bytes: u64 = 100 * 1024; // ~50 windows of 2 KiB each; 500 windows = 10x cap!
    let store = PackStore::open(&dir.path, pack_cfg(pack_size))?;

    let mut ring_cfg = RetentionRingConfig::new(
        60_000_000_000, // 60s hot retention
        ring_cap_bytes,
        ring_cap_bytes,
        75,
        95,
    )?;
    ring_cfg = ring_cfg.with_sensor_policy(SensorRetentionPolicy::new(
        "cam-front",
        60_000_000_000,
        ring_cap_bytes,
    )?)?;

    // Track live ring state, pinned objects, and evicted unheld objects.
    let mut ring_candidates: Vec<RetentionCandidate> = Vec::new();
    let mut pinned_objects: BTreeMap<ContentDigest, Vec<u8>> = BTreeMap::new();
    let mut evicted_unheld_digests: BTreeSet<ContentDigest> = BTreeSet::new();
    let mut total_proxies_shed: u64 = 0;
    let mut total_sources_evicted: u64 = 0;
    let mut total_packs_unlinked: u64 = 0;
    let mut total_packs_rewritten: u64 = 0;
    let mut total_bytes_reclaimed: u64 = 0;
    let mut peak_on_disk_bytes: u64 = 0;

    // Select 3 active legal holds, 5 corroborated active events, and 2 active obligations spread across early & mid windows.
    let hold_windows: BTreeSet<u64> = [5, 110, 260].into_iter().collect();
    let event_windows: BTreeSet<u64> = [12, 75, 155, 220, 340].into_iter().collect();
    let obligation_windows: BTreeSet<u64> = [33, 190].into_iter().collect();

    let mut shared_hold_payload = make_payload("shared-config-frame", 512);
    shared_hold_payload[0] ^= 0x42;
    let shared_digest = ContentDigest::sha256(&shared_hold_payload);

    for win in 0_u64..500 {
        let now_ns = TimestampNs(1_000_000_000_000 + i128::from(win) * 1_000_000_000);
        let sensor = if win % 2 == 0 {
            "cam-front"
        } else {
            "cam-yard"
        };
        let is_proxy = win % 5 == 0
            && !hold_windows.contains(&win)
            && !event_windows.contains(&win)
            && !obligation_windows.contains(&win);
        let payload_len = if is_proxy { 1_024 } else { 2_048 };
        let payload = make_payload(&format!("window-{win:04}-{sensor}-{is_proxy}"), payload_len);
        let digest = ContentDigest::sha256(&payload);

        let import_id = format!("{sensor}:win:{win:05}");
        let mut obj_inputs = vec![PackObjectInput::with_digest(
            if is_proxy {
                PACK_KIND_METADATA
            } else {
                PACK_KIND_MEDIA_CHUNK
            },
            0,
            &payload,
            digest,
        )];
        let mut obj_digests = vec![digest];
        // Attach the shared content-addressed object to both held window 5 and unheld window 6
        // to prove deduped objects referenced by held windows are NEVER tombstoned or lost!
        if win == 5 || win == 6 {
            obj_inputs.push(PackObjectInput::with_digest(
                PACK_KIND_RAW_PAYLOAD,
                0,
                &shared_hold_payload,
                shared_digest,
            ));
            obj_digests.push(shared_digest);
        }

        let root = VirtualRootRecord::new(
            import_id.clone(),
            digest,
            if is_proxy { "proxy-v1" } else { "gop-v1" },
            obj_digests.len() as u64,
            payload_len as u64,
            1,
            now_ns,
            None,
        )?;
        let _ = store.publish_graph(&obj_inputs, root)?;

        let held_by = if hold_windows.contains(&win) {
            vec![format!("hold:legal:{win}")]
        } else {
            Vec::new()
        };
        let active_event_ids = if event_windows.contains(&win) {
            vec![format!("event:corroborated:{win}")]
        } else {
            Vec::new()
        };
        let active_obligation_ids = if obligation_windows.contains(&win) {
            vec![format!("obl:archive:{win}")]
        } else {
            Vec::new()
        };

        let cand = RetentionCandidate {
            import_id,
            sensor_id: sensor.to_owned(),
            capture_end_ns: now_ns,
            byte_size: payload_len as u64,
            object_digests: obj_digests,
            is_derived_proxy: is_proxy,
            held_by,
            active_obligation_ids,
            active_event_ids,
        };
        if cand.is_pinned() {
            pinned_objects.insert(digest, payload.clone());
            if win == 5 {
                pinned_objects.insert(shared_digest, shared_hold_payload.clone());
            }
        }
        ring_candidates.push(cand);

        // Run retention + tombstone commitment + online compaction periodically.
        if win % 10 == 9 {
            let outcome = plan_retention(&ring_cfg, &ring_candidates, now_ns)?;
            if let RetentionPlanOutcome::Evict(batch) = outcome {
                let proof = store.commit_eviction_tombstones(&batch, Some(win + 1))?;
                proof.verify()?;

                total_proxies_shed += batch.proxies_shed_count;
                total_sources_evicted += batch.sources_evicted_count;

                let evicted_ids: BTreeSet<String> = batch
                    .tombstones
                    .iter()
                    .map(|t| t.import_id.clone())
                    .collect();
                for &d in &batch.reclaimable_digests {
                    assert!(
                        !pinned_objects.contains_key(&d),
                        "pinned digest must NEVER be marked reclaimable"
                    );
                    evicted_unheld_digests.insert(d);
                }
                ring_candidates.retain(|c| !evicted_ids.contains(&c.import_id));

                let comp_policy = CompactionPolicy {
                    min_live_ratio_ppm: if batch.accelerate_compaction {
                        750_000
                    } else {
                        500_000
                    },
                    reader_drain_timeout_ms: 2_000,
                    max_packs_per_pass: None,
                };
                let report = store.compact_sealed_packs(&proof, comp_policy)?;
                total_packs_unlinked += report.packs_unlinked_empty;
                total_packs_rewritten += report.packs_rewritten;
                total_bytes_reclaimed += report.total_bytes_reclaimed;
            }
            let disk_bytes = store.on_disk_pack_bytes()?;
            peak_on_disk_bytes = peak_on_disk_bytes.max(disk_bytes);
        }
    }

    // Seal final active pack and run one final retention + compaction sweep.
    let _ = store.seal_active_pack()?;
    let final_now = TimestampNs(1_000_000_000_000 + 500 * 1_000_000_000);
    if let RetentionPlanOutcome::Evict(batch) =
        plan_retention(&ring_cfg, &ring_candidates, final_now)?
    {
        let proof = store.commit_eviction_tombstones(&batch, Some(501))?;
        let evicted_ids: BTreeSet<String> = batch
            .tombstones
            .iter()
            .map(|t| t.import_id.clone())
            .collect();
        for &d in &batch.reclaimable_digests {
            evicted_unheld_digests.insert(d);
        }
        ring_candidates.retain(|c| !evicted_ids.contains(&c.import_id));
        let report = store.compact_sealed_packs(&proof, CompactionPolicy::default())?;
        total_packs_unlinked += report.packs_unlinked_empty;
        total_packs_rewritten += report.packs_rewritten;
        total_bytes_reclaimed += report.total_bytes_reclaimed;
    }

    let final_on_disk_bytes = store.on_disk_pack_bytes()?;
    let bound = ring_cap_bytes + 2 * pack_size;

    // Emit structured JSONL metrics for the 500-window rolling ring E2E test.
    println!(
        "{{\"test\":\"rolling_500_window_e2e\",\"windows_ingested\":500,\"ring_cap_bytes\":{ring_cap_bytes},\"pack_size\":{pack_size},\"final_on_disk_bytes\":{final_on_disk_bytes},\"peak_on_disk_bytes\":{peak_on_disk_bytes},\"bound_bytes\":{bound},\"proxies_shed\":{total_proxies_shed},\"sources_evicted\":{total_sources_evicted},\"packs_unlinked_empty\":{total_packs_unlinked},\"packs_rewritten\":{total_packs_rewritten},\"bytes_reclaimed\":{total_bytes_reclaimed},\"pinned_preserved\":{}}}",
        pinned_objects.len()
    );

    assert!(
        final_on_disk_bytes <= bound,
        "final on-disk bytes {final_on_disk_bytes} exceeded cap + 2*pack_size ({bound})"
    );
    assert!(total_proxies_shed > 0, "derived proxies must be shed");
    assert!(
        total_sources_evicted > 0,
        "expired unheld sources must be evicted"
    );
    assert!(
        total_packs_unlinked > 0,
        "expired unheld sealed packs must be physically unlinked on disk"
    );
    assert!(
        total_packs_rewritten > 0,
        "sparse sealed packs mixing held + expired objects must be compacted & rewritten"
    );
    assert!(total_bytes_reclaimed > 500 * 1024);

    // 100% of held, corroborated-event, active-obligation, and shared objects MUST verify!
    assert_eq!(pinned_objects.len(), 3 + 5 + 2 + 1);
    for (digest, expected_bytes) in &pinned_objects {
        assert_eq!(store.read_verified(digest)?, *expected_bytes);
    }

    // Expired unheld objects MUST return ERR-EVIDENCE-DELETED-001!
    assert!(!evicted_unheld_digests.is_empty());
    for digest in evicted_unheld_digests.iter().take(32) {
        let err = store
            .read_verified(digest)
            .err()
            .ok_or("expired unheld object must not read as live")?;
        assert_eq!(err.stable_error_id(), Some(ERR_EVIDENCE_DELETED_001));
    }

    // Reopen from disk and re-verify 100% of pinned objects + ERR-EVIDENCE-DELETED-001 persistence!
    drop(store);
    let reopened = PackStore::open(&dir.path, pack_cfg(pack_size))?;
    for (digest, expected_bytes) in &pinned_objects {
        assert_eq!(reopened.read_verified(digest)?, *expected_bytes);
    }
    for digest in evicted_unheld_digests.iter().take(16) {
        let err = reopened
            .read_verified(digest)
            .err()
            .ok_or("tombstone must persist across reopen")?;
        assert_eq!(err.stable_error_id(), Some(ERR_EVIDENCE_DELETED_001));
    }
    let tomb_root = reopened
        .get_root("cam-front:win:00000")?
        .ok_or("tombstoned root must remain recorded in catalog")?;
    assert!(matches!(tomb_root.status, RootStatus::Tombstoned { .. }));
    Ok(())
}

/// Proof 2: Watermark degradation ladder (proxies shed FIRST under Elevated/Constrained)
/// and Disk-Full All-Held Safety (`ERR-STORAGE-QUOTA-PINNED-001`).
#[test]
fn watermark_ladder_sheds_proxies_first_and_all_held_critical_returns_quota_pinned() -> TestResult {
    let cfg = RetentionRingConfig::new(10_000_000, 10_000, 1_000, 75, 95)?;
    assert_eq!(cfg.classify_pressure(749), CapacityPressure::Nominal);
    assert_eq!(cfg.classify_pressure(750), CapacityPressure::Elevated);
    assert_eq!(cfg.classify_pressure(849), CapacityPressure::Elevated);
    assert_eq!(cfg.classify_pressure(850), CapacityPressure::Constrained);
    assert_eq!(cfg.classify_pressure(949), CapacityPressure::Constrained);
    assert_eq!(cfg.classify_pressure(950), CapacityPressure::Critical);

    // Case A: Elevated (80%) with 1 older unheld source + 1 newer derived proxy -> sheds proxy ONLY!
    let d_src = ContentDigest::sha256(b"orig-source-1");
    let d_proxy = ContentDigest::sha256(b"derived-proxy-1");
    let elevated_cands = vec![
        RetentionCandidate {
            import_id: "src-1".to_owned(),
            sensor_id: "cam-1".to_owned(),
            capture_end_ns: TimestampNs(1_000),
            byte_size: 700,
            object_digests: vec![d_src],
            is_derived_proxy: false,
            held_by: Vec::new(),
            active_obligation_ids: Vec::new(),
            active_event_ids: Vec::new(),
        },
        RetentionCandidate {
            import_id: "proxy-1".to_owned(),
            sensor_id: "cam-1".to_owned(),
            capture_end_ns: TimestampNs(2_000),
            byte_size: 100,
            object_digests: vec![d_proxy],
            is_derived_proxy: true,
            held_by: Vec::new(),
            active_obligation_ids: Vec::new(),
            active_event_ids: Vec::new(),
        },
    ];
    let elevated_out = plan_retention(&cfg, &elevated_cands, TimestampNs(3_000))?;
    match elevated_out {
        RetentionPlanOutcome::Evict(batch) => {
            assert_eq!(batch.pressure_before, CapacityPressure::Elevated);
            assert_eq!(batch.pressure_after, CapacityPressure::Nominal);
            assert!(batch.accelerate_compaction);
            assert_eq!(batch.proxies_shed_count, 1);
            assert_eq!(batch.sources_evicted_count, 0);
            assert_eq!(batch.tombstones[0].import_id, "proxy-1");
            assert_eq!(
                batch.tombstones[0].reason,
                EvictionReason::DeploymentPressureProxyShed
            );
        }
        other => {
            return Err(format!("expected Evict for elevated proxy shed, got {other:?}").into());
        }
    }

    // Case B: 100% held/event/obligation data at Critical (98%) -> QuotaPinned (0 bytes lost!).
    let dir = TempTestDir::new("all-held-critical")?;
    let store = PackStore::open(&dir.path, pack_cfg(4096))?;
    let p_hold = make_payload("legal-hold-evidence", 350);
    let p_obl = make_payload("active-obligation-evidence", 350);
    let p_evt = make_payload("active-event-evidence", 280);
    let d_hold = ContentDigest::sha256(&p_hold);
    let d_obl = ContentDigest::sha256(&p_obl);
    let d_evt = ContentDigest::sha256(&p_evt);
    let _ = store.append_batch(&[
        PackObjectInput::with_digest(PACK_KIND_MEDIA_CHUNK, 0, &p_hold, d_hold),
        PackObjectInput::with_digest(PACK_KIND_MEDIA_CHUNK, 0, &p_obl, d_obl),
        PackObjectInput::with_digest(PACK_KIND_MEDIA_CHUNK, 0, &p_evt, d_evt),
    ])?;

    let all_pinned = vec![
        RetentionCandidate {
            import_id: "pinned-hold".to_owned(),
            sensor_id: "cam-1".to_owned(),
            capture_end_ns: TimestampNs(1), // even far past retain_hot_ns!
            byte_size: 350,
            object_digests: vec![d_hold],
            is_derived_proxy: false,
            held_by: vec!["hold:litigation-001".to_owned()],
            active_obligation_ids: Vec::new(),
            active_event_ids: Vec::new(),
        },
        RetentionCandidate {
            import_id: "pinned-obl".to_owned(),
            sensor_id: "cam-1".to_owned(),
            capture_end_ns: TimestampNs(2),
            byte_size: 350,
            object_digests: vec![d_obl],
            is_derived_proxy: false,
            held_by: Vec::new(),
            active_obligation_ids: vec!["obl:upload-001".to_owned()],
            active_event_ids: Vec::new(),
        },
        RetentionCandidate {
            import_id: "pinned-evt".to_owned(),
            sensor_id: "cam-1".to_owned(),
            capture_end_ns: TimestampNs(3),
            byte_size: 280,
            object_digests: vec![d_evt],
            is_derived_proxy: true, // even a pinned derived proxy MUST NOT be evicted!
            held_by: Vec::new(),
            active_obligation_ids: Vec::new(),
            active_event_ids: vec!["evt:intrusion-001".to_owned()],
        },
    ];

    let pinned_out = plan_retention(&cfg, &all_pinned, TimestampNs(999_999_999))?;
    match pinned_out {
        RetentionPlanOutcome::QuotaPinned {
            error_id,
            pressure,
            pinned_bytes,
            cap_bytes,
            partial_eviction,
        } => {
            assert_eq!(error_id, ERR_STORAGE_QUOTA_PINNED_001);
            assert_eq!(pressure, CapacityPressure::Critical);
            assert_eq!(pinned_bytes, 980);
            assert_eq!(cap_bytes, 1_000);
            assert!(partial_eviction.is_none());
        }
        other => return Err(format!("expected QuotaPinned, got {other:?}").into()),
    }
    // Zero held bytes lost!
    assert_eq!(store.read_verified(&d_hold)?, p_hold);
    assert_eq!(store.read_verified(&d_obl)?, p_obl);
    assert_eq!(store.read_verified(&d_evt)?, p_evt);
    Ok(())
}

/// Proof 3: Deletion ordering invariant (refuses compaction without committed tombstone proof)
/// and reader-epoch drain barrier (never unlinks old packfile while a reader pins retired epoch).
#[test]
fn deletion_ordering_and_reader_epoch_drain_barrier_enforced() -> TestResult {
    let dir = TempTestDir::new("tombstone-order-and-epoch")?;
    let store = Arc::new(PackStore::open(&dir.path, pack_cfg(64 * 1024))?);

    let p_keep = make_payload("keep-live-object", 512);
    let p_del1 = make_payload("delete-object-1", 1024);
    let p_del2 = make_payload("delete-object-2", 1024);
    let d_keep = ContentDigest::sha256(&p_keep);
    let d_del1 = ContentDigest::sha256(&p_del1);
    let d_del2 = ContentDigest::sha256(&p_del2);

    let locs = store.append_batch(&[
        PackObjectInput::with_digest(PACK_KIND_RAW_PAYLOAD, 0, &p_keep, d_keep),
        PackObjectInput::with_digest(PACK_KIND_RAW_PAYLOAD, 0, &p_del1, d_del1),
        PackObjectInput::with_digest(PACK_KIND_RAW_PAYLOAD, 0, &p_del2, d_del2),
    ])?;
    let pack_id = locs[0].pack_id;
    let _ = store.seal_active_pack()?;

    // Build an eviction batch for del1 & del2, then forge an UNCOMMITTED TombstoneCommitProof!
    let cfg = RetentionRingConfig::new(100, 100_000, 100_000, 75, 95)?;
    let cands = vec![
        RetentionCandidate {
            import_id: "keep-win".to_owned(),
            sensor_id: "cam-1".to_owned(),
            capture_end_ns: TimestampNs(1_000),
            byte_size: 512,
            object_digests: vec![d_keep],
            is_derived_proxy: false,
            held_by: vec!["hold-1".to_owned()],
            active_obligation_ids: Vec::new(),
            active_event_ids: Vec::new(),
        },
        RetentionCandidate {
            import_id: "del-win".to_owned(),
            sensor_id: "cam-1".to_owned(),
            capture_end_ns: TimestampNs(10),
            byte_size: 2048,
            object_digests: vec![d_del1, d_del2],
            is_derived_proxy: false,
            held_by: Vec::new(),
            active_obligation_ids: Vec::new(),
            active_event_ids: Vec::new(),
        },
    ];
    let RetentionPlanOutcome::Evict(batch) = plan_retention(&cfg, &cands, TimestampNs(500))? else {
        return Err("expected eviction batch".into());
    };

    // Uncommitted proof must be rejected when attempting to reclaim!
    let forged_uncommitted = TombstoneCommitProof::build(
        &batch,
        vec!["del-win".to_owned()],
        [d_del1, d_del2].into_iter().collect(),
        TimestampNs(500),
        None,
    )?;
    // Tampered proof digest fails verification immediately.
    let mut tampered = forged_uncommitted.clone();
    tampered.committed_tombstone_count = 999;
    assert!(matches!(
        store.compact_pack(pack_id, &tampered, CompactionPolicy::default()),
        Err(PackError::InvalidTombstoneProof { .. })
    ));
    // Validly constructed proof whose tombstones were NEVER committed to PackStore MUST fail closed!
    assert!(matches!(
        store.compact_pack(pack_id, &forged_uncommitted, CompactionPolicy::default()),
        Err(PackError::UncommittedTombstone { .. })
    ));

    // Now commit tombstones durably:
    let committed_proof = store.commit_eviction_tombstones(&batch, Some(42))?;
    assert!(committed_proof.covers_digest(&d_del1));
    assert!(committed_proof.covers_digest(&d_del2));

    let stats = store.pack_live_stats(pack_id)?;
    assert_eq!(stats.total_objects, 3);
    assert_eq!(stats.live_objects, 1);
    assert!(stats.live_ratio_ppm < 500_000);

    // Pin a ReaderEpochGuard and verify compaction REFUSES to unlink while reader holds pin!
    let reader = store.reader();
    let reader_guard = reader.pin_epoch()?;
    let zero_wait = CompactionPolicy {
        min_live_ratio_ppm: 500_000,
        reader_drain_timeout_ms: 0,
        max_packs_per_pass: None,
    };
    let drain_err = store.compact_pack(pack_id, &committed_proof, zero_wait);
    assert!(matches!(
        drain_err,
        Err(PackError::ReaderEpochDrainTimeout {
            active_readers: 1,
            ..
        })
    ));
    // Old packfile MUST STILL EXIST on disk because reader pin hadn't drained!
    let old_pack_path = store.packs_dir().join(pack_id.file_name());
    assert!(old_pack_path.exists());

    // Now drop the guard on a background thread after 25ms and run reclaim_superseded_packs ->
    // waits for the reader epoch to drain, then unlinks the old superseded packfile cleanly!
    let drop_handle = thread::spawn(move || {
        thread::sleep(Duration::from_millis(25));
        drop(reader_guard);
    });
    let reclaim_report = store.reclaim_superseded_packs(CompactionPolicy {
        min_live_ratio_ppm: 500_000,
        reader_drain_timeout_ms: 2_000,
        max_packs_per_pass: None,
    })?;
    drop_handle.join().map_err(|_| "drop thread panicked")?;
    assert_eq!(reclaim_report.packs_unlinked_empty, 1);
    assert!(!old_pack_path.exists());
    assert_eq!(store.read_verified(&d_keep)?, p_keep);
    Ok(())
}

/// Proof 4: Compaction crash-cut faults BEFORE staging rename, AFTER new pack before index swap,
/// and AFTER index swap before old-pack unlink!
#[test]
fn compaction_crash_cut_faults_recover_with_zero_data_loss_and_zero_dangling_pointers() -> TestResult
{
    for cut in [
        PackCutPoint::CompactionBeforeStagingRename,
        PackCutPoint::CompactionAfterNewPackBeforeIndexSwap,
        PackCutPoint::CompactionAfterIndexSwapBeforeOldPackUnlink,
    ] {
        let dir = TempTestDir::new(&format!("crash-cut-{cut}"))?;
        let store = PackStore::open(&dir.path, pack_cfg(64 * 1024))?;

        let live_payload = make_payload(&format!("live-surviving-{cut}"), 512);
        let dead1 = make_payload(&format!("dead-1-{cut}"), 1_536);
        let dead2 = make_payload(&format!("dead-2-{cut}"), 1_536);
        let d_live = ContentDigest::sha256(&live_payload);
        let d_dead1 = ContentDigest::sha256(&dead1);
        let d_dead2 = ContentDigest::sha256(&dead2);

        let locs = store.append_batch(&[
            PackObjectInput::with_digest(PACK_KIND_MEDIA_CHUNK, 0, &live_payload, d_live),
            PackObjectInput::with_digest(PACK_KIND_MEDIA_CHUNK, 0, &dead1, d_dead1),
            PackObjectInput::with_digest(PACK_KIND_MEDIA_CHUNK, 0, &dead2, d_dead2),
        ])?;
        let old_pack_id = locs[0].pack_id;
        let _ = store.seal_active_pack()?;

        let ring_cfg = RetentionRingConfig::new(100, 100_000, 100_000, 75, 95)?;
        let cands = vec![
            RetentionCandidate {
                import_id: "live".to_owned(),
                sensor_id: "cam-1".to_owned(),
                capture_end_ns: TimestampNs(1_000),
                byte_size: 512,
                object_digests: vec![d_live],
                is_derived_proxy: false,
                held_by: vec!["hold-crash".to_owned()],
                active_obligation_ids: Vec::new(),
                active_event_ids: Vec::new(),
            },
            RetentionCandidate {
                import_id: "dead".to_owned(),
                sensor_id: "cam-1".to_owned(),
                capture_end_ns: TimestampNs(1),
                byte_size: 3_072,
                object_digests: vec![d_dead1, d_dead2],
                is_derived_proxy: false,
                held_by: Vec::new(),
                active_obligation_ids: Vec::new(),
                active_event_ids: Vec::new(),
            },
        ];
        let RetentionPlanOutcome::Evict(batch) =
            plan_retention(&ring_cfg, &cands, TimestampNs(500))?
        else {
            return Err("expected eviction batch".into());
        };
        let proof = store.commit_eviction_tombstones(&batch, Some(1))?;

        let crash_res = store.compact_pack_with_cut_point(
            old_pack_id,
            &proof,
            CompactionPolicy::default(),
            cut,
        );
        assert!(matches!(crash_res, Err(PackError::InjectedCrash(c)) if c == cut));

        if cut == PackCutPoint::CompactionBeforeStagingRename {
            // Orphaned *.pack.compact.tmp MUST be present before reopen.
            let expected_tmp = store
                .packs_dir()
                .join(compact_staging_file_name(fss_pack::PackId::new(1, 2)));
            assert!(expected_tmp.exists());
        }
        drop(store);

        // Reopen after simulated crash: ZERO data loss, ZERO dangling pointers, ZERO resurrected tombstones!
        let reopened = PackStore::open(&dir.path, pack_cfg(64 * 1024))?;
        if cut == PackCutPoint::CompactionBeforeStagingRename {
            assert_eq!(
                reopened.recovery_report().packs.cleaned_staging_packs.len(),
                1
            );
            assert!(reopened.recovery_report().packs.foreign_entries.is_empty());
        }
        assert_eq!(reopened.read_verified(&d_live)?, live_payload);
        assert_eq!(
            reopened
                .read_verified(&d_dead1)
                .err()
                .and_then(|e| e.stable_error_id()),
            Some(ERR_EVIDENCE_DELETED_001)
        );
        assert_eq!(
            reopened
                .read_verified(&d_dead2)
                .err()
                .and_then(|e| e.stable_error_id()),
            Some(ERR_EVIDENCE_DELETED_001)
        );

        // Subsequent compaction / superseded pack cleanup finishes reclaiming old_pack_id cleanly!
        let finish = reopened.reclaim_superseded_packs(CompactionPolicy::default())?;
        assert!(
            finish.packs_unlinked_empty + finish.packs_rewritten >= 1,
            "old pack should finish compacting/unlinking after crash cut {cut}"
        );
        assert!(!reopened.packs_dir().join(old_pack_id.file_name()).exists());
        assert_eq!(reopened.read_verified(&d_live)?, live_payload);

        // Verify every remaining sealed pack passes full verification (zero dangling index pointers).
        let loc = reopened
            .lookup(&d_live)?
            .ok_or("live digest missing from index after recovery")?;
        let footer = reopened.verify_pack(loc.pack_id)?;
        assert_eq!(footer.entries.len(), 1);
        assert_eq!(footer.entries[0].digest(), d_live);
        assert!(matches!(
            reopened
                .compact_pack(loc.pack_id, &proof, CompactionPolicy::default())?
                .action,
            PackCompactionAction::SkippedAboveThreshold
        ));
    }
    Ok(())
}

/// Proof 5: Rate-limited incremental background doctor scrubber with deterministic cursor
/// and exact 1-byte corruption detection naming the exact corrupt digest & requiring an obligation.
#[test]
fn background_scrubber_incremental_cursor_and_single_byte_corruption_detection() -> TestResult {
    let dir = TempTestDir::new("scrubber-contract")?;
    // Each payload is 400 bytes -> 2 objects per 900-byte pack -> 3 sealed packs (6 objects total).
    let store = PackStore::open(&dir.path, pack_cfg(900))?;

    let mut stored = Vec::new();
    for i in 0_u32..6 {
        let payload = make_payload(&format!("scrub-object-{i:03}"), 360);
        let digest = ContentDigest::sha256(&payload);
        let locs = store.append_batch(&[PackObjectInput::with_digest(
            PACK_KIND_RAW_PAYLOAD,
            0,
            &payload,
            digest,
        )])?;
        stored.push((digest, locs[0]));
    }
    let _ = store.seal_active_pack()?;
    let sealed_ids = store.sealed_pack_ids()?;
    assert_eq!(sealed_ids.len(), 3);

    // 1. Clean incremental passes with strict budget (1 pack per pass) advance cursor smoothly.
    let mut scrubber = BackgroundScrubber::new();
    let pass_budget = ScrubBudget {
        max_bytes: 16 * 1024,
        max_packs: 1,
        max_objects: 10,
    };

    let r1 = scrubber.scrub_pass(&store, pass_budget, TimestampNs(1_000))?;
    r1.verify_digest()?;
    assert_eq!(r1.verdict, ScrubVerdict::Degraded);
    assert!(!r1.cycle_completed);
    assert!(!r1.requires_obligation);
    assert_eq!(r1.verified_packs, 1);
    assert_eq!(r1.verified_objects, 2);
    assert_eq!(r1.verified_fraction_ppm, 333_333);

    let r2 = scrubber.scrub_pass(&store, pass_budget, TimestampNs(2_000))?;
    r2.verify_digest()?;
    assert_eq!(r2.verdict, ScrubVerdict::Degraded);
    assert!(!r2.cycle_completed);
    assert_eq!(r2.verified_packs, 1);
    assert_eq!(r2.verified_fraction_ppm, 666_666);

    let r3 = scrubber.scrub_pass(&store, pass_budget, TimestampNs(3_000))?;
    r3.verify_digest()?;
    assert_eq!(r3.verdict, ScrubVerdict::Clean);
    assert!(r3.cycle_completed);
    assert!(!r3.requires_obligation);
    assert_eq!(r3.verified_packs, 1);
    assert_eq!(r3.verified_fraction_ppm, MAX_VERIFIED_FRACTION_PPM);
    assert_eq!(scrubber.cursor().completed_cycles, 1);

    // 2. Flip 1 byte inside object #3's payload in its sealed packfile!
    let (corrupt_digest, corrupt_loc) = stored[3];
    let corrupt_pack_path = store.packs_dir().join(corrupt_loc.pack_id.file_name());
    let mut raw = fs::read(&corrupt_pack_path)?;
    let flip_pos = (corrupt_loc.offset as usize) + PACK_RECORD_HEADER_LEN + 17;
    raw[flip_pos] ^= 0x01;
    {
        let mut f = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&corrupt_pack_path)?;
        f.write_all(&raw)?;
        f.sync_all()?;
    }

    // Run bounded incremental passes until corruption is caught!
    let mut detected_report = None;
    for step in 0_u64..4 {
        let rep =
            scrubber.scrub_pass(&store, pass_budget, TimestampNs(10_000 + i128::from(step)))?;
        rep.verify_digest()?;
        if rep.verdict == ScrubVerdict::Failed {
            detected_report = Some(rep);
            break;
        }
    }

    let failed = detected_report.ok_or("scrubber failed to detect 1-byte bitflip")?;
    assert_eq!(failed.verdict, ScrubVerdict::Failed);
    assert!(failed.requires_obligation);
    assert!(
        failed.corrupt_digests.contains(&corrupt_digest),
        "expected exact corrupt digest {corrupt_digest} in {:?}",
        failed.corrupt_digests
    );
    assert!(failed.findings.iter().any(|f| {
        f.pack_id == corrupt_loc.pack_id
            && f.digest == Some(corrupt_digest)
            && matches!(
                f.kind,
                ScrubFailureKind::CrcMismatch | ScrubFailureKind::ObjectDigestMismatch
            )
    }));
    assert!(failed.findings.iter().any(|f| {
        f.pack_id == corrupt_loc.pack_id && f.kind == ScrubFailureKind::WholePackDigestMismatch
    }));
    Ok(())
}

#[test]
fn catalog_retirement_recovery_finishes_object_deletion_and_compaction() -> TestResult {
    let dir = TempTestDir::new("resume-catalog-retirement")?;
    let cfg = pack_cfg(64 * 1024);
    let media = make_payload("retired-media", 16 * 1024);
    let metadata = make_payload("canonical-replay-metadata", 256);
    let child = make_payload("unrelated-child", 512);
    let media_digest = ContentDigest::sha256(&media);
    let metadata_digest = ContentDigest::sha256(&metadata);
    let child_digest = ContentDigest::sha256(&child);
    let reason = ContentDigest::sha256(b"canonical-footage-retirement");
    let root_id = "gop:recovery:1";

    let store = PackStore::open(&dir.path, cfg)?;
    let _ = store.publish_graph(
        &[
            PackObjectInput::with_digest(PACK_KIND_MEDIA_CHUNK, 0, &media, media_digest),
            PackObjectInput::with_digest(PACK_KIND_METADATA, 0, &metadata, metadata_digest),
            PackObjectInput::with_digest(PACK_KIND_RAW_PAYLOAD, 0, &child, child_digest),
        ],
        VirtualRootRecord::new(
            root_id,
            media_digest,
            "media-gop-v2",
            1,
            (media.len() + metadata.len()) as u64,
            1,
            TimestampNs(10),
            Some(metadata_digest),
        )?,
    )?;
    let _ = store.seal_active_pack()?;
    // Reproduce the durable cut after catalog retirement and before object log commitment.
    let retired = store.tombstone_root(root_id, reason)?;
    assert_eq!(store.object_tombstone(&media_digest)?, None);
    drop(store);

    let store = PackStore::open(&dir.path, cfg)?;
    assert_eq!(store.read_verified(&media_digest)?, media);
    let bytes_before = store.on_disk_pack_bytes()?;
    assert!(store.resume_root_object_deletion(root_id, media_digest)?);
    assert_eq!(store.get_root(root_id)?, Some(retired.clone()));
    assert_eq!(store.object_tombstone(&media_digest)?, Some(reason));
    assert_eq!(store.lookup(&media_digest)?, None);
    assert!(matches!(
        store.read_verified(&media_digest),
        Err(PackError::EvidenceDeleted { digest, reason_digest })
            if digest == media_digest && reason_digest == reason
    ));
    assert_eq!(store.read_verified(&metadata_digest)?, metadata);
    assert_eq!(store.read_verified(&child_digest)?, child);
    assert!(!store.resume_root_object_deletion(root_id, media_digest)?);
    assert_eq!(store.on_disk_pack_bytes()?, bytes_before);
    drop(store);

    // Also restart between the object tombstone and physical compaction.
    let store = PackStore::open(&dir.path, cfg)?;
    assert!(!store.resume_root_object_deletion(root_id, media_digest)?);
    assert_eq!(store.get_root(root_id)?, Some(retired));
    let reclaimed = store.reclaim_superseded_packs(CompactionPolicy::default())?;
    assert!(reclaimed.total_bytes_reclaimed > 0);
    assert!(store.on_disk_pack_bytes()? < bytes_before);
    assert_eq!(store.object_tombstone(&media_digest)?, Some(reason));
    assert_eq!(store.read_verified(&metadata_digest)?, metadata);
    assert_eq!(store.read_verified(&child_digest)?, child);
    assert_eq!(
        store
            .reclaim_superseded_packs(CompactionPolicy::default())?
            .total_bytes_reclaimed,
        0
    );

    // A restore/reimport must not physically reintroduce deleted payloads or commit
    // the innocent prefix of a mixed batch, even after reclamation and restart.
    drop(store);
    let store = PackStore::open(&dir.path, cfg)?;
    let new_payload = b"uncommitted fresh source";
    let fresh_digest = ContentDigest::sha256(new_payload);
    let inputs = [
        PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, new_payload),
        PackObjectInput::new(PACK_KIND_MEDIA_CHUNK, 0, &media),
    ];
    let bytes_before_retry = store.on_disk_pack_bytes()?;
    let fsyncs_before_retry = store.telemetry_snapshot()?.pack_fsync_count;
    assert!(matches!(
        store.append_batch(&inputs),
        Err(PackError::EvidenceDeleted { digest, reason_digest })
            if digest == media_digest && reason_digest == reason
    ));
    let retry_root = VirtualRootRecord::new(
        "gop:retry",
        fresh_digest,
        "media-gop-v2",
        2,
        128,
        1,
        TimestampNs(22),
        None,
    )?;
    assert!(matches!(
        store.publish_graph(&inputs, retry_root),
        Err(PackError::EvidenceDeleted { digest, reason_digest })
            if digest == media_digest && reason_digest == reason
    ));
    assert!(store.get_root("gop:retry")?.is_none());
    assert!(store.lookup(&fresh_digest)?.is_none());
    assert!(store.lookup(&media_digest)?.is_none());
    assert_eq!(store.on_disk_pack_bytes()?, bytes_before_retry);
    assert_eq!(
        store.telemetry_snapshot()?.pack_fsync_count,
        fsyncs_before_retry
    );
    let _ = store.append_batch(&inputs[..1])?;
    assert_eq!(store.read_verified(&fresh_digest)?, new_payload);
    Ok(())
}

#[test]
fn catalog_retirement_recovery_requires_exact_dead_root_and_preserves_live_aliases() -> TestResult {
    for metadata_reference in [false, true] {
        let dir = TempTestDir::new(if metadata_reference {
            "resume-live-metadata-reference"
        } else {
            "resume-live-root-reference"
        })?;
        let store = PackStore::open(&dir.path, pack_cfg(64 * 1024))?;
        let media = make_payload("shared-retired-media", 1024);
        let other = make_payload("unrelated-live-root", 256);
        let media_digest = ContentDigest::sha256(&media);
        let other_digest = ContentDigest::sha256(&other);
        let reason = ContentDigest::sha256(b"original-catalog-reason");
        let _ = store.append_batch(&[
            PackObjectInput::with_digest(PACK_KIND_MEDIA_CHUNK, 0, &media, media_digest),
            PackObjectInput::with_digest(PACK_KIND_RAW_PAYLOAD, 0, &other, other_digest),
        ])?;
        let root = |id: &str, digest: ContentDigest, metadata: Option<ContentDigest>| {
            VirtualRootRecord::new(
                id,
                digest,
                "media-gop-v2",
                1,
                1024,
                1,
                TimestampNs(10),
                metadata,
            )
        };
        let _ = store.publish_root(root("retired", media_digest, None)?)?;
        assert!(matches!(
            store.resume_root_object_deletion("absent", media_digest),
            Err(PackError::RootNotFound(_))
        ));
        assert!(matches!(
            store.resume_root_object_deletion("retired", media_digest),
            Err(PackError::InvalidTombstoneProof { .. })
        ));
        assert_eq!(store.object_tombstone(&media_digest)?, None);
        let retired = store.tombstone_root("retired", reason)?;
        assert!(matches!(
            store.resume_root_object_deletion("retired", other_digest),
            Err(PackError::InvalidTombstoneProof { .. })
        ));
        assert!(matches!(
            store.resume_root_object_deletion(
                "retired",
                ContentDigest::new(fss_core::DigestAlgorithm::Blake3, media_digest.bytes()),
            ),
            Err(PackError::UnsupportedDigestAlgorithm(_))
        ));

        // Put the protecting reference after a full page of unrelated live roots.
        let mut live_roots = Vec::new();
        for i in 0..513 {
            live_roots.push(root(&format!("a-live-{i:04}"), other_digest, None)?);
        }
        live_roots.push(if metadata_reference {
            root("z-protecting-root", other_digest, Some(media_digest))?
        } else {
            root("z-protecting-root", media_digest, None)?
        });
        let _ = store.publish_roots_batch(&live_roots)?;
        assert!(!store.resume_root_object_deletion("retired", media_digest)?);
        assert_eq!(store.get_root("retired")?, Some(retired.clone()));
        assert_eq!(store.object_tombstone(&media_digest)?, None);
        assert_eq!(store.read_verified(&media_digest)?, media);
        assert_eq!(store.read_verified(&other_digest)?, other);

        let _ = store.tombstone_root(
            "z-protecting-root",
            ContentDigest::sha256(b"separate-alias-retirement"),
        )?;
        assert!(store.resume_root_object_deletion("retired", media_digest)?);
        assert!(!store.resume_root_object_deletion("retired", media_digest)?);
        assert_eq!(store.get_root("retired")?, Some(retired));
        assert_eq!(store.object_tombstone(&media_digest)?, Some(reason));
        if !metadata_reference {
            assert!(!store.resume_root_object_deletion("z-protecting-root", media_digest)?);
            assert_eq!(store.object_tombstone(&media_digest)?, Some(reason));
        }
        assert_eq!(store.read_verified(&other_digest)?, other);

        // Supersession is not deletion authority either.
        let _ = store.publish_root(root("superseded-old", other_digest, None)?)?;
        let _ = store.supersede_root(
            "superseded-old",
            root("superseded-new", other_digest, None)?,
        )?;
        assert!(matches!(
            store.resume_root_object_deletion("superseded-old", other_digest),
            Err(PackError::InvalidTombstoneProof { .. })
        ));
        assert_eq!(store.object_tombstone(&other_digest)?, None);
    }
    Ok(())
}
