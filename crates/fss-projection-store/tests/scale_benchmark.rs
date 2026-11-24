#![forbid(unsafe_code)]
//! Scale and latency benchmark verifying sub-millisecond/low-millisecond p99 read latencies
//! across 100 cameras, 500 active events, 10,000+ coverage witnesses, and 20,000 (or 100,000+)
//! commits, emitting structured JSONL telemetry.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EventId, EventKind, EventState, EvidenceDelta,
    EvidenceDeltaBatch, ObjectId, ObjectRevision, Plane, SensorId, StreamId, TimestampNs,
};
use fss_ledger::{
    EpochLedgerConfig, IncompleteTailPolicy, MerkleEpochLedger, RadixMerkleTrie,
    merkle_genesis_anchor,
};
use fss_pack::{DurabilityMode, PACK_KIND_METADATA, PackConfig, PackStore};
use fss_projection_store::{
    CommitCombiner, CommitCombinerConfig, CommitProposal, CoverageStatus, CoverageWitnessPayload,
    EventQueryFilter, EventRevisionPayload, FAMILY_COVERAGE_WITNESS, FAMILY_EVENT_REVISION,
    FAMILY_FOOTAGE_IMPORT, FAMILY_SENSOR_LIVENESS, FootageAdapterKind, FootageImportPayload,
    FootageQueryFilter, HistoryChainMode, InMemoryPayloadResolver, LedgerPackProjectionSink,
    MvccProjectionStore, OwnedPackObject, ProjectionRecordPayload, ProjectionStore,
    ProjectionStoreConfig, SensorLivenessPayload, SensorLivenessStatus, WalSyncPolicy,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static BENCH_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempBenchDir {
    root: PathBuf,
}

impl TempBenchDir {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let id = BENCH_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "fss-proj-bench-{label}-{}-{id}",
            std::process::id()
        ));
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }
}

impl Drop for TempBenchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn percentile_us(samples: &mut [u64], pct_num: usize, pct_den: usize) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    samples.sort_unstable();
    let idx = (samples.len().saturating_sub(1) * pct_num) / pct_den;
    samples[idx]
}

fn run_combiner_burst(root: &std::path::Path) -> Result<(u64, u64), Box<dyn std::error::Error>> {
    let ledger = MerkleEpochLedger::open(
        root.join("comb-ledger"),
        "site:bench-comb",
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )?;
    let packs = Arc::new(PackStore::open(
        root.join("comb-packs"),
        PackConfig {
            durability: DurabilityMode::Fsync,
            ..PackConfig::default()
        },
    )?);
    let proj = Arc::new(MvccProjectionStore::open_empty(
        root.join("comb-proj"),
        ledger.genesis_anchor(),
        ProjectionStoreConfig::default(),
    )?);
    let sink = LedgerPackProjectionSink::new(ledger, packs, proj);
    let combiner = Arc::new(CommitCombiner::new(sink, CommitCombinerConfig::default())?);

    const THREADS: usize = 16;
    const PER_THREAD: u64 = 4;
    let barrier = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::with_capacity(THREADS);
    for tid in 0..THREADS {
        let c = Arc::clone(&combiner);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || -> Result<(), String> {
            b.wait();
            for step in 1..=PER_THREAD {
                let sensor =
                    SensorId::parse(format!("bcam-{tid:02}")).map_err(|e| e.to_string())?;
                let interval = CaptureInterval::new(
                    TimestampNs(step as i128 * 1000),
                    TimestampNs(step as i128 * 1000 + 500),
                )
                .map_err(|e| e.to_string())?;
                let payload = ProjectionRecordPayload::SensorLiveness(SensorLivenessPayload {
                    sensor_id: sensor.clone(),
                    state: SensorLivenessStatus::Online,
                    last_seen_ns: interval.earliest,
                    observed_at_ns: interval.latest,
                });
                let raw = payload.encode_bytes().map_err(|e| e.to_string())?;
                let digest = ContentDigest::sha256(&raw);
                let delta = EvidenceDelta {
                    delta_id: format!("bd-{tid:02}-{step:02}"),
                    family: FAMILY_SENSOR_LIVENESS.to_owned(),
                    object_id: ObjectId::parse(format!("obj:blive:{tid:02}"))
                        .map_err(|e| e.to_string())?,
                    prior_generation: (step > 1).then_some(step - 1),
                    new_generation: step,
                    validity: interval,
                    plane: Plane::Authority,
                    payload_digest: digest,
                    witness_digest: None,
                    operation_id: None,
                };
                let prop = CommitProposal {
                    request_digest: ContentDigest::sha256(format!("breq-{tid}-{step}").as_bytes()),
                    sensor_scope: sensor.into_inner(),
                    objects: vec![OwnedPackObject::with_digest(
                        PACK_KIND_METADATA,
                        0,
                        raw,
                        digest,
                    )],
                    deltas: vec![delta],
                    batch_id_prefix: format!("b{tid:02}"),
                };
                let _ = c.submit(prop).map_err(|e| e.to_string())?;
            }
            Ok(())
        }));
    }
    for h in handles {
        h.join()
            .map_err(|_| "combiner benchmark thread panicked")?
            .map_err(|e| format!("combiner thread error: {e}"))?;
    }
    let stats = combiner.shutdown()?;
    Ok((stats.coalesced_commits, stats.fsyncs_saved))
}

fn run_scale_suite(label: &str, total_commits: u64) -> TestResult {
    let dir = TempBenchDir::new(label)?;
    let genesis = merkle_genesis_anchor("site:scale-bench");
    let config = ProjectionStoreConfig {
        durability: DurabilityMode::Fsync,
        wal_sync: WalSyncPolicy::FlushOnly,
        snapshot_stride: 10_000,
        max_retained_snapshots: 32,
        history_mode: HistoryChainMode::V2MerkleEpoch,
    };
    let store = MvccProjectionStore::open_empty(dir.root.join("proj"), &genesis, config)?;
    let resolver = InMemoryPayloadResolver::new();

    let mut trie = RadixMerkleTrie::new();
    let mut head_anchor = genesis;
    let mut gens: BTreeMap<ObjectId, u64> = BTreeMap::new();
    let adapters = [
        FootageAdapterKind::Rtsp,
        FootageAdapterKind::Http,
        FootageAdapterKind::File,
        FootageAdapterKind::Tutk,
    ];

    // Pre-parse 100 sensors and 20 zones so benchmark setup measures store overhead cleanly.
    let sensors: Vec<SensorId> = (0..100)
        .map(|i| SensorId::parse(format!("cam-{i:03}")))
        .collect::<Result<_, _>>()?;
    let streams: Vec<StreamId> = (0..100)
        .map(|i| StreamId::parse(format!("stream-{i:03}")))
        .collect::<Result<_, _>>()?;
    let zones: Vec<String> = (0..20).map(|i| format!("zone-{i:02}")).collect();

    for seq in 1..=total_commits {
        let cam = (seq as usize) % sensors.len();
        let zone_idx = (seq as usize) % zones.len();
        let start = TimestampNs((seq as i128) * 1_000_000);
        let end = TimestampNs((seq as i128) * 1_000_000 + 250_000);
        let interval = CaptureInterval::new(start, end)?;

        let (family, object_id, plane, payload) = if seq <= 500 {
            // 500 active events across 100 cameras and 20 zones.
            let ev_id = EventId::parse(format!("ev-{seq:05}"))?;
            let state = match seq % 5 {
                0 => EventState::Hypothesized,
                1 => EventState::Witnessed,
                2 => EventState::Corroborated,
                3 => EventState::Adjudicated,
                _ => EventState::AlertDelivered,
            };
            (
                FAMILY_EVENT_REVISION,
                ObjectId::parse(format!("obj:ev:{seq:05}"))?,
                Plane::Cognition,
                ProjectionRecordPayload::EventRevision(EventRevisionPayload {
                    event_id: ev_id,
                    revision: 1,
                    state,
                    kind: EventKind::PerimeterBreach,
                    zones: vec![zones[zone_idx].clone()],
                    sensor_ids: vec![sensors[cam].clone()],
                    interval,
                    event_root: ContentDigest::sha256(&seq.to_be_bytes()),
                    supersedes: None,
                    corroborated: seq % 5 >= 2,
                    tamper_open: seq.is_multiple_of(50),
                }),
            )
        } else if seq <= 10_500 {
            // 10,000 coverage witnesses across 100 cameras x 5 zones.
            let z = (seq as usize) % 5;
            let status = if seq.is_multiple_of(25) {
                CoverageStatus::NotObservable
            } else {
                CoverageStatus::Covered
            };
            (
                FAMILY_COVERAGE_WITNESS,
                ObjectId::parse(format!("obj:cov:{cam:03}:{z:02}"))?,
                Plane::Authority,
                ProjectionRecordPayload::CoverageWitness(CoverageWitnessPayload {
                    sensor_id: sensors[cam].clone(),
                    zone_id: zones[z].clone(),
                    window: interval,
                    status,
                    active_gaps: u32::from(status == CoverageStatus::NotObservable),
                    health_conflicts: 0,
                }),
            )
        } else if seq % 4 == 0 {
            // Unified RTSP/HTTP/File/TUTK footage imports.
            let adapter_kind = adapters[(seq as usize / 4) % adapters.len()];
            let import_id = ContentDigest::sha256(&seq.to_be_bytes());
            (
                FAMILY_FOOTAGE_IMPORT,
                ObjectId::parse(format!("obj:imp:{seq:07}"))?,
                Plane::Authority,
                ProjectionRecordPayload::FootageImport(FootageImportPayload {
                    import_id,
                    adapter_kind,
                    sensor_id: sensors[cam].clone(),
                    stream_id: streams[cam].clone(),
                    capture_interval: interval,
                    manifest_digest: import_id,
                    capsule_count: 10,
                    total_bytes: 16_384,
                    adapter_id: format!("adp-{}", adapter_kind.as_str()),
                    adapter_generation: "gen-v1".to_owned(),
                    completed: true,
                }),
            )
        } else {
            // Sensor liveness heartbeats across all 100 cameras.
            (
                FAMILY_SENSOR_LIVENESS,
                ObjectId::parse(format!("obj:live:{cam:03}"))?,
                Plane::Authority,
                ProjectionRecordPayload::SensorLiveness(SensorLivenessPayload {
                    sensor_id: sensors[cam].clone(),
                    state: SensorLivenessStatus::Online,
                    last_seen_ns: start,
                    observed_at_ns: end,
                }),
            )
        };

        let (digest, _) = resolver.insert_payload(&payload)?;
        let prior = gens.get(&object_id).copied();
        let next_gen = prior.map_or(1, |g| g + 1);
        gens.insert(object_id.clone(), next_gen);

        let rev = ObjectRevision {
            generation: next_gen,
            family: family.to_owned(),
            plane,
            payload_digest: digest,
            validity: interval,
        };
        trie.insert(object_id.clone(), rev)?;

        let delta = EvidenceDelta {
            delta_id: format!("sd-{seq:07}"),
            family: family.to_owned(),
            object_id,
            prior_generation: prior,
            new_generation: next_gen,
            validity: interval,
            plane,
            payload_digest: digest,
            witness_digest: None,
            operation_id: None,
        };
        let mut next_anchor = head_anchor.clone();
        next_anchor.commit_sequence = seq;
        next_anchor.state_root = trie.root();

        let mut batch = EvidenceDeltaBatch {
            batch_id: BatchId::parse(format!("sb-{seq:07}"))?,
            basis_anchor: head_anchor,
            new_anchor: next_anchor.clone(),
            deltas: vec![delta],
            children: vec![digest],
            batch_digest: ContentDigest::sha256(b"pending"),
        };
        batch.batch_digest = batch.computed_digest();
        let _ = store.apply_delta_batch(&batch, &resolver)?;
        head_anchor = next_anchor;
    }

    let snap = store.snapshot_latest();
    let summary = snap.orient_summary();
    assert_eq!(summary.anchor.commit_sequence, total_commits);
    assert_eq!(summary.total_events, 500);

    // Measure 500 iterations of orient, event/footage queries, and small-delta follow_since.
    const SAMPLES: usize = 500;
    let mut orient_us = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let t0 = Instant::now();
        let s = store.snapshot_latest();
        let sum = s.orient_summary();
        assert_eq!(sum.total_events, 500);
        orient_us.push(t0.elapsed().as_micros() as u64);
    }

    let mut query_us = Vec::with_capacity(SAMPLES);
    for i in 0..SAMPLES {
        let ev_filter = EventQueryFilter {
            state: Some(EventState::Corroborated),
            zone: Some(zones[i % zones.len()].clone()),
            ..EventQueryFilter::default()
        };
        let foot_filter = FootageQueryFilter {
            sensor: Some(sensors[i % sensors.len()].clone()),
            adapter_kind: Some(adapters[i % adapters.len()]),
            completed_only: true,
            ..FootageQueryFilter::default()
        };
        let t0 = Instant::now();
        let s = store.snapshot_latest();
        let _ep = store.query_events(&s, &ev_filter, 32);
        let _fp = store.query_footage(&s, &foot_filter, 32);
        query_us.push(t0.elapsed().as_micros() as u64);
    }

    let mut follow_us = Vec::with_capacity(SAMPLES);
    let follow_from = total_commits.saturating_sub(16);
    for _ in 0..SAMPLES {
        let t0 = Instant::now();
        let page = store.follow_since(follow_from, 32)?;
        assert_eq!(page.commits.len(), 16);
        follow_us.push(t0.elapsed().as_micros() as u64);
    }

    let orient_p99_us = percentile_us(&mut orient_us, 99, 100);
    let query_p99_us = percentile_us(&mut query_us, 99, 100);
    let follow_p99_us = percentile_us(&mut follow_us, 99, 100);

    let (coalesced_commits, fsyncs_saved) = run_combiner_burst(&dir.root)?;

    println!(
        "{{\"event\":\"projection_scale_benchmark\",\"projection_high_water\":{},\"commit_count\":{},\"orient_p99_us\":{},\"query_p99_us\":{},\"follow_p99_us\":{},\"coalesced_commits\":{},\"fsyncs_saved\":{}}}",
        summary.anchor.commit_sequence,
        total_commits,
        orient_p99_us,
        query_p99_us,
        follow_p99_us,
        coalesced_commits,
        fsyncs_saved,
    );

    assert!(
        orient_p99_us < 10_000,
        "orient_p99_us={orient_p99_us} exceeded 10ms budget"
    );
    assert!(
        query_p99_us < 5_000,
        "query_p99_us={query_p99_us} exceeded 5ms budget"
    );
    assert!(
        follow_p99_us < 3_000,
        "follow_p99_us={follow_p99_us} exceeded 3ms budget"
    );
    Ok(())
}

#[test]
fn scale_benchmark_20k_commits() -> TestResult {
    run_scale_suite("20k", 20_000)
}

#[test]
#[ignore = "heavy 100k-commit scale benchmark; run explicitly with -- --ignored --nocapture"]
fn scale_benchmark_100k_commits() -> TestResult {
    run_scale_suite("100k", 100_000)
}
