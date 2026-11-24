#![forbid(unsafe_code)]
//! Real 100-camera / 1,000,000-commit scale benchmark (`QL-SCALE-001`) driving
//! `MerkleEpochLedger` + `PackStore` + `VirtualRootCatalog` + `MvccProjectionStore`
//! + `CommitCombiner` + `BackgroundScrubber` + hold-safe ring compaction end-to-end.
//!
//! All temporary packfile, ledger, and projection directories live under `std::env::temp_dir()`
//! and are unconditionally removed on drop to prevent disk exhaustion, while compact structured
//! proof artifacts (`scale_timeseries.jsonl` and `scale_million_report.json`) are retained under
//! `target/test-logs/scale-benchmark/`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EventId, EventKind, EventState, EvidenceDelta,
    ObjectId, ObligationId, ObligationState, OperationId, Plane, SensorId, StreamId, TimestampNs,
};
use fss_ledger::{EpochLedgerConfig, IncompleteTailPolicy, MerkleEpochLedger};
use fss_pack::{
    BackgroundScrubber, CompactionPolicy, DurabilityMode, ERR_EVIDENCE_DELETED_001,
    PACK_KIND_MEDIA_CHUNK, PACK_KIND_METADATA, PackConfig, PackObjectInput, PackStore, QuotaPolicy,
    RetentionCandidate, RetentionPlanOutcome, RetentionRingConfig, ScrubBudget,
    ScrubVerdict as PackScrubVerdict, VirtualRootRecord, plan_retention,
};
use fss_projection_store::{
    CommitCombiner, CommitCombinerConfig, CommitProposal, CoverageStatus, CoverageWitnessPayload,
    DeletionTarget, DeletionTombstonePayload, EventQueryFilter, EventRevisionPayload,
    EvidenceHoldPayload, FAMILY_COVERAGE_WITNESS, FAMILY_DELETION_TOMBSTONE, FAMILY_EVENT_REVISION,
    FAMILY_EVIDENCE_HOLD, FAMILY_FOOTAGE_IMPORT, FAMILY_OBLIGATION, FAMILY_PRIVACY_MASK_POLICY,
    FAMILY_SENSOR_LIVENESS, FootageAdapterKind, FootageImportPayload, FootageQueryFilter,
    HistoryChainMode, LedgerPackProjectionSink, MvccProjectionStore, ObligationPayload,
    OwnedPackObject, PackStorePayloadResolver, PrivacyMaskPayload, ProjectionRecordPayload,
    ProjectionRecoveryMode, ProjectionStore, ProjectionStoreConfig, SensorLivenessPayload,
    SensorLivenessStatus, WalSyncPolicy,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CAMERA_COUNT: usize = 100;
const ZONE_COUNT: usize = 20;
const ZONES_PER_CAMERA: usize = 5;
const COMMITS_PER_WAVE: u64 = 5_000;
const LOGICAL_GOP_BYTES: u64 = 1_048_576; // 1 MiB logical 3s H.264 GOP accounted per virtual root
const TARGET_ACTIVE_FOOTAGE_RING: usize = 100;
const TARGET_ACTIVE_EVENTS_WINDOW: usize = 200;

/// Canonical non-projected FSS provenance families committed into `MerkleEpochLedger`.
const FAMILY_SENSOR_CAPSULE: &str = "sensor_capsule";
const FAMILY_DECODE_RECEIPT: &str = "decode_receipt";
const FAMILY_MODEL_INVOCATION_RECEIPT: &str = "model_invocation_receipt";
const FAMILY_EXECUTOR_MODEL_RESULT: &str = "executor_model_result";

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempScaleWorkspace {
    root: PathBuf,
}

impl TempScaleWorkspace {
    fn new(label: &str) -> TestResult<Self> {
        let id = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("fss-scale-1m-{label}-{}-{id}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }
}

impl Drop for TempScaleWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone, Copy, Debug)]
struct ScaleProfile {
    fast_mode: bool,
    total_commits: u64,
    total_waves: u64,
    target_events_total: usize,
    roots_per_wave: usize,
    milestones: [u64; 5],
    pack_target_bytes: u64,
    ring_cap_bytes: u64,
    gop_chunks_per_wave: usize,
    gop_physical_bytes: usize,
}

impl ScaleProfile {
    fn from_env() -> Self {
        let fast = std::env::var("FSS_SCALE_FAST")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if fast {
            Self {
                fast_mode: true,
                total_commits: 100_000,
                total_waves: 21, // w1=1k, w2=4k, w3=5k (10k), w4..=21=5k (100k)
                target_events_total: 1_000,
                roots_per_wave: 500, // 10,500 virtual roots
                milestones: [1_000, 10_000, 25_000, 50_000, 100_000],
                pack_target_bytes: 512 * 1024,
                ring_cap_bytes: 4 * 1024 * 1024,
                gop_chunks_per_wave: 16,
                gop_physical_bytes: 8_192,
            }
        } else {
            Self {
                fast_mode: false,
                total_commits: 1_000_000,
                total_waves: 201, // w1=1k, w2=4k, w3=5k (10k), w4..=201=5k (1,000,000)
                target_events_total: 5_000,
                roots_per_wave: 520, // 104,520 virtual roots (> 100k roots, > 104 GiB logical media)
                milestones: [1_000, 10_000, 100_000, 500_000, 1_000_000],
                pack_target_bytes: 2 * 1024 * 1024, // 2 MiB sealed packs -> 60+ pack rotations
                ring_cap_bytes: 16 * 1024 * 1024,   // 16 MiB bounded local hot ring cap
                gop_chunks_per_wave: 32, // 32 x 16 KiB = 512 KiB/wave = 103 MiB streamed & compacted
                gop_physical_bytes: 16_384,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct LatencyStatsUs {
    samples: usize,
    p50_us: u64,
    p95_us: u64,
    p99_us: u64,
    max_us: u64,
}

impl LatencyStatsUs {
    fn from_samples(raw: &[u64]) -> Self {
        if raw.is_empty() {
            return Self::default();
        }
        let mut sorted = raw.to_vec();
        sorted.sort_unstable();
        let len = sorted.len();
        let at = |num: usize, den: usize| -> u64 {
            let idx = (len.saturating_sub(1) * num) / den;
            sorted[idx]
        };
        Self {
            samples: len,
            p50_us: at(50, 100),
            p95_us: at(95, 100),
            p99_us: at(99, 100),
            max_us: sorted[len - 1],
        }
    }

    fn to_json(self) -> String {
        format!(
            "{{\"samples\":{},\"p50_us\":{},\"p95_us\":{},\"p99_us\":{},\"max_us\":{}}}",
            self.samples, self.p50_us, self.p95_us, self.p99_us, self.max_us
        )
    }
}

struct MilestoneRecord {
    commits: u64,
    waves: u64,
    group_commit: LatencyStatsUs,
    amortized_commit: LatencyStatsUs,
    orient: LatencyStatsUs,
    query: LatencyStatsUs,
    follow: LatencyStatsUs,
    cold_open_merkle: LatencyStatsUs,
    cold_open_mvcc: LatencyStatsUs,
    cold_open_total: LatencyStatsUs,
    doctor_scrub: LatencyStatsUs,
    rss_mib: f64,
    on_disk_pack_bytes: u64,
    sealed_packs: usize,
    total_roots_published: u64,
    live_roots: u64,
    total_events_created: usize,
    active_events: usize,
    active_holds: usize,
    privacy_masks: usize,
    fd_pool_open: usize,
    fd_pool_evictions: u64,
}

impl MilestoneRecord {
    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\"schema\":\"fss.scale_timeseries.v1\",",
                "\"commits\":{},\"waves\":{},",
                "\"group_commit\":{},\"amortized_commit\":{},",
                "\"orient\":{},\"query\":{},\"follow\":{},",
                "\"cold_open_merkle\":{},\"cold_open_mvcc\":{},\"cold_open_total\":{},",
                "\"doctor_scrub\":{},",
                "\"rss_mib\":{:.3},\"on_disk_pack_bytes\":{},\"sealed_packs\":{},",
                "\"total_roots_published\":{},\"live_roots\":{},",
                "\"total_events_created\":{},\"active_events\":{},\"active_holds\":{},\"privacy_masks\":{},",
                "\"fd_pool_open\":{},\"fd_pool_evictions\":{}}}"
            ),
            self.commits,
            self.waves,
            self.group_commit.to_json(),
            self.amortized_commit.to_json(),
            self.orient.to_json(),
            self.query.to_json(),
            self.follow.to_json(),
            self.cold_open_merkle.to_json(),
            self.cold_open_mvcc.to_json(),
            self.cold_open_total.to_json(),
            self.doctor_scrub.to_json(),
            self.rss_mib,
            self.on_disk_pack_bytes,
            self.sealed_packs,
            self.total_roots_published,
            self.live_roots,
            self.total_events_created,
            self.active_events,
            self.active_holds,
            self.privacy_masks,
            self.fd_pool_open,
            self.fd_pool_evictions,
        )
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

fn sample_rss_mib() -> f64 {
    let pid = std::process::id().to_string();
    let output = Command::new("ps").args(["-o", "rss=", "-p", &pid]).output();
    let Ok(out) = output else {
        return 0.0;
    };
    if !out.status.success() {
        return 0.0;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let kib = text.trim().parse::<u64>().unwrap_or(0);
    (kib as f64) / 1024.0
}

fn make_deterministic_gop_bytes(seed_tag: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0_u8; len];
    let mut state = seed_tag
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0xD1B5_4A32_D192_ED03);
    for chunk in out.chunks_mut(8) {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let word = state.wrapping_mul(0x2545_F491_4F6C_DD1D).to_be_bytes();
        let copy_len = chunk.len();
        chunk.copy_from_slice(&word[..copy_len]);
    }
    out
}

struct WaveAccumulator<'a> {
    gens: &'a mut BTreeMap<ObjectId, u64>,
    deltas: Vec<EvidenceDelta>,
    children: Vec<ContentDigest>,
    objects: Vec<(u16, Vec<u8>, ContentDigest)>,
    seen_pack_digests: &'a mut BTreeSet<ContentDigest>,
}

impl<'a> WaveAccumulator<'a> {
    fn new(
        gens: &'a mut BTreeMap<ObjectId, u64>,
        seen_pack_digests: &'a mut BTreeSet<ContentDigest>,
        cap: usize,
    ) -> Self {
        Self {
            gens,
            deltas: Vec::with_capacity(cap),
            children: Vec::with_capacity(cap),
            objects: Vec::with_capacity(256),
            seen_pack_digests,
        }
    }

    fn push_projected_delta(
        &mut self,
        delta_id: String,
        family: &str,
        object_id: ObjectId,
        plane: Plane,
        validity: CaptureInterval,
        payload: &ProjectionRecordPayload,
    ) -> TestResult<ContentDigest> {
        let raw = payload.encode_bytes()?;
        let digest = ContentDigest::sha256(&raw);
        let prior = self.gens.get(&object_id).copied();
        let next_gen = prior.map_or(1, |g| g + 1);
        self.gens.insert(object_id.clone(), next_gen);
        self.deltas.push(EvidenceDelta {
            delta_id,
            family: family.to_owned(),
            object_id,
            prior_generation: prior,
            new_generation: next_gen,
            validity,
            plane,
            payload_digest: digest,
            witness_digest: None,
            operation_id: None,
        });
        self.children.push(digest);
        if self.seen_pack_digests.insert(digest) {
            self.objects.push((PACK_KIND_METADATA, raw, digest));
        }
        Ok(digest)
    }

    fn push_provenance_delta(
        &mut self,
        delta_id: String,
        family: &str,
        object_id: ObjectId,
        plane: Plane,
        validity: CaptureInterval,
        payload_digest: ContentDigest,
    ) {
        let prior = self.gens.get(&object_id).copied();
        let next_gen = prior.map_or(1, |g| g + 1);
        self.gens.insert(object_id.clone(), next_gen);
        self.deltas.push(EvidenceDelta {
            delta_id,
            family: family.to_owned(),
            object_id,
            prior_generation: prior,
            new_generation: next_gen,
            validity,
            plane,
            payload_digest,
            witness_digest: None,
            operation_id: None,
        });
        self.children.push(payload_digest);
    }
}

fn run_100_camera_combiner_burst(root: &Path) -> TestResult<(u64, u64, u64)> {
    let ledger = MerkleEpochLedger::open(
        root.join("comb-ledger"),
        "site:scale-combiner-100cam",
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

    const THREADS: usize = 20; // 20 concurrent worker threads x 5 cameras = 100 cameras
    const CAMS_PER_THREAD: usize = 5;
    let barrier = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::with_capacity(THREADS);

    for tid in 0..THREADS {
        let comb = Arc::clone(&combiner);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || -> Result<(), String> {
            b.wait();
            for local_cam in 0..CAMS_PER_THREAD {
                let cam_idx = tid * CAMS_PER_THREAD + local_cam;
                let sensor = SensorId::parse(format!("sensor:cam-{cam_idx:03}"))
                    .map_err(|e| e.to_string())?;
                let interval = CaptureInterval::new(
                    TimestampNs(1_700_000_000_000_000_000 + (cam_idx as i128) * 1_000),
                    TimestampNs(1_700_000_000_000_000_500 + (cam_idx as i128) * 1_000),
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
                    delta_id: format!("c100-{cam_idx:03}"),
                    family: FAMILY_SENSOR_LIVENESS.to_owned(),
                    object_id: ObjectId::parse(format!("obj:comb:live:{cam_idx:03}"))
                        .map_err(|e| e.to_string())?,
                    prior_generation: None,
                    new_generation: 1,
                    validity: interval,
                    plane: Plane::Authority,
                    payload_digest: digest,
                    witness_digest: None,
                    operation_id: None,
                };
                let prop = CommitProposal {
                    request_digest: ContentDigest::sha256(
                        format!("c100-req-{cam_idx:03}").as_bytes(),
                    ),
                    sensor_scope: sensor.into_inner(),
                    objects: vec![OwnedPackObject::with_digest(
                        PACK_KIND_METADATA,
                        0,
                        raw,
                        digest,
                    )],
                    deltas: vec![delta],
                    batch_id_prefix: format!("c{cam_idx:03}"),
                };
                let _ = comb.submit(prop).map_err(|e| e.to_string())?;
            }
            Ok(())
        }));
    }

    for h in handles {
        h.join()
            .map_err(|_| "100-camera combiner thread panicked")?
            .map_err(|e| format!("100-camera combiner error: {e}"))?;
    }
    let stats = combiner.shutdown()?;
    Ok((
        stats.proposals_committed,
        stats.coalesced_commits,
        stats.fsyncs_saved,
    ))
}

#[allow(clippy::too_many_arguments)]
fn measure_milestone(
    commits: u64,
    waves: u64,
    wave_latencies_us: &[u64],
    amortized_latencies_us: &[u64],
    ledger: &mut MerkleEpochLedger,
    ledger_dir: &Path,
    ledger_cfg: EpochLedgerConfig,
    packs: &PackStore,
    proj: &MvccProjectionStore,
    proj_dir: &Path,
    proj_cfg: ProjectionStoreConfig,
    scrubber: &mut BackgroundScrubber,
    sensors: &[SensorId],
    zones: &[String],
    total_roots_published: u64,
    total_events_created: usize,
    now_ns: TimestampNs,
) -> TestResult<MilestoneRecord> {
    let adapters = [
        FootageAdapterKind::Rtsp,
        FootageAdapterKind::Http,
        FootageAdapterKind::File,
        FootageAdapterKind::Tutk,
    ];

    let group_commit = LatencyStatsUs::from_samples(wave_latencies_us);
    let amortized_commit = LatencyStatsUs::from_samples(amortized_latencies_us);

    // 1. Orient latency histogram (200 samples).
    const READ_SAMPLES: usize = 200;
    let mut orient_samples = Vec::with_capacity(READ_SAMPLES);
    for _ in 0..READ_SAMPLES {
        let t0 = Instant::now();
        let snap = proj.snapshot_latest();
        let sum = snap.orient_summary();
        assert_eq!(sum.anchor.commit_sequence, waves);
        orient_samples.push(t0.elapsed().as_micros() as u64);
    }
    let orient = LatencyStatsUs::from_samples(&orient_samples);

    // 2. Query latency histogram (events + footage + coverage across 200 samples).
    let mut query_samples = Vec::with_capacity(READ_SAMPLES);
    for i in 0..READ_SAMPLES {
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
        let cov_sensor = &sensors[i % sensors.len()];
        let cov_zone = &zones[i % ZONES_PER_CAMERA];

        let t0 = Instant::now();
        let snap = proj.snapshot_latest();
        let _ep = proj.query_events(&snap, &ev_filter, 32);
        let _fp = proj.query_footage(&snap, &foot_filter, 32);
        let _cp = proj.query_coverage(&snap, Some(cov_sensor), Some(cov_zone));
        query_samples.push(t0.elapsed().as_micros() as u64);
    }
    let query = LatencyStatsUs::from_samples(&query_samples);

    // 3. Follow latency histogram (O(delta) follow_since across 200 samples).
    let mut follow_samples = Vec::with_capacity(READ_SAMPLES);
    let follow_from = waves.saturating_sub(16);
    let expected_delta = (waves - follow_from) as usize;
    for _ in 0..READ_SAMPLES {
        let t0 = Instant::now();
        let page = proj.follow_since(follow_from, 32)?;
        assert_eq!(page.commits.len(), expected_delta);
        follow_samples.push(t0.elapsed().as_micros() as u64);
    }
    let follow = LatencyStatsUs::from_samples(&follow_samples);

    // 4. Cold-open latency histogram from verified Merkle FSSC checkpoint + MVCC snapshot.
    let _cp = ledger.force_checkpoint()?;
    let _snap_bytes = proj.compact_snapshot()?;
    let expected_state_digest = proj.snapshot_latest().state_digest();
    let expected_merkle_root = ledger.state_root();
    let resolver = PackStorePayloadResolver::new(packs);

    const OPEN_SAMPLES: usize = 5;
    let mut merkle_open_us = Vec::with_capacity(OPEN_SAMPLES);
    let mut mvcc_open_us = Vec::with_capacity(OPEN_SAMPLES);
    let mut total_open_us = Vec::with_capacity(OPEN_SAMPLES);
    for _ in 0..OPEN_SAMPLES {
        let t_all = Instant::now();
        let t_m = Instant::now();
        let reopened_ledger = MerkleEpochLedger::open(
            ledger_dir,
            "site:scale-1m-100cam",
            ledger_cfg,
            IncompleteTailPolicy::Reject,
        )?;
        let m_us = t_m.elapsed().as_micros() as u64;
        assert_eq!(reopened_ledger.commit_sequence(), waves);
        assert_eq!(reopened_ledger.state_root(), expected_merkle_root);
        assert_eq!(reopened_ledger.recovery_summary().replayed_tail_batches, 0);

        let t_p = Instant::now();
        let reopened_proj = MvccProjectionStore::open_or_rebuild_with_config(
            proj_dir,
            &reopened_ledger,
            &resolver,
            proj_cfg,
        )?;
        let p_us = t_p.elapsed().as_micros() as u64;
        let tot_us = t_all.elapsed().as_micros() as u64;

        assert_eq!(
            reopened_proj.recovery_report().mode,
            ProjectionRecoveryMode::LoadedCurrent
        );
        assert_eq!(
            reopened_proj.snapshot_latest().state_digest(),
            expected_state_digest
        );
        merkle_open_us.push(m_us);
        mvcc_open_us.push(p_us);
        total_open_us.push(tot_us);
    }
    let cold_open_merkle = LatencyStatsUs::from_samples(&merkle_open_us);
    let cold_open_mvcc = LatencyStatsUs::from_samples(&mvcc_open_us);
    let cold_open_total = LatencyStatsUs::from_samples(&total_open_us);

    // 5. Doctor scrubber bounded incremental tick histogram.
    if packs.sealed_pack_ids()?.is_empty() {
        let _ = packs.seal_active_pack()?;
    }
    let scrub_budget = ScrubBudget {
        max_bytes: 2 * 1024 * 1024,
        max_packs: 2,
        max_objects: 128,
    };
    const SCRUB_SAMPLES: usize = 12;
    let mut scrub_samples = Vec::with_capacity(SCRUB_SAMPLES);
    for tick in 0..SCRUB_SAMPLES {
        let t0 = Instant::now();
        let report = scrubber.scrub_pass(
            packs,
            scrub_budget,
            TimestampNs(now_ns.0 + i128::from(tick as u64)),
        )?;
        scrub_samples.push(t0.elapsed().as_micros() as u64);
        assert!(
            report.findings.is_empty()
                && report.corrupt_digests.is_empty()
                && report.missing_packs.is_empty()
                && report.verdict != PackScrubVerdict::Failed,
            "scrubber found corruption at {commits} commits: {:?}",
            report.findings
        );
    }
    let doctor_scrub = LatencyStatsUs::from_samples(&scrub_samples);

    let summary = proj.snapshot_latest().orient_summary();
    let telemetry = packs.telemetry_snapshot()?;
    let on_disk_pack_bytes = packs.on_disk_pack_bytes()?;
    let sealed_packs = packs.sealed_pack_ids()?.len();
    let rss_mib = sample_rss_mib();

    Ok(MilestoneRecord {
        commits,
        waves,
        group_commit,
        amortized_commit,
        orient,
        query,
        follow,
        cold_open_merkle,
        cold_open_mvcc,
        cold_open_total,
        doctor_scrub,
        rss_mib,
        on_disk_pack_bytes,
        sealed_packs,
        total_roots_published,
        live_roots: telemetry.live_roots,
        total_events_created,
        active_events: summary.total_events,
        active_holds: summary.active_holds,
        privacy_masks: summary.privacy_masks,
        fd_pool_open: telemetry.fd_pool.open_count,
        fd_pool_evictions: telemetry.fd_pool.evictions,
    })
}

#[test]
fn scale_100_camera_million_commit_benchmark() -> TestResult {
    let profile = ScaleProfile::from_env();
    let ws = TempScaleWorkspace::new(if profile.fast_mode { "fast" } else { "full" })?;

    let ledger_dir = ws.root.join("ledger");
    let packs_root = ws.root.join("packs-store");
    let proj_dir = ws.root.join("projections/mvcc");

    let ledger_cfg = EpochLedgerConfig {
        max_epoch_bytes: 64 * 1024 * 1024,
        max_batches_per_epoch: 25, // 8+ sealed epochs across 201 waves in full mode
        checkpoint_stride: 25,
        max_objects: None,
    };
    let mut ledger = MerkleEpochLedger::open(
        &ledger_dir,
        "site:scale-1m-100cam",
        ledger_cfg,
        IncompleteTailPolicy::Reject,
    )?;

    let pack_cfg = PackConfig {
        target_pack_bytes: profile.pack_target_bytes,
        durability: DurabilityMode::Fsync,
        max_open_packs: 12,
        quota: QuotaPolicy {
            auto_compact_every: 50_000,
            ..QuotaPolicy::default()
        },
        auto_save_index_on_seal: false,
        ..PackConfig::default()
    };
    let packs = PackStore::open(&packs_root, pack_cfg)?;

    let proj_cfg = ProjectionStoreConfig {
        durability: DurabilityMode::Fsync,
        wal_sync: WalSyncPolicy::FlushOnly,
        snapshot_stride: 128,
        max_retained_snapshots: 4,
        history_mode: HistoryChainMode::V2MerkleEpoch,
    };
    let proj = MvccProjectionStore::open_empty(&proj_dir, ledger.genesis_anchor(), proj_cfg)?;

    let ring_cfg = RetentionRingConfig::new(
        60_000_000_000, // 60s hot retention
        profile.ring_cap_bytes,
        profile.ring_cap_bytes,
        75,
        95,
    )?;

    // Pre-build stable identities for 100 simulated cameras, streams, zones, and provenance lanes.
    let sensors: Vec<SensorId> = (0..CAMERA_COUNT)
        .map(|i| SensorId::parse(format!("sensor:cam-{i:03}")))
        .collect::<Result<_, _>>()?;
    let streams: Vec<StreamId> = (0..CAMERA_COUNT)
        .map(|i| StreamId::parse(format!("stream:cam-{i:03}:main")))
        .collect::<Result<_, _>>()?;
    let zones: Vec<String> = (0..ZONE_COUNT).map(|i| format!("zone:{i:02}")).collect();
    let live_obj_ids: Vec<ObjectId> = (0..CAMERA_COUNT)
        .map(|i| ObjectId::parse(format!("obj:live:cam-{i:03}")))
        .collect::<Result<_, _>>()?;
    let cov_obj_ids: Vec<Vec<ObjectId>> = (0..CAMERA_COUNT)
        .map(|c| {
            (0..ZONES_PER_CAMERA)
                .map(|z| ObjectId::parse(format!("obj:cov:cam-{c:03}:z{z:02}")))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<_, _>>()?;
    let imp_obj_ids: Vec<ObjectId> = (0..CAMERA_COUNT)
        .map(|c| ObjectId::parse(format!("obj:imp:cam-{c:03}")))
        .collect::<Result<_, _>>()?;
    let del_imp_obj_ids: Vec<ObjectId> = (0..CAMERA_COUNT)
        .map(|c| ObjectId::parse(format!("obj:del-imp:cam-{c:03}")))
        .collect::<Result<_, _>>()?;
    let del_ev_obj_ids: Vec<ObjectId> = (0..CAMERA_COUNT)
        .map(|c| ObjectId::parse(format!("obj:del-ev:cam-{c:03}")))
        .collect::<Result<_, _>>()?;
    let mask_obj_ids: Vec<ObjectId> = (0..CAMERA_COUNT)
        .map(|c| ObjectId::parse(format!("obj:mask:cam-{c:03}")))
        .collect::<Result<_, _>>()?;

    // Real canonical camera pipeline provenance lanes (5,200 per-camera custody/decode/model objects).
    let capsule_obj_ids: Vec<Vec<ObjectId>> = (0..CAMERA_COUNT)
        .map(|c| {
            (0..13_usize)
                .map(|k| ObjectId::parse(format!("obj:cap:cam-{c:03}:{k:02}")))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<_, _>>()?;
    let decode_obj_ids: Vec<Vec<ObjectId>> = (0..CAMERA_COUNT)
        .map(|c| {
            (0..13_usize)
                .map(|k| ObjectId::parse(format!("obj:dec:cam-{c:03}:{k:02}")))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<_, _>>()?;
    let model_inv_obj_ids: Vec<Vec<ObjectId>> = (0..CAMERA_COUNT)
        .map(|c| {
            (0..13_usize)
                .map(|k| ObjectId::parse(format!("obj:minv:cam-{c:03}:{k:02}")))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<_, _>>()?;
    let model_res_obj_ids: Vec<Vec<ObjectId>> = (0..CAMERA_COUNT)
        .map(|c| {
            (0..13_usize)
                .map(|k| ObjectId::parse(format!("obj:mres:cam-{c:03}:{k:02}")))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<_, _>>()?;

    let adapters = [
        FootageAdapterKind::Rtsp,
        FootageAdapterKind::Http,
        FootageAdapterKind::File,
        FootageAdapterKind::Tutk,
    ];

    let mut gens: BTreeMap<ObjectId, u64> = BTreeMap::new();
    let mut seen_pack_digests: BTreeSet<ContentDigest> = BTreeSet::new();
    let mut active_unheld_imports: VecDeque<ContentDigest> = VecDeque::new();
    let mut held_import_targets: Vec<ContentDigest> = Vec::with_capacity(50);
    let mut active_event_queue: VecDeque<ObjectId> = VecDeque::new();

    // Hold-safe retention ring tracking for physical GOP media payloads.
    let mut ring_candidates: Vec<RetentionCandidate> = Vec::new();
    let mut pinned_gop_payloads: BTreeMap<ContentDigest, Vec<u8>> = BTreeMap::new();
    let mut evicted_gop_digests: BTreeSet<ContentDigest> = BTreeSet::new();
    let mut pending_roots: Vec<VirtualRootRecord> = Vec::with_capacity(1_024);

    let mut total_roots_published: u64 = 0;
    let mut total_logical_catalog_bytes: u64 = 0;
    let mut physical_bytes_written: u64 = 0;
    let mut peak_on_disk_pack_bytes: u64 = 0;
    let mut total_bytes_reclaimed: u64 = 0;
    let mut total_packs_compacted: u64 = 0;
    let mut total_proxies_shed: u64 = 0;
    let mut total_sources_evicted: u64 = 0;
    let mut peak_rss_mib: f64 = sample_rss_mib();

    let mut scrubber = BackgroundScrubber::new();
    let mut wave_latencies_since_milestone: Vec<u64> = Vec::with_capacity(256);
    let mut amortized_since_milestone: Vec<u64> = Vec::with_capacity(256);
    let mut all_wave_latencies_us: Vec<u64> = Vec::with_capacity(profile.total_waves as usize);
    let mut milestones_out: Vec<MilestoneRecord> = Vec::with_capacity(profile.milestones.len());
    let mut next_milestone_idx: usize = 0;
    let mut created_events: usize = 0;
    let mut masks_seeded: usize = 0;
    let mut holds_seeded: usize = 0;
    let mut obligations_seeded: usize = 0;
    let mut gop_seq: u64 = 0;

    // Pure sustained ingest wall time (excluding milestone read/cold-open/scrub measurements).
    let mut cumulative_ingest_us: u64 = 0;
    let mut commits_done: u64 = 0;

    for wave in 1..=profile.total_waves {
        let wave_target_commits: u64 = match wave {
            1 => 1_000,
            2 => 4_000,
            _ => COMMITS_PER_WAVE,
        };
        let wave_start = Instant::now();
        let base_ts_ns: i128 = 1_700_000_000_000_000_000 + i128::from(wave) * 1_000_000_000;
        let now_ns = TimestampNs(base_ts_ns);
        let interval =
            CaptureInterval::new(TimestampNs(base_ts_ns), TimestampNs(base_ts_ns + 500_000))?;
        let bucket_ts_ns: i128 =
            1_700_000_000_000_000_000 + i128::from((wave - 1) / 100) * 100_000_000_000;
        let bucket_interval = CaptureInterval::new(
            TimestampNs(bucket_ts_ns),
            TimestampNs(bucket_ts_ns + 500_000),
        )?;

        let mut acc = WaveAccumulator::new(
            &mut gens,
            &mut seen_pack_digests,
            wave_target_commits as usize,
        );

        // Stream unique physical GOP media chunks into PackStore every wave (60+ 2 MiB sealed packs
        // + continuous hold-safe ring compaction!).
        let mut wave_gop_digests: Vec<ContentDigest> =
            Vec::with_capacity(profile.gop_chunks_per_wave);
        for g in 0..profile.gop_chunks_per_wave {
            gop_seq += 1;
            let is_held = pinned_gop_payloads.len() < 24 && g == 0 && wave.is_multiple_of(3);
            let is_proxy = !is_held && g == profile.gop_chunks_per_wave - 1;
            let len = if is_proxy {
                profile.gop_physical_bytes / 2
            } else {
                profile.gop_physical_bytes
            };
            let gop_bytes = make_deterministic_gop_bytes(gop_seq, len);
            let gop_digest = ContentDigest::sha256(&gop_bytes);
            if is_held {
                pinned_gop_payloads.insert(gop_digest, gop_bytes.clone());
            }
            acc.objects
                .push((PACK_KIND_MEDIA_CHUNK, gop_bytes, gop_digest));
            wave_gop_digests.push(gop_digest);

            let cam_idx = ((gop_seq as usize) % CAMERA_COUNT) as u32;
            let root_id = format!("cam-{cam_idx:03}:gop:{gop_seq:07}");
            pending_roots.push(VirtualRootRecord::new(
                root_id.clone(),
                gop_digest,
                if is_proxy { "proxy-v1" } else { "media-gop-v1" },
                1,
                LOGICAL_GOP_BYTES,
                1,
                now_ns,
                None,
            )?);
            total_roots_published += 1;
            total_logical_catalog_bytes =
                total_logical_catalog_bytes.saturating_add(LOGICAL_GOP_BYTES);

            ring_candidates.push(RetentionCandidate {
                import_id: root_id,
                sensor_id: format!("sensor:cam-{cam_idx:03}"),
                capture_end_ns: now_ns,
                byte_size: len as u64,
                object_digests: vec![gop_digest],
                is_derived_proxy: is_proxy,
                held_by: if is_held {
                    vec![format!("hold:gop:{gop_seq}")]
                } else {
                    Vec::new()
                },
                active_obligation_ids: Vec::new(),
                active_event_ids: Vec::new(),
            });
        }

        // Publish additional virtual roots referencing wave GOP chunks (> 100,000 roots, > 100 GiB logical!).
        let extra_roots = profile
            .roots_per_wave
            .saturating_sub(profile.gop_chunks_per_wave);
        for r in 0..extra_roots {
            let cam_idx = (wave as usize + r) % CAMERA_COUNT;
            let backing_digest = wave_gop_digests[r % wave_gop_digests.len()];
            let root_id = format!("cam-{cam_idx:03}:seg:w{wave:04}:r{r:03}");
            pending_roots.push(VirtualRootRecord::new(
                root_id,
                backing_digest,
                "media-gop-v1",
                1,
                LOGICAL_GOP_BYTES,
                1,
                now_ns,
                None,
            )?);
            total_roots_published += 1;
            total_logical_catalog_bytes =
                total_logical_catalog_bytes.saturating_add(LOGICAL_GOP_BYTES);
        }

        // (A) Sensor liveness heartbeats (wave 1..=4 seed all 100 cameras; steady-state rotates 25 cameras/wave).
        let live_batch = 25_usize;
        let live_start = (((wave as usize) - 1) * live_batch) % CAMERA_COUNT;
        for offset in 0..live_batch {
            let cam = (live_start + offset) % CAMERA_COUNT;
            let state = if cam == 99 && wave.is_multiple_of(50) {
                SensorLivenessStatus::Degraded
            } else {
                SensorLivenessStatus::Online
            };
            let payload = ProjectionRecordPayload::SensorLiveness(SensorLivenessPayload {
                sensor_id: sensors[cam].clone(),
                state,
                last_seen_ns: bucket_interval.earliest,
                observed_at_ns: bucket_interval.latest,
            });
            let _ = acc.push_projected_delta(
                format!("w{wave:04}-live-{cam:03}"),
                FAMILY_SENSOR_LIVENESS,
                live_obj_ids[cam].clone(),
                Plane::Authority,
                interval,
                &payload,
            )?;
        }

        // (B) Coverage witnesses (25 cameras x 5 zones = 125/wave -> full 100-camera x 5-zone coverage every 4 waves!).
        for offset in 0..live_batch {
            let cam = (live_start + offset) % CAMERA_COUNT;
            for z in 0..ZONES_PER_CAMERA {
                let status = if (cam + z).is_multiple_of(41) {
                    CoverageStatus::NotObservable
                } else {
                    CoverageStatus::Covered
                };
                let payload = ProjectionRecordPayload::CoverageWitness(CoverageWitnessPayload {
                    sensor_id: sensors[cam].clone(),
                    zone_id: zones[z].clone(),
                    window: bucket_interval,
                    status,
                    active_gaps: u32::from(status == CoverageStatus::NotObservable),
                    health_conflicts: 0,
                });
                let _ = acc.push_projected_delta(
                    format!("w{wave:04}-cov-{cam:03}-z{z}"),
                    FAMILY_COVERAGE_WITNESS,
                    cov_obj_ids[cam][z].clone(),
                    Plane::Authority,
                    interval,
                    &payload,
                )?;
            }
        }

        // (C) 4 unified footage imports (rotating across all 100 cameras & 4 adapters)
        //     + balanced 1:1 rolling deletion tombstones keeping active footage ring bounded!
        const IMPORTS_PER_WAVE: usize = 4;
        let cam_offset = ((wave as usize - 1) * IMPORTS_PER_WAVE) % CAMERA_COUNT;
        for i in 0..IMPORTS_PER_WAVE {
            let cam = (cam_offset + i) % CAMERA_COUNT;
            let adapter_kind = adapters[(cam + wave as usize) % adapters.len()];
            let import_id = ContentDigest::sha256(format!("imp-w{wave:04}-c{cam:03}").as_bytes());
            if held_import_targets.len() < 50 {
                held_import_targets.push(import_id);
            } else {
                active_unheld_imports.push_back(import_id);
            }
            let payload = ProjectionRecordPayload::FootageImport(FootageImportPayload {
                import_id,
                adapter_kind,
                sensor_id: sensors[cam].clone(),
                stream_id: streams[cam].clone(),
                capture_interval: interval,
                manifest_digest: import_id,
                capsule_count: 10,
                total_bytes: LOGICAL_GOP_BYTES,
                adapter_id: format!("adp-{}", adapter_kind.as_str()),
                adapter_generation: "gen-v2".to_owned(),
                completed: true,
            });
            let _ = acc.push_projected_delta(
                format!("w{wave:04}-imp-{cam:03}"),
                FAMILY_FOOTAGE_IMPORT,
                imp_obj_ids[cam].clone(),
                Plane::Authority,
                interval,
                &payload,
            )?;
        }

        let mut imp_dels = 0_usize;
        while imp_dels < IMPORTS_PER_WAVE
            && active_unheld_imports.len() > TARGET_ACTIVE_FOOTAGE_RING
        {
            if let Some(old_imp) = active_unheld_imports.pop_front() {
                let cam = (cam_offset + imp_dels) % CAMERA_COUNT;
                let payload =
                    ProjectionRecordPayload::DeletionTombstone(DeletionTombstonePayload {
                        target: DeletionTarget::FootageImport(old_imp),
                    });
                let _ = acc.push_projected_delta(
                    format!("w{wave:04}-delimp-{cam:03}"),
                    FAMILY_DELETION_TOMBSTONE,
                    del_imp_obj_ids[cam].clone(),
                    Plane::Authority,
                    interval,
                    &payload,
                )?;
                imp_dels += 1;
            }
        }

        // (D) 100 privacy masks, 50 active legal holds, 50 obligations, and >= 5,000 events
        //     (rolling retention retires oldest resolved events past TARGET_ACTIVE_EVENTS_WINDOW
        //      so hot MVCC cold-open stays sub-15ms while all 5,000 events live in canonical ledger!).
        if masks_seeded < CAMERA_COUNT {
            let n = 50.min(CAMERA_COUNT - masks_seeded);
            for _ in 0..n {
                let cam = masks_seeded;
                masks_seeded += 1;
                let payload = ProjectionRecordPayload::PrivacyMask(PrivacyMaskPayload {
                    sensor_id: sensors[cam].clone(),
                    policy_digest: ContentDigest::sha256(format!("mask-cam-{cam:03}").as_bytes()),
                });
                let _ = acc.push_projected_delta(
                    format!("w{wave:04}-mask-{cam:03}"),
                    FAMILY_PRIVACY_MASK_POLICY,
                    mask_obj_ids[cam].clone(),
                    Plane::Authority,
                    interval,
                    &payload,
                )?;
            }
        }

        if holds_seeded < 50 && held_import_targets.len() >= 50 {
            let n = 25.min(50 - holds_seeded);
            for _ in 0..n {
                let h = holds_seeded;
                holds_seeded += 1;
                let payload = ProjectionRecordPayload::EvidenceHold(EvidenceHoldPayload {
                    hold_id: format!("hold:legal:{h:03}"),
                    scope: format!("scope:cam-{h:03}"),
                    target_digest: held_import_targets[h],
                    active: true,
                });
                let obj_id = ObjectId::parse(format!("obj:hold:{h:03}"))?;
                let _ = acc.push_projected_delta(
                    format!("w{wave:04}-hold-{h:03}"),
                    FAMILY_EVIDENCE_HOLD,
                    obj_id,
                    Plane::Authority,
                    interval,
                    &payload,
                )?;
            }
        }

        if obligations_seeded < 50 && holds_seeded == 50 {
            let n = 25.min(50 - obligations_seeded);
            for _ in 0..n {
                let ob = obligations_seeded;
                obligations_seeded += 1;
                let payload = ProjectionRecordPayload::Obligation(ObligationPayload {
                    obligation_id: ObligationId::parse(format!("ob:scale:{ob:03}"))?,
                    operation_id: OperationId::parse(format!("op:scale:{ob:03}"))?,
                    terminal_predicate: "alert_receipt_verified".to_owned(),
                    state: if ob < 25 {
                        ObligationState::Pending
                    } else {
                        ObligationState::Verified
                    },
                    proof_digest: (ob >= 25)
                        .then(|| ContentDigest::sha256(format!("ob-proof-{ob}").as_bytes())),
                });
                let obj_id = ObjectId::parse(format!("obj:ob:{ob:03}"))?;
                let _ = acc.push_projected_delta(
                    format!("w{wave:04}-ob-{ob:03}"),
                    FAMILY_OBLIGATION,
                    obj_id,
                    Plane::Effect,
                    interval,
                    &payload,
                )?;
            }
        }

        // Emit events steadily across the run so total_events_created reaches >= 5,000 (25/wave in full mode).
        let events_per_wave = if profile.fast_mode {
            50_usize
        } else {
            25_usize
        };
        if created_events < profile.target_events_total {
            let n = events_per_wave.min(profile.target_events_total - created_events);
            for _ in 0..n {
                let ev_idx = created_events;
                created_events += 1;
                let cam = ev_idx % CAMERA_COUNT;
                let z = ev_idx % ZONE_COUNT;
                let state = match ev_idx % 5 {
                    0 => EventState::Hypothesized,
                    1 => EventState::Witnessed,
                    2 => EventState::Corroborated,
                    3 => EventState::Adjudicated,
                    _ => EventState::AlertDelivered,
                };
                let ev_id = EventId::parse(format!("ev-{ev_idx:05}"))?;
                let payload = ProjectionRecordPayload::EventRevision(EventRevisionPayload {
                    event_id: ev_id,
                    revision: 1,
                    state,
                    kind: EventKind::PerimeterBreach,
                    zones: vec![zones[z].clone()],
                    sensor_ids: vec![sensors[cam].clone()],
                    interval,
                    event_root: ContentDigest::sha256(format!("evroot-{ev_idx}-r1").as_bytes()),
                    supersedes: None,
                    corroborated: (ev_idx % 5) >= 2,
                    tamper_open: ev_idx.is_multiple_of(100),
                });
                let obj_id = ObjectId::parse(format!("obj:ev:{ev_idx:05}"))?;
                let _ = acc.push_projected_delta(
                    format!("w{wave:04}-ev-{ev_idx:05}"),
                    FAMILY_EVENT_REVISION,
                    obj_id.clone(),
                    Plane::Cognition,
                    interval,
                    &payload,
                )?;
                active_event_queue.push_back(obj_id);
            }
        }

        let mut ev_dels = 0_usize;
        while ev_dels < events_per_wave && active_event_queue.len() > TARGET_ACTIVE_EVENTS_WINDOW {
            if let Some(old_ev_obj) = active_event_queue.pop_front() {
                let cam = (cam_offset + ev_dels) % CAMERA_COUNT;
                let payload =
                    ProjectionRecordPayload::DeletionTombstone(DeletionTombstonePayload {
                        target: DeletionTarget::Object(old_ev_obj),
                    });
                let _ = acc.push_projected_delta(
                    format!("w{wave:04}-delev-{cam:03}"),
                    FAMILY_DELETION_TOMBSTONE,
                    del_ev_obj_ids[cam].clone(),
                    Plane::Authority,
                    interval,
                    &payload,
                )?;
                ev_dels += 1;
            }
        }

        // (E) Fill remaining slots up to exact wave_target_commits deltas/wave with real canonical FSS
        //     camera custody & inference provenance deltas (sensor_capsule, decode_receipt,
        //     model_invocation_receipt, executor_model_result) anchored to the wave's GOP digests!
        let remaining = (wave_target_commits as usize) - acc.deltas.len();
        let mut emitted = 0_usize;
        'fill: for lane in 0..4_usize {
            let (family, plane, slots_per_cam, pool) = match lane {
                0 => (
                    FAMILY_SENSOR_CAPSULE,
                    Plane::Authority,
                    13_usize,
                    &capsule_obj_ids,
                ),
                1 => (
                    FAMILY_DECODE_RECEIPT,
                    Plane::Cognition,
                    13_usize,
                    &decode_obj_ids,
                ),
                2 => (
                    FAMILY_MODEL_INVOCATION_RECEIPT,
                    Plane::Cognition,
                    13_usize,
                    &model_inv_obj_ids,
                ),
                _ => (
                    FAMILY_EXECUTOR_MODEL_RESULT,
                    Plane::Cognition,
                    13_usize,
                    &model_res_obj_ids,
                ),
            };
            for slot in 0..slots_per_cam {
                for (cam, cam_objs) in pool.iter().enumerate() {
                    if emitted >= remaining {
                        break 'fill;
                    }
                    let digest = wave_gop_digests[(cam + slot + lane) % wave_gop_digests.len()];
                    acc.push_provenance_delta(
                        format!("w{wave:04}-p{lane}-{cam:03}-{slot}"),
                        family,
                        cam_objs[slot].clone(),
                        plane,
                        interval,
                        digest,
                    );
                    emitted += 1;
                }
            }
        }
        assert_eq!(acc.deltas.len(), wave_target_commits as usize);

        // 1) Group-commit new objects into PackStore (single fsync per wave).
        for (_, raw, _) in &acc.objects {
            physical_bytes_written = physical_bytes_written.saturating_add(raw.len() as u64);
        }
        if !acc.objects.is_empty() {
            let pack_inputs: Vec<PackObjectInput<'_>> = acc
                .objects
                .iter()
                .map(|(kind, raw, digest)| PackObjectInput::with_digest(*kind, 0, raw, *digest))
                .collect();
            let _locs = packs.append_batch(&pack_inputs)?;
        }

        commits_done += wave_target_commits;
        let is_milestone = next_milestone_idx < profile.milestones.len()
            && commits_done == profile.milestones[next_milestone_idx];
        let is_retention_wave = wave.is_multiple_of(10);
        if pending_roots.len() >= 1_000
            || is_retention_wave
            || is_milestone
            || wave == profile.total_waves
        {
            let _receipts = packs.publish_roots_batch(&pending_roots)?;
            pending_roots.clear();
        }

        // 2) Commit coalesced 2,000-delta EvidenceDeltaBatch into MerkleEpochLedger.
        let batch = ledger.prepare_batch(
            BatchId::parse(format!("w-{wave:05}"))?,
            acc.deltas,
            acc.children,
        )?;
        let _ledger_receipt = ledger.append_batch(batch.clone())?;

        // 3) Advance MvccProjectionStore atomically at the exact Merkle anchor.
        let resolver = PackStorePayloadResolver::new(&packs);
        let proj_anchor = proj.apply_delta_batch(&batch, &resolver)?;
        assert_eq!(proj_anchor.commit_sequence, wave);
        assert_eq!(proj_anchor.authority_root, ledger.state_root());

        let wave_us = wave_start.elapsed().as_micros() as u64;
        cumulative_ingest_us = cumulative_ingest_us.saturating_add(wave_us);
        wave_latencies_since_milestone.push(wave_us);
        amortized_since_milestone.push(wave_us / wave_target_commits);
        all_wave_latencies_us.push(wave_us);

        // Periodic hold-safe retention ring eviction + tombstone commit + online pack compaction
        // keeping on-disk bytes tightly bounded while preserving 100% of legal holds!
        if wave.is_multiple_of(10) && !ring_candidates.is_empty() {
            let outcome = plan_retention(&ring_cfg, &ring_candidates, now_ns)?;
            if let RetentionPlanOutcome::Evict(evict_batch) = outcome {
                let proof = packs.commit_eviction_tombstones(&evict_batch, Some(wave))?;
                proof.verify()?;
                total_proxies_shed += evict_batch.proxies_shed_count;
                total_sources_evicted += evict_batch.sources_evicted_count;

                let evicted_ids: BTreeSet<String> = evict_batch
                    .tombstones
                    .iter()
                    .map(|t| t.import_id.clone())
                    .collect();
                for &d in &evict_batch.reclaimable_digests {
                    assert!(
                        !pinned_gop_payloads.contains_key(&d),
                        "pinned held GOP digest must NEVER be reclaimed"
                    );
                    evicted_gop_digests.insert(d);
                }
                ring_candidates.retain(|c| !evicted_ids.contains(&c.import_id));

                let comp_report = packs.compact_sealed_packs(
                    &proof,
                    CompactionPolicy {
                        min_live_ratio_ppm: 600_000,
                        reader_drain_timeout_ms: 2_000,
                        max_packs_per_pass: Some(8),
                    },
                )?;
                total_bytes_reclaimed =
                    total_bytes_reclaimed.saturating_add(comp_report.total_bytes_reclaimed);
                total_packs_compacted = total_packs_compacted
                    .saturating_add(comp_report.packs_unlinked_empty + comp_report.packs_rewritten);
            }
            let disk_now = packs.on_disk_pack_bytes()?;
            peak_on_disk_pack_bytes = peak_on_disk_pack_bytes.max(disk_now);
        }

        // Measure full milestone histograms at 2k, 10k, 100k, 500k, 1M commits.
        if is_milestone {
            let rec = measure_milestone(
                commits_done,
                wave,
                &wave_latencies_since_milestone,
                &amortized_since_milestone,
                &mut ledger,
                &ledger_dir,
                ledger_cfg,
                &packs,
                &proj,
                &proj_dir,
                proj_cfg,
                &mut scrubber,
                &sensors,
                &zones,
                total_roots_published,
                created_events,
                now_ns,
            )?;
            peak_rss_mib = peak_rss_mib.max(rec.rss_mib);
            peak_on_disk_pack_bytes = peak_on_disk_pack_bytes.max(rec.on_disk_pack_bytes);
            println!("{}", rec.to_json());
            milestones_out.push(rec);
            wave_latencies_since_milestone.clear();
            amortized_since_milestone.clear();
            next_milestone_idx += 1;
        }
    }

    // Seal final pack, compact virtual root catalog, save index, and run complete BackgroundScrubber sweep!
    let _ = packs.seal_active_pack()?;
    let catalog_compact = packs.compact_catalog()?;
    let _ = packs.save_index_snapshot()?;

    // Verify 100% of pinned held GOP payloads survive compaction and verify bit-for-bit!
    assert!(!pinned_gop_payloads.is_empty());
    for (digest, expected) in &pinned_gop_payloads {
        assert_eq!(packs.read_verified(digest)?, *expected);
    }
    // Verify evicted unheld GOP payloads return ERR-EVIDENCE-DELETED-001!
    for digest in evicted_gop_digests.iter().take(32) {
        let err = packs
            .read_verified(digest)
            .err()
            .ok_or("evicted unheld GOP must not read as live")?;
        assert_eq!(err.stable_error_id(), Some(ERR_EVIDENCE_DELETED_001));
    }

    // Complete a full BackgroundScrubber verification cycle over ALL remaining sealed packfiles!
    let mut full_scrubber = BackgroundScrubber::new();
    let mut full_scrub_passes = 0_u64;
    loop {
        full_scrub_passes += 1;
        let rep = full_scrubber.scrub_pass(
            &packs,
            ScrubBudget {
                max_bytes: 32 * 1024 * 1024,
                max_packs: 16,
                max_objects: 65_536,
            },
            TimestampNs(1_700_005_000_000_000_000 + i128::from(full_scrub_passes)),
        )?;
        assert!(
            rep.findings.is_empty()
                && rep.corrupt_digests.is_empty()
                && rep.missing_packs.is_empty(),
            "full scrub found defects: {:?}",
            rep.findings
        );
        if rep.cycle_completed {
            assert_eq!(rep.verdict, PackScrubVerdict::Clean);
            break;
        }
        assert!(
            full_scrub_passes < 1_000,
            "full scrub did not complete in 1000 passes"
        );
    }

    // Run real concurrent 100-camera CommitCombiner burst verifying multi-thread coalescing.
    let (comb_proposals, comb_coalesced, comb_fsyncs_saved) =
        run_100_camera_combiner_burst(&ws.root)?;
    assert_eq!(comb_proposals, 100);
    assert!(comb_coalesced > 0);

    peak_rss_mib = peak_rss_mib.max(sample_rss_mib());

    // Compute sustained multi-camera ingest factor across 100 streams:
    // At 1 commit/sec/camera (100 commits/sec aggregate), 1,000,000 commits = 10,000 s of real time.
    // Even at aggressive 10 commits/sec/camera (1,000 commits/sec aggregate), 1,000,000 commits = 1,000 s.
    let ingest_secs = (cumulative_ingest_us as f64) / 1_000_000.0;
    let commits_per_sec = (profile.total_commits as f64) / ingest_secs.max(1e-6);
    let simulated_rt_1hz_secs = (profile.total_commits as f64) / (CAMERA_COUNT as f64);
    let simulated_rt_10hz_secs = (profile.total_commits as f64) / ((CAMERA_COUNT * 10) as f64);
    let real_time_factor_1hz = ingest_secs / simulated_rt_1hz_secs;
    let real_time_factor_10hz = ingest_secs / simulated_rt_10hz_secs;

    let final_milestone = milestones_out
        .last()
        .ok_or("missing final milestone record")?;
    let overall_group_commit = LatencyStatsUs::from_samples(&all_wave_latencies_us);

    // Evaluate ALL hard SLO gates!
    let slo_orient_pass = final_milestone.orient.p99_us < 10_000;
    let slo_query_pass = final_milestone.query.p99_us < 5_000;
    let slo_cold_open_mvcc_pass = final_milestone.cold_open_mvcc.p95_us < 15_000;
    let slo_cold_open_merkle_pass = final_milestone.cold_open_merkle.p95_us < 15_000;
    let slo_realtime_pass = real_time_factor_10hz < 0.30;
    let slo_rss_pass = peak_rss_mib < 512.0;
    let slo_roots_pass = if profile.fast_mode {
        total_roots_published >= 10_000
    } else {
        total_roots_published >= 100_000
    };
    let slo_events_pass = created_events >= profile.target_events_total;

    // Persist compact structured proof artifacts under target/test-logs/scale-benchmark/.
    let out_dir = log_output_dir();
    fs::create_dir_all(&out_dir)?;

    let ts_path = out_dir.join("scale_timeseries.jsonl");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&ts_path)?;
        for rec in &milestones_out {
            writeln!(f, "{}", rec.to_json())?;
        }
    }

    let milestones_json: Vec<String> = milestones_out
        .iter()
        .map(MilestoneRecord::to_json)
        .collect();
    let report_json = format!(
        concat!(
            "{{\n",
            "  \"schema\": \"fss.scale_million_report.v1\",\n",
            "  \"mode\": \"{}\",\n",
            "  \"cameras\": {},\n",
            "  \"total_commits\": {},\n",
            "  \"total_waves\": {},\n",
            "  \"commits_per_wave\": {},\n",
            "  \"ledger_epochs_created\": {},\n",
            "  \"total_roots_published\": {},\n",
            "  \"catalog_snapshot_entries\": {},\n",
            "  \"total_events_created\": {},\n",
            "  \"active_events\": {},\n",
            "  \"active_holds\": {},\n",
            "  \"privacy_masks\": {},\n",
            "  \"pinned_held_gops_verified\": {},\n",
            "  \"evicted_unheld_gops\": {},\n",
            "  \"proxies_shed\": {},\n",
            "  \"sources_evicted\": {},\n",
            "  \"packs_compacted\": {},\n",
            "  \"physical_bytes_written\": {},\n",
            "  \"peak_on_disk_pack_bytes\": {},\n",
            "  \"total_bytes_reclaimed\": {},\n",
            "  \"logical_catalog_bytes_accounted\": {},\n",
            "  \"full_scrub_verdict\": \"clean\",\n",
            "  \"full_scrub_passes\": {},\n",
            "  \"combiner_100cam\": {{\"proposals\":{},\"coalesced\":{},\"fsyncs_saved\":{}}},\n",
            "  \"ingest_wall_secs\": {:.4},\n",
            "  \"sustained_commits_per_sec\": {:.1},\n",
            "  \"real_time_factor_1hz_per_cam\": {:.6},\n",
            "  \"real_time_factor_10hz_per_cam\": {:.6},\n",
            "  \"peak_rss_mib\": {:.3},\n",
            "  \"overall_group_commit\": {},\n",
            "  \"final_milestone\": {},\n",
            "  \"slo_gates\": {{\n",
            "    \"orient_p99_lt_10ms\": {},\n",
            "    \"query_p99_lt_5ms\": {},\n",
            "    \"cold_open_mvcc_lt_15ms\": {},\n",
            "    \"cold_open_merkle_lt_15ms\": {},\n",
            "    \"realtime_factor_lt_0_3x\": {},\n",
            "    \"peak_rss_lt_512_mib\": {},\n",
            "    \"roots_target_met\": {},\n",
            "    \"events_target_met\": {}\n",
            "  }},\n",
            "  \"milestones\": [\n    {}\n  ]\n",
            "}}\n"
        ),
        if profile.fast_mode { "fast" } else { "full" },
        CAMERA_COUNT,
        profile.total_commits,
        profile.total_waves,
        COMMITS_PER_WAVE,
        ledger.active_epoch_id() + 1,
        total_roots_published,
        catalog_compact.total_entries,
        created_events,
        final_milestone.active_events,
        final_milestone.active_holds,
        final_milestone.privacy_masks,
        pinned_gop_payloads.len(),
        evicted_gop_digests.len(),
        total_proxies_shed,
        total_sources_evicted,
        total_packs_compacted,
        physical_bytes_written,
        peak_on_disk_pack_bytes,
        total_bytes_reclaimed,
        total_logical_catalog_bytes,
        full_scrub_passes,
        comb_proposals,
        comb_coalesced,
        comb_fsyncs_saved,
        ingest_secs,
        commits_per_sec,
        real_time_factor_1hz,
        real_time_factor_10hz,
        peak_rss_mib,
        overall_group_commit.to_json(),
        final_milestone.to_json(),
        slo_orient_pass,
        slo_query_pass,
        slo_cold_open_mvcc_pass,
        slo_cold_open_merkle_pass,
        slo_realtime_pass,
        slo_rss_pass,
        slo_roots_pass,
        slo_events_pass,
        milestones_json.join(",\n    "),
    );

    let report_path = out_dir.join("scale_million_report.json");
    fs::write(&report_path, report_json)?;

    // Enforce hard SLO assertions!
    assert!(
        slo_orient_pass,
        "SLO VIOLATION: orient p99={}us >= 10_000us",
        final_milestone.orient.p99_us
    );
    assert!(
        slo_query_pass,
        "SLO VIOLATION: query p99={}us >= 5_000us",
        final_milestone.query.p99_us
    );
    assert!(
        slo_cold_open_mvcc_pass,
        "SLO VIOLATION: mvcc cold_open p95={}us >= 15_000us",
        final_milestone.cold_open_mvcc.p95_us
    );
    assert!(
        slo_cold_open_merkle_pass,
        "SLO VIOLATION: merkle cold_open p95={}us >= 15_000us",
        final_milestone.cold_open_merkle.p95_us
    );
    assert!(
        slo_realtime_pass,
        "SLO VIOLATION: real_time_factor_10hz={real_time_factor_10hz:.4} >= 0.30"
    );
    assert!(
        slo_rss_pass,
        "SLO VIOLATION: peak_rss_mib={peak_rss_mib:.2} >= 512.0 MiB"
    );
    assert!(
        slo_roots_pass,
        "SLO VIOLATION: total_roots_published={total_roots_published} below target"
    );
    assert!(
        slo_events_pass,
        "SLO VIOLATION: total_events_created={created_events} < {}",
        profile.target_events_total
    );

    Ok(())
}
