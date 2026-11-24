#![forbid(unsafe_code)]
//! Unit, property & differential oracle test suite for Anchor-Pinned MVCC Projections and the
//! Deterministic Flat-Combining Commit Coalescer (bead `fss-x4a.31.1.7` / `A7`):
//! - Seeded property testing of MVCC snapshot isolation: concurrent readers pinned to older
//!   `ProjectionAnchor`s continue observing immutable historical state while concurrent producer
//!   threads commit waves via `CommitCombiner`;
//! - Deterministic batch commit order invariant under concurrent producer waves: identical input
//!   waves produce identical canonical `state_digest`, `authority_root`, `history_root`, and
//!   `batch_id` regardless of thread arrival scheduling;
//! - Full projection rebuild equivalence: delete `mvcc.snap` and `mvcc.wal`, rebuild from
//!   canonical history, and prove bit-identical `state_digest` and every query answer (events,
//!   holds, masks, tombstones, footage, coverage, obligations, indeterminate effects, graph edges);
//! - Structured pure-Rust JSONL telemetry emitted to `target/test-logs/scale-storage/`.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::thread;
use std::time::Instant;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EffectState, EventId, EventKind, EventState,
    EvidenceDelta, EvidenceDeltaBatch, ObjectId, ObligationId, ObligationState, OperationId, Plane,
    SensorId, StreamId, TimestampNs,
};
use fss_ledger::{EpochLedgerConfig, IncompleteTailPolicy, MerkleEpochLedger};
use fss_pack::{DurabilityMode, PACK_KIND_METADATA, PackConfig, PackObjectInput, PackStore};
use fss_projection_store::{
    CombinerError, CommitCombiner, CommitCombinerConfig, CommitProposal, CommitSink,
    CoverageStatus, CoverageWitnessPayload, DeletionTarget, DeletionTombstonePayload,
    EffectOutcomePayload, EventQueryFilter, EventRevisionPayload, EvidenceHoldPayload,
    FAMILY_ALERT_EFFECT_OUTCOME, FAMILY_COVERAGE_WITNESS, FAMILY_DELETION_TOMBSTONE,
    FAMILY_EVENT_REVISION, FAMILY_EVIDENCE_HOLD, FAMILY_FOOTAGE_IMPORT, FAMILY_GRAPH_EDGE,
    FAMILY_OBLIGATION, FAMILY_PRIVACY_MASK_POLICY, FAMILY_SENSOR_LIVENESS,
    FAMILY_SENSOR_TAMPER_STATUS, FootageAdapterKind, FootageImportPayload, FootageQueryFilter,
    GraphEdgeDeltaPayload, GraphEdgeKey, HistoryChainMode, LedgerPackProjectionSink,
    MvccProjectionStore, ObligationPayload, OwnedPackObject, PackStorePayloadResolver,
    PrivacyMaskPayload, ProjectionRebuildReason, ProjectionRecordPayload, ProjectionRecoveryMode,
    ProjectionStore, ProjectionStoreConfig, SNAPSHOT_FILENAME, SensorLivenessPayload,
    SensorLivenessStatus, SensorTamperPayload, SinkCommitOutcome, WAL_FILENAME,
    replay_from_batches,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SUITE_NAME: &str = "mvcc_property_oracle";

static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);
static LOG_LOCK: Mutex<()> = Mutex::new(());

struct TempMvccDir {
    root: PathBuf,
}

impl TempMvccDir {
    fn new(label: &str) -> TestResult<Self> {
        let seq = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("fss-a7-mvcc-{label}-{}-{seq}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }
}

impl Drop for TempMvccDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
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

struct ProposalSpec<'a> {
    tag: &'a str,
    sensor_scope: &'a str,
    family: &'a str,
    object_id: ObjectId,
    prior_gen: Option<u64>,
    plane: Plane,
    interval: CaptureInterval,
    prefix: &'a str,
}

fn build_proposal(
    spec: ProposalSpec<'_>,
    payload: &ProjectionRecordPayload,
) -> TestResult<CommitProposal> {
    let raw = payload.encode_bytes()?;
    let digest = ContentDigest::sha256(&raw);
    let delta = EvidenceDelta {
        delta_id: format!("delta:{}", spec.tag),
        family: spec.family.to_owned(),
        object_id: spec.object_id,
        prior_generation: spec.prior_gen,
        new_generation: spec.prior_gen.map_or(1, |g| g + 1),
        validity: spec.interval,
        plane: spec.plane,
        payload_digest: digest,
        witness_digest: None,
        operation_id: None,
    };
    Ok(CommitProposal {
        request_digest: ContentDigest::sha256(format!("req:{}", spec.tag).as_bytes()),
        sensor_scope: spec.sensor_scope.to_owned(),
        objects: vec![OwnedPackObject::with_digest(
            PACK_KIND_METADATA,
            0,
            raw,
            digest,
        )],
        deltas: vec![delta],
        batch_id_prefix: spec.prefix.to_owned(),
    })
}

fn make_diverse_proposal(seed: u64, wave: u64, slot: usize) -> TestResult<CommitProposal> {
    let cam = format!("cam-{:02}", slot % 8);
    let sensor = SensorId::parse(&cam)?;
    let zone = format!("zone-{:02}", (slot + (wave as usize)) % 4);
    let ts = ((seed * 10_000) + (wave * 1_000) + (slot as u64) * 10) as i128;
    let interval = CaptureInterval::new(TimestampNs(ts), TimestampNs(ts + 500))?;
    let tag = format!("s{seed}-w{wave}-k{slot}");

    match (slot + (wave as usize) + (seed as usize)) % 7 {
        0 => {
            let ev_id = EventId::parse(format!("ev-s{seed}-w{wave}-k{slot}"))?;
            let payload = ProjectionRecordPayload::EventRevision(EventRevisionPayload {
                event_id: ev_id,
                revision: 1,
                state: if slot.is_multiple_of(2) {
                    EventState::Witnessed
                } else {
                    EventState::Corroborated
                },
                kind: EventKind::PerimeterBreach,
                zones: vec![zone],
                sensor_ids: vec![sensor],
                interval,
                event_root: ContentDigest::sha256(format!("evroot:{tag}").as_bytes()),
                supersedes: None,
                corroborated: slot % 2 == 1,
                tamper_open: false,
            });
            let prefix = format!("ev{slot:02}");
            build_proposal(
                ProposalSpec {
                    tag: &tag,
                    sensor_scope: &cam,
                    family: FAMILY_EVENT_REVISION,
                    object_id: ObjectId::parse(format!("obj:ev:{tag}"))?,
                    prior_gen: None,
                    plane: Plane::Cognition,
                    interval,
                    prefix: &prefix,
                },
                &payload,
            )
        }
        1 => {
            let adapters = [
                FootageAdapterKind::Rtsp,
                FootageAdapterKind::Http,
                FootageAdapterKind::File,
                FootageAdapterKind::Tutk,
            ];
            let kind = adapters[(slot + (seed as usize)) % adapters.len()];
            let payload = ProjectionRecordPayload::FootageImport(FootageImportPayload {
                import_id: ContentDigest::sha256(format!("imp:{tag}").as_bytes()),
                adapter_kind: kind,
                sensor_id: sensor,
                stream_id: StreamId::parse(format!("stream-{:02}", slot % 8))?,
                capture_interval: interval,
                manifest_digest: ContentDigest::sha256(format!("man:{tag}").as_bytes()),
                capsule_count: 12,
                total_bytes: 16_384 + (slot as u64) * 256,
                adapter_id: format!("adp-{}", kind.as_str()),
                adapter_generation: "v1".to_owned(),
                completed: true,
            });
            let prefix = format!("ft{slot:02}");
            build_proposal(
                ProposalSpec {
                    tag: &tag,
                    sensor_scope: &cam,
                    family: FAMILY_FOOTAGE_IMPORT,
                    object_id: ObjectId::parse(format!("obj:foot:{tag}"))?,
                    prior_gen: None,
                    plane: Plane::Authority,
                    interval,
                    prefix: &prefix,
                },
                &payload,
            )
        }
        2 => {
            let status = match (slot + (wave as usize)) % 3 {
                0 => CoverageStatus::Covered,
                1 => CoverageStatus::Stale,
                _ => CoverageStatus::NotObservable,
            };
            let payload = ProjectionRecordPayload::CoverageWitness(CoverageWitnessPayload {
                sensor_id: sensor,
                zone_id: zone,
                window: interval,
                status,
                active_gaps: u32::from(status == CoverageStatus::NotObservable),
                health_conflicts: u32::from(status == CoverageStatus::Stale),
            });
            let prefix = format!("cv{slot:02}");
            build_proposal(
                ProposalSpec {
                    tag: &tag,
                    sensor_scope: &cam,
                    family: FAMILY_COVERAGE_WITNESS,
                    object_id: ObjectId::parse(format!("obj:cov:{tag}"))?,
                    prior_gen: None,
                    plane: Plane::Authority,
                    interval,
                    prefix: &prefix,
                },
                &payload,
            )
        }
        3 => {
            let payload = ProjectionRecordPayload::EvidenceHold(EvidenceHoldPayload {
                hold_id: format!("hold-{tag}"),
                scope: format!("scope-{zone}"),
                target_digest: ContentDigest::sha256(format!("tgt:{tag}").as_bytes()),
                active: true,
            });
            let prefix = format!("hd{slot:02}");
            build_proposal(
                ProposalSpec {
                    tag: &tag,
                    sensor_scope: &cam,
                    family: FAMILY_EVIDENCE_HOLD,
                    object_id: ObjectId::parse(format!("obj:hold:{tag}"))?,
                    prior_gen: None,
                    plane: Plane::Authority,
                    interval,
                    prefix: &prefix,
                },
                &payload,
            )
        }
        4 => {
            let payload = ProjectionRecordPayload::PrivacyMask(PrivacyMaskPayload {
                sensor_id: sensor,
                policy_digest: ContentDigest::sha256(format!("mask:{tag}").as_bytes()),
            });
            let prefix = format!("mk{slot:02}");
            build_proposal(
                ProposalSpec {
                    tag: &tag,
                    sensor_scope: &cam,
                    family: FAMILY_PRIVACY_MASK_POLICY,
                    object_id: ObjectId::parse(format!("obj:mask:{tag}"))?,
                    prior_gen: None,
                    plane: Plane::Authority,
                    interval,
                    prefix: &prefix,
                },
                &payload,
            )
        }
        5 => {
            let payload = ProjectionRecordPayload::EffectOutcome(EffectOutcomePayload {
                operation_id: OperationId::parse(format!("op-{tag}"))?,
                obligation_id: Some(ObligationId::parse(format!("ob-{tag}"))?),
                effect_state: EffectState::Indeterminate,
                reason: "network_timeout".to_owned(),
            });
            let prefix = format!("ef{slot:02}");
            build_proposal(
                ProposalSpec {
                    tag: &tag,
                    sensor_scope: &cam,
                    family: FAMILY_ALERT_EFFECT_OUTCOME,
                    object_id: ObjectId::parse(format!("obj:eff:{tag}"))?,
                    prior_gen: None,
                    plane: Plane::Effect,
                    interval,
                    prefix: &prefix,
                },
                &payload,
            )
        }
        _ => {
            let payload = ProjectionRecordPayload::GraphEdgeDelta(GraphEdgeDeltaPayload {
                edge_deltas: vec![(GraphEdgeKey::new("corroborates", &cam, &zone), 1)],
            });
            let prefix = format!("eg{slot:02}");
            build_proposal(
                ProposalSpec {
                    tag: &tag,
                    sensor_scope: &cam,
                    family: FAMILY_GRAPH_EDGE,
                    object_id: ObjectId::parse(format!("obj:edge:{tag}"))?,
                    prior_gen: None,
                    plane: Plane::Cognition,
                    interval,
                    prefix: &prefix,
                },
                &payload,
            )
        }
    }
}

/// Seeded property testing of MVCC snapshot isolation: concurrent readers pinned to older
/// `ProjectionAnchor`s continue observing bit-immutable historical state & query answers while
/// concurrent producer threads commit waves via `CommitCombiner`.
#[test]
fn property_seeded_mvcc_snapshot_isolation_under_concurrent_combiner_waves() -> TestResult {
    const SEEDS: u64 = 10;
    let started = Instant::now();
    let mut total_writer_commits: u64 = 0;
    let mut total_reader_checks: u64 = 0;
    let mut digest_acc = Vec::new();

    for seed in 1..=SEEDS {
        let dir = TempMvccDir::new(&format!("iso-s{seed:02}"))?;
        let mut rng = SeededRng::new(0x1501_0000_u64 ^ seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));

        let ledger = MerkleEpochLedger::open(
            dir.root.join("ledger"),
            format!("site:mvcc-iso-{seed}"),
            EpochLedgerConfig {
                max_batches_per_epoch: 16,
                checkpoint_stride: 16,
                ..EpochLedgerConfig::default()
            },
            IncompleteTailPolicy::Reject,
        )?;
        let packs = Arc::new(PackStore::open(
            dir.root.join("packs"),
            PackConfig {
                durability: DurabilityMode::Fsync,
                ..PackConfig::default()
            },
        )?);
        let projection = Arc::new(MvccProjectionStore::open_empty(
            dir.root.join("projection"),
            ledger.genesis_anchor(),
            ProjectionStoreConfig {
                max_retained_snapshots: 32, // deliberately small to test explicit pin protection!
                snapshot_stride: 16,
                ..ProjectionStoreConfig::default()
            },
        )?);
        let sink =
            LedgerPackProjectionSink::new(ledger, Arc::clone(&packs), Arc::clone(&projection));
        let combiner = Arc::new(CommitCombiner::new(sink, CommitCombinerConfig::default())?);

        // Commit 4 distinct historical anchor states T1..=T4 and pin all 4!
        let mut pinned_baselines = Vec::new();
        for hist_step in 1..=4_u64 {
            let prop = make_diverse_proposal(seed, 0, hist_step as usize)?;
            let receipt = combiner.submit(prop)?;
            let snap = projection.pin_snapshot(receipt.commit_sequence)?;
            pinned_baselines.push((
                receipt.commit_sequence,
                snap.anchor(),
                snap.state_digest(),
                snap.orient_summary(),
                projection.query_events(&snap, &EventQueryFilter::default(), 64),
                projection.query_footage(&snap, &FootageQueryFilter::default(), 64),
                projection.query_coverage(&snap, None, None),
            ));
        }
        let pinned_baselines = Arc::new(pinned_baselines);

        let writer_count = 6 + rng.range(5); // 6..=10 writers
        let commits_per_writer = 4 + rng.range(4); // 4..=7 commits each
        let reader_count = 8 + rng.range(5); // 8..=12 readers
        let barrier = Arc::new(Barrier::new(writer_count + reader_count));
        let writers_done = Arc::new(AtomicBool::new(false));

        let mut writer_handles = Vec::with_capacity(writer_count);
        for w in 0..writer_count {
            let comb = Arc::clone(&combiner);
            let bar = Arc::clone(&barrier);
            writer_handles.push(thread::spawn(move || -> Result<Vec<u64>, String> {
                bar.wait();
                let mut seqs = Vec::with_capacity(commits_per_writer);
                for round in 1..=(commits_per_writer as u64) {
                    let slot = w * 100 + (round as usize);
                    let prop = make_diverse_proposal(seed, round, slot)
                        .map_err(|e| format!("proposal build error: {e}"))?;
                    let r = comb
                        .submit(prop)
                        .map_err(|e| format!("writer {w} round {round} failed: {e}"))?;
                    seqs.push(r.commit_sequence);
                }
                Ok(seqs)
            }));
        }

        let mut reader_handles = Vec::with_capacity(reader_count);
        for r_id in 0..reader_count {
            let proj = Arc::clone(&projection);
            let base = Arc::clone(&pinned_baselines);
            let bar = Arc::clone(&barrier);
            let done = Arc::clone(&writers_done);
            reader_handles.push(thread::spawn(move || -> Result<u64, String> {
                bar.wait();
                let mut checks = 0_u64;
                let mut prev_head_seq = 0_u64;
                while !done.load(Ordering::Acquire) || checks < 25 {
                    // Verify EVERY pinned historical anchor remains 100% immutable under live writes!
                    for (seq, exp_anchor, exp_digest, exp_summary, exp_ev, exp_ft, exp_cov) in
                        base.iter()
                    {
                        let snap = proj
                            .snapshot_at(*seq)
                            .map_err(|e| format!("reader {r_id} pinned seq {seq} evicted: {e}"))?;
                        if snap.anchor() != *exp_anchor || snap.state_digest() != *exp_digest {
                            return Err(format!("reader {r_id}: pinned snapshot {seq} mutated!"));
                        }
                        if snap.orient_summary() != *exp_summary {
                            return Err(format!("reader {r_id}: pinned orient_summary {seq} drifted!"));
                        }
                        if proj.query_events(&snap, &EventQueryFilter::default(), 64) != *exp_ev
                            || proj.query_footage(&snap, &FootageQueryFilter::default(), 64) != *exp_ft
                            || proj.query_coverage(&snap, None, None) != *exp_cov
                        {
                            return Err(format!("reader {r_id}: pinned query answers {seq} drifted!"));
                        }
                    }

                    // Verify latest snapshot monotonicity & follow_since consistency.
                    let latest = proj.snapshot_latest();
                    let head_seq = latest.anchor().commit_sequence;
                    if head_seq < prev_head_seq {
                        return Err(format!(
                            "reader {r_id}: latest commit_sequence regressed {head_seq} < {prev_head_seq}"
                        ));
                    }
                    prev_head_seq = head_seq;
                    let follow = proj
                        .follow_since(4, 128)
                        .map_err(|e| format!("reader {r_id} follow_since failed: {e}"))?;
                    if follow.head_anchor.commit_sequence < head_seq {
                        return Err("follow_since regressed behind observed latest snapshot".to_owned());
                    }
                    checks += 1;
                }
                Ok(checks)
            }));
        }

        for h in writer_handles {
            let seqs = h
                .join()
                .map_err(|_| "writer thread panicked")?
                .map_err(|e| -> Box<dyn Error> { e.into() })?;
            assert!(seqs.windows(2).all(|w| w[0] < w[1]));
            total_writer_commits += seqs.len() as u64;
        }
        writers_done.store(true, Ordering::Release);

        for h in reader_handles {
            let count = h
                .join()
                .map_err(|_| "reader thread panicked")?
                .map_err(|e| -> Box<dyn Error> { e.into() })?;
            assert!(count >= 25);
            total_reader_checks += count;
        }

        let stats = combiner.shutdown()?;
        let expected_proposals = 4 + (writer_count * commits_per_writer) as u64;
        assert_eq!(stats.proposals_committed, expected_proposals);
        let final_digest = projection.snapshot_latest().state_digest();
        digest_acc.extend_from_slice(&final_digest.bytes());

        // Unpin historical snapshots cleanly.
        for (seq, _, _, _, _, _, _) in pinned_baselines.iter() {
            projection.unpin_snapshot(*seq)?;
        }
    }

    emit_jsonl(&JsonlLogEntry {
        test_name: "property_seeded_mvcc_snapshot_isolation_under_concurrent_combiner_waves",
        seed: SEEDS,
        op_count: total_writer_commits + total_reader_checks,
        stage_latency_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        pack_count: SEEDS,
        live_bytes: total_writer_commits,
        assertion_digest: ContentDigest::sha256(&digest_acc),
        verdict: "pass",
    });
    Ok(())
}

/// Thin wave-gating wrapper around a real `LedgerPackProjectionSink` allowing tests to queue an
/// entire wave of concurrent producer proposals in an arbitrary thread-arrival permutation before
/// releasing the combiner to drain and canonically sort that wave.
struct WaveGatedSink {
    inner: LedgerPackProjectionSink,
    gate_seq: u64,
    entered: Arc<(Mutex<bool>, Condvar)>,
    release: Arc<(Mutex<bool>, Condvar)>,
}

impl CommitSink for WaveGatedSink {
    fn current_object_generation(&self, object_id: &ObjectId) -> Option<u64> {
        self.inner.current_object_generation(object_id)
    }

    fn commit_coalesced_wave(
        &mut self,
        batch_id: BatchId,
        objects: &[OwnedPackObject],
        deltas: Vec<EvidenceDelta>,
        child_roots: Vec<ContentDigest>,
    ) -> Result<SinkCommitOutcome, CombinerError> {
        let outcome = self
            .inner
            .commit_coalesced_wave(batch_id, objects, deltas, child_roots)?;
        if outcome.commit_sequence == self.gate_seq {
            if let Ok(mut flag) = self.entered.0.lock() {
                *flag = true;
                self.entered.1.notify_all();
            }
            if let Ok(mut rel) = self.release.0.lock() {
                while !*rel {
                    rel = match self.release.1.wait(rel) {
                        Ok(g) => g,
                        Err(_) => return Err(CombinerError::LockPoisoned),
                    };
                }
            }
        }
        Ok(outcome)
    }
}

/// Deterministic batch commit order invariant under concurrent producer waves:
/// For 20 seeded random multi-family waves, run identical wave inputs through real
/// `CommitCombiner<WaveGatedSink>` under 3 different thread-arrival permutations (ascending,
/// descending, and Fisher-Yates seeded shuffle) and prove bit-identical canonical `state_digest`,
/// `authority_root`, `history_root`, `batch_id`, and `proposal_position` regardless of scheduling!
#[test]
fn property_deterministic_batch_commit_order_invariant_across_thread_schedules() -> TestResult {
    const SEEDS: u64 = 20;
    let started = Instant::now();
    let mut digest_acc = Vec::new();
    let mut total_proposals: u64 = 0;

    for seed in 1..=SEEDS {
        let mut rng = SeededRng::new(0xDE7E_0000_u64 ^ seed.wrapping_mul(0x517C_C1B7_2722_0A95));
        let wave_size = 4 + rng.range(4); // 4..=7 concurrent proposals in the wave
        let gate_proposal = make_diverse_proposal(seed, 1, 99)?;
        let wave_proposals: Vec<CommitProposal> = (0..wave_size)
            .map(|slot| make_diverse_proposal(seed, 2, slot))
            .collect::<TestResult<Vec<_>>>()?;

        let asc_order: Vec<usize> = (0..wave_size).collect();
        let desc_order: Vec<usize> = (0..wave_size).rev().collect();
        let mut shuf_order: Vec<usize> = (0..wave_size).collect();
        for i in (1..shuf_order.len()).rev() {
            let j = rng.range(i + 1);
            shuf_order.swap(i, j);
        }

        let mut schedule_results = Vec::new();
        for (sched_idx, order) in [asc_order, desc_order, shuf_order].iter().enumerate() {
            let dir = TempMvccDir::new(&format!("det-s{seed:02}-p{sched_idx}"))?;
            let site = format!("site:det-order-{seed}");
            let ledger = MerkleEpochLedger::open(
                dir.root.join("ledger"),
                &site,
                EpochLedgerConfig::default(),
                IncompleteTailPolicy::Reject,
            )?;
            let packs = Arc::new(PackStore::open(
                dir.root.join("packs"),
                PackConfig {
                    durability: DurabilityMode::Fsync,
                    ..PackConfig::default()
                },
            )?);
            let projection = Arc::new(MvccProjectionStore::open_empty(
                dir.root.join("projection"),
                ledger.genesis_anchor(),
                ProjectionStoreConfig::default(),
            )?);
            let inner =
                LedgerPackProjectionSink::new(ledger, Arc::clone(&packs), Arc::clone(&projection));
            let entered = Arc::new((Mutex::new(false), Condvar::new()));
            let release = Arc::new((Mutex::new(false), Condvar::new()));
            let gated_sink = WaveGatedSink {
                inner,
                gate_seq: 1,
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            };
            let combiner = Arc::new(CommitCombiner::new(
                gated_sink,
                CommitCombinerConfig::default(),
            )?);

            // Submit wave-1 gate proposal so combiner holds active slot while wave-2 queues in `order`.
            let c_gate = Arc::clone(&combiner);
            let gp = gate_proposal.clone();
            let h_gate = thread::spawn(move || c_gate.submit(gp).map_err(|e| e.to_string()));
            {
                let mut e_guard = entered.0.lock().map_err(|_| "entered lock poisoned")?;
                while !*e_guard {
                    e_guard = entered
                        .1
                        .wait(e_guard)
                        .map_err(|_| "entered wait poisoned")?;
                }
            }

            // Enqueue all wave-2 proposals in the exact thread arrival permutation `order`,
            // waiting for each thread to enter the combiner's pending queue deterministically
            // rather than guessing with a fixed sleep.
            let mut handles = Vec::with_capacity(wave_size);
            for (expected_len, &slot) in order.iter().enumerate() {
                let c = Arc::clone(&combiner);
                let prop = wave_proposals[slot].clone();
                handles.push((
                    slot,
                    thread::spawn(move || c.submit(prop).map_err(|e| e.to_string())),
                ));
                let target_len = expected_len + 1;
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                while combiner.pending_len()? < target_len {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "seed {seed}: wave proposal {slot} failed to enqueue within 2s"
                    );
                    thread::yield_now();
                }
            }
            {
                let mut r_guard = release.0.lock().map_err(|_| "release lock poisoned")?;
                *r_guard = true;
                release.1.notify_all();
            }

            let gate_rcpt = h_gate
                .join()
                .map_err(|_| "gate thread panicked")?
                .map_err(|e| -> Box<dyn Error> { e.into() })?;
            assert_eq!(gate_rcpt.commit_sequence, 1);

            let mut positions = BTreeMap::new();
            let mut wave2_batch_id = None;
            let mut wave2_auth_root = None;
            let mut wave2_hist_root = None;
            for (slot, h) in handles {
                let r = h
                    .join()
                    .map_err(|_| "wave worker panicked")?
                    .map_err(|e| -> Box<dyn Error> { e.into() })?;
                assert_eq!(r.commit_sequence, 2);
                assert_eq!(r.coalesced_count, wave_size);
                positions.insert(slot, r.proposal_position);
                wave2_batch_id = Some(r.batch_id);
                wave2_auth_root = Some(r.authority_root);
                wave2_hist_root = Some(r.history_root);
            }

            let _ = combiner.shutdown()?;
            let snap = projection.snapshot_latest();
            schedule_results.push((
                wave2_batch_id.ok_or("missing wave2 batch_id")?,
                wave2_auth_root.ok_or("missing wave2 auth_root")?,
                wave2_hist_root.ok_or("missing wave2 hist_root")?,
                positions,
                snap.state_digest(),
                snap.orient_summary(),
            ));
            total_proposals += (wave_size + 1) as u64;
        }

        // Assert ALL THREE thread schedules produced bit-identical canonical state!
        let baseline = &schedule_results[0];
        for (idx, other) in schedule_results.iter().enumerate().skip(1) {
            assert_eq!(
                other.0, baseline.0,
                "seed {seed} schedule {idx}: coalesced batch_id diverged"
            );
            assert_eq!(
                other.1, baseline.1,
                "seed {seed} schedule {idx}: Merkle authority_root diverged"
            );
            assert_eq!(
                other.2, baseline.2,
                "seed {seed} schedule {idx}: history_root diverged"
            );
            assert_eq!(
                other.3, baseline.3,
                "seed {seed} schedule {idx}: canonical proposal_positions diverged"
            );
            assert_eq!(
                other.4, baseline.4,
                "seed {seed} schedule {idx}: MVCC projection state_digest diverged"
            );
            assert_eq!(
                other.5, baseline.5,
                "seed {seed} schedule {idx}: orient_summary diverged"
            );
        }
        digest_acc.extend_from_slice(&baseline.4.bytes());
    }

    emit_jsonl(&JsonlLogEntry {
        test_name: "property_deterministic_batch_commit_order_invariant_across_thread_schedules",
        seed: SEEDS,
        op_count: total_proposals,
        stage_latency_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        pack_count: SEEDS * 3,
        live_bytes: total_proposals,
        assertion_digest: ContentDigest::sha256(&digest_acc),
        verdict: "pass",
    });
    Ok(())
}

/// Full projection rebuild equivalence across 36 seeded multi-family histories:
/// deletes `mvcc.snap` and `mvcc.wal`, rebuilds from canonical `MerkleEpochLedger` + `PackStore`,
/// cross-checks against independent `replay_from_batches`, and proves bit-identical `state_digest`
/// and EVERY query answer (events, holds, masks, tombstones, footage, coverage, obligations,
/// indeterminate effects, and Z-set graph edges).
#[test]
fn property_full_projection_rebuild_equivalence_across_all_entity_families() -> TestResult {
    const SEEDS: u64 = 36;
    let started = Instant::now();
    let mut total_batches_rebuilt: u64 = 0;
    let mut digest_acc = Vec::new();

    for seed in 1..=SEEDS {
        let dir = TempMvccDir::new(&format!("rebuild-s{seed:02}"))?;
        let proj_dir = dir.root.join("projection");
        let mut rng = SeededRng::new(0x4EB0_0000_u64 ^ seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));

        let mut ledger = MerkleEpochLedger::open(
            dir.root.join("ledger"),
            format!("site:mvcc-rebuild-{seed}"),
            EpochLedgerConfig {
                max_batches_per_epoch: 12,
                checkpoint_stride: 10,
                ..EpochLedgerConfig::default()
            },
            IncompleteTailPolicy::Reject,
        )?;
        let packs = PackStore::open(
            dir.root.join("packs"),
            PackConfig {
                durability: DurabilityMode::Fsync,
                ..PackConfig::default()
            },
        )?;
        let store = MvccProjectionStore::open_empty(
            &proj_dir,
            ledger.genesis_anchor(),
            ProjectionStoreConfig {
                snapshot_stride: 15,
                max_retained_snapshots: 32,
                ..ProjectionStoreConfig::default()
            },
        )?;

        let num_steps = 36 + rng.range(16); // 36..=51 batches per seed
        let mut gens: BTreeMap<ObjectId, u64> = BTreeMap::new();
        let mut rev_digests: BTreeMap<String, ContentDigest> = BTreeMap::new();
        let mut tracked_events: BTreeSet<EventId> = BTreeSet::new();
        let mut tracked_holds: BTreeSet<String> = BTreeSet::new();
        let mut tracked_masks: BTreeSet<SensorId> = BTreeSet::new();
        let mut tracked_imports: Vec<(ObjectId, ContentDigest)> = Vec::new();
        let mut tracked_obligations: BTreeSet<ObligationId> = BTreeSet::new();
        let mut tracked_ops: BTreeSet<OperationId> = BTreeSet::new();
        let mut tracked_edges: BTreeSet<GraphEdgeKey> = BTreeSet::new();
        let mut all_batches: Vec<EvidenceDeltaBatch> = Vec::with_capacity(num_steps);

        for step in 1..=(num_steps as u64) {
            let cam_idx = rng.range(6);
            let zone_idx = rng.range(4);
            let sensor = SensorId::parse(format!("cam-{cam_idx:02}"))?;
            let zone = format!("zone-{zone_idx:02}");
            let ts = (step as i128) * 1_000_000;
            let interval = CaptureInterval::new(TimestampNs(ts), TimestampNs(ts + 400_000))?;

            let (family, obj_id, plane, payload) = match (step as usize) % 11 {
                1 | 2 => {
                    let ev_idx = rng.range(8);
                    let ev_key = format!("ev-{ev_idx:02}");
                    let ev_id = EventId::parse(&ev_key)?;
                    let oid = ObjectId::parse(format!("obj:ev:{ev_idx:02}"))?;
                    let rev = gens.get(&oid).copied().map_or(1, |g| g + 1);
                    let state = match rev {
                        1 => EventState::Witnessed,
                        2 => EventState::Corroborated,
                        3 => EventState::Adjudicated,
                        _ => EventState::Resolved,
                    };
                    tracked_events.insert(ev_id.clone());
                    let p = ProjectionRecordPayload::EventRevision(EventRevisionPayload {
                        event_id: ev_id,
                        revision: rev,
                        state,
                        kind: if ev_idx.is_multiple_of(2) {
                            EventKind::PerimeterBreach
                        } else {
                            EventKind::UnknownPresence
                        },
                        zones: vec![zone.clone()],
                        sensor_ids: vec![sensor.clone()],
                        interval,
                        event_root: ContentDigest::sha256(format!("er-{seed}-{step}").as_bytes()),
                        supersedes: rev_digests.get(&ev_key).copied(),
                        corroborated: rev >= 2,
                        tamper_open: false,
                    });
                    (FAMILY_EVENT_REVISION, oid, Plane::Cognition, p)
                }
                3 => {
                    let st = match rng.range(3) {
                        0 => CoverageStatus::Covered,
                        1 => CoverageStatus::Stale,
                        _ => CoverageStatus::NotObservable,
                    };
                    let oid = ObjectId::parse(format!("obj:cov:{cam_idx:02}:{zone_idx:02}"))?;
                    let p = ProjectionRecordPayload::CoverageWitness(CoverageWitnessPayload {
                        sensor_id: sensor.clone(),
                        zone_id: zone.clone(),
                        window: interval,
                        status: st,
                        active_gaps: u32::from(st == CoverageStatus::NotObservable),
                        health_conflicts: u32::from(st == CoverageStatus::Stale),
                    });
                    (FAMILY_COVERAGE_WITNESS, oid, Plane::Authority, p)
                }
                4 => {
                    let adapters = [
                        FootageAdapterKind::Rtsp,
                        FootageAdapterKind::Http,
                        FootageAdapterKind::File,
                        FootageAdapterKind::Tutk,
                    ];
                    let kind = adapters[(step as usize / 11 + rng.range(4)) % 4];
                    let imp_id = ContentDigest::sha256(format!("imp-{seed}-{step}").as_bytes());
                    let oid = ObjectId::parse(format!("obj:imp:{step:04}"))?;
                    tracked_imports.push((oid.clone(), imp_id));
                    let p = ProjectionRecordPayload::FootageImport(FootageImportPayload {
                        import_id: imp_id,
                        adapter_kind: kind,
                        sensor_id: sensor.clone(),
                        stream_id: StreamId::parse(format!("stream-{cam_idx:02}"))?,
                        capture_interval: interval,
                        manifest_digest: ContentDigest::sha256(
                            format!("man-{seed}-{step}").as_bytes(),
                        ),
                        capsule_count: 8,
                        total_bytes: 32_768 * step,
                        adapter_id: format!("adp-{}", kind.as_str()),
                        adapter_generation: "v1".to_owned(),
                        completed: !step.is_multiple_of(5),
                    });
                    (FAMILY_FOOTAGE_IMPORT, oid, Plane::Authority, p)
                }
                5 => {
                    let h_idx = rng.range(4);
                    let hold_id = format!("hold-{h_idx}");
                    tracked_holds.insert(hold_id.clone());
                    let oid = ObjectId::parse(format!("obj:hold:{h_idx}"))?;
                    let p = ProjectionRecordPayload::EvidenceHold(EvidenceHoldPayload {
                        hold_id,
                        scope: format!("scope-{zone}"),
                        target_digest: ContentDigest::sha256(format!("htgt-{h_idx}").as_bytes()),
                        active: rng.range(3) != 0,
                    });
                    (FAMILY_EVIDENCE_HOLD, oid, Plane::Authority, p)
                }
                6 => {
                    tracked_masks.insert(sensor.clone());
                    let oid = ObjectId::parse(format!("obj:mask:{cam_idx:02}"))?;
                    let p = ProjectionRecordPayload::PrivacyMask(PrivacyMaskPayload {
                        sensor_id: sensor.clone(),
                        policy_digest: ContentDigest::sha256(
                            format!("mpol-{seed}-{step}").as_bytes(),
                        ),
                    });
                    (FAMILY_PRIVACY_MASK_POLICY, oid, Plane::Authority, p)
                }
                7 => {
                    let ob_idx = rng.range(4);
                    let ob_id = ObligationId::parse(format!("ob-{ob_idx:02}"))?;
                    let op_id = OperationId::parse(format!("op-ob-{ob_idx:02}"))?;
                    tracked_obligations.insert(ob_id.clone());
                    let st = if step > 20 && rng.range(2) == 0 {
                        ObligationState::Verified
                    } else {
                        ObligationState::Pending
                    };
                    let oid = ObjectId::parse(format!("obj:ob:{ob_idx:02}"))?;
                    let p = ProjectionRecordPayload::Obligation(ObligationPayload {
                        obligation_id: ob_id,
                        operation_id: op_id,
                        terminal_predicate: "provider_verified".to_owned(),
                        state: st,
                        proof_digest: (st == ObligationState::Verified).then(|| {
                            ContentDigest::sha256(format!("obp-{seed}-{step}").as_bytes())
                        }),
                    });
                    (FAMILY_OBLIGATION, oid, Plane::Effect, p)
                }
                8 => {
                    let op_idx = rng.range(4);
                    let op_id = OperationId::parse(format!("op-eff-{op_idx:02}"))?;
                    tracked_ops.insert(op_id.clone());
                    let eff_state = if step > 25 && op_idx == 0 {
                        EffectState::Verified
                    } else {
                        EffectState::Indeterminate
                    };
                    let oid = ObjectId::parse(format!("obj:eff:{op_idx:02}"))?;
                    let p = ProjectionRecordPayload::EffectOutcome(EffectOutcomePayload {
                        operation_id: op_id,
                        obligation_id: Some(ObligationId::parse(format!("ob-{op_idx:02}"))?),
                        effect_state: eff_state,
                        reason: "gateway_timeout".to_owned(),
                    });
                    (FAMILY_ALERT_EFFECT_OUTCOME, oid, Plane::Effect, p)
                }
                9 => {
                    let key = GraphEdgeKey::new("handover_link", sensor.as_str(), zone.as_str());
                    tracked_edges.insert(key.clone());
                    let weight = if step > 28 && rng.range(3) == 0 {
                        -1
                    } else {
                        1
                    };
                    let oid = ObjectId::parse(format!("obj:edge:{step:04}"))?;
                    let p = ProjectionRecordPayload::GraphEdgeDelta(GraphEdgeDeltaPayload {
                        edge_deltas: vec![(key, weight)],
                    });
                    (FAMILY_GRAPH_EDGE, oid, Plane::Cognition, p)
                }
                10 => {
                    let st = match rng.range(4) {
                        0 => SensorLivenessStatus::Online,
                        1 => SensorLivenessStatus::Degraded,
                        2 => SensorLivenessStatus::Offline,
                        _ => SensorLivenessStatus::Unknown,
                    };
                    let oid = ObjectId::parse(format!("obj:live:{cam_idx:02}"))?;
                    let p = ProjectionRecordPayload::SensorLiveness(SensorLivenessPayload {
                        sensor_id: sensor.clone(),
                        state: st,
                        last_seen_ns: interval.earliest,
                        observed_at_ns: interval.latest,
                    });
                    (FAMILY_SENSOR_LIVENESS, oid, Plane::Authority, p)
                }
                _ => {
                    if !tracked_imports.is_empty() && rng.range(2) == 0 {
                        let pick = rng.range(tracked_imports.len());
                        let oid = ObjectId::parse(format!("obj:tomb:{step:04}"))?;
                        let p =
                            ProjectionRecordPayload::DeletionTombstone(DeletionTombstonePayload {
                                target: DeletionTarget::Object(tracked_imports[pick].0.clone()),
                            });
                        (FAMILY_DELETION_TOMBSTONE, oid, Plane::Authority, p)
                    } else if let Some(ev_id) = tracked_events.iter().next().cloned() {
                        if rng.range(2) == 0 {
                            let oid = ObjectId::parse(format!("obj:tomb-ev:{step:04}"))?;
                            let p = ProjectionRecordPayload::DeletionTombstone(
                                DeletionTombstonePayload {
                                    target: DeletionTarget::Event(ev_id),
                                },
                            );
                            (FAMILY_DELETION_TOMBSTONE, oid, Plane::Authority, p)
                        } else {
                            let oid = ObjectId::parse(format!("obj:tamper:{step:04}"))?;
                            let p = ProjectionRecordPayload::SensorTamper(SensorTamperPayload {
                                event_id: ev_id,
                                tamper_open: true,
                            });
                            (FAMILY_SENSOR_TAMPER_STATUS, oid, Plane::Authority, p)
                        }
                    } else {
                        let key = GraphEdgeKey::new("sees", sensor.as_str(), zone.as_str());
                        tracked_edges.insert(key.clone());
                        let oid = ObjectId::parse(format!("obj:edge:{step:04}"))?;
                        let p = ProjectionRecordPayload::GraphEdgeDelta(GraphEdgeDeltaPayload {
                            edge_deltas: vec![(key, 1)],
                        });
                        (FAMILY_GRAPH_EDGE, oid, Plane::Cognition, p)
                    }
                }
            };

            let raw = payload.encode_bytes()?;
            let digest = ContentDigest::sha256(&raw);
            let _ = packs.append_batch(&[PackObjectInput::with_digest(
                PACK_KIND_METADATA,
                0,
                &raw,
                digest,
            )])?;
            let prior = gens.get(&obj_id).copied();
            let next_gen = prior.map_or(1, |g| g + 1);
            gens.insert(obj_id.clone(), next_gen);
            if family == FAMILY_EVENT_REVISION
                && let ProjectionRecordPayload::EventRevision(ref ev) = payload
            {
                rev_digests.insert(ev.event_id.as_str().to_owned(), digest);
            }
            let delta = EvidenceDelta {
                delta_id: format!("d-{seed}-{step}"),
                family: family.to_owned(),
                object_id: obj_id,
                prior_generation: prior,
                new_generation: next_gen,
                validity: interval,
                plane,
                payload_digest: digest,
                witness_digest: None,
                operation_id: None,
            };
            let batch = ledger.prepare_batch(
                BatchId::parse(format!("b-{seed:02}-{step:04}"))?,
                vec![delta],
                [digest],
            )?;
            let _ = ledger.append_batch(batch.clone())?;
            let resolver = PackStorePayloadResolver::new(&packs);
            let _ = store.apply_delta_batch(&batch, &resolver)?;
            all_batches.push(batch);
        }

        // Capture incremental snapshot before wiping mvcc.snap and mvcc.wal!
        let inc_snap = store.snapshot_latest();
        let inc_digest = inc_snap.state_digest();
        drop(store);

        // Delete mvcc.snap and mvcc.wal explicitly (leaving directory empty or removed).
        let snap_path = proj_dir.join(SNAPSHOT_FILENAME);
        let wal_path = proj_dir.join(WAL_FILENAME);
        if snap_path.exists() {
            fs::remove_file(&snap_path)?;
        }
        if wal_path.exists() {
            fs::remove_file(&wal_path)?;
        }
        if seed.is_multiple_of(2) && proj_dir.exists() {
            fs::remove_dir_all(&proj_dir)?;
        }

        let resolver = PackStorePayloadResolver::new(&packs);
        let rebuilt = MvccProjectionStore::open_or_rebuild(&proj_dir, &ledger, &resolver)?;
        assert_eq!(
            rebuilt.recovery_report().mode,
            ProjectionRecoveryMode::RebuiltFromGenesis
        );
        assert_eq!(
            rebuilt.recovery_report().rebuild_reason,
            Some(ProjectionRebuildReason::Missing)
        );
        assert_eq!(
            rebuilt.recovery_report().replayed_ledger_batches,
            all_batches.len() as u64
        );
        let reb_snap = rebuilt.snapshot_latest();

        // Also cross-check against independent pure replay_from_batches oracle!
        let ora_snap = replay_from_batches(
            ledger.genesis_anchor(),
            HistoryChainMode::V2MerkleEpoch,
            &all_batches,
            &resolver,
        )?;

        // Bit-identical state_digest and orient_summary across incremental, rebuilt, and oracle!
        assert_eq!(
            inc_digest,
            reb_snap.state_digest(),
            "seed {seed}: rebuild digest mismatch"
        );
        assert_eq!(
            inc_digest,
            ora_snap.state_digest(),
            "seed {seed}: oracle digest mismatch"
        );
        assert_eq!(inc_snap.orient_summary(), reb_snap.orient_summary());
        assert_eq!(inc_snap.orient_summary(), ora_snap.orient_summary());

        // Verify EVERY query answer: events, holds, masks, tombstones, footage, coverage,
        // obligations, indeterminate effects, graph edges, and follow_since!
        assert_eq!(
            inc_snap.query_events(&EventQueryFilter::default(), 200),
            reb_snap.query_events(&EventQueryFilter::default(), 200)
        );
        for ev_id in &tracked_events {
            assert_eq!(inc_snap.get_event(ev_id), reb_snap.get_event(ev_id));
            assert_eq!(inc_snap.get_event(ev_id), ora_snap.get_event(ev_id));
            for rev in 1..=4_u64 {
                assert_eq!(
                    inc_snap.get_event_revision(ev_id, rev),
                    reb_snap.get_event_revision(ev_id, rev)
                );
            }
        }
        for hold_id in &tracked_holds {
            assert_eq!(inc_snap.get_hold(hold_id), reb_snap.get_hold(hold_id));
            assert_eq!(inc_snap.get_hold(hold_id), ora_snap.get_hold(hold_id));
        }
        for sensor_id in &tracked_masks {
            assert_eq!(
                inc_snap.get_privacy_mask(sensor_id),
                reb_snap.get_privacy_mask(sensor_id)
            );
            assert_eq!(
                inc_snap.get_privacy_mask(sensor_id),
                ora_snap.get_privacy_mask(sensor_id)
            );
        }
        assert_eq!(
            inc_snap.query_footage(&FootageQueryFilter::default(), 200),
            reb_snap.query_footage(&FootageQueryFilter::default(), 200)
        );
        for (_, imp_id) in &tracked_imports {
            assert_eq!(
                inc_snap.get_footage_import(imp_id),
                reb_snap.get_footage_import(imp_id)
            );
            assert_eq!(
                inc_snap.get_footage_import(imp_id),
                ora_snap.get_footage_import(imp_id)
            );
        }
        assert_eq!(
            inc_snap.query_coverage(None, None),
            reb_snap.query_coverage(None, None)
        );
        assert_eq!(
            inc_snap.query_coverage(None, None),
            ora_snap.query_coverage(None, None)
        );
        for ob_id in &tracked_obligations {
            assert_eq!(
                inc_snap.get_obligation(ob_id),
                reb_snap.get_obligation(ob_id)
            );
        }
        for op_id in &tracked_ops {
            assert_eq!(
                inc_snap.get_indeterminate_effect(op_id),
                reb_snap.get_indeterminate_effect(op_id)
            );
        }
        for edge_key in &tracked_edges {
            assert_eq!(
                inc_snap.zset_edge_weight(edge_key),
                reb_snap.zset_edge_weight(edge_key)
            );
            assert_eq!(
                inc_snap.zset_edge_weight(edge_key),
                ora_snap.zset_edge_weight(edge_key)
            );
        }
        assert_eq!(
            inc_snap.to_zset_graph_state()?,
            reb_snap.to_zset_graph_state()?
        );
        assert_eq!(
            inc_snap.follow_since(0, 200)?,
            reb_snap.follow_since(0, 200)?
        );

        total_batches_rebuilt += all_batches.len() as u64;
        digest_acc.extend_from_slice(&inc_digest.bytes());
    }

    emit_jsonl(&JsonlLogEntry {
        test_name: "property_full_projection_rebuild_equivalence_across_all_entity_families",
        seed: SEEDS,
        op_count: total_batches_rebuilt,
        stage_latency_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        pack_count: SEEDS,
        live_bytes: total_batches_rebuilt,
        assertion_digest: ContentDigest::sha256(&digest_acc),
        verdict: "pass",
    });
    Ok(())
}
