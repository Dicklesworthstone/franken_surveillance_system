#![forbid(unsafe_code)]
//! Concurrency, MVCC snapshot isolation (`T1`/`T2`/`T3` pinned reads under `T4+` mutations),
//! flat-combining fsync amortization, deterministic canonical batch ordering, and cancellation tests.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use fss_core::{
    CaptureInterval, ContentDigest, EventId, EventKind, EventState, EvidenceDelta, ObjectId, Plane,
    SensorId, StreamId, TimestampNs,
};
use fss_ledger::{EpochLedgerConfig, IncompleteTailPolicy, MerkleEpochLedger};
use fss_pack::{DurabilityMode, PACK_KIND_METADATA, PackConfig, PackStore};
use fss_projection_store::{
    CombinerError, CommitCombiner, CommitCombinerConfig, CommitProposal, CoverageStatus,
    CoverageWitnessPayload, EventQueryFilter, EventRevisionPayload, FAMILY_COVERAGE_WITNESS,
    FAMILY_EVENT_REVISION, FAMILY_FOOTAGE_IMPORT, FootageAdapterKind, FootageImportPayload,
    FootageQueryFilter, LedgerPackProjectionSink, MvccProjectionStore, OwnedPackObject,
    ProjectionRecordPayload, ProjectionStore, ProjectionStoreConfig,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static CONC_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    root: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let id = CONC_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("fss-proj-conc-{label}-{}-{id}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn make_event_proposal(
    sensor_idx: usize,
    round: u64,
    prior_gen: Option<u64>,
) -> Result<CommitProposal, Box<dyn std::error::Error>> {
    let sensor_scope = format!("cam-{sensor_idx:02}");
    let sensor = SensorId::parse(&sensor_scope)?;
    let event_id = EventId::parse(format!("ev-cam-{sensor_idx:02}-r{round:03}"))?;
    let obj_id = ObjectId::parse(format!("obj:ev:{sensor_idx:02}:r{round:03}"))?;
    let interval = CaptureInterval::new(
        TimestampNs((round as i128) * 10_000 + sensor_idx as i128),
        TimestampNs((round as i128) * 10_000 + sensor_idx as i128 + 500),
    )?;
    let payload = ProjectionRecordPayload::EventRevision(EventRevisionPayload {
        event_id,
        revision: 1,
        state: EventState::Witnessed,
        kind: EventKind::PerimeterBreach,
        zones: vec![format!("zone-{:02}", sensor_idx % 4)],
        sensor_ids: vec![sensor],
        interval,
        event_root: ContentDigest::sha256(format!("root-{sensor_idx}-{round}").as_bytes()),
        supersedes: None,
        corroborated: false,
        tamper_open: false,
    });
    let raw = payload.encode_bytes()?;
    let digest = ContentDigest::sha256(&raw);
    let delta = EvidenceDelta {
        delta_id: format!("d-{sensor_idx:02}-{round:03}"),
        family: FAMILY_EVENT_REVISION.to_owned(),
        object_id: obj_id,
        prior_generation: prior_gen,
        new_generation: prior_gen.map_or(1, |g| g + 1),
        validity: interval,
        plane: Plane::Cognition,
        payload_digest: digest,
        witness_digest: None,
        operation_id: None,
    };
    let req_digest = ContentDigest::sha256(format!("req-{sensor_idx:02}-{round:03}").as_bytes());
    Ok(CommitProposal {
        request_digest: req_digest,
        sensor_scope,
        objects: vec![OwnedPackObject::with_digest(
            PACK_KIND_METADATA,
            0,
            raw,
            digest,
        )],
        deltas: vec![delta],
        batch_id_prefix: format!("cam{sensor_idx:02}"),
    })
}

fn make_coverage_and_footage_proposal(
    tag: u64,
    adapter_kind: FootageAdapterKind,
) -> Result<CommitProposal, Box<dyn std::error::Error>> {
    let sensor = SensorId::parse(format!("seed-cam-{tag:02}"))?;
    let interval = CaptureInterval::new(
        TimestampNs(tag as i128 * 1000),
        TimestampNs(tag as i128 * 1000 + 900),
    )?;
    let cov_payload = ProjectionRecordPayload::CoverageWitness(CoverageWitnessPayload {
        sensor_id: sensor.clone(),
        zone_id: format!("zone-{tag:02}"),
        window: interval,
        status: CoverageStatus::Covered,
        active_gaps: 0,
        health_conflicts: 0,
    });
    let cov_raw = cov_payload.encode_bytes()?;
    let cov_digest = ContentDigest::sha256(&cov_raw);

    let import_id = ContentDigest::sha256(format!("seed-imp-{tag}").as_bytes());
    let foot_payload = ProjectionRecordPayload::FootageImport(FootageImportPayload {
        import_id,
        adapter_kind,
        sensor_id: sensor.clone(),
        stream_id: StreamId::parse(format!("seed-stream-{tag:02}"))?,
        capture_interval: interval,
        manifest_digest: ContentDigest::sha256(format!("seed-man-{tag}").as_bytes()),
        capsule_count: 8,
        total_bytes: 32_768,
        adapter_id: format!("adp-{}", adapter_kind.as_str()),
        adapter_generation: "gen-v1".to_owned(),
        completed: true,
    });
    let foot_raw = foot_payload.encode_bytes()?;
    let foot_digest = ContentDigest::sha256(&foot_raw);

    let deltas = vec![
        EvidenceDelta {
            delta_id: format!("seed-cov-{tag}"),
            family: FAMILY_COVERAGE_WITNESS.to_owned(),
            object_id: ObjectId::parse(format!("obj:seed:cov:{tag:02}"))?,
            prior_generation: None,
            new_generation: 1,
            validity: interval,
            plane: Plane::Authority,
            payload_digest: cov_digest,
            witness_digest: None,
            operation_id: None,
        },
        EvidenceDelta {
            delta_id: format!("seed-foot-{tag}"),
            family: FAMILY_FOOTAGE_IMPORT.to_owned(),
            object_id: ObjectId::parse(format!("obj:seed:foot:{tag:02}"))?,
            prior_generation: None,
            new_generation: 1,
            validity: interval,
            plane: Plane::Authority,
            payload_digest: foot_digest,
            witness_digest: None,
            operation_id: None,
        },
    ];
    Ok(CommitProposal {
        request_digest: ContentDigest::sha256(format!("seed-req-{tag}").as_bytes()),
        sensor_scope: sensor.into_inner(),
        objects: vec![
            OwnedPackObject::with_digest(PACK_KIND_METADATA, 0, cov_raw, cov_digest),
            OwnedPackObject::with_digest(PACK_KIND_METADATA, 0, foot_raw, foot_digest),
        ],
        deltas,
        batch_id_prefix: format!("seed{tag:02}"),
    })
}

#[test]
fn concurrent_16_writers_32_readers_mvcc_isolation_and_coalescing() -> TestResult {
    let dir = TempDir::new("16w32r")?;
    let ledger = MerkleEpochLedger::open(
        dir.root.join("ledger"),
        "site:conc-mvcc",
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
        ProjectionStoreConfig {
            max_retained_snapshots: 256,
            snapshot_stride: 64,
            ..ProjectionStoreConfig::default()
        },
    )?);
    let sink = LedgerPackProjectionSink::new(ledger, Arc::clone(&packs), Arc::clone(&projection));
    let combiner = Arc::new(CommitCombiner::new(sink, CommitCombinerConfig::default())?);

    // Establish historical pinned anchors T1, T2, T3 BEFORE concurrent T4+ writers run.
    let r1 = combiner.submit(make_coverage_and_footage_proposal(
        1,
        FootageAdapterKind::Rtsp,
    )?)?;
    let r2 = combiner.submit(make_coverage_and_footage_proposal(
        2,
        FootageAdapterKind::Http,
    )?)?;
    let r3 = combiner.submit(make_coverage_and_footage_proposal(
        3,
        FootageAdapterKind::Tutk,
    )?)?;
    let t1_seq = r1.commit_sequence;
    let t2_seq = r2.commit_sequence;
    let t3_seq = r3.commit_sequence;
    assert_eq!((t1_seq, t2_seq, t3_seq), (1, 2, 3));

    let t1_snap = projection.pin_snapshot(t1_seq)?;
    let t2_snap = projection.pin_snapshot(t2_seq)?;
    let t3_snap = projection.pin_snapshot(t3_seq)?;
    let t1_digest = t1_snap.state_digest();
    let t2_digest = t2_snap.state_digest();
    let t3_digest = t3_snap.state_digest();
    assert_ne!(t1_digest, t2_digest);
    assert_ne!(t2_digest, t3_digest);

    // Launch 16 concurrent writers (8 commits each = 128 proposals) + 32 concurrent readers!
    const WRITERS: usize = 16;
    const COMMITS_PER_WRITER: u64 = 8;
    const READERS: usize = 32;
    let start_barrier = Arc::new(Barrier::new(WRITERS + READERS));
    let writers_done = Arc::new(AtomicBool::new(false));

    let mut writer_handles = Vec::with_capacity(WRITERS);
    for writer_id in 0..WRITERS {
        let comb = Arc::clone(&combiner);
        let barrier = Arc::clone(&start_barrier);
        writer_handles.push(thread::spawn(move || -> Result<Vec<u64>, String> {
            barrier.wait();
            let mut seqs = Vec::with_capacity(COMMITS_PER_WRITER as usize);
            for round in 1..=COMMITS_PER_WRITER {
                let proposal = make_event_proposal(writer_id, round, None)
                    .map_err(|e| format!("proposal build failed: {e}"))?;
                let receipt = comb
                    .submit(proposal)
                    .map_err(|e| format!("writer {writer_id} round {round} failed: {e}"))?;
                seqs.push(receipt.commit_sequence);
            }
            Ok(seqs)
        }));
    }

    let mut reader_handles = Vec::with_capacity(READERS);
    for reader_id in 0..READERS {
        let proj = Arc::clone(&projection);
        let barrier = Arc::clone(&start_barrier);
        let done = Arc::clone(&writers_done);
        reader_handles.push(thread::spawn(move || -> Result<u64, String> {
            barrier.wait();
            let mut reads = 0_u64;
            while !done.load(Ordering::Acquire) || reads < 40 {
                // Verify historical pinned snapshots T1, T2, T3 NEVER observe T4+ mutations!
                let s1 = proj
                    .snapshot_at(t1_seq)
                    .map_err(|e| format!("reader {reader_id} T1 failed: {e}"))?;
                let s2 = proj
                    .snapshot_at(t2_seq)
                    .map_err(|e| format!("reader {reader_id} T2 failed: {e}"))?;
                let s3 = proj
                    .snapshot_at(t3_seq)
                    .map_err(|e| format!("reader {reader_id} T3 failed: {e}"))?;
                if s1.state_digest() != t1_digest
                    || s2.state_digest() != t2_digest
                    || s3.state_digest() != t3_digest
                {
                    return Err("historical pinned snapshot mutated!".to_owned());
                }
                if s1.orient_summary().total_events != 0
                    || s2.orient_summary().total_footage_imports != 2
                    || s3.orient_summary().total_footage_imports != 3
                {
                    return Err("historical pinned snapshot counts drifted!".to_owned());
                }

                // Concurrent latest orient / query / follow reads.
                let latest = proj.snapshot_latest();
                let summary = latest.orient_summary();
                if summary.anchor.commit_sequence < t3_seq {
                    return Err("latest snapshot regressed below T3".to_owned());
                }
                let _ev_page = proj.query_events(
                    &latest,
                    &EventQueryFilter {
                        state: Some(EventState::Witnessed),
                        ..EventQueryFilter::default()
                    },
                    16,
                );
                let _foot_page = proj.query_footage(&latest, &FootageQueryFilter::default(), 16);
                let _cov = proj.query_coverage(&latest, None, None);
                let _follow = proj
                    .follow_since(t3_seq, 32)
                    .map_err(|e| format!("follow_since failed: {e}"))?;
                reads += 1;
            }
            Ok(reads)
        }));
    }

    for handle in writer_handles {
        let seqs = handle
            .join()
            .map_err(|_| "writer thread panicked")?
            .map_err(|e| format!("writer error: {e}"))?;
        assert_eq!(seqs.len(), COMMITS_PER_WRITER as usize);
        assert!(seqs.windows(2).all(|w| w[0] < w[1]));
    }
    writers_done.store(true, Ordering::Release);

    let mut total_reader_ops = 0_u64;
    for handle in reader_handles {
        let count = handle
            .join()
            .map_err(|_| "reader thread panicked")?
            .map_err(|e| format!("reader error: {e}"))?;
        assert!(count >= 40);
        total_reader_ops += count;
    }
    assert!(total_reader_ops >= (READERS as u64) * 40);

    let stats = combiner.shutdown()?;
    let total_submissions = 3 + (WRITERS as u64) * COMMITS_PER_WRITER;
    assert_eq!(stats.proposals_committed, total_submissions);
    // Genuine flat-combining coalescing: far fewer rounds & fsyncs than submissions!
    assert!(
        stats.rounds_executed < total_submissions,
        "expected flat-combining coalescing: rounds={} vs submissions={total_submissions}",
        stats.rounds_executed
    );
    assert!(
        stats.fsyncs_executed < total_submissions * 2,
        "expected fsync amortization: fsyncs={} vs baseline={}",
        stats.fsyncs_executed,
        total_submissions * 2
    );
    assert!(stats.coalesced_commits > 0);
    assert!(stats.fsyncs_saved > 0);

    // Verify all 128 events from 16 writers are materialized cleanly in the final snapshot.
    let final_snap = projection.snapshot_latest();
    assert_eq!(
        final_snap.orient_summary().total_events,
        WRITERS * (COMMITS_PER_WRITER as usize)
    );
    assert_eq!(final_snap.orient_summary().total_footage_imports, 3);
    assert_eq!(final_snap.anchor().commit_sequence, stats.rounds_executed);

    // Submissions after shutdown must fail cleanly with Shutdown.
    let post_shutdown = combiner.submit(make_event_proposal(99, 1, None)?);
    assert!(matches!(post_shutdown, Err(CombinerError::Shutdown)));
    Ok(())
}

#[test]
fn combiner_deterministic_order_cancellation_and_collision_deferral() -> TestResult {
    let dir = TempDir::new("determ")?;
    let ledger = MerkleEpochLedger::open(
        dir.root.join("ledger"),
        "site:determ",
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )?;
    let packs = Arc::new(PackStore::open(
        dir.root.join("packs"),
        PackConfig::default(),
    )?);
    let projection = Arc::new(MvccProjectionStore::open_empty(
        dir.root.join("projection"),
        ledger.genesis_anchor(),
        ProjectionStoreConfig::default(),
    )?);
    let sink = LedgerPackProjectionSink::new(ledger, Arc::clone(&packs), Arc::clone(&projection));
    let combiner = CommitCombiner::new(sink, CommitCombinerConfig::default())?;

    // Cancelled submission before queueing returns Cancelled and leaves commit sequence at 0.
    let cancel_flag = Arc::new(AtomicBool::new(true));
    let res = combiner.submit_with_cancel(make_event_proposal(0, 1, None)?, cancel_flag);
    assert!(matches!(res, Err(CombinerError::Cancelled)));
    assert_eq!(projection.head_anchor().commit_sequence, 0);

    // Invalid generation conflict is rejected cleanly with GenerationConflict.
    let bad = make_event_proposal(0, 1, Some(5))?;
    let bad_res = combiner.submit(bad);
    assert!(matches!(
        bad_res,
        Err(CombinerError::GenerationConflict { .. })
    ));
    assert_eq!(projection.head_anchor().commit_sequence, 0);

    // Valid commit succeeds immediately afterwards.
    let ok = combiner.submit(make_event_proposal(0, 1, None)?)?;
    assert_eq!(ok.commit_sequence, 1);
    assert_eq!(ok.proposal_position, 0);
    let _sink = combiner.into_sink()?;
    Ok(())
}

type CheckpointFaultCombiner = (
    CommitCombiner<LedgerPackProjectionSink>,
    Arc<MvccProjectionStore>,
    PathBuf,
);

/// Block checkpoint publication at its temporary path without interfering with epoch or pack I/O.
fn checkpoint_fault_combiner(
    dir: &TempDir,
) -> Result<CheckpointFaultCombiner, Box<dyn std::error::Error>> {
    let ledger_dir = dir.root.join("ledger");
    let ledger = MerkleEpochLedger::open(
        &ledger_dir,
        "site:checkpoint-fault",
        EpochLedgerConfig {
            checkpoint_stride: 1,
            ..EpochLedgerConfig::default()
        },
        IncompleteTailPolicy::Reject,
    )?;
    let packs = Arc::new(PackStore::open(
        dir.root.join("packs"),
        PackConfig::default(),
    )?);
    let projection = Arc::new(MvccProjectionStore::open_empty(
        dir.root.join("projection"),
        ledger.genesis_anchor(),
        ProjectionStoreConfig::default(),
    )?);
    let sink = LedgerPackProjectionSink::new(ledger, packs, Arc::clone(&projection));
    let blocked = ledger_dir
        .join("checkpoints")
        .join(format!(".seq-{:020}.fssc.tmp", 1));
    fs::create_dir(&blocked)?;
    Ok((
        CommitCombiner::new(sink, CommitCombinerConfig::default())?,
        projection,
        blocked,
    ))
}

#[test]
fn combiner_projects_durable_batch_despite_checkpoint_failure() -> TestResult {
    let dir = TempDir::new("durable-without-checkpoint")?;
    let (combiner, projection, blocked) = checkpoint_fault_combiner(&dir)?;
    let proposal = make_event_proposal(0, 1, None)?;
    let committed = combiner.submit(proposal.clone())?;
    assert!(committed.checkpoint_failure.is_some());
    let visible = projection.snapshot_latest();
    assert_eq!(visible.orient_summary().total_events, 1);
    assert_eq!(visible.anchor().commit_sequence, committed.commit_sequence);
    assert_eq!(visible.anchor().high_water_digest, committed.batch_digest);
    assert_eq!(visible.anchor().history_root, committed.history_root);
    assert!(matches!(
        combiner.submit(proposal),
        Err(CombinerError::GenerationConflict { .. })
    ));

    fs::remove_dir(blocked)?;
    let next = combiner.submit(make_event_proposal(0, 2, None)?)?;
    assert!(next.checkpoint_failure.is_none());
    assert_eq!(next.commit_sequence, 2);
    assert_eq!(
        projection.snapshot_latest().orient_summary().total_events,
        2
    );
    let sink = combiner.into_sink()?;
    assert_eq!(sink.ledger().verify_full_chain()?.batches_verified, 2);
    Ok(())
}

#[test]
fn combiner_rejects_missing_payload_before_canonical_commit_and_checkpoint() -> TestResult {
    let dir = TempDir::new("durable-missing-projection")?;
    let (combiner, projection, blocked) = checkpoint_fault_combiner(&dir)?;
    let mut proposal = make_event_proposal(0, 1, None)?;
    proposal.objects.clear();
    let rejected = combiner.submit(proposal);
    assert!(
        matches!(rejected, Err(CombinerError::SinkFailure(ref detail)) if detail.contains("missing payload"))
    );
    assert_eq!(projection.head_anchor().commit_sequence, 0);
    // The rejected generation was never committed, and the checkpoint path was never reached.
    let receipt = combiner.submit(make_event_proposal(0, 1, None)?)?;
    assert_eq!(receipt.commit_sequence, 1);
    assert!(receipt.checkpoint_failure.is_some());
    fs::remove_dir(blocked)?;
    let sink = combiner.into_sink()?;
    assert_eq!(sink.ledger().head_anchor().commit_sequence, 1);
    assert_eq!(sink.ledger().history_root(), receipt.history_root);
    assert_eq!(sink.ledger().verify_full_chain()?.batches_verified, 1);
    Ok(())
}

fn history_test_sink(
    dir: &TempDir,
    history_mode: fss_projection_store::HistoryChainMode,
) -> Result<LedgerPackProjectionSink, Box<dyn std::error::Error>> {
    let ledger = MerkleEpochLedger::open(
        dir.root.join("ledger"),
        "site:paired-histories",
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )?;
    let packs = Arc::new(PackStore::open(
        dir.root.join("packs"),
        PackConfig::default(),
    )?);
    let projection = Arc::new(MvccProjectionStore::open_empty(
        dir.root.join("projection"),
        ledger.genesis_anchor(),
        ProjectionStoreConfig {
            history_mode,
            ..ProjectionStoreConfig::default()
        },
    )?);
    Ok(LedgerPackProjectionSink::new(ledger, packs, projection))
}

#[test]
fn combiner_refuses_equal_state_from_a_different_merkle_history() -> TestResult {
    use fss_projection_store::HistoryChainMode::V2MerkleEpoch;

    let canonical_dir = TempDir::new("canonical-history")?;
    let alternate_dir = TempDir::new("alternate-history")?;
    let canonical = CommitCombiner::new(
        history_test_sink(&canonical_dir, V2MerkleEpoch)?,
        CommitCombinerConfig::default(),
    )?;
    let alternate = CommitCombiner::new(
        history_test_sink(&alternate_dir, V2MerkleEpoch)?,
        CommitCombinerConfig::default(),
    )?;
    // Identical object revisions under different batch IDs produce the same authority
    // root but a different history commitment.
    let mut first = make_event_proposal(0, 1, None)?;
    let canonical_commit = canonical.submit(first.clone())?;
    first.request_digest = ContentDigest::sha256(b"alternate-request");
    let alternate_commit = alternate.submit(first)?;
    assert_eq!(
        canonical_commit.commit_sequence,
        alternate_commit.commit_sequence
    );
    assert_eq!(
        canonical_commit.authority_root,
        alternate_commit.authority_root
    );
    assert_ne!(canonical_commit.history_root, alternate_commit.history_root);

    let (ledger, packs, _) = canonical.into_sink()?.into_parts();
    // Forwarding cites a payload already in the pack so closure verification alone
    // cannot reject the crossed history.
    let successor = make_event_proposal(0, 1, Some(1))?;
    let child = successor.deltas[0].payload_digest;
    let exact = ledger.prepare_batch(
        fss_core::BatchId::parse("exact-next")?,
        successor.deltas,
        [child],
    )?;
    let (_, _, wrong_projection) = alternate.into_sink()?.into_parts();
    let mixed = CommitCombiner::new(
        LedgerPackProjectionSink::new(ledger, Arc::clone(&packs), wrong_projection),
        CommitCombinerConfig::default(),
    )?;
    let next = make_event_proposal(0, 2, None)?;
    let digest = next.deltas[0].payload_digest;
    assert!(matches!(
        packs.read_verified(&digest),
        Err(fss_pack::PackError::MissingObject(_))
    ));
    assert!(mixed.submit(next).is_err());
    assert!(mixed.submit_exact_batch(exact).is_err());
    assert!(matches!(
        packs.read_verified(&digest),
        Err(fss_pack::PackError::MissingObject(_))
    ));
    let sink = mixed.into_sink()?;
    assert_eq!(sink.ledger().verify_full_chain()?.batches_verified, 1);
    assert_eq!(sink.ledger().history_root(), canonical_commit.history_root);
    assert_eq!(
        sink.projection().head_anchor().history_root,
        alternate_commit.history_root
    );
    Ok(())
}

#[test]
fn combiner_preserves_legacy_projection_history_mode() -> TestResult {
    use fss_projection_store::HistoryChainMode::V1LedgerOracle;

    let dir = TempDir::new("legacy-projection-history")?;
    let combiner = CommitCombiner::new(
        history_test_sink(&dir, V1LedgerOracle)?,
        CommitCombinerConfig::default(),
    )?;
    let _ = combiner.submit(make_event_proposal(0, 1, None)?)?;
    let next = combiner.submit(make_event_proposal(0, 2, None)?)?;
    let sink = combiner.into_sink()?;
    assert_eq!(next.commit_sequence, 2);
    assert_ne!(next.history_root, sink.ledger().history_root());
    assert_eq!(next.authority_root, sink.ledger().head_anchor().state_root);
    Ok(())
}

#[test]
fn combiner_canonical_sort_order_is_arrival_independent() -> TestResult {
    use fss_core::BatchId;
    use fss_projection_store::{CommitSink, SinkCommitOutcome};
    use std::sync::Condvar;

    struct GatedMockSink {
        seq: u64,
        first_entered: Arc<(Mutex<bool>, Condvar)>,
        release_first: Arc<(Mutex<bool>, Condvar)>,
        recorded_batches: Vec<(BatchId, Vec<ObjectId>)>,
    }

    impl CommitSink for GatedMockSink {
        fn current_object_generation(&self, _object_id: &ObjectId) -> Option<u64> {
            None
        }

        fn commit_coalesced_wave(
            &mut self,
            batch_id: BatchId,
            _objects: &[OwnedPackObject],
            deltas: Vec<EvidenceDelta>,
            _child_roots: Vec<ContentDigest>,
        ) -> Result<SinkCommitOutcome, CombinerError> {
            self.seq += 1;
            if self.seq == 1 {
                if let Ok(mut entered) = self.first_entered.0.lock() {
                    *entered = true;
                    self.first_entered.1.notify_all();
                }
                if let Ok(mut rel) = self.release_first.0.lock() {
                    while !*rel {
                        rel = match self.release_first.1.wait(rel) {
                            Ok(g) => g,
                            Err(_) => return Err(CombinerError::LockPoisoned),
                        };
                    }
                }
            }
            let ids: Vec<ObjectId> = deltas.iter().map(|d| d.object_id.clone()).collect();
            self.recorded_batches.push((batch_id.clone(), ids));
            let root = ContentDigest::sha256(batch_id.as_str().as_bytes());
            Ok(SinkCommitOutcome {
                commit_sequence: self.seq,
                batch_id,
                authority_root: root,
                history_root: root,
                batch_digest: root,
                fsyncs_executed: 2,
                checkpoint_failure: None,
                projection_snapshot_failure: None,
            })
        }
    }

    use std::sync::Mutex;

    type OrderRunResult = Result<(BatchId, Vec<(usize, usize)>), Box<dyn std::error::Error>>;
    let run_order = |arrival_order: [usize; 3]| -> OrderRunResult {
        let first_entered = Arc::new((Mutex::new(false), Condvar::new()));
        let release_first = Arc::new((Mutex::new(false), Condvar::new()));
        let sink = GatedMockSink {
            seq: 0,
            first_entered: Arc::clone(&first_entered),
            release_first: Arc::clone(&release_first),
            recorded_batches: Vec::new(),
        };
        let comb = Arc::new(CommitCombiner::new(sink, CommitCombinerConfig::default())?);

        // Hold wave 1 inside the combiner so wave 2 accumulates all 3 proposals in arrival_order.
        let c0 = Arc::clone(&comb);
        let h0 = thread::spawn(move || {
            let p = make_event_proposal(90, 1, None).map_err(|e| e.to_string())?;
            c0.submit(p).map_err(|e| e.to_string())
        });
        {
            let mut entered = first_entered.0.lock().map_err(|_| "lock poisoned")?;
            while !*entered {
                entered = first_entered.1.wait(entered).map_err(|_| "lock poisoned")?;
            }
        }

        let mut handles = Vec::new();
        for cam_idx in arrival_order {
            let c = Arc::clone(&comb);
            handles.push((
                cam_idx,
                thread::spawn(move || {
                    let p = make_event_proposal(cam_idx, 1, None).map_err(|e| e.to_string())?;
                    c.submit(p).map_err(|e| e.to_string())
                }),
            ));
            // Give each thread a moment to push into the pending queue in arrival_order.
            thread::sleep(std::time::Duration::from_millis(5));
        }

        {
            let mut rel = release_first.0.lock().map_err(|_| "lock poisoned")?;
            *rel = true;
            release_first.1.notify_all();
        }
        let _ = h0.join().map_err(|_| "h0 panic")??;
        let mut positions = Vec::new();
        let mut wave2_batch_id = None;
        for (cam_idx, h) in handles {
            let r = h.join().map_err(|_| "worker panic")??;
            assert_eq!(r.commit_sequence, 2);
            assert_eq!(r.coalesced_count, 3);
            wave2_batch_id = Some(r.batch_id);
            positions.push((cam_idx, r.proposal_position));
        }
        positions.sort_unstable();
        let bid = wave2_batch_id.ok_or("missing wave 2 batch_id")?;
        Ok((bid, positions))
    };

    let (fwd_batch_id, fwd_pos) = run_order([1, 2, 3])?;
    let (rev_batch_id, rev_pos) = run_order([3, 1, 2])?;
    assert_eq!(fwd_batch_id, rev_batch_id);
    assert_eq!(fwd_pos, vec![(1, 0), (2, 1), (3, 2)]);
    assert_eq!(rev_pos, vec![(1, 0), (2, 1), (3, 2)]);
    Ok(())
}
