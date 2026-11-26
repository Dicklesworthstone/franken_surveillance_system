#![forbid(unsafe_code)]
//! A durable canonical append remains committed when optional checkpoints fail.
//! Invalid projected payloads must be refused before they enter canonical history.

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, EvidenceDeltaBatch, ObjectId, Plane,
    SensorId, TimestampNs,
};
use fss_ledger::{CommitReceipt, EpochLedgerConfig, IncompleteTailPolicy, MerkleEpochLedger};
use fss_pack::{PACK_KIND_METADATA, PackConfig, PackStore};
use fss_projection_store::{
    CombinerError, CommitCombiner, CommitCombinerConfig, CommitProposal, CommitSink,
    CoverageStatus, CoverageWitnessPayload, DoctorScrubReceipt, FAMILY_COVERAGE_WITNESS,
    InMemoryPayloadResolver, LedgerPackProjectionSink, MvccProjectionStore, OwnedPackObject,
    PackStorePayloadResolver, ProjectionError, ProjectionRecordPayload, ProjectionStore,
    ProjectionStoreConfig, ScrubVerdict, SinkCommitOutcome,
};

type TestResult = Result<(), Box<dyn Error>>;
static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Result<Self, Box<dyn Error>> {
        let index = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "fss-projection-commit-maintenance-{label}-{}-{index}",
            std::process::id()
        ));
        fs::create_dir(&root)?;
        Ok(Self(root))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn proposal(index: u64) -> Result<CommitProposal, Box<dyn Error>> {
    let interval = CaptureInterval::new(TimestampNs(0), TimestampNs(100))?;
    let payload = ProjectionRecordPayload::CoverageWitness(CoverageWitnessPayload {
        sensor_id: SensorId::parse(format!("sensor:maintenance:{index}"))?,
        zone_id: "zone:maintenance".to_owned(),
        window: interval,
        status: CoverageStatus::NotObservable,
        active_gaps: 1,
        health_conflicts: 0,
    })
    .encode_bytes()?;
    let digest = ContentDigest::sha256(&payload);
    Ok(CommitProposal {
        request_digest: ContentDigest::sha256(format!("maintenance-request-{index}").as_bytes()),
        sensor_scope: "sensor:maintenance".to_owned(),
        objects: vec![OwnedPackObject::with_digest(
            PACK_KIND_METADATA,
            0,
            payload,
            digest,
        )],
        deltas: vec![EvidenceDelta {
            delta_id: format!("maintenance-delta-{index}"),
            family: FAMILY_COVERAGE_WITNESS.to_owned(),
            object_id: ObjectId::parse(format!("obj:maintenance:{index}"))?,
            prior_generation: None,
            new_generation: 1,
            validity: interval,
            plane: Plane::Authority,
            payload_digest: digest,
            witness_digest: None,
            operation_id: None,
        }],
        batch_id_prefix: format!("maintenance-{index}"),
    })
}

fn stores(
    dir: &TempDir,
    checkpoint_stride: u64,
    snapshot_stride: u64,
) -> Result<(LedgerPackProjectionSink, Arc<MvccProjectionStore>), Box<dyn Error>> {
    let ledger = MerkleEpochLedger::open(
        dir.0.join("ledger"),
        "site:commit-maintenance",
        EpochLedgerConfig {
            checkpoint_stride,
            ..EpochLedgerConfig::default()
        },
        IncompleteTailPolicy::Reject,
    )?;
    let packs = Arc::new(PackStore::open(dir.0.join("packs"), PackConfig::default())?);
    let projection = Arc::new(MvccProjectionStore::open_empty(
        dir.0.join("projection"),
        ledger.genesis_anchor(),
        ProjectionStoreConfig {
            snapshot_stride,
            ..ProjectionStoreConfig::default()
        },
    )?);
    Ok((
        LedgerPackProjectionSink::new(ledger, packs, Arc::clone(&projection)),
        projection,
    ))
}

fn prepare_exact(
    sink: &LedgerPackProjectionSink,
    index: u64,
) -> Result<EvidenceDeltaBatch, Box<dyn Error>> {
    let prop = proposal(index)?;
    let inputs: Vec<_> = prop
        .objects
        .iter()
        .map(OwnedPackObject::as_pack_input)
        .collect();
    sink.pack_store().append_batch(&inputs)?;
    let children: Vec<_> = prop
        .deltas
        .iter()
        .map(|delta| delta.payload_digest)
        .collect();
    Ok(sink.ledger().prepare_batch(
        BatchId::parse(format!("maintenance-exact-{index}"))?,
        prop.deltas,
        children,
    )?)
}

#[test]
fn durable_checkpoint_failure_still_publishes_projection_and_next_commit() -> TestResult {
    let dir = TempDir::new("ledger")?;
    let (sink, projection) = stores(&dir, 1, 0)?;
    // Checkpoint staging cannot open this directory, after the epoch append succeeds.
    let blocked = dir
        .0
        .join("ledger/checkpoints/.seq-00000000000000000001.fssc.tmp");
    fs::create_dir(&blocked)?;
    let combiner = CommitCombiner::new(sink, CommitCombinerConfig::default())?;
    let first = combiner.submit(proposal(1)?)?;
    assert_eq!(first.commit_sequence, 1);
    assert_eq!(projection.head_anchor().commit_sequence, 1);
    assert_eq!(projection.head_anchor().history_root, first.history_root);
    assert!(
        first
            .checkpoint_failure
            .as_ref()
            .is_some_and(|detail| !detail.is_empty())
    );
    assert!(first.projection_snapshot_failure.is_none());
    assert_eq!(
        projection
            .query_coverage(&projection.snapshot_latest(), None, None)
            .len(),
        1
    );

    fs::remove_dir(&blocked)?;
    let second = combiner.submit(proposal(2)?)?;
    assert_eq!(second.commit_sequence, 2);
    assert_eq!(projection.head_anchor().commit_sequence, 2);
    assert!(second.checkpoint_failure.is_none());
    assert!(second.projection_snapshot_failure.is_none());
    let sink = combiner.into_sink()?;
    assert_eq!(sink.ledger().verify_full_chain()?.batches_verified, 2);
    let (ledger, packs, owned_projection) = sink.into_parts();
    drop(owned_projection);
    drop(projection);
    let reopened = MvccProjectionStore::open_or_rebuild(
        dir.0.join("projection"),
        &ledger,
        &PackStorePayloadResolver::new(&packs),
    )?;
    assert_eq!(reopened.head_anchor().history_root, second.history_root);
    assert_eq!(
        reopened
            .query_coverage(&reopened.snapshot_latest(), None, None)
            .len(),
        2
    );
    Ok(())
}

#[test]
fn projection_snapshot_failure_does_not_turn_a_published_commit_into_failure() -> TestResult {
    let dir = TempDir::new("projection")?;
    let (sink, projection) = stores(&dir, 0, 1)?;
    let snapshot = dir.0.join("projection/mvcc.snap");
    fs::rename(&snapshot, dir.0.join("projection/genesis.saved"))?;
    fs::create_dir(&snapshot)?;
    let combiner = CommitCombiner::new(sink, CommitCombinerConfig::default())?;
    let first = combiner.submit(proposal(1)?)?;
    assert_eq!(first.commit_sequence, 1);
    assert_eq!(projection.head_anchor().commit_sequence, 1);

    assert!(first.checkpoint_failure.is_none());
    assert!(
        first
            .projection_snapshot_failure
            .as_ref()
            .is_some_and(|detail| !detail.is_empty())
    );
    fs::remove_dir(&snapshot)?;
    projection.compact_snapshot()?;
    let second = combiner.submit(proposal(2)?)?;
    assert_eq!(second.commit_sequence, 2);
    assert!(second.checkpoint_failure.is_none());
    assert!(second.projection_snapshot_failure.is_none());
    let sink = combiner.into_sink()?;
    assert_eq!(sink.ledger().verify_full_chain()?.batches_verified, 2);
    Ok(())
}

#[test]
fn missing_or_malformed_projection_payload_cannot_poison_canonical_history() -> TestResult {
    for malformed in [false, true] {
        let dir = TempDir::new(if malformed { "malformed" } else { "missing" })?;
        let (sink, projection) = stores(&dir, 0, 0)?;
        let combiner = CommitCombiner::new(sink, CommitCombinerConfig::default())?;
        let mut bad = proposal(1)?;
        if malformed {
            let raw = b"not a coverage witness".to_vec();
            let digest = ContentDigest::sha256(&raw);
            bad.objects = vec![OwnedPackObject::with_digest(
                PACK_KIND_METADATA,
                0,
                raw,
                digest,
            )];
            bad.deltas[0].payload_digest = digest;
        } else {
            bad.objects.clear();
        }
        assert!(combiner.submit(bad).is_err());
        assert_eq!(projection.head_anchor().commit_sequence, 0);
        // The exact same object generation remains admissible; no malformed canonical row exists.
        let receipt = combiner.submit(proposal(1)?)?;
        assert_eq!(receipt.commit_sequence, 1);
        let sink = combiner.into_sink()?;
        assert_eq!(sink.ledger().verify_full_chain()?.batches_verified, 1);
    }
    Ok(())
}

#[test]
fn simultaneous_maintenance_failures_preserve_both_owners_and_committed_receipt() -> TestResult {
    let dir = TempDir::new("both")?;
    let (sink, projection) = stores(&dir, 1, 1)?;
    fs::create_dir(
        dir.0
            .join("ledger/checkpoints/.seq-00000000000000000001.fssc.tmp"),
    )?;
    fs::create_dir(dir.0.join("projection/.mvcc.snap.tmp"))?;
    let combiner = CommitCombiner::new(sink, CommitCombinerConfig::default())?;
    let receipt = combiner.submit(proposal(1)?)?;
    assert_eq!(receipt.commit_sequence, 1);
    assert_eq!(projection.head_anchor().history_root, receipt.history_root);
    assert!(receipt.checkpoint_failure.is_some());
    assert!(receipt.projection_snapshot_failure.is_some());
    let sink = combiner.into_sink()?;
    assert_eq!(sink.ledger().verify_full_chain()?.batches_verified, 1);
    Ok(())
}

#[test]
fn public_projection_apply_reports_already_visible_anchor_on_maintenance_failure() -> TestResult {
    let dir = TempDir::new("public-apply")?;
    let (sink, projection) = stores(&dir, 0, 1)?;
    let (mut ledger, _packs, _owned_projection) = sink.into_parts();
    let prop = proposal(1)?;
    let resolver = InMemoryPayloadResolver::new();
    for object in &prop.objects {
        resolver.insert(object.payload.clone())?;
    }
    let batch = ledger.prepare_batch(BatchId::parse("public-apply")?, prop.deltas, Vec::new())?;
    ledger.append_batch(batch.clone())?;
    fs::create_dir(dir.0.join("projection/.mvcc.snap.tmp"))?;
    let result = projection.apply_delta_batch(&batch, &resolver);
    let Err(ProjectionError::AppliedMaintenanceFailed { anchor, source }) = result else {
        return Err("expected an already-applied maintenance failure".into());
    };
    assert_eq!(anchor, projection.head_anchor());
    assert_eq!(anchor.commit_sequence, 1);
    assert!(matches!(*source, ProjectionError::Io { .. }));
    assert_eq!(
        projection
            .query_coverage(&projection.snapshot_latest(), None, None)
            .len(),
        1
    );
    fs::remove_dir(dir.0.join("projection/.mvcc.snap.tmp"))?;
    projection.compact_snapshot()?;
    assert!(matches!(
        projection.apply_delta_batch(&batch, &resolver),
        Err(ProjectionError::AnchorMismatch { .. })
    ));
    Ok(())
}

#[test]
fn lagging_projection_fences_new_canonical_commits_before_pack_io() -> TestResult {
    let dir = TempDir::new("lagging")?;
    let (sink, projection) = stores(&dir, 0, 0)?;
    let (mut ledger, packs, _owned_projection) = sink.into_parts();
    let batch =
        ledger.prepare_batch(BatchId::parse("already-committed")?, Vec::new(), Vec::new())?;
    ledger.append_batch(batch)?;
    let before = packs.telemetry_snapshot()?.pack_fsync_count;
    let mut sink = LedgerPackProjectionSink::new(ledger, Arc::clone(&packs), projection);
    let prop = proposal(1)?;
    let result = sink.commit_coalesced_wave(
        BatchId::parse("must-not-commit")?,
        &prop.objects,
        prop.deltas,
        Vec::new(),
    );
    assert!(matches!(
        result,
        Err(CombinerError::Projection(ProjectionError::AnchorMismatch {
            expected_sequence: 1,
            actual_sequence: 0,
            ..
        }))
    ));
    assert_eq!(packs.telemetry_snapshot()?.pack_fsync_count, before);
    assert_eq!(sink.ledger().head_anchor().commit_sequence, 1);
    assert_eq!(sink.ledger().verify_full_chain()?.batches_verified, 1);
    Ok(())
}

#[test]
fn scrub_receipt_stays_visible_when_snapshot_maintenance_fails() -> TestResult {
    let dir = TempDir::new("scrub")?;
    let (_sink, projection) = stores(&dir, 0, 1)?;
    let receipt = DoctorScrubReceipt {
        scrubbed_at_ns: TimestampNs(100),
        anchor: projection.head_anchor(),
        first_seq: 0,
        last_seq: 0,
        verified_objects: 0,
        verified_packs: 0,
        verified_fraction_ppm: 0,
        verdict: ScrubVerdict::Degraded,
    };
    fs::create_dir(dir.0.join("projection/.mvcc.snap.tmp"))?;
    let result = projection.record_scrub_receipt(receipt.clone());
    assert!(matches!(
        result,
        Err(ProjectionError::AppliedMaintenanceFailed { anchor, .. })
            if anchor == receipt.anchor
    ));
    assert_eq!(projection.latest_scrub_receipt(), Some(receipt));
    fs::remove_dir(dir.0.join("projection/.mvcc.snap.tmp"))?;
    projection.compact_snapshot()?;
    Ok(())
}

#[test]
fn combiner_preserves_typed_postcommit_projection_failure_and_exact_receipt() -> TestResult {
    struct FailingPublicationSink {
        receipt: Arc<CommitReceipt>,
    }

    impl CommitSink for FailingPublicationSink {
        fn current_object_generation(&self, _object_id: &ObjectId) -> Option<u64> {
            None
        }

        fn commit_coalesced_wave(
            &mut self,
            _batch_id: BatchId,
            _objects: &[OwnedPackObject],
            _deltas: Vec<EvidenceDelta>,
            _child_roots: Vec<ContentDigest>,
        ) -> Result<SinkCommitOutcome, CombinerError> {
            Err(CombinerError::CommittedProjectionFailed {
                receipt: Arc::clone(&self.receipt),
                checkpoint_failure: Some(Arc::<str>::from("checkpoint failed after commitment")),
                source: Arc::new(ProjectionError::LockPoisoned),
            })
        }
    }

    let dir = TempDir::new("receipt")?;
    let (sink, _projection) = stores(&dir, 0, 0)?;
    let (mut ledger, _packs, _owned_projection) = sink.into_parts();
    let batch =
        ledger.prepare_batch(BatchId::parse("publication-fault")?, Vec::new(), Vec::new())?;
    let canonical_receipt = Arc::new(ledger.append_batch(batch)?);
    let combiner = CommitCombiner::new(
        FailingPublicationSink {
            receipt: Arc::clone(&canonical_receipt),
        },
        CommitCombinerConfig::default(),
    )?;
    let result = combiner.submit(proposal(1)?);
    let Err(CombinerError::CommittedProjectionFailed {
        receipt,
        checkpoint_failure,
        source,
    }) = result
    else {
        return Err("combiner erased an already-committed receipt".into());
    };
    assert!(Arc::ptr_eq(&receipt, &canonical_receipt));
    assert_eq!(receipt.sequence, 1);
    assert_eq!(receipt.anchor, *ledger.head_anchor());
    assert_eq!(
        checkpoint_failure.as_deref(),
        Some("checkpoint failed after commitment")
    );
    assert!(matches!(source.as_ref(), ProjectionError::LockPoisoned));
    Ok(())
}

#[test]
fn exact_batch_reports_both_maintenance_failures_and_retains_head_recovery() -> TestResult {
    let dir = TempDir::new("exact-maintenance")?;
    let (sink, projection) = stores(&dir, 1, 1)?;
    let batch = prepare_exact(&sink, 1)?;
    let checkpoint_blocker = dir
        .0
        .join("ledger/checkpoints/.seq-00000000000000000001.fssc.tmp");
    let snapshot_blocker = dir.0.join("projection/.mvcc.snap.tmp");
    fs::create_dir(&checkpoint_blocker)?;
    fs::create_dir(&snapshot_blocker)?;
    let combiner = CommitCombiner::new(sink, CommitCombinerConfig::default())?;
    let receipt = combiner.submit_exact_batch(batch.clone())?;
    assert_eq!(receipt.commit_sequence, 1);
    assert_eq!(receipt.batch_id, batch.batch_id);
    assert_eq!(receipt.batch_digest, batch.batch_digest);
    assert!(receipt.checkpoint_failure.is_some());
    assert!(receipt.projection_snapshot_failure.is_some());
    assert_eq!(projection.head_anchor().history_root, receipt.history_root);
    let recovered = combiner
        .receipt_for_exact_head(&batch)?
        .ok_or("published exact head lost its receipt")?;
    assert_eq!(recovered.batch_digest, receipt.batch_digest);
    assert_eq!(recovered.anchor, batch.new_anchor);
    fs::remove_dir(&checkpoint_blocker)?;
    fs::remove_dir(&snapshot_blocker)?;
    projection.compact_snapshot()?;

    let sink = combiner.into_sink()?;
    let next = prepare_exact(&sink, 2)?;
    let combiner = CommitCombiner::new(sink, CommitCombinerConfig::default())?;
    let receipt = combiner.submit_exact_batch(next.clone())?;
    assert_eq!(receipt.commit_sequence, 2);
    assert_eq!(receipt.batch_digest, next.batch_digest);
    assert!(receipt.checkpoint_failure.is_none());
    assert!(receipt.projection_snapshot_failure.is_none());
    let sink = combiner.into_sink()?;
    assert_eq!(sink.ledger().verify_full_chain()?.batches_verified, 2);
    Ok(())
}
