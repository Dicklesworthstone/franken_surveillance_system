#![forbid(unsafe_code)]
//! Exact canonical forwarding must preserve its basis, successor, and custody closure.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, EvidenceDeltaBatch, ObjectId, Plane,
    TimestampNs,
};
use fss_ledger::{EpochLedgerConfig, IncompleteTailPolicy, MerkleEpochLedger};
use fss_pack::{PACK_KIND_METADATA, PackConfig, PackObjectInput, PackStore};
use fss_projection_store::{
    CanonicalBatchSource, CombinerError, CommitCombiner, CommitCombinerConfig, CommitProposal,
    CommitSink, LedgerPackProjectionSink, MvccProjectionStore, OwnedPackObject, ProjectionStore,
    ProjectionStoreConfig, SinkCommitOutcome,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self, std::io::Error> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "fss-exact-batch-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn open_sink(dir: &TempDir) -> Result<LedgerPackProjectionSink, Box<dyn std::error::Error>> {
    open_sink_with_config(dir, EpochLedgerConfig::default())
}

fn open_sink_with_config(
    dir: &TempDir,
    config: EpochLedgerConfig,
) -> Result<LedgerPackProjectionSink, Box<dyn std::error::Error>> {
    let ledger = MerkleEpochLedger::open(
        dir.0.join("ledger"),
        "site:exact-batch",
        config,
        IncompleteTailPolicy::Reject,
    )?;
    let packs = Arc::new(PackStore::open(
        dir.0.join("packs"),
        PackConfig::default(),
    )?);
    let projection = Arc::new(MvccProjectionStore::open_empty(
        dir.0.join("projection"),
        ledger.genesis_anchor(),
        ProjectionStoreConfig::default(),
    )?);
    Ok(LedgerPackProjectionSink::new(ledger, packs, projection))
}

fn prepare(
    sink: &LedgerPackProjectionSink,
    label: &str,
) -> Result<EvidenceDeltaBatch, Box<dyn std::error::Error>> {
    let payload = b"synthetic exact-batch metadata";
    sink.pack_store()
        .append_batch(&[PackObjectInput::new(PACK_KIND_METADATA, 0, payload)])?;
    let digest = ContentDigest::sha256(payload);
    Ok(sink.ledger().prepare_batch(
        BatchId::parse(format!("batch:exact:{label}"))?,
        vec![EvidenceDelta {
            delta_id: format!("delta:exact:{label}"),
            family: "synthetic_exact_metadata".to_owned(),
            object_id: ObjectId::parse(format!("obj:exact:{label}"))?,
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(0), TimestampNs(1))?,
            plane: Plane::Authority,
            payload_digest: digest,
            witness_digest: None,
            operation_id: None,
        }],
        [digest],
    )?)
}

fn proposal(batch: &EvidenceDeltaBatch) -> CommitProposal {
    CommitProposal {
        request_digest: batch.batch_digest,
        sensor_scope: "camera:ordinary".to_owned(),
        objects: Vec::new(),
        deltas: batch.deltas.clone(),
        batch_id_prefix: "ordinary".to_owned(),
    }
}

#[test]
fn exact_batch_preserves_identity_successor_and_extra_children_across_reopen() -> TestResult {
    let dir = TempDir::new()?;
    let sink = open_sink(&dir)?;
    let mut batch = prepare(&sink, "preserved")?;
    let witness = b"exact witness bytes";
    let extra = b"additional declared closure member";
    sink.pack_store().append_batch(&[
        PackObjectInput::new(PACK_KIND_METADATA, 0, witness),
        PackObjectInput::new(PACK_KIND_METADATA, 0, extra),
    ])?;
    batch.deltas[0].witness_digest = Some(ContentDigest::sha256(witness));
    batch.children.extend([
        ContentDigest::sha256(witness),
        ContentDigest::sha256(extra),
    ]);
    batch.children.sort_unstable();
    batch.batch_digest = batch.computed_digest();
    let combiner = CommitCombiner::new(sink, CommitCombinerConfig::default())?;
    let receipt = combiner.submit_exact_batch(batch.clone())?;
    assert_eq!(receipt.batch_id, batch.batch_id);
    assert_eq!(receipt.batch_digest, batch.batch_digest);
    assert_eq!(receipt.authority_root, batch.new_anchor.state_root);
    assert_eq!(receipt.coalesced_count, 1);
    let sink = combiner.into_sink()?;
    assert_eq!(sink.ledger().read_batches_range(1, 1)?, vec![batch.clone()]);
    drop(sink);

    let reopened = MerkleEpochLedger::open(
        dir.0.join("ledger"),
        "site:exact-batch",
        EpochLedgerConfig::default(),
        IncompleteTailPolicy::Reject,
    )?;
    assert_eq!(reopened.head_anchor(), &batch.new_anchor);
    assert_eq!(reopened.read_batches_range(1, 1)?, vec![batch]);
    Ok(())
}

#[test]
fn exact_batch_rejects_forked_and_invented_anchors_without_publishing() -> TestResult {
    let dir = TempDir::new()?;
    let sink = open_sink(&dir)?;
    let batch = prepare(&sink, "anchors")?;
    let projection = Arc::clone(sink.projection());
    let combiner = CommitCombiner::new(sink, CommitCombinerConfig::default())?;
    let mut forks = Vec::new();
    let mut other_site = batch.clone();
    other_site.basis_anchor.site_lineage = "site:other".to_owned();
    other_site.new_anchor.site_lineage = "site:other".to_owned();
    forks.push(other_site);
    let mut other_state = batch.clone();
    other_state.basis_anchor.state_root = ContentDigest::sha256(b"other history");
    forks.push(other_state);
    let mut other_policy = batch.clone();
    other_policy.basis_anchor.policy_epoch += 1;
    other_policy.new_anchor.policy_epoch += 1;
    forks.push(other_policy);
    let mut invalid_successor = batch.clone();
    invalid_successor.new_anchor.state_root = ContentDigest::sha256(b"invented successor");
    forks.push(invalid_successor);
    for mut fork in forks {
        fork.batch_digest = fork.computed_digest();
        assert!(combiner.submit_exact_batch(fork).is_err());
        assert_eq!(projection.head_anchor().commit_sequence, 0);
    }
    let receipt = combiner.submit_exact_batch(batch)?;
    assert_eq!(receipt.commit_sequence, 1);
    Ok(())
}

#[test]
fn exact_batch_requires_children_payloads_and_witnesses_before_publication() -> TestResult {
    let dir = TempDir::new()?;
    let sink = open_sink(&dir)?;
    let valid = prepare(&sink, "custody")?;
    let missing = ContentDigest::sha256(b"not retained anywhere");
    let mut missing_child = valid.clone();
    missing_child.children.push(missing);
    missing_child.children.sort_unstable();
    missing_child.batch_digest = missing_child.computed_digest();
    let mut missing_witness = valid.clone();
    missing_witness.deltas[0].witness_digest = Some(missing);
    missing_witness.batch_digest = missing_witness.computed_digest();
    let mut delta = valid.deltas[0].clone();
    delta.payload_digest = missing;
    let missing_payload = sink.ledger().prepare_batch(
        BatchId::parse("batch:missing-payload")?,
        vec![delta],
        [],
    )?;
    let projection = Arc::clone(sink.projection());
    let combiner = CommitCombiner::new(sink, CommitCombinerConfig::default())?;
    for batch in [missing_child, missing_witness, missing_payload] {
        assert!(combiner.submit_exact_batch(batch).is_err());
        assert_eq!(projection.head_anchor().commit_sequence, 0);
    }
    assert_eq!(combiner.submit_exact_batch(valid)?.commit_sequence, 1);
    Ok(())
}

struct GatedSink {
    inner: LedgerPackProjectionSink,
    entered: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
    gate_next: bool,
}

impl CommitSink for GatedSink {
    fn current_object_generation(&self, object_id: &ObjectId) -> Option<u64> {
        self.inner.current_object_generation(object_id)
    }

    fn commit_exact_batch(
        &mut self,
        batch: EvidenceDeltaBatch,
    ) -> Result<SinkCommitOutcome, CombinerError> {
        self.inner.commit_exact_batch(batch)
    }

    fn commit_coalesced_wave(
        &mut self,
        batch_id: BatchId,
        objects: &[OwnedPackObject],
        deltas: Vec<EvidenceDelta>,
        child_roots: Vec<ContentDigest>,
    ) -> Result<SinkCommitOutcome, CombinerError> {
        if self.gate_next {
            self.gate_next = false;
            self.entered
                .send(())
                .map_err(|err| CombinerError::SinkFailure(err.to_string()))?;
            self.release
                .recv_timeout(Duration::from_secs(10))
                .map_err(|err| CombinerError::SinkFailure(err.to_string()))?;
        }
        self.inner
            .commit_coalesced_wave(batch_id, objects, deltas, child_roots)
    }
}

#[test]
fn queued_exact_batch_rechecks_basis_under_the_commit_lock() -> TestResult {
    let dir = TempDir::new()?;
    let sink = open_sink(&dir)?;
    let ordinary = prepare(&sink, "ordinary")?;
    let stale = prepare(&sink, "queued")?;
    let stale_object = stale.deltas[0].object_id.clone();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let combiner = Arc::new(CommitCombiner::new(
        GatedSink {
            inner: sink,
            entered: entered_tx,
            release: release_rx,
            gate_next: true,
        },
        CommitCombinerConfig::default(),
    )?);
    let ordinary_combiner = Arc::clone(&combiner);
    let ordinary_writer = thread::spawn(move || {
        ordinary_combiner
            .submit(proposal(&ordinary))
            .map_err(|err| err.to_string())
    });
    entered_rx.recv_timeout(Duration::from_secs(10))?;
    let exact_combiner = Arc::clone(&combiner);
    let exact_writer = thread::spawn(move || {
        exact_combiner
            .submit_exact_batch(stale)
            .map_err(|err| err.to_string())
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while combiner.pending_len()? == 0 {
        if Instant::now() >= deadline {
            return Err("exact submission did not reach the bounded queue".into());
        }
        thread::yield_now();
    }
    release_tx.send(())?;
    let ordinary_receipt = ordinary_writer.join().map_err(|_| "ordinary writer panicked")??;
    assert_eq!(ordinary_receipt.commit_sequence, 1);
    assert!(exact_writer.join().map_err(|_| "exact writer panicked")?.is_err());
    let combiner = Arc::try_unwrap(combiner).map_err(|_| "combiner still shared")?;
    let sink = combiner.into_sink()?.inner;
    assert_eq!(sink.ledger().commit_sequence(), 1);
    assert!(sink.ledger().get_object(&stale_object).is_none());
    Ok(())
}

#[test]
fn exact_batch_keeps_the_committed_receipt_after_checkpoint_failure() -> TestResult {
    let dir = TempDir::new()?;
    let sink = open_sink_with_config(
        &dir,
        EpochLedgerConfig {
            checkpoint_stride: 1,
            ..EpochLedgerConfig::default()
        },
    )?;
    let batch = prepare(&sink, "checkpoint")?;
    let projection = Arc::clone(sink.projection());
    let blocked = dir
        .0
        .join("ledger/checkpoints")
        .join(format!(".seq-{:020}.fssc.tmp", 1));
    fs::create_dir(&blocked)?;
    let combiner = CommitCombiner::new(sink, CommitCombinerConfig::default())?;
    let receipt = combiner.submit_exact_batch(batch.clone())?;
    assert!(receipt.checkpoint_failure.is_some());
    assert_eq!(receipt.batch_digest, batch.batch_digest);
    assert_eq!(projection.head_anchor().commit_sequence, 1);
    assert_eq!(projection.head_anchor().high_water_digest, batch.batch_digest);
    fs::remove_dir(blocked)?;
    let sink = combiner.into_sink()?;
    assert_eq!(sink.ledger().read_batches_range(1, 1)?, vec![batch]);
    Ok(())
}

#[test]
fn exact_batch_preserves_committed_projection_failure_and_fences_later_appends() -> TestResult {
    let dir = TempDir::new()?;
    let sink = open_sink(&dir)?;
    let source = prepare(&sink, "projection-fault")?;
    let mut deltas = source.deltas.clone();
    // Bytes exist and are authentic, but cannot decode as this projected family.
    deltas[0].family = fss_projection_store::FAMILY_EVENT_REVISION.to_owned();
    deltas[0].plane = Plane::Cognition;
    let offered = sink.ledger().prepare_batch(
        source.batch_id.clone(),
        deltas,
        source.children.clone(),
    )?;
    let projection = Arc::clone(sink.projection());
    let combiner = CommitCombiner::new(sink, CommitCombinerConfig::default())?;
    let Err(CombinerError::CommittedProjectionFailed { receipt, .. }) =
        combiner.submit_exact_batch(offered.clone())
    else {
        return Err("projection failure lost the exact durable receipt".into());
    };
    assert_eq!(receipt.sequence, 1);
    assert_eq!(receipt.batch_digest, offered.batch_digest);
    assert_eq!(projection.head_anchor().commit_sequence, 0);
    let sink = combiner.into_sink()?;
    let next = prepare(&sink, "after-projection-fault")?;
    assert_eq!(next.basis_anchor.commit_sequence, 1);
    let combiner = CommitCombiner::new(sink, CommitCombinerConfig::default())?;
    assert!(combiner.submit_exact_batch(next).is_err());
    let sink = combiner.into_sink()?;
    assert_eq!(sink.ledger().commit_sequence(), 1);
    assert_eq!(sink.ledger().read_batches_range(1, 1)?, vec![offered]);
    Ok(())
}
