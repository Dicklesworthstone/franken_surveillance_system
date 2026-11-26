#![forbid(unsafe_code)]
//! Receipt, snapshot, and IPC `ForwardBatchWriter` types for [`crate::storage::StorageEngine`].
//!
//! Semantic plane: `"authority"`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use fss_core::{BatchId, CanonicalEncoder, ContentDigest, ErrorId, ObjectId};
use fss_ipc::ActiveScrubStatus;
use fss_ledger::decode_batch;
use fss_pack::{CapacityPressure, PackScrubReport, ScrubVerdict as PackScrubVerdict};
use fss_projection_store::{
    CommitCombiner, FootageAdapterKind, LedgerPackProjectionSink, MvccProjectionStore,
    ProjectionStore, ScrubVerdict as ProjectionScrubVerdict,
};

use crate::control::{ForwardBatchReceipt, ForwardBatchWriter};
use crate::error::DaemonError;
use crate::manifest::CameraAdapterKind;
use crate::storage::forward_requests::{ForwardRequestReservation, ForwardRequestStore};

/// Receipt returned after one group-committed storage wave succeeds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageCommitReceipt {
    /// Committed canonical ledger sequence.
    pub commit_sequence: u64,
    /// Deterministic coalesced batch identifier.
    pub batch_id: BatchId,
    /// Committed authority state root.
    pub authority_root: ContentDigest,
    /// Committed history-chain root.
    pub history_root: ContentDigest,
    /// Canonical batch digest.
    pub batch_digest: ContentDigest,
    /// Optional ledger checkpoint failure after the canonical commit and projection succeeded.
    pub checkpoint_failure: Option<Arc<str>>,
    /// Optional projection snapshot failure after the canonical commit and projection succeeded.
    pub projection_snapshot_failure: Option<Arc<str>>,
    /// OS durability fsync barriers executed during this commit.
    pub fsyncs_executed: u64,
}

/// Summary emitted by [`crate::storage::StorageEngine::run_maintenance_tick`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceTickReport {
    /// Current capacity watermark pressure.
    pub pressure: CapacityPressure,
    /// True when critical capacity is 100% pinned (`ERR-STORAGE-QUOTA-PINNED-001`).
    pub quota_pinned: bool,
    /// Bytes protected by active holds, obligations, events, or canonical replay history.
    pub pinned_bytes: u64,
    /// Configured total local ring capacity cap in bytes.
    pub cap_bytes: u64,
    /// Number of unheld imports tombstoned in this tick.
    pub evicted_imports: u64,
    /// Physical bytes reclaimed by online pack compaction in this tick.
    pub bytes_reclaimed: u64,
    /// Sealed packfiles rewritten or unlinked in this tick.
    pub packs_compacted: u64,
    /// Incremental background scrubber pass report, if any.
    pub scrub_report: Option<PackScrubReport>,
    /// IPC-facing scrub status derived from the pass.
    pub scrub_status: ActiveScrubStatus,
}

/// Final verified storage state emitted by [`crate::storage::StorageEngine::shutdown_and_flush`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageShutdownSummary {
    /// Final committed ledger sequence.
    pub head_commit_sequence: u64,
    /// Final history-chain root digest.
    pub history_root: ContentDigest,
    /// Final Merkle state root digest.
    pub state_root: ContentDigest,
    /// Whether a non-empty active packfile was sealed on shutdown.
    pub sealed_pack_on_shutdown: bool,
    /// Number of epoch segments independently verified by `verify_full_chain()`.
    pub verified_epochs: u64,
    /// Number of committed batches independently verified by `verify_full_chain()`.
    pub verified_batches: u64,
    /// Distinct live (including tombstoned) objects verified at head.
    pub verified_live_objects: u64,
    /// Serialized bytes written for the compacted `mvcc.snap`.
    pub projection_snapshot_bytes: usize,
}

/// Point-in-time read-only view of storage head and ring metrics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageHeadSnapshot {
    /// Current committed sequence.
    pub commit_sequence: u64,
    /// Current history-chain root.
    pub history_root: ContentDigest,
    /// Current authority state root.
    pub state_root: ContentDigest,
    /// Cumulative on-disk `.fssp` packfile bytes.
    pub on_disk_pack_bytes: u64,
    /// Logical local ring occupancy, including protected canonical replay payloads.
    pub ring_used_bytes: u64,
    /// Configured ring capacity ceiling in bytes.
    pub ring_cap_bytes: u64,
    /// Current capacity pressure classification.
    pub pressure: CapacityPressure,
    /// True when 100%-pinned critical pressure paused new non-critical ingest.
    pub quota_pinned: bool,
    /// Latest incremental scrub status.
    pub scrub_status: ActiveScrubStatus,
}

pub(crate) struct CombinerForwardWriter {
    pub(crate) combiner: Arc<CommitCombiner<LedgerPackProjectionSink>>,
    pub(crate) forward_requests: Arc<ForwardRequestStore>,
    pub(crate) projection: Arc<MvccProjectionStore>,
    pub(crate) object_generations: Arc<Mutex<BTreeMap<ObjectId, u64>>>,
    pub(crate) retention_gate: Arc<Mutex<()>>,
    pub(crate) quota_pinned: Arc<AtomicBool>,
    pub(crate) pinned_bytes: Arc<AtomicU64>,
    pub(crate) cap_bytes: u64,
}

impl ForwardBatchWriter for CombinerForwardWriter {
    fn supports_durable_idempotency(&self) -> bool {
        true
    }

    fn forward_delta_batch_idempotent(
        &self,
        idempotency_key: ContentDigest,
        request_digest: ContentDigest,
        batch_bytes: &[u8],
    ) -> Result<ForwardBatchReceipt, DaemonError> {
        // Invalid wire bytes cannot have produced an effect and need no reservation.
        let batch = decode_batch(batch_bytes).map_err(|err| DaemonError::InvalidConfig {
            detail: format!("forwarded batch decode failed: {err}"),
        })?;
        // Enforce the payload binding here as well as in the IPC handler: direct
        // trait callers cannot pair an old caller digest with different batch bytes.
        let request_digest = forward_payload_binding(request_digest, batch_bytes)?;
        match self
            .forward_requests
            .reserve(idempotency_key, request_digest)?
        {
            ForwardRequestReservation::Completed(receipt) => {
                let head = self.projection.head_anchor();
                if receipt.commit_sequence > head.commit_sequence
                    || (receipt.commit_sequence == head.commit_sequence
                        && (receipt.history_root != head.history_root
                            || receipt.state_root != head.authority_root))
                {
                    return Err(DaemonError::Ipc(fss_ipc::IpcError::Refused {
                        request_id: 0,
                        error_id: ErrorId::parse("ERR-OP-RECONCILIATION-REQUIRED-001")?,
                        reason:
                            "forwarded completion is inconsistent with the current canonical head"
                                .to_owned(),
                        retryable: false,
                    }));
                }
                return Ok(receipt);
            }
            ForwardRequestReservation::Pending => {
                // Observe only: an existing claim never permits another append. The ledger
                // writer proves the complete original batch is its durable current head,
                // and the sink also proves the projection published that exact commit.
                let Some(committed) = self.combiner.receipt_for_exact_head(&batch)? else {
                    return Err(DaemonError::Ipc(fss_ipc::IpcError::Refused {
                        request_id: 0,
                        error_id: ErrorId::parse("ERR-OP-RECONCILIATION-REQUIRED-001")?,
                        reason: "pending forwarded request is not the exact verified canonical head; reconcile its outcome before retry"
                            .to_owned(),
                        retryable: false,
                    }));
                };
                let receipt = ForwardBatchReceipt {
                    commit_sequence: committed.sequence,
                    history_root: committed.history_root,
                    state_root: committed.anchor.state_root,
                    replayed: false,
                };
                {
                    let mut generations =
                        self.object_generations
                            .lock()
                            .map_err(|_| DaemonError::LockPoisoned {
                                component: "object_generations",
                            })?;
                    // A newer commit may follow the immutable receipt proof. Catch up the
                    // local generation cache without ever lowering a newer generation.
                    for delta in &batch.deltas {
                        generations
                            .entry(delta.object_id.clone())
                            .and_modify(|generation| {
                                *generation = (*generation).max(delta.new_generation);
                            })
                            .or_insert(delta.new_generation);
                    }
                }
                self.forward_requests
                    .complete(idempotency_key, request_digest, receipt)?;
                return Ok(ForwardBatchReceipt {
                    replayed: true,
                    ..receipt
                });
            }
            ForwardRequestReservation::Fresh => {}
        }
        let (commit_sequence, history_root, state_root) = self.forward_delta_batch(batch_bytes)?;
        let receipt = ForwardBatchReceipt {
            commit_sequence,
            history_root,
            state_root,
            replayed: false,
        };
        self.forward_requests
            .complete(idempotency_key, request_digest, receipt)?;
        Ok(receipt)
    }

    fn forward_delta_batch(
        &self,
        batch_bytes: &[u8],
    ) -> Result<(u64, ContentDigest, ContentDigest), DaemonError> {
        let batch = decode_batch(batch_bytes).map_err(|err| DaemonError::InvalidConfig {
            detail: format!("forwarded batch decode failed: {err}"),
        })?;
        let _guard = self
            .retention_gate
            .lock()
            .map_err(|_| DaemonError::LockPoisoned {
                component: "retention_gate",
            })?;
        // Hold releases and deletion authority must remain available to clear pinned pressure.
        let retention_control = batch.deltas.iter().all(|delta| {
            matches!(
                delta.family.as_str(),
                fss_projection_store::FAMILY_EVIDENCE_HOLD
                    | fss_projection_store::FAMILY_DELETION_TOMBSTONE
            )
        });
        if self.quota_pinned.load(Ordering::Acquire) && !retention_control {
            return Err(DaemonError::StorageQuotaPinned {
                pinned_bytes: self.pinned_bytes.load(Ordering::Acquire),
                cap_bytes: self.cap_bytes,
            });
        }
        // The supplied batch is an exact canonical successor, not a rebasing intent.
        // Its basis and full closure are validated under the combiner's commit mutex.
        let receipt = self.combiner.submit_exact_batch(batch.clone())?;
        if let Ok(mut gens) = self.object_generations.lock() {
            for delta in &batch.deltas {
                gens.entry(delta.object_id.clone())
                    .and_modify(|current| *current = (*current).max(delta.new_generation))
                    .or_insert(delta.new_generation);
            }
        }
        Ok((
            receipt.commit_sequence,
            receipt.history_root,
            receipt.authority_root,
        ))
    }
}

pub(crate) fn forward_payload_binding(
    request_digest: ContentDigest,
    batch_bytes: &[u8],
) -> Result<ContentDigest, DaemonError> {
    let mut binding = CanonicalEncoder::new();
    binding.text("fss.canonical.v1");
    binding.text("fss.daemon.forwarded_payload_binding.v1");
    binding.digest(request_digest);
    binding.digest(ContentDigest::sha256(batch_bytes));
    Ok(ContentDigest::sha256(&binding.finish_checked()?))
}

pub(crate) const fn map_footage_adapter(adapter: CameraAdapterKind) -> FootageAdapterKind {
    match adapter {
        CameraAdapterKind::Rtsp | CameraAdapterKind::Synthetic => FootageAdapterKind::Rtsp,
        CameraAdapterKind::Tutk => FootageAdapterKind::Tutk,
        CameraAdapterKind::UniFiProtect | CameraAdapterKind::OnvifHttp => FootageAdapterKind::Http,
    }
}

pub(crate) const fn map_scrub_verdict(verdict: PackScrubVerdict) -> ProjectionScrubVerdict {
    match verdict {
        PackScrubVerdict::Clean => ProjectionScrubVerdict::Clean,
        PackScrubVerdict::Degraded => ProjectionScrubVerdict::Degraded,
        PackScrubVerdict::Failed => ProjectionScrubVerdict::Failed,
    }
}

pub(crate) fn scrub_report_to_ipc_status(report: &PackScrubReport) -> ActiveScrubStatus {
    if report.verdict == PackScrubVerdict::Failed {
        let error_id =
            ErrorId::parse("ERR-DAEMON-STORAGE-001").unwrap_or_else(|_| unreachable_err_id());
        return ActiveScrubStatus::Failed { error_id };
    }
    if report.total_sealed_packs == 0 {
        ActiveScrubStatus::Idle
    } else if report.cycle_completed {
        ActiveScrubStatus::Completed {
            checked_objects: report.verified_objects,
            anomalies_found: report.findings.len() as u64,
        }
    } else {
        ActiveScrubStatus::Running {
            checked_objects: report.verified_objects,
            total_objects: report.verified_objects.max(1),
        }
    }
}

fn unreachable_err_id() -> ErrorId {
    loop {
        if let Ok(id) = ErrorId::parse("ERR-STORAGE-001") {
            return id;
        }
    }
}

pub(crate) fn sanitize_object_part(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(48));
    for ch in raw.chars().take(48) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "item".to_owned()
    } else {
        out
    }
}
