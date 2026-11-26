#![forbid(unsafe_code)]
//! Deterministic catch-up, corrupt-file quarantine, full rebuild from canonical ledger history,
//! and batch-advance verification for [`MvccProjectionStore`].

use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

use fss_core::{ContentDigest, EvidenceDeltaBatch, LedgerAnchor};

use crate::error::{ProjectionError, ProjectionIoOperation};
use crate::history::CanonicalBatchSource;
use crate::payloads::PayloadResolver;
use crate::schema::{HistoryChainMode, ProjectionAnchor};
use crate::snapshot::ProjectionSnapshot;
use crate::store::{
    MvccProjectionStore, MvccReadState, MvccWriterState, ProjectionRebuildReason,
    ProjectionRecoveryMode, ProjectionRecoveryReport, ProjectionStoreConfig,
};
use crate::wal::{
    ProjectionWal, WAL_FILENAME, WalRecord, load_snapshot_if_present, quarantine_derived_files,
    visit_verified_wal, write_snapshot_atomic,
};

impl MvccProjectionStore {
    /// Opens an existing projection directory or deterministically catches up / rebuilds bit-for-bit
    /// from `ledger_backend` using default configuration.
    pub fn open_or_rebuild<L: CanonicalBatchSource>(
        projection_dir: impl AsRef<Path>,
        ledger_backend: &L,
        payload_resolver: &dyn PayloadResolver,
    ) -> Result<Self, ProjectionError> {
        let config = ProjectionStoreConfig {
            history_mode: ledger_backend.history_mode(),
            ..ProjectionStoreConfig::default()
        };
        Self::open_or_rebuild_with_config(projection_dir, ledger_backend, payload_resolver, config)
    }

    /// Opens an existing projection directory or deterministically catches up / rebuilds bit-for-bit
    /// from `ledger_backend` with explicit [`ProjectionStoreConfig`].
    pub fn open_or_rebuild_with_config<L: CanonicalBatchSource>(
        projection_dir: impl AsRef<Path>,
        ledger_backend: &L,
        payload_resolver: &dyn PayloadResolver,
        mut config: ProjectionStoreConfig,
    ) -> Result<Self, ProjectionError> {
        config.validate()?;
        config.history_mode = ledger_backend.history_mode();

        let dir = projection_dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::CreateDir, err))?;

        let genesis_ledger = ledger_backend.genesis_anchor();
        let head_ledger = ledger_backend.head_ledger_anchor();
        let genesis_anchor = ProjectionAnchor::genesis(&genesis_ledger, config.history_mode)?;

        let try_existing = try_load_existing_state(
            &dir,
            genesis_anchor,
            config.history_mode,
            ledger_backend,
            payload_resolver,
        )?;

        match try_existing {
            ExistingLoadOutcome::Valid {
                snapshot,
                loaded_snapshot_seq,
                replayed_wal_frames,
            } => {
                let mut snapshot = *snapshot;
                let (retained_history, replayed_ledger_batches) = replay_to_head(
                    &mut snapshot,
                    ledger_backend,
                    &head_ledger,
                    payload_resolver,
                    config.max_retained_snapshots,
                )?;
                let mode = if replayed_ledger_batches == 0 {
                    ProjectionRecoveryMode::LoadedCurrent
                } else {
                    ProjectionRecoveryMode::CaughtUpFromSnapshot
                };

                let mut wal = ProjectionWal::open_append(&dir, config.wal_sync, config.durability)?;
                if replayed_ledger_batches > 0 {
                    let _ = write_snapshot_atomic(&dir, &snapshot, config.durability)?;
                    wal.reset_empty()?;
                }

                let read_state = build_read_state(retained_history, config.max_retained_snapshots);
                let head_anchor = read_state.latest.anchor;
                let recovery_report = ProjectionRecoveryReport {
                    mode,
                    rebuild_reason: None,
                    loaded_snapshot_seq,
                    replayed_wal_frames,
                    replayed_ledger_batches,
                    quarantined_files: Vec::new(),
                    head_anchor,
                };
                Ok(Self {
                    read_state: RwLock::new(read_state),
                    writer: Mutex::new(MvccWriterState { dir, config, wal }),
                    recovery_report,
                })
            }
            ExistingLoadOutcome::NeedsRebuild(reason) => {
                let quarantined_files = quarantine_derived_files(&dir)?;
                let mut snapshot = ProjectionSnapshot::empty(genesis_anchor, config.history_mode);
                let (retained_history, replayed_ledger_batches) = replay_to_head(
                    &mut snapshot,
                    ledger_backend,
                    &head_ledger,
                    payload_resolver,
                    config.max_retained_snapshots,
                )?;

                let _ = write_snapshot_atomic(&dir, &snapshot, config.durability)?;
                let mut wal = ProjectionWal::open_append(&dir, config.wal_sync, config.durability)?;
                wal.reset_empty()?;

                let read_state = build_read_state(retained_history, config.max_retained_snapshots);
                let head_anchor = read_state.latest.anchor;
                let recovery_report = ProjectionRecoveryReport {
                    mode: ProjectionRecoveryMode::RebuiltFromGenesis,
                    rebuild_reason: Some(reason),
                    loaded_snapshot_seq: None,
                    replayed_wal_frames: 0,
                    replayed_ledger_batches,
                    quarantined_files,
                    head_anchor,
                };
                Ok(Self {
                    read_state: RwLock::new(read_state),
                    writer: Mutex::new(MvccWriterState { dir, config, wal }),
                    recovery_report,
                })
            }
        }
    }
}

/// Replays canonical batches directly into the working projection. Only snapshots inside the
/// final retention window can be served after open, so older intermediate states need no clone.
fn replay_to_head(
    snapshot: &mut ProjectionSnapshot,
    ledger: &impl CanonicalBatchSource,
    head: &LedgerAnchor,
    resolver: &dyn PayloadResolver,
    max_retained: usize,
) -> Result<(Vec<Arc<ProjectionSnapshot>>, u64), ProjectionError> {
    let start = snapshot.anchor.commit_sequence;
    let first_retained = head
        .commit_sequence
        .saturating_sub((max_retained - 1) as u64);
    let mut retained = Vec::new();
    if start >= first_retained {
        retained.push(Arc::new(snapshot.clone()));
    }
    if start < head.commit_sequence {
        ledger.visit_batches_range(start + 1, head.commit_sequence, &mut |batch| {
            advance_snapshot_in_place(snapshot, batch, resolver)?;
            if snapshot.anchor.commit_sequence >= first_retained {
                retained.push(Arc::new(snapshot.clone()));
            }
            Ok(())
        })?;
    }
    verify_final_anchor(snapshot, head, ledger.head_history_root())?;
    Ok((retained, head.commit_sequence - start))
}

/// Validates batch anchor/digest continuity and applies one [`EvidenceDeltaBatch`] to `snapshot`.
pub(crate) fn advance_snapshot_in_place(
    snapshot: &mut ProjectionSnapshot,
    batch: &EvidenceDeltaBatch,
    payload_resolver: &dyn PayloadResolver,
) -> Result<(), ProjectionError> {
    let computed = batch.computed_digest();
    if computed != batch.batch_digest {
        return Err(ProjectionError::BatchDigestMismatch {
            declared: batch.batch_digest,
            computed,
        });
    }
    if batch.basis_anchor.commit_sequence != snapshot.anchor.commit_sequence {
        return Err(ProjectionError::AnchorMismatch {
            expected_sequence: snapshot.anchor.commit_sequence,
            actual_sequence: batch.basis_anchor.commit_sequence,
            detail: "basis commit sequence does not match projection head",
        });
    }
    if batch.basis_anchor.state_root != snapshot.anchor.authority_root {
        return Err(ProjectionError::AnchorMismatch {
            expected_sequence: snapshot.anchor.commit_sequence,
            actual_sequence: batch.basis_anchor.commit_sequence,
            detail: "basis state_root does not match projection authority_root",
        });
    }
    let expected_next = snapshot
        .anchor
        .commit_sequence
        .checked_add(1)
        .ok_or(ProjectionError::ArithmeticOverflow("commit_sequence"))?;
    if batch.new_anchor.commit_sequence != expected_next {
        return Err(ProjectionError::AnchorMismatch {
            expected_sequence: expected_next,
            actual_sequence: batch.new_anchor.commit_sequence,
            detail: "successor commit_sequence is not basis + 1",
        });
    }

    let next_history_root = snapshot.history_mode.successor_root(
        snapshot.anchor.history_root,
        expected_next,
        batch.batch_digest,
        &batch.new_anchor,
    )?;

    let _summary = snapshot.tables.apply_batch(batch, payload_resolver)?;
    snapshot.anchor = ProjectionAnchor {
        commit_sequence: expected_next,
        authority_root: batch.new_anchor.state_root,
        history_root: next_history_root,
        high_water_digest: batch.batch_digest,
    };
    Ok(())
}

enum ExistingLoadOutcome {
    Valid {
        snapshot: Box<ProjectionSnapshot>,
        loaded_snapshot_seq: Option<u64>,
        replayed_wal_frames: u64,
    },
    NeedsRebuild(ProjectionRebuildReason),
}

fn try_load_existing_state<L: CanonicalBatchSource>(
    dir: &Path,
    genesis_anchor: ProjectionAnchor,
    history_mode: HistoryChainMode,
    ledger_backend: &L,
    payload_resolver: &dyn PayloadResolver,
) -> Result<ExistingLoadOutcome, ProjectionError> {
    let snap_loaded = match load_snapshot_if_present(dir) {
        Ok(opt) => opt,
        Err(ProjectionError::CorruptDerivedStore { .. }) => {
            return Ok(ExistingLoadOutcome::NeedsRebuild(
                ProjectionRebuildReason::CorruptSnapshot,
            ));
        }
        Err(err) => return Err(err),
    };

    let wal_path = dir.join(WAL_FILENAME);
    let wal_exists = wal_path.exists();
    if snap_loaded.is_none() && !wal_exists {
        return Ok(ExistingLoadOutcome::NeedsRebuild(
            ProjectionRebuildReason::Missing,
        ));
    }

    let loaded_snapshot_seq = snap_loaded.as_ref().map(|s| s.anchor.commit_sequence);
    let mut snapshot = match snap_loaded {
        Some(s) => {
            if s.history_mode != history_mode {
                return Ok(ExistingLoadOutcome::NeedsRebuild(
                    ProjectionRebuildReason::AnchorMismatch,
                ));
            }
            s
        }
        None => ProjectionSnapshot::empty(genesis_anchor, history_mode),
    };

    let mut replayed_wal_frames = 0_u64;
    let wal_result = visit_verified_wal(&wal_path, |rec| {
        match rec {
            WalRecord::ApplyBatch {
                commit_sequence,
                batch,
            } => {
                if commit_sequence <= snapshot.anchor.commit_sequence {
                    return Ok(());
                }
                if advance_snapshot_in_place(&mut snapshot, &batch, payload_resolver).is_err() {
                    return Err(ProjectionError::CorruptDerivedStore {
                        artifact: WAL_FILENAME,
                        detail: format!(
                            "WAL batch at sequence {commit_sequence} cannot advance the projection"
                        ),
                    });
                }
                replayed_wal_frames = replayed_wal_frames.saturating_add(1);
            }
            WalRecord::RecordScrubReceipt { receipt, .. } => {
                if receipt.validate().is_err()
                    || receipt.anchor.commit_sequence > snapshot.anchor.commit_sequence
                {
                    return Err(ProjectionError::CorruptDerivedStore {
                        artifact: WAL_FILENAME,
                        detail: "invalid or future WAL scrub receipt".to_owned(),
                    });
                }
                snapshot.scrub_receipt = Some(receipt);
                replayed_wal_frames = replayed_wal_frames.saturating_add(1);
            }
        }
        Ok(())
    });
    match wal_result {
        Ok(()) => {}
        Err(ProjectionError::CorruptDerivedStore { .. }) => {
            return Ok(ExistingLoadOutcome::NeedsRebuild(
                ProjectionRebuildReason::CorruptWal,
            ));
        }
        Err(err) => return Err(err),
    }

    if !ledger_backend.matches_anchor(&snapshot.anchor)? {
        return Ok(ExistingLoadOutcome::NeedsRebuild(
            ProjectionRebuildReason::AnchorMismatch,
        ));
    }

    Ok(ExistingLoadOutcome::Valid {
        snapshot: Box::new(snapshot),
        loaded_snapshot_seq,
        replayed_wal_frames,
    })
}

fn verify_final_anchor(
    snapshot: &ProjectionSnapshot,
    head_ledger: &LedgerAnchor,
    head_history_root: ContentDigest,
) -> Result<(), ProjectionError> {
    if snapshot.anchor.commit_sequence != head_ledger.commit_sequence
        || snapshot.anchor.authority_root != head_ledger.state_root
        || snapshot.anchor.history_root != head_history_root
    {
        return Err(ProjectionError::AnchorMismatch {
            expected_sequence: head_ledger.commit_sequence,
            actual_sequence: snapshot.anchor.commit_sequence,
            detail: "rebuilt projection anchor diverged from canonical ledger head",
        });
    }
    Ok(())
}

fn build_read_state(
    mut retained_history: Vec<Arc<ProjectionSnapshot>>,
    max_retained: usize,
) -> MvccReadState {
    let latest = retained_history.pop().unwrap_or_else(|| {
        Arc::new(ProjectionSnapshot::empty(
            ProjectionAnchor {
                commit_sequence: 0,
                authority_root: ContentDigest::sha256(b""),
                history_root: ContentDigest::sha256(b""),
                high_water_digest: ContentDigest::sha256(b""),
            },
            HistoryChainMode::V2MerkleEpoch,
        ))
    });
    let mut state = MvccReadState::new(Arc::clone(&latest), max_retained);
    for snap in retained_history {
        state.retained.insert(snap.anchor.commit_sequence, snap);
    }
    state.evict_excess();
    state
}
