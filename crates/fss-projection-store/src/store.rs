#![forbid(unsafe_code)]
//! Anchor-pinned MVCC [`ProjectionStore`] trait, durable [`MvccProjectionStore`],
//! and standalone full-history replay helper.

mod prepared;
#[cfg(test)]
mod receipt_publication_tests;
mod recovery;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use fss_core::{EvidenceDeltaBatch, LedgerAnchor, SensorId};
use fss_pack::DurabilityMode;

use crate::error::{ProjectionError, ProjectionIoOperation};
use crate::payloads::PayloadResolver;
use crate::schema::{
    DoctorScrubReceipt, EventQueryFilter, EventQueryPage, FollowDeltaPage, FootageQueryFilter,
    FootageQueryPage, HistoryChainMode, ProjectedCoverageState, ProjectionAnchor,
};
use crate::snapshot::ProjectionSnapshot;
use crate::wal::{ProjectionWal, WalSyncPolicy, write_snapshot_atomic};
use recovery::advance_snapshot_in_place;

/// Default commit stride between automatic atomic `mvcc.snap` compactions.
pub const DEFAULT_SNAPSHOT_STRIDE: u64 = 1_024;
/// Default number of recent historical MVCC snapshots retained in memory for `snapshot_at`.
pub const DEFAULT_MAX_RETAINED_SNAPSHOTS: usize = 256;

/// Configuration bounds and durability settings for [`MvccProjectionStore`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionStoreConfig {
    /// Durability barrier mode for atomic snapshots and scrub receipts.
    pub durability: DurabilityMode,
    /// Derived WAL sync policy for per-commit frames.
    pub wal_sync: WalSyncPolicy,
    /// Automatically compact `mvcc.snap` and reset `mvcc.wal` every N commits (`0` disables).
    pub snapshot_stride: u64,
    /// Maximum historical MVCC snapshots retained automatically in the sliding window (>= 1).
    pub max_retained_snapshots: usize,
    /// Canonical history-root chaining mode.
    pub history_mode: HistoryChainMode,
}

impl Default for ProjectionStoreConfig {
    fn default() -> Self {
        Self {
            durability: DurabilityMode::Fsync,
            wal_sync: WalSyncPolicy::FlushOnly,
            snapshot_stride: DEFAULT_SNAPSHOT_STRIDE,
            max_retained_snapshots: DEFAULT_MAX_RETAINED_SNAPSHOTS,
            history_mode: HistoryChainMode::V2MerkleEpoch,
        }
    }
}

impl ProjectionStoreConfig {
    /// Validates configuration invariants.
    pub fn validate(&self) -> Result<(), ProjectionError> {
        if self.max_retained_snapshots == 0 {
            return Err(ProjectionError::InvalidRequest(
                "max_retained_snapshots must be >= 1",
            ));
        }
        Ok(())
    }
}

/// How [`MvccProjectionStore::open_or_rebuild`] initialized its live projection state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProjectionRecoveryMode {
    /// Loaded verified derived `mvcc.snap` + `mvcc.wal` already matching the canonical ledger head.
    LoadedCurrent,
    /// Loaded verified derived state at an earlier anchor and replayed only `high_water + 1 ..= head`.
    CaughtUpFromSnapshot,
    /// Quarantined missing/corrupt/mismatched derived files and rebuilt bit-for-bit from genesis.
    RebuiltFromGenesis,
}

/// Specific reason a full rebuild from canonical ledger history was required.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProjectionRebuildReason {
    /// Neither `mvcc.snap` nor `mvcc.wal` existed on disk.
    Missing,
    /// `mvcc.snap` failed magic, domain, SHA-256, or canonical decoding checks.
    CorruptSnapshot,
    /// `mvcc.wal` failed magic, CRC32C, sequence, or batch decoding checks.
    CorruptWal,
    /// Persisted derived anchor did not match canonical ledger history.
    AnchorMismatch,
}

/// Diagnostics recorded when opening or rebuilding an [`MvccProjectionStore`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionRecoveryReport {
    /// Initialization mode taken on open.
    pub mode: ProjectionRecoveryMode,
    /// Reason for full rebuild, if [`ProjectionRecoveryMode::RebuiltFromGenesis`].
    pub rebuild_reason: Option<ProjectionRebuildReason>,
    /// Commit sequence of the loaded `mvcc.snap` (`None` if no snapshot loaded).
    pub loaded_snapshot_seq: Option<u64>,
    /// Number of WAL frames replayed after the snapshot.
    pub replayed_wal_frames: u64,
    /// Number of canonical ledger batches replayed during catch-up or full rebuild.
    pub replayed_ledger_batches: u64,
    /// Quarantined corrupt or mismatched derived file paths, if any.
    pub quarantined_files: Vec<PathBuf>,
    /// Verified projection head anchor after open/rebuild completed.
    pub head_anchor: ProjectionAnchor,
}

/// Anchor-pinned MVCC projection store contract.
pub trait ProjectionStore: Send + Sync {
    /// Returns the latest committed [`ProjectionAnchor`].
    fn head_anchor(&self) -> ProjectionAnchor;

    /// Returns an `O(1)` lock-free immutable [`Arc<ProjectionSnapshot>`] at the current head.
    fn snapshot_latest(&self) -> Arc<ProjectionSnapshot>;

    /// Returns a retained historical immutable [`Arc<ProjectionSnapshot>`] pinned to
    /// `commit_sequence` without blocking concurrent writers.
    fn snapshot_at(&self, commit_sequence: u64)
    -> Result<Arc<ProjectionSnapshot>, ProjectionError>;

    /// Executes an indexed event query against a pinned `snapshot`.
    fn query_events(
        &self,
        snapshot: &ProjectionSnapshot,
        filter: &EventQueryFilter,
        limit: usize,
    ) -> EventQueryPage;

    /// Executes an indexed unified footage query (RTSP, HTTP, File, TUTK) against `snapshot`.
    fn query_footage(
        &self,
        snapshot: &ProjectionSnapshot,
        filter: &FootageQueryFilter,
        limit: usize,
    ) -> FootageQueryPage;

    /// Queries coverage state for optional `(sensor, zone)` filters against `snapshot`.
    fn query_coverage(
        &self,
        snapshot: &ProjectionSnapshot,
        sensor: Option<&SensorId>,
        zone: Option<&str>,
    ) -> Vec<ProjectedCoverageState>;

    /// Executes an `O(delta)` indexed range scan of commits strictly after `after_sequence`.
    fn follow_since(
        &self,
        after_sequence: u64,
        max_entries: usize,
    ) -> Result<FollowDeltaPage, ProjectionError>;

    /// Returns the latest recorded [`DoctorScrubReceipt`], or `None` (`unknown`).
    fn latest_scrub_receipt(&self) -> Option<DoctorScrubReceipt>;

    /// Validates, persists durably to `mvcc.wal`, and records a new [`DoctorScrubReceipt`].
    /// [`ProjectionError::AppliedMaintenanceFailed`] means the receipt is already visible
    /// and only optional snapshot maintenance requires repair.
    fn record_scrub_receipt(&self, receipt: DoctorScrubReceipt) -> Result<(), ProjectionError>;

    /// Deterministically applies one canonical [`EvidenceDeltaBatch`], persists its WAL frame,
    /// and atomically advances the MVCC head snapshot.
    /// [`ProjectionError::AppliedMaintenanceFailed`] means the new head is already visible;
    /// repair snapshot storage and compact it rather than applying the same batch again.
    fn apply_delta_batch(
        &self,
        batch: &EvidenceDeltaBatch,
        payload_resolver: &dyn PayloadResolver,
    ) -> Result<ProjectionAnchor, ProjectionError>;
}

pub(crate) struct MvccReadState {
    pub(crate) latest: Arc<ProjectionSnapshot>,
    pub(crate) retained: BTreeMap<u64, Arc<ProjectionSnapshot>>,
    pub(crate) pinned: BTreeSet<u64>,
    pub(crate) max_retained: usize,
}

impl MvccReadState {
    pub(crate) fn new(initial: Arc<ProjectionSnapshot>, max_retained: usize) -> Self {
        let mut retained = BTreeMap::new();
        retained.insert(initial.anchor.commit_sequence, Arc::clone(&initial));
        Self {
            latest: initial,
            retained,
            pinned: BTreeSet::new(),
            max_retained,
        }
    }

    pub(crate) fn publish(&mut self, next: Arc<ProjectionSnapshot>) {
        let seq = next.anchor.commit_sequence;
        self.latest = Arc::clone(&next);
        self.retained.insert(seq, next);
        self.evict_excess();
    }

    pub(crate) fn evict_excess(&mut self) {
        let head_seq = self.latest.anchor.commit_sequence;
        let mut unpinned_count = self
            .retained
            .keys()
            .filter(|seq| **seq != head_seq && !self.pinned.contains(seq))
            .count();
        let allowed_old = self.max_retained.saturating_sub(1);
        if unpinned_count <= allowed_old {
            return;
        }
        let mut to_remove = Vec::new();
        for &seq in self.retained.keys() {
            if unpinned_count <= allowed_old {
                break;
            }
            if seq == head_seq || self.pinned.contains(&seq) {
                continue;
            }
            to_remove.push(seq);
            unpinned_count = unpinned_count.saturating_sub(1);
        }
        for seq in to_remove {
            self.retained.remove(&seq);
        }
    }
}

pub(crate) struct MvccWriterState {
    pub(crate) dir: PathBuf,
    pub(crate) config: ProjectionStoreConfig,
    pub(crate) wal: ProjectionWal,
}

/// Durable, anchor-pinned MVCC materialized projection store backed by `<dir>/mvcc.snap` and
/// `<dir>/mvcc.wal`.
pub struct MvccProjectionStore {
    pub(crate) read_state: RwLock<MvccReadState>,
    pub(crate) writer: Mutex<MvccWriterState>,
    pub(crate) recovery_report: ProjectionRecoveryReport,
}

impl MvccProjectionStore {
    /// Opens an empty genesis projection store in `projection_dir`.
    pub fn open_empty(
        projection_dir: impl AsRef<Path>,
        genesis_anchor: &LedgerAnchor,
        config: ProjectionStoreConfig,
    ) -> Result<Self, ProjectionError> {
        config.validate()?;
        let dir = projection_dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)
            .map_err(|err| ProjectionError::io(ProjectionIoOperation::CreateDir, err))?;

        let anchor = ProjectionAnchor::genesis(genesis_anchor, config.history_mode)?;
        let snapshot = Arc::new(ProjectionSnapshot::empty(anchor, config.history_mode));
        let _ = write_snapshot_atomic(&dir, &snapshot, config.durability)?;
        let mut wal = ProjectionWal::open_append(&dir, config.wal_sync, config.durability)?;
        wal.reset_empty()?;

        let recovery_report = ProjectionRecoveryReport {
            mode: ProjectionRecoveryMode::RebuiltFromGenesis,
            rebuild_reason: Some(ProjectionRebuildReason::Missing),
            loaded_snapshot_seq: None,
            replayed_wal_frames: 0,
            replayed_ledger_batches: 0,
            quarantined_files: Vec::new(),
            head_anchor: anchor,
        };
        Ok(Self {
            read_state: RwLock::new(MvccReadState::new(snapshot, config.max_retained_snapshots)),
            writer: Mutex::new(MvccWriterState { dir, config, wal }),
            recovery_report,
        })
    }

    /// Returns the recovery/rebuild diagnostics captured when this store was opened.
    #[must_use]
    pub const fn recovery_report(&self) -> &ProjectionRecoveryReport {
        &self.recovery_report
    }

    /// Reads the current publication for an authority-bearing check without recovering poison.
    pub(crate) fn try_snapshot_latest(&self) -> Result<Arc<ProjectionSnapshot>, ProjectionError> {
        let guard = self
            .read_state
            .read()
            .map_err(|_| ProjectionError::LockPoisoned)?;
        Ok(Arc::clone(&guard.latest))
    }

    /// Explicitly pins a currently retained historical snapshot sequence against sliding-window
    /// eviction until [`Self::unpin_snapshot`] is called.
    pub fn pin_snapshot(
        &self,
        commit_sequence: u64,
    ) -> Result<Arc<ProjectionSnapshot>, ProjectionError> {
        let mut guard = self
            .read_state
            .write()
            .map_err(|_| ProjectionError::LockPoisoned)?;
        if commit_sequence > guard.latest.anchor.commit_sequence {
            return Err(ProjectionError::SequenceAhead {
                requested: commit_sequence,
                head: guard.latest.anchor.commit_sequence,
            });
        }
        let snap = guard
            .retained
            .get(&commit_sequence)
            .cloned()
            .ok_or_else(|| ProjectionError::SnapshotEvicted {
                requested: commit_sequence,
                oldest_retained: guard.retained.keys().next().copied(),
            })?;
        guard.pinned.insert(commit_sequence);
        Ok(snap)
    }

    /// Releases an explicit pin placed by [`Self::pin_snapshot`].
    pub fn unpin_snapshot(&self, commit_sequence: u64) -> Result<(), ProjectionError> {
        let mut guard = self
            .read_state
            .write()
            .map_err(|_| ProjectionError::LockPoisoned)?;
        guard.pinned.remove(&commit_sequence);
        guard.evict_excess();
        Ok(())
    }

    /// Forces an atomic verified `mvcc.snap` checkpoint and resets `mvcc.wal`.
    pub fn compact_snapshot(&self) -> Result<usize, ProjectionError> {
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| ProjectionError::LockPoisoned)?;
        let snapshot = self.snapshot_latest();
        let written = write_snapshot_atomic(&writer.dir, &snapshot, writer.config.durability)?;
        writer.wal.reset_empty()?;
        Ok(written)
    }
}

impl ProjectionStore for MvccProjectionStore {
    fn head_anchor(&self) -> ProjectionAnchor {
        self.snapshot_latest().anchor
    }

    fn snapshot_latest(&self) -> Arc<ProjectionSnapshot> {
        match self.read_state.read() {
            Ok(guard) => Arc::clone(&guard.latest),
            Err(poisoned) => Arc::clone(&poisoned.into_inner().latest),
        }
    }

    fn snapshot_at(
        &self,
        commit_sequence: u64,
    ) -> Result<Arc<ProjectionSnapshot>, ProjectionError> {
        let guard = self
            .read_state
            .read()
            .map_err(|_| ProjectionError::LockPoisoned)?;
        if commit_sequence > guard.latest.anchor.commit_sequence {
            return Err(ProjectionError::SequenceAhead {
                requested: commit_sequence,
                head: guard.latest.anchor.commit_sequence,
            });
        }
        guard
            .retained
            .get(&commit_sequence)
            .cloned()
            .ok_or_else(|| ProjectionError::SnapshotEvicted {
                requested: commit_sequence,
                oldest_retained: guard.retained.keys().next().copied(),
            })
    }

    fn query_events(
        &self,
        snapshot: &ProjectionSnapshot,
        filter: &EventQueryFilter,
        limit: usize,
    ) -> EventQueryPage {
        snapshot.query_events(filter, limit)
    }

    fn query_footage(
        &self,
        snapshot: &ProjectionSnapshot,
        filter: &FootageQueryFilter,
        limit: usize,
    ) -> FootageQueryPage {
        snapshot.query_footage(filter, limit)
    }

    fn query_coverage(
        &self,
        snapshot: &ProjectionSnapshot,
        sensor: Option<&SensorId>,
        zone: Option<&str>,
    ) -> Vec<ProjectedCoverageState> {
        snapshot.query_coverage(sensor, zone)
    }

    fn follow_since(
        &self,
        after_sequence: u64,
        max_entries: usize,
    ) -> Result<FollowDeltaPage, ProjectionError> {
        let snap = self.snapshot_latest();
        snap.follow_since(after_sequence, max_entries)
    }

    fn latest_scrub_receipt(&self) -> Option<DoctorScrubReceipt> {
        self.snapshot_latest().scrub_receipt.clone()
    }

    fn record_scrub_receipt(&self, receipt: DoctorScrubReceipt) -> Result<(), ProjectionError> {
        receipt.validate()?;
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| ProjectionError::LockPoisoned)?;
        let current = self.snapshot_latest();
        if receipt.anchor.commit_sequence > current.anchor.commit_sequence {
            return Err(ProjectionError::InvalidScrubReceipt(
                "scrub receipt anchor is ahead of projection head",
            ));
        }
        writer.wal.append_scrub_receipt(&receipt)?;
        let mut next = (*current).clone();
        next.scrub_receipt = Some(receipt);
        let next_arc = Arc::new(next);
        {
            let mut guard = self
                .read_state
                .write()
                .map_err(|_| ProjectionError::LockPoisoned)?;
            guard.publish(Arc::clone(&next_arc));
        }
        if writer.config.snapshot_stride > 0
            && writer.wal.frames_written() >= writer.config.snapshot_stride
        {
            let maintenance =
                write_snapshot_atomic(&writer.dir, &next_arc, writer.config.durability)
                    .and_then(|_| writer.wal.reset_empty());
            if let Err(source) = maintenance {
                return Err(ProjectionError::AppliedMaintenanceFailed {
                    anchor: next_arc.anchor,
                    source: Box::new(source),
                });
            }
        }
        Ok(())
    }

    fn apply_delta_batch(
        &self,
        batch: &EvidenceDeltaBatch,
        payload_resolver: &dyn PayloadResolver,
    ) -> Result<ProjectionAnchor, ProjectionError> {
        self.prepare_delta_batch(batch, payload_resolver)?.publish()
    }
}

/// Independent pure full-history replay oracle from genesis + ordered canonical batches.
pub fn replay_from_batches(
    genesis_anchor: &LedgerAnchor,
    history_mode: HistoryChainMode,
    batches: &[EvidenceDeltaBatch],
    payload_resolver: &dyn PayloadResolver,
) -> Result<ProjectionSnapshot, ProjectionError> {
    let genesis = ProjectionAnchor::genesis(genesis_anchor, history_mode)?;
    let mut snapshot = ProjectionSnapshot::empty(genesis, history_mode);
    for batch in batches {
        advance_snapshot_in_place(&mut snapshot, batch, payload_resolver)?;
    }
    Ok(snapshot)
}

/// Strictly replays all ordered batches strictly ahead of `base.anchor.commit_sequence` onto an
/// existing verified [`ProjectionSnapshot`], ignoring older already-checkpointed batches.
pub fn replay_onto_snapshot(
    mut base: ProjectionSnapshot,
    batches: &[EvidenceDeltaBatch],
    payload_resolver: &dyn PayloadResolver,
) -> Result<ProjectionSnapshot, ProjectionError> {
    for batch in batches {
        if batch.new_anchor.commit_sequence <= base.anchor.commit_sequence {
            continue;
        }
        advance_snapshot_in_place(&mut base, batch, payload_resolver)?;
    }
    Ok(base)
}

/// Replays the longest valid contiguous suffix of `batches` strictly ahead of
/// `base.anchor.commit_sequence` onto an existing [`ProjectionSnapshot`] for lock-free read-only
/// observers (e.g., live dashboard fallback reading an active WAL that may have an in-flight tail).
///
/// Returns `(updated_snapshot, applied_count)`. Any batch already covered by `base` is skipped;
/// on the first invalid or non-contiguous tail batch, replay stops cleanly without discarding
/// earlier valid commits.
#[must_use]
pub fn replay_valid_prefix_onto_snapshot(
    mut base: ProjectionSnapshot,
    batches: &[EvidenceDeltaBatch],
    payload_resolver: &dyn PayloadResolver,
) -> (ProjectionSnapshot, u64) {
    let mut applied = 0_u64;
    for batch in batches {
        if batch.new_anchor.commit_sequence <= base.anchor.commit_sequence {
            continue;
        }
        let mut candidate = base.clone();
        if advance_snapshot_in_place(&mut candidate, batch, payload_resolver).is_err() {
            break;
        }
        base = candidate;
        applied = applied.saturating_add(1);
    }
    (base, applied)
}
