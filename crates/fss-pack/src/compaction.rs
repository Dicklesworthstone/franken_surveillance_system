#![forbid(unsafe_code)]
//! Online hold-safe packfile compaction, live-byte accounting, and reader-epoch drain barrier
//! (`COMPREHENSIVE_PLAN §13.8`).
//!
//! # Safety & Physical-Only Invariants
//!
//! 1. **Physical-Only**: Canonical object SHA-256 digests NEVER change across compaction.
//! 2. **Re-Verification on Copy**: Every live object streamed from an old sealed pack into a
//!    compacted staging pack (`*.pack.compact.tmp`) is re-verified end-to-end (header, CRC32C,
//!    and SHA-256) before writing.
//! 3. **Deletion Ordering**: Every dead object not copied forward MUST be backed by a verified
//!    [`crate::TombstoneCommitProof`] and durably present in [`crate::ObjectTombstoneLog`] (or
//!    already live in another packfile). Uncommitted tombstones fail closed with
//!    [`PackError::UncommittedTombstone`].
//! 4. **Reader Epoch Drain**: An old packfile is NEVER unlinked while any concurrent reader holds
//!    a [`ReaderEpochGuard`] on an epoch `<= retired_epoch`.
//! 5. **Crash Consistency**: Staging packs (`*.pack.compact.tmp`) are automatically cleaned up on
//!    reopen; crashing before or after the `PackIndex` swap leaves zero data loss and zero
//!    dangling index pointers.

mod engine;

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest};

use crate::error::PackError;
use crate::format::PackId;

pub(crate) use engine::{compute_pack_live_stats, execute_pack_compaction};

/// Canonical digest domain for [`PackCompactionReceipt::receipt_digest`].
pub const PACK_COMPACTION_RECEIPT_DOMAIN: &str = "fss.pack.compaction_receipt.v1";
/// Filename suffix for crash-safe temporary compacted staging packfiles.
pub const COMPACT_STAGING_SUFFIX: &str = ".pack.compact.tmp";
/// Default live-byte ratio threshold below which sealed packs are compacted (`50% = 500_000` ppm).
pub const DEFAULT_COMPACTION_LIVE_RATIO_PPM: u32 = 500_000;
/// Default bounded timeout waiting for concurrent readers on a retired epoch to drain (5 seconds).
pub const DEFAULT_READER_DRAIN_TIMEOUT_MS: u64 = 5_000;

#[derive(Debug)]
struct EpochTrackerState {
    current_epoch: u64,
    active_by_epoch: BTreeMap<u64, u64>,
}

/// Linearizable reader-epoch barrier preventing packfile unlink while concurrent readers hold pins.
#[derive(Debug)]
pub struct ReaderEpochTracker {
    state: Mutex<EpochTrackerState>,
    drained: Condvar,
}

impl Default for ReaderEpochTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ReaderEpochTracker {
    /// Creates a new [`ReaderEpochTracker`] starting at epoch `1`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(EpochTrackerState {
                current_epoch: 1,
                active_by_epoch: BTreeMap::new(),
            }),
            drained: Condvar::new(),
        }
    }

    /// Acquires an RAII [`ReaderEpochGuard`] pinning the current reader epoch.
    pub fn pin(self: &Arc<Self>) -> Result<ReaderEpochGuard, PackError> {
        let mut guard = self.state.lock().map_err(|_| PackError::LockPoisoned)?;
        let epoch = guard.current_epoch;
        let count = guard.active_by_epoch.entry(epoch).or_insert(0);
        *count = count.checked_add(1).ok_or(PackError::ArithmeticOverflow)?;
        Ok(ReaderEpochGuard {
            tracker: Arc::clone(self),
            epoch,
        })
    }

    /// Advances the current reader epoch and returns the retired epoch number.
    ///
    /// Must be called AFTER swapping `PackIndex` pointers so every reader pinning a subsequent
    /// epoch is guaranteed to observe the new locations.
    pub fn advance_epoch(&self) -> Result<u64, PackError> {
        let mut guard = self.state.lock().map_err(|_| PackError::LockPoisoned)?;
        let retired = guard.current_epoch;
        guard.current_epoch = retired
            .checked_add(1)
            .ok_or(PackError::ArithmeticOverflow)?;
        Ok(retired)
    }

    /// Returns the current reader epoch number.
    pub fn current_epoch(&self) -> Result<u64, PackError> {
        let guard = self.state.lock().map_err(|_| PackError::LockPoisoned)?;
        Ok(guard.current_epoch)
    }

    /// Returns the total active reader count pinning epochs `<= max_epoch`.
    pub fn active_readers_up_to(&self, max_epoch: u64) -> Result<u64, PackError> {
        let guard = self.state.lock().map_err(|_| PackError::LockPoisoned)?;
        Ok(count_active_up_to(&guard.active_by_epoch, max_epoch))
    }

    /// Waits (bounded by `timeout`) until all active readers on epochs `<= retired_epoch` drop.
    pub fn wait_for_drain(&self, retired_epoch: u64, timeout: Duration) -> Result<(), PackError> {
        let deadline = Instant::now() + timeout;
        let mut guard = self.state.lock().map_err(|_| PackError::LockPoisoned)?;
        loop {
            let active = count_active_up_to(&guard.active_by_epoch, retired_epoch);
            if active == 0 {
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(PackError::ReaderEpochDrainTimeout {
                    retired_epoch,
                    active_readers: active,
                });
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next_guard, _) = self
                .drained
                .wait_timeout(guard, remaining)
                .map_err(|_| PackError::LockPoisoned)?;
            guard = next_guard;
        }
    }

    fn release(&self, epoch: u64) {
        if let Ok(mut guard) = self.state.lock() {
            let remove = if let Some(count) = guard.active_by_epoch.get_mut(&epoch) {
                *count = count.saturating_sub(1);
                *count == 0
            } else {
                false
            };
            if remove {
                guard.active_by_epoch.remove(&epoch);
                self.drained.notify_all();
            }
        }
    }
}

fn count_active_up_to(active_by_epoch: &BTreeMap<u64, u64>, max_epoch: u64) -> u64 {
    active_by_epoch
        .range(..=max_epoch)
        .map(|(_, &count)| count)
        .fold(0_u64, u64::saturating_add)
}

/// RAII guard pinning one reader epoch; guarantees no packfile referenced in this epoch is unlinked.
#[derive(Debug)]
pub struct ReaderEpochGuard {
    tracker: Arc<ReaderEpochTracker>,
    epoch: u64,
}

impl ReaderEpochGuard {
    /// Returns the reader epoch pinned by this guard.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl Drop for ReaderEpochGuard {
    fn drop(&mut self) {
        self.tracker.release(self.epoch);
    }
}

/// Live-object and live-byte accounting for one sealed packfile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackLiveStats {
    /// Target sealed packfile identifier.
    pub pack_id: PackId,
    /// Total framed records recorded in this packfile's sealed footer.
    pub total_objects: u64,
    /// Count of records in this packfile that are currently live (indexed here and not tombstoned).
    pub live_objects: u64,
    /// Total framed bytes across all records in this packfile.
    pub total_bytes: u64,
    /// Total framed bytes belonging to currently live objects in this packfile.
    pub live_bytes: u64,
    /// Live byte fraction in parts per million (`0..=1_000_000`).
    pub live_ratio_ppm: u32,
}

/// Policy thresholds governing online sealed-pack compaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionPolicy {
    /// Sealed packfiles with `live_ratio_ppm < min_live_ratio_ppm` are compacted (`0..=1_000_000`).
    pub min_live_ratio_ppm: u32,
    /// Maximum milliseconds to wait for concurrent readers on a retired epoch before failing closed.
    pub reader_drain_timeout_ms: u64,
    /// Optional cap on how many sealed packs to compact in a single pass (`None` = all eligible).
    pub max_packs_per_pass: Option<usize>,
}

impl Default for CompactionPolicy {
    fn default() -> Self {
        Self {
            min_live_ratio_ppm: DEFAULT_COMPACTION_LIVE_RATIO_PPM,
            reader_drain_timeout_ms: DEFAULT_READER_DRAIN_TIMEOUT_MS,
            max_packs_per_pass: None,
        }
    }
}

impl CompactionPolicy {
    /// Validates policy bounds.
    pub fn validate(self) -> Result<Self, PackError> {
        if self.min_live_ratio_ppm > 1_000_000 {
            return Err(PackError::InvalidConfig {
                detail: format!(
                    "min_live_ratio_ppm {} exceeds 1_000_000",
                    self.min_live_ratio_ppm
                ),
            });
        }
        if self.max_packs_per_pass == Some(0) {
            return Err(PackError::InvalidConfig {
                detail: "max_packs_per_pass must be >= 1 when set".to_owned(),
            });
        }
        Ok(self)
    }
}

/// Disposition taken for one sealed packfile during compaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackCompactionAction {
    /// Packfile had `0` live bytes and was safely unlinked after reader-epoch drain.
    UnlinkedEmpty,
    /// Live objects (`1..threshold`) were re-verified, written to `replacement_pack_id`,
    /// indexed atomically, and the old packfile was unlinked after reader-epoch drain.
    RewrittenAndUnlinked {
        /// Newly created sealed packfile carrying the surviving live objects.
        replacement_pack_id: PackId,
    },
    /// Packfile live ratio met or exceeded `min_live_ratio_ppm` and was left untouched.
    SkippedAboveThreshold,
}

impl PackCompactionAction {
    /// Encodes action discriminant as a canonical 1-byte tag.
    #[must_use]
    pub const fn to_tag(self) -> u8 {
        match self {
            Self::UnlinkedEmpty => 1,
            Self::RewrittenAndUnlinked { .. } => 2,
            Self::SkippedAboveThreshold => 3,
        }
    }
}

/// Canonical receipt witnessing one physical-only sealed pack compaction operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackCompactionReceipt {
    /// Source sealed packfile evaluated/compacted.
    pub source_pack_id: PackId,
    /// Action executed on `source_pack_id`.
    pub action: PackCompactionAction,
    /// Live-byte statistics observed prior to compaction.
    pub stats_before: PackLiveStats,
    /// Count of live objects re-verified and copied to a replacement packfile.
    pub copied_live_objects: u64,
    /// Physical bytes reclaimed on disk (old packfile size minus replacement packfile size).
    pub bytes_reclaimed: u64,
    /// Reader epoch retired and drained prior to unlinking `source_pack_id` (if unlinked).
    pub drained_reader_epoch: Option<u64>,
    /// Commitment digest of the verified [`crate::TombstoneCommitProof`] authorizing reclamation.
    pub tombstone_proof_digest: Option<ContentDigest>,
}

impl PackCompactionReceipt {
    /// Computes the canonical SHA-256 receipt digest under [`PACK_COMPACTION_RECEIPT_DOMAIN`].
    #[must_use]
    pub fn receipt_digest(&self) -> ContentDigest {
        self.canonical_digest(PACK_COMPACTION_RECEIPT_DOMAIN)
    }
}

impl CanonicalEncode for PackCompactionReceipt {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(u64::from(self.source_pack_id.epoch));
        encoder.u64(self.source_pack_id.seq);
        encoder.tag(self.action.to_tag());
        if let PackCompactionAction::RewrittenAndUnlinked {
            replacement_pack_id,
        } = self.action
        {
            encoder.u64(u64::from(replacement_pack_id.epoch));
            encoder.u64(replacement_pack_id.seq);
        }
        encoder.u64(self.stats_before.total_objects);
        encoder.u64(self.stats_before.live_objects);
        encoder.u64(self.stats_before.total_bytes);
        encoder.u64(self.stats_before.live_bytes);
        encoder.u64(u64::from(self.stats_before.live_ratio_ppm));
        encoder.u64(self.copied_live_objects);
        encoder.u64(self.bytes_reclaimed);
        match self.drained_reader_epoch {
            Some(ep) => {
                encoder.bool(true);
                encoder.u64(ep);
            }
            None => encoder.bool(false),
        }
        match self.tombstone_proof_digest {
            Some(d) => {
                encoder.bool(true);
                encoder.digest(d);
            }
            None => encoder.bool(false),
        }
    }
}

/// Aggregated summary returned by a multi-pack compaction pass.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompactionPassReport {
    /// Sealed packfiles inspected during this pass.
    pub packs_scanned: u64,
    /// Empty sealed packfiles (`0` live bytes) unlinked.
    pub packs_unlinked_empty: u64,
    /// Sparse sealed packfiles rewritten into fresh compacted packs and unlinked.
    pub packs_rewritten: u64,
    /// Total live objects re-verified and copied across rewritten packs.
    pub live_objects_copied: u64,
    /// Cumulative physical bytes reclaimed on disk.
    pub total_bytes_reclaimed: u64,
    /// Per-pack compaction receipts in deterministic ascending `PackId` order.
    pub receipts: Vec<PackCompactionReceipt>,
}

/// Computes canonical staging filename `pack-<epoch:08>-<seq:012>.pack.compact.tmp`.
#[must_use]
pub fn compact_staging_file_name(pack_id: PackId) -> String {
    format!(
        "pack-{:08}-{:012}{COMPACT_STAGING_SUFFIX}",
        pack_id.epoch, pack_id.seq
    )
}
