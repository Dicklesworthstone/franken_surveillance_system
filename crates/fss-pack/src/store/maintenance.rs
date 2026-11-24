#![forbid(unsafe_code)]
//! Hold-safe tombstone commitment, live-object accounting, and online compaction facade on
//! [`PackStore`].

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use fss_core::ContentDigest;

use crate::compaction::{
    CompactionPassReport, CompactionPolicy, PackCompactionAction, PackCompactionReceipt,
    PackLiveStats, ReaderEpochGuard, compute_pack_live_stats, execute_pack_compaction,
};
use crate::error::{PackCutPoint, PackError, PackIoOperation};
use crate::format::PackId;
use crate::retention::{RetentionEvictionBatch, TombstoneCommitProof};
use crate::store::PackStore;

impl PackStore {
    /// Returns the on-disk packfiles directory (`<root>/objects/packs`).
    #[must_use]
    pub fn packs_dir(&self) -> &Path {
        &self.packs_dir
    }

    /// Pins the current reader epoch until the returned [`ReaderEpochGuard`] is dropped.
    ///
    /// Guarantees that online compaction will never unlink any packfile visible in this epoch
    /// while the guard remains alive.
    pub fn pin_reader_epoch(&self) -> Result<ReaderEpochGuard, PackError> {
        self.reader_epochs.pin()
    }

    /// Returns all sealed [`PackId`]s currently registered in deterministic ascending order.
    pub fn sealed_pack_ids(&self) -> Result<Vec<PackId>, PackError> {
        let guard = self.index.read().map_err(|_| PackError::LockPoisoned)?;
        Ok(guard.sealed_pack_ids())
    }

    /// Returns the currently open active (unsealed) [`PackId`], if any.
    pub fn active_pack_id(&self) -> Result<Option<PackId>, PackError> {
        let writer = self.writer.lock().map_err(|_| PackError::LockPoisoned)?;
        Ok(writer.active_pack_id())
    }

    /// Returns the exact cumulative on-disk byte size of all `.fssp` packfiles in `objects/packs/`.
    pub fn on_disk_pack_bytes(&self) -> Result<u64, PackError> {
        let mut total = 0_u64;
        for dir_entry in fs::read_dir(&self.packs_dir)
            .map_err(|err| PackError::io(PackIoOperation::ReadDir, err))?
        {
            let entry = dir_entry.map_err(|err| PackError::io(PackIoOperation::ReadDir, err))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if PackId::parse_file_name(&name).is_some() {
                let meta = entry
                    .metadata()
                    .map_err(|err| PackError::io(PackIoOperation::Metadata, err))?;
                if meta.is_file() {
                    total = total
                        .checked_add(meta.len())
                        .ok_or(PackError::ArithmeticOverflow)?;
                }
            }
        }
        Ok(total)
    }

    /// Returns the committed deletion tombstone reason digest if `digest` was deleted.
    pub fn object_tombstone(
        &self,
        digest: &ContentDigest,
    ) -> Result<Option<ContentDigest>, PackError> {
        let guard = self
            .tombstones
            .read()
            .map_err(|_| PackError::LockPoisoned)?;
        Ok(guard.get(digest))
    }

    /// Durably commits deletion tombstones for `batch` (both in the virtual root catalog and the
    /// append-only object tombstone log), removing reclaimed digests from the live index and
    /// returning a verified [`TombstoneCommitProof`] required before physical compaction/unlink.
    pub fn commit_eviction_tombstones(
        &self,
        batch: &RetentionEvictionBatch,
        ledger_commit_seq: Option<u64>,
    ) -> Result<TombstoneCommitProof, PackError> {
        let mut committed_import_ids = Vec::with_capacity(batch.tombstones.len());
        let mut digest_reasons: Vec<(ContentDigest, ContentDigest)> = Vec::new();
        let reclaimable_set: BTreeSet<ContentDigest> =
            batch.reclaimable_digests.iter().copied().collect();

        {
            let mut catalog_guard = self.catalog.write().map_err(|_| PackError::LockPoisoned)?;
            for tomb in &batch.tombstones {
                if catalog_guard.get_root(&tomb.import_id).is_some() {
                    let _ = catalog_guard.tombstone_root(&tomb.import_id, tomb.reason_digest)?;
                }
                committed_import_ids.push(tomb.import_id.clone());
                for &digest in &tomb.object_digests {
                    if reclaimable_set.contains(&digest) {
                        digest_reasons.push((digest, tomb.reason_digest));
                    }
                }
            }
        }

        // Durable fsync of object-level tombstones BEFORE modifying the live index or unlinking packs.
        {
            let mut tomb_guard = self
                .tombstones
                .write()
                .map_err(|_| PackError::LockPoisoned)?;
            let _ = tomb_guard.append_batch(&digest_reasons)?;
        }

        // Remove tombstoned digests from the live content index so live-byte accounting reflects deletion.
        {
            let mut index_guard = self.index.write().map_err(|_| PackError::LockPoisoned)?;
            for &(digest, _) in &digest_reasons {
                let _ = index_guard.remove_sha256(&digest.bytes());
            }
        }

        let committed_digests: BTreeSet<ContentDigest> =
            digest_reasons.into_iter().map(|(d, _)| d).collect();
        TombstoneCommitProof::build(
            batch,
            committed_import_ids,
            committed_digests,
            batch.evaluated_at_ns,
            ledger_commit_seq,
        )
    }

    /// Computes live-object and live-byte ratio statistics for sealed packfile `pack_id`.
    pub fn pack_live_stats(&self, pack_id: PackId) -> Result<PackLiveStats, PackError> {
        let index_guard = self.index.read().map_err(|_| PackError::LockPoisoned)?;
        let tomb_guard = self
            .tombstones
            .read()
            .map_err(|_| PackError::LockPoisoned)?;
        let (stats, _, _) =
            compute_pack_live_stats(&self.packs_dir, &index_guard, &tomb_guard, pack_id)?;
        Ok(stats)
    }

    /// Computes [`PackLiveStats`] for every sealed packfile in ascending `PackId` order.
    pub fn all_sealed_pack_live_stats(&self) -> Result<Vec<PackLiveStats>, PackError> {
        let sealed = self.sealed_pack_ids()?;
        let index_guard = self.index.read().map_err(|_| PackError::LockPoisoned)?;
        let tomb_guard = self
            .tombstones
            .read()
            .map_err(|_| PackError::LockPoisoned)?;
        let mut out = Vec::with_capacity(sealed.len());
        for pack_id in sealed {
            let (stats, _, _) =
                compute_pack_live_stats(&self.packs_dir, &index_guard, &tomb_guard, pack_id)?;
            out.push(stats);
        }
        Ok(out)
    }

    /// Compacts one sealed packfile under `policy`, requiring a verified [`TombstoneCommitProof`].
    pub fn compact_pack(
        &self,
        pack_id: PackId,
        proof: &TombstoneCommitProof,
        policy: CompactionPolicy,
    ) -> Result<PackCompactionReceipt, PackError> {
        self.compact_pack_internal(pack_id, Some(proof), policy, None)
    }

    /// Fault-injection seam for deterministic compaction crash-cut verification.
    pub fn compact_pack_with_cut_point(
        &self,
        pack_id: PackId,
        proof: &TombstoneCommitProof,
        policy: CompactionPolicy,
        cut_point: PackCutPoint,
    ) -> Result<PackCompactionReceipt, PackError> {
        self.compact_pack_internal(pack_id, Some(proof), policy, Some(cut_point))
    }

    /// Scans all sealed packfiles in deterministic ascending order and compacts every pack below
    /// `policy.min_live_ratio_ppm` backed by `proof` and durable deletion tombstones.
    pub fn compact_sealed_packs(
        &self,
        proof: &TombstoneCommitProof,
        policy: CompactionPolicy,
    ) -> Result<CompactionPassReport, PackError> {
        let policy = policy.validate()?;
        proof.verify()?;
        self.compact_sealed_packs_internal(Some(proof), policy)
    }

    /// Reclaims any sealed packfiles whose objects are already durably tombstoned or superseded by
    /// a newer compacted packfile (e.g., following crash recovery after an index swap).
    pub fn reclaim_superseded_packs(
        &self,
        policy: CompactionPolicy,
    ) -> Result<CompactionPassReport, PackError> {
        let policy = policy.validate()?;
        self.compact_sealed_packs_internal(None, policy)
    }

    fn compact_sealed_packs_internal(
        &self,
        proof: Option<&TombstoneCommitProof>,
        policy: CompactionPolicy,
    ) -> Result<CompactionPassReport, PackError> {
        let sealed = self.sealed_pack_ids()?;
        let mut report = CompactionPassReport::default();
        let mut compacted_count = 0_usize;

        for pack_id in sealed {
            if let Some(limit) = policy.max_packs_per_pass
                && compacted_count >= limit
            {
                break;
            }
            report.packs_scanned = report.packs_scanned.saturating_add(1);
            let receipt = self.compact_pack_internal(pack_id, proof, policy, None)?;
            match receipt.action {
                PackCompactionAction::UnlinkedEmpty => {
                    report.packs_unlinked_empty = report.packs_unlinked_empty.saturating_add(1);
                    report.total_bytes_reclaimed = report
                        .total_bytes_reclaimed
                        .saturating_add(receipt.bytes_reclaimed);
                    compacted_count += 1;
                    report.receipts.push(receipt);
                }
                PackCompactionAction::RewrittenAndUnlinked { .. } => {
                    report.packs_rewritten = report.packs_rewritten.saturating_add(1);
                    report.live_objects_copied = report
                        .live_objects_copied
                        .saturating_add(receipt.copied_live_objects);
                    report.total_bytes_reclaimed = report
                        .total_bytes_reclaimed
                        .saturating_add(receipt.bytes_reclaimed);
                    compacted_count += 1;
                    report.receipts.push(receipt);
                }
                PackCompactionAction::SkippedAboveThreshold => {}
            }
        }
        Ok(report)
    }

    fn compact_pack_internal(
        &self,
        pack_id: PackId,
        proof: Option<&TombstoneCommitProof>,
        policy: CompactionPolicy,
        cut_point: Option<PackCutPoint>,
    ) -> Result<PackCompactionReceipt, PackError> {
        execute_pack_compaction(
            &self.packs_dir,
            &self.index_dir,
            &self.fd_pool,
            &self.index,
            &self.tombstones,
            &self.reader_epochs,
            self.config.durability,
            self.config.max_object_bytes,
            self.config.max_read_bytes,
            pack_id,
            proof,
            policy,
            || {
                let mut writer = self.writer.lock().map_err(|_| PackError::LockPoisoned)?;
                writer.allocate_next_pack_id()
            },
            cut_point,
        )
    }
}
