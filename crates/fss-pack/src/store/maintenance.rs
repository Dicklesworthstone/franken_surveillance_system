#![forbid(unsafe_code)]
//! Hold-safe tombstone commitment, live-object accounting, and online compaction facade on
//! [`PackStore`].

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use fss_core::{ContentDigest, DigestAlgorithm};

use crate::catalog::{RootStatus, VirtualRootCatalog};

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
    ///
    /// Before changing either tombstone owner, rechecks direct root and metadata references
    /// against the current catalog. A surviving reference, duplicate import, or conflicting
    /// prior root tombstone refuses the entire batch. Callers still own hold authority and
    /// format-specific child-graph revalidation; an I/O failure may leave partial durable work.
    pub fn commit_eviction_tombstones(
        &self,
        batch: &RetentionEvictionBatch,
        ledger_commit_seq: Option<u64>,
    ) -> Result<TombstoneCommitProof, PackError> {
        let mut committed_import_ids = Vec::with_capacity(batch.tombstones.len());
        // Serialize direct-reference verification/publication with object tombstone commitment.
        let mut catalog_guard = self.catalog.write().map_err(|_| PackError::LockPoisoned)?;
        let digest_reasons = preflight_eviction(&catalog_guard, batch)?;
        for tomb in &batch.tombstones {
            if catalog_guard.get_root(&tomb.import_id).is_some() {
                let _ = catalog_guard.tombstone_root(&tomb.import_id, tomb.reason_digest)?;
            }
            committed_import_ids.push(tomb.import_id.clone());
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

    /// Completes object deletion interrupted after a root catalog tombstone was committed.
    ///
    /// Only the exact root object is eligible; children and metadata are never inferred as
    /// deletable. A live root or metadata reference defers cleanup without changing state.
    /// The original catalog reason is copied into the durable object tombstone log before
    /// removing the object from the live index. Repeated calls preserve that first reason.
    ///
    /// Returns `true` when a new object tombstone was committed, or `false` when the
    /// object was already tombstoned or is still referenced by a live catalog root.
    ///
    /// The caller must verify canonical retirement and current hold authority, and keep
    /// writers quiesced during recovery. This method does not grant deletion authority.
    /// Physical reclamation can subsequently resume through [`Self::reclaim_superseded_packs`].
    pub fn resume_root_object_deletion(
        &self,
        root_id: &str,
        expected_digest: ContentDigest,
    ) -> Result<bool, PackError> {
        if expected_digest.algorithm() != DigestAlgorithm::Sha256 {
            return Err(PackError::UnsupportedDigestAlgorithm(
                expected_digest.algorithm(),
            ));
        }
        // Exclusive ownership fences append and compaction until index removal is finished.
        let catalog = self.catalog.write().map_err(|_| PackError::LockPoisoned)?;
        let entry = catalog
            .get_root(root_id)
            .ok_or_else(|| PackError::RootNotFound(root_id.to_owned()))?;
        let RootStatus::Tombstoned { reason_digest, .. } = entry.status else {
            return Err(PackError::InvalidTombstoneProof {
                detail: "root object recovery requires a committed catalog tombstone".to_owned(),
            });
        };
        if entry.record.root_digest != expected_digest {
            return Err(PackError::InvalidTombstoneProof {
                detail: "root object recovery digest does not match the catalog root".to_owned(),
            });
        }

        let already_deleted = self
            .tombstones
            .read()
            .map_err(|_| PackError::LockPoisoned)?
            .get(&expected_digest)
            .is_some();
        if already_deleted {
            // A durable tombstone wins over a stale derived index after an interrupted
            // removal; no new deletion or catalog scan is needed on repeated recovery.
            let mut index = self.index.write().map_err(|_| PackError::LockPoisoned)?;
            let _ = index.remove_sha256(&expected_digest.bytes());
            return Ok(false);
        }

        // Retain the catalog lock across the entire scan and durable mutation. Bounded
        // pages avoid materializing the complete catalog, including large deployments.
        let mut cursor: Option<String> = None;
        loop {
            let page = catalog.list_live_roots(cursor.as_deref(), 512);
            if page.entries.iter().any(|live| {
                live.record.root_digest == expected_digest
                    || live.record.metadata_digest == Some(expected_digest)
            }) {
                return Ok(false);
            }
            if !page.has_more {
                break;
            }
            let next = page.next_cursor.ok_or_else(|| PackError::CorruptCatalog {
                detail: "live root recovery scan omitted its continuation cursor".to_owned(),
            })?;
            if cursor.as_ref().is_some_and(|previous| next <= *previous) {
                return Err(PackError::CorruptCatalog {
                    detail: "live root recovery scan did not advance".to_owned(),
                });
            }
            cursor = Some(next);
        }

        let written = {
            let mut tombstones = self
                .tombstones
                .write()
                .map_err(|_| PackError::LockPoisoned)?;
            tombstones.append_batch(&[(expected_digest, reason_digest)])?
        };
        // Even an already durable tombstone may precede an interrupted index removal.
        let mut index = self.index.write().map_err(|_| PackError::LockPoisoned)?;
        let _ = index.remove_sha256(&expected_digest.bytes());
        Ok(written != 0)
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
        // A digest selected for copying must remain live until the replacement is installed.
        let _catalog = self.catalog.read().map_err(|_| PackError::LockPoisoned)?;
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

/// The caller holds the catalog write lock through this check and the resulting deletions.
/// Only catalog roots actually retiring in this batch may stop protecting their direct bytes.
fn preflight_eviction(
    catalog: &VirtualRootCatalog,
    batch: &RetentionEvictionBatch,
) -> Result<Vec<(ContentDigest, ContentDigest)>, PackError> {
    let reclaimable: BTreeSet<_> = batch.reclaimable_digests.iter().copied().collect();
    let mut seen_imports = BTreeSet::new();
    let mut retiring_live_roots = BTreeSet::new();
    let mut digest_reasons = Vec::new();
    for tomb in &batch.tombstones {
        if tomb.import_id.is_empty() || !seen_imports.insert(tomb.import_id.as_str()) {
            return Err(PackError::RetentionPolicyViolation {
                detail: "eviction batch has an empty or duplicate import_id".to_owned(),
            });
        }
        if tomb.reason_digest.algorithm() != DigestAlgorithm::Sha256 {
            return Err(PackError::UnsupportedDigestAlgorithm(
                tomb.reason_digest.algorithm(),
            ));
        }
        if let Some(entry) = catalog.get_root(&tomb.import_id) {
            match &entry.status {
                RootStatus::Live => {
                    retiring_live_roots.insert(tomb.import_id.as_str());
                }
                RootStatus::Tombstoned { reason_digest, .. }
                    if *reason_digest != tomb.reason_digest =>
                {
                    return Err(PackError::TombstoneConflict {
                        root_id: tomb.import_id.clone(),
                        existing_reason: *reason_digest,
                        attempted_reason: tomb.reason_digest,
                    });
                }
                RootStatus::Superseded { .. } | RootStatus::Tombstoned { .. } => {}
            }
        }
        // Object-only retention records remain supported, but an absent catalog identity
        // exempts no live root from the protection check below.
        for &digest in &tomb.object_digests {
            if digest.algorithm() != DigestAlgorithm::Sha256 {
                return Err(PackError::UnsupportedDigestAlgorithm(digest.algorithm()));
            }
            if reclaimable.contains(&digest) {
                digest_reasons.push((digest, tomb.reason_digest));
            }
        }
    }
    let deleted: BTreeSet<_> = digest_reasons.iter().map(|(digest, _)| *digest).collect();
    if deleted.is_empty() {
        return Ok(digest_reasons);
    }

    // Page through current live descriptors rather than copying the complete catalog.
    // Holding its write lock makes the scan and subsequent mutation one publication boundary.
    let mut cursor: Option<String> = None;
    loop {
        let page = catalog.list_live_roots(cursor.as_deref(), 512);
        for entry in &page.entries {
            let record = &entry.record;
            if !retiring_live_roots.contains(record.root_id.as_str())
                && (deleted.contains(&record.root_digest)
                    || record
                        .metadata_digest
                        .is_some_and(|digest| deleted.contains(&digest)))
            {
                return Err(PackError::RetentionPolicyViolation {
                    detail: format!(
                        "eviction would delete bytes referenced by surviving live root '{}'",
                        record.root_id
                    ),
                });
            }
        }
        if !page.has_more {
            break;
        }
        let next = page.next_cursor.ok_or_else(|| PackError::CorruptCatalog {
            detail: "live root eviction scan omitted its continuation cursor".to_owned(),
        })?;
        if cursor.as_ref().is_some_and(|previous| next <= *previous) {
            return Err(PackError::CorruptCatalog {
                detail: "live root eviction scan did not advance".to_owned(),
            });
        }
        cursor = Some(next);
    }
    Ok(digest_reasons)
}
