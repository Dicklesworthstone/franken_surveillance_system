#![forbid(unsafe_code)]
//! Append-only sealed packfile writer, configuration, and group-commit engine.
//!
//! [`PackWriter`] appends deduplicated batches of `FSSP` framed objects into the active
//! packfile (`pack-<epoch:08>-<seq:012>.fssp`) with **one durability barrier (`sync_data`/`sync_all`)
//! per batch**, rotating and sealing with a canonical `FSSF`..`FSSE` sorted footer and
//! whole-pack SHA-256 once `target_pack_bytes` is reached.

mod recovery;
pub(crate) mod verified;

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use fss_core::{ContentDigest, DigestAlgorithm, Sha256Hasher, sha256};

use crate::error::{PackError, PackIoOperation, QuotaResource};
use crate::fd_pool::DEFAULT_MAX_OPEN_PACKS;
use crate::format::{
    DEFAULT_MAX_OBJECT_BYTES, DEFAULT_MAX_READ_BYTES, DEFAULT_TARGET_PACK_BYTES, DurabilityMode,
    MIN_CONFIGURABLE_TARGET_PACK_BYTES, PACK_RECORD_OVERHEAD_LEN, PackFooterEntry, PackId,
    PackLocation, PackObjectInput, PackObjectState, encode_record_into, encode_sealed_footer,
    sync_dir, write_all_bounded,
};
use crate::index::{IndexRebuildReason, PackIndex, PackInventoryEntry};
use crate::retention::ObjectTombstoneLog;

pub use recovery::{verify_sealed_pack, verify_sealed_pack_with_digest};
pub(crate) use recovery::{
    read_sealed_footer_from_file, read_verified_location, recover_packs_and_index,
};

/// Verifies a complete sealed pack already held in memory, including every indexed payload.
pub fn verify_sealed_pack_bytes(pack_id: PackId, bytes: &[u8]) -> Result<crate::format::PackFooter, PackError> {
    verified::verify(&mut std::io::Cursor::new(bytes), pack_id).map(|(footer, _)| footer)
}

/// Soft and hard configurable quota limits for the pack store and virtual root catalog.
///
/// By default all limits are `None` (unbounded), eliminating legacy 128-root and
/// 65,536-object walls while allowing operators to configure soft warnings or hard ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotaPolicy {
    /// Soft warning threshold on live roots (writes still succeed with a soft-limit notice).
    pub soft_max_live_roots: Option<u64>,
    /// Hard refusal ceiling on live roots.
    pub hard_max_live_roots: Option<u64>,
    /// Soft warning threshold on cumulative unique payload bytes.
    pub soft_max_total_bytes: Option<u64>,
    /// Hard refusal ceiling on cumulative unique payload bytes.
    pub hard_max_total_bytes: Option<u64>,
    /// Automatic catalog compaction interval in journal operations (`0` disables auto-compaction).
    pub auto_compact_every: u64,
}

impl Default for QuotaPolicy {
    fn default() -> Self {
        Self {
            soft_max_live_roots: None,
            hard_max_live_roots: None,
            soft_max_total_bytes: None,
            hard_max_total_bytes: None,
            auto_compact_every: 4_096,
        }
    }
}

/// Configuration for opening and operating a [`crate::PackStore`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackConfig {
    /// Target packfile seal size in bytes (default 128 MiB; configurable down to 256 B for tests).
    pub target_pack_bytes: u64,
    /// Durability barrier mode (`Fsync` vs `FullSync`).
    pub durability: DurabilityMode,
    /// Maximum open packfile file descriptors held in the bounded LRU pool.
    pub max_open_packs: usize,
    /// Maximum single object payload size in bytes.
    pub max_object_bytes: u64,
    /// Maximum byte size permitted for a single verified read (including record framing).
    pub max_read_bytes: u64,
    /// Storage epoch assigned to newly created packfiles (must be `>= 1`).
    pub epoch: u32,
    /// Soft/hard quota and catalog compaction policy.
    pub quota: QuotaPolicy,
    /// Whether to automatically persist `pack-index.fssi` each time a pack is sealed.
    pub auto_save_index_on_seal: bool,
}

impl Default for PackConfig {
    fn default() -> Self {
        Self {
            target_pack_bytes: DEFAULT_TARGET_PACK_BYTES,
            durability: DurabilityMode::Fsync,
            max_open_packs: DEFAULT_MAX_OPEN_PACKS,
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
            max_read_bytes: DEFAULT_MAX_READ_BYTES,
            epoch: 1,
            quota: QuotaPolicy::default(),
            auto_save_index_on_seal: false,
        }
    }
}

impl PackConfig {
    /// Validates every configuration invariant before performing filesystem I/O.
    pub fn validate(self) -> Result<Self, PackError> {
        if self.target_pack_bytes < MIN_CONFIGURABLE_TARGET_PACK_BYTES {
            return Err(PackError::InvalidConfig {
                detail: format!(
                    "target_pack_bytes {} is below minimum {MIN_CONFIGURABLE_TARGET_PACK_BYTES}",
                    self.target_pack_bytes
                ),
            });
        }
        if self.max_open_packs == 0 {
            return Err(PackError::InvalidConfig {
                detail: "max_open_packs must be at least 1".to_owned(),
            });
        }
        if self.max_object_bytes == 0 || self.max_object_bytes > DEFAULT_MAX_OBJECT_BYTES {
            return Err(PackError::InvalidConfig {
                detail: format!(
                    "max_object_bytes {} must be in 1..={DEFAULT_MAX_OBJECT_BYTES}",
                    self.max_object_bytes
                ),
            });
        }
        if self.max_read_bytes < PACK_RECORD_OVERHEAD_LEN as u64 {
            return Err(PackError::InvalidConfig {
                detail: format!(
                    "max_read_bytes {} is smaller than record overhead {PACK_RECORD_OVERHEAD_LEN}",
                    self.max_read_bytes
                ),
            });
        }
        if self.epoch == 0 {
            return Err(PackError::InvalidConfig {
                detail: "epoch must be >= 1".to_owned(),
            });
        }
        Ok(self)
    }
}

/// Receipt emitted when an active packfile is sealed with its canonical `FSSF`..`FSSE` footer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedPackReceipt {
    /// Pack identifier that was sealed.
    pub pack_id: PackId,
    /// Number of unique records sealed inside the packfile.
    pub entry_count: u64,
    /// Byte offset where the `FSSF` footer begins.
    pub footer_offset: u64,
    /// Final total packfile length in bytes.
    pub total_bytes: u64,
    /// Whole-pack SHA-256 covering bytes `[0 .. total_bytes - 36]`.
    pub whole_pack_digest: ContentDigest,
}

/// Summary of packfile and index recovery performed during open.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PackRecoveryReport {
    /// Number of sealed packfiles discovered.
    pub sealed_pack_count: usize,
    /// Active packfile resumed for appends, if any.
    pub active_pack_id: Option<PackId>,
    /// Number of unique objects admitted into the index.
    pub indexed_objects: usize,
    /// Reason the index was rebuilt from packfiles, or `None` if loaded directly from `pack-index.fssi`.
    pub index_rebuild_reason: Option<IndexRebuildReason>,
    /// Trailing incomplete or torn bytes truncated from an unsealed active pack during recovery.
    pub truncated_tail_bytes: u64,
    /// Orphaned compaction staging packs (`*.pack.compact.tmp`) automatically cleaned on open.
    pub cleaned_staging_packs: Vec<String>,
    /// Unrecognized entries observed in `objects/packs/` (never deleted automatically).
    pub foreign_entries: Vec<String>,
}

/// Active packfile state maintained by [`PackWriter`].
pub(crate) struct ActivePackState {
    pub(crate) pack_id: PackId,
    pub(crate) file: File,
    pub(crate) offset: u64,
    pub(crate) hasher: Sha256Hasher,
    pub(crate) entries: Vec<PackFooterEntry>,
}

/// Single-writer append engine for sealed packfiles with group-commit durability barriers.
pub struct PackWriter {
    packs_dir: PathBuf,
    index_dir: PathBuf,
    config: PackConfig,
    index: Arc<RwLock<PackIndex>>,
    tombstones: Arc<RwLock<ObjectTombstoneLog>>,
    active: Option<ActivePackState>,
    next_seq: u64,
    fsync_count: Arc<AtomicU64>,
}

impl PackWriter {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        packs_dir: PathBuf,
        index_dir: PathBuf,
        config: PackConfig,
        index: Arc<RwLock<PackIndex>>,
        tombstones: Arc<RwLock<ObjectTombstoneLog>>,
        active: Option<ActivePackState>,
        next_seq: u64,
        fsync_count: Arc<AtomicU64>,
    ) -> Self {
        Self {
            packs_dir,
            index_dir,
            config,
            index,
            tombstones,
            active,
            next_seq,
            fsync_count,
        }
    }

    /// Returns the total number of packfile `fsync`/`sync_data` durability barriers executed.
    #[must_use]
    pub fn fsync_count(&self) -> u64 {
        self.fsync_count.load(Ordering::Relaxed)
    }

    /// Returns the currently open active pack identifier, if one is open.
    #[must_use]
    pub fn active_pack_id(&self) -> Option<PackId> {
        self.active.as_ref().map(|a| a.pack_id)
    }

    /// Allocates a strictly increasing unused [`PackId`] in the configured epoch for online compaction.
    pub(crate) fn allocate_next_pack_id(&mut self) -> Result<PackId, PackError> {
        let pack_id = PackId::new(self.config.epoch, self.next_seq);
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or(PackError::ArithmeticOverflow)?;
        Ok(pack_id)
    }

    /// Appends a batch of objects sequentially into the active packfile (rotating and sealing
    /// cleanly upon reaching `target_pack_bytes`) with **one durability barrier per batch**.
    pub fn append_batch(
        &mut self,
        objects: &[PackObjectInput<'_>],
    ) -> Result<Vec<PackLocation>, PackError> {
        if objects.is_empty() {
            return Ok(Vec::new());
        }

        let mut prepared: Vec<([u8; 32], usize)> = Vec::with_capacity(objects.len());
        for (idx, obj) in objects.iter().enumerate() {
            let payload_len = obj.payload.len() as u64;
            if payload_len > self.config.max_object_bytes {
                return Err(PackError::ObjectTooLarge {
                    length: payload_len,
                    maximum: self.config.max_object_bytes,
                });
            }
            let digest_bytes = sha256(obj.payload);
            if let Some(expected) = obj.expected_digest {
                if expected.algorithm() != DigestAlgorithm::Sha256 {
                    return Err(PackError::UnsupportedDigestAlgorithm(expected.algorithm()));
                }
                if expected.bytes() != digest_bytes {
                    return Err(PackError::DigestMismatch {
                        expected,
                        actual: ContentDigest::new(DigestAlgorithm::Sha256, digest_bytes),
                    });
                }
            }
            prepared.push((digest_bytes, idx));
        }

        // Check actual payload identities before deduplication, pack rotation, or any write.
        // Catalog ownership prevents deletion commitment until this append finishes.
        {
            let tombstones = self
                .tombstones
                .read()
                .map_err(|_| PackError::LockPoisoned)?;
            for (digest, _) in &prepared {
                if let Some(reason_digest) = tombstones.get_sha256(digest) {
                    return Err(PackError::EvidenceDeleted {
                        digest: ContentDigest::new(DigestAlgorithm::Sha256, *digest),
                        reason_digest,
                    });
                }
            }
        }

        let mut results: Vec<Option<PackLocation>> = vec![None; objects.len()];
        let mut to_write: Vec<(usize, [u8; 32])> = Vec::new();
        let mut batch_seen: HashMap<[u8; 32], usize> = HashMap::new();
        let mut intra_batch_dups: Vec<(usize, usize)> = Vec::new();
        let mut new_payload_bytes = 0_u64;
        {
            let index_guard = self.index.read().map_err(|_| PackError::LockPoisoned)?;
            for &(digest_bytes, idx) in &prepared {
                if let Some(existing) = index_guard.get_sha256(&digest_bytes) {
                    results[idx] = Some(existing);
                } else if let Some(&first_idx) = batch_seen.get(&digest_bytes) {
                    intra_batch_dups.push((idx, first_idx));
                } else {
                    batch_seen.insert(digest_bytes, idx);
                    to_write.push((idx, digest_bytes));
                    new_payload_bytes = new_payload_bytes
                        .checked_add(objects[idx].payload.len() as u64)
                        .ok_or(PackError::ArithmeticOverflow)?;
                }
            }
            if let Some(hard_max) = self.config.quota.hard_max_total_bytes {
                let current = index_guard.total_payload_bytes();
                let projected = current
                    .checked_add(new_payload_bytes)
                    .ok_or(PackError::ArithmeticOverflow)?;
                if projected > hard_max {
                    return Err(PackError::QuotaExceeded {
                        resource: QuotaResource::TotalPayloadBytes,
                        current,
                        requested: new_payload_bytes,
                        maximum: hard_max,
                    });
                }
            }
        }

        if to_write.is_empty() {
            return results
                .into_iter()
                .map(|opt| opt.ok_or(PackError::ArithmeticOverflow))
                .collect();
        }

        let mut sealed_packs: Vec<PackId> = Vec::new();
        let mut cursor = 0_usize;
        while cursor < to_write.len() {
            let first_rec_len = (objects[to_write[cursor].0].payload.len() as u64)
                .checked_add(PACK_RECORD_OVERHEAD_LEN as u64)
                .ok_or(PackError::ArithmeticOverflow)?;

            if let Some(active) = &self.active
                && active.offset > 0
                && active
                    .offset
                    .checked_add(first_rec_len)
                    .is_none_or(|end| end > self.config.target_pack_bytes)
                && let Some(receipt) = self.seal_active()?
            {
                sealed_packs.push(receipt.pack_id);
            }

            self.ensure_active_pack()?;
            let current_offset = self.active.as_ref().ok_or(PackError::LockPoisoned)?.offset;

            let seg_start = cursor;
            let mut planned_offset = current_offset;
            let mut seg_bytes = 0_usize;
            while cursor < to_write.len() {
                let obj = &objects[to_write[cursor].0];
                let rec_len = (obj.payload.len() as u64)
                    .checked_add(PACK_RECORD_OVERHEAD_LEN as u64)
                    .ok_or(PackError::ArithmeticOverflow)?;
                if planned_offset > 0
                    && planned_offset
                        .checked_add(rec_len)
                        .is_none_or(|end| end > self.config.target_pack_bytes)
                {
                    break;
                }
                planned_offset = planned_offset
                    .checked_add(rec_len)
                    .ok_or(PackError::ArithmeticOverflow)?;
                seg_bytes = seg_bytes
                    .checked_add(
                        usize::try_from(rec_len).map_err(|_| PackError::ArithmeticOverflow)?,
                    )
                    .ok_or(PackError::ArithmeticOverflow)?;
                cursor += 1;
            }

            let seal_now = planned_offset >= self.config.target_pack_bytes;
            let mut write_buf = Vec::with_capacity(seg_bytes);
            let mut staged_entries: Vec<(usize, PackFooterEntry)> =
                Vec::with_capacity(cursor - seg_start);

            let active = self.active.as_mut().ok_or(PackError::LockPoisoned)?;
            let pack_id = active.pack_id;
            let rollback_offset = active.offset;
            let rollback_entries_len = active.entries.len();
            let rollback_hasher = active.hasher.clone();

            let mut rec_offset = active.offset;
            for &(idx, digest_bytes) in &to_write[seg_start..cursor] {
                let obj = &objects[idx];
                let before = write_buf.len();
                let _crc = encode_record_into(
                    obj.flags,
                    obj.object_kind,
                    digest_bytes,
                    obj.payload,
                    &mut write_buf,
                );
                let rec_slice = &write_buf[before..];
                active.hasher.update(rec_slice);
                let entry = PackFooterEntry {
                    sha256: digest_bytes,
                    offset: rec_offset,
                    len: obj.payload.len() as u64,
                    kind: obj.object_kind,
                    flags: obj.flags,
                };
                active.entries.push(entry);
                staged_entries.push((idx, entry));
                rec_offset = rec_offset
                    .checked_add(rec_slice.len() as u64)
                    .ok_or(PackError::ArithmeticOverflow)?;
            }

            let sealed_total_len = if seal_now {
                let (footer_bytes, _whole_sha) =
                    encode_sealed_footer(&active.entries, rec_offset, active.hasher.clone())?;
                write_buf.extend_from_slice(&footer_bytes);
                Some(
                    rec_offset
                        .checked_add(footer_bytes.len() as u64)
                        .ok_or(PackError::ArithmeticOverflow)?,
                )
            } else {
                None
            };

            let io_result = (|| -> Result<(), PackError> {
                write_all_bounded(&mut active.file, &write_buf)?;
                self.config.durability.sync_file(&active.file)?;
                Ok(())
            })();

            if let Err(err) = io_result {
                let _ = active.file.set_len(rollback_offset);
                let _ = active.file.seek(SeekFrom::Start(rollback_offset));
                active.offset = rollback_offset;
                active.entries.truncate(rollback_entries_len);
                active.hasher = rollback_hasher;
                return Err(err);
            }

            self.fsync_count.fetch_add(1, Ordering::Relaxed);
            active.offset = sealed_total_len.unwrap_or(rec_offset);
            let final_state = if sealed_total_len.is_some() {
                PackObjectState::Sealed
            } else {
                PackObjectState::Active
            };
            let final_file_len = active.offset;

            if sealed_total_len.is_some() {
                self.active = None;
                sealed_packs.push(pack_id);
            }

            {
                let mut index_guard = self.index.write().map_err(|_| PackError::LockPoisoned)?;
                for &(idx, entry) in &staged_entries {
                    let loc = PackLocation {
                        pack_id,
                        offset: entry.offset,
                        len: entry.len,
                        object_kind: entry.kind,
                        flags: entry.flags,
                        state: final_state,
                    };
                    let _ = index_guard.insert_if_absent(entry.sha256, loc)?;
                    results[idx] = Some(loc);
                }
                if let Some(total_len) = sealed_total_len {
                    index_guard.mark_pack_sealed(pack_id, total_len);
                } else {
                    index_guard.upsert_pack(PackInventoryEntry {
                        pack_id,
                        file_len: final_file_len,
                        sealed: false,
                    });
                }
            }

            if sealed_total_len.is_some() && self.config.auto_save_index_on_seal {
                let index_snapshot = self
                    .index
                    .read()
                    .map_err(|_| PackError::LockPoisoned)?
                    .clone();
                let _ = index_snapshot.save_atomic(&self.index_dir, self.config.durability)?;
            }
        }

        for (dup_idx, first_idx) in intra_batch_dups {
            results[dup_idx] = results[first_idx];
        }
        if !sealed_packs.is_empty() {
            for loc in results.iter_mut().flatten() {
                if sealed_packs.contains(&loc.pack_id) {
                    loc.state = PackObjectState::Sealed;
                }
            }
        }

        results
            .into_iter()
            .map(|opt| opt.ok_or(PackError::ArithmeticOverflow))
            .collect()
    }

    /// Explicitly seals the currently active packfile (if non-empty) with its `FSSF`..`FSSE`
    /// footer, fsyncs it, drops the writer FD, and marks its indexed objects `Sealed`.
    pub fn seal_active(&mut self) -> Result<Option<SealedPackReceipt>, PackError> {
        let Some(mut active) = self.active.take() else {
            return Ok(None);
        };
        if active.entries.is_empty() && active.offset == 0 {
            self.active = Some(active);
            return Ok(None);
        }

        let footer_offset = active.offset;
        let entry_count = active.entries.len() as u64;
        let (footer_bytes, whole_sha) =
            encode_sealed_footer(&active.entries, footer_offset, active.hasher.clone())?;
        let total_bytes = footer_offset
            .checked_add(footer_bytes.len() as u64)
            .ok_or(PackError::ArithmeticOverflow)?;

        let write_res = (|| -> Result<(), PackError> {
            write_all_bounded(&mut active.file, &footer_bytes)?;
            self.config.durability.sync_file(&active.file)?;
            Ok(())
        })();

        if let Err(err) = write_res {
            let _ = active.file.set_len(footer_offset);
            let _ = active.file.seek(SeekFrom::Start(footer_offset));
            self.active = Some(active);
            return Err(err);
        }

        self.fsync_count.fetch_add(1, Ordering::Relaxed);
        let pack_id = active.pack_id;
        drop(active);

        {
            let mut index_guard = self.index.write().map_err(|_| PackError::LockPoisoned)?;
            index_guard.mark_pack_sealed(pack_id, total_bytes);
        }

        if self.config.auto_save_index_on_seal {
            let index_snapshot = self
                .index
                .read()
                .map_err(|_| PackError::LockPoisoned)?
                .clone();
            let _ = index_snapshot.save_atomic(&self.index_dir, self.config.durability)?;
        }

        Ok(Some(SealedPackReceipt {
            pack_id,
            entry_count,
            footer_offset,
            total_bytes,
            whole_pack_digest: ContentDigest::new(DigestAlgorithm::Sha256, whole_sha),
        }))
    }

    fn ensure_active_pack(&mut self) -> Result<(), PackError> {
        if self.active.is_some() {
            return Ok(());
        }
        let pack_id = PackId::new(self.config.epoch, self.next_seq);
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or(PackError::ArithmeticOverflow)?;
        let path = self.packs_dir.join(pack_id.file_name());
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|err| PackError::io(PackIoOperation::Open, err))?;
        sync_dir(&self.packs_dir, self.config.durability)?;
        self.active = Some(ActivePackState {
            pack_id,
            file,
            offset: 0,
            hasher: Sha256Hasher::new(),
            entries: Vec::new(),
        });
        Ok(())
    }
}
