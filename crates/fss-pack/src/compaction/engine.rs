#![forbid(unsafe_code)]
//! Live-byte accounting, verified live-object streaming, atomic index swap, and reader-epoch
//! drain execution for online sealed packfile compaction.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::Duration;

use fss_core::{ContentDigest, Sha256Hasher};

use crate::error::{PackCutPoint, PackError, PackIoOperation};
use crate::fd_pool::FdPool;
use crate::format::{
    DurabilityMode, PACK_RECORD_OVERHEAD_LEN, PackFooterEntry, PackId, PackLocation,
    PackObjectState, encode_record_into, encode_sealed_footer, sync_dir, verify_record_slice,
    write_all_bounded,
};
use crate::index::{PackIndex, PackInventoryEntry};
use crate::packfile::read_sealed_footer_from_file;
use crate::retention::{ObjectTombstoneLog, TombstoneCommitProof};

use super::{
    CompactionPolicy, PackCompactionAction, PackCompactionReceipt, PackLiveStats,
    ReaderEpochTracker, compact_staging_file_name,
};

/// Computes live-object and live-byte statistics for sealed packfile `pack_id`.
pub(crate) fn compute_pack_live_stats(
    packs_dir: &Path,
    index: &PackIndex,
    tombstones: &ObjectTombstoneLog,
    pack_id: PackId,
) -> Result<(PackLiveStats, Vec<PackFooterEntry>, Vec<PackFooterEntry>), PackError> {
    let Some(pack_meta) = index.pack_entry(pack_id) else {
        return Err(PackError::CorruptPack {
            pack_id,
            offset: 0,
            detail: "pack_id is not present in pack inventory".to_owned(),
        });
    };
    if !pack_meta.sealed {
        return Err(PackError::PackNotSealed(pack_id));
    }

    let path = packs_dir.join(pack_id.file_name());
    let file = fs::File::open(&path).map_err(|err| PackError::io(PackIoOperation::Open, err))?;
    let file_len = file
        .metadata()
        .map_err(|err| PackError::io(PackIoOperation::Metadata, err))?
        .len();
    let footer = read_sealed_footer_from_file(&file, pack_id, file_len)?;

    let mut total_bytes = 0_u64;
    let mut live_bytes = 0_u64;
    let mut live_entries = Vec::new();
    let mut dead_entries = Vec::new();

    for entry in footer.entries {
        let framed_len = entry
            .len
            .checked_add(PACK_RECORD_OVERHEAD_LEN as u64)
            .ok_or(PackError::ArithmeticOverflow)?;
        total_bytes = total_bytes
            .checked_add(framed_len)
            .ok_or(PackError::ArithmeticOverflow)?;
        let is_live_here = !tombstones.contains_sha256(&entry.sha256)
            && index
                .get_sha256(&entry.sha256)
                .is_some_and(|loc| loc.pack_id == pack_id);
        if is_live_here {
            live_bytes = live_bytes
                .checked_add(framed_len)
                .ok_or(PackError::ArithmeticOverflow)?;
            live_entries.push(entry);
        } else {
            dead_entries.push(entry);
        }
    }

    let total_objects = (live_entries.len() + dead_entries.len()) as u64;
    let live_objects = live_entries.len() as u64;
    let live_ratio_ppm = if total_bytes == 0 {
        0
    } else {
        let ppm = (u128::from(live_bytes) * 1_000_000) / u128::from(total_bytes);
        u32::try_from(ppm.min(1_000_000)).unwrap_or(1_000_000)
    };

    let stats = PackLiveStats {
        pack_id,
        total_objects,
        live_objects,
        total_bytes,
        live_bytes,
        live_ratio_ppm,
    };
    Ok((stats, live_entries, dead_entries))
}

/// Verifies that every dead entry in `pack_id` is authorized for physical reclamation.
pub(crate) fn verify_dead_entries_authorized(
    pack_id: PackId,
    dead_entries: &[PackFooterEntry],
    proof: Option<&TombstoneCommitProof>,
    index: &PackIndex,
    tombstones: &ObjectTombstoneLog,
) -> Result<Option<ContentDigest>, PackError> {
    let proof_digest = if let Some(p) = proof {
        p.verify()?;
        for digest in &p.committed_digests {
            if !tombstones.contains_sha256(&digest.bytes()) {
                return Err(PackError::UncommittedTombstone {
                    pack_id,
                    digest: *digest,
                });
            }
        }
        Some(p.proof_digest)
    } else {
        None
    };

    for entry in dead_entries {
        let live_elsewhere = index
            .get_sha256(&entry.sha256)
            .is_some_and(|loc| loc.pack_id != pack_id);
        if live_elsewhere {
            continue;
        }
        if !tombstones.contains_sha256(&entry.sha256) {
            return Err(PackError::UncommittedTombstone {
                pack_id,
                digest: entry.digest(),
            });
        }
    }

    Ok(proof_digest)
}

/// Streams live entries from `source_pack_id`, re-verifies every CRC32C and SHA-256 digest,
/// writes and fsyncs a fresh sealed staging pack (`*.pack.compact.tmp`), and returns the new
/// footer entries, sealed byte length, and staging path.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_compacted_staging_pack(
    packs_dir: &Path,
    fd_pool: &FdPool,
    durability: DurabilityMode,
    max_object_bytes: u64,
    max_read_bytes: u64,
    source_pack_id: PackId,
    target_pack_id: PackId,
    live_entries: &[PackFooterEntry],
) -> Result<(Vec<PackFooterEntry>, u64, PathBuf), PackError> {
    let staging_path = packs_dir.join(compact_staging_file_name(target_pack_id));
    let mut staging_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&staging_path)
        .map_err(|err| PackError::io(PackIoOperation::Open, err))?;

    let mut hasher = Sha256Hasher::new();
    let mut new_entries = Vec::with_capacity(live_entries.len());
    let mut out_offset = 0_u64;
    let mut write_buf = Vec::new();

    let copy_res = (|| -> Result<u64, PackError> {
        for entry in live_entries {
            if entry.len > max_object_bytes {
                return Err(PackError::ObjectTooLarge {
                    length: entry.len,
                    maximum: max_object_bytes,
                });
            }
            let record_len_u64 = entry
                .len
                .checked_add(PACK_RECORD_OVERHEAD_LEN as u64)
                .ok_or(PackError::ArithmeticOverflow)?;
            if record_len_u64 > max_read_bytes {
                return Err(PackError::ReadLimitExceeded {
                    current: 0,
                    requested: record_len_u64,
                    maximum: max_read_bytes,
                });
            }
            let record_len =
                usize::try_from(record_len_u64).map_err(|_| PackError::ArithmeticOverflow)?;
            let mut raw = vec![0_u8; record_len];
            fd_pool.read_exact_at(source_pack_id, entry.offset, &mut raw)?;

            // Re-verify header, CRC32C, AND exact SHA-256 content digest before copying!
            let (header, payload) =
                verify_record_slice(source_pack_id, entry.offset, &raw, Some(entry.digest()))?;

            write_buf.clear();
            let _crc = encode_record_into(
                header.flags,
                header.object_kind,
                header.content_sha256,
                payload,
                &mut write_buf,
            );
            hasher.update(&write_buf);
            write_all_bounded(&mut staging_file, &write_buf)?;

            new_entries.push(PackFooterEntry {
                sha256: header.content_sha256,
                offset: out_offset,
                len: payload.len() as u64,
                kind: header.object_kind,
                flags: header.flags,
            });
            out_offset = out_offset
                .checked_add(write_buf.len() as u64)
                .ok_or(PackError::ArithmeticOverflow)?;
        }

        let (footer_bytes, _whole_sha) =
            encode_sealed_footer(&new_entries, out_offset, hasher.clone())?;
        write_all_bounded(&mut staging_file, &footer_bytes)?;
        durability.sync_file(&staging_file)?;

        let sealed_len = out_offset
            .checked_add(footer_bytes.len() as u64)
            .ok_or(PackError::ArithmeticOverflow)?;
        Ok(sealed_len)
    })();

    drop(staging_file);
    match copy_res {
        Ok(sealed_len) => Ok((new_entries, sealed_len, staging_path)),
        Err(err) => {
            let _ = fs::remove_file(&staging_path);
            Err(err)
        }
    }
}

/// Executes atomic replacement, reader-epoch drain, and old packfile unlink for one sealed pack.
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_pack_compaction<F>(
    packs_dir: &Path,
    index_dir: &Path,
    fd_pool: &FdPool,
    index_lock: &RwLock<PackIndex>,
    tombstones_lock: &RwLock<ObjectTombstoneLog>,
    reader_epochs: &ReaderEpochTracker,
    durability: DurabilityMode,
    max_object_bytes: u64,
    max_read_bytes: u64,
    pack_id: PackId,
    proof: Option<&TombstoneCommitProof>,
    policy: CompactionPolicy,
    allocate_target_id: F,
    cut_point: Option<PackCutPoint>,
) -> Result<PackCompactionReceipt, PackError>
where
    F: FnOnce() -> Result<PackId, PackError>,
{
    let policy = policy.validate()?;
    let (stats, live_entries, dead_entries, proof_digest, old_file_bytes) = {
        let index_guard = index_lock.read().map_err(|_| PackError::LockPoisoned)?;
        let tomb_guard = tombstones_lock
            .read()
            .map_err(|_| PackError::LockPoisoned)?;
        let (stats, live_entries, dead_entries) =
            compute_pack_live_stats(packs_dir, &index_guard, &tomb_guard, pack_id)?;
        let old_file_bytes = index_guard
            .pack_entry(pack_id)
            .map_or(0, |entry| entry.file_len);
        // Always verify caller-supplied TombstoneCommitProof BEFORE threshold skipping so
        // tampered or uncommitted proofs fail closed unconditionally.
        let proof_digest = verify_dead_entries_authorized(
            pack_id,
            &dead_entries,
            proof,
            &index_guard,
            &tomb_guard,
        )?;
        if stats.live_ratio_ppm >= policy.min_live_ratio_ppm {
            return Ok(PackCompactionReceipt {
                source_pack_id: pack_id,
                action: PackCompactionAction::SkippedAboveThreshold,
                stats_before: stats,
                copied_live_objects: 0,
                bytes_reclaimed: 0,
                drained_reader_epoch: None,
                tombstone_proof_digest: proof_digest,
            });
        }
        (
            stats,
            live_entries,
            dead_entries,
            proof_digest,
            old_file_bytes,
        )
    };

    let (action, copied_live_objects, new_file_bytes) = if live_entries.is_empty() {
        {
            let mut index_guard = index_lock.write().map_err(|_| PackError::LockPoisoned)?;
            for dead in &dead_entries {
                if index_guard
                    .get_sha256(&dead.sha256)
                    .is_some_and(|loc| loc.pack_id == pack_id)
                {
                    let _ = index_guard.remove_sha256(&dead.sha256);
                }
            }
        }
        let index_snap = index_lock
            .read()
            .map_err(|_| PackError::LockPoisoned)?
            .clone();
        let _ = index_snap.save_atomic(index_dir, durability)?;
        (PackCompactionAction::UnlinkedEmpty, 0_u64, 0_u64)
    } else {
        let target_pack_id = allocate_target_id()?;
        let (new_entries, sealed_len, staging_path) = write_compacted_staging_pack(
            packs_dir,
            fd_pool,
            durability,
            max_object_bytes,
            max_read_bytes,
            pack_id,
            target_pack_id,
            &live_entries,
        )?;

        if matches!(cut_point, Some(PackCutPoint::CompactionBeforeStagingRename)) {
            return Err(PackError::InjectedCrash(
                PackCutPoint::CompactionBeforeStagingRename,
            ));
        }

        let final_new_path = packs_dir.join(target_pack_id.file_name());
        fs::rename(&staging_path, &final_new_path)
            .map_err(|err| PackError::io(PackIoOperation::Rename, err))?;
        sync_dir(packs_dir, durability)?;

        if matches!(
            cut_point,
            Some(PackCutPoint::CompactionAfterNewPackBeforeIndexSwap)
        ) {
            return Err(PackError::InjectedCrash(
                PackCutPoint::CompactionAfterNewPackBeforeIndexSwap,
            ));
        }

        let copied = new_entries.len() as u64;
        {
            let mut index_guard = index_lock.write().map_err(|_| PackError::LockPoisoned)?;
            index_guard.upsert_pack(PackInventoryEntry {
                pack_id: target_pack_id,
                file_len: sealed_len,
                sealed: true,
            });
            for entry in &new_entries {
                let loc = PackLocation {
                    pack_id: target_pack_id,
                    offset: entry.offset,
                    len: entry.len,
                    object_kind: entry.kind,
                    flags: entry.flags,
                    state: PackObjectState::Sealed,
                };
                let _ = index_guard.insert_or_replace(entry.sha256, loc)?;
            }
            for dead in &dead_entries {
                if index_guard
                    .get_sha256(&dead.sha256)
                    .is_some_and(|loc| loc.pack_id == pack_id)
                {
                    let _ = index_guard.remove_sha256(&dead.sha256);
                }
            }
        }
        let index_snap = index_lock
            .read()
            .map_err(|_| PackError::LockPoisoned)?
            .clone();
        let _ = index_snap.save_atomic(index_dir, durability)?;

        (
            PackCompactionAction::RewrittenAndUnlinked {
                replacement_pack_id: target_pack_id,
            },
            copied,
            sealed_len,
        )
    };

    if matches!(
        cut_point,
        Some(PackCutPoint::CompactionAfterIndexSwapBeforeOldPackUnlink)
    ) {
        return Err(PackError::InjectedCrash(
            PackCutPoint::CompactionAfterIndexSwapBeforeOldPackUnlink,
        ));
    }

    let retired_epoch = reader_epochs.advance_epoch()?;
    reader_epochs.wait_for_drain(
        retired_epoch,
        Duration::from_millis(policy.reader_drain_timeout_ms),
    )?;

    fd_pool.invalidate(pack_id);
    let old_path = packs_dir.join(pack_id.file_name());
    if old_path.exists() {
        fs::remove_file(&old_path).map_err(|err| PackError::io(PackIoOperation::Remove, err))?;
        sync_dir(packs_dir, durability)?;
    }

    {
        let mut index_guard = index_lock.write().map_err(|_| PackError::LockPoisoned)?;
        let _ = index_guard.remove_pack(pack_id);
    }
    let final_index_snap = index_lock
        .read()
        .map_err(|_| PackError::LockPoisoned)?
        .clone();
    let _ = final_index_snap.save_atomic(index_dir, durability)?;

    Ok(PackCompactionReceipt {
        source_pack_id: pack_id,
        action,
        stats_before: stats,
        copied_live_objects,
        bytes_reclaimed: old_file_bytes.saturating_sub(new_file_bytes),
        drained_reader_epoch: Some(retired_epoch),
        tombstone_proof_digest: proof_digest,
    })
}
