#![forbid(unsafe_code)]
//! Sealed packfile verification, verified object reads, and deterministic crash recovery.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::path::Path;

use fss_core::{ContentDigest, Sha256Hasher};

use crate::compaction::COMPACT_STAGING_SUFFIX;
use crate::error::{PackError, PackIoOperation};
use crate::fd_pool::FdPool;
use crate::format::{
    PACK_FOOTER_MAGIC, PACK_FOOTER_PREFIX_LEN, PACK_FOOTER_TAIL_LEN, PACK_RECORD_HEADER_LEN,
    PACK_RECORD_MAGIC, PACK_RECORD_OVERHEAD_LEN, PackFooter, PackFooterEntry, PackId, PackLocation,
    PackObjectState, decode_footer_tail, decode_record_header, decode_sealed_footer,
    encode_sealed_footer, read_exact_at_bounded, sync_dir, verify_record_slice, write_all_bounded,
};
use crate::index::{IndexLoadOutcome, IndexRebuildReason, PackIndex, PackInventoryEntry};
use crate::packfile::{ActivePackState, PackConfig, PackRecoveryReport};

/// Reads and verifies one object payload at `location`, checking bounds, `FSSP` header,
/// Castagnoli CRC32C, and exact SHA-256 content digest.
pub(crate) fn read_verified_location(
    fd_pool: &FdPool,
    expected_digest: ContentDigest,
    location: PackLocation,
    max_object_bytes: u64,
    max_read_bytes: u64,
) -> Result<Vec<u8>, PackError> {
    if location.len > max_object_bytes {
        return Err(PackError::ObjectTooLarge {
            length: location.len,
            maximum: max_object_bytes,
        });
    }
    let record_len_u64 = location.record_len()?;
    if record_len_u64 > max_read_bytes {
        return Err(PackError::ReadLimitExceeded {
            current: 0,
            requested: record_len_u64,
            maximum: max_read_bytes,
        });
    }
    let record_len = usize::try_from(record_len_u64).map_err(|_| PackError::ArithmeticOverflow)?;
    let mut buf = vec![0_u8; record_len];
    fd_pool.read_exact_at(location.pack_id, location.offset, &mut buf)?;
    let (_header, payload) = verify_record_slice(
        location.pack_id,
        location.offset,
        &buf,
        Some(expected_digest),
    )?;
    Ok(payload.to_vec())
}

/// Verifies complete FSSP record inventory, metadata, CRC32C, payload SHA-256s and sealed digest.
pub fn verify_sealed_pack(packs_dir: &Path, pack_id: PackId) -> Result<PackFooter, PackError> {
    verify_sealed_pack_with_digest(packs_dir, pack_id).map(|(footer, _)| footer)
}

/// Also returns the digest of the entire verified file for later encryption or transfer.
pub fn verify_sealed_pack_with_digest(
    packs_dir: &Path,
    pack_id: PackId,
) -> Result<(PackFooter, ContentDigest), PackError> {
    let path = packs_dir.join(pack_id.file_name());
    let mut file = File::open(&path).map_err(|err| PackError::io(PackIoOperation::Open, err))?;
    super::verified::verify(&mut file, pack_id)
}

/// Reads and structurally parses the `FSSF`..`FSSE` footer of a sealed packfile in O(footer_bytes).
pub(crate) fn read_sealed_footer_from_file(
    file: &File,
    pack_id: PackId,
    file_len: u64,
) -> Result<PackFooter, PackError> {
    if file_len < (PACK_FOOTER_PREFIX_LEN + PACK_FOOTER_TAIL_LEN) as u64 {
        return Err(PackError::CorruptPack {
            pack_id,
            offset: 0,
            detail: "pack too small to contain sealed footer".to_owned(),
        });
    }
    let mut tail_buf = [0_u8; PACK_FOOTER_TAIL_LEN];
    read_exact_at_bounded(file, file_len - PACK_FOOTER_TAIL_LEN as u64, &mut tail_buf)?;
    let tail = decode_footer_tail(&tail_buf).ok_or_else(|| PackError::CorruptPack {
        pack_id,
        offset: file_len - PACK_FOOTER_TAIL_LEN as u64,
        detail: "missing FSSE footer end magic".to_owned(),
    })?;
    if tail.footer_offset >= file_len - PACK_FOOTER_TAIL_LEN as u64 {
        return Err(PackError::CorruptPack {
            pack_id,
            offset: tail.footer_offset,
            detail: "footer_offset out of file bounds".to_owned(),
        });
    }
    let footer_len_u64 = file_len - tail.footer_offset;
    let footer_len = usize::try_from(footer_len_u64).map_err(|_| PackError::ArithmeticOverflow)?;
    let mut footer_raw = vec![0_u8; footer_len];
    read_exact_at_bounded(file, tail.footer_offset, &mut footer_raw)?;
    decode_sealed_footer(pack_id, tail.footer_offset, &footer_raw)
}

/// Recovers on-disk packfiles and either loads the verified `pack-index.fssi` cache or
/// deterministically rebuilds it from sealed footers and the active pack tail.
///
/// Automatically cleans up orphaned compaction staging files (`*.pack.compact.tmp`) and ensures
/// durably tombstoned objects are never resurrected during index rebuilds.
pub(crate) fn recover_packs_and_index(
    packs_dir: &Path,
    index_dir: &Path,
    config: PackConfig,
    tombstoned: &HashMap<[u8; 32], ContentDigest>,
) -> Result<(PackIndex, Option<ActivePackState>, u64, PackRecoveryReport), PackError> {
    let mut on_disk_packs: BTreeMap<PackId, u64> = BTreeMap::new();
    let mut cleaned_staging_packs = Vec::new();
    let mut foreign_entries = Vec::new();
    for dir_entry in
        fs::read_dir(packs_dir).map_err(|err| PackError::io(PackIoOperation::ReadDir, err))?
    {
        let entry = dir_entry.map_err(|err| PackError::io(PackIoOperation::ReadDir, err))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(COMPACT_STAGING_SUFFIX) {
            let meta = entry
                .metadata()
                .map_err(|err| PackError::io(PackIoOperation::Metadata, err))?;
            if meta.is_file() {
                fs::remove_file(entry.path())
                    .map_err(|err| PackError::io(PackIoOperation::Remove, err))?;
                cleaned_staging_packs.push(name);
                continue;
            }
        }
        if let Some(pack_id) = PackId::parse_file_name(&name) {
            let meta = entry
                .metadata()
                .map_err(|err| PackError::io(PackIoOperation::Metadata, err))?;
            if !meta.is_file() {
                foreign_entries.push(name);
                continue;
            }
            on_disk_packs.insert(pack_id, meta.len());
        } else {
            foreign_entries.push(name);
        }
    }
    cleaned_staging_packs.sort();
    foreign_entries.sort();
    if !cleaned_staging_packs.is_empty() {
        sync_dir(packs_dir, config.durability)?;
    }

    let next_seq = on_disk_packs
        .keys()
        .filter(|id| id.epoch == config.epoch)
        .map(|id| id.seq)
        .max()
        .map_or(1, |s| s.saturating_add(1));

    let index_path = index_dir.join("pack-index.fssi");
    match PackIndex::load_verified(&index_path, &on_disk_packs) {
        IndexLoadOutcome::Loaded(mut loaded) => {
            for sha in tombstoned.keys() {
                let _ = loaded.remove_sha256(sha);
            }
            let tip_unsealed = loaded
                .packs()
                .values()
                .next_back()
                .filter(|entry| !entry.sealed)
                .copied();

            if let Some(active_meta) = tip_unsealed {
                let (active_state, truncated, _entries) =
                    recover_active_pack_tail(packs_dir, active_meta.pack_id, config)?;
                if truncated == 0 {
                    let sealed_count = loaded.packs().values().filter(|p| p.sealed).count();
                    let report = PackRecoveryReport {
                        sealed_pack_count: sealed_count,
                        active_pack_id: Some(active_meta.pack_id),
                        indexed_objects: loaded.len(),
                        index_rebuild_reason: None,
                        truncated_tail_bytes: 0,
                        cleaned_staging_packs,
                        foreign_entries,
                    };
                    return Ok((loaded, Some(active_state), next_seq, report));
                }
                return rebuild_index_from_packs(
                    packs_dir,
                    index_dir,
                    &on_disk_packs,
                    config,
                    next_seq,
                    IndexRebuildReason::ActivePackRecovered,
                    cleaned_staging_packs,
                    foreign_entries,
                    truncated,
                    tombstoned,
                );
            }

            let sealed_count = loaded.packs().values().filter(|p| p.sealed).count();
            let report = PackRecoveryReport {
                sealed_pack_count: sealed_count,
                active_pack_id: None,
                indexed_objects: loaded.len(),
                index_rebuild_reason: None,
                truncated_tail_bytes: 0,
                cleaned_staging_packs,
                foreign_entries,
            };
            Ok((loaded, None, next_seq, report))
        }
        IndexLoadOutcome::NeedsRebuild(reason) => rebuild_index_from_packs(
            packs_dir,
            index_dir,
            &on_disk_packs,
            config,
            next_seq,
            reason,
            cleaned_staging_packs,
            foreign_entries,
            0,
            tombstoned,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn rebuild_index_from_packs(
    packs_dir: &Path,
    index_dir: &Path,
    on_disk_packs: &BTreeMap<PackId, u64>,
    config: PackConfig,
    next_seq: u64,
    reason: IndexRebuildReason,
    cleaned_staging_packs: Vec<String>,
    foreign_entries: Vec<String>,
    initial_truncated: u64,
    tombstoned: &HashMap<[u8; 32], ContentDigest>,
) -> Result<(PackIndex, Option<ActivePackState>, u64, PackRecoveryReport), PackError> {
    let mut index = PackIndex::new();
    let mut sealed_count = 0_usize;
    let mut active_state: Option<ActivePackState> = None;
    let mut total_truncated = initial_truncated;

    let pack_ids: Vec<PackId> = on_disk_packs.keys().copied().collect();
    let last_idx = pack_ids.len().saturating_sub(1);

    for (pos, pack_id) in pack_ids.into_iter().enumerate() {
        let path = packs_dir.join(pack_id.file_name());
        let file = File::open(&path).map_err(|err| PackError::io(PackIoOperation::Open, err))?;
        let current_len = file
            .metadata()
            .map_err(|err| PackError::io(PackIoOperation::Metadata, err))?
            .len();

        if let Ok(footer) = read_sealed_footer_from_file(&file, pack_id, current_len) {
            for entry in footer.entries {
                if !tombstoned.contains_key(&entry.sha256) {
                    let _ =
                        index.insert_or_replace(entry.sha256, entry.to_sealed_location(pack_id))?;
                }
            }
            index.upsert_pack(PackInventoryEntry {
                pack_id,
                file_len: current_len,
                sealed: true,
            });
            sealed_count += 1;
            continue;
        }

        drop(file);
        let (mut recovered, truncated, entries) =
            recover_active_pack_tail(packs_dir, pack_id, config)?;
        total_truncated = total_truncated
            .checked_add(truncated)
            .ok_or(PackError::ArithmeticOverflow)?;

        if pos == last_idx {
            for entry in &entries {
                if !tombstoned.contains_key(&entry.sha256) {
                    let loc = PackLocation {
                        pack_id,
                        offset: entry.offset,
                        len: entry.len,
                        object_kind: entry.kind,
                        flags: entry.flags,
                        state: PackObjectState::Active,
                    };
                    let _ = index.insert_or_replace(entry.sha256, loc)?;
                }
            }
            index.upsert_pack(PackInventoryEntry {
                pack_id,
                file_len: recovered.offset,
                sealed: false,
            });
            active_state = Some(recovered);
        } else {
            let footer_offset = recovered.offset;
            let (footer_bytes, _whole) =
                encode_sealed_footer(&recovered.entries, footer_offset, recovered.hasher.clone())?;
            write_all_bounded(&mut recovered.file, &footer_bytes)?;
            config.durability.sync_file(&recovered.file)?;
            let sealed_len = footer_offset
                .checked_add(footer_bytes.len() as u64)
                .ok_or(PackError::ArithmeticOverflow)?;
            for entry in &entries {
                if !tombstoned.contains_key(&entry.sha256) {
                    let _ =
                        index.insert_or_replace(entry.sha256, entry.to_sealed_location(pack_id))?;
                }
            }
            index.upsert_pack(PackInventoryEntry {
                pack_id,
                file_len: sealed_len,
                sealed: true,
            });
            sealed_count += 1;
        }
    }

    let _ = index.save_atomic(index_dir, config.durability)?;

    let report = PackRecoveryReport {
        sealed_pack_count: sealed_count,
        active_pack_id: active_state.as_ref().map(|a| a.pack_id),
        indexed_objects: index.len(),
        index_rebuild_reason: Some(reason),
        truncated_tail_bytes: total_truncated,
        cleaned_staging_packs,
        foreign_entries,
    };
    Ok((index, active_state, next_seq, report))
}

fn recover_active_pack_tail(
    packs_dir: &Path,
    pack_id: PackId,
    config: PackConfig,
) -> Result<(ActivePackState, u64, Vec<PackFooterEntry>), PackError> {
    let path = packs_dir.join(pack_id.file_name());
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|err| PackError::io(PackIoOperation::Open, err))?;
    let file_len = file
        .metadata()
        .map_err(|err| PackError::io(PackIoOperation::Metadata, err))?
        .len();

    let mut offset = 0_u64;
    let mut hasher = Sha256Hasher::new();
    let mut entries = Vec::new();
    let mut header_buf = [0_u8; PACK_RECORD_HEADER_LEN];

    while offset < file_len {
        let remaining = file_len - offset;
        if remaining < PACK_RECORD_HEADER_LEN as u64 {
            break;
        }
        read_exact_at_bounded(&file, offset, &mut header_buf)?;
        if header_buf[0..4] == PACK_FOOTER_MAGIC || header_buf[0..4] != PACK_RECORD_MAGIC {
            break;
        }
        let Ok(header) = decode_record_header(pack_id, offset, &header_buf) else {
            break;
        };
        if header.payload_len > config.max_object_bytes {
            break;
        }
        let Some(rec_len_u64) = header
            .payload_len
            .checked_add(PACK_RECORD_OVERHEAD_LEN as u64)
        else {
            break;
        };
        if rec_len_u64 > remaining {
            break;
        }
        let Ok(rec_len) = usize::try_from(rec_len_u64) else {
            break;
        };
        let mut raw_record = vec![0_u8; rec_len];
        if read_exact_at_bounded(&file, offset, &mut raw_record).is_err() {
            break;
        }
        if verify_record_slice(pack_id, offset, &raw_record, None).is_err() {
            break;
        }

        hasher.update(&raw_record);
        entries.push(PackFooterEntry {
            sha256: header.content_sha256,
            offset,
            len: header.payload_len,
            kind: header.object_kind,
            flags: header.flags,
        });
        offset = offset
            .checked_add(rec_len_u64)
            .ok_or(PackError::ArithmeticOverflow)?;
    }

    let truncated_bytes = file_len.saturating_sub(offset);
    if truncated_bytes > 0 {
        file.set_len(offset)
            .map_err(|err| PackError::io(PackIoOperation::Truncate, err))?;
        config.durability.sync_file(&file)?;
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|err| PackError::io(PackIoOperation::Write, err))?;

    let state = ActivePackState {
        pack_id,
        file,
        offset,
        hasher,
        entries: entries.clone(),
    };
    Ok((state, truncated_bytes, entries))
}
