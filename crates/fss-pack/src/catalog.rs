#![forbid(unsafe_code)]
//! Unbounded virtual root and tombstone catalog (`catalog.fssr` + `catalog.snap`).
//!
//! Replaces per-root filesystem files (`STANDARD_MAX_ROOTS = 128`) with an append-only,
//! Castagnoli CRC32C-framed Root Publication Journal (`<root>/objects/roots/catalog.fssr`)
//! paired with periodic atomic compacted snapshots (`<root>/objects/roots/catalog.snap`).
//! Supports 100,000+ roots and 100+ GiB with O(1) lookup, deterministic cursor pagination,
//! soft/hard configurable quota policies, and permanent tombstone retention.

mod codec;
mod record;

use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::ops::Bound;
use std::path::PathBuf;

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm};

use crate::crc32c::crc32c;
use crate::error::{PackError, PackIoOperation, QuotaResource};
use crate::format::{DurabilityMode, read_exact_at_bounded, sync_dir, write_all_bounded};
use crate::packfile::QuotaPolicy;

use codec::{
    JOURNAL_HEADER_LEN, JOURNAL_TRAILER_LEN, OP_PUBLISH, OP_SUPERSEDE, OP_TOMBSTONE,
    apply_journal_op, encode_journal_frame, encode_snapshot, load_snapshot_if_present,
};

pub use record::{
    CatalogRecoveryReport, CatalogRootEntry, CompactionReceipt, MAX_ROOT_ID_BYTES,
    MAX_ROOT_KIND_BYTES, PACK_VIRTUAL_ROOT_RECORD_DOMAIN, QuotaStatus, RootPage,
    RootPublishReceipt, RootStatus, VirtualRootRecord, validate_root_id,
};

/// Magic bytes for each append-only root journal frame in `catalog.fssr`.
pub const CATALOG_JOURNAL_MAGIC: [u8; 4] = *b"FSSR";
/// Magic bytes for compacted root catalog snapshots in `catalog.snap`.
pub const CATALOG_SNAPSHOT_MAGIC: [u8; 4] = *b"FSSS";
/// Format version for both `catalog.fssr` frames and `catalog.snap` snapshots.
pub const CATALOG_FORMAT_VERSION: u16 = 1;
/// Maximum byte length of a single journal frame body (64 KiB).
pub const MAX_JOURNAL_BODY_BYTES: usize = 64 * 1024;
/// Maximum byte length of a compacted snapshot file (512 MiB).
pub const MAX_CATALOG_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;

/// Append-only CRC32C-framed virtual root catalog with periodic atomic snapshot compaction.
pub struct VirtualRootCatalog {
    roots_dir: PathBuf,
    durability: DurabilityMode,
    quota: QuotaPolicy,
    journal_file: File,
    journal_offset: u64,
    last_seq: u64,
    ops_since_compact: u64,
    fsync_count: u64,
    entries: HashMap<String, CatalogRootEntry>,
    ordered_ids: BTreeSet<String>,
    live_count: u64,
    live_payload_bytes: u64,
}

impl VirtualRootCatalog {
    /// Opens or creates a virtual root catalog inside `roots_dir`, loading `catalog.snap` if
    /// present and replaying `catalog.fssr` (cleanly truncating any torn tail frame).
    pub fn open(
        roots_dir: PathBuf,
        durability: DurabilityMode,
        quota: QuotaPolicy,
    ) -> Result<(Self, CatalogRecoveryReport), PackError> {
        fs::create_dir_all(&roots_dir)
            .map_err(|err| PackError::io(PackIoOperation::CreateDir, err))?;

        let snap_path = roots_dir.join("catalog.snap");
        let (snapshot_seq, mut entries, mut ordered_ids, mut live_count, mut live_payload_bytes) =
            load_snapshot_if_present(&snap_path)?;

        let journal_path = roots_dir.join("catalog.fssr");
        let mut journal_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&journal_path)
            .map_err(|err| PackError::io(PackIoOperation::Open, err))?;

        let file_len = journal_file
            .metadata()
            .map_err(|err| PackError::io(PackIoOperation::Metadata, err))?
            .len();

        let mut offset = 0_u64;
        let mut last_seq = snapshot_seq;
        let mut replayed_frames = 0_u64;
        let mut header_buf = [0_u8; JOURNAL_HEADER_LEN];

        while offset < file_len {
            let remaining = file_len - offset;
            if remaining < (JOURNAL_HEADER_LEN + JOURNAL_TRAILER_LEN) as u64 {
                break;
            }
            if read_exact_at_bounded(&journal_file, offset, &mut header_buf).is_err() {
                break;
            }
            if header_buf[0..4] != CATALOG_JOURNAL_MAGIC {
                break;
            }
            let version = u16::from_be_bytes([header_buf[4], header_buf[5]]);
            if version != CATALOG_FORMAT_VERSION {
                return Err(PackError::CorruptCatalog {
                    detail: format!("unsupported catalog journal version {version}"),
                });
            }
            let op_tag = u16::from_be_bytes([header_buf[6], header_buf[7]]);
            let seq = u64::from_be_bytes([
                header_buf[8],
                header_buf[9],
                header_buf[10],
                header_buf[11],
                header_buf[12],
                header_buf[13],
                header_buf[14],
                header_buf[15],
            ]);
            let body_len = u32::from_be_bytes([
                header_buf[16],
                header_buf[17],
                header_buf[18],
                header_buf[19],
            ]) as usize;
            if body_len > MAX_JOURNAL_BODY_BYTES {
                break;
            }
            let frame_len = (JOURNAL_HEADER_LEN + body_len + JOURNAL_TRAILER_LEN) as u64;
            if frame_len > remaining {
                break;
            }
            let mut frame = vec![0_u8; frame_len as usize];
            if read_exact_at_bounded(&journal_file, offset, &mut frame).is_err() {
                break;
            }
            let crc_pos = frame.len() - JOURNAL_TRAILER_LEN;
            let stored_crc = u32::from_be_bytes([
                frame[crc_pos],
                frame[crc_pos + 1],
                frame[crc_pos + 2],
                frame[crc_pos + 3],
            ]);
            if crc32c(&frame[..crc_pos]) != stored_crc {
                break;
            }

            if seq > snapshot_seq {
                let body = &frame[JOURNAL_HEADER_LEN..crc_pos];
                apply_journal_op(
                    op_tag,
                    seq,
                    body,
                    &mut entries,
                    &mut ordered_ids,
                    &mut live_count,
                    &mut live_payload_bytes,
                )?;
                last_seq = seq;
                replayed_frames = replayed_frames.saturating_add(1);
            }

            offset = offset
                .checked_add(frame_len)
                .ok_or(PackError::ArithmeticOverflow)?;
        }

        let truncated_journal_bytes = file_len.saturating_sub(offset);
        if truncated_journal_bytes > 0 {
            journal_file
                .set_len(offset)
                .map_err(|err| PackError::io(PackIoOperation::Truncate, err))?;
            durability.sync_file(&journal_file)?;
        }
        journal_file
            .seek(SeekFrom::Start(offset))
            .map_err(|err| PackError::io(PackIoOperation::Write, err))?;

        let report = CatalogRecoveryReport {
            snapshot_seq,
            replayed_frames,
            truncated_journal_bytes,
            total_entries: entries.len() as u64,
            live_entries: live_count,
        };
        let catalog = Self {
            roots_dir,
            durability,
            quota,
            journal_file,
            journal_offset: offset,
            last_seq,
            ops_since_compact: replayed_frames,
            fsync_count: 0,
            entries,
            ordered_ids,
            live_count,
            live_payload_bytes,
        };
        Ok((catalog, report))
    }

    /// Returns the number of currently `Live` roots in O(1) time.
    #[must_use]
    pub const fn live_root_count(&self) -> u64 {
        self.live_count
    }

    /// Returns the total number of retained roots (live + superseded + tombstoned).
    #[must_use]
    pub fn total_root_count(&self) -> u64 {
        self.entries.len() as u64
    }

    /// Returns the cumulative logical payload bytes across currently live roots.
    #[must_use]
    pub const fn live_payload_bytes(&self) -> u64 {
        self.live_payload_bytes
    }

    /// Returns total catalog durability barriers executed in this session.
    #[must_use]
    pub const fn fsync_count(&self) -> u64 {
        self.fsync_count
    }

    /// Looks up any root (live, superseded, or tombstoned) by stable identifier in O(1) time.
    #[must_use]
    pub fn get_root(&self, root_id: &str) -> Option<&CatalogRootEntry> {
        self.entries.get(root_id)
    }

    /// Lists roots deterministically in ascending `root_id` order starting strictly after `cursor`.
    #[must_use]
    pub fn list_roots(&self, cursor: Option<&str>, limit: usize) -> RootPage {
        self.list_filtered(cursor, limit, false)
    }

    /// Lists only `Live` roots deterministically in ascending `root_id` order after `cursor`.
    #[must_use]
    pub fn list_live_roots(&self, cursor: Option<&str>, limit: usize) -> RootPage {
        self.list_filtered(cursor, limit, true)
    }

    fn list_filtered(&self, cursor: Option<&str>, limit: usize, live_only: bool) -> RootPage {
        let mut entries = Vec::with_capacity(limit.min(self.entries.len()));
        let mut has_more = false;
        let iter: Box<dyn Iterator<Item = &String> + '_> = match cursor {
            Some(c) => Box::new(
                self.ordered_ids
                    .range::<str, _>((Bound::Excluded(c), Bound::Unbounded)),
            ),
            None => Box::new(self.ordered_ids.iter()),
        };

        for id in iter {
            let Some(entry) = self.entries.get(id) else {
                continue;
            };
            if live_only && !matches!(entry.status, RootStatus::Live) {
                continue;
            }
            if entries.len() == limit {
                has_more = true;
                break;
            }
            entries.push(entry.clone());
        }
        let next_cursor = if has_more {
            entries.last().map(|e| e.record.root_id.clone())
        } else {
            None
        };
        RootPage {
            entries,
            next_cursor,
            has_more,
        }
    }

    /// Publishes one new root durably into `catalog.fssr`.
    pub fn publish_root(
        &mut self,
        record: VirtualRootRecord,
    ) -> Result<RootPublishReceipt, PackError> {
        let mut receipts = self.publish_roots_batch(&[record])?;
        receipts.pop().ok_or(PackError::ArithmeticOverflow)
    }

    /// Group-commits a batch of new roots into `catalog.fssr` with ONE durability barrier.
    pub fn publish_roots_batch(
        &mut self,
        records: &[VirtualRootRecord],
    ) -> Result<Vec<RootPublishReceipt>, PackError> {
        if records.is_empty() {
            return Ok(Vec::new());
        }
        let mut seen = BTreeSet::new();
        for rec in records {
            rec.validate()?;
            if self.entries.contains_key(&rec.root_id) {
                return Err(PackError::RootAlreadyExists(rec.root_id.clone()));
            }
            if !seen.insert(rec.root_id.as_str()) {
                return Err(PackError::RootAlreadyExists(rec.root_id.clone()));
            }
        }
        let added = records.len() as u64;
        if let Some(hard_max) = self.quota.hard_max_live_roots {
            let projected = self
                .live_count
                .checked_add(added)
                .ok_or(PackError::ArithmeticOverflow)?;
            if projected > hard_max {
                return Err(PackError::QuotaExceeded {
                    resource: QuotaResource::LiveRoots,
                    current: self.live_count,
                    requested: added,
                    maximum: hard_max,
                });
            }
        }

        let mut buf = Vec::new();
        let mut seq = self.last_seq;
        for rec in records {
            seq = seq.checked_add(1).ok_or(PackError::ArithmeticOverflow)?;
            let body = rec.try_canonical_bytes()?;
            encode_journal_frame(OP_PUBLISH, seq, &body, &mut buf)?;
        }

        self.append_and_sync_journal(&buf)?;

        let mut receipts = Vec::with_capacity(records.len());
        let mut applied_seq = self.last_seq;
        for rec in records {
            applied_seq = applied_seq
                .checked_add(1)
                .ok_or(PackError::ArithmeticOverflow)?;
            let entry = CatalogRootEntry {
                sequence: applied_seq,
                record: rec.clone(),
                predecessor: None,
                status: RootStatus::Live,
            };
            self.live_count = self
                .live_count
                .checked_add(1)
                .ok_or(PackError::ArithmeticOverflow)?;
            self.live_payload_bytes = self
                .live_payload_bytes
                .saturating_add(rec.total_payload_bytes);
            self.ordered_ids.insert(rec.root_id.clone());
            self.entries.insert(rec.root_id.clone(), entry.clone());
            receipts.push(RootPublishReceipt {
                entry,
                quota_status: self.current_quota_status(),
            });
        }
        self.last_seq = applied_seq;
        self.ops_since_compact = self.ops_since_compact.saturating_add(added);
        self.maybe_auto_compact()?;
        Ok(receipts)
    }

    /// Atomically supersedes a `Live` root with a new stable root record in one journal frame.
    pub fn supersede_root(
        &mut self,
        old_id: &str,
        new_record: VirtualRootRecord,
    ) -> Result<RootPublishReceipt, PackError> {
        new_record.validate()?;
        let Some(old_entry) = self.entries.get(old_id) else {
            return Err(PackError::RootNotFound(old_id.to_owned()));
        };
        if !matches!(old_entry.status, RootStatus::Live) {
            return Err(PackError::RootNotLive(old_id.to_owned()));
        }
        if self.entries.contains_key(&new_record.root_id) {
            return Err(PackError::RootAlreadyExists(new_record.root_id));
        }

        let seq = self
            .last_seq
            .checked_add(1)
            .ok_or(PackError::ArithmeticOverflow)?;
        let mut enc = CanonicalEncoder::new();
        enc.text(old_id);
        new_record.encode_canonical(&mut enc);
        let body = enc.finish_checked()?;

        let mut buf = Vec::new();
        encode_journal_frame(OP_SUPERSEDE, seq, &body, &mut buf)?;
        self.append_and_sync_journal(&buf)?;

        let old_payload = if let Some(entry) = self.entries.get_mut(old_id) {
            entry.status = RootStatus::Superseded {
                superseded_by: new_record.root_id.clone(),
                superseded_at_seq: seq,
            };
            entry.record.total_payload_bytes
        } else {
            0
        };
        self.live_payload_bytes = self
            .live_payload_bytes
            .saturating_sub(old_payload)
            .saturating_add(new_record.total_payload_bytes);

        let new_entry = CatalogRootEntry {
            sequence: seq,
            record: new_record.clone(),
            predecessor: Some(old_id.to_owned()),
            status: RootStatus::Live,
        };
        self.ordered_ids.insert(new_record.root_id.clone());
        self.entries
            .insert(new_record.root_id.clone(), new_entry.clone());
        self.last_seq = seq;
        self.ops_since_compact = self.ops_since_compact.saturating_add(1);
        self.maybe_auto_compact()?;

        Ok(RootPublishReceipt {
            entry: new_entry,
            quota_status: self.current_quota_status(),
        })
    }

    /// Permanently tombstones an existing root, retaining its tombstone entry in the catalog.
    pub fn tombstone_root(
        &mut self,
        root_id: &str,
        reason_digest: ContentDigest,
    ) -> Result<CatalogRootEntry, PackError> {
        if reason_digest.algorithm() != DigestAlgorithm::Sha256 {
            return Err(PackError::UnsupportedDigestAlgorithm(
                reason_digest.algorithm(),
            ));
        }
        let Some(existing) = self.entries.get(root_id) else {
            return Err(PackError::RootNotFound(root_id.to_owned()));
        };
        if let RootStatus::Tombstoned {
            reason_digest: existing_reason,
            ..
        } = existing.status
        {
            if existing_reason == reason_digest {
                return Ok(existing.clone());
            }
            return Err(PackError::TombstoneConflict {
                root_id: root_id.to_owned(),
                existing_reason,
                attempted_reason: reason_digest,
            });
        }

        let seq = self
            .last_seq
            .checked_add(1)
            .ok_or(PackError::ArithmeticOverflow)?;
        let mut enc = CanonicalEncoder::new();
        enc.text(root_id);
        enc.digest(reason_digest);
        let body = enc.finish_checked()?;

        let mut buf = Vec::new();
        encode_journal_frame(OP_TOMBSTONE, seq, &body, &mut buf)?;
        self.append_and_sync_journal(&buf)?;

        let updated = {
            let entry = self
                .entries
                .get_mut(root_id)
                .ok_or_else(|| PackError::RootNotFound(root_id.to_owned()))?;
            if matches!(entry.status, RootStatus::Live) {
                self.live_count = self.live_count.saturating_sub(1);
                self.live_payload_bytes = self
                    .live_payload_bytes
                    .saturating_sub(entry.record.total_payload_bytes);
            }
            entry.status = RootStatus::Tombstoned {
                reason_digest,
                tombstoned_at_seq: seq,
            };
            entry.clone()
        };
        self.last_seq = seq;
        self.ops_since_compact = self.ops_since_compact.saturating_add(1);
        self.maybe_auto_compact()?;
        Ok(updated)
    }

    /// Writes an atomic compacted snapshot (`catalog.snap`) and rotates `catalog.fssr`.
    pub fn compact(&mut self) -> Result<CompactionReceipt, PackError> {
        let out = encode_snapshot(self.last_seq, &self.ordered_ids, &self.entries)?;

        let tmp_snap = self.roots_dir.join("catalog.snap.tmp");
        let final_snap = self.roots_dir.join("catalog.snap");
        let mut snap_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_snap)
            .map_err(|err| PackError::io(PackIoOperation::Open, err))?;
        write_all_bounded(&mut snap_file, &out)?;
        self.durability.sync_file(&snap_file)?;
        self.fsync_count = self.fsync_count.saturating_add(1);
        drop(snap_file);

        fs::rename(&tmp_snap, &final_snap)
            .map_err(|err| PackError::io(PackIoOperation::Rename, err))?;
        sync_dir(&self.roots_dir, self.durability)?;

        let new_journal_tmp = self.roots_dir.join("catalog.fssr.new");
        let journal_path = self.roots_dir.join("catalog.fssr");
        let fresh = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&new_journal_tmp)
            .map_err(|err| PackError::io(PackIoOperation::Open, err))?;
        self.durability.sync_file(&fresh)?;
        self.fsync_count = self.fsync_count.saturating_add(1);
        fs::rename(&new_journal_tmp, &journal_path)
            .map_err(|err| PackError::io(PackIoOperation::Rename, err))?;
        sync_dir(&self.roots_dir, self.durability)?;

        self.journal_file = fresh;
        self.journal_offset = 0;
        self.ops_since_compact = 0;

        Ok(CompactionReceipt {
            snapshot_seq: self.last_seq,
            total_entries: self.entries.len() as u64,
            live_entries: self.live_count,
            snapshot_bytes: out.len(),
        })
    }

    fn append_and_sync_journal(&mut self, bytes: &[u8]) -> Result<(), PackError> {
        let rollback_offset = self.journal_offset;
        let res = (|| -> Result<(), PackError> {
            write_all_bounded(&mut self.journal_file, bytes)?;
            self.durability.sync_file(&self.journal_file)?;
            Ok(())
        })();
        if let Err(err) = res {
            let _ = self.journal_file.set_len(rollback_offset);
            let _ = self.journal_file.seek(SeekFrom::Start(rollback_offset));
            return Err(err);
        }
        self.journal_offset = self
            .journal_offset
            .checked_add(bytes.len() as u64)
            .ok_or(PackError::ArithmeticOverflow)?;
        self.fsync_count = self.fsync_count.saturating_add(1);
        Ok(())
    }

    fn maybe_auto_compact(&mut self) -> Result<(), PackError> {
        if self.quota.auto_compact_every > 0
            && self.ops_since_compact >= self.quota.auto_compact_every
        {
            let _ = self.compact()?;
        }
        Ok(())
    }

    fn current_quota_status(&self) -> QuotaStatus {
        if let Some(soft) = self.quota.soft_max_live_roots
            && self.live_count > soft
        {
            return QuotaStatus::SoftLimitExceeded {
                resource: QuotaResource::LiveRoots,
                current: self.live_count,
                soft_limit: soft,
            };
        }
        QuotaStatus::WithinPolicy
    }
}
