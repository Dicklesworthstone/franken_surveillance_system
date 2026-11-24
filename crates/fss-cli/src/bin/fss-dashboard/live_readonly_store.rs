#![forbid(unsafe_code)]
//! Lock-free, strictly read-only MVCC snapshot, WAL, packfile, and v1 deployment loader.
//!
//! Semantic plane: `"projection"`.
//!
//! NEVER acquires `<root>/LOCK`, NEVER writes, creates, truncates, or repairs any file.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use fss_core::{CanonicalDecode, EvidenceDeltaBatch};
use fss_ledger::decode_batch;
use fss_pack::{
    PACK_FOOTER_END_MAGIC, PACK_KIND_METADATA, PACK_RECORD_HEADER_LEN, PACK_RECORD_MAGIC,
    PACK_RECORD_TRAILER_LEN, PackId, crc32c, decode_record_header, verify_record_slice,
};
use fss_projection_store::{
    DoctorScrubReceipt, HistoryChainMode, InMemoryPayloadResolver, ProjectionSnapshot,
    replay_from_batches, replay_valid_prefix_onto_snapshot,
};
use fss_reference::agent_orient::{OrientLimits, read_deployment};

const MAX_WAL_READ_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SNAP_READ_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PACK_METADATA_RECORDS: usize = 16_384;
const MAX_PACK_METADATA_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_SINGLE_METADATA_BYTES: u64 = 1024 * 1024;
const WAL_FRAME_HEADER_LEN: usize = 20;
const WAL_FRAME_TRAILER_LEN: usize = 4;
const WAL_OP_APPLY_BATCH: u16 = 1;
const WAL_OP_SCRUB_RECEIPT: u16 = 2;

/// Read-only on-disk packfile inventory scanned without acquiring `PackStore` locks.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PackDiskScan {
    /// Total `.fssp` packfiles discovered under `objects/packs/`.
    pub pack_count: u64,
    /// Number of sealed packfiles ending with `FSSE`.
    pub sealed_pack_count: u64,
    /// Cumulative on-disk bytes across all packfiles.
    pub on_disk_pack_bytes: u64,
}

/// Loaded read-only projection state from either a v2 MVCC deployment or a v1 deployment.
pub enum ReadonlyStoreState {
    /// Materialized v2 MVCC snapshot plus packfile disk telemetry.
    Mvcc {
        /// Reconstructed or decoded immutable projection snapshot.
        snapshot: ProjectionSnapshot,
        /// Read-only packfile disk telemetry.
        packs: PackDiskScan,
    },
    /// Legacy v1 reference deployment read-only snapshot.
    V1 {
        /// Verified read-only v1 snapshot.
        snapshot: fss_reference::agent_orient::DeploymentSnapshot,
    },
}

fn scan_packs_readonly(root: &Path, resolver: &InMemoryPayloadResolver) -> PackDiskScan {
    let mut scan = PackDiskScan::default();
    let packs_dir = root.join("objects").join("packs");
    let Ok(entries) = fs::read_dir(&packs_dir) else {
        return scan;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("fssp"))
        .collect();
    paths.sort();

    let (mut meta_records, mut meta_bytes) = (0usize, 0usize);
    for (idx, path) in paths.into_iter().enumerate() {
        let pack_id = PackId::new(0, u64::try_from(idx).unwrap_or(0));
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.file_type().is_file() {
            continue;
        }
        let file_len = meta.len();
        scan.pack_count = scan.pack_count.saturating_add(1);
        scan.on_disk_pack_bytes = scan.on_disk_pack_bytes.saturating_add(file_len);

        let Ok(mut file) = File::open(&path) else {
            continue;
        };
        if file_len >= 4 && file.seek(SeekFrom::End(-4)).is_ok() {
            let mut tail = [0u8; 4];
            if file.read_exact(&mut tail).is_ok() && tail == PACK_FOOTER_END_MAGIC {
                scan.sealed_pack_count = scan.sealed_pack_count.saturating_add(1);
            }
        }
        if file.seek(SeekFrom::Start(0)).is_err() {
            continue;
        }
        let mut offset = 0u64;
        while offset.saturating_add(PACK_RECORD_HEADER_LEN as u64) <= file_len {
            let mut hdr_bytes = [0u8; PACK_RECORD_HEADER_LEN];
            if file.read_exact(&mut hdr_bytes).is_err() || hdr_bytes[0..4] != PACK_RECORD_MAGIC {
                break;
            }
            let Ok(hdr) = decode_record_header(pack_id, offset, &hdr_bytes) else {
                break;
            };
            let rest_len = hdr
                .payload_len
                .saturating_add(PACK_RECORD_TRAILER_LEN as u64);
            let next_offset = offset
                .saturating_add(PACK_RECORD_HEADER_LEN as u64)
                .saturating_add(rest_len);
            if next_offset > file_len {
                break;
            }
            if hdr.object_kind == PACK_KIND_METADATA
                && hdr.payload_len <= MAX_SINGLE_METADATA_BYTES
                && meta_records < MAX_PACK_METADATA_RECORDS
                && meta_bytes.saturating_add(hdr.payload_len as usize)
                    <= MAX_PACK_METADATA_TOTAL_BYTES
            {
                let mut rec =
                    Vec::with_capacity(PACK_RECORD_HEADER_LEN.saturating_add(rest_len as usize));
                rec.extend_from_slice(&hdr_bytes);
                let mut tail_buf = vec![0u8; rest_len as usize];
                if file.read_exact(&mut tail_buf).is_err() {
                    break;
                }
                rec.extend_from_slice(&tail_buf);
                if let Ok((_, payload)) = verify_record_slice(pack_id, offset, &rec, None)
                    && resolver.insert(payload.to_vec()).is_ok()
                {
                    meta_records = meta_records.saturating_add(1);
                    meta_bytes = meta_bytes.saturating_add(payload.len());
                }
            } else if file.seek(SeekFrom::Start(next_offset)).is_err() {
                break;
            }
            offset = next_offset;
        }
    }
    scan
}

fn read_wal_readonly(path: &Path) -> (Vec<EvidenceDeltaBatch>, Option<DoctorScrubReceipt>) {
    let (mut batches, mut latest_scrub) = (Vec::new(), None);
    let Ok(meta) = fs::symlink_metadata(path) else {
        return (batches, latest_scrub);
    };
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > MAX_WAL_READ_BYTES {
        return (batches, latest_scrub);
    }
    let Ok(raw) = fs::read(path) else {
        return (batches, latest_scrub);
    };
    let mut offset = 0usize;
    while offset < raw.len() {
        let remaining = raw.len().saturating_sub(offset);
        if remaining < WAL_FRAME_HEADER_LEN + WAL_FRAME_TRAILER_LEN {
            break;
        }
        let hdr = &raw[offset..offset + WAL_FRAME_HEADER_LEN];
        if &hdr[0..4] != b"FMVW" || u16::from_be_bytes([hdr[4], hdr[5]]) != 1 {
            break;
        }
        let op_tag = u16::from_be_bytes([hdr[6], hdr[7]]);
        let body_len = u32::from_be_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]) as usize;
        let Some(frame_len) = WAL_FRAME_HEADER_LEN
            .checked_add(body_len)
            .and_then(|v| v.checked_add(WAL_FRAME_TRAILER_LEN))
        else {
            break;
        };
        if frame_len > remaining {
            break;
        }
        let frame = &raw[offset..offset + frame_len];
        let crc_pos = frame_len - WAL_FRAME_TRAILER_LEN;
        let stored_crc = u32::from_be_bytes([
            frame[crc_pos],
            frame[crc_pos + 1],
            frame[crc_pos + 2],
            frame[crc_pos + 3],
        ]);
        if crc32c(&frame[..crc_pos]) != stored_crc {
            break;
        }
        let body = &frame[WAL_FRAME_HEADER_LEN..crc_pos];
        match op_tag {
            WAL_OP_APPLY_BATCH => match decode_batch(body) {
                Ok(batch) => batches.push(batch),
                Err(_) => break,
            },
            WAL_OP_SCRUB_RECEIPT => {
                if let Ok(receipt) = DoctorScrubReceipt::from_canonical_bytes(body) {
                    latest_scrub = Some(receipt);
                }
            }
            _ => break,
        }
        offset = offset.saturating_add(frame_len);
    }
    (batches, latest_scrub)
}

fn find_projection_dir(root: &Path) -> Option<PathBuf> {
    [
        root.join("projections").join("mvcc"),
        root.join("projection"),
    ]
    .into_iter()
    .find(|candidate| candidate.join("mvcc.snap").is_file() || candidate.join("mvcc.wal").is_file())
}

/// Loads deployment projection state strictly read-only without acquiring locks or writing files.
pub fn load_readonly_store(root: &Path, site: &str) -> io::Result<ReadonlyStoreState> {
    if let Some(proj_dir) = find_projection_dir(root) {
        let resolver = InMemoryPayloadResolver::new();
        let packs = scan_packs_readonly(root, &resolver);
        let snap_path = proj_dir.join("mvcc.snap");
        let base_snap = fs::symlink_metadata(&snap_path)
            .ok()
            .filter(|m| m.file_type().is_file() && m.len() <= MAX_SNAP_READ_BYTES)
            .and_then(|_| fs::read(&snap_path).ok())
            .and_then(|bytes| ProjectionSnapshot::decode_snapshot_bytes(&bytes).ok());
        let (wal_batches, wal_scrub) = read_wal_readonly(&proj_dir.join("mvcc.wal"));
        let snapshot = if let Some(snap) = base_snap {
            let (mut updated, _) = if wal_batches.is_empty() {
                (snap, 0)
            } else {
                replay_valid_prefix_onto_snapshot(snap, &wal_batches, &resolver)
            };
            if let Some(scrub) = wal_scrub
                && scrub.anchor.commit_sequence <= updated.anchor.commit_sequence
            {
                updated.scrub_receipt = Some(scrub);
            }
            updated
        } else if let Some(first) = wal_batches.first() {
            let mut replayed = replay_from_batches(
                &first.basis_anchor,
                HistoryChainMode::V2MerkleEpoch,
                &wal_batches,
                &resolver,
            )
            .map_err(|err| io::Error::other(format!("readonly mvcc replay failed: {err}")))?;
            if let Some(scrub) = wal_scrub
                && scrub.anchor.commit_sequence <= replayed.anchor.commit_sequence
            {
                replayed.scrub_receipt = Some(scrub);
            }
            replayed
        } else {
            return Err(io::Error::other(
                "projection directory has no readable mvcc.snap or mvcc.wal",
            ));
        };
        return Ok(ReadonlyStoreState::Mvcc { snapshot, packs });
    }
    let v1 = read_deployment(root, &OrientLimits::default())
        .map_err(|err| io::Error::other(format!("readonly deployment open failed: {err}")))?;
    if v1.site_lineage != site {
        return Err(io::Error::other("deployment site lineage mismatch"));
    }
    Ok(ReadonlyStoreState::V1 { snapshot: v1 })
}
