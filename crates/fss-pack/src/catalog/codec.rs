#![forbid(unsafe_code)]
//! Binary journal framing (`FSSR`) and compacted snapshot (`FSSS`) codecs for the virtual root catalog.

use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::Read;
use std::path::Path;

use fss_core::{CanonicalDecode, CanonicalDecoder, CanonicalEncode, sha256};

use crate::catalog::record::{CatalogRootEntry, RootStatus, VirtualRootRecord};
use crate::catalog::{
    CATALOG_FORMAT_VERSION, CATALOG_JOURNAL_MAGIC, CATALOG_SNAPSHOT_MAGIC,
    MAX_CATALOG_SNAPSHOT_BYTES, MAX_JOURNAL_BODY_BYTES,
};
use crate::crc32c::crc32c;
use crate::error::{PackError, PackIoOperation};

pub(crate) const JOURNAL_HEADER_LEN: usize = 20;
pub(crate) const JOURNAL_TRAILER_LEN: usize = 4;
pub(crate) const SNAPSHOT_HEADER_LEN: usize = 24;
pub(crate) const SNAPSHOT_TRAILER_LEN: usize = 32;

pub(crate) const OP_PUBLISH: u16 = 1;
pub(crate) const OP_SUPERSEDE: u16 = 2;
pub(crate) const OP_TOMBSTONE: u16 = 3;

pub(crate) type LoadedSnapshot = (
    u64,
    HashMap<String, CatalogRootEntry>,
    BTreeSet<String>,
    u64,
    u64,
);

pub(crate) fn encode_journal_frame(
    op_tag: u16,
    seq: u64,
    body: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), PackError> {
    if body.len() > MAX_JOURNAL_BODY_BYTES {
        return Err(PackError::InvalidRootRecord {
            detail: format!(
                "journal body {} exceeds max {MAX_JOURNAL_BODY_BYTES}",
                body.len()
            ),
        });
    }
    let body_len_u32 = u32::try_from(body.len()).map_err(|_| PackError::ArithmeticOverflow)?;
    let start = out.len();
    out.extend_from_slice(&CATALOG_JOURNAL_MAGIC);
    out.extend_from_slice(&CATALOG_FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&op_tag.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&body_len_u32.to_be_bytes());
    out.extend_from_slice(body);
    let crc = crc32c(&out[start..]);
    out.extend_from_slice(&crc.to_be_bytes());
    Ok(())
}

pub(crate) fn encode_snapshot(
    last_seq: u64,
    ordered_ids: &BTreeSet<String>,
    entries: &HashMap<String, CatalogRootEntry>,
) -> Result<Vec<u8>, PackError> {
    let mut out = Vec::new();
    out.extend_from_slice(&CATALOG_SNAPSHOT_MAGIC);
    out.extend_from_slice(&CATALOG_FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&last_seq.to_be_bytes());
    out.extend_from_slice(&(entries.len() as u64).to_be_bytes());

    for id in ordered_ids {
        if let Some(entry) = entries.get(id) {
            let encoded = entry.try_canonical_bytes()?;
            let len = u32::try_from(encoded.len()).map_err(|_| PackError::ArithmeticOverflow)?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&encoded);
        }
    }
    let digest = sha256(&out);
    out.extend_from_slice(&digest);
    Ok(out)
}

pub(crate) fn load_snapshot_if_present(path: &Path) -> Result<LoadedSnapshot, PackError> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok((0, HashMap::new(), BTreeSet::new(), 0, 0));
        }
        Err(err) => return Err(PackError::io(PackIoOperation::Open, err)),
    };
    let meta = file
        .metadata()
        .map_err(|err| PackError::io(PackIoOperation::Metadata, err))?;
    if meta.len() > MAX_CATALOG_SNAPSHOT_BYTES {
        return Err(PackError::CorruptCatalog {
            detail: format!("catalog snapshot {} exceeds ceiling", meta.len()),
        });
    }
    let mut raw = Vec::with_capacity(meta.len() as usize);
    file.read_to_end(&mut raw)
        .map_err(|err| PackError::io(PackIoOperation::Read, err))?;

    if raw.len() < SNAPSHOT_HEADER_LEN + SNAPSHOT_TRAILER_LEN {
        return Err(PackError::CorruptCatalog {
            detail: "catalog snapshot shorter than header + trailer".to_owned(),
        });
    }
    let body_len = raw.len() - SNAPSHOT_TRAILER_LEN;
    let (body, trailer) = raw.split_at(body_len);
    if sha256(body) != trailer {
        return Err(PackError::CorruptCatalog {
            detail: "catalog snapshot SHA-256 mismatch".to_owned(),
        });
    }
    if body[0..4] != CATALOG_SNAPSHOT_MAGIC {
        return Err(PackError::CorruptCatalog {
            detail: "invalid FSSS catalog snapshot magic".to_owned(),
        });
    }
    let version = u16::from_be_bytes([body[4], body[5]]);
    if version != CATALOG_FORMAT_VERSION {
        return Err(PackError::CorruptCatalog {
            detail: format!("unsupported catalog snapshot version {version}"),
        });
    }
    let snapshot_seq = u64::from_be_bytes([
        body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
    ]);
    let count_u64 = u64::from_be_bytes([
        body[16], body[17], body[18], body[19], body[20], body[21], body[22], body[23],
    ]);
    let count = usize::try_from(count_u64).map_err(|_| PackError::ArithmeticOverflow)?;

    let mut entries = HashMap::with_capacity(count);
    let mut ordered_ids = BTreeSet::new();
    let mut live_count = 0_u64;
    let mut live_payload_bytes = 0_u64;
    let mut cursor = SNAPSHOT_HEADER_LEN;

    for _ in 0..count {
        if cursor + 4 > body.len() {
            return Err(PackError::CorruptCatalog {
                detail: "truncated entry length in catalog snapshot".to_owned(),
            });
        }
        let entry_len = u32::from_be_bytes([
            body[cursor],
            body[cursor + 1],
            body[cursor + 2],
            body[cursor + 3],
        ]) as usize;
        cursor += 4;
        if cursor + entry_len > body.len() {
            return Err(PackError::CorruptCatalog {
                detail: "truncated entry payload in catalog snapshot".to_owned(),
            });
        }
        let entry = CatalogRootEntry::from_canonical_bytes(&body[cursor..cursor + entry_len])
            .map_err(|err| PackError::CorruptCatalog {
                detail: format!("failed to decode snapshot entry: {err}"),
            })?;
        cursor += entry_len;
        if matches!(entry.status, RootStatus::Live) {
            live_count = live_count.saturating_add(1);
            live_payload_bytes =
                live_payload_bytes.saturating_add(entry.record.total_payload_bytes);
        }
        ordered_ids.insert(entry.record.root_id.clone());
        entries.insert(entry.record.root_id.clone(), entry);
    }
    if cursor != body.len() {
        return Err(PackError::CorruptCatalog {
            detail: "trailing unparsed bytes in catalog snapshot".to_owned(),
        });
    }
    Ok((
        snapshot_seq,
        entries,
        ordered_ids,
        live_count,
        live_payload_bytes,
    ))
}

pub(crate) fn apply_journal_op(
    op_tag: u16,
    seq: u64,
    body: &[u8],
    entries: &mut HashMap<String, CatalogRootEntry>,
    ordered_ids: &mut BTreeSet<String>,
    live_count: &mut u64,
    live_payload_bytes: &mut u64,
) -> Result<(), PackError> {
    match op_tag {
        OP_PUBLISH => {
            let rec = VirtualRootRecord::from_canonical_bytes(body).map_err(|err| {
                PackError::CorruptCatalog {
                    detail: format!("corrupt publish journal frame at seq {seq}: {err}"),
                }
            })?;
            rec.validate()?;
            let entry = CatalogRootEntry {
                sequence: seq,
                record: rec.clone(),
                predecessor: None,
                status: RootStatus::Live,
            };
            *live_count = live_count.saturating_add(1);
            *live_payload_bytes = live_payload_bytes.saturating_add(rec.total_payload_bytes);
            ordered_ids.insert(rec.root_id.clone());
            entries.insert(rec.root_id, entry);
            Ok(())
        }
        OP_SUPERSEDE => {
            let mut dec = CanonicalDecoder::new(body);
            let old_id = dec
                .text()
                .map_err(|err| PackError::CorruptCatalog {
                    detail: format!("corrupt supersede old_id at seq {seq}: {err}"),
                })?
                .to_owned();
            let new_rec = VirtualRootRecord::decode_canonical(&mut dec).map_err(|err| {
                PackError::CorruptCatalog {
                    detail: format!("corrupt supersede record at seq {seq}: {err}"),
                }
            })?;
            dec.ensure_finished()
                .map_err(|err| PackError::CorruptCatalog {
                    detail: format!("trailing bytes in supersede frame at seq {seq}: {err}"),
                })?;
            new_rec.validate()?;

            if let Some(old_entry) = entries.get_mut(&old_id) {
                if matches!(old_entry.status, RootStatus::Live) {
                    *live_payload_bytes =
                        live_payload_bytes.saturating_sub(old_entry.record.total_payload_bytes);
                }
                old_entry.status = RootStatus::Superseded {
                    superseded_by: new_rec.root_id.clone(),
                    superseded_at_seq: seq,
                };
            }
            *live_payload_bytes = live_payload_bytes.saturating_add(new_rec.total_payload_bytes);
            let new_entry = CatalogRootEntry {
                sequence: seq,
                record: new_rec.clone(),
                predecessor: Some(old_id),
                status: RootStatus::Live,
            };
            ordered_ids.insert(new_rec.root_id.clone());
            entries.insert(new_rec.root_id, new_entry);
            Ok(())
        }
        OP_TOMBSTONE => {
            let mut dec = CanonicalDecoder::new(body);
            let root_id = dec
                .text()
                .map_err(|err| PackError::CorruptCatalog {
                    detail: format!("corrupt tombstone root_id at seq {seq}: {err}"),
                })?
                .to_owned();
            let reason_digest = dec.digest().map_err(|err| PackError::CorruptCatalog {
                detail: format!("corrupt tombstone digest at seq {seq}: {err}"),
            })?;
            dec.ensure_finished()
                .map_err(|err| PackError::CorruptCatalog {
                    detail: format!("trailing bytes in tombstone frame at seq {seq}: {err}"),
                })?;

            if let Some(entry) = entries.get_mut(&root_id) {
                if matches!(entry.status, RootStatus::Live) {
                    *live_count = live_count.saturating_sub(1);
                    *live_payload_bytes =
                        live_payload_bytes.saturating_sub(entry.record.total_payload_bytes);
                }
                entry.status = RootStatus::Tombstoned {
                    reason_digest,
                    tombstoned_at_seq: seq,
                };
            }
            Ok(())
        }
        other => Err(PackError::CorruptCatalog {
            detail: format!("unknown catalog journal op tag {other} at seq {seq}"),
        }),
    }
}
