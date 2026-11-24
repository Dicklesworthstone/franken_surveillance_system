#![forbid(unsafe_code)]
//! Sealed packfile footer encoding and decoding (`FSSF` .. `FSSE`).

use fss_core::Sha256Hasher;

use crate::error::PackError;
use crate::format::{
    PACK_FOOTER_END_MAGIC, PACK_FOOTER_ENTRY_LEN, PACK_FOOTER_MAGIC, PACK_FOOTER_PREFIX_LEN,
    PACK_FOOTER_TAIL_LEN, PACK_RECORD_OVERHEAD_LEN, PackId, PackLocation, PackObjectState,
};

/// One entry in a sealed packfile footer (`52` bytes on disk).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackFooterEntry {
    /// Content SHA-256 digest bytes (primary sort key).
    pub sha256: [u8; 32],
    /// Byte offset of the `FSSP` record header in the packfile.
    pub offset: u64,
    /// Payload length in bytes.
    pub len: u64,
    /// Object kind tag.
    pub kind: u16,
    /// Record flags.
    pub flags: u16,
}

impl PackFooterEntry {
    /// Returns this entry's content identity as a SHA-256 [`fss_core::ContentDigest`].
    #[must_use]
    pub const fn digest(self) -> fss_core::ContentDigest {
        fss_core::ContentDigest::new(fss_core::DigestAlgorithm::Sha256, self.sha256)
    }

    /// Converts this entry into a [`PackLocation`] marked [`PackObjectState::Sealed`].
    #[must_use]
    pub const fn to_sealed_location(self, pack_id: PackId) -> PackLocation {
        PackLocation {
            pack_id,
            offset: self.offset,
            len: self.len,
            object_kind: self.kind,
            flags: self.flags,
            state: PackObjectState::Sealed,
        }
    }
}

/// Decoded trailer at the very end of a sealed packfile (last 44 bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackFooterTail {
    /// Byte offset where `FSSF` begins.
    pub footer_offset: u64,
    /// SHA-256 over bytes `[0 .. file_len - 36]` (all records + footer prefix + entries + footer_offset).
    pub whole_pack_sha256: [u8; 32],
}

/// Decoded complete footer of a sealed packfile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackFooter {
    /// Sorted entries stored in this sealed packfile.
    pub entries: Vec<PackFooterEntry>,
    /// Byte offset where `FSSF` begins.
    pub footer_offset: u64,
    /// Whole-pack SHA-256 covering bytes `[0 .. file_len - 36]`.
    pub whole_pack_sha256: [u8; 32],
}

/// Encodes a sealed packfile footer, updating `pack_hasher` with all bytes preceding
/// `whole_pack_sha256` and finalizing the whole-pack digest.
pub fn encode_sealed_footer(
    entries: &[PackFooterEntry],
    footer_offset: u64,
    mut pack_hasher: Sha256Hasher,
) -> Result<(Vec<u8>, [u8; 32]), PackError> {
    let mut sorted = entries.to_vec();
    sorted.sort_unstable();

    let total_len = PACK_FOOTER_PREFIX_LEN
        .checked_add(
            sorted
                .len()
                .checked_mul(PACK_FOOTER_ENTRY_LEN)
                .ok_or(PackError::ArithmeticOverflow)?,
        )
        .and_then(|n| n.checked_add(PACK_FOOTER_TAIL_LEN))
        .ok_or(PackError::ArithmeticOverflow)?;
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&PACK_FOOTER_MAGIC);
    out.extend_from_slice(&(sorted.len() as u64).to_be_bytes());
    for entry in &sorted {
        out.extend_from_slice(&entry.sha256);
        out.extend_from_slice(&entry.offset.to_be_bytes());
        out.extend_from_slice(&entry.len.to_be_bytes());
        out.extend_from_slice(&entry.kind.to_be_bytes());
        out.extend_from_slice(&entry.flags.to_be_bytes());
    }
    out.extend_from_slice(&footer_offset.to_be_bytes());

    pack_hasher.update(&out);
    let whole_pack_sha256 = pack_hasher
        .finalize()
        .map_err(|_| PackError::ArithmeticOverflow)?;
    out.extend_from_slice(&whole_pack_sha256);
    out.extend_from_slice(&PACK_FOOTER_END_MAGIC);
    Ok((out, whole_pack_sha256))
}

/// Attempts to parse the last 44 bytes of a packfile as a sealed footer tail.
#[must_use]
pub fn decode_footer_tail(tail: &[u8; PACK_FOOTER_TAIL_LEN]) -> Option<PackFooterTail> {
    if tail[40..44] != PACK_FOOTER_END_MAGIC {
        return None;
    }
    let footer_offset = u64::from_be_bytes([
        tail[0], tail[1], tail[2], tail[3], tail[4], tail[5], tail[6], tail[7],
    ]);
    let mut whole_pack_sha256 = [0_u8; 32];
    whole_pack_sha256.copy_from_slice(&tail[8..40]);
    Some(PackFooterTail {
        footer_offset,
        whole_pack_sha256,
    })
}

/// Decodes and validates the full footer bytes starting at `footer_offset`.
pub fn decode_sealed_footer(
    pack_id: PackId,
    footer_offset: u64,
    raw: &[u8],
) -> Result<PackFooter, PackError> {
    if raw.len() < PACK_FOOTER_PREFIX_LEN + PACK_FOOTER_TAIL_LEN {
        return Err(PackError::CorruptPack {
            pack_id,
            offset: footer_offset,
            detail: "sealed footer shorter than minimum size".to_owned(),
        });
    }
    if raw[0..4] != PACK_FOOTER_MAGIC {
        return Err(PackError::CorruptPack {
            pack_id,
            offset: footer_offset,
            detail: "invalid FSSF footer magic".to_owned(),
        });
    }
    let tail_start = raw.len() - PACK_FOOTER_TAIL_LEN;
    let tail_arr: &[u8; PACK_FOOTER_TAIL_LEN] =
        raw[tail_start..]
            .try_into()
            .map_err(|_| PackError::CorruptPack {
                pack_id,
                offset: footer_offset,
                detail: "failed to read footer tail".to_owned(),
            })?;
    let tail = decode_footer_tail(tail_arr).ok_or_else(|| PackError::CorruptPack {
        pack_id,
        offset: footer_offset,
        detail: "invalid FSSE footer end magic".to_owned(),
    })?;
    if tail.footer_offset != footer_offset {
        return Err(PackError::CorruptPack {
            pack_id,
            offset: footer_offset,
            detail: format!(
                "footer_offset mismatch: tail says {}, expected {footer_offset}",
                tail.footer_offset
            ),
        });
    }

    let entry_count = u64::from_be_bytes([
        raw[4], raw[5], raw[6], raw[7], raw[8], raw[9], raw[10], raw[11],
    ]);
    let entries_region_len = tail_start - PACK_FOOTER_PREFIX_LEN;
    let entry_count_usize = usize::try_from(entry_count).map_err(|_| PackError::CorruptPack {
        pack_id,
        offset: footer_offset,
        detail: "footer entry_count overflows usize".to_owned(),
    })?;
    let expected_entries_len = entry_count_usize
        .checked_mul(PACK_FOOTER_ENTRY_LEN)
        .ok_or(PackError::ArithmeticOverflow)?;
    if entries_region_len != expected_entries_len {
        return Err(PackError::CorruptPack {
            pack_id,
            offset: footer_offset,
            detail: format!(
                "footer entry byte length mismatch: expected {expected_entries_len}, observed {entries_region_len}"
            ),
        });
    }

    let mut entries = Vec::with_capacity(entry_count_usize);
    let mut cursor = PACK_FOOTER_PREFIX_LEN;
    for _ in 0..entry_count_usize {
        let mut sha256 = [0_u8; 32];
        sha256.copy_from_slice(&raw[cursor..cursor + 32]);
        let offset = u64::from_be_bytes([
            raw[cursor + 32],
            raw[cursor + 33],
            raw[cursor + 34],
            raw[cursor + 35],
            raw[cursor + 36],
            raw[cursor + 37],
            raw[cursor + 38],
            raw[cursor + 39],
        ]);
        let len = u64::from_be_bytes([
            raw[cursor + 40],
            raw[cursor + 41],
            raw[cursor + 42],
            raw[cursor + 43],
            raw[cursor + 44],
            raw[cursor + 45],
            raw[cursor + 46],
            raw[cursor + 47],
        ]);
        let kind = u16::from_be_bytes([raw[cursor + 48], raw[cursor + 49]]);
        let flags = u16::from_be_bytes([raw[cursor + 50], raw[cursor + 51]]);
        cursor += PACK_FOOTER_ENTRY_LEN;

        let end = offset
            .checked_add(PACK_RECORD_OVERHEAD_LEN as u64)
            .and_then(|v| v.checked_add(len))
            .ok_or(PackError::ArithmeticOverflow)?;
        if end > footer_offset {
            return Err(PackError::CorruptPack {
                pack_id,
                offset,
                detail: format!(
                    "footer entry span {offset}..{end} exceeds footer_offset {footer_offset}"
                ),
            });
        }
        let entry = PackFooterEntry {
            sha256,
            offset,
            len,
            kind,
            flags,
        };
        if let Some(prev) = entries.last()
            && *prev >= entry
        {
            return Err(PackError::CorruptPack {
                pack_id,
                offset: footer_offset,
                detail: "footer entries are not strictly canonically sorted".to_owned(),
            });
        }
        entries.push(entry);
    }

    Ok(PackFooter {
        entries,
        footer_offset,
        whole_pack_sha256: tail.whole_pack_sha256,
    })
}
