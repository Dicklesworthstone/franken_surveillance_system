#![forbid(unsafe_code)]
//! Complete verification of the physical FSSP record stream against its sealed inventory.

use std::io::{Read, Seek, SeekFrom};

use fss_core::{ContentDigest, DigestAlgorithm, Sha256Hasher};

use crate::crc32c::Crc32cHasher;
use crate::error::{PackError, PackIoOperation};
use crate::format::{
    PACK_FOOTER_ENTRY_LEN, PACK_FOOTER_MAGIC, PACK_FOOTER_PREFIX_LEN, PACK_FOOTER_TAIL_LEN,
    PACK_RECORD_HEADER_LEN, PACK_RECORD_OVERHEAD_LEN, PackFooter, PackId, decode_footer_tail,
    decode_record_header, decode_sealed_footer,
};

/// Returns the canonical footer and SHA-256 of the complete verified file, including its trailer.
pub(crate) fn verify<R: Read + Seek>(
    reader: &mut R,
    pack_id: PackId,
) -> Result<(PackFooter, ContentDigest), PackError> {
    let io = |err| PackError::io(PackIoOperation::Read, err);
    let corrupt = |offset, reason: &str| PackError::CorruptPack {
        pack_id,
        offset,
        detail: reason.to_owned(),
    };
    let file_len = reader.seek(SeekFrom::End(0)).map_err(io)?;
    if file_len < (PACK_FOOTER_PREFIX_LEN + PACK_FOOTER_TAIL_LEN) as u64 {
        return Err(corrupt(0, "sealed pack shorter than minimum footer"));
    }
    let tail_start = file_len - PACK_FOOTER_TAIL_LEN as u64;
    reader.seek(SeekFrom::Start(tail_start)).map_err(io)?;
    let mut tail_bytes = [0; PACK_FOOTER_TAIL_LEN];
    reader.read_exact(&mut tail_bytes).map_err(io)?;
    let tail = decode_footer_tail(&tail_bytes)
        .ok_or_else(|| corrupt(tail_start, "missing FSSE footer end magic"))?;
    if tail.footer_offset > tail_start - PACK_FOOTER_PREFIX_LEN as u64 {
        return Err(corrupt(
            tail.footer_offset,
            "sealed footer offset outside file",
        ));
    }
    let footer_len = usize::try_from(file_len - tail.footer_offset)
        .map_err(|_| PackError::ArithmeticOverflow)?;
    reader
        .seek(SeekFrom::Start(tail.footer_offset))
        .map_err(io)?;
    let mut prefix = [0; PACK_FOOTER_PREFIX_LEN];
    reader.read_exact(&mut prefix).map_err(io)?;
    let mut count_bytes = [0; 8];
    count_bytes.copy_from_slice(&prefix[4..]);
    let count = u64::from_be_bytes(count_bytes);
    let entries_bytes = footer_len - PACK_FOOTER_PREFIX_LEN - PACK_FOOTER_TAIL_LEN;
    if prefix[..4] != PACK_FOOTER_MAGIC
        || count > tail.footer_offset / PACK_RECORD_OVERHEAD_LEN as u64
        || count.checked_mul(PACK_FOOTER_ENTRY_LEN as u64) != Some(entries_bytes as u64)
    {
        return Err(corrupt(
            tail.footer_offset,
            "invalid sealed footer inventory size",
        ));
    }
    let mut footer_bytes = vec![0; footer_len];
    footer_bytes[..prefix.len()].copy_from_slice(&prefix);
    reader
        .read_exact(&mut footer_bytes[prefix.len()..])
        .map_err(io)?;
    let mut footer = decode_sealed_footer(pack_id, tail.footer_offset, &footer_bytes)?;

    reader.seek(SeekFrom::Start(0)).map_err(io)?;
    let mut whole = Sha256Hasher::new();
    let mut buf = [0; 64 * 1024];
    let mut next_offset = 0;
    footer.entries.sort_unstable_by_key(|entry| entry.offset);
    for entry in &footer.entries {
        if entry.offset != next_offset {
            return Err(corrupt(
                entry.offset,
                "sealed footer omits or overlaps record bytes",
            ));
        }
        let mut header_bytes = [0; PACK_RECORD_HEADER_LEN];
        reader.read_exact(&mut header_bytes).map_err(io)?;
        let header = decode_record_header(pack_id, entry.offset, &header_bytes)?;
        if header.payload_len != entry.len
            || header.object_kind != entry.kind
            || header.flags != entry.flags
            || header.content_sha256 != entry.sha256
        {
            return Err(corrupt(
                entry.offset,
                "sealed footer fields differ from record header",
            ));
        }

        whole.update(&header_bytes);
        let mut crc = Crc32cHasher::new();
        crc.update(&header_bytes);
        let mut payload = Sha256Hasher::new();
        let mut remaining = entry.len;
        while remaining > 0 {
            let n = remaining.min(buf.len() as u64) as usize;
            reader.read_exact(&mut buf[..n]).map_err(io)?;
            crc.update(&buf[..n]);
            payload.update(&buf[..n]);
            whole.update(&buf[..n]);
            remaining -= n as u64;
        }
        let mut trailer = [0; 4];
        reader.read_exact(&mut trailer).map_err(io)?;
        whole.update(&trailer);
        let stored = u32::from_be_bytes(trailer);
        let actual = crc.finalize();
        if actual != stored {
            return Err(PackError::CrcMismatch {
                expected: stored,
                actual,
            });
        }
        let actual = ContentDigest::new(
            DigestAlgorithm::Sha256,
            payload
                .finalize()
                .map_err(|_| PackError::ArithmeticOverflow)?,
        );
        if actual != entry.digest() {
            return Err(PackError::DigestMismatch {
                expected: entry.digest(),
                actual,
            });
        }
        // decode_sealed_footer already checked that the complete span fits the file.
        next_offset = entry.offset + PACK_RECORD_OVERHEAD_LEN as u64 + entry.len;
    }
    if next_offset != footer.footer_offset {
        return Err(corrupt(
            next_offset,
            "sealed footer leaves trailing record bytes unindexed",
        ));
    }

    let prefix_len = footer_bytes.len() - 36;
    whole.update(&footer_bytes[..prefix_len]);
    let sealed_digest = whole
        .clone()
        .finalize()
        .map_err(|_| PackError::ArithmeticOverflow)?;
    if sealed_digest != footer.whole_pack_sha256 {
        return Err(PackError::DigestMismatch {
            expected: ContentDigest::new(DigestAlgorithm::Sha256, footer.whole_pack_sha256),
            actual: ContentDigest::new(DigestAlgorithm::Sha256, sealed_digest),
        });
    }
    whole.update(&footer_bytes[prefix_len..]);
    let file_digest = whole
        .finalize()
        .map_err(|_| PackError::ArithmeticOverflow)?;
    footer.entries.sort_unstable();
    Ok((
        footer,
        ContentDigest::new(DigestAlgorithm::Sha256, file_digest),
    ))
}
