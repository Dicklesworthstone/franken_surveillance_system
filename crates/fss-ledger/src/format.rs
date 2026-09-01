//! Durable journal framing and root algebra.

use fss_core::sha256;

pub(crate) const RECORD_MAGIC: [u8; 8] = *b"FSSJRN01";
pub(crate) const COMMIT_MAGIC: [u8; 8] = *b"FSSCMT01";
pub(crate) const FORMAT_VERSION: u16 = 1;
pub(crate) const HEADER_LEN: usize = 8 + 2 + 8 + 2 + 4 + 32 + 32;
pub(crate) const TRAILER_LEN: usize = 8 + 32;
const ROOT_DOMAIN: &[u8] = b"FSS-JOURNAL-RECORD-ROOT-V1\0";

pub(crate) fn record_root(
    sequence: u64,
    kind: u16,
    payload_len: u32,
    previous_root: [u8; 32],
    payload_digest: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(ROOT_DOMAIN.len() + 8 + 2 + 4 + 32 + 32);
    bytes.extend_from_slice(ROOT_DOMAIN);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&payload_len.to_be_bytes());
    bytes.extend_from_slice(&previous_root);
    bytes.extend_from_slice(&payload_digest);
    sha256(&bytes)
}

pub(crate) fn read_u16(bytes: &[u8], offset: &mut usize) -> u16 {
    let value = u16::from_be_bytes([bytes[*offset], bytes[*offset + 1]]);
    *offset += 2;
    value
}

pub(crate) fn read_u32(bytes: &[u8], offset: &mut usize) -> u32 {
    let value = u32::from_be_bytes([
        bytes[*offset],
        bytes[*offset + 1],
        bytes[*offset + 2],
        bytes[*offset + 3],
    ]);
    *offset += 4;
    value
}

pub(crate) fn read_u64(bytes: &[u8], offset: &mut usize) -> u64 {
    let value = u64::from_be_bytes([
        bytes[*offset],
        bytes[*offset + 1],
        bytes[*offset + 2],
        bytes[*offset + 3],
        bytes[*offset + 4],
        bytes[*offset + 5],
        bytes[*offset + 6],
        bytes[*offset + 7],
    ]);
    *offset += 8;
    value
}
