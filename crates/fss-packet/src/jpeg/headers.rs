#![forbid(unsafe_code)]
//! RFC 2435 header admission and deterministic JPEG interchange headers.

use super::{JpegError, Parameters};
use std::ops::Range;

pub(super) struct Header {
    pub parameters: Parameters,
    pub offset: usize,
    pub payload_start: usize,
    pub quantizers: Option<usize>,
}

pub(super) fn parse(bytes: &[u8], maximum_dimension: u16) -> Result<Header, JpegError> {
    let header = bytes.get(..8).ok_or(JpegError::Malformed)?;
    // RFC 2435 section 4.1's field-coded variants need an independently versioned
    // deinterlacing/field-time contract. Only complete progressive frames are admitted.
    if header[0] != 0 || !matches!(header[4], 0 | 1 | 64 | 65) {
        return Err(JpegError::Unsupported);
    }
    let quality = header[5];
    if !matches!(quality, 1..=99 | 128..=255) {
        return Err(JpegError::Unsupported);
    }
    let width = u16::from(header[6]) * 8;
    let height = u16::from(header[7]) * 8;
    if width == 0 || height == 0 {
        return Err(JpegError::Malformed);
    }
    if width > maximum_dimension || height > maximum_dimension {
        return Err(JpegError::Limit);
    }
    let offset =
        (usize::from(header[1]) << 16) | (usize::from(header[2]) << 8) | usize::from(header[3]);
    let mut at = 8;
    let restart = if header[4] >= 64 {
        let restart_header = bytes.get(at..at + 4).ok_or(JpegError::Malformed)?;
        at += 4;
        let interval = u16::from_be_bytes([restart_header[0], restart_header[1]]);
        if interval == 0 {
            return Err(JpegError::Malformed);
        }
        // F/L/count are only partial-decoding hints. This profile always reassembles
        // the complete image and the JPEG decoder verifies the actual restart sequence.
        if restart_header[2] & 0x3f == 0x3f
            && restart_header[3] == 0xff
            && restart_header[2] != 0xff
        {
            return Err(JpegError::Malformed);
        }
        interval
    } else {
        0
    };
    let mut quantizers = None;
    if quality >= 128 && offset == 0 {
        let tables = bytes.get(at..at + 4).ok_or(JpegError::Malformed)?;
        if tables[0] != 0 {
            return Err(JpegError::Malformed);
        }
        // Only bits 0 and 1 describe the two admitted tables. RFC 2435 requires
        // ignoring higher precision bits; retain their original source bytes.
        if tables[1] & 0x03 != 0 {
            return Err(JpegError::Unsupported);
        }
        let length = usize::from(u16::from_be_bytes([tables[2], tables[3]]));
        at += 4;
        match length {
            0 if quality != 255 => {}
            128 => {
                bytes.get(at..at + length).ok_or(JpegError::Malformed)?;
                quantizers = Some(at);
                at += length;
            }
            0 => return Err(JpegError::MissingQuantizers),
            _ => return Err(JpegError::Unsupported),
        }
    }
    if offset
        .checked_add(bytes.len() - at)
        .ok_or(JpegError::Limit)?
        > 1 << 24
    {
        return Err(JpegError::Limit);
    }
    Ok(Header {
        parameters: Parameters {
            kind: header[4],
            quality,
            width,
            height,
            restart,
        },
        offset,
        payload_start: at,
        quantizers,
    })
}

const LUMA: [u8; 64] = [
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113,
    92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
];
const CHROMA: [u8; 64] = [
    17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99, 24, 26, 56, 99, 99, 99, 99, 99,
    47, 66, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
];
const ZIGZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

/// RFC 2435 Appendix A's integer scaling, serialized in JPEG zigzag order.
pub(super) fn quantizers(q: u8) -> [u8; 128] {
    let q = u32::from(q);
    let scale = if q < 50 { 5000 / q } else { 200 - 2 * q };
    let mut output = [0; 128];
    for (table, base) in [LUMA, CHROMA].into_iter().enumerate() {
        for (i, &position) in ZIGZAG.iter().enumerate() {
            output[table * 64 + i] =
                ((u32::from(base[position]) * scale + 50) / 100).clamp(1, 255) as u8;
        }
    }
    output
}

// JPEG Annex K's standard DC/AC luminance and chrominance tables required by
// RFC 2435 section 4.1. The retained encoder fixtures independently supply them.
const HUFFMAN: [u8; 416] = [
    0, 0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 16, 0,
    2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 125, 1, 2, 3, 0, 4, 17, 5, 18, 33, 49, 65, 6, 19, 81,
    97, 7, 34, 113, 20, 50, 129, 145, 161, 8, 35, 66, 177, 193, 21, 82, 209, 240, 36, 51, 98, 114,
    130, 9, 10, 22, 23, 24, 25, 26, 37, 38, 39, 40, 41, 42, 52, 53, 54, 55, 56, 57, 58, 67, 68, 69,
    70, 71, 72, 73, 74, 83, 84, 85, 86, 87, 88, 89, 90, 99, 100, 101, 102, 103, 104, 105, 106, 115,
    116, 117, 118, 119, 120, 121, 122, 131, 132, 133, 134, 135, 136, 137, 138, 146, 147, 148, 149,
    150, 151, 152, 153, 154, 162, 163, 164, 165, 166, 167, 168, 169, 170, 178, 179, 180, 181, 182,
    183, 184, 185, 186, 194, 195, 196, 197, 198, 199, 200, 201, 202, 210, 211, 212, 213, 214, 215,
    216, 217, 218, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 241, 242, 243, 244, 245, 246,
    247, 248, 249, 250, 1, 0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7,
    8, 9, 10, 11, 17, 0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 119, 0, 1, 2, 3, 17, 4, 5, 33,
    49, 6, 18, 65, 81, 7, 97, 113, 19, 34, 50, 129, 8, 20, 66, 145, 161, 177, 193, 9, 35, 51, 82,
    240, 21, 98, 114, 209, 10, 22, 36, 52, 225, 37, 241, 23, 24, 25, 26, 38, 39, 40, 41, 42, 53,
    54, 55, 56, 57, 58, 67, 68, 69, 70, 71, 72, 73, 74, 83, 84, 85, 86, 87, 88, 89, 90, 99, 100,
    101, 102, 103, 104, 105, 106, 115, 116, 117, 118, 119, 120, 121, 122, 130, 131, 132, 133, 134,
    135, 136, 137, 138, 146, 147, 148, 149, 150, 151, 152, 153, 154, 162, 163, 164, 165, 166, 167,
    168, 169, 170, 178, 179, 180, 181, 182, 183, 184, 185, 186, 194, 195, 196, 197, 198, 199, 200,
    201, 202, 210, 211, 212, 213, 214, 215, 216, 217, 218, 226, 227, 228, 229, 230, 231, 232, 233,
    234, 242, 243, 244, 245, 246, 247, 248, 249, 250,
];

pub(super) fn build(
    p: Parameters,
    tables: &[u8; 128],
) -> Result<(Vec<u8>, [Range<usize>; 2]), JpegError> {
    let mut out = Vec::new();
    out.try_reserve_exact(640)
        .map_err(|_| JpegError::Allocation)?;
    out.extend_from_slice(&[0xff, 0xd8]);
    let mut ranges = [0..0, 0..0];
    for (table, range) in ranges.iter_mut().enumerate() {
        out.extend_from_slice(&[0xff, 0xdb, 0, 67, table as u8]);
        *range = out.len()..out.len() + 64;
        out.extend_from_slice(&tables[table * 64..(table + 1) * 64]);
    }
    out.extend_from_slice(&[0xff, 0xc0, 0, 17, 8]);
    out.extend_from_slice(&p.height.to_be_bytes());
    out.extend_from_slice(&p.width.to_be_bytes());
    out.extend_from_slice(&[
        3,
        1,
        if p.kind & 1 == 0 { 0x21 } else { 0x22 },
        0,
        2,
        0x11,
        1,
        3,
        0x11,
        1,
    ]);
    out.extend_from_slice(&[0xff, 0xc4, 1, 162]);
    out.extend_from_slice(&HUFFMAN);
    if p.restart != 0 {
        out.extend_from_slice(&[0xff, 0xdd, 0, 4]);
        out.extend_from_slice(&p.restart.to_be_bytes());
    }
    out.extend_from_slice(&[0xff, 0xda, 0, 12, 3, 1, 0, 2, 0x11, 3, 0x11, 0, 63, 0]);
    Ok((out, ranges))
}

/// Screen entropy framing without claiming Huffman/MCU validity. An explicit EOI must be
/// terminal. Arbitrary padding/extra coded scan lines are outside this strict decode profile.
pub(super) fn validate_scan(scan: &[u8], restart: bool) -> Result<bool, JpegError> {
    let mut at = 0;
    while at < scan.len() {
        if scan[at] != 0xff {
            at += 1;
            continue;
        }
        let start = at;
        while scan.get(at) == Some(&0xff) {
            at += 1;
        }
        let marker = *scan.get(at).ok_or(JpegError::Malformed)?;
        at += 1;
        match marker {
            0 if at - start == 2 => {}
            0xd0..=0xd7 if restart => {}
            0xd9 if at == scan.len() => return Ok(true),
            _ => return Err(JpegError::Malformed),
        }
    }
    Ok(false)
}
