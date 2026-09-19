#![forbid(unsafe_code)]
//! Small, deterministic integration-test helpers; no device or network access.

use fss_packet::avc::{AvcPps, AvcSps, AvcSyntaxLimits, parse_pps, parse_sps};
use fss_packet::{
    StreamKey,
};

pub type Error = Box<dyn std::error::Error>;
pub const KEY: StreamKey = StreamKey {
    ingress: 17,
    generation: 1,
    ssrc: 7,
};

pub fn split(bytes: &[u8]) -> Vec<&[u8]> {
    let mut result = Vec::new();
    let mut start = None;
    let mut at = 0;
    while at + 3 <= bytes.len() {
        let prefix = if bytes.get(at..at + 4) == Some(&[0, 0, 0, 1]) {
            4
        } else if bytes[at..at + 3] == [0, 0, 1] {
            3
        } else {
            0
        };
        if prefix != 0 {
            if let Some(begin) = start {
                let mut end = at;
                while end > begin && bytes[end - 1] == 0 {
                    end -= 1;
                }
                if begin < end {
                    result.push(&bytes[begin..end]);
                }
            }
            start = Some(at + prefix);
            at += prefix;
        } else {
            at += 1;
        }
    }
    if let Some(begin) = start
        && begin < bytes.len()
    {
        result.push(&bytes[begin..]);
    }
    result
}

pub fn parameters() -> Result<(AvcSps, AvcPps), Error> {
    let nals = split(include_bytes!("../fixtures/avc/baseline.264"));
    let sps = parse_sps(nals[0], AvcSyntaxLimits::default())?;
    let pps = parse_pps(nals[1], &sps, AvcSyntaxLimits::default())?;
    Ok((sps, pps))
}

pub fn wire(
    key: StreamKey,
    sequence: u64,
    timestamp: u32,
    marker: bool,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![0x80, 96 | if marker { 128 } else { 0 }];
    bytes.extend_from_slice(&(sequence as u16).to_be_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&key.ssrc.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

pub fn slice(first_mb: u32, frame: u32) -> Vec<u8> {
    let mut bits = Vec::new();
    for value in [first_mb, 0, 0] {
        let code = value + 1;
        let width = 32 - code.leading_zeros();
        bits.extend(std::iter::repeat_n(false, (width - 1) as usize));
        for shift in (0..width).rev() {
            bits.push((code >> shift) & 1 != 0);
        }
    }
    for shift in (0..4).rev() {
        bits.push((frame >> shift) & 1 != 0);
    }
    // The baseline laboratory fixture has POC type 2 and no redundant_pic_cnt.
    // This synthetic payload intentionally proves only the identity prefix.
    bits.push(true);
    while !bits.len().is_multiple_of(8) {
        bits.push(false);
    }
    let mut bytes = vec![0x41];
    let mut zeros = 0;
    for chunk in bits.as_chunks::<8>().0 {
        let byte = chunk.iter().fold(0_u8, |v, b| (v << 1) | u8::from(*b));
        if zeros == 2 && byte <= 3 {
            bytes.push(3);
            zeros = 0;
        }
        bytes.push(byte);
        zeros = if byte == 0 { zeros + 1 } else { 0 };
    }
    bytes
}
