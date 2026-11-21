#![forbid(unsafe_code)]
//! First-party FLV framing for original AVC bytes from retained laboratory MP4 fixtures.
//! This generator never calls the FLV parser under test.

use std::ops::Range;

pub fn header(audio: bool) -> Vec<u8> {
    let mut bytes = b"FLV\x01".to_vec();
    bytes.push(if audio { 5 } else { 1 });
    bytes.extend_from_slice(&9_u32.to_be_bytes());
    bytes.extend_from_slice(&[0; 4]);
    bytes
}

pub fn tag(bytes: &mut Vec<u8>, kind: u8, timestamp: u32, payload: &[u8]) -> Range<usize> {
    let start = bytes.len();
    bytes.push(kind);
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    bytes.extend_from_slice(&timestamp.to_be_bytes()[1..]);
    bytes.push(timestamp.to_be_bytes()[0]);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&(11 + payload.len() as u32).to_be_bytes());
    start..bytes.len()
}

pub fn configuration(bytes: &mut Vec<u8>, record: &[u8]) -> Range<usize> {
    let mut payload = vec![0x17, 0, 0, 0, 0];
    payload.extend_from_slice(record);
    tag(bytes, 9, 0, &payload)
}

pub fn sample(
    bytes: &mut Vec<u8>,
    source: &[u8],
    dts: u32,
    cts: i32,
    keyframe: bool,
) -> Range<usize> {
    let mut payload = vec![if keyframe { 0x17 } else { 0x27 }, 1];
    payload.extend_from_slice(&cts.to_be_bytes()[1..]);
    payload.extend_from_slice(source);
    tag(bytes, 9, dts, &payload)
}

/// The fixtures contain one avcC marker. Check the surrounding original box length.
pub fn avcc(mp4: &[u8]) -> Result<&[u8], Box<dyn std::error::Error>> {
    let at = mp4
        .windows(4)
        .position(|bytes| bytes == b"avcC")
        .ok_or("missing fixture avcC")?;
    let size = u32::from_be_bytes(
        mp4.get(at - 4..at)
            .ok_or("fixture avcC header")?
            .try_into()?,
    ) as usize;
    Ok(mp4.get(at + 4..at - 4 + size).ok_or("fixture avcC body")?)
}
