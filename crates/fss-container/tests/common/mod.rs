#![forbid(unsafe_code)]
//! Only synthetic fixture helpers; no private media or device access.

use fss_container::TimedAvcPicture;
use fss_packet::avc::{
    AvcAssembler, AvcAssemblyLimits, AvcAssemblyStep, AvcPictureGroup, AvcSyntaxLimits, parse_pps,
    parse_sps,
};
use fss_packet::{H264Depacketizer, H264Limits, H264Mode, PacketLimits, RtpPacket, StreamKey};

pub type Error = Box<dyn std::error::Error>;
pub const KEY: StreamKey = StreamKey {
    ingress: 17,
    generation: 1,
    ssrc: 7,
};
pub const BASELINE: &[u8] = include_bytes!("../../../fss-packet/tests/fixtures/avc/baseline.264");
pub const HIGH: &[u8] = include_bytes!("../../../fss-packet/tests/fixtures/avc/high_cropped.264");

pub fn groups(
    data: &[u8],
    key: StreamKey,
    marked: bool,
    discontinuity: bool,
) -> Result<Vec<AvcPictureGroup>, Error> {
    let nals = split(data);
    let syntax = AvcSyntaxLimits::default();
    let sps = parse_sps(nals[0], syntax)?;
    let pps = parse_pps(nals[1], &sps, syntax)?;
    let mut a = AvcAssembler::new(key, sps, pps, syntax, AvcAssemblyLimits::default())?;
    let mut d = H264Depacketizer::new(key, 96, H264Mode::NonInterleaved, H264Limits::default())?;
    if discontinuity {
        a.discontinuity(key, 0)?;
    }
    let mut output = Vec::new();
    let mut frame = 0_u32;
    for (index, nal) in nals.iter().enumerate() {
        let sequence = index as u64 + 1;
        let is_vcl = matches!(nal[0] & 31, 1 | 5);
        let mut wire = vec![0x80, 96 | if marked && is_vcl { 128 } else { 0 }];
        wire.extend_from_slice(&(sequence as u16).to_be_bytes());
        wire.extend_from_slice(&(frame * 3600).to_be_bytes());
        wire.extend_from_slice(&key.ssrc.to_be_bytes());
        wire.extend_from_slice(nal);
        let packet = RtpPacket::parse(&wire, PacketLimits::default())?;
        for nal in d.push(key, sequence, packet, sequence)?.nals {
            match a.push(nal, sequence) {
                AvcAssemblyStep::Accepted(step) => {
                    if step.retired.is_some() {
                        return Err("unexpected clean fixture retirement".into());
                    }
                    if let Some(picture) = step.picture {
                        output.push(picture);
                    }
                }
                AvcAssemblyStep::Refused(r) => return Err(r.reason.into()),
            }
        }
        if is_vcl {
            frame += 1;
        }
    }
    if let Some(tail) = a.finish(100)?.picture {
        output.push(tail);
    }
    Ok(output)
}

pub fn timed<'a>(groups: &'a [AvcPictureGroup], pts: &[u64]) -> Vec<TimedAvcPicture<'a>> {
    groups
        .iter()
        .zip(pts)
        .enumerate()
        .map(|(i, (picture, pts))| TimedAvcPicture {
            picture,
            decode_time: i as u64 * 3600,
            duration: 3600,
            composition_offset: (*pts as i64 - i as i64 * 3600) as i32,
        })
        .collect()
}

fn split(bytes: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
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
                    out.push(&bytes[begin..end]);
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
        out.push(&bytes[begin..]);
    }
    out
}
