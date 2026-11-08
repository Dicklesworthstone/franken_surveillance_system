#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Synthetic original RTP through the production depacketizers and picture assemblers.
//! Explicit media timing is independent of the deliberately different RTP/receive clocks.

use fss_container::demux::{AvcMp4, DemuxLimits, VideoCodec};
use fss_container::{TimedAvcPicture, TimedHevcPicture};
use fss_packet::avc::{
    AvcAssembler, AvcAssemblyLimits, AvcAssemblyStep, AvcPictureGroup, AvcSyntaxLimits, parse_pps,
    parse_sps,
};
use fss_packet::hevc::{
    HevcAssembler, HevcAssemblyLimits, HevcAssemblyStep, HevcConfiguration,
    HevcConfigurationLimits, HevcPictureGroup,
};
use fss_packet::{
    H264Depacketizer, H264Limits, H264Mode, H265Depacketizer, H265Limits, PacketLimits, RtpPacket,
    StreamKey,
};
use std::collections::BTreeMap;

pub type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub const KEY: StreamKey = StreamKey {
    ingress: 23,
    generation: 1,
    ssrc: 7,
};
pub const SCALE: u32 = 90_000;
pub const BASE: u64 = 90_000;
pub const AVC_STEP: u32 = 3_600;
pub const HEVC_STEP: u32 = 18_000;

pub struct Packet {
    pub sequence: u64,
    pub received_ns: u64,
    pub bytes: Vec<u8>,
}

fn packet(sequence: u64, timestamp: u32, marker: bool, payload: &[u8]) -> Packet {
    let mut bytes = vec![0x80, 96 | if marker { 128 } else { 0 }];
    bytes.extend_from_slice(&(sequence as u16).to_be_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&KEY.ssrc.to_be_bytes());
    bytes.extend_from_slice(payload);
    Packet {
        sequence,
        received_ns: 700_000_000 + sequence,
        bytes,
    }
}

pub struct AvcSource {
    pub pictures: Vec<AvcPictureGroup>,
    pub packets: Vec<Packet>,
}

pub fn avc() -> Test<AvcSource> {
    let nals = split_annex_b(include_bytes!(
        "../../../fss-packet/tests/fixtures/avc/baseline.264"
    ));
    let syntax = AvcSyntaxLimits::default();
    let sps = parse_sps(nals.first().ok_or("SPS")?, syntax)?;
    let pps = parse_pps(nals.get(1).ok_or("PPS")?, &sps, syntax)?;
    let mut assembler = AvcAssembler::new(KEY, sps, pps, syntax, AvcAssemblyLimits::default())?;
    let mut depacketizer =
        H264Depacketizer::new(KEY, 96, H264Mode::NonInterleaved, H264Limits::default())?;
    let mut pictures = Vec::new();
    let mut packets = Vec::new();
    let mut frame = 0_u32;
    for (ordinal, nal) in nals.into_iter().enumerate() {
        let vcl = matches!(nal[0] & 31, 1 | 5);
        let source = packet(ordinal as u64 + 1, 450_000 + frame * AVC_STEP, vcl, nal);
        let output = depacketizer.push(
            KEY,
            source.sequence,
            RtpPacket::parse(&source.bytes, PacketLimits::default())?,
            0,
        )?;
        if output.discarded.is_some() {
            return Err("AVC fixture packet discarded".into());
        }
        for nal in output.nals {
            match assembler.push(nal, 0) {
                AvcAssemblyStep::Accepted(output) => {
                    if output.retired.is_some() {
                        return Err("AVC fixture retired".into());
                    }
                    pictures.extend(output.picture);
                }
                AvcAssemblyStep::Refused(refused) => return Err(refused.reason.into()),
            }
        }
        packets.push(source);
        if vcl {
            frame += 1;
        }
    }
    if depacketizer.finish().is_some() || pictures.len() != 4 {
        return Err("AVC fixture is not four observed complete pictures".into());
    }
    Ok(AvcSource { pictures, packets })
}

pub fn avc_timing(pictures: &[AvcPictureGroup]) -> Vec<TimedAvcPicture<'_>> {
    pictures
        .iter()
        .enumerate()
        .map(|(index, picture)| TimedAvcPicture {
            picture,
            decode_time: BASE + index as u64 * u64::from(AVC_STEP),
            duration: AVC_STEP,
            composition_offset: composition(index, AVC_STEP),
        })
        .collect()
}

pub struct HevcSource {
    pub configuration: HevcConfiguration,
    pub pictures: Vec<HevcPictureGroup>,
    pub packets: Vec<Packet>,
}

pub fn hevc() -> Test<HevcSource> {
    let nals: Vec<Vec<u8>> =
        include_str!("../../../../tests/fixtures/media/hevc/remux_main8.nals.hex")
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                if !line.is_ascii() || line.len() % 2 != 0 {
                    return Err("invalid hex fixture".into());
                }
                (0..line.len())
                    .step_by(2)
                    .map(|at| u8::from_str_radix(&line[at..at + 2], 16).map_err(Into::into))
                    .collect::<Test<Vec<_>>>()
            })
            .collect::<Test<_>>()?;
    let configuration = HevcConfiguration::parse(
        nals.first().ok_or("VPS")?,
        nals.get(1).ok_or("SPS")?,
        nals.get(2).ok_or("PPS")?,
        HevcConfigurationLimits::default(),
    )?;
    let times = [0, 0, 0, 0, 18_000, 36_000, 36_000, 36_000, 36_000, 54_000];
    let mut packets: Vec<_> = times
        .into_iter()
        .zip(nals)
        .enumerate()
        .map(|(index, (time, nal))| packet(65_533 + index as u64, 450_000 + time, true, &nal))
        .collect();
    // Source-observed synthetic EOS; no end-of-input flush invents a closing boundary.
    packets.push(packet(65_543, 504_000, true, &[0x48, 1, 0x80]));
    let mut depacketizer = H265Depacketizer::new(KEY, 96, 0, H265Limits::default())?;
    let mut assembler = HevcAssembler::new(KEY, HevcAssemblyLimits::default())?;
    let mut pictures = Vec::new();
    for source in &packets {
        let output = depacketizer.push(
            KEY,
            source.sequence,
            RtpPacket::parse(&source.bytes, PacketLimits::default())?,
            0,
        )?;
        if output.discarded.is_some() {
            return Err("HEVC fixture packet discarded".into());
        }
        for nal in output.nals {
            match assembler.push(nal, 0) {
                HevcAssemblyStep::Accepted(output) => {
                    if output.retired.is_some() {
                        return Err("HEVC fixture retired".into());
                    }
                    pictures.extend(output.picture);
                }
                HevcAssemblyStep::Refused(refused) => return Err(refused.reason.into()),
            }
        }
    }
    if depacketizer.finish().is_some() || pictures.len() != 4 {
        return Err("HEVC fixture is not four observed complete pictures".into());
    }
    Ok(HevcSource {
        configuration,
        pictures,
        packets,
    })
}

pub fn hevc_timing(pictures: &[HevcPictureGroup]) -> Vec<TimedHevcPicture<'_>> {
    pictures
        .iter()
        .enumerate()
        .map(|(index, picture)| TimedHevcPicture {
            picture,
            decode_time: BASE + index as u64 * u64::from(HEVC_STEP),
            duration: HEVC_STEP,
            composition_offset: composition(index, HEVC_STEP),
        })
        .collect()
}

pub fn composition(index: usize, step: u32) -> i32 {
    match index {
        1 => step as i32,
        2 => -(step as i32),
        _ => 0,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Image {
    pub dimensions: [u32; 2],
    pub pixels: Vec<u8>,
}

/// Full-source native pixel oracle, independent of retained-range and movie-output owners.
pub fn native_images(source: &[u8]) -> Test<BTreeMap<usize, Image>> {
    let parsed = AvcMp4::parse(source, None, DemuxLimits::default())?;
    let annex_b = parsed.annex_b(0, parsed.samples().len())?;
    let mut images = BTreeMap::new();
    match parsed.codec() {
        VideoCodec::Avc => {
            let mut decoder = fss_codec_h264::Decoder::new(Default::default())?;
            let mut pictures = decoder.decode_annex_b(annex_b.bytes())?;
            pictures.extend(decoder.finish()?);
            for picture in pictures {
                if images
                    .insert(
                        usize::try_from(picture.decode_index())?,
                        Image {
                            dimensions: [picture.width(), picture.height()],
                            pixels: picture.luma().to_vec(),
                        },
                    )
                    .is_some()
                {
                    return Err("duplicate native AVC source picture".into());
                }
            }
        }
        VideoCodec::Hevc => {
            let mut decoder = fss_codec_h265::Decoder::new(Default::default())?;
            let mut pictures = decoder.decode_annex_b(annex_b.bytes())?;
            pictures.extend(decoder.finish()?);
            for picture in pictures {
                if images
                    .insert(
                        usize::try_from(picture.decode_index())?,
                        Image {
                            dimensions: [picture.width(), picture.height()],
                            pixels: picture.luma().to_vec(),
                        },
                    )
                    .is_some()
                {
                    return Err("duplicate native HEVC source picture".into());
                }
            }
        }
    }
    if images.len() != parsed.samples().len() {
        return Err("missing native source picture".into());
    }
    Ok(images)
}

fn split_annex_b(bytes: &[u8]) -> Vec<&[u8]> {
    let mut output = Vec::new();
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
        if prefix == 0 {
            at += 1;
            continue;
        }
        if let Some(begin) = start {
            let mut end = at;
            while end > begin && bytes[end - 1] == 0 {
                end -= 1;
            }
            if begin < end {
                output.push(&bytes[begin..end]);
            }
        }
        start = Some(at + prefix);
        at += prefix;
    }
    if let Some(begin) = start
        && begin < bytes.len()
    {
        output.push(&bytes[begin..]);
    }
    output
}
