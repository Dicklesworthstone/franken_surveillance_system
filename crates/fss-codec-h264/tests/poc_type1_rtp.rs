#![forbid(unsafe_code)]
//! Exercise the actual bounded RTP receiver, AVC picture assembler and pixel decoder.
//! Source-copy spans and pixels are checked independently; these are local wire fixtures,
//! not evidence of physical-camera interoperability or durable deployment custody.

use std::collections::BTreeMap;

use fss_codec_h264::{Decoder, DecoderLimits, Picture, annex_b_nal_units};
use fss_core::ContentDigest;
use fss_packet::avc::{
    AvcAssemblyStep, AvcPictureGroup, AvcReceiveLimits, AvcReceivePoll, AvcReceiver,
    AvcSyntaxLimits, PocMode, parse_pps, parse_sps,
};
use fss_packet::{H264Mode, ReorderDisposition, StreamKey};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const KEY: StreamKey = StreamKey {
    ingress: 19,
    generation: 3,
    ssrc: 73,
};
const FIRST_SEQUENCE: u64 = 65_531;
const STREAM: &[u8] = include_bytes!("fixtures/decode/ip_100x60_poc1_cycle.h264");
const ORACLE: &str = include_str!("fixtures/decode/ip_100x60_poc1_cycle.sha256");

fn datagram(sequence: u64, timestamp: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, 96 | if marker { 0x80 } else { 0 }];
    bytes.extend_from_slice(&(sequence as u16).to_be_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&KEY.ssrc.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn packetize(stream: &[u8]) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    let mut timestamp = 0;
    for nal in annex_b_nal_units(stream) {
        let vcl = matches!(nal[0] & 31, 1 | 5);
        // Deliberately small fragments exercise FU-A reconstruction and sequence wrap.
        // This fixture has one slice per picture; only the final fragment carries marker.
        if nal.len() > 61 {
            let parts: Vec<_> = nal[1..].chunks(59).collect();
            for (index, part) in parts.iter().enumerate() {
                let last = index + 1 == parts.len();
                let mut payload = vec![
                    (nal[0] & 0xe0) | 28,
                    (nal[0] & 31) | if index == 0 { 0x80 } else { 0 } | if last { 0x40 } else { 0 },
                ];
                payload.extend_from_slice(part);
                packets.push(datagram(
                    FIRST_SEQUENCE + packets.len() as u64,
                    timestamp,
                    vcl && last,
                    &payload,
                ));
            }
        } else {
            packets.push(datagram(
                FIRST_SEQUENCE + packets.len() as u64,
                timestamp,
                vcl,
                nal,
            ));
        }
        if vcl {
            timestamp += 3_600;
        }
    }
    packets
}

#[derive(Default)]
struct Trace {
    sources: BTreeMap<u64, Vec<u8>>,
    groups: Vec<AvcPictureGroup>,
    source_spans: usize,
    fragments: usize,
}

impl Trace {
    fn picture(&mut self, group: AvcPictureGroup) -> TestResult {
        assert_eq!(group.key(), KEY);
        assert!(matches!(group.sps().poc_mode(), PocMode::Delta { .. }));
        assert!(group.saw_first_macroblock());
        assert!(!group.discontinuity_before());
        for nal in group.nals() {
            assert_eq!(nal.key(), KEY);
            for span in nal.sources() {
                let wire = self
                    .sources
                    .get(&span.sequence)
                    .ok_or("picture was emitted before its exact source datagram was exposed")?;
                assert_eq!(
                    wire[span.wire_range.clone()],
                    nal.bytes()[span.nal_range.clone()]
                );
                if let Some(header) = &span.fragment_header_range {
                    let header = &wire[header.clone()];
                    assert_eq!(header.len(), 2);
                    assert_eq!((header[0] & 0xe0) | (header[1] & 31), nal.bytes()[0]);
                    self.fragments += 1;
                }
                self.source_spans += 1;
            }
        }
        self.groups.push(group);
        Ok(())
    }

    fn drain(&mut self, receiver: &mut AvcReceiver, now: u64) -> TestResult<bool> {
        for _ in 0..4_096 {
            match receiver.poll(now)? {
                AvcReceivePoll::Source {
                    source,
                    gap_before,
                    fragment,
                    picture,
                    ..
                } => {
                    assert!(!gap_before && fragment.is_none() && picture.is_none());
                    assert_eq!(source.key(), KEY);
                    assert!(
                        self.sources
                            .insert(source.sequence(), source.bytes().to_vec())
                            .is_none()
                    );
                }
                AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(output)) => {
                    assert!(output.retired.is_none());
                    if let Some(picture) = output.picture {
                        self.picture(picture)?;
                    }
                }
                AvcReceivePoll::Picture(picture) => self.picture(picture)?,
                AvcReceivePoll::Pending { .. } => return Ok(false),
                AvcReceivePoll::Ended {
                    fragment,
                    interrupted_picture,
                    tail,
                } => {
                    assert!(fragment.is_none() && interrupted_picture.is_none());
                    if let Some(tail) = tail {
                        assert!(tail.retired.is_none());
                        if let Some(picture) = tail.picture {
                            self.picture(picture)?;
                        }
                    }
                    return Ok(true);
                }
                other => return Err(format!("unexpected admitted-wire result: {other:?}").into()),
            }
        }
        Err("receiver exceeded its fixture progress bound".into())
    }
}

fn check(reordered: bool) -> TestResult {
    let syntax = AvcSyntaxLimits::default();
    let nals: Vec<_> = annex_b_nal_units(STREAM).collect();
    let sps = parse_sps(
        nals.iter().find(|n| n[0] & 31 == 7).ok_or("missing SPS")?,
        syntax,
    )?;
    let pps = parse_pps(
        nals.iter().find(|n| n[0] & 31 == 8).ok_or("missing PPS")?,
        &sps,
        syntax,
    )?;
    assert!(matches!(
        sps.poc_mode(),
        PocMode::Delta { always_zero: true }
    ));
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    assert!(decoder.decode_nal(sps.nal_bytes())?.is_none());
    assert!(decoder.decode_nal(pps.nal_bytes())?.is_none());
    let mut receiver = AvcReceiver::new(
        KEY,
        96,
        H264Mode::NonInterleaved,
        AvcReceiveLimits::default(),
        (sps, pps),
    )?;
    // RTP sequence probation is explicit. It is not treated as retained source or a frame.
    let probation = datagram(FIRST_SEQUENCE - 1, 0, false, nals[0]);
    assert_eq!(
        receiver
            .ingest(KEY, &probation, 0)?
            .transport
            .transport
            .disposition,
        ReorderDisposition::NotAdmitted,
    );
    let packets = packetize(STREAM);
    assert!(FIRST_SEQUENCE + packets.len() as u64 > 65_536);
    let mut delivery = vec![0];
    for pair in (1..packets.len()).collect::<Vec<_>>().chunks(2) {
        if reordered {
            delivery.extend(pair.iter().rev().copied());
        } else {
            delivery.extend(pair.iter().copied());
        }
    }
    let mut trace = Trace::default();
    for (clock, index) in delivery.into_iter().enumerate() {
        let now = clock as u64 + 1;
        let admission = receiver.ingest(KEY, &packets[index], now)?;
        assert_eq!(
            admission.transport.transport.disposition,
            ReorderDisposition::Buffered
        );
        assert!(!trace.drain(&mut receiver, now)?);
    }
    receiver.finish();
    assert!(trace.drain(&mut receiver, packets.len() as u64 + 1)?);
    assert_eq!(trace.sources.len(), packets.len());
    for (index, packet) in packets.iter().enumerate() {
        assert_eq!(
            trace.sources.get(&(FIRST_SEQUENCE + index as u64)),
            Some(packet)
        );
    }
    assert!(trace.fragments > 6 && trace.source_spans > 6);
    assert_eq!(trace.groups.len(), 6);
    let reconstructed: Vec<_> = trace
        .groups
        .iter()
        .flat_map(|group| group.nals())
        .map(|nal| nal.bytes())
        .collect();
    assert_eq!(
        reconstructed, nals,
        "RTP reconstruction must preserve every exact source NAL"
    );

    let mut frames: Vec<Picture> = Vec::new();
    for (index, group) in trace.groups.iter().enumerate() {
        assert_eq!(group.timestamp(), index as u32 * 3_600);
        for nal in group.nals() {
            if let Some(frame) = decoder.decode_nal(nal.bytes())? {
                frames.push(frame);
            }
            while let Some(frame) = decoder.next_output() {
                frames.push(frame);
            }
        }
    }
    frames.extend(decoder.finish()?);
    let expected: Vec<_> = ORACLE
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .collect();
    assert_eq!(frames.len(), expected.len());
    for (index, (frame, line)) in frames.iter().zip(expected).enumerate() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].parse::<usize>()?, index);
        assert_eq!(fields[1].parse::<usize>()?, frame.to_i420().len());
        assert_eq!(
            ContentDigest::sha256(&frame.to_i420()).to_text(),
            format!("sha256:{}", fields[2])
        );
        assert_eq!(frame.decode_index(), index as u64);
        assert_eq!(frame.poc(), index as i32 * 2);
        assert_eq!(frame.width(), 100);
        assert_eq!(frame.height(), 60);
    }
    Ok(())
}

#[test]
fn type1_rtp_fragments_preserve_source_spans_and_oracle_pixels() -> TestResult {
    check(false)
}

#[test]
fn type1_rtp_reordering_and_sequence_wrap_preserve_source_and_display_order() -> TestResult {
    check(true)
}
