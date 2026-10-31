#![forbid(unsafe_code)]
//! Actual RTP/JPEG transport reconstruction composed with the first-party pixel decoder.

use fss_codec_mjpeg::color::{RgbDecodeLimits, decode_rgb};
use fss_codec_mjpeg::{
    ComponentInterpretation, DecodeBudget, DecodeError, DecodeLimits, decode_luma,
};
use fss_core::ContentDigest;
use fss_packet::jpeg::{JpegDepacketizer, JpegFrame, JpegLimits, JpegReceivePoll, JpegReceiver};
use fss_packet::{PacketLimits, ReorderLimits, RtpPacket, StreamKey};
use std::sync::atomic::AtomicBool;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const KEY: StreamKey = StreamKey {
    ingress: 11,
    generation: 8,
    ssrc: 23,
};

struct Fixture {
    jpeg: &'static [u8],
    luma: &'static [u8],
    q: u8,
}
const FIXTURES: [Fixture; 6] = [
    Fixture {
        jpeg: include_bytes!("fixtures/rtp_jpeg/422_32x24_q50_rst0.jpg"),
        luma: include_bytes!("fixtures/rtp_jpeg/422_32x24_q50_rst0.ffmpeg.luma"),
        q: 50,
    },
    Fixture {
        jpeg: include_bytes!("fixtures/rtp_jpeg/420_32x24_q75_rst0.jpg"),
        luma: include_bytes!("fixtures/rtp_jpeg/420_32x24_q75_rst0.ffmpeg.luma"),
        q: 75,
    },
    Fixture {
        jpeg: include_bytes!("fixtures/rtp_jpeg/420_40x32_q31_rst2.jpg"),
        luma: include_bytes!("fixtures/rtp_jpeg/420_40x32_q31_rst2.ffmpeg.luma"),
        q: 31,
    },
    Fixture {
        jpeg: include_bytes!("fixtures/rtp_jpeg/422_40x24_q80_rst1.jpg"),
        luma: include_bytes!("fixtures/rtp_jpeg/422_40x24_q80_rst1.ffmpeg.luma"),
        q: 80,
    },
    Fixture {
        jpeg: include_bytes!("fixtures/rtp_jpeg/420_24x16_q99_rst0.jpg"),
        luma: include_bytes!("fixtures/rtp_jpeg/420_24x16_q99_rst0.ffmpeg.luma"),
        q: 99,
    },
    Fixture {
        jpeg: include_bytes!("fixtures/rtp_jpeg/422_16x16_q1_rst0.jpg"),
        luma: include_bytes!("fixtures/rtp_jpeg/422_16x16_q1_rst0.ffmpeg.luma"),
        q: 1,
    },
];

struct Scan<'a> {
    bytes: &'a [u8],
    tables: [u8; 128],
    dimensions: [u16; 2],
    kind: u8,
    restart: u16,
}

/// Independent test-only JPEG envelope reader. It does not call production RTP code to
/// derive the expected table data, scan, dimensions, or original decoder result.
fn scan(bytes: &[u8]) -> Test<Scan<'_>> {
    let mut at = 2;
    let mut tables = [0; 128];
    let mut table_mask = 0;
    let mut dimensions = [0; 2];
    let mut kind = 0;
    let mut restart = 0;
    while at < bytes.len() {
        let marker = bytes.get(at..at + 4).ok_or("short fixture header")?;
        assert_eq!(marker[0], 255);
        let length = usize::from(u16::from_be_bytes([marker[2], marker[3]]));
        let body = bytes
            .get(at + 4..at + 2 + length)
            .ok_or("short fixture marker")?;
        at += length + 2;
        match marker[1] {
            0xdb => {
                let (entries, remainder) = body.as_chunks::<65>();
                assert!(remainder.is_empty());
                for table in entries {
                    let id = usize::from(table[0]);
                    assert!(id < 2);
                    tables[id * 64..(id + 1) * 64].copy_from_slice(&table[1..]);
                    table_mask |= 1 << id;
                }
            }
            0xc0 => {
                assert_eq!(body[0], 8);
                dimensions = [
                    u16::from_be_bytes([body[3], body[4]]),
                    u16::from_be_bytes([body[1], body[2]]),
                ];
                kind = match body[7] {
                    0x21 => 0,
                    0x22 => 1,
                    _ => return Err("fixture sampling exceeds RTP profile".into()),
                };
            }
            0xdd => restart = u16::from_be_bytes([body[0], body[1]]),
            0xda => {
                assert_eq!(table_mask, 3);
                assert!(dimensions.iter().all(|n| *n > 0 && n.is_multiple_of(8)));
                return Ok(Scan {
                    bytes: &bytes[at..],
                    tables,
                    dimensions,
                    kind: kind + if restart == 0 { 0 } else { 64 },
                    restart,
                });
            }
            _ => {}
        }
    }
    Err("fixture has no scan".into())
}

fn wire(
    scan: &Scan<'_>,
    q: u8,
    sequence: u16,
    range: std::ops::Range<usize>,
    marker: bool,
    explicit: bool,
) -> Vec<u8> {
    let mut out = vec![0x80, 26 | if marker { 0x80 } else { 0 }];
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&9000_u32.to_be_bytes());
    out.extend_from_slice(&KEY.ssrc.to_be_bytes());
    out.extend_from_slice(&[
        0,
        (range.start >> 16) as u8,
        (range.start >> 8) as u8,
        range.start as u8,
        scan.kind,
        q,
        (scan.dimensions[0] / 8) as u8,
        (scan.dimensions[1] / 8) as u8,
    ]);
    if scan.restart != 0 {
        out.extend_from_slice(&scan.restart.to_be_bytes());
        out.extend_from_slice(&[0xff, 0xff]);
    }
    if q >= 128 && range.start == 0 {
        out.extend_from_slice(&[0, 0, 0, if explicit { 128 } else { 0 }]);
        if explicit {
            out.extend_from_slice(&scan.tables);
        }
    }
    out.extend_from_slice(&scan.bytes[range]);
    out
}

fn reconstruct(scan: &Scan<'_>, q: u8, packet_size: usize, explicit_eoi: bool) -> Test<JpegFrame> {
    let mut receiver = JpegDepacketizer::new(KEY, 26, JpegLimits::default())?;
    let end = scan.bytes.len() - if explicit_eoi { 0 } else { 2 };
    let mut complete = None;
    for (index, begin) in (0..end).step_by(packet_size).enumerate() {
        let limit = (begin + packet_size).min(end);
        let sequence = index as u16 + 1;
        let packet = wire(scan, q, sequence, begin..limit, limit == end, true);
        let output = receiver.push(
            KEY,
            u64::from(sequence),
            RtpPacket::parse(&packet, PacketLimits::default())?,
            u64::from(sequence),
        )?;
        if limit < end {
            assert!(output.frame.is_none());
        } else {
            complete = output.frame;
        }
    }
    Ok(*complete.ok_or("RTP reconstruction did not complete")?)
}

fn luma(bytes: &[u8]) -> Result<fss_codec_mjpeg::DecodedLuma, DecodeError> {
    decode_luma(
        bytes,
        ContentDigest::sha256(bytes).bytes(),
        ComponentInterpretation::YCbCr,
        DecodeLimits::default(),
        &mut DecodeBudget::new(100_000_000),
    )
}

#[test]
fn computed_and_explicit_quantizers_decode_all_real_fixtures_against_independent_oracles() -> Test {
    for fixture in &FIXTURES {
        let source = scan(fixture.jpeg)?;
        let original = luma(fixture.jpeg)?;
        for q in [fixture.q, 128, 255] {
            let frame = reconstruct(&source, q, 97, true)?;
            let decoded = luma(frame.bytes())?;
            assert_eq!(decoded.dimensions(), source.dimensions.map(u32::from));
            assert_eq!(decoded.pixels(), original.pixels());
            assert_eq!(decoded.pixels().len(), fixture.luma.len());
            for (&native, &oracle) in decoded.pixels().iter().zip(fixture.luma) {
                assert!(native.abs_diff(oracle) <= 1);
            }
            assert_eq!(decoded.receipt().restarts, original.receipt().restarts);
            assert_eq!(
                decoded.receipt().encoded_sha256,
                ContentDigest::sha256(frame.bytes()).bytes()
            );
            assert_ne!(
                decoded.receipt().encoded_sha256,
                ContentDigest::sha256(fixture.jpeg).bytes()
            );
        }
    }
    Ok(())
}

#[test]
fn every_byte_fragment_and_implicit_eoi_preserve_exact_decoded_pixels() -> Test {
    for fixture in &FIXTURES[..4] {
        let source = scan(fixture.jpeg)?;
        let complete = reconstruct(&source, fixture.q, usize::MAX, true)?;
        for (size, eoi) in [(1, true), (7, false), (64, true), (101, false)] {
            let fragmented = reconstruct(&source, fixture.q, size, eoi)?;
            assert_eq!(fragmented.bytes(), complete.bytes());
            assert_eq!(
                luma(fragmented.bytes())?.pixels(),
                luma(complete.bytes())?.pixels()
            );
        }
    }
    Ok(())
}

#[test]
fn native_rgb_decode_matches_original_stream_for_both_sampling_modes_and_restarts() -> Test {
    for fixture in &FIXTURES[..4] {
        let frame = reconstruct(&scan(fixture.jpeg)?, 255, 71, false)?;
        let decode = |bytes: &[u8]| {
            decode_rgb(
                bytes,
                ContentDigest::sha256(bytes).bytes(),
                ComponentInterpretation::YCbCr,
                RgbDecodeLimits::default(),
                &mut DecodeBudget::new(100_000_000),
            )
        };
        let original = decode(fixture.jpeg)?;
        let rebuilt = decode(frame.bytes())?;
        assert_eq!(original.dimensions(), rebuilt.dimensions());
        assert_eq!(original.pixels(), rebuilt.pixels());
    }
    Ok(())
}

#[test]
fn quantizer_cache_reuse_preserves_real_pixels_and_explicit_original_table_dependencies() -> Test {
    let fixture = &FIXTURES[1];
    let source = scan(fixture.jpeg)?;
    let mut receiver = JpegDepacketizer::new(KEY, 26, JpegLimits::default())?;
    let original = wire(&source, 128, 1, 0..source.bytes.len(), true, true);
    receiver.push(
        KEY,
        1,
        RtpPacket::parse(&original, PacketLimits::default())?,
        0,
    )?;
    let reuse = wire(&source, 128, 2, 0..source.bytes.len(), true, false);
    let output = receiver.push(
        KEY,
        2,
        RtpPacket::parse(&reuse, PacketLimits::default())?,
        1,
    )?;
    let frame = output.frame.ok_or("missing cached-table image")?;
    assert_eq!(frame.source_spans()[0].sequence, 1);
    assert_eq!(frame.source_spans()[1].sequence, 1);
    assert_eq!(frame.header_sources()[0].wire_range, 12..152);
    assert_eq!(luma(frame.bytes())?.pixels(), luma(fixture.jpeg)?.pixels());
    Ok(())
}

#[test]
fn dynamic_quantizers_and_dimensions_change_without_reusing_previous_image_state() -> Test {
    let mut receiver = JpegDepacketizer::new(KEY, 26, JpegLimits::default())?;
    for (index, fixture) in FIXTURES.iter().enumerate() {
        let source = scan(fixture.jpeg)?;
        let sequence = index as u16 + 1;
        let mut packet = wire(&source, 255, sequence, 0..source.bytes.len(), true, true);
        packet[4..8].copy_from_slice(&(u32::from(sequence) * 9000).to_be_bytes());
        let output = receiver.push(
            KEY,
            u64::from(sequence),
            RtpPacket::parse(&packet, PacketLimits::default())?,
            u64::from(sequence),
        )?;
        assert_eq!(
            luma(
                output
                    .frame
                    .ok_or("missing changed-configuration image")?
                    .bytes()
            )?
            .pixels(),
            luma(fixture.jpeg)?.pixels()
        );
        assert_eq!(receiver.cached_quantizers(), 0);
    }
    Ok(())
}

#[test]
fn real_image_survives_reordering_and_raw_sequence_wrap_with_original_source_bytes() -> Test {
    let fixture = &FIXTURES[0];
    let source = scan(fixture.jpeg)?;
    let mut receiver = JpegReceiver::new(KEY, 26, ReorderLimits::default(), JpegLimits::default())?;
    let a = source.bytes.len() / 3;
    let b = a * 2;
    let probation = wire(
        &source,
        fixture.q,
        65533,
        0..source.bytes.len(),
        true,
        false,
    );
    let first = wire(&source, fixture.q, 65534, 0..a, false, false);
    let middle = wire(&source, fixture.q, 65535, a..b, false, false);
    let last = wire(&source, fixture.q, 0, b..source.bytes.len(), true, false);
    receiver.ingest(KEY, &probation, 0)?;
    receiver.ingest(KEY, &first, 1)?;
    receiver.ingest(KEY, &last, 2)?;
    receiver.ingest(KEY, &middle, 3)?;
    let mut complete = None;
    for (sequence, original) in [(65534, &first), (65535, &middle), (65536, &last)] {
        let JpegReceivePoll::Packet {
            source,
            reconstruction,
        } = receiver.poll(3)?
        else {
            return Err("missing ordered RTP source".into());
        };
        assert_eq!(source.sequence(), sequence);
        assert_eq!(source.bytes(), original);
        let output = reconstruction?;
        if sequence == 65536 {
            complete = output.frame;
        } else {
            assert!(output.frame.is_none());
        }
    }
    assert_eq!(
        luma(complete.ok_or("reordering did not complete")?.bytes())?.pixels(),
        luma(fixture.jpeg)?.pixels()
    );
    Ok(())
}

#[test]
fn transport_completion_cannot_publish_invalid_entropy_as_pixels() -> Test {
    let fixture = &FIXTURES[1];
    let mut source = scan(fixture.jpeg)?;
    source.bytes = &[0xff, 0, 0xff, 0, 0xff, 0, 0xff, 0xd9];
    let frame = reconstruct(&source, fixture.q, 3, true)?;
    assert!(luma(frame.bytes()).is_err());
    Ok(())
}

#[test]
fn cancelled_or_underbudget_pixel_validation_never_returns_an_image() -> Test {
    let frame = reconstruct(&scan(FIXTURES[0].jpeg)?, 255, 51, true)?;
    let digest = ContentDigest::sha256(frame.bytes()).bytes();
    let cancelled = AtomicBool::new(true);
    for (mut budget, expected) in [
        (DecodeBudget::new(0), DecodeError::BudgetExhausted),
        (
            DecodeBudget::cancellable(100_000_000, &cancelled),
            DecodeError::Cancelled,
        ),
    ] {
        let result = decode_luma(
            frame.bytes(),
            digest,
            ComponentInterpretation::YCbCr,
            DecodeLimits::default(),
            &mut budget,
        );
        assert_eq!(result.err().ok_or("unvalidated pixels escaped")?, expected);
    }
    Ok(())
}
