#![forbid(unsafe_code)]
//! FSS-059 malformed-media gauntlet for RTP/RTCP parsing, RFC 6184 / RFC 7798
//! depacketization, reordering, AVC/HEVC parameter-set screening and picture grouping.
//!
//! Seeds are the checked-in AVC fixtures (`tests/fixtures/avc/*.264`) and the shared
//! HEVC remux fixture (`tests/fixtures/media/hevc/remux_main8.nals.hex`), packetized
//! in-test as single-NAL, STAP-A/AP and FU-A/FU packets (some with CSRCs, header
//! extensions and padding), plus three hand-built RTCP compounds. Mutants come from
//! the shared fixed-seed engine in `tests/media_mutation`.
//!
//! Invariants per mutant (each run twice): no panic in a debug build, Ok or a typed
//! error, every accessor of an accepted RTP/RTCP view stays inside its datagram, the
//! receivers' queues and retained bytes stay under their declared limits, the poll
//! loop terminates within a bound fixed by the input size, every published NAL is
//! byte-for-byte the concatenation of the datagram ranges its source spans name
//! (no invented or partial bytes), and the two runs are identical.
//!
//! No-Claim: evidence against these mutation classes over this corpus only; not
//! coverage-guided fuzzing and not a proof.

mod media_mutation;

use std::collections::BTreeMap;

use fss_packet::avc::{
    AvcAssemblyLimits, AvcAssemblyStep, AvcPictureGroup, AvcReceiveAdmission, AvcReceiveError,
    AvcReceiveLimits, AvcReceivePoll, AvcReceiver, AvcSyntaxLimits, parse_pps,
    parse_slice_identity, parse_sps,
};
use fss_packet::hevc::{
    HevcAssembler, HevcAssemblyLimits, HevcAssemblyStep, HevcConfiguration,
    HevcConfigurationLimits, HevcPictureGroup, parse_slice_prefix,
};
use fss_packet::{
    H264Limits, H264Mode, H265Limits, H265ReceivePoll, H265Receiver, NalSourceSpan, PacketLimits,
    ReorderLimits, RtcpCompound, RtcpMode, RtpPacket, StreamKey,
};
use media_mutation::{
    CLASSES, Class, Failure, LengthField, Rng, Seed, Tally, annex_b_units, check, mutate_sequence,
    mutate_stacked, report,
};

const KEY: StreamKey = StreamKey {
    ingress: 59,
    generation: 1,
    ssrc: 0x0F55_0059,
};
const PT: u8 = 96;
const BASELINE: &[u8] = include_bytes!("fixtures/avc/baseline.264");
const HIGH: &[u8] = include_bytes!("fixtures/avc/high_cropped.264");
const HEVC_HEX: &str = include_str!("../../../tests/fixtures/media/hevc/remux_main8.nals.hex");

const RTP_MUTANTS: usize = 30_000;
const RTCP_MUTANTS: usize = 30_000;
const PARAMETER_MUTANTS: usize = 30_000;
const AVC_STREAM_MUTANTS: usize = 12_000;
const HEVC_STREAM_MUTANTS: usize = 12_000;

/// FU fragment payload size used by the in-test packetizer.
const FRAGMENT: usize = 300;

fn nals(annex_b: &[u8]) -> Vec<Vec<u8>> {
    annex_b_units(annex_b)
        .into_iter()
        .filter_map(|unit| {
            let unit = annex_b.get(unit)?;
            let start = unit.windows(3).position(|w| w == [0, 0, 1])? + 3;
            let mut nal = unit.get(start..)?.to_vec();
            while nal.last() == Some(&0) {
                nal.pop();
            }
            (!nal.is_empty()).then_some(nal)
        })
        .collect()
}

fn hevc_nals() -> Vec<Vec<u8>> {
    let digit = |b: u8| match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => 0,
    };
    HEVC_HEX
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let compact: Vec<u8> = line.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
            compact
                .chunks(2)
                .map(|p| digit(p[0]) * 16 + digit(*p.get(1).unwrap_or(&b'0')))
                .collect()
        })
        .collect()
}

/// Header options for the seed packets.
#[derive(Clone, Copy)]
struct Shape {
    csrcs: usize,
    extension_words: usize,
    padding: u8,
}

const PLAIN: Shape = Shape {
    csrcs: 0,
    extension_words: 0,
    padding: 0,
};

/// RTP fixed-header values of one seed datagram.
#[derive(Clone, Copy)]
struct Fixed {
    sequence: u16,
    timestamp: u32,
    marker: bool,
}

/// One RTP datagram seed; `size_fields` are the STAP/AP member size-field offsets.
fn rtp_seed(
    name: String,
    fixed: Fixed,
    payload: &[u8],
    payload_units: &[std::ops::Range<usize>],
    size_fields: &[usize],
    shape: Shape,
) -> Seed {
    let mut bytes = vec![
        0x80 | if shape.padding > 0 { 0x20 } else { 0 }
            | if shape.extension_words > 0 { 0x10 } else { 0 }
            | shape.csrcs as u8,
        PT | if fixed.marker { 0x80 } else { 0 },
    ];
    bytes.extend_from_slice(&fixed.sequence.to_be_bytes());
    bytes.extend_from_slice(&fixed.timestamp.to_be_bytes());
    bytes.extend_from_slice(&KEY.ssrc.to_be_bytes());
    let mut seed = Seed::new(name, Vec::new());
    seed.units.push(0..12);
    seed.length_fields.push(LengthField::Binary {
        offset: 0,
        width: 1,
    });
    for i in 0..shape.csrcs {
        let start = bytes.len();
        bytes.extend_from_slice(&(0x1000_0000_u32 + i as u32).to_be_bytes());
        seed.units.push(start..bytes.len());
    }
    if shape.extension_words > 0 {
        let start = bytes.len();
        bytes.extend_from_slice(&0xBEDE_u16.to_be_bytes());
        bytes.extend_from_slice(&(shape.extension_words as u16).to_be_bytes());
        bytes.extend(std::iter::repeat_n(0x5A, shape.extension_words * 4));
        seed.units.push(start..bytes.len());
        seed.length_fields.push(LengthField::Binary {
            offset: start + 2,
            width: 2,
        });
    }
    let base = bytes.len();
    bytes.extend_from_slice(payload);
    seed.units.push(base..bytes.len());
    seed.units
        .extend(payload_units.iter().map(|u| u.start + base..u.end + base));
    seed.length_fields
        .extend(size_fields.iter().map(|&offset| LengthField::Binary {
            offset: offset + base,
            width: 2,
        }));
    if shape.padding > 0 {
        let start = bytes.len();
        bytes.extend(std::iter::repeat_n(0, usize::from(shape.padding) - 1));
        bytes.push(shape.padding);
        seed.units.push(start..bytes.len());
        seed.length_fields.push(LengthField::Binary {
            offset: bytes.len() - 1,
            width: 1,
        });
    }
    seed.units.sort_by_key(|u| (u.start, u.end));
    seed.bytes = bytes;
    seed
}

/// RFC 6184 (`hevc == false`) or RFC 7798 packetization of a NAL sequence.
fn packetize(nal_list: &[Vec<u8>], hevc: bool, label: &str) -> Vec<Seed> {
    let mut packets = Vec::new();
    let mut sequence: u16 = 1;
    let mut timestamp: u32 = 90_000;
    let is_parameter = |nal: &[u8]| {
        if hevc {
            matches!((nal[0] >> 1) & 63, 32..=34)
        } else {
            matches!(nal[0] & 31, 7 | 8)
        }
    };
    let is_vcl = |nal: &[u8]| {
        if hevc {
            (nal[0] >> 1) & 63 < 32
        } else {
            matches!(nal[0] & 31, 1 | 5)
        }
    };
    let header_len = if hevc { 2 } else { 1 };
    let shapes = [
        PLAIN,
        Shape { csrcs: 2, ..PLAIN },
        Shape {
            extension_words: 2,
            ..PLAIN
        },
        Shape {
            padding: 4,
            ..PLAIN
        },
    ];
    let mut index = 0;
    let mut push = |payload: Vec<u8>,
                    units: Vec<std::ops::Range<usize>>,
                    sizes: Vec<usize>,
                    marker: bool,
                    timestamp: u32,
                    packets: &mut Vec<Seed>| {
        let shape = shapes[index % shapes.len()];
        packets.push(rtp_seed(
            format!("{label}#{index}"),
            Fixed {
                sequence,
                timestamp,
                marker,
            },
            &payload,
            &units,
            &sizes,
            shape,
        ));
        index += 1;
        sequence = sequence.wrapping_add(1);
    };
    let mut at = 0;
    while at < nal_list.len() {
        let nal = &nal_list[at];
        if is_parameter(nal) {
            // Aggregate this run of parameter sets (STAP-A type 24 / AP type 48).
            let mut payload = if hevc {
                vec![48 << 1, nal[1]]
            } else {
                vec![24 | (nal[0] & 0x60)]
            };
            let mut units = Vec::new();
            let mut sizes = Vec::new();
            while at < nal_list.len() && is_parameter(&nal_list[at]) {
                let member = &nal_list[at];
                sizes.push(payload.len());
                payload.extend_from_slice(&(member.len() as u16).to_be_bytes());
                let start = payload.len();
                payload.extend_from_slice(member);
                units.push(start..payload.len());
                at += 1;
            }
            push(payload, units, sizes, false, timestamp, &mut packets);
            continue;
        }
        let marker = is_vcl(nal);
        if nal.len() > FRAGMENT {
            let body = &nal[header_len..];
            let pieces: Vec<&[u8]> = body.chunks(FRAGMENT).collect();
            for (i, piece) in pieces.iter().enumerate() {
                let first = i == 0;
                let last = i + 1 == pieces.len();
                let flags = if first { 0x80 } else { 0 } | if last { 0x40 } else { 0 };
                let mut payload = if hevc {
                    vec![
                        (nal[0] & 0x81) | (49 << 1),
                        nal[1],
                        flags | ((nal[0] >> 1) & 63),
                    ]
                } else {
                    vec![(nal[0] & 0x60) | 28, flags | (nal[0] & 31)]
                };
                let head = payload.len();
                payload.extend_from_slice(piece);
                push(
                    payload,
                    vec![0..head, head..head + piece.len()],
                    Vec::new(),
                    marker && last,
                    timestamp,
                    &mut packets,
                );
            }
        } else {
            push(
                nal.clone(),
                std::iter::once(0..header_len).collect(),
                Vec::new(),
                marker,
                timestamp,
                &mut packets,
            );
        }
        if marker {
            timestamp = timestamp.wrapping_add(3_000);
        }
        at += 1;
    }
    for packet in &mut packets {
        packet.markers = if hevc {
            vec![
                vec![48 << 1, 1],
                vec![49 << 1, 1, 0x80 | 19],
                vec![49 << 1, 1, 0x40 | 1],
                vec![0, 0],
                vec![0xFF, 0xFF],
                vec![50 << 1, 1],
            ]
        } else {
            vec![
                vec![0x18],
                vec![0x7C, 0x85],
                vec![0x7C, 0x45],
                vec![0x7C, 0xC5],
                vec![0x1A],
                vec![0x00, 0x00],
                vec![0xFF, 0xFF],
            ]
        };
    }
    packets
}

fn finish(target: &str, tally: &Tally, failures: Vec<Failure>, expected: usize) {
    report(target, tally);
    assert_eq!(tally.mutants, expected, "{target}: mutant count drifted");
    assert!(
        tally.refused > 0 && tally.ok > 0,
        "{target}: degenerate outcomes"
    );
    assert!(failures.is_empty(), "{target}: {failures:#?}");
}

#[derive(Debug, PartialEq)]
struct RtpView {
    payload: std::ops::Range<usize>,
    padding: usize,
    csrcs: Vec<u32>,
    extension: Option<(u16, usize)>,
    header: (u8, bool, u16, u32, u32),
}

fn rtp_target(bytes: &[u8], limits: PacketLimits) -> Result<Result<RtpView, String>, String> {
    let packet = match RtpPacket::parse(bytes, limits) {
        Ok(packet) => packet,
        Err(error) => return Ok(Err(format!("{error:?}"))),
    };
    let range = packet.payload_range();
    if range.start > range.end
        || range.end > bytes.len()
        || bytes.get(range.clone()) != Some(packet.payload())
        || range.end + packet.padding_len() != bytes.len()
        || packet.wire_bytes() != bytes
    {
        return Err(format!("payload view {range:?} escapes its datagram"));
    }
    let csrcs: Vec<u32> = packet.csrcs().collect();
    if csrcs.len() != usize::from(bytes[0] & 0x0F) {
        return Err("CSRC count disagrees with header".into());
    }
    let extension = packet.extension().map(|e| (e.profile, e.bytes.len()));
    if extension.is_some_and(|(_, len)| len > limits.max_extension_bytes) {
        return Err("extension over its declared limit".into());
    }
    Ok(Ok(RtpView {
        payload: range,
        padding: packet.padding_len(),
        csrcs,
        extension,
        header: (
            packet.payload_type(),
            packet.marker(),
            packet.sequence(),
            packet.timestamp(),
            packet.ssrc(),
        ),
    }))
}

#[test]
fn rtp_header_parser_survives_mutation_gauntlet() {
    const RNG_SEED: u64 = 0x0F55_0059_0000_0A01;
    let mut seeds = packetize(&nals(BASELINE), false, "baseline");
    seeds.extend(packetize(&hevc_nals(), true, "hevc"));
    let limits = PacketLimits {
        max_packet_bytes: 1_500,
        max_extension_bytes: 64,
        max_rtcp_packets: 8,
    };
    let mut rng = Rng::new(RNG_SEED);
    let mut failures = Vec::new();
    let mut tally = Tally::default();
    for index in 0..RTP_MUTANTS {
        let seed = &seeds[index % seeds.len()];
        let class = CLASSES[(index / seeds.len()) % CLASSES.len()];
        let (mutation, bytes) = mutate_stacked(seed, &seeds, class, &mut rng);
        tally.count(class);
        tally.note(&mutation);
        let run = || rtp_target(&bytes, limits);
        if let Some(outcome) = check(
            "rtp",
            &seed.name,
            RNG_SEED,
            index,
            &mutation,
            &mut failures,
            run,
        ) {
            if outcome.is_ok() {
                tally.ok += 1;
            } else {
                tally.refused += 1;
            }
        }
    }
    finish("rtp", &tally, failures, RTP_MUTANTS);
}

/// Hand-built compounds: SR+SDES(CNAME), RR+SDES+BYE(reason), SR+APP with padding.
fn rtcp_seeds() -> Vec<Seed> {
    fn packet(seed: &mut Seed, first: u8, kind: u8, body: &[u8]) {
        let start = seed.bytes.len();
        let words = (4 + body.len()) / 4 - 1;
        seed.bytes.extend_from_slice(&[first, kind]);
        seed.bytes.extend_from_slice(&(words as u16).to_be_bytes());
        seed.bytes.extend_from_slice(body);
        seed.units.push(start..seed.bytes.len());
        seed.length_fields.push(LengthField::Binary {
            offset: start + 2,
            width: 2,
        });
        seed.length_fields.push(LengthField::Binary {
            offset: start,
            width: 1,
        });
    }
    let ssrc = KEY.ssrc.to_be_bytes();
    let mut sr = ssrc.to_vec();
    sr.extend_from_slice(&[0xE5, 0, 0, 1, 0x80, 0, 0, 0]); // NTP
    sr.extend_from_slice(&90_000_u32.to_be_bytes());
    sr.extend_from_slice(&7_u32.to_be_bytes());
    sr.extend_from_slice(&1_400_u32.to_be_bytes());
    let block = [
        0x22, 0x22, 0x22, 0x22, 3, 0, 0, 5, 0, 0, 0x10, 0, 0, 0, 0, 9, 1, 2, 3, 4, 0, 0, 0, 7,
    ];
    let mut sr_block = sr.clone();
    sr_block.extend_from_slice(&block);
    let mut sdes = ssrc.to_vec();
    sdes.extend_from_slice(&[1, 6]);
    sdes.extend_from_slice(b"fss059");
    sdes.extend_from_slice(&[0, 0, 0, 0]);
    let mut rr = ssrc.to_vec();
    rr.extend_from_slice(&block);
    let mut bye = ssrc.to_vec();
    bye.extend_from_slice(&[3]);
    bye.extend_from_slice(b"end");
    let mut app = ssrc.to_vec();
    app.extend_from_slice(b"FSS5");
    app.extend_from_slice(&[1, 2, 3, 4]);
    app.extend_from_slice(&[0, 0, 0, 4]); // four bytes of padding, count in the last byte

    let mut a = Seed::new("rtcp:sr+sdes", Vec::new());
    packet(&mut a, 0x81, 200, &sr_block);
    packet(&mut a, 0x81, 202, &sdes);
    let mut b = Seed::new("rtcp:rr+sdes+bye", Vec::new());
    packet(&mut b, 0x81, 201, &rr);
    packet(&mut b, 0x81, 202, &sdes);
    packet(&mut b, 0x81, 203, &bye);
    let mut c = Seed::new("rtcp:sr+sdes+app-padded", Vec::new());
    packet(&mut c, 0x80, 200, &sr);
    packet(&mut c, 0x81, 202, &sdes);
    packet(&mut c, 0xA1, 204, &app);
    for seed in [&mut a, &mut b, &mut c] {
        seed.markers = vec![
            vec![0x81, 200, 0, 6],
            vec![0x81, 202, 0, 0],
            vec![0xA0, 204, 0, 0],
            vec![0, 0, 0, 0],
            vec![0xFF; 4],
        ];
    }
    vec![a, b, c]
}

#[derive(Debug, PartialEq)]
struct RtcpView {
    packets: Vec<RtcpItem>,
}

/// Accessor results of one accepted RTCP packet.
#[derive(Debug, PartialEq)]
struct RtcpItem {
    kind: u8,
    count: u8,
    body: usize,
    sender: Option<u32>,
    blocks: usize,
    extension: Option<usize>,
}

fn rtcp_target(bytes: &[u8], mode: RtcpMode) -> Result<Result<RtcpView, String>, String> {
    let limits = PacketLimits {
        max_packet_bytes: 1_500,
        max_extension_bytes: 64,
        max_rtcp_packets: 8,
    };
    let compound = match RtcpCompound::parse(bytes, limits, mode) {
        Ok(compound) => compound,
        Err(error) => return Ok(Err(format!("{error:?}"))),
    };
    if compound.wire_bytes() != bytes || compound.packet_count() > limits.max_rtcp_packets {
        return Err("compound view escapes its datagram or packet limit".into());
    }
    let mut total = 0;
    let mut packets = Vec::new();
    for packet in compound.packets() {
        total += packet.wire_bytes().len();
        // Every accessor on an accepted packet must stay inside its bytes.
        let body = packet.body().len();
        let sender = packet.sender_report().map(|sr| sr.ssrc);
        let blocks: Vec<_> = packet.report_blocks().collect();
        let extension = packet.report_extension().map(<[u8]>::len);
        if body + 4 > packet.wire_bytes().len() || blocks.len() > 31 {
            return Err("RTCP body/report view escapes its packet".into());
        }
        packets.push(RtcpItem {
            kind: packet.packet_type(),
            count: packet.count(),
            body,
            sender,
            blocks: blocks.len(),
            extension,
        });
    }
    if packets.len() != compound.packet_count() || total != bytes.len() {
        return Err("RTCP packet iteration does not tile the datagram".into());
    }
    Ok(Ok(RtcpView { packets }))
}

#[test]
fn rtcp_compound_parser_survives_mutation_gauntlet() {
    const RNG_SEED: u64 = 0x0F55_0059_0000_0A02;
    let seeds = rtcp_seeds();
    for seed in &seeds {
        assert!(
            matches!(rtcp_target(&seed.bytes, RtcpMode::Compound), Ok(Ok(_))),
            "{} must be a valid compound",
            seed.name
        );
    }
    let mut rng = Rng::new(RNG_SEED);
    let mut failures = Vec::new();
    let mut tally = Tally::default();
    for index in 0..RTCP_MUTANTS {
        let seed = &seeds[index % seeds.len()];
        let class = CLASSES[(index / seeds.len()) % CLASSES.len()];
        let (mutation, bytes) = mutate_stacked(seed, &seeds, class, &mut rng);
        let mode = if index % 2 == 0 {
            RtcpMode::Compound
        } else {
            RtcpMode::ReducedSize
        };
        tally.count(class);
        tally.note(&mutation);
        let run = || rtcp_target(&bytes, mode);
        if let Some(outcome) = check(
            "rtcp",
            &seed.name,
            RNG_SEED,
            index,
            &mutation,
            &mut failures,
            run,
        ) {
            if outcome.is_ok() {
                tally.ok += 1;
            } else {
                tally.refused += 1;
            }
        }
    }
    finish("rtcp", &tally, failures, RTCP_MUTANTS);
}

fn nal_seed(name: String, nal: &[u8], hevc: bool) -> Seed {
    let mut seed = Seed::new(name, nal.to_vec());
    let header = if hevc { 2 } else { 1 };
    seed.units.push(0..header.min(nal.len()));
    // Byte-granular units after the header let truncation/reorder hit every field.
    let mut at = header;
    while at < nal.len() {
        let end = (at + 4).min(nal.len());
        seed.units.push(at..end);
        at = end;
    }
    seed.markers = vec![
        vec![0, 0, 3],
        vec![0, 0, 1],
        vec![0, 0, 0],
        vec![0xFF, 0xFF],
    ];
    seed
}

#[derive(Debug, PartialEq)]
enum Screened {
    Avc(Result<String, String>),
    Hevc(Result<String, String>),
}

/// AVC SPS/PPS/slice-identity and HEVC VPS/SPS/PPS/slice-prefix screening.
#[test]
fn parameter_and_slice_prefix_parsers_survive_mutation_gauntlet() {
    const RNG_SEED: u64 = 0x0F55_0059_0000_0A03;
    let syntax = AvcSyntaxLimits {
        max_width: 256,
        max_height: 256,
        max_luma_samples: 256 * 256,
        ..AvcSyntaxLimits::default()
    };
    let hevc_limits = HevcConfigurationLimits {
        max_parameter_bytes: 4_096,
        max_width: 256,
        max_height: 256,
        max_luma_samples: 256 * 256,
    };
    let avc = nals(BASELINE);
    let high = nals(HIGH);
    let hevc = hevc_nals();
    let clean_sps = parse_sps(&avc[0], syntax);
    let clean_pps = clean_sps
        .as_ref()
        .ok()
        .and_then(|sps| parse_pps(&avc[1], sps, syntax).ok());
    let (Ok(clean_sps), Some(clean_pps)) = (clean_sps, clean_pps) else {
        unreachable_clean("baseline parameter sets");
        return;
    };
    // Seeds: AVC SPS/PPS/slices of both profiles, HEVC VPS/SPS/PPS/slices.
    let mut seeds: Vec<(u8, Seed)> = Vec::new();
    for (i, nal) in avc.iter().chain(&high).enumerate().take(12) {
        seeds.push((
            0,
            nal_seed(format!("avc-nal#{i}"), &nal[..nal.len().min(96)], false),
        ));
    }
    for (i, nal) in hevc.iter().enumerate() {
        seeds.push((
            1,
            nal_seed(format!("hevc-nal#{i}"), &nal[..nal.len().min(96)], true),
        ));
    }
    let donors: Vec<Seed> = seeds.iter().map(|(_, s)| s.clone()).collect();
    // Bare NAL payloads carry no binary length fields; STAP-A/AP sizes are covered above.
    let classes: Vec<Class> = CLASSES
        .iter()
        .copied()
        .filter(|c| *c != Class::LengthField)
        .collect();
    let mut rng = Rng::new(RNG_SEED);
    let mut failures = Vec::new();
    let mut tally = Tally::default();
    for index in 0..PARAMETER_MUTANTS {
        let (family, seed) = &seeds[index % seeds.len()];
        let class = classes[(index / seeds.len()) % classes.len()];
        let (mutation, bytes) = mutate_stacked(seed, &donors, class, &mut rng);
        tally.count(class);
        tally.note(&mutation);
        let run = || -> Result<Screened, String> {
            if *family == 0 {
                let sps = parse_sps(&bytes, syntax).map(|sps| {
                    let (w, h) = sps.coded_dimensions();
                    let (dw, dh) = sps.display_dimensions();
                    (w, h, dw, dh, sps.nal_bytes() == bytes.as_slice())
                });
                if let Ok((w, h, dw, dh, exact)) = sps
                    && (w > 256 || h > 256 || dw > w || dh > h || !exact)
                {
                    return Err(format!("SPS {w}x{h} display {dw}x{dh} escapes limits"));
                }
                let pps = parse_pps(&bytes, &clean_sps, syntax).map(|p| (p.id(), p.sps_id()));
                let slice = parse_slice_identity(&bytes, &clean_sps, &clean_pps, syntax)
                    .map(|s| (s.first_mb_in_slice(), s.frame_num(), s.prefix_bits()));
                if let Ok((_, _, bits)) = slice
                    && bits > syntax.max_slice_identity_bits
                {
                    return Err("slice identity read beyond its bit budget".into());
                }
                Ok(Screened::Avc(match (&sps, &pps, &slice) {
                    (Err(_), Err(_), Err(_)) => Err(format!("{sps:?} {pps:?} {slice:?}")),
                    _ => Ok(format!("{sps:?} {pps:?} {slice:?}")),
                }))
            } else {
                let prefix = parse_slice_prefix(&bytes, 4_096);
                // Substitute the mutant for each member of the configuration tuple.
                let position = index % 3;
                let mut tuple = [hevc[0].as_slice(), hevc[1].as_slice(), hevc[2].as_slice()];
                tuple[position] = &bytes;
                let config = HevcConfiguration::parse(tuple[0], tuple[1], tuple[2], hevc_limits);
                if let Ok(config) = &config {
                    let (w, h) = config.coded_dimensions();
                    let (dw, dh) = config.display_dimensions();
                    if w > 256
                        || h > 256
                        || dw > w
                        || dh > h
                        || config.vps() != tuple[0]
                        || config.sps() != tuple[1]
                        || config.pps() != tuple[2]
                    {
                        return Err(format!("HEVC configuration {w}x{h} escapes limits"));
                    }
                }
                Ok(Screened::Hevc(match (&prefix, &config) {
                    (Err(_), Err(_)) => Err(format!("{prefix:?} {config:?}")),
                    _ => Ok(format!(
                        "{prefix:?} {:?}",
                        config.as_ref().map(|c| c.coded_dimensions())
                    )),
                }))
            }
        };
        if let Some(outcome) = check(
            "parameters",
            &seed.name,
            RNG_SEED,
            index,
            &mutation,
            &mut failures,
            run,
        ) {
            match outcome {
                Screened::Avc(Ok(_)) | Screened::Hevc(Ok(_)) => tally.ok += 1,
                _ => tally.refused += 1,
            }
        }
    }
    finish("parameters", &tally, failures, PARAMETER_MUTANTS);
}

fn unreachable_clean(what: &str) {
    assert!(what.is_empty(), "clean fixture refused: {what}");
}

/// Every published NAL is exactly the datagram bytes its spans name, in order.
fn check_avc_provenance(
    nal: &[u8],
    sources: &[NalSourceSpan],
    datagrams: &BTreeMap<u64, Vec<u8>>,
) -> Result<(), String> {
    let mut next = 0;
    for span in sources {
        let wire = datagrams
            .get(&span.sequence)
            .ok_or("span names a datagram that was never delivered")?;
        if span.fragment_header_range.is_some() && next == 0 {
            // FU start: output byte zero is synthesized from indicator + header.
            let header = span
                .fragment_header_range
                .clone()
                .and_then(|r| wire.get(r))
                .ok_or("FU header range escapes datagram")?;
            if header.len() != 2 || nal.first() != Some(&((header[0] & 0xE0) | (header[1] & 31))) {
                return Err("FU NAL header not synthesized from its source".into());
            }
            next = 1;
        }
        if span.nal_range.start != next
            || nal.get(span.nal_range.clone()) != wire.get(span.wire_range.clone())
        {
            return Err(format!(
                "NAL bytes {:?} not equal to their wire span",
                span.nal_range
            ));
        }
        next = span.nal_range.end;
    }
    if next != nal.len() {
        return Err("source spans do not cover the NAL".into());
    }
    Ok(())
}

#[derive(Debug, PartialEq)]
enum AvcEvent {
    Admit(Result<AvcReceiveAdmission, AvcReceiveError>),
    Poll(Result<AvcReceivePoll, AvcReceiveError>),
}

fn avc_limits() -> AvcReceiveLimits {
    AvcReceiveLimits {
        reorder: ReorderLimits {
            packet: PacketLimits {
                max_packet_bytes: 1_500,
                max_extension_bytes: 64,
                max_rtcp_packets: 8,
            },
            max_packets: 16,
            max_bytes: 16 * 1_500,
            max_delay_ns: 5_000,
        },
        reconstruction: H264Limits {
            max_nal_bytes: 32 * 1_024,
            max_packet_nals: 8,
            max_fragment_packets: 64,
            max_pending_age_ns: 50_000,
        },
        syntax: AvcSyntaxLimits::default(),
        assembly: AvcAssemblyLimits {
            max_nals: 32,
            max_bytes: 64 * 1_024,
            max_age_ns: 50_000,
        },
    }
}

fn check_group(
    group: &AvcPictureGroup,
    datagrams: &BTreeMap<u64, Vec<u8>>,
    limits: AvcReceiveLimits,
) -> Result<(), String> {
    if group.byte_len() > limits.assembly.max_bytes || group.nals().len() > limits.assembly.max_nals
    {
        return Err("picture group exceeds assembly limits".into());
    }
    let mut total = 0;
    for nal in group.nals() {
        total += nal.bytes().len();
        if nal.bytes().len() > limits.reconstruction.max_nal_bytes {
            return Err("NAL exceeds reconstruction limit".into());
        }
        check_avc_provenance(nal.bytes(), nal.sources(), datagrams)?;
    }
    if total != group.byte_len() {
        return Err("picture group byte accounting disagrees with its NALs".into());
    }
    Ok(())
}

/// Returns (event log, pictures) for one datagram sequence.
fn drive_avc(
    datagrams_in: &[Vec<u8>],
    parameters: &(fss_packet::avc::AvcSps, fss_packet::avc::AvcPps),
) -> Result<(Vec<AvcEvent>, usize), String> {
    let limits = avc_limits();
    let mut receiver = AvcReceiver::new(
        KEY,
        PT,
        H264Mode::NonInterleaved,
        limits,
        parameters.clone(),
    )
    .map_err(|e| format!("configuration refused: {e:?}"))?;
    let bytes_in: usize = datagrams_in.iter().map(Vec::len).sum();
    let poll_bound = 64 * datagrams_in.len() + bytes_in + 64;
    let mut polls = 0;
    let mut log = Vec::new();
    let mut delivered: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut pictures = 0;
    let mut now = 0_u64;
    let on_poll = |event: &AvcReceivePoll,
                   delivered: &mut BTreeMap<u64, Vec<u8>>,
                   pictures: &mut usize|
     -> Result<(), String> {
        let mut groups: Vec<&AvcPictureGroup> = Vec::new();
        match event {
            AvcReceivePoll::Source { source, .. } | AvcReceivePoll::CodecRefused { source, .. } => {
                delivered.insert(source.sequence(), source.bytes().to_vec());
            }
            AvcReceivePoll::Picture(group) => groups.push(group),
            AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(output)) => {
                groups.extend(output.picture.as_ref());
            }
            AvcReceivePoll::Ended {
                tail: Some(tail), ..
            } => groups.extend(tail.picture.as_ref()),
            _ => {}
        }
        for group in groups {
            check_group(group, delivered, limits)?;
            *pictures += 1;
        }
        Ok(())
    };
    let mut step = |receiver: &mut AvcReceiver,
                    now: &mut u64,
                    log: &mut Vec<AvcEvent>,
                    finished: bool|
     -> Result<bool, String> {
        polls += 1;
        if polls > poll_bound {
            return Err(format!(
                "poll loop exceeded its bound of {poll_bound} (hang)"
            ));
        }
        let polled = receiver.poll(*now);
        if let Ok(event) = &polled {
            on_poll(event, &mut delivered, &mut pictures)?;
        }
        let more = match &polled {
            Ok(AvcReceivePoll::Pending { wake_at_ns }) => {
                if finished {
                    // After finish, time advances to each declared wake; a pending
                    // receiver with no wake would never end and trips the bound.
                    if let Some(at) = wake_at_ns {
                        *now = (*at).max(*now);
                    }
                    true
                } else {
                    false
                }
            }
            Ok(AvcReceivePoll::Ended { .. }) => false,
            Err(_) => false,
            Ok(_) => true,
        };
        log.push(AvcEvent::Poll(polled));
        if receiver.queued_packets() > limits.reorder.max_packets
            || receiver.retained_nal_bytes()
                > limits.reconstruction.max_nal_bytes
                    + limits.assembly.max_bytes
                    + limits.reorder.max_bytes
        {
            return Err("receiver retained beyond its declared limits".into());
        }
        Ok(more)
    };
    for datagram in datagrams_in {
        now += 1_000;
        log.push(AvcEvent::Admit(receiver.ingest(KEY, datagram, now)));
        while step(&mut receiver, &mut now, &mut log, false)? {}
    }
    receiver.finish();
    while step(&mut receiver, &mut now, &mut log, true)? {}
    Ok((log, pictures))
}

#[test]
fn avc_rtp_receiver_survives_mutation_gauntlet() {
    const RNG_SEED: u64 = 0x0F55_0059_0000_0A04;
    let syntax = AvcSyntaxLimits::default();
    let mut streams = Vec::new();
    for (label, fixture) in [("baseline", BASELINE), ("high_cropped", HIGH)] {
        let list = nals(fixture);
        let sps = parse_sps(&list[0], syntax);
        let pps = sps
            .as_ref()
            .ok()
            .and_then(|s| parse_pps(&list[1], s, syntax).ok());
        let (Ok(sps), Some(pps)) = (sps, pps) else {
            unreachable_clean(label);
            return;
        };
        let packets = packetize(&list, false, label);
        let clean: Vec<Vec<u8>> = packets.iter().map(|p| p.bytes.clone()).collect();
        let (_, pictures) = drive_avc(&clean, &(sps.clone(), pps.clone())).unwrap_or_default();
        let vcl = list.iter().filter(|n| matches!(n[0] & 31, 1 | 5)).count();
        assert_eq!(pictures, vcl, "{label}: clean stream yields every picture");
        streams.push((label, packets, (sps, pps)));
    }
    let mut rng = Rng::new(RNG_SEED);
    let mut failures = Vec::new();
    let mut tally = Tally::default();
    for index in 0..AVC_STREAM_MUTANTS {
        let (label, packets, parameters) = &streams[index % streams.len()];
        let class = CLASSES[(index / streams.len()) % CLASSES.len()];
        let (packet, mutation, datagrams) = mutate_sequence(packets, class, &mut rng);
        tally.count(class);
        tally.note(&mutation);
        let run = || drive_avc(&datagrams, parameters).map(|(log, _)| log);
        let described = (packet, &mutation);
        if let Some(log) = check(
            "avc-rtp",
            label,
            RNG_SEED,
            index,
            &described,
            &mut failures,
            run,
        ) {
            let refused = log.iter().any(|event| match event {
                AvcEvent::Admit(Err(_)) | AvcEvent::Poll(Err(_)) => true,
                AvcEvent::Poll(Ok(poll)) => matches!(
                    poll,
                    AvcReceivePoll::CodecRefused { .. }
                        | AvcReceivePoll::Gap { .. }
                        | AvcReceivePoll::FragmentRetired { .. }
                        | AvcReceivePoll::PictureRetired(_)
                        | AvcReceivePoll::Assembly(AvcAssemblyStep::Refused(_))
                ),
                AvcEvent::Admit(Ok(_)) => false,
            });
            if refused {
                tally.refused += 1;
            } else {
                tally.ok += 1;
            }
        }
    }
    finish("avc-rtp", &tally, failures, AVC_STREAM_MUTANTS);
}

fn check_hevc_group(
    group: &HevcPictureGroup,
    datagrams: &BTreeMap<u64, Vec<u8>>,
    limits: HevcAssemblyLimits,
) -> Result<(), String> {
    if group.byte_len() > limits.max_bytes
        || group.nals().len() > limits.max_nals
        || group.source_span_count() > limits.max_source_spans
    {
        return Err("HEVC picture group exceeds assembly limits".into());
    }
    for nal in group.nals() {
        let bytes = nal.bytes();
        let mut next = 0;
        for span in nal.sources() {
            let wire = datagrams
                .get(&span.sequence)
                .ok_or("span names an undelivered datagram")?;
            if let Some(range) = span.fragment_header_range.clone()
                && next == 0
            {
                let header = wire.get(range).ok_or("FU header escapes datagram")?;
                let [indicator, layer, fu] = header else {
                    return Err("HEVC FU header range is not three bytes".into());
                };
                let synthesized = [(indicator & 0x81) | ((fu & 63) << 1), *layer];
                if bytes.get(..2) != Some(&synthesized[..]) {
                    return Err("HEVC FU header not synthesized from its source".into());
                }
                next = 2;
            }
            if span.nal_range.start != next
                || bytes.get(span.nal_range.clone()) != wire.get(span.wire_range.clone())
            {
                return Err("HEVC NAL bytes not equal to their wire span".into());
            }
            next = span.nal_range.end;
        }
        if next != bytes.len() {
            return Err("HEVC source spans do not cover the NAL".into());
        }
    }
    Ok(())
}

fn hevc_assembly_limits() -> HevcAssemblyLimits {
    HevcAssemblyLimits {
        max_nals: 32,
        max_bytes: 64 * 1_024,
        max_source_spans: 256,
        max_age_ns: 50_000,
    }
}

/// H265Receiver (reorder + RFC 7798) feeding the HEVC picture assembler.
fn drive_hevc(datagrams_in: &[Vec<u8>]) -> Result<(Vec<String>, usize), String> {
    let reorder = ReorderLimits {
        packet: PacketLimits {
            max_packet_bytes: 1_500,
            max_extension_bytes: 64,
            max_rtcp_packets: 8,
        },
        max_packets: 16,
        max_bytes: 16 * 1_500,
        max_delay_ns: 5_000,
    };
    let h265 = H265Limits {
        max_nal_bytes: 32 * 1_024,
        max_packet_nals: 8,
        max_fragment_packets: 64,
        max_pending_age_ns: 50_000,
    };
    let assembly = hevc_assembly_limits();
    let mut receiver = H265Receiver::new(KEY, PT, 0, reorder, h265)
        .map_err(|e| format!("configuration refused: {e:?}"))?;
    let mut assembler =
        HevcAssembler::new(KEY, assembly).map_err(|e| format!("assembler refused: {e:?}"))?;
    let bytes_in: usize = datagrams_in.iter().map(Vec::len).sum();
    let poll_bound = 64 * datagrams_in.len() + bytes_in + 64;
    let mut polls = 0;
    let mut log = Vec::new();
    let mut delivered = BTreeMap::new();
    let mut pictures = 0;
    let mut now = 0_u64;
    let mut step = |receiver: &mut H265Receiver,
                    assembler: &mut HevcAssembler,
                    now: &mut u64,
                    log: &mut Vec<String>,
                    finished: bool|
     -> Result<bool, String> {
        polls += 1;
        if polls > poll_bound {
            return Err(format!(
                "poll loop exceeded its bound of {poll_bound} (hang)"
            ));
        }
        let polled = receiver.poll(*now);
        let more = match &polled {
            Ok(H265ReceivePoll::Pending { wake_at_ns }) => {
                if finished {
                    if let Some(at) = wake_at_ns {
                        *now = (*at).max(*now);
                    }
                    true
                } else {
                    false
                }
            }
            Ok(H265ReceivePoll::Ended { .. }) | Err(_) => false,
            Ok(_) => true,
        };
        let nal_list = match polled {
            Ok(H265ReceivePoll::Packet {
                source,
                reconstruction,
            }) => {
                delivered.insert(source.sequence(), source.bytes().to_vec());
                match reconstruction {
                    Ok(output) => {
                        log.push(format!("packet {:?} {}", output.status, output.nals.len()));
                        if output
                            .nals
                            .iter()
                            .any(|n| n.bytes().len() > h265.max_nal_bytes)
                        {
                            return Err("HEVC NAL exceeds reconstruction limit".into());
                        }
                        output.nals
                    }
                    Err(error) => {
                        log.push(format!("Err {error:?}"));
                        Vec::new()
                    }
                }
            }
            other => {
                log.push(format!("{other:?}"));
                Vec::new()
            }
        };
        for nal in nal_list {
            match assembler.push(nal, *now) {
                HevcAssemblyStep::Accepted(output) => {
                    if let Some(group) = &output.picture {
                        check_hevc_group(group, &delivered, assembly)?;
                        pictures += 1;
                    }
                    log.push(format!("accepted {:?}", output.retired));
                }
                HevcAssemblyStep::Refused(refusal) => log.push(format!("Refused {refusal:?}")),
            }
            if assembler.pending_bytes() > assembly.max_bytes {
                return Err("assembler retained beyond its limit".into());
            }
        }
        if receiver.queued_packets() > reorder.max_packets
            || receiver.pending_nal_bytes() > h265.max_nal_bytes
        {
            return Err("receiver retained beyond its declared limits".into());
        }
        Ok(more)
    };
    for datagram in datagrams_in {
        now += 1_000;
        log.push(format!("{:?}", receiver.ingest(KEY, datagram, now)));
        while step(&mut receiver, &mut assembler, &mut now, &mut log, false)? {}
    }
    receiver.finish();
    while step(&mut receiver, &mut assembler, &mut now, &mut log, true)? {}
    match assembler.finish(now) {
        Ok(output) => {
            if let Some(group) = &output.picture {
                check_hevc_group(group, &delivered, assembly)?;
                pictures += 1;
            }
            log.push(format!("finish {:?}", output.retired));
        }
        Err(error) => log.push(format!("finish Err {error:?}")),
    }
    Ok((log, pictures))
}

#[test]
fn hevc_rtp_receiver_survives_mutation_gauntlet() {
    const RNG_SEED: u64 = 0x0F55_0059_0000_0A05;
    let list = hevc_nals();
    let packets = packetize(&list, true, "remux_main8");
    let clean: Vec<Vec<u8>> = packets.iter().map(|p| p.bytes.clone()).collect();
    let (_, pictures) = drive_hevc(&clean).unwrap_or_default();
    let vcl = list.iter().filter(|n| (n[0] >> 1) & 63 < 32).count();
    assert!(
        pictures > 0 && pictures <= vcl,
        "clean HEVC stream yields pictures"
    );
    // Second seed: the same NALs with the parameter sets repeated before the tail.
    let mut repeated = list.clone();
    repeated.extend(list.iter().take(3).cloned());
    repeated.extend(list.iter().skip(3).cloned());
    let streams = [packets, packetize(&repeated, true, "remux_main8x2")];
    let mut rng = Rng::new(RNG_SEED);
    let mut failures = Vec::new();
    let mut tally = Tally::default();
    for index in 0..HEVC_STREAM_MUTANTS {
        let packets = &streams[index % streams.len()];
        let class = CLASSES[(index / streams.len()) % CLASSES.len()];
        let (packet, mutation, datagrams) = mutate_sequence(packets, class, &mut rng);
        tally.count(class);
        tally.note(&mutation);
        let run = || drive_hevc(&datagrams).map(|(log, _)| log);
        let described = (packet, &mutation);
        if let Some(log) = check(
            "hevc-rtp",
            "remux_main8",
            RNG_SEED,
            index,
            &described,
            &mut failures,
            run,
        ) {
            if log
                .iter()
                .any(|l| l.contains("Err") || l.contains("Refus") || l.contains("Gap"))
            {
                tally.refused += 1;
            } else {
                tally.ok += 1;
            }
        }
    }
    finish("hevc-rtp", &tally, failures, HEVC_STREAM_MUTANTS);
}

/// The harness itself must turn a panic, a violated invariant and a nondeterministic
/// outcome into recorded failures; otherwise a green gauntlet would prove nothing.
#[test]
fn gauntlet_harness_reports_panics_violations_and_nondeterminism() {
    let mut failures = Vec::new();
    let empty: Vec<u8> = Vec::new();
    let index = std::hint::black_box(3_usize);
    let panicked = check("self-test", "panic", 1, 0, &"index", &mut failures, || {
        Ok::<u8, String>(empty[index])
    });
    let violated = check(
        "self-test",
        "invariant",
        1,
        1,
        &"err",
        &mut failures,
        || Err::<u8, String>("violated".into()),
    );
    let mut calls = 0_u32;
    let drifting = check(
        "self-test",
        "nondeterminism",
        1,
        2,
        &"drift",
        &mut failures,
        || {
            calls += 1;
            Ok::<u32, String>(calls)
        },
    );
    let stable = check("self-test", "stable", 1, 3, &"ok", &mut failures, || {
        Ok::<u8, String>(7)
    });
    assert!(panicked.is_none() && violated.is_none() && drifting.is_none());
    assert_eq!(stable, Some(7));
    let problems: Vec<&str> = failures.iter().map(|f| f.problem.as_str()).collect();
    assert_eq!(failures.len(), 3, "{problems:?}");
    assert!(problems[0].starts_with("panic:"));
    assert_eq!(problems[1], "violated");
    assert!(problems[2].starts_with("nondeterministic:"));
    // Same seed, same mutant: the engine itself is deterministic.
    let seed = Seed::new("self-test", (0_u8..64).collect());
    let one = mutate_stacked(&seed, &[], Class::BitFlip, &mut Rng::new(59));
    let two = mutate_stacked(&seed, &[], Class::BitFlip, &mut Rng::new(59));
    assert_eq!(one, two);
}
