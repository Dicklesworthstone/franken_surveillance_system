#![forbid(unsafe_code)]
//! Real depacketizer -> picture assembler -> native HEVC MP4 writer contracts.

use fss_container::{HevcMuxer, Mp4Error as E, Mp4Limits, TimedHevcPicture};
use fss_packet::hevc::{
    HevcAssembler, HevcAssemblyLimits, HevcAssemblyStep, HevcBoundary, HevcConfiguration,
    HevcConfigurationLimits, HevcPictureGroup,
};
use fss_packet::{H265Depacketizer, H265Limits, PacketLimits, RtpPacket, StreamKey};
type TestResult = Result<(), Box<dyn std::error::Error>>;
const KEY: StreamKey = StreamKey {
    ingress: 1,
    generation: 1,
    ssrc: 7,
};
const FIXTURE: &str = include_str!("../../../tests/fixtures/media/hevc/remux_main8.nals.hex");
const INIT: &str = include_str!("../../../tests/fixtures/media/hevc/remux_main8.init.hex");
fn hex(s: &str) -> Vec<u8> {
    let compact: Vec<_> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    compact
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| {
            let digit = |b| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => 0,
            };
            digit(p[0]) * 16 + digit(p[1])
        })
        .collect()
}
fn fixture() -> Vec<Vec<u8>> {
    FIXTURE.lines().filter(|l| !l.is_empty()).map(hex).collect()
}
fn config() -> Result<HevcConfiguration, Box<dyn std::error::Error>> {
    let n = fixture();
    Ok(HevcConfiguration::parse(
        &n[0],
        &n[1],
        &n[2],
        HevcConfigurationLimits::default(),
    )?)
}
fn mux(limits: Mp4Limits) -> Result<HevcMuxer, Box<dyn std::error::Error>> {
    Ok(HevcMuxer::new(KEY, config()?, 90_000, limits)?)
}
fn wire(seq: u16, timestamp: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80, 96 | 128];
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&KEY.ssrc.to_be_bytes());
    out.extend_from_slice(payload);
    out
}
type AssembleResult = Result<(Vec<HevcPictureGroup>, Vec<Vec<u8>>), Box<dyn std::error::Error>>;
fn assemble(payloads: &[(u32, Vec<u8>)], eof: bool, discontinuous: bool) -> AssembleResult {
    let mut dep = H265Depacketizer::new(KEY, 96, 0, H265Limits::default())?;
    let mut a = HevcAssembler::new(KEY, HevcAssemblyLimits::default())?;
    if discontinuous {
        let _ = a.discard_gap();
    }
    let mut groups = Vec::new();
    let mut sources = Vec::new();
    for (i, (timestamp, payload)) in payloads.iter().enumerate() {
        let mut raw = wire(i as u16 + 1, *timestamp, payload);
        // A nonfinal FU packet cannot carry an RTP marker.
        if payload[0] >> 1 & 63 == 49 && payload[2] & 0x40 == 0 {
            raw[1] &= 127;
        }
        let output = dep.push(
            KEY,
            i as u64 + 1,
            RtpPacket::parse(&raw, PacketLimits::default())?,
            i as u64,
        )?;
        for nal in output.nals {
            match a.push(nal, i as u64) {
                HevcAssemblyStep::Accepted(output) => {
                    assert!(output.retired.is_none());
                    if let Some(p) = output.picture {
                        groups.push(p);
                    }
                }
                HevcAssemblyStep::Refused(refused) => return Err(refused.reason.into()),
            }
        }
        sources.push(raw);
    }
    if eof {
        let picture = a.finish(payloads.len() as u64)?.picture;
        if let Some(tail) = picture {
            groups.push(tail);
        }
    }
    Ok((groups, sources))
}
fn pictures() -> AssembleResult {
    let timestamps = [0, 0, 0, 0, 18_000, 36_000, 36_000, 36_000, 36_000, 54_000];
    let mut payloads: Vec<_> = timestamps.into_iter().zip(fixture()).collect();
    payloads.push((54_000, vec![0x48, 1, 0x80])); // explicit synthetic EOS closes the final group.
    assemble(&payloads, false, false)
}
fn timed(groups: &[HevcPictureGroup], base: u64) -> Vec<TimedHevcPicture<'_>> {
    groups
        .iter()
        .enumerate()
        .map(|(i, picture)| TimedHevcPicture {
            picture,
            decode_time: base + i as u64 * 18_000,
            duration: 18_000,
            composition_offset: 0,
        })
        .collect()
}
fn tag(bytes: &[u8], name: &[u8; 4]) -> Result<usize, Box<dyn std::error::Error>> {
    bytes
        .windows(4)
        .position(|s| s == name)
        .ok_or_else(|| "required box missing".into())
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32, Box<dyn std::error::Error>> {
    Ok(u32::from_be_bytes(
        bytes.get(at..at + 4).ok_or("four bytes")?.try_into()?,
    ))
}

#[test]
fn initialization_matches_independent_layout_and_exact_parameter_locations() -> TestResult {
    let m = mux(Mp4Limits::default())?;
    let bytes = m.initialization().bytes();
    assert_eq!(bytes, hex(INIT));
    assert_eq!(&bytes[4..8], b"ftyp");
    let hvcc = tag(bytes, b"hvcC")? + 4;
    assert_eq!(bytes[hvcc], 1);
    assert_eq!(
        &bytes[hvcc + 1..hvcc + 13],
        m.configuration().profile_tier_level()
    );
    assert_eq!(
        &bytes[hvcc + 13..hvcc + 23],
        &[0xf0, 0, 0xfc, 0xfd, 0xf8, 0xf8, 0, 0, 0x0f, 3]
    );
    for (index, original) in fixture()[..3].iter().enumerate() {
        let range = m.initialization().parameter_ranges()[index].clone();
        assert_eq!(&bytes[range.clone()], original);
        assert_eq!(bytes[range.start - 5], 32 + index as u8); // array_completeness stays zero.
        assert_eq!(&bytes[range.start - 4..range.start - 2], &[0, 1]);
    }
    Ok(())
}

#[test]
fn real_four_picture_fixture_preserves_every_nal_and_source_copy_span() -> TestResult {
    let (groups, original) = pictures()?;
    assert_eq!(groups.len(), 4);
    let mut m = mux(Mp4Limits::default())?;
    let f = m.fragment(&timed(&groups, 0))?;
    assert_eq!(f.key(), KEY);
    assert_eq!(f.sequence(), 1);
    assert_eq!(f.samples().len(), 4);
    assert_eq!(f.mappings().len(), 11); // ten source NALs plus the explicitly supplied EOS.
    assert_eq!(f.timeline_gap(), None);
    assert_eq!(m.next_sequence(), Some(2));
    let trun = tag(f.bytes(), b"trun")?;
    assert_eq!(u32_at(f.bytes(), trun + 4)?, 0x01000f01);
    assert_eq!(u32_at(f.bytes(), trun + 8)?, 4);
    assert_eq!(
        u32_at(f.bytes(), trun + 12)? as usize,
        f.samples()[0].range.start
    );
    for (i, sample) in f.samples().iter().enumerate() {
        assert_eq!(sample.decode_time, i as u64 * 18_000);
        assert_eq!(sample.presentation_time, sample.decode_time);
        assert_eq!(sample.idr, i % 2 == 0);
        assert_ne!(sample.boundary, HevcBoundary::EndOfInputUnverified);
        assert_eq!(
            u32_at(f.bytes(), trun + 20 + i * 16)? as usize,
            sample.range.len()
        );
        for mapping in &f.mappings()[sample.mappings.clone()] {
            let nal = &groups[i].nals()[mapping.nal];
            assert_eq!(&f.bytes()[mapping.range.clone()], nal.bytes());
            assert_eq!(
                u32_at(f.bytes(), mapping.range.start - 4)? as usize,
                nal.bytes().len()
            );
            assert_eq!(mapping.sources, nal.sources());
            for span in &mapping.sources {
                assert_eq!(
                    &original[span.sequence as usize - 1][span.wire_range.clone()],
                    &f.bytes()[mapping.range.start + span.nal_range.start
                        ..mapping.range.start + span.nal_range.end]
                );
            }
        }
    }
    assert!(
        !format!("{f:?}").contains(
            &fixture()[3]
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect::<String>()
        )
    );
    Ok(())
}

#[test]
fn signed_composition_offsets_and_64_bit_decode_base_are_written_exactly() -> TestResult {
    let (groups, _) = pictures()?;
    let base = u64::from(u32::MAX) + 17;
    let mut t = timed(&groups[..2], base);
    t[0].composition_offset = 9_000;
    t[1].composition_offset = -9_000;
    let f = mux(Mp4Limits::default())?.fragment(&t)?;
    let tfdt = tag(f.bytes(), b"tfdt")?;
    assert_eq!(u32_at(f.bytes(), tfdt + 4)?, 0x01000000);
    assert_eq!(
        u64::from_be_bytes(f.bytes()[tfdt + 8..tfdt + 16].try_into()?),
        base
    );
    let trun = tag(f.bytes(), b"trun")?;
    assert_eq!(u32_at(f.bytes(), trun + 28)?, 9_000);
    assert_eq!(u32_at(f.bytes(), trun + 44)? as i32, -9_000);
    assert_eq!(f.samples()[0].presentation_time, base + 9_000);
    assert_eq!(f.samples()[1].presentation_time, base + 9_000);
    Ok(())
}

#[test]
fn gaps_are_receipted_without_padding_or_consuming_failed_retries() -> TestResult {
    let (groups, _) = pictures()?;
    let mut m = mux(Mp4Limits::default())?;
    m.fragment(&timed(&groups[..2], 0))?;
    let repeated = timed(&groups[..2], 36_000);
    assert_eq!(m.fragment(&repeated).err(), Some(E::SourceOrder));
    assert_eq!(m.next_sequence(), Some(2));
    let backwards = timed(&groups[2..], 35_999);
    assert_eq!(m.fragment(&backwards).err(), Some(E::Timeline));
    let f = m.fragment(&timed(&groups[2..], 40_000))?;
    assert_eq!(f.sequence(), 2);
    assert_eq!(f.timeline_gap(), Some(36_000..40_000));
    assert_eq!(f.samples().len(), 2);
    Ok(())
}

#[test]
fn zero_discontinuous_overflowing_and_negative_presentation_timelines_are_retry_safe() -> TestResult
{
    let (groups, _) = pictures()?;
    let mut m = mux(Mp4Limits::default())?;
    for case in 0..5 {
        let mut t = timed(&groups[..2], 0);
        match case {
            0 => t[0].duration = 0,
            1 => t[1].decode_time += 1,
            2 => t[0].composition_offset = -1,
            3 => {
                t.truncate(1);
                t[0].decode_time = u64::MAX - 1;
            }
            _ => {
                t.truncate(1);
                t[0].decode_time = u64::MAX - 20_000;
                t[0].composition_offset = i32::MAX;
            }
        }
        assert_eq!(m.fragment(&t).err(), Some(E::Timeline));
        assert_eq!(m.next_sequence(), Some(1));
    }
    assert_eq!(m.fragment(&timed(&groups, 0))?.sequence(), 1);
    Ok(())
}

#[test]
fn predicted_cra_and_leading_pictures_are_not_mislabeled_idr_fragments() -> TestResult {
    let (groups, _) = pictures()?;
    assert_eq!(
        mux(Mp4Limits::default())?
            .fragment(&timed(&groups[1..2], 0))
            .err(),
        Some(E::RandomAccessRequired)
    );
    for kind in [6, 8, 16, 21] {
        let payloads = [
            (0, vec![0x28, 1, 0xa0]),
            (
                18_000,
                vec![kind << 1, 1, if kind >= 16 { 0xa0 } else { 0xc0 }],
            ),
            (18_000, vec![0x48, 1, 0x80]),
        ];
        let (pictures, _) = assemble(&payloads, false, false)?;
        assert_eq!(pictures.len(), 2);
        assert_eq!(
            mux(Mp4Limits::default())?
                .fragment(&timed(&pictures, 0))
                .err(),
            Some(E::UnsupportedFormat)
        );
    }
    Ok(())
}

#[test]
fn eof_unverified_and_known_discontinuities_are_not_exported_as_verified_media() -> TestResult {
    let payloads = [(0, vec![0x28, 1, 0xa0])];
    let (tail, _) = assemble(&payloads, true, false)?;
    assert_eq!(
        mux(Mp4Limits::default())?.fragment(&timed(&tail, 0)).err(),
        Some(E::UnverifiedPicture)
    );
    let (discontinuous, _) = assemble(
        &[(0, vec![0x28, 1, 0xa0]), (0, vec![0x48, 1, 0x80])],
        false,
        true,
    )?;
    assert_eq!(
        mux(Mp4Limits::default())?
            .fragment(&timed(&discontinuous, 0))
            .err(),
        Some(E::Discontinuity)
    );
    Ok(())
}

#[test]
fn changed_inband_parameters_wrong_pps_and_wrong_epoch_fail_before_cursor_advance() -> TestResult {
    let mut raw = fixture();
    raw[2].push(0x80);
    let payloads = [
        (0, raw[0].clone()),
        (0, raw[1].clone()),
        (0, raw[2].clone()),
        (0, vec![0x28, 1, 0xa0]),
        (0, vec![0x48, 1, 0x80]),
    ];
    let (changed, _) = assemble(&payloads, false, false)?;
    let (wrong_pps, _) = assemble(
        &[(0, vec![0x28, 1, 0x90]), (0, vec![0x48, 1, 0x80])],
        false,
        false,
    )?;
    let mut m = mux(Mp4Limits::default())?;
    for p in [&changed, &wrong_pps] {
        assert_eq!(m.fragment(&timed(p, 0)).err(), Some(E::ParameterSet));
        assert_eq!(m.next_sequence(), Some(1));
    }
    let (groups, _) = pictures()?;
    let mut foreign = HevcMuxer::new(
        StreamKey {
            generation: 2,
            ..KEY
        },
        config()?,
        90_000,
        Mp4Limits::default(),
    )?;
    assert_eq!(
        foreign.fragment(&timed(&groups, 0)).err(),
        Some(E::StreamMismatch)
    );
    assert_eq!(m.fragment(&timed(&groups, 0))?.sequence(), 1);
    Ok(())
}

#[test]
fn packet_aggregation_and_fragmented_nals_retain_exact_hevc_header_provenance() -> TestResult {
    let raw = fixture();
    let mut ap = vec![0x60, 1];
    for nal in &raw[..3] {
        ap.extend_from_slice(&(nal.len() as u16).to_be_bytes());
        ap.extend_from_slice(nal);
    }
    let payloads = [
        (0, ap),
        (0, vec![0x62, 1, 0x94, 0xa0, 1]),
        (0, vec![0x62, 1, 0x54, 2]),
        (0, vec![0x48, 1, 0x80]),
    ];
    let (groups, originals) = assemble(&payloads, false, false)?;
    let f = mux(Mp4Limits::default())?.fragment(&timed(&groups, 0))?;
    let mapping = &f.mappings()[3];
    assert_eq!(&f.bytes()[mapping.range.clone()], &[0x28, 1, 0xa0, 1, 2]);
    assert_eq!(mapping.sources.len(), 2);
    for span in &mapping.sources {
        assert_eq!(span.fragment_header_range, Some(12..15));
        assert_eq!(
            &originals[span.sequence as usize - 1][span.wire_range.clone()],
            &f.bytes()[mapping.range.start + span.nal_range.start
                ..mapping.range.start + span.nal_range.end]
        );
    }
    assert_eq!(
        f.mappings()[0].sources[0].sequence,
        f.mappings()[2].sources[0].sequence
    );
    Ok(())
}

#[test]
fn output_sample_nal_span_and_initialization_limits_are_independent() -> TestResult {
    let (groups, _) = pictures()?;
    let t = timed(&groups, 0);
    let size = mux(Mp4Limits::default())?.fragment(&t)?.bytes().len();
    for limits in [
        Mp4Limits {
            max_samples: 3,
            ..Mp4Limits::default()
        },
        Mp4Limits {
            max_nals: 10,
            ..Mp4Limits::default()
        },
        Mp4Limits {
            max_source_spans: 10,
            ..Mp4Limits::default()
        },
        Mp4Limits {
            max_fragment_bytes: size - 1,
            ..Mp4Limits::default()
        },
    ] {
        let mut m = mux(limits)?;
        assert_eq!(m.fragment(&t).err(), Some(E::Limit));
        assert_eq!(m.next_sequence(), Some(1));
    }
    let init_limit = Mp4Limits {
        max_initialization_bytes: 8,
        ..Mp4Limits::default()
    };
    assert!(HevcMuxer::new(KEY, config()?, 90_000, init_limit).is_err());
    assert_eq!(
        HevcMuxer::new(KEY, config()?, 0, Mp4Limits::default()).err(),
        Some(E::Configuration)
    );
    Ok(())
}

#[test]
fn temporal_layers_are_bound_to_configuration_and_replay_is_deterministic() -> TestResult {
    let (too_high, _) = assemble(
        &[(0, vec![0x28, 2, 0xa0]), (0, vec![0x48, 1, 0x80])],
        false,
        false,
    )?;
    assert_eq!(
        mux(Mp4Limits::default())?
            .fragment(&timed(&too_high, 0))
            .err(),
        Some(E::UnsupportedFormat)
    );
    let (groups, _) = pictures()?;
    let mut a = mux(Mp4Limits::default())?;
    let mut b = mux(Mp4Limits::default())?;
    assert_eq!(a.initialization(), b.initialization());
    assert_eq!(
        a.fragment(&timed(&groups, 123))?,
        b.fragment(&timed(&groups, 123))?
    );
    Ok(())
}
