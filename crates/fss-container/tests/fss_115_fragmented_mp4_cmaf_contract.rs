#![forbid(unsafe_code)]
//! Contract, determinism, multi-fragment round-trip, timeline-gap preservation, and hostile
//! truncation/corruption verification for `FSS-115` (`fss-x4a.12.14`: deterministic fragmented
//! MP4 / CMAF writer and reader).

mod common;

use common::{BASELINE, Error, HIGH, KEY, groups, timed};
use fss_container::demux::{AvcMp4, DemuxLimits, VideoCodec};
use fss_container::{AvcMuxer, HevcMuxer, Mp4Error, Mp4Limits, NalTarget, TimedHevcPicture};
use fss_core::ContentDigest;
use fss_packet::hevc::{
    HevcAssembler, HevcAssemblyLimits, HevcAssemblyStep, HevcConfiguration,
    HevcConfigurationLimits, HevcPictureGroup,
};
use fss_packet::{H265Depacketizer, H265Limits, PacketLimits, RtpPacket};

const HEVC_FIXTURE: &str = include_str!("../../../tests/fixtures/media/hevc/remux_main8.nals.hex");

type TestResult = Result<(), Error>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn new_avc_muxer(
    pictures: &[fss_packet::avc::AvcPictureGroup],
    limits: Mp4Limits,
) -> Result<AvcMuxer, Mp4Error> {
    AvcMuxer::new(
        pictures[0].key(),
        pictures[0].sps().clone(),
        pictures[0].pps().clone(),
        90_000,
        limits,
    )
}

#[test]
fn cmaf_multi_fragment_write_and_demux_roundtrip_is_bit_deterministic() -> TestResult {
    let pictures = groups(BASELINE, KEY, true, false)?;
    assert_eq!(pictures.len(), 4);

    let mut mux_a = new_avc_muxer(&pictures, Mp4Limits::default())?;
    let mut mux_b = new_avc_muxer(&pictures, Mp4Limits::default())?;

    // Initialization segment (`ftyp` + `moov`) must be bit-identical across independent writers.
    let init_a = mux_a.initialization().bytes().to_vec();
    let init_b = mux_b.initialization().bytes().to_vec();
    assert_eq!(init_a, init_b);
    assert_eq!(&init_a[4..8], b"ftyp");
    let init_digest = ContentDigest::sha256(&init_a);

    // Fragment 1: 3 samples [0, 3600, 7200] (seq 1).
    let frag1_in = timed(&pictures[..3], &[0, 3600, 7200]);
    let frag1_a = mux_a.fragment(&frag1_in)?;
    let frag1_b = mux_b.fragment(&frag1_in)?;
    assert_eq!(frag1_a, frag1_b);
    assert_eq!(frag1_a.sequence(), 1);
    assert_eq!(&frag1_a.bytes()[4..8], b"moof");
    assert!(frag1_a.timeline_gap().is_none());

    // Fragment 2: 1 IDR sample at decode_time=18_000 (explicit timeline gap 10_800..18_000, seq 2).
    let mut frag2_in = timed(&pictures[3..], &[18_000]);
    frag2_in[0].decode_time = 18_000;
    frag2_in[0].composition_offset = 0;
    let frag2_a = mux_a.fragment(&frag2_in)?;
    let frag2_b = mux_b.fragment(&frag2_in)?;
    assert_eq!(frag2_a, frag2_b);
    assert_eq!(frag2_a.sequence(), 2);
    assert_eq!(frag2_a.timeline_gap(), Some(10_800..18_000));
    assert_eq!(mux_a.next_sequence(), Some(3));

    // Assemble complete multi-fragment CMAF stream: `init || frag1 || frag2`.
    let mut cmaf_stream = Vec::new();
    cmaf_stream.extend_from_slice(&init_a);
    let frag1_offset = cmaf_stream.len();
    cmaf_stream.extend_from_slice(frag1_a.bytes());
    let frag2_offset = cmaf_stream.len();
    cmaf_stream.extend_from_slice(frag2_a.bytes());
    let stream_digest = ContentDigest::sha256(&cmaf_stream);

    // Demux the complete multi-fragment CMAF stream back and verify every sample & source span.
    let parsed = AvcMp4::parse(&cmaf_stream, None, DemuxLimits::default())?;
    assert_eq!(parsed.codec(), VideoCodec::Avc);
    assert_eq!(parsed.samples().len(), 4);

    let written_samples: Vec<(
        usize,
        &fss_container::SampleMapping,
        &fss_container::AvcFragment,
    )> = frag1_a
        .samples()
        .iter()
        .map(|s| (frag1_offset, s, &frag1_a))
        .chain(
            frag2_a
                .samples()
                .iter()
                .map(|s| (frag2_offset, s, &frag2_a)),
        )
        .collect();

    for (demuxed, (frag_off, written, frag)) in parsed.samples().iter().zip(written_samples) {
        assert_eq!(
            demuxed.source,
            frag_off + written.range.start..frag_off + written.range.end
        );
        assert_eq!(demuxed.decode_time, written.decode_time);
        assert_eq!(demuxed.duration, written.duration);
        assert_eq!(
            demuxed.presentation_time(),
            i128::from(written.presentation_time)
        );
        assert_eq!(demuxed.contains_idr, written.idr);

        // Verify every mapped NAL inside the demuxed byte range matches the original picture NAL.
        for mapping in &frag.mappings()[written.mappings.clone()] {
            let orig_nal = &pictures[mapping.sample + if frag.sequence() == 2 { 3 } else { 0 }]
                .nals()[mapping.nal];
            if let NalTarget::Media(range) = &mapping.target {
                let abs_start = frag_off + range.start;
                let abs_end = frag_off + range.end;
                assert_eq!(&cmaf_stream[abs_start..abs_end], orig_nal.bytes());
            }
        }
    }

    // Also certify B-frame signed composition offsets (`HIGH` profile) round-trip cleanly.
    let high_pics = groups(HIGH, KEY, true, false)?;
    let mut high_mux = new_avc_muxer(&high_pics, Mp4Limits::default())?;
    let high_frag = high_mux.fragment(&timed(
        &high_pics,
        &[0, 10_800, 3_600, 7_200, 18_000, 14_400],
    ))?;
    let mut high_cmaf = high_mux.initialization().bytes().to_vec();
    high_cmaf.extend_from_slice(high_frag.bytes());
    let high_parsed = AvcMp4::parse(&high_cmaf, None, DemuxLimits::default())?;
    assert_eq!(high_parsed.samples().len(), 6);
    for (demuxed, written) in high_parsed.samples().iter().zip(high_frag.samples()) {
        assert_eq!(
            demuxed.presentation_time(),
            i128::from(written.presentation_time)
        );
    }

    assert_ne!(init_digest, stream_digest);
    emit_caplog(
        "fss_115_cmaf_roundtrip_and_determinism",
        "bit_exact_multi_fragment_avc_high_cmaf_write_demux_roundtrip_verified",
        "bit_exact_multi_fragment_avc_high_cmaf_write_demux_roundtrip_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn cmaf_hostile_truncation_box_corruption_and_writer_refusals_fail_closed() -> TestResult {
    let pictures = groups(BASELINE, KEY, true, false)?;
    let mut writer = new_avc_muxer(&pictures, Mp4Limits::default())?;
    let frag = writer.fragment(&timed(&pictures, &[0, 3600, 7200, 10800]))?;

    let init = writer.initialization().bytes();
    let mut stream = Vec::with_capacity(init.len() + frag.bytes().len());
    stream.extend_from_slice(init);
    let moof_start = stream.len();
    stream.extend_from_slice(frag.bytes());

    // 1. Every truncated prefix inside init or fragment must fail closed without panicking.
    for cut in [
        0_usize,
        1,
        7,
        init.len() / 2,
        init.len() - 1,
        init.len(), // init-only with 0 samples must fail closed
        moof_start + 4,
        moof_start + 16,
        stream.len() - 1,
    ] {
        assert!(
            AvcMp4::parse(&stream[..cut], None, DemuxLimits::default()).is_err(),
            "truncated CMAF prefix of {cut} bytes must fail closed"
        );
    }

    // 2. Corrupting the moof box size to claim bytes past EOF fails closed.
    let mut oversized_moof = stream.clone();
    oversized_moof[moof_start..moof_start + 4].copy_from_slice(&0x7FFF_FFFF_u32.to_be_bytes());
    assert!(AvcMp4::parse(&oversized_moof, None, DemuxLimits::default()).is_err());

    // 3. Flipping the `ftyp` magic fails closed.
    let mut bad_ftyp = stream.clone();
    bad_ftyp[4..8].copy_from_slice(b"XXXX");
    assert!(AvcMp4::parse(&bad_ftyp, None, DemuxLimits::default()).is_err());

    // 4. Writer refusals (non-IDR start, timeline reversal, zero duration) never mutate sequence.
    let mut fresh = new_avc_muxer(&pictures, Mp4Limits::default())?;
    assert_eq!(
        fresh.fragment(&timed(&pictures[1..], &[0, 3600, 7200])),
        Err(Mp4Error::RandomAccessRequired)
    );
    let mut bad_time = timed(&pictures, &[0, 3600, 7200, 10800]);
    bad_time[1].duration = 0;
    assert_eq!(fresh.fragment(&bad_time), Err(Mp4Error::Timeline));
    assert_eq!(fresh.next_sequence(), Some(1));

    emit_caplog(
        "fss_115_cmaf_hostile_and_refusals",
        "truncated_prefixes_box_corruption_and_writer_refusals_fail_closed",
        "truncated_prefixes_box_corruption_and_writer_refusals_fail_closed",
        "pass",
    );
    Ok(())
}

fn decode_hex_line(s: &str) -> Result<Vec<u8>, Error> {
    let compact: Vec<_> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !compact.len().is_multiple_of(2) {
        return Err("odd hex fixture line length".into());
    }
    compact
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let nibble = |b| -> Result<u8, Error> {
                match b {
                    b'0'..=b'9' => Ok(b - b'0'),
                    b'a'..=b'f' => Ok(b - b'a' + 10),
                    b'A'..=b'F' => Ok(b - b'A' + 10),
                    _ => Err("non-hex byte in fixture".into()),
                }
            };
            Ok(nibble(pair[0])? * 16 + nibble(pair[1])?)
        })
        .collect()
}

fn assemble_hevc_pictures()
-> Result<(HevcConfiguration, HevcConfiguration, Vec<HevcPictureGroup>), Error> {
    let nals: Vec<Vec<u8>> = HEVC_FIXTURE
        .lines()
        .filter(|line| !line.is_empty())
        .map(decode_hex_line)
        .collect::<Result<_, _>>()?;
    let config_a = HevcConfiguration::parse(
        &nals[0],
        &nals[1],
        &nals[2],
        HevcConfigurationLimits::default(),
    )?;
    let config_b = HevcConfiguration::parse(
        &nals[0],
        &nals[1],
        &nals[2],
        HevcConfigurationLimits::default(),
    )?;
    let timestamps = [0, 0, 0, 0, 18_000, 36_000, 36_000, 36_000, 36_000, 54_000];
    let mut payloads: Vec<(u32, Vec<u8>)> = timestamps.into_iter().zip(nals).collect();
    payloads.push((54_000, vec![0x48, 1, 0x80]));

    let mut dep = H265Depacketizer::new(KEY, 96, 0, H265Limits::default())?;
    let mut assembler = HevcAssembler::new(KEY, HevcAssemblyLimits::default())?;
    let mut pictures = Vec::new();
    for (i, (timestamp, payload)) in payloads.iter().enumerate() {
        let mut raw = vec![0x80, 96 | 128];
        raw.extend_from_slice(&(i as u16 + 1).to_be_bytes());
        raw.extend_from_slice(&timestamp.to_be_bytes());
        raw.extend_from_slice(&KEY.ssrc.to_be_bytes());
        raw.extend_from_slice(payload);
        let output = dep.push(
            KEY,
            i as u64 + 1,
            RtpPacket::parse(&raw, PacketLimits::default())?,
            i as u64,
        )?;
        for nal in output.nals {
            match assembler.push(nal, i as u64) {
                HevcAssemblyStep::Accepted(step) => {
                    if let Some(pic) = step.picture {
                        pictures.push(pic);
                    }
                }
                HevcAssemblyStep::Refused(refused) => return Err(refused.reason.into()),
            }
        }
    }
    Ok((config_a, config_b, pictures))
}

#[test]
fn cmaf_hevc_multi_fragment_write_and_demux_roundtrip_is_bit_deterministic() -> TestResult {
    let (config_a, config_b, pictures) = assemble_hevc_pictures()?;
    assert_eq!(pictures.len(), 4);

    let mut mux_a = HevcMuxer::new(KEY, config_a, 90_000, Mp4Limits::default())?;
    let mut mux_b = HevcMuxer::new(KEY, config_b, 90_000, Mp4Limits::default())?;
    let init_a = mux_a.initialization().bytes().to_vec();
    let init_b = mux_b.initialization().bytes().to_vec();
    assert_eq!(init_a, init_b);

    let timed_frag1: Vec<TimedHevcPicture<'_>> = pictures[..2]
        .iter()
        .enumerate()
        .map(|(i, picture)| TimedHevcPicture {
            picture,
            decode_time: i as u64 * 18_000,
            duration: 18_000,
            composition_offset: 0,
        })
        .collect();
    let timed_frag2: Vec<TimedHevcPicture<'_>> = pictures[2..]
        .iter()
        .enumerate()
        .map(|(i, picture)| TimedHevcPicture {
            picture,
            decode_time: 54_000 + i as u64 * 18_000,
            duration: 18_000,
            composition_offset: 0,
        })
        .collect();

    let frag1_a = mux_a.fragment(&timed_frag1)?;
    let frag1_b = mux_b.fragment(&timed_frag1)?;
    assert_eq!(frag1_a, frag1_b);
    assert!(frag1_a.timeline_gap().is_none());

    let frag2_a = mux_a.fragment(&timed_frag2)?;
    let frag2_b = mux_b.fragment(&timed_frag2)?;
    assert_eq!(frag2_a, frag2_b);
    assert_eq!(frag2_a.timeline_gap(), Some(36_000..54_000));

    let mut cmaf_stream = Vec::new();
    cmaf_stream.extend_from_slice(&init_a);
    let frag1_off = cmaf_stream.len();
    cmaf_stream.extend_from_slice(frag1_a.bytes());
    let frag2_off = cmaf_stream.len();
    cmaf_stream.extend_from_slice(frag2_a.bytes());

    let parsed = AvcMp4::parse(&cmaf_stream, None, DemuxLimits::default())?;
    assert_eq!(parsed.codec(), VideoCodec::Hevc);
    assert_eq!(parsed.samples().len(), 4);

    let written_samples: Vec<(
        usize,
        usize,
        &fss_container::HevcSampleMapping,
        &fss_container::HevcFragment,
    )> = frag1_a
        .samples()
        .iter()
        .enumerate()
        .map(|(idx, s)| (idx, frag1_off, s, &frag1_a))
        .chain(
            frag2_a
                .samples()
                .iter()
                .enumerate()
                .map(|(idx, s)| (2 + idx, frag2_off, s, &frag2_a)),
        )
        .collect();
    for (demuxed, (pic_idx, frag_off, written, frag)) in
        parsed.samples().iter().zip(written_samples)
    {
        assert_eq!(
            demuxed.source,
            frag_off + written.range.start..frag_off + written.range.end
        );
        assert_eq!(demuxed.decode_time, written.decode_time);
        assert_eq!(demuxed.duration, written.duration);
        assert_eq!(
            demuxed.presentation_time(),
            i128::from(written.presentation_time)
        );
        assert_eq!(demuxed.contains_idr, written.idr);
        for mapping in &frag.mappings()[written.mappings.clone()] {
            let orig_nal = &pictures[pic_idx].nals()[mapping.nal];
            let abs_start = frag_off + mapping.range.start;
            let abs_end = frag_off + mapping.range.end;
            assert_eq!(&cmaf_stream[abs_start..abs_end], orig_nal.bytes());
        }
    }

    emit_caplog(
        "fss_115_cmaf_hevc_roundtrip",
        "bit_exact_multi_fragment_hevc_cmaf_write_demux_roundtrip_verified",
        "bit_exact_multi_fragment_hevc_cmaf_write_demux_roundtrip_verified",
        "pass",
    );
    Ok(())
}
