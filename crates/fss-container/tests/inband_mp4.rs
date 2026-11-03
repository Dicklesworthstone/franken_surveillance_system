#![forbid(unsafe_code)]
//! Real encoded avc3/hev1 -> source-linked extraction -> native pixels. Expected hashes are
//! independent FFmpeg outputs generated offline; these tests never invoke another process.

use fss_container::demux::{
    AvcMp4, DemuxError, DemuxLimits, InbandSampleEntry, VideoCodec, length_prefixed_nals,
};
use fss_core::ContentDigest;
use std::error::Error;
use std::ops::Range;

type Test = Result<(), Box<dyn Error>>;
type Frames = Vec<([u32; 2], String, u64)>;

struct Oracle {
    source: String,
    frames: Vec<([u32; 2], String)>,
    samples: Vec<(u64, i128, u32, bool)>,
    ranges: Vec<(usize, usize)>,
}
fn oracle(text: &str) -> Result<Oracle, Box<dyn Error>> {
    let mut result = Oracle {
        source: String::new(),
        frames: Vec::new(),
        samples: Vec::new(),
        ranges: Vec::new(),
    };
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        match fields.as_slice() {
            ["source", digest] => result.source = (*digest).to_owned(),
            ["frame", width, height, digest] => result
                .frames
                .push(([width.parse()?, height.parse()?], (*digest).to_owned())),
            ["sample", dts, pts, duration, sync] => {
                result
                    .samples
                    .push((dts.parse()?, pts.parse()?, duration.parse()?, *sync == "1"))
            }
            ["range", first, count] => result.ranges.push((first.parse()?, count.parse()?)),
            _ => return Err(format!("invalid oracle row: {line}").into()),
        }
    }
    Ok(result)
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    result
}
fn decode(codec: VideoCodec, bytes: &[u8]) -> Result<Frames, Box<dyn Error>> {
    match codec {
        VideoCodec::Avc => {
            let mut decoder =
                fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
            let mut frames = decoder.decode_annex_b(bytes)?;
            frames.extend(decoder.finish()?);
            Ok(frames
                .iter()
                .map(|p| {
                    (
                        [p.width(), p.height()],
                        hex(&p.i420_sha256()),
                        p.decode_index(),
                    )
                })
                .collect())
        }
        VideoCodec::Hevc => {
            let mut decoder =
                fss_codec_h265::Decoder::new(fss_codec_h265::DecoderLimits::default())?;
            let mut frames = decoder.decode_annex_b(bytes)?;
            frames.extend(decoder.finish()?);
            Ok(frames
                .iter()
                .map(|p| {
                    (
                        [p.width(), p.height()],
                        hex(&p.i420_sha256()),
                        p.decode_index(),
                    )
                })
                .collect())
        }
    }
}
fn check(bytes: &[u8], expected: &str) -> Test {
    let expected = oracle(expected)?;
    assert_eq!(hex(&ContentDigest::sha256(bytes).bytes()), expected.source);
    let movie = AvcMp4::parse_inband(bytes, None, DemuxLimits::default())?;
    assert!(movie.uses_inband_configuration());
    assert_eq!(movie.samples().len(), expected.samples.len());
    for (sample, &(decode, presentation, duration, sync)) in
        movie.samples().iter().zip(&expected.samples)
    {
        assert_eq!(
            (
                sample.decode_time,
                sample.presentation_time(),
                sample.duration,
                sample.sync_sample
            ),
            (decode, presentation, duration, sync)
        );
        let config = movie
            .sample_configuration(sample.index)
            .ok_or("missing sample configuration")?;
        assert_eq!(config.display_dimensions(), expected.frames[sample.index].0);
        assert_eq!(config.bit_depth(), 8);
        assert_eq!(config.is_random_access(), sample.contains_idr);
        for parameter in config.parameter_sets() {
            if let Some(origin) = parameter.sample {
                let sample_range = &movie.samples()[origin].source;
                assert!(origin <= sample.index);
                assert!(
                    parameter.source.start >= sample_range.start
                        && parameter.source.end <= sample_range.end
                );
            } else {
                let config_range = movie.configuration_record();
                assert!(
                    parameter.source.start >= config_range.start
                        && parameter.source.end <= config_range.end
                );
            }
        }
    }
    let extraction = movie.annex_b(0, movie.samples().len())?;
    let actual = decode(movie.codec(), extraction.bytes())?;
    assert_eq!(
        actual
            .iter()
            .map(|(dimensions, digest, _)| (*dimensions, digest.clone()))
            .collect::<Vec<_>>(),
        expected.frames
    );
    let indices: std::collections::BTreeSet<_> = actual.iter().map(|p| p.2).collect();
    assert_eq!(
        indices.into_iter().collect::<Vec<_>>(),
        (0..actual.len() as u64).collect::<Vec<_>>()
    );
    for mapping in extraction.mappings() {
        let count = mapping.source.len();
        assert_eq!(
            &extraction.bytes()[mapping.output_start..mapping.output_start + count],
            &bytes[mapping.source.clone()]
        );
    }
    for (first, count) in expected.ranges {
        let extraction = movie.annex_b(first, count)?;
        let actual = decode(movie.codec(), extraction.bytes())?;
        assert_eq!(
            actual
                .iter()
                .map(|(d, h, _)| (*d, h.clone()))
                .collect::<Vec<_>>(),
            expected.frames[first..first + count]
        );
        let config = movie
            .sample_configuration(first)
            .ok_or("missing random-access configuration")?;
        assert_eq!(config.generation(), u32::from(first > 0));
        assert!(
            config
                .parameter_sets()
                .iter()
                .all(|p| p.sample.is_none() || p.sample == Some(first))
        );
        // Cold retained replay needs only the original sample-entry span plus the selected
        // sample. It cannot accidentally inherit parameter state from the first GOP.
        let entry_bytes = &bytes[movie.sample_entry_range()];
        let entry = InbandSampleEntry::parse(entry_bytes, DemuxLimits::default())?;
        assert_eq!(entry.codec(), movie.codec());
        assert_eq!(entry.nal_length_bytes(), movie.nal_length_bytes());
        let sample_bytes = &bytes[movie.samples()[first].source.clone()];
        let bootstrap = entry.bootstrap(sample_bytes)?;
        assert_eq!(
            bootstrap.configuration().display_dimensions(),
            config.display_dimensions()
        );
        let mut cold = Vec::new();
        for (nal, origin) in bootstrap
            .parameter_sets()
            .iter()
            .zip(bootstrap.configuration().parameter_sets())
        {
            let source = if origin.sample.is_none() {
                entry_bytes
            } else {
                sample_bytes
            };
            assert_eq!(*nal, &source[origin.source.clone()]);
            cold.extend_from_slice(&[0, 0, 0, 1]);
            cold.extend_from_slice(nal);
        }
        for nal in length_prefixed_nals(sample_bytes, entry.nal_length_bytes())? {
            cold.extend_from_slice(&[0, 0, 0, 1]);
            cold.extend_from_slice(&sample_bytes[nal]);
        }
        assert_eq!(decode(entry.codec(), &cold)?, actual[..1]);

        // The owned streaming configuration also supplies a later out-of-band PPS/SPS ID
        // when that tuple was not referenced by the selected first picture.
        let mut state = entry.stream(first)?;
        let mut streamed = Vec::new();
        for sample in &movie.samples()[first..first + count] {
            let payload = &bytes[sample.source.clone()];
            let parameters = state.sample(payload)?;
            let config = parameters.configuration();
            assert_eq!(config.display_dimensions(), expected.frames[sample.index].0);
            for origin in config.parameter_sets() {
                let original = match origin.sample {
                    None => entry_bytes,
                    Some(index) => &bytes[movie.samples()[index].source.clone()],
                };
                assert!(original.get(origin.source.clone()).is_some());
            }
            for nal in parameters.decoder_prefix() {
                assert!(config.parameter_sets().iter().any(|origin| {
                    let original = match origin.sample {
                        None => entry_bytes,
                        Some(index) => &bytes[movie.samples()[index].source.clone()],
                    };
                    original.get(origin.source.clone()) == Some(nal)
                }));
                streamed.extend_from_slice(&[0, 0, 0, 1]);
                streamed.extend_from_slice(nal);
            }
            for nal in length_prefixed_nals(payload, entry.nal_length_bytes())? {
                streamed.extend_from_slice(&[0, 0, 0, 1]);
                streamed.extend_from_slice(&payload[nal]);
            }
        }
        assert_eq!(decode(entry.codec(), &streamed)?, actual);
    }
    Ok(())
}

macro_rules! fixture {
    ($name:ident) => {
        #[test]
        fn $name() -> Test {
            check(
                include_bytes!(concat!("fixtures/inband/", stringify!($name), ".mp4")),
                include_str!(concat!("fixtures/inband/", stringify!($name), ".oracle")),
            )
        }
    };
}
fixture!(avc3_empty_change);
fixture!(avc3_partial_change);
fixture!(avc3_full_change);
fixture!(avc3_indexed_change);
fixture!(avc3_length2);
fixture!(avc3_length1);
fixture!(avc3_multislice);
fixture!(avc3_bframes);
fixture!(hev1_empty_change);
fixture!(hev1_partial_change);
fixture!(hev1_full_change);
fixture!(hev1_indexed_change);
fixture!(hev1_length2);
fixture!(hev1_bframes);
fixture!(avc3_later_pps_entry);
fixture!(hev1_later_pps_entry);

const AVC: &[u8] = include_bytes!("fixtures/inband/avc3_empty_change.mp4");
const HEVC: &[u8] = include_bytes!("fixtures/inband/hev1_empty_change.mp4");

#[test]
fn explicit_avc3_brand_is_admitted_by_the_new_profile() -> Test {
    let original = AvcMp4::parse_inband(AVC, None, DemuxLimits::default())?;
    let mut branded = AVC.to_vec();
    let size = u32::from_be_bytes(branded[..4].try_into()?) as usize;
    branded[8..12].copy_from_slice(b"avc3");
    for brand in branded[16..size].chunks_mut(4) {
        brand.copy_from_slice(b"avc3");
    }
    assert_eq!(
        AvcMp4::parse(&branded, None, DemuxLimits::default()).map(|_| ()),
        Err(DemuxError::Unsupported)
    );
    let admitted = AvcMp4::parse_inband(&branded, None, DemuxLimits::default())?;
    assert_eq!(admitted.samples(), original.samples());
    assert_eq!(
        admitted.annex_b(0, 8)?.bytes(),
        original.annex_b(0, 8)?.bytes()
    );
    Ok(())
}

#[test]
fn later_entry_only_pps_id_is_supplied_when_the_picture_first_references_it() -> Test {
    for source in [
        include_bytes!("fixtures/inband/avc3_later_pps_entry.mp4").as_slice(),
        include_bytes!("fixtures/inband/hev1_later_pps_entry.mp4").as_slice(),
    ] {
        let movie = AvcMp4::parse_inband(source, None, DemuxLimits::default())?;
        let first = movie.sample_configuration(0).ok_or("first configuration")?;
        let second = movie
            .sample_configuration(1)
            .ok_or("second configuration")?;
        assert_eq!(first.parameter_sets().last().ok_or("PPS0")?.id, 0);
        assert_eq!(second.parameter_sets().last().ok_or("PPS1")?.id, 1);
        assert_eq!(second.parameter_sets().last().ok_or("PPS1")?.sample, None);
        assert_eq!(first.generation(), 0);
        assert_eq!(second.generation(), 1);
        let entry =
            InbandSampleEntry::parse(&source[movie.sample_entry_range()], DemuxLimits::default())?;
        let first_sample = &source[movie.samples()[0].source.clone()];
        let bootstrap = entry.bootstrap(first_sample)?;
        let mut first_tuple_only = Vec::new();
        for nal in bootstrap.parameter_sets() {
            first_tuple_only.extend_from_slice(&[0, 0, 0, 1]);
            first_tuple_only.extend_from_slice(nal);
        }
        for sample in movie.samples() {
            let bytes = &source[sample.source.clone()];
            for nal in length_prefixed_nals(bytes, movie.nal_length_bytes())? {
                first_tuple_only.extend_from_slice(&[0, 0, 0, 1]);
                first_tuple_only.extend_from_slice(&bytes[nal]);
            }
        }
        assert!(
            decode(movie.codec(), &first_tuple_only).is_err(),
            "fixture must require the later entry PPS"
        );
        let mut state = entry.stream(0)?;
        state.sample(first_sample)?;
        let later = state.sample(&source[movie.samples()[1].source.clone()])?;
        assert_eq!(
            later
                .configuration()
                .parameter_sets()
                .last()
                .ok_or("PPS1")?
                .id,
            1
        );
        assert_eq!(
            later.decoder_prefix().len(),
            if movie.codec() == VideoCodec::Avc {
                2
            } else {
                3
            }
        );
    }
    Ok(())
}

#[test]
fn later_picture_cannot_reach_back_before_its_random_access_for_a_parameter() -> Test {
    let source = include_bytes!("fixtures/inband/avc3_later_pps_entry.mp4");
    let movie = AvcMp4::parse_inband(source, None, DemuxLimits::default())?;
    let entry_range = movie.sample_entry_range();
    let pps = movie
        .sample_configuration(1)
        .ok_or("P picture")?
        .parameter_sets()
        .iter()
        .find(|p| p.nal_type == 8 && p.id == 1)
        .ok_or("entry PPS1")?;
    assert_eq!(pps.sample, None);
    let pps_bytes = &source[pps.source.clone()];
    let mut entry_bytes = source[entry_range.clone()].to_vec();
    let id_byte = pps.source.start - entry_range.start + 1;
    assert_eq!(entry_bytes[id_byte] >> 5, 0b010);
    // Replace entry PPS1 with same-length PPS2; the real PPS1 will be carried only by the
    // first GOP. The ue(v) ID is the first three RBSP bits, before any emulation prevention.
    entry_bytes[id_byte] ^= 0x20;
    let entry = InbandSampleEntry::parse(&entry_bytes, DemuxLimits::default())?;
    let with_pps = |sample: &[u8]| -> Result<Vec<u8>, Box<dyn Error>> {
        let length = u32::try_from(pps_bytes.len())?.to_be_bytes();
        let mut bytes = length[4 - movie.nal_length_bytes()..].to_vec();
        bytes.extend_from_slice(pps_bytes);
        bytes.extend_from_slice(sample);
        Ok(bytes)
    };
    let idr = &source[movie.samples()[0].source.clone()];
    let p = &source[movie.samples()[1].source.clone()];
    let mut state = entry.stream(0)?;
    state.sample(&with_pps(idr)?)?;
    state.sample(p)?;
    state.sample(idr)?;
    assert_eq!(
        state.sample(p).map(|_| ()),
        Err(DemuxError::RandomAccessRequired)
    );
    assert_eq!(
        state.sample(&with_pps(p)?).map(|_| ()),
        Err(DemuxError::RandomAccessRequired)
    );
    let mut fresh = entry.stream(0)?;
    fresh.sample(&with_pps(idr)?)?;
    fresh.sample(p)?;
    fresh.sample(idr)?;
    let admitted = fresh.sample(&with_pps(p)?)?;
    assert_eq!(
        admitted
            .configuration()
            .parameter_sets()
            .last()
            .ok_or("PPS1")?
            .sample,
        Some(3)
    );
    Ok(())
}

#[test]
fn historical_entrypoints_still_refuse_new_admission_and_keep_old_bytes() -> Test {
    assert_eq!(
        AvcMp4::parse(AVC, None, DemuxLimits::default()).map(|_| ()),
        Err(DemuxError::Unsupported)
    );
    assert!(AvcMp4::parse(HEVC, None, DemuxLimits::default()).is_err());
    let fixtures: &[&[u8]] = &[
        include_bytes!("fixtures/indexed_avc.mp4"),
        include_bytes!("fixtures/interleaved_av.mp4"),
        include_bytes!("fixtures/fragmented_av.mp4"),
        include_bytes!("fixtures/qt_av.mov"),
        include_bytes!("fixtures/hevc_av.mp4"),
        include_bytes!("fixtures/hevc_fragmented_av.mp4"),
        include_bytes!("fixtures/qt_hevc.mov"),
    ];
    for bytes in fixtures {
        let legacy = AvcMp4::parse(bytes, None, DemuxLimits::default())?;
        let current = AvcMp4::parse_inband(bytes, None, DemuxLimits::default())?;
        assert!(!current.uses_inband_configuration());
        assert_eq!(legacy.work(), current.work());
        assert_eq!(legacy.samples(), current.samples());
        assert_eq!(legacy.parameter_sets(), current.parameter_sets());
        let old = legacy.annex_b(0, legacy.samples().len())?;
        let new = current.annex_b(0, current.samples().len())?;
        assert_eq!(old.bytes(), new.bytes());
        assert_eq!(old.mappings(), new.mappings());
    }
    Ok(())
}

#[test]
fn hybrid_bootstrap_and_changed_same_ids_use_the_correct_original_bytes() -> Test {
    for bytes in [
        include_bytes!("fixtures/inband/avc3_partial_change.mp4").as_slice(),
        include_bytes!("fixtures/inband/hev1_partial_change.mp4").as_slice(),
    ] {
        let movie = AvcMp4::parse_inband(bytes, None, DemuxLimits::default())?;
        let first = movie.sample_configuration(0).ok_or("first configuration")?;
        let later = movie.sample_configuration(4).ok_or("later configuration")?;
        assert!(first.parameter_sets().iter().any(|p| p.sample.is_none()));
        assert!(first.parameter_sets().iter().any(|p| p.sample == Some(0)));
        assert_eq!(
            first
                .parameter_sets()
                .iter()
                .map(|p| (p.nal_type, p.id))
                .collect::<Vec<_>>(),
            later
                .parameter_sets()
                .iter()
                .map(|p| (p.nal_type, p.id))
                .collect::<Vec<_>>()
        );
        assert_ne!(first.coded_dimensions(), later.coded_dimensions());
        assert_eq!(later.generation(), 1);
        assert_eq!(
            movie.annex_b(1, 1).map(|_| ()),
            Err(DemuxError::RandomAccessRequired)
        );
    }
    Ok(())
}

fn sample_nals(movie: &AvcMp4<'_>, sample: usize) -> Result<Vec<Range<usize>>, DemuxError> {
    let range = movie.samples()[sample].source.clone();
    Ok(
        length_prefixed_nals(&movie.source()[range.clone()], movie.nal_length_bytes())?
            .into_iter()
            .map(|p| p.start + range.start..p.end + range.start)
            .collect(),
    )
}

#[test]
fn a_later_random_access_cannot_borrow_an_unavailable_old_gop_configuration() -> Test {
    for bytes in [AVC, HEVC] {
        let movie = AvcMp4::parse_inband(bytes, None, DemuxLimits::default())?;
        let sps_kind = if movie.codec() == VideoCodec::Avc {
            7
        } else {
            33
        };
        let location = sample_nals(&movie, 4)?
            .into_iter()
            .find(|p| {
                let kind = if movie.codec() == VideoCodec::Avc {
                    bytes[p.start] & 31
                } else {
                    bytes[p.start] >> 1 & 63
                };
                kind == sps_kind
            })
            .ok_or("later SPS")?;
        let mut changed = bytes.to_vec();
        // Leave lengths and source sample tables untouched; the required SPS is now absent.
        changed[location.start] = if movie.codec() == VideoCodec::Avc {
            0x06
        } else {
            39 << 1
        };
        assert_eq!(
            AvcMp4::parse_inband(&changed, None, DemuxLimits::default()).map(|_| ()),
            Err(DemuxError::RandomAccessRequired)
        );
    }
    Ok(())
}

fn box_bytes(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut result = ((body.len() + 8) as u32).to_be_bytes().to_vec();
    result.extend_from_slice(kind);
    result.extend_from_slice(body);
    result
}
fn full_box(kind: &[u8; 4], flags: u32, body: &[u8]) -> Vec<u8> {
    let mut data = flags.to_be_bytes().to_vec();
    data.extend_from_slice(body);
    box_bytes(kind, &data)
}
fn merge_first_two_samples(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let movie = AvcMp4::parse_inband(bytes, None, DemuxLimits::default())?;
    let first_moof = bytes.windows(4).position(|b| b == b"moof").ok_or("moof")? - 4;
    let mut output = bytes[..first_moof].to_vec();
    let mut samples: Vec<Vec<u8>> = movie
        .samples()
        .iter()
        .map(|s| bytes[s.source.clone()].to_vec())
        .collect();
    let second = samples.remove(1);
    samples[0].extend_from_slice(&second);
    let mut entries = Vec::new();
    for (index, sample) in samples.iter().enumerate() {
        for n in [
            if index == 0 { 18000 } else { 9000 },
            sample.len() as u32,
            if index == 0 || index == 3 {
                0x02000000
            } else {
                0x01010000
            },
            0,
        ] {
            entries.extend_from_slice(&n.to_be_bytes());
        }
    }
    let mut trun = (samples.len() as u32).to_be_bytes().to_vec();
    trun.extend_from_slice(&(96 + 16 * samples.len() as u32).to_be_bytes());
    trun.extend_from_slice(&entries);
    let mut traf = full_box(b"tfhd", 0x20000, &1_u32.to_be_bytes());
    traf.extend_from_slice(&full_box(b"tfdt", 0x1000000, &0_u64.to_be_bytes()));
    traf.extend_from_slice(&full_box(b"trun", 0x1000f01, &trun));
    let mut moof = full_box(b"mfhd", 0, &1_u32.to_be_bytes());
    moof.extend_from_slice(&box_bytes(b"traf", &traf));
    output.extend_from_slice(&box_bytes(b"moof", &moof));
    output.extend_from_slice(&box_bytes(b"mdat", &samples.concat()));
    Ok(output)
}

#[test]
fn two_real_complete_pictures_cannot_share_one_source_sample() -> Test {
    for bytes in [AVC, HEVC] {
        let changed = merge_first_two_samples(bytes)?;
        assert_eq!(
            AvcMp4::parse_inband(&changed, None, DemuxLimits::default()).map(|_| ()),
            Err(DemuxError::Nal)
        );
        // The immutable original is still admitted after the failed parse.
        assert_eq!(
            AvcMp4::parse_inband(bytes, None, DemuxLimits::default())?
                .samples()
                .len(),
            8
        );
    }
    Ok(())
}

#[test]
fn complete_hevc_arrays_cannot_be_redefined_in_the_samples() -> Test {
    let bytes = include_bytes!("fixtures/inband/hev1_partial_change.mp4");
    let movie = AvcMp4::parse_inband(bytes, None, DemuxLimits::default())?;
    let mut changed = bytes.to_vec();
    changed[movie.configuration_record().start + 23] |= 0x80;
    assert_eq!(
        AvcMp4::parse_inband(&changed, None, DemuxLimits::default()).map(|_| ()),
        Err(DemuxError::Nal)
    );
    Ok(())
}

#[test]
fn inband_work_output_and_cancellation_remain_bounded() -> Test {
    for limits in [
        DemuxLimits {
            maximum_nals: 5,
            ..DemuxLimits::default()
        },
        DemuxLimits {
            maximum_table_entries: 10,
            ..DemuxLimits::default()
        },
        DemuxLimits {
            maximum_samples: 4,
            ..DemuxLimits::default()
        },
    ] {
        assert_eq!(
            AvcMp4::parse_inband(AVC, None, limits).map(|_| ()),
            Err(DemuxError::Limit)
        );
    }
    let movie = AvcMp4::parse_inband(
        AVC,
        None,
        DemuxLimits {
            maximum_output_bytes: 8,
            ..DemuxLimits::default()
        },
    )?;
    assert_eq!(movie.annex_b(0, 8).map(|_| ()), Err(DemuxError::Limit));
    for stop in [1, 25, 60, 100] {
        let mut calls = 0;
        let mut check = || {
            calls += 1;
            if calls == stop {
                Err(DemuxError::Cancelled)
            } else {
                Ok(())
            }
        };
        assert_eq!(
            AvcMp4::parse_inband_with_checkpoint(AVC, None, DemuxLimits::default(), &mut check)
                .map(|_| ()),
            Err(DemuxError::Cancelled)
        );
    }
    Ok(())
}

#[test]
fn every_truncated_prefix_of_inband_only_media_refuses_without_panicking() {
    let source = include_bytes!("fixtures/inband/avc3_length1.mp4");
    for end in 0..source.len() {
        assert!(
            AvcMp4::parse_inband(&source[..end], None, DemuxLimits::default()).is_err(),
            "prefix {end}"
        );
    }
}

#[test]
fn streaming_configuration_keeps_aggregate_bounds_and_terminal_failure() -> Test {
    let movie = AvcMp4::parse_inband(AVC, None, DemuxLimits::default())?;
    let entry_bytes = &AVC[movie.sample_entry_range()];
    let first = &AVC[movie.samples()[0].source.clone()];
    let next = &AVC[movie.samples()[1].source.clone()];
    let byte_limited = InbandSampleEntry::parse(
        entry_bytes,
        DemuxLimits {
            maximum_input_bytes: entry_bytes.len() + first.len(),
            ..DemuxLimits::default()
        },
    )?;
    byte_limited.bootstrap(first)?;
    let mut byte_state = byte_limited.stream(0)?;
    byte_state.sample(first)?;
    assert_eq!(byte_state.sample(next).map(|_| ()), Err(DemuxError::Limit));
    let limited = InbandSampleEntry::parse(
        entry_bytes,
        DemuxLimits {
            maximum_samples: 1,
            ..DemuxLimits::default()
        },
    )?;
    let mut one = limited.stream(0)?;
    assert!(one.sample(first)?.decoder_prefix().len() >= 2);
    assert_eq!(one.sample(next).map(|_| ()), Err(DemuxError::Limit));
    assert_eq!(one.sample(first).map(|_| ()), Err(DemuxError::Limit));

    let initial_nals = length_prefixed_nals(first, movie.nal_length_bytes())?.len();
    let limited = InbandSampleEntry::parse(
        entry_bytes,
        DemuxLimits {
            maximum_nals: initial_nals,
            ..DemuxLimits::default()
        },
    )?;
    let mut nals = limited.stream(0)?;
    nals.sample(first)?;
    assert_eq!(nals.sample(next).map(|_| ()), Err(DemuxError::Limit));

    let entry = InbandSampleEntry::parse(entry_bytes, DemuxLimits::default())?;
    let mut cancelled = entry.stream(0)?;
    let mut checkpoints = 0;
    assert_eq!(
        cancelled
            .sample_with_checkpoint(first, &mut || {
                checkpoints += 1;
                if checkpoints == 3 {
                    Err(DemuxError::Cancelled)
                } else {
                    Ok(())
                }
            })
            .map(|_| ()),
        Err(DemuxError::Cancelled)
    );
    assert_eq!(
        cancelled.sample(first).map(|_| ()),
        Err(DemuxError::Cancelled)
    );
    let mut fresh = entry.stream(0)?;
    fresh.sample(first)?;
    assert_eq!(fresh.sample(next)?.decoder_prefix().len(), 0);
    Ok(())
}
