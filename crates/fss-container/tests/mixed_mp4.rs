#![forbid(unsafe_code)]
//! A real indexed first GOP followed by movie fragments, with original AVC/HEVC and audio
//! bytes. Frozen laboratory fixtures exercise native parsing and pixels without subprocesses.

use fss_container::demux::{
    AvcMp4, DemuxError, DemuxLimits, MovieGapKind, MovieSelectionLimits, VideoCodec,
    length_prefixed_nals,
};
use fss_core::ContentDigest;
use std::error::Error;

type Test<T = ()> = Result<T, Box<dyn Error>>;

const AVC: &[u8] = include_bytes!("fixtures/mixed_av.mp4");
const HEVC: &[u8] = include_bytes!("fixtures/hevc_mixed_av.mp4");
const INDEXED_AVC: &[u8] = include_bytes!("fixtures/interleaved_av.mp4");
const INDEXED_HEVC: &[u8] = include_bytes!("fixtures/hevc_av.mp4");

fn tag(bytes: &[u8], kind: &[u8; 4]) -> Test<usize> {
    bytes
        .windows(4)
        .position(|b| b == kind)
        .ok_or_else(|| "missing fixture box".into())
}

fn word(bytes: &[u8], at: usize) -> Test<u32> {
    Ok(u32::from_be_bytes(
        bytes.get(at..at + 4).ok_or("fixture u32")?.try_into()?,
    ))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode(codec: VideoCodec, bytes: &[u8]) -> Test<Vec<String>> {
    match codec {
        VideoCodec::Avc => {
            let mut decoder =
                fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
            let mut frames = decoder.decode_annex_b(bytes)?;
            frames.extend(decoder.finish()?);
            Ok(frames
                .iter()
                .map(|p| {
                    assert_eq!([p.width(), p.height()], [64, 48]);
                    hex(&p.i420_sha256())
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
                    assert_eq!([p.width(), p.height()], [64, 48]);
                    hex(&p.i420_sha256())
                })
                .collect())
        }
    }
}

#[test]
fn indexed_prefix_and_fragments_preserve_all_sample_bytes_and_media_ticks() -> Test {
    // Positions independently reported by FFprobe, before any native parsing.
    for (bytes, indexed, codec, prefix, positions, digest) in [
        (
            AVC,
            INDEXED_AVC,
            VideoCodec::Avc,
            5,
            [1569, 3309, 3607, 4004, 4238, 4753, 5916, 6015, 6036, 6094],
            "7302e4839ecbf322ea614bcf9a75496e3cf4b0f17e4845017de09f2919e6f7e7",
        ),
        (
            HEVC,
            INDEXED_HEVC,
            VideoCodec::Hevc,
            3,
            [1604, 2542, 2827, 3571, 4546, 4571, 4593, 4640, 4694, 4725],
            "6559942bcf718bc7de53b44f2f134266d5a9f26c11ddd3eef7098097c7b8370d",
        ),
    ] {
        assert_eq!(hex(&ContentDigest::sha256(bytes).bytes()), digest);
        let mixed = AvcMp4::parse(bytes, None, DemuxLimits::default())?;
        let original = AvcMp4::parse(indexed, None, DemuxLimits::default())?;
        assert_eq!(mixed.codec(), codec);
        assert_eq!(mixed.timescale(), original.timescale());
        assert_eq!(mixed.tracks(), original.tracks());
        assert_eq!(mixed.samples().len(), 10);
        assert_eq!(word(bytes, tag(bytes, b"stsz")? + 12)?, prefix);
        for (index, (a, b)) in mixed.samples().iter().zip(original.samples()).enumerate() {
            assert_eq!(a.source.start, positions[index]);
            assert_eq!(bytes[a.source.clone()], indexed[b.source.clone()]);
            assert_eq!(
                (
                    a.index,
                    a.decode_time,
                    a.duration,
                    a.composition_offset,
                    a.sync_sample,
                    a.contains_idr
                ),
                (
                    b.index,
                    b.decode_time,
                    b.duration,
                    b.composition_offset,
                    b.sync_sample,
                    b.contains_idr
                )
            );
        }
        for (first, count) in [(0, 10), (prefix as usize, 10 - prefix as usize)] {
            let stream = mixed.annex_b(first, count)?;
            assert_eq!(stream.bytes(), original.annex_b(first, count)?.bytes());
            for mapping in stream.mappings() {
                assert_eq!(
                    &stream.bytes()
                        [mapping.output_start..mapping.output_start + mapping.source.len()],
                    &bytes[mapping.source.clone()]
                );
            }
        }
    }
    Ok(())
}

#[test]
fn mixed_avc_and_hevc_decode_to_the_existing_independent_frame_hashes() -> Test {
    for (bytes, indexed, oracle, random_access) in [
        (
            AVC,
            INDEXED_AVC,
            include_str!("fixtures/indexed_avc_i420.sha256"),
            5,
        ),
        (
            HEVC,
            INDEXED_HEVC,
            include_str!("fixtures/hevc_av_i420.sha256"),
            3,
        ),
    ] {
        let mixed = AvcMp4::parse(bytes, None, DemuxLimits::default())?;
        let original = AvcMp4::parse(indexed, None, DemuxLimits::default())?;
        let expected: Vec<_> = oracle
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.split_whitespace().last().ok_or("missing frame hash"))
            .collect::<Result<_, _>>()?;
        assert_eq!(expected.len(), 10);
        let actual = decode(mixed.codec(), mixed.annex_b(0, 10)?.bytes())?;
        assert_eq!(actual, expected);
        assert_eq!(
            actual,
            decode(original.codec(), original.annex_b(0, 10)?.bytes())?
        );
        // HEVC's second GOP starts with a CRA and two RASLs: random access skips those
        // leading pictures, while a continuous full-movie decode emits all ten frames.
        assert_eq!(
            decode(
                mixed.codec(),
                mixed.annex_b(random_access, 10 - random_access)?.bytes()
            )?,
            expected[5..]
        );
    }
    Ok(())
}

#[test]
fn fragments_inherit_indexed_decode_end_and_preserve_explicit_gaps() -> Test {
    let original = AvcMp4::parse(AVC, None, DemuxLimits::default())?;
    let tfdt = tag(AVC, b"tfdt")?;
    assert_eq!(AVC[tfdt + 4], 1);
    let mut implicit = AVC.to_vec();
    implicit[tfdt..tfdt + 4].copy_from_slice(b"free");
    assert_eq!(
        AvcMp4::parse(&implicit, None, DemuxLimits::default())?.samples(),
        original.samples()
    );
    let mut gap = AVC.to_vec();
    gap[tfdt + 8..tfdt + 16].copy_from_slice(&10_247_u64.to_be_bytes());
    let gapped = AvcMp4::parse(&gap, None, DemuxLimits::default())?;
    assert_eq!(&gapped.samples()[..5], &original.samples()[..5]);
    for (actual, expected) in gapped.samples()[5..].iter().zip(&original.samples()[5..]) {
        assert_eq!(actual.decode_time, expected.decode_time + 7);
        assert_eq!(actual.presentation_time(), expected.presentation_time() + 7);
        assert_eq!(actual.duration, expected.duration);
        assert_eq!(actual.source, expected.source);
    }
    Ok(())
}

#[test]
fn backwards_fragment_time_and_invalid_indexed_duration_refuse_the_whole_movie() -> Test {
    let mut backwards = AVC.to_vec();
    let tfdt = tag(AVC, b"tfdt")?;
    backwards[tfdt + 8..tfdt + 16].copy_from_slice(&10_239_u64.to_be_bytes());
    let mut duration = AVC.to_vec();
    let mdhd = tag(AVC, b"mdhd")?;
    assert_eq!(AVC[mdhd + 4], 0);
    // mdhd describes the initial indexed movie, not the sum including its fragments.
    duration[mdhd + 20..mdhd + 24].copy_from_slice(&20_480_u32.to_be_bytes());
    for bytes in [backwards, duration] {
        assert_eq!(
            AvcMp4::parse(&bytes, None, DemuxLimits::default()).map(|_| ()),
            Err(DemuxError::Timeline)
        );
        assert_eq!(
            AvcMp4::parse_recovering_tail(&bytes, None, DemuxLimits::default(), &mut || Ok(()))
                .map(|_| ()),
            Err(DemuxError::Timeline)
        );
    }
    Ok(())
}

#[test]
fn legacy_hevc_duration_outside_the_admitted_profile_is_not_silently_normalized() -> Test {
    let mdhd = tag(HEVC, b"mdhd")?;
    assert_eq!(HEVC[mdhd + 4], 0);
    assert_eq!(mdhd + 20, 280);
    assert_eq!(word(HEVC, mdhd + 20)?, 6_144);
    let mut raw = HEVC.to_vec();
    // Reconstruct the exact original FFmpeg 6.1.1 remux, which uses its presentation
    // duration here. The admitted indexed profile requires the sum of decode deltas.
    raw[mdhd + 20..mdhd + 24].copy_from_slice(&10_240_u32.to_be_bytes());
    assert_eq!(
        hex(&ContentDigest::sha256(&raw).bytes()),
        "01550857c8e27ec3d6a8c8aead61c30f15f84dc0f508067169c1f89f7c89d037"
    );
    assert_eq!(
        AvcMp4::parse(&raw, None, DemuxLimits::default()).map(|_| ()),
        Err(DemuxError::Timeline)
    );
    assert_eq!(
        AvcMp4::parse_inband_recovering_tail(&raw, None, DemuxLimits::default(), &mut || Ok(()))
            .map(|_| ()),
        Err(DemuxError::Timeline)
    );
    Ok(())
}

#[test]
fn fragments_cannot_alias_the_initial_indexed_sample_ranges() -> Test {
    let original = AvcMp4::parse(AVC, None, DemuxLimits::default())?;
    let mut bytes = AVC.to_vec();
    let tfhd = tag(AVC, b"tfhd")?;
    assert_ne!(word(AVC, tfhd + 4)? & 1, 0);
    let base = u64::from_be_bytes(AVC[tfhd + 12..tfhd + 20].try_into()?);
    let offset =
        i32::try_from(i64::try_from(original.samples()[0].source.start)? - i64::try_from(base)?)?;
    let trun = tag(AVC, b"trun")?;
    assert_ne!(word(AVC, trun + 4)? & 1, 0);
    bytes[trun + 12..trun + 16].copy_from_slice(&offset.to_be_bytes());
    // Every fragment range still fits inside the first mdat, and fragment ranges do not
    // overlap each other. The cross-boundary source overlap must reject before NAL parsing.
    assert_eq!(
        AvcMp4::parse(&bytes, None, DemuxLimits::default()).map(|_| ()),
        Err(DemuxError::Layout)
    );
    Ok(())
}

#[test]
fn sample_work_and_output_limits_cover_both_indexed_and_fragment_parts() -> Test {
    let defaults = DemuxLimits::default();
    let full = AvcMp4::parse(AVC, None, defaults)?;
    let [boxes, entries, nals] = full.work();
    let size = full.annex_b(0, 10)?.bytes().len();
    let exact = DemuxLimits {
        maximum_samples: 10,
        maximum_boxes: boxes,
        maximum_table_entries: entries,
        maximum_nals: nals,
        maximum_output_bytes: size,
        ..defaults
    };
    assert_eq!(
        AvcMp4::parse(AVC, None, exact)?
            .annex_b(0, 10)?
            .bytes()
            .len(),
        size
    );
    for limits in [
        DemuxLimits {
            maximum_samples: 9,
            ..exact
        },
        DemuxLimits {
            maximum_boxes: boxes - 1,
            ..exact
        },
        DemuxLimits {
            maximum_table_entries: entries - 1,
            ..exact
        },
        DemuxLimits {
            maximum_nals: nals - 1,
            ..exact
        },
    ] {
        assert_eq!(
            AvcMp4::parse(AVC, None, limits).map(|_| ()),
            Err(DemuxError::Limit)
        );
    }
    let narrow = AvcMp4::parse(
        AVC,
        None,
        DemuxLimits {
            maximum_output_bytes: size - 1,
            ..exact
        },
    )?;
    assert_eq!(narrow.annex_b(0, 10).map(|_| ()), Err(DemuxError::Limit));
    assert!(narrow.annex_b(5, 5).is_ok());
    Ok(())
}

#[test]
fn cancellation_at_each_mixed_parse_checkpoint_returns_no_partial_index() -> Test {
    let limits = DemuxLimits::default();
    let mut visits = 0;
    AvcMp4::parse_with_checkpoint(AVC, None, limits, &mut || {
        visits += 1;
        Ok(())
    })?;
    for stop in 1..=visits {
        let mut seen = 0;
        assert_eq!(
            AvcMp4::parse_with_checkpoint(AVC, None, limits, &mut || {
                seen += 1;
                if seen == stop {
                    Err(DemuxError::Cancelled)
                } else {
                    Ok(())
                }
            })
            .map(|_| ()),
            Err(DemuxError::Cancelled),
            "checkpoint {stop}"
        );
        assert_eq!(seen, stop);
    }
    Ok(())
}

#[test]
fn every_torn_mixed_prefix_preserves_only_complete_indexed_and_fragment_media() -> Test {
    for (bytes, prefix) in [(AVC, 5), (HEVC, 3)] {
        let complete = AvcMp4::parse(bytes, None, DemuxLimits::default())?;
        let first_fragment = tag(bytes, b"moof")? - 4;
        let fragment_end = tag(bytes, b"mfra")? - 4;
        for cut in 0..=bytes.len() {
            let source = &bytes[..cut];
            let expected = if cut >= fragment_end {
                10
            } else if cut >= first_fragment {
                prefix
            } else {
                0
            };
            if let Ok(strict) = AvcMp4::parse(source, None, DemuxLimits::default()) {
                assert_eq!(strict.samples().len(), expected, "strict cut {cut}");
                assert_eq!(strict.truncated_tail(), None);
                assert!(cut == first_fragment || cut == fragment_end || cut == bytes.len());
            }
            let recovered =
                AvcMp4::parse_recovering_tail(source, None, DemuxLimits::default(), &mut || Ok(()));
            if expected == 0 {
                assert!(recovered.is_err(), "incomplete indexed media at {cut}");
                continue;
            }
            let recovered = recovered?;
            assert_eq!(
                recovered.samples(),
                &complete.samples()[..expected],
                "cut {cut}"
            );
            assert_eq!(recovered.source(), source);
            assert_eq!(
                recovered.truncated_tail(),
                if cut == first_fragment || cut == fragment_end || cut == bytes.len() {
                    None
                } else if cut < fragment_end {
                    Some(first_fragment)
                } else {
                    Some(fragment_end)
                },
                "cut {cut}"
            );
        }
        // Stopping exactly after the indexed movie remains a complete, playable prefix.
        assert_eq!(
            AvcMp4::parse(&bytes[..first_fragment], None, DemuxLimits::default())?
                .samples()
                .len(),
            prefix
        );
    }
    Ok(())
}

#[test]
fn init_only_movies_and_undeclared_or_malformed_extensions_still_refuse() -> Test {
    let fragmented = include_bytes!("fixtures/fragmented_av.mp4");
    let mut init = fragmented[..tag(fragmented, b"moof")? - 4].to_vec();
    assert!(AvcMp4::parse(&init, None, DemuxLimits::default()).is_err());
    init.extend_from_slice(&[0, 0, 0, 8, b'm', b'd', b'a', b't']);
    assert_eq!(
        AvcMp4::parse(&init, None, DemuxLimits::default()).map(|_| ()),
        Err(DemuxError::Layout)
    );
    let mut undeclared = AVC.to_vec();
    let mvex = tag(AVC, b"mvex")?;
    undeclared[mvex..mvex + 4].copy_from_slice(b"free");
    assert_eq!(
        AvcMp4::parse(&undeclared, None, DemuxLimits::default()).map(|_| ()),
        Err(DemuxError::Unsupported)
    );
    // Even before the first fragment, an extension's selected-track defaults must be valid.
    let mut prefix = AVC[..tag(AVC, b"moof")? - 4].to_vec();
    let trex = tag(AVC, b"trex")?;
    prefix[trex + 12..trex + 16].copy_from_slice(&2_u32.to_be_bytes());
    assert_eq!(
        AvcMp4::parse(&prefix, None, DemuxLimits::default()).map(|_| ()),
        Err(DemuxError::Unsupported)
    );
    Ok(())
}

#[test]
fn mixed_avc3_configurations_cover_the_indexed_and_fragment_samples() -> Test {
    let static_movie = AvcMp4::parse(AVC, None, DemuxLimits::default())?;
    let entry = static_movie.sample_entry_range().start + 4;
    let mut bytes = AVC.to_vec();
    bytes[entry..entry + 4].copy_from_slice(b"avc3");
    let inband = AvcMp4::parse_inband(&bytes, None, DemuxLimits::default())?;
    assert!(inband.uses_inband_configuration());
    assert_eq!(inband.samples(), static_movie.samples());
    for sample in inband.samples() {
        assert!(inband.sample_configuration(sample.index).is_some());
    }
    assert_eq!(
        inband.annex_b(0, 10)?.bytes(),
        static_movie.annex_b(0, 10)?.bytes()
    );
    Ok(())
}

#[test]
fn movie_queries_preserve_mixed_source_identity_edit_mapping_and_gap_bootstrap() -> Test {
    // Independent fixture tables: indexed movies shift media by 4096/10240 seconds;
    // the mixed remuxes have no edit list. Their corresponding movie queries differ by
    // 400 ticks. The frozen packet positions below straddle each layout's coding boundary.
    for (bytes, indexed, expected, positions, spans) in [
        (AVC, INDEXED_AVC, [4, 5], [4238, 4753], vec![(0, 5), (5, 1)]),
        (HEVC, INDEXED_HEVC, [4, 3], [4546, 3571], vec![(3, 2)]),
    ] {
        let mixed = AvcMp4::parse(bytes, None, DemuxLimits::default())?;
        let original = AvcMp4::parse(indexed, None, DemuxLimits::default())?;
        assert_eq!((mixed.movie_timescale(), mixed.timescale()), (1000, 10240));
        assert!(mixed.edits().is_empty());
        assert_eq!(original.edits().len(), 1);
        assert_eq!(original.edits()[0].media_time, 4096);
        let selected = mixed.select_movie_interval(1300..1500, MovieSelectionLimits::default())?;
        let reference =
            original.select_movie_interval(900..1100, MovieSelectionLimits::default())?;
        assert_eq!(selected.samples.len(), 2);
        assert_eq!(reference.samples.len(), 2);
        assert!(selected.gaps.is_empty());
        assert!(reference.gaps.is_empty());
        for (at, (actual, old)) in selected.samples.iter().zip(&reference.samples).enumerate() {
            assert_eq!(
                (actual.sample_index, old.sample_index),
                (expected[at], expected[at])
            );
            assert_eq!(actual.source.start, positions[at]);
            assert_eq!(actual.source, mixed.samples()[expected[at]].source);
            assert_eq!(bytes[actual.source.clone()], indexed[old.source.clone()]);
            assert_eq!((actual.edit_index, old.edit_index), (None, Some(0)));
            assert_eq!(actual.interval.denominator, 10240);
            assert_eq!(
                actual.interval.start_numerator,
                old.interval.start_numerator + 400 * 10240
            );
            assert_eq!(
                actual.interval.end_numerator,
                old.interval.end_numerator + 400 * 10240
            );
        }
        assert_eq!(
            selected
                .decode_spans
                .iter()
                .map(|span| (span.first_sample, span.sample_count))
                .collect::<Vec<_>>(),
            spans
        );
        let mut source_bytes = 0;
        let mut annex_b_bytes = 0;
        for span in &selected.decode_spans {
            let end = span.first_sample + span.sample_count;
            let extraction = mixed.annex_b(span.first_sample, span.sample_count)?;
            assert_eq!(
                extraction.bytes(),
                original
                    .annex_b(span.first_sample, span.sample_count)?
                    .bytes()
            );
            assert_eq!(span.annex_b_bytes, extraction.bytes().len() as u64);
            assert_eq!(
                span.source_bytes,
                mixed.samples()[span.first_sample..end]
                    .iter()
                    .map(|sample| sample.source.len() as u64)
                    .sum::<u64>()
            );
            source_bytes += span.source_bytes;
            annex_b_bytes += span.annex_b_bytes;
        }
        assert_eq!(
            selected.sample_bytes,
            expected
                .iter()
                .map(|index| mixed.samples()[*index].source.len() as u64)
                .sum::<u64>()
        );
        assert_eq!(selected.decode_bytes, source_bytes);
        assert_eq!(selected.annex_b_bytes, annex_b_bytes);
        // HEVC's requested RASL remains a source selection. The quote preserves existing
        // CRA admission; this does not claim that isolated CRA decoding emits that picture.
    }

    let mut gapped = AVC.to_vec();
    let tfdt = tag(AVC, b"tfdt")?;
    gapped[tfdt + 8..tfdt + 16].copy_from_slice(&20_480_u64.to_be_bytes());
    let parsed = AvcMp4::parse(&gapped, None, DemuxLimits::default())?;
    let selection = parsed.select_movie_interval(1300..2500, MovieSelectionLimits::default())?;
    assert_eq!(
        selection
            .samples
            .iter()
            .map(|sample| sample.sample_index)
            .collect::<Vec<_>>(),
        [4, 5]
    );
    assert_eq!(selection.gaps.len(), 1);
    assert_eq!(selection.gaps[0].kind, MovieGapKind::Unrepresented);
    assert_eq!(selection.gaps[0].interval.start_numerator, 1400 * 10240);
    assert_eq!(selection.gaps[0].interval.end_numerator, 2400 * 10240);
    let first_fragment = parsed.samples()[5].source.clone();
    let headers = length_prefixed_nals(&gapped[first_fragment.clone()], parsed.nal_length_bytes())?
        .into_iter()
        .filter(|nal| gapped[first_fragment.start + nal.start] & 31 == 5)
        .map(|nal| first_fragment.start + nal.start)
        .collect::<Vec<_>>();
    assert!(!headers.is_empty());
    for at in headers {
        gapped[at] = 0x41;
    }
    let missing = AvcMp4::parse(&gapped, None, DemuxLimits::default())?;
    assert!(missing.annex_b(0, 10).is_ok());
    assert_eq!(
        missing.select_movie_interval(2400..2500, MovieSelectionLimits::default()),
        Err(DemuxError::RandomAccessRequired)
    );
    Ok(())
}
