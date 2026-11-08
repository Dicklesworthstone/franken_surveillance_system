#![forbid(unsafe_code)]
//! Real RTP -> native fragmented MP4 -> movie selection -> native pixels -> timed Matroska.
//! This target proves component behavior, not retained custody, privacy authority, runtime,
//! filesystem durability or CLI execution. Import/receipt pins are explicit fixture metadata.

#[path = "../../fss-cli/src/bin/fss-file/movie_output.rs"]
mod movie_output;
#[path = "../../fss-cli/src/bin/fss-file/movie_timing.rs"]
mod movie_timing;
mod rtsp_movie_support;
#[path = "../../fss-cli/src/bin/fss-file/gray_matroska_stream/encoder.rs"]
mod stream;
#[path = "../../fss-reference/src/ingest/recorded_decode/video_access_unit.rs"]
mod video_access_unit;

use fss_container::demux::{
    AvcMp4, DemuxLimits, MovieSelection, MovieSelectionLimits, VideoCodec, length_prefixed_nals,
};
use fss_container::matroska_gray::TimedGrayMatroskaConfig;
use fss_container::{AvcMuxer, HevcMuxer, Mp4Limits, NalTarget};
use fss_core::ContentDigest;
use movie_output::{FrameInput, MovieOutput, SourceBinding};
use movie_timing::MovieTiming;
use rtsp_movie_support::{AVC_STEP, BASE, HEVC_STEP, Image, KEY, SCALE, Test};
use std::collections::BTreeMap;
use std::ops::Range;

fn avc_mp4() -> Test<Vec<u8>> {
    let source = rtsp_movie_support::avc()?;
    let first = source.pictures.first().ok_or("first AVC picture")?;
    let mut mux = AvcMuxer::new(
        KEY,
        first.sps().clone(),
        first.pps().clone(),
        SCALE,
        Mp4Limits::default(),
    )?;
    let fragment = mux.fragment(&rtsp_movie_support::avc_timing(&source.pictures))?;
    let init = mux.initialization().bytes();
    let mut bytes = init.to_vec();
    bytes.extend_from_slice(fragment.bytes());
    for mapping in fragment.mappings() {
        let nal = &source.pictures[mapping.sample].nals()[mapping.nal];
        assert_eq!(mapping.sources, nal.sources());
        let actual = match &mapping.target {
            NalTarget::Initialization(range) => &init[range.clone()],
            NalTarget::Media(range) => &fragment.bytes()[range.clone()],
        };
        assert_eq!(actual, nal.bytes());
    }
    let parsed = AvcMp4::parse(&bytes, None, DemuxLimits::default())?;
    for (sample, original) in parsed.samples().iter().zip(fragment.samples()) {
        assert_eq!(
            sample.source,
            init.len() + original.range.start..init.len() + original.range.end
        );
        assert_eq!(
            sample.presentation_time(),
            i128::from(original.presentation_time)
        );
        assert_ne!(original.rtp_timestamp as u64, original.decode_time);
    }
    Ok(bytes)
}

fn hevc_mp4() -> Test<Vec<u8>> {
    let source = rtsp_movie_support::hevc()?;
    let mut mux = HevcMuxer::new(KEY, source.configuration, SCALE, Mp4Limits::default())?;
    let fragment = mux.fragment(&rtsp_movie_support::hevc_timing(&source.pictures))?;
    let init = mux.initialization().bytes();
    let mut bytes = init.to_vec();
    bytes.extend_from_slice(fragment.bytes());
    for mapping in fragment.mappings() {
        let nal = &source.pictures[mapping.sample].nals()[mapping.nal];
        assert_eq!(mapping.sources, nal.sources());
        assert_eq!(&fragment.bytes()[mapping.range.clone()], nal.bytes());
    }
    let parsed = AvcMp4::parse(&bytes, None, DemuxLimits::default())?;
    for (sample, original) in parsed.samples().iter().zip(fragment.samples()) {
        assert_eq!(
            sample.source,
            init.len() + original.range.start..init.len() + original.range.end
        );
        assert_eq!(
            sample.presentation_time(),
            i128::from(original.presentation_time)
        );
        assert_ne!(original.rtp_timestamp as u64, original.decode_time);
    }
    Ok(bytes)
}

/// Exercise the same production access-unit driver as retained native ranges. Full-source
/// native_images is a separate oracle; this path opens every planned random-access span.
fn selected_decode(
    parsed: &AvcMp4<'_>,
    selection: &MovieSelection,
) -> Test<BTreeMap<usize, Image>> {
    let mut images = BTreeMap::new();
    for span in &selection.decode_spans {
        assert_eq!(
            parsed
                .annex_b(span.first_sample, span.sample_count)?
                .bytes()
                .len() as u64,
            span.annex_b_bytes
        );
        match parsed.codec() {
            VideoCodec::Avc => {
                let mut decoder = fss_codec_h264::Decoder::new(Default::default())?;
                for parameter in parsed.parameter_sets() {
                    assert!(
                        decoder
                            .decode_nal(&parsed.source()[parameter.clone()])?
                            .is_none()
                    );
                }
                let mut pictures = Vec::new();
                for segment in span.first_sample..span.first_sample + span.sample_count {
                    let bytes = &parsed.source()[parsed.samples()[segment].source.clone()];
                    let ranges = length_prefixed_nals(bytes, parsed.nal_length_bytes())?;
                    let nals: Vec<_> = ranges.iter().map(|range| &bytes[range.clone()]).collect();
                    pictures.extend(
                        video_access_unit::h264(&mut decoder, &nals, &mut || Ok(()))
                            .map_err(|error| format!("AVC access unit: {error:?}"))?,
                    );
                }
                pictures.extend(decoder.finish()?);
                assert_eq!(pictures.len(), span.sample_count);
                for picture in pictures {
                    assert!(
                        images
                            .insert(
                                span.first_sample + picture.decode_index() as usize,
                                Image {
                                    dimensions: [picture.width(), picture.height()],
                                    pixels: picture.luma().to_vec(),
                                }
                            )
                            .is_none()
                    );
                }
            }
            VideoCodec::Hevc => {
                let mut decoder = fss_codec_h265::Decoder::new(Default::default())?;
                for parameter in parsed.parameter_sets() {
                    assert!(
                        decoder
                            .decode_nal(&parsed.source()[parameter.clone()])?
                            .is_none()
                    );
                }
                let mut pictures = Vec::new();
                for segment in span.first_sample..span.first_sample + span.sample_count {
                    let bytes = &parsed.source()[parsed.samples()[segment].source.clone()];
                    let ranges = length_prefixed_nals(bytes, parsed.nal_length_bytes())?;
                    let nals: Vec<_> = ranges.iter().map(|range| &bytes[range.clone()]).collect();
                    let unit = video_access_unit::h265(&mut decoder, &nals, &mut || Ok(()))
                        .map_err(|error| format!("HEVC access unit: {error:?}"))?;
                    assert!(!unit.skipped_rasl);
                    pictures.extend(unit.output);
                }
                pictures.extend(decoder.finish()?);
                assert_eq!(pictures.len(), span.sample_count);
                for picture in pictures {
                    assert!(
                        images
                            .insert(
                                span.first_sample + picture.decode_index() as usize,
                                Image {
                                    dimensions: [picture.width(), picture.height()],
                                    pixels: picture.luma().to_vec(),
                                }
                            )
                            .is_none()
                    );
                }
            }
        }
    }
    Ok(images)
}

fn export(
    source: &[u8],
    query: Range<u64>,
    expected_indices: &[usize],
    intervals: &[(u64, u64)],
    duration_ns: u64,
) -> Test {
    let parsed = AvcMp4::parse(source, None, DemuxLimits::default())?;
    assert_eq!(parsed.samples().len(), 4);
    assert_eq!(parsed.samples()[0].decode_time, BASE);
    let selection = parsed.select_movie_interval(query, MovieSelectionLimits::default())?;
    assert_eq!(selection.movie_timescale, SCALE);
    assert_eq!(selection.media_timescale, SCALE);
    assert_eq!(
        selection
            .samples
            .iter()
            .map(|sample| sample.sample_index)
            .collect::<Vec<_>>(),
        expected_indices
    );
    let native = selected_decode(&parsed, &selection)?;
    let oracle = rtsp_movie_support::native_images(source)?;
    for (segment, image) in &native {
        assert_eq!(oracle.get(segment), Some(image));
    }
    let binding = SourceBinding {
        import_identity: ContentDigest::sha256(b"component test import metadata"),
        import_root: ContentDigest::sha256(b"component test import root metadata"),
        manifest_digest: ContentDigest::sha256(b"component test manifest metadata"),
        input_sha256: ContentDigest::sha256(source),
        track_id: parsed.track_id(),
        codec: parsed.codec(),
    };
    let mut output = MovieOutput::new(&selection, binding, movie_output::DEFAULT_LUMA_BYTES)?;
    for (segment, image) in &native {
        if output.wants(*segment) {
            output.insert(
                FrameInput {
                    segment: *segment,
                    dimensions: image.dimensions,
                    pixels: &image.pixels,
                    luma_sha256: ContentDigest::sha256(&image.pixels).bytes(),
                    decode_receipt: ContentDigest::sha256(
                        format!("native component fixture segment {segment}").as_bytes(),
                    ),
                },
                &mut || Ok(()),
            )?;
        }
    }
    let complete = output.finish(&mut || Ok(()))?;
    let timing = MovieTiming::new(&selection, &mut || Ok(()))?;
    assert_eq!(timing.duration_ns(), duration_ns);
    assert_eq!(timing.frames(), expected_indices.len());
    let mut encoder = stream::Encoder::<Vec<u8>>::new_movie(
        stream::DEFAULT_OUTPUT_BYTES,
        complete.frames(),
        timing.duration_ns(),
        complete.lineage_digest(),
    )?;
    let mut expected = Vec::new();
    for (ordinal, (&segment, &(start, end))) in expected_indices.iter().zip(intervals).enumerate() {
        let frame = complete.frame(ordinal).ok_or("selected frame")?;
        assert_eq!(frame.segment, segment);
        let time = timing.frame(ordinal).ok_or("selected timing")?;
        assert_eq!((time.start_ns, time.end_ns), (start, end));
        let original = oracle.get(&segment).ok_or("source pixel oracle")?;
        assert_eq!(frame.pixels(), original.pixels);
        let config = TimedGrayMatroskaConfig::new(frame.dimensions, duration_ns)?;
        if ordinal == 0 {
            expected.extend_from_slice(config.initialization()?.bytes());
        }
        expected.extend_from_slice(config.frame(ordinal as u64, start, end)?.prefix());
        expected.extend_from_slice(&original.pixels);
        encoder.frame_at(
            stream::FrameInput {
                dimensions: frame.dimensions,
                pixels: frame.pixels(),
                luma_sha256: frame.luma_sha256,
                decode_receipt: frame.decode_receipt,
            },
            start,
            end,
            || Ok(Vec::new()),
            &mut || Ok(()),
        )?;
    }
    let (bytes, receipt) = encoder.finish(&mut || Ok(()))?;
    assert_eq!(bytes, expected);
    assert_eq!(receipt.frames, expected_indices.len());
    assert_eq!(receipt.duration_ns, duration_ns);
    assert_eq!(receipt.digest, ContentDigest::sha256(&expected));
    Ok(())
}

#[test]
fn original_avc_rtp_fragments_select_reordered_clipped_pictures_on_native_movie_clock() -> Test {
    export(
        &avc_mp4()?,
        94_500..99_900,
        &[2, 1],
        &[(0, 30_000_000), (30_000_000, 60_000_000)],
        60_000_000,
    )
}

#[test]
fn original_hevc_rtp_fragments_select_reordered_clipped_pictures_on_native_movie_clock() -> Test {
    export(
        &hevc_mp4()?,
        112_500..139_500,
        &[2, 1],
        &[(0, 150_000_000), (150_000_000, 300_000_000)],
        300_000_000,
    )
}

#[test]
fn native_avc_tfdt_leading_and_trailing_holes_keep_the_full_query_envelope() -> Test {
    let end = BASE + 4 * u64::from(AVC_STEP) + 900;
    export(
        &avc_mp4()?,
        0..end,
        &[0, 2, 1, 3],
        &[
            (1_000_000_000, 1_040_000_000),
            (1_040_000_000, 1_080_000_000),
            (1_080_000_000, 1_120_000_000),
            (1_120_000_000, 1_160_000_000),
        ],
        1_170_000_000,
    )
}

#[test]
fn native_hevc_tfdt_leading_and_trailing_holes_keep_the_full_query_envelope() -> Test {
    let end = BASE + 4 * u64::from(HEVC_STEP) + 900;
    export(
        &hevc_mp4()?,
        0..end,
        &[0, 2, 1, 3],
        &[
            (1_000_000_000, 1_200_000_000),
            (1_200_000_000, 1_400_000_000),
            (1_400_000_000, 1_600_000_000),
            (1_600_000_000, 1_800_000_000),
        ],
        1_810_000_000,
    )
}
