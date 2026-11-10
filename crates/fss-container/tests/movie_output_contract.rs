#![forbid(unsafe_code)]
//! Exact production movie materialization, MP4 demux, native sample driver and lossless writer.
//! This target does not substitute for retained custody, privacy authorization, async runtime,
//! filesystem durability or CLI process tests. Source/receipt pins below are test metadata;
//! native pictures and the exercised production implementations are real, not codec stubs.

#[path = "../../fss-reference/src/review_media/render/output.rs"]
mod movie_output;
#[path = "../../fss-cli/src/bin/fss-file/gray_matroska_stream/encoder.rs"]
mod stream;
#[path = "../../fss-reference/src/ingest/recorded_decode/video_access_unit.rs"]
mod video_access_unit;

use fss_codec_h264 as avc;
use fss_codec_h265 as hevc;
use fss_container::demux::{
    AvcMp4, DemuxLimits, MovieDecodeSpan, MovieEditSelection, MovieGap, MovieGapKind,
    MovieInterval, MovieSampleSelection, MovieSelection, MovieSelectionLimits, VideoCodec,
    length_prefixed_nals,
};
use fss_container::matroska_gray::{GrayMatroskaConfig, PlaybackRate};
use fss_core::ContentDigest;
use movie_output::{
    CompleteMovieOutput, DEFAULT_LUMA_BYTES, FrameInput, MAX_LUMA_BYTES, MAX_MOVIE_FRAMES,
    MovieOutput, MovieOutputError, SourceBinding,
};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const AVC: &[u8] = include_bytes!("fixtures/indexed_avc.mp4");
const HEVC: &[u8] = include_bytes!("fixtures/hevc_av.mp4");

fn source(bytes: &[u8], codec: VideoCodec) -> SourceBinding {
    SourceBinding {
        import_identity: ContentDigest::sha256(b"test import identity"),
        import_root: ContentDigest::sha256(b"test import root"),
        manifest_digest: ContentDigest::sha256(b"test manifest"),
        input_sha256: ContentDigest::sha256(bytes),
        track_id: 1,
        codec,
    }
}

struct NativeFrame {
    segment: usize,
    dimensions: [u32; 2],
    pixels: Vec<u8>,
    i420_sha256: [u8; 32],
}

impl NativeFrame {
    fn input(&self) -> FrameInput<'_> {
        // A fixture-only receipt pin, never a retained decoding receipt or custody claim.
        let mut receipt = b"movie-output-contract native fixture metadata".to_vec();
        receipt.extend_from_slice(&(self.segment as u64).to_le_bytes());
        receipt.extend_from_slice(&self.i420_sha256);
        FrameInput {
            segment: self.segment,
            dimensions: self.dimensions,
            pixels: &self.pixels,
            luma_sha256: ContentDigest::sha256(&self.pixels).bytes(),
            decode_receipt: ContentDigest::sha256(&receipt),
        }
    }
}

fn native_frames(
    parsed: &AvcMp4<'_>,
    selection: &MovieSelection,
) -> Test<(Vec<NativeFrame>, Vec<usize>)> {
    let mut frames = Vec::new();
    let mut skipped = Vec::new();
    for span in &selection.decode_spans {
        // Exercise real indexed extraction too, including its random-access and quote checks.
        assert_eq!(
            parsed
                .annex_b(span.first_sample, span.sample_count)?
                .bytes()
                .len() as u64,
            span.annex_b_bytes
        );
        let mut segments = Vec::new();
        match parsed.codec() {
            VideoCodec::Avc => {
                let mut decoder = avc::Decoder::new(avc::DecoderLimits::default())?;
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
                            .map_err(|error| format!("AVC sample {segment}: {error:?}"))?,
                    );
                    segments.push(segment);
                }
                pictures.extend(decoder.finish()?);
                assert_eq!(pictures.len(), span.sample_count);
                for picture in pictures {
                    frames.push(NativeFrame {
                        segment: segments[picture.decode_index() as usize],
                        dimensions: [picture.width(), picture.height()],
                        pixels: picture.luma().to_vec(),
                        i420_sha256: picture.i420_sha256(),
                    });
                }
            }
            VideoCodec::Hevc => {
                let mut decoder = hevc::Decoder::new(hevc::DecoderLimits::default())?;
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
                        .map_err(|error| format!("HEVC sample {segment}: {error:?}"))?;
                    if unit.skipped_rasl {
                        skipped.push(segment);
                    } else {
                        segments.push(segment);
                    }
                    pictures.extend(unit.output);
                }
                pictures.extend(decoder.finish()?);
                assert_eq!(pictures.len(), segments.len());
                for picture in pictures {
                    frames.push(NativeFrame {
                        segment: segments[picture.decode_index() as usize],
                        dimensions: [picture.width(), picture.height()],
                        pixels: picture.luma().to_vec(),
                        i420_sha256: picture.i420_sha256(),
                    });
                }
            }
        }
    }
    Ok((frames, skipped))
}

fn materialize(
    selection: &MovieSelection,
    binding: SourceBinding,
    frames: &[NativeFrame],
) -> Test<CompleteMovieOutput> {
    let mut output = MovieOutput::new(selection, binding, DEFAULT_LUMA_BYTES)?;
    for frame in frames {
        if output.wants(frame.segment) {
            output.insert(frame.input(), &mut || Ok(()))?;
        }
    }
    Ok(output.finish(&mut || Ok(()))?)
}

#[test]
fn real_avc_movie_selection_exports_exact_requested_pictures_in_movie_order() -> Test {
    let parsed = AvcMp4::parse(AVC, None, DemuxLimits::default())?;
    let selection = parsed.select_movie_interval(400..800, MovieSelectionLimits::default())?;
    assert_eq!(
        selection
            .samples
            .iter()
            .map(|s| s.sample_index)
            .collect::<Vec<_>>(),
        [3, 1]
    );
    assert_eq!(selection.decode_spans[0].requested_samples, [1, 3]);
    assert_eq!(selection.decode_spans[0].sample_count, 4);
    let (frames, skipped) = native_frames(&parsed, &selection)?;
    assert!(skipped.is_empty());
    assert_eq!(
        frames.iter().map(|f| f.segment).collect::<Vec<_>>(),
        [0, 2, 3, 1]
    );
    let oracle: Vec<_> = include_str!("fixtures/indexed_avc_i420.sha256")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_whitespace().nth(2))
        .collect();
    for (frame, expected) in frames.iter().zip(oracle) {
        let actual: String = frame
            .i420_sha256
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(actual, expected);
    }
    let complete = materialize(&selection, source(AVC, parsed.codec()), &frames)?;
    assert_eq!(
        (
            complete.frames(),
            complete.unique_frames(),
            complete.luma_bytes()
        ),
        (2, 2, 6144)
    );
    assert_eq!(complete.frame(0).ok_or("first missing")?.segment, 3);
    assert_eq!(complete.frame(1).ok_or("second missing")?.segment, 1);
    assert!(complete.frame(2).is_none());
    assert_lossless_stream(&complete)?;
    Ok(())
}

fn assert_lossless_stream(complete: &CompleteMovieOutput) -> Test {
    let rate = PlaybackRate::new(30_000, 1001)?;
    let mut encoder =
        stream::Encoder::<Vec<u8>>::new(stream::DEFAULT_OUTPUT_BYTES, complete.frames(), rate)?;
    for ordinal in 0..complete.frames() {
        let frame = complete.frame(ordinal).ok_or("missing output occurrence")?;
        encoder.frame(
            stream::FrameInput {
                dimensions: frame.dimensions,
                pixels: frame.pixels(),
                luma_sha256: frame.luma_sha256,
                decode_receipt: frame.decode_receipt,
            },
            || Ok(Vec::new()),
            &mut || Ok(()),
        )?;
    }
    let (bytes, receipt) = encoder.finish(&mut || Ok(()))?;
    assert_eq!(receipt.frames, complete.frames());
    assert_eq!(receipt.bytes, bytes.len() as u64);
    assert_eq!(receipt.digest, ContentDigest::sha256(&bytes));
    let config = GrayMatroskaConfig::new(receipt.dimensions, rate)?;
    let mut offset = config.initialization()?.bytes().len();
    for ordinal in 0..complete.frames() {
        let frame = complete.frame(ordinal).ok_or("missing output occurrence")?;
        let framing = config.frame(ordinal as u64)?;
        assert_eq!(
            &bytes[offset..offset + framing.prefix().len()],
            framing.prefix()
        );
        offset += framing.prefix().len();
        assert_eq!(
            &bytes[offset..offset + frame.pixels().len()],
            frame.pixels()
        );
        offset += frame.pixels().len();
    }
    assert_eq!(offset, bytes.len());
    assert_eq!(
        receipt.duration_ns,
        (complete.frames() as u64 * 1_000_000_000 * 1001) / 30_000
    );
    Ok(())
}

#[test]
fn real_hevc_idr_selection_completes_but_selected_leading_rasl_cannot() -> Test {
    let parsed = AvcMp4::parse(HEVC, None, DemuxLimits::default())?;
    let selection = parsed.select_movie_interval(0..400, MovieSelectionLimits::default())?;
    assert_eq!(
        selection
            .samples
            .iter()
            .map(|s| s.sample_index)
            .collect::<Vec<_>>(),
        [0, 2]
    );
    let (frames, skipped) = native_frames(&parsed, &selection)?;
    assert!(skipped.is_empty());
    let complete = materialize(&selection, source(HEVC, parsed.codec()), &frames)?;
    assert_eq!(complete.frames(), 2);
    assert_lossless_stream(&complete)?;

    let selection = parsed.select_movie_interval(600..800, MovieSelectionLimits::default())?;
    assert_eq!(
        selection
            .samples
            .iter()
            .map(|s| s.sample_index)
            .collect::<Vec<_>>(),
        [5]
    );
    assert_eq!(
        (
            selection.decode_spans[0].first_sample,
            selection.decode_spans[0].sample_count
        ),
        (3, 3)
    );
    let (frames, skipped) = native_frames(&parsed, &selection)?;
    assert_eq!(skipped, [4, 5]);
    assert_eq!(frames.iter().map(|f| f.segment).collect::<Vec<_>>(), [3]);
    let mut output =
        MovieOutput::new(&selection, source(HEVC, parsed.codec()), DEFAULT_LUMA_BYTES)?;
    for frame in frames {
        if output.wants(frame.segment) {
            output.insert(frame.input(), &mut || Ok(()))?;
        }
    }
    assert!(matches!(
        output.finish(&mut || Ok(())),
        Err(MovieOutputError::Missing)
    ));
    Ok(())
}

fn interval(start: u128, end: u128) -> MovieInterval {
    MovieInterval {
        start_numerator: start,
        end_numerator: end,
        denominator: 1,
    }
}

/// Deliberately small metadata plans for materialization invariants, never decoder inputs.
fn plan(indices: &[usize]) -> MovieSelection {
    let mut unique = indices.to_vec();
    unique.sort_unstable();
    unique.dedup();
    let first = unique[0];
    let count = unique[unique.len() - 1] - first + 1;
    MovieSelection {
        query: 0..indices.len() as u64,
        movie_timescale: 1,
        media_timescale: 1,
        samples: indices
            .iter()
            .enumerate()
            .map(|(i, segment)| MovieSampleSelection {
                sample_index: *segment,
                edit_index: Some(i),
                source: 100 + segment..101 + segment,
                interval: interval(i as u128, i as u128 + 1),
            })
            .collect(),
        edits: indices
            .iter()
            .enumerate()
            .map(|(i, segment)| MovieEditSelection {
                edit_index: Some(i),
                interval: interval(i as u128, i as u128 + 1),
                media_time: Some(*segment as u64),
            })
            .collect(),
        gaps: Vec::new(),
        decode_spans: vec![MovieDecodeSpan {
            first_sample: first,
            sample_count: count,
            requested_samples: unique.clone(),
            source_bytes: count as u64,
            annex_b_bytes: count as u64 * 5,
        }],
        work: 1,
        sample_bytes: unique.len() as u64,
        decode_bytes: count as u64,
        annex_b_bytes: count as u64 * 5,
    }
}

fn pixels(segment: usize, dimensions: [u32; 2], fill: u8) -> NativeFrame {
    NativeFrame {
        segment,
        dimensions,
        pixels: vec![fill; dimensions[0] as usize * dimensions[1] as usize],
        i420_sha256: ContentDigest::sha256(&[fill]).bytes(),
    }
}

#[test]
fn repeated_backward_edits_reuse_unique_pixels_and_keep_every_occurrence() -> Test {
    let selection = plan(&[1, 2, 0, 1]);
    let frames = [
        pixels(0, [2, 2], 7),
        pixels(1, [2, 2], 49),
        pixels(2, [2, 2], 208),
    ];
    let complete = materialize(&selection, source(b"edited", VideoCodec::Avc), &frames)?;
    assert_eq!(
        (
            complete.frames(),
            complete.unique_frames(),
            complete.luma_bytes()
        ),
        (4, 3, 12)
    );
    assert_eq!(
        (0..4)
            .map(|i| complete.frame(i).expect("occurrence").segment)
            .collect::<Vec<_>>(),
        [1, 2, 0, 1]
    );
    assert!(std::ptr::eq(
        complete.frame(0).ok_or("first")?,
        complete.frame(3).ok_or("repeat")?
    ));
    assert_lossless_stream(&complete)?;
    Ok(())
}

#[test]
fn sparse_original_segment_indices_do_not_expand_the_luma_cache() -> Test {
    let selection = plan(&[65_000, 65_000]);
    let frame = pixels(65_000, [1, 1], 51);
    let mut output = MovieOutput::new(&selection, source(b"sparse", VideoCodec::Avc), 1)?;
    assert!(!output.wants(0));
    assert!(output.wants(65_000));
    output.insert(frame.input(), &mut || Ok(()))?;
    let complete = output.finish(&mut || Ok(()))?;
    assert_eq!(
        (
            complete.frames(),
            complete.unique_frames(),
            complete.luma_bytes()
        ),
        (2, 1, 1)
    );
    Ok(())
}

#[test]
fn aggregate_luma_limit_reserves_each_whole_unique_frame_and_fences_late_refusal() -> Test {
    let selection = plan(&[0, 1, 0]);
    let frames = [pixels(0, [2, 2], 10), pixels(1, [2, 2], 20)];
    for maximum in [7, 8] {
        let mut output = MovieOutput::new(&selection, source(b"budget", VideoCodec::Avc), maximum)?;
        output.insert(frames[0].input(), &mut || Ok(()))?;
        let result = output.insert(frames[1].input(), &mut || Ok(()));
        if maximum == 7 {
            assert_eq!(result, Err(MovieOutputError::Limit));
            assert!(matches!(
                output.finish(&mut || Ok(())),
                Err(MovieOutputError::Fenced)
            ));
        } else {
            result?;
            assert_eq!(output.finish(&mut || Ok(()))?.luma_bytes(), 8);
        }
    }
    for maximum in [0, MAX_LUMA_BYTES + 1] {
        assert!(matches!(
            MovieOutput::new(&selection, source(b"budget", VideoCodec::Avc), maximum),
            Err(MovieOutputError::Limit)
        ));
    }
    Ok(())
}

#[test]
fn duplicate_missing_unwanted_shape_and_pixel_pin_failures_never_complete() -> Test {
    let selection = plan(&[0, 1]);
    let frame = pixels(0, [2, 2], 10);
    for case in 0..5 {
        let mut output = MovieOutput::new(&selection, source(b"refusal", VideoCodec::Avc), 8)?;
        output.insert(frame.input(), &mut || Ok(()))?;
        let mut second = frame.input();
        let expected = match case {
            0 => MovieOutputError::Duplicate,
            1 => {
                second.segment = 3;
                MovieOutputError::InvalidFrame
            }
            2 => {
                second.segment = 1;
                second.dimensions = [4, 4];
                MovieOutputError::InvalidFrame
            }
            3 => {
                second.segment = 1;
                second.luma_sha256 = [0; 32];
                MovieOutputError::InvalidFrame
            }
            _ => {
                second.segment = 1;
                second.decode_receipt =
                    ContentDigest::new(fss_core::DigestAlgorithm::Sha256, [0; 32]);
                MovieOutputError::InvalidFrame
            }
        };
        assert_eq!(output.insert(second, &mut || Ok(())), Err(expected));
        assert!(matches!(
            output.finish(&mut || Ok(())),
            Err(MovieOutputError::Fenced)
        ));
    }
    let mut output = MovieOutput::new(&selection, source(b"missing", VideoCodec::Avc), 8)?;
    output.insert(frame.input(), &mut || Ok(()))?;
    assert!(matches!(
        output.finish(&mut || Ok(())),
        Err(MovieOutputError::Missing)
    ));
    Ok(())
}

#[test]
fn cancellation_at_every_copy_checkpoint_and_finalization_checkpoint_refuses() -> Test {
    let selection = plan(&[0]);
    let frame = pixels(0, [128, 128], 61);
    let binding = source(b"cancellation", VideoCodec::Avc);
    let mut baseline = MovieOutput::new(&selection, binding, DEFAULT_LUMA_BYTES)?;
    let mut insert_checks = 0;
    baseline.insert(frame.input(), &mut || {
        insert_checks += 1;
        Ok(())
    })?;
    let mut finish_checks = 0;
    baseline.finish(&mut || {
        finish_checks += 1;
        Ok(())
    })?;
    assert!(insert_checks >= 6);
    assert!(finish_checks >= 6);
    for cancelled in 1..=insert_checks {
        let mut output = MovieOutput::new(&selection, binding, DEFAULT_LUMA_BYTES)?;
        let mut checks = 0;
        assert_eq!(
            output.insert(frame.input(), &mut || {
                checks += 1;
                if checks == cancelled {
                    Err(MovieOutputError::Cancelled)
                } else {
                    Ok(())
                }
            }),
            Err(MovieOutputError::Cancelled)
        );
        assert!(matches!(
            output.finish(&mut || Ok(())),
            Err(MovieOutputError::Fenced)
        ));
    }
    for cancelled in 1..=finish_checks {
        let mut output = MovieOutput::new(&selection, binding, DEFAULT_LUMA_BYTES)?;
        output.insert(frame.input(), &mut || Ok(()))?;
        let mut checks = 0;
        assert!(matches!(
            output.finish(&mut || {
                checks += 1;
                if checks == cancelled {
                    Err(MovieOutputError::Cancelled)
                } else {
                    Ok(())
                }
            }),
            Err(MovieOutputError::Cancelled)
        ));
    }
    Ok(())
}

#[test]
fn count_and_decode_span_limits_apply_before_materialization() -> Test {
    let binding = source(b"limits", VideoCodec::Avc);
    let mut selection = plan(&[0]);
    selection
        .samples
        .resize(MAX_MOVIE_FRAMES + 1, selection.samples[0].clone());
    assert!(matches!(
        MovieOutput::new(&selection, binding, DEFAULT_LUMA_BYTES),
        Err(MovieOutputError::Limit)
    ));
    let selection = plan(&[0, MAX_MOVIE_FRAMES]);
    assert!(matches!(
        MovieOutput::new(&selection, binding, DEFAULT_LUMA_BYTES),
        Err(MovieOutputError::Limit)
    ));
    let mut selection = plan(&[0, 1]);
    selection.decode_spans = vec![
        MovieDecodeSpan {
            first_sample: 0,
            sample_count: 600,
            requested_samples: vec![0],
            source_bytes: 600,
            annex_b_bytes: 3000,
        },
        MovieDecodeSpan {
            first_sample: 600,
            sample_count: 600,
            requested_samples: vec![1],
            source_bytes: 600,
            annex_b_bytes: 3000,
        },
    ];
    assert!(matches!(
        MovieOutput::new(&selection, binding, DEFAULT_LUMA_BYTES),
        Err(MovieOutputError::Limit)
    ));
    Ok(())
}

#[test]
fn malformed_plan_quotes_membership_and_interval_coverage_are_refused() -> Test {
    for case in 0..9 {
        let mut selection = plan(&[0, 1]);
        match case {
            0 => selection.sample_bytes += 1,
            1 => selection.decode_bytes += 1,
            2 => selection.annex_b_bytes += 1,
            3 => selection.decode_spans[0]
                .requested_samples
                .pop()
                .map(|_| ())
                .unwrap_or(()),
            4 => selection.decode_spans[0].requested_samples.reverse(),
            5 => selection.samples[1].interval.start_numerator = 0,
            6 => selection.query.end += 1,
            7 => selection.samples[1].edit_index = Some(99),
            _ => selection.edits[1].media_time = None,
        }
        assert!(
            matches!(
                MovieOutput::new(
                    &selection,
                    source(b"invalid", VideoCodec::Avc),
                    DEFAULT_LUMA_BYTES
                ),
                Err(MovieOutputError::InvalidPlan)
            ),
            "case {case}"
        );
    }
    Ok(())
}

#[test]
fn lineage_binds_source_receipts_movie_intervals_edits_gaps_and_repeated_occurrences() -> Test {
    let mut selection = plan(&[0, 1, 0]);
    selection.query.end += 1;
    selection.gaps.push(MovieGap {
        interval: interval(3, 4),
        kind: MovieGapKind::Unrepresented,
    });
    let frames = [pixels(0, [2, 2], 12), pixels(1, [2, 2], 21)];
    let binding = source(b"lineage", VideoCodec::Avc);
    let reference = materialize(&selection, binding, &frames)?.lineage_digest();
    let reversed = [pixels(1, [2, 2], 21), pixels(0, [2, 2], 12)];
    assert_eq!(
        materialize(&selection, binding, &reversed)?.lineage_digest(),
        reference
    );
    for case in 0..7 {
        let mut changed = selection.clone();
        let mut changed_source = binding;
        let mut changed_frames = [pixels(0, [2, 2], 12), pixels(1, [2, 2], 21)];
        match case {
            0 => changed_source.import_root = ContentDigest::sha256(b"different root"),
            1 => changed.gaps[0].kind = MovieGapKind::EmptyEdit,
            2 => changed.edits[2].media_time = Some(99),
            3 => {
                changed_frames[0].i420_sha256 = ContentDigest::sha256(b"different receipt").bytes()
            }
            4 => changed_frames[0].pixels[0] ^= 1,
            5 => {
                changed.query.end += 1;
                changed.gaps[0].interval.end_numerator += 1;
            }
            _ => changed.movie_timescale = 2,
        }
        assert_ne!(
            materialize(&changed, changed_source, &changed_frames)?.lineage_digest(),
            reference,
            "case {case}"
        );
    }
    Ok(())
}
