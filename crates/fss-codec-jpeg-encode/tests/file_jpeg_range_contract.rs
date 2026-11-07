#![forbid(unsafe_code)]
//! Executes the production range owner, JPEG codec, selector and lossless stream core.
//! Retained custody, CLI processes and filesystem sync are separate process-test boundaries.

extern crate self as fss_container;
#[path = "../../fss-container/src/matroska_gray.rs"]
pub mod matroska_gray;
#[path = "../../fss-cli/src/bin/fss-file/frame_range.rs"]
mod range;
#[path = "../../fss-cli/src/bin/fss-file/gray_matroska_stream/encoder.rs"]
mod stream;
#[path = "../../fss-reference/src/ingest/recorded_decode/window.rs"]
mod window;

use fss_codec_jpeg_encode::{EncodeBudget, EncodeConfig, EncodeLimits, PixelFormat, encode_jpeg};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits, decode_luma};
use fss_core::{
    CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, ContentDigest, SensorCapsule,
    SensorId, SensorSourceBytesSpec, StreamId, TimestampNs,
};
use matroska_gray::{GrayMatroskaConfig, PlaybackRate};
use range::FrameRange;
use std::cell::RefCell;
use std::io::{self, Write};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use window::{
    DecodedOutputWindow, FrameWindowReceipt, FrameWindowSelector, FrameWindowSource,
    FrameWindowTimeProvenance,
};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Source {
    bytes: Vec<u8>,
    capsule: SensorCapsule,
}

fn source(segment: usize, dimensions: [u32; 2]) -> Test<Source> {
    let pixels: Vec<_> = (0..dimensions[0] * dimensions[1])
        .map(|i| ((i as usize * 7 + segment * 43) % 256) as u8)
        .collect();
    let encoded = encode_jpeg(
        dimensions[0],
        dimensions[1],
        &pixels,
        ContentDigest::sha256(&pixels).bytes(),
        EncodeConfig {
            quality: 85,
            format: PixelFormat::Grayscale,
        },
        &EncodeLimits::default(),
        &mut EncodeBudget::new(100_000_000),
    )?;
    let bytes = encoded.bytes().to_vec();
    let time = (segment as i128 + 1) * 10;
    let capsule = SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
        capsule_id: CapsuleId::parse(format!("capsule:jpeg-range:{segment}"))?,
        sensor_id: SensorId::parse("sensor:jpeg-range")?,
        stream_id: StreamId::parse("stream:jpeg-range")?,
        sequence: segment as u64,
        capture: CaptureInterval::point(TimestampNs(time)),
        receive_time: TimestampNs(100),
        clock_basis: ClockBasis::Estimated,
        source: &bytes,
        frame_count: 1,
        gap_before: false,
    })?;
    Ok(Source { bytes, capsule })
}

fn sources() -> Test<Vec<Source>> {
    (0..3).map(|segment| source(segment, [7, 5])).collect()
}

#[derive(Default)]
struct Sink {
    bytes: Vec<u8>,
    creations: usize,
    completions: usize,
    segments: Vec<usize>,
}

#[derive(Clone, Default)]
struct Writer(Rc<RefCell<Sink>>);

impl Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len().min(13);
        self.0.borrow_mut().bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Options {
    first: usize,
    count: usize,
    maximum: u64,
    start: i128,
    end: i128,
    cancel_after: Option<usize>,
    time_provenance: FrameWindowTimeProvenance,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            first: 0,
            count: 3,
            maximum: stream::DEFAULT_OUTPUT_BYTES,
            start: 0,
            end: 100,
            cancel_after: None,
            time_provenance: FrameWindowTimeProvenance::OperatorAssumption,
        }
    }
}

fn check(cancelled: &AtomicBool) -> io::Result<()> {
    if cancelled.load(Ordering::Acquire) {
        Err(io::Error::other("range cancelled"))
    } else {
        Ok(())
    }
}

fn run(
    sources: &[Source],
    options: Options,
    budget: &mut DecodeBudget<'_>,
    writer: &Writer,
    cancelled: &AtomicBool,
) -> Test<(FrameWindowReceipt, stream::StreamReceipt)> {
    let range = FrameRange::new(options.first, options.count, sources.len())?;
    let request = DecodedOutputWindow::new(
        TimestampNs(options.start),
        TimestampNs(options.end),
        ClockBasis::Estimated,
    )?;
    assert_eq!(
        (request.start().0, request.end().0),
        (options.start, options.end)
    );
    assert_eq!(request.clock_basis(), ClockBasis::Estimated);
    let selector = FrameWindowSelector::new(
        request,
        FrameWindowSource {
            import_identity: ContentDigest::sha256(b"JPEG range fixture"),
            import_root: ContentDigest::sha256(b"JPEG range fixture root"),
            first_segment: options.first as u64,
            segment_count: options.count,
            time_provenance: options.time_provenance,
        },
    )?;
    let encoder = stream::Encoder::new(
        options.maximum,
        options.count,
        PlaybackRate::new(30_000, 1001)?,
    )?;
    range.run(
        budget,
        (selector, encoder),
        |segment, budget| {
            check(cancelled)?;
            let source = &sources[segment];
            let image = decode_luma(
                &source.bytes,
                ContentDigest::sha256(&source.bytes).bytes(),
                ComponentInterpretation::Grayscale,
                DecodeLimits::default(),
                budget,
            )?;
            Ok(image)
        },
        |(selector, encoder), ordinal, segment, image| {
            check(cancelled)?;
            let capsule = &sources[segment].capsule;
            let pin = ContentDigest::sha256(&capsule.try_canonical_bytes()?);
            if selector.observe(ordinal as u64, segment as u64, capsule, pin, false)? {
                encoder.frame(
                    stream::FrameInput {
                        dimensions: image.dimensions(),
                        pixels: image.pixels(),
                        luma_sha256: image.receipt().luma_sha256,
                        decode_receipt: pin,
                    },
                    || {
                        writer.0.borrow_mut().creations += 1;
                        Ok(writer.clone())
                    },
                    &mut || check(cancelled),
                )?;
                writer.0.borrow_mut().segments.push(segment);
            }
            if options.cancel_after == Some(ordinal) {
                cancelled.store(true, Ordering::Release);
            }
            Ok(())
        },
        |(selector, encoder), processed| {
            check(cancelled)?;
            let selection = selector.finish(processed as u64, false)?;
            let (_, media) = encoder.finish(&mut || check(cancelled))?;
            writer.0.borrow_mut().completions += 1;
            Ok((selection, media))
        },
    )
}

fn expected(sources: &[Source]) -> Test<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut budget = DecodeBudget::new(100_000_000);
    for (ordinal, source) in sources.iter().enumerate() {
        let image = decode_luma(
            &source.bytes,
            ContentDigest::sha256(&source.bytes).bytes(),
            ComponentInterpretation::Grayscale,
            DecodeLimits::default(),
            &mut budget,
        )?;
        let config = GrayMatroskaConfig::new(image.dimensions(), PlaybackRate::new(30_000, 1001)?)?;
        if ordinal == 0 {
            bytes.extend_from_slice(config.initialization()?.bytes());
        }
        bytes.extend_from_slice(config.frame(ordinal as u64)?.prefix());
        bytes.extend_from_slice(image.pixels());
    }
    Ok(bytes)
}

#[test]
fn bounded_range_streams_real_jpegs_in_source_order_with_exact_pixels_and_cumulative_work() -> Test
{
    let sources = sources()?;
    let writer = Writer::default();
    let mut budget = DecodeBudget::new(100_000_000);
    let (selection, media) = run(
        &sources,
        Options::default(),
        &mut budget,
        &writer,
        &AtomicBool::new(false),
    )?;
    let bytes = expected(&sources)?;
    assert_eq!(writer.0.borrow().bytes, bytes);
    assert_eq!(writer.0.borrow().segments, [0, 1, 2]);
    assert_eq!(
        (writer.0.borrow().creations, writer.0.borrow().completions),
        (1, 1)
    );
    assert_eq!(
        (
            selection.observed_frames,
            selection.selected_frames,
            selection.skipped_frames
        ),
        (3, 3, 0)
    );
    assert_eq!(
        selection.selected_capture,
        CaptureInterval::new(TimestampNs(10), TimestampNs(30))?
    );
    assert_ne!(selection.request_digest, selection.selection_digest);
    assert_eq!((media.frames, media.bytes), (3, bytes.len() as u64));
    assert_eq!(media.digest, ContentDigest::sha256(&bytes));
    assert_eq!(media.dimensions, [7, 5]);
    assert_eq!(media.rate, PlaybackRate::new(30_000, 1001)?);
    assert_eq!(media.duration_ns, 100_100_000);
    assert_ne!(media.encoder.bytes(), [0; 32]);
    assert_ne!(media.frame_receipts_digest, media.digest);
    assert!(media.hashed_bytes > media.bytes + 3 * 35);
    assert_eq!(stream::WORK_MODEL, "logical_sha256_input_bytes");
    assert_eq!(
        stream::FRAME_RECEIPTS_DOMAIN,
        "fss.file_gray_matroska_frame_receipts.v1"
    );
    assert!(budget.used() > 0);
    let exact = budget.used();
    for limit in [exact, exact - 1] {
        let writer = Writer::default();
        let mut budget = DecodeBudget::new(limit);
        let result = run(
            &sources,
            Options::default(),
            &mut budget,
            &writer,
            &AtomicBool::new(false),
        );
        assert_eq!(result.is_ok(), limit == exact);
        assert_eq!(writer.0.borrow().completions, usize::from(limit == exact));
        assert!(budget.used() <= limit);
        if limit < exact {
            assert_eq!(writer.0.borrow().segments, [0, 1]);
        }
    }
    Ok(())
}

#[test]
fn selection_keeps_full_ordinals_and_checks_excluded_tail_before_completing() -> Test {
    let mut sources = sources()?;
    let writer = Writer::default();
    let options = Options {
        first: 1,
        count: 2,
        start: 15,
        end: 25,
        ..Options::default()
    };
    let (selection, media) = run(
        &sources,
        options,
        &mut DecodeBudget::new(100_000_000),
        &writer,
        &AtomicBool::new(false),
    )?;
    assert_eq!(writer.0.borrow().bytes, expected(&sources[1..2])?);
    assert_eq!(writer.0.borrow().segments, [1]);
    assert_eq!(
        (
            selection.observed_frames,
            selection.selected_frames,
            selection.skipped_frames
        ),
        (2, 1, 1)
    );
    assert_eq!((media.frames, media.duration_ns), (1, 33_366_666));
    sources[2].bytes.truncate(20);
    let writer = Writer::default();
    let result = run(
        &sources,
        Options {
            start: 15,
            end: 25,
            ..Options::default()
        },
        &mut DecodeBudget::new(100_000_000),
        &writer,
        &AtomicBool::new(false),
    );
    assert!(result.is_err());
    assert_eq!(writer.0.borrow().segments, [1]);
    assert_eq!(writer.0.borrow().completions, 0);
    Ok(())
}

#[test]
fn empty_or_late_uncertain_window_never_returns_a_prefix_receipt() -> Test {
    let mut sources = sources()?;
    let writer = Writer::default();
    assert!(
        run(
            &sources,
            Options {
                start: 40,
                end: 50,
                ..Options::default()
            },
            &mut DecodeBudget::new(100_000_000),
            &writer,
            &AtomicBool::new(false)
        )
        .is_err()
    );
    assert_eq!(
        (writer.0.borrow().creations, writer.0.borrow().completions),
        (0, 0)
    );
    sources[1].capsule.capture = CaptureInterval::new(TimestampNs(20), TimestampNs(26))?;
    let writer = Writer::default();
    assert!(
        run(
            &sources,
            Options {
                end: 25,
                ..Options::default()
            },
            &mut DecodeBudget::new(100_000_000),
            &writer,
            &AtomicBool::new(false)
        )
        .is_err()
    );
    assert_eq!(writer.0.borrow().segments, [0]);
    assert_eq!(writer.0.borrow().completions, 0);
    Ok(())
}

#[test]
fn byte_pressure_and_dimension_drift_preserve_but_never_certify_prior_frames() -> Test {
    let mut sources = sources()?;
    let first = expected(&sources[..1])?;
    for maximum in [first.len() as u64 - 1, first.len() as u64] {
        let writer = Writer::default();
        assert!(
            run(
                &sources,
                Options {
                    maximum,
                    ..Options::default()
                },
                &mut DecodeBudget::new(100_000_000),
                &writer,
                &AtomicBool::new(false)
            )
            .is_err()
        );
        assert_eq!(writer.0.borrow().completions, 0);
        if maximum < first.len() as u64 {
            assert_eq!(writer.0.borrow().creations, 0);
        } else {
            assert_eq!(writer.0.borrow().bytes, first);
        }
    }
    sources[1] = source(1, [8, 5])?;
    let writer = Writer::default();
    assert!(
        run(
            &sources,
            Options::default(),
            &mut DecodeBudget::new(100_000_000),
            &writer,
            &AtomicBool::new(false)
        )
        .is_err()
    );
    assert_eq!(writer.0.borrow().bytes, first);
    assert_eq!(writer.0.borrow().completions, 0);
    Ok(())
}

#[test]
fn cancellation_before_between_and_after_frames_never_finalizes() -> Test {
    let sources = sources()?;
    for after in [None, Some(0), Some(2)] {
        let writer = Writer::default();
        let cancelled = AtomicBool::new(after.is_none());
        let mut budget = DecodeBudget::cancellable(100_000_000, &cancelled);
        assert!(
            run(
                &sources,
                Options {
                    cancel_after: after,
                    ..Options::default()
                },
                &mut budget,
                &writer,
                &cancelled
            )
            .is_err()
        );
        assert_eq!(writer.0.borrow().completions, 0);
        assert_eq!(writer.0.borrow().segments.len(), after.map_or(0, |n| n + 1));
        if after.is_none() {
            assert_eq!(budget.used(), 0);
        }
    }
    Ok(())
}

#[test]
fn range_bounds_refuse_before_loading_or_allocating_any_output() -> Test {
    assert_eq!(range::MAX_FRAMES, 1024);
    for (first, count, available) in [
        (0, 0, 3),
        (0, 1025, 1025),
        (1, 3, 3),
        (usize::MAX, 2, usize::MAX),
    ] {
        assert!(FrameRange::new(first, count, available).is_err());
    }
    let _ = FrameRange::new(5, 1024, 1029)?;
    let writer = Writer::default();
    let mut budget = DecodeBudget::new(100_000_000);
    assert!(
        run(
            &sources()?,
            Options {
                time_provenance: FrameWindowTimeProvenance::Unknown,
                ..Options::default()
            },
            &mut budget,
            &writer,
            &AtomicBool::new(false)
        )
        .is_err()
    );
    assert_eq!(budget.used(), 0);
    assert_eq!(writer.0.borrow().creations, 0);
    Ok(())
}
