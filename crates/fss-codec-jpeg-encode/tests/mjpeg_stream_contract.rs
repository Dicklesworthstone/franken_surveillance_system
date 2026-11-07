#![forbid(unsafe_code)]
//! Executes the unchanged production CLI stream core, without a replay-runtime substitute.

#[path = "../../fss-cli/src/bin/fss-file/jpeg_stream/encoder.rs"]
mod stream;

use fss_codec_jpeg_encode::{EncodeBudget, EncodeConfig, EncodeLimits, PixelFormat, encode_jpeg};
use fss_core::ContentDigest;
use std::cell::RefCell;
use std::io::{self, Write};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use stream::{DEFAULT_ENCODE_WORK_UNITS, DEFAULT_OUTPUT_BYTES, DEFAULT_QUALITY, Encoder, FrameInput};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Default)]
struct State {
    bytes: Vec<u8>,
    created: usize,
    writes: usize,
    largest: usize,
    flushes: usize,
    fail_after: Option<usize>,
    interrupt: bool,
    zero: bool,
    flush_failure: bool,
}

#[derive(Clone, Default)]
struct Writer(Rc<RefCell<State>>);
impl Writer {
    fn create(&self) -> io::Result<Self> {
        self.0.borrow_mut().created += 1;
        Ok(self.clone())
    }
    fn bytes(&self) -> Vec<u8> {
        self.0.borrow().bytes.clone()
    }
}
impl Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut state = self.0.borrow_mut();
        state.writes += 1;
        state.largest = state.largest.max(bytes.len());
        if state.interrupt {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if state.zero {
            return Ok(0);
        }
        let remaining = state.fail_after.map_or(usize::MAX, |limit| limit - state.bytes.len());
        if remaining == 0 {
            return Err(io::Error::other("injected write failure"));
        }
        let count = bytes.len().min(17).min(remaining);
        state.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut state = self.0.borrow_mut();
        state.flushes += 1;
        if state.flush_failure {
            Err(io::Error::other("injected flush failure"))
        } else {
            Ok(())
        }
    }
}

fn hash(pixels: &[u8]) -> [u8; 32] {
    ContentDigest::sha256(pixels).bytes()
}

fn input(dimensions: [u32; 2], pixels: &[u8], luma_sha256: [u8; 32]) -> FrameInput<'_> {
    FrameInput {
        dimensions, pixels, luma_sha256,
        decode_receipt: ContentDigest::sha256(b"sealed retained source receipt fixture"),
    }
}

fn expected(pixels: &[u8], width: u32, height: u32) -> Test<(Vec<u8>, u64)> {
    let mut budget = EncodeBudget::new(DEFAULT_ENCODE_WORK_UNITS);
    let encoded = encode_jpeg(
        width, height, pixels, hash(pixels),
        EncodeConfig { quality: DEFAULT_QUALITY, format: PixelFormat::Grayscale },
        &EncodeLimits::default(), &mut budget,
    )?;
    Ok((encoded.into_bytes(), budget.used()))
}

#[test]
fn display_order_bytes_hash_and_work_match_individual_native_encodes() -> Test {
    let pixels = (0_u8..=255).collect::<Vec<_>>();
    let (first, first_work) = expected(&pixels, 16, 16)?;
    let (second, second_work) = expected(&[17, 31, 129], 3, 1)?;
    let expected = [first, second].concat();
    let mut identities = Vec::new();
    for maximum in [expected.len() as u64, DEFAULT_OUTPUT_BYTES] {
        let writer = Writer::default();
        let mut stream = Encoder::new(maximum, 2, DEFAULT_QUALITY)?;
        let mut budget = EncodeBudget::new(first_work + second_work);
        stream.frame(input([16, 16], &pixels, hash(&pixels)), &mut budget, || writer.create(), &mut || Ok(()))?;
        stream.frame(input([3, 1], &[17, 31, 129], hash(&[17, 31, 129])), &mut budget, || writer.create(), &mut || Ok(()))?;
        let (_, receipt) = stream.finish(&mut || Ok(()))?;
        assert_eq!(writer.bytes(), expected);
        assert_eq!(receipt.digest, ContentDigest::sha256(&expected));
        assert_eq!(receipt.bytes, expected.len() as u64);
        assert_eq!(receipt.frames, 2);
        assert_eq!(receipt.quality, DEFAULT_QUALITY);
        assert_eq!(receipt.encoder.bytes(), fss_codec_jpeg_encode::encoder_identity());
        assert_eq!(receipt.work_units, first_work + second_work);
        assert_eq!(budget.remaining(), 0);
        assert_eq!(writer.0.borrow().created, 1);
        assert!(writer.0.borrow().largest <= 4096);
        assert!(writer.0.borrow().writes > 10);
        assert_eq!(writer.0.borrow().flushes, 1);
        identities.push((receipt.frame_receipts_digest, receipt.encoder));
    }
    assert_eq!(identities[0], identities[1]);
    Ok(())
}

#[test]
fn aggregate_byte_and_work_limits_leave_only_complete_prior_frames_and_fence_finish() -> Test {
    let pixels = [71; 64];
    let (jpeg, used) = expected(&pixels, 8, 8)?;
    for (maximum, work) in [(2 * jpeg.len() as u64 - 1, 2 * used), (2 * jpeg.len() as u64, 2 * used - 1)] {
        let writer = Writer::default();
        let mut stream = Encoder::new(maximum, 2, DEFAULT_QUALITY)?;
        let mut budget = EncodeBudget::new(work);
        stream.frame(input([8, 8], &pixels, hash(&pixels)), &mut budget, || writer.create(), &mut || Ok(()))?;
        assert!(stream.frame(input([8, 8], &pixels, hash(&pixels)), &mut budget, || writer.create(), &mut || Ok(())).is_err());
        assert_eq!(writer.bytes(), jpeg);
        let work_after_refusal = budget.used();
        assert!(stream.frame(input([8, 8], &pixels, hash(&pixels)), &mut budget, || writer.create(), &mut || Ok(())).is_err());
        assert_eq!(budget.used(), work_after_refusal);
        assert!(stream.finish(&mut || Ok(())).is_err());
        assert_eq!(writer.0.borrow().flushes, 0);
    }
    Ok(())
}

#[test]
fn invalid_pixels_wrong_pin_or_first_frame_pressure_never_create_a_file() -> Test {
    for case in 0..5 {
        let writer = Writer::default();
        let mut stream = Encoder::new(if case == 2 { 1 } else { DEFAULT_OUTPUT_BYTES }, 1, DEFAULT_QUALITY)?;
        let mut budget = EncodeBudget::new(if case == 3 { 0 } else { DEFAULT_ENCODE_WORK_UNITS });
        let dimensions = if case == 0 { [0, 8] } else if case == 4 { [4097, 1] } else { [8, 8] };
        let digest = if case == 1 { hash(b"wrong input") } else { hash(&[31; 64]) };
        assert!(stream.frame(input(dimensions, &[31; 64], digest), &mut budget, || writer.create(), &mut || Ok(())).is_err());
        assert_eq!(writer.0.borrow().created, 0);
        assert!(writer.bytes().is_empty());
        assert!(stream.finish(&mut || Ok(())).is_err());
    }
    Ok(())
}

#[test]
fn cancellation_inside_real_encoder_refuses_before_writer_creation() -> Test {
    let calls = AtomicUsize::new(0);
    let cancelled = || calls.fetch_add(1, Ordering::SeqCst) >= 4;
    let writer = Writer::default();
    let mut stream = Encoder::new(DEFAULT_OUTPUT_BYTES, 1, DEFAULT_QUALITY)?;
    let mut budget = EncodeBudget::with_cancellation_probe(DEFAULT_ENCODE_WORK_UNITS, &cancelled);
    let pixels = [53; 128 * 128];
    assert!(stream.frame(input([128, 128], &pixels, hash(&pixels)), &mut budget, || writer.create(), &mut || Ok(())).is_err());
    assert!(calls.load(Ordering::SeqCst) >= 5);
    assert_eq!(writer.0.borrow().created, 0);
    assert!(stream.finish(&mut || Ok(())).is_err());
    Ok(())
}

#[test]
fn partial_writes_and_checkpoint_cancellation_never_certify_a_shorter_stream() -> Test {
    for cancellation in [false, true] {
        let writer = Writer::default();
        if !cancellation { writer.0.borrow_mut().fail_after = Some(20); }
        let mut stream = Encoder::new(DEFAULT_OUTPUT_BYTES, 1, DEFAULT_QUALITY)?;
        let mut budget = EncodeBudget::new(DEFAULT_ENCODE_WORK_UNITS);
        let mut checks = 0;
        assert!(stream.frame(input([8, 8], &[29; 64], hash(&[29; 64])), &mut budget, || writer.create(), &mut || {
            checks += 1;
            if cancellation && checks == 4 { Err(io::Error::other("cancelled")) } else { Ok(()) }
        }).is_err());
        assert_eq!(writer.bytes().len(), if cancellation { 17 } else { 20 });
        assert!(stream.finish(&mut || Ok(())).is_err());
    }
    Ok(())
}

#[test]
fn zero_progress_interruptions_flush_and_final_checkpoint_are_bounded_refusals() -> Test {
    for case in 0..4 {
        let writer = Writer::default();
        {
            let mut state = writer.0.borrow_mut();
            state.zero = case == 0;
            state.interrupt = case == 1;
            state.flush_failure = case == 2;
        }
        let mut stream = Encoder::new(DEFAULT_OUTPUT_BYTES, 1, DEFAULT_QUALITY)?;
        let mut budget = EncodeBudget::new(DEFAULT_ENCODE_WORK_UNITS);
        let result = stream.frame(input([8, 8], &[93; 64], hash(&[93; 64])), &mut budget, || writer.create(), &mut || Ok(()));
        if case <= 1 {
            assert!(result.is_err());
            assert_eq!(writer.0.borrow().writes, if case == 0 { 1 } else { 8 });
            assert!(stream.finish(&mut || Ok(())).is_err());
        } else {
            result?;
            let mut checks = 0;
            assert!(stream.finish(&mut || {
                checks += 1;
                if case == 3 && checks == 2 { Err(io::Error::other("final cancellation")) } else { Ok(()) }
            }).is_err());
            assert_eq!(writer.0.borrow().flushes, 1);
        }
    }
    Ok(())
}

#[test]
fn frame_limit_empty_stream_and_invalid_config_refuse() -> Test {
    for (maximum, frames, quality) in [(0, 1, 85), (stream::MAX_OUTPUT_BYTES + 1, 1, 85), (1, 0, 85), (1, 1025, 85), (1, 1, 0), (1, 1, 101)] {
        assert!(Encoder::<Writer>::new(maximum, frames, quality).is_err());
    }
    assert!(Encoder::<Writer>::new(1000, 1, DEFAULT_QUALITY)?.finish(&mut || Ok(())).is_err());
    let writer = Writer::default();
    let mut stream = Encoder::new(DEFAULT_OUTPUT_BYTES, 1, DEFAULT_QUALITY)?;
    let mut budget = EncodeBudget::new(DEFAULT_ENCODE_WORK_UNITS);
    stream.frame(input([1, 1], &[16], hash(&[16])), &mut budget, || writer.create(), &mut || Ok(()))?;
    let before = writer.bytes();
    let used = budget.used();
    assert!(stream.frame(input([1, 1], &[16], hash(&[16])), &mut budget, || writer.create(), &mut || Ok(())).is_err());
    assert_eq!(budget.used(), used);
    assert_eq!(writer.bytes(), before);
    assert!(stream.finish(&mut || Ok(())).is_err());
    Ok(())
}

#[test]
fn identical_pixels_keep_distinct_source_and_order_lineage_without_changing_jpeg_bytes() -> Test {
    let a = ContentDigest::sha256(b"source-a import and current mask decode receipt");
    let b = ContentDigest::sha256(b"source-b import and current mask decode receipt");
    let mut reports = Vec::new();
    for origins in [[a, b], [b, a], [a, a], [a, b]] {
        let writer = Writer::default();
        let mut stream = Encoder::new(DEFAULT_OUTPUT_BYTES, 2, DEFAULT_QUALITY)?;
        let mut budget = EncodeBudget::new(DEFAULT_ENCODE_WORK_UNITS);
        for origin in origins {
            let mut frame = input([8, 8], &[16; 64], hash(&[16; 64]));
            frame.decode_receipt = origin;
            stream.frame(frame, &mut budget, || writer.create(), &mut || Ok(()))?;
        }
        let (_, receipt) = stream.finish(&mut || Ok(()))?;
        reports.push((writer.bytes(), receipt.frame_receipts_digest));
    }
    assert_eq!(reports[0].0, reports[1].0);
    assert_eq!(reports[0].0, reports[2].0);
    assert_ne!(reports[0].1, reports[1].1);
    assert_ne!(reports[0].1, reports[2].1);
    assert_eq!(reports[0], reports[3]);
    Ok(())
}
