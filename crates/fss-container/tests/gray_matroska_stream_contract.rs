#![forbid(unsafe_code)]
//! Executes the exact production stream core and independently inspects its wire output.
//!
//! These contracts require neither the async runtime nor a replacement media encoder.
//! The parser below checks the admitted EBML profile independently of the writer.

#[path = "../../fss-cli/src/bin/fss-file/gray_matroska_stream/encoder.rs"]
mod stream;

use fss_container::matroska_gray::{GrayMatroskaConfig, PlaybackRate};
use fss_core::{ContentDigest, DigestAlgorithm, Sha256Hasher};
use std::cell::RefCell;
use std::io::{self, Write};
use std::rc::Rc;
use stream::{
    DEFAULT_OUTPUT_BYTES, ENCODER_IDENTITY_DOMAIN, Encoder, FRAME_RECEIPTS_DOMAIN, FrameInput,
    MAX_OUTPUT_BYTES, StreamReceipt, WORK_MODEL,
};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Default)]
struct State {
    bytes: Vec<u8>,
    created: usize,
    writes: usize,
    largest: usize,
    flushes: usize,
    maximum_piece: usize,
    fail_after: Option<usize>,
    interruptions: usize,
    interruption_cycle: usize,
    always_interrupt: bool,
    zero: bool,
    overreport: bool,
    create_failure: bool,
    flush_failure: bool,
}

#[derive(Clone)]
struct Writer(Rc<RefCell<State>>);

impl Writer {
    fn new(maximum_piece: usize) -> Self {
        assert!(maximum_piece > 0);
        Self(Rc::new(RefCell::new(State {
            maximum_piece,
            ..State::default()
        })))
    }

    fn create(&self) -> io::Result<Self> {
        let mut state = self.0.borrow_mut();
        state.created += 1;
        if state.create_failure {
            Err(io::Error::other("injected creation failure"))
        } else {
            Ok(self.clone())
        }
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
        if state.always_interrupt {
            // Bound a broken implementation too: the assertion below still requires eight.
            return Err(if state.writes > 32 {
                io::Error::other("unbounded interrupted-write retry")
            } else {
                io::ErrorKind::Interrupted.into()
            });
        }
        if state.interruptions > 0 {
            state.interruptions -= 1;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if state.zero {
            return Ok(0);
        }
        if state.overreport {
            return Ok(bytes.len() + 1);
        }
        let remaining = state
            .fail_after
            .map_or(usize::MAX, |limit| limit.saturating_sub(state.bytes.len()));
        if remaining == 0 {
            return Err(io::Error::other("injected partial-write failure"));
        }
        let count = bytes.len().min(state.maximum_piece).min(remaining);
        state.bytes.extend_from_slice(&bytes[..count]);
        state.interruptions = state.interruption_cycle;
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

fn pin(seed: u8) -> ContentDigest {
    ContentDigest::sha256(&[seed])
}

fn frame(dimensions: [u32; 2], pixels: &[u8], source: ContentDigest) -> FrameInput<'_> {
    FrameInput {
        dimensions,
        pixels,
        luma_sha256: ContentDigest::sha256(pixels).bytes(),
        decode_receipt: source,
    }
}

fn encode(
    dimensions: [u32; 2],
    pixels: &[Vec<u8>],
    sources: &[ContentDigest],
    rate: PlaybackRate,
    piece: usize,
) -> Test<(Vec<u8>, StreamReceipt)> {
    assert_eq!(pixels.len(), sources.len());
    let writer = Writer::new(piece);
    let mut encoder = Encoder::new(DEFAULT_OUTPUT_BYTES, pixels.len(), rate)?;
    for (pixels, source) in pixels.iter().zip(sources) {
        encoder.frame(
            frame(dimensions, pixels, *source),
            || writer.create(),
            &mut || Ok(()),
        )?;
    }
    let (_, receipt) = encoder.finish(&mut || Ok(()))?;
    assert_eq!(writer.0.borrow().created, 1);
    assert_eq!(writer.0.borrow().flushes, 1);
    assert!(writer.0.borrow().largest <= 4096);
    Ok((writer.bytes(), receipt))
}

fn same_receipt(left: &StreamReceipt, right: &StreamReceipt) {
    assert_eq!(left.bytes, right.bytes);
    assert_eq!(left.frames, right.frames);
    assert_eq!(left.digest, right.digest);
    assert_eq!(left.frame_receipts_digest, right.frame_receipts_digest);
    assert_eq!(left.encoder, right.encoder);
    assert_eq!(left.dimensions, right.dimensions);
    assert_eq!(left.timing, right.timing);
    assert_eq!(left.duration_ns, right.duration_ns);
    assert_eq!(left.last_frame_end_ns, right.last_frame_end_ns);
    assert_eq!(left.hashed_bytes, right.hashed_bytes);
}

fn assert_fenced(
    mut encoder: Encoder<Writer>,
    writer: &Writer,
    dimensions: [u32; 2],
    pixels: &[u8],
) -> Test {
    let before = writer.bytes();
    let created = writer.0.borrow().created;
    let writes = writer.0.borrow().writes;
    let flushes = writer.0.borrow().flushes;
    let mut checks = 0;
    assert!(
        encoder
            .frame(
                frame(dimensions, pixels, pin(1)),
                || writer.create(),
                &mut || {
                    checks += 1;
                    Ok(())
                }
            )
            .is_err()
    );
    assert!(
        encoder
            .finish(&mut || {
                checks += 1;
                Ok(())
            })
            .is_err()
    );
    assert_eq!(checks, 0, "a fenced stream must do no further work");
    assert_eq!(writer.bytes(), before);
    assert_eq!(writer.0.borrow().created, created);
    assert_eq!(writer.0.borrow().writes, writes);
    assert_eq!(writer.0.borrow().flushes, flushes);
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Clone, Copy)]
struct Element<'a> {
    id: u32,
    payload: &'a [u8],
    unknown: bool,
    size_width: usize,
}

fn element(input: &[u8]) -> Test<(Element<'_>, &[u8])> {
    let first = *input
        .first()
        .ok_or_else(|| invalid("missing EBML identifier"))?;
    let id_width = first.leading_zeros() as usize + 1;
    if id_width > 4 || input.len() <= id_width {
        return Err(invalid("invalid EBML identifier width").into());
    }
    let id = input[..id_width]
        .iter()
        .fold(0_u32, |value, byte| (value << 8) | u32::from(*byte));
    let size_width = input[id_width].leading_zeros() as usize + 1;
    if size_width > 8 || input.len() < id_width + size_width {
        return Err(invalid("invalid EBML size width").into());
    }
    let mut size = u64::from(input[id_width] & (0xff_u16 >> size_width) as u8);
    for byte in &input[id_width + 1..id_width + size_width] {
        size = (size << 8) | u64::from(*byte);
    }
    let unknown = size == (1_u64 << (7 * size_width)) - 1;
    let start = id_width + size_width;
    let payload_length = if unknown {
        input.len() - start
    } else {
        usize::try_from(size)?
    };
    let end = start
        .checked_add(payload_length)
        .ok_or_else(|| invalid("EBML length overflow"))?;
    let payload = input
        .get(start..end)
        .ok_or_else(|| invalid("truncated EBML element"))?;
    Ok((
        Element {
            id,
            payload,
            unknown,
            size_width,
        },
        &input[end..],
    ))
}

fn children(mut bytes: &[u8]) -> Test<Vec<Element<'_>>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        let (child, rest) = element(bytes)?;
        assert!(
            !child.unknown,
            "only the top-level Segment may have unknown size"
        );
        result.push(child);
        bytes = rest;
    }
    Ok(result)
}

fn ids(elements: &[Element<'_>], expected: &[u32]) {
    assert_eq!(
        elements
            .iter()
            .map(|element| element.id)
            .collect::<Vec<_>>(),
        expected
    );
}

fn one<'a>(elements: &[Element<'a>], id: u32) -> Test<Element<'a>> {
    let mut matching = elements.iter().filter(|element| element.id == id);
    let value = *matching
        .next()
        .ok_or_else(|| invalid("missing expected EBML field"))?;
    assert!(matching.next().is_none(), "duplicate EBML field");
    Ok(value)
}

fn uint(element: Element<'_>) -> Test<u64> {
    if !(1..=8).contains(&element.payload.len()) {
        return Err(invalid("invalid unsigned EBML field width").into());
    }
    Ok(element
        .payload
        .iter()
        .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)))
}

struct ParsedFrame<'a> {
    pixels: &'a [u8],
    timestamp_ns: u64,
    duration_ns: u64,
}

fn inspect(bytes: &[u8]) -> Test<([u32; 2], Vec<ParsedFrame<'_>>)> {
    inspect_with_duration(bytes, None)
}

fn inspect_with_duration(
    bytes: &[u8],
    duration: Option<u64>,
) -> Test<([u32; 2], Vec<ParsedFrame<'_>>)> {
    let (header, rest) = element(bytes)?;
    assert_eq!(header.id, 0x1a45dfa3);
    assert!(!header.unknown);
    let header = children(header.payload)?;
    ids(
        &header,
        &[0x4286, 0x42f7, 0x42f2, 0x42f3, 0x4282, 0x4287, 0x4285],
    );
    for (id, expected) in [
        (0x4286, 1),
        (0x42f7, 1),
        (0x42f2, 4),
        (0x42f3, 8),
        (0x4287, 4),
        (0x4285, 2),
    ] {
        assert_eq!(uint(one(&header, id)?)?, expected);
    }
    assert_eq!(one(&header, 0x4282)?.payload, b"matroska");

    let (segment, rest) = element(rest)?;
    assert_eq!(segment.id, 0x18538067);
    assert!(segment.unknown);
    assert_eq!(segment.size_width, 8);
    assert!(rest.is_empty());
    let segment = children(segment.payload)?;
    assert!(segment.len() >= 3);
    assert_eq!(segment[0].id, 0x1549a966);
    assert_eq!(segment[1].id, 0x1654ae6b);
    let info = children(segment[0].payload)?;
    if let Some(duration) = duration {
        assert_eq!(info.len(), 4);
        assert_eq!(
            f64::from_be_bytes(one(&info, 0x4489)?.payload.try_into()?),
            duration as f64
        );
        let ordinary: Vec<_> = info
            .iter()
            .copied()
            .filter(|field| field.id != 0x4489)
            .collect();
        ids(&ordinary, &[0x2ad7b1, 0x4d80, 0x5741]);
    } else {
        ids(&info, &[0x2ad7b1, 0x4d80, 0x5741]);
    }
    assert_eq!(uint(one(&info, 0x2ad7b1)?)?, 1);
    for id in [0x4d80, 0x5741] {
        assert_eq!(one(&info, id)?.payload, b"fss.matroska_gray.v1");
    }
    let tracks = children(segment[1].payload)?;
    ids(&tracks, &[0xae]);
    let track = children(tracks[0].payload)?;
    ids(&track, &[0xd7, 0x73c5, 0x83, 0x9c, 0x86, 0xe0]);
    for (id, expected) in [(0xd7, 1), (0x73c5, 1), (0x83, 1), (0x9c, 0)] {
        assert_eq!(uint(one(&track, id)?)?, expected);
    }
    assert_eq!(one(&track, 0x86)?.payload, b"V_UNCOMPRESSED");
    let video = children(one(&track, 0xe0)?.payload)?;
    ids(&video, &[0x9a, 0xb0, 0xba, 0x2eb524, 0x55b0]);
    assert_eq!(uint(one(&video, 0x9a)?)?, 2);
    assert_eq!(one(&video, 0x2eb524)?.payload, b"Y800");
    let dimensions = [
        u32::try_from(uint(one(&video, 0xb0)?)?)?,
        u32::try_from(uint(one(&video, 0xba)?)?)?,
    ];
    let colour = children(one(&video, 0x55b0)?.payload)?;
    ids(&colour, &[0x55b2, 0x55b9]);
    assert_eq!(uint(one(&colour, 0x55b2)?)?, 8);
    assert_eq!(uint(one(&colour, 0x55b9)?)?, 2);

    let mut frames = Vec::new();
    for cluster in &segment[2..] {
        assert_eq!(cluster.id, 0x1f43b675);
        let fields = children(cluster.payload)?;
        ids(&fields, &[0xe7, 0xa0]);
        let group = children(fields[1].payload)?;
        ids(&group, &[0x9b, 0xa1]);
        let block = group[1].payload;
        assert!(block.len() >= 4);
        assert_eq!(&block[..4], &[0x81, 0, 0, 0]);
        let pixels = &block[4..];
        assert_eq!(
            pixels.len() as u64,
            u64::from(dimensions[0]) * u64::from(dimensions[1])
        );
        let duration_ns = uint(group[0])?;
        assert!(duration_ns > 0);
        frames.push(ParsedFrame {
            pixels,
            timestamp_ns: uint(fields[0])?,
            duration_ns,
        });
    }
    Ok((dimensions, frames))
}

fn masked_fixture(phase: u8) -> Vec<u8> {
    let mut pixels = Vec::new();
    for y in 0_u32..37 {
        for x in 0_u32..65 {
            pixels.push(if (13..42).contains(&x) && (9..23).contains(&y) {
                16
            } else {
                17 + ((x * 17 + y * 29 + u32::from(phase) * 31) % 239) as u8
            });
        }
    }
    pixels
}

fn expected_identity() -> Test<(ContentDigest, u64)> {
    // Every production file that chooses output bytes belongs to this generation.
    let sources: [&[u8]; 3] = [
        include_bytes!("../../fss-cli/src/bin/fss-file/gray_matroska_stream/encoder.rs"),
        include_bytes!("../src/matroska_gray.rs"),
        include_bytes!("../src/matroska_gray/ebml.rs"),
    ];
    let mut hash = Sha256Hasher::new();
    hash.update(ENCODER_IDENTITY_DOMAIN.as_bytes());
    hash.update(&[0]);
    let mut work = ENCODER_IDENTITY_DOMAIN.len() as u64 + 1;
    for source in sources {
        hash.update(&(source.len() as u64).to_le_bytes());
        hash.update(source);
        work += 8 + source.len() as u64;
    }
    let digest = hash
        .finalize()
        .map_err(|_| invalid("identity hash overflow"))?;
    Ok((ContentDigest::new(DigestAlgorithm::Sha256, digest), work))
}

#[test]
fn exact_odd_rectangle_masks_survive_timed_container_and_receipt_hashing() -> Test {
    let rate = PlaybackRate::new(30_000, 1001)?;
    let pixels = vec![masked_fixture(0), masked_fixture(1), masked_fixture(2)];
    let (bytes, receipt) = encode([65, 37], &pixels, &[pin(1), pin(2), pin(3)], rate, 17)?;
    let (dimensions, frames) = inspect(&bytes)?;
    assert_eq!(dimensions, [65, 37]);
    assert_eq!(frames.len(), 3);
    for (ordinal, (decoded, expected)) in frames.iter().zip(&pixels).enumerate() {
        let start = (ordinal as u128 * 1_000_000_000 * 1001 / 30_000) as u64;
        let end = ((ordinal as u128 + 1) * 1_000_000_000 * 1001 / 30_000) as u64;
        assert_eq!(decoded.timestamp_ns, start);
        assert_eq!(decoded.duration_ns, end - start);
        assert_eq!(decoded.pixels, expected);
        for y in 0..37 {
            for x in 0..65 {
                if (13..42).contains(&x) && (9..23).contains(&y) {
                    assert_eq!(decoded.pixels[y * 65 + x], 16);
                } else {
                    assert!(decoded.pixels[y * 65 + x] >= 17);
                }
            }
        }
    }
    assert_eq!(receipt.bytes, bytes.len() as u64);
    assert_eq!(receipt.frames, 3);
    assert_eq!(receipt.digest, ContentDigest::sha256(&bytes));
    assert_eq!(receipt.dimensions, dimensions);
    assert_eq!(receipt.timing, stream::Timing::Uniform(rate));
    assert_eq!(receipt.duration_ns, 100_100_000);
    let (identity, identity_work) = expected_identity()?;
    assert_eq!(receipt.encoder, identity);
    assert!(!receipt.encoder.is_laboratory());
    assert_eq!(
        receipt.frame_receipts_digest.algorithm(),
        DigestAlgorithm::Sha256
    );
    assert_ne!(receipt.frame_receipts_digest.bytes(), [0; 32]);
    // Source verification + exact accepted output + complete generation and lineage inputs.
    let expected_work = FRAME_RECEIPTS_DOMAIN.len() as u64
        + 1
        + identity_work
        + 48
        + (65 * 37 * 3)
        + receipt.bytes
        + (96 * 3)
        + 65;
    assert_eq!(receipt.hashed_bytes, expected_work);
    assert_eq!(WORK_MODEL, "logical_sha256_input_bytes");
    Ok(())
}

#[test]
fn byte_hash_work_and_lineage_are_independent_of_short_write_boundaries() -> Test {
    let rate = PlaybackRate::new(30, 1)?;
    let pixels = vec![vec![83; 97 * 83], vec![119; 97 * 83]];
    let sources = [pin(1), pin(2)];
    let (expected, expected_receipt) = encode([97, 83], &pixels, &sources, rate, usize::MAX)?;
    for piece in [1, 17, 4095, 4096] {
        let (actual, receipt) = encode([97, 83], &pixels, &sources, rate, piece)?;
        assert_eq!(actual, expected);
        same_receipt(&receipt, &expected_receipt);
    }
    Ok(())
}

#[test]
fn complete_first_frame_quota_is_checked_before_hashing_or_lazy_creation() -> Test {
    let rate = PlaybackRate::new(1, 1)?;
    let pixels = vec![71; 7 * 5];
    let (expected, expected_receipt) =
        encode([7, 5], std::slice::from_ref(&pixels), &[pin(1)], rate, 17)?;
    for maximum in [expected.len() as u64, DEFAULT_OUTPUT_BYTES] {
        let writer = Writer::new(17);
        let mut encoder = Encoder::new(maximum, 1, rate)?;
        encoder.frame(
            frame([7, 5], &pixels, pin(1)),
            || writer.create(),
            &mut || Ok(()),
        )?;
        let (_, receipt) = encoder.finish(&mut || Ok(()))?;
        assert_eq!(writer.bytes(), expected);
        same_receipt(&receipt, &expected_receipt);
    }
    let writer = Writer::new(17);
    let mut encoder = Encoder::new(expected.len() as u64 - 1, 1, rate)?;
    let mut checks = 0;
    assert!(
        encoder
            .frame(
                frame([7, 5], &pixels, pin(1)),
                || writer.create(),
                &mut || {
                    checks += 1;
                    Ok(())
                }
            )
            .is_err()
    );
    assert_eq!(
        checks, 1,
        "no pixel or implementation hashing after quota refusal"
    );
    assert_eq!(writer.0.borrow().created, 0);
    assert!(writer.bytes().is_empty());
    assert_fenced(encoder, &writer, [7, 5], &pixels)
}

#[test]
fn late_quota_refusal_preserves_complete_prior_frame_and_never_certifies_it_as_complete() -> Test {
    let rate = PlaybackRate::new(30, 1)?;
    let pixels = vec![57; 7 * 5];
    let (first, _) = encode([7, 5], std::slice::from_ref(&pixels), &[pin(1)], rate, 17)?;
    let (both, _) = encode(
        [7, 5],
        &[pixels.clone(), pixels.clone()],
        &[pin(1), pin(2)],
        rate,
        17,
    )?;
    let writer = Writer::new(17);
    let mut encoder = Encoder::new(both.len() as u64 - 1, 2, rate)?;
    encoder.frame(
        frame([7, 5], &pixels, pin(1)),
        || writer.create(),
        &mut || Ok(()),
    )?;
    assert!(
        encoder
            .frame(
                frame([7, 5], &pixels, pin(2)),
                || writer.create(),
                &mut || Ok(())
            )
            .is_err()
    );
    assert_eq!(writer.bytes(), first);
    assert_fenced(encoder, &writer, [7, 5], &pixels)
}

#[test]
fn invalid_dimensions_lengths_pixels_and_source_pins_refuse_without_creating_output() -> Test {
    let rate = PlaybackRate::new(30, 1)?;
    let pixels = [47; 35];
    for case in 0..8 {
        let writer = Writer::new(17);
        let mut encoder = Encoder::new(DEFAULT_OUTPUT_BYTES, 1, rate)?;
        let mut input = frame([7, 5], &pixels, pin(1));
        match case {
            0 => input.dimensions = [0, 5],
            1 => input.dimensions = [4097, 1],
            2 => input.dimensions = [4096, 4096],
            3 => input.pixels = &pixels[..34],
            4 => input.luma_sha256 = ContentDigest::sha256(b"wrong pixels").bytes(),
            5 => input.decode_receipt = ContentDigest::new(DigestAlgorithm::Blake3, [1; 32]),
            6 => input.decode_receipt = pin(1).with_laboratory(true),
            _ => input.decode_receipt = ContentDigest::new(DigestAlgorithm::Sha256, [0; 32]),
        }
        assert!(
            encoder
                .frame(input, || writer.create(), &mut || Ok(()))
                .is_err()
        );
        assert_eq!(writer.0.borrow().created, 0);
        assert!(writer.bytes().is_empty());
        assert_fenced(encoder, &writer, [7, 5], &pixels)?;
    }
    Ok(())
}

#[test]
fn dimension_drift_and_late_invalid_lineage_permanently_fence_the_stream() -> Test {
    let rate = PlaybackRate::new(30, 1)?;
    let pixels = [51; 35];
    for changed_dimensions in [true, false] {
        let writer = Writer::new(17);
        let mut encoder = Encoder::new(DEFAULT_OUTPUT_BYTES, 2, rate)?;
        encoder.frame(
            frame([7, 5], &pixels, pin(1)),
            || writer.create(),
            &mut || Ok(()),
        )?;
        let before = writer.bytes();
        let mut next = frame([7, 5], &pixels, pin(2));
        if changed_dimensions {
            next.dimensions = [5, 7];
        } else {
            next.decode_receipt = pin(2).with_laboratory(true);
        }
        assert!(
            encoder
                .frame(next, || writer.create(), &mut || Ok(()))
                .is_err()
        );
        assert_eq!(writer.bytes(), before);
        assert_eq!(writer.0.borrow().created, 1);
        assert_fenced(encoder, &writer, [7, 5], &pixels)?;
    }
    Ok(())
}

#[test]
fn allowances_empty_streams_and_frame_limit_cannot_produce_success_receipts() -> Test {
    let rate = PlaybackRate::new(1, 1)?;
    for (maximum, frames) in [
        (0, 1),
        (MAX_OUTPUT_BYTES + 1, 1),
        (DEFAULT_OUTPUT_BYTES, 0),
        (DEFAULT_OUTPUT_BYTES, 1025),
    ] {
        assert!(Encoder::<Writer>::new(maximum, frames, rate).is_err());
    }
    let empty = Encoder::<Writer>::new(MAX_OUTPUT_BYTES, 1024, rate)?;
    assert!(empty.finish(&mut || Ok(())).is_err());
    let writer = Writer::new(17);
    let mut encoder = Encoder::new(DEFAULT_OUTPUT_BYTES, 1, rate)?;
    encoder.frame(
        frame([1, 1], &[16], pin(1)),
        || writer.create(),
        &mut || Ok(()),
    )?;
    let before = writer.bytes();
    assert!(
        encoder
            .frame(
                frame([1, 1], &[16], pin(2)),
                || writer.create(),
                &mut || Ok(())
            )
            .is_err()
    );
    assert_eq!(writer.bytes(), before);
    assert_fenced(encoder, &writer, [1, 1], &[16])
}

#[test]
fn maximum_frame_count_and_slowest_rate_keep_every_boundary_exact() -> Test {
    let rate = PlaybackRate::new(1, 1_000_000)?;
    let writer = Writer::new(usize::MAX);
    let mut encoder = Encoder::new(DEFAULT_OUTPUT_BYTES, 1024, rate)?;
    for ordinal in 0..1024 {
        encoder.frame(
            frame([1, 1], &[16], pin((ordinal % 251) as u8)),
            || writer.create(),
            &mut || Ok(()),
        )?;
    }
    let (_, receipt) = encoder.finish(&mut || Ok(()))?;
    let bytes = writer.bytes();
    let (_, frames) = inspect(&bytes)?;
    assert_eq!(frames.len(), 1024);
    for (ordinal, frame) in frames.iter().enumerate() {
        assert_eq!(frame.pixels, &[16]);
        assert_eq!(frame.timestamp_ns, ordinal as u64 * 1_000_000_000_000_000);
        assert_eq!(frame.duration_ns, 1_000_000_000_000_000);
    }
    assert_eq!(receipt.frames, 1024);
    assert_eq!(receipt.duration_ns, 1_024_000_000_000_000_000);
    assert_eq!(receipt.digest, ContentDigest::sha256(&bytes));
    Ok(())
}

#[test]
fn normalized_rate_is_canonical_and_source_order_is_bound_separately_from_pixels() -> Test {
    let pixels = vec![vec![16; 35], vec![16; 35]];
    let (bytes, receipt) = encode(
        [7, 5],
        &pixels,
        &[pin(1), pin(2)],
        PlaybackRate::new(30, 1)?,
        17,
    )?;
    let (equivalent, equivalent_receipt) = encode(
        [7, 5],
        &pixels,
        &[pin(1), pin(2)],
        PlaybackRate::new(60, 2)?,
        17,
    )?;
    assert_eq!(bytes, equivalent);
    same_receipt(&receipt, &equivalent_receipt);

    let (reordered, reordered_receipt) = encode(
        [7, 5],
        &pixels,
        &[pin(2), pin(1)],
        PlaybackRate::new(30, 1)?,
        17,
    )?;
    assert_eq!(bytes, reordered);
    assert_eq!(receipt.digest, reordered_receipt.digest);
    assert_ne!(
        receipt.frame_receipts_digest,
        reordered_receipt.frame_receipts_digest
    );
    assert_eq!(receipt.encoder, reordered_receipt.encoder);
    assert_eq!(receipt.hashed_bytes, reordered_receipt.hashed_bytes);

    let (retimed, retimed_receipt) = encode(
        [7, 5],
        &pixels,
        &[pin(1), pin(2)],
        PlaybackRate::new(25, 1)?,
        17,
    )?;
    assert_ne!(bytes, retimed);
    assert_ne!(receipt.digest, retimed_receipt.digest);
    assert_ne!(
        receipt.frame_receipts_digest,
        retimed_receipt.frame_receipts_digest
    );
    assert_eq!(receipt.encoder, retimed_receipt.encoder);
    assert_eq!(retimed_receipt.duration_ns, 80_000_000);
    Ok(())
}

#[test]
fn invalid_writer_progress_and_eight_consecutive_interruptions_fence_completion() -> Test {
    let rate = PlaybackRate::new(30, 1)?;
    for case in 0..3 {
        let writer = Writer::new(17);
        {
            let mut state = writer.0.borrow_mut();
            state.zero = case == 0;
            state.overreport = case == 1;
            state.always_interrupt = case == 2;
        }
        let mut encoder = Encoder::new(DEFAULT_OUTPUT_BYTES, 1, rate)?;
        let result = encoder.frame(
            frame([7, 5], &[31; 35], pin(1)),
            || writer.create(),
            &mut || Ok(()),
        );
        assert!(result.is_err());
        if case == 2 {
            assert_eq!(writer.0.borrow().writes, 8);
        } else {
            assert_eq!(writer.0.borrow().writes, 1);
        }
        assert!(writer.bytes().is_empty());
        assert_fenced(encoder, &writer, [7, 5], &[31; 35])?;
    }
    Ok(())
}

#[test]
fn seven_interruptions_recover_and_retry_allowance_resets_only_after_progress() -> Test {
    let rate = PlaybackRate::new(30, 1)?;
    let pixels = vec![31; 35];
    let (expected, expected_receipt) =
        encode([7, 5], std::slice::from_ref(&pixels), &[pin(1)], rate, 17)?;
    let writer = Writer::new(17);
    {
        let mut state = writer.0.borrow_mut();
        state.interruptions = 7;
        state.interruption_cycle = 7;
    }
    let mut encoder = Encoder::new(DEFAULT_OUTPUT_BYTES, 1, rate)?;
    encoder.frame(
        frame([7, 5], &pixels, pin(1)),
        || writer.create(),
        &mut || Ok(()),
    )?;
    let (_, receipt) = encoder.finish(&mut || Ok(()))?;
    assert_eq!(writer.bytes(), expected);
    same_receipt(&receipt, &expected_receipt);
    assert!(writer.0.borrow().writes > 8);
    assert_eq!(writer.0.borrow().writes % 8, 0);
    Ok(())
}

#[test]
fn partial_header_payload_and_second_frame_failures_never_certify_shorter_output() -> Test {
    let rate = PlaybackRate::new(30, 1)?;
    let pixels = vec![63; 35];
    let config = GrayMatroskaConfig::new([7, 5], rate)?;
    let initial = config.initialization()?.bytes().len();
    let first_payload = initial + config.frame(0)?.prefix().len();
    let first_end = first_payload + pixels.len();
    let second_payload = first_end + config.frame(1)?.prefix().len();
    let (expected, _) = encode(
        [7, 5],
        &[pixels.clone(), pixels.clone()],
        &[pin(1), pin(2)],
        rate,
        17,
    )?;
    for limit in [1, first_payload + 5, second_payload + 5] {
        let writer = Writer::new(17);
        writer.0.borrow_mut().fail_after = Some(limit);
        let mut encoder = Encoder::new(DEFAULT_OUTPUT_BYTES, 2, rate)?;
        let first = encoder.frame(
            frame([7, 5], &pixels, pin(1)),
            || writer.create(),
            &mut || Ok(()),
        );
        if limit < first_end {
            assert!(first.is_err());
        } else {
            first?;
            assert!(
                encoder
                    .frame(
                        frame([7, 5], &pixels, pin(2)),
                        || writer.create(),
                        &mut || Ok(())
                    )
                    .is_err()
            );
        }
        assert_eq!(writer.bytes(), expected[..limit]);
        assert_fenced(encoder, &writer, [7, 5], &pixels)?;
    }
    Ok(())
}

#[test]
fn cancellation_before_creation_and_during_pin_hashing_fences_without_output() -> Test {
    let rate = PlaybackRate::new(30, 1)?;
    let pixels = vec![53; 128 * 128];
    for reject_at in [1, 3] {
        let writer = Writer::new(17);
        let mut encoder = Encoder::new(DEFAULT_OUTPUT_BYTES, 1, rate)?;
        let mut checks = 0;
        assert!(
            encoder
                .frame(
                    frame([128, 128], &pixels, pin(1)),
                    || writer.create(),
                    &mut || {
                        checks += 1;
                        if checks == reject_at {
                            Err(io::Error::other("cancelled while hashing"))
                        } else {
                            Ok(())
                        }
                    }
                )
                .is_err()
        );
        assert_eq!(checks, reject_at);
        assert_eq!(writer.0.borrow().created, 0);
        assert!(writer.bytes().is_empty());
        assert_fenced(encoder, &writer, [128, 128], &pixels)?;
    }
    Ok(())
}

#[test]
fn cancellation_after_partial_or_complete_frame_bytes_never_returns_a_receipt() -> Test {
    let rate = PlaybackRate::new(30, 1)?;
    let pixels = vec![41; 35];
    let (expected, _) = encode([7, 5], std::slice::from_ref(&pixels), &[pin(1)], rate, 17)?;
    for cancel_after in [1, expected.len()] {
        let writer = Writer::new(17);
        let mut encoder = Encoder::new(DEFAULT_OUTPUT_BYTES, 1, rate)?;
        assert!(
            encoder
                .frame(
                    frame([7, 5], &pixels, pin(1)),
                    || writer.create(),
                    &mut || {
                        if writer.0.borrow().bytes.len() >= cancel_after {
                            Err(io::Error::other("cancelled after accepted output"))
                        } else {
                            Ok(())
                        }
                    }
                )
                .is_err()
        );
        let written = writer.bytes();
        assert_eq!(
            written.len(),
            if cancel_after == 1 {
                17
            } else {
                expected.len()
            }
        );
        assert_eq!(written, expected[..written.len()]);
        assert_fenced(encoder, &writer, [7, 5], &pixels)?;
    }
    Ok(())
}

#[test]
fn creation_failure_is_permanent_and_never_retries_the_sink() -> Test {
    let rate = PlaybackRate::new(30, 1)?;
    let writer = Writer::new(17);
    writer.0.borrow_mut().create_failure = true;
    let mut encoder = Encoder::new(DEFAULT_OUTPUT_BYTES, 1, rate)?;
    assert!(
        encoder
            .frame(
                frame([7, 5], &[29; 35], pin(1)),
                || writer.create(),
                &mut || Ok(())
            )
            .is_err()
    );
    assert_eq!(writer.0.borrow().created, 1);
    assert_eq!(writer.0.borrow().writes, 0);
    assert!(writer.bytes().is_empty());
    assert_fenced(encoder, &writer, [7, 5], &[29; 35])
}

#[test]
fn finish_requires_successful_flush_and_both_cancellation_checkpoints() -> Test {
    let rate = PlaybackRate::new(30, 1)?;
    for case in 0..3 {
        let writer = Writer::new(17);
        let mut encoder = Encoder::new(DEFAULT_OUTPUT_BYTES, 1, rate)?;
        encoder.frame(
            frame([7, 5], &[29; 35], pin(1)),
            || writer.create(),
            &mut || Ok(()),
        )?;
        let before = writer.bytes();
        writer.0.borrow_mut().flush_failure = case == 1;
        assert!(
            encoder
                .finish(&mut || {
                    if case == 0 || (case == 2 && writer.0.borrow().flushes > 0) {
                        Err(io::Error::other("cancelled at completion"))
                    } else {
                        Ok(())
                    }
                })
                .is_err()
        );
        assert_eq!(writer.bytes(), before);
        assert_eq!(writer.0.borrow().flushes, usize::from(case != 0));
        assert_eq!(writer.0.borrow().created, 1);
    }
    Ok(())
}

fn encode_movie(
    intervals: &[(u64, u64)],
    duration: u64,
    selection: ContentDigest,
    piece: usize,
) -> Test<(Vec<u8>, StreamReceipt)> {
    let writer = Writer::new(piece);
    let mut encoder =
        Encoder::new_movie(DEFAULT_OUTPUT_BYTES, intervals.len(), duration, selection)?;
    for (index, (start, end)) in intervals.iter().copied().enumerate() {
        let pixels = [0, 16, index as u8, 127, 235, 255];
        encoder.frame_at(
            frame([3, 2], &pixels, pin(index as u8)),
            start,
            end,
            || writer.create(),
            &mut || Ok(()),
        )?;
    }
    let (_, receipt) = encoder.finish(&mut || Ok(()))?;
    assert_eq!(writer.0.borrow().created, 1);
    assert_eq!(writer.0.borrow().flushes, 1);
    assert!(writer.0.borrow().largest <= 4096);
    Ok((writer.bytes(), receipt))
}

#[test]
fn movie_stream_preserves_timestamp_holes_and_full_envelope_with_exact_pixels() -> Test {
    let intervals = [(100, 200), (350, 600), (900, 950)];
    let (expected, expected_receipt) = encode_movie(&intervals, 1000, pin(91), usize::MAX)?;
    let (dimensions, parsed) = inspect_with_duration(&expected, Some(1000))?;
    assert_eq!(dimensions, [3, 2]);
    assert_eq!(parsed.len(), 3);
    for (index, (frame, (start, end))) in parsed.iter().zip(intervals).enumerate() {
        assert_eq!(frame.timestamp_ns, start);
        assert_eq!(frame.duration_ns, end - start);
        assert_eq!(frame.pixels, [0, 16, index as u8, 127, 235, 255]);
    }
    assert_eq!(expected_receipt.duration_ns, 1000);
    assert_eq!(expected_receipt.last_frame_end_ns, 950);
    assert_eq!(
        expected_receipt.timing,
        stream::Timing::Movie {
            duration_ns: 1000,
            movie_lineage: pin(91)
        }
    );
    assert_eq!(
        expected_receipt.timing.domain(),
        stream::MOVIE_FRAME_RECEIPTS_DOMAIN
    );
    assert_eq!(expected_receipt.digest, ContentDigest::sha256(&expected));
    for piece in [1, 17, 4096] {
        let (bytes, receipt) = encode_movie(&intervals, 1000, pin(91), piece)?;
        assert_eq!(bytes, expected);
        same_receipt(&receipt, &expected_receipt);
    }
    Ok(())
}

#[test]
fn movie_lineage_binds_query_intervals_and_duration_separately_from_pixels() -> Test {
    let intervals = [(100, 200), (300, 600)];
    let (original, receipt) = encode_movie(&intervals, 1000, pin(91), 17)?;
    let (same_pixels_and_times, other_selection) = encode_movie(&intervals, 1000, pin(92), 17)?;
    assert_eq!(same_pixels_and_times, original);
    assert_eq!(other_selection.digest, receipt.digest);
    assert_ne!(
        other_selection.frame_receipts_digest,
        receipt.frame_receipts_digest
    );
    let (different_times, other_times) =
        encode_movie(&[(100, 200), (301, 600)], 1000, pin(91), 17)?;
    assert_ne!(different_times, original);
    assert_ne!(
        other_times.frame_receipts_digest,
        receipt.frame_receipts_digest
    );
    let (longer_tail, other_duration) = encode_movie(&intervals, 1001, pin(91), 17)?;
    assert_ne!(longer_tail, original);
    assert_ne!(
        other_duration.frame_receipts_digest,
        receipt.frame_receipts_digest
    );
    assert_eq!(other_duration.last_frame_end_ns, receipt.last_frame_end_ns);
    assert_ne!(receipt.timing.domain(), stream::FRAME_RECEIPTS_DOMAIN);
    Ok(())
}

#[test]
fn movie_mode_and_interval_refusals_fence_writes_and_completion() -> Test {
    let rate = PlaybackRate::new(30, 1)?;
    let writer = Writer::new(17);
    let mut movie = Encoder::new_movie(DEFAULT_OUTPUT_BYTES, 1, 1000, pin(91))?;
    assert!(
        movie
            .frame(
                frame([3, 2], &[16; 6], pin(1)),
                || writer.create(),
                &mut || Ok(())
            )
            .is_err()
    );
    assert!(writer.bytes().is_empty());
    assert_fenced(movie, &writer, [3, 2], &[16; 6])?;
    let writer = Writer::new(17);
    let mut uniform = Encoder::new(DEFAULT_OUTPUT_BYTES, 1, rate)?;
    assert!(
        uniform
            .frame_at(
                frame([3, 2], &[16; 6], pin(1)),
                100,
                200,
                || writer.create(),
                &mut || Ok(())
            )
            .is_err()
    );
    assert!(writer.bytes().is_empty());
    assert_fenced(uniform, &writer, [3, 2], &[16; 6])?;
    for interval in [(199, 300), (300, 299), (300, 300), (300, 1001)] {
        let writer = Writer::new(17);
        let mut movie = Encoder::new_movie(DEFAULT_OUTPUT_BYTES, 2, 1000, pin(91))?;
        movie.frame_at(
            frame([3, 2], &[16; 6], pin(1)),
            100,
            200,
            || writer.create(),
            &mut || Ok(()),
        )?;
        let before = writer.bytes();
        assert!(
            movie
                .frame_at(
                    frame([3, 2], &[17; 6], pin(2)),
                    interval.0,
                    interval.1,
                    || writer.create(),
                    &mut || Ok(())
                )
                .is_err()
        );
        assert_eq!(writer.bytes(), before);
        assert_fenced(movie, &writer, [3, 2], &[16; 6])?;
    }
    for duration in [0, fss_container::matroska_gray::MAX_TIMED_DURATION_NS + 1] {
        assert!(Encoder::<Writer>::new_movie(DEFAULT_OUTPUT_BYTES, 1, duration, pin(91)).is_err());
    }
    for selection in [
        ContentDigest::new(DigestAlgorithm::Sha256, [0; 32]),
        pin(1).with_laboratory(true),
    ] {
        assert!(Encoder::<Writer>::new_movie(DEFAULT_OUTPUT_BYTES, 1, 1000, selection).is_err());
    }
    Ok(())
}

#[test]
fn movie_quota_accounts_for_duration_header_and_never_completes_a_prefix() -> Test {
    let (first, _) = encode_movie(&[(100, 200)], 1000, pin(91), 17)?;
    let (both, expected_receipt) = encode_movie(&[(100, 200), (300, 600)], 1000, pin(91), 17)?;
    let writer = Writer::new(17);
    let mut encoder = Encoder::new_movie(first.len() as u64 - 1, 1, 1000, pin(91))?;
    let mut checks = 0;
    assert!(
        encoder
            .frame_at(
                frame([3, 2], &[0, 16, 0, 127, 235, 255], pin(0)),
                100,
                200,
                || writer.create(),
                &mut || {
                    checks += 1;
                    Ok(())
                }
            )
            .is_err()
    );
    assert_eq!(checks, 1);
    assert_eq!(writer.0.borrow().created, 0);
    assert_fenced(encoder, &writer, [3, 2], &[16; 6])?;
    for maximum in [both.len() as u64 - 1, both.len() as u64] {
        let writer = Writer::new(17);
        let mut encoder = Encoder::new_movie(maximum, 2, 1000, pin(91))?;
        encoder.frame_at(
            frame([3, 2], &[0, 16, 0, 127, 235, 255], pin(0)),
            100,
            200,
            || writer.create(),
            &mut || Ok(()),
        )?;
        let result = encoder.frame_at(
            frame([3, 2], &[0, 16, 1, 127, 235, 255], pin(1)),
            300,
            600,
            || writer.create(),
            &mut || Ok(()),
        );
        if maximum == both.len() as u64 {
            result?;
            let (_, receipt) = encoder.finish(&mut || Ok(()))?;
            assert_eq!(writer.bytes(), both);
            same_receipt(&receipt, &expected_receipt);
        } else {
            assert!(result.is_err());
            assert_eq!(writer.bytes(), first);
            assert_fenced(encoder, &writer, [3, 2], &[16; 6])?;
        }
    }
    Ok(())
}

#[test]
fn movie_cancellation_at_every_frame_checkpoint_and_failed_flush_cannot_complete() -> Test {
    let writer = Writer::new(17);
    let mut encoder = Encoder::new_movie(DEFAULT_OUTPUT_BYTES, 1, 1000, pin(91))?;
    let mut checkpoints = 0;
    encoder.frame_at(
        frame([3, 2], &[16; 6], pin(1)),
        100,
        200,
        || writer.create(),
        &mut || {
            checkpoints += 1;
            Ok(())
        },
    )?;
    let expected = writer.bytes();
    encoder.finish(&mut || Ok(()))?;
    for cut in 1..=checkpoints {
        let writer = Writer::new(17);
        let mut encoder = Encoder::new_movie(DEFAULT_OUTPUT_BYTES, 1, 1000, pin(91))?;
        let mut count = 0;
        assert!(
            encoder
                .frame_at(
                    frame([3, 2], &[16; 6], pin(1)),
                    100,
                    200,
                    || writer.create(),
                    &mut || {
                        count += 1;
                        if count == cut {
                            Err(io::Error::other("cancelled timed frame"))
                        } else {
                            Ok(())
                        }
                    }
                )
                .is_err()
        );
        let written = writer.bytes();
        assert_eq!(written, expected[..written.len()]);
        assert_fenced(encoder, &writer, [3, 2], &[16; 6])?;
    }
    for case in 0..3 {
        let writer = Writer::new(17);
        let mut encoder = Encoder::new_movie(DEFAULT_OUTPUT_BYTES, 1, 1000, pin(91))?;
        encoder.frame_at(
            frame([3, 2], &[16; 6], pin(1)),
            100,
            200,
            || writer.create(),
            &mut || Ok(()),
        )?;
        writer.0.borrow_mut().flush_failure = case == 1;
        assert!(
            encoder
                .finish(&mut || {
                    if case == 0 || (case == 2 && writer.0.borrow().flushes > 0) {
                        Err(io::Error::other("cancelled timed finalization"))
                    } else {
                        Ok(())
                    }
                })
                .is_err()
        );
    }
    Ok(())
}
