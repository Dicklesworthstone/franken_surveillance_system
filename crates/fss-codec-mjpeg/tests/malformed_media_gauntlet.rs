#![forbid(unsafe_code)]
//! FSS-059 malformed-media gauntlet for every untrusted-byte entry point of this crate:
//! `decode_luma`, `color::decode_rgb`, `stream::JpegStream`, `multipart::MultipartStream`
//! and the `http::HttpResponseStream` -> `http_mjpeg::HttpMultipartStream` composition.
//!
//! Seeds are the checked-in fixtures (`tests/fixtures/*.jpg`) plus MIME/HTTP wrappers
//! built from them in-test. Mutants come from the shared fixed-seed engine in
//! `fss-packet/tests/media_mutation`. For every mutant the test asserts: no panic
//! (debug build, so arithmetic overflow panics too), Ok or a typed error, work charged
//! within the declared `DecodeBudget`, incremental parsers make progress on every call
//! (so the drive loop is bounded by the input length), identical results on a second
//! run, and no truncated or partial frame published as success.
//!
//! No-Claim: passing is evidence against these mutation classes over this corpus only;
//! it is not coverage-guided fuzzing and not a proof of absence of defects.

#[path = "../../fss-packet/tests/media_mutation/mod.rs"]
mod media_mutation;

use fss_codec_mjpeg::color::{RgbDecodeLimits, decode_rgb};
use fss_codec_mjpeg::http::{HttpEvent, HttpLimits, HttpResponseStream};
use fss_codec_mjpeg::http_mjpeg::HttpMultipartStream;
use fss_codec_mjpeg::multipart::{MultipartLimits, MultipartStream};
use fss_codec_mjpeg::stream::{FramingLimits, JpegStream, StreamBasis};
use fss_codec_mjpeg::{
    ComponentInterpretation, DecodeBudget, DecodeError, DecodeLimits, decode_luma,
};
use fss_core::ContentDigest;
use media_mutation::{
    CLASSES, Failure, LengthField, Mutation, Rng, Seed, Tally, check, mutate_stacked, report,
};

const FIXTURES: [(&str, &[u8]); 5] = [
    ("gray.jpg", include_bytes!("fixtures/gray.jpg")),
    (
        "y420_restart.jpg",
        include_bytes!("fixtures/y420_restart.jpg"),
    ),
    ("y422.jpg", include_bytes!("fixtures/y422.jpg")),
    ("y444.jpg", include_bytes!("fixtures/y444.jpg")),
    ("background.jpg", include_bytes!("fixtures/background.jpg")),
];

/// Declared per-decode work allowance; every mutant must stay within it.
const DECODE_BUDGET: u64 = 20_000_000;
/// Declared per-stream work allowance for the framing/MIME/HTTP drivers.
const STREAM_BUDGET: u64 = 200_000_000;

const JPEG_MUTANTS: usize = 20_000;
const STREAM_MUTANTS: usize = 8_000;
const MULTIPART_MUTANTS: usize = 8_000;
const HTTP_MUTANTS: usize = 8_000;

fn limits() -> DecodeLimits {
    // Narrowed owner limits: large enough for every fixture, small enough that a
    // mutated SOF cannot request more than 64x64 samples of work.
    DecodeLimits {
        maximum_bytes: 64 * 1024,
        maximum_dimension: 64,
        maximum_pixels: 4096,
        maximum_markers: 64,
    }
}

fn basis() -> StreamBasis {
    StreamBasis {
        source: [0x59; 32],
        generation: 59,
    }
}

fn be16(bytes: &[u8], at: usize) -> Option<usize> {
    Some(usize::from(u16::from_be_bytes([
        *bytes.get(at)?,
        *bytes.get(at + 1)?,
    ])))
}

/// JPEG structure: marker segments, entropy runs split at restart markers,
/// segment lengths, SOF dimensions and DRI intervals as length fields.
fn jpeg_seed(name: &str, bytes: &[u8]) -> Seed {
    let mut seed = Seed::new(name, bytes.to_vec());
    let mut at = 0;
    while at + 1 < bytes.len() {
        if bytes[at] != 0xFF {
            at += 1;
            continue;
        }
        let marker = bytes[at + 1];
        match marker {
            0xD8 | 0xD9 | 0x01 | 0xD0..=0xD7 => {
                seed.units.push(at..at + 2);
                at += 2;
            }
            0x00 | 0xFF => at += 1,
            _ => {
                let Some(length) = be16(bytes, at + 2) else {
                    break;
                };
                let end = (at + 2 + length).min(bytes.len());
                seed.units.push(at..end);
                seed.length_fields.push(LengthField::Binary {
                    offset: at + 2,
                    width: 2,
                });
                if matches!(marker, 0xC0..=0xC3) {
                    for offset in [at + 5, at + 7] {
                        seed.length_fields
                            .push(LengthField::Binary { offset, width: 2 });
                    }
                    seed.length_fields.push(LengthField::Binary {
                        offset: at + 9,
                        width: 1,
                    });
                }
                if marker == 0xDD {
                    seed.length_fields.push(LengthField::Binary {
                        offset: at + 4,
                        width: 2,
                    });
                }
                at = end;
                if marker == 0xDA {
                    // Entropy-coded data up to the next non-stuffed, non-RST marker.
                    let start = at;
                    let mut run = start;
                    while at + 1 < bytes.len() {
                        if bytes[at] == 0xFF && bytes[at + 1] != 0 {
                            if (0xD0..=0xD7).contains(&bytes[at + 1]) {
                                seed.units.push(run..at);
                                seed.units.push(at..at + 2);
                                at += 2;
                                run = at;
                                continue;
                            }
                            break;
                        }
                        at += 1;
                    }
                    if run < at {
                        seed.units.push(run..at);
                    }
                }
            }
        }
    }
    seed.markers = [
        [0xFF, 0xD8],
        [0xFF, 0xD9],
        [0xFF, 0xDA],
        [0xFF, 0xD0],
        [0xFF, 0xD7],
        [0xFF, 0x00],
        [0xFF, 0xC0],
        [0xFF, 0xC2],
        [0xFF, 0xC4],
        [0xFF, 0xDB],
        [0xFF, 0xDD],
        [0xFF, 0xFF],
    ]
    .iter()
    .map(|m| m.to_vec())
    .collect();
    seed
}

fn interpretation(bytes: &[u8]) -> ComponentInterpretation {
    // The SOF0 component count selects the explicit caller contract for the seed.
    let gray = bytes
        .windows(2)
        .position(|w| w == [0xFF, 0xC0])
        .and_then(|at| bytes.get(at + 9))
        == Some(&1);
    if gray {
        ComponentInterpretation::Grayscale
    } else {
        ComponentInterpretation::YCbCr
    }
}

fn corpus() -> Vec<Seed> {
    FIXTURES
        .iter()
        .map(|(name, bytes)| jpeg_seed(name, bytes))
        .collect()
}

fn is_strict_prefix(mutation: &Mutation) -> bool {
    matches!(mutation, Mutation::Truncate { .. })
}

/// Outcome summary compared across the two determinism runs.
#[derive(Debug, PartialEq)]
enum Decoded {
    Luma([u32; 2], [u8; 32], u64),
    Rgb([u32; 2], [u8; 32], u64),
    Refused(DecodeError, u64),
}

fn luma_target(bytes: &[u8], interp: ComponentInterpretation) -> Result<Decoded, String> {
    let digest = ContentDigest::sha256(bytes).bytes();
    let mut budget = DecodeBudget::new(DECODE_BUDGET);
    let result = decode_luma(bytes, digest, interp, limits(), &mut budget);
    if budget.used() > DECODE_BUDGET || budget.used() + budget.remaining() != DECODE_BUDGET {
        return Err(format!("budget accounting broken: used {}", budget.used()));
    }
    match result {
        Ok(image) => {
            let [w, h] = image.dimensions();
            let l = limits();
            let receipt = image.receipt();
            if w == 0
                || h == 0
                || w > l.maximum_dimension
                || h > l.maximum_dimension
                || (w as usize) * (h as usize) > l.maximum_pixels
                || image.pixels().len() != (w as usize) * (h as usize)
            {
                return Err(format!("luma outside declared limits: {w}x{h}"));
            }
            if receipt.encoded_sha256 != digest
                || receipt.luma_sha256 != ContentDigest::sha256(image.pixels()).bytes()
                || budget.used() < bytes.len() as u64
            {
                return Err("luma receipt does not bind source/pixels/work".into());
            }
            Ok(Decoded::Luma([w, h], receipt.luma_sha256, budget.used()))
        }
        Err(error) => Ok(Decoded::Refused(error, budget.used())),
    }
}

fn rgb_target(bytes: &[u8], interp: ComponentInterpretation) -> Result<Decoded, String> {
    let digest = ContentDigest::sha256(bytes).bytes();
    let mut budget = DecodeBudget::new(DECODE_BUDGET);
    let rgb_limits = RgbDecodeLimits {
        frame: limits(),
        maximum_output_bytes: 3 * 4096,
    };
    let result = decode_rgb(bytes, digest, interp, rgb_limits, &mut budget);
    if budget.used() > DECODE_BUDGET {
        return Err(format!("budget overrun: used {}", budget.used()));
    }
    match result {
        Ok(image) => {
            let [w, h] = image.dimensions();
            let receipt = image.receipt();
            let samples = (w as usize) * (h as usize) * 3;
            if w == 0
                || h == 0
                || w > 64
                || h > 64
                || image.pixels().len() != samples
                || samples > rgb_limits.maximum_output_bytes
            {
                return Err(format!("rgb outside declared limits: {w}x{h}"));
            }
            if receipt.encoded_sha256 != digest
                || receipt.rgb_sha256 != ContentDigest::sha256(image.pixels()).bytes()
            {
                return Err("rgb receipt does not bind source/pixels".into());
            }
            Ok(Decoded::Rgb([w, h], receipt.rgb_sha256, budget.used()))
        }
        Err(error) => Ok(Decoded::Refused(error, budget.used())),
    }
}

fn finish(target: &str, tally: &Tally, failures: Vec<Failure>, expected: usize) {
    report(target, tally);
    assert_eq!(tally.mutants, expected, "{target}: mutant count drifted");
    assert!(tally.refused > 0, "{target}: no mutant was refused");
    assert!(failures.is_empty(), "{target}: {failures:#?}");
}

/// Stateless frame decoders (luma and RGB) over mutated single JPEG frames,
/// plus exhaustive structural truncation at every marker/segment/RST boundary.
#[test]
fn jpeg_frame_decoders_survive_mutation_gauntlet() {
    const RNG_SEED: u64 = 0x0F55_0059_0000_0001;
    let seeds = corpus();
    let mut rng = Rng::new(RNG_SEED);
    let mut failures = Vec::new();
    let mut tally = Tally::default();
    for index in 0..JPEG_MUTANTS {
        let seed = &seeds[index % seeds.len()];
        let class = CLASSES[(index / seeds.len()) % CLASSES.len()];
        let (mutation, bytes) = mutate_stacked(seed, &seeds, class, &mut rng);
        let interp = interpretation(&seed.bytes);
        // Every eighth mutant also claims the wrong component interpretation.
        let interp = if index % 8 == 7 {
            match interp {
                ComponentInterpretation::Grayscale => ComponentInterpretation::YCbCr,
                ComponentInterpretation::YCbCr => ComponentInterpretation::Grayscale,
            }
        } else {
            interp
        };
        tally.count(class);
        tally.note(&mutation);
        let strict_prefix = is_strict_prefix(&mutation) && bytes.len() < seed.bytes.len();
        let run = || -> Result<(Decoded, Decoded), String> {
            let luma = luma_target(&bytes, interp)?;
            let rgb = rgb_target(&bytes, interp)?;
            if strict_prefix
                && (!matches!(luma, Decoded::Refused(..)) || !matches!(rgb, Decoded::Refused(..)))
            {
                return Err("truncated frame published as success".into());
            }
            Ok((luma, rgb))
        };
        if let Some((luma, _)) = check(
            "jpeg-frame",
            &seed.name,
            RNG_SEED,
            index,
            &mutation,
            &mut failures,
            run,
        ) {
            if matches!(luma, Decoded::Refused(..)) {
                tally.refused += 1;
            } else {
                tally.ok += 1;
            }
        }
    }
    // Exhaustive structural truncations, counted separately from the random mutants.
    let mut cuts = 0;
    for seed in &seeds {
        for cut in seed.structural_cuts() {
            cuts += 1;
            let bytes = &seed.bytes[..cut];
            let interp = interpretation(&seed.bytes);
            let mutation = Mutation::Truncate {
                len: cut,
                structural: true,
            };
            let run = || -> Result<Decoded, String> {
                let luma = luma_target(bytes, interp)?;
                let rgb = rgb_target(bytes, interp)?;
                match (&luma, &rgb) {
                    (Decoded::Refused(..), Decoded::Refused(..)) => Ok(luma),
                    _ => Err("structurally truncated frame published".into()),
                }
            };
            check(
                "jpeg-truncation",
                &seed.name,
                0,
                cut,
                &mutation,
                &mut failures,
                run,
            );
        }
    }
    println!("FSS-059 gauntlet jpeg-truncation: {cuts} exhaustive structural cuts");
    assert!(cuts > 100);
    finish("jpeg-frame", &tally, failures, JPEG_MUTANTS);
}

#[derive(Debug, PartialEq)]
struct StreamOutcome {
    frames: Vec<([u64; 2], [u8; 32], Option<Decoded>)>,
    end: Result<u64, String>,
    used: u64,
}

/// Feed `bytes` in `chunk`-sized pieces. Every accepting call must consume input,
/// so the loop is bounded by `bytes.len()` iterations plus one.
fn drive_jpeg_stream(bytes: &[u8], chunk: usize) -> Result<StreamOutcome, String> {
    let mut stream = JpegStream::new(
        basis(),
        FramingLimits {
            maximum_frame_bytes: 4096,
            maximum_markers: 64,
        },
    )
    .map_err(|e| format!("configuration refused: {e:?}"))?;
    let mut budget = DecodeBudget::new(STREAM_BUDGET);
    let mut frames = Vec::new();
    let mut offset = 0;
    let mut iterations = 0;
    let mut failed = None;
    while offset < bytes.len() {
        iterations += 1;
        if iterations > bytes.len() + 1 {
            return Err("framing made no progress (hang)".into());
        }
        let end = (offset + chunk).min(bytes.len());
        match stream.push(offset as u64, &bytes[offset..end], &mut budget) {
            Ok(step) => {
                if step.consumed == 0 || step.consumed > end - offset {
                    return Err(format!("bad consumed count {}", step.consumed));
                }
                offset += step.consumed;
                if let Some(frame) = step.frame {
                    let [a, b] = frame.byte_range();
                    let source = bytes.get(a as usize..b as usize);
                    if source != Some(frame.bytes())
                        || frame.bytes().len() > 4096
                        || frame.markers() > 64
                        || frame.encoded_sha256() != ContentDigest::sha256(frame.bytes()).bytes()
                    {
                        return Err("framed JPEG is not the exact bounded source range".into());
                    }
                    let mut decode_budget = DecodeBudget::new(DECODE_BUDGET);
                    let decoded = match frame.decode(
                        interpretation(frame.bytes()),
                        limits(),
                        &mut decode_budget,
                    ) {
                        Ok(image) => {
                            let [w, h] = image.dimensions();
                            if image.pixels().len() != (w as usize) * (h as usize)
                                || w > 64
                                || h > 64
                            {
                                return Err("framed decode outside limits".into());
                            }
                            Decoded::Luma([w, h], image.receipt().luma_sha256, decode_budget.used())
                        }
                        Err(e) => Decoded::Refused(e, decode_budget.used()),
                    };
                    frames.push(([a, b], frame.encoded_sha256(), Some(decoded)));
                }
            }
            Err(failure) => {
                if failure.consumed > end - offset {
                    return Err("failure consumed more than supplied".into());
                }
                failed = Some(format!("{:?}", failure.error));
                break;
            }
        }
    }
    let end = match failed {
        Some(error) => Err(error),
        None => stream
            .finish(&mut budget)
            .map(|end| end.frames)
            .map_err(|e| format!("{:?}", e.error)),
    };
    if budget.used() > STREAM_BUDGET {
        return Err("stream budget overrun".into());
    }
    Ok(StreamOutcome {
        frames,
        end,
        used: budget.used(),
    })
}

/// Concatenated-JPEG framing (`JpegStream`) followed by decode of each framed image.
#[test]
fn jpeg_stream_framing_survives_mutation_gauntlet() {
    const RNG_SEED: u64 = 0x0F55_0059_0000_0002;
    let singles = corpus();
    // Seeds: pairs of concatenated fixtures, with unit/length offsets shifted.
    let mut seeds = Vec::new();
    for i in 0..singles.len() {
        let a = &singles[i];
        let b = &singles[(i + 1) % singles.len()];
        let mut seed = a.clone();
        seed.name = format!("{}+{}", a.name, b.name);
        let shift = a.bytes.len();
        seed.bytes.extend_from_slice(&b.bytes);
        seed.units
            .extend(b.units.iter().map(|u| u.start + shift..u.end + shift));
        seed.length_fields
            .extend(b.length_fields.iter().map(|f| match f {
                LengthField::Binary { offset, width } => LengthField::Binary {
                    offset: offset + shift,
                    width: *width,
                },
                other => other.clone(),
            }));
        seeds.push(seed);
    }
    let originals: Vec<[u8; 32]> = FIXTURES
        .iter()
        .map(|(_, b)| ContentDigest::sha256(b).bytes())
        .collect();
    let mut rng = Rng::new(RNG_SEED);
    let mut failures = Vec::new();
    let mut tally = Tally::default();
    for index in 0..STREAM_MUTANTS {
        let seed = &seeds[index % seeds.len()];
        let class = CLASSES[(index / seeds.len()) % CLASSES.len()];
        let (mutation, bytes) = mutate_stacked(seed, &seeds, class, &mut rng);
        let chunk = 1 + (index * 37) % 257;
        tally.count(class);
        tally.note(&mutation);
        let truncated = is_strict_prefix(&mutation);
        let run = || -> Result<StreamOutcome, String> {
            let outcome = drive_jpeg_stream(&bytes, chunk)?;
            if truncated
                && outcome
                    .frames
                    .iter()
                    .any(|(_, digest, _)| !originals.contains(digest))
            {
                return Err("truncation produced a frame that is not an original image".into());
            }
            Ok(outcome)
        };
        if let Some(outcome) = check(
            "jpeg-stream",
            &seed.name,
            RNG_SEED,
            index,
            &mutation,
            &mut failures,
            run,
        ) {
            if outcome.end.is_err() {
                tally.refused += 1;
            } else {
                tally.ok += 1;
            }
        }
    }
    finish("jpeg-stream", &tally, failures, STREAM_MUTANTS);
}

const BOUNDARY: &str = "fss059";

/// Multipart entity with MIME structure as units and Content-Length as length fields.
fn multipart_seed(images: &[(&str, &[u8])], with_length: bool) -> Seed {
    let mut seed = Seed::new(
        format!(
            "multipart[{}]{}",
            images.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(","),
            if with_length { "+len" } else { "" }
        ),
        Vec::new(),
    );
    let push_unit = |seed: &mut Seed, bytes: &[u8]| {
        let start = seed.bytes.len();
        seed.bytes.extend_from_slice(bytes);
        seed.units.push(start..seed.bytes.len());
        start
    };
    push_unit(&mut seed, format!("--{BOUNDARY}\r\n").as_bytes());
    for (i, (_, image)) in images.iter().enumerate() {
        push_unit(&mut seed, b"Content-Type: image/jpeg\r\n");
        if with_length {
            let line = format!("Content-Length: {}\r\n", image.len());
            let start = push_unit(&mut seed, line.as_bytes());
            let digits = start + "Content-Length: ".len();
            seed.length_fields.push(LengthField::Decimal {
                range: digits..digits + image.len().to_string().len(),
            });
        }
        push_unit(&mut seed, b"\r\n");
        let image_start = push_unit(&mut seed, image);
        let inner = jpeg_seed("", image);
        seed.units.extend(
            inner
                .units
                .iter()
                .map(|u| u.start + image_start..u.end + image_start),
        );
        let closing = if i + 1 == images.len() {
            format!("\r\n--{BOUNDARY}--\r\n")
        } else {
            format!("\r\n--{BOUNDARY}\r\n")
        };
        push_unit(&mut seed, closing.as_bytes());
    }
    seed.units.sort_by_key(|u| (u.start, u.end));
    seed.markers = vec![
        format!("\r\n--{BOUNDARY}\r\n").into_bytes(),
        format!("\r\n--{BOUNDARY}--").into_bytes(),
        format!("--{BOUNDARY}").into_bytes(),
        b"\r\n\r\n".to_vec(),
        b"Content-Length: 0\r\n".to_vec(),
        b"Content-Type: text/plain\r\n".to_vec(),
        vec![0xFF, 0xD9],
        b"\r".to_vec(),
    ];
    seed
}

#[derive(Debug, PartialEq)]
struct PartOutcome {
    parts: Vec<([u64; 2], [u8; 32], Option<Decoded>)>,
    end: Result<u64, String>,
    used: u64,
}

fn part_invariants(
    entity: &[u8],
    range: [u64; 2],
    part: &[u8],
    digest: [u8; 32],
    limits: MultipartLimits,
) -> Result<Decoded, String> {
    if entity.get(range[0] as usize..range[1] as usize) != Some(part)
        || part.len() > limits.frame_bytes
        || digest != ContentDigest::sha256(part).bytes()
    {
        return Err("multipart JPEG is not the exact bounded entity range".into());
    }
    luma_target(part, interpretation(part))
}

fn multipart_limits() -> MultipartLimits {
    MultipartLimits {
        frame_bytes: 4096,
        header_bytes: 512,
        wrapper_bytes: 256,
    }
}

fn drive_multipart(entity: &[u8], chunk: usize) -> Result<PartOutcome, String> {
    let limits = multipart_limits();
    let mut budget = DecodeBudget::new(STREAM_BUDGET);
    let content_type = format!("multipart/x-mixed-replace; boundary={BOUNDARY}");
    let mut parser = MultipartStream::new(basis(), &content_type, limits, &mut budget)
        .map_err(|e| format!("configuration refused: {e:?}"))?;
    let mut parts = Vec::new();
    let mut at = 0;
    let mut iterations = 0;
    let mut failed = None;
    while at < entity.len() {
        iterations += 1;
        if iterations > entity.len() + 1 {
            return Err("multipart made no progress (hang)".into());
        }
        let end = (at + chunk).min(entity.len());
        match parser.push(at as u64, &entity[at..end], &mut budget) {
            Ok(step) => {
                if step.consumed == 0 || step.consumed > end - at {
                    return Err(format!("bad consumed count {}", step.consumed));
                }
                at += step.consumed;
                if let Some(frame) = step.frame {
                    let r = frame.receipt();
                    let decoded = part_invariants(
                        entity,
                        r.jpeg_range,
                        frame.bytes(),
                        r.encoded_sha256,
                        limits,
                    )?;
                    parts.push((r.jpeg_range, r.encoded_sha256, Some(decoded)));
                }
            }
            Err(failure) => {
                failed = Some(format!("{:?}", failure.error));
                break;
            }
        }
    }
    let end = match failed {
        Some(error) => Err(error),
        None => match parser.finish(&mut budget) {
            Ok(finish) => {
                if let Some(frame) = finish.frame {
                    let r = frame.receipt();
                    let decoded = part_invariants(
                        entity,
                        r.jpeg_range,
                        frame.bytes(),
                        r.encoded_sha256,
                        limits,
                    )?;
                    parts.push((r.jpeg_range, r.encoded_sha256, Some(decoded)));
                }
                if finish.end.preamble.bytes().len() > limits.wrapper_bytes
                    || finish.end.epilogue.bytes().len() > limits.wrapper_bytes
                {
                    return Err("wrapper retained beyond its limit".into());
                }
                Ok(finish.end.frames)
            }
            Err(e) => Err(format!("{:?}", e.error)),
        },
    };
    if budget.used() > STREAM_BUDGET {
        return Err("multipart budget overrun".into());
    }
    Ok(PartOutcome {
        parts,
        end,
        used: budget.used(),
    })
}

/// Dechunked multipart/x-mixed-replace entities, with and without Content-Length.
#[test]
fn multipart_framing_survives_mutation_gauntlet() {
    const RNG_SEED: u64 = 0x0F55_0059_0000_0003;
    let seeds = vec![
        multipart_seed(&[FIXTURES[0], FIXTURES[1]], false),
        multipart_seed(&[FIXTURES[2], FIXTURES[3]], true),
        multipart_seed(&[FIXTURES[4], FIXTURES[0], FIXTURES[2]], true),
    ];
    let mut rng = Rng::new(RNG_SEED);
    let mut failures = Vec::new();
    let mut tally = Tally::default();
    for index in 0..MULTIPART_MUTANTS {
        let seed = &seeds[index % seeds.len()];
        let class = CLASSES[(index / seeds.len()) % CLASSES.len()];
        let (mutation, bytes) = mutate_stacked(seed, &seeds, class, &mut rng);
        let chunk = 1 + (index * 53) % 311;
        tally.count(class);
        tally.note(&mutation);
        let run = || drive_multipart(&bytes, chunk);
        if let Some(outcome) = check(
            "multipart",
            &seed.name,
            RNG_SEED,
            index,
            &mutation,
            &mut failures,
            run,
        ) {
            if outcome.end.is_err() {
                tally.refused += 1;
            } else {
                tally.ok += 1;
            }
        }
    }
    finish("multipart", &tally, failures, MULTIPART_MUTANTS);
}

/// HTTP response wire: header lines, chunk-size lines, chunk data and MIME units.
fn http_seed(chunked: bool, chunk: usize, images: &[(&str, &[u8])]) -> Seed {
    let entity = multipart_seed(images, true);
    let mut seed = Seed::new(
        format!(
            "http[{}]{}",
            entity.name,
            if chunked { "chunked" } else { "length" }
        ),
        Vec::new(),
    );
    let line = |seed: &mut Seed, bytes: &[u8]| {
        let start = seed.bytes.len();
        seed.bytes.extend_from_slice(bytes);
        seed.units.push(start..seed.bytes.len());
        start
    };
    line(&mut seed, b"HTTP/1.1 200 OK\r\n");
    line(
        &mut seed,
        format!("Content-Type: multipart/x-mixed-replace; boundary={BOUNDARY}\r\n").as_bytes(),
    );
    if chunked {
        line(&mut seed, b"Transfer-Encoding: chunked\r\n");
        line(&mut seed, b"\r\n");
        for part in entity.bytes.chunks(chunk) {
            let size = format!("{:x}", part.len());
            let start = line(&mut seed, format!("{size}\r\n").as_bytes());
            seed.length_fields.push(LengthField::Hex {
                range: start..start + size.len(),
            });
            line(&mut seed, part);
            line(&mut seed, b"\r\n");
        }
        line(&mut seed, b"0\r\n");
        line(&mut seed, b"\r\n");
    } else {
        let digits = entity.bytes.len().to_string();
        let start = line(
            &mut seed,
            format!("Content-Length: {digits}\r\n").as_bytes(),
        );
        let at = start + "Content-Length: ".len();
        seed.length_fields.push(LengthField::Decimal {
            range: at..at + digits.len(),
        });
        line(&mut seed, b"\r\n");
        let body = seed.bytes.len();
        seed.bytes.extend_from_slice(&entity.bytes);
        seed.units
            .extend(entity.units.iter().map(|u| u.start + body..u.end + body));
        seed.length_fields
            .extend(entity.length_fields.iter().map(|f| match f {
                LengthField::Decimal { range } => LengthField::Decimal {
                    range: range.start + body..range.end + body,
                },
                other => other.clone(),
            }));
    }
    seed.markers = vec![
        b"\r\n\r\n".to_vec(),
        b"0\r\n\r\n".to_vec(),
        b"Content-Length: 5\r\n".to_vec(),
        b"Transfer-Encoding: gzip\r\n".to_vec(),
        b"HTTP/1.1 100 Continue\r\n\r\n".to_vec(),
        b"ffffffffffffffff\r\n".to_vec(),
        format!("\r\n--{BOUNDARY}\r\n").into_bytes(),
        b"\n".to_vec(),
    ];
    seed
}

#[derive(Debug, PartialEq)]
struct HttpOutcome {
    frames: Vec<([u8; 32], Decoded)>,
    end: Result<u64, String>,
    used: u64,
}

fn check_http_frame(
    wire: &[u8],
    frame: &fss_codec_mjpeg::http_mjpeg::HttpJpegFrame,
) -> Result<([u8; 32], Decoded), String> {
    // Complete, ordered source map: the JPEG is exactly the concatenation of its spans.
    let part = frame.part().bytes();
    let mut rebuilt = Vec::new();
    let mut next = 0;
    for span in frame.source_spans() {
        if span.jpeg_range[0] != next
            || span.jpeg_range[1] <= span.jpeg_range[0]
            || span.wire_range[1] - span.wire_range[0] != span.jpeg_range[1] - span.jpeg_range[0]
        {
            return Err("HTTP JPEG source map is not contiguous".into());
        }
        let bytes = wire
            .get(span.wire_range[0] as usize..span.wire_range[1] as usize)
            .ok_or("source span beyond wire")?;
        rebuilt.extend_from_slice(bytes);
        next = span.jpeg_range[1];
    }
    if rebuilt != part || part.len() > multipart_limits().frame_bytes {
        return Err("HTTP JPEG bytes do not equal their mapped wire bytes".into());
    }
    let digest = frame.part().receipt().encoded_sha256;
    Ok((digest, luma_target(part, interpretation(part))?))
}

fn drive_http(wire: &[u8], split: usize) -> Result<HttpOutcome, String> {
    let limits = HttpLimits {
        header_bytes: 1024,
        fragment_bytes: 512,
        chunk_bytes: 8192,
        entity_bytes: 1 << 20,
        wire_bytes: 1 << 21,
        chunks: 1024,
    };
    let mut http = HttpResponseStream::new(basis(), limits)
        .map_err(|e| format!("configuration refused: {e:?}"))?;
    let mut budget = DecodeBudget::new(STREAM_BUDGET);
    let mut consumer: Option<HttpMultipartStream> = None;
    let mut frames = Vec::new();
    let mut failed = None;
    let mut iterations = 0;
    let mut pos = 0;
    'outer: while pos < wire.len() {
        iterations += 1;
        if iterations > wire.len() + 1 {
            return Err("HTTP made no progress (hang)".into());
        }
        let end = (pos + split).min(wire.len());
        let step = match http.push(http.next_offset(), &wire[pos..end], &mut budget) {
            Ok(step) => step,
            Err(failure) => {
                failed = Some(format!("http {:?}", failure.error));
                break;
            }
        };
        if step.consumed == 0 || step.consumed > end - pos {
            return Err(format!("bad HTTP consumed count {}", step.consumed));
        }
        pos += step.consumed;
        match step.event {
            Some(HttpEvent::Head(head)) => {
                match HttpMultipartStream::new(&head, multipart_limits(), 4096, &mut budget) {
                    Ok(stream) => consumer = Some(stream),
                    Err(error) => {
                        failed = Some(format!("mime {error:?}"));
                        break;
                    }
                }
            }
            Some(HttpEvent::Data(data)) => {
                let Some(mime) = consumer.as_mut() else {
                    return Err("entity data before head".into());
                };
                let [a, b] = data.mapping().wire_range;
                if wire.get(a as usize..b as usize) != Some(data.bytes())
                    || data.bytes().len() > limits.fragment_bytes
                {
                    return Err("entity data is not its exact bounded wire range".into());
                }
                let mut used = 0;
                let mut inner = 0;
                while used < data.bytes().len() {
                    inner += 1;
                    if inner > data.bytes().len() + 1 {
                        return Err("MIME consumer made no progress (hang)".into());
                    }
                    match mime.push(&data, used, &mut budget) {
                        Ok(s) => {
                            if s.consumed == 0 {
                                return Err("MIME consumer consumed nothing".into());
                            }
                            used += s.consumed;
                            if let Some(frame) = s.frame {
                                frames.push(check_http_frame(wire, &frame)?);
                            }
                        }
                        Err(failure) => {
                            failed = Some(format!("mime {:?}", failure.error));
                            break 'outer;
                        }
                    }
                }
            }
            Some(HttpEvent::Control(_)) | None => {}
        }
    }
    let end = match failed {
        Some(error) => Err(error),
        None => match (http.finish(&mut budget), consumer.as_mut()) {
            (Ok(http_end), Some(mime)) => match mime.finish(http_end, &mut budget) {
                Ok(mut end) => {
                    if let Some(frame) = end.final_frame.take() {
                        frames.push(check_http_frame(wire, &frame)?);
                    }
                    if end.http.entity_bytes != end.multipart.bytes {
                        return Err("HTTP and MIME byte accounting disagree".into());
                    }
                    Ok(end.multipart.frames)
                }
                Err(error) => Err(format!("mime {error:?}")),
            },
            (Ok(_), None) => Err("no head".into()),
            (Err(error), _) => Err(format!("http {error:?}")),
        },
    };
    if budget.used() > STREAM_BUDGET {
        return Err("HTTP budget overrun".into());
    }
    Ok(HttpOutcome {
        frames,
        end,
        used: budget.used(),
    })
}

/// HTTP/1.1 response (Content-Length and chunked) carrying multipart JPEG.
#[test]
fn http_multipart_jpeg_survives_mutation_gauntlet() {
    const RNG_SEED: u64 = 0x0F55_0059_0000_0004;
    let seeds = vec![
        http_seed(false, 0, &[FIXTURES[0], FIXTURES[1]]),
        http_seed(true, 97, &[FIXTURES[2], FIXTURES[4]]),
        http_seed(true, 400, &[FIXTURES[3], FIXTURES[0]]),
    ];
    let mut rng = Rng::new(RNG_SEED);
    let mut failures = Vec::new();
    let mut tally = Tally::default();
    for index in 0..HTTP_MUTANTS {
        let seed = &seeds[index % seeds.len()];
        let class = CLASSES[(index / seeds.len()) % CLASSES.len()];
        let (mutation, bytes) = mutate_stacked(seed, &seeds, class, &mut rng);
        let split = 1 + (index * 71) % 509;
        tally.count(class);
        tally.note(&mutation);
        let run = || drive_http(&bytes, split);
        if let Some(outcome) = check(
            "http-mjpeg",
            &seed.name,
            RNG_SEED,
            index,
            &mutation,
            &mut failures,
            run,
        ) {
            if outcome.end.is_err() {
                tally.refused += 1;
            } else {
                tally.ok += 1;
            }
        }
    }
    assert!(
        tally
            .per_class
            .iter()
            .all(|(c, n)| *n > 0 && CLASSES.contains(c)),
        "every class must be exercised"
    );
    finish("http-mjpeg", &tally, failures, HTTP_MUTANTS);
}
