//! Bit-exact differential conformance against the sealed FFmpeg oracle.
//!
//! Every fixture stream in `tests/fixtures/decode/` has a sibling
//! `.sha256` file produced OFFLINE by
//! `scripts/generate_h265_decode_fixtures.sh`: FFmpeg decodes the stream to
//! packed I420 and records one SHA-256 per frame in FFmpeg's OUTPUT
//! (display) order. These tests decode the same bytes with the pure-Rust
//! decoder and require every frame digest, in the same order, the frame
//! count and the frame size to match exactly. No expected value here is
//! derived from this crate's own output.

#![forbid(unsafe_code)]

use std::error::Error;

use fss_codec_h265::{Decoder, DecoderLimits, Picture};

type TestResult = Result<(), Box<dyn Error>>;

struct OracleFrame {
    bytes: usize,
    sha256: String,
}

fn parse_oracle(text: &str) -> Result<Vec<OracleFrame>, Box<dyn Error>> {
    let mut frames = Vec::new();
    for (index, line) in text
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .enumerate()
    {
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 3, "oracle line {line:?}");
        assert_eq!(fields[0].parse::<usize>()?, index, "oracle frame order");
        frames.push(OracleFrame {
            bytes: fields[1].parse()?,
            sha256: fields[2].to_owned(),
        });
    }
    Ok(frames)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    out
}

fn decode_stream(stream: &[u8]) -> Result<Vec<Picture>, Box<dyn Error>> {
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let mut pictures = decoder.decode_annex_b(stream)?;
    pictures.extend(decoder.finish()?);
    Ok(pictures)
}

/// Optional local aid: when `tests/fixtures/decode_debug/<name>.yuv` (raw
/// oracle frames, never committed) exists, report the first differing
/// sample to localise a mismatch. It never changes the verdict.
fn locate_mismatch(name: &str, index: usize, picture: &Picture) -> String {
    let path = format!(
        "{}/tests/fixtures/decode_debug/{name}.yuv",
        env!("CARGO_MANIFEST_DIR")
    );
    let Ok(raw) = std::fs::read(path) else {
        return String::from("(no local raw oracle frames for localisation)");
    };
    let ours = picture.to_i420();
    let Some(theirs) = raw.get(index * ours.len()..(index + 1) * ours.len()) else {
        return String::from("(raw oracle frame missing)");
    };
    let luma = (picture.width() * picture.height()) as usize;
    let chroma = (picture.chroma_width() * picture.chroma_height()) as usize;
    let differing = ours.iter().zip(theirs).filter(|(a, b)| a != b).count();
    match ours.iter().zip(theirs).position(|(a, b)| a != b) {
        None => String::from("(raw frames equal?)"),
        Some(pos) => {
            let (plane, offset, width) = if pos < luma {
                ("Y", pos, picture.width() as usize)
            } else if pos < luma + chroma {
                ("Cb", pos - luma, picture.chroma_width() as usize)
            } else {
                ("Cr", pos - luma - chroma, picture.chroma_width() as usize)
            };
            format!(
                "first diff {plane} x={} y={}: ours {} oracle {}; {differing} samples differ",
                offset % width,
                offset / width,
                ours[pos],
                theirs[pos]
            )
        }
    }
}

/// Output order of a decode: identical to decode order, or reordered
/// (B pictures), which the digest sequence then pins down.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Order {
    Decode,
    Reordered,
}

fn check(name: &str, stream: &[u8], oracle: &str, order: Order) -> TestResult {
    let expected = parse_oracle(oracle)?;
    assert!(!expected.is_empty(), "{name}: empty oracle");
    let pictures = decode_stream(stream)?;
    assert_eq!(pictures.len(), expected.len(), "{name}: frame count");
    for (index, (picture, frame)) in pictures.iter().zip(&expected).enumerate() {
        let bytes = picture.to_i420();
        assert_eq!(bytes.len(), frame.bytes, "{name} frame {index}: I420 size");
        let digest = hex(&picture.i420_sha256());
        assert!(
            digest == frame.sha256,
            "{name} frame {index} (poc {}): digest {digest} != oracle {}; {}",
            picture.poc(),
            frame.sha256,
            locate_mismatch(name, index, picture)
        );
        if order == Order::Decode {
            assert_eq!(picture.decode_index(), index as u64, "{name}: decode order");
        }
    }
    if order == Order::Reordered {
        assert!(
            pictures
                .iter()
                .enumerate()
                .any(|(index, p)| p.decode_index() != index as u64),
            "{name}: expected output order to differ from decode order"
        );
    }
    // Output order is display order: POC increases between IRAP pictures
    // that start a new sequence (IDR / BLA reset POC to 0).
    for pair in pictures.windows(2) {
        if !pair[1].is_idr() {
            assert!(pair[0].poc() < pair[1].poc(), "{name}: POC order {pair:?}");
        }
    }
    // Every decode index appears exactly once.
    let mut seen: Vec<u64> = pictures.iter().map(Picture::decode_index).collect();
    seen.sort_unstable();
    assert_eq!(
        seen,
        (0..pictures.len() as u64).collect::<Vec<_>>(),
        "{name}"
    );
    Ok(())
}

macro_rules! oracle_test {
    ($test:ident, $name:literal) => {
        oracle_test!($test, $name, Order::Decode);
    };
    ($test:ident, $name:literal, $order:expr) => {
        #[test]
        fn $test() -> TestResult {
            check(
                $name,
                include_bytes!(concat!("fixtures/decode/", $name, ".h265")),
                include_str!(concat!("fixtures/decode/", $name, ".sha256")),
                $order,
            )
        }
    };
}

// ----- Stage 1: intra-only Main streams (in-loop filters off) -----
oracle_test!(intra_64x64_ctu32_bit_exact, "i_64x64_ctu32_qp30");
oracle_test!(intra_qcif_ctu64_tu_depth3_bit_exact, "i_qcif_ctu64_qp22");
oracle_test!(intra_qcif_ctu16_qp37_bit_exact, "i_qcif_ctu16_qp37");
oracle_test!(intra_mandelbrot_qp12_wpp_bit_exact, "i_mandel_128x96_qp12");
oracle_test!(intra_cropped_100x60_bit_exact, "i_100x60_crop");
oracle_test!(intra_transform_skip_bit_exact, "i_qcif_tskip");
oracle_test!(
    intra_default_scaling_lists_bit_exact,
    "i_qcif_scaling_default"
);
oracle_test!(intra_no_sign_hiding_bit_exact, "i_qcif_nosignhide");
oracle_test!(intra_cu_qp_delta_bit_exact, "i_qcif_cuqp");
oracle_test!(intra_wavefront_bit_exact, "i_qcif_wpp");
oracle_test!(intra_four_slices_wpp_bit_exact, "i_qcif_slices4");
oracle_test!(
    intra_lossless_transquant_bypass_bit_exact,
    "i_64x64_lossless"
);
oracle_test!(intra_no_strong_smoothing_bit_exact, "i_qcif_nostrong");
oracle_test!(
    intra_custom_sps_scaling_lists_bit_exact,
    "i_qcif_scaling_custom"
);
oracle_test!(intra_cra_pictures_bit_exact, "i_qcif_cra");
// Hand-assembled PCM + intra coding units (scripts/generate_h265_pcm_fixture.py).
oracle_test!(pcm_mixed_nodeblock_bit_exact, "pcm_mixed_nodeblock");

// ----- Stage 2: P and B slices (in-loop filters off) -----
oracle_test!(p_single_reference_bit_exact, "p_qcif_ref1");
oracle_test!(p_three_refs_rect_amp_bit_exact, "p_qcif_ref3_amp");
oracle_test!(p_cropped_edge_clamping_bit_exact, "p_100x60_crop");
oracle_test!(p_inter_transform_depth_bit_exact, "p_mandel_tu_inter");
oracle_test!(p_constrained_intra_bit_exact, "p_qcif_constrained_intra");
oracle_test!(p_no_tmvp_single_merge_bit_exact, "p_qcif_notmvp_merge1");
oracle_test!(b_pyramid_ref3_bit_exact, "b_qcif_pyramid", Order::Reordered);
oracle_test!(
    b_no_pyramid_ref1_bit_exact,
    "b_qcif_nopyramid_ref1",
    Order::Reordered
);
oracle_test!(
    b_weighted_prediction_bit_exact,
    "b_128x96_weighted",
    Order::Reordered
);
oracle_test!(b_open_gop_cra_bit_exact, "b_qcif_opengop", Order::Reordered);
oracle_test!(
    b_wavefront_two_slices_bit_exact,
    "b_qcif_wpp_slices",
    Order::Reordered
);

/// Independent of any decoder: the PCM coding units must reproduce the
/// generator's sample pattern exactly (scripts/generate_h265_pcm_fixture.py:
/// luma ((7x + 13y + 50k) & 31) << 3, chroma ((11x + 5y + 30k + 17c) &
/// 63) << 2, for the 16x16 unit k = 0 at (0, 0) and the 8x8 unit k = 1 at
/// (16, 0) of a 32x16 picture).
#[test]
fn pcm_samples_match_generator_pattern() -> TestResult {
    let pictures = decode_stream(include_bytes!("fixtures/decode/pcm_mixed_nodeblock.h265"))?;
    assert_eq!(pictures.len(), 1);
    let picture = &pictures[0];
    assert_eq!((picture.width(), picture.height()), (32, 16));
    for (k, x0, size) in [(0usize, 0usize, 16usize), (1, 16, 8)] {
        for y in 0..size {
            for x in 0..size {
                let expected = (((x * 7 + y * 13 + k * 50) & 31) << 3) as u8;
                assert_eq!(
                    picture.luma()[y * 32 + x0 + x],
                    expected,
                    "luma k {k} ({x},{y})"
                );
            }
        }
        for (c, plane) in [picture.cb(), picture.cr()].into_iter().enumerate() {
            for y in 0..size / 2 {
                for x in 0..size / 2 {
                    let expected = (((x * 11 + y * 5 + k * 30 + c * 17) & 63) << 2) as u8;
                    let sample = plane[y * 16 + x0 / 2 + x];
                    assert_eq!(sample, expected, "chroma {c} k {k} ({x},{y})");
                }
            }
        }
    }
    Ok(())
}

/// B-pyramid output order: 12 pictures (IDR + 11 inter) in strictly
/// increasing POC, released while decoding (not only at `finish`), with
/// the display-order POCs 0..=11 of a closed GOP.
#[test]
fn b_pyramid_output_is_display_order() -> TestResult {
    let stream = include_bytes!("fixtures/decode/b_qcif_pyramid.h265");
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let early = decoder.decode_annex_b(stream)?;
    assert!(
        !early.is_empty(),
        "the reorder depth releases pictures early"
    );
    let mut pictures = early;
    pictures.extend(decoder.finish()?);
    let pocs: Vec<i32> = pictures.iter().map(Picture::poc).collect();
    assert_eq!(pocs, (0..12).collect::<Vec<_>>());
    Ok(())
}

/// Picture order count across CRA pictures that do not start a new coded
/// video sequence: 0 (IDR), then 1 and 2 (CRA, POC continues).
#[test]
fn cra_pictures_continue_poc() -> TestResult {
    let pictures = decode_stream(include_bytes!("fixtures/decode/i_qcif_cra.h265"))?;
    let pocs: Vec<i32> = pictures.iter().map(Picture::poc).collect();
    assert_eq!(pocs, vec![0, 1, 2]);
    assert!(pictures[0].is_idr());
    assert!(pictures[1..].iter().all(|p| p.is_irap() && !p.is_idr()));
    Ok(())
}

/// Streams outside the admitted tool set are refused with a typed error
/// naming the feature, never decoded approximately.
#[test]
fn unsupported_profiles_and_formats_are_refused() -> TestResult {
    use fss_codec_h265::{DecodeError, UnsupportedFeature};
    let cases: [(&[u8], UnsupportedFeature); 3] = [
        (
            include_bytes!("fixtures/decode/unsupported_rext_main_intra.h265"),
            UnsupportedFeature::Profile,
        ),
        (
            include_bytes!("fixtures/decode/unsupported_main10.h265"),
            UnsupportedFeature::SampleFormat,
        ),
        (
            include_bytes!("fixtures/decode/unsupported_422.h265"),
            UnsupportedFeature::SampleFormat,
        ),
    ];
    for (stream, feature) in cases {
        let mut decoder = Decoder::new(DecoderLimits::default())?;
        assert_eq!(
            decoder.decode_annex_b(stream).err(),
            Some(DecodeError::Unsupported(feature))
        );
    }
    Ok(())
}

/// Cropping metadata: 100x60 is coded as 104x64 (8-sample minimum coding
/// blocks) with a right/bottom conformance window.
#[test]
fn cropped_dimensions_and_plane_sizes() -> TestResult {
    let pictures = decode_stream(include_bytes!("fixtures/decode/i_100x60_crop.h265"))?;
    let first = &pictures[0];
    assert_eq!((first.width(), first.height()), (100, 60));
    assert_eq!((first.chroma_width(), first.chroma_height()), (50, 30));
    assert_eq!(first.luma().len(), 6_000);
    assert_eq!(first.cb().len(), 1_500);
    assert!(first.is_idr() && first.is_irap());
    Ok(())
}

/// NAL-by-NAL feeding yields the same pictures as whole-buffer feeding.
#[test]
fn nal_by_nal_matches_annex_b() -> TestResult {
    for stream in [
        &include_bytes!("fixtures/decode/i_qcif_slices4.h265")[..],
        &include_bytes!("fixtures/decode/b_qcif_pyramid.h265")[..],
    ] {
        nal_by_nal_matches(stream)?;
    }
    Ok(())
}

fn nal_by_nal_matches(stream: &[u8]) -> TestResult {
    let whole = decode_stream(stream)?;
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let mut pieces = Vec::new();
    for nal in fss_codec_h265::annex_b_nal_units(stream) {
        if let Some(picture) = decoder.decode_nal(nal)? {
            pieces.push(picture);
        }
        while let Some(picture) = decoder.next_output() {
            pieces.push(picture);
        }
    }
    pieces.extend(decoder.finish()?);
    assert_eq!(whole, pieces);
    Ok(())
}
