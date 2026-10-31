#![forbid(unsafe_code)]
//! Independent libjpeg progressive/baseline pairs, FFmpeg luma, and hostile scan contracts.

use fss_codec_mjpeg::color::{
    RgbDecodeLimits, decode_rgb, decode_rgb_for_identity, decode_rgb_v1,
    progressive_rgb_decoder_identity, rgb_decoder_identity,
};
use fss_codec_mjpeg::{
    ComponentInterpretation as Color, DecodeBudget, DecodeError, DecodeLimits, DecodedLuma,
    decode_luma, decode_luma_for_identity, decode_luma_v1, decoder_identity,
    decoder_identity_for_frame, progressive_decoder_identity,
};
use fss_core::ContentDigest;
use std::sync::atomic::AtomicBool;

type Test = Result<(), Box<dyn std::error::Error>>;
struct Case {
    name: &'static str,
    progressive: &'static [u8],
    baseline: &'static [u8],
    oracle: &'static [u8],
    color: Color,
    dimensions: [u32; 2],
    restarts: usize,
}
macro_rules! case {
    ($name:literal, $color:expr, $dimensions:expr, $restarts:expr) => {
        Case {
            name: $name,
            progressive: include_bytes!(concat!(
                "fixtures/progressive_jpeg/",
                $name,
                ".progressive.jpg"
            )),
            baseline: include_bytes!(concat!(
                "fixtures/progressive_jpeg/",
                $name,
                ".baseline.jpg"
            )),
            oracle: include_bytes!(concat!("fixtures/progressive_jpeg/", $name, ".ffmpeg.luma")),
            color: $color,
            dimensions: $dimensions,
            restarts: $restarts,
        }
    };
}
const CASES: &[Case] = &[
    case!("gray_17x19_rst0", Color::Grayscale, [17, 19], 0),
    case!("gray_37x29_rst2", Color::Grayscale, [37, 29], 54),
    case!("444_17x19_rst0", Color::YCbCr, [17, 19], 0),
    case!("444_37x29_rst2", Color::YCbCr, [37, 29], 90),
    case!("422_17x19_rst0", Color::YCbCr, [17, 19], 0),
    case!("422_37x29_rst2", Color::YCbCr, [37, 29], 66),
    case!("420_17x19_rst0", Color::YCbCr, [17, 19], 0),
    case!("420_37x29_rst2", Color::YCbCr, [37, 29], 48),
];
fn digest(bytes: &[u8]) -> [u8; 32] {
    ContentDigest::sha256(bytes).bytes()
}
fn decode(bytes: &[u8], color: Color) -> Result<DecodedLuma, DecodeError> {
    decode_luma(
        bytes,
        digest(bytes),
        color,
        DecodeLimits::default(),
        &mut DecodeBudget::new(100_000_000),
    )
}

#[test]
fn real_progressive_spectral_refinement_restart_and_sampling_pairs_match_exactly() -> Test {
    for case in CASES {
        let mut luma_budget = DecodeBudget::new(100_000_000);
        let progressive = decode_luma(
            case.progressive,
            digest(case.progressive),
            case.color,
            DecodeLimits::default(),
            &mut luma_budget,
        )?;
        let baseline = decode_luma_v1(
            case.baseline,
            digest(case.baseline),
            case.color,
            DecodeLimits::default(),
            &mut DecodeBudget::new(100_000_000),
        )?;
        assert_eq!(progressive.dimensions(), case.dimensions, "{}", case.name);
        assert_eq!(progressive.pixels(), baseline.pixels(), "{}", case.name);
        assert_eq!(
            progressive.receipt().restarts,
            case.restarts,
            "{}",
            case.name
        );
        assert_eq!(
            progressive.receipt().decoder,
            progressive_decoder_identity()
        );
        assert_eq!(
            progressive.receipt().encoded_sha256,
            digest(case.progressive)
        );
        assert!(progressive.receipt().entropy_blocks > baseline.receipt().entropy_blocks);
        assert!(luma_budget.used() <= DecodeLimits::default().luma_work_bound());
        let maximum_difference = progressive
            .pixels()
            .iter()
            .zip(case.oracle)
            .map(|(&a, &b)| a.abs_diff(b))
            .max()
            .unwrap_or(0);
        assert_eq!(progressive.pixels().len(), case.oracle.len());
        assert!(
            maximum_difference <= 1,
            "{}: FFmpeg difference {maximum_difference}",
            case.name
        );

        let rgb = decode_rgb(
            case.progressive,
            digest(case.progressive),
            case.color,
            RgbDecodeLimits::default(),
            &mut DecodeBudget::new(100_000_000),
        )?;
        let old_rgb = decode_rgb_v1(
            case.baseline,
            digest(case.baseline),
            case.color,
            RgbDecodeLimits::default(),
            &mut DecodeBudget::new(100_000_000),
        )?;
        assert_eq!(rgb.pixels(), old_rgb.pixels(), "{} RGB", case.name);
        assert_eq!(rgb.receipt().decoder, progressive_rgb_decoder_identity());
        assert_eq!(rgb.receipt().mcus, progressive.receipt().mcus);
        assert_eq!(
            rgb.receipt().entropy_blocks,
            progressive.receipt().entropy_blocks
        );
        assert_eq!(rgb.receipt().restarts, case.restarts);
    }
    Ok(())
}

#[test]
fn baseline_dispatch_keeps_pixels_receipts_work_and_exact_budget_acceptance() -> Test {
    for case in CASES {
        let mut old_budget = DecodeBudget::new(100_000_000);
        let old = decode_luma_v1(
            case.baseline,
            digest(case.baseline),
            case.color,
            DecodeLimits::default(),
            &mut old_budget,
        )?;
        let mut exact_budget = DecodeBudget::new(old_budget.used());
        let current = decode_luma(
            case.baseline,
            digest(case.baseline),
            case.color,
            DecodeLimits::default(),
            &mut exact_budget,
        )?;
        assert_eq!(current.pixels(), old.pixels());
        assert_eq!(current.receipt(), old.receipt());
        assert_eq!(exact_budget.used(), old_budget.used());
        assert_eq!(
            decoder_identity_for_frame(case.baseline),
            decoder_identity()
        );

        let mut old_budget = DecodeBudget::new(100_000_000);
        let old = decode_rgb_v1(
            case.baseline,
            digest(case.baseline),
            case.color,
            RgbDecodeLimits::default(),
            &mut old_budget,
        )?;
        let mut exact_budget = DecodeBudget::new(old_budget.used());
        let current = decode_rgb(
            case.baseline,
            digest(case.baseline),
            case.color,
            RgbDecodeLimits::default(),
            &mut exact_budget,
        )?;
        assert_eq!(current.pixels(), old.pixels());
        assert_eq!(current.receipt(), old.receipt());
        assert_eq!(exact_budget.used(), old_budget.used());
    }
    Ok(())
}

#[test]
fn original_rgb_identity_is_the_hash_of_its_frozen_source_preimages() -> Test {
    let preimages = [
        "9b250dbc6ecbcffb84acf0e305ee2a82b9bee77d9c5f2ae7d5a02b21eb32c1df",
        "d47cf83b929fcb851ed57f0787cfa3ba5443b69634862cd9947904376a9e7b53",
        "f65771835480873280ddb02b7cf4f84bf113a1c78e7d0abf6868fd0e37567d95",
        "ceed9f6dfd3575246727f7e4cf791c207a90e3c2ac03ff193b334fb433943276",
        "927582fc8f72d3ea6488ef8d623fa8f815bb8e882a2bc967797d5f0b1d6fb5bb",
    ];
    let mut bytes = digest(b"fss/jpeg-rgb/reference/1;nearest-chroma;q16-half-up;rgb-hwc").to_vec();
    for hash in preimages {
        for pair in hash.as_bytes().chunks(2) {
            bytes.push(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?);
        }
    }
    assert_eq!(rgb_decoder_identity(), digest(&bytes));
    assert_ne!(rgb_decoder_identity(), progressive_rgb_decoder_identity());
    assert_ne!(decoder_identity(), progressive_decoder_identity());
    Ok(())
}

#[test]
fn old_generation_replays_progressive_refusals_without_changing_their_work() {
    let case = &CASES[7];
    let mut old_budget = DecodeBudget::new(100_000_000);
    assert_eq!(
        decode_luma_v1(
            case.progressive,
            digest(case.progressive),
            case.color,
            DecodeLimits::default(),
            &mut old_budget
        )
        .err(),
        Some(DecodeError::Unsupported)
    );
    let mut replay_budget = DecodeBudget::new(old_budget.used());
    assert_eq!(
        decode_luma_for_identity(
            decoder_identity(),
            case.progressive,
            digest(case.progressive),
            case.color,
            DecodeLimits::default(),
            &mut replay_budget
        )
        .err(),
        Some(DecodeError::Unsupported)
    );
    assert_eq!(old_budget.used(), replay_budget.used());
    assert_eq!(
        decode_rgb_for_identity(
            rgb_decoder_identity(),
            case.progressive,
            digest(case.progressive),
            case.color,
            RgbDecodeLimits::default(),
            &mut DecodeBudget::new(100_000_000)
        )
        .err(),
        Some(DecodeError::Unsupported)
    );
    assert_eq!(
        decode_luma_for_identity(
            [0; 32],
            case.progressive,
            digest(case.progressive),
            case.color,
            DecodeLimits::default(),
            &mut DecodeBudget::new(100_000_000)
        )
        .err(),
        Some(DecodeError::Unsupported)
    );
}

#[test]
fn exact_budget_cancellation_output_source_and_dimension_limits_refuse_whole_images() -> Test {
    let case = &CASES[7];
    let mut full = DecodeBudget::new(100_000_000);
    let expected = decode_luma(
        case.progressive,
        digest(case.progressive),
        case.color,
        DecodeLimits::default(),
        &mut full,
    )?;
    let exact = decode_luma(
        case.progressive,
        digest(case.progressive),
        case.color,
        DecodeLimits::default(),
        &mut DecodeBudget::new(full.used()),
    )?;
    assert_eq!(expected.receipt(), exact.receipt());
    assert_eq!(
        decode_luma(
            case.progressive,
            digest(case.progressive),
            case.color,
            DecodeLimits::default(),
            &mut DecodeBudget::new(full.used() - 1)
        )
        .err(),
        Some(DecodeError::BudgetExhausted)
    );
    let cancelled = AtomicBool::new(true);
    let mut budget = DecodeBudget::cancellable(100_000_000, &cancelled);
    assert_eq!(
        decode_luma(
            case.progressive,
            digest(case.progressive),
            case.color,
            DecodeLimits::default(),
            &mut budget
        )
        .err(),
        Some(DecodeError::Cancelled)
    );
    assert_eq!(budget.used(), 0);
    assert_eq!(
        decode_luma(
            case.progressive,
            [1; 32],
            case.color,
            DecodeLimits::default(),
            &mut DecodeBudget::new(100_000_000)
        )
        .err(),
        Some(DecodeError::SourceMismatch)
    );
    for limits in [
        DecodeLimits {
            maximum_dimension: 36,
            ..DecodeLimits::default()
        },
        DecodeLimits {
            maximum_pixels: 37 * 29 - 1,
            ..DecodeLimits::default()
        },
        DecodeLimits {
            maximum_bytes: case.progressive.len() - 1,
            ..DecodeLimits::default()
        },
        DecodeLimits {
            maximum_markers: 4,
            ..DecodeLimits::default()
        },
    ] {
        assert_eq!(
            decode_luma(
                case.progressive,
                digest(case.progressive),
                case.color,
                limits,
                &mut DecodeBudget::new(100_000_000)
            )
            .err(),
            Some(DecodeError::Limit)
        );
    }
    assert_eq!(
        decode_rgb(
            case.progressive,
            digest(case.progressive),
            case.color,
            RgbDecodeLimits {
                maximum_output_bytes: 37 * 29 * 3 - 1,
                ..RgbDecodeLimits::default()
            },
            &mut DecodeBudget::new(100_000_000)
        )
        .err(),
        Some(DecodeError::Limit)
    );
    Ok(())
}

#[test]
fn every_truncation_and_bad_suffix_refuses_then_the_original_decodes() -> Test {
    let case = &CASES[7];
    for cut in 0..case.progressive.len() {
        assert!(
            decode(&case.progressive[..cut], case.color).is_err(),
            "cut {cut}"
        );
    }
    let mut trailing = case.progressive.to_vec();
    trailing.push(0);
    assert_eq!(
        decode(&trailing, case.color).err(),
        Some(DecodeError::Malformed)
    );
    assert_eq!(
        decode(case.progressive, case.color)?.dimensions(),
        case.dimensions
    );
    Ok(())
}

fn segment(bytes: &mut Vec<u8>, marker: u8, data: &[u8]) {
    bytes.extend_from_slice(&[255, marker]);
    bytes.extend_from_slice(&((data.len() + 2) as u16).to_be_bytes());
    bytes.extend_from_slice(data);
}
fn flat_prefix(dc_symbol: u8, ac_symbol: u8) -> Vec<u8> {
    let mut bytes = vec![255, 216];
    let mut q = vec![0];
    q.extend_from_slice(&[8; 64]);
    segment(&mut bytes, 0xdb, &q);
    segment(&mut bytes, 0xc2, &[8, 0, 8, 0, 8, 1, 1, 0x11, 0]);
    let mut h = Vec::new();
    for (class, symbol) in [(0, dc_symbol), (16, ac_symbol)] {
        h.extend_from_slice(&[class, 1]);
        h.extend_from_slice(&[0; 15]);
        h.push(symbol);
    }
    segment(&mut bytes, 0xc4, &h);
    bytes
}
fn one_block_scan(bytes: &mut Vec<u8>, start: u8, end: u8, high: u8, low: u8, entropy: u8) {
    segment(bytes, 0xda, &[1, 1, 0, start, end, high << 4 | low]);
    bytes.push(entropy);
    if entropy == 255 {
        bytes.push(0);
    }
}

#[test]
fn negative_dc_refinement_appends_twos_complement_bits_even_at_al13() -> Test {
    for precision in [1, 13] {
        let mut bytes = flat_prefix(1, 0);
        one_block_scan(&mut bytes, 0, 0, 0, precision, 0x3f); // category 1, difference -1.
        for low in (0..precision).rev() {
            one_block_scan(&mut bytes, 0, 0, low + 1, low, 0xff); // append one, including byte stuffing.
        }
        bytes.extend_from_slice(&[255, 217]);
        assert_eq!(decode(&bytes, Color::Grayscale)?.pixels(), &[127; 64]);
    }
    Ok(())
}

#[test]
fn eight_bit_ac_amplitude_bound_applies_to_first_scans_and_new_refinement_coefficients() -> Test {
    for low in [0, 1] {
        let mut bytes = flat_prefix(0, 10);
        one_block_scan(&mut bytes, 0, 0, 0, 0, 0x7f);
        segment(&mut bytes, 0xda, &[1, 1, 0, 1, 1, low]);
        // Huffman code 0, then ten one-bits: +1023 before the point transform.
        bytes.extend_from_slice(&[0x7f, 0xff, 0, 0xff, 0xd9]);
        if low == 0 {
            assert_eq!(decode(&bytes, Color::Grayscale)?.dimensions(), [8, 8]);
        } else {
            assert_eq!(
                decode(&bytes, Color::Grayscale).err(),
                Some(DecodeError::Limit)
            );
        }
    }
    let mut bytes = flat_prefix(0, 0);
    one_block_scan(&mut bytes, 0, 0, 0, 0, 0x7f);
    one_block_scan(&mut bytes, 1, 1, 0, 11, 0x7f); // All AC magnitudes are zero at Al=11.
    let mut table = vec![16, 1];
    table.extend_from_slice(&[0; 15]);
    table.push(1); // Refinement Huffman code 0 inserts a newly nonzero coefficient.
    segment(&mut bytes, 0xc4, &table);
    one_block_scan(&mut bytes, 1, 1, 11, 10, 0x7f); // positive 2^10 exceeds +1023.
    bytes.extend_from_slice(&[255, 217]);
    assert_eq!(
        decode(&bytes, Color::Grayscale).err(),
        Some(DecodeError::Limit)
    );
    Ok(())
}

#[test]
fn eob_runs_cannot_cross_the_scan_or_restart_boundary() {
    let mut bytes = flat_prefix(0, 0x10);
    one_block_scan(&mut bytes, 0, 0, 0, 0, 0x7f);
    one_block_scan(&mut bytes, 1, 63, 0, 0, 0x3f); // EOB1+0 says two blocks, but only one remains.
    bytes.extend_from_slice(&[255, 217]);
    assert_eq!(
        decode(&bytes, Color::Grayscale).err(),
        Some(DecodeError::Malformed)
    );
    let case = &CASES[7];
    let mut bytes = case.progressive.to_vec();
    let restart = bytes
        .windows(2)
        .position(|w| w == [255, 0xd0])
        .unwrap_or(bytes.len());
    assert!(restart < bytes.len());
    bytes[restart + 1] = 0xd1;
    assert_eq!(
        decode(&bytes, case.color).err(),
        Some(DecodeError::Malformed)
    );
}

#[test]
fn repeated_spectral_first_scan_invalid_refinement_and_ac_before_dc_are_rejected() {
    for scans in [
        vec![(0, 0, 0, 0), (0, 0, 0, 0)],
        vec![(0, 0, 0, 2), (0, 0, 1, 0)],
        vec![(1, 63, 0, 0)],
        vec![(0, 63, 0, 0)],
        vec![(0, 0, 0, 14)],
    ] {
        let mut bytes = flat_prefix(0, 0);
        for (start, end, high, low) in scans {
            one_block_scan(&mut bytes, start, end, high, low, 0x7f);
        }
        bytes.extend_from_slice(&[255, 217]);
        assert_eq!(
            decode(&bytes, Color::Grayscale).err(),
            Some(DecodeError::Malformed)
        );
    }
}

#[test]
fn scan_ceiling_bounds_even_a_valid_finely_partitioned_progression() {
    let mut bytes = flat_prefix(0, 0);
    one_block_scan(&mut bytes, 0, 0, 0, 0, 0x7f);
    for coefficient in 1..=20 {
        one_block_scan(&mut bytes, coefficient, coefficient, 0, 13, 0x7f);
        for low in (0..13).rev() {
            one_block_scan(&mut bytes, coefficient, coefficient, low + 1, low, 0x7f);
        }
    }
    bytes.extend_from_slice(&[255, 217]);
    assert_eq!(
        decode(&bytes, Color::Grayscale).err(),
        Some(DecodeError::Limit)
    );
}

#[test]
fn quantizers_cannot_change_under_accumulated_coefficients_and_metadata_is_not_a_frame_header()
-> Test {
    let mut bytes = flat_prefix(0, 0);
    one_block_scan(&mut bytes, 0, 0, 0, 0, 0x7f);
    let mut q = vec![0];
    q.extend_from_slice(&[9; 64]);
    segment(&mut bytes, 0xdb, &q);
    one_block_scan(&mut bytes, 1, 63, 0, 0, 0x7f);
    bytes.extend_from_slice(&[255, 217]);
    assert_eq!(
        decode(&bytes, Color::Grayscale).err(),
        Some(DecodeError::Malformed)
    );
    let case = &CASES[0];
    let mut bytes = vec![255, 216];
    segment(&mut bytes, 0xfe, &[255, 0xc2, 0, 2]);
    bytes.extend_from_slice(&case.baseline[2..]);
    assert_eq!(decoder_identity_for_frame(&bytes), decoder_identity());
    assert_eq!(
        decode(&bytes, case.color)?.pixels(),
        decode(case.baseline, case.color)?.pixels()
    );
    Ok(())
}
