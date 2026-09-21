#![forbid(unsafe_code)]
//! Complete color reconstruction and failure contracts over real JPEG syntax.
use fss_codec_mjpeg::{ComponentInterpretation as Color, DecodeBudget, DecodeError, DecodeLimits, decode_luma};
use fss_codec_mjpeg::color::{DecodedRgb, RgbDecodeLimits, decode_rgb, rgb_decoder_identity};
use fss_core::ContentDigest;
mod rgb_support;
type Test = Result<(), Box<dyn std::error::Error>>;
fn decode(bytes: &[u8], color: Color) -> Result<DecodedRgb, DecodeError> {
    decode_rgb(bytes, ContentDigest::sha256(bytes).bytes(), color,
        RgbDecodeLimits::default(), &mut DecodeBudget::new(100_000_000))
}
#[test]
fn grayscale_is_exact_luma_replication_with_distinct_receipt() -> Test {
    let bytes = rgb_support::jpeg(19, 17, [1, 1], true, false, false, &[[40, 0, 0], [230, 0, 0]]);
    let rgb = decode(&bytes, Color::Grayscale)?;
    let luma = decode_luma(&bytes, ContentDigest::sha256(&bytes).bytes(), Color::Grayscale,
        DecodeLimits::default(), &mut DecodeBudget::new(100_000_000))?;
    for (channels, &y) in rgb.pixels().chunks_exact(3).zip(luma.pixels()) { assert_eq!(channels, [y; 3]); }
    assert_eq!(rgb.dimensions(), luma.dimensions());
    assert_eq!(rgb.receipt().entropy_blocks, luma.receipt().entropy_blocks);
    assert_ne!(rgb.receipt().decoder, luma.receipt().decoder); Ok(())
}
#[test]
fn every_sampling_mode_and_scan_order_reconstructs_color_at_odd_edges() -> Test {
    for sampling in [[1, 1], [2, 1], [2, 2]] {
        for reversed in [false, true] {
            let bytes = rgb_support::jpeg(19, 17, sampling, false, false, reversed, &[[100, 150, 200]]);
            let image = decode(&bytes, Color::YCbCr)?;
            assert_eq!(image.dimensions(), [19, 17]); assert_eq!(image.pixels().len(), 19 * 17 * 3);
            for pixel in image.pixels().chunks_exact(3) { assert_eq!(pixel, [201, 41, 139]); }
            assert_eq!(image.receipt().entropy_blocks, image.receipt().mcus * (sampling[0] * sampling[1] + 2));
        }
    }
    Ok(())
}
#[test]
fn chroma_is_real_not_luma_replicated_into_three_channels() -> Test {
    let a = rgb_support::jpeg(8, 8, [1, 1], false, false, false, &[[100, 128, 128]]);
    let b = rgb_support::jpeg(8, 8, [1, 1], false, false, false, &[[100, 150, 200]]);
    let y = |bytes: &[u8]| decode_luma(bytes, ContentDigest::sha256(bytes).bytes(), Color::YCbCr,
        DecodeLimits::default(), &mut DecodeBudget::new(100_000_000));
    assert_eq!(y(&a)?.pixels(), y(&b)?.pixels());
    assert_ne!(decode(&a, Color::YCbCr)?.pixels(), decode(&b, Color::YCbCr)?.pixels()); Ok(())
}
#[test]
fn mcu_chroma_does_not_bleed_or_shift_into_adjacent_tiles() -> Test {
    let bytes = rgb_support::jpeg(19, 17, [2, 2], false, false, true,
        &[[100, 150, 200], [40, 128, 128], [230, 128, 128], [0, 128, 128]]);
    let image = decode(&bytes, Color::YCbCr)?;
    for y in 0..17 { for x in 0..19 {
        let expected = [[201, 41, 139], [40; 3], [230; 3], [0; 3]][(y / 16) * 2 + x / 16];
        assert_eq!(&image.pixels()[(y * 19 + x) * 3..(y * 19 + x + 1) * 3], expected);
    }}
    Ok(())
}
#[test]
fn restart_markers_reset_all_component_predictors_and_validate_sequence() -> Test {
    let samples = [[100, 150, 200], [230, 110, 90]];
    let a = rgb_support::jpeg(73, 17, [2, 2], false, false, false, &samples);
    let mut b = rgb_support::jpeg(73, 17, [2, 2], false, true, false, &samples);
    let plain = decode(&a, Color::YCbCr)?; let restarted = decode(&b, Color::YCbCr)?;
    assert_eq!(plain.pixels(), restarted.pixels());
    assert_eq!(restarted.receipt().restarts, restarted.receipt().mcus - 1);
    let at = b.windows(2).position(|w| w == [255, 208]).ok_or("missing restart")?;
    b[at + 1] = 209; assert!(decode(&b, Color::YCbCr).is_err()); Ok(())
}
#[test]
fn complete_source_digest_and_rgb_digest_are_checked_and_reproducible() -> Test {
    let bytes = rgb_support::jpeg(1, 1, [2, 2], false, false, false, &[[100, 150, 200]]);
    let a = decode(&bytes, Color::YCbCr)?; let b = decode(&bytes, Color::YCbCr)?;
    assert_eq!(a.receipt(), b.receipt()); assert_eq!(a.receipt().decoder, rgb_decoder_identity());
    assert_eq!(a.receipt().rgb_sha256, ContentDigest::sha256(a.pixels()).bytes());
    assert_eq!(a.receipt().encoded_sha256, ContentDigest::sha256(&bytes).bytes());
    assert!(matches!(decode_rgb(&bytes, [0; 32], Color::YCbCr, RgbDecodeLimits::default(),
        &mut DecodeBudget::new(100_000_000)), Err(DecodeError::SourceMismatch))); Ok(())
}
#[test]
fn invalid_suffix_truncated_chroma_and_interpretation_refuse_whole_frame() -> Test {
    let bytes = rgb_support::jpeg(8, 8, [1, 1], false, false, false, &[[100, 150, 200]]);
    for end in (bytes.len() - 7)..bytes.len() { assert!(decode(&bytes[..end], Color::YCbCr).is_err()); }
    let mut extra = bytes.clone(); extra.push(0);
    assert!(matches!(decode(&extra, Color::YCbCr), Err(DecodeError::Malformed)));
    assert!(matches!(decode(&bytes, Color::Grayscale), Err(DecodeError::Unsupported)));
    let mut progressive = bytes.clone();
    let at = progressive.windows(2).position(|w| w == [255, 192]).ok_or("missing SOF")?;
    progressive[at + 1] = 194; assert!(matches!(decode(&progressive, Color::YCbCr), Err(DecodeError::Unsupported)));
    Ok(())
}
#[test]
fn independent_output_and_pixel_limits_refuse_without_silent_resize() -> Test {
    let bytes = rgb_support::jpeg(19, 17, [2, 2], false, false, false, &[[100, 150, 200]]);
    for maximum in [0, 1, 19 * 17 * 3 - 1] {
        assert!(matches!(decode_rgb(&bytes, ContentDigest::sha256(&bytes).bytes(), Color::YCbCr,
            RgbDecodeLimits { maximum_output_bytes: maximum, ..RgbDecodeLimits::default() },
            &mut DecodeBudget::new(100_000_000)), Err(DecodeError::Limit)));
    }
    let limits = RgbDecodeLimits { frame: DecodeLimits { maximum_pixels: 19 * 17 - 1,
        ..DecodeLimits::default() }, ..RgbDecodeLimits::default() };
    assert!(matches!(decode_rgb(&bytes, ContentDigest::sha256(&bytes).bytes(), Color::YCbCr,
        limits, &mut DecodeBudget::new(100_000_000)), Err(DecodeError::Limit))); Ok(())
}
#[test]
fn exact_budget_completes_while_earlier_cuts_and_cancellation_return_no_image() -> Test {
    let bytes = rgb_support::jpeg(8, 8, [2, 2], false, false, false, &[[100, 150, 200]]);
    let hash = ContentDigest::sha256(&bytes).bytes(); let limits = RgbDecodeLimits::default();
    let mut full = DecodeBudget::new(100_000_000);
    let expected = decode_rgb(&bytes, hash, Color::YCbCr, limits, &mut full)?;
    for limit in [0, 1, bytes.len() as u64, full.used() / 2, full.used() - 1] {
        assert!(matches!(decode_rgb(&bytes, hash, Color::YCbCr, limits, &mut DecodeBudget::new(limit)),
            Err(DecodeError::BudgetExhausted)));
    }
    assert_eq!(decode_rgb(&bytes, hash, Color::YCbCr, limits, &mut DecodeBudget::new(full.used()))?.receipt(), expected.receipt());
    let flag = std::sync::atomic::AtomicBool::new(true);
    assert!(matches!(decode_rgb(&bytes, hash, Color::YCbCr, limits,
        &mut DecodeBudget::cancellable(100_000_000, &flag)), Err(DecodeError::Cancelled))); Ok(())
}
