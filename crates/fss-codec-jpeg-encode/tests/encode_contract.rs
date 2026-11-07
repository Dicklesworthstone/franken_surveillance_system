#![forbid(unsafe_code)]
//! Complete production encoding, independent flat-block syntax vectors, and native decoding.

use fss_codec_jpeg_encode::{
    ENCODE_WORK_MODEL, EncodeBudget, EncodeConfig, EncodeError, EncodeLimits, EncodedJpeg,
    MAX_DIMENSION, MAX_OUTPUT_BYTES, MAX_PIXELS, PixelFormat, encode_jpeg, encoder_identity,
};
use fss_codec_mjpeg::color::{RgbDecodeLimits, decode_rgb};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits, decode_luma};
use fss_core::ContentDigest;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

type Test = Result<(), Box<dyn std::error::Error>>;
type JpegSyntax<'a> = (Vec<(u8, &'a [u8])>, &'a [u8]);

fn encode(width: u32, height: u32, pixels: &[u8], format: PixelFormat, quality: u8) -> Result<EncodedJpeg, EncodeError> {
    encode_jpeg(
        width, height, pixels, ContentDigest::sha256(pixels).bytes(),
        EncodeConfig { quality, format }, &EncodeLimits::default(), &mut EncodeBudget::new(u64::MAX),
    )
}

fn decode(jpeg: &EncodedJpeg) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let receipt = jpeg.receipt();
    let interpretation = if receipt.format == PixelFormat::Grayscale {
        ComponentInterpretation::Grayscale
    } else {
        ComponentInterpretation::YCbCr
    };
    let mut budget = DecodeBudget::new(u64::MAX);
    if receipt.format == PixelFormat::Grayscale {
        let decoded = decode_luma(jpeg.bytes(), receipt.encoded_sha256, interpretation, DecodeLimits::default(), &mut budget)?;
        assert_eq!(decoded.dimensions(), receipt.dimensions);
        assert_eq!(decoded.receipt().metadata_segments, 0);
        assert_eq!(decoded.receipt().entropy_blocks, receipt.entropy_blocks);
        Ok(decoded.pixels().to_vec())
    } else {
        let decoded = decode_rgb(jpeg.bytes(), receipt.encoded_sha256, interpretation, RgbDecodeLimits::default(), &mut budget)?;
        assert_eq!(decoded.dimensions(), receipt.dimensions);
        assert_eq!(decoded.receipt().metadata_segments, 0);
        assert_eq!(decoded.receipt().entropy_blocks, receipt.entropy_blocks);
        Ok(decoded.pixels().to_vec())
    }
}

/// Independent marker walker: the encoder does not export its framing or entropy helpers.
fn syntax(bytes: &[u8]) -> Result<JpegSyntax<'_>, Box<dyn std::error::Error>> {
    if !bytes.starts_with(&[0xff, 0xd8]) || !bytes.ends_with(&[0xff, 0xd9]) {
        return Err("complete JPEG delimiters".into());
    }
    let mut at = 2;
    let mut headers = Vec::new();
    while headers.len() < 8 {
        let header = bytes.get(at..at + 4).ok_or("header")?;
        if header[0] != 0xff { return Err("marker prefix".into()); }
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if length < 2 { return Err("marker length".into()); }
        let end = at.checked_add(2 + length).ok_or("marker overflow")?;
        let payload = bytes.get(at + 4..end).ok_or("marker body")?;
        headers.push((header[1], payload));
        at = end;
        if header[1] == 0xda {
            let entropy = bytes.get(at..bytes.len() - 2).ok_or("entropy")?;
            return Ok((headers, entropy));
        }
    }
    Err("unexpected JPEG header count".into())
}

fn pattern(width: u32, height: u32, format: PixelFormat) -> Vec<u8> {
    let mut pixels = Vec::new();
    for y in 0..height {
        for x in 0..width {
            let r = ((x * 17 + y * 29 + x * y * 3) % 256) as u8;
            if format == PixelFormat::Grayscale {
                pixels.push(r);
            } else {
                pixels.extend_from_slice(&[r, ((x * 53 + y * 7 + 39) % 256) as u8, ((x * 11 + y * 61 + 173) % 256) as u8]);
            }
        }
    }
    pixels
}

#[test]
fn hand_derived_flat_block_entropy_matches_standard_codewords() -> Test {
    // These entropy bytes follow the Annex K codewords directly, independent of
    // either the production FDCT or the production JPEG decoder.
    for (value, quality, expected) in [
        (128, 50, [0x2b].as_slice()), // DC=0: 00; EOB=1010; two one padding bits.
        (129, 50, [0x5a].as_slice()), // DC=+1 after exact half-tie quantization.
        (127, 50, [0x4a].as_slice()), // DC=-1: complemented amplitude bit zero.
        (0, 50, [0xf3, 0xfa].as_slice()), // DC=-64, then EOB.
        (255, 50, [0xf4, 0x0a].as_slice()), // DC=+64, then EOB.
        (0, 100, [0xff, 0x00, 0x3f, 0xfa].as_slice()), // DC=-1024; FF is stuffed.
        (255, 100, [0xfe, 0xfe, 0x2b].as_slice()), // DC=+1016 and final padding.
    ] {
        let jpeg = encode(8, 8, &[value; 64], PixelFormat::Grayscale, quality)?;
        let (_, entropy) = syntax(jpeg.bytes())?;
        assert_eq!(entropy, expected, "value={value} quality={quality}");
    }
    let rgb = encode(8, 8, &[128; 192], PixelFormat::Rgb, 50)?;
    // Luma 001010, each chroma 0000, then two one padding bits.
    assert_eq!(syntax(rgb.bytes())?.1, [0x28, 0x03]);
    Ok(())
}

#[test]
fn headers_declare_only_bounded_baseline_gray_or_ycbcr444_without_metadata() -> Test {
    for format in [PixelFormat::Grayscale, PixelFormat::Rgb] {
        let pixels = pattern(17, 13, format);
        let jpeg = encode(17, 13, &pixels, format, 100)?;
        let (headers, _) = syntax(jpeg.bytes())?;
        assert_eq!(headers.iter().map(|entry| entry.0).collect::<Vec<_>>(), [0xdb, 0xc0, 0xc4, 0xda]);
        let count = if format == PixelFormat::Grayscale { 1 } else { 3 };
        let quantizers = headers[0].1;
        assert_eq!(quantizers.len(), if count == 1 { 65 } else { 130 });
        for table in quantizers.as_chunks::<65>().0 {
            assert!(table[1..].iter().all(|value| *value == 1));
        }
        let sof = headers[1].1;
        assert_eq!(&sof[..6], &[8, 0, 13, 0, 17, count]);
        for (component, entry) in sof[6..].as_chunks::<3>().0.iter().enumerate() {
            assert_eq!(entry, &[component as u8 + 1, 0x11, u8::from(component != 0)]);
        }
        let decoded = decode(&jpeg)?;
        assert_eq!(decoded.len(), pixels.len());
        assert_eq!(jpeg.receipt().mcus, 6);
        assert_eq!(jpeg.receipt().entropy_blocks, 6 * usize::from(count));
    }
    Ok(())
}

#[test]
fn constant_fields_reconstruct_exactly_at_unit_quantization() -> Test {
    for value in [0_u8, 1, 64, 127, 128, 129, 192, 254, 255] {
        for (width, height) in [(1, 1), (8, 8), (17, 9)] {
            let pixels = vec![value; width as usize * height as usize];
            let jpeg = encode(width, height, &pixels, PixelFormat::Grayscale, 100)?;
            assert_eq!(decode(&jpeg)?, pixels, "gray {value} {width}x{height}");
        }
    }
    for pixel in [[0, 0, 0], [255, 255, 255], [128, 128, 128]] {
        let pixels = pixel.repeat(17 * 9);
        let jpeg = encode(17, 9, &pixels, PixelFormat::Rgb, 100)?;
        assert_eq!(decode(&jpeg)?, pixels);
    }
    Ok(())
}

#[test]
fn odd_edge_color_and_gray_reconstruct_with_bounded_unit_quantization_error() -> Test {
    for format in [PixelFormat::Grayscale, PixelFormat::Rgb] {
        for (width, height) in [(1, 1), (7, 9), (17, 13), (31, 29)] {
            let pixels = pattern(width, height, format);
            let first = encode(width, height, &pixels, format, 100)?;
            let second = encode(width, height, &pixels, format, 100)?;
            assert_eq!(first.bytes(), second.bytes());
            assert_eq!(first.receipt(), second.receipt());
            let result = decode(&first)?;
            let maximum = result.iter().zip(&pixels).map(|(a, b)| a.abs_diff(*b)).max().ok_or("pixels")?;
            assert!(maximum <= if format == PixelFormat::Rgb { 4 } else { 2 }, "{format:?} {width}x{height}: {maximum}");
            assert_eq!(first.receipt().pixel_sha256, ContentDigest::sha256(&pixels).bytes());
            assert_eq!(first.receipt().encoded_sha256, ContentDigest::sha256(first.bytes()).bytes());
            assert_eq!(first.receipt().encoder, encoder_identity());
        }
    }
    Ok(())
}

#[test]
fn quality_scaling_stays_baseline_and_preserves_real_color_components() -> Test {
    let pixels = pattern(32, 24, PixelFormat::Rgb);
    for quality in [1, 2, 25, 50, 75, 99, 100] {
        let jpeg = encode(32, 24, &pixels, PixelFormat::Rgb, quality)?;
        let (headers, _) = syntax(jpeg.bytes())?;
        for table in headers[0].1.as_chunks::<65>().0 {
            assert!(table[1..].iter().all(|value| *value != 0));
            if quality == 1 { assert!(table[1..].iter().all(|value| *value == 255)); }
        }
        let result = decode(&jpeg)?;
        assert!(result.as_chunks::<3>().0.iter().any(|pixel| pixel[0] != pixel[1] && pixel[1] != pixel[2]));
    }
    let gray = encode(8, 8, &[128; 64], PixelFormat::Grayscale, 50)?;
    assert_eq!(&syntax(gray.bytes())?.0[0].1[..9], &[0, 16, 11, 12, 14, 12, 10, 16, 14]);
    Ok(())
}

#[test]
fn exact_work_and_complete_output_caps_pass_and_one_less_refuses() -> Test {
    let pixels = pattern(17, 13, PixelFormat::Rgb);
    let config = EncodeConfig { quality: 91, format: PixelFormat::Rgb };
    let source = ContentDigest::sha256(&pixels).bytes();
    let complete = encode(17, 13, &pixels, config.format, config.quality)?;
    let used = complete.receipt().work_units;
    let limits = EncodeLimits { maximum_output_bytes: complete.bytes().len(), ..EncodeLimits::default() };
    let mut exact = EncodeBudget::new(used);
    let result = encode_jpeg(17, 13, &pixels, source, config, &limits, &mut exact)?;
    assert_eq!(result.bytes(), complete.bytes());
    assert_eq!(result.receipt(), complete.receipt());
    assert_eq!(exact.remaining(), 0);
    assert_eq!(exact.used(), used);
    assert_eq!(encode_jpeg(17, 13, &pixels, source, config, &limits, &mut EncodeBudget::new(used - 1)).map(|_| ()), Err(EncodeError::BudgetExhausted));
    let short = EncodeLimits { maximum_output_bytes: limits.maximum_output_bytes - 1, ..limits };
    assert_eq!(encode_jpeg(17, 13, &pixels, source, config, &short, &mut EncodeBudget::new(used)).map(|_| ()), Err(EncodeError::Limit));
    Ok(())
}

#[test]
fn shared_allowance_never_renews_and_receipt_reports_only_current_frame() -> Test {
    let pixels = pattern(17, 13, PixelFormat::Grayscale);
    let config = EncodeConfig { quality: 80, format: PixelFormat::Grayscale };
    let source = ContentDigest::sha256(&pixels).bytes();
    let single = encode(17, 13, &pixels, config.format, config.quality)?;
    let used = single.receipt().work_units;
    let mut budget = EncodeBudget::new(used * 2);
    for _ in 0..2 {
        let encoded = encode_jpeg(17, 13, &pixels, source, config, &EncodeLimits::default(), &mut budget)?;
        assert_eq!(encoded.receipt(), single.receipt());
    }
    assert_eq!(budget.used(), 2 * used);
    assert_eq!(budget.remaining(), 0);
    assert_eq!(encode_jpeg(17, 13, &pixels, source, config, &EncodeLimits::default(), &mut budget).map(|_| ()), Err(EncodeError::BudgetExhausted));
    assert_eq!(budget.used(), 2 * used);
    Ok(())
}

#[test]
fn empty_malformed_or_oversized_inputs_refuse_before_image_work() {
    let config = EncodeConfig { quality: 90, format: PixelFormat::Grayscale };
    let mut budget = EncodeBudget::new(1_000_000);
    for (width, height, pixels, expected) in [
        (0, 1, [].as_slice(), EncodeError::InvalidPixels),
        (1, 0, [].as_slice(), EncodeError::InvalidPixels),
        (1, 1, [].as_slice(), EncodeError::InvalidPixels),
        (1, 1, [1, 2].as_slice(), EncodeError::InvalidPixels),
        (MAX_DIMENSION + 1, 1, [1].as_slice(), EncodeError::Limit),
        (MAX_DIMENSION, MAX_DIMENSION, [1].as_slice(), EncodeError::Limit),
        (u32::MAX, u32::MAX, [1].as_slice(), EncodeError::Limit),
    ] {
        assert_eq!(encode_jpeg(width, height, pixels, [1; 32], config, &EncodeLimits::default(), &mut budget).map(|_| ()), Err(expected));
    }
    for quality in [0, 101, 255] {
        assert_eq!(encode_jpeg(1, 1, &[1], [1; 32], EncodeConfig { quality, ..config }, &EncodeLimits::default(), &mut budget).map(|_| ()), Err(EncodeError::InvalidConfiguration));
    }
    assert_eq!(budget.used(), 0);
}

#[test]
fn independent_limits_are_never_silently_clamped() {
    let defaults = EncodeLimits::default();
    let config = EncodeConfig { quality: 90, format: PixelFormat::Grayscale };
    for limits in [
        EncodeLimits { maximum_dimension: 0, ..defaults },
        EncodeLimits { maximum_dimension: MAX_DIMENSION + 1, ..defaults },
        EncodeLimits { maximum_pixels: 0, ..defaults },
        EncodeLimits { maximum_pixels: MAX_PIXELS + 1, ..defaults },
        EncodeLimits { maximum_output_bytes: 0, ..defaults },
        EncodeLimits { maximum_output_bytes: MAX_OUTPUT_BYTES + 1, ..defaults },
    ] {
        let mut budget = EncodeBudget::new(u64::MAX);
        assert_eq!(encode_jpeg(1, 1, &[128], [1; 32], config, &limits, &mut budget).map(|_| ()), Err(EncodeError::InvalidConfiguration));
        assert_eq!(budget.used(), 0);
    }
    let limits = EncodeLimits { maximum_dimension: 1, maximum_pixels: 1, maximum_output_bytes: 1 };
    assert_eq!(encode_jpeg(1, 1, &[128], ContentDigest::sha256(&[128]).bytes(), config, &limits, &mut EncodeBudget::new(u64::MAX)).map(|_| ()), Err(EncodeError::Limit));
}

#[test]
fn source_binding_refuses_wrong_and_absent_pixel_digests() {
    let pixels = [128; 64];
    let config = EncodeConfig { quality: 90, format: PixelFormat::Grayscale };
    for digest in [[0; 32], ContentDigest::sha256(&[127; 64]).bytes()] {
        assert_eq!(encode_jpeg(8, 8, &pixels, digest, config, &EncodeLimits::default(), &mut EncodeBudget::new(u64::MAX)).map(|_| ()), Err(EncodeError::SourceMismatch));
    }
}

#[test]
fn cancellation_is_atomic_at_every_actual_checkpoint_including_finalization() -> Test {
    let pixels = pattern(8, 8, PixelFormat::Rgb);
    let source = ContentDigest::sha256(&pixels).bytes();
    let config = EncodeConfig { quality: 95, format: PixelFormat::Rgb };
    let visits = AtomicUsize::new(0);
    let observe = || { visits.fetch_add(1, Ordering::SeqCst); false };
    encode_jpeg(8, 8, &pixels, source, config, &EncodeLimits::default(), &mut EncodeBudget::with_cancellation_probe(u64::MAX, &observe))?;
    let total = visits.load(Ordering::SeqCst);
    assert!(total > 10);
    for stop in 1..=total {
        let count = AtomicUsize::new(0);
        let cancelled = || count.fetch_add(1, Ordering::SeqCst) + 1 >= stop;
        let mut budget = EncodeBudget::with_cancellation_probe(u64::MAX, &cancelled);
        assert_eq!(encode_jpeg(8, 8, &pixels, source, config, &EncodeLimits::default(), &mut budget).map(|_| ()), Err(EncodeError::Cancelled), "checkpoint {stop}/{total}");
    }
    let flag = AtomicBool::new(true);
    let mut cancelled = EncodeBudget::with_cancellation(100_000, &flag);
    assert_eq!(encode_jpeg(8, 8, &pixels, source, config, &EncodeLimits::default(), &mut cancelled).map(|_| ()), Err(EncodeError::Cancelled));
    assert_eq!(cancelled.used(), 0);
    Ok(())
}

#[test]
fn input_hashing_has_bounded_cancellation_checkpoints() {
    let pixels = vec![19; 257 * 129];
    let digest = ContentDigest::sha256(&pixels).bytes();
    let calls = AtomicUsize::new(0);
    let cancelled = || calls.fetch_add(1, Ordering::SeqCst) >= 4;
    let mut budget = EncodeBudget::with_cancellation_probe(u64::MAX, &cancelled);
    assert_eq!(encode_jpeg(257, 129, &pixels, digest, EncodeConfig { quality: 90, format: PixelFormat::Grayscale }, &EncodeLimits::default(), &mut budget).map(|_| ()), Err(EncodeError::Cancelled));
    assert!(budget.used() < pixels.len() as u64);
}

#[test]
fn work_bound_covers_padded_components_hashing_and_output_without_allocation_guessing() -> Test {
    let limits = EncodeLimits { maximum_dimension: 32, maximum_pixels: 1000, maximum_output_bytes: 8192 };
    for format in [PixelFormat::Grayscale, PixelFormat::Rgb] {
        let pixels = pattern(31, 29, format);
        let bound = limits.work_bound(format);
        let mut budget = EncodeBudget::new(bound);
        let encoded = encode_jpeg(31, 29, &pixels, ContentDigest::sha256(&pixels).bytes(), EncodeConfig { quality: 100, format }, &limits, &mut budget)?;
        assert!(encoded.receipt().work_units <= bound);
        assert_eq!(encoded.receipt().work_units, budget.used());
    }
    assert!(ENCODE_WORK_MODEL.starts_with("fss/jpeg-encode/work/1;"));
    Ok(())
}

#[test]
fn receipt_binds_source_shape_quality_generation_cost_and_complete_derivative() -> Test {
    let pixels = pattern(17, 13, PixelFormat::Grayscale);
    let encoded = encode(17, 13, &pixels, PixelFormat::Grayscale, 90)?;
    let original = encoded.receipt();
    let digest = original.digest();
    for mut changed in [original; 10].into_iter().enumerate() {
        match changed.0 {
            0 => changed.1.pixel_sha256[0] ^= 1,
            1 => changed.1.encoded_sha256[0] ^= 1,
            2 => changed.1.encoder[0] ^= 1,
            3 => changed.1.dimensions[0] += 1,
            4 => changed.1.format = PixelFormat::Rgb,
            5 => changed.1.quality -= 1,
            6 => changed.1.output_bytes += 1,
            7 => changed.1.mcus += 1,
            8 => changed.1.entropy_blocks += 1,
            _ => changed.1.work_units += 1,
        }
        assert_ne!(changed.1.digest(), digest);
    }
    assert_ne!(digest.bytes(), original.pixel_sha256);
    assert_ne!(digest.bytes(), original.encoded_sha256);
    assert_ne!(digest.bytes(), original.encoder);
    Ok(())
}

#[test]
fn screened_black_input_is_not_claimed_as_exactly_black_lossy_reconstruction() -> Test {
    let mut pixels = pattern(16, 8, PixelFormat::Grayscale);
    for y in 0..8 {
        pixels[y * 16 + 5..y * 16 + 16].fill(0);
    }
    let jpeg = encode(16, 8, &pixels, PixelFormat::Grayscale, 50)?;
    let result = decode(&jpeg)?;
    assert_ne!(jpeg.receipt().pixel_sha256, ContentDigest::sha256(&result).bytes());
    assert!((0..8).any(|y| result[y * 16 + 5..y * 16 + 8].iter().any(|value| *value != 0)));
    assert!((0..8).all(|y| result[y * 16 + 8..y * 16 + 16].iter().all(|value| *value == 0)));
    Ok(())
}
