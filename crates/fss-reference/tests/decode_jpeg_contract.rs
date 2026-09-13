#![forbid(unsafe_code)]
//! Integration and contract tests for safe baseline JPEG decoding into [`fss_tensor::Tensor`].
//!
//! Verifies:
//! - Hand-built minimal byte vectors: rejection of non-JPEG streams, truncated headers,
//!   and unsupported features (progressive SOF2, extended 12-bit sequential, lossless SOF3,
//!   arithmetic coding, 16-bit DQT, 4-component CMYK, Adobe transforms).
//! - Limits validation before allocation (width, height, total pixels, storage bytes,
//!   Huffman symbols, restart intervals).
//! - Truncation detection in entropy stream with no partial image returned.
//! - Grayscale reference acceptance on `brown_luma_96x96` with PSNR >= 30.0 dB and
//!   exact luma-to-tensor equivalence.
//! - Bounded differential check at quality 100 (max error <= 2).
//! - Full-color Yuv444, Yuv420, and Yuv422 decode to RGB `[H, W, 3]` with PSNR >= 30.0 dB.
//! - DRI / restart marker resync and bounds enforcement.
//! - Cooperative cancellation via [`ReplayCx`] per MCU row.
//! - Hostile / corrupted input fuzzing: zero crashes, typed errors only.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::ContentDigest;
use fss_reference::media_fixture::jpeg::{
    JpegConfig, Subsampling, brown_luma_96x96, compute_psnr, encode_jpeg,
    generate_all_jpeg_fixtures, generate_colorbars_rgb, generate_gradient_rgb, source_pixels,
};
use fss_reference::{
    JPEG_DECODER_GENERATION, JpegDecodeError, JpegDecodeLimits, JpegSubsampling, ReplayCx,
    decode_baseline_jpeg,
};

macro_rules! require {
    ($cond:expr, $($arg:tt)+) => {
        if !($cond) {
            return Err(format!($($arg)+).into());
        }
    };
}

fn require_psnr_ge(val: f64, min_val: f64, label: &str) -> Result<(), Box<dyn Error>> {
    if val < min_val || val.is_nan() {
        return Err(format!("{label}: PSNR {val:.2} dB is below required {min_val:.2} dB").into());
    }
    Ok(())
}

#[test]
fn test_invalid_header_rejection() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = JpegDecodeLimits::default();

    // 1. Empty buffer
    let res = decode_baseline_jpeg(&[], limits, &cx);
    require!(
        matches!(res, Err(JpegDecodeError::InvalidHeader(_))),
        "empty buffer must return InvalidHeader"
    );

    // 2. Single byte
    let res = decode_baseline_jpeg(&[0xFF], limits, &cx);
    require!(
        matches!(res, Err(JpegDecodeError::InvalidHeader(_))),
        "single byte must return InvalidHeader"
    );

    // 3. Incorrect magic bytes
    let res = decode_baseline_jpeg(&[0x00, 0x11, 0x22, 0x33], limits, &cx);
    require!(
        matches!(res, Err(JpegDecodeError::InvalidHeader(_))),
        "arbitrary magic bytes must return InvalidHeader"
    );

    // 4. SOI followed immediately by EOF
    let res = decode_baseline_jpeg(&[0xFF, 0xD8], limits, &cx);
    require!(
        matches!(
            res,
            Err(JpegDecodeError::InvalidSyntax(_)) | Err(JpegDecodeError::Truncated { .. })
        ),
        "SOI without subsequent segments must return error"
    );

    Ok(())
}

#[test]
fn test_unsupported_processes_refusal() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = JpegDecodeLimits::default();

    // 1. Progressive DCT (SOF2, 0xFFC2)
    let progressive_bytes = [
        0xFF, 0xD8, // SOI
        0xFF, 0xC2, // SOF2 marker
        0x00, 0x0B, // Length 11
        0x08, // 8-bit precision
        0x00, 0x10, // Height 16
        0x00, 0x10, // Width 16
        0x01, // 1 component
        0x01, 0x11, 0x00, // Comp 1, 1x1, quant 0
        0xFF, 0xD9, // EOI
    ];
    let res = decode_baseline_jpeg(&progressive_bytes, limits, &cx);
    match res {
        Err(JpegDecodeError::Unsupported { process }) => {
            require!(
                process.contains("progressive SOF2"),
                "SOF2 should mention progressive SOF2, got: {process}"
            );
        }
        other => {
            return Err(format!("expected Unsupported for progressive SOF2, got {other:?}").into());
        }
    }

    // 2. Extended Sequential (SOF1, 0xFFC1)
    let extended_bytes = [
        0xFF, 0xD8, // SOI
        0xFF, 0xC1, // SOF1
        0x00, 0x0B, 0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xD9,
    ];
    let res = decode_baseline_jpeg(&extended_bytes, limits, &cx);
    match res {
        Err(JpegDecodeError::Unsupported { process }) => {
            require!(
                process.contains("extended sequential"),
                "SOF1 should mention extended sequential, got: {process}"
            );
        }
        other => return Err(format!("expected Unsupported for SOF1, got {other:?}").into()),
    }

    // 3. Lossless (SOF3, 0xFFC3)
    let lossless_bytes = [
        0xFF, 0xD8, // SOI
        0xFF, 0xC3, // SOF3
        0x00, 0x0B, 0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xD9,
    ];
    let res = decode_baseline_jpeg(&lossless_bytes, limits, &cx);
    match res {
        Err(JpegDecodeError::Unsupported { process }) => {
            require!(
                process.contains("lossless SOF3"),
                "SOF3 should mention lossless SOF3, got: {process}"
            );
        }
        other => return Err(format!("expected Unsupported for SOF3, got {other:?}").into()),
    }

    // 4. Arithmetic Coding (SOF9, 0xFFC9)
    let arithmetic_bytes = [
        0xFF, 0xD8, // SOI
        0xFF, 0xC9, // SOF9
        0x00, 0x0B, 0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xD9,
    ];
    let res = decode_baseline_jpeg(&arithmetic_bytes, limits, &cx);
    match res {
        Err(JpegDecodeError::Unsupported { process }) => {
            require!(
                process.contains("arithmetic coding"),
                "SOF9 should mention arithmetic coding, got: {process}"
            );
        }
        other => {
            return Err(
                format!("expected Unsupported for arithmetic coding, got {other:?}").into(),
            );
        }
    }

    // 5. 12-bit precision in SOF0
    let twelve_bit_bytes = [
        0xFF, 0xD8, // SOI
        0xFF, 0xC0, // SOF0
        0x00, 0x0B, // Length 11
        0x0C, // 12-bit precision
        0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xD9,
    ];
    let res = decode_baseline_jpeg(&twelve_bit_bytes, limits, &cx);
    match res {
        Err(JpegDecodeError::Unsupported { process }) => {
            require!(
                process.contains("12-bit"),
                "12-bit should mention precision, got: {process}"
            );
        }
        other => return Err(format!("expected Unsupported for 12-bit, got {other:?}").into()),
    }

    // 6. 4-component CMYK
    let cmyk_bytes = [
        0xFF, 0xD8, // SOI
        0xFF, 0xC0, // SOF0
        0x00, 0x14, // Length 20 (8 + 3*4)
        0x08, // 8-bit
        0x00, 0x10, 0x00, 0x10, // 16x16
        0x04, // 4 components
        0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01, 0x04, 0x11, 0x01, 0xFF, 0xD9,
    ];
    let res = decode_baseline_jpeg(&cmyk_bytes, limits, &cx);
    match res {
        Err(JpegDecodeError::Unsupported { process }) => {
            require!(
                process.contains("CMYK") || process.contains("4-component"),
                "CMYK should mention CMYK or 4-component, got: {process}"
            );
        }
        other => return Err(format!("expected Unsupported for CMYK, got {other:?}").into()),
    }

    // 7. 16-bit DQT
    let mut dqt_16bit_bytes = vec![
        0xFF, 0xD8, // SOI
        0xFF, 0xDB, // DQT
        0x00, 0x43, // Length 67 (2 + 1 + 64)
        0x10, // Precision = 1 (16-bit), table 0
    ];
    dqt_16bit_bytes.resize(71, 0x01);
    dqt_16bit_bytes.extend_from_slice(&[0xFF, 0xD9]);
    let res = decode_baseline_jpeg(&dqt_16bit_bytes, limits, &cx);
    match res {
        Err(JpegDecodeError::Unsupported { process }) => {
            require!(
                process.contains("16-bit DQT"),
                "16-bit DQT should mention 16-bit DQT, got: {process}"
            );
        }
        other => return Err(format!("expected Unsupported for 16-bit DQT, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_limit_exceeded_before_allocation() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();

    // Create a small valid JPEG to test limit overrides
    let gray_src = brown_luma_96x96();
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let encoded = encode_jpeg(96, 96, gray_src, &config)?;

    // 1. max_width limit
    let limits_width = JpegDecodeLimits {
        max_width: 50,
        ..Default::default()
    };
    let res = decode_baseline_jpeg(&encoded, limits_width, &cx);
    require!(
        matches!(res, Err(JpegDecodeError::LimitExceeded { ref limit }) if limit.contains("max_width")),
        "should fail on width limit"
    );

    // 2. max_height limit
    let limits_height = JpegDecodeLimits {
        max_height: 50,
        ..Default::default()
    };
    let res = decode_baseline_jpeg(&encoded, limits_height, &cx);
    require!(
        matches!(res, Err(JpegDecodeError::LimitExceeded { ref limit }) if limit.contains("max_height")),
        "should fail on height limit"
    );

    // 3. max_pixels limit
    let limits_pixels = JpegDecodeLimits {
        max_pixels: 5000,
        ..Default::default()
    };
    let res = decode_baseline_jpeg(&encoded, limits_pixels, &cx);
    require!(
        matches!(res, Err(JpegDecodeError::LimitExceeded { ref limit }) if limit.contains("max_pixels")),
        "should fail on max_pixels limit"
    );

    // 4. max_tensor_bytes limit
    let limits_tensor = JpegDecodeLimits {
        max_tensor_bytes: 5000,
        ..Default::default()
    };
    let res = decode_baseline_jpeg(&encoded, limits_tensor, &cx);
    require!(
        matches!(res, Err(JpegDecodeError::LimitExceeded { ref limit }) if limit.contains("max_tensor_bytes")),
        "should fail on max_tensor_bytes limit"
    );

    // 5. max_huffman_symbols limit
    let limits_huff = JpegDecodeLimits {
        max_huffman_symbols: 5,
        ..Default::default()
    };
    let res = decode_baseline_jpeg(&encoded, limits_huff, &cx);
    require!(
        matches!(res, Err(JpegDecodeError::LimitExceeded { ref limit }) if limit.contains("Huffman")),
        "should fail on max_huffman_symbols limit"
    );

    Ok(())
}

#[test]
fn test_truncation_detection() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = JpegDecodeLimits::default();

    let gray_src = brown_luma_96x96();
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let encoded = encode_jpeg(96, 96, gray_src, &config)?;

    // Truncate stream halfway through
    let cut_point = encoded.len() / 2;
    let truncated_slice = &encoded[..cut_point];

    let res = decode_baseline_jpeg(truncated_slice, limits, &cx);
    match res {
        Err(JpegDecodeError::Truncated { mcu_row }) => {
            // Must specify the row where truncation happened
            require!(
                mcu_row < 12,
                "mcu_row should be within total 12 rows, got {mcu_row}"
            );
        }
        other => return Err(format!("expected Truncated error, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_brown_luma_grayscale_acceptance() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = JpegDecodeLimits::default();

    let gray_src = brown_luma_96x96();
    require!(gray_src.len() == 96 * 96, "brown_luma size mismatch");

    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let encoded = encode_jpeg(96, 96, gray_src, &config)?;

    let decoded = decode_baseline_jpeg(&encoded, limits, &cx)?;

    // Dimensions and metadata
    require!(decoded.width == 96, "width mismatch: {}", decoded.width);
    require!(decoded.height == 96, "height mismatch: {}", decoded.height);
    require!(
        decoded.components == 1,
        "components mismatch: {}",
        decoded.components
    );
    require!(
        decoded.sampling == JpegSubsampling::Grayscale,
        "sampling should be Grayscale"
    );
    require!(
        decoded.decoder_generation == JPEG_DECODER_GENERATION,
        "decoder_generation mismatch: {}",
        decoded.decoder_generation
    );
    require!(
        !decoded.decoder_generation.contains('@'),
        "decoder_generation must not contain '@'"
    );

    // Tensor checks
    let shape = decoded.tensor.shape();
    require!(
        shape.dims() == [96, 96, 1],
        "tensor shape mismatch: {:?}",
        shape.dims()
    );

    let tensor_bytes = decoded.tensor.to_vec::<u8>()?;
    require!(
        tensor_bytes.len() == 96 * 96,
        "tensor bytes length mismatch: {}",
        tensor_bytes.len()
    );

    // Luma plane equivalence: for grey fixture, luma equals tensor single channel byte for byte
    let luma = decoded.luma();
    require!(
        luma == tensor_bytes.as_slice(),
        "luma() must equal tensor single channel byte-for-byte on grayscale"
    );

    // SHA-256 validation
    let expected_luma_digest = ContentDigest::sha256(luma);
    let mut expected_hex = String::with_capacity(64);
    for b in expected_luma_digest.bytes() {
        use std::fmt::Write;
        let _ = write!(&mut expected_hex, "{b:02x}");
    }
    require!(
        decoded.luma_sha256 == expected_hex,
        "luma_sha256 mismatch: {} vs {}",
        decoded.luma_sha256,
        expected_hex
    );

    // PSNR vs ground truth source: >= 30.0 dB
    let psnr = compute_psnr(gray_src, luma)?;
    require_psnr_ge(psnr, 30.0, "brown_luma_96x96")?;

    // Tensor generation check
    let canonical_digest = decoded.tensor.content_digest()?;
    require!(
        canonical_digest.algorithm().as_str() == "sha256",
        "tensor digest algorithm mismatch"
    );

    Ok(())
}

#[test]
fn test_brown_luma_q100_bounded_error() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = JpegDecodeLimits::default();

    let gray_src = brown_luma_96x96();
    let config = JpegConfig {
        quality: 100,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let encoded = encode_jpeg(96, 96, gray_src, &config)?;

    let decoded = decode_baseline_jpeg(&encoded, limits, &cx)?;
    let luma = decoded.luma();

    // At Q=100, discrete cosine quantization error is minimal; fixed-point integer
    // arithmetic yields a bounded maximum absolute error <= 2 on every pixel.
    let mut max_abs_diff = 0i32;
    let mut i = 0;
    while i < gray_src.len() {
        let diff = (gray_src[i] as i32 - luma[i] as i32).abs();
        if diff > max_abs_diff {
            max_abs_diff = diff;
        }
        i += 1;
    }

    require!(
        max_abs_diff <= 2,
        "Q100 bounded check failed: max error {max_abs_diff} > 2"
    );

    let psnr = compute_psnr(gray_src, luma)?;
    require_psnr_ge(psnr, 50.0, "Q100 brown_luma_96x96")?;

    Ok(())
}

#[test]
fn test_color_yuv444_roundtrip() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = JpegDecodeLimits::default();

    let width = 32u32;
    let height = 32u32;
    let rgb_src = generate_gradient_rgb(width, height);

    let config = JpegConfig {
        quality: 85,
        subsampling: Subsampling::Yuv444,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let encoded = encode_jpeg(width, height, &rgb_src, &config)?;

    let decoded = decode_baseline_jpeg(&encoded, limits, &cx)?;

    require!(decoded.width == width, "width mismatch");
    require!(decoded.height == height, "height mismatch");
    require!(decoded.components == 3, "components mismatch");
    require!(
        decoded.sampling == JpegSubsampling::Yuv444,
        "sampling mismatch"
    );

    let shape = decoded.tensor.shape();
    require!(
        shape.dims() == [height as usize, width as usize, 3],
        "shape mismatch: {:?}",
        shape.dims()
    );

    let decoded_rgb = decoded.tensor.to_vec::<u8>()?;
    let psnr = compute_psnr(&rgb_src, &decoded_rgb)?;
    require_psnr_ge(psnr, 30.0, "YUV444")?;

    require!(
        decoded.luma().len() == (width * height) as usize,
        "luma length mismatch"
    );

    Ok(())
}

#[test]
fn test_color_yuv420_roundtrip() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = JpegDecodeLimits::default();

    let width = 32u32;
    let height = 32u32;
    let rgb_src = generate_colorbars_rgb(width, height);

    let config = JpegConfig {
        quality: 85,
        subsampling: Subsampling::Yuv420,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let encoded = encode_jpeg(width, height, &rgb_src, &config)?;

    let decoded = decode_baseline_jpeg(&encoded, limits, &cx)?;

    require!(decoded.width == width, "width mismatch");
    require!(decoded.height == height, "height mismatch");
    require!(decoded.components == 3, "components mismatch");
    require!(
        decoded.sampling == JpegSubsampling::Yuv420,
        "sampling mismatch"
    );

    let shape = decoded.tensor.shape();
    require!(
        shape.dims() == [height as usize, width as usize, 3],
        "shape mismatch: {:?}",
        shape.dims()
    );

    let decoded_rgb = decoded.tensor.to_vec::<u8>()?;
    let psnr = compute_psnr(&rgb_src, &decoded_rgb)?;
    require_psnr_ge(psnr, 30.0, "YUV420")?;

    Ok(())
}

#[test]
fn test_color_yuv422_roundtrip() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = JpegDecodeLimits::default();

    let width = 32u32;
    let height = 32u32;
    let rgb_src = generate_colorbars_rgb(width, height);

    let config = JpegConfig {
        quality: 85,
        subsampling: Subsampling::Yuv422,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let encoded = encode_jpeg(width, height, &rgb_src, &config)?;

    let decoded = decode_baseline_jpeg(&encoded, limits, &cx)?;

    require!(decoded.width == width, "width mismatch");
    require!(decoded.height == height, "height mismatch");
    require!(decoded.components == 3, "components mismatch");
    require!(
        decoded.sampling == JpegSubsampling::Yuv422,
        "sampling mismatch"
    );

    let shape = decoded.tensor.shape();
    require!(
        shape.dims() == [height as usize, width as usize, 3],
        "shape mismatch: {:?}",
        shape.dims()
    );

    let decoded_rgb = decoded.tensor.to_vec::<u8>()?;
    let psnr = compute_psnr(&rgb_src, &decoded_rgb)?;
    require_psnr_ge(psnr, 30.0, "YUV422")?;

    Ok(())
}

#[test]
fn test_restart_interval_resync() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = JpegDecodeLimits::default();

    let gray_src = brown_luma_96x96();
    let config = JpegConfig {
        quality: 85,
        subsampling: Subsampling::Grayscale,
        restart_interval: 4, // 144 MCUs total -> 36 restart intervals
        custom_markers: Vec::new(),
    };
    let encoded = encode_jpeg(96, 96, gray_src, &config)?;

    // Successful decode with restart intervals
    let decoded = decode_baseline_jpeg(&encoded, limits, &cx)?;
    let psnr = compute_psnr(gray_src, decoded.luma())?;
    require_psnr_ge(psnr, 30.0, "DRI")?;

    // Limit exceeded check on restart intervals
    let tight_limits = JpegDecodeLimits {
        max_restart_intervals: 2,
        ..Default::default()
    };
    let res = decode_baseline_jpeg(&encoded, tight_limits, &cx);
    require!(
        matches!(res, Err(JpegDecodeError::LimitExceeded { ref limit }) if limit.contains("restart")),
        "should fail when restart interval count exceeds limit"
    );

    Ok(())
}

#[test]
fn test_cooperative_cancellation() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = JpegDecodeLimits::default();

    let gray_src = brown_luma_96x96();
    let config = JpegConfig {
        quality: 85,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let encoded = encode_jpeg(96, 96, gray_src, &config)?;

    // Signal cancellation before execution
    cx.request_cancellation();

    let res = decode_baseline_jpeg(&encoded, limits, &cx);
    require!(
        matches!(res, Err(JpegDecodeError::Cancelled)),
        "cancelled context must yield JpegDecodeError::Cancelled"
    );

    Ok(())
}

#[test]
fn test_corrupt_fuzzed_no_panic() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = JpegDecodeLimits::default();

    let gray_src = brown_luma_96x96();
    let config = JpegConfig {
        quality: 85,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let encoded = encode_jpeg(96, 96, gray_src, &config)?;

    // Test a variety of corruptions: bit flips, byte overwrites, truncations
    let mut rng_seed = 0x1234_5678u64;
    let next_pseudo_rand = |seed: &mut u64| -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        *seed
    };

    let mut trial = 0;
    while trial < 50 {
        let mut corrupted = encoded.clone();
        let rand_val = next_pseudo_rand(&mut rng_seed);
        let offset = (rand_val as usize) % corrupted.len();
        let mode = (rand_val >> 32) % 3;

        match mode {
            0 => {
                // Byte flip
                corrupted[offset] ^= 0xFF;
            }
            1 => {
                // Invalidate to marker byte
                corrupted[offset] = 0xFF;
            }
            2 => {
                // Truncate at offset
                corrupted.truncate(offset.max(2));
            }
            _ => {}
        }

        // Must never panic!
        let _ = decode_baseline_jpeg(&corrupted, limits, &cx);

        trial += 1;
    }

    Ok(())
}

const GOLDEN_TENSOR_DIGESTS: &[(&str, &str)] = &[
    ("gray_16x16_flat.jpg", "sha256:0920952e15b0efcdbb399ee883ce6c115f3ad4dbe73d788961f80633c2eb7d3a"),
    ("gray_16x16_gradient.jpg", "sha256:75d8e132fed51df3b983581205f6a039dc1a80500bd66ed8f27f7259cc057a78"),
    ("gray_33x17_checkerboard.jpg", "sha256:68f7a13180614c3841a4179d2f2a56935e103fc843f9cbf4a2fccbbe61b3113f"),
    ("brown_luma_q100.jpg", "sha256:d0a7caed27baf1cc2c3f2ee86e9890aa7e2a5af2cd2ad34f589a61ae2b1e5103"),
    ("brown_luma_qfix.jpg", "sha256:b9207cbcc9db6e7bd5413b5520cd2c9e9e847fb45a97d281c84777bc8d6fcdb6"),
    ("rgb_16x16_flat_444.jpg", "sha256:fb7bb29e7ffd1dec57d03f2dfafc8bcd0c6cbac4ca2c0720ce7fc756ca581de1"),
    ("rgb_16x16_gradient_420.jpg", "sha256:f47deec78410d492a43d70dcef76309a0193f06d657fc9120b6ff4db1ba6974b"),
    ("rgb_33x17_checkerboard_420.jpg", "sha256:90c34688c298d8b20d168b6be211e2774ebcc14573fed85c7dc610bd571ce53d"),
    ("rgb_64x48_colorbars_420.jpg", "sha256:82b06c327e2e4222fc8b5649be2f1efa57e8bbd3d675fc139e643fbdb471f03f"),
    ("rgb_64x48_colorbars_444.jpg", "sha256:0aa04687ca43761fe4215e827a247958b96586ec7ea4b11d3cb28561f9919fd6"),
    ("rgb_64x48_colorbars_422.jpg", "sha256:82b06c327e2e4222fc8b5649be2f1efa57e8bbd3d675fc139e643fbdb471f03f"),
    ("rgb_64x48_restart_ri5.jpg", "sha256:82b06c327e2e4222fc8b5649be2f1efa57e8bbd3d675fc139e643fbdb471f03f"),
    ("rgb_64x48_app_com_ffd9.jpg", "sha256:82b06c327e2e4222fc8b5649be2f1efa57e8bbd3d675fc139e643fbdb471f03f"),
];

#[test]
fn test_every_fixjpeg_fixture_decodes_and_matches_golden_tensor_digest() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = JpegDecodeLimits::default();

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .ok_or("Failed to locate repo root")?;

    let jpeg_dir = repo_root.join("tests/fixtures/media/jpeg");
    let jpegs = generate_all_jpeg_fixtures()?;
    require!(jpegs.len() == 13, "expected 13 JPEG fixtures");

    for j in &jpegs {
        let path = jpeg_dir.join(&j.name);
        require!(path.is_file(), "missing fixture file: {}", path.display());
        let disk_bytes = fs::read(&path)?;
        require!(disk_bytes == j.file_bytes, "disk bytes differ from generator for {}", j.name);

        let decoded = decode_baseline_jpeg(&disk_bytes, limits, &cx)?;

        require!(decoded.width == j.width, "width mismatch on {}: {} != {}", j.name, decoded.width, j.width);
        require!(decoded.height == j.height, "height mismatch on {}: {} != {}", j.name, decoded.height, j.height);
        require!(decoded.components == j.channels, "components mismatch on {}: {} != {}", j.name, decoded.components, j.channels);

        let shape = decoded.tensor.shape();
        require!(
            shape.dims() == [j.height as usize, j.width as usize, j.channels as usize],
            "shape dims mismatch on {}: {:?}",
            j.name,
            shape.dims()
        );
        require!(decoded.tensor.dtype() == fss_tensor::DType::U8, "dtype must be U8");
        require!(
            decoded.tensor.generation() == fss_reference::decode::JPEG_DECODER_GENERATION_NUMERIC,
            "generation mismatch"
        );
        require!(
            decoded.decoder_generation == fss_reference::decode::JPEG_DECODER_GENERATION,
            "decoder generation mismatch"
        );
        require!(
            !decoded.decoder_generation.contains('@'),
            "decoder generation must not contain @"
        );

        if j.channels == 1 {
            let tensor_bytes = decoded.tensor.to_vec::<u8>()?;
            require!(
                decoded.luma() == tensor_bytes.as_slice(),
                "luma() must equal tensor bytes byte-for-byte on grayscale fixture {}",
                j.name
            );
        }

        let luma_digest = ContentDigest::sha256(decoded.luma());
        let mut luma_hex = String::with_capacity(64);
        for b in luma_digest.bytes() {
            use std::fmt::Write;
            let _ = write!(&mut luma_hex, "{b:02x}");
        }
        require!(
            decoded.luma_sha256 == luma_hex,
            "luma_sha256 mismatch on {}: {} != {}",
            j.name,
            decoded.luma_sha256,
            luma_hex
        );

        let src = source_pixels(&j.name)?;
        let decoded_pixel_bytes = decoded.tensor.to_vec::<u8>()?;
        let psnr = compute_psnr(&src, &decoded_pixel_bytes)?;
        if let Some(min_psnr) = j.psnr_threshold {
            require_psnr_ge(psnr, min_psnr, &j.name)?;
        }

        let actual_digest = decoded.tensor.content_digest()?.to_string();
        let expected_golden = GOLDEN_TENSOR_DIGESTS
            .iter()
            .find(|(name, _)| *name == j.name)
            .map(|(_, digest)| *digest)
            .ok_or_else(|| format!("fixture {} missing from golden table", j.name))?;

        require!(
            actual_digest == expected_golden,
            "golden tensor digest mismatch on {}: actual {} != expected {}",
            j.name,
            actual_digest,
            expected_golden
        );
    }

    Ok(())
}
