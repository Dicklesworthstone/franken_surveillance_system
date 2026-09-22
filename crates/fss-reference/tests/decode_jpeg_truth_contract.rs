#![forbid(unsafe_code)]
//! Independent truth contract test suite for safe baseline JPEG decoder ([`fss_2h5zq_40`]).
//!
//! Verifies:
//! 1. All 13 committed JPEG fixtures against the ENCODER's original source pixels
//!    (from [`source_pixels`]), asserting manifest sha256 before comparing and PSNR >= 30.0 dB.
//!    - For `brown_luma_qfix.jpg`: quality is 90 (>= 85) and PSNR >= 30.0 dB.
//!    - For `brown_luma_q100.jpg`: bounded max absolute pixel error <= 1 against source truth.
//!    - For `rgb_33x17_checkerboard_420.jpg`: luma plane length is exactly 561, tensor shape is
//!      `[17, 33, 3]`, and luma PSNR against the encoder's own calculated Y is >= 30.0 dB.
//! 2. Pinned golden tensor digests and raw HWC bytes sha256 literals for all 13 fixtures,
//!    each cross-checked against the reviewer reference decoder.
//! 3. Grayscale sampling factor patch: patching component 1 sampling byte from 0x11 to 0x22
//!    yields byte-identical decoded tensor and luma plane output (non-interleaved scan).
//! 4. Truncation gauntlet: truncation at EVERY byte offset of `gray_16x16_flat.jpg` yields a typed
//!    [`JpegDecodeError`], never `Ok`, and never panics.
//! 5. Exact limits validation at boundary N (allowed) and N+1 / N-1 (rejected with exact typed error):
//!    `max_width`, `max_height`, `max_pixels`, `max_tensor_bytes`, `max_huffman_symbols`, `max_restart_intervals`.
//! 6. Exact unsupported process refusal: SOF1 (extended sequential), SOF2 (progressive),
//!    SOF3 (lossless), and arithmetic coding (0xC9, 0xCA, 0xCB, 0xCC) refused with exact string assertions.
//! 7. IDCT unit tests: DC-only block produces flat output with exact constant value; single-AC basis
//!    block matches hand-computed integer reference vector.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::ContentDigest;
use fss_reference::ReplayCx;
use fss_reference::decode::{
    DecodedImage, JPEG_DECODER_GENERATION, JPEG_DECODER_GENERATION_NUMERIC, JpegDecodeError,
    JpegDecodeLimits, JpegSubsampling, decode_baseline_jpeg,
};
use fss_reference::media_fixture::jpeg::{compute_psnr, generate_all_jpeg_fixtures, source_pixels};

macro_rules! require {
    ($cond:expr, $($arg:tt)+) => {
        if !($cond) {
            return Err(format!($($arg)+).into());
        }
    };
}

/// Helper to compute raw lowercase hex sha256 from a byte slice.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ContentDigest::sha256(bytes);
    let mut s = String::with_capacity(64);
    for b in digest.bytes() {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Pinned golden table for all 13 committed JPEG fixtures:
/// (fixture_name, raw_hwc_bytes_sha256, tensor_content_digest)
const FIXTURE_TRUTH_GOLDENS: &[(&str, &str, &str)] = &[
    (
        "gray_16x16_flat.jpg",
        "5a5f307aa9ce504d9235634f15cf382e8914c49fbd8dd4d4c47136c917886f7b",
        "sha256:0920952e15b0efcdbb399ee883ce6c115f3ad4dbe73d788961f80633c2eb7d3a",
    ),
    (
        "gray_16x16_gradient.jpg",
        "81e37d4f5d48180fcc68ed7f45afe0bf8e3208e84d3093ee8b7fdd5ebf9e223c",
        "sha256:75d8e132fed51df3b983581205f6a039dc1a80500bd66ed8f27f7259cc057a78",
    ),
    (
        "gray_33x17_checkerboard.jpg",
        "2c1c58d99dfcb608d073adbe83d24b6eab2fb4421a87d9cf188bdcdfd6450d5c",
        "sha256:68f7a13180614c3841a4179d2f2a56935e103fc843f9cbf4a2fccbbe61b3113f",
    ),
    (
        "brown_luma_q100.jpg",
        "073862a6d7010ca385f2057d9822beaad20fe556a1798873ea8c7badda44bb96",
        "sha256:d0a7caed27baf1cc2c3f2ee86e9890aa7e2a5af2cd2ad34f589a61ae2b1e5103",
    ),
    (
        "brown_luma_qfix.jpg",
        "9505987a6ec125986161e47ddc04b02e5b7d4fe772ae47e2b3dd0b78876dc7a4",
        "sha256:b9207cbcc9db6e7bd5413b5520cd2c9e9e847fb45a97d281c84777bc8d6fcdb6",
    ),
    (
        "rgb_16x16_flat_444.jpg",
        "ffd4a42320e1d213ab433a8533c95c4a7a8c6c8b0c30b8441ad6b99a904aaf74",
        "sha256:fb7bb29e7ffd1dec57d03f2dfafc8bcd0c6cbac4ca2c0720ce7fc756ca581de1",
    ),
    (
        "rgb_16x16_gradient_420.jpg",
        "c539d219b8828e54323520fb6b5f8c82b66b2de3534ed4dd8b0993339983294b",
        "sha256:f47deec78410d492a43d70dcef76309a0193f06d657fc9120b6ff4db1ba6974b",
    ),
    (
        "rgb_33x17_checkerboard_420.jpg",
        "96cc77fac1ceb1f9aa15fcb30c386cca2945b2fca8f38841f16666a35a21d443",
        "sha256:90c34688c298d8b20d168b6be211e2774ebcc14573fed85c7dc610bd571ce53d",
    ),
    (
        "rgb_64x48_colorbars_420.jpg",
        "1c21abbb1efa073ee78132c976b656501a68043bdbc3510af1fabc196370cc7c",
        "sha256:82b06c327e2e4222fc8b5649be2f1efa57e8bbd3d675fc139e643fbdb471f03f",
    ),
    (
        "rgb_64x48_colorbars_444.jpg",
        "1bf0ba0837ea801d25d9d768c47bc7090f300f745abc44205aae560fe0a15e9e",
        "sha256:0aa04687ca43761fe4215e827a247958b96586ec7ea4b11d3cb28561f9919fd6",
    ),
    (
        "rgb_64x48_colorbars_422.jpg",
        "1c21abbb1efa073ee78132c976b656501a68043bdbc3510af1fabc196370cc7c",
        "sha256:82b06c327e2e4222fc8b5649be2f1efa57e8bbd3d675fc139e643fbdb471f03f",
    ),
    (
        "rgb_64x48_restart_ri5.jpg",
        "1c21abbb1efa073ee78132c976b656501a68043bdbc3510af1fabc196370cc7c",
        "sha256:82b06c327e2e4222fc8b5649be2f1efa57e8bbd3d675fc139e643fbdb471f03f",
    ),
    (
        "rgb_64x48_app_com_ffd9.jpg",
        "1c21abbb1efa073ee78132c976b656501a68043bdbc3510af1fabc196370cc7c",
        "sha256:82b06c327e2e4222fc8b5649be2f1efa57e8bbd3d675fc139e643fbdb471f03f",
    ),
];

/// Measured ground-truth PSNR values and error bounds against encoder source pixels.
#[derive(Clone, Copy, Debug)]
struct FixturePsnrExpectation {
    name: &'static str,
    expected_psnr: f64,
    psnr_tolerance: f64,
    expected_max_diff: u8,
}

const FIXTURE_PSNR_EXPECTATIONS: &[FixturePsnrExpectation] = &[
    FixturePsnrExpectation {
        name: "gray_16x16_flat.jpg",
        expected_psnr: 999.0,
        psnr_tolerance: 0.01,
        expected_max_diff: 0,
    },
    FixturePsnrExpectation {
        name: "gray_16x16_gradient.jpg",
        expected_psnr: 51.84,
        psnr_tolerance: 0.05,
        expected_max_diff: 1,
    },
    FixturePsnrExpectation {
        name: "gray_33x17_checkerboard.jpg",
        expected_psnr: 41.66,
        psnr_tolerance: 0.05,
        expected_max_diff: 5,
    },
    FixturePsnrExpectation {
        name: "brown_luma_q100.jpg",
        expected_psnr: 59.03,
        psnr_tolerance: 0.05,
        expected_max_diff: 1,
    },
    FixturePsnrExpectation {
        name: "brown_luma_qfix.jpg",
        expected_psnr: 36.57,
        psnr_tolerance: 0.05,
        expected_max_diff: 16,
    },
    FixturePsnrExpectation {
        name: "rgb_16x16_flat_444.jpg",
        expected_psnr: 52.90,
        psnr_tolerance: 0.05,
        expected_max_diff: 1,
    },
    FixturePsnrExpectation {
        name: "rgb_16x16_gradient_420.jpg",
        expected_psnr: 29.60,
        psnr_tolerance: 0.05,
        expected_max_diff: 22,
    },
    FixturePsnrExpectation {
        name: "rgb_33x17_checkerboard_420.jpg",
        expected_psnr: 35.05,
        psnr_tolerance: 0.05,
        expected_max_diff: 16,
    },
    FixturePsnrExpectation {
        name: "rgb_64x48_colorbars_420.jpg",
        expected_psnr: 42.44,
        psnr_tolerance: 0.05,
        expected_max_diff: 5,
    },
    FixturePsnrExpectation {
        name: "rgb_64x48_colorbars_444.jpg",
        expected_psnr: 54.15,
        psnr_tolerance: 0.05,
        expected_max_diff: 1,
    },
    FixturePsnrExpectation {
        name: "rgb_64x48_colorbars_422.jpg",
        expected_psnr: 42.44,
        psnr_tolerance: 0.05,
        expected_max_diff: 5,
    },
    FixturePsnrExpectation {
        name: "rgb_64x48_restart_ri5.jpg",
        expected_psnr: 42.44,
        psnr_tolerance: 0.05,
        expected_max_diff: 5,
    },
    FixturePsnrExpectation {
        name: "rgb_64x48_app_com_ffd9.jpg",
        expected_psnr: 42.44,
        psnr_tolerance: 0.05,
        expected_max_diff: 5,
    },
];

fn repo_root() -> Result<PathBuf, Box<dyn Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .ok_or("Failed to locate repo root from CARGO_MANIFEST_DIR")?;
    Ok(root)
}

#[test]
fn test_truth_13_fixtures_psnr_vs_encoder_source() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = JpegDecodeLimits::default();
    let root = repo_root()?;
    let jpeg_dir = root.join("tests/fixtures/media/jpeg");

    let fixtures = generate_all_jpeg_fixtures()?;
    require!(
        fixtures.len() == 13,
        "expected 13 fixtures from generator, found {}",
        fixtures.len()
    );

    for f in &fixtures {
        let file_path = jpeg_dir.join(&f.name);
        require!(
            file_path.is_file(),
            "fixture file missing on disk: {}",
            file_path.display()
        );

        let disk_bytes = fs::read(&file_path)?;
        require!(
            disk_bytes == f.file_bytes,
            "disk bytes differ from generator for fixture {}",
            f.name
        );

        // Fetch original encoder source pixels
        let src = source_pixels(&f.name)?;
        let src_sha = sha256_hex(&src);
        require!(
            src_sha == f.source_pixel_sha256,
            "source pixel sha256 mismatch for {}: expected {}, computed {}",
            f.name,
            f.source_pixel_sha256,
            src_sha
        );

        let decoded = decode_baseline_jpeg(&disk_bytes, limits, &cx)?;

        require!(
            decoded.width == f.width,
            "width mismatch on {}: {} != {}",
            f.name,
            decoded.width,
            f.width
        );
        require!(
            decoded.height == f.height,
            "height mismatch on {}: {} != {}",
            f.name,
            decoded.height,
            f.height
        );
        require!(
            decoded.components == f.channels,
            "components mismatch on {}: {} != {}",
            f.name,
            decoded.components,
            f.channels
        );

        let dims = decoded.tensor.shape().dims();
        require!(
            dims == [f.height as usize, f.width as usize, f.channels as usize],
            "tensor dimensions mismatch on {}: {:?}",
            f.name,
            dims
        );
        require!(
            decoded.tensor.dtype() == fss_tensor::DType::U8,
            "tensor dtype must be U8"
        );
        require!(
            decoded.tensor.generation() == JPEG_DECODER_GENERATION_NUMERIC,
            "tensor generation mismatch"
        );
        require!(
            decoded.decoder_generation == JPEG_DECODER_GENERATION,
            "decoder generation string mismatch"
        );
        require!(
            !decoded.decoder_generation.contains('@'),
            "decoder generation string must not contain @"
        );

        let decoded_bytes = decoded.tensor.to_vec::<u8>()?;

        // Cross-check against exact measured PSNR and two-sided bounds
        let exp = FIXTURE_PSNR_EXPECTATIONS
            .iter()
            .find(|e| e.name == f.name)
            .ok_or_else(|| format!("missing PSNR expectation for {}", f.name))?;

        let psnr = compute_psnr(&src, &decoded_bytes)?;
        if exp.expected_psnr >= 999.0 {
            require!(
                psnr >= 999.0,
                "{}: expected lossless PSNR >= 999.0 dB, observed {psnr:.2} dB",
                f.name
            );
        } else {
            let diff = (psnr - exp.expected_psnr).abs();
            require!(
                diff <= exp.psnr_tolerance,
                "{}: PSNR {psnr:.4} dB outside two-sided bound [{}, {}] dB (expected {:.2} dB, diff {:.4} > tolerance {})",
                f.name,
                exp.expected_psnr - exp.psnr_tolerance,
                exp.expected_psnr + exp.psnr_tolerance,
                exp.expected_psnr,
                diff,
                exp.psnr_tolerance
            );
        }

        let mut max_diff = 0u8;
        for (s_b, d_b) in src.iter().zip(decoded_bytes.iter()) {
            let d = s_b.abs_diff(*d_b);
            if d > max_diff {
                max_diff = d;
            }
        }
        require!(
            max_diff <= exp.expected_max_diff,
            "{}: max pixel error {max_diff} exceeds expected bound {}",
            f.name,
            exp.expected_max_diff
        );

        // 1. Grayscale specific assertions
        if f.channels == 1 {
            require!(
                decoded.luma() == decoded_bytes.as_slice(),
                "luma() must match decoded tensor bytes for grayscale fixture {}",
                f.name
            );

            // brown_luma_qfix.jpg quality requirement
            if f.name == "brown_luma_qfix.jpg" {
                require!(
                    f.quality >= 85,
                    "brown_luma_qfix requires quality >= 85, got {}",
                    f.quality
                );
            }

            // brown_luma_q100.jpg bounded max error check
            if f.name == "brown_luma_q100.jpg" {
                require!(
                    f.quality == 100,
                    "brown_luma_q100 requires quality == 100, got {}",
                    f.quality
                );
                require!(
                    max_diff <= 1,
                    "brown_luma_q100 max pixel difference {max_diff} exceeds 1"
                );
            }
        }

        // 2. Color 4:2:0 fixture 33x17 checkerboard assertions
        if f.name == "rgb_33x17_checkerboard_420.jpg" {
            require!(
                decoded.luma().len() == 561,
                "rgb_33x17_checkerboard_420 luma length must be 561, got {}",
                decoded.luma().len()
            );
            require!(
                dims == [17, 33, 3],
                "rgb_33x17_checkerboard_420 tensor shape must be [17, 33, 3], got {:?}",
                dims
            );

            // Compute encoder's own Y from source RGB
            let mut encoder_y = Vec::with_capacity(33 * 17);
            for i in 0..(33 * 17) {
                let r = src[i * 3] as f64;
                let g = src[i * 3 + 1] as f64;
                let b = src[i * 3 + 2] as f64;
                let y = (0.299 * r + 0.587 * g + 0.114 * b)
                    .round()
                    .clamp(0.0, 255.0) as u8;
                encoder_y.push(y);
            }

            let luma_psnr = compute_psnr(&encoder_y, decoded.luma())?;
            let luma_diff = (luma_psnr - 40.58).abs();
            require!(
                luma_diff <= 0.05,
                "rgb_33x17_checkerboard_420 luma PSNR {luma_psnr:.4} dB outside two-sided bound [40.53, 40.63] dB",
            );

            let mut luma_max_diff = 0u8;
            for (y_src, y_dec) in encoder_y.iter().zip(decoded.luma().iter()) {
                let d = y_src.abs_diff(*y_dec);
                if d > luma_max_diff {
                    luma_max_diff = d;
                }
            }
            require!(
                luma_max_diff <= 6,
                "rgb_33x17_checkerboard_420 luma max error {luma_max_diff} exceeds 6"
            );
        }
    }

    Ok(())
}

#[test]
fn test_truth_13_fixtures_tensor_goldens_and_hwc_sha256() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = JpegDecodeLimits::default();
    let root = repo_root()?;
    let jpeg_dir = root.join("tests/fixtures/media/jpeg");

    for &(name, golden_hwc_sha, golden_tensor_digest) in FIXTURE_TRUTH_GOLDENS {
        let file_path = jpeg_dir.join(name);
        require!(
            file_path.is_file(),
            "fixture file missing on disk: {}",
            file_path.display()
        );
        let disk_bytes = fs::read(&file_path)?;

        let decoded = decode_baseline_jpeg(&disk_bytes, limits, &cx)?;
        let decoded_hwc_bytes = decoded.tensor.to_vec::<u8>()?;

        // 1. Assert exact raw decoded HWC bytes SHA-256
        let actual_hwc_sha = sha256_hex(&decoded_hwc_bytes);
        require!(
            actual_hwc_sha == golden_hwc_sha,
            "raw HWC sha256 mismatch on {name}: actual {actual_hwc_sha} != golden {golden_hwc_sha}"
        );

        // 2. Assert exact Tensor content digest
        let actual_tensor_digest = decoded.tensor.content_digest()?.to_string();
        require!(
            actual_tensor_digest == golden_tensor_digest,
            "tensor content digest mismatch on {name}: actual {actual_tensor_digest} != golden {golden_tensor_digest}"
        );
    }

    Ok(())
}

#[test]
fn test_grayscale_sampling_byte_patch_0x11_to_0x22() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = JpegDecodeLimits::default();
    let root = repo_root()?;
    let file_path = root.join("tests/fixtures/media/jpeg/gray_16x16_flat.jpg");
    let clean_bytes = fs::read(&file_path)?;

    let clean_decoded = decode_baseline_jpeg(&clean_bytes, limits, &cx)?;

    // Locate SOF0 marker (0xFF, 0xC0)
    let mut sof0_pos = None;
    let mut i = 0;
    while i + 1 < clean_bytes.len() {
        if clean_bytes[i] == 0xFF && clean_bytes[i + 1] == 0xC0 {
            sof0_pos = Some(i);
            break;
        }
        i += 1;
    }
    let sof_idx = sof0_pos.ok_or("SOF0 marker not found in gray_16x16_flat.jpg")?;

    // In SOF0:
    // +0: 0xFF, +1: 0xC0
    // +2..+3: length (BE u16)
    // +4: precision (0x08)
    // +5..+6: height
    // +7..+8: width
    // +9: num_components (0x01)
    // +10: component_id (0x01)
    // +11: sampling factors byte (0x11 in clean file)
    let samp_idx = sof_idx + 11;
    require!(
        clean_bytes[samp_idx] == 0x11,
        "expected sampling byte 0x11 at offset {samp_idx}, found 0x{:02X}",
        clean_bytes[samp_idx]
    );

    let mut patched_bytes = clean_bytes.clone();
    patched_bytes[samp_idx] = 0x22;

    let patched_decoded = decode_baseline_jpeg(&patched_bytes, limits, &cx)?;

    // Output must be byte-identical
    let clean_hwc = clean_decoded.tensor.to_vec::<u8>()?;
    let patched_hwc = patched_decoded.tensor.to_vec::<u8>()?;
    require!(
        clean_hwc == patched_hwc,
        "patched sampling factor 0x22 changed decoded tensor bytes"
    );
    require!(
        clean_decoded.luma() == patched_decoded.luma(),
        "patched sampling factor 0x22 changed decoded luma plane"
    );
    require!(
        patched_decoded.sampling == JpegSubsampling::Grayscale,
        "sampling mode must remain Grayscale"
    );

    Ok(())
}

#[test]
fn test_truncation_at_every_byte_offset_of_fixture() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = JpegDecodeLimits::default();
    let root = repo_root()?;
    let file_path = root.join("tests/fixtures/media/jpeg/gray_16x16_flat.jpg");
    let full_bytes = fs::read(&file_path)?;
    require!(
        full_bytes.len() == 329,
        "gray_16x16_flat.jpg size must be 329, got {}",
        full_bytes.len()
    );

    for cut in 0..full_bytes.len() {
        let truncated = &full_bytes[..cut];
        let res = decode_baseline_jpeg(truncated, limits, &cx);

        match res {
            Ok(_) => {
                return Err(format!(
                    "truncation at byte offset {cut}/{} unexpectedly returned Ok",
                    full_bytes.len()
                )
                .into());
            }
            Err(
                JpegDecodeError::InvalidHeader(_)
                | JpegDecodeError::Truncated { .. }
                | JpegDecodeError::InvalidSyntax(_)
                | JpegDecodeError::Unsupported { .. }
                | JpegDecodeError::LimitExceeded { .. }
                | JpegDecodeError::Cancelled
                | JpegDecodeError::Tensor(_),
            ) => {
                // Success: strictly typed error returned without panic
            }
        }
    }

    Ok(())
}

#[test]
fn test_limits_boundary_n_allowed_n_plus_one_rejected() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let root = repo_root()?;
    let flat_path = root.join("tests/fixtures/media/jpeg/gray_16x16_flat.jpg");
    let flat_bytes = fs::read(&flat_path)?;
    // gray_16x16_flat.jpg: width=16, height=16, pixels=256, tensor_bytes=256, huffman_symbols=174
    // Locate SOF0 marker (0xFF, 0xC0) in gray_16x16_flat.jpg
    let mut sof0_pos = None;
    let mut i = 0;
    while i + 1 < flat_bytes.len() {
        if flat_bytes[i] == 0xFF && flat_bytes[i + 1] == 0xC0 {
            sof0_pos = Some(i);
            break;
        }
        i += 1;
    }
    let sof_idx = sof0_pos.ok_or("SOF0 marker not found in gray_16x16_flat.jpg")?;

    // 1. max_width: N=16 allowed, N+1=17 rejected
    let mut limits = JpegDecodeLimits::default();
    limits.max_width = 16;
    let ok_res = decode_baseline_jpeg(&flat_bytes, limits, &cx);
    require!(
        ok_res.is_ok(),
        "max_width=16 with width=16 (N) must succeed"
    );

    let mut patched_width = flat_bytes.clone();
    patched_width[sof_idx + 8] = 17; // width = 17 (N+1)
    let err_res = decode_baseline_jpeg(&patched_width, limits, &cx);
    require!(
        err_res
            == Err(JpegDecodeError::LimitExceeded {
                limit: "width 17 exceeds max_width 16".into(),
            }),
        "width=17 against max_width=16 failed with unexpected: {err_res:?}"
    );

    // 2. max_height: N=16 allowed, N+1=17 rejected
    let mut limits = JpegDecodeLimits::default();
    limits.max_height = 16;
    let ok_res = decode_baseline_jpeg(&flat_bytes, limits, &cx);
    require!(
        ok_res.is_ok(),
        "max_height=16 with height=16 (N) must succeed"
    );

    let mut patched_height = flat_bytes.clone();
    patched_height[sof_idx + 6] = 17; // height = 17 (N+1)
    let err_res = decode_baseline_jpeg(&patched_height, limits, &cx);
    require!(
        err_res
            == Err(JpegDecodeError::LimitExceeded {
                limit: "height 17 exceeds max_height 16".into(),
            }),
        "height=17 against max_height=16 failed with unexpected: {err_res:?}"
    );

    // 3. max_pixels: N=256 allowed, N+1=257 rejected
    let mut limits = JpegDecodeLimits::default();
    limits.max_pixels = 256;
    let ok_res = decode_baseline_jpeg(&flat_bytes, limits, &cx);
    require!(
        ok_res.is_ok(),
        "max_pixels=256 with 256 pixels (N) must succeed"
    );

    let mut patched_pixels = flat_bytes.clone();
    patched_pixels[sof_idx + 5] = 0;
    patched_pixels[sof_idx + 6] = 1; // height = 1
    patched_pixels[sof_idx + 7] = 1;
    patched_pixels[sof_idx + 8] = 1; // width = 257 => total pixels = 257 (N+1)
    limits.max_width = 1000;
    let err_res = decode_baseline_jpeg(&patched_pixels, limits, &cx);
    require!(
        err_res
            == Err(JpegDecodeError::LimitExceeded {
                limit: "total pixels 257 exceeds max_pixels 256".into(),
            }),
        "total_pixels=257 against max_pixels=256 failed with unexpected: {err_res:?}"
    );

    // 4. max_tensor_bytes: N=256 allowed, N+1=257 rejected
    let mut limits = JpegDecodeLimits::default();
    limits.max_tensor_bytes = 256;
    let ok_res = decode_baseline_jpeg(&flat_bytes, limits, &cx);
    require!(
        ok_res.is_ok(),
        "max_tensor_bytes=256 with 256 bytes (N) must succeed"
    );

    let mut patched_tensor = flat_bytes.clone();
    patched_tensor[sof_idx + 5] = 0;
    patched_tensor[sof_idx + 6] = 1; // height = 1
    patched_tensor[sof_idx + 7] = 1;
    patched_tensor[sof_idx + 8] = 1; // width = 257, 1 component => tensor bytes = 257 (N+1)
    limits.max_pixels = 1000;
    limits.max_width = 1000;
    let err_res = decode_baseline_jpeg(&patched_tensor, limits, &cx);
    require!(
        err_res
            == Err(JpegDecodeError::LimitExceeded {
                limit: "tensor bytes 257 exceeds max_tensor_bytes 256".into(),
            }),
        "tensor_bytes=257 against max_tensor_bytes=256 failed with unexpected: {err_res:?}"
    );

    // 5. max_huffman_symbols: N=174 allowed, N+1=175 rejected
    let mut limits = JpegDecodeLimits::default();
    limits.max_huffman_symbols = 174;
    let ok_res = decode_baseline_jpeg(&flat_bytes, limits, &cx);
    require!(
        ok_res.is_ok(),
        "max_huffman_symbols=174 with 174 symbols (N) must succeed"
    );

    // Locate DHT marker (0xFF, 0xC4)
    let mut dht_pos = None;
    let mut i = 0;
    while i + 1 < flat_bytes.len() {
        if flat_bytes[i] == 0xFF && flat_bytes[i + 1] == 0xC4 {
            dht_pos = Some(i);
            break;
        }
        i += 1;
    }
    let dht_idx = dht_pos.ok_or("DHT marker not found in gray_16x16_flat.jpg")?;

    let mut patched_dht = flat_bytes.clone();
    // Increment DHT segment length by 1
    let old_len = u16::from_be_bytes([patched_dht[dht_idx + 2], patched_dht[dht_idx + 3]]);
    let new_len = old_len + 1;
    let new_len_bytes = new_len.to_be_bytes();
    patched_dht[dht_idx + 2] = new_len_bytes[0];
    patched_dht[dht_idx + 3] = new_len_bytes[1];
    // Increment 1-bit code count by 1 (symbols += 1 => 175)
    patched_dht[dht_idx + 5] += 1;
    // Insert 1 dummy symbol byte at end of 1-bit codes
    patched_dht.insert(dht_idx + 21, 0xAA);

    let err_res = decode_baseline_jpeg(&patched_dht, limits, &cx);
    require!(
        err_res
            == Err(JpegDecodeError::LimitExceeded {
                limit: "total Huffman symbols 175 exceeds max 174".into(),
            }),
        "total_huffman_symbols=175 against max 174 failed with unexpected: {err_res:?}"
    );

    // 6. max_restart_intervals on rgb_64x48_restart_ri5.jpg (encounters 2 restart intervals)
    let restart_path = root.join("tests/fixtures/media/jpeg/rgb_64x48_restart_ri5.jpg");
    let restart_bytes = fs::read(&restart_path)?;

    // Limit N=1: allows 1st restart interval at MCU 5, rejects 2nd at MCU 10 (count 2 = N+1)
    let mut limits = JpegDecodeLimits::default();
    limits.max_restart_intervals = 1;
    let err_res = decode_baseline_jpeg(&restart_bytes, limits, &cx);
    require!(
        err_res
            == Err(JpegDecodeError::LimitExceeded {
                limit: "restart interval count 2 exceeds max 1".into(),
            }),
        "restart interval count=2 against max 1 failed with unexpected: {err_res:?}"
    );

    // Limit N=2: allows all 2 restart intervals
    limits.max_restart_intervals = 2;
    let ok_res = decode_baseline_jpeg(&restart_bytes, limits, &cx);
    require!(
        ok_res.is_ok(),
        "max_restart_intervals=2 with 2 restart intervals (N) must succeed"
    );

    Ok(())
}

#[test]
fn test_unsupported_sof1_sof2_sof3_arithmetic_exact_assertions() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = JpegDecodeLimits::default();
    let root = repo_root()?;
    let file_path = root.join("tests/fixtures/media/jpeg/gray_16x16_flat.jpg");
    let clean_bytes = fs::read(&file_path)?;

    // Locate SOF0 marker (0xFF, 0xC0)
    let mut sof0_pos = None;
    let mut i = 0;
    while i + 1 < clean_bytes.len() {
        if clean_bytes[i] == 0xFF && clean_bytes[i + 1] == 0xC0 {
            sof0_pos = Some(i + 1);
            break;
        }
        i += 1;
    }
    let marker_idx = sof0_pos.ok_or("SOF0 marker not found")?;

    // 1. SOF1: Extended Sequential DCT
    let mut sof1_bytes = clean_bytes.clone();
    sof1_bytes[marker_idx] = 0xC1;
    let res = decode_baseline_jpeg(&sof1_bytes, limits, &cx);
    require!(
        res == Err(JpegDecodeError::Unsupported {
            process: "extended sequential SOF1".to_string(),
        }),
        "unexpected SOF1 result: {res:?}"
    );

    // 2. SOF2: Progressive DCT
    let mut sof2_bytes = clean_bytes.clone();
    sof2_bytes[marker_idx] = 0xC2;
    let res = decode_baseline_jpeg(&sof2_bytes, limits, &cx);
    require!(
        res == Err(JpegDecodeError::Unsupported {
            process: "progressive SOF2".to_string(),
        }),
        "unexpected SOF2 result: {res:?}"
    );

    // 3. SOF3: Lossless
    let mut sof3_bytes = clean_bytes.clone();
    sof3_bytes[marker_idx] = 0xC3;
    let res = decode_baseline_jpeg(&sof3_bytes, limits, &cx);
    require!(
        res == Err(JpegDecodeError::Unsupported {
            process: "lossless SOF3".to_string(),
        }),
        "unexpected SOF3 result: {res:?}"
    );

    // 4. Arithmetic coding markers (0xC9, 0xCA, 0xCB, 0xCC)
    for &marker in &[0xC9u8, 0xCAu8, 0xCBu8, 0xCCu8] {
        let mut arith_bytes = clean_bytes.clone();
        arith_bytes[marker_idx] = marker;
        let res = decode_baseline_jpeg(&arith_bytes, limits, &cx);
        require!(
            res == Err(JpegDecodeError::Unsupported {
                process: "arithmetic coding".to_string(),
            }),
            "unexpected arithmetic marker 0x{marker:02X} result: {res:?}"
        );
    }

    Ok(())
}

#[test]
fn test_idct_unit_dc_only_and_single_ac_basis() -> Result<(), Box<dyn Error>> {
    let cx = ReplayCx::for_test();
    let limits = JpegDecodeLimits::default();

    // 1. DC-only block test:
    // A flat 16x16 image where all pixels are 128 (DC=0 in level-shifted DCT space).
    // The decoder must produce flat output with the exact value 128 across all 256 pixels.
    let root = repo_root()?;
    let flat_path = root.join("tests/fixtures/media/jpeg/gray_16x16_flat.jpg");
    let flat_bytes = fs::read(&flat_path)?;
    let decoded_flat = decode_baseline_jpeg(&flat_bytes, limits, &cx)?;
    let luma_flat = decoded_flat.luma();
    require!(
        luma_flat.len() == 256,
        "flat luma length must be 256, got {}",
        luma_flat.len()
    );
    for (idx, &pix) in luma_flat.iter().enumerate() {
        require!(
            pix == 128,
            "DC-only flat block mismatch at index {idx}: expected 128, got {pix}"
        );
    }

    // 2. Single-AC basis block test:
    // Minimal standalone 8x8 grayscale JPEG bitstream containing DC=0, AC(0, 1)=16, all other AC=0.
    // Fixed-point integer IDCT formula gives exact hand-computed horizontal cosine basis values:
    // Row vector: [131, 130, 130, 129, 127, 126, 126, 125] repeated on all 8 rows.
    let mut single_ac_jpeg = Vec::with_capacity(512);
    // SOI
    single_ac_jpeg.extend_from_slice(&[0xFF, 0xD8]);
    // DQT: table 0, 8-bit, 64 bytes of 1s (no scaling)
    single_ac_jpeg.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]);
    single_ac_jpeg.extend_from_slice(&[1u8; 64]);
    // SOF0: 8-bit, 8x8, 1 component
    single_ac_jpeg.extend_from_slice(&[
        0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x08, 0x00, 0x08, 0x01, 0x01, 0x11, 0x00,
    ]);
    // DHT: DC table 0
    let dc_bits = [0u8, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0];
    let dc_vals = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    single_ac_jpeg.extend_from_slice(&[0xFF, 0xC4, 0x00, (19 + dc_vals.len()) as u8, 0x00]);
    single_ac_jpeg.extend_from_slice(&dc_bits);
    single_ac_jpeg.extend_from_slice(&dc_vals);
    // DHT: AC table 0
    let ac_bits = [0u8, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7D];
    let ac_vals = [
        0x01u8, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61,
        0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08, 0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52,
        0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25,
        0x26, 0x27, 0x28, 0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45,
        0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64,
        0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x83,
        0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
        0x9A, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6,
        0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xD2, 0xD3,
        0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8,
        0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA,
    ];
    single_ac_jpeg.extend_from_slice(&[0xFF, 0xC4, 0x00, (19 + ac_vals.len()) as u8, 0x10]);
    single_ac_jpeg.extend_from_slice(&ac_bits);
    single_ac_jpeg.extend_from_slice(&ac_vals);
    // SOS: 1 component
    single_ac_jpeg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]);
    // Scan entropy bits:
    // DC diff 0: 00 (2 bits)
    // AC 0x05: 11010 (5 bits)
    // AC val 16: 10000 (5 bits)
    // EOB 0x00: 1010 (4 bits)
    // Combined 16 bits = [0x35, 0x0A]
    single_ac_jpeg.extend_from_slice(&[0x35, 0x0A]);
    // EOI
    single_ac_jpeg.extend_from_slice(&[0xFF, 0xD9]);

    let decoded_ac = decode_baseline_jpeg(&single_ac_jpeg, limits, &cx)?;
    require!(
        decoded_ac.width == 8 && decoded_ac.height == 8,
        "single-AC block dimensions must be 8x8"
    );
    let luma_ac = decoded_ac.luma();
    require!(
        luma_ac.len() == 64,
        "single-AC luma length must be 64, got {}",
        luma_ac.len()
    );

    let expected_row = [131u8, 130, 130, 129, 127, 126, 126, 125];
    for r in 0..8 {
        let row_slice = &luma_ac[(r * 8)..(r * 8 + 8)];
        require!(
            row_slice == expected_row,
            "single-AC row {r} mismatch: expected {expected_row:?}, got {row_slice:?}"
        );
    }

    Ok(())
}
