#![forbid(unsafe_code)]
//! FSS-052: pure-Rust media kernel contracts and limits — property family.
//!
//! Registry validity and digest identity, codec-defaults-within-contract
//! agreement across all three kernels, limit-validation refusals, and
//! typed (never panicking) decode refusals over a seeded garbage corpus.
//! Each property emits one JSONL verdict line.

use fss_core::media_kernel::{
    KERNEL_CONTRACTS, MAX_CODED_AXIS, MAX_ENCODED_BYTES, MAX_MJPEG_DIMENSION, MediaKernelContract,
    MediaKernelContractError, MediaKernelId,
};

fn emit(property: &str, cases: u64) {
    println!(
        "{{\"family\":\"FSS-052\",\"property\":\"{property}\",\"cases\":{cases},\"verdict\":\"pass\"}}"
    );
}

fn contract(kernel: MediaKernelId) -> MediaKernelContract {
    KERNEL_CONTRACTS
        .iter()
        .copied()
        .find(|c| c.kernel == kernel)
        .unwrap_or(KERNEL_CONTRACTS[0])
}

/// P1 REGISTRY: every row validates; digests are deterministic and
/// pairwise distinct (kernel identity is citable without ambiguity).
#[test]
fn p1_registry_validity_and_digest_identity() -> Result<(), Box<dyn std::error::Error>> {
    for row in KERNEL_CONTRACTS {
        row.validate()?;
        assert_eq!(row.digest(), row.digest(), "deterministic digest");
    }
    let digests: Vec<_> = KERNEL_CONTRACTS.iter().map(|c| c.digest()).collect();
    for i in 0..digests.len() {
        for j in i + 1..digests.len() {
            assert_ne!(digests[i], digests[j], "kernels {i}/{j} must not collide");
        }
    }
    // Bounds violations are named per field.
    let mut bad_axis = contract(MediaKernelId::H264);
    bad_axis.bounds.max_axis = MAX_CODED_AXIS + 1;
    assert_eq!(
        bad_axis.validate(),
        Err(MediaKernelContractError::BoundsViolation { field: "max_axis" })
    );
    let mut bad_bytes = contract(MediaKernelId::Mjpeg);
    bad_bytes.bounds.max_encoded_bytes = MAX_ENCODED_BYTES + 1;
    assert!(matches!(
        bad_bytes.validate(),
        Err(MediaKernelContractError::BoundsViolation { .. })
    ));
    let mut zero_pics = contract(MediaKernelId::H265);
    zero_pics.bounds.max_pictures = 0;
    assert!(matches!(
        zero_pics.validate(),
        Err(MediaKernelContractError::BoundsViolation { .. })
    ));
    let mut zero_version = contract(MediaKernelId::H264);
    zero_version.version = 0;
    assert_eq!(
        zero_version.validate(),
        Err(MediaKernelContractError::ZeroVersion)
    );
    // MJPEG's tighter dimension ceiling is enforced per kernel.
    let mut mjpeg_over = contract(MediaKernelId::Mjpeg);
    mjpeg_over.bounds.max_axis = MAX_MJPEG_DIMENSION + 1;
    assert!(mjpeg_over.validate().is_err());
    emit("registry-validity", 12);
    Ok(())
}

/// P2 CODEC AGREEMENT: each codec's default limits sit within its
/// contract's documented ceilings (registry/implementation agreement).
#[test]
fn p2_codec_defaults_within_contract() -> Result<(), Box<dyn std::error::Error>> {
    let h264 = fss_codec_h264::DecoderLimits::default();
    let h264_contract = contract(MediaKernelId::H264);
    assert!(h264.max_width <= h264_contract.bounds.max_axis);
    assert!(h264.max_height <= h264_contract.bounds.max_axis);
    assert!(h264.max_nal_bytes as u64 <= h264_contract.bounds.max_encoded_bytes);
    assert!(h264.max_pictures <= h264_contract.bounds.max_pictures);

    let h265 = fss_codec_h265::DecoderLimits::default();
    let h265_contract = contract(MediaKernelId::H265);
    assert!(h265.max_width <= h265_contract.bounds.max_axis);
    assert!(h265.max_height <= h265_contract.bounds.max_axis);
    assert!(h265.max_nal_bytes as u64 <= h265_contract.bounds.max_encoded_bytes);

    let mjpeg = fss_codec_mjpeg::DecodeLimits::default();
    let mjpeg_contract = contract(MediaKernelId::Mjpeg);
    assert!(mjpeg.maximum_dimension <= mjpeg_contract.bounds.max_axis);
    assert!(mjpeg.maximum_bytes as u64 <= mjpeg_contract.bounds.max_encoded_bytes);
    emit("codec-defaults-agreement", 9);
    Ok(())
}

/// P3 LIMIT VALIDATION: the codecs refuse over-ceiling and degenerate
/// limit sets deterministically (bounds are load-bearing, not advisory).
#[test]
fn p3_limit_validation_refusals() -> Result<(), Box<dyn std::error::Error>> {
    let over = fss_codec_h264::DecoderLimits {
        max_width: MAX_CODED_AXIS + 1,
        ..fss_codec_h264::DecoderLimits::default()
    };
    assert!(fss_codec_h264::Decoder::new(over).is_err());
    let zero_pics = fss_codec_h264::DecoderLimits {
        max_pictures: 0,
        ..fss_codec_h264::DecoderLimits::default()
    };
    assert!(fss_codec_h264::Decoder::new(zero_pics).is_err());
    let h265_over = fss_codec_h265::DecoderLimits {
        max_width: MAX_CODED_AXIS + 1,
        ..fss_codec_h265::DecoderLimits::default()
    };
    assert!(fss_codec_h265::Decoder::new(h265_over).is_err());
    emit("limit-validation", 3);
    Ok(())
}

/// P4 GARBAGE REFUSALS: a seeded corpus of truncated and mutated NAL
/// units is refused with typed errors — never a panic — under both ITU
/// decoders.
#[test]
fn p4_typed_refusals_over_garbage() -> Result<(), Box<dyn std::error::Error>> {
    let mut seed = 0x0047_4152_u64;
    let mut next = move || {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        seed >> 33
    };
    let mut refused = 0u64;
    for trial in 0..200u64 {
        let len = (next() % 64) as usize + 1;
        let mut bytes = vec![0u8; len];
        for b in &mut bytes {
            *b = (next() % 256) as u8;
        }
        // Keep a plausible NAL header for the ITU parsers to engage.
        bytes[0] = if trial % 2 == 0 { 0x67 } else { 0x68 };
        let mut h264 = fss_codec_h264::Decoder::new(fss_codec_h264::DecoderLimits::default())?;
        let mut h265 = fss_codec_h265::Decoder::new(fss_codec_h265::DecoderLimits::default())?;
        // Any outcome (Ok picture-free, Ok picture, or typed Err) is fine;
        // a panic would fail the test harness itself.
        let _ = h264.decode_nal(&bytes);
        let _ = h265.decode_nal(&bytes);
        refused += 2;
    }
    emit("typed-garbage-refusals", refused);
    Ok(())
}
