#![forbid(unsafe_code)]
//! Contract, 0-ULP preprocess/postprocess fusion law certification, permutation invariance,
//! boundary/NaN/padding suppression, cancellation, and hostile-wire tests for `FSS-143`
//! (`fss-x4a.14.14`).

use fss_core::Generation;
use fss_reference::preprocess::{ImageBytes, ResizeAspect, ResizeFilter, ResizeOptions};
use fss_reference::preprocess_fusion::{
    FusionLawError, FusionLawKind, FusionVerificationVerdict, MODEL_FUSION_LAW_RECEIPT_DOMAIN,
    MODEL_FUSION_WIRE_MAGIC, MODEL_FUSION_WIRE_VERSION, ModelFusionLawReceipt,
    PostprocessFusionConfig, RawBoxProposal, certify_identity_resize_fusion,
    certify_postprocess_fusion, certify_preprocess_fusion,
};
use fss_reference::{ChannelTransform, ExecBudget, PreprocessProgram, ScalarExecCx};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

#[test]
fn preprocess_and_identity_resize_fusion_laws_are_bit_exact_across_all_modes() -> TestResult {
    assert_eq!(
        MODEL_FUSION_LAW_RECEIPT_DOMAIN,
        "fss.reference.model_fusion_law_receipt.v1"
    );

    let cx = ScalarExecCx::new();
    let gen_id = Generation(19);
    // Non-trivial 10x14 RGB test frame (deterministic pattern).
    let rgb_bytes: Vec<u8> = (0..(10 * 14 * 3))
        .map(|i| ((i * 37 + 13) % 256) as u8)
        .collect();
    let luma_bytes: Vec<u8> = (0..(10 * 14)).map(|i| ((i * 29 + 7) % 256) as u8).collect();

    let filters = [ResizeFilter::Nearest, ResizeFilter::Bilinear];
    let aspects = [ResizeAspect::Stretch, ResizeAspect::Letterbox(114)];
    let transforms = [
        (ChannelTransform::Rgb, 3, rgb_bytes.as_slice()),
        (ChannelTransform::LumaOnly, 3, rgb_bytes.as_slice()),
        (ChannelTransform::LumaOnly, 1, luma_bytes.as_slice()),
    ];

    let mut certified_count = 0_usize;
    for filter in filters {
        for aspect in aspects {
            for (transform, channels, bytes) in transforms {
                for scale_to_unit in [false, true] {
                    let program = PreprocessProgram::new(8, 8, transform, scale_to_unit);
                    let image = ImageBytes {
                        bytes,
                        height: 10,
                        width: 14,
                        channels,
                        generation: gen_id,
                    };
                    let options = ResizeOptions {
                        filter,
                        aspect,
                        budget: ExecBudget::unlimited(),
                    };
                    let (_tensor, _geo, receipt) =
                        certify_preprocess_fusion(&program, image, options, &cx)?;
                    assert!(!receipt.grants_effect_authority());
                    assert_eq!(
                        receipt.law_kind,
                        FusionLawKind::PreprocessResizeColorScaleNchw
                    );
                    assert_eq!(
                        receipt.verdict,
                        FusionVerificationVerdict::CertifiedBitExact
                    );
                    assert_eq!(receipt.max_ulp_delta, 0);
                    assert_eq!(receipt.unfused_output_digest, receipt.fused_output_digest);
                    assert!(
                        receipt.saved_intermediate_bytes > 0,
                        "single-pass fusion must eliminate unfused intermediate stage buffers"
                    );
                    certified_count += 1;
                }
            }
        }
    }
    assert_eq!(certified_count, 24);

    // Law 2: Identity resize `Stretch(10x14 -> 10x14)` == strict `execute_bytes` (0 ULP)!
    for filter in filters {
        let prog = PreprocessProgram::new(10, 14, ChannelTransform::Rgb, true);
        let id_receipt = certify_identity_resize_fusion(
            &prog,
            ImageBytes {
                bytes: &rgb_bytes,
                height: 10,
                width: 14,
                channels: 3,
                generation: gen_id,
            },
            filter,
            ExecBudget::unlimited(),
            &cx,
        )?;
        assert_eq!(id_receipt.law_kind, FusionLawKind::PreprocessIdentityResize);
        assert_eq!(id_receipt.max_ulp_delta, 0);
        assert_eq!(
            id_receipt.verdict,
            FusionVerificationVerdict::CertifiedBitExact
        );
    }

    emit_caplog(
        "fss_143_preprocess_fusion_laws",
        "all_24_preprocess_modes_and_identity_resize_certified_0ulp",
        "all_24_preprocess_modes_and_identity_resize_certified_0ulp",
        "pass",
    );
    Ok(())
}

#[test]
fn postprocess_fusion_law_nms_permutation_invariance_faults_and_wire() -> TestResult {
    let cx = ScalarExecCx::new();
    let gen_id = Generation(21);
    let rgb_bytes: Vec<u8> = (0..(12 * 24 * 3)).map(|i| (i % 251) as u8).collect();
    let prog = PreprocessProgram::new(16, 16, ChannelTransform::Rgb, true);
    let (_, letterbox_geo, _) = certify_preprocess_fusion(
        &prog,
        ImageBytes {
            bytes: &rgb_bytes,
            height: 12,
            width: 24,
            channels: 3,
            generation: gen_id,
        },
        ResizeOptions {
            filter: ResizeFilter::Bilinear,
            aspect: ResizeAspect::Letterbox(114),
            budget: ExecBudget::unlimited(),
        },
        &cx,
    )?;
    // Letterbox of 12x24 into 16x16 yields image_height=8, image_width=16, top=4, left=0!
    assert_eq!(letterbox_geo.top, 4);
    assert_eq!(letterbox_geo.image_height, 8);

    // Mix of high-score detections, overlapping NMS loser, exact-tie boxes, padding-only box,
    // NaN/Inf logits, boundary logit near threshold 0.5 (logit=0.0), and sub-threshold noise!
    let mut proposals = vec![
        // Class 0 high confidence inside active image [4..12]
        RawBoxProposal {
            class_id: 0,
            logit: 2.2,
            model_xyxy: [2.0, 5.0, 10.0, 11.0],
        },
        // Class 0 overlapping lower confidence (should be suppressed by NMS)
        RawBoxProposal {
            class_id: 0,
            logit: 1.5,
            model_xyxy: [2.5, 5.2, 10.2, 11.0],
        },
        // Class 1 same box as class 0 (different class -> MUST survive class-aware NMS!)
        RawBoxProposal {
            class_id: 1,
            logit: 1.8,
            model_xyxy: [2.0, 5.0, 10.0, 11.0],
        },
        // Exact threshold boundary (sigmoid(0.0) == 0.5) -> MUST survive!
        RawBoxProposal {
            class_id: 2,
            logit: 0.0,
            model_xyxy: [11.0, 4.0, 15.0, 9.0],
        },
        // Padding-only box (y in [0.0, 3.5] < top=4) -> MUST be suppressed!
        RawBoxProposal {
            class_id: 0,
            logit: 5.0,
            model_xyxy: [1.0, 0.0, 8.0, 3.5],
        },
        // Non-finite logit -> MUST be suppressed!
        RawBoxProposal {
            class_id: 0,
            logit: f32::NAN,
            model_xyxy: [1.0, 5.0, 6.0, 10.0],
        },
        // Reversed box -> MUST be suppressed!
        RawBoxProposal {
            class_id: 0,
            logit: 4.0,
            model_xyxy: [10.0, 5.0, 5.0, 10.0],
        },
    ];
    // Add 200 low-logit background proposals to exercise sub-threshold short-circuiting.
    for i in 0..200_u32 {
        proposals.push(RawBoxProposal {
            class_id: i % 4,
            logit: -3.5 - (i as f32) * 0.01,
            model_xyxy: [1.0, 5.0, 4.0, 8.0],
        });
    }

    let cfg = PostprocessFusionConfig {
        score_threshold: 0.5,
        nms_iou_threshold: 0.5,
        max_detections: 16,
        max_proposals: 1024,
    };

    let (dets_fwd, receipt) = certify_postprocess_fusion(&proposals, letterbox_geo, cfg, &cx)?;
    assert_eq!(
        receipt.law_kind,
        FusionLawKind::PostprocessThresholdUnletterboxNms
    );
    assert_eq!(
        receipt.verdict,
        FusionVerificationVerdict::CertifiedBitExact
    );
    assert_eq!(receipt.max_ulp_delta, 0);
    assert_eq!(dets_fwd.len(), 3);
    assert!(receipt.skipped_work_items >= 200);
    assert!(receipt.saved_intermediate_bytes > 0);

    // Permutation invariance: reversing proposal input order yields BIT-EXACT identical detections!
    proposals.reverse();
    let (dets_rev, receipt_rev) = certify_postprocess_fusion(&proposals, letterbox_geo, cfg, &cx)?;
    assert_eq!(dets_fwd.len(), dets_rev.len());
    for (a, b) in dets_fwd.iter().zip(&dets_rev) {
        assert!(
            a.bit_eq(b),
            "postprocess detections must be permutation invariant"
        );
    }
    assert_eq!(receipt.fused_output_digest, receipt_rev.fused_output_digest);

    // Fault checks: invalid thresholds, exceeded max_proposals, cancellation, hostile `FSSMFU01` wire!
    let bad_cfg = PostprocessFusionConfig {
        score_threshold: 1.0,
        ..cfg
    };
    assert!(matches!(
        certify_postprocess_fusion(&proposals, letterbox_geo, bad_cfg, &cx),
        Err(FusionLawError::InvalidConfig(_))
    ));
    let tiny_cap = PostprocessFusionConfig {
        max_proposals: 4,
        ..cfg
    };
    assert!(matches!(
        certify_postprocess_fusion(&proposals, letterbox_geo, tiny_cap, &cx),
        Err(FusionLawError::BoundsExceeded { .. })
    ));
    let cancel_cx = ScalarExecCx::new();
    cancel_cx.request_cancellation();
    assert_eq!(
        certify_postprocess_fusion(&proposals, letterbox_geo, cfg, &cancel_cx).unwrap_err(),
        FusionLawError::Cancelled
    );

    let wire = receipt.to_canonical_bytes()?;
    assert_eq!(&wire[..8], &MODEL_FUSION_WIRE_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]),
        MODEL_FUSION_WIRE_VERSION
    );
    assert_eq!(ModelFusionLawReceipt::from_canonical_bytes(&wire)?, receipt);
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        ModelFusionLawReceipt::from_canonical_bytes(&bad_magic),
        Err(FusionLawError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&9_u32.to_be_bytes());
    assert_eq!(
        ModelFusionLawReceipt::from_canonical_bytes(&bad_ver),
        Err(FusionLawError::UnsupportedVersion { version: 9 })
    );
    assert!(matches!(
        ModelFusionLawReceipt::from_canonical_bytes(&wire[..wire.len() - 4]),
        Err(FusionLawError::MalformedWire(_))
    ));
    let mut flipped = wire.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert_eq!(
        ModelFusionLawReceipt::from_canonical_bytes(&flipped),
        Err(FusionLawError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0xAB);
    assert!(matches!(
        ModelFusionLawReceipt::from_canonical_bytes(&trailing),
        Err(FusionLawError::MalformedWire(_))
    ));

    emit_caplog(
        "fss_143_postprocess_fusion_and_faults",
        "postprocess_0ulp_permutation_invariant_faults_and_fssmfu01_verified",
        "postprocess_0ulp_permutation_invariant_faults_and_fssmfu01_verified",
        "pass",
    );
    Ok(())
}
