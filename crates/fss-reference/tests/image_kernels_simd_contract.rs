#![forbid(unsafe_code)]
//! FSS-123 (`fss-x4a.12.22`) contract, differential, metamorphic, malformed-input,
//! cancellation, pressure, privacy, stale-generation, and same-binary A/A + A/B
//! gate test suite for safe SIMD image transform candidates.
//!
//! Emits structured `CAPLOG` records compatible with `scripts/e2e/lib.sh` and
//! `scripts/e2e/validate_log.py` (bounded size, zero secret-like keys).

use std::error::Error;

use fss_core::experiment::{ComparisonOutcome, ExperimentKind, ExperimentReceipt};
use fss_core::{ContentDigest, Generation, ResourcePressure, TimestampNs};
use fss_reference::image_kernels::simd::{
    CandidateGateState, FallbackReason, GateFailureAction, GateFaultInjection, GatePolicy,
    ImageKernelBackend, ImageKernelCx, ImageKernelOp, ImageTransformBudget, ImageTransformRequest,
    NORMALIZE_LUT_THRESHOLD, SameBinaryImageGate, SimdKernelError, TransformOutcome,
    normalize_luma_simd, resize_bilinear_luma_simd, rgb_to_luma_simd,
    scalar_image_kernel_generation, simd_image_kernel_generation,
};
use fss_reference::image_kernels::{
    ImageKernelError, MAX_AXIS, normalize_luma, resize_bilinear_luma, rgb_to_luma,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn emit_caplog(step: &str, verdict: bool, digest: ContentDigest, detail: &str) {
    let observed = if verdict { detail } else { "failed" };
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"exit\":{},\"verdict\":\"{}\",\"expected\":\"{detail}\",\"observed\":\"{observed}\",\"digest\":\"{}\"}}",
        if verdict { 0 } else { 1 },
        if verdict { "pass" } else { "fail" },
        digest.to_text(),
    );
}

fn basis() -> ContentDigest {
    ContentDigest::sha256(b"contract_basis:fss.media.v1")
}

fn synthetic_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        out.push((state >> 56) as u8);
    }
    out
}

#[test]
fn differential_bit_exact_parity_across_geometries_and_tails() -> TestResult {
    // 1. Resize bilinear luma: sweep tiny, odd, tile-aligned, non-aligned, upscales, downscales.
    let mut resize_cases = 0u64;
    let mut combined = Vec::new();
    for &(sw, sh) in &[(1usize, 1), (3, 5), (8, 8), (15, 9), (33, 19), (64, 24)] {
        let src = synthetic_bytes(sw * sh, (sw as u64) * 997 + sh as u64);
        for &(dw, dh) in &[
            (1usize, 1),
            (2, 7),
            (8, 4),
            (9, 9),
            (16, 12),
            (25, 13),
            (40, 17),
        ] {
            let ref_out = resize_bilinear_luma(&src, sw, sh, dw, dh)?;
            let simd_out = resize_bilinear_luma_simd(&src, sw, sh, dw, dh)?;
            assert_eq!(
                simd_out, ref_out,
                "resize mismatch for {sw}x{sh} -> {dw}x{dh}"
            );
            resize_cases += 1;
            if resize_cases <= 8 {
                combined.extend_from_slice(&simd_out[..simd_out.len().min(16)]);
            }
        }
    }

    // 2. RGB to luma: sweep 1..=35 pixels (exercises 0..4 full 8-pixel SIMD chunks + every tail 0..7)
    // plus boundary primary/extreme colors.
    let mut rgb_cases = 0u64;
    for pixels in 1usize..=35 {
        let rgb = synthetic_bytes(pixels * 3, 0xABCD_0000 + pixels as u64);
        let ref_out = rgb_to_luma(&rgb)?;
        let simd_out = rgb_to_luma_simd(&rgb)?;
        assert_eq!(simd_out, ref_out, "rgb_to_luma mismatch at {pixels} pixels");
        rgb_cases += 1;
    }
    let extremes = [
        0u8, 0, 0, 255, 255, 255, 255, 0, 0, 0, 255, 0, 0, 0, 255, 1, 2, 3, 254, 253, 252, 128,
        128, 128, 17, 239, 91,
    ];
    assert_eq!(rgb_to_luma_simd(&extremes)?, rgb_to_luma(&extremes)?);

    // 3. Normalize luma: below and above NORMALIZE_LUT_THRESHOLD (256), plus constant & full-range.
    let mut norm_cases = 0u64;
    for &(w, h) in &[
        (1usize, 1),
        (7, 3),
        (16, 4),
        (15, 17), // 255 (just below LUT threshold)
        (16, 16), // 256 (exact LUT threshold)
        (17, 17), // 289 (LUT + tail)
        (37, 29), // 1073 (LUT + multi-chunk + tail)
    ] {
        let plane = synthetic_bytes(w * h, 0x5555_0000 + (w * h) as u64);
        let ref_out = normalize_luma(&plane, w, h, 128)?;
        let simd_out = normalize_luma_simd(&plane, w, h, 128)?;
        assert_eq!(simd_out, ref_out, "normalize mismatch at {w}x{h}");
        // Constant plane check.
        let flat = vec![73u8; w * h];
        assert_eq!(
            normalize_luma_simd(&flat, w, h, 99)?,
            normalize_luma(&flat, w, h, 99)?
        );
        norm_cases += 1;
    }
    assert!(NORMALIZE_LUT_THRESHOLD == 256);

    // 4. Metamorphic invariants: constant-image preservation & horizontal flip commutativity.
    let src_img = synthetic_bytes(23 * 13, 0x1234_5678);
    let mut flipped_src = vec![0u8; 23 * 13];
    for y in 0..13 {
        for x in 0..23 {
            flipped_src[y * 23 + (22 - x)] = src_img[y * 23 + x];
        }
    }
    let out_norm = normalize_luma_simd(&src_img, 23, 13, 128)?;
    let out_flipped = normalize_luma_simd(&flipped_src, 23, 13, 128)?;
    for y in 0..13 {
        for x in 0..23 {
            assert_eq!(out_norm[y * 23 + x], out_flipped[y * 23 + (22 - x)]);
        }
    }

    // Kernel generation digests must be distinct, non-zero, and deterministic.
    assert_ne!(
        scalar_image_kernel_generation(),
        simd_image_kernel_generation()
    );

    let digest = ContentDigest::sha256(&combined);
    emit_caplog(
        "differential_bit_exact_parity_across_geometries_and_tails",
        true,
        digest,
        &format!("resize={resize_cases}_rgb={rgb_cases}_norm={norm_cases}_bit_exact"),
    );
    Ok(())
}

#[test]
fn same_binary_gate_aa_ab_certification_and_execution() -> TestResult {
    let mut gate = SameBinaryImageGate::new(GatePolicy::default())?;
    let cx = ImageKernelCx::nominal("pipeline:ingest-01", basis(), Generation::from_u64(7));

    // All three operators start Staged (uncertified).
    for op in [
        ImageKernelOp::ResizeBilinearLuma,
        ImageKernelOp::RgbToLuma,
        ImageKernelOp::NormalizeLuma,
    ] {
        assert_eq!(gate.state(op), &CandidateGateState::Staged);
    }

    // 1. Resize gated execution triggers automatic same-binary A/A + A/B certification.
    let src = synthetic_bytes(32 * 24, 42);
    let req_resize = ImageTransformRequest::ResizeBilinearLuma {
        src: &src,
        src_w: 32,
        src_h: 24,
        dst_w: 19,
        dst_h: 13,
    };
    let outcome = gate.execute_gated("exp:resize-1", &req_resize, &cx, TimestampNs(100))?;
    let TransformOutcome::Completed {
        output,
        output_digest,
        backend_used,
        kernel_generation,
        cost,
        gate_receipt,
    } = outcome
    else {
        return Err("expected Completed outcome for valid resize".into());
    };
    assert_eq!(backend_used, ImageKernelBackend::SafeSimdV1);
    assert_eq!(kernel_generation, simd_image_kernel_generation());
    assert_eq!(output, resize_bilinear_luma(&src, 32, 24, 19, 13)?);
    assert_eq!(output_digest, ContentDigest::sha256(&output));
    assert!(cost.simd_chunks > 0);
    assert!(cost.scalar_tail_items > 0);
    assert!(cost.scratch_bytes > 0);

    let rcpt = gate_receipt.ok_or("expected SameBinaryGateReceipt on initial certification")?;
    assert_eq!(rcpt.receipt_digest, rcpt.compute_digest());
    assert_eq!(rcpt.ab_receipt.kind, ExperimentKind::Ab);
    assert_eq!(rcpt.ab_receipt.comparison, ComparisonOutcome::Identical);
    assert_eq!(
        rcpt.ab_receipt.runs[0].binary_identity,
        gate.binary_identity()
    );
    assert_eq!(
        rcpt.ab_receipt.runs[1].binary_identity,
        gate.binary_identity()
    );
    assert_eq!(ExperimentReceipt::SCHEMA, "fss.experiment_receipt.v1");
    let aa = rcpt.aa_receipt.ok_or("expected mandatory A/A receipt")?;
    assert_eq!(aa.kind, ExperimentKind::Aa);
    assert_eq!(aa.comparison, ComparisonOutcome::Identical);
    assert!(!aa.is_determinism_alarm());
    assert!(matches!(
        gate.state(ImageKernelOp::ResizeBilinearLuma),
        CandidateGateState::Certified { .. }
    ));

    // Subsequent call reuses certified state without re-running certification.
    let outcome2 = gate.execute_gated("exp:resize-2", &req_resize, &cx, TimestampNs(101))?;
    let TransformOutcome::Completed {
        gate_receipt: rcpt2,
        output_digest: dig2,
        ..
    } = outcome2
    else {
        return Err("expected Completed on cached certified call".into());
    };
    assert!(rcpt2.is_none());
    assert_eq!(dig2, output_digest);

    // 2. Certify and execute RGB-to-luma and Normalize-luma through the same gate.
    let rgb = synthetic_bytes(37 * 3, 99);
    let req_rgb = ImageTransformRequest::RgbToLuma { rgb: &rgb };
    let out_rgb = gate.execute_gated("exp:rgb-1", &req_rgb, &cx, TimestampNs(102))?;
    assert!(matches!(
        out_rgb,
        TransformOutcome::Completed {
            backend_used: ImageKernelBackend::SafeSimdV1,
            gate_receipt: Some(_),
            ..
        }
    ));

    let plane = synthetic_bytes(20 * 20, 123);
    let req_norm = ImageTransformRequest::NormalizeLuma {
        plane: &plane,
        width: 20,
        height: 20,
        constant_fill: 128,
    };
    let out_norm = gate.execute_gated("exp:norm-1", &req_norm, &cx, TimestampNs(103))?;
    assert!(matches!(
        out_norm,
        TransformOutcome::Completed {
            backend_used: ImageKernelBackend::SafeSimdV1,
            gate_receipt: Some(_),
            ..
        }
    ));

    assert_eq!(gate.metrics().certifications_admitted, 3);
    assert_eq!(gate.metrics().simd_executions, 4);

    emit_caplog(
        "same_binary_gate_aa_ab_certification_and_execution",
        true,
        rcpt.receipt_digest,
        "certified_3_ops_simd_execs=4",
    );
    Ok(())
}

#[test]
fn fault_injected_aa_alarm_ab_divergence_indeterminate_quarantine_and_fallback() -> TestResult {
    let src = synthetic_bytes(24 * 16, 777);
    let req = ImageTransformRequest::ResizeBilinearLuma {
        src: &src,
        src_w: 24,
        src_h: 16,
        dst_w: 16,
        dst_h: 10,
    };
    let scalar_expected = resize_bilinear_luma(&src, 24, 16, 16, 10)?;

    // 1. A/A determinism alarm under Quarantine policy -> fail closed, zero output, stays quarantined!
    let mut gate_q = SameBinaryImageGate::new(GatePolicy {
        on_gate_failure: GateFailureAction::Quarantine,
        ..GatePolicy::default()
    })?;
    let mut cx_aa = ImageKernelCx::nominal("op:audit", basis(), Generation::from_u64(1));
    cx_aa.fault_injection = Some(GateFaultInjection::AaSecondRunFlipBit);
    let res_aa = gate_q.execute_gated("exp:aa-fault", &req, &cx_aa, TimestampNs(10))?;
    let TransformOutcome::Quarantined { gate_receipt, .. } = res_aa else {
        return Err("A/A alarm must quarantine fail-closed".into());
    };
    assert!(
        gate_receipt
            .aa_receipt
            .as_ref()
            .is_some_and(ExperimentReceipt::is_determinism_alarm)
    );
    assert_eq!(gate_q.metrics().aa_alarms, 1);
    assert!(matches!(
        gate_q.state(ImageKernelOp::ResizeBilinearLuma),
        CandidateGateState::Quarantined { .. }
    ));

    // Even with fault cleared, previously quarantined operator refuses silently re-admitting!
    let cx_clean = ImageKernelCx::nominal("op:audit", basis(), Generation::from_u64(1));
    let res_sticky = gate_q.execute_gated("exp:sticky", &req, &cx_clean, TimestampNs(11))?;
    assert!(matches!(res_sticky, TransformOutcome::Quarantined { .. }));

    // 2. A/B divergence under FallbackToScalar policy -> explicit FallbackToScalar with scalar oracle output + negative receipt!
    let mut gate_fb = SameBinaryImageGate::new(GatePolicy {
        on_gate_failure: GateFailureAction::FallbackToScalar,
        ..GatePolicy::default()
    })?;
    let mut cx_ab = ImageKernelCx::nominal("op:audit", basis(), Generation::from_u64(2));
    cx_ab.fault_injection = Some(GateFaultInjection::AbCandidateFlipByte);
    let res_ab = gate_fb.execute_gated("exp:ab-fault", &req, &cx_ab, TimestampNs(20))?;
    let TransformOutcome::FallbackToScalar {
        output,
        reason,
        gate_receipt: Some(ab_rcpt),
        ..
    } = res_ab
    else {
        return Err(
            "A/B divergence under FallbackToScalar must return FallbackToScalar with receipt"
                .into(),
        );
    };
    assert_eq!(reason, FallbackReason::AbDivergence);
    assert_eq!(output, scalar_expected);
    assert_eq!(ab_rcpt.ab_receipt.comparison, ComparisonOutcome::Divergent);
    assert_eq!(gate_fb.metrics().ab_divergences, 1);
    assert_eq!(gate_fb.metrics().scalar_fallbacks, 1);

    // Next clean call on quarantined op under FallbackToScalar explicitly reports PreviouslyQuarantined.
    let res_fb2 = gate_fb.execute_gated(
        "exp:ab-post",
        &req,
        &ImageKernelCx::nominal("op:audit", basis(), Generation::from_u64(2)),
        TimestampNs(21),
    )?;
    assert!(matches!(
        res_fb2,
        TransformOutcome::FallbackToScalar {
            reason: FallbackReason::PreviouslyQuarantined,
            ..
        }
    ));

    // 3. Indeterminate run never compares and never certifies.
    let mut gate_ind = SameBinaryImageGate::new(GatePolicy {
        on_gate_failure: GateFailureAction::Quarantine,
        ..GatePolicy::default()
    })?;
    let mut cx_ind = ImageKernelCx::nominal("op:audit", basis(), Generation::from_u64(3));
    cx_ind.fault_injection = Some(GateFaultInjection::CandidateOutcomeIndeterminate);
    let res_ind = gate_ind.execute_gated("exp:indet", &req, &cx_ind, TimestampNs(30))?;
    let TransformOutcome::Indeterminate {
        gate_receipt: ind_rcpt,
        ..
    } = res_ind
    else {
        return Err("expected Indeterminate outcome".into());
    };
    assert_eq!(
        ind_rcpt.ab_receipt.comparison,
        ComparisonOutcome::Indeterminate
    );
    assert_eq!(gate_ind.metrics().indeterminates, 1);

    emit_caplog(
        "fault_injected_aa_alarm_ab_divergence_indeterminate_quarantine_and_fallback",
        true,
        ab_rcpt.receipt_digest,
        "aa_alarm_ab_div_indet_all_honest",
    );
    Ok(())
}

#[test]
fn malformed_inputs_privacy_stale_generation_budget_pressure_and_cancellation() -> TestResult {
    // 1. Malformed dimensions and buffer lengths match FSS-122 typed refusals identically.
    assert!(matches!(
        resize_bilinear_luma_simd(&[1, 2, 3], 2, 2, 2, 2),
        Err(ImageKernelError::BufferMismatch { .. })
    ));
    assert!(matches!(
        resize_bilinear_luma_simd(&[1, 2, 3, 4], 0, 2, 2, 2),
        Err(ImageKernelError::InvalidDimension { .. })
    ));
    assert!(matches!(
        resize_bilinear_luma_simd(&[1, 2, 3, 4], 2, 2, MAX_AXIS + 1, 2),
        Err(ImageKernelError::EmptyTarget)
    ));
    assert!(matches!(
        rgb_to_luma_simd(&[1, 2]),
        Err(ImageKernelError::BufferMismatch { .. })
    ));
    assert!(matches!(
        rgb_to_luma_simd(&[]),
        Err(ImageKernelError::InvalidDimension { value: 0 })
    ));
    assert!(matches!(
        normalize_luma_simd(&[1, 2], 2, 2, 128),
        Err(ImageKernelError::BufferMismatch { .. })
    ));

    let mut gate = SameBinaryImageGate::new(GatePolicy::default())?;
    let plane = synthetic_bytes(32 * 32, 555);
    let req = ImageTransformRequest::NormalizeLuma {
        plane: &plane,
        width: 32,
        height: 32,
        constant_fill: 128,
    };

    // 2. Uncleared privacy refused before touching bytes.
    let mut cx_priv = ImageKernelCx::nominal("op:test", basis(), Generation::from_u64(1));
    cx_priv.privacy_cleared = false;
    assert!(matches!(
        gate.execute_gated("exp:priv", &req, &cx_priv, TimestampNs(10)),
        Err(SimdKernelError::PrivacyRefused { .. })
    ));

    // 3. Stale generation refused.
    let mut cx_stale = ImageKernelCx::nominal("op:test", basis(), Generation::from_u64(1));
    cx_stale.expected_generation = Generation::from_u64(2);
    assert!(matches!(
        gate.execute_gated("exp:stale", &req, &cx_stale, TimestampNs(11)),
        Err(SimdKernelError::StaleGeneration { .. })
    ));

    // 4. Hard budget refusal before allocation.
    let mut cx_budget = ImageKernelCx::nominal("op:test", basis(), Generation::from_u64(1));
    cx_budget.budget = ImageTransformBudget {
        max_input_bytes: 512,
        max_output_bytes: 512,
        max_work_units: 512,
    };
    assert!(matches!(
        gate.execute_gated("exp:budget", &req, &cx_budget, TimestampNs(12)),
        Err(SimdKernelError::BudgetExceeded {
            bound: "max_input_bytes",
            ..
        })
    ));

    // 5. Pressure refusal under Quarantine policy, vs explicit PressureDegraded fallback under FallbackToScalar.
    let mut cx_press = ImageKernelCx::nominal("op:test", basis(), Generation::from_u64(1));
    cx_press.pressure = ResourcePressure::Critical;
    assert!(matches!(
        gate.execute_gated("exp:press-q", &req, &cx_press, TimestampNs(13)),
        Err(SimdKernelError::PressureRefused {
            observed: ResourcePressure::Critical,
            ..
        })
    ));
    let mut gate_fb = SameBinaryImageGate::new(GatePolicy {
        on_gate_failure: GateFailureAction::FallbackToScalar,
        ..GatePolicy::default()
    })?;
    let fb_press = gate_fb.execute_gated("exp:press-fb", &req, &cx_press, TimestampNs(14))?;
    assert!(matches!(
        fb_press,
        TransformOutcome::FallbackToScalar {
            reason: FallbackReason::PressureDegraded,
            ..
        }
    ));

    // 6. Clean cancellation at bounded chunk checkpoint (request -> drain -> finalize).
    let mut cx_cancel = ImageKernelCx::nominal("op:test", basis(), Generation::from_u64(1));
    cx_cancel.cancel_after_chunks = Some(3);
    let cancelled = gate.execute_gated("exp:cancel", &req, &cx_cancel, TimestampNs(20))?;
    let TransformOutcome::Cancelled {
        backend_attempted,
        completed_chunks,
        cost,
    } = cancelled
    else {
        return Err("expected Cancelled outcome at chunk 3".into());
    };
    assert_eq!(backend_attempted, ImageKernelBackend::SafeSimdV1);
    assert_eq!(completed_chunks, 3);
    assert_eq!(cost.output_bytes, 0);
    assert_eq!(gate.metrics().cancellations, 1);

    // 7. Clock regression refused cleanly.
    let cx_ok = ImageKernelCx::nominal("op:test", basis(), Generation::from_u64(1));
    assert!(matches!(
        gate.execute_gated("exp:clock", &req, &cx_ok, TimestampNs(19)),
        Err(SimdKernelError::ClockRegression { .. })
    ));

    emit_caplog(
        "malformed_inputs_privacy_stale_generation_budget_pressure_and_cancellation",
        true,
        gate.binary_identity(),
        "malformed_privacy_stale_budget_pressure_cancel_clock_all_enforced",
    );
    Ok(())
}
