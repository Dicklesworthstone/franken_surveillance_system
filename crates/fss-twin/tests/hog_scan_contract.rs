#![forbid(unsafe_code)]
//! Synthetic coefficient fixtures test computation, NOT pedestrian detection quality.
use std::error::Error;
use std::sync::atomic::AtomicBool;
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, WorkBudget};
use fss_twin::foreground::ForegroundSource;
use fss_twin::hog::{HogError, HogFrame, HogLevel, HogModel, HOG_PARAMETERS};
use fss_twin::hog_scan::*;
use fss_twin::localization::ImageIdentity;

type Test = Result<(), Box<dyn Error>>;
const BUDGET: u64 = 100_000_000;
fn source(pixels: &[u8], dimensions: [u32; 2]) -> ForegroundSource {
    ForegroundSource { image: ImageIdentity { exposure: [1; 32], pixels: ContentDigest::sha256(pixels).bytes(),
        image_domain: [2; 32], dimensions }, camera: 1, calibration: [3; 32], clock: 1, capture: [4, 6] }
}
fn policy() -> ScanPolicy {
    ScanPolicy { stride: [8, 8], minimum_margin: 1.0, suppression_iou_ppm: 500_000,
        maximum_windows: 100, maximum_candidates: 100 }
}
fn model(bias: f32) -> Result<HogModel, HogError> {
    let mut bytes = vec![0_u8; HOG_PARAMETERS * 4];
    bytes[(HOG_PARAMETERS - 1) * 4..].copy_from_slice(&bias.to_le_bytes());
    HogModel::from_f32_le(&bytes, ContentDigest::sha256(&bytes).bytes(), [9; 32], &mut WorkBudget::new(BUDGET))
}
#[test]
fn complete_native_and_resized_scales_have_stable_scores_suppression_and_source_bounds() -> Test {
    let pixels = vec![100; 80 * 136]; let mask = vec![1; pixels.len()]; let source = source(&pixels, [80, 136]);
    let model = model(1.0)?;
    let levels = [ScanLevel { dimensions: [80, 136] }, ScanLevel { dimensions: [64, 128] }, ScanLevel { dimensions: [32, 64] }];
    let run = |levels: &[ScanLevel]| scan_hog(source, &pixels, &mask, &model, levels, policy(), &mut WorkBudget::new(BUDGET));
    let a = run(&levels)?; let b = run(&[levels[2], levels[0], levels[1]])?;
    assert_eq!(a.digest(), b.digest()); assert_eq!(a.windows(), b.windows());
    assert_eq!(a.windows().len(), 7); assert_eq!(a.selected().count(), 1);
    assert_eq!(a.levels()[2].windows, 0);
    assert_eq!(a.windows()[6].source_min, [0, 0]); assert_eq!(a.windows()[6].source_max, [80, 136]);
    for window in a.windows() {
        assert_eq!(window.margin, Some(1.0));
        if window.id != 1 { assert_eq!(window.disposition, WindowDisposition::Suppressed { by: 1 }); }
    }
    for level in a.levels() {
        assert_eq!(level.source.image.exposure, source.image.exposure);
        assert_eq!(level.source.capture, source.capture);
    }
    assert_ne!(a.levels()[0].source.image.image_domain, a.levels()[1].source.image.image_domain);
    Ok(())
}
#[test]
fn margins_are_actual_native_kernel_outputs_not_a_constant_detector_stub() -> Test {
    let pixels: Vec<_> = (0..64 * 128).map(|i| ((i * 17 + i / 64 * 11) % 256) as u8).collect();
    let mask = vec![1; pixels.len()]; let source = source(&pixels, [64, 128]);
    let mut bytes = Vec::new();
    for i in 0..HOG_PARAMETERS { bytes.extend_from_slice(&(((i % 11) as f32 - 5.0) * 0.01).to_le_bytes()); }
    let mut budget = WorkBudget::new(BUDGET);
    let model = HogModel::from_f32_le(&bytes, ContentDigest::sha256(&bytes).bytes(), [9; 32], &mut budget)?;
    let frame = HogFrame::new(source, &pixels, &mask, &mut budget)?;
    let level = HogLevel::compute(&frame, &mut budget)?;
    let descriptor = level.descriptor([0, 0], &mut budget)?.ok_or("unexpected private fixture")?;
    let parameters: Vec<_> = bytes.chunks_exact(4).map(|v| f32::from_le_bytes([v[0], v[1], v[2], v[3]])).collect();
    let expected = descriptor.iter().zip(&parameters).fold(f64::from(parameters[HOG_PARAMETERS - 1]),
        |sum, (feature, weight)| sum + f64::from(*feature) * f64::from(*weight));
    let scan = scan_hog(source, &pixels, &mask, &model, &[ScanLevel { dimensions: [64, 128] }], policy(), &mut budget)?;
    assert_eq!(scan.windows()[0].margin, Some(expected));
    assert_ne!(expected, f64::from(parameters[HOG_PARAMETERS - 1])); Ok(())
}
#[test]
fn denied_windows_remain_unscored_instead_of_becoming_negatives() -> Test {
    let pixels = vec![100; 80 * 136]; let mask = vec![0; pixels.len()]; let model = model(1.0)?;
    let scan = scan_hog(source(&pixels, [80, 136]), &pixels, &mask, &model,
        &[ScanLevel { dimensions: [80, 136] }, ScanLevel { dimensions: [64, 128] }], policy(), &mut WorkBudget::new(BUDGET))?;
    assert_eq!(scan.windows().len(), 7); assert_eq!(scan.selected().count(), 0);
    assert!(scan.windows().iter().all(|w| w.margin.is_none() && w.disposition == WindowDisposition::Unobservable)); Ok(())
}
#[test]
fn native_gradient_halo_privacy_is_preserved_by_scan() -> Test {
    let pixels = vec![100; 72 * 128]; let mut mask = vec![1; pixels.len()]; mask[64] = 0;
    let scan = scan_hog(source(&pixels, [72, 128]), &pixels, &mask, &model(1.0)?,
        &[ScanLevel { dimensions: [72, 128] }], policy(), &mut WorkBudget::new(BUDGET))?;
    // x=64 is outside the first 64-pixel window but supplies its last gradient.
    assert_eq!(scan.windows()[0].disposition, WindowDisposition::Unobservable); Ok(())
}
#[test]
fn below_threshold_is_distinct_from_masked_and_small_grid() -> Test {
    let pixels = vec![100; 64 * 128]; let mask = vec![1; pixels.len()];
    let scan = scan_hog(source(&pixels, [64, 128]), &pixels, &mask, &model(0.5)?,
        &[ScanLevel { dimensions: [64, 128] }, ScanLevel { dimensions: [32, 64] }], policy(), &mut WorkBudget::new(BUDGET))?;
    assert_eq!(scan.windows().len(), 1); assert_eq!(scan.windows()[0].margin, Some(0.5));
    assert_eq!(scan.windows()[0].disposition, WindowDisposition::BelowThreshold);
    assert_eq!(scan.levels()[1].windows, 0); Ok(())
}
#[test]
fn complete_window_and_presuppression_limits_refuse_instead_of_top_k() -> Test {
    let pixels = vec![100; 80 * 136]; let mask = vec![1; pixels.len()]; let model = model(1.0)?;
    let levels = [ScanLevel { dimensions: [80, 136] }];
    for p in [ScanPolicy { maximum_windows: 5, ..policy() }, ScanPolicy { maximum_candidates: 1, ..policy() }] {
        assert!(matches!(scan_hog(source(&pixels, [80, 136]), &pixels, &mask, &model,
            &levels, p, &mut WorkBudget::new(BUDGET)), Err(HogError::Limit)));
    }
    Ok(())
}
#[test]
fn duplicate_grids_invalid_policy_and_forged_source_are_rejected() -> Test {
    let pixels = vec![100; 64 * 128]; let mask = vec![1; pixels.len()]; let model = model(1.0)?;
    let level = ScanLevel { dimensions: [64, 128] }; let src = source(&pixels, level.dimensions);
    assert!(matches!(scan_hog(src, &pixels, &mask, &model, &[level, level], policy(), &mut WorkBudget::new(BUDGET)), Err(HogError::InvalidInput)));
    for p in [ScanPolicy { minimum_margin: f64::NAN, ..policy() }, ScanPolicy { stride: [1, 8], ..policy() },
        ScanPolicy { suppression_iou_ppm: 0, ..policy() }] {
        assert!(matches!(scan_hog(src, &pixels, &mask, &model, &[level], p, &mut WorkBudget::new(BUDGET)), Err(HogError::InvalidInput)));
    }
    let mut bad = src; bad.image.pixels = [8; 32];
    assert!(matches!(scan_hog(bad, &pixels, &mask, &model, &[level], policy(), &mut WorkBudget::new(BUDGET)), Err(HogError::DigestMismatch))); Ok(())
}
#[test]
fn cancellation_budget_refusal_and_exact_retry_preserve_complete_identity() -> Test {
    let pixels = vec![100; 64 * 128]; let mask = vec![1; pixels.len()]; let model = model(1.0)?;
    let level = ScanLevel { dimensions: [64, 128] }; let src = source(&pixels, level.dimensions);
    let mut budget = WorkBudget::new(BUDGET);
    let expected = scan_hog(src, &pixels, &mask, &model, &[level], policy(), &mut budget)?;
    for limit in [0, 1, 100, 10_000, budget.used() - 1] {
        assert!(matches!(scan_hog(src, &pixels, &mask, &model, &[level], policy(), &mut WorkBudget::new(limit)), Err(HogError::Work(GeometryError::BudgetExhausted))));
    }
    let cancelled = AtomicBool::new(true);
    assert!(matches!(scan_hog(src, &pixels, &mask, &model, &[level], policy(),
        &mut WorkBudget::cancellable(BUDGET, &cancelled)), Err(HogError::Work(GeometryError::Cancelled))));
    let repeated = scan_hog(src, &pixels, &mask, &model, &[level], policy(), &mut WorkBudget::new(BUDGET))?;
    assert_eq!(expected.digest(), repeated.digest()); Ok(())
}
#[test]
fn generation_changes_with_weights_threshold_and_grid_but_not_frame_pixels() -> Test {
    let pixels = vec![100; 64 * 128]; let mask = vec![1; pixels.len()]; let src = source(&pixels, [64, 128]);
    let levels = [ScanLevel { dimensions: [64, 128] }];
    let a = scan_hog(src, &pixels, &mask, &model(1.0)?, &levels, policy(), &mut WorkBudget::new(BUDGET))?;
    let b = scan_hog(src, &pixels, &mask, &model(2.0)?, &levels, policy(), &mut WorkBudget::new(BUDGET))?;
    let c = scan_hog(src, &pixels, &mask, &model(1.0)?, &levels, ScanPolicy { minimum_margin: 2.0, ..policy() }, &mut WorkBudget::new(BUDGET))?;
    assert_ne!(a.generation(), b.generation()); assert_ne!(a.generation(), c.generation());
    let other = vec![99; pixels.len()];
    let d = scan_hog(source(&other, [64, 128]), &other, &mask, &model(1.0)?, &levels, policy(), &mut WorkBudget::new(BUDGET))?;
    assert_eq!(a.generation(), d.generation()); assert_ne!(a.digest(), d.digest()); Ok(())
}
