#![forbid(unsafe_code)]
//! Fixed-recipe learned classifier, numerical oracle and privacy-footprint contracts.
use std::error::Error;
use std::sync::atomic::AtomicBool;
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, WorkBudget};
use fss_twin::foreground::ForegroundSource;
use fss_twin::hog::*;
use fss_twin::localization::ImageIdentity;

type Test = Result<(), Box<dyn Error>>;
fn budget() -> WorkBudget<'static> { WorkBudget::new(100_000_000) }
fn source(pixels: &[u8], dimensions: [u32; 2]) -> ForegroundSource {
    ForegroundSource { image: ImageIdentity { exposure: [1; 32],
        pixels: ContentDigest::sha256(pixels).bytes(), image_domain: [2; 32], dimensions },
        camera: 1, calibration: [3; 32], clock: 1, capture: [10, 10] }
}
fn texture(width: usize, height: usize) -> Vec<u8> {
    (0..height).flat_map(|y| (0..width).map(move |x| ((x * 17 + y * 29 + (x * y) % 251) % 256) as u8)).collect()
}
fn weights(bias: f32) -> Vec<u8> {
    let mut bytes = vec![0; HOG_PARAMETERS * 4];
    bytes[HOG_FEATURES * 4..].copy_from_slice(&bias.to_le_bytes());
    bytes
}
fn model(bytes: &[u8]) -> Result<HogModel, HogError> {
    HogModel::from_f32_le(bytes, ContentDigest::sha256(bytes).bytes(), [9; 32], &mut budget())
}

#[test]
fn descriptor_matches_retained_opencv_cpu_oracle_with_declared_tolerance() -> Test {
    // OpenCV 4.13.0 CPU HOGDescriptor, gamma=true, same whole-image border context.
    // Accurate f64 atan2 differs from OpenCV's fast angle approximation: tolerance,
    // not bit identity. The source image is generated here, not a third-party photo.
    let pixels = texture(80, 144); let allowed = vec![1; pixels.len()];
    let frame = HogFrame::new(source(&pixels, [80, 144]), &pixels, &allowed, &mut budget())?;
    let level = HogLevel::compute(&frame, &mut budget())?;
    let descriptor = level.descriptor([8, 8], &mut budget())?.ok_or("private descriptor")?;
    let oracle = [(0, 0.0), (1, 0.23236859), (8, 0.0), (9, 0.0), (17, 0.0),
        (35, 0.0), (36, 0.0), (107, 0.018602155), (539, 0.20640914),
        (540, 0.0008533759), (1234, 0.32865542), (2000, 0.005156574), (3779, 0.0)];
    for (index, expected) in oracle {
        assert!((descriptor[index] - expected).abs() < 0.0003, "feature {index}");
    }
    assert_eq!(level.source(), frame.source());
    assert_eq!(level.mask_digest(), frame.mask_digest());
    Ok(())
}

#[test]
fn constant_image_produces_zero_descriptor_and_exact_classifier_intercept() -> Test {
    let pixels = vec![73; 64 * 128]; let allowed = vec![1; pixels.len()];
    let frame = HogFrame::new(source(&pixels, [64, 128]), &pixels, &allowed, &mut budget())?;
    let level = HogLevel::compute(&frame, &mut budget())?;
    assert_eq!(level.descriptor([0, 0], &mut budget())?, Some([0.0; HOG_FEATURES]));
    assert_eq!(level.score(&model(&weights(-2.5))?, [0, 0], &mut budget())?, Some(-2.5));
    Ok(())
}

#[test]
fn classifier_really_uses_every_learned_feature_and_sign() -> Test {
    let pixels = texture(64, 128); let allowed = vec![1; pixels.len()];
    let frame = HogFrame::new(source(&pixels, [64, 128]), &pixels, &allowed, &mut budget())?;
    let level = HogLevel::compute(&frame, &mut budget())?;
    let descriptor = level.descriptor([0, 0], &mut budget())?.ok_or("missing descriptor")?;
    let mut bytes = weights(-0.25); let mut expected = -0.25_f64;
    for (i, feature) in descriptor.iter().enumerate() {
        let coefficient = (i as i32 % 13 - 6) as f32 * 0.01;
        bytes[i * 4..i * 4 + 4].copy_from_slice(&coefficient.to_le_bytes());
        expected += f64::from(*feature) * f64::from(coefficient);
    }
    let learned = model(&bytes)?;
    assert_eq!(level.score(&learned, [0, 0], &mut budget())?, Some(expected));
    assert_ne!(learned.digest(), model(&weights(-0.25))?.digest());
    Ok(())
}

#[test]
fn gradient_halo_denial_invalidates_window_even_outside_its_box() -> Test {
    let pixels = texture(80, 144); let mut allowed = vec![1; pixels.len()];
    // Window x=8..72; pixel x=7 is outside it but feeds its leftmost gradient.
    allowed[64 * 80 + 7] = 0;
    let frame = HogFrame::new(source(&pixels, [80, 144]), &pixels, &allowed, &mut budget())?;
    let level = HogLevel::compute(&frame, &mut budget())?;
    assert!(level.descriptor([8, 8], &mut budget())?.is_none());
    assert!(level.score(&model(&weights(1.0))?, [8, 8], &mut budget())?.is_none());
    Ok(())
}

#[test]
fn changing_denied_pixels_cannot_change_admitted_window_features() -> Test {
    let mut pixels = texture(80, 144); let mut allowed = vec![1; pixels.len()]; allowed[0] = 0;
    let frame = HogFrame::new(source(&pixels, [80, 144]), &pixels, &allowed, &mut budget())?;
    let before = HogLevel::compute(&frame, &mut budget())?.descriptor([8, 8], &mut budget())?;
    pixels[0] ^= 255;
    let frame = HogFrame::new(source(&pixels, [80, 144]), &pixels, &allowed, &mut budget())?;
    let after = HogLevel::compute(&frame, &mut budget())?.descriptor([8, 8], &mut budget())?;
    assert!(before.is_some()); assert_eq!(before, after);
    Ok(())
}

#[test]
fn all_private_image_is_unknown_even_with_strong_positive_intercept() -> Test {
    let pixels = texture(64, 128); let allowed = vec![0; pixels.len()];
    let frame = HogFrame::new(source(&pixels, [64, 128]), &pixels, &allowed, &mut budget())?;
    let level = HogLevel::compute(&frame, &mut budget())?;
    assert!(level.score(&model(&weights(1000.0))?, [0, 0], &mut budget())?.is_none());
    Ok(())
}

#[test]
fn source_and_mask_validation_fail_before_feature_computation() -> Test {
    let pixels = texture(64, 128); let mut allowed = vec![1; pixels.len()];
    let mut identity = source(&pixels, [64, 128]); identity.image.pixels = [8; 32];
    assert!(matches!(HogFrame::new(identity, &pixels, &allowed, &mut budget()), Err(HogError::DigestMismatch)));
    allowed[7] = 2;
    assert!(matches!(HogFrame::new(source(&pixels, [64, 128]), &pixels, &allowed, &mut budget()), Err(HogError::InvalidInput)));
    assert!(matches!(HogFrame::new(source(&pixels, [4096, 4096]), &pixels, &allowed, &mut budget()), Err(HogError::Limit)));
    Ok(())
}

#[test]
fn model_rejects_wrong_digest_nonfinite_truncated_and_trailing_coefficients() -> Test {
    let valid = weights(-1.0);
    assert!(matches!(HogModel::from_f32_le(&valid, [1; 32], [9; 32], &mut budget()), Err(HogError::DigestMismatch)));
    for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, 1_000_001.0] {
        let mut invalid = valid.clone(); invalid[..4].copy_from_slice(&value.to_le_bytes());
        assert!(matches!(model(&invalid), Err(HogError::InvalidWeight)));
    }
    assert!(matches!(model(&valid[..valid.len() - 1]), Err(HogError::InvalidInput)));
    let mut longer = valid.clone(); longer.push(0);
    assert!(matches!(model(&longer), Err(HogError::InvalidInput)));
    let other = HogModel::from_f32_le(&valid, ContentDigest::sha256(&valid).bytes(), [10; 32], &mut budget())?;
    assert_ne!(other.digest(), model(&valid)?.digest());
    Ok(())
}

#[test]
fn unaligned_or_out_of_image_windows_are_not_implicitly_clamped() -> Test {
    let pixels = texture(64, 128); let allowed = vec![1; pixels.len()];
    let frame = HogFrame::new(source(&pixels, [64, 128]), &pixels, &allowed, &mut budget())?;
    let level = HogLevel::compute(&frame, &mut budget())?;
    for origin in [[1, 0], [0, 1], [8, 0], [0, 8], [u32::MAX, u32::MAX]] {
        assert!(matches!(level.descriptor(origin, &mut budget()), Err(HogError::InvalidInput)));
    }
    let pixels = vec![0; 8]; let allowed = vec![1; 8];
    let frame = HogFrame::new(source(&pixels, [1, 8]), &pixels, &allowed, &mut budget())?;
    let small = HogLevel::compute(&frame, &mut budget())?;
    assert!(matches!(small.descriptor([0, 0], &mut budget()), Err(HogError::InvalidInput)));
    Ok(())
}

#[test]
fn budget_and_cancellation_refuse_complete_work_without_rewriting_inputs() -> Test {
    let pixels = texture(64, 128); let allowed = vec![1; pixels.len()];
    let frame = HogFrame::new(source(&pixels, [64, 128]), &pixels, &allowed, &mut budget())?;
    let mut complete = budget(); let level = HogLevel::compute(&frame, &mut complete)?;
    let used = complete.used();
    for limit in [0, 1, 8192, 65536, used - 1] {
        assert!(matches!(HogLevel::compute(&frame, &mut WorkBudget::new(limit)), Err(HogError::Work(GeometryError::BudgetExhausted))));
    }
    let cancelled = AtomicBool::new(true);
    assert!(matches!(HogLevel::compute(&frame, &mut WorkBudget::cancellable(used, &cancelled)), Err(HogError::Work(GeometryError::Cancelled))));
    assert_eq!(frame.source().image.pixels, ContentDigest::sha256(&pixels).bytes());
    let model = model(&weights(1.0))?;
    let mut score_budget = budget(); let expected = level.score(&model, [0, 0], &mut score_budget)?;
    assert!(matches!(level.score(&model, [0, 0], &mut WorkBudget::new(score_budget.used() - 1)), Err(HogError::Work(GeometryError::BudgetExhausted))));
    assert_eq!(level.score(&model, [0, 0], &mut budget())?, expected);
    Ok(())
}
