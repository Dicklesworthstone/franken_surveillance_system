#![forbid(unsafe_code)]
//! Real pretrained coefficients; procedural images test arithmetic, not detector quality.
use std::error::Error;
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_twin::foreground::ForegroundSource;
use fss_twin::hog::{HogError, HogFrame, HogLevel, HogModel, HOG_PARAMETERS, hog_recipe_digest};
use fss_twin::hog_scan::{ScanLevel, ScanPolicy, scan_hog};
use fss_twin::localization::ImageIdentity;
use fss_twin::pretrained_hog::*;

type Test = Result<(), Box<dyn Error>>;
const WORK: u64 = 100_000_000;
fn image(k: u32) -> Vec<u8> {
    (0..128).flat_map(|y| (0..64).map(move |x| {
        (match k {
            0 => 0, 1 => 255, 2 => x * 4, 3 => y * 2,
            4 => ((x / 8 + y / 8) % 2) * 255,
            _ => (x * (17 + k * 2) + y * (31 + k * 3) + (x * y) % (13 + k * 5)) % 256,
        }) as u8
    })).collect()
}
fn source(pixels: &[u8]) -> ForegroundSource {
    ForegroundSource { image: ImageIdentity { exposure: [1;32],
        pixels: ContentDigest::sha256(pixels).bytes(), image_domain: [2;32], dimensions: [64,128] },
        camera: 1, calibration: [3;32], clock: 1, capture: [4,6] }
}
#[test]
fn unchanged_trained_assets_and_model_generation_are_pinned() -> Test {
    assert_eq!(opencv_people_weights().len(), HOG_PARAMETERS * 4);
    assert_eq!(ContentDigest::sha256(opencv_people_weights()).bytes(), OPENCV_PEOPLE_WEIGHTS_SHA256);
    assert_eq!(ContentDigest::sha256(opencv_people_provenance().as_bytes()).bytes(), OPENCV_PEOPLE_PROVENANCE_SHA256);
    assert_eq!(ContentDigest::sha256(opencv_people_license().as_bytes()).bytes(), OPENCV_PEOPLE_LICENSE_SHA256);
    assert_eq!(hog_recipe_digest(), OPENCV_PEOPLE_RECIPE_SHA256);
    let model = load_opencv_people_candidate(&mut WorkBudget::new(WORK))?;
    assert_eq!(model.weights_digest(), OPENCV_PEOPLE_WEIGHTS_SHA256);
    assert_eq!(model.provenance(), OPENCV_PEOPLE_PROVENANCE_SHA256);
    let expected = [0xf7,0x5b,0x82,0xd4,0x53,0x2b,0x05,0x36,0x5b,0x77,0xb7,0x8a,0xe2,0xb4,0xce,0x58,
        0xfe,0xf8,0x53,0xa3,0xf4,0xdd,0x57,0x5b,0x81,0x66,0x16,0x79,0x46,0x84,0xa7,0xe6];
    assert_eq!(model.digest(), expected);
    Ok(())
}
#[test]
fn real_trained_margins_match_retained_procedural_numeric_examples() -> Test {
    // Native values: independent Python scalar-recipe mirror. Oracle: cv2 4.13.0 CPU.
    // Tolerances apply ONLY to these ten fixtures, not an arbitrary-image guarantee.
    let expected = [(-6.6657915115356445,-6.6657915115356445),
        (-6.6657915115356445,-6.6657915115356445),(-3.8759877860091767,-3.8759877860091767),
        (-5.5279403317694005,-5.5279403317694005),(-4.45516621963684,-4.453545276177976),
        (-4.579090416443567,-4.578850730765833),(-4.387786588320922,-4.387497959530209),
        (-4.392289084759522,-4.392013219118344),(-4.244129512657451,-4.243925858567829),
        (-3.9917389524622355,-3.991523228126974)];
    let model = load_opencv_people_candidate(&mut WorkBudget::new(WORK))?;
    for (k, (native, oracle)) in expected.into_iter().enumerate() {
        let pixels = image(k as u32); let allowed = vec![1;pixels.len()];
        let mut budget = WorkBudget::new(WORK);
        let frame = HogFrame::new(source(&pixels), &pixels, &allowed, &mut budget)?;
        let level = HogLevel::compute(&frame, &mut budget)?;
        let margin = level.score(&model, [0,0], &mut budget)?.ok_or("unexpected denied window")?;
        assert!((margin-native).abs() < 0.000002, "native fixture {k}: {margin}");
        assert!((margin-oracle).abs() < 0.003, "oracle fixture {k}: {margin}");
    }
    Ok(())
}
#[test]
fn trained_model_does_not_convert_private_pixels_into_negative_detections() -> Test {
    let pixels = image(5); let mut allowed = vec![1;pixels.len()]; allowed[100] = 0;
    let mut budget = WorkBudget::new(WORK);
    let model = load_opencv_people_candidate(&mut budget)?;
    let frame = HogFrame::new(source(&pixels), &pixels, &allowed, &mut budget)?;
    let level = HogLevel::compute(&frame, &mut budget)?;
    assert_eq!(level.score(&model, [0,0], &mut budget)?, None);
    Ok(())
}
#[test]
fn actual_model_scans_keep_scores_below_policy_threshold() -> Test {
    let pixels = image(2); let allowed = vec![1;pixels.len()]; let mut budget = WorkBudget::new(WORK);
    let model = load_opencv_people_candidate(&mut budget)?;
    let scan = scan_hog(source(&pixels), &pixels, &allowed, &model,
        &[ScanLevel { dimensions: [64,128] }, ScanLevel { dimensions: [32,64] }],
        ScanPolicy { stride: [8,8], minimum_margin: 0.0, suppression_iou_ppm: 500_000,
            maximum_windows: 16, maximum_candidates: 16 }, &mut budget)?;
    assert_eq!(scan.windows().len(), 1); assert_eq!(scan.selected().count(), 0);
    assert!((scan.windows()[0].margin.ok_or("missing actual score")? + 3.8759877860091767).abs() < 0.000002);
    assert_eq!(scan.levels()[1].windows, 0);
    Ok(())
}
#[test]
fn insufficient_work_never_publishes_a_partial_model_and_exact_retry_is_stable() -> Test {
    for limit in [0,1,100,10_000] {
        assert!(matches!(load_opencv_people_candidate(&mut WorkBudget::new(limit)), Err(HogError::Work(_))));
    }
    let a = load_opencv_people_candidate(&mut WorkBudget::new(WORK))?;
    let b = load_opencv_people_candidate(&mut WorkBudget::new(WORK))?;
    assert_eq!(a.digest(), b.digest());
    Ok(())
}
#[test]
fn normal_loader_rejects_mutated_pretrained_weights() -> Test {
    let mut bytes = opencv_people_weights().to_vec(); bytes[8] ^= 1;
    assert!(matches!(HogModel::from_f32_le(&bytes, OPENCV_PEOPLE_WEIGHTS_SHA256,
        OPENCV_PEOPLE_PROVENANCE_SHA256, &mut WorkBudget::new(WORK)), Err(HogError::DigestMismatch)));
    Ok(())
}
