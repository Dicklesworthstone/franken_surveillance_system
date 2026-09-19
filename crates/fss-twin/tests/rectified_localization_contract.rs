#![forbid(unsafe_code)]
//! Rectified-image localization contracts through the twin localization pipeline.
mod common;

use std::{error::Error, sync::atomic::AtomicBool};
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, PinholeIntrinsics, PoseSolverOptions, WorkBudget};
use fss_twin::PropertyTwin;
use fss_twin::localization::*;
use fss_twin::localization::native::*;
use fss_twin::rectification::*;

type Test = Result<(), Box<dyn Error>>;
const RAW: &[u8] = include_bytes!("fixtures/brown_luma_96x96.gray");
const CORRECTED_HASH: &str = "7e31c6e153dded00386436ef3b1bdc98dba5a8dd9049c3fb65bb6ce68bd20e98";

fn texture() -> Vec<u8> {
    let mut state = 1973_u32;
    (0..96*96).map(|_| {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        20 + ((state >> 16) % 180) as u8
    }).collect()
}
fn setup(budget: &mut WorkBudget<'_>) -> Result<(PropertyTwin, LocalizationAtlas, RectificationSpec), Box<dyn Error>> {
    let twin = common::twin(&[0.0], None)?;
    let pixels = texture(); let mask = vec![1; pixels.len()];
    let reference = GrayImage::new(ImageIdentity { exposure: [1;32],
        pixels: ContentDigest::sha256(&pixels).bytes(), image_domain: [9;32], dimensions: [96,96] },
        &pixels, &mask, budget)?;
    let frame = extract_gray(&reference, options().extraction, budget)?.frame;
    let mut landmarks = Vec::new(); let mut bindings = Vec::new();
    for (i, point) in frame.features().iter().enumerate() {
        let depth = 6.0 + (i%7) as f64 * 0.5;
        landmarks.push(AtlasLandmark { id: i as u64+1, physical_group: i as u64+1, feature: 0,
            world: [(point.pixel[0]-48.0)*depth/80.0, (point.pixel[1]-48.0)*depth/80.0, depth],
            evidence: [8;32], error: None });
        bindings.push(AtlasBinding { landmark: i as u64+1, reference: 1, image_feature: point.id });
    }
    let atlas = LocalizationAtlas::new(&twin, landmarks, vec![AtlasReference { id: 1, frame }], bindings, budget)?;
    let camera = PinholeIntrinsics::new(96,96,80.0,80.0,48.0,48.0)?;
    let spec = RectificationSpec { source: camera, target: camera,
        distortion: LensDistortion::BrownConrady { radial: [-0.1,0.001,0.0001], tangential: [0.001,-0.001] },
        maximum_radius: 1.0, source_domain: [3;32], calibration: [4;32], range: LumaRange::Full };
    Ok((twin,atlas,spec))
}
fn options() -> ImageLocalizationOptions {
    ImageLocalizationOptions { extraction: ExtractionOptions { maximum_features:200, ..ExtractionOptions::default() },
        matching: MatchOptions::default(), solving: PoseSolverOptions { ransac_trials:0, ..PoseSolverOptions::default() } }
}
fn source<'a>(spec: RectificationSpec, exposure: u8, pixels: &'a [u8], mask: &'a [u8], budget: &mut WorkBudget<'_>)
    -> Result<RawGrayFrame<'a>, RectificationError> {
    RawGrayFrame::new(RawFrameIdentity { exposure: [exposure;32], storage: ContentDigest::sha256(pixels).bytes(),
        allowed_mask: ContentDigest::sha256(mask).bytes(), image_domain: spec.source_domain,
        calibration: spec.calibration, dimensions: [96,96], row_stride:96, range:spec.range }, pixels, mask, budget)
}
fn check_pose(result: &ImageLocalization) -> Test {
    assert!(result.localization.matches.correspondences.len() >= 8);
    let LocalizationOutcome::Candidates(search) = &result.localization.outcome else {
        return Err("distorted fixture did not produce a pose".into());
    };
    assert_eq!(search.candidates().len(),1);
    let candidate = &search.candidates()[0];
    assert!(candidate.rms_px() < 1e-4);
    assert!(candidate.pose().center().iter().all(|value| value.abs() < 1e-4));
    let identity = [[1.0,0.0,0.0],[0.0,1.0,0.0],[0.0,0.0,1.0]];
    for (actual,expected) in candidate.pose().rotation().iter().flatten().zip(identity.iter().flatten()) {
        assert!((actual-expected).abs() < 1e-4);
    }
    Ok(())
}

#[test]
fn independent_distorted_fixture_flows_through_rectification_matching_and_pose() -> Test {
    let mut budget = WorkBudget::new(2_000_000_000);
    let (twin,atlas,spec) = setup(&mut budget)?; let mask = vec![1;RAW.len()];
    let raw = source(spec,2,RAW,&mask,&mut budget)?;
    let plan = RectificationPlan::compile(spec,&mut budget)?;
    let expected = ContentDigest::parse(format!("sha256:{CORRECTED_HASH}"))?.bytes();
    assert_eq!(plan.apply(&raw,&mut budget)?.identity().pixels, expected);
    let localized = localize_raw_frame(&atlas,&twin,&plan,&raw,options(),&mut budget)?;
    assert_eq!(localized.rectification.output.pixels,expected);
    assert_eq!(localized.rectification.output.exposure,raw.identity().exposure);
    assert_eq!(localized.result.localization.matches.query,localized.rectification.output);
    assert_eq!(localized.rectification.allowed_pixels,9216);
    assert!(localized.result.localization.matches.correspondences.len() >= 16);
    check_pose(&localized.result)
}

#[test]
fn cropped_target_intrinsics_are_used_instead_of_raw_camera_intrinsics() -> Test {
    let mut budget = WorkBudget::new(2_000_000_000);
    let (twin,atlas,mut spec) = setup(&mut budget)?;let mask=vec![1;RAW.len()];
    spec.target=PinholeIntrinsics::new(80,80,80.0,80.0,40.0,40.0)?;
    let raw=source(spec,2,RAW,&mask,&mut budget)?;let plan=RectificationPlan::compile(spec,&mut budget)?;
    let localized=localize_raw_frame(&atlas,&twin,&plan,&raw,options(),&mut budget)?;
    assert_eq!(localized.rectification.output.dimensions,[80,80]);
    assert_eq!(localized.result.localization.matches.query.image_domain,plan.output_domain());
    check_pose(&localized.result)
}

#[test]
fn rectification_does_not_launder_a_reference_exposure() -> Test {
    let mut budget=WorkBudget::new(1_000_000_000);
    let (twin,atlas,spec)=setup(&mut budget)?;let mask=vec![1;RAW.len()];
    let plan=RectificationPlan::compile(spec,&mut budget)?;
    // Same source exposure, but distorted pixels and a different image domain.
    let raw=source(spec,1,RAW,&mask,&mut budget)?;
    assert!(matches!(localize_raw_frame(&atlas,&twin,&plan,&raw,options(),&mut WorkBudget::new(1)),
        Err(RawLocalizationError::Localization(LocalizationError::ReferenceExposure))));
    Ok(())
}

#[test]
fn fully_masked_or_blank_source_remains_unlocalized() -> Test {
    let mut budget=WorkBudget::new(2_000_000_000);
    let (twin,atlas,spec)=setup(&mut budget)?;let allowed=vec![1;RAW.len()];let denied=vec![0;RAW.len()];
    let blank=vec![100;RAW.len()];let plan=RectificationPlan::compile(spec,&mut budget)?;
    for (pixels,mask) in [(RAW,denied.as_slice()),(blank.as_slice(),allowed.as_slice())] {
        let raw=source(spec,2,pixels,mask,&mut budget)?;
        let localized=localize_raw_frame(&atlas,&twin,&plan,&raw,options(),&mut budget)?;
        assert_eq!(localized.result.selection.selected,0);
        assert!(matches!(localized.result.localization.outcome,LocalizationOutcome::InsufficientMatches));
        if mask==denied.as_slice() {assert_eq!(localized.rectification.allowed_pixels,0);}
    }
    Ok(())
}

#[test]
fn stale_source_or_twin_is_not_processed_as_current() -> Test {
    let mut budget=WorkBudget::new(1_000_000_000);
    let (twin,atlas,spec)=setup(&mut budget)?;let mask=vec![1;RAW.len()];
    let mut changed=spec;changed.calibration=[5;32];
    let raw=source(changed,2,RAW,&mask,&mut budget)?;let plan=RectificationPlan::compile(spec,&mut budget)?;
    assert!(matches!(localize_raw_frame(&atlas,&twin,&plan,&raw,options(),&mut budget),
        Err(RawLocalizationError::Rectification(RectificationError::BasisMismatch))));
    let changed_twin=common::twin(&[1.0],None)?;
    assert!(matches!(localize_raw_frame(&atlas,&changed_twin,&plan,&raw,options(),&mut budget),
        Err(RawLocalizationError::Localization(LocalizationError::BasisMismatch))));
    Ok(())
}

#[test]
fn failed_composition_leaves_inputs_reusable_and_publishes_no_result() -> Test {
    let mut budget=WorkBudget::new(2_000_000_000);
    let (twin,atlas,spec)=setup(&mut budget)?;let mask=vec![1;RAW.len()];
    let raw=source(spec,2,RAW,&mask,&mut budget)?;let plan=RectificationPlan::compile(spec,&mut budget)?;
    // Enough for rectification but not feature extraction. No successful prefix escapes.
    assert!(localize_raw_frame(&atlas,&twin,&plan,&raw,options(),&mut WorkBudget::new(400_000)).is_err());
    let flag=AtomicBool::new(true);
    assert!(matches!(localize_raw_frame(&atlas,&twin,&plan,&raw,options(),&mut WorkBudget::cancellable(2_000_000_000,&flag)),
        Err(RawLocalizationError::Rectification(RectificationError::Geometry(GeometryError::Cancelled)))));
    let localized=localize_raw_frame(&atlas,&twin,&plan,&raw,options(),&mut budget)?;
    check_pose(&localized.result)
}
