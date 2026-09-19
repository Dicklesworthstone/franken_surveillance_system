#![forbid(unsafe_code)]
//! Rectification contract contract tests.

use fss_core::ContentDigest;
use fss_geometry::{GeometryError, PinholeIntrinsics, WorkBudget};
use fss_twin::rectification::*;
use std::error::Error;
use std::sync::atomic::AtomicBool;

type Test = Result<(), Box<dyn Error>>;

fn spec(width: u32, height: u32) -> Result<RectificationSpec, Box<dyn Error>> {
    let camera = PinholeIntrinsics::new(width, height, 5.0, 5.0,
        f64::from(width)/2.0, f64::from(height)/2.0)?;
    Ok(RectificationSpec { source: camera, target: camera, distortion: LensDistortion::Pinhole,
        maximum_radius: 2.0, source_domain: [3; 32], calibration: [4; 32], range: LumaRange::Full })
}
fn identity(s: RectificationSpec, bytes: &[u8], mask: &[u8], stride: u32) -> RawFrameIdentity {
    RawFrameIdentity { exposure: [7; 32], storage: ContentDigest::sha256(bytes).bytes(),
        allowed_mask: ContentDigest::sha256(mask).bytes(), image_domain: s.source_domain,
        calibration: s.calibration, dimensions: s.source.dimensions(), row_stride: stride, range: s.range }
}
fn hex(bytes: [u8; 32]) -> String { bytes.iter().map(|x| format!("{x:02x}")).collect() }

#[test]
fn identity_is_exact_at_every_center_including_borders() -> Test {
    let s = spec(9,7)?;
    let pixels: Vec<u8> = (0..63).map(|n| (n*3) as u8).collect();
    let mask = vec![1;63];
    let mut budget = WorkBudget::new(1_000_000);
    let plan = RectificationPlan::compile(s,&mut budget)?;
    for y in 0..7 { for x in 0..9 {
        assert_eq!(plan.sampling_position(x,y)?,Some([f64::from(x)+0.5,f64::from(y)+0.5]));
    }}
    let raw = RawGrayFrame::new(identity(s,&pixels,&mask,9),&pixels,&mask,&mut budget)?;
    let output = plan.apply(&raw,&mut budget)?;
    assert_eq!(output.pixels(),pixels); assert_eq!(output.allowed(),mask);
    assert_eq!(output.identity().exposure,raw.identity().exposure);
    assert_eq!(output.receipt().allowed_pixels,63);
    assert_eq!(output.as_gray_image(&mut budget)?.identity(),output.identity());
    Ok(())
}

#[test]
fn brown_and_fisheye_maps_match_independent_opencv_goldens() -> Test {
    let mut s = spec(9,7)?;
    let mut budget = WorkBudget::new(2_000_000);
    s.distortion = LensDistortion::BrownConrady { radial: [0.04,0.002,0.0001], tangential: [0.003,-0.002] };
    let brown = RectificationPlan::compile(s,&mut budget)?;
    assert_eq!(hex(brown.map_digest()),"7605020b6cb5d4962b937fe94b3590bbe1f11ab06be8063c87fafca6cd783ba0");
    s.distortion = LensDistortion::Fisheye { coefficients: [0.01,-0.0001,0.00001,0.0] };
    let fish = RectificationPlan::compile(s,&mut budget)?;
    assert_eq!(hex(fish.map_digest()),"3fd8619dc9ce9a66ac93cdbb30e70d07019736eeca10b015571114986a99a780");
    assert_eq!(brown.source_pixel([4.5,3.5])?,Some([4.5,3.5]));
    assert_eq!(fish.source_pixel([4.5,3.5])?,Some([4.5,3.5]));
    Ok(())
}

#[test]
fn zero_fisheye_coefficients_do_not_mean_pinhole() -> Test {
    let mut s=spec(9,7)?; let mut budget=WorkBudget::new(1_000_000);
    let pinhole=RectificationPlan::compile(s,&mut budget)?;
    s.distortion=LensDistortion::Fisheye{coefficients:[0.0;4]};
    let fish=RectificationPlan::compile(s,&mut budget)?;
    assert_ne!(fish.source_pixel([8.5,3.5])?,pinhole.source_pixel([8.5,3.5])?);
    assert_ne!(fish.map_digest(),pinhole.map_digest());
    Ok(())
}

#[test]
fn masked_contributors_cannot_affect_any_exposed_output() -> Test {
    let mut s=spec(4,3)?;
    s.target=PinholeIntrinsics::new(3,2,5.0,5.0,1.75,1.0)?;
    let mut budget=WorkBudget::new(1_000_000);
    let plan=RectificationPlan::compile(s,&mut budget)?;
    let mut first=vec![40;12]; let mut second=first.clone();
    first[5]=0; second[5]=255;
    let mut mask=vec![1;12]; mask[5]=0;
    let a=RawGrayFrame::new(identity(s,&first,&mask,4),&first,&mask,&mut budget)?;
    let b=RawGrayFrame::new(identity(s,&second,&mask,4),&second,&mask,&mut budget)?;
    let a=plan.apply(&a,&mut budget)?; let b=plan.apply(&b,&mut budget)?;
    assert_eq!(a.pixels(),b.pixels()); assert_eq!(a.allowed(),b.allowed());
    assert_eq!(a.allowed()[0],0); assert_eq!(a.pixels()[0],0);
    assert!(a.receipt().privacy_rejected>0);
    assert_eq!(a.receipt().allowed_pixels+a.receipt().privacy_rejected,plan.coverage().mapped);
    assert_ne!(a.receipt().source.storage,b.receipt().source.storage);
    assert_eq!(a.identity().pixels,b.identity().pixels);
    Ok(())
}

#[test]
fn zero_weight_neighbors_do_not_expand_a_mask_in_identity_mode() -> Test {
    let s=spec(3,3)?; let pixels=vec![97;9]; let mut mask=vec![1;9]; mask[4]=0;
    let mut budget=WorkBudget::new(1_000_000);
    let plan=RectificationPlan::compile(s,&mut budget)?;
    let raw=RawGrayFrame::new(identity(s,&pixels,&mask,3),&pixels,&mask,&mut budget)?;
    let image=plan.apply(&raw,&mut budget)?;
    assert_eq!(image.allowed(),mask);assert_eq!(image.receipt().privacy_rejected,1);
    assert_eq!(image.pixels(),[97,97,97,97,0,97,97,97,97]);
    Ok(())
}

#[test]
fn bilinear_interpolation_has_independent_integer_values() -> Test {
    let mut s=spec(2,2)?;
    s.target=PinholeIntrinsics::new(1,1,5.0,5.0,0.75,0.5)?;
    let pixels=[0,100,200,240];let mask=[1;4];let mut budget=WorkBudget::new(1_000_000);
    let plan=RectificationPlan::compile(s,&mut budget)?;
    assert_eq!(plan.sampling_position(0,0)?,Some([0.75,1.0]));
    let raw=RawGrayFrame::new(identity(s,&pixels,&mask,2),&pixels,&mask,&mut budget)?;
    let output=plan.apply(&raw,&mut budget)?;
    assert_eq!(output.pixels(),[118]);
    Ok(())
}

#[test]
fn crop_resize_and_outside_samples_never_replicate_border_values() -> Test {
    let mut s=spec(3,3)?;s.target=PinholeIntrinsics::new(5,5,5.0,5.0,2.5,2.5)?;
    let pixels=vec![255;9];let mask=vec![1;9];let mut budget=WorkBudget::new(1_000_000);
    let plan=RectificationPlan::compile(s,&mut budget)?;
    assert_eq!(plan.coverage().mapped,9);assert_eq!(plan.coverage().outside_source,16);
    let raw=RawGrayFrame::new(identity(s,&pixels,&mask,3),&pixels,&mask,&mut budget)?;
    let output=plan.apply(&raw,&mut budget)?;
    for y in 0..5 {for x in 0..5 {
        let valid=x>0 && x<4 && y>0 && y<4;
        assert_eq!(output.allowed()[y*5+x],u8::from(valid));
        assert_eq!(output.pixels()[y*5+x],if valid {255} else {0});
    }}
    s=spec(3,3)?;s.maximum_radius=0.01;
    let small=RectificationPlan::compile(s,&mut budget)?;
    assert_eq!(small.coverage().mapped,1);assert_eq!(small.coverage().outside_lens_domain,8);
    Ok(())
}

#[test]
fn explicit_row_padding_is_not_image_content() -> Test {
    let s=spec(2,2)?;let pixels=[10,20,250,249,30,40,248,247];let mask=[1;4];
    let mut budget=WorkBudget::new(1_000_000);let plan=RectificationPlan::compile(s,&mut budget)?;
    let raw=RawGrayFrame::new(identity(s,&pixels,&mask,4),&pixels,&mask,&mut budget)?;
    assert_eq!(plan.apply(&raw,&mut budget)?.pixels(),[10,20,30,40]);
    Ok(())
}

#[test]
fn video_luma_range_is_explicit_and_bound_to_image_domain() -> Test {
    let mut s=spec(6,1)?;let pixels=[0,16,17,125,235,255];let mask=[1;6];
    let mut budget=WorkBudget::new(1_000_000);let full=RectificationPlan::compile(s,&mut budget)?;
    s.range=LumaRange::Video;let video=RectificationPlan::compile(s,&mut budget)?;
    let raw=RawGrayFrame::new(identity(s,&pixels,&mask,6),&pixels,&mask,&mut budget)?;
    assert_eq!(video.apply(&raw,&mut budget)?.pixels(),[0,0,1,127,255,255]);
    assert_eq!(full.map_digest(),video.map_digest());
    assert_ne!(full.output_domain(),video.output_domain());
    assert!(matches!(full.apply(&raw,&mut budget),Err(RectificationError::BasisMismatch)));
    Ok(())
}

#[test]
fn stale_calibration_and_source_domains_cannot_reuse_a_map() -> Test {
    let s=spec(3,3)?;let pixels=[127;9];let mask=[1;9];let mut budget=WorkBudget::new(1_000_000);
    let plan=RectificationPlan::compile(s,&mut budget)?;
    for is_calibration in [false,true] {
        let mut id=identity(s,&pixels,&mask,3);
        if is_calibration {id.calibration=[8;32];} else {id.image_domain=[8;32];}
        let raw=RawGrayFrame::new(id,&pixels,&mask,&mut budget)?;
        assert!(matches!(plan.apply(&raw,&mut budget),Err(RectificationError::BasisMismatch)));
    }
    let mut changed=s;changed.calibration=[8;32];
    let another=RectificationPlan::compile(changed,&mut budget)?;
    assert_eq!(plan.map_digest(),another.map_digest());assert_ne!(plan.output_domain(),another.output_domain());
    Ok(())
}

#[test]
fn malformed_masks_storage_and_dimensions_fail_before_output() -> Test {
    let s=spec(3,3)?;let pixels=[127;9];let mask=[1;9];let mut budget=WorkBudget::new(1_000_000);
    let mut id=identity(s,&pixels,&mask,3);id.storage=[1;32];
    assert!(matches!(RawGrayFrame::new(id,&pixels,&mask,&mut budget),Err(RectificationError::BasisMismatch)));
    let mut bad=mask;bad[8]=2;
    assert!(matches!(RawGrayFrame::new(identity(s,&pixels,&bad,3),&pixels,&bad,&mut budget),Err(RectificationError::InvalidInput)));
    assert!(matches!(RawGrayFrame::new(identity(s,&pixels,&mask,4),&pixels,&mask,&mut budget),Err(RectificationError::InvalidInput)));
    let mut id=identity(s,&pixels,&mask,3);id.dimensions=[4097,1];
    assert!(matches!(RawGrayFrame::new(id,&pixels,&mask,&mut budget),Err(RectificationError::Limit)));
    Ok(())
}

#[test]
fn folded_and_nonfinite_lens_models_are_not_accepted() -> Test {
    let mut s=spec(9,7)?;s.maximum_radius=1.0;let mut budget=WorkBudget::new(1_000_000);
    for distortion in [LensDistortion::BrownConrady{radial:[-1.0,0.0,0.0],tangential:[0.0;2]},
        LensDistortion::BrownConrady{radial:[0.0;3],tangential:[1.0,0.0]},
        LensDistortion::Fisheye{coefficients:[-1.0,0.0,0.0,0.0]}] {
        s.distortion=distortion;
        assert!(matches!(RectificationPlan::compile(s,&mut budget),Err(RectificationError::NonInvertibleModel)));
    }
    s.distortion=LensDistortion::Fisheye{coefficients:[f64::NAN,0.0,0.0,0.0]};
    assert!(matches!(RectificationPlan::compile(s,&mut budget),Err(RectificationError::InvalidModel)));
    Ok(())
}

#[test]
fn budget_and_cancellation_leave_source_and_compiled_plan_reusable() -> Test {
    let s=spec(9,7)?;let pixels=[127;63];let mask=[1;63];let mut budget=WorkBudget::new(1_000_000);
    assert!(matches!(RectificationPlan::compile(s,&mut WorkBudget::new(0)),
        Err(RectificationError::Geometry(GeometryError::BudgetExhausted))));
    let plan=RectificationPlan::compile(s,&mut budget)?;
    let raw=RawGrayFrame::new(identity(s,&pixels,&mask,9),&pixels,&mask,&mut budget)?;
    let cancelled=AtomicBool::new(true);
    assert!(matches!(plan.apply(&raw,&mut WorkBudget::cancellable(1_000_000,&cancelled)),
        Err(RectificationError::Geometry(GeometryError::Cancelled))));
    assert!(matches!(plan.apply(&raw,&mut WorkBudget::new(126)),
        Err(RectificationError::Geometry(GeometryError::BudgetExhausted))));
    assert_eq!(plan.apply(&raw,&mut budget)?.pixels(),pixels);
    Ok(())
}
