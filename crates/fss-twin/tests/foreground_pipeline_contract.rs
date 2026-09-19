#![forbid(unsafe_code)]
//! Foreground pipeline contract contract tests.
use std::error::Error;
use std::sync::atomic::AtomicBool;
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, PinholeIntrinsics, WorkBudget};
use fss_twin::foreground::*;
use fss_twin::foreground::pipeline::*;
use fss_twin::rectification::*;

type Test = Result<(), Box<dyn Error>>;
fn spec() -> Result<RectificationSpec, GeometryError> {
    let k=PinholeIntrinsics::new(6,5,10.0,10.0,3.0,2.5)?;
    Ok(RectificationSpec{source:k,target:k,distortion:LensDistortion::Pinhole,
        maximum_radius:1.0,source_domain:[7;32],calibration:[9;32],range:LumaRange::Full})
}
fn identity(e:u8,p:&[u8],mask:&[u8],s:RectificationSpec,stride:u32)->RawFrameIdentity {
    RawFrameIdentity{exposure:[e;32],storage:ContentDigest::sha256(p).bytes(),
        allowed_mask:ContentDigest::sha256(mask).bytes(),image_domain:s.source_domain,
        calibration:s.calibration,dimensions:s.source.dimensions(),row_stride:stride,range:s.range}
}
fn capture(e:u64)->FrameCapture {FrameCapture{camera:1,clock:2,capture:[e*10;2]}}
fn policy()->ForegroundPolicy {ForegroundPolicy{minimum_change:10,minimum_area:2,maximum_regions:32,widespread_per_mille:750}}
fn baseline(plan:&RectificationPlan, masks:&[Vec<u8>;3])->Result<RectifiedBackground,Box<dyn Error>> {
    let p=vec![100;30];let mut budget=WorkBudget::new(10_000_000);let mut frames=Vec::new();
    for (i,mask) in masks.iter().enumerate() {
        let raw=RawGrayFrame::new(identity(i as u8+1,&p,mask,plan.spec(),6),&p,mask,&mut budget)?;
        frames.push(plan.apply(&raw,&mut budget)?);
    }
    let refs:Vec<_>=frames.iter().enumerate().map(|(i,frame)|RectifiedReference{frame,capture:capture(i as u64+1)}).collect();
    Ok(RectifiedBackground::build(plan,&refs,BackgroundPolicy{selection_evidence:[6;32],
        validity:[0,10000],maximum_spread:4},&mut budget)?)
}
fn query(plan:&RectificationPlan,m:&RectifiedBackground,p:&[u8],mask:&[u8])->Result<RectifiedForeground,Box<dyn Error>> {
    let mut budget=WorkBudget::new(10_000_000);
    let raw=RawGrayFrame::new(identity(4,p,mask,plan.spec(),6),p,mask,&mut budget)?;
    Ok(m.detect_luma(plan,&raw,capture(4),policy(),&mut budget)?)
}
#[test]
fn raw_pixels_rectify_detect_crop_and_prepare_explicit_contact()->Test {
    let plan=RectificationPlan::compile(spec()?,&mut WorkBudget::new(100000))?;
    let m=baseline(&plan,&[vec![1;30],vec![1;30],vec![1;30]])?;
    let mut p=vec![100;30];for i in [7,8,13] {p[i]=150;}let mask=vec![1;30];
    let result=query(&plan,&m,&p,&mask)?;assert_eq!(result.report().regions().len(),1);
    assert_eq!(result.report().source().image.exposure,[4;32]);
    assert_eq!(result.frame().receipt().source.storage,ContentDigest::sha256(&p).bytes());
    assert_eq!(m.reference_receipts().len(),3);
    let mut budget=WorkBudget::new(100000);
    let crop=result.crop(8,0,30,&mut budget)?;
    assert_eq!(crop.origin(),[1,1]);assert_eq!(crop.dimensions(),[2,2]);
    assert_eq!(crop.pixels(),[150,150,150,100]);assert_eq!(crop.membership(),[1,1,1,0]);
    let prepared=crop.prepare_contact([88;32],[0.5,1.5],[0.5,1.5],true,&mut budget)?;
    assert_eq!(prepared.detection.pixel_min,[1.5,2.5]);assert_eq!(prepared.detection.pixel_max,[1.5,2.5]);
    assert_eq!(prepared.detection.id,8);assert_eq!(prepared.source.capture,[40;2]);
    assert_eq!(prepared.crop,crop.digest());assert_eq!(prepared.report,result.report().digest());
    assert!(prepared.detection.visible_contact);
    let unknown=crop.prepare_contact([89;32],[0.5,1.5],[0.5,1.5],false,&mut budget)?;
    assert!(!unknown.detection.visible_contact);Ok(())
}
#[test]
fn padded_crop_never_exposes_masked_context_or_accepts_masked_contact()->Test {
    let plan=RectificationPlan::compile(spec()?,&mut WorkBudget::new(100000))?;
    let m=baseline(&plan,&[vec![1;30],vec![1;30],vec![1;30]])?;
    let mut p=vec![100;30];for i in [7,8,13] {p[i]=150;}p[14]=211;
    let mut mask=vec![1;30];mask[14]=0;
    let result=query(&plan,&m,&p,&mask)?;
    let mut budget=WorkBudget::new(100000);let crop=result.crop(8,1,30,&mut budget)?;
    assert_eq!(crop.origin(),[0,0]);assert_eq!(crop.dimensions(),[4,4]);
    assert_eq!(crop.pixels()[10],0);assert_eq!(crop.allowed()[10],0);assert_eq!(crop.membership()[10],0);
    assert!(result.report().regions()[0].touches_unknown);
    assert!(crop.prepare_contact([88;32],[1.5,2.5],[2.5,2.5],true,&mut budget).is_err());
    assert!(crop.prepare_contact([89;32],[0.5,0.5],[0.5,0.5],true,&mut budget).is_err());Ok(())
}
#[test]
fn unknown_baseline_is_not_misused_as_the_current_privacy_mask()->Test {
    let plan=RectificationPlan::compile(spec()?,&mut WorkBudget::new(100000))?;
    let mut old=vec![1;30];old[14]=0;
    let m=baseline(&plan,&[old,vec![1;30],vec![1;30]])?;
    let mut p=vec![100;30];for i in [7,8,13] {p[i]=150;}p[14]=211;
    let result=query(&plan,&m,&p,&[1;30])?;
    assert_eq!(result.report().pixel_states()[14],0);
    let crop=result.crop(8,0,30,&mut WorkBudget::new(100000))?;
    assert_eq!(crop.pixels()[3],211);assert_eq!(crop.allowed()[3],1);assert_eq!(crop.membership()[3],0);Ok(())
}
#[test]
fn changed_rectification_or_capture_basis_cannot_reuse_background()->Test {
    let plan=RectificationPlan::compile(spec()?,&mut WorkBudget::new(100000))?;
    let m=baseline(&plan,&[vec![1;30],vec![1;30],vec![1;30]])?;
    let mut changed=spec()?;changed.calibration=[5;32];
    let other=RectificationPlan::compile(changed,&mut WorkBudget::new(100000))?;
    let p=[100;30];let mask=[1;30];let mut budget=WorkBudget::new(100000);
    let raw=RawGrayFrame::new(identity(4,&p,&mask,plan.spec(),6),&p,&mask,&mut budget)?;
    assert!(m.detect_luma(&other,&raw,capture(4),policy(),&mut budget).is_err());
    let wrong=FrameCapture{camera:5,..capture(4)};
    assert!(m.detect_luma(&plan,&raw,wrong,policy(),&mut budget).is_err());Ok(())
}
#[test]
fn video_range_and_row_padding_are_normalized_before_comparison()->Test {
    let mut s=spec()?;s.range=LumaRange::Video;
    let plan=RectificationPlan::compile(s,&mut WorkBudget::new(100000))?;
    let m=baseline(&plan,&[vec![1;30],vec![1;30],vec![1;30]])?;
    let mut pixels=vec![100;40];for y in 0..5 {pixels[y*8+6]=255;pixels[y*8+7]=0;}
    pixels[8+1]=200;pixels[8+2]=200;
    let mask=vec![1;30];let mut budget=WorkBudget::new(100000);
    let raw=RawGrayFrame::new(identity(4,&pixels,&mask,s,8),&pixels,&mask,&mut budget)?;
    let result=m.detect_luma(&plan,&raw,capture(4),policy(),&mut budget)?;
    assert_eq!(result.report().changed_pixels(),2);assert_eq!(result.frame().pixels()[7],214);
    assert_eq!(result.frame().receipt().source.row_stride,8);Ok(())
}
#[test]
fn crop_bounds_cancellation_and_forged_contact_identity_fail_atomically()->Test {
    let plan=RectificationPlan::compile(spec()?,&mut WorkBudget::new(100000))?;
    let m=baseline(&plan,&[vec![1;30],vec![1;30],vec![1;30]])?;
    let mut p=vec![100;30];p[7]=150;p[8]=150;let result=query(&plan,&m,&p,&[1;30])?;
    let mut budget=WorkBudget::new(100000);
    assert!(result.crop(999,0,30,&mut budget).is_err());assert!(result.crop(8,1,2,&mut budget).is_err());
    let flag=AtomicBool::new(true);assert!(result.crop(8,0,30,&mut WorkBudget::cancellable(1000,&flag)).is_err());
    let crop=result.crop(8,0,30,&mut budget)?;
    assert!(crop.prepare_contact([0;32],[0.5,0.5],[0.5,0.5],true,&mut budget).is_err());
    assert!(crop.prepare_contact(crop.digest(),[0.5,0.5],[0.5,0.5],true,&mut budget).is_err());
    assert!(crop.prepare_contact([88;32],[f64::NAN,0.5],[0.5,0.5],true,&mut budget).is_err());
    assert!(crop.prepare_contact([88;32],[0.5,0.5],[2.0,0.5],true,&mut budget).is_err());Ok(())
}
