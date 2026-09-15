#![forbid(unsafe_code)]
mod common;

use std::error::Error;
use fss_geometry::{PinholeIntrinsics,RigidPose,WorkBudget};
use fss_twin::{ContactObservation,ProjectionOptions,ProjectionQuality,TrackingCamera};
use fss_twin::calibration_gate::*;
use fss_twin::calibration_monitor::{CalibrationDisposition,CalibrationMonitorReport};
use fss_twin::localization::{ImageIdentity,MatchReport};

type Test=Result<(),Box<dyn Error>>;
fn camera(twin:&fss_twin::PropertyTwin)->Result<TrackingCamera,Box<dyn Error>>{
    Ok(TrackingCamera{geometry:twin.basis(),camera:7,calibration:9,image_domain:11,clock:13,
        validity:[100,200],pose:RigidPose::new([[1.0,0.0,0.0],[0.0,1.0,0.0],[0.0,0.0,1.0]],[0.0,0.0,8.0])?,
        intrinsics:PinholeIntrinsics::new(640,480,500.0,500.0,320.0,240.0)?,error:None})
}
fn report(twin:&fss_twin::PropertyTwin,disposition:CalibrationDisposition)->CalibrationMonitorReport{
    CalibrationMonitorReport{calibration:[8;32],twin_digest:twin.digest(),atlas_digest:[7;32],
        matches:MatchReport{atlas:[7;32],query:ImageIdentity{exposure:[2;32],pixels:[3;32],image_domain:[4;32],dimensions:[640,480]},decisions:vec![],correspondences:vec![]},
        residuals:vec![],projected:12,inliers:12,rms_inlier_px:Some(0.0),maximum_inlier_error_px:Some(0.0),
        image_span_fraction:[0.4,0.3],disposition}
}
fn basis()->CalibrationGateBasis{CalibrationGateBasis{calibration_digest:[8;32],camera:7,calibration:9,
    image_domain:11,image_domain_digest:[4;32],clock:13,checked_capture:[120,130]}}
fn observation(capture:[u64;2])->ContactObservation{ContactObservation{evidence:[5;32],track:1,camera:7,
    exposure:2,image_domain:11,clock:13,capture,pixel_min:[320.0,240.0],pixel_max:[320.0,240.0],visible_contact:false}}

#[test]
fn valid_monitor_receipt_admits_only_its_checked_capture_interval()->Test{
    let twin=common::twin(&[0.0],None)?; let camera=camera(&twin)?; let report=report(&twin,CalibrationDisposition::ValidUnderPolicy);
    let admitted=admit_tracking_camera(camera,&report,basis())?;
    let projected=admitted.project_contact(&twin,observation([125,125]),ProjectionOptions::default(),&mut WorkBudget::new(100_000))?;
    assert_eq!(projected.quality(),ProjectionQuality::ContactUnknown);
    assert!(matches!(admitted.project_contact(&twin,observation([131,131]),ProjectionOptions::default(),&mut WorkBudget::new(100_000)),Err(CalibrationGateError::BasisMismatch)));
    Ok(())
}

#[test]
fn invalidated_and_indeterminate_calibrations_never_expose_tracking_camera()->Test{
    let twin=common::twin(&[0.0],None)?; let camera=camera(&twin)?;
    assert!(matches!(admit_tracking_camera(camera,&report(&twin,CalibrationDisposition::Invalidate),basis()),Err(CalibrationGateError::Invalidated)));
    assert!(matches!(admit_tracking_camera(camera,&report(&twin,CalibrationDisposition::Indeterminate),basis()),Err(CalibrationGateError::Indeterminate)));
    Ok(())
}

#[test]
fn digest_handle_clock_and_validity_rebinding_are_refused()->Test{
    let twin=common::twin(&[0.0],None)?; let camera=camera(&twin)?; let report=report(&twin,CalibrationDisposition::ValidUnderPolicy);
    let mut wrong=basis(); wrong.image_domain_digest=[6;32];
    assert!(matches!(admit_tracking_camera(camera,&report,wrong),Err(CalibrationGateError::BasisMismatch)));
    let mut wrong=basis(); wrong.checked_capture=[90,130];
    assert!(matches!(admit_tracking_camera(camera,&report,wrong),Err(CalibrationGateError::BasisMismatch)));
    let mut wrong=basis(); wrong.clock=99;
    assert!(matches!(admit_tracking_camera(camera,&report,wrong),Err(CalibrationGateError::BasisMismatch)));
    Ok(())
}
