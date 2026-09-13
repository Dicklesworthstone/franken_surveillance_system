#![forbid(unsafe_code)]
mod common;
use fss_geometry::{PinholeIntrinsics,RigidPose,WorkBudget};
use fss_twin::{ContactObservation,MotionFitOptions,ProjectionError,ProjectionOptions,ProjectionQuality,
    TrackingCamera,TwinError,fit_world_motion,project_contact,propagate_motion};

fn camera(twin:&fss_twin::PropertyTwin)->Result<TrackingCamera,Box<dyn std::error::Error>> {
    Ok(TrackingCamera{geometry:twin.basis(),camera:1,calibration:1,image_domain:1,clock:1,
        validity:[0,10_000_000_000],pose:RigidPose::from_center([[1.0,0.0,0.0],[0.0,-1.0,0.0],[0.0,0.0,-1.0]],[2.0,2.0,10.0])?,
        intrinsics:PinholeIntrinsics::new(1000,1000,500.0,500.0,500.0,500.0)?,error:Some(ProjectionError::EXACT)})
}
fn observation(exposure:u64,pixel:[f64;2])->ContactObservation {
    ContactObservation{evidence:[exposure as u8;32],track:1,camera:1,exposure,image_domain:1,clock:1,
        capture:[exposure*1_000_000_000;2],pixel_min:pixel,pixel_max:pixel,visible_contact:true}
}

#[test]
fn contact_lifts_to_actual_triangle_not_its_bounding_box()->Result<(),Box<dyn std::error::Error>> {
    let twin=common::twin(&[0.0],Some(0.0))?;let c=camera(&twin)?;
    let p=project_contact(&twin,c,observation(1,[450.0,450.0]),ProjectionOptions::default(),&mut WorkBudget::new(100_000))?;
    assert_eq!(p.quality(),ProjectionQuality::Bounded);assert_eq!(p.hypotheses().len(),1);
    let h=p.hypotheses()[0];assert_eq!(h.triangle,1);
    assert!(h.bounds.ok_or("bounds absent")?.contains([1.0,3.0,0.0]));
    assert_eq!(h.nominal_occluded,Some(false));
    Ok(())
}
#[test]
fn multiple_levels_and_blocked_nominal_support_remain_visible()->Result<(),Box<dyn std::error::Error>> {
    let twin=common::twin(&[0.0,2.0],Some(0.0))?;
    let p=project_contact(&twin,camera(&twin)?,observation(1,[450.0,450.0]),ProjectionOptions::default(),&mut WorkBudget::new(100_000))?;
    assert_eq!(p.hypotheses().len(),2);
    assert!(p.hypotheses().iter().any(|h|h.nominal_occluded==Some(true)));
    assert!(p.hypotheses().iter().any(|h|h.nominal_occluded==Some(false)));
    Ok(())
}
#[test]
fn missing_contact_or_error_never_becomes_precise_geometry()->Result<(),Box<dyn std::error::Error>> {
    let twin=common::twin(&[0.0],None)?;let c=camera(&twin)?;let mut o=observation(1,[450.0,450.0]);
    let p=project_contact(&twin,c,o,ProjectionOptions::default(),&mut WorkBudget::new(100_000))?;
    assert_eq!(p.quality(),ProjectionQuality::NominalOnly);assert!(p.hypotheses()[0].bounds.is_none());
    o.visible_contact=false;
    let p=project_contact(&twin,c,o,ProjectionOptions::default(),&mut WorkBudget::new(100_000))?;
    assert_eq!(p.quality(),ProjectionQuality::ContactUnknown);assert!(p.hypotheses().is_empty());assert_eq!(p.observation(),o);
    Ok(())
}
#[test]
fn continuous_pixel_lens_pose_and_map_bounds_cover_perturbed_ground()->Result<(),Box<dyn std::error::Error>> {
    let twin=common::twin(&[0.0],Some(0.02))?;let mut c=camera(&twin)?;
    c.error=Some(ProjectionError{centre:[0.05;3],rotation_entry:0.005,focal:[10.0;2],principal:[1.0;2]});
    let mut o=observation(1,[450.0,450.0]);o.pixel_min=[449.0;2];o.pixel_max=[451.0;2];
    let p=project_contact(&twin,c,o,ProjectionOptions::default(),&mut WorkBudget::new(100_000))?;
    for dx in [-0.04,0.0,0.04] {for dz in [-0.01,0.0,0.01] {for focal in [491.0,500.0,509.0] {
        for angle in [-0.002f64,0.0,0.002] {
            let(s,co)=angle.sin_cos();
            let pose=RigidPose::from_center([[co,0.0,s],[0.0,-1.0,0.0],[s,0.0,-co]],[2.0+dx,2.0-dx,10.0+dx])?;
            let k=PinholeIntrinsics::new(1000,1000,focal,focal,500.5,499.5)?;
            for u in [449.0,450.0,451.0] {for v in [449.0,450.0,451.0] {
                let ray=pose.ray(k,[u,v])?;let distance=(dz-ray.origin()[2])/ray.direction()[2];let point=ray.at(distance)?;
                assert!(p.hypotheses().iter().any(|h|h.bounds.is_some_and(|b|b.contains(point))));
            }}
        }
    }}}
    Ok(())
}
#[test]
fn motion_uses_capture_intervals_and_preserves_source_pair()->Result<(),Box<dyn std::error::Error>> {
    let twin=common::twin(&[0.0],Some(0.01))?;let c=camera(&twin)?;
    let mut a=observation(1,[450.0,450.0]);a.capture=[990_000_000,1_010_000_000];
    let mut b=observation(2,[500.0,450.0]);b.capture=[1_990_000_000,2_010_000_000];
    let pa=project_contact(&twin,c,a,ProjectionOptions::default(),&mut WorkBudget::new(100_000))?;
    let pb=project_contact(&twin,c,b,ProjectionOptions::default(),&mut WorkBudget::new(100_000))?;
    let motion=fit_world_motion(&pa,&pb,MotionFitOptions::default(),&mut WorkBudget::new(10_000))?;
    assert_eq!(motion.observations(),[a,b]);assert_eq!(motion.modes().len(),1);
    let velocity=motion.modes()[0].velocity.ok_or("velocity absent")?;
    assert!(velocity.contains([1.0,0.0,0.0]));assert!(velocity.0[0].lower()<1.0);assert!(velocity.0[0].upper()>1.0);
    let future=propagate_motion(&motion,[4_000_000_000;2],[0.0;3],&mut WorkBudget::new(10_000))?;
    assert!(future[0].bounds.ok_or("bounds absent")?.contains([4.0,3.0,0.0]));
    Ok(())
}
#[test]
fn propagation_accounts_for_average_versus_endpoint_velocity()->Result<(),Box<dyn std::error::Error>> {
    let twin=common::twin(&[0.0],Some(0.0))?;let c=camera(&twin)?;
    let pa=project_contact(&twin,c,observation(1,[450.0,450.0]),ProjectionOptions::default(),&mut WorkBudget::new(100_000))?;
    let pb=project_contact(&twin,c,observation(2,[500.0,450.0]),ProjectionOptions::default(),&mut WorkBudget::new(100_000))?;
    let motion=fit_world_motion(&pa,&pb,MotionFitOptions::default(),&mut WorkBudget::new(10_000))?;
    // Acceleration 2 throughout: x=1 -> x=2 with v=2 at t=2, then x=5 at t=3.
    let future=propagate_motion(&motion,[3_000_000_000;2],[2.0,0.0,0.0],&mut WorkBudget::new(10_000))?;
    assert!(future[0].bounds.ok_or("bounds absent")?.contains([5.0,3.0,0.0]));
    Ok(())
}
#[test]
fn duplicate_exposures_and_overlapping_times_do_not_create_velocity()->Result<(),Box<dyn std::error::Error>> {
    let twin=common::twin(&[0.0],Some(0.0))?;let c=camera(&twin)?;
    let a=observation(1,[450.0,450.0]);let pa=project_contact(&twin,c,a,ProjectionOptions::default(),&mut WorkBudget::new(100_000))?;
    assert_eq!(fit_world_motion(&pa,&pa,MotionFitOptions::default(),&mut WorkBudget::new(10_000)).err(),Some(TwinError::Basis));
    let mut b=observation(2,[500.0,450.0]);b.capture=a.capture;
    let pb=project_contact(&twin,c,b,ProjectionOptions::default(),&mut WorkBudget::new(100_000))?;
    assert_eq!(fit_world_motion(&pa,&pb,MotionFitOptions::default(),&mut WorkBudget::new(10_000)).err(),Some(TwinError::Unobservable));
    Ok(())
}
#[test]
fn changed_modes_and_exhausted_budgets_refuse()->Result<(),Box<dyn std::error::Error>> {
    let twin=common::twin(&[0.0],Some(0.0))?;let c=camera(&twin)?;let mut o=observation(1,[450.0,450.0]);
    o.image_domain=2;
    assert_eq!(project_contact(&twin,c,o,ProjectionOptions::default(),&mut WorkBudget::new(100_000)).err(),Some(TwinError::Basis));
    o.image_domain=1;
    assert!(project_contact(&twin,c,o,ProjectionOptions::default(),&mut WorkBudget::new(0)).is_err());
    Ok(())
}
#[test]
fn cross_camera_fit_requires_and_retains_association_basis()->Result<(),Box<dyn std::error::Error>> {
    let twin=common::twin(&[0.0],Some(0.0))?;let c=camera(&twin)?;
    let pa=project_contact(&twin,c,observation(1,[450.0,450.0]),ProjectionOptions::default(),&mut WorkBudget::new(100_000))?;
    let mut other=c;other.camera=2;let mut b=observation(2,[500.0,450.0]);b.camera=2;
    let pb=project_contact(&twin,other,b,ProjectionOptions::default(),&mut WorkBudget::new(100_000))?;
    assert_eq!(fit_world_motion(&pa,&pb,MotionFitOptions::default(),&mut WorkBudget::new(10_000)).err(),Some(TwinError::Basis));
    let result=fit_world_motion(&pa,&pb,MotionFitOptions{association:Some([9;32]),..MotionFitOptions::default()},&mut WorkBudget::new(10_000))?;
    assert_eq!(result.association(),Some([9;32]));
    Ok(())
}
#[test]
fn large_epoch_differences_and_unknown_error_are_preserved()->Result<(),Box<dyn std::error::Error>> {
    let twin=common::twin(&[0.0],None)?;let mut c=camera(&twin)?;c.validity=[u64::MAX-10_000_000_000,u64::MAX];
    let mut a=observation(1,[450.0,450.0]);a.capture=[u64::MAX-3_000_000_000;2];
    let mut b=observation(2,[500.0,450.0]);b.capture=[u64::MAX-2_000_000_000;2];
    let pa=project_contact(&twin,c,a,ProjectionOptions::default(),&mut WorkBudget::new(100_000))?;
    let pb=project_contact(&twin,c,b,ProjectionOptions::default(),&mut WorkBudget::new(100_000))?;
    let result=fit_world_motion(&pa,&pb,MotionFitOptions::default(),&mut WorkBudget::new(10_000))?;
    assert_eq!(result.modes()[0].nominal_velocity,Some([1.0,0.0,0.0]));
    let future=propagate_motion(&result,[u64::MAX;2],[2.0;3],&mut WorkBudget::new(10_000))?;
    assert!(future[0].bounds.is_none());
    assert_eq!(future[0].nominal,Some([4.0,3.0,0.0]));
    Ok(())
}
