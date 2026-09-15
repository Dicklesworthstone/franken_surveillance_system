#![forbid(unsafe_code)]

use std::sync::atomic::AtomicBool;
use fss_geometry::{Correspondence, GeometryBasis, GeometryError, PinholeIntrinsics,
    PoseSolverOptions, RigidPose, WorkBudget, DEFAULT_PLANAR_RESIDUAL_RATIO,
    estimate_nonplanar_camera_pose, estimate_camera_pose_adaptive, estimate_planar_camera_pose};

type Test = Result<(), Box<dyn std::error::Error>>;
fn camera() -> Result<PinholeIntrinsics, GeometryError> { PinholeIntrinsics::new(1920,1080,800.0,820.0,960.0,540.0) }
fn options() -> PoseSolverOptions { PoseSolverOptions { ransac_trials:0, ..PoseSolverOptions::default() } }
fn points(depth:f64) -> Vec<Correspondence> {
    (0..24).map(|i| {
        let x=(i%6) as f64*0.5-1.3; let y=(i/6) as f64*0.6-0.9;
        Correspondence { landmark:i+1,physical_group:i+1,world:[x,y,0.0],
            pixel:[800.0*(0.8*x+0.3)/(-0.6*x+depth)+960.0, 820.0*(y-0.4)/(-0.6*x+depth)+540.0] }
    }).collect()
}
fn truth(depth:f64) -> Result<RigidPose, GeometryError> { RigidPose::new([[0.8,0.0,0.6],[0.0,1.0,0.0],[-0.6,0.0,0.8]], [0.3,-0.4,depth]) }
fn distance(a:[f64;3],b:[f64;3])->f64 {(a[0]-b[0]).hypot(a[1]-b[1]).hypot(a[2]-b[2])}

#[test]
fn planar_pose_recovers_fixed_map_and_retains_admission() -> Test {
    let basis=GeometryBasis::new(1,1)?; let input=points(8.0); let unchanged=input.clone();
    let result=estimate_planar_camera_pose(basis,camera()?,&input,options(),DEFAULT_PLANAR_RESIDUAL_RATIO,&mut WorkBudget::new(10_000_000))?;
    assert!(distance(result.candidates()[0].pose().center(),truth(8.0)?.center())<1e-5);
    assert!(result.candidates()[0].rms_px()<1e-5); assert_eq!(input,unchanged);
    let support=result.planar_support().ok_or("missing planar support")?;
    assert!(support.maximum_off_plane<1e-12); assert!(support.in_plane_axis_ratio>0.1);
    Ok(())
}

#[test]
fn adaptive_route_preserves_original_nonplanar_boundary() -> Test {
    let basis=GeometryBasis::new(1,1)?; let input=points(8.0);
    assert!(matches!(estimate_nonplanar_camera_pose(basis,camera()?,&input,options(),&mut WorkBudget::new(10_000_000)),Err(GeometryError::UnsupportedGeometry)));
    let result=estimate_camera_pose_adaptive(basis,camera()?,&input,options(),&mut WorkBudget::new(10_000_000))?;
    assert!(result.planar_support().is_some());
    Ok(())
}

#[test]
fn vertical_and_sloped_world_planes_work_without_z_zero_assumption() -> Test {
    for axes in [ [[0.0,0.0,1.0],[1.0,0.0,0.0],[0.0,1.0,0.0]], [[0.8,0.0,0.6],[0.0,1.0,0.0],[-0.6,0.0,0.8]] ] {
        let offset=[7.0,-11.0,4.0]; let input=points(8.0);
        let mapped:Vec<_>=input.iter().map(|p| Correspondence {world:std::array::from_fn(|i| offset[i]+(0..3).map(|j| axes[i][j]*p.world[j]).sum::<f64>()),..*p}).collect();
        let result=estimate_camera_pose_adaptive(GeometryBasis::new(1,1)?,camera()?,&mapped,options(),&mut WorkBudget::new(10_000_000))?;
        let original=truth(8.0)?.center();
        let expected=std::array::from_fn(|i|offset[i]+(0..3).map(|j| axes[i][j]*original[j]).sum::<f64>());
        assert!(distance(result.candidates()[0].pose().center(),expected)<1e-5);
    }
    Ok(())
}

#[test]
fn weak_perspective_keeps_two_passing_orientations() -> Test {
    let opt=PoseSolverOptions { minimum_image_span:0.0, inlier_threshold_px:1.0, refinement_iterations:50,..options() };
    let result=estimate_camera_pose_adaptive(GeometryBasis::new(1,1)?,camera()?,&points(80.0),opt,&mut WorkBudget::new(20_000_000))?;
    assert!(result.candidates().len()>=2);
    assert!(result.candidates().iter().all(|c|c.maximum_error_px()<1.0));
    Ok(())
}

#[test]
fn planar_ransac_rejects_bad_image_associations() -> Test {
    let mut input=points(8.0);
    for (i,p) in input.iter_mut().enumerate() { if i%4==0 { p.pixel=[100.0+i as f64*17.0,70.0+i as f64*11.0]; } }
    let opt=PoseSolverOptions { ransac_trials:128,minimum_inliers:16,..options() };
    let result=estimate_camera_pose_adaptive(GeometryBasis::new(1,1)?,camera()?,&input,opt,&mut WorkBudget::new(200_000_000))?;
    assert_eq!(result.candidates()[0].inlier_landmarks().len(),18);
    assert!(distance(result.candidates()[0].pose().center(),truth(8.0)?.center())<1e-4);
    Ok(())
}

#[test]
fn collinear_and_weak_nonplanar_maps_are_not_flattened() -> Test {
    let mut line=points(8.0); for (i,p) in line.iter_mut().enumerate() { p.world=[i as f64,0.0,0.0]; }
    assert!(matches!(estimate_camera_pose_adaptive(GeometryBasis::new(1,1)?,camera()?,&line,options(),&mut WorkBudget::new(10_000_000)),Err(GeometryError::UnsupportedGeometry)));
    let mut weak=points(8.0); weak[0].world[2]=1e-5;
    assert!(matches!(estimate_camera_pose_adaptive(GeometryBasis::new(1,1)?,camera()?,&weak,options(),&mut WorkBudget::new(10_000_000)),Err(GeometryError::UnsupportedGeometry)));
    Ok(())
}

#[test]
fn held_out_depth_discriminates_all_modes_without_refitting() -> Test {
    let basis=GeometryBasis::new(1,1)?;
    let opt=PoseSolverOptions {minimum_image_span:0.0,inlier_threshold_px:1.0,refinement_iterations:50,..options()};
    let result=estimate_camera_pose_adaptive(basis,camera()?,&points(80.0),opt,&mut WorkBudget::new(20_000_000))?;
    assert!(result.candidates().len()>=2);
    let held:Vec<_>=(0..6).map(|i| {
        let x=-0.7+i as f64*0.23; let y=0.12+(i%2) as f64*0.27; let z=2.5+(i%3) as f64*0.5;
        Correspondence {landmark:100+i,physical_group:100+i,world:[x,y,z],
            pixel:[800.0*(0.8*x+0.6*z+0.3)/(-0.6*x+0.8*z+80.0)+960.0,820.0*(y-0.4)/(-0.6*x+0.8*z+80.0)+540.0]}
    }).collect();
    let validated=result.validate_all_candidates(basis,&held,0.1,&mut WorkBudget::new(1_000_000))?;
    assert_eq!(validated.reports().len(),result.candidates().len());
    assert_eq!(validated.passing_candidates(),&[0]);
    assert!(validated.reports().iter().any(|p|!p.passed));
    Ok(())
}

#[test]
fn cancellation_limits_and_duplicate_inputs_refuse() -> Test {
    let input=points(8.0); let basis=GeometryBasis::new(1,1)?; let flag=AtomicBool::new(true);
    assert!(matches!(estimate_camera_pose_adaptive(basis,camera()?,&input,options(),&mut WorkBudget::cancellable(100_000,&flag)),Err(GeometryError::Cancelled)));
    assert!(matches!(estimate_camera_pose_adaptive(basis,camera()?,&input,options(),&mut WorkBudget::new(1)),Err(GeometryError::BudgetExhausted)));
    let mut duplicate=input; duplicate[1].physical_group=duplicate[0].physical_group;
    assert!(matches!(estimate_camera_pose_adaptive(basis,camera()?,&duplicate,options(),&mut WorkBudget::new(100_000)),Err(GeometryError::InvalidCorrespondence)));
    Ok(())
}
