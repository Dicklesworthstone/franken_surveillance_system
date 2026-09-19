#![forbid(unsafe_code)]
//! Frontier handoff contracts: route frontier construction and handoff selection.

use std::error::Error;
use fss_core::ContentDigest;
use fss_geometry::{BodySamples,CameraAvailability,CaptureSchedule,GeometryBasis,HandoffCamera,HandoffOptions,
    NanosecondInterval,NextCameraOutcome,PinholeIntrinsics,RigidPose,RouteEnd,WorkBudget};
use fss_twin::{ContactObservation,ImportExpectation,ImportLimits,MovementClass,NavigationProfile,PropertyTwin,
    SupportNetwork,TrackingCamera,import_twin};
use fss_twin::calibration_gate::{CalibrationGateBasis,admit_tracking_camera};
use fss_twin::calibration_monitor::{CalibrationDisposition,CalibrationMonitorReport};
use fss_twin::frontier_handoff::*;
use fss_twin::localization::{ImageIdentity,MatchReport};
use fss_twin::monitored_handoff::MonitoredHandoffCamera;
use fss_twin::route_frontier::{RouteFrontierOptions,build_route_frontier};
use fss_twin::stream::{ContactTrack,TrackOptions,TrackScope};

type Test=Result<(),Box<dyn Error>>;
fn text(bytes:&mut Vec<u8>,value:&str){bytes.extend_from_slice(&(value.len() as u16).to_le_bytes());bytes.extend_from_slice(value.as_bytes());}
fn twin()->Result<PropertyTwin,Box<dyn Error>>{
    let mut body=vec![1;32];text(&mut body,"handoff/Z-up");text(&mut body,"synthetic");body.push(0);
    for n in [0.0f64,-1.0,0.0]{body.extend_from_slice(&n.to_le_bytes());}
    for n in [2u32,2,4,2]{body.extend_from_slice(&n.to_le_bytes());}
    for (id,kind) in [("grass",2u8),("path",1u8)]{text(&mut body,id);body.push(kind);}
    for i in 0..2{text(&mut body,&format!("object{i}"));body.extend_from_slice(&(i as u32).to_le_bytes());body.extend_from_slice(&[1,0]);}
    for p in [[0.0f64,0.,0.],[2.,0.,0.],[2.,2.,0.],[0.,2.,0.]]{for n in p{body.extend_from_slice(&n.to_le_bytes());}}
    for (tri,obj) in [([0u32,1,2],0u32),([0,2,3],1)]{for n in tri{body.extend_from_slice(&n.to_le_bytes());}body.extend_from_slice(&obj.to_le_bytes());}
    let mut bytes=b"FSSTWIN1".to_vec();bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());bytes.extend_from_slice(&body);bytes.extend_from_slice(&ContentDigest::sha256(&bytes).bytes());
    Ok(import_twin(&bytes,ImportExpectation{package_sha256:ContentDigest::sha256(&bytes).bytes(),source_scene_sha256:[1;32],basis:GeometryBasis::new(1,1)?},ImportLimits::default(),&mut WorkBudget::new(1_000_000))?)
}
fn pose()->Result<RigidPose,Box<dyn Error>>{Ok(RigidPose::new([[1.,0.,0.],[0.,-1.,0.],[0.,0.,-1.]],[-1.,1.,5.])?)}
fn intrinsics()->Result<PinholeIntrinsics,Box<dyn Error>>{Ok(PinholeIntrinsics::new(100,100,100.,100.,50.,50.)?)}
fn tracking(twin:&PropertyTwin,id:u64,calibration:u64,image:u64)->Result<TrackingCamera,Box<dyn Error>>{
    Ok(TrackingCamera{geometry:twin.basis(),camera:id,calibration,image_domain:image,clock:13,validity:[0,10_000_000_000],pose:pose()?,intrinsics:intrinsics()?,error:None})
}
fn pixel(world:[f64;3])->[f64;2]{[100.*(world[0]-1.)/5.+50.,100.*(1.-world[1])/5.+50.]}
fn observation(e:u8,exposure:u64,capture:u64,world:[f64;3])->ContactObservation{let p=pixel(world);ContactObservation{evidence:[e;32],track:99,camera:7,exposure,image_domain:11,clock:13,capture:[capture,capture],pixel_min:p,pixel_max:p,visible_contact:true}}
fn report(twin:&PropertyTwin)->CalibrationMonitorReport{CalibrationMonitorReport{calibration:[8;32],twin_digest:twin.digest(),atlas_digest:[7;32],matches:MatchReport{atlas:[7;32],query:ImageIdentity{exposure:[6;32],pixels:[5;32],image_domain:[4;32],dimensions:[100,100]},decisions:vec![],correspondences:vec![]},residuals:vec![],projected:12,inliers:12,rms_inlier_px:Some(0.),maximum_inlier_error_px:Some(0.),image_span_fraction:[0.4,0.4],disposition:CalibrationDisposition::ValidUnderPolicy}}

#[test]
fn moving_track_frontier_predicts_monitored_next_camera_without_destination_input()->Test{
    let twin=twin()?;let mut budget=WorkBudget::new(500_000_000);let source=tracking(&twin,7,9,11)?;let candidate=tracking(&twin,8,19,21)?;
    let mut track=ContactTrack::new(&twin,TrackScope{track:99,clock:13,epoch:1},&[source,candidate],TrackOptions::default(),&mut budget)?;
    track.ingest(&twin,observation(1,1,100,[0.6,0.3,0.]),None,&mut budget)?;
    track.ingest(&twin,observation(2,2,1_000_000_100,[1.0,0.4,0.]),None,&mut budget)?;
    let snapshot=track.snapshot(2)?;let network=SupportNetwork::compile(&twin,16,&mut budget)?;
    let frontier=build_route_frontier(&twin,&network,snapshot,RouteFrontierOptions{profile:NavigationProfile::new(MovementClass::Person,0.9,0.,4)?,maximum_features:16,maximum_routes:64,maximum_points:256,retain_without_preference:true},&mut budget)?;
    let gate=CalibrationGateBasis{twin_digest:twin.digest(),atlas_digest:[7;32],calibration_digest:[8;32],camera:8,calibration:19,image_domain:21,image_domain_digest:[4;32],clock:13,checked_capture:[0,2_000_000_000]};
    let monitored=admit_tracking_camera(candidate,&report(&twin),gate)?;
    let view=HandoffCamera{id:8,geometry:twin.basis(),clock:13,observation_generation:1,image_mode:21,pose:pose()?,intrinsics:intrinsics()?,availability:CameraAvailability::Ready,already_observing:false,valid:NanosecondInterval::new(0,10_000_000_000)?,schedule:CaptureSchedule::new(100_000_000,0)?,latency:NanosecondInterval::new(0,0)?,privacy_masks:&[],visible_per_mille:500,minimum_extent_px:[0.1,0.1]};
    let body=BodySamples::new(1,&[[0.,0.,0.],[0.,0.,1.]],&mut budget)?;
    let forecast=forecast_frontier_handoffs(&twin,snapshot,&frontier,&[MonitoredHandoffCamera{view,monitor:&monitored}],&body,FrontierHandoffOptions{horizon_ns:2_000_000_000,motion_generation:1,initial_pause_ns:0,route_end:RouteEnd::Stop,masses:HeadingMassPolicy::default(),handoff:HandoffOptions{max_samples_per_camera:1000,endpoint_margin:1e-6}},&mut budget)?;
    assert_eq!(forecast.bindings.len(),forecast.motion.hypotheses().len());
    assert!(forecast.bindings.iter().any(|b|b.kind==FrontierMotionKind::Stop));
    assert!(forecast.handoff.routes.iter().any(|r|matches!(r.next,NextCameraOutcome::Predicted{ref cameras,..} if cameras.contains(&8))));
    assert!(forecast.bindings.iter().filter(|b|b.kind==FrontierMotionKind::Route).any(|b|b.heading_cosine.is_some()));
    Ok(())
}

#[test]
fn candidate_camera_monitor_must_cover_the_source_observation()->Test{
    let twin=twin()?;let mut budget=WorkBudget::new(500_000_000);let source=tracking(&twin,7,9,11)?;let candidate=tracking(&twin,8,19,21)?;
    let mut track=ContactTrack::new(&twin,TrackScope{track:99,clock:13,epoch:1},&[source,candidate],TrackOptions::default(),&mut budget)?;
    track.ingest(&twin,observation(1,1,100,[0.6,0.3,0.]),None,&mut budget)?;track.ingest(&twin,observation(2,2,1_000_000_100,[1.0,0.4,0.]),None,&mut budget)?;
    let snapshot=track.snapshot(2)?;let network=SupportNetwork::compile(&twin,16,&mut budget)?;
    let frontier=build_route_frontier(&twin,&network,snapshot,RouteFrontierOptions{profile:NavigationProfile::new(MovementClass::Unknown,0.9,0.,1)?,maximum_features:16,maximum_routes:64,maximum_points:256,retain_without_preference:false},&mut budget)?;
    let gate=CalibrationGateBasis{twin_digest:twin.digest(),atlas_digest:[7;32],calibration_digest:[8;32],camera:8,calibration:19,image_domain:21,image_domain_digest:[4;32],clock:13,checked_capture:[0,500_000_000]};
    let monitored=admit_tracking_camera(candidate,&report(&twin),gate)?;
    let view=HandoffCamera{id:8,geometry:twin.basis(),clock:13,observation_generation:1,image_mode:21,pose:pose()?,intrinsics:intrinsics()?,availability:CameraAvailability::Ready,already_observing:false,valid:NanosecondInterval::new(0,10_000_000_000)?,schedule:CaptureSchedule::new(100_000_000,0)?,latency:NanosecondInterval::new(0,0)?,privacy_masks:&[],visible_per_mille:500,minimum_extent_px:[0.1,0.1]};
    let body=BodySamples::new(1,&[[0.,0.,0.],[0.,0.,1.]],&mut budget)?;
    assert!(matches!(forecast_frontier_handoffs(&twin,snapshot,&frontier,&[MonitoredHandoffCamera{view,monitor:&monitored}],&body,FrontierHandoffOptions{horizon_ns:1_000_000_000,motion_generation:1,initial_pause_ns:0,route_end:RouteEnd::Stop,masses:HeadingMassPolicy::default(),handoff:HandoffOptions{max_samples_per_camera:1000,endpoint_margin:1e-6}},&mut budget),Err(FrontierHandoffError::Calibration(_))));
    Ok(())
}
