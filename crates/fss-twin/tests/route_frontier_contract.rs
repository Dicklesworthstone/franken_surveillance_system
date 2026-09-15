#![forbid(unsafe_code)]

use std::error::Error;
use fss_core::ContentDigest;
use fss_geometry::{GeometryBasis,PinholeIntrinsics,RigidPose,WorkBudget};
use fss_twin::{ContactObservation,ImportExpectation,ImportLimits,MovementClass,NavigationProfile,
    ProjectionOptions,PropertyTwin,SupportNetwork,TrackingCamera,import_twin};
use fss_twin::route_frontier::*;
use fss_twin::stream::{ContactTrack,TrackOptions,TrackScope};

type Test=Result<(),Box<dyn Error>>;
fn text(bytes:&mut Vec<u8>,value:&str){bytes.extend_from_slice(&(value.len() as u16).to_le_bytes());bytes.extend_from_slice(value.as_bytes());}
fn twin()->Result<PropertyTwin,Box<dyn Error>>{
    let vertices=[[0.,0.,0.],[2.,0.,0.],[2.,2.,0.],[0.,2.,0.]];
    let faces=[([0u32,1,2],0u32),([0,2,3],1)];
    let mut body=vec![1;32];text(&mut body,"frontier/Z-up");text(&mut body,"synthetic");body.push(0);
    for n in [0.0f64,-1.0,0.0]{body.extend_from_slice(&n.to_le_bytes());}
    for n in [2u32,2,4,2]{body.extend_from_slice(&n.to_le_bytes());}
    for (id,kind) in [("path",1u8),("grass",2u8)]{text(&mut body,id);body.push(kind);}
    for i in 0..2{text(&mut body,&format!("object{i}"));body.extend_from_slice(&(i as u32).to_le_bytes());body.extend_from_slice(&[1,0]);}
    for p in vertices{for n in p{body.extend_from_slice(&n.to_le_bytes());}}
    for (indices,object) in faces{for n in indices{body.extend_from_slice(&n.to_le_bytes());}body.extend_from_slice(&object.to_le_bytes());}
    let mut bytes=b"FSSTWIN1".to_vec();bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());bytes.extend_from_slice(&body);
    bytes.extend_from_slice(&ContentDigest::sha256(&bytes).bytes());
    Ok(import_twin(&bytes,ImportExpectation{package_sha256:ContentDigest::sha256(&bytes).bytes(),source_scene_sha256:[1;32],basis:GeometryBasis::new(1,1)?},ImportLimits::default(),&mut WorkBudget::new(1_000_000))?)
}
fn camera(twin:&PropertyTwin)->Result<TrackingCamera,Box<dyn Error>>{
    let rotation=[[1.0,0.0,0.0],[0.0,-1.0,0.0],[0.0,0.0,-1.0]];
    let pose=RigidPose::new(rotation,[-1.0,1.0,5.0])?;
    Ok(TrackingCamera{geometry:twin.basis(),camera:7,calibration:9,image_domain:11,clock:13,validity:[0,10_000_000_000],
        pose,intrinsics:PinholeIntrinsics::new(100,100,100.0,100.0,50.0,50.0)?,error:None})
}
fn pixel(world:[f64;3])->[f64;2]{[100.0*(world[0]-1.0)/5.0+50.0,100.0*(1.0-world[1])/5.0+50.0]}
fn observation(evidence:u8,exposure:u64,capture:u64,world:[f64;3])->ContactObservation{
    let p=pixel(world);ContactObservation{evidence:[evidence;32],track:99,camera:7,exposure,image_domain:11,clock:13,capture:[capture,capture],pixel_min:p,pixel_max:p,visible_contact:true}
}
fn tracked(twin:&PropertyTwin,budget:&mut WorkBudget<'_>)->Result<ContactTrack,Box<dyn Error>>{
    let mut track=ContactTrack::new(twin,TrackScope{track:99,clock:13,epoch:1},&[camera(twin)?],TrackOptions::default(),budget)?;
    track.ingest(twin,observation(1,1,100,[0.6,0.3,0.0]),None,budget)?;
    track.ingest(twin,observation(2,2,1_000_000_100,[1.0,0.4,0.0]),None,budget)?;
    Ok(track)
}

#[test]
fn person_frontier_retains_path_preference_and_protected_neutral_routes()->Test{
    let twin=twin()?;let mut budget=WorkBudget::new(100_000_000);let network=SupportNetwork::compile(&twin,16,&mut budget)?;
    let track=tracked(&twin,&mut budget)?;let snapshot=track.snapshot(2)?;
    let frontier=build_route_frontier(&twin,&network,snapshot,RouteFrontierOptions{
        profile:NavigationProfile::new(MovementClass::Person,0.9,0.0,4)?,maximum_features:16,maximum_routes:64,maximum_points:256,retain_without_preference:true},&mut budget)?;
    assert_eq!(frontier.destination_features,2);assert_eq!(frontier.unresolved_sources.len(),0);
    assert_eq!(frontier.routes.len(),4);
    for feature in 0..2u32{
        assert!(frontier.routes.iter().any(|r|r.destination_feature==feature&&r.kind==FrontierRouteKind::Preferred));
        assert!(frontier.routes.iter().any(|r|r.destination_feature==feature&&r.kind==FrontierRouteKind::WithoutPathPreference));
    }
    assert!(frontier.routes.iter().all(|r|!r.motion.is_empty()));
    assert!(frontier.routes.iter().filter_map(|r|r.motion[0].initial_direction_cosine).any(|c|c>0.0));
    Ok(())
}

#[test]
fn bear_frontier_never_inherits_pedestrian_preference()->Test{
    let twin=twin()?;let mut budget=WorkBudget::new(100_000_000);let network=SupportNetwork::compile(&twin,16,&mut budget)?;
    let track=tracked(&twin,&mut budget)?;let snapshot=track.snapshot(2)?;
    let frontier=build_route_frontier(&twin,&network,snapshot,RouteFrontierOptions{
        profile:NavigationProfile::new(MovementClass::Bear,0.9,0.0,1)?,maximum_features:16,maximum_routes:64,maximum_points:256,retain_without_preference:true},&mut budget)?;
    assert_eq!(frontier.routes.len(),2);
    assert!(frontier.routes.iter().all(|r|r.kind==FrontierRouteKind::Preferred));
    assert_eq!(frontier.profile.person_path_multiplier(),1);
    Ok(())
}

#[test]
fn complete_output_limit_refuses_instead_of_pruning_destinations()->Test{
    let twin=twin()?;let mut budget=WorkBudget::new(100_000_000);let network=SupportNetwork::compile(&twin,16,&mut budget)?;
    let track=tracked(&twin,&mut budget)?;let snapshot=track.snapshot(2)?;
    let result=build_route_frontier(&twin,&network,snapshot,RouteFrontierOptions{
        profile:NavigationProfile::new(MovementClass::Person,0.9,0.0,4)?,maximum_features:16,maximum_routes:3,maximum_points:256,retain_without_preference:true},&mut budget);
    assert!(matches!(result,Err(RouteFrontierError::Limit)));
    Ok(())
}

#[test]
fn frontier_is_pinned_to_exact_track_revision()->Test{
    let twin=twin()?;let mut budget=WorkBudget::new(100_000_000);let network=SupportNetwork::compile(&twin,16,&mut budget)?;
    let mut track=tracked(&twin,&mut budget)?;
    let frontier=build_route_frontier(&twin,&network,track.snapshot(2)?,RouteFrontierOptions{
        profile:NavigationProfile::new(MovementClass::Unknown,0.9,0.0,1)?,maximum_features:16,maximum_routes:64,maximum_points:256,retain_without_preference:false},&mut budget)?;
    track.ingest(&twin,observation(3,3,2_000_000_100,[1.3,0.5,0.0]),None,&mut budget)?;
    assert!(matches!(frontier.check_source_current(track.snapshot(3)?),Err(RouteFrontierError::BasisMismatch)));
    Ok(())
}
