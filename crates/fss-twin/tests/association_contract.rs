#![forbid(unsafe_code)]
//! Association gating contracts: exposure reuse, basis, and limit refusals.
mod common;

use std::error::Error;
use std::sync::atomic::AtomicBool;
use fss_geometry::{GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};
use fss_twin::association::*;
use fss_twin::stream::{ContactTrack, TrackOptions, TrackScope};
use fss_twin::{ContactObservation, ProjectionError, ProjectionOptions, PropertyTwin, TrackingCamera};

type Test = Result<(), Box<dyn Error>>;
fn camera(twin: &PropertyTwin) -> Result<TrackingCamera, Box<dyn Error>> {
    Ok(TrackingCamera { geometry: twin.basis(), camera: 1, calibration: 1, image_domain: 1,
        clock: 1, validity: [0, 100_000_000_000],
        pose: RigidPose::from_center([[1.0,0.0,0.0],[0.0,-1.0,0.0],[0.0,0.0,-1.0]], [2.0,2.0,5.0])?,
        intrinsics: PinholeIntrinsics::new(128,128,100.0,100.0,64.0,64.0)?,
        error: Some(ProjectionError::EXACT) })
}
fn observation(c: TrackingCamera, track: u64, exposure: u64, point: [f64; 3]) -> Result<ContactObservation, Box<dyn Error>> {
    let pixel = c.pose.project(c.intrinsics, point)?;
    Ok(ContactObservation { evidence: [(track * 10 + exposure) as u8; 32], track,
        camera: c.camera, exposure, image_domain: c.image_domain, clock: c.clock,
        capture: [exposure * 1_000_000_000; 2], pixel_min: pixel, pixel_max: pixel, visible_contact: true })
}
fn track(twin: &PropertyTwin, c: TrackingCamera, id: u64, x: [f64; 2], y: f64,
    budget: &mut WorkBudget<'_>) -> Result<ContactTrack, Box<dyn Error>> {
    let mut t = ContactTrack::new(twin, TrackScope { track: id, clock: 1, epoch: 1 },
        &[c], TrackOptions::default(), budget)?;
    t.ingest(twin, observation(c,id,1,[x[0],y,0.0])?, None, budget)?;
    t.ingest(twin, observation(c,id,2,[x[1],y,0.0])?, None, budget)?;
    Ok(t)
}
fn detection(c: TrackingCamera, id: u64, point: [f64; 3]) -> Result<UnassignedContact, Box<dyn Error>> {
    let pixel = c.pose.project(c.intrinsics, point)?;
    Ok(UnassignedContact { id, evidence: [(100 + id) as u8; 32],
        pixel_min: pixel, pixel_max: pixel, visible_contact: true })
}
fn frame(c: TrackingCamera) -> AssociationFrame {
    AssociationFrame { camera: c, exposure: 3, evidence: [200; 32], capture: [3_000_000_000; 2] }
}
fn options() -> AssociationOptions {
    AssociationOptions { projection: ProjectionOptions::default(), acceleration: [0.0; 3],
        maximum_gap_ns: 30_000_000_000, maximum_witnesses: 4096 }
}

#[test]
fn source_motion_gates_separated_targets_without_assigning_identity() -> Test {
    let twin = common::twin(&[0.0],Some(0.0))?;
    let c = camera(&twin)?; let mut b = WorkBudget::new(100_000_000);
    let first = track(&twin,c,1,[0.5,1.0],0.8,&mut b)?;
    let second = track(&twin,c,2,[3.5,3.0],3.1,&mut b)?;
    let inputs = [second.snapshot(2)?,first.snapshot(2)?];
    let detections = [detection(c,2,[2.5,3.1,0.0])?,detection(c,1,[1.5,0.8,0.0])?];
    let graph = gate_contact_batch(&twin,frame(c),&inputs,&detections,options(),&mut b)?;
    assert_eq!(graph.pairs().iter().map(|p|(p.track(),p.detection(),p.possible())).collect::<Vec<_>>(),
        vec![(1,1,true),(1,2,false),(2,1,false),(2,2,true)]);
    for pair in graph.pairs().iter().filter(|p|p.possible()) {
        assert!(!pair.overlaps().is_empty()); assert!(pair.unresolved().is_empty());
    }
    assert_eq!(first.revision(),2); assert_eq!(second.revision(),2);
    graph.check_current(&twin,c,&inputs,&mut b)?;
    Ok(())
}
#[test]
fn crossing_targets_retain_both_identity_permutations() -> Test {
    let twin = common::twin(&[0.0],Some(0.0))?;
    let c = camera(&twin)?; let mut b = WorkBudget::new(100_000_000);
    let first = track(&twin,c,1,[0.5,1.0],2.0,&mut b)?;
    let second = track(&twin,c,2,[2.5,2.0],2.0,&mut b)?;
    let detections = [detection(c,1,[1.5,2.0,0.0])?,detection(c,2,[1.5,2.0,0.0])?];
    let graph = gate_contact_batch(&twin,frame(c),&[first.snapshot(2)?,second.snapshot(2)?],
        &detections,options(),&mut b)?;
    assert_eq!(graph.pairs().len(),4); assert!(graph.pairs().iter().all(AssociationPair::possible));
    Ok(())
}
#[test]
fn unknown_map_error_keeps_distant_candidates_unresolved() -> Test {
    let twin = common::twin(&[0.0],None)?;
    let c = camera(&twin)?; let mut b = WorkBudget::new(100_000_000);
    let t = track(&twin,c,1,[0.5,1.0],0.8,&mut b)?;
    let graph = gate_contact_batch(&twin,frame(c),&[t.snapshot(2)?],
        &[detection(c,1,[3.5,3.0,0.0])?],options(),&mut b)?;
    let pair = &graph.pairs()[0];
    assert!(pair.possible()); assert!(pair.unresolved().contains(UnresolvedAssociation::UnknownBounds));
    assert!(pair.overlaps().is_empty());
    Ok(())
}
#[test]
fn missing_contact_and_missing_motion_do_not_become_exclusions() -> Test {
    let twin = common::twin(&[0.0],Some(0.0))?;
    let c = camera(&twin)?; let mut b = WorkBudget::new(100_000_000);
    let mut t = ContactTrack::new(&twin, TrackScope {track:1,clock:1,epoch:1}, &[c], TrackOptions::default(), &mut b)?;
    t.ingest(&twin,observation(c,1,2,[1.0,0.8,0.0])?,None,&mut b)?;
    let mut d = detection(c,1,[3.0,3.5,0.0])?; d.visible_contact = false;
    let graph = gate_contact_batch(&twin,frame(c),&[t.snapshot(1)?],&[d],options(),&mut b)?;
    let p = &graph.pairs()[0];
    assert!(p.possible());
    assert!(p.unresolved().contains(UnresolvedAssociation::MotionUnavailable));
    assert!(p.unresolved().contains(UnresolvedAssociation::ContactUnavailable));
    Ok(())
}
#[test]
fn unordered_and_old_captures_preserve_candidates_but_not_motion_claims() -> Test {
    let twin = common::twin(&[0.0],Some(0.0))?;
    let c = camera(&twin)?; let mut b = WorkBudget::new(100_000_000);
    let t = track(&twin,c,1,[0.5,1.0],0.8,&mut b)?;
    let d = detection(c,1,[3.0,3.5,0.0])?;
    for (capture,reason) in [([1_000_000_000;2],UnresolvedAssociation::CaptureOrder),
        ([40_000_000_000;2],UnresolvedAssociation::Gap)] {
        let graph = gate_contact_batch(&twin,AssociationFrame{capture,..frame(c)},&[t.snapshot(2)?],&[d],options(),&mut b)?;
        assert!(graph.pairs()[0].unresolved().contains(reason)); assert!(graph.pairs()[0].possible());
    }
    Ok(())
}
#[test]
fn acceleration_widens_the_candidate_graph() -> Test {
    let twin = common::twin(&[0.0],Some(0.0))?;
    let c = camera(&twin)?; let mut b = WorkBudget::new(100_000_000);
    let t = track(&twin,c,1,[0.5,1.0],0.8,&mut b)?;
    let d = detection(c,1,[2.0,0.8,0.0])?;
    let narrow = gate_contact_batch(&twin,frame(c),&[t.snapshot(2)?],&[d],options(),&mut b)?;
    let broad = gate_contact_batch(&twin,frame(c),&[t.snapshot(2)?],&[d],
        AssociationOptions{acceleration:[1.0,0.0,0.0],..options()},&mut b)?;
    assert!(!narrow.pairs()[0].possible()); assert!(broad.pairs()[0].possible());
    Ok(())
}
#[test]
fn empty_proposals_and_empty_track_sets_are_not_evidence_of_absence() -> Test {
    let twin = common::twin(&[0.0],Some(0.0))?;
    let c = camera(&twin)?; let mut b = WorkBudget::new(100_000_000);
    let t = track(&twin,c,1,[0.5,1.0],0.8,&mut b)?;
    let graph = gate_contact_batch(&twin,frame(c),&[t.snapshot(2)?],&[],options(),&mut b)?;
    assert_eq!(graph.sources().len(),1); assert!(graph.pairs().is_empty());
    let graph = gate_contact_batch(&twin,frame(c),&[],&[detection(c,1,[1.5,0.8,0.0])?],options(),&mut b)?;
    assert_eq!(graph.detections().len(),1); assert!(graph.sources().is_empty());
    Ok(())
}
#[test]
fn consumed_exposures_and_reused_evidence_are_rejected() -> Test {
    let twin = common::twin(&[0.0],Some(0.0))?;
    let c = camera(&twin)?; let mut b = WorkBudget::new(100_000_000);
    let t = track(&twin,c,1,[0.5,1.0],0.8,&mut b)?;
    let d = detection(c,1,[1.5,0.8,0.0])?;
    assert!(matches!(gate_contact_batch(&twin,AssociationFrame{exposure:2,..frame(c)},&[t.snapshot(2)?],&[d],options(),&mut b), Err(AssociationError::ReusedExposure)));
    let d = UnassignedContact{evidence:[12;32],..d};
    assert!(matches!(gate_contact_batch(&twin,frame(c),&[t.snapshot(2)?],&[d],options(),&mut b), Err(AssociationError::ReusedExposure)));
    Ok(())
}
#[test]
fn malformed_suffix_and_duplicate_sources_refuse_the_whole_graph() -> Test {
    let twin = common::twin(&[0.0],Some(0.0))?;
    let c = camera(&twin)?; let mut b = WorkBudget::new(100_000_000);
    let t = track(&twin,c,1,[0.5,1.0],0.8,&mut b)?;
    let d = detection(c,1,[1.5,0.8,0.0])?;
    assert!(matches!(gate_contact_batch(&twin,frame(c),&[t.snapshot(2)?],&[d,d],options(),&mut b), Err(AssociationError::InvalidInput)));
    assert!(matches!(gate_contact_batch(&twin,frame(c),&[t.snapshot(2)?,t.snapshot(2)?],&[d],options(),&mut b), Err(AssociationError::BasisMismatch)));
    let bad = UnassignedContact{id:2,evidence:[105;32],pixel_max:[f64::NAN,0.0],..d};
    assert!(matches!(gate_contact_batch(&twin,frame(c),&[t.snapshot(2)?],&[d,bad],options(),&mut b), Err(AssociationError::InvalidInput)));
    Ok(())
}
#[test]
fn stale_sources_and_camera_changes_invalidate_owned_graphs() -> Test {
    let twin = common::twin(&[0.0],Some(0.0))?;
    let c = camera(&twin)?; let mut b = WorkBudget::new(100_000_000);
    let mut t = track(&twin,c,1,[0.5,1.0],0.8,&mut b)?;
    let graph = gate_contact_batch(&twin,frame(c),&[t.snapshot(2)?],&[],options(),&mut b)?;
    assert_eq!(graph.check_current(&twin,TrackingCamera{calibration:2,..c},&[t.snapshot(2)?],&mut b),Err(AssociationError::BasisMismatch));
    t.ingest(&twin,observation(c,1,4,[2.0,0.8,0.0])?,None,&mut b)?;
    assert_eq!(graph.check_current(&twin,c,&[t.snapshot(3)?],&mut b),Err(AssociationError::BasisMismatch));
    Ok(())
}
#[test]
fn cancellation_and_complete_overlap_limits_leave_tracks_unchanged() -> Test {
    let twin = common::twin(&[0.0],Some(0.0))?;
    let c = camera(&twin)?; let mut b = WorkBudget::new(100_000_000);
    let t = track(&twin,c,1,[0.5,1.0],0.8,&mut b)?;
    let detections = [detection(c,1,[1.5,0.8,0.0])?,detection(c,2,[1.5,0.8,0.0])?];
    let cancel = AtomicBool::new(true);
    let mut cancelled = WorkBudget::cancellable(100_000_000,&cancel);
    assert!(matches!(gate_contact_batch(&twin,frame(c),&[t.snapshot(2)?],&detections,options(),&mut cancelled), Err(AssociationError::Twin(fss_twin::TwinError::Geometry(GeometryError::Cancelled)))));
    assert!(matches!(gate_contact_batch(&twin,frame(c),&[t.snapshot(2)?],&detections, AssociationOptions{maximum_witnesses:1,..options()},&mut b), Err(AssociationError::Limit)));
    assert_eq!(t.revision(),2);
    Ok(())
}
