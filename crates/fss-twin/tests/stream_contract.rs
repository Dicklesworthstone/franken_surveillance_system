#![forbid(unsafe_code)]
mod common;

use std::error::Error;
use std::sync::atomic::AtomicBool;
use fss_geometry::{GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};
use fss_twin::{ContactObservation, ProjectionError, TrackingCamera};
use fss_twin::stream::{ContactTrack, TrackDisposition as D, TrackError, TrackOptions, TrackScope};

type Test = Result<(), Box<dyn Error>>;
fn scope() -> TrackScope { TrackScope { track: 9, clock: 1, epoch: 7 } }
fn camera(id: u64) -> Result<TrackingCamera, Box<dyn Error>> {
    Ok(TrackingCamera { geometry: fss_geometry::GeometryBasis::new(1, 1)?, camera: id,
        calibration: 2, image_domain: 3, clock: 1, validity: [0, 100_000_000_000],
        pose: RigidPose::from_center([[1.0,0.0,0.0],[0.0,-1.0,0.0],[0.0,0.0,-1.0]], [2.0,2.0,10.0])?,
        intrinsics: PinholeIntrinsics::new(200,200,100.0,100.0,100.0,100.0)?,
        error: Some(ProjectionError::EXACT) })
}
fn observation(id: u64, second: u64, x: f64) -> ContactObservation {
    let mut evidence = [77; 32]; evidence[..8].copy_from_slice(&id.to_le_bytes());
    let pixel = [100.0 + 10.0 * (x - 2.0), 115.0];
    ContactObservation { evidence, track: 9, camera: 1, exposure: id, image_domain: 3, clock: 1,
        capture: [second * 1_000_000_000; 2], pixel_min: pixel, pixel_max: pixel, visible_contact: true }
}
fn budget() -> WorkBudget<'static> { WorkBudget::new(100_000_000) }

#[test]
fn source_stream_establishes_motion_and_exact_revision_snapshots() -> Test {
    let twin = common::twin(&[0.0], Some(0.0))?;
    let mut b = budget();
    let mut track = ContactTrack::new(&twin, scope(), &[camera(1)?], TrackOptions::default(), &mut b)?;
    assert!(matches!(track.snapshot(0), Err(TrackError::Empty)));
    let first = track.ingest(&twin, observation(1,1,1.0), None, &mut b)?;
    assert_eq!(first.receipt.disposition, D::Seeded);
    let second = track.ingest(&twin, observation(2,2,2.0), None, &mut b)?;
    assert_eq!(second.receipt.disposition, D::MotionUpdated);
    assert!(matches!(track.snapshot(1), Err(TrackError::BasisMismatch)));
    let snapshot = track.snapshot(2)?;
    let motion = snapshot.motion().ok_or("missing motion")?;
    for mode in motion.modes() {
        let v = mode.nominal_velocity.ok_or("missing nominal velocity")?;
        assert!((v[0] - 1.0).abs() < 1e-9 && v[1].abs() < 1e-9 && v[2].abs() < 1e-9);
    }
    assert_eq!(motion.observations()[1].evidence, second.receipt.evidence);
    Ok(())
}
#[test]
fn exact_old_retry_returns_original_receipt_without_rolling_back() -> Test {
    let twin = common::twin(&[0.0], None)?; let mut b = budget();
    let mut track = ContactTrack::new(&twin, scope(), &[camera(1)?], TrackOptions::default(), &mut b)?;
    let old = track.ingest(&twin, observation(1,1,1.0), None, &mut b)?;
    track.ingest(&twin, observation(2,2,2.0), None, &mut b)?;
    let retry = track.ingest(&twin, observation(1,1,1.0), None, &mut b)?;
    assert!(retry.replayed); assert_eq!(old.receipt, retry.receipt); assert_eq!(track.revision(),2);
    assert!(track.snapshot(2)?.motion().is_some());
    Ok(())
}
#[test]
fn conflicting_evidence_exposure_and_association_retries_are_atomic() -> Test {
    let twin = common::twin(&[0.0], None)?; let mut b = budget();
    let mut track = ContactTrack::new(&twin, scope(), &[camera(1)?], TrackOptions::default(), &mut b)?;
    let first = observation(1,1,1.0); track.ingest(&twin,first,None,&mut b)?;
    let mut changed = first; changed.pixel_min[0]+=1.0; changed.pixel_max=changed.pixel_min;
    assert_eq!(track.ingest(&twin,changed,None,&mut b),Err(TrackError::ConflictingReplay));
    changed=first; changed.evidence=[3;32];
    assert_eq!(track.ingest(&twin,changed,None,&mut b),Err(TrackError::ConflictingReplay));
    assert_eq!(track.ingest(&twin,first,Some([2;32]),&mut b),Err(TrackError::ConflictingReplay));
    assert_eq!(track.revision(),1);
    Ok(())
}
#[test]
fn eviction_does_not_readmit_old_observations() -> Test {
    let twin=common::twin(&[0.0],None)?; let mut b=budget();
    let options=TrackOptions{receipt_capacity:1,..TrackOptions::default()};
    let mut track=ContactTrack::new(&twin,scope(),&[camera(1)?],options,&mut b)?;
    track.ingest(&twin,observation(1,1,1.0),None,&mut b)?;
    track.ingest(&twin,observation(2,2,2.0),None,&mut b)?;
    assert_eq!(track.ingest(&twin,observation(1,1,1.0),None,&mut b),Err(TrackError::LateObservation));
    assert_eq!(track.revision(),2);
    Ok(())
}
#[test]
fn lost_contact_clears_velocity_and_requires_a_new_usable_pair() -> Test {
    let twin=common::twin(&[0.0],None)?; let mut b=budget();
    let mut track=ContactTrack::new(&twin,scope(),&[camera(1)?],TrackOptions::default(),&mut b)?;
    track.ingest(&twin,observation(1,1,1.0),None,&mut b)?;
    track.ingest(&twin,observation(2,2,2.0),None,&mut b)?;
    let mut hidden=observation(3,3,2.2); hidden.visible_contact=false;
    assert_eq!(track.ingest(&twin,hidden,None,&mut b)?.receipt.disposition,D::ContactUnavailable);
    assert!(track.snapshot(3)?.motion().is_none());
    assert_eq!(track.snapshot(3)?.projection().observation(),hidden);
    assert_eq!(track.ingest(&twin,observation(4,4,2.4),None,&mut b)?.receipt.disposition,D::Seeded);
    assert_eq!(track.ingest(&twin,observation(5,5,2.6),None,&mut b)?.receipt.disposition,D::MotionUpdated);
    Ok(())
}
#[test]
fn unknown_support_never_preserves_old_motion() -> Test {
    let twin=common::twin(&[0.0],None)?; let mut b=budget();
    let mut track=ContactTrack::new(&twin,scope(),&[camera(1)?],TrackOptions::default(),&mut b)?;
    track.ingest(&twin,observation(1,1,1.0),None,&mut b)?;
    track.ingest(&twin,observation(2,2,2.0),None,&mut b)?;
    assert_eq!(track.ingest(&twin,observation(3,3,8.0),None,&mut b)?.receipt.disposition,D::SupportUnavailable);
    assert!(track.snapshot(3)?.motion().is_none());
    Ok(())
}
#[test]
fn overlap_and_gap_are_accepted_sources_but_not_velocity() -> Test {
    let twin=common::twin(&[0.0],None)?; let mut b=budget();
    let options=TrackOptions{max_gap_ns:5_000_000_000,..TrackOptions::default()};
    let mut track=ContactTrack::new(&twin,scope(),&[camera(1)?],options,&mut b)?;
    let mut first=observation(1,1,1.0); first.capture[1]=3_000_000_000;
    track.ingest(&twin,first,None,&mut b)?;
    assert_eq!(track.ingest(&twin,observation(2,2,2.0),None,&mut b)?.receipt.disposition,D::TimeAmbiguous);
    assert!(track.snapshot(2)?.motion().is_none());
    assert_eq!(track.ingest(&twin,observation(3,10,2.5),None,&mut b)?.receipt.disposition,D::Gap);
    assert_eq!(track.ingest(&twin,observation(4,11,3.0),None,&mut b)?.receipt.disposition,D::MotionUpdated);
    Ok(())
}
#[test]
fn cross_camera_pair_requires_and_retains_association() -> Test {
    let twin=common::twin(&[0.0],None)?; let mut b=budget();
    for supplied in [None,Some([42;32])] {
        let mut track=ContactTrack::new(&twin,scope(),&[camera(1)?,camera(2)?],TrackOptions::default(),&mut b)?;
        track.ingest(&twin,observation(1,1,1.0),None,&mut b)?;
        let mut next=observation(2,2,2.0); next.camera=2;
        let result=track.ingest(&twin,next,supplied,&mut b)?;
        if let Some(id)=supplied {
            assert_eq!(result.receipt.disposition,D::MotionUpdated);
            assert_eq!(track.snapshot(2)?.motion().ok_or("missing motion")?.association(),Some(id));
        } else {
            assert_eq!(result.receipt.disposition,D::AssociationRequired);
            assert!(track.snapshot(2)?.motion().is_none());
        }
    }
    Ok(())
}
#[test]
fn exhausted_or_cancelled_update_can_be_retried_without_losing_the_frame() -> Test {
    let twin=common::twin(&[0.0],Some(0.0))?; let mut b=budget();
    let mut track=ContactTrack::new(&twin,scope(),&[camera(1)?],TrackOptions::default(),&mut b)?;
    track.ingest(&twin,observation(1,1,1.0),None,&mut b)?;
    let second=observation(2,2,2.0);
    assert!(matches!(track.ingest(&twin,second,None,&mut WorkBudget::new(2)),
        Err(TrackError::Twin(fss_twin::TwinError::Geometry(GeometryError::BudgetExhausted)))));
    let cancelled=AtomicBool::new(true);
    assert!(matches!(track.ingest(&twin,second,None,&mut WorkBudget::cancellable(1_000_000,&cancelled)),
        Err(TrackError::Twin(fss_twin::TwinError::Geometry(GeometryError::Cancelled)))));
    assert_eq!(track.revision(),1);
    assert_eq!(track.ingest(&twin,second,None,&mut b)?.receipt.revision,2);
    Ok(())
}
#[test]
fn stale_twin_camera_mode_and_invalidated_session_cannot_update() -> Test {
    let twin=common::twin(&[0.0],None)?; let other=common::twin(&[1.0],None)?; let mut b=budget();
    let mut track=ContactTrack::new(&twin,scope(),&[camera(1)?],TrackOptions::default(),&mut b)?;
    assert_eq!(track.ingest(&other,observation(1,1,1.0),None,&mut b),Err(TrackError::BasisMismatch));
    let mut changed=observation(1,1,1.0); changed.image_domain=4;
    assert!(track.ingest(&twin,changed,None,&mut b).is_err()); assert_eq!(track.revision(),0);
    track.ingest(&twin,observation(1,1,1.0),None,&mut b)?; track.invalidate();
    assert!(matches!(track.snapshot(1),Err(TrackError::Invalidated)));
    assert_eq!(track.ingest(&twin,observation(1,1,1.0),None,&mut b),Err(TrackError::Invalidated));
    assert_eq!(track.last_receipt().ok_or("lost receipt")?.revision,1);
    Ok(())
}
#[test]
fn mode_overflow_keeps_the_previous_accepted_state() -> Test {
    let twin=common::twin(&[0.0,1.0],None)?; let mut b=budget();
    let options=TrackOptions{max_modes:1,..TrackOptions::default()};
    let mut track=ContactTrack::new(&twin,scope(),&[camera(1)?],options,&mut b)?;
    track.ingest(&twin,observation(1,1,1.0),None,&mut b)?;
    assert!(track.ingest(&twin,observation(2,2,2.0),None,&mut b).is_err());
    assert_eq!(track.revision(),1);
    Ok(())
}
#[test]
fn constructor_rejects_invalid_policy_and_duplicate_camera_identities() -> Test {
    let twin=common::twin(&[0.0],None)?; let mut b=budget(); let cam=camera(1)?;
    assert!(ContactTrack::new(&twin,scope(),&[cam,cam],TrackOptions::default(),&mut b).is_err());
    assert!(ContactTrack::new(&twin,scope(),&[cam],TrackOptions{receipt_capacity:0,..TrackOptions::default()},&mut b).is_err());
    let mut bad=cam; bad.clock=2;
    assert!(ContactTrack::new(&twin,scope(),&[bad],TrackOptions::default(),&mut b).is_err());
    Ok(())
}
