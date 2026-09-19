#![forbid(unsafe_code)]
//! Association factorization contracts: k-best joint assignments and policy refusals.
mod common;
use std::error::Error;
use std::sync::atomic::AtomicBool;
use fss_geometry::{PinholeIntrinsics,RigidPose,WorkBudget};
use fss_twin::association::*;
use fss_twin::association_hypotheses::*;
use fss_twin::stream::{ContactTrack,TrackOptions,TrackScope};
use fss_twin::{ContactObservation,ProjectionError,ProjectionOptions,PropertyTwin,TrackingCamera};

type Test = Result<(),Box<dyn Error>>;
fn policy() -> AssignmentPolicy {
    AssignmentPolicy { one_to_one_basis: [77;32], maximum_per_factor: 1024, maximum_materialized: 4096 }
}
/// Fixture tuple returned by [`setup`]: twin, camera, tracks, and unassigned contacts.
type SetupFixture=(PropertyTwin,TrackingCamera,Vec<ContactTrack>,Vec<UnassignedContact>);
fn setup(separated: bool) -> Result<SetupFixture,Box<dyn Error>> {
    let twin = common::twin(&[0.0],Some(0.0))?;
    let c = TrackingCamera { geometry: twin.basis(), camera: 1, calibration: 1, image_domain: 1,
        clock: 1, validity: [0,100_000_000_000], error: Some(ProjectionError::EXACT),
        intrinsics: PinholeIntrinsics::new(128,128,100.0,100.0,64.0,64.0)?,
        pose: RigidPose::from_center([[1.0,0.0,0.0],[0.0,-1.0,0.0],[0.0,0.0,-1.0]],[2.0,2.0,5.0])? };
    let mut budget = WorkBudget::new(100_000_000); let mut tracks = Vec::new(); let mut detections = Vec::new();
    for id in 1..=2_u64 {
        let mut track = ContactTrack::new(&twin,TrackScope{track:id,clock:1,epoch:1},&[c],TrackOptions::default(),&mut budget)?;
        let y = if separated { if id==1 {0.8} else {3.1} } else {2.0};
        let xs = if id==1 {[0.5,1.0,1.5]} else if separated {[3.5,3.0,2.5]} else {[2.5,2.0,1.5]};
        for exposure in 1..=2_u64 {
            let pixel = c.pose.project(c.intrinsics,[xs[exposure as usize-1],y,0.0])?;
            track.ingest(&twin,ContactObservation{evidence:[(id*10+exposure) as u8;32],track:id,
                camera:1,exposure,image_domain:1,clock:1,capture:[exposure*1_000_000_000;2],
                pixel_min:pixel,pixel_max:pixel,visible_contact:true},None,&mut budget)?;
        }
        let pixel = c.pose.project(c.intrinsics,[xs[2],y,0.0])?;
        detections.push(UnassignedContact{id,evidence:[(100+id) as u8;32],pixel_min:pixel,pixel_max:pixel,visible_contact:true});
        tracks.push(track);
    }
    Ok((twin,c,tracks,detections))
}
fn graph(twin:&PropertyTwin,c:TrackingCamera,tracks:&[ContactTrack],detections:&[UnassignedContact]) -> Result<AssociationGraph,Box<dyn Error>> {
    let snapshots = tracks.iter().map(|t|t.snapshot(t.revision())).collect::<Result<Vec<_>,_>>()?;
    Ok(gate_contact_batch(twin,AssociationFrame{camera:c,exposure:3,evidence:[200;32],capture:[3_000_000_000;2]},
        &snapshots,detections,AssociationOptions{projection:ProjectionOptions::default(),acceleration:[0.0;3],
            maximum_gap_ns:30_000_000_000,maximum_witnesses:4096},&mut WorkBudget::new(100_000_000))?)
}
#[test]
fn crossing_has_two_permutations_four_single_links_and_all_unmatched() -> Test {
    let (twin,c,tracks,ds) = setup(false)?; let g = graph(&twin,c,&tracks,&ds)?;
    let h = factorize_associations(&g,policy(),&mut WorkBudget::new(100000))?;
    assert_eq!(h.joint_count(),Some(7)); assert_eq!(h.factors().len(),1);
    let FactorAlternatives::Explicit(all) = h.factors()[0].alternatives() else { return Err("small factor must enumerate".into()); };
    assert_eq!(all.iter().filter(|a|a.links().len()==2).count(),2);
    assert_eq!(all.iter().filter(|a|a.links().len()==1).count(),4);
    assert_eq!(all.iter().filter(|a|a.links().is_empty()).count(),1);
    assert_eq!(tracks[0].revision(),2); assert_eq!(tracks[1].revision(),2);
    Ok(())
}
#[test]
fn separated_components_combine_without_forcing_every_detection_to_match() -> Test {
    let (twin,c,tracks,ds) = setup(true)?; let g = graph(&twin,c,&tracks,&ds)?;
    let h = factorize_associations(&g,policy(),&mut WorkBudget::new(100000))?;
    assert_eq!(h.factors().len(),2); assert_eq!(h.joint_count(),Some(4));
    let none = h.check_assignment(&[],&mut WorkBudget::new(100000))?;
    assert_eq!(none.assignment().unmatched_tracks(),&[1,2]);
    assert_eq!(none.assignment().unmatched_detections(),&[1,2]);
    assert!(h.check_assignment(&[AssignmentLink{track:1,detection:2}],&mut WorkBudget::new(100000)).is_err());
    Ok(())
}
#[test]
fn representation_limits_keep_full_implicit_families_not_partial_lists() -> Test {
    let (twin,c,tracks,ds) = setup(false)?; let g = graph(&twin,c,&tracks,&ds)?;
    let h = factorize_associations(&g,AssignmentPolicy{maximum_per_factor:2,..policy()},&mut WorkBudget::new(100000))?;
    assert_eq!(h.joint_count(),None); assert_eq!(h.factors()[0].allowed_links().len(),4);
    assert_eq!(h.factors()[0].alternatives(),&FactorAlternatives::Implicit(ImplicitReason::FactorLimit));
    h.check_assignment(&[AssignmentLink{track:1,detection:2},AssignmentLink{track:2,detection:1}],&mut WorkBudget::new(100000))?;
    let (twin,c,tracks,ds) = setup(true)?; let g = graph(&twin,c,&tracks,&ds)?;
    let h = factorize_associations(&g,AssignmentPolicy{maximum_materialized:1,..policy()},&mut WorkBudget::new(100000))?;
    assert!(h.factors().iter().all(|f|matches!(f.alternatives(),FactorAlternatives::Implicit(ImplicitReason::TotalLimit))));
    assert_eq!(h.factors().iter().map(|f|f.allowed_links().len()).sum::<usize>(),2);
    Ok(())
}
#[test]
fn selected_membership_preserves_source_records_and_requires_explicit_ingestion() -> Test {
    let (twin,c,mut tracks,ds) = setup(false)?; let g = graph(&twin,c,&tracks,&ds)?;
    let mut b = WorkBudget::new(100_000_000); let h = factorize_associations(&g,policy(),&mut b)?;
    let chosen = h.check_assignment(&[AssignmentLink{track:2,detection:1},AssignmentLink{track:1,detection:2}],&mut b)?;
    let observations = chosen.observations(&mut b)?;
    assert_eq!(observations[0].track,1); assert_eq!(observations[0].evidence,ds[1].evidence);
    assert_eq!(observations[1].track,2); assert_eq!(observations[1].evidence,ds[0].evidence);
    assert_eq!(tracks[0].revision(),2);
    chosen.graph().check_current(&twin,c,&[tracks[0].snapshot(2)?,tracks[1].snapshot(2)?],&mut b)?;
    // An explicit caller choice invokes the existing owner; factorization does not.
    tracks[0].ingest(&twin,observations[0],Some([88;32]),&mut b)?;
    assert_eq!(tracks[0].revision(),3);
    assert!(g.check_current(&twin,c,&[tracks[0].snapshot(3)?,tracks[1].snapshot(2)?],&mut b).is_err());
    Ok(())
}
#[test]
fn one_to_one_membership_rejects_duplicate_track_or_detection_use() -> Test {
    let (twin,c,tracks,ds) = setup(false)?; let g = graph(&twin,c,&tracks,&ds)?;
    let mut b = WorkBudget::new(100000); let h = factorize_associations(&g,policy(),&mut b)?;
    for links in [[AssignmentLink{track:1,detection:1},AssignmentLink{track:2,detection:1}],
        [AssignmentLink{track:1,detection:1},AssignmentLink{track:1,detection:2}]] {
        assert!(matches!(h.check_assignment(&links,&mut b), Err(AssociationError::InvalidInput)));
    }
    Ok(())
}
#[test]
fn actual_work_failure_and_missing_partition_assumption_are_not_success() -> Test {
    let (twin,c,tracks,ds) = setup(false)?; let g = graph(&twin,c,&tracks,&ds)?;
    assert!(factorize_associations(&g,policy(),&mut WorkBudget::new(0)).is_err());
    let cancelled = AtomicBool::new(true);
    assert!(factorize_associations(&g,policy(),&mut WorkBudget::cancellable(100000,&cancelled)).is_err());
    assert!(matches!(factorize_associations(&g,AssignmentPolicy{one_to_one_basis:[0;32],..policy()},&mut WorkBudget::new(100000)), Err(AssociationError::InvalidInput)));
    Ok(())
}
