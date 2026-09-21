#![forbid(unsafe_code)]
//! Native JPEG neural boxes reach the existing tracker and image-zone monitor.
mod rgb_zone_support;
use rgb_zone_support::*;
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, WorkBudget};
use fss_reference::ingest::rgb_tracking::*;
use fss_twin::image_tracking::{ImageTrackingError, TrackingAvailability};
use fss_twin::image_zones::{ImageZoneBasis, ImageZonePolicy, ImageZoneSpec, ImageZoneEventKind, ImageZoneRelation};

#[test]
fn actual_pixels_move_one_selected_class_through_entry_dwell_and_exit() -> Test {
    let model = model(1)?; let head = head(&model)?; let mut tracker = tracker(&head, tracking_policy())?;
    let outside = detection(&model, &head, 16, 1)?; let inside = detection(&model, &head, 240, 2)?;
    observe(&mut tracker, &outside, TrackingAvailability::Available)?;
    let id = tracker.tracker().tracks()[0].id();
    assert_eq!(tracker.zone_report().ok_or("zones")?.cells()[0].relation, ImageZoneRelation::Outside);
    observe(&mut tracker, &inside, TrackingAvailability::Available)?;
    assert_eq!(tracker.tracker().tracks()[0].id(), id);
    let zones = tracker.zone_report().ok_or("zones")?;
    assert!(zones.events().iter().any(|e| e.kind == ImageZoneEventKind::EnteredBetweenObservations));
    assert_eq!(zones.cells()[0].last_observation.frame.source.image.exposure, [2; 32]);
    let again = detection(&model, &head, 240, 3)?;
    observe(&mut tracker, &again, TrackingAvailability::Available)?;
    assert!(tracker.zone_report().ok_or("zones")?.events().iter().any(|e| e.kind == ImageZoneEventKind::SampledDwell));
    observe(&mut tracker, &detection(&model, &head, 16, 4)?, TrackingAvailability::Available)?;
    assert!(tracker.zone_report().ok_or("zones")?.events().iter().any(|e| e.kind == ImageZoneEventKind::LeftBetweenObservations));
    assert_eq!(tracker.tracker().exposure_count(), 4); Ok(())
}
#[test]
fn multilabel_rows_remain_one_object_and_other_classes_are_explicit() -> Test {
    let model = model(1)?; let head = head(&model)?; let run = detection(&model, &head, 240, 1)?;
    let mut tracker = tracker(&head, tracking_policy())?; observe(&mut tracker, &run, TrackingAvailability::Available)?;
    assert_eq!(run.report().detections().len(), 2);
    let p = tracker.prepared().ok_or("prepared")?;
    assert_eq!(p.decisions().len(), 2); assert_eq!(p.proposals().len(), 1);
    assert_eq!(p.decisions().iter().filter(|d| d.proposal.is_none()).count(), 1);
    assert_eq!(p.detection_digest(), run.report().digest()); assert_eq!(p.frame().evidence, p.digest().bytes());
    assert_eq!(p.frame().source.image.pixels, run.inference().decode_receipt().rgb_sha256);
    assert_eq!(tracker.contract().label(), "numeric-a"); assert_eq!(tracker.tracker().tracks().len(), 1); Ok(())
}
#[test]
fn subpixel_cover_is_outward_and_preserves_the_exact_original_box() -> Test {
    let model = model(1)?; let head = head(&model)?; let run = detection(&model, &head, 100, 1)?;
    let mut tracker = tracker(&head, tracking_policy())?; observe(&mut tracker, &run, TrackingAvailability::Available)?;
    let p = tracker.prepared().ok_or("prepared")?;
    for d in p.decisions().iter().filter(|d| d.proposal.is_some()) {
        let q = d.detection.bounds(); let b = d.proposal.ok_or("proposal")?;
        assert!(b.min[0] * 256 <= q[0] && b.min[1] * 256 <= q[1]);
        assert!(b.max[0] * 256 >= q[2] && b.max[1] * 256 >= q[3]);
        assert!(q[0] - b.min[0] * 256 < 256 && b.max[0] * 256 - q[2] < 256);
        assert_eq!(b.id, d.detection.row() as u64 + 1);
    }
    Ok(())
}
#[test]
fn unavailable_input_interrupts_observation_without_inventing_exit() -> Test {
    let model = model(1)?; let head = head(&model)?;
    for unavailable in [TrackingAvailability::Unobservable, TrackingAvailability::Disturbed] {
        let mut tracker = tracker(&head, tracking_policy())?;
        observe(&mut tracker, &detection(&model, &head, 240, 1)?, TrackingAvailability::Available)?;
        let before = tracker.tracker().tracks()[0].latest();
        observe(&mut tracker, &detection(&model, &head, 16, 2)?, unavailable)?;
        assert_eq!(tracker.tracker().tracks()[0].latest(), before);
        let events = tracker.zone_report().ok_or("zones")?.events();
        assert!(events.iter().any(|e| e.kind == ImageZoneEventKind::ObservationInterrupted));
        assert!(!events.iter().any(|e| e.kind == ImageZoneEventKind::LeftBetweenObservations));
        assert_eq!(tracker.prepared().ok_or("prepared")?.admission().availability(), unavailable);
    }
    Ok(())
}
#[test]
fn report_inference_admission_and_class_contract_cannot_be_cross_wired() -> Test {
    let model = model(1)?; let head = head(&model)?;
    let a = detection(&model, &head, 16, 1)?; let b = detection(&model, &head, 240, 2)?;
    let mut tracker = tracker(&head, tracking_policy())?; let before = tracker.tracker().digest();
    let admit = admission(a.report().source(), TrackingAvailability::Available)?;
    assert!(matches!(tracker.observe(b.inference(), a.report(), admit, &mut WorkBudget::new(WORK)), Err(RgbTrackingError::BindingMismatch)));
    assert!(matches!(tracker.observe(b.inference(), b.report(), admit, &mut WorkBudget::new(WORK)), Err(RgbTrackingError::BindingMismatch)));
    assert_eq!(tracker.tracker().digest(), before);
    assert!(RgbTrackingContract::new(&head, 2, ContentDigest::sha256(b"selection")).is_err());
    let first = RgbTrackingContract::new(&head, 0, ContentDigest::sha256(b"selection"))?;
    let second = RgbTrackingContract::new(&head, 1, ContentDigest::sha256(b"selection"))?;
    assert_ne!(first.digest(), second.digest()); Ok(())
}
#[test]
fn repeated_exposure_and_changed_mask_are_refused_before_temporal_mutation() -> Test {
    let model = model(1)?; let head = head(&model)?; let run = detection(&model, &head, 240, 1)?;
    let mut tracker = tracker(&head, tracking_policy())?; observe(&mut tracker, &run, TrackingAvailability::Available)?;
    let before = tracker.tracker().digest(); let zone = tracker.zone_report().ok_or("zones")?.digest();
    assert!(matches!(tracker.observe(run.inference(), run.report(), admission(run.report().source(), TrackingAvailability::Available)?,
        &mut WorkBudget::new(WORK)), Err(RgbTrackingError::Tracking(ImageTrackingError::ReusedExposure))));
    let mut s = run.report().source(); s.permission_mask = [77; 32];
    assert!(matches!(tracker.observe(run.inference(), run.report(), admission(s, TrackingAvailability::Available)?,
        &mut WorkBudget::new(WORK)), Err(RgbTrackingError::BindingMismatch)));
    assert_eq!(tracker.tracker().digest(), before); assert_eq!(tracker.zone_report().ok_or("zones")?.digest(), zone); Ok(())
}
#[test]
fn complete_selected_class_overflow_never_silently_truncates() -> Test {
    let model = model(65)?; let head = head(&model)?; let run = detection(&model, &head, 240, 1)?;
    assert_eq!(run.report().detections().len(), 130);
    let mut tracker = tracker(&head, tracking_policy())?; let before = tracker.tracker().digest();
    assert!(matches!(tracker.observe(run.inference(), run.report(), admission(run.report().source(), TrackingAvailability::Available)?,
        &mut WorkBudget::new(WORK)), Err(RgbTrackingError::Limit)));
    assert_eq!(tracker.tracker().digest(), before); assert_eq!(tracker.tracker().exposure_count(), 0); Ok(())
}
#[test]
fn every_budget_cut_is_atomic_or_retains_the_exact_pending_zone_input() -> Test {
    let model = model(1)?; let head = head(&model)?;
    let a = detection(&model, &head, 16, 1)?; let b = detection(&model, &head, 240, 2)?;
    let admit = admission(b.report().source(), TrackingAvailability::Available)?;
    let mut reference = tracker(&head, tracking_policy())?; observe(&mut reference, &a, TrackingAvailability::Available)?;
    let mut work = WorkBudget::new(WORK);
    let expected = reference.observe(b.inference(), b.report(), admit, &mut work)?;
    let mut saw_pending = false;
    for limit in 0..work.used() {
        let mut current = tracker(&head, tracking_policy())?; observe(&mut current, &a, TrackingAvailability::Available)?;
        let before = current.tracker().digest();
        match current.observe(b.inference(), b.report(), admit, &mut WorkBudget::new(limit)) {
            Err(_) => {
                assert_eq!(current.tracker().digest(), before); assert_eq!(current.tracker().exposure_count(), 1);
                assert_eq!(current.observe(b.inference(), b.report(), admit, &mut WorkBudget::new(WORK))?, expected);
            }
            Ok(RgbZoneProgress::Pending { .. }) => {
                saw_pending = true; assert_eq!(current.tracker().exposure_count(), 2); assert!(current.zone_report().is_none());
                assert_eq!(current.prepared().ok_or("lost preparation")?.detection_digest(), b.report().digest());
                assert!(matches!(current.observe(b.inference(), b.report(), admit, &mut WorkBudget::new(WORK)), Err(RgbTrackingError::PendingZones)));
                assert_eq!(current.resume(&mut WorkBudget::new(WORK))?, expected);
                assert_eq!(current.resume(&mut WorkBudget::new(0))?, expected);
            }
            Ok(RgbZoneProgress::Complete { .. }) => return Err("insufficient budget completed".into()),
        }
    }
    assert!(saw_pending); Ok(())
}
#[test]
fn cancellation_and_wrong_zone_basis_do_not_consume_input() -> Test {
    let model = model(1)?; let head = head(&model)?; let run = detection(&model, &head, 240, 1)?;
    let mut tracker = tracker(&head, tracking_policy())?; let before = tracker.tracker().digest();
    let flag = std::sync::atomic::AtomicBool::new(true);
    assert!(matches!(tracker.observe(run.inference(), run.report(), admission(run.report().source(), TrackingAvailability::Available)?,
        &mut WorkBudget::cancellable(WORK, &flag)), Err(RgbTrackingError::Work(GeometryError::Cancelled))));
    assert_eq!(tracker.tracker().digest(), before);
    let mut wrong = RgbZoneTracker::new([9; 32], RgbTrackingContract::new(&head, 0, ContentDigest::sha256(b"selected"))?,
        tracking_policy(), ImageZoneBasis { camera: 99, clock: 2, image_domain: [3; 32], calibration: [4; 32], dimensions: [32, 16] },
        ImageZonePolicy { selection_evidence: [8; 32], maximum_sample_gap_ns: 10_000_000_000 },
        &[ImageZoneSpec { id: 1, vertices: vec![[1, 1], [30, 1], [30, 15], [1, 15]], margin: 0, dwell_ns: None }],
        &mut WorkBudget::new(WORK))?;
    assert!(matches!(wrong.observe(run.inference(), run.report(), admission(run.report().source(), TrackingAvailability::Available)?,
        &mut WorkBudget::new(WORK)), Err(RgbTrackingError::BindingMismatch)));
    assert_eq!(wrong.tracker().exposure_count(), 0); Ok(())
}
