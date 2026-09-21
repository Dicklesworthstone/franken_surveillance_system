#![forbid(unsafe_code)]
//! Actual luma -> frozen-background components -> health -> guarded trajectories.
use std::error::Error;
use std::sync::atomic::AtomicBool;
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, WorkBudget};
use fss_twin::foreground::{BackgroundModel, BackgroundPolicy, ForegroundFrame,
    ForegroundPolicy, ForegroundReport, ForegroundSource};
use fss_twin::image_tracking::{ImageDetectionDisposition, ImageTrackState,
    ImageTrackingError, ImageTrackingPolicy, TrackingAvailability};
use fss_twin::localization::ImageIdentity;
use fss_twin::screening::{AnalysisReason, HealthFlag, ScreeningHealth, ScreeningMonitor,
    ScreeningPolicy, ScreeningReport, ScreeningStamp};
use fss_twin::screening::tracking::{ScreenedImageTracker, ScreenedTrackingError};

type Test = Result<(), Box<dyn Error>>;
const W: u32 = 20;
const H: u32 = 12;
const N: usize = (W * H) as usize;
fn work() -> WorkBudget<'static> { WorkBudget::new(100_000_000) }
fn track_policy() -> ImageTrackingPolicy {
    ImageTrackingPolicy { maximum_tracks: 16, maximum_detections: 16, maximum_exposures: 128,
        minimum_observations: 2, maximum_misses: 8, maximum_gap_ns: 1000, maximum_speed: 10,
        gate_padding: 8, miss_cost: 100, ambiguity_margin: 0 }
}
fn health_policy() -> ScreeningPolicy {
    ScreeningPolicy { minimum_visible_pixels: 1, dark_luma: 10, bright_luma: 245,
        extreme_per_mille: 900, flat_range: 0, repeat_frames: 3, repeat_duration_ns: 20,
        stall_after_ns: 1000, maximum_capture_uncertainty_ns: 5, recovery_frames: 1,
        minimum_analysis_interval_ns: 5, sentinel_interval_ns: 40, activity_hold_ns: 10 }
}
fn tracker() -> Result<ScreenedImageTracker, ScreenedTrackingError> {
    ScreenedImageTracker::new([88; 32], 7, track_policy(), &mut work())
}
fn monitor() -> Result<ScreeningMonitor, Box<dyn Error>> {
    Ok(ScreeningMonitor::new(health_policy(), 7, 0)?)
}
fn detection_policy() -> ForegroundPolicy {
    ForegroundPolicy { minimum_change: 10, minimum_area: 1, maximum_regions: 64, widespread_per_mille: 1000 }
}
fn pixels() -> Vec<u8> { (0..N).map(|i| 100 + (i % 2) as u8 * 20).collect() }
fn source(id: u8, pixels: &[u8]) -> ForegroundSource {
    ForegroundSource { image: ImageIdentity { exposure: [id; 32], pixels: ContentDigest::sha256(pixels).bytes(),
        image_domain: [3; 32], dimensions: [W, H] }, camera: 1, clock: 2,
        calibration: [5; 32], capture: [u64::from(id) * 10; 2] }
}
struct Scene { model: BackgroundModel }
struct Image { report: ForegroundReport, pixels: Vec<u8>, mask: Vec<u8> }
impl Scene {
    fn new() -> Result<Self, Box<dyn Error>> {
        let pixels = pixels(); let mask = vec![1; N]; let mut b = work();
        let frames = (1..=3).map(|id| ForegroundFrame::new(source(id, &pixels), &pixels, &mask, &mut b))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { model: BackgroundModel::build(&frames, BackgroundPolicy {
            selection_evidence: [77; 32], validity: [0, 10_000], maximum_spread: 0 }, &mut b)? })
    }
    fn image(&self, id: u8, boxes: &[[u32; 4]]) -> Result<Image, Box<dyn Error>> {
        let mut pixels = pixels();
        for &[x0, y0, x1, y1] in boxes {
            for y in y0..y1 { for x in x0..x1 { pixels[(y * W + x) as usize] = 200; } }
        }
        self.explicit(id, pixels, vec![1; N], detection_policy())
    }
    fn explicit(&self, id: u8, pixels: Vec<u8>, mask: Vec<u8>, policy: ForegroundPolicy)
        -> Result<Image, Box<dyn Error>> {
        let mut budget = work();
        let frame = ForegroundFrame::new(source(id, &pixels), &pixels, &mask, &mut budget)?;
        Ok(Image { report: self.model.detect(&frame, policy, &mut budget)?, pixels, mask })
    }
}
fn screen(monitor: &mut ScreeningMonitor, image: &Image, sequence: u64, owner: bool)
    -> Result<ScreeningReport, Box<dyn Error>> {
    Ok(monitor.observe(image.report.source(), &image.pixels, &image.mask, Some(&image.report),
        ScreeningStamp { stream_generation: 7, sequence,
            received_at_ns: image.report.source().capture[1], owner_requests_analysis: owner }, &mut work())?)
}
#[test]
fn clean_source_pairs_continue_without_acknowledging_semantic_analysis() -> Test {
    let scene = Scene::new()?; let mut m = monitor()?; let mut t = tracker()?;
    let a = scene.image(4, &[[2,2,4,4]])?; let sa = screen(&mut m, &a, 1, false)?;
    let first = t.update_foreground(&a.report, &sa, &mut work())?;
    assert_eq!(first.screening().health(), ScreeningHealth::NoFaultObserved);
    assert_eq!(first.tracking().decisions()[0].disposition, ImageDetectionDisposition::Started(1));
    assert_eq!(first.tracking().frame().evidence, sa.digest()); assert!(t.requires_analysis());
    let b = scene.image(5, &[[3,2,5,4]])?; let sb = screen(&mut m, &b, 2, t.requires_analysis())?;
    let next = t.update_foreground(&b.report, &sb, &mut work())?;
    assert_eq!(next.prior_digest(), first.digest()); assert_eq!(next.input_digest(), sb.digest());
    assert_eq!(next.tracking().decisions()[0].disposition, ImageDetectionDisposition::Continued(1));
    assert_eq!(t.tracker().tracks()[0].observations(), 2);
    assert_eq!(t.tracker().tracks()[0].latest().frame.source, b.report.source());
    assert!(sb.reasons().contains(AnalysisReason::OwnerRequested));
    assert!(next.screening().last_completed_analysis().is_none());
    assert!(m.last_report().ok_or("missing screen")?.last_completed_analysis().is_none());
    assert_eq!(next.skipped_sequences(), 0); assert!(!next.health_history_gap()); Ok(())
}
#[test]
fn freeze_suspicion_keeps_real_proposals_but_cannot_update_a_track() -> Test {
    let scene = Scene::new()?; let mut m = monitor()?; let mut t = tracker()?;
    for id in 4..=6 {
        let image = scene.image(id, &[[2,2,4,4]])?;
        let health = screen(&mut m, &image, u64::from(id - 3), t.requires_analysis())?;
        let before = t.tracker().tracks().first().copied();
        let update = t.update_foreground(&image.report, &health, &mut work())?;
        if id == 6 {
            assert!(health.flags().contains(HealthFlag::SuspectedFreeze));
            assert_eq!(update.tracking().frame().availability, TrackingAvailability::Disturbed);
            assert_eq!(update.tracking().decisions()[0].disposition, ImageDetectionDisposition::Unavailable);
            assert_eq!(t.tracker().tracks()[0].latest(), before.ok_or("missing track")?.latest());
            assert_eq!(t.tracker().tracks()[0].observations(), 2);
            assert_eq!(t.tracker().tracks()[0].state(), ImageTrackState::Coasting);
        }
    }
    Ok(())
}
#[test]
fn recovery_window_withholds_births_until_clean_observations_are_sufficient() -> Test {
    let scene = Scene::new()?;
    let mut m = ScreeningMonitor::new(ScreeningPolicy { recovery_frames: 2, ..health_policy() }, 7, 0)?;
    let mut t = tracker()?;
    let a = scene.image(4, &[[2,2,4,4]])?; let sa = screen(&mut m, &a, 1, false)?;
    let first = t.update_foreground(&a.report, &sa, &mut work())?;
    assert_eq!(first.screening().health(), ScreeningHealth::Recovering);
    assert_eq!(first.tracking().decisions()[0].disposition, ImageDetectionDisposition::Unavailable);
    assert!(!t.requires_analysis());
    let b = scene.image(5, &[[3,2,5,4]])?; let sb = screen(&mut m, &b, 2, false)?;
    let next = t.update_foreground(&b.report, &sb, &mut work())?;
    assert_eq!(next.tracking().decisions()[0].disposition, ImageDetectionDisposition::Started(1)); Ok(())
}
#[test]
fn a_clean_health_screen_cannot_clear_a_widespread_foreground_disturbance() -> Test {
    let scene = Scene::new()?; let mut m = monitor()?; let mut t = tracker()?;
    let image = scene.explicit(4, pixels().into_iter().map(|v| v + 60).collect(), vec![1; N], detection_policy())?;
    let health = screen(&mut m, &image, 1, false)?;
    assert_eq!(health.health(), ScreeningHealth::NoFaultObserved);
    let result = t.update_foreground(&image.report, &health, &mut work())?;
    assert_eq!(result.tracking().frame().availability, TrackingAvailability::Disturbed);
    assert_eq!(result.tracking().decisions()[0].disposition, ImageDetectionDisposition::Unavailable);
    assert!(t.tracker().tracks().is_empty()); Ok(())
}
#[test]
fn fully_denied_input_is_unobservable_not_an_empty_available_scene() -> Test {
    let scene = Scene::new()?; let mut m = monitor()?; let mut t = tracker()?;
    let image = scene.explicit(4, pixels(), vec![0; N], detection_policy())?;
    let health = screen(&mut m, &image, 1, false)?;
    let result = t.update_foreground(&image.report, &health, &mut work())?;
    assert_eq!(result.tracking().frame().availability, TrackingAvailability::Unobservable);
    assert!(t.tracker().tracks().is_empty()); assert!(!t.requires_analysis()); Ok(())
}
#[test]
fn skipped_tracking_inputs_are_disclosed_and_do_not_create_a_measurement_bridge() -> Test {
    let scene = Scene::new()?; let mut m = monitor()?; let mut t = tracker()?;
    let a = scene.image(4, &[[2,2,4,4]])?; let sa = screen(&mut m, &a, 1, false)?;
    t.update_foreground(&a.report, &sa, &mut work())?; let old = t.tracker().tracks()[0];
    // Health completes an input that this tracker never receives.
    screen(&mut m, &scene.image(5, &[[3,2,5,4]])?, 2, true)?;
    let c = scene.image(6, &[[4,2,6,4]])?; let sc = screen(&mut m, &c, 3, true)?;
    assert_eq!(sc.health(), ScreeningHealth::NoFaultObserved);
    let gap = t.update_foreground(&c.report, &sc, &mut work())?;
    assert_eq!(gap.skipped_sequences(), 1); assert!(gap.health_history_gap());
    assert_eq!(gap.tracking().decisions()[0].disposition, ImageDetectionDisposition::Unavailable);
    assert_eq!(t.tracker().tracks()[0].latest(), old.latest());
    let d = scene.image(7, &[[5,2,7,4]])?; let sd = screen(&mut m, &d, 4, true)?;
    let recovered = t.update_foreground(&d.report, &sd, &mut work())?;
    assert!(!recovered.health_history_gap());
    assert_eq!(recovered.tracking().decisions()[0].disposition, ImageDetectionDisposition::Continued(1)); Ok(())
}
#[test]
fn mismatched_source_mask_and_derivation_are_refused_atomically() -> Test {
    let scene = Scene::new()?; let a = scene.image(4, &[[2,2,4,4]])?;
    let mut m = monitor()?; let sa = screen(&mut m, &a, 1, false)?; let mut t = tracker()?;
    let root = t.digest();
    let b = scene.image(5, &[[2,2,4,4]])?;
    let mut mask = vec![1; N]; mask[0] = 0;
    let masked = scene.explicit(4, a.pixels.clone(), mask, detection_policy())?;
    let changed = scene.explicit(4, a.pixels.clone(), a.mask.clone(),
        ForegroundPolicy { minimum_change: 11, ..detection_policy() })?;
    for other in [&b.report, &masked.report, &changed.report] {
        assert!(matches!(t.update_foreground(other, &sa, &mut work()), Err(ScreenedTrackingError::BasisMismatch)));
        assert_eq!(t.digest(), root); assert!(t.last_screening().is_none());
        assert_eq!(t.tracker().exposure_count(), 0);
    }
    t.update_foreground(&a.report, &sa, &mut work())?; Ok(())
}
#[test]
fn generation_policy_restart_and_sequence_cannot_silently_reinterpret_an_episode() -> Test {
    let scene = Scene::new()?; let a = scene.image(4, &[[2,2,4,4]])?;
    let mut m = monitor()?; let sa = screen(&mut m, &a, 1, false)?; let mut t = tracker()?;
    let mut wrong = ScreenedImageTracker::new([88; 32], 8, track_policy(), &mut work())?;
    assert!(matches!(wrong.update_foreground(&a.report, &sa, &mut work()), Err(ScreenedTrackingError::BasisMismatch)));
    t.update_foreground(&a.report, &sa, &mut work())?; let root = t.digest();
    assert!(matches!(t.update_foreground(&a.report, &sa, &mut work()), Err(ScreenedTrackingError::OutOfOrder)));
    let b = scene.image(5, &[[3,2,5,4]])?;
    for policy in [health_policy(), ScreeningPolicy { recovery_frames: 2, ..health_policy() }] {
        let mut restarted = ScreeningMonitor::new(policy, 7, 0)?;
        let sb = screen(&mut restarted, &b, 2, true)?;
        assert!(matches!(t.update_foreground(&b.report, &sb, &mut work()), Err(ScreenedTrackingError::BasisMismatch)));
    }
    assert_eq!(t.digest(), root); assert_eq!(t.last_screening(), Some(&sa)); Ok(())
}
#[test]
fn joining_a_health_history_does_not_assimilate_across_its_unseen_prefix() -> Test {
    let scene = Scene::new()?; let mut m = monitor()?;
    screen(&mut m, &scene.image(4, &[[2,2,4,4]])?, 1, false)?;
    let b = scene.image(5, &[[3,2,5,4]])?; let sb = screen(&mut m, &b, 2, false)?;
    let mut t = tracker()?; let result = t.update_foreground(&b.report, &sb, &mut work())?;
    assert!(result.health_history_gap()); assert_eq!(result.skipped_sequences(), 0);
    assert_eq!(result.tracking().decisions()[0].disposition, ImageDetectionDisposition::Unavailable);
    assert!(t.tracker().tracks().is_empty()); Ok(())
}
#[test]
fn capacity_failure_preserves_sequence_and_health_for_an_exact_retry() -> Test {
    let scene = Scene::new()?; let mut m = monitor()?;
    let image = scene.image(4, &[[2,2,4,4], [12,2,14,4]])?;
    let health = screen(&mut m, &image, 1, false)?;
    let mut t = ScreenedImageTracker::new([88; 32], 7,
        ImageTrackingPolicy { maximum_detections: 1, ..track_policy() }, &mut work())?;
    let before = t.digest();
    assert!(matches!(t.update_foreground(&image.report, &health, &mut work()),
        Err(ScreenedTrackingError::Tracking(ImageTrackingError::Limit))));
    assert_eq!(t.digest(), before); assert_eq!(t.tracker().exposure_count(), 0);
    assert!(t.last_screening().is_none()); assert_eq!(m.last_report(), Some(&health)); Ok(())
}
#[test]
fn every_work_cut_rolls_back_both_receipt_heads_and_a_retry_is_exact() -> Test {
    let scene = Scene::new()?; let mut m = monitor()?;
    let a = scene.image(4, &[[2,2,4,4]])?; let sa = screen(&mut m, &a, 1, false)?;
    let b = scene.image(5, &[[3,2,5,4]])?; let sb = screen(&mut m, &b, 2, true)?;
    let mut control = tracker()?; control.update_foreground(&a.report, &sa, &mut work())?;
    let mut measured = work(); let expected = control.update_foreground(&b.report, &sb, &mut measured)?;
    assert_eq!(expected.work_units(), measured.used());
    for allowance in 0..measured.used() {
        let mut t = tracker()?; t.update_foreground(&a.report, &sa, &mut work())?;
        let before = t.digest(); let inner = t.tracker().digest(); let tracks = t.tracker().tracks().to_vec();
        assert!(matches!(t.update_foreground(&b.report, &sb, &mut WorkBudget::new(allowance)),
            Err(ScreenedTrackingError::Tracking(ImageTrackingError::Geometry(GeometryError::BudgetExhausted)))), "cut={allowance}");
        assert_eq!(t.digest(), before); assert_eq!(t.tracker().digest(), inner);
        assert_eq!(t.tracker().tracks(), tracks.as_slice()); assert_eq!(t.last_screening(), Some(&sa));
        assert_eq!(t.update_foreground(&b.report, &sb, &mut work())?.digest(), expected.digest());
    }
    let mut t = tracker()?; t.update_foreground(&a.report, &sa, &mut work())?;
    assert_eq!(t.update_foreground(&b.report, &sb, &mut WorkBudget::new(measured.used()))?.digest(), expected.digest()); Ok(())
}
#[test]
fn cancellation_cannot_spend_an_exposure_or_hide_screening_evidence() -> Test {
    let scene = Scene::new()?; let mut m = monitor()?;
    let image = scene.image(4, &[[2,2,4,4]])?; let health = screen(&mut m, &image, 1, false)?;
    let mut t = tracker()?; let before = t.digest(); let cancelled = AtomicBool::new(true);
    assert!(matches!(t.update_foreground(&image.report, &health, &mut WorkBudget::cancellable(100_000, &cancelled)),
        Err(ScreenedTrackingError::Tracking(ImageTrackingError::Geometry(GeometryError::Cancelled)))));
    assert_eq!(t.digest(), before); assert!(t.last_screening().is_none());
    assert_eq!(m.last_report(), Some(&health)); assert_eq!(t.tracker().exposure_count(), 0);
    let expected = tracker()?.update_foreground(&image.report, &health, &mut work())?.digest();
    assert_eq!(t.update_foreground(&image.report, &health, &mut work())?.digest(), expected); Ok(())
}
