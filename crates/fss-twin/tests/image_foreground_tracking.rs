#![forbid(unsafe_code)]
//! Pixel-to-trajectory integration: no model script, supplied detections or metric twin.
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, WorkBudget};
use fss_twin::foreground::{BackgroundModel, BackgroundPolicy, ForegroundFrame, ForegroundPolicy,
    ForegroundReport, ForegroundSource, FrameAssessment};
use fss_twin::image_tracking::{ImageDetectionDisposition, ImageTracker, ImageTrackingError,
    ImageTrackingPolicy, ImageTrackState, TrackingAvailability};
use fss_twin::localization::ImageIdentity;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const WIDTH: usize = 64;
const HEIGHT: usize = 16;
const SECOND: u64 = 1_000_000_000;
fn key(value: u64) -> [u8; 32] { ContentDigest::sha256(&value.to_le_bytes()).bytes() }
fn budget() -> WorkBudget<'static> { WorkBudget::new(100_000_000) }
fn source(sequence: u64, pixels: &[u8]) -> ForegroundSource {
    ForegroundSource { image: ImageIdentity { exposure: key(sequence),
        pixels: ContentDigest::sha256(pixels).bytes(), image_domain: key(1000),
        dimensions: [WIDTH as u32, HEIGHT as u32] }, camera: 1, clock: 1,
        calibration: key(2000), capture: [sequence * SECOND, sequence * SECOND] }
}
fn detector() -> ForegroundPolicy {
    ForegroundPolicy { minimum_change: 10, minimum_area: 4, maximum_regions: 32,
        widespread_per_mille: 800 }
}
fn tracking() -> ImageTrackingPolicy {
    ImageTrackingPolicy { maximum_tracks: 16, maximum_detections: 16, maximum_exposures: 64,
        minimum_observations: 2, maximum_misses: 3, maximum_gap_ns: 20 * SECOND,
        maximum_speed: 100, gate_padding: 2, miss_cost: 1000, ambiguity_margin: 0 }
}
fn tracker() -> TestResult<ImageTracker> { Ok(ImageTracker::new(key(3000), tracking(), &mut budget())?) }
fn background(allowed: &[u8], selection: u64) -> TestResult<BackgroundModel> {
    let pixels = vec![40; WIDTH * HEIGHT];
    let mut frames = Vec::new();
    for n in 1..=3 { frames.push(ForegroundFrame::new(source(n, &pixels), &pixels, allowed, &mut budget())?); }
    Ok(BackgroundModel::build(&frames, BackgroundPolicy { selection_evidence: key(selection),
        validity: [0, 1000 * SECOND], maximum_spread: 2 }, &mut budget())?)
}
fn pixels(boxes: &[[usize; 4]]) -> Vec<u8> {
    let mut pixels = vec![40; WIDTH * HEIGHT];
    for &[left, top, right, bottom] in boxes {
        for y in top..bottom { for x in left..right { pixels[y * WIDTH + x] = 200; } }
    }
    pixels
}
fn detect(model: &BackgroundModel, sequence: u64, pixels: &[u8], allowed: &[u8],
    policy: ForegroundPolicy) -> TestResult<ForegroundReport> {
    let frame = ForegroundFrame::new(source(sequence, pixels), pixels, allowed, &mut budget())?;
    Ok(model.detect(&frame, policy, &mut budget())?)
}

#[test]
fn actual_luma_regions_form_paths_and_stopped_targets_are_not_learned_away() -> TestResult {
    let allowed = vec![1; WIDTH * HEIGHT]; let model = background(&allowed, 4000)?;
    let mut tracker = tracker()?;
    for (sequence, x) in [(4, 4), (5, 7), (6, 10), (7, 10)] {
        let image = pixels(&[[x, 5, x + 4, 9]]);
        let foreground = detect(&model, sequence, &image, &allowed, detector())?;
        assert_eq!(foreground.assessment(), FrameAssessment::LocalChange);
        let report = tracker.update_foreground(&foreground, &mut budget())?;
        assert_eq!(report.frame().evidence, foreground.digest());
        assert_eq!(report.frame().source, foreground.source());
        assert_eq!(tracker.tracks().len(), 1);
        assert_eq!(tracker.tracks()[0].id(), 1);
        assert_eq!(tracker.tracks()[0].latest().detection.min, [x as u32, 5]);
        assert_eq!(tracker.tracks()[0].observations(), (sequence - 3) as u32);
    }
    assert_eq!(tracker.tracks()[0].state(), ImageTrackState::Established);
    Ok(())
}
#[test]
fn merged_components_keep_both_old_paths_unresolved() -> TestResult {
    let allowed = vec![1; WIDTH * HEIGHT]; let model = background(&allowed, 4000)?;
    let mut tracker = tracker()?;
    let first = detect(&model, 4, &pixels(&[[8, 5, 12, 9], [24, 5, 28, 9]]), &allowed, detector())?;
    tracker.update_foreground(&first, &mut budget())?;
    let merged = detect(&model, 5, &pixels(&[[8, 5, 28, 9]]), &allowed, detector())?;
    assert_eq!(merged.regions().len(), 1);
    let report = tracker.update_foreground(&merged, &mut budget())?;
    assert_eq!(report.candidates().len(), 2);
    assert_eq!(report.decisions()[0].disposition, ImageDetectionDisposition::Unresolved);
    assert_eq!(tracker.tracks().len(), 2);
    assert!(tracker.tracks().iter().all(|t| t.state() == ImageTrackState::Coasting && t.observations() == 1));
    Ok(())
}
#[test]
fn widespread_scene_change_is_not_assimilated_or_replaced_with_births() -> TestResult {
    let allowed = vec![1; WIDTH * HEIGHT]; let model = background(&allowed, 4000)?;
    let mut tracker = tracker()?;
    tracker.update_foreground(&detect(&model, 4, &pixels(&[[8, 5, 12, 9]]), &allowed, detector())?, &mut budget())?;
    let prior = tracker.tracks()[0].latest();
    let report = tracker.update_foreground(&detect(&model, 5, &[200; WIDTH * HEIGHT], &allowed, detector())?, &mut budget())?;
    assert_eq!(report.frame().availability, TrackingAvailability::Disturbed);
    assert_eq!(report.decisions()[0].disposition, ImageDetectionDisposition::Unavailable);
    assert_eq!(tracker.tracks()[0].latest(), prior);
    assert_eq!(tracker.tracks()[0].misses(), 1);
    assert_eq!(tracker.tracks().len(), 1);
    Ok(())
}
#[test]
fn unknown_comparison_pixels_do_not_certify_absence() -> TestResult {
    let denied = vec![0; WIDTH * HEIGHT]; let model = background(&denied, 4000)?;
    let mut tracker = tracker()?;
    let foreground = detect(&model, 4, &pixels(&[[8, 5, 12, 9]]), &denied, detector())?;
    let report = tracker.update_foreground(&foreground, &mut budget())?;
    assert_eq!(foreground.comparable_pixels(), 0);
    assert_eq!(report.frame().availability, TrackingAvailability::Unobservable);
    assert!(tracker.tracks().is_empty());
    Ok(())
}
#[test]
fn privacy_background_and_detector_changes_require_a_new_episode() -> TestResult {
    let allowed = vec![1; WIDTH * HEIGHT]; let model = background(&allowed, 4000)?;
    let mut tracker = tracker()?; let image = pixels(&[[8, 5, 12, 9]]);
    tracker.update_foreground(&detect(&model, 4, &image, &allowed, detector())?, &mut budget())?;
    let prior = tracker.digest(); let tracks = tracker.tracks().to_vec();
    let mut denied = allowed.clone(); denied[0] = 0;
    let mut changed_policy = detector(); changed_policy.minimum_change += 1;
    let changed_model = background(&allowed, 4001)?;
    let reports = [detect(&model, 5, &image, &denied, detector())?,
        detect(&model, 5, &image, &allowed, changed_policy)?,
        detect(&changed_model, 5, &image, &allowed, detector())?];
    for report in &reports {
        assert!(matches!(tracker.update_foreground(report, &mut budget()), Err(ImageTrackingError::BasisMismatch)));
        assert_eq!(tracker.digest(), prior); assert_eq!(tracker.tracks(), tracks.as_slice());
        assert_eq!(tracker.exposure_count(), 1);
    }
    Ok(())
}
#[test]
fn region_ceiling_refuses_complete_frame_without_silent_top_k() -> TestResult {
    let allowed = vec![1; WIDTH * HEIGHT]; let model = background(&allowed, 4000)?;
    let mut policy = tracking(); policy.maximum_detections = 1;
    let mut tracker = ImageTracker::new(key(3000), policy, &mut budget())?;
    let prior = tracker.digest();
    let report = detect(&model, 4, &pixels(&[[8, 5, 12, 9], [24, 5, 28, 9]]), &allowed, detector())?;
    assert_eq!(report.regions().len(), 2);
    assert!(matches!(tracker.update_foreground(&report, &mut budget()), Err(ImageTrackingError::Limit)));
    assert_eq!(tracker.digest(), prior); assert!(tracker.tracks().is_empty());
    Ok(())
}
#[test]
fn size_omissions_and_partial_boundaries_remain_source_linked() -> TestResult {
    let allowed = vec![1; WIDTH * HEIGHT]; let model = background(&allowed, 4000)?;
    let mut tracker = tracker()?;
    let foreground = detect(&model, 4, &pixels(&[[0, 5, 4, 9], [30, 5, 31, 6]]), &allowed, detector())?;
    assert_eq!(foreground.small_component_count(), 1);
    assert_eq!(foreground.small_component_pixels(), 1);
    let report = tracker.update_foreground(&foreground, &mut budget())?;
    assert_eq!(report.frame().evidence, foreground.digest());
    assert_eq!(report.decisions().len(), 1);
    assert!(report.decisions()[0].detection.partial);
    assert_ne!(report.decisions()[0].detection.evidence, foreground.digest());
    Ok(())
}
#[test]
fn unmatched_foreground_does_not_become_new_observations_and_reacquisition_reuses_path() -> TestResult {
    let allowed = vec![1; WIDTH * HEIGHT]; let model = background(&allowed, 4000)?;
    let mut tracker = tracker()?;
    tracker.update_foreground(&detect(&model, 4, &pixels(&[[8, 5, 12, 9]]), &allowed, detector())?, &mut budget())?;
    let observed = tracker.tracks()[0].latest();
    let empty = detect(&model, 5, &pixels(&[]), &allowed, detector())?;
    tracker.update_foreground(&empty, &mut budget())?;
    assert_eq!(tracker.tracks()[0].latest(), observed);
    assert_eq!(tracker.tracks()[0].state(), ImageTrackState::Coasting);
    let recovered = detect(&model, 6, &pixels(&[[12, 5, 16, 9]]), &allowed, detector())?;
    tracker.update_foreground(&recovered, &mut budget())?;
    assert_eq!(tracker.tracks()[0].id(), 1); assert_eq!(tracker.tracks()[0].observations(), 2);
    Ok(())
}
#[test]
fn failed_preparation_and_replay_do_not_age_tracks() -> TestResult {
    let allowed = vec![1; WIDTH * HEIGHT]; let model = background(&allowed, 4000)?;
    let mut tracker = tracker()?;
    let report = detect(&model, 4, &pixels(&[[8, 5, 12, 9]]), &allowed, detector())?;
    let prior = tracker.digest();
    assert!(matches!(tracker.update_foreground(&report, &mut WorkBudget::new(511)),
        Err(ImageTrackingError::Geometry(GeometryError::BudgetExhausted))));
    assert_eq!(tracker.digest(), prior); assert_eq!(tracker.exposure_count(), 0);
    tracker.update_foreground(&report, &mut budget())?;
    let prior = tracker.digest();
    assert!(matches!(tracker.update_foreground(&report, &mut budget()), Err(ImageTrackingError::ReusedExposure)));
    assert_eq!(tracker.digest(), prior); assert_eq!(tracker.tracks()[0].observations(), 1);
    Ok(())
}
