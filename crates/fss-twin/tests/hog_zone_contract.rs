#![forbid(unsafe_code)]
//! Real pixel/kernel/screen/tracker/zone composition with SYNTHETIC test weights.
//! These fixtures do not establish pedestrian or event-classification quality.
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_twin::foreground::*;
use fss_twin::hog::{HOG_PARAMETERS, HogModel};
use fss_twin::hog_scan::*;
use fss_twin::image_tracking::{ImageTrackingError, ImageTrackingPolicy, TrackingAvailability};
use fss_twin::image_zones::pipeline::{ImageZonePipeline, ZonePipelineError, ZonePipelineProgress};
use fss_twin::image_zones::{ImageZoneBasis, ImageZoneEventKind, ImageZonePolicy, ImageZoneSpec};
use fss_twin::localization::ImageIdentity;
use fss_twin::screening::tracking::hog::{HogZoneError, HogZonePipeline};
use fss_twin::screening::{
    ScreeningHealth, ScreeningMonitor, ScreeningPolicy, ScreeningReport, ScreeningStamp,
};
use std::error::Error;
use std::sync::atomic::AtomicBool;

type Test = Result<(), Box<dyn Error>>;
const BUDGET: u64 = 100_000_000;
fn policy() -> ScreeningPolicy {
    ScreeningPolicy {
        minimum_visible_pixels: 16,
        dark_luma: 5,
        bright_luma: 250,
        extreme_per_mille: 900,
        flat_range: 2,
        repeat_frames: 100,
        repeat_duration_ns: 500,
        stall_after_ns: 1_000_000,
        maximum_capture_uncertainty_ns: 10,
        recovery_frames: 1,
        minimum_analysis_interval_ns: 0,
        sentinel_interval_ns: 1000,
        activity_hold_ns: 1000,
    }
}
fn pixels() -> Vec<u8> {
    (0..80 * 144).map(|i| (40 + i % 140) as u8).collect()
}
fn source(n: u8, pixels: &[u8]) -> ForegroundSource {
    ForegroundSource {
        image: ImageIdentity {
            exposure: [n; 32],
            pixels: ContentDigest::sha256(pixels).bytes(),
            image_domain: [2; 32],
            dimensions: [80, 144],
        },
        camera: 1,
        clock: 1,
        calibration: [3; 32],
        capture: [u64::from(n) * 1000; 2],
    }
}
fn model(bias: f32) -> Result<HogModel, Box<dyn Error>> {
    let mut bytes = vec![0_u8; HOG_PARAMETERS * 4];
    bytes[(HOG_PARAMETERS - 1) * 4..].copy_from_slice(&bias.to_le_bytes());
    Ok(HogModel::from_f32_le(
        &bytes,
        ContentDigest::sha256(&bytes).bytes(),
        [200; 32],
        &mut WorkBudget::new(BUDGET),
    )?)
}
fn sample(
    monitor: &mut ScreeningMonitor,
    n: u8,
    model: &HogModel,
) -> Result<(HogScan, ScreeningReport), Box<dyn Error>> {
    let pixels = pixels();
    let mask = vec![1; pixels.len()];
    let mut budget = WorkBudget::new(BUDGET);
    let refs: Vec<_> = (1..=3)
        .map(|n| ForegroundFrame::new(source(n, &pixels), &pixels, &mask, &mut budget))
        .collect::<Result<_, _>>()?;
    let background = BackgroundModel::build(
        &refs,
        BackgroundPolicy {
            selection_evidence: [9; 32],
            validity: [0, u64::MAX],
            maximum_spread: 0,
        },
        &mut budget,
    )?;
    let src = source(n, &pixels);
    let frame = ForegroundFrame::new(src, &pixels, &mask, &mut budget)?;
    let foreground = background.detect(
        &frame,
        ForegroundPolicy {
            minimum_change: 10,
            minimum_area: 1,
            maximum_regions: 16,
            widespread_per_mille: 900,
        },
        &mut budget,
    )?;
    assert_eq!(foreground.changed_pixels(), 0); // Learned detection is NOT motion-gated.
    let screen = monitor.observe(
        src,
        &pixels,
        &mask,
        Some(&foreground),
        ScreeningStamp {
            stream_generation: 1,
            sequence: u64::from(n),
            received_at_ns: u64::from(n) * 1000,
            owner_requests_analysis: true,
        },
        &mut budget,
    )?;
    let scan = scan_hog(
        src,
        &pixels,
        &mask,
        model,
        &[ScanLevel {
            dimensions: [80, 144],
        }],
        ScanPolicy {
            stride: [8, 8],
            minimum_margin: 0.5,
            suppression_iou_ppm: 1_000_000,
            maximum_windows: 16,
            maximum_candidates: 16,
        },
        &mut budget,
    )?;
    assert_eq!(scan.selected().count(), 9);
    Ok((scan, screen))
}
fn pipeline(maximum_detections: usize) -> Result<HogZonePipeline, Box<dyn Error>> {
    let mut budget = WorkBudget::new(BUDGET);
    let p = ImageZonePipeline::new(
        [50; 32],
        ImageTrackingPolicy {
            maximum_tracks: 16,
            maximum_detections,
            maximum_exposures: 32,
            minimum_observations: 2,
            maximum_misses: 10,
            maximum_gap_ns: 100_000,
            maximum_speed: 1_000_000,
            gate_padding: 2,
            miss_cost: 1000,
            ambiguity_margin: 0,
        },
        ImageZoneBasis {
            camera: 1,
            clock: 1,
            calibration: [3; 32],
            image_domain: [2; 32],
            dimensions: [80, 144],
        },
        ImageZonePolicy {
            selection_evidence: [10; 32],
            maximum_sample_gap_ns: 100_000,
        },
        &[ImageZoneSpec {
            id: 1,
            vertices: vec![[0, 0], [80, 0], [80, 144], [0, 144]],
            margin: 0,
            dwell_ns: Some(1000),
        }],
        &mut budget,
    )?;
    Ok(HogZonePipeline::new(p, 1, &mut budget)?)
}
#[test]
fn learned_scans_reach_sampled_zone_events_even_without_foreground_motion() -> Test {
    let mut monitor = ScreeningMonitor::new(policy(), 1, 0)?;
    let model = model(1.0)?;
    let (first, a) = sample(&mut monitor, 4, &model)?;
    let (second, b) = sample(&mut monitor, 5, &model)?;
    assert_eq!(a.health(), ScreeningHealth::NoFaultObserved);
    assert_eq!(b.health(), ScreeningHealth::NoFaultObserved);
    let mut p = pipeline(16)?;
    for (scan, screen) in [(&first, &a), (&second, &b)] {
        assert!(matches!(
            p.observe(scan, screen, &mut WorkBudget::new(BUDGET))?,
            ZonePipelineProgress::Complete { .. }
        ));
        assert_eq!(p.scan_digest(), Some(scan.digest()));
        assert_eq!(p.last_screening(), Some(screen));
    }
    assert_eq!(p.pipeline().tracker().tracks().len(), 9);
    assert!(
        p.pipeline()
            .tracker()
            .tracks()
            .iter()
            .all(|t| t.observations() == 2)
    );
    let zones = p.pipeline().zone_report().ok_or("missing zone result")?;
    assert!(
        zones
            .events()
            .iter()
            .any(|e| e.kind == ImageZoneEventKind::SampledDwell)
    );
    assert!(p.pipeline().foreground_digest().is_none());
    assert!(
        monitor
            .last_report()
            .ok_or("no screen")?
            .last_completed_analysis()
            .is_none()
    );
    Ok(())
}
#[test]
fn freeze_health_prevents_assimilation_and_sampled_dwell() -> Test {
    let mut health = policy();
    health.repeat_frames = 2;
    let mut monitor = ScreeningMonitor::new(health, 1, 0)?;
    let model = model(1.0)?;
    let (first, a) = sample(&mut monitor, 4, &model)?;
    let (second, b) = sample(&mut monitor, 5, &model)?;
    assert_eq!(b.health(), ScreeningHealth::Degraded);
    let mut p = pipeline(16)?;
    p.observe(&first, &a, &mut WorkBudget::new(BUDGET))?;
    p.observe(&second, &b, &mut WorkBudget::new(BUDGET))?;
    let tracking = p.pipeline().tracking_report().ok_or("missing tracking")?;
    assert_eq!(
        tracking.frame().availability,
        TrackingAvailability::Disturbed
    );
    assert!(
        p.pipeline()
            .tracker()
            .tracks()
            .iter()
            .all(|t| t.observations() == 1 && t.misses() == 1)
    );
    assert!(
        !p.pipeline()
            .zone_report()
            .ok_or("missing zones")?
            .events()
            .iter()
            .any(|e| e.kind == ImageZoneEventKind::SampledDwell)
    );
    Ok(())
}
#[test]
fn mismatched_screen_and_model_generation_refuse_without_consumption() -> Test {
    let mut monitor = ScreeningMonitor::new(policy(), 1, 0)?;
    let model_a = model(1.0)?;
    let (first, a) = sample(&mut monitor, 4, &model_a)?;
    let (second, b) = sample(&mut monitor, 5, &model_a)?;
    let mut p = pipeline(16)?;
    assert_eq!(
        p.observe(&first, &b, &mut WorkBudget::new(BUDGET)),
        Err(HogZoneError::BasisMismatch)
    );
    assert_eq!(p.pipeline().tracker().exposure_count(), 0);
    p.observe(&first, &a, &mut WorkBudget::new(BUDGET))?;
    let mut other = ScreeningMonitor::new(policy(), 1, 0)?;
    let (changed, _) = sample(&mut other, 5, &model(2.0)?)?;
    assert_eq!(
        p.observe(&changed, &b, &mut WorkBudget::new(BUDGET)),
        Err(HogZoneError::Pipeline(ZonePipelineError::Tracking(
            ImageTrackingError::BasisMismatch
        )))
    );
    assert_eq!(p.pipeline().tracker().exposure_count(), 1);
    assert_eq!(p.scan_digest(), Some(first.digest()));
    p.observe(&second, &b, &mut WorkBudget::new(BUDGET))?;
    assert_eq!(p.pipeline().tracker().exposure_count(), 2);
    Ok(())
}
#[test]
fn skipped_health_history_is_retained_and_cannot_bridge_zone_dwell() -> Test {
    let mut monitor = ScreeningMonitor::new(policy(), 1, 0)?;
    let model = model(1.0)?;
    let (first, a) = sample(&mut monitor, 4, &model)?;
    let _omitted = sample(&mut monitor, 5, &model)?;
    let (third, c) = sample(&mut monitor, 6, &model)?;
    let mut p = pipeline(16)?;
    p.observe(&first, &a, &mut WorkBudget::new(BUDGET))?;
    p.observe(&third, &c, &mut WorkBudget::new(BUDGET))?;
    assert!(p.health_history_gap());
    assert_eq!(
        p.pipeline()
            .tracking_report()
            .ok_or("no tracking")?
            .frame()
            .availability,
        TrackingAvailability::Disturbed
    );
    assert!(
        p.pipeline()
            .tracker()
            .tracks()
            .iter()
            .all(|t| t.observations() == 1)
    );
    Ok(())
}
#[test]
fn complete_capacity_and_cancellation_refusals_keep_both_cursors_unchanged() -> Test {
    let mut monitor = ScreeningMonitor::new(policy(), 1, 0)?;
    let (scan, screen) = sample(&mut monitor, 4, &model(1.0)?)?;
    let mut limited = pipeline(1)?;
    assert_eq!(
        limited.observe(&scan, &screen, &mut WorkBudget::new(BUDGET)),
        Err(HogZoneError::Pipeline(ZonePipelineError::Tracking(
            ImageTrackingError::Limit
        )))
    );
    assert_eq!(limited.pipeline().tracker().exposure_count(), 0);
    assert!(limited.last_screening().is_none());
    let mut p = pipeline(16)?;
    let flag = AtomicBool::new(true);
    assert!(
        p.observe(&scan, &screen, &mut WorkBudget::cancellable(BUDGET, &flag))
            .is_err()
    );
    assert_eq!(p.pipeline().tracker().exposure_count(), 0);
    assert!(p.last_screening().is_none());
    Ok(())
}
#[test]
fn accepted_tracking_survives_zone_budget_refusal_and_resumes_without_rescanning() -> Test {
    let mut monitor = ScreeningMonitor::new(policy(), 1, 0)?;
    let model = model(1.0)?;
    let (first, a) = sample(&mut monitor, 4, &model)?;
    let (second, b) = sample(&mut monitor, 5, &model)?;
    let mut expected = pipeline(16)?;
    expected.observe(&first, &a, &mut WorkBudget::new(BUDGET))?;
    let mut measured = WorkBudget::new(BUDGET);
    let complete = expected.observe(&second, &b, &mut measured)?;
    let mut pending_seen = false;
    for limit in [
        0,
        1023,
        1024,
        measured.used() / 2,
        measured.used() - 1,
        measured.used(),
    ] {
        let mut p = pipeline(16)?;
        p.observe(&first, &a, &mut WorkBudget::new(BUDGET))?;
        match p.observe(&second, &b, &mut WorkBudget::new(limit)) {
            Err(_) => {
                assert_eq!(p.pipeline().tracker().exposure_count(), 1);
                assert_eq!(p.scan_digest(), Some(first.digest()));
                assert_eq!(
                    p.observe(&second, &b, &mut WorkBudget::new(BUDGET))?,
                    complete
                );
            }
            Ok(ZonePipelineProgress::Pending { .. }) => {
                pending_seen = true;
                assert_eq!(p.pipeline().tracker().exposure_count(), 2);
                assert_eq!(p.scan_digest(), Some(second.digest()));
                assert_eq!(p.last_screening(), Some(&b));
                assert!(p.pipeline().zone_report().is_none());
                assert_eq!(
                    p.observe(&second, &b, &mut WorkBudget::new(BUDGET)),
                    Err(HogZoneError::Pipeline(ZonePipelineError::PendingAnalysis))
                );
                assert_eq!(p.resume(&mut WorkBudget::new(BUDGET))?, complete);
                assert_eq!(p.pipeline().tracker().exposure_count(), 2);
            }
            Ok(done) => assert_eq!(done, complete),
        }
    }
    assert!(pending_seen);
    Ok(())
}
