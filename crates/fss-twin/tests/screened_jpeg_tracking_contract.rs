#![forbid(unsafe_code)]
//! Real compressed fixtures, native decoding and source-linked screened trajectories.
use fss_codec_mjpeg::stream::{FramingLimits, JpegStream, StreamBasis};
use fss_codec_mjpeg::{ComponentInterpretation as Color, DecodeBudget, DecodeLimits};
use fss_core::ContentDigest;
use fss_geometry::{GeometryError, PinholeIntrinsics, WorkBudget};
use fss_twin::foreground::pipeline::FrameCapture;
use fss_twin::foreground::{BackgroundPolicy, ForegroundError, ForegroundPolicy};
use fss_twin::image_tracking::{
    ImageDetectionDisposition, ImageTrackingError, ImageTrackingPolicy, TrackingAvailability,
};
use fss_twin::mjpeg::stream::FramedQuery;
use fss_twin::mjpeg::{
    JpegBackground, JpegFrameBinding, JpegReference, decode_rectified, decoded_image_domain,
};
use fss_twin::rectification::{LensDistortion, LumaRange, RectificationPlan, RectificationSpec};
use fss_twin::screened_mjpeg::{
    ForegroundStage, JpegScreeningQuery, ScreenedJpeg, screen_framed_jpeg, screen_jpeg,
};
use fss_twin::screening::tracking::{ScreenedImageTracker, ScreenedTrackingError};
use fss_twin::screening::{HealthFlag, ScreeningMonitor, ScreeningPolicy, ScreeningStamp};
use std::error::Error;
use std::sync::atomic::AtomicBool;

type Test = Result<(), Box<dyn Error>>;
const BG: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/background.jpg");
const IMAGE: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
fn work() -> WorkBudget<'static> {
    WorkBudget::new(100_000_000)
}
fn decode() -> DecodeBudget<'static> {
    DecodeBudget::new(100_000_000)
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    ContentDigest::sha256(bytes).bytes()
}
fn binding(bytes: &[u8], mask: &[u8], exposure: u8) -> JpegFrameBinding {
    JpegFrameBinding {
        encoded_sha256: hash(bytes),
        exposure: [exposure; 32],
        allowed_mask: hash(mask),
        camera_image_domain: [7; 32],
        calibration: [8; 32],
        interpretation: Color::Grayscale,
    }
}
fn plan() -> Result<RectificationPlan, Box<dyn Error>> {
    let k = PinholeIntrinsics::new(17, 13, 20.0, 20.0, 8.5, 6.5)?;
    Ok(RectificationPlan::compile(
        RectificationSpec {
            source: k,
            target: k,
            distortion: LensDistortion::Pinhole,
            maximum_radius: 1.0,
            source_domain: decoded_image_domain([7; 32], Color::Grayscale),
            calibration: [8; 32],
            range: LumaRange::Full,
        },
        &mut work(),
    )?)
}
fn baseline(plan: &RectificationPlan, mask: &[u8]) -> Result<JpegBackground, Box<dyn Error>> {
    let mut images = Vec::new();
    for id in 1..=3 {
        images.push(decode_rectified(
            plan,
            BG,
            mask,
            binding(BG, mask, id),
            DecodeLimits::default(),
            &mut decode(),
            &mut work(),
        )?);
    }
    let selected: Vec<_> = images
        .iter()
        .enumerate()
        .map(|(i, image)| JpegReference {
            image,
            capture: FrameCapture {
                camera: 1,
                clock: 2,
                capture: [(i as u64 + 1) * 10; 2],
            },
        })
        .collect();
    Ok(JpegBackground::build(
        plan,
        &selected,
        BackgroundPolicy {
            selection_evidence: [9; 32],
            validity: [0, 1000],
            maximum_spread: 0,
        },
        &mut work(),
    )?)
}
fn monitor() -> Result<ScreeningMonitor, Box<dyn Error>> {
    Ok(ScreeningMonitor::new(
        ScreeningPolicy {
            minimum_visible_pixels: 16,
            dark_luma: 10,
            bright_luma: 245,
            extreme_per_mille: 900,
            flat_range: 2,
            repeat_frames: 3,
            repeat_duration_ns: 20,
            stall_after_ns: 100,
            maximum_capture_uncertainty_ns: 5,
            recovery_frames: 1,
            minimum_analysis_interval_ns: 5,
            sentinel_interval_ns: 40,
            activity_hold_ns: 10,
        },
        1,
        0,
    )?)
}
fn tracker(generation: u64) -> Result<ScreenedImageTracker, ScreenedTrackingError> {
    ScreenedImageTracker::new(
        [88; 32],
        generation,
        ImageTrackingPolicy {
            maximum_tracks: 64,
            maximum_detections: 64,
            maximum_exposures: 128,
            minimum_observations: 2,
            maximum_misses: 8,
            maximum_gap_ns: 1000,
            maximum_speed: 100,
            gate_padding: 8,
            miss_cost: 100,
            ambiguity_margin: 0,
        },
        &mut work(),
    )
}
fn query(mask: &[u8], sequence: u64) -> JpegScreeningQuery<'_> {
    let time = (sequence + 3) * 10;
    JpegScreeningQuery {
        bytes: IMAGE,
        mask,
        binding: binding(IMAGE, mask, (sequence + 3) as u8),
        capture: FrameCapture {
            camera: 1,
            clock: 2,
            capture: [time; 2],
        },
        foreground_policy: ForegroundPolicy {
            minimum_change: 10,
            minimum_area: 1,
            maximum_regions: 64,
            widespread_per_mille: 1000,
        },
        decode_limits: DecodeLimits::default(),
        stamp: ScreeningStamp {
            stream_generation: 1,
            sequence,
            received_at_ns: time,
            owner_requests_analysis: false,
        },
    }
}
fn screen(
    plan: &RectificationPlan,
    model: Option<&JpegBackground>,
    mask: &[u8],
    monitor: &mut ScreeningMonitor,
    sequence: u64,
    foreground: &mut WorkBudget<'_>,
) -> Result<ScreenedJpeg, Box<dyn Error>> {
    Ok(screen_jpeg(
        monitor,
        model,
        plan,
        query(mask, sequence),
        &mut decode(),
        &mut work(),
        foreground,
        &mut work(),
    )?)
}
#[test]
fn native_jpeg_keeps_exact_compressed_lineage_and_every_foreground_component() -> Test {
    let p = plan()?;
    let mask = [1; 221];
    let model = baseline(&p, &mask)?;
    let mut m = monitor()?;
    let image = screen(&p, Some(&model), &mask, &mut m, 1, &mut work())?;
    let ForegroundStage::Complete(fg) = image.foreground() else {
        return Err("missing foreground".into());
    };
    let mut t = tracker(1)?;
    let result = t.update_jpeg(&image, &mut work())?;
    assert_eq!(result.input_digest(), image.digest());
    assert_eq!(result.tracking().frame().evidence, image.digest());
    assert_eq!(result.tracking().frame().source, image.screening().source());
    assert_eq!(image.source_receipt().source.encoded_sha256, hash(IMAGE));
    assert_eq!(result.tracking().decisions().len(), fg.regions().len());
    assert!(!fg.regions().is_empty());
    for (decision, region) in result.tracking().decisions().iter().zip(fg.regions()) {
        assert_eq!(decision.detection.id, u64::from(region.id));
        assert_eq!(decision.detection.min, region.min);
        assert_eq!(decision.detection.max, region.max);
        assert_eq!(
            decision.detection.partial,
            region.touches_edge || region.touches_unknown
        );
    }
    assert!(result.screening().last_completed_analysis().is_none());
    assert_eq!(m.last_report(), Some(image.screening()));
    Ok(())
}
#[test]
fn a_refused_foreground_stage_is_not_an_empty_success_or_a_spent_exposure() -> Test {
    let p = plan()?;
    let mask = [1; 221];
    let model = baseline(&p, &mask)?;
    let mut m = monitor()?;
    let image = screen(&p, Some(&model), &mask, &mut m, 1, &mut WorkBudget::new(0))?;
    let mut t = tracker(1)?;
    let before = t.digest();
    assert!(matches!(
        t.update_jpeg(&image, &mut work()),
        Err(ScreenedTrackingError::Foreground(
            ForegroundError::Geometry(GeometryError::BudgetExhausted)
        ))
    ));
    assert!(
        image
            .screening()
            .flags()
            .contains(HealthFlag::ForegroundUnavailable)
    );
    assert_eq!(t.digest(), before);
    assert_eq!(t.tracker().exposure_count(), 0);
    assert_eq!(m.last_report(), Some(image.screening()));
    assert!(image.analysis_frame().is_some());
    Ok(())
}
#[test]
fn absent_background_and_fully_masked_images_keep_distinct_states() -> Test {
    let p = plan()?;
    let visible = [1; 221];
    let mut m = monitor()?;
    let absent = screen(&p, None, &visible, &mut m, 1, &mut work())?;
    let mut t = tracker(1)?;
    assert!(matches!(
        t.update_jpeg(&absent, &mut work()),
        Err(ScreenedTrackingError::NotConfigured)
    ));
    let denied = [0; 221];
    let model = baseline(&p, &denied)?;
    let mut m = monitor()?;
    let image = screen(&p, Some(&model), &denied, &mut m, 1, &mut work())?;
    let result = t.update_jpeg(&image, &mut work())?;
    assert_eq!(
        result.tracking().frame().availability,
        TrackingAvailability::Unobservable
    );
    assert!(t.tracker().tracks().is_empty());
    assert!(image.analysis_frame().is_none());
    Ok(())
}
#[test]
fn native_tracking_retry_does_not_rescreen_or_consume_the_exposure_twice() -> Test {
    let p = plan()?;
    let mask = [1; 221];
    let model = baseline(&p, &mask)?;
    let mut m = monitor()?;
    let image = screen(&p, Some(&model), &mask, &mut m, 1, &mut work())?;
    let mut t = tracker(1)?;
    let before = t.digest();
    assert!(matches!(
        t.update_jpeg(&image, &mut WorkBudget::new(0)),
        Err(ScreenedTrackingError::Tracking(
            ImageTrackingError::Geometry(GeometryError::BudgetExhausted)
        ))
    ));
    let cancelled = AtomicBool::new(true);
    assert!(matches!(
        t.update_jpeg(&image, &mut WorkBudget::cancellable(100_000, &cancelled)),
        Err(ScreenedTrackingError::Tracking(
            ImageTrackingError::Geometry(GeometryError::Cancelled)
        ))
    ));
    assert_eq!(t.digest(), before);
    assert_eq!(m.last_report(), Some(image.screening()));
    let expected = tracker(1)?.update_jpeg(&image, &mut work())?.digest();
    assert_eq!(t.update_jpeg(&image, &mut work())?.digest(), expected);
    assert_eq!(t.tracker().exposure_count(), 1);
    assert_eq!(m.last_report(), Some(image.screening()));
    Ok(())
}
#[test]
fn input_lanes_cannot_relabel_an_existing_episode_even_with_the_same_pixels() -> Test {
    let p = plan()?;
    let mask = [1; 221];
    let model = baseline(&p, &mask)?;
    let mut m = monitor()?;
    let image = screen(&p, Some(&model), &mask, &mut m, 1, &mut work())?;
    let ForegroundStage::Complete(fg) = image.foreground() else {
        return Err("missing foreground".into());
    };
    let mut t = tracker(1)?;
    t.update_jpeg(&image, &mut work())?;
    let before = t.digest();
    assert!(matches!(
        t.update_foreground(fg, image.screening(), &mut work()),
        Err(ScreenedTrackingError::BasisMismatch)
    ));
    assert_eq!(t.digest(), before);
    assert_eq!(t.tracker().exposure_count(), 1);
    Ok(())
}
#[test]
fn framed_jpeg_retains_original_stream_byte_range_without_inventing_capture_time() -> Test {
    let p = plan()?;
    let mask = [1; 221];
    let model = baseline(&p, &mask)?;
    let mut m = monitor()?;
    let basis = StreamBasis {
        source: [19; 32],
        generation: 1,
    };
    let mut input = JpegStream::new(basis, FramingLimits::default())?;
    let frame = input
        .push(0, IMAGE, &mut decode())?
        .frame
        .ok_or("missing frame")?;
    input.finish(&mut decode())?;
    let q = query(&mask, 1);
    let actual = screen_framed_jpeg(
        &mut m,
        Some(&model),
        &p,
        FramedQuery {
            expected_stream: basis,
            frame: &frame,
            mask: &mask,
            binding: q.binding,
            capture: q.capture,
            policy: q.foreground_policy,
            limits: q.decode_limits,
        },
        q.stamp,
        &mut decode(),
        &mut work(),
        &mut work(),
        &mut work(),
    )?;
    let mut wrong = tracker(2)?;
    let before = wrong.digest();
    assert!(matches!(
        wrong.update_framed_jpeg(&actual, &mut work()),
        Err(ScreenedTrackingError::BasisMismatch)
    ));
    assert_eq!(wrong.digest(), before);
    let result = tracker(1)?.update_framed_jpeg(&actual, &mut work())?;
    assert_eq!(result.input_digest(), actual.digest());
    let source = result.stream().ok_or("missing stream receipt")?;
    assert_eq!(source.basis, basis);
    assert_eq!(source.ordinal, 1);
    assert_eq!(source.byte_range, [0, IMAGE.len() as u64]);
    assert_eq!(source.encoded_sha256, hash(IMAGE));
    assert_eq!(result.tracking().frame().source.capture, [40; 2]);
    assert_eq!(result.tracking().frame().evidence, actual.digest());
    Ok(())
}
#[test]
fn repeated_real_jpeg_evidence_cannot_confirm_measurements_after_freeze_suspicion() -> Test {
    let p = plan()?;
    let mask = [1; 221];
    let model = baseline(&p, &mask)?;
    let mut m = monitor()?;
    let mut t = tracker(1)?;
    for sequence in 1..=3 {
        let image = screen(&p, Some(&model), &mask, &mut m, sequence, &mut work())?;
        let previous = t.tracker().tracks().to_vec();
        let result = t.update_jpeg(&image, &mut work())?;
        if sequence == 3 {
            assert!(
                result
                    .screening()
                    .flags()
                    .contains(HealthFlag::SuspectedFreeze)
            );
            assert_ne!(
                result.tracking().frame().availability,
                TrackingAvailability::Available
            );
            assert!(
                result
                    .tracking()
                    .decisions()
                    .iter()
                    .all(|d| d.disposition == ImageDetectionDisposition::Unavailable)
            );
            for (old, now) in previous.iter().zip(t.tracker().tracks()) {
                assert_eq!(old.latest(), now.latest());
                assert_eq!(old.observations(), now.observations());
            }
        }
        assert!(result.screening().last_completed_analysis().is_none());
    }
    Ok(())
}
