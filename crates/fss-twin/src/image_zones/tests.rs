#![forbid(unsafe_code)]
use super::*;
use crate::foreground::ForegroundSource;
use crate::image_tracking::ImageTrackingPolicy;
use crate::localization::ImageIdentity;
use std::sync::atomic::AtomicBool;

type Test = Result<(), Box<dyn std::error::Error>>;
const SECOND: u64 = 1_000_000_000;
fn work() -> WorkBudget<'static> {
    WorkBudget::new(100_000_000)
}
fn tracker() -> Result<ImageTracker, ImageTrackingError> {
    ImageTracker::new(
        [20; 32],
        ImageTrackingPolicy {
            maximum_tracks: 8,
            maximum_detections: 8,
            maximum_exposures: 64,
            minimum_observations: 2,
            maximum_misses: 2,
            maximum_gap_ns: 60 * SECOND,
            maximum_speed: 200,
            gate_padding: 8,
            miss_cost: 1000,
            ambiguity_margin: 0,
        },
        &mut work(),
    )
}
use crate::image_tracking::ImageTrackingError;
fn basis() -> ImageZoneBasis {
    ImageZoneBasis {
        camera: 1,
        clock: 2,
        calibration: [6; 32],
        image_domain: [5; 32],
        dimensions: [100, 100],
    }
}
fn zone() -> ImageZoneSpec {
    ImageZoneSpec {
        id: 1,
        vertices: vec![[40, 10], [90, 10], [90, 90], [40, 90]],
        margin: 0,
        dwell_ns: Some(2 * SECOND),
    }
}
fn policy() -> ImageZonePolicy {
    ImageZonePolicy {
        selection_evidence: [30; 32],
        maximum_sample_gap_ns: 3 * SECOND,
    }
}
fn monitor(t: &ImageTracker) -> Result<ImageZoneMonitor, ImageZoneError> {
    ImageZoneMonitor::new(t, basis(), policy(), &[zone()], &mut work())
}
fn hash(text: String) -> [u8; 32] {
    ContentDigest::sha256(text.as_bytes()).bytes()
}
fn frame(
    exposure: u8,
    capture: [u64; 2],
    availability: TrackingAvailability,
) -> ImageTrackingFrame {
    ImageTrackingFrame {
        source: ForegroundSource {
            image: ImageIdentity {
                exposure: hash(format!("exposure:{exposure}")),
                pixels: [90; 32],
                image_domain: [5; 32],
                dimensions: [100, 100],
            },
            camera: 1,
            clock: 2,
            calibration: [6; 32],
            capture,
        },
        detector: [7; 32],
        permission_mask: [8; 32],
        evidence: hash(format!("report:{exposure}")),
        availability,
    }
}
fn detection(exposure: u8, x: u32) -> ImageDetection {
    ImageDetection {
        id: 1,
        evidence: hash(format!("detection:{exposure}")),
        min: [x, 30],
        max: [x + 8, 40],
        partial: false,
    }
}
fn update(
    t: &mut ImageTracker,
    exposure: u8,
    x: Option<u32>,
) -> Result<ImageTrackingReport, ImageTrackingError> {
    let f = frame(
        exposure,
        [u64::from(exposure) * SECOND; 2],
        TrackingAvailability::Available,
    );
    t.update(
        f,
        &x.map(|x| vec![detection(exposure, x)]).unwrap_or_default(),
        &mut work(),
    )
}
fn kinds(r: &ImageZoneReport) -> Vec<ImageZoneEventKind> {
    r.events().iter().map(|e| e.kind).collect()
}

#[test]
fn entry_boundary_dwell_exit_from_actual_tracking() -> Test {
    let mut t = tracker()?;
    let mut z = monitor(&t)?;
    let r = update(&mut t, 1, Some(20))?;
    assert!(z.observe(&t, &r, &mut work())?.events().is_empty());
    let r = update(&mut t, 2, Some(36))?; // observed box straddles boundary
    assert_eq!(
        z.observe(&t, &r, &mut work())?.cells()[0].relation,
        ImageZoneRelation::Boundary
    );
    let r = update(&mut t, 3, Some(52))?;
    let result = z.observe(&t, &r, &mut work())?;
    assert_eq!(
        kinds(result),
        vec![ImageZoneEventKind::EnteredBetweenObservations]
    );
    assert_eq!(
        result.events()[0]
            .from
            .ok_or("missing entry endpoint")?
            .frame
            .source
            .capture,
        [SECOND; 2]
    );
    let r = update(&mut t, 4, Some(56))?;
    assert!(z.observe(&t, &r, &mut work())?.events().is_empty());
    let r = update(&mut t, 5, Some(58))?;
    let result = z.observe(&t, &r, &mut work())?;
    assert_eq!(kinds(result), vec![ImageZoneEventKind::SampledDwell]);
    assert_eq!(result.cells()[0].inside_samples, 3);
    assert_eq!(result.cells()[0].sampled_span_ns, Some([2 * SECOND; 2]));
    let r = update(&mut t, 6, Some(20))?;
    assert_eq!(
        kinds(z.observe(&t, &r, &mut work())?),
        vec![ImageZoneEventKind::LeftBetweenObservations]
    );
    Ok(())
}
#[test]
fn first_inside_is_not_entry_and_dwell_only_once() -> Test {
    let mut t = tracker()?;
    let mut z = monitor(&t)?;
    let r = update(&mut t, 1, Some(52))?;
    assert_eq!(
        kinds(z.observe(&t, &r, &mut work())?),
        vec![ImageZoneEventKind::ObservedInside]
    );
    for exposure in 2..=5 {
        let r = update(&mut t, exposure, Some(52))?;
        let result = z.observe(&t, &r, &mut work())?;
        assert_eq!(
            kinds(result),
            if exposure == 3 {
                vec![ImageZoneEventKind::SampledDwell]
            } else {
                vec![]
            }
        );
    }
    Ok(())
}
#[test]
fn gaps_break_dwell_and_never_invent_exit_or_reentry() -> Test {
    let mut t = tracker()?;
    let mut z = monitor(&t)?;
    let r = update(&mut t, 1, Some(52))?;
    z.observe(&t, &r, &mut work())?;
    let r = update(&mut t, 2, None)?;
    let result = z.observe(&t, &r, &mut work())?;
    assert_eq!(
        kinds(result),
        vec![ImageZoneEventKind::ObservationInterrupted]
    );
    assert_eq!(result.cells()[0].relation, ImageZoneRelation::Unobserved);
    assert_eq!(result.cells()[0].sampled_span_ns, None);
    assert_eq!(
        result.cells()[0].last_observation.frame.source.capture,
        [SECOND; 2]
    );
    let r = update(&mut t, 3, Some(52))?;
    assert_eq!(
        kinds(z.observe(&t, &r, &mut work())?),
        vec![ImageZoneEventKind::ObservedInside]
    );
    let r = update(&mut t, 4, Some(52))?;
    assert!(z.observe(&t, &r, &mut work())?.events().is_empty());
    Ok(())
}
#[test]
fn disturbed_and_unobservable_frames_cannot_accumulate_inside_time() -> Test {
    for availability in [
        TrackingAvailability::Disturbed,
        TrackingAvailability::Unobservable,
    ] {
        let mut t = tracker()?;
        let mut z = monitor(&t)?;
        let r = update(&mut t, 1, Some(52))?;
        z.observe(&t, &r, &mut work())?;
        let r = t.update(
            frame(2, [2 * SECOND; 2], availability),
            &[detection(2, 52)],
            &mut work(),
        )?;
        let result = z.observe(&t, &r, &mut work())?;
        assert_eq!(
            kinds(result),
            vec![ImageZoneEventKind::ObservationInterrupted]
        );
        assert_eq!(result.cells()[0].inside_samples, 0);
        assert!(matches!(
            result.cells()[0].relation,
            ImageZoneRelation::Disturbed | ImageZoneRelation::Unobservable
        ));
    }
    Ok(())
}
#[test]
fn partial_silhouette_and_ambiguous_assignment_interrupt() -> Test {
    let mut t = tracker()?;
    let mut z = monitor(&t)?;
    let r = update(&mut t, 1, Some(52))?;
    z.observe(&t, &r, &mut work())?;
    let mut d = detection(2, 52);
    d.partial = true;
    let r = t.update(
        frame(2, [2 * SECOND; 2], TrackingAvailability::Available),
        &[d],
        &mut work(),
    )?;
    let result = z.observe(&t, &r, &mut work())?;
    assert_eq!(result.cells()[0].relation, ImageZoneRelation::Partial);
    assert_eq!(
        kinds(result),
        vec![ImageZoneEventKind::ObservationInterrupted]
    );
    let r = update(&mut t, 3, Some(52))?;
    z.observe(&t, &r, &mut work())?;
    let a = detection(4, 52);
    let mut b = a;
    b.id = 2;
    b.evidence = [150; 32];
    let r = t.update(
        frame(4, [4 * SECOND; 2], TrackingAvailability::Available),
        &[a, b],
        &mut work(),
    )?;
    assert!(r.candidates().iter().any(|c| c.ambiguous));
    let result = z.observe(&t, &r, &mut work())?;
    assert_eq!(result.cells()[0].relation, ImageZoneRelation::Unobserved);
    assert_eq!(
        kinds(result),
        vec![ImageZoneEventKind::ObservationInterrupted]
    );
    Ok(())
}
#[test]
fn uncertain_capture_uses_lower_dwell_span_and_upper_gap() -> Test {
    let mut t = tracker()?;
    let mut p = policy();
    p.maximum_sample_gap_ns = 5 * SECOND;
    let mut z = ImageZoneMonitor::new(&t, basis(), p, &[zone()], &mut work())?;
    for (exposure, capture) in [
        (1, [0, SECOND]),
        (2, [2 * SECOND, 3 * SECOND]),
        (3, [3 * SECOND + 1, 4 * SECOND]),
    ] {
        let r = t.update(
            frame(exposure, capture, TrackingAvailability::Available),
            &[detection(exposure, 52)],
            &mut work(),
        )?;
        let result = z.observe(&t, &r, &mut work())?;
        if exposure == 2 {
            assert_eq!(
                result.cells()[0].sampled_span_ns,
                Some([SECOND, 3 * SECOND])
            );
            assert!(result.events().is_empty());
        }
        if exposure == 3 {
            assert_eq!(kinds(result), vec![ImageZoneEventKind::SampledDwell]);
        }
    }
    let mut t = tracker()?;
    let mut z = monitor(&t)?;
    let r = t.update(
        frame(1, [0, SECOND], TrackingAvailability::Available),
        &[detection(1, 52)],
        &mut work(),
    )?;
    z.observe(&t, &r, &mut work())?;
    let r = t.update(
        frame(2, [2 * SECOND, 4 * SECOND], TrackingAvailability::Available),
        &[detection(2, 52)],
        &mut work(),
    )?;
    let result = z.observe(&t, &r, &mut work())?;
    assert_eq!(result.cells()[0].inside_samples, 1);
    assert_eq!(
        kinds(result),
        vec![
            ImageZoneEventKind::ObservedInside,
            ImageZoneEventKind::ObservationInterrupted
        ]
    );
    Ok(())
}
#[test]
fn track_expiry_is_not_zone_exit() -> Test {
    let mut t = tracker()?;
    let mut z = monitor(&t)?;
    let r = update(&mut t, 1, Some(52))?;
    z.observe(&t, &r, &mut work())?;
    for exposure in 2..=4 {
        let r = update(&mut t, exposure, None)?;
        let result = z.observe(&t, &r, &mut work())?;
        if exposure == 4 {
            assert_eq!(kinds(result), vec![ImageZoneEventKind::TrackExpired]);
            assert_eq!(result.cells()[0].relation, ImageZoneRelation::Expired);
        }
        assert!(!kinds(result).contains(&ImageZoneEventKind::LeftBetweenObservations));
    }
    Ok(())
}
#[test]
fn exact_retry_is_idempotent_and_skipping_is_refused() -> Test {
    let mut t = tracker()?;
    let mut z = monitor(&t)?;
    let r = update(&mut t, 1, Some(52))?;
    let first = z.observe(&t, &r, &mut work())?.digest();
    assert_eq!(z.observe(&t, &r, &mut WorkBudget::new(0))?.digest(), first);
    let skipped = update(&mut t, 2, Some(52))?;
    let next = update(&mut t, 3, Some(52))?;
    assert!(matches!(
        z.observe(&t, &next, &mut work()),
        Err(ImageZoneError::TrackingOrder)
    ));
    assert!(matches!(
        z.observe(&t, &skipped, &mut work()),
        Err(ImageZoneError::TrackingOrder)
    ));
    assert_eq!(z.digest(), first);
    Ok(())
}
#[test]
fn every_budget_cut_is_atomic_and_retry_reproduces_result() -> Test {
    let mut t = tracker()?;
    let mut z = monitor(&t)?;
    let r = update(&mut t, 1, Some(52))?;
    let before = z.digest();
    let prior_tracking = z.tracking_digest();
    let mut measure = work();
    let expected = z.observe(&t, &r, &mut measure)?.digest();
    // Bind each new monitor to the same original tracker seed, not its new position.
    for cut in 0..measure.used() {
        let original = tracker()?;
        let mut retry = monitor(&original)?;
        assert_eq!(retry.digest(), before);
        assert!(matches!(
            retry.observe(&t, &r, &mut WorkBudget::new(cut)),
            Err(ImageZoneError::Geometry(GeometryError::BudgetExhausted))
        ));
        assert_eq!(retry.digest(), before);
        assert_eq!(retry.tracking_digest(), prior_tracking);
        assert!(retry.latest().is_none());
        assert_eq!(retry.observe(&t, &r, &mut work())?.digest(), expected);
    }
    Ok(())
}
#[test]
fn cancellation_and_basis_refusal_leave_monitor_unchanged() -> Test {
    let mut t = tracker()?;
    let mut z = monitor(&t)?;
    let before = z.digest();
    let r = update(&mut t, 1, Some(52))?;
    let flag = AtomicBool::new(true);
    assert!(matches!(
        z.observe(&t, &r, &mut WorkBudget::cancellable(100000, &flag)),
        Err(ImageZoneError::Geometry(GeometryError::Cancelled))
    ));
    assert_eq!(z.digest(), before);
    let original = tracker()?;
    let mut wrong = basis();
    wrong.camera = 2;
    let mut z = ImageZoneMonitor::new(&original, wrong, policy(), &[zone()], &mut work())?;
    let before = z.digest();
    assert!(matches!(
        z.observe(&t, &r, &mut work()),
        Err(ImageZoneError::BasisMismatch)
    ));
    assert_eq!(z.digest(), before);
    Ok(())
}
#[test]
fn polygon_winding_rotation_and_zone_order_are_canonical() -> Test {
    let t = tracker()?;
    let mut rotated = zone();
    rotated.vertices.reverse();
    rotated.vertices.rotate_left(2);
    let one = ImageZoneMonitor::new(&t, basis(), policy(), &[zone()], &mut work())?;
    let two = ImageZoneMonitor::new(&t, basis(), policy(), &[rotated], &mut work())?;
    assert_eq!(one.digest(), two.digest());
    let mut other = zone();
    other.id = 2;
    other.margin = 1;
    let one = ImageZoneMonitor::new(&t, basis(), policy(), &[zone(), other.clone()], &mut work())?;
    let two = ImageZoneMonitor::new(&t, basis(), policy(), &[other, zone()], &mut work())?;
    assert_eq!(one.digest(), two.digest());
    Ok(())
}
#[test]
fn malformed_and_nonconvex_zones_refuse() -> Test {
    let t = tracker()?;
    for vertices in [
        vec![[10, 10], [90, 90], [10, 90], [90, 10]], // crossed
        vec![[10, 10], [90, 10], [50, 40], [90, 90], [10, 90]], // concave
        vec![[10, 10], [90, 10], [90, 10], [10, 90]], // duplicate
        vec![[10, 10], [50, 10], [90, 10], [10, 90]], // collinear
        vec![[10, 10], [101, 10], [10, 90]],
    ] {
        let mut invalid = zone();
        invalid.vertices = vertices;
        assert!(matches!(
            ImageZoneMonitor::new(&t, basis(), policy(), &[invalid], &mut work()),
            Err(ImageZoneError::InvalidInput)
        ));
    }
    assert!(matches!(
        ImageZoneMonitor::new(&t, basis(), policy(), &[zone(), zone()], &mut work()),
        Err(ImageZoneError::InvalidInput)
    ));
    assert!(matches!(
        ImageZoneMonitor::new(
            &t,
            basis(),
            policy(),
            &vec![zone(); MAX_IMAGE_ZONES + 1],
            &mut work()
        ),
        Err(ImageZoneError::Limit)
    ));
    Ok(())
}
#[test]
fn whole_box_boundaries_slack_and_rectangle_separating_axes() -> Test {
    let z = geometry::normalize(&zone(), [100, 100], &mut work())?;
    for (x, expected) in [
        (20, ImageZoneRelation::Outside),
        (32, ImageZoneRelation::Boundary),
        (40, ImageZoneRelation::Boundary),
        (41, ImageZoneRelation::Inside),
        (82, ImageZoneRelation::Boundary),
    ] {
        assert_eq!(
            geometry::classify(&z, detection(1, x), &mut work())?,
            expected
        );
    }
    let mut slack = z.clone();
    slack.margin = 2;
    assert_eq!(
        geometry::classify(&slack, detection(1, 41), &mut work())?,
        ImageZoneRelation::Boundary
    );
    // All polygon-edge half-planes intersect this rectangle, but the X axis separates.
    let diamond = ImageZoneSpec {
        id: 1,
        vertices: vec![[40, 50], [50, 40], [60, 50], [50, 60]],
        margin: 0,
        dwell_ns: None,
    };
    let diamond = geometry::normalize(&diamond, [100, 100], &mut work())?;
    let d = ImageDetection {
        min: [61, 0],
        max: [70, 100],
        ..detection(1, 20)
    };
    assert_eq!(
        geometry::classify(&diamond, d, &mut work())?,
        ImageZoneRelation::Outside
    );
    Ok(())
}
