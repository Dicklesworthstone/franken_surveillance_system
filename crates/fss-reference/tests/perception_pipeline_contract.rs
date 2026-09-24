#![forbid(unsafe_code)]
//! End-to-end perception pipeline contract: luma frames → foreground
//! detection → Kalman tracking → zone membership → capability-gated event
//! generation.
//!
//! Proves the four perception components compose into a working pixels-in to
//! events-out path with no mock layers, using deterministic synthetic frames:
//!
//! 1. A bright square moves across a dark scene toward a protected zone.
//! 2. The foreground detector isolates it; the tracker confirms it.
//! 3. On zone entry the generator publishes one `EventHypothesis` — gated by
//!    `CAP-OBSERVE-EVENT-001`, evidence-bound to the frame digest.
//! 4. Continued presence inside the cooldown dedups to zero further events.

use fss_core::abstraction::runtime_authority::RuntimeGrant;
use fss_core::event::{EventHypothesis, EventKind, EventState};
use fss_core::{ContentDigest, TimestampNs};

use fss_reference::ingest::cross_camera::{CameraObservation, CrossCameraConfig, associate};
use fss_reference::ingest::eventgen::{ZoneEventConfig, ZoneEventGenerator, ZoneSpec};
use fss_reference::ingest::foreground::{ForegroundConfig, ForegroundDetector};
use fss_reference::ingest::tracker::{Detection, MultiObjectTracker, TrackerConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const WIDTH: u32 = 64;
const HEIGHT: u32 = 64;

/// Scene: near-black background; one 8x8 bright square whose top-left corner
/// tracks `x0..x1` over `steps` frames. Frame 0 (baseline) has no square.
fn frame(baseline_square_at: Option<(f64, f64)>) -> Vec<u8> {
    let mut pixels = vec![12u8; (WIDTH * HEIGHT) as usize];
    if let Some((sx, sy)) = baseline_square_at {
        for y in sy as u32..(sy as u32 + 8).min(HEIGHT) {
            for x in sx as u32..(sx as u32 + 8).min(WIDTH) {
                let idx = y as usize * WIDTH as usize + x as usize;
                pixels[idx] = 220;
            }
        }
    }
    pixels
}

fn foreground() -> TestResult<ForegroundDetector> {
    Ok(ForegroundDetector::new(ForegroundConfig {
        base_threshold: 30,
        threshold_sigma: 2,
        learning_rate_num: 1,
        learning_rate_den: 256,
        minimum_region_pixels: 16,
        dimensions: [WIDTH, HEIGHT],
    })?)
}

fn tracker() -> TestResult<MultiObjectTracker> {
    Ok(MultiObjectTracker::new(TrackerConfig {
        min_hits: 2,
        max_misses: 3,
        iou_threshold: 0.05,
        process_noise: 1.0,
        measurement_noise: 1.0,
    })?)
}

fn event_generator() -> TestResult<ZoneEventGenerator> {
    let mut zonegen = ZoneEventGenerator::new(ZoneEventConfig {
        policy_generation: ContentDigest::sha256(b"e2e-perception-policy-gen"),
        dedup_cooldown_ns: 500_000_000, // 500 ms
        min_probability: 0.3,
        max_dedup_entries: 16,
    })?;
    // Protected zone: right half of the scene.
    zonegen.register_zone(ZoneSpec {
        zone_id: "protected_yard".to_string(),
        bounds: (32.0, 0.0, 32.0, 64.0),
        kind: EventKind::PerimeterBreach,
    })?;
    Ok(zonegen)
}

/// Runs the full pipeline over one frame. Returns generated events (if any)
/// together with the tracker output for callers that need track identities.
fn step_with_tracks(
    detector: &mut ForegroundDetector,
    tracker: &mut MultiObjectTracker,
    zonegen: &mut ZoneEventGenerator,
    square_at: Option<(f64, f64)>,
    ts_ns: i128,
) -> Result<
    (
        Vec<EventHypothesis>,
        fss_reference::ingest::tracker::TrackerOutput,
    ),
    String,
> {
    let pixels = frame(square_at);
    let frame_digest = ContentDigest::sha256(&pixels);

    // 1. Foreground detection.
    let fg = detector
        .observe(&pixels, WIDTH, HEIGHT)
        .map_err(|err| format!("foreground: {err}"))?;

    // 2. Detection → tracker.
    let detections: Vec<Detection> = fg
        .boxes
        .iter()
        .map(|b| Detection {
            box_x: f64::from(b.x),
            box_y: f64::from(b.y),
            box_w: f64::from(b.width),
            box_h: f64::from(b.height),
        })
        .collect();
    let output = tracker.step(&detections);

    // 3. Zone-gated event generation for every confirmed track.
    let mut events = Vec::new();
    for target in &output.tracks {
        if let Some(zone) = zonegen.zone_for_target(target) {
            let zone_id = zone.zone_id.clone();
            if let Some(event) = zonegen
                .observe(
                    RuntimeGrant::ObserveEvent,
                    target,
                    &zone_id,
                    "cam-e2e",
                    TimestampNs(ts_ns),
                    frame_digest,
                    0.9,
                )
                .map_err(|err| format!("eventgen: {err}"))?
            {
                events.push(event);
            }
        }
    }
    Ok((events, output))
}

/// Runs the full pipeline over one frame. Returns generated events, if any.
fn step(
    detector: &mut ForegroundDetector,
    tracker: &mut MultiObjectTracker,
    zonegen: &mut ZoneEventGenerator,
    square_at: Option<(f64, f64)>,
    ts_ns: i128,
) -> Result<Vec<EventHypothesis>, String> {
    step_with_tracks(detector, tracker, zonegen, square_at, ts_ns).map(|(events, _)| events)
}

#[test]
fn pipeline_generates_one_deduplicated_event_for_zone_breach() -> TestResult {
    let mut detector = foreground()?;
    let mut tracker = tracker()?;
    let mut zonegen = event_generator()?;

    let mut all_events = Vec::new();

    // Frame 0: baseline, no square. Detector absorbs background; no detections.
    let events = step(&mut detector, &mut tracker, &mut zonegen, None, 0)
        .map_err(|err| format!("frame 0 runs: {err}"))?;
    assert!(events.is_empty());
    all_events.extend(events);

    // Frames 1-2: square approaches in the LEFT (unprotected) half.
    // Tracker confirms during these frames, but no zone is touched.
    for (i, x) in [4.0f64, 10.0].into_iter().enumerate() {
        let events = step(
            &mut detector,
            &mut tracker,
            &mut zonegen,
            Some((x, 28.0)),
            i128::from(i as i64 + 1) * 33_000_000,
        )
        .map_err(|err| format!("approach frame {i} runs: {err}"))?;
        assert!(
            events.is_empty(),
            "movement outside the protected zone must not generate events"
        );
        all_events.extend(events);
    }

    // Frames 3-6: square crosses into the protected zone and stays.
    for i in 3..=6 {
        let x = if i == 3 { 34.0 } else { 36.0 };
        let events = step(
            &mut detector,
            &mut tracker,
            &mut zonegen,
            Some((x, 28.0)),
            i128::from(i) * 33_000_000,
        )
        .map_err(|err| format!("breach frame {i} runs: {err}"))?;
        all_events.extend(events);
    }

    // Exactly one event for the whole presence episode (dedup collapsed
    // frames 4-6), correct kind/state, evidence-bound, contract-valid.
    assert_eq!(
        all_events.len(),
        1,
        "one presence episode must yield exactly one event"
    );
    let event = &all_events[0];
    assert_eq!(event.kind, EventKind::PerimeterBreach);
    assert_eq!(event.state, EventState::Hypothesized);
    assert_eq!(event.zone_ids, vec!["protected_yard"]);
    assert_eq!(event.evidence.len(), 1);
    assert_eq!(event.evidence[0].failure_domain, "cam-e2e");
    event.verify()?;

    // Generator sequencing is sane: one publication consumed.
    assert_eq!(zonegen.generated_count(), 1);
    Ok(())
}

#[test]
fn pipeline_event_evidence_digest_matches_input_frame() -> TestResult {
    let mut detector = foreground()?;
    let mut tracker = tracker()?;
    let mut zonegen = event_generator()?;

    // Baseline.
    step(&mut detector, &mut tracker, &mut zonegen, None, 0)?;
    // Approach (unprotected half): 4 -> 10 keeps IoU association alive.
    step(
        &mut detector,
        &mut tracker,
        &mut zonegen,
        Some((4.0, 28.0)),
        33_000_000,
    )?;
    step(
        &mut detector,
        &mut tracker,
        &mut zonegen,
        Some((10.0, 28.0)),
        66_000_000,
    )?;
    // Breach entry: the 10 -> 34 jump exceeds IoU overlap, so the tracker
    // starts a fresh Tentative track here (by design: unconfirmed until a
    // second consecutive hit). No event yet.
    let no_events = step(
        &mut detector,
        &mut tracker,
        &mut zonegen,
        Some((34.0, 28.0)),
        99_000_000,
    )?;
    assert!(
        no_events.is_empty(),
        "tentative track inside the zone must not evidence events yet"
    );
    // Second breach frame: association succeeds, track confirms, zone gate
    // passes — the event must bind THIS frame's digest.
    let confirm_pixels = frame(Some((36.0, 28.0)));
    let confirm_digest = ContentDigest::sha256(&confirm_pixels);
    let events = step(
        &mut detector,
        &mut tracker,
        &mut zonegen,
        Some((36.0, 28.0)),
        132_000_000,
    )?;
    assert_eq!(
        events.len(),
        1,
        "confirmation inside the zone must generate exactly one event"
    );
    assert_eq!(
        events[0].evidence[0].digest, confirm_digest,
        "event evidence must bind the digest of the frame that confirmed the breach"
    );
    Ok(())
}

#[test]
fn pipeline_without_authority_generates_nothing() -> TestResult {
    let mut detector = foreground()?;
    let mut tracker = tracker()?;
    let mut zonegen = event_generator()?;

    let pixels = frame(Some((34.0, 28.0)));
    let fg = detector.observe(&pixels, WIDTH, HEIGHT)?;
    let detections: Vec<Detection> = fg
        .boxes
        .iter()
        .map(|b| Detection {
            box_x: f64::from(b.x),
            box_y: f64::from(b.y),
            box_w: f64::from(b.width),
            box_h: f64::from(b.height),
        })
        .collect();
    let output = tracker.step(&detections);
    for target in &output.tracks {
        if let Some(zone) = zonegen.zone_for_target(target) {
            let zone_id = zone.zone_id.clone();
            // Wrong grant: publication must be refused with a typed error.
            let Err(err) = zonegen.observe(
                RuntimeGrant::ObserveStatus,
                target,
                &zone_id,
                "cam-e2e",
                TimestampNs(0),
                ContentDigest::sha256(&pixels),
                0.9,
            ) else {
                return Err("ObserveStatus must not authorize event publication".into());
            };
            assert!(
                matches!(
                    err,
                    fss_reference::ingest::eventgen::ZoneEventError::CapabilityDenied { .. }
                ),
                "expected CapabilityDenied, got {err:?}"
            );
        }
    }
    assert_eq!(zonegen.generated_count(), 0);
    Ok(())
}

#[test]
fn two_camera_breach_associates_and_corroborates() -> TestResult {
    // Camera A runs the full pipeline and publishes a corroborated-ready
    // event; camera B independently tracks the same physical square.
    let mut detector_a = foreground()?;
    let mut tracker_a = tracker()?;
    let mut zonegen = event_generator()?;

    // --- Camera A: baseline, approach, breach, confirmation. ---
    step(&mut detector_a, &mut tracker_a, &mut zonegen, None, 0)?;
    step(
        &mut detector_a,
        &mut tracker_a,
        &mut zonegen,
        Some((4.0, 28.0)),
        33_000_000,
    )?;
    step(
        &mut detector_a,
        &mut tracker_a,
        &mut zonegen,
        Some((10.0, 28.0)),
        66_000_000,
    )?;
    step(
        &mut detector_a,
        &mut tracker_a,
        &mut zonegen,
        Some((34.0, 28.0)),
        99_000_000,
    )?;
    let mut events = step(
        &mut detector_a,
        &mut tracker_a,
        &mut zonegen,
        Some((36.0, 28.0)),
        132_000_000,
    )?;
    assert_eq!(
        events.len(),
        1,
        "camera A must publish one zone-breach event"
    );
    let mut lineage = fss_core::event::EventLineage::new(events.remove(0))?;

    // Camera A's own continued observation witnesses the event, using the
    // confirmed track from a later frame with distinct bytes.
    let (_, tracks_a) = step_with_tracks(
        &mut detector_a,
        &mut tracker_a,
        &mut zonegen,
        Some((38.0, 28.0)),
        165_000_000,
    )
    .map_err(|err| format!("camera A witness frame runs: {err}"))?;
    let track_a = tracks_a
        .tracks
        .iter()
        .find(|t| t.status == fss_reference::ingest::tracker::TrackStatus::Confirmed)
        .ok_or("camera A holds a confirmed track")?;
    let witness_digest = ContentDigest::sha256(&frame(Some((38.0, 28.0))));
    zonegen.witness(
        RuntimeGrant::ObserveEvent,
        &mut lineage,
        track_a,
        "cam-e2e",
        TimestampNs(165_000_000),
        witness_digest,
    )?;
    assert_eq!(
        lineage.current_state(),
        fss_core::event::EventState::Witnessed
    );

    // --- Camera B: same square, different viewpoint, own frames. ---
    // B's rectified ground-plane positions land within association gates of
    // A's observation of the same object.
    let ground_truth = (12.5_f64, 7.0_f64);
    let pair_obs = (
        CameraObservation {
            camera_id: "cam-a-rectified".to_string(),
            track_id: track_a.id,
            timestamp_ns: 165_000_000,
            ground_x: ground_truth.0,
            ground_y: ground_truth.1,
        },
        CameraObservation {
            camera_id: "cam-b-rectified".to_string(),
            track_id: 11,
            timestamp_ns: 171_000_000,
            ground_x: ground_truth.0 + 0.4,
            ground_y: ground_truth.1 + 0.1,
        },
    );
    let config = CrossCameraConfig {
        max_time_delta_ns: 50_000_000,
        max_position_distance: 2.0,
        min_confidence: 0.1,
    };
    let pairs = associate(&config, &[pair_obs.0], &[pair_obs.1])?;
    assert_eq!(
        pairs.len(),
        1,
        "the two cameras observe the same physical object"
    );

    // Corroborate with camera B's independent frame bytes and domain.
    // Camera B's viewpoint: same scene, one pixel of parallax — distinct
    // bytes, independent observation.
    let cam_b_digest = ContentDigest::sha256(&frame(Some((35.0, 28.0))));
    zonegen.corroborate(
        RuntimeGrant::ObserveEvent,
        &mut lineage,
        &pairs[0],
        "cam-b-e2e",
        TimestampNs(171_000_000),
        cam_b_digest,
        0.95,
    )?;

    assert_eq!(
        lineage.current_state(),
        fss_core::event::EventState::Corroborated
    );
    assert_eq!(lineage.len(), 3, "genesis -> witnessed -> corroborated");
    let final_event = lineage.current();
    assert_eq!(final_event.evidence.len(), 3);
    assert!(final_event.track_ids.contains(&"track:11".to_string()));
    assert_ne!(
        final_event.evidence[0].digest, final_event.evidence[2].digest,
        "corroborating frame bytes must differ from the originating camera's"
    );
    for revision in lineage.history() {
        revision.verify()?;
    }
    Ok(())
}
