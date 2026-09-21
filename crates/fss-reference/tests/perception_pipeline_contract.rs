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

use fss_reference::ingest::eventgen::{ZoneEventConfig, ZoneEventGenerator, ZoneSpec};
use fss_reference::ingest::foreground::{ForegroundConfig, ForegroundDetector};
use fss_reference::ingest::tracker::{Detection, MultiObjectTracker, TrackerConfig};

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

fn foreground() -> ForegroundDetector {
    ForegroundDetector::new(ForegroundConfig {
        base_threshold: 30,
        threshold_sigma: 2,
        learning_rate_num: 1,
        learning_rate_den: 256,
        minimum_region_pixels: 16,
        dimensions: [WIDTH, HEIGHT],
    })
    .expect("foreground config is valid")
}

fn tracker() -> MultiObjectTracker {
    MultiObjectTracker::new(TrackerConfig {
        min_hits: 2,
        max_misses: 3,
        iou_threshold: 0.05,
        process_noise: 1.0,
        measurement_noise: 1.0,
    })
    .expect("tracker config is valid")
}

fn event_generator() -> ZoneEventGenerator {
    let mut zonegen = ZoneEventGenerator::new(ZoneEventConfig {
        policy_generation: ContentDigest::sha256(b"e2e-perception-policy-gen"),
        dedup_cooldown_ns: 500_000_000, // 500 ms
        min_probability: 0.3,
        max_dedup_entries: 16,
    })
    .expect("generator config is valid");
    // Protected zone: right half of the scene.
    zonegen
        .register_zone(ZoneSpec {
            zone_id: "protected_yard".to_string(),
            bounds: (32.0, 0.0, 32.0, 64.0),
            kind: EventKind::PerimeterBreach,
        })
        .expect("zone spec is valid");
    zonegen
}

/// Runs the full pipeline over one frame. Returns generated events, if any.
fn step(
    detector: &mut ForegroundDetector,
    tracker: &mut MultiObjectTracker,
    zonegen: &mut ZoneEventGenerator,
    square_at: Option<(f64, f64)>,
    ts_ns: i128,
) -> Result<Vec<EventHypothesis>, String> {
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
    Ok(events)
}

#[test]
fn pipeline_generates_one_deduplicated_event_for_zone_breach() {
    let mut detector = foreground();
    let mut tracker = tracker();
    let mut zonegen = event_generator();

    let mut all_events = Vec::new();

    // Frame 0: baseline, no square. Detector absorbs background; no detections.
    let events = step(&mut detector, &mut tracker, &mut zonegen, None, 0)
        .expect("frame 0 runs");
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
        .unwrap_or_else(|err| panic!("approach frame {i} runs: {err}"));
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
        .unwrap_or_else(|err| panic!("breach frame {i} runs: {err}"));
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
    event.verify().expect("generated event passes contract");

    // Generator sequencing is sane: one publication consumed.
    assert_eq!(zonegen.generated_count(), 1);
}

#[test]
fn pipeline_event_evidence_digest_matches_input_frame() {
    let mut detector = foreground();
    let mut tracker = tracker();
    let mut zonegen = event_generator();

    // Baseline.
    step(&mut detector, &mut tracker, &mut zonegen, None, 0).unwrap();
    // Approach (unprotected half): 4 -> 10 keeps IoU association alive.
    step(&mut detector, &mut tracker, &mut zonegen, Some((4.0, 28.0)), 33_000_000)
        .unwrap();
    step(&mut detector, &mut tracker, &mut zonegen, Some((10.0, 28.0)), 66_000_000)
        .unwrap();
    // Breach entry: the 10 -> 34 jump exceeds IoU overlap, so the tracker
    // starts a fresh Tentative track here (by design: unconfirmed until a
    // second consecutive hit). No event yet.
    let no_events =
        step(&mut detector, &mut tracker, &mut zonegen, Some((34.0, 28.0)), 99_000_000)
            .unwrap();
    assert!(
        no_events.is_empty(),
        "tentative track inside the zone must not evidence events yet"
    );
    // Second breach frame: association succeeds, track confirms, zone gate
    // passes — the event must bind THIS frame's digest.
    let confirm_pixels = frame(Some((36.0, 28.0)));
    let confirm_digest = ContentDigest::sha256(&confirm_pixels);
    let events =
        step(&mut detector, &mut tracker, &mut zonegen, Some((36.0, 28.0)), 132_000_000)
            .unwrap();
    assert_eq!(events.len(), 1, "confirmation inside the zone must generate exactly one event");
    assert_eq!(
        events[0].evidence[0].digest, confirm_digest,
        "event evidence must bind the digest of the frame that confirmed the breach"
    );
}

#[test]
fn pipeline_without_authority_generates_nothing() {
    let mut detector = foreground();
    let mut tracker = tracker();
    let mut zonegen = event_generator();

    let pixels = frame(Some((34.0, 28.0)));
    let fg = detector.observe(&pixels, WIDTH, HEIGHT).unwrap();
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
            let err = zonegen
                .observe(
                    RuntimeGrant::ObserveStatus,
                    target,
                    &zone_id,
                    "cam-e2e",
                    TimestampNs(0),
                    ContentDigest::sha256(&pixels),
                    0.9,
                )
                .expect_err("ObserveStatus must not authorize event publication");
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
}
