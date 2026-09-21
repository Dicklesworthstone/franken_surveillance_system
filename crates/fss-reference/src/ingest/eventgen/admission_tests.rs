#![forbid(unsafe_code)]
//! Retry, capture uncertainty, complete-state limits and source-isolation regressions.
use super::*;
use std::error::Error;
type TestResult = Result<(), Box<dyn Error>>;
fn generator() -> Result<ZoneEventGenerator, ZoneEventError> {
    let mut g = ZoneEventGenerator::new(ZoneEventConfig {
        policy_generation: ContentDigest::sha256(b"policy"), dedup_cooldown_ns: 10, min_probability: 0.0, max_dedup_entries: MAX_EVENT_TRACKS,
    })?;
    g.register_zone(ZoneSpec { zone_id: "yard".into(), bounds: (0.0, 0.0, 100.0, 100.0), kind: EventKind::Unclassified })?;
    Ok(g)
}
fn target() -> TrackedTarget {
    TrackedTarget { id: 1, status: TrackStatus::Confirmed, cx: 10.0, cy: 20.0,
        vx: 0.0, vy: 0.0, box_w: 2.0, box_h: 3.0, hits: 5, misses: 0 }
}
fn input(target: &TrackedTarget) -> ZoneObservation<'_> {
    ZoneObservation { source_generation: "camera-a:stream-1", target, zone_id: "yard", failure_domain: "shared-power",
        capture: CaptureInterval::point(TimestampNs(100)), frame_digest: ContentDigest::sha256(b"pixels"), upper_probability: 1.0 }
}
fn run(g: &mut ZoneEventGenerator, input: ZoneObservation<'_>) -> Result<Option<EventHypothesis>, ZoneEventError> {
    g.observe_interval(RuntimeGrant::ObserveEvent, input)
}
fn required(event: Option<EventHypothesis>) -> Result<EventHypothesis, Box<dyn Error>> {
    event.ok_or_else(|| "expected generated hypothesis".into())
}
#[test]
fn invalid_score_does_not_poison_retry_or_consume_sequence() -> TestResult {
    for upper in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let mut g = generator()?; let t = target(); let mut request = input(&t); request.upper_probability = upper;
        assert!(matches!(run(&mut g, request), Err(ZoneEventError::InvalidConfig(_))));
        assert_eq!(g.generated_count(), 0); assert!(g.last_emitted.is_empty());
        let actual = required(run(&mut g, input(&t))?)?;
        let expected = required(run(&mut generator()?, input(&t))?)?;
        assert_eq!(actual, expected); assert_eq!(g.generated_count(), 1);
    }
    Ok(())
}
#[test]
fn overlong_failure_domain_does_not_suppress_corrected_retry() -> TestResult {
    let mut g = generator()?; let t = target(); let domain = "x".repeat(MAX_FAILURE_DOMAIN_LEN + 1);
    let mut request = input(&t); request.failure_domain = &domain;
    assert!(matches!(run(&mut g, request), Err(ZoneEventError::InvalidConfig(_))));
    assert_eq!(g.generated_count(), 0); assert!(g.last_emitted.is_empty());
    assert!(run(&mut g, input(&t))?.is_some());
    Ok(())
}
#[test]
fn capture_uncertainty_controls_dedup_and_is_not_collapsed() -> TestResult {
    let mut g = generator()?; let t = target(); let mut request = input(&t);
    request.capture = CaptureInterval::new(TimestampNs(100), TimestampNs(120))?;
    assert_eq!(required(run(&mut g, request)?)?.interval, request.capture);
    request.capture = CaptureInterval::new(TimestampNs(125), TimestampNs(200))?;
    assert!(run(&mut g, request)?.is_none(), "earliest-to-latest gap is only five");
    request.capture = CaptureInterval::new(TimestampNs(130), TimestampNs(210))?;
    assert_eq!(required(run(&mut g, request)?)?.interval, request.capture);
    assert_eq!(g.generated_count(), 2);
    Ok(())
}
#[test]
fn cameras_sharing_failure_domain_keep_independent_tracks() -> TestResult {
    let mut g = generator()?; let t = target(); let mut request = input(&t);
    let a = required(run(&mut g, request)?)?;
    request.source_generation = "camera-b:stream-1";
    let b = required(run(&mut g, request)?)?;
    assert_ne!(a.event_id, b.event_id);
    assert_eq!(a.evidence[0].failure_domain, b.evidence[0].failure_domain);
    assert_eq!(g.generated_count(), 2);
    assert!(run(&mut g, request)?.is_none());
    Ok(())
}
#[test]
fn regressed_and_overflowing_time_are_typed_and_atomic() -> TestResult {
    let mut g = generator()?; let t = target(); let mut request = input(&t);
    required(run(&mut g, request)?)?;
    request.capture = CaptureInterval::point(TimestampNs(99));
    assert!(matches!(run(&mut g, request), Err(ZoneEventError::ClockReversed)));
    assert_eq!(g.generated_count(), 1);
    let mut g = generator()?;
    g.last_emitted.insert((request.source_generation.into(), request.zone_id.into(), t.id),
        CaptureInterval::point(TimestampNs(i128::MIN)));
    request.capture = CaptureInterval::point(TimestampNs(i128::MAX));
    assert!(matches!(run(&mut g, request), Err(ZoneEventError::TimeOrder)));
    assert_eq!(g.generated_count(), 0); assert_eq!(g.last_emitted.len(), 1);
    Ok(())
}
#[test]
fn sequence_exhaustion_leaves_cooldowns_unchanged() -> TestResult {
    let mut g = generator()?; g.event_seq = u64::MAX; let t = target();
    assert!(matches!(run(&mut g, input(&t)), Err(ZoneEventError::SequenceExhausted)));
    assert_eq!(g.generated_count(), u64::MAX); assert!(g.last_emitted.is_empty());
    Ok(())
}
#[test]
fn nonfinite_zones_and_overflowing_extents_are_refused() -> TestResult {
    let mut g = generator()?;
    for bounds in [(f64::NAN, 0.0, 1.0, 1.0), (0.0, f64::INFINITY, 1.0, 1.0),
        (0.0, 0.0, f64::NAN, 1.0), (f64::MAX, 0.0, f64::MAX, 1.0)] {
        let zone = ZoneSpec { zone_id: "bad".into(), bounds, kind: EventKind::Unclassified };
        assert!(!zone.contains(1.0, 1.0));
        assert!(matches!(g.register_zone(zone), Err(ZoneEventError::InvalidZoneSpec(_))));
    }
    assert_eq!(g.zones.len(), 1);
    Ok(())
}
#[test]
fn nonfinite_track_and_predicted_sighting_do_not_create_events() -> TestResult {
    let mut g = generator()?; let mut t = target(); t.cx = f64::NAN;
    assert!(matches!(run(&mut g, input(&t)), Err(ZoneEventError::InvalidConfig(_))));
    t = target(); t.misses = 1;
    assert!(run(&mut g, input(&t))?.is_none());
    assert_eq!(g.generated_count(), 0); assert!(g.last_emitted.is_empty());
    Ok(())
}
#[test]
fn zone_capacity_is_exact_without_silent_replacement() -> TestResult {
    let mut g = generator()?;
    for n in 1..MAX_EVENT_ZONES {
        g.register_zone(ZoneSpec { zone_id: format!("z{n}"), bounds: (0.0, 0.0, 1.0, 1.0), kind: EventKind::Unclassified })?;
    }
    assert_eq!(g.zones.len(), MAX_EVENT_ZONES);
    assert!(matches!(g.register_zone(ZoneSpec { zone_id: "overflow".into(),
        bounds: (0.0, 0.0, 1.0, 1.0), kind: EventKind::Unclassified }), Err(ZoneEventError::CapacityExceeded("zones"))));
    assert_eq!(g.zones.len(), MAX_EVENT_ZONES);
    assert_eq!(g.zones[0].zone_id, "yard");
    Ok(())
}
#[test]
fn track_capacity_refuses_new_key_but_allows_existing_key() -> TestResult {
    let mut g = generator()?; let mut t = target(); let request = input(&t);
    for id in 0..MAX_EVENT_TRACKS as u64 {
        g.last_emitted.insert((request.source_generation.into(), request.zone_id.into(), id), request.capture);
    }
    t.id = MAX_EVENT_TRACKS as u64;
    assert!(matches!(run(&mut g, input(&t)), Err(ZoneEventError::Limit)));
    assert_eq!(g.generated_count(), 0); assert_eq!(g.last_emitted.len(), MAX_EVENT_TRACKS);
    t.id = 0; let mut next = input(&t); next.capture = CaptureInterval::point(TimestampNs(110));
    assert!(run(&mut g, next)?.is_some());
    assert_eq!(g.last_emitted.len(), MAX_EVENT_TRACKS); assert_eq!(g.generated_count(), 1);
    Ok(())
}
#[test]
fn denied_capability_precedes_other_refusals() -> TestResult {
    let mut g = generator()?; let t = target(); let mut request = input(&t);
    request.source_generation = ""; request.zone_id = "missing"; request.upper_probability = f64::NAN;
    assert!(matches!(g.observe_interval(RuntimeGrant::ObserveStatus, request),
        Err(ZoneEventError::CapabilityDenied { required: "CAP-OBSERVE-EVENT-001" })));
    assert_eq!(g.generated_count(), 0); assert!(g.last_emitted.is_empty());
    Ok(())
}

#[test]
fn expired_capacity_is_reclaimed_only_after_successful_admission() -> TestResult {
    let mut g = generator()?; g.config.max_dedup_entries = 1;
    let mut t = target(); required(run(&mut g, input(&t))?)?;
    t.id = 2; let mut next = input(&t);
    assert!(matches!(run(&mut g, next), Err(ZoneEventError::Limit)));
    next.capture = CaptureInterval::point(TimestampNs(110));
    next.upper_probability = f64::NAN;
    assert!(matches!(run(&mut g, next), Err(ZoneEventError::InvalidConfig(_))));
    assert_eq!(g.generated_count(), 1); assert_eq!(g.clock, Some(100));
    assert!(g.last_emitted.keys().any(|key| key.2 == 1));
    next.upper_probability = 1.0;
    assert!(run(&mut g, next)?.is_some());
    assert_eq!(g.last_emitted.len(), 1); assert_eq!(g.clock, Some(110));
    assert!(g.last_emitted.keys().all(|key| key.2 == 2));
    t.id = 1;
    assert!(matches!(run(&mut g, input(&t)), Err(ZoneEventError::ClockReversed)));
    Ok(())
}
