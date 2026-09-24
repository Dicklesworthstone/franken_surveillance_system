#![forbid(unsafe_code)]
//! Original generator behavior retained while admission becomes transactional.
use super::*;
use std::error::Error;
type TestResult = Result<(), Box<dyn Error>>;
fn config() -> ZoneEventConfig {
    ZoneEventConfig {
        policy_generation: ContentDigest::sha256(b"policy"),
        dedup_cooldown_ns: 1_000_000_000,
        min_probability: 0.4,
        max_dedup_entries: 64,
    }
}
fn target() -> TrackedTarget {
    TrackedTarget {
        id: 7,
        status: TrackStatus::Confirmed,
        cx: 50.0,
        cy: 60.0,
        vx: 1.0,
        vy: 0.0,
        box_w: 20.0,
        box_h: 40.0,
        hits: 6,
        misses: 0,
    }
}
fn zone(id: &str) -> ZoneSpec {
    ZoneSpec {
        zone_id: id.into(),
        bounds: (0.0, 0.0, 100.0, 100.0),
        kind: EventKind::UnknownPresence,
    }
}
fn generator() -> Result<ZoneEventGenerator, ZoneEventError> {
    let mut g = ZoneEventGenerator::new(config())?;
    g.register_zone(zone("driveway"))?;
    Ok(g)
}
fn observe(
    g: &mut ZoneEventGenerator,
    t: &TrackedTarget,
    z: &str,
    ns: i128,
    digest: ContentDigest,
    upper: f64,
) -> Result<Option<EventHypothesis>, ZoneEventError> {
    g.observe(
        RuntimeGrant::ObserveEvent,
        t,
        z,
        "cam-a",
        TimestampNs(ns),
        digest,
        upper,
    )
}
fn frame() -> ContentDigest {
    ContentDigest::sha256(b"frame")
}
fn required(e: Option<EventHypothesis>) -> Result<EventHypothesis, Box<dyn Error>> {
    e.ok_or_else(|| "expected hypothesis".into())
}
#[test]
fn confirmed_track_in_registered_zone_generates_event() -> TestResult {
    let event = required(observe(
        &mut generator()?,
        &target(),
        "driveway",
        10,
        frame(),
        0.9,
    )?)?;
    assert_eq!(event.kind, EventKind::UnknownPresence);
    assert_eq!(event.state, EventState::Hypothesized);
    assert_eq!(event.revision, 1);
    assert_eq!(event.zone_ids, vec!["driveway"]);
    assert_eq!(event.track_ids, vec!["track:7"]);
    assert_eq!(event.evidence.len(), 1);
    assert_eq!(event.evidence[0].digest, frame());
    assert_eq!(event.evidence[0].failure_domain, "cam-a");
    assert!(event.evidence[0].supports);
    assert_eq!(
        event.decision_path.policy_generation,
        config().policy_generation
    );
    Ok(())
}
#[test]
fn tentative_track_does_not_generate() -> TestResult {
    let mut t = target();
    t.status = TrackStatus::Tentative;
    assert!(observe(&mut generator()?, &t, "driveway", 10, frame(), 0.9)?.is_none());
    Ok(())
}
#[test]
fn track_outside_zone_does_not_generate() -> TestResult {
    let mut t = target();
    t.cx = 150.0;
    assert!(observe(&mut generator()?, &t, "driveway", 10, frame(), 0.9)?.is_none());
    Ok(())
}
#[test]
fn capability_gate_denies_wrong_grant() -> TestResult {
    let mut g = generator()?;
    assert!(matches!(
        g.observe(
            RuntimeGrant::ObserveStatus,
            &target(),
            "driveway",
            "cam-a",
            TimestampNs(10),
            frame(),
            0.9
        ),
        Err(ZoneEventError::CapabilityDenied { .. })
    ));
    assert_eq!(g.generated_count(), 0);
    Ok(())
}
#[test]
fn dedup_suppresses_repeat_within_cooldown() -> TestResult {
    let mut g = generator()?;
    let t = target();
    assert!(observe(&mut g, &t, "driveway", 10_000_000_000, frame(), 0.9)?.is_some());
    assert!(observe(&mut g, &t, "driveway", 10_100_000_000, frame(), 0.9)?.is_none());
    assert!(observe(&mut g, &t, "driveway", 12_000_000_000, frame(), 0.9)?.is_some());
    Ok(())
}
#[test]
fn distinct_zones_track_pairs_do_not_cross_dedup() -> TestResult {
    let mut g = generator()?;
    let mut porch = zone("porch");
    porch.kind = EventKind::PerimeterBreach;
    g.register_zone(porch)?;
    let a = required(observe(&mut g, &target(), "driveway", 10, frame(), 0.9)?)?;
    let b = required(observe(&mut g, &target(), "porch", 10, frame(), 0.9)?)?;
    assert_eq!(a.kind, EventKind::UnknownPresence);
    assert_eq!(b.kind, EventKind::PerimeterBreach);
    Ok(())
}
#[test]
fn unregistered_zone_is_error() -> TestResult {
    assert!(matches!(
        observe(&mut generator()?, &target(), "missing", 10, frame(), 0.9),
        Err(ZoneEventError::UnregisteredZone(_))
    ));
    Ok(())
}
#[test]
fn decision_fingerprint_is_deterministic_and_input_sensitive() -> TestResult {
    let mut a = generator()?;
    let mut b = generator()?;
    let first = required(observe(&mut a, &target(), "driveway", 10, frame(), 0.9)?)?;
    let same = required(observe(&mut b, &target(), "driveway", 10, frame(), 0.9)?)?;
    assert_eq!(
        first.decision_path.fingerprint,
        same.decision_path.fingerprint
    );
    let changed = required(observe(
        &mut a,
        &target(),
        "driveway",
        2_000_000_010,
        ContentDigest::sha256(b"different"),
        0.9,
    )?)?;
    assert_ne!(
        first.decision_path.fingerprint,
        changed.decision_path.fingerprint
    );
    Ok(())
}
#[test]
fn probability_interval_is_bounded_and_ordered() -> TestResult {
    let mut g = generator()?;
    let a = required(observe(&mut g, &target(), "driveway", 10, frame(), 0.9)?)?;
    assert_eq!((a.probability.lower, a.probability.upper), (0.4, 0.9));
    let b = required(observe(
        &mut g,
        &target(),
        "driveway",
        2_000_000_010,
        frame(),
        5.0,
    )?)?;
    assert_eq!(b.probability.upper, 1.0);
    Ok(())
}
#[test]
fn zone_registration_validates_input() -> TestResult {
    let mut g = generator()?;
    for id in ["", "bad:colon"] {
        assert!(g.register_zone(zone(id)).is_err());
    }
    let mut flat = zone("flat");
    flat.bounds.2 = 0.0;
    assert!(g.register_zone(flat).is_err());
    for id in ["dup", "ok_zone-1"] {
        g.register_zone(zone(id))?;
        assert!(g.register_zone(zone(id)).is_err());
    }
    Ok(())
}
#[test]
fn config_validates_bounds() {
    let mut c = config();
    c.dedup_cooldown_ns = 0;
    assert!(ZoneEventGenerator::new(c).is_err());
    c = config();
    c.max_dedup_entries = 0;
    assert!(ZoneEventGenerator::new(c).is_err());
    c = config();
    c.max_dedup_entries = MAX_EVENT_TRACKS + 1;
    assert!(ZoneEventGenerator::new(c).is_err());
    c = config();
    c.min_probability = 1.5;
    assert!(ZoneEventGenerator::new(c).is_err());
}
