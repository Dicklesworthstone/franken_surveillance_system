#![forbid(unsafe_code)]
//! Preserve the concurrently added witness/corroboration contracts.
use super::*;
use fss_core::event::EventLineage;
use crate::ingest::cross_camera::CameraObservation;
use std::error::Error;
type TestResult = Result<(), Box<dyn Error>>;
fn track() -> TrackedTarget {
    TrackedTarget { id: 7, status: TrackStatus::Confirmed, cx: 50.0, cy: 60.0,
        vx: 1.0, vy: 0.0, box_w: 20.0, box_h: 40.0, hits: 6, misses: 0 }
}
fn pair() -> AssociatedPair {
    AssociatedPair {
        first: CameraObservation { camera_id: "cam-a".into(), track_id: 7,
            timestamp_ns: 1_000_000_000, ground_x: 50.0, ground_y: 60.0 },
        second: CameraObservation { camera_id: "cam-b".into(), track_id: 3,
            timestamp_ns: 1_010_000_000, ground_x: 51.0, ground_y: 60.0 },
        confidence: 0.94,
    }
}
fn witnessed() -> Result<(ZoneEventGenerator, EventLineage), Box<dyn Error>> {
    let mut g = ZoneEventGenerator::new(ZoneEventConfig {
        policy_generation: ContentDigest::sha256(b"policy"), dedup_cooldown_ns: 1_000_000_000,
        min_probability: 0.4, max_dedup_entries: 64,
    })?;
    g.register_zone(ZoneSpec { zone_id: "driveway".into(), bounds: (0.0, 0.0, 100.0, 100.0), kind: EventKind::UnknownPresence })?;
    let genesis = g.observe(RuntimeGrant::ObserveEvent, &track(), "driveway", "cam-a",
        TimestampNs(1_000_000_000), ContentDigest::sha256(b"frame"), 0.9)?.ok_or("expected genesis")?;
    let mut lineage = EventLineage::new(genesis)?;
    g.witness(RuntimeGrant::ObserveEvent, &mut lineage, &track(), "cam-a",
        TimestampNs(2_000_000_000), ContentDigest::sha256(b"later"))?;
    Ok((g, lineage))
}
#[test]
fn witness_advances_hypothesized_to_witnessed() -> TestResult {
    let (_, l) = witnessed()?;
    assert_eq!(l.current_state(), EventState::Witnessed);
    assert_eq!(l.current_revision(), 2); assert_eq!(l.len(), 2);
    assert!(l.current().supersedes.is_some()); assert_eq!(l.current().evidence.len(), 2);
    assert_eq!(l.current().interval.earliest, TimestampNs(1_000_000_000));
    Ok(())
}
#[test]
fn corroborate_advances_witnessed_to_corroborated() -> TestResult {
    let (g, mut l) = witnessed()?;
    g.corroborate(RuntimeGrant::ObserveEvent, &mut l, &pair(), "cam-b",
        TimestampNs(3_000_000_000), ContentDigest::sha256(b"camera-b"), 0.95)?;
    assert_eq!(l.current_state(), EventState::Corroborated);
    assert_eq!(l.current_revision(), 3); assert_eq!(l.current().evidence.len(), 3);
    assert!(l.current().track_ids.contains(&"track:3".into()));
    assert_eq!(l.current().probability.upper, 0.95);
    let domains: Vec<_> = l.current().evidence.iter().map(|e| e.failure_domain.as_str()).collect();
    assert!(domains.contains(&"cam-a") && domains.contains(&"cam-b"));
    Ok(())
}
#[test]
fn corroboration_refuses_same_failure_domain() -> TestResult {
    let (g, mut l) = witnessed()?;
    assert!(matches!(g.corroborate(RuntimeGrant::ObserveEvent, &mut l, &pair(), "cam-a",
        TimestampNs(3_000_000_000), ContentDigest::sha256(b"new-frame"), 0.95),
        Err(ZoneEventError::SameFailureDomain(d)) if d == "cam-a"));
    assert_eq!(l.current_state(), EventState::Witnessed);
    Ok(())
}
#[test]
fn corroboration_refuses_duplicate_frame_digest() -> TestResult {
    let (g, mut l) = witnessed()?;
    assert!(matches!(g.corroborate(RuntimeGrant::ObserveEvent, &mut l, &pair(), "cam-b",
        TimestampNs(3_000_000_000), ContentDigest::sha256(b"frame"), 0.95),
        Err(ZoneEventError::DuplicateEvidenceDigest)));
    Ok(())
}
#[test]
fn corroboration_requires_capability() -> TestResult {
    let (g, mut l) = witnessed()?;
    assert!(matches!(g.corroborate(RuntimeGrant::ObserveStatus, &mut l, &pair(), "cam-b",
        TimestampNs(3_000_000_000), ContentDigest::sha256(b"camera-b"), 0.95),
        Err(ZoneEventError::CapabilityDenied { .. })));
    assert_eq!(l.current_state(), EventState::Witnessed);
    Ok(())
}
#[test]
fn corroborated_lineage_survives_full_contract_verification() -> TestResult {
    let (g, mut l) = witnessed()?;
    g.corroborate(RuntimeGrant::ObserveEvent, &mut l, &pair(), "cam-b",
        TimestampNs(3_000_000_000), ContentDigest::sha256(b"camera-b"), 0.95)?;
    for revision in l.history() { revision.verify()?; }
    assert_eq!(l.highest_canonical_state(), Some(EventState::Corroborated));
    Ok(())
}
