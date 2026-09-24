#![forbid(unsafe_code)]
//! Pure contracts of the corroboration composition: homography admission and projection, the
//! worst-case interval time gate, plan validation, and the zone-entry policy's independence rule.
//! The end-to-end pipeline on real retained bytes is exercised through the binaries
//! (crates/fss-cli/tests/corroborate_cli_contract.rs); synthetic scenes prove wiring only.

use super::*;
use crate::ReferencePolicyAction;
use fss_core::{EventState, TimestampNs};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const IDENTITY: [f64; 9] = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0];

fn interval(earliest: i128, latest: i128) -> TestResult<CaptureInterval> {
    Ok(CaptureInterval::new(
        TimestampNs(earliest),
        TimestampNs(latest),
    )?)
}

fn plan() -> CorroborationPlan {
    let camera = |name: &str, seed: &[u8], matrix| CorroborationCamera {
        name: name.to_owned(),
        import_identity: ContentDigest::sha256(seed),
        homography: GroundHomography { matrix },
    };
    CorroborationPlan {
        cameras: [
            camera("east", b"east", IDENTITY),
            camera(
                "west",
                b"west",
                [-1.0, 0.0, 96.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
            ),
        ],
        interpretation: ComponentInterpretation::Grayscale,
        zones: vec![GroundZone {
            zone_id: "door".to_owned(),
            x: 56.0,
            y: 0.0,
            width: 40.0,
            height: 48.0,
        }],
        gates: CorroborationGates {
            time_gate_ns: 250_000_000,
            distance_gate: 16.0,
        },
        detector: WatchDetectorConfig::default(),
        tracker: WatchTrackerConfig::default(),
    }
}

#[test]
fn homography_admission_refuses_non_finite_zero_and_singular_matrices() {
    assert!(GroundHomography { matrix: IDENTITY }.validate().is_ok());
    let mut nan = IDENTITY;
    nan[4] = f64::NAN;
    assert!(GroundHomography { matrix: nan }.validate().is_err());
    assert!(GroundHomography { matrix: [0.0; 9] }.validate().is_err());
    // Rank two: the third row repeats the first.
    let singular = [1.0, 2.0, 3.0, 0.0, 1.0, 4.0, 1.0, 2.0, 3.0];
    assert!(GroundHomography { matrix: singular }.validate().is_err());
}

#[test]
fn projection_applies_the_owner_matrix_and_refuses_the_horizon() {
    let mirror = GroundHomography {
        matrix: [-1.0, 0.0, 96.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
    };
    assert_eq!(mirror.project(16.0, 24.0), Some((80.0, 24.0)));
    // w = 0.01 * v - 1: points with v <= 100 lie at or beyond the horizon.
    let tilted = GroundHomography {
        matrix: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.01, -1.0],
    };
    assert!(tilted.validate().is_ok());
    assert_eq!(tilted.project(0.0, 100.0), None);
    assert_eq!(tilted.project(0.0, 50.0), None);
    assert!(tilted.project(0.0, 200.0).is_some());
    assert_ne!(
        mirror.digest(),
        GroundHomography { matrix: IDENTITY }.digest()
    );
}

#[test]
fn time_gate_uses_the_worst_case_over_both_conservative_intervals() -> TestResult {
    // Midpoints coincide, but the widest admissible reading is 20 apart.
    let wide = interval(0, 20)?;
    let narrow = interval(9, 11)?;
    assert_eq!(worst_case_separation(wide, narrow), 11);
    assert_eq!(worst_case_separation(narrow, wide), 11);
    assert_eq!(
        worst_case_separation(interval(0, 0)?, interval(100, 100)?),
        100
    );
    assert_eq!(
        worst_case_separation(interval(0, 20)?, interval(0, 20)?),
        20
    );
    assert_eq!(midpoint(interval(10, 21)?)?, 15);
    Ok(())
}

#[test]
fn plan_validation_refuses_one_import_twice_bad_zones_and_gates() {
    assert!(plan().validate().is_ok());
    let mut same = plan();
    same.cameras[1].import_identity = same.cameras[0].import_identity;
    assert!(matches!(
        same.validate(),
        Err(CorroborationError::SameSensor)
    ));
    let mut names = plan();
    names.cameras[1].name = "east".to_owned();
    assert!(matches!(
        names.validate(),
        Err(CorroborationError::InvalidPlan(_))
    ));
    let mut singular = plan();
    singular.cameras[0].homography.matrix = [0.0; 9];
    assert_eq!(
        singular.validate().err().map(|e| e.stable_id()),
        Some("ERR-CORROBORATE-HOMOGRAPHY-INVALID-001")
    );
    let mut zone = plan();
    zone.zones[0].width = 0.0;
    assert!(zone.validate().is_err());
    let mut gate = plan();
    gate.gates.time_gate_ns = 0;
    assert!(gate.validate().is_err());
    let mut distance = plan();
    distance.gates.distance_gate = f64::INFINITY;
    assert!(distance.validate().is_err());
    assert_ne!(plan().digest(), gate.digest());
}

fn witness(sensor: &[u8], capsule: &[u8], record: &[u8]) -> TestResult<ZoneEntryWitness> {
    let sensor_digest = ContentDigest::sha256(sensor);
    Ok(ZoneEntryWitness {
        record_digest: ContentDigest::sha256(record),
        sensor_digest,
        capsule_digest: ContentDigest::sha256(capsule),
        failure_domain: format!("recorded-sensor:{}", hex(sensor_digest)),
        interval: interval(100, 200)?,
    })
}

fn decision(witnesses: Vec<ZoneEntryWitness>) -> TestResult<ReferencePolicyDecision> {
    Ok(evaluate_zone_entry_corroboration(ZoneEntryCorroboration {
        event_id: EventId::parse("event:corroborated:test")?,
        zone_id: "door".to_owned(),
        track_ids: vec!["track:east:1".to_owned(), "track:west:1".to_owned()],
        witnesses,
        association_digest: ContentDigest::sha256(b"association"),
        association_domain: "cross-camera-association:test".to_owned(),
        uncertainty_reason: UNCERTAINTY.to_owned(),
    })?)
}

#[test]
fn zone_entry_policy_corroborates_only_independent_sensors() -> TestResult {
    let two = decision(vec![
        witness(b"sensor:east", b"capsule:east", b"record:east")?,
        witness(b"sensor:west", b"capsule:west", b"record:west")?,
    ])?;
    assert_eq!(two.event.state, EventState::Corroborated);
    assert_eq!(two.action, ReferencePolicyAction::PrepareAlert);
    assert_eq!(
        crate::committed_reference_policy_action(&two.event),
        ReferencePolicyAction::PrepareAlert
    );

    // One sensor seen twice (two records, two capsules) is still one failure domain.
    let same = decision(vec![
        witness(b"sensor:east", b"capsule:one", b"record:one")?,
        witness(b"sensor:east", b"capsule:two", b"record:two")?,
    ])?;
    assert_eq!(same.event.state, EventState::Witnessed);
    assert_eq!(same.action, ReferencePolicyAction::Hold);
    assert_eq!(
        crate::committed_reference_policy_action(&same.event),
        ReferencePolicyAction::Hold
    );

    let single = decision(vec![witness(
        b"sensor:east",
        b"capsule:east",
        b"record:east",
    )?])?;
    assert_eq!(single.event.state, EventState::Witnessed);
    assert_eq!(single.action, ReferencePolicyAction::Hold);

    // A relabelled decision path does not become alert-eligible.
    let mut forged = two.event.clone();
    forged.decision_path = crate::policy::zone_entry_decision_path(
        &forged.event_id,
        &forged.evidence,
        forged.state,
        ReferencePolicyAction::Hold,
    );
    assert_eq!(
        crate::committed_reference_policy_action(&forged),
        ReferencePolicyAction::Hold
    );
    Ok(())
}
