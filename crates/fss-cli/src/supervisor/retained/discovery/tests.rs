#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use fss_fusion::{FusionPolicy, LlrInterval, ScoreCalibration, Severity};

use super::*;
use crate::supervisor::retained::{
    RetainedSupervisorLimits, RetainedSupervisorSpec, RetainedSupervisorWindow,
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn template() -> TestResult<RetainedSupervisorPlan> {
    let pin = ContentDigest::sha256(b"discovery-fixture");
    Ok(RetainedSupervisorPlan::new(RetainedSupervisorSpec {
        site_lineage: "site:discovery".into(),
        hypothesis_id: "hyp:class:tie".into(),
        expected_authority_root: pin,
        label: "tie".into(),
        start_ns: 10,
        cameras: vec![RetainedCameraSpec {
            camera_id: "east".into(),
            sensor_id: "sensor:discovery-east".into(),
            package_digest: pin,
            model_digest: pin,
            contract_digest: pin,
            class_index: 27,
            failure_domains: BTreeSet::new(),
            calibration: None,
        }],
        events: Vec::new(),
        windows: vec![
            RetainedSupervisorWindow {
                window_index: 0,
                end_ns: 20,
                observations: Vec::new(),
            },
            RetainedSupervisorWindow {
                window_index: 1,
                end_ns: 30,
                observations: Vec::new(),
            },
        ],
        prior: LlrInterval::new(-200, -100)?,
        policy: FusionPolicy {
            generation: "policy:discovery".into(),
            alert_threshold: 1800,
            retain_threshold: 0,
            reject_threshold: -1000,
            min_independent_support: 2,
            urgent_single_domain_threshold: None,
            max_wait_ns: 0,
            look_penalty_per_doubling: 0,
            operator_confirmation_available: false,
        },
        severity: Severity {
            expected_harm: 10000,
            false_alert_cost: 500,
            delay_cost_per_second: 100,
            reversible: false,
        },
        limits: RetainedSupervisorLimits {
            max_read_bytes: 134217728,
            max_read_attempts: 8192,
            max_journal_bytes: 16777216,
            max_report_bytes: 2097152,
        },
    })?)
}

#[test]
fn request_rejects_supplied_sources_and_binds_the_catalog_allowance() -> TestResult {
    let template = template()?;
    let first = RetainedDiscoveryRequest::new(template.clone(), 1)?;
    let second = RetainedDiscoveryRequest::new(template.clone(), 2)?;
    assert_eq!(first.template().digest(), template.digest());
    assert_eq!(first.maximum_catalog_events(), 1);
    assert_ne!(first.digest(), second.digest());
    for maximum in [0, MAX_RETAINED_DISCOVERY_CATALOG_EVENTS + 1, usize::MAX] {
        assert!(matches!(
            RetainedDiscoveryRequest::new(template.clone(), maximum),
            Err(Error::Limit(_))
        ));
    }
    let mut selected = template.spec().clone();
    let event = EventId::parse("event:package:fixture")?;
    selected.events.push(RetainedEventPin {
        camera_id: "east".into(),
        event_id: event.clone(),
        expected_event_root: ContentDigest::sha256(b"event-root"),
    });
    selected.windows[0]
        .observations
        .push(RetainedObservationSelector {
            event_id: event,
            capsule_digest: ContentDigest::sha256(b"source-capsule"),
            segment: 0,
            detection_row: 7,
        });
    let selected = RetainedSupervisorPlan::new(selected)?;
    assert!(matches!(
        RetainedDiscoveryRequest::new(selected, 8),
        Err(Error::Plan(_))
    ));
    Ok(())
}

#[test]
fn generated_v1_plan_round_trips_all_policy_calibration_and_native_pins() -> TestResult {
    let mut spec = template()?.spec().clone();
    spec.cameras[0].camera_id = "east \"camera\"".into();
    spec.cameras[0].failure_domains =
        BTreeSet::from(["shared power / east".into(), "shared-model".into()]);
    spec.cameras[0].calibration = Some(ScoreCalibration::from_counts(
        "cal:discovery:v1",
        &[0, 1],
        &[(2, 98), (98, 2)],
    )?);
    spec.policy.urgent_single_domain_threshold = Some(3000);
    spec.policy.max_wait_ns = u64::MAX;
    spec.policy.operator_confirmation_available = true;
    spec.severity.expected_harm = u64::MAX;
    spec.severity.reversible = true;
    let event = EventId::parse("event:package:fixture")?;
    spec.events.push(RetainedEventPin {
        camera_id: spec.cameras[0].camera_id.clone(),
        event_id: event.clone(),
        expected_event_root: ContentDigest::sha256(b"current-event-root"),
    });
    spec.windows[1].end_ns = u64::MAX;
    spec.windows[1]
        .observations
        .push(RetainedObservationSelector {
            event_id: event,
            capsule_digest: ContentDigest::sha256(b"original-capsule"),
            segment: u64::MAX,
            detection_row: u64::MAX - 1,
        });
    let selected = RetainedSupervisorPlan::new(spec)?;
    let json = plan_to_json(&selected);
    let reopened = RetainedSupervisorPlan::from_json(
        json.as_bytes(),
        ContentDigest::sha256(json.as_bytes()),
    )?;
    assert_eq!(reopened.digest(), selected.digest());
    assert_eq!(
        reopened.spec().cameras[0].calibration,
        selected.spec().cameras[0].calibration
    );
    assert_eq!(
        reopened.spec().windows[1].observations,
        selected.spec().windows[1].observations
    );
    assert_eq!(reopened.spec().windows[1].end_ns, u64::MAX);
    assert_eq!(reopened.spec().severity.expected_harm, u64::MAX);
    assert_eq!(reopened.spec().policy.max_wait_ns, u64::MAX);
    Ok(())
}

#[test]
fn only_a_complete_original_capture_interval_selects_its_first_enclosing_window() -> TestResult {
    let template = template()?;
    let windows = &template.spec().windows;
    assert_eq!(enclosing_window(10, windows, 10, 20), Ok(0));
    assert_eq!(enclosing_window(10, windows, 19, 21), Ok(1));
    assert_eq!(enclosing_window(10, windows, 30, 30), Ok(1));
    assert_eq!(
        enclosing_window(10, windows, 0, 9),
        Err("observation_before_requested_interval")
    );
    assert_eq!(
        enclosing_window(10, windows, 31, 40),
        Err("observation_after_requested_interval")
    );
    assert_eq!(
        enclosing_window(10, windows, 0, 20),
        Err("observation_straddles_requested_boundary")
    );
    assert_eq!(
        enclosing_window(10, windows, 20, 40),
        Err("observation_straddles_requested_boundary")
    );
    Ok(())
}

#[test]
fn complete_exclusion_inventory_never_accepts_a_truncated_prefix() -> TestResult {
    let mut discovery = Discovery::default();
    let event = EventId::parse("event:package:excluded")?;
    let root = ContentDigest::sha256(b"excluded-current-root");
    for _ in 0..MAX_RETAINED_DISCOVERY_EXCLUSIONS {
        discovery.exclude(&event, root, "model_digest_mismatch", true, None)?;
    }
    assert!(matches!(
        discovery.exclude(&event, root, "model_digest_mismatch", true, None),
        Err(Error::Limit(_))
    ));
    assert_eq!(discovery.exclusions.len(), MAX_RETAINED_DISCOVERY_EXCLUSIONS);
    assert!(
        discovery
            .exclusions
            .iter()
            .all(|excluded| excluded.event_root == root && excluded.source_verified)
    );
    Ok(())
}

#[test]
fn explicit_authority_rebinding_preserves_every_original_scope_choice() -> TestResult {
    let original = RetainedDiscoveryRequest::new(template()?, 8)?;
    let old = original.template().spec().expected_authority_root;
    let root = ContentDigest::sha256(b"explicit current authority");
    let current = original.for_authority(root)?;
    assert_eq!(current.template().spec().expected_authority_root, root);
    assert_eq!(original.template().spec().expected_authority_root, old);
    assert_ne!(current.digest(), original.digest());
    assert_eq!(current.for_authority(old)?.digest(), original.digest());
    assert!(current.for_authority(ContentDigest::new(
        fss_core::DigestAlgorithm::Sha256, [0; 32],
    )).is_err());
    Ok(())
}

#[test]
fn scheduled_prefix_is_exact_bounded_and_preserves_the_full_configuration() -> TestResult {
    let original = RetainedDiscoveryRequest::new(template()?, 8)?;
    let first = original.for_window_prefix(1)?;
    assert_eq!(first.template().spec().windows.len(), 1);
    assert_eq!(first.template().spec().windows[0].window_index, 0);
    assert_eq!(first.template().spec().windows[0].end_ns, 20);
    assert_eq!(first.maximum_catalog_events(), original.maximum_catalog_events());
    assert_ne!(first.digest(), original.digest());
    assert_eq!(original.for_window_prefix(2)?.digest(), original.digest());
    assert_eq!(original.template().spec().windows.len(), 2);
    for count in [0, 3, usize::MAX] {
        assert!(matches!(original.for_window_prefix(count), Err(Error::Plan(_))));
    }
    let root = ContentDigest::sha256(b"explicit scheduled authority");
    assert_eq!(
        original.for_authority(root)?.for_window_prefix(1)?.digest(),
        first.for_authority(root)?.digest(),
    );
    let mut restored = first.template().spec().clone();
    restored.windows = original.template().spec().windows.clone();
    assert_eq!(RetainedSupervisorPlan::new(restored)?.digest(), original.template().digest());
    Ok(())
}
