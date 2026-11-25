#![forbid(unsafe_code)]
//! Integration & E2E replay contract tests for live streaming multi-camera corroboration (`C8`).
//!
//! Covers all required end-to-end replay scenarios plus clock, horizon, bridge, eviction, and
//! `C5` `CascadeFrameReceipt` bridge invariants with structured JSONL audit output:
//! - Scenario A: Wyze `.51` (Wi-Fi/main power) + UniFi G4 `.177` (separate PoE switch/UPS) =
//!   2 independent failure-domain clusters -> canonical `EventState::Corroborated`
//!   `EventHypothesis` passing `verify()` and alert-eligibility checks in `< 10 ms`.
//! - Scenario B: Two cameras sharing declared `wifi:home` failure domain -> honestly withholds
//!   corroboration (`SharedFailureDomainHeld`, `supporting_clusters == 1`,
//!   `requires_operator_confirmation == true`, NOT alert-eligible).
//! - Scenario C: Inject 10 seconds of synthetic clock skew on one camera -> widens
//!   `[earliest_ns, latest_ns]` and honestly emits `ClockUncertaintyAbstained`.
//! - Scenario D: Calibrated transit corridor (`camA:driveway -> camB:porch` in `1s..=8s`)
//!   corroborates on valid transit and abstains on impossible `0.01s` or `30s` transit.
//! - Scenario E: Clock jitter/step-jump widening, horizon refusal, transitive bridge cluster
//!   contraction, sliding-window eviction, uncalibrated fail-closed, and `C5` cascade bridge.

use std::collections::BTreeSet;
use std::time::Instant;

use fss_core::{ContentDigest, EventState, SensorId};
use fss_fusion::ScoreCalibration;
use fss_reference::ingest::live_corroborate::{
    BoundedCaptureInterval, CameraClockEstimator, CameraHomography, CameraTopologyEntry,
    ClockAnomaly, ClockBasis, ClockEstimatorConfig, ClockObservationSample, CorroborationOutcome,
    LiveCorroborationConfig, LiveCorroborationEngine, LiveObservation, MatchMechanism,
    ObservationWindow, SharedZoneOverlap, SiteTopologyRegistry, SlidingWindowConfig,
    SpatialRelation, TransitCorridor,
};
use fss_reference::ingest::model_pool::{
    CameraPriorityTier, CascadeFrameReceipt, ModelDetectionSummary, Stage1Telemetry, StageDecision,
};
use fss_reference::{ReferencePolicyAction, committed_reference_policy_action};

fn domains(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

fn calibrated_person_detector() -> Result<ScoreCalibration, Box<dyn std::error::Error>> {
    Ok(ScoreCalibration::from_counts(
        "cal:live-corroborate:person:v1",
        &[0, 500_000, 800_000],
        &[(1, 85), (3, 14), (96, 1)],
    )?)
}

fn identity_homography(distance_gate: f64) -> CameraHomography {
    CameraHomography {
        matrix: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
        distance_gate,
    }
}

fn obs(
    sensor_id: &str,
    zone_id: &str,
    track_id: u64,
    foot_px: Option<[f64; 2]>,
    score_ppm: u32,
    bounded_capture: BoundedCaptureInterval,
    seed: &[u8],
) -> LiveObservation {
    LiveObservation {
        sensor_id: sensor_id.to_owned(),
        stream_id: "rtsp:main".to_owned(),
        zone_id: zone_id.to_owned(),
        track_id,
        foot_px,
        class_label: "person".to_owned(),
        score_ppm,
        bounded_capture,
        source_capsule_digest: ContentDigest::sha256(&[b"capsule:", seed].concat()),
        model_receipt_digest: ContentDigest::sha256(&[b"model:", seed].concat()),
        cascade_receipt_digest: ContentDigest::sha256(&[b"cascade:", seed].concat()),
    }
}

#[test]
fn invalidated_camera_tracks_and_clock_cannot_match_later_observations()
-> Result<(), Box<dyn std::error::Error>> {
    let mut topology = SiteTopologyRegistry::new("site:health-invalidation");
    for sensor in ["sensor:health-a", "sensor:health-b"] {
        topology.register_camera(CameraTopologyEntry {
            sensor_id: sensor.to_owned(),
            failure_domains: domains(&[sensor]),
            homography: Some(identity_homography(2.0)),
            zones: domains(&["yard"]),
        });
    }
    let mut engine =
        LiveCorroborationEngine::new(topology, LiveCorroborationConfig::default_config()?)?;
    let sample = ClockObservationSample {
        media_pts_ns: 1_000_000,
        host_receive_ns: 2_000_000,
        rtt_jitter_ns: 10_000,
        node_clock_uncertainty_ns: 1_000,
    };
    let capture_a = engine.observe_clock_sample("sensor:health-a", sample)?;
    let capture_b = engine.observe_clock_sample("sensor:health-b", sample)?;
    engine.ingest_observation(obs(
        "sensor:health-a",
        "yard",
        1,
        Some([1.0, 1.0]),
        950_000,
        capture_a,
        b"health-a",
    ))?;
    engine.ingest_observation(obs(
        "sensor:health-b",
        "yard",
        2,
        Some([1.0, 1.0]),
        950_000,
        capture_b,
        b"health-b",
    ))?;
    assert_eq!(engine.window_len(), 2);
    assert_eq!(engine.invalidate_camera("sensor:health-a")?, 1);
    assert_eq!(engine.window_len(), 1);
    assert_eq!(
        engine
            .clock_estimator("sensor:health-a")
            .ok_or("missing clock")?
            .sample_count(),
        0
    );
    assert_eq!(
        engine
            .clock_estimator("sensor:health-b")
            .ok_or("missing clock")?
            .sample_count(),
        1
    );
    assert!(
        engine
            .ingest_observation(obs(
                "sensor:health-b",
                "yard",
                3,
                Some([1.0, 1.0]),
                950_000,
                capture_b,
                b"health-b-later"
            ))?
            .is_empty()
    );
    assert!(engine.invalidate_camera("sensor:unknown").is_err());
    assert_eq!(engine.window_len(), 2);
    Ok(())
}

#[test]
fn scenario_a_wyze_and_unifi_independent_clusters_corroborate_under_10ms()
-> Result<(), Box<dyn std::error::Error>> {
    let mut topology = SiteTopologyRegistry::new("site:live-scenario-a");
    topology
        .register_camera(CameraTopologyEntry {
            sensor_id: "sensor:wyze-51".to_owned(),
            failure_domains: domains(&["wifi:home", "power:main", "vendor:wyze"]),
            homography: Some(identity_homography(2.0)),
            zones: domains(&["front_walk"]),
        })
        .register_camera(CameraTopologyEntry {
            sensor_id: "sensor:unifi-g4-177".to_owned(),
            failure_domains: domains(&["poe_switch:1", "ups:rack", "vendor:unifi"]),
            homography: Some(identity_homography(2.0)),
            zones: domains(&["front_walk"]),
        });

    let mut cfg = LiveCorroborationConfig::default_config()?;
    cfg.fusion = cfg
        .fusion
        .with_calibration("person", calibrated_person_detector()?);
    let mut engine = LiveCorroborationEngine::new(topology, cfg)?;

    let started = Instant::now();
    let (mut last_wyze, mut last_unifi) = (None, None);
    for frame in 1_i128..=5 {
        let host_ns = 1_700_000_000_000_000_000_i128 + frame * 100_000_000;
        last_wyze = Some(engine.observe_clock_sample(
            "sensor:wyze-51",
            ClockObservationSample {
                media_pts_ns: frame * 100_000_000,
                host_receive_ns: host_ns + 12_000_000,
                rtt_jitter_ns: 20_000_000,
                node_clock_uncertainty_ns: 2_000_000,
            },
        )?);
        last_unifi = Some(engine.observe_clock_sample(
            "sensor:unifi-g4-177",
            ClockObservationSample {
                media_pts_ns: 900_000_000 + frame * 100_000_000,
                host_receive_ns: host_ns + 4_000_000,
                rtt_jitter_ns: 6_000_000,
                node_clock_uncertainty_ns: 1_000_000,
            },
        )?);
    }

    let obs_wyze = obs(
        "sensor:wyze-51",
        "front_walk",
        101,
        Some([12.0, 8.0]),
        930_000,
        last_wyze.ok_or("missing wyze interval")?,
        b"scen-a-wyze",
    );
    let obs_unifi = obs(
        "sensor:unifi-g4-177",
        "front_walk",
        202,
        Some([12.4, 8.3]),
        950_000,
        last_unifi.ok_or("missing unifi interval")?,
        b"scen-a-unifi",
    );

    assert!(engine.ingest_observation(obs_wyze.clone())?.is_empty());
    let decisions = engine.ingest_observation(obs_unifi.clone())?;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;

    assert_eq!(decisions.len(), 1);
    let decision = &decisions[0];
    println!("SCENARIO_A_JSONL={}", decision.to_jsonl());
    println!("SCENARIO_A_ELAPSED_MS={elapsed_ms:.3}");
    assert!(elapsed_ms < 10.0, "expected < 10ms, got {elapsed_ms:.3}ms");

    match &decision.outcome {
        CorroborationOutcome::Corroborated {
            supporting_clusters,
            posterior,
            probability_ppm,
            event,
            policy_action,
            alert_eligible,
            ..
        } => {
            assert_eq!(*supporting_clusters, 2);
            assert!(posterior.lo() >= 1_500);
            assert!(probability_ppm.0 > 900_000);
            assert_eq!(event.state, EventState::Corroborated);
            assert_eq!(*policy_action, ReferencePolicyAction::PrepareAlert);
            assert!(*alert_eligible);
            assert_eq!(
                committed_reference_policy_action(event),
                ReferencePolicyAction::PrepareAlert
            );
            event.verify()?;
            let analysis = event.analyze_corroboration();
            assert!(analysis.is_corroborated);
            assert_eq!(analysis.distinct_failure_domains.len(), 2);
            let capsules: BTreeSet<ContentDigest> = event
                .evidence
                .iter()
                .filter_map(|e| e.capsule_digest)
                .collect();
            assert!(capsules.contains(&obs_wyze.source_capsule_digest));
            assert!(capsules.contains(&obs_unifi.source_capsule_digest));
        }
        other => return Err(format!("Scenario A expected Corroborated, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn scenario_b_shared_wifi_failure_domain_withholds_corroboration()
-> Result<(), Box<dyn std::error::Error>> {
    let mut topology = SiteTopologyRegistry::new("site:live-scenario-b");
    topology
        .register_camera(CameraTopologyEntry {
            sensor_id: "sensor:wyze-39".to_owned(),
            failure_domains: domains(&["wifi:home", "power:main", "vendor:wyze"]),
            homography: Some(identity_homography(2.0)),
            zones: domains(&["driveway"]),
        })
        .register_camera(CameraTopologyEntry {
            sensor_id: "sensor:wyze-51".to_owned(),
            failure_domains: domains(&["wifi:home", "power:main", "vendor:wyze"]),
            homography: Some(identity_homography(2.0)),
            zones: domains(&["driveway"]),
        });

    let mut cfg = LiveCorroborationConfig::default_config()?;
    cfg.fusion = cfg
        .fusion
        .with_calibration("person", calibrated_person_detector()?);
    let mut engine = LiveCorroborationEngine::new(topology, cfg)?;

    let t_a = engine.observe_clock_sample(
        "sensor:wyze-39",
        ClockObservationSample {
            media_pts_ns: 1_000_000_000,
            host_receive_ns: 1_700_000_100_000_000_000,
            rtt_jitter_ns: 18_000_000,
            node_clock_uncertainty_ns: 2_000_000,
        },
    )?;
    let t_b = engine.observe_clock_sample(
        "sensor:wyze-51",
        ClockObservationSample {
            media_pts_ns: 2_000_000_000,
            host_receive_ns: 1_700_000_100_020_000_000,
            rtt_jitter_ns: 18_000_000,
            node_clock_uncertainty_ns: 2_000_000,
        },
    )?;

    engine.ingest_observation(obs(
        "sensor:wyze-39",
        "driveway",
        11,
        Some([4.0, 6.0]),
        960_000,
        t_a,
        b"b39",
    ))?;
    let decisions = engine.ingest_observation(obs(
        "sensor:wyze-51",
        "driveway",
        12,
        Some([4.2, 6.1]),
        970_000,
        t_b,
        b"b51",
    ))?;

    assert_eq!(decisions.len(), 1);
    println!("SCENARIO_B_JSONL={}", decisions[0].to_jsonl());
    match &decisions[0].outcome {
        CorroborationOutcome::SharedFailureDomainHeld {
            supporting_clusters,
            shared_domains,
            requires_operator_confirmation,
            event,
            policy_action,
            ..
        } => {
            assert_eq!(*supporting_clusters, 1);
            assert!(*requires_operator_confirmation);
            assert!(shared_domains.contains("wifi:home"));
            assert_eq!(event.state, EventState::Indeterminate);
            assert_eq!(*policy_action, ReferencePolicyAction::Hold);
            assert_eq!(
                committed_reference_policy_action(event),
                ReferencePolicyAction::Hold
            );
            assert!(!event.analyze_corroboration().is_corroborated);
            event.verify()?;
        }
        other => {
            return Err(
                format!("Scenario B expected SharedFailureDomainHeld, got {other:?}").into(),
            );
        }
    }
    Ok(())
}

#[test]
fn scenario_c_ten_second_clock_skew_abstains() -> Result<(), Box<dyn std::error::Error>> {
    let mut topology = SiteTopologyRegistry::new("site:live-scenario-c");
    topology
        .register_camera(CameraTopologyEntry {
            sensor_id: "sensor:wyze-51".to_owned(),
            failure_domains: domains(&["wifi:home", "power:main"]),
            homography: Some(identity_homography(2.0)),
            zones: domains(&["front_walk"]),
        })
        .register_camera(CameraTopologyEntry {
            sensor_id: "sensor:unifi-g4-177".to_owned(),
            failure_domains: domains(&["poe_switch:1", "ups:rack"]),
            homography: Some(identity_homography(2.0)),
            zones: domains(&["front_walk"]),
        });

    let mut cfg = LiveCorroborationConfig::default_config()?;
    cfg.fusion = cfg
        .fusion
        .with_calibration("person", calibrated_person_detector()?);
    let mut engine = LiveCorroborationEngine::new(topology, cfg)?;

    let t0 = 1_700_000_200_000_000_000_i128;
    let clean_w = engine.observe_clock_sample(
        "sensor:wyze-51",
        ClockObservationSample {
            media_pts_ns: 1_000_000_000,
            host_receive_ns: t0,
            rtt_jitter_ns: 15_000_000,
            node_clock_uncertainty_ns: 2_000_000,
        },
    )?;
    let skewed_w = engine.observe_clock_sample(
        "sensor:wyze-51",
        ClockObservationSample {
            media_pts_ns: 1_100_000_000,
            host_receive_ns: t0 + 10_100_000_000,
            rtt_jitter_ns: 15_000_000,
            node_clock_uncertainty_ns: 2_000_000,
        },
    )?;
    assert!(skewed_w.width_ns() > clean_w.width_ns());
    assert!(skewed_w.width_ns() >= 10_000_000_000);
    let clean_u = engine.observe_clock_sample(
        "sensor:unifi-g4-177",
        ClockObservationSample {
            media_pts_ns: 1_100_000_000,
            host_receive_ns: t0 + 10_100_000_000,
            rtt_jitter_ns: 5_000_000,
            node_clock_uncertainty_ns: 1_000_000,
        },
    )?;

    engine.ingest_observation(obs(
        "sensor:wyze-51",
        "front_walk",
        31,
        Some([7.0, 9.0]),
        950_000,
        skewed_w,
        b"cw",
    ))?;
    let decisions = engine.ingest_observation(obs(
        "sensor:unifi-g4-177",
        "front_walk",
        32,
        Some([7.1, 9.1]),
        950_000,
        clean_u,
        b"cu",
    ))?;

    assert_eq!(decisions.len(), 1);
    println!("SCENARIO_C_JSONL={}", decisions[0].to_jsonl());
    match &decisions[0].outcome {
        CorroborationOutcome::ClockUncertaintyAbstained {
            uncertainty_ns,
            max_allowed_ns,
            ..
        } => {
            assert!(*uncertainty_ns >= 10_000_000_000);
            assert_eq!(*max_allowed_ns, 1_000_000_000);
        }
        other => {
            return Err(
                format!("Scenario C expected ClockUncertaintyAbstained, got {other:?}").into(),
            );
        }
    }
    Ok(())
}

#[test]
fn scenario_d_calibrated_transit_corridor_valid_vs_impossible()
-> Result<(), Box<dyn std::error::Error>> {
    let mut topology = SiteTopologyRegistry::new("site:live-scenario-d");
    topology
        .register_camera(CameraTopologyEntry {
            sensor_id: "sensor:cam-a".to_owned(),
            failure_domains: domains(&["wifi:driveway", "power:garage"]),
            homography: None,
            zones: domains(&["driveway"]),
        })
        .register_camera(CameraTopologyEntry {
            sensor_id: "sensor:cam-b".to_owned(),
            failure_domains: domains(&["poe_switch:1", "ups:porch"]),
            homography: None,
            zones: domains(&["porch"]),
        })
        .add_transit_corridor(TransitCorridor {
            corridor_id: "corridor:driveway-to-porch".to_owned(),
            from_camera: "sensor:cam-a".to_owned(),
            from_zone: "driveway".to_owned(),
            to_camera: "sensor:cam-b".to_owned(),
            to_zone: "porch".to_owned(),
            min_transit_ns: 1_000_000_000,
            max_transit_ns: 8_000_000_000,
            bidirectional: false,
        });

    let mut cfg = LiveCorroborationConfig::default_config()?;
    cfg.window.retention_ns = 60_000_000_000;
    cfg.fusion = cfg
        .fusion
        .with_calibration("person", calibrated_person_detector()?);
    let mut engine = LiveCorroborationEngine::new(topology, cfg)?;

    let t_origin = BoundedCaptureInterval::new(
        1_700_000_300_000_000_000,
        1_700_000_300_020_000_000,
        ClockBasis::AuthenticatedNtp,
    )?;
    assert!(
        engine
            .ingest_observation(obs(
                "sensor:cam-a",
                "driveway",
                1,
                None,
                950_000,
                t_origin,
                b"d0"
            ))?
            .is_empty()
    );

    let t_fast = BoundedCaptureInterval::new(
        1_700_000_300_010_000_000,
        1_700_000_300_030_000_000,
        ClockBasis::AuthenticatedNtp,
    )?;
    assert!(
        engine
            .ingest_observation(obs(
                "sensor:cam-b",
                "porch",
                2,
                None,
                950_000,
                t_fast,
                b"df"
            ))?
            .is_empty()
    );

    let t_valid = BoundedCaptureInterval::new(
        1_700_000_303_500_000_000,
        1_700_000_303_520_000_000,
        ClockBasis::AuthenticatedNtp,
    )?;
    let valid = engine.ingest_observation(obs(
        "sensor:cam-b",
        "porch",
        3,
        None,
        960_000,
        t_valid,
        b"dv",
    ))?;
    assert_eq!(valid.len(), 1);
    println!("SCENARIO_D_VALID_JSONL={}", valid[0].to_jsonl());
    assert!(matches!(
        valid[0].match_mechanism,
        Some(MatchMechanism::TransitCorridor { ref corridor_id, .. }) if corridor_id == "corridor:driveway-to-porch"
    ));
    assert!(matches!(
        valid[0].outcome,
        CorroborationOutcome::Corroborated {
            supporting_clusters: 2,
            alert_eligible: true,
            ..
        }
    ));

    let t_slow = BoundedCaptureInterval::new(
        1_700_000_330_000_000_000,
        1_700_000_330_020_000_000,
        ClockBasis::AuthenticatedNtp,
    )?;
    assert!(
        engine
            .ingest_observation(obs(
                "sensor:cam-b",
                "porch",
                4,
                None,
                950_000,
                t_slow,
                b"ds"
            ))?
            .is_empty()
    );
    println!("SCENARIO_D_ABSTAINED_JSONL={{\"too_fast_matches\":0,\"too_slow_matches\":0}}");
    Ok(())
}

#[test]
fn scenario_e_clock_horizon_bridge_eviction_and_cascade_bridge()
-> Result<(), Box<dyn std::error::Error>> {
    // 1. Clock jitter widening + step-jump anomaly detection.
    let mut est = CameraClockEstimator::new("sensor:cam-1", ClockEstimatorConfig::default())?;
    let c1 = est.observe(ClockObservationSample {
        media_pts_ns: 1_000_000_000,
        host_receive_ns: 50_000_000_000,
        rtt_jitter_ns: 10_000_000,
        node_clock_uncertainty_ns: 1_000_000,
    })?;
    let c2 = est.observe(ClockObservationSample {
        media_pts_ns: 2_000_000_000,
        host_receive_ns: 61_000_000_000,
        rtt_jitter_ns: 90_000_000,
        node_clock_uncertainty_ns: 1_000_000,
    })?;
    assert!(c2.width_ns() > c1.width_ns() && c2.width_ns() >= 10_000_000_000);
    assert!(
        est.anomalies()
            .iter()
            .any(|a| matches!(a, ClockAnomaly::ClockStepJump { .. }))
    );

    // 2. Horizon refusal + transitive bridge contraction.
    let horizon_h = CameraHomography {
        matrix: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, -1.0, 100.0],
        distance_gate: 2.0,
    };
    assert!(horizon_h.project([5.0, 100.0]).is_none());
    let mut topo = SiteTopologyRegistry::new("site:scen-e");
    topo.register_camera(CameraTopologyEntry {
        sensor_id: "sensor:a".to_owned(),
        failure_domains: domains(&["wifi:home"]),
        homography: Some(horizon_h),
        zones: domains(&["entry"]),
    })
    .register_camera(CameraTopologyEntry {
        sensor_id: "sensor:bridge".to_owned(),
        failure_domains: domains(&["wifi:home", "power:main"]),
        homography: None,
        zones: domains(&["entry"]),
    })
    .register_camera(CameraTopologyEntry {
        sensor_id: "sensor:c".to_owned(),
        failure_domains: domains(&["power:main"]),
        homography: Some(identity_homography(2.0)),
        zones: domains(&["entry"]),
    })
    .register_camera(CameraTopologyEntry {
        sensor_id: "sensor:d".to_owned(),
        failure_domains: domains(&["poe_switch:2", "ups:2"]),
        homography: Some(identity_homography(2.0)),
        zones: domains(&["entry"]),
    })
    .add_shared_zone(SharedZoneOverlap {
        zone_id: "entry".to_owned(),
        cameras: domains(&["sensor:a", "sensor:d"]),
        max_separation_ns: 2_000_000_000,
    });
    topo.validate()?;
    assert_eq!(topo.failure_domain_clusters().len(), 2);
    assert!(matches!(
        topo.evaluate_pair_geometry(
            "sensor:a",
            "entry",
            Some([5.0, 120.0]),
            "sensor:d",
            "entry",
            Some([5.0, 5.0])
        ),
        SpatialRelation::HorizonRefused { .. }
    ));

    // 3. Sliding-window bounded eviction.
    let mut win = ObservationWindow::new(SlidingWindowConfig {
        retention_ns: 3_000_000_000,
        max_total_observations: 6,
        max_observations_per_camera: 4,
    })?;
    for i in 1_u64..=20 {
        let ts = i128::from(i) * 500_000_000;
        let cap = BoundedCaptureInterval::new(ts, ts + 1_000_000, ClockBasis::AuthenticatedNtp)?;
        win.insert(obs(
            if i % 2 == 0 { "sensor:a" } else { "sensor:d" },
            "entry",
            i,
            None,
            900_000,
            cap,
            &i.to_le_bytes(),
        ));
        assert!(win.len() <= 6);
    }
    assert!(
        win.advance_watermark(1_000_000_000_000)
            .evicted_by_watermark
            > 0
    );
    assert_eq!(win.len(), 0);

    // 4. Uncalibrated fail-closed & calibrated C5 CascadeFrameReceipt bridge over SharedZone.
    let mk_rcpt =
        |s: &str, tag: &[u8]| -> Result<CascadeFrameReceipt, Box<dyn std::error::Error>> {
            Ok(CascadeFrameReceipt {
                stream_order: 0,
                frame_sequence: 1,
                sensor_id: SensorId::parse(s)?,
                source_digest: ContentDigest::sha256(&[b"src:", tag].concat()),
                is_keyframe: true,
                priority: CameraPriorityTier::HighConsequenceZone,
                model_id: "det:person".to_owned(),
                package_digest: ContentDigest::sha256(b"pkg"),
                model_generation: "gen:v1".to_owned(),
                execution_profile_digest: ContentDigest::sha256(b"exec"),
                stage_decision: StageDecision::MotionTriggered,
                stage1: Stage1Telemetry {
                    foreground_pixels: 400,
                    foreground_box_count: 1,
                    osd_ignore_regions_digest: ContentDigest::sha256(b"osd"),
                    osd_ignore_region_count: 0,
                    health_findings_count: 0,
                    work_units: 10,
                },
                detections: vec![ModelDetectionSummary {
                    class_index: 0,
                    label: "person".to_owned(),
                    score_bits: 0.95_f32.to_bits(),
                    bounds: [20 * 256, 10 * 256, 40 * 256, 80 * 256],
                }],
                activity_score_bits: None,
                inference_output_digest: Some(ContentDigest::sha256(&[b"out:", tag].concat())),
                executed_macs: 1_000,
                unsampled_gap_recorded: false,
                unsampled_reason: None,
                decline_receipt: None,
                work_units_spent: 50,
                absence_certifiable: false,
                effects_authorized: false,
                receipt_digest: ContentDigest::sha256(&[b"rcpt:", tag].concat()),
            })
        };
    let (ra, rd) = (mk_rcpt("sensor:a", b"ea")?, mk_rcpt("sensor:d", b"ed")?);
    let sa = ClockObservationSample {
        media_pts_ns: 1_000_000_000,
        host_receive_ns: 50_000_000_000,
        rtt_jitter_ns: 10_000_000,
        node_clock_uncertainty_ns: 1_000_000,
    };
    let sd = ClockObservationSample {
        media_pts_ns: 1_000_000_000,
        host_receive_ns: 50_020_000_000,
        rtt_jitter_ns: 10_000_000,
        node_clock_uncertainty_ns: 1_000_000,
    };
    // Clear homographies on a/d so SharedZone path is exercised directly from CascadeFrameReceipt.
    topo.cameras.get_mut("sensor:a").ok_or("a")?.homography = None;
    topo.cameras.get_mut("sensor:d").ok_or("d")?.homography = None;
    let mut uncal =
        LiveCorroborationEngine::new(topo.clone(), LiveCorroborationConfig::default_config()?)?;
    assert!(
        uncal
            .ingest_cascade_receipt(&ra, "main", "entry", 1, sa)?
            .is_empty()
    );
    let held = uncal.ingest_cascade_receipt(&rd, "main", "entry", 2, sd)?;
    assert!(matches!(
        held[0].outcome,
        CorroborationOutcome::InsufficientEvidenceHeld { .. }
    ));
    let mut cal_cfg = LiveCorroborationConfig::default_config()?;
    cal_cfg.fusion = cal_cfg
        .fusion
        .with_calibration("person", calibrated_person_detector()?);
    let mut cal = LiveCorroborationEngine::new(topo, cal_cfg)?;
    assert!(
        cal.ingest_cascade_receipt(&ra, "main", "entry", 1, sa)?
            .is_empty()
    );
    let corr = cal.ingest_cascade_receipt(&rd, "main", "entry", 2, sd)?;
    println!("SCENARIO_E_CASCADE_JSONL={}", corr[0].to_jsonl());
    assert!(matches!(
        corr[0].outcome,
        CorroborationOutcome::Corroborated {
            supporting_clusters: 2,
            alert_eligible: true,
            ..
        }
    ));
    Ok(())
}
