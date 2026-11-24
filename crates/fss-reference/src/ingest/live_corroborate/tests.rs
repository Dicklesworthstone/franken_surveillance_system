#![forbid(unsafe_code)]
//! Unit and property tests for live bounded clock estimation, site topology clustering,
//! sliding-window eviction, shared-failure-domain refusal, and clock-skew abstention.

use std::collections::BTreeSet;

use fss_core::{ContentDigest, EventState};
use fss_fusion::ScoreCalibration;

use crate::alert::committed_reference_policy_action;
use crate::policy::ReferencePolicyAction;

use super::*;

fn domains(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

fn identity_homography(distance_gate: f64) -> CameraHomography {
    CameraHomography {
        matrix: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
        distance_gate,
    }
}

fn sample_calibration() -> Result<ScoreCalibration, Box<dyn std::error::Error>> {
    // High-confidence bin (800_000..=1_000_000): 95 TP vs 1 FP -> strong positive milliban LLR.
    let cal = ScoreCalibration::from_counts(
        "cal:live-person:v1",
        &[0, 500_000, 800_000],
        &[(2, 80), (15, 19), (95, 1)],
    )?;
    Ok(cal)
}

fn make_obs(
    sensor_id: &str,
    zone_id: &str,
    track_id: u64,
    foot_px: Option<[f64; 2]>,
    score_ppm: u32,
    capture: BoundedCaptureInterval,
    tag: &[u8],
) -> LiveObservation {
    LiveObservation {
        sensor_id: sensor_id.to_owned(),
        stream_id: "main".to_owned(),
        zone_id: zone_id.to_owned(),
        track_id,
        foot_px,
        class_label: "person".to_owned(),
        score_ppm,
        bounded_capture: capture,
        source_capsule_digest: ContentDigest::sha256(&[b"cap:", tag].concat()),
        model_receipt_digest: ContentDigest::sha256(&[b"model:", tag].concat()),
        cascade_receipt_digest: ContentDigest::sha256(&[b"cascade:", tag].concat()),
    }
}

#[test]
fn clock_envelope_widens_under_jitter_and_detects_step_jump()
-> Result<(), Box<dyn std::error::Error>> {
    let cfg = ClockEstimatorConfig {
        window_size: 16,
        max_drift_ppm: 500,
        step_jump_threshold_ns: 200_000_000,
        max_clock_uncertainty_ns: 1_000_000_000,
        basis: ClockBasis::BoundedReceiveEnvelope,
    };
    let mut est = CameraClockEstimator::new("sensor:wyze-51", cfg)?;

    let tight = est.observe(ClockObservationSample {
        media_pts_ns: 1_000_000_000,
        host_receive_ns: 101_000_000_000,
        rtt_jitter_ns: 10_000_000,
        node_clock_uncertainty_ns: 2_000_000,
    })?;
    assert!(tight.earliest_ns <= tight.latest_ns);
    assert_eq!(tight.width_ns(), 14_000_000);
    assert!(est.anomalies().is_empty());

    // Inject larger network RTT jitter -> interval MUST strictly widen.
    let jittered = est.observe(ClockObservationSample {
        media_pts_ns: 2_000_000_000,
        host_receive_ns: 102_000_000_000,
        rtt_jitter_ns: 120_000_000,
        node_clock_uncertainty_ns: 2_000_000,
    })?;
    assert!(jittered.width_ns() > tight.width_ns());
    assert_eq!(jittered.width_ns(), 124_000_000);

    // Inject sudden 10-second clock skew jump -> widens by 10s & records ClockStepJump anomaly.
    let jumped = est.observe(ClockObservationSample {
        media_pts_ns: 3_000_000_000,
        host_receive_ns: 113_000_000_000,
        rtt_jitter_ns: 10_000_000,
        node_clock_uncertainty_ns: 2_000_000,
    })?;
    assert!(jumped.width_ns() >= 10_000_000_000);
    assert!(
        est.anomalies()
            .iter()
            .any(|a| matches!(a, ClockAnomaly::ClockStepJump { jump_magnitude_ns, .. } if *jump_magnitude_ns == 10_000_000_000))
    );
    let receipt = est.receipt()?;
    assert!(receipt.offset_uncertainty_ns >= 10_000_000_000);
    Ok(())
}

#[test]
fn clock_interval_compatibility_and_transit_properties() -> Result<(), Box<dyn std::error::Error>> {
    let a =
        BoundedCaptureInterval::new(10_000_000_000, 10_020_000_000, ClockBasis::AuthenticatedNtp)?;
    let b =
        BoundedCaptureInterval::new(10_050_000_000, 10_080_000_000, ClockBasis::AuthenticatedNtp)?;

    // Worst-case separation = 80ms <= 500ms gate -> Compatible.
    assert!(matches!(
        intervals_compatible(a, b, 500_000_000, 1_000_000_000),
        MatchDisposition::Compatible {
            max_separation_ns: 80_000_000,
            ..
        }
    ));

    // Gate = 60ms: min separation 30ms <= 60ms < max separation 80ms -> BoundaryUncertain.
    assert!(matches!(
        intervals_compatible(a, b, 60_000_000, 1_000_000_000),
        MatchDisposition::TemporalBoundaryUncertain { .. }
    ));

    // Huge 10-second uncertainty on b -> ClockUncertaintyAbstained!
    let wide = BoundedCaptureInterval::new(
        10_000_000_000,
        20_000_000_000,
        ClockBasis::BoundedReceiveEnvelope,
    )?;
    assert!(matches!(
        intervals_compatible(a, wide, 500_000_000, 1_000_000_000),
        MatchDisposition::ClockUncertaintyAbstained {
            uncertainty_ns: 10_000_000_000,
            max_allowed_ns: 1_000_000_000
        }
    ));

    // Directed transit corridor [1s, 8s]: valid 3s transit passes; 10ms & 30s fail.
    let t_arrive_ok =
        BoundedCaptureInterval::new(13_000_000_000, 13_020_000_000, ClockBasis::AuthenticatedNtp)?;
    assert!(matches!(
        transit_compatible(a, t_arrive_ok, 1_000_000_000, 8_000_000_000, 1_000_000_000),
        MatchDisposition::TransitCompatible { .. }
    ));
    let t_too_fast =
        BoundedCaptureInterval::new(10_010_000_000, 10_030_000_000, ClockBasis::AuthenticatedNtp)?;
    assert!(matches!(
        transit_compatible(a, t_too_fast, 1_000_000_000, 8_000_000_000, 1_000_000_000),
        MatchDisposition::TemporalMismatch { .. }
    ));
    let t_too_slow =
        BoundedCaptureInterval::new(40_000_000_000, 40_020_000_000, ClockBasis::AuthenticatedNtp)?;
    assert!(matches!(
        transit_compatible(a, t_too_slow, 1_000_000_000, 8_000_000_000, 1_000_000_000),
        MatchDisposition::TemporalMismatch { .. }
    ));
    Ok(())
}

#[test]
fn homography_horizon_refusal_and_transitive_cluster_contraction()
-> Result<(), Box<dyn std::error::Error>> {
    // Homography whose denominator w = -1*v + 100 hits horizon at v >= 100.
    let h = CameraHomography {
        matrix: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, -1.0, 100.0],
        distance_gate: 2.0,
    };
    h.validate()?;
    assert!(h.project([10.0, 50.0]).is_some());
    assert!(h.project([10.0, 100.0]).is_none());
    assert!(h.project([10.0, 150.0]).is_none());

    // Singular matrix refused.
    let singular = CameraHomography {
        matrix: [1.0, 2.0, 3.0, 2.0, 4.0, 6.0, 0.0, 0.0, 1.0],
        distance_gate: 1.0,
    };
    assert!(singular.validate().is_err());

    // Transitive bridge: A shares wifi:home with B, B shares power:main with C, D is independent.
    let mut topo = SiteTopologyRegistry::new("site:bridge-test");
    topo.register_camera(CameraTopologyEntry {
        sensor_id: "sensor:cam-a".to_owned(),
        failure_domains: domains(&["wifi:home"]),
        homography: Some(h),
        zones: domains(&["yard"]),
    })
    .register_camera(CameraTopologyEntry {
        sensor_id: "sensor:cam-b".to_owned(),
        failure_domains: domains(&["wifi:home", "power:main"]),
        homography: Some(identity_homography(2.0)),
        zones: domains(&["yard"]),
    })
    .register_camera(CameraTopologyEntry {
        sensor_id: "sensor:cam-c".to_owned(),
        failure_domains: domains(&["power:main"]),
        homography: Some(identity_homography(2.0)),
        zones: domains(&["yard"]),
    })
    .register_camera(CameraTopologyEntry {
        sensor_id: "sensor:cam-d".to_owned(),
        failure_domains: domains(&["poe_switch:2", "ups:shed"]),
        homography: Some(identity_homography(2.0)),
        zones: domains(&["yard"]),
    });
    topo.validate()?;

    let clusters = topo.failure_domain_clusters();
    assert_eq!(clusters.len(), 2);
    let cluster_a = topo
        .cluster_for_camera("sensor:cam-a")
        .ok_or("missing cam-a cluster")?;
    let cluster_c = topo
        .cluster_for_camera("sensor:cam-c")
        .ok_or("missing cam-c cluster")?;
    let cluster_d = topo
        .cluster_for_camera("sensor:cam-d")
        .ok_or("missing cam-d cluster")?;
    assert_eq!(cluster_a.cluster_id, cluster_c.cluster_id);
    assert_ne!(cluster_a.cluster_id, cluster_d.cluster_id);

    // Horizon refusal check through evaluate_pair_geometry.
    assert!(matches!(
        topo.evaluate_pair_geometry(
            "sensor:cam-a",
            "yard",
            Some([10.0, 120.0]),
            "sensor:cam-d",
            "yard",
            Some([10.0, 10.0]),
        ),
        SpatialRelation::HorizonRefused { ref camera } if camera == "sensor:cam-a"
    ));
    Ok(())
}

#[test]
fn wyze_39_and_51_shared_wifi_and_power_refuses_corroboration()
-> Result<(), Box<dyn std::error::Error>> {
    let mut topo = SiteTopologyRegistry::new("site:home-lab");
    topo.register_camera(CameraTopologyEntry {
        sensor_id: "sensor:wyze-39".to_owned(),
        failure_domains: domains(&["wifi:home", "power:main", "vendor:wyze"]),
        homography: Some(identity_homography(2.5)),
        zones: domains(&["driveway"]),
    })
    .register_camera(CameraTopologyEntry {
        sensor_id: "sensor:wyze-51".to_owned(),
        failure_domains: domains(&["wifi:home", "power:main", "vendor:wyze"]),
        homography: Some(identity_homography(2.5)),
        zones: domains(&["driveway"]),
    });

    let mut cfg = LiveCorroborationConfig::default_config()?;
    cfg.fusion = cfg.fusion.with_calibration("person", sample_calibration()?);
    let mut engine = LiveCorroborationEngine::new(topo, cfg)?;

    let t39 = engine.observe_clock_sample(
        "sensor:wyze-39",
        ClockObservationSample {
            media_pts_ns: 1_000_000_000,
            host_receive_ns: 50_000_000_000,
            rtt_jitter_ns: 20_000_000,
            node_clock_uncertainty_ns: 2_000_000,
        },
    )?;
    let t51 = engine.observe_clock_sample(
        "sensor:wyze-51",
        ClockObservationSample {
            media_pts_ns: 1_010_000_000,
            host_receive_ns: 50_010_000_000,
            rtt_jitter_ns: 20_000_000,
            node_clock_uncertainty_ns: 2_000_000,
        },
    )?;

    assert!(
        engine
            .ingest_observation(make_obs(
                "sensor:wyze-39",
                "driveway",
                1,
                Some([10.0, 20.0]),
                950_000,
                t39,
                b"w39",
            ))?
            .is_empty()
    );
    let decisions = engine.ingest_observation(make_obs(
        "sensor:wyze-51",
        "driveway",
        2,
        Some([10.5, 20.2]),
        940_000,
        t51,
        b"w51",
    ))?;
    assert_eq!(decisions.len(), 1);
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
            assert!(shared_domains.contains("power:main"));
            assert_eq!(event.state, EventState::Indeterminate);
            assert_eq!(*policy_action, ReferencePolicyAction::Hold);
            assert_eq!(
                committed_reference_policy_action(event),
                ReferencePolicyAction::Hold
            );
            event.verify()?;
        }
        other => return Err(format!("expected SharedFailureDomainHeld, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn ten_second_clock_skew_abstains_cleanly() -> Result<(), Box<dyn std::error::Error>> {
    let mut topo = SiteTopologyRegistry::new("site:skew-test");
    topo.register_camera(CameraTopologyEntry {
        sensor_id: "sensor:wyze-51".to_owned(),
        failure_domains: domains(&["wifi:home", "power:main"]),
        homography: Some(identity_homography(3.0)),
        zones: domains(&["porch"]),
    })
    .register_camera(CameraTopologyEntry {
        sensor_id: "sensor:unifi-177".to_owned(),
        failure_domains: domains(&["poe_switch:1", "ups:rack"]),
        homography: Some(identity_homography(3.0)),
        zones: domains(&["porch"]),
    });

    let mut cfg = LiveCorroborationConfig::default_config()?;
    cfg.fusion = cfg.fusion.with_calibration("person", sample_calibration()?);
    let mut engine = LiveCorroborationEngine::new(topo, cfg)?;

    let _baseline = engine.observe_clock_sample(
        "sensor:wyze-51",
        ClockObservationSample {
            media_pts_ns: 1_000_000_000,
            host_receive_ns: 100_000_000_000,
            rtt_jitter_ns: 15_000_000,
            node_clock_uncertainty_ns: 2_000_000,
        },
    )?;
    // Inject 10-second clock skew on Wyze camera.
    let skewed_wyze = engine.observe_clock_sample(
        "sensor:wyze-51",
        ClockObservationSample {
            media_pts_ns: 2_000_000_000,
            host_receive_ns: 111_000_000_000,
            rtt_jitter_ns: 15_000_000,
            node_clock_uncertainty_ns: 2_000_000,
        },
    )?;
    let clean_unifi = engine.observe_clock_sample(
        "sensor:unifi-177",
        ClockObservationSample {
            media_pts_ns: 2_000_000_000,
            host_receive_ns: 111_000_000_000,
            rtt_jitter_ns: 5_000_000,
            node_clock_uncertainty_ns: 1_000_000,
        },
    )?;

    engine.ingest_observation(make_obs(
        "sensor:wyze-51",
        "porch",
        10,
        Some([5.0, 5.0]),
        950_000,
        skewed_wyze,
        b"skew-w",
    ))?;
    let decisions = engine.ingest_observation(make_obs(
        "sensor:unifi-177",
        "porch",
        20,
        Some([5.1, 5.1]),
        950_000,
        clean_unifi,
        b"skew-u",
    ))?;
    assert_eq!(decisions.len(), 1);
    match &decisions[0].outcome {
        CorroborationOutcome::ClockUncertaintyAbstained {
            uncertainty_ns,
            max_allowed_ns,
            ..
        } => {
            assert!(*uncertainty_ns >= 10_000_000_000);
            assert_eq!(*max_allowed_ns, DEFAULT_MAX_CLOCK_UNCERTAINTY_NS);
        }
        other => return Err(format!("expected ClockUncertaintyAbstained, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn sliding_window_evicts_by_watermark_and_bounds_memory() -> Result<(), Box<dyn std::error::Error>>
{
    let cfg = SlidingWindowConfig {
        retention_ns: 5_000_000_000,
        max_total_observations: 12,
        max_observations_per_camera: 8,
    };
    let mut win = ObservationWindow::new(cfg)?;
    for i in 1_u64..=40 {
        let ts = i128::from(i) * 500_000_000;
        let cap = BoundedCaptureInterval::new(ts, ts + 5_000_000, ClockBasis::AuthenticatedNtp)?;
        let cam = if i % 2 == 0 {
            "sensor:cam-a"
        } else {
            "sensor:cam-b"
        };
        win.insert(make_obs(
            cam,
            "entry",
            i,
            None,
            900_000,
            cap,
            &i.to_le_bytes(),
        ));
        assert!(win.len() <= cfg.max_total_observations);
        assert!(win.camera_len("sensor:cam-a") <= cfg.max_observations_per_camera);
        assert!(win.camera_len("sensor:cam-b") <= cfg.max_observations_per_camera);
    }
    // Advance watermark well past all observations -> complete eviction.
    let stats = win.advance_watermark(1_000_000_000_000);
    assert!(stats.evicted_by_watermark > 0);
    assert_eq!(win.len(), 0);
    Ok(())
}

#[test]
fn uncalibrated_scores_fail_closed_and_shared_zone_cascade_bridge_works()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::ingest::model_pool::{
        CameraPriorityTier, CascadeFrameReceipt, ModelDetectionSummary, Stage1Telemetry,
        StageDecision,
    };
    use fss_core::SensorId;

    let mut topo = SiteTopologyRegistry::new("site:shared-zone-test");
    topo.register_camera(CameraTopologyEntry {
        sensor_id: "sensor:cam-1".to_owned(),
        failure_domains: domains(&["wifi:east", "power:circuit-a"]),
        homography: None,
        zones: domains(&["entryway"]),
    })
    .register_camera(CameraTopologyEntry {
        sensor_id: "sensor:cam-2".to_owned(),
        failure_domains: domains(&["poe_switch:west", "ups:b"]),
        homography: None,
        zones: domains(&["entryway"]),
    })
    .add_shared_zone(SharedZoneOverlap {
        zone_id: "entryway".to_owned(),
        cameras: domains(&["sensor:cam-1", "sensor:cam-2"]),
        max_separation_ns: 2_000_000_000,
    });

    // Without any registered ScoreCalibration, fss-fusion MUST fail closed and hold!
    let mut uncal_engine =
        LiveCorroborationEngine::new(topo.clone(), LiveCorroborationConfig::default_config()?)?;
    let mk_receipt =
        |sensor: &str, tag: &[u8]| -> Result<CascadeFrameReceipt, Box<dyn std::error::Error>> {
            Ok(CascadeFrameReceipt {
                stream_order: 0,
                frame_sequence: 1,
                sensor_id: SensorId::parse(sensor)?,
                source_digest: ContentDigest::sha256(&[b"src:", tag].concat()),
                is_keyframe: true,
                priority: CameraPriorityTier::HighConsequenceZone,
                model_id: "det:person".to_owned(),
                package_digest: ContentDigest::sha256(b"pkg:det"),
                model_generation: "gen:v1".to_owned(),
                execution_profile_digest: ContentDigest::sha256(b"exec:v1"),
                stage_decision: StageDecision::MotionTriggered,
                stage1: Stage1Telemetry {
                    foreground_pixels: 500,
                    foreground_box_count: 1,
                    osd_ignore_regions_digest: ContentDigest::sha256(b"osd:none"),
                    osd_ignore_region_count: 0,
                    health_findings_count: 0,
                    work_units: 10,
                },
                detections: vec![ModelDetectionSummary {
                    class_index: 0,
                    label: "person".to_owned(),
                    score_bits: 0.95_f32.to_bits(),
                    bounds: [100 * 256, 50 * 256, 200 * 256, 300 * 256],
                }],
                activity_score_bits: None,
                inference_output_digest: Some(ContentDigest::sha256(&[b"out:", tag].concat())),
                executed_macs: 1_000,
                unsampled_gap_recorded: false,
                unsampled_reason: None,
                decline_receipt: None,
                work_units_spent: 100,
                absence_certifiable: false,
                effects_authorized: false,
                receipt_digest: ContentDigest::sha256(&[b"rcpt:", tag].concat()),
            })
        };
    let r1 = mk_receipt("sensor:cam-1", b"r1")?;
    let r2 = mk_receipt("sensor:cam-2", b"r2")?;
    let s1 = ClockObservationSample {
        media_pts_ns: 1_000_000_000,
        host_receive_ns: 50_000_000_000,
        rtt_jitter_ns: 10_000_000,
        node_clock_uncertainty_ns: 1_000_000,
    };
    let s2 = ClockObservationSample {
        media_pts_ns: 2_000_000_000,
        host_receive_ns: 50_020_000_000,
        rtt_jitter_ns: 10_000_000,
        node_clock_uncertainty_ns: 1_000_000,
    };
    assert!(
        uncal_engine
            .ingest_cascade_receipt(&r1, "main", "entryway", 1, s1)?
            .is_empty()
    );
    let held = uncal_engine.ingest_cascade_receipt(&r2, "main", "entryway", 2, s2)?;
    assert_eq!(held.len(), 1);
    assert!(matches!(
        held[0].outcome,
        CorroborationOutcome::InsufficientEvidenceHeld { .. }
    ));

    // With calibration registered, the exact same cascade receipts corroborate via SharedZone!
    let mut cal_cfg = LiveCorroborationConfig::default_config()?;
    cal_cfg.fusion = cal_cfg
        .fusion
        .with_calibration("person", sample_calibration()?);
    let mut cal_engine = LiveCorroborationEngine::new(topo, cal_cfg)?;
    assert!(
        cal_engine
            .ingest_cascade_receipt(&r1, "main", "entryway", 1, s1)?
            .is_empty()
    );
    let corr = cal_engine.ingest_cascade_receipt(&r2, "main", "entryway", 2, s2)?;
    assert_eq!(corr.len(), 1);
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
