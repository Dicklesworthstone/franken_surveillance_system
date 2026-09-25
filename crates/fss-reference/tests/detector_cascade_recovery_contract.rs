#![forbid(unsafe_code)]
//! Recovery composed with the retained watch/corroboration path and the pinned YOLOX package.
//!
//! The generated JPEG stream has one zero quantizer in segment 5: framing and custody remain
//! intact, but native decoding must refuse that segment. These tests use the real codec, cheap
//! tracker, package inference and coverage builder, not mocked detector outcomes. Each test
//! performs one model inference. Synthetic fixtures prove contracts, not detection quality.

#[path = "yolox_support/person.rs"]
mod person;
#[path = "cascade_support/mod.rs"]
mod support;

use std::collections::BTreeSet;

use fss_core::{ContentDigest, EventKind, EventState};
use fss_reference::ScalarExecCx;
use fss_reference::ingest::FileFormatHint;
use fss_reference::ingest::detector_cascade::{CascadeConfig, DetectorCascade, FrameStatus};
use fss_reference::ingest::package_detect::PackageDetectLimits;
use fss_reference::ingest::recorded_corroboration::{
    CorroborationCamera, CorroborationGates, CorroborationOptions, CorroborationPlan,
    CorroborationReport, GroundHomography, GroundVisibilityPlan, GroundZone,
};
use fss_reference::ingest::recorded_coverage::{CoverageRecord, UncoveredReason};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchError, WatchLimits, WatchOptions, WatchPlan, WatchReport,
    WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::tolerant_decode::tolerable;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use support::{Fixture, TestResult};

const PACKAGE_SHA256: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";
const PACKAGE: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
const FRAMES: usize = 12;
const GAP: usize = 5;

fn scene(mirror: bool, damage: bool) -> TestResult<Vec<u8>> {
    let [width, height] = person::PERSON_SCENE_DIMENSIONS;
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Yuv420,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..FRAMES {
        let foot = (index >= 2).then(|| 60 + 24 * (index as i64 - 2));
        let mut pixels = person::person_scene(foot);
        if mirror {
            for row in pixels.chunks_exact_mut(width as usize * 3) {
                let flipped: Vec<u8> = row
                    .as_chunks::<3>()
                    .0
                    .iter()
                    .rev()
                    .flatten()
                    .copied()
                    .collect();
                row.copy_from_slice(&flipped);
            }
        }
        let mut jpeg = encode_jpeg(width, height, &pixels, &config)?;
        if damage && index == GAP {
            // Generated headers have no custom payloads. The first DQT is before entropy;
            // replacing its first 8-bit value changes no marker, length, frame count or time.
            let dqt = jpeg
                .windows(2)
                .position(|pair| pair == [0xff, 0xdb])
                .ok_or("fixture has no quantization table")?;
            let value = jpeg.get_mut(dqt + 5).ok_or("truncated fixture quantizer")?;
            assert_ne!(*value, 0);
            *value = 0;
        }
        stream.extend(jpeg);
    }
    Ok(stream)
}

fn foreground() -> WatchDetectorConfig {
    WatchDetectorConfig {
        minimum_region_pixels: 1500,
        ..WatchDetectorConfig::default()
    }
}

fn limits() -> WatchLimits {
    WatchLimits {
        jpeg_work_units: 2_000_000_000,
        ..WatchLimits::default()
    }
}

fn watch_plan(import_identity: ContentDigest) -> WatchPlan {
    WatchPlan {
        import_identity,
        interpretation: ComponentInterpretation::YCbCr,
        first_segment: 0,
        segment_count: FRAMES,
        zones: vec![WatchZone {
            zone_id: "door".to_owned(),
            x: 200,
            y: 0,
            width: 160,
            height: 640,
        }],
        detector: foreground(),
        tracker: WatchTrackerConfig::default(),
    }
}

fn package(fixture: &Fixture, scalar: &ScalarExecCx) -> TestResult<RgbDetectorPackage> {
    Ok(RgbDetectorPackage::load(
        PACKAGE,
        ContentDigest::parse(PACKAGE_SHA256)?,
        1 << 40,
        &fixture.cx,
        scalar,
    )?)
}

fn config(frames_per_track: usize) -> CascadeConfig {
    CascadeConfig {
        frames_per_track,
        max_inferences: 1,
        minimum_association_iou_ppm: 200_000,
        minimum_score_ppm: None,
    }
}

fn gap_is_uncovered(record: &CoverageRecord, error_id: &str) {
    assert!(!record.zones.is_empty());
    for zone in &record.zones {
        assert!(zone.uncovered.iter().any(|interval| {
            interval.first_segment == GAP as u64
                && interval.last_segment == GAP as u64
                && matches!(&interval.reason, UncoveredReason::DecodeRefused { error_id: id } if id == error_id)
        }));
        assert!(zone.witnesses.iter().all(|witness| {
            witness.last_segment < GAP as u64 || witness.first_segment > GAP as u64
        }));
    }
}

#[test]
fn recovered_watch_infers_after_damage_without_bridging_tracks_or_granting_effects() -> TestResult {
    let mut fixture = Fixture::new("recovered-watch")?;
    let import = fixture.ingest(
        "sensor:recovered-watch",
        &scene(false, true)?,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    let plan = watch_plan(import);
    let limits = limits();
    let before = fixture.deployment.current_anchor().clone();
    let scalar = ScalarExecCx::new();
    let package = package(&fixture, &scalar)?;
    let mut cascade =
        DetectorCascade::new(&package, config(2), PackageDetectLimits::default(), &scalar)?;

    let strict = WatchReport::analyze_with_detector(
        &fixture.deployment,
        &plan,
        &limits,
        Some(&mut cascade),
        &fixture.cx,
    );
    let error = strict
        .err()
        .ok_or("strict mode accepted a malformed quantizer")?;
    let WatchError::Decode(ref cause) = error else {
        return Err(format!("wrong strict refusal: {error}").into());
    };
    assert!(tolerable(cause));
    assert_eq!(cascade.executed_inferences(), 0);
    let error_id = error.stable_id();
    let options = WatchOptions {
        tolerate_decode_refusals: true,
    };
    let plain = WatchReport::analyze_with_options(
        &fixture.deployment,
        &plan,
        &limits,
        None,
        options,
        &fixture.cx,
    )?;
    let mut report = WatchReport::analyze_with_options(
        &fixture.deployment,
        &plan,
        &limits,
        Some(&mut cascade),
        options,
        &fixture.cx,
    )?;
    assert_eq!(report.frames().len(), FRAMES - 1);
    assert_eq!(report.tracking_restarts(), &[GAP + 1]);
    assert_eq!(report.decode_refusals(), plain.decode_refusals());
    assert_eq!(report.frames(), plain.frames());
    assert_eq!(report.candidates().len(), plain.candidates().len());
    assert!(!report.candidates().is_empty());
    assert_eq!(cascade.executed_inferences(), 1);
    let outcome = report.detector_cascade().ok_or("no recovered cascade")?;
    assert_eq!(outcome.inferred_segments().len(), 1);
    assert!(
        outcome
            .inferred_segments()
            .iter()
            .all(|segment| *segment > GAP)
    );
    assert!(!outcome.budget_skipped_segments().is_empty());
    assert!(outcome.refused_segments().is_empty());
    assert!(outcome.frames.iter().all(|frame| frame.segment != GAP));
    assert!(!outcome.cascade_skipped.contains(&GAP));
    gap_is_uncovered(report.coverage(), error_id);
    assert!(report.coverage().zones.iter().any(|zone| {
        zone.witnesses
            .iter()
            .any(|witness| witness.first_segment > GAP as u64)
    }));
    for candidate in report.candidates() {
        // This zone is entered only after the damaged frame and the tracking restart.
        assert!(candidate.frame_range()[0] > GAP);
        assert!(
            candidate
                .class_evidence
                .iter()
                .all(|item| item.segment > GAP)
        );
        assert_eq!(candidate.event().kind, EventKind::Unclassified);
        assert_eq!(candidate.event().state, EventState::Indeterminate);
        assert!(candidate.event().decision_path.abstained);
        assert!(!candidate.event().analyze_corroboration().is_corroborated);
    }
    assert_eq!(*fixture.deployment.current_anchor(), before);
    let bogus = ContentDigest::sha256(b"not an approval for recovered evidence");
    assert!(matches!(
        report.publish(&mut fixture.deployment, &BTreeSet::from([bogus]), &fixture.cx),
        Err(WatchError::StaleApproval(value)) if value == bogus
    ));
    assert_eq!(*fixture.deployment.current_anchor(), before);
    scalar.drain_and_finalize();
    Ok(())
}

#[test]
fn recovered_corroboration_shares_one_allowance_and_keeps_sensor_policy_independent() -> TestResult
{
    let mut fixture = Fixture::new("recovered-corroboration")?;
    let east = fixture.ingest(
        "sensor:recovered-east",
        &scene(false, true)?,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    let west = fixture.ingest(
        "sensor:recovered-west",
        &scene(true, false)?,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    let plan = CorroborationPlan {
        cameras: [
            CorroborationCamera {
                name: "east".to_owned(),
                import_identity: east,
                homography: GroundHomography {
                    matrix: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
                },
            },
            CorroborationCamera {
                name: "west".to_owned(),
                import_identity: west,
                homography: GroundHomography {
                    matrix: [-1.0, 0.0, 360.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
                },
            },
        ],
        interpretation: ComponentInterpretation::YCbCr,
        zones: vec![GroundZone {
            zone_id: "door".to_owned(),
            x: 200.0,
            y: 0.0,
            width: 160.0,
            height: 640.0,
        }],
        gates: CorroborationGates {
            time_gate_ns: 250_000_000,
            distance_gate: 16.0,
        },
        detector: foreground(),
        tracker: WatchTrackerConfig::default(),
    };
    let limits = limits();
    let visibility = GroundVisibilityPlan::default();
    let options = CorroborationOptions {
        tolerate_decode_refusals: true,
    };
    let before = fixture.deployment.current_anchor().clone();
    let plain = CorroborationReport::analyze_with_options(
        &fixture.deployment,
        &plan,
        &limits,
        None,
        &visibility,
        options,
        &fixture.cx,
    )?;
    let scalar = ScalarExecCx::new();
    let package = package(&fixture, &scalar)?;
    let mut cascade =
        DetectorCascade::new(&package, config(1), PackageDetectLimits::default(), &scalar)?;
    let report = CorroborationReport::analyze_with_options(
        &fixture.deployment,
        &plan,
        &limits,
        Some(&mut cascade),
        &visibility,
        options,
        &fixture.cx,
    )?;
    let [east, west] = report.detector_cascade().ok_or("no recovered cascade")? else {
        return Err("expected both camera outcomes".into());
    };
    assert_eq!(cascade.executed_inferences(), 1);
    assert_eq!(east.inferred_segments().len(), 1);
    assert!(
        east.inferred_segments()
            .iter()
            .all(|segment| *segment > GAP)
    );
    assert!(west.inferred_segments().is_empty());
    assert!(!west.frames.is_empty());
    assert!(
        west.frames
            .iter()
            .all(|frame| matches!(frame.status, FrameStatus::BudgetExhausted))
    );
    assert_eq!(report.cameras()[0].tracking_restarts, vec![GAP + 1]);
    assert!(report.cameras()[1].decode_refusals.is_empty());
    let [refusal] = &report.cameras()[0].decode_refusals[..] else {
        return Err("expected the exact east-camera decode refusal".into());
    };
    assert_eq!((refusal.first_segment, refusal.last_segment), (GAP, GAP));
    gap_is_uncovered(&report.coverage()[0], &refusal.error_id);
    assert_eq!(report.entries().len(), plain.entries().len());
    assert!(report.entries().iter().any(|entry| entry.camera == 0));
    assert!(report.entries().iter().any(|entry| entry.camera == 1));
    for (entry, baseline) in report.entries().iter().zip(plain.entries()) {
        assert_eq!(entry.disposition, baseline.disposition);
        assert_eq!(entry.capture, baseline.capture);
        assert_eq!(entry.record_digest, baseline.record_digest);
    }
    assert_eq!(report.candidates().len(), plain.candidates().len());
    assert!(!report.candidates().is_empty());
    for (candidate, baseline) in report.candidates().iter().zip(plain.candidates()) {
        assert_eq!(candidate.event().kind, EventKind::Unclassified);
        assert_eq!(candidate.event().state, baseline.event().state);
        assert_eq!(candidate.policy_action(), baseline.policy_action());
        assert_eq!(
            candidate.worst_case_separation_ns,
            baseline.worst_case_separation_ns
        );
        let classes: BTreeSet<_> = report
            .entries()
            .iter()
            .flat_map(|entry| entry.class_evidence.iter().map(|item| item.digest))
            .collect();
        assert!(
            candidate
                .event()
                .evidence
                .iter()
                .all(|edge| !classes.contains(&edge.digest))
        );
    }
    assert_eq!(*fixture.deployment.current_anchor(), before);
    assert!(
        report
            .to_json(0, None, None)
            .contains("\"effects_authorized\":false")
    );
    scalar.drain_and_finalize();
    Ok(())
}

#[test]
fn clean_tolerant_cascade_keeps_exact_report_bytes_and_completed_inference_cache() -> TestResult {
    let mut fixture = Fixture::new("clean-tolerant-cascade")?;
    let import = fixture.ingest(
        "sensor:clean-tolerant-cascade",
        &scene(false, false)?,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    let plan = watch_plan(import);
    let limits = limits();
    let scalar = ScalarExecCx::new();
    let package = package(&fixture, &scalar)?;
    let mut cascade =
        DetectorCascade::new(&package, config(1), PackageDetectLimits::default(), &scalar)?;
    let strict = WatchReport::analyze_with_detector(
        &fixture.deployment,
        &plan,
        &limits,
        Some(&mut cascade),
        &fixture.cx,
    )?;
    assert_eq!(cascade.executed_inferences(), 1);
    let tolerant = WatchReport::analyze_with_options(
        &fixture.deployment,
        &plan,
        &limits,
        Some(&mut cascade),
        WatchOptions {
            tolerate_decode_refusals: true,
        },
        &fixture.cx,
    )?;
    assert!(tolerant.decode_refusals().is_empty());
    assert!(tolerant.tracking_restarts().is_empty());
    assert_eq!(cascade.executed_inferences(), 1);
    assert_eq!(tolerant.to_json(0, None), strict.to_json(0, None));
    assert_eq!(tolerant.coverage(), strict.coverage());
    scalar.drain_and_finalize();
    Ok(())
}
