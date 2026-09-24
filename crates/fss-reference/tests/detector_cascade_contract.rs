#![forbid(unsafe_code)]
//! Detection cascade (fss-704tz) on real retained bytes with the verified YOLOX-Nano package.
//!
//! A synthetic person-shaped silhouette (the conformance generator, `yolox_support/person.rs`)
//! walks into an owner zone. The cheap foreground + Kalman gate selects frames; the package runs
//! only there, within an explicit budget. Each test runs exactly one real inference (about a
//! minute in debug builds). This proves wiring and evidence shape, not detection quality: scores
//! are uncalibrated and a synthetic scene says nothing about deployment recall.

#[path = "yolox_support/person.rs"]
mod person;
#[path = "cascade_support/mod.rs"]
mod support;

use fss_core::{ContentDigest, EventKind, EventState};
use fss_reference::ReferencePolicyAction;
use fss_reference::ScalarExecCx;
use fss_reference::ingest::FileFormatHint;
use fss_reference::ingest::detector_cascade::{
    CascadeConfig, DetectorCascade, EvidenceOutcome, FrameStatus, SelectionReason,
};
use fss_reference::ingest::package_detect::PackageDetectLimits;
use fss_reference::ingest::recorded_corroboration::{
    CorroborationCamera, CorroborationGates, CorroborationPlan, CorroborationReport,
    GroundHomography, GroundZone,
};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchLimits, WatchPlan, WatchReport, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::rgb_package::{RgbDetectorPackage, RgbPackageError};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use support::{Fixture, TestResult};

const PACKAGE_SHA256: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";
const PACKAGE: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
const FRAMES: usize = 12;

/// Two empty frames, then the silhouette walks right 24 px per frame from foot x = 60.
/// `mirror` flips every frame horizontally (the second camera of the corroboration scene).
fn person_mjpeg(mirror: bool) -> TestResult<Vec<u8>> {
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
        stream.extend(encode_jpeg(width, height, &pixels, &config)?);
    }
    Ok(stream)
}

/// Only the silhouette's torso/legs blob passes; thin arm and hair blobs are below the floor.
fn foreground() -> WatchDetectorConfig {
    WatchDetectorConfig {
        minimum_region_pixels: 1500,
        ..WatchDetectorConfig::default()
    }
}

/// Twelve 360x640 color frames need more JPEG work than the default ceiling.
fn limits() -> WatchLimits {
    WatchLimits {
        jpeg_work_units: 2_000_000_000,
        ..WatchLimits::default()
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

#[test]
fn watch_cascade_infers_only_selected_frames_types_budget_exhaustion_and_stays_unclassified()
-> TestResult {
    let mut fixture = Fixture::new("watch")?;
    let import = fixture.ingest(
        "sensor:cascade-watch",
        &person_mjpeg(false)?,
        FileFormatHint::JpegStream,
        None,
    )?;
    let plan = WatchPlan {
        import_identity: import,
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
    };
    let limits = limits();
    let plain = WatchReport::analyze(&fixture.deployment, &plan, &limits, &fixture.cx)?;
    assert_eq!(plain.candidates().len(), 1, "{}", plain.to_json(0, None));

    // A wrong package digest is refused before the archive is parsed.
    let scalar = ScalarExecCx::new();
    let wrong = RgbDetectorPackage::load(
        PACKAGE,
        ContentDigest::sha256(b"not the package"),
        1 << 40,
        &fixture.cx,
        &scalar,
    );
    assert!(matches!(
        wrong,
        Err(ref e @ RgbPackageError::DigestMismatch) if e.stable_id() == "ERR-MODEL-PACKAGE-DIGEST-001"
    ));

    let package = package(&fixture, &scalar)?;
    let config = CascadeConfig {
        frames_per_track: 2,
        max_inferences: 1,
        minimum_association_iou_ppm: 200_000,
        minimum_score_ppm: None,
    };
    let mut cascade =
        DetectorCascade::new(&package, config, PackageDetectLimits::default(), &scalar)?;
    let report = WatchReport::analyze_with_detector(
        &fixture.deployment,
        &plan,
        &limits,
        Some(&mut cascade),
        &fixture.cx,
    )?;
    // Exactly one model execution for a twelve-frame recording.
    assert_eq!(cascade.executed_inferences(), 1);
    let outcome = report.detector_cascade().ok_or("cascade outcome missing")?;
    let [candidate] = report.candidates() else {
        return Err("expected exactly one candidate".into());
    };
    let [plain_candidate] = plain.candidates() else {
        return Err("expected exactly one plain candidate".into());
    };
    assert_eq!(candidate.entry_segment, plain_candidate.entry_segment);
    assert_eq!(candidate.track_id, plain_candidate.track_id);
    assert_ne!(candidate.identity(), plain_candidate.identity());
    assert_eq!(outcome.inferred_segments(), [candidate.entry_segment]);
    let skipped = outcome.budget_skipped_segments();
    let [budgeted] = skipped[..] else {
        return Err("expected one budget-skipped frame".into());
    };
    assert!(budgeted < candidate.entry_segment);
    assert!(outcome.refused_segments().is_empty());
    assert_eq!(outcome.cascade_skipped.len(), FRAMES - 2);
    assert!(matches!(
        outcome.frames[1].status,
        FrameStatus::BudgetExhausted
    ));

    // Class evidence: the entry frame's person detection, then typed budget exhaustion.
    let [entry, confirmation] = &candidate.class_evidence[..] else {
        return Err("expected two class evidence records".into());
    };
    assert_eq!(entry.reason, SelectionReason::ZoneEntry);
    assert_eq!(entry.segment, candidate.entry_segment);
    let EvidenceOutcome::Associated { detection, iou_ppm } = &entry.outcome else {
        return Err(format!("entry frame not associated: {:?}", entry.outcome).into());
    };
    assert_eq!(detection.label, "person");
    assert_eq!(detection.class_index, 0);
    assert!(detection.score >= 0.3, "{detection:?}");
    assert!(*iou_ppm >= 200_000);
    assert_eq!(confirmation.reason, SelectionReason::Confirmation);
    assert_eq!(confirmation.segment, budgeted);
    assert_eq!(confirmation.outcome, EvidenceOutcome::BudgetExhausted);

    // Supporting cognition evidence only: kind, state and failure domains are unchanged.
    let event = candidate.event();
    assert_eq!(event.kind, EventKind::Unclassified);
    assert_eq!(event.state, EventState::Indeterminate);
    assert!(event.decision_path.abstained);
    let corroboration = event.analyze_corroboration();
    assert!(!corroboration.is_corroborated);
    assert_eq!(corroboration.distinct_failure_domains.len(), 1);
    assert_eq!(corroboration.supporting_count, 1);
    assert!(
        event
            .evidence
            .iter()
            .any(|e| e.digest == entry.digest && e.supports)
    );
    assert!(
        event
            .evidence
            .iter()
            .any(|e| e.digest == confirmation.digest && !e.supports)
    );
    assert_eq!(
        event.evidence.len(),
        plain_candidate.event().evidence.len() + 2
    );

    // The coverage pipeline generation binds the detector generation.
    assert_ne!(
        report.coverage().zones[0].pipeline_generation,
        plain.coverage().zones[0].pipeline_generation
    );
    let json = report.to_json(0, None);
    for needle in [
        "\"detector_cascade\":{\"cascade_digest\":",
        &format!("\"package_digest\":\"{PACKAGE_SHA256}\""),
        "\"model_id\":\"MOD-YOLOXNANO-001\"",
        "\"inference_count\":1",
        "\"budget_exhausted\":true",
        "\"refusal_id\":\"ERR-DETECTOR-CASCADE-BUDGET-001\"",
        "\"label\":\"person\"",
        "\"score_calibrated\":false",
        "\"scores\":\"uncalibrated\"",
        "\"event_kind\":\"unclassified\"",
        "\"corroborated\":false",
    ] {
        assert!(json.contains(needle), "{needle} missing from {json}");
    }
    // A re-analysis with the same cascade reuses the completed inference and is byte-identical.
    let again = WatchReport::analyze_with_detector(
        &fixture.deployment,
        &plan,
        &limits,
        Some(&mut cascade),
        &fixture.cx,
    )?;
    assert_eq!(cascade.executed_inferences(), 1);
    assert_eq!(again.to_json(0, None), json);
    scalar.drain_and_finalize();
    Ok(())
}

#[test]
fn corroborate_cascade_binds_class_evidence_but_never_changes_the_policy_event() -> TestResult {
    let mut fixture = Fixture::new("corroborate")?;
    let east = fixture.ingest(
        "sensor:cascade-east",
        &person_mjpeg(false)?,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    let west = fixture.ingest(
        "sensor:cascade-west",
        &person_mjpeg(true)?,
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
    let plain = CorroborationReport::analyze(&fixture.deployment, &plan, &limits, &fixture.cx)?;
    let [plain_candidate] = plain.candidates() else {
        return Err("expected one plain corroborated candidate".into());
    };
    assert_eq!(plain_candidate.event().state, EventState::Corroborated);

    let scalar = ScalarExecCx::new();
    let package = package(&fixture, &scalar)?;
    let config = CascadeConfig {
        frames_per_track: 1,
        max_inferences: 1,
        minimum_association_iou_ppm: 200_000,
        minimum_score_ppm: None,
    };
    let mut cascade =
        DetectorCascade::new(&package, config, PackageDetectLimits::default(), &scalar)?;
    let report = CorroborationReport::analyze_with_detector(
        &fixture.deployment,
        &plan,
        &limits,
        Some(&mut cascade),
        &fixture.cx,
    )?;
    // One budget for both recordings: the east entry ran, the west entry is typed exhaustion.
    assert_eq!(cascade.executed_inferences(), 1);
    let [east_outcome, west_outcome] = report.detector_cascade().ok_or("no cascade")? else {
        return Err("expected two camera outcomes".into());
    };
    assert_eq!(east_outcome.inferred_segments().len(), 1);
    assert!(west_outcome.inferred_segments().is_empty());
    assert_eq!(west_outcome.budget_skipped_segments().len(), 1);
    let [candidate] = report.candidates() else {
        return Err("expected one corroborated candidate".into());
    };
    let [left, right] = candidate.entries.map(|i| &report.entries()[i]);
    let [east_evidence] = &left.class_evidence[..] else {
        return Err("expected one east evidence record".into());
    };
    assert!(
        matches!(&east_evidence.outcome, EvidenceOutcome::Associated { detection, .. } if detection.label == "person"),
        "{:?}",
        east_evidence.outcome
    );
    assert_eq!(
        right
            .class_evidence
            .iter()
            .map(|e| &e.outcome)
            .collect::<Vec<_>>(),
        [&EvidenceOutcome::BudgetExhausted]
    );

    // The policy event rests only on the two sensors' own witnesses.
    let event = candidate.event();
    let baseline = plain_candidate.event();
    assert_eq!(event.state, EventState::Corroborated);
    assert_eq!(event.kind, EventKind::Unclassified);
    assert_eq!(event.evidence.len(), baseline.evidence.len());
    assert_eq!(
        candidate.policy_action(),
        ReferencePolicyAction::PrepareAlert
    );
    assert_eq!(candidate.policy_action(), plain_candidate.policy_action());
    assert!(
        !event
            .evidence
            .iter()
            .any(|e| e.digest == east_evidence.digest)
    );
    assert_ne!(candidate.identity(), plain_candidate.identity());
    let json = report.to_json(0, None, None);
    for needle in [
        "\"budget_scope\":\"both_recordings\"",
        "\"inference_count\":1",
        "\"class_evidence\":[",
        "\"event_kind\":\"unclassified\"",
    ] {
        assert!(json.contains(needle), "{needle} missing from {json}");
    }
    scalar.drain_and_finalize();
    Ok(())
}
