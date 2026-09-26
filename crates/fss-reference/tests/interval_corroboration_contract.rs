#![forbid(unsafe_code)]
//! Real retained JPEGs through interval-gated corroboration and exact event publication.
//! Synthetic moving squares prove wiring, not camera calibration or detection quality.

#[path = "cascade_support/mod.rs"]
mod support;

use std::collections::BTreeSet;
use std::fs;

use fss_core::{ContentDigest, EventKind, EventState, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::recorded_corroboration::{
    CorroborationCamera, CorroborationError, CorroborationGates, CorroborationPlan,
    CorroborationReport, EntryDisposition, GroundHomography, GroundZone,
};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{WatchDetectorConfig, WatchLimits, WatchTrackerConfig};
use fss_reference::ingest::{CaptureHint, FileFormatHint, FileIngestAdapter, FileIngestRequest};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use support::{Fixture, TestResult};

fn scene(mirror: bool) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    for index in 0..14 {
        let mut pixels = vec![40_u8; 96 * 48];
        if index >= 3 {
            let left = (index - 3) * 8;
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * 96 + x] = 220;
                }
            }
        }
        if mirror {
            for row in pixels.as_chunks_mut::<96>().0 {
                row.reverse();
            }
        }
        bytes.extend(encode_jpeg(96, 48, &pixels, &config)?);
    }
    Ok(bytes)
}

fn plan(east: ContentDigest, west: ContentDigest) -> CorroborationPlan {
    CorroborationPlan {
        cameras: [
            CorroborationCamera {
                name: "east".into(),
                import_identity: east,
                homography: GroundHomography {
                    matrix: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
                },
            },
            CorroborationCamera {
                name: "west".into(),
                import_identity: west,
                homography: GroundHomography {
                    matrix: [-1.0, 0.0, 96.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
                },
            },
        ],
        interpretation: ComponentInterpretation::Grayscale,
        zones: vec![GroundZone {
            zone_id: "door".into(),
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
fn retained_interval_corroboration_is_deterministic_approved_and_published_once() -> TestResult {
    let mut fixture = Fixture::new("interval-publication")?;
    let east = fixture.ingest(
        "sensor:interval-east",
        &scene(false)?,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    let west = fixture.ingest(
        "sensor:interval-west",
        &scene(true)?,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    let plan = plan(east, west);
    let limits = WatchLimits::default();
    let before = fixture.deployment.current_anchor().clone();
    let effects = fixture.deployment.effects().last_root();
    let mut report =
        CorroborationReport::analyze(&fixture.deployment, &plan, &limits, &fixture.cx)?;
    assert_eq!(*fixture.deployment.current_anchor(), before);
    assert_eq!(
        report.candidates().len(),
        1,
        "{}",
        report.to_json(0, None, None)
    );
    let candidate = &report.candidates()[0];
    assert_eq!(candidate.event().state, EventState::Corroborated);
    assert_eq!(candidate.event().kind, EventKind::Unclassified);
    assert!(candidate.worst_case_separation_ns <= u128::from(plan.gates.time_gate_ns));
    let proposal = candidate.proposal_digest();
    let repeated = CorroborationReport::analyze(&fixture.deployment, &plan, &limits, &fixture.cx)?;
    assert_eq!(
        repeated.to_json(0, None, None),
        report.to_json(0, None, None)
    );
    let bogus = ContentDigest::sha256(b"not this interval analysis");
    assert!(
        matches!(report.publish(&mut fixture.deployment, &BTreeSet::from([bogus]), &fixture.cx),
        Err(CorroborationError::StaleApproval(value)) if value == bogus)
    );
    assert_eq!(*fixture.deployment.current_anchor(), before);
    assert_eq!(
        report.publish(
            &mut fixture.deployment,
            &BTreeSet::from([proposal]),
            &fixture.cx
        )?,
        1
    );
    let published = fixture.deployment.current_anchor().clone();
    let mut repeated =
        CorroborationReport::analyze(&fixture.deployment, &plan, &limits, &fixture.cx)?;
    assert_eq!(repeated.candidates()[0].proposal_digest(), proposal);
    assert_eq!(
        repeated.publish(
            &mut fixture.deployment,
            &BTreeSet::from([proposal]),
            &fixture.cx
        )?,
        0
    );
    assert_eq!(*fixture.deployment.current_anchor(), published);
    // Corroboration is an event decision, not permission to send a notification.
    assert_eq!(fixture.deployment.effects().last_root(), effects);
    Ok(())
}

fn ingest_uncertain(fixture: &mut Fixture, name: &str, mirror: bool) -> TestResult<ContentDigest> {
    let path = fixture.directory.0.join(format!("{name}.mjpeg"));
    fs::write(&path, scene(mirror)?)?;
    let request = FileIngestRequest::new(
        path.clone(),
        SensorId::parse(format!("sensor:{name}"))?,
        StreamId::parse(format!("stream:{name}"))?,
    )
    .with_receive_time(TimestampNs(10_000_000_000_000))
    .with_format_hint(FileFormatHint::JpegStream)
    .with_capture_hint(CaptureHint::new(
        TimestampNs(1_000_000_000),
        200_000_000,
        10.0,
    )?);
    let identity =
        FileIngestAdapter::ingest(request, &fixture.cx, &mut fixture.deployment)?.import_identity;
    fs::remove_file(path)?;
    Ok(identity)
}

#[test]
fn overlapping_uncertain_retained_entries_never_become_corroborated_events() -> TestResult {
    let mut fixture = Fixture::new("interval-uncertainty")?;
    let east = ingest_uncertain(&mut fixture, "uncertain-east", false)?;
    let west = ingest_uncertain(&mut fixture, "uncertain-west", true)?;
    let before = fixture.deployment.current_anchor().clone();
    let effects = fixture.deployment.effects().last_root();
    let report = CorroborationReport::analyze(
        &fixture.deployment,
        &plan(east, west),
        &WatchLimits::default(),
        &fixture.cx,
    )?;
    assert!(report.candidates().is_empty());
    assert_eq!(
        report.entries().len(),
        2,
        "{}",
        report.to_json(0, None, None)
    );
    assert!(
        report
            .entries()
            .iter()
            .all(|entry| entry.disposition == EntryDisposition::TimeGateUncertain)
    );
    assert!(
        report
            .entries()
            .iter()
            .all(|entry| entry.capture.earliest < entry.capture.latest)
    );
    let json = report.to_json(0, None, None);
    assert!(json.contains("\"absence_certifiable\":false"));
    assert!(json.contains("\"effects_authorized\":false"));
    assert_eq!(*fixture.deployment.current_anchor(), before);
    assert_eq!(fixture.deployment.effects().last_root(), effects);
    Ok(())
}
