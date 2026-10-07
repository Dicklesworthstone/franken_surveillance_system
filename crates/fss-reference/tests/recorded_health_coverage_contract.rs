#![forbid(unsafe_code)]
//! Recorded sensor-health coverage contracts over real retained MJPEG custody and decoding.
//! Synthetic scenes exercise admission, provenance and continuity; they do not qualify health.

#[path = "cascade_support/mod.rs"]
mod support;

use std::collections::BTreeSet;

use fss_core::{ContentDigest, EvidenceEdgeRelation};
use fss_reference::ingest::FileFormatHint;
use fss_reference::ingest::recorded_coverage::{CoverageRecord, UncoveredReason};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_health::RecordedHealthPolicy;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchLimits, WatchOptions, WatchPlan, WatchReport, WatchTrackerConfig,
    WatchZone,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use support::{Fixture, TestResult};

const FRAMES: usize = 32;
const HEALTH: Option<RecordedHealthPolicy> = Some(RecordedHealthPolicy::ConservativeV1);

fn scene(
    value: impl Fn(usize) -> u8,
    square: impl Fn(usize) -> bool,
    corrupt: Option<usize>,
) -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..FRAMES {
        let mut pixels = vec![value(index); 96 * 48];
        if square(index) {
            for y in 8..24 {
                for x in 8..24 {
                    pixels[y * 96 + x] = 220;
                }
            }
        }
        let mut frame = encode_jpeg(96, 48, &pixels, &config)?;
        if corrupt == Some(index) {
            let sof = frame.windows(2).position(|bytes| bytes == [0xff, 0xc0])
                .ok_or("missing synthetic SOF0")?;
            frame[sof + 12] = 4;
        }
        stream.extend(frame);
    }
    Ok(stream)
}

fn plan(import_identity: ContentDigest) -> WatchPlan {
    WatchPlan {
        import_identity,
        interpretation: ComponentInterpretation::Grayscale,
        first_segment: 0,
        segment_count: FRAMES,
        zones: vec![WatchZone {
            zone_id: "door".to_owned(), x: 0, y: 0, width: 32, height: 32,
        }],
        detector: WatchDetectorConfig::default(),
        tracker: WatchTrackerConfig::default(),
    }
}

fn analyse(fixture: &Fixture, plan: &WatchPlan, tolerant: bool) -> TestResult<WatchReport> {
    Ok(WatchReport::analyze_with_health(
        &fixture.deployment, plan, &WatchLimits::default(), None,
        WatchOptions { tolerate_decode_refusals: tolerant }, HEALTH, &fixture.cx,
    )?)
}

fn assert_roundtrip(record: &CoverageRecord) -> TestResult {
    assert_eq!(CoverageRecord::from_bytes(&record.to_bytes(), record.digest())?, *record);
    Ok(())
}

#[test]
fn recorded_health_defaults_and_clear_screen_bind_approvals_and_provenance() -> TestResult {
    let mut fixture = Fixture::new("recorded-health-clear")?;
    let import = fixture.ingest(
        "sensor:recorded-health-clear",
        &scene(|i| if i % 2 == 0 { 40 } else { 48 }, |i| i >= 3, None)?,
        FileFormatHint::JpegStream, Some(1_000_000_000),
    )?;
    let plan = plan(import);
    let legacy = WatchReport::analyze(
        &fixture.deployment, &plan, &WatchLimits::default(), &fixture.cx,
    )?;
    let explicit_none = WatchReport::analyze_with_health(
        &fixture.deployment, &plan, &WatchLimits::default(), None,
        WatchOptions::default(), None, &fixture.cx,
    )?;
    assert_eq!(legacy.to_json(0, None), explicit_none.to_json(0, None));
    assert_eq!(legacy.coverage().to_bytes(), explicit_none.coverage().to_bytes());

    let mut screened = analyse(&fixture, &plan, false)?;
    let summary = screened.sensor_health().ok_or("missing health receipts")?;
    let summary_digest = summary.digest();
    assert!(summary.affected_segments().is_empty());
    assert_eq!(summary.observations().len(), FRAMES);
    assert_eq!(summary.samples_used(), (FRAMES * 96 * 48) as u64);
    assert_eq!(legacy.candidates().len(), 1);
    assert_eq!(screened.candidates().len(), 1);
    assert_ne!(legacy.plan_digest(), screened.plan_digest());
    assert_ne!(legacy.coverage_approval(), screened.coverage_approval());
    assert_ne!(
        legacy.candidates()[0].proposal_digest(),
        screened.candidates()[0].proposal_digest(),
    );
    assert!(screened.candidates()[0].event().evidence.iter().any(|evidence| {
        evidence.digest == summary_digest
            && evidence.relation == EvidenceEdgeRelation::RequiredBy && !evidence.supports
    }));
    assert!(summary.to_json().contains("\"status\":\"clear_screen_not_health_evidence\""));
    assert!(summary.to_json().contains("\"health_certified\":false"));
    assert_roundtrip(screened.coverage())?;
    let approval = screened.candidates()[0].proposal_digest();
    assert_eq!(
        screened.publish(
            &mut fixture.deployment,
            &BTreeSet::from([approval]),
            &fixture.cx,
        )?,
        1,
    );
    let again = analyse(&fixture, &plan, false)?;
    assert_eq!(again.sensor_health().map(|summary| summary.digest()), Some(summary_digest));
    assert_eq!(again.candidates()[0].proposal_digest(), approval);
    Ok(())
}

#[test]
fn recorded_health_retracts_frozen_track_prefix_before_candidate_or_coverage() -> TestResult {
    let mut fixture = Fixture::new("recorded-health-frozen")?;
    let import = fixture.ingest(
        "sensor:recorded-health-frozen",
        &scene(|_| 40, |i| i >= 3, None)?,
        FileFormatHint::JpegStream, Some(1_000_000_000),
    )?;
    let plan = plan(import);
    let legacy = WatchReport::analyze(
        &fixture.deployment, &plan, &WatchLimits::default(), &fixture.cx,
    )?;
    assert_eq!(legacy.candidates().len(), 1);
    let screened = analyse(&fixture, &plan, false)?;
    let summary = screened.sensor_health().ok_or("missing health receipts")?;
    assert_eq!(summary.affected_segments(), &(3..FRAMES as u64).collect::<BTreeSet<_>>());
    assert!(screened.candidates().is_empty());
    assert!(screened.coverage().witnesses().next().is_none());
    assert!(screened.frames().iter().all(|frame| frame.boxes.is_empty()));
    assert!(screened.coverage().zones[0].uncovered.iter().any(|interval| {
        interval.reason == UncoveredReason::SensorHealthDegraded
            && interval.first_segment == 3 && interval.last_segment == 31
    }));
    assert_roundtrip(screened.coverage())?;
    Ok(())
}

#[test]
fn recorded_health_coverage_restarts_background_and_confirmation_after_a_bad_run() -> TestResult {
    let mut fixture = Fixture::new("recorded-health-recovery")?;
    let import = fixture.ingest(
        "sensor:recorded-health-recovery",
        &scene(
            |i| if (12..17).contains(&i) { 0 } else if i % 2 == 0 { 40 } else { 48 },
            |_| false, None,
        )?,
        FileFormatHint::JpegStream, Some(1_000_000_000),
    )?;
    let screened = analyse(&fixture, &plan(import), false)?;
    let summary = screened.sensor_health().ok_or("missing health receipts")?;
    assert_eq!(summary.affected_segments(), &(12..17).collect::<BTreeSet<_>>());
    assert_eq!(screened.tracking_restarts(), &[17]);
    assert!(screened.decode_restarts().is_empty());
    let witnesses = screened.coverage().zones[0].witnesses.iter()
        .map(|witness| (witness.first_segment, witness.last_segment)).collect::<Vec<_>>();
    assert_eq!(witnesses, [(4, 9), (21, 29)]);
    assert!(screened.coverage().zones[0].uncovered.iter().any(|interval| {
        interval.reason == UncoveredReason::BackgroundWarmup
            && interval.first_segment == 17 && interval.last_segment == 20
    }));
    for candidate in screened.candidates() {
        assert!(candidate.observations.iter().all(|frame| !summary.affects(frame.segment)));
        let [first, last] = candidate.frame_range();
        assert!(last < 12 || first > 16);
    }
    assert_roundtrip(screened.coverage())?;
    Ok(())
}

#[test]
fn recorded_health_decode_refusals_reset_screening_without_degradation() -> TestResult {
    let mut fixture = Fixture::new("recorded-health-decode-gap")?;
    let import = fixture.ingest(
        "sensor:recorded-health-decode-gap",
        &scene(
            |i| if i < 7 { 80 } else if i < 15 { 90 } else if i % 2 == 0 { 40 } else { 48 },
            |_| false, Some(7),
        )?,
        FileFormatHint::JpegStream, Some(1_000_000_000),
    )?;
    let screened = analyse(&fixture, &plan(import), true)?;
    let summary = screened.sensor_health().ok_or("missing health receipts")?;
    assert_eq!(summary.observations().len(), FRAMES - 1);
    assert!(summary.affected_segments().is_empty());
    let first_after_gap = summary.observations().iter().find(|frame| frame.segment == 8)
        .ok_or("missing resumed frame")?;
    assert!(first_after_gap.baseline_reset);
    assert_eq!(first_after_gap.repeated_frames, 1);
    assert_eq!(screened.decode_restarts(), &[8]);
    assert_eq!(screened.tracking_restarts(), &[8]);
    assert!(screened.coverage().zones[0].uncovered.iter().any(|interval| {
        matches!(interval.reason, UncoveredReason::DecodeRefused { .. })
            && interval.first_segment == 7 && interval.last_segment == 7
    }));
    for (_, witness) in screened.coverage().witnesses() {
        assert!(witness.last_segment < 7 || witness.first_segment > 7);
    }
    assert_roundtrip(screened.coverage())?;
    Ok(())
}

#[test]
fn recorded_health_receipts_prevent_old_or_forged_witnesses_covering_a_suspect_run() -> TestResult {
    let mut fixture = Fixture::new("recorded-health-forged")?;
    let import = fixture.ingest(
        "sensor:recorded-health-forged",
        &scene(|_| 80, |_| false, None)?,
        FileFormatHint::JpegStream, Some(1_000_000_000),
    )?;
    let plan = plan(import);
    let legacy = WatchReport::analyze(
        &fixture.deployment, &plan, &WatchLimits::default(), &fixture.cx,
    )?;
    assert!(legacy.coverage().witnesses().next().is_some());
    let screened = analyse(&fixture, &plan, false)?;
    let mut forged = legacy.coverage().clone();
    forged.sensor_health = screened.coverage().sensor_health.clone();
    assert!(forged.validate().is_err());
    assert!(CoverageRecord::from_bytes(&forged.to_bytes(), forged.digest()).is_err());
    let mut stripped = screened.coverage().clone();
    stripped.sensor_health = None;
    assert!(stripped.validate().is_err());
    assert!(CoverageRecord::from_bytes(
        &screened.coverage().to_bytes(), legacy.coverage().digest(),
    ).is_err());
    Ok(())
}

#[test]
fn recorded_health_source_and_generation_transplants_with_matching_layout_are_rejected() -> TestResult {
    let mut fixture = Fixture::new("recorded-health-transplant")?;
    let bytes = scene(|i| if i % 2 == 0 { 80 } else { 88 }, |_| false, None)?;
    let first = fixture.ingest(
        "sensor:health-first", &bytes, FileFormatHint::JpegStream, Some(1_000_000_000),
    )?;
    let second = fixture.ingest(
        "sensor:health-second", &bytes, FileFormatHint::JpegStream, Some(1_000_000_000),
    )?;
    let original = analyse(&fixture, &plan(first), false)?;
    let other_source = analyse(&fixture, &plan(second), false)?;
    let mut changed_plan = plan(first);
    changed_plan.tracker.confirmation_hits = 4;
    let other_generation = analyse(&fixture, &changed_plan, false)?;
    for replacement in [other_source.coverage(), other_generation.coverage()] {
        assert_eq!(original.coverage().analysed, replacement.analysed);
        assert_eq!(original.coverage().first_segment, replacement.first_segment);
        assert_eq!(original.coverage().last_segment, replacement.last_segment);
        let mut transplanted = original.coverage().clone();
        transplanted.sensor_health = replacement.sensor_health.clone();
        assert!(transplanted.validate().is_err());
        assert!(CoverageRecord::from_bytes(
            &transplanted.to_bytes(), transplanted.digest(),
        ).is_err());
    }
    Ok(())
}

#[test]
fn recorded_health_late_failure_never_turns_an_earlier_positive_into_absence() -> TestResult {
    let mut fixture = Fixture::new("recorded-health-dependent-track")?;
    let import = fixture.ingest(
        "sensor:recorded-health-dependent-track",
        &scene(|i| if i >= 14 || i % 2 == 0 { 40 } else { 48 }, |i| i >= 3, None)?,
        FileFormatHint::JpegStream, Some(1_000_000_000),
    )?;
    let mut plan = plan(import);
    // Keep the stationary foreground track observable until the late freeze is detected.
    plan.detector.learning_rate_den = 1024;
    let legacy = WatchReport::analyze(
        &fixture.deployment, &plan, &WatchLimits::default(), &fixture.cx,
    )?;
    assert_eq!(legacy.candidates().len(), 1);
    let earlier_entry = legacy.candidates()[0].entry_segment;
    assert!(earlier_entry < 14);
    let screened = analyse(&fixture, &plan, false)?;
    let summary = screened.sensor_health().ok_or("missing health receipts")?;
    assert!(!summary.affects(earlier_entry));
    assert!(summary.withdrawn_track_segments().contains(&(earlier_entry as u64)));
    assert!(screened.candidates().is_empty());
    assert!(screened.coverage().witnesses().next().is_none());
    assert!(screened.coverage().zones[0].uncovered.iter().any(|interval| {
        interval.reason == UncoveredReason::SensorHealthDependentTrack
            && interval.first_segment <= earlier_entry as u64
            && interval.last_segment >= earlier_entry as u64
    }));
    assert_roundtrip(screened.coverage())?;
    Ok(())
}
