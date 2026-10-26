#![forbid(unsafe_code)]
//! Retained historical findings must invalidate matching legacy negative evidence on cold reads.
//! Native synthetic MJPEG exercises custody and projection; it does not qualify sensor health.

#[path = "cascade_support/mod.rs"]
mod support;

use std::fs;

use fss_core::{
    AgentView, Completeness, ContentDigest, MeaningfulDeltaClass, PrincipalId, SensorId,
};
use fss_reference::agent_follow::{
    AnchorToken, FollowRequest, follow_deployment, snapshot_anchor_token,
};
use fss_reference::agent_orient::{
    DeploymentHistory, DeploymentOrientation, OrientLimits, OrientRequest, ZoneCoverageState,
    orient_deployment, read_deployment,
};
use fss_reference::ingest::FileFormatHint;
use fss_reference::ingest::historical_health::HistoricalHealthRecord;
use fss_reference::ingest::long_dwell::{LongDwellLimits, LongDwellReport};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchLimits, WatchOptions, WatchPlan, WatchReport, WatchTrackerConfig,
    WatchZone,
};
use fss_reference::ingest::zone_dwell::DwellPolicy;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use support::{Fixture, TestResult};

const FRAMES: usize = 32;
const WIDTH: usize = 32;
const HEIGHT: usize = 24;
const SENSOR: &str = "sensor:historical-coverage";

fn scene(frozen: bool) -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut bytes = Vec::new();
    for index in 0..FRAMES {
        let value = if frozen || index % 2 == 0 { 80 } else { 88 };
        bytes.extend(encode_jpeg(
            WIDTH as u32,
            HEIGHT as u32,
            &vec![value; WIDTH * HEIGHT],
            &config,
        )?);
    }
    Ok(bytes)
}

fn import(fixture: &mut Fixture, frozen: bool) -> TestResult<ContentDigest> {
    fixture.ingest(
        SENSOR,
        &scene(frozen)?,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )
}

fn plan(import_identity: ContentDigest, first_segment: usize, segment_count: usize) -> WatchPlan {
    WatchPlan {
        import_identity,
        interpretation: ComponentInterpretation::Grayscale,
        first_segment,
        segment_count,
        zones: vec![WatchZone {
            zone_id: "quiet-zone".to_owned(),
            x: 0,
            y: 0,
            width: WIDTH as u32,
            height: HEIGHT as u32,
        }],
        detector: WatchDetectorConfig::default(),
        tracker: WatchTrackerConfig::default(),
    }
}

fn retain_coverage(fixture: &mut Fixture, plan: &WatchPlan) -> TestResult<Vec<u8>> {
    let mut report = WatchReport::analyze(
        &fixture.deployment,
        plan,
        &WatchLimits::default(),
        &fixture.cx,
    )?;
    assert!(report.candidates().is_empty());
    assert!(report.coverage().witnesses().next().is_some());
    let bytes = report.coverage().to_bytes();
    let approval = report.coverage_approval();
    report.retain_coverage(&mut fixture.deployment, approval, &fixture.cx)?;
    Ok(bytes)
}

fn retain_diagnostic(
    fixture: &mut Fixture,
    plan: &WatchPlan,
) -> TestResult<HistoricalHealthRecord> {
    let report = LongDwellReport::analyze_screened(
        &fixture.deployment,
        plan,
        DwellPolicy {
            minimum_duration_ns: 20_000_000_000,
            maximum_sample_gap_ns: 102_000_000,
            minimum_observations: 3,
        },
        WatchOptions::default(),
        &LongDwellLimits::default(),
        &fixture.cx,
    )?;
    assert!(report.candidates().is_empty());
    let diagnostic = report.health_diagnostic().ok_or("missing diagnostic")?;
    let record = diagnostic.record().clone();
    diagnostic.retain(
        &mut fixture.deployment,
        diagnostic.approval_digest(),
        &fixture.cx,
    )?;
    Ok(record)
}

fn request() -> TestResult<OrientRequest> {
    Ok(OrientRequest {
        view: AgentView::Brief,
        principal: PrincipalId::parse("principal:cascade")?,
        budget_tokens: None,
    })
}

fn orient(fixture: &Fixture) -> TestResult<DeploymentOrientation> {
    let limits = OrientLimits::default();
    let snapshot = read_deployment(fixture.deployment.root(), &limits)?;
    Ok(orient_deployment(&snapshot, &request()?, &limits)?)
}

fn assert_covered(orientation: &DeploymentOrientation) {
    let coverage = orientation.coverage.as_ref().expect("retained coverage");
    assert_eq!(coverage.zones.len(), 1);
    assert!(coverage.complete());
    assert_eq!(coverage.zones[0].state, ZoneCoverageState::Covered);
    assert!(coverage.zones[0].window.is_some());
    assert!(!coverage.zones[0].witnesses.is_empty());
    assert_eq!(orientation.capsule().completeness, Completeness::Complete);
}

fn assert_health_veto(orientation: &DeploymentOrientation) {
    let coverage = orientation.coverage.as_ref().expect("retained coverage");
    assert_eq!(coverage.zones.len(), 1);
    assert!(!coverage.complete());
    let zone = &coverage.zones[0];
    assert_eq!(zone.state, ZoneCoverageState::NotObservable);
    assert!(zone.window.is_none());
    assert!(zone.witnesses.is_empty());
    assert!(zone.gaps.iter().any(|gap| gap.contains("health")));
    assert_ne!(orientation.capsule().completeness, Completeness::Complete);
}

fn assert_diagnostic_handle(orientation: &DeploymentOrientation, record: &HistoricalHealthRecord) {
    assert!(
        orientation
            .capsule()
            .frame
            .evidence_handles
            .contains(&format!("fss://proof/{}", record.digest()))
    );
}

#[test]
fn retained_frozen_diagnostic_revokes_cold_coverage_and_protects_follow_without_rewriting_history()
-> TestResult {
    let mut fixture = Fixture::new("historical-coverage-cold")?;
    let identity = import(&mut fixture, true)?;
    let plan = plan(identity, 0, FRAMES);
    let original = retain_coverage(&mut fixture, &plan)?;
    let limits = OrientLimits::default();
    let before = read_deployment(fixture.deployment.root(), &limits)?;
    assert_covered(&orient_deployment(&before, &request()?, &limits)?);
    let token = AnchorToken::parse(&snapshot_anchor_token(&before)).ok_or("anchor token")?;

    let diagnostic = retain_diagnostic(&mut fixture, &plan)?;
    assert_eq!(diagnostic.status(), "suspected_degradation");
    let history = DeploymentHistory::read(fixture.deployment.root(), &limits)?;
    let historical = history.snapshot_at(before.position)?;
    assert!(historical.historical_health.is_empty());
    assert_covered(&orient_deployment(&historical, &request()?, &limits)?);
    let current = history.snapshot_at(history.head())?;
    assert_eq!(current.coverage.len(), 1);
    assert_eq!(current.coverage[0].record.to_bytes(), original);
    let current = orient_deployment(&current, &request()?, &limits)?;
    assert_health_veto(&current);
    assert_diagnostic_handle(&current, &diagnostic);

    let follow = follow_deployment(
        &history,
        &token,
        &FollowRequest {
            view: AgentView::Brief,
            principal: PrincipalId::parse("principal:cascade")?,
            max_entries: 64,
            continuation: None,
        },
    )?;
    assert!(
        follow
            .delta
            .classes
            .contains(&MeaningfulDeltaClass::SensorHealth)
    );
    assert!(
        follow
            .delta
            .classes
            .contains(&MeaningfulDeltaClass::CoverageLoss)
    );
    assert!(
        !follow
            .delta
            .classes
            .contains(&MeaningfulDeltaClass::CoverageRecovery)
    );
    assert!(follow.delta.silence_certificate.is_none());
    Ok(())
}

#[test]
fn same_source_findings_outside_a_witness_do_not_revoke_the_disjoint_window() -> TestResult {
    let mut fixture = Fixture::new("historical-coverage-disjoint")?;
    let identity = import(&mut fixture, true)?;
    retain_coverage(&mut fixture, &plan(identity, 16, 16))?;
    let before = orient(&fixture)?;
    assert_covered(&before);
    let diagnostic = retain_diagnostic(&mut fixture, &plan(identity, 0, 16))?;
    assert_eq!(diagnostic.status(), "suspected_degradation");
    assert!(
        diagnostic
            .summary()
            .findings()
            .iter()
            .all(|finding| finding.last_segment < 16)
    );
    let after = orient(&fixture)?;
    assert_covered(&after);
    assert_eq!(before.coverage, after.coverage);
    Ok(())
}

#[test]
fn equal_sensor_and_capture_times_do_not_cross_contaminate_different_imports() -> TestResult {
    let mut fixture = Fixture::new("historical-coverage-other-import")?;
    let frozen = import(&mut fixture, true)?;
    let changing = import(&mut fixture, false)?;
    assert_ne!(frozen, changing);
    retain_coverage(&mut fixture, &plan(changing, 0, FRAMES))?;
    let before = orient(&fixture)?;
    assert_covered(&before);
    let diagnostic = retain_diagnostic(&mut fixture, &plan(frozen, 0, FRAMES))?;
    assert_eq!(diagnostic.status(), "suspected_degradation");
    let after = orient(&fixture)?;
    assert_covered(&after);
    assert_eq!(before.coverage, after.coverage);
    Ok(())
}

#[test]
fn unaffected_overlapping_import_keeps_coverage_when_a_conflicting_witness_is_withdrawn()
-> TestResult {
    let mut fixture = Fixture::new("historical-coverage-independent-witness")?;
    let frozen = import(&mut fixture, true)?;
    let changing = import(&mut fixture, false)?;
    let frozen_record = retain_coverage(&mut fixture, &plan(frozen, 0, FRAMES))?;
    retain_coverage(&mut fixture, &plan(changing, 0, FRAMES))?;
    let limits = OrientLimits::default();
    let before = read_deployment(fixture.deployment.root(), &limits)?;
    let independent = before
        .coverage
        .iter()
        .find(|retained| retained.record.import_identity == changing)
        .ok_or("independent source coverage")?;
    let unaffected: Vec<_> = independent.record.zones[0]
        .witnesses
        .iter()
        .map(|witness| witness.witness.witness_digest())
        .collect();
    assert_eq!(unaffected.len(), 1);
    let before = orient_deployment(&before, &request()?, &limits)?;
    assert_covered(&before);
    let before_zone = &before.coverage.as_ref().expect("coverage").zones[0];
    assert_eq!(before_zone.witnesses.len(), 2);

    let diagnostic = retain_diagnostic(&mut fixture, &plan(frozen, 0, FRAMES))?;
    let after = orient(&fixture)?;
    assert_covered(&after);
    let zone = &after.coverage.as_ref().expect("coverage").zones[0];
    assert_eq!(zone.window, before_zone.window);
    assert_eq!(zone.witnesses, unaffected);
    assert!(!zone.health_conflicts.is_empty());
    assert!(zone.health_conflicts.iter().all(|conflict| {
        conflict.coverage_record == ContentDigest::sha256(&frozen_record)
            && conflict.diagnostic == diagnostic.digest()
            && !zone.witnesses.contains(&conflict.witness)
    }));
    assert!(!after.contradictions.contains(&zone.claim_id()));
    assert_diagnostic_handle(&after, &diagnostic);
    Ok(())
}

#[test]
fn later_no_findings_on_the_same_source_cannot_clear_an_earlier_degradation() -> TestResult {
    let mut fixture = Fixture::new("historical-coverage-no-clear")?;
    let identity = import(&mut fixture, true)?;
    retain_coverage(&mut fixture, &plan(identity, 0, FRAMES))?;
    let degraded = retain_diagnostic(&mut fixture, &plan(identity, 0, FRAMES))?;
    assert_health_veto(&orient(&fixture)?);
    let shorter = retain_diagnostic(&mut fixture, &plan(identity, 0, 6))?;
    assert_eq!(shorter.status(), "no_findings");
    assert_ne!(degraded.digest(), shorter.digest());
    let after = orient(&fixture)?;
    assert_health_veto(&after);
    assert_diagnostic_handle(&after, &degraded);
    assert_diagnostic_handle(&after, &shorter);
    Ok(())
}

#[test]
fn threshold_reached_after_the_coverage_window_still_revokes_its_implicated_prefix() -> TestResult {
    let mut fixture = Fixture::new("historical-coverage-threshold-prefix")?;
    let identity = import(&mut fixture, true)?;
    retain_coverage(&mut fixture, &plan(identity, 0, FRAMES))?;
    let before = read_deployment(fixture.deployment.root(), &OrientLimits::default())?;
    let witnesses = &before.coverage[0].record.zones[0].witnesses;
    assert!(witnesses.iter().any(|witness| {
        witness.first_segment <= 24 && witness.last_segment >= 24 && witness.last_segment < 31
    }));

    // The eighth identical frame triggers at 31, beyond the watch confirmation tail at 29.
    // The diagnostic's requested scan range still implicates the overlapping 24..29 prefix.
    let diagnostic = retain_diagnostic(&mut fixture, &plan(identity, 24, 8))?;
    assert_eq!(diagnostic.status(), "suspected_degradation");
    assert!(
        diagnostic
            .summary()
            .findings()
            .iter()
            .all(|finding| finding.first_segment == 31)
    );
    assert_health_veto(&orient(&fixture)?);
    Ok(())
}

#[test]
fn damaged_retained_health_metadata_refuses_orientation_instead_of_restoring_coverage() -> TestResult
{
    let mut fixture = Fixture::new("historical-coverage-tampered")?;
    let identity = import(&mut fixture, true)?;
    retain_coverage(&mut fixture, &plan(identity, 0, FRAMES))?;
    let diagnostic = retain_diagnostic(&mut fixture, &plan(identity, 0, FRAMES))?;
    assert_health_veto(&orient(&fixture)?);
    let path = fixture
        .deployment
        .publisher()
        .spool()
        .object_path(diagnostic.digest());
    let mut bytes = fs::read(&path)?;
    *bytes.last_mut().ok_or("empty diagnostic")? ^= 1;
    fs::write(path, bytes)?;
    assert!(read_deployment(fixture.deployment.root(), &OrientLimits::default()).is_err());
    Ok(())
}

#[test]
fn coverage_health_binding_uses_original_mask_generation_even_when_policy_bytes_repeat()
-> TestResult {
    for repeat_policy in [false, true] {
        let mut fixture = Fixture::new(if repeat_policy {
            "historical-coverage-mask-aba"
        } else {
            "historical-coverage-same-mask"
        })?;
        let identity = import(&mut fixture, true)?;
        let sensor = SensorId::parse(SENSOR)?;
        let first = PrivacyMaskPolicy::new(
            sensor.clone(),
            [WIDTH as u32, HEIGHT as u32],
            &[[0, 0, 4, 4]],
        )?;
        let second =
            PrivacyMaskPolicy::new(sensor, [WIDTH as u32, HEIGHT as u32], &[[0, 4, 4, 4]])?;
        let approval = preview_mask(&fixture.deployment, &first)?.approval;
        declare_mask(&mut fixture.deployment, &first, approval, &fixture.cx)?;

        // The witness zone stays outside both masks. A mask-caused coverage exclusion would
        // hide the generation-binding bug this test is intended to exercise.
        let mut plan = plan(identity, 0, FRAMES);
        plan.zones[0].x = 8;
        plan.zones[0].width = WIDTH as u32 - 8;
        retain_coverage(&mut fixture, &plan)?;
        assert_covered(&orient(&fixture)?);

        if repeat_policy {
            for policy in [&second, &first] {
                let approval = preview_mask(&fixture.deployment, policy)?.approval;
                declare_mask(&mut fixture.deployment, policy, approval, &fixture.cx)?;
            }
        }
        let diagnostic = retain_diagnostic(&mut fixture, &plan)?;
        assert_eq!(diagnostic.status(), "suspected_degradation");
        assert_eq!(diagnostic.privacy_policy_digest(), Some(first.digest()));
        assert_eq!(
            diagnostic.privacy_generation(),
            Some(if repeat_policy { 3 } else { 1 })
        );
        let snapshot = read_deployment(fixture.deployment.root(), &OrientLimits::default())?;
        assert_eq!(snapshot.coverage[0].privacy_generation, Some(1));
        let orientation = orient_deployment(&snapshot, &request()?, &OrientLimits::default())?;
        if repeat_policy {
            assert_covered(&orientation);
            assert!(
                orientation.coverage.as_ref().expect("coverage").zones[0]
                    .health_conflicts
                    .is_empty()
            );
        } else {
            assert_health_veto(&orientation);
        }
    }
    Ok(())
}
