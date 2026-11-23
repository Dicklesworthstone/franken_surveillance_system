#![forbid(unsafe_code)]
//! FSS-078/FSS-083: sensor-health admission for sampled dwell over retained, decoded MJPEG.
//! These synthetic scenes prove continuity and custody contracts, not detection quality,
//! physical sensor health, continuous occupancy, or alert eligibility.

#[path = "cascade_support/mod.rs"]
mod support;

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, ContentDigest, EventKind, EventState, EvidenceEdgeRelation, LedgerAnchor,
    ObjectId, OperationId, SensorId,
};
use fss_object::ObjectManifest;
use fss_reference::ingest::FileFormatHint;
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_coverage::{CoverageRecord, UncoveredReason};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_dwell::DwellReport;
use fss_reference::ingest::recorded_health::{RecordedHealthPolicy, RecordedHealthSummary};
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchError, WatchLimits, WatchOptions, WatchPlan, WatchStatus,
    WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::sensor_health::{OpticalFinding, OpticalThresholds};
use fss_reference::ingest::zone_dwell::DwellPolicy;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::retained_source::{ImmutableRetainedReadLimits, ImmutableRetainedSource};
use fss_reference::{ReferenceDeployment, ReplayCx};
use support::{Fixture, SITE, TestResult};

const FRAMES: usize = 32;
const WIDTH: usize = 96;
const HEIGHT: usize = 48;
const SENSOR: &str = "sensor:dwell-health";
const PERIOD_NS: u64 = 100_000_000;

#[derive(Clone, Copy)]
enum Scene {
    Clear,
    Blur,
    Glare,
    Frozen,
}

impl Scene {
    fn gap(self) -> Option<std::ops::Range<usize>> {
        match self {
            Self::Clear => None,
            Self::Blur | Self::Glare => Some(12..15),
            Self::Frozen => Some(12..22),
        }
    }
}

/// Stable texture makes sharpness observable. The small alternating offset prevents an
/// intentionally stationary foreground target from being mistaken for a frozen recording.
fn scene(kind: Scene) -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..FRAMES {
        let gap = kind.gap();
        let degraded = gap.as_ref().is_some_and(|range| range.contains(&index));
        let offset = if degraded && matches!(kind, Scene::Frozen) {
            0
        } else {
            (index % 2) as u8 * 4
        };
        let mut pixels = (0..WIDTH * HEIGHT)
            .map(|pixel| {
                let x = pixel % WIDTH;
                let y = pixel / WIDTH;
                if (x / 4 + y / 4) % 2 == 0 {
                    40 + offset
                } else {
                    88 + offset
                }
            })
            .collect::<Vec<_>>();
        // A recovered screen gets three clean background frames before a fresh target enters.
        let square = index >= 3
            && gap.as_ref().is_none_or(|range| {
                index < range.start
                    || index >= range.end + 3
                    || (degraded && matches!(kind, Scene::Frozen))
            });
        if square {
            for y in 8..24 {
                for x in 8..24 {
                    pixels[y * WIDTH + x] = 220;
                }
            }
        }
        if degraded {
            match kind {
                Scene::Blur => pixels.fill(100 + offset),
                Scene::Glare => pixels[..WIDTH * 12].fill(255),
                Scene::Clear | Scene::Frozen => {}
            }
        }
        stream.extend(encode_jpeg(WIDTH as u32, HEIGHT as u32, &pixels, &config)?);
    }
    Ok(stream)
}

fn fixture(label: &str, kind: Scene) -> TestResult<(Fixture, WatchPlan)> {
    let mut fixture = Fixture::new(label)?;
    let import_identity = fixture.ingest(
        SENSOR,
        &scene(kind)?,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    let plan = WatchPlan {
        import_identity,
        interpretation: ComponentInterpretation::Grayscale,
        first_segment: 0,
        segment_count: FRAMES,
        zones: vec![WatchZone {
            zone_id: "yard".to_owned(),
            x: 0,
            y: 0,
            width: WIDTH as u32,
            height: HEIGHT as u32,
        }],
        detector: WatchDetectorConfig {
            learning_rate_den: 1024,
            ..WatchDetectorConfig::default()
        },
        tracker: WatchTrackerConfig::default(),
    };
    Ok((fixture, plan))
}

fn rule() -> DwellPolicy {
    DwellPolicy {
        minimum_duration_ns: 2 * PERIOD_NS,
        // Fixture capture hints have +/- 1 ms uncertainty at 10 fps.
        maximum_sample_gap_ns: PERIOD_NS + 2_000_000,
        minimum_observations: 3,
    }
}

fn optical() -> RecordedHealthPolicy {
    RecordedHealthPolicy::ConservativeOpticalV1(OpticalThresholds::default())
}

fn analyse(
    fixture: &Fixture,
    plan: &WatchPlan,
    health: Option<RecordedHealthPolicy>,
) -> TestResult<DwellReport> {
    Ok(DwellReport::analyze_with_health(
        &fixture.deployment,
        plan,
        rule(),
        &WatchLimits::default(),
        None,
        WatchOptions::default(),
        health,
        &fixture.cx,
    )?)
}

fn snapshot(fixture: &Fixture) -> (LedgerAnchor, ContentDigest, usize) {
    (
        fixture.deployment.current_anchor().clone(),
        fixture.deployment.effects().last_root(),
        fixture.deployment.publisher().spool().digests().count(),
    )
}

fn context(root: &Path, principal: &str) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:cascade".to_owned(),
        operation_id: OperationId::parse("operation:cascade")?,
        principal: principal.to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(256 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

#[test]
fn healthy_screen_admits_dwell_and_none_preserves_legacy_bytes() -> TestResult {
    let (fixture, plan) = fixture("dwell-health-clear", Scene::Clear)?;
    let before = snapshot(&fixture);
    let legacy = DwellReport::analyze(
        &fixture.deployment,
        &plan,
        rule(),
        &WatchLimits::default(),
        None,
        WatchOptions::default(),
        &fixture.cx,
    )?;
    let explicit_none = analyse(&fixture, &plan, None)?;
    assert!(explicit_none.sensor_health().is_none());
    assert_eq!(legacy.to_json(0, None)?, explicit_none.to_json(0, None)?);
    assert_eq!(legacy.analysis_digest(), explicit_none.analysis_digest());
    assert_eq!(
        legacy.coverage().to_bytes(),
        explicit_none.coverage().to_bytes()
    );
    assert_eq!(legacy.candidates().len(), 1);
    assert!(!legacy.to_json(0, None)?.contains("\"sensor_health\""));

    for policy in [RecordedHealthPolicy::ConservativeV1, optical()] {
        let report = analyse(&fixture, &plan, Some(policy))?;
        let summary = report.sensor_health().ok_or("missing health receipt")?;
        assert!(summary.affected_segments().is_empty());
        assert_eq!(summary.observations().len(), FRAMES);
        assert_eq!(summary.policy(), policy);
        assert_eq!(summary.samples_used(), (FRAMES * WIDTH * HEIGHT) as u64);
        assert_eq!(
            RecordedHealthSummary::from_bytes(&summary.to_bytes())?,
            *summary
        );
        assert_eq!(report.candidates().len(), 1);
        let candidate = &report.candidates()[0];
        assert_eq!(candidate.event().kind, EventKind::Unclassified);
        assert_eq!(candidate.event().state, EventState::Indeterminate);
        assert!(candidate.event().decision_path.abstained);
        assert!(
            candidate
                .event()
                .evidence
                .iter()
                .all(|evidence| !evidence.supports)
        );
        assert!(candidate.event().evidence.iter().any(|evidence| {
            evidence.digest == summary.digest()
                && evidence.relation == EvidenceEdgeRelation::RequiredBy
                && !evidence.supports
        }));
        assert_ne!(legacy.analysis_digest(), report.analysis_digest());
        assert_ne!(
            legacy.candidates()[0].proposal_digest(),
            candidate.proposal_digest(),
        );
        let json = report.to_json(0, None)?;
        assert!(json.contains("\"sensor_health\":{"));
        assert!(json.contains("\"health_certified\":false"));
        assert!(json.contains("\"continuous_occupancy_certified\":false"));
        assert!(json.contains("\"alert_authorized\":false"));
        assert_eq!(
            analyse(&fixture, &plan, Some(policy))?.to_json(0, None)?,
            json
        );
        assert_eq!(
            CoverageRecord::from_bytes(&report.coverage().to_bytes(), report.coverage().digest())?,
            *report.coverage(),
        );
    }
    assert_eq!(snapshot(&fixture), before, "analysis must remain read-only");
    Ok(())
}

#[test]
fn exact_optical_thresholds_bind_dwell_identity_and_reject_previous_approvals() -> TestResult {
    let (mut fixture, plan) = fixture("dwell-health-policy", Scene::Clear)?;
    let original = analyse(&fixture, &plan, Some(optical()))?;
    let previous = original.candidates()[0].proposal_digest();
    let defaults = OpticalThresholds::default();
    let mut identities = BTreeSet::from([original.analysis_digest()]);
    let mut approvals = BTreeSet::from([previous]);
    for policy in [
        RecordedHealthPolicy::ConservativeV1,
        RecordedHealthPolicy::ConservativeOpticalV1(OpticalThresholds {
            min_laplacian_variance_x1000: defaults.min_laplacian_variance_x1000 + 1,
            ..defaults
        }),
        RecordedHealthPolicy::ConservativeOpticalV1(OpticalThresholds {
            glare_luma_min: defaults.glare_luma_min - 1,
            ..defaults
        }),
        RecordedHealthPolicy::ConservativeOpticalV1(OpticalThresholds {
            max_glare_ppm: defaults.max_glare_ppm - 1,
            ..defaults
        }),
    ] {
        let mut changed = analyse(&fixture, &plan, Some(policy))?;
        assert_eq!(changed.candidates().len(), 1);
        assert!(identities.insert(changed.analysis_digest()));
        assert!(approvals.insert(changed.candidates()[0].proposal_digest()));
        let before = snapshot(&fixture);
        assert!(matches!(
            changed.publish(
                &mut fixture.deployment,
                &BTreeSet::from([previous]),
                &fixture.cx
            ),
            Err(WatchError::StaleApproval(_)),
        ));
        assert_eq!(snapshot(&fixture), before);
    }
    Ok(())
}

#[test]
fn blur_and_glare_break_dwell_and_recovery_requires_fresh_confirmed_samples() -> TestResult {
    for (name, kind, finding) in [
        ("dwell-health-blur", Scene::Blur, OpticalFinding::SevereBlur),
        (
            "dwell-health-glare",
            Scene::Glare,
            OpticalFinding::LocalizedHighlightGlare,
        ),
    ] {
        let (fixture, plan) = fixture(name, kind)?;
        let report = analyse(&fixture, &plan, Some(optical()))?;
        let summary = report.sensor_health().ok_or("missing optical receipt")?;
        assert_eq!(
            summary.affected_segments(),
            &(12..15).collect::<BTreeSet<_>>()
        );
        for segment in 12..15 {
            assert!(
                summary.optical_observations()[segment]
                    .findings
                    .contains(&finding)
            );
        }
        assert!(
            report
                .candidates()
                .iter()
                .any(|candidate| candidate.segments()[2] < 12)
        );
        assert!(
            report
                .candidates()
                .iter()
                .any(|candidate| candidate.segments()[0] >= 20)
        );
        for candidate in report.candidates() {
            let [first, _, last] = candidate.segments();
            assert!(
                last < 12 || first >= 20,
                "degraded samples or recovery warmup counted"
            );
            assert!((first..=last).all(|segment| !summary.affects(segment)));
        }
        assert!(report.coverage().zones[0].uncovered.iter().any(|interval| {
            interval.reason == UncoveredReason::SensorHealthDegraded
                && interval.first_segment == 12
                && interval.last_segment == 14
        }));
        // Neither side is long enough by itself. Their sum must never bridge the blind run.
        let mut long_rule = rule();
        long_rule.minimum_duration_ns = 1_600_000_000;
        let long = DwellReport::analyze_with_health(
            &fixture.deployment,
            &plan,
            long_rule,
            &WatchLimits::default(),
            None,
            WatchOptions::default(),
            Some(optical()),
            &fixture.cx,
        )?;
        assert!(long.candidates().is_empty());
    }
    Ok(())
}

#[test]
fn late_frozen_run_withdraws_its_track_prefix_and_allows_only_new_recovered_dwell() -> TestResult {
    let (fixture, plan) = fixture("dwell-health-frozen", Scene::Frozen)?;
    let legacy = analyse(&fixture, &plan, None)?;
    assert!(
        legacy
            .candidates()
            .iter()
            .any(|candidate| candidate.segments()[0] < 12)
    );
    for policy in [RecordedHealthPolicy::ConservativeV1, optical()] {
        let report = analyse(&fixture, &plan, Some(policy))?;
        let summary = report.sensor_health().ok_or("missing frozen-run receipt")?;
        assert_eq!(
            summary.affected_segments(),
            &(12..22).collect::<BTreeSet<_>>()
        );
        assert!(summary.withdrawn_track_segments().contains(&5));
        assert!(
            !summary.affects(5),
            "the prefix was clear but depended on the frozen track"
        );
        assert_eq!(report.candidates().len(), 1);
        assert!(report.candidates()[0].segments()[0] >= 27);
        assert!(report.coverage().zones[0].uncovered.iter().any(|interval| {
            interval.reason == UncoveredReason::SensorHealthDependentTrack
                && interval.first_segment <= 5
                && interval.last_segment >= 5
        }));
    }
    Ok(())
}

#[test]
fn publication_retains_exact_health_objects_and_immutable_retry_keeps_same_identity() -> TestResult
{
    let (mut fixture, plan) = fixture("dwell-health-custody", Scene::Glare)?;
    let mut report = analyse(&fixture, &plan, Some(optical()))?;
    let summary = report
        .sensor_health()
        .ok_or("missing health receipt")?
        .clone();
    let candidate = &report.candidates()[0];
    let approval = candidate.proposal_digest();
    let provenance = candidate.provenance_root();
    let event = candidate.event().clone();
    assert_eq!(
        report.publish(
            &mut fixture.deployment,
            &BTreeSet::from([approval]),
            &fixture.cx
        )?,
        1,
    );
    let spool = fixture.deployment.publisher().spool();
    let manifest = ObjectManifest::from_canonical_bytes(&spool.read(provenance)?)?;
    assert!(manifest.children().contains(&summary.digest()));
    assert!(manifest.children().contains(&summary.policy_digest()));
    for observation in summary.observations() {
        assert!(manifest.children().contains(&observation.capsule_digest));
    }
    assert_eq!(spool.read(summary.digest())?, summary.to_bytes());
    assert_eq!(spool.read(summary.policy_digest())?, summary.policy_bytes());
    assert_eq!(
        fixture
            .deployment
            .current_event_authority(&event.event_id)?
            .0,
        event
    );
    assert!(fixture.deployment.effects().operations().next().is_none());

    let before = snapshot(&fixture);
    let source = ImmutableRetainedSource::open(
        fixture.deployment.root(),
        ImmutableRetainedReadLimits {
            snapshot: fss_reference::agent_orient::OrientLimits::default(),
            max_read_bytes: 64 * 1024 * 1024,
            max_read_objects: 8192,
        },
        &fixture.cx,
    )?;
    let preview = DwellReport::analyze_with_health(
        &source,
        &plan,
        rule(),
        &WatchLimits::default(),
        None,
        WatchOptions::default(),
        Some(optical()),
        &fixture.cx,
    )?;
    assert_eq!(
        preview.candidates()[0].status(),
        WatchStatus::AlreadyPublished
    );
    assert_eq!(preview.candidates()[0].proposal_digest(), approval);
    assert_eq!(preview.sensor_health(), Some(&summary));
    preview.revalidate_derived_source(&source, &fixture.cx)?;
    source.revalidate()?;
    let mut retry = analyse(&fixture, &plan, Some(optical()))?;
    assert_eq!(
        retry.publish(
            &mut fixture.deployment,
            &BTreeSet::from([approval]),
            &fixture.cx
        )?,
        0,
    );
    assert_eq!(snapshot(&fixture), before);
    Ok(())
}

#[test]
fn screened_publication_rechecks_root_principal_and_current_privacy_before_writing() -> TestResult {
    let (mut fixture, plan) = fixture("dwell-health-authority", Scene::Clear)?;
    let mut report = analyse(&fixture, &plan, Some(optical()))?;
    let approvals = BTreeSet::from([report.candidates()[0].proposal_digest()]);
    let other_root = Fixture::new("dwell-health-other-root")?;
    let other_principal = context(fixture.deployment.root(), "principal:other")?;
    let before = snapshot(&fixture);
    for cx in [&other_root.cx, &other_principal] {
        assert!(
            report
                .publish(&mut fixture.deployment, &approvals, cx)
                .is_err()
        );
        assert_eq!(snapshot(&fixture), before);
    }
    let mask = PrivacyMaskPolicy::new(
        SensorId::parse(SENSOR)?,
        [WIDTH as u32, HEIGHT as u32],
        &[[80, 40, 8, 8]],
    )?;
    let approval = preview_mask(&fixture.deployment, &mask)?.approval;
    declare_mask(&mut fixture.deployment, &mask, approval, &fixture.cx)?;
    let before = snapshot(&fixture);
    assert!(
        report
            .publish(&mut fixture.deployment, &approvals, &fixture.cx)
            .is_err()
    );
    assert_eq!(snapshot(&fixture), before);
    assert!(
        analyse(&fixture, &plan, Some(optical()))?
            .candidates()
            .is_empty()
    );
    Ok(())
}

#[test]
fn original_capsule_damage_refuses_screened_publication_without_repair_or_new_writes() -> TestResult
{
    let (mut fixture, plan) = fixture("dwell-health-source-damage", Scene::Clear)?;
    let mut report = analyse(&fixture, &plan, Some(optical()))?;
    let approval = report.candidates()[0].proposal_digest();
    let capsule = report
        .sensor_health()
        .ok_or("missing health receipt")?
        .observations()[0]
        .capsule_digest;
    let path = fixture.deployment.publisher().spool().object_path(capsule);
    let mut permissions = fs::metadata(&path)?.permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    fs::set_permissions(&path, permissions)?;
    fs::write(&path, b"damaged original capsule")?;
    let before = snapshot(&fixture);
    assert!(
        report
            .revalidate_derived_source(&fixture.deployment, &fixture.cx)
            .is_err()
    );
    assert!(
        report
            .publish(
                &mut fixture.deployment,
                &BTreeSet::from([approval]),
                &fixture.cx
            )
            .is_err()
    );
    assert!(analyse(&fixture, &plan, Some(optical())).is_err());
    assert_eq!(fs::read(path)?, b"damaged original capsule");
    assert_eq!(snapshot(&fixture), before);
    Ok(())
}

#[test]
fn optical_cancellation_returns_no_report_and_publication_resumes_only_exact_approval() -> TestResult
{
    let (cancelled, plan) = fixture("dwell-health-optical-cancel", Scene::Clear)?;
    let before = snapshot(&cancelled);
    cancelled
        .cx
        .set_cancel_at_checkpoint("sensor_health:optical_laplacian_row");
    assert!(analyse(&cancelled, &plan, Some(optical())).is_err());
    assert!(cancelled.cx.is_drain_completed());
    assert_eq!(snapshot(&cancelled), before);

    let (mut fixture, plan) = fixture("dwell-health-publish-cancel", Scene::Clear)?;
    let mut report = analyse(&fixture, &plan, Some(optical()))?;
    let approval = report.candidates()[0].proposal_digest();
    let event = report.candidates()[0].event().clone();
    let summary = report
        .sensor_health()
        .ok_or("missing health receipt")?
        .digest();
    fixture.cx.set_cancel_at_checkpoint("recorded_dwell:commit");
    assert!(
        report
            .publish(
                &mut fixture.deployment,
                &BTreeSet::from([approval]),
                &fixture.cx
            )
            .is_err()
    );
    assert!(fixture.cx.is_drain_completed());
    let event_object = ObjectId::parse(format!("object:event:{}", event.event_id.as_str()))?;
    assert!(
        !fixture
            .deployment
            .ledger()
            .current()
            .objects
            .contains_key(&event_object)
    );
    assert!(fixture.deployment.effects().operations().next().is_none());
    let root = fixture.deployment.root().to_path_buf();
    drop(fixture.deployment);
    let cx = context(&root, "principal:cascade")?;
    let mut reopened = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    let mut retry = DwellReport::analyze_with_health(
        &reopened,
        &plan,
        rule(),
        &WatchLimits::default(),
        None,
        WatchOptions::default(),
        Some(optical()),
        &cx,
    )?;
    assert_eq!(retry.candidates()[0].proposal_digest(), approval);
    assert_eq!(
        retry.sensor_health().map(RecordedHealthSummary::digest),
        Some(summary)
    );
    assert_eq!(
        retry.publish(&mut reopened, &BTreeSet::from([approval]), &cx)?,
        1
    );
    assert_eq!(reopened.current_event_authority(&event.event_id)?.0, event);
    let anchor = reopened.current_anchor().clone();
    assert_eq!(
        retry.publish(&mut reopened, &BTreeSet::from([approval]), &cx)?,
        0
    );
    assert_eq!(reopened.current_anchor(), &anchor);
    assert!(reopened.effects().operations().next().is_none());
    Ok(())
}
