#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Native retained QSR source plus unresolved effects shared by API and actual-process tests.

use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::{
    ContentDigest, EffectIntent, EffectState, IdempotencyKey, ObligationId, ObligationState,
    OperationId, TimestampNs,
};
use fss_reference::ingest::historical_health::exposure::HealthExposureLimits;
use fss_reference::ingest::long_dwell::{LongDwellLimits, LongDwellReport};
use fss_reference::ingest::package_zones::{PackageZone, PackageZoneConfig, PackageZoneReport};
use fss_reference::ingest::qsr_observations::{
    QsrConfig, QsrObservationReport, QsrZoneBinding, QsrZoneRole,
};
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::zone_dwell::DwellPolicy;
use fss_reference::{DeploymentLimits, ReferenceDeployment};

#[path = "../package_evaluation_support/mod.rs"]
mod package;

pub use package::{Directory, PRINCIPAL, SITE, Test, context};

pub fn config() -> QsrConfig {
    QsrConfig {
        zone_roles: vec![QsrZoneBinding {
            zone: "image".into(),
            role: QsrZoneRole::Queue,
        }],
        lane_stages: Vec::new(),
    }
}

pub struct Fixture {
    pub source: package::Fixture,
    pub report: ContentDigest,
    pub expected_json: String,
    pub expected_bytes: Vec<u8>,
    pub expected_lane_json: String,
}

impl Fixture {
    pub fn new(label: &str) -> Test<Self> {
        Self::new_with_limits(label, DeploymentLimits::standard())
    }

    pub fn new_with_limits(label: &str, limits: DeploymentLimits) -> Test<Self> {
        Self::build(label, limits, false)
    }

    /// Actual retained numeric detector evidence crossing two declared, distinct lane regions.
    pub fn new_lane(label: &str) -> Test<Self> {
        Self::build(label, DeploymentLimits::standard(), true)
    }

    fn build(label: &str, limits: DeploymentLimits, lane: bool) -> Test<Self> {
        let source =
            package::Fixture::new_with_limits(label, [128, 160, 192], Some(1_000_000), limits)?;
        let cx = context(&source.root)?;
        let mut deployment =
            ReferenceDeployment::open_with_limits(&source.root, SITE, limits, &cx)?;
        let diagnostic = LongDwellReport::analyze_screened(
            &deployment,
            &WatchPlan {
                import_identity: source.import,
                interpretation: ComponentInterpretation::YCbCr,
                first_segment: 0,
                segment_count: 3,
                zones: vec![WatchZone {
                    zone_id: "screen".into(),
                    x: 0,
                    y: 0,
                    width: 32,
                    height: 16,
                }],
                detector: WatchDetectorConfig::default(),
                tracker: WatchTrackerConfig::default(),
            },
            DwellPolicy {
                minimum_duration_ns: 180_000_000,
                maximum_sample_gap_ns: 110_000_000,
                minimum_observations: 3,
            },
            WatchOptions {
                tolerate_decode_refusals: false,
            },
            &LongDwellLimits::default(),
            &cx,
        )?;
        let summary = diagnostic.health_summary().ok_or("native health summary")?;
        assert!(summary.complete());
        assert_eq!(summary.frames_screened(), 3);
        assert!(summary.findings().is_empty());
        let proposal = diagnostic
            .health_diagnostic()
            .ok_or("native health diagnostic")?;
        proposal.retain(&mut deployment, proposal.approval_digest(), &cx)?;
        let mut source_zones = vec![PackageZone {
            id: "image".into(),
            x: 0,
            y: 0,
            width: 32,
            height: 16,
            margin: 0,
        }];
        if lane {
            source_zones.extend([
                PackageZone {
                    id: "early".into(),
                    x: 13,
                    y: 0,
                    width: 6,
                    height: 16,
                    margin: 0,
                },
                PackageZone {
                    id: "late".into(),
                    x: 15,
                    y: 0,
                    width: 7,
                    height: 16,
                    margin: 0,
                },
            ]);
            source_zones.sort_by(|left, right| left.id.cmp(&right.id));
        }
        let mut zones = PackageZoneReport::analyze_screened(
            &deployment,
            source.report,
            "numeric-a",
            package::tracking(),
            PackageZoneConfig {
                maximum_sample_gap_ns: 110_000_000,
                dwell: None,
                zones: source_zones,
            },
            HealthExposureLimits::default(),
            &cx,
        )?;
        zones.retain(&mut deployment, zones.approval_digest(), &cx)?;
        let mut configuration = config();
        if lane {
            configuration.lane_stages = vec!["early".into(), "late".into()];
        }
        let expected = QsrObservationReport::open(&deployment, zones.digest(), configuration, &cx)?;
        let image = expected
            .config()
            .zone_roles
            .iter()
            .position(|zone| zone.zone == "image")
            .ok_or("image zone")?;
        assert_eq!(expected.observations().zones[image].supported_frames, 3);
        assert_eq!(expected.observations().zones[image].unknown_frames, 0);
        assert_eq!(
            expected.observations().zones[image].frames_with_observed_tracks,
            2
        );
        let authority_before_effects = deployment.current_anchor().clone();

        // These are durable fixture operations, with no provider dispatch. A normal deployment
        // reopen would append a Committed -> Indeterminate transition and change its obligation.
        // A QSR read must preserve all three states byte-for-byte on success and refusal.
        for (label, state) in [
            ("prepared", EffectState::Prepared),
            ("committed", EffectState::Committed),
            ("indeterminate", EffectState::Indeterminate),
        ] {
            let operation = OperationId::parse(format!("operation:qsr-read:{label}"))?;
            let obligation = ObligationId::parse(format!("obligation:qsr-read:{label}"))?;
            let intent = EffectIntent::new(
                operation.clone(),
                IdempotencyKey::parse(format!("idempotency:qsr-read:{label}"))?,
                "fixture:qsr-notification",
                ContentDigest::sha256(label.as_bytes()),
                ContentDigest::sha256(b"qsr-read-fixture-authority"),
            )?;
            deployment.effects_mut().prepare(
                intent,
                obligation.clone(),
                "fixture notification observed",
                TimestampNs(1),
            )?;
            if state != EffectState::Prepared {
                deployment.effects_mut().transition(
                    &operation,
                    EffectState::Committed,
                    TimestampNs(2),
                    None,
                    None,
                )?;
            }
            if state == EffectState::Indeterminate {
                deployment.effects_mut().mark_indeterminate(
                    &operation,
                    TimestampNs(3),
                    "fixture provider result unavailable",
                )?;
            }
            assert_eq!(
                deployment
                    .effects()
                    .operation(&operation)
                    .map(|value| value.state),
                Some(state)
            );
            assert_eq!(
                deployment
                    .effects()
                    .obligation(&obligation)
                    .map(|value| value.state),
                Some(if state == EffectState::Indeterminate {
                    ObligationState::Indeterminate
                } else {
                    ObligationState::Pending
                })
            );
        }
        assert_eq!(deployment.current_anchor(), &authority_before_effects);
        let result = Self {
            source,
            report: zones.digest(),
            expected_json: expected.to_json()?,
            expected_bytes: expected.encoded().to_vec(),
            expected_lane_json: expected.lane_traversals().to_json().to_owned(),
        };
        drop(deployment);
        cx.drain_and_finalize();
        Ok(result)
    }
}
