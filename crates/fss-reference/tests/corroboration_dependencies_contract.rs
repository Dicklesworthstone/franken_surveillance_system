#![forbid(unsafe_code)]
//! Common-cause contraction through actual retained recordings, durable event publication and
//! ledger-wide sensor-integrity checks. Synthetic observations prove the control boundary only.

#[path = "cascade_support/mod.rs"]
mod support;

use std::collections::BTreeSet;

use fss_core::{
    ContentDigest, ContractError, DecisionPath, EventId, EventKind, EventState, EvidenceClass,
    EvidenceEdgeRelation, IdempotencyKey, ObligationId, OperationId, TimestampNs,
};
use fss_reference::ingest::FileFormatHint;
use fss_reference::ingest::recorded_corroboration::{
    CorroborationCamera, CorroborationDependencies, CorroborationDependencyReport,
    CorroborationError, CorroborationGates, CorroborationOptions, CorroborationPlan,
    CorroborationReport, EntryDisposition, FailureDomainDeclaration, GroundHomography,
    GroundVisibilityPlan, GroundZone,
};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{WatchDetectorConfig, WatchLimits, WatchTrackerConfig};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{
    DurableEffectError, PrepareAlertParams, ReferenceError, ReferencePolicyAction,
    ReferencePolicyDecision, ReferenceProviderBehavior,
};
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

fn dependencies(shared: bool) -> TestResult<CorroborationDependencies> {
    Ok(CorroborationDependencies::new(if shared {
        vec![FailureDomainDeclaration {
            domain: "network:lan".into(),
            cameras: vec!["east".into(), "west".into()],
        }]
    } else {
        vec![
            FailureDomainDeclaration {
                domain: "power:east".into(),
                cameras: vec!["east".into()],
            },
            FailureDomainDeclaration {
                domain: "power:west".into(),
                cameras: vec!["west".into()],
            },
        ]
    })?)
}

fn analyze(
    fixture: &Fixture,
    plan: &CorroborationPlan,
    dependencies: &CorroborationDependencies,
) -> TestResult<CorroborationReport> {
    Ok(CorroborationReport::analyze_with_dependencies(
        &fixture.deployment,
        plan,
        &WatchLimits::default(),
        None,
        &GroundVisibilityPlan::default(),
        &[None, None],
        &[None, None],
        CorroborationOptions::default(),
        None,
        dependencies,
        &fixture.cx,
    )?)
}

fn setup(name: &str) -> TestResult<(Fixture, CorroborationPlan)> {
    let mut fixture = Fixture::new(name)?;
    let east = fixture.ingest(
        "sensor:dependency-east",
        &scene(false)?,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    let west = fixture.ingest(
        "sensor:dependency-west",
        &scene(true)?,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    Ok((fixture, plan(east, west)))
}

#[test]
fn declared_shared_causes_retain_witnessed_events_and_full_rebuildable_custody() -> TestResult {
    let (mut fixture, plan) = setup("shared-dependency")?;
    let compatibility = CorroborationReport::analyze(
        &fixture.deployment,
        &plan,
        &WatchLimits::default(),
        &fixture.cx,
    )?;
    let policy = dependencies(true)?;
    let mut report = analyze(&fixture, &plan, &policy)?;
    assert_eq!(report.candidates().len(), 1);
    assert_eq!(report.dependencies().clusters().len(), 1);
    let candidate = &report.candidates()[0];
    assert_eq!(candidate.event().state, EventState::Witnessed);
    assert_eq!(candidate.policy_action(), ReferencePolicyAction::Hold);
    assert_eq!(
        fss_reference::committed_reference_policy_action(candidate.event()),
        ReferencePolicyAction::Hold
    );
    assert!(
        report
            .entries()
            .iter()
            .all(|entry| entry.disposition == EntryDisposition::SharedFailureDomain)
    );
    assert_ne!(
        candidate.proposal_digest(),
        compatibility.candidates()[0].proposal_digest()
    );
    // Per-camera coverage remains the same observation process: contraction does not withdraw
    // or create any witness. A positive interval names the new dependency-bound event identity.
    for (old, new) in compatibility.coverage().iter().zip(report.coverage()) {
        assert_eq!(
            old.witnesses()
                .map(|(_, witness)| witness)
                .collect::<Vec<_>>(),
            new.witnesses()
                .map(|(_, witness)| witness)
                .collect::<Vec<_>>(),
        );
    }
    let proposal = candidate.proposal_digest();
    let event_id = candidate.event().event_id.clone();
    let before = fixture.deployment.current_anchor().clone();
    assert!(matches!(
        report.publish(
            &mut fixture.deployment,
            &BTreeSet::from([compatibility.candidates()[0].proposal_digest()]),
            &fixture.cx
        ),
        Err(CorroborationError::StaleApproval(_))
    ));
    assert_eq!(*fixture.deployment.current_anchor(), before);
    let assessment = report.dependencies().clone();
    assert_eq!(
        report.publish(
            &mut fixture.deployment,
            &BTreeSet::from([proposal]),
            &fixture.cx
        )?,
        1
    );
    let bytes = fixture
        .deployment
        .publisher()
        .spool()
        .read(assessment.digest())?;
    assert_eq!(
        CorroborationDependencyReport::from_bytes(&bytes)?,
        assessment
    );
    assert_eq!(
        fixture
            .deployment
            .publisher()
            .spool()
            .read(policy.digest())?,
        policy.to_bytes()
    );
    let (event, _) = fixture.deployment.current_event_authority(&event_id)?;
    assert_eq!(event.state, EventState::Witnessed);
    let support: BTreeSet<_> = event
        .evidence
        .iter()
        .filter(|edge| edge.counts_as_support())
        .map(|edge| &edge.failure_domain)
        .collect();
    assert_eq!(support.len(), 1);
    assert!(
        event
            .evidence
            .iter()
            .filter(|edge| edge.failure_domain.starts_with("recorded-sensor:"))
            .all(|edge| !edge.supports && edge.relation == EvidenceEdgeRelation::RequiredBy)
    );
    let mut repeated = analyze(&fixture, &plan, &policy)?;
    assert_eq!(
        repeated.publish(
            &mut fixture.deployment,
            &BTreeSet::from([proposal]),
            &fixture.cx
        )?,
        0
    );
    Ok(())
}

#[test]
fn dependency_contraction_cannot_hide_intrinsic_or_declared_tamper_from_dispatch() -> TestResult {
    for intrinsic in [true, false] {
        let (mut fixture, plan) = setup(if intrinsic {
            "dependency-sensor-tamper"
        } else {
            "dependency-power-tamper"
        })?;
        let mut report = analyze(&fixture, &plan, &dependencies(false)?)?;
        let candidate = &report.candidates()[0];
        assert_eq!(candidate.event().state, EventState::Corroborated);
        assert_eq!(
            fss_reference::committed_reference_policy_action(candidate.event()),
            ReferencePolicyAction::PrepareAlert
        );
        let event_id = candidate.event().event_id.clone();
        let proposal = candidate.proposal_digest();
        report.publish(
            &mut fixture.deployment,
            &BTreeSet::from([proposal]),
            &fixture.cx,
        )?;
        let (event, receipt) = fixture.deployment.current_event_authority(&event_id)?;
        let decision = ReferencePolicyDecision {
            event: event.clone(),
            action: ReferencePolicyAction::PrepareAlert,
        };
        let (journal, ledger) = fixture.deployment.effects_and_ledger();
        let alert = journal.prepare_alert(PrepareAlertParams {
            decision: &decision,
            event_receipt: &receipt,
            authority: ledger,
            operation_id: OperationId::parse("operation:dependency-alert")?,
            idempotency_key: IdempotencyKey::parse("idempotency:dependency-alert")?,
            obligation_id: ObligationId::parse("obligation:dependency-alert")?,
            channel: "operator:test".into(),
            now: TimestampNs(3_000_000_000),
        })?;
        let edge = event
            .evidence
            .iter()
            .find(|edge| {
                if intrinsic {
                    edge.failure_domain.starts_with("recorded-sensor:")
                } else {
                    edge.failure_domain == "power:east"
                }
            })
            .ok_or("individual common cause missing from event dependencies")?;
        assert!(!edge.counts_as_support());
        // A separate synthetic sensor-health event enters the same durable ledger after alert
        // preparation. The candidate's own lineage stays unchanged throughout this regression.
        let mut tamper = event.clone();
        tamper.event_id = EventId::parse("event:dependency-health")?;
        tamper.state = EventState::Indeterminate;
        tamper.kind = EventKind::SensorTamper;
        let bytes = b"synthetic dependency sensor-integrity observation";
        let digest = fixture.deployment.publisher_mut().stage_object(bytes)?;
        fixture.deployment.publisher_mut().verify_object(digest)?;
        let mut tamper_edge = edge.clone();
        tamper_edge.digest = digest;
        tamper_edge.class = EvidenceClass::Derived;
        tamper_edge.relation = EvidenceEdgeRelation::SensorTamper;
        tamper.evidence = vec![tamper_edge];
        tamper.decision_path = DecisionPath {
            policy_generation: ContentDigest::sha256(b"synthetic dependency tamper policy"),
            fingerprint: digest,
            abstained: true,
            abstention_reason: Some("synthetic sensor-integrity investigation".into()),
        };
        fixture.deployment.publish_event(
            &ReferencePolicyDecision {
                event: tamper,
                action: ReferencePolicyAction::Hold,
            },
            &fixture.cx,
        )?;
        let result = fixture.deployment.dispatch_alert(
            &alert,
            ReferenceProviderBehavior::Deliver,
            TimestampNs(4_000_000_000),
            TimestampNs(4_000_000_001),
            &fixture.cx,
        );
        assert!(
            matches!(result, Err(ReferenceError::DurableEffect(ref error)) if matches!(error.as_ref(), DurableEffectError::Contract(ContractError::SensorIntegrityRisk))),
            "{result:?}"
        );
        assert_eq!(fixture.deployment.alert_provider().message_count(), 0);
    }
    Ok(())
}
