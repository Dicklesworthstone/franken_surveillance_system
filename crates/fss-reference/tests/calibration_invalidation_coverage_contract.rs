#![forbid(unsafe_code)]
//! Owner withdrawals must reach cold coverage, graph, timeline and follow projections.
//! Canonical coverage fixtures bind real retained source capsules; this does not qualify
//! physical geometry, camera movement detection, or live source continuity.

#[path = "cascade_support/mod.rs"]
mod support;

use std::collections::BTreeMap;
use std::fs;

use fss_core::{AgentView, ContentDigest, MeaningfulDeltaClass, PrincipalId, SensorId};
use fss_geometry::CameraGeneration;
use fss_graph_algorithms::GraphBudget;
use fss_graph_algorithms::coverage_timeline::{
    MAX_TIMELINE_OPERATIONS, MAX_TIMELINE_OUTPUT_ENTRIES,
};
use fss_reference::agent_follow::{
    AnchorToken, FollowRequest, follow_deployment, snapshot_anchor_token,
};
use fss_reference::agent_orient::{
    DeploymentHistory, DeploymentSnapshot, OrientLimits, OrientRequest, ZoneCoverageState,
    orient_deployment, read_deployment,
};
use fss_reference::coverage_graph::{
    coverage_observations, coverage_observations_during, coverage_single_points_during,
};
use fss_reference::coverage_timeline::coverage_timeline;
use fss_reference::ingest::calibration_adoption::{
    CalibrationSubject, RetainedAdoption, adopt, preview_adoption, retained_adoptions,
};
use fss_reference::ingest::calibration_invalidation::{
    Invalidation, InvalidationReason, InvalidationRequest, invalidate, preview_invalidation,
};
use fss_reference::ingest::ground_visibility::{
    CameraModel, Occlusion, OcclusionUnknownReason, ZoneVisibility,
};
use fss_reference::ingest::recorded_coverage::{
    CoverageExtras, CoverageFrame, CoverageInput, CoverageRecord, CoverageSource,
    CoverageZoneInput, GenerationCurrency, PoseProvenance, approval_digest, build_coverage_with,
    retain_coverage,
};
use fss_reference::ingest::recorded_decode::retained_source_capsule;
use fss_reference::ingest::{FileFormatHint, RetainedFileImport, RetainedReadLimits};
use support::{Fixture, TestResult};

const JPEG: &[u8] = include_bytes!("../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
const EAST: &str = "sensor:withdraw-east";
const WEST: &str = "sensor:withdraw-west";

fn subject(label: &str, extrinsics: u64) -> CalibrationSubject {
    CalibrationSubject {
        calibration_digest: ContentDigest::sha256(label.as_bytes()),
        twin_package: ContentDigest::sha256(b"withdraw-coverage-twin"),
        cameras: vec![
            (
                "east".to_owned(),
                CameraGeneration {
                    camera: 21,
                    intrinsics: 1,
                    extrinsics,
                },
            ),
            (
                "west".to_owned(),
                CameraGeneration {
                    camera: 22,
                    intrinsics: 1,
                    extrinsics: 1,
                },
            ),
        ],
    }
}

fn bindings() -> TestResult<Vec<(String, SensorId)>> {
    Ok(vec![
        ("east".to_owned(), SensorId::parse(EAST)?),
        ("west".to_owned(), SensorId::parse(WEST)?),
    ])
}

fn record(
    fixture: &Fixture,
    import: ContentDigest,
    adoption: &RetainedAdoption,
    owner_asserted: bool,
) -> TestResult<CoverageRecord> {
    let source = RetainedFileImport::open(
        &fixture.deployment,
        import,
        RetainedReadLimits::default(),
        &fixture.cx,
    )?;
    let mut frames = Vec::new();
    let mut gaps = Vec::new();
    for segment in 0..source.manifest().segment_spans.len() {
        let capsule = retained_source_capsule(&fixture.deployment, &source, segment)?;
        frames.push(CoverageFrame {
            segment,
            capture: capsule.capture,
        });
        gaps.push(capsule.gap_before);
    }
    let receipt = &adoption.receipt;
    let generation = ContentDigest::sha256(
        format!(
            "coverage:{}:{}:{}",
            receipt.calibration_digest,
            receipt.intrinsics_generation,
            receipt.extrinsics_generation,
        )
        .as_bytes(),
    );
    Ok(build_coverage_with(
        &CoverageInput {
            source: CoverageSource::Corroborate,
            import_identity: import,
            import_root: source.import_root(),
            sensor_id: receipt.sensor_id.as_str(),
            analysis_digest: generation,
            basis: fixture.deployment.current_anchor().clone(),
            capture_time_label: &source.manifest().capture_time_label,
            segment_gaps: &gaps,
            first_segment: 0,
            last_segment: frames.len() - 1,
            frames: &frames,
            confirmation_hits: 1,
            zones: vec![CoverageZoneInput {
                zone_id: "door".to_owned(),
                geometry: "0,0,1,1".to_owned(),
                inside_frame: true,
                pipeline_generation: generation,
                entries: Vec::new(),
            }],
        },
        &CoverageExtras {
            visibility: vec![Some(ZoneVisibility {
                camera_model: CameraModel::CalibratedPose,
                grid: 2,
                threshold_ppm: 1_000_000,
                samples: 4,
                visible: 4,
                outside_frustum: 0,
                occluded: 0,
                privacy_masked: 0,
                occlusion: Occlusion::Unknown(OcclusionUnknownReason::NoSceneMesh),
            })],
            pose_provenance: Some(PoseProvenance::SiteCalibration {
                calibration_digest: receipt.calibration_digest,
                camera_handle: receipt.camera_handle,
                intrinsics_generation: receipt.intrinsics_generation,
                extrinsics_generation: receipt.extrinsics_generation,
                currency: if owner_asserted {
                    GenerationCurrency::OwnerAsserted
                } else {
                    GenerationCurrency::AdoptedCurrent {
                        receipt: adoption.digest,
                    }
                },
            }),
            ..CoverageExtras::default()
        },
    )?)
}

fn setup(name: &str, owner_asserted: bool) -> TestResult<(Fixture, [ContentDigest; 2])> {
    let mut fixture = Fixture::new(name)?;
    let mut imports = Vec::new();
    for sensor in [EAST, WEST] {
        imports.push(fixture.ingest(
            sensor,
            &JPEG.repeat(20),
            FileFormatHint::JpegStream,
            Some(1_000_000_000),
        )?);
    }
    let calibration = subject("withdraw-coverage-v1", 1);
    let binding = bindings()?;
    let preview = preview_adoption(&fixture.deployment, &calibration, &binding)?;
    adopt(
        &mut fixture.deployment,
        &calibration,
        &binding,
        preview.approval,
        &fixture.cx,
    )?;
    let history = retained_adoptions(&fixture.deployment)?;
    let records = [
        record(&fixture, imports[0], &history[&21][0], owner_asserted)?,
        record(&fixture, imports[1], &history[&22][0], false)?,
    ];
    let refs: Vec<_> = records.iter().collect();
    retain_coverage(
        &mut fixture.deployment,
        &refs,
        approval_digest(&refs),
        &fixture.cx,
    )?;
    Ok((fixture, [imports[0], imports[1]]))
}

fn withdraw(fixture: &mut Fixture) -> TestResult<Invalidation> {
    let history = retained_adoptions(&fixture.deployment)?;
    let request = InvalidationRequest {
        camera_handle: 21,
        adoption_digest: history[&21].last().ok_or("adoption")?.digest,
        reason: InvalidationReason::CameraMoved,
        evidence: None,
    };
    let preview = preview_invalidation(&fixture.deployment, &request)?;
    Ok(invalidate(
        &mut fixture.deployment,
        &request,
        preview.approval,
        &fixture.cx,
    )?)
}

fn request() -> TestResult<OrientRequest> {
    Ok(OrientRequest {
        view: AgentView::Brief,
        principal: PrincipalId::parse("principal:cascade")?,
        budget_tokens: None,
    })
}

fn read(fixture: &Fixture) -> TestResult<DeploymentSnapshot> {
    Ok(read_deployment(
        fixture.deployment.root(),
        &OrientLimits::default(),
    )?)
}

fn complete(snapshot: &DeploymentSnapshot) -> TestResult<bool> {
    let orientation = orient_deployment(snapshot, &request()?, &OrientLimits::default())?;
    Ok(orientation.coverage.as_ref().ok_or("coverage")?.complete())
}

#[test]
fn withdrawal_reaches_cold_orientation_graph_timeline_and_follow_without_rewriting_history()
-> TestResult {
    let (mut fixture, _) = setup("calibration-coverage-cold", false)?;
    let before = read(&fixture)?;
    assert!(complete(&before)?);
    let original: BTreeMap<_, _> = before
        .coverage
        .iter()
        .map(|item| (item.payload_digest, item.record.to_bytes()))
        .collect();
    let token = AnchorToken::parse(&snapshot_anchor_token(&before)).ok_or("anchor token")?;
    let withdrawal = withdraw(&mut fixture)?;
    let digest = withdrawal.receipt.digest();
    let history = DeploymentHistory::read(fixture.deployment.root(), &OrientLimits::default())?;
    let historical = history.snapshot_at(before.position)?;
    assert!(
        historical
            .coverage
            .iter()
            .all(|item| item.calibration_invalidation.is_none())
    );
    assert!(complete(&historical)?);
    let current = history.snapshot_at(history.head())?;
    for item in &current.coverage {
        assert_eq!(item.record.to_bytes(), original[&item.payload_digest]);
        assert_eq!(
            item.calibration_invalidation,
            (item.record.sensor_id == EAST).then_some(digest)
        );
    }
    let orientation = orient_deployment(&current, &request()?, &OrientLimits::default())?;
    let coverage = orientation.coverage.as_ref().ok_or("coverage")?;
    assert!(!coverage.complete());
    let east = coverage
        .zones
        .iter()
        .find(|zone| zone.sensor_id.as_deref() == Some(EAST))
        .ok_or("east")?;
    let west = coverage
        .zones
        .iter()
        .find(|zone| zone.sensor_id.as_deref() == Some(WEST))
        .ok_or("west")?;
    assert_eq!(east.state, ZoneCoverageState::Stale);
    assert!(east.witnesses.is_empty() && east.window.is_none());
    assert_eq!(east.calibration_invalidations, vec![digest]);
    assert!(
        east.gaps
            .iter()
            .any(|gap| gap.contains("calibration invalidation"))
    );
    assert_eq!(west.state, ZoneCoverageState::Covered);
    assert!(!west.witnesses.is_empty());
    assert!(
        orientation
            .capsule()
            .frame
            .evidence_handles
            .contains(&format!("fss://proof/{digest}"))
    );
    let window = west.window.ok_or("covered window")?;
    for observations in [
        coverage_observations(&current),
        coverage_observations_during(&current, window)?,
    ] {
        assert_eq!(observations.len(), 2);
        assert_eq!(
            observations
                .iter()
                .find(|row| row.sensor_id == EAST)
                .ok_or("east fact")?
                .witnesses,
            0
        );
        assert!(
            observations
                .iter()
                .find(|row| row.sensor_id == WEST)
                .ok_or("west fact")?
                .witnesses
                > 0
        );
    }
    let graph = coverage_single_points_during(&current, window)?;
    assert_eq!(graph.answer.zones[0].observers, vec![WEST]);
    assert_eq!(graph.answer.sensors.len(), 2);
    let timeline = coverage_timeline(
        &current,
        window,
        GraphBudget {
            max_operations: MAX_TIMELINE_OPERATIONS,
            max_output_entries: MAX_TIMELINE_OUTPUT_ENTRIES,
        },
    )?;
    assert!(!timeline.segments.is_empty());
    assert!(
        timeline
            .segments
            .iter()
            .all(|segment| segment.report.answer.zones[0].observers == vec![WEST])
    );
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
            .contains(&MeaningfulDeltaClass::CoverageLoss)
    );
    assert!(follow.delta.silence_certificate.is_none());
    Ok(())
}

#[test]
fn replacement_generation_restores_only_fresh_coverage_and_never_old_witnesses() -> TestResult {
    let (mut fixture, imports) = setup("calibration-coverage-recovery", false)?;
    let withdrawn = withdraw(&mut fixture)?.receipt.digest();
    let calibration = subject("withdraw-coverage-v2", 2);
    let binding = vec![("east".to_owned(), SensorId::parse(EAST)?)];
    let preview = preview_adoption(&fixture.deployment, &calibration, &binding)?;
    adopt(
        &mut fixture.deployment,
        &calibration,
        &binding,
        preview.approval,
        &fixture.cx,
    )?;
    let after_adoption = read(&fixture)?;
    assert!(!complete(&after_adoption)?);
    assert!(
        after_adoption
            .coverage
            .iter()
            .filter(|item| item.record.sensor_id == EAST)
            .all(|item| item.calibration_invalidation == Some(withdrawn))
    );
    let history = retained_adoptions(&fixture.deployment)?;
    let fresh = record(
        &fixture,
        imports[0],
        history[&21].last().ok_or("new adoption")?,
        false,
    )?;
    let fresh_digest = fresh.digest();
    retain_coverage(
        &mut fixture.deployment,
        &[&fresh],
        approval_digest(&[&fresh]),
        &fixture.cx,
    )?;
    let recovered = read(&fixture)?;
    assert!(complete(&recovered)?);
    assert!(
        recovered
            .coverage
            .iter()
            .filter(|item| item.record.sensor_id == EAST)
            .all(|item| {
                if item.payload_digest == fresh_digest {
                    item.calibration_invalidation.is_none()
                } else {
                    item.calibration_invalidation == Some(withdrawn)
                }
            })
    );
    Ok(())
}

#[test]
fn owner_asserted_provenance_cannot_evade_withdrawal_of_the_same_calibration_basis() -> TestResult {
    let (mut fixture, _) = setup("calibration-coverage-owner-asserted", true)?;
    assert!(complete(&read(&fixture)?)?);
    let withdrawal = withdraw(&mut fixture)?.receipt.digest();
    let current = read(&fixture)?;
    assert!(!complete(&current)?);
    let east = current
        .coverage
        .iter()
        .find(|item| item.record.sensor_id == EAST)
        .ok_or("east record")?;
    assert_eq!(east.calibration_invalidation, Some(withdrawal));
    Ok(())
}

#[test]
fn corrupt_withdrawal_or_approval_fails_closed_but_does_not_poison_earlier_prefixes() -> TestResult
{
    for damage_approval in [false, true] {
        let (mut fixture, _) = setup(
            if damage_approval {
                "calibration-approval-damage"
            } else {
                "calibration-receipt-damage"
            },
            false,
        )?;
        let before = read(&fixture)?;
        let withdrawal = withdraw(&mut fixture)?;
        let damaged = if damage_approval {
            withdrawal.approval
        } else {
            withdrawal.receipt.digest()
        };
        let path = fixture.deployment.publisher().spool().object_path(damaged);
        let mut bytes = fs::read(&path)?;
        *bytes.last_mut().ok_or("empty authority receipt")? ^= 1;
        fs::write(path, bytes)?;
        assert!(read_deployment(fixture.deployment.root(), &OrientLimits::default()).is_err());
        let history = DeploymentHistory::read(fixture.deployment.root(), &OrientLimits::default())?;
        assert!(complete(&history.snapshot_at(before.position)?)?);
        assert!(history.snapshot_at(history.head()).is_err());
    }
    Ok(())
}
