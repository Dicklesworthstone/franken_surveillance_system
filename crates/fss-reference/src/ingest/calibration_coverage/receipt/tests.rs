#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crate::ingest::calibration_coverage::{
    CalibrationCoverageInput, MAX_CALIBRATION_COVERAGE_WORK, assess_calibration_coverage,
};
use crate::ingest::ground_visibility::{
    CameraModel, Occlusion, OcclusionUnknownReason, PoseCovariance, PoseRobustness,
    PoseRobustnessClass, VisibilityPolicy, ZoneVisibility,
};
use crate::ingest::privacy_mask::MaskBinding;
use crate::ingest::recorded_corroboration::GroundZone;
use crate::ingest::recorded_coverage::{
    CoverageEntry, CoverageExtras, CoverageFrame, CoverageInput, CoverageZoneInput,
    GenerationCurrency, approval_digest, build_coverage_with,
};
use fss_core::{CaptureInterval, LedgerAnchor, SensorId, TimestampNs};
use fss_geometry::{CameraCovariance, PinholeIntrinsics, RadialDistortion, RigidPose};
use std::sync::atomic::AtomicBool;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture() -> Result<(CoverageRecord, CalibrationCoverageAssessment), Box<dyn std::error::Error>>
{
    use BundleParameter::{Cx, Cy, Fx, Fy, K1, K2, Rotation, Translation};
    let identity = CameraGeneration {
        camera: 1,
        intrinsics: 2,
        extrinsics: 3,
    };
    let model = AdjustedCamera {
        identity,
        intrinsics: PinholeIntrinsics::new(100, 100, 100.0, 100.0, 50.0, 50.0)?,
        distortion: RadialDistortion::NONE,
        pose: RigidPose::new(
            [[1.0, 0.0, 0.0], [0.0, -1.0, 0.0], [0.0, 0.0, -1.0]],
            [0.0, 0.0, 10.0],
        )?,
        covariance: CameraCovariance {
            parameters: vec![Cx],
            matrix: vec![4.0],
            fixed: vec![
                Rotation(0),
                Rotation(1),
                Rotation(2),
                Translation(0),
                Translation(1),
                Translation(2),
                Fx,
                Fy,
                Cy,
                K1,
                K2,
            ],
        },
    };
    let ground = vec![
        GroundZone {
            zone_id: "center".to_owned(),
            x: -1.0,
            y: -1.0,
            width: 2.0,
            height: 2.0,
        },
        GroundZone {
            zone_id: "edge".to_owned(),
            x: 4.5,
            y: -1.0,
            width: 0.4,
            height: 2.0,
        },
    ];
    let calibration = ContentDigest::sha256(b"receipt fixture calibration");
    let assessment = assess_calibration_coverage(
        CalibrationCoverageInput {
            camera_name: "front",
            camera: &model,
            calibration_digest: calibration,
            sensor: &SensorId::parse("sensor:front")?,
            privacy: &MaskBinding::NoPolicy,
            zones: &ground,
            policy: VisibilityPolicy {
                grid: 2,
                threshold_ppm: 1_000_000,
            },
        },
        &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK),
    )?;
    let frames: Vec<_> = (0..20)
        .filter(|n| *n != 8)
        .map(|segment| {
            Ok(CoverageFrame {
                segment,
                capture: CaptureInterval::new(
                    TimestampNs(1_000 + segment as i128 * 100),
                    TimestampNs(1_002 + segment as i128 * 100),
                )?,
            })
        })
        .collect::<Result<_, ContractError>>()?;
    let zones = ground
        .iter()
        .map(|zone| CoverageZoneInput {
            zone_id: zone.zone_id.clone(),
            geometry: format!("{},{},{},{}", zone.x, zone.y, zone.width, zone.height),
            inside_frame: true,
            pipeline_generation: ContentDigest::sha256(zone.zone_id.as_bytes()),
            entries: vec![CoverageEntry {
                segment: 12,
                candidate: ContentDigest::sha256(b"entry"),
                event_id: Some("event:observed-entry".to_owned()),
            }],
        })
        .collect();
    let visibility = ZoneVisibility {
        camera_model: CameraModel::CalibratedPose,
        grid: 2,
        threshold_ppm: 1_000_000,
        samples: 4,
        visible: 4,
        outside_frustum: 0,
        occluded: 0,
        privacy_masked: 0,
        occlusion: Occlusion::Unknown(OcclusionUnknownReason::NoSceneMesh),
    };
    let robust = PoseRobustness {
        nominal: PoseRobustnessClass::Observable,
        perturbations: 12,
        observable: 12,
        occluded: 0,
        outside_frustum: 0,
        privacy_masked: 0,
    };
    let mut record = build_coverage_with(
        &CoverageInput {
            source: CoverageSource::Corroborate,
            import_identity: ContentDigest::sha256(b"import"),
            import_root: ContentDigest::sha256(b"root"),
            sensor_id: "sensor:front",
            analysis_digest: ContentDigest::sha256(b"analysis"),
            basis: LedgerAnchor::genesis("site:receipt"),
            capture_time_label: "operator_assumption",
            segment_gaps: &[false; 20],
            first_segment: 0,
            last_segment: 19,
            frames: &frames,
            confirmation_hits: 3,
            zones,
        },
        &CoverageExtras {
            sensor_health: None,
            visibility: vec![Some(visibility.clone()), Some(visibility)],
            refusals: Vec::new(),
            restarts: vec![9],
            pose_provenance: Some(PoseProvenance::SiteCalibration {
                calibration_digest: calibration,
                camera_handle: identity.camera,
                intrinsics_generation: identity.intrinsics,
                extrinsics_generation: identity.extrinsics,
                currency: GenerationCurrency::OwnerAsserted,
            }),
            pose_uncertainty: Some(PoseUncertainty::SigmaPoints {
                covariance: PoseCovariance::new([[0.0; 6]; 6])?,
            }),
            pose_robustness: vec![Some(robust), Some(robust)],
        },
    )?;
    for zone in &mut record.zones {
        for interval in &mut zone.uncovered {
            if interval.reason == UncoveredReason::SegmentNotDecoded {
                interval.reason = UncoveredReason::DecodeRefused {
                    error_id: "ERR-MEDIA-DECODE-001".to_owned(),
                };
            }
        }
    }
    record.validate()?;
    Ok((record, assessment))
}

fn guarded(
    record: &CoverageRecord,
    assessment: &CalibrationCoverageAssessment,
) -> Result<CoverageRecord, CorroborationError> {
    apply_calibration_coverage(
        record,
        assessment,
        &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK),
    )
}

#[test]
fn only_rejected_zones_lose_witnesses_and_no_segment_or_reason_is_lost() -> TestResult {
    let (nominal, assessment) = fixture()?;
    let before = nominal.to_bytes();
    let result = guarded(&nominal, &assessment)?;
    assert_eq!(nominal.to_bytes(), before);
    assert!(!result.zones[0].witnesses.is_empty());
    assert!(result.zones[1].witnesses.is_empty());
    for (old, new) in nominal.zones.iter().zip(&result.zones) {
        for interval in &old.uncovered {
            assert!(new.uncovered.contains(interval));
        }
        check_partition(&result, new)?;
    }
    let added: Vec<_> = result.zones[1]
        .uncovered
        .iter()
        .filter(|u| u.reason == UncoveredReason::CalibrationUncertainty)
        .collect();
    assert_eq!(added.len(), nominal.zones[1].witnesses.len());
    for (gap, witness) in added.iter().zip(&nominal.zones[1].witnesses) {
        assert_eq!(
            (gap.first_segment, gap.last_segment, gap.capture),
            (
                witness.first_segment,
                witness.last_segment,
                Some(witness.outer)
            )
        );
    }
    Ok(())
}

#[test]
fn surviving_witnesses_keep_anchor_domains_and_capture_but_rebind_predicates() -> TestResult {
    let (nominal, assessment) = fixture()?;
    let result = guarded(&nominal, &assessment)?;
    assert_ne!(nominal.identity(), result.identity());
    assert_ne!(nominal.object_id()?, result.object_id()?);
    assert_ne!(approval_digest(&[&nominal]), approval_digest(&[&result]));
    for (old, new) in nominal.zones[0]
        .witnesses
        .iter()
        .zip(&result.zones[0].witnesses)
    {
        assert_eq!(
            (
                old.first_segment,
                old.last_segment,
                old.frames,
                old.covered,
                old.outer
            ),
            (
                new.first_segment,
                new.last_segment,
                new.frames,
                new.covered,
                new.outer
            )
        );
        assert_eq!(old.witness.anchor, new.witness.anchor);
        assert_eq!(old.witness.authorized_domain, new.witness.authorized_domain);
        assert_ne!(
            old.witness.negative_predicate,
            new.witness.negative_predicate
        );
        assert!(
            new.witness
                .negative_predicate
                .contains("not physical observability or a probability")
        );
        new.witness.require_certified_absence()?;
    }
    result.validate()?;
    Ok(())
}

#[test]
fn version_six_and_standalone_receipt_round_trip_while_v5_stays_v5() -> TestResult {
    let (nominal, assessment) = fixture()?;
    let old = nominal.to_bytes();
    let mut d = CanonicalDecoder::new(&old);
    d.bytes()?;
    assert_eq!(d.u32()?, 5);
    assert_eq!(CoverageRecord::from_bytes(&old, nominal.digest())?, nominal);
    let result = guarded(&nominal, &assessment)?;
    let bytes = result.to_bytes();
    let mut d = CanonicalDecoder::new(&bytes);
    d.bytes()?;
    assert_eq!(d.u32()?, 6);
    assert_eq!(CoverageRecord::from_bytes(&bytes, result.digest())?, result);
    let receipt = result
        .pose_uncertainty
        .as_ref()
        .and_then(PoseUncertainty::guard_receipt)
        .unwrap();
    assert_eq!(
        CalibrationCoverageReceipt::from_bytes(&receipt.to_bytes(), receipt.digest())?,
        *receipt
    );
    assert!(receipt.to_bytes().len() < MAX_CALIBRATION_COVERAGE_RECEIPT_BYTES);
    Ok(())
}

#[test]
fn the_same_screen_is_idempotent_and_another_requires_fresh_nominal_analysis() -> TestResult {
    let (nominal, mut assessment) = fixture()?;
    let result = guarded(&nominal, &assessment)?;
    assert_eq!(guarded(&result, &assessment)?, result);
    assessment.input_digest = ContentDigest::sha256(b"different covariance");
    assert!(guarded(&result, &assessment).is_err());
    Ok(())
}

#[test]
fn incorrect_sensor_calibration_generation_geometry_and_pose_block_are_refused() -> TestResult {
    let (nominal, assessment) = fixture()?;
    for change in 0..7 {
        let mut wrong = nominal.clone();
        match change {
            0 => wrong.sensor_id = "sensor:other".to_owned(),
            1 => {
                if let Some(PoseProvenance::SiteCalibration {
                    calibration_digest, ..
                }) = &mut wrong.pose_provenance
                {
                    *calibration_digest = ContentDigest::sha256(b"other calibration");
                }
            }
            2 => {
                if let Some(PoseProvenance::SiteCalibration {
                    extrinsics_generation,
                    ..
                }) = &mut wrong.pose_provenance
                {
                    *extrinsics_generation += 1;
                }
            }
            3 => wrong.zones[0].geometry = "-2,-1,2,2".to_owned(),
            4 => wrong.zones[0].visibility.as_mut().unwrap().grid = 4,
            5 => wrong.zones[1].zone_id = wrong.zones[0].zone_id.clone(),
            _ => {
                let mut matrix = [[0.0; 6]; 6];
                matrix[0][0] = 1.0;
                wrong.pose_uncertainty = Some(PoseUncertainty::SigmaPoints {
                    covariance: PoseCovariance::new(matrix)?,
                });
            }
        }
        assert!(guarded(&wrong, &assessment).is_err(), "change {change}");
    }
    Ok(())
}

#[test]
fn receipt_validation_blocks_forged_witnesses_and_scope_rebinding() -> TestResult {
    let (nominal, assessment) = fixture()?;
    let result = guarded(&nominal, &assessment)?;
    for change in 0..5 {
        let mut forged = result.clone();
        match change {
            0 => forged.zones[1].witnesses = nominal.zones[1].witnesses.clone(),
            1 => forged.zones[0].pipeline_generation = nominal.zones[0].pipeline_generation,
            2 => forged.analysis_digest = nominal.analysis_digest,
            3 => forged.import_root = ContentDigest::sha256(b"another root"),
            _ => forged.zones[0].uncovered[0].reason = UncoveredReason::CalibrationUncertainty,
        }
        assert!(forged.validate().is_err(), "change {change}");
        assert!(CoverageRecord::from_bytes(&forged.to_bytes(), forged.digest()).is_err());
    }
    Ok(())
}

#[test]
fn overlap_or_holes_are_rejected_without_widening_the_interval() -> TestResult {
    let (nominal, assessment) = fixture()?;
    for overlap in [false, true] {
        let mut wrong = nominal.clone();
        if overlap {
            wrong.zones[0].uncovered[0].last_segment += 1;
        } else {
            wrong.zones[0].uncovered[0].last_segment -= 1;
        }
        assert!(guarded(&wrong, &assessment).is_err());
    }
    Ok(())
}

#[test]
fn malformed_receipts_unknown_versions_and_trailing_bytes_are_refused() -> TestResult {
    let (nominal, assessment) = fixture()?;
    let result = guarded(&nominal, &assessment)?;
    let receipt = *result
        .pose_uncertainty
        .as_ref()
        .and_then(PoseUncertainty::guard_receipt)
        .unwrap();
    for change in 0..5 {
        let mut wrong = receipt;
        match change {
            0 => wrong.len = 17,
            1 => wrong.len = 0,
            2 => wrong.zones[0].as_mut().unwrap().counts = [u32::MAX; 7],
            3 => wrong.zones.swap(0, 1),
            _ => wrong.pose_bits[0] = f64::NAN.to_bits(),
        }
        let bytes = wrong.to_bytes();
        assert!(
            CalibrationCoverageReceipt::from_bytes(&bytes, ContentDigest::sha256(&bytes)).is_err()
        );
    }
    let mut trailing = receipt.to_bytes();
    trailing.push(0);
    assert!(
        CalibrationCoverageReceipt::from_bytes(&trailing, ContentDigest::sha256(&trailing))
            .is_err()
    );
    assert!(
        CalibrationCoverageReceipt::from_bytes(
            &receipt.to_bytes(),
            ContentDigest::sha256(b"wrong")
        )
        .is_err()
    );
    let original = result.to_bytes();
    let mut d = CanonicalDecoder::new(&original);
    d.bytes()?;
    let offset = original.len() - d.remaining();
    for version in [5_u32, 7] {
        let mut bytes = original.clone();
        let mut e = CanonicalEncoder::new();
        e.u32(version);
        bytes[offset..offset + 4].copy_from_slice(&e.finish());
        assert!(CoverageRecord::from_bytes(&bytes, ContentDigest::sha256(&bytes)).is_err());
    }
    Ok(())
}

#[test]
fn budget_and_cancellation_fail_atomically_with_exact_cost_boundary() -> TestResult {
    let (nominal, assessment) = fixture()?;
    let original = nominal.to_bytes();
    let mut enough = WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK);
    apply_calibration_coverage(&nominal, &assessment, &mut enough)?;
    let work = enough.used();
    assert!(
        apply_calibration_coverage(&nominal, &assessment, &mut WorkBudget::new(work - 1)).is_err()
    );
    let mut exact = WorkBudget::new(work);
    apply_calibration_coverage(&nominal, &assessment, &mut exact)?;
    assert_eq!(exact.remaining(), 0);
    let flag = AtomicBool::new(true);
    assert!(
        apply_calibration_coverage(
            &nominal,
            &assessment,
            &mut WorkBudget::cancellable(MAX_CALIBRATION_COVERAGE_WORK, &flag)
        )
        .is_err()
    );
    assert_eq!(nominal.to_bytes(), original);
    Ok(())
}

#[test]
fn recorded_health_composes_with_full_camera_guard_and_roundtrips_version_seven() -> TestResult {
    use crate::ingest::recorded_health::RecordedHealthScreen;
    use crate::ingest::sensor_health::HealthFrame;
    use fss_core::region::{ContextAuthority, RootAuthoritySpec};
    let (nominal, assessment) = fixture()?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:health-guard".to_owned(),
        operation_id: fss_core::OperationId::parse("operation:health-guard")?,
        principal: "principal:health-guard".to_owned(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(4096)
            .build()?,
        privacy_scope: "privacy:test".to_owned(),
        retention_scope: "retention:test".to_owned(),
        anchor_universe: ContentDigest::sha256(b"site:health-guard"),
        generation: 1,
    })?;
    let cx = crate::ReplayCx::from_context_authority(
        &authority,
        std::env::temp_dir().join("fss-health-guard-context"),
    )?;
    let generation = ContentDigest::sha256(b"health-guard-plan");
    let mut screen = RecordedHealthScreen::new(
        20,
        nominal.import_identity,
        nominal.import_root,
        &nominal.sensor_id,
        generation,
        std::collections::BTreeSet::new(),
    )?;
    for segment in (0..20_u64).filter(|segment| *segment != 8) {
        let pixels = vec![80 + (segment % 2) as u8; 100 * 100];
        let _ = screen.observe(
            HealthFrame {
                source_generation: generation,
                segment,
                capsule_digest: ContentDigest::sha256(&segment.to_le_bytes()),
                capture: CaptureInterval::new(
                    TimestampNs(1_000 + i128::from(segment) * 100),
                    TimestampNs(1_002 + i128::from(segment) * 100),
                )?,
                dimensions: [100, 100],
                gap_before: segment == 9,
                pixels: &pixels,
            },
            &cx,
        )?;
    }
    let summary = screen.finish(&[9])?;
    let frames = summary.observations().iter().map(|frame| CoverageFrame {
        segment: frame.segment as usize,
        capture: frame.capture,
    }).collect::<Vec<_>>();
    let zones = nominal.zones.iter().map(|zone| CoverageZoneInput {
        zone_id: zone.zone_id.clone(),
        geometry: zone.geometry.clone(),
        inside_frame: true,
        pipeline_generation: zone.pipeline_generation,
        entries: zone.uncovered.iter().filter_map(|interval| {
            if let UncoveredReason::ZoneEntry { candidate, event_id } = &interval.reason {
                Some(CoverageEntry {
                    segment: interval.first_segment as usize,
                    candidate: *candidate,
                    event_id: event_id.clone(),
                })
            } else {
                None
            }
        }).collect(),
    }).collect();
    let health_record = build_coverage_with(
        &CoverageInput {
            source: nominal.source,
            import_identity: nominal.import_identity,
            import_root: nominal.import_root,
            sensor_id: &nominal.sensor_id,
            analysis_digest: nominal.analysis_digest,
            basis: nominal.basis.clone(),
            capture_time_label: &nominal.capture_time_label,
            segment_gaps: &[false; 20],
            first_segment: 0,
            last_segment: 19,
            frames: &frames,
            confirmation_hits: 3,
            zones,
        },
        &CoverageExtras {
            visibility: nominal.zones.iter().map(|zone| zone.visibility.clone()).collect(),
            refusals: vec![crate::ingest::tolerant_decode::DecodeRefusal {
                first_segment: 8,
                last_segment: 8,
                error_id: "ERR-MEDIA-DECODE-001".to_owned(),
            }],
            restarts: vec![9],
            pose_provenance: nominal.pose_provenance,
            pose_uncertainty: nominal.pose_uncertainty,
            pose_robustness: nominal.zones.iter().map(|zone| zone.pose_robustness).collect(),
            sensor_health: Some(summary),
        },
    )?;
    let guarded = apply_calibration_coverage(
        &health_record,
        &assessment,
        &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK),
    )?;
    assert!(guarded.witnesses().next().is_some());
    assert_eq!(guarded.sensor_health, health_record.sensor_health);
    let bytes = guarded.to_bytes();
    let mut decoder = CanonicalDecoder::new(&bytes);
    assert_eq!(decoder.bytes()?, b"FSSCOV01");
    assert_eq!(decoder.u32()?, 7);
    assert_eq!(CoverageRecord::from_bytes(&bytes, guarded.digest())?, guarded);
    let mut stripped = guarded.clone();
    stripped.sensor_health = None;
    assert!(stripped.validate().is_err());
    Ok(())
}
