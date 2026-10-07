#![forbid(unsafe_code)]
//! Publication-boundary tests for current-authority checks on version-6 coverage.
//! Synthetic coverage isolates the retention protocol; it is not a device qualification.

use fss_core::{
    CaptureInterval, ContentDigest, ContractError, LedgerAnchor, SensorId, TimestampNs,
};
use fss_geometry::{
    AdjustedCamera, BundleParameter, CameraCovariance, CameraGeneration, PinholeIntrinsics,
    RadialDistortion, RigidPose, WorkBudget,
};
use fss_reference::ingest::calibration_coverage::{
    CalibrationCoverageAssessment, CalibrationCoverageInput, MAX_CALIBRATION_COVERAGE_WORK,
    apply_calibration_coverage, assess_calibration_coverage,
};
use fss_reference::ingest::ground_visibility::{
    CameraModel, Occlusion, OcclusionUnknownReason, PoseCovariance, PoseRobustness,
    PoseRobustnessClass, VisibilityPolicy, ZoneVisibility,
};
use fss_reference::ingest::privacy_mask::MaskBinding;
use fss_reference::ingest::recorded_corroboration::{CorroborationError, GroundZone};
use fss_reference::ingest::recorded_coverage::{
    CoverageEntry, CoverageExtras, CoverageFrame, CoverageInput, CoverageRecord, CoverageSource,
    CoverageZoneInput, GenerationCurrency, PoseProvenance, PoseUncertainty, approval_digest,
    build_coverage_with,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fixture(
    variance: f64,
    time: &str,
) -> TestResult<(CoverageRecord, CalibrationCoverageAssessment)> {
    fixture_with_privacy(variance, time, &MaskBinding::NoPolicy)
}

fn fixture_with_privacy(
    variance: f64,
    time: &str,
    privacy: &MaskBinding,
) -> TestResult<(CoverageRecord, CalibrationCoverageAssessment)> {
    use BundleParameter::{Cx, Cy, Fx, Fy, K1, K2, Rotation, Translation};
    let model = AdjustedCamera {
        identity: CameraGeneration {
            camera: 1,
            intrinsics: 2,
            extrinsics: 3,
        },
        intrinsics: PinholeIntrinsics::new(100, 100, 100.0, 100.0, 50.0, 50.0)?,
        distortion: RadialDistortion::NONE,
        pose: RigidPose::new(
            [[1.0, 0.0, 0.0], [0.0, -1.0, 0.0], [0.0, 0.0, -1.0]],
            [0.0, 0.0, 10.0],
        )?,
        covariance: CameraCovariance {
            parameters: vec![Cx],
            matrix: vec![variance],
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
    let ground = [
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
    let calibration = ContentDigest::sha256(b"CLI guard calibration fixture");
    let assessment = assess_calibration_coverage(
        CalibrationCoverageInput {
            camera_name: "front",
            camera: &model,
            calibration_digest: calibration,
            sensor: &SensorId::parse("sensor:front")?,
            privacy,
            zones: &ground,
            policy: VisibilityPolicy {
                grid: 2,
                threshold_ppm: 1_000_000,
            },
        },
        &mut WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK),
    )?;
    let frames = (0..20)
        .filter(|segment| *segment != 8)
        .map(|segment| {
            Ok(CoverageFrame {
                segment,
                capture: CaptureInterval::new(
                    TimestampNs(1_000 + segment as i128 * 100),
                    TimestampNs(1_002 + segment as i128 * 100),
                )?,
            })
        })
        .collect::<Result<Vec<_>, ContractError>>()?;
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
    let record = build_coverage_with(
        &CoverageInput {
            source: CoverageSource::Corroborate,
            import_identity: ContentDigest::sha256(b"CLI guard import"),
            import_root: ContentDigest::sha256(b"root"),
            sensor_id: "sensor:front",
            analysis_digest: ContentDigest::sha256(b"CLI analysis"),
            basis: LedgerAnchor::genesis("site:receipt"),
            capture_time_label: time,
            segment_gaps: &[false; 20],
            first_segment: 0,
            last_segment: 19,
            frames: &frames,
            confirmation_hits: 3,
            zones: ground
                .iter()
                .map(|zone| CoverageZoneInput {
                    zone_id: zone.zone_id.clone(),
                    geometry: format!("{},{},{},{}", zone.x, zone.y, zone.width, zone.height),
                    inside_frame: true,
                    pipeline_generation: ContentDigest::sha256(zone.zone_id.as_bytes()),
                    entries: vec![CoverageEntry {
                        segment: 12,
                        candidate: ContentDigest::sha256(b"observed entry"),
                        event_id: Some("event:entry".to_owned()),
                    }],
                })
                .collect(),
        },
        &CoverageExtras {
            sensor_health: None,
            visibility: vec![Some(visibility.clone()), Some(visibility)],
            refusals: Vec::new(),
            restarts: vec![9],
            pose_provenance: Some(PoseProvenance::SiteCalibration {
                calibration_digest: calibration,
                camera_handle: 1,
                intrinsics_generation: 2,
                extrinsics_generation: 3,
                currency: GenerationCurrency::OwnerAsserted,
            }),
            pose_uncertainty: Some(PoseUncertainty::SigmaPoints {
                covariance: PoseCovariance::new([[0.0; 6]; 6])?,
            }),
            pose_robustness: vec![Some(robust), Some(robust)],
        },
    )?;
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

// Publication-boundary regressions for the version-6 currency interlock.
mod currency_retention {
    use super::*;
    use fss_core::region::{ContextAuthority, RootAuthoritySpec};
    use fss_core::{BudgetVector, OperationId};
    use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
    use fss_reference::ingest::recorded_coverage::{
        CoverageError, check_approval, retain_coverage,
    };
    use fss_reference::{ReferenceDeployment, ReplayCx};
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};

    struct Directory(PathBuf);
    impl Directory {
        fn new(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
            for attempt in 0..100_u32 {
                let path = std::env::temp_dir().join(format!(
                    "fss-coverage-currency-{name}-{}-{attempt}",
                    std::process::id(),
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Ok(Self(path)),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Err(std::io::Error::other("owned test directory limit").into())
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn open(
        name: &str,
    ) -> Result<(Directory, ReplayCx, ReferenceDeployment), Box<dyn std::error::Error>> {
        let directory = Directory::new(name)?;
        let root = directory.0.join("deployment");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:coverage-currency".to_owned(),
            operation_id: OperationId::parse("operation:coverage-currency")?,
            principal: "principal:coverage-currency".to_owned(),
            capabilities: vec!["ADP-REPLAY-001".to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(64 * 1024 * 1024)
                .storage_operations(4096)
                .build()?,
            privacy_scope: "privacy:test".to_owned(),
            retention_scope: "retention:test".to_owned(),
            anchor_universe: ContentDigest::sha256(b"site:receipt"),
            generation: 1,
        })?;
        authority.validate()?;
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let deployment = ReferenceDeployment::open(&root, "site:receipt", &cx)?;
        Ok((directory, cx, deployment))
    }

    fn inventory(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>, std::io::Error> {
        let mut result = BTreeMap::new();
        let mut pending = vec![root.to_path_buf()];
        let mut visited = 0;
        while let Some(path) = pending.pop() {
            visited += 1;
            if visited > 4096 {
                return Err(std::io::Error::other("test inventory bound"));
            }
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    pending.push(entry.path());
                } else if entry.file_type()?.is_file() {
                    result.insert(entry.path(), fs::read(entry.path())?);
                } else {
                    return Err(std::io::Error::other("unexpected test directory entry"));
                }
            }
        }
        Ok(result)
    }

    fn mask(deployment: &mut ReferenceDeployment, cx: &ReplayCx, sensor: &str) -> TestResult {
        let policy = PrivacyMaskPolicy::new(SensorId::parse(sensor)?, [100, 100], &[[0, 0, 2, 2]])?;
        let approval = preview_mask(deployment, &policy)?.approval;
        declare_mask(deployment, &policy, approval, cx)?;
        Ok(())
    }

    #[test]
    fn changed_privacy_blocks_the_entire_batch_before_staging_not_historical_decode() -> TestResult
    {
        let (directory, cx, mut deployment) = open("changed-mask")?;
        let (nominal, assessment) = fixture(4.0, "operator_assumption")?;
        let guarded = guarded(&nominal, &assessment)?;
        let bytes = guarded.to_bytes();
        let approval = approval_digest(&[&nominal, &guarded]);
        check_approval(&deployment, &[&nominal, &guarded], approval)?;
        mask(&mut deployment, &cx, "sensor:front")?;
        let before = inventory(&directory.0)?;
        let anchor = deployment.current_anchor().clone();
        assert!(matches!(
            retain_coverage(&mut deployment, &[&nominal, &guarded], approval, &cx),
            Err(CoverageError::Currency { .. }),
        ));
        assert_eq!(deployment.current_anchor().clone(), anchor);
        assert_eq!(inventory(&directory.0)?, before);
        assert_eq!(
            CoverageRecord::from_bytes(&bytes, guarded.digest())?,
            guarded
        );
        Ok(())
    }

    #[test]
    fn an_unrelated_sensors_mask_does_not_invalidate_the_guard() -> TestResult {
        let (_directory, cx, mut deployment) = open("unrelated-mask")?;
        let (nominal, assessment) = fixture(4.0, "operator_assumption")?;
        let guarded = guarded(&nominal, &assessment)?;
        let approval = approval_digest(&[&guarded]);
        check_approval(&deployment, &[&guarded], approval)?;
        let anchor = deployment.current_anchor().clone();
        mask(&mut deployment, &cx, "sensor:other")?;
        assert_ne!(deployment.current_anchor().clone(), anchor);
        check_approval(&deployment, &[&guarded], approval)?;
        Ok(())
    }

    #[test]
    fn an_adopted_current_claim_needs_the_exact_retained_receipt() -> TestResult {
        let (_directory, _cx, deployment) = open("missing-adoption")?;
        let (mut nominal, assessment) = fixture(4.0, "operator_assumption")?;
        if let Some(PoseProvenance::SiteCalibration { currency, .. }) = &mut nominal.pose_provenance
        {
            *currency = GenerationCurrency::AdoptedCurrent {
                receipt: ContentDigest::sha256(b"not a retained owner adoption"),
            };
        }
        let guarded = guarded(&nominal, &assessment)?;
        assert!(matches!(
            check_approval(&deployment, &[&guarded], approval_digest(&[&guarded])),
            Err(CoverageError::Currency { .. }),
        ));
        Ok(())
    }

    #[test]
    fn legacy_proposals_keep_their_old_semantics() -> TestResult {
        let (_directory, cx, mut deployment) = open("legacy")?;
        let (nominal, _) = fixture(4.0, "operator_assumption")?;
        let original = nominal.to_bytes();
        mask(&mut deployment, &cx, "sensor:front")?;
        check_approval(&deployment, &[&nominal], approval_digest(&[&nominal]))?;
        assert_eq!(nominal.to_bytes(), original);
        Ok(())
    }

    #[test]
    fn a_retained_guard_cannot_skip_currency_checks_on_its_idempotent_path() -> TestResult {
        use fss_reference::ingest::recorded_coverage::CoverageStatus;
        let (directory, cx, mut deployment) = open("retained-rerun")?;
        let (nominal, assessment) = fixture(4.0, "operator_assumption")?;
        // Seed only the synthetic fixture root required by this retention-owner test.
        // This is not an acquisition or real-camera evidence qualification.
        let root = deployment.publisher_mut().stage_object(b"root")?;
        deployment.publisher_mut().verify_object(root)?;
        assert_eq!(root, nominal.import_root);
        let guarded = guarded(&nominal, &assessment)?;
        let approval = approval_digest(&[&guarded]);
        assert_eq!(
            retain_coverage(&mut deployment, &[&guarded], approval, &cx)?,
            CoverageStatus::Retained
        );
        let retained = inventory(&directory.0)?;
        assert_eq!(
            retain_coverage(&mut deployment, &[&guarded], approval, &cx)?,
            CoverageStatus::AlreadyRetained
        );
        assert_eq!(inventory(&directory.0)?, retained);
        mask(&mut deployment, &cx, "sensor:front")?;
        let before = inventory(&directory.0)?;
        let anchor = deployment.current_anchor().clone();
        assert!(matches!(
            retain_coverage(&mut deployment, &[&guarded], approval, &cx),
            Err(CoverageError::Currency { .. }),
        ));
        assert_eq!(deployment.current_anchor().clone(), anchor);
        assert_eq!(inventory(&directory.0)?, before);
        Ok(())
    }

    #[test]
    fn restoring_mask_bytes_does_not_resurrect_an_old_generation() -> TestResult {
        use fss_reference::ingest::privacy_mask::current_mask;
        let (directory, cx, mut deployment) = open("mask-aba")?;
        let sensor = SensorId::parse("sensor:front")?;
        let first = PrivacyMaskPolicy::new(sensor.clone(), [100, 100], &[[0, 0, 2, 2]])?;
        let second = PrivacyMaskPolicy::new(sensor.clone(), [100, 100], &[[1, 0, 2, 2]])?;
        let approval = preview_mask(&deployment, &first)?.approval;
        declare_mask(&mut deployment, &first, approval, &cx)?;
        let original = current_mask(&deployment, &sensor)?;
        let (nominal, assessment) = fixture_with_privacy(4.0, "operator_assumption", &original)?;
        let screened = guarded(&nominal, &assessment)?;
        let approval = approval_digest(&[&screened]);
        check_approval(&deployment, &[&screened], approval)?;
        for policy in [&second, &first] {
            let approval = preview_mask(&deployment, policy)?.approval;
            declare_mask(&mut deployment, policy, approval, &cx)?;
        }
        let now = current_mask(&deployment, &sensor)?;
        assert_eq!(original.digest(), now.digest());
        assert_eq!(original.generation(), Some(1));
        assert_eq!(now.generation(), Some(3));
        let before = inventory(&directory.0)?;
        let anchor = deployment.current_anchor().clone();
        assert!(matches!(
            retain_coverage(&mut deployment, &[&screened], approval, &cx),
            Err(CoverageError::Currency { .. }),
        ));
        assert_eq!(deployment.current_anchor(), &anchor);
        assert_eq!(inventory(&directory.0)?, before);
        Ok(())
    }
}
