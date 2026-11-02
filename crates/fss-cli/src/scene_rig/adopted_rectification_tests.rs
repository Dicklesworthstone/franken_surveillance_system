#![forbid(unsafe_code)]
//! Real adopted camera models cannot cross the original/rectified rig admission boundary.
//! Candidate matrices are authored controls, not measured camera accuracy.

use super::*;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, ContentDigest, DigestAlgorithm, OperationId, SensorId, StreamId, TimestampNs,
};
use fss_geometry::{BundleParameter, CameraGeneration, GeometryError};
use fss_reference::ingest::calibration_adoption::{CalibrationSubject, adopt, preview_adoption};
use fss_reference::ingest::scene_calibration::{
    SceneCalibrationBinding, SceneCalibrationRequest, resolve_scene_calibration,
    resolve_scene_calibration_for_rectification,
};
use fss_reference::ingest::site_calibration::{
    CalibratedCamera, CalibrationInput, SeedMode, SiteCalibration,
};
use fss_reference::ingest::{FileIngestAdapter, FileIngestRequest};
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_twin::localization::native::descriptor_domain;
use fss_twin::rectification::{LumaRange, RectificationPlan};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

#[path = "../../../fss-twin/tests/common/mod.rs"]
mod twin_fixture;
const JPEG: &[u8] = include_bytes!("../../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
const WORK: u64 = 10_000_000;
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn h(value: &str) -> ContentDigest {
    ContentDigest::sha256(value.as_bytes())
}
fn raw(value: [u8; 32]) -> ContentDigest {
    ContentDigest::new(DigestAlgorithm::Sha256, value)
}

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(tag: &str) -> TestResult<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-adopted-rectified-rig-{tag}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context(root: &Path, site: &str) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:scene-calibration".into(),
        operation_id: OperationId::parse("operation:scene-calibration")?,
        principal: "principal:scene-calibration".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: h(site),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

fn original_input(identity: CameraGeneration, frame: bool) -> Vec<u8> {
    let header = if frame {
        "fss.site_camera_frame.v1"
    } else {
        "fss.site_camera_observations.v1"
    };
    let extra = if frame {
        "interpretation gray\n".into()
    } else {
        format!(
            "pixels {}\ndescriptor-domain {}\n",
            h("calibration pixels"),
            raw(descriptor_domain())
        )
    };
    format!(
        "{header}\ncamera {} {} {}\nimage 96 96\nexposure {}\nimage-domain {}\n{extra}intrinsics fixed 80 80 48 48\n",
        identity.camera, identity.intrinsics, identity.extrinsics,
        h(&format!("calibration exposure {}", identity.camera)), h("original pinhole image mode"),
    ).into_bytes()
}

fn candidate(twin: &PropertyTwin, inputs: &[Vec<u8>; 2]) -> SiteCalibration {
    let rotation = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
    let cameras = ["east", "west"]
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let translation = [-(i as f64), 0.0, 0.0];
            let mut covariance = vec![0.0; 36];
            for axis in 0..6 {
                covariance[axis * 6 + axis] = (axis as f64 + 1.0) * 1e-6;
            }
            covariance[1] = 1e-7;
            covariance[6] = 1e-7;
            CalibratedCamera {
                name: (*name).into(),
                identity: CameraGeneration {
                    camera: 21 + i as u64,
                    intrinsics: 1,
                    extrinsics: 1,
                },
                observations: ContentDigest::sha256(&inputs[i]),
                input: CalibrationInput::Correspondences,
                dimensions: [96, 96],
                mode: SeedMode::Fixed,
                seed_sample: None,
                seed_candidate: 0,
                seed_alternatives: 1,
                seed_inliers: 8,
                seed_fit_rms_px: 0.1,
                seed_intrinsics: [80.0, 80.0, 48.0, 48.0],
                seed_rotation: rotation,
                seed_translation: translation,
                intrinsics: [80.0, 80.0, 48.0, 48.0],
                distortion: [0.0, 0.0],
                rotation,
                translation,
                covariance_parameters: vec![
                    BundleParameter::Rotation(0),
                    BundleParameter::Rotation(1),
                    BundleParameter::Rotation(2),
                    BundleParameter::Translation(0),
                    BundleParameter::Translation(1),
                    BundleParameter::Translation(2),
                ],
                covariance,
                fixed_parameters: vec![
                    BundleParameter::Focal,
                    BundleParameter::Cx,
                    BundleParameter::Cy,
                ],
                seed_rms_px: 1.0,
                refined_rms_px: 0.1,
                control_observations: 8,
                free_observations: 0,
            }
        })
        .collect();
    SiteCalibration {
        twin_package: raw(twin.digest()),
        twin_source: raw(twin.source_scene_digest()),
        atlas_package: h("authored test atlas package"),
        atlas_fingerprint: h("authored test atlas semantic identity").bytes(),
        atlas_provenance: h("authored test atlas provenance"),
        descriptor_domain: descriptor_domain(),
        control_error_bound: None,
        initial_rms_px: 1.0,
        final_rms_px: 0.1,
        iterations: 2,
        accepted_steps: 1,
        convergence: "gradient".into(),
        observation_sigma_px: 0.5,
        sigma_estimated: false,
        control_points: vec![1, 2, 3],
        tie_points: vec![],
        excluded_points: vec![],
        frame_policy: None,
        cameras,
    }
}

struct Fixture {
    _directory: OwnedDirectory,
    cx: ReplayCx,
    deployment: ReferenceDeployment,
    twin: PropertyTwin,
    calibration: SiteCalibration,
    encoded: Vec<u8>,
    inputs: [Vec<u8>; 2],
    sensors: [SensorId; 2],
    adoptions: [ContentDigest; 2],
}
impl Fixture {
    fn new(label: &str, radial: [f64; 2]) -> TestResult<Self> {
        let directory = OwnedDirectory::new(label)?;
        let root = directory.0.join("deployment");
        let site = format!("site:rectified-rig-{label}");
        let cx = context(&root, &site)?;
        let mut deployment = ReferenceDeployment::open(&root, &site, &cx)?;
        let sensors = [
            SensorId::parse("sensor:rectified-east")?,
            SensorId::parse("sensor:rectified-west")?,
        ];
        for (index, sensor) in sensors.iter().enumerate() {
            let path = directory.0.join(format!("source-{index}.mjpeg"));
            fs::write(&path, JPEG)?;
            FileIngestAdapter::ingest(
                FileIngestRequest::new(
                    path,
                    sensor.clone(),
                    StreamId::parse(format!("stream:rectified-{index}"))?,
                )
                .with_receive_time(TimestampNs(1_000_000_000)),
                &cx,
                &mut deployment,
            )?;
        }
        let twin = twin_fixture::twin(&[0.0], None)?;
        let inputs = [21, 22].map(|camera| {
            original_input(
                CameraGeneration {
                    camera,
                    intrinsics: 1,
                    extrinsics: 1,
                },
                false,
            )
        });
        let mut calibration = candidate(&twin, &inputs);
        calibration.cameras[0].distortion = radial;
        let encoded = calibration.encode()?;
        let subject = CalibrationSubject::from_calibration(&calibration, calibration.digest()?);
        let bindings = calibration
            .cameras
            .iter()
            .enumerate()
            .map(|(index, camera)| (camera.name.clone(), sensors[index].clone()))
            .collect::<Vec<_>>();
        let approval = preview_adoption(&deployment, &subject, &bindings)?.approval;
        let retained = adopt(&mut deployment, &subject, &bindings, approval, &cx)?;
        let mut adoptions = [h("unretained east"), h("unretained west")];
        for camera in retained.cameras {
            adoptions[(camera.receipt.camera_handle - 21) as usize] = camera.receipt.digest();
        }
        Ok(Self {
            _directory: directory,
            cx,
            deployment,
            twin,
            calibration,
            encoded,
            inputs,
            sensors,
            adoptions,
        })
    }
    fn resolve(
        &self,
        profile: SceneCalibrationImageProfile,
    ) -> TestResult<RetainedSceneCalibration> {
        let bindings = [0, 1].map(|index| SceneCalibrationBinding {
            camera_handle: 21 + index as u64,
            sensor_id: self.sensors[index].clone(),
            adoption_digest: self.adoptions[index],
            camera_input: &self.inputs[index],
        });
        let request = SceneCalibrationRequest {
            calibration_bytes: &self.encoded,
            calibration_digest: self.calibration.digest()?,
            bindings: &bindings,
        };
        Ok(match profile {
            SceneCalibrationImageProfile::OriginalPinhole => resolve_scene_calibration(
                &self.deployment,
                &request,
                &self.twin,
                &mut WorkBudget::new(WORK),
                &self.cx,
            )?,
            SceneCalibrationImageProfile::NativeRadialRectification => {
                resolve_scene_calibration_for_rectification(
                    &self.deployment,
                    &request,
                    &self.twin,
                    &mut WorkBudget::new(WORK),
                    &self.cx,
                )?
            }
        })
    }
}
fn declarations() -> [AdoptedSceneCameraBinding; 2] {
    [21, 22].map(|camera| AdoptedSceneCameraBinding {
        camera,
        source_object_id: format!("scene-camera-{camera}"),
        image_domain: camera + 100,
        clock: 7,
        privacy_domain: 9,
        validity: [100, 1000],
    })
}

#[test]
fn radial_source_uses_the_explicit_virtual_target_and_never_the_original_constructor() -> TestResult
{
    let f = Fixture::new("radial", [-0.08, 0.01])?;
    let owner = f.resolve(SceneCalibrationImageProfile::NativeRadialRectification)?;
    let declarations = declarations();
    assert!(matches!(
        SceneRig::from_retained_calibration(
            &f.twin,
            &owner,
            (1, 1),
            &declarations,
            &mut WorkBudget::new(WORK)
        ),
        Err(SceneRigError::Unsupported)
    ));
    let rig = SceneRig::from_retained_rectified_calibration(
        &f.twin,
        &owner,
        (1, 1),
        &declarations,
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(rig.cameras().len(), 2);
    for declaration in &declarations {
        let camera = rig
            .camera(declaration.camera)
            .ok_or("target camera")?
            .camera;
        let original = owner.camera(declaration.camera).ok_or("original camera")?;
        assert_eq!(camera.pose, original.pose());
        assert_eq!(camera.intrinsics, original.intrinsics());
        assert_eq!(camera.image_domain, declaration.image_domain);
        assert_eq!(camera.calibration, original.adoption().receipt.adoption);
        assert_eq!(camera.error, None);
        let spec = owner.rectification_spec(declaration.camera, 1.0, LumaRange::Full)?;
        assert_eq!(camera.intrinsics, spec.target);
        let plan = RectificationPlan::compile(spec, &mut WorkBudget::new(20_000_000))?;
        let world = [2.0, 1.0, 10.0];
        let target = camera.pose.project(camera.intrinsics, world)?;
        let source = plan.source_pixel(target)?.ok_or("original image pixel")?;
        let [fx, fy] = original.intrinsics().focal_lengths();
        let [cx, cy] = original.intrinsics().principal_point();
        let x = (target[0] - cx) / fx;
        let y = (target[1] - cy) / fy;
        let q = x * x + y * y;
        let [k1, k2] = original.record().distortion;
        let scale = 1.0 + k1 * q + k2 * q * q;
        for (actual, expected) in source
            .into_iter()
            .zip([fx * x * scale + cx, fy * y * scale + cy])
        {
            assert!((actual - expected).abs() < 1e-12);
        }
    }
    Ok(())
}

#[test]
fn zero_radial_still_requires_matching_resolver_and_rig_profiles() -> TestResult {
    let f = Fixture::new("zero", [0.0, 0.0])?;
    let direct = f.resolve(SceneCalibrationImageProfile::OriginalPinhole)?;
    let rectified = f.resolve(SceneCalibrationImageProfile::NativeRadialRectification)?;
    let declarations = declarations();
    assert!(matches!(
        SceneRig::from_retained_calibration(
            &f.twin,
            &rectified,
            (1, 1),
            &declarations,
            &mut WorkBudget::new(WORK)
        ),
        Err(SceneRigError::Unsupported)
    ));
    assert!(matches!(
        SceneRig::from_retained_rectified_calibration(
            &f.twin,
            &direct,
            (1, 1),
            &declarations,
            &mut WorkBudget::new(WORK)
        ),
        Err(SceneRigError::Unsupported)
    ));
    let a = SceneRig::from_retained_calibration(
        &f.twin,
        &direct,
        (1, 1),
        &declarations,
        &mut WorkBudget::new(WORK),
    )?;
    let b = SceneRig::from_retained_rectified_calibration(
        &f.twin,
        &rectified,
        (1, 1),
        &declarations,
        &mut WorkBudget::new(WORK),
    )?;
    assert_ne!(a.digest(), b.digest());
    assert_eq!(a.cameras(), b.cameras());
    Ok(())
}

#[test]
fn virtual_image_handles_are_bound_without_changing_measured_geometry() -> TestResult {
    let f = Fixture::new("image-handles", [-0.08, 0.01])?;
    let owner = f.resolve(SceneCalibrationImageProfile::NativeRadialRectification)?;
    let mut declarations = declarations();
    let first = SceneRig::from_retained_rectified_calibration(
        &f.twin,
        &owner,
        (1, 1),
        &declarations,
        &mut WorkBudget::new(WORK),
    )?;
    declarations[0].image_domain += 1000;
    let second = SceneRig::from_retained_rectified_calibration(
        &f.twin,
        &owner,
        (1, 1),
        &declarations,
        &mut WorkBudget::new(WORK),
    )?;
    assert_ne!(first.digest(), second.digest());
    let a = first.camera(21).ok_or("first target")?.camera;
    let b = second.camera(21).ok_or("second target")?.camera;
    assert_ne!(a.image_domain, b.image_domain);
    assert_eq!(a.intrinsics, b.intrinsics);
    assert_eq!(a.pose, b.pose);
    Ok(())
}

#[test]
fn explicit_rectified_rig_retains_full_inventory_basis_work_and_cancellation_checks() -> TestResult
{
    let f = Fixture::new("limits", [-0.08, 0.01])?;
    let owner = f.resolve(SceneCalibrationImageProfile::NativeRadialRectification)?;
    let declarations = declarations();
    let make = |rows: &[AdoptedSceneCameraBinding], basis, work: &mut WorkBudget<'_>| {
        SceneRig::from_retained_rectified_calibration(&f.twin, &owner, basis, rows, work)
    };
    assert!(matches!(
        make(&declarations[..1], (1, 1), &mut WorkBudget::new(WORK)),
        Err(SceneRigError::Limit)
    ));
    assert!(matches!(
        make(&declarations, (1, 2), &mut WorkBudget::new(WORK)),
        Err(SceneRigError::Basis)
    ));
    let mut duplicate = declarations.clone();
    duplicate[1].camera = duplicate[0].camera;
    assert!(matches!(
        make(&duplicate, (1, 1), &mut WorkBudget::new(WORK)),
        Err(SceneRigError::Duplicate)
    ));
    let mut measured = WorkBudget::new(WORK);
    make(&declarations, (1, 1), &mut measured)?;
    make(&declarations, (1, 1), &mut WorkBudget::new(measured.used()))?;
    assert!(matches!(
        make(
            &declarations,
            (1, 1),
            &mut WorkBudget::new(measured.used() - 1)
        ),
        Err(SceneRigError::Geometry(GeometryError::BudgetExhausted))
    ));
    let cancelled = AtomicBool::new(true);
    assert!(matches!(
        make(
            &declarations,
            (1, 1),
            &mut WorkBudget::cancellable(WORK, &cancelled)
        ),
        Err(SceneRigError::Geometry(GeometryError::Cancelled))
    ));
    Ok(())
}
