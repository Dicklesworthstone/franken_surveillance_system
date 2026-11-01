#![forbid(unsafe_code)]
//! Real retained adoption/withdrawal authority around controlled synthetic calibration geometry.
//! The small camera candidate is authored test data, not a claim that an optimizer measured a
//! physical site. Deployment, source ingestion, authority receipts and native triangulation use
//! the production owners. No runtime, custody reader or current-adoption check is replaced.

use super::*;
use crate::ingest::calibration_adoption::{CalibrationSubject, adopt, preview_adoption};
use crate::ingest::calibration_invalidation::{
    InvalidationReason, InvalidationRequest, invalidate, preview_invalidation,
};
use crate::ingest::site_calibration::{CalibrationInput, FrameInput, FramePolicy, SeedMode};
use crate::ingest::{FileIngestAdapter, FileIngestRequest};
use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, OperationId, StreamId, TimestampNs};
use fss_geometry::triangulation::TriangulationOptions;
use fss_geometry::{BundleParameter, CameraGeneration};
use fss_twin::localization::native::descriptor_domain;
use fss_twin::multiview::{CommonPointMotion, FusionInput, FusionRequest, fuse_scene_point};
use fss_twin::{ContactObservation, TrackingCamera};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

#[path = "../../../fss-twin/tests/common/mod.rs"]
mod twin_fixture;

const JPEG: &[u8] = include_bytes!("../../../fss-codec-mjpeg/tests/fixtures/gray.jpg");
const WORK: u64 = 10_000_000;
type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

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
                "fss-scene-calibration-{tag}-{}-{attempt}",
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
    directory: OwnedDirectory,
    site: String,
    cx: ReplayCx,
    deployment: ReferenceDeployment,
    twin: PropertyTwin,
    sensors: [SensorId; 2],
    inputs: [Vec<u8>; 2],
    calibration: SiteCalibration,
    encoded: Vec<u8>,
    adoptions: [ContentDigest; 2],
}
impl Fixture {
    fn new(tag: &str, adopt_now: bool) -> TestResult<Self> {
        let directory = OwnedDirectory::new(tag)?;
        let site = format!("site:scene-calibration-{tag}");
        let root = directory.0.join("deployment");
        let cx = context(&root, &site)?;
        let mut deployment = ReferenceDeployment::open(&root, &site, &cx)?;
        let sensors = [
            SensorId::parse("sensor:scene-east")?,
            SensorId::parse("sensor:scene-west")?,
        ];
        for (i, sensor) in sensors.iter().enumerate() {
            let path = directory.0.join(format!("source-{i}.mjpeg"));
            fs::write(&path, JPEG)?;
            let request = FileIngestRequest::new(
                path,
                sensor.clone(),
                StreamId::parse(format!("stream:scene-{i}"))?,
            )
            .with_receive_time(TimestampNs(1_000_000_000));
            FileIngestAdapter::ingest(request, &cx, &mut deployment)?;
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
        let calibration = candidate(&twin, &inputs);
        let encoded = calibration.encode()?;
        let mut fixture = Self {
            directory,
            site,
            cx,
            deployment,
            twin,
            sensors,
            inputs,
            calibration,
            encoded,
            adoptions: [h("unretained east receipt"), h("unretained west receipt")],
        };
        if adopt_now {
            fixture.adopt_cameras(&[0, 1])?;
        }
        Ok(fixture)
    }
    fn adopt_cameras(&mut self, indices: &[usize]) -> TestResult {
        self.encoded = self.calibration.encode()?;
        let subject =
            CalibrationSubject::from_calibration(&self.calibration, self.calibration.digest()?);
        let bindings: Vec<_> = indices
            .iter()
            .map(|&i| {
                (
                    self.calibration.cameras[i].name.clone(),
                    self.sensors[i].clone(),
                )
            })
            .collect();
        let approval = preview_adoption(&self.deployment, &subject, &bindings)?.approval;
        let retained = adopt(
            &mut self.deployment,
            &subject,
            &bindings,
            approval,
            &self.cx,
        )?;
        for camera in retained.cameras {
            let slot = (camera.receipt.camera_handle - 21) as usize;
            self.adoptions[slot] = camera.receipt.digest();
        }
        Ok(())
    }
    fn bindings(&self) -> [SceneCalibrationBinding<'_>; 2] {
        [0, 1].map(|i| SceneCalibrationBinding {
            camera_handle: 21 + i as u64,
            sensor_id: self.sensors[i].clone(),
            adoption_digest: self.adoptions[i],
            camera_input: &self.inputs[i],
        })
    }
    fn resolve(&self) -> Result<RetainedSceneCalibration> {
        self.resolve_budget(&mut WorkBudget::new(WORK))
    }
    fn resolve_budget(&self, work: &mut WorkBudget<'_>) -> Result<RetainedSceneCalibration> {
        let bindings = self.bindings();
        resolve_scene_calibration(
            &self.deployment,
            &SceneCalibrationRequest {
                calibration_bytes: &self.encoded,
                calibration_digest: self.calibration.digest()?,
                bindings: &bindings,
            },
            &self.twin,
            work,
            &self.cx,
        )
    }
    fn withdraw_east(&mut self) -> TestResult<ContentDigest> {
        let request = InvalidationRequest {
            camera_handle: 21,
            adoption_digest: self.adoptions[0],
            reason: InvalidationReason::CameraMoved,
            evidence: None,
        };
        let approval = preview_invalidation(&self.deployment, &request)?.approval;
        Ok(
            invalidate(&mut self.deployment, &request, approval, &self.cx)?
                .receipt
                .digest(),
        )
    }
}

#[test]
fn current_adopted_geometry_drives_native_stereo_with_complete_original_basis() -> TestResult {
    let f = Fixture::new("geometry", true)?;
    let anchor = f.deployment.current_anchor().clone();
    let owner = f.resolve()?;
    assert_eq!(owner.record(), &f.calibration);
    assert_eq!(owner.calibration_identity(), f.calibration.digest()?);
    assert_eq!(
        owner.calibration_file_digest(),
        ContentDigest::sha256(&f.encoded)
    );
    assert_ne!(
        owner.calibration_identity(),
        owner.calibration_file_digest()
    );
    assert_eq!(owner.twin_package().bytes(), f.twin.digest());
    assert_eq!(owner.twin_source().bytes(), f.twin.source_scene_digest());
    assert_eq!(
        owner.input_bytes(),
        (f.encoded.len() + f.inputs.iter().map(Vec::len).sum::<usize>()) as u64
    );
    assert_eq!(
        owner.source_bytes(),
        owner.input_bytes() + owner.authority_read_bytes()
    );
    assert!(owner.authority_read_bytes() > 0);
    assert!(owner.authority_read_bytes() <= owner.authority_reserved_bytes());
    assert_eq!(owner.anchor(), &anchor);
    let mut reversed = f.bindings();
    reversed.reverse();
    let reordered = resolve_scene_calibration(
        &f.deployment,
        &SceneCalibrationRequest {
            calibration_bytes: &f.encoded,
            calibration_digest: f.calibration.digest()?,
            bindings: &reversed,
        },
        &f.twin,
        &mut WorkBudget::new(WORK),
        &f.cx,
    )?;
    assert_eq!(owner.digest(), reordered.digest());
    assert_eq!(
        owner
            .cameras()
            .iter()
            .map(|c| c.record().identity.camera)
            .collect::<Vec<_>>(),
        [21, 22]
    );
    let mut views = Vec::new();
    for (i, camera) in owner.cameras().iter().enumerate() {
        assert_eq!(camera.record(), &f.calibration.cameras[i]);
        assert_eq!(
            camera.image_basis().input_digest,
            ContentDigest::sha256(&f.inputs[i])
        );
        assert_eq!(
            camera.image_basis().image.image_domain,
            h("original pinhole image mode").bytes()
        );
        assert_eq!(camera.image_basis().image.dimensions, [96, 96]);
        assert_eq!(camera.image_basis().encoded_frame, None);
        assert_eq!(camera.adoption().receipt.sensor_id, f.sensors[i]);
        let pixel = if i == 0 { [56.0, 56.0] } else { [40.0, 56.0] };
        assert_eq!(
            camera
                .pose()
                .project(camera.intrinsics(), [0.5, 0.5, 5.0])?,
            pixel
        );
        views.push(FusionInput {
            camera: TrackingCamera {
                geometry: f.twin.basis(),
                camera: 21 + i as u64,
                calibration: camera.adoption().receipt.adoption,
                image_domain: 1,
                clock: 1,
                validity: [0, 2000],
                pose: camera.pose(),
                intrinsics: camera.intrinsics(),
                error: None,
            },
            observation: ContactObservation {
                evidence: h(&format!("stereo source {i}")).bytes(),
                track: 1,
                camera: 21 + i as u64,
                exposure: 1 + i as u64,
                image_domain: 1,
                clock: 1,
                capture: [100, 110],
                pixel_min: pixel,
                pixel_max: pixel,
                visible_contact: true,
            },
            privacy_domain: 1,
            sigma_pixels: 0.5,
        });
    }
    let solved = fuse_scene_point(
        &f.twin,
        &views,
        FusionRequest {
            association_evidence: h("authored stereo correspondence").bytes(),
            privacy_domain: 1,
            reference_time_ns: 105,
            max_capture_span_ns: 10,
            motion: CommonPointMotion::Static,
            triangulation: TriangulationOptions::default(),
        },
        &mut WorkBudget::new(WORK),
    )?;
    for (actual, expected) in solved.estimate().position.iter().zip([0.5, 0.5, 5.0]) {
        assert!((actual - expected).abs() < 1e-8);
    }
    assert!(
        solved
            .inputs()
            .iter()
            .all(|input| input.camera.error.is_none())
    );
    assert_eq!(f.deployment.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn frame_calibration_recovers_exact_metadata_mode_and_encoded_frame_lineage() -> TestResult {
    let mut f = Fixture::new("frame-mode", false)?;
    f.calibration.frame_policy = Some(FramePolicy::current());
    for i in 0..2 {
        f.inputs[i] = original_input(f.calibration.cameras[i].identity, true);
        f.calibration.cameras[i].observations = ContentDigest::sha256(JPEG);
        f.calibration.cameras[i].input = CalibrationInput::Frame(FrameInput {
            metadata: ContentDigest::sha256(&f.inputs[i]),
            luma: h("original frame luma"),
            interpretation: ComponentInterpretation::Grayscale,
            extracted_features: 32,
            atlas_matches: 8,
            tie_observations: 0,
        });
    }
    f.adopt_cameras(&[0, 1])?;
    assert_eq!(&f.encoded[..8], b"FSSCAL02");
    let owner = f.resolve()?;
    let image = owner.camera(21).ok_or("missing east camera")?.image_basis();
    assert_eq!(image.input_digest, ContentDigest::sha256(&f.inputs[0]));
    assert_eq!(image.encoded_frame, Some(ContentDigest::sha256(JPEG)));
    assert_eq!(image.image.pixels, h("original frame luma").bytes());
    assert_eq!(
        image.interpretation,
        Some(ComponentInterpretation::Grayscale)
    );
    f.inputs[0].push(b'\n');
    assert!(matches!(
        f.resolve(),
        Err(SceneCalibrationError::Calibration(_))
    ));
    Ok(())
}

#[test]
fn adopted_frame_and_atlas_provenance_never_relabels_another_hash_algorithm() -> TestResult {
    for invalid in [
        ContentDigest::new(
            DigestAlgorithm::Blake3,
            h("other algorithm identity").bytes(),
        ),
        raw([0; 32]),
    ] {
        for field in 0..5 {
            let mut f = Fixture::new("provenance-algorithm", false)?;
            f.calibration.frame_policy = Some(FramePolicy::current());
            for i in 0..2 {
                f.inputs[i] = original_input(f.calibration.cameras[i].identity, true);
                f.calibration.cameras[i].observations = ContentDigest::sha256(JPEG);
                f.calibration.cameras[i].input = CalibrationInput::Frame(FrameInput {
                    metadata: ContentDigest::sha256(&f.inputs[i]),
                    luma: h("original frame luma"),
                    interpretation: ComponentInterpretation::Grayscale,
                    extracted_features: 32,
                    atlas_matches: 8,
                    tie_observations: 0,
                });
            }
            match field {
                0 => f.calibration.atlas_package = invalid,
                1 => f.calibration.atlas_provenance = invalid,
                2 => f.calibration.cameras[0].observations = invalid,
                _ => {
                    let CalibrationInput::Frame(mut frame) = f.calibration.cameras[0].input else {
                        return Err("frame fixture is not a frame".into());
                    };
                    if field == 3 {
                        frame.metadata = invalid;
                    } else {
                        frame.luma = invalid;
                    }
                    f.calibration.cameras[0].input = CalibrationInput::Frame(frame);
                }
            }
            // The existing generic FSSCAL codec and real adoption owner can retain this
            // candidate. New scene admission must reject it rather than relabel its bytes.
            f.adopt_cameras(&[0, 1])?;
            let anchor = f.deployment.current_anchor().clone();
            assert_eq!(
                SiteCalibration::decode(&f.encoded, Some(f.calibration.digest()?))?.0,
                f.calibration
            );
            assert!(matches!(
                f.resolve(),
                Err(SceneCalibrationError::InvalidInput(_))
            ));
            assert_eq!(f.deployment.current_anchor(), &anchor);
        }
    }
    Ok(())
}

#[test]
fn absent_authority_and_duplicate_physical_selections_never_fall_back_to_nominal() -> TestResult {
    let mut f = Fixture::new("required-adoption", false)?;
    assert!(matches!(
        f.resolve(),
        Err(SceneCalibrationError::Unadopted(21))
    ));
    f.adopt_cameras(&[0, 1])?;
    let mut bindings = f.bindings();
    let identity = f.calibration.digest()?;
    let resolve = |bindings: &[SceneCalibrationBinding<'_>]| {
        resolve_scene_calibration(
            &f.deployment,
            &SceneCalibrationRequest {
                calibration_bytes: &f.encoded,
                calibration_digest: identity,
                bindings,
            },
            &f.twin,
            &mut WorkBudget::new(WORK),
            &f.cx,
        )
    };
    assert!(matches!(
        resolve(&[]),
        Err(SceneCalibrationError::InvalidInput(_))
    ));
    bindings[1].sensor_id = bindings[0].sensor_id.clone();
    assert!(matches!(
        resolve(&bindings),
        Err(SceneCalibrationError::InvalidInput(_))
    ));
    bindings = f.bindings();
    bindings[1].camera_handle = bindings[0].camera_handle;
    assert!(matches!(
        resolve(&bindings),
        Err(SceneCalibrationError::InvalidInput(_))
    ));
    let too_many = vec![bindings[0].clone(); MAX_SCENE_CALIBRATION_CAMERAS + 1];
    assert!(matches!(
        resolve(&too_many),
        Err(SceneCalibrationError::InvalidInput(_))
    ));
    let mut one = f.bindings();
    one[0].sensor_id = f.sensors[1].clone();
    assert!(matches!(
        resolve(&one[..1]),
        Err(SceneCalibrationError::BasisMismatch(_))
    ));
    one = f.bindings();
    one[0].adoption_digest = h("another receipt");
    assert!(matches!(
        resolve(&one[..1]),
        Err(SceneCalibrationError::BasisMismatch(_))
    ));
    one[0].adoption_digest = raw([0; 32]);
    assert!(matches!(
        resolve(&one[..1]),
        Err(SceneCalibrationError::InvalidInput(_))
    ));
    Ok(())
}

#[test]
fn supersession_refuses_both_old_resolution_and_final_revalidation() -> TestResult {
    let mut f = Fixture::new("supersession", true)?;
    let owner = f.resolve()?;
    let old_bytes = f.encoded.clone();
    let old_identity = f.calibration.digest()?;
    let old_input = f.inputs[0].clone();
    let old_receipt = f.adoptions[0];
    f.calibration.cameras[0].identity.extrinsics = 2;
    f.inputs[0] = original_input(f.calibration.cameras[0].identity, false);
    f.calibration.cameras[0].observations = ContentDigest::sha256(&f.inputs[0]);
    f.calibration.cameras[0].translation[0] = 0.25;
    f.adopt_cameras(&[0])?;
    assert!(matches!(
        owner.revalidate(&f.deployment, &f.cx, &mut WorkBudget::new(WORK)),
        Err(SceneCalibrationError::Adoption(_))
    ));
    let bindings = [SceneCalibrationBinding {
        camera_handle: 21,
        sensor_id: f.sensors[0].clone(),
        adoption_digest: old_receipt,
        camera_input: &old_input,
    }];
    assert!(matches!(
        resolve_scene_calibration(
            &f.deployment,
            &SceneCalibrationRequest {
                calibration_bytes: &old_bytes,
                calibration_digest: old_identity,
                bindings: &bindings,
            },
            &f.twin,
            &mut WorkBudget::new(WORK),
            &f.cx
        ),
        Err(SceneCalibrationError::Adoption(_))
    ));
    Ok(())
}

#[test]
fn owner_withdrawal_is_sticky_and_withdrawal_custody_cannot_be_ignored() -> TestResult {
    let mut f = Fixture::new("withdrawal", true)?;
    let owner = f.resolve()?;
    let invalidation = f.withdraw_east()?;
    assert!(matches!(
        f.resolve(),
        Err(SceneCalibrationError::Adoption(_))
    ));
    assert!(matches!(
        owner.revalidate(&f.deployment, &f.cx, &mut WorkBudget::new(WORK)),
        Err(SceneCalibrationError::Adoption(_))
    ));
    let anchor = f.deployment.current_anchor().clone();
    let path = f.deployment.publisher().spool().object_path(invalidation);
    let bytes = fs::read(&path)?;
    fs::remove_file(&path)?;
    assert!(matches!(f.resolve(), Err(SceneCalibrationError::Custody)));
    fs::write(&path, &bytes)?;
    assert!(matches!(
        f.resolve(),
        Err(SceneCalibrationError::Adoption(_))
    ));
    assert_eq!(f.deployment.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn corrupt_or_missing_adoption_receipts_are_refused_without_repair_or_renewed_budget() -> TestResult
{
    let f = Fixture::new("receipt-custody", true)?;
    let owner = f.resolve()?;
    let anchor = f.deployment.current_anchor().clone();
    for digest in f.adoptions {
        let path = f.deployment.publisher().spool().object_path(digest);
        let bytes = fs::read(&path)?;
        let mut corrupt = bytes.clone();
        *corrupt.last_mut().ok_or("empty receipt fixture")? ^= 1;
        fs::write(&path, &corrupt)?;
        let before = owner.authority_reserved_bytes();
        assert!(
            owner
                .revalidate(&f.deployment, &f.cx, &mut WorkBudget::new(WORK))
                .is_err()
        );
        assert!(owner.authority_reserved_bytes() > before);
        assert_eq!(fs::read(&path)?, corrupt);
        fs::remove_file(&path)?;
        let before = owner.authority_reserved_bytes();
        assert!(matches!(
            owner.revalidate(&f.deployment, &f.cx, &mut WorkBudget::new(WORK)),
            Err(SceneCalibrationError::Custody)
        ));
        assert!(owner.authority_reserved_bytes() > before);
        assert!(!path.exists());
        fs::write(&path, &bytes)?;
        owner.revalidate(&f.deployment, &f.cx, &mut WorkBudget::new(WORK))?;
    }
    assert_eq!(f.deployment.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn original_text_tuple_dimensions_descriptor_and_semantic_identity_are_exact() -> TestResult {
    let f = Fixture::new("input-pins", true)?;
    let mut altered = f.inputs[0].clone();
    altered.push(b'\n');
    let mut bindings = f.bindings();
    bindings[0].camera_input = &altered;
    assert!(matches!(
        resolve_scene_calibration(
            &f.deployment,
            &SceneCalibrationRequest {
                calibration_bytes: &f.encoded,
                calibration_digest: f.calibration.digest()?,
                bindings: &bindings,
            },
            &f.twin,
            &mut WorkBudget::new(WORK),
            &f.cx
        ),
        Err(SceneCalibrationError::Calibration(_))
    ));
    for (from, to) in [
        ("camera 21 1 1".to_owned(), "camera 21 1 2".to_owned()),
        ("image 96 96".to_owned(), "image 95 96".to_owned()),
        (
            raw(descriptor_domain()).to_string(),
            h("foreign descriptors").to_string(),
        ),
    ] {
        let mut bad = Fixture::new("header-mismatch", false)?;
        bad.inputs[0] = String::from_utf8(bad.inputs[0].clone())?
            .replace(&from, &to)
            .into_bytes();
        bad.calibration.cameras[0].observations = ContentDigest::sha256(&bad.inputs[0]);
        bad.adopt_cameras(&[0, 1])?;
        assert!(matches!(
            bad.resolve(),
            Err(SceneCalibrationError::Calibration(_))
        ));
    }
    let good = f.bindings();
    for identity in [
        ContentDigest::sha256(&f.encoded),
        h("wrong calibration semantic identity"),
    ] {
        assert!(matches!(
            resolve_scene_calibration(
                &f.deployment,
                &SceneCalibrationRequest {
                    calibration_bytes: &f.encoded,
                    calibration_digest: identity,
                    bindings: &good,
                },
                &f.twin,
                &mut WorkBudget::new(WORK),
                &f.cx
            ),
            Err(SceneCalibrationError::Calibration(_))
        ));
    }
    let mut encoded = f.encoded.clone();
    encoded[20] ^= 1;
    assert!(matches!(
        resolve_scene_calibration(
            &f.deployment,
            &SceneCalibrationRequest {
                calibration_bytes: &encoded,
                calibration_digest: f.calibration.digest()?,
                bindings: &good,
            },
            &f.twin,
            &mut WorkBudget::new(WORK),
            &f.cx
        ),
        Err(SceneCalibrationError::Calibration(_))
    ));
    Ok(())
}

#[test]
fn twin_package_and_original_scene_are_separate_required_pins() -> TestResult {
    for source in [false, true] {
        let mut f = Fixture::new("twin-pins", false)?;
        if source {
            f.calibration.twin_source = h("another original scene");
        } else {
            f.calibration.twin_package = h("another twin package");
        }
        f.adopt_cameras(&[0, 1])?;
        assert!(matches!(
            f.resolve(),
            Err(SceneCalibrationError::BasisMismatch(_))
        ));
    }
    Ok(())
}

#[test]
fn actual_receipt_name_twin_and_full_camera_tuple_must_match_the_decoded_candidate() -> TestResult {
    for mismatch in 0..3 {
        let mut f = Fixture::new("receipt-tuple", false)?;
        let mut subject =
            CalibrationSubject::from_calibration(&f.calibration, f.calibration.digest()?);
        subject.cameras.truncate(1);
        match mismatch {
            0 => subject.cameras[0].0 = "east-renamed".into(),
            1 => subject.twin_package = h("receipt names another twin"),
            _ => subject.cameras[0].1.extrinsics = 2,
        }
        let bindings = [(subject.cameras[0].0.clone(), f.sensors[0].clone())];
        let approval = preview_adoption(&f.deployment, &subject, &bindings)?.approval;
        let retained = adopt(&mut f.deployment, &subject, &bindings, approval, &f.cx)?;
        f.adoptions[0] = retained.cameras[0].receipt.digest();
        let selected = f.bindings();
        let refused = resolve_scene_calibration(
            &f.deployment,
            &SceneCalibrationRequest {
                calibration_bytes: &f.encoded,
                calibration_digest: f.calibration.digest()?,
                bindings: &selected[..1],
            },
            &f.twin,
            &mut WorkBudget::new(WORK),
            &f.cx,
        );
        assert!(matches!(
            refused,
            Err(SceneCalibrationError::BasisMismatch(_) | SceneCalibrationError::Adoption(_))
        ));
    }
    Ok(())
}

#[test]
fn radial_calibration_is_explicitly_refused_without_inventing_rectification() -> TestResult {
    let mut f = Fixture::new("radial", false)?;
    f.calibration.cameras[1].distortion = [0.01, -0.001];
    f.adopt_cameras(&[0, 1])?;
    let anchor = f.deployment.current_anchor().clone();
    assert!(matches!(
        f.resolve(),
        Err(SceneCalibrationError::Unsupported(_))
    ));
    assert_eq!(f.deployment.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn work_and_authority_allowances_are_complete_and_never_reset_on_revalidation() -> TestResult {
    let f = Fixture::new("work", true)?;
    let mut measured = WorkBudget::new(WORK);
    let owner = f.resolve_budget(&mut measured)?;
    let used = measured.used();
    assert!(used > f.encoded.len() as u64);
    f.resolve_budget(&mut WorkBudget::new(used))?;
    assert!(matches!(
        f.resolve_budget(&mut WorkBudget::new(used - 1)),
        Err(SceneCalibrationError::Geometry(
            GeometryError::BudgetExhausted
        ))
    ));
    let before_bytes = owner.authority_read_bytes();
    let mut revalidation = WorkBudget::new(WORK);
    owner.revalidate(&f.deployment, &f.cx, &mut revalidation)?;
    let used = revalidation.used();
    owner.revalidate(&f.deployment, &f.cx, &mut WorkBudget::new(used))?;
    assert!(matches!(
        owner.revalidate(&f.deployment, &f.cx, &mut WorkBudget::new(used - 1)),
        Err(SceneCalibrationError::Geometry(
            GeometryError::BudgetExhausted
        ))
    ));
    assert!(owner.authority_read_bytes() >= before_bytes * 3);
    let bytes = owner.authority_read_bytes();
    owner
        .reads
        .reserved
        .set(MAX_SCENE_CALIBRATION_AUTHORITY_BYTES);
    assert!(matches!(
        owner.revalidate(&f.deployment, &f.cx, &mut WorkBudget::new(WORK)),
        Err(SceneCalibrationError::Limit)
    ));
    assert_eq!(owner.authority_read_bytes(), bytes);
    assert_eq!(
        owner.authority_reserved_bytes(),
        MAX_SCENE_CALIBRATION_AUTHORITY_BYTES
    );
    let cancelled = AtomicBool::new(true);
    assert!(matches!(
        f.resolve_budget(&mut WorkBudget::cancellable(WORK, &cancelled)),
        Err(SceneCalibrationError::Cancelled)
    ));
    Ok(())
}

#[test]
fn cancellation_before_after_custody_and_before_return_leaves_authority_unchanged() -> TestResult {
    for stage in [
        "scene_calibration:begin",
        "scene_calibration:read",
        "scene_calibration:read_complete",
        "scene_calibration:resolved",
    ] {
        let f = Fixture::new("cancel", true)?;
        let anchor = f.deployment.current_anchor().clone();
        f.cx.set_cancel_at_checkpoint(stage);
        assert!(matches!(f.resolve(), Err(SceneCalibrationError::Cancelled)));
        assert_eq!(f.deployment.current_anchor(), &anchor);
    }
    let f = Fixture::new("cancel-final", true)?;
    let owner = f.resolve()?;
    let anchor = f.deployment.current_anchor().clone();
    f.cx.set_cancel_at_checkpoint("scene_calibration:revalidated");
    assert!(matches!(
        owner.revalidate(&f.deployment, &f.cx, &mut WorkBudget::new(WORK)),
        Err(SceneCalibrationError::Cancelled)
    ));
    assert_eq!(f.deployment.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn unrelated_appends_preserve_the_selection_but_not_cross_site_authority() -> TestResult {
    let mut f = Fixture::new("unrelated", true)?;
    let owner = f.resolve()?;
    let before = owner.anchor().clone();
    let path = f.directory.0.join("unrelated.mjpeg");
    fs::write(&path, JPEG)?;
    let request = FileIngestRequest::new(
        path,
        SensorId::parse("sensor:unrelated")?,
        StreamId::parse("stream:unrelated")?,
    )
    .with_receive_time(TimestampNs(2_000_000_000));
    FileIngestAdapter::ingest(request, &f.cx, &mut f.deployment)?;
    assert!(f.deployment.current_anchor().commit_sequence > before.commit_sequence);
    owner.revalidate(&f.deployment, &f.cx, &mut WorkBudget::new(WORK))?;
    assert_eq!(owner.digest(), f.resolve()?.digest());
    let current = f.deployment.current_anchor().clone();
    let root = f.deployment.root().to_path_buf();
    // The production owner holds the exclusive deployment lock for its complete lifetime.
    // Release it before testing restart reconstruction of the same retained authority.
    drop(f.deployment);
    let reopened = ReferenceDeployment::open(&root, &f.site, &f.cx)?;
    owner.revalidate(&reopened, &f.cx, &mut WorkBudget::new(WORK))?;
    assert_eq!(reopened.current_anchor(), &current);
    let other = Fixture::new("different-site", true)?;
    assert!(matches!(
        owner.revalidate(&other.deployment, &other.cx, &mut WorkBudget::new(WORK)),
        Err(SceneCalibrationError::BasisMismatch(_))
    ));
    Ok(())
}
