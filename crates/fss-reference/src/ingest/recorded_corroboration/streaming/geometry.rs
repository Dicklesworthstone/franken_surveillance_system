#![forbid(unsafe_code)]
//! Optional conservative geometry support for retained whole-recording corroboration.
//!
//! The owner homography still projects actual observations. This additional screen can only
//! remove support: it never establishes physical camera currency, detector recall, independent
//! evidence, an absence certificate, or a calibrated event probability.

use std::collections::BTreeSet;
use std::sync::Arc;

use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, ContractError, SensorId};
use fss_geometry::{CameraGeneration, WorkBudget};
use fss_twin::PropertyTwin;

use super::{CorroborationDependencies, CorroborationError, CorroborationPlan, Result, checkpoint};
use crate::ingest::calibration_adoption::{adopted_currency, retained_adoptions};
use crate::ingest::calibration_coverage::{
    CALIBRATION_COVERAGE_POLICY, CalibrationCoverageInput, CalibrationSampleRelation,
    MAX_CALIBRATION_COVERAGE_WORK, assess_calibration_coverage, calibrated_camera_model,
};
use crate::ingest::ground_visibility::{
    CameraPose, MAX_VISIBILITY_WORK, POSE_SENSITIVITY_POLICY, SceneMesh, VISIBILITY_POLICY,
    VisibilityCamera, VisibilityPolicy, assess_pose_robustness, assess_samples, ground_samples,
    import_scene_mesh, pose_matches_homography, rectangle,
};
use crate::ingest::privacy_mask::MaskBinding;
use crate::ingest::recorded_corroboration::{FailureDomainDeclaration, hex, json_string};
use crate::ingest::recorded_coverage::{GenerationCurrency, PoseProvenance};
use crate::ingest::site_calibration::SiteCalibration;
use crate::{ReferenceDeployment, ReplayCx};

/// Fixed custody bound for an optional neutral scene package.
pub const MAX_LONG_CORROBORATION_SCENE_BYTES: usize = 64 * 1024 * 1024;
const MAX_CALIBRATION_BYTES: usize = 4 * 1024 * 1024;
const MAX_GEOMETRY_RECIPE_BYTES: usize = 4096;
/// Maximum optional per-camera diagnostic receipt (no pixels or mesh are embedded).
pub(crate) const MAX_GEOMETRY_RECEIPT_BYTES: usize = 64 * 1024;
pub(crate) const GEOMETRY_POLICY: &[u8] = b"fss.long-corroboration.geometry-support.v1:\
owner-homography-remains-observation-projection:exact-pose-homography-grid-agreement:\
native-privacy-aware-frustum-and-optional-mesh-visibility:\
calibration-pose-sigma-and-full-camera-linearized-abstention:\
whole-camera-shared-geometry-work-budget:preserve-unsupported-observations:\
exclude-unsupported-zone-from-association:shared-calibration-and-mesh-common-causes:\
exact-archive-and-pose-provenance:current-adoption-before-analysis-and-publication:\
no-physical-currency:no-absence:no-probability:no-independent-geometry-vote";

fn invalid(camera: &str, reason: &'static str) -> CorroborationError {
    CorroborationError::InvalidPose {
        camera: camera.to_owned(),
        reason,
    }
}

/// Exact optional geometry owner inputs; archives are retained as separate custody children.
/// Omitting this extension preserves every historical recipe and event identity.
#[derive(Clone, Debug)]
pub struct LongCorroborationGeometryRecipe {
    plan: ContentDigest,
    policy: VisibilityPolicy,
    poses: [Option<CameraPose>; 2],
    provenance: [Option<PoseProvenance>; 2],
    calibration: Option<(ContentDigest, ContentDigest)>,
    scene: Option<(ContentDigest, ContentDigest)>,
}

impl LongCorroborationGeometryRecipe {
    /// Canonical immutable configuration, including the exact native screening semantics.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.bytes(GEOMETRY_POLICY);
        e.text(VISIBILITY_POLICY);
        e.text(POSE_SENSITIVITY_POLICY);
        e.text(CALIBRATION_COVERAGE_POLICY);
        e.u64(MAX_VISIBILITY_WORK);
        e.u64(MAX_CALIBRATION_COVERAGE_WORK);
        e.digest(self.plan);
        e.u32(self.policy.grid);
        e.u32(self.policy.threshold_ppm);
        for (pose, provenance) in self.poses.iter().zip(self.provenance) {
            e.bool(pose.is_some());
            if let Some(pose) = pose {
                for size in pose.intrinsics.dimensions() {
                    e.u32(size);
                }
                for bits in pose.parameter_bits() {
                    e.u64(bits);
                }
            }
            e.bool(provenance.is_some());
            if let Some(provenance) = provenance {
                encode_provenance(&mut e, provenance);
            }
        }
        for archive in [self.calibration, self.scene] {
            e.bool(archive.is_some());
            if let Some((identity, object)) = archive {
                e.digest(identity);
                e.digest(object);
            }
        }
        e.finish()
    }

    /// Exact identity of the geometry component, independent of source decoding.
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }

    pub(crate) fn from_bytes(bytes: &[u8], plan: &CorroborationPlan) -> Result<Self> {
        if bytes.len() > MAX_GEOMETRY_RECIPE_BYTES {
            return Err(CorroborationError::Limit);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != GEOMETRY_POLICY
            || d.text()? != VISIBILITY_POLICY
            || d.text()? != POSE_SENSITIVITY_POLICY
            || d.text()? != CALIBRATION_COVERAGE_POLICY
            || d.u64()? != MAX_VISIBILITY_WORK
            || d.u64()? != MAX_CALIBRATION_COVERAGE_WORK
        {
            return Err(CorroborationError::InvalidPlan(
                "unknown geometry support policy",
            ));
        }
        let identity = d.digest()?;
        let policy = VisibilityPolicy {
            grid: d.u32()?,
            threshold_ppm: d.u32()?,
        };
        let mut poses = [None; 2];
        let mut provenance = [None; 2];
        for index in 0..2 {
            if d.bool()? {
                let dimensions = [d.u32()?, d.u32()?];
                let mut values = [0.0; 16];
                for value in &mut values {
                    *value = f64::from_bits(d.u64()?);
                }
                poses[index] = Some(CameraPose::from_parameters(
                    dimensions,
                    [values[0], values[1], values[2], values[3]],
                    [
                        [values[4], values[5], values[6]],
                        [values[7], values[8], values[9]],
                        [values[10], values[11], values[12]],
                    ],
                    [values[13], values[14], values[15]],
                )?);
            }
            if d.bool()? {
                provenance[index] = Some(decode_provenance(&mut d)?);
            }
        }
        let mut archives = [None; 2];
        for archive in &mut archives {
            if d.bool()? {
                *archive = Some((d.digest()?, d.digest()?));
            }
        }
        d.ensure_finished()?;
        let value = Self {
            plan: identity,
            policy,
            poses,
            provenance,
            calibration: archives[0],
            scene: archives[1],
        };
        value.validate(plan)?;
        if value.to_bytes() != bytes {
            return Err(ContractError::NonCanonicalOrdering.into());
        }
        Ok(value)
    }

    fn validate(&self, plan: &CorroborationPlan) -> Result<()> {
        self.policy.validate()?;
        if self.plan != plan.digest() {
            return Err(ContractError::DigestMismatch.into());
        }
        let mut uses_calibration = false;
        for index in 0..2 {
            if self.poses[index].is_some() != self.provenance[index].is_some() {
                return Err(invalid(
                    &plan.cameras[index].name,
                    "pose and provenance disagree",
                ));
            }
            if let Some(provenance) = self.provenance[index] {
                provenance.validate()?;
                if let PoseProvenance::SiteCalibration {
                    calibration_digest,
                    currency,
                    ..
                } = provenance
                {
                    if currency.adoption_receipt().is_some_and(|receipt| {
                        receipt.algorithm() != fss_core::DigestAlgorithm::Sha256
                            || receipt.bytes() == [0; 32]
                    }) {
                        return Err(ContractError::InvalidIdentifier.into());
                    }
                    uses_calibration = true;
                    if self.calibration.map(|value| value.0) != Some(calibration_digest) {
                        return Err(invalid(
                            &plan.cameras[index].name,
                            "calibration identity differs from pose provenance",
                        ));
                    }
                }
            }
        }
        if uses_calibration != self.calibration.is_some() {
            return Err(CorroborationError::InvalidPlan(
                "unused or missing geometry calibration",
            ));
        }
        for (a, b) in [self.calibration, self.scene].into_iter().flatten() {
            for digest in [a, b] {
                if digest.algorithm() != fss_core::DigestAlgorithm::Sha256
                    || digest.bytes() == [0; 32]
                {
                    return Err(ContractError::InvalidIdentifier.into());
                }
            }
        }
        if self.to_bytes().len() > MAX_GEOMETRY_RECIPE_BYTES {
            return Err(CorroborationError::Limit);
        }
        Ok(())
    }

    /// Archive object digests and strict per-object byte ceilings required for cold replay.
    pub fn archive_objects(&self) -> Vec<(ContentDigest, usize)> {
        let mut objects = Vec::new();
        if let Some((_, object)) = self.calibration {
            objects.push((object, MAX_CALIBRATION_BYTES));
        }
        if let Some((object, _)) = self.scene {
            objects.push((object, MAX_LONG_CORROBORATION_SCENE_BYTES));
        }
        objects
    }

    /// Shared supplied geometry is a common cause, never an independent corroborating vote.
    pub(crate) fn dependencies(
        &self,
        plan: &CorroborationPlan,
        owner: &CorroborationDependencies,
    ) -> Result<CorroborationDependencies> {
        let mut declarations = owner.declarations().to_vec();
        let mut add = |domain: String, cameras: Vec<String>| {
            if let Some(existing) = declarations.iter_mut().find(|value| value.domain == domain) {
                existing.cameras.extend(cameras);
                existing.cameras.sort();
                existing.cameras.dedup();
            } else {
                declarations.push(FailureDomainDeclaration { domain, cameras });
            }
        };
        if let Some((calibration, _)) = self.calibration {
            let cameras = self
                .provenance
                .iter()
                .enumerate()
                .filter(|(_, source)| {
                    matches!(source, Some(PoseProvenance::SiteCalibration { .. }))
                })
                .map(|(index, _)| plan.cameras[index].name.clone())
                .collect();
            add(format!("calibration:site-{}", hex(calibration)), cameras);
        }
        if let Some((scene, _)) = self.scene {
            add(
                format!("calibration:scene-{}", hex(scene)),
                plan.cameras
                    .iter()
                    .map(|camera| camera.name.clone())
                    .collect(),
            );
        }
        CorroborationDependencies::new(declarations)
    }
}

/// Verified geometry inputs, owned for the complete analysis and exact publication retry.
#[derive(Clone, Debug)]
pub struct LongCorroborationGeometry {
    recipe: LongCorroborationGeometryRecipe,
    calibration: Option<SiteCalibration>,
    scene: Option<Arc<PropertyTwin>>,
    archives: Vec<(ContentDigest, Arc<Vec<u8>>)>,
}

impl LongCorroborationGeometry {
    /// Bind resolved poses to pinned calibration/scene bytes before opening either recording.
    /// Calibration tuple: semantic identity and archive. Scene tuple: package, source, archive.
    pub fn new(
        plan: &CorroborationPlan,
        policy: VisibilityPolicy,
        poses: [Option<CameraPose>; 2],
        provenance: [Option<PoseProvenance>; 2],
        calibration: Option<(ContentDigest, Vec<u8>)>,
        scene: Option<(ContentDigest, ContentDigest, Vec<u8>)>,
    ) -> Result<Self> {
        plan.validate()?;
        if calibration
            .as_ref()
            .is_some_and(|(_, bytes)| bytes.len() > MAX_CALIBRATION_BYTES)
            || scene
                .as_ref()
                .is_some_and(|(_, _, bytes)| bytes.len() > MAX_LONG_CORROBORATION_SCENE_BYTES)
        {
            return Err(CorroborationError::Limit);
        }
        let recipe = LongCorroborationGeometryRecipe {
            plan: plan.digest(),
            policy,
            poses,
            provenance,
            calibration: calibration
                .as_ref()
                .map(|(identity, bytes)| (*identity, ContentDigest::sha256(bytes))),
            scene: scene
                .as_ref()
                .map(|(package, source, _)| (*package, *source)),
        };
        Self::from_archives(
            plan,
            &recipe,
            calibration.map(|(_, bytes)| bytes),
            scene.map(|(_, _, bytes)| bytes),
        )
    }

    /// Exact geometry recipe, containing no loose filesystem paths.
    pub fn recipe(&self) -> &LongCorroborationGeometryRecipe {
        &self.recipe
    }

    /// Recover and verify archives from their retained recipe. Missing, changed or unrelated
    /// archives are refused before any geometry or perception result is accepted.
    pub(crate) fn from_archives(
        plan: &CorroborationPlan,
        recipe: &LongCorroborationGeometryRecipe,
        calibration: Option<Vec<u8>>,
        scene: Option<Vec<u8>>,
    ) -> Result<Self> {
        recipe.validate(plan)?;
        let mut archives = Vec::new();
        let calibration = match (recipe.calibration, calibration) {
            (Some((identity, object)), Some(bytes)) => {
                if bytes.len() > MAX_CALIBRATION_BYTES {
                    return Err(CorroborationError::Limit);
                }
                if ContentDigest::sha256(&bytes) != object {
                    return Err(ContractError::DigestMismatch.into());
                }
                let (calibration, _) =
                    SiteCalibration::decode(&bytes, Some(identity)).map_err(|_| {
                        CorroborationError::InvalidPlan("retained geometry calibration refused")
                    })?;
                archives.push((object, Arc::new(bytes)));
                Some(calibration)
            }
            (None, None) => None,
            _ => {
                return Err(CorroborationError::InvalidPlan(
                    "geometry calibration custody missing",
                ));
            }
        };
        let scene = match (recipe.scene, scene) {
            (Some((package, source)), Some(bytes)) => {
                if bytes.len() > MAX_LONG_CORROBORATION_SCENE_BYTES {
                    return Err(CorroborationError::Limit);
                }
                let scene = import_scene_mesh(&bytes, package, source)?;
                if calibration
                    .as_ref()
                    .is_some_and(|cal| cal.twin_package != package || cal.twin_source != source)
                {
                    return Err(CorroborationError::InvalidPlan(
                        "calibration and scene coordinate provenance differ",
                    ));
                }
                archives.push((package, Arc::new(bytes)));
                Some(Arc::new(scene))
            }
            (None, None) => None,
            _ => {
                return Err(CorroborationError::InvalidPlan(
                    "geometry scene custody missing",
                ));
            }
        };
        for index in 0..2 {
            if let Some(PoseProvenance::SiteCalibration {
                camera_handle,
                intrinsics_generation,
                extrinsics_generation,
                ..
            }) = recipe.provenance[index]
            {
                let camera = calibration
                    .as_ref()
                    .and_then(|cal| cal.camera(&plan.cameras[index].name))
                    .ok_or_else(|| {
                        invalid(
                            &plan.cameras[index].name,
                            "calibration has no selected camera",
                        )
                    })?;
                let exact_pose = match (camera.pinhole_pose(), recipe.poses[index]) {
                    (Ok(calibrated), Some(selected)) => {
                        calibrated.intrinsics.dimensions() == selected.intrinsics.dimensions()
                            && calibrated.parameter_bits() == selected.parameter_bits()
                    }
                    _ => false,
                };
                if camera.identity
                    != (CameraGeneration {
                        camera: camera_handle,
                        intrinsics: intrinsics_generation,
                        extrinsics: extrinsics_generation,
                    })
                    || !exact_pose
                {
                    return Err(invalid(
                        &plan.cameras[index].name,
                        "pose or generations differ from exact calibration",
                    ));
                }
                // Complete covariance partition and native pinhole support are mandatory.
                calibrated_camera_model(camera)?;
            }
        }
        Ok(Self {
            recipe: recipe.clone(),
            calibration,
            scene,
            archives,
        })
    }

    pub(crate) fn load_retained(
        deployment: &ReferenceDeployment,
        plan: &CorroborationPlan,
        recipe: &LongCorroborationGeometryRecipe,
        cx: &ReplayCx,
    ) -> Result<Self> {
        if cx.root_dir() != deployment.root() {
            return Err(CorroborationError::Conflict);
        }
        checkpoint(cx, "long_corroboration:retained_geometry")?;
        let read = |digest, maximum| {
            fss_object::read_verified_payload(
                deployment.publisher().spool().root(),
                digest,
                maximum,
                &fss_object::HostSpoolIo,
            )
            .map_err(CorroborationError::from)
        };
        let calibration = recipe
            .calibration
            .map(|(_, digest)| read(digest, MAX_CALIBRATION_BYTES))
            .transpose()?;
        let scene = recipe
            .scene
            .map(|(digest, _)| read(digest, MAX_LONG_CORROBORATION_SCENE_BYTES))
            .transpose()?;
        let value = Self::from_archives(plan, recipe, calibration, scene)?;
        checkpoint(cx, "long_corroboration:retained_geometry_complete")?;
        Ok(value)
    }

    pub(crate) fn from_retained_objects(
        plan: &CorroborationPlan,
        recipe: &LongCorroborationGeometryRecipe,
        objects: &std::collections::BTreeMap<ContentDigest, Vec<u8>>,
    ) -> Result<Self> {
        let read = |digest| {
            objects
                .get(&digest)
                .cloned()
                .ok_or(CorroborationError::InvalidPlan(
                    "geometry archive missing from retained closure",
                ))
        };
        let calibration = recipe
            .calibration
            .map(|(_, digest)| read(digest))
            .transpose()?;
        let scene = recipe.scene.map(|(digest, _)| read(digest)).transpose()?;
        Self::from_archives(plan, recipe, calibration, scene)
    }

    pub(crate) fn archives(&self) -> impl Iterator<Item = (ContentDigest, &[u8])> {
        self.archives
            .iter()
            .map(|(digest, bytes)| (*digest, bytes.as_slice()))
    }

    /// Revalidate the exact retained adoption basis, including reverse sensor-to-camera binding.
    /// An owner assertion cannot silently become an adopted generation during an exact retry.
    pub(crate) fn check_current(
        &self,
        deployment: &ReferenceDeployment,
        plan: &CorroborationPlan,
        sensors: &[SensorId; 2],
        cx: &ReplayCx,
    ) -> Result<()> {
        checkpoint(cx, "long_corroboration:geometry_currency")?;
        if self.recipe.calibration.is_none() {
            return Ok(());
        }
        let adoptions = retained_adoptions(deployment).map_err(|_| {
            CorroborationError::InvalidPlan("current calibration authority could not be verified")
        })?;
        for (index, sensor) in sensors.iter().enumerate() {
            let Some(PoseProvenance::SiteCalibration {
                calibration_digest,
                camera_handle,
                intrinsics_generation,
                extrinsics_generation,
                currency,
            }) = self.recipe.provenance[index]
            else {
                continue;
            };
            let name = &plan.cameras[index].name;
            for (handle, history) in &adoptions {
                if *handle != camera_handle
                    && history
                        .last()
                        .is_some_and(|current| current.receipt.sensor_id == *sensor)
                {
                    return Err(invalid(
                        name,
                        "sensor is adopted under a different camera; reanalyse",
                    ));
                }
            }
            let current = adopted_currency(
                &adoptions,
                calibration_digest,
                name,
                CameraGeneration {
                    camera: camera_handle,
                    intrinsics: intrinsics_generation,
                    extrinsics: extrinsics_generation,
                },
                || Ok(sensor.clone()),
            )
            .map_err(|_| invalid(name, "calibration or sensor adoption changed; reanalyse"))?;
            let same = match (currency, current.map(|current| current.digest)) {
                (GenerationCurrency::AdoptedCurrent { receipt }, Some(actual)) => receipt == actual,
                (GenerationCurrency::Unasserted | GenerationCurrency::OwnerAsserted, None) => true,
                _ => false,
            };
            if !same {
                return Err(invalid(
                    name,
                    "calibration adoption basis changed; reanalyse",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn assess(
        &self,
        plan: &CorroborationPlan,
        index: usize,
        dimensions: [u32; 2],
        sensor: &SensorId,
        privacy: &MaskBinding,
        cx: &ReplayCx,
    ) -> Result<GeometryAssessment> {
        checkpoint(cx, "long_corroboration:geometry_support")?;
        self.recipe.validate(plan)?;
        let camera = &plan.cameras[index];
        let pose = self.recipe.poses[index].as_ref();
        if pose.is_some_and(|pose| pose.intrinsics.dimensions() != dimensions) {
            return Err(invalid(
                &camera.name,
                "pose dimensions differ from decoded source",
            ));
        }
        let calibrated = self
            .calibration
            .as_ref()
            .and_then(|cal| cal.camera(&camera.name))
            .filter(|_| {
                matches!(
                    self.recipe.provenance[index],
                    Some(PoseProvenance::SiteCalibration { .. })
                )
            });
        let covariance = calibrated
            .map(|cal| cal.pose_covariance())
            .transpose()
            .map_err(|_| invalid(&camera.name, "calibration pose covariance refused"))?;
        let mesh = match (&self.scene, self.recipe.scene) {
            (Some(scene), Some((package_digest, _))) => Some(SceneMesh {
                mesh: scene.mesh(),
                package_digest,
            }),
            (None, None) => None,
            _ => {
                return Err(CorroborationError::InvalidPlan(
                    "scene and recipe custody disagree",
                ));
            }
        };
        let mask = |column, row| privacy.policy().is_some_and(|mask| mask.masks(column, row));
        let masked: Option<crate::ingest::ground_visibility::PixelMask<'_>> =
            privacy.policy().map(|_| &mask as _);
        // Both nominal samples and all pose perturbations spend one budget across every zone.
        let mut budget = WorkBudget::new(MAX_VISIBILITY_WORK);
        let mut blocked = BTreeSet::new();
        let mut zones = Vec::new();
        let mut e = CanonicalEncoder::new();
        e.bytes(GEOMETRY_POLICY);
        e.digest(self.recipe.digest());
        e.u64(index as u64);
        e.text(sensor.as_str());
        for size in dimensions {
            e.u32(size);
        }
        e.digest(privacy.digest());
        e.u64(privacy.generation().unwrap_or(0));
        let full = if let (Some(cal), Some((digest, _))) = (calibrated, self.recipe.calibration) {
            let adjusted = calibrated_camera_model(cal)?;
            let mut full_budget = WorkBudget::new(MAX_CALIBRATION_COVERAGE_WORK);
            Some(assess_calibration_coverage(
                CalibrationCoverageInput {
                    camera_name: &camera.name,
                    camera: &adjusted,
                    calibration_digest: digest,
                    sensor,
                    privacy,
                    zones: &plan.zones,
                    policy: self.recipe.policy,
                },
                &mut full_budget,
            )?)
        } else {
            None
        };
        e.u64(plan.zones.len() as u64);
        for (zone_index, zone) in plan.zones.iter().enumerate() {
            checkpoint(cx, "long_corroboration:geometry_zone")?;
            let polygon = rectangle(zone.x, zone.y, zone.width, zone.height);
            if pose.is_some_and(|pose| {
                !pose_matches_homography(
                    pose,
                    &camera.homography.matrix,
                    &polygon,
                    self.recipe.policy,
                )
            }) {
                return Err(invalid(&camera.name, "pose and ground homography disagree"));
            }
            let model = pose
                .map(VisibilityCamera::Pose)
                .unwrap_or(VisibilityCamera::Homography(&camera.homography.matrix));
            let visibility = assess_samples(
                model,
                dimensions,
                &ground_samples(&polygon, self.recipe.policy)?,
                mesh,
                self.recipe.policy,
                masked,
                &mut budget,
            )?;
            let robustness = match (pose, covariance.as_ref()) {
                (Some(pose), Some(covariance)) => Some(assess_pose_robustness(
                    pose,
                    covariance,
                    dimensions,
                    &polygon,
                    mesh,
                    self.recipe.policy,
                    masked,
                    &visibility,
                    &mut budget,
                )?),
                _ => None,
            };
            let full_abstains = full.as_ref().is_some_and(|full| {
                full.zones()
                    .iter()
                    .find(|assessment| assessment.zone_id() == zone.zone_id)
                    .is_none_or(|assessment| assessment.requires_abstention())
            });
            let available = visibility.observable()
                && robustness.as_ref().is_none_or(|value| value.robust())
                && !full_abstains;
            if !available {
                blocked.insert(zone_index);
            }
            e.text(&zone.zone_id);
            visibility.encode_versioned(&mut e, true);
            e.bool(robustness.is_some());
            if let Some(value) = robustness {
                value.encode(&mut e);
            }
            e.bool(full_abstains);
            e.bool(available);
            zones.push(format!("{{\"zone_id\":{},\"support_available\":{},\"visibility\":{},\"claim\":{},\"pose_robust\":{},\"full_camera_requires_abstention\":{}}}",
                json_string(&zone.zone_id), available, json_string(&visibility.summary()), json_string(visibility.claim()),
                robustness.map(|value| value.robust().to_string()).unwrap_or_else(|| "null".to_owned()), full_abstains));
        }
        e.u64(budget.used());
        e.bool(full.is_some());
        if let Some(full) = &full {
            // Encode evidence fields directly. JSON presentation does not own immutable proof.
            e.digest(full.input_digest());
            e.u64(full.work_units());
            e.u64(full.zones().len() as u64);
            for zone in full.zones() {
                e.text(zone.zone_id());
                e.u32(zone.samples());
                for relation in [
                    CalibrationSampleRelation::InsideUnmasked,
                    CalibrationSampleRelation::OutsideFrustum,
                    CalibrationSampleRelation::FrustumBoundary,
                    CalibrationSampleRelation::CameraPlaneCrossing,
                    CalibrationSampleRelation::PrivacyMasked,
                    CalibrationSampleRelation::PrivacyBoundary,
                    CalibrationSampleRelation::MeanBehindCamera,
                ] {
                    e.text(relation.as_str());
                    e.u32(zone.count(relation));
                }
                e.bool(zone.requires_abstention());
            }
        }
        let receipt = e.finish();
        if receipt.len() > MAX_GEOMETRY_RECEIPT_BYTES {
            return Err(CorroborationError::Limit);
        }
        let scene_json = self.recipe.scene.map(|(package, source)| format!(
            "{{\"package_digest\":\"{package}\",\"source_scene_digest\":\"{source}\",\"claim\":\"owner_supplied_geometry_not_physical_currency\"}}"))
            .unwrap_or_else(|| "null".to_owned());
        let json = format!(
            "{{\"recipe_digest\":\"{}\",\"receipt_digest\":\"{}\",\"pose_provenance\":{},\"scene\":{},\"geometry_work\":{},\"zones\":[{}],\"full_camera_guard\":{},\"claim\":\"conditional_geometry_screen_not_physical_currency_or_absence\"}}",
            self.recipe.digest(),
            ContentDigest::sha256(&receipt),
            provenance_json(self.recipe.provenance[index]),
            scene_json,
            budget.used(),
            zones.join(","),
            full.map(|full| full.to_json())
                .unwrap_or_else(|| "null".to_owned())
        );
        Ok(GeometryAssessment {
            receipt,
            blocked,
            json,
        })
    }

    /// Recompute every geometry receipt field under current privacy from retained archives.
    /// Native event verification additionally checks these declared dimensions against pixels.
    pub(crate) fn verify_assessment(
        &self,
        plan: &CorroborationPlan,
        index: usize,
        sensor: &SensorId,
        privacy: &MaskBinding,
        bytes: &[u8],
        cx: &ReplayCx,
    ) -> Result<GeometryAssessment> {
        if bytes.len() > MAX_GEOMETRY_RECEIPT_BYTES {
            return Err(CorroborationError::Limit);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != GEOMETRY_POLICY
            || d.digest()? != self.recipe.digest()
            || d.u64()? != index as u64
            || d.text()? != sensor.as_str()
        {
            return Err(ContractError::DigestMismatch.into());
        }
        let dimensions = [d.u32()?, d.u32()?];
        let actual = self.assess(plan, index, dimensions, sensor, privacy, cx)?;
        if actual.receipt != bytes {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(actual)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct GeometryAssessment {
    pub(crate) receipt: Vec<u8>,
    pub(crate) blocked: BTreeSet<usize>,
    pub(crate) json: String,
}

fn provenance_json(source: Option<PoseProvenance>) -> String {
    match source {
        None => "null".to_owned(),
        Some(PoseProvenance::OwnerPoseArgument) => format!(
            "{{\"source\":\"owner_pose_argument\",\"claim\":{}}}",
            json_string(PoseProvenance::OwnerPoseArgument.claim())
        ),
        Some(
            source @ PoseProvenance::SiteCalibration {
                calibration_digest,
                camera_handle,
                intrinsics_generation,
                extrinsics_generation,
                currency,
            },
        ) => format!(
            "{{\"source\":\"site_calibration\",\"calibration_digest\":\"{calibration_digest}\",\"camera_handle\":{camera_handle},\"intrinsics_generation\":{intrinsics_generation},\"extrinsics_generation\":{extrinsics_generation},\"generation_currency\":{},\"adoption_receipt\":{},\"claim\":{}}}",
            json_string(currency.as_str()),
            currency
                .adoption_receipt()
                .map(|receipt| json_string(&receipt.to_text()))
                .unwrap_or_else(|| "null".to_owned()),
            json_string(source.claim())
        ),
    }
}

fn encode_provenance(e: &mut CanonicalEncoder, source: PoseProvenance) {
    e.text(source.source());
    if let PoseProvenance::SiteCalibration {
        calibration_digest,
        camera_handle,
        intrinsics_generation,
        extrinsics_generation,
        currency,
    } = source
    {
        e.digest(calibration_digest);
        e.u64(camera_handle);
        e.u64(intrinsics_generation);
        e.u64(extrinsics_generation);
        e.text(currency.as_str());
        if let Some(receipt) = currency.adoption_receipt() {
            e.digest(receipt);
        }
    }
}

fn decode_provenance(d: &mut CanonicalDecoder<'_>) -> Result<PoseProvenance> {
    match d.text()? {
        "owner_pose_argument" => Ok(PoseProvenance::OwnerPoseArgument),
        "site_calibration" => {
            let calibration_digest = d.digest()?;
            let camera_handle = d.u64()?;
            let intrinsics_generation = d.u64()?;
            let extrinsics_generation = d.u64()?;
            let currency = match d.text()? {
                "unasserted_unknown" => GenerationCurrency::Unasserted,
                "owner_asserted_not_observed" => GenerationCurrency::OwnerAsserted,
                "adopted_current" => GenerationCurrency::AdoptedCurrent {
                    receipt: d.digest()?,
                },
                _ => return Err(ContractError::InvalidIdentifier.into()),
            };
            Ok(PoseProvenance::SiteCalibration {
                calibration_digest,
                camera_handle,
                intrinsics_generation,
                extrinsics_generation,
                currency,
            })
        }
        _ => Err(ContractError::InvalidIdentifier.into()),
    }
}
