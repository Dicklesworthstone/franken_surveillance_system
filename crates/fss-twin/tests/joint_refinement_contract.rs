#![forbid(unsafe_code)]
//! Joint site refinement contracts on a deterministic synthetic site.
//!
//! Every camera is first localized independently through the real atlas matching
//! and focal-scan (or fixed-intrinsics) localization paths from noisy synthetic
//! pixels; the joint refinement is then seeded from those genuine localization
//! candidates. Synthetic scenes do not establish accuracy on real site footage.
mod common;

use fss_geometry::{
    BundleAdjustmentError, BundleGaugeChoice, BundleParameter, BundleValidity, CameraGeneration,
    FocalSampleOutcome, FocalScanOptions, PinholeIntrinsics, PoseSolverOptions, RigidPose,
    WorkBudget,
};
use fss_twin::PropertyTwin;
use fss_twin::focal_localization::{
    FocalLocalization, FocalLocalizationOutcome, localize_focal_scan,
};
use fss_twin::joint_refinement::{
    ControlSelection, JointCamera, JointOptions, JointRefinement, JointRefinementError,
    LocalizationSeed, TieObservation, refine_site_jointly,
};
use fss_twin::localization::{
    AtlasBinding, AtlasLandmark, AtlasReference, BinaryDescriptor, CameraLocalization,
    FeatureFrame, ImageFeature, ImageIdentity, LocalizationAtlas, LocalizationCamera,
    LocalizationOutcome, MatchOptions,
};
use std::error::Error;

type Test = Result<(), Box<dyn Error>>;
type M3 = [[f64; 3]; 3];

const CAMERAS: usize = 5;
const ATLAS: u64 = 12;
const TIES: u64 = 16;
const TIE_BASE: u64 = 1001;
const DOMAIN: [u8; 32] = [3; 32];
/// Truth focal lengths deliberately fall between focal-scan grid samples.
const TRUTH_FX: [f64; CAMERAS] = [845.0, 893.0, 941.0, 992.0, 1046.0];

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn uniform(&mut self, low: f64, high: f64) -> f64 {
        low + (high - low) * ((self.next() >> 11) as f64 / (1_u64 << 53) as f64)
    }
    fn gaussian(&mut self) -> f64 {
        let u1 = self.uniform(f64::MIN_POSITIVE, 1.0);
        let u2 = self.uniform(0.0, 1.0);
        (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
    }
}

fn descriptor(id: u64) -> BinaryDescriptor {
    BinaryDescriptor([
        id.wrapping_mul(0x9e37_79b9_7f4a_7c15),
        !id,
        id.rotate_left(17),
        id.wrapping_mul(0xd6e8_feb8_6659_fd93),
    ])
}
fn cross(a: [f64; 3], b: [f64; 3]) -> [f64; 3] {
    [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]
}
fn norm(a: [f64; 3]) -> f64 {
    (a[0] * a[0] + a[1] * a[1] + a[2] * a[2]).sqrt()
}
fn unit(a: [f64; 3]) -> [f64; 3] {
    let n = norm(a);
    [a[0] / n, a[1] / n, a[2] / n]
}
fn mm(a: M3, b: M3) -> M3 {
    std::array::from_fn(|i| std::array::from_fn(|j| (0..3).map(|k| a[i][k] * b[k][j]).sum()))
}
fn transpose(a: M3) -> M3 {
    std::array::from_fn(|i| std::array::from_fn(|j| a[j][i]))
}
fn rotation_error(a: M3, b: M3) -> f64 {
    let r = mm(a, transpose(b));
    let sine = norm([r[2][1] - r[1][2], r[0][2] - r[2][0], r[1][0] - r[0][1]]) / 2.0;
    let cosine = (r[0][0] + r[1][1] + r[2][2] - 1.0) / 2.0;
    sine.atan2(cosine)
}
fn look_at(center: [f64; 3], target: [f64; 3]) -> Result<RigidPose, Box<dyn Error>> {
    let z = unit([
        target[0] - center[0],
        target[1] - center[1],
        target[2] - center[2],
    ]);
    let x = unit(cross(z, [0.0, 0.0, 1.0]));
    let y = cross(z, x);
    Ok(RigidPose::from_center([x, y, z], center)?)
}

#[derive(Clone, Copy)]
enum Survey {
    /// Every atlas landmark declares a 2 mm survey error.
    All,
    /// Only the first `n` landmarks declare a survey error; the rest are unknown.
    FirstN(u64),
    /// Like `FirstN(3)`, with those three placed on one line.
    CollinearFirstThree,
}

struct Truth {
    identity: CameraGeneration,
    pose: RigidPose,
    intrinsics: PinholeIntrinsics,
}

struct Site {
    twin: PropertyTwin,
    atlas: LocalizationAtlas,
    truth: Vec<Truth>,
    ties: Vec<TieObservation>,
    focal: Vec<FocalLocalization>,
    fixed: Vec<CameraLocalization>,
}

fn atlas_world(id: u64, survey: Survey, rng: &mut Rng) -> [f64; 3] {
    let random = [
        rng.uniform(-3.0, 3.0),
        rng.uniform(-3.0, 3.0),
        rng.uniform(0.0, 2.5),
    ];
    match survey {
        Survey::CollinearFirstThree if id <= 3 => {
            let t = id as f64;
            [-2.0 + 1.3 * t, 1.5 - 0.7 * t, 0.4 + 0.2 * t]
        }
        _ => random,
    }
}

fn site(survey: Survey, noise_px: f64) -> Result<Site, Box<dyn Error>> {
    let twin = common::twin(&[0.0], None)?;
    let mut budget = WorkBudget::new(4_000_000_000);
    let mut rng = Rng(0x0517_E5EE_D001);
    let worlds: Vec<[f64; 3]> = (1..=ATLAS)
        .map(|id| atlas_world(id, survey, &mut rng))
        .collect();
    let surveyed = |id: u64| match survey {
        Survey::All => true,
        Survey::FirstN(n) => id <= n,
        Survey::CollinearFirstThree => id <= 3,
    };
    let landmarks = (1..=ATLAS)
        .map(|id| AtlasLandmark {
            id,
            physical_group: id,
            feature: 0,
            world: worlds[id as usize - 1],
            evidence: [7; 32],
            error: surveyed(id).then_some([0.002; 3]),
        })
        .collect();
    let reference_features = (1..=ATLAS)
        .map(|id| ImageFeature {
            id,
            pixel: [40.0 + id as f64 * 60.0, 100.0 + (id % 5) as f64 * 90.0],
            descriptor: descriptor(id),
        })
        .collect();
    let identity = |exposure: u8| ImageIdentity {
        exposure: [exposure; 32],
        pixels: [exposure.wrapping_add(40); 32],
        image_domain: DOMAIN,
        dimensions: [1920, 1080],
    };
    let reference = FeatureFrame::new(identity(1), [9; 32], reference_features, &mut budget)?;
    let atlas = LocalizationAtlas::new(
        &twin,
        landmarks,
        vec![AtlasReference {
            id: 1,
            frame: reference,
        }],
        (1..=ATLAS)
            .map(|id| AtlasBinding {
                landmark: id,
                reference: 1,
                image_feature: id,
            })
            .collect(),
        &mut budget,
    )?;
    let tie_worlds: Vec<[f64; 3]> = (0..TIES)
        .map(|_| {
            [
                rng.uniform(-3.0, 3.0),
                rng.uniform(-3.0, 3.0),
                rng.uniform(0.0, 2.5),
            ]
        })
        .collect();
    let mut truth = Vec::new();
    for (i, &fx) in TRUTH_FX.iter().enumerate() {
        let angle = std::f64::consts::TAU * i as f64 / CAMERAS as f64 + 0.4;
        let radius = 9.0 + 0.8 * (i % 2) as f64;
        let center = [
            radius * angle.cos(),
            radius * angle.sin(),
            3.0 + 0.6 * i as f64,
        ];
        truth.push(Truth {
            identity: CameraGeneration {
                camera: 21 + i as u64,
                intrinsics: 5,
                extrinsics: 6,
            },
            pose: look_at(center, [0.2 * i as f64 - 0.4, 0.1, 1.0])?,
            intrinsics: PinholeIntrinsics::new(1920, 1080, fx, fx, 960.0, 540.0)?,
        });
    }
    let observe =
        |camera: &Truth, world: [f64; 3], rng: &mut Rng| -> Result<[f64; 2], Box<dyn Error>> {
            let clean = camera.pose.project(camera.intrinsics, world)?;
            let pixel = [
                clean[0] + noise_px * rng.gaussian(),
                clean[1] + noise_px * rng.gaussian(),
            ];
            if !camera.intrinsics.contains(pixel) {
                return Err("synthetic point left the image".into());
            }
            Ok(pixel)
        };
    let scan = FocalScanOptions {
        minimum_fx_px: 600.0,
        maximum_fx_px: 1400.0,
        y_over_x: 1.0,
        principal_point: [960.0, 540.0],
        samples: 17,
        pose: PoseSolverOptions {
            ransac_trials: 0,
            inlier_threshold_px: 40.0,
            ..PoseSolverOptions::default()
        },
    };
    let matching = MatchOptions {
        maximum_distance: 0,
        ratio_percent: 80,
    };
    let mut focal = Vec::new();
    let mut fixed = Vec::new();
    let mut ties = Vec::new();
    for (i, camera) in truth.iter().enumerate() {
        let mut features = Vec::new();
        for id in 1..=ATLAS {
            features.push(ImageFeature {
                id,
                pixel: observe(camera, worlds[id as usize - 1], &mut rng)?,
                descriptor: descriptor(id),
            });
        }
        let query = FeatureFrame::new(identity(10 + i as u8), [9; 32], features, &mut budget)?;
        focal.push(localize_focal_scan(
            &atlas,
            &twin,
            &query,
            DOMAIN,
            matching,
            scan,
            &mut budget,
        )?);
        fixed.push(atlas.localize(
            &twin,
            &query,
            LocalizationCamera {
                intrinsics: camera.intrinsics,
                image_domain: DOMAIN,
            },
            matching,
            PoseSolverOptions {
                ransac_trials: 0,
                ..PoseSolverOptions::default()
            },
            &mut budget,
        )?);
        for (k, &world) in tie_worlds.iter().enumerate() {
            ties.push(TieObservation {
                camera: camera.identity.camera,
                tie: TIE_BASE + k as u64,
                pixel: observe(camera, world, &mut rng)?,
            });
        }
    }
    Ok(Site {
        twin,
        atlas,
        truth,
        ties,
        focal,
        fixed,
    })
}

/// Caller policy for this fixture (not the module's): the full-support candidate
/// with the lowest fit RMS across the focal grid.
fn focal_seeds(site: &Site) -> Result<Vec<JointCamera<'_>>, Box<dyn Error>> {
    let mut seeds = Vec::new();
    for (truth, localization) in site.truth.iter().zip(&site.focal) {
        let FocalLocalizationOutcome::Scan(scan) = &localization.outcome else {
            return Err("no focal scan".into());
        };
        let mut best: Option<(f64, usize, usize)> = None;
        for (si, sample) in scan.samples().iter().enumerate() {
            if let FocalSampleOutcome::Candidates(search) = sample.outcome() {
                for (ci, candidate) in search.candidates().iter().enumerate() {
                    if candidate.inlier_landmarks().len() == ATLAS as usize
                        && best.is_none_or(|b| candidate.rms_px() < b.0)
                    {
                        best = Some((candidate.rms_px(), si, ci));
                    }
                }
            }
        }
        let (_, sample, candidate) = best.ok_or("no full-support focal candidate")?;
        seeds.push(JointCamera {
            identity: truth.identity,
            seed: LocalizationSeed::Focal {
                localization,
                sample,
                candidate,
            },
        });
    }
    Ok(seeds)
}

fn fixed_seeds(site: &Site) -> Result<Vec<JointCamera<'_>>, Box<dyn Error>> {
    let mut seeds = Vec::new();
    for (truth, localization) in site.truth.iter().zip(&site.fixed) {
        let LocalizationOutcome::Candidates(search) = &localization.outcome else {
            return Err("no fixed-intrinsics pose".into());
        };
        if search.candidates().is_empty() {
            return Err("no fixed-intrinsics candidate".into());
        }
        seeds.push(JointCamera {
            identity: truth.identity,
            seed: LocalizationSeed::Fixed {
                localization,
                candidate: 0,
            },
        });
    }
    Ok(seeds)
}

fn refine(
    site: &Site,
    seeds: &[JointCamera<'_>],
    ties: &[TieObservation],
    control: ControlSelection,
) -> Result<JointRefinement, JointRefinementError> {
    refine_site_jointly(
        &site.twin,
        &site.atlas,
        seeds,
        ties,
        JointOptions {
            control,
            ..JointOptions::default()
        },
        &mut WorkBudget::new(4_000_000_000),
    )
}

/// (rms center error m, max center error m, max rotation error rad, max |focal error| px)
fn pose_errors(
    site: &Site,
    poses: &[(u64, RigidPose, PinholeIntrinsics)],
) -> Result<(f64, f64, f64, f64), Box<dyn Error>> {
    let (mut sum, mut max_center, mut max_rotation, mut max_focal) =
        (0.0, 0.0_f64, 0.0_f64, 0.0_f64);
    for truth in &site.truth {
        let (_, pose, intrinsics) = poses
            .iter()
            .find(|p| p.0 == truth.identity.camera)
            .ok_or("camera")?;
        let (a, b) = (pose.center(), truth.pose.center());
        let center = norm([a[0] - b[0], a[1] - b[1], a[2] - b[2]]);
        sum += center * center;
        max_center = max_center.max(center);
        max_rotation = max_rotation.max(rotation_error(pose.rotation(), truth.pose.rotation()));
        max_focal = max_focal
            .max((intrinsics.focal_lengths()[0] - truth.intrinsics.focal_lengths()[0]).abs());
    }
    Ok((
        (sum / site.truth.len() as f64).sqrt(),
        max_center,
        max_rotation,
        max_focal,
    ))
}

fn seed_poses(result: &JointRefinement) -> Vec<(u64, RigidPose, PinholeIntrinsics)> {
    result
        .cameras
        .iter()
        .map(|c| (c.identity.camera, c.seed_pose, c.seed_intrinsics))
        .collect()
}
fn refined_poses(result: &JointRefinement) -> Vec<(u64, RigidPose, PinholeIntrinsics)> {
    result
        .adjustment
        .cameras()
        .iter()
        .map(|c| (c.identity.camera, c.pose, c.intrinsics))
        .collect()
}

fn bits(result: &JointRefinement) -> Vec<u64> {
    let mut out = Vec::new();
    for c in result.adjustment.cameras() {
        out.extend(c.pose.rotation().iter().flatten().map(|x| x.to_bits()));
        out.extend(c.pose.translation().iter().map(|x| x.to_bits()));
        out.extend(c.intrinsics.focal_lengths().iter().map(|x| x.to_bits()));
        out.extend(c.covariance.matrix.iter().map(|x| x.to_bits()));
    }
    for l in result.adjustment.landmarks() {
        out.extend(l.position.iter().map(|x| x.to_bits()));
        out.extend(l.covariance.iter().flatten().map(|x| x.to_bits()));
    }
    for c in &result.cameras {
        out.push(c.seed_rms_px.to_bits());
        out.push(c.refined_rms_px.to_bits());
    }
    let r = result.adjustment.report();
    out.extend([
        r.initial_rms_px.to_bits(),
        r.final_rms_px.to_bits(),
        r.work_units,
    ]);
    out
}

#[test]
fn focal_scan_localizations_are_jointly_refined_to_sub_pixel_metric_poses() -> Test {
    let site = site(Survey::All, 0.3)?;
    let seeds = focal_seeds(&site)?;
    let result = refine(
        &site,
        &seeds,
        &site.ties,
        ControlSelection::AllAtlasLandmarks,
    )?;
    let independent = pose_errors(&site, &seed_poses(&result))?;
    let joint = pose_errors(&site, &refined_poses(&result))?;
    let factor = independent.0 / joint.0;
    println!(
        "focal-scan site: rms {:.4} -> {:.4} px; center rms {:.4e} -> {:.4e} m (factor {factor:.1}); \
         center max {:.4e} -> {:.4e} m; rotation max {:.4e} -> {:.4e} rad; focal max {:.3} -> {:.3} px; {:?}",
        result.initial_rms_px(),
        result.final_rms_px(),
        independent.0,
        joint.0,
        independent.1,
        joint.1,
        independent.2,
        joint.2,
        independent.3,
        joint.3,
        result.adjustment.report().convergence,
    );
    for c in &result.cameras {
        println!(
            "  camera {}: seed fx {:.2}, rms {:.3} -> {:.3} px ({} control + {} free obs)",
            c.identity.camera,
            c.seed_intrinsics.focal_lengths()[0],
            c.seed_rms_px,
            c.refined_rms_px,
            c.control_observations,
            c.free_observations
        );
        assert!(c.refined_rms_px < 1.0);
        assert_eq!(c.control_observations, ATLAS as usize);
        assert_eq!(c.free_observations, TIES as usize);
    }
    assert!(result.final_rms_px() < 1.0, "sub-pixel joint RMS");
    assert!(result.initial_rms_px() > 2.0 * result.final_rms_px());
    assert!(
        factor >= 5.0,
        "pose error must drop by at least 5x, got {factor}"
    );
    assert!(joint.1 < independent.1 && joint.2 < independent.2 && joint.3 < independent.3);
    // Metric control-point gauge: no reference pose, no scale anchor.
    assert_eq!(result.adjustment.gauge(), BundleGaugeChoice::ControlPoints);
    assert_eq!(result.adjustment.control_points().len(), ATLAS as usize);
    assert_eq!(result.adjustment.landmarks().len(), TIES as usize);
    assert!(result.excluded_points.is_empty());
    for camera in result.adjustment.cameras() {
        let cov = &camera.covariance;
        // Six pose parameters plus the aspect-held focal length, all free.
        assert_eq!(cov.parameters.len(), 7);
        assert!(cov.parameters.contains(&BundleParameter::Focal));
        assert!(!cov.fixed.iter().any(|p| matches!(
            p,
            BundleParameter::Rotation(_) | BundleParameter::Translation(_)
        )));
        for i in 0..cov.parameters.len() {
            let v = cov.matrix[i * cov.parameters.len() + i];
            assert!(v.is_finite() && v > 0.0);
        }
        let (intrinsics, pose) = result
            .pinhole_camera(camera.identity.camera)
            .ok_or("pinhole consumer view")?;
        assert_eq!((intrinsics, pose), (camera.intrinsics, camera.pose));
    }
    // CameraGeneration dependencies and invalidation.
    let current: Vec<CameraGeneration> = site.truth.iter().map(|t| t.identity).collect();
    assert_eq!(result.dependencies(), current);
    assert_eq!(result.validity(&current), BundleValidity::Current);
    let mut moved = current.clone();
    moved[2].extrinsics += 1;
    assert!(matches!(
        result.validity(&moved),
        BundleValidity::Invalidated(_)
    ));
    // Deterministic: a second run and a permuted input are bit-identical.
    let again = refine(
        &site,
        &seeds,
        &site.ties,
        ControlSelection::AllAtlasLandmarks,
    )?;
    assert_eq!(bits(&result), bits(&again));
    let mut reversed_seeds = seeds.clone();
    reversed_seeds.reverse();
    let mut reversed_ties = site.ties.clone();
    reversed_ties.reverse();
    let permuted = refine(
        &site,
        &reversed_seeds,
        &reversed_ties,
        ControlSelection::AllAtlasLandmarks,
    )?;
    assert_eq!(bits(&result), bits(&permuted));
    println!("bit-identical over {} words", bits(&result).len());
    Ok(())
}

#[test]
fn fixed_intrinsics_localizations_measure_the_tie_point_coupling() -> Test {
    let site = site(Survey::All, 0.5)?;
    let seeds = fixed_seeds(&site)?;
    let result = refine(
        &site,
        &seeds,
        &site.ties,
        ControlSelection::AllAtlasLandmarks,
    )?;
    let independent = pose_errors(&site, &seed_poses(&result))?;
    let joint = pose_errors(&site, &refined_poses(&result))?;
    println!(
        "fixed-intrinsics site: rms {:.4} -> {:.4} px; center rms {:.4e} -> {:.4e} m (factor {:.2}); \
         rotation max {:.4e} -> {:.4e} rad",
        result.initial_rms_px(),
        result.final_rms_px(),
        independent.0,
        joint.0,
        independent.0 / joint.0,
        independent.2,
        joint.2,
    );
    assert!(result.final_rms_px() < 1.0);
    // Intrinsics were not estimated by these localizations, so none are refined.
    for camera in result.adjustment.cameras() {
        assert_eq!(camera.covariance.parameters.len(), 6);
        let truth = site
            .truth
            .iter()
            .find(|t| t.identity == camera.identity)
            .ok_or("truth")?;
        assert_eq!(camera.intrinsics, truth.intrinsics);
    }
    assert!(
        joint.0 < independent.0,
        "tie coupling must not worsen poses"
    );
    Ok(())
}

#[test]
fn surveyed_only_policy_frees_unsurveyed_atlas_landmarks() -> Test {
    let site = site(Survey::FirstN(6), 0.3)?;
    let seeds = focal_seeds(&site)?;
    let result = refine(
        &site,
        &seeds,
        &site.ties,
        ControlSelection::DeclaredErrorAtMost(0.01),
    )?;
    assert_eq!(result.adjustment.control_points().len(), 6);
    assert_eq!(result.adjustment.landmarks().len(), (TIES + 6) as usize);
    assert!(result.adjustment.landmark(7).is_some() && result.adjustment.landmark(6).is_none());
    assert!(result.final_rms_px() < 1.0);
    let joint = pose_errors(&site, &refined_poses(&result))?;
    println!(
        "surveyed-only (6 control): rms {:.4} -> {:.4} px, center rms {:.4e} m",
        result.initial_rms_px(),
        result.final_rms_px(),
        joint.0
    );
    Ok(())
}

#[test]
fn too_few_or_collinear_control_points_are_typed_refusals() -> Test {
    let two = site(Survey::FirstN(2), 0.3)?;
    let seeds = focal_seeds(&two)?;
    assert_eq!(
        refine(
            &two,
            &seeds,
            &two.ties,
            ControlSelection::DeclaredErrorAtMost(0.01)
        )
        .err(),
        Some(JointRefinementError::TooFewControlPoints { observed: 2 })
    );
    let line = site(Survey::CollinearFirstThree, 0.3)?;
    let seeds = focal_seeds(&line)?;
    assert_eq!(
        refine(
            &line,
            &seeds,
            &line.ties,
            ControlSelection::DeclaredErrorAtMost(0.01)
        )
        .err(),
        Some(JointRefinementError::CollinearControlPoints)
    );
    Ok(())
}

#[test]
fn disconnected_camera_graph_and_nan_correspondence_are_typed_refusals() -> Test {
    let site = site(Survey::All, 0.3)?;
    let seeds = focal_seeds(&site)?;
    // Cameras 21, 22 share ties 1001..1008 only; cameras 23..25 share 1009..1016 only.
    let split: Vec<TieObservation> = site
        .ties
        .iter()
        .copied()
        .filter(|t| (t.camera <= 22) == (t.tie < TIE_BASE + 8))
        .collect();
    assert_eq!(
        refine(&site, &seeds, &split, ControlSelection::AllAtlasLandmarks).err(),
        Some(JointRefinementError::DisconnectedCameras { camera: 23 })
    );
    // No ties at all: control points alone couple no cameras.
    assert_eq!(
        refine(&site, &seeds, &[], ControlSelection::AllAtlasLandmarks).err(),
        Some(JointRefinementError::DisconnectedCameras { camera: 22 })
    );
    let mut nan_tie = site.ties.clone();
    nan_tie[5].pixel[1] = f64::NAN;
    assert_eq!(
        refine(&site, &seeds, &nan_tie, ControlSelection::AllAtlasLandmarks).err(),
        Some(JointRefinementError::NonFiniteObservation {
            camera: nan_tie[5].camera,
            landmark: nan_tie[5].tie
        })
    );
    // An exhausted work budget is a typed refusal, not a partial result.
    let starved = refine_site_jointly(
        &site.twin,
        &site.atlas,
        &seeds,
        &site.ties,
        JointOptions::default(),
        &mut WorkBudget::new(200_000),
    );
    assert!(
        matches!(
            starved,
            Err(JointRefinementError::Bundle(
                BundleAdjustmentError::BudgetExhausted { .. }
            ))
        ),
        "{starved:?}"
    );
    drop(seeds);
    // A NaN pixel planted in one camera's atlas correspondences.
    let mut poisoned = site;
    let landmark = poisoned.focal[3].matches.correspondences[4].landmark;
    poisoned.focal[3].matches.correspondences[4].pixel[0] = f64::NAN;
    let seeds = focal_seeds(&poisoned)?;
    assert_eq!(
        refine(
            &poisoned,
            &seeds,
            &poisoned.ties,
            ControlSelection::AllAtlasLandmarks
        )
        .err(),
        Some(JointRefinementError::NonFiniteObservation {
            camera: 24,
            landmark
        })
    );
    // Single camera: nothing is joint.
    assert_eq!(
        refine(
            &poisoned,
            &seeds[..1],
            &[],
            ControlSelection::AllAtlasLandmarks
        )
        .err(),
        Some(JointRefinementError::TooFewCameras { cameras: 1 })
    );
    // A tie handle that is an atlas landmark handle is refused.
    let mut clash = poisoned.ties.clone();
    clash[0].tie = 3;
    assert_eq!(
        refine(
            &poisoned,
            &seeds[..3],
            &clash,
            ControlSelection::AllAtlasLandmarks
        )
        .err(),
        Some(JointRefinementError::TieCollidesWithAtlas { tie: 3 })
    );
    Ok(())
}
