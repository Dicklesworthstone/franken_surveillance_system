#![forbid(unsafe_code)]
//! Reference bundle-adjustment contracts on deterministic synthetic ground truth.
//!
//! Fixtures are generated in-test from a seeded SplitMix64 stream. The gauge
//! (reference camera pose and scale-anchor translation component) is set to the
//! ground-truth values, so recovered parameters are directly comparable with truth
//! without any post-hoc similarity alignment. Passing these contracts does not
//! establish accuracy on real camera footage.

use fss_geometry::{
    BudgetKind, BundleAdjustment, BundleAdjustmentError, BundleCamera, BundleGauge, BundleLandmark,
    BundleObservation, BundleOptions, BundleParameter, BundleProblem, BundleValidity,
    CameraGeneration, Convergence, FocalRefinement, GeometryBasis, IntrinsicsRefinement,
    InvalidationCause, NonFiniteInput, PinholeIntrinsics, RadialDistortion, RigidPose,
    SingularStage, UnderConstrainedReason, WorkBudget, bundle_adjust,
};
use std::sync::atomic::AtomicBool;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type M3 = [[f64; 3]; 3];

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
fn mv(m: M3, v: [f64; 3]) -> [f64; 3] {
    std::array::from_fn(|i| m[i][0] * v[0] + m[i][1] * v[1] + m[i][2] * v[2])
}
fn mm(a: M3, b: M3) -> M3 {
    std::array::from_fn(|i| std::array::from_fn(|j| (0..3).map(|k| a[i][k] * b[k][j]).sum()))
}
fn transpose(a: M3) -> M3 {
    std::array::from_fn(|i| std::array::from_fn(|j| a[j][i]))
}
fn rodrigues(w: [f64; 3]) -> M3 {
    let angle = norm(w);
    if angle == 0.0 {
        return [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
    }
    let k = [w[0] / angle, w[1] / angle, w[2] / angle];
    let (s, c) = angle.sin_cos();
    let skew = [[0.0, -k[2], k[1]], [k[2], 0.0, -k[0]], [-k[1], k[0], 0.0]];
    let sq = mm(skew, skew);
    std::array::from_fn(|i| {
        std::array::from_fn(|j| {
            let identity = if i == j { 1.0 } else { 0.0 };
            identity + s * skew[i][j] + (1.0 - c) * sq[i][j]
        })
    })
}
/// Angle (radians) of `a b^T`.
fn rotation_error(a: M3, b: M3) -> f64 {
    // atan2 of the skew and symmetric parts keeps full precision near zero,
    // unlike acos of the trace.
    let r = mm(a, transpose(b));
    let sine = norm([r[2][1] - r[1][2], r[0][2] - r[2][0], r[1][0] - r[0][1]]) / 2.0;
    let cosine = (r[0][0] + r[1][1] + r[2][2] - 1.0) / 2.0;
    sine.atan2(cosine)
}
fn look_at(center: [f64; 3], target: [f64; 3]) -> Result<RigidPose, Box<dyn std::error::Error>> {
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
struct TruthCamera {
    identity: CameraGeneration,
    pose: RigidPose,
    intrinsics: PinholeIntrinsics,
    distortion: RadialDistortion,
}

struct Fixture {
    truth_cameras: Vec<TruthCamera>,
    truth_points: Vec<(u64, [f64; 3])>,
    problem: BundleProblem,
}

fn distort_project(
    camera: &TruthCamera,
    world: [f64; 3],
) -> Result<[f64; 2], Box<dyn std::error::Error>> {
    let p = camera.pose.transform(world)?;
    let (xn, yn) = (p[0] / p[2], p[1] / p[2]);
    let r2 = xn * xn + yn * yn;
    let d = 1.0 + camera.distortion.k1 * r2 + camera.distortion.k2 * r2 * r2;
    let [fx, fy] = camera.intrinsics.focal_lengths();
    let [cx, cy] = camera.intrinsics.principal_point();
    Ok([fx * d * xn + cx, fy * d * yn + cy])
}

struct Spec {
    cameras: usize,
    landmarks: usize,
    noise_px: f64,
    distortion: RadialDistortion,
    refinement: IntrinsicsRefinement,
    calibrated_reference: bool,
    seed: u64,
}

fn fixture(spec: &Spec) -> Result<Fixture, Box<dyn std::error::Error>> {
    let mut rng = Rng(spec.seed);
    let mut truth_cameras = Vec::new();
    for i in 0..spec.cameras {
        let angle = std::f64::consts::TAU * i as f64 / spec.cameras as f64 + 0.3;
        // Varied radius, mounting height, and aim point: optical axes do not
        // share a common point, avoiding the orbital critical configuration.
        let radius = 6.5 + 1.5 * (i % 3) as f64;
        let height = [1.2, 4.5, 2.8, 6.0, 1.8, 3.6][i % 6];
        let center = [radius * angle.cos(), radius * angle.sin(), height];
        let aim = 2.1 * i as f64;
        let target = [aim.cos(), aim.sin(), 0.4 * (i % 3) as f64 - 0.2];
        let fx = 800.0 + 30.0 * i as f64;
        truth_cameras.push(TruthCamera {
            identity: CameraGeneration {
                camera: 100 + i as u64,
                intrinsics: 7,
                extrinsics: 11,
            },
            pose: look_at(center, target)?,
            intrinsics: PinholeIntrinsics::new(
                1920,
                1080,
                fx,
                fx * 1.004,
                960.0 + 6.0 * i as f64,
                540.0 - 5.0 * i as f64,
            )?,
            distortion: spec.distortion,
        });
    }
    let mut truth_points = Vec::new();
    for i in 0..spec.landmarks {
        truth_points.push((
            1000 + i as u64,
            [
                rng.uniform(-2.5, 2.5),
                rng.uniform(-2.5, 2.5),
                rng.uniform(-1.0, 2.0),
            ],
        ));
    }
    let mut observations = Vec::new();
    for camera in &truth_cameras {
        for &(landmark, world) in &truth_points {
            let clean = distort_project(camera, world)?;
            let pixel = [
                clean[0] + spec.noise_px * rng.gaussian(),
                clean[1] + spec.noise_px * rng.gaussian(),
            ];
            if !camera.intrinsics.contains(pixel) {
                return Err("fixture landmark left the image".into());
            }
            observations.push(BundleObservation {
                camera: camera.identity.camera,
                landmark,
                pixel,
            });
        }
    }
    // Scale anchor: the translation component most sensitive to scale about camera 0.
    let c0 = truth_cameras[0].pose.center();
    let c1 = truth_cameras[1].pose.center();
    let lever = mv(
        truth_cameras[1].pose.rotation(),
        [c0[0] - c1[0], c0[1] - c1[1], c0[2] - c1[2]],
    );
    let scale_axis = (0..3)
        .max_by(|a, b| lever[*a].abs().total_cmp(&lever[*b].abs()))
        .ok_or("axis")?;
    let mut cameras = Vec::new();
    for (i, truth) in truth_cameras.iter().enumerate() {
        let [fx, fy] = truth.intrinsics.focal_lengths();
        let [cx, cy] = truth.intrinsics.principal_point();
        // One focal factor keeps the supplied aspect equal to truth, as an
        // aspect-held refinement requires; the principal point is perturbed freely.
        let focal_factor = 1.0 + rng.uniform(-0.03, 0.03);
        let principal = [rng.uniform(-12.0, 12.0), rng.uniform(-12.0, 12.0)];
        let calibrated = i == 0 && spec.calibrated_reference;
        let intrinsics = if calibrated {
            truth.intrinsics
        } else {
            PinholeIntrinsics::new(
                1920,
                1080,
                fx * focal_factor,
                fy * focal_factor,
                cx + principal[0],
                cy + principal[1],
            )?
        };
        let pose = if i == 0 {
            truth.pose // gauge: reference pose held at truth
        } else {
            let w = [
                rng.uniform(-0.03, 0.03),
                rng.uniform(-0.03, 0.03),
                rng.uniform(-0.03, 0.03),
            ];
            let rotation = mm(rodrigues(w), truth.pose.rotation());
            let center = truth.pose.center();
            let moved = [
                center[0] + rng.uniform(-0.25, 0.25),
                center[1] + rng.uniform(-0.25, 0.25),
                center[2] + rng.uniform(-0.25, 0.25),
            ];
            let mut translation = mv(rotation, moved).map(|x| -x);
            if i == 1 {
                // gauge: scale-anchor component held at truth
                translation[scale_axis] = truth.pose.translation()[scale_axis];
            }
            RigidPose::new(rotation, translation)?
        };
        cameras.push(BundleCamera {
            identity: truth.identity,
            intrinsics,
            distortion: if calibrated {
                truth.distortion
            } else {
                RadialDistortion::NONE
            },
            pose,
            refinement: if calibrated {
                IntrinsicsRefinement::FIXED
            } else {
                spec.refinement
            },
        });
    }
    let landmarks = truth_points
        .iter()
        .map(|&(landmark, world)| BundleLandmark {
            landmark,
            position: [
                world[0] + rng.uniform(-0.2, 0.2),
                world[1] + rng.uniform(-0.2, 0.2),
                world[2] + rng.uniform(-0.2, 0.2),
            ],
        })
        .collect();
    Ok(Fixture {
        problem: BundleProblem {
            basis: GeometryBasis::new(3, 5)?,
            cameras,
            landmarks,
            observations,
            gauge: BundleGauge {
                reference_camera: truth_cameras[0].identity.camera,
                scale_camera: truth_cameras[1].identity.camera,
                scale_axis,
            },
        },
        truth_cameras,
        truth_points,
    })
}

fn spec(noise_px: f64) -> Spec {
    Spec {
        cameras: 6,
        landmarks: 48,
        noise_px,
        distortion: RadialDistortion::NONE,
        refinement: IntrinsicsRefinement::FOCAL_AND_PRINCIPAL_POINT,
        calibrated_reference: false,
        seed: 0x5EED_BA11,
    }
}

fn solve(problem: &BundleProblem) -> Result<BundleAdjustment, BundleAdjustmentError> {
    let mut budget = WorkBudget::new(2_000_000_000);
    bundle_adjust(problem, BundleOptions::default(), &mut budget)
}

struct Errors {
    rotation_rad: f64,
    center_m: f64,
    focal_px: f64,
    principal_px: f64,
    landmark_m: f64,
    k1: f64,
}

fn errors(
    fixture: &Fixture,
    result: &BundleAdjustment,
) -> Result<Errors, Box<dyn std::error::Error>> {
    let mut e = Errors {
        rotation_rad: 0.0,
        center_m: 0.0,
        focal_px: 0.0,
        principal_px: 0.0,
        landmark_m: 0.0,
        k1: 0.0,
    };
    for truth in &fixture.truth_cameras {
        let adjusted = result.camera(truth.identity.camera).ok_or("camera")?;
        e.rotation_rad = e.rotation_rad.max(rotation_error(
            adjusted.pose.rotation(),
            truth.pose.rotation(),
        ));
        let (a, b) = (adjusted.pose.center(), truth.pose.center());
        e.center_m = e
            .center_m
            .max(norm([a[0] - b[0], a[1] - b[1], a[2] - b[2]]));
        let (fa, fb) = (
            adjusted.intrinsics.focal_lengths(),
            truth.intrinsics.focal_lengths(),
        );
        let (pa, pb) = (
            adjusted.intrinsics.principal_point(),
            truth.intrinsics.principal_point(),
        );
        for k in 0..2 {
            e.focal_px = e.focal_px.max((fa[k] - fb[k]).abs());
            e.principal_px = e.principal_px.max((pa[k] - pb[k]).abs());
        }
        e.k1 =
            e.k1.max((adjusted.distortion.k1 - truth.distortion.k1).abs());
    }
    for &(landmark, world) in &fixture.truth_points {
        let p = result.landmark(landmark).ok_or("landmark")?.position;
        e.landmark_m = e
            .landmark_m
            .max(norm([p[0] - world[0], p[1] - world[1], p[2] - world[2]]));
    }
    Ok(e)
}

fn report_line(label: &str, result: &BundleAdjustment, e: &Errors) {
    let r = result.report();
    println!(
        "{label}: rms {:.6e} -> {:.6e} px; iterations {} (accepted {}, rejected {}); work {} units; \
         {:?}; max errors: rotation {:.3e} rad, center {:.3e} m, focal {:.3e} px, principal {:.3e} px, \
         landmark {:.3e} m, k1 {:.3e}; sigma {:?}",
        r.initial_rms_px,
        r.final_rms_px,
        r.iterations,
        r.accepted_steps,
        r.rejected_steps,
        r.work_units,
        r.convergence,
        e.rotation_rad,
        e.center_m,
        e.focal_px,
        e.principal_px,
        e.landmark_m,
        e.k1,
        result.observation_sigma_px(),
    );
}

#[test]
fn exact_data_converges_to_ground_truth_in_the_declared_gauge() -> TestResult {
    let fixture = fixture(&spec(0.0))?;
    let result = solve(&fixture.problem)?;
    let e = errors(&fixture, &result)?;
    report_line("exact", &result, &e);
    let report = result.report();
    assert!(
        report.initial_rms_px > 20.0,
        "perturbation must be material"
    );
    assert!(report.final_rms_px < 1e-6, "sub-pixel (in fact ~exact) RMS");
    assert!(report.convergence.is_some());
    assert!(report.iterations <= report.max_iterations);
    assert!(report.work_units > 0);
    assert_eq!(report.residual_count, 2 * 6 * 48);
    // 6 cameras x (focal, cx, cy) + 5 free poses x 6 - 1 scale anchor + 48 x 3 landmarks.
    assert_eq!(report.parameter_count, 18 + 29 + 144);
    assert!(e.rotation_rad < 1e-8);
    assert!(e.center_m < 1e-7);
    assert!(e.focal_px < 1e-5);
    assert!(e.principal_px < 1e-5);
    assert!(e.landmark_m < 1e-7);
    // Gauge parameters are held bit-exactly.
    let reference = result.camera(100).ok_or("reference")?;
    assert_eq!(reference.pose, fixture.problem.cameras[0].pose);
    assert_eq!(
        reference.covariance.parameters,
        [
            BundleParameter::Focal,
            BundleParameter::Cx,
            BundleParameter::Cy
        ]
    );
    assert_eq!(reference.covariance.fixed.len(), 9);
    let gauge = fixture.problem.gauge;
    let scale = result.camera(101).ok_or("scale")?;
    assert_eq!(
        scale.pose.translation()[gauge.scale_axis].to_bits(),
        fixture.problem.cameras[1].pose.translation()[gauge.scale_axis].to_bits()
    );
    assert!(
        scale
            .covariance
            .fixed
            .contains(&BundleParameter::Translation(gauge.scale_axis))
    );
    Ok(())
}

#[test]
fn three_cameras_twenty_four_landmarks_converge_sub_pixel() -> TestResult {
    let fixture = fixture(&Spec {
        cameras: 3,
        landmarks: 24,
        seed: 0x0DD5_EED5,
        calibrated_reference: true,
        ..spec(0.0)
    })?;
    let result = solve(&fixture.problem)?;
    let e = errors(&fixture, &result)?;
    report_line("3cam-24lm exact", &result, &e);
    assert!(result.report().final_rms_px < 1e-6);
    assert!(e.rotation_rad < 1e-7 && e.center_m < 1e-6 && e.landmark_m < 1e-6);
    assert!(e.focal_px < 1e-4 && e.principal_px < 1e-4);
    Ok(())
}

#[test]
fn seeded_pixel_noise_yields_noise_level_rms_and_positive_finite_covariance() -> TestResult {
    let sigma = 0.5;
    let fixture = fixture(&spec(sigma))?;
    let result = solve(&fixture.problem)?;
    let e = errors(&fixture, &result)?;
    report_line("noise 0.5px", &result, &e);
    let report = result.report();
    // Per-axis residual RMS shrinks by sqrt((m - n) / m) relative to sigma.
    let dof =
        (report.residual_count - report.parameter_count) as f64 / report.residual_count as f64;
    let expected_rms = sigma * dof.sqrt();
    println!("expected per-axis rms {expected_rms:.4} px");
    assert!(report.final_rms_px > 0.8 * expected_rms && report.final_rms_px < 1.2 * expected_rms);
    let (estimated_sigma, estimated) = result.observation_sigma_px();
    assert!(estimated);
    assert!((estimated_sigma - sigma).abs() < 0.15 * sigma);
    // Every free parameter's actual error is compared with its predicted standard
    // deviation. Both directions matter: a mean squared z far above 1 means the
    // covariance is overconfident; far below 1 means it is vacuously inflated.
    let mut z_values: Vec<(String, f64)> = Vec::new();
    let mut push = |label: String, error: f64, variance: f64| {
        assert!(
            variance.is_finite() && variance > 0.0,
            "{label} variance {variance}"
        );
        z_values.push((label, error / variance.sqrt()));
    };
    for camera in result.cameras() {
        let truth = fixture
            .truth_cameras
            .iter()
            .find(|t| t.identity == camera.identity)
            .ok_or("truth")?;
        let covariance = &camera.covariance;
        // Left-perturbation tangent error: R_est = exp([w]x) R_true.
        let r = mm(camera.pose.rotation(), transpose(truth.pose.rotation()));
        let w = [
            (r[2][1] - r[1][2]) / 2.0,
            (r[0][2] - r[2][0]) / 2.0,
            (r[1][0] - r[0][1]) / 2.0,
        ];
        let id = camera.identity.camera;
        for (i, parameter) in covariance.parameters.iter().enumerate() {
            let variance = covariance.matrix[i * covariance.parameters.len() + i];
            let error = match *parameter {
                BundleParameter::Rotation(k) => w[k],
                BundleParameter::Translation(k) => {
                    camera.pose.translation()[k] - truth.pose.translation()[k]
                }
                BundleParameter::Focal | BundleParameter::Fx => {
                    camera.intrinsics.focal_lengths()[0] - truth.intrinsics.focal_lengths()[0]
                }
                BundleParameter::Fy => {
                    camera.intrinsics.focal_lengths()[1] - truth.intrinsics.focal_lengths()[1]
                }
                BundleParameter::Cx => {
                    camera.intrinsics.principal_point()[0] - truth.intrinsics.principal_point()[0]
                }
                BundleParameter::Cy => {
                    camera.intrinsics.principal_point()[1] - truth.intrinsics.principal_point()[1]
                }
                BundleParameter::K1 => camera.distortion.k1 - truth.distortion.k1,
                BundleParameter::K2 => camera.distortion.k2 - truth.distortion.k2,
            };
            push(format!("camera {id} {parameter:?}"), error, variance);
        }
    }
    for &(landmark, world) in &fixture.truth_points {
        let adjusted = result.landmark(landmark).ok_or("landmark")?;
        for k in 0..3 {
            push(
                format!("landmark {landmark} axis {k}"),
                adjusted.position[k] - world[k],
                adjusted.covariance[k][k],
            );
        }
    }
    let count = z_values.len() as f64;
    let mean_square = z_values.iter().map(|(_, z)| z * z).sum::<f64>() / count;
    let worst = z_values
        .iter()
        .max_by(|a, b| a.1.abs().total_cmp(&b.1.abs()))
        .ok_or("no parameters")?;
    println!(
        "z-scores over {} free parameters: mean z^2 {mean_square:.3}, worst {} = {:.3}",
        z_values.len(),
        worst.0,
        worst.1
    );
    assert_eq!(z_values.len(), report.parameter_count);
    assert!(
        (0.3..3.0).contains(&mean_square),
        "covariance mis-scaled: mean z^2 {mean_square}"
    );
    assert!(worst.1.abs() < 5.0, "error outside 5 predicted sd");
    // Stated absolute tolerances for this 6-camera, 0.5 px, self-calibrating
    // geometry. The principal point / rotation trade-off dominates: cx error of
    // ~15 px at f ~ 800 px corresponds to ~0.02 rad, which the covariance predicts.
    assert!(e.landmark_m < 0.25, "landmark error {}", e.landmark_m);
    assert!(e.center_m < 0.4, "center error {}", e.center_m);
    assert!(e.focal_px < 25.0, "focal error {}", e.focal_px);
    assert!(e.principal_px < 40.0, "principal error {}", e.principal_px);
    assert!(e.rotation_rad < 0.05, "rotation error {}", e.rotation_rad);
    Ok(())
}

#[test]
fn radial_distortion_is_jointly_recovered() -> TestResult {
    let fixture = fixture(&Spec {
        distortion: RadialDistortion {
            k1: -0.08,
            k2: 0.01,
        },
        refinement: IntrinsicsRefinement::FULL,
        ..spec(0.0)
    })?;
    let result = solve(&fixture.problem)?;
    let e = errors(&fixture, &result)?;
    report_line("radial exact", &result, &e);
    assert!(result.report().final_rms_px < 1e-6);
    assert!(e.k1 < 1e-5 && e.focal_px < 1e-3 && e.landmark_m < 1e-6);
    Ok(())
}

fn bits(result: &BundleAdjustment) -> Vec<u64> {
    let mut out = Vec::new();
    for camera in result.cameras() {
        out.extend(camera.pose.rotation().iter().flatten().map(|x| x.to_bits()));
        out.extend(camera.pose.translation().iter().map(|x| x.to_bits()));
        out.extend(
            camera
                .intrinsics
                .focal_lengths()
                .iter()
                .map(|x| x.to_bits()),
        );
        out.extend(
            camera
                .intrinsics
                .principal_point()
                .iter()
                .map(|x| x.to_bits()),
        );
        out.push(camera.distortion.k1.to_bits());
        out.push(camera.distortion.k2.to_bits());
        out.extend(camera.covariance.matrix.iter().map(|x| x.to_bits()));
    }
    for landmark in result.landmarks() {
        out.extend(landmark.position.iter().map(|x| x.to_bits()));
        out.extend(landmark.covariance.iter().flatten().map(|x| x.to_bits()));
    }
    let r = result.report();
    out.extend(
        [
            r.initial_rms_px,
            r.final_rms_px,
            r.final_damping,
            result.observation_sigma_px().0,
        ]
        .map(f64::to_bits),
    );
    out.extend([r.iterations as u64, r.accepted_steps as u64, r.work_units]);
    out
}

#[test]
fn repeated_and_permuted_runs_are_bit_identical() -> TestResult {
    let fixture = fixture(&spec(0.3))?;
    let first = bits(&solve(&fixture.problem)?);
    let second = bits(&solve(&fixture.problem)?);
    assert_eq!(first, second);
    let mut permuted = fixture.problem.clone();
    permuted.cameras.reverse();
    permuted.landmarks.reverse();
    permuted.observations.reverse();
    assert_eq!(first, bits(&solve(&permuted)?));
    println!("bit-identical over {} f64/u64 words", first.len());
    Ok(())
}

#[test]
fn single_camera_and_thin_observation_sets_are_under_constrained() -> TestResult {
    let base = fixture(&spec(0.0))?;
    let mut single = base.problem.clone();
    single.cameras.truncate(1);
    single.observations.retain(|o| o.camera == 100);
    assert_eq!(
        solve(&single).err(),
        Some(BundleAdjustmentError::UnderConstrained(
            UnderConstrainedReason::TooFewCameras { cameras: 1 }
        ))
    );

    let mut one_view = base.problem.clone();
    one_view
        .observations
        .retain(|o| o.landmark != 1005 || o.camera == 102);
    assert_eq!(
        solve(&one_view).err(),
        Some(BundleAdjustmentError::UnderConstrained(
            UnderConstrainedReason::LandmarkUnderObserved {
                landmark: 1005,
                cameras: 1
            }
        ))
    );

    let mut thin_camera = base.problem.clone();
    thin_camera
        .observations
        .retain(|o| o.camera != 103 || o.landmark < 1004);
    assert_eq!(
        solve(&thin_camera).err(),
        Some(BundleAdjustmentError::UnderConstrained(
            UnderConstrainedReason::CameraUnderObserved {
                camera: 103,
                observations: 4,
                parameters: 9
            }
        ))
    );

    // Cameras {100,101} and {102,103} share no landmark: two independent gauges.
    let mut split = base.problem.clone();
    split.observations.retain(|o| {
        let low = o.landmark < 1024;
        (o.camera <= 101) == low
    });
    assert_eq!(
        solve(&split).err(),
        Some(BundleAdjustmentError::UnderConstrained(
            UnderConstrainedReason::DisconnectedCamera { camera: 102 }
        ))
    );
    Ok(())
}

#[test]
fn nan_observation_is_a_typed_non_finite_error() -> TestResult {
    let mut problem = fixture(&spec(0.0))?.problem;
    problem.observations[17].pixel[1] = f64::NAN;
    let o = problem.observations[17];
    assert_eq!(
        solve(&problem).err(),
        Some(BundleAdjustmentError::NonFiniteInput(
            NonFiniteInput::Observation {
                camera: o.camera,
                landmark: o.landmark
            }
        ))
    );
    let mut problem = fixture(&spec(0.0))?.problem;
    problem.landmarks[3].position[0] = f64::INFINITY;
    assert_eq!(
        solve(&problem).err(),
        Some(BundleAdjustmentError::NonFiniteInput(
            NonFiniteInput::Landmark {
                landmark: problem.landmarks[3].landmark
            }
        ))
    );
    Ok(())
}

#[test]
fn exhausted_budgets_are_typed_failures_not_success() -> TestResult {
    let problem = fixture(&spec(0.0))?.problem;
    let mut budget = WorkBudget::new(2_000_000_000);
    let options = BundleOptions {
        max_iterations: 1,
        ..BundleOptions::default()
    };
    match bundle_adjust(&problem, options, &mut budget) {
        Err(BundleAdjustmentError::BudgetExhausted {
            kind: BudgetKind::Iterations,
            report,
        }) => {
            assert_eq!(report.iterations, 1);
            assert_eq!(report.convergence, None);
            assert!(report.final_rms_px > 1e-3);
        }
        other => return Err(format!("expected iteration exhaustion, got {other:?}").into()),
    }
    let mut small = WorkBudget::new(50_000);
    match bundle_adjust(&problem, BundleOptions::default(), &mut small) {
        Err(BundleAdjustmentError::BudgetExhausted {
            kind: BudgetKind::WorkUnits,
            report,
        }) => assert!(report.work_units <= 50_000 && report.convergence.is_none()),
        other => return Err(format!("expected work exhaustion, got {other:?}").into()),
    }
    let cancelled = AtomicBool::new(true);
    let mut budget = WorkBudget::cancellable(2_000_000_000, &cancelled);
    assert_eq!(
        bundle_adjust(&problem, BundleOptions::default(), &mut budget).err(),
        Some(BundleAdjustmentError::Cancelled)
    );
    Ok(())
}

#[test]
fn depth_unobservable_landmark_is_a_typed_singular_system() -> TestResult {
    let mut fixture = fixture(&spec(0.0))?;
    // Camera 103 is re-seated at camera 102's optical center with a small rotation,
    // and landmark 1000 is seen only by that concentric pair: its depth is unobservable.
    let base = fixture.truth_cameras[2];
    let rotation = mm(rodrigues([0.01, -0.02, 0.015]), base.pose.rotation());
    let moved = RigidPose::from_center(rotation, base.pose.center())?;
    fixture.truth_cameras[3].pose = moved;
    fixture.problem.cameras[3].pose = moved;
    let truth3 = fixture.truth_cameras[3];
    for o in &mut fixture.problem.observations {
        if o.camera == 103 {
            let world = fixture
                .truth_points
                .iter()
                .find(|p| p.0 == o.landmark)
                .ok_or("point")?
                .1;
            o.pixel = distort_project(&truth3, world)?;
        }
    }
    fixture
        .problem
        .observations
        .retain(|o| o.landmark != 1000 || o.camera == 102 || o.camera == 103);
    assert_eq!(
        solve(&fixture.problem).err(),
        Some(BundleAdjustmentError::Singular(
            SingularStage::LandmarkCovariance { landmark: 1000 }
        ))
    );
    Ok(())
}

#[test]
fn camera_generation_changes_invalidate_the_result() -> TestResult {
    let fixture = fixture(&spec(0.0))?;
    let result = solve(&fixture.problem)?;
    let current: Vec<CameraGeneration> = fixture.truth_cameras.iter().map(|c| c.identity).collect();
    assert_eq!(result.dependencies(), current);
    assert_eq!(result.validity(&current), BundleValidity::Current);
    assert!(!result.is_invalidated_by(&current));

    let mut zoomed = current.clone();
    zoomed[2].intrinsics += 1;
    assert!(result.is_invalidated_by(&zoomed));
    assert_eq!(
        result.validity(&zoomed),
        BundleValidity::Invalidated(vec![fss_geometry::CameraInvalidation {
            camera: 102,
            cause: InvalidationCause::IntrinsicsChanged
        }])
    );
    let mut moved = current.clone();
    moved[1].extrinsics += 1;
    moved.remove(3);
    assert_eq!(
        result.validity(&moved),
        BundleValidity::Invalidated(vec![
            fss_geometry::CameraInvalidation {
                camera: 101,
                cause: InvalidationCause::ExtrinsicsChanged
            },
            fss_geometry::CameraInvalidation {
                camera: 103,
                cause: InvalidationCause::CameraMissing
            },
        ])
    );
    let converged = result.report().convergence;
    assert!(matches!(
        converged,
        Some(
            Convergence::ZeroResidual
                | Convergence::StepTolerance
                | Convergence::CostStalled
                | Convergence::Gradient
        )
    ));
    Ok(())
}

#[test]
fn free_fx_fy_cx_cy_everywhere_is_a_detected_self_calibration_ambiguity() -> TestResult {
    // With zero skew as the only intrinsic prior, four cameras cannot fix the
    // projective-to-metric ambiguity. The solver must refuse, not report covariance.
    let fixture = fixture(&Spec {
        refinement: IntrinsicsRefinement {
            focal: FocalRefinement::Independent,
            principal_point: true,
            radial: false,
        },
        cameras: 4,
        ..spec(0.0)
    })?;
    assert_eq!(
        solve(&fixture.problem).err(),
        Some(BundleAdjustmentError::Singular(
            SingularStage::CameraCovariance
        ))
    );
    Ok(())
}
