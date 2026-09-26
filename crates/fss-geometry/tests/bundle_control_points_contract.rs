#![forbid(unsafe_code)]
//! Control-point gauge contracts for the reference bundle adjuster.
//!
//! Surveyed control points are held fixed; they contribute residuals but no
//! parameters. With three or more observed, non-collinear control points the gauge
//! is fixed without any reference pose or scale anchor, so every camera pose is free
//! and recovered parameters are compared with metric ground truth directly.
//! Fixtures are generated in-test from a seeded SplitMix64 stream; passing these
//! contracts does not establish accuracy on real camera footage.

use fss_geometry::{
    AnchoredBundleProblem, BundleAdjustment, BundleAdjustmentError, BundleCamera,
    BundleControlPoint, BundleGauge, BundleGaugeChoice, BundleInputError, BundleLandmark,
    BundleObservation, BundleOptions, BundleParameter, BundleProblem, CameraGeneration,
    GeometryBasis, IntrinsicsRefinement, NonFiniteInput, PinholeIntrinsics, RadialDistortion,
    RigidPose, UnderConstrainedReason, WorkBudget, bundle_adjust, bundle_adjust_anchored,
    control_points_span_plane,
};

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
fn rotation_error(a: M3, b: M3) -> f64 {
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

struct Truth {
    identity: CameraGeneration,
    pose: RigidPose,
    intrinsics: PinholeIntrinsics,
}

struct Fixture {
    truth: Vec<Truth>,
    truth_ties: Vec<(u64, [f64; 3])>,
    problem: AnchoredBundleProblem,
}

const CONTROL_BASE: u64 = 1;
const TIE_BASE: u64 = 500;

/// Five cameras on a varied ring; `controls` surveyed points plus `ties` free
/// points, all seen by every camera; poses and ties are perturbed.
fn fixture(
    controls: usize,
    ties: usize,
    noise_px: f64,
    seed: u64,
) -> Result<Fixture, Box<dyn std::error::Error>> {
    let mut rng = Rng(seed);
    let mut truth = Vec::new();
    for i in 0..5 {
        let angle = std::f64::consts::TAU * i as f64 / 5.0 + 0.2;
        let radius = 7.0 + (i % 2) as f64;
        let center = [
            radius * angle.cos(),
            radius * angle.sin(),
            2.5 + 0.7 * i as f64,
        ];
        let aim = 1.7 * i as f64;
        let target = [0.4 * aim.cos(), 0.4 * aim.sin(), 0.3];
        let fx = 900.0 + 25.0 * i as f64;
        truth.push(Truth {
            identity: CameraGeneration {
                camera: 10 + i as u64,
                intrinsics: 3,
                extrinsics: 4,
            },
            pose: look_at(center, target)?,
            intrinsics: PinholeIntrinsics::new(1920, 1080, fx, fx * 1.002, 960.0, 540.0)?,
        });
    }
    let mut control_points = Vec::new();
    for i in 0..controls {
        control_points.push(BundleControlPoint {
            landmark: CONTROL_BASE + i as u64,
            position: [
                rng.uniform(-2.5, 2.5),
                rng.uniform(-2.5, 2.5),
                rng.uniform(-0.5, 1.5),
            ],
        });
    }
    let mut truth_ties = Vec::new();
    for i in 0..ties {
        truth_ties.push((
            TIE_BASE + i as u64,
            [
                rng.uniform(-2.0, 2.0),
                rng.uniform(-2.0, 2.0),
                rng.uniform(-0.8, 1.8),
            ],
        ));
    }
    let mut observations = Vec::new();
    for camera in &truth {
        let points = control_points
            .iter()
            .map(|c| (c.landmark, c.position))
            .chain(truth_ties.iter().copied());
        for (landmark, world) in points {
            let clean = camera.pose.project(camera.intrinsics, world)?;
            let pixel = [
                clean[0] + noise_px * rng.gaussian(),
                clean[1] + noise_px * rng.gaussian(),
            ];
            if !camera.intrinsics.contains(pixel) {
                return Err("fixture point left the image".into());
            }
            observations.push(BundleObservation {
                camera: camera.identity.camera,
                landmark,
                pixel,
            });
        }
    }
    let mut cameras = Vec::new();
    for camera in &truth {
        let w = [
            rng.uniform(-0.02, 0.02),
            rng.uniform(-0.02, 0.02),
            rng.uniform(-0.02, 0.02),
        ];
        let rotation = mm(rodrigues(w), camera.pose.rotation());
        let c = camera.pose.center();
        let moved = [
            c[0] + rng.uniform(-0.2, 0.2),
            c[1] + rng.uniform(-0.2, 0.2),
            c[2] + rng.uniform(-0.2, 0.2),
        ];
        cameras.push(BundleCamera {
            identity: camera.identity,
            intrinsics: camera.intrinsics,
            distortion: RadialDistortion::NONE,
            pose: RigidPose::from_center(rotation, moved)?,
            refinement: IntrinsicsRefinement::FIXED,
        });
    }
    let landmarks = truth_ties
        .iter()
        .map(|&(landmark, p)| BundleLandmark {
            landmark,
            position: [
                p[0] + rng.uniform(-0.15, 0.15),
                p[1] + rng.uniform(-0.15, 0.15),
                p[2] + rng.uniform(-0.15, 0.15),
            ],
        })
        .collect();
    Ok(Fixture {
        truth,
        truth_ties,
        problem: AnchoredBundleProblem {
            basis: GeometryBasis::new(3, 5)?,
            cameras,
            landmarks,
            control_points,
            observations,
            gauge: BundleGaugeChoice::ControlPoints,
        },
    })
}

fn solve(problem: &AnchoredBundleProblem) -> Result<BundleAdjustment, BundleAdjustmentError> {
    bundle_adjust_anchored(
        problem,
        BundleOptions::default(),
        &mut WorkBudget::new(2_000_000_000),
    )
}

fn max_pose_errors(
    fixture: &Fixture,
    result: &BundleAdjustment,
) -> Result<(f64, f64), Box<dyn std::error::Error>> {
    let mut rotation = 0.0_f64;
    let mut center = 0.0_f64;
    for truth in &fixture.truth {
        let adjusted = result.camera(truth.identity.camera).ok_or("camera")?;
        rotation = rotation.max(rotation_error(
            adjusted.pose.rotation(),
            truth.pose.rotation(),
        ));
        let (a, b) = (adjusted.pose.center(), truth.pose.center());
        center = center.max(norm([a[0] - b[0], a[1] - b[1], a[2] - b[2]]));
    }
    Ok((rotation, center))
}

#[test]
fn control_points_fix_a_metric_gauge_without_reference_pose_or_scale_anchor() -> TestResult {
    let fixture = fixture(10, 16, 0.0, 0xC017_2001)?;
    let result = solve(&fixture.problem)?;
    let report = result.report();
    let (rotation, center) = max_pose_errors(&fixture, &result)?;
    println!(
        "control gauge exact: rms {:.3e} -> {:.3e} px, rotation {rotation:.3e} rad, center {center:.3e} m, {:?}",
        report.initial_rms_px, report.final_rms_px, report.convergence
    );
    assert!(
        report.initial_rms_px > 10.0,
        "perturbation must be material"
    );
    assert!(report.final_rms_px < 1e-6);
    assert_eq!(result.gauge(), BundleGaugeChoice::ControlPoints);
    assert_eq!(result.control_points(), &fixture.problem.control_points[..]);
    // Every observation (control and tie) is a residual; only poses and ties are unknown.
    assert_eq!(report.residual_count, 2 * 5 * (10 + 16));
    assert_eq!(report.parameter_count, 5 * 6 + 16 * 3);
    // Metric: absolute pose and tie errors against truth, with no alignment step.
    assert!(rotation < 1e-9 && center < 1e-8);
    for &(landmark, world) in &fixture.truth_ties {
        let p = result.landmark(landmark).ok_or("tie")?.position;
        assert!(norm([p[0] - world[0], p[1] - world[1], p[2] - world[2]]) < 1e-8);
    }
    // No pose parameter is fixed by a fabricated gauge; control points are not landmarks.
    for camera in result.cameras() {
        assert_eq!(camera.covariance.parameters.len(), 6);
        assert!(!camera.covariance.fixed.iter().any(|p| matches!(
            p,
            BundleParameter::Rotation(_) | BundleParameter::Translation(_)
        )));
    }
    assert_eq!(result.landmarks().len(), 16);
    assert!(result.landmark(CONTROL_BASE).is_none());
    Ok(())
}

#[test]
fn noisy_control_gauge_is_sub_pixel_with_finite_covariance_and_bit_identical() -> TestResult {
    let fixture = fixture(8, 12, 0.4, 0x05EE_D0C7)?;
    let first = solve(&fixture.problem)?;
    let report = first.report();
    let (rotation, center) = max_pose_errors(&fixture, &first)?;
    println!(
        "control gauge 0.4px: rms {:.4} -> {:.4} px, rotation {rotation:.3e} rad, center {center:.3e} m",
        report.initial_rms_px, report.final_rms_px
    );
    assert!(report.final_rms_px < 0.5);
    assert!(center < 0.05 && rotation < 5e-3);
    for camera in first.cameras() {
        let k = camera.covariance.parameters.len();
        for i in 0..k {
            let v = camera.covariance.matrix[i * k + i];
            assert!(v.is_finite() && v > 0.0);
        }
    }
    let second = solve(&fixture.problem)?;
    let bits = |r: &BundleAdjustment| -> Vec<u64> {
        let mut out = Vec::new();
        for c in r.cameras() {
            out.extend(c.pose.rotation().iter().flatten().map(|x| x.to_bits()));
            out.extend(c.pose.translation().iter().map(|x| x.to_bits()));
            out.extend(c.covariance.matrix.iter().map(|x| x.to_bits()));
        }
        for l in r.landmarks() {
            out.extend(l.position.iter().map(|x| x.to_bits()));
            out.extend(l.covariance.iter().flatten().map(|x| x.to_bits()));
        }
        out.push(r.report().final_rms_px.to_bits());
        out.push(r.report().work_units);
        out
    };
    assert_eq!(bits(&first), bits(&second));
    let mut permuted = fixture.problem.clone();
    permuted.cameras.reverse();
    permuted.landmarks.reverse();
    permuted.control_points.reverse();
    permuted.observations.reverse();
    assert_eq!(bits(&first), bits(&solve(&permuted)?));
    Ok(())
}

#[test]
fn too_few_collinear_or_unanchored_control_sets_are_typed_refusals() -> TestResult {
    let base = fixture(10, 16, 0.0, 0xC017_2001)?;
    // Only two control points observed.
    let mut two = base.problem.clone();
    two.observations
        .retain(|o| o.landmark >= TIE_BASE || o.landmark < CONTROL_BASE + 2);
    assert_eq!(
        solve(&two).err(),
        Some(BundleAdjustmentError::UnderConstrained(
            UnderConstrainedReason::TooFewControlPoints { observed: 2 }
        ))
    );
    // Four exactly collinear control points (re-projected so data stay consistent).
    let mut collinear = base.problem.clone();
    collinear.control_points.truncate(4);
    for (i, c) in collinear.control_points.iter_mut().enumerate() {
        c.position = [-1.5 + i as f64, 0.5 - 0.5 * i as f64, 0.2 + 0.1 * i as f64];
    }
    collinear
        .observations
        .retain(|o| o.landmark >= TIE_BASE || o.landmark < CONTROL_BASE + 4);
    for o in &mut collinear.observations {
        if let Some(c) = collinear
            .control_points
            .iter()
            .find(|c| c.landmark == o.landmark)
        {
            let truth = base
                .truth
                .iter()
                .find(|t| t.identity.camera == o.camera)
                .ok_or("camera")?;
            o.pixel = truth.pose.project(truth.intrinsics, c.position)?;
        }
    }
    let positions: Vec<[f64; 3]> = collinear
        .control_points
        .iter()
        .map(|c| c.position)
        .collect();
    assert!(!control_points_span_plane(&positions));
    assert_eq!(
        solve(&collinear).err(),
        Some(BundleAdjustmentError::UnderConstrained(
            UnderConstrainedReason::CollinearControlPoints
        ))
    );
    // Cameras {13, 14} share ties only with each other and see just two control
    // points: their component's similarity gauge is free.
    let mut split = base.problem.clone();
    split.observations.retain(|o| {
        let low = o.camera <= 12;
        if o.landmark >= TIE_BASE {
            // Ties 500..507 for the low component, 508.. for the high one.
            (o.landmark < TIE_BASE + 8) == low
        } else {
            low || o.landmark < CONTROL_BASE + 2
        }
    });
    assert_eq!(
        solve(&split).err(),
        Some(BundleAdjustmentError::UnderConstrained(
            UnderConstrainedReason::UnanchoredCamera { camera: 13 }
        ))
    );
    Ok(())
}

#[test]
fn malformed_control_inputs_are_typed_errors() -> TestResult {
    let base = fixture(8, 10, 0.0, 0x0BAD_C0DE)?;
    let mut nan = base.problem.clone();
    nan.control_points[2].position[1] = f64::NAN;
    assert_eq!(
        solve(&nan).err(),
        Some(BundleAdjustmentError::NonFiniteInput(
            NonFiniteInput::ControlPoint {
                landmark: nan.control_points[2].landmark
            }
        ))
    );
    let mut nan_pixel = base.problem.clone();
    let o = nan_pixel.observations[3];
    nan_pixel.observations[3].pixel[0] = f64::NAN;
    assert_eq!(
        solve(&nan_pixel).err(),
        Some(BundleAdjustmentError::NonFiniteInput(
            NonFiniteInput::Observation {
                camera: o.camera,
                landmark: o.landmark
            }
        ))
    );
    let mut collision = base.problem.clone();
    collision.control_points[0].landmark = TIE_BASE;
    assert_eq!(
        solve(&collision).err(),
        Some(BundleAdjustmentError::InvalidInput(
            BundleInputError::DuplicateLandmark(TIE_BASE)
        ))
    );
    // Control points with the reference-pose gauge would over-fix it: refused.
    let mut mixed = base.problem.clone();
    mixed.gauge = BundleGaugeChoice::ReferencePose(BundleGauge {
        reference_camera: 10,
        scale_camera: 11,
        scale_axis: 0,
    });
    assert_eq!(
        solve(&mixed).err(),
        Some(BundleAdjustmentError::InvalidInput(
            BundleInputError::InvalidGauge
        ))
    );
    Ok(())
}

#[test]
fn reference_pose_choice_without_controls_matches_legacy_entry_point_bit_for_bit() -> TestResult {
    // The anchored entry point with the reference-pose gauge and no control points
    // is the legacy problem; its output must equal `bundle_adjust` bit for bit.
    let base = fixture(0, 24, 0.3, 0x001E_6AC7)?;
    let truth0 = &base.truth[0];
    let mut cameras = base.problem.cameras.clone();
    cameras[0].pose = truth0.pose;
    let legacy = BundleProblem {
        basis: base.problem.basis,
        cameras: cameras.clone(),
        landmarks: base.problem.landmarks.clone(),
        observations: base.problem.observations.clone(),
        gauge: BundleGauge {
            reference_camera: 10,
            scale_camera: 12,
            scale_axis: 2,
        },
    };
    let anchored = AnchoredBundleProblem {
        cameras,
        control_points: Vec::new(),
        gauge: BundleGaugeChoice::ReferencePose(legacy.gauge),
        ..base.problem.clone()
    };
    let mut budget = WorkBudget::new(2_000_000_000);
    let a = bundle_adjust(&legacy, BundleOptions::default(), &mut budget)?;
    let b = solve(&anchored)?;
    assert_eq!(a.report(), b.report());
    assert_eq!(b.gauge(), BundleGaugeChoice::ReferencePose(legacy.gauge));
    for (x, y) in a.cameras().iter().zip(b.cameras()) {
        assert_eq!(x.pose, y.pose);
        assert_eq!(x.covariance, y.covariance);
    }
    assert_eq!(a.landmarks(), b.landmarks());
    Ok(())
}
