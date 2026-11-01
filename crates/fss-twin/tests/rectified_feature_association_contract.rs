#![forbid(unsafe_code)]
//! Independently rendered distorted planes -> native correction/features -> native geometry.
//! These are authored optical fixtures, not evidence of a deployed lens calibration.
mod common;

use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_core::ContentDigest;
use fss_geometry::triangulation::TriangulationOptions;
use fss_geometry::{GeometryError, PinholeIntrinsics, RigidPose, WorkBudget};
use fss_twin::feature_association::{
    AssociationError, AssociationOptions, FeatureHypothesisOutcome, FeatureView, associate_features,
};
use fss_twin::localization::LocalizationError;
use fss_twin::localization::native::{ExtractionOptions, GrayImage, extract_gray};
use fss_twin::multiview_feature_association::{ComponentOutcome, associate_multiview_features};
use fss_twin::rectification::{
    LensDistortion, LumaRange, RawFrameIdentity, RawGrayFrame, RawLocalizationError,
    RectificationError, RectificationPlan, RectificationSpec, RectifiedFeatures,
    extract_raw_features,
};
use fss_twin::{ProjectionError, PropertyTwin, TrackingCamera};

type Test<T = ()> = Result<T, Box<dyn Error>>;
const WORK: u64 = 500_000_000;
const WIDTH: u32 = 192;
const HEIGHT: u32 = 128;
const ROTATION: [[f64; 3]; 3] = [[1., 0., 0.], [0., 1., 0.], [0., 0., 1.]];

fn brown() -> LensDistortion {
    LensDistortion::BrownConrady {
        radial: [-0.12, 0.01, 0.0003],
        tangential: [0.001, -0.002],
    }
}
fn fisheye() -> LensDistortion {
    LensDistortion::Fisheye {
        coefficients: [0.03, -0.001, 0.0002, 0.00001],
    }
}
fn spec(camera: u8, distortion: LensDistortion) -> Test<RectificationSpec> {
    Ok(RectificationSpec {
        source: PinholeIntrinsics::new(256, 192, 160., 160., 128., 96.)?,
        target: PinholeIntrinsics::new(WIDTH, HEIGHT, 120., 120., 96., 64.)?,
        distortion,
        maximum_radius: 1.1,
        source_domain: [camera + 20; 32],
        calibration: [camera + 30; 32],
        range: LumaRange::Full,
    })
}
fn options() -> ExtractionOptions {
    ExtractionOptions {
        maximum_features: 64,
        ..ExtractionOptions::default()
    }
}
fn association_options() -> AssociationOptions {
    AssociationOptions {
        association_basis: [90; 32],
        camera_rig_digest: [91; 32],
        privacy_domain: 2,
        clock: 1,
        clock_evidence: [92; 32],
        reference_time_ns: 100,
        max_capture_span_ns: 20,
        maximum_hamming_distance: 64,
        ratio_percent: 75,
        maximum_epipolar_distance_pixels: 1.01,
        triangulation: TriangulationOptions::default(),
    }
}

fn texel(x: i32, y: i32) -> f64 {
    let mut hash =
        (x as u32).wrapping_mul(0x9e37_79b9) ^ (y as u32).wrapping_mul(0x85eb_ca6b) ^ 0x1234_5678;
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x7feb_352d);
    hash ^= hash >> 15;
    f64::from(20 + hash % 216)
}

// Continuous, repeatable billboard radiance. Camera translation changes the ray's plane
// intersection, not the descriptor or a supplied correspondence. A two-pixel texture cell
// limits aliasing in the independently sampled source and subsequent native resampling.
fn texture(x: f64, y: f64) -> u8 {
    let (x, y) = (x / 2., y / 2.);
    let (ix, iy) = (x.floor() as i32, y.floor() as i32);
    let (dx, dy) = (x - f64::from(ix), y - f64::from(iy));
    let top = texel(ix, iy) * (1. - dx) + texel(ix + 1, iy) * dx;
    let bottom = texel(ix, iy + 1) * (1. - dx) + texel(ix + 1, iy + 1) * dx;
    (top * (1. - dy) + bottom * dy).round() as u8
}

// Independent source-camera ray inversion. This renderer does not call the production
// rectification plan, source_pixel, sampling_position, camera.project or camera.ray.
// Brown uses a bounded numerical-Jacobian Newton solve; fisheye solves the angular law.
fn ray(distortion: LensDistortion, xd: f64, yd: f64) -> [f64; 2] {
    match distortion {
        LensDistortion::Pinhole => [xd, yd],
        LensDistortion::BrownConrady {
            radial: [k1, k2, k3],
            tangential: [p1, p2],
        } => {
            let project = |x: f64, y: f64| {
                let r2 = x * x + y * y;
                let radial = 1. + k1 * r2 + k2 * r2.powi(2) + k3 * r2.powi(3);
                [
                    x * radial + 2. * p1 * x * y + p2 * (r2 + 2. * x * x),
                    y * radial + p1 * (r2 + 2. * y * y) + 2. * p2 * x * y,
                ]
            };
            let (mut x, mut y) = (xd, yd);
            for _ in 0..30 {
                let p = project(x, y);
                let (ex, ey) = (p[0] - xd, p[1] - yd);
                if ex.hypot(ey) < 1e-13 {
                    return [x, y];
                }
                let step = 1e-6;
                let px = project(x + step, y);
                let py = project(x, y + step);
                let (a, b) = ((px[0] - p[0]) / step, (py[0] - p[0]) / step);
                let (c, d) = ((px[1] - p[1]) / step, (py[1] - p[1]) / step);
                let det = a * d - b * c;
                x -= (d * ex - b * ey) / det;
                y -= (a * ey - c * ex) / det;
            }
            let residual = project(x, y);
            assert!(
                (residual[0] - xd).hypot(residual[1] - yd) < 1e-10,
                "independent Brown renderer failed to invert its fixture lens"
            );
            [x, y]
        }
        LensDistortion::Fisheye { coefficients: k } => {
            let radius = xd.hypot(yd);
            if radius == 0. {
                return [0., 0.];
            }
            let mut theta = radius;
            for _ in 0..30 {
                let t2 = theta * theta;
                let value = theta
                    * (1. + k[0] * t2 + k[1] * t2.powi(2) + k[2] * t2.powi(3) + k[3] * t2.powi(4));
                let slope = 1.
                    + 3. * k[0] * t2
                    + 5. * k[1] * t2.powi(2)
                    + 7. * k[2] * t2.powi(3)
                    + 9. * k[3] * t2.powi(4);
                theta -= (value - radius) / slope;
            }
            let scale = theta.tan() / radius;
            [xd * scale, yd * scale]
        }
    }
}

fn render(s: RectificationSpec, center_x: f64) -> Vec<u8> {
    let [width, height] = s.source.dimensions();
    let [fx, fy] = s.source.focal_lengths();
    let [cx, cy] = s.source.principal_point();
    (0..height)
        .flat_map(|y| {
            (0..width).map(move |x| {
                let [rx, ry] = ray(
                    s.distortion,
                    (f64::from(x) + 0.5 - cx) / fx,
                    (f64::from(y) + 0.5 - cy) / fy,
                );
                // Z=10, world X=center_x+10*rx, Y=10*ry. Billboard units are
                // independently chosen as twelve pixels per world unit.
                texture(120. * rx + 96. + 12. * center_x, 120. * ry + 64.)
            })
        })
        .collect()
}

fn raw<'a>(
    s: RectificationSpec,
    exposure: u8,
    pixels: &'a [u8],
    mask: &'a [u8],
    work: &mut WorkBudget<'_>,
) -> Result<RawGrayFrame<'a>, RectificationError> {
    RawGrayFrame::new(
        RawFrameIdentity {
            exposure: [exposure; 32],
            storage: ContentDigest::sha256(pixels).bytes(),
            allowed_mask: ContentDigest::sha256(mask).bytes(),
            image_domain: s.source_domain,
            calibration: s.calibration,
            dimensions: s.source.dimensions(),
            row_stride: s.source.dimensions()[0],
            range: s.range,
        },
        pixels,
        mask,
        work,
    )
}

fn view(
    twin: &PropertyTwin,
    camera: u8,
    s: RectificationSpec,
    extracted: RectifiedFeatures,
) -> Test<FeatureView> {
    let receipt = extracted.rectification;
    assert_eq!(extracted.result.frame.identity(), receipt.output);
    assert_eq!(receipt.output.exposure, receipt.source.exposure);
    assert_eq!(extracted.result.selection.mask_digest, receipt.allowed_mask);
    Ok(FeatureView {
        image_domain_digest: receipt.output.image_domain,
        allowed_mask_digest: receipt.allowed_mask,
        source_digest: receipt.source.storage,
        frame: extracted.result.frame,
        camera: TrackingCamera {
            geometry: twin.basis(),
            camera: u64::from(camera),
            calibration: u64::from(camera) + 30,
            image_domain: u64::from(camera) + 20,
            clock: 1,
            validity: [0, 1000],
            pose: RigidPose::from_center(ROTATION, [f64::from(camera) - 1., 0., 0.])?,
            intrinsics: s.target,
            error: Some(ProjectionError::EXACT),
        },
        mapping_basis: [camera + 40; 32],
        privacy_domain: 2,
        clock_evidence: [92; 32],
        capture: [90, 110],
        sigma_pixels: 0.5,
    })
}

fn views(twin: &PropertyTwin, lenses: &[LensDistortion]) -> Test<Vec<FeatureView>> {
    let mut result = Vec::new();
    let mut work = WorkBudget::new(WORK);
    for (i, &lens) in lenses.iter().enumerate() {
        let camera = i as u8 + 1;
        let s = spec(camera, lens)?;
        let pixels = render(s, i as f64);
        let mask = vec![1; pixels.len()];
        let source = raw(s, camera, &pixels, &mask, &mut work)?;
        let plan = RectificationPlan::compile(s, &mut work)?;
        let features = extract_raw_features(&plan, &source, options(), &mut work)?;
        assert!(features.result.frame.features().len() >= 32);
        assert_ne!(
            features.rectification.source.dimensions,
            features.rectification.output.dimensions
        );
        assert_ne!(
            features.rectification.source.storage,
            features.rectification.output.pixels
        );
        result.push(view(twin, camera, s, features)?);
    }
    Ok(result)
}

fn known_plane(lenses: &[LensDistortion]) -> Test {
    let twin = common::twin(&[-20.], Some(0.))?;
    let views = views(&twin, lenses)?;
    let pair = associate_features(
        &twin,
        [&views[0], &views[1]],
        association_options(),
        &mut WorkBudget::new(WORK),
    )?;
    let mut pair_points = 0;
    for hypothesis in pair.hypotheses() {
        if let FeatureHypothesisOutcome::Fused(point) = &hypothesis.outcome {
            let z = point.estimate().position[2];
            // Integer corner locations after two resampling stages need not land at
            // the same subpixel maximum. The physical plane remains independently Z=10.
            assert!((z - 10.).abs() < 1.0, "pair reconstructed plane at {z}");
            pair_points += 1;
        }
    }
    assert!(
        pair_points >= 12,
        "only {pair_points} independent stereo points"
    );
    let scene = associate_multiview_features(
        &twin,
        &views,
        association_options(),
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(scene.pairs().len(), 3);
    let mut triples = 0;
    for component in scene.components() {
        if let ComponentOutcome::Fused(point) = component.outcome() {
            assert!((point.estimate().position[2] - 10.).abs() < 1.0);
            if component.members().len() == 3 {
                triples += 1;
                assert_eq!(point.inputs().len(), 3);
                assert_eq!(component.links().len(), 3);
                assert_eq!(point.request().triangulation.max_outliers, 0);
            }
        }
    }
    assert!(
        triples >= 8,
        "only {triples} cycle-supported three-camera points"
    );
    Ok(())
}

#[test]
fn nonzero_brown_images_recover_independent_plane_through_pair_and_joint_geometry() -> Test {
    known_plane(&[brown(); 3])
}

#[test]
fn nonzero_fisheye_images_recover_independent_plane_through_pair_and_joint_geometry() -> Test {
    known_plane(&[fisheye(); 3])
}

#[test]
fn different_lens_families_share_native_descriptors_after_declared_correction() -> Test {
    known_plane(&[brown(), fisheye(), LensDistortion::Pinhole])
}

#[test]
fn crop_and_resize_produce_exact_independent_pinhole_feature_coordinates() -> Test {
    let mut s = spec(1, LensDistortion::Pinhole)?;
    s.source = PinholeIntrinsics::new(448, 288, 240., 240., 224., 144.)?;
    let pixels: Vec<_> = (0..288)
        .flat_map(|y| (0..448).map(move |x| texel(x / 2, y / 2) as u8))
        .collect();
    let expected: Vec<_> = (0..HEIGHT)
        .flat_map(|y| (0..WIDTH).map(move |x| texel(x as i32 + 16, y as i32 + 8) as u8))
        .collect();
    let mask = vec![1; pixels.len()];
    let mut work = WorkBudget::new(WORK);
    let source = raw(s, 1, &pixels, &mask, &mut work)?;
    let plan = RectificationPlan::compile(s, &mut work)?;
    let result = extract_raw_features(&plan, &source, options(), &mut work)?;
    assert_eq!(
        result.rectification.output.pixels,
        ContentDigest::sha256(&expected).bytes()
    );
    assert_eq!(result.rectification.output.dimensions, [WIDTH, HEIGHT]);
    assert_eq!(
        result.rectification.output.image_domain,
        plan.output_domain()
    );
    let allowed = vec![1; expected.len()];
    let image = GrayImage::new(result.rectification.output, &expected, &allowed, &mut work)?;
    let oracle = extract_gray(&image, options(), &mut work)?;
    assert_eq!(result.result.frame.features(), oracle.frame.features());
    assert_eq!(result.result.selection, oracle.selection);
    assert_eq!(result.result.selection.selected, 64);
    Ok(())
}

#[test]
fn masked_interpolation_taps_and_entire_descriptor_support_cannot_leak_pixels() -> Test {
    for lens in [brown(), fisheye()] {
        let s = spec(1, lens)?;
        let first = render(s, 0.);
        let mut second = first.clone();
        let mut mask = vec![1; first.len()];
        for y in 40..150 {
            for x in 110..120 {
                mask[y * 256 + x] = 0;
                second[y * 256 + x] = 255 - first[y * 256 + x];
            }
        }
        let mut work = WorkBudget::new(WORK);
        let a = raw(s, 1, &first, &mask, &mut work)?;
        let b = raw(s, 1, &second, &mask, &mut work)?;
        let plan = RectificationPlan::compile(s, &mut work)?;
        let projected = plan.apply(&a, &mut work)?;
        let result_a = extract_raw_features(&plan, &a, options(), &mut work)?;
        let result_b = extract_raw_features(&plan, &b, options(), &mut work)?;
        assert_ne!(
            result_a.rectification.source.storage,
            result_b.rectification.source.storage
        );
        assert_eq!(result_a.rectification.output, result_b.rectification.output);
        assert_eq!(
            result_a.result.frame.features(),
            result_b.result.frame.features()
        );
        assert_eq!(result_a.result.selection, result_b.result.selection);
        assert!(result_a.rectification.privacy_rejected > 0);
        assert!(result_a.result.selection.selected > 8);
        assert_eq!(
            result_a.result.selection.mask_digest,
            result_a.rectification.allowed_mask
        );
        assert_eq!(
            result_a.rectification.allowed_pixels + result_a.rectification.privacy_rejected,
            result_a.rectification.coverage.mapped
        );
        let mut excluded_neighbor = false;
        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                let Some([sx, sy]) = plan.sampling_position(x, y)? else {
                    continue;
                };
                let (x0, y0) = ((sx - 0.5).floor() as usize, (sy - 0.5).floor() as usize);
                let (dx, dy) = (sx - 0.5 - x0 as f64, sy - 0.5 - y0 as f64);
                if x0 + 1 < 256
                    && y0 + 1 < 192
                    && dx > 0.
                    && dy > 0.
                    && mask[y0 * 256 + x0] == 1
                    && [
                        mask[y0 * 256 + x0 + 1],
                        mask[(y0 + 1) * 256 + x0],
                        mask[(y0 + 1) * 256 + x0 + 1],
                    ]
                    .contains(&0)
                {
                    excluded_neighbor = true;
                    assert_eq!(projected.allowed()[(y * WIDTH + x) as usize], 0);
                }
            }
        }
        assert!(
            excluded_neighbor,
            "fixture must exercise a positive-weight masked neighbor"
        );
        for feature in result_a.result.frame.features() {
            let (x, y) = (
                feature.pixel[0].floor() as usize,
                feature.pixel[1].floor() as usize,
            );
            // Native descriptor support is the full 33x33 square, including its orientation.
            for row in y - 16..=y + 16 {
                for column in x - 16..=x + 16 {
                    assert_eq!(projected.allowed()[row * WIDTH as usize + column], 1);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn full_privacy_and_lens_domain_holes_never_manufacture_a_feature() -> Test {
    let mut s = spec(1, LensDistortion::Pinhole)?;
    let pixels = render(s, 0.);
    let mut work = WorkBudget::new(WORK);
    for hidden in [true, false] {
        if !hidden {
            s.maximum_radius = 0.1;
        }
        let mask = vec![u8::from(!hidden); pixels.len()];
        let source = raw(s, 1, &pixels, &mask, &mut work)?;
        let plan = RectificationPlan::compile(s, &mut work)?;
        let result = extract_raw_features(&plan, &source, options(), &mut work)?;
        assert!(result.result.frame.features().is_empty());
        assert_eq!(result.result.selection.tested_centers, 0);
        if hidden {
            assert_eq!(result.rectification.allowed_pixels, 0);
            assert_eq!(
                result.rectification.privacy_rejected,
                result.rectification.coverage.mapped
            );
        } else {
            assert!(result.rectification.allowed_pixels > 0);
            assert!(result.rectification.coverage.outside_lens_domain > 0);
        }
    }
    Ok(())
}

#[test]
fn correction_changes_domain_but_never_creates_an_independent_exposure() -> Test {
    let twin = common::twin(&[-20.], None)?;
    let s = spec(1, brown())?;
    let pixels = render(s, 0.);
    let mask = vec![1; pixels.len()];
    let mut work = WorkBudget::new(WORK);
    let source = raw(s, 1, &pixels, &mask, &mut work)?;
    let plan = RectificationPlan::compile(s, &mut work)?;
    let a = extract_raw_features(&plan, &source, options(), &mut work)?;
    let mut changed = s;
    changed.calibration = [55; 32];
    let other_source = raw(changed, 1, &pixels, &mask, &mut work)?;
    assert!(matches!(
        extract_raw_features(&plan, &other_source, options(), &mut work),
        Err(RawLocalizationError::Rectification(
            RectificationError::BasisMismatch
        ))
    ));
    let other_plan = RectificationPlan::compile(changed, &mut work)?;
    let b = extract_raw_features(&other_plan, &other_source, options(), &mut work)?;
    assert_eq!(a.rectification.map_digest, b.rectification.map_digest);
    assert_eq!(a.result.frame.features(), b.result.frame.features());
    assert_ne!(
        a.rectification.output.image_domain,
        b.rectification.output.image_domain
    );
    assert_eq!(
        a.rectification.output.exposure,
        b.rectification.output.exposure
    );
    let left = view(&twin, 1, s, a)?;
    let right = view(&twin, 2, changed, b)?;
    assert!(matches!(
        associate_features(&twin, [&left, &right], association_options(), &mut work),
        Err(AssociationError::DuplicateExposure)
    ));
    Ok(())
}

fn stopped(error: RawLocalizationError, expected: GeometryError) -> bool {
    matches!(error, RawLocalizationError::Rectification(RectificationError::Geometry(e))
        | RawLocalizationError::Localization(LocalizationError::Geometry(e)) if e == expected)
}

#[test]
fn composed_work_is_nonrenewable_and_late_cancellation_returns_no_features() -> Test {
    let s = spec(1, brown())?;
    let pixels = render(s, 0.);
    let mask = vec![1; pixels.len()];
    let mut setup = WorkBudget::new(WORK);
    let source = raw(s, 1, &pixels, &mask, &mut setup)?;
    let plan = RectificationPlan::compile(s, &mut setup)?;
    let calls = AtomicUsize::new(0);
    let probe = || {
        calls.fetch_add(1, Ordering::Relaxed);
        false
    };
    let mut measured = WorkBudget::with_cancellation_probe(WORK, &probe);
    let complete = extract_raw_features(&plan, &source, options(), &mut measured)?;
    let cost = measured.used();
    let checkpoints = calls.load(Ordering::Relaxed);
    let retry = extract_raw_features(&plan, &source, options(), &mut WorkBudget::new(cost))?;
    assert_eq!(
        retry.result.frame.features(),
        complete.result.frame.features()
    );
    let Err(error) =
        extract_raw_features(&plan, &source, options(), &mut WorkBudget::new(cost - 1))
    else {
        return Err("one shared allowance must cover both correction and extraction".into());
    };
    assert!(stopped(error, GeometryError::BudgetExhausted));
    // Refuse during resampling, during later feature work, and at final result release.
    for at in [20, checkpoints / 2, checkpoints] {
        let calls = AtomicUsize::new(0);
        let probe = || calls.fetch_add(1, Ordering::Relaxed) + 1 >= at;
        let Err(error) = extract_raw_features(
            &plan,
            &source,
            options(),
            &mut WorkBudget::with_cancellation_probe(WORK, &probe),
        ) else {
            return Err("cancellation must not expose a successful prefix".into());
        };
        assert!(stopped(error, GeometryError::Cancelled));
    }
    Ok(())
}
