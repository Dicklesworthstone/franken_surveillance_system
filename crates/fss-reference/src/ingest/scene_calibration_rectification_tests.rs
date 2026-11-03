#![forbid(unsafe_code)]
//! Real current adoption under an explicit image-model profile, with native map checks.
//! Shares only the existing real source/adoption fixture; no authority owner is fabricated.

use super::*;
use fss_twin::rectification::{LensDistortion, LumaRange, RectificationPlan};

fn radial_fixture(tag: &str, radial: [f64; 2]) -> TestResult<Fixture> {
    let mut fixture = Fixture::new(tag, false)?;
    fixture.calibration.cameras[0].distortion = radial;
    fixture.adopt_cameras(&[0, 1])?;
    Ok(fixture)
}
fn resolve_radial(
    fixture: &Fixture,
    work: &mut WorkBudget<'_>,
) -> Result<RetainedSceneCalibration> {
    let bindings = fixture.bindings();
    resolve_scene_calibration_for_rectification(
        &fixture.deployment,
        &SceneCalibrationRequest {
            calibration_bytes: &fixture.encoded,
            calibration_digest: fixture.calibration.digest()?,
            bindings: &bindings,
        },
        &fixture.twin,
        work,
        &fixture.cx,
    )
}

#[test]
fn explicit_radial_profile_preserves_adoption_and_generates_the_exact_original_model() -> TestResult
{
    let f = radial_fixture("rectified-model", [-0.08, 0.01])?;
    let anchor = f.deployment.current_anchor().clone();
    assert!(matches!(
        f.resolve(),
        Err(SceneCalibrationError::Unsupported(_))
    ));
    let owner = resolve_radial(&f, &mut WorkBudget::new(WORK))?;
    assert_eq!(
        owner.image_profile(),
        SceneCalibrationImageProfile::NativeRadialRectification
    );
    let selected = owner.camera(21).ok_or("selected camera")?;
    assert_eq!(selected.record().distortion, [-0.08, 0.01]);
    assert_eq!(
        selected.record().covariance,
        f.calibration.cameras[0].covariance
    );
    assert_eq!(selected.adoption().digest, f.adoptions[0]);
    let spec = owner.rectification_spec(21, 1.0, LumaRange::Full)?;
    assert_eq!(spec.source, selected.intrinsics());
    assert_eq!(spec.target, spec.source);
    assert_eq!(
        spec.source.dimensions(),
        f.calibration.cameras[0].dimensions
    );
    assert_eq!(
        spec.source_domain,
        selected.image_basis().image.image_domain
    );
    assert_eq!(spec.calibration, f.calibration.digest()?.bytes());
    assert_ne!(raw(spec.calibration), owner.calibration_file_digest());
    assert_ne!(raw(spec.calibration), selected.adoption().digest);
    assert_eq!(
        spec.distortion,
        LensDistortion::BrownConrady {
            radial: [-0.08, 0.01, 0.0],
            tangential: [0.0, 0.0],
        }
    );
    let plan = RectificationPlan::compile(spec, &mut WorkBudget::new(20_000_000))?;
    let [fx, fy, cx, cy] = f.calibration.cameras[0].intrinsics;
    for pixel in [[48.5, 48.5], [72.5, 60.5], [20.5, 24.5]] {
        // Independent direct projection of the calibration's documented two-term model.
        let x = (pixel[0] - cx) / fx;
        let y = (pixel[1] - cy) / fy;
        let radius2 = x * x + y * y;
        let scale = 1.0 - 0.08 * radius2 + 0.01 * radius2 * radius2;
        let expected = [fx * x * scale + cx, fy * y * scale + cy];
        let actual = plan.source_pixel(pixel)?.ok_or("admitted source point")?;
        for (actual, expected) in actual.into_iter().zip(expected) {
            assert!((actual - expected).abs() < 1e-12);
        }
    }
    assert_ne!(plan.output_domain(), spec.source_domain);
    owner.revalidate(&f.deployment, &f.cx, &mut WorkBudget::new(WORK))?;
    assert_eq!(f.deployment.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn zero_radial_opt_in_stays_distinct_from_the_original_pinhole_contract() -> TestResult {
    let f = Fixture::new("rectified-zero-profile", true)?;
    let original = f.resolve()?;
    let prepared = resolve_radial(&f, &mut WorkBudget::new(WORK))?;
    assert_eq!(
        original.image_profile(),
        SceneCalibrationImageProfile::OriginalPinhole
    );
    assert_ne!(original.digest(), prepared.digest());
    assert_eq!(
        original.calibration_identity(),
        prepared.calibration_identity()
    );
    assert_eq!(
        original.calibration_file_digest(),
        prepared.calibration_file_digest()
    );
    for handle in [21, 22] {
        let direct = original.camera(handle).ok_or("direct camera")?;
        let source = prepared.camera(handle).ok_or("prepared camera")?;
        assert_eq!(direct.pose(), source.pose());
        assert_eq!(direct.intrinsics(), source.intrinsics());
        assert_eq!(direct.image_basis(), source.image_basis());
        assert_eq!(direct.adoption(), source.adoption());
        assert!(matches!(
            original.rectification_spec(handle, 1.0, LumaRange::Full),
            Err(SceneCalibrationError::Unsupported(_))
        ));
    }
    let full = prepared.rectification_spec(21, 1.0, LumaRange::Full)?;
    let video = prepared.rectification_spec(21, 1.0, LumaRange::Video)?;
    let full = RectificationPlan::compile(full, &mut WorkBudget::new(20_000_000))?;
    let video = RectificationPlan::compile(video, &mut WorkBudget::new(20_000_000))?;
    assert_ne!(full.output_domain(), video.output_domain());
    Ok(())
}

#[test]
fn exact_source_profile_bounds_do_not_claim_that_a_folded_lens_was_rectified() -> TestResult {
    let f = radial_fixture("rectified-folded", [-1.0, 0.0])?;
    let owner = resolve_radial(&f, &mut WorkBudget::new(WORK))?;
    let spec = owner.rectification_spec(21, 1.0, LumaRange::Full)?;
    assert!(RectificationPlan::compile(spec, &mut WorkBudget::new(20_000_000)).is_err());
    // A narrow declaration may admit only a central disk; excluded pixels remain explicit.
    let central = owner.rectification_spec(21, 0.1, LumaRange::Full)?;
    let central = RectificationPlan::compile(central, &mut WorkBudget::new(20_000_000))?;
    assert!(central.coverage().outside_lens_domain > 0);
    for radius in [0.0, -1.0, f64::NAN, f64::INFINITY, 64.00001] {
        assert!(
            owner
                .rectification_spec(21, radius, LumaRange::Full)
                .is_err()
        );
    }
    assert!(matches!(
        owner.rectification_spec(23, 1.0, LumaRange::Full),
        Err(SceneCalibrationError::BasisMismatch(_))
    ));
    let too_wide = radial_fixture("rectified-coefficient-bound", [100.01, 0.0])?;
    assert!(matches!(
        resolve_radial(&too_wide, &mut WorkBudget::new(WORK)),
        Err(SceneCalibrationError::Unsupported(_))
    ));
    Ok(())
}

#[test]
fn radial_profile_uses_current_authority_and_cannot_survive_a_withdrawal() -> TestResult {
    let mut f = radial_fixture("rectified-withdrawal", [-0.08, 0.01])?;
    let owner = resolve_radial(&f, &mut WorkBudget::new(WORK))?;
    let read_before = owner.authority_read_bytes();
    f.withdraw_east()?;
    let anchor = f.deployment.current_anchor().clone();
    assert!(
        owner
            .revalidate(&f.deployment, &f.cx, &mut WorkBudget::new(WORK))
            .is_err()
    );
    assert!(owner.authority_read_bytes() > read_before);
    assert!(resolve_radial(&f, &mut WorkBudget::new(WORK)).is_err());
    assert_eq!(f.deployment.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn radial_profile_keeps_original_input_and_authority_receipt_custody_mandatory() -> TestResult {
    let mut f = radial_fixture("rectified-original-custody", [-0.08, 0.01])?;
    let owner = resolve_radial(&f, &mut WorkBudget::new(WORK))?;
    let original_input = f.inputs[0].clone();
    f.inputs[0].extend_from_slice(b"# different original bytes\n");
    assert!(resolve_radial(&f, &mut WorkBudget::new(WORK)).is_err());
    f.inputs[0] = original_input;
    let path = f.deployment.publisher().spool().object_path(f.adoptions[0]);
    let original = fs::read(&path)?;
    let mut corrupt = original.clone();
    *corrupt.last_mut().ok_or("receipt bytes")? ^= 1;
    fs::write(&path, corrupt)?;
    assert!(
        owner
            .revalidate(&f.deployment, &f.cx, &mut WorkBudget::new(WORK))
            .is_err()
    );
    assert!(resolve_radial(&f, &mut WorkBudget::new(WORK)).is_err());
    fs::remove_file(&path)?;
    assert!(
        owner
            .revalidate(&f.deployment, &f.cx, &mut WorkBudget::new(WORK))
            .is_err()
    );
    assert!(!path.exists());
    fs::write(path, original)?;
    owner.revalidate(&f.deployment, &f.cx, &mut WorkBudget::new(WORK))?;
    Ok(())
}

#[test]
fn radial_profile_consumes_the_same_nonrenewable_work_read_and_cancellation_limits() -> TestResult {
    let f = radial_fixture("rectified-work", [-0.08, 0.01])?;
    let mut work = WorkBudget::new(WORK);
    let owner = resolve_radial(&f, &mut work)?;
    resolve_radial(&f, &mut WorkBudget::new(work.used()))?;
    assert!(matches!(
        resolve_radial(&f, &mut WorkBudget::new(work.used() - 1)),
        Err(SceneCalibrationError::Geometry(
            GeometryError::BudgetExhausted
        ))
    ));
    let verified = owner.authority_read_bytes();
    owner
        .reads
        .reserved
        .set(MAX_SCENE_CALIBRATION_AUTHORITY_BYTES);
    assert!(matches!(
        owner.revalidate(&f.deployment, &f.cx, &mut WorkBudget::new(WORK)),
        Err(SceneCalibrationError::Limit)
    ));
    assert_eq!(owner.authority_read_bytes(), verified);
    let cancelled = AtomicBool::new(true);
    assert!(matches!(
        resolve_radial(&f, &mut WorkBudget::cancellable(WORK, &cancelled)),
        Err(SceneCalibrationError::Cancelled)
    ));
    Ok(())
}
