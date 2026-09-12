#![forbid(unsafe_code)]
//! Integration contract tests for camera intrinsics and distortion certificate (FSS-089 / WP-110).

use std::error::Error;

use fss_core::{
    CalibrationGeneration, CaptureInterval, DeviceGeneration, DeviceId, FirmwareGeneration,
    TimestampNs,
};
use fss_reference::{
    CalibrationError, CalibrationLifecycle, CalibrationLifecycleState, CalibrationSample,
    CameraIntrinsics, DistortionModel, Fixed64, IntrinsicsCertificateBuilder, IntrinsicsCovariance,
    IntrinsicsResidual, MAX_CALIBRATION_SAMPLES, MAX_CERTIFICATE_ID_BYTES,
    MAX_REPROJECTION_TOLERANCE_UPX, MIN_CALIBRATION_SAMPLES,
};

/// Helper to generate synthetic, non-degenerate calibration sample points.
fn generate_synthetic_samples(
    count: usize,
    intrinsics: &CameraIntrinsics,
    base_time_ns: i128,
) -> Result<Vec<CalibrationSample>, Box<dyn Error>> {
    let mut samples = Vec::with_capacity(count);
    let mut prng: u64 = 0x1234_5678_9abc_def0;

    let mut next_u64 = || {
        prng ^= prng >> 12;
        prng ^= prng << 25;
        prng ^= prng >> 27;
        prng.wrapping_mul(0x2545_f491_4f6c_dd1d_u64)
    };

    for i in 0..count {
        let frame_index = (i / 16) as u32;
        let t_ns = base_time_ns + (i as i128) * 10_000_000;

        // Generate non-degenerate 3D points across 4 quadrants in front of camera
        let quadrant = i % 4;
        let (sign_x, sign_y) = match quadrant {
            0 => (1.0, 1.0),
            1 => (-1.0, 1.0),
            2 => (-1.0, -1.0),
            _ => (1.0, -1.0),
        };

        let rand_x = ((next_u64() % 1000) as f64) / 10.0 + 50.0;
        let rand_y = ((next_u64() % 1000) as f64) / 10.0 + 50.0;
        let z_mm = 1500.0 + ((next_u64() % 1000) as f64);

        let x_mm = sign_x * rand_x;
        let y_mm = sign_y * rand_y;

        let proj = intrinsics.project_point_f64([x_mm, y_mm, z_mm])?;
        let u_upx = (proj[0] * 1_000_000.0).round() as i64;
        let v_upx = (proj[1] * 1_000_000.0).round() as i64;

        let sample = CalibrationSample::new(
            (i + 1) as u64,
            [
                x_mm.round() as i32,
                y_mm.round() as i32,
                z_mm.round() as i32,
            ],
            (u_upx, v_upx),
            frame_index,
            TimestampNs(t_ns),
        )?;
        samples.push(sample);
    }
    Ok(samples)
}

fn sample_intrinsics_brown_conrady() -> CameraIntrinsics {
    CameraIntrinsics {
        width_px: 1920,
        height_px: 1080,
        fx: Fixed64::from_f64(1450.5),
        fy: Fixed64::from_f64(1450.2),
        cx: Fixed64::from_f64(960.25),
        cy: Fixed64::from_f64(540.15),
        skew: Fixed64::from_f64(0.0001),
        distortion: DistortionModel::BrownConrady {
            k1: Fixed64::from_f64(-0.12),
            k2: Fixed64::from_f64(0.035),
            p1: Fixed64::from_f64(0.001),
            p2: Fixed64::from_f64(-0.0005),
            k3: Fixed64::from_f64(0.005),
        },
    }
}

fn sample_residual() -> IntrinsicsResidual {
    IntrinsicsResidual {
        mean_reprojection_error_upx: 250_000, // 0.25 px
        max_reprojection_error_upx: 850_000,  // 0.85 px
        rmse_upx: 320_000,                    // 0.32 px
        covariance: IntrinsicsCovariance {
            fx_variance_upx2: 120_000,
            fy_variance_upx2: 115_000,
            cx_variance_upx2: 80_000,
            cy_variance_upx2: 75_000,
            skew_variance_u2: 10,
        },
        observation_count: 32,
        frame_count: 4,
    }
}

// ---------------------------------------------------------------------------
// 1. Bit-identical deterministic replay
// ---------------------------------------------------------------------------

#[test]
fn test_certificate_deterministic_bit_identical_hash_and_encoding() -> Result<(), Box<dyn Error>> {
    let intrinsics = sample_intrinsics_brown_conrady();
    let samples = generate_synthetic_samples(MIN_CALIBRATION_SAMPLES, &intrinsics, 1_000_000_000)?;

    let dev_id = DeviceId::parse("dev:camera:front-01")?;
    let dev_gen = DeviceGeneration::parse("dev:gen:sensor-rev-2")?;
    let fw_gen = FirmwareGeneration::parse("fw:gen:v2.4.1")?;
    let cal_gen = CalibrationGeneration::parse("cal:shuttle:pass-001")?;

    let validity = CaptureInterval::new(TimestampNs(1_000_000_000), TimestampNs(2_000_000_000))?;

    let cert_a = IntrinsicsCertificateBuilder::new("cert:front:001")?
        .device(dev_id.clone(), dev_gen.clone(), fw_gen.clone())
        .calibration_generation(cal_gen.clone())
        .intrinsics(intrinsics.clone())
        .residual(sample_residual())
        .validity(validity)
        .evidence(samples.clone())?
        .build()?;

    let cert_b = IntrinsicsCertificateBuilder::new("cert:front:001")?
        .device(dev_id, dev_gen, fw_gen)
        .calibration_generation(cal_gen)
        .intrinsics(intrinsics)
        .residual(sample_residual())
        .validity(validity)
        .evidence(samples)?
        .build()?;

    assert_eq!(cert_a, cert_b);
    assert_eq!(cert_a.certificate_digest, cert_b.certificate_digest);
    assert_eq!(cert_a.evidence_root, cert_b.evidence_root);
    assert_eq!(cert_a.canonical_bytes()?, cert_b.canonical_bytes()?);

    Ok(())
}

// ---------------------------------------------------------------------------
// 2. Projection: Pinhole and Distortion Models
// ---------------------------------------------------------------------------

#[test]
fn test_intrinsics_projection_pinhole_and_distortion_models() -> Result<(), Box<dyn Error>> {
    let pinhole = CameraIntrinsics {
        width_px: 1920,
        height_px: 1080,
        fx: Fixed64::from_f64(1000.0),
        fy: Fixed64::from_f64(1000.0),
        cx: Fixed64::from_f64(960.0),
        cy: Fixed64::from_f64(540.0),
        skew: Fixed64::from_raw(0),
        distortion: DistortionModel::None,
    };

    // Center optical axis point: (0, 0, 2000) mm -> must project to exact principal point
    let proj_center = pinhole.project_point_f64([0.0, 0.0, 2000.0])?;
    assert!((proj_center[0] - 960.0).abs() < 1e-9);
    assert!((proj_center[1] - 540.0).abs() < 1e-9);

    // Off-axis point: (500, 250, 1000) mm -> x = 0.5, y = 0.25 -> u = 1000*0.5 + 960 = 1460, v = 1000*0.25 + 540 = 790
    let proj_off = pinhole.project_point_f64([500.0, 250.0, 1000.0])?;
    assert!((proj_off[0] - 1460.0).abs() < 1e-9);
    assert!((proj_off[1] - 790.0).abs() < 1e-9);

    // Test fixed-point projection matches
    let proj_fixed = pinhole.project_point_fixed([
        Fixed64::from_f64(500.0),
        Fixed64::from_f64(250.0),
        Fixed64::from_f64(1000.0),
    ])?;
    assert_eq!(proj_fixed[0].to_raw(), 1460 * 1_000_000);
    assert_eq!(proj_fixed[1].to_raw(), 790 * 1_000_000);

    // Kannala-Brandt fisheye projection
    let fisheye = CameraIntrinsics {
        width_px: 1920,
        height_px: 1080,
        fx: Fixed64::from_f64(600.0),
        fy: Fixed64::from_f64(600.0),
        cx: Fixed64::from_f64(960.0),
        cy: Fixed64::from_f64(540.0),
        skew: Fixed64::from_raw(0),
        distortion: DistortionModel::KannalaBrandt {
            k1: Fixed64::from_f64(0.05),
            k2: Fixed64::from_f64(-0.01),
            k3: Fixed64::from_f64(0.002),
            k4: Fixed64::from_f64(-0.0001),
        },
    };

    let proj_fish = fisheye.project_point_f64([400.0, 300.0, 1000.0])?;
    assert!(proj_fish[0] > 960.0 && proj_fish[0] < 1920.0);
    assert!(proj_fish[1] > 540.0 && proj_fish[1] < 1080.0);

    Ok(())
}

// ---------------------------------------------------------------------------
// 3. Platform stability: fixed-point & IEEE 754
// ---------------------------------------------------------------------------

#[test]
fn test_platform_stability_fixed_point_and_ieee754() -> Result<(), Box<dyn Error>> {
    // Fixed64 integer operations are bit-identical regardless of FPU rounding mode or target arch.
    let a = Fixed64::from_raw(1_234_567_890);
    let b = Fixed64::from_raw(987_654_321);

    let sum = a.checked_add(b).ok_or("overflow")?;
    assert_eq!(sum.to_raw(), 2_222_222_211);

    let diff = a.checked_sub(b).ok_or("overflow")?;
    assert_eq!(diff.to_raw(), 246_913_569);

    // Fixed-point scaling multiplication: (a * b) / 1_000_000
    let prod = a.checked_mul(b).ok_or("overflow")?;
    assert_eq!(prod.to_raw(), 1_219_326_311_126);

    // IEEE 754 conversion roundtrips within micro-unit precision
    let f = 1450.123456;
    let fixed_f = Fixed64::from_f64(f);
    assert_eq!(fixed_f.to_raw(), 1_450_123_456);
    assert!((fixed_f.to_f64() - f).abs() < 1e-6);

    Ok(())
}

// ---------------------------------------------------------------------------
// 4. Prohibited default identity calibration
// ---------------------------------------------------------------------------

#[test]
fn test_rejection_of_default_identity_calibration() -> Result<(), Box<dyn Error>> {
    let identity_intrinsics = CameraIntrinsics {
        width_px: 1920,
        height_px: 1080,
        fx: Fixed64::from_f64(1.0),
        fy: Fixed64::from_f64(1.0),
        cx: Fixed64::from_raw(0),
        cy: Fixed64::from_raw(0),
        skew: Fixed64::from_raw(0),
        distortion: DistortionModel::None,
    };

    assert!(identity_intrinsics.is_identity());

    let samples =
        generate_synthetic_samples(MIN_CALIBRATION_SAMPLES, &identity_intrinsics, 1_000_000_000)?;
    let dev_id = DeviceId::parse("dev:camera:01")?;
    let dev_gen = DeviceGeneration::parse("dev:gen:v1")?;
    let fw_gen = FirmwareGeneration::parse("fw:gen:v1")?;
    let cal_gen = CalibrationGeneration::parse("cal:gen:v1")?;
    let validity = CaptureInterval::new(TimestampNs(1_000), TimestampNs(2_000))?;

    let res = IntrinsicsCertificateBuilder::new("cert:ident:fail")?
        .device(dev_id, dev_gen, fw_gen)
        .calibration_generation(cal_gen)
        .intrinsics(identity_intrinsics)
        .residual(sample_residual())
        .validity(validity)
        .evidence(samples)?
        .build();

    match res {
        Err(CalibrationError::IdentityCalibrationProhibited) => {}
        other => {
            return Err(format!("expected IdentityCalibrationProhibited, got {other:?}").into());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 5. Insufficient evidence failure
// ---------------------------------------------------------------------------

#[test]
fn test_typed_failure_insufficient_evidence() -> Result<(), Box<dyn Error>> {
    let intrinsics = sample_intrinsics_brown_conrady();
    let too_few_samples =
        generate_synthetic_samples(MIN_CALIBRATION_SAMPLES - 1, &intrinsics, 1_000_000_000)?;

    let dev_id = DeviceId::parse("dev:camera:01")?;
    let dev_gen = DeviceGeneration::parse("dev:gen:v1")?;
    let fw_gen = FirmwareGeneration::parse("fw:gen:v1")?;
    let cal_gen = CalibrationGeneration::parse("cal:gen:v1")?;
    let validity = CaptureInterval::new(TimestampNs(1_000), TimestampNs(2_000))?;

    let res = IntrinsicsCertificateBuilder::new("cert:insufficient:fail")?
        .device(dev_id, dev_gen, fw_gen)
        .calibration_generation(cal_gen)
        .intrinsics(intrinsics)
        .residual(sample_residual())
        .validity(validity)
        .evidence(too_few_samples);

    match res {
        Err(CalibrationError::InsufficientEvidence {
            count,
            min_required,
        }) => {
            assert_eq!(count, MIN_CALIBRATION_SAMPLES - 1);
            assert_eq!(min_required, MIN_CALIBRATION_SAMPLES);
        }
        other => return Err(format!("expected InsufficientEvidence, got {other:?}").into()),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 6. Degenerate evidence failure
// ---------------------------------------------------------------------------

#[test]
fn test_typed_failure_degenerate_evidence_collinear() -> Result<(), Box<dyn Error>> {
    let intrinsics = sample_intrinsics_brown_conrady();

    // Construct degenerate samples where all 3D points are collinear (along a single line X=100, Y=100)
    let mut degenerate_samples = Vec::new();
    for i in 0..MIN_CALIBRATION_SAMPLES {
        let z_mm = 1000 + (i as i32) * 50;
        let s = CalibrationSample::new(
            (i + 1) as u64,
            [100, 100, z_mm],
            (960_000_000, 540_000_000),
            0,
            TimestampNs(1_000_000 + (i as i128) * 10_000),
        )?;
        degenerate_samples.push(s);
    }

    let dev_id = DeviceId::parse("dev:camera:01")?;
    let dev_gen = DeviceGeneration::parse("dev:gen:v1")?;
    let fw_gen = FirmwareGeneration::parse("fw:gen:v1")?;
    let cal_gen = CalibrationGeneration::parse("cal:gen:v1")?;
    let validity = CaptureInterval::new(TimestampNs(1_000), TimestampNs(2_000))?;

    let res = IntrinsicsCertificateBuilder::new("cert:degen:fail")?
        .device(dev_id, dev_gen, fw_gen)
        .calibration_generation(cal_gen)
        .intrinsics(intrinsics)
        .residual(sample_residual())
        .validity(validity)
        .evidence(degenerate_samples)?
        .build();

    match res {
        Err(CalibrationError::DegenerateEvidence { reason }) => {
            assert!(
                reason.contains("collinear")
                    || reason.contains("degenerate")
                    || reason.contains("spatial spread")
            );
        }
        other => return Err(format!("expected DegenerateEvidence, got {other:?}").into()),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 7. Residual above tolerance failure
// ---------------------------------------------------------------------------

#[test]
fn test_typed_failure_residual_above_tolerance() -> Result<(), Box<dyn Error>> {
    let intrinsics = sample_intrinsics_brown_conrady();
    let samples = generate_synthetic_samples(MIN_CALIBRATION_SAMPLES, &intrinsics, 1_000_000_000)?;

    let mut bad_residual = sample_residual();
    bad_residual.rmse_upx = MAX_REPROJECTION_TOLERANCE_UPX + 1; // Exceeds tolerance limit

    let dev_id = DeviceId::parse("dev:camera:01")?;
    let dev_gen = DeviceGeneration::parse("dev:gen:v1")?;
    let fw_gen = FirmwareGeneration::parse("fw:gen:v1")?;
    let cal_gen = CalibrationGeneration::parse("cal:gen:v1")?;
    let validity = CaptureInterval::new(TimestampNs(1_000), TimestampNs(2_000))?;

    let res = IntrinsicsCertificateBuilder::new("cert:highres:fail")?
        .device(dev_id, dev_gen, fw_gen)
        .calibration_generation(cal_gen)
        .intrinsics(intrinsics)
        .residual(bad_residual)
        .validity(validity)
        .evidence(samples)?
        .build();

    match res {
        Err(CalibrationError::ResidualExceedsTolerance {
            actual_rmse_upx,
            max_allowed_upx,
        }) => {
            assert_eq!(actual_rmse_upx, MAX_REPROJECTION_TOLERANCE_UPX + 1);
            assert_eq!(max_allowed_upx, MAX_REPROJECTION_TOLERANCE_UPX);
        }
        other => return Err(format!("expected ResidualExceedsTolerance, got {other:?}").into()),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 8. Stale certificate past validity failure
// ---------------------------------------------------------------------------

#[test]
fn test_typed_failure_stale_certificate_past_validity() -> Result<(), Box<dyn Error>> {
    let intrinsics = sample_intrinsics_brown_conrady();
    let samples = generate_synthetic_samples(MIN_CALIBRATION_SAMPLES, &intrinsics, 1_000_000_000)?;

    let dev_id = DeviceId::parse("dev:camera:01")?;
    let dev_gen = DeviceGeneration::parse("dev:gen:v1")?;
    let fw_gen = FirmwareGeneration::parse("fw:gen:v1")?;
    let cal_gen = CalibrationGeneration::parse("cal:gen:v1")?;

    let valid_start = TimestampNs(1_000_000_000);
    let valid_end = TimestampNs(2_000_000_000);
    let validity = CaptureInterval::new(valid_start, valid_end)?;

    let cert = IntrinsicsCertificateBuilder::new("cert:validity:check")?
        .device(dev_id, dev_gen, fw_gen)
        .calibration_generation(cal_gen)
        .intrinsics(intrinsics)
        .residual(sample_residual())
        .validity(validity)
        .evidence(samples)?
        .build()?;

    // Within validity: succeeds
    assert!(cert.validate_at_time(TimestampNs(1_500_000_000)).is_ok());
    assert!(cert.validate_at_time(valid_start).is_ok());
    assert!(cert.validate_at_time(valid_end).is_ok());

    // Before validity: fails
    match cert.validate_at_time(TimestampNs(999_999_999)) {
        Err(CalibrationError::StaleCertificatePastValidity {
            requested,
            valid_until,
        }) => {
            assert_eq!(requested, TimestampNs(999_999_999));
            assert_eq!(valid_until, valid_end);
        }
        other => {
            return Err(format!("expected StaleCertificatePastValidity, got {other:?}").into());
        }
    }

    // After validity: fails
    match cert.validate_at_time(TimestampNs(2_000_000_001)) {
        Err(CalibrationError::StaleCertificatePastValidity {
            requested,
            valid_until,
        }) => {
            assert_eq!(requested, TimestampNs(2_000_000_001));
            assert_eq!(valid_until, valid_end);
        }
        other => {
            return Err(format!("expected StaleCertificatePastValidity, got {other:?}").into());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 9. Generation mismatch failures (device, firmware, ID)
// ---------------------------------------------------------------------------

#[test]
fn test_typed_failure_device_and_firmware_generation_mismatches() -> Result<(), Box<dyn Error>> {
    let intrinsics = sample_intrinsics_brown_conrady();
    let samples = generate_synthetic_samples(MIN_CALIBRATION_SAMPLES, &intrinsics, 1_000_000_000)?;

    let dev_id = DeviceId::parse("dev:camera:front-01")?;
    let dev_gen = DeviceGeneration::parse("dev:gen:hw-rev-2")?;
    let fw_gen = FirmwareGeneration::parse("fw:gen:v3.1.0")?;
    let cal_gen = CalibrationGeneration::parse("cal:gen:v1")?;
    let validity = CaptureInterval::new(TimestampNs(1_000), TimestampNs(2_000))?;

    let cert = IntrinsicsCertificateBuilder::new("cert:mismatch:check")?
        .device(dev_id.clone(), dev_gen.clone(), fw_gen.clone())
        .calibration_generation(cal_gen)
        .intrinsics(intrinsics)
        .residual(sample_residual())
        .validity(validity)
        .evidence(samples)?
        .build()?;

    // Exact match passes
    assert!(cert.validate_device(&dev_id, &dev_gen, &fw_gen).is_ok());

    // Device ID mismatch fails
    let wrong_id = DeviceId::parse("dev:camera:back-02")?;
    match cert.validate_device(&wrong_id, &dev_gen, &fw_gen) {
        Err(CalibrationError::DeviceIdMismatch { expected, actual }) => {
            assert_eq!(expected, dev_id);
            assert_eq!(actual, wrong_id);
        }
        other => return Err(format!("expected DeviceIdMismatch, got {other:?}").into()),
    }

    // Device generation mismatch fails
    let wrong_dev_gen = DeviceGeneration::parse("dev:gen:hw-rev-3")?;
    match cert.validate_device(&dev_id, &wrong_dev_gen, &fw_gen) {
        Err(CalibrationError::DeviceGenerationMismatch { expected, actual }) => {
            assert_eq!(expected, dev_gen);
            assert_eq!(actual, wrong_dev_gen);
        }
        other => return Err(format!("expected DeviceGenerationMismatch, got {other:?}").into()),
    }

    // Firmware generation mismatch fails (firmware changes can alter crop/pipeline)
    let wrong_fw_gen = FirmwareGeneration::parse("fw:gen:v3.2.0")?;
    match cert.validate_device(&dev_id, &dev_gen, &wrong_fw_gen) {
        Err(CalibrationError::FirmwareGenerationMismatch { expected, actual }) => {
            assert_eq!(expected, fw_gen);
            assert_eq!(actual, wrong_fw_gen);
        }
        other => return Err(format!("expected FirmwareGenerationMismatch, got {other:?}").into()),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 10. Invalidation when new evidence contradicts certificate
// ---------------------------------------------------------------------------

#[test]
fn test_invalidation_when_new_evidence_contradicts_certificate() -> Result<(), Box<dyn Error>> {
    let intrinsics = sample_intrinsics_brown_conrady();
    let samples = generate_synthetic_samples(MIN_CALIBRATION_SAMPLES, &intrinsics, 1_000_000_000)?;

    let dev_id = DeviceId::parse("dev:camera:01")?;
    let dev_gen = DeviceGeneration::parse("dev:gen:v1")?;
    let fw_gen = FirmwareGeneration::parse("fw:gen:v1")?;
    let cal_gen = CalibrationGeneration::parse("cal:gen:v1")?;
    let validity = CaptureInterval::new(TimestampNs(1_000_000_000), TimestampNs(5_000_000_000))?;

    let cert = IntrinsicsCertificateBuilder::new("cert:contradict:check")?
        .device(dev_id, dev_gen, fw_gen)
        .calibration_generation(cal_gen)
        .intrinsics(intrinsics.clone())
        .residual(sample_residual())
        .validity(validity)
        .evidence(samples)?
        .build()?;

    let mut lifecycle = CalibrationLifecycle::new();
    lifecycle.activate_certificate(cert)?;

    assert!(matches!(
        lifecycle.state(),
        CalibrationLifecycleState::Active(_)
    ));

    // 1. Consistent observation (error within tolerance) -> passes
    let consistent_3d = [200.0, 150.0, 1500.0];
    let proj = intrinsics.project_point_f64(consistent_3d)?;
    let consistent_sample = CalibrationSample::new(
        1001,
        [200, 150, 1500],
        (
            (proj[0] * 1e6).round() as i64,
            (proj[1] * 1e6).round() as i64,
        ),
        5,
        TimestampNs(2_000_000_000),
    )?;

    assert!(
        lifecycle
            .verify_observation(&consistent_sample, 1_000_000)
            .is_ok()
    );
    assert!(matches!(
        lifecycle.state(),
        CalibrationLifecycleState::Active(_)
    ));

    // 2. Contradictory observation (e.g. physical camera shifted or dropped lens)
    // Observed pixel is 100 pixels away from expected projection!
    let contradictory_sample = CalibrationSample::new(
        1002,
        [200, 150, 1500],
        (
            (proj[0] * 1e6).round() as i64 + 100_000_000,
            (proj[1] * 1e6).round() as i64,
        ),
        6,
        TimestampNs(2_500_000_000),
    )?;

    let res = lifecycle.verify_observation(&contradictory_sample, 1_000_000); // 1.0 px tolerance
    match res {
        Err(CalibrationError::ContradictedCertificate {
            point_id,
            observed_error_upx,
            tolerance_upx,
        }) => {
            assert_eq!(point_id, 1002);
            assert!(observed_error_upx >= 100_000_000);
            assert_eq!(tolerance_upx, 1_000_000);
        }
        other => return Err(format!("expected ContradictedCertificate, got {other:?}").into()),
    }

    // Lifecycle must now be in Invalidated state
    match lifecycle.state() {
        CalibrationLifecycleState::Invalidated {
            reason,
            contradicting_sample,
            ..
        } => {
            assert!(reason.contains("reprojection contradiction"));
            assert_eq!(
                contradicting_sample.as_ref().map(|s| s.point_id),
                Some(1002)
            );
        }
        other => return Err(format!("expected Invalidated state, got {other:?}").into()),
    }

    // Subsequent queries are rejected because certificate is invalidated
    let post_inval_res = lifecycle.active_certificate();
    assert!(matches!(
        post_inval_res,
        Err(CalibrationError::CertificateInvalidated { .. })
    ));

    Ok(())
}

// ---------------------------------------------------------------------------
// 11. Bounds: Sample count at bound and bound+1
// ---------------------------------------------------------------------------

#[test]
fn test_bounds_calibration_samples_at_bound_and_bound_plus_one() -> Result<(), Box<dyn Error>> {
    let intrinsics = sample_intrinsics_brown_conrady();

    // At bound: MAX_CALIBRATION_SAMPLES (512)
    let at_bound_samples =
        generate_synthetic_samples(MAX_CALIBRATION_SAMPLES, &intrinsics, 1_000_000_000)?;
    assert_eq!(at_bound_samples.len(), MAX_CALIBRATION_SAMPLES);

    let dev_id = DeviceId::parse("dev:camera:01")?;
    let dev_gen = DeviceGeneration::parse("dev:gen:v1")?;
    let fw_gen = FirmwareGeneration::parse("fw:gen:v1")?;
    let cal_gen = CalibrationGeneration::parse("cal:gen:v1")?;
    let validity = CaptureInterval::new(TimestampNs(1_000), TimestampNs(2_000))?;

    let builder_at_bound = IntrinsicsCertificateBuilder::new("cert:bound:at")?
        .device(dev_id.clone(), dev_gen.clone(), fw_gen.clone())
        .calibration_generation(cal_gen.clone())
        .intrinsics(intrinsics.clone())
        .residual(sample_residual())
        .validity(validity)
        .evidence(at_bound_samples);

    assert!(builder_at_bound.is_ok());

    // Over bound: MAX_CALIBRATION_SAMPLES + 1 (513)
    let over_bound_samples =
        generate_synthetic_samples(MAX_CALIBRATION_SAMPLES + 1, &intrinsics, 1_000_000_000)?;
    assert_eq!(over_bound_samples.len(), MAX_CALIBRATION_SAMPLES + 1);

    let builder_over_bound = IntrinsicsCertificateBuilder::new("cert:bound:over")?
        .device(dev_id, dev_gen, fw_gen)
        .calibration_generation(cal_gen)
        .intrinsics(intrinsics)
        .residual(sample_residual())
        .validity(validity)
        .evidence(over_bound_samples);

    match builder_over_bound {
        Err(CalibrationError::TooManyEvidenceSamples { actual, max }) => {
            assert_eq!(actual, MAX_CALIBRATION_SAMPLES + 1);
            assert_eq!(max, MAX_CALIBRATION_SAMPLES);
        }
        other => return Err(format!("expected TooManyEvidenceSamples, got {other:?}").into()),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 12. Bounds: Certificate ID at bound and bound+1
// ---------------------------------------------------------------------------

#[test]
fn test_bounds_certificate_id_at_bound_and_bound_plus_one() -> Result<(), Box<dyn Error>> {
    // MAX_CERTIFICATE_ID_BYTES = 128
    let at_bound_id = "c".repeat(MAX_CERTIFICATE_ID_BYTES);
    let builder_at = IntrinsicsCertificateBuilder::new(&at_bound_id);
    assert!(builder_at.is_ok());

    let over_bound_id = "c".repeat(MAX_CERTIFICATE_ID_BYTES + 1);
    let builder_over = IntrinsicsCertificateBuilder::new(&over_bound_id);
    match builder_over {
        Err(CalibrationError::CertificateIdTooLong { actual, max }) => {
            assert_eq!(actual, MAX_CERTIFICATE_ID_BYTES + 1);
            assert_eq!(max, MAX_CERTIFICATE_ID_BYTES);
        }
        other => return Err(format!("expected CertificateIdTooLong, got {other:?}").into()),
    }

    // Empty ID is also rejected
    match IntrinsicsCertificateBuilder::new("") {
        Err(CalibrationError::EmptyCertificateId) => {}
        other => return Err(format!("expected EmptyCertificateId, got {other:?}").into()),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 13. End-to-end full calibration lifecycle workflow
// ---------------------------------------------------------------------------

#[test]
fn test_end_to_end_calibration_lifecycle_workflow() -> Result<(), Box<dyn Error>> {
    let intrinsics = sample_intrinsics_brown_conrady();
    let samples = generate_synthetic_samples(32, &intrinsics, 1_000_000_000)?;

    let dev_id = DeviceId::parse("dev:camera:front-e2e")?;
    let dev_gen = DeviceGeneration::parse("dev:gen:hw-1")?;
    let fw_gen = FirmwareGeneration::parse("fw:gen:v1.0")?;
    let cal_gen = CalibrationGeneration::parse("cal:shuttle:pass-1")?;
    let validity = CaptureInterval::new(TimestampNs(1_000_000_000), TimestampNs(10_000_000_000))?;

    let cert = IntrinsicsCertificateBuilder::new("cert:e2e:front")?
        .device(dev_id.clone(), dev_gen.clone(), fw_gen.clone())
        .calibration_generation(cal_gen)
        .intrinsics(intrinsics)
        .residual(sample_residual())
        .validity(validity)
        .evidence(samples.clone())?
        .build()?;

    let mut lifecycle = CalibrationLifecycle::new();
    assert!(matches!(
        lifecycle.state(),
        CalibrationLifecycleState::Uncalibrated
    ));

    lifecycle.activate_certificate(cert)?;
    assert!(lifecycle.is_active());

    // Validate against device and time
    let active_cert = lifecycle.active_certificate()?;
    active_cert.validate_device(&dev_id, &dev_gen, &fw_gen)?;
    active_cert.validate_at_time(TimestampNs(5_000_000_000))?;

    // Verify all original training samples satisfy tolerance
    for sample in &samples {
        lifecycle.verify_observation(sample, 1_000_000)?; // 1.0 px tolerance
    }

    // Manual revocation / invalidation
    lifecycle.invalidate("operator flagged calibration drift".to_string(), None);
    assert!(!lifecycle.is_active());
    assert!(matches!(
        lifecycle.state(),
        CalibrationLifecycleState::Invalidated { .. }
    ));

    Ok(())
}
