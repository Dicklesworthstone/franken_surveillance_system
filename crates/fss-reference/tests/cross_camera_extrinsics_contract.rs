#![forbid(unsafe_code)]
//! Integration contract tests for cross-camera extrinsics solver interface and certificate subsystem (FSS-090 / WP-110).

use std::error::Error;

use fss_core::{
    CalibrationGeneration, CanonicalEncode, CaptureInterval, ContentDigest, DeviceGeneration,
    DeviceId, FirmwareGeneration, TimestampNs,
};
use fss_reference::{
    CalibrationSample, CameraIntrinsics, DistortionModel, ExtrinsicsCertificateBuilder,
    ExtrinsicsCorrespondence, ExtrinsicsCovariance, ExtrinsicsError, ExtrinsicsLifecycle,
    ExtrinsicsLifecycleState, ExtrinsicsResidual, ExtrinsicsSolveRequest, Fixed64,
    IntrinsicsCertificate, IntrinsicsCertificateBuilder, IntrinsicsCovariance, IntrinsicsResidual,
    MAX_CERTIFICATE_ID_BYTES, MAX_EXTRINSICS_CORRESPONDENCES,
    MAX_EXTRINSICS_REPROJECTION_TOLERANCE_UPX, MIN_EXTRINSICS_CORRESPONDENCES,
    ReferenceExtrinsicsSolver, RigidTransform3D, solve_extrinsics,
};

/// Helper to create a valid synthetic intrinsics certificate for a camera.
fn build_test_intrinsics(
    device_id_suffix: &str,
    cal_gen_suffix: &str,
) -> Result<IntrinsicsCertificate, Box<dyn Error>> {
    let intrinsics = CameraIntrinsics {
        width_px: 1920,
        height_px: 1080,
        fx: Fixed64::from_integer(1200),
        fy: Fixed64::from_integer(1200),
        cx: Fixed64::from_integer(960),
        cy: Fixed64::from_integer(540),
        skew: Fixed64::ZERO,
        distortion: DistortionModel::None,
    };

    let mut samples = Vec::new();
    for i in 0..16 {
        let x_mm = if i % 2 == 0 { 200 } else { -200 };
        let y_mm = if (i / 2) % 2 == 0 { 150 } else { -150 };
        let z_mm = 1500 + i * 50;

        let proj = intrinsics.project_point_f64([x_mm as f64, y_mm as f64, z_mm as f64])?;
        let u_upx = (proj[0] * 1_000_000.0).round() as i64;
        let v_upx = (proj[1] * 1_000_000.0).round() as i64;

        let s = CalibrationSample::new(
            (i + 1) as u64,
            [x_mm, y_mm, z_mm],
            (u_upx, v_upx),
            0,
            TimestampNs(1_700_000_000_000_000_000 + (i as i128) * 10_000_000),
        )?;
        samples.push(s);
    }

    let residual = IntrinsicsResidual {
        mean_reprojection_error_upx: 50_000,
        max_reprojection_error_upx: 120_000,
        rmse_upx: 65_000,
        covariance: IntrinsicsCovariance {
            fx_variance_upx2: 1000,
            fy_variance_upx2: 1000,
            cx_variance_upx2: 500,
            cy_variance_upx2: 500,
            skew_variance_u2: 10,
        },
        observation_count: samples.len(),
        frame_count: 1,
    };

    let validity = CaptureInterval::new(
        TimestampNs(1_700_000_000_000_000_000),
        TimestampNs(1_700_010_000_000_000_000),
    )?;

    let cert = IntrinsicsCertificateBuilder::new(&format!("cert:intrinsics:{device_id_suffix}"))?
        .device(
            DeviceId::parse(format!("dev:camera:{device_id_suffix}"))?,
            DeviceGeneration::parse("dev:gen:sensor-rev-1")?,
            FirmwareGeneration::parse("fw:gen:v1.0.0")?,
        )
        .calibration_generation(CalibrationGeneration::parse(format!(
            "cal:intrinsics:{cal_gen_suffix}"
        ))?)
        .intrinsics(intrinsics)
        .residual(residual)
        .validity(validity)
        .evidence(samples)?
        .build()?;

    Ok(cert)
}

/// Helper for a standard well-behaved non-identity rigid transform with positive depth.
fn sample_test_transform() -> Result<RigidTransform3D, Box<dyn Error>> {
    let theta_rad = 15.0_f64.to_radians();
    let cos_t = theta_rad.cos();
    let sin_t = theta_rad.sin();
    let rotation = [[cos_t, 0.0, sin_t], [0.0, 1.0, 0.0], [-sin_t, 0.0, cos_t]];
    let translation = [200.0, 100.0, 50.0];
    Ok(RigidTransform3D::from_f64_parts(rotation, translation)?)
}

/// Helper to generate synthetic cross-camera correspondences given ground-truth rigid transform.
fn generate_synthetic_correspondences(
    count: usize,
    transform: &RigidTransform3D,
    source_intrinsics: &CameraIntrinsics,
    target_intrinsics: &CameraIntrinsics,
    base_time_ns: i128,
) -> Result<Vec<ExtrinsicsCorrespondence>, Box<dyn Error>> {
    let mut correspondences = Vec::with_capacity(count);
    let mut prng: u64 = 0xcafe_babe_dead_beef;

    let mut next_u64 = || {
        prng ^= prng >> 12;
        prng ^= prng << 25;
        prng ^= prng >> 27;
        prng.wrapping_mul(0x2545_f491_4f6c_dd1d_u64)
    };

    for i in 0..count {
        let t_ns = base_time_ns + (i as i128) * 10_000_000;

        let quadrant = i % 4;
        let (sign_x, sign_y) = match quadrant {
            0 => (1.0, 1.0),
            1 => (-1.0, 1.0),
            2 => (-1.0, -1.0),
            _ => (1.0, -1.0),
        };

        let rand_x = ((next_u64() % 1000) as f64) / 5.0 + 100.0;
        let rand_y = ((next_u64() % 1000) as f64) / 5.0 + 100.0;
        let z_mm = 2000.0 + ((next_u64() % 1500) as f64);

        let x_mm = (sign_x * rand_x).round() as i32;
        let y_mm = (sign_y * rand_y).round() as i32;
        let z_mm_i = z_mm.round() as i32;

        let p_src = [x_mm as f64, y_mm as f64, z_mm_i as f64];
        let p_tgt = transform.transform_point_f64(p_src);
        let tgt_i32 = [
            p_tgt[0].round() as i32,
            p_tgt[1].round() as i32,
            p_tgt[2].round() as i32,
        ];

        let proj_src = source_intrinsics.project_point_f64(p_src)?;
        let proj_tgt = target_intrinsics.project_point_f64(p_tgt)?;

        let u_src_upx = (proj_src[0] * 1_000_000.0).round() as i64;
        let v_src_upx = (proj_src[1] * 1_000_000.0).round() as i64;
        let u_tgt_upx = (proj_tgt[0] * 1_000_000.0).round() as i64;
        let v_tgt_upx = (proj_tgt[1] * 1_000_000.0).round() as i64;

        let corr = ExtrinsicsCorrespondence::new(
            (i + 1) as u64,
            (1000 + i) as u64,
            [x_mm, y_mm, z_mm_i],
            tgt_i32,
            (u_src_upx, v_src_upx),
            (u_tgt_upx, v_tgt_upx),
            TimestampNs(t_ns),
        )?;

        correspondences.push(corr);
    }

    Ok(correspondences)
}

#[test]
fn test_extrinsics_reference_solver_known_geometry() -> Result<(), Box<dyn Error>> {
    let source_cert = build_test_intrinsics("cam-1", "001")?;
    let target_cert = build_test_intrinsics("cam-2", "001")?;

    // Ground truth: 15 degree yaw around Y axis, translation [400mm, -150mm, 200mm]
    let theta_rad = 15.0_f64.to_radians();
    let cos_t = theta_rad.cos();
    let sin_t = theta_rad.sin();

    let gt_rotation = [[cos_t, 0.0, sin_t], [0.0, 1.0, 0.0], [-sin_t, 0.0, cos_t]];
    let gt_translation = [400.0, -150.0, 200.0];

    let gt_transform = RigidTransform3D::from_f64_parts(gt_rotation, gt_translation)?;

    let correspondences = generate_synthetic_correspondences(
        32,
        &gt_transform,
        &source_cert.intrinsics,
        &target_cert.intrinsics,
        1_700_000_000_000_000_000,
    )?;

    let validity = CaptureInterval::new(
        TimestampNs(1_700_000_000_000_000_000),
        TimestampNs(1_700_010_000_000_000_000),
    )?;

    let req = ExtrinsicsSolveRequest {
        certificate_id: "ext:cert:cam1-cam2-001".to_string(),
        source_certificate: &source_cert,
        target_certificate: &target_cert,
        correspondences,
        validity,
        calibration_generation: CalibrationGeneration::parse("cal:extrinsics:gen-1")?,
        max_reprojection_tolerance_upx: 500_000, // 0.5 px
    };

    let cert = solve_extrinsics(&req)?;

    // 1. Verify recovered rotation matches ground truth within 0.005
    for i in 0..3 {
        for j in 0..3 {
            let diff = (cert.transform.rotation[i][j].to_f64() - gt_rotation[i][j]).abs();
            assert!(
                diff < 0.005,
                "Rotation mismatch at [{i}][{j}]: got {}, expected {}, diff {}",
                cert.transform.rotation[i][j].to_f64(),
                gt_rotation[i][j],
                diff
            );
        }
    }

    // 2. Verify recovered translation matches ground truth within 5 mm
    for i in 0..3 {
        let diff = (cert.transform.translation_mm[i].to_f64() - gt_translation[i]).abs();
        assert!(
            diff < 5.0,
            "Translation mismatch at [{i}]: got {}, expected {}, diff {}",
            cert.transform.translation_mm[i].to_f64(),
            gt_translation[i],
            diff
        );
    }

    // 3. Verify residual metrics
    assert!(
        cert.residual.rmse_upx < 300_000,
        "RMSE is unexpectedly high: {} upx",
        cert.residual.rmse_upx
    );
    assert_eq!(cert.residual.correspondence_count, 32);

    // 4. Verify camera pair and bindings
    assert_eq!(cert.source_camera.as_str(), "device:camera:cam-1");
    assert_eq!(cert.target_camera.as_str(), "device:camera:cam-2");
    assert_eq!(
        cert.source_intrinsics_digest,
        source_cert.certificate_digest
    );
    assert_eq!(
        cert.target_intrinsics_digest,
        target_cert.certificate_digest
    );

    Ok(())
}

#[test]
fn test_extrinsics_deterministic_canonical_encoding_and_digest() -> Result<(), Box<dyn Error>> {
    let source_cert = build_test_intrinsics("cam-left", "001")?;
    let target_cert = build_test_intrinsics("cam-right", "001")?;

    let gt_transform = sample_test_transform()?;

    let correspondences = generate_synthetic_correspondences(
        16,
        &gt_transform,
        &source_cert.intrinsics,
        &target_cert.intrinsics,
        1_700_000_000_000_000_000,
    )?;

    let validity = CaptureInterval::new(
        TimestampNs(1_700_000_000_000_000_000),
        TimestampNs(1_700_010_000_000_000_000),
    )?;

    let req = ExtrinsicsSolveRequest {
        certificate_id: "ext:cert:det-test".to_string(),
        source_certificate: &source_cert,
        target_certificate: &target_cert,
        correspondences,
        validity,
        calibration_generation: CalibrationGeneration::parse("cal:extrinsics:gen-1")?,
        max_reprojection_tolerance_upx: 1_000_000,
    };

    let cert1 = solve_extrinsics(&req)?;
    let cert2 = solve_extrinsics(&req)?;

    // Bit-identical verification across two independent runs
    assert_eq!(cert1.certificate_digest, cert2.certificate_digest);
    assert_eq!(cert1.evidence_root, cert2.evidence_root);
    assert_eq!(cert1.canonical_bytes()?, cert2.canonical_bytes()?);

    Ok(())
}

#[test]
fn test_extrinsics_identity_transform_strictly_prohibited() -> Result<(), Box<dyn Error>> {
    let source_cert = build_test_intrinsics("cam-1", "001")?;
    let target_cert = build_test_intrinsics("cam-2", "001")?;

    let validity = CaptureInterval::new(
        TimestampNs(1_700_000_000_000_000_000),
        TimestampNs(1_700_010_000_000_000_000),
    )?;

    let correspondences = generate_synthetic_correspondences(
        16,
        &sample_test_transform()?,
        &source_cert.intrinsics,
        &target_cert.intrinsics,
        1_700_000_000_000_000_000,
    )?;

    let residual = ExtrinsicsResidual {
        mean_reprojection_error_upx: 50_000,
        max_reprojection_error_upx: 100_000,
        rmse_upx: 60_000,
        alignment_3d_rmse_umm: 500,
        covariance: ExtrinsicsCovariance {
            rotation_variance_urad2: [100, 100, 100],
            translation_variance_umm2: [500, 500, 500],
        },
        correspondence_count: 16,
    };

    let builder_res = ExtrinsicsCertificateBuilder::new("test-identity-prohibited")?
        .camera_pair(source_cert.device_id.clone(), target_cert.device_id.clone())
        .source_binding(
            source_cert.device_generation.clone(),
            source_cert.firmware_generation.clone(),
            source_cert.certificate_digest,
            source_cert.calibration_generation.clone(),
        )
        .target_binding(
            target_cert.device_generation.clone(),
            target_cert.firmware_generation.clone(),
            target_cert.certificate_digest,
            target_cert.calibration_generation.clone(),
        )
        .calibration_generation(CalibrationGeneration::parse("cal:extrinsics:001")?)
        .transform(RigidTransform3D::IDENTITY)
        .residual(residual)
        .validity(validity)
        .evidence(correspondences)?
        .build();

    match builder_res {
        Err(ExtrinsicsError::IdentityTransformProhibited) => {}
        other => {
            return Err(format!("Expected IdentityTransformProhibited, got: {other:?}").into());
        }
    }

    Ok(())
}

#[test]
fn test_extrinsics_insufficient_correspondences_bound() -> Result<(), Box<dyn Error>> {
    let source_cert = build_test_intrinsics("cam-1", "001")?;
    let target_cert = build_test_intrinsics("cam-2", "001")?;

    let transform = sample_test_transform()?;

    let validity = CaptureInterval::new(
        TimestampNs(1_700_000_000_000_000_000),
        TimestampNs(1_700_010_000_000_000_000),
    )?;

    // Bound - 1: MIN_EXTRINSICS_CORRESPONDENCES - 1 = 7 correspondences
    let samples_7 = generate_synthetic_correspondences(
        MIN_EXTRINSICS_CORRESPONDENCES - 1,
        &transform,
        &source_cert.intrinsics,
        &target_cert.intrinsics,
        1_700_000_000_000_000_000,
    )?;
    assert_eq!(samples_7.len(), 7);

    let req_7 = ExtrinsicsSolveRequest {
        certificate_id: "ext:cert:underflow".to_string(),
        source_certificate: &source_cert,
        target_certificate: &target_cert,
        correspondences: samples_7,
        validity,
        calibration_generation: CalibrationGeneration::parse("cal:extrinsics:001")?,
        max_reprojection_tolerance_upx: 1_000_000,
    };

    match solve_extrinsics(&req_7) {
        Err(ExtrinsicsError::InsufficientCorrespondences {
            count: 7,
            min_required: 8,
        }) => {}
        other => {
            return Err(format!("Expected InsufficientCorrespondences, got: {other:?}").into());
        }
    }

    // Exact bound: MIN_EXTRINSICS_CORRESPONDENCES = 8 correspondences succeeds
    let samples_8 = generate_synthetic_correspondences(
        MIN_EXTRINSICS_CORRESPONDENCES,
        &transform,
        &source_cert.intrinsics,
        &target_cert.intrinsics,
        1_700_000_000_000_000_000,
    )?;
    assert_eq!(samples_8.len(), 8);

    let req_8 = ExtrinsicsSolveRequest {
        certificate_id: "ext:cert:exact-min".to_string(),
        source_certificate: &source_cert,
        target_certificate: &target_cert,
        correspondences: samples_8,
        validity,
        calibration_generation: CalibrationGeneration::parse("cal:extrinsics:001")?,
        max_reprojection_tolerance_upx: 1_000_000,
    };

    let cert_8 = solve_extrinsics(&req_8)?;
    assert_eq!(cert_8.residual.correspondence_count, 8);

    Ok(())
}

#[test]
fn test_extrinsics_too_many_correspondences_bound() -> Result<(), Box<dyn Error>> {
    let source_cert = build_test_intrinsics("cam-1", "001")?;
    let target_cert = build_test_intrinsics("cam-2", "001")?;

    let transform = sample_test_transform()?;

    let validity = CaptureInterval::new(
        TimestampNs(1_700_000_000_000_000_000),
        TimestampNs(1_700_010_000_000_000_000),
    )?;

    // Bound + 1: MAX_EXTRINSICS_CORRESPONDENCES + 1 = 513
    let samples_513 = generate_synthetic_correspondences(
        MAX_EXTRINSICS_CORRESPONDENCES + 1,
        &transform,
        &source_cert.intrinsics,
        &target_cert.intrinsics,
        1_700_000_000_000_000_000,
    )?;
    assert_eq!(samples_513.len(), 513);

    let req_513 = ExtrinsicsSolveRequest {
        certificate_id: "ext:cert:overflow".to_string(),
        source_certificate: &source_cert,
        target_certificate: &target_cert,
        correspondences: samples_513,
        validity,
        calibration_generation: CalibrationGeneration::parse("cal:extrinsics:001")?,
        max_reprojection_tolerance_upx: 1_000_000,
    };

    match solve_extrinsics(&req_513) {
        Err(ExtrinsicsError::TooManyCorrespondences {
            actual: 513,
            max: 512,
        }) => {}
        other => return Err(format!("Expected TooManyCorrespondences, got: {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_extrinsics_certificate_id_bounds() -> Result<(), Box<dyn Error>> {
    // 1. Empty ID rejected
    match ExtrinsicsCertificateBuilder::new("") {
        Err(ExtrinsicsError::EmptyCertificateId) => {}
        other => return Err(format!("Expected EmptyCertificateId, got: {other:?}").into()),
    }

    // 2. Exact bound: MAX_CERTIFICATE_ID_BYTES (128) succeeds
    let id_128 = "a".repeat(MAX_CERTIFICATE_ID_BYTES);
    assert!(ExtrinsicsCertificateBuilder::new(&id_128).is_ok());

    // 3. Bound + 1: MAX_CERTIFICATE_ID_BYTES + 1 (129) rejected
    let id_129 = "a".repeat(MAX_CERTIFICATE_ID_BYTES + 1);
    match ExtrinsicsCertificateBuilder::new(&id_129) {
        Err(ExtrinsicsError::CertificateIdTooLong {
            actual: 129,
            max: 128,
        }) => {}
        other => return Err(format!("Expected CertificateIdTooLong, got: {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_extrinsics_residual_tolerance_bound() -> Result<(), Box<dyn Error>> {
    let source_cert = build_test_intrinsics("cam-1", "001")?;
    let target_cert = build_test_intrinsics("cam-2", "001")?;

    let transform = sample_test_transform()?;

    let correspondences = generate_synthetic_correspondences(
        16,
        &transform,
        &source_cert.intrinsics,
        &target_cert.intrinsics,
        1_700_000_000_000_000_000,
    )?;

    let validity = CaptureInterval::new(
        TimestampNs(1_700_000_000_000_000_000),
        TimestampNs(1_700_010_000_000_000_000),
    )?;

    // Exact bound: RMSE at MAX_EXTRINSICS_REPROJECTION_TOLERANCE_UPX (10,000,000 upx) succeeds
    let residual_at_bound = ExtrinsicsResidual {
        mean_reprojection_error_upx: 5_000_000,
        max_reprojection_error_upx: 9_000_000,
        rmse_upx: MAX_EXTRINSICS_REPROJECTION_TOLERANCE_UPX,
        alignment_3d_rmse_umm: 50_000,
        covariance: ExtrinsicsCovariance {
            rotation_variance_urad2: [100, 100, 100],
            translation_variance_umm2: [500, 500, 500],
        },
        correspondence_count: 16,
    };

    let builder_bound = ExtrinsicsCertificateBuilder::new("cert:bound")?
        .camera_pair(source_cert.device_id.clone(), target_cert.device_id.clone())
        .source_binding(
            source_cert.device_generation.clone(),
            source_cert.firmware_generation.clone(),
            source_cert.certificate_digest,
            source_cert.calibration_generation.clone(),
        )
        .target_binding(
            target_cert.device_generation.clone(),
            target_cert.firmware_generation.clone(),
            target_cert.certificate_digest,
            target_cert.calibration_generation.clone(),
        )
        .calibration_generation(CalibrationGeneration::parse("cal:extrinsics:001")?)
        .transform(transform.clone())
        .residual(residual_at_bound)
        .validity(validity)
        .evidence(correspondences.clone())?
        .build();

    assert!(builder_bound.is_ok());

    // Bound + 1: RMSE at 10,000,001 upx rejected with ResidualExceedsTolerance
    let residual_above_bound = ExtrinsicsResidual {
        mean_reprojection_error_upx: 5_000_000,
        max_reprojection_error_upx: 9_000_000,
        rmse_upx: MAX_EXTRINSICS_REPROJECTION_TOLERANCE_UPX + 1,
        alignment_3d_rmse_umm: 50_000,
        covariance: ExtrinsicsCovariance {
            rotation_variance_urad2: [100, 100, 100],
            translation_variance_umm2: [500, 500, 500],
        },
        correspondence_count: 16,
    };

    let builder_above = ExtrinsicsCertificateBuilder::new("cert:above")?
        .camera_pair(source_cert.device_id.clone(), target_cert.device_id.clone())
        .source_binding(
            source_cert.device_generation.clone(),
            source_cert.firmware_generation.clone(),
            source_cert.certificate_digest,
            source_cert.calibration_generation.clone(),
        )
        .target_binding(
            target_cert.device_generation.clone(),
            target_cert.firmware_generation.clone(),
            target_cert.certificate_digest,
            target_cert.calibration_generation.clone(),
        )
        .calibration_generation(CalibrationGeneration::parse("cal:extrinsics:001")?)
        .transform(transform)
        .residual(residual_above_bound)
        .validity(validity)
        .evidence(correspondences)?
        .build();

    match builder_above {
        Err(ExtrinsicsError::ResidualExceedsTolerance {
            actual_rmse_upx,
            max_allowed_upx,
        }) => {
            assert_eq!(
                actual_rmse_upx,
                MAX_EXTRINSICS_REPROJECTION_TOLERANCE_UPX + 1
            );
            assert_eq!(max_allowed_upx, MAX_EXTRINSICS_REPROJECTION_TOLERANCE_UPX);
        }
        other => return Err(format!("Expected ResidualExceedsTolerance, got: {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_extrinsics_degenerate_geometry_rejected() -> Result<(), Box<dyn Error>> {
    let source_cert = build_test_intrinsics("cam-1", "001")?;
    let target_cert = build_test_intrinsics("cam-2", "001")?;

    let validity = CaptureInterval::new(
        TimestampNs(1_700_000_000_000_000_000),
        TimestampNs(1_700_010_000_000_000_000),
    )?;

    // Create 16 collinear points (spread only along X axis, Y=0 and Z=2000 constant)
    let mut collinear_samples = Vec::new();
    for i in 0..16 {
        let x_mm = i * 50;
        let s = ExtrinsicsCorrespondence::new(
            (i + 1) as u64,
            (2000 + i) as u64,
            [x_mm, 0, 2000],
            [x_mm + 100, 50, 2000],
            (500_000, 500_000),
            (600_000, 550_000),
            TimestampNs(1_700_000_000_000_000_000),
        )?;
        collinear_samples.push(s);
    }

    let req = ExtrinsicsSolveRequest {
        certificate_id: "ext:cert:collinear".to_string(),
        source_certificate: &source_cert,
        target_certificate: &target_cert,
        correspondences: collinear_samples,
        validity,
        calibration_generation: CalibrationGeneration::parse("cal:extrinsics:001")?,
        max_reprojection_tolerance_upx: 1_000_000,
    };

    match solve_extrinsics(&req) {
        Err(ExtrinsicsError::DegenerateCorrespondences { reason }) => {
            assert!(
                reason.contains("collinear"),
                "Expected collinearity reason, got: {reason}"
            );
        }
        other => return Err(format!("Expected DegenerateCorrespondences, got: {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_extrinsics_identical_camera_pair_rejected() -> Result<(), Box<dyn Error>> {
    let source_cert = build_test_intrinsics("cam-1", "001")?;

    let transform = sample_test_transform()?;

    let correspondences = generate_synthetic_correspondences(
        16,
        &transform,
        &source_cert.intrinsics,
        &source_cert.intrinsics,
        1_700_000_000_000_000_000,
    )?;

    let validity = CaptureInterval::new(
        TimestampNs(1_700_000_000_000_000_000),
        TimestampNs(1_700_010_000_000_000_000),
    )?;

    let req = ExtrinsicsSolveRequest {
        certificate_id: "ext:cert:self".to_string(),
        source_certificate: &source_cert,
        target_certificate: &source_cert,
        correspondences,
        validity,
        calibration_generation: CalibrationGeneration::parse("cal:extrinsics:001")?,
        max_reprojection_tolerance_upx: 1_000_000,
    };

    match solve_extrinsics(&req) {
        Err(ExtrinsicsError::IdenticalCameraPair { camera }) => {
            assert_eq!(camera.as_str(), "device:camera:cam-1");
        }
        other => return Err(format!("Expected IdenticalCameraPair, got: {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_extrinsics_stale_validity_interval() -> Result<(), Box<dyn Error>> {
    let source_cert = build_test_intrinsics("cam-1", "001")?;
    let target_cert = build_test_intrinsics("cam-2", "001")?;

    let transform = sample_test_transform()?;

    let correspondences = generate_synthetic_correspondences(
        16,
        &transform,
        &source_cert.intrinsics,
        &target_cert.intrinsics,
        1_700_000_000_000_000_000,
    )?;

    let validity = CaptureInterval::new(
        TimestampNs(1_700_000_000_000_000_000),
        TimestampNs(1_700_010_000_000_000_000),
    )?;

    let cert = solve_extrinsics(&ExtrinsicsSolveRequest {
        certificate_id: "ext:cert:stale".to_string(),
        source_certificate: &source_cert,
        target_certificate: &target_cert,
        correspondences,
        validity,
        calibration_generation: CalibrationGeneration::parse("cal:extrinsics:001")?,
        max_reprojection_tolerance_upx: 1_000_000,
    })?;

    // Valid time inside window
    assert!(
        cert.validate_at_time(TimestampNs(1_700_005_000_000_000_000))
            .is_ok()
    );

    // Stale: time after latest
    match cert.validate_at_time(TimestampNs(1_700_015_000_000_000_000)) {
        Err(ExtrinsicsError::StaleCertificatePastValidity {
            requested,
            valid_until,
        }) => {
            assert_eq!(requested, TimestampNs(1_700_015_000_000_000_000));
            assert_eq!(valid_until, TimestampNs(1_700_010_000_000_000_000));
        }
        other => {
            return Err(format!("Expected StaleCertificatePastValidity, got: {other:?}").into());
        }
    }

    Ok(())
}

#[test]
fn test_extrinsics_intrinsics_and_device_generation_mismatches() -> Result<(), Box<dyn Error>> {
    let source_cert = build_test_intrinsics("cam-1", "001")?;
    let target_cert = build_test_intrinsics("cam-2", "001")?;

    let transform = sample_test_transform()?;

    let correspondences = generate_synthetic_correspondences(
        16,
        &transform,
        &source_cert.intrinsics,
        &target_cert.intrinsics,
        1_700_000_000_000_000_000,
    )?;

    let validity = CaptureInterval::new(
        TimestampNs(1_700_000_000_000_000_000),
        TimestampNs(1_700_010_000_000_000_000),
    )?;

    let cert = solve_extrinsics(&ExtrinsicsSolveRequest {
        certificate_id: "ext:cert:mismatch".to_string(),
        source_certificate: &source_cert,
        target_certificate: &target_cert,
        correspondences,
        validity,
        calibration_generation: CalibrationGeneration::parse("cal:extrinsics:001")?,
        max_reprojection_tolerance_upx: 1_000_000,
    })?;

    // Valid pair
    let dev1 = DeviceId::parse("dev:camera:cam-1")?;
    let dev2 = DeviceId::parse("dev:camera:cam-2")?;
    let dev3 = DeviceId::parse("dev:camera:cam-3")?;

    assert!(cert.validate_camera_pair(&dev1, &dev2).is_ok());

    // Wrong target camera
    match cert.validate_camera_pair(&dev1, &dev3) {
        Err(ExtrinsicsError::CameraIdMismatch { expected, actual }) => {
            assert_eq!(expected.as_str(), "device:camera:cam-2");
            assert_eq!(actual.as_str(), "device:camera:cam-3");
        }
        other => return Err(format!("Expected CameraIdMismatch, got: {other:?}").into()),
    }

    // Mismatched intrinsics certificate
    let other_target_cert = build_test_intrinsics("cam-2", "002")?;
    match cert.validate_intrinsics(&source_cert, &other_target_cert) {
        Err(ExtrinsicsError::TargetIntrinsicsDigestMismatch { .. })
        | Err(ExtrinsicsError::CalibrationGenerationMismatch { .. }) => {}
        other => {
            return Err(format!("Expected intrinsics digest/gen mismatch, got: {other:?}").into());
        }
    }

    Ok(())
}

#[test]
fn test_extrinsics_lifecycle_invalidation_on_contradiction() -> Result<(), Box<dyn Error>> {
    let source_cert = build_test_intrinsics("cam-1", "001")?;
    let target_cert = build_test_intrinsics("cam-2", "001")?;

    let gt_transform = sample_test_transform()?;

    let correspondences = generate_synthetic_correspondences(
        16,
        &gt_transform,
        &source_cert.intrinsics,
        &target_cert.intrinsics,
        1_700_000_000_000_000_000,
    )?;

    let validity = CaptureInterval::new(
        TimestampNs(1_700_000_000_000_000_000),
        TimestampNs(1_700_010_000_000_000_000),
    )?;

    let cert = solve_extrinsics(&ExtrinsicsSolveRequest {
        certificate_id: "ext:cert:lifecycle".to_string(),
        source_certificate: &source_cert,
        target_certificate: &target_cert,
        correspondences: correspondences.clone(),
        validity,
        calibration_generation: CalibrationGeneration::parse("cal:extrinsics:001")?,
        max_reprojection_tolerance_upx: 1_000_000,
    })?;

    let mut lifecycle = ExtrinsicsLifecycle::new();
    lifecycle.activate_certificate(
        cert,
        &target_cert,
        TimestampNs(1_700_005_000_000_000_000),
    )?;
    assert!(lifecycle.is_active());

    // 1. Verify a consistent observation passes verification
    lifecycle.verify_observation(&correspondences[0], 500_000)?;
    assert!(lifecycle.is_active());

    // 2. Introduce a contradictory observation (camera moved, pixel is 50 pixels away = 50,000,000 upx error)
    let bad_obs = ExtrinsicsCorrespondence::new(
        999,
        5555,
        correspondences[0].source_point_mm,
        correspondences[0].target_point_mm,
        correspondences[0].source_pixel_upx,
        (
            correspondences[0].target_pixel_upx.0 + 50_000_000,
            correspondences[0].target_pixel_upx.1,
        ),
        TimestampNs(1_700_005_000_000_000_000),
    )?;

    match lifecycle.verify_observation(&bad_obs, 500_000) {
        Err(ExtrinsicsError::ContradictedExtrinsics {
            correspondence_id: 999,
            observed_error_upx,
            tolerance_upx: 500_000,
        }) => {
            assert!(
                observed_error_upx > 40_000_000,
                "Observed error was lower than expected: {observed_error_upx}"
            );
        }
        other => return Err(format!("Expected ContradictedExtrinsics, got: {other:?}").into()),
    }

    // 3. Lifecycle state must now be Invalidated
    assert!(!lifecycle.is_active());
    match lifecycle.state() {
        ExtrinsicsLifecycleState::Invalidated {
            reason,
            contradicting_evidence,
            ..
        } => {
            assert!(reason.contains("contradiction"));
            assert_eq!(
                contradicting_evidence.as_ref().map(|c| c.correspondence_id),
                Some(999)
            );
        }
        other => return Err(format!("Expected Invalidated state, got: {other:?}").into()),
    }

    // 4. Subsequent queries fail with CertificateInvalidated
    match lifecycle.active_certificate() {
        Err(ExtrinsicsError::CertificateInvalidated { .. }) => {}
        other => return Err(format!("Expected CertificateInvalidated, got: {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_extrinsics_rigid_transform_inverse_and_point_transforms() -> Result<(), Box<dyn Error>> {
    let theta_rad = 30.0_f64.to_radians();
    let cos_t = theta_rad.cos();
    let sin_t = theta_rad.sin();

    let rotation = [[cos_t, -sin_t, 0.0], [sin_t, cos_t, 0.0], [0.0, 0.0, 1.0]];
    let translation = [300.0, -200.0, 150.0];

    let transform = RigidTransform3D::from_f64_parts(rotation, translation)?;
    let inv = transform.inverse()?;

    let p = [100.0, 200.0, 1500.0];
    let p_transformed = transform.transform_point_f64(p);
    let p_roundtrip = inv.transform_point_f64(p_transformed);

    for i in 0..3 {
        let diff = (p[i] - p_roundtrip[i]).abs();
        assert!(
            diff < 0.001,
            "Roundtrip mismatch at [{i}]: got {}, expected {}, diff {}",
            p_roundtrip[i],
            p[i],
            diff
        );
    }

    // Fixed-point transform test
    let p_fixed = [
        Fixed64::from_integer(100),
        Fixed64::from_integer(200),
        Fixed64::from_integer(1500),
    ];
    let p_fixed_trans = transform.transform_point_fixed(p_fixed)?;
    let p_fixed_roundtrip = inv.transform_point_fixed(p_fixed_trans)?;

    for i in 0..3 {
        let diff = (p_fixed[i].to_f64() - p_fixed_roundtrip[i].to_f64()).abs();
        assert!(
            diff < 0.001,
            "Fixed-point roundtrip mismatch at [{i}]: got {}, expected {}, diff {}",
            p_fixed_roundtrip[i].to_f64(),
            p_fixed[i].to_f64(),
            diff
        );
    }

    Ok(())
}

#[test]
fn test_extrinsics_reference_solver_trait() -> Result<(), Box<dyn Error>> {
    let source_cert = build_test_intrinsics("cam-a", "001")?;
    let target_cert = build_test_intrinsics("cam-b", "001")?;

    let transform = sample_test_transform()?;

    let correspondences = generate_synthetic_correspondences(
        16,
        &transform,
        &source_cert.intrinsics,
        &target_cert.intrinsics,
        1_700_000_000_000_000_000,
    )?;

    let validity = CaptureInterval::new(
        TimestampNs(1_700_000_000_000_000_000),
        TimestampNs(1_700_010_000_000_000_000),
    )?;

    let solver = ReferenceExtrinsicsSolver::new();
    let req = ExtrinsicsSolveRequest {
        certificate_id: "ext:cert:trait-test".to_string(),
        source_certificate: &source_cert,
        target_certificate: &target_cert,
        correspondences,
        validity,
        calibration_generation: CalibrationGeneration::parse("cal:extrinsics:001")?,
        max_reprojection_tolerance_upx: 1_000_000,
    };

    use fss_reference::ExtrinsicsSolver;
    let cert = solver.solve(&req)?;
    assert_eq!(cert.certificate_id, "ext:cert:trait-test");
    assert_eq!(cert.residual.correspondence_count, 16);

    Ok(())
}
