#![forbid(unsafe_code)]

use super::*;
use fss_cli::json_input::{Value, parse};
use fss_geometry::WorkBudget;
use fss_twin::rectification::{RawFrameIdentity, RawGrayFrame, RectificationPlan};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn field<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a Value> {
    let mut value = value;
    for key in path {
        value = value
            .object()
            .and_then(|fields| fields.get(*key))
            .ok_or("report field")?;
    }
    Ok(value)
}

#[test]
fn direct_image_report_names_actual_feature_grid_without_inventing_a_transform() -> TestResult {
    let output = ImageIdentity {
        exposure: [1; 32],
        pixels: [2; 32],
        image_domain: [3; 32],
        dimensions: [80, 48],
    };
    let text = processing(output, [4; 32], None);
    let value = parse(&text)?;
    assert_eq!(value.object().ok_or("object")?.len(), 3);
    assert_eq!(field(&value, &["kind"])?.text(), Some("native_pinhole"));
    assert_eq!(
        field(&value, &["output", "dimensions"])?
            .array()
            .ok_or("dimensions")?,
        &[Value::Number("80".into()), Value::Number("48".into())]
    );
    assert_eq!(
        field(&value, &["output", "pixel_digest"])?.text(),
        Some(
            ContentDigest::new(DigestAlgorithm::Sha256, [2; 32])
                .to_text()
                .as_str()
        )
    );
    println!("FSS_IMAGE_PROCESSING_FIXTURE direct {text}");
    Ok(())
}

#[test]
fn native_model_receipts_keep_raw_and_corrected_images_separate() -> TestResult {
    for (name, distortion) in [
        ("pinhole", LensDistortion::Pinhole),
        (
            "brown_conrady",
            LensDistortion::BrownConrady {
                radial: [0.025, 0.003, -0.0001],
                tangential: [0.0003, -0.0002],
            },
        ),
        (
            "fisheye",
            LensDistortion::Fisheye {
                coefficients: [0.01, 0.001, 0.0, 0.0],
            },
        ),
    ] {
        let spec = RectificationSpec {
            source: PinholeIntrinsics::new(96, 80, 100.0, 110.0, 48.0, 40.0)?,
            target: PinholeIntrinsics::new(80, 48, 75.0, 80.0, 40.0, 24.0)?,
            distortion,
            maximum_radius: 1.0,
            source_domain: [5; 32],
            calibration: [6; 32],
            range: LumaRange::Video,
        };
        let pixels = (0..96 * 80)
            .map(|i| (16 + (i * 31) % 220) as u8)
            .collect::<Vec<_>>();
        let mut allowed = vec![1; pixels.len()];
        for y in 0..80 {
            for x in 44..49 {
                allowed[y * 96 + x] = 0;
            }
        }
        let identity = RawFrameIdentity {
            exposure: [7; 32],
            storage: ContentDigest::sha256(&pixels).bytes(),
            allowed_mask: ContentDigest::sha256(&allowed).bytes(),
            image_domain: spec.source_domain,
            calibration: spec.calibration,
            dimensions: [96, 80],
            row_stride: 96,
            range: spec.range,
        };
        let mut work = WorkBudget::new(20_000_000);
        let plan = RectificationPlan::compile(spec, &mut work)?;
        let raw = RawGrayFrame::new(identity, &pixels, &allowed, &mut work)?;
        let corrected = plan.apply(&raw, &mut work)?;
        let receipt = corrected.receipt();
        assert!(receipt.privacy_rejected > 0);
        assert_ne!(corrected.identity().pixels, identity.storage);
        let text = processing(
            corrected.identity(),
            receipt.allowed_mask,
            Some((spec, receipt)),
        );
        let value = parse(&text)?;
        assert_eq!(field(&value, &["kind"])?.text(), Some("native_rectified"));
        assert_eq!(
            field(&value, &["model", "distortion", "kind"])?.text(),
            Some(name)
        );
        assert_eq!(
            field(&value, &["model", "source_intrinsics", "width"])?.integer(),
            Some(96)
        );
        assert_eq!(
            field(&value, &["model", "target_intrinsics", "width"])?.integer(),
            Some(80)
        );
        assert_eq!(
            field(&value, &["source", "row_stride"])?.integer(),
            Some(96)
        );
        assert_eq!(
            field(&value, &["source", "exposure_digest"])?,
            field(&value, &["output", "exposure_digest"])?
        );
        assert_ne!(
            field(&value, &["source", "storage_digest"])?,
            field(&value, &["output", "pixel_digest"])?
        );
        assert_eq!(
            field(&value, &["coverage", "privacy_rejected"])?.integer(),
            Some(receipt.privacy_rejected as i128)
        );
        assert_eq!(field(&value, &["output_luma_range"])?.text(), Some("full"));
        assert_eq!(
            field(&value, &["calibration_established"])?.boolean(),
            Some(false)
        );
        println!("FSS_IMAGE_PROCESSING_FIXTURE {name} {text}");
    }
    Ok(())
}

#[test]
fn corrected_reports_keep_interpolation_and_calibration_uncertainty_explicit() -> TestResult {
    for multi in [false, true] {
        let value = parse(&assumptions(multi))?;
        let values = value.array().ok_or("assumptions")?;
        assert!(values.iter().any(|v| v.text() == Some(
            "pixel_noise_covariance_excludes_interpolation_correlations_and_lens_parameter_error")));
        assert!(
            values
                .iter()
                .any(|v| v.text() == Some("sigma_pixels_is_declared_on_the_actual_output_grid"))
        );
        assert_eq!(
            values.iter().any(|v| v.text()
                == Some("all_participating_component_views_are_required_with_no_outlier_removal")),
            multi
        );
    }
    Ok(())
}
