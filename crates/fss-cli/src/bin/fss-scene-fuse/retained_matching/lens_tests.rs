#![forbid(unsafe_code)]
//! Real retained owners through explicit v2 image modes; no inferred lens calibration.
//! The original JPEG plane has baseline1, focal160, disparity16 and independent depth10.
//! An integer32×16 crop preserves the feature descriptors and world-point oracle.

use super::tests::{Fixture, checked, context, field, h, json, put};
use super::*;
use crate::matching::fixtures::{HEIGHT, WIDTH};
use fss_cli::json_input::{Value, parse};
use fss_cli::json_output::{object, string};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn crop_fixture(label: &str, raw: [bool; 2]) -> TestResult<Fixture> {
    let mut f = Fixture::new(label)?;
    let mut rig = parse(std::str::from_utf8(&fs::read(&f.options.rig)?)?)?;
    let mut query = f.document.clone();
    put(
        &mut query,
        &["schema"],
        Value::Text(input::SCHEMA_V2.into()),
    )?;
    for (index, side) in ["left", "right"].into_iter().enumerate() {
        let domain = field(&query, &[side, "image_domain_digest"])?.clone();
        let image = if raw[index] {
            let camera_index = index.to_string();
            for (key, value) in [("width", 128), ("height", 96), ("cx", 64), ("cy", 48)] {
                put(
                    &mut rig,
                    &["cameras", &camera_index, "intrinsics", key],
                    Value::Number(value.to_string()),
                )?;
            }
            parse(&object(&[
                ("kind", string("rectified")),
                ("source_domain_digest", json(&domain)),
                (
                    "lens_basis",
                    string(&h(format!("declared original pinhole crop {side}")).to_text()),
                ),
                (
                    "source_intrinsics",
                    r#"{"width":192,"height":128,"fx":160,"fy":160,"cx":96,"cy":64}"#.into(),
                ),
                ("distortion", r#"{"kind":"pinhole"}"#.into()),
                ("maximum_radius", "1".into()),
                ("luma_range", string("full")),
            ]))?
        } else {
            parse(&object(&[
                ("kind", string("pinhole")),
                ("image_domain_digest", json(&domain)),
            ]))?
        };
        let Value::Object(top) = &mut query else {
            return Err("query object".into());
        };
        let Value::Object(view) = top.get_mut(side).ok_or("view")? else {
            return Err("view object".into());
        };
        view.remove("image_domain_digest");
        view.insert("image".into(), image);
    }
    let rig = json(&rig);
    fs::write(&f.options.rig, &rig)?;
    put(
        &mut query,
        &["camera_rig_digest"],
        Value::Text(h(&rig).to_text()),
    )?;
    f.set_query(&query)?;
    f.document = query;
    Ok(f)
}

fn refused(f: &Fixture) -> TestResult {
    let mut stdout = Vec::new();
    assert!(execute(&f.options, &mut stdout).is_err());
    assert!(stdout.is_empty());
    if let Some(path) = &f.options.report_out {
        assert!(!path.exists());
    }
    Ok(())
}

#[test]
fn retained_crop_and_mixed_native_views_reconstruct_the_same_known_plane() -> TestResult {
    for raw in [[true, true], [true, false]] {
        let f = crop_fixture(if raw[1] { "lens-both" } else { "lens-mixed" }, raw)?;
        let mut stdout = Vec::new();
        assert!(checked(execute(&f.options, &mut stdout))?);
        assert_eq!(
            stdout,
            fs::read(f.options.report_out.as_ref().ok_or("output")?)?
        );
        let value = parse(std::str::from_utf8(&stdout)?)?;
        assert_eq!(
            field(&value, &["schema"])?.text(),
            Some("fss.scene_feature_match_retained.v2")
        );
        assert_eq!(
            field(&value, &["report", "schema"])?.text(),
            Some("fss.scene_feature_match_retained_report.v2")
        );
        let analysis = field(&value, &["report", "analysis"])?;
        assert_eq!(
            field(analysis, &["physical_identity_established"])?.boolean(),
            Some(false)
        );
        let hypotheses = field(analysis, &["hypotheses"])?
            .array()
            .ok_or("hypotheses")?;
        assert!(
            hypotheses.len() >= 3,
            "crop lost all useful native correspondences"
        );
        for point in hypotheses {
            let Value::Number(z) = field(point, &["estimate", "position", "2"])? else {
                return Err("point depth".into());
            };
            assert!((z.parse::<f64>()? - 10.0).abs() < 1e-8);
        }
        for (index, view) in field(analysis, &["views"])?
            .array()
            .ok_or("views")?
            .iter()
            .enumerate()
        {
            let processing = field(view, &["image_processing"])?;
            assert_eq!(
                field(view, &["source", "dimensions", "0"])?.integer(),
                Some(i128::from(WIDTH))
            );
            assert_eq!(
                field(view, &["source", "dimensions", "1"])?.integer(),
                Some(i128::from(HEIGHT))
            );
            assert_eq!(
                field(view, &["source", "encoded_source_digest"])?.text(),
                Some(f.capsules[index].source_digest.to_text().as_str())
            );
            assert_eq!(
                field(processing, &["output", "exposure_digest"])?,
                field(view, &["source", "exposure_digest"])?
            );
            assert_eq!(
                field(processing, &["output", "image_domain_digest"])?,
                field(view, &["image_domain_digest"])?
            );
            assert_eq!(
                field(processing, &["allowed_mask_digest"])?,
                field(view, &["allowed_mask_digest"])?
            );
            if raw[index] {
                assert_eq!(
                    field(processing, &["kind"])?.text(),
                    Some("native_rectified")
                );
                assert_eq!(
                    field(processing, &["source", "dimensions", "0"])?.integer(),
                    Some(192)
                );
                assert_eq!(
                    field(processing, &["output", "dimensions", "0"])?.integer(),
                    Some(128)
                );
                assert_eq!(
                    field(processing, &["output", "dimensions", "1"])?.integer(),
                    Some(96)
                );
                assert_eq!(
                    field(processing, &["source", "storage_digest"])?,
                    field(view, &["source", "pixel_digest"])?
                );
                assert_ne!(
                    field(processing, &["output", "pixel_digest"])?,
                    field(view, &["source", "pixel_digest"])?
                );
                assert_eq!(
                    field(processing, &["model", "target_intrinsics", "width"])?,
                    field(view, &["intrinsics", "width"])?
                );
                assert_eq!(
                    field(processing, &["coverage", "allowed_pixels"])?.integer(),
                    Some(128 * 96)
                );
                assert_eq!(
                    field(processing, &["calibration_established"])?.boolean(),
                    Some(false)
                );
            } else {
                assert_eq!(field(processing, &["kind"])?.text(), Some("native_pinhole"));
                assert_eq!(
                    field(processing, &["output", "pixel_digest"])?,
                    field(view, &["source", "pixel_digest"])?
                );
            }
        }
    }
    Ok(())
}

#[test]
fn folded_later_lens_is_refused_before_any_retained_jpeg_publication() -> TestResult {
    let mut f = crop_fixture("lens-preflight", [true, true])?;
    let mut query = f.document.clone();
    put(
        &mut query,
        &["right", "image", "distortion"],
        parse(r#"{"kind":"brown_conrady","radial":[-1,0,0],"tangential":[0,0]}"#)?,
    )?;
    f.set_query(&query)?;
    refused(&f)?;
    assert_eq!(f.head()?, f.head);
    Ok(())
}

#[test]
fn declared_source_grid_cannot_relabel_the_actual_retained_decoder_dimensions() -> TestResult {
    let mut f = crop_fixture("lens-source-grid", [true, false])?;
    let mut query = f.document.clone();
    put(
        &mut query,
        &["left", "image", "source_intrinsics", "width"],
        Value::Number("191".into()),
    )?;
    f.set_query(&query)?;
    refused(&f)?;
    // The original JPEG's valid derivative may be retained before the raw-grid mismatch;
    // no corrected image identity or partial scene report is released by this failure.
    Ok(())
}

#[test]
fn current_raw_privacy_mask_propagates_into_the_corrected_grid_and_empty_scene_report() -> TestResult
{
    let mut f = crop_fixture("lens-current-mask", [true, true])?;
    let cx = context(&f.options.root)?;
    let mut deployment = ReferenceDeployment::reopen(&f.options.root, &f.options.site, &cx)?;
    let policy = PrivacyMaskPolicy::new(
        f.capsules[0].sensor_id.clone(),
        [WIDTH, HEIGHT],
        &[[0, 0, WIDTH, HEIGHT]],
    )?;
    let approval = preview_mask(&deployment, &policy)?.approval;
    declare_mask(&mut deployment, &policy, approval, &cx)?;
    f.options.expected_anchor = Some(anchor_digest(deployment.current_anchor()));
    drop(deployment);
    cx.drain_and_finalize();
    let mut stdout = Vec::new();
    assert!(!checked(execute(&f.options, &mut stdout))?);
    let value = parse(std::str::from_utf8(&stdout)?)?;
    let analysis = field(&value, &["report", "analysis"])?;
    assert_eq!(
        field(analysis, &["outcome"])?.text(),
        Some("no_reconstruction")
    );
    let view = field(analysis, &["views", "0"])?;
    assert_eq!(field(view, &["selection", "selected"])?.integer(), Some(0));
    assert_eq!(
        field(view, &["source", "mask_policy", "digest"])?.text(),
        Some(policy.digest().to_text().as_str())
    );
    assert_eq!(
        field(view, &["source", "encoded_source_digest"])?.text(),
        Some(f.capsules[0].source_digest.to_text().as_str())
    );
    assert_eq!(
        field(view, &["image_processing", "coverage", "allowed_pixels"])?.integer(),
        Some(0)
    );
    assert_eq!(
        field(view, &["image_processing", "coverage", "privacy_rejected"])?.integer(),
        Some(128 * 96)
    );
    assert_eq!(
        field(view, &["image_processing", "source_exposure_preserved"])?.boolean(),
        Some(true)
    );
    assert!(
        !field(analysis, &["feature_outcomes"])?
            .array()
            .ok_or("feature outcomes")?
            .is_empty()
    );
    Ok(())
}

#[test]
fn explicit_lens_work_cancellation_and_output_limits_release_no_partial_result() -> TestResult {
    let f = crop_fixture("lens-cancel", [true, true])?;
    let cx = context(&f.options.root)?;
    cx.request_cancellation();
    assert!(analyze(&f.options, &f.options.root, &cx).is_err());
    cx.drain_and_finalize();
    assert_eq!(f.head()?, f.head);
    for mode in 0..3 {
        let mut f = crop_fixture(&format!("lens-limits-{mode}"), [true, true])?;
        match mode {
            0 => f.options.timeout = Duration::ZERO,
            1 => f.options.work = 1,
            _ => f.options.report_bytes = 1024,
        }
        refused(&f)?;
        if mode < 2 {
            assert_eq!(f.head()?, f.head);
        }
    }
    Ok(())
}
