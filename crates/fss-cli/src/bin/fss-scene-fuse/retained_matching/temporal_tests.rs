#![forbid(unsafe_code)]
//! Real retained imports through the temporal command, including exact repeated-camera owners.
//!
//! Later synthetic JPEGs add only a valid COM marker to the original left/right pair. Their
//! unchanged pixels describe the same authored z=10 plane one second later: the independent
//! motion oracle is zero velocity. These are authored fixtures, not physical recordings or
//! evidence that two observations from one camera have independent calibration errors.

use super::super::tests::{Fixture, checked, context, field, h, json, put};
use super::*;
use crate::matching::fixtures::{HEIGHT, LEFT, RIGHT, WIDTH};
use fss_cli::json_input::{Value, parse, parse_reconstruction_atlas_report as parse_report};
use fss_core::{CanonicalEncode, TimestampNs};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_decode::retained_source_capsule;
use fss_reference::ingest::{
    CaptureHint, FileIngestAdapter, FileIngestRequest, RetainedFileImport, RetainedReadLimits,
};
use std::path::PathBuf;
use std::time::Duration;

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const LATE_TIME: i128 = 1_000_001_050;
const REFERENCE_TIME: &str = "500001050";

fn later_jpeg(original: &[u8], camera: usize) -> Test<Vec<u8>> {
    assert_eq!(&original[..2], &[0xff, 0xd8]);
    let comment = format!("original synthetic stationary camera {camera}, later exposure");
    let length = u16::try_from(comment.len() + 2)?;
    let mut bytes = Vec::with_capacity(original.len() + comment.len() + 4);
    bytes.extend_from_slice(&original[..2]);
    bytes.extend_from_slice(&[0xff, 0xfe]);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(comment.as_bytes());
    bytes.extend_from_slice(&original[2..]);
    assert_ne!(h(&bytes), h(original));
    Ok(bytes)
}

pub(in crate::retained_matching) fn fixture(label: &str, raw_left: bool) -> Test<Fixture> {
    let mut f = Fixture::new(label)?;
    let cx = context(&f.options.root)?;
    let mut deployment = ReferenceDeployment::reopen(&f.options.root, &f.options.site, &cx)?;
    for (index, original) in [LEFT, RIGHT].into_iter().enumerate() {
        let bytes = later_jpeg(original, index + 1)?;
        let path = f
            .directory()
            .join(format!("later-source-{}.mjpeg", index + 1));
        fs::write(&path, &bytes)?;
        let imported = FileIngestAdapter::ingest(
            FileIngestRequest::new(
                &path,
                f.capsules[index].sensor_id.clone(),
                f.capsules[index].stream_id.clone(),
            )
            .with_receive_time(TimestampNs(LATE_TIME + 450))
            .with_capture_hint(CaptureHint::new(TimestampNs(LATE_TIME), 50, 30.0)?),
            &cx,
            &mut deployment,
        )?;
        fs::remove_file(path)?;
        let retained = RetainedFileImport::open(
            &deployment,
            imported.import_identity,
            RetainedReadLimits::default(),
            &cx,
        )?;
        assert_eq!(retained.manifest().segment_spans.len(), 1);
        let capsule = retained_source_capsule(&deployment, &retained, 0)?;
        assert_eq!(capsule.source_digest, h(&bytes));
        assert_eq!(
            [capsule.capture.earliest.0, capsule.capture.latest.0],
            [LATE_TIME - 50, LATE_TIME + 50]
        );
        f.imports.push(imported.import_identity);
        f.capsules.push(capsule);
    }
    f.head = deployment.current_anchor().clone();
    drop(deployment);
    cx.drain_and_finalize();

    let mut rig = parse(std::str::from_utf8(&fs::read(&f.options.rig)?)?)?;
    let mut modes = Vec::new();
    for (index, side) in ["left", "right"].into_iter().enumerate() {
        let row = index.to_string();
        put(
            &mut rig,
            &["cameras", &row, "validity_ns"],
            parse("[0,2000000000]")?,
        )?;
        let domain = field(&f.document, &[side, "image_domain_digest"])?;
        let image = if raw_left && index == 0 {
            for (key, value) in [("width", 128), ("height", 96), ("cx", 64), ("cy", 48)] {
                put(
                    &mut rig,
                    &["cameras", &row, "intrinsics", key],
                    Value::Number(value.to_string()),
                )?;
            }
            parse(&object(&[
                ("kind", string("rectified")),
                ("source_domain_digest", json(domain)),
                (
                    "lens_basis",
                    string(&h("fixed temporal left integer crop").to_text()),
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
                ("image_domain_digest", json(domain)),
            ]))?
        };
        let mut view = field(&f.document, &[side])?.clone();
        let Value::Object(fields) = &mut view else {
            return Err("view object".into());
        };
        fields.remove("image_domain_digest");
        fields.insert("image".into(), image);
        modes.push(view);
    }
    let mut views = modes.clone();
    for (index, original) in modes.iter().enumerate() {
        let source = index + 2;
        let mut view = original.clone();
        for (name, value) in [
            ("import_identity", f.imports[source]),
            (
                "capsule_digest",
                h(f.capsules[source].try_canonical_bytes()?),
            ),
            ("encoded_source_digest", f.capsules[source].source_digest),
        ] {
            put(&mut view, &["source", name], Value::Text(value.to_text()))?;
        }
        put(
            &mut view,
            &["alignment", "import_identity"],
            Value::Text(f.imports[source].to_text()),
        )?;
        views.push(view);
    }
    let rig_text = json(&rig);
    fs::write(&f.options.rig, &rig_text)?;
    let mut query = f.document.clone();
    let Value::Object(top) = &mut query else {
        return Err("query object".into());
    };
    top.remove("left");
    top.remove("right");
    top.insert("schema".into(), Value::Text(input::SCHEMA.into()));
    top.insert(
        "camera_rig_digest".into(),
        Value::Text(h(rig_text).to_text()),
    );
    top.insert("views".into(), Value::Array(views));
    top.insert(
        "motion".into(),
        Value::Text("constant_velocity_during_capture_hull".into()),
    );
    top.insert(
        "reference_time_ns".into(),
        Value::Text(REFERENCE_TIME.into()),
    );
    top.insert(
        "max_capture_span_ns".into(),
        Value::Number("2000000000".into()),
    );
    top.insert(
        "max_capture_uncertainty_ns".into(),
        Value::Number("120".into()),
    );
    top.insert(
        "matching".into(),
        parse(r#"{"maximum_hamming_distance":0,"ratio_percent":80}"#)?,
    );
    top.insert("triangulation".into(), parse(r#"{"max_reprojection_pixels":0.01,"max_distance":1000,"max_speed":10,"max_condition_number":10000000000,"max_iterations":16}"#)?);
    f.set_query(&query)?;
    f.document = query;
    f.options.expected_anchor = Some(anchor_digest(&f.head));
    f.options.work = DEFAULT_WORK;
    f.options.report_bytes = MAX_REPORT_BYTES;
    Ok(f)
}

fn refused(f: &Fixture) -> Test {
    let mut stdout = Vec::new();
    assert!(execute(&f.options, &mut stdout).is_err());
    assert!(stdout.is_empty());
    if let Some(path) = &f.options.report_out {
        assert!(!path.exists());
    }
    Ok(())
}
fn number(value: &Value) -> Test<f64> {
    let Value::Number(text) = value else {
        return Err("numeric report value".into());
    };
    Ok(text.parse()?)
}
fn geometry(value: &Value) -> Test<&Value> {
    field(value, &["report", "analysis", "geometry"])
}
fn check_stationary(value: &Value) -> Test<usize> {
    let geometry = geometry(value)?;
    assert_eq!(field(geometry, &["counts", "cameras"])?.integer(), Some(2));
    assert_eq!(
        field(geometry, &["counts", "exposures"])?.integer(),
        Some(4)
    );
    assert_eq!(
        field(geometry, &["counts", "exposure_pairs"])?.integer(),
        Some(6)
    );
    assert_eq!(
        field(geometry, &["capture_hull_ns", "0"])?.text(),
        Some("990")
    );
    assert_eq!(
        field(geometry, &["capture_hull_ns", "1"])?.text(),
        Some("1000001110")
    );
    assert_eq!(
        field(geometry, &["requested_scene_time_ns"])?.text(),
        Some(REFERENCE_TIME)
    );
    assert_eq!(
        field(geometry, &["pair_geometry"])?.text(),
        Some("not_applied_to_staggered_moving_observations")
    );
    let mut solved = 0;
    for component in field(geometry, &["components"])?
        .array()
        .ok_or("components")?
    {
        let outcome = field(component, &["outcome"])?;
        if field(outcome, &["state"])?.text() != Some("estimated") {
            continue;
        }
        solved += 1;
        assert_eq!(
            field(component, &["members"])?
                .array()
                .ok_or("members")?
                .len(),
            4
        );
        assert_eq!(
            field(outcome, &["kind"])?.text(),
            Some("constant_velocity_trajectory")
        );
        assert_eq!(
            field(outcome, &["reference_time_ns"])?.text(),
            Some(REFERENCE_TIME)
        );
        assert!((number(field(outcome, &["position", "2"])?)? - 10.0).abs() < 1e-7);
        for speed in field(outcome, &["velocity_per_second"])?
            .array()
            .ok_or("velocity")?
        {
            assert!(number(speed)?.abs() < 1e-7);
        }
        let covariance = field(outcome, &["pixel_noise_covariance"])?
            .array()
            .ok_or("covariance")?;
        assert_eq!(covariance.len(), 6);
        for row in covariance {
            assert_eq!(row.array().ok_or("covariance row")?.len(), 6);
        }
        let residuals = field(outcome, &["views"])?.array().ok_or("residuals")?;
        assert_eq!(residuals.len(), 4);
        let exposure_ids = residuals
            .iter()
            .map(|row| field(row, &["exposure"]).map(|v| v.text().map(str::to_owned)))
            .collect::<Test<std::collections::BTreeSet<_>>>()?;
        assert_eq!(
            exposure_ids.len(),
            4,
            "repeated cameras must retain distinct motion observations"
        );
    }
    Ok(solved)
}

#[test]
fn retained_repeated_camera_frames_keep_all_source_owners_and_zero_velocity_geometry() -> Test {
    let mut f = fixture("temporal-complete", false)?;
    let mut stdout = Vec::new();
    let success = checked(execute(&f.options, &mut stdout))?;
    // Same-camera-only features remain two-observation components; successful motion fits
    // do not erase those unresolved alternatives, so the complete command returns exit3.
    assert!(!success);
    let output = f.options.report_out.as_ref().ok_or("output")?;
    assert_eq!(fs::read(output)?, stdout);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(output)?.permissions().mode() & 0o777, 0o600);
    }
    let text = std::str::from_utf8(&stdout)?;
    let value = parse_report(text)?;
    assert_eq!(
        field(&value, &["schema"])?.text(),
        Some("fss.scene_feature_motion_match_retained.v1")
    );
    assert!(check_stationary(&value)? >= 8);
    let analysis = field(&value, &["report", "analysis"])?;
    assert_eq!(
        field(analysis, &["physical_identity_established"])?.boolean(),
        Some(false)
    );
    assert_eq!(
        field(geometry(&value)?, &["outcome"])?.text(),
        Some("reconstructed_with_refusals")
    );
    let rows = field(analysis, &["views"])?.array().ok_or("source views")?;
    assert_eq!(rows.len(), 4);
    let mut exposures = std::collections::BTreeSet::new();
    for (row, source) in rows.iter().zip([0, 2, 1, 3]) {
        let view = field(row, &["view"])?;
        let original = &f.capsules[source];
        assert_eq!(
            field(view, &["source", "import_identity"])?.text(),
            Some(f.imports[source].to_text().as_str())
        );
        assert_eq!(
            field(view, &["source", "capsule_digest"])?.text(),
            Some(h(original.try_canonical_bytes()?).to_text().as_str())
        );
        assert_eq!(
            field(view, &["source", "encoded_source_digest"])?.text(),
            Some(original.source_digest.to_text().as_str())
        );
        assert_eq!(
            field(view, &["source", "capsule", "sensor_id"])?.text(),
            Some(original.sensor_id.as_str())
        );
        assert_eq!(
            field(view, &["source", "capsule", "capture_ns", "0"])?.text(),
            Some(original.capture.earliest.0.to_string().as_str())
        );
        assert_eq!(
            field(view, &["source", "capsule", "capture_ns", "1"])?.text(),
            Some(original.capture.latest.0.to_string().as_str())
        );
        exposures.insert(
            field(view, &["source", "exposure_digest"])?
                .text()
                .ok_or("exposure digest")?
                .to_owned(),
        );
    }
    assert_eq!(exposures.len(), 4);
    assert_eq!(
        field(
            &value,
            &[
                "report",
                "cost",
                "source_bytes",
                "includes_final_revalidation"
            ]
        )?
        .boolean(),
        Some(true)
    );
    let body = text
        .trim_end()
        .strip_suffix('}')
        .ok_or("wrapper")?
        .split_once(",\"report\":")
        .ok_or("body")?
        .1;
    assert_eq!(
        field(&value, &["report_digest"])?.text(),
        Some(h(body).to_text().as_str())
    );

    let completed = f.head()?;
    assert_ne!(completed, f.head);
    let mut reversed = f.document.clone();
    let Value::Object(top) = &mut reversed else {
        return Err("query".into());
    };
    let Value::Array(views) = top.get_mut("views").ok_or("views")? else {
        return Err("views array".into());
    };
    views.reverse();
    f.set_query(&reversed)?;
    f.options.report_out = None;
    f.options.expected_anchor = Some(anchor_digest(&completed));
    let mut replay = Vec::new();
    assert!(!checked(execute(&f.options, &mut replay))?);
    let replay = parse_report(std::str::from_utf8(&replay)?)?;
    assert_eq!(geometry(&value)?, geometry(&replay)?);
    assert_eq!(
        field(analysis, &["views"])?,
        field(&replay, &["report", "analysis", "views"])?
    );
    assert_eq!(
        f.head()?,
        completed,
        "replay cannot republish existing native derivatives"
    );
    Ok(())
}

#[test]
fn fixed_raw_lens_mode_keeps_each_repeated_exposure_and_the_known_stationary_plane() -> Test {
    let f = fixture("temporal-rectified", true)?;
    let mut stdout = Vec::new();
    checked(execute(&f.options, &mut stdout))?;
    let value = parse_report(std::str::from_utf8(&stdout)?)?;
    assert!(check_stationary(&value)? >= 3);
    let rows = field(&value, &["report", "analysis", "views"])?
        .array()
        .ok_or("views")?;
    let mut domains = Vec::new();
    let mut exposures = Vec::new();
    for row in &rows[..2] {
        let view = field(row, &["view"])?;
        let processing = field(view, &["image_processing"])?;
        assert_eq!(
            field(processing, &["kind"])?.text(),
            Some("native_rectified")
        );
        assert_eq!(
            field(view, &["source", "dimensions", "0"])?.integer(),
            Some(192)
        );
        assert_eq!(
            field(view, &["source", "dimensions", "1"])?.integer(),
            Some(128)
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
            field(processing, &["output", "exposure_digest"])?,
            field(view, &["source", "exposure_digest"])?
        );
        assert_eq!(
            field(processing, &["source", "storage_digest"])?,
            field(view, &["source", "pixel_digest"])?
        );
        assert_eq!(
            field(processing, &["output", "image_domain_digest"])?,
            field(view, &["image_domain_digest"])?
        );
        domains.push(field(view, &["image_domain_digest"])?.clone());
        exposures.push(field(view, &["source", "exposure_digest"])?.clone());
    }
    assert_eq!(domains[0], domains[1]);
    assert_ne!(exposures[0], exposures[1]);
    for row in &rows[2..] {
        assert_eq!(
            field(row, &["view", "image_processing", "kind"])?.text(),
            Some("native_pinhole")
        );
    }
    Ok(())
}

#[test]
fn duplicate_exposure_and_later_source_pin_mismatch_refuse_before_any_publication() -> Test {
    let mut f = fixture("temporal-preflight", false)?;
    let mut duplicate = f.document.clone();
    put(
        &mut duplicate,
        &["views", "3"],
        field(&f.document, &["views", "1"])?.clone(),
    )?;
    f.set_query(&duplicate)?;
    refused(&f)?;
    assert_eq!(f.head()?, f.head);
    for (path, value) in [
        (
            vec!["views", "3", "source", "encoded_source_digest"],
            Value::Text(h("wrong late source").to_text()),
        ),
        (
            vec!["views", "3", "source", "sensor_id"],
            Value::Text("sensor:wrong-late-camera".into()),
        ),
        (
            vec!["views", "3", "alignment", "stream_id"],
            Value::Text("stream:wrong-late-stream".into()),
        ),
    ] {
        let mut query = f.document.clone();
        put(&mut query, &path, value)?;
        f.set_query(&query)?;
        refused(&f)?;
        assert_eq!(f.head()?, f.head);
    }
    Ok(())
}

#[test]
fn new_current_privacy_masks_all_exposures_of_the_sensor_after_a_previous_analysis() -> Test {
    let mut f = fixture("temporal-current-privacy", false)?;
    let cx = context(&f.options.root)?;
    let before = checked(analyze(&f.options, &f.options.root, &cx))?;
    assert!(check_stationary(&parse_report(&before.json)?)? >= 8);
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
    let value = parse_report(std::str::from_utf8(&stdout)?)?;
    assert_eq!(
        field(geometry(&value)?, &["counts", "solved"])?.integer(),
        Some(0)
    );
    assert_eq!(
        field(geometry(&value)?, &["counts", "exposures"])?.integer(),
        Some(4)
    );
    for (index, row) in field(&value, &["report", "analysis", "views"])?
        .array()
        .ok_or("views")?
        .iter()
        .enumerate()
    {
        let view = field(row, &["view"])?;
        if index < 2 {
            assert_eq!(field(view, &["selection", "selected"])?.integer(), Some(0));
            assert_eq!(
                field(view, &["source", "mask_policy", "digest"])?.text(),
                Some(policy.digest().to_text().as_str())
            );
        } else {
            assert!(
                field(view, &["selection", "selected"])?
                    .integer()
                    .ok_or("selected count")?
                    > 0
            );
        }
    }
    Ok(())
}

fn later_custody(f: &Fixture) -> Test<Vec<PathBuf>> {
    let cx = context(&f.options.root)?;
    let deployment = ReferenceDeployment::reopen(&f.options.root, &f.options.site, &cx)?;
    let retained = RetainedFileImport::open(
        &deployment,
        f.imports[2],
        RetainedReadLimits::default(),
        &cx,
    )?;
    let result = vec![
        deployment
            .publisher()
            .spool()
            .object_path(retained.manifest().ordered_chunks[0]),
        deployment
            .publisher()
            .spool()
            .object_path(h(f.capsules[2].try_canonical_bytes()?)),
    ];
    drop(deployment);
    cx.drain_and_finalize();
    Ok(result)
}

#[test]
fn later_original_custody_cannot_be_replaced_by_the_earlier_same_camera_derivative() -> Test {
    let mut f = fixture("temporal-later-custody", false)?;
    let cx = context(&f.options.root)?;
    checked(analyze(&f.options, &f.options.root, &cx))?;
    cx.drain_and_finalize();
    f.options.expected_anchor = Some(anchor_digest(&f.head()?));
    for path in later_custody(&f)? {
        let original = fs::read(&path)?;
        let mut corrupt = original.clone();
        *corrupt.last_mut().ok_or("custody bytes")? ^= 1;
        fs::write(&path, &corrupt)?;
        refused(&f)?;
        assert_eq!(fs::read(&path)?, corrupt);
        fs::remove_file(&path)?;
        refused(&f)?;
        assert!(!path.exists());
        fs::write(&path, original)?;
    }
    Ok(())
}

#[test]
fn complete_work_is_exact_and_one_less_unit_cannot_publish_a_prefix() -> Test {
    let mut f = fixture("temporal-exact-work", false)?;
    f.options.report_out = None;
    let cx = context(&f.options.root)?;
    checked(analyze(&f.options, &f.options.root, &cx))?;
    cx.drain_and_finalize();
    let head = f.head()?;
    f.options.expected_anchor = Some(anchor_digest(&head));
    let cx = context(&f.options.root)?;
    let baseline = checked(analyze(&f.options, &f.options.root, &cx))?;
    cx.drain_and_finalize();
    let baseline = parse_report(&baseline.json)?;
    let used = field(&baseline, &["report", "cost", "geometry_work", "used"])?
        .text()
        .ok_or("work used")?
        .parse::<u64>()?;
    assert!(used > 1);
    f.options.work = used;
    let mut stdout = Vec::new();
    checked(execute(&f.options, &mut stdout))?;
    assert!(!stdout.is_empty());
    f.options.work = used - 1;
    refused(&f)?;
    assert_eq!(f.head()?, head);
    Ok(())
}

#[test]
fn cancellation_deadline_and_complete_report_cap_leave_no_partial_output() -> Test {
    let f = fixture("temporal-cancel", false)?;
    let cx = context(&f.options.root)?;
    cx.request_cancellation();
    assert!(analyze(&f.options, &f.options.root, &cx).is_err());
    cx.drain_and_finalize();
    assert_eq!(f.head()?, f.head);
    for case in 0..3 {
        let mut f = fixture(&format!("temporal-limits-{case}"), false)?;
        match case {
            0 => f.options.timeout = Duration::ZERO,
            1 => f.options.work = 1,
            _ => f.options.report_bytes = 1024,
        }
        refused(&f)?;
        if case < 2 {
            assert_eq!(f.head()?, f.head);
        }
        // Completed native JPEG derivatives may survive a late report-size refusal.
    }
    Ok(())
}

#[test]
fn exact_motion_flags_and_create_only_outputs_are_checked_before_source_work() -> Test {
    let f = fixture("temporal-exclusive", false)?;
    let arguments = vec![
        "--root".into(),
        f.options.root.as_os_str().to_owned(),
        "--site".into(),
        f.options.site.clone().into(),
        "--twin".into(),
        f.options.twin.as_os_str().to_owned(),
        "--rig".into(),
        f.options.rig.as_os_str().to_owned(),
        "--query".into(),
        f.options.query.as_os_str().to_owned(),
    ];
    let parsed = checked(options(&arguments))?.ok_or("options")?;
    assert_eq!(parsed.work, DEFAULT_WORK);
    assert_eq!(parsed.report_bytes, MAX_REPORT_BYTES);
    for extra in [
        vec!["--work-units", "16000000001"],
        vec!["--max-report-bytes", "33554433"],
        vec!["--work-units", "1", "--work-units", "2"],
        vec!["--camera", "1"],
    ] {
        let mut invalid = arguments.clone();
        invalid.extend(extra.into_iter().map(OsString::from));
        assert!(options(&invalid).is_err());
    }
    let path = f.options.report_out.as_ref().ok_or("output")?;
    let sentinel = b"existing temporal report";
    fs::write(path, sentinel)?;
    let mut stdout = Vec::new();
    assert!(execute(&f.options, &mut stdout).is_err());
    assert!(stdout.is_empty());
    assert_eq!(fs::read(path)?, sentinel);
    assert_eq!(f.head()?, f.head);
    #[cfg(unix)]
    {
        fs::remove_file(path)?;
        let target = f.directory().join("untouched-temporal-target");
        fs::write(&target, sentinel)?;
        std::os::unix::fs::symlink(&target, path)?;
        assert!(execute(&f.options, &mut stdout).is_err());
        assert!(stdout.is_empty());
        assert_eq!(fs::read(target)?, sentinel);
        assert!(fs::symlink_metadata(path)?.file_type().is_symlink());
        assert_eq!(f.head()?, f.head);
    }
    Ok(())
}
