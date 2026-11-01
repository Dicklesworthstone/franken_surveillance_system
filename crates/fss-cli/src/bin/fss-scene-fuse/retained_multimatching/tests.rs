#![forbid(unsafe_code)]
//! Real retained imports and sealed native owners through the multi-camera command.
//!
//! The third original JPEG is constructed in memory from the original RIGHT fixture by adding
//! a COM marker. Its pixels are unchanged; it represents another explicitly authored synthetic
//! camera, not an independent physical recording. On the z=10 plane, camera 2 at x=1,cx=96 and
//! camera 3 at x=2,cx=112 both project u=16X+80 (fx=160). This gives different camera rays and
//! distinct original source/capsule identities with a directly checkable three-view oracle.

use super::super::tests::{Fixture, checked, context, field, h, json, put};
use super::*;
use crate::matching::fixtures::{HEIGHT, RIGHT, WIDTH};
use fss_cli::json_input::{Value, parse};
use fss_core::{CanonicalEncode, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_decode::retained_source_capsule;
use fss_reference::ingest::{
    CaptureHint, FileIngestAdapter, FileIngestRequest, RetainedFileImport, RetainedReadLimits,
};
use std::path::PathBuf;
use std::time::Duration;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn third_jpeg() -> TestResult<Vec<u8>> {
    const COMMENT: &[u8] = b"original synthetic third camera: x=2,cx=112,z=10";
    assert_eq!(&RIGHT[..2], &[0xff, 0xd8]);
    let length = u16::try_from(COMMENT.len() + 2)?;
    let mut bytes = Vec::with_capacity(RIGHT.len() + COMMENT.len() + 4);
    bytes.extend_from_slice(&RIGHT[..2]);
    bytes.extend_from_slice(&[0xff, 0xfe]);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(COMMENT);
    bytes.extend_from_slice(&RIGHT[2..]);
    assert_ne!(h(&bytes), h(RIGHT));
    Ok(bytes)
}

fn fixture(label: &str, late_third: bool) -> TestResult<Fixture> {
    let mut f = Fixture::new(label)?;
    let bytes = third_jpeg()?;
    let path = f.directory().join("source-3.mjpeg");
    fs::write(&path, &bytes)?;
    let cx = context(&f.options.root)?;
    let mut deployment = ReferenceDeployment::reopen(&f.options.root, &f.options.site, &cx)?;
    let (capture, uncertainty) = if late_third { (1305, 5) } else { (1050, 50) };
    let imported = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            &path,
            SensorId::parse("sensor:retained-match-3")?,
            StreamId::parse("stream:retained-match-3:g1")?,
        )
        .with_receive_time(TimestampNs(1500))
        .with_capture_hint(CaptureHint::new(TimestampNs(capture), uncertainty, 30.0)?),
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
    f.imports.push(imported.import_identity);
    f.capsules.push(capsule);
    f.head = deployment.current_anchor().clone();
    drop(deployment);
    cx.drain_and_finalize();

    let mut rig = parse(std::str::from_utf8(&fs::read(&f.options.rig)?)?)?;
    let mut third_camera = field(&rig, &["cameras", "1"])?.clone();
    put(&mut third_camera, &["camera"], Value::Number("3".into()))?;
    put(
        &mut third_camera,
        &["image_domain"],
        Value::Number("3".into()),
    )?;
    put(
        &mut third_camera,
        &["source_object_id"],
        Value::Text("synthetic_camera_3".into()),
    )?;
    put(
        &mut third_camera,
        &["world_to_camera", "translation", "0"],
        Value::Number("-2".into()),
    )?;
    put(
        &mut third_camera,
        &["intrinsics", "cx"],
        Value::Number("112".into()),
    )?;
    let mut cameras = field(&rig, &["cameras"])?
        .array()
        .ok_or("camera rows")?
        .to_vec();
    cameras.push(third_camera);
    put(&mut rig, &["cameras"], Value::Array(cameras))?;
    let rig_text = json(&rig);
    fs::write(&f.options.rig, &rig_text)?;

    let mut document = f.document.clone();
    let first = field(&document, &["left"])?.clone();
    let second = field(&document, &["right"])?.clone();
    let mut third = second.clone();
    let capsule = &f.capsules[2];
    put(&mut third, &["camera"], Value::Number("3".into()))?;
    for (path, value) in [
        (
            vec!["image_domain_digest"],
            h("retained undistorted fixture mode 3"),
        ),
        (
            vec!["mapping_basis"],
            h("retained fixture camera mapping 3"),
        ),
        (vec!["source", "import_identity"], f.imports[2]),
        (
            vec!["source", "capsule_digest"],
            h(capsule.try_canonical_bytes()?),
        ),
        (
            vec!["source", "encoded_source_digest"],
            capsule.source_digest,
        ),
        (vec!["alignment", "import_identity"], f.imports[2]),
        (
            vec!["alignment", "basis"],
            h("declared additive clock mapping 3"),
        ),
    ] {
        put(&mut third, &path, Value::Text(value.to_text()))?;
    }
    put(
        &mut third,
        &["source", "sensor_id"],
        Value::Text(capsule.sensor_id.as_str().into()),
    )?;
    put(
        &mut third,
        &["alignment", "stream_id"],
        Value::Text(capsule.stream_id.as_str().into()),
    )?;
    let Value::Object(fields) = &mut document else {
        return Err("query object".into());
    };
    fields.remove("left");
    fields.remove("right");
    fields.insert("schema".into(), Value::Text(input::SCHEMA.into()));
    fields.insert(
        "camera_rig_digest".into(),
        Value::Text(h(&rig_text).to_text()),
    );
    fields.insert("views".into(), Value::Array(vec![first, second, third]));
    if late_third {
        fields.insert("reference_time_ns".into(), Value::Number("1305".into()));
        fields.insert("max_capture_span_ns".into(), Value::Number("400".into()));
    }
    f.set_query(&document)?;
    f.document = document;
    f.options.expected_anchor = Some(anchor_digest(&f.head));
    f.options.work = DEFAULT_WORK;
    f.options.report_bytes = MAX_REPORT_BYTES;
    Ok(f)
}

/// Reuse the actual three-camera imports and preview without exposing fixture internals.
/// The third view remains the explicitly authored synthetic camera described above.
pub(in super::super) fn atlas_fixture_preview(label: &str) -> TestResult<(Fixture, String)> {
    let f = fixture(label, false)?;
    let cx = context(&f.options.root)?;
    let preview = analyze(&f.options, &f.options.root, &cx);
    cx.drain_and_finalize();
    let preview = checked(preview)?;
    assert!(preview.reconstructed);
    assert!(
        !f.options
            .report_out
            .as_ref()
            .ok_or("preview output")?
            .exists()
    );
    Ok((f, preview.json))
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

fn mask(f: &mut Fixture, camera_index: usize) -> TestResult<ContentDigest> {
    let cx = context(&f.options.root)?;
    let mut deployment = ReferenceDeployment::reopen(&f.options.root, &f.options.site, &cx)?;
    let policy = PrivacyMaskPolicy::new(
        f.capsules[camera_index].sensor_id.clone(),
        [WIDTH, HEIGHT],
        &[[0, 0, WIDTH, HEIGHT]],
    )?;
    let approval = preview_mask(&deployment, &policy)?.approval;
    declare_mask(&mut deployment, &policy, approval, &cx)?;
    f.options.expected_anchor = Some(anchor_digest(deployment.current_anchor()));
    drop(deployment);
    cx.drain_and_finalize();
    Ok(policy.digest())
}

fn geometry(value: &Value) -> TestResult<&Value> {
    field(value, &["report", "analysis", "geometry"])
}

#[test]
fn three_retained_jpegs_close_native_components_and_preserve_all_source_bindings() -> TestResult {
    let mut f = fixture("multiview-complete", false)?;
    for id in 1..=3 {
        assert!(!f.directory().join(format!("source-{id}.mjpeg")).exists());
    }
    let mut stdout = Vec::new();
    assert!(checked(execute(&f.options, &mut stdout))?); // main maps true to exit 0.
    let output = f.options.report_out.as_ref().ok_or("report output")?;
    assert_eq!(fs::read(output)?, stdout);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(output)?.permissions().mode() & 0o777, 0o600);
    }
    let text = std::str::from_utf8(&stdout)?;
    let value = parse(text)?;
    assert_eq!(
        field(&value, &["schema"])?.text(),
        Some("fss.scene_feature_multimatch_retained.v1")
    );
    let analysis = field(&value, &["report", "analysis"])?;
    assert_eq!(
        field(analysis, &["physical_identity_established"])?.boolean(),
        Some(false)
    );
    assert_eq!(
        field(analysis, &["source_provenance"])?.text(),
        Some("verified_retained_native_frames")
    );
    let g = geometry(&value)?;
    assert_eq!(field(g, &["outcome"])?.text(), Some("reconstructed"));
    assert_eq!(field(g, &["counts", "cameras"])?.integer(), Some(3));
    assert_eq!(field(g, &["counts", "camera_pairs"])?.integer(), Some(3));
    let mut triples = 0;
    for component in field(g, &["components"])?.array().ok_or("components")? {
        if field(component, &["outcome", "state"])?.text() != Some("estimated") {
            continue;
        }
        let members = field(component, &["members"])?.array().ok_or("members")?;
        if members.len() == 3 {
            triples += 1;
            assert_eq!(
                field(component, &["links"])?.array().ok_or("links")?.len(),
                3
            );
        }
        let Value::Number(z) = field(component, &["outcome", "position", "2"])? else {
            return Err("joint point depth".into());
        };
        assert!((z.parse::<f64>()? - 10.0).abs() < 1e-8);
    }
    assert!(
        triples >= 8,
        "expected closed three-camera feature components"
    );
    let views = field(analysis, &["views"])?.array().ok_or("views")?;
    assert_eq!(views.len(), 3);
    for (index, view) in views.iter().enumerate() {
        let capsule = &f.capsules[index];
        assert_eq!(
            field(view, &["camera"])?.text(),
            Some((index + 1).to_string().as_str())
        );
        assert_eq!(
            field(view, &["source", "import_identity"])?.text(),
            Some(f.imports[index].to_text().as_str())
        );
        assert_eq!(
            field(view, &["source", "capsule_digest"])?.text(),
            Some(h(capsule.try_canonical_bytes()?).to_text().as_str())
        );
        assert_eq!(
            field(view, &["source", "encoded_source_digest"])?.text(),
            Some(capsule.source_digest.to_text().as_str())
        );
        assert_eq!(
            field(view, &["source", "capsule", "sensor_id"])?.text(),
            Some(capsule.sensor_id.as_str())
        );
        assert_eq!(
            field(view, &["source", "capsule", "stream_id"])?.text(),
            Some(capsule.stream_id.as_str())
        );
        assert_eq!(
            field(view, &["source", "decode_publication_root", "state"])?.text(),
            Some("available")
        );
    }
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
    let after = f.head()?;
    assert_ne!(after, f.head);

    // Sorting by native camera identity must preserve the correct sealed owner even when
    // declarations are permuted. Authority entry anchors change on initial JPEG publication;
    // native geometry and final retained custody remain identical on replay.
    let mut document = f.document.clone();
    let mut declarations = field(&document, &["views"])?
        .array()
        .ok_or("views")?
        .to_vec();
    declarations.rotate_right(1);
    put(&mut document, &["views"], Value::Array(declarations))?;
    f.set_query(&document)?;
    f.options.expected_anchor = Some(anchor_digest(&after));
    f.options.report_out = None;
    let mut repeated = Vec::new();
    assert!(checked(execute(&f.options, &mut repeated))?);
    let repeated = parse(std::str::from_utf8(&repeated)?)?;
    assert_eq!(geometry(&value)?, geometry(&repeated)?);
    assert_eq!(
        field(analysis, &["views"])?,
        field(&repeated, &["report", "analysis", "views"])?
    );
    assert_eq!(f.head()?, after);
    Ok(())
}

#[test]
fn every_later_source_pin_is_preflighted_before_the_first_jpeg_publication() -> TestResult {
    let mut f = fixture("multiview-preflight", false)?;
    for (path, value) in [
        (
            vec!["source", "capsule_digest"],
            h("wrong third capsule").to_text(),
        ),
        (
            vec!["source", "encoded_source_digest"],
            h("wrong third bytes").to_text(),
        ),
        (vec!["source", "sensor_id"], "sensor:wrong-third".into()),
        (
            vec!["alignment", "stream_id"],
            "stream:wrong-third:g2".into(),
        ),
        (vec!["alignment", "clock_basis"], "device_monotonic".into()),
    ] {
        let mut document = f.document.clone();
        let mut full = vec!["views", "2"];
        full.extend(path);
        put(&mut document, &full, Value::Text(value))?;
        f.set_query(&document)?;
        refused(&f)?;
        assert_eq!(
            f.head()?,
            f.head,
            "late source pin changed authority: {full:?}"
        );
    }
    Ok(())
}

#[test]
fn missing_or_corrupt_third_original_objects_never_release_or_repair_a_scene() -> TestResult {
    for object in 0..2 {
        let mut f = fixture(&format!("multiview-custody-{object}"), false)?;
        let cx = context(&f.options.root)?;
        let deployment = ReferenceDeployment::reopen(&f.options.root, &f.options.site, &cx)?;
        let retained = RetainedFileImport::open(
            &deployment,
            f.imports[2],
            RetainedReadLimits::default(),
            &cx,
        )?;
        let digest = if object == 0 {
            retained.manifest().ordered_chunks[0]
        } else {
            h(f.capsules[2].try_canonical_bytes()?)
        };
        let path = deployment.publisher().spool().object_path(digest);
        drop(deployment);
        cx.drain_and_finalize();
        let original = fs::read(&path)?;
        let mut corrupt = original.clone();
        *corrupt.last_mut().ok_or("empty custody object")? ^= 1;
        fs::write(&path, &corrupt)?;
        refused(&f)?;
        assert_eq!(fs::read(&path)?, corrupt);
        // Earlier valid JPEG derivatives may have advanced the anchor. The second attempt
        // must independently reach missing-source validation rather than stale-anchor refusal.
        f.options.expected_anchor = None;
        fs::remove_file(&path)?;
        refused(&f)?;
        assert!(!path.exists());
        fs::write(&path, original)?;
        // A third-source encoded-byte failure may follow valid derivatives for earlier views;
        // canonical capsule mismatch is rejected in the all-source preflight instead.
        if object == 1 {
            assert_eq!(f.head()?, f.head);
        }
    }
    Ok(())
}

#[test]
fn current_masks_keep_empty_cameras_visible_and_allow_only_remaining_supported_points() -> TestResult
{
    let mut f = fixture("multiview-current-mask", false)?;
    let policy = mask(&mut f, 2)?;
    let mut stdout = Vec::new();
    assert!(checked(execute(&f.options, &mut stdout))?);
    let value = parse(std::str::from_utf8(&stdout)?)?;
    assert_eq!(
        field(
            &value,
            &["report", "analysis", "views", "2", "selection", "selected"]
        )?
        .integer(),
        Some(0)
    );
    assert_eq!(
        field(
            &value,
            &[
                "report",
                "analysis",
                "views",
                "2",
                "source",
                "mask_policy",
                "digest"
            ]
        )?
        .text(),
        Some(policy.to_text().as_str())
    );
    let g = geometry(&value)?;
    assert_eq!(field(g, &["counts", "cameras"])?.integer(), Some(3));
    assert_eq!(field(g, &["counts", "camera_pairs"])?.integer(), Some(3));
    assert!(
        field(g, &["counts", "solved"])?
            .integer()
            .is_some_and(|n| n >= 8)
    );
    for component in field(g, &["components"])?.array().ok_or("components")? {
        assert!(
            field(component, &["members"])?
                .array()
                .ok_or("members")?
                .len()
                <= 2
        );
    }
    mask(&mut f, 0)?;
    f.options.report_out = None;
    let mut remaining = Vec::new();
    assert!(!checked(execute(&f.options, &mut remaining))?); // main maps false to exit 3.
    let remaining = parse(std::str::from_utf8(&remaining)?)?;
    let g = geometry(&remaining)?;
    assert_eq!(field(g, &["outcome"])?.text(), Some("no_reconstruction"));
    assert_eq!(field(g, &["counts", "solved"])?.integer(), Some(0));
    assert!(
        field(g, &["counts", "unmatched"])?
            .integer()
            .is_some_and(|n| n > 0)
    );
    assert_eq!(
        field(g, &["camera_pairs"])?
            .array()
            .ok_or("pair rows")?
            .len(),
        3
    );
    Ok(())
}

#[test]
fn an_empty_later_retained_camera_extends_only_the_global_static_capture_hull() -> TestResult {
    let mut f = fixture("multiview-subset-time", true)?;
    mask(&mut f, 2)?;
    let mut stdout = Vec::new();
    assert!(checked(execute(&f.options, &mut stdout))?);
    let value = parse(std::str::from_utf8(&stdout)?)?;
    let g = geometry(&value)?;
    assert_eq!(field(g, &["requested_scene_time_ns"])?.text(), Some("1305"));
    assert_eq!(field(g, &["capture_hull_ns", "0"])?.text(), Some("990"));
    assert_eq!(field(g, &["capture_hull_ns", "1"])?.text(), Some("1320"));
    let pair = field(g, &["camera_pairs", "0"])?;
    assert_eq!(field(pair, &["cameras", "0"])?.text(), Some("1"));
    assert_eq!(field(pair, &["cameras", "1"])?.text(), Some("2"));
    assert_eq!(
        field(pair, &["requested_scene_time_ns"])?.text(),
        Some("1305")
    );
    assert_eq!(field(pair, &["solve_time_ns"])?.text(), Some("1110"));
    for component in field(g, &["components"])?.array().ok_or("components")? {
        assert_eq!(
            field(component, &["requested_scene_time_ns"])?.text(),
            Some("1305")
        );
        assert_eq!(field(component, &["solve_time_ns"])?.text(), Some("1110"));
    }
    Ok(())
}

#[test]
fn cancellation_deadline_geometry_and_complete_report_limits_emit_no_partial_inventory()
-> TestResult {
    let f = fixture("multiview-cancel", false)?;
    let cx = context(&f.options.root)?;
    cx.request_cancellation();
    assert!(analyze(&f.options, &f.options.root, &cx).is_err());
    cx.drain_and_finalize();
    assert_eq!(f.head()?, f.head);
    for kind in 0..3 {
        let mut f = fixture(&format!("multiview-limits-{kind}"), false)?;
        match kind {
            0 => f.options.timeout = Duration::ZERO,
            1 => f.options.work = 1,
            _ => f.options.report_bytes = 1024,
        }
        refused(&f)?;
        if kind < 2 {
            assert_eq!(f.head()?, f.head);
        }
    }
    Ok(())
}

#[test]
fn exclusive_report_files_and_symlinks_are_refused_before_multi_camera_work() -> TestResult {
    let f = fixture("multiview-exclusive", false)?;
    let output = f.options.report_out.as_ref().ok_or("report output")?;
    let sentinel = b"existing complete report";
    fs::write(output, sentinel)?;
    let mut stdout = Vec::new();
    assert!(execute(&f.options, &mut stdout).is_err());
    assert!(stdout.is_empty());
    assert_eq!(fs::read(output)?, sentinel);
    assert_eq!(f.head()?, f.head);
    #[cfg(unix)]
    {
        fs::remove_file(output)?;
        let destination: PathBuf = f.directory().join("report-target");
        fs::write(&destination, sentinel)?;
        std::os::unix::fs::symlink(&destination, output)?;
        assert!(execute(&f.options, &mut stdout).is_err());
        assert!(stdout.is_empty());
        assert_eq!(fs::read(destination)?, sentinel);
        assert!(fs::symlink_metadata(output)?.file_type().is_symlink());
        assert_eq!(f.head()?, f.head);
    }
    Ok(())
}

#[test]
fn stdout_failure_preserves_the_complete_private_multi_camera_report() -> TestResult {
    struct RefuseStdout;
    impl Write for RefuseStdout {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "test closed stdout",
            ))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let f = fixture("multiview-stdout", false)?;
    assert!(execute(&f.options, &mut RefuseStdout).is_err());
    let bytes = fs::read(f.options.report_out.as_ref().ok_or("report output")?)?;
    assert!(bytes.ends_with(b"\n"));
    let value = parse(std::str::from_utf8(&bytes)?)?;
    assert_eq!(
        field(geometry(&value)?, &["outcome"])?.text(),
        Some("reconstructed")
    );
    Ok(())
}

fn crop_third_view(f: &mut Fixture) -> TestResult {
    let mut rig = parse(std::str::from_utf8(&fs::read(&f.options.rig)?)?)?;
    let source_intrinsics = field(&rig, &["cameras", "2", "intrinsics"])?.clone();
    for (key, value) in [("width", 128), ("height", 96), ("cx", 80), ("cy", 48)] {
        put(
            &mut rig,
            &["cameras", "2", "intrinsics", key],
            Value::Number(value.to_string()),
        )?;
    }
    let rig_text = json(&rig);
    fs::write(&f.options.rig, &rig_text)?;
    let mut document = f.document.clone();
    put(
        &mut document,
        &["schema"],
        Value::Text(input::SCHEMA_V2.into()),
    )?;
    put(
        &mut document,
        &["camera_rig_digest"],
        Value::Text(h(&rig_text).to_text()),
    )?;
    let mut views = field(&document, &["views"])?
        .array()
        .ok_or("views")?
        .to_vec();
    for (index, view) in views.iter_mut().enumerate() {
        let Value::Object(fields) = view else {
            return Err("view object".into());
        };
        let domain = fields
            .remove("image_domain_digest")
            .ok_or("source image domain")?;
        let image = if index == 2 {
            parse(&object(&[
                ("kind", string("rectified")),
                ("source_domain_digest", json(&domain)),
                (
                    "lens_basis",
                    string(&h("explicit synthetic camera 3 pinhole crop").to_text()),
                ),
                ("source_intrinsics", json(&source_intrinsics)),
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
        fields.insert("image".into(), image);
    }
    put(&mut document, &["views"], Value::Array(views))?;
    f.set_query(&document)?;
    f.document = document;
    Ok(())
}

#[test]
fn mixed_native_and_corrected_retained_views_preserve_joint_points_and_original_grid_lineage()
-> TestResult {
    let mut f = fixture("multiview-v2-lens", false)?;
    crop_third_view(&mut f)?;
    let mut stdout = Vec::new();
    assert!(checked(execute(&f.options, &mut stdout))?);
    assert_eq!(
        stdout,
        fs::read(f.options.report_out.as_ref().ok_or("report output")?)?
    );
    let value = parse(std::str::from_utf8(&stdout)?)?;
    assert_eq!(
        field(&value, &["schema"])?.text(),
        Some("fss.scene_feature_multimatch_retained.v2")
    );
    let analysis = field(&value, &["report", "analysis"])?;
    assert_eq!(
        field(analysis, &["physical_identity_established"])?.boolean(),
        Some(false)
    );
    let source_view = field(analysis, &["views", "2"])?;
    let processing = field(source_view, &["image_processing"])?;
    assert_eq!(
        field(processing, &["kind"])?.text(),
        Some("native_rectified")
    );
    assert_eq!(
        field(source_view, &["source", "dimensions", "0"])?.integer(),
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
        field(processing, &["source", "exposure_digest"])?,
        field(processing, &["output", "exposure_digest"])?
    );
    assert_eq!(
        field(processing, &["source", "storage_digest"])?,
        field(source_view, &["source", "pixel_digest"])?
    );
    assert_ne!(
        field(processing, &["output", "pixel_digest"])?,
        field(source_view, &["source", "pixel_digest"])?
    );
    assert_eq!(
        field(processing, &["output", "image_domain_digest"])?,
        field(source_view, &["image_domain_digest"])?
    );
    assert_eq!(
        field(processing, &["allowed_mask_digest"])?,
        field(source_view, &["allowed_mask_digest"])?
    );
    assert_eq!(
        field(source_view, &["source", "encoded_source_digest"])?.text(),
        Some(f.capsules[2].source_digest.to_text().as_str())
    );
    assert_eq!(
        field(analysis, &["views", "0", "image_processing", "kind"])?.text(),
        Some("native_pinhole")
    );
    assert_eq!(
        field(analysis, &["views", "1", "image_processing", "kind"])?.text(),
        Some("native_pinhole")
    );
    let g = geometry(&value)?;
    assert_eq!(field(g, &["counts", "camera_pairs"])?.integer(), Some(3));
    let mut triples = 0;
    for component in field(g, &["components"])?.array().ok_or("components")? {
        if field(component, &["outcome", "state"])?.text() != Some("estimated") {
            continue;
        }
        if field(component, &["members"])?
            .array()
            .ok_or("members")?
            .len()
            == 3
        {
            triples += 1;
        }
        let Value::Number(depth) = field(component, &["outcome", "position", "2"])? else {
            return Err("point depth".into());
        };
        assert!((depth.parse::<f64>()? - 10.0).abs() < 1e-8);
    }
    assert!(
        triples >= 3,
        "expected three-camera components after exact native crop"
    );
    Ok(())
}

#[test]
fn a_folded_final_camera_lens_prevents_every_earlier_decode_publication() -> TestResult {
    let mut f = fixture("multiview-v2-preflight", false)?;
    crop_third_view(&mut f)?;
    let mut document = f.document.clone();
    put(
        &mut document,
        &["views", "2", "image", "distortion"],
        parse(r#"{"kind":"brown_conrady","radial":[-1,0,0],"tangential":[0,0]}"#)?,
    )?;
    f.set_query(&document)?;
    refused(&f)?;
    assert_eq!(f.head()?, f.head);
    Ok(())
}
