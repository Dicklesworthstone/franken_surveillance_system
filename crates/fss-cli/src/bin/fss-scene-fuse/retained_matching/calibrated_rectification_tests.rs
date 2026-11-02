#![forbid(unsafe_code)]
//! Genuine retained/adopted command owners consuming independently rendered radial JPEGs.
//! The fixed plane and camera models are numeric controls, not physical survey evidence.

use super::*;
use fss_core::{CanonicalEncode, TimestampNs};
use fss_reference::ingest::recorded_decode::retained_source_capsule;
use fss_reference::ingest::{CaptureHint, FileIngestAdapter, FileIngestRequest};

const RAW: [&str; 3] = [
    include_str!("../../../../tests/fixtures/adopted_radial/camera_0.jpeg.hex"),
    include_str!("../../../../tests/fixtures/adopted_radial/camera_1.jpeg.hex"),
    include_str!("../../../../tests/fixtures/adopted_radial/camera_2.jpeg.hex"),
];
const RAW_DIGESTS: [&str; 3] = [
    "sha256:3eeaa2b3128a7ae5314e9beb35f459148a9c8b76596ae8188a8e6a0920321f7d",
    "sha256:84a7fa0b59e32969a099188ab0bdd56503ecb0cbd9bea5b942de02bad3bb5309",
    "sha256:226a0c4d3ac3a75bf690384a49d0f1017d90703d5983ef321911a60270b9e8f9",
];
const RADIAL: [f64; 2] = [-0.08, 0.01];

#[derive(Clone, Copy)]
pub(in crate::retained_matching) enum Mode {
    Pair,
    Multi,
    Temporal,
}

fn jpeg(camera: usize, exposure: usize) -> Test<Vec<u8>> {
    let hex = RAW.get(camera).ok_or("raw camera fixture")?;
    let digits = hex
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    assert_eq!(digits.len() % 2, 0);
    let mut bytes = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks_exact(2) {
        bytes.push(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?);
    }
    assert_eq!(h(&bytes).to_text(), RAW_DIGESTS[camera]);
    if exposure >= 2 && camera < 2 {
        // A later authenticated exposure has distinct original encoded bytes but the
        // exact same native pixels. The independent physical-motion control is zero.
        let comment = format!("original radial fixture camera {camera}, exposure {exposure}");
        let length = u16::try_from(comment.len() + 2)?;
        let mut later = Vec::with_capacity(bytes.len() + comment.len() + 4);
        later.extend_from_slice(&bytes[..2]);
        later.extend_from_slice(&[0xff, 0xfe]);
        later.extend_from_slice(&length.to_be_bytes());
        later.extend_from_slice(comment.as_bytes());
        later.extend_from_slice(&bytes[2..]);
        bytes = later;
    }
    Ok(bytes)
}

fn owned_views(document: &Value) -> Test<Vec<Value>> {
    Ok(query_views(document)?.into_iter().cloned().collect())
}
fn replace_views(document: &mut Value, views: Vec<Value>) -> Test {
    let Value::Object(top) = document else {
        return Err("query object".into());
    };
    if top.contains_key("views") {
        top.insert("views".into(), Value::Array(views));
    } else {
        let [left, right]: [Value; 2] = views.try_into().map_err(|_| "pair views")?;
        top.insert("left".into(), left);
        top.insert("right".into(), right);
    }
    Ok(())
}

fn source_inputs(mut base: Fixture, mode: Mode) -> Test<Fixture> {
    let mut query = base.document.clone();
    let mut views = owned_views(&query)?;
    let cx = context(&base.options.root)?;
    let mut deployment = ReferenceDeployment::reopen(&base.options.root, &base.options.site, &cx)?;
    for (index, view) in views.iter_mut().enumerate() {
        let camera = usize::try_from(scalar(field(view, &["camera"])?)?)? - 1;
        let original = base.capsules[index].clone();
        let bytes = jpeg(
            camera,
            if matches!(mode, Mode::Temporal) {
                index
            } else {
                0
            },
        )?;
        let path = base
            .directory()
            .join(format!("independent-radial-{index}.mjpeg"));
        fs::write(&path, &bytes)?;
        let capture = (original.capture.earliest.0 + original.capture.latest.0) / 2;
        let uncertainty =
            u64::try_from((original.capture.latest.0 - original.capture.earliest.0) / 2)?;
        let imported = FileIngestAdapter::ingest(
            FileIngestRequest::new(
                &path,
                original.sensor_id.clone(),
                original.stream_id.clone(),
            )
            .with_receive_time(original.receive_time)
            .with_capture_hint(CaptureHint::new(
                TimestampNs(capture),
                uncertainty,
                30.0,
            )?),
            &cx,
            &mut deployment,
        )?;
        fs::remove_file(&path)?;
        let retained = RetainedFileImport::open(
            &deployment,
            imported.import_identity,
            RetainedReadLimits::default(),
            &cx,
        )?;
        let capsule = retained_source_capsule(&deployment, &retained, 0)?;
        assert_eq!(capsule.source_digest, h(&bytes));
        assert_eq!(capsule.capture, original.capture);
        assert_eq!(capsule.sensor_id, original.sensor_id);
        assert_eq!(capsule.stream_id, original.stream_id);
        base.imports[index] = imported.import_identity;
        base.capsules[index] = capsule.clone();
        for (key, digest) in [
            ("import_identity", imported.import_identity),
            ("capsule_digest", h(capsule.try_canonical_bytes()?)),
            ("encoded_source_digest", capsule.source_digest),
        ] {
            put(view, &["source", key], Value::Text(digest.to_text()))?;
        }
        put(
            view,
            &["alignment", "import_identity"],
            Value::Text(imported.import_identity.to_text()),
        )?;
        put(
            view,
            &["alignment", "clock_basis"],
            Value::Text(capsule.clock_basis.as_str().into()),
        )?;
        let domain = h(format!("independent raw radial camera {} grid", camera + 1));
        if view
            .object()
            .is_some_and(|row| row.contains_key("image_domain_digest"))
        {
            put(
                view,
                &["image_domain_digest"],
                Value::Text(domain.to_text()),
            )?;
        } else {
            put(
                view,
                &["image", "image_domain_digest"],
                Value::Text(domain.to_text()),
            )?;
        }
    }
    base.head = deployment.current_anchor().clone();
    drop(deployment);
    cx.drain_and_finalize();
    replace_views(&mut query, views)?;
    let mut rig = parse(std::str::from_utf8(&fs::read(&base.options.rig)?)?)?;
    let cameras = rows(&rig, &["cameras"])?.len();
    for index in 0..cameras {
        // The three new cameras all have the same original K. The previous third
        // fixture's cx112 represented a different authored camera and is not reused.
        put(
            &mut rig,
            &["cameras", &index.to_string(), "intrinsics", "cx"],
            Value::Number("96".into()),
        )?;
    }
    let rig_bytes = json(&rig);
    fs::write(&base.options.rig, &rig_bytes)?;
    put(
        &mut query,
        &["camera_rig_digest"],
        Value::Text(h(rig_bytes).to_text()),
    )?;
    base.set_query(&query)?;
    base.document = query;
    base.options.expected_anchor = Some(anchor_digest(&base.head));
    Ok(base)
}

fn configure_images(f: &mut AdoptedFixture, mode: Mode, radial: [f64; 2]) -> Test {
    let mut views = owned_views(&f.base.document)?;
    for view in &mut views {
        let camera = scalar(field(view, &["camera"])?)?;
        let index = f
            .calibration
            .cameras
            .iter()
            .position(|record| record.identity.camera == camera)
            .ok_or("calibrated camera")?;
        let original = f.calibration.camera_input_basis(camera, &f.inputs[index])?;
        let image = parse(&object(&[
            ("kind", string("rectified")),
            (
                "source_domain_digest",
                string(
                    &ContentDigest::new(
                        fss_core::DigestAlgorithm::Sha256,
                        original.image.image_domain,
                    )
                    .to_text(),
                ),
            ),
            ("lens_basis", string(&f.calibration.digest()?.to_text())),
            (
                "source_intrinsics",
                r#"{"width":192,"height":128,"fx":160,"fy":160,"cx":96,"cy":64}"#.into(),
            ),
            (
                "distortion",
                object(&[
                    ("kind", string("brown_conrady")),
                    (
                        "radial",
                        array(&[radial[0].to_string(), radial[1].to_string(), "0".into()]),
                    ),
                    ("tangential", "[0,0]".into()),
                ]),
            ),
            ("maximum_radius", "1".into()),
            ("luma_range", string("full")),
        ]))?;
        let Value::Object(row) = view else {
            return Err("view row".into());
        };
        row.remove("image_domain_digest");
        row.insert("image".into(), image);
    }
    let mut query = f.base.document.clone();
    replace_views(&mut query, views)?;
    let schema = match mode {
        Mode::Pair => "fss.scene_feature_match_retained_query.v2",
        Mode::Multi => "fss.scene_feature_multimatch_retained_query.v2",
        Mode::Temporal => "fss.scene_feature_motion_match_retained_query.v1",
    };
    put(&mut query, &["schema"], Value::Text(schema.into()))?;
    put(
        &mut query,
        &["extraction", "maximum_features"],
        Value::Number("64".into()),
    )?;
    let matching = if matches!(mode, Mode::Temporal) {
        r#"{"maximum_hamming_distance":64,"ratio_percent":75}"#
    } else {
        r#"{"maximum_hamming_distance":64,"ratio_percent":75,"maximum_epipolar_distance_pixels":1.01}"#
    };
    put(&mut query, &["matching"], parse(matching)?)?;
    put(
        &mut query,
        &["triangulation", "max_reprojection_pixels"],
        Value::Number("1.01".into()),
    )?;
    f.base.document = query;
    f.save_rig()?;
    Ok(())
}

pub(in crate::retained_matching) fn fixture(label: &str, mode: Mode) -> Test<AdoptedFixture> {
    fixture_model(label, mode, RADIAL)
}

/// A complete native analysis may retain unresolved alternatives alongside solved points.
/// Atlas tests select actual solved pins without requiring that every component resolve.
pub(in crate::retained_matching) fn preview_report(f: &AdoptedFixture) -> Test<String> {
    let cx = context(&f.base.options.root)?;
    let report = checked(analyze(&f.base.options, &f.base.options.root, &cx))?;
    let bytes = report.json.clone();
    drop(report);
    cx.drain_and_finalize();
    let value = parse_report(&bytes)?;
    check_lineage(f, &value)?;
    Ok(bytes)
}

/// Optional laboratory export of exact executed owner output for full-schema validation.
pub(in crate::retained_matching) fn export_fixture(name: &str, bytes: &[u8]) -> Test {
    if let Some(directory) = std::env::var_os("FSS_ADOPTED_RADIAL_FIXTURE_DIR") {
        let directory = PathBuf::from(directory);
        fs::create_dir_all(&directory)?;
        fs::write(directory.join(name), bytes)?;
    }
    Ok(())
}

fn fixture_model(label: &str, mode: Mode, radial: [f64; 2]) -> Test<AdoptedFixture> {
    let base = match mode {
        Mode::Pair => Fixture::new(label)?,
        Mode::Multi => crate::retained_matching::multiview::tests::atlas_fixture_preview(label)?.0,
        Mode::Temporal => crate::retained_matching::temporal::tests::fixture(label, false)?,
    };
    let base = source_inputs(base, mode)?;
    let mut f = AdoptedFixture::from_source(base, false)?;
    for camera in &mut f.calibration.cameras {
        camera.distortion = radial;
    }
    let bytes = f.calibration.encode()?;
    fs::write(&f.calibration_path, &bytes)?;
    put(
        &mut f.rig,
        &["schema"],
        Value::Text("fss.scene_camera_rig_adopted.v2".into()),
    )?;
    put(
        &mut f.rig,
        &["calibration", "digest"],
        Value::Text(f.calibration.digest()?.to_text()),
    )?;
    put(
        &mut f.rig,
        &["calibration", "file_digest"],
        Value::Text(h(bytes).to_text()),
    )?;
    let bindings = f
        .calibration
        .cameras
        .iter()
        .enumerate()
        .map(|(index, camera)| {
            (
                camera.name.clone(),
                f.base.capsules[index].sensor_id.clone(),
            )
        })
        .collect::<Vec<_>>();
    let subject = CalibrationSubject::from_calibration(&f.calibration, f.calibration.digest()?);
    let cx = context(&f.base.options.root)?;
    let mut deployment =
        ReferenceDeployment::reopen(&f.base.options.root, &f.base.options.site, &cx)?;
    let approval = preview_adoption(&deployment, &subject, &bindings)?.approval;
    let adopted = adopt(&mut deployment, &subject, &bindings, approval, &cx)?;
    f.adoptions = adopted
        .cameras
        .iter()
        .map(|camera| camera.receipt.digest())
        .collect();
    for (index, digest) in f.adoptions.iter().enumerate() {
        put(
            &mut f.rig,
            &["cameras", &index.to_string(), "adoption_digest"],
            Value::Text(digest.to_text()),
        )?;
    }
    f.base.head = deployment.current_anchor().clone();
    f.base.options.expected_anchor = Some(anchor_digest(&f.base.head));
    drop(deployment);
    cx.drain_and_finalize();
    configure_images(&mut f, mode, radial)?;
    Ok(f)
}

fn save_query(f: &mut AdoptedFixture, query: Value) -> Test {
    f.base.set_query(&query)?;
    f.base.document = query;
    Ok(())
}

fn check_lineage(f: &AdoptedFixture, value: &Value) -> Test {
    assert_eq!(
        field(value, &["schema"])?.text(),
        Some("fss.scene_feature_match_adopted.v2")
    );
    assert_eq!(
        field(value, &["report", "schema"])?.text(),
        Some("fss.scene_feature_match_adopted_report.v2")
    );
    let analysis = field(value, &["report", "analysis"])?;
    let cameras = rows(analysis, &["calibration", "selected_cameras"])?;
    for camera in cameras {
        assert_eq!(vector::<2>(field(camera, &["radial_distortion"])?)?, RADIAL);
        assert_eq!(
            field(camera, &["absolute_calibration_error", "state"])?.text(),
            Some("unknown")
        );
        assert_eq!(field(camera, &["status"])?.text(), Some("adopted_current"));
    }
    let views = rows(analysis, &["views"])?;
    assert_eq!(views.len(), f.base.imports.len());
    for row in views {
        let view = field(row, &["view"])?;
        let image = field(view, &["image_processing"])?;
        assert_eq!(field(image, &["kind"])?.text(), Some("native_rectified"));
        assert_eq!(
            field(image, &["source", "exposure_digest"])?,
            field(image, &["output", "exposure_digest"])?
        );
        assert_eq!(
            field(image, &["source", "storage_digest"])?,
            field(view, &["source", "pixel_digest"])?
        );
        assert_ne!(
            field(image, &["source", "storage_digest"])?,
            field(image, &["output", "pixel_digest"])?
        );
        assert_ne!(
            field(image, &["source", "image_domain_digest"])?,
            field(image, &["output", "image_domain_digest"])?
        );
        assert_eq!(
            field(image, &["output", "image_domain_digest"])?,
            field(view, &["image_domain_digest"])?
        );
        assert_eq!(
            field(image, &["allowed_mask_digest"])?,
            field(view, &["allowed_mask_digest"])?
        );
        assert_eq!(
            pin(field(image, &["model", "lens_basis"])?)?,
            f.calibration.digest()?
        );
        assert_ne!(
            pin(field(image, &["model", "lens_basis"])?)?,
            h(fs::read(&f.calibration_path)?)
        );
        assert_eq!(
            field(image, &["model", "source_intrinsics"])?,
            field(image, &["model", "target_intrinsics"])?
        );
        assert_eq!(
            vector::<3>(field(image, &["model", "distortion", "radial"])?)?,
            [-0.08, 0.01, 0.]
        );
        assert_eq!(
            field(image, &["source", "dimensions"])?,
            field(image, &["output", "dimensions"])?
        );
        assert!(!text(field(view, &["source", "native_receipt_hex"])?)?.is_empty());
        let source = pin(field(view, &["source", "encoded_source_digest"])?)?;
        assert!(
            f.base
                .capsules
                .iter()
                .any(|capsule| capsule.source_digest == source)
        );
    }
    Ok(())
}

fn check_estimates(value: &Value, temporal: bool) -> Test<usize> {
    let mut points = Vec::new();
    estimates(
        field(value, &["report", "analysis", "geometry"])?,
        &mut points,
    );
    assert!(
        !points.is_empty(),
        "native radial pixels must provide geometric support"
    );
    for point in &points {
        let position = vector::<3>(field(point, &["position"])?)?;
        assert!((position[2] - 10.).abs() < 1.0);
        if temporal {
            for velocity in vector::<3>(field(point, &["velocity_per_second"])?)? {
                assert!(velocity.abs() < 1e-5);
            }
        }
    }
    Ok(points.len())
}

#[test]
fn nonzero_adopted_lenses_reconstruct_retained_pair_multiview_and_stationary_temporal_sources()
-> Test {
    for (mode, label, temporal) in [
        (Mode::Pair, "adopted-radial-pair", false),
        (Mode::Multi, "adopted-radial-multi", false),
        (Mode::Temporal, "adopted-radial-temporal", true),
    ] {
        let f = fixture(label, mode)?;
        let (stdout, value) = execute_report(&f)?;
        check_lineage(&f, &value)?;
        assert!(check_estimates(&value, temporal)? >= 3);
        export_fixture(
            match mode {
                Mode::Pair => "pair.json",
                Mode::Multi => "multiview.json",
                Mode::Temporal => "temporal.json",
            },
            &stdout,
        )?;
        let path = f.base.options.report_out.as_ref().ok_or("private report")?;
        assert_eq!(fs::read(path)?, stdout);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
        }
    }
    Ok(())
}

#[test]
fn mismatched_raw_models_and_target_overrides_refuse_before_any_derivative_publication() -> Test {
    let mut f = fixture("adopted-radial-model-pins", Mode::Pair)?;
    let base_query = f.base.document.clone();
    for (path, replacement) in [
        (
            vec!["left", "image", "source_intrinsics", "fx"],
            Value::Number("159".into()),
        ),
        (
            vec!["left", "image", "source_intrinsics", "width"],
            Value::Number("191".into()),
        ),
        (
            vec!["left", "image", "source_domain_digest"],
            Value::Text(h("wrong original raw domain").to_text()),
        ),
        (
            vec!["left", "image", "lens_basis"],
            Value::Text(h(fs::read(&f.calibration_path)?).to_text()),
        ),
        (
            vec!["left", "image", "distortion", "radial", "0"],
            Value::Number("-0.07".into()),
        ),
        (
            vec!["left", "image", "distortion", "radial", "2"],
            Value::Number("0.001".into()),
        ),
        (
            vec!["left", "image", "distortion", "tangential", "0"],
            Value::Number("0.001".into()),
        ),
    ] {
        let mut invalid = base_query.clone();
        put(&mut invalid, &path, replacement)?;
        f.base.set_query(&invalid)?;
        f.refused()?;
        assert_eq!(f.base.head()?, f.base.head);
    }
    let mut invalid = base_query;
    let Value::Object(top) = &mut invalid else {
        return Err("query".into());
    };
    let Value::Object(left) = top.get_mut("left").ok_or("left")? else {
        return Err("left".into());
    };
    let Value::Object(image) = left.get_mut("image").ok_or("image")? else {
        return Err("image".into());
    };
    image.insert(
        "target_intrinsics".into(),
        parse(r#"{"width":192,"height":128,"fx":160,"fy":160,"cx":96,"cy":64}"#)?,
    );
    f.base.set_query(&invalid)?;
    f.refused()?;
    assert_eq!(f.base.head()?, f.base.head);
    Ok(())
}

#[test]
fn nonzero_models_cannot_claim_direct_pinhole_or_enter_the_original_rig_profile() -> Test {
    let mut f = fixture("adopted-radial-direct-refusal", Mode::Pair)?;
    let mut query = f.base.document.clone();
    let domain = field(&query, &["left", "image", "source_domain_digest"])?.clone();
    put(
        &mut query,
        &["left", "image"],
        parse(&object(&[
            ("kind", string("pinhole")),
            ("image_domain_digest", json(&domain)),
        ]))?,
    )?;
    save_query(&mut f, query)?;
    f.refused()?;
    assert_eq!(f.base.head()?, f.base.head);

    let mut f = fixture("adopted-radial-legacy-refusal", Mode::Pair)?;
    put(
        &mut f.rig,
        &["schema"],
        Value::Text("fss.scene_camera_rig_adopted.v1".into()),
    )?;
    f.save_rig()?;
    f.refused()?;
    assert_eq!(f.base.head()?, f.base.head);
    Ok(())
}

#[test]
fn a_genuinely_adopted_folded_lens_is_refused_before_original_jpeg_decode() -> Test {
    let f = fixture_model("adopted-radial-fold", Mode::Pair, [-1., 0.])?;
    // Calibration and query agree exactly. This must reach the native map admission,
    // not pass by failing a declaration/receipt hash before the folding check.
    assert_eq!(
        vector::<3>(field(
            &f.base.document,
            &["right", "image", "distortion", "radial"]
        )?)?,
        [-1., 0., 0.]
    );
    let mut stdout = Vec::new();
    let error = execute(&f.base.options, &mut stdout).expect_err("folded native lens must refuse");
    assert_eq!(error.code, "ERR-SCENE-FUSION-INPUT-001");
    assert_eq!(
        error.detail,
        "native image model refused: lens model not admitted over declared domain"
    );
    assert!(stdout.is_empty());
    assert!(
        !f.base
            .options
            .report_out
            .as_ref()
            .ok_or("report output")?
            .exists()
    );
    assert_eq!(f.base.head()?, f.base.head);
    Ok(())
}

#[test]
fn original_source_current_privacy_and_adoption_are_required_after_a_radial_preview() -> Test {
    let mut f = fixture("adopted-radial-current-mask", Mode::Pair)?;
    let cx = context(&f.base.options.root)?;
    let preview = checked(analyze(&f.base.options, &f.base.options.root, &cx))?;
    drop(preview);
    cx.drain_and_finalize();
    let cx = context(&f.base.options.root)?;
    let mut deployment =
        ReferenceDeployment::reopen(&f.base.options.root, &f.base.options.site, &cx)?;
    let policy = PrivacyMaskPolicy::new(
        f.base.capsules[0].sensor_id.clone(),
        [WIDTH, HEIGHT],
        &[[0, 0, WIDTH, HEIGHT]],
    )?;
    let approval = preview_mask(&deployment, &policy)?.approval;
    declare_mask(&mut deployment, &policy, approval, &cx)?;
    drop(deployment);
    cx.drain_and_finalize();
    f.refresh_anchor()?;
    let (_, value) = execute_report(&f)?;
    assert_eq!(
        field(&value, &["report", "analysis", "counts", "solved"])?.integer(),
        Some(0)
    );
    let left = rows(&value, &["report", "analysis", "views"])?
        .iter()
        .find(|row| {
            field(row, &["view", "camera"])
                .ok()
                .and_then(Value::integer)
                == Some(1)
        })
        .ok_or("left view")?;
    assert!(rows(left, &["view", "features"])?.is_empty());
    assert_eq!(
        field(
            left,
            &["view", "image_processing", "coverage", "allowed_pixels"]
        )?
        .integer(),
        Some(0)
    );
    assert_eq!(
        pin(field(left, &["view", "source", "encoded_source_digest"])?)?,
        f.base.capsules[0].source_digest
    );

    let mut f = fixture("adopted-radial-withdrawn", Mode::Pair)?;
    let cx = context(&f.base.options.root)?;
    let preview = checked(analyze(&f.base.options, &f.base.options.root, &cx))?;
    drop(preview);
    cx.drain_and_finalize();
    let cx = context(&f.base.options.root)?;
    let mut deployment =
        ReferenceDeployment::reopen(&f.base.options.root, &f.base.options.site, &cx)?;
    let request = InvalidationRequest {
        camera_handle: 1,
        adoption_digest: f.adoptions[0],
        reason: InvalidationReason::OwnerRevoked,
        evidence: None,
    };
    let approval = preview_invalidation(&deployment, &request)?.approval;
    invalidate(&mut deployment, &request, approval, &cx)?;
    drop(deployment);
    cx.drain_and_finalize();
    f.refresh_anchor()?;
    f.refused()?;
    assert_eq!(f.base.head()?, f.base.head);

    let mut f = fixture("adopted-radial-original-custody", Mode::Pair)?;
    let cx = context(&f.base.options.root)?;
    let preview = checked(analyze(&f.base.options, &f.base.options.root, &cx))?;
    drop(preview);
    cx.drain_and_finalize();
    f.refresh_anchor()?;
    let cx = context(&f.base.options.root)?;
    let deployment = ReferenceDeployment::reopen(&f.base.options.root, &f.base.options.site, &cx)?;
    let source = RetainedFileImport::open(
        &deployment,
        f.base.imports[0],
        RetainedReadLimits::default(),
        &cx,
    )?;
    let path = deployment
        .publisher()
        .spool()
        .object_path(source.manifest().ordered_chunks[0]);
    let mut bytes = fs::read(&path)?;
    *bytes.last_mut().ok_or("source bytes")? ^= 1;
    fs::write(&path, &bytes)?;
    drop(deployment);
    cx.drain_and_finalize();
    f.refused()?;
    assert_eq!(fs::read(path)?, bytes);
    Ok(())
}

#[test]
fn radial_preparation_obeys_work_cancellation_and_complete_output_bounds() -> Test {
    let f = fixture("adopted-radial-cancel", Mode::Pair)?;
    let cx = context(&f.base.options.root)?;
    cx.request_cancellation();
    assert!(analyze(&f.base.options, &f.base.options.root, &cx).is_err());
    cx.drain_and_finalize();
    assert_eq!(f.base.head()?, f.base.head);
    for report_limit in [false, true] {
        let mut f = fixture(
            if report_limit {
                "adopted-radial-report-cap"
            } else {
                "adopted-radial-work-cap"
            },
            Mode::Pair,
        )?;
        if report_limit {
            f.base.options.report_bytes = 1024;
        } else {
            f.base.options.work = 1;
        }
        f.refused()?;
        if !report_limit {
            assert_eq!(f.base.head()?, f.base.head);
        }
    }
    Ok(())
}
