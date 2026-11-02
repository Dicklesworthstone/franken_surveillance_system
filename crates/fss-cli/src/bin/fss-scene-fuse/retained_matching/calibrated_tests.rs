#![forbid(unsafe_code)]
//! Actual retained JPEGs, original calibration metadata, adoption authority and command I/O.
//!
//! Calibration matrices and covariance are explicitly authored synthetic controls matching
//! the existing z=10 JPEG fixtures. Their adoption is real retained owner authority; it does
//! not claim that an optimizer or a physical survey measured these fixture parameters.

use super::super::tests::{Fixture, checked, context, field, h, json, put};
use super::*;
use crate::matching::fixtures::{HEIGHT, WIDTH};
use fss_cli::json_input::{Value, parse, parse_reconstruction_atlas_report as parse_report};
use fss_cli::json_output::{array, object, string};
use fss_core::{ContentDigest, SensorId};
use fss_geometry::BundleParameter;
use fss_reference::ingest::calibration_adoption::{
    CalibrationSubject, CameraGeneration, adopt, preview_adoption, retained_adoptions,
};
use fss_reference::ingest::calibration_invalidation::{
    InvalidationReason, InvalidationRequest, invalidate, preview_invalidation,
};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::site_calibration::{
    CalibratedCamera, CalibrationInput, SeedMode, SiteCalibration,
};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_twin::localization::native::descriptor_domain;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const WORK: u64 = 8_000_000_000;
const OUTPUT: usize = 32 * 1024 * 1024;

#[path = "calibrated_rectification_tests.rs"]
pub(in crate::retained_matching) mod rectification;

fn number(value: &Value) -> Test<f64> {
    match value {
        Value::Number(text) => Ok(text.parse()?),
        _ => Err("expected number".into()),
    }
}
fn text(value: &Value) -> Test<&str> {
    value.text().ok_or("expected text".into())
}
fn pin(value: &Value) -> Test<ContentDigest> {
    Ok(ContentDigest::parse(text(value)?)?)
}
fn scalar(value: &Value) -> Test<u64> {
    Ok(u64::try_from(value.integer().ok_or("expected integer")?)?)
}
fn rows<'a>(value: &'a Value, path: &[&str]) -> Test<&'a [Value]> {
    field(value, path)?.array().ok_or("expected rows".into())
}
fn vector<const N: usize>(value: &Value) -> Test<[f64; N]> {
    let values = value.array().ok_or("expected vector")?;
    if values.len() != N {
        return Err("wrong vector length".into());
    }
    let mut output = [0.; N];
    for (slot, value) in output.iter_mut().zip(values) {
        *slot = number(value)?;
    }
    Ok(output)
}
fn query_views(value: &Value) -> Test<Vec<&Value>> {
    if value.object().is_some_and(|top| top.contains_key("views")) {
        Ok(rows(value, &["views"])?.iter().collect())
    } else {
        Ok(vec![field(value, &["left"])?, field(value, &["right"])?])
    }
}
fn image_domain(value: &Value) -> Test<ContentDigest> {
    if value
        .object()
        .is_some_and(|row| row.contains_key("image_domain_digest"))
    {
        pin(field(value, &["image_domain_digest"])?)
    } else {
        pin(field(value, &["image", "image_domain_digest"])?)
    }
}

pub(in super::super) struct AdoptedFixture {
    pub(in super::super) base: Fixture,
    pub(in super::super) calibration: SiteCalibration,
    pub(in super::super) calibration_path: PathBuf,
    inputs: Vec<Vec<u8>>,
    pub(in super::super) input_paths: Vec<PathBuf>,
    rig: Value,
    pub(in super::super) adoptions: Vec<ContentDigest>,
}
impl AdoptedFixture {
    pub(in super::super) fn pair(label: &str) -> Test<Self> {
        Self::from_source(Fixture::new(label)?, true)
    }
    pub(in super::super) fn from_source(mut base: Fixture, retain: bool) -> Test<Self> {
        let nominal = parse(std::str::from_utf8(&fs::read(&base.options.rig)?)?)?;
        let cameras = rows(&nominal, &["cameras"])?;
        let sources = query_views(&base.document)?;
        let mut records = Vec::new();
        let mut inputs = Vec::new();
        let mut input_paths = Vec::new();
        let mut bindings = Vec::new();
        for camera in cameras {
            let handle = scalar(field(camera, &["camera"])?)?;
            let source = sources
                .iter()
                .copied()
                .find(|view| {
                    field(view, &["camera"]).ok().and_then(Value::integer)
                        == Some(i128::from(handle))
                })
                .ok_or("missing camera source")?;
            let sensor = SensorId::parse(text(field(source, &["source", "sensor_id"])?)?)?;
            let intrinsics = [
                number(field(camera, &["intrinsics", "fx"])?)?,
                number(field(camera, &["intrinsics", "fy"])?)?,
                number(field(camera, &["intrinsics", "cx"])?)?,
                number(field(camera, &["intrinsics", "cy"])?)?,
            ];
            let dimensions = [
                u32::try_from(scalar(field(camera, &["intrinsics", "width"])?)?)?,
                u32::try_from(scalar(field(camera, &["intrinsics", "height"])?)?)?,
            ];
            let rotation_rows = rows(camera, &["world_to_camera", "rotation"])?;
            let rotation = [
                vector(&rotation_rows[0])?,
                vector(&rotation_rows[1])?,
                vector(&rotation_rows[2])?,
            ];
            let translation = vector(field(camera, &["world_to_camera", "translation"])?)?;
            let name = format!("camera{handle}");
            let input = format!(
                "fss.site_camera_observations.v1\ncamera {handle} 1 1\nimage {} {}\nexposure {}\npixels {}\nimage-domain {}\ndescriptor-domain {}\nintrinsics fixed {} {} {} {}\n",
                dimensions[0], dimensions[1], h(format!("earlier original calibration exposure {handle}")),
                h(format!("earlier original calibration pixels {handle}")), image_domain(source)?,
                ContentDigest::new(fss_core::DigestAlgorithm::Sha256, descriptor_domain()),
                intrinsics[0], intrinsics[1], intrinsics[2], intrinsics[3],
            ).into_bytes();
            let path = base
                .directory()
                .join(format!("camera-{handle}.observations"));
            fs::write(&path, &input)?;
            let covariance_parameters = vec![
                BundleParameter::Rotation(0),
                BundleParameter::Rotation(1),
                BundleParameter::Rotation(2),
                BundleParameter::Translation(0),
                BundleParameter::Translation(1),
                BundleParameter::Translation(2),
            ];
            let covariance = (0..36)
                .map(|index| if index / 6 == index % 6 { 1e-8 } else { 0. })
                .collect();
            records.push(CalibratedCamera {
                name: name.clone(),
                identity: CameraGeneration {
                    camera: handle,
                    intrinsics: 1,
                    extrinsics: 1,
                },
                observations: h(&input),
                input: CalibrationInput::Correspondences,
                dimensions,
                mode: SeedMode::Fixed,
                seed_sample: None,
                seed_candidate: 0,
                seed_alternatives: 1,
                seed_inliers: 0,
                seed_fit_rms_px: 0.,
                seed_intrinsics: intrinsics,
                seed_rotation: rotation,
                seed_translation: translation,
                intrinsics,
                distortion: [0., 0.],
                rotation,
                translation,
                covariance_parameters,
                covariance,
                fixed_parameters: vec![
                    BundleParameter::Focal,
                    BundleParameter::Cx,
                    BundleParameter::Cy,
                ],
                seed_rms_px: 0.,
                refined_rms_px: 0.,
                control_observations: 0,
                free_observations: 0,
            });
            inputs.push(input);
            input_paths.push(path);
            bindings.push((name, sensor));
        }
        let calibration = SiteCalibration {
            twin_package: h(fs::read(&base.options.twin)?),
            twin_source: pin(field(&nominal, &["source_scene_digest"])?)?,
            atlas_package: h("authored synthetic calibration atlas package"),
            atlas_fingerprint: h("authored synthetic calibration atlas fingerprint").bytes(),
            atlas_provenance: h("authored synthetic calibration atlas provenance"),
            descriptor_domain: descriptor_domain(),
            control_error_bound: None,
            initial_rms_px: 0.,
            final_rms_px: 0.,
            iterations: 1,
            accepted_steps: 1,
            convergence: "gradient".into(),
            observation_sigma_px: 1.,
            sigma_estimated: false,
            control_points: vec![],
            tie_points: vec![],
            excluded_points: vec![],
            frame_policy: None,
            cameras: records,
        };
        let encoded = calibration.encode()?;
        let calibration_path = base.directory().join("adopted.calibration");
        fs::write(&calibration_path, &encoded)?;
        assert_ne!(
            h(&encoded),
            calibration.digest()?,
            "semantic and whole-file pins are distinct"
        );
        let subject = CalibrationSubject::from_calibration(&calibration, calibration.digest()?);
        let cx = context(&base.options.root)?;
        let mut deployment =
            ReferenceDeployment::reopen(&base.options.root, &base.options.site, &cx)?;
        let preview = preview_adoption(&deployment, &subject, &bindings)?;
        let selection = if retain {
            adopt(&mut deployment, &subject, &bindings, preview.approval, &cx)?
        } else {
            preview
        };
        let adoptions: Vec<_> = selection
            .cameras
            .iter()
            .map(|camera| camera.receipt.digest())
            .collect();
        base.head = deployment.current_anchor().clone();
        base.options.expected_anchor = Some(anchor_digest(&base.head));
        drop(deployment);
        cx.drain_and_finalize();
        let rows: Vec<_> = cameras
            .iter()
            .enumerate()
            .map(|(index, camera)| -> Test<String> {
                Ok(object(&[
                    ("camera", json(field(camera, &["camera"])?)),
                    ("sensor_id", string(bindings[index].1.as_str())),
                    ("adoption_digest", string(&adoptions[index].to_text())),
                    (
                        "original_input",
                        object(&[
                            (
                                "path",
                                string(input_paths[index].to_str().ok_or("input path")?),
                            ),
                            ("digest", string(&h(&inputs[index]).to_text())),
                        ]),
                    ),
                    (
                        "source_object_id",
                        json(field(camera, &["source_object_id"])?),
                    ),
                    ("image_domain", json(field(camera, &["image_domain"])?)),
                    ("clock", json(field(camera, &["clock"])?)),
                    ("privacy_domain", json(field(camera, &["privacy_domain"])?)),
                    ("validity_ns", json(field(camera, &["validity_ns"])?)),
                ]))
            })
            .collect::<Test<_>>()?;
        let rig = parse(&object(&[
            ("schema", string("fss.scene_camera_rig_adopted.v1")),
            (
                "source_scene_digest",
                json(field(&nominal, &["source_scene_digest"])?),
            ),
            ("twin_digest", json(field(&nominal, &["twin_digest"])?)),
            (
                "geometry_basis",
                json(field(&nominal, &["geometry_basis"])?),
            ),
            ("coordinate_frame", string("RH_Z_UP")),
            (
                "evaluation_scope",
                json(field(&nominal, &["evaluation_scope"])?),
            ),
            (
                "calibration",
                object(&[
                    (
                        "path",
                        string(calibration_path.to_str().ok_or("calibration path")?),
                    ),
                    ("digest", string(&calibration.digest()?.to_text())),
                    ("file_digest", string(&h(&encoded).to_text())),
                ]),
            ),
            ("cameras", array(&rows)),
        ]))?;
        base.options.work = WORK;
        base.options.report_bytes = OUTPUT;
        let mut fixture = Self {
            base,
            calibration,
            calibration_path,
            inputs,
            input_paths,
            rig,
            adoptions,
        };
        fixture.save_rig()?;
        Ok(fixture)
    }
    fn save_rig(&mut self) -> Test {
        let bytes = json(&self.rig);
        fs::write(&self.base.options.rig, &bytes)?;
        put(
            &mut self.base.document,
            &["camera_rig_digest"],
            Value::Text(h(bytes).to_text()),
        )?;
        let query = self.base.document.clone();
        self.base.set_query(&query)?;
        Ok(())
    }
    pub(in super::super) fn refresh_anchor(&mut self) -> Test {
        self.base.head = self.base.head()?;
        self.base.options.expected_anchor = Some(anchor_digest(&self.base.head));
        Ok(())
    }
    fn refused(&self) -> Test {
        let mut stdout = Vec::new();
        assert!(execute(&self.base.options, &mut stdout).is_err());
        assert!(stdout.is_empty());
        if let Some(path) = &self.base.options.report_out {
            assert!(!path.exists());
        }
        Ok(())
    }
}

/// Reuse actual calibrated reconstruction without publishing a preview report file.
/// The returned bytes carry no authority lease: the deployment lock is released here.
pub(in super::super) fn preview_json(f: &AdoptedFixture) -> Test<String> {
    let cx = context(&f.base.options.root)?;
    let result = analyze(&f.base.options, &f.base.options.root, &cx);
    let report = checked(result)?;
    assert!(report.reconstructed);
    let json = report.json.clone();
    drop(report);
    cx.drain_and_finalize();
    Ok(json)
}

fn estimates<'a>(value: &'a Value, output: &mut Vec<&'a Value>) {
    match value {
        Value::Object(fields) => {
            if fields.get("state").and_then(Value::text) == Some("estimated")
                && fields.contains_key("position")
                && fields.contains_key("pixel_noise_covariance")
            {
                output.push(value);
            }
            for child in fields.values() {
                estimates(child, output);
            }
        }
        Value::Array(children) => {
            for child in children {
                estimates(child, output);
            }
        }
        _ => {}
    }
}
fn check_geometry(value: &Value, temporal: bool) -> Test<usize> {
    let mut outcomes = Vec::new();
    estimates(
        field(value, &["report", "analysis", "geometry"])?,
        &mut outcomes,
    );
    assert!(
        !outcomes.is_empty(),
        "actual JPEG geometry must reconstruct"
    );
    for outcome in &outcomes {
        assert!((number(field(outcome, &["position", "2"])?)? - 10.).abs() < 1e-6);
        let covariance = rows(outcome, &["pixel_noise_covariance"])?;
        assert_eq!(covariance.len(), if temporal { 6 } else { 3 });
        if temporal {
            assert_eq!(
                field(outcome, &["reference_time_ns"])?.text(),
                Some("500001050")
            );
            for speed in rows(outcome, &["velocity_per_second"])? {
                assert!(number(speed)?.abs() < 1e-6);
            }
        }
    }
    Ok(outcomes.len())
}
fn check_sources(f: &AdoptedFixture, value: &Value) -> Test {
    let analysis = field(value, &["report", "analysis"])?;
    assert_eq!(
        field(analysis, &["authority"])?.text(),
        Some("derived_cognition_no_effect_authority")
    );
    assert_eq!(
        field(analysis, &["calibration", "calibration_digest"])?.text(),
        Some(f.calibration.digest()?.to_text().as_str())
    );
    assert_eq!(
        field(analysis, &["calibration", "calibration_file_digest"])?.text(),
        Some(h(fs::read(&f.calibration_path)?).to_text().as_str())
    );
    let cameras = rows(analysis, &["calibration", "selected_cameras"])?;
    assert_eq!(cameras.len(), f.calibration.cameras.len());
    for (index, camera) in cameras.iter().enumerate() {
        assert_eq!(field(camera, &["status"])?.text(), Some("adopted_current"));
        assert_eq!(
            field(camera, &["absolute_calibration_error", "state"])?.text(),
            Some("unknown")
        );
        assert_eq!(
            field(camera, &["original_image_basis", "input_digest"])?.text(),
            Some(h(&f.inputs[index]).to_text().as_str())
        );
        let covariance = rows(camera, &["local_covariance", "matrix"])?;
        assert_eq!(covariance.len(), 6);
        for (row, expected) in covariance.iter().zip(
            f.calibration.cameras[index]
                .covariance
                .as_chunks::<6>()
                .0
                .iter(),
        ) {
            let row = row.array().ok_or("covariance row")?;
            assert_eq!(row.len(), 6);
            for (actual, expected) in row.iter().zip(expected) {
                assert_eq!(number(actual)?, *expected);
            }
        }
    }
    let views = rows(analysis, &["views"])?;
    assert_eq!(views.len(), f.base.imports.len());
    let mut exposures = BTreeSet::new();
    for row in views {
        exposures.insert(text(field(row, &["exposure"])?)?.to_owned());
        let view = field(row, &["view"])?;
        assert_eq!(field(view, &["status"])?.text(), Some("adopted_current"));
        assert_eq!(
            field(view, &["calibration_error", "state"])?.text(),
            Some("unknown")
        );
        let camera: u64 = text(field(view, &["camera"])?)?.parse()?;
        let record = f
            .calibration
            .cameras
            .iter()
            .find(|record| record.identity.camera == camera)
            .ok_or("camera")?;
        assert_eq!(
            vector::<3>(field(view, &["world_to_camera", "translation"])?)?,
            record.translation
        );
        for (index, key) in ["fx", "fy", "cx", "cy"].into_iter().enumerate() {
            assert_eq!(
                number(field(view, &["intrinsics", key])?)?,
                record.intrinsics[index]
            );
        }
        let source = pin(field(view, &["source", "import_identity"])?)?;
        let index = f
            .base
            .imports
            .iter()
            .position(|identity| *identity == source)
            .ok_or("original import")?;
        assert_eq!(
            field(view, &["source", "capsule", "sensor_id"])?.text(),
            Some(f.base.capsules[index].sensor_id.as_str())
        );
        assert_eq!(
            field(view, &["source", "encoded_source_digest"])?.text(),
            Some(f.base.capsules[index].source_digest.to_text().as_str())
        );
    }
    assert_eq!(exposures.len(), views.len());
    Ok(())
}
fn execute_report(f: &AdoptedFixture) -> Test<(Vec<u8>, Value)> {
    let mut stdout = Vec::new();
    let success = checked(execute(&f.base.options, &mut stdout))?;
    let value = parse_report(std::str::from_utf8(&stdout)?)?;
    let counts = field(&value, &["report", "analysis", "counts"])?;
    let solved = scalar(field(counts, &["solved"])?)?;
    let unresolved = scalar(field(counts, &["unresolved"])?)?;
    assert_eq!(success, solved > 0 && unresolved == 0);
    if let Some(directory) = std::env::var_os("FSS_ADOPTED_MATCH_FIXTURE_DIR") {
        let directory = PathBuf::from(directory);
        fs::create_dir_all(&directory)?;
        let filename = format!("{}.json", h(&stdout).to_text().replace(':', "-"));
        fs::write(directory.join(filename), &stdout)?;
    }
    Ok((stdout, value))
}

#[test]
fn adopted_original_camera_geometry_reconstructs_retained_stereo_with_complete_report_bytes() -> Test
{
    let f = AdoptedFixture::pair("adopted-stereo")?;
    let (stdout, value) = execute_report(&f)?;
    assert_eq!(
        field(&value, &["schema"])?.text(),
        Some("fss.scene_feature_match_adopted.v1")
    );
    assert_eq!(
        field(&value, &["report", "analysis", "kind"])?.text(),
        Some("static_pair")
    );
    assert!(check_geometry(&value, false)? >= 8);
    check_sources(&f, &value)?;
    let path = f.base.options.report_out.as_ref().ok_or("output")?;
    assert_eq!(fs::read(path)?, stdout);
    let body = std::str::from_utf8(&stdout)?
        .trim_end()
        .strip_suffix('}')
        .ok_or("wrapper")?
        .split_once(",\"report\":")
        .ok_or("report body")?
        .1;
    assert_eq!(
        field(&value, &["report_digest"])?.text(),
        Some(h(body).to_text().as_str())
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
    }
    let cx = context(&f.base.options.root)?;
    let deployment = ReferenceDeployment::reopen(&f.base.options.root, &f.base.options.site, &cx)?;
    let retained = retained_adoptions(&deployment)?;
    assert!(retained.values().all(|history| history.len() == 1));
    assert_eq!(
        retained.len(),
        2,
        "reconstruction does not publish another adoption"
    );
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn adopted_three_camera_and_repeated_exposure_modes_reuse_real_source_owners() -> Test {
    let (multi, _) = super::super::multiview::tests::atlas_fixture_preview("adopted-three")?;
    let temporal = super::super::temporal::tests::fixture("adopted-temporal", false)?;
    for (base, kind, is_temporal) in [
        (multi, "static_multiview", false),
        (temporal, "temporal", true),
    ] {
        let f = AdoptedFixture::from_source(base, true)?;
        let (_, value) = execute_report(&f)?;
        assert_eq!(
            field(&value, &["report", "analysis", "kind"])?.text(),
            Some(kind)
        );
        assert!(check_geometry(&value, is_temporal)? >= 3);
        check_sources(&f, &value)?;
        assert_eq!(
            rows(
                &value,
                &["report", "analysis", "calibration", "selected_cameras"]
            )?
            .len(),
            if is_temporal { 2 } else { 3 }
        );
    }
    Ok(())
}

#[test]
fn missing_superseded_or_withdrawn_adoption_never_falls_back_to_authored_geometry() -> Test {
    for case in 0..3 {
        let mut f = AdoptedFixture::from_source(
            Fixture::new(&format!("adopted-currency-{case}"))?,
            case != 0,
        )?;
        if case != 0 {
            let cx = context(&f.base.options.root)?;
            let mut deployment =
                ReferenceDeployment::reopen(&f.base.options.root, &f.base.options.site, &cx)?;
            if case == 1 {
                let mut newer = f.calibration.clone();
                for (record, input) in newer.cameras.iter_mut().zip(&f.inputs) {
                    record.identity.extrinsics = 2;
                    let input = std::str::from_utf8(input)?.replace(
                        &format!("camera {} 1 1\n", record.identity.camera),
                        &format!("camera {} 1 2\n", record.identity.camera),
                    );
                    record.observations = h(input);
                }
                let subject = CalibrationSubject::from_calibration(&newer, newer.digest()?);
                let bindings: Vec<_> = newer
                    .cameras
                    .iter()
                    .enumerate()
                    .map(|(i, camera)| (camera.name.clone(), f.base.capsules[i].sensor_id.clone()))
                    .collect();
                let approval = preview_adoption(&deployment, &subject, &bindings)?.approval;
                adopt(&mut deployment, &subject, &bindings, approval, &cx)?;
            } else {
                let request = InvalidationRequest {
                    camera_handle: 1,
                    adoption_digest: f.adoptions[0],
                    reason: InvalidationReason::OwnerRevoked,
                    evidence: None,
                };
                let approval = preview_invalidation(&deployment, &request)?.approval;
                invalidate(&mut deployment, &request, approval, &cx)?;
            }
            drop(deployment);
            cx.drain_and_finalize();
            f.refresh_anchor()?;
        }
        f.refused()?;
        assert_eq!(
            f.base.head()?,
            f.base.head,
            "authority refusal precedes JPEG publication"
        );
    }
    Ok(())
}

#[test]
fn wrong_physical_sensor_image_mode_or_original_camera_input_refuses_the_complete_selection() -> Test
{
    for case in 0..4 {
        let mut f = AdoptedFixture::pair(&format!("adopted-binding-{case}"))?;
        match case {
            0 => {
                put(
                    &mut f.rig,
                    &["cameras", "0", "sensor_id"],
                    Value::Text("sensor:wrong-physical-device".into()),
                )?;
                f.save_rig()?;
            }
            1 => {
                put(
                    &mut f.base.document,
                    &["left", "image_domain_digest"],
                    Value::Text(h("wrong raw mode").to_text()),
                )?;
                let query = f.base.document.clone();
                f.base.set_query(&query)?;
            }
            2 => {
                fs::write(&f.input_paths[0], &f.inputs[1])?;
            }
            _ => {
                let Value::Object(row) = (match &mut f.rig {
                    Value::Object(top) => top
                        .get_mut("cameras")
                        .and_then(|value| match value {
                            Value::Array(rows) => rows.first_mut(),
                            _ => None,
                        })
                        .ok_or("camera row")?,
                    _ => return Err("rig".into()),
                }) else {
                    return Err("camera".into());
                };
                row.insert(
                    "world_to_camera".into(),
                    parse(r#"{"rotation":[[1,0,0],[0,1,0],[0,0,1]],"translation":[0,0,0]}"#)?,
                );
                f.save_rig()?;
            }
        }
        f.refused()?;
        assert_eq!(f.base.head()?, f.base.head);
    }
    Ok(())
}

#[test]
fn whole_file_and_semantic_calibration_pins_are_distinct_and_every_input_byte_is_bound() -> Test {
    for case in 0..3 {
        let mut f = AdoptedFixture::pair(&format!("adopted-calibration-pin-{case}"))?;
        let mut bytes = fs::read(&f.calibration_path)?;
        match case {
            0 => put(
                &mut f.rig,
                &["calibration", "digest"],
                Value::Text(h(&bytes).to_text()),
            )?,
            1 => put(
                &mut f.rig,
                &["calibration", "file_digest"],
                Value::Text(f.calibration.digest()?.to_text()),
            )?,
            _ => {
                bytes[20] ^= 1;
                fs::write(&f.calibration_path, &bytes)?;
                // Rehashing the complete file cannot replace its canonical semantic identity.
                put(
                    &mut f.rig,
                    &["calibration", "file_digest"],
                    Value::Text(h(&bytes).to_text()),
                )?;
            }
        }
        f.save_rig()?;
        f.refused()?;
        assert_eq!(f.base.head()?, f.base.head);
    }
    Ok(())
}

#[test]
fn retained_adoption_and_original_frame_custody_remain_required_and_current_privacy_wins() -> Test {
    for authority in [false, true] {
        let f = AdoptedFixture::pair(if authority {
            "adopted-authority-custody"
        } else {
            "adopted-source-custody"
        })?;
        let cx = context(&f.base.options.root)?;
        let deployment =
            ReferenceDeployment::reopen(&f.base.options.root, &f.base.options.site, &cx)?;
        let digest = if authority {
            f.adoptions[0]
        } else {
            let source = RetainedFileImport::open(
                &deployment,
                f.base.imports[0],
                RetainedReadLimits::default(),
                &cx,
            )?;
            source.manifest().ordered_chunks[0]
        };
        fs::remove_file(deployment.publisher().spool().object_path(digest))?;
        drop(deployment);
        cx.drain_and_finalize();
        f.refused()?;
    }
    let mut f = AdoptedFixture::pair("adopted-current-privacy")?;
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
    let mut stdout = Vec::new();
    assert!(!checked(execute(&f.base.options, &mut stdout))?);
    let value = parse_report(std::str::from_utf8(&stdout)?)?;
    assert_eq!(
        field(&value, &["report", "analysis", "outcome"])?.text(),
        Some("no_reconstruction")
    );
    assert_eq!(
        field(&value, &["report", "analysis", "counts", "solved"])?.integer(),
        Some(0)
    );
    let first = rows(&value, &["report", "analysis", "views"])?
        .iter()
        .find(|row| field(row, &["view", "camera"]).ok().and_then(Value::text) == Some("1"))
        .ok_or("first camera")?;
    assert!(rows(first, &["view", "features"])?.is_empty());
    Ok(())
}

#[test]
fn work_deadline_anchor_and_output_limits_refuse_without_publishing_partial_reports() -> Test {
    let f = AdoptedFixture::pair("adopted-cancel")?;
    let cx = context(&f.base.options.root)?;
    cx.request_cancellation();
    assert!(analyze(&f.base.options, &f.base.options.root, &cx).is_err());
    cx.drain_and_finalize();
    assert_eq!(f.base.head()?, f.base.head);
    for case in 0..4 {
        let mut f = AdoptedFixture::pair(&format!("adopted-limit-{case}"))?;
        match case {
            0 => f.base.options.work = 1,
            1 => f.base.options.timeout = Duration::ZERO,
            2 => f.base.options.expected_anchor = Some(h("wrong adopted selection entry anchor")),
            _ => f.base.options.report_bytes = 1024,
        }
        f.refused()?;
        if case < 3 {
            assert_eq!(f.base.head()?, f.base.head);
        }
        // A late report bound may leave complete retained JPEG derivatives, never a report prefix.
    }
    Ok(())
}

#[test]
fn adopted_command_options_and_create_only_report_files_preserve_existing_bytes() -> Test {
    let f = AdoptedFixture::pair("adopted-output-exclusive")?;
    let arguments = vec![
        OsString::from("--root"),
        f.base.options.root.as_os_str().to_owned(),
        OsString::from("--site"),
        f.base.options.site.clone().into(),
        OsString::from("--twin"),
        f.base.options.twin.as_os_str().to_owned(),
        OsString::from("--rig"),
        f.base.options.rig.as_os_str().to_owned(),
        OsString::from("--query"),
        f.base.options.query.as_os_str().to_owned(),
    ];
    let parsed = checked(options(&arguments))?.ok_or("options")?;
    assert_eq!(parsed.work, WORK);
    assert_eq!(parsed.report_bytes, OUTPUT);
    for extra in [
        vec!["--work-units", "16000000001"],
        vec!["--max-report-bytes", "33554433"],
        vec!["--camera", "1"],
        vec!["--work-units", "1", "--work-units", "2"],
    ] {
        let mut invalid = arguments.clone();
        invalid.extend(extra.into_iter().map(OsString::from));
        assert!(options(&invalid).is_err());
    }
    let path = f.base.options.report_out.as_ref().ok_or("report path")?;
    let sentinel = b"existing report must survive";
    fs::write(path, sentinel)?;
    let mut stdout = Vec::new();
    assert!(execute(&f.base.options, &mut stdout).is_err());
    assert!(stdout.is_empty());
    assert_eq!(fs::read(path)?, sentinel);
    assert_eq!(f.base.head()?, f.base.head);
    #[cfg(unix)]
    {
        fs::remove_file(path)?;
        let target = f.base.directory().join("adopted-output-sentinel");
        fs::write(&target, sentinel)?;
        std::os::unix::fs::symlink(&target, path)?;
        assert!(execute(&f.base.options, &mut stdout).is_err());
        assert!(stdout.is_empty());
        assert_eq!(fs::read(target)?, sentinel);
        assert!(fs::symlink_metadata(path)?.file_type().is_symlink());
        assert_eq!(f.base.head()?, f.base.head);
    }
    struct RefuseStdout;
    impl std::io::Write for RefuseStdout {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("closed synthetic stdout"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let failed_stdout = AdoptedFixture::pair("adopted-stdout-failure")?;
    assert!(execute(&failed_stdout.base.options, &mut RefuseStdout).is_err());
    let completed = fs::read(
        failed_stdout
            .base
            .options
            .report_out
            .as_ref()
            .ok_or("report path")?,
    )?;
    assert!(completed.ends_with(b"\n"));
    let value = parse_report(std::str::from_utf8(&completed)?)?;
    assert!(check_geometry(&value, false)? >= 8);
    Ok(())
}

#[test]
fn current_deployment_authority_stays_locked_until_stdout_release_finishes() -> Test {
    struct GuardedStdout<'a> {
        root: &'a std::path::Path,
        site: &'a str,
        cx: &'a ReplayCx,
        bytes: Vec<u8>,
        locked_writes: usize,
    }
    impl std::io::Write for GuardedStdout<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            // This is a genuine, nonblocking competing deployment open on the same thread.
            // It would succeed if analyze dropped its authority guard before execute wrote.
            match ReferenceDeployment::reopen(self.root, self.site, self.cx) {
                Err(fss_reference::ReferenceError::DeploymentLocked { .. }) => {
                    self.locked_writes += 1;
                }
                Ok(_) => {
                    return Err(std::io::Error::other(
                        "deployment authority was released before stdout completed",
                    ));
                }
                Err(error) => {
                    return Err(std::io::Error::other(format!(
                        "competing deployment open failed for a different reason: {error}"
                    )));
                }
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let f = AdoptedFixture::pair("adopted-release-guard")?;
    let cx = context(&f.base.options.root)?;
    let mut stdout = GuardedStdout {
        root: &f.base.options.root,
        site: &f.base.options.site,
        cx: &cx,
        bytes: Vec::new(),
        locked_writes: 0,
    };
    assert!(checked(execute(&f.base.options, &mut stdout))?);
    assert!(stdout.locked_writes > 0);
    assert!(stdout.bytes.ends_with(b"\n"));
    let value = parse_report(std::str::from_utf8(&stdout.bytes)?)?;
    assert_eq!(
        field(&value, &["report", "analysis", "outcome"])?.text(),
        Some("reconstructed")
    );
    assert!(check_geometry(&value, false)? >= 8);
    check_sources(&f, &value)?;
    assert_eq!(
        fs::read(f.base.options.report_out.as_ref().ok_or("report path")?)?,
        stdout.bytes
    );

    // execute must release its guard on completion; the report does not grant a lasting lease.
    let reopened = ReferenceDeployment::reopen(&f.base.options.root, &f.base.options.site, &cx)?;
    let current = retained_adoptions(&reopened)?;
    assert_eq!(current.len(), 2);
    assert!(current.values().all(|history| history.len() == 1));
    drop(reopened);
    cx.drain_and_finalize();
    Ok(())
}
