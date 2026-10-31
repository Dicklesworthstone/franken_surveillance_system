#![forbid(unsafe_code)]
//! Synthetic public binding shapes exercise the exact transform and native solvers only.
//! They do not construct a sealed source owner or establish authenticated custody.

use super::*;
use fss_cli::retained_handoff_contract::{PackageClockAlignment, PackageHandoffTracking};
use fss_core::{ClockBasis, LedgerAnchor};
use fss_geometry::{GeometryBasis, WorkBudget};
use fss_twin::multiview::{CommonPointMotion, FusionError, FusionRequest, fuse_scene_point};
use fss_twin::multiview_motion::{MotionFusionRequest, fuse_scene_motion};
use fss_twin::{ImportExpectation, ImportLimits, PropertyTwin, import_twin};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const REFERENCE: u64 = 1_500_000_000;
const POSITION: [f64; 3] = [0.3, 0.2, 6.0];
const VELOCITY: [f64; 3] = [1.0, -0.25, 0.5];
const CENTERS: [[f64; 3]; 3] = [[-2.0, 0.0, 0.0], [2.0, 0.0, 0.0], [0.0, 2.0, 0.0]];

fn h(value: impl AsRef<[u8]>) -> ContentDigest {
    ContentDigest::sha256(value.as_ref())
}
fn d(value: ContentDigest) -> String {
    string(&value.to_text())
}
fn vector<const N: usize>(value: [f64; N]) -> String {
    array(&value.map(|v| v.to_string()))
}
fn checked<T>(result: Result<T>) -> TestResult<T> {
    result.map_err(|e| format!("{e:?}").into())
}

fn value_mut<'a>(value: &'a mut Value, path: &[&str]) -> TestResult<&'a mut Value> {
    if path.is_empty() {
        return Ok(value);
    }
    let next = match value {
        Value::Object(values) => values.get_mut(path[0]).ok_or("fixture field")?,
        Value::Array(values) => values
            .get_mut(path[0].parse::<usize>()?)
            .ok_or("fixture item")?,
        _ => return Err("fixture container".into()),
    };
    value_mut(next, &path[1..])
}
fn set(value: &mut Value, path: &[&str], replacement: Value) -> TestResult {
    *value_mut(value, path)? = replacement;
    Ok(())
}
fn map_mut(value: &mut Value) -> TestResult<&mut BTreeMap<String, Value>> {
    if let Value::Object(value) = value {
        Ok(value)
    } else {
        Err("fixture object".into())
    }
}
fn list_mut(value: &mut Value) -> TestResult<&mut Vec<Value>> {
    if let Value::Array(value) = value {
        Ok(value)
    } else {
        Err("fixture array".into())
    }
}

fn package() -> Vec<u8> {
    fn text(out: &mut Vec<u8>, value: &str) {
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    let mut body = h("synthetic retained fusion scene").bytes().to_vec();
    text(&mut body, "retained_fusion_fixture");
    text(&mut body, "fixture_epoch");
    body.push(0);
    for n in [0.0_f64, -1.0, -1.0] {
        body.extend_from_slice(&n.to_le_bytes());
    }
    for n in [1_u32, 1, 3, 1] {
        body.extend_from_slice(&n.to_le_bytes());
    }
    text(&mut body, "background");
    body.push(5);
    text(&mut body, "background");
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&[0, 0]);
    for point in [
        [-10.0_f64, -10.0, 20.0],
        [10.0, -10.0, 20.0],
        [0.0, 10.0, 20.0],
    ] {
        for n in point {
            body.extend_from_slice(&n.to_le_bytes());
        }
    }
    for n in [0_u32, 1, 2, 0] {
        body.extend_from_slice(&n.to_le_bytes());
    }
    let mut bytes = b"FSSTWIN1".to_vec();
    bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
    bytes.extend(body);
    bytes.extend_from_slice(&h(&bytes).bytes());
    bytes
}

struct Fixture {
    twin: PropertyTwin,
    rig: SceneRig,
    rig_digest: ContentDigest,
    document: Value,
    bindings: Vec<PackageHandoffBinding>,
}
impl Fixture {
    fn new(moving: bool) -> TestResult<Self> {
        let bytes = package();
        let twin = import_twin(
            &bytes,
            ImportExpectation {
                package_sha256: h(&bytes).bytes(),
                source_scene_sha256: h("synthetic retained fusion scene").bytes(),
                basis: GeometryBasis::new(7, 2)?,
            },
            ImportLimits::default(),
            &mut WorkBudget::new(10_000_000),
        )?;
        let mut cameras = Vec::new();
        let mut mappings = Vec::new();
        let mut selections = Vec::new();
        let mut features = Vec::new();
        let mut bindings = Vec::new();
        for (index, center) in CENTERS.into_iter().enumerate() {
            let camera = index + 1;
            let alias = format!("selected-{camera}");
            let sensor_id = format!("sensor:fixture-{camera}");
            let stream_id = format!("stream:fixture-{camera}:g1");
            let camera_generation = camera_generation(&sensor_id, &stream_id, [640, 480])?;
            let calibration = h(format!("calibration-{camera}"));
            let report_digest = h(format!("report-{camera}"));
            let track = h(format!("native-track-{camera}"));
            let alignment = PackageClockAlignment {
                import_identity: h(format!("import-{camera}")),
                stream_id: stream_id.clone(),
                clock_basis: ClockBasis::Estimated,
                offset_ns: [0, 0],
                basis: h(format!("alignment-{camera}")),
            };
            let tracking = PackageHandoffTracking {
                confirmation_hits: 1,
                maximum_missed_frames: 1,
                minimum_iou_ppm: 0,
            };
            cameras.push(object(&[
                ("camera", camera.to_string()),
                ("calibration", "1".into()),
                ("image_domain", "1".into()),
                ("clock", "11".into()),
                ("privacy_domain", "9".into()),
                ("validity_ns", format!("[0,{}]", u64::MAX)),
                (
                    "source_object_id",
                    string(&format!("fixture-camera-{camera}")),
                ),
                ("image_model", string("undistorted_pinhole")),
                ("status", string("authored_nominal")),
                ("error", "null".into()),
                (
                    "world_to_camera",
                    object(&[
                        ("rotation", "[[1,0,0],[0,1,0],[0,0,1]]".into()),
                        ("translation", vector(center.map(|v| -v))),
                    ]),
                ),
                (
                    "intrinsics",
                    r#"{"width":640,"height":480,"fx":400,"fy":400,"cx":320,"cy":240}"#.into(),
                ),
            ]));
            mappings.push(object(&[
                ("selection", string(&alias)),
                ("camera", camera.to_string()),
                ("camera_generation", d(camera_generation)),
                ("calibration", d(calibration)),
                ("image_domain", "1".into()),
                ("mapping_basis", d(h(format!("map-{camera}")))),
                (
                    "image_domain_basis",
                    d(h(format!("undistorted-source-{camera}"))),
                ),
            ]));
            selections.push(object(&[
                ("id", string(&alias)),
                ("report_digest", d(report_digest)),
                ("label", string("marker")),
                ("track", d(track)),
                ("calibration", d(calibration)),
                (
                    "tracking",
                    r#"{"confirmation_hits":1,"maximum_missed_frames":1,"minimum_iou_ppm":0}"#
                        .into(),
                ),
                (
                    "alignment",
                    object(&[
                        ("import_identity", d(alignment.import_identity)),
                        ("stream_id", string(&stream_id)),
                        ("clock_basis", string("estimated")),
                        ("offset_ns", "[0,0]".into()),
                        ("basis", d(alignment.basis)),
                    ]),
                ),
            ]));
            let times = if moving {
                vec![1_000_000_000, 2_000_000_000]
            } else {
                vec![REFERENCE]
            };
            let mut observations = Vec::new();
            for (segment, time) in times.into_iter().enumerate() {
                let dt = (i128::from(time) - i128::from(REFERENCE)) as f64 * 1e-9;
                let p = std::array::from_fn::<_, 3, _>(|i| {
                    POSITION[i] + if moving { dt * VELOCITY[i] } else { 0.0 }
                });
                let pixel = [
                    320.0 + 400.0 * (p[0] - center[0]) / p[2],
                    240.0 + 400.0 * (p[1] - center[1]) / p[2],
                ];
                let capsule_digest = h(format!("capsule-{camera}-{segment}"));
                features.push(object(&[
                    ("selection", string(&alias)),
                    ("segment", segment.to_string()),
                    ("detection_row", "0".into()),
                    ("capsule_digest", d(capsule_digest)),
                    ("pixel_min", vector(pixel)),
                    ("pixel_max", vector(pixel)),
                    ("visible_contact", "true".into()),
                    ("sigma_pixels", "0.5".into()),
                    ("contact_basis", d(h(format!("feature-{camera}-{segment}")))),
                ]));
                observations.push(PackageHandoffObservation {
                    segment: segment as u64,
                    capsule_digest,
                    source_digest: h(format!("source-{camera}-{segment}")),
                    capture: [i128::from(time); 2],
                    aligned_capture: [time as i64; 2],
                    detection_row: 0,
                    class_index: 0,
                    score_bits: 0.75_f32.to_bits(),
                    bounds: [
                        ((pixel[0] - 1.0) * 256.0).floor() as u32,
                        ((pixel[1] - 1.0) * 256.0).floor() as u32,
                        ((pixel[0] + 1.0) * 256.0).ceil() as u32,
                        ((pixel[1] + 1.0) * 256.0).ceil() as u32,
                    ],
                    inference_identity: h(format!("inference-{camera}-{segment}")),
                    output_digest: h(format!("output-{camera}-{segment}")),
                    detection_report_digest: h(format!("head-{camera}-{segment}")),
                    confirmed: true,
                });
            }
            bindings.push(PackageHandoffBinding {
                id: alias,
                report_digest,
                analysis_digest: h(format!("analysis-{camera}")),
                record_digest: h(format!("record-{camera}")),
                retained_root: h(format!("retained-root-{camera}")),
                import_identity: alignment.import_identity,
                import_root: h(format!("import-root-{camera}")),
                retained_anchor: LedgerAnchor::genesis("site:retained-fusion-fixture"),
                track,
                sensor_id,
                stream_id,
                clock_basis: ClockBasis::Estimated,
                capture_time_label: "operator_assumption".into(),
                dimensions: [640, 480],
                camera_generation,
                calibration,
                model: h("comparison-space"),
                package_digest: h("package"),
                manifest_digest: h("manifest"),
                model_digest: h("model"),
                graph_digest: h("graph"),
                contract_digest: h("head"),
                model_id: "MOD-SYNTHETIC-FEATURE".into(),
                model_generation: "model:fixture:g1".into(),
                label: "marker".into(),
                class_index: 0,
                tracking,
                privacy_binding: h("privacy-unmasked-fixture"),
                privacy_policy: None,
                alignment,
                observations,
                confirmed: true,
            });
        }
        let rig_text = object(&[
            ("schema", string("fss.scene_camera_rig.v1")),
            (
                "source_scene_digest",
                d(h("synthetic retained fusion scene")),
            ),
            ("twin_digest", d(h(&bytes))),
            ("geometry_basis", r#"{"property":7,"revision":2}"#.into()),
            ("coordinate_frame", string("RH_Z_UP")),
            ("evaluation_scope", string("retained_fusion_fixture")),
            ("cameras", array(&cameras)),
        ]);
        let rig_digest = h(&rig_text);
        let rig = SceneRig::from_document(
            &json_input::parse(&rig_text)?,
            &twin,
            &mut WorkBudget::new(10_000_000),
        )?;
        let text = object(&[
            ("schema", string(SCHEMA)),
            ("session", string("scene:fixture")),
            ("generation", d(h("generation"))),
            ("clock_evidence", d(h("common-clock"))),
            ("camera_rig_digest", d(rig_digest)),
            ("privacy_domain", "9".into()),
            ("clock", "11".into()),
            ("reference_time_ns", REFERENCE.to_string()),
            ("selections", array(&selections)),
            ("camera_bindings", array(&mappings)),
            (
                "hypotheses",
                array(&[object(&[
                    ("id", string("common-feature")),
                    ("association_evidence", d(h("correspondence"))),
                    ("max_capture_span_ns", "1000000000".into()),
                    (
                        "motion",
                        if moving {
                            r#"{"kind":"infer_linear","max_capture_uncertainty_ns":0}"#.into()
                        } else {
                            r#"{"kind":"static"}"#.into()
                        },
                    ),
                    ("observations", array(&features)),
                ])]),
            ),
        ]);
        Ok(Self {
            twin,
            rig,
            rig_digest,
            document: json_input::parse(&text)?,
            bindings,
        })
    }
    fn parse(&self) -> TestResult<Parsed> {
        checked(parse(
            json(&self.document).as_bytes(),
            self.rig_digest,
            &self.rig,
        ))
    }
    fn query(&self) -> TestResult<Query> {
        checked(build_query(&self.parse()?, &self.bindings, &self.rig))
    }
}

fn point(
    fixture: &Fixture,
    query: &Query,
) -> TestResult<std::result::Result<fss_twin::multiview::FusedScenePoint, FusionError>> {
    let h = query.hypotheses.first().ok_or("hypothesis")?;
    let Motion::Static(options) = h.motion else {
        return Err("static hypothesis required".into());
    };
    Ok(fuse_scene_point(
        &fixture.twin,
        &h.observations.iter().map(|o| o.input).collect::<Vec<_>>(),
        FusionRequest {
            association_evidence: h.association_evidence.bytes(),
            privacy_domain: query.privacy_domain,
            reference_time_ns: query.reference_time_ns,
            max_capture_span_ns: h.max_capture_span_ns,
            motion: CommonPointMotion::Static,
            triangulation: options,
        },
        &mut WorkBudget::new(100_000_000),
    ))
}

#[test]
fn retained_feature_transform_drives_native_three_camera_reconstruction() -> TestResult {
    let fixture = Fixture::new(false)?;
    let parsed = fixture.parse()?;
    assert!(parsed.request.transitions.is_empty());
    let query = checked(build_query(&parsed, &fixture.bindings, &fixture.rig))?;
    let result = point(&fixture, &query)??;
    for (actual, expected) in result.estimate().position.into_iter().zip(POSITION) {
        assert!((actual - expected).abs() < 1e-9);
    }
    assert_eq!(result.inputs().len(), 3);
    for (index, observation) in query.hypotheses[0].observations.iter().enumerate() {
        assert_eq!(
            observation.source_digest,
            fixture.bindings[index].observations[0].source_digest
        );
        assert_eq!(observation.input.observation.capture, [REFERENCE; 2]);
        assert_eq!(observation.input.observation.track, index as u64 + 1);
        assert_eq!(observation.input.observation.exposure, 1);
        assert_ne!(observation.input.observation.evidence, [0; 32]);
    }
    assert_eq!(
        json_input::parse(parsed.declarations_json())?,
        fixture.document
    );
    assert_eq!(
        json_input::parse(&parsed.track_aliases_json())?
            .array()
            .ok_or("aliases")?
            .len(),
        3
    );
    Ok(())
}

#[test]
fn actual_staggered_observations_drive_native_position_and_velocity_fit() -> TestResult {
    let fixture = Fixture::new(true)?;
    let query = fixture.query()?;
    let h = &query.hypotheses[0];
    let Motion::InferLinear {
        max_capture_uncertainty_ns,
        options,
    } = h.motion
    else {
        return Err("motion profile".into());
    };
    let result = fuse_scene_motion(
        &fixture.twin,
        &h.observations.iter().map(|o| o.input).collect::<Vec<_>>(),
        MotionFusionRequest {
            association_evidence: h.association_evidence.bytes(),
            privacy_domain: query.privacy_domain,
            reference_time_ns: query.reference_time_ns,
            max_capture_span_ns: h.max_capture_span_ns,
            max_capture_uncertainty_ns,
            triangulation: options,
        },
        &mut WorkBudget::new(100_000_000),
    )?;
    for (actual, expected) in result.estimate().position.into_iter().zip(POSITION) {
        assert!((actual - expected).abs() < 1e-8);
    }
    for (actual, expected) in result
        .estimate()
        .velocity_per_second
        .into_iter()
        .zip(VELOCITY)
    {
        assert!((actual - expected).abs() < 1e-8);
    }
    assert_eq!(result.inputs().len(), 6);
    Ok(())
}

#[test]
fn reorder_does_not_change_native_aliases_or_source_feature_identities() -> TestResult {
    let mut fixture = Fixture::new(true)?;
    let before = fixture.query()?;
    for path in [
        &["selections"][..],
        &["camera_bindings"],
        &["hypotheses", "0", "observations"],
    ] {
        list_mut(value_mut(&mut fixture.document, path)?)?.reverse();
    }
    fixture.bindings.reverse();
    let after = fixture.query()?;
    for (before, after) in before.hypotheses[0]
        .observations
        .iter()
        .zip(&after.hypotheses[0].observations)
    {
        assert_eq!(before.input, after.input);
        assert_eq!(before.source_digest, after.source_digest);
    }
    Ok(())
}

#[test]
fn caller_cannot_replace_source_facts_or_supply_unbound_image_or_clock_fields() -> TestResult {
    for key in [
        "source_digest",
        "capture_ns",
        "track",
        "exposure",
        "evidence_digest",
        "source_path",
        "model",
    ] {
        let mut fixture = Fixture::new(false)?;
        map_mut(value_mut(
            &mut fixture.document,
            &["hypotheses", "0", "observations", "0"],
        )?)?
        .insert(key.into(), Value::Null);
        assert!(fixture.parse().is_err(), "accepted injected {key}");
    }
    for (path, replacement) in [
        (
            &["camera_bindings", "0", "image_domain"][..],
            Value::Number("99".into()),
        ),
        (
            &["camera_bindings", "0", "calibration"][..],
            Value::Text(h("wrong calibration").to_text()),
        ),
        (&["clock"][..], Value::Number("12".into())),
        (&["privacy_domain"][..], Value::Number("10".into())),
        (
            &["camera_rig_digest"][..],
            Value::Text(h("wrong rig").to_text()),
        ),
    ] {
        let mut fixture = Fixture::new(false)?;
        set(&mut fixture.document, path, replacement)?;
        assert!(fixture.parse().is_err());
    }
    Ok(())
}

#[test]
fn exact_detector_row_and_capsule_pins_are_checked_before_geometry() -> TestResult {
    for (key, replacement) in [
        ("segment", Value::Number("1".into())),
        ("detection_row", Value::Number("1".into())),
        ("capsule_digest", Value::Text(h("wrong capsule").to_text())),
    ] {
        let mut fixture = Fixture::new(false)?;
        set(
            &mut fixture.document,
            &["hypotheses", "0", "observations", "0", key],
            replacement,
        )?;
        assert!(fixture.query().is_err());
    }
    let mut fixture = Fixture::new(false)?;
    let duplicate = fixture.bindings[0].observations[0].clone();
    fixture.bindings[0].observations.push(duplicate);
    assert!(fixture.query().is_err());
    Ok(())
}

#[test]
fn contact_must_stay_inside_actual_source_grid_detector_bounds() -> TestResult {
    let mut fixture = Fixture::new(false)?;
    set(
        &mut fixture.document,
        &["hypotheses", "0", "observations", "0", "pixel_min"],
        Value::Array(vec![Value::Number("0".into()), Value::Number("0".into())]),
    )?;
    assert!(fixture.parse().is_ok());
    assert!(fixture.query().is_err());
    let mut fixture = Fixture::new(false)?;
    fixture.bindings[0].dimensions[0] = 320;
    assert!(fixture.query().is_err());
    let mut fixture = Fixture::new(false)?;
    fixture.bindings[0].camera_generation = h("different source generation");
    assert!(fixture.query().is_err());
    Ok(())
}

#[test]
fn full_capture_uncertainty_survives_and_unrepresentable_clock_alignment_refuses() -> TestResult {
    let mut fixture = Fixture::new(false)?;
    fixture.bindings[0].observations[0].capture =
        [i128::from(REFERENCE) - 5, i128::from(REFERENCE) + 7];
    fixture.bindings[0].observations[0].aligned_capture =
        [REFERENCE as i64 - 5, REFERENCE as i64 + 7];
    let query = fixture.query()?;
    assert_eq!(
        query.hypotheses[0].observations[0]
            .input
            .observation
            .capture,
        [REFERENCE - 5, REFERENCE + 7]
    );
    fixture.bindings[0].observations[0].aligned_capture = [REFERENCE as i64; 2];
    assert!(fixture.query().is_err());
    fixture.bindings[0].observations[0].capture = [-1, 0];
    fixture.bindings[0].observations[0].aligned_capture = [-1, 0];
    assert!(fixture.query().is_err());
    fixture.bindings[0].observations[0].capture = [i128::MAX; 2];
    assert!(fixture.query().is_err());
    Ok(())
}

#[test]
fn one_source_sensor_cannot_be_counted_as_two_scene_cameras() -> TestResult {
    let mut fixture = Fixture::new(false)?;
    fixture.bindings[1].sensor_id = fixture.bindings[0].sensor_id.clone();
    let generation = camera_generation(
        &fixture.bindings[1].sensor_id,
        &fixture.bindings[1].stream_id,
        [640, 480],
    )?;
    fixture.bindings[1].camera_generation = generation;
    set(
        &mut fixture.document,
        &["camera_bindings", "1", "camera_generation"],
        Value::Text(generation.to_text()),
    )?;
    assert!(fixture.query().is_err());
    Ok(())
}

#[test]
fn invisible_contact_stays_an_explicit_native_refusal() -> TestResult {
    let mut fixture = Fixture::new(false)?;
    set(
        &mut fixture.document,
        &["hypotheses", "0", "observations", "0", "visible_contact"],
        Value::Bool(false),
    )?;
    let query = fixture.query()?;
    assert_eq!(query.hypotheses[0].observations.len(), 3);
    assert!(matches!(
        point(&fixture, &query)?,
        Err(FusionError::ContactUnknown)
    ));
    Ok(())
}

#[test]
fn feature_and_image_applicability_assumptions_are_bound_into_observation_identity() -> TestResult {
    let mut fixture = Fixture::new(false)?;
    let original = fixture.query()?.hypotheses[0].observations[0]
        .input
        .observation
        .evidence;
    set(
        &mut fixture.document,
        &["hypotheses", "0", "observations", "0", "contact_basis"],
        Value::Text(h("new feature assumption").to_text()),
    )?;
    assert_ne!(
        fixture.query()?.hypotheses[0].observations[0]
            .input
            .observation
            .evidence,
        original
    );
    let mut fixture = Fixture::new(false)?;
    set(
        &mut fixture.document,
        &["camera_bindings", "0", "image_domain_basis"],
        Value::Text(h("new image assumption").to_text()),
    )?;
    assert_ne!(
        fixture.query()?.hypotheses[0].observations[0]
            .input
            .observation
            .evidence,
        original
    );
    let mut fixture = Fixture::new(false)?;
    set(
        &mut fixture.document,
        &["clock_evidence"],
        Value::Text(h("new common clock assumption").to_text()),
    )?;
    assert_ne!(
        fixture.query()?.hypotheses[0].observations[0]
            .input
            .observation
            .evidence,
        original
    );
    Ok(())
}

#[test]
fn parser_refuses_duplicate_unknown_unused_and_coercive_selection_input() -> TestResult {
    for spelling in ["-0", "01", "+1", "1e0", "1.0"] {
        let mut fixture = Fixture::new(false)?;
        set(
            &mut fixture.document,
            &["reference_time_ns"],
            Value::Text(spelling.into()),
        )?;
        assert!(fixture.parse().is_err());
    }
    let mut fixture = Fixture::new(false)?;
    list_mut(value_mut(
        &mut fixture.document,
        &["hypotheses", "0", "observations"],
    )?)?
    .remove(0);
    assert!(fixture.parse().is_err());
    let mut fixture = Fixture::new(false)?;
    let features = list_mut(value_mut(
        &mut fixture.document,
        &["hypotheses", "0", "observations"],
    )?)?;
    features.push(features[0].clone());
    assert!(fixture.parse().is_err());
    let fixture = Fixture::new(false)?;
    assert!(
        parse(
            &vec![b' '; json_input::MAX_INPUT_BYTES + 1],
            fixture.rig_digest,
            &fixture.rig
        )
        .is_err()
    );
    let text = json(&fixture.document);
    let duplicate = text.replacen('{', "{\"schema\":\"duplicate\",", 1);
    assert!(parse(duplicate.as_bytes(), fixture.rig_digest, &fixture.rig).is_err());
    Ok(())
}
