#![forbid(unsafe_code)]
//! Synthetic source snapshots test the pure adapter and real geometry only.
//! They do not construct a sealed source owner or authenticate retained custody.

use super::*;
use fss_core::{CapsuleId, CaptureInterval, SensorSourceBytesSpec, TimestampNs};
use fss_geometry::{GeometryBasis, WorkBudget};
use fss_twin::feature_association::{FeatureHypothesisOutcome, associate_features};
use fss_twin::localization::{BinaryDescriptor, ImageFeature, ImageIdentity};
use fss_twin::{ImportExpectation, ImportLimits, PropertyTwin, import_twin};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn h(value: impl AsRef<[u8]>) -> ContentDigest {
    ContentDigest::sha256(value.as_ref())
}
fn pin(value: impl AsRef<[u8]>) -> String {
    string(&h(value).to_text())
}
fn checked<T>(value: Result<T>) -> TestResult<T> {
    value.map_err(|error| format!("{error:?}").into())
}
fn at_mut<'a>(value: &'a mut Value, path: &[&str]) -> TestResult<&'a mut Value> {
    let Some((key, rest)) = path.split_first() else {
        return Ok(value);
    };
    let Value::Object(values) = value else {
        return Err("fixture object".into());
    };
    at_mut(values.get_mut(*key).ok_or("fixture key")?, rest)
}
fn edit(document: &Value, path: &[&str], value: Value) -> TestResult<String> {
    let mut document = document.clone();
    *at_mut(&mut document, path)? = value;
    Ok(json(&document))
}
fn number(value: impl ToString) -> Value {
    Value::Number(value.to_string())
}
fn text_value(value: impl Into<String>) -> Value {
    Value::Text(value.into())
}

fn package() -> Vec<u8> {
    fn text(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend_from_slice(&(value.len() as u16).to_le_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    let mut body = h("retained match binding fixture").bytes().to_vec();
    text(&mut body, "retained_match_binding");
    text(&mut body, "synthetic_epoch");
    body.push(0);
    for value in [0.0_f64, -1.0, -1.0] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    for value in [1_u32, 1, 3, 1] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    text(&mut body, "background");
    body.push(5);
    text(&mut body, "background");
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&[0, 1]);
    for point in [
        [-10.0_f64, -10.0, 20.0],
        [10.0, -10.0, 20.0],
        [0.0, 10.0, 20.0],
    ] {
        for value in point {
            body.extend_from_slice(&value.to_le_bytes());
        }
    }
    for value in [0_u32, 1, 2, 0] {
        body.extend_from_slice(&value.to_le_bytes());
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
    rig_document: Value,
    rig_digest: ContentDigest,
    document: Value,
    capsules: [SensorCapsule; 2],
    frames: [FeatureFrame; 2],
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let bytes = package();
        let twin = import_twin(
            &bytes,
            ImportExpectation {
                package_sha256: h(&bytes).bytes(),
                source_scene_sha256: h("retained match binding fixture").bytes(),
                basis: GeometryBasis::new(7, 2)?,
            },
            ImportLimits::default(),
            &mut WorkBudget::new(10_000_000),
        )?;
        let camera = |id: u64| {
            object(&[
                ("camera", id.to_string()),
                ("calibration", "1".into()),
                ("image_domain", id.to_string()),
                ("clock", "11".into()),
                ("privacy_domain", "9".into()),
                ("validity_ns", "[0,2000]".into()),
                (
                    "source_object_id",
                    string(&format!("synthetic_camera_{id}")),
                ),
                ("image_model", string("undistorted_pinhole")),
                ("status", string("authored_nominal")),
                ("error", "null".into()),
                (
                    "world_to_camera",
                    format!(
                        r#"{{"rotation":[[1,0,0],[0,1,0],[0,0,1]],"translation":[{},0,0]}}"#,
                        1_i64 - id as i64
                    ),
                ),
                (
                    "intrinsics",
                    r#"{"width":640,"height":480,"fx":400,"fy":400,"cx":320,"cy":240}"#.into(),
                ),
            ])
        };
        let rig_text = object(&[
            ("schema", string("fss.scene_camera_rig.v1")),
            ("source_scene_digest", pin("retained match binding fixture")),
            ("twin_digest", string(&h(&bytes).to_text())),
            ("geometry_basis", r#"{"property":7,"revision":2}"#.into()),
            ("coordinate_frame", string("RH_Z_UP")),
            ("evaluation_scope", string("retained_match_binding")),
            ("cameras", array(&[camera(1), camera(2)])),
        ]);
        let rig_digest = h(&rig_text);
        let rig_document = json_input::parse(&rig_text)?;
        let rig = SceneRig::from_document(&rig_document, &twin, &mut WorkBudget::new(1_000_000))?;
        let capsule = |id: u64, capture: [i128; 2]| -> TestResult<SensorCapsule> {
            Ok(SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
                capsule_id: CapsuleId::parse(format!("capsule:retained-match-{id}"))?,
                sensor_id: SensorId::parse(format!("sensor:retained-match-{id}"))?,
                stream_id: StreamId::parse(format!("stream:retained-match-{id}:g1"))?,
                sequence: id + 20,
                capture: CaptureInterval::new(TimestampNs(capture[0]), TimestampNs(capture[1]))?,
                receive_time: TimestampNs(1500),
                clock_basis: ClockBasis::DeviceMonotonic,
                source: format!("independent synthetic encoded source {id}").as_bytes(),
                frame_count: 1,
                gap_before: false,
            })?)
        };
        let capsules = [capsule(1, [1000, 1010])?, capsule(2, [980, 1020])?];
        let view = |index: usize| -> TestResult<String> {
            let id = index + 1;
            let capsule = &capsules[index];
            Ok(object(&[
                ("camera", id.to_string()),
                ("image_domain_digest", pin(format!("image-domain-{id}"))),
                ("mapping_basis", pin(format!("mapping-{id}"))),
                ("sigma_pixels", "0.5".into()),
                (
                    "source",
                    object(&[
                        ("codec", string("jpeg")),
                        ("import_identity", pin(format!("import-{id}"))),
                        ("segment", id.to_string()),
                        (
                            "capsule_digest",
                            string(&h(capsule.try_canonical_bytes()?).to_text()),
                        ),
                        (
                            "encoded_source_digest",
                            string(&capsule.source_digest.to_text()),
                        ),
                        ("sensor_id", string(capsule.sensor_id.as_str())),
                        ("component_interpretation", string("grayscale")),
                    ]),
                ),
                (
                    "alignment",
                    object(&[
                        ("import_identity", pin(format!("import-{id}"))),
                        ("stream_id", string(capsule.stream_id.as_str())),
                        ("clock_basis", string(capsule.clock_basis.as_str())),
                        (
                            "offset_ns",
                            if index == 0 { "[-10,20]" } else { "[10,30]" }.into(),
                        ),
                        ("basis", pin(format!("alignment-{id}"))),
                    ]),
                ),
            ]))
        };
        let document = json_input::parse(&object(&[
            ("schema", string(SCHEMA)), ("camera_rig_digest", string(&rig_digest.to_text())),
            ("privacy_domain", "9".into()), ("clock", "11".into()),
            ("clock_evidence", pin("common clock assumption")),
            ("association_basis", pin("static feature assumption")),
            ("reference_time_ns", "1020".into()), ("max_capture_span_ns", "100".into()),
            ("motion", string("static_during_capture_hull")),
            ("left", view(0)?), ("right", view(1)?),
            ("extraction", r#"{"threshold":20,"maximum_features":32,"separation":6}"#.into()),
            ("matching", r#"{"maximum_hamming_distance":0,"ratio_percent":80,"maximum_epipolar_distance_pixels":0.001}"#.into()),
        ]))?;
        let frame = |id: u64| -> TestResult<FeatureFrame> {
            Ok(FeatureFrame::new(
                ImageIdentity {
                    exposure: h(format!("exposure-{id}")).bytes(),
                    pixels: h(format!("luma-{id}")).bytes(),
                    image_domain: h(format!("image-domain-{id}")).bytes(),
                    dimensions: [640, 480],
                },
                h("native descriptor space").bytes(),
                vec![
                    ImageFeature {
                        id: 1,
                        pixel: [320.0 - 80.0 * (id - 1) as f64, 240.0],
                        descriptor: BinaryDescriptor([0; 4]),
                    },
                    ImageFeature {
                        id: 2,
                        pixel: [360.0 - 80.0 * (id - 1) as f64, 240.0],
                        descriptor: BinaryDescriptor([u64::MAX; 4]),
                    },
                ],
                &mut WorkBudget::new(1000),
            )?)
        };
        let frames = [frame(1)?, frame(2)?];
        Ok(Self {
            twin,
            rig,
            rig_document,
            rig_digest,
            document,
            capsules,
            frames,
        })
    }

    fn parse(&self, document: &str) -> Result<Query> {
        parse(document.as_bytes(), self.rig_digest)
    }
    fn query(&self) -> TestResult<Query> {
        checked(self.parse(&json(&self.document)))
    }
    fn resolved(&self) -> [ResolvedFrame<'_>; 2] {
        [0, 1].map(|index| {
            let id = index + 1;
            ResolvedFrame {
                capsule: &self.capsules[index],
                import_identity: h(format!("import-{id}")),
                segment: id as u64,
                dimensions: [640, 480],
                exposure: h(format!("exposure-{id}")),
                luma: h(format!("luma-{id}")),
                frame: &self.frames[index],
                allowed_mask_digest: h(format!("mask-{id}")).bytes(),
                codec: "jpeg",
                range_start: id as u64,
                range_count: 1,
                rectification: None,
            }
        })
    }
}

fn pinhole_v2(document: &Value) -> TestResult<Value> {
    let mut result = document.clone();
    *at_mut(&mut result, &["schema"])? = text_value(SCHEMA_V2);
    for side in ["left", "right"] {
        let Value::Object(view) = at_mut(&mut result, &[side])? else {
            return Err("view object".into());
        };
        let domain = view.remove("image_domain_digest").ok_or("pinhole domain")?;
        view.insert(
            "image".into(),
            Value::Object(BTreeMap::from([
                ("kind".into(), text_value("pinhole")),
                ("image_domain_digest".into(), domain),
            ])),
        );
    }
    Ok(result)
}

#[test]
fn v2_explicit_pinhole_preserves_v1_source_geometry_and_complete_declarations() -> TestResult {
    let f = Fixture::new()?;
    let old = f.query()?;
    let new = checked(f.parse(&json(&pinhole_v2(&f.document)?)))?;
    assert_eq!(old.version, 1);
    assert_eq!(new.version, 2);
    assert_eq!(old.matching, new.matching);
    assert_eq!(
        new.declarations,
        checked(f.parse(&new.declarations))?.declarations
    );
    assert_eq!(old.declarations, json(&f.document));
    let old_views = checked(bind(&old, f.resolved(), &f.rig))?;
    let new_views = checked(bind(&new, f.resolved(), &f.rig))?;
    let old_geometry = associate_features(
        &f.twin,
        [&old_views[0], &old_views[1]],
        old.matching,
        &mut WorkBudget::new(10_000_000),
    )?;
    let new_geometry = associate_features(
        &f.twin,
        [&new_views[0], &new_views[1]],
        new.matching,
        &mut WorkBudget::new(10_000_000),
    )?;
    assert_eq!(old_geometry.evidence(), new_geometry.evidence());
    assert_eq!(
        old_geometry.hypotheses().len(),
        new_geometry.hypotheses().len()
    );
    Ok(())
}

#[test]
fn exact_schema_versions_have_exclusive_view_image_field_shapes() -> TestResult {
    let f = Fixture::new()?;
    let valid = pinhole_v2(&f.document)?;
    for schema in [
        "fss.scene_feature_match_retained_query.v0",
        "fss.scene_feature_match_retained_query.v3",
        "fss.scene_feature_match_retained_query.v02",
        "fss.scene_feature_match_retained_query.v2.extra",
        "fss.scene_feature_multimatch_retained_query.v2",
    ] {
        assert!(
            f.parse(&edit(&valid, &["schema"], text_value(schema))?)
                .is_err()
        );
    }
    let mut old_with_new = f.document.clone();
    let Value::Object(left) = at_mut(&mut old_with_new, &["left"])? else {
        return Err("view".into());
    };
    left.insert("image".into(), Value::Object(BTreeMap::new()));
    assert!(f.parse(&json(&old_with_new)).is_err());
    let mut new_with_old = valid.clone();
    let Value::Object(left) = at_mut(&mut new_with_old, &["left"])? else {
        return Err("view".into());
    };
    left.insert(
        "image_domain_digest".into(),
        text_value(h("undeclared domain").to_text()),
    );
    assert!(f.parse(&json(&new_with_old)).is_err());
    let mut mixed = valid.clone();
    *at_mut(&mut mixed, &["right"])? = at_mut(&mut f.document.clone(), &["right"])?.clone();
    assert!(f.parse(&json(&mixed)).is_err());
    Ok(())
}

#[test]
fn full_interval_binding_feeds_real_geometry_without_time_or_source_substitution() -> TestResult {
    let f = Fixture::new()?;
    let query = f.query()?;
    let views = checked(bind(&query, f.resolved(), &f.rig))?;
    assert_eq!(views[0].capture, [990, 1030]);
    assert_eq!(views[1].capture, [990, 1050]);
    assert_eq!(
        query.views[0].alignment.clock_basis,
        ClockBasis::DeviceMonotonic
    );
    assert_eq!(f.capsules[0].capture.earliest.0, 1000);
    for (index, view) in views.iter().enumerate() {
        assert_eq!(view.source_digest, f.capsules[index].source_digest.bytes());
        assert_eq!(view.frame.identity(), f.frames[index].identity());
        assert_eq!(
            view.allowed_mask_digest,
            h(format!("mask-{}", index + 1)).bytes()
        );
        assert_eq!(view.frame.features(), f.frames[index].features());
    }
    let association = associate_features(
        &f.twin,
        [&views[0], &views[1]],
        query.matching,
        &mut WorkBudget::new(10_000_000),
    )?;
    assert_eq!(association.capture_hull(), [990, 1050]);
    assert_eq!(association.hypotheses().len(), 2);
    for hypothesis in association.hypotheses() {
        let FeatureHypothesisOutcome::Fused(point) = &hypothesis.outcome else {
            return Err("known stereo point was not reconstructed".into());
        };
        assert!((point.estimate().position[2] - 5.0).abs() < 1e-8);
    }
    Ok(())
}

#[test]
fn strict_declarations_round_trip_and_retain_all_alignment_assumptions() -> TestResult {
    let f = Fixture::new()?;
    let query = f.query()?;
    assert_eq!(
        query.declarations,
        checked(f.parse(&query.declarations))?.declarations
    );
    assert_eq!(query.matching.triangulation.min_views, 2);
    assert_eq!(query.matching.triangulation.max_outliers, 0);
    assert!(query.declarations.contains("device_monotonic"));
    assert!(query.declarations.contains(&h("alignment-1").to_text()));
    assert!(matches!(
        &query.views[0].source,
        Source::Jpeg {
            interpretation: ComponentInterpretation::Grayscale,
            ..
        }
    ));
    Ok(())
}

#[test]
fn caller_pixels_times_dimensions_masks_and_unknown_fields_are_refused() -> TestResult {
    let f = Fixture::new()?;
    for path in [
        vec![],
        vec!["left"],
        vec!["left", "source"],
        vec!["left", "alignment"],
        vec!["extraction"],
        vec!["matching"],
    ] {
        for key in [
            "capture_ns",
            "dimensions",
            "mask",
            "pixels",
            "features",
            "unknown",
        ] {
            let mut document = f.document.clone();
            let Value::Object(row) = at_mut(&mut document, &path)? else {
                return Err("fixture map".into());
            };
            row.insert(key.into(), Value::Null);
            assert!(
                f.parse(&json(&document)).is_err(),
                "accepted {path:?}.{key}"
            );
        }
    }
    let text = json(&f.document);
    assert!(
        f.parse(&text.replacen("\"clock\":11", "\"clock\":11,\"clock\":11", 1))
            .is_err()
    );
    assert!(
        f.parse(&text.replacen("\"motion\":\"static_during_capture_hull\",", "", 1))
            .is_err()
    );
    assert!(parse(&[0xff], f.rig_digest).is_err());
    assert!(parse(&vec![b' '; json_input::MAX_INPUT_BYTES + 1], f.rig_digest).is_err());
    Ok(())
}

#[test]
fn source_tags_have_exclusive_fields_and_complete_bounded_video_ranges() -> TestResult {
    let f = Fixture::new()?;
    for codec in ["h264", "h265"] {
        let mut document = f.document.clone();
        let Value::Object(row) = at_mut(&mut document, &["left", "source"])? else {
            return Err("fixture source".into());
        };
        row.insert("codec".into(), text_value(codec));
        row.remove("component_interpretation");
        row.insert("first_segment".into(), number(0));
        row.insert("segment_count".into(), number(64));
        let query = checked(f.parse(&json(&document)))?;
        let mut resolved = f.resolved();
        resolved[0].codec = codec;
        resolved[0].range_start = 0;
        resolved[0].range_count = 64;
        checked(bind(&query, resolved, &f.rig))?;
        for (key, value) in [
            ("first_segment", number(2)),
            ("segment_count", number(0)),
            ("segment_count", number(65)),
        ] {
            assert!(
                f.parse(&edit(&document, &["left", "source", key], value)?)
                    .is_err()
            );
        }
        let mut overflow = document.clone();
        *at_mut(&mut overflow, &["left", "source", "first_segment"])? =
            text_value(usize::MAX.to_string());
        assert!(f.parse(&json(&overflow)).is_err());
        let Value::Object(row) = at_mut(&mut document, &["left", "source"])? else {
            return Err("fixture source".into());
        };
        row.insert("component_interpretation".into(), text_value("grayscale"));
        assert!(f.parse(&json(&document)).is_err());
    }
    for (path, value) in [
        (vec!["left", "source", "codec"], text_value("auto")),
        (
            vec!["left", "source", "component_interpretation"],
            text_value("auto"),
        ),
        (vec!["left", "source", "segment"], number("1.0")),
    ] {
        assert!(f.parse(&edit(&f.document, &path, value)?).is_err());
    }
    Ok(())
}

#[test]
fn exact_ids_pins_and_distinct_actual_sources_are_required() -> TestResult {
    let f = Fixture::new()?;
    for (path, value) in [
        (
            vec!["camera_rig_digest"],
            text_value(h("other rig").to_text()),
        ),
        (vec!["right", "camera"], number(1)),
        (
            vec!["right", "source", "sensor_id"],
            text_value("sensor:retained-match-1"),
        ),
        (
            vec!["right", "source", "encoded_source_digest"],
            text_value(f.capsules[0].source_digest.to_text()),
        ),
        (
            vec!["left", "source", "sensor_id"],
            text_value("sensor:invalid space"),
        ),
        (
            vec!["left", "alignment", "stream_id"],
            text_value("stream:invalid/path"),
        ),
        (
            vec!["left", "alignment", "import_identity"],
            text_value(h("other import").to_text()),
        ),
        (vec!["left", "alignment", "clock_basis"], text_value("utc")),
        (
            vec!["left", "image_domain_digest"],
            text_value(format!("sha256:{}", "0".repeat(64))),
        ),
        (
            vec!["left", "source", "sensor_id"],
            text_value(format!("sensor:{}", "s".repeat(256))),
        ),
    ] {
        assert!(
            f.parse(&edit(&f.document, &path, value)?).is_err(),
            "accepted {path:?}"
        );
    }
    let query = f.query()?;
    let mut duplicate = f.capsules[1].clone();
    duplicate.sensor_id = f.capsules[0].sensor_id.clone();
    let mut resolved = f.resolved();
    resolved[1].capsule = &duplicate;
    assert!(bind(&query, resolved, &f.rig).is_err());
    Ok(())
}

#[test]
fn capsule_preflight_checks_every_pin_before_pixel_work() -> TestResult {
    let f = Fixture::new()?;
    let query = f.query()?;
    assert_eq!(
        checked(validate_capsule(&query.views[0], &f.capsules[0]))?,
        [990, 1030]
    );
    for field in 0..7 {
        let mut view = query.views[0].clone();
        match field {
            0 => view.alignment.import_identity = h("other import"),
            1 => view.alignment.stream_id = "stream:other".into(),
            2 => view.alignment.clock_basis = ClockBasis::UtcDisciplined,
            3..=6 => {
                let Source::Jpeg { pins, .. } = &mut view.source else {
                    return Err("fixture codec".into());
                };
                match field {
                    3 => pins.capsule_digest = h("other capsule"),
                    4 => pins.encoded_source_digest = h("other encoded source"),
                    5 => pins.sensor_id = "sensor:other".into(),
                    _ => pins.import_identity = h("other import"),
                }
            }
            _ => unreachable!(),
        }
        assert!(
            validate_capsule(&view, &f.capsules[0]).is_err(),
            "accepted pin {field}"
        );
    }
    let mut capsule = f.capsules[0].clone();
    capsule.sequence += 1;
    assert!(validate_capsule(&query.views[0], &capsule).is_err());
    Ok(())
}

#[test]
fn full_capture_interval_rejects_overflow_negative_results_and_reversed_offsets() -> TestResult {
    let f = Fixture::new()?;
    let query = f.query()?;
    for (capture, offset) in [
        ([i128::MAX, i128::MAX], [1, 1]),
        ([i128::MIN, i128::MIN], [-1, -1]),
        ([i64::MAX as i128, i64::MAX as i128], [0, 1]),
        ([0, 10], [-1, 1]),
        ([100, 90], [0, 0]),
        ([100, 110], [2, 1]),
    ] {
        let mut capsule = f.capsules[0].clone();
        capsule.capture = CaptureInterval {
            earliest: TimestampNs(capture[0]),
            latest: TimestampNs(capture[1]),
        };
        capsule.receive_time = TimestampNs(capture[1].max(capture[0]));
        let mut view = query.views[0].clone();
        view.alignment.offset_ns = offset;
        let Source::Jpeg { pins, .. } = &mut view.source else {
            return Err("fixture codec".into());
        };
        pins.capsule_digest = h(capsule.try_canonical_bytes()?);
        assert!(
            validate_capsule(&view, &capsule).is_err(),
            "accepted {capture:?}+{offset:?}"
        );
    }
    Ok(())
}

#[test]
fn offsets_and_large_integer_literals_are_lossless_and_strict() -> TestResult {
    let f = Fixture::new()?;
    let values = Value::Array(vec![
        text_value(i64::MIN.to_string()),
        text_value(i64::MAX.to_string()),
    ]);
    let query = checked(f.parse(&edit(
        &f.document,
        &["left", "alignment", "offset_ns"],
        values,
    )?))?;
    assert_eq!(query.views[0].alignment.offset_ns, [i64::MIN, i64::MAX]);
    for bad in [
        number("1e2"),
        number("10.0"),
        text_value("-0"),
        text_value("01"),
        text_value("+1"),
        text_value("9223372036854775808"),
    ] {
        let value = Value::Array(vec![bad, number(1000)]);
        assert!(
            f.parse(&edit(
                &f.document,
                &["left", "alignment", "offset_ns"],
                value
            )?)
            .is_err()
        );
    }
    let query = checked(f.parse(&edit(
        &f.document,
        &["reference_time_ns"],
        text_value(u64::MAX.to_string()),
    )?))?;
    assert_eq!(query.matching.reference_time_ns, u64::MAX);
    for bad in [
        number("1020.0"),
        number("1e3"),
        text_value("01020"),
        text_value("18446744073709551616"),
    ] {
        assert!(
            f.parse(&edit(&f.document, &["reference_time_ns"], bad)?)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn decoder_import_selection_range_and_native_pixel_pins_cannot_be_swapped() -> TestResult {
    let f = Fixture::new()?;
    let query = f.query()?;
    for field in 0..11 {
        let mut resolved = f.resolved();
        let left = &mut resolved[0];
        match field {
            0 => left.import_identity = h("other import"),
            1 => left.segment += 1,
            2 => left.codec = "h264",
            3 => left.range_start += 1,
            4 => left.range_count += 1,
            5 => left.dimensions = [640, 479],
            6 => left.exposure = h("other exposure"),
            7 => left.luma = h("other luma"),
            8 => left.allowed_mask_digest = [0; 32],
            9 => left.frame = &f.frames[1],
            10 => left.capsule = &f.capsules[1],
            _ => unreachable!(),
        }
        assert!(
            bind(&query, resolved, &f.rig).is_err(),
            "accepted snapshot field {field}"
        );
    }
    Ok(())
}

#[test]
fn common_clock_privacy_mode_and_capture_hull_must_match_the_rig() -> TestResult {
    let f = Fixture::new()?;
    for (path, value) in [
        (vec!["privacy_domain"], number(10)),
        (vec!["clock"], number(12)),
        (vec!["left", "camera"], number(3)),
        (
            vec!["left", "image_domain_digest"],
            text_value(h("other image mode").to_text()),
        ),
        (vec!["reference_time_ns"], number(1051)),
        (vec!["max_capture_span_ns"], number(59)),
        (vec!["extraction", "maximum_features"], number(1)),
        (
            vec!["left", "alignment", "offset_ns"],
            Value::Array(vec![number(1000), number(1001)]),
        ),
    ] {
        let query = checked(f.parse(&edit(&f.document, &path, value)?))?;
        assert!(
            bind(&query, f.resolved(), &f.rig).is_err(),
            "accepted {path:?}"
        );
    }
    let query = f.query()?;
    let rig_text = json(&f.rig_document).replace("\"width\":640", "\"width\":641");
    let rig = SceneRig::from_document(
        &json_input::parse(&rig_text)?,
        &f.twin,
        &mut WorkBudget::new(1_000_000),
    )?;
    assert!(bind(&query, f.resolved(), &rig).is_err());
    Ok(())
}

#[test]
fn unsupported_geometry_and_feature_limits_cannot_weaken_the_pair_contract() -> TestResult {
    let f = Fixture::new()?;
    for (path, value) in [
        (vec!["motion"], text_value("moving")),
        (vec!["extraction", "maximum_features"], number(129)),
        (vec!["extraction", "threshold"], number(255)),
        (vec!["extraction", "separation"], number(0)),
        (vec!["matching", "ratio_percent"], number(100)),
        (vec!["matching", "maximum_hamming_distance"], number(257)),
        (
            vec!["matching", "maximum_epipolar_distance_pixels"],
            number("1e309"),
        ),
        (vec!["left", "sigma_pixels"], number(0)),
        (vec!["max_capture_span_ns"], number(1_000_000_001_u64)),
    ] {
        assert!(
            f.parse(&edit(&f.document, &path, value)?).is_err(),
            "accepted {path:?}"
        );
    }
    for triangulation in [
        r#"{"min_views":1}"#,
        r#"{"max_outliers":1}"#,
        r#"{"max_iterations":33}"#,
        r#"{"max_iterations":"1e1"}"#,
        r#"{"unknown":1}"#,
    ] {
        let mut document = f.document.clone();
        let Value::Object(top) = &mut document else {
            return Err("fixture document".into());
        };
        top.insert("triangulation".into(), json_input::parse(triangulation)?);
        assert!(f.parse(&json(&document)).is_err());
    }
    Ok(())
}
