#![forbid(unsafe_code)]
//! Pure admission tests. File pins and source declarations here assert no retained custody.

use super::*;
use fss_cli::json_output::{array, object, string};

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn h(value: impl AsRef<[u8]>) -> ContentDigest {
    ContentDigest::sha256(value.as_ref())
}
fn pin(value: impl AsRef<[u8]>) -> String {
    string(&h(value).to_text())
}
fn checked<T>(value: Result<T>) -> Test<T> {
    value.map_err(|error| format!("{error:?}").into())
}
fn at<'a>(value: &'a mut Value, path: &[&str]) -> Test<&'a mut Value> {
    let Some((key, rest)) = path.split_first() else {
        return Ok(value);
    };
    let child = match value {
        Value::Object(values) => values.get_mut(*key).ok_or("fixture field")?,
        Value::Array(values) => values.get_mut(key.parse::<usize>()?).ok_or("fixture row")?,
        _ => return Err("fixture container".into()),
    };
    at(child, rest)
}
fn replace(document: &Value, path: &[&str], value: Value) -> Test<String> {
    let mut document = document.clone();
    *at(&mut document, path)? = value;
    Ok(shared::json(&document))
}
fn add(document: &Value, path: &[&str], key: &str, value: Value) -> Test<String> {
    let mut document = document.clone();
    let Value::Object(row) = at(&mut document, path)? else {
        return Err("fixture object".into());
    };
    row.insert(key.into(), value);
    Ok(shared::json(&document))
}

fn rig_document(count: usize) -> Test<Value> {
    let cameras = (1..=count)
        .rev()
        .map(|id| {
            object(&[
                ("camera", id.to_string()),
                ("sensor_id", string(&format!("sensor:adopted-{id}"))),
                ("adoption_digest", pin(format!("adoption-{id}"))),
                (
                    "original_input",
                    object(&[
                        ("path", string(&format!("inputs/camera-{id}.txt"))),
                        ("digest", pin(format!("original-input-{id}"))),
                    ]),
                ),
                ("source_object_id", string(&format!("source_camera_{id}"))),
                ("image_domain", (id + 100).to_string()),
                ("clock", "11".into()),
                ("privacy_domain", "9".into()),
                ("validity_ns", "[0,60000000000]".into()),
            ])
        })
        .collect::<Vec<_>>();
    Ok(json_input::parse(&object(&[
        ("schema", string(SCHEMA)),
        ("source_scene_digest", pin("source-scene")),
        ("twin_digest", pin("twin")),
        ("geometry_basis", r#"{"property":7,"revision":2}"#.into()),
        ("coordinate_frame", string("RH_Z_UP")),
        ("evaluation_scope", string("adopted_scene_fixture")),
        (
            "calibration",
            object(&[
                ("path", string("candidate/site.fsscal")),
                ("digest", pin("semantic-calibration-identity")),
                ("file_digest", pin("whole-calibration-file")),
            ]),
        ),
        ("cameras", array(&cameras)),
    ]))?)
}

fn query_view(index: usize, camera: usize, version: u8) -> String {
    let mut fields = vec![
        ("camera", camera.to_string()),
        ("mapping_basis", pin(format!("camera-mapping-{camera}"))),
        ("sigma_pixels", "0.25".into()),
        (
            "source",
            object(&[
                ("codec", string("jpeg")),
                ("import_identity", pin(format!("source-import-{index}"))),
                ("segment", "0".into()),
                ("capsule_digest", pin(format!("source-capsule-{index}"))),
                (
                    "encoded_source_digest",
                    pin(format!("source-pixels-{index}")),
                ),
                ("sensor_id", string(&format!("sensor:adopted-{camera}"))),
                ("component_interpretation", string("grayscale")),
            ]),
        ),
        (
            "alignment",
            object(&[
                ("import_identity", pin(format!("source-import-{index}"))),
                ("stream_id", string(&format!("stream:adopted-{camera}:g1"))),
                ("clock_basis", string("estimated")),
                ("offset_ns", "[-2,3]".into()),
                ("basis", pin(format!("clock-basis-{camera}"))),
            ]),
        ),
    ];
    fields.push(if version == 1 {
        ("image_domain_digest", pin(format!("image-{camera}")))
    } else {
        (
            "image",
            object(&[
                ("kind", string("pinhole")),
                ("image_domain_digest", pin(format!("image-{camera}"))),
            ]),
        )
    });
    object(&fields)
}

fn query_document(schema: &str) -> Test<Value> {
    let temporal = schema == temporal_input::SCHEMA;
    let pair = matches!(schema, shared::SCHEMA | shared::SCHEMA_V2);
    let version = if temporal || schema.ends_with(".v2") {
        2
    } else {
        1
    };
    let mut fields = vec![
        ("schema", string(schema)),
        ("camera_rig_digest", pin("exact-adopted-rig-document")),
        ("privacy_domain", "9".into()),
        ("clock", "11".into()),
        ("clock_evidence", pin("declared-common-clock")),
        ("association_basis", pin("declared-correspondence-model")),
        ("reference_time_ns", "1500000000".into()),
        ("max_capture_span_ns", if temporal { "59000000000" } else { "1000000" }.into()),
        (
            "motion",
            string(if temporal {
                "constant_velocity_during_capture_hull"
            } else {
                "static_during_capture_hull"
            }),
        ),
        ("extraction", r#"{"threshold":20,"maximum_features":32,"separation":6}"#.into()),
        (
            "matching",
            if temporal {
                r#"{"maximum_hamming_distance":0,"ratio_percent":80}"#
            } else {
                r#"{"maximum_hamming_distance":0,"ratio_percent":80,"maximum_epipolar_distance_pixels":0.001}"#
            }.into(),
        ),
    ];
    if pair {
        fields.push(("left", query_view(0, 1, version)));
        fields.push(("right", query_view(1, 2, version)));
    } else {
        let count = if temporal { 4 } else { 3 };
        let views = (0..count)
            .map(|index| {
                query_view(
                    index,
                    if temporal { index % 2 + 1 } else { index + 1 },
                    version,
                )
            })
            .collect::<Vec<_>>();
        fields.push(("views", array(&views)));
    }
    if temporal {
        fields.push(("max_capture_uncertainty_ns", "1000".into()));
    }
    Ok(json_input::parse(&object(&fields))?)
}

const QUERY_SCHEMAS: [&str; 5] = [
    shared::SCHEMA,
    shared::SCHEMA_V2,
    multiview::input::SCHEMA,
    multiview::input::SCHEMA_V2,
    temporal_input::SCHEMA,
];

#[test]
fn adopted_rig_preserves_exact_dependencies_and_canonical_camera_order() -> Test {
    let document = rig_document(3)?;
    let parsed = checked(parse_rig(shared::json(&document).as_bytes()))?;
    assert_eq!(parsed.source_scene_digest, h("source-scene"));
    assert_eq!(parsed.twin_digest, h("twin"));
    assert_eq!(parsed.geometry_basis, (7, 2));
    assert_eq!(parsed.evaluation_scope, "adopted_scene_fixture");
    assert_eq!(parsed.calibration.path, "candidate/site.fsscal");
    assert_eq!(
        parsed.calibration.digest,
        h("semantic-calibration-identity")
    );
    assert_eq!(parsed.calibration.file_digest, h("whole-calibration-file"));
    assert_ne!(parsed.calibration.digest, parsed.calibration.file_digest);
    for (index, camera) in parsed.cameras.iter().enumerate() {
        let id = index + 1;
        assert_eq!(camera.camera, id as u64);
        assert_eq!(camera.sensor_id.as_str(), format!("sensor:adopted-{id}"));
        assert_eq!(camera.adoption_digest, h(format!("adoption-{id}")));
        assert_eq!(
            camera.original_input.digest,
            h(format!("original-input-{id}"))
        );
        assert_eq!(
            camera.original_input.path,
            format!("inputs/camera-{id}.txt")
        );
        assert_eq!(camera.validity, [0, 60_000_000_000]);
    }
    let mut reordered = document.clone();
    let Value::Array(cameras) = at(&mut reordered, &["cameras"])? else {
        return Err("fixture rows".into());
    };
    cameras.reverse();
    assert_eq!(
        checked(parse_rig(shared::json(&reordered).as_bytes()))?,
        parsed
    );
    Ok(())
}

#[test]
fn full_u64_handles_and_clock_bounds_are_exact_for_numbers_and_strings() -> Test {
    for string_form in [false, true] {
        let mut document = rig_document(1)?;
        for path in [
            vec!["geometry_basis", "property"],
            vec!["geometry_basis", "revision"],
            vec!["cameras", "0", "camera"],
            vec!["cameras", "0", "image_domain"],
            vec!["cameras", "0", "clock"],
            vec!["cameras", "0", "privacy_domain"],
            vec!["cameras", "0", "validity_ns", "0"],
            vec!["cameras", "0", "validity_ns", "1"],
        ] {
            *at(&mut document, &path)? = if string_form {
                Value::Text(u64::MAX.to_string())
            } else {
                Value::Number(u64::MAX.to_string())
            };
        }
        let parsed = checked(parse_rig(shared::json(&document).as_bytes()))?;
        assert_eq!(parsed.geometry_basis, (u64::MAX, u64::MAX));
        let camera = &parsed.cameras[0];
        assert_eq!(
            [
                camera.camera,
                camera.image_domain,
                camera.clock,
                camera.privacy_domain
            ],
            [u64::MAX; 4]
        );
        assert_eq!(camera.validity, [u64::MAX; 2]);
    }
    Ok(())
}

#[test]
fn unsigned_identifiers_refuse_noncanonical_lossy_and_zero_forms() -> Test {
    let document = rig_document(1)?;
    for literal in [
        "0",
        "-0",
        "-1",
        "01",
        "+1",
        "1.0",
        "1e0",
        "",
        "18446744073709551616",
    ] {
        for replacement in [Value::Number(literal.into()), Value::Text(literal.into())] {
            let bytes = replace(&document, &["cameras", "0", "camera"], replacement)?;
            assert!(parse_rig(bytes.as_bytes()).is_err(), "accepted {literal:?}");
        }
    }
    let reversed = replace(
        &document,
        &["cameras", "0", "validity_ns"],
        json_input::parse("[2,1]")?,
    )?;
    assert!(parse_rig(reversed.as_bytes()).is_err());
    Ok(())
}

#[test]
fn camera_sensor_and_scene_object_aliases_are_refused_independently() -> Test {
    let document = rig_document(2)?;
    for key in ["camera", "sensor_id", "source_object_id"] {
        let mut changed = document.clone();
        let value = at(&mut changed, &["cameras", "0", key])?.clone();
        *at(&mut changed, &["cameras", "1", key])? = value;
        assert!(
            parse_rig(shared::json(&changed).as_bytes()).is_err(),
            "accepted alias {key}"
        );
    }
    Ok(())
}

#[test]
fn candidate_pose_intrinsics_error_and_authority_overrides_cannot_enter_the_rig() -> Test {
    let document = rig_document(1)?;
    for key in [
        "world_to_camera",
        "intrinsics",
        "error",
        "status",
        "calibration",
        "image_model",
    ] {
        let changed = add(&document, &["cameras", "0"], key, Value::Null)?;
        assert!(
            parse_rig(changed.as_bytes()).is_err(),
            "accepted override {key}"
        );
    }
    for path in [
        vec![],
        vec!["calibration"],
        vec!["geometry_basis"],
        vec!["cameras", "0", "original_input"],
    ] {
        let changed = add(&document, &path, "unknown", Value::Bool(true))?;
        assert!(parse_rig(changed.as_bytes()).is_err());
    }
    Ok(())
}

#[test]
fn every_required_dependency_is_mandatory_and_all_hashes_are_nonzero_sha256() -> Test {
    let document = rig_document(1)?;
    for path in [
        vec!["source_scene_digest"],
        vec!["twin_digest"],
        vec!["calibration", "digest"],
        vec!["calibration", "file_digest"],
        vec!["cameras", "0", "adoption_digest"],
        vec!["cameras", "0", "original_input", "digest"],
    ] {
        for value in [
            Value::Null,
            Value::Text(format!("sha256:{}", "0".repeat(64))),
            Value::Text(format!("blake3:{}", "1".repeat(64))),
        ] {
            assert!(parse_rig(replace(&document, &path, value)?.as_bytes()).is_err());
        }
        let mut missing = document.clone();
        let (key, parent) = path.split_last().ok_or("fixture path")?;
        let Value::Object(row) = at(&mut missing, parent)? else {
            return Err("fixture object".into());
        };
        row.remove(*key);
        assert!(parse_rig(shared::json(&missing).as_bytes()).is_err());
    }
    for (key, wrong) in [
        ("schema", "fss.scene_camera_rig.v1"),
        ("coordinate_frame", "RH_Y_UP"),
    ] {
        assert!(
            parse_rig(replace(&document, &[key], Value::Text(wrong.into()))?.as_bytes()).is_err()
        );
    }
    Ok(())
}

#[test]
fn paths_and_labels_remain_bounded_without_opening_or_reinterpreting_them() -> Test {
    let document = rig_document(1)?;
    for path in [
        vec!["calibration", "path"],
        vec!["cameras", "0", "original_input", "path"],
    ] {
        for value in [
            "".to_owned(),
            "  ".to_owned(),
            "a\0b".to_owned(),
            "a\nb".to_owned(),
            "a\u{7f}b".to_owned(),
            "a".repeat(4097),
        ] {
            assert!(parse_rig(replace(&document, &path, Value::Text(value))?.as_bytes()).is_err());
        }
        let expected = "../owner inputs/unknown-but-pinned.dat";
        let parsed = checked(parse_rig(
            replace(&document, &path, Value::Text(expected.into()))?.as_bytes(),
        ))?;
        assert!(
            parsed.calibration.path == expected
                || parsed.cameras[0].original_input.path == expected
        );
    }
    for (path, maximum) in [
        (vec!["evaluation_scope"], 2048),
        (vec!["cameras", "0", "source_object_id"], 256),
    ] {
        assert!(
            parse_rig(replace(&document, &path, Value::Text("a".repeat(maximum)))?.as_bytes())
                .is_ok()
        );
        assert!(
            parse_rig(replace(&document, &path, Value::Text("a".repeat(maximum + 1)))?.as_bytes())
                .is_err()
        );
    }
    assert!(
        parse_rig(
            replace(
                &document,
                &["cameras", "0", "sensor_id"],
                Value::Text("sensor:bad space".into())
            )?
            .as_bytes()
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn complete_camera_inventory_has_explicit_one_and_sixteen_limits() -> Test {
    for count in [0, 1, 16, 17] {
        let parsed = parse_rig(shared::json(&rig_document(count)?).as_bytes());
        assert_eq!(parsed.is_ok(), (1..=16).contains(&count));
        if let Ok(parsed) = parsed {
            assert_eq!(parsed.cameras.len(), count);
        }
    }
    Ok(())
}

#[test]
fn all_five_existing_query_schemas_keep_their_complete_typed_policies() -> Test {
    let rig = h("exact-adopted-rig-document");
    for (index, schema) in QUERY_SCHEMAS.iter().enumerate() {
        let document = query_document(schema)?;
        let bytes = shared::json(&document);
        let parsed = checked(MatchingQuery::parse(bytes.as_bytes(), rig))?;
        assert_eq!(json_input::parse(parsed.declarations())?, document);
        let extraction = parsed.extraction();
        assert_eq!(
            (
                extraction.threshold,
                extraction.maximum_features,
                extraction.separation
            ),
            (20, 32, 6)
        );
        assert_eq!(parsed.views().len(), [2, 2, 3, 3, 4][index]);
        assert_eq!(
            parsed.kind(),
            [
                "static_pair",
                "static_pair",
                "static_multiview",
                "static_multiview",
                "temporal"
            ][index]
        );
        match parsed {
            MatchingQuery::Pair(query) => {
                assert_eq!(query.version, index as u8 + 1);
                assert_eq!(query.matching.camera_rig_digest, rig.bytes());
                assert_eq!(query.matching.maximum_epipolar_distance_pixels, 0.001);
            }
            MatchingQuery::Multi(query) => {
                assert_eq!(query.version, index as u8 - 1);
                assert_eq!(query.matching.camera_rig_digest, rig.bytes());
            }
            MatchingQuery::Temporal(query) => {
                assert_eq!(query.matching.camera_rig_digest, rig.bytes());
                assert_eq!(query.matching.max_capture_uncertainty_ns, 1000);
                assert_eq!(query.matching.max_capture_span_ns, 59_000_000_000);
            }
        }
    }
    Ok(())
}

fn raw_image() -> Test<Value> {
    Ok(json_input::parse(&object(&[
        ("kind", string("rectified")),
        ("source_domain_digest", pin("raw-source-domain")),
        ("lens_basis", pin("raw-lens-model")),
        (
            "source_intrinsics",
            r#"{"width":192,"height":128,"fx":160,"fy":160,"cx":96,"cy":64}"#.into(),
        ),
        (
            "distortion",
            r#"{"kind":"brown_conrady","radial":[0.01,0,0],"tangential":[0,0]}"#.into(),
        ),
        ("maximum_radius", "2".into()),
        ("luma_range", string("full")),
    ]))?)
}

#[test]
fn otherwise_valid_raw_lens_queries_fail_before_any_source_decode() -> Test {
    let rig = h("exact-adopted-rig-document");
    for schema in [
        shared::SCHEMA_V2,
        multiview::input::SCHEMA_V2,
        temporal_input::SCHEMA,
    ] {
        let mut document = query_document(schema)?;
        if schema == shared::SCHEMA_V2 {
            *at(&mut document, &["left", "image"])? = raw_image()?;
            assert!(shared::parse(shared::json(&document).as_bytes(), rig).is_ok());
        } else if schema == multiview::input::SCHEMA_V2 {
            *at(&mut document, &["views", "2", "image"])? = raw_image()?;
            assert!(multiview::input::parse(shared::json(&document).as_bytes(), rig).is_ok());
        } else {
            // Both exposures of a fixed camera keep the same valid lens declaration.
            *at(&mut document, &["views", "0", "image"])? = raw_image()?;
            *at(&mut document, &["views", "2", "image"])? = raw_image()?;
            assert!(temporal_input::parse(shared::json(&document).as_bytes(), rig).is_ok());
        }
        assert!(MatchingQuery::parse(shared::json(&document).as_bytes(), rig).is_err());
    }
    Ok(())
}

#[test]
fn query_dispatch_preserves_exact_rig_pin_schema_and_existing_policy_refusals() -> Test {
    let rig = h("exact-adopted-rig-document");
    for schema in QUERY_SCHEMAS {
        let document = query_document(schema)?;
        assert!(
            MatchingQuery::parse(shared::json(&document).as_bytes(), h("different-rig")).is_err()
        );
        for (path, value) in [
            (vec!["schema"], Value::Text(format!("{schema}.unknown"))),
            (
                vec!["matching", "ratio_percent"],
                Value::Number("100".into()),
            ),
            (
                vec!["extraction", "maximum_features"],
                Value::Number("129".into()),
            ),
            (
                vec!["motion"],
                Value::Text("owner-wishes-it-were-static".into()),
            ),
        ] {
            assert!(
                MatchingQuery::parse(replace(&document, &path, value)?.as_bytes(), rig).is_err()
            );
        }
        assert!(
            MatchingQuery::parse(
                add(&document, &[], "pose_override", Value::Null)?.as_bytes(),
                rig
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn temporal_repeats_keep_exact_camera_mode_and_never_alias_distinct_sensors() -> Test {
    let document = query_document(temporal_input::SCHEMA)?;
    let rig = h("exact-adopted-rig-document");
    let parsed = checked(MatchingQuery::parse(
        shared::json(&document).as_bytes(),
        rig,
    ))?;
    assert_eq!(
        parsed
            .views()
            .iter()
            .map(|view| view.camera)
            .collect::<Vec<_>>(),
        vec![1, 2, 1, 2]
    );
    for (path, value) in [
        (
            vec!["views", "2", "source", "sensor_id"],
            Value::Text("sensor:other".into()),
        ),
        (
            vec!["views", "2", "image", "image_domain_digest"],
            Value::Text(h("different-domain").to_text()),
        ),
        (
            vec!["views", "2", "alignment", "stream_id"],
            Value::Text("stream:different:g1".into()),
        ),
        (
            vec!["views", "1", "source", "sensor_id"],
            Value::Text("sensor:adopted-1".into()),
        ),
    ] {
        assert!(MatchingQuery::parse(replace(&document, &path, value)?.as_bytes(), rig).is_err());
    }
    Ok(())
}

#[test]
fn malformed_duplicate_trailing_and_oversized_json_is_refused() -> Test {
    let rig = h("exact-adopted-rig-document");
    for bytes in [
        b"{\"schema\":0,\"schema\":1}".to_vec(),
        b"{} {}".to_vec(),
        vec![0xff],
        vec![b' '; json_input::MAX_INPUT_BYTES + 1],
    ] {
        assert!(parse_rig(&bytes).is_err());
        assert!(MatchingQuery::parse(&bytes, rig).is_err());
    }
    Ok(())
}
