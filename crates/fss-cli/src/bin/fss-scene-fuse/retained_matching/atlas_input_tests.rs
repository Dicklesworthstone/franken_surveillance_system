#![forbid(unsafe_code)]
//! Actual parser, source-binding and native image types; synthetic snapshots confer no custody.

use super::*;
use crate::matching::fixtures::{HEIGHT, WIDTH, package, rig_document};
use fss_core::{
    CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, SensorCapsule, SensorId,
    SensorSourceBytesSpec, StreamId, TimestampNs,
};
use fss_geometry::{GeometryBasis, WorkBudget};
use fss_twin::localization::native::descriptor_domain;
use fss_twin::localization::{BinaryDescriptor, FeatureFrame, ImageFeature, ImageIdentity};
use fss_twin::rectification::{LumaRange, RawFrameIdentity, RawGrayFrame, extract_raw_features};
use fss_twin::{ImportExpectation, ImportLimits, import_twin};

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn h(value: impl AsRef<[u8]>) -> ContentDigest {
    ContentDigest::sha256(value.as_ref())
}
fn checked<T>(result: Result<T>) -> Test<T> {
    result.map_err(|error| format!("{error:?}").into())
}
fn json(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.clone(),
        Value::Text(value) => string(value),
        Value::Array(values) => array(&values.iter().map(json).collect::<Vec<_>>()),
        Value::Object(values) => object(
            &values
                .iter()
                .map(|(key, value)| (key.as_str(), json(value)))
                .collect::<Vec<_>>(),
        ),
    }
}
fn at<'a>(value: &'a mut Value, path: &[&str]) -> Test<&'a mut Value> {
    let Some((key, rest)) = path.split_first() else {
        return Ok(value);
    };
    let next = match value {
        Value::Object(values) => values.get_mut(*key).ok_or("fixture key")?,
        Value::Array(values) => values.get_mut(key.parse::<usize>()?).ok_or("fixture row")?,
        _ => return Err("fixture container".into()),
    };
    at(next, rest)
}
fn landmark(index: u64) -> String {
    object(&[
        ("hypothesis", pin(h(format!("hypothesis-{index}")).bytes())),
        ("landmark", (index + 1).to_string()),
        ("physical_group", (index + 101).to_string()),
        ("feature", "0".into()),
        (
            "enduring_static_basis",
            pin(h("owner selected persistent reference").bytes()),
        ),
    ])
}
fn selection(rows: &[String]) -> String {
    object(&[
        ("schema", string(SCHEMA)),
        (
            "association_evidence",
            pin(h("complete native association").bytes()),
        ),
        ("landmarks", array(rows)),
    ])
}

struct Fixture {
    twin: PropertyTwin,
    rig: SceneRig,
    rig_digest: ContentDigest,
    document: Value,
    capsules: Vec<SensorCapsule>,
    frames: Vec<FeatureFrame>,
}
impl Fixture {
    fn new(count: usize, version: u8) -> Test<Self> {
        let bytes = package();
        let twin = import_twin(
            &bytes,
            ImportExpectation {
                package_sha256: h(&bytes).bytes(),
                source_scene_sha256: h("synthetic native JPEG matching scene").bytes(),
                basis: GeometryBasis::new(7, 2)?,
            },
            ImportLimits::default(),
            &mut WorkBudget::new(10_000_000),
        )?;
        let mut rig_value = json_input::parse(&rig_document(&bytes))?;
        let camera = at(&mut rig_value, &["cameras", "0"])?.clone();
        let mut cameras = Vec::new();
        for id in 1..=count {
            let mut camera = camera.clone();
            *at(&mut camera, &["camera"])? = Value::Number(id.to_string());
            *at(&mut camera, &["image_domain"])? = Value::Number(id.to_string());
            *at(&mut camera, &["source_object_id"])? = Value::Text(format!("camera_{id}"));
            *at(&mut camera, &["world_to_camera", "translation"])? =
                json_input::parse(&format!("[{},0,0]", 1_i64 - id as i64))?;
            cameras.push(camera);
        }
        *at(&mut rig_value, &["cameras"])? = Value::Array(cameras);
        let rig_digest = h(json(&rig_value));
        let rig = SceneRig::from_document(&rig_value, &twin, &mut WorkBudget::new(1_000_000))?;
        let mut capsules = Vec::new();
        let mut frames = Vec::new();
        let mut views = Vec::new();
        for id in 1..=count {
            let capsule = SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
                capsule_id: CapsuleId::parse(format!("capsule:atlas-input-{id}"))?,
                sensor_id: SensorId::parse(format!("sensor:atlas-input-{id}"))?,
                stream_id: StreamId::parse(format!("stream:atlas-input-{id}"))?,
                sequence: 0,
                capture: CaptureInterval::new(TimestampNs(1000), TimestampNs(1100))?,
                receive_time: TimestampNs(1200),
                clock_basis: ClockBasis::Estimated,
                source: format!("synthetic retained source snapshot {id}").as_bytes(),
                frame_count: 1,
                gap_before: false,
            })?;
            let mut view = vec![
                ("camera", id.to_string()),
                ("mapping_basis", pin(h(format!("mapping-{id}")).bytes())),
                ("sigma_pixels", "0.5".into()),
                (
                    "source",
                    object(&[
                        ("codec", string("jpeg")),
                        ("import_identity", pin(h(format!("import-{id}")).bytes())),
                        ("segment", "0".into()),
                        (
                            "capsule_digest",
                            pin(h(capsule.try_canonical_bytes()?).bytes()),
                        ),
                        ("encoded_source_digest", pin(capsule.source_digest.bytes())),
                        ("sensor_id", string(capsule.sensor_id.as_str())),
                        ("component_interpretation", string("grayscale")),
                    ]),
                ),
                (
                    "alignment",
                    object(&[
                        ("import_identity", pin(h(format!("import-{id}")).bytes())),
                        ("stream_id", string(capsule.stream_id.as_str())),
                        ("clock_basis", string("estimated")),
                        ("offset_ns", "[-10,10]".into()),
                        ("basis", pin(h(format!("alignment-{id}")).bytes())),
                    ]),
                ),
            ];
            let image_domain = pin(h(format!("image-domain-{id}")).bytes());
            if version == 1 {
                view.push(("image_domain_digest", image_domain));
            } else {
                view.push((
                    "image",
                    object(&[
                        ("kind", string("pinhole")),
                        ("image_domain_digest", image_domain),
                    ]),
                ));
            }
            views.push(object(&view));
            capsules.push(capsule);
            frames.push(Self::frame(id, 1)?);
        }
        let schema = match (count == 2, version) {
            (true, 1) => input::SCHEMA,
            (true, _) => input::SCHEMA_V2,
            (false, 1) => multi::SCHEMA,
            (false, _) => multi::SCHEMA_V2,
        };
        let mut fields = vec![
            ("schema", string(schema)),
            ("camera_rig_digest", pin(rig_digest.bytes())),
            ("privacy_domain", "9".into()),
            ("clock", "11".into()),
            ("clock_evidence", pin(h("declared scene clock").bytes())),
            ("association_basis", pin(h("static during this capture hull").bytes())),
            ("reference_time_ns", "1050".into()),
            ("max_capture_span_ns", "1000".into()),
            ("motion", string("static_during_capture_hull")),
            ("extraction", r#"{"threshold":20,"maximum_features":128,"separation":6}"#.into()),
            ("matching", r#"{"maximum_hamming_distance":20,"ratio_percent":80,"maximum_epipolar_distance_pixels":1}"#.into()),
        ];
        if count == 2 {
            fields.push(("left", views[0].clone()));
            fields.push(("right", views[1].clone()));
        } else {
            fields.push(("views", array(&views)));
        }
        Ok(Self {
            twin,
            rig,
            rig_digest,
            document: json_input::parse(&object(&fields))?,
            capsules,
            frames,
        })
    }
    fn frame(id: usize, count: usize) -> Test<FeatureFrame> {
        Ok(FeatureFrame::new(
            ImageIdentity {
                exposure: h(format!("exposure-{id}")).bytes(),
                pixels: h(format!("luma-{id}")).bytes(),
                image_domain: h(format!("image-domain-{id}")).bytes(),
                dimensions: [WIDTH, HEIGHT],
            },
            descriptor_domain(),
            (0..count)
                .map(|point| ImageFeature {
                    id: point as u64 + 1,
                    pixel: [point as f64 + 0.5, 40.5],
                    descriptor: BinaryDescriptor([point as u64, 0, 0, 0]),
                })
                .collect(),
            &mut WorkBudget::new(1_000_000),
        )?)
    }
    fn query(&self) -> Test<MatchingQuery> {
        checked(parse_matching(
            json(&self.document).as_bytes(),
            self.rig_digest,
        ))
    }
    fn resolved(&self) -> Vec<ResolvedFrame<'_>> {
        self.capsules
            .iter()
            .zip(&self.frames)
            .enumerate()
            .map(|(index, (capsule, frame))| ResolvedFrame {
                capsule,
                import_identity: h(format!("import-{}", index + 1)),
                segment: 0,
                dimensions: [WIDTH, HEIGHT],
                exposure: ContentDigest::new(DigestAlgorithm::Sha256, frame.identity().exposure),
                luma: ContentDigest::new(DigestAlgorithm::Sha256, frame.identity().pixels),
                frame,
                allowed_mask_digest: h("complete synthetic allowed mask").bytes(),
                codec: "jpeg",
                range_start: 0,
                range_count: 1,
                rectification: None,
            })
            .collect()
    }
}

#[test]
fn selection_order_and_integer_spelling_have_one_complete_declaration() -> Test {
    let normal = checked(parse_selection(
        selection(&[landmark(0), landmark(1)]).as_bytes(),
    ))?;
    let mut reverse = json_input::parse(&selection(&[landmark(1), landmark(0)]))?;
    *at(&mut reverse, &["landmarks", "0", "landmark"])? = Value::Text("2".into());
    *at(&mut reverse, &["landmarks", "1", "feature"])? = Value::Text("0".into());
    let reverse = checked(parse_selection(json(&reverse).as_bytes()))?;
    assert_eq!(normal.declarations, reverse.declarations);
    assert_eq!(
        normal
            .landmarks
            .iter()
            .map(|l| l.landmark)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(
        normal.association_evidence,
        h("complete native association").bytes()
    );
    assert!(
        normal
            .declarations
            .contains(&h("owner selected persistent reference").to_text())
    );
    assert_eq!(
        checked(parse_selection(normal.declarations.as_bytes()))?.declarations,
        normal.declarations
    );
    Ok(())
}

#[test]
fn integer_ids_preserve_full_u64_precision_and_feature_ordinal_limits() -> Test {
    let mut doc = json_input::parse(&selection(&[landmark(0)]))?;
    *at(&mut doc, &["landmarks", "0", "landmark"])? = Value::Number(u64::MAX.to_string());
    *at(&mut doc, &["landmarks", "0", "physical_group"])? = Value::Text("9007199254740993".into());
    *at(&mut doc, &["landmarks", "0", "feature"])? = Value::Number(u32::MAX.to_string());
    let result = checked(parse_selection(json(&doc).as_bytes()))?;
    assert_eq!(result.landmarks[0].landmark, u64::MAX);
    assert_eq!(result.landmarks[0].physical_group, 9_007_199_254_740_993);
    assert_eq!(result.landmarks[0].feature, u32::MAX);
    for (field, value) in [
        ("landmark", "18446744073709551616"),
        ("physical_group", "0"),
        ("feature", "4294967296"),
        ("landmark", "01"),
        ("landmark", "+1"),
        ("landmark", "-1"),
        ("landmark", "1e2"),
        ("landmark", "1.0"),
    ] {
        let mut invalid = doc.clone();
        *at(&mut invalid, &["landmarks", "0", field])? = Value::Text(value.into());
        assert!(
            parse_selection(json(&invalid).as_bytes()).is_err(),
            "{field}={value}"
        );
    }
    Ok(())
}

#[test]
fn every_selected_hypothesis_landmark_and_physical_group_must_be_unique() -> Test {
    let doc = json_input::parse(&selection(&[landmark(0), landmark(1)]))?;
    for field in ["hypothesis", "landmark", "physical_group"] {
        let mut invalid = doc.clone();
        let repeated = at(&mut invalid, &["landmarks", "0", field])?.clone();
        *at(&mut invalid, &["landmarks", "1", field])? = repeated;
        assert!(
            parse_selection(json(&invalid).as_bytes()).is_err(),
            "{field}"
        );
    }
    Ok(())
}

#[test]
fn source_association_hypothesis_and_enduring_static_pins_are_required_nonzero_sha256() -> Test {
    let doc = json_input::parse(&selection(&[landmark(0)]))?;
    for path in [
        vec!["association_evidence"],
        vec!["landmarks", "0", "hypothesis"],
        vec!["landmarks", "0", "enduring_static_basis"],
    ] {
        for value in [
            format!("sha256:{}", "0".repeat(64)),
            "sha256:1234".into(),
            format!("blake3:{}", "1".repeat(64)),
        ] {
            let mut invalid = doc.clone();
            *at(&mut invalid, &path)? = Value::Text(value);
            assert!(parse_selection(json(&invalid).as_bytes()).is_err());
        }
    }
    Ok(())
}

#[test]
fn selection_refuses_missing_duplicate_unknown_fields_and_geometry_overrides() -> Test {
    let text = selection(&[landmark(0)]);
    let doc = json_input::parse(&text)?;
    for field in ["schema", "association_evidence", "landmarks"] {
        let Value::Object(mut fields) = doc.clone() else {
            return Err("fixture".into());
        };
        fields.remove(field);
        assert!(parse_selection(json(&Value::Object(fields)).as_bytes()).is_err());
    }
    for field in [
        "hypothesis",
        "landmark",
        "physical_group",
        "feature",
        "enduring_static_basis",
    ] {
        let mut invalid = doc.clone();
        let Value::Object(fields) = at(&mut invalid, &["landmarks", "0"])? else {
            return Err("fixture".into());
        };
        fields.remove(field);
        assert!(parse_selection(json(&invalid).as_bytes()).is_err());
    }
    for field in [
        "world",
        "descriptor",
        "error",
        "pixels",
        "confidence",
        "source_record",
    ] {
        let mut invalid = doc.clone();
        let Value::Object(fields) = at(&mut invalid, &["landmarks", "0"])? else {
            return Err("fixture".into());
        };
        fields.insert(field.into(), Value::Null);
        assert!(
            parse_selection(json(&invalid).as_bytes()).is_err(),
            "{field}"
        );
    }
    let duplicate = text.replacen("\"schema\":", "\"schema\":\"duplicate\",\"schema\":", 1);
    assert!(parse_selection(duplicate.as_bytes()).is_err());
    assert!(parse_selection(format!("{text} {{}}").as_bytes()).is_err());
    assert!(parse_selection(&[0xff]).is_err());
    Ok(())
}

#[test]
fn selection_count_and_document_size_remain_bounded() -> Test {
    assert!(parse_selection(selection(&[]).as_bytes()).is_err());
    let maximum: Vec<_> = (0..128).map(landmark).collect();
    assert_eq!(
        checked(parse_selection(selection(&maximum).as_bytes()))?
            .landmarks
            .len(),
        128
    );
    let excessive: Vec<_> = (0..129).map(landmark).collect();
    assert!(parse_selection(selection(&excessive).as_bytes()).is_err());
    assert!(parse_selection(&vec![b' '; MAX_SELECTION_BYTES + 1]).is_err());
    Ok(())
}

#[test]
fn selected_feature_ordinals_resolve_against_the_actual_imported_twin() -> Test {
    let fixture = Fixture::new(2, 1)?;
    let mut chosen = checked(parse_selection(
        selection(&[landmark(0), landmark(1)]).as_bytes(),
    ))?;
    checked(validate_twin(&chosen, &fixture.twin))?;
    chosen.landmarks[1].feature = fixture.twin.features().len() as u32;
    assert!(validate_twin(&chosen, &fixture.twin).is_err());
    Ok(())
}

#[test]
fn all_four_existing_query_schemas_dispatch_and_bind_without_changing_declarations() -> Test {
    for count in [2, 3] {
        for version in [1, 2] {
            let fixture = Fixture::new(count, version)?;
            let query = fixture.query()?;
            assert_eq!(query.views().len(), count);
            assert_eq!(query.extraction().maximum_features, 128);
            assert_eq!(query.matching().reference_time_ns, 1050);
            assert_eq!(query.declarations(), json(&fixture.document));
            assert_eq!(matches!(query, MatchingQuery::Pair(_)), count == 2);
            let views = checked(query.bind(&fixture.resolved(), &fixture.rig))?;
            assert_eq!(views.len(), count);
            for (index, view) in views.iter().enumerate() {
                assert_eq!(view.frame.identity(), fixture.frames[index].identity());
                assert_eq!(view.frame.features(), fixture.frames[index].features());
                assert_eq!(view.capture, [990, 1110]);
                assert_eq!(
                    view.source_digest,
                    fixture.capsules[index].source_digest.bytes()
                );
            }
        }
    }
    Ok(())
}

#[test]
fn matching_dispatch_rejects_schema_aliases_mismatched_shape_and_old_field_overrides() -> Test {
    let fixture = Fixture::new(2, 1)?;
    for schema in [
        "fss.scene_feature_match_retained_query.v3",
        "fss.scene_feature_match_query.v1",
        multi::SCHEMA,
        SCHEMA,
        "fss.scene_feature_match_retained_query.v1 ",
    ] {
        let mut document = fixture.document.clone();
        *at(&mut document, &["schema"])? = Value::Text(schema.into());
        assert!(parse_matching(json(&document).as_bytes(), fixture.rig_digest).is_err());
    }
    assert!(parse_matching(json(&fixture.document).as_bytes(), h("wrong rig")).is_err());
    for version in [1, 2] {
        let fixture = Fixture::new(2, version)?;
        let mut document = fixture.document.clone();
        let Value::Object(view) = at(&mut document, &["left"])? else {
            return Err("fixture".into());
        };
        view.insert(
            if version == 1 {
                "image"
            } else {
                "image_domain_digest"
            }
            .into(),
            Value::Null,
        );
        assert!(parse_matching(json(&document).as_bytes(), fixture.rig_digest).is_err());
    }
    Ok(())
}

#[test]
fn matching_binding_preserves_complete_source_count_and_source_pin_checks() -> Test {
    for count in [2, 3] {
        let fixture = Fixture::new(count, 2)?;
        let query = fixture.query()?;
        let mut resolved = fixture.resolved();
        assert!(query.bind(&resolved[..count - 1], &fixture.rig).is_err());
        resolved[0].codec = "h264";
        assert!(query.bind(&resolved, &fixture.rig).is_err());
        resolved[0].codec = "jpeg";
        resolved[0].range_count = 2;
        assert!(query.bind(&resolved, &fixture.rig).is_err());
        resolved[0].range_count = 1;
        resolved[0].import_identity = h("wrong import");
        assert!(query.bind(&resolved, &fixture.rig).is_err());
        resolved[0].import_identity = h("import-1");
        resolved[0].allowed_mask_digest = [0; 32];
        assert!(query.bind(&resolved, &fixture.rig).is_err());
    }
    Ok(())
}

#[test]
fn multiview_dispatch_keeps_the_complete_actual_feature_inventory_limit() -> Test {
    let mut fixture = Fixture::new(3, 2)?;
    for (index, frame) in fixture.frames.iter_mut().enumerate() {
        *frame = Fixture::frame(index + 1, 86)?;
    }
    let query = fixture.query()?;
    assert!(query.bind(&fixture.resolved(), &fixture.rig).is_err());
    fixture.frames[2] = Fixture::frame(3, 84)?;
    let views = checked(query.bind(&fixture.resolved(), &fixture.rig))?;
    assert_eq!(
        views
            .iter()
            .map(|view| view.frame.features().len())
            .sum::<usize>(),
        256
    );
    Ok(())
}

#[test]
fn pair_dispatch_preserves_actual_native_rectification_receipt_and_rejects_substitution() -> Test {
    let mut fixture = Fixture::new(2, 2)?;
    *at(&mut fixture.document, &["left", "image"])? = json_input::parse(&object(&[
        ("kind", string("rectified")),
        (
            "source_domain_digest",
            pin(h("raw native image mode").bytes()),
        ),
        ("lens_basis", pin(h("explicit native lens model").bytes())),
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
    ]))?;
    let query = fixture.query()?;
    let target = fixture
        .rig
        .camera(1)
        .ok_or("fixture camera")?
        .camera
        .intrinsics;
    let mut work = WorkBudget::new(100_000_000);
    let prepared = checked(query.views()[0].image.prepare(target, &mut work))?;
    let plan = prepared.rectifier.ok_or("native rectifier")?;
    let mut state = 9_u32;
    let pixels: Vec<_> = (0..WIDTH * HEIGHT)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect();
    let allowed = vec![1_u8; pixels.len()];
    let raw = RawGrayFrame::new(
        RawFrameIdentity {
            exposure: fixture.frames[0].identity().exposure,
            storage: h(&pixels).bytes(),
            allowed_mask: h(&allowed).bytes(),
            image_domain: plan.spec().source_domain,
            calibration: plan.spec().calibration,
            dimensions: [WIDTH, HEIGHT],
            row_stride: WIDTH,
            range: LumaRange::Full,
        },
        &pixels,
        &allowed,
        &mut work,
    )?;
    let extracted = extract_raw_features(&plan, &raw, query.extraction(), &mut work)?;
    assert!(!extracted.result.frame.features().is_empty());
    let mut resolved = fixture.resolved();
    resolved[0].frame = &extracted.result.frame;
    resolved[0].luma = h(&pixels);
    resolved[0].allowed_mask_digest = extracted.result.selection.mask_digest;
    assert!(query.bind(&resolved, &fixture.rig).is_err());
    resolved[0].rectification = Some((plan.spec(), extracted.rectification));
    let views = checked(query.bind(&resolved, &fixture.rig))?;
    assert_eq!(views[0].frame.identity(), extracted.result.frame.identity());
    assert_eq!(views[0].image_domain_digest, prepared.domain.bytes());
    assert_eq!(
        views[0].allowed_mask_digest,
        extracted.rectification.allowed_mask
    );
    let mut altered = extracted.rectification;
    altered.source.storage = h("substituted luma").bytes();
    resolved[0].rectification = Some((plan.spec(), altered));
    assert!(query.bind(&resolved, &fixture.rig).is_err());
    Ok(())
}
