#![forbid(unsafe_code)]
//! Real native types and geometry over synthetic snapshots; no retained custody is asserted.

use super::*;
use crate::matching::fixtures::{HEIGHT, WIDTH, package, rig_document};
use fss_cli::json_output::{array, object, string};
use fss_core::{
    CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, DigestAlgorithm, SensorCapsule,
    SensorId, SensorSourceBytesSpec, StreamId, TimestampNs,
};
use fss_geometry::{GeometryBasis, WorkBudget};
use fss_twin::localization::native::descriptor_domain;
use fss_twin::localization::{BinaryDescriptor, FeatureFrame, ImageFeature, ImageIdentity};
use fss_twin::rectification::{LumaRange, RawFrameIdentity, RawGrayFrame, extract_raw_features};
use fss_twin::temporal_feature_association::{
    TemporalComponentOutcome, associate_temporal_features,
};
use fss_twin::{ImportExpectation, ImportLimits, PropertyTwin, import_twin};

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn h(value: impl AsRef<[u8]>) -> ContentDigest {
    ContentDigest::sha256(value.as_ref())
}
fn pin(value: ContentDigest) -> String {
    string(&value.to_text())
}
fn checked<T>(value: Result<T>) -> Test<T> {
    value.map_err(|e| format!("{e:?}").into())
}
fn at<'a>(value: &'a mut Value, path: &[&str]) -> Test<&'a mut Value> {
    let Some((key, rest)) = path.split_first() else {
        return Ok(value);
    };
    let child = match value {
        Value::Object(values) => values.get_mut(*key).ok_or("fixture key")?,
        Value::Array(values) => values.get_mut(key.parse::<usize>()?).ok_or("fixture row")?,
        _ => return Err("fixture container".into()),
    };
    at(child, rest)
}
fn replace(document: &Value, path: &[&str], replacement: Value) -> Test<String> {
    let mut document = document.clone();
    *at(&mut document, path)? = replacement;
    Ok(shared::json(&document))
}

struct Fixture {
    twin: PropertyTwin,
    rig: SceneRig,
    rig_digest: ContentDigest,
    document: Value,
    cameras: usize,
    capsules: Vec<SensorCapsule>,
    frames: Vec<FeatureFrame>,
}
impl Fixture {
    fn new(exposures: usize, cameras: usize, features: usize) -> Test<Self> {
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
        let template = at(&mut rig_value, &["cameras", "0"])?.clone();
        let mut camera_rows = Vec::new();
        for id in 1..=cameras {
            let mut camera = template.clone();
            *at(&mut camera, &["camera"])? = Value::Number(id.to_string());
            *at(&mut camera, &["image_domain"])? = Value::Number(id.to_string());
            *at(&mut camera, &["source_object_id"])? = Value::Text(format!("fixed_camera_{id}"));
            *at(&mut camera, &["validity_ns"])? = json_input::parse("[0,60000000000]")?;
            *at(&mut camera, &["world_to_camera", "translation"])? =
                json_input::parse(&format!("[{},0,0]", -(id as f64 - 1.0) * 0.5))?;
            camera_rows.push(camera);
        }
        *at(&mut rig_value, &["cameras"])? = Value::Array(camera_rows);
        let rig_digest = h(shared::json(&rig_value));
        let rig = SceneRig::from_document(&rig_value, &twin, &mut WorkBudget::new(1_000_000))?;
        let mut capsules = Vec::new();
        let mut frames = Vec::new();
        let mut views = Vec::new();
        for index in 0..exposures {
            let camera = index % cameras + 1;
            let epoch = index / cameras + 1;
            let time = epoch as i128 * 1_000_000_000;
            let capsule = SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
                capsule_id: CapsuleId::parse(format!("capsule:temporal-source-{index}"))?,
                sensor_id: SensorId::parse(format!("sensor:temporal-camera-{camera}"))?,
                stream_id: StreamId::parse(format!("stream:temporal-camera-{camera}:g1"))?,
                sequence: epoch as u64,
                capture: CaptureInterval::new(TimestampNs(time - 5), TimestampNs(time + 5))?,
                receive_time: TimestampNs(20_000_000_000),
                clock_basis: ClockBasis::Estimated,
                // Repeated bytes are legitimate distinct source exposures; no independence claim.
                source: format!("repeated encoded camera {camera} frame").as_bytes(),
                frame_count: 1,
                gap_before: false,
            })?;
            views.push(object(&[
                ("camera", camera.to_string()),
                (
                    "image",
                    object(&[
                        ("kind", string("pinhole")),
                        (
                            "image_domain_digest",
                            pin(h(format!("image-camera-{camera}"))),
                        ),
                    ]),
                ),
                ("mapping_basis", pin(h(format!("fixed-mapping-{camera}")))),
                ("sigma_pixels", "0.5".into()),
                (
                    "source",
                    object(&[
                        ("codec", string("jpeg")),
                        ("import_identity", pin(h(format!("source-import-{index}")))),
                        ("segment", "0".into()),
                        ("capsule_digest", pin(h(capsule.try_canonical_bytes()?))),
                        ("encoded_source_digest", pin(capsule.source_digest)),
                        ("sensor_id", string(capsule.sensor_id.as_str())),
                        ("component_interpretation", string("grayscale")),
                    ]),
                ),
                (
                    "alignment",
                    object(&[
                        ("import_identity", pin(h(format!("source-import-{index}")))),
                        ("stream_id", string(capsule.stream_id.as_str())),
                        ("clock_basis", string("estimated")),
                        ("offset_ns", "[-2,3]".into()),
                        ("basis", pin(h(format!("clock-mapping-{camera}")))),
                    ]),
                ),
            ]));
            frames.push(Self::frame(index, cameras, features)?);
            capsules.push(capsule);
        }
        let document = json_input::parse(&object(&[
            ("schema", string(SCHEMA)),
            ("camera_rig_digest", pin(rig_digest)),
            ("privacy_domain", "9".into()),
            ("clock", "11".into()),
            ("clock_evidence", pin(h("explicit common temporal clock"))),
            ("association_basis", pin(h("constant velocity correspondence hypothesis"))),
            ("reference_time_ns", "1500000000".into()),
            ("max_capture_span_ns", "59000000000".into()),
            ("max_capture_uncertainty_ns", "1000".into()),
            ("motion", string("constant_velocity_during_capture_hull")),
            ("views", array(&views)),
            ("extraction", r#"{"threshold":20,"maximum_features":128,"separation":6}"#.into()),
            ("matching", r#"{"maximum_hamming_distance":0,"ratio_percent":80}"#.into()),
            ("triangulation", r#"{"max_reprojection_pixels":0.001,"max_distance":1000,"max_speed":20,"max_condition_number":10000000000,"max_iterations":16}"#.into()),
        ]))?;
        Ok(Self {
            twin,
            rig,
            rig_digest,
            document,
            cameras,
            capsules,
            frames,
        })
    }
    fn frame(index: usize, cameras: usize, count: usize) -> Test<FeatureFrame> {
        let camera = index % cameras + 1;
        let t = (index / cameras + 1) as f64;
        // Independent pinhole projection of X(t)=X0+v*t; camera centers are 0.5 apart.
        let world = [0.2 + 0.25 * t, 0.1 + 0.1 * t, 8.0 + 0.1 * t];
        let pixel = [
            96.0 + 160.0 * (world[0] - 0.5 * (camera - 1) as f64) / world[2],
            64.0 + 160.0 * world[1] / world[2],
        ];
        Ok(FeatureFrame::new(
            ImageIdentity {
                exposure: h(format!("actual-exposure-{index}")).bytes(),
                pixels: h(format!("native-luma-{index}")).bytes(),
                image_domain: h(format!("image-camera-{camera}")).bytes(),
                dimensions: [WIDTH, HEIGHT],
            },
            descriptor_domain(),
            (0..count)
                .map(|point| ImageFeature {
                    id: point as u64 + 1,
                    pixel: if point == 0 {
                        pixel
                    } else {
                        [
                            10.5 + (point % 16) as f64 * 8.0,
                            10.5 + (point / 16) as f64 * 8.0,
                        ]
                    },
                    descriptor: BinaryDescriptor([point as u64 + 1, 3, 5, 7]),
                })
                .collect(),
            &mut WorkBudget::new(1_000_000),
        )?)
    }
    fn query(&self) -> Test<Query> {
        checked(parse(
            shared::json(&self.document).as_bytes(),
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
                import_identity: h(format!("source-import-{index}")),
                segment: 0,
                dimensions: [WIDTH, HEIGHT],
                exposure: ContentDigest::new(DigestAlgorithm::Sha256, frame.identity().exposure),
                luma: ContentDigest::new(DigestAlgorithm::Sha256, frame.identity().pixels),
                frame,
                allowed_mask_digest: h("complete source permission mask").bytes(),
                codec: "jpeg",
                range_start: 0,
                range_count: 1,
                rectification: None,
            })
            .collect()
    }
    fn set_capture(&mut self, index: usize, interval: [i128; 2]) -> Test {
        self.capsules[index].capture =
            CaptureInterval::new(TimestampNs(interval[0]), TimestampNs(interval[1]))?;
        self.repin(index)
    }
    fn repin(&mut self, index: usize) -> Test {
        *at(
            &mut self.document,
            &["views", &index.to_string(), "source", "capsule_digest"],
        )? = Value::Text(h(self.capsules[index].try_canonical_bytes()?).to_text());
        Ok(())
    }
}

#[test]
fn repeated_camera_exposures_bind_actual_full_intervals_and_preserve_complete_declarations() -> Test
{
    for (count, cameras) in [(4, 2), (6, 2), (16, 8)] {
        let f = Fixture::new(count, cameras, 1)?;
        let query = f.query()?;
        assert_eq!(query.views.len(), count);
        assert_eq!(query.matching.max_capture_span_ns, 59_000_000_000);
        assert_eq!(query.matching.max_capture_uncertainty_ns, 1000);
        assert_eq!(
            checked(parse(query.declarations.as_bytes(), f.rig_digest))?.declarations,
            query.declarations
        );
        let bound = checked(bind(&query, &f.resolved(), &f.rig))?;
        for (index, view) in bound.iter().enumerate() {
            let t = (index / cameras + 1) as u64 * 1_000_000_000;
            assert_eq!(view.capture, [t - 7, t + 8]);
            assert_eq!(view.frame.identity(), f.frames[index].identity());
            assert_eq!(view.frame.features(), f.frames[index].features());
        }
    }
    Ok(())
}

#[test]
fn repeated_encoded_bytes_do_not_replace_or_merge_distinct_actual_exposures() -> Test {
    let f = Fixture::new(4, 2, 1)?;
    assert_eq!(f.capsules[0].source_digest, f.capsules[2].source_digest);
    let query = f.query()?;
    let bound = checked(bind(&query, &f.resolved(), &f.rig))?;
    assert_eq!(bound[0].camera, bound[2].camera);
    assert_ne!(
        bound[0].frame.identity().exposure,
        bound[2].frame.identity().exposure
    );
    assert_ne!(bound[0].capture, bound[2].capture);
    Ok(())
}

#[test]
fn source_binding_feeds_native_position_velocity_fusion_with_permutation_invariance() -> Test {
    // A second actual feature supplies the strict ratio test's runner-up; absence of
    // descriptor competition is deliberately ambiguous in the native matcher.
    let mut f = Fixture::new(6, 2, 2)?;
    for (index, frame) in f.frames.iter_mut().enumerate() {
        let t = (index / 2 + 1) as f64;
        let center = 0.5 * (index % 2) as f64;
        let world = [0.7 + 0.15 * t, -0.1 + 0.05 * t, 9.0 - 0.05 * t];
        let mut features = frame.features().to_vec();
        features[1].pixel = [
            96.0 + 160.0 * (world[0] - center) / world[2],
            64.0 + 160.0 * world[1] / world[2],
        ];
        *frame = FeatureFrame::new(
            frame.identity(),
            frame.descriptor_domain(),
            features,
            &mut WorkBudget::new(1_000_000),
        )?;
    }
    let query = f.query()?;
    let views = checked(bind(&query, &f.resolved(), &f.rig))?;
    let report = associate_temporal_features(
        &f.twin,
        &views,
        query.matching,
        &mut WorkBudget::new(100_000_000),
    )?;
    assert_eq!(report.views().len(), 6);
    assert_eq!(report.pairs().len(), 15);
    assert_eq!(report.components().len(), 2);
    let component = &report.components()[0];
    assert_eq!(component.members().len(), 6);
    let TemporalComponentOutcome::Fused(motion) = component.outcome() else {
        return Err(format!(
            "known projected motion was refused: {:?}",
            component.outcome()
        )
        .into());
    };
    let t = query.matching.reference_time_ns as f64 * 1e-9;
    let expected_position = [0.2 + 0.25 * t, 0.1 + 0.1 * t, 8.0 + 0.1 * t];
    let estimate = motion.estimate();
    for (actual, expected) in estimate.position.iter().zip(expected_position) {
        assert!((actual - expected).abs() < 1e-7);
    }
    for (actual, expected) in estimate.velocity_per_second.iter().zip([0.25, 0.1, 0.1]) {
        assert!((actual - expected).abs() < 1e-7);
    }
    assert_eq!(motion.inputs().len(), 6);
    assert_eq!(estimate.residuals.len(), 6);
    assert_eq!(report.capture_hull(), [999_999_993, 3_000_000_008]);
    let mut reversed = f.document.clone();
    let Value::Array(rows) = at(&mut reversed, &["views"])? else {
        return Err("fixture views".into());
    };
    rows.reverse();
    let reordered = checked(parse(shared::json(&reversed).as_bytes(), f.rig_digest))?;
    let mut snapshots = f.resolved();
    snapshots.reverse();
    let reordered_views = checked(bind(&reordered, &snapshots, &f.rig))?;
    let reordered_report = associate_temporal_features(
        &f.twin,
        &reordered_views,
        reordered.matching,
        &mut WorkBudget::new(100_000_000),
    )?;
    assert_eq!(report.evidence(), reordered_report.evidence());
    assert_eq!(
        component.evidence(),
        reordered_report.components()[0].evidence()
    );
    Ok(())
}

#[test]
fn exact_motion_schema_rejects_static_epipolar_and_source_override_fields() -> Test {
    let f = Fixture::new(4, 2, 1)?;
    for (path, value) in [
        (vec!["schema"], Value::Text(shared::SCHEMA_V2.into())),
        (
            vec!["schema"],
            Value::Text("fss.scene_feature_motion_match_retained_query.v2".into()),
        ),
        (
            vec!["motion"],
            Value::Text("static_during_capture_hull".into()),
        ),
        (
            vec!["camera_rig_digest"],
            Value::Text(h("different rig").to_text()),
        ),
    ] {
        assert!(parse(replace(&f.document, &path, value)?.as_bytes(), f.rig_digest).is_err());
    }
    for (path, key) in [
        (vec!["matching"], "maximum_epipolar_distance_pixels"),
        (vec!["views", "0"], "image_domain_digest"),
        (vec!["views", "0"], "capture_ns"),
        (vec!["views", "0"], "pixels"),
        (vec!["views", "0"], "allowed_mask"),
        (vec!["views", "0"], "exposure_digest"),
    ] {
        let mut document = f.document.clone();
        let Value::Object(values) = at(&mut document, &path)? else {
            return Err("fixture object".into());
        };
        values.insert(key.into(), Value::Null);
        assert!(
            parse(shared::json(&document).as_bytes(), f.rig_digest).is_err(),
            "{key}"
        );
    }
    let text = shared::json(&f.document);
    assert!(
        parse(
            text.replacen("\"schema\":", "\"schema\":\"duplicate\",\"schema\":", 1)
                .as_bytes(),
            f.rig_digest
        )
        .is_err()
    );
    assert!(parse(format!("{text} {{}}").as_bytes(), f.rig_digest).is_err());
    Ok(())
}

#[test]
fn complete_exposure_and_fixed_camera_counts_have_hard_bounds() -> Test {
    for (exposures, cameras) in [(3, 2), (17, 2), (4, 1), (9, 9)] {
        let f = Fixture::new(exposures, cameras, 1)?;
        assert!(
            parse(shared::json(&f.document).as_bytes(), f.rig_digest).is_err(),
            "{exposures}/{cameras}"
        );
    }
    Ok(())
}

#[test]
fn duplicate_capsules_and_import_segment_selections_are_rejected_before_decoding() -> Test {
    let f = Fixture::new(4, 2, 1)?;
    for duplicate_capsule in [true, false] {
        let mut document = f.document.clone();
        if duplicate_capsule {
            let repeated = at(&mut document, &["views", "0", "source", "capsule_digest"])?.clone();
            *at(&mut document, &["views", "2", "source", "capsule_digest"])? = repeated;
        } else {
            for field in ["source", "alignment"] {
                *at(&mut document, &["views", "2", field, "import_identity"])? =
                    Value::Text(h("source-import-0").to_text());
            }
        }
        assert!(parse(shared::json(&document).as_bytes(), f.rig_digest).is_err());
    }
    Ok(())
}

#[test]
fn repeated_camera_requires_one_fixed_sensor_stream_alignment_and_image_mapping() -> Test {
    let f = Fixture::new(4, 2, 1)?;
    for (path, value) in [
        (
            vec!["source", "sensor_id"],
            Value::Text("sensor:another".into()),
        ),
        (
            vec!["alignment", "stream_id"],
            Value::Text("stream:another-generation".into()),
        ),
        (
            vec!["alignment", "clock_basis"],
            Value::Text("device_monotonic".into()),
        ),
        (vec!["alignment", "offset_ns"], json_input::parse("[-1,3]")?),
        (
            vec!["alignment", "basis"],
            Value::Text(h("different clock evidence").to_text()),
        ),
        (
            vec!["image", "image_domain_digest"],
            Value::Text(h("different image generation").to_text()),
        ),
        (
            vec!["mapping_basis"],
            Value::Text(h("different physical mapping").to_text()),
        ),
    ] {
        let mut full = vec!["views", "2"];
        full.extend(path);
        assert!(
            parse(replace(&f.document, &full, value)?.as_bytes(), f.rig_digest).is_err(),
            "{full:?}"
        );
    }
    let mut shared_sensor = f.document.clone();
    for index in [1, 3] {
        *at(
            &mut shared_sensor,
            &["views", &index.to_string(), "source", "sensor_id"],
        )? = Value::Text("sensor:temporal-camera-1".into());
    }
    assert!(parse(shared::json(&shared_sensor).as_bytes(), f.rig_digest).is_err());
    // Pixel-noise assumptions may differ by exposure without changing the camera snapshot.
    let changed = replace(
        &f.document,
        &["views", "2", "sigma_pixels"],
        Value::Number("0.75".into()),
    )?;
    let changed = checked(parse(changed.as_bytes(), f.rig_digest))?;
    assert_eq!(
        checked(bind(&changed, &f.resolved(), &f.rig))?[2].sigma_pixels,
        0.75
    );
    Ok(())
}

#[test]
fn native_temporal_solver_bounds_are_admitted_before_any_source_work() -> Test {
    let f = Fixture::new(4, 2, 1)?;
    for (key, invalid) in [
        ("max_capture_span_ns", "0"),
        ("max_capture_span_ns", "60000000001"),
        ("max_capture_uncertainty_ns", "59000000001"),
    ] {
        assert!(
            parse(
                replace(&f.document, &[key], Value::Text(invalid.into()))?.as_bytes(),
                f.rig_digest
            )
            .is_err()
        );
    }
    for (key, invalid) in [
        ("max_reprojection_pixels", "0"),
        ("max_distance", "-1"),
        ("max_speed", "0"),
        ("max_condition_number", "0.5"),
        ("max_iterations", "33"),
    ] {
        assert!(
            parse(
                replace(
                    &f.document,
                    &["triangulation", key],
                    Value::Number(invalid.into())
                )?
                .as_bytes(),
                f.rig_digest
            )
            .is_err()
        );
    }
    for (key, invalid) in [
        ("maximum_hamming_distance", "257"),
        ("ratio_percent", "100"),
    ] {
        assert!(
            parse(
                replace(
                    &f.document,
                    &["matching", key],
                    Value::Number(invalid.into())
                )?
                .as_bytes(),
                f.rig_digest
            )
            .is_err()
        );
    }
    for value in [Value::Text("015".into()), Value::Number("1.5".into())] {
        assert!(
            parse(
                replace(&f.document, &["max_capture_uncertainty_ns"], value)?.as_bytes(),
                f.rig_digest
            )
            .is_err()
        );
    }
    let exact = replace(
        &f.document,
        &["max_capture_span_ns"],
        Value::Text("60000000000".into()),
    )?;
    assert_eq!(
        checked(parse(exact.as_bytes(), f.rig_digest))?
            .matching
            .max_capture_span_ns,
        60_000_000_000
    );
    Ok(())
}

#[test]
fn full_alignment_uncertainty_and_source_interval_extremes_are_not_midpoint_substituted() -> Test {
    let mut f = Fixture::new(4, 2, 1)?;
    let mut query = f.query()?;
    query.matching.max_capture_uncertainty_ns = 14;
    assert!(bind(&query, &f.resolved(), &f.rig).is_err());
    query.matching.max_capture_uncertainty_ns = 15;
    checked(bind(&query, &f.resolved(), &f.rig))?;
    f.set_capture(3, [2_000_000_000, 2_000_002_000])?;
    assert!(bind(&f.query()?, &f.resolved(), &f.rig).is_err());
    f.set_capture(3, [0, 1])?;
    assert!(bind(&f.query()?, &f.resolved(), &f.rig).is_err()); // offset lower endpoint is negative.
    f.set_capture(3, [i128::MAX - 1, i128::MAX])?;
    assert!(bind(&f.query()?, &f.resolved(), &f.rig).is_err());
    Ok(())
}

#[test]
fn empty_exposures_still_extend_the_global_hull_and_undergo_all_source_checks() -> Test {
    let mut f = Fixture::new(6, 2, 1)?;
    f.frames[5] = Fixture::frame(5, 2, 0)?;
    f.set_capture(5, [10_000_000_000, 10_000_000_000])?;
    let mut query = f.query()?;
    query.matching.reference_time_ns = 9_000_000_000;
    let views = checked(bind(&query, &f.resolved(), &f.rig))?;
    assert_eq!(views.len(), 6);
    assert!(views[5].frame.features().is_empty());
    assert_eq!(views[5].capture, [9_999_999_998, 10_000_000_003]);
    query.matching.max_capture_span_ns = 8_000_000_000;
    assert!(bind(&query, &f.resolved(), &f.rig).is_err());
    query.matching.max_capture_span_ns = 59_000_000_000;
    let mut sources = f.resolved();
    sources[5].luma = h("wrong empty source luma");
    assert!(bind(&query, &sources, &f.rig).is_err());
    Ok(())
}

#[test]
fn the_complete_actual_feature_inventory_is_256_without_dropping_exposures() -> Test {
    let mut f = Fixture::new(4, 2, 64)?;
    let query = f.query()?;
    assert_eq!(
        checked(bind(&query, &f.resolved(), &f.rig))?
            .iter()
            .map(|v| v.frame.features().len())
            .sum::<usize>(),
        256
    );
    f.frames[3] = Fixture::frame(3, f.cameras, 65)?;
    assert!(bind(&query, &f.resolved(), &f.rig).is_err());
    assert!(bind(&query, &f.resolved()[..3], &f.rig).is_err());
    Ok(())
}

#[test]
fn duplicate_exposure_capsule_identity_and_mixed_descriptor_generations_are_refused() -> Test {
    let mut f = Fixture::new(4, 2, 1)?;
    let query = f.query()?;
    let mut sources = f.resolved();
    sources[2].exposure = sources[0].exposure;
    assert!(bind(&query, &sources, &f.rig).is_err());
    drop(sources);
    f.capsules[2].capsule_id = f.capsules[0].capsule_id.clone();
    f.repin(2)?;
    assert!(bind(&f.query()?, &f.resolved(), &f.rig).is_err());
    let mut f = Fixture::new(4, 2, 1)?;
    f.frames[2] = FeatureFrame::new(
        f.frames[2].identity(),
        h("foreign descriptor generation").bytes(),
        f.frames[2].features().to_vec(),
        &mut WorkBudget::new(1_000_000),
    )?;
    assert!(bind(&f.query()?, &f.resolved(), &f.rig).is_err());
    Ok(())
}

#[test]
fn source_native_grid_mask_and_complete_decoder_range_remain_bound() -> Test {
    let f = Fixture::new(4, 2, 1)?;
    let query = f.query()?;
    for case in 0..6 {
        let mut sources = f.resolved();
        match case {
            0 => sources[3].import_identity = h("wrong retained import"),
            1 => sources[3].codec = "h264",
            2 => sources[3].range_count = 2,
            3 => sources[3].allowed_mask_digest = [0; 32],
            4 => sources[3].dimensions = [WIDTH - 1, HEIGHT],
            _ => sources[3].segment = 1,
        }
        assert!(bind(&query, &sources, &f.rig).is_err());
    }
    let mut query = f.query()?;
    query.matching.privacy_domain += 1;
    assert!(bind(&query, &f.resolved(), &f.rig).is_err());
    query.matching.privacy_domain -= 1;
    query.matching.clock += 1;
    assert!(bind(&query, &f.resolved(), &f.rig).is_err());
    Ok(())
}

#[test]
fn repeated_camera_rectification_preserves_each_actual_exposure_and_receipt() -> Test {
    let mut f = Fixture::new(4, 2, 1)?;
    let image = json_input::parse(&object(&[
        ("kind", string("rectified")),
        ("source_domain_digest", pin(h("raw fixed camera mode"))),
        ("lens_basis", pin(h("fixed Brown-Conrady lens"))),
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
    for index in [0, 2] {
        *at(&mut f.document, &["views", &index.to_string(), "image"])? = image.clone();
    }
    let query = f.query()?;
    let camera = f.rig.camera(1).ok_or("camera")?.camera.intrinsics;
    let mut work = WorkBudget::new(200_000_000);
    let prepared = checked(query.views[0].image.prepare(camera, &mut work))?;
    let plan = prepared.rectifier.ok_or("native plan")?;
    let mut state = 7_u32;
    let pixels: Vec<_> = (0..WIDTH * HEIGHT)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect();
    let allowed = vec![1_u8; pixels.len()];
    let mut extracted = Vec::new();
    for index in [0, 2] {
        let raw = RawGrayFrame::new(
            RawFrameIdentity {
                exposure: f.frames[index].identity().exposure,
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
        extracted.push(extract_raw_features(
            &plan,
            &raw,
            ExtractionOptions {
                maximum_features: 32,
                ..query.extraction
            },
            &mut work,
        )?);
    }
    let mut sources = f.resolved();
    for (ordinal, index) in [0, 2].into_iter().enumerate() {
        sources[index].frame = &extracted[ordinal].result.frame;
        sources[index].luma = h(&pixels);
        sources[index].allowed_mask_digest = extracted[ordinal].result.selection.mask_digest;
        sources[index].rectification = Some((plan.spec(), extracted[ordinal].rectification));
    }
    let views = checked(bind(&query, &sources, &f.rig))?;
    assert_eq!(views[0].image_domain_digest, views[2].image_domain_digest);
    assert_eq!(
        views[0].frame.identity().pixels,
        views[2].frame.identity().pixels
    );
    assert_ne!(
        views[0].frame.identity().exposure,
        views[2].frame.identity().exposure
    );
    assert!(!views[0].frame.features().is_empty());
    sources[2].rectification = Some((plan.spec(), extracted[0].rectification));
    assert!(bind(&query, &sources, &f.rig).is_err());
    Ok(())
}
