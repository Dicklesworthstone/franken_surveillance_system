#![forbid(unsafe_code)]
//! Real native types and geometry over synthetic source snapshots, without custody claims.

use super::*;
use crate::matching::fixtures::{HEIGHT, WIDTH, package, rig_document};
use fss_cli::json_input::{self, Value};
use fss_cli::json_output::{array, object, string};
use fss_core::{
    CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, DigestAlgorithm, SensorCapsule,
    SensorId, SensorSourceBytesSpec, StreamId, TimestampNs,
};
use fss_geometry::{GeometryBasis, WorkBudget};
use fss_twin::localization::{BinaryDescriptor, FeatureFrame, ImageFeature, ImageIdentity};
use fss_twin::multiview_feature_association::associate_multiview_features;
use fss_twin::{ImportExpectation, ImportLimits, PropertyTwin, import_twin};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn h(value: impl AsRef<[u8]>) -> ContentDigest {
    ContentDigest::sha256(value.as_ref())
}
fn pin(value: ContentDigest) -> String {
    string(&value.to_text())
}
fn checked<T>(value: Result<T>) -> TestResult<T> {
    value.map_err(|error| format!("{error:?}").into())
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
fn at_mut<'a>(value: &'a mut Value, path: &[&str]) -> TestResult<&'a mut Value> {
    let Some((key, rest)) = path.split_first() else {
        return Ok(value);
    };
    let next = match value {
        Value::Object(values) => values.get_mut(*key).ok_or("fixture field")?,
        Value::Array(values) => values.get_mut(key.parse::<usize>()?).ok_or("fixture row")?,
        _ => return Err("fixture container".into()),
    };
    at_mut(next, rest)
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
    fn new(count: usize, features: usize) -> TestResult<Self> {
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
        let mut rig_document = json_input::parse(&rig_document(&bytes))?;
        let template = at_mut(&mut rig_document, &["cameras", "0"])?.clone();
        let mut cameras = Vec::new();
        for index in 0..count {
            let mut camera = template.clone();
            *at_mut(&mut camera, &["camera"])? = Value::Number((index + 1).to_string());
            *at_mut(&mut camera, &["image_domain"])? = Value::Number((index + 1).to_string());
            *at_mut(&mut camera, &["source_object_id"])? =
                Value::Text(format!("synthetic_camera_{}", index + 1));
            *at_mut(&mut camera, &["world_to_camera", "translation"])? = Value::Array(vec![
                Value::Number((-(index as i64)).to_string()),
                Value::Number("0".into()),
                Value::Number("0".into()),
            ]);
            cameras.push(camera);
        }
        *at_mut(&mut rig_document, &["cameras"])? = Value::Array(cameras);
        let rig_digest = h(json(&rig_document));
        let rig = SceneRig::from_document(&rig_document, &twin, &mut WorkBudget::new(1_000_000))?;
        let mut capsules = Vec::new();
        let mut views = Vec::new();
        let mut frames = Vec::new();
        for index in 0..count {
            let id = index + 1;
            let capsule = SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
                capsule_id: CapsuleId::parse(format!("capsule:multi-match-{id}"))?,
                sensor_id: SensorId::parse(format!("sensor:multi-match-{id}"))?,
                stream_id: StreamId::parse(format!("stream:multi-match-{id}:g1"))?,
                sequence: 0,
                capture: CaptureInterval::new(TimestampNs(1000), TimestampNs(1100))?,
                receive_time: TimestampNs(1500),
                clock_basis: ClockBasis::Estimated,
                source: format!("synthetic original source {id}").as_bytes(),
                frame_count: 1,
                gap_before: false,
            })?;
            views.push(object(&[
                ("camera", id.to_string()),
                ("image_domain_digest", pin(h(format!("image-mode-{id}")))),
                ("mapping_basis", pin(h(format!("mapping-{id}")))),
                ("sigma_pixels", "0.5".into()),
                (
                    "source",
                    object(&[
                        ("codec", string("jpeg")),
                        ("import_identity", pin(h(format!("import-{id}")))),
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
                        ("import_identity", pin(h(format!("import-{id}")))),
                        ("stream_id", string(capsule.stream_id.as_str())),
                        ("clock_basis", string("estimated")),
                        ("offset_ns", "[0,0]".into()),
                        ("basis", pin(h(format!("clock-mapping-{id}")))),
                    ]),
                ),
            ]));
            frames.push(Self::frame(
                id,
                features,
                h("native descriptor generation").bytes(),
            )?);
            capsules.push(capsule);
        }
        let document = json_input::parse(&object(&[
            ("schema", string(SCHEMA)), ("camera_rig_digest", pin(rig_digest)),
            ("privacy_domain", "9".into()), ("clock", "11".into()),
            ("clock_evidence", pin(h("declared common clock"))),
            ("association_basis", pin(h("static-scene assumption"))),
            ("reference_time_ns", "1050".into()), ("max_capture_span_ns", "1000".into()),
            ("motion", string("static_during_capture_hull")), ("views", array(&views)),
            ("extraction", r#"{"threshold":20,"maximum_features":128,"separation":6}"#.into()),
            ("matching", r#"{"maximum_hamming_distance":0,"ratio_percent":80,"maximum_epipolar_distance_pixels":0.001}"#.into()),
        ]))?;
        Ok(Self {
            twin,
            rig,
            rig_digest,
            document,
            capsules,
            frames,
        })
    }
    fn frame(id: usize, count: usize, descriptor_domain: [u8; 32]) -> TestResult<FeatureFrame> {
        Ok(FeatureFrame::new(
            ImageIdentity {
                exposure: h(format!("exposure-{id}")).bytes(),
                pixels: h(format!("luma-{id}")).bytes(),
                image_domain: h(format!("image-mode-{id}")).bytes(),
                dimensions: [WIDTH, HEIGHT],
            },
            descriptor_domain,
            (0..count)
                .map(|index| ImageFeature {
                    id: index as u64 + 1,
                    pixel: [
                        32.0 + 4.0 * (index % 16) as f64,
                        32.0 + 4.0 * (index / 16) as f64,
                    ],
                    descriptor: BinaryDescriptor([index as u64; 4]),
                })
                .collect(),
            &mut WorkBudget::new(1_000_000),
        )?)
    }
    fn query(&self) -> TestResult<Query> {
        checked(parse(json(&self.document).as_bytes(), self.rig_digest))
    }
    fn resolved(&self) -> Vec<shared::ResolvedFrame<'_>> {
        self.frames
            .iter()
            .zip(&self.capsules)
            .enumerate()
            .map(|(index, (frame, capsule))| {
                let id = index + 1;
                shared::ResolvedFrame {
                    capsule,
                    import_identity: h(format!("import-{id}")),
                    segment: 0,
                    dimensions: [WIDTH, HEIGHT],
                    exposure: ContentDigest::new(
                        DigestAlgorithm::Sha256,
                        frame.identity().exposure,
                    ),
                    luma: ContentDigest::new(DigestAlgorithm::Sha256, frame.identity().pixels),
                    frame,
                    allowed_mask_digest: h(format!("allowed-{id}")).bytes(),
                    codec: "jpeg",
                    range_start: 0,
                    range_count: 1,
                    rectification: None,
                }
            })
            .collect()
    }
    fn set_capture(&mut self, index: usize, interval: [i128; 2]) -> TestResult {
        self.capsules[index].capture =
            CaptureInterval::new(TimestampNs(interval[0]), TimestampNs(interval[1]))?;
        let pin = h(self.capsules[index].try_canonical_bytes()?);
        *at_mut(
            &mut self.document,
            &["views", &index.to_string(), "source", "capsule_digest"],
        )? = Value::Text(pin.to_text());
        Ok(())
    }
}

fn pinhole_v2(document: &Value) -> TestResult<Value> {
    let mut result = document.clone();
    *at_mut(&mut result, &["schema"])? = Value::Text(SCHEMA_V2.into());
    let Value::Array(views) = at_mut(&mut result, &["views"])? else {
        return Err("views".into());
    };
    for view in views {
        let Value::Object(fields) = view else {
            return Err("view".into());
        };
        let domain = fields.remove("image_domain_digest").ok_or("image domain")?;
        fields.insert(
            "image".into(),
            Value::Object(std::collections::BTreeMap::from([
                ("kind".into(), Value::Text("pinhole".into())),
                ("image_domain_digest".into(), domain),
            ])),
        );
    }
    Ok(result)
}

#[test]
fn v2_multi_view_headers_preserve_inventory_and_refuse_mixed_or_unknown_versions() -> TestResult {
    let f = Fixture::new(8, 32)?;
    let old = f.query()?;
    let document = pinhole_v2(&f.document)?;
    let new = checked(parse(json(&document).as_bytes(), f.rig_digest))?;
    assert_eq!(old.version, 1);
    assert_eq!(new.version, 2);
    assert_eq!(old.matching, new.matching);
    assert_eq!(
        checked(bind(&new, &f.resolved(), &f.rig))?
            .iter()
            .map(|view| view.frame.features().len())
            .sum::<usize>(),
        256
    );
    assert_eq!(
        new.declarations,
        checked(parse(new.declarations.as_bytes(), f.rig_digest))?.declarations
    );
    for schema in [
        shared::SCHEMA_V2,
        "fss.scene_feature_multimatch_retained_query.v3",
        "fss.scene_feature_multimatch_retained_query.v02",
    ] {
        let mut changed = document.clone();
        *at_mut(&mut changed, &["schema"])? = Value::Text(schema.into());
        assert!(parse(json(&changed).as_bytes(), f.rig_digest).is_err());
    }
    let mut mixed = document.clone();
    *at_mut(&mut mixed, &["views", "7"])? =
        at_mut(&mut f.document.clone(), &["views", "7"])?.clone();
    assert!(parse(json(&mixed).as_bytes(), f.rig_digest).is_err());
    let mut old_mixed = f.document.clone();
    *at_mut(&mut old_mixed, &["views", "7"])? =
        at_mut(&mut document.clone(), &["views", "7"])?.clone();
    assert!(parse(json(&old_mixed).as_bytes(), f.rig_digest).is_err());
    Ok(())
}

#[test]
fn an_empty_corrected_view_keeps_both_image_domains_and_complete_source_checks() -> TestResult {
    use fss_geometry::PinholeIntrinsics;
    use fss_twin::localization::native::extract_gray;
    use fss_twin::rectification::{RawFrameIdentity, RawGrayFrame};
    let mut f = Fixture::new(3, 0)?;
    let mut document = pinhole_v2(&f.document)?;
    *at_mut(&mut document, &["views", "2", "image"])? = json_input::parse(&object(&[
        ("kind", string("rectified")),
        ("source_domain_digest", pin(h("third raw source mode"))),
        ("lens_basis", pin(h("third raw lens"))),
        (
            "source_intrinsics",
            r#"{"width":208,"height":144,"fx":160,"fy":160,"cx":104,"cy":72}"#.into(),
        ),
        ("distortion", r#"{"kind":"pinhole"}"#.into()),
        ("maximum_radius", "1".into()),
        ("luma_range", string("full")),
    ]))?;
    let query = checked(parse(json(&document).as_bytes(), f.rig_digest))?;
    let mut work = WorkBudget::new(100_000_000);
    let target = f.rig.camera(3).ok_or("third rig camera")?.camera.intrinsics;
    assert_eq!(
        target,
        PinholeIntrinsics::new(WIDTH, HEIGHT, 160.0, 160.0, 96.0, 64.0)?
    );
    let prepared = checked(query.views[2].image.prepare(target, &mut work))?;
    let plan = prepared.rectifier.ok_or("rectifier")?;
    let spec = plan.spec();
    let pixels = vec![128; 208 * 144];
    let allowed = vec![1; pixels.len()];
    let raw = RawGrayFrame::new(
        RawFrameIdentity {
            exposure: f.frames[2].identity().exposure,
            storage: h(&pixels).bytes(),
            allowed_mask: h(&allowed).bytes(),
            image_domain: spec.source_domain,
            calibration: spec.calibration,
            dimensions: [208, 144],
            row_stride: 208,
            range: spec.range,
        },
        &pixels,
        &allowed,
        &mut work,
    )?;
    let corrected = plan.apply(&raw, &mut work)?;
    let extraction = extract_gray(
        &corrected.as_gray_image(&mut work)?,
        query.extraction,
        &mut work,
    )?;
    assert!(extraction.frame.features().is_empty());
    for frame in f.frames.iter_mut().take(2) {
        *frame = FeatureFrame::new(
            frame.identity(),
            extraction.frame.descriptor_domain(),
            Vec::new(),
            &mut work,
        )?;
    }
    f.frames[2] = extraction.frame;
    let mut sources = f.resolved();
    sources[2].dimensions = [208, 144];
    sources[2].luma = h(&pixels);
    sources[2].allowed_mask_digest = extraction.selection.mask_digest;
    sources[2].rectification = Some((spec, corrected.receipt()));
    let views = checked(bind(&query, &sources, &f.rig))?;
    assert_eq!(views.len(), 3);
    assert_eq!(views[2].frame.identity().dimensions, [WIDTH, HEIGHT]);
    assert_eq!(views[2].image_domain_digest, prepared.domain.bytes());
    assert_ne!(views[2].image_domain_digest, spec.source_domain);
    assert_eq!(views[2].frame.identity().exposure, raw.identity().exposure);
    sources[2].luma = h("wrong raw source pixels");
    assert!(bind(&query, &sources, &f.rig).is_err());
    Ok(())
}

#[test]
fn three_and_eight_views_share_the_pair_headers_without_dropping_declarations() -> TestResult {
    for count in [3, 8] {
        let f = Fixture::new(count, 2)?;
        let query = f.query()?;
        assert_eq!(query.views.len(), count);
        assert_eq!(query.matching.triangulation.min_views, 2);
        assert_eq!(query.matching.triangulation.max_outliers, 0);
        assert_eq!(
            query.declarations,
            checked(parse(query.declarations.as_bytes(), f.rig_digest))?.declarations
        );
        assert_eq!(checked(bind(&query, &f.resolved(), &f.rig))?.len(), count);
        let mut pair = f.document.clone();
        let Value::Object(top) = &mut pair else {
            return Err("query object".into());
        };
        let Value::Array(mut rows) = top.remove("views").ok_or("views")? else {
            return Err("view list".into());
        };
        top.insert("schema".into(), Value::Text(shared::SCHEMA.into()));
        top.insert("right".into(), rows.remove(1));
        top.insert("left".into(), rows.remove(0));
        let pair = checked(shared::parse(json(&pair).as_bytes(), f.rig_digest))?;
        assert_eq!(query.matching, pair.matching);
        assert_eq!(
            query.extraction.maximum_features,
            pair.extraction.maximum_features
        );
        assert_eq!(query.extraction.threshold, pair.extraction.threshold);
        assert_eq!(
            query.views[0].source.pins().capsule_digest,
            pair.views[0].source.pins().capsule_digest
        );
    }
    Ok(())
}

#[test]
fn only_three_through_eight_views_are_admitted_and_pair_shape_is_not_an_alias() -> TestResult {
    let f = Fixture::new(3, 0)?;
    let Value::Array(rows) = at_mut(&mut f.document.clone(), &["views"])?.clone() else {
        return Err("views".into());
    };
    for count in [0, 1, 2, 9] {
        let mut document = f.document.clone();
        *at_mut(&mut document, &["views"])? = Value::Array(
            (0..count)
                .map(|index| rows[index % rows.len()].clone())
                .collect(),
        );
        assert!(parse(json(&document).as_bytes(), f.rig_digest).is_err());
    }
    let mut document = f.document.clone();
    let Value::Object(top) = &mut document else {
        return Err("query object".into());
    };
    top.insert("left".into(), rows[0].clone());
    assert!(parse(json(&document).as_bytes(), f.rig_digest).is_err());
    assert!(shared::parse(json(&f.document).as_bytes(), f.rig_digest).is_err());
    Ok(())
}

#[test]
fn empty_late_camera_extends_global_hull_without_requiring_scene_time_in_every_pair() -> TestResult
{
    let mut f = Fixture::new(3, 0)?;
    f.set_capture(2, [1300, 1310])?;
    *at_mut(&mut f.document, &["reference_time_ns"])? = Value::Number("1305".into());
    let query = f.query()?;
    let views = checked(bind(&query, &f.resolved(), &f.rig))?;
    assert_eq!(views[0].capture, [1000, 1100]);
    assert_eq!(views[2].capture, [1300, 1310]);
    let analysis = associate_multiview_features(
        &f.twin,
        &views,
        query.matching,
        &mut WorkBudget::new(10_000_000),
    )?;
    assert_eq!(analysis.capture_hull(), [1000, 1310]);
    assert_eq!(analysis.options().reference_time_ns, 1305);
    assert_eq!(analysis.pairs().len(), 3);
    assert_eq!(analysis.pairs()[0].requested_scene_time_ns(), 1305);
    assert_eq!(analysis.pairs()[0].solve_time_ns(), 1100);
    *at_mut(&mut f.document, &["reference_time_ns"])? = Value::Number("1311".into());
    assert!(bind(&f.query()?, &f.resolved(), &f.rig).is_err());
    *at_mut(&mut f.document, &["reference_time_ns"])? = Value::Number("1305".into());
    *at_mut(&mut f.document, &["max_capture_span_ns"])? = Value::Number("309".into());
    assert!(bind(&f.query()?, &f.resolved(), &f.rig).is_err());
    Ok(())
}

#[test]
fn actual_256_feature_inventory_is_exact_and_never_silently_truncated() -> TestResult {
    let f = Fixture::new(8, 32)?;
    let query = f.query()?;
    assert_eq!(query.extraction.maximum_features, 128);
    let views = checked(bind(&query, &f.resolved(), &f.rig))?;
    assert_eq!(
        views
            .iter()
            .map(|view| view.frame.features().len())
            .sum::<usize>(),
        256
    );
    let f = Fixture::new(8, 33)?;
    let query = f.query()?;
    assert!(bind(&query, &f.resolved(), &f.rig).is_err());
    let mut f = Fixture::new(3, 0)?;
    f.frames[0] = Fixture::frame(1, 129, h("native descriptor generation").bytes())?;
    assert!(bind(&f.query()?, &f.resolved(), &f.rig).is_err());
    Ok(())
}

#[test]
fn distant_rows_cannot_reuse_cameras_sensors_sources_or_capsules() -> TestResult {
    let f = Fixture::new(8, 0)?;
    for path in [
        vec!["camera"],
        vec!["source", "sensor_id"],
        vec!["source", "encoded_source_digest"],
        vec!["source", "capsule_digest"],
    ] {
        let mut document = f.document.clone();
        let mut first_path = vec!["views", "0"];
        first_path.extend_from_slice(&path);
        let first = at_mut(&mut document, &first_path)?.clone();
        let mut last_path = vec!["views", "7"];
        last_path.extend_from_slice(&path);
        *at_mut(&mut document, &last_path)? = first;
        assert!(
            parse(json(&document).as_bytes(), f.rig_digest).is_err(),
            "accepted {path:?}"
        );
    }
    let query = f.query()?;
    let mut sources = f.resolved();
    sources[7].capsule = &f.capsules[0];
    assert!(bind(&query, &sources, &f.rig).is_err());
    Ok(())
}

#[test]
fn every_owner_snapshot_is_checked_even_when_its_view_has_no_features() -> TestResult {
    let mut f = Fixture::new(3, 0)?;
    let query = f.query()?;
    for field in 0..6 {
        let mut sources = f.resolved();
        match field {
            0 => sources[2].import_identity = h("other import"),
            1 => sources[2].segment = 1,
            2 => sources[2].dimensions = [WIDTH + 1, HEIGHT],
            3 => sources[2].allowed_mask_digest = [0; 32],
            4 => sources[2].luma = h("other pixels"),
            _ => sources.swap(0, 2),
        }
        assert!(
            bind(&query, &sources, &f.rig).is_err(),
            "accepted source field {field}"
        );
    }
    assert!(bind(&query, &f.resolved()[..2], &f.rig).is_err());
    f.frames[2] = Fixture::frame(3, 0, h("different descriptor generation").bytes())?;
    assert!(bind(&query, &f.resolved(), &f.rig).is_err());
    Ok(())
}

#[test]
fn shared_view_rules_refuse_capture_mask_and_alignment_overrides_in_multi_view_queries()
-> TestResult {
    let f = Fixture::new(3, 0)?;
    for key in [
        "capture_ns",
        "dimensions",
        "mask",
        "features",
        "pixels",
        "unknown",
    ] {
        let mut document = f.document.clone();
        let Value::Object(view) = at_mut(&mut document, &["views", "2"])? else {
            return Err("view object".into());
        };
        view.insert(key.into(), Value::Null);
        assert!(parse(json(&document).as_bytes(), f.rig_digest).is_err());
    }
    let mut document = f.document.clone();
    *at_mut(
        &mut document,
        &["views", "2", "alignment", "import_identity"],
    )? = Value::Text(h("other import").to_text());
    assert!(parse(json(&document).as_bytes(), f.rig_digest).is_err());
    *at_mut(
        &mut document,
        &["views", "2", "alignment", "import_identity"],
    )? = Value::Text(h("import-3").to_text());
    *at_mut(&mut document, &["clock"])? = Value::Number("12".into());
    let query = checked(parse(json(&document).as_bytes(), f.rig_digest))?;
    assert!(bind(&query, &f.resolved(), &f.rig).is_err());
    Ok(())
}
