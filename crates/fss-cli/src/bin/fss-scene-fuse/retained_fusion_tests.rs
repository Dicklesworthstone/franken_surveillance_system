#![forbid(unsafe_code)]
//! Actual source custody, native detector/tracker and command boundaries for retained fusion.
//! Synthetic coefficients and authored camera poses test composition, not trained accuracy.

use super::*;
use fss_cli::agent_json::array;
use fss_cli::json_input::{Value, parse};
use fss_cli::retained_continuity_query::anchor_digest;
use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::{ClockBasis, LedgerAnchor, SensorId, StreamId, TimestampNs};
use fss_reference::ScalarExecCx;
use fss_reference::ingest::package_detect::{
    PackageDetectLimits, PackageDetectRequest, run_package_detection,
};
use fss_reference::ingest::package_event::{
    PackageAnalysisReport, PackageTrackingConfig, retain_package_detection,
};
use fss_reference::ingest::package_handoffs::{
    PackageClockAlignment, PackageHandoffBinding, PackageHandoffRequest, PackageHandoffSelection,
    PackageHandoffTracking,
};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::{
    CaptureHint, FileIngestAdapter, FileIngestRequest, RetainedFileImport, RetainedReadLimits,
};

#[path = "../../../../fss-reference/tests/package_zone_support/mod.rs"]
mod native_fixture;
use native_fixture::{Test, jpeg, package};

const SITE: &str = "site:retained-fusion-tests";
const PRINCIPAL: &str = "principal:retained-fusion-tests";
const POSITION: [f64; 3] = [0.0, 0.0, 6.0];
const CENTERS: [[f64; 3]; 3] = [[-2.0, 0.0, 0.0], [2.0, 0.0, 0.0], [0.0, 2.0, 0.0]];

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-retained-fusion-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("fixture directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn cli<T>(value: Result<T>) -> Test<T> {
    value.map_err(|e| format!("{}: {}", e.code, e.detail).into())
}
fn d(value: ContentDigest) -> String {
    string(&value.to_text())
}
fn digest(value: &str) -> ContentDigest {
    ContentDigest::sha256(value.as_bytes())
}
fn vector<const N: usize>(value: [f64; N]) -> String {
    array(&value.map(|v| v.to_string()))
}
fn json(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.clone(),
        Value::Text(v) => string(v),
        Value::Array(v) => array(&v.iter().map(json).collect::<Vec<_>>()),
        Value::Object(v) => object(
            &v.iter()
                .map(|(key, value)| (key.as_str(), json(value)))
                .collect::<Vec<_>>(),
        ),
    }
}
fn field<'a>(value: &'a Value, path: &[&str]) -> Test<&'a Value> {
    if path.is_empty() {
        return Ok(value);
    }
    let next = match value {
        Value::Object(values) => values.get(path[0]).ok_or("missing object field")?,
        Value::Array(values) => values
            .get(path[0].parse::<usize>()?)
            .ok_or("missing array row")?,
        _ => return Err("not a JSON container".into()),
    };
    field(next, &path[1..])
}
fn put(value: &mut Value, path: &[&str], new: Value) -> Test {
    if path.is_empty() {
        *value = new;
        return Ok(());
    }
    let next = match value {
        Value::Object(values) => values.get_mut(path[0]).ok_or("missing object field")?,
        Value::Array(values) => values
            .get_mut(path[0].parse::<usize>()?)
            .ok_or("missing array row")?,
        _ => return Err("not a JSON container".into()),
    };
    put(next, &path[1..], new)
}

fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:retained-fusion-test".into(),
        operation_id: OperationId::parse("operation:retained-fusion-test")?,
        principal: PRINCIPAL.into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(512 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: digest(SITE),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

// Minimal explicit relative-unit twin with one non-opaque triangle. No Blender or model
// runtime is involved in the reconstruction, and authored geometry is not a certificate.
fn twin_bytes() -> Vec<u8> {
    fn text(out: &mut Vec<u8>, value: &str) {
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    let mut body = digest("synthetic retained fusion scene").bytes().to_vec();
    text(&mut body, "synthetic_retained_fusion");
    text(&mut body, "fixture_epoch");
    body.push(0);
    for value in [0.0_f64, -1.0, -1.0] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    for value in [1_u32, 1, 3, 1] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    text(&mut body, "wall");
    body.push(5);
    text(&mut body, "wall");
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&[0, 0]);
    for point in [
        [-10.0_f64, -10.0, 4.0],
        [10.0, -10.0, 4.0],
        [0.0, 10.0, 4.0],
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
    bytes.extend_from_slice(&ContentDigest::sha256(&bytes).bytes());
    bytes
}

fn selection(value: &PackageHandoffSelection) -> String {
    object(&[
        ("id", string(&value.id)),
        ("report_digest", d(value.report_digest)),
        ("label", string(&value.label)),
        (
            "tracking",
            "{\"confirmation_hits\":2,\"maximum_missed_frames\":1,\"minimum_iou_ppm\":0}".into(),
        ),
        ("track", d(value.track)),
        ("calibration", d(value.calibration)),
        (
            "alignment",
            object(&[
                ("import_identity", d(value.alignment.import_identity)),
                ("stream_id", string(&value.alignment.stream_id)),
                ("clock_basis", string(value.alignment.clock_basis.as_str())),
                ("offset_ns", "[0,0]".into()),
                ("basis", d(value.alignment.basis)),
            ]),
        ),
    ])
}

struct Fixture {
    directory: Directory,
    root: PathBuf,
    twin: PathBuf,
    rig: PathBuf,
    selection: PathBuf,
    report: PathBuf,
    query: Value,
    bindings: Vec<PackageHandoffBinding>,
    head: LedgerAnchor,
    source_chunk: PathBuf,
    capsule: PathBuf,
}
impl Fixture {
    fn new(label: &str) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let model_bytes = package()?;
        let scalar = ScalarExecCx::new();
        let model = RgbDetectorPackage::load(
            &model_bytes,
            ContentDigest::sha256(&model_bytes),
            1 << 40,
            &cx,
            &scalar,
        )?;
        let mut selections = Vec::new();
        for id in ["a", "b", "c"] {
            let path = directory.0.join(format!("source-{id}.mjpeg"));
            fs::write(
                &path,
                [192, 224, 240]
                    .into_iter()
                    .flat_map(jpeg)
                    .collect::<Vec<_>>(),
            )?;
            let stream = format!("stream:retained-fusion-{id}");
            let imported = FileIngestAdapter::ingest(
                FileIngestRequest::new(
                    &path,
                    SensorId::parse(format!("sensor:retained-fusion-{id}"))?,
                    StreamId::parse(&stream)?,
                )
                .with_receive_time(TimestampNs(10_000_000_000))
                .with_capture_hint(CaptureHint::new(
                    TimestampNs(1_500_000_000),
                    1_000_000,
                    10.0,
                )?),
                &cx,
                &mut deployment,
            )?;
            fs::remove_file(path)?;
            let detected = run_package_detection(
                &deployment,
                &model,
                &PackageDetectRequest {
                    import_identity: imported.import_identity,
                    first_segment: 0,
                    segment_count: 3,
                    interpretation: ComponentInterpretation::YCbCr,
                    minimum_score_ppm: None,
                },
                &PackageDetectLimits::default(),
                &cx,
                &scalar,
            )?;
            retain_package_detection(&mut deployment, &model, &detected, &cx)?;
            let report = PackageAnalysisReport::read(
                &deployment,
                detected.digest,
                "numeric-a",
                PackageTrackingConfig {
                    confirmation_hits: 2,
                    maximum_missed_frames: 1,
                    minimum_iou_ppm: 0,
                },
                &cx,
            )?;
            assert_eq!(report.tracks().len(), 1);
            selections.push(PackageHandoffSelection {
                id: id.into(),
                report_digest: detected.digest,
                label: "numeric-a".into(),
                tracking: PackageHandoffTracking {
                    confirmation_hits: 2,
                    maximum_missed_frames: 1,
                    minimum_iou_ppm: 0,
                },
                track: report.tracks()[0].identity,
                calibration: digest(&format!("declared fixture calibration {id}")),
                alignment: PackageClockAlignment {
                    import_identity: imported.import_identity,
                    stream_id: stream,
                    clock_basis: ClockBasis::Estimated,
                    offset_ns: [0, 0],
                    basis: digest("explicit fixture common-clock assumption"),
                },
            });
        }
        let request = PackageHandoffRequest {
            session: "session:retained-fusion-test".into(),
            generation: digest("declared analysis generation"),
            clock: digest("declared common clock"),
            cost_unit: "unused".into(),
            birth_cost: 0,
            end_cost: 0,
            k: 1,
            selections,
            transitions: vec![],
        };
        let projected = PackageHandoffProjection::read(&deployment, &request, &cx)?;
        let bindings = projected.bindings().to_vec();
        let source = RetainedFileImport::open(
            &deployment,
            bindings[0].import_identity,
            RetainedReadLimits::default(),
            &cx,
        )?;
        let source_chunk = deployment
            .publisher()
            .spool()
            .object_path(source.manifest().ordered_chunks[0]);
        let capsule = deployment
            .publisher()
            .spool()
            .object_path(bindings[0].observations[1].capsule_digest);
        let head = deployment.current_anchor().clone();
        let twin = directory.0.join("property.fsstwin");
        let rig = directory.0.join("cameras.json");
        let selection_path = directory.0.join("selection.json");
        let report = directory.0.join("report.json");
        let twin_data = twin_bytes();
        fs::write(&twin, &twin_data)?;
        let mut cameras = Vec::new();
        let mut mappings = Vec::new();
        let mut observations = Vec::new();
        for (index, binding) in bindings.iter().enumerate() {
            assert_eq!(binding.dimensions, [32, 16]);
            assert_eq!(binding.observations.len(), 3);
            let observation = &binding.observations[1];
            let bounds = observation.bounds.map(|n| n as f64 / 256.0);
            let pixel = [(bounds[0] + bounds[2]) * 0.5, (bounds[1] + bounds[3]) * 0.5];
            let center = CENTERS[index];
            let principal = [
                pixel[0] - 12.0 * (POSITION[0] - center[0]) / (POSITION[2] - center[2]),
                pixel[1] - 12.0 * (POSITION[1] - center[1]) / (POSITION[2] - center[2]),
            ];
            cameras.push(object(&[
                ("camera", (index + 1).to_string()),
                ("calibration", "1".into()),
                ("image_domain", "1".into()),
                ("clock", "11".into()),
                ("privacy_domain", "9".into()),
                ("validity_ns", "[0,10000000000]".into()),
                ("source_object_id", string(&format!("camera_{}", index + 1))),
                ("image_model", string("undistorted_pinhole")),
                ("status", string("authored_nominal")),
                ("error", "null".into()),
                (
                    "world_to_camera",
                    object(&[
                        ("rotation", "[[1,0,0],[0,1,0],[0,0,1]]".into()),
                        ("translation", vector(center.map(|n| -n))),
                    ]),
                ),
                (
                    "intrinsics",
                    object(&[
                        ("width", "32".into()),
                        ("height", "16".into()),
                        ("fx", "12".into()),
                        ("fy", "12".into()),
                        ("cx", principal[0].to_string()),
                        ("cy", principal[1].to_string()),
                    ]),
                ),
            ]));
            mappings.push(object(&[
                ("selection", string(&binding.id)),
                ("camera", (index + 1).to_string()),
                ("camera_generation", d(binding.camera_generation)),
                ("calibration", d(binding.calibration)),
                ("image_domain", "1".into()),
                (
                    "mapping_basis",
                    d(digest("synthetic source-to-camera declaration")),
                ),
                (
                    "image_domain_basis",
                    d(digest("synthetic source pixels are pinhole pixels")),
                ),
            ]));
            observations.push(object(&[
                ("selection", string(&binding.id)),
                ("segment", observation.segment.to_string()),
                ("detection_row", observation.detection_row.to_string()),
                ("capsule_digest", d(observation.capsule_digest)),
                ("pixel_min", vector(pixel)),
                ("pixel_max", vector(pixel)),
                ("visible_contact", "true".into()),
                ("sigma_pixels", "0.5".into()),
                (
                    "contact_basis",
                    d(digest("synthetic corresponding box-interior feature")),
                ),
            ]));
        }
        let rig_data = object(&[
            ("schema", string("fss.scene_camera_rig.v1")),
            (
                "source_scene_digest",
                d(digest("synthetic retained fusion scene")),
            ),
            ("twin_digest", d(ContentDigest::sha256(&twin_data))),
            ("geometry_basis", "{\"property\":7,\"revision\":2}".into()),
            ("coordinate_frame", string("RH_Z_UP")),
            ("evaluation_scope", string("synthetic_retained_fusion")),
            ("cameras", array(&cameras)),
        ]);
        fs::write(&rig, &rig_data)?;
        let query_data = object(&[
            ("schema", string("fss.scene_fusion_retained_query.v1")),
            ("session", string(&request.session)),
            ("generation", d(request.generation)),
            ("clock_evidence", d(request.clock)),
            (
                "camera_rig_digest",
                d(ContentDigest::sha256(rig_data.as_bytes())),
            ),
            ("privacy_domain", "9".into()),
            ("clock", "11".into()),
            ("reference_time_ns", "1600000000".into()),
            (
                "selections",
                array(&request.selections.iter().map(selection).collect::<Vec<_>>()),
            ),
            ("camera_bindings", array(&mappings)),
            (
                "hypotheses",
                array(&[object(&[
                    ("id", string("one-shared-feature")),
                    (
                        "association_evidence",
                        d(digest("explicit same-feature hypothesis")),
                    ),
                    ("max_capture_span_ns", "10000000".into()),
                    ("motion", "{\"kind\":\"static\"}".into()),
                    ("observations", array(&observations)),
                ])]),
            ),
        ]);
        fs::write(&selection_path, &query_data)?;
        let query = parse(&query_data)?;
        drop(deployment);
        cx.drain_and_finalize();
        Ok(Self {
            directory,
            root,
            twin,
            rig,
            selection: selection_path,
            report,
            query,
            bindings,
            head,
            source_chunk,
            capsule,
        })
    }

    fn options(&self) -> Test<Options> {
        Ok(Options {
            root: self.root.clone(),
            site: SITE.into(),
            principal: PRINCIPAL.into(),
            twin: self.twin.clone(),
            rig: self.rig.clone(),
            selection: self.selection.clone(),
            report_out: Some(self.report.clone()),
            expected_input: Some(ContentDigest::sha256(&fs::read(&self.selection)?)),
            expected_anchor: Some(anchor_digest(&self.head)),
            work: 100_000_000,
            timeout: Duration::from_secs(30),
            report_bytes: 8 * 1024 * 1024,
        })
    }
    fn write_query(&self, value: &Value) -> Test {
        fs::write(&self.selection, json(value))?;
        Ok(())
    }
    fn assert_head(&self, expected: &LedgerAnchor) -> Test {
        let cx = context(&self.root)?;
        let deployment = ReferenceDeployment::reopen(&self.root, SITE, &cx)?;
        assert_eq!(deployment.current_anchor(), expected);
        drop(deployment);
        cx.drain_and_finalize();
        Ok(())
    }
    fn refused(&self, options: &Options) -> Test {
        let mut stdout = Vec::new();
        assert!(execute(options, &mut stdout).is_err());
        assert!(stdout.is_empty());
        assert!(!self.report.exists());
        self.assert_head(&self.head)
    }
}

#[test]
fn actual_retained_detections_reconstruct_a_shared_point_and_replay_exactly() -> Test {
    let f = Fixture::new("complete")?;
    for id in ["a", "b", "c"] {
        assert!(!f.directory.0.join(format!("source-{id}.mjpeg")).exists());
    }
    let mut options = f.options()?;
    let mut stdout = Vec::new();
    assert!(cli(execute(&options, &mut stdout))?);
    assert_eq!(stdout, fs::read(&f.report)?);
    let text = std::str::from_utf8(&stdout)?;
    let value = parse(text)?;
    assert_eq!(
        field(&value, &["schema"])?.text(),
        Some("fss.scene_fusion_retained.v1")
    );
    assert_eq!(
        field(&value, &["report", "source_provenance"])?.text(),
        Some("verified_retained_package_observations")
    );
    assert_eq!(
        field(&value, &["report", "authority"])?.text(),
        Some("derived_cognition_no_effect_authority")
    );
    let raw_body = text
        .trim_end()
        .strip_suffix('}')
        .ok_or("wrapper end")?
        .split_once(",\"report\":")
        .ok_or("wrapper body")?
        .1;
    assert_eq!(
        field(&value, &["report_digest"])?.text(),
        Some(
            ContentDigest::sha256(raw_body.as_bytes())
                .to_text()
                .as_str()
        )
    );
    let projected = field(&value, &["report", "bindings"])?
        .array()
        .ok_or("bindings")?;
    assert_eq!(projected.len(), 3);
    for (row, expected) in projected.iter().zip(&f.bindings) {
        assert_eq!(
            field(row, &["sensor_id"])?.text(),
            Some(expected.sensor_id.as_str())
        );
        assert_eq!(field(row, &["clock_basis"])?.text(), Some("estimated"));
        assert_eq!(
            field(row, &["capture_time_label"])?.text(),
            Some("operator_assumption")
        );
        let observations = field(row, &["observations"])?
            .array()
            .ok_or("observations")?;
        assert_eq!(observations.len(), 3);
        for (actual, original) in observations.iter().zip(&expected.observations) {
            assert_eq!(
                field(actual, &["source_digest"])?.text(),
                Some(original.source_digest.to_text().as_str())
            );
            assert_eq!(
                field(actual, &["capsule_digest"])?.text(),
                Some(original.capsule_digest.to_text().as_str())
            );
            assert_eq!(
                field(actual, &["score_bits"])?.integer(),
                Some(i128::from(original.score_bits))
            );
            assert_eq!(
                field(actual, &["confirmed"])?,
                &Value::Bool(original.confirmed)
            );
            for (index, endpoint) in original.capture.into_iter().enumerate() {
                assert_eq!(
                    field(actual, &["capture", &index.to_string()])?.integer(),
                    Some(endpoint)
                );
            }
        }
    }
    let geometry = field(&value, &["report", "geometry", "report"])?;
    assert_eq!(
        field(geometry, &["assumptions", "source_custody"])?.text(),
        Some("retained_package_projection_verified_and_revalidated_by_enclosing_owner")
    );
    assert_eq!(
        field(geometry, &["assumptions", "calibration"])?.text(),
        Some("authored_nominal_camera_rig_not_activated_or_physically_validated")
    );
    assert_eq!(field(geometry, &["counts", "solved"])?.integer(), Some(1));
    let point = field(geometry, &["hypotheses", "0", "estimate", "position"])?
        .array()
        .ok_or("point")?;
    assert_eq!(point.len(), POSITION.len());
    for (actual, expected) in point.iter().zip(POSITION) {
        let Value::Number(actual) = actual else {
            return Err("position number".into());
        };
        assert!((actual.parse::<f64>()? - expected).abs() < 1e-8);
    }
    options.report_out = None;
    let mut second = Vec::new();
    assert!(cli(execute(&options, &mut second))?);
    assert_eq!(stdout, second);
    f.assert_head(&f.head)
}

#[test]
fn geometric_refusal_remains_visible_beside_a_solved_retained_hypothesis() -> Test {
    let f = Fixture::new("alternatives")?;
    let mut query = f.query.clone();
    let mut alternative = field(&query, &["hypotheses", "0"])?.clone();
    put(
        &mut alternative,
        &["id"],
        Value::Text("unknown-contact".into()),
    )?;
    put(
        &mut alternative,
        &["observations", "0", "visible_contact"],
        Value::Bool(false),
    )?;
    let original = field(&query, &["hypotheses", "0"])?.clone();
    put(
        &mut query,
        &["hypotheses"],
        Value::Array(vec![original, alternative]),
    )?;
    f.write_query(&query)?;
    let mut stdout = Vec::new();
    assert!(!cli(execute(&f.options()?, &mut stdout))?);
    assert_eq!(stdout, fs::read(&f.report)?);
    let value = parse(std::str::from_utf8(&stdout)?)?;
    assert_eq!(
        field(&value, &["report", "outcome"])?.text(),
        Some("complete_with_refusals")
    );
    let geometry = field(&value, &["report", "geometry", "report"])?;
    assert_eq!(field(geometry, &["counts", "total"])?.integer(), Some(2));
    assert_eq!(field(geometry, &["counts", "solved"])?.integer(), Some(1));
    assert_eq!(field(geometry, &["counts", "refused"])?.integer(), Some(1));
    assert_eq!(
        field(geometry, &["hypotheses", "1", "estimate", "reason"])?.text(),
        Some("common_feature_not_visible")
    );
    assert_eq!(
        field(geometry, &["hypotheses", "1", "observations"])?
            .array()
            .ok_or("refused sources")?
            .len(),
        3
    );
    f.assert_head(&f.head)
}

#[test]
fn authenticated_source_and_camera_mode_mismatches_refuse_without_output() -> Test {
    let f = Fixture::new("pins")?;
    for (path, replacement) in [
        (
            vec!["camera_bindings", "0", "camera_generation"],
            Value::Text(digest("wrong source generation").to_text()),
        ),
        (
            vec!["camera_bindings", "0", "image_domain"],
            Value::Number("2".into()),
        ),
        (
            vec!["hypotheses", "0", "observations", "0", "capsule_digest"],
            Value::Text(digest("foreign capsule").to_text()),
        ),
        (
            vec!["selections", "0", "report_digest"],
            Value::Text(digest("unavailable retained report").to_text()),
        ),
    ] {
        let mut query = f.query.clone();
        put(&mut query, &path, replacement)?;
        f.write_query(&query)?;
        f.refused(&f.options()?)?;
    }
    let mut rig = parse(&fs::read_to_string(&f.rig)?)?;
    put(
        &mut rig,
        &["cameras", "0", "intrinsics", "width"],
        Value::Number("64".into()),
    )?;
    let bytes = json(&rig);
    fs::write(&f.rig, &bytes)?;
    let mut query = f.query.clone();
    put(
        &mut query,
        &["camera_rig_digest"],
        Value::Text(ContentDigest::sha256(bytes.as_bytes()).to_text()),
    )?;
    f.write_query(&query)?;
    f.refused(&f.options()?)
}

#[test]
fn missing_and_corrupt_original_custody_is_not_repaired_or_reported_as_verified() -> Test {
    let f = Fixture::new("custody")?;
    for path in [&f.source_chunk, &f.capsule] {
        let original = fs::read(path)?;
        let mut damaged = original.clone();
        *damaged.last_mut().ok_or("empty custody object")? ^= 1;
        fs::write(path, &damaged)?;
        f.refused(&f.options()?)?;
        assert_eq!(fs::read(path)?, damaged);
        fs::remove_file(path)?;
        f.refused(&f.options()?)?;
        assert!(!path.exists());
        fs::write(path, original)?;
    }
    Ok(())
}

#[test]
fn stale_anchor_and_new_privacy_policy_withdraw_previously_available_geometry() -> Test {
    let f = Fixture::new("privacy")?;
    let mut options = f.options()?;
    options.expected_anchor = Some(digest("wrong anchor"));
    f.refused(&options)?;
    let cx = context(&f.root)?;
    let mut deployment = ReferenceDeployment::reopen(&f.root, SITE, &cx)?;
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse(&f.bindings[0].sensor_id)?,
        [32, 16],
        &[[0, 0, 32, 16]],
    )?;
    let approved = preview_mask(&deployment, &policy)?.approval;
    declare_mask(&mut deployment, &policy, approved, &cx)?;
    let head = deployment.current_anchor().clone();
    drop(deployment);
    cx.drain_and_finalize();
    for pin in [Some(anchor_digest(&f.head)), None] {
        options.expected_anchor = pin;
        let mut stdout = Vec::new();
        assert!(execute(&options, &mut stdout).is_err());
        assert!(stdout.is_empty());
        assert!(!f.report.exists());
        f.assert_head(&head)?;
    }
    Ok(())
}

#[test]
fn cancellation_and_complete_output_budget_leave_no_partial_report() -> Test {
    let f = Fixture::new("cancel")?;
    let mut options = f.options()?;
    let cx = context(&f.root)?;
    cx.request_cancellation();
    assert!(analyze(&options, &f.root, &cx).is_err());
    cx.drain_and_finalize();
    assert!(!f.report.exists());
    options.timeout = Duration::ZERO;
    f.refused(&options)?;
    options.timeout = Duration::from_secs(30);
    options.report_bytes = 1024;
    f.refused(&options)
}

#[test]
fn existing_report_and_missing_deployment_are_preserved_on_refusal() -> Test {
    let f = Fixture::new("ownership")?;
    let mut options = f.options()?;
    fs::write(&f.report, b"keep existing report")?;
    let mut stdout = Vec::new();
    assert!(execute(&options, &mut stdout).is_err());
    assert!(stdout.is_empty());
    assert_eq!(fs::read(&f.report)?, b"keep existing report");
    options.report_out = None;
    options.root = f.directory.0.join("never-created");
    assert!(execute(&options, &mut stdout).is_err());
    assert!(!options.root.exists());
    assert!(stdout.is_empty());
    f.assert_head(&f.head)
}
