#![forbid(unsafe_code)]
//! Cold supervisor processes consume real retained native package events, never supplied scores.
//! The committed JPEG/package fixture proves source wiring and refusals, not detector quality.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::agent_json::{array, object, string};
use fss_cli::json_input::{self, Value};
use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, EventId, OperationId, RootAuthoritySpec,
    SensorId, StreamId, TimestampNs,
};
use fss_fusion::ScoreCalibration;
use fss_reference::ingest::package_detect::{
    PackageDetectLimits, PackageDetectRequest, run_package_detection,
};
use fss_reference::ingest::package_event::{
    PackageAnalysisReport, PackageEventProposal, PackageTrackingConfig, retain_package_detection,
};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::{FileIngestAdapter, FileIngestRequest};
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:retained-supervisor-cli";
const JPEG: &[u8] =
    include_bytes!("../../../tests/fixtures/media/jpeg/rgb_64x48_colorbars_420.jpg");
const PACKAGE: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
const PACKAGE_SHA256: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

struct Directory(PathBuf);
impl Directory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-retained-supervisor-{name}-{}-{attempt}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:retained-supervisor-fixture".into(),
        operation_id: OperationId::parse("operation:retained-supervisor-fixture")?,
        principal: "principal:local-operator".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(8192)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

struct NativeCamera {
    alias: String,
    sensor: String,
    import: ContentDigest,
    event: EventId,
    event_root: ContentDigest,
    package: ContentDigest,
    model: ContentDigest,
    contract: ContentDigest,
    class_index: u64,
    capsule: ContentDigest,
    segment: u64,
    row: u64,
    score_bits: u32,
}
struct Fixture {
    directory: Directory,
    root: PathBuf,
    cameras: Vec<NativeCamera>,
    authority: ContentDigest,
}
impl Fixture {
    fn new(name: &str, count: usize) -> TestResult<Self> {
        let directory = Directory::new(name)?;
        let root = directory.0.join("deployment");
        let cx = context(&root)?;
        let scalar = ScalarExecCx::new();
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let package = RgbDetectorPackage::load(
            PACKAGE,
            ContentDigest::parse(PACKAGE_SHA256)?,
            1 << 40,
            &cx,
            &scalar,
        )?;
        let mut cameras = Vec::new();
        for index in 0..count {
            let alias = format!("camera-{index}");
            let sensor = format!("sensor:retained-supervisor-{index}");
            let source = directory.0.join(format!("source-{index}.jpg"));
            fs::write(&source, JPEG)?;
            let imported = FileIngestAdapter::ingest(
                FileIngestRequest::new(
                    &source,
                    SensorId::parse(&sensor)?,
                    StreamId::parse(format!("stream:retained-supervisor-{index}"))?,
                )
                .with_receive_time(TimestampNs(1_000_000_000)),
                &cx,
                &mut deployment,
            )?;
            fs::remove_file(source)?;
            let native = run_package_detection(
                &deployment,
                &package,
                &PackageDetectRequest {
                    import_identity: imported.import_identity,
                    first_segment: 0,
                    segment_count: 1,
                    interpretation: ComponentInterpretation::YCbCr,
                    minimum_score_ppm: None,
                },
                &PackageDetectLimits::default(),
                &cx,
                &scalar,
            )?;
            retain_package_detection(&mut deployment, &package, &native, &cx)?;
            let report = PackageAnalysisReport::read(
                &deployment,
                native.digest,
                "tie",
                PackageTrackingConfig {
                    confirmation_hits: 1,
                    maximum_missed_frames: 1,
                    minimum_iou_ppm: 100_000,
                },
                &cx,
            )?;
            let track = report
                .tracks()
                .iter()
                .find(|track| track.confirmed)
                .ok_or("native fixture track")?;
            let observation = track
                .observations
                .first()
                .ok_or("native fixture observation")?;
            let (row, score_bits, _, _) = observation.detection.ok_or("native assigned row")?;
            let proposal = PackageEventProposal::prepare(
                &deployment,
                report.encoded(),
                report.digest(),
                track.identity,
                &cx,
            )?;
            let receipt = proposal.publish(&mut deployment, proposal.digest(), &cx)?;
            let record = report.retained().record();
            cameras.push(NativeCamera {
                alias,
                sensor,
                import: imported.import_identity,
                event: receipt.event.event_id,
                event_root: receipt.event_root,
                package: record.package_digest,
                model: record.model_digest,
                contract: record.contract_digest,
                class_index: report.class_index(),
                capsule: observation.capsule_digest,
                segment: observation.segment,
                row,
                score_bits,
            });
        }
        let authority = deployment.current_anchor().state_root;
        drop(deployment);
        drop(package);
        scalar.drain_and_finalize();
        cx.drain_and_finalize();
        Ok(Self {
            directory,
            root,
            cameras,
            authority,
        })
    }

    fn refresh_authority(&mut self) -> TestResult {
        let cx = context(&self.root)?;
        let deployment = ReferenceDeployment::open(&self.root, SITE, &cx)?;
        self.authority = deployment.current_anchor().state_root;
        drop(deployment);
        cx.drain_and_finalize();
        Ok(())
    }

    fn plan(&self, selected: &[usize], calibrated: bool) -> TestResult<Value> {
        let calibration = ScoreCalibration::from_counts(
            "cal:retained-supervisor-fixture:v1",
            &[0, 1],
            &[(2, 98), (98, 2)],
        )?;
        let calibration_json = if calibrated {
            format!(
                r#"{{"schema":"fss.score_calibration.v1","generation":"{}","digest":"{}","bins":[{{"lo_ppm":0,"true_positives":2,"false_positives":98}},{{"lo_ppm":1,"true_positives":98,"false_positives":2}}]}}"#,
                calibration.generation, calibration.digest
            )
        } else {
            "null".to_owned()
        };
        let mut cameras = Vec::new();
        let mut events = Vec::new();
        let mut observations = Vec::new();
        for &index in selected {
            let c = &self.cameras[index];
            cameras.push(object(&[
                ("camera_id", string(&c.alias)),
                ("sensor_id", string(&c.sensor)),
                ("package_digest", string(&c.package.to_text())),
                ("model_digest", string(&c.model.to_text())),
                ("contract_digest", string(&c.contract.to_text())),
                ("class_index", c.class_index.to_string()),
                ("failure_domains", "[]".to_owned()),
                ("calibration", calibration_json.clone()),
            ]));
            events.push(object(&[
                ("camera_id", string(&c.alias)),
                ("event_id", string(c.event.as_str())),
                ("expected_event_root", string(&c.event_root.to_text())),
            ]));
            observations.push(object(&[
                ("event_id", string(c.event.as_str())),
                ("capsule_digest", string(&c.capsule.to_text())),
                ("segment", c.segment.to_string()),
                ("detection_row", c.row.to_string()),
            ]));
        }
        let windows: Vec<_> = (0..3_u64)
            .map(|index| {
                object(&[
                    ("window_index", index.to_string()),
                    ("end_ns", (2_000_000_000 + index * 1_000_000_000).to_string()),
                    (
                        "observations",
                        if index < 2 { array(&observations) } else { "[]".to_owned() },
                    ),
                ])
            })
            .collect();
        let document = object(&[
            ("schema", string("fss.retained_supervisor_plan.v1")),
            ("site_lineage", string(SITE)),
            ("hypothesis_id", string("hyp:class:tie")),
            ("expected_authority_root", string(&self.authority.to_text())),
            ("label", string("tie")),
            ("start_ns", "0".to_owned()),
            ("cameras", array(&cameras)),
            ("events", array(&events)),
            ("windows", array(&windows)),
            ("prior", "[0,0]".to_owned()),
            ("policy", r#"{"generation":"policy:retained-supervisor-fixture:v1","alert_threshold":1800,"retain_threshold":0,"reject_threshold":-1000,"min_independent_support":2,"urgent_single_domain_threshold":null,"max_wait_ns":0,"look_penalty_per_doubling":0,"operator_confirmation_available":false}"#.to_owned()),
            ("severity", r#"{"expected_harm":10000,"false_alert_cost":500,"delay_cost_per_second":100,"reversible":false}"#.to_owned()),
            ("limits", r#"{"max_read_bytes":134217728,"max_read_attempts":8192,"max_journal_bytes":16777216,"max_report_bytes":2097152}"#.to_owned()),
        ]);
        Ok(json_input::parse(&document)?)
    }

    /// Reconstruct every native source pin from the actual cold CLI inventory. The fixture's
    /// original receipt remains an independent assertion, not the source of the resulting plan.
    fn plan_from_read_inventory(&self, selected: &[usize]) -> TestResult<Value> {
        let mut plan = self.plan(selected, true)?;
        let mut selectors = Vec::new();
        for (position, &index) in selected.iter().enumerate() {
            let c = &self.cameras[index];
            let output = Command::new(env!("CARGO_BIN_EXE_fss-event"))
                .args(["read", "--root"])
                .arg(&self.root)
                .args(["--site", SITE, "--event-id", c.event.as_str()])
                .output()?;
            success(&output);
            let text_output = std::str::from_utf8(&output.stdout)?;
            let inventory = text_output
                .lines()
                .find_map(|line| line.strip_prefix("retained_supervisor_sources="))
                .ok_or("source inventory line")?;
            let inventory = json_input::parse(inventory)?;
            assert_eq!(text(&inventory, "expected_authority_root")?, self.authority.to_text());
            assert_eq!(text(&inventory, "expected_event_root")?, c.event_root.to_text());
            assert_eq!(text(&inventory, "package_digest")?, c.package.to_text());
            assert_eq!(text(&inventory, "model_digest")?, c.model.to_text());
            assert_eq!(text(&inventory, "contract_digest")?, c.contract.to_text());
            assert_eq!(field(&inventory, "class_index")?.integer(), Some(i128::from(c.class_index)));
            assert_eq!(field(&inventory, "source_custody_verified")?.boolean(), Some(true));
            assert_eq!(field(&inventory, "effects_authorized")?.boolean(), Some(false));
            let observations = field(&inventory, "observations")?.array().ok_or("source observations")?;
            assert_eq!(observations.len(), 1);
            let observation = &observations[0];
            assert_eq!(text(observation, "sensor_id")?, c.sensor);
            assert_eq!(field(observation, "score_f32_bits")?.integer(), Some(i128::from(c.score_bits)));
            let selector = field(observation, "selector")?;
            assert_eq!(text(selector, "event_id")?, c.event.as_str());
            assert_eq!(text(selector, "capsule_digest")?, c.capsule.to_text());
            assert_eq!(field(selector, "segment")?.integer(), Some(i128::from(c.segment)));
            assert_eq!(field(selector, "detection_row")?.integer(), Some(i128::from(c.row)));
            for key in ["site_lineage", "label", "expected_authority_root"] {
                fields(&mut plan).insert(key.to_owned(), field(&inventory, key)?.clone());
            }
            {
                let camera = &mut rows(fields(&mut plan).get_mut("cameras").ok_or("cameras")?)[position];
                for key in ["package_digest", "model_digest", "contract_digest", "class_index"] {
                    fields(camera).insert(key.to_owned(), field(&inventory, key)?.clone());
                }
                fields(camera).insert("sensor_id".into(), field(observation, "sensor_id")?.clone());
            }
            {
                let event = &mut rows(fields(&mut plan).get_mut("events").ok_or("events")?)[position];
                for key in ["event_id", "expected_event_root"] {
                    fields(event).insert(key.to_owned(), field(&inventory, key)?.clone());
                }
            }
            selectors.push(selector.clone());
        }
        for (index, window) in rows(fields(&mut plan).get_mut("windows").ok_or("windows")?)
            .iter_mut()
            .enumerate()
        {
            fields(window).insert(
                "observations".into(),
                Value::Array(if index < 2 { selectors.clone() } else { Vec::new() }),
            );
        }
        Ok(plan)
    }

    fn run(&self, plan: &Value) -> TestResult<Output> {
        let bytes = encode(plan);
        let path = self.directory.0.join("retained-plan.json");
        fs::write(&path, &bytes)?;
        Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .args(["supervise", "--root"])
            .arg(&self.root)
            .args(["--site", SITE, "--retained-plan"])
            .arg(&path)
            .args([
                "--retained-digest",
                &ContentDigest::sha256(bytes.as_bytes()).to_text(),
            ])
            .output()?)
    }
}

fn encode(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.clone(),
        Value::Text(value) => string(value),
        Value::Array(values) => array(&values.iter().map(encode).collect::<Vec<_>>()),
        Value::Object(values) => object(
            &values.iter().map(|(key, value)| (key.as_str(), encode(value))).collect::<Vec<_>>(),
        ),
    }
}
fn fields(value: &mut Value) -> &mut BTreeMap<String, Value> {
    match value {
        Value::Object(fields) => fields,
        _ => panic!("fixture object"),
    }
}
fn rows(value: &mut Value) -> &mut Vec<Value> {
    match value {
        Value::Array(rows) => rows,
        _ => panic!("fixture array"),
    }
}
fn field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value.object().and_then(|fields| fields.get(key))
        .ok_or_else(|| format!("missing JSON field {key}").into())
}
fn text<'a>(value: &'a Value, key: &str) -> TestResult<&'a str> {
    field(value, key)?.text().ok_or_else(|| format!("non-text JSON field {key}").into())
}
fn numeric(value: u64) -> Value { Value::Number(value.to_string()) }
fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
fn report(output: &Output) -> TestResult<Value> {
    Ok(json_input::parse(std::str::from_utf8(&output.stdout)?)?)
}
fn inventory(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    fn visit(root: &Path, path: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) -> TestResult {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                visit(root, &entry.path(), files)?;
            } else if entry.file_type()?.is_file() {
                files.insert(entry.path().strip_prefix(root)?.to_path_buf(), fs::read(entry.path())?);
            }
        }
        Ok(())
    }
    let mut files = BTreeMap::new();
    visit(root, root, &mut files)?;
    Ok(files)
}
fn refused_without_mutation(f: &Fixture, plan: &Value) -> TestResult<Output> {
    let before = inventory(&f.root)?;
    let output = f.run(plan)?;
    assert!(!output.status.success(), "request unexpectedly succeeded");
    assert!(output.stdout.is_empty(), "partial advice escaped a refusal");
    assert_eq!(inventory(&f.root)?, before, "refusal changed retained state");
    Ok(output)
}

#[test]
fn cold_real_package_events_preserve_exact_scores_and_do_not_multiply_repeated_evidence()
-> TestResult {
    let f = Fixture::new("cold", 2)?;
    let before = inventory(&f.root)?;
    let plan = f.plan_from_read_inventory(&[0, 1])?;
    let first = f.run(&plan)?;
    success(&first);
    let document = report(&first)?;
    assert_eq!(text(&document, "schema")?, "fss.retained_supervisor_report.v1");
    assert_eq!(
        text(&document, "observation_basis")?,
        "verified_retained_native_detections"
    );
    assert_eq!(text(&document, "clock_synchronization")?, "not_established");
    assert_eq!(field(&document, "source_custody_verified")?.boolean(), Some(true));
    for flag in ["effects_authorized", "supports_absence_claim", "anytime_bound_verified"] {
        assert_eq!(field(&document, flag)?.boolean(), Some(false));
    }
    let observations = field(&document, "observations")?.array().ok_or("observations")?;
    assert_eq!(observations.len(), 2);
    for c in &f.cameras {
        let observation = observations
            .iter()
            .find(|value| text(value, "sensor_id").is_ok_and(|sensor| sensor == c.sensor))
            .ok_or("native sensor observation")?;
        assert_eq!(text(observation, "capsule_digest")?, c.capsule.to_text());
        assert_eq!(text(observation, "package_digest")?, c.package.to_text());
        assert_eq!(text(observation, "clock_basis")?, "estimated");
        assert_eq!(text(observation, "capture_time_label")?, "unknown");
        assert_eq!(
            field(observation, "score_f32_bits")?.integer(),
            Some(i128::from(c.score_bits))
        );
    }
    let windows = field(&document, "windows")?.array().ok_or("windows")?;
    assert_eq!(windows.len(), 3);
    let baseline = field(field(&windows[0], "outcome")?, "posterior_log_odds_millibans")?;
    for (index, window) in windows.iter().enumerate() {
        assert_eq!(field(window, "unique_observations")?.integer(), Some(2));
        assert_eq!(
            field(window, "new_observations")?.integer(),
            Some(if index == 0 { 2 } else { 0 })
        );
        let outcome = field(window, "outcome")?;
        assert_eq!(field(outcome, "posterior_log_odds_millibans")?, baseline);
        assert_eq!(
            field(outcome, "supporting_clusters")?.integer(),
            Some(1),
            "shared native package and calibration are common causes"
        );
        assert_eq!(field(outcome, "effect_authority")?.boolean(), Some(false));
    }
    assert!(
        field(field(&document, "read_usage")?, "reserved_bytes")?
            .integer()
            .is_some_and(|n| n > 0)
    );
    let second = f.run(&plan)?;
    success(&second);
    assert_eq!(second.stdout, first.stdout, "cold exact retry changed the complete report");

    // A configured camera without a selected source remains explicitly unobservable. Its
    // missing observation cannot become a negative detection or a complete-coverage claim.
    let mut missing = f.plan(&[0], true)?;
    let cameras = field(&plan, "cameras")?.array().ok_or("cameras")?;
    rows(fields(&mut missing).get_mut("cameras").ok_or("cameras")?).push(cameras[1].clone());
    let absent = f.run(&missing)?;
    success(&absent);
    let absent = report(&absent)?;
    let windows = field(&absent, "windows")?.array().ok_or("windows")?;
    for window in windows {
        let query = field(window, "query")?;
        assert_eq!(text(field(query, "coverage")?, "state")?, "gap");
        let evidence = field(query, "evidence")?.array().ok_or("evidence")?;
        let missing_camera = evidence.iter()
            .find(|value| text(value, "sensor").is_ok_and(|sensor| sensor == f.cameras[1].sensor))
            .ok_or("missing camera projection")?;
        assert!(field(field(missing_camera, "observability")?, "not_observable")?.text().is_some());
        assert!(field(field(missing_camera, "calibration")?, "uncalibrated")?.text().is_some());
        assert_eq!(field(window, "unique_observations")?.integer(), Some(1));
    }
    assert_eq!(inventory(&f.root)?, before);
    Ok(())
}

#[test]
fn retained_scope_and_resource_refusals_cannot_be_replaced_with_caller_values() -> TestResult {
    let f = Fixture::new("refusals", 1)?;
    let base = f.plan(&[0], true)?;
    let wrong = ContentDigest::sha256(b"foreign retained source pin").to_text();
    for (key, value) in [
        ("expected_authority_root", Value::Text(wrong.clone())),
        ("start_ns", numeric(1_000_000_001)),
        ("site_lineage", Value::Text("site:foreign".into())),
    ] {
        let mut changed = base.clone();
        fields(&mut changed).insert(key.into(), value);
        refused_without_mutation(&f, &changed)?;
    }
    let mut foreign_event = base.clone();
    fields(&mut rows(fields(&mut foreign_event).get_mut("events").ok_or("events")?)[0])
        .insert("expected_event_root".into(), Value::Text(wrong.clone()));
    refused_without_mutation(&f, &foreign_event)?;
    for key in ["package_digest", "model_digest", "contract_digest"] {
        let mut changed = base.clone();
        let camera = &mut rows(fields(&mut changed).get_mut("cameras").ok_or("cameras")?)[0];
        fields(camera).insert(key.to_owned(), Value::Text(wrong.clone()));
        refused_without_mutation(&f, &changed)?;
    }
    for (key, value) in [
        ("sensor_id", Value::Text("sensor:foreign".into())),
        ("class_index", numeric(f.cameras[0].class_index + 1)),
    ] {
        let mut changed = base.clone();
        fields(&mut rows(fields(&mut changed).get_mut("cameras").ok_or("cameras")?)[0])
            .insert(key.into(), value);
        refused_without_mutation(&f, &changed)?;
    }
    for (key, value) in [("end_ns", numeric(1)), ("window_index", numeric(1))] {
        let mut changed = base.clone();
        fields(&mut rows(fields(&mut changed).get_mut("windows").ok_or("windows")?)[0])
            .insert(key.into(), value);
        refused_without_mutation(&f, &changed)?;
    }
    for (key, value) in [
        ("segment", numeric(1)),
        ("detection_row", numeric(u64::MAX)),
        ("capsule_digest", Value::Text(wrong.clone())),
        ("score_ppm", numeric(999999)),
    ] {
        let mut changed = base.clone();
        let window = &mut rows(fields(&mut changed).get_mut("windows").ok_or("windows")?)[0];
        fields(&mut rows(fields(window).get_mut("observations").ok_or("observations")?)[0])
            .insert(key.into(), value);
        refused_without_mutation(&f, &changed)?;
    }
    for key in ["max_read_bytes", "max_read_attempts", "max_journal_bytes", "max_report_bytes"] {
        let mut changed = base.clone();
        fields(fields(&mut changed).get_mut("limits").ok_or("limits")?)
            .insert(key.into(), numeric(1));
        refused_without_mutation(&f, &changed)?;
    }
    let mut duplicate = base.clone();
    let window = &mut rows(fields(&mut duplicate).get_mut("windows").ok_or("windows")?)[0];
    let selections = rows(fields(window).get_mut("observations").ok_or("observations")?);
    selections.push(selections[0].clone());
    refused_without_mutation(&f, &duplicate)?;
    let uncalibrated = f.run(&f.plan(&[0], false)?)?;
    success(&uncalibrated);
    let document = report(&uncalibrated)?;
    let windows = field(&document, "windows")?.array().ok_or("windows")?;
    assert_eq!(
        field(field(&windows[0], "outcome")?, "supporting_clusters")?.integer(),
        Some(0)
    );

    // Damage only this fixture's retained capsule after a successful cold read. Startup or
    // source validation must refuse it; neither may repair bytes while producing advice.
    let cx = context(&f.root)?;
    let deployment = ReferenceDeployment::open(&f.root, SITE, &cx)?;
    let capsule_path = deployment.publisher().spool().object_path(f.cameras[0].capsule);
    drop(deployment);
    cx.drain_and_finalize();
    let original = fs::read(&capsule_path)?;
    let mut corrupt = original.clone();
    *corrupt.last_mut().ok_or("retained capsule bytes")? ^= 1;
    fs::write(&capsule_path, corrupt)?;
    refused_without_mutation(&f, &base)?;
    fs::write(capsule_path, original)?;
    Ok(())
}

#[test]
fn current_privacy_and_real_import_deletion_withdraw_cold_supervisor_access() -> TestResult {
    let mut f = Fixture::new("withdrawal", 2)?;
    success(&f.run(&f.plan(&[0, 1], true)?)?);
    let preview = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["privacy-mask", "declare", "--root"])
        .arg(&f.root)
        .args([
            "--site", SITE, "--sensor", &f.cameras[0].sensor,
            "--resolution", "64x48", "--rect", "0,0,1,1",
        ])
        .output()?;
    success(&preview);
    let preview = report(&preview)?;
    let declared = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["privacy-mask", "declare", "--root"])
        .arg(&f.root)
        .args([
            "--site", SITE, "--sensor", &f.cameras[0].sensor,
            "--resolution", "64x48", "--rect", "0,0,1,1",
            "--approve", text(&preview, "approval_digest")?,
        ])
        .output()?;
    success(&declared);
    f.refresh_authority()?;
    let private = refused_without_mutation(&f, &f.plan(&[0], true)?)?;
    assert!(std::str::from_utf8(&private.stderr)?.contains("ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001"));

    // The second sensor is still readable before its actual import deletion is committed.
    success(&f.run(&f.plan(&[1], true)?)?);
    let deletion = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "plan", "--root"])
        .arg(&f.root)
        .args(["--site", SITE, "--import-id", &f.cameras[1].import.to_text()])
        .output()?;
    success(&deletion);
    let deletion = report(&deletion)?;
    let committed = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "commit", "--root"])
        .arg(&f.root)
        .args([
            "--site", SITE, "--plan", text(&deletion, "plan_digest")?,
            "--approve", text(&deletion, "approval_digest")?,
        ])
        .output()?;
    success(&committed);
    f.refresh_authority()?;
    refused_without_mutation(&f, &f.plan(&[1], true)?)?;
    Ok(())
}

#[test]
fn mode_and_exact_plan_digest_are_admitted_before_an_absent_deployment_is_touched() -> TestResult {
    let directory = Directory::new("admission")?;
    let root = directory.0.join("must-not-exist");
    let plan = directory.0.join("not-a-plan.json");
    fs::write(&plan, b"not JSON")?;
    let base = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
        command.args(["supervise", "--root"]).arg(&root)
            .args(["--site", SITE, "--retained-plan"]).arg(&plan);
        command
    };
    let missing = base().output()?;
    assert_eq!(
        missing.status.code(),
        Some(i32::from(fss_cli::ExitIdentity::MALFORMED_VALUE.code))
    );
    let wrong = base()
        .args(["--retained-digest", &ContentDigest::sha256(b"other").to_text()])
        .output()?;
    assert!(!wrong.status.success());
    assert!(std::str::from_utf8(&wrong.stderr)?.contains("plan byte digest"));
    let mixed = base()
        .args([
            "--retained-digest", &ContentDigest::sha256(b"not JSON").to_text(),
            "--plan", "legacy.json",
        ])
        .output()?;
    assert!(!mixed.status.success());
    assert!(std::str::from_utf8(&mixed.stderr)?.contains("mutually exclusive"));
    assert!(!root.exists());
    let help = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["supervise", "--help"]).output()?;
    success(&help);
    let help = std::str::from_utf8(&help.stdout)?;
    assert!(help.contains("--retained-plan") && help.contains("caller-score simulation"));
    Ok(())
}
