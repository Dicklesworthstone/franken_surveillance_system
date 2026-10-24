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
use fss_cli::supervisor::retained::{
    RetainedDiscoveryRequest, RetainedDiscoverySource, RetainedDiscoveryValidation,
    revalidate_retained_discovery_sources, run_discovered_retained_supervisor,
};

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

    fn discovery(&self, selected: &[usize]) -> TestResult<Value> {
        let mut plan = self.plan(selected, true)?;
        fields(&mut plan).insert("events".into(), Value::Array(Vec::new()));
        for window in rows(fields(&mut plan).get_mut("windows").ok_or("windows")?) {
            fields(window).insert("observations".into(), Value::Array(Vec::new()));
        }
        Ok(Value::Object(BTreeMap::from([
            (
                "schema".into(),
                Value::Text("fss.retained_supervisor_discovery.v1".into()),
            ),
            ("maximum_catalog_events".into(), numeric(64)),
            ("plan".into(), plan),
        ])))
    }

    fn run_discovered(&self, request: &Value) -> TestResult<Output> {
        let bytes = encode(request);
        let path = self.directory.0.join("discovery-plan.json");
        fs::write(&path, &bytes)?;
        Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .args(["supervise", "--root"])
            .arg(&self.root)
            .args(["--site", SITE, "--discover-plan"])
            .arg(&path)
            .args([
                "--discover-digest",
                &ContentDigest::sha256(bytes.as_bytes()).to_text(),
            ])
            .output()?)
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

fn discovered_refusal_without_mutation(f: &Fixture, request: &Value) -> TestResult<Output> {
    let before = inventory(&f.root)?;
    let output = f.run_discovered(request)?;
    assert!(!output.status.success(), "discovery unexpectedly succeeded");
    assert!(output.stdout.is_empty(), "partial discovered advice escaped a refusal");
    assert_eq!(inventory(&f.root)?, before, "discovery refusal changed retained state");
    Ok(output)
}

fn discovery_plan(request: &mut Value) -> &mut Value {
    fields(request).get_mut("plan").expect("discovery fixture plan")
}


fn historical_sources(
    f: &Fixture,
    request: &Value,
) -> TestResult<(RetainedDiscoveryRequest, Vec<RetainedDiscoverySource>)> {
    let bytes = encode(request).into_bytes();
    let request = RetainedDiscoveryRequest::from_json(&bytes, ContentDigest::sha256(&bytes))?;
    let cx = context(&f.root)?;
    let mut deployment = ReferenceDeployment::open(&f.root, SITE, &cx)?;
    let result = run_discovered_retained_supervisor(&mut deployment, &request, &cx)
        .and_then(|report| report.source_inventory());
    drop(deployment);
    cx.drain_and_finalize();
    Ok((request, result?))
}

fn revalidate_sources(
    f: &Fixture,
    request: &RetainedDiscoveryRequest,
    sources: &[RetainedDiscoverySource],
) -> TestResult<RetainedDiscoveryValidation> {
    let current = request.for_authority(f.authority)?;
    let cx = context(&f.root)?;
    let mut deployment = ReferenceDeployment::open(&f.root, SITE, &cx)?;
    let result = revalidate_retained_discovery_sources(&mut deployment, &current, sources, &cx);
    drop(deployment);
    cx.drain_and_finalize();
    Ok(result?)
}

fn assert_unobserved_camera(supervision: &Value, sensor: &str) -> TestResult {
    for window in field(supervision, "windows")?.array().ok_or("windows")? {
        let query = field(window, "query")?;
        assert_eq!(text(field(query, "coverage")?, "state")?, "gap");
        let evidence = field(query, "evidence")?.array().ok_or("evidence")?;
        let camera = evidence
            .iter()
            .find(|item| text(item, "sensor").is_ok_and(|value| value == sensor))
            .ok_or("unobserved configured camera")?;
        assert!(field(field(camera, "observability")?, "not_observable")?.text().is_some());
        assert!(field(field(camera, "calibration")?, "uncalibrated")?.text().is_some());
    }
    Ok(())
}

#[test]
fn cold_real_package_events_preserve_exact_scores_and_do_not_multiply_repeated_evidence()
-> TestResult {
    let f = Fixture::new("cold", 2)?;
    let before = inventory(&f.root)?;
    let plan = f.plan_from_read_inventory(&[0, 1])?;
    let first = f.run(&plan)?;
    success(&first);
    // Even a fully admitted, exact-byte plan must not initialize an absent deployment.
    let absent_root = f.directory.0.join("must-stay-absent");
    let admitted_plan = f.directory.0.join("admitted-plan.json");
    let admitted_bytes = encode(&plan);
    fs::write(&admitted_plan, &admitted_bytes)?;
    let absent = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["supervise", "--root"]).arg(&absent_root)
        .args(["--site", SITE, "--retained-plan"]).arg(&admitted_plan)
        .args(["--retained-digest", &ContentDigest::sha256(admitted_bytes.as_bytes()).to_text()])
        .output()?;
    assert_eq!(
        absent.status.code(),
        Some(i32::from(fss_cli::ExitIdentity::RUNTIME_FAILURE.code))
    );
    assert!(absent.stdout.is_empty());
    assert!(std::str::from_utf8(&absent.stderr)?.contains("existing non-symlink deployment required"));
    assert!(!absent_root.exists());
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
    discovered_refusal_without_mutation(&f, &f.discovery(&[0])?)?;
    fs::write(capsule_path, original)?;
    Ok(())
}

#[test]
fn current_privacy_and_real_import_deletion_withdraw_cold_supervisor_access() -> TestResult {
    let mut f = Fixture::new("withdrawal", 2)?;
    success(&f.run(&f.plan(&[0, 1], true)?)?);
    success(&f.run_discovered(&f.discovery(&[0, 1])?)?);
    // A generation-excluded source still requires native verification on historical delivery.
    let mut excluded = f.discovery(&[0])?;
    let camera = &mut rows(
        fields(discovery_plan(&mut excluded)).get_mut("cameras").ok_or("cameras")?,
    )[0];
    fields(camera).insert(
        "package_digest".into(),
        Value::Text(ContentDigest::sha256(b"historical other package").to_text()),
    );
    let (excluded_request, excluded_sources) = historical_sources(&f, &excluded)?;
    assert!(excluded_sources.iter().any(|source| {
        source.event_id == f.cameras[0].event && source.source_verified
    }));
    revalidate_sources(&f, &excluded_request, &excluded_sources)?;
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
    let revoked = revalidate_sources(&f, &excluded_request, &excluded_sources)
        .expect_err("private generation-excluded source cannot redeliver");
    assert!(revoked.to_string().contains("ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001"));
    let private = refused_without_mutation(&f, &f.plan(&[0], true)?)?;
    assert!(std::str::from_utf8(&private.stderr)?.contains("ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001"));
    let private_discovery = discovered_refusal_without_mutation(&f, &f.discovery(&[0])?)?;
    assert!(
        std::str::from_utf8(&private_discovery.stderr)?
            .contains("ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001")
    );
    // A configured sensor's private event must still fail if its requested package pin differs.
    // Discovery may not hide the refusal by applying a generation filter before source checks.
    let mut private_mismatch = f.discovery(&[0])?;
    let camera = &mut rows(
        fields(discovery_plan(&mut private_mismatch)).get_mut("cameras").ok_or("cameras")?,
    )[0];
    fields(camera).insert(
        "package_digest".into(),
        Value::Text(ContentDigest::sha256(b"other package").to_text()),
    );
    let private_mismatch = discovered_refusal_without_mutation(&f, &private_mismatch)?;
    assert!(
        std::str::from_utf8(&private_mismatch.stderr)?
            .contains("ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001")
    );

    // The second sensor is still readable before its actual import deletion is committed.
    success(&f.run(&f.plan(&[1], true)?)?);
    success(&f.run_discovered(&f.discovery(&[1])?)?);
    let (before_delete, delete_sources) = historical_sources(&f, &f.discovery(&[1])?)?;
    revalidate_sources(&f, &before_delete, &delete_sources)?;
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
    discovered_refusal_without_mutation(&f, &f.discovery(&[1])?)?;
    assert!(revalidate_sources(&f, &before_delete, &delete_sources).is_err());
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

#[test]
fn discovery_finds_real_native_rows_and_emits_an_executable_deterministic_plan() -> TestResult {
    let f = Fixture::new("discovery", 2)?;
    let before = inventory(&f.root)?;
    let request = f.discovery(&[0, 1])?;
    // Historical inventory includes every catalog candidate, even metadata-only exclusions.
    let (subset_request, subset_sources) = historical_sources(&f, &f.discovery(&[0])?)?;
    assert_eq!(subset_sources.len(), 2);
    for camera in &f.cameras {
        let source = subset_sources.iter().find(|source| source.event_id == camera.event)
            .ok_or("complete historical source inventory")?;
        assert_eq!(source.event_root, camera.event_root);
        assert_eq!(source.source_verified, camera.event == f.cameras[0].event);
    }
    let validation = revalidate_sources(&f, &subset_request, &subset_sources)?;
    assert_eq!(validation.basis().state_root, f.authority);
    assert!(validation.reserved_bytes() > 0 && validation.read_attempts() > 0);
    let validation_json = json_input::parse(&validation.to_json()?)?;
    assert_eq!(field(&validation_json, "metadata_sources")?.integer(), Some(2));
    assert_eq!(field(&validation_json, "native_sources")?.integer(), Some(1));
    assert_eq!(field(&validation_json, "complete_current_catalog")?.boolean(), Some(false));
    let mut changed_sources = subset_sources.clone();
    changed_sources[0].event_root = ContentDigest::sha256(b"wrong historical revision");
    assert!(revalidate_sources(&f, &subset_request, &changed_sources).is_err());
    let encoded = encode(&request);
    for camera in &f.cameras {
        assert!(!encoded.contains(camera.event.as_str()), "request supplied an event selector");
        assert!(!encoded.contains(&camera.capsule.to_text()), "request supplied a source row");
    }
    let first = f.run_discovered(&request)?;
    success(&first);
    let document = report(&first)?;
    assert_eq!(
        text(&document, "schema")?,
        "fss.retained_supervisor_discovery_report.v1"
    );
    assert_eq!(field(&document, "effects_authorized")?.boolean(), Some(false));
    assert_eq!(field(&document, "supports_absence_claim")?.boolean(), Some(false));
    let selected = field(&document, "selected_plan")?;
    assert_eq!(text(selected, "schema")?, "fss.retained_supervisor_plan.v1");
    assert_eq!(text(selected, "expected_authority_root")?, f.authority.to_text());
    let events = field(selected, "events")?.array().ok_or("selected events")?;
    assert_eq!(events.len(), 2);
    for camera in &f.cameras {
        let event = events.iter()
            .find(|event| text(event, "event_id").is_ok_and(|id| id == camera.event.as_str()))
            .ok_or("discovered native event")?;
        assert_eq!(text(event, "camera_id")?, camera.alias);
        assert_eq!(text(event, "expected_event_root")?, camera.event_root.to_text());
    }
    let selected_windows = field(selected, "windows")?.array().ok_or("selected windows")?;
    let first_rows = field(&selected_windows[0], "observations")?.array().ok_or("selected rows")?;
    assert_eq!(first_rows.len(), 2);
    for camera in &f.cameras {
        let row = first_rows.iter()
            .find(|row| text(row, "event_id").is_ok_and(|id| id == camera.event.as_str()))
            .ok_or("discovered assigned native row")?;
        assert_eq!(text(row, "capsule_digest")?, camera.capsule.to_text());
        assert_eq!(field(row, "segment")?.integer(), Some(i128::from(camera.segment)));
        assert_eq!(field(row, "detection_row")?.integer(), Some(i128::from(camera.row)));
    }
    for window in &selected_windows[1..] {
        assert!(field(window, "observations")?.array().ok_or("selected rows")?.is_empty());
    }
    let discovery = field(&document, "discovery")?;
    // Sensor-tamper companions remain catalog objects but are not event revisions.
    assert_eq!(field(discovery, "catalog_events")?.integer(), Some(2));
    assert_eq!(field(discovery, "package_event_candidates")?.integer(), Some(2));
    assert_eq!(field(discovery, "metadata_reads")?.integer(), Some(2));
    assert_eq!(field(discovery, "selected_events")?.integer(), Some(2));
    assert_eq!(field(discovery, "selected_observations")?.integer(), Some(2));
    let supervision = field(&document, "supervision")?;
    let ordinary = f.run(selected)?;
    success(&ordinary);
    let ordinary = report(&ordinary)?;
    for key in ["plan_digest", "observations", "windows", "authority_state_root"] {
        assert_eq!(
            field(supervision, key)?,
            field(&ordinary, key)?,
            "discovered and explicit supervision differ at {key}"
        );
    }
    let usage = field(&document, "read_usage")?;
    for (total, discovery_key, supervision_key) in [
        ("reserved_bytes", "discovery_reserved_bytes", "supervision_reserved_bytes"),
        ("read_attempts", "discovery_read_attempts", "supervision_read_attempts"),
    ] {
        let discovered = field(usage, discovery_key)?.integer().ok_or("discovery usage")?;
        let supervised = field(usage, supervision_key)?.integer().ok_or("supervision usage")?;
        assert!(discovered > 0 && supervised > 0);
        assert_eq!(field(usage, total)?.integer(), Some(discovered + supervised));
    }
    let second = f.run_discovered(&request)?;
    success(&second);
    assert_eq!(second.stdout, first.stdout, "discovery retry changed the complete result");

    // A conservative [0, receive] interval cannot enter the first too-short window. It is
    // placed at the first later window that contains the entire original interval.
    let mut delayed = request.clone();
    let windows = rows(fields(discovery_plan(&mut delayed)).get_mut("windows").ok_or("windows")?);
    fields(&mut windows[0]).insert("end_ns".into(), numeric(500_000_000));
    let delayed = f.run_discovered(&delayed)?;
    success(&delayed);
    let delayed = report(&delayed)?;
    let windows = field(field(&delayed, "selected_plan")?, "windows")?.array().ok_or("windows")?;
    assert!(field(&windows[0], "observations")?.array().ok_or("rows")?.is_empty());
    assert_eq!(field(&windows[1], "observations")?.array().ok_or("rows")?.len(), 2);
    let windows = field(field(&delayed, "supervision")?, "windows")?.array().ok_or("windows")?;
    assert_eq!(field(&windows[0], "unique_observations")?.integer(), Some(0));
    assert_eq!(field(&windows[1], "unique_observations")?.integer(), Some(2));

    let mut missing = request.clone();
    let cameras = rows(fields(discovery_plan(&mut missing)).get_mut("cameras").ok_or("cameras")?);
    let mut camera = cameras[0].clone();
    fields(&mut camera).insert("camera_id".into(), Value::Text("missing-camera".into()));
    fields(&mut camera).insert("sensor_id".into(), Value::Text("sensor:missing-camera".into()));
    cameras.push(camera);
    let missing = f.run_discovered(&missing)?;
    success(&missing);
    let missing = report(&missing)?;
    assert_unobserved_camera(field(&missing, "supervision")?, "sensor:missing-camera")?;

    // Reusing a configured sensor with another native package cannot silently turn its event
    // into an empty catalog. Every excluded event remains named with its exact root.
    for key in ["package_digest", "model_digest", "contract_digest"] {
        let mut mismatch = request.clone();
        let camera = &mut rows(
            fields(discovery_plan(&mut mismatch)).get_mut("cameras").ok_or("cameras")?,
        )[0];
        fields(camera).insert(
            key.into(),
            Value::Text(ContentDigest::sha256(b"foreign native generation").to_text()),
        );
        let output = f.run_discovered(&mismatch)?;
        success(&output);
        let output = report(&output)?;
        let exclusions = field(field(&output, "discovery")?, "exclusions")?
            .array().ok_or("exclusions")?;
        let exclusion = exclusions.iter()
            .find(|entry| text(entry, "event_id").is_ok_and(|id| id == f.cameras[0].event.as_str()))
            .ok_or("mismatched configured source must be explicit")?;
        assert_eq!(text(exclusion, "event_root")?, f.cameras[0].event_root.to_text());
        assert_eq!(text(exclusion, "reason")?, format!("{key}_mismatch"));
        assert_eq!(field(exclusion, "source_verified")?.boolean(), Some(true));
        assert_unobserved_camera(field(&output, "supervision")?, &f.cameras[0].sensor)?;
    }

    let mut catalog_bound = request.clone();
    fields(&mut catalog_bound).insert("maximum_catalog_events".into(), numeric(1));
    discovered_refusal_without_mutation(&f, &catalog_bound)?;
    for key in ["max_read_bytes", "max_read_attempts", "max_report_bytes"] {
        let mut bounded = request.clone();
        let limits = fields(discovery_plan(&mut bounded)).get_mut("limits").ok_or("limits")?;
        fields(limits).insert(key.into(), numeric(1));
        discovered_refusal_without_mutation(&f, &bounded)?;
    }
    assert_eq!(inventory(&f.root)?, before, "discovery or explicit replay changed authority");
    Ok(())
}

#[test]
fn discovery_digest_and_mode_admission_precede_opening_an_absent_deployment() -> TestResult {
    let directory = Directory::new("discovery-admission")?;
    let root = directory.0.join("must-not-exist");
    let plan = directory.0.join("not-a-discovery-plan.json");
    fs::write(&plan, b"not JSON")?;
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
        command.args(["supervise", "--root"]).arg(&root)
            .args(["--site", SITE, "--discover-plan"]).arg(&plan);
        command
    };
    let missing = command().output()?;
    assert_eq!(
        missing.status.code(),
        Some(i32::from(fss_cli::ExitIdentity::MALFORMED_VALUE.code))
    );
    assert!(missing.stdout.is_empty());
    let wrong = command()
        .args(["--discover-digest", &ContentDigest::sha256(b"wrong").to_text()])
        .output()?;
    assert_eq!(
        wrong.status.code(),
        Some(i32::from(fss_cli::ExitIdentity::MALFORMED_VALUE.code))
    );
    assert!(std::str::from_utf8(&wrong.stderr)?.contains("discovery request byte digest"));
    for flag in ["--plan", "--retained-plan", "--retained-digest"] {
        let mixed = command()
            .args([
                "--discover-digest", &ContentDigest::sha256(b"not JSON").to_text(),
                flag, "other",
            ])
            .output()?;
        assert!(!mixed.status.success());
        assert!(mixed.stdout.is_empty());
        assert!(std::str::from_utf8(&mixed.stderr)?.contains("mutually exclusive"));
    }
    assert!(!root.exists());
    let help = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["supervise", "--help"]).output()?;
    success(&help);
    let help = std::str::from_utf8(&help.stdout)?;
    assert!(help.contains("--discover-plan") && help.contains("--discover-digest"));
    Ok(())
}

#[path = "supervisor_retained_contract/session.rs"]
mod session;
