#![forbid(unsafe_code)]
//! Real retained detector bursts can contribute class advice before a track or event exists.
//! The synthetic color bars exercise native custody and control flow, not detector quality.

use super::*;

use fss_cli::supervisor::retained::{
    RetainedDetectionRequest, RetainedDetectionSource, RetainedDetectionValidation,
    revalidate_detection_sources, run_discovered_detection_supervisor,
};
use fss_core::{BatchId, CaptureInterval, EvidenceDelta, ObjectId, Plane};
use fss_reference::ingest::long_dwell::LongDwellLimits;
use fss_reference::ingest::long_watch::LongWatchReport;
use fss_reference::ingest::package_event::{RecordDetection, RecordFrame};
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::{CaptureHint, FileFormatHint};

#[path = "detection/session.rs"]
mod session;

struct DetectionCamera {
    alias: String,
    sensor: String,
    import: ContentDigest,
    package: ContentDigest,
    model: ContentDigest,
    contract: ContentDigest,
    class_index: u64,
    rows: Vec<(RecordFrame, RecordDetection)>,
}

struct DetectionSource {
    report: ContentDigest,
    record: ContentDigest,
    root: ContentDigest,
}

struct DetectionFixture {
    directory: Directory,
    root: PathBuf,
    cameras: Vec<DetectionCamera>,
    sources: Vec<DetectionSource>,
    authority: ContentDigest,
}

impl DetectionFixture {
    fn new(
        name: &str,
        camera_count: usize,
        frame_count: usize,
        overlap: bool,
        minimum_score_ppm: Option<u32>,
    ) -> TestResult<Self> {
        Self::with_source_frames(
            name,
            camera_count,
            frame_count,
            frame_count,
            overlap,
            minimum_score_ppm,
            false,
        )
    }

    fn with_source_frames(
        name: &str,
        camera_count: usize,
        frame_count: usize,
        source_frames: usize,
        overlap: bool,
        minimum_score_ppm: Option<u32>,
        capture_hint: bool,
    ) -> TestResult<Self> {
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
        let mut sources = Vec::new();
        for index in 0..camera_count {
            let alias = format!("camera-{index}");
            let sensor = format!("sensor:retained-detection-{index}");
            let source = directory.0.join(format!("source-{index}.mjpeg"));
            fs::write(&source, JPEG.repeat(source_frames))?;
            let mut request = FileIngestRequest::new(
                &source,
                SensorId::parse(&sensor)?,
                StreamId::parse(format!("stream:retained-detection-{index}"))?,
            )
            .with_format_hint(FileFormatHint::JpegStream)
            .with_receive_time(TimestampNs(if capture_hint {
                2_000_000_000
            } else {
                1_000_000_000
            }));
            if capture_hint {
                request = request.with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?);
            }
            let imported = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;
            fs::remove_file(source)?;
            let ranges = if overlap {
                vec![1, frame_count]
            } else {
                vec![frame_count]
            };
            let mut camera = None;
            for segment_count in ranges {
                let native = run_package_detection(
                    &deployment,
                    &package,
                    &PackageDetectRequest {
                        import_identity: imported.import_identity,
                        first_segment: 0,
                        segment_count,
                        interpretation: ComponentInterpretation::YCbCr,
                        minimum_score_ppm,
                    },
                    &PackageDetectLimits::default(),
                    &cx,
                    &scalar,
                )?;
                let retained = retain_package_detection(&mut deployment, &package, &native, &cx)?;
                sources.push(DetectionSource {
                    report: native.digest,
                    record: retained.record_digest(),
                    root: retained.root(),
                });
                let record = retained.record();
                let class_index = record
                    .labels
                    .iter()
                    .position(|label| label == "tie")
                    .ok_or("native fixture class")? as u64;
                let mut native_rows = Vec::new();
                for frame in &record.frames {
                    for detection in &frame.detections {
                        if detection.class_index == class_index {
                            native_rows.push((frame.clone(), *detection));
                        }
                    }
                }
                camera = Some(DetectionCamera {
                    alias: alias.clone(),
                    sensor: sensor.clone(),
                    import: imported.import_identity,
                    package: record.package_digest,
                    model: record.model_digest,
                    contract: record.contract_digest,
                    class_index,
                    rows: native_rows,
                });
            }
            cameras.push(camera.ok_or("retained native report")?);
        }
        assert_eq!(
            deployment
                .ledger()
                .batches()
                .iter()
                .flat_map(|batch| &batch.deltas)
                .filter(|delta| delta.family == "event_revision")
                .count(),
            0,
            "fixture must not publish an event to unlock detector evidence",
        );
        let authority = deployment.current_anchor().state_root;
        drop(deployment);
        drop(package);
        scalar.drain_and_finalize();
        cx.drain_and_finalize();
        Ok(Self {
            directory,
            root,
            cameras,
            sources,
            authority,
        })
    }

    fn request(&self) -> TestResult<Value> {
        let calibration = ScoreCalibration::from_counts(
            "cal:retained-supervisor-fixture:v1",
            &[0, 1],
            &[(2, 98), (98, 2)],
        )?;
        let calibration = format!(
            r#"{{"schema":"fss.score_calibration.v1","generation":"{}","digest":"{}","bins":[{{"lo_ppm":0,"true_positives":2,"false_positives":98}},{{"lo_ppm":1,"true_positives":98,"false_positives":2}}]}}"#,
            calibration.generation, calibration.digest,
        );
        let cameras: Vec<_> = self
            .cameras
            .iter()
            .map(|camera| {
                object(&[
                    ("camera_id", string(&camera.alias)),
                    ("sensor_id", string(&camera.sensor)),
                    ("package_digest", string(&camera.package.to_text())),
                    ("model_digest", string(&camera.model.to_text())),
                    ("contract_digest", string(&camera.contract.to_text())),
                    ("class_index", camera.class_index.to_string()),
                    ("failure_domains", "[]".to_owned()),
                    ("calibration", calibration.clone()),
                ])
            })
            .collect();
        let windows: Vec<_> = (0..3_u64)
            .map(|index| {
                object(&[
                    ("window_index", index.to_string()),
                    (
                        "end_ns",
                        (2_000_000_000 + index * 1_000_000_000).to_string(),
                    ),
                    ("observations", "[]".to_owned()),
                ])
            })
            .collect();
        let plan = object(&[
            ("schema", string("fss.retained_supervisor_plan.v1")),
            ("site_lineage", string(SITE)),
            ("hypothesis_id", string("hyp:class:tie")),
            ("expected_authority_root", string(&self.authority.to_text())),
            ("label", string("tie")),
            ("start_ns", "0".to_owned()),
            ("cameras", array(&cameras)),
            ("events", "[]".to_owned()),
            ("windows", array(&windows)),
            ("prior", "[0,0]".to_owned()),
            ("policy", r#"{"generation":"policy:retained-supervisor-fixture:v1","alert_threshold":1800,"retain_threshold":0,"reject_threshold":-1000,"min_independent_support":2,"urgent_single_domain_threshold":null,"max_wait_ns":0,"look_penalty_per_doubling":0,"operator_confirmation_available":false}"#.to_owned()),
            ("severity", r#"{"expected_harm":10000,"false_alert_cost":500,"delay_cost_per_second":100,"reversible":false}"#.to_owned()),
            ("limits", r#"{"max_read_bytes":134217728,"max_read_attempts":8192,"max_journal_bytes":16777216,"max_report_bytes":2097152}"#.to_owned()),
        ]);
        Ok(json_input::parse(&object(&[
            ("schema", string("fss.retained_detection_discovery.v1")),
            ("maximum_catalog_reports", "64".to_owned()),
            ("plan", plan),
        ]))?)
    }

    fn run(&self, request: &Value) -> TestResult<Output> {
        let bytes = encode(request);
        let path = self.directory.0.join("detection-plan.json");
        fs::write(&path, &bytes)?;
        Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .args(["supervise", "--root"])
            .arg(&self.root)
            .args(["--site", SITE, "--detection-plan"])
            .arg(path)
            .args([
                "--detection-digest",
                &ContentDigest::sha256(bytes.as_bytes()).to_text(),
            ])
            .output()?)
    }

    fn refuses_without_mutation(&self, request: &Value) -> TestResult<Output> {
        let before = inventory(&self.root)?;
        let output = self.run(request)?;
        assert!(
            !output.status.success(),
            "detector discovery unexpectedly succeeded"
        );
        assert!(
            output.stdout.is_empty(),
            "partial detector advice escaped a refusal"
        );
        assert_eq!(inventory(&self.root)?, before);
        Ok(output)
    }

    fn refresh_authority(&mut self) -> TestResult {
        let cx = context(&self.root)?;
        let deployment = ReferenceDeployment::open(&self.root, SITE, &cx)?;
        self.authority = deployment.current_anchor().state_root;
        drop(deployment);
        cx.drain_and_finalize();
        Ok(())
    }
}

fn assert_native_rows(fixture: &DetectionFixture, document: &Value) -> TestResult {
    let observed = field(document, "observations")?
        .array()
        .ok_or("native observations")?;
    let expected_count: usize = fixture.cameras.iter().map(|camera| camera.rows.len()).sum();
    assert_eq!(observed.len(), expected_count);
    for camera in &fixture.cameras {
        for (frame, native) in &camera.rows {
            let observation = observed
                .iter()
                .find(|row| {
                    text(row, "sensor_id").is_ok_and(|sensor| sensor == camera.sensor)
                        && field(row, "segment")
                            .is_ok_and(|value| value.integer() == Some(i128::from(frame.segment)))
                        && field(row, "detection_row")
                            .is_ok_and(|value| value.integer() == Some(i128::from(native.row)))
                })
                .ok_or("exact native detector row")?;
            assert_eq!(
                text(observation, "capsule_digest")?,
                frame.capsule_digest.to_text()
            );
            assert_eq!(
                text(observation, "package_digest")?,
                camera.package.to_text()
            );
            assert_eq!(text(observation, "model_digest")?, camera.model.to_text());
            assert_eq!(
                text(observation, "contract_digest")?,
                camera.contract.to_text()
            );
            assert_eq!(
                text(observation, "inference_identity")?,
                frame.inference_identity.to_text()
            );
            assert_eq!(
                field(observation, "score_f32_bits")?.integer(),
                Some(i128::from(native.score_bits))
            );
            assert_eq!(text(observation, "clock_basis")?, "estimated");
            assert_eq!(text(observation, "capture_time_label")?, "unknown");
        }
    }
    let sources = field(document, "source_inventory")?
        .array()
        .ok_or("source inventory")?;
    assert_eq!(sources.len(), fixture.sources.len());
    for expected in &fixture.sources {
        let source = sources
            .iter()
            .find(|source| {
                text(source, "report_digest").is_ok_and(|value| value == expected.report.to_text())
            })
            .ok_or("retained detector source pin")?;
        assert_eq!(text(source, "record_digest")?, expected.record.to_text());
        assert_eq!(text(source, "detection_root")?, expected.root.to_text());
        assert_eq!(field(source, "source_verified")?.boolean(), Some(true));
    }
    Ok(())
}

fn retained_detection_sources(
    fixture: &DetectionFixture,
    request: &Value,
) -> TestResult<(RetainedDetectionRequest, Vec<RetainedDetectionSource>)> {
    let bytes = encode(request).into_bytes();
    let request = RetainedDetectionRequest::from_json(&bytes, ContentDigest::sha256(&bytes))?;
    let cx = context(&fixture.root)?;
    let mut deployment = ReferenceDeployment::open(&fixture.root, SITE, &cx)?;
    let sources = run_discovered_detection_supervisor(&mut deployment, &request, &cx)
        .and_then(|report| report.source_inventory());
    drop(deployment);
    cx.drain_and_finalize();
    Ok((request, sources?))
}

fn validate_detection_sources(
    fixture: &DetectionFixture,
    request: &RetainedDetectionRequest,
    sources: &[RetainedDetectionSource],
) -> TestResult<RetainedDetectionValidation> {
    let request = request.for_authority(fixture.authority)?;
    let cx = context(&fixture.root)?;
    let mut deployment = ReferenceDeployment::open(&fixture.root, SITE, &cx)?;
    let validation = revalidate_detection_sources(&mut deployment, &request, sources, &cx);
    drop(deployment);
    cx.drain_and_finalize();
    Ok(validation?)
}

fn append_unrelated_authority(fixture: &mut DetectionFixture) -> TestResult {
    let cx = context(&fixture.root)?;
    let mut deployment = ReferenceDeployment::open(&fixture.root, SITE, &cx)?;
    let payload = deployment.stage_payload(b"explicit unrelated detector retry fixture")?;
    deployment.append_batch(
        BatchId::parse("batch:detection-revalidation:unrelated")?,
        vec![EvidenceDelta {
            delta_id: "delta:detection-revalidation:unrelated".into(),
            family: "decode_receipt".into(),
            object_id: ObjectId::parse("object:detection-revalidation:unrelated")?,
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(0), TimestampNs(2_000_000_000))?,
            plane: Plane::Cognition,
            payload_digest: payload,
            witness_digest: None,
            operation_id: None,
        }],
        vec![payload],
        &cx,
    )?;
    fixture.authority = deployment.current_anchor().state_root;
    drop(deployment);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn cold_detector_bursts_contribute_without_events_and_preserve_native_uncertainty() -> TestResult {
    let fixture = DetectionFixture::new("detection-no-event", 2, 1, false, None)?;
    assert!(fixture.cameras.iter().all(|camera| camera.rows.len() == 1));
    let before = inventory(&fixture.root)?;
    let request = fixture.request()?;
    let bytes = encode(&request);
    for source in &fixture.sources {
        assert!(
            !bytes.contains(&source.report.to_text()),
            "request supplied a detector report selector"
        );
    }
    let first = fixture.run(&request)?;
    success(&first);
    let document = report(&first)?;
    assert_eq!(
        text(&document, "schema")?,
        "fss.retained_detection_discovery_report.v1"
    );
    assert_native_rows(&fixture, &document)?;
    for flag in [
        "effects_authorized",
        "supports_absence_claim",
        "anytime_bound_verified",
    ] {
        assert_eq!(field(&document, flag)?.boolean(), Some(false));
    }
    assert_eq!(text(&document, "clock_synchronization")?, "not_established");
    assert_eq!(
        text(&document, "cross_camera_actor_association")?,
        "not_established"
    );
    let windows = field(&document, "windows")?.array().ok_or("windows")?;
    let posterior = field(
        field(&windows[0], "outcome")?,
        "posterior_log_odds_millibans",
    )?;
    for (index, window) in windows.iter().enumerate() {
        assert_eq!(field(window, "unique_observations")?.integer(), Some(2));
        assert_eq!(
            field(window, "new_observations")?.integer(),
            Some(if index == 0 { 2 } else { 0 })
        );
        assert_eq!(
            field(field(window, "outcome")?, "posterior_log_odds_millibans")?,
            posterior
        );
        assert_eq!(
            field(field(window, "outcome")?, "supporting_clusters")?.integer(),
            Some(1)
        );
        assert_eq!(
            field(field(window, "outcome")?, "effect_authority")?.boolean(),
            Some(false)
        );
    }
    let second = fixture.run(&request)?;
    success(&second);
    assert_eq!(
        second.stdout, first.stdout,
        "cold native discovery is deterministic"
    );
    let mut missing = request;
    let cameras = rows(
        fields(discovery_plan(&mut missing))
            .get_mut("cameras")
            .ok_or("cameras")?,
    );
    let mut camera = cameras[0].clone();
    fields(&mut camera).insert("camera_id".into(), Value::Text("missing-camera".into()));
    fields(&mut camera).insert(
        "sensor_id".into(),
        Value::Text("sensor:missing-camera".into()),
    );
    cameras.push(camera);
    let missing = fixture.run(&missing)?;
    success(&missing);
    assert_unobserved_camera(&report(&missing)?, "sensor:missing-camera")?;
    assert_eq!(inventory(&fixture.root)?, before);
    Ok(())
}

#[test]
fn overlapping_native_reports_count_each_source_row_once_and_wait_for_its_whole_interval()
-> TestResult {
    let fixture = DetectionFixture::new("detection-overlap", 1, 2, true, None)?;
    assert_eq!(fixture.sources.len(), 2);
    assert_ne!(fixture.sources[0].report, fixture.sources[1].report);
    assert_eq!(fixture.cameras[0].rows.len(), 2);
    let before = inventory(&fixture.root)?;
    let mut request = fixture.request()?;
    let windows = rows(
        fields(discovery_plan(&mut request))
            .get_mut("windows")
            .ok_or("windows")?,
    );
    fields(&mut windows[0]).insert("end_ns".into(), numeric(500_000_000));
    let output = fixture.run(&request)?;
    success(&output);
    let document = report(&output)?;
    assert_native_rows(&fixture, &document)?;
    let discovery = field(&document, "discovery")?;
    assert_eq!(field(discovery, "catalog_reports")?.integer(), Some(2));
    assert_eq!(
        field(discovery, "source_reports_opened")?.integer(),
        Some(2)
    );
    assert_eq!(
        field(discovery, "selected_observations")?.integer(),
        Some(3)
    );
    let windows = field(&document, "windows")?.array().ok_or("windows")?;
    for (index, window) in windows.iter().enumerate() {
        assert_eq!(
            field(window, "unique_observations")?.integer(),
            Some(if index == 0 { 0 } else { 2 })
        );
        assert_eq!(
            field(window, "new_observations")?.integer(),
            Some(if index == 1 { 2 } else { 0 })
        );
    }
    assert_eq!(
        field(
            field(&windows[1], "outcome")?,
            "posterior_log_odds_millibans"
        )?,
        field(
            field(&windows[2], "outcome")?,
            "posterior_log_odds_millibans"
        )?,
    );
    assert_eq!(inventory(&fixture.root)?, before);
    Ok(())
}

#[test]
fn generation_filtered_detections_still_require_native_custody_and_all_bounds() -> TestResult {
    let mut fixture = DetectionFixture::new("detection-excluded", 2, 1, false, None)?;
    let before = inventory(&fixture.root)?;
    let request = fixture.request()?;
    let mut excluded_request = None;
    for key in ["package_digest", "model_digest", "contract_digest"] {
        let mut changed = request.clone();
        let camera = &mut rows(
            fields(discovery_plan(&mut changed))
                .get_mut("cameras")
                .ok_or("cameras")?,
        )[0];
        fields(camera).insert(
            key.into(),
            Value::Text(ContentDigest::sha256(b"other native generation").to_text()),
        );
        let output = fixture.run(&changed)?;
        success(&output);
        let document = report(&output)?;
        let exclusions = field(field(&document, "discovery")?, "exclusions")?
            .array()
            .ok_or("exclusions")?;
        let exclusion = exclusions
            .iter()
            .find(|entry| {
                text(entry, "report_digest")
                    .is_ok_and(|value| value == fixture.sources[0].report.to_text())
                    && text(entry, "reason").is_ok_and(|value| value == format!("{key}_mismatch"))
            })
            .ok_or("verified generation exclusion")?;
        assert_eq!(
            text(exclusion, "record_digest")?,
            fixture.sources[0].record.to_text()
        );
        assert_eq!(
            text(exclusion, "detection_root")?,
            fixture.sources[0].root.to_text()
        );
        assert_eq!(field(exclusion, "source_verified")?.boolean(), Some(true));
        assert_unobserved_camera(&document, &fixture.cameras[0].sensor)?;
        excluded_request = Some(changed);
    }
    let mut catalog = request.clone();
    fields(&mut catalog).insert("maximum_catalog_reports".into(), numeric(1));
    fixture.refuses_without_mutation(&catalog)?;
    for key in [
        "max_read_bytes",
        "max_read_attempts",
        "max_journal_bytes",
        "max_report_bytes",
    ] {
        let mut bounded = request.clone();
        let limits = fields(discovery_plan(&mut bounded))
            .get_mut("limits")
            .ok_or("limits")?;
        fields(limits).insert(key.into(), numeric(1));
        fixture.refuses_without_mutation(&bounded)?;
    }
    let mut stale = request.clone();
    fields(discovery_plan(&mut stale)).insert(
        "expected_authority_root".into(),
        Value::Text(ContentDigest::sha256(b"stale root").to_text()),
    );
    fixture.refuses_without_mutation(&stale)?;
    assert_eq!(inventory(&fixture.root)?, before);

    let mut excluded_request = excluded_request.ok_or("excluded request")?;
    let (historical_request, historical_sources) =
        retained_detection_sources(&fixture, &excluded_request)?;
    assert_eq!(historical_sources.len(), 2);
    assert!(
        historical_sources
            .iter()
            .all(|source| source.source_verified)
    );
    let validation =
        validate_detection_sources(&fixture, &historical_request, &historical_sources)?;
    assert_eq!(validation.basis().state_root, fixture.authority);
    assert!(validation.reserved_bytes() > 0 && validation.read_attempts() > 0);
    let mut changed_sources = historical_sources.clone();
    changed_sources[0].detection_root = ContentDigest::sha256(b"wrong historical source root");
    assert!(validate_detection_sources(&fixture, &historical_request, &changed_sources).is_err());
    let original_authority = fixture.authority;
    append_unrelated_authority(&mut fixture)?;
    assert_ne!(fixture.authority, original_authority);
    let advanced = inventory(&fixture.root)?;
    let validated = validate_detection_sources(&fixture, &historical_request, &historical_sources)?;
    assert_eq!(validated.basis().state_root, fixture.authority);
    let validated = json_input::parse(&validated.to_json()?)?;
    assert_eq!(field(&validated, "metadata_sources")?.integer(), Some(2));
    assert_eq!(field(&validated, "native_sources")?.integer(), Some(2));
    assert_eq!(
        field(&validated, "complete_current_catalog")?.boolean(),
        Some(false)
    );
    assert_eq!(inventory(&fixture.root)?, advanced);
    let request = fixture.request()?;
    fields(discovery_plan(&mut excluded_request)).insert(
        "expected_authority_root".into(),
        Value::Text(fixture.authority.to_text()),
    );
    let cx = context(&fixture.root)?;
    let deployment = ReferenceDeployment::open(&fixture.root, SITE, &cx)?;
    let path = deployment
        .publisher()
        .spool()
        .object_path(fixture.cameras[0].rows[0].0.capsule_digest);
    drop(deployment);
    cx.drain_and_finalize();
    let original = fs::read(&path)?;
    let mut damaged = original.clone();
    *damaged.last_mut().ok_or("capsule bytes")? ^= 1;
    fs::write(&path, damaged)?;
    fixture.refuses_without_mutation(&request)?;
    fixture.refuses_without_mutation(&excluded_request)?;
    assert!(
        validate_detection_sources(&fixture, &historical_request, &historical_sources).is_err()
    );
    fs::write(path, original)?;
    Ok(())
}

#[test]
fn a_complete_empty_detector_burst_preserves_missing_observability_and_neutral_evidence()
-> TestResult {
    let fixture = DetectionFixture::new("detection-empty", 1, 1, false, Some(1_000_000))?;
    assert!(fixture.cameras[0].rows.is_empty());
    let before = inventory(&fixture.root)?;
    let output = fixture.run(&fixture.request()?)?;
    success(&output);
    let document = report(&output)?;
    assert_native_rows(&fixture, &document)?;
    assert_eq!(
        field(field(&document, "discovery")?, "non_detection_frames")?.integer(),
        Some(1)
    );
    assert_unobserved_camera(&document, &fixture.cameras[0].sensor)?;
    assert_eq!(
        field(&document, "supports_absence_claim")?.boolean(),
        Some(false)
    );
    for window in field(&document, "windows")?.array().ok_or("windows")? {
        assert_eq!(field(window, "unique_observations")?.integer(), Some(0));
        assert_eq!(
            field(field(window, "outcome")?, "supporting_clusters")?.integer(),
            Some(0)
        );
        let posterior = field(field(window, "outcome")?, "posterior_log_odds_millibans")?;
        assert_eq!(posterior, &Value::Array(vec![numeric(0), numeric(0)]));
    }
    assert_eq!(inventory(&fixture.root)?, before);
    Ok(())
}

#[test]
fn retained_frozen_health_withholds_early_detection_and_invalidates_prior_advice() -> TestResult {
    const SOURCE_FRAMES: usize = 12;
    let mut fixture = DetectionFixture::with_source_frames(
        "detection-health",
        1,
        1,
        SOURCE_FRAMES,
        false,
        None,
        true,
    )?;
    assert_eq!(fixture.cameras[0].rows.len(), 1);
    let request = fixture.request()?;
    let initial = fixture.run(&request)?;
    success(&initial);
    let initial = report(&initial)?;
    let initial_observation = &field(&initial, "observations")?
        .array()
        .ok_or("native rows")?[0];
    let initial_health = field(initial_observation, "historical_health")?;
    assert_eq!(text(initial_health, "state")?, "no_matching_diagnostic");
    assert_eq!(
        field(initial_health, "support_withheld")?.boolean(),
        Some(false)
    );
    let (historical_request, historical_sources) = retained_detection_sources(&fixture, &request)?;
    assert_eq!(historical_sources.len(), 1);
    assert!(historical_sources[0].health_digest.is_some());
    validate_detection_sources(&fixture, &historical_request, &historical_sources)?;

    // Screen the real retained import, including frames that were never passed to the detector.
    // The diagnostic reaches its frozen-frame threshold after the selected first source row.
    let cx = context(&fixture.root)?;
    let mut deployment = ReferenceDeployment::open(&fixture.root, SITE, &cx)?;
    let original_effect_root = deployment.effects().last_root();
    let screened = LongWatchReport::analyze_screened(
        &deployment,
        &WatchPlan {
            import_identity: fixture.cameras[0].import,
            interpretation: ComponentInterpretation::YCbCr,
            first_segment: 0,
            segment_count: SOURCE_FRAMES,
            zones: vec![WatchZone {
                zone_id: "camera-view".into(),
                x: 0,
                y: 0,
                width: 64,
                height: 48,
            }],
            detector: WatchDetectorConfig::default(),
            tracker: WatchTrackerConfig::default(),
        },
        WatchOptions {
            tolerate_decode_refusals: false,
        },
        &LongDwellLimits::default(),
        &cx,
    )?;
    let diagnostic = screened
        .health_diagnostic()
        .ok_or("native health diagnostic")?;
    let retained = diagnostic.retain(&mut deployment, diagnostic.approval_digest(), &cx)?;
    fixture.authority = deployment.current_anchor().state_root;
    assert_eq!(deployment.effects().last_root(), original_effect_root);
    assert_eq!(
        deployment
            .ledger()
            .batches()
            .iter()
            .flat_map(|batch| &batch.deltas)
            .filter(|delta| delta.family == "event_revision")
            .count(),
        0,
    );
    drop(deployment);
    cx.drain_and_finalize();
    let retained_inventory = inventory(&fixture.root)?;

    let error = validate_detection_sources(&fixture, &historical_request, &historical_sources)
        .expect_err("new matching diagnostic must invalidate the original health interpretation");
    assert!(
        error.to_string().contains("health context changed"),
        "{error}"
    );
    let request = fixture.request()?;
    let refreshed = fixture.run(&request)?;
    success(&refreshed);
    let refreshed = report(&refreshed)?;
    let observations = field(&refreshed, "observations")?
        .array()
        .ok_or("native rows")?;
    assert_eq!(observations.len(), 1);
    let observation = &observations[0];
    for key in [
        "identity",
        "capsule_digest",
        "inference_identity",
        "score_f32_bits",
    ] {
        assert_eq!(field(observation, key)?, field(initial_observation, key)?);
    }
    assert_eq!(field(observation, "segment")?.integer(), Some(0));
    assert_eq!(
        text(observation, "capture_time_label")?,
        "operator_assumption"
    );
    let health = field(observation, "historical_health")?;
    assert_eq!(text(health, "state")?, "findings");
    assert_eq!(field(health, "support_withheld")?.boolean(), Some(true));
    assert_eq!(
        field(health, "screening_incomplete")?.boolean(),
        Some(false)
    );
    assert_eq!(
        field(health, "current_camera_health_established")?.boolean(),
        Some(false)
    );
    assert_eq!(
        text(health, "source_import")?,
        fixture.cameras[0].import.to_text()
    );
    let diagnostics = field(health, "diagnostics")?
        .array()
        .ok_or("diagnostic pins")?;
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        text(&diagnostics[0], "record_digest")?,
        retained.record_digest.to_text()
    );
    assert_eq!(
        text(&diagnostics[0], "provenance_root")?,
        retained.provenance_root.to_text()
    );
    let findings = field(health, "findings")?
        .array()
        .ok_or("native findings")?;
    let frozen = findings
        .iter()
        .find(|finding| text(finding, "finding").is_ok_and(|name| name == "exact_frame_repetition"))
        .ok_or("actual native repetition finding")?;
    assert!(
        field(frozen, "finding_first_segment")?
            .integer()
            .is_some_and(|segment| segment > 0)
    );
    assert_eq!(field(frozen, "withheld_first_segment")?.integer(), Some(0));
    assert_eq!(
        field(frozen, "withheld_last_segment")?.integer(),
        Some((SOURCE_FRAMES - 1) as i128)
    );
    for window in field(&refreshed, "windows")?.array().ok_or("windows")? {
        assert_eq!(field(window, "unique_observations")?.integer(), Some(1));
        let outcome = field(window, "outcome")?;
        assert_eq!(field(outcome, "supporting_clusters")?.integer(), Some(0));
        assert_eq!(
            field(outcome, "posterior_log_odds_millibans")?,
            &Value::Array(vec![numeric(0), numeric(0)])
        );
        assert_eq!(field(outcome, "effect_authority")?.boolean(), Some(false));
        let evidence = field(field(window, "query")?, "evidence")?
            .array()
            .ok_or("fusion evidence")?;
        let reason = text(field(&evidence[0], "observability")?, "not_observable")?;
        assert!(reason.contains("exact_frame_repetition"));
    }
    assert_eq!(
        field(&refreshed, "supports_absence_claim")?.boolean(),
        Some(false)
    );
    let (fresh_request, fresh_sources) = retained_detection_sources(&fixture, &request)?;
    assert_ne!(
        fresh_sources[0].health_digest,
        historical_sources[0].health_digest
    );
    assert_eq!(
        fresh_sources[0].report_digest,
        historical_sources[0].report_digest
    );
    assert_eq!(
        fresh_sources[0].record_digest,
        historical_sources[0].record_digest
    );
    assert_eq!(
        fresh_sources[0].detection_root,
        historical_sources[0].detection_root
    );
    validate_detection_sources(&fixture, &fresh_request, &fresh_sources)?;
    assert_eq!(inventory(&fixture.root)?, retained_inventory);
    Ok(())
}

#[test]
fn current_privacy_and_import_deletion_withdraw_direct_detector_advice() -> TestResult {
    let mut fixture = DetectionFixture::new("detection-withdrawal", 2, 1, false, None)?;
    success(&fixture.run(&fixture.request()?)?);
    let preview = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["privacy-mask", "declare", "--root"])
        .arg(&fixture.root)
        .args([
            "--site",
            SITE,
            "--sensor",
            &fixture.cameras[0].sensor,
            "--resolution",
            "64x48",
            "--rect",
            "0,0,1,1",
        ])
        .output()?;
    success(&preview);
    let preview = report(&preview)?;
    let declared = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["privacy-mask", "declare", "--root"])
        .arg(&fixture.root)
        .args([
            "--site",
            SITE,
            "--sensor",
            &fixture.cameras[0].sensor,
            "--resolution",
            "64x48",
            "--rect",
            "0,0,1,1",
            "--approve",
            text(&preview, "approval_digest")?,
        ])
        .output()?;
    success(&declared);
    fixture.refresh_authority()?;
    let mut request = fixture.request()?;
    let refused = fixture.refuses_without_mutation(&request)?;
    assert!(
        std::str::from_utf8(&refused.stderr)?.contains("ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001")
    );
    let camera = &mut rows(
        fields(discovery_plan(&mut request))
            .get_mut("cameras")
            .ok_or("cameras")?,
    )[0];
    fields(camera).insert(
        "package_digest".into(),
        Value::Text(ContentDigest::sha256(b"foreign generation").to_text()),
    );
    let excluded = fixture.refuses_without_mutation(&request)?;
    assert!(
        std::str::from_utf8(&excluded.stderr)?.contains("ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001")
    );

    // The unrelated sensor is still readable. Delete through the real owner, then verify that
    // metadata discovery cannot resurrect the retained report's now-withdrawn source.
    let mut second_only = fixture.request()?;
    rows(
        fields(discovery_plan(&mut second_only))
            .get_mut("cameras")
            .ok_or("cameras")?,
    )
    .remove(0);
    success(&fixture.run(&second_only)?);
    let deletion = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "plan", "--root"])
        .arg(&fixture.root)
        .args([
            "--site",
            SITE,
            "--import-id",
            &fixture.cameras[1].import.to_text(),
        ])
        .output()?;
    success(&deletion);
    let deletion = report(&deletion)?;
    let committed = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "commit", "--root"])
        .arg(&fixture.root)
        .args([
            "--site",
            SITE,
            "--plan",
            text(&deletion, "plan_digest")?,
            "--approve",
            text(&deletion, "approval_digest")?,
        ])
        .output()?;
    success(&committed);
    fixture.refresh_authority()?;
    fields(discovery_plan(&mut second_only)).insert(
        "expected_authority_root".into(),
        Value::Text(fixture.authority.to_text()),
    );
    fixture.refuses_without_mutation(&second_only)?;
    Ok(())
}

#[test]
fn detector_discovery_admission_precedes_any_creation_of_an_absent_deployment() -> TestResult {
    let directory = Directory::new("detection-admission")?;
    let root = directory.0.join("must-not-exist");
    let plan = directory.0.join("not-a-plan.json");
    fs::write(&plan, b"not JSON")?;
    let base = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
        command
            .args(["supervise", "--root"])
            .arg(&root)
            .args(["--site", SITE, "--detection-plan"])
            .arg(&plan);
        command
    };
    let missing = base().output()?;
    assert!(!missing.status.success() && missing.stdout.is_empty());
    let wrong = base()
        .args([
            "--detection-digest",
            &ContentDigest::sha256(b"other").to_text(),
        ])
        .output()?;
    assert!(!wrong.status.success() && wrong.stdout.is_empty());
    assert!(std::str::from_utf8(&wrong.stderr)?.contains("byte digest"));
    let mixed = base()
        .args([
            "--detection-digest",
            &ContentDigest::sha256(b"not JSON").to_text(),
            "--discover-plan",
            "other.json",
        ])
        .output()?;
    assert!(!mixed.status.success() && mixed.stdout.is_empty());
    assert!(std::str::from_utf8(&mixed.stderr)?.contains("mutually exclusive"));
    assert!(!root.exists());
    Ok(())
}
