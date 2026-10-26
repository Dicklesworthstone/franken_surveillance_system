#![forbid(unsafe_code)]
//! Cold durable delivery carries actual native detector sources without inventing events.

use super::*;

use fss_reference::agent_session::checkpoint::journal::supervision::SupervisionSubscription;
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, inspect_session_bytes,
};
use fss_reference::agent_session::work_claims::WorkClaimLimits;

const SUBSCRIPTION: &str = "native-detector";

fn open_session(fixture: &DetectionFixture) -> TestResult<String> {
    let output = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(["session", "open", "--json", "--root"])
        .arg(&fixture.root)
        .args([
            "--principal",
            "principal:local-operator",
            "--mission",
            "Review retained detector bursts with durable delivery",
            "--objective",
            "Preserve native sources, health context and exact acknowledgements",
            "--view",
            "brief",
            "--budget-tokens",
            "100000",
        ])
        .output()?;
    success(&output);
    Ok(text(&report(&output)?, "sessionId")?.to_owned())
}

fn configuration_path(fixture: &DetectionFixture) -> PathBuf {
    fixture.directory.0.join("detection-session-plan.json")
}

fn poll(
    fixture: &DetectionFixture,
    request: &Value,
    session: &str,
    maximum_attempts: u32,
    flags: &[(&str, &str)],
) -> TestResult<Output> {
    let bytes = encode(request);
    let path = configuration_path(fixture);
    fs::write(&path, &bytes)?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
    command
        .args(["supervise", "--root"])
        .arg(&fixture.root)
        .args(["--site", SITE, "--detection-plan"])
        .arg(path)
        .args([
            "--detection-digest",
            &ContentDigest::sha256(bytes.as_bytes()).to_text(),
            "--session",
            session,
            "--subscription",
            SUBSCRIPTION,
            "--authority-root",
            &fixture.authority.to_text(),
            "--max-poll-attempts",
            &maximum_attempts.to_string(),
        ]);
    for &(flag, value) in flags {
        command.args([flag, value]);
    }
    Ok(command.output()?)
}

fn resume(fixture: &DetectionFixture, session: &str, flags: &[(&str, &str)]) -> TestResult<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
    command
        .args(["supervise", "--resume", "yes", "--root"])
        .arg(&fixture.root)
        .args([
            "--site",
            SITE,
            "--session",
            session,
            "--subscription",
            SUBSCRIPTION,
            "--authority-root",
            &fixture.authority.to_text(),
        ]);
    for &(flag, value) in flags {
        command.args([flag, value]);
    }
    Ok(command.output()?)
}

fn state(fixture: &DetectionFixture) -> TestResult<SupervisionSubscription> {
    inspect_session_bytes(
        &fs::read(fixture.root.join("agent/sessions/journal.fssj"))?,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?
    .supervisions
    .into_iter()
    .find(|state| state.registration().subscription_id == SUBSCRIPTION)
    .ok_or_else(|| "native detector subscription missing".into())
}

fn canonical_inventory(fixture: &DetectionFixture) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    Ok(inventory(&fixture.root)?
        .into_iter()
        .filter(|(path, _)| !path.starts_with("agent"))
        .collect())
}

fn raw_report(output: &Output) -> TestResult<&[u8]> {
    let text = std::str::from_utf8(&output.stdout)?;
    let start = text.find(",\"report\":").ok_or("embedded report")? + ",\"report\":".len();
    let end = text
        .rfind(",\"receipt_digest\":")
        .ok_or("outer complete receipt")?;
    if end <= start {
        return Err("invalid native report boundaries".into());
    }
    Ok(&output.stdout[start..end])
}

fn refusal(output: &Output) {
    assert!(
        !output.status.success(),
        "native session operation unexpectedly succeeded"
    );
    assert!(
        output.stdout.is_empty(),
        "private or partial successful report escaped refusal"
    );
}

fn assert_native_inventory(
    state: &SupervisionSubscription,
    expected: &[&DetectionSource],
) -> TestResult {
    let pending = state.pending().ok_or("pending native delivery")?;
    assert!(
        pending.source_inventory().is_empty(),
        "native records acquired fake event pins"
    );
    let sources = pending.detection_source_inventory();
    assert_eq!(sources.len(), expected.len());
    for expected in expected {
        let source = sources
            .iter()
            .find(|source| source.report_digest == expected.report)
            .ok_or("exact typed native source")?;
        assert_eq!(source.record_digest, expected.record);
        assert_eq!(source.detection_root, expected.root);
        assert!(source.source_verified);
    }
    Ok(())
}

fn append_later_detection(
    fixture: &mut DetectionFixture,
) -> TestResult<(DetectionSource, ContentDigest, u32)> {
    let source = fixture.directory.0.join("later-native-burst.jpg");
    fs::write(&source, JPEG)?;
    let cx = context(&fixture.root)?;
    let scalar = ScalarExecCx::new();
    let mut deployment = ReferenceDeployment::open(&fixture.root, SITE, &cx)?;
    let package = RgbDetectorPackage::load(
        PACKAGE,
        ContentDigest::parse(PACKAGE_SHA256)?,
        1 << 40,
        &cx,
        &scalar,
    )?;
    let imported = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            &source,
            SensorId::parse(&fixture.cameras[0].sensor)?,
            StreamId::parse("stream:retained-detection-later")?,
        )
        .with_receive_time(TimestampNs(2_500_000_000)),
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
    let retained = retain_package_detection(&mut deployment, &package, &native, &cx)?;
    let frame = retained
        .record()
        .frames
        .first()
        .ok_or("later retained frame")?;
    let row = frame
        .detections
        .iter()
        .find(|row| row.class_index == fixture.cameras[0].class_index)
        .ok_or("later native class row")?;
    let result = (
        DetectionSource {
            report: native.digest,
            record: retained.record_digest(),
            root: retained.root(),
        },
        frame.capsule_digest,
        row.score_bits,
    );
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
    fixture.authority = deployment.current_anchor().state_root;
    drop(deployment);
    drop(package);
    scalar.drain_and_finalize();
    cx.drain_and_finalize();
    Ok(result)
}

#[test]
fn cold_native_schedule_recovers_typed_sources_advances_real_bursts_and_preserves_quota()
-> TestResult {
    let mut fixture = DetectionFixture::new("detection-session-schedule", 1, 1, false, None)?;
    let request = fixture.request()?;
    let session = open_session(&fixture)?;
    let scheduled = poll(&fixture, &request, &session, 4, &[("--schedule", "yes")])?;
    success(&scheduled);
    assert_eq!(text(&report(&scheduled)?, "state")?, "scheduled");
    assert_eq!(state(&fixture)?.attempts_reserved(), 0);
    let first = poll(&fixture, &request, &session, 4, &[])?;
    success(&first);
    let first_json = report(&first)?;
    assert_eq!(
        text(&first_json, "schema")?,
        "fss.retained_supervisor_session_report.v1"
    );
    assert_eq!(
        field(&first_json, "active_window_count")?.integer(),
        Some(1)
    );
    let native = field(&first_json, "report")?;
    assert_eq!(
        text(native, "schema")?,
        "fss.retained_detection_discovery_report.v1"
    );
    assert_native_rows(&fixture, native)?;
    assert_eq!(
        field(native, "windows")?
            .array()
            .ok_or("initial native windows")?
            .len(),
        1
    );
    let receipt = text(&first_json, "delivery_receipt")?.to_owned();
    let original_payload = raw_report(&first)?.to_vec();
    assert_eq!(
        text(&first_json, "payload_digest")?,
        ContentDigest::sha256(&original_payload).to_text()
    );
    let original = state(&fixture)?;
    let registration = original.registration().clone();
    assert_native_inventory(&original, &[&fixture.sources[0]])?;
    assert!(
        original
            .pending()
            .ok_or("pending")?
            .detection_source_inventory()[0]
            .health_digest
            .is_some()
    );
    fs::remove_file(configuration_path(&fixture))?;

    let inspected = resume(&fixture, &session, &[("--inspect", "yes")])?;
    success(&inspected);
    let inspected = report(&inspected)?;
    assert_eq!(text(&inspected, "pending_receipt")?, receipt);
    assert_eq!(field(&inspected, "report")?, &Value::Null);
    assert_eq!(field(&inspected, "source_validation")?, &Value::Null);
    assert_eq!(state(&fixture)?, original);

    // A genuine newer native burst cannot widen a pending report or its historical inventory.
    let (later, later_capsule, later_score) = append_later_detection(&mut fixture)?;
    let canonical = canonical_inventory(&fixture)?;
    let replay = resume(&fixture, &session, &[])?;
    success(&replay);
    let replay_json = report(&replay)?;
    assert_eq!(raw_report(&replay)?, original_payload);
    assert_eq!(text(&replay_json, "delivery_receipt")?, receipt);
    assert_eq!(field(&replay_json, "replayed")?.boolean(), Some(true));
    assert_eq!(field(&replay_json, "attempts_reserved")?.integer(), Some(2));
    assert_eq!(
        text(&replay_json, "configuration_digest")?,
        registration.configuration_digest.to_text()
    );
    assert_eq!(
        field(
            field(&replay_json, "source_validation")?,
            "complete_current_catalog"
        )?
        .boolean(),
        Some(false),
    );
    assert_native_inventory(&state(&fixture)?, &[&fixture.sources[0]])?;
    success(&resume(&fixture, &session, &[("--acknowledge", &receipt)])?);
    success(&resume(&fixture, &session, &[("--acknowledge", &receipt)])?);
    assert_eq!(state(&fixture)?.attempts_reserved(), 3);
    success(&resume(
        &fixture,
        &session,
        &[("--advance-window", "1"), ("--after-receipt", &receipt)],
    )?);
    assert_eq!(state(&fixture)?.attempts_reserved(), 3);

    let next = resume(&fixture, &session, &[])?;
    success(&next);
    let next_json = report(&next)?;
    let next_receipt = text(&next_json, "delivery_receipt")?.to_owned();
    assert_ne!(next_receipt, receipt);
    assert_eq!(field(&next_json, "active_window_count")?.integer(), Some(2));
    let native = field(&next_json, "report")?;
    let observations = field(native, "observations")?
        .array()
        .ok_or("native observations")?;
    assert_eq!(observations.len(), 2);
    let later_row = observations
        .iter()
        .find(|row| {
            text(row, "capsule_digest").is_ok_and(|digest| digest == later_capsule.to_text())
        })
        .ok_or("newly eligible native burst")?;
    assert_eq!(
        field(later_row, "score_f32_bits")?.integer(),
        Some(i128::from(later_score))
    );
    assert_eq!(text(later_row, "capture_time_label")?, "unknown");
    for (index, window) in field(native, "windows")?
        .array()
        .ok_or("native windows")?
        .iter()
        .enumerate()
    {
        assert_eq!(field(window, "new_observations")?.integer(), Some(1));
        assert_eq!(
            field(window, "unique_observations")?.integer(),
            Some(index as i128 + 1)
        );
        assert_eq!(
            field(field(window, "outcome")?, "effect_authority")?.boolean(),
            Some(false)
        );
    }
    let pending = state(&fixture)?;
    assert_native_inventory(&pending, &[&fixture.sources[0], &later])?;
    assert_eq!(pending.attempts_reserved(), 4);
    refusal(&resume(&fixture, &session, &[])?);
    refusal(&resume(
        &fixture,
        &session,
        &[("--acknowledge", &next_receipt)],
    )?);
    success(&resume(&fixture, &session, &[("--inspect", "yes")])?);
    success(&resume(&fixture, &session, &[("--acknowledge", &receipt)])?);
    assert_eq!(state(&fixture)?, pending);
    success(&resume(
        &fixture,
        &session,
        &[("--discard", &next_receipt)],
    )?);
    success(&resume(
        &fixture,
        &session,
        &[
            ("--advance-window", "2"),
            ("--after-receipt", &next_receipt),
        ],
    )?);
    refusal(&resume(&fixture, &session, &[])?);
    refusal(&resume(
        &fixture,
        &session,
        &[("--max-poll-attempts", "64")],
    )?);
    let exhausted = state(&fixture)?;
    assert_eq!(exhausted.registration(), &registration);
    assert_eq!(exhausted.active_window_count(), Some(3));
    assert_eq!(exhausted.attempts_reserved(), 4);
    assert_eq!(exhausted.reserved_bytes(), 4 * registration.max_read_bytes);
    assert_eq!(
        exhausted.reserved_read_attempts(),
        4 * registration.max_read_attempts
    );
    assert_eq!(
        exhausted.last_acknowledged(),
        Some(ContentDigest::parse(&receipt)?)
    );
    assert_eq!(
        exhausted.last_discarded(),
        Some(ContentDigest::parse(&next_receipt)?)
    );
    assert!(exhausted.pending().is_none());
    assert!(!configuration_path(&fixture).exists());
    assert_eq!(canonical_inventory(&fixture)?, canonical);
    Ok(())
}

#[test]
fn real_new_health_diagnostic_blocks_pending_native_replay_and_first_ack_without_hiding_receipt()
-> TestResult {
    let mut fixture = DetectionFixture::with_source_frames(
        "detection-session-health",
        1,
        1,
        12,
        false,
        None,
        true,
    )?;
    let session = open_session(&fixture)?;
    let first = poll(&fixture, &fixture.request()?, &session, 3, &[])?;
    success(&first);
    let receipt = text(&report(&first)?, "delivery_receipt")?.to_owned();
    let original = state(&fixture)?;
    assert_native_inventory(&original, &[&fixture.sources[0]])?;
    let original_health = original
        .pending()
        .ok_or("pending")?
        .detection_source_inventory()[0]
        .health_digest;
    assert!(original_health.is_some());
    fs::remove_file(configuration_path(&fixture))?;

    let cx = context(&fixture.root)?;
    let mut deployment = ReferenceDeployment::open(&fixture.root, SITE, &cx)?;
    let effects = deployment.effects().last_root();
    let screened = LongWatchReport::analyze_screened(
        &deployment,
        &WatchPlan {
            import_identity: fixture.cameras[0].import,
            interpretation: ComponentInterpretation::YCbCr,
            first_segment: 0,
            segment_count: 12,
            zones: vec![WatchZone {
                zone_id: "native-view".into(),
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
        .ok_or("actual retained health diagnostic")?;
    diagnostic.retain(&mut deployment, diagnostic.approval_digest(), &cx)?;
    fixture.authority = deployment.current_anchor().state_root;
    assert_eq!(deployment.effects().last_root(), effects);
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
    let canonical = canonical_inventory(&fixture)?;

    for flags in [Vec::new(), vec![("--acknowledge", receipt.as_str())]] {
        let output = resume(&fixture, &session, &flags)?;
        refusal(&output);
        assert!(String::from_utf8_lossy(&output.stderr).contains("health context changed"));
    }
    let blocked = state(&fixture)?;
    assert_eq!(blocked.attempts_reserved(), 3);
    assert_eq!(blocked.last_acknowledged(), None);
    assert_eq!(
        blocked
            .pending()
            .ok_or("blocked pending")?
            .receipt()
            .to_text(),
        receipt
    );
    assert_eq!(
        blocked
            .pending()
            .ok_or("blocked pins")?
            .detection_source_inventory()[0]
            .health_digest,
        original_health,
    );
    let inspected = resume(&fixture, &session, &[("--inspect", "yes")])?;
    success(&inspected);
    let inspected = report(&inspected)?;
    assert_eq!(text(&inspected, "pending_receipt")?, receipt);
    assert_eq!(field(&inspected, "report")?, &Value::Null);
    assert_eq!(field(&inspected, "source_validation")?, &Value::Null);
    assert_eq!(state(&fixture)?, blocked);
    success(&resume(&fixture, &session, &[("--discard", &receipt)])?);
    let discarded = state(&fixture)?;
    assert!(discarded.pending().is_none());
    assert_eq!(discarded.attempts_reserved(), 3);
    assert_eq!(discarded.last_acknowledged(), None);
    assert_eq!(
        discarded.last_discarded(),
        Some(ContentDigest::parse(&receipt)?)
    );
    refusal(&resume(&fixture, &session, &[])?);
    assert!(!configuration_path(&fixture).exists());
    assert_eq!(canonical_inventory(&fixture)?, canonical);
    Ok(())
}

#[test]
fn corrupt_generation_excluded_native_source_still_blocks_cold_replay_and_ack() -> TestResult {
    let fixture = DetectionFixture::new("detection-session-corrupt", 2, 1, false, None)?;
    let mut request = fixture.request()?;
    let camera = &mut rows(
        fields(discovery_plan(&mut request))
            .get_mut("cameras")
            .ok_or("cameras")?,
    )[0];
    fields(camera).insert(
        "package_digest".into(),
        Value::Text(ContentDigest::sha256(b"different selected native generation").to_text()),
    );
    let session = open_session(&fixture)?;
    let first = poll(&fixture, &request, &session, 3, &[])?;
    success(&first);
    let first_json = report(&first)?;
    assert_eq!(
        field(field(&first_json, "report")?, "observations")?
            .array()
            .ok_or("selected rows")?
            .len(),
        1
    );
    let receipt = text(&first_json, "delivery_receipt")?.to_owned();
    let original = state(&fixture)?;
    assert_native_inventory(&original, &[&fixture.sources[0], &fixture.sources[1]])?;
    let excluded = original
        .pending()
        .ok_or("pending")?
        .detection_source_inventory()
        .iter()
        .find(|source| source.report_digest == fixture.sources[0].report)
        .ok_or("generation-excluded typed source")?;
    assert!(excluded.source_verified && excluded.health_digest.is_none());
    fs::remove_file(configuration_path(&fixture))?;

    let cx = context(&fixture.root)?;
    let deployment = ReferenceDeployment::open(&fixture.root, SITE, &cx)?;
    let capsule_path = deployment
        .publisher()
        .spool()
        .object_path(fixture.cameras[0].rows[0].0.capsule_digest);
    drop(deployment);
    cx.drain_and_finalize();
    let original_bytes = fs::read(&capsule_path)?;
    let mut damaged = original_bytes.clone();
    *damaged.last_mut().ok_or("native capsule bytes")? ^= 1;
    fs::write(&capsule_path, damaged)?;
    let canonical = canonical_inventory(&fixture)?;

    refusal(&resume(&fixture, &session, &[])?);
    refusal(&resume(&fixture, &session, &[("--acknowledge", &receipt)])?);
    let blocked = state(&fixture)?;
    assert_eq!(blocked.attempts_reserved(), 3);
    assert_eq!(blocked.registration(), original.registration());
    assert_eq!(blocked.last_acknowledged(), None);
    assert_native_inventory(&blocked, &[&fixture.sources[0], &fixture.sources[1]])?;
    let inspected = resume(&fixture, &session, &[("--inspect", "yes")])?;
    success(&inspected);
    let inspected = report(&inspected)?;
    assert_eq!(text(&inspected, "pending_receipt")?, receipt);
    assert_eq!(field(&inspected, "report")?, &Value::Null);
    assert_eq!(field(&inspected, "source_validation")?, &Value::Null);
    assert_eq!(state(&fixture)?, blocked);
    success(&resume(&fixture, &session, &[("--discard", &receipt)])?);
    let discarded = state(&fixture)?;
    assert!(discarded.pending().is_none());
    assert_eq!(discarded.last_acknowledged(), None);
    assert_eq!(
        discarded.last_discarded(),
        Some(ContentDigest::parse(&receipt)?)
    );
    assert_eq!(discarded.attempts_reserved(), 3);
    assert_eq!(canonical_inventory(&fixture)?, canonical);
    fs::write(capsule_path, original_bytes)?;
    refusal(&resume(&fixture, &session, &[])?);
    assert_eq!(state(&fixture)?.attempts_reserved(), 3);
    assert!(!configuration_path(&fixture).exists());
    Ok(())
}
