#![forbid(unsafe_code)]
//! Fresh processes advance the immutable native evidence horizon without resetting custody or quota.

use super::*;

/// Publish a second real native observation for the configured sensor. The file adapter honestly
/// bounds its unknown capture interval by receive time; it does not invent a precise capture time.
fn append_later_native_event(f: &mut Fixture) -> TestResult<NativeCamera> {
    let sensor = f.cameras[0].sensor.clone();
    let source = f.directory.0.join("later-native-source.jpg");
    fs::write(&source, JPEG)?;
    let cx = context(&f.root)?;
    let scalar = ScalarExecCx::new();
    let mut deployment = ReferenceDeployment::open(&f.root, SITE, &cx)?;
    let package = RgbDetectorPackage::load(
        PACKAGE, ContentDigest::parse(PACKAGE_SHA256)?, 1 << 40, &cx, &scalar,
    )?;
    let imported = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            &source, SensorId::parse(&sensor)?,
            StreamId::parse("stream:retained-supervisor-later")?,
        ).with_receive_time(TimestampNs(2_500_000_000)),
        &cx, &mut deployment,
    )?;
    fs::remove_file(source)?;
    let native = run_package_detection(
        &deployment, &package,
        &PackageDetectRequest {
            import_identity: imported.import_identity,
            first_segment: 0, segment_count: 1,
            interpretation: ComponentInterpretation::YCbCr,
            minimum_score_ppm: None,
        },
        &PackageDetectLimits::default(), &cx, &scalar,
    )?;
    retain_package_detection(&mut deployment, &package, &native, &cx)?;
    let report = PackageAnalysisReport::read(
        &deployment, native.digest, "tie",
        PackageTrackingConfig {
            confirmation_hits: 1, maximum_missed_frames: 1, minimum_iou_ppm: 100_000,
        },
        &cx,
    )?;
    let track = report.tracks().iter().find(|track| track.confirmed)
        .ok_or("later native fixture track")?;
    let observation = track.observations.first().ok_or("later native fixture observation")?;
    let (row, score_bits, _, _) = observation.detection.ok_or("later native assigned row")?;
    let proposal = PackageEventProposal::prepare(
        &deployment, report.encoded(), report.digest(), track.identity, &cx,
    )?;
    let receipt = proposal.publish(&mut deployment, proposal.digest(), &cx)?;
    let record = report.retained().record();
    let camera = NativeCamera {
        alias: f.cameras[0].alias.clone(), sensor,
        import: imported.import_identity, event: receipt.event.event_id,
        event_root: receipt.event_root, package: record.package_digest,
        model: record.model_digest, contract: record.contract_digest,
        class_index: report.class_index(), capsule: observation.capsule_digest,
        segment: observation.segment, row, score_bits,
    };
    f.authority = deployment.current_anchor().state_root;
    drop(deployment);
    drop(package);
    scalar.drain_and_finalize();
    cx.drain_and_finalize();
    assert_ne!(camera.capsule, f.cameras[0].capsule);
    assert_ne!(camera.event, f.cameras[0].event);
    Ok(camera)
}

fn advance(
    f: &Fixture, request: &Value, session: &str, subscription: &str,
    maximum_attempts: u32, window_index: &str, receipt: &str,
) -> TestResult<Output> {
    poll_with_flags(f, request, session, subscription, maximum_attempts, &[
        ("--advance-window", window_index), ("--after-receipt", receipt),
    ])
}

fn assert_prefix(output: &Output, windows: usize, observations: usize) -> TestResult<Value> {
    success(output);
    let envelope = report(output)?;
    assert_eq!(field(&envelope, "active_window_count")?.integer(), Some(windows as i128));
    assert_eq!(field(&envelope, "report_window_count")?.integer(), Some(windows as i128));
    let native = field(field(&envelope, "report")?, "supervision")?;
    assert_eq!(field(native, "windows")?.array().ok_or("native windows")?.len(), windows);
    assert_eq!(field(native, "observations")?.array().ok_or("native observations")?.len(), observations);
    assert_eq!(text(&envelope, "payload_digest")?, ContentDigest::sha256(raw_report(output)?).to_text());
    Ok(envelope)
}

#[test]
fn scheduled_cold_delivery_advances_real_native_evidence_without_replaying_support() -> TestResult {
    let mut f = Fixture::new("scheduled-native", 1)?;
    let request = f.discovery(&[0])?;
    let session = open_session(&f)?;
    let configured = poll(&f, &request, &session, "schedule", 16, Some(("--schedule", "yes")))?;
    success(&configured);
    let configured = report(&configured)?;
    assert_eq!(text(&configured, "state")?, "scheduled");
    assert_eq!(field(&configured, "active_window_count")?.integer(), Some(1));
    assert_eq!(field(&configured, "total_windows")?.integer(), Some(3));
    assert_eq!(field(&configured, "report")?, &Value::Null);
    assert_eq!(field(&configured, "source_validation")?, &Value::Null);
    let initial = state(&f, "schedule")?;
    assert_eq!(initial.attempts_reserved(), 0);
    assert!(initial.reservation().is_none() && initial.pending().is_none());
    success(&poll(&f, &request, &session, "schedule", 16, Some(("--schedule", "yes")))?);
    assert_eq!(state(&f, "schedule")?.digest(), initial.digest());

    let first = poll(&f, &request, &session, "schedule", 16, None)?;
    let first_json = assert_prefix(&first, 1, 1)?;
    let first_receipt = text(&first_json, "delivery_receipt")?.to_owned();
    let first_payload = raw_report(&first)?.to_vec();
    let replay = poll(&f, &request, &session, "schedule", 16, None)?;
    assert_prefix(&replay, 1, 1)?;
    assert_eq!(raw_report(&replay)?, first_payload);
    assert_eq!(state(&f, "schedule")?.attempts_reserved(), 2);
    refusal(&advance(&f, &request, &session, "schedule", 16, "1", &first_receipt)?);
    refusal(&advance(&f, &request, &session, "schedule", 16, "2", &first_receipt)?);
    assert_eq!(state(&f, "schedule")?.attempts_reserved(), 2);

    // The newly retained native event is outside prefix one. A cold historical retry still
    // releases the exact original bytes under current source checks, not a newly widened report.
    let later = append_later_native_event(&mut f)?;
    let canonical = canonical_inventory(&f)?;
    let replay = poll(&f, &request, &session, "schedule", 16, None)?;
    assert_prefix(&replay, 1, 1)?;
    assert_eq!(raw_report(&replay)?, first_payload);
    assert_eq!(text(&report(&replay)?, "delivery_receipt")?, first_receipt);
    success(&poll(&f, &request, &session, "schedule", 16, Some(("--acknowledge", &first_receipt)))?);
    let refreshed = poll(&f, &request, &session, "schedule", 16, None)?;
    let refreshed_json = assert_prefix(&refreshed, 1, 1)?;
    let refreshed_receipt = text(&refreshed_json, "delivery_receipt")?.to_owned();
    success(&poll(&f, &request, &session, "schedule", 16, Some(("--acknowledge", &refreshed_receipt)))?);
    assert_eq!(state(&f, "schedule")?.attempts_reserved(), 6);

    let advanced = advance(&f, &request, &session, "schedule", 16, "1", &refreshed_receipt)?;
    success(&advanced);
    let advanced = report(&advanced)?;
    assert_eq!(text(&advanced, "state")?, "advanced");
    assert_eq!(field(&advanced, "active_window_count")?.integer(), Some(2));
    assert_eq!(field(&advanced, "report")?, &Value::Null);
    assert_eq!(field(&advanced, "source_validation")?, &Value::Null);
    assert_eq!(state(&f, "schedule")?.attempts_reserved(), 6);
    let before_retry = state(&f, "schedule")?.digest();
    success(&advance(&f, &request, &session, "schedule", 16, "1", &refreshed_receipt)?);
    assert_eq!(state(&f, "schedule")?.digest(), before_retry);

    let second = poll(&f, &request, &session, "schedule", 16, None)?;
    let second_json = assert_prefix(&second, 2, 2)?;
    let second_receipt = text(&second_json, "delivery_receipt")?.to_owned();
    let native = field(field(&second_json, "report")?, "supervision")?;
    let observations = field(native, "observations")?.array().ok_or("two native observations")?;
    let observation = observations.iter().find(|item|
        text(item, "capsule_digest").is_ok_and(|digest| digest == later.capsule.to_text()))
        .ok_or("newly eligible native observation")?;
    assert_eq!(field(observation, "score_f32_bits")?.integer(), Some(i128::from(later.score_bits)));
    assert_eq!(text(observation, "clock_basis")?, "estimated");
    assert_eq!(text(observation, "capture_time_label")?, "unknown");
    let windows = field(native, "windows")?.array().ok_or("cumulative native windows")?;
    for (index, window) in windows.iter().enumerate() {
        assert_eq!(field(window, "new_observations")?.integer(), Some(1));
        assert_eq!(field(window, "unique_observations")?.integer(), Some(index as i128 + 1));
    }

    // Exact retries of the latest advance/configuration are metadata-only and preserve a
    // successor pending delivery. Replacing any future window is a configuration conflict.
    let pending_state = state(&f, "schedule")?;
    success(&advance(&f, &request, &session, "schedule", 16, "1", &refreshed_receipt)?);
    success(&poll(&f, &request, &session, "schedule", 16, Some(("--schedule", "yes")))?);
    assert_eq!(state(&f, "schedule")?.digest(), pending_state.digest());
    let mut changed = request.clone();
    let future = &mut rows(fields(discovery_plan(&mut changed)).get_mut("windows").ok_or("windows")?)[2];
    fields(future).insert("end_ns".into(), numeric(5_000_000_000));
    refusal(&poll(&f, &changed, &session, "schedule", 16, Some(("--schedule", "yes")))?);
    assert_eq!(state(&f, "schedule")?.digest(), pending_state.digest());

    success(&poll(&f, &request, &session, "schedule", 16, Some(("--discard", &second_receipt)))?);
    let discarded = state(&f, "schedule")?;
    assert_eq!(discarded.schedule().ok_or("schedule")?.resolved_acknowledged(), Some(false));
    assert_eq!(discarded.last_acknowledged(), Some(ContentDigest::parse(&refreshed_receipt)?));
    success(&advance(&f, &request, &session, "schedule", 16, "2", &second_receipt)?);
    refusal(&advance(&f, &request, &session, "schedule", 16, "1", &refreshed_receipt)?);
    let final_report = poll(&f, &request, &session, "schedule", 16, None)?;
    let final_json = assert_prefix(&final_report, 3, 2)?;
    let final_native = field(field(&final_json, "report")?, "supervision")?;
    let windows = field(final_native, "windows")?.array().ok_or("all windows")?;
    assert_eq!(field(&windows[2], "new_observations")?.integer(), Some(0));
    assert_eq!(field(&windows[2], "unique_observations")?.integer(), Some(2));
    let mut current_request = request.clone();
    fields(discovery_plan(&mut current_request)).insert(
        "expected_authority_root".into(), Value::Text(f.authority.to_text()),
    );
    let one_shot = f.run_discovered(&current_request)?;
    success(&one_shot);
    let one_shot = report(&one_shot)?;
    for key in ["plan_digest", "observations", "windows", "authority_state_root"] {
        assert_eq!(field(final_native, key)?, field(field(&one_shot, "supervision")?, key)?);
    }
    let final_receipt = text(&final_json, "delivery_receipt")?;
    success(&poll(&f, &request, &session, "schedule", 16, Some(("--acknowledge", final_receipt)))?);
    refusal(&advance(&f, &request, &session, "schedule", 16, "3", final_receipt)?);
    assert_eq!(state(&f, "schedule")?.attempts_reserved(), 9);
    assert_eq!(canonical_inventory(&f)?, canonical);
    Ok(())
}

#[test]
fn failed_scheduled_native_read_can_advance_after_ack_without_refunding_lifetime_quota() -> TestResult {
    let f = Fixture::new("scheduled-budget", 1)?;
    let request = f.discovery(&[0])?;
    let session = open_session(&f)?;
    success(&poll(&f, &request, &session, "budget", 3, Some(("--schedule", "yes")))?);
    let first = poll(&f, &request, &session, "budget", 3, None)?;
    let first = assert_prefix(&first, 1, 1)?;
    let receipt = text(&first, "delivery_receipt")?.to_owned();
    success(&poll(&f, &request, &session, "budget", 3, Some(("--acknowledge", &receipt)))?);

    // Damage only the test fixture's retained native capsule. Ledger metadata stays valid,
    // so the native verification failure occurs after the durable full-cap reservation.
    let cx = context(&f.root)?;
    let deployment = ReferenceDeployment::open(&f.root, SITE, &cx)?;
    let capsule_path = deployment.publisher().spool().object_path(f.cameras[0].capsule);
    drop(deployment);
    cx.drain_and_finalize();
    let original = fs::read(&capsule_path)?;
    let mut corrupt = original.clone();
    *corrupt.last_mut().ok_or("retained native capsule bytes")? ^= 1;
    fs::write(&capsule_path, corrupt)?;
    let canonical = canonical_inventory(&f)?;
    refusal(&poll(&f, &request, &session, "budget", 3, None)?);
    let failed = state(&f, "budget")?;
    assert_eq!(failed.attempts_reserved(), 3);
    assert!(failed.pending().is_none() && failed.reservation().is_some());
    let advanced = advance(&f, &request, &session, "budget", 3, "1", &receipt)?;
    success(&advanced);
    assert_eq!(field(&report(&advanced)?, "source_validation")?, &Value::Null);
    let progressed = state(&f, "budget")?;
    assert_eq!(progressed.active_window_count(), Some(2));
    assert_eq!(progressed.attempts_reserved(), failed.attempts_reserved());
    assert_eq!(progressed.reserved_bytes(), failed.reserved_bytes());
    assert_eq!(progressed.reserved_read_attempts(), failed.reserved_read_attempts());
    assert!(progressed.reservation().is_none());
    success(&poll(&f, &request, &session, "budget", 3, Some(("--inspect", "yes")))?);
    success(&poll(&f, &request, &session, "budget", 3, Some(("--schedule", "yes")))?);
    refusal(&poll(&f, &request, &session, "budget", 3, None)?);
    refusal(&poll(&f, &request, &session, "budget", 4, Some(("--schedule", "yes")))?);
    assert_eq!(state(&f, "budget")?.digest(), progressed.digest());
    assert_eq!(canonical_inventory(&f)?, canonical);
    fs::write(capsule_path, original)?;
    Ok(())
}
