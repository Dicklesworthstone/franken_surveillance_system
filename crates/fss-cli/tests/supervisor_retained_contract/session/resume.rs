#![forbid(unsafe_code)]
//! Cold native supervision recovers its exact durable configuration after the loose file is lost.

use super::*;

fn resume_at(
    f: &Fixture,
    session: &str,
    subscription: &str,
    authority: ContentDigest,
    flags: &[(&str, &str)],
) -> TestResult<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
    command.args(["supervise", "--resume", "yes", "--root"]).arg(&f.root)
        .args([
            "--site", SITE, "--session", session, "--subscription", subscription,
            "--authority-root", &authority.to_text(),
        ]);
    for &(flag, value) in flags { command.args([flag, value]); }
    // No discovery file or lifetime limit is supplied or recreated by this cold process.
    Ok(command.output()?)
}

fn resume(
    f: &Fixture,
    session: &str,
    subscription: &str,
    flags: &[(&str, &str)],
) -> TestResult<Output> {
    resume_at(f, session, subscription, f.authority, flags)
}

fn remove_configuration(f: &Fixture) -> TestResult {
    let path = f.directory.0.join("session-discovery.json");
    fs::remove_file(&path)?;
    assert!(!path.exists());
    Ok(())
}

#[test]
fn cold_resume_recovers_exact_schedule_after_configuration_loss_without_refilling_quota()
-> TestResult {
    let mut f = Fixture::new("resume-schedule", 1)?;
    let request = f.discovery(&[0])?;
    let session = open_session(&f)?;
    success(&poll(&f, &request, &session, "recoverable", 4, Some(("--schedule", "yes")))?);
    let first = poll(&f, &request, &session, "recoverable", 4, None)?;
    success(&first);
    let first_json = report(&first)?;
    let receipt = text(&first_json, "delivery_receipt")?.to_owned();
    let original_payload = raw_report(&first)?.to_vec();
    let original = state(&f, "recoverable")?;
    let registration = original.registration().clone();
    let original_authority = f.authority;
    remove_configuration(&f)?;

    // Losing stdout and the loose input must not lose the pending receipt or its frozen caps.
    let inspected = resume(&f, &session, "recoverable", &[("--inspect", "yes")])?;
    success(&inspected);
    let inspected = report(&inspected)?;
    assert_eq!(text(&inspected, "state")?, "inspected");
    assert_eq!(text(&inspected, "pending_receipt")?, receipt);
    assert_eq!(field(&inspected, "report")?, &Value::Null);
    assert_eq!(field(&inspected, "source_validation")?, &Value::Null);
    assert_eq!(state(&f, "recoverable")?, original);

    // Recovery still validates the original source inventory against the current head.
    append_unrelated_authority(&mut f)?;
    let canonical = canonical_inventory(&f)?;
    assert_ne!(f.authority, original_authority);
    let replay = resume(&f, &session, "recoverable", &[])?;
    success(&replay);
    let replay_json = report(&replay)?;
    assert_eq!(raw_report(&replay)?, original_payload);
    assert_eq!(text(&replay_json, "delivery_receipt")?, receipt);
    assert_eq!(text(&replay_json, "configuration_digest")?, registration.configuration_digest.to_text());
    assert_eq!(text(&replay_json, "report_authority_root")?, original_authority.to_text());
    assert_eq!(text(&replay_json, "current_authority_root")?, f.authority.to_text());
    assert_eq!(
        text(field(&replay_json, "source_validation")?, "current_authority_root")?,
        f.authority.to_text(),
    );
    assert_eq!(field(&replay_json, "attempts_reserved")?.integer(), Some(2));
    assert_eq!(field(&replay_json, "active_window_count")?.integer(), Some(1));

    success(&resume(&f, &session, "recoverable", &[("--acknowledge", &receipt)])?);
    success(&resume(&f, &session, "recoverable", &[("--acknowledge", &receipt)])?);
    assert_eq!(state(&f, "recoverable")?.attempts_reserved(), 3);
    let advanced = resume(&f, &session, "recoverable", &[
        ("--advance-window", "1"), ("--after-receipt", &receipt),
    ])?;
    success(&advanced);
    let advanced = report(&advanced)?;
    assert_eq!(text(&advanced, "state")?, "advanced");
    assert_eq!(field(&advanced, "active_window_count")?.integer(), Some(2));
    assert_eq!(field(&advanced, "report")?, &Value::Null);
    assert_eq!(field(&advanced, "source_validation")?, &Value::Null);
    assert_eq!(state(&f, "recoverable")?.attempts_reserved(), 3);

    let next = resume(&f, &session, "recoverable", &[])?;
    success(&next);
    let next_json = report(&next)?;
    let next_receipt = text(&next_json, "delivery_receipt")?.to_owned();
    assert_ne!(next_receipt, receipt);
    assert_eq!(text(&next_json, "configuration_digest")?, registration.configuration_digest.to_text());
    assert_eq!(field(&next_json, "maximum_attempts")?.integer(), Some(4));
    assert_eq!(field(&next_json, "active_window_count")?.integer(), Some(2));
    let native = field(field(&next_json, "report")?, "supervision")?;
    let windows = field(native, "windows")?.array().ok_or("resumed native windows")?;
    assert_eq!(windows.len(), 2);
    assert_eq!(field(native, "observations")?.array().ok_or("resumed observations")?.len(), 1);
    for (index, window) in windows.iter().enumerate() {
        assert_eq!(field(window, "unique_observations")?.integer(), Some(1));
        assert_eq!(field(window, "new_observations")?.integer(), Some(if index == 0 { 1 } else { 0 }));
    }
    let pending = state(&f, "recoverable")?;
    assert_eq!(pending.attempts_reserved(), 4);
    assert_eq!(pending.registration(), &registration);
    // Historical retries cannot consume the newer delivery, even after the work quota ends.
    success(&resume(&f, &session, "recoverable", &[("--acknowledge", &receipt)])?);
    success(&resume(&f, &session, "recoverable", &[
        ("--advance-window", "1"), ("--after-receipt", &receipt),
    ])?);
    refusal(&resume(&f, &session, "recoverable", &[])?);
    refusal(&resume(&f, &session, "recoverable", &[("--acknowledge", &next_receipt)])?);
    let exhausted_inspection = resume(&f, &session, "recoverable", &[("--inspect", "yes")])?;
    success(&exhausted_inspection);
    let exhausted_inspection = report(&exhausted_inspection)?;
    assert_eq!(text(&exhausted_inspection, "pending_receipt")?, next_receipt);
    assert_eq!(field(&exhausted_inspection, "report")?, &Value::Null);
    assert_eq!(field(&exhausted_inspection, "source_validation")?, &Value::Null);
    assert_eq!(state(&f, "recoverable")?, pending);

    success(&resume(&f, &session, "recoverable", &[("--discard", &next_receipt)])?);
    success(&resume(&f, &session, "recoverable", &[
        ("--advance-window", "2"), ("--after-receipt", &next_receipt),
    ])?);
    refusal(&resume(&f, &session, "recoverable", &[])?);
    refusal(&resume(&f, &session, "recoverable", &[("--max-poll-attempts", "64")])?);
    let final_state = state(&f, "recoverable")?;
    assert_eq!(final_state.registration(), &registration);
    assert_eq!(final_state.active_window_count(), Some(3));
    assert_eq!(final_state.attempts_reserved(), 4);
    assert_eq!(final_state.reserved_bytes(), 4 * registration.max_read_bytes);
    assert_eq!(final_state.reserved_read_attempts(), 4 * registration.max_read_attempts);
    assert_eq!(final_state.last_acknowledged(), Some(ContentDigest::parse(&receipt)?));
    assert_eq!(final_state.last_discarded(), Some(ContentDigest::parse(&next_receipt)?));
    assert!(final_state.pending().is_none());
    assert!(!f.directory.0.join("session-discovery.json").exists());
    assert_eq!(canonical_inventory(&f)?, canonical);
    Ok(())
}

#[test]
fn resume_refuses_unknown_foreign_stale_and_override_inputs_without_creating_work() -> TestResult {
    let mut f = Fixture::new("resume-refusals", 1)?;
    let request = f.discovery(&[0])?;
    let session = open_session(&f)?;
    let first = poll(&f, &request, &session, "owned", 8, None)?;
    success(&first);
    let original_payload = raw_report(&first)?.to_vec();
    let original = state(&f, "owned")?;
    let previous_root = f.authority;
    remove_configuration(&f)?;
    append_unrelated_authority(&mut f)?;
    let canonical = canonical_inventory(&f)?;

    refusal(&resume(&f, &session, "unknown", &[("--inspect", "yes")])?);
    assert!(state(&f, "unknown").is_err());
    refusal(&resume(&f, "session:missing-resume-owner", "owned", &[("--inspect", "yes")])?);
    refusal(&resume(&f, &session, "owned", &[("--principal", "principal:foreign-operator")])?);
    refusal(&resume_at(&f, &session, "owned", previous_root, &[])?);
    for (flag, value) in [
        ("--discover-plan", "lost-discovery.json"),
        ("--discover-digest", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        ("--retained-plan", "different-retained.json"),
        ("--retained-digest", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        ("--plan", "different-legacy.json"),
        ("--max-poll-attempts", "9"),
        ("--schedule", "yes"),
    ] {
        let output = resume(&f, &session, "owned", &[(flag, value)])?;
        refusal(&output);
        assert_eq!(output.status.code(), Some(i32::from(fss_cli::ExitIdentity::MALFORMED_VALUE.code)));
    }
    assert_eq!(state(&f, "owned")?, original);

    let absent_root = f.directory.0.join("resume-must-not-initialize");
    let absent = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["supervise", "--resume", "yes", "--root"]).arg(&absent_root)
        .args([
            "--site", SITE, "--session", &session, "--subscription", "owned",
            "--authority-root", &f.authority.to_text(), "--inspect", "yes",
        ])
        .output()?;
    refusal(&absent);
    assert!(!absent_root.exists(), "resuming an absent deployment created its root");
    let resumed = resume(&f, &session, "owned", &[])?;
    success(&resumed);
    assert_eq!(raw_report(&resumed)?, original_payload);
    assert_eq!(state(&f, "owned")?.attempts_reserved(), 2);
    assert!(!f.directory.0.join("session-discovery.json").exists());
    assert_eq!(canonical_inventory(&f)?, canonical);
    Ok(())
}

#[test]
fn resumed_pending_native_delivery_still_obeys_deleted_generation_excluded_source() -> TestResult {
    let mut f = Fixture::new("resume-deletion", 2)?;
    let mut request = f.discovery(&[0, 1])?;
    let camera = &mut rows(
        fields(discovery_plan(&mut request)).get_mut("cameras").ok_or("cameras")?,
    )[0];
    fields(camera).insert(
        "package_digest".into(),
        Value::Text(ContentDigest::sha256(b"explicit other package for resume fixture").to_text()),
    );
    let session = open_session(&f)?;
    let first = poll(&f, &request, &session, "withdrawn", 8, None)?;
    success(&first);
    let receipt = text(&report(&first)?, "delivery_receipt")?.to_owned();
    let original = state(&f, "withdrawn")?;
    assert!(original.pending().ok_or("original pending inventory")?.source_inventory()
        .iter().any(|source| source.event_id == f.cameras[0].event && source.source_verified));
    remove_configuration(&f)?;

    let deletion = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "plan", "--root"]).arg(&f.root)
        .args(["--site", SITE, "--import-id", &f.cameras[0].import.to_text()])
        .output()?;
    success(&deletion);
    let deletion = report(&deletion)?;
    let committed = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "commit", "--root"]).arg(&f.root)
        .args([
            "--site", SITE, "--plan", text(&deletion, "plan_digest")?,
            "--approve", text(&deletion, "approval_digest")?,
        ])
        .output()?;
    success(&committed);
    f.refresh_authority()?;
    let canonical = canonical_inventory(&f)?;

    refusal(&resume(&f, &session, "withdrawn", &[])?);
    refusal(&resume(&f, &session, "withdrawn", &[("--acknowledge", &receipt)])?);
    let blocked = state(&f, "withdrawn")?;
    assert_eq!(blocked.attempts_reserved(), 3);
    assert_eq!(blocked.registration(), original.registration());
    assert_eq!(blocked.pending().ok_or("withdrawn report descriptor")?.receipt().to_text(), receipt);
    assert_eq!(blocked.last_acknowledged(), None);
    let inspected = resume(&f, &session, "withdrawn", &[("--inspect", "yes")])?;
    success(&inspected);
    let inspected = report(&inspected)?;
    assert_eq!(text(&inspected, "pending_receipt")?, receipt);
    assert_eq!(field(&inspected, "report")?, &Value::Null);
    assert_eq!(field(&inspected, "source_validation")?, &Value::Null);
    assert_eq!(state(&f, "withdrawn")?, blocked);
    success(&resume(&f, &session, "withdrawn", &[("--discard", &receipt)])?);
    let discarded = state(&f, "withdrawn")?;
    assert!(discarded.pending().is_none());
    assert_eq!(discarded.attempts_reserved(), 3);
    assert_eq!(discarded.last_acknowledged(), None);
    assert_eq!(discarded.last_discarded(), Some(ContentDigest::parse(&receipt)?));
    assert!(!f.directory.0.join("session-discovery.json").exists());
    assert_eq!(canonical_inventory(&f)?, canonical);
    Ok(())
}

#[test]
fn new_source_health_blocks_cold_event_report_replay_and_ack_but_preserves_inspect_and_discard()
-> TestResult {
    let mut fixture = Fixture::with_source_frames("event-session-health", 1, 12, false)?;
    let session = open_session(&fixture)?;
    let first = poll(
        &fixture,
        &fixture.discovery(&[0])?,
        &session,
        "health",
        3,
        None,
    )?;
    success(&first);
    let receipt = text(&report(&first)?, "delivery_receipt")?.to_owned();
    let original = state(&fixture, "health")?;
    let pending = original.pending().ok_or("original event report")?;
    assert_eq!(pending.source_inventory().len(), 1);
    assert!(pending.source_inventory()[0].health_digest.is_some());
    assert!(pending.detection_source_inventory().is_empty());
    remove_configuration(&fixture)?;

    super::super::health::retain_health(&mut fixture, 0, 12, false)?;
    let canonical = canonical_inventory(&fixture)?;
    for flags in [Vec::new(), vec![("--acknowledge", receipt.as_str())]] {
        let output = resume(&fixture, &session, "health", &flags)?;
        refusal(&output);
        assert!(String::from_utf8_lossy(&output.stderr).contains("health context changed"));
    }
    let blocked = state(&fixture, "health")?;
    assert_eq!(blocked.attempts_reserved(), 3);
    assert_eq!(blocked.registration(), original.registration());
    assert_eq!(blocked.last_acknowledged(), None);
    let blocked_pending = blocked.pending().ok_or("blocked event report")?;
    assert_eq!(blocked_pending.receipt().to_text(), receipt);
    assert_eq!(blocked_pending.payload_digest(), pending.payload_digest());
    assert_eq!(
        blocked_pending.source_inventory(),
        pending.source_inventory()
    );

    let inspected = resume(&fixture, &session, "health", &[("--inspect", "yes")])?;
    success(&inspected);
    let inspected = report(&inspected)?;
    assert_eq!(text(&inspected, "pending_receipt")?, receipt);
    assert_eq!(field(&inspected, "report")?, &Value::Null);
    assert_eq!(field(&inspected, "source_validation")?, &Value::Null);
    assert_eq!(state(&fixture, "health")?, blocked);
    success(&resume(
        &fixture,
        &session,
        "health",
        &[("--discard", &receipt)],
    )?);
    let discarded = state(&fixture, "health")?;
    assert!(discarded.pending().is_none());
    assert_eq!(discarded.attempts_reserved(), 3);
    assert_eq!(discarded.last_acknowledged(), None);
    assert_eq!(
        discarded.last_discarded(),
        Some(ContentDigest::parse(&receipt)?)
    );
    refusal(&resume(&fixture, &session, "health", &[])?);
    assert!(!fixture.directory.0.join("session-discovery.json").exists());
    assert_eq!(canonical_inventory(&fixture)?, canonical);
    Ok(())
}
