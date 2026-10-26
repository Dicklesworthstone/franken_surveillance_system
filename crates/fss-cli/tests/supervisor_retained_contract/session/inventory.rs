#![forbid(unsafe_code)]
//! A cold operator can discover durable work without a label, loose recipe, or native read.

use super::*;

fn open_inventory_session(f: &Fixture, mission: &str) -> TestResult<String> {
    let output = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(["session", "open", "--json", "--root"])
        .arg(&f.root)
        .args([
            "--principal",
            PRINCIPAL,
            "--mission",
            mission,
            "--objective",
            "Discover only this session's durable supervision metadata",
            "--view",
            "brief",
            "--budget-tokens",
            "100000",
        ])
        .output()?;
    success(&output);
    Ok(text(&report(&output)?, "sessionId")?.to_owned())
}

fn list_at(
    f: &Fixture,
    principal: &str,
    session: &str,
    authority: ContentDigest,
    flags: &[(&str, &str)],
) -> TestResult<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
    command
        .args(["supervise", "--list", "yes", "--root"])
        .arg(&f.root)
        .args([
            "--site",
            SITE,
            "--principal",
            principal,
            "--session",
            session,
            "--authority-root",
            &authority.to_text(),
        ]);
    for &(flag, value) in flags {
        command.args([flag, value]);
    }
    Ok(command.output()?)
}

fn list(f: &Fixture, session: &str, flags: &[(&str, &str)]) -> TestResult<Output> {
    list_at(f, PRINCIPAL, session, f.authority, flags)
}

fn subscriptions(document: &Value) -> TestResult<&[Value]> {
    field(document, "subscriptions")?
        .array()
        .ok_or_else(|| "subscription array".into())
}

fn subscription<'a>(document: &'a Value, id: &str) -> TestResult<&'a Value> {
    subscriptions(document)?
        .iter()
        .find(|entry| text(entry, "subscription_id").is_ok_and(|value| value == id))
        .ok_or_else(|| format!("missing discovered subscription {id}").into())
}

#[test]
fn cold_inventory_recovers_schedule_receipts_and_spent_quota_after_recipe_loss() -> TestResult {
    let f = Fixture::new("inventory-recovery", 1)?;
    let request = f.discovery(&[0])?;
    let session = open_session(&f)?;
    success(&poll(
        &f,
        &request,
        &session,
        "alpha-schedule",
        4,
        Some(("--schedule", "yes")),
    )?);
    let scheduled = poll(&f, &request, &session, "alpha-schedule", 4, None)?;
    success(&scheduled);
    let scheduled_receipt = text(&report(&scheduled)?, "delivery_receipt")?.to_owned();
    success(&poll(
        &f,
        &request,
        &session,
        "alpha-schedule",
        4,
        Some(("--discard", &scheduled_receipt)),
    )?);
    success(&poll_with_flags(
        &f,
        &request,
        &session,
        "alpha-schedule",
        4,
        &[
            ("--advance-window", "1"),
            ("--after-receipt", &scheduled_receipt),
        ],
    )?);
    let pending = poll(&f, &request, &session, "beta-pending", 1, None)?;
    success(&pending);
    let pending_report = report(&pending)?;
    let pending_receipt = text(&pending_report, "delivery_receipt")?.to_owned();
    let pending_payload_len = raw_report(&pending)?.len();
    let states = [state(&f, "alpha-schedule")?, state(&f, "beta-pending")?];
    fs::remove_file(f.directory.0.join("session-discovery.json"))?;
    let canonical = canonical_inventory(&f)?;
    let output_path = f.directory.0.join("inventory.json");
    let output_path_text = output_path.to_str().ok_or("inventory output path")?;

    // This process receives neither a recipe nor any remembered subscription identifier.
    let first = list(&f, &session, &[("--report-out", output_path_text)])?;
    success(&first);
    assert_eq!(fs::read(&output_path)?, first.stdout);
    let document = report(&first)?;
    assert_eq!(
        text(&document, "schema")?,
        "fss.retained_supervisor_inventory.v1"
    );
    assert_eq!(text(&document, "session_id")?, session);
    assert_eq!(
        text(&document, "current_authority_root")?,
        f.authority.to_text()
    );
    assert_eq!(field(&document, "complete")?.boolean(), Some(true));
    assert_eq!(
        field(&document, "native_attempts_reserved_by_listing")?.integer(),
        Some(0)
    );
    for flag in [
        "effects_authorized",
        "supports_absence_claim",
        "sources_revalidated",
    ] {
        assert_eq!(field(&document, flag)?.boolean(), Some(false));
    }
    let entries = subscriptions(&document)?;
    assert_eq!(entries.len(), 2);
    assert_eq!(text(&entries[0], "subscription_id")?, "alpha-schedule");
    assert_eq!(text(&entries[1], "subscription_id")?, "beta-pending");

    let scheduled = &entries[0];
    let schedule = field(scheduled, "schedule")?;
    assert_eq!(field(schedule, "total_windows")?.integer(), Some(3));
    assert_eq!(field(schedule, "active_window_count")?.integer(), Some(2));
    assert_eq!(field(schedule, "active_window_index")?.integer(), Some(1));
    assert_eq!(text(scheduled, "last_discarded")?, scheduled_receipt);
    assert_eq!(field(scheduled, "pending")?, &Value::Null);
    let advance = field(schedule, "last_advance")?;
    assert_eq!(field(advance, "target_window_count")?.integer(), Some(2));
    assert_eq!(text(advance, "after_receipt")?, scheduled_receipt);

    let pending = &entries[1];
    assert_eq!(field(pending, "attempts_reserved")?.integer(), Some(1));
    assert_eq!(field(pending, "attempts_remaining")?.integer(), Some(0));
    assert_eq!(field(pending, "schedule")?, &Value::Null);
    let delivery = field(pending, "pending")?;
    assert_eq!(text(delivery, "receipt")?, pending_receipt);
    assert_eq!(
        text(delivery, "payload_digest")?,
        text(&pending_report, "payload_digest")?
    );
    assert_eq!(
        field(delivery, "payload_len")?.integer(),
        Some(pending_payload_len as i128)
    );
    assert_eq!(
        field(delivery, "report_is_historical")?.boolean(),
        Some(true)
    );
    assert_eq!(
        field(delivery, "sources_revalidated")?.boolean(),
        Some(false)
    );
    for (entry, expected) in entries.iter().zip(&states) {
        assert_eq!(
            text(entry, "subscription_digest")?,
            expected.digest().to_text()
        );
        assert_eq!(
            text(entry, "configuration_digest")?,
            expected.registration().configuration_digest.to_text()
        );
        assert_eq!(
            field(entry, "attempts_reserved")?.integer(),
            Some(i128::from(expected.attempts_reserved()))
        );
        assert_eq!(
            field(entry, "reserved_bytes")?.integer(),
            Some(i128::from(expected.reserved_bytes()))
        );
        assert_eq!(
            field(entry, "reserved_read_attempts")?.integer(),
            Some(i128::from(expected.reserved_read_attempts()))
        );
        for private_field in ["report", "configuration", "source_inventory", "payload"] {
            assert!(
                !entry
                    .object()
                    .ok_or("inventory entry")?
                    .contains_key(private_field)
            );
        }
    }
    let emitted = std::str::from_utf8(&first.stdout)?;
    assert!(!emitted.contains(&f.cameras[0].sensor));
    assert!(!emitted.contains(&f.cameras[0].capsule.to_text()));
    let repeated = list(&f, &session, &[])?;
    success(&repeated);
    assert_eq!(
        field(&report(&repeated)?, "subscriptions")?,
        field(&document, "subscriptions")?
    );
    assert_eq!(
        [state(&f, "alpha-schedule")?, state(&f, "beta-pending")?],
        states
    );
    assert_eq!(canonical_inventory(&f)?, canonical);
    assert!(!f.directory.0.join("session-discovery.json").exists());
    Ok(())
}

#[test]
fn inventory_is_session_scoped_and_foreign_principals_receive_no_metadata() -> TestResult {
    let f = Fixture::new("inventory-isolation", 1)?;
    let request = f.discovery(&[0])?;
    let first_session = open_inventory_session(&f, "First inventory isolation mission")?;
    success(&poll(
        &f,
        &request,
        &first_session,
        "private-first-work",
        1,
        Some(("--schedule", "yes")),
    )?);
    let second_session = open_inventory_session(&f, "Second inventory isolation mission")?;
    assert_ne!(first_session, second_session);
    success(&poll(
        &f,
        &request,
        &second_session,
        "private-second-work",
        1,
        Some(("--schedule", "yes")),
    )?);
    let empty_session = open_inventory_session(&f, "Empty inventory isolation mission")?;
    let canonical = canonical_inventory(&f)?;
    let first_state = state(&f, "private-first-work")?;
    let second_state = state(&f, "private-second-work")?;
    for (session, own, foreign) in [
        (&first_session, "private-first-work", "private-second-work"),
        (&second_session, "private-second-work", "private-first-work"),
    ] {
        let output = list(&f, session, &[])?;
        success(&output);
        let document = report(&output)?;
        assert_eq!(subscriptions(&document)?.len(), 1);
        subscription(&document, own)?;
        assert!(!std::str::from_utf8(&output.stdout)?.contains(foreign));
    }
    let empty = list(&f, &empty_session, &[])?;
    success(&empty);
    assert!(subscriptions(&report(&empty)?)?.is_empty());
    for session in [&first_session, &second_session] {
        refusal(&list_at(
            &f,
            "principal:unrelated-operator",
            session,
            f.authority,
            &[],
        )?);
    }
    refusal(&list(&f, "session:missing-inventory-owner", &[])?);
    assert_eq!(state(&f, "private-first-work")?, first_state);
    assert_eq!(state(&f, "private-second-work")?, second_state);
    assert_eq!(canonical_inventory(&f)?, canonical);
    Ok(())
}

#[test]
fn inventory_requires_current_head_but_preserves_exhausted_pending_source_uncertainty() -> TestResult
{
    let mut f = Fixture::new("inventory-current-head", 1)?;
    let request = f.discovery(&[0])?;
    let session = open_session(&f)?;
    let pending = poll(&f, &request, &session, "exhausted", 1, None)?;
    success(&pending);
    let receipt = text(&report(&pending)?, "delivery_receipt")?.to_owned();
    let original_state = state(&f, "exhausted")?;
    let old_root = f.authority;
    append_unrelated_authority(&mut f)?;
    refusal(&list_at(&f, PRINCIPAL, &session, old_root, &[])?);

    // Discovery is metadata only: unavailable source bytes do not erase the obligation or
    // force an exhausted native attempt. The report explicitly declines custody revalidation.
    let cx = context(&f.root)?;
    let deployment = ReferenceDeployment::open(&f.root, SITE, &cx)?;
    let source_path = deployment
        .publisher()
        .spool()
        .object_path(f.cameras[0].capsule);
    drop(deployment);
    cx.drain_and_finalize();
    let original_source = fs::read(&source_path)?;
    let mut damaged = original_source.clone();
    *damaged.last_mut().ok_or("native source capsule")? ^= 1;
    fs::write(&source_path, damaged)?;
    let canonical = canonical_inventory(&f)?;
    let output = list(&f, &session, &[])?;
    success(&output);
    let document = report(&output)?;
    assert_eq!(
        text(&document, "current_authority_root")?,
        f.authority.to_text()
    );
    let entry = subscription(&document, "exhausted")?;
    assert_eq!(field(entry, "attempts_remaining")?.integer(), Some(0));
    assert_eq!(text(field(entry, "pending")?, "receipt")?, receipt);
    assert_eq!(
        field(&document, "sources_revalidated")?.boolean(),
        Some(false)
    );
    assert_eq!(state(&f, "exhausted")?, original_state);
    assert_eq!(canonical_inventory(&f)?, canonical);
    fs::write(source_path, original_source)?;
    Ok(())
}

#[test]
fn inventory_rejects_mixed_modes_and_missing_authority_before_creating_a_deployment() -> TestResult
{
    let directory = Directory::new("inventory-admission")?;
    let root = directory.0.join("must-not-exist");
    let authority = ContentDigest::sha256(b"inventory admission authority").to_text();
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
        command
            .args(["supervise", "--list", "yes", "--root"])
            .arg(&root)
            .args(["--site", SITE, "--session", "session:inventory-admission"]);
        command
    };
    let missing_root = command().output()?;
    refusal(&missing_root);
    assert_eq!(
        missing_root.status.code(),
        Some(i32::from(fss_cli::ExitIdentity::MALFORMED_VALUE.code))
    );
    for (flag, value) in [
        ("--subscription", "remembered-label"),
        ("--resume", "yes"),
        ("--inspect", "yes"),
        ("--schedule", "yes"),
        ("--acknowledge", authority.as_str()),
        ("--discard", authority.as_str()),
        ("--advance-window", "1"),
        ("--after-receipt", authority.as_str()),
        ("--max-poll-attempts", "1"),
        ("--plan", "missing.json"),
        ("--retained-plan", "missing.json"),
        ("--retained-digest", authority.as_str()),
        ("--discover-plan", "missing.json"),
        ("--discover-digest", authority.as_str()),
    ] {
        let mixed = command()
            .args(["--authority-root", &authority, flag, value])
            .output()?;
        refusal(&mixed);
        assert_eq!(
            mixed.status.code(),
            Some(i32::from(fss_cli::ExitIdentity::MALFORMED_VALUE.code))
        );
        assert!(!root.exists(), "invalid inventory mode initialized storage");
    }
    let absent = command().args(["--authority-root", &authority]).output()?;
    refusal(&absent);
    assert!(!root.exists());
    let help = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["supervise", "--help"])
        .output()?;
    success(&help);
    assert!(std::str::from_utf8(&help.stdout)?.contains("--list yes"));
    Ok(())
}
