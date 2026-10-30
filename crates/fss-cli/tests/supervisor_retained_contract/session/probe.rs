#![forbid(unsafe_code)]
//! AOP-006 and MCP use the same retained-source owner after a complete process restart.

use super::*;
use std::io::Write;
use std::process::Stdio;

#[path = "../../mcp_investigation_contract/wire.rs"]
mod wire;

fn cli(f: &Fixture, session: &str, transition: &str, flags: &[(&str, &str)]) -> TestResult<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss"));
    command
        .args(["investigate", "--json", "--root"])
        .arg(&f.root)
        .args([
            "--principal",
            PRINCIPAL,
            "--session",
            session,
            "--transition",
            transition,
            "--subscription",
            "agent-probe",
            "--authority-root",
            &f.authority.to_text(),
        ]);
    for (flag, value) in flags {
        command.args([flag, value]);
    }
    Ok(command.output()?)
}

fn tool(
    f: &Fixture,
    session: &str,
    transition: &str,
    extra: &[(&str, String)],
    notification: bool,
) -> TestResult<Value> {
    let mut args = vec![
        ("session", string(session)),
        ("transition", string(transition)),
        ("subscription", string("agent-probe")),
        ("authority_root", string(&f.authority.to_text())),
        ("view", string("forensic")),
    ];
    args.extend(extra.iter().map(|(key, value)| (*key, value.clone())));
    let call = object(&[
        ("name", string("investigate")),
        ("arguments", object(&args)),
    ]);
    let mut child = Command::new(env!("CARGO_BIN_EXE_fss-mcp"))
        .args(["--root"])
        .arg(&f.root)
        .args(["--principal", PRINCIPAL])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut input = child.stdin.take().ok_or("MCP stdin")?;
    writeln!(
        input,
        "{}",
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"retained-probe-contract","version":"1"}}}"#
    )?;
    writeln!(
        input,
        "{}",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
    )?;
    if notification {
        writeln!(
            input,
            "{}",
            object(&[
                ("jsonrpc", string("2.0")),
                ("method", string("tools/call")),
                ("params", call)
            ])
        )?;
        writeln!(input, "{}", r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#)?;
    } else {
        writeln!(
            input,
            "{}",
            object(&[
                ("jsonrpc", string("2.0")),
                ("id", "2".to_owned()),
                ("method", string("tools/call")),
                ("params", call)
            ])
        )?;
    }
    drop(input);
    let output = child.wait_with_output()?;
    success(&output);
    let output_text = std::str::from_utf8(&output.stdout)?;
    let lines: Vec<_> = output_text.lines().collect();
    assert_eq!(lines.len(), 2, "unexpected MCP responses: {output_text}");
    let response = wire::parse_response(lines[1])?;
    if notification {
        return Ok(response);
    }
    let result = field(&response, "result")?;
    assert_eq!(
        field(result, "isError")?.boolean(),
        Some(false),
        "{response:?}"
    );
    let content = field(result, "content")?.array().ok_or("MCP content")?;
    Ok(json_input::parse(text(&content[0], "text")?)?)
}

fn spent(f: &Fixture, session: &str) -> TestResult<u64> {
    Ok(inspect_session_bytes(
        &fs::read(f.root.join("agent/sessions/journal.fssj"))?,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?
    .sessions
    .iter()
    .find(|entry| entry.session.session_id.as_str() == session)
    .ok_or("session budget state")?
    .spent_tokens)
}

fn payload(value: &Value) -> TestResult<&Value> {
    field(value, "payload")
}

fn has_proposition(value: &Value, id: &str, needle: &str) -> TestResult<bool> {
    Ok(field(field(payload(value)?, "epistemic")?, "propositions")?
        .array()
        .ok_or("propositions")?
        .iter()
        .any(|p| {
            text(p, "id").is_ok_and(|value| value == id)
                && text(p, "statement").is_ok_and(|statement| statement.contains(needle))
        }))
}

fn packed_items(value: &Value) -> TestResult<&[Value]> {
    field(field(payload(value)?, "contextPack")?, "items")?
        .array()
        .ok_or_else(|| "required complete context pack missing".into())
}

fn has_packed_proposition(value: &Value, id: &str, needle: &str) -> TestResult<bool> {
    Ok(packed_items(value)?.iter().any(|item| {
        text(item, "itemId").is_ok_and(|value| value == id)
            && text(item, "content").is_ok_and(|statement| statement.contains(needle))
    }))
}

/// Compare the delivered typed inventory with the independently executed native owner, not a
/// shortened summary. Every native row class is retained, including empty/negative qualifications.
fn assert_complete_native_inventory(answer: &Value, native: &Value) -> TestResult {
    let body = field(native, "supervision")?;
    let array = |value: &Value, name| -> TestResult<usize> {
        Ok(field(value, name)?.array().ok_or("native row array")?.len())
    };
    let cameras = field(body, "cameras")?.array().ok_or("cameras")?;
    let observations = field(body, "observations")?.array().ok_or("observations")?;
    let windows = field(body, "windows")?.array().ok_or("windows")?;
    let mut expected = BTreeMap::from([
        ("scope", 1),
        ("health-catalog", 1),
        ("camera", cameras.len()),
        ("observation", observations.len()),
        ("window", windows.len()),
        ("policy", windows.len()),
        ("uncalibrated", windows.len()),
        ("source", array(native, "source_inventory")?),
        (
            "discovery-exclusion",
            array(field(native, "discovery")?, "exclusions")?,
        ),
        ("calibration", 0),
        ("calibration-bin", 0),
        ("health", 0),
        ("health-finding", 0),
        ("health-pin", 0),
        ("evidence", 0),
        ("cluster", 0),
        ("exclusion", 0),
        ("counterfactual", 0),
    ]);
    let mut calibrations = std::collections::BTreeSet::new();
    for camera in cameras {
        let calibration = field(camera, "calibration")?;
        if calibration != &Value::Null && calibrations.insert(text(calibration, "digest")?) {
            *expected
                .get_mut("calibration")
                .ok_or("calibration counter")? += 1;
            *expected.get_mut("calibration-bin").ok_or("bin counter")? +=
                array(calibration, "bins")?;
        }
    }
    for observation in observations {
        if let Some(health) = observation
            .object()
            .and_then(|fields| fields.get("historical_health"))
        {
            *expected.get_mut("health").ok_or("health counter")? += 1;
            *expected
                .get_mut("health-finding")
                .ok_or("finding counter")? += array(health, "findings")?;
            *expected.get_mut("health-pin").ok_or("pin counter")? += array(health, "diagnostics")?;
        }
    }
    for window in windows {
        let outcome = field(window, "outcome")?;
        *expected.get_mut("evidence").ok_or("evidence counter")? +=
            array(field(window, "query")?, "evidence")?;
        for (kind, field_name) in [
            ("cluster", "clusters"),
            ("exclusion", "excluded"),
            ("counterfactual", "counterfactuals"),
        ] {
            *expected.get_mut(kind).ok_or("outcome counter")? += array(outcome, field_name)?;
        }
        let index = encode(field(window, "window_index")?);
        let item = packed_items(answer)?
            .iter()
            .find(|item| {
                text(item, "itemId").is_ok_and(|id| id.starts_with("probe:window:"))
                    && text(item, "content")
                        .is_ok_and(|content| content.starts_with(&format!("Window {index};")))
            })
            .ok_or("complete typed native window")?;
        assert_eq!(
            text(item, "epistemicState")?,
            text(outcome, "knowledge_state")?
        );
        for interval in ["posterior_log_odds_millibans", "probability_ppm"] {
            let values = field(outcome, interval)?.array().ok_or("native interval")?;
            let exact = format!("[{}, {}]", encode(&values[0]), encode(&values[1]));
            assert!(
                text(item, "content")?.contains(&exact),
                "missing exact {interval}"
            );
        }
    }
    let items = packed_items(answer)?;
    for (label, count) in expected {
        let prefix = format!("probe:{label}:");
        assert_eq!(
            items
                .iter()
                .filter(|item| text(item, "itemId").is_ok_and(|id| id.starts_with(&prefix)))
                .count(),
            count,
            "native inventory {label}"
        );
    }
    assert!(items.iter().any(|item| {
        text(item, "content")
            .is_ok_and(|content| content.contains("wilson_z2_per_bin_not_simultaneous"))
    }));
    assert!(items.iter().any(|item| {
        text(item, "content").is_ok_and(|content| content.contains("native trace replayed=false"))
    }));
    // Details belong to the REQUIRED pack; a receiver that reads only the summary is incomplete.
    assert!(
        !field(field(payload(answer)?, "epistemic")?, "propositions")?
            .array()
            .ok_or("summary")?
            .iter()
            .any(|item| text(item, "id").is_ok_and(|id| id.starts_with("probe:cluster:")))
    );
    Ok(())
}

fn quote(value: &Value) -> TestResult<u64> {
    field(
        field(field(payload(value)?, "budget")?, "consumed")?,
        "context_token_quote",
    )?
    .integer()
    .and_then(|n| u64::try_from(n).ok())
    .ok_or_else(|| "charged quote missing".into())
}

fn has_receipt(value: &Value, receipt: ContentDigest) -> TestResult<bool> {
    Ok(field(payload(value)?, "evidenceHandles")?
        .array()
        .ok_or("evidence handles")?
        .iter()
        .any(|h| text(h, "objectDigest").is_ok_and(|v| v == receipt.to_text())))
}

fn assert_v2_contract(f: &Fixture, answer: &Value) -> TestResult {
    let payload = payload(answer)?;
    let pack = field(payload, "contextPack")?;
    let receipt = field(payload, "compressionReceipt")?;
    assert_eq!(
        text(answer, "compressionReceiptId")?,
        text(receipt, "receiptId")?
    );
    assert_eq!(
        text(pack, "compressionReceiptId")?,
        text(receipt, "receiptId")?
    );
    assert_eq!(text(pack, "packDigest")?, text(receipt, "outputDigest")?);
    assert_eq!(
        field(answer, "contractBasis")?,
        field(payload, "contractBasis")?
    );
    assert_eq!(
        field(payload, "contractBasis")?,
        field(pack, "contractBasis")?
    );
    let actual_wire_tokens = (encode(answer).len() as u64).div_ceil(4);
    assert!(
        actual_wire_tokens <= quote(answer)?,
        "complete actual wire exceeds committed quote"
    );
    let selected = fss_core::AgentView::from_id(text(payload, "viewId")?)?;
    assert!(
        quote(answer)? <= u64::from(selected.maximum_tokens()),
        "complete native probe exceeds explicitly selected view ceiling"
    );
    assert_eq!(text(pack, "viewId")?, selected.id());
    assert_eq!(text(receipt, "viewId")?, selected.id());
    assert_eq!(
        field(receipt, "targetTokens")?.integer(),
        Some(i128::from(selected.maximum_tokens()))
    );
    for summary in field(field(payload, "epistemic")?, "propositions")?
        .array()
        .ok_or("summary")?
    {
        let item = packed_items(answer)?
            .iter()
            .find(|item| text(item, "itemId").ok() == text(summary, "id").ok())
            .ok_or("summary item absent from required pack")?;
        assert_eq!(text(item, "content")?, text(summary, "statement")?);
        assert_eq!(text(item, "epistemicState")?, text(summary, "state")?);
        let basis = field(item, "basis")?.array().ok_or("basis")?;
        for evidence in field(summary, "evidence")?
            .array()
            .ok_or("summary evidence")?
        {
            assert!(basis.contains(evidence));
        }
    }
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("repository root")?;
    for (schema, instance) in [
        ("agent_response_envelope.v1.json", answer),
        ("agent_cognitive_envelope.v2.json", payload),
        ("semantic_context_pack.v1.json", pack),
        ("semantic_compression_receipt.v1.json", receipt),
    ] {
        let path = f.directory.0.join(format!("probe-validate-{schema}"));
        fs::write(&path, encode(instance))?;
        let result = Command::new("python3")
            .arg("-B")
            .arg(repository.join("scripts/json_instance_validate.py"))
            .arg(repository.join("schemas").join(schema))
            .arg(&path)
            .output()?;
        fs::remove_file(&path)?;
        assert!(
            result.status.success(),
            "{schema}: {}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
    Ok(())
}

#[test]
fn investigate_probe_cold_cli_mcp_replay_ack_and_adjacent_advance_preserve_native_custody()
-> TestResult {
    let f = Fixture::new("agent-probe-cold", 1)?;
    let request = f.discovery(&[0])?;
    let mut active_request = request.clone();
    rows(
        fields(discovery_plan(&mut active_request))
            .get_mut("windows")
            .ok_or("native windows")?,
    )
    .truncate(1);
    let native_output = f.run_discovered(&active_request)?;
    success(&native_output);
    let native = report(&native_output)?;
    let session = open_session(&f)?;
    success(&poll(
        &f,
        &request,
        &session,
        "agent-probe",
        8,
        Some(("--schedule", "yes")),
    )?);
    fs::remove_file(f.directory.0.join("session-discovery.json"))?;
    let canonical = canonical_inventory(&f)?;
    let before_tokens = spent(&f, &session)?;

    let first = cli(&f, &session, "probe", &[("--view", "forensic")])?;
    success(&first);
    let first = report(&first)?;
    assert_eq!(text(&first, "operationId")?, "AOP-006");
    assert_eq!(
        text(payload(&first)?, "schema")?,
        "fss.agent_cognitive_envelope.v2"
    );
    assert_eq!(text(payload(&first)?, "viewId")?, "AVIEW-004");
    assert!(text(&first, "compressionReceiptId")?.starts_with("compression:probe:"));
    assert!(has_proposition(
        &first,
        "probe:packaging-scope",
        "Upstream context compression and native/H0 source omissions remain separate"
    )?);
    assert!(has_packed_proposition(
        &first,
        "probe:upstream-context-compression",
        "These source-selection omissions remain in force"
    )?);
    assert_v2_contract(&f, &first)?;
    assert_complete_native_inventory(&first, &native)?;
    let first_state = state(&f, "agent-probe")?;
    let pending = first_state.pending().ok_or("pending native delivery")?;
    let receipt = pending.receipt();
    assert_eq!(first_state.attempts_reserved(), 1);
    assert!(has_receipt(&first, receipt)?);
    assert!(has_proposition(
        &first,
        "probe:pending",
        "explicitly acknowledged"
    )?);
    assert!(encode(&first).contains("common-cause cluster"));
    assert_eq!(spent(&f, &session)?, before_tokens + quote(&first)?);

    let replay = tool(&f, &session, "probe", &[], false)?;
    assert_v2_contract(&f, &replay)?;
    assert_complete_native_inventory(&replay, &native)?;
    let after_replay = state(&f, "agent-probe")?;
    assert_eq!(after_replay.pending(), first_state.pending());
    assert_eq!(after_replay.attempts_reserved(), 2);
    assert!(has_receipt(&replay, receipt)?);
    assert!(has_proposition(
        &replay,
        "probe:outcome",
        "replayed the exact historical"
    )?);
    assert!(has_packed_proposition(
        &replay,
        "probe:source-revalidation",
        "Current historical-source validation"
    )?);
    assert_eq!(
        spent(&f, &session)?,
        before_tokens + quote(&first)? + quote(&replay)?
    );

    let no_action = state(&f, "agent-probe")?;
    let no_tokens = spent(&f, &session)?;
    tool(
        &f,
        &session,
        "probe-ack",
        &[("receipt", string(&receipt.to_text()))],
        true,
    )?;
    assert_eq!(
        state(&f, "agent-probe")?,
        no_action,
        "notification acknowledged delivery"
    );
    assert_eq!(spent(&f, &session)?, no_tokens);

    let ack = cli(
        &f,
        &session,
        "probe-ack",
        &[("--receipt", &receipt.to_text()), ("--view", "forensic")],
    )?;
    success(&ack);
    let acknowledged = state(&f, "agent-probe")?;
    assert!(acknowledged.pending().is_none());
    assert_eq!(acknowledged.last_acknowledged(), Some(receipt));
    assert_eq!(acknowledged.attempts_reserved(), 3);
    let advanced = tool(
        &f,
        &session,
        "probe-advance",
        &[
            ("window_index", "1".to_owned()),
            ("after_receipt", string(&receipt.to_text())),
        ],
        false,
    )?;
    assert!(has_proposition(
        &advanced,
        "probe:outcome",
        "without evaluating a successor"
    )?);
    assert_eq!(state(&f, "agent-probe")?.attempts_reserved(), 3);
    assert_eq!(state(&f, "agent-probe")?.active_window_count(), Some(2));

    // Metadata inspection charges its disclosed context, but no new native source attempt.
    let inspected = tool(&f, &session, "probe-inspect", &[], false)?;
    assert!(has_proposition(
        &inspected,
        "probe:outcome",
        "inspected without source work"
    )?);
    assert_eq!(state(&f, "agent-probe")?.attempts_reserved(), 3);
    assert!(!f.directory.0.join("session-discovery.json").exists());
    assert_eq!(canonical_inventory(&f)?, canonical);
    Ok(())
}

#[test]
fn complete_probe_overflow_preserves_pending_receipt_and_explicit_discard_without_source_work()
-> TestResult {
    let f = Fixture::new("agent-probe-overflow", 1)?;
    let mut request = f.discovery(&[0])?;
    let windows = rows(
        fields(discovery_plan(&mut request))
            .get_mut("windows")
            .ok_or("windows")?,
    );
    let template = windows[0].clone();
    windows.clear();
    for index in 0..32_u64 {
        let mut window = template.clone();
        fields(&mut window).insert("window_index".to_owned(), numeric(index));
        fields(&mut window).insert(
            "end_ns".to_owned(),
            numeric(2_000_000_000 + index * 1_000_000_000),
        );
        windows.push(window);
    }
    let session = open_session(&f)?;
    // Existing unscheduled owner evaluates its full declared window set.
    success(&poll(&f, &request, &session, "agent-probe", 8, None)?);
    let pending = state(&f, "agent-probe")?;
    let receipt = pending.pending().ok_or("pending")?.receipt();
    let spent_before = spent(&f, &session)?;
    let response = cli(&f, &session, "probe", &[])?;
    assert_eq!(
        response.status.code(),
        Some(i32::from(fss_cli::ExitIdentity::AGENT_REFUSED.code))
    );
    let response = report(&response)?;
    assert_eq!(text(&response, "outcome")?, "partial");
    assert_eq!(
        text(payload(&response)?, "viewId")?,
        "AVIEW-003",
        "default Case was silently widened"
    );
    assert_eq!(
        text(&response, "errorId")?,
        "ERR-AGENT-CONTEXT-INCOMPLETE-001"
    );
    assert!(has_receipt(&response, receipt)?);
    let retained = state(&f, "agent-probe")?;
    assert_eq!(retained.pending(), pending.pending());
    assert_eq!(retained.last_acknowledged(), None);
    assert_eq!(
        retained.attempts_reserved(),
        pending.attempts_reserved() + 1
    );
    assert_eq!(
        spent(&f, &session)?,
        spent_before,
        "undelivered full projection charged tokens"
    );
    let discard = cli(
        &f,
        &session,
        "probe-discard",
        &[("--receipt", &receipt.to_text()), ("--view", "forensic")],
    )?;
    success(&discard);
    let discarded = state(&f, "agent-probe")?;
    assert_eq!(discarded.last_discarded(), Some(receipt));
    assert!(discarded.pending().is_none());
    assert_eq!(discarded.attempts_reserved(), retained.attempts_reserved());
    Ok(())
}

#[test]
fn probe_refuses_foreign_missing_and_stale_scope_before_native_work_and_preserves_orient_views()
-> TestResult {
    let f = Fixture::new("agent-probe-admission", 1)?;
    let request = f.discovery(&[0])?;
    let session = open_session(&f)?;
    success(&poll(
        &f,
        &request,
        &session,
        "agent-probe",
        8,
        Some(("--schedule", "yes")),
    )?);
    let initial = state(&f, "agent-probe")?;
    let initial_tokens = spent(&f, &session)?;
    let missing = cli(&f, "session:does-not-exist", "probe", &[])?;
    assert!(!missing.status.success());
    let mut wrong = fss_cli::probe_cmd::ProbeArgs {
        root: f.root.clone(),
        request: fss_reference::deployment_session::probe::ProbeRequest {
            session_id: fss_core::SessionId::parse(session.as_str())?,
            principal: fss_core::PrincipalId::parse("principal:another")?,
            subscription_id: "agent-probe".to_owned(),
            expected_authority_root: f.authority,
            view: fss_core::AgentView::Case,
            action: fss_reference::deployment_session::supervision::SupervisionAction::Poll,
        },
    };
    assert_ne!(
        fss_cli::probe_cmd::execute_probe(&wrong).1,
        fss_cli::ExitIdentity::SUCCESS
    );
    wrong.request.principal = fss_core::PrincipalId::parse(PRINCIPAL)?;
    wrong.request.expected_authority_root = ContentDigest::sha256(b"stale authority");
    assert_ne!(
        fss_cli::probe_cmd::execute_probe(&wrong).1,
        fss_cli::ExitIdentity::SUCCESS
    );
    let ordinary = fss_reference::deployment_session::orient::orient_session(
        &f.root,
        &fss_reference::deployment_session::orient::OrientSessionRequest {
            session_id: fss_core::SessionId::parse(session.as_str())?,
            principal: fss_core::PrincipalId::parse(PRINCIPAL)?,
            view: fss_core::AgentView::Case,
            budget_tokens: None,
        },
    );
    assert!(ordinary.is_err(), "AOP-003 silently widened to Case");
    assert_eq!(state(&f, "agent-probe")?, initial);
    assert_eq!(spent(&f, &session)?, initial_tokens);
    Ok(())
}

#[test]
fn deleted_source_cannot_escape_through_probe_projection_or_ack_and_work_remains_charged()
-> TestResult {
    let mut f = Fixture::new("agent-probe-custody", 1)?;
    let request = f.discovery(&[0])?;
    let session = open_session(&f)?;
    success(&poll(
        &f,
        &request,
        &session,
        "agent-probe",
        8,
        Some(("--schedule", "yes")),
    )?);
    success(&poll(&f, &request, &session, "agent-probe", 8, None)?);
    let original = state(&f, "agent-probe")?;
    let receipt = original.pending().ok_or("pending delivery")?.receipt();
    let planned = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "plan", "--root"])
        .arg(&f.root)
        .args([
            "--site",
            SITE,
            "--import-id",
            &f.cameras[0].import.to_text(),
        ])
        .output()?;
    success(&planned);
    let planned = report(&planned)?;
    let deleted = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["delete", "commit", "--root"])
        .arg(&f.root)
        .args([
            "--site",
            SITE,
            "--plan",
            text(&planned, "plan_digest")?,
            "--approve",
            text(&planned, "approval_digest")?,
        ])
        .output()?;
    success(&deleted);
    f.refresh_authority()?;
    let canonical = canonical_inventory(&f)?;
    let original_tokens = spent(&f, &session)?;
    for (transition, flags) in [
        ("probe", Vec::new()),
        ("probe-ack", vec![("--receipt", receipt.to_text())]),
    ] {
        let borrowed: Vec<_> = flags
            .iter()
            .map(|(key, value)| (*key, value.as_str()))
            .collect();
        let output = cli(&f, &session, transition, &borrowed)?;
        assert!(!output.status.success());
        let output = report(&output)?;
        assert_eq!(text(&output, "outcome")?, "partial");
        assert!(has_receipt(&output, receipt)?);
        assert!(
            !packed_items(&output)?
                .iter()
                .any(|item| text(item, "itemId").is_ok_and(|id| id.starts_with("probe:window:"))),
            "historical report escaped failed source custody"
        );
    }
    let blocked = state(&f, "agent-probe")?;
    assert_eq!(blocked.pending(), original.pending());
    assert_eq!(blocked.last_acknowledged(), None);
    assert_eq!(
        blocked.attempts_reserved(),
        original.attempts_reserved() + 2
    );
    assert_eq!(spent(&f, &session)?, original_tokens);
    success(&cli(
        &f,
        &session,
        "probe-discard",
        &[("--receipt", &receipt.to_text()), ("--view", "forensic")],
    )?);
    assert_eq!(state(&f, "agent-probe")?.last_discarded(), Some(receipt));
    assert_eq!(canonical_inventory(&f)?, canonical);
    Ok(())
}
