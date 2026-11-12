#![forbid(unsafe_code)]
//! Canonical source-verified recorder queries over retained custody, through real processes.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::process::{Command, Output, Stdio};

use fss_cli::json_input::{Value, parse};
use fss_cli::json_output::string;
use fss_core::ContentDigest;
use fss_reference::ingest::rtsp_import::RtspImportCodec;

use super::footage::snapshot;
use super::retained_time::{import, query_args};
use super::support::{Fixture, SITE, Test, field, good, serial, set};

fn args(fixture: &Fixture, identity: &str) -> Vec<OsString> {
    let native = query_args(fixture, Some(identity));
    let mut result = vec![
        "query".into(),
        "--json".into(),
        "--target".into(),
        "recordings".into(),
        "--retained-import".into(),
        identity.into(),
        "--verify-replay-source".into(),
        "yes".into(),
    ];
    for pair in native[1..].chunks_exact(2) {
        let key = pair[0].to_str().expect("fixture option");
        let key = match key {
            "--site" | "--import-id" | "--max-segment-bytes" | "--timeout-ms" => continue,
            "--anchor" => "--source-anchor",
            "--expected-replay-root" => "--replay-root",
            "--expected-replay-request" => "--replay-request",
            other => other,
        };
        result.extend([key.into(), pair[1].clone()]);
    }
    result
}

fn cli(args: &[OsString]) -> Test<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(args)
        .output()?)
}

fn item<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|object| object.get(key))
        .ok_or_else(|| format!("missing {key}").into())
}

fn mcp(fixture: &Fixture, args: &[OsString], granted: bool) -> Test<Value> {
    let mut fields = Vec::new();
    // query and --json have no value. All remaining canonical fixture options are pairs.
    for pair in args[2..].chunks_exact(2) {
        let option = pair[0].to_str().ok_or("fixture option")?;
        if matches!(option, "--root" | "--verify-replay-source") {
            continue;
        }
        let key = option
            .strip_prefix("--")
            .ok_or("canonical option")?
            .replace('-', "_");
        let value = pair[1].to_str().ok_or("fixture value")?;
        let rendered = if matches!(
            key.as_str(),
            "time_scale"
                | "ntp_era"
                | "max_query_windows"
                | "max_query_samples"
                | "max_query_packets"
                | "max_query_results"
        ) {
            value.parse::<u64>()?.to_string()
        } else {
            string(value)
        };
        fields.push(format!("{}:{rendered}", string(&key)));
    }
    let requests = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"retained-recorder-contract\",\"version\":\"1\"}}}}}}\n\
         {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"query\",\"arguments\":{{{}}}}}}}\n",
        fields.join(",")
    );
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-mcp"));
    command.arg("--root").arg(fixture.target());
    if granted {
        command.arg("--allow-replay-source-verification");
    }
    // Deliberately no --archive-root: all original custody is in the destination.
    let mut process = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut input = process.stdin.take().ok_or("MCP input")?;
    input.write_all(requests.as_bytes())?;
    drop(input);
    let output = process.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let output = String::from_utf8(output.stdout)?;
    let lines: Vec<_> = output.lines().collect();
    assert_eq!(lines.len(), 2);
    Ok(parse(lines[1])?)
}

fn mcp_text(response: &Value) -> Test<&str> {
    let result = item(response, "result")?;
    assert_eq!(item(result, "isError")?.boolean(), Some(false));
    let content = item(result, "content")?.array().ok_or("MCP content")?;
    assert_eq!(content.len(), 1);
    field(&content[0], "text")
}

fn refused(output: Output) -> Test {
    let exit_code = output.status.code();
    assert!(
        matches!(exit_code, Some(2 | 5)),
        "expected a parser or agent refusal, received {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    // Argument diagnostics contain human text followed by structured JSON on stderr.
    // Once parsing succeeds, --json execution refusals are emitted on stdout.
    let (diagnostic, phase) = if stdout.is_empty() {
        (
            parse(stderr.lines().last().ok_or("missing parser diagnostic")?)?,
            "argument_parsing",
        )
    } else {
        assert!(stderr.is_empty(), "execution refusal mixed output channels");
        (parse(&stdout)?, "execution")
    };
    assert_eq!(field(&diagnostic, "schema")?, "fss.cli_diagnostic.v1");
    assert_eq!(field(&diagnostic, "phase")?, phase);
    assert_eq!(
        item(&diagnostic, "exit_code")?.integer(),
        exit_code.map(i128::from)
    );
    assert_eq!(item(&diagnostic, "effect_started")?.boolean(), Some(false));
    assert!(field(&diagnostic, "error_id")?.starts_with("ERR-"));
    assert!(
        !stdout.contains("native_report="),
        "refusal exposed a partial native report"
    );
    for prefix in [
        "claim:recordings-replay:match:",
        "claim:recordings-replay:unknown:",
        "claim:recordings-replay:source-only:",
    ] {
        assert!(!stdout.contains(prefix), "refusal exposed native rows");
    }
    assert!(!stdout.contains("\"status\":\"success\""));
    Ok(())
}

#[test]
fn retained_cli_and_mcp_preserve_native_report_after_archive_removal_for_both_codecs() -> Test {
    let _serial = serial();
    for codec in [RtspImportCodec::Avc, RtspImportCodec::Hevc] {
        let fixture = Fixture::new(codec, 2, 0)?;
        let identity = import(&fixture)?;
        let native = parse(&good(
            Command::new(env!("CARGO_BIN_EXE_fss-file"))
                .args(query_args(&fixture, Some(&identity)))
                .output()?,
        )?)?;
        let native_report = item(&native, "report")?;
        assert_eq!(
            item(native_report, "unknown_samples")?.integer(),
            Some(fixture.frames as i128)
        );
        assert_eq!(item(native_report, "matched_samples")?.integer(), Some(0));

        fs::rename(
            fixture.archive(),
            fixture.directory.0.join("archive offline"),
        )?;
        let before = snapshot(&fixture.target())?;
        let args = args(&fixture, &identity);
        let output = good(cli(&args)?)?;
        parse(&output)?;
        for expected in [
            format!("native_report={}", field(native_report, "report_digest")?),
            format!("native_index={}", field(native_report, "index_digest")?),
            format!("destination import={identity}"),
            format!("unknown_samples={}", fixture.frames),
            "matches=0".to_owned(),
            "retained_replay_receipt_exhausted".to_owned(),
            "retained-original-custody-metadata".to_owned(),
        ] {
            assert!(output.contains(&expected), "missing {expected}: {output}");
        }
        assert_eq!(
            mcp_text(&mcp(&fixture, &args, true)?)?,
            output.trim_end_matches('\n')
        );
        assert_eq!(
            snapshot(&fixture.target())?,
            before,
            "query wrote into retained custody"
        );
        assert!(!fixture.archive().exists());
    }
    Ok(())
}

#[test]
fn missing_grants_wrong_native_pins_and_exhausted_read_balances_refuse_without_writes() -> Test {
    let _serial = serial();
    let fixture = Fixture::new(RtspImportCodec::Hevc, 2, 0)?;
    let identity = import(&fixture)?;
    fs::rename(
        fixture.archive(),
        fixture.directory.0.join("archive offline"),
    )?;
    let args = args(&fixture, &identity);
    let before = snapshot(&fixture.target())?;
    let foreign = ContentDigest::sha256(b"foreign exact retained recorder pin").to_text();
    for (key, value) in [
        ("--retained-import", foreign.as_str()),
        ("--replay-root", foreign.as_str()),
        ("--replay-request", foreign.as_str()),
        ("--receive-clock", foreign.as_str()),
        ("--decode-clock", foreign.as_str()),
        ("--codec", "avc"),
        ("--max-query-read-bytes", "1"),
        ("--max-query-read-objects", "1"),
        ("--max-query-source-bytes", "1"),
        ("--max-query-results", "1"),
        ("--verify-replay-source", "no"),
        ("--archive-root", "/PRIVATE_MIXED_ARCHIVE"),
        ("--max-query-io-calls", "100"),
    ] {
        let mut wrong = args.clone();
        set(&mut wrong, key, value);
        refused(cli(&wrong)?)?;
        assert_eq!(
            snapshot(&fixture.target())?,
            before,
            "refusal for {key} wrote custody"
        );
    }
    let denied = mcp(&fixture, &args, false)?;
    assert!(
        denied.object().is_some_and(|v| v.contains_key("error")),
        "MCP client obtained source authority without launcher grant"
    );
    assert_eq!(snapshot(&fixture.target())?, before);
    assert!(!fixture.archive().exists());
    Ok(())
}

#[test]
fn committed_deletion_removes_canonical_retained_query_availability() -> Test {
    let _serial = serial();
    let fixture = Fixture::new(RtspImportCodec::Avc, 2, 0)?;
    let identity = import(&fixture)?;
    fs::rename(
        fixture.archive(),
        fixture.directory.0.join("archive offline"),
    )?;
    let args = args(&fixture, &identity);
    good(cli(&args)?)?;
    let plan = parse(&good(
        Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .args(["delete", "plan", "--root"])
            .arg(fixture.target())
            .args(["--site", SITE, "--import-id", &identity])
            .output()?,
    )?)?;
    good(
        Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .args(["delete", "commit", "--root"])
            .arg(fixture.target())
            .args([
                "--site",
                SITE,
                "--plan",
                field(&plan, "plan_digest")?,
                "--approve",
                field(&plan, "approval_digest")?,
            ])
            .output()?,
    )?;
    let before = snapshot(&fixture.target())?;
    refused(cli(&args)?)?;
    assert_eq!(snapshot(&fixture.target())?, before);
    assert!(!fixture.archive().exists());
    Ok(())
}
