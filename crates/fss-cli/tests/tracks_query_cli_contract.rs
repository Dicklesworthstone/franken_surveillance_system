#![forbid(unsafe_code)]
//! Actual retained matched detector observations across canonical Rust, CLI and MCP boundaries.

#[path = "../../fss-reference/tests/qsr_observations_support/mod.rs"]
mod support;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use fss_cli::{ExitIdentity, FssCommand, execute_fss_with_exit, parse_fss_args};
use fss_core::json_input::{Value, parse};
use support::{Fixture, PRINCIPAL, SITE, Test, context};

fn field<'a>(value: &'a Value, name: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|object| object.get(name))
        .ok_or_else(|| format!("missing {name}").into())
}

fn tree(root: &Path) -> Test<BTreeMap<PathBuf, (bool, Vec<u8>)>> {
    let mut pending = vec![root.to_owned()];
    let mut result = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let key = path.strip_prefix(root)?.to_owned();
        if metadata.is_dir() {
            result.insert(key, (true, Vec::new()));
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
        } else if metadata.is_file() {
            result.insert(key, (false, fs::read(path)?));
        } else {
            return Err("unexpected fixture file type".into());
        }
    }
    Ok(result)
}

fn args(fixture: &Fixture, extras: &[(&str, &str)]) -> Vec<OsString> {
    let mut values: Vec<OsString> = vec![
        "query".into(),
        "--json".into(),
        "--target=tracks".into(),
        "--root".into(),
        fixture.source.root.clone().into(),
        format!("--principal={PRINCIPAL}").into(),
        format!("--report-digest={}", fixture.source.report).into(),
        "--verify-tracks-source=yes".into(),
        "--label=numeric-a".into(),
        "--minimum-iou-ppm=0".into(),
    ];
    values.extend(
        extras
            .iter()
            .map(|(key, value)| format!("{key}={value}").into()),
    );
    values
}

fn cli(fixture: &Fixture, extras: &[(&str, &str)]) -> Test<(String, ExitIdentity)> {
    let args = args(fixture, extras);
    let expected = execute_fss_with_exit(parse_fss_args(args.clone())?);
    let process = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(args)
        .output()?;
    assert_eq!(
        process.status.code(),
        Some(i32::from(expected.1.code)),
        "{}",
        String::from_utf8_lossy(&process.stderr)
    );
    assert!(
        process.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&process.stderr)
    );
    assert_eq!(
        String::from_utf8(process.stdout)?,
        format!("{}\n", expected.0)
    );
    Ok(expected)
}

fn mcp(fixture: &Fixture, grant: bool, extra: &str) -> Test<Value> {
    let mut process = Command::new(env!("CARGO_BIN_EXE_fss-mcp"));
    process
        .arg("--root")
        .arg(&fixture.source.root)
        .args(["--principal", PRINCIPAL]);
    if grant {
        process.arg("--allow-tracks-source-verification");
    }
    let mut child = process
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let input = format!(
        concat!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"tracks-contract\",\"version\":\"1\"}}}}}}\n",
            "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}}\n",
            "{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"query\",\"arguments\":{{\"target\":\"tracks\",\"report_digest\":\"{}\",\"label\":\"numeric-a\",\"minimum_iou_ppm\":0{}}}}}}}\n"
        ),
        fixture.source.report, extra
    );
    child
        .stdin
        .take()
        .ok_or("stdin pipe")?
        .write_all(input.as_bytes())?;
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout)?;
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    Ok(parse(lines[1])?)
}

fn same_mcp(fixture: &Fixture, extra: &str, expected: &(String, ExitIdentity)) -> Test {
    let value = mcp(fixture, true, extra)?;
    let result = field(&value, "result")?;
    assert_eq!(
        field(result, "isError")?.boolean(),
        Some(expected.1.code != 0)
    );
    let content = field(result, "content")?
        .array()
        .and_then(|rows| rows.first())
        .ok_or("tool content")?;
    assert_eq!(field(content, "text")?.text(), Some(expected.0.as_str()));
    Ok(())
}

fn projected(output: &str) -> Test<BTreeMap<String, Value>> {
    let response = parse(output)?;
    let propositions = field(
        field(field(&response, "payload")?, "epistemic")?,
        "propositions",
    )?
    .array()
    .ok_or("propositions")?;
    let mut rows = BTreeMap::new();
    for proposition in propositions {
        let id = field(proposition, "id")?.text().ok_or("proposition ID")?;
        let Some(id) = id.strip_prefix("claim:tracks:") else {
            continue;
        };
        if matches!(id, "deployment-anchor" | "physical-absence") {
            continue;
        }
        let statement = field(proposition, "statement")?.text().ok_or("statement")?;
        let body = statement.split_once(": ").ok_or("complete native row")?.1;
        assert!(
            rows.insert(id.to_owned(), parse(body)?).is_none(),
            "duplicate projected row"
        );
    }
    Ok(rows)
}

#[test]
fn actual_matched_rows_and_protected_context_match_across_rust_cli_mcp_with_a_live_writer() -> Test
{
    let fixture = Fixture::new("canonical-tracks-parity")?;
    let cx = context(&fixture.source.root)?;
    let writer = fss_reference::ReferenceDeployment::open(&fixture.source.root, SITE, &cx)?;
    fs::write(
        fixture.source.root.join("LAYOUT.tmp"),
        b"unrelated pending layout bytes",
    )?;
    let before = tree(&fixture.source.root)?;
    let expected = cli(&fixture, &[])?;
    assert_eq!(expected.1, ExitIdentity::SUCCESS, "{}", expected.0);
    same_mcp(&fixture, "", &expected)?;
    assert!(expected.0.contains("AOP-005"));
    assert!(expected.0.contains("CAP-AGENT-QUERY-001"));
    assert!(expected.0.contains("CAP-READ-MEDIA-001"));
    assert!(
        !expected
            .0
            .contains(fixture.source.root.to_str().ok_or("root")?)
    );
    for state in ["prepared", "committed", "indeterminate"] {
        assert!(expected.0.contains(&format!("obligation:qsr-read:{state}")));
    }
    let value = parse(&expected.0)?;
    let cognitive = field(&value, "payload")?;
    assert_eq!(
        field(cognitive, "schema")?.text(),
        Some("fss.agent_cognitive_envelope.v1")
    );
    assert!(matches!(field(&value, "continuation")?, Value::Null));
    let rows = projected(&expected.0)?;
    assert_eq!(
        field(rows.get("model").ok_or("model")?, "selected_label")?.text(),
        Some("numeric-a")
    );
    assert_eq!(
        field(
            rows.get("source").ok_or("source")?,
            "detection_report_digest"
        )?
        .text(),
        Some(fixture.source.report.to_text().as_str())
    );
    for index in 0..3 {
        let row = rows
            .get(&format!("observation:{index}"))
            .ok_or("matched observation")?;
        assert_eq!(field(row, "sample_confirmed")?.boolean(), Some(index > 0));
        assert_eq!(field(row, "track_ever_confirmed")?.boolean(), Some(true));
        assert!(field(row, "assigned_detection")?.object().is_some());
        assert!(rows.contains_key(&format!("frame:{index}")));
    }
    assert_eq!(
        rows.keys()
            .filter(|key| key.starts_with("observation:"))
            .count(),
        3
    );
    for handle in field(cognitive, "evidenceHandles")?
        .array()
        .ok_or("handles")?
    {
        let text = format!("{handle:?}");
        assert!(!text.contains("H1") && !text.contains("H2") && !text.contains("H3"));
    }
    assert!(expected.0.contains("uncalibrated"));
    assert!(expected.0.contains("physical-absence"));
    assert_eq!(tree(&fixture.source.root)?, before);
    drop(writer);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn exact_page_continuations_match_across_transports_and_refuse_page_scope_changes() -> Test {
    let fixture = Fixture::new("canonical-tracks-pages")?;
    let before = tree(&fixture.source.root)?;
    let first = cli(&fixture, &[("--max-entries", "1")])?;
    assert_eq!(first.1, ExitIdentity::SUCCESS, "{}", first.0);
    same_mcp(&fixture, r#", "max_entries":1"#, &first)?;
    let value = parse(&first.0)?;
    let first_cursor = field(&value, "continuation")?
        .text()
        .ok_or("page continuation")?
        .to_owned();
    let first_rows = projected(&first.0)?;
    let mut observations = vec![
        field(
            first_rows.get("observation:0").ok_or("first observation")?,
            "row_digest",
        )?
        .text()
        .ok_or("row digest")?
        .to_owned(),
    ];
    let mut cursor = first_cursor.clone();
    for index in 1..3 {
        let page = cli(
            &fixture,
            &[("--max-entries", "1"), ("--continuation", &cursor)],
        )?;
        assert_eq!(page.1, ExitIdentity::SUCCESS, "{}", page.0);
        same_mcp(
            &fixture,
            &format!(
                r#", "max_entries":1,"continuation":{}"#,
                fss_cli::json_output::string(&cursor)
            ),
            &page,
        )?;
        let rows = projected(&page.0)?;
        assert_eq!(
            rows.keys()
                .filter(|key| key.starts_with("observation:"))
                .count(),
            1
        );
        observations.push(
            field(
                rows.get(&format!("observation:{index}"))
                    .ok_or("next observation")?,
                "row_digest",
            )?
            .text()
            .ok_or("row digest")?
            .to_owned(),
        );
        let value = parse(&page.0)?;
        if index == 2 {
            assert!(matches!(field(&value, "continuation")?, Value::Null));
        } else {
            cursor = field(&value, "continuation")?
                .text()
                .ok_or("next cursor")?
                .to_owned();
        }
    }
    assert_eq!(
        observations
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
    let refused = cli(
        &fixture,
        &[("--max-entries", "2"), ("--continuation", &first_cursor)],
    )?;
    assert_eq!(refused.1, ExitIdentity::AGENT_REFUSED);
    assert!(!refused.0.contains("claim:tracks:observation:"));
    same_mcp(
        &fixture,
        &format!(
            r#", "max_entries":2,"continuation":{}"#,
            fss_cli::json_output::string(&first_cursor)
        ),
        &refused,
    )?;
    assert_eq!(tree(&fixture.source.root)?, before);
    Ok(())
}

#[test]
fn missing_grant_scope_overrides_budget_and_corruption_never_deliver_partial_observations() -> Test
{
    let fixture = Fixture::new("canonical-tracks-refusals")?;
    let before = tree(&fixture.source.root)?;
    let FssCommand::TracksQuery(mut typed) = parse_fss_args(args(&fixture, &[]))? else {
        return Err("tracks command".into());
    };
    typed.verify_tracks_source = false;
    let denied = fss_cli::tracks_query_cmd::execute_tracks_query(&typed);
    assert_eq!(denied.1, ExitIdentity::AGENT_REFUSED);
    assert!(!denied.0.contains("claim:tracks:observation:"));
    assert!(field(&mcp(&fixture, false, "")?, "error").is_ok());
    for extra in [
        r#", "root":"/private-scope-canary""#,
        r#", "principal":"principal:private-scope-canary""#,
        r#", "allow_tracks_source_verification":true"#,
        r#", "zone_roles":[]"#,
        r#", "at":"private-scope-canary""#,
    ] {
        let refused = mcp(&fixture, true, extra)?;
        assert!(field(&refused, "error").is_ok());
        assert!(!format!("{refused:?}").contains("private-scope-canary"));
    }
    let limited = cli(&fixture, &[("--max-query-read-objects", "1")])?;
    assert_eq!(limited.1, ExitIdentity::AGENT_REFUSED);
    same_mcp(&fixture, r#", "max_query_read_objects":"1""#, &limited)?;
    assert!(!limited.0.contains("claim:tracks:observation:"));
    assert_eq!(tree(&fixture.source.root)?, before);
    let mut corrupt = fs::read(&fixture.source.chunk)?;
    *corrupt.last_mut().ok_or("source byte")? ^= 1;
    fs::write(&fixture.source.chunk, corrupt)?;
    let before = tree(&fixture.source.root)?;
    let refused = cli(&fixture, &[])?;
    assert_eq!(refused.1, ExitIdentity::AGENT_REFUSED);
    same_mcp(&fixture, "", &refused)?;
    assert!(!refused.0.contains("claim:tracks:observation:"));
    assert_eq!(tree(&fixture.source.root)?, before);
    Ok(())
}

#[test]
fn tracks_cli_has_closed_grammar_and_explicit_native_defaults_without_io() -> Test {
    let base: Vec<OsString> = [
        "query",
        "--json",
        "--target=tracks",
        "--root=/operator/absent-tracks-root",
        "--principal=principal:tracks-parser",
        "--report-digest=sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "--label=person",
        "--verify-tracks-source=yes",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let FssCommand::TracksQuery(parsed) = parse_fss_args(base.clone())? else {
        return Err("tracks command".into());
    };
    assert_eq!(parsed.request.config.confirmation_hits, 2);
    assert_eq!(parsed.request.config.maximum_missed_frames, 1);
    assert_eq!(parsed.request.config.minimum_iou_ppm, 100_000);
    assert_eq!(parsed.request.max_entries, 16);
    for invalid in [
        "--confirmation-hits=0",
        "--maximum-missed-frames=0",
        "--minimum-iou-ppm=1000001",
        "--max-entries=0",
        "--max-entries=33",
        "--max-entries=01",
        "--max-entries=1e0",
        "--zone-roles=[]",
        "--media=/private-scope-canary",
        "--execute=yes",
    ] {
        let mut args = base.clone();
        args.push(invalid.into());
        assert!(parse_fss_args(args).is_err(), "{invalid}");
    }
    for removed in ["--label=person", "--verify-tracks-source=yes"] {
        let args: Vec<_> = base
            .iter()
            .filter(|value| value.as_os_str() != std::ffi::OsStr::new(removed))
            .cloned()
            .collect();
        assert!(parse_fss_args(args).is_err());
    }
    Ok(())
}
