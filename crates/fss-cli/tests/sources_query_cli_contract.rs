#![forbid(unsafe_code)]
//! Real retained source metadata across native Rust, CLI and closed MCP transport boundaries.

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
use fss_object::SPOOL_OBJECTS_DIR;
use fss_publication::LOCAL_SPOOL_DIR;
use fss_reference::agent_sources::{query_sources, row_json};
use support::{Fixture, PRINCIPAL, Test};

fn field<'a>(value: &'a Value, name: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|object| object.get(name))
        .ok_or_else(|| format!("missing {name}").into())
}

fn projected_sources(envelope: &Value) -> Test<BTreeMap<(String, String), Value>> {
    let cognitive = field(envelope, "payload")?;
    let propositions = field(field(cognitive, "epistemic")?, "propositions")?
        .array()
        .ok_or("propositions")?;
    let mut sources = BTreeMap::new();
    for proposition in propositions {
        let statement = field(proposition, "statement")?.text().ok_or("statement")?;
        if let Some(encoded) = statement.strip_prefix("Retained source metadata: ") {
            let row = parse(encoded)?;
            let key = (
                field(&row, "sensor_id")?.text().ok_or("sensor identity")?.to_owned(),
                field(&row, "stream_id")?.text().ok_or("stream identity")?.to_owned(),
            );
            assert!(sources.insert(key, row).is_none(), "duplicate source stream");
        }
    }
    Ok(sources)
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
        "--target=sources".into(),
        "--root".into(),
        fixture.source.root.clone().into(),
        format!("--principal={PRINCIPAL}").into(),
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

fn mcp(fixture: &Fixture, extra: &str) -> Test<Value> {
    // Metadata discovery must work without any launcher source-verification grant.
    let mut child = Command::new(env!("CARGO_BIN_EXE_fss-mcp"))
        .arg("--root")
        .arg(&fixture.source.root)
        .args(["--principal", PRINCIPAL])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let input = format!(
        concat!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"source-inventory-contract\",\"version\":\"1\"}}}}}}\n",
            "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}}\n",
            "{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"query\",\"arguments\":{{\"target\":\"sources\"{}}}}}}}\n"
        ),
        extra
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
    let value = mcp(fixture, extra)?;
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

#[test]
fn source_inventory_and_protected_context_match_cli_and_mcp_without_media_grants() -> Test {
    let fixture = Fixture::new("sources-cli-mcp-parity")?;
    fs::write(fixture.source.root.join("LAYOUT.tmp"), b"pending layout bytes")?;
    let before = tree(&fixture.source.root)?;
    let expected = cli(&fixture, &[])?;
    assert_eq!(expected.1, ExitIdentity::SUCCESS, "{}", expected.0);
    assert!(expected.0.len() <= 256 * 1024);
    same_mcp(&fixture, "", &expected)?;
    assert!(expected.0.contains("AOP-005"));
    assert!(!expected.0.contains(fixture.source.root.to_str().ok_or("root")?));
    for state in ["prepared", "committed", "indeterminate"] {
        assert!(expected.0.contains(&format!("obligation:qsr-read:{state}")));
    }

    let value = parse(&expected.0)?;
    let FssCommand::SourcesQuery(native_args) = parse_fss_args(args(&fixture, &[]))? else {
        return Err("native source inventory request".into());
    };
    let cx = support::context(&fixture.source.root)?;
    let native = query_sources(
        &fixture.source.root, &native_args.request, native_args.limits, &cx, &|| false,
    )?;
    cx.drain_and_finalize();
    assert!(!native.rows.is_empty(), "fixture must retain a source stream");
    let mut projected = projected_sources(&value)?;
    assert_eq!(projected.len(), native.rows.len());
    for row in &native.rows {
        let key = (row.stream.sensor_id.clone(), row.stream.stream_id.clone());
        let projected = projected.remove(&key).ok_or("native source projection")?;
        assert_eq!(field(&projected, "sensor_id")?.text(), Some(key.0.as_str()));
        assert_eq!(field(&projected, "stream_id")?.text(), Some(key.1.as_str()));
        assert_eq!(projected, parse(&row_json(row))?);
    }
    assert!(projected.is_empty());
    let cognitive = field(&value, "payload")?;
    let handles = field(cognitive, "evidenceHandles")?.array().ok_or("handles")?;
    assert!(!handles.is_empty(), "retained capsule metadata handles");
    for handle in handles {
        assert_eq!(field(handle, "hydration")?.text(), Some("H0"));
        let allowed = field(handle, "allowedHydration")?.array().ok_or("allowed hydration")?;
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0].text(), Some("H0"));
        assert_eq!(
            field(handle, "requiredCapability")?.text(),
            Some("CAP-AGENT-QUERY-001")
        );
    }
    assert_eq!(tree(&fixture.source.root)?, before);

    // Inventory makes no claim about original source availability and must not read media.
    fs::remove_file(&fixture.source.chunk)?;
    let absent_media = tree(&fixture.source.root)?;
    assert_eq!(cli(&fixture, &[])?, expected);
    same_mcp(&fixture, "", &expected)?;
    assert_eq!(tree(&fixture.source.root)?, absent_media);
    Ok(())
}

#[test]
fn empty_filters_keep_protected_context_and_cannot_hide_corrupt_capsules() -> Test {
    let fixture = Fixture::new("sources-filter-integrity")?;
    let before = tree(&fixture.source.root)?;
    let empty = cli(&fixture, &[("--sensor", "sensor:not-retained")])?;
    assert_eq!(empty.1, ExitIdentity::SUCCESS, "{}", empty.0);
    same_mcp(&fixture, r#", "sensor":"sensor:not-retained""#, &empty)?;
    assert!(projected_sources(&parse(&empty.0)?)?.is_empty());
    for state in ["prepared", "committed", "indeterminate"] {
        assert!(empty.0.contains(&format!("obligation:qsr-read:{state}")));
    }
    assert_eq!(tree(&fixture.source.root)?, before);

    let FssCommand::SourcesQuery(native_args) = parse_fss_args(args(&fixture, &[]))? else {
        return Err("source inventory request".into());
    };
    let cx = support::context(&fixture.source.root)?;
    let native = query_sources(
        &fixture.source.root, &native_args.request, native_args.limits, &cx, &|| false,
    )?;
    cx.drain_and_finalize();
    let digest = native.rows.first().and_then(|row| row.capsule_metadata.first())
        .ok_or("retained capsule metadata")?;
    let hex: String = digest.bytes().iter().map(|byte| format!("{byte:02x}")).collect();
    let metadata = fixture.source.root.join("objects")
        .join(LOCAL_SPOOL_DIR).join(SPOOL_OBJECTS_DIR).join(hex);
    fs::write(metadata, b"corrupt excluded capsule metadata")?;
    let damaged = tree(&fixture.source.root)?;
    let refused = cli(&fixture, &[("--sensor", "sensor:not-retained")])?;
    assert_eq!(refused.1, ExitIdentity::AGENT_REFUSED);
    same_mcp(&fixture, r#", "sensor":"sensor:not-retained""#, &refused)?;
    assert!(!refused.0.contains("Retained source metadata: "));
    assert_eq!(tree(&fixture.source.root)?, damaged);
    Ok(())
}

#[test]
fn bounded_reads_and_closed_grammar_refuse_without_source_rows() -> Test {
    let fixture = Fixture::new("sources-query-refusals")?;
    let before = tree(&fixture.source.root)?;
    let limited = cli(&fixture, &[("--max-query-read-objects", "1")])?;
    assert_eq!(limited.1, ExitIdentity::AGENT_REFUSED);
    same_mcp(&fixture, r#", "max_query_read_objects":"1""#, &limited)?;
    assert!(!limited.0.contains("Retained source metadata: "));
    for (flag, value) in [
        ("--family", "package_zone_report"),
        ("--from-ns", "0"),
        ("--at", "latest"),
        ("--sensor", "sensor invalid"),
        ("--stream", ""),
        ("--max-entries", "33"),
        ("--max-query-read-bytes", "268435457"),
        ("--max-query-read-objects", "65537"),
        ("--max-query-results", "1025"),
        ("--report-digest", "sha256:invalid"),
        ("--continuation", "continuation:INVALID"),
    ] {
        assert!(parse_fss_args(args(&fixture, &[(flag, value)])).is_err(), "{flag}");
    }
    for extra in [
        r#", "root":"/another-deployment""#,
        r#", "principal":"principal:another-reader""#,
        r#", "verify_source":true"#,
        r#", "hydrate":"H3""#,
        r#", "sources":[]"#,
        r#", "family":"package_zone_report""#,
        r#", "from_ns":"0""#,
        r#", "max_entries":"1""#,
        r#", "max_entries":1.0"#,
        r#", "max_query_read_objects":1"#,
        r#", "max_query_results":"1025""#,
    ] {
        assert!(field(&mcp(&fixture, extra)?, "error").is_ok(), "{extra}");
    }
    assert_eq!(tree(&fixture.source.root)?, before);
    Ok(())
}
