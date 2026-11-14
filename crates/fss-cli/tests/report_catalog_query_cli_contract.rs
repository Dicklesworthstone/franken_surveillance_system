#![forbid(unsafe_code)]
//! Real retained report metadata across native Rust, CLI and closed MCP transport boundaries.

#[path = "../../fss-reference/tests/qsr_observations_support/mod.rs"]
mod support;

#[path = "report_catalog_query_cli_contract/model_run.rs"]
mod model_run;

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
use fss_reference::agent_report_catalog::query_report_catalog;
use support::{Fixture, PRINCIPAL, Test};

fn field<'a>(value: &'a Value, name: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|object| object.get(name))
        .ok_or_else(|| format!("missing {name}").into())
}

fn projected_reports(envelope: &Value) -> Test<BTreeMap<(String, String), Value>> {
    let cognitive = field(envelope, "payload")?;
    let propositions = field(field(cognitive, "epistemic")?, "propositions")?
        .array()
        .ok_or("propositions")?;
    let mut reports = BTreeMap::new();
    for proposition in propositions {
        let statement = field(proposition, "statement")?.text().ok_or("statement")?;
        if let Some(encoded) = statement.strip_prefix("Retained report metadata: ") {
            let row = parse(encoded)?;
            let key = (
                field(&row, "family")?
                    .text()
                    .ok_or("report family")?
                    .to_owned(),
                field(&row, "report_digest")?
                    .text()
                    .ok_or("report digest")?
                    .to_owned(),
            );
            assert!(
                reports.insert(key, row).is_none(),
                "duplicate projected report"
            );
        }
    }
    Ok(reports)
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
        "--target=reports".into(),
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
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"report-catalog-contract\",\"version\":\"1\"}}}}}}\n",
            "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}}\n",
            "{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"query\",\"arguments\":{{\"target\":\"reports\"{}}}}}}}\n"
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
fn exact_report_handles_and_protected_context_match_cli_and_mcp_without_source_grants() -> Test {
    let fixture = Fixture::new("catalog-cli-mcp-parity")?;
    fs::write(
        fixture.source.root.join("LAYOUT.tmp"),
        b"unrelated pending layout bytes",
    )?;
    let before = tree(&fixture.source.root)?;
    let expected = cli(&fixture, &[])?;
    assert_eq!(expected.1, ExitIdentity::SUCCESS, "{}", expected.0);
    assert!(expected.0.len() <= 256 * 1024);
    same_mcp(&fixture, "", &expected)?;
    assert!(expected.0.contains("AOP-005"));
    assert!(expected.0.contains(&fixture.source.report.to_text()));
    assert!(expected.0.contains(&fixture.report.to_text()));
    assert!(expected.0.contains("package_detection_record"));
    assert!(expected.0.contains("fss.package_zone_report.v2"));
    assert!(
        !expected
            .0
            .contains(fixture.source.root.to_str().ok_or("root")?)
    );
    for state in ["prepared", "committed", "indeterminate"] {
        assert!(expected.0.contains(&format!("obligation:qsr-read:{state}")));
    }
    let value = parse(&expected.0)?;
    let FssCommand::ReportCatalogQuery(native_args) = parse_fss_args(args(&fixture, &[]))? else {
        return Err("native report catalog request".into());
    };
    let cx = support::context(&fixture.source.root)?;
    let native = query_report_catalog(
        &fixture.source.root,
        &native_args.request,
        native_args.limits,
        &cx,
        &|| false,
    )?;
    cx.drain_and_finalize();
    let mut projected = projected_reports(&value)?;
    assert_eq!(projected.len(), native.rows.len());
    for row in &native.rows {
        let projected = projected
            .remove(&(row.family.as_str().to_owned(), row.report_digest.to_text()))
            .ok_or("exact native report projection")?;
        assert_eq!(projected.object().ok_or("row object")?.len(), 12);
        for (key, expected) in [
            ("report_digest", row.report_digest.to_text()),
            ("record_digest", row.record_digest.to_text()),
            ("provenance_root", row.provenance_root.to_text()),
            ("publication_slot", row.publication_slot.clone()),
            ("schema", row.schema.clone()),
        ] {
            assert_eq!(
                field(&projected, key)?.text(),
                Some(expected.as_str()),
                "{key}"
            );
        }
        let interval = field(&projected, "declared_validity_ns")?
            .array()
            .ok_or("declared interval")?;
        assert_eq!(interval.len(), 2);
        assert_eq!(
            interval[0]
                .text()
                .ok_or("exact earliest")?
                .parse::<i128>()?,
            row.validity.earliest.0
        );
        assert_eq!(
            interval[1].text().ok_or("exact latest")?.parse::<i128>()?,
            row.validity.latest.0
        );
        assert_eq!(
            field(&projected, "retention_commit")?
                .text()
                .ok_or("exact commit")?
                .parse::<u64>()?,
            row.committed_sequence
        );
        for (key, expected) in [
            ("metadata_availability", "verified"),
            ("source_payload_availability", "unknown"),
            ("source_reconstruction", "not_performed"),
            ("qsr_eligibility", "unknown"),
        ] {
            assert_eq!(field(&projected, key)?.text(), Some(expected), "{key}");
        }
    }
    assert!(projected.is_empty());
    let cognitive = field(&value, "payload")?;
    assert_eq!(
        field(cognitive, "schema")?.text(),
        Some("fss.agent_cognitive_envelope.v1")
    );
    let handles = field(cognitive, "evidenceHandles")?
        .array()
        .ok_or("handles")?;
    assert_eq!(
        handles.len(),
        5,
        "detector report/record/root plus zone report/root"
    );
    for handle in handles {
        assert_eq!(field(handle, "hydration")?.text(), Some("H0"));
        let allowed = field(handle, "allowedHydration")?
            .array()
            .ok_or("allowed hydration")?;
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0].text(), Some("H0"));
        assert_eq!(
            field(handle, "requiredCapability")?.text(),
            Some("CAP-AGENT-QUERY-001")
        );
    }
    assert_eq!(tree(&fixture.source.root)?, before);

    // Retained metadata remains discoverable even when source reconstruction would refuse.
    fs::remove_file(&fixture.source.chunk)?;
    let absent_media = tree(&fixture.source.root)?;
    assert_eq!(cli(&fixture, &[])?, expected);
    same_mcp(&fixture, "", &expected)?;
    assert_eq!(tree(&fixture.source.root)?, absent_media);
    Ok(())
}

#[test]
fn native_report_continuations_and_filters_are_identical_across_transports() -> Test {
    let fixture = Fixture::new("catalog-cli-continuation")?;
    let before = tree(&fixture.source.root)?;
    let first = cli(&fixture, &[("--max-entries", "1")])?;
    assert_eq!(first.1, ExitIdentity::SUCCESS, "{}", first.0);
    same_mcp(&fixture, r#", "max_entries":1"#, &first)?;
    let value = parse(&first.0)?;
    assert_eq!(field(&value, "outcome")?.text(), Some("partial"));
    let continuation = field(&value, "continuation")?.text().ok_or("next cursor")?;
    let second = cli(
        &fixture,
        &[("--max-entries", "1"), ("--continuation", continuation)],
    )?;
    assert_eq!(second.1, ExitIdentity::SUCCESS, "{}", second.0);
    same_mcp(
        &fixture,
        &format!(
            r#", "max_entries":1, "continuation":{}"#,
            fss_cli::json_output::string(continuation)
        ),
        &second,
    )?;
    let second_value = parse(&second.0)?;
    assert_eq!(field(&second_value, "outcome")?.text(), Some("ok"));
    assert!(field(&second_value, "continuation")?.text().is_none());
    assert!(second.0.contains(&fixture.report.to_text()));
    let wrong_scope = cli(
        &fixture,
        &[
            ("--max-entries", "1"),
            ("--continuation", continuation),
            ("--family", "package_zone_report"),
        ],
    )?;
    assert_eq!(wrong_scope.1, ExitIdentity::AGENT_REFUSED);
    assert!(!wrong_scope.0.contains("claim:report-catalog:"));
    let selected = cli(&fixture, &[("--family", "package_zone_report")])?;
    assert_eq!(selected.1, ExitIdentity::SUCCESS);
    same_mcp(&fixture, r#", "family":"package_zone_report""#, &selected)?;
    let selected_rows = projected_reports(&parse(&selected.0)?)?;
    assert_eq!(selected_rows.len(), 1);
    assert!(
        selected_rows.contains_key(&("package_zone_report".to_owned(), fixture.report.to_text()))
    );
    assert_eq!(tree(&fixture.source.root)?, before);
    Ok(())
}

#[test]
fn exhausted_allowances_and_corrupt_excluded_reports_return_no_partial_catalog() -> Test {
    let fixture = Fixture::new("catalog-cli-refusals")?;
    let before = tree(&fixture.source.root)?;
    let limited = cli(&fixture, &[("--max-query-read-objects", "1")])?;
    assert_eq!(limited.1, ExitIdentity::AGENT_REFUSED);
    same_mcp(&fixture, r#", "max_query_read_objects":"1""#, &limited)?;
    assert!(!limited.0.contains("claim:report-catalog:"));
    let index_limit = cli(
        &fixture,
        &[
            ("--max-query-results", "1"),
            ("--family", "package_detection_record"),
        ],
    )?;
    assert_eq!(index_limit.1, ExitIdentity::AGENT_REFUSED);
    same_mcp(
        &fixture,
        r#", "max_query_results":"1", "family":"package_detection_record""#,
        &index_limit,
    )?;
    assert_eq!(tree(&fixture.source.root)?, before);
    let hex: String = fixture
        .report
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let metadata = fixture
        .source
        .root
        .join("objects")
        .join(LOCAL_SPOOL_DIR)
        .join(SPOOL_OBJECTS_DIR)
        .join(hex);
    fs::write(metadata, b"corrupt excluded retained zone report")?;
    let damaged = tree(&fixture.source.root)?;
    let refused = cli(&fixture, &[("--family", "package_detection_record")])?;
    assert_eq!(refused.1, ExitIdentity::AGENT_REFUSED);
    same_mcp(
        &fixture,
        r#", "family":"package_detection_record""#,
        &refused,
    )?;
    assert!(!refused.0.contains("claim:report-catalog:"));
    assert_eq!(tree(&fixture.source.root)?, damaged);
    Ok(())
}

#[test]
fn closed_reports_grammar_rejects_other_targets_selectors_and_mcp_scope_overrides() -> Test {
    let fixture = Fixture::new("catalog-cli-closed-grammar")?;
    let before = tree(&fixture.source.root)?;
    assert!(matches!(
        parse_fss_args(args(&fixture, &[]))?,
        FssCommand::ReportCatalogQuery(_)
    ));
    for (flag, value) in [
        ("--family", "detections"),
        ("--family", "package_zone_report "),
        ("--from-ns", "-0"),
        ("--through-ns", "01"),
        ("--max-entries", "33"),
        ("--max-query-read-bytes", "268435457"),
        ("--max-query-read-objects", "65537"),
        ("--max-query-results", "4097"),
        ("--at", "latest"),
        ("--sensor", "sensor:one"),
        ("--report-digest", "sha256:invalid"),
        ("--verify-qsr-source", "yes"),
        ("--zone-roles", "[]"),
        ("--continuation", "continuation:INVALID"),
    ] {
        assert!(
            parse_fss_args(args(&fixture, &[(flag, value)])).is_err(),
            "{flag}"
        );
    }
    for extra in [
        r#", "root":"/another-deployment""#,
        r#", "principal":"principal:another-reader""#,
        r#", "verify_qsr_source":true"#,
        r#", "report_digest":"sha256:invalid""#,
        r#", "zone_roles":[]"#,
        r#", "family":"detections""#,
        r#", "from_ns":9007199254740993"#,
        r#", "from_ns":"-0""#,
        r#", "from_ns":"2", "through_ns":"1""#,
        r#", "max_entries":"1""#,
        r#", "max_entries":1.0"#,
        r#", "max_query_read_objects":1"#,
        r#", "max_query_results":"4097""#,
        r#", "hydrate":"H3""#,
    ] {
        let response = mcp(&fixture, extra)?;
        assert!(field(&response, "error").is_ok(), "{extra}");
    }
    assert_eq!(tree(&fixture.source.root)?, before);
    Ok(())
}
