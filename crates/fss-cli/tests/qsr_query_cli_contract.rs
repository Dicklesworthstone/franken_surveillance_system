#![forbid(unsafe_code)]
//! Real retained detector/health evidence across canonical Rust, CLI and MCP boundaries.

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
use support::{Fixture, PRINCIPAL, Test};

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
        "--target=qsr".into(),
        "--root".into(),
        fixture.source.root.clone().into(),
        format!("--principal={PRINCIPAL}").into(),
        format!("--report-digest={}", fixture.report).into(),
        "--verify-qsr-source=yes".into(),
        r#"--zone-roles=[{"zone":"image","role":"queue"}]"#.into(),
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
        process.arg("--allow-qsr-source-verification");
    }
    let mut child = process
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let input = format!(
        concat!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"qsr-contract\",\"version\":\"1\"}}}}}}\n",
            "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}}\n",
            "{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"query\",\"arguments\":{{\"target\":\"qsr\",\"report_digest\":\"{}\",\"zone_roles\":[{{\"zone\":\"image\",\"role\":\"queue\"}}]{}}}}}}}\n"
        ),
        fixture.report, extra
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

fn assert_lane_companion(fixture: &Fixture, propositions: &[Value], expected: &str) -> Test {
    let native = parse(expected)?;
    let native = native.object().ok_or("native lane companion")?;
    let mut rows = BTreeMap::new();
    let mut encoded_rows = BTreeMap::new();
    let expected_evidence: Vec<_> = [
        "report_digest",
        "source_qsr_report",
        "source_zone_report",
        "provenance_root",
    ]
    .iter()
    .map(|key| {
        native
            .get(*key)
            .and_then(Value::text)
            .ok_or("companion evidence")
    })
    .collect::<Result<_, _>>()?;
    for proposition in propositions {
        let Some(id) = field(proposition, "id")?
            .text()
            .and_then(|id| id.strip_prefix("claim:qsr-lane:"))
        else {
            continue;
        };
        let statement = field(proposition, "statement")?
            .text()
            .ok_or("lane statement")?;
        let encoded_row = statement.split_once(": ").ok_or("lane row")?.1;
        let row = parse(encoded_row)?;
        let evidence: Vec<_> = field(proposition, "evidence")?
            .array()
            .ok_or("lane evidence")?
            .iter()
            .map(|value| value.text().ok_or("evidence text"))
            .collect::<Result<_, _>>()?;
        assert_eq!(evidence, expected_evidence);
        if id.starts_with("traversals:") {
            let expected_state = if field(&row, "status")?.text() == Some("completed") {
                "estimated"
            } else {
                "unknown"
            };
            assert_eq!(field(proposition, "state")?.text(), Some(expected_state));
        }
        assert!(rows.insert(id.to_owned(), row).is_none());
        assert!(
            encoded_rows
                .insert(id.to_owned(), encoded_row.to_owned())
                .is_none()
        );
    }
    let mut emitted = Vec::new();
    for (section, value) in native {
        if section == "traversals" && value.array().is_some_and(|values| !values.is_empty()) {
            let mut encoded = Vec::new();
            for (ordinal, value) in value.array().ok_or("traversals")?.iter().enumerate() {
                let id = format!("traversals:{ordinal}");
                assert_eq!(rows.remove(&id).as_ref(), Some(value));
                encoded.push(encoded_rows.remove(&id).ok_or("emitted traversal")?);
            }
            emitted.push(format!("\"traversals\":[{}]", encoded.join(",")));
        } else {
            assert_eq!(rows.remove(section).as_ref(), Some(value));
            emitted.push(format!(
                "{}:{}",
                fss_cli::agent_json::string(section),
                encoded_rows
                    .remove(section)
                    .ok_or("emitted companion section")?
            ));
        }
    }
    assert!(rows.is_empty(), "unexpected lane companion rows");
    assert!(encoded_rows.is_empty());
    // Reassemble the actual emitted rows; the fixture is only an independent parity oracle.
    // The bounded validation file is outside the deployment whose no-mutation tree is asserted.
    let emitted = format!("{{{}}}", emitted.join(","));
    assert!(emitted.len() <= 256 * 1024);
    let path = fixture
        .source
        .directory
        .0
        .join("qsr-lane-schema-instance.json");
    fs::write(&path, emitted)?;
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let checked = Command::new("python3")
        .arg("-B")
        .arg(repository.join("scripts/json_instance_validate.py"))
        .arg(repository.join("schemas/qsr_lane_traversal_report.v1.json"))
        .arg(&path)
        .output()?;
    fs::remove_file(path)?;
    assert!(
        checked.status.success(),
        "{}{}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
    Ok(())
}

#[test]
fn complete_native_rows_and_protected_context_match_across_rust_cli_and_mcp() -> Test {
    let fixture = Fixture::new("canonical-qsr-parity")?;
    fs::write(
        fixture.source.root.join("LAYOUT.tmp"),
        b"unrelated pending layout bytes",
    )?;
    let before = tree(&fixture.source.root)?;
    let expected = cli(&fixture, &[])?;
    assert_eq!(expected.1, ExitIdentity::SUCCESS, "{}", expected.0);
    same_mcp(&fixture, "", &expected)?;
    assert!(expected.0.contains("AOP-005"));
    for state in ["prepared", "committed", "indeterminate"] {
        assert!(expected.0.contains(&format!("obligation:qsr-read:{state}")));
    }
    let value = parse(&expected.0)?;
    let cognitive = field(&value, "payload")?;
    assert_eq!(
        field(cognitive, "schema")?.text(),
        Some("fss.agent_cognitive_envelope.v1")
    );
    let propositions = field(field(cognitive, "epistemic")?, "propositions")?
        .array()
        .ok_or("propositions")?;
    let mut rows = BTreeMap::new();
    for proposition in propositions {
        let id = field(proposition, "id")?.text().ok_or("proposition ID")?;
        if let Some(id) = id.strip_prefix("claim:qsr:") {
            if id == "deployment-anchor" {
                continue;
            }
            let statement = field(proposition, "statement")?
                .text()
                .ok_or("proposition statement")?;
            let (_, native) = statement.split_once(": ").ok_or("native row")?;
            assert!(rows.insert(id.to_owned(), parse(native)?).is_none());
        }
    }
    let native = parse(&fixture.expected_json)?;
    for (section, value) in native.object().ok_or("native object")? {
        if let Some(values) = value.array().filter(|values| !values.is_empty()) {
            for (ordinal, value) in values.iter().enumerate() {
                assert_eq!(
                    rows.remove(&format!("{section}:{ordinal}")).as_ref(),
                    Some(value)
                );
            }
        } else {
            assert_eq!(rows.remove(section).as_ref(), Some(value));
        }
    }
    assert!(rows.is_empty(), "unexpected native rows: {rows:?}");
    assert_lane_companion(&fixture, propositions, &fixture.expected_lane_json)?;
    for handle in field(cognitive, "evidenceHandles")?
        .array()
        .ok_or("handles")?
    {
        let text = format!("{handle:?}");
        assert!(!text.contains("H1") && !text.contains("H2") && !text.contains("H3"));
    }
    assert_eq!(tree(&fixture.source.root)?, before);
    Ok(())
}

#[test]
fn observed_whole_lane_completion_reaches_actual_cli_and_mcp_with_bounded_uncertainty() -> Test {
    let fixture = Fixture::new_lane("canonical-qsr-whole-lane")?;
    let before = tree(&fixture.source.root)?;
    let expected = cli(&fixture, &[("--lane-stages", r#"["early","late"]"#)])?;
    assert_eq!(expected.1, ExitIdentity::SUCCESS, "{}", expected.0);
    same_mcp(&fixture, r#", "lane_stages":["early","late"]"#, &expected)?;
    let value = parse(&expected.0)?;
    let cognitive = field(&value, "payload")?;
    let propositions = field(field(cognitive, "epistemic")?, "propositions")?
        .array()
        .ok_or("propositions")?;
    assert_lane_companion(&fixture, propositions, &fixture.expected_lane_json)?;
    let native = parse(&fixture.expected_lane_json)?;
    let companion_digest = field(&native, "report_digest")?
        .text()
        .ok_or("companion digest")?;
    assert!(
        field(&value, "proofPointers")?
            .array()
            .ok_or("outer proofs")?
            .iter()
            .any(|proof| proof.text() == Some(companion_digest))
    );
    let rows = field(&native, "traversals")?.array().ok_or("traversals")?;
    assert_eq!(rows.len(), 1);
    assert_eq!(field(&rows[0], "status")?.text(), Some("completed"));
    assert_eq!(
        field(&rows[0], "minimum_elapsed_ns")?.text(),
        Some("98000000")
    );
    assert_eq!(
        field(&rows[0], "maximum_elapsed_ns")?.text(),
        Some("102000000")
    );
    assert_eq!(
        field(
            field(&native, "interpretation")?,
            "service_or_wait_duration_established"
        )?
        .boolean(),
        Some(false)
    );
    assert_eq!(
        field(
            field(&native, "interpretation")?,
            "continuous_traversal_established"
        )?
        .boolean(),
        Some(false)
    );
    // Reversing the declared order yields a suffix and a report-end-censored prefix;
    // neither may inherit the completed row's epistemic state or duration.
    let reversed = cli(&fixture, &[("--lane-stages", r#"["late","early"]"#)])?;
    assert_eq!(reversed.1, ExitIdentity::SUCCESS, "{}", reversed.0);
    same_mcp(&fixture, r#", "lane_stages":["late","early"]"#, &reversed)?;
    let reversed = parse(&reversed.0)?;
    let propositions = field(
        field(field(&reversed, "payload")?, "epistemic")?,
        "propositions",
    )?
    .array()
    .ok_or("reversed propositions")?;
    let mut terminations = Vec::new();
    for proposition in propositions {
        if !field(proposition, "id")?
            .text()
            .is_some_and(|id| id.starts_with("claim:qsr-lane:traversals:"))
        {
            continue;
        }
        assert_eq!(field(proposition, "state")?.text(), Some("unknown"));
        let statement = field(proposition, "statement")?
            .text()
            .ok_or("reversed statement")?;
        let row = parse(statement.split_once(": ").ok_or("reversed native row")?.1)?;
        assert_eq!(field(&row, "status")?.text(), Some("incomplete"));
        terminations.push(
            field(&row, "termination")?
                .text()
                .ok_or("termination")?
                .to_owned(),
        );
    }
    assert_eq!(terminations, ["last_stage_observed", "source_sample_ended"]);
    assert_eq!(tree(&fixture.source.root)?, before);
    Ok(())
}

#[test]
fn source_grant_budget_and_corruption_refusals_return_no_partial_observations() -> Test {
    let fixture = Fixture::new("canonical-qsr-refusals")?;
    let before = tree(&fixture.source.root)?;
    let FssCommand::QsrQuery(mut typed) = parse_fss_args(args(&fixture, &[]))? else {
        return Err("QSR command".into());
    };
    typed.verify_qsr_source = false;
    let denied = fss_cli::qsr_query_cmd::execute_qsr_query(&typed);
    assert_eq!(denied.1, ExitIdentity::AGENT_REFUSED);
    assert!(!denied.0.contains("claim:qsr:samples"));
    assert!(!denied.0.contains("claim:qsr-lane:"));
    let denied = mcp(&fixture, false, "")?;
    assert!(field(&denied, "error").is_ok());
    let limited = cli(&fixture, &[("--max-query-read-objects", "1")])?;
    assert_eq!(limited.1, ExitIdentity::AGENT_REFUSED);
    same_mcp(&fixture, r#", "max_query_read_objects":"1""#, &limited)?;
    assert!(!limited.0.contains("claim:qsr:samples"));
    assert!(!limited.0.contains("claim:qsr-lane:"));
    assert_eq!(tree(&fixture.source.root)?, before);
    let mut corrupt = fs::read(&fixture.source.chunk)?;
    *corrupt.last_mut().ok_or("source byte")? ^= 1;
    fs::write(&fixture.source.chunk, corrupt)?;
    let before = tree(&fixture.source.root)?;
    let refused = cli(&fixture, &[])?;
    assert_eq!(refused.1, ExitIdentity::AGENT_REFUSED);
    same_mcp(&fixture, "", &refused)?;
    assert!(!refused.0.contains("claim:qsr:samples"));
    assert_eq!(tree(&fixture.source.root)?, before);
    Ok(())
}
