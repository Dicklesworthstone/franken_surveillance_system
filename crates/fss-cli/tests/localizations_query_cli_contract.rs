#![forbid(unsafe_code)]
//! Genuine retained camera-pose proposals across native Rust, CLI and MCP discovery.

#[path = "../../fss-reference/tests/twin_localization_query_support/mod.rs"]
mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use fss_cli::{ExitIdentity, FssCommand, execute_fss_with_exit, parse_fss_args};
use fss_core::json_input::{Value, parse};
use fss_reference::agent_localizations::{query_localizations, row_json};
use support::{Fixture, PRINCIPAL, Test};

fn field<'a>(value: &'a Value, name: &str) -> Test<&'a Value> {
    value
        .object()
        .and_then(|object| object.get(name))
        .ok_or_else(|| format!("missing {name}").into())
}

fn projected_localizations(envelope: &Value) -> Test<Vec<Value>> {
    let propositions = field(
        field(field(envelope, "payload")?, "epistemic")?,
        "propositions",
    )?
    .array()
    .ok_or("propositions")?;
    let mut rows = Vec::new();
    for proposition in propositions {
        let statement = field(proposition, "statement")?.text().ok_or("statement")?;
        if let Some(encoded) = statement.strip_prefix("Retained localization metadata: ") {
            rows.push(parse(encoded)?);
        }
    }
    Ok(rows)
}

fn payload_free_refusal(response: &(String, ExitIdentity)) -> Test {
    assert_eq!(response.1, ExitIdentity::AGENT_REFUSED);
    let value = parse(&response.0)?;
    if field(&value, "schema")?.text() == Some("fss.cli_diagnostic.v1") {
        assert!(
            !value
                .object()
                .ok_or("diagnostic object")?
                .contains_key("payload")
        );
        assert_eq!(field(&value, "effect_started")?.boolean(), Some(false));
    } else {
        assert_eq!(field(&value, "payload")?, &Value::Null);
    }
    assert!(!response.0.contains("Retained localization metadata: "));
    Ok(())
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

fn args(root: &Path, extras: &[(&str, &str)]) -> Vec<OsString> {
    let mut values: Vec<OsString> = vec![
        "query".into(),
        "--json".into(),
        "--target=localizations".into(),
        "--root".into(),
        root.into(),
        format!("--principal={PRINCIPAL}").into(),
    ];
    values.extend(
        extras
            .iter()
            .map(|(key, value)| format!("{key}={value}").into()),
    );
    values
}

fn cli(root: &Path, extras: &[(&str, &str)]) -> Test<(String, ExitIdentity)> {
    let args = args(root, extras);
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

fn mcp(root: &Path, extra: &str) -> Test<Value> {
    // The launcher grants metadata reads only: no perception or source-verification grant.
    let mut child = Command::new(env!("CARGO_BIN_EXE_fss-mcp"))
        .arg("--root")
        .arg(root)
        .args(["--principal", PRINCIPAL])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let input = format!(
        concat!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"localization-discovery-contract\",\"version\":\"1\"}}}}}}\n",
            "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}}\n",
            "{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\"name\":\"query\",\"arguments\":{{\"target\":\"localizations\"{}}}}}}}\n"
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

fn same_mcp(root: &Path, extra: &str, expected: &(String, ExitIdentity)) -> Test {
    let value = mcp(root, extra)?;
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
fn genuine_pose_proposals_match_native_cli_and_mcp_without_replay_assets_or_grants() -> Test {
    // The producer retains the publication owner for the duration of every read.
    let fixture = Fixture::new("localizations-cli-mcp-parity")?;
    let root = fixture.root();
    fs::write(root.join("LAYOUT.tmp"), b"pending layout bytes")?;
    let before = tree(root)?;
    let expected = cli(root, &[])?;
    assert_eq!(expected.1, ExitIdentity::SUCCESS, "{}", expected.0);
    assert!(expected.0.len() <= 256 * 1024);
    assert!(expected.0.contains("AOP-005"));
    assert!(!expected.0.contains(root.to_str().ok_or("root")?));
    same_mcp(root, "", &expected)?;

    let FssCommand::LocalizationsQuery(native_args) = parse_fss_args(args(root, &[]))? else {
        return Err("native localizations request".into());
    };
    let cx = support::context(root)?;
    let native = query_localizations(root, &native_args.request, native_args.limits, &cx, &|| {
        false
    })?;
    cx.drain_and_finalize();
    assert_eq!(native.rows.len(), fixture.records.len());
    assert!(
        native.rows.len() >= 2,
        "genuine distinct localization outcomes"
    );
    let projected = projected_localizations(&parse(&expected.0)?)?;
    let native_rows: Result<Vec<_>, _> = native
        .rows
        .iter()
        .map(|row| parse(&row_json(row)))
        .collect();
    assert_eq!(projected, native_rows?);
    for row in &projected {
        for (key, expected) in [
            ("scope", "unactivated_camera_pose_candidates"),
            ("verification", "metadata_only"),
            ("replay", "not_performed"),
            ("candidate_outcome", "not_interpreted"),
            ("adoption", "unknown"),
            ("current_calibration", "unknown"),
            ("physical_coverage", "unknown"),
            ("source_payload_availability", "unknown"),
            ("archive_payload_availability", "unknown"),
            ("privacy_status", "current_binding_matches_receipt"),
        ] {
            assert_eq!(field(row, key)?.text(), Some(expected), "{key}");
        }
        assert_eq!(field(row, "activation_performed")?.boolean(), Some(false));
    }
    for record in &fixture.records {
        for digest in [
            record.identity,
            record.root,
            record.receipt,
            record.import_identity,
        ] {
            assert!(expected.0.contains(&digest.to_text()), "missing {digest:?}");
        }
    }

    let value = parse(&expected.0)?;
    let cognitive = field(&value, "payload")?;
    assert_eq!(
        field(cognitive, "schema")?.text(),
        Some("fss.agent_cognitive_envelope.v1")
    );
    let handles = field(cognitive, "evidenceHandles")?
        .array()
        .ok_or("handles")?;
    assert!(
        !handles.is_empty(),
        "retained localization metadata handles"
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
    assert_eq!(tree(root)?, before);

    // H0 must not depend on decoding the footage or loading the retained mapping archives.
    let replay_assets: BTreeSet<_> = fixture
        .records
        .iter()
        .flat_map(|record| {
            [
                record.source_blob,
                record.luma_blob,
                record.twin_blob,
                record.atlas_blob,
            ]
        })
        .collect();
    for digest in replay_assets {
        fs::remove_file(fixture.object_path(digest))?;
    }
    let absent_replay_assets = tree(root)?;
    assert_eq!(cli(root, &[])?, expected);
    same_mcp(root, "", &expected)?;
    assert_eq!(tree(root)?, absent_replay_assets);
    Ok(())
}

#[test]
fn localization_pagination_and_exact_selectors_share_native_scope_across_transports() -> Test {
    let fixture = Fixture::new("localizations-cli-continuation")?;
    let root = fixture.root();
    let before = tree(root)?;
    let all = cli(root, &[])?;
    assert_eq!(all.1, ExitIdentity::SUCCESS, "{}", all.0);
    let all_rows = projected_localizations(&parse(&all.0)?)?;
    let first = cli(root, &[("--max-entries", "1")])?;
    assert_eq!(first.1, ExitIdentity::SUCCESS, "{}", first.0);
    same_mcp(root, r#", "max_entries":1"#, &first)?;
    let first_value = parse(&first.0)?;
    assert_eq!(field(&first_value, "outcome")?.text(), Some("partial"));
    let first_cursor = field(&first_value, "continuation")?
        .text()
        .ok_or("first page cursor")?
        .to_owned();
    let mut actual_rows = projected_localizations(&first_value)?;
    assert_eq!(actual_rows.len(), 1);
    let mut continuation = Some(first_cursor.clone());
    let mut page_count = 1;
    while let Some(cursor) = continuation {
        assert!(
            page_count < fixture.records.len(),
            "continuation must advance"
        );
        let page = cli(root, &[("--max-entries", "1"), ("--continuation", &cursor)])?;
        assert_eq!(page.1, ExitIdentity::SUCCESS, "{}", page.0);
        same_mcp(
            root,
            &format!(
                r#", "max_entries":1, "continuation":{}"#,
                fss_cli::json_output::string(&cursor)
            ),
            &page,
        )?;
        let value = parse(&page.0)?;
        let rows = projected_localizations(&value)?;
        assert_eq!(rows.len(), 1);
        actual_rows.extend(rows);
        continuation = field(&value, "continuation")?.text().map(str::to_owned);
        assert_eq!(
            field(&value, "outcome")?.text(),
            Some(if continuation.is_some() {
                "partial"
            } else {
                "ok"
            })
        );
        page_count += 1;
    }
    assert_eq!(
        actual_rows, all_rows,
        "pages preserve exact native row order"
    );

    let wrong_scope = cli(
        root,
        &[
            ("--max-entries", "1"),
            ("--continuation", &first_cursor),
            ("--sensor", "sensor:not-retained"),
        ],
    )?;
    assert_eq!(wrong_scope.1, ExitIdentity::AGENT_REFUSED);
    same_mcp(
        root,
        &format!(
            r#", "max_entries":1, "continuation":{}, "sensor":"sensor:not-retained""#,
            fss_cli::json_output::string(&first_cursor)
        ),
        &wrong_scope,
    )?;
    payload_free_refusal(&wrong_scope)?;

    let record = fixture.records.first().ok_or("retained localization")?;
    let import = record.import_identity.to_text();
    let twin = record.twin_blob.to_text();
    let selected = cli(
        root,
        &[
            ("--sensor", record.sensor_id.as_str()),
            ("--stream", record.stream_id.as_str()),
            ("--import-id", &import),
            ("--twin-digest", &twin),
        ],
    )?;
    assert_eq!(selected.1, ExitIdentity::SUCCESS, "{}", selected.0);
    same_mcp(
        root,
        &format!(
            r#", "sensor":"{}", "stream":"{}", "import_id":"{import}", "twin_digest":"{twin}""#,
            record.sensor_id.as_str(),
            record.stream_id.as_str(),
        ),
        &selected,
    )?;
    assert!(selected.0.contains(&record.identity.to_text()));
    assert_eq!(
        projected_localizations(&parse(&selected.0)?)?.len(),
        fixture
            .records
            .iter()
            .filter(|candidate| candidate.sensor_id == record.sensor_id
                && candidate.stream_id == record.stream_id
                && candidate.import_identity == record.import_identity
                && candidate.twin_blob == record.twin_blob)
            .count(),
        "all four selectors are exact conjunctive native predicates",
    );
    let empty = cli(root, &[("--stream", "stream:not-retained")])?;
    assert_eq!(empty.1, ExitIdentity::SUCCESS, "{}", empty.0);
    same_mcp(root, r#", "stream":"stream:not-retained""#, &empty)?;
    assert!(projected_localizations(&parse(&empty.0)?)?.is_empty());
    assert_eq!(tree(root)?, before);
    Ok(())
}

#[test]
fn bounded_reads_and_corrupt_excluded_receipts_never_return_partial_localizations() -> Test {
    let fixture = Fixture::new("localizations-cli-refusals")?;
    let root = fixture.root();
    let before = tree(root)?;
    let limited = cli(root, &[("--max-query-read-objects", "1")])?;
    assert_eq!(limited.1, ExitIdentity::AGENT_REFUSED);
    same_mcp(root, r#", "max_query_read_objects":"1""#, &limited)?;
    payload_free_refusal(&limited)?;
    let index_limit = cli(
        root,
        &[
            ("--max-query-results", "1"),
            ("--sensor", "sensor:not-retained"),
        ],
    )?;
    assert_eq!(index_limit.1, ExitIdentity::AGENT_REFUSED);
    same_mcp(
        root,
        r#", "max_query_results":"1", "sensor":"sensor:not-retained""#,
        &index_limit,
    )?;
    payload_free_refusal(&index_limit)?;
    assert_eq!(tree(root)?, before);

    let receipt = fixture.records.last().ok_or("retained receipt")?.receipt;
    fs::write(
        fixture.object_path(receipt),
        b"corrupt excluded localization receipt",
    )?;
    let damaged = tree(root)?;
    let refused = cli(root, &[("--sensor", "sensor:not-retained")])?;
    assert_eq!(refused.1, ExitIdentity::AGENT_REFUSED);
    same_mcp(root, r#", "sensor":"sensor:not-retained""#, &refused)?;
    payload_free_refusal(&refused)?;
    assert_eq!(tree(root)?, damaged);
    Ok(())
}

#[test]
fn closed_localization_grammar_rejects_mutations_scope_overrides_and_widened_bounds() -> Test {
    let fixture = Fixture::new("localizations-cli-closed-grammar")?;
    let root = fixture.root();
    let before = tree(root)?;
    assert!(matches!(
        parse_fss_args(args(root, &[]))?,
        FssCommand::LocalizationsQuery(_)
    ));
    for (flag, value) in [
        ("--family", "package_zone_report"),
        ("--from-ns", "0"),
        ("--at", "latest"),
        ("--sensor", "sensor invalid"),
        ("--stream", ""),
        ("--import-id", "sha256:invalid"),
        ("--twin-digest", "sha256:invalid"),
        ("--max-entries", "33"),
        ("--max-query-read-bytes", "268435457"),
        ("--max-query-read-objects", "65537"),
        ("--max-query-results", "1025"),
        ("--report-digest", "sha256:invalid"),
        ("--execute-perception", "yes"),
        ("--retain-result", "yes"),
        ("--continuation", "continuation:INVALID"),
    ] {
        assert!(
            parse_fss_args(args(root, &[(flag, value)])).is_err(),
            "{flag}"
        );
    }
    for extra in [
        r#", "root":"/another-deployment""#,
        r#", "principal":"principal:another-reader""#,
        r#", "execute_perception":true"#,
        r#", "retain_result":true"#,
        r#", "verify_source":true"#,
        r#", "hydrate":"H3""#,
        r#", "sources":[]"#,
        r#", "family":"package_zone_report""#,
        r#", "from_ns":"0""#,
        r#", "import_id":"sha256:invalid""#,
        r#", "twin_digest":"sha256:invalid""#,
        r#", "max_entries":"1""#,
        r#", "max_entries":1.0"#,
        r#", "max_query_read_objects":1"#,
        r#", "max_query_results":"1025""#,
    ] {
        assert!(field(&mcp(root, extra)?, "error").is_ok(), "{extra}");
    }
    assert_eq!(tree(root)?, before);
    Ok(())
}
