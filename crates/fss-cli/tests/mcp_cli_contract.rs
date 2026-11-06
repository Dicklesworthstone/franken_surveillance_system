#![forbid(unsafe_code)]
//! Cross-surface checks against a real reference deployment and the actual MCP executable.
//! The transport must return the exact CLI semantic bytes and leave the deployment unchanged.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use fss_cli::{ExitIdentity, escape_json_str, execute_fss_with_exit, parse_fss_args};
use fss_core::{ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"contract-test","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

struct Directory(PathBuf);

impl Directory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir()
                .join(format!("fss-mcp-{name}-{}-{attempt}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory capacity".into())
    }

    fn deployment(&self) -> TestResult<PathBuf> {
        let root = self.0.join("deployment");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:mcp-contract".to_owned(),
            operation_id: OperationId::parse("operation:mcp-contract")?,
            principal: "operator:mcp-contract".to_owned(),
            capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
            deadline: None,
            priority: 10,
            budgets: fss_core::BudgetVector::default(),
            privacy_scope: "privacy:internal".to_owned(),
            retention_scope: "retention:ephemeral".to_owned(),
            anchor_universe: ContentDigest::sha256(b"mcp-contract"),
            generation: 1,
        })?;
        let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
            &authority,
            self.0.join("cx"),
        )?);
        drop(ReferenceDeployment::open(&root, "site:mcp-contract", &cx)?);
        Ok(root.canonicalize()?)
    }

    /// Synthetic source bytes exercise retained-capsule custody and pagination only.
    /// Declared capture times do not establish UTC alignment or physical coverage.
    fn import_footage(&self, root: &Path) -> TestResult {
        let config = JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        };
        let mut recording = Vec::new();
        for value in [24_u8, 80, 144] {
            recording.extend(encode_jpeg(96, 48, &vec![value; 96 * 48], &config)?);
        }
        let input = self.0.join("retained-footage.mjpeg");
        fs::write(&input, recording)?;
        let output = Command::new(env!("CARGO_BIN_EXE_fss-file"))
            .args(["import", "--root"])
            .arg(root)
            .args(["--site", "site:mcp-contract", "--input"])
            .arg(input)
            .args(["--sensor", "sensor:mcp-footage", "--stream", "stream:main"])
            .args([
                "--media-format",
                "mjpeg",
                "--receive-time-ns",
                "10000000000000",
                "--capture-start-ns",
                "1000000000",
                "--capture-uncertainty-ns",
                "1000000",
                "--assumed-fps",
                "10",
            ])
            .output()?;
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn quote(text: &str) -> String {
    format!("\"{}\"", escape_json_str(text))
}

fn call(id: u64, name: &str, arguments: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":{},"arguments":{arguments}}}}}"#,
        quote(name)
    )
}

fn cli(root: &Path, command: &str, extra: &[&str]) -> TestResult<(String, ExitIdentity)> {
    let mut args: Vec<OsString> = vec![
        command.into(),
        "--json".into(),
        "--root".into(),
        root.as_os_str().to_owned(),
    ];
    args.extend(extra.iter().map(OsString::from));
    Ok(execute_fss_with_exit(parse_fss_args(args)?))
}

fn exchange(root: &Path, requests: &str) -> TestResult<Output> {
    let mut process = Command::new(env!("CARGO_BIN_EXE_fss-mcp"))
        .arg("--root")
        .arg(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut input = process.stdin.take().ok_or("missing stdin")?;
    input.write_all(requests.as_bytes())?;
    drop(input);
    Ok(process.wait_with_output()?)
}

/// File bytes and directory membership, excluding read-induced access timestamps.
fn snapshot(root: &Path) -> TestResult<BTreeMap<PathBuf, (bool, Vec<u8>)>> {
    let mut pending = vec![root.to_path_buf()];
    let mut result = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path.strip_prefix(root)?.to_path_buf();
        if metadata.is_dir() {
            result.insert(relative, (true, Vec::new()));
            for entry in fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        } else if metadata.is_file() {
            result.insert(relative, (false, fs::read(path)?));
        } else {
            return Err("unexpected special file in reference fixture".into());
        }
    }
    Ok(result)
}

/// Tokens have no JSON escapes. Returns the first `"anchor:` string that the actual semantic
/// parser accepts: other orient fields (the registered anchor projection) also begin with
/// `anchor:`, so the first textual match is not necessarily the follow token.
fn orientation_anchor(envelope: &str) -> TestResult<&str> {
    let mut rest = envelope;
    let mut offset = 0;
    while let Some(found) = rest.find("\"anchor:") {
        let start = offset + found + 1;
        let tail = &envelope[start..];
        let end = tail.find('"').ok_or("unterminated anchor token")?;
        let token = &tail[..end];
        if fss_reference::agent_follow::AnchorToken::parse(token).is_some() {
            return Ok(token);
        }
        offset = start + end;
        rest = &envelope[offset..];
    }
    Err("orientation emitted no well-formed anchor token".into())
}

#[test]
fn actual_stdio_reads_match_cli_and_leave_all_deployment_bytes_unchanged() -> TestResult {
    let directory = Directory::new("parity")?;
    let root = directory.deployment()?;
    let before = snapshot(&root)?;
    let orient = cli(&root, "orient", &["--view", "pulse"])?;
    let anchor = orientation_anchor(&orient.0)?;
    let follow = cli(&root, "follow", &["--since", anchor, "--max-entries", "1"])?;
    let explain = cli(&root, "explain", &["--event-id", "event:missing"])?;
    let doctor = cli(&root, "doctor", &[])?;
    let requests = format!(
        "{INIT}\n{READY}\n{}\n{}\n{}\n{}\n",
        call(2, "session_orient", r#"{"view":"pulse"}"#),
        call(
            3,
            "session_follow",
            &format!(r#"{{"since":{},"max_entries":1}}"#, quote(anchor))
        ),
        call(4, "explain", r#"{"event_id":"event:missing"}"#),
        call(5, "doctor", "{}")
    );
    let output = exchange(&root, &requests)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout)?;
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(
        lines.len(),
        5,
        "one initialize response and four tool responses; no notification reply"
    );
    for (line, (semantic, exit)) in lines.iter().skip(1).zip([orient, follow, explain, doctor]) {
        // Exact text equality after MCP string encoding, not an approximation of selected fields.
        assert!(
            line.contains(&format!("\"text\":{}", quote(&semantic))),
            "{line}"
        );
        assert!(line.contains(&format!("\"isError\":{}", exit.code != 0)));
    }
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn retained_footage_pages_and_cursor_refusals_match_cli_without_writes() -> TestResult {
    use fss_cli::json_input::{Value, parse};

    fn privacy_domains(envelope: &Value) -> TestResult<(&[Value], &[Value])> {
        let projection = envelope
            .object()
            .and_then(|value| value.get("effectivePrivacyProjection"))
            .and_then(Value::object)
            .ok_or("effective privacy projection")?;
        Ok((
            projection
                .get("allowedDomains")
                .and_then(Value::array)
                .ok_or("allowed data domains")?,
            projection
                .get("redactedDomains")
                .and_then(Value::array)
                .ok_or("redacted data domains")?,
        ))
    }

    let directory = Directory::new("footage-parity")?;
    let root = directory.deployment()?;
    directory.import_footage(&root)?;
    let before = snapshot(&root)?;
    let mut requests = format!("{INIT}\n{READY}\n");
    let mut expected = Vec::new();
    let mut continuation: Option<String> = None;
    let mut first_cursor = None;
    for id in 2..6 {
        let mut extra = vec![
            "--target",
            "footage",
            "--sensor",
            "sensor:mcp-footage",
            "--stream",
            "stream:main",
            "--from-ns",
            "0",
            "--through-ns",
            "2000000000",
            "--max-entries",
            "1",
        ];
        let cursor_argument = if let Some(cursor) = continuation.as_deref() {
            extra.extend(["--continuation", cursor]);
            format!(",\"continuation\":{}", quote(cursor))
        } else {
            String::new()
        };
        let response = cli(&root, "query", &extra)?;
        let envelope = parse(&response.0)?;
        let (allowed, redacted) = privacy_domains(&envelope)?;
        for domain in ["retained-import-metadata", "sensor-capsule-metadata"] {
            assert!(allowed.iter().any(|value| value.text() == Some(domain)));
        }
        assert!(
            redacted
                .iter()
                .any(|value| value.text() == Some("media-payloads"))
        );
        let next = envelope
            .object()
            .ok_or("query envelope")?
            .get("continuation")
            .ok_or("query continuation field")?;
        continuation = match next {
            Value::Null => None,
            Value::Text(token) => Some(token.clone()),
            _ => return Err("unexpected query continuation type".into()),
        };
        if id == 2 {
            first_cursor.clone_from(&continuation);
        }
        requests.push_str(&call(
            id,
            "query",
            &format!(
                r#"{{"target":"footage","sensor":"sensor:mcp-footage","stream":"stream:main","from_ns":"0","through_ns":"2000000000","max_entries":1{cursor_argument}}}"#
            ),
        ));
        requests.push('\n');
        expected.push(response);
        if continuation.is_none() {
            break;
        }
    }
    assert_eq!(expected.len(), 3, "one retained frame per bounded page");
    assert!(
        continuation.is_none(),
        "last page must exhaust the selection"
    );
    let first_cursor = first_cursor.ok_or("missing bounded-page continuation")?;

    // The same cursor cannot cross query targets or silently change its source predicate.
    for (target, sensor) in [("events", None), ("footage", Some("sensor:other"))] {
        let mut extra = vec![
            "--target",
            target,
            "--max-entries",
            "1",
            "--continuation",
            &first_cursor,
        ];
        let source_arguments = if let Some(sensor) = sensor {
            extra.extend([
                "--sensor",
                sensor,
                "--stream",
                "stream:main",
                "--from-ns",
                "0",
                "--through-ns",
                "2000000000",
            ]);
            format!(
                r#", "sensor":{}, "stream":"stream:main", "from_ns":"0", "through_ns":"2000000000""#,
                quote(sensor)
            )
        } else {
            String::new()
        };
        let response = cli(&root, "query", &extra)?;
        assert_ne!(
            response.1.code, 0,
            "a changed cursor binding must be refused"
        );
        requests.push_str(&call(
            expected.len() as u64 + 2,
            "query",
            &format!(
                r#"{{"target":{},"max_entries":1,"continuation":{}{source_arguments}}}"#,
                quote(target),
                quote(&first_cursor)
            ),
        ));
        requests.push('\n');
        expected.push(response);
    }
    // The new target declares its additional metadata domains without extending events.
    let events = cli(&root, "query", &[])?;
    let event_envelope = parse(&events.0)?;
    let (allowed, redacted) = privacy_domains(&event_envelope)?;
    for domain in ["retained-import-metadata", "sensor-capsule-metadata"] {
        assert!(!allowed.iter().any(|value| value.text() == Some(domain)));
    }
    assert!(
        redacted
            .iter()
            .any(|value| value.text() == Some("media-payloads"))
    );
    requests.push_str(&call(expected.len() as u64 + 2, "query", "{}"));
    requests.push('\n');
    expected.push(events);
    let output = exchange(&root, &requests)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout)?;
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), expected.len() + 1);
    for (line, (semantic, exit)) in lines.iter().skip(1).zip(expected) {
        assert!(
            line.contains(&format!("\"text\":{}", quote(&semantic))),
            "{line}"
        );
        assert!(line.contains(&format!("\"isError\":{}", exit.code != 0)));
    }
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn a_wrong_stream_cursor_is_the_same_typed_refusal_over_mcp() -> TestResult {
    let directory = Directory::new("cursor")?;
    let root = directory.deployment()?;
    let before = snapshot(&root)?;
    let (orientation, _) = cli(&root, "orient", &[])?;
    let anchor = orientation_anchor(&orientation)?;
    let cursor = "continuation:unknown-stream";
    let (expected, exit) = cli(
        &root,
        "follow",
        &["--since", anchor, "--continuation", cursor],
    )?;
    assert_ne!(exit.code, 0);
    assert!(expected.contains("ERR-AGENT-FOLLOW-CONTINUATION-001"));
    let args = format!(
        r#"{{"since":{},"continuation":{}}}"#,
        quote(anchor),
        quote(cursor)
    );
    let output = exchange(
        &root,
        &format!("{INIT}\n{READY}\n{}\n", call(2, "session_follow", &args)),
    )?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains(&format!("\"text\":{}", quote(&expected))));
    assert!(text.contains("\"isError\":true"));
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn notifications_scope_overrides_and_mutations_do_not_modify_the_root() -> TestResult {
    let directory = Directory::new("authority")?;
    let root = directory.deployment()?;
    let before = snapshot(&root)?;
    let requests = format!(
        "{INIT}\n{READY}\n{}\n{}\n{}\n{}\n",
        r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"session_orient"}}"#,
        call(2, "commit", "{}"),
        call(3, "session_open", r#"{"mission":"mutate"}"#),
        call(4, "doctor", r#"{"root":"/other"}"#)
    );
    let output = exchange(&root, &requests)?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert_eq!(text.lines().count(), 4);
    assert_eq!(text.matches("-32602").count(), 3);
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}
