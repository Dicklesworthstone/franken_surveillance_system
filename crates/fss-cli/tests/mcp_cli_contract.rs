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

/// Tokens have no JSON escapes. Validate the extracted token with the actual semantic parser.
fn orientation_anchor(envelope: &str) -> TestResult<&str> {
    let start = envelope
        .find("\"anchor:")
        .ok_or("orientation emitted no anchor token")?
        + 1;
    let tail = &envelope[start..];
    let end = tail.find('"').ok_or("unterminated anchor token")?;
    let token = &tail[..end];
    if fss_reference::agent_follow::AnchorToken::parse(token).is_none() {
        return Err("orientation emitted malformed anchor token".into());
    }
    Ok(token)
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
