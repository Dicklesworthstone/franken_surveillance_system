#![forbid(unsafe_code)]
//! Real executable parity and read-only query checks over retained reference deployments.
//! Generated recordings exercise wiring only; they establish no detector-quality claim.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use fss_cli::{ExitIdentity, escape_json_str, execute_fss_with_exit, parse_fss_args};
use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_reference::agent_orient::{OrientLimits, read_deployment};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:query-surface";
const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"query-contract","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

struct Fixture {
    directory: PathBuf,
    root: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> TestResult<Self> {
        for attempt in 0..100 {
            let directory = std::env::temp_dir().join(format!(
                "fss-query-surface-{tag}-{}-{attempt}", std::process::id()
            ));
            match fs::create_dir(&directory) {
                Ok(()) => {
                    let fixture = Self { root: directory.join("deployment"), directory };
                    let authority = ContextAuthority::new_root(RootAuthoritySpec {
                        trace_id: "trace:query-surface".to_owned(),
                        operation_id: OperationId::parse("operation:query-surface")?,
                        principal: "operator:query-surface".to_owned(),
                        capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
                        deadline: None, priority: 10, budgets: BudgetVector::default(),
                        privacy_scope: "privacy:internal".to_owned(),
                        retention_scope: "retention:ephemeral".to_owned(),
                        anchor_universe: ContentDigest::sha256(b"query-surface"), generation: 1,
                    })?;
                    let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
                        &authority, fixture.directory.join("cx"),
                    )?);
                    drop(ReferenceDeployment::open(&fixture.root, SITE, &cx)?);
                    return Ok(fixture);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("query fixture directory capacity".into())
    }

    fn publish(&self, sensor: &str) -> TestResult<String> {
        let config = JpegConfig {
            quality: 90, subsampling: Subsampling::Grayscale,
            restart_interval: 0, custom_markers: Vec::new(),
        };
        let mut recording = Vec::new();
        for index in 0..14_usize {
            let mut pixels = vec![40_u8; 96 * 48];
            if index >= 3 {
                let left = (index - 3) * 8;
                for y in 8..24 {
                    for x in left..left + 16 { pixels[y * 96 + x] = 220; }
                }
            }
            recording.extend(encode_jpeg(96, 48, &pixels, &config)?);
        }
        let input = self.directory.join(format!("{}.mjpeg", sensor.replace(':', "-")));
        fs::write(&input, recording)?;
        let imported = Command::new(env!("CARGO_BIN_EXE_fss-file"))
            .args(["import", "--root"]).arg(&self.root)
            .args(["--site", SITE, "--input"]).arg(&input)
            .args(["--sensor", sensor, "--stream", &format!("stream:{sensor}")])
            .args(["--media-format", "mjpeg", "--receive-time-ns", "10000000000000"])
            .args(["--capture-start-ns", "1000000000", "--capture-uncertainty-ns", "1000000"])
            .args(["--assumed-fps", "10"]).output()?;
        success(&imported);
        let imported = String::from_utf8(imported.stdout)?;
        let identity = imported.lines().find_map(|line| line.strip_prefix("import_identity="))
            .ok_or("missing import identity")?;
        let watch = |approval: Option<&str>| -> TestResult<Output> {
            let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
            command.args(["watch", "--root"]).arg(&self.root)
                .args(["--site", SITE, "--import-id", identity, "--interpretation", "gray"])
                .args(["--zone", "door:64,0,32,32"]);
            if let Some(approval) = approval { command.args(["--approve", approval]); }
            Ok(command.output()?)
        };
        let prepared = watch(None)?;
        success(&prepared);
        let prepared = String::from_utf8(prepared.stdout)?;
        let proposal = quoted_field(&prepared, "proposal_digest")?;
        let published = watch(Some(&proposal))?;
        success(&published);
        quoted_field(&String::from_utf8(published.stdout)?, "event_id")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.directory); }
}

fn success(output: &Output) {
    assert!(output.status.success(), "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}

fn quote(value: &str) -> String { format!("\"{}\"", escape_json_str(value)) }

// Used only for digests, tokens and fixture event IDs, whose alphabets exclude JSON escapes.
fn quoted_field(text: &str, field: &str) -> TestResult<String> {
    let marker = format!("\"{field}\":\"");
    let start = text.find(&marker).ok_or_else(|| format!("missing {field}"))? + marker.len();
    let value = text[start..].split('"').next().ok_or("unterminated token")?;
    if value.contains('\\') { return Err("unexpected escaped token".into()); }
    Ok(value.to_owned())
}

fn tree(root: &Path) -> TestResult<BTreeMap<PathBuf, (bool, Vec<u8>)>> {
    let mut pending = vec![root.to_path_buf()];
    let mut result = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path.strip_prefix(root)?.to_path_buf();
        if metadata.is_dir() {
            result.insert(relative, (true, Vec::new()));
            for entry in fs::read_dir(path)? { pending.push(entry?.path()); }
        } else if metadata.is_file() {
            result.insert(relative, (false, fs::read(path)?));
        } else { return Err("special file in reference fixture".into()); }
    }
    Ok(result)
}

fn query(root: &Path, extra: &[&str]) -> TestResult<(String, ExitIdentity)> {
    let mut args: Vec<OsString> = vec!["query".into(), "--json".into(), "--root".into(), root.as_os_str().to_owned()];
    args.extend(extra.iter().map(OsString::from));
    let expected = execute_fss_with_exit(parse_fss_args(args.clone())?);
    let output = Command::new(env!("CARGO_BIN_EXE_fss")).args(args).output()?;
    assert_eq!(output.status.code(), Some(i32::from(expected.1.code)));
    assert_eq!(String::from_utf8(output.stdout)?, format!("{}\n", expected.0));
    assert!(output.stderr.is_empty());
    Ok(expected)
}

fn mcp(root: &Path, arguments: &str, expected: &(String, ExitIdentity)) -> TestResult {
    let request = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"query","arguments":{arguments}}}}}"#
    );
    let mut process = Command::new(env!("CARGO_BIN_EXE_fss-mcp"))
        .arg("--root").arg(root).stdin(Stdio::piped()).stdout(Stdio::piped())
        .stderr(Stdio::piped()).spawn()?;
    let mut stdin = process.stdin.take().ok_or("missing stdin")?;
    writeln!(stdin, "{INIT}\n{READY}\n{request}")?;
    drop(stdin);
    let output = process.wait_with_output()?;
    success(&output);
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout)?;
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[1].contains(&format!("\"text\":{}", quote(&expected.0))));
    assert!(lines[1].contains(&format!("\"isError\":{}", expected.1.code != 0)));
    Ok(())
}

fn conforms(fixture: &Fixture, answer: &str) -> TestResult {
    let repo = std::env::var_os("CARGO_MANIFEST_DIR")
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from).join("../..");
    let start = answer.find(",\"payload\":").ok_or("missing payload")? + ",\"payload\":".len();
    let end = answer.find(",\"payloadDigest\":").ok_or("missing payload digest")?;
    let payload = &answer[start..end];
    for (schema, instance) in [
        ("agent_response_envelope.v1.json", answer),
        ("agent_cognitive_envelope.v1.json", payload),
    ] {
        if instance == "null" { continue; }
        let path = fixture.directory.join(format!("{schema}.instance.json"));
        fs::write(&path, instance)?;
        let output = Command::new("python3").arg("-B").arg(repo.join("scripts/json_instance_validate.py"))
            .arg(repo.join("schemas").join(schema)).arg(path).output()?;
        success(&output);
    }
    Ok(())
}

#[test]
fn real_empty_catalogue_and_native_refusal_match_every_surface() -> TestResult {
    let fixture = Fixture::new("empty")?;
    let before = tree(&fixture.root)?;
    let answer = query(&fixture.root, &[])?;
    assert_eq!(answer.1, ExitIdentity::SUCCESS);
    assert!(answer.0.contains("committed_index_exhausted"));
    assert!(answer.0.contains("claim:query:physical-absence"));
    assert!(answer.0.contains("not_observable"));
    conforms(&fixture, &answer.0)?;
    mcp(&fixture.root, "{}", &answer)?;
    let refused = query(&fixture.root, &["--continuation", "continuation:wrong-stream"])?;
    assert_eq!(refused.1, ExitIdentity::AGENT_REFUSED);
    assert!(refused.0.contains("continuation_wrong_stream"));
    conforms(&fixture, &refused.0)?;
    mcp(&fixture.root, r#"{"continuation":"continuation:wrong-stream"}"#, &refused)?;
    assert_eq!(tree(&fixture.root)?, before);
    Ok(())
}

#[test]
fn published_recordings_query_exactly_and_paginate_without_changing_custody() -> TestResult {
    let fixture = Fixture::new("recordings")?;
    let first_id = fixture.publish("sensor:query-east")?;
    let second_id = fixture.publish("sensor:query-west")?;
    assert_ne!(first_id, second_id);
    let snapshot = read_deployment(&fixture.root, &OrientLimits::default())?;
    assert_eq!(snapshot.events.len(), 2);
    let before = tree(&fixture.root)?;
    let page_one = query(&fixture.root, &["--max-entries", "1"])?;
    assert_eq!(page_one.1, ExitIdentity::SUCCESS);
    conforms(&fixture, &page_one.0)?;
    mcp(&fixture.root, r#"{"max_entries":1}"#, &page_one)?;
    let cursor = quoted_field(&page_one.0, "continuation")?;
    let page_two = query(&fixture.root, &["--max-entries", "1", "--continuation", &cursor])?;
    assert_eq!(page_two.1, ExitIdentity::SUCCESS);
    conforms(&fixture, &page_two.0)?;
    mcp(&fixture.root, &format!(r#"{{"max_entries":1,"continuation":{}}}"#, quote(&cursor)), &page_two)?;
    for id in [&first_id, &second_id] {
        let proposition = format!("\"id\":{}", quote(id));
        assert_eq!(page_one.0.matches(&proposition).count() + page_two.0.matches(&proposition).count(), 1);
    }
    assert!(page_two.0.contains("\"continuation\":null"));
    let changed = query(&fixture.root, &["--max-entries", "2", "--continuation", &cursor])?;
    assert_eq!(changed.1, ExitIdentity::AGENT_REFUSED);
    let row = snapshot.events.iter().find(|row| row.event.event_id.as_str() == first_id).ok_or("missing published record")?;
    let endpoint = row.event.interval.latest.0.to_string();
    let matching = query(&fixture.root, &["--event-id", &first_id, "--from-ns", &endpoint, "--through-ns", &endpoint])?;
    assert_eq!(matching.1, ExitIdentity::SUCCESS);
    assert!(matching.0.contains(&format!("\"id\":{}", quote(&first_id))));
    let outside = row.event.interval.latest.0.checked_add(1).ok_or("fixture time overflow")?.to_string();
    let empty = query(&fixture.root, &["--event-id", &first_id, "--from-ns", &outside])?;
    assert_eq!(empty.1, ExitIdentity::SUCCESS);
    assert!(!empty.0.contains(&format!("\"id\":{}", quote(&first_id))));
    assert!(empty.0.contains("claim:query:physical-absence"));
    assert_eq!(tree(&fixture.root)?, before);
    Ok(())
}
