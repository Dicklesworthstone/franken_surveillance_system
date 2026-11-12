#![forbid(unsafe_code)]
//! Native imports remain discoverable through the canonical metadata transports offline.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use fss_cli::json_input::{Value, parse};
use fss_reference::ingest::rtsp_import::RtspImportCodec;

use super::support::{Fixture, Test, approve, field, good, run, serial};

fn snapshot(root: &Path) -> Test<BTreeMap<PathBuf, (bool, Vec<u8>)>> {
    let mut pending = vec![root.to_path_buf()];
    let mut result = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path.strip_prefix(root)?.to_path_buf();
        if metadata.is_dir() {
            result.insert(relative, (true, Vec::new()));
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
        } else if metadata.is_file() {
            result.insert(relative, (false, fs::read(path)?));
        } else {
            return Err("unexpected special file in fixture".into());
        }
    }
    Ok(result)
}

fn mcp(root: &Path) -> Test<String> {
    const REQUESTS: &str = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"native-footage-contract\",\"version\":\"1\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"query\",\"arguments\":{\"target\":\"footage\",\"max_entries\":1}}}\n",
    );
    let mut process = Command::new(env!("CARGO_BIN_EXE_fss-mcp"))
        .arg("--root")
        .arg(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut input = process.stdin.take().ok_or("missing MCP input")?;
    input.write_all(REQUESTS.as_bytes())?;
    drop(input);
    let output = process.wait_with_output()?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout)?;
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 2, "initialize and one query response");
    let response = parse(lines[1])?;
    let result = response
        .object()
        .and_then(|value| value.get("result"))
        .and_then(Value::object)
        .ok_or("MCP query result")?;
    assert_eq!(result.get("isError"), Some(&Value::Bool(false)));
    let content = result
        .get("content")
        .and_then(Value::array)
        .ok_or("MCP result content")?;
    assert_eq!(content.len(), 1);
    Ok(field(&content[0], "text")?.to_owned())
}

#[test]
fn native_replay_metadata_matches_real_cli_and_mcp_after_archive_goes_offline() -> Test {
    let _serial = serial();
    for codec in [RtspImportCodec::Avc, RtspImportCodec::Hevc] {
        let fixture = Fixture::new(codec, 1, 0)?;
        let mut args = fixture.args()?;
        approve(&mut args)?;
        let imported = parse(&good(run(&args)?)?)?;
        let identity = field(&imported, "import_identity")?;
        let origin = field(&imported, "origin_proof")?;
        fs::rename(
            fixture.archive(),
            fixture.directory.0.join("offline archive"),
        )?;
        let before = snapshot(&fixture.target())?;

        let output = Command::new(env!("CARGO_BIN_EXE_fss"))
            .args(["query", "--json", "--target", "footage", "--root"])
            .arg(fixture.target())
            .args(["--max-entries", "1"])
            .output()?;
        let cli = good(output)?;
        parse(&cli)?;
        for expected in [
            "adapter_id=ADP-RTSP-REPLAY-ARCHIVE-001".to_owned(),
            format!("import_identity={identity}"),
            format!("declared_origin_digest={origin}"),
            "adapter_origin_verification=not_performed".to_owned(),
            "source_payload_availability=unknown".to_owned(),
            "capture_time_label=unknown".to_owned(),
        ] {
            assert!(cli.contains(&expected), "missing {expected}: {cli}");
        }
        assert_eq!(mcp(&fixture.target())?, cli.trim_end_matches('\n'));
        assert_eq!(snapshot(&fixture.target())?, before);
    }
    Ok(())
}
