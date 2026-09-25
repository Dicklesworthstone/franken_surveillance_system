#![forbid(unsafe_code)]
//! Real binaries compose hold preview/commit/release with the existing deletion command.

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::{FileFormatHint, FileIngestAdapter, FileIngestRequest};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const HOLD: &str = env!("CARGO_BIN_EXE_fss-hold");
const EVENT: &str = env!("CARGO_BIN_EXE_fss-event");
const SITE: &str = "site:hold-cli";

struct Directory(PathBuf);
impl Directory {
    fn new() -> TestResult<Self> {
        for n in 0..100 {
            let path = std::env::temp_dir().join(format!("fss-hold-cli-{}-{n}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

fn success(output: Output) -> TestResult<String> {
    if !output.status.success() {
        return Err(format!("command refused: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn approval(json: &str) -> TestResult<String> {
    let marker = "\"approval_digest\":\"";
    if json.matches(marker).count() != 1 { return Err("expected one approval digest".into()); }
    let value = json.split_once(marker).ok_or("missing approval")?.1
        .split('"').next().ok_or("unterminated approval")?;
    Ok(ContentDigest::parse(value)?.to_text())
}

#[test]
fn binary_hold_release_and_deletion_preview_share_authority() -> TestResult {
    let directory = Directory::new()?;
    let root = directory.0.join("deployment");
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:hold-cli".into(), operation_id: OperationId::parse("operation:hold-cli")?,
        principal: "principal:local-operator".into(), capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None, priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).storage_operations(8192).build()?,
        privacy_scope: "privacy:test".into(), retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()), generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let path = directory.0.join("source.mjpeg");
    fs::write(&path, encode_jpeg(16, 16, &[40; 256], &JpegConfig {
        quality: 90, subsampling: Subsampling::Grayscale, restart_interval: 0, custom_markers: Vec::new(),
    })?)?;
    let request = FileIngestRequest::new(path, SensorId::parse("sensor:hold-cli")?, StreamId::parse("stream:hold-cli")?)
        .with_receive_time(TimestampNs(1_000_000_000)).with_format_hint(FileFormatHint::JpegStream);
    let import = FileIngestAdapter::ingest(request, &cx, &mut deployment)?.import_identity.to_text();
    drop(deployment);
    let hold = |action: &str, approval: Option<&str>| -> TestResult<String> {
        let mut command = Command::new(HOLD);
        command.arg(action).arg("--root").arg(&root).args(["--site", SITE,
            "--hold-id", "incident", "--import-id", &import, "--reason", "Owner incident review"]);
        if let Some(digest) = approval { command.args(["--approve", digest]); }
        success(command.output()?)
    };
    let preview = hold("place", None)?;
    assert!(preview.contains("\"status\":\"proposed\""));
    let place = approval(&preview)?;
    assert!(hold("place", Some(&place))?.contains("\"status\":\"committed\""));
    assert!(hold("place", Some(&place))?.contains("\"status\":\"already_current\""));
    let listed = success(Command::new(HOLD).arg("list").arg("--root").arg(&root).args(["--site", SITE]).output()?)?;
    assert!(listed.contains("\"active_holds\":1"));
    let deletion = || -> TestResult<String> {
        success(Command::new(EVENT).args(["delete", "plan"]).arg("--root").arg(&root)
            .args(["--site", SITE, "--import-id", &import]).output()?)
    };
    let blocked = deletion()?;
    assert!(blocked.contains("\"kind\":\"evidence_hold\""));
    assert!(blocked.contains("enforced_import_closure_v1"));
    let release = approval(&hold("release", None)?)?;
    assert_ne!(place, release);
    assert!(hold("release", Some(&release))?.contains("\"state\":\"released\""));
    assert!(!deletion()?.contains("\"kind\":\"evidence_hold\""));
    let listed = success(Command::new(HOLD).arg("list").arg("--root").arg(&root).args(["--site", SITE]).output()?)?;
    assert!(listed.contains("\"active_holds\":0"));
    assert!(listed.contains("\"state\":\"released\""));
    Ok(())
}

#[test]
fn malformed_cli_does_not_create_a_deployment() -> TestResult {
    let directory = Directory::new()?;
    let absent = directory.0.join("not-a-deployment");
    let output = Command::new(HOLD).arg("place").arg("--root").arg(&absent)
        .args(["--site", SITE, "--hold-id", "incident", "--import-id", "bad", "--reason", "Preserve"])
        .output()?;
    assert!(!output.status.success());
    assert!(!absent.exists());
    let output = Command::new(HOLD).arg("list").arg("--root").arg(&absent).args(["--site", SITE]).output()?;
    assert!(!output.status.success());
    assert!(!absent.exists());
    Ok(())
}
