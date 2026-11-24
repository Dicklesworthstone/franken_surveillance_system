#![forbid(unsafe_code)]
//! Real-process contract tests for the unified `fss <domain> <verb>` CLI grammar, universal
//! `--help`/`-h` support, `fss-hold` canonical `prefix:id` + legacy IDs + top-level approval
//! preview keys, `fss-file import --json`, and automated ergonomics linter (`fss-x4a.31.5.4`).

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use fss_cli::unified::{UNIFIED_DOMAINS, lint_unified_cli_surface};
use fss_core::json_input::{Value, parse as parse_json};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const FSS: &str = env!("CARGO_BIN_EXE_fss");
const HOLD: &str = env!("CARGO_BIN_EXE_fss-hold");
const FILE: &str = env!("CARGO_BIN_EXE_fss-file");
const BACKUP: &str = env!("CARGO_BIN_EXE_fss-backup");
const SITE: &str = "site:unified-cli-contract";

struct TempWorkspace(PathBuf);

impl TempWorkspace {
    fn new(tag: &str) -> TestResult<Self> {
        for attempt in 0..200 {
            let path = std::env::temp_dir().join(format!(
                "fss-unified-cli-{tag}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("failed to allocate temp workspace".into())
    }

    fn init_deployment(&self, name: &str) -> TestResult<PathBuf> {
        let root = self.0.join(name);
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:unified-contract".into(),
            operation_id: OperationId::parse("operation:unified-contract")?,
            principal: "principal:local-operator".into(),
            capabilities: vec!["ADP-REPLAY-001".into()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(64 * 1024 * 1024)
                .storage_operations(8192)
                .build()?,
            privacy_scope: "privacy:test".into(),
            retention_scope: "retention:test".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        drop(deployment);
        cx.drain_and_finalize();
        Ok(root)
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn require_success(output: Output, label: &str) -> TestResult<String> {
    if !output.status.success() {
        return Err(format!(
            "{label} failed (code={:?}):\nstdout: {}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn write_test_jpeg(path: &PathBuf) -> TestResult<()> {
    let bytes = encode_jpeg(
        16,
        16,
        &[64; 256],
        &JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        },
    )?;
    fs::write(path, bytes)?;
    Ok(())
}

#[test]
fn every_unified_domain_verb_and_fss1_subcommand_accepts_help_and_exits_zero() -> TestResult {
    // 1. Every registered unified domain and every verb under it.
    for domain in UNIFIED_DOMAINS {
        for flag in ["--help", "-h"] {
            let stdout = require_success(
                Command::new(FSS).args([domain.name, flag]).output()?,
                &format!("fss {} {flag}", domain.name),
            )?;
            assert!(
                stdout.contains("USAGE:"),
                "fss {} {flag} missing USAGE:\n{stdout}",
                domain.name
            );
            assert!(
                stdout.contains("--json"),
                "fss {} {flag} missing --json:\n{stdout}",
                domain.name
            );
        }

        if domain.name == "migrate" {
            continue;
        }
        for verb in domain.verbs {
            let stdout = require_success(
                Command::new(FSS)
                    .args([domain.name, verb.verb, "--help"])
                    .output()?,
                &format!("fss {} {} --help", domain.name, verb.verb),
            )?;
            assert!(
                stdout.contains("USAGE:"),
                "fss {} {} --help missing USAGE:\n{stdout}",
                domain.name,
                verb.verb
            );
            assert!(
                stdout.contains("--help"),
                "fss {} {} --help missing --help:\n{stdout}",
                domain.name,
                verb.verb
            );
            assert!(
                stdout.contains("--json"),
                "fss {} {} --help missing --json:\n{stdout}",
                domain.name,
                verb.verb
            );
        }
    }

    // 2. Every canonical fss/1 top-level verb and nested session/site subcommand.
    let fss1_cases: &[&[&str]] = &[
        &["session", "--help"],
        &["session", "open", "--help"],
        &["session", "resume", "--help"],
        &["session", "orient", "--help"],
        &["session", "follow", "--help"],
        &["session", "handoff", "--help"],
        &["orient", "--help"],
        &["follow", "--help"],
        &["handoff", "--help"],
        &["query", "--help"],
        &["query", "--target", "events", "--help"],
        &["explain", "--help"],
        &["investigate", "--help"],
        &["plan", "--help"],
        &["commit", "--help"],
        &["wait", "--help"],
        &["cancel", "--help"],
        &["feedback", "--help"],
        &["doctor", "--help"],
        &["status", "--help"],
        &["capabilities", "--help"],
        &["version", "--help"],
        &["site", "--help"],
        &["site", "run", "--help"],
        &["site", "status", "--help"],
        &["site", "stop", "--help"],
        &["site", "validate", "--help"],
        &["site", "plan", "--help"],
        &["site", "probe", "--help"],
        &["site", "probe-file", "--help"],
        &["migrate", "--help"],
        &["negative-evidence", "--help"],
    ];

    for argv in fss1_cases {
        let stdout = require_success(
            Command::new(FSS).args(*argv).output()?,
            &format!("fss {}", argv.join(" ")),
        )?;
        assert!(
            stdout.contains("USAGE:"),
            "fss {} missing USAGE:\n{stdout}",
            argv.join(" ")
        );
    }

    // 3. Companion subcommand --help fixes on fss-file and fss-hold.
    for argv in [
        &["import", "--help"][..],
        &["decode", "-h"],
        &["verify", "--help"],
    ] {
        let stdout = require_success(
            Command::new(FILE).args(argv).output()?,
            &format!("fss-file {}", argv.join(" ")),
        )?;
        assert!(stdout.contains("USAGE:"));
        assert!(stdout.contains("--json"));
    }
    for argv in [
        &["--help"][..],
        &["place", "--help"],
        &["release", "--help"],
        &["list", "-h"],
    ] {
        let stdout = require_success(
            Command::new(HOLD).args(argv).output()?,
            &format!("fss-hold {}", argv.join(" ")),
        )?;
        assert!(stdout.contains("fss-hold"));
    }
    let backup_help = require_success(
        Command::new(BACKUP).args(["plan", "--help"]).output()?,
        "fss-backup plan --help",
    )?;
    assert!(backup_help.contains("fss-backup"));
    Ok(())
}

#[test]
fn live_unified_read_commands_execute_in_process_and_return_valid_envelopes() -> TestResult {
    let ws = TempWorkspace::new("live-reads")?;
    let root = ws.init_deployment("deploy")?;
    let root_str = root.to_string_lossy().into_owned();

    let cases: &[(&[&str], &str)] = &[
        (
            &["graph", "coverage", "--root", &root_str, "--json"],
            "fss.agent_ops_graph.v1",
        ),
        (
            &["graph", "claims", "--root", &root_str, "--json"],
            "fss.agent_ops_graph.v1",
        ),
        (
            &["graph", "failures", "--root", &root_str, "--json"],
            "fss.agent_ops_graph.v1",
        ),
        (
            &["graph", "obligations", "--root", &root_str, "--json"],
            "fss.agent_ops_graph.v1",
        ),
        (
            &["hold", "list", "--root", &root_str, "--json"],
            "fss.agent_ops_holds.v1",
        ),
        (
            &["privacy", "list", "--root", &root_str, "--json"],
            "fss.agent_ops_privacy_masks.v1",
        ),
        (
            &["camera", "list", "--root", &root_str, "--json"],
            "fss.agent_ops_cameras.v1",
        ),
    ];

    for (argv, expected_schema) in cases {
        let stdout = require_success(
            Command::new(FSS).args(*argv).output()?,
            &format!("fss {}", argv.join(" ")),
        )?;
        let doc = parse_json(stdout.trim())
            .map_err(|e| format!("invalid JSON for {argv:?}: {e}\n{stdout}"))?;
        let obj = doc.object().ok_or("expected JSON object")?;
        assert_eq!(
            obj.get("schema").and_then(Value::text),
            Some("fss.agent_response_envelope.v1"),
            "missing AgentResponseEnvelope schema for {argv:?}"
        );
        assert!(
            stdout.contains(expected_schema),
            "expected payload schema `{expected_schema}` for {argv:?}, got:\n{stdout}"
        );
    }

    // `fss fuse evaluate --root ... --json` without `--event-id` or `--query` fails closed inside
    // a valid `AgentResponseEnvelope` (`fss.agent_ops_fusion.v1`), never fabricating evidence.
    let fuse_out = Command::new(FSS)
        .args(["fuse", "evaluate", "--root", &root_str, "--json"])
        .output()?;
    assert!(!fuse_out.status.success());
    let fuse_stdout = String::from_utf8(fuse_out.stdout)?;
    let fuse_doc = parse_json(fuse_stdout.trim())?;
    let fuse_obj = fuse_doc.object().ok_or("expected JSON object for fuse")?;
    assert_eq!(
        fuse_obj.get("schema").and_then(Value::text),
        Some("fss.agent_response_envelope.v1")
    );
    assert_eq!(
        fuse_obj.get("payloadSchema").and_then(Value::text),
        Some("fss.agent_ops_fusion.v1")
    );
    assert_eq!(
        fuse_obj.get("outcome").and_then(Value::text),
        Some("refused")
    );

    // Archive-only capture command refuses `--root` to guarantee `--root` is never aliased to archive.
    let bad_rtsp = Command::new(FSS)
        .args(["camera", "capture-rtsp", "--root", &root_str])
        .output()?;
    assert!(!bad_rtsp.status.success());
    assert_eq!(bad_rtsp.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&bad_rtsp.stderr).contains("--archive"),
        "expected diagnostic directing user to --archive"
    );

    Ok(())
}

#[test]
fn fss_file_import_json_and_legacy_kv_and_unified_media_import() -> TestResult {
    let ws = TempWorkspace::new("file-json")?;
    let root = ws.init_deployment("deploy")?;
    let jpeg_path = ws.0.join("sample.mjpeg");
    write_test_jpeg(&jpeg_path)?;

    // 1. Direct `fss-file import --json` emits valid JSON (`fss.file_cli.v1`).
    let json_stdout = require_success(
        Command::new(FILE)
            .args([
                "import",
                "--root",
                &root.to_string_lossy(),
                "--site",
                SITE,
                "--input",
                &jpeg_path.to_string_lossy(),
                "--sensor",
                "sensor:front-door",
                "--stream",
                "stream:main",
                "--receive-time-ns",
                "1000000000",
                "--media-format",
                "mjpeg",
                "--json",
            ])
            .output()?,
        "fss-file import --json",
    )?;
    let doc = parse_json(json_stdout.trim())?;
    let obj = doc.object().ok_or("expected JSON object")?;
    assert_eq!(
        obj.get("schema").and_then(Value::text),
        Some("fss.file_cli.v1")
    );
    let import_id = obj
        .get("import_identity")
        .and_then(Value::text)
        .ok_or("missing import_identity")?
        .to_owned();
    assert!(import_id.starts_with("sha256:"));

    // 2. Default `fss-file import` (without `--json`) stays 100% backwards-compatible `key=value`.
    let kv_stdout = require_success(
        Command::new(FILE)
            .args([
                "import",
                "--root",
                &root.to_string_lossy(),
                "--site",
                SITE,
                "--input",
                &jpeg_path.to_string_lossy(),
                "--sensor",
                "sensor:front-door",
                "--stream",
                "stream:main",
                "--receive-time-ns",
                "1000000000",
                "--media-format",
                "mjpeg",
            ])
            .output()?,
        "fss-file import default kv",
    )?;
    assert!(kv_stdout.contains(&format!("import_identity={import_id}")));
    assert!(!kv_stdout.trim_start().starts_with('{'));

    // 3. Unified `fss media verify --root ... --import-id ... --json` delegates cleanly and
    // auto-resolves `--site` from the existing deployment root.
    let verify_stdout = require_success(
        Command::new(FSS)
            .args([
                "media",
                "verify",
                "--root",
                &root.to_string_lossy(),
                "--import-id",
                &import_id,
                "--json",
            ])
            .output()?,
        "fss media verify --json",
    )?;
    let verify_doc = parse_json(verify_stdout.trim())?;
    assert_eq!(
        verify_doc
            .object()
            .and_then(|o| o.get("import_identity"))
            .and_then(Value::text),
        Some(import_id.as_str())
    );
    Ok(())
}

#[test]
fn fss_hold_accepts_canonical_prefix_id_and_legacy_id_with_top_level_approval_keys() -> TestResult {
    let ws = TempWorkspace::new("hold-ids")?;
    let root = ws.init_deployment("deploy")?;
    let jpeg_path = ws.0.join("sample.mjpeg");
    write_test_jpeg(&jpeg_path)?;

    let import_out = require_success(
        Command::new(FILE)
            .args([
                "import",
                "--root",
                &root.to_string_lossy(),
                "--site",
                SITE,
                "--input",
                &jpeg_path.to_string_lossy(),
                "--sensor",
                "sensor:front-door",
                "--stream",
                "stream:main",
                "--receive-time-ns",
                "1000000000",
                "--media-format",
                "mjpeg",
                "--json",
            ])
            .output()?,
        "import media for hold test",
    )?;
    let import_id = parse_json(import_out.trim())?
        .object()
        .and_then(|o| o.get("import_identity"))
        .and_then(Value::text)
        .ok_or("missing import_identity")?
        .to_owned();

    // Test both canonical `hold:front-door-001` and legacy `hold_legacy_001` end-to-end.
    for hold_id in ["hold:front-door-001", "hold_legacy_001"] {
        let preview_raw = require_success(
            Command::new(HOLD)
                .args([
                    "place",
                    "--root",
                    &root.to_string_lossy(),
                    "--site",
                    SITE,
                    "--hold-id",
                    hold_id,
                    "--import-id",
                    &import_id,
                    "--reason",
                    "Preserve test evidence",
                    "--json",
                ])
                .output()?,
            &format!("fss-hold place preview {hold_id}"),
        )?;
        let preview_doc = parse_json(preview_raw.trim())?;
        let obj = preview_doc.object().ok_or("expected JSON object")?;
        let top_approval = obj
            .get("approval_digest")
            .and_then(Value::text)
            .ok_or("missing top-level approval_digest")?
            .to_owned();
        let top_cmd = obj
            .get("approve_command")
            .and_then(Value::text)
            .ok_or("missing top-level approve_command")?;
        assert!(top_approval.starts_with("sha256:"));
        assert!(top_cmd.contains(&top_approval));
        assert!(top_cmd.contains(hold_id));

        // Legacy nested `.result.approval_digest` is preserved too.
        let nested_approval = obj
            .get("result")
            .and_then(Value::object)
            .and_then(|r| r.get("approval_digest"))
            .and_then(Value::text);
        assert_eq!(nested_approval, Some(top_approval.as_str()));

        // Commit via unified `fss hold place` (auto-resolving `--site`).
        let committed_raw = require_success(
            Command::new(FSS)
                .args([
                    "hold",
                    "place",
                    "--root",
                    &root.to_string_lossy(),
                    "--hold-id",
                    hold_id,
                    "--import-id",
                    &import_id,
                    "--reason",
                    "Preserve test evidence",
                    "--approve",
                    &top_approval,
                    "--json",
                ])
                .output()?,
            &format!("fss hold place commit {hold_id}"),
        )?;
        let committed_doc = parse_json(committed_raw.trim())?;
        assert_eq!(
            committed_doc
                .object()
                .and_then(|o| o.get("result"))
                .and_then(Value::object)
                .and_then(|r| r.get("status"))
                .and_then(Value::text),
            Some("committed")
        );
    }

    // `fss-hold list` displays both canonical `hold:front-door-001` and legacy `hold_legacy_001`.
    let listed = require_success(
        Command::new(HOLD)
            .args([
                "list",
                "--root",
                &root.to_string_lossy(),
                "--site",
                SITE,
                "--json",
            ])
            .output()?,
        "fss-hold list",
    )?;
    assert!(listed.contains("\"hold_id\":\"hold:front-door-001\""));
    assert!(listed.contains("\"hold_id\":\"hold_legacy_001\""));
    assert!(listed.contains("\"active_holds\":2"));

    // Unsafe hold IDs fail closed with exit 2.
    for bad in ["../escape", "hold:../escape", "hold:a/b", "hold:"] {
        let out = Command::new(HOLD)
            .args([
                "place",
                "--root",
                &root.to_string_lossy(),
                "--site",
                SITE,
                "--hold-id",
                bad,
                "--import-id",
                &import_id,
                "--reason",
                "Bad id",
            ])
            .output()?;
        assert!(!out.status.success(), "expected `{bad}` to be refused");
        assert_eq!(out.status.code(), Some(2));
    }

    // Unified `fss backup plan` normalizes `manifest_digest` into top-level `approval_digest` +
    // `approve_command` while preserving `manifest_digest`.
    let backup_plan = require_success(
        Command::new(FSS)
            .args([
                "backup",
                "plan",
                "--root",
                &root.to_string_lossy(),
                "--allow-originals",
                "--json",
            ])
            .output()?,
        "fss backup plan",
    )?;
    let backup_doc = parse_json(backup_plan.trim())?;
    let bobj = backup_doc.object().ok_or("backup plan json object")?;
    let manifest = bobj
        .get("manifest_digest")
        .and_then(Value::text)
        .ok_or("missing manifest_digest")?;
    assert_eq!(
        bobj.get("approval_digest").and_then(Value::text),
        Some(manifest)
    );
    assert!(
        bobj.get("approve_command")
            .and_then(Value::text)
            .is_some_and(|c| c.contains(manifest))
    );

    Ok(())
}

#[test]
fn automated_cli_ergonomics_linter_is_clean() {
    let report = lint_unified_cli_surface();
    assert!(
        report.is_clean(),
        "CLI ergonomics linter reported findings: {:?}",
        report.findings
    );
    assert_eq!(report.checked_domains, 14);
    assert!(report.checked_verbs >= 52);
    assert!(report.checked_fss1_commands >= 20);
}
