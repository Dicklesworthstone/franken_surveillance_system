#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
//! Live-binary 3-surface transcript-equivalence harness (`FSS-235` / `fss-x4a.24.35`).
//!
//! Proves semantic equivalence across ALL THREE real public control-plane surfaces:
//! 1. **Direct Rust API** (`fss_cli::parse_fss_args` + `fss_cli::execute_live_fss_with_exit`)
//! 2. **Live `fss` CLI binary** (`CARGO_BIN_EXE_fss` over OS argv, stdout, stderr, exit code)
//! 3. **Live `fss-mcp` stdio server** (`CARGO_BIN_EXE_fss-mcp` over JSON-RPC 2.0 `tools/call`)
//!
//! Covers:
//! - Exact bit-for-bit canonical JSON, `ContractBasis`, `WorldEnvelope`, control-envelope
//!   affordance classifications, `payloadDigest`, and `decisionFingerprint` parity for
//!   read-only `AOP-014 doctor`, `AOP-003 session.orient` (`pulse`/`brief`/`epistemic_map`),
//!   `AOP-005 query` (`events`, `footage`, `sources`, `reports`, `localizations`, `cameras`,
//!   `graph`, `holds`, `privacy-masks`), `AOP-011 explain` (`why`, `why_not`, `forensic`),
//!   and `AOP-004 session.follow`.
//! - Full 14-operation stateful mission lifecycle across three bit-identical isolated
//!   deployment clones (`AOP-001 session.open` -> `AOP-003` -> `AOP-006 investigate`
//!   [`open`/`inspect`/`list`/`claim`/`claim-list`] -> `AOP-007 plan` [preview + prepare] ->
//!   `AOP-008 commit` [dispatch against live loopback HTTP relay] -> `AOP-009 wait` ->
//!   `AOP-008 commit` [reconcile preview + approve] -> `AOP-007 plan` [close] ->
//!   `AOP-010 cancel` [second prepared alert preview + approve] -> `AOP-013 feedback` ->
//!   `AOP-012 handoff` -> `AOP-002 session.resume` -> `AOP-010 cancel` [session revocation]).
//! - Exact 3-surface refusal parity (`explain` missing event, `wait` missing operation,
//!   `session_follow` foreign anchor, `session_resume` missing handoff), vault canary-leak
//!   scanning across all captured transcripts/stderr, and planted-bug divergence detection.

use std::collections::BTreeSet;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fss_cli::agent_json::{object, string};
use fss_cli::crosswalk::REGISTERED_OPERATION_CROSSWALK;
use fss_cli::escape_json_str;
use fss_cli::query_cmd::ops_targets::{CAP_AGENT_QUERY, CAP_OBSERVE_STATUS};
use fss_cli::transcript_equivalence::{
    NormalizationPolicy, SemanticProjection, StepEquivalenceRow, SurfaceKind, TokenNormalizer,
    TranscriptEquivalenceReport, build_report, compare_step, execute_rust_api_argv,
    project_surface_response,
};
use fss_core::json_input::{Value, parse_mcp_reply};
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec, TimestampNs,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority};
use fss_vault::{
    AdapterFamily, CAP_SECRET_READ_001, CAP_SECRET_WRITE_001, CanaryLeakScanner, KdfParams,
    LabEntropy, LocalEncryptedVault, SecretAccessCx, SecretBytes, SecretId, SecretScope,
    SecretStore,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const PROTOCOL_VERSION: &str = "2025-06-18";
const SITE_ID: &str = "site:fss235-equiv";
const PRINCIPAL: &str = "principal:fss235-owner";
const MIRROR_HOMOGRAPHY: &str = "-1,0,96,0,1,0,0,0,1";
const OPS_READ_CAPS: &[&str] = &[CAP_AGENT_QUERY, CAP_OBSERVE_STATUS];

const CANARY_RTSP: &[u8] = b"CANARY-FSS235-RTSP-SECRET-9988776655443322-NO-LEAK";
const CANARY_HMAC: &[u8] = b"CANARY-FSS235-HMAC-SECRET-1122334455667788-NO-LEAK";

static DIR_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> TestResult<Self> {
        let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let raw = PathBuf::from("/tmp").join(format!("fss235-{tag}-{}-{seq}", std::process::id()));
        let _ = fs::remove_dir_all(&raw);
        fs::create_dir_all(&raw)?;
        let path = raw.canonicalize()?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn quote(s: &str) -> String {
    format!("\"{}\"", escape_json_str(s))
}

fn field<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a Value> {
    let mut cur = value;
    for key in path {
        cur = cur
            .object()
            .and_then(|o| o.get(*key))
            .ok_or_else(|| format!("missing field `{key}` in path {path:?}"))?;
    }
    Ok(cur)
}

fn text<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a str> {
    field(value, path)?
        .text()
        .ok_or_else(|| format!("field {path:?} is not a string").into())
}

fn array<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a [Value]> {
    field(value, path)?
        .array()
        .ok_or_else(|| format!("field {path:?} is not an array").into())
}

fn texts(value: &Value, path: &[&str]) -> TestResult<Vec<String>> {
    array(value, path)?
        .iter()
        .map(|v| {
            v.text()
                .map(str::to_owned)
                .ok_or_else(|| format!("array item in {path:?} is not a string").into())
        })
        .collect()
}

fn wall_now_ns() -> TestResult<i128> {
    Ok(i128::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
    )?)
}

fn assert_bin_ok(out: &Output, label: &str) -> TestResult {
    if !out.status.success() {
        return Err(format!(
            "{label} failed ({:?}): stdout={} stderr={}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(())
}

fn kv_field(out: &Output, key: &str) -> TestResult<String> {
    let prefix = format!("{key}=");
    String::from_utf8(out.stdout.clone())?
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
        .ok_or_else(|| format!("missing `{key}=` in stdout").into())
}

fn json_report_field(out: &Output, key: &str) -> TestResult<String> {
    let raw = String::from_utf8(out.stdout.clone())?;
    let pattern = format!("\"{key}\":");
    let start = raw
        .find(&pattern)
        .ok_or_else(|| format!("missing JSON `{key}` in {raw}"))?
        + pattern.len();
    let rest = &raw[start..];
    Ok(match rest.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next().unwrap_or_default().to_owned(),
        None => rest
            .split([',', '}', ']'])
            .next()
            .unwrap_or_default()
            .to_owned(),
    })
}

fn init_deployment(root: &Path, tag: &str) -> TestResult {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: format!("trace:fss235-{tag}"),
        operation_id: OperationId::parse(format!("operation:fss235-{tag}"))?,
        principal: PRINCIPAL.to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(32 * 1024 * 1024)
            .storage_operations(50_000)
            .build()?,
        privacy_scope: "private:property".to_owned(),
        retention_scope: "retention:current-deletion-restrictions".to_owned(),
        anchor_universe: ContentDigest::sha256(SITE_ID.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?);
    drop(ReferenceDeployment::open(root, SITE_ID, &cx)?);
    cx.drain_and_finalize();
    Ok(())
}

fn encode_corroboration_mjpeg(rightward: bool) -> TestResult<Vec<u8>> {
    let (width, height) = (96_u32, 48_u32);
    let cfg = JpegConfig {
        quality: 80,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..8_usize {
        let mut pixels = vec![40_u8; (width * height) as usize];
        if index >= 3 {
            let offset = 16 + (index - 3) * 8;
            let left = if rightward { offset } else { 80 - offset };
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * width as usize + x] = 220;
                }
            }
        }
        stream.extend(encode_jpeg(width, height, &pixels, &cfg)?);
    }
    Ok(stream)
}

/// Seeds a deployment with two-camera MJPEG footage + one corroborated event,
/// returning `(pre_event_anchor, corroborated_event_id)`.
fn seed_corroborated_deployment(work_dir: &Path, dep_root: &Path) -> TestResult<(String, String)> {
    init_deployment(dep_root, "seed")?;
    let snap_before = fss_reference::agent_orient::read_deployment(
        dep_root,
        &fss_reference::agent_orient::OrientLimits::default(),
    )?;
    let anchor_before = fss_reference::agent_follow::snapshot_anchor_token(&snap_before);

    let now = u128::try_from(wall_now_ns()?)?;
    let capture_start = now.saturating_sub(10_000_000_000);
    let mut cam_args = Vec::new();
    for (label, sensor, rightward) in [
        ("east", "sensor:east", true),
        ("west", "sensor:west", false),
    ] {
        let mjpeg_path = work_dir.join(format!("{label}.mjpeg"));
        fs::write(&mjpeg_path, encode_corroboration_mjpeg(rightward)?)?;
        let out = Command::new(env!("CARGO_BIN_EXE_fss-file"))
            .args(["import", "--root"])
            .arg(dep_root)
            .args(["--site", SITE_ID, "--input"])
            .arg(&mjpeg_path)
            .args(["--sensor", sensor, "--stream", &format!("stream:{label}")])
            .args([
                "--media-format",
                "mjpeg",
                "--receive-time-ns",
                &now.to_string(),
                "--capture-start-ns",
                &capture_start.to_string(),
                "--capture-uncertainty-ns",
                "1000000",
                "--assumed-fps",
                "10",
            ])
            .output()?;
        assert_bin_ok(&out, "fss-file import")?;
        let import_id = kv_field(&out, "import_identity")?;
        cam_args.push(format!("{label}:{import_id}"));
    }

    let west_ground = format!("west:{MIRROR_HOMOGRAPHY}");
    let run_corr = |extra: &[&str]| -> TestResult<Output> {
        let mut args = vec![
            "corroborate",
            "--root",
            dep_root.to_str().ok_or("non-utf8 dep_root")?,
            "--site",
            SITE_ID,
            "--camera",
            cam_args[0].as_str(),
            "--camera",
            cam_args[1].as_str(),
            "--ground",
            "east:1,0,0,0,1,0,0,0,1",
            "--ground",
            west_ground.as_str(),
            "--zone",
            "door:32,0,40,48",
            "--interpretation",
            "gray",
            "--time-gate-ns",
            "250000000",
            "--distance-gate",
            "16",
        ];
        args.extend_from_slice(extra);
        Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .args(args)
            .output()?)
    };
    let preview = run_corr(&[])?;
    assert_bin_ok(&preview, "fss-event corroborate preview")?;
    let proposal = json_report_field(&preview, "proposal_digest")?;
    let published = run_corr(&["--approve", &proposal])?;
    assert_bin_ok(&published, "fss-event corroborate publish")?;
    let event_id = json_report_field(&published, "event_id")?;
    Ok((anchor_before, event_id))
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> TestResult {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if src_path.is_file() {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

/// Real loopback HTTP relay accepting `expected_requests` sequential alerts and
/// answering `202 Accepted` on the same `127.0.0.1:<port>` address across all 3 surfaces.
struct LoopbackRelay {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    handle: Option<JoinHandle<()>>,
}

impl LoopbackRelay {
    fn spawn(expected_requests: usize) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_bg = Arc::clone(&hits);
        let handle = thread::spawn(move || {
            for _ in 0..expected_requests {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                let mut req = Vec::new();
                let mut buf = [0_u8; 4096];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    if req.windows(4).any(|w| w == b"\r\n\r\n") && req.len() >= 64 {
                        break;
                    }
                }
                hits_bg.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(
                    b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                let _ = stream.flush();
            }
        });
        Ok(Self {
            addr,
            hits,
            handle: Some(handle),
        })
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn join(mut self) {
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

struct LiveMcp {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
    wire_log: Vec<String>,
}

impl LiveMcp {
    fn spawn(root: &Path, capabilities: &[&str]) -> TestResult<Self> {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fss-mcp"));
        cmd.arg("--root").arg(root).args(["--principal", PRINCIPAL]);
        for cap in capabilities {
            cmd.args(["--grant-capability", cap]);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn()?;
        let stdin = child.stdin.take().ok_or("missing fss-mcp stdin")?;
        let stdout = BufReader::new(child.stdout.take().ok_or("missing fss-mcp stdout")?);
        let mut mcp = Self {
            child,
            stdin: Some(stdin),
            stdout,
            next_id: 1,
            wire_log: Vec::new(),
        };
        let id = mcp.alloc_id();
        let init = format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"initialize","params":{{"protocolVersion":"{PROTOCOL_VERSION}","capabilities":{{}},"clientInfo":{{"name":"fss235-equiv","version":"1"}}}}}}"#
        );
        mcp.send_line(&init)?;
        let (_, init_reply) = mcp.read_reply()?;
        assert_eq!(
            text(&init_reply, &["result", "protocolVersion"])?,
            PROTOCOL_VERSION
        );
        mcp.send_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)?;
        Ok(mcp)
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn send_line(&mut self, line: &str) -> TestResult {
        let stdin = self.stdin.as_mut().ok_or("stdin already closed")?;
        writeln!(stdin, "{line}")?;
        stdin.flush()?;
        Ok(())
    }

    fn read_reply(&mut self) -> TestResult<(String, Value)> {
        let mut line = String::new();
        let n = self.stdout.read_line(&mut line)?;
        if n == 0 {
            return Err("fss-mcp closed stdout unexpectedly".into());
        }
        let trimmed = line.trim_end_matches(['\r', '\n']).to_owned();
        self.wire_log.push(trimmed.clone());
        let parsed = parse_mcp_reply(&trimmed)?;
        Ok((trimmed, parsed))
    }

    fn call_tool(
        &mut self,
        name: &str,
        args_json: &str,
        policy: &NormalizationPolicy,
        tokens: &TokenNormalizer,
    ) -> TestResult<(SemanticProjection, String, Value)> {
        let id = self.alloc_id();
        let req = format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":{},"arguments":{args_json}}}}}"#,
            quote(name)
        );
        let started = Instant::now();
        self.send_line(&req)?;
        let (raw_wire, wire) = self.read_reply()?;
        let elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        let res = field(&wire, &["result"])
            .map_err(|e| format!("expected result for `{name}` ({e}): {raw_wire}"))?;
        let is_error = res
            .object()
            .and_then(|o| o.get("isError"))
            .and_then(Value::boolean)
            .unwrap_or(false);
        let content = array(res, &["content"])?;
        let body = text(&content[0], &["text"])?.to_owned();
        let env = parse_mcp_reply(body.trim_end())?;
        let proj = project_surface_response(
            SurfaceKind::Mcp,
            is_error,
            &body,
            elapsed_us,
            policy,
            tokens,
        )?;
        Ok((proj, body, env))
    }

    fn finish(mut self) -> TestResult<(i32, Vec<u8>, Vec<String>)> {
        drop(self.stdin.take());
        let out = self.child.wait_with_output()?;
        Ok((out.status.code().unwrap_or(-1), out.stderr, self.wire_log))
    }
}

fn execute_cli_argv(
    argv: &[OsString],
    policy: &NormalizationPolicy,
    tokens: &TokenNormalizer,
) -> TestResult<(SemanticProjection, String, Value, Vec<u8>)> {
    let started = Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(argv)
        .output()?;
    let elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    let is_error = !out.status.success();
    let stdout = String::from_utf8(out.stdout)?;
    let env = parse_mcp_reply(stdout.trim())?;
    let proj = project_surface_response(
        SurfaceKind::Cli,
        is_error,
        &stdout,
        elapsed_us,
        policy,
        tokens,
    )?;
    Ok((proj, stdout, env, out.stderr))
}

fn os_args(parts: &[&str]) -> Vec<OsString> {
    parts.iter().map(OsString::from).collect()
}

fn extract_plan_approvals(env: &Value) -> TestResult<(String, String, String)> {
    let pointers = texts(env, &["proofPointers"])?;
    Ok((
        text(env, &["payload", "planId"])?.to_owned(),
        pointers.get(2).ok_or("missing plan approval")?.clone(),
        pointers.last().ok_or("missing dispatch approval")?.clone(),
    ))
}

fn extract_operation_id(env: &Value) -> TestResult<String> {
    let steps = array(env, &["payload", "steps"])?;
    let prepare = steps
        .iter()
        .find(|s| text(s, &["stepId"]).is_ok_and(|id| id == "step:prepare"))
        .ok_or("missing step:prepare")?;
    texts(prepare, &["writeWitnesses"])?
        .into_iter()
        .next()
        .ok_or_else(|| "missing operation witness".into())
}

fn extract_approval_from_proof_pointers(env: &Value) -> TestResult<String> {
    let pointers = texts(env, &["proofPointers"])?;
    pointers
        .into_iter()
        .find(|p| p.starts_with("sha256:"))
        .ok_or_else(|| "missing sha256 approval in proofPointers".into())
}

fn run_read_only_step(
    steps: &mut Vec<StepEquivalenceRow>,
    mcp: &mut LiveMcp,
    label: &str,
    expected_op: &str,
    cli_argv: &[OsString],
    mcp_tool: &str,
    mcp_args: &str,
) -> TestResult<(String, String, String)> {
    let policy = NormalizationPolicy::exact();
    let tokens = TokenNormalizer::none();
    let (p_api, raw_api) = execute_rust_api_argv(cli_argv, &policy, &tokens)?;
    let (p_cli, raw_cli, _, _) = execute_cli_argv(cli_argv, &policy, &tokens)?;
    let (p_mcp, raw_mcp, _) = mcp.call_tool(mcp_tool, mcp_args, &policy, &tokens)?;
    let idx = steps.len();
    let row = compare_step(idx, label, expected_op, &policy, p_api, p_cli, p_mcp)?;
    assert!(
        row.equivalent,
        "step `{label}` ({expected_op}) diverged under EXACT policy: {:?}",
        row.mismatches
    );
    steps.push(row);
    Ok((raw_api, raw_cli, raw_mcp))
}

#[test]
fn fss_235_read_only_and_query_three_surface_exact_equivalence() -> TestResult {
    let tmp = TempDir::new("ro")?;
    let dep = tmp.path.join("dep");
    let (anchor_before, event_id) = seed_corroborated_deployment(&tmp.path, &dep)?;
    let root_s = dep.to_str().ok_or("utf8 root")?;
    let principal_flag = format!("--principal={PRINCIPAL}");

    let mut mcp = LiveMcp::spawn(&dep, OPS_READ_CAPS)?;
    let mut steps = Vec::new();

    // 1. AOP-014 doctor
    run_read_only_step(
        &mut steps,
        &mut mcp,
        "doctor healthy",
        "AOP-014",
        &os_args(&["doctor", "--json", "--root", root_s]),
        "doctor",
        "{}",
    )?;

    // 2. AOP-003 session.orient across all 3 views (pulse, brief, epistemic_map)
    for (view, budget) in [
        ("pulse", "300"),
        ("brief", "1600"),
        ("epistemic_map", "3000"),
    ] {
        run_read_only_step(
            &mut steps,
            &mut mcp,
            &format!("session.orient {view}"),
            "AOP-003",
            &os_args(&[
                "orient",
                "--json",
                "--root",
                root_s,
                &principal_flag,
                &format!("--view={view}"),
                &format!("--budget-tokens={budget}"),
            ]),
            "session_orient",
            &format!(r#"{{"view":"{view}","budget_tokens":{budget}}}"#),
        )?;
    }

    // 3. AOP-005 query across native & operational targets
    run_read_only_step(
        &mut steps,
        &mut mcp,
        "query events",
        "AOP-005",
        &os_args(&[
            "query",
            "--json",
            "--root",
            root_s,
            &principal_flag,
            "--target=events",
        ]),
        "query",
        r#"{"target":"events"}"#,
    )?;
    run_read_only_step(
        &mut steps,
        &mut mcp,
        "query footage",
        "AOP-005",
        &os_args(&[
            "query",
            "--json",
            "--root",
            root_s,
            &principal_flag,
            "--target=footage",
        ]),
        "query",
        r#"{"target":"footage"}"#,
    )?;
    for target in ["sources", "reports", "localizations"] {
        run_read_only_step(
            &mut steps,
            &mut mcp,
            &format!("query {target}"),
            "AOP-005",
            &os_args(&[
                "query",
                "--json",
                "--root",
                root_s,
                &principal_flag,
                &format!("--target={target}"),
            ]),
            "query",
            &format!(r#"{{"target":"{target}"}}"#),
        )?;
    }
    for target in ["cameras", "graph", "holds", "privacy-masks"] {
        run_read_only_step(
            &mut steps,
            &mut mcp,
            &format!("query ops {target}"),
            "AOP-005",
            &os_args(&[
                "query",
                "--json",
                "--root",
                root_s,
                &principal_flag,
                &format!("--target={target}"),
                "--capability",
                CAP_AGENT_QUERY,
                "--capability",
                CAP_OBSERVE_STATUS,
            ]),
            "query",
            &format!(r#"{{"target":"{target}"}}"#),
        )?;
    }

    // 4. AOP-011 explain (why, why_not, forensic with custody=yes)
    run_read_only_step(
        &mut steps,
        &mut mcp,
        "explain why",
        "AOP-011",
        &os_args(&[
            "explain",
            "--json",
            "--root",
            root_s,
            &principal_flag,
            &format!("--event-id={event_id}"),
            "--view=decision_diff",
        ]),
        "explain",
        &object(&[
            ("event_id", string(&event_id)),
            ("view", string("decision_diff")),
        ]),
    )?;
    run_read_only_step(
        &mut steps,
        &mut mcp,
        "explain why_not",
        "AOP-011",
        &os_args(&[
            "explain",
            "--json",
            "--root",
            root_s,
            &principal_flag,
            &format!("--event-id={event_id}"),
            "--question=why_not",
        ]),
        "explain",
        &object(&[
            ("event_id", string(&event_id)),
            ("question", string("why_not")),
        ]),
    )?;
    run_read_only_step(
        &mut steps,
        &mut mcp,
        "explain forensic custody",
        "AOP-011",
        &os_args(&[
            "explain",
            "--json",
            "--root",
            root_s,
            &principal_flag,
            &format!("--event-id={event_id}"),
            "--view=forensic",
            "--budget-tokens=8000",
            "--custody=yes",
        ]),
        "explain",
        &object(&[
            ("event_id", string(&event_id)),
            ("view", string("forensic")),
            ("budget_tokens", "8000".to_owned()),
            ("custody", string("yes")),
        ]),
    )?;

    // 5. AOP-004 session.follow since pre-event anchor
    run_read_only_step(
        &mut steps,
        &mut mcp,
        "session.follow since pre-event anchor",
        "AOP-004",
        &os_args(&[
            "follow",
            "--json",
            "--root",
            root_s,
            &principal_flag,
            &format!("--since={anchor_before}"),
            "--view=brief",
            "--max-entries=16",
        ]),
        "session_follow",
        &object(&[
            ("since", string(&anchor_before)),
            ("view", string("brief")),
            ("max_entries", "16".to_owned()),
        ]),
    )?;

    let (mcp_exit, _stderr, _wire) = mcp.finish()?;
    assert_eq!(mcp_exit, 0);

    let report: TranscriptEquivalenceReport = build_report(steps)?;
    assert!(report.equivalent);
    assert_eq!(report.total_mismatches, 0);
    assert!(!report.grants_effect_authority);
    assert_eq!(report.steps.len(), 17);
    println!("CAPLOG_FSS235_READ_ONLY_EXACT={}", report.to_json());
    Ok(())
}

#[test]
fn fss_235_full_14_op_stateful_mission_lifecycle_three_surface_equivalence() -> TestResult {
    let tmp = TempDir::new("st")?;
    let seed_root = tmp.path.join("seed");
    let (_, event_id) = seed_corroborated_deployment(&tmp.path, &seed_root)?;

    // Create 3 bit-identical isolated clones so Direct Rust API, CLI, and MCP each mutate
    // their own durable agent/effect journals independently.
    let dep_api = tmp.path.join("dep_api");
    let dep_cli = tmp.path.join("dep_cli");
    let dep_mcp = tmp.path.join("dep_mcp");
    copy_dir_recursive(&seed_root, &dep_api)?;
    copy_dir_recursive(&seed_root, &dep_cli)?;
    copy_dir_recursive(&seed_root, &dep_mcp)?;

    let root_api = dep_api.to_str().ok_or("utf8 api root")?;
    let root_cli = dep_cli.to_str().ok_or("utf8 cli root")?;
    let principal_flag = format!("--principal={PRINCIPAL}");

    let relay = LoopbackRelay::spawn(3)?;
    let relay_addr = relay.addr.to_string();

    let mut mcp = LiveMcp::spawn(&dep_mcp, OPS_READ_CAPS)?;
    let policy = NormalizationPolicy::stateful_clone();
    let mut tok_api = TokenNormalizer::stateful_clone();
    let mut tok_cli = TokenNormalizer::stateful_clone();
    let mut tok_mcp = TokenNormalizer::stateful_clone();
    tok_api.push(root_api, "<DEPLOY_ROOT>")?;
    tok_cli.push(root_cli, "<DEPLOY_ROOT>")?;
    tok_mcp.push(dep_mcp.to_str().ok_or("utf8 mcp root")?, "<DEPLOY_ROOT>")?;

    let mut steps = Vec::new();
    let mut covered_all_14: BTreeSet<String> = ["AOP-004", "AOP-005", "AOP-011", "AOP-014"]
        .into_iter()
        .map(str::to_owned)
        .collect();

    // Helper closure macro-style for stateful step comparison
    let mut record = |label: &str,
                      op: &str,
                      p_api: SemanticProjection,
                      p_cli: SemanticProjection,
                      p_mcp: SemanticProjection|
     -> TestResult {
        let idx = steps.len();
        let row = compare_step(idx, label, op, &policy, p_api, p_cli, p_mcp)?;
        assert!(
            row.equivalent,
            "stateful step `{label}` ({op}) diverged: {:?}",
            row.mismatches
        );
        covered_all_14.insert(op.to_owned());
        steps.push(row);
        Ok(())
    };

    // 1. AOP-001 session.open with tainted literal mission/objective (must stay literal on all 3 surfaces)
    let tainted_mission = "Inspect east door ../etc/passwd --root=/tmp/evil";
    let tainted_objective = "Verify corroborated alert $(id) without shell expansion";
    let (p_api, raw_api) = execute_rust_api_argv(
        &os_args(&[
            "session",
            "open",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            &format!("--mission={tainted_mission}"),
            &format!("--objective={tainted_objective}"),
            "--view=brief",
            "--budget-tokens=40000",
        ]),
        &policy,
        &tok_api,
    )?;
    let (p_cli, raw_cli_open, env_cli, _) = execute_cli_argv(
        &os_args(&[
            "session",
            "open",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            &format!("--mission={tainted_mission}"),
            &format!("--objective={tainted_objective}"),
            "--view=brief",
            "--budget-tokens=40000",
        ]),
        &policy,
        &tok_cli,
    )?;
    let (p_mcp, raw_mcp_open, env_mcp) = mcp.call_tool(
        "session_open",
        &object(&[
            ("mission", string(tainted_mission)),
            ("objective", string(tainted_objective)),
            ("view", string("brief")),
            ("budget_tokens", "40000".to_owned()),
        ]),
        &policy,
        &tok_mcp,
    )?;
    let env_api = parse_mcp_reply(raw_api.trim())?;
    let sid_api = text(&env_api, &["sessionId"])?.to_owned();
    let sid_cli = text(&env_cli, &["sessionId"])?.to_owned();
    let sid_mcp = text(&env_mcp, &["sessionId"])?.to_owned();
    let mid_api = text(&env_api, &["missionId"])?.to_owned();
    let mid_cli = text(&env_cli, &["missionId"])?.to_owned();
    let mid_mcp = text(&env_mcp, &["missionId"])?.to_owned();
    // Register concrete session & mission IDs as canonical placeholders so prose/executionBoundary stays exact!
    tok_api.push(&sid_api, "<SESSION_ID>")?;
    tok_cli.push(&sid_cli, "<SESSION_ID>")?;
    tok_mcp.push(&sid_mcp, "<SESSION_ID>")?;
    tok_api.push(&mid_api, "<MISSION_ID>")?;
    tok_cli.push(&mid_cli, "<MISSION_ID>")?;
    tok_mcp.push(&mid_mcp, "<MISSION_ID>")?;
    let p_api = project_surface_response(
        SurfaceKind::RustApi,
        p_api.is_error,
        &raw_api,
        p_api.elapsed_us,
        &policy,
        &tok_api,
    )?;
    let p_cli = project_surface_response(
        SurfaceKind::Cli,
        p_cli.is_error,
        &raw_cli_open,
        p_cli.elapsed_us,
        &policy,
        &tok_cli,
    )?;
    let p_mcp = project_surface_response(
        SurfaceKind::Mcp,
        p_mcp.is_error,
        &raw_mcp_open,
        p_mcp.elapsed_us,
        &policy,
        &tok_mcp,
    )?;
    record(
        "session.open literal tainted mission",
        "AOP-001",
        p_api,
        p_cli,
        p_mcp,
    )?;

    // 2. AOP-003 session-bound orient
    let (p_api, _) = execute_rust_api_argv(
        &os_args(&[
            "orient",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            &format!("--session={sid_api}"),
            "--view=brief",
        ]),
        &policy,
        &tok_api,
    )?;
    let (p_cli, _, _, _) = execute_cli_argv(
        &os_args(&[
            "orient",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            &format!("--session={sid_cli}"),
            "--view=brief",
        ]),
        &policy,
        &tok_cli,
    )?;
    let (p_mcp, _, _) = mcp.call_tool(
        "session_orient",
        &object(&[("session", string(&sid_mcp)), ("view", string("brief"))]),
        &policy,
        &tok_mcp,
    )?;
    record("session-bound orient brief", "AOP-003", p_api, p_cli, p_mcp)?;

    // 3. AOP-006 investigate (open -> inspect -> list -> claim -> claim-list)
    let case_id = "case:fss235-door";
    let draft_json = format!(
        r#"{{"caseId":"{case_id}","question":"Did a corroborated entrant cross the east door?","decisionInformed":"Alert dispatch vs hold","hypotheses":[{{"hypothesisId":"h:entry","description":"Corroborated physical entry","predictions":["matched east and west tracks"]}},{{"hypothesisId":"h:artifact","description":"Transient glare artifact","predictions":["disjoint sensor tracks"]}}],"knowns":[{{"statementId":"k:cams","text":"East and west cameras retained footage","basis":["sensor:east","sensor:west"]}}],"unknowns":[{{"statementId":"u:identity","text":"Person identity remains unknown"}}],"discriminators":[{{"discriminatorId":"d:overlap","description":"Two-camera ground-plane overlap","separates":["h:entry","h:artifact"],"expectedOutcomes":["matched","disjoint"]}}],"probes":["probe:corroborate"],"stopRules":["independent two-camera evidence settles competing hypotheses"],"decisionWindowNs":3600000000000}}"#
    );
    let draft_file = tmp.path.join("case_draft.json");
    fs::write(&draft_file, &draft_json)?;
    let draft_path = draft_file.to_str().ok_or("utf8 draft_file")?;

    let (p_api, _) = execute_rust_api_argv(
        &os_args(&[
            "investigate",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            &format!("--session={sid_api}"),
            "--transition=open",
            &format!("--case-file={draft_path}"),
        ]),
        &policy,
        &tok_api,
    )?;
    let (p_cli, _, _, _) = execute_cli_argv(
        &os_args(&[
            "investigate",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            &format!("--session={sid_cli}"),
            "--transition=open",
            &format!("--case-file={draft_path}"),
        ]),
        &policy,
        &tok_cli,
    )?;
    let (p_mcp, _, _) = mcp.call_tool(
        "investigate",
        &format!(
            r#"{{"session":{},"transition":"open","draft":{draft_json}}}"#,
            quote(&sid_mcp)
        ),
        &policy,
        &tok_mcp,
    )?;
    record("investigate open", "AOP-006", p_api, p_cli, p_mcp)?;

    let (p_api, _) = execute_rust_api_argv(
        &os_args(&[
            "investigate",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            &format!("--session={sid_api}"),
            "--transition=inspect",
            &format!("--case={case_id}"),
        ]),
        &policy,
        &tok_api,
    )?;
    let (p_cli, _, _, _) = execute_cli_argv(
        &os_args(&[
            "investigate",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            &format!("--session={sid_cli}"),
            "--transition=inspect",
            &format!("--case={case_id}"),
        ]),
        &policy,
        &tok_cli,
    )?;
    let (p_mcp, _, _) = mcp.call_tool(
        "investigate",
        &object(&[
            ("session", string(&sid_mcp)),
            ("transition", string("inspect")),
            ("case", string(case_id)),
        ]),
        &policy,
        &tok_mcp,
    )?;
    record("investigate inspect", "AOP-006", p_api, p_cli, p_mcp)?;

    let (p_api, _) = execute_rust_api_argv(
        &os_args(&[
            "investigate",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            &format!("--session={sid_api}"),
            "--transition=claim",
            &format!("--case={case_id}"),
            "--work=case",
            "--lease-ms=60000",
        ]),
        &policy,
        &tok_api,
    )?;
    let (p_cli, _, _, _) = execute_cli_argv(
        &os_args(&[
            "investigate",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            &format!("--session={sid_cli}"),
            "--transition=claim",
            &format!("--case={case_id}"),
            "--work=case",
            "--lease-ms=60000",
        ]),
        &policy,
        &tok_cli,
    )?;
    let (p_mcp, _, _) = mcp.call_tool(
        "investigate",
        &object(&[
            ("session", string(&sid_mcp)),
            ("transition", string("claim")),
            ("case", string(case_id)),
            ("work", string("case")),
            ("lease_ms", "60000".to_owned()),
        ]),
        &policy,
        &tok_mcp,
    )?;
    record("investigate claim acquire", "AOP-006", p_api, p_cli, p_mcp)?;

    // 4. AOP-007 plan: prepare a cancelable alert (port 9) AND the dispatchable loopback alert
    //    while the session workspace is at the current ledger head.
    let plaintext_app = ContentDigest::sha256(b"fss235 loopback relay approval").to_text();
    let (_, raw_c_prev_api) = execute_rust_api_argv(
        &os_args(&[
            "plan",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            &format!("--session={sid_api}"),
            "--intent=alert",
            &format!("--event-id={event_id}"),
            "--relay=127.0.0.1:9",
            "--path=/fss/eq-cancel",
            &format!("--plaintext-approval={plaintext_app}"),
            "--deadline-ms=5000",
        ]),
        &policy,
        &tok_api,
    )?;
    let (_, _, env_c_prev_cli, _) = execute_cli_argv(
        &os_args(&[
            "plan",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            &format!("--session={sid_cli}"),
            "--intent=alert",
            &format!("--event-id={event_id}"),
            "--relay=127.0.0.1:9",
            "--path=/fss/eq-cancel",
            &format!("--plaintext-approval={plaintext_app}"),
            "--deadline-ms=5000",
        ]),
        &policy,
        &tok_cli,
    )?;
    let (_, _, env_c_prev_mcp) = mcp.call_tool(
        "plan",
        &object(&[
            ("intent", string("alert")),
            ("session", string(&sid_mcp)),
            ("event_id", string(&event_id)),
            ("relay", string("127.0.0.1:9")),
            ("path", string("/fss/eq-cancel")),
            ("plaintext_approval", string(&plaintext_app)),
            ("deadline_ms", "5000".to_owned()),
        ]),
        &policy,
        &tok_mcp,
    )?;
    let env_c_prev_api = parse_mcp_reply(raw_c_prev_api.trim())?;
    let (_, c_app_api, _) = extract_plan_approvals(&env_c_prev_api)?;
    let (_, c_app_cli, _) = extract_plan_approvals(&env_c_prev_cli)?;
    let (_, c_app_mcp, _) = extract_plan_approvals(&env_c_prev_mcp)?;
    let c_op_api = extract_operation_id(&env_c_prev_api)?;
    let c_op_cli = extract_operation_id(&env_c_prev_cli)?;
    let c_op_mcp = extract_operation_id(&env_c_prev_mcp)?;
    assert_eq!(c_op_api, c_op_cli);
    assert_eq!(c_op_api, c_op_mcp);

    // Prepare cancelable alert on all 3 surfaces before Alert #1 mutates the effect journal.
    let _ = execute_rust_api_argv(
        &os_args(&[
            "plan",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            &format!("--session={sid_api}"),
            "--intent=alert",
            &format!("--event-id={event_id}"),
            "--relay=127.0.0.1:9",
            "--path=/fss/eq-cancel",
            &format!("--plaintext-approval={plaintext_app}"),
            "--deadline-ms=5000",
            &format!("--approve={c_app_api}"),
        ]),
        &policy,
        &tok_api,
    )?;
    let _ = execute_cli_argv(
        &os_args(&[
            "plan",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            &format!("--session={sid_cli}"),
            "--intent=alert",
            &format!("--event-id={event_id}"),
            "--relay=127.0.0.1:9",
            "--path=/fss/eq-cancel",
            &format!("--plaintext-approval={plaintext_app}"),
            "--deadline-ms=5000",
            &format!("--approve={c_app_cli}"),
        ]),
        &policy,
        &tok_cli,
    )?;
    let _ = mcp.call_tool(
        "plan",
        &object(&[
            ("intent", string("alert")),
            ("session", string(&sid_mcp)),
            ("event_id", string(&event_id)),
            ("relay", string("127.0.0.1:9")),
            ("path", string("/fss/eq-cancel")),
            ("plaintext_approval", string(&plaintext_app)),
            ("deadline_ms", "5000".to_owned()),
            ("approve", string(&c_app_mcp)),
        ]),
        &policy,
        &tok_mcp,
    )?;

    // Now preview + prepare the dispatchable loopback alert (verify EXACT plan approval parity).
    let (p_api, raw_plan_api) = execute_rust_api_argv(
        &os_args(&[
            "plan",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            &format!("--session={sid_api}"),
            "--intent=alert",
            &format!("--event-id={event_id}"),
            &format!("--relay={relay_addr}"),
            "--path=/fss/eq-alert",
            &format!("--plaintext-approval={plaintext_app}"),
            "--deadline-ms=5000",
        ]),
        &policy,
        &tok_api,
    )?;
    let (p_cli, raw_plan_cli, env_plan_cli, _) = execute_cli_argv(
        &os_args(&[
            "plan",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            &format!("--session={sid_cli}"),
            "--intent=alert",
            &format!("--event-id={event_id}"),
            &format!("--relay={relay_addr}"),
            "--path=/fss/eq-alert",
            &format!("--plaintext-approval={plaintext_app}"),
            "--deadline-ms=5000",
        ]),
        &policy,
        &tok_cli,
    )?;
    let (p_mcp, raw_plan_mcp, env_plan_mcp) = mcp.call_tool(
        "plan",
        &object(&[
            ("intent", string("alert")),
            ("session", string(&sid_mcp)),
            ("event_id", string(&event_id)),
            ("relay", string(&relay_addr)),
            ("path", string("/fss/eq-alert")),
            ("plaintext_approval", string(&plaintext_app)),
            ("deadline_ms", "5000".to_owned()),
        ]),
        &policy,
        &tok_mcp,
    )?;
    let env_plan_api = parse_mcp_reply(raw_plan_api.trim())?;
    let (plan_id_api, plan_app_api, _) = extract_plan_approvals(&env_plan_api)?;
    let (plan_id_cli, plan_app_cli, _) = extract_plan_approvals(&env_plan_cli)?;
    let (plan_id_mcp, plan_app_mcp, _) = extract_plan_approvals(&env_plan_mcp)?;
    let op_id_api = extract_operation_id(&env_plan_api)?;
    let op_id_cli = extract_operation_id(&env_plan_cli)?;
    let op_id_mcp = extract_operation_id(&env_plan_mcp)?;
    // Plan approval digest AND operation ID are content-derived from (event, relay, path, principal):
    // ALL THREE SURFACES MUST PRODUCE THE EXACT SAME DIGEST AND OPERATION ID!
    assert_eq!(plan_app_api, plan_app_cli);
    assert_eq!(plan_app_api, plan_app_mcp);
    assert_eq!(op_id_api, op_id_cli);
    assert_eq!(op_id_api, op_id_mcp);
    tok_api.push(&plan_id_api, "<PLAN_ID>")?;
    tok_cli.push(&plan_id_cli, "<PLAN_ID>")?;
    tok_mcp.push(&plan_id_mcp, "<PLAN_ID>")?;
    let p_api = project_surface_response(
        SurfaceKind::RustApi,
        p_api.is_error,
        &raw_plan_api,
        p_api.elapsed_us,
        &policy,
        &tok_api,
    )?;
    let p_cli = project_surface_response(
        SurfaceKind::Cli,
        p_cli.is_error,
        &raw_plan_cli,
        p_cli.elapsed_us,
        &policy,
        &tok_cli,
    )?;
    let p_mcp = project_surface_response(
        SurfaceKind::Mcp,
        p_mcp.is_error,
        &raw_plan_mcp,
        p_mcp.elapsed_us,
        &policy,
        &tok_mcp,
    )?;
    record("plan alert preview", "AOP-007", p_api, p_cli, p_mcp)?;

    // Prepare with exact shared plan approval digest
    let (p_api, raw_prep_api) = execute_rust_api_argv(
        &os_args(&[
            "plan",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            &format!("--session={sid_api}"),
            "--intent=alert",
            &format!("--event-id={event_id}"),
            &format!("--relay={relay_addr}"),
            "--path=/fss/eq-alert",
            &format!("--plaintext-approval={plaintext_app}"),
            "--deadline-ms=5000",
            &format!("--approve={plan_app_api}"),
        ]),
        &policy,
        &tok_api,
    )?;
    let (p_cli, _, env_prep_cli, _) = execute_cli_argv(
        &os_args(&[
            "plan",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            &format!("--session={sid_cli}"),
            "--intent=alert",
            &format!("--event-id={event_id}"),
            &format!("--relay={relay_addr}"),
            "--path=/fss/eq-alert",
            &format!("--plaintext-approval={plaintext_app}"),
            "--deadline-ms=5000",
            &format!("--approve={plan_app_cli}"),
        ]),
        &policy,
        &tok_cli,
    )?;
    let (p_mcp, _, env_prep_mcp) = mcp.call_tool(
        "plan",
        &object(&[
            ("intent", string("alert")),
            ("session", string(&sid_mcp)),
            ("event_id", string(&event_id)),
            ("relay", string(&relay_addr)),
            ("path", string("/fss/eq-alert")),
            ("plaintext_approval", string(&plaintext_app)),
            ("deadline_ms", "5000".to_owned()),
            ("approve", string(&plan_app_mcp)),
        ]),
        &policy,
        &tok_mcp,
    )?;
    let env_prep_api = parse_mcp_reply(raw_prep_api.trim())?;
    let (_, _, disp_app_api) = extract_plan_approvals(&env_prep_api)?;
    let (_, _, disp_app_cli) = extract_plan_approvals(&env_prep_cli)?;
    let (_, _, disp_app_mcp) = extract_plan_approvals(&env_prep_mcp)?;
    // Dispatch approvals bind each clone's wall-clock-timed prepared journal record;
    // verify all three surfaces emit valid SHA-256 dispatch approvals and identical semantics.
    for app in [&disp_app_api, &disp_app_cli, &disp_app_mcp] {
        ContentDigest::parse(app)?;
    }
    record("plan alert prepare", "AOP-007", p_api, p_cli, p_mcp)?;

    // 5. AOP-008 commit (dispatch to live loopback HTTP relay -> adapter_accepted on all 3 surfaces)
    let (p_api, _) = execute_rust_api_argv(
        &os_args(&[
            "commit",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            &format!("--plan={plan_id_api}"),
            &format!("--approve={disp_app_api}"),
        ]),
        &policy,
        &tok_api,
    )?;
    let (p_cli, _, _, _) = execute_cli_argv(
        &os_args(&[
            "commit",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            &format!("--plan={plan_id_cli}"),
            &format!("--approve={disp_app_cli}"),
        ]),
        &policy,
        &tok_cli,
    )?;
    let (p_mcp, _, _) = mcp.call_tool(
        "commit",
        &object(&[
            ("intent", string("dispatch")),
            ("plan", string(&plan_id_mcp)),
            ("approve", string(&disp_app_mcp)),
        ]),
        &policy,
        &tok_mcp,
    )?;
    assert_eq!(p_api.payload_state.as_deref(), Some("adapter_accepted"));
    assert_eq!(relay.hits(), 3, "each surface must dispatch exactly once");
    record("commit alert dispatch", "AOP-008", p_api, p_cli, p_mcp)?;

    // 6. AOP-009 wait (observe adapter_accepted on all 3 surfaces)
    let (p_api, _) = execute_rust_api_argv(
        &os_args(&[
            "wait",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            &format!("--operation={op_id_api}"),
            "--deadline-ms=50",
        ]),
        &policy,
        &tok_api,
    )?;
    let (p_cli, _, _, _) = execute_cli_argv(
        &os_args(&[
            "wait",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            &format!("--operation={op_id_cli}"),
            "--deadline-ms=50",
        ]),
        &policy,
        &tok_cli,
    )?;
    let (p_mcp, _, _) = mcp.call_tool(
        "wait",
        &object(&[
            ("operation_id", string(&op_id_mcp)),
            ("deadline_ms", "50".to_owned()),
        ]),
        &policy,
        &tok_mcp,
    )?;
    assert_eq!(p_api.payload_state.as_deref(), Some("adapter_accepted"));
    record("wait operation state", "AOP-009", p_api, p_cli, p_mcp)?;

    // 7. AOP-008 commit (reconcile preview + approve -> delivered)
    let ev_ack = ContentDigest::sha256(b"fss235-relay-delivery-proof").to_text();
    let stmt = "Owner confirmed loopback 202 delivery receipt";
    let (p_api, raw_rec_prev_api) = execute_rust_api_argv(
        &os_args(&[
            "commit",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            "--reconcile=delivered",
            &format!("--operation={op_id_api}"),
            &format!("--evidence={ev_ack}"),
            &format!("--statement={stmt}"),
        ]),
        &policy,
        &tok_api,
    )?;
    let (p_cli, _, env_rec_prev_cli, _) = execute_cli_argv(
        &os_args(&[
            "commit",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            "--reconcile=delivered",
            &format!("--operation={op_id_cli}"),
            &format!("--evidence={ev_ack}"),
            &format!("--statement={stmt}"),
        ]),
        &policy,
        &tok_cli,
    )?;
    let (p_mcp, _, env_rec_prev_mcp) = mcp.call_tool(
        "commit",
        &object(&[
            ("intent", string("reconcile")),
            ("operation_id", string(&op_id_mcp)),
            ("outcome", string("delivered")),
            ("evidence", string(&ev_ack)),
            ("statement", string(stmt)),
        ]),
        &policy,
        &tok_mcp,
    )?;
    let env_rec_prev_api = parse_mcp_reply(raw_rec_prev_api.trim())?;
    let rec_app_api = extract_approval_from_proof_pointers(&env_rec_prev_api)?;
    let rec_app_cli = extract_approval_from_proof_pointers(&env_rec_prev_cli)?;
    let rec_app_mcp = extract_approval_from_proof_pointers(&env_rec_prev_mcp)?;
    for app in [&rec_app_api, &rec_app_cli, &rec_app_mcp] {
        ContentDigest::parse(app)?;
    }
    record("commit reconcile preview", "AOP-008", p_api, p_cli, p_mcp)?;

    let (p_api, _) = execute_rust_api_argv(
        &os_args(&[
            "commit",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            "--reconcile=delivered",
            &format!("--operation={op_id_api}"),
            &format!("--evidence={ev_ack}"),
            &format!("--statement={stmt}"),
            &format!("--approve={rec_app_api}"),
        ]),
        &policy,
        &tok_api,
    )?;
    let (p_cli, _, _, _) = execute_cli_argv(
        &os_args(&[
            "commit",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            "--reconcile=delivered",
            &format!("--operation={op_id_cli}"),
            &format!("--evidence={ev_ack}"),
            &format!("--statement={stmt}"),
            &format!("--approve={rec_app_cli}"),
        ]),
        &policy,
        &tok_cli,
    )?;
    let (p_mcp, _, _) = mcp.call_tool(
        "commit",
        &object(&[
            ("intent", string("reconcile")),
            ("operation_id", string(&op_id_mcp)),
            ("outcome", string("delivered")),
            ("evidence", string(&ev_ack)),
            ("statement", string(stmt)),
            ("approve", string(&rec_app_mcp)),
        ]),
        &policy,
        &tok_mcp,
    )?;
    assert_eq!(p_api.payload_state.as_deref(), Some("verified"));
    record("commit reconcile approve", "AOP-008", p_api, p_cli, p_mcp)?;

    // 8. AOP-007 plan close -> immutable episode across all 3 surfaces
    let (p_api, _) = execute_rust_api_argv(
        &os_args(&[
            "plan",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            &format!("--session={sid_api}"),
            &format!("--close={plan_id_api}"),
        ]),
        &policy,
        &tok_api,
    )?;
    let (p_cli, _, _, _) = execute_cli_argv(
        &os_args(&[
            "plan",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            &format!("--session={sid_cli}"),
            &format!("--close={plan_id_cli}"),
        ]),
        &policy,
        &tok_cli,
    )?;
    let (p_mcp, _, _) = mcp.call_tool(
        "plan",
        &object(&[
            ("intent", string("close")),
            ("session", string(&sid_mcp)),
            ("plan", string(&plan_id_mcp)),
        ]),
        &policy,
        &tok_mcp,
    )?;
    record("plan close episode", "AOP-007", p_api, p_cli, p_mcp)?;

    // 9. AOP-010 cancel (preview + approve cancel on the prepared port-9 alert)
    let (p_api, raw_can_prev_api) = execute_rust_api_argv(
        &os_args(&[
            "cancel",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            &format!("--operation={c_op_api}"),
        ]),
        &policy,
        &tok_api,
    )?;
    let (p_cli, _, env_can_prev_cli, _) = execute_cli_argv(
        &os_args(&[
            "cancel",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            &format!("--operation={c_op_cli}"),
        ]),
        &policy,
        &tok_cli,
    )?;
    let (p_mcp, _, env_can_prev_mcp) = mcp.call_tool(
        "cancel",
        &object(&[("operation_id", string(&c_op_mcp))]),
        &policy,
        &tok_mcp,
    )?;
    let env_can_prev_api = parse_mcp_reply(raw_can_prev_api.trim())?;
    let can_app_api = extract_approval_from_proof_pointers(&env_can_prev_api)?;
    let can_app_cli = extract_approval_from_proof_pointers(&env_can_prev_cli)?;
    let can_app_mcp = extract_approval_from_proof_pointers(&env_can_prev_mcp)?;
    for app in [&can_app_api, &can_app_cli, &can_app_mcp] {
        ContentDigest::parse(app)?;
    }
    record("cancel alert preview", "AOP-010", p_api, p_cli, p_mcp)?;

    let (p_api, _) = execute_rust_api_argv(
        &os_args(&[
            "cancel",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            &format!("--operation={c_op_api}"),
            &format!("--approve={can_app_api}"),
        ]),
        &policy,
        &tok_api,
    )?;
    let (p_cli, _, _, _) = execute_cli_argv(
        &os_args(&[
            "cancel",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            &format!("--operation={c_op_cli}"),
            &format!("--approve={can_app_cli}"),
        ]),
        &policy,
        &tok_cli,
    )?;
    let (p_mcp, _, _) = mcp.call_tool(
        "cancel",
        &object(&[
            ("operation_id", string(&c_op_mcp)),
            ("approve", string(&can_app_mcp)),
        ]),
        &policy,
        &tok_mcp,
    )?;
    assert_eq!(p_api.payload_state.as_deref(), Some("cancelled"));
    record("cancel alert approve", "AOP-010", p_api, p_cli, p_mcp)?;

    // 10. AOP-013 feedback (advisory only; activePolicyMutation == false across all 3 surfaces)
    let fb_digest = ContentDigest::sha256(b"fss235-feedback-evidence").to_text();
    let fb_target = format!("event:{event_id}");
    let fb_stmt = "Corroborated alert verified; retain advisory note only.";
    let (p_api, _) = execute_rust_api_argv(
        &os_args(&[
            "feedback",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            &format!("--session={sid_api}"),
            &format!("--target={fb_target}"),
            "--kind=helpful",
            &format!("--statement={fb_stmt}"),
            &format!("--supporting={fb_digest}"),
            "--disposition=record_only",
        ]),
        &policy,
        &tok_api,
    )?;
    let (p_cli, _, _, _) = execute_cli_argv(
        &os_args(&[
            "feedback",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            &format!("--session={sid_cli}"),
            &format!("--target={fb_target}"),
            "--kind=helpful",
            &format!("--statement={fb_stmt}"),
            &format!("--supporting={fb_digest}"),
            "--disposition=record_only",
        ]),
        &policy,
        &tok_cli,
    )?;
    let (p_mcp, _, _) = mcp.call_tool(
        "feedback",
        &object(&[
            ("session", string(&sid_mcp)),
            ("target", string(&fb_target)),
            ("kind", string("helpful")),
            ("statement", string(fb_stmt)),
            ("supporting", format!("[{}]", string(&fb_digest))),
            ("disposition", string("record_only")),
        ]),
        &policy,
        &tok_mcp,
    )?;
    assert_eq!(p_api.active_policy_mutation, Some(false));
    record("feedback record_only", "AOP-013", p_api, p_cli, p_mcp)?;

    // 11. AOP-012 handoff
    let note = "Shift change handoff across API/CLI/MCP";
    let (p_api, raw_ho_api) = execute_rust_api_argv(
        &os_args(&[
            "handoff",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            &format!("--session={sid_api}"),
            &format!("--note={note}"),
        ]),
        &policy,
        &tok_api,
    )?;
    let (p_cli, raw_ho_cli, env_ho_cli, _) = execute_cli_argv(
        &os_args(&[
            "handoff",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            &format!("--session={sid_cli}"),
            &format!("--note={note}"),
        ]),
        &policy,
        &tok_cli,
    )?;
    let (p_mcp, raw_ho_mcp, env_ho_mcp) = mcp.call_tool(
        "handoff",
        &object(&[("session", string(&sid_mcp)), ("note", string(note))]),
        &policy,
        &tok_mcp,
    )?;
    let env_ho_api = parse_mcp_reply(raw_ho_api.trim())?;
    let ho_api = text(&env_ho_api, &["payload", "handoffId"])?.to_owned();
    let ho_cli = text(&env_ho_cli, &["payload", "handoffId"])?.to_owned();
    let ho_mcp = text(&env_ho_mcp, &["payload", "handoffId"])?.to_owned();
    tok_api.push(&ho_api, "<HANDOFF_ID>")?;
    tok_cli.push(&ho_cli, "<HANDOFF_ID>")?;
    tok_mcp.push(&ho_mcp, "<HANDOFF_ID>")?;
    let p_api = project_surface_response(
        SurfaceKind::RustApi,
        p_api.is_error,
        &raw_ho_api,
        p_api.elapsed_us,
        &policy,
        &tok_api,
    )?;
    let p_cli = project_surface_response(
        SurfaceKind::Cli,
        p_cli.is_error,
        &raw_ho_cli,
        p_cli.elapsed_us,
        &policy,
        &tok_cli,
    )?;
    let p_mcp = project_surface_response(
        SurfaceKind::Mcp,
        p_mcp.is_error,
        &raw_ho_mcp,
        p_mcp.elapsed_us,
        &policy,
        &tok_mcp,
    )?;
    record("handoff capsule publish", "AOP-012", p_api, p_cli, p_mcp)?;

    // 12. AOP-002 session.resume
    let (p_api, _) = execute_rust_api_argv(
        &os_args(&[
            "session",
            "resume",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            &format!("--handoff={ho_api}"),
        ]),
        &policy,
        &tok_api,
    )?;
    let (p_cli, _, _, _) = execute_cli_argv(
        &os_args(&[
            "session",
            "resume",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            &format!("--handoff={ho_cli}"),
        ]),
        &policy,
        &tok_cli,
    )?;
    let (p_mcp, _, _) = mcp.call_tool(
        "session_resume",
        &object(&[("handoff", string(&ho_mcp))]),
        &policy,
        &tok_mcp,
    )?;
    record(
        "session.resume from handoff",
        "AOP-002",
        p_api,
        p_cli,
        p_mcp,
    )?;

    // 13. AOP-010 session revocation preview + approve
    let (p_api, raw_sc_api) = execute_rust_api_argv(
        &os_args(&[
            "cancel",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            &format!("--session={sid_api}"),
        ]),
        &policy,
        &tok_api,
    )?;
    let (p_cli, _, env_sc_cli, _) = execute_cli_argv(
        &os_args(&[
            "cancel",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            &format!("--session={sid_cli}"),
        ]),
        &policy,
        &tok_cli,
    )?;
    let (p_mcp, _, env_sc_mcp) = mcp.call_tool(
        "cancel",
        &object(&[("session", string(&sid_mcp))]),
        &policy,
        &tok_mcp,
    )?;
    let env_sc_api = parse_mcp_reply(raw_sc_api.trim())?;
    let sc_app_api = extract_approval_from_proof_pointers(&env_sc_api)?;
    let sc_app_cli = extract_approval_from_proof_pointers(&env_sc_cli)?;
    let sc_app_mcp = extract_approval_from_proof_pointers(&env_sc_mcp)?;
    tok_api.push(&sc_app_api, "<SESSION_CANCEL_APPROVAL>")?;
    tok_cli.push(&sc_app_cli, "<SESSION_CANCEL_APPROVAL>")?;
    tok_mcp.push(&sc_app_mcp, "<SESSION_CANCEL_APPROVAL>")?;
    let _ = (p_api, p_cli, p_mcp);

    let (p_api, _) = execute_rust_api_argv(
        &os_args(&[
            "cancel",
            "--json",
            "--root",
            root_api,
            &principal_flag,
            &format!("--session={sid_api}"),
            &format!("--approve={sc_app_api}"),
        ]),
        &policy,
        &tok_api,
    )?;
    let (p_cli, _, _, _) = execute_cli_argv(
        &os_args(&[
            "cancel",
            "--json",
            "--root",
            root_cli,
            &principal_flag,
            &format!("--session={sid_cli}"),
            &format!("--approve={sc_app_cli}"),
        ]),
        &policy,
        &tok_cli,
    )?;
    let (p_mcp, _, _) = mcp.call_tool(
        "cancel",
        &object(&[
            ("session", string(&sid_mcp)),
            ("approve", string(&sc_app_mcp)),
        ]),
        &policy,
        &tok_mcp,
    )?;
    record("cancel session revoke", "AOP-010", p_api, p_cli, p_mcp)?;

    relay.join();
    let (mcp_exit, _stderr, _wire) = mcp.finish()?;
    assert_eq!(mcp_exit, 0);

    // Verify ALL 14 registered operations from the canonical crosswalk are covered!
    let expected_14: BTreeSet<String> = REGISTERED_OPERATION_CROSSWALK
        .iter()
        .map(|entry| entry.operation_id.to_owned())
        .collect();
    assert_eq!(
        covered_all_14, expected_14,
        "FSS-235 must cover all 14 registered AOP-001..AOP-014 operations"
    );

    let report = build_report(steps)?;
    assert!(report.equivalent);
    assert_eq!(report.total_mismatches, 0);
    assert!(!report.grants_effect_authority);
    println!("CAPLOG_FSS235_STATEFUL_14OP={}", report.to_json());
    Ok(())
}

#[test]
fn fss_235_refusals_faults_canary_isolation_and_planted_divergence() -> TestResult {
    let tmp = TempDir::new("faults")?;
    let dep = tmp.path.join("dep");
    let vault_dir = tmp.path.join("vault");
    fs::create_dir_all(&vault_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&vault_dir, fs::Permissions::from_mode(0o700))?;
    }
    init_deployment(&dep, "faults")?;

    // Populate a real LocalEncryptedVault with canary secrets and configure a CanaryLeakScanner.
    let now = TimestampNs(1_750_000_000_i128 * 1_000_000_000);
    let pass = SecretBytes::from_slice(b"fss235-master-passphrase")?;
    let mut vault = LocalEncryptedVault::open_with_entropy(
        &vault_dir,
        KdfParams::for_testing(1)?,
        LabEntropy::from_seed([0x35; 32]),
    );
    vault.initialize(&pass)?;
    let mut scanner = CanaryLeakScanner::new();
    for (id, family, name, target, bytes) in [
        (
            "secret:rtsp:cam-east",
            AdapterFamily::Rtsp,
            "cam-east",
            "rtsp://10.0.0.10/stream1",
            CANARY_RTSP,
        ),
        (
            "secret:webhook:primary-hmac",
            AdapterFamily::AlertWebhook,
            "primary-hmac",
            "https://hooks.fss.test/alert",
            CANARY_HMAC,
        ),
    ] {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:fss235-vault".to_owned(),
            operation_id: OperationId::parse("op:vault:fss235")?,
            principal: PRINCIPAL.to_owned(),
            capabilities: vec![
                CAP_SECRET_WRITE_001.to_owned(),
                CAP_SECRET_READ_001.to_owned(),
            ],
            deadline: None,
            priority: 100,
            budgets: BudgetVector::default(),
            privacy_scope: "privacy:owner".to_owned(),
            retention_scope: "retention:standard".to_owned(),
            anchor_universe: ContentDigest::sha256(b"fss235-vault-universe"),
            generation: 1,
        })?;
        let scope = SecretScope::new(family, name, target)?;
        let store_cx = SecretAccessCx::new(authority, scope, now)?;
        vault.store(
            &store_cx,
            &SecretId::parse(id)?,
            SecretBytes::from_slice(bytes)?,
        )?;
        scanner.register_bytes(id, bytes)?;
    }

    let root_s = dep.to_str().ok_or("utf8 root")?;
    let principal_flag = format!("--principal={PRINCIPAL}");
    let mut mcp = LiveMcp::spawn(&dep, OPS_READ_CAPS)?;
    let mut steps = Vec::new();
    let mut captured_blobs: Vec<(&str, String)> = Vec::new();

    // Refusal 1: explain nonexistent event -> exact 3-surface error parity
    let (a, c, m) = run_read_only_step(
        &mut steps,
        &mut mcp,
        "refusal explain missing event",
        "AOP-011",
        &os_args(&[
            "explain",
            "--json",
            "--root",
            root_s,
            &principal_flag,
            "--event-id=event:nonexistent:9999",
        ]),
        "explain",
        r#"{"event_id":"event:nonexistent:9999"}"#,
    )?;
    assert!(steps[0].rust_api.is_error);
    assert_eq!(
        steps[0].rust_api.error_id.as_deref(),
        Some("ERR-AGENT-EVENT-NOT-FOUND-001")
    );
    captured_blobs.extend([("explain_api", a), ("explain_cli", c), ("explain_mcp", m)]);

    // Refusal 2: wait nonexistent operation -> exact 3-surface error parity
    let (a, c, m) = run_read_only_step(
        &mut steps,
        &mut mcp,
        "refusal wait missing operation",
        "AOP-009",
        &os_args(&[
            "wait",
            "--json",
            "--root",
            root_s,
            &principal_flag,
            "--operation=operation:nonexistent:9999",
            "--deadline-ms=50",
        ]),
        "wait",
        r#"{"operation_id":"operation:nonexistent:9999","deadline_ms":50}"#,
    )?;
    assert!(steps[1].rust_api.is_error);
    captured_blobs.extend([("wait_api", a), ("wait_cli", c), ("wait_mcp", m)]);

    // Refusal 3: session_follow foreign/unknown anchor -> exact 3-surface error parity
    let foreign_anchor = format!("anchor:{}:9:none:{}", "12".repeat(8), "ab".repeat(32));
    let (a, c, m) = run_read_only_step(
        &mut steps,
        &mut mcp,
        "refusal session.follow foreign anchor",
        "AOP-004",
        &os_args(&[
            "follow",
            "--json",
            "--root",
            root_s,
            &principal_flag,
            &format!("--since={foreign_anchor}"),
        ]),
        "session_follow",
        &object(&[("since", string(&foreign_anchor))]),
    )?;
    assert!(steps[2].rust_api.is_error);
    captured_blobs.extend([("follow_api", a), ("follow_cli", c), ("follow_mcp", m)]);

    // Refusal 4: session_resume nonexistent handoff -> exact 3-surface error parity
    let (a, c, m) = run_read_only_step(
        &mut steps,
        &mut mcp,
        "refusal session.resume missing handoff",
        "AOP-002",
        &os_args(&[
            "session",
            "resume",
            "--json",
            "--root",
            root_s,
            &principal_flag,
            "--handoff=handoff:nonexistent:9999",
        ]),
        "session_resume",
        r#"{"handoff":"handoff:nonexistent:9999"}"#,
    )?;
    assert!(steps[3].rust_api.is_error);
    captured_blobs.extend([("resume_api", a), ("resume_cli", c), ("resume_mcp", m)]);

    // Planted-bug differential verification against real live captured JSON from orient!
    let (live_orient_api, live_orient_cli, live_orient_mcp) = run_read_only_step(
        &mut steps,
        &mut mcp,
        "live orient baseline for planted mutation",
        "AOP-003",
        &os_args(&["orient", "--json", "--root", root_s, &principal_flag]),
        "session_orient",
        "{}",
    )?;
    let policy = NormalizationPolicy::exact();
    let tokens = TokenNormalizer::none();
    let base_api = project_surface_response(
        SurfaceKind::RustApi,
        false,
        &live_orient_api,
        1,
        &policy,
        &tokens,
    )?;
    let base_cli = project_surface_response(
        SurfaceKind::Cli,
        false,
        &live_orient_cli,
        1,
        &policy,
        &tokens,
    )?;

    // Planted bug A: flip MCP `is_error` flag without changing JSON body
    let bad_is_err = project_surface_response(
        SurfaceKind::Mcp,
        true,
        &live_orient_mcp,
        1,
        &policy,
        &tokens,
    )?;
    let row_err = compare_step(
        0,
        "planted is_error flip",
        "AOP-003",
        &policy,
        base_api.clone(),
        base_cli.clone(),
        bad_is_err,
    )?;
    assert!(!row_err.equivalent);
    assert!(row_err.mismatches.iter().any(|m| m.field == "is_error"));

    // Planted bug B: mutate MCP outcome from "ok" to "partial"
    let mutated_outcome =
        live_orient_mcp.replacen("\"outcome\":\"ok\"", "\"outcome\":\"partial\"", 1);
    let bad_outcome = project_surface_response(
        SurfaceKind::Mcp,
        false,
        &mutated_outcome,
        1,
        &policy,
        &tokens,
    )?;
    let row_out = compare_step(
        1,
        "planted outcome drift",
        "AOP-003",
        &policy,
        base_api.clone(),
        base_cli.clone(),
        bad_outcome,
    )?;
    assert!(!row_out.equivalent);
    assert!(row_out.mismatches.iter().any(|m| m.field == "outcome"));

    // Planted bug C: inject a warning on one surface without mutating the other two
    let mutated_warn = if live_orient_mcp.contains("\"warnings\":[]") {
        live_orient_mcp.replacen(
            "\"warnings\":[]",
            "\"warnings\":[\"planted-surface-drift-warning\"]",
            1,
        )
    } else {
        live_orient_mcp.replacen(
            "\"warnings\":[",
            "\"warnings\":[\"planted-surface-drift-warning\",",
            1,
        )
    };
    let bad_warn =
        project_surface_response(SurfaceKind::Mcp, false, &mutated_warn, 1, &policy, &tokens)?;
    let row_warn = compare_step(
        2,
        "planted warning drift",
        "AOP-003",
        &policy,
        base_api,
        base_cli,
        bad_warn,
    )?;
    assert!(!row_warn.equivalent);
    assert!(row_warn.mismatches.iter().any(|m| m.field == "warnings"));

    let (mcp_exit, mcp_stderr, mcp_wire) = mcp.finish()?;
    assert_eq!(mcp_exit, 0);

    // Zero canary leakage across every captured response, MCP wire frame, stderr, and disk artifact
    for (surface_name, blob) in &captured_blobs {
        let leaks = scanner.scan(surface_name, blob.as_bytes());
        assert!(
            leaks.is_empty(),
            "canary leaked on {surface_name}: {leaks:?}"
        );
    }
    assert!(scanner.scan("mcp_stderr", &mcp_stderr).is_empty());
    for (idx, frame) in mcp_wire.iter().enumerate() {
        let leaks = scanner.scan(&format!("mcp_wire_{idx}"), frame.as_bytes());
        assert!(leaks.is_empty(), "canary leaked on mcp wire frame {idx}");
    }

    let report = build_report(steps)?;
    assert!(report.equivalent);
    assert_eq!(report.total_mismatches, 0);
    assert!(!report.grants_effect_authority);
    println!("CAPLOG_FSS235_REFUSALS_AND_FAULTS={}", report.to_json());
    Ok(())
}
