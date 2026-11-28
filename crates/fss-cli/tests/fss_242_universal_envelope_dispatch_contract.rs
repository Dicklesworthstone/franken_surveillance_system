#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
//! Live-binary 4-surface universal envelope dispatch & transcript-equivalence contract
//! (`FSS-242` / `fss-x4a.24.42`).
//!
//! Proves universal `AgentRequestEnvelope` / `AgentResponseEnvelope` dispatch with
//! operation-registry-owned typed payload validation across ALL FOUR real public surfaces:
//! 1. **Universal `AgentRequestEnvelope` Dispatch** (`fss_cli::dispatch_envelope_json_with_control`)
//! 2. **Direct Rust API** (`fss_cli::parse_fss_args` + `fss_cli::execute_live_fss_with_exit`)
//! 3. **Live `fss` CLI binary** (`CARGO_BIN_EXE_fss`)
//! 4. **Live `fss-mcp` stdio server** (`CARGO_BIN_EXE_fss-mcp`)
//!
//! Covers:
//! - Exact bit-for-bit 4-surface parity across read-only `AOP-014 doctor`, `AOP-003 session.orient`,
//!   `AOP-005 query` (`events`, `footage`, `sources`, `reports`, `localizations`, `cameras`, `graph`,
//!   `holds`, `privacy-masks`), `AOP-011 explain` (`why`, `why_not`, `forensic`), and
//!   `AOP-004 session.follow`.
//! - Complete 14-operation (`AOP-001`..`AOP-014`) stateful mission lifecycle across 4 isolated
//!   deployment clones and live loopback HTTP relays (`202 Accepted`), including tainted literal
//!   mission text preservation on `session.open`, investigation cases, work claims, shared findings,
//!   alert plan/prepare/commit/wait/reconcile/close, alert cancel, advisory feedback, handoff,
//!   resume, and session revocation.
//! - Exhaustive adversarial & fault matrix: incompatible protocol/registry `ContractBasis`,
//!   superseded capability/cost generations (`ERR-AGENT-SESSION-STALE-001`), pinned stale/foreign
//!   `inputAnchor`, wrong `payloadSchema` across all 14 `AOP-*` operations, principal impersonation,
//!   ungranted capabilities, payload authority overrides (`root`/`principal`/`capabilities`),
//!   effectful missing `idempotencyKey`, tainted effectful denial, response byte-budget exhaustion
//!   without mid-object truncation, cooperative cancellation drain, vault canary-leak scanning, and
//!   planted response-schema / 4-surface divergence detection.

use std::collections::{BTreeMap, BTreeSet};
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
use fss_cli::envelope_dispatch::{
    DispatchAuthority, ERR_AGENT_PROTOCOL, ERR_AGENT_SESSION_STALE, ERR_AUTH_DENIED,
    ERR_BUDGET_EXHAUSTED, ERR_IDEMPOTENCY_CONFLICT, RequestEnvelopeSpec, dispatch_envelope_json,
    dispatch_envelope_json_with_control, validate_response_envelope_against_registry,
};
use fss_cli::error::{ERR_CLI_READ_CANCELLED, ExitIdentity};
use fss_cli::escape_json_str;
use fss_cli::query_cmd::ops_targets::{CAP_AGENT_QUERY, CAP_OBSERVE_STATUS};
use fss_cli::request_control::RequestControl;
use fss_cli::transcript_equivalence::{
    NormalizationPolicy, SemanticProjection, StepEquivalenceRow, SurfaceKind, TokenNormalizer,
    build_report, compare_step, execute_rust_api_argv, project_surface_response,
};
use fss_core::contract_basis::{
    SUPERSEDED_CAPABILITY_REGISTRY_DIGEST_V1, SUPERSEDED_CAPABILITY_REGISTRY_DIGEST_V2,
    SUPERSEDED_COST_REGISTRY_DIGEST_V1, probe_contract_basis, reference_contract_basis,
};
use fss_core::json_input::{Value, parse_mcp_reply};
use fss_core::{
    AgentOperation, BudgetVector, ContentDigest, ContextAuthority, LedgerAnchor, OperationId,
    PrincipalId, RequestTaint, RootAuthoritySpec, SessionId, TimestampNs,
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
const SITE_ID: &str = "site:fss242-dispatch";
const PRINCIPAL: &str = "principal:fss242-owner";
const MIRROR_HOMOGRAPHY: &str = "-1,0,96,0,1,0,0,0,1";
const OPS_READ_CAPS: &[&str] = &[CAP_AGENT_QUERY, CAP_OBSERVE_STATUS];

const CANARY_RTSP: &[u8] = b"CANARY-FSS242-RTSP-SECRET-AABBCCDDEEFF0011-NO-LEAK";
const CANARY_HMAC: &[u8] = b"CANARY-FSS242-HMAC-SECRET-9988776655443322-NO-LEAK";

static DIR_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> TestResult<Self> {
        let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let raw = PathBuf::from("/tmp").join(format!("fss242-{tag}-{}-{seq}", std::process::id()));
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

fn snapshot_tree(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    let mut pending = vec![root.to_path_buf()];
    let mut rows = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let meta = fs::symlink_metadata(&path)?;
        if meta.is_dir() {
            rows.insert(path.strip_prefix(root)?.to_path_buf(), Vec::new());
            for entry in fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        } else if meta.is_file() {
            rows.insert(path.strip_prefix(root)?.to_path_buf(), fs::read(&path)?);
        }
    }
    Ok(rows)
}

fn init_deployment(root: &Path, tag: &str) -> TestResult {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: format!("trace:fss242-{tag}"),
        operation_id: OperationId::parse(format!("operation:fss242-{tag}"))?,
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
            r#"{{"jsonrpc":"2.0","id":{id},"method":"initialize","params":{{"protocolVersion":"{PROTOCOL_VERSION}","capabilities":{{}},"clientInfo":{{"name":"fss242-dispatch","version":"1"}}}}}}"#
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
) -> TestResult<(SemanticProjection, String, Value)> {
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
    Ok((proj, stdout, env))
}

#[allow(clippy::too_many_arguments)]
fn execute_envelope_step(
    auth: &DispatchAuthority,
    op: AgentOperation,
    req_id: &str,
    payload_json: &str,
    session_id: Option<&str>,
    tainted: bool,
    policy: &NormalizationPolicy,
    tokens: &TokenNormalizer,
) -> TestResult<(SemanticProjection, String, Value)> {
    let mut spec =
        RequestEnvelopeSpec::for_operation(op, req_id, auth.principal.clone(), payload_json);
    if let Some(sid) = session_id {
        spec.session_id = Some(SessionId::parse(sid)?);
    }
    if tainted {
        spec.taint = RequestTaint {
            contains_untrusted_control_text: true,
            sources: vec!["untrusted:operator-note".to_owned()],
        };
    }
    let started = Instant::now();
    let outcome = dispatch_envelope_json(auth, &spec.to_json());
    let elapsed_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    assert!(
        !outcome.receipt.grants_effect_authority,
        "dispatch receipt must never grant effect authority"
    );
    assert_eq!(outcome.receipt.operation_id, op.id());
    let is_error = outcome.exit_identity != ExitIdentity::SUCCESS;
    let env = parse_mcp_reply(outcome.response_json.trim())?;
    let proj = project_surface_response(
        SurfaceKind::EnvelopeDispatch,
        is_error,
        &outcome.response_json,
        elapsed_us,
        policy,
        tokens,
    )?;
    Ok((proj, outcome.response_json, env))
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

#[allow(clippy::too_many_arguments)]
fn verify_four_surface_step(
    steps: &mut Vec<StepEquivalenceRow>,
    label: &str,
    expected_op: &str,
    policy: &NormalizationPolicy,
    p_env: SemanticProjection,
    p_api: SemanticProjection,
    p_cli: SemanticProjection,
    p_mcp: SemanticProjection,
) -> TestResult {
    let idx = steps.len();
    // 1. Compare RustApi == Cli == Mcp
    let row_tri = compare_step(
        idx,
        label,
        expected_op,
        policy,
        p_api.clone(),
        p_cli,
        p_mcp.clone(),
    )?;
    assert!(
        row_tri.equivalent,
        "step `{label}` ({expected_op}) diverged across RustApi/Cli/Mcp: {:?}",
        row_tri.mismatches
    );
    // 2. Compare RustApi == EnvelopeDispatch == Mcp (proving exact 4-way transitive parity!)
    let row_env = compare_step(
        idx,
        format!("{label} [envelope]"),
        expected_op,
        policy,
        p_api,
        p_env,
        p_mcp,
    )?;
    assert!(
        row_env.equivalent,
        "step `{label}` ({expected_op}) diverged on EnvelopeDispatch surface: {:?}",
        row_env.mismatches
    );
    steps.push(row_env);
    Ok(())
}

#[test]
fn fss_242_read_only_four_surface_exact_equivalence() -> TestResult {
    let tmp = TempDir::new("ro4")?;
    let dep = tmp.path.join("dep");
    let (anchor_before, event_id) = seed_corroborated_deployment(&tmp.path, &dep)?;
    let root_s = dep.to_str().ok_or("utf8 root")?;
    let principal_flag = format!("--principal={PRINCIPAL}");
    let auth = DispatchAuthority::owner_standard(dep.clone(), PrincipalId::parse(PRINCIPAL)?);
    let mut mcp = LiveMcp::spawn(&dep, OPS_READ_CAPS)?;
    let policy = NormalizationPolicy::exact();
    let tokens = TokenNormalizer::none();
    let mut steps = Vec::new();
    let mut seq = 1_u32;

    let mut run_ro = |label: &str,
                      op: AgentOperation,
                      cli_argv: &[OsString],
                      mcp_tool: &str,
                      payload_json: &str|
     -> TestResult {
        let req_id = format!("req:ro:{seq:03}");
        seq += 1;
        let (p_env, _, _) = execute_envelope_step(
            &auth,
            op,
            &req_id,
            payload_json,
            None,
            false,
            &policy,
            &tokens,
        )?;
        let (p_api, _) = execute_rust_api_argv(cli_argv, &policy, &tokens)?;
        let (p_cli, _, _) = execute_cli_argv(cli_argv, &policy, &tokens)?;
        let (p_mcp, _, _) = mcp.call_tool(mcp_tool, payload_json, &policy, &tokens)?;
        verify_four_surface_step(
            &mut steps,
            label,
            op.id(),
            &policy,
            p_env,
            p_api,
            p_cli,
            p_mcp,
        )
    };

    // AOP-014 doctor
    run_ro(
        "doctor healthy",
        AgentOperation::Doctor,
        &os_args(&["doctor", "--json", "--root", root_s]),
        "doctor",
        "{}",
    )?;

    // AOP-003 session.orient (pulse, brief, epistemic_map)
    for (view, budget) in [
        ("pulse", "300"),
        ("brief", "1600"),
        ("epistemic_map", "3000"),
    ] {
        run_ro(
            &format!("session.orient {view}"),
            AgentOperation::SessionOrient,
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

    // AOP-005 query (events, footage, sources, reports, localizations, cameras, graph, holds, privacy-masks)
    for target in ["events", "footage", "sources", "reports", "localizations"] {
        run_ro(
            &format!("query {target}"),
            AgentOperation::Query,
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
    for (target, extra_cli, payload) in [
        ("cameras", vec![], r#"{"target":"cameras"}"#),
        (
            "graph",
            vec![
                "--projection=SensorCoverageGraph",
                "--algorithm=ALG-BRIDGE-001",
            ],
            r#"{"target":"graph","projection":"SensorCoverageGraph","algorithm":"ALG-BRIDGE-001"}"#,
        ),
        ("holds", vec![], r#"{"target":"holds"}"#),
        ("privacy-masks", vec![], r#"{"target":"privacy-masks"}"#),
    ] {
        let mut argv = vec![
            "query",
            "--json",
            "--root",
            root_s,
            &principal_flag,
            "--capability",
            CAP_AGENT_QUERY,
            "--capability",
            CAP_OBSERVE_STATUS,
        ];
        let tgt_flag = format!("--target={target}");
        argv.push(&tgt_flag);
        argv.extend(extra_cli);
        run_ro(
            &format!("query {target}"),
            AgentOperation::Query,
            &os_args(&argv),
            "query",
            payload,
        )?;
    }

    // AOP-011 explain (why, why_not, forensic)
    for (label, extra_cli, payload) in [
        (
            "explain why",
            vec![],
            format!(r#"{{"event_id":{}}}"#, quote(&event_id)),
        ),
        (
            "explain why_not",
            vec!["--question=why_not"],
            format!(
                r#"{{"event_id":{},"question":"why_not"}}"#,
                quote(&event_id)
            ),
        ),
        (
            "explain forensic",
            vec!["--view=forensic", "--budget-tokens=8000"],
            format!(
                r#"{{"event_id":{},"view":"forensic","budget_tokens":8000}}"#,
                quote(&event_id)
            ),
        ),
    ] {
        let ev_flag = format!("--event-id={event_id}");
        let mut argv = vec![
            "explain",
            "--json",
            "--root",
            root_s,
            &principal_flag,
            &ev_flag,
        ];
        argv.extend(extra_cli);
        run_ro(
            label,
            AgentOperation::Explain,
            &os_args(&argv),
            "explain",
            &payload,
        )?;
    }

    // AOP-004 session.follow
    run_ro(
        "session.follow since pre-event anchor",
        AgentOperation::SessionFollow,
        &os_args(&[
            "follow",
            "--json",
            "--root",
            root_s,
            &principal_flag,
            &format!("--since={anchor_before}"),
            "--view=brief",
        ]),
        "session_follow",
        &format!(r#"{{"since":{},"view":"brief"}}"#, quote(&anchor_before)),
    )?;

    let (code, stderr, _) = mcp.finish()?;
    assert_eq!(
        code,
        0,
        "fss-mcp stderr: {}",
        String::from_utf8_lossy(&stderr)
    );

    let report = build_report(steps)?;
    assert!(report.equivalent);
    assert!(!report.grants_effect_authority);
    assert_eq!(report.steps.len(), 17);
    println!(
        "CAPLOG {}",
        object(&[
            ("scenario", string("fss_242_read_only_four_surface_exact")),
            ("stepCount", report.steps.len().to_string()),
            ("equivalent", report.equivalent.to_string()),
            (
                "transcriptDigest",
                string(&report.transcript_digest.to_text())
            ),
        ])
    );
    Ok(())
}

#[test]
fn fss_242_full_14_operation_stateful_lifecycle_and_four_surface_equivalence() -> TestResult {
    let tmp = TempDir::new("life14")?;
    let seed = tmp.path.join("seed");
    let (anchor_before, event_id) = seed_corroborated_deployment(&tmp.path, &seed)?;

    let dep_env = tmp.path.join("dep-env");
    let dep_api = tmp.path.join("dep-api");
    let dep_cli = tmp.path.join("dep-cli");
    let dep_mcp = tmp.path.join("dep-mcp");
    for dst in [&dep_env, &dep_api, &dep_cli, &dep_mcp] {
        copy_dir_recursive(&seed, dst)?;
    }

    let auth_env =
        DispatchAuthority::owner_standard(dep_env.clone(), PrincipalId::parse(PRINCIPAL)?);
    let mut mcp = LiveMcp::spawn(&dep_mcp, OPS_READ_CAPS)?;
    let relay = LoopbackRelay::spawn(4)?;
    let relay_addr = relay.addr.to_string();
    let root_api_s = dep_api.to_str().ok_or("utf8 api")?.to_owned();
    let root_cli_s = dep_cli.to_str().ok_or("utf8 cli")?.to_owned();
    let principal_flag = format!("--principal={PRINCIPAL}");

    let policy = NormalizationPolicy::stateful_clone();
    let mut norm_env = TokenNormalizer::stateful_clone();
    let mut norm_api = TokenNormalizer::stateful_clone();
    let mut norm_cli = TokenNormalizer::stateful_clone();
    let mut norm_mcp = TokenNormalizer::stateful_clone();
    norm_env.push(dep_env.to_string_lossy(), "<DEPLOY_ROOT>")?;
    norm_api.push(dep_api.to_string_lossy(), "<DEPLOY_ROOT>")?;
    norm_cli.push(dep_cli.to_string_lossy(), "<DEPLOY_ROOT>")?;
    norm_mcp.push(dep_mcp.to_string_lossy(), "<DEPLOY_ROOT>")?;

    let mut steps = Vec::new();
    let mut seq = 1_u32;

    let run_4 = |steps: &mut Vec<StepEquivalenceRow>,
                 mcp: &mut LiveMcp,
                 seq: &mut u32,
                 label: &str,
                 op: AgentOperation,
                 mcp_tool: &str,
                 env_payload: &str,
                 env_session: Option<&str>,
                 tainted: bool,
                 argv_api: &[OsString],
                 argv_cli: &[OsString],
                 mcp_args: &str,
                 n_env: &TokenNormalizer,
                 n_api: &TokenNormalizer,
                 n_cli: &TokenNormalizer,
                 n_mcp: &TokenNormalizer|
     -> TestResult<(Value, Value, Value, Value)> {
        let req_id = format!("req:life:{:03}", *seq);
        *seq += 1;
        let (p_env, _, v_env) = execute_envelope_step(
            &auth_env,
            op,
            &req_id,
            env_payload,
            env_session,
            tainted,
            &policy,
            n_env,
        )?;
        let (p_api, raw_api) = execute_rust_api_argv(argv_api, &policy, n_api)?;
        let v_api = parse_mcp_reply(raw_api.trim())?;
        let (p_cli, _, v_cli) = execute_cli_argv(argv_cli, &policy, n_cli)?;
        let (p_mcp, _, v_mcp) = mcp.call_tool(mcp_tool, mcp_args, &policy, n_mcp)?;
        verify_four_surface_step(steps, label, op.id(), &policy, p_env, p_api, p_cli, p_mcp)?;
        Ok((v_env, v_api, v_cli, v_mcp))
    };

    // 1. AOP-001 session.open (with tainted literal mission text containing path & flag tokens!)
    let tainted_mission = "@/etc/passwd --root=/forbidden verify east/west door entry";
    let objective = "Investigate door entry and dispatch approved alert";
    let open_payload = format!(
        r#"{{"mission":{},"objective":{},"view":"brief","budget_tokens":64000}}"#,
        quote(tainted_mission),
        quote(objective)
    );
    let (v_env, v_api, v_cli, v_mcp) = run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "session.open tainted literal",
        AgentOperation::SessionOpen,
        "session_open",
        &open_payload,
        None,
        true,
        &os_args(&[
            "session",
            "open",
            "--json",
            "--root",
            &root_api_s,
            &principal_flag,
            &format!("--mission-text={tainted_mission}"),
            &format!("--objective={objective}"),
            "--view=brief",
            "--budget-tokens=64000",
        ]),
        &os_args(&[
            "session",
            "open",
            "--json",
            "--root",
            &root_cli_s,
            &principal_flag,
            &format!("--mission-text={tainted_mission}"),
            &format!("--objective={objective}"),
            "--view=brief",
            "--budget-tokens=64000",
        ]),
        &open_payload,
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;
    let s_env = text(&v_env, &["sessionId"])?.to_owned();
    let s_api = text(&v_api, &["sessionId"])?.to_owned();
    let s_cli = text(&v_cli, &["sessionId"])?.to_owned();
    let s_mcp = text(&v_mcp, &["sessionId"])?.to_owned();

    // 2. AOP-003 session.orient (session-bound)
    run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "session.orient session-bound",
        AgentOperation::SessionOrient,
        "session_orient",
        r#"{"view":"brief","budget_tokens":1600}"#,
        Some(&s_env),
        false,
        &os_args(&[
            "orient",
            "--json",
            "--root",
            &root_api_s,
            &principal_flag,
            &format!("--session={s_api}"),
            "--view=brief",
            "--budget-tokens=1600",
        ]),
        &os_args(&[
            "orient",
            "--json",
            "--root",
            &root_cli_s,
            &principal_flag,
            &format!("--session={s_cli}"),
            "--view=brief",
            "--budget-tokens=1600",
        ]),
        &format!(
            r#"{{"session":{},"view":"brief","budget_tokens":1600}}"#,
            quote(&s_mcp)
        ),
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;

    // 3. AOP-004 session.follow
    let follow_payload = format!(r#"{{"since":{},"view":"brief"}}"#, quote(&anchor_before));
    run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "session.follow delta",
        AgentOperation::SessionFollow,
        "session_follow",
        &follow_payload,
        None,
        false,
        &os_args(&[
            "follow",
            "--json",
            "--root",
            &root_api_s,
            &principal_flag,
            &format!("--since={anchor_before}"),
            "--view=brief",
        ]),
        &os_args(&[
            "follow",
            "--json",
            "--root",
            &root_cli_s,
            &principal_flag,
            &format!("--since={anchor_before}"),
            "--view=brief",
        ]),
        &follow_payload,
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;

    // 4. AOP-005 query events
    run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "query events",
        AgentOperation::Query,
        "query",
        r#"{"target":"events"}"#,
        None,
        false,
        &os_args(&[
            "query",
            "--json",
            "--root",
            &root_api_s,
            &principal_flag,
            "--target=events",
        ]),
        &os_args(&[
            "query",
            "--json",
            "--root",
            &root_cli_s,
            &principal_flag,
            "--target=events",
        ]),
        r#"{"target":"events"}"#,
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;

    // 5. AOP-011 explain event
    let explain_payload = format!(r#"{{"event_id":{}}}"#, quote(&event_id));
    let ev_flag = format!("--event-id={event_id}");
    run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "explain corroborated event",
        AgentOperation::Explain,
        "explain",
        &explain_payload,
        None,
        false,
        &os_args(&[
            "explain",
            "--json",
            "--root",
            &root_api_s,
            &principal_flag,
            &ev_flag,
        ]),
        &os_args(&[
            "explain",
            "--json",
            "--root",
            &root_cli_s,
            &principal_flag,
            &ev_flag,
        ]),
        &explain_payload,
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;

    // 6. AOP-006 investigate (open case, list, claim, claim-list, finding, finding-list)
    let case_id = "case:fss242-door";
    let evidence_digest = ContentDigest::sha256(event_id.as_bytes()).to_text();
    let draft_json = format!(
        r#"{{"caseId":"{case_id}","question":"Did a corroborated entrant cross the east door?","decisionInformed":"Alert dispatch vs hold","hypotheses":[{{"hypothesisId":"h:entry","description":"Corroborated physical entry","predictions":["matched east and west tracks"]}},{{"hypothesisId":"h:artifact","description":"Transient glare artifact","predictions":["disjoint sensor tracks"]}}],"knowns":[{{"statementId":"k:cams","text":"East and west cameras retained footage","basis":["sensor:east","sensor:west"]}}],"unknowns":[{{"statementId":"u:identity","text":"Person identity remains unknown"}}],"discriminators":[{{"discriminatorId":"d:overlap","description":"Two-camera ground-plane overlap","separates":["h:entry","h:artifact"],"expectedOutcomes":["matched","disjoint"]}}],"probes":["probe:corroborate"],"stopRules":["independent two-camera evidence settles competing hypotheses"],"decisionWindowNs":3600000000000}}"#
    );
    let draft_file = tmp.path.join("case_draft.json");
    fs::write(&draft_file, &draft_json)?;
    let draft_path_s = draft_file.to_str().ok_or("utf8 draft")?;
    run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "investigate open",
        AgentOperation::Investigate,
        "investigate",
        &format!(r#"{{"transition":"open","draft":{draft_json}}}"#),
        Some(&s_env),
        false,
        &os_args(&[
            "investigate",
            "--json",
            "--root",
            &root_api_s,
            &principal_flag,
            &format!("--session={s_api}"),
            "--transition=open",
            &format!("--case-file={draft_path_s}"),
        ]),
        &os_args(&[
            "investigate",
            "--json",
            "--root",
            &root_cli_s,
            &principal_flag,
            &format!("--session={s_cli}"),
            "--transition=open",
            &format!("--case-file={draft_path_s}"),
        ]),
        &format!(
            r#"{{"session":{},"transition":"open","draft":{draft_json}}}"#,
            quote(&s_mcp)
        ),
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;

    run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "investigate claim",
        AgentOperation::Investigate,
        "investigate",
        &format!(
            r#"{{"transition":"claim","case":{},"work":"case","lease_ms":60000}}"#,
            quote(case_id)
        ),
        Some(&s_env),
        false,
        &os_args(&[
            "investigate",
            "--json",
            "--root",
            &root_api_s,
            &principal_flag,
            &format!("--session={s_api}"),
            "--transition=claim",
            &format!("--case={case_id}"),
            "--work=case",
            "--lease-ms=60000",
        ]),
        &os_args(&[
            "investigate",
            "--json",
            "--root",
            &root_cli_s,
            &principal_flag,
            &format!("--session={s_cli}"),
            "--transition=claim",
            &format!("--case={case_id}"),
            "--work=case",
            "--lease-ms=60000",
        ]),
        &format!(
            r#"{{"session":{},"transition":"claim","case":{},"work":"case","lease_ms":60000}}"#,
            quote(&s_mcp),
            quote(case_id)
        ),
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;

    run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "investigate finding",
        AgentOperation::Investigate,
        "investigate",
        &format!(
            r#"{{"transition":"finding","case":{},"claim":"East and west overlap","state":"known","supporting":[{}]}}"#,
            quote(case_id),
            quote(&evidence_digest)
        ),
        Some(&s_env),
        false,
        &os_args(&[
            "investigate",
            "--json",
            "--root",
            &root_api_s,
            &principal_flag,
            &format!("--session={s_api}"),
            "--transition=finding",
            &format!("--case={case_id}"),
            "--claim=East and west overlap",
            "--state=known",
            &format!("--supporting={evidence_digest}"),
        ]),
        &os_args(&[
            "investigate",
            "--json",
            "--root",
            &root_cli_s,
            &principal_flag,
            &format!("--session={s_cli}"),
            "--transition=finding",
            &format!("--case={case_id}"),
            "--claim=East and west overlap",
            "--state=known",
            &format!("--supporting={evidence_digest}"),
        ]),
        &format!(
            r#"{{"session":{},"transition":"finding","case":{},"claim":"East and west overlap","state":"known","supporting":[{}]}}"#,
            quote(&s_mcp),
            quote(case_id),
            quote(&evidence_digest)
        ),
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;

    // 7. AOP-007 plan (preview + prepare)
    let plaintext_approval = ContentDigest::sha256(b"fss242 loopback relay approval").to_text();
    let plan_prev_env = format!(
        r#"{{"intent":"alert","event_id":{},"relay":{},"path":"/fss242-alert","plaintext_approval":{},"deadline_ms":5000,"case":{}}}"#,
        quote(&event_id),
        quote(&relay_addr),
        quote(&plaintext_approval),
        quote(case_id)
    );
    let plan_prev_mcp = format!(
        r#"{{"intent":"alert","session":{},"event_id":{},"relay":{},"path":"/fss242-alert","plaintext_approval":{},"deadline_ms":5000,"case":{}}}"#,
        quote(&s_mcp),
        quote(&event_id),
        quote(&relay_addr),
        quote(&plaintext_approval),
        quote(case_id)
    );
    let (pv_env, pv_api, pv_cli, pv_mcp) = run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "plan alert preview",
        AgentOperation::Plan,
        "plan",
        &plan_prev_env,
        Some(&s_env),
        false,
        &os_args(&[
            "plan",
            "--json",
            "--root",
            &root_api_s,
            &principal_flag,
            &format!("--session={s_api}"),
            "--intent=alert",
            &format!("--event-id={event_id}"),
            &format!("--relay={relay_addr}"),
            "--path=/fss242-alert",
            &format!("--plaintext-approval={plaintext_approval}"),
            "--deadline-ms=5000",
            &format!("--case={case_id}"),
        ]),
        &os_args(&[
            "plan",
            "--json",
            "--root",
            &root_cli_s,
            &principal_flag,
            &format!("--session={s_cli}"),
            "--intent=alert",
            &format!("--event-id={event_id}"),
            &format!("--relay={relay_addr}"),
            "--path=/fss242-alert",
            &format!("--plaintext-approval={plaintext_approval}"),
            "--deadline-ms=5000",
            &format!("--case={case_id}"),
        ]),
        &plan_prev_mcp,
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;
    let (plan_env, app_env, _) = extract_plan_approvals(&pv_env)?;
    let (plan_api, app_api, _) = extract_plan_approvals(&pv_api)?;
    let (plan_cli, app_cli, _) = extract_plan_approvals(&pv_cli)?;
    let (plan_mcp, app_mcp, _) = extract_plan_approvals(&pv_mcp)?;

    let (prep_env, prep_api, prep_cli, prep_mcp) = run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "plan alert prepare",
        AgentOperation::Plan,
        "plan",
        &format!(
            r#"{{"intent":"alert","event_id":{},"relay":{},"path":"/fss242-alert","plaintext_approval":{},"deadline_ms":5000,"case":{},"approve":{}}}"#,
            quote(&event_id),
            quote(&relay_addr),
            quote(&plaintext_approval),
            quote(case_id),
            quote(&app_env)
        ),
        Some(&s_env),
        false,
        &os_args(&[
            "plan",
            "--json",
            "--root",
            &root_api_s,
            &principal_flag,
            &format!("--session={s_api}"),
            "--intent=alert",
            &format!("--event-id={event_id}"),
            &format!("--relay={relay_addr}"),
            "--path=/fss242-alert",
            &format!("--plaintext-approval={plaintext_approval}"),
            "--deadline-ms=5000",
            &format!("--case={case_id}"),
            &format!("--approve={app_api}"),
        ]),
        &os_args(&[
            "plan",
            "--json",
            "--root",
            &root_cli_s,
            &principal_flag,
            &format!("--session={s_cli}"),
            "--intent=alert",
            &format!("--event-id={event_id}"),
            &format!("--relay={relay_addr}"),
            "--path=/fss242-alert",
            &format!("--plaintext-approval={plaintext_approval}"),
            "--deadline-ms=5000",
            &format!("--case={case_id}"),
            &format!("--approve={app_cli}"),
        ]),
        &format!(
            r#"{{"intent":"alert","session":{},"event_id":{},"relay":{},"path":"/fss242-alert","plaintext_approval":{},"deadline_ms":5000,"case":{},"approve":{}}}"#,
            quote(&s_mcp),
            quote(&event_id),
            quote(&relay_addr),
            quote(&plaintext_approval),
            quote(case_id),
            quote(&app_mcp)
        ),
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;
    let (_, _, disp_env) = extract_plan_approvals(&prep_env)?;
    let (_, _, disp_api) = extract_plan_approvals(&prep_api)?;
    let (_, _, disp_cli) = extract_plan_approvals(&prep_cli)?;
    let (_, _, disp_mcp) = extract_plan_approvals(&prep_mcp)?;
    let op_env = extract_operation_id(&prep_env)?;
    let op_api = extract_operation_id(&prep_api)?;
    let op_cli = extract_operation_id(&prep_cli)?;
    let op_mcp = extract_operation_id(&prep_mcp)?;

    // 8. AOP-008 commit (dispatch live webhook across all 4 surfaces!)
    run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "commit dispatch live webhook",
        AgentOperation::Commit,
        "commit",
        &format!(
            r#"{{"intent":"dispatch","plan":{},"approve":{}}}"#,
            quote(&plan_env),
            quote(&disp_env)
        ),
        None,
        false,
        &os_args(&[
            "commit",
            "--json",
            "--root",
            &root_api_s,
            &principal_flag,
            &format!("--plan={plan_api}"),
            &format!("--approve={disp_api}"),
        ]),
        &os_args(&[
            "commit",
            "--json",
            "--root",
            &root_cli_s,
            &principal_flag,
            &format!("--plan={plan_cli}"),
            &format!("--approve={disp_cli}"),
        ]),
        &format!(
            r#"{{"intent":"dispatch","plan":{},"approve":{}}}"#,
            quote(&plan_mcp),
            quote(&disp_mcp)
        ),
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;
    assert_eq!(
        relay.hits(),
        4,
        "live loopback relay must receive exactly 4 webhook dispatches"
    );
    relay.join();

    // 9. AOP-009 wait
    run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "wait on dispatched alert",
        AgentOperation::Wait,
        "wait",
        &format!(r#"{{"operation_id":{},"deadline_ms":50}}"#, quote(&op_env)),
        None,
        false,
        &os_args(&[
            "wait",
            "--json",
            "--root",
            &root_api_s,
            &principal_flag,
            &format!("--operation={op_api}"),
            "--deadline-ms=50",
        ]),
        &os_args(&[
            "wait",
            "--json",
            "--root",
            &root_cli_s,
            &principal_flag,
            &format!("--operation={op_cli}"),
            "--deadline-ms=50",
        ]),
        &format!(r#"{{"operation_id":{},"deadline_ms":50}}"#, quote(&op_mcp)),
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;

    // 10. AOP-008 commit reconcile (preview + approve)
    let rec_evidence = ContentDigest::sha256(b"owner-confirmed-delivery").to_text();
    let rec_stmt = "Owner verified webhook 202 acceptance";
    let (rp_env, rp_api, rp_cli, rp_mcp) = run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "commit reconcile preview",
        AgentOperation::Commit,
        "commit",
        &format!(
            r#"{{"intent":"reconcile","operation_id":{},"outcome":"delivered","evidence":{},"statement":{}}}"#,
            quote(&op_env),
            quote(&rec_evidence),
            quote(rec_stmt)
        ),
        None,
        false,
        &os_args(&[
            "commit",
            "--json",
            "--root",
            &root_api_s,
            &principal_flag,
            "--reconcile=delivered",
            &format!("--operation={op_api}"),
            &format!("--evidence={rec_evidence}"),
            &format!("--statement={rec_stmt}"),
        ]),
        &os_args(&[
            "commit",
            "--json",
            "--root",
            &root_cli_s,
            &principal_flag,
            "--reconcile=delivered",
            &format!("--operation={op_cli}"),
            &format!("--evidence={rec_evidence}"),
            &format!("--statement={rec_stmt}"),
        ]),
        &format!(
            r#"{{"intent":"reconcile","operation_id":{},"outcome":"delivered","evidence":{},"statement":{}}}"#,
            quote(&op_mcp),
            quote(&rec_evidence),
            quote(rec_stmt)
        ),
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;
    let rapp_env = extract_approval_from_proof_pointers(&rp_env)?;
    let rapp_api = extract_approval_from_proof_pointers(&rp_api)?;
    let rapp_cli = extract_approval_from_proof_pointers(&rp_cli)?;
    let rapp_mcp = extract_approval_from_proof_pointers(&rp_mcp)?;

    run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "commit reconcile approve",
        AgentOperation::Commit,
        "commit",
        &format!(
            r#"{{"intent":"reconcile","operation_id":{},"outcome":"delivered","evidence":{},"statement":{},"approve":{}}}"#,
            quote(&op_env),
            quote(&rec_evidence),
            quote(rec_stmt),
            quote(&rapp_env)
        ),
        None,
        false,
        &os_args(&[
            "commit",
            "--json",
            "--root",
            &root_api_s,
            &principal_flag,
            "--reconcile=delivered",
            &format!("--operation={op_api}"),
            &format!("--evidence={rec_evidence}"),
            &format!("--statement={rec_stmt}"),
            &format!("--approve={rapp_api}"),
        ]),
        &os_args(&[
            "commit",
            "--json",
            "--root",
            &root_cli_s,
            &principal_flag,
            "--reconcile=delivered",
            &format!("--operation={op_cli}"),
            &format!("--evidence={rec_evidence}"),
            &format!("--statement={rec_stmt}"),
            &format!("--approve={rapp_cli}"),
        ]),
        &format!(
            r#"{{"intent":"reconcile","operation_id":{},"outcome":"delivered","evidence":{},"statement":{},"approve":{}}}"#,
            quote(&op_mcp),
            quote(&rec_evidence),
            quote(rec_stmt),
            quote(&rapp_mcp)
        ),
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;

    // 11. AOP-007 plan close (immutable execution episode)
    run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "plan close episode",
        AgentOperation::Plan,
        "plan",
        &format!(r#"{{"intent":"close","plan":{}}}"#, quote(&plan_env)),
        Some(&s_env),
        false,
        &os_args(&[
            "plan",
            "--json",
            "--root",
            &root_api_s,
            &principal_flag,
            &format!("--session={s_api}"),
            &format!("--close={plan_api}"),
        ]),
        &os_args(&[
            "plan",
            "--json",
            "--root",
            &root_cli_s,
            &principal_flag,
            &format!("--session={s_cli}"),
            &format!("--close={plan_cli}"),
        ]),
        &format!(
            r#"{{"intent":"close","session":{},"plan":{}}}"#,
            quote(&s_mcp),
            quote(&plan_mcp)
        ),
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;

    // 12. AOP-013 feedback (advisory; activePolicyMutation == false)
    let (fb_env, _, _, _) = run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "feedback advisory proposal",
        AgentOperation::Feedback,
        "feedback",
        &format!(
            r#"{{"target":{},"kind":"helpful","statement":"Corroborated event was accurate","supporting":[{}]}}"#,
            quote(&format!("event:{event_id}")),
            quote(&evidence_digest)
        ),
        Some(&s_env),
        false,
        &os_args(&[
            "feedback",
            "--json",
            "--root",
            &root_api_s,
            &principal_flag,
            &format!("--session={s_api}"),
            &format!("--target=event:{event_id}"),
            "--kind=helpful",
            "--statement=Corroborated event was accurate",
            &format!("--supporting={evidence_digest}"),
        ]),
        &os_args(&[
            "feedback",
            "--json",
            "--root",
            &root_cli_s,
            &principal_flag,
            &format!("--session={s_cli}"),
            &format!("--target=event:{event_id}"),
            "--kind=helpful",
            "--statement=Corroborated event was accurate",
            &format!("--supporting={evidence_digest}"),
        ]),
        &format!(
            r#"{{"session":{},"target":{},"kind":"helpful","statement":"Corroborated event was accurate","supporting":[{}]}}"#,
            quote(&s_mcp),
            quote(&format!("event:{event_id}")),
            quote(&evidence_digest)
        ),
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;
    assert_eq!(
        field(&fb_env, &["payload", "activePolicyMutation"])?.boolean(),
        Some(false)
    );

    // 13. AOP-012 handoff
    let (ho_env, ho_api, ho_cli, ho_mcp) = run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "handoff publish",
        AgentOperation::Handoff,
        "handoff",
        r#"{"note":"FSS-242 4-surface handoff"}"#,
        Some(&s_env),
        false,
        &os_args(&[
            "handoff",
            "--json",
            "--root",
            &root_api_s,
            &principal_flag,
            &format!("--session={s_api}"),
            "--note=FSS-242 4-surface handoff",
        ]),
        &os_args(&[
            "handoff",
            "--json",
            "--root",
            &root_cli_s,
            &principal_flag,
            &format!("--session={s_cli}"),
            "--note=FSS-242 4-surface handoff",
        ]),
        &format!(
            r#"{{"session":{},"note":"FSS-242 4-surface handoff"}}"#,
            quote(&s_mcp)
        ),
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;
    let h_env = text(&ho_env, &["payload", "handoffId"])?.to_owned();
    let h_api = text(&ho_api, &["payload", "handoffId"])?.to_owned();
    let h_cli = text(&ho_cli, &["payload", "handoffId"])?.to_owned();
    let h_mcp = text(&ho_mcp, &["payload", "handoffId"])?.to_owned();

    // 14. AOP-002 session.resume
    run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "session.resume from handoff",
        AgentOperation::SessionResume,
        "session_resume",
        &format!(r#"{{"handoff":{}}}"#, quote(&h_env)),
        None,
        false,
        &os_args(&[
            "session",
            "resume",
            "--json",
            "--root",
            &root_api_s,
            &principal_flag,
            &format!("--handoff={h_api}"),
        ]),
        &os_args(&[
            "session",
            "resume",
            "--json",
            "--root",
            &root_cli_s,
            &principal_flag,
            &format!("--handoff={h_cli}"),
        ]),
        &format!(r#"{{"handoff":{}}}"#, quote(&h_mcp)),
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;

    // 15. AOP-010 cancel (session revocation preview + approve)
    let (cp_env, cp_api, cp_cli, cp_mcp) = run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "cancel session preview",
        AgentOperation::Cancel,
        "cancel",
        &format!(r#"{{"session":{}}}"#, quote(&s_env)),
        Some(&s_env),
        false,
        &os_args(&[
            "cancel",
            "--json",
            "--root",
            &root_api_s,
            &principal_flag,
            &format!("--session={s_api}"),
        ]),
        &os_args(&[
            "cancel",
            "--json",
            "--root",
            &root_cli_s,
            &principal_flag,
            &format!("--session={s_cli}"),
        ]),
        &format!(r#"{{"session":{}}}"#, quote(&s_mcp)),
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;
    let capp_env = extract_approval_from_proof_pointers(&cp_env)?;
    let capp_api = extract_approval_from_proof_pointers(&cp_api)?;
    let capp_cli = extract_approval_from_proof_pointers(&cp_cli)?;
    let capp_mcp = extract_approval_from_proof_pointers(&cp_mcp)?;

    run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "cancel session approve",
        AgentOperation::Cancel,
        "cancel",
        &format!(
            r#"{{"session":{},"approve":{}}}"#,
            quote(&s_env),
            quote(&capp_env)
        ),
        Some(&s_env),
        false,
        &os_args(&[
            "cancel",
            "--json",
            "--root",
            &root_api_s,
            &principal_flag,
            &format!("--session={s_api}"),
            &format!("--approve={capp_api}"),
        ]),
        &os_args(&[
            "cancel",
            "--json",
            "--root",
            &root_cli_s,
            &principal_flag,
            &format!("--session={s_cli}"),
            &format!("--approve={capp_cli}"),
        ]),
        &format!(
            r#"{{"session":{},"approve":{}}}"#,
            quote(&s_mcp),
            quote(&capp_mcp)
        ),
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;

    // 16. AOP-014 doctor after complete lifecycle
    run_4(
        &mut steps,
        &mut mcp,
        &mut seq,
        "doctor post-lifecycle",
        AgentOperation::Doctor,
        "doctor",
        "{}",
        None,
        false,
        &os_args(&["doctor", "--json", "--root", &root_api_s]),
        &os_args(&["doctor", "--json", "--root", &root_cli_s]),
        "{}",
        &norm_env,
        &norm_api,
        &norm_cli,
        &norm_mcp,
    )?;

    let (code, stderr, _) = mcp.finish()?;
    assert_eq!(
        code,
        0,
        "fss-mcp stderr: {}",
        String::from_utf8_lossy(&stderr)
    );

    let report = build_report(steps)?;
    assert!(report.equivalent);
    assert!(!report.grants_effect_authority);
    let expected_all: BTreeSet<String> = REGISTERED_OPERATION_CROSSWALK
        .iter()
        .map(|e| e.operation_id.to_owned())
        .collect();
    assert_eq!(
        report.operations_covered, expected_all,
        "must prove all 14 AOP-001..AOP-014 operations across 4 surfaces"
    );

    println!(
        "CAPLOG {}",
        object(&[
            ("scenario", string("fss_242_full_14_op_four_surface")),
            ("stepCount", report.steps.len().to_string()),
            (
                "operationsCoveredCount",
                report.operations_covered.len().to_string()
            ),
            ("equivalent", report.equivalent.to_string()),
            (
                "transcriptDigest",
                string(&report.transcript_digest.to_text())
            ),
        ])
    );
    Ok(())
}

#[test]
fn fss_242_adversarial_basis_anchor_authority_taint_budget_cancel_and_canary_scan() -> TestResult {
    let tmp = TempDir::new("adv")?;
    let dep = tmp.path.join("dep");
    let (_anchor_before, _event_id) = seed_corroborated_deployment(&tmp.path, &dep)?;

    // Initialize an encrypted vault seeded with canary secrets so we prove zero leakage across all responses.
    let vault_dir = tmp.path.join("vault");
    fs::create_dir_all(&vault_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&vault_dir, fs::Permissions::from_mode(0o700))?;
    }
    let now = TimestampNs(1_750_000_000_i128 * 1_000_000_000);
    let pass = SecretBytes::from_slice(b"fss242-vault-passphrase")?;
    let mut vault = LocalEncryptedVault::open_with_entropy(
        &vault_dir,
        KdfParams::for_testing(1)?,
        LabEntropy::from_seed([0x24; 32]),
    );
    vault.initialize(&pass)?;
    let mut canary_scanner = CanaryLeakScanner::new();
    for (id, family, name, target, bytes) in [
        (
            "secret:fss242:rtsp",
            AdapterFamily::Rtsp,
            "cam-east",
            "rtsp://10.0.0.10/stream1",
            CANARY_RTSP,
        ),
        (
            "secret:fss242:hmac",
            AdapterFamily::AlertWebhook,
            "primary-hmac",
            "https://hooks.fss.test/alert",
            CANARY_HMAC,
        ),
    ] {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:fss242-vault-seed".to_owned(),
            operation_id: OperationId::parse("op:vault:fss242")?,
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
            anchor_universe: ContentDigest::sha256(b"fss242-vault-universe"),
            generation: 1,
        })?;
        let scope = SecretScope::new(family, name, target)?;
        let store_cx = SecretAccessCx::new(authority, scope, now)?;
        vault.store(
            &store_cx,
            &SecretId::parse(id)?,
            SecretBytes::from_slice(bytes)?,
        )?;
        canary_scanner.register_bytes(id, bytes)?;
    }

    let before_snapshot = snapshot_tree(&dep)?;
    let principal = PrincipalId::parse(PRINCIPAL)?;
    let auth = DispatchAuthority::owner_standard(dep.clone(), principal.clone());
    let mut outputs: Vec<String> = Vec::new();

    // 1. Incompatible protocol + superseded ContractBasis generations
    for (tag, mutate, expected_err, expect_resnapshot) in [
        (
            "bad-proto",
            Box::new(|spec: &mut RequestEnvelopeSpec| {
                spec.contract_basis.semantic_protocol = "fss/2".to_owned();
            }) as Box<dyn Fn(&mut RequestEnvelopeSpec)>,
            ERR_AGENT_PROTOCOL,
            false,
        ),
        (
            "superseded-cap-v1",
            Box::new(|spec: &mut RequestEnvelopeSpec| {
                if let Ok(d) = ContentDigest::parse(SUPERSEDED_CAPABILITY_REGISTRY_DIGEST_V1) {
                    spec.contract_basis.capability_registry_digest = d;
                }
            }),
            ERR_AGENT_SESSION_STALE,
            true,
        ),
        (
            "superseded-cap-v2",
            Box::new(|spec: &mut RequestEnvelopeSpec| {
                if let Ok(d) = ContentDigest::parse(SUPERSEDED_CAPABILITY_REGISTRY_DIGEST_V2) {
                    spec.contract_basis.capability_registry_digest = d;
                }
            }),
            ERR_AGENT_SESSION_STALE,
            true,
        ),
        (
            "superseded-cost-v1",
            Box::new(|spec: &mut RequestEnvelopeSpec| {
                if let Ok(d) = ContentDigest::parse(SUPERSEDED_COST_REGISTRY_DIGEST_V1) {
                    spec.contract_basis.cost_registry_digest = d;
                }
            }),
            ERR_AGENT_SESSION_STALE,
            true,
        ),
    ] {
        let mut spec = RequestEnvelopeSpec::for_operation(
            AgentOperation::SessionOrient,
            format!("req:adv:{tag}"),
            principal.clone(),
            "{}",
        );
        mutate(&mut spec);
        let out = dispatch_envelope_json(&auth, &spec.to_json());
        assert_eq!(out.exit_identity, ExitIdentity::AGENT_REFUSED, "{tag}");
        assert_eq!(out.receipt.error_id.as_deref(), Some(expected_err), "{tag}");
        assert!(!out.receipt.grants_effect_authority);
        let parsed = parse_mcp_reply(&out.response_json)?;
        assert_eq!(
            field(&parsed, &["resnapshotRequired"])?.boolean(),
            Some(expect_resnapshot),
            "{tag}"
        );
        outputs.push(out.response_json);
        outputs.push(out.receipt.to_json());
    }

    // 2. Stale inputAnchor (genesis sequence 0 against advanced head) & foreign lineage anchor
    for (tag, anchor) in [
        ("stale-seq", LedgerAnchor::genesis(SITE_ID)),
        (
            "foreign-site",
            LedgerAnchor::genesis("site:foreign-deployment"),
        ),
    ] {
        let mut spec = RequestEnvelopeSpec::for_operation(
            AgentOperation::SessionOrient,
            format!("req:anchor:{tag}"),
            principal.clone(),
            "{}",
        );
        spec.input_anchor = Some(anchor);
        let out = dispatch_envelope_json(&auth, &spec.to_json());
        assert_eq!(out.exit_identity, ExitIdentity::AGENT_REFUSED, "{tag}");
        assert_eq!(
            out.receipt.error_id.as_deref(),
            Some(ERR_AGENT_SESSION_STALE),
            "{tag}"
        );
        outputs.push(out.response_json);
    }

    // 3. Wrong payloadSchema for ALL 14 registered operations must fail closed with ERR-AGENT-PROTOCOL-001
    for op in AgentOperation::ALL_OPERATIONS {
        let mut spec = RequestEnvelopeSpec::for_operation(
            op,
            format!("req:wrong-schema:{}", op.id()),
            principal.clone(),
            "{}",
        );
        spec.payload_schema = "fss.wrong_payload_schema.v1".to_owned();
        let out = dispatch_envelope_json(&auth, &spec.to_json());
        assert_eq!(
            out.exit_identity,
            ExitIdentity::AGENT_REFUSED,
            "{}",
            op.id()
        );
        assert_eq!(
            out.receipt.error_id.as_deref(),
            Some(ERR_AGENT_PROTOCOL),
            "{}",
            op.id()
        );
        outputs.push(out.response_json);
    }

    // 4. Authority overrides, principal impersonation, ungranted capability, missing idempotency, tainted effect
    let bad_root = RequestEnvelopeSpec::for_operation(
        AgentOperation::Query,
        "req:adv:root-override",
        principal.clone(),
        r#"{"target":"events","root":"/etc"}"#,
    );
    let out = dispatch_envelope_json(&auth, &bad_root.to_json());
    assert_eq!(out.receipt.error_id.as_deref(), Some(ERR_AUTH_DENIED));
    outputs.push(out.response_json);

    let imposter = RequestEnvelopeSpec::for_operation(
        AgentOperation::SessionOrient,
        "req:adv:imposter",
        PrincipalId::parse("principal:attacker")?,
        "{}",
    );
    let out = dispatch_envelope_json(&auth, &imposter.to_json());
    assert_eq!(out.receipt.error_id.as_deref(), Some(ERR_AUTH_DENIED));
    outputs.push(out.response_json);

    let read_only_auth = DispatchAuthority::with_capabilities(
        dep.clone(),
        principal.clone(),
        BTreeSet::from(["CAP-AGENT-SITUATION-READ-001".to_owned()]),
    );
    let commit_req = RequestEnvelopeSpec::for_operation(
        AgentOperation::Commit,
        "req:adv:commit-nocap",
        principal.clone(),
        r#"{"intent":"dispatch","plan":"plan:1","approve":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}"#,
    );
    let out = dispatch_envelope_json(&read_only_auth, &commit_req.to_json());
    assert_eq!(out.receipt.error_id.as_deref(), Some(ERR_AUTH_DENIED));
    outputs.push(out.response_json);

    let mut missing_idem = commit_req.clone();
    missing_idem.idempotency_key = None;
    let out = dispatch_envelope_json(&auth, &missing_idem.to_json());
    assert_eq!(
        out.receipt.error_id.as_deref(),
        Some(ERR_IDEMPOTENCY_CONFLICT)
    );
    outputs.push(out.response_json);

    let mut tainted_effect = commit_req;
    tainted_effect.taint = RequestTaint {
        contains_untrusted_control_text: true,
        sources: vec!["untrusted:webhook".to_owned()],
    };
    let out = dispatch_envelope_json(&auth, &tainted_effect.to_json());
    assert_eq!(out.receipt.error_id.as_deref(), Some(ERR_AUTH_DENIED));
    assert!(out.receipt.tainted);
    outputs.push(out.response_json);

    // 5. Response byte-budget exhaustion (refuse cleanly without truncating mid-object)
    let mut tiny_budget = RequestEnvelopeSpec::for_operation(
        AgentOperation::SessionOrient,
        "req:adv:tiny-budget",
        principal.clone(),
        r#"{"view":"brief"}"#,
    );
    tiny_budget.budget = BudgetVector::builder().bytes(2048).build()?;
    let out = dispatch_envelope_json(&auth, &tiny_budget.to_json());
    assert_eq!(out.exit_identity, ExitIdentity::AGENT_REFUSED);
    assert_eq!(out.receipt.error_id.as_deref(), Some(ERR_BUDGET_EXHAUSTED));
    let parsed_budget = parse_mcp_reply(&out.response_json)?;
    assert_eq!(text(&parsed_budget, &["errorId"])?, ERR_BUDGET_EXHAUSTED);
    outputs.push(out.response_json);

    // 6. Cooperative cancellation drain
    let cancelled = || true;
    let cancel_out = dispatch_envelope_json_with_control(
        &auth,
        &RequestEnvelopeSpec::for_operation(
            AgentOperation::SessionOrient,
            "req:adv:cancel",
            principal,
            "{}",
        )
        .to_json(),
        &RequestControl::new(&cancelled),
    );
    assert_eq!(cancel_out.exit_identity, ExitIdentity::AGENT_REFUSED);
    assert_eq!(cancel_out.receipt.outcome, "cancelled");
    assert_eq!(
        cancel_out.receipt.error_id.as_deref(),
        Some(ERR_CLI_READ_CANCELLED)
    );
    outputs.push(cancel_out.response_json);

    // 7. Zero filesystem mutation across ALL adversarial faults & zero vault canary leakage!
    assert_eq!(
        snapshot_tree(&dep)?,
        before_snapshot,
        "adversarial refusals must never mutate deployment state"
    );
    for (idx, text_blob) in outputs.iter().enumerate() {
        let surface = format!("envelope_dispatch_output_{idx}");
        assert!(
            canary_scanner
                .scan(&surface, text_blob.as_bytes())
                .is_empty(),
            "vault canary leaked into envelope dispatch output!"
        );
    }
    Ok(())
}

#[test]
fn fss_242_planted_response_drift_and_four_surface_divergence_detected() -> TestResult {
    let basis = reference_contract_basis();
    let probe_basis = probe_contract_basis();
    let principal = PrincipalId::parse(PRINCIPAL)?;
    let d = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    // Planted V2 payload schema under reference V1 basis fails closed; allowed under probe_contract_basis.
    let v2_resp = format!(
        r#"{{"schema":"fss.agent_response_envelope.v1","contractBasis":{{}},"operationId":"AOP-006","principalId":"{PRINCIPAL}","outcome":"ok","errorId":null,"payloadSchema":"fss.agent_cognitive_envelope.v2","payloadDigest":"{d}","decisionFingerprint":"{d}"}}"#
    );
    assert!(
        validate_response_envelope_against_registry(
            &v2_resp,
            AgentOperation::Investigate,
            &basis,
            &principal,
        )
        .is_err()
    );
    assert!(
        validate_response_envelope_against_registry(
            &v2_resp,
            AgentOperation::Investigate,
            &probe_basis,
            &principal,
        )
        .is_ok()
    );

    // Planted EnvelopeDispatch single-field drift against RustApi/Mcp fails closed cleanly.
    let good = format!(
        r#"{{"schema":"fss.agent_response_envelope.v1","contractBasis":{{"semanticProtocol":"fss/1"}},"operationId":"AOP-003","principalId":"{PRINCIPAL}","effectiveViewId":"AVIEW-002","effectiveCapabilities":["CAP-AGENT-SITUATION-READ-001"],"outcome":"ok","errorId":null,"payloadSchema":"fss.situation_capsule.v1","payload":{{"note":"same"}},"payloadDigest":"{d}","epistemicState":"known","completeness":"complete","warnings":[],"contradictions":[],"degradation":[],"affordances":[],"decisionFingerprint":"{d}","recoveryClass":"safe_read_retry","safeRetry":"yes_same_request","resnapshotRequired":false}}"#
    );
    let drifted = good.replace("\"note\":\"same\"", "\"note\":\"drifted\"");
    let policy = NormalizationPolicy::exact();
    let tokens = TokenNormalizer::none();
    let p_api = project_surface_response(SurfaceKind::RustApi, false, &good, 1, &policy, &tokens)?;
    let p_env = project_surface_response(
        SurfaceKind::EnvelopeDispatch,
        false,
        &drifted,
        1,
        &policy,
        &tokens,
    )?;
    let p_mcp = project_surface_response(SurfaceKind::Mcp, false, &good, 1, &policy, &tokens)?;
    let row = compare_step(0, "planted-drift", "AOP-003", &policy, p_api, p_env, p_mcp)?;
    assert!(!row.equivalent);
    assert!(
        row.mismatches
            .iter()
            .any(|m| m.field == "canonicalPayloadDigest")
    );
    Ok(())
}
